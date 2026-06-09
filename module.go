package llmprivacyfilter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	pf "privacyfilter/filter"
)

const defaultMaxBodySize int64 = 8 << 20

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("llm_privacy_filter", parseCaddyfile)
}

// Handler redacts sensitive text from LLM request bodies before the request is
// passed to the next Caddy handler, typically reverse_proxy.
type Handler struct {
	// API selects the JSON request shape to filter. Supported values are
	// "auto", "openai", "openai-compatible", "responses", and
	// "anthropic-message".
	API string `json:"api,omitempty"`

	// GitleaksTOML optionally points at a gitleaks-compatible TOML rules file.
	// When empty, privacy-filter's built-in rules are used.
	GitleaksTOML string `json:"gitleaks_toml,omitempty"`

	// MaxBodySize is the largest JSON body to buffer and redact, in bytes.
	// The default is 8 MiB. Set to -1 for no explicit limit.
	MaxBodySize int64 `json:"max_body_size,omitempty"`

	// FailOpen passes the original request through if the body cannot be
	// inspected. The default is fail-closed.
	FailOpen bool `json:"fail_open,omitempty"`

	api    apiMode
	filter *pf.Filter
	logger *zap.Logger
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.llm_privacy_filter",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	api, err := parseAPIMode(h.API)
	if err != nil {
		return err
	}
	if h.MaxBodySize == 0 {
		h.MaxBodySize = defaultMaxBodySize
	}
	if h.MaxBodySize < -1 {
		return fmt.Errorf("max_body_size must be -1 or greater")
	}

	f, err := pf.New(h.GitleaksTOML)
	if err != nil {
		return fmt.Errorf("load privacy filter: %w", err)
	}

	h.api = api
	h.filter = f
	h.logger = ctx.Logger(h)
	return nil
}

func (h *Handler) Validate() error {
	if _, err := parseAPIMode(h.API); err != nil {
		return err
	}
	if h.MaxBodySize < -1 {
		return fmt.Errorf("max_body_size must be -1 or greater")
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.filter == nil {
		return caddyhttp.Error(http.StatusInternalServerError, errors.New("llm_privacy_filter is not provisioned"))
	}
	if !shouldInspect(r) {
		return next.ServeHTTP(w, r)
	}

	if enc := r.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return h.handleFailure(w, r, next, nil, http.StatusUnsupportedMediaType,
			fmt.Errorf("cannot inspect compressed request body with Content-Encoding %q", enc))
	}

	if h.MaxBodySize >= 0 && r.ContentLength > h.MaxBodySize {
		if h.FailOpen {
			h.logFailure("body exceeds max_body_size before buffering", nil)
			return next.ServeHTTP(w, r)
		}
		return caddyhttp.Error(http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds max_body_size"))
	}

	originalBody := r.Body
	body, tooLarge, err := readBodyLimit(originalBody, h.MaxBodySize)
	if err != nil {
		return h.handleFailure(w, r, next, body, http.StatusBadRequest, fmt.Errorf("read request body: %w", err))
	}
	if tooLarge {
		if h.FailOpen {
			r.Body = prefixReadCloser(body, originalBody)
			r.ContentLength = originalContentLength(r.ContentLength)
			if r.ContentLength >= 0 {
				r.Header.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
			} else {
				r.Header.Del("Content-Length")
			}
			h.logFailure("body exceeds max_body_size while buffering", nil)
			return next.ServeHTTP(w, r)
		}
		_ = originalBody.Close()
		return caddyhttp.Error(http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds max_body_size"))
	}
	_ = originalBody.Close()

	redacted, summary, err := newPayloadRedactor(h.filter).RedactJSON(body, h.api, r.URL.Path)
	if err != nil {
		return h.handleFailure(w, r, next, body, http.StatusBadRequest, err)
	}
	if summary.Changed {
		h.logger.Debug("redacted llm request body", zap.Int("entities", summary.Entities))
		resetBody(r, redacted)
	} else {
		resetBody(r, body)
	}
	return next.ServeHTTP(w, r)
}

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var h Handler
	err := h.UnmarshalCaddyfile(helper.Dispenser)
	return &h, err
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		if len(args) > 1 {
			return d.ArgErr()
		}
		if len(args) == 1 {
			h.API = args[0]
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "api":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.API = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			case "gitleaks_toml":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.GitleaksTOML = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			case "max_body_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				n, err := strconv.ParseInt(d.Val(), 10, 64)
				if err != nil {
					return d.Errf("invalid max_body_size: %v", err)
				}
				h.MaxBodySize = n
				if d.NextArg() {
					return d.ArgErr()
				}
			case "fail_open":
				if d.NextArg() {
					v, err := strconv.ParseBool(d.Val())
					if err != nil {
						return d.Errf("invalid fail_open value: %v", err)
					}
					h.FailOpen = v
					if d.NextArg() {
						return d.ArgErr()
					}
				} else {
					h.FailOpen = true
				}
			default:
				return d.Errf("unrecognized subdirective %q", d.Val())
			}
		}
	}
	return nil
}

func shouldInspect(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func readBodyLimit(r io.Reader, max int64) ([]byte, bool, error) {
	if max < 0 {
		body, err := io.ReadAll(r)
		return body, false, err
	}
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return body, false, err
	}
	if int64(len(body)) > max {
		return body, true, nil
	}
	return body, false, nil
}

func resetBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
}

type prefixedReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func prefixReadCloser(prefix []byte, rest io.ReadCloser) io.ReadCloser {
	return prefixedReadCloser{
		reader: io.MultiReader(bytes.NewReader(prefix), rest),
		closer: rest,
	}
}

func (rc prefixedReadCloser) Read(p []byte) (int, error) {
	return rc.reader.Read(p)
}

func (rc prefixedReadCloser) Close() error {
	return rc.closer.Close()
}

func originalContentLength(n int64) int64 {
	if n > 0 {
		return n
	}
	return -1
}

func (h *Handler) handleFailure(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, body []byte, status int, err error) error {
	if h.FailOpen {
		if body != nil {
			resetBody(r, body)
		}
		h.logFailure("passing original llm request body after privacy filter failure", err)
		return next.ServeHTTP(w, r)
	}
	return caddyhttp.Error(status, err)
}

func (h *Handler) logFailure(msg string, err error) {
	if h.logger == nil {
		return
	}
	if err != nil {
		h.logger.Warn(msg, zap.Error(err))
		return
	}
	h.logger.Warn(msg)
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
