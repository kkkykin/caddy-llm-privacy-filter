package llmprivacyfilter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	pf "privacyfilter/filter"
)

type captureNext struct {
	body string
}

func (n *captureNext) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	n.body = string(body)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func TestHandlerRedactsAndForwardsBody(t *testing.T) {
	f, err := pf.New("")
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	h := &Handler{
		api:         apiAuto,
		filter:      f,
		logger:      zap.NewNop(),
		MaxBodySize: defaultMaxBodySize,
	}
	next := &captureNext{}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"a@example.com"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	if err := h.ServeHTTP(rr, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rr.Code)
	}
	if strings.Contains(next.body, "a@example.com") || !strings.Contains(next.body, "[邮箱]") {
		t.Fatalf("body was not redacted: %s", next.body)
	}
}

func TestHandlerSkipsNonJSON(t *testing.T) {
	f, err := pf.New("")
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	h := &Handler{
		api:         apiAuto,
		filter:      f,
		logger:      zap.NewNop(),
		MaxBodySize: defaultMaxBodySize,
	}
	next := &captureNext{}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("a@example.com"))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	if err := h.ServeHTTP(rr, req, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if next.body != "a@example.com" {
		t.Fatalf("expected original body, got %s", next.body)
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`llm_privacy_filter responses {
		gitleaks_toml /etc/caddy/gitleaks.toml
		max_body_size 42
		fail_open true
	}`)
	var h Handler

	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal Caddyfile: %v", err)
	}
	if h.API != "responses" {
		t.Fatalf("API = %q", h.API)
	}
	if h.GitleaksTOML != "/etc/caddy/gitleaks.toml" {
		t.Fatalf("GitleaksTOML = %q", h.GitleaksTOML)
	}
	if h.MaxBodySize != 42 {
		t.Fatalf("MaxBodySize = %d", h.MaxBodySize)
	}
	if !h.FailOpen {
		t.Fatal("FailOpen = false")
	}
}
