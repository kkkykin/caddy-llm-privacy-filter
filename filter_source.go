package llmprivacyfilter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"go.uber.org/zap"
	pf "privacyfilter/filter"
)

const maxRemoteGitleaksTOMLSize int64 = 32 << 20

type filterStore struct {
	ptr atomic.Pointer[pf.Filter]
}

func (s *filterStore) Load() *pf.Filter {
	return s.ptr.Load()
}

func (s *filterStore) Store(f *pf.Filter) {
	s.ptr.Store(f)
}

func startFilterRefresh(ctx context.Context, sources []string, interval time.Duration, logger *zap.Logger, store func(*pf.Filter)) (context.CancelFunc, chan struct{}, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	sources = compactGitleaksSources(sources)

	filter, err := loadPrivacyFilterSources(ctx, sources)
	if err != nil {
		return nil, nil, err
	}
	store(filter)

	if len(sources) == 0 {
		return stoppedRefresh()
	}
	if interval == 0 {
		if hasHTTPURL(sources) {
			interval = defaultGitleaksTOMLRefreshInterval
		} else {
			return stoppedRefresh()
		}
	}

	refreshCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-refreshCtx.Done():
				return
			case <-ticker.C:
				filter, err := loadPrivacyFilterSources(refreshCtx, sources)
				if err != nil {
					logger.Warn("failed to refresh gitleaks_toml; keeping previous privacy filter rules",
						append(gitleaksSourceFields(sources), zap.Error(err))...)
					continue
				}
				store(filter)
				rules, skipped := filter.Stats()
				logger.Info("refreshed gitleaks_toml privacy filter rules",
					append(gitleaksSourceFields(sources),
						zap.Int("rules", rules),
						zap.Int("skipped_rules", skipped))...)
			}
		}
	}()

	return cancel, done, nil
}

func stoppedRefresh() (context.CancelFunc, chan struct{}, error) {
	done := make(chan struct{})
	close(done)
	return func() {}, done, nil
}

func loadPrivacyFilter(ctx context.Context, source string) (*pf.Filter, error) {
	if source == "" || !isHTTPURL(source) {
		return pf.New(source)
	}

	body, err := fetchGitleaksTOML(ctx, source)
	if err != nil {
		return nil, err
	}
	return newFilterFromTOMLBytes(body)
}

func loadPrivacyFilterSources(ctx context.Context, sources []string) (*pf.Filter, error) {
	sources = compactGitleaksSources(sources)
	switch len(sources) {
	case 0:
		return pf.New("")
	case 1:
		return loadPrivacyFilter(ctx, sources[0])
	}

	body, err := mergeGitleaksTOML(ctx, sources)
	if err != nil {
		return nil, err
	}
	return newFilterFromTOMLBytes(body)
}

func fetchGitleaksTOML(ctx context.Context, source string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, fmt.Errorf("create gitleaks_toml request: %w", err)
	}

	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch gitleaks_toml: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch gitleaks_toml: unexpected HTTP status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteGitleaksTOMLSize+1))
	if err != nil {
		return nil, fmt.Errorf("read gitleaks_toml response: %w", err)
	}
	if int64(len(body)) > maxRemoteGitleaksTOMLSize {
		return nil, fmt.Errorf("gitleaks_toml response exceeds %d bytes", maxRemoteGitleaksTOMLSize)
	}
	return body, nil
}

type gitleaksTOMLConfig struct {
	Rules []gitleaksTOMLRule `toml:"rules"`
}

type gitleaksTOMLRule struct {
	ID          string   `toml:"id"`
	Regex       string   `toml:"regex"`
	Keywords    []string `toml:"keywords"`
	Entropy     float64  `toml:"entropy"`
	SecretGroup int      `toml:"secretGroup"`
}

func mergeGitleaksTOML(ctx context.Context, sources []string) ([]byte, error) {
	var merged gitleaksTOMLConfig
	for _, source := range sources {
		body, err := readGitleaksTOML(ctx, source)
		if err != nil {
			return nil, fmt.Errorf("load gitleaks_toml %q: %w", source, err)
		}

		var cfg gitleaksTOMLConfig
		if _, err := toml.Decode(string(body), &cfg); err != nil {
			return nil, fmt.Errorf("decode gitleaks_toml %q: %w", source, err)
		}
		merged.Rules = append(merged.Rules, cfg.Rules...)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(merged); err != nil {
		return nil, fmt.Errorf("encode merged gitleaks_toml: %w", err)
	}
	return buf.Bytes(), nil
}

func readGitleaksTOML(ctx context.Context, source string) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if isHTTPURL(source) {
		return fetchGitleaksTOML(ctx, source)
	}
	body, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("read gitleaks_toml: %w", err)
	}
	return body, nil
}

func newFilterFromTOMLBytes(body []byte) (*pf.Filter, error) {
	tmp, err := os.CreateTemp("", "caddy-llm-privacy-filter-gitleaks-*.toml")
	if err != nil {
		return nil, fmt.Errorf("create temporary gitleaks_toml: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write temporary gitleaks_toml: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close temporary gitleaks_toml: %w", err)
	}

	return pf.New(name)
}

func isHTTPURL(source string) bool {
	u, err := url.Parse(source)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func hasHTTPURL(sources []string) bool {
	for _, source := range sources {
		if isHTTPURL(source) {
			return true
		}
	}
	return false
}

func compactGitleaksSources(sources []string) []string {
	if len(sources) == 0 {
		return nil
	}
	compact := make([]string, 0, len(sources))
	for _, source := range sources {
		if source != "" {
			compact = append(compact, source)
		}
	}
	return compact
}

func gitleaksSourceFields(sources []string) []zap.Field {
	if len(sources) == 1 {
		return []zap.Field{zap.String("source", sources[0])}
	}
	return []zap.Field{zap.Strings("sources", sources)}
}
