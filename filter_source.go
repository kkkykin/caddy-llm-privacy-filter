package llmprivacyfilter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

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

func startFilterRefresh(ctx context.Context, source string, interval time.Duration, logger *zap.Logger, store func(*pf.Filter)) (context.CancelFunc, chan struct{}, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	filter, err := loadPrivacyFilter(ctx, source)
	if err != nil {
		return nil, nil, err
	}
	store(filter)

	if source == "" {
		return stoppedRefresh()
	}
	if interval == 0 {
		if isHTTPURL(source) {
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
				filter, err := loadPrivacyFilter(refreshCtx, source)
				if err != nil {
					logger.Warn("failed to refresh gitleaks_toml; keeping previous privacy filter rules",
						zap.String("source", source),
						zap.Error(err))
					continue
				}
				store(filter)
				rules, skipped := filter.Stats()
				logger.Info("refreshed gitleaks_toml privacy filter rules",
					zap.String("source", source),
					zap.Int("rules", rules),
					zap.Int("skipped_rules", skipped))
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
