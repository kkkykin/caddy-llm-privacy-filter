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
)

const maxRemoteGitleaksTOMLSize int64 = 32 << 20

type filterStore struct {
	ptr atomic.Pointer[GitleaksFilter]
}

func (s *filterStore) Load() *GitleaksFilter {
	return s.ptr.Load()
}

func (s *filterStore) Store(f *GitleaksFilter) {
	s.ptr.Store(f)
}

func startFilterRefresh(ctx context.Context, sources []string, interval time.Duration, logger *zap.Logger, store func(*GitleaksFilter)) (context.CancelFunc, chan struct{}, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	sources = compactGitleaksSources(sources)

	// initialLoaded tracks whether we have a usable filter after the first load.
	// URL-only sources are allowed to start without a filter (ServeHTTP returns
	// 500 until a background retry succeeds). Local or mixed sources still fail
	// fast so bad paths or malformed files surface at startup.
	initialLoaded := true
	filter, err := loadPrivacyFilterSources(ctx, sources)
	if err != nil {
		if !allHTTPURLs(sources) {
			return nil, nil, err
		}
		logger.Warn("failed to load gitleaks_toml from URL source(s); starting without filter and retrying in background",
			append(gitleaksSourceFields(sources), zap.Error(err))...)
		initialLoaded = false
	} else {
		store(filter)
	}

	if len(sources) == 0 {
		return stoppedRefresh()
	}
	successInterval := interval
	if successInterval == 0 {
		if hasHTTPURL(sources) {
			successInterval = defaultGitleaksTOMLRefreshInterval
		} else if initialLoaded {
			// Local-only sources with no explicit refresh interval: load once.
			return stoppedRefresh()
		} else {
			// URL load failed with no explicit interval: still need retries.
			successInterval = defaultGitleaksTOMLRefreshInterval
		}
	}

	refreshCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)

		// After a successful load, wait successInterval between reloads.
		// After a failed load (including the initial URL failure), retry with
		// exponential backoff starting at defaultRefreshBackoffMin.
		backoff := defaultRefreshBackoffMin
		var wait time.Duration
		if initialLoaded {
			wait = successInterval
		} else {
			wait = backoff
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()

		for {
			select {
			case <-refreshCtx.Done():
				return
			case <-timer.C:
				filter, err := loadPrivacyFilterSources(refreshCtx, sources)
				if err != nil {
					logger.Warn("failed to refresh gitleaks_toml; retrying with backoff",
						append(gitleaksSourceFields(sources),
							zap.Duration("backoff", backoff),
							zap.Error(err))...)
					timer.Reset(backoff)
					backoff = nextRefreshBackoff(backoff)
					continue
				}
				store(filter)
				rules, skipped := filter.Stats()
				logger.Info("refreshed gitleaks_toml rules",
					append(gitleaksSourceFields(sources),
						zap.Int("rules", rules),
						zap.Int("skipped_rules", skipped))...)
				backoff = defaultRefreshBackoffMin
				timer.Reset(successInterval)
			}
		}
	}()

	return cancel, done, nil
}

const (
	defaultRefreshBackoffMin = time.Second
	defaultRefreshBackoffMax = 60 * time.Second
)

// nextRefreshBackoff doubles the current backoff, capped at defaultRefreshBackoffMax.
func nextRefreshBackoff(current time.Duration) time.Duration {
	if current < defaultRefreshBackoffMin {
		return defaultRefreshBackoffMin
	}
	next := current * 2
	if next > defaultRefreshBackoffMax || next < current {
		return defaultRefreshBackoffMax
	}
	return next
}

func stoppedRefresh() (context.CancelFunc, chan struct{}, error) {
	done := make(chan struct{})
	close(done)
	return func() {}, done, nil
}

func loadPrivacyFilter(ctx context.Context, source string) (*GitleaksFilter, error) {
	if source == "" {
		return NewGitleaksFilter(nil)
	}
	body, err := readGitleaksTOML(ctx, source)
	if err != nil {
		return nil, err
	}
	return newFilterFromTOMLBytes(body)
}

func loadPrivacyFilterSources(ctx context.Context, sources []string) (*GitleaksFilter, error) {
	sources = compactGitleaksSources(sources)
	switch len(sources) {
	case 0:
		return NewGitleaksFilter(nil)
	case 1:
		return loadPrivacyFilter(ctx, sources[0])
	}

	bodies := make([][]byte, 0, len(sources))
	for _, source := range sources {
		body, err := readGitleaksTOML(ctx, source)
		if err != nil {
			return nil, fmt.Errorf("load gitleaks_toml %q: %w", source, err)
		}
		bodies = append(bodies, body)
	}
	return NewGitleaksFilterFromSources(bodies)
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
	Rules      []gitleaksTOMLRule      `toml:"rules"`
	Allowlists []gitleaksTOMLAllowlist `toml:"allowlists"`
	Extend     gitleaksTOMLExtend      `toml:"extend"`
}

type gitleaksTOMLExtend struct {
	DisabledRules []string `toml:"disabledRules"`
}

type gitleaksTOMLRule struct {
	ID          string                  `toml:"id"`
	Description string                  `toml:"description"`
	Regex       string                  `toml:"regex"`
	Keywords    []string                `toml:"keywords"`
	Entropy     float64                 `toml:"entropy"`
	SecretGroup int                     `toml:"secretGroup"`
	Tags        []string                `toml:"tags"`
	Allowlists  []gitleaksTOMLAllowlist `toml:"allowlists"`
}

type gitleaksTOMLAllowlist struct {
	Description string   `toml:"description"`
	Condition   string   `toml:"condition"`
	Commits     []string `toml:"commits"`
	Paths       []string `toml:"paths"`
	RegexTarget string   `toml:"regexTarget"`
	Regexes     []string `toml:"regexes"`
	StopWords   []string `toml:"stopwords"`
	TargetRules []string `toml:"targetRules"`
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

func newFilterFromTOMLBytes(body []byte) (*GitleaksFilter, error) {
	return NewGitleaksFilter(body)
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

func allHTTPURLs(sources []string) bool {
	if len(sources) == 0 {
		return false
	}
	for _, source := range sources {
		if !isHTTPURL(source) {
			return false
		}
	}
	return true
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
