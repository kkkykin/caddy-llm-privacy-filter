package llmprivacyfilter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestLoadPrivacyFilterFromURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gitleaksRuleTOML("test-secret", "TESTSECRET[0-9]+", "TESTSECRET")))
	}))
	defer server.Close()

	filter, err := loadPrivacyFilter(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("load privacy filter: %v", err)
	}
	if res := filter.RedactString("value TESTSECRET123"); !res.Hit {
		t.Fatalf("expected URL rule to redact, got %+v", res)
	}
}

func TestLoadPrivacyFilterMergesSources(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.toml")
	second := filepath.Join(dir, "second.toml")
	if err := os.WriteFile(first, []byte(gitleaksRuleTOML("first-secret", "FIRSTSECRET[0-9]+", "FIRSTSECRET")), 0o600); err != nil {
		t.Fatalf("write first toml: %v", err)
	}
	if err := os.WriteFile(second, []byte(gitleaksRuleTOML("second-secret", "SECONDSECRET[0-9]+", "SECONDSECRET")), 0o600); err != nil {
		t.Fatalf("write second toml: %v", err)
	}

	filter, err := loadPrivacyFilterSources(context.Background(), []string{first, second})
	if err != nil {
		t.Fatalf("load privacy filter sources: %v", err)
	}
	if res := filter.RedactString("value FIRSTSECRET123"); !res.Hit {
		t.Fatalf("expected first rule to redact, got %+v", res)
	}
	if res := filter.RedactString("value SECONDSECRET123"); !res.Hit {
		t.Fatalf("expected second rule to redact, got %+v", res)
	}
}

func TestLoadPrivacyFilterMergesAllowlists(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.toml")
	allowlist := filepath.Join(dir, "allowlist.toml")
	if err := os.WriteFile(rules, []byte(gitleaksRuleTOML("internal-token", "INTERNAL_[A-Z0-9]{16}", "INTERNAL_")), 0o600); err != nil {
		t.Fatalf("write rules toml: %v", err)
	}
	if err := os.WriteFile(allowlist, []byte(`
[[allowlists]]
regexes = ['''^INTERNAL_ALLOWLISTED$''']
`), 0o600); err != nil {
		t.Fatalf("write allowlist toml: %v", err)
	}

	filter, err := loadPrivacyFilterSources(context.Background(), []string{rules, allowlist})
	if err != nil {
		t.Fatalf("load privacy filter sources: %v", err)
	}
	result := filter.RedactString("INTERNAL_ALLOWLISTED INTERNAL_1234567890ABCDEF")
	if !strings.Contains(result.Redacted, "INTERNAL_ALLOWLISTED") || strings.Contains(result.Redacted, "INTERNAL_1234567890ABCDEF") {
		t.Fatalf("merged allowlist result = %q", result.Redacted)
	}
}

func TestLoadPrivacyFilterAppendsGlobalAllowlistsFromEverySource(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.toml")
	second := filepath.Join(dir, "second.toml")
	if err := os.WriteFile(first, []byte(`
[[rules]]
id = "multi-token"
regex = '''TOKEN_[A-Z0-9]+'''
keywords = ["TOKEN_"]

[[allowlists]]
regexes = ['''^TOKEN_PATTERNA$''']
`), 0o600); err != nil {
		t.Fatalf("write first toml: %v", err)
	}
	if err := os.WriteFile(second, []byte(`
[[allowlists]]
regexes = ['''^TOKEN_PATTERNB$''']
`), 0o600); err != nil {
		t.Fatalf("write second toml: %v", err)
	}

	filter, err := loadPrivacyFilterSources(context.Background(), []string{first, second})
	if err != nil {
		t.Fatalf("load privacy filter sources: %v", err)
	}
	result := filter.RedactString("TOKEN_PATTERNA TOKEN_PATTERNB TOKEN_BLOCKED")
	if !strings.Contains(result.Redacted, "TOKEN_PATTERNA") || !strings.Contains(result.Redacted, "TOKEN_PATTERNB") {
		t.Fatalf("global allowlists were not both retained: %q", result.Redacted)
	}
	if strings.Contains(result.Redacted, "TOKEN_BLOCKED") {
		t.Fatalf("non-allowlisted token was not redacted: %q", result.Redacted)
	}
}

func TestLoadPrivacyFilterAppendsPerRuleAllowlistWhenLaterRuleOverrides(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.toml")
	second := filepath.Join(dir, "second.toml")
	if err := os.WriteFile(first, []byte(`
[[rules]]
id = "overridden-token"
regex = '''TOKEN_[A-Z]+'''

    [[rules.allowlists]]
    regexes = ['''^TOKEN_ALLOWED$''']
`), 0o600); err != nil {
		t.Fatalf("write first toml: %v", err)
	}
	if err := os.WriteFile(second, []byte(`
[[rules]]
id = "overridden-token"
regex = '''TOKEN_[A-Z0-9]+'''
`), 0o600); err != nil {
		t.Fatalf("write second toml: %v", err)
	}

	filter, err := loadPrivacyFilterSources(context.Background(), []string{first, second})
	if err != nil {
		t.Fatalf("load privacy filter sources: %v", err)
	}
	result := filter.RedactString("TOKEN_ALLOWED TOKEN_BLOCK123")
	if !strings.Contains(result.Redacted, "TOKEN_ALLOWED") {
		t.Fatalf("earlier per-rule allowlist was lost: %q", result.Redacted)
	}
	if strings.Contains(result.Redacted, "TOKEN_BLOCK123") {
		t.Fatalf("later rule definition did not override regex: %q", result.Redacted)
	}
}

func TestLoadPrivacyFilterAccumulatesDisabledRulesAcrossSources(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.toml")
	second := filepath.Join(dir, "second.toml")
	if err := os.WriteFile(first, []byte("[extend]\ndisabledRules = [\"generic-api-key\"]\n"), 0o600); err != nil {
		t.Fatalf("write first toml: %v", err)
	}
	if err := os.WriteFile(second, []byte("[extend]\ndisabledRules = [\"pii-email\"]\n"), 0o600); err != nil {
		t.Fatalf("write second toml: %v", err)
	}

	filter, err := loadPrivacyFilterSources(context.Background(), []string{first, second})
	if err != nil {
		t.Fatalf("load privacy filter sources: %v", err)
	}
	for _, ruleID := range []string{"generic-api-key", "pii-email"} {
		if _, ok := filter.detector.Config.Rules[ruleID]; ok {
			t.Fatalf("disabled rule %q remains active", ruleID)
		}
	}
	if _, ok := filter.detector.Config.Rules["github-pat"]; !ok {
		t.Fatal("unrelated inherited default rule was removed")
	}
	for _, finding := range filter.detector.DetectString("api_key = 'abcdefghijklmnopqrstuvwxyz123456'") {
		if finding.RuleID == "generic-api-key" {
			t.Fatalf("disabled generic-api-key still detected: %+v", finding)
		}
	}
}

func TestLoadPrivacyFilterMergesURLAndLocalSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(gitleaksRuleTOML("url-secret", "URLSECRET[0-9]+", "URLSECRET")))
	}))
	defer server.Close()

	dir := t.TempDir()
	local := filepath.Join(dir, "local.toml")
	if err := os.WriteFile(local, []byte(gitleaksRuleTOML("local-secret", "LOCALSECRET[0-9]+", "LOCALSECRET")), 0o600); err != nil {
		t.Fatalf("write local toml: %v", err)
	}

	filter, err := loadPrivacyFilterSources(context.Background(), []string{server.URL, local})
	if err != nil {
		t.Fatalf("load privacy filter sources: %v", err)
	}
	if res := filter.RedactString("value URLSECRET123"); !res.Hit {
		t.Fatalf("expected URL rule to redact, got %+v", res)
	}
	if res := filter.RedactString("value LOCALSECRET123"); !res.Hit {
		t.Fatalf("expected local rule to redact, got %+v", res)
	}
}

func TestStartFilterRefreshReplacesURLRules(t *testing.T) {
	var toml atomic.Value
	toml.Store(gitleaksRuleTOML("first-secret", "FIRSTSECRET[0-9]+", "FIRSTSECRET"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(toml.Load().(string)))
	}))
	defer server.Close()

	store := filterStore{}
	cancel, done, err := startFilterRefresh(context.Background(), []string{server.URL}, 10*time.Millisecond, false, zap.NewNop(), store.Store)
	if err != nil {
		t.Fatalf("start filter refresh: %v", err)
	}
	defer func() {
		cancel()
		<-done
	}()

	if res := store.Load().RedactString("value FIRSTSECRET123"); !res.Hit {
		t.Fatalf("expected initial URL rule to redact, got %+v", res)
	}

	toml.Store(gitleaksRuleTOML("second-secret", "SECONDSECRET[0-9]+", "SECONDSECRET"))
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for refreshed URL rule")
		case <-tick.C:
			if res := store.Load().RedactString("value SECONDSECRET123"); res.Hit {
				return
			}
		}
	}
}

func TestStartFilterRefreshURLFailureFallsBackWhenFailOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	store := filterStore{}
	cancel, done, err := startFilterRefresh(context.Background(), []string{server.URL}, time.Hour, true, zap.NewNop(), store.Store)
	if err != nil {
		t.Fatalf("expected fallback to built-in rules, got error: %v", err)
	}
	defer func() {
		cancel()
		<-done
	}()

	if store.Load() == nil {
		t.Fatal("expected built-in filter to be stored after fallback")
	}
}

func TestStartFilterRefreshURLFailureFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	store := filterStore{}
	cancel, done, err := startFilterRefresh(context.Background(), []string{server.URL}, time.Hour, false, zap.NewNop(), store.Store)
	if err == nil {
		cancel()
		<-done
		t.Fatal("expected startup to fail when a URL source fails and fail_open is false")
	}
}

func TestStartFilterRefreshLocalFailureNeverDegrades(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.toml")

	store := filterStore{}
	cancel, done, err := startFilterRefresh(context.Background(), []string{missing}, 0, true, zap.NewNop(), store.Store)
	if err == nil {
		cancel()
		<-done
		t.Fatal("expected startup to fail for a missing local source even with fail_open")
	}
}

func TestStartFilterRefreshMixedFailureNeverDegrades(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	local := filepath.Join(t.TempDir(), "local.toml")
	if err := os.WriteFile(local, []byte(gitleaksRuleTOML("local-secret", "LOCALSECRET[0-9]+", "LOCALSECRET")), 0o600); err != nil {
		t.Fatalf("write local toml: %v", err)
	}

	store := filterStore{}
	cancel, done, err := startFilterRefresh(context.Background(), []string{server.URL, local}, time.Hour, true, zap.NewNop(), store.Store)
	if err == nil {
		cancel()
		<-done
		t.Fatal("expected startup to fail for a mixed source set even with fail_open")
	}
}

func gitleaksRuleTOML(id, regex, keyword string) string {
	return fmt.Sprintf(`[[rules]]
id = "%s"
regex = '''%s'''
keywords = ["%s"]
`, id, regex, keyword)
}
