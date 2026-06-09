package llmprivacyfilter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	if res := filter.Redact("value TESTSECRET123"); !res.Hit {
		t.Fatalf("expected URL rule to redact, got %+v", res)
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
	cancel, done, err := startFilterRefresh(context.Background(), server.URL, 10*time.Millisecond, zap.NewNop(), store.Store)
	if err != nil {
		t.Fatalf("start filter refresh: %v", err)
	}
	defer func() {
		cancel()
		<-done
	}()

	if res := store.Load().Redact("value FIRSTSECRET123"); !res.Hit {
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
			if res := store.Load().Redact("value SECONDSECRET123"); res.Hit {
				return
			}
		}
	}
}

func gitleaksRuleTOML(id, regex, keyword string) string {
	return fmt.Sprintf(`[[rules]]
id = "%s"
regex = '''%s'''
keywords = ["%s"]
`, id, regex, keyword)
}
