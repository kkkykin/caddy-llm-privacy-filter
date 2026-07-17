package llmprivacyfilter

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

var (
	benchmarkRedactedString string
	benchmarkRegexMatches   [][]int
)

const benchmarkSRIHash = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

func newTestRedactor(t *testing.T) payloadRedactor {
	t.Helper()
	f, err := NewGitleaksFilter(nil)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	return newPayloadRedactor(f, nil)
}

func BenchmarkRedactString(b *testing.B) {
	f, err := NewGitleaksFilter(nil)
	if err != nil {
		b.Fatalf("new filter: %v", err)
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`sha256-[A-Za-z0-9+/]{43}=`),
		regexp.MustCompile(`myapp_[A-Za-z0-9]{32}`),
	}
	ordinaryContent := benchmarkOpenAIChatContent(strings.Repeat("x", len(benchmarkSRIHash)))
	protectedContent := benchmarkOpenAIChatContent(benchmarkSRIHash)

	benchmarks := []struct {
		name     string
		redactor payloadRedactor
		content  string
		wantSRI  bool
	}{
		{
			name:     "no_skip_regex",
			redactor: newPayloadRedactor(f, nil),
			content:  ordinaryContent,
		},
		{
			name:     "skip_regex_no_match_2_rules",
			redactor: newPayloadRedactor(f, patterns),
			content:  ordinaryContent,
		},
		{
			name:     "skip_regex_match_sri",
			redactor: newPayloadRedactor(f, patterns),
			content:  protectedContent,
			wantSRI:  true,
		},
	}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			body := benchmarkOpenAIChatBody(benchmark.content)
			var summary RedactSummary
			got := benchmark.redactor.redactString(benchmark.content, &summary)
			if !summary.Changed || summary.Entities != 1 {
				b.Fatalf("unexpected redaction summary: %+v", summary)
			}
			if strings.Contains(got, "owner@example.com") || !strings.Contains(got, "[邮箱]") {
				b.Fatalf("email was not redacted: %q", got)
			}
			if benchmark.wantSRI && !strings.Contains(got, benchmarkSRIHash) {
				b.Fatalf("SRI hash was not protected: %q", got)
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(benchmark.content)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				summary = RedactSummary{}
				got = benchmark.redactor.redactString(benchmark.content, &summary)
			}
			b.ReportMetric(float64(len(body)), "body_B")
			benchmarkRedactedString = got
		})
	}
}

func BenchmarkSkipRegexScan(b *testing.B) {
	sriPattern := regexp.MustCompile(`sha256-[A-Za-z0-9+/]{43}=`)
	tokenPattern := regexp.MustCompile(`myapp_[A-Za-z0-9]{32}`)
	ordinaryContent := benchmarkOpenAIChatContent(strings.Repeat("x", len(benchmarkSRIHash)))
	protectedContent := benchmarkOpenAIChatContent(benchmarkSRIHash)

	benchmarks := []struct {
		name     string
		text     string
		patterns []*regexp.Regexp
	}{
		{
			name:     "random_token_32B_no_match",
			text:     "J7pQ2mV9xK4cN8rT6wY3aF5hL0sD1zBq",
			patterns: []*regexp.Regexp{sriPattern},
		},
		{
			name:     "openai_content_no_match",
			text:     ordinaryContent,
			patterns: []*regexp.Regexp{sriPattern},
		},
		{
			name:     "openai_content_no_match_2_rules",
			text:     ordinaryContent,
			patterns: []*regexp.Regexp{sriPattern, tokenPattern},
		},
		{
			name:     "openai_content_match",
			text:     protectedContent,
			patterns: []*regexp.Regexp{sriPattern},
		},
	}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(benchmark.text)))
			var matches [][]int
			for i := 0; i < b.N; i++ {
				for _, pattern := range benchmark.patterns {
					matches = pattern.FindAllStringSubmatchIndex(benchmark.text, -1)
				}
			}
			benchmarkRegexMatches = matches
		})
	}
}

func benchmarkOpenAIChatContent(integrity string) string {
	paragraph := "Review the deployment plan, summarize the tradeoffs, and explain each recommendation in plain language. " +
		"The service validates headers, parses JSON, records metrics, and returns a concise response to the caller. " +
		"Include failure handling, rollout steps, and a short verification checklist for the operations team.\n"
	return strings.Repeat(paragraph, 16) +
		"The frontend integrity value is " + integrity +
		". Send the final review to owner@example.com after the checks complete."
}

func benchmarkOpenAIChatBody(content string) []byte {
	body, err := json.Marshal(map[string]any{
		"model": "gpt-4.1",
		"messages": []map[string]string{
			{"role": "system", "content": "You are a careful production reviewer."},
			{"role": "user", "content": content},
		},
		"temperature": 0.2,
	})
	if err != nil {
		panic(err)
	}
	return body
}

func TestSkipRegexSkipsRedaction(t *testing.T) {
	f, err := NewGitleaksFilter(nil)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	tokenPattern := regexp.MustCompile(`myapp_[A-Za-z0-9]{32}`)
	var token string
	var unprotected string
	for attempt := 0; attempt < 100; attempt++ {
		randomBytes := make([]byte, 24)
		if _, err := rand.Read(randomBytes); err != nil {
			t.Fatalf("generate high-entropy token: %v", err)
		}
		token = "myapp_" + base64.StdEncoding.EncodeToString(randomBytes)[:32]
		if !tokenPattern.MatchString(token) {
			continue
		}
		unprotected = f.RedactString(token).Redacted
		if unprotected == "[密钥]" {
			break
		}
	}
	if unprotected != "[密钥]" {
		t.Fatalf("unprotected high-entropy token was not redacted as a key: %q -> %q", token, unprotected)
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`a@example[.]com`),
		tokenPattern,
	}
	redactor := newPayloadRedactor(f, patterns)
	body := []byte(`{"model":"gpt-compatible","messages":[{"role":"user","content":"keep a@example.com and ` + token + `, redact b@example.com"}]}`)

	out, summary, err := redactor.RedactJSON(body, apiOpenAI)
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	text := string(out)
	if !summary.Changed || summary.Entities != 1 {
		t.Fatalf("expected one non-protected redaction, got %+v in %s", summary, text)
	}
	if !strings.Contains(text, "a@example.com") || !strings.Contains(text, token) {
		t.Fatalf("skip_regex fragments were changed: %s", text)
	}
	if strings.Contains(text, "b@example.com") || !strings.Contains(text, "[邮箱]") {
		t.Fatalf("non-protected email was not redacted: %s", text)
	}
}

func TestSkipRegexProtectsSRIHashAlongsideEmail(t *testing.T) {
	f, err := NewGitleaksFilter(nil)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}

	var sri string
	var unprotected string
	for attempt := 0; attempt < 100; attempt++ {
		digest := make([]byte, 32)
		if _, err := rand.Read(digest); err != nil {
			t.Fatalf("generate SRI digest: %v", err)
		}
		sri = "sha256-" + base64.StdEncoding.EncodeToString(digest)
		unprotected = f.RedactString(sri).Redacted
		if unprotected == "[密钥]" {
			break
		}
	}
	if unprotected != "[密钥]" {
		t.Fatalf("unprotected SRI hash was not redacted as a key: %q", unprotected)
	}

	redactor := newPayloadRedactor(f, []*regexp.Regexp{
		regexp.MustCompile(`sha256-[A-Za-z0-9+/]{43}=`),
	})
	body := []byte(`{"model":"gpt-compatible","messages":[{"role":"user","content":"` + sri + ` and owner@example.com"}]}`)

	out, summary, err := redactor.RedactJSON(body, apiOpenAI)
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	text := string(out)
	if !summary.Changed || summary.Entities != 1 {
		t.Fatalf("expected only the email to be redacted, got %+v in %s", summary, text)
	}
	if !strings.Contains(text, sri+" and [邮箱]") {
		t.Fatalf("SRI hash was not preserved beside the redacted email: %s", text)
	}
	if strings.Contains(text, "owner@example.com") {
		t.Fatalf("email was not redacted: %s", text)
	}
}

func TestMergeSpans(t *testing.T) {
	spans := [][2]int{{8, 12}, {1, 5}, {3, 9}, {12, 14}, {20, 24}, {21, 23}}
	want := [][2]int{{1, 12}, {12, 14}, {20, 24}}
	got := mergeSpans(spans)
	if len(got) != len(want) {
		t.Fatalf("mergeSpans = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mergeSpans = %#v, want %#v", got, want)
		}
	}
}

func TestRedactOpenAICompatibleChat(t *testing.T) {
	redactor := newTestRedactor(t)
	body := []byte(`{
		"model":"gpt-compatible",
		"messages":[
			{"role":"system","content":"不要泄露 token sk-proj-vW8qN4mZ2cR7tY9pL5xK3dH6sF1aB0uE"},
			{"role":"user","content":[{"type":"text","text":"邮箱 a@example.com，电话 13800138000"}]},
			{"role":"assistant","tool_calls":[{"type":"function","function":{"name":"lookup","arguments":"{\"email\":\"b@example.com\"}"}}]}
		]
	}`)

	out, summary, err := redactor.RedactJSON(body, apiOpenAI)
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	if !summary.Changed || summary.Entities < 4 {
		t.Fatalf("expected redactions, got %+v in %s", summary, out)
	}
	text := string(out)
	for _, sensitive := range []string{"a@example.com", "13800138000", "b@example.com", "sk-proj-vW8qN4mZ2cR7tY9pL5xK3dH6sF1aB0uE"} {
		if strings.Contains(text, sensitive) {
			t.Fatalf("sensitive value %q remained in %s", sensitive, text)
		}
	}
}

func TestRedactResponsesAPI(t *testing.T) {
	redactor := newTestRedactor(t)
	body := []byte(`{
		"model":"gpt-4.1",
		"instructions":"联系我：owner@example.com",
		"input":[
			{"role":"user","content":[{"type":"input_text","text":"我的 IP 是 192.168.1.10"}]},
			{"type":"function_call_output","call_id":"call_1","output":"结果包含 user@example.com"}
		]
	}`)

	out, summary, err := redactor.RedactJSON(body, apiResponses)
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	if !summary.Changed || summary.Entities != 3 {
		t.Fatalf("expected three redactions, got %+v in %s", summary, out)
	}
	text := string(out)
	for _, sensitive := range []string{"owner@example.com", "192.168.1.10", "user@example.com"} {
		if strings.Contains(text, sensitive) {
			t.Fatalf("sensitive value %q remained in %s", sensitive, text)
		}
	}
}

func TestRedactAnthropicMessages(t *testing.T) {
	redactor := newTestRedactor(t)
	body := []byte(`{
		"model":"claude-3-5-sonnet",
		"system":[{"type":"text","text":"管理员邮箱 admin@example.com"}],
		"messages":[
			{"role":"user","content":"手机号 13900139000"},
			{"role":"user","content":[
				{"type":"text","text":"身份证 11010519491231002X"},
				{"type":"tool_use","id":"toolu_1","name":"lookup","input":{"email":"tool@example.com","id":"keep-this-id"}}
			]}
		]
	}`)

	out, summary, err := redactor.RedactJSON(body, apiAnthropic)
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	if !summary.Changed || summary.Entities != 4 {
		t.Fatalf("expected four redactions, got %+v in %s", summary, out)
	}
	text := string(out)
	for _, sensitive := range []string{"admin@example.com", "13900139000", "11010519491231002X", "tool@example.com"} {
		if strings.Contains(text, sensitive) {
			t.Fatalf("sensitive value %q remained in %s", sensitive, text)
		}
	}
	if !strings.Contains(text, "keep-this-id") {
		t.Fatalf("metadata id should be preserved in %s", text)
	}
}

func TestAutoDetectByBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		want apiMode
	}{
		{
			name: "responses",
			body: `{"model":"gpt-4.1","input":"email a@example.com"}`,
			want: apiResponses,
		},
		{
			name: "openai compatible",
			body: `{"model":"gpt-compatible","messages":[{"role":"user","content":"email a@example.com"}]}`,
			want: apiOpenAI,
		},
		{
			name: "anthropic",
			body: `{"model":"claude-3-5-sonnet","max_tokens":64,"messages":[{"role":"user","content":"email a@example.com"}]}`,
			want: apiAnthropic,
		},
		{
			name: "unknown",
			body: `{"text":"email a@example.com"}`,
			want: apiAuto,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc any
			if err := json.Unmarshal([]byte(tt.body), &doc); err != nil {
				t.Fatalf("unmarshal body: %v", err)
			}
			if got := detectAPIMode(doc); got != tt.want {
				t.Fatalf("detectAPIMode = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRedactedJSONRemainsValid(t *testing.T) {
	redactor := newTestRedactor(t)
	body := []byte(`{"model":"gpt-compatible","messages":[{"role":"user","content":"a@example.com"}]}`)
	out, summary, err := redactor.RedactJSON(body, apiAuto)
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	if !summary.Changed {
		t.Fatal("expected redaction")
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("redacted output is invalid JSON: %v", err)
	}
}

func TestAutoPassesThroughUnknownBody(t *testing.T) {
	redactor := newTestRedactor(t)
	body := []byte(`{"text":"a@example.com"}`)
	out, summary, err := redactor.RedactJSON(body, apiAuto)
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	if summary.Changed {
		t.Fatalf("unexpected redaction summary: %+v", summary)
	}
	if string(out) != string(body) {
		t.Fatalf("expected passthrough body %s, got %s", body, out)
	}
}
