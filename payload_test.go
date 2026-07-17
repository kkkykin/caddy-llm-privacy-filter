package llmprivacyfilter

import (
	"encoding/json"
	"strings"
	"testing"
)

var benchmarkRedactedString string

func newTestRedactor(t *testing.T) payloadRedactor {
	t.Helper()
	f, err := NewGitleaksFilter(nil)
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	return newPayloadRedactor(f)
}

func BenchmarkRedactString(b *testing.B) {
	f, err := NewGitleaksFilter(nil)
	if err != nil {
		b.Fatalf("new filter: %v", err)
	}

	redactor := newPayloadRedactor(f)
	content := benchmarkOpenAIChatContent()
	body := benchmarkOpenAIChatBody(content)
	var summary RedactSummary
	got := redactor.redactString(content, &summary)
	if !summary.Changed || summary.Entities != 1 {
		b.Fatalf("unexpected redaction summary: %+v", summary)
	}
	if strings.Contains(got, "owner@example.com") || !strings.Contains(got, "[redacted:pii-email]") {
		b.Fatalf("email was not redacted: %q", got)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summary = RedactSummary{}
		got = redactor.redactString(content, &summary)
	}
	b.ReportMetric(float64(len(body)), "body_B")
	benchmarkRedactedString = got
}

func benchmarkOpenAIChatContent() string {
	paragraph := "Review the deployment plan, summarize the tradeoffs, and explain each recommendation in plain language. " +
		"The service validates headers, parses JSON, records metrics, and returns a concise response to the caller. " +
		"Include failure handling, rollout steps, and a short verification checklist for the operations team.\n"
	return strings.Repeat(paragraph, 16) +
		"Send the final review to owner@example.com after the checks complete."
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
