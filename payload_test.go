package llmprivacyfilter

import (
	"encoding/json"
	"strings"
	"testing"

	pf "privacyfilter/filter"
)

func newTestRedactor(t *testing.T) payloadRedactor {
	t.Helper()
	f, err := pf.New("")
	if err != nil {
		t.Fatalf("new filter: %v", err)
	}
	return newPayloadRedactor(f)
}

func TestRedactOpenAICompatibleChat(t *testing.T) {
	redactor := newTestRedactor(t)
	body := []byte(`{
		"model":"gpt-compatible",
		"messages":[
			{"role":"system","content":"不要泄露 token sk-proj-abcdefghijklmnopqrstuvwxyz"},
			{"role":"user","content":[{"type":"text","text":"邮箱 a@example.com，电话 13800138000"}]},
			{"role":"assistant","tool_calls":[{"type":"function","function":{"name":"lookup","arguments":"{\"email\":\"b@example.com\"}"}}]}
		]
	}`)

	out, summary, err := redactor.RedactJSON(body, apiOpenAI, "/v1/chat/completions")
	if err != nil {
		t.Fatalf("redact JSON: %v", err)
	}
	if !summary.Changed || summary.Entities < 4 {
		t.Fatalf("expected redactions, got %+v in %s", summary, out)
	}
	text := string(out)
	for _, sensitive := range []string{"a@example.com", "13800138000", "b@example.com", "sk-proj-abcdefghijklmnopqrstuvwxyz"} {
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

	out, summary, err := redactor.RedactJSON(body, apiResponses, "/v1/responses")
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

	out, summary, err := redactor.RedactJSON(body, apiAnthropic, "/v1/messages")
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

func TestAutoDetectByPath(t *testing.T) {
	if got := detectAPIMode("/v1/responses", map[string]any{}); got != apiResponses {
		t.Fatalf("responses path detected as %s", got)
	}
	if got := detectAPIMode("/v1/chat/completions", map[string]any{}); got != apiOpenAI {
		t.Fatalf("chat completions path detected as %s", got)
	}
	if got := detectAPIMode("/v1/messages", map[string]any{}); got != apiAnthropic {
		t.Fatalf("messages path detected as %s", got)
	}
}

func TestRedactedJSONRemainsValid(t *testing.T) {
	redactor := newTestRedactor(t)
	body := []byte(`{"messages":[{"role":"user","content":"a@example.com"}]}`)
	out, summary, err := redactor.RedactJSON(body, apiAuto, "/v1/chat/completions")
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
