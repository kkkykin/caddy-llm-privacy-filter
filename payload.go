package llmprivacyfilter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	pf "privacyfilter/filter"
)

type apiMode string

const (
	apiAuto      apiMode = "auto"
	apiOpenAI    apiMode = "openai"
	apiResponses apiMode = "responses"
	apiAnthropic apiMode = "anthropic-message"
)

type RedactSummary struct {
	Changed  bool
	Entities int
}

type payloadRedactor struct {
	filter *pf.Filter
}

func newPayloadRedactor(f *pf.Filter) payloadRedactor {
	return payloadRedactor{filter: f}
}

func parseAPIMode(v string) (apiMode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto":
		return apiAuto, nil
	case "openai", "openai-compatible", "openai_compatible", "openai-compatible-chat", "chat-completions", "chat_completions":
		return apiOpenAI, nil
	case "responses", "openai-responses", "openai_responses":
		return apiResponses, nil
	case "anthropic", "anthropic-message", "anthropic-messages", "anthropic_message", "anthropic_messages", "messages":
		return apiAnthropic, nil
	default:
		return "", fmt.Errorf("unsupported api %q", v)
	}
}

func (pr payloadRedactor) RedactJSON(body []byte, mode apiMode, path string) ([]byte, RedactSummary, error) {
	var doc any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, RedactSummary{}, fmt.Errorf("decode JSON body: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, RedactSummary{}, fmt.Errorf("decode JSON body: trailing data")
	}

	summary := RedactSummary{}
	pr.redactForMode(doc, mode, path, &summary)
	if !summary.Changed {
		return body, summary, nil
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, RedactSummary{}, fmt.Errorf("encode redacted JSON body: %w", err)
	}
	return out, summary, nil
}

func (pr payloadRedactor) redactForMode(doc any, mode apiMode, path string, summary *RedactSummary) {
	if mode == apiAuto {
		detected := detectAPIMode(path, doc)
		if detected != apiAuto {
			pr.redactForMode(doc, detected, path, summary)
			return
		}
		pr.redactOpenAI(doc, summary)
		pr.redactResponses(doc, summary)
		pr.redactAnthropic(doc, summary)
		return
	}

	switch mode {
	case apiOpenAI:
		pr.redactOpenAI(doc, summary)
	case apiResponses:
		pr.redactResponses(doc, summary)
	case apiAnthropic:
		pr.redactAnthropic(doc, summary)
	}
}

func detectAPIMode(path string, doc any) apiMode {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "/responses"):
		return apiResponses
	case strings.Contains(p, "/chat/completions"), strings.Contains(p, "/completions"), strings.Contains(p, "/embeddings"):
		return apiOpenAI
	case strings.Contains(p, "/messages"):
		return apiAnthropic
	}

	root, ok := doc.(map[string]any)
	if !ok {
		return apiAuto
	}
	if _, hasInput := root["input"]; hasInput {
		return apiResponses
	}
	if _, hasMessages := root["messages"]; hasMessages {
		if _, hasSystem := root["system"]; hasSystem {
			return apiAnthropic
		}
		return apiOpenAI
	}
	if _, hasPrompt := root["prompt"]; hasPrompt {
		return apiOpenAI
	}
	return apiAuto
}

func (pr payloadRedactor) redactOpenAI(doc any, summary *RedactSummary) {
	root, ok := doc.(map[string]any)
	if !ok {
		return
	}
	pr.redactField(root, "instructions", summary, pr.redactTextValue)
	pr.redactField(root, "prompt", summary, pr.redactTextValue)
	pr.redactField(root, "input", summary, pr.redactTextValue)
	pr.redactField(root, "messages", summary, pr.redactOpenAIMessages)
}

func (pr payloadRedactor) redactOpenAIMessages(v any, summary *RedactSummary) any {
	items, ok := v.([]any)
	if !ok {
		return v
	}
	for _, item := range items {
		msg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		pr.redactField(msg, "content", summary, pr.redactContent)
		pr.redactField(msg, "function_call", summary, pr.redactFunctionCall)
		pr.redactField(msg, "tool_calls", summary, pr.redactToolCalls)
	}
	return v
}

func (pr payloadRedactor) redactFunctionCall(v any, summary *RedactSummary) any {
	fn, ok := v.(map[string]any)
	if !ok {
		return v
	}
	pr.redactField(fn, "arguments", summary, pr.redactTextValue)
	return v
}

func (pr payloadRedactor) redactToolCalls(v any, summary *RedactSummary) any {
	items, ok := v.([]any)
	if !ok {
		return v
	}
	for _, item := range items {
		call, ok := item.(map[string]any)
		if !ok {
			continue
		}
		pr.redactField(call, "function", summary, pr.redactFunctionCall)
	}
	return v
}

func (pr payloadRedactor) redactResponses(doc any, summary *RedactSummary) {
	root, ok := doc.(map[string]any)
	if !ok {
		return
	}
	pr.redactField(root, "instructions", summary, pr.redactTextValue)
	pr.redactField(root, "input", summary, pr.redactResponsesInput)
}

func (pr payloadRedactor) redactResponsesInput(v any, summary *RedactSummary) any {
	switch x := v.(type) {
	case string:
		return pr.redactString(x, summary)
	case []any:
		for i, item := range x {
			x[i] = pr.redactResponsesInput(item, summary)
		}
	case map[string]any:
		pr.redactField(x, "content", summary, pr.redactContent)
		pr.redactField(x, "text", summary, pr.redactTextValue)
		pr.redactField(x, "output", summary, pr.redactTextValue)
	}
	return v
}

func (pr payloadRedactor) redactAnthropic(doc any, summary *RedactSummary) {
	root, ok := doc.(map[string]any)
	if !ok {
		return
	}
	pr.redactField(root, "system", summary, pr.redactContent)
	pr.redactField(root, "messages", summary, pr.redactAnthropicMessages)
}

func (pr payloadRedactor) redactAnthropicMessages(v any, summary *RedactSummary) any {
	items, ok := v.([]any)
	if !ok {
		return v
	}
	for _, item := range items {
		msg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		pr.redactField(msg, "content", summary, pr.redactAnthropicContent)
	}
	return v
}

func (pr payloadRedactor) redactAnthropicContent(v any, summary *RedactSummary) any {
	switch x := v.(type) {
	case string:
		return pr.redactString(x, summary)
	case []any:
		for i, item := range x {
			x[i] = pr.redactAnthropicContent(item, summary)
		}
	case map[string]any:
		blockType, _ := x["type"].(string)
		switch blockType {
		case "text":
			pr.redactField(x, "text", summary, pr.redactTextValue)
		case "tool_result":
			pr.redactField(x, "content", summary, pr.redactAnthropicContent)
		case "tool_use":
			pr.redactField(x, "input", summary, pr.redactDeepStrings)
		default:
			pr.redactField(x, "content", summary, pr.redactAnthropicContent)
			pr.redactField(x, "text", summary, pr.redactTextValue)
		}
	}
	return v
}

func (pr payloadRedactor) redactContent(v any, summary *RedactSummary) any {
	switch x := v.(type) {
	case string:
		return pr.redactString(x, summary)
	case []any:
		for i, item := range x {
			x[i] = pr.redactContent(item, summary)
		}
	case map[string]any:
		blockType, _ := x["type"].(string)
		if isTextBlockType(blockType) {
			pr.redactField(x, "text", summary, pr.redactTextValue)
			pr.redactField(x, "content", summary, pr.redactContent)
			pr.redactField(x, "output", summary, pr.redactTextValue)
			return v
		}
		switch blockType {
		case "tool_result":
			pr.redactField(x, "content", summary, pr.redactContent)
		case "tool_use":
			pr.redactField(x, "input", summary, pr.redactDeepStrings)
		case "message", "":
			pr.redactField(x, "content", summary, pr.redactContent)
			pr.redactField(x, "text", summary, pr.redactTextValue)
		}
	}
	return v
}

func (pr payloadRedactor) redactTextValue(v any, summary *RedactSummary) any {
	switch x := v.(type) {
	case string:
		return pr.redactString(x, summary)
	case []any:
		for i, item := range x {
			x[i] = pr.redactTextValue(item, summary)
		}
	case map[string]any:
		pr.redactField(x, "content", summary, pr.redactContent)
		pr.redactField(x, "text", summary, pr.redactTextValue)
	}
	return v
}

func (pr payloadRedactor) redactDeepStrings(v any, summary *RedactSummary) any {
	switch x := v.(type) {
	case string:
		return pr.redactString(x, summary)
	case []any:
		for i, item := range x {
			x[i] = pr.redactDeepStrings(item, summary)
		}
	case map[string]any:
		for key, val := range x {
			if isMetadataKey(key) {
				continue
			}
			x[key] = pr.redactDeepStrings(val, summary)
		}
	}
	return v
}

func (pr payloadRedactor) redactField(m map[string]any, key string, summary *RedactSummary, redact func(any, *RedactSummary) any) {
	if val, ok := m[key]; ok {
		m[key] = redact(val, summary)
	}
}

func (pr payloadRedactor) redactString(s string, summary *RedactSummary) string {
	res := pr.filter.Redact(s)
	if !res.Hit {
		return s
	}
	summary.Changed = true
	summary.Entities += res.Count
	return res.Redacted
}

func isTextBlockType(t string) bool {
	switch strings.ToLower(t) {
	case "text", "input_text", "output_text":
		return true
	default:
		return false
	}
}

func isMetadataKey(key string) bool {
	switch strings.ToLower(key) {
	case "id", "type", "role", "name", "model", "call_id", "tool_call_id":
		return true
	default:
		return false
	}
}
