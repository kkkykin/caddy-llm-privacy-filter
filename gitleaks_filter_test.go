package llmprivacyfilter

import (
	"strings"
	"testing"
)

func TestGitleaksFilterRedactBytes(t *testing.T) {
	filter, err := NewGitleaksFilter(nil)
	if err != nil {
		t.Fatalf("new gitleaks filter: %v", err)
	}
	input := []byte("email owner@example.com phone 13800138000 ip 192.168.1.10 key sk-proj-vW8qN4mZ2cR7tY9pL5xK3dH6sF1aB0uE")
	out, err := filter.Redact(input)
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	text := string(out)
	for _, sensitive := range []string{"owner@example.com", "13800138000", "192.168.1.10", "sk-proj-vW8qN4mZ2cR7tY9pL5xK3dH6sF1aB0uE"} {
		if strings.Contains(text, sensitive) {
			t.Fatalf("sensitive value %q remained in %q", sensitive, text)
		}
	}
	for _, label := range []string{
		"[redacted:pii-email]",
		"[redacted:pii-phone-cn]",
		"[redacted:pii-ipv4]",
		"[redacted:privacy-high-entropy]",
	} {
		if !strings.Contains(text, label) {
			t.Fatalf("label %q missing from %q", label, text)
		}
	}
}

func TestGitleaksFilterEntityOffsets(t *testing.T) {
	filter, err := NewGitleaksFilter(nil)
	if err != nil {
		t.Fatalf("new gitleaks filter: %v", err)
	}
	input := "first owner@example.com\nsecond user@example.com"
	result := filter.RedactString(input)
	if result.Count != 2 {
		t.Fatalf("count = %d, want 2: %+v", result.Count, result)
	}
	for _, entity := range result.Entities {
		if got := input[entity.Start:entity.End]; got != entity.Text {
			t.Fatalf("entity range [%d:%d] = %q, want %q", entity.Start, entity.End, got, entity.Text)
		}
		if entity.Type != "[redacted:pii-email]" {
			t.Fatalf("entity type = %q, want [redacted:pii-email]", entity.Type)
		}
	}
}

func TestGitleaksFilterPIIValidators(t *testing.T) {
	filter, err := NewGitleaksFilter(nil)
	if err != nil {
		t.Fatalf("new gitleaks filter: %v", err)
	}
	input := "ssh git@example.com and invalid card 4111111111111112, valid card 4111111111111111"
	result := filter.RedactString(input)
	if !strings.Contains(result.Redacted, "git@example.com") {
		t.Fatalf("SSH target was redacted: %q", result.Redacted)
	}
	if !strings.Contains(result.Redacted, "4111111111111112") {
		t.Fatalf("invalid Luhn number was redacted: %q", result.Redacted)
	}
	if strings.Contains(result.Redacted, "4111111111111111") || !strings.Contains(result.Redacted, "[redacted:pii-bank-card]") {
		t.Fatalf("valid bank card was not redacted correctly: %q", result.Redacted)
	}
}

func TestGitleaksFilterCustomRuleExtendsDefaults(t *testing.T) {
	filter, err := NewGitleaksFilter([]byte(gitleaksRuleTOML("internal-token", "INTERNAL_[A-Z0-9]{16}", "INTERNAL_")))
	if err != nil {
		t.Fatalf("new gitleaks filter: %v", err)
	}
	result := filter.RedactString("INTERNAL_1234567890ABCDEF and owner@example.com")
	if result.Count != 2 {
		t.Fatalf("count = %d, want custom secret plus built-in PII: %+v", result.Count, result)
	}
	if strings.Contains(result.Redacted, "INTERNAL_1234567890ABCDEF") || strings.Contains(result.Redacted, "owner@example.com") {
		t.Fatalf("custom/default rules were not both applied: %q", result.Redacted)
	}
	for _, label := range []string{"[redacted:internal-token]", "[redacted:pii-email]"} {
		if !strings.Contains(result.Redacted, label) {
			t.Fatalf("label %q missing from %q", label, result.Redacted)
		}
	}
}

func TestGitleaksFilterGlobalAllowlistRegex(t *testing.T) {
	toml := []byte(`
[[rules]]
id = "internal-token"
regex = '''INTERNAL_[A-Z0-9]{16}'''
keywords = ["INTERNAL_"]

[[allowlists]]
regexes = ['''^INTERNAL_ALLOWLISTED$''']
`)
	filter, err := NewGitleaksFilter(toml)
	if err != nil {
		t.Fatalf("new gitleaks filter: %v", err)
	}
	result := filter.RedactString("INTERNAL_ALLOWLISTED INTERNAL_1234567890ABCDEF owner@example.com")
	if !strings.Contains(result.Redacted, "INTERNAL_ALLOWLISTED") {
		t.Fatalf("global allowlist did not preserve token: %q", result.Redacted)
	}
	if strings.Contains(result.Redacted, "INTERNAL_1234567890ABCDEF") || strings.Contains(result.Redacted, "owner@example.com") {
		t.Fatalf("non-allowlisted findings were not redacted: %q", result.Redacted)
	}
}

func TestGitleaksFilterPerRuleAllowlistRegex(t *testing.T) {
	toml := []byte(`
[[rules]]
id = "internal-token"
regex = '''INTERNAL_[A-Z0-9]{16}'''
keywords = ["INTERNAL_"]

    [[rules.allowlists]]
    regexes = ['''^INTERNAL_ALLOWLISTED$''']
`)
	filter, err := NewGitleaksFilter(toml)
	if err != nil {
		t.Fatalf("new gitleaks filter: %v", err)
	}
	result := filter.RedactString("INTERNAL_ALLOWLISTED INTERNAL_1234567890ABCDEF")
	if !strings.Contains(result.Redacted, "INTERNAL_ALLOWLISTED") || strings.Contains(result.Redacted, "INTERNAL_1234567890ABCDEF") {
		t.Fatalf("per-rule allowlist result = %q", result.Redacted)
	}
}

func TestGitleaksFilterTargetedGlobalAllowlistForBuiltinRule(t *testing.T) {
	toml := []byte(`
[[allowlists]]
targetRules = ["pii-email"]
regexes = ['''^allowed@example[.]com$''']
`)
	filter, err := NewGitleaksFilter(toml)
	if err != nil {
		t.Fatalf("new gitleaks filter: %v", err)
	}
	result := filter.RedactString("allowed@example.com blocked@example.com")
	if !strings.Contains(result.Redacted, "allowed@example.com") || strings.Contains(result.Redacted, "blocked@example.com") {
		t.Fatalf("targeted global allowlist result = %q", result.Redacted)
	}
}

func TestGitleaksFilterAllowlistStopword(t *testing.T) {
	toml := []byte(`
[[rules]]
id = "internal-token"
regex = '''TOKEN_[A-Z0-9]{16}'''

    [[rules.allowlists]]
    stopwords = ["allow"]
`)
	filter, err := NewGitleaksFilter(toml)
	if err != nil {
		t.Fatalf("new gitleaks filter: %v", err)
	}
	result := filter.RedactString("TOKEN_ALLOW12345678901 TOKEN_BLOCK12345678901")
	if !strings.Contains(result.Redacted, "TOKEN_ALLOW12345678901") || strings.Contains(result.Redacted, "TOKEN_BLOCK12345678901") {
		t.Fatalf("stopword allowlist result = %q", result.Redacted)
	}
}

func TestGitleaksFilterRejectsUnknownAllowlistTargetRule(t *testing.T) {
	_, err := NewGitleaksFilter([]byte(`
[[allowlists]]
targetRules = ["missing-rule"]
regexes = ['''allowed''']
`))
	if err == nil || !strings.Contains(err.Error(), "missing-rule") {
		t.Fatalf("expected unknown target rule error, got %v", err)
	}
}
