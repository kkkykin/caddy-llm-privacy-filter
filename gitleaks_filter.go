package llmprivacyfilter

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	gitleaksregexp "github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
)

// GitleaksFilter is the in-process redaction engine. The detector is built
// once and is safe to reuse for concurrent requests.
type GitleaksFilter struct {
	detector *detect.Detector
	skipped  int
}

// Redact scans input and replaces every detected secret or PII value. The
// returned bytes are always valid UTF-8 when input is valid UTF-8; gitleaks
// itself scans arbitrary bytes after the conversion to string.
func (f *GitleaksFilter) Redact(input []byte) ([]byte, error) {
	if f == nil || f.detector == nil {
		return nil, fmt.Errorf("gitleaks filter is not initialized")
	}
	result := f.redactString(string(input))
	return []byte(result.Redacted), nil
}

// RedactResult contains the redacted text and byte ranges of the original
// findings. Start and End are UTF-8 byte offsets used by the payload walker.
type RedactResult struct {
	Redacted string
	Hit      bool
	Count    int
	Entities []RedactEntity
}

type RedactEntity struct {
	Type  string
	Start int
	End   int
	Text  string
}

// RedactString is used by the JSON payload walker, which already operates on
// Go strings and needs entity counts for logging and tests.
func (f *GitleaksFilter) RedactString(input string) RedactResult {
	if f == nil || f.detector == nil {
		return RedactResult{Redacted: input}
	}
	return f.redactString(input)
}

func (f *GitleaksFilter) redactString(input string) RedactResult {
	findings := f.detector.DetectString(input)
	spans := make([]redactSpan, 0, len(findings))
	for _, finding := range findings {
		start, end, ok := locateFinding(input, finding)
		if !ok || !keepFinding(input, finding, start, end) {
			continue
		}
		spans = append(spans, redactSpan{
			start: start,
			end:   end,
			label: labelForRule(finding.RuleID),
		})
	}
	spans = mergeRedactSpans(spans)

	result := RedactResult{Redacted: input, Hit: len(spans) > 0, Count: len(spans)}
	if len(spans) == 0 {
		return result
	}
	var out strings.Builder
	out.Grow(len(input))
	result.Entities = make([]RedactEntity, len(spans))
	prev := 0
	for i, span := range spans {
		out.WriteString(input[prev:span.start])
		out.WriteString(span.label)
		result.Entities[i] = RedactEntity{
			Type:  span.label,
			Start: span.start,
			End:   span.end,
			Text:  input[span.start:span.end],
		}
		prev = span.end
	}
	out.WriteString(input[prev:])
	result.Redacted = out.String()
	return result
}

func (f *GitleaksFilter) Stats() (rules, skipped int) {
	if f == nil || f.detector == nil {
		return 0, 0
	}
	return len(f.detector.Config.Rules), f.skipped
}

type redactSpan struct {
	start int
	end   int
	label string
}

func mergeRedactSpans(spans []redactSpan) []redactSpan {
	valid := spans[:0]
	for _, span := range spans {
		if span.start >= 0 && span.start < span.end {
			valid = append(valid, span)
		}
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].start != valid[j].start {
			return valid[i].start < valid[j].start
		}
		if valid[i].end != valid[j].end {
			return valid[i].end > valid[j].end
		}
		// Prefer a structured PII label over the generic secret label when
		// two rules identify the exact same range.
		return valid[i].label != "[密钥]" && valid[j].label == "[密钥]"
	})
	merged := make([]redactSpan, 0, len(valid))
	lastEnd := -1
	for _, span := range valid {
		if span.start >= lastEnd {
			merged = append(merged, span)
			lastEnd = span.end
		}
	}
	return merged
}

// locateFinding converts gitleaks' 0-based line and 1-based byte column into
// an exact byte span. Finding.Secret is preferred over Match because rules
// with secretGroup may match surrounding assignment syntax.
func locateFinding(text string, finding report.Finding) (int, int, bool) {
	if finding.Secret == "" {
		return 0, 0, false
	}
	lineStarts := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	line := finding.StartLine
	if line < 0 || line >= len(lineStarts) {
		line = 0
	}
	lineStart := lineStarts[line]
	start := lineStart
	if finding.StartColumn > 0 {
		start += finding.StartColumn - 1
	}
	end := len(text)
	if line+1 < len(lineStarts) {
		end = lineStarts[line+1]
	}
	if start > end {
		start = end
	}
	if located, ok := closestOccurrence(text[lineStart:end], finding.Secret, start-lineStart); ok {
		start = lineStart + located
		return start, start + len(finding.Secret), true
	}
	// A multi-line match or a rule whose context starts on an earlier line may
	// not fit the single-line fast path. Restrict the fallback to the finding's
	// line range before searching globally.
	searchEnd := len(text)
	if finding.EndLine >= 0 && finding.EndLine+1 < len(lineStarts) {
		searchEnd = lineStarts[finding.EndLine+1]
	}
	if offset := strings.Index(text[start:searchEnd], finding.Secret); offset >= 0 {
		start += offset
		return start, start + len(finding.Secret), true
	}
	return 0, 0, false
}

func closestOccurrence(text, needle string, approximate int) (int, bool) {
	best := -1
	bestDistance := len(text) + 1
	for searchFrom := 0; searchFrom <= len(text); {
		offset := strings.Index(text[searchFrom:], needle)
		if offset < 0 {
			break
		}
		offset += searchFrom
		distance := offset - approximate
		if distance < 0 {
			distance = -distance
		}
		if distance < bestDistance {
			best = offset
			bestDistance = distance
		}
		searchFrom = offset + 1
	}
	return best, best >= 0
}

func labelForRule(ruleID string) string {
	switch strings.ToLower(ruleID) {
	case "pii-email", "email":
		return "[邮箱]"
	case "pii-phone-cn", "phone", "phone-cn":
		return "[电话]"
	case "pii-id-card-cn", "id-card", "身份证":
		return "[身份证]"
	case "pii-bank-card", "bank-card":
		return "[银行卡]"
	case "pii-ipv4", "ip", "ipv4":
		return "[IP]"
	default:
		return "[密钥]"
	}
}

func keepFinding(text string, finding report.Finding, start, end int) bool {
	switch strings.ToLower(finding.RuleID) {
	case "pii-email", "email":
		// user@host:path is an SSH/Git target rather than an email address.
		if end < len(text) && text[end] == ':' && end+1 < len(text) && text[end+1] != ' ' && text[end+1] != '\t' {
			return false
		}
		lineStart := strings.LastIndexByte(text[:start], '\n') + 1
		line := text[lineStart:start]
		for _, command := range []string{"ssh ", "scp ", "rsync ", "sftp ", "ssh-copy-id ", "ssh-keygen "} {
			if strings.Contains(line, command) {
				return false
			}
		}
	case "pii-phone-cn", "phone", "phone-cn", "pii-id-card-cn", "id-card", "身份证":
		return digitBounded(text, start, end)
	case "pii-ipv4", "ip", "ipv4":
		return ipBounded(text, start, end)
	case "pii-bank-card", "bank-card":
		return digitBounded(text, start, end) && luhnValid(text[start:end])
	case "privacy-high-entropy":
		candidate := text[start:end]
		if isHexHash(candidate) || isUUID(candidate) || isLikelyPlaceholder(candidate) {
			return false
		}
	}
	return true
}

func isDigitByte(b byte) bool { return b >= '0' && b <= '9' }

func digitBounded(text string, start, end int) bool {
	return (start == 0 || !isDigitByte(text[start-1])) && (end == len(text) || !isDigitByte(text[end]))
}

func ipBounded(text string, start, end int) bool {
	leftOK := start == 0 || (!isDigitByte(text[start-1]) && text[start-1] != '.')
	rightOK := end == len(text) || (!isDigitByte(text[end]) && text[end] != '.')
	return leftOK && rightOK
}

func luhnValid(number string) bool {
	sum := 0
	double := false
	for i := len(number) - 1; i >= 0; i-- {
		digit := int(number[i] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexPattern  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

func isHexHash(candidate string) bool {
	switch len(candidate) {
	case 32, 40, 64:
		return hexPattern.MatchString(candidate)
	default:
		return false
	}
}

func isUUID(candidate string) bool {
	return uuidPattern.MatchString(candidate)
}

func isLikelyPlaceholder(candidate string) bool {
	upper := strings.ToUpper(candidate)
	for _, placeholder := range []string{
		"REPLACE_ME", "REPLACE_THIS", "REPLACE_WITH", "YOUR_KEY", "YOUR_TOKEN",
		"YOUR_SECRET", "YOUR_API_KEY", "YOUR_PASSWORD", "INSERT_HERE", "PLACEHOLDER",
		"EXAMPLE_KEY", "EXAMPLE_TOKEN", "TODO", "FIXME", "XXXX",
	} {
		if strings.Contains(upper, placeholder) {
			return true
		}
	}
	return false
}

var (
	defaultConfigOnce sync.Once
	defaultConfig     config.Config
	defaultConfigErr  error
)

func baseGitleaksConfig() (config.Config, error) {
	defaultConfigOnce.Do(func() {
		detector, err := detect.NewDetectorDefaultConfig()
		if err != nil {
			defaultConfigErr = err
			return
		}
		defaultConfig = detector.Config
	})
	if defaultConfigErr != nil {
		return config.Config{}, defaultConfigErr
	}
	// Rule maps and slices are treated as immutable by Detector. Copy the
	// containers so each filter can append/override custom rules safely.
	cloned := defaultConfig
	cloned.Rules = make(map[string]config.Rule, len(defaultConfig.Rules))
	for id, rule := range defaultConfig.Rules {
		cloned.Rules[id] = rule
	}
	cloned.Keywords = make(map[string]struct{}, len(defaultConfig.Keywords))
	for keyword := range defaultConfig.Keywords {
		cloned.Keywords[keyword] = struct{}{}
	}
	cloned.OrderedRules = append([]string(nil), defaultConfig.OrderedRules...)
	cloned.Allowlists = append([]*config.Allowlist(nil), defaultConfig.Allowlists...)
	return cloned, nil
}

// NewGitleaksFilter creates a filter from gitleaks' embedded default rules,
// built-in PII rules, and optional custom TOML rules and allowlists. Custom
// rules extend the defaults; an identical rule ID replaces the default entry.
func NewGitleaksFilter(tomlBytes []byte) (*GitleaksFilter, error) {
	cfg, err := baseGitleaksConfig()
	if err != nil {
		return nil, fmt.Errorf("load gitleaks default config: %w", err)
	}
	filter := &GitleaksFilter{}
	for _, rule := range builtinPIIRules() {
		addConfigRule(&cfg, rule)
	}
	addConfigRule(&cfg, configRule{
		ID:       "privacy-openai-key",
		Regex:    `\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`,
		Keywords: []string{"sk-"},
	})
	addConfigRule(&cfg, configRule{
		ID:          "privacy-context-secret",
		Regex:       `(?i)(?:password|passwd|pwd|secret|token|api[_ -]?key|access[_ -]?key|bearer|authorization|密码|口令|密钥|令牌|凭证)\s*(?:is|为|是|:|：|=)\s*[\"']?([^\s\"'，。；;]{4,})`,
		SecretGroup: 1,
		Keywords:    []string{"password", "secret", "token", "api", "bearer", "authorization", "密码", "口令", "密钥", "令牌", "凭证"},
	})
	addConfigRule(&cfg, configRule{
		ID:       "privacy-high-entropy",
		Regex:    `[A-Za-z0-9+/=_-]{20,}`,
		Entropy:  4.8,
		Keywords: nil,
	})
	if len(tomlBytes) > 0 {
		custom, allowlists, skipped, err := parseCustomGitleaksRules(tomlBytes)
		if err != nil {
			return nil, err
		}
		filter.skipped = skipped
		for _, rule := range custom {
			if rule.Regex != "" {
				addConfigRule(&cfg, rule)
			}
		}
		for _, rule := range custom {
			if rule.Regex != "" {
				continue
			}
			existing, ok := cfg.Rules[rule.ID]
			if !ok {
				filter.skipped++
				continue
			}
			existing.Allowlists = append(existing.Allowlists, rule.Allowlists...)
			cfg.Rules[rule.ID] = existing
		}
		for _, allowlist := range allowlists {
			if len(allowlist.TargetRules) == 0 {
				cfg.Allowlists = append(cfg.Allowlists, allowlist.Allowlist)
				continue
			}
			for _, ruleID := range allowlist.TargetRules {
				rule, ok := cfg.Rules[ruleID]
				if !ok {
					return nil, fmt.Errorf("global allowlist targets unknown rule %q", ruleID)
				}
				rule.Allowlists = append(rule.Allowlists, allowlist.Allowlist)
				cfg.Rules[ruleID] = rule
			}
		}
	}
	detector := detect.NewDetector(cfg)
	// Request payloads are already decoded JSON strings. Avoid gitleaks'
	// secondary base64/URL decoding because decoded findings cannot be mapped
	// back to a safe byte range in the original payload.
	detector.MaxDecodeDepth = 0
	filter.detector = detector
	return filter, nil
}

type configRule struct {
	ID          string
	Description string
	Regex       string
	Keywords    []string
	Entropy     float64
	SecretGroup int
	Tags        []string
	Allowlists  []*config.Allowlist
}

type targetedAllowlist struct {
	Allowlist   *config.Allowlist
	TargetRules []string
}

func builtinPIIRules() []configRule {
	return []configRule{
		{ID: "pii-email", Regex: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`},
		{ID: "pii-phone-cn", Regex: `(?:\+?86[-\s]?)?1[3-9][0-9]{9}`},
		{ID: "pii-id-card-cn", Regex: `[1-9][0-9]{16}[0-9Xx]`},
		{ID: "pii-bank-card", Regex: `[0-9]{13,19}`},
		{ID: "pii-ipv4", Regex: `(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])`},
	}
}

func addConfigRule(cfg *config.Config, rule configRule) {
	compiled := regexp.MustCompile(rule.Regex)
	cfg.Rules[rule.ID] = config.Rule{
		RuleID:      rule.ID,
		Description: rule.Description,
		Regex:       compiled,
		SecretGroup: rule.SecretGroup,
		Entropy:     rule.Entropy,
		Keywords:    lowerKeywords(rule.Keywords),
		Tags:        append([]string(nil), rule.Tags...),
		Allowlists:  append([]*config.Allowlist(nil), rule.Allowlists...),
	}
	if cfg.Keywords == nil {
		cfg.Keywords = make(map[string]struct{})
	}
	for _, keyword := range rule.Keywords {
		cfg.Keywords[strings.ToLower(keyword)] = struct{}{}
	}
	for _, id := range cfg.OrderedRules {
		if id == rule.ID {
			return
		}
	}
	cfg.OrderedRules = append(cfg.OrderedRules, rule.ID)
}

func lowerKeywords(keywords []string) []string {
	out := make([]string, len(keywords))
	for i, keyword := range keywords {
		out[i] = strings.ToLower(keyword)
	}
	return out
}

func parseCustomGitleaksRules(body []byte) ([]configRule, []targetedAllowlist, int, error) {
	var cfg gitleaksTOMLConfig
	if _, err := toml.Decode(string(body), &cfg); err != nil {
		return nil, nil, 0, fmt.Errorf("decode gitleaks rules: %w", err)
	}
	rules := make([]configRule, 0, len(cfg.Rules))
	skipped := 0
	for _, rule := range cfg.Rules {
		if rule.ID == "" || (rule.Regex == "" && len(rule.Allowlists) == 0) {
			skipped++
			continue
		}
		if rule.Regex != "" {
			if _, err := regexp.Compile(rule.Regex); err != nil {
				skipped++
				continue
			}
		}
		allowlists, err := compileGitleaksAllowlists(rule.Allowlists)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("rule %q allowlist: %w", rule.ID, err)
		}
		rules = append(rules, configRule{
			ID:          rule.ID,
			Description: rule.Description,
			Regex:       rule.Regex,
			Keywords:    rule.Keywords,
			Entropy:     rule.Entropy,
			SecretGroup: rule.SecretGroup,
			Tags:        rule.Tags,
			Allowlists:  allowlists,
		})
	}
	global := make([]targetedAllowlist, 0, len(cfg.Allowlists))
	for i, raw := range cfg.Allowlists {
		compiled, err := compileGitleaksAllowlist(raw)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("global allowlist %d: %w", i+1, err)
		}
		global = append(global, targetedAllowlist{Allowlist: compiled, TargetRules: raw.TargetRules})
	}
	return rules, global, skipped, nil
}

func compileGitleaksAllowlists(raw []gitleaksTOMLAllowlist) ([]*config.Allowlist, error) {
	compiled := make([]*config.Allowlist, 0, len(raw))
	for i, allowlist := range raw {
		a, err := compileGitleaksAllowlist(allowlist)
		if err != nil {
			return nil, fmt.Errorf("%d: %w", i+1, err)
		}
		compiled = append(compiled, a)
	}
	return compiled, nil
}

func compileGitleaksAllowlist(raw gitleaksTOMLAllowlist) (*config.Allowlist, error) {
	condition := config.AllowlistMatchOr
	switch strings.ToUpper(raw.Condition) {
	case "", "OR", "||":
	case "AND", "&&":
		condition = config.AllowlistMatchAnd
	default:
		return nil, fmt.Errorf("unknown condition %q", raw.Condition)
	}
	regexTarget := raw.RegexTarget
	switch regexTarget {
	case "", "secret":
		regexTarget = ""
	case "match", "line":
	default:
		return nil, fmt.Errorf("unknown regexTarget %q", raw.RegexTarget)
	}
	compile := func(patterns []string) ([]*gitleaksregexp.Regexp, error) {
		out := make([]*gitleaksregexp.Regexp, 0, len(patterns))
		for _, pattern := range patterns {
			if _, err := regexp.Compile(pattern); err != nil {
				return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
			}
			out = append(out, gitleaksregexp.MustCompile(pattern))
		}
		return out, nil
	}
	regexes, err := compile(raw.Regexes)
	if err != nil {
		return nil, err
	}
	paths, err := compile(raw.Paths)
	if err != nil {
		return nil, err
	}
	allowlist := &config.Allowlist{
		Description:    raw.Description,
		MatchCondition: condition,
		Commits:        append([]string(nil), raw.Commits...),
		Paths:          paths,
		RegexTarget:    regexTarget,
		Regexes:        regexes,
		StopWords:      append([]string(nil), raw.StopWords...),
	}
	if err := allowlist.Validate(); err != nil {
		return nil, err
	}
	return allowlist, nil
}
