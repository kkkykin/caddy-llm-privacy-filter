# Caddy LLM Privacy Filter

Caddy v2 HTTP middleware that redacts PII and secrets from LLM JSON request
bodies before proxying them upstream. Secret detection runs in-process through
the maintained [gitleaks](https://github.com/gitleaks/gitleaks) Go library; no
external filtering service is required.

Detection has two rule layers:

- gitleaks' embedded default rules for API keys, access tokens, passwords,
  private keys, cloud credentials, and other provider-specific secrets
- built-in PII rules for email, mainland China mobile numbers and ID cards,
  Luhn-valid bank cards, and IPv4 addresses, plus compatibility rules for
  contextual passwords and high-entropy tokens

Matches are replaced with typed markers such as `[邮箱]`, `[电话]`, `[IP]`,
`[银行卡]`, or `[密钥]`.

Supported request shapes:

- OpenAI-compatible chat/completions style payloads
- OpenAI Responses API payloads
- Anthropic Messages API payloads

## Development

```bash
nix develop
go test ./...
go run ./cmd/caddy run --config Caddyfile
```

The flake shell provides Go, Caddy, xcaddy, gopls, gotools, jq, and git.

## Caddyfile

```caddyfile
:8080 {
	route /v1/* {
		llm_privacy_filter {
			api auto
			# gitleaks_toml /etc/caddy/base-gitleaks.toml /etc/caddy/team-gitleaks.toml
			# gitleaks_toml https://example.com/shared-gitleaks.toml
			# gitleaks_toml_refresh_interval 1h
			max_body_size 8388608
			fail_open false
		}

		reverse_proxy https://api.openai.com {
			header_up Host api.openai.com
		}
	}
}
```

The directive is fail-closed by default. If the JSON body cannot be inspected,
Caddy returns an error instead of forwarding the original sensitive body. Set
`fail_open true` only when availability is more important than privacy.

When `api auto` is used, the module detects the interface from the JSON body
shape only. Bodies that do not match OpenAI-compatible, Responses, or Anthropic
Messages are forwarded unchanged.

## Multiple TOML Sources

Both `gitleaks_toml` and its `gitleaks_tomls` alias accept multiple sources.
Sources can be local paths, HTTP(S) URLs, or a mixture of both, and may be
provided on one line or by repeating the option:

```caddyfile
llm_privacy_filter {
	api auto
	gitleaks_toml /etc/caddy/base-gitleaks.toml /etc/caddy/team-gitleaks.toml
	gitleaks_toml https://example.com/shared-gitleaks.toml
	gitleaks_toml_refresh_interval 1h
}
```

Sources are merged in configuration order. A later rule with the same ID
replaces the earlier rule fields, while per-rule and global allowlists from all
sources are appended. `disabledRules` entries from all sources are accumulated
and applied after the merge. If any source is a URL, the merged configuration
refreshes every hour by default; a refresh failure keeps the previous filter.

## Gitleaks Allowlists

Gitleaks-native `[[allowlists]]` and `[[rules.allowlists]]` are accepted in
files loaded with `gitleaks_toml`. Their `regexes` and `stopwords` checks run
after a rule has produced a finding and discard the whole finding. Use a global
allowlist when the same known value or format should be ignored by every rule,
use `targetRules` to restrict a global allowlist to named rules, or nest an
allowlist under one custom rule:

```toml
[[allowlists]]
description = "Nix SRI hashes are expected"
targetRules = ["privacy-high-entropy"]
regexes = ['''^sha256-[A-Za-z0-9+/]{43}=$''']

[[rules]]
id = "internal-token"
regex = '''INTERNAL_[A-Z0-9]{16}'''

    [[rules.allowlists]]
    regexes = ['''^INTERNAL_ALLOWLISTED$''']
```

Since this module scans decoded request strings rather than repository commits
or files, allowlist `commits` and `paths` have no useful request metadata to
match; `regexes` and `stopwords` are the relevant fields. `condition`,
`regexTarget`, and `targetRules` follow gitleaks semantics. Be careful with
`regexTarget = "line"`: it can suppress every finding whose source line matches
the allowlist regex.

## Disabling Rules

Use gitleaks' `[extend]` section to remove rules from the final merged
configuration:

```toml
[extend]
disabledRules = [
  "generic-api-key",
  "privacy-high-entropy",
  "pii-ipv4",
]
```

`disabledRules` accepts rule IDs from gitleaks defaults, the built-in PII and
compatibility rules, or custom rules loaded from any configured TOML source.
Because disabling is applied after all sources are merged, listing an ID in any
source disables that rule in the resulting filter.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `api` | `auto` | One of `auto`, `openai`, `openai-compatible`, `responses`, `anthropic-message`. |
| `gitleaks_toml` | empty | Optional local path or HTTP(S) URL to a gitleaks-compatible rules file. Repeat it or pass multiple paths on one line to merge rule sets. Custom rules and native allowlists extend gitleaks defaults and the built-in PII rules. |
| `gitleaks_tomls` | empty | Array/alias form for multiple gitleaks-compatible files. Rules and allowlists are appended and matched as one filter. |
| `gitleaks_toml_refresh_interval` | `1h` when any URL is configured, off for local-only sources | Periodically reload configured gitleaks TOML sources. Refresh failures keep the previous compiled rules. See `fail_open` for startup load-failure behavior. |
| `max_body_size` | `8388608` | Largest JSON body to buffer, in bytes. Use `-1` for no explicit limit. |
| `fail_open` | `false` | Forward the original body when filtering fails. Also governs startup load failures: when every configured `gitleaks_toml` source is a URL, `true` falls back to built-in rules and keeps serving while `false` aborts startup. A local source that fails to load always aborts startup regardless of this setting. |

## Custom PII Rules

The built-in PII rules are enabled without a TOML file. They can be replaced or
extended with standard gitleaks rule syntax. For example:

```toml
[[rules]]
id = "pii-email"
description = "Email address"
regex = '''[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'''

[[rules]]
id = "pii-phone-cn"
description = "Mainland China mobile number"
regex = '''(?:\+?86[-\s]?)?1[3-9][0-9]{9}'''
```

Rules may also set `keywords`, `entropy`, `secretGroup`, and `tags`. Findings
retain the gitleaks rule ID internally; known PII IDs receive typed markers and
other custom rules use `[密钥]`.

## Go API

`NewGitleaksFilter` accepts TOML bytes, not a path. Pass `nil` or an empty slice
to use the embedded gitleaks defaults and built-in PII rules, or pass one TOML
document to extend them:

```go
filter, err := llmprivacyfilter.NewGitleaksFilter(tomlBytes)
if err != nil {
	return err
}

redacted, err := filter.Redact(input)
```

For multiple in-memory TOML documents, use
`NewGitleaksFilterFromSources([][]byte{baseTOML, teamTOML})`; it uses the same
ordered merge behavior as multiple `gitleaks_toml` sources.

## Build A Custom Caddy

From this repo:

```bash
nix develop
go build -o bin/caddy ./cmd/caddy
```

With xcaddy from another checkout:

```bash
xcaddy build --with github.com/kkkykin/caddy-llm-privacy-filter=.
```
