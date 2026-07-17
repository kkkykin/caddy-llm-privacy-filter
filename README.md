# Caddy LLM Privacy Filter

Caddy v2 HTTP middleware that redacts PII and secrets from LLM JSON request
bodies before proxying them upstream. Secret detection runs in-process through
the maintained [gitleaks](https://github.com/gitleaks/gitleaks) Go library; no
external filtering service or `privacyfilter` module is required.

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
			# skip_regex sha256-[A-Za-z0-9+/]{43}=
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

## Skip Patterns (Allowlist)

The `skip_regex` subdirective protects content that would otherwise be flagged
by the high-entropy fallback rule. Each pattern is
matched against every string value in the request body; matching byte ranges
are masked with equal-length spaces before filtering, then restored from the
original value in the final output.

Use this to prevent false positives on known formats such as Nix SRI hashes,
Git commit SHAs, or your own application-level tokens:

```caddyfile
llm_privacy_filter {
    skip_regex sha256-[A-Za-z0-9+/]{43}=
    skip_regex ^myapp_[A-Za-z0-9]{32}$
}
```

Multiple patterns can be specified by repeating the directive. When no
`skip_regex` is configured there is zero additional overhead — the original
fast path is preserved.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `api` | `auto` | One of `auto`, `openai`, `openai-compatible`, `responses`, `anthropic-message`. |
| `gitleaks_toml` | empty | Optional local path or HTTP(S) URL to a gitleaks-compatible rules file. Repeat it or pass multiple paths on one line to merge rule sets. Custom rules extend gitleaks defaults and the built-in PII rules. |
| `gitleaks_tomls` | empty | Array/alias form for multiple gitleaks-compatible rules files. Rules are appended in order and matched as one filter. |
| `gitleaks_toml_refresh_interval` | `1h` when any URL is configured, off for local-only sources | Periodically reload configured gitleaks TOML sources. Refresh failures keep the previous compiled rules. See `fail_open` for startup load-failure behavior. |
| `max_body_size` | `8388608` | Largest JSON body to buffer, in bytes. Use `-1` for no explicit limit. |
| `fail_open` | `false` | Forward the original body when filtering fails. Also governs startup load failures: when every configured `gitleaks_toml` source is a URL, `true` falls back to built-in rules and keeps serving while `false` aborts startup. A local source that fails to load always aborts startup regardless of this setting. |
| `skip_regex` | empty | Regular expression patterns for content that should be preserved without redaction. Repeat the directive for multiple patterns. Patterns are compiled at startup; an invalid pattern fails the configuration load. |

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
