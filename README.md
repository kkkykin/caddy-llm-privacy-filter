# Caddy LLM Privacy Filter

Caddy v2 HTTP middleware that redacts PII and secrets from LLM JSON request
bodies before proxying them upstream. It uses
[`packyme/privacy-filter`](https://github.com/packyme/privacy-filter) as a Go
module dependency.

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
			# gitleaks_toml https://example.com/gitleaks.toml
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

## Options

| Option | Default | Description |
| --- | --- | --- |
| `api` | `auto` | One of `auto`, `openai`, `openai-compatible`, `responses`, `anthropic-message`. |
| `gitleaks_toml` | empty | Optional local path or HTTP(S) URL to a gitleaks-compatible rules file. Empty uses privacy-filter built-ins. |
| `gitleaks_toml_refresh_interval` | `1h` for URL, off for local path | Periodically reload `gitleaks_toml`. Refresh failures keep the previous compiled rules. |
| `max_body_size` | `8388608` | Largest JSON body to buffer, in bytes. Use `-1` for no explicit limit. |
| `fail_open` | `false` | Forward the original body when filtering fails. |

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
