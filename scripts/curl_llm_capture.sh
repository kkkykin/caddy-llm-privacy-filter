#!/usr/bin/env bash
set -euo pipefail

CADDY_BASE_URL=http://127.0.0.1:8880
AUTH_TOKEN="${AUTH_TOKEN:-test-token}"

curl_common=(
  --verbose
  --show-error
  --no-buffer
  --http1.1
  --noproxy '*'
  --connect-timeout 10
  --max-time 120
  --header "Content-Type: application/json"
  --header "Authorization: Bearer ${AUTH_TOKEN}"
)

request_openai_image_edit() {
  curl "${curl_common[@]}" \
  -X POST "${CADDY_BASE_URL}/v1/images/edits" \
  -F "model=gpt-image-1.5" \
  -F 'prompt=Create a lovely gift basket with these four items in it'
}

request_openai_compatible() {
  curl "${curl_common[@]}" \
    "${CADDY_BASE_URL}/v1/chat/completions" \
    --data-binary @- <<'JSON'
{
  "model": "gpt-4.1-mini",
  "messages": [
    {
      "role": "system",
      "content": "你是一个测试助手。"
    },
    {
      "role": "user",
      "content": "请帮我记录邮箱 alice@example.com，手机号 13800138000，token sk-proj-abcdefghijklmnopqrstuvwxyz123456。"
    }
  ],
  "stream": false
}
JSON
}

request_responses() {
  curl "${curl_common[@]}" \
    "${CADDY_BASE_URL}/v1/responses" \
    --data-binary @- <<'JSON'
{
  "model": "gpt-4.1-mini",
  "instructions": "测试 Responses API 脱敏。",
  "input": [
    {
      "role": "user",
      "content": [
        {
          "type": "input_text",
          "text": "我的邮箱是 bob@example.com，内网 IP 是 192.168.1.10。"
        }
      ]
    }
  ],
  "stream": false
}
JSON
}

request_anthropic_messages() {
  curl "${curl_common[@]}" \
    "${CADDY_BASE_URL}/v1/messages" \
    --header "anthropic-version: 2023-06-01" \
    --data-binary @- <<'JSON'
{
  "model": "claude-3-5-sonnet-latest",
  "max_tokens": 128,
  "system": [
    {
      "type": "text",
      "text": "系统提示里包含 admin@example.com。"
    }
  ],
  "messages": [
    {
      "role": "user",
      "content": [
        {
          "type": "text",
          "text": "身份证 11010519491231002X，银行卡 4111111111111111。"
        }
      ]
    }
  ],
  "stream": false
}
JSON
}

case "${1:-all}" in
  image|edit)
    request_openai_image_edit
    ;;
  openai|chat)
    request_openai_compatible
    ;;
  responses)
    request_responses
    ;;
  anthropic|messages)
    request_anthropic_messages
    ;;
  all)
    request_openai_compatible
    printf '\n\n'
    request_responses
    printf '\n\n'
    request_anthropic_messages
    printf '\n\n'
    request_openai_image_edit
    ;;
  *)
    printf 'usage: %s [all|openai|responses|anthropic]\n' "$0" >&2
    exit 2
    ;;
esac

