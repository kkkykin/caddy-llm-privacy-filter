package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/kkkykin/caddy-llm-privacy-filter"
)

func main() {
	caddycmd.Main()
}
