# `ratelimit` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test. Moved here on
2026-09-17 from a private `~/.cache` directory, where they were the only copy.

| file | produces | needs |
|---|---|---|
| `xrate/main.go` | `src/xrate_vectors.zig` (`cd xrate && go run . > ../../src/xrate_vectors.zig`) | Go, `golang.org/x/time` (pinned in `go.mod`/`go.sum`) |
| `xrate/probe/main.go` | nothing committed — prints the out-of-contract backwards-timestamp behaviour the module deliberately does not copy | the same |
