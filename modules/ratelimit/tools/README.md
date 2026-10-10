# `ratelimit` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test. Moved here on
2026-09-17 from a private `~/.cache` directory, where they were the only copy.

| file | produces | needs |
|---|---|---|
| `xrate/main.go` | `src/xrate_vectors.zig` (`cd xrate && go run . > ../../src/xrate_vectors.zig`) | Go, `golang.org/x/time` (pinned in `go.mod`/`go.sum`) |
| `xrate/probe/main.go` | nothing committed — prints the out-of-contract backwards-timestamp behaviour the module deliberately does not copy | the same |
| `bench.zig` + `go_bench/` | `zig build bench-ratelimit`: comparative benchmark against golang.org/x/time v0.15.0 `rate`, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). 4096 requests over 1024 keys with an injected clock: `bucket` = `TokenBucket.allowAt` vs one `rate.Limiter`, `keyed` = `Limiter.allowAt` vs `map[string]*rate.Limiter` under a mutex. Counts must agree or the run fails. Needs the same x/time module cache as `xrate`. Not run by any lane. 2026-10-10, x86-64 (provisional): bucket 0.08, keyed 0.38 (ours/Go). |
