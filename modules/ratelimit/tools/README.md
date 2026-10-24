# `ratelimit` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test. Moved here on
2026-09-17 from a private `~/.cache` directory, where they were the only copy.

| file | produces | needs |
|---|---|---|
| `xrate/main.go` | `src/xrate_vectors.zig` (`cd xrate && go run . > ../../src/xrate_vectors.zig`) | Go, `golang.org/x/time` (pinned in `go.mod`/`go.sum`) |
| `xrate/ops.go` (`go run . ops`) | `src/xrate_ops_vectors.zig` (`cd xrate && go run . ops > ../../src/xrate_ops_vectors.zig`): seeded random + 2 scripted AllowN/ReserveN/CancelAt/SetLimitAt/SetBurstAt sequences on one limiter, `TokensAt` after each | the same |
| `xrate/probe/main.go` | nothing committed — prints the out-of-contract backwards-timestamp behaviour the module deliberately does not copy | the same |
| `bench.zig` + `go_bench/` | `zig build bench-ratelimit`: comparative benchmark against golang.org/x/time v0.15.0 `rate`, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). 4096 requests over 1024 keys with an injected clock: `bucket` = `TokenBucket.allowAt` vs one `rate.Limiter`, `keyed` = `Limiter.allowAt` vs `map[string]*rate.Limiter` under a mutex. Counts must agree or the run fails. Needs the same x/time module cache as `xrate`. Not run by any lane. 2026-10-10, x86-64 (provisional): bucket 0.08, keyed 0.38 (ours/Go). |
| `rust_fast_bench/` | the "fastest in the field" side of `bench-ratelimit`: governor 0.10.4 (GCRA, feature `no_std`; pinned in `Cargo.toml`/`Cargo.lock`), same sequence, clock injected through governor's `Clock` trait. `BENCH_FAST=0` skips it. 2026-10-24: bucket 0.41, keyed 1.13 (ours/governor). | cargo, the pinned crates in `~/.cargo/registry` (`cargo fetch` once; swept 2026-10-24: one build script, portable-atomic's `rustc -vV` probe; no proc-macro) |
| `lead_probe/main.go` | nothing committed — the `**Ahead:**` line's case: x/time/rate v0.15.0 admits 30 events at one instant with burst 3 when one reservation is cancelled ten times (`cd lead_probe && GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly go run .`) | the same x/time cache as `xrate` |
