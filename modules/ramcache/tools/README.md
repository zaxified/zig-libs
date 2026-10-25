# `ramcache` verification instruments

| tool | role |
|---|---|
| `bench.zig` + `go_bench/` | `zig build bench-ramcache`: comparative benchmark against maypok86/otter v2.3.0 (the reference; a Go port of Caffeine), the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). |
| `rust_fast_bench/` | The fastest in the field for `bench-ramcache`: quick_cache 0.6.24 and moka 0.12.16 on the same rows (pinned by `Cargo.lock`, built offline; `BENCH_FAST=0` skips it). |
