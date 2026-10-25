# `datefmt` verification instruments

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-datefmt [-- --check]`: re-takes the two oracles below and writes (or compares) their vectors; the interop lane runs it with `--check`. Its header lists what each needs. |
| `go_time_oracle/` | Go `time` (`ParseDuration`, `Duration.String`, the `RFC1123Z` layout) as a black box → `src/go_time_vectors.zig`. Standard library only. |
| `mail_date_oracle.py` | Python `email.utils.parsedate_tz` as a black box, each row labelled with our expectation → `src/mail_date_vectors.zig`. |
| `bench.zig` + `go_bench/` | `zig build bench-datefmt`: comparative benchmark against Go `time`, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). |
| `rust_fast_bench/` | The fastest in the field for `bench-datefmt` (httpdate 1.0.3, humantime 2.4.0, chrono 0.4.45, jiff 0.2.38; pinned by `Cargo.lock`, built offline; `BENCH_FAST=0` skips it). `--probe` reads inputs from stdin and prints each crate's verdict: the instrument behind the grammar lead in `src/lead_test.zig`. |
