# `metrics` verification instruments

Differential oracles, run by hand; its answers are frozen in
`src/go_oracle_vectors.zig` and replayed by `src/go_oracle_test.zig` in the module's
own lane, with no Go (`CONVENTIONS.md` §9).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-metrics`: has `go_oracle` generate the scripts, runs each on a `metrics.Registry`, records `writeText`, has `go_oracle` judge, and writes (or with `--check` compares) the vectors. |
| `go_oracle/` `register` | `go run . register ../../src/go_register_vectors.zig` (in `go_oracle/`, `GOPROXY=off`): registration sequences on client_golang v1.24.1 + legacy name rules; see `register.go`. |
| `go_oracle/` | Go: `gen` (seeded operation scripts plus three crafted ones) and `judge` (the same operations on client_golang v1.24.1; our text parsed by prometheus/common v0.71.0 expfmt and scraped by Prometheus v0.315.0 model/textparse; families compared). |
| `bench.zig` + `go_bench/` | `zig build bench-metrics`: comparative benchmark against prometheus/client_golang v1.24.1, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). `counter_inc`, `observe`, `counter_vec` (`Registry.counter(...).inc()` vs `WithLabelValues(...).Inc()`), `scrape` (`writeText` vs `promhttp.HandlerFor`, byte sums must agree) and `serve_plain`/`serve_metrics` (request-metrics middleware vs promhttp instrumentation; verdict net of the plain stack). Counts must agree or the run fails. Needs the same module cache as `go_oracle`. Not run by any lane. 2026-10-10, x86-64 (provisional): worst counter_vec 1.69, best serve net 0.05. |

```bash
zig build interop-metrics              # re-take, write src/go_oracle_vectors.zig
zig build interop-metrics -- --check   # re-take, compare with the committed file
```

Needs `go` with those modules in its cache; the driver sets `GOPROXY=off`, so no
network. `go_oracle/go.sum` pins them.

**What the replay holds** (2026-10-05): 163 scripts; every exposition equal, as
families, to what client_golang gathered after the same operations, and scraped by
textparse without error into the same samples. Class EMPTY_BUCKETS (21): an empty
bucket list, which client_golang replaces with DefBuckets and this module keeps as
`+Inf` only, is compared without buckets. A mutated exposition (one sample changed,
one series duplicated) is caught — by expfmt and by textparse respectively.
