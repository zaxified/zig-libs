# `accesslog` verification instruments

Two differential oracles, run by hand; their answers are frozen in
`src/json_oracle_vectors.zig` (replayed by `src/json_oracle_test.zig`) and
`src/json_path_vectors.zig` (replayed in `src/root.zig`) in the module's own
lane, with no Python, Go or jq (`CONVENTIONS.md` §9). The Combined
format's goaccess anchor lives in `src/root.zig` (verdicts frozen as literals).

| tool | role |
|---|---|
| `interop.zig` | `zig build interop-accesslog`: has `json_oracle.py gen` draw entries, writes each with `writeJsonLines` and `writeLogfmt`, has `json_oracle.py judge` read them back, and writes (or with `--check` compares) the vectors. |
| `json_oracle.py` | `gen`: seeded entries (+ every hostile string in every field). `judge`: Python json, Go (`go_json/`) and jq read each line; each must give the entry back exactly. |
| `json_path_oracle.py` | `python3 tools/json_path_oracle.py > src/json_path_vectors.zig`: Python's `decode('utf-8', 'replace')` of 333 request paths (33 at every Unicode Table 3-7 edge, 300 drawn around them), replayed as `Entry.target` through JSON Lines. Moved from `metrics` with its access-log writer (2026-10-06). |
| `go_json/` | Go `encoding/json` (stdlib only), one line at a time, numbers exact. |
| `go_logfmt/` | go-logfmt v0.6.1 (MIT; pinned in `go.sum`), one logfmt line at a time, values as raw bytes. |
| `bench.zig` + `go_bench/` | `zig build bench-accesslog`: comparative benchmark, the source of the maturity card's `**Performance:**` line (CONVENTIONS.md §9 kind 3). 16 entries per op: `writeJsonLines` vs `encoding/json` and vs `slog.JSONHandler`, `writeLogfmt` vs go-logfmt v0.6.1 (the card's own reference, Apache httpd, is a server directive and cannot be timed; the Combined writer has no reference and is not measured). Byte counts must agree or the run fails. Needs the same go-logfmt module cache as `go_logfmt`. Not run by any lane. 2026-10-10, x86-64 (provisional): json_encoding 0.32, json_slog 0.14, logfmt 0.27 (ours/Go). |
| `go_fast_bench/` + `rust_fast_bench/` | The fastest-in-the-field half of `zig build bench-accesslog` (`BENCH_FAST=0` skips it), the card's `fastest` ratio (2026-10-25): rs/zerolog v1.35.1, uber-go/zap v1.28.0, phuslu/log v1.0.138 (Go, pinned by go.mod/go.sum) and serde_json 1.0.150 with a hand-written `Serialize` (Rust, no derive, Cargo.lock; built into `.zig-cache/bench-accesslog/rust-target`). The same 16 entries as JSON lines; phuslu's clock writes a 6-byte shorter timestamp, added back in the byte count. No faster logfmt writer than go-logfmt was found. Foreign code (cgo, exec, network, init, build.rs) swept before the first build (2026-10-25). |
| `go_utf8_probe/` | The contenders' half of the `**Ahead:** correctness` claim (2026-10-25): truncated UTF-8 prefixes (`E1 80`, `F0 9F 98`, …) through encoding/json, log/slog, zerolog, zap and phuslu/log, printing the U+FFFD count each writes. Our half is `src/lead_test.zig`. `go build` in the directory, then run it; no arguments. |

```bash
zig build interop-accesslog              # re-take, write src/json_oracle_vectors.zig
zig build interop-accesslog -- --check   # re-take, compare with the committed file
```

Needs python3, go (with go-logfmt in its module cache; `GOPROXY=off`) and jq; no network.

**What the replay holds** (2026-10-05): 421 entries, every line read back to exactly
its entry by all three readers (key order too, where the reader keeps it), each
ill-formed UTF-8 subsequence as one U+FFFD per maximal subpart — what Python's own
`decode('utf-8', 'replace')` gives; and every logfmt line read by go-logfmt back to
exactly the entry's key/value pairs, raw bytes included.
