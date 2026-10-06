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
