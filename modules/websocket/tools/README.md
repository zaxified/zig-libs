# `websocket` tools

Recipes for committed data (`CONVENTIONS.md` §9): run by hand, never by a test. Moved here on
2026-09-17 from a private `~/.cache` directory, where they were the only copy.

The frozen three-implementation corpus in `src/connection.zig` came from:

| file | step |
|---|---|
| `cases.py` | the shared case table (valid and adversarial client frames) |
| `oracle_python.py` | runs the cases through `websockets` 15.0.1 → `out_python.json`, `cases.json` |
| `oracle_go_main.go` | runs the same cases against `coder/websocket` and `gorilla/websocket` over loopback: `go run oracle_go_main.go <cases.json> <out_go.json>` |
| `report.py` | merges both → `merged.json` |
| `emit_zig.py` | writes the Zig table → `corpus.zig.txt` |

Scratch goes to `$WS_WORK` (default `.zig-cache/websocket-capture`, run from the
repo root). The Go program needs a `go.mod` requiring the two libraries at the
versions it prints.

## The opening handshake, differentially (not covered by the corpus above)

The three-implementation corpus above is entirely post-handshake data frames fed to a
`Connection`; it never drives the handshake itself. `oracle_handshake.py` +
`verify_response_probe.zig` do: they diff the module's `handshake.verifyResponse`
(client side) and `handshake.acceptHandshake` (server side) against python-websockets
15.0.1's (BSD-3-Clause, verified via `pip show websockets`) `ClientProtocol`/
`ServerProtocol` over the same fixed case table. Adopted 2026-09-17 from an audit
reproducer that only printed python-websockets' own verdicts (`CONVENTIONS.md` §9);
this version also builds and runs the Zig side and diffs the two.

```bash
scripts/lib/capped zig build-exe --cache-dir <scratch>/zc \
  -femit-bin=<scratch>/verify_response_probe \
  --dep websocket --dep http \
  -Mmain=modules/websocket/tools/verify_response_probe.zig \
  --dep http -Mwebsocket=modules/websocket/src/root.zig \
  --dep netaddr --dep datefmt \
  -Mhttp=modules/http/src/root.zig \
  -Mnetaddr=modules/netaddr/src/root.zig \
  -Mdatefmt=modules/datefmt/src/root.zig
modules/websocket/tools/oracle_handshake.py <scratch>/verify_response_probe
```

**Measured 2026-09-17: 10/10 cases agree** (6 client-side `verifyResponse` cases, 4
server-side `acceptHandshake` cases) — no case where this module's ACCEPT/REJECT
decision differs from python-websockets'. Needs `pip install websockets==15.0.1`.

**Stale as of 2026-09-28** for one row: `acceptHandshake`'s new `Origin` allow-list
(SPEC.md "Server-side `Origin` check") makes the `server_cases` "Origin: https://evil.example"
case a *known, deliberate* divergence rather than an agreement — this module's default policy
now rejects it (`error.OriginNotAllowed`, Origin's host doesn't match `Host: h`), while
python-websockets' bare `ServerProtocol` has no origin policy of its own to check it against.
The other 9 rows are unaffected. Not re-run for this change (no python/go environment
available); re-running would now report 9/10, with this row's comment in
`verify_response_probe.zig` explaining why.

## The live oracle: `interop.zig` + `go_oracle/` (2026-10-26)

`zig build interop-websocket` (a program, not a test; `check-interop` compiles it) builds
`go_oracle` — github.com/coder/websocket v1.8.15 and github.com/gorilla/websocket v1.5.3 through
their public APIs, pinned by `go_oracle/go.mod`/`go.sum`, `GOPROXY=off` — and runs three families
over loopback: this module's client against both Go servers, both Go clients against this
module's server (`http.Server` + `respondUpgraded` + `Conn`, 16 KiB buffers), and fixed raw
handshakes and frames sent to all three servers. Expectations are `agree`, `stricter` (the
card's `**Ahead:**` rows) or `differs` (documented); anything else is a SURPRISE and exit 1.
Verdicts: `.zig-cache/interop-websocket/verdicts.tsv`.

`-- --capture` rewrites `src/testdata/interop/*.bin`: the bytes the Go libraries sent after the
handshake in the scenarios without 1 MiB of plain payload, replayed hermetically by
`src/interop_replay_test.zig`.

## Fastest in the field: `go_bench/gorilla/`, `rust_fast_bench/` (2026-10-26)

`zig build bench-websocket` also times gorilla/websocket v1.5.3 (`go_bench/gorilla`, same module
cache) and denoland/fastwebsockets 0.10.0 + snapview/tungstenite 0.30.0 (`rust_fast_bench`,
`cargo build --release --offline`, versions pinned with `=`, `Cargo.lock` committed; their
dependency closure was read before the first build — build scripts, proc macros, the code paths
run). `BENCH_FAST=0` skips these three sides.
