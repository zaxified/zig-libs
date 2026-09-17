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
scripts/capped zig build-exe --cache-dir <scratch>/zc \
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
