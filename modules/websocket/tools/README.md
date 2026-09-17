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
