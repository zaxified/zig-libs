# `s7comm` verification instruments

Four instruments, run by hand. None is wired into `zig build`: all need a
**foreign toolchain** (`python-snap7`, i.e. Davide Nardella's `libsnap7.so`, or Go for gos7).
`zig build test-s7comm` must require none of it (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

Figures below were measured on 2026-09-17 against the tree as it stands.

## The goldens can be re-derived, not just read

| tool | question it answers |
|---|---|
| `snap7_oracle.py` | Does an independently written S7 stack answer the same frames the same way? Stands up a local `python-snap7` server and sends hand-built frames straight at it. |
| `snap7_live.py` | — Holds a local S7 server open so the module's own `live:` test (normally SKIPPED) runs against a real second implementation. |
| `snap7_client_drive.py` | — The other direction: an independent S7 **client** against this module's `Responder`: DB read/write, SZL, and the block services (`list_blocks`, `list_blocks_of_type`, `get_block_info`; run 2026-11-21 against python-snap7 3.1.0, counts, numbers, sizes, author and version as configured). |
| `gos7_client_drive/` | — gos7 (BSD-3, pinned commit `153d631d8881` in `go.mod`/`go.sum`) as the client against the `Responder`: DB read/write, session password wrong/right/9 characters, clear, protection record. Its request bytes are the group-5 goldens in `src/root.zig` and `src/server.zig`. Run: `S7COMM_TEST_LISTEN=127.0.0.1:10503 <s7comm test binary> &` then `cd tools/gos7_client_drive && go run . 10503` (prints `ALL OK`; the test binary prints the userdata frames in hex). Last run 2026-11-19: ALL OK. |

`src/goldens.zig` is 45 KB of byte-exact captures, and `SPEC.md` grades the
module **class A · oracle MIXED** naming those captures as the anchor. These
scripts are how they were obtained and the only way to obtain them again —
before this migration that recipe lived in a droppable cache. A golden nobody
can re-derive is a number, not evidence.

Measured precondition: `python-snap7` 3.1.0 is importable on this machine, so
the oracle can actually be run rather than merely described.
