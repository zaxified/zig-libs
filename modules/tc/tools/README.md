# `tc` verification instruments

Three instruments, one group. None is wired into `zig build`: each is run by
hand and prints what it found. They live here rather than in `src/` because each
either needs a **foreign toolchain** — iproute2, strace, unprivileged user
namespaces, a Python — or costs far more than a test lane should, and
`zig build test-tc` must require none of it (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

All figures below were measured on 2026-09-16 against the tree as it stands.

## The goldens can be re-derived, not just read

| tool | question it answers |
|---|---|
| `verify_goldens.py` | Does a stock `tc` still put exactly these bytes on the wire? |
| `capture.sh` | — Runs one `tc` command inside `unshare -rn` under `strace` and prints the `sendmsg` payload as hex. |
| `parse_strace.py` | — Turns that strace output into one hex line per buffer. |

`src/goldens.zig` is ~106 KB of byte-exact netlink datagrams captured from a
real `iproute2`. Its header records the capture recipe in prose; this is the
executable half. **A golden nobody can re-derive is a number, not evidence** —
and before this migration the recipe existed only as a comment plus a script in
a droppable cache.

    modules/tc/tools/verify_goldens.py          # all of them
    modules/tc/tools/verify_goldens.py htb      # only matching names

Measured: **51 of 51 goldens reproduced**, 0 MISS, 0 TMO, on
`iproute2-6.19.0` with `/proc/net/psched = 000003e8 00000040 000f4240
3b9aca00` — the same calibration `ratespec.golden_psched` pins, which is what
makes the rate tables host-independent.

⚠ A MISS means *this host disagrees*, not automatically *the module is wrong*.
Check `tc -V` against the provenance recorded in `goldens.zig` first.
