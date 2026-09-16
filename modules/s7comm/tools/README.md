# `s7comm` verification instruments

Six instruments, run by hand. None is wired into `zig build`: two need a
**foreign toolchain** (`python-snap7`, i.e. Davide Nardella's `libsnap7.so`),
one needs a listening socket, and the mutation runner costs minutes per row.
`zig build test-s7comm` must require none of it (`CONVENTIONS.md` §9).

Figures below were measured on 2026-09-17 against the tree as it stands.

## The goldens can be re-derived, not just read

| tool | question it answers |
|---|---|
| `snap7_oracle.py` | Does an independently written S7 stack answer the same frames the same way? Stands up a local `python-snap7` server and sends hand-built frames straight at it. |
| `snap7_live.py` | — Holds a local S7 server open so the module's own `live:` test (normally SKIPPED) runs against a real second implementation. |
| `snap7_client_drive.py` | — The other direction: an independent S7 **client** against this module's `Responder`. |
| `silent_peer.py` | What does `TcpTransport.setReadTimeout` actually bound? A peer that says nothing, or announces 256 octets and then says nothing (audit F2). Pure stdlib. |

`src/goldens.zig` is 45 KB of byte-exact captures, and `SPEC.md` grades the
module **class A · oracle MIXED** naming those captures as the anchor. These
scripts are how they were obtained and the only way to obtain them again —
before this migration that recipe lived in a droppable cache. A golden nobody
can re-derive is a number, not evidence.

Measured precondition: `python-snap7` 3.1.0 is importable on this machine, so
the oracle can actually be run rather than merely described.

## Would the suite notice if a guard were removed?

    modules/s7comm/tools/mutate.py            # the whole table
    modules/s7comm/tools/mutate.py W2 D7      # only those rows
    modules/s7comm/tools/mutate.py --controls # only the two positive controls

18 mutations and 2 positive controls. Deletions neutralise a guard outright;
**weakenings** move a bound by one, compare fewer octets, or widen a range —
that second kind is what found audit F7.

Measured: **20 rows, 17 RED, 3 GREEN, 0 BROKEN, 0 anchor problems.** One of the
greens is the `PC-ok` control. The two real survivors:

| mutant | guard the suite does not notice |
|---|---|
| `D4` | the recursion depth limit in `s7plus_value.skipBody` |
| `W6b` | the **shared** element budget — each nested object given its own again |

⚠ `W6b` is a row the audit could not have had. Re-deriving `W6` (below) showed
that the 2026-08 F6 fix introduced a guard nothing tests: one `elem_budget`
shared by every attribute value in the whole object graph, which is what stops
a handful of octets buying tens of millions of loop iterations. Undoing that
leaves the suite green. Feed both survivors to `verify_survivors.py`, which
compiles a small driver against the mutated copy and shows what the weakened
code actually does — for audit F7's `server.zig` row that was an octet read
*past* the registered area and handed back in the reply.

### Three anchors that had to be re-derived, and why each mattered

- **`W6`** named `try value.skipValue(cur, depth);`. The F5/F6 fixes gave that
  call a third argument, so the old text matches **zero** times: the row read
  "needle not found" while looking like a result.
- **`D2`** neutralised its guard with `if (false)`, which left `need` unused —
  so the mutant **failed to compile** and the row scored **RED**, i.e. "the
  suite noticed". Nothing had run. It now spends the value (`need != need`),
  compiles, and comes back RED for the real reason:
  `vars.zig -> FAIL (TestExpectedError)`.
- **`PC-bad`** took two goes. The first named a constant written from how TPKT
  works rather than from the file (`min_length: usize = 7;` — zero matches).
  The second *raised* the minimum, which the suite did not notice at all: the
  tests expect `LengthTooSmall` for `00 04` and `00 00`, and a higher minimum
  still refuses those. Only shifting the `version` octet fails at runtime, in
  both `tpkt.zig` and the goldens.

That last one is the point of having controls: **a positive control that comes
back GREEN has failed, and the runner refuses the whole table** rather than
publishing rows that mean nothing.

### And the command line rots separately from the anchors

The audit's runner drove a bare `zig test <file>`. Measured today that fails
with `no module named 'testkit'` — **12** of this module's files import
`testkit` at file scope for their fuzz corpora. Its positive control ran the
same way, so it failed loudly rather than lying, but it measured nothing at
all. A dry run cannot see this: 16 of its 17 anchors still matched exactly
once. `BROKEN` is a verdict here, distinct from `RED`.

## What was deliberately not brought over, and what is still elsewhere

`.zig-cache/audit-s7comm` was 691 MB and held **no source at all** — 143
compiled artefacts, 25 cache manifests and one `strace`. The instruments came
from `~/CML/20260901-zig-libs-audit/A1/repro/s7comm/`.

- `instrument_fuzz.py` — spent. It measured the `Smith.bytes` + ranged-draw
  trap; the fix is in `src/` (`smith.slice` in `tpkt`, `address`, `vars`,
  `s7plus_object`), with the reach measurement recorded beside it.
- ⚠ **Eight probe sources stay in the repro stash for now** —
  `probe_layers.zig`, `probe_s7plus.zig`, `probe_client.zig`, `probe_perf.zig`,
  `probe_amp2.zig`, `probe_timeout.zig`, `probe_stack.zig`,
  `probe_responder_tap.zig`. They are *not* in this directory and this
  migration did not judge them; they belong to the second stash
  (`A1/repro/`), which is a separate pass. `silent_peer.py` came over because
  `probe_timeout.zig`'s question outlives the probe: the record's F2 evidence
  is the peer's behaviour, not the driver's.
