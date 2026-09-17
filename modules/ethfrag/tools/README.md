# `ethfrag` verification instruments

Eight instruments, run by hand. None is wired into `zig build`: `capture.py`
needs a **privileged network namespace**, the mutation runner costs a full build
plus 42 tests per row, and two of the probes are *expected to abort* — that is
what they measure. `zig build test-ethfrag` must require none of it
(`CONVENTIONS.md` §9).

Figures below were measured on 2026-09-17 against the tree as it stands
(`2f123350`), ReleaseFast unless stated, on an otherwise idle machine.

| tool | question it answers |
|---|---|
| `attacks.zig` | The 29-row overlap/evasion table, plus the F2 keep-alive probe. |
| `consequence.zig` | What a *surviving* mutation hands the caller: poison bytes, a rewritten frame, a panic. |
| `config_probe.zig` | Config validation (F7), allocation counts (F8), duplicate-drop churn (K5). |
| `perf.zig` | Wire→held ratio (F5), the documented memory bound (F4), insertion cost vs fragment count (F9). |
| `perf2.zig` | The sharper half of F4 (hardened configs) and of F9 (the overlap scan alone). |
| `track.zig` | The tracking allocator both `perf` probes measure through — **peak live bytes**, not a cumulative total. |
| `mutate.py` | Would the suite notice if a guard were weakened? |
| `capture.py` | Records what the real Linux kernel does with a fragment set, for `kernel_oracle.zig` (Audit F13). |

```bash
# the probes (⚠ -OReleaseFast BEFORE the -M arguments -- see below)
cd modules/ethfrag/tools
zig build-exe -OReleaseFast --dep ethfrag -Mmain=perf.zig -Methfrag=../src/root.zig \
    --cache-dir <scratch>/zc-perf -femit-bin=<scratch>/perf
zig build-exe --dep ethfrag -Mmain=attacks.zig -Methfrag=../src/root.zig \
    --cache-dir <scratch>/zc-attacks -femit-bin=<scratch>/attacks

modules/ethfrag/tools/mutate.py             # the whole table
modules/ethfrag/tools/mutate.py --only M8   # rows whose id contains "M8"
modules/ethfrag/tools/mutate.py --controls  # only the controls

# capture.py needs the namespace; without it every scenario SKIPs and exits 1
unshare --user --map-root-user --net -- sh -c \
    'ip link set lo up && python3 modules/ethfrag/tools/capture.py --verify'
```

⚠ **Build the probe binary from the current source every time.** Preparing this
README, five of these binaries were left in the cache from an earlier edit and
one was 90 seconds older than its own `.zig` file. The run it produced looked
perfectly plausible. Check the mtimes or rebuild; a stale probe reports on code
that no longer exists.

## Would the suite notice if a guard were weakened?

19 mutations and 2 controls. Measured: **21 rows, 18 RED, 3 GREEN, 0 BROKEN
(0 unpinned), 0 anchor problems**, every verdict pinned and re-run for
self-consistency (21/21, exit 0).

The audit found **8 survivors of 17**. Six of those eight are RED today
(`M1`, `M2b`, `M6`, `M7`, `M8`, `M12`), closed by audit F3's seven new tests;
`M4b` and `M9` remain GREEN, and they are not the same kind of thing.

### `M4b` — the boundary is pinned on ONE of the invariant's TWO copies

Audit F3 added `F3/M4b-shape` (`root.zig:1352`) to pin the strict `>` in the
idle-timeout comparison: a gap of exactly `timeout_ns` must *not* count as
expired. It does pin it — on the path that existed when it was written, the
inline staleness check inside `insert` (`root.zig:508`). The test's only
mutating call is `r.insert(&b, 100)`.

Audit F2 then added the absolute lifetime cap, and with it a **second copy of
the same comparison** in the sweep (`root.zig:442`,
`idle_expired = now_ns -| last_seen_ns > timeout_ns`). Nothing drives
`expireOlderThan` at that exact boundary, so weakening the second copy to `>=`
leaves 42/42 green — measured, not inferred.

This is the "N copies of one invariant" shape: two sites now encode one rule and
a test covers one of them. The gap is narrow (it costs an attacker an entry
reclaimed one tick early) but the instrument that would have caught it is a
direct sweep-path test, and there isn't one.

### `M9` — a recorded decision, not an oversight

`covered >= total_len` instead of `==`. The 2026-09-10 disposition states the
reasoning: every interval summed into `covered` has already passed either the
forward (`frag_end > t`) or the retroactive bounds check against `t`, so
`covered` cannot legitimately exceed it — and says openly that this was *not*
independently proven by construction, so it is left as a coverage gap rather
than claimed as closed. That record and this GREEN row agree.

### The two controls point opposite ways

`NC-no-edit` must come back GREEN and `PC-overlap` (the predecessor overlap
check deleted outright) must come back RED, or every other row is meaningless.
The audit's runner had only the first kind, and read no exit code at all.

### ⚠ `if (false)` is how you get BROKEN instead of RED

Four rows came back BROKEN on the first run of this table, all of mine:
neutralising a guard with `if (false and …)` orphans the value the guard was
reading — a loop capture (`iv`), an `if`-capture (`t`), two decoded locals
(`flags`, `reserved`), a constant one scope up (`lifetime_cap`) — and Zig
refuses to compile an unused local. **Nothing ran**, so scoring those as "the
suite noticed" would have reported four measurements that never happened. The
cure is to spend the value rather than delete it: `iv.offset != iv.offset`,
`t != t`, `flags != flags or reserved != reserved`, `lifetime_cap !=
lifetime_cap`.

This is the fifth module in this campaign to meet that trap, and the first where
it was walked into with three earlier READMEs already describing it.

### The command line rots separately from the anchors

The audit's runner drove a bare `zig test root.zig`. Measured today it dies at
`root.zig:1504` with `no module named 'testkit'`; with `--dep testkit` the suite
is 42/42. **A dry run cannot see this** — 12 of the audit's 16 anchors still
matched their site exactly once.

And the scratch copy must be the whole `src/` tree: `root.zig` reaches
`kernel_oracle.zig` and that file imports back, so copying `root.zig` alone
builds nothing.

### Three anchors rotted, all three because the finding was FIXED

- `M1`/`M8` named the overlap scan. F8+F9 replaced the linear walk with sorted
  intervals and `lowerBound`, so there is no single loop left to weaken: there
  is a predecessor check (`root.zig:609`) and a successor loop (`:621`). `M8`'s
  original "compare only the LAST interval" has no meaning against a sorted
  structure; switching off one side is the equivalent blind spot.
- `M4b` named the timeout comparison, which F2 rewrote when it added the
  lifetime cap beside it.

⚠ `M1` first came back GREEN here, and that was **a weak mutation, not a gap**.
Putting the `+1` on the second term (`end > iv.offset + 1`) leaves the shape
`F3/M1-shape` tests indistinguishable — `[9,19)` against `[0,10)` still reads
`19 > 1`. On the first term it is RED. A mutation the targeted test cannot tell
apart is evidence about the mutation.

## The attack table: the F1 rows are closed, and the F2 carrier with them

`attacks.zig`, 29 rows, `max_frame_len = 300`. The three rows the audit marked
⛔ **F1** now refuse:

| row | audit | today |
|---|---|---|
| A3 exact duplicate, zero length | **accepted**, inflight 1 | `EmptyNonFinalFragment` |
| A3b same zero-length fragment ×6 | **6/6 accepted** | `EmptyNonFinalFragment` ×6 |
| A21 two `more=false`, same end, zero length | **both accepted** | `OverlappingFragment` |

A12, A13 and A28 (zero-length non-final fragments inside, at the end of, and
beyond an interval) also come back `EmptyNonFinalFragment`. ⚠ The audit's table
lists **A13 as accepted** and the 2026-09-10 disposition leaves it deliberately
open; measured today it is refused by F1's rule 1. The two should be reconciled
in the record — this README reports the measurement, not an intent.

**The F2 keep-alive probe now fails to hold anything.** The audit's scenario —
`max_inflight = 1`, `timeout_ns = 1000`, the same 8-byte zero-length fragment
every 999 ns — measured over 100 000 rounds (800 000 wire bytes, 99 900 timeout
periods):

| | audit | today |
|---|---|---|
| entries held at the end | **1** | **0** |
| the cheap fragment | accepted 100 000× | `refused-as-empty` **100 000×** |
| entry re-created on hitting the fragment cap | 24× | **0** |
| a legitimate `frag_id` afterwards | **`TableFull`** | **ACCEPTED** |

F2 was closed by adding `max_lifetime_ns`, but what kills this particular attack
is F1: the carrier fragment is refused before the lifetime cap is ever consulted.
Worth saying plainly, because the fix that closes a finding is not always the one
written against it.

## What a surviving mutation buys an attacker

`consequence.zig`, run against the **live** module — every row must be refused,
and every row is:

| scenario | verdict | poison | frame rewritten |
|---|---|---|---|
| C1 one-byte overlap + matching one-byte gap | `OverlappingFragment` | 0 | no |
| C2 non-adjacent overlap (rewrite `[0,50)`, 50 B hole) | `OverlappingFragment` | 0 | no |
| C3 retro-bound off-by-one | `OutOfBounds` | 0 | no |
| C4 `frag_end == max_frame_len + 1` | `OutOfBounds` | 0 | no |
| C5 header claims 4 B, 12 B on the wire | `LengthMismatch` | — | — |

Against a mutant copy these same five rows produced 50 bytes of `0xAA`
(uninitialised heap delivered as a complete frame), a rewritten frame prefix,
and two `@memcpy` panics — which is why F3 was HIGH rather than "some guards
lack tests". The file stays because the tests assert the mutation is *caught*;
this shows what a future regression would hand a caller.

⚠ It needs `DebugAllocator` specifically. Another allocator fills freed memory
with different bytes and the poison column silently means nothing.

## Config validation, and what ReleaseFast does with it (F7)

`config_probe` merges five programs the audit left in the cache as separate
files (`config.zig`, `k2.zig`, `k3.zig`, `churn.zig`, `churn2.zig`). `k2`/`k3`
differed only in a print label and a comptime toggle edited in place;
`churn`/`churn2` only in which allocator backed the tracker. Here the choice is
an argument, so measuring another case does not fork the source again.

**F7 is closed, and ReleaseFast is where that had to be shown.** The audit
measured `std.debug.assert` compiled out: `max_inflight = 0` gave **SIGSEGV
before `init` returned**, and `max_fragments_per_datagram` was not validated in
any mode. Today, in ReleaseFast:

    max_inflight = 0                  -> panic: "ReassemblerConfig.max_inflight
                                         must be at least 1" (root.zig:398), SIGABRT
    max_fragments_per_datagram = 0    -> panic: "... must be at least 1"
                                         (root.zig:402), SIGABRT

Both abort by design. `--unchecked` and `--invalid-config` exit 134 and that is
the pass condition, not a malfunction.

**K5, duplicate-drop churn.** 50 000 inserts of the same 9-byte fragment (every
second one a duplicate → `OverlappingFragment` → `dropEntry` → re-created):

| | audit | today |
|---|---|---|
| wire in | 450 000 B | 450 000 B |
| allocated and freed | 1 641 675 624 B (**3648×**) | 3 325 688 B (**7×**) |
| peak live | 66 291 B | **821 B** |

Identical to the byte under `DebugAllocator` and `smp_allocator` — it is a
counter, not a clock, so the allocator does not change the answer.

## Memory and complexity: F5 and F9 closed, measured

**F5.** README's own suggested config (`max_inflight = 64`, default
`max_frame_len`), peak live bytes:

| | audit | today |
|---|---|---|
| 64 zero-length first fragments | 512 B wire → 4 212 312 B live (**8227×**) | **all 64 refused**, 0 B held |
| 64 one-byte first fragments | 7313× | 576 B wire → 22 767 B live (**39×**) |

F8's lazy buffer sizing is the reason: `Entry.buf` is allocated for what the
first fragment needs (`root.zig:524`) and grown by `ensureCapacity` only as
later fragments require, instead of `max_frame_len` up front.

**F9 is no longer quadratic.** The overlap scan alone, arena-backed, `n`
one-byte fragments into one datagram — `ns/(n²/2)` settling to a constant is
what "quadratic" looks like, and it does the opposite:

| n | ns/(n²/2) |
|---:|---:|
| 64 | 4.911 |
| 256 | 0.970 |
| 1024 | 0.200 |
| 4096 | **0.050** |

The audit measured this settling at **0.44 ns** across the same range. On a real
split (60 000 B in `n` pieces) per-fragment cost falls from 1847 ns at `n = 64`
to **135 ns** at `n = 4096`, where the audit had 3.96 ms total for `n = 4096`
against 70.9 µs at `n = 256` — 56× for 16× the fragments. Today the same 16×
costs 3.6×.

⚠ Absolute nanoseconds here belong to this machine. The **ratios** are the
portable part, and the audit said the same about its own numbers (it ran under
three concurrent agents).

⚠ **`-OReleaseFast` must come BEFORE the `-M` arguments.** Placed after, it is
silently ignored, the binary is Debug, and Debug and ReleaseFast then agree to
within a per-mille — which looks like a result. Both probes print
`builtin.mode`; read it before quoting anything.

## ⚠ F4: closed by documentation in September, and the documentation is now stale

This one needs stating carefully, because the obvious reading is wrong in both
directions.

F4 said the SPEC's claim — *"an attacker cannot grow it past `max_inflight *
max_frame_len` no matter how many fragments or datagrams it sends"* — is false,
because the formula omits the interval list. It was **closed on 2026-09-10 by
correcting SPEC.md**, which now says openly that the buffer bound is not the
whole per-entry cost and quotes the audit's overshoot figures.

Measured today against that corrected text:

| `max_frame_len` | SPEC says (audit) | measured now |
|---:|---:|---:|
| 65535 | 1.37× | **0.44×** (overshoot 0 B) |
| 9216 | 3.68× | **3.13×** |
| 1500 | 17.49× | **5.47×** |

So the finding's *direction* still holds — the tighter a consumer sets
`max_frame_len`, the larger the share of real memory the formula does not
describe — but every number in the corrected paragraph is now too pessimistic,
and one sentence in it is no longer true at all:

> Every reassembly-table entry pre-allocates a fixed `config.max_frame_len`-byte
> buffer up front rather than growing on demand …

F8 removed that behaviour on **2026-09-11**, the day after the documentation was
corrected. `modules/ethfrag/README.md` carries the same claim (*"`Entry.buf`
allocates the full `config.max_frame_len` bytes up front"*) and the same dead
number (*"512 bytes on the wire hold 4,212,312 bytes live"*) — measured above as
**64 fragments refused outright, 0 bytes held**.

**This is a documentation-only fix that a later code fix aged out, one day
apart.** It is recorded here and in the audit record; nothing in `src/` or the
two documents was changed by this migration, because an instrument must not
quietly reshape the thing it verifies.

## What was deliberately not brought over

`.zig-cache/audit-ethfrag` was 206 MB. What stayed behind:

- **Four module snapshots** (`mut/`, `mut2/`, `cq/`, `fuzzsrc/`, each a
  `root.zig` + `kernel_oracle.zig` pair) and every built binary — 78 MB of it in
  `fuzzbuild/` alone. The snapshots predate F1, F2, F3, F7, F8, F9, F13 and F6's
  harness rewrite; a mutation run against them would measure a module that no
  longer exists.
- **`k2.zig`, `k3.zig`, `churn2.zig`** — merged into `config_probe.zig` as
  arguments, as described above.
- **`fuzz-reach.log` and the instrumented fuzz copy** — spent. F6's reach
  measurement now lives in the repository as `scripts/modtest <m> --fuzz=N` plus
  `scripts/fuzz-coverage.py` (commit `e6434b94`), and the guards it measures are
  `noinline` markers in `src/` rather than a patched copy.
- **`ex.strace`, `test.strace`, `runex.sh`** — one-shot evidence that the gate
  makes no network calls, already recorded in the audit file.

`capture.py` was never in the cache: it was written into `modules/ethfrag/tools/`
directly when F13 was closed (2026-09-15), which is the shape §9 asks for and
the reason this directory already existed.
