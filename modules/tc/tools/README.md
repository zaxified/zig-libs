# `tc` verification instruments

Six instruments in three groups. None is wired into `zig build`: each is run by
hand and prints what it found. They live here rather than in `src/` because each
either needs a **foreign toolchain** — iproute2, strace, unprivileged user
namespaces, a Python — or costs far more than a test lane should, and
`zig build test-tc` must require none of it (`CONVENTIONS.md` §9).

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

## Would the suite notice if a guard were removed?

    modules/tc/tools/mutate.py             # the whole table
    modules/tc/tools/mutate.py M13 M18     # only those rows
    modules/tc/tools/mutate.py --controls  # only the two positive controls

40 mutations plus 2 positive controls, each one copying the **live** `src/*.zig`
into a per-process scratch tree and rebuilding the whole suite from the copy.
About 1 s per row (0.86 s build, 0.07 s run), so the full table is under a
minute — there is no reason to run a subset except when iterating.

Measured: **42 rows, 39 RED, 3 GREEN, 0 anchor problems**, every row matching
its pinned verdict. Two of those greens are real guards:

| mutant | guard | suite |
|---|---|---|
| **M13** | `parseU32Options`' `uw.keys_len < uw.keys.len` bound | **GREEN** |
| **M33** | `spec.linklayer = … & LinkLayer.mask` | **GREEN** |

M13 is the one worth knowing. Removing that bound leaves the module's own suite
**green (exit 0)** — and `probe_hostile.zig` on the same mutated tree **aborts**:

    index out of bounds: index 8, len 8
    src/filter.zig:256: uw.keys[uw.keys_len] = U32Key.decode(…)

That is the whole case for keeping these instruments in the tree: the probe
reproduces an out-of-bounds write on the exact line the guard protects, and the
gate cannot see it.

### Three things this runner had to be taught, each of which had already gone wrong

- **The verdicts are measured, never inherited.** The 2026-09-04 audit found 36
  of 53 mutants RED. Five fix passes have closed F1–F12 and F-VM1 since, and
  several of those fixes exist precisely to turn a row from GREEN to RED, so
  copying the old verdicts forward would have pinned them upside down.
- **M23's anchor had rotted by GROWTH, not by rewrite.** It named
  `while ((mtu >> @intCast(cell_log)) > 255) …`; the live loop gained a
  `cell_log < max_cell_log` clause when F2/F7 were fixed, so the old text
  matched **zero** times and the row read "not applied" while looking like a
  result. A row that was not applied is *missing*, not passing — the runner
  exits non-zero on it.
- **M18 was one row naming two sites.** Its anchor matched twice in
  `action.zig` (the actions path and the refs path) and `str.replace` patched
  both, so the verdict was about two guards jointly and about neither
  separately. Split into M18/M18b, each anchored by the call that follows it.

### And why there are two control rows

`PC-ok` is a no-op edit that must stay **GREEN**; `PC-bad` must come back
**RED**. Without them a broken command line — one missing `--dep` — fails every
build identically, and a table of uniform REDs reads exactly like a suite that
catches everything. That is not hypothetical: `whois`'s migrated runner shipped
with `testkit` missing and every row read RED, the no-op control included.

⚠ `PC-bad` must fail at **runtime**, not in the compiler. Its first version
shrank `rate_table_entries` to 4 and went RED with *"index 255 outside array of
length 4"* — a compile error, which proves the mutation landed and proves
nothing about whether the test binary ever ran. It now shifts the golden host's
`us2t` by one tick: that compiles cleanly and is caught by an assertion
(`131 passed; 7 skipped; 16 failed`).

## Inputs the suite never produces

| tool | question it answers | measured |
|---|---|---|
| `probe_hostile.zig` | What do the parsers do with malformed kernel replies — over-long `TCA_ACT_KIND`, a 4000-byte cookie, a `u32` selector claiming 40 keys, truncated fixed structs, a 32-deep nest? | **11/11 pass** |
| `probe_reach.zig` | Is an out-of-range `cell_log`, `mtu` or `kind` reachable through the public API? | **7/7 pass** |

Both run as a `zig test` over the real module graph — `--dep netlink --dep
testkit`, which is what `build.zig` declares — so the dependency set stays
correct by construction rather than by a hand-kept list that rots. The exact
command line is in each file's header.

⚠ `probe_reach.zig` is written the other way up from the audit probe it
replaces, and the reason generalises. When it was written the guards did not
exist, so *"the test aborts"* was the finding and the cases needed no assertion
at all. F2/F7 then closed that, and the same four cases came back
`InvalidCellLog` ×3 and `OptionsTooLong` ×1 — **4 of 7 failing, every failure
being the fix working.** An instrument that fires on every healthy run is no
better than one that cannot fire at all; it just fails in the opposite
direction. Each case now names the error the guard owes.

One of its case names was also a stale claim: the audit called the `mtu = 2^31`
row *"silently wraps the last table entry to 0"*, and the arithmetic saturates
today (`RTAB[254] = RTAB[255] = 4294967295`). The test asserts the table does
not **decrease** and says nothing about how that is spelled.

## What was deliberately not brought over

The 2026-09-04 audit left 17 files in `.zig-cache/audit-tc/`. Six became the
instruments above; the rest were dropped, each for a stated reason:

- `smith_probe.zig` — spent. It measured the `Smith.bytes` + ranged-draw trap
  that fed every fuzz harness an empty slice. The fix is in `src/` (one
  `smith.slice` call) together with an **executable** corpus test that pins the
  reached counts, which is strictly better than a probe nobody runs.
- `ratespec_probe.zig`, `ratetable_ab.zig`, `errdefer_probe.zig` — each kept its
  own copy of the code it was checking (a `cp` of `ratespec.zig`, an arm A
  "copied verbatim", a control flow "copied verbatim from root.zig:598-652").
  Those copies had rotted 101 and 608 lines behind, and all three findings are
  closed.
- `tcmod/` + `dumpstub.py` — a whole snapshot of the module, 608 lines behind on
  `root.zig` alone, and the one script that read it.
- `bench.zig` — an ancestor of the live `src/bench.zig`, 302 lines behind.
