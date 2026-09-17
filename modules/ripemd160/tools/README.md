# `ripemd160` verification instruments

Seven instruments and one shared helper (`out.zig`), run by hand. None is wired
into `zig build`: `oracle_sweep.py` needs a **foreign toolchain** (Python
`hashlib` with ripemd160 and the `openssl` CLI), `bigsweep` writes ~59 MB of
blobs, and the mutation runner costs a full build plus 13 tests per row.
`zig build test-ripemd160` must require none of it (`CONVENTIONS.md` §9).

Figures below were measured on 2026-09-17 against the tree as it stands.

## Where the module's constants come from

`src/root.zig`'s KATs are individual digests, and a constant inherits whatever
mistake produced it. These are how those numbers can be **re-derived** rather
than re-read.

| tool | question it answers |
|---|---|
| `sweep.zig` | What does the module return for **every** length 0..1024? |
| `oracle_sweep.py` | Do Python `hashlib` and `openssl` agree, counted **separately**? |
| `bigsweep.zig` | Do the multi-megabyte sizes agree, one-shot vs streamed vs external? |
| `filehash.zig` | Does the module agree with `openssl` on bytes **somebody else** chose? |
| `misuse.zig` | Exhaustive split differential, and what the module does when misused. |
| `bench.zig` | Does `SPEC.md`'s Performance section still hold on this machine? |
| `mutate.py` | Would the suite notice if a constant were wrong? |

Measured today:

- **Oracle sweep: 1025 lengths, 3 075 comparisons, 0 mismatches**, and `openssl`
  returned **1025 of 1025** digests. That last number is reported on purpose —
  an oracle that silently returned nothing would otherwise look like a clean
  run, so the script exits non-zero if the counts disagree.
- **Multi-megabyte: 12 blobs (59 MB), 36 external comparisons, 0 mismatches**,
  and one-shot equals streamed on all 12.
- **Exhaustive split differential: 3 178 512 comparisons, 0 mismatches**
  (180 901 two-way + 2 997 411 three-way + 200 fixed-chunk). The module's fuzz
  target walks the splits its input picks; this walks every split there is.
- **All four optimize modes are byte-identical**: the 1025-length sweep built in
  Debug, ReleaseSafe, ReleaseFast and ReleaseSmall produces the same 1025 lines,
  `sha256 576cbe15…`, in all four.

⚠ Both oracles are kept and counted separately even though `hashlib`'s
ripemd160 is itself usually OpenSSL-backed — "two oracles" that share a backend
are one witness wearing two hats, and that should be visible rather than
assumed away.

## Would the suite notice if a constant were wrong?

    modules/ripemd160/tools/mutate.py              # the whole table
    modules/ripemd160/tools/mutate.py --only PAD   # rows whose label contains "PAD"
    modules/ripemd160/tools/mutate.py --controls   # only the controls

31 mutations and 2 controls, each copying the live `modules/ripemd160/src/root.zig`
into a per-process scratch tree. A hash has no branches worth weakening: every
row is one wrong **token** — a table entry, a rotation amount, a round function,
an endianness, a padding bound.

Measured: **33 rows, 32 RED, 1 GREEN, 0 BROKEN, 0 anchor problems**, every
verdict pinned and re-run for self-consistency (33/33).

### The one GREEN is supposed to be green

The two controls point **opposite ways**, and that distinction is the whole
reason the table can be trusted:

- `NC-no-edit` — mutates nothing and must come back **GREEN**. If the unmutated
  suite does not pass, nothing below it measures the module.
- `PC-broken-IV` — corrupts `h[0]` and must come back **RED**. If a broken
  initialisation vector survives, the runner is measuring nothing at all.

The audit's runner had only the first kind, and **no exit code**: every row
printed and the process returned 0 whatever the table said.

### ⭐ The audit's two survivors are now both RED, and that is the result

The 2026-09-04 audit measured 30 RED / 3 GREEN, of which one green was its
control — so **two real survivors**, and both were real holes:

| row | then | now | what closed it |
|---|---|---|---|
| `PAD SPILL: < 8 → < 7` | GREEN — survived the suite *and* 300 069 `--fuzz` runs | **RED**, 1 test fails | audit F1: a KAT at length **56**, the first length that forces a second padding block |
| `drain guard >= 64 → > 64` | GREEN — silent wrong digest in ReleaseFast, out-of-bounds write | **RED**, the mutant **panics** | audit F8: `assert(d.buf_len < 64)` plus a call-order test |

That is what this instrument is for. It does not prevent the finding — the
**tests in `src/` do that**. It answers the question the tests cannot ask about
themselves: *are they actually watching?* Re-running it after a fix is how a
closed finding is shown to be closed, rather than asserted to be.

### The anchors held; the command line did not

Unusually, **all 32 anchors still matched their site exactly once** — the
mutations aim at the constant tables, and the F4 rewrite (`while (j < 80)` →
`inline for (0..80)`) changed only the loop around them.

That tells you nothing about whether the runner works. Measured 2026-09-17, the
audit's bare `zig test m.zig` fails at `root.zig:517` with
`no module named 'testkit'`; with `--dep testkit` the same suite is
**13/13, rc=0**. A dry run cannot see this — which is exactly why a green
anchor count is not a green runner.

## Cost, and the SPEC claim it checks

`SPEC.md`'s "Performance" section asserts numbers no test can pin — throughput
is not a pass/fail property. `bench.zig` is the only way to re-derive them.

Measured today (ReleaseFast, best of 5 rounds, spread reported alongside):

| what | measured | `SPEC.md` says |
|---|---|---|
| one-shot, 8 KiB | **393.5 MiB/s** (spread 6.0 %) | unrolled 340–362 MiB/s |
| one-shot, 1 MiB | **395.0 MiB/s** (spread 2.8 %) | — |
| 1 MiB streamed in 64 B chunks | **395.7 MiB/s**, ratio **1.000** | — |
| `hash160(33 B)` | **383.4 ns/call = 2.61 M calls/s** | — |

⚠ Today's numbers sit **above** the SPEC's stated 340–362 MiB/s range. The SPEC
is not wrong — it records an A/B on a machine that was shared with another agent
that day, and says so — but the range is a measurement, not a bound, and a
reader should not treat it as one.

`ratio = 1.000` is worth its own line: feeding 1 MiB in 64-byte `update` calls
costs nothing measurable against one-shot, so the streaming path carries no
per-call overhead worth avoiding.

## What was deliberately not brought over

`.zig-cache/audit-ripemd160` was 268 MB. Of its 35 `.zig` files, most are
**copies of the module** in various states (`mod/`, `mut/`, `mut2/`, `green/`,
`perf/baseline.zig`, `perf/unrolled.zig`, `fuzz/f.zig`, `example/`) — mutants,
instrumented builds and A/B arms, not instruments.

- `hmac.zig` — **spent**. It was the first outside caller to drop `Ripemd160`
  into std's generic `Hmac`, which is the only thing that consumes
  `block_length`. It is now a test: *HMAC-RIPEMD160: RFC 2286 test vectors via
  std.crypto.auth.hmac.Hmac(Ripemd160)* (`src/root.zig:462`), closing audit F6.
- `allocprobe.zig` — **spent**. It used `strace` to show zero allocations. The
  module has **no `Allocator` in any signature** (checked), so allocating would
  require an API change, and the type system now carries the claim.
- `ab.zig`, `perf/baseline.zig`, `perf/unrolled.zig` — **spent**. They answered
  audit F4 (`inline for` is ~3× faster); the winner shipped, so the comparison
  has no second arm left. `bench.zig` measures what shipped.
- `demo.zig`, `demo64.zig` — **spent**. They demonstrated what the two surviving
  mutations *did*; both mutations now come back RED, so their subject is gone.
- `inline-for.diff`, `mutation-g7.diff`, `mutation-g64.diff`,
  `fuzz-instrumentation.diff` — **spent**: each is either shipped in `src/` or
  is now a row in `mutate.py`.

⚠ `filehash.zig` existed **only** in `.zig-cache/audit-ripemd160`, not in the
audit's repro stash. A migration that trusted the stash alone would have deleted
it with the cache.
