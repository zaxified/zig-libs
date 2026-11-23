# scripts/mutation — the mutation kit

The source-agnostic half of a mutation audit (CONVENTIONS.md §9, "the mutation
kit"). Nothing here names a module or anchors on a line of its source; the
per-module part — the mutant list, the table of verdicts — is the audit's own
scratch and is deleted when the audit closes, as before.

The method (owner's rules): **mutant schemata**, never a rebuild per mutant —
one build of a test binary with every mutant behind a runtime switch, run once
per mutant, in a detached COPY of the tree; a strict verdict; a baseline first.

## 1. A detached copy

```sh
git worktree add --detach .zig-cache/mut-wt HEAD
cd .zig-cache/mut-wt
```

Never mutate the tree you commit from. `git worktree remove --force
.zig-cache/mut-wt` at the end.

## 2. The mutant list

A TSV, one mutant per line: `id`, `file`, `line`, the original text, the
mutated text. The mutated text keeps the original as its other arm and names
`mut(<id>)`:

```
1	modules/crc32c/src/root.zig	198	if (a & m != 0)	if (!mut(1) and a & m != 0)
4	modules/crc32c/src/root.zig	118	return ~raw(b, 0xffff_ffff, bytes);	return if (mut(4)) raw(b, 0xffff_ffff, bytes) else ~raw(b, 0xffff_ffff, bytes);
```

One mutant per guard × operator class (drop / flip / off by one / skip an
assignment / the other arm / skip a wipe); nothing on arid code (printing,
debug-only asserts). Line numbers are those of the file before insertion.

```sh
python3 scripts/mutation/insert.py mutants.tsv CRC32C_MUT
```

Two or more mutants on ONE anchor (same file, line and original text: `<` to
`<=` and to `>`) are listed as separate lines; they nest, each later one into
the original arm of the one before:

```
5	f.zig	40	a < b	(if (mut(5)) a <= b else a < b)
6	f.zig	40	a < b	(if (mut(6)) a > b else a < b)
```

becomes `(if (mut(5)) a <= b else (if (mut(6)) a > b else a < b))`. An earlier
replacement that does not hold the anchor exactly once (a prefix form,
`if (x` → `if (!mut(1) and x`) cannot take a second one and is refused with
that reason (since 2026-11-17; three agents had hand-patched the kit for it).

It refuses an anchor that is not on its line exactly once, a missing
`mut(<id>)`, a duplicate id, and fails unless the distinct `mut(N)` calls it
wrote equal the list (a failed insert once left a copy unmutated, and every
mutant "survived"). The switch it adds returns the original in comptime code
and reads `<ENV_NAME>` through `std.testing.environ`, so the mutated file
compiles only into a TEST binary.

Comptime traps: a format string or comptime argument cannot take a runtime
switch — mutate the whole statement; a literal inside a runtime `if` needs a
type (`@as(usize, if (mut(3)) 0 else K)`).

## 3. One build, then the runner

```sh
hw run --name <m>-mut-build -- zig test -OReleaseSafe --dep testkit \
    -Mroot=modules/<m>/src/root.zig -Mtestkit=modules/testkit/src/root.zig \
    --cache-dir .zig-cache --test-no-exec -femit-bin=.zig-cache/<m>-mut
hw run --slots 4 --name <m>-mut --quiet 600 -- \
    bash scripts/mutation/run.sh .zig-cache/<m>-mut <ENV_NAME> <last-id>
```

**A module whose suite is slow, or whose deps make a hand-written `zig test`
line fragile:** build through the build system with the kit's runner instead,
then run the binary directly:

```sh
hw run --name <m>-mut-build -- zig build test-<m> -Doptimize=ReleaseSafe \
    -Dtest-runner=scripts/mutation/test_runner.zig     # builds, runs mutant 0 once
B=$(ls -t .zig-cache/o/*/<m> | head -1)
MUT_TESTS=zkproofs.test.,presign.test. <ENV_NAME>=17 $B
```

`test_runner.zig` is the default terminal runner plus `MUT_TESTS` (comma-
separated substrings of the fully qualified test name; unset = all) and
fail-fast at the first failing test (`MUT_FAIL_FAST=0` to keep going), with
the default runner's words, so `run.sh` classifies its output unchanged
(`MUT_TESTS` passes through its environment). Without it a whole-suite run per
mutant costs the full suite even for a mutant killed by the first test of its
own file (threshold_ecdsa: 221 s × 111 mutants).

`run.sh` runs mutant 0 (the original) first and stops if it does not pass
under the exact command; each mutant under `ulimit -v` and
`setsid -w timeout -s KILL` in its own session; one TSV line per mutant:

| verdict | meaning |
|---|---|
| `PASS` | mutant 0 only |
| `KILLED` | a failing test (`FAIL (…)`, `<k> failed.`), a panic or a safety check, or a signal |
| `HANG` | killed at `MUT_TIMEOUT` (20 s) — counts as killed, reported apart |
| `SURVIVED` | exit 0: needs a killing test, an argued EQUIVALENT, or a finding |
| `UNCLEAR` | non-zero exit with none of the above — never a kill; look at `out-<id>.log` |

`ONLY="0 5 9"` reruns a subset (the baseline still first). Knobs:
`MUT_TIMEOUT`, `MUT_ULIMIT_KB` (default 3 000 000), `MUT_LOGDIR`.

Smoke-tested 2026-11-14 on `crc32c`: four mutants gave HANG ×2 (a loop guard,
the polynomial), SURVIVED (a cache bypass, cost-only) and KILLED
(`FAIL (TestExpectedEqual)`).

## 4. Verdicts and the card

Strict: a changed pass/skip count is not a kill. Every survivor ends as a new
killing test, an EQUIVALENT naming the invariant ("cost-only" for a speed-only
mutant), an UNOBSERVABLE naming the injection it would need, or a finding.
The card's `**Audit:**` line records `mutation <date> (<killed>/<total>, <n> eq)`
with killed + eq + survivors = total.

A card entry whose previous mutation run recorded no counts (`mutation <date> ·
src ?`) does not take a delta run's counts: those would read as a whole-module
score. Put the delta in a SPEC paragraph and run the whole module.

## 4a. `score.py`: the card line from the tables

Nobody sums counts by hand (six card errors, 2026-11-08..22). `score.py` turns
the verdict tables into the card's mutation entry, in the exact grammar the
grade gate parses (`mutation <date> (<killed>/<total>[, <n> eq])`):

```sh
python3 scripts/mutation/score.py whole --table m.tsv [--table m2.tsv] --date YYYY-MM-DD \
    --src <16 hex> [--total N] [--card modules/<m>/SPEC.md --write]
python3 scripts/mutation/score.py delta --card modules/<m>/SPEC.md --table d.tsv --date ... \
    --src-from-report maturity.tsv [--write]
python3 -I scripts/mutation/score.py --self-test        # in the checks-fast phase
```

- A table has a header with a `verdict` column (and `id`), or is `run.sh`'s
  headerless output. A later table / row overrides an earlier one per id, so
  `run.sh` output followed by the analysed table works. EQUIVALENT, EQ and
  UNOBSERVABLE count as `eq`; KILLED and HANG as killed (the first word of the
  cell decides: `KILLED-DEBUG` is killed, with a warning); SURVIVED, UNCLEAR
  and anything else is OPEN. The baseline row 0 is ignored.
- `whole`: total counts every mutant (`--total N` when ids were never run, so
  a cut-short run still gets a score; OPEN = total - killed - eq).
- `delta` is cumulative: old + delta (783/824, 41 eq + 13/14, 1 eq = 796/838,
  42 eq). It prints the delta's own numbers for the dated SPEC paragraph, and
  REFUSES (exit 1, card untouched) when the card's mutation entry has no counts
  (`src ?`, `none`): whole-module run needed.
- `--write` rewrites the mutation and `src` parts of the card's `**Audit:**`
  line; the review part is untouched. `--src-from-report` reads the `src now`
  column of `zig build maturity-report` (the hash is never computed here).

## 5. Stack-burn and wipe sites

A wipe (`secureZero`) or a stack burn is observable only to the module's
ReleaseFast stack probe, so these mutants need a ReleaseFast schemata build.
Two traps, both met on 2026-11-17/18 (dkg, bip32, p256, opaque):

- **A switch at the burn site perturbs the frame the probe reads.**
  `{ if (!mut(n)) burn.stack(X); }` adds a call and a load in the caller's own
  frame, between the body and the burn; the probe's baseline (mutant 0) then
  finds secrets above the burn although the plain ReleaseFast build is clean.
  Do not record such mutants as UNOBSERVABLE and do not raise the burn: move
  the switch INTO the callee. In the scratch copy, rewrite each site
  `burn.stack(X);` → `burn.stackAt(X, ID);` and `std.crypto.secureZero(T, s);`
  → `burn.zeroAt(T, s, ID);` with the mutant id as a comptime argument, and
  append to the module's `burn.zig`:

  ```zig
  var w_id: u32 = 0;
  var w_init: bool = false;
  noinline fn wInit() void {
      const v = std.testing.environ.getPosix("<ENV_NAME>") orelse "0";
      w_id = std.fmt.parseInt(u32, v, 10) catch 0;
      w_init = true;
  }
  inline fn wOn(comptime id: u32) bool {
      if (!w_init) wInit();
      return w_id == id;
  }
  pub noinline fn stackAt(comptime n: usize, comptime id: u32) void {
      if (wOn(id)) return;
      // the module's own burn body, e.g. a volatile zero-fill of n bytes
  }
  pub inline fn zeroAt(comptime T: type, s: []volatile T, comptime id: u32) void {
      if (wOn(id)) return;
      std.crypto.secureZero(T, s);
  }
  ```

  With the switch off the caller's frame is the original one. Confirm with
  mutant 0 (the probe must pass) before trusting any verdict.
- **A red baseline with NO burn-site switch is a finding**, not an artefact:
  the original logic leaves a secret under some code shape (dkg
  `takeKeyShare`, 2026-11-17: an entry point without a burn). Fix the module
  (a noinline `…Unburned` body plus a burn), then measure. A residue that is
  a copy of the function's own by-value RESULT (bip32 `neuter`) sits in the
  wrapper's frame above any burn; it is output the caller holds — exclude that
  needle for that entry point with a comment, or offer an out-pointer variant.

Heap wipes right before `free` are UNOBSERVABLE in safe builds
(`Allocator.free` poisons the bytes first); a ReleaseFast test with a scanning
allocator can kill them.
