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
