# `netsim` verification instruments

One instrument: a mutation runner. It is here rather than in `src/` because it
drives the compiler as a subprocess and writes working trees, which a module's
own test must never do (`CONVENTIONS.md` §9).

| tool | question it answers | why this tool and not a test |
|---|---|---|
| `mutate.sh` | Would the suite notice if a fault stopped happening? | A fault injector's worst failure is silent: a dropped packet that is never dropped leaves every test green and every simulation meaningless. Tests prove the simulator runs; only mutation shows the suite can tell a working injector from a disarmed one. |

Run it with `./mutate.sh`. It copies `../src` into `.zig-cache/netsim-mutate/`,
applies one edit, checks by `diff` that the edit landed, and runs the suite. The
tracked tree is never touched.

## How to read the output

`RED` means the suite caught the mutation — the guard is covered. `GREEN` means
the guard could be deleted and every test would still pass; that is the finding.
`SKIPPED` means the edit did not apply, which is a **missing row**, not a
result — never read it as either verdict.

The five mutations under POSITIVE CONTROLS must all be RED. If one is not, the
runner itself is broken and the rest of the run says nothing; it exits non-zero
so a scripted run cannot miss that.

## ⚠ Two anchors are stale

`severed ignores partitions` and `max_events_cap backstop removed` no longer
match `sim.zig` and report SKIPPED. Re-deriving them means reading those two
functions and writing the edit against what is there now — not relaxing the
match until something sticks.

The audit's own `base/` snapshot was deliberately left behind: by 2026-09-16 it
had drifted 748 lines from `sim.zig` and 285 from `root.zig`, so it was mutating
code that no longer existed. `mutate.sh` copies from `../src` at run time
instead.
