# `drand` verification instruments

Six instruments, in two groups. None is wired into `zig build`: each is run by
hand and prints what it found. They are here rather than in `src/` because each
needs a foreign toolchain — a Python, and in two cases the live network — which
a module must never require (`CONVENTIONS.md` §9).

## Where this module's vectors come from, and how to refresh them

⚠ Read this before running `fetch.py`. `modules/drand` has **no `testdata/` and
no generated vector file**: the quicknet `/info` document and the round
documents are inline string literals in `src/root.zig` and `src/verify.zig`.
`fetch.py` and `gen_vectors.py` are the recipe that produced them and the way to
refresh them — the output is pasted in by hand, deliberately, because a vector
that changes without a human reading the diff is a vector nobody checked.

    python3 fetch.py live/          # hits api.drand.sh, writes live/*.json
    python3 gen_vectors.py live/    # turns those into Zig literals on stdout

## What each one is for

| tool | question it answers | why this tool and not a test |
|---|---|---|
| `chainhash.py` | Does each chain's advertised hash actually match the fields it publishes? | The module reads the chain hash from `/info` and trusts it; nothing in the module derives it. A re-derivation catches a swapped field or a substituted document. |
| `ch2.py` | Which encoding reproduces the published hash? | The search that *found* the formula `chainhash.py` uses. Kept so that formula rests on a reproducible experiment rather than on someone having read drand's Go. |
| `mutate.py` | Would this module's suite notice if a check were removed or weakened? | 22 mutations over the verification path — subgroup checks, identity guards, the randomness comparison, the signed message. Tests prove the code passes; only mutation shows the suite can fail. |
| `mutate_m10.py` | — | M10 alone, re-run. Removing the randomness comparison left `digest` unused, so the first attempt was a BUILD-ERROR — and a mutation that does not compile is not a verdict, it is a missing row. Kept as the evidence that the row was actually obtained. |
| `fetch.py` | What does the live network currently serve? | Fixtures for the vectors above, from two chains and ~60 rounds. |
| `gen_vectors.py` | — | Formats what `fetch.py` captured as Zig literals. |

## ⚠ `mutate.py` edits the tracked tree

It patches `modules/drand/src/*.zig` in place and restores with
`git checkout --` in a `finally`, refusing to start unless the module is
pristine. That is enough for a normal run and for a `Ctrl-C`, and **not** enough
for a SIGKILL, an OOM kill or a power loss: those leave a mutated file in the
working tree. If it ever exits without restoring, `git checkout -- modules/drand`
puts it back.

The safer shape is to copy the sources to a scratch tree and build there — see
`modules/hqc/tools/mutate.py` and `modules/k256/tools/`. This one was not
converted because the conversion cannot be validated without re-running all 22
mutations, and an unvalidated rewrite of a mutation runner is worse than a
documented hazard.
