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

## ⚠ One anchor is stale (M16)

Measured 2026-09-16 against the current sources: **22 of 23 anchors still match
exactly once; M16 no longer matches at all.** It named `expectedRound`'s
`return (now_unix - info.genesis_time) / info.period_seconds + 1;` in
`verify.zig`, and that text is gone.

The runner does not fail open on it — a non-matching anchor is reported as
`PATCH-MISS`, and an anchor matching more than once as `AMBIGUOUS(n)`, neither
of which is a verdict. So the row is **missing**, not passing. Re-deriving it
means re-reading `expectedRound` and naming the current site; loosening the
match until it sticks would produce a mutant that is neither the original nor
the intended edit.

## The mutation runners mutate a separate worktree, not the tracked tree

Both `mutate.py` and `mutate_m10.py`: every edit lands in a **detached
`git worktree`** under `.zig-cache/drand-mutate/wt`, created on first use and
then **re-pointed at the current `HEAD` on every run**. `mutate_m10.py` imports
`ensure_worktree()` from `mutate.py` rather than restating it, so there is one
implementation of this rule and not two that can drift apart.

⚠ The re-pointing is not housekeeping. A worktree created once and merely
*reused* stays pinned at whatever `HEAD` was that day, so every later run
mutates a module some commits behind the tree it reports on — an instrument
keeping its own copy, which is the exact defect `CONVENTIONS.md` §9 exists to
prevent and which this conversion nearly reintroduced in a new form. It is
caught here: the runner refuses if the checkout is dirty, and otherwise moves
it, printing `worktree advanced <old> -> <new>`. A SIGKILL, an OOM
kill or a power loss mid-run therefore cannot leave a mutated file in the tree
you work in. Remove the checkout with:

    git worktree remove --force .zig-cache/drand-mutate/wt

Until 2026-09-16 this patched `modules/drand/src/*.zig` **in place**, restoring
with `git checkout --` in a `finally` — enough for a normal exit and a `Ctrl-C`,
not enough for anything that skips the `finally`. The conversion was deferred
then on the grounds that it could not be validated without re-running all 22
mutations; what changed is the shape of the fix, not the standard of evidence.

⚠ **It still runs `zig build test-drand`, and that is deliberate.** The obvious
"scratch tree" conversion — copy `src/` somewhere and drive `zig test` with a
hand-written `-M` module graph, as `hqc` and `whois` do — would have to restate
this module's whole dependency closure (`bls12_381 → entropy`,
`tlock → bls12_381 + entropy`, plus `testkit` for tests) and would rot silently
when it changes. That is not hypothetical: `whois`'s runner was migrated with
exactly one dep missing, so **every** build failed and every row read RED, the
no-op control included. Driving the real build system inside a throwaway
checkout keeps the dependency set correct by construction *and* the tree safe,
which neither of the two obvious options does on its own.
