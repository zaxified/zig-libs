# `drand` verification instruments

Four instruments. None is wired into `zig build`: each is run by
hand and prints what it found. They are here rather than in `src/` because each
needs a foreign toolchain — a Python, and in two cases the live network — which
a module must never require (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

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
| `fetch.py` | What does the live network currently serve? | Fixtures for the vectors above, from two chains and ~60 rounds. |
| `gen_vectors.py` | — | Formats what `fetch.py` captured as Zig literals. |
