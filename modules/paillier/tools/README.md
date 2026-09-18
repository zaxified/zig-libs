# `paillier` verification instruments

Two instruments that work as a pair, run by hand. Neither is wired into `zig build`:
the oracle needs a Python. `zig build test-paillier` must require
neither (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners and per-finding probes were deleted on
2026-09-17; what they found is pinned by tests in `src/` or filed as open findings.

Figures below were measured on 2026-09-16 against the tree as it stands.

## Does a second implementation agree, at real key sizes?

    scripts/lib/capped zig build-exe --cache-dir .zig-cache \
      -femit-bin=.zig-cache/paillier-oracle/probe_vectors \
      --dep paillier --dep montint \
      -Mroot=modules/paillier/tools/probe_vectors.zig \
      --dep montint -Mpaillier=modules/paillier/src/root.zig \
      -Mmontint=modules/montint/src/root.zig
    .zig-cache/paillier-oracle/probe_vectors 512 200 2>&1 \
      | modules/paillier/tools/oracle_paillier.py

`probe_vectors.zig` drives the public API and prints key material plus one line
per trial; `oracle_paillier.py` recomputes every line from `n`/`g`/`lambda`/`mu`
with `pow(x, y, m)` alone, from the Paillier 1999 formulas. No shared code.

Measured at 512 bits / 60 trials: `V=60, A=15, P=15, M=15`, **0 mismatches**.

SPEC grades this module *class B · oracle EXTERNAL*. In the tree that rests on
four `phe`-cross-checked toy vectors against one small key; this is the part
that makes the grade true at real sizes and across all four homomorphic
operations.

⚠ **`2>&1` is not decoration.** Every line is written with `std.debug.print`,
which goes to stderr, so a plain `|` captures nothing. Dropping it produced
exactly that on 2026-09-16: probe exit 0, zero lines, and an oracle that saw an
empty stream.

⚠ The oracle **exits on the result**, and each branch was demonstrated rather
than assumed: the full stream exits 0, a truncated one exits 2 naming the
missing `END` marker, an empty one exits 2. Without the `END` check a probe
that died halfway would yield a short stream this script would compare happily
and call clean — content it could judge, truncation it could not.
