# `paillier` verification instruments

Three instruments, run by hand. Neither is wired into `zig build`: one needs a
Python, the other costs minutes per row. `zig build test-paillier` must require
neither (`CONVENTIONS.md` §9).

Figures below were measured on 2026-09-16 against the tree as it stands.

## Would the suite notice if a guard were removed?

    modules/paillier/tools/mutate.py              # the whole table
    modules/paillier/tools/mutate.py m5 m13       # only those rows
    modules/paillier/tools/mutate.py --controls   # only the two positive controls

17 mutations and 2 positive controls, each copying the live
`modules/paillier/src/root.zig` into a per-process scratch tree and rebuilding
the suite from the copy.

Measured: **19 rows, 8 RED, 11 GREEN, 0 BROKEN, 0 anchor problems.** The
controls behaved (`PC-ok` GREEN; `PC-bad` RED at `30 passed; 1 skipped;
10 failed` — a runtime failure caught by assertions, not a compile error).

**Ten guards the suite does not notice:**

| mutant | guard |
|---|---|
| `m1`, `m2`, `m16` | the zero-ciphertext and non-unit checks in `decrypt`, singly and both at once |
| `m4` | `r = 0` allowed |
| `m8` | the FIPS 186-5 closeness guard bypassed **at the call site** (`topBitsMatch` has its own direct test; the call does not) |
| `m9`, `m10` | `p == q`, and `p, q < 3` |
| `m11` | L-exactness in `fromPrimes` — the check composite-factor rejection rests on |
| `m13b` | `decrypt`'s own copy of the key is no longer zeroed |
| `m14` | the `n_bytes` upper bound |

⚠ `m1`/`m2`/`m16` are **redundancy, not a hole**: the 2026-09-05 audit ran a
census of hostile ciphertexts against the `m16` mutant and got byte-identical
verdicts to the original, because L-exactness (`m3`, RED) catches everything
those guards would. `m9`/`m10` are the other shape — three negative tests
(`c = 0`, `p == q`, `p < 3`) exist and **pass by the wrong route**.

### ⛔ `m13b` is new, and it came out of the migration itself

The audit had one row here. Its anchor,
`std.crypto.secureZero(u8, std.mem.asBytes(&sk.lambda));`, matches **twice** in
the current source, so `str.replace` disarmed both sites at once and the
verdict was about neither on its own. The second site did not exist when the
audit ran: closing F2 (secret copies surviving on the dead stack) added a
`var sk = sk_in; defer secureZero(...)` inside `decrypt` itself.

Split into two rows, they disagree: **`m13` is RED, `m13b` is GREEN.**
`SecretKey.deinit` is pinned by a test; `decrypt`'s own zeroing of its
by-value copy is not. That is consistent with what the audit said about F2 in
the first place — the regression tests look at the struct's fields, not at the
stack — and it means the fix's *second* half is currently unguarded.

### The verdicts are measured, never inherited

The audit found 10 of 15 mutants survived. Two of its sharpest survivors are
**RED today**: `m5` (a constant `r` for every encryption, which SPEC says is
where "Paillier's IND-CPA security lives entirely") and `m7` (Miller-Rabin
64 rounds down to 1). Both gained pinning tests after the audit. Copying the
old verdicts forward would have pinned them upside down — which is exactly why
`expect` is filled in from a run, not from the record.

### ⚠ The command line rots separately from the anchors

The shell runner this replaces passed `--dep montint` alone. That was right
when written and is wrong now: `root.zig` imports `testkit` at file scope for
its fuzz corpus. Measured — it fails outright; with `--dep montint --dep
testkit` the same command is exit 0 at `40 passed; 1 skipped`. A dry run cannot
see this: every anchor still matched. `whois` shipped a migrated runner with
this defect and every row read RED, the control included, which is
indistinguishable from a suite that catches everything. `BROKEN` is therefore a
verdict here, distinct from `RED`.

## Does a second implementation agree, at real key sizes?

    scripts/capped zig build-exe --cache-dir .zig-cache \
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

## What was deliberately not brought over

The audit left 15 files in `.zig-cache/audit-paillier/` (94 MB). Three became
the instruments above; the rest were dropped, each for a stated reason:

- `probe_stack.zig` — spent in the strongest sense: its technique is now a test
  in the module (`root.zig`, *"decrypt: no secret full-value copy survives on
  the dead stack (paillier F2, ReleaseFast only)"*, painting the stack with
  `0x5A`).
- `ctgrind_probe.zig`, `ctrun.sh`, `_ct_gen.zig`, `classify.py`,
  `probe_timing.zig`, `probe_divtime.zig` — the module has
  `src/ctgrind_harness.zig` and **four pinned rows** in
  `scripts/ctgrind-expected.tsv` (`crt`, `noncrt`, `mul`, `addm`), inside a
  gate. `classify.py` belongs to this group, not to the hostile-input probes:
  it classifies memcheck contexts by innermost frame and by the last frame
  before `main`, and emits instruction pointers because memcheck cannot
  distinguish a `Jcc` from a `cmov`.
- `probe_random.zig` — its finding (F1: roughly 28.9% of draws folded onto
  `r - n` instead of being redrawn) is fixed and pinned by
  *"sampleNonzeroLtN draws land strictly below n, never n_sq (paillier F1)"*.
- `probe_hostile.zig` — a census that asserts nothing ("every row prints ACCEPT
  or the error name"), i.e. the cannot-fail shape. What it surveyed is covered
  by the module's own reject tests and by the mutation table above.
- `probe_perf.zig`, `build.sh`, `mutest.sh` — a benchmark and two wrappers the
  Python runner replaces.
