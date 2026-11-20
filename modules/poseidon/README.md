# poseidon

**The ZK-friendly hash.** A permutation built from field additions,
multiplications and one `x^5` S-box, so that hashing *inside* an arithmetic
circuit costs a few hundred constraints instead of the tens of thousands
SHA-256 costs. SHA-256 is cheap on bits; circuits are not made of bits.

This repo already had [`groth16`](../groth16/README.md),
[`bn254`](../bn254/README.md) and [`bulletproofs`](../bulletproofs/README.md) —
a proof system with nothing cheap to hash with. Poseidon is what the Merkle
trees, commitments and Fiat-Shamir transcripts inside real circuits are
actually made of.

**Status: COMPLETE.** Permutation, fixed-arity hash, 2-to-1 compression, and
the Grain-LFSR parameter generator — including the MDS subspace-trail security
checks and the rejection loop around them, so the generator can be aimed at a
parameter set nobody has published constants for.

**Model-after:** `iden3/circomlib` + `iden3/circomlibjs` (what deployed circom
circuits use), and the Poseidon authors' own `hadeshash` sage reference.

Provenance: ⚠ **this module carries required attribution.** The parameter
generator and the MDS acceptance checks **port** the Poseidon authors'
`hadeshash` reference (MIT), whose copyright notice must be preserved in any
copy — the terms are in this module's own [`NOTICE`](NOTICE), beside the code
that owes them. The permutation and its parameter generation otherwise follow
eprint 2019/458 (Grassi-Khovratovich-Rechberger-Roy-Schofnegger) and the
subspace-trail analysis of eprint 2020/500 (Grassi-Rechberger-Schofnegger), and
the GF(p) linear algebra (`linalg.zig`) is the authors' own.
`iden3/circomlibjs` (**GPL-3.0**) and `iden3/circomlib` (**LGPL-3.0**) are a
design/comparison reference for the deployed constants, used ONLY by being
*run* or *digested*: `vectors_test.zig`'s circomlibjs known answers are
produced by executing the library (`tools/gen_vectors.mjs`), never read out of
its sources, and `constants_test.zig` pins SHA-256 digests of tables this
module derives itself. No circomlib or circomlibjs source or data is present,
so their copyleft terms do not reach this repository, and neither reference
imposes a condition beyond MIT's own.

## Read this first

> **The permutation is the easy part.** Twenty lines. Every implementation
> that gets Poseidon wrong gets it wrong upstream of that — in the round
> constants, the MDS matrix, the full/partial round split, or which state
> element the partial round's S-box touches. Each of those mistakes produces a
> perfectly deterministic hash that round-trips fine and is simply not
> Poseidon. That is why this module derives its parameters from the authors'
> published generator rather than remembering them, and why every claim here
> is pinned to a byte-exact external vector.

> **Build the instance once.** `Perm(t).init()` runs the parameter generator,
> including the MDS security checks. That is ~2 ms at `t = 3` and ~70 ms at
> `t = 17` in an optimized build (10x that unoptimized), and the result is
> immutable — hold one per width for the life of the program. Do not call it
> per hash.

## Import

```zig
const poseidon = @import("poseidon");
```

## API

```zig
// The 2-to-1 Merkle node function — circomlib's Poseidon(2).
const p = poseidon.bn254.Perm(3).init();
const node = p.compress(left, right);

// General fixed arity: Perm(t) hashes t-1 inputs. t = 2..17 on BN254.
const p5 = poseidon.bn254.Perm(5).init();
const h  = p5.hash(.{ a, b, c, d });

// circomlib's PoseidonEx: explicit initial state (the capacity slot) and up
// to t outputs. This is what a transcript or duplex construction wants.
const out = p5.hashN(3, initial_state, .{ a, b, c, d });   // [3]Fr

// The bare permutation — the thing the published vectors pin.
const s = p.permute(.{ c0, c1, c2 });

// Field elements come from the sibling curve modules; `fromU64` is a
// convenience for indices, domain tags and tests.
const one = poseidon.bn254.fromU64(1);
```

BLS12-381 is the same shape, narrower:

```zig
const q = poseidon.bls12_381.Perm(3).init();   // t = 3 or t = 5 only
const s = q.permute(.{ x, y, z });             // externally anchored
```

## Fields and widths

| field | widths | `R_F` / `R_P` | parameters from |
|---|---|---|---|
| BN254 `Fr` (`bn254.Fr`) | `t = 2..17`, i.e. 1..16 inputs | 8 / `N_ROUNDS_P[t-2]` | circomlib — what deployed circuits use |
| BLS12-381 `Fr` (`bls12_381.Fr`) | `t = 3`, `t = 5` | 8 / 57, 8 / 60 | the authors' `poseidonperm_x5_255_{3,5}` |

No new field arithmetic is defined anywhere in this module; both `Fr` types
come from the sibling curve modules unchanged.

⚠ On BLS12-381 only the **permutation** has an external anchor. The
`hash`/`compress` framing on that field is this module's own and does not
match Filecoin's `neptune` or dusk, which use domain tags. See `SPEC.md`.

## Anchoring

Grade 1 — published vectors and reference-implementation output, byte-exact —
throughout. Two upstream sources, each with its retrieval command recorded
in the test files rather than summarised:

* `hadeshash/code/test_vectors.txt` — the Poseidon authors' permutation KATs,
  all four GF(p) instances, every output word;
* circomlibjs **executed** — `tools/gen_vectors.mjs`, which runs the optimized
  and the reference JS implementations and requires them to agree. It covers
  the input sets upstream's own suite exercises (non-zero initial state,
  multi-output) *and* a `t = 2..17` sweep, so every published width and every
  `N_ROUNDS_P` entry is included. Nothing is transcribed from circomlibjs'
  test file: it is GPL-3.0, and this repository runs it rather than reading
  it (see [`NOTICE`](NOTICE)).

The round constants and MDS matrices are separately pinned by SHA-256 against
`circomlibjs/src/poseidon_constants.json` (all 16 BN254 widths) and the
authors' sage files (both BLS12-381 widths), plus literal spot values an
auditor can read off upstream by eye.

The MDS security checks are cross-checked against an independent sympy port of the
same sage source, a grade-2 oracle (a second transcription by the same author, not
external validation); `SPEC.md` §"Anchoring" is explicit about what it can and
cannot prove. The module is standalone Zig, so the comparison is split in two: the
transcript of the sympy peer's verdicts for 182 matrices is committed
(`src/testdata/mds_subspace_trail.txt`) and replayed by `src/mds_replay_test.zig`
with **no `python3` anywhere**, so it asserts on every host; the live peer is a
pre-release check:

```sh
zig build interop-poseidon                # re-run the sympy peer, diff, no rewrite
zig build interop-poseidon -- --capture   # re-take the transcript (tools/interop.zig drives tools/subspace_trail.py)
```

## Tests

```sh
zig build test-poseidon                             # slow in Debug (see below)
zig build test-poseidon -Doptimize=ReleaseFast      # a few seconds
```

The fuzz harnesses (injectivity of the permutation) are run by the repo's
deterministic fuzz driver (`POSEIDON_FUZZ`), as every module's are; `SPEC.md`
§"Verification" lists the test classes. The tests are green in Debug, ReleaseSafe
and ReleaseFast.

The Debug lane is slow because `std.crypto.ff`'s constant-time multiply costs
9.6 µs unoptimized against 0.8 µs optimized, and the MDS security checks are
~70 000 multiplications at `t = 17`. `SPEC.md` records why marking the module
`heavy` was measured and makes it *worse*.

## Not provided

Variable-length (sponge) hashing and circuit / constraint-system integration are
refused; Poseidon2 and a neptune-compatible BLS12-381 framing are not built (open
items). Rescue-Prime is the sibling module [`rescue`](../rescue/README.md).
`SPEC.md` gives the reasoning (*What is deliberately not done*, *Backlog /
deferred*).

Constant-time behaviour, and where it does and does not apply: `SPEC.md`
§"Constant time". Short version — the permutation is constant time with
respect to its inputs; `init()`'s parameter derivation is not, and consumes
only public values.
