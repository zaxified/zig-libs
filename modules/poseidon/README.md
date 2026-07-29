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

**Status: COMPLETE for the shipped parameter sets.** Permutation, fixed-arity
hash, 2-to-1 compression, and the Grain-LFSR parameter generator, over two
fields.

**Model-after:** `iden3/circomlib` + `iden3/circomlibjs` (what deployed circom
circuits use), and the Poseidon authors' own `hadeshash` sage reference.

## Read this first

> **The permutation is the easy part.** Twenty lines. Every implementation
> that gets Poseidon wrong gets it wrong upstream of that — in the round
> constants, the MDS matrix, the full/partial round split, or which state
> element the partial round's S-box touches. Each of those mistakes produces a
> perfectly deterministic hash that round-trips fine and is simply not
> Poseidon. That is why this module derives its parameters from the authors'
> published generator rather than remembering them, and why every claim here
> is pinned to a byte-exact external vector.

> **Build the instance once.** `Perm(t).init()` runs the parameter generator.
> It is fast (microseconds) but not free, and the result is immutable — hold
> one per width for the life of the program.

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
throughout. Three upstream sources, each with its retrieval command recorded
in the test files rather than summarised:

* `hadeshash/code/test_vectors.txt` — the Poseidon authors' permutation KATs,
  all four GF(p) instances, every output word;
* `circomlibjs/test/poseidon.js` — the deployed reference implementation's own
  known answers, including non-zero initial state and multi-output;
* circomlibjs **executed** — a `t = 2..17` sweep with the optimized and the
  reference JS implementations required to agree, so every published width and
  every `N_ROUNDS_P` entry is covered.

The round constants and MDS matrices are separately pinned by SHA-256 against
`circomlibjs/src/poseidon_constants.json` (all 16 BN254 widths) and the
authors' sage files (both BLS12-381 widths), plus literal spot values an
auditor can read off upstream by eye.

### Mutation — evidence the tests bite

Four deliberate breakages, each reverted, each verified restored by file
checksum (the module is untracked, so `git diff` had nothing to compare):

| mutation | result |
|---|---|
| partial-round S-box on `state[t-1]` instead of `state[0]` | **caught** — 10 vector tests fail; all constant pins and structural tests still pass |
| S-box applied to all elements in partial rounds (no partial/full distinction) | **caught** — the same 10 vector tests fail |
| round split shifted (`R_F/2 + 1` leading full rounds, one fewer partial round, identical total round count and identical constant consumption) | **caught** — the same 10 vector tests fail |
| MDS seed draws rejection-sampled instead of reduced (`grain.zig`) | **caught** — 8 vector tests + 3 constant pins fail; the failure message names the layer (`MDS digest mismatch at t=2`) while the round-constant digests stay green |

Two things worth recording from that last one. First, the constant pins do
what they are for: they separate "the generator drifted" from "the
permutation is wrong". Second, `poseidonperm_x5_254_5` and
`poseidonperm_x5_255_5` **survived** it — at `t = 5` no MDS draw happened to
land above `p`, so the matrix was unchanged. The `t = 2..17` sweep is what
caught it there, which is the concrete reason that sweep exists rather than
just the three widths upstream's own suite exercises.

## Tests

```sh
zig build test-poseidon                             # 30 tests, ~5 s in Debug
zig build test-poseidon -Doptimize=ReleaseFast      # ~0.45 s
zig build test-poseidon --fuzz --release=safe       # injectivity harnesses
```

`--release=safe` is not optional for `--fuzz`. Green in Debug, ReleaseSafe and
ReleaseFast.

## Not here

Variable-length (sponge) hashing, Poseidon2, Rescue/Rescue-Prime, and circuit
/ constraint-system integration. `SPEC.md` gives the reasoning for each and
names Rescue-Prime as the obvious follow-up module.

Constant-time behaviour, and where it does and does not apply: `SPEC.md`
§"Constant time". Short version — the permutation is constant time with
respect to its inputs; `init()`'s parameter derivation is not, and consumes
only public values.
