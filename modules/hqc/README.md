# hqc

HQC (Hamming Quasi-Cyclic) — the code-based Key Encapsulation Mechanism
NIST selected in March 2025 as a structurally independent backup to
ML-KEM. `std.crypto` ships ML-KEM and ML-DSA, both lattice-based; HQC's
hardness assumption is unrelated (quasi-cyclic syndrome decoding, not
lattices), so it's a genuine gap this repo didn't previously cover.

**This is Part 1 of a multi-part arc: the ring/PRNG foundation, not yet a
usable KEM.** There is no `keygen`/`encapsulate`/`decapsulate` here — see
"Arc plan" in SPEC.md for what Parts 2 and 3 add and why the decoder
(Part 2) is the hard part, not this module.

## What's here

- **`params`** — the three NIST parameter sets (`hqc128`, `hqc192`,
  `hqc256`) as comptime structs: ring size, code lengths, sample weights,
  byte sizes, and the SHAKE domain separators. Every field is transcribed
  from and cross-checked against the official spec's tables — see
  params.zig's module doc and SPEC.md for the exact citation.
- **`gf2x`** — the ambient ring R = F2[X]/(X^n − 1): `Ring(n)` builds a
  bit-packed vector type (`Elem`) with `add` (XOR), `mul` (cyclic
  convolution), `weight` (Hamming weight), `fromBytes`/`toBytes` (the
  spec's LSB-first byte packing), and `truncate`.
- **`prng`** — the two SHAKE256 instantiations HQC uses: `Prng` (HQC's
  internal PRNG, and — per the reference implementation — also exactly
  what the official NIST KAT harness's `randombytes()` is in this HQC
  release, no AES-DRBG needed) and `Xof` (used for every ring vector's
  randomness, with a load-bearing byte-consumption quirk documented on
  `Xof.getBytes`). Plus the I/G/H/J hash oracles and both fixed-weight
  vector samplers (`sampleFixedWeightRejection` — unbiased, keygen's x/y;
  `sampleFixedWeightBiased` — encryption's r1/r2/e).

## Usage

```zig
const hqc = @import("hqc");

const P = hqc.params.hqc128;
const Ring = hqc.gf2x.Ring(P.n);

var xof = hqc.prng.Xof.init(some_32_byte_seed);
var h: Ring.Elem = Ring.zero;
hqc.prng.sampleVect(&xof, P.n, &h); // the public generator vector
```

`gf2x.Ring(n)` is a fresh type per `n` (comptime-parameterized), so
`hqc128`/`hqc192`/`hqc256` each get their own `Elem` type — sized exactly,
no runtime allocation anywhere in this module.

## Verify

```
zig build test-hqc --summary all                        # Debug
zig build test-hqc --summary all -Doptimize=ReleaseFast  # ReleaseFast
```

28 tests: parameter-table cross-checks against the spec's Table 5/6,
`gf2x` algebraic identities (commutativity, distributivity, identity
element, hand-verified monomial wraparound), and — the load-bearing
ones — `prng`'s `Xof`/`Prng`/`hashI`/`hashG`/sampler chain reproduced
byte-exact against the reference implementation's own intermediate-value
dump. See SPEC.md's Verification section for exactly which primitives are
numeric-KAT-pinned vs. transcribed-from-source-only.

Provenance: [NOTICE](NOTICE) (design reference); [SPEC.md](SPEC.md)
(spec version, KAT source, per-primitive verification tier, arc plan for
Parts 2–3).
