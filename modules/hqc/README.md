# hqc

HQC (Hamming Quasi-Cyclic) — the code-based Key Encapsulation Mechanism
NIST selected in March 2025 as a structurally independent backup to
ML-KEM. `std.crypto` ships ML-KEM and ML-DSA, both lattice-based; HQC's
hardness assumption is unrelated (quasi-cyclic syndrome decoding, not
lattices), so it's a genuine gap this repo didn't previously cover.

**The arc is complete — this is a usable KEM.** `Hqc128`/`Hqc192`/
`Hqc256` (see "Usage" below) expose `keypair`/`encaps`/`decaps`,
byte-exact against the official NIST KAT. Part 2's codec (both ENCODE and
the two DECODE cores — RS Berlekamp-Massey + additive-FFT root-finding +
Forney, RM fast Hadamard transform, the genuinely hard part of the whole
arc) and Part 3's PKE/KEM composition (pure wiring over Parts 1-2, no new
algorithm) are both implemented and tested — see "What's here" below and
SPEC.md's "Part 2"/"Part 3" sections and "Arc plan".

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
- **`gf256`** — GF(2^8), the field the codec's Reed-Solomon layer is built
  over: `add`/`mul`/`square`/`inverse`, plus the reference's `exp`/`log`
  tables (independently re-derived and cross-checked, see SPEC.md).
- **`reedsolomon`** — the outer `[n1,k,delta]` Reed-Solomon code:
  `RS(params, generator).encode` (byte-exact-KAT'd) and `.decode`
  (constant-time Berlekamp-Massey + Gao-Mateer additive-FFT root-finding +
  Forney, an exact port of the v5.0.0 reference).
- **`reedmuller`** — the inner duplicated RM(1,7) code:
  `RM(params).encodeBlock`/`.encodeSymbol` (byte-exact-KAT'd) and
  `.decodeSymbol` (expand-and-sum + fast Hadamard transform + find_peaks
  maximum-likelihood decode, an exact port of the reference).
- **`code`** — the concatenation: `Code(params, generator).encode`
  (byte-exact-KAT'd end to end) and `.decode` (composes the two real
  decoders above).
- **`gate`** — `decoder_core_implemented` (now `true`): the switch that
  turns on the decode-correctness tests; kept as a single named toggle
  documenting that the decoder core is the Fable-hard part of the arc.
- **`pke`** — the HQC public-key encryption scheme: `Pke(params,
  generator).keygen`/`.encrypt`/`.decrypt`. Pure composition over
  `gf2x`/`prng`/`code` — no new algorithm (see pke.zig's module doc).
- **`kem`** — the Fujisaki-Okamoto implicit-rejection KEM transform over
  `pke`: `Kem(params, generator).keypair`/`.encaps`/`.decaps`. Same
  composition posture as `pke` (see kem.zig's module doc for the exact
  hash wiring and the constant-time implicit-rejection mask).
- **`Hqc128`/`Hqc192`/`Hqc256`** (in `root.zig`) — ready-made
  `Kem(params, generator)` instantiations for the three NIST parameter
  sets; the main entry point for using this module as a KEM.

## Usage

```zig
const hqc = @import("hqc");

var seed_kem: [32]u8 = undefined;
std.crypto.random.bytes(&seed_kem);
const kp = hqc.Hqc128.keypair(&seed_kem); // { ek, dk }

var coins: [hqc.Hqc128.coins_bytes]u8 = undefined; // m || salt
std.crypto.random.bytes(&coins);
const enc = hqc.Hqc128.encaps(kp.ek, &coins); // { ct, ss }

const ss = hqc.Hqc128.decaps(kp.dk, enc.ct);
// ss == enc.ss
```

Lower-level access (the ring/PRNG primitives Parts 1-2 build on) is still
available directly:

```zig
const P = hqc.params.hqc128;
const Ring = hqc.gf2x.Ring(P.n);

var xof = hqc.prng.Xof.init(some_32_byte_seed);
var h: Ring.Elem = Ring.zero;
hqc.prng.sampleVect(&xof, P.n, &h); // the public generator vector
```

`gf2x.Ring(n)` is a fresh type per `n` (comptime-parameterized), so
`Hqc128`/`Hqc192`/`Hqc256` each get their own `Elem`/key/ciphertext types
— sized exactly, no runtime allocation anywhere in this module.

## Verify

```
zig build test-hqc --summary all                        # Debug
zig build test-hqc --summary all -Doptimize=ReleaseFast  # ReleaseFast
```

67 tests, all passing (Debug + ReleaseFast): Part 1's parameter-table
cross-checks, `gf2x` algebraic identities, and `prng`'s `Xof`/`Prng`/
`hashI`/`hashG`/sampler chain reproduced byte-exact against the reference
implementation's own intermediate-value dump; Part 2's `gf256` field-axiom
+ self-derived-table tests, `reedsolomon`/`reedmuller`/`code` encode
reproduced byte-exact against the reference's own C source (compiled and
run locally — see `kat_vectors_code.zig`), plus decode-correctness tests
(zero-error round-trip, at-capacity δ-symbol-error correction, exhaustive
RM `decodeSymbol`) across all three parameter sets — including hqc-192/256's
PARAM_FFT=5 additive-FFT `radixBig` path; Part 3's `Kem`/`Pke` reproduced
byte-exact against the official NIST KAT (`kem_kat_test.zig`: pk/sk/ct/ss
for the first 3 `count`s × 3 parameter sets, plus decaps-agrees, random-
coins round-trip, and implicit-rejection tests). See SPEC.md's
Verification section for exactly which primitives are numeric-KAT-pinned
vs. transcribed-from-source-only.

Provenance: [NOTICE](NOTICE) (design reference); [SPEC.md](SPEC.md)
(spec version, KAT source, per-primitive verification tier, arc plan).
