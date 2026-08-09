# tfhe — TFHE/FHEW gate bootstrapping (unbounded-depth FHE)

**Bootstrapping** is what turns *leveled* FHE (the sibling `bfv`, which can add
and multiply only to a bounded depth) into *unbounded-depth* FHE. After every
gate, a **blind rotation** homomorphically re-decodes the encrypted message
through a programmable lookup table and emits a FRESH, low-noise ciphertext — so
noise is reset rather than accumulated and an arbitrarily deep circuit stays
correct. This module implements the TFHE/FHEW line (Chillotti–Gama–Georgieva–
Izabachène; Ducas–Micciancio): LWE/GLWE/GGSW ciphertexts over the power-of-two
torus `Z_{2^32}`, blind rotation by CMux over a GGSW bootstrap key, sample
extraction, and LWE key switching. It is self-contained and **std-only** — no
pairing, no floating point, no external C. The ring modulus stays `2^32`
(exact wrapping `u32`); an auxiliary 64-bit prime is used *inside* `ntt.zig`
purely to compute the same convolution faster, and its output is bit-identical
to the schoolbook one.

**The module is complete**: the entire mechanical layer is real and tested,
and the irreducible soundness core (external product / CMux / blind rotation /
bootstrap) — previously gated behind a flag for a later Fable-tier pass — is
now implemented for real (`gate.fable_core_implemented = true`, no `@panic`
remains). Toy/test parameters only — **no security level is claimed**.

## What is real today (mechanical)

| Piece | File | What |
|---|---|---|
| Torus | `torus.zig` | `Z_{2^32}` encode/decode by a scale `Δ`, round-to-nearest modulus switch (`q → 2N`), gadget weights — exact integer rounding |
| Negacyclic ring | `poly.zig` | `Poly(N)` over `Z_{2^32}[X]/(X^N+1)` — add/sub/negate/scalar, monomial rotation `X^e`, and `mul`: **exact** `O(N²)` schoolbook below `ntt_min_degree`, **exact** `O(N log N)` integer NTT above it (bit-identical, no FFT, no rounding budget) |
| Exact NTT | `ntt.zig` | negacyclic transform over the Goldilocks prime `2^64−2^32+1` with 16-bit operand splitting; 4 forward + 1 inverse transform per product. Measured vs schoolbook: 1.7× at `N=256`, 7.0× at `N=1024`, 12.1× at `N=2048`; a `toy` gate bootstrap goes 54.4 ms → 33.3 ms |
| Gadget | `gadget.zig` | signed (balanced) base-`2^b` decomposition into `ℓ` digits + `recompose`, with an explicit `maxError` bound |
| Parameters | `params.zig` | `Params` + validation; the `toy` set and the failure-probability ledger |
| Scheme | `tfhe.zig` | `Tfhe(P)`: LWE/GLWE/GGSW keygen·encrypt·decrypt, bootstrap-key + key-switch-key gen, `sampleExtract`, `keySwitch`, `decomposeGlwe`, LUT builder, and `clearBootstrap` (the cleartext oracle) |

## The Fable core (now implemented)

`Tfhe(P)` exposes four functions behind `gate.fable_core_implemented` (now
`true`; no `@panic` remains):

- `externalProduct(ggsw, glwe)` — GGSW ⊠ GLWE (decompose + dot with the GGSW
  rows); the noise-growth heart.
- `cmux(ctrl, d0, d1)` — the encrypted selector `d0 + ctrl ⊠ (d1 − d0)`.
- `blindRotate(bsk, lut, b̃, ã)` — the accumulator loop of `n` CMux over the
  bootstrap key (the rotation exponents live here).
- `bootstrap(bsk, ksk, lut, ct)` — mod-switch → blind-rotate → sample-extract →
  key-switch → fresh LWE.

## Usage

```zig
const tfhe = @import("tfhe");
const T = tfhe.Tfhe(tfhe.params.toy);
const inst = try T.init();

const sk   = T.lweKeyGen(64, rand);
const gk   = T.glweKeyGen(rand);
const bsk  = T.bootstrapKeyGen(&sk, &gk, rand);
const ksk  = T.keySwitchKeyGen(&gk, &sk, rand);

const lut  = T.testPolynomial(2, .{ T.encodeBit(0), T.encodeBit(1) }); // identity
const ct   = T.lweEncrypt(64, &sk, T.encodeBit(1), rand);
const fresh = T.bootstrap(&bsk, &ksk, &lut, &ct);   // Dec == 1, noise reset
```

Every piece above — the mechanical surface (ring, gadget, `sampleExtract`/
`keySwitch`, `clearBootstrap`) AND `bootstrap` itself — is real and tested
today; the snippet runs end to end.

## Verify

```
zig build test-tfhe --summary all                    # Debug
zig build test-tfhe -Doptimize=ReleaseFast --summary all
```

All pass, no skips (Debug and ReleaseFast). This includes the core-dependent
end-to-end anchors — the programmable gate (`bootstrap(identity)`/
`bootstrap(NOT)`), a 2-input homomorphic AND, an unlimited-depth bootstrap
chain, a corrupted-bootstrap-key control, and the output noise-budget
assertion — plus the ring/gadget/torus tests, the LWE/GLWE round-trips, the
sample-extract and key-switch anchors, the cleartext LUT+rotation oracle over
64 random bits, and three deliberately-broken positive controls (sign-dropped
sample extraction, dropped-level gadget decomposition, wrong-sign rotation
exponent) that prove the harness has teeth independent of the core.

Provenance: clean-room from the TFHE (ePrint 2016/870) and FHEW (EUROCRYPT 2015)
papers; no third-party source ported and no implementation studied as a design
reference. **No external byte-exact KAT exists** for gate bootstrapping —
verified by property (homomorphic gate + unlimited-depth chain) + positive
controls + the cleartext oracle. See `SPEC.md`. No `NOTICE` entry required
(CONVENTIONS.md §5).
