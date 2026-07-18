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
pairing, no NTT prime (the `2^32` modulus makes the ring arithmetic exact
wrapping `u32`), no external C.

This is a **scaffold commit**: the entire mechanical layer is real and tested;
the irreducible soundness core (external product / CMux / blind rotation /
bootstrap) is scaffolded behind a gate for a later Fable-tier pass. Toy/test
parameters only — **no security level is claimed**.

## What is real today (mechanical)

| Piece | File | What |
|---|---|---|
| Torus | `torus.zig` | `Z_{2^32}` encode/decode by a scale `Δ`, round-to-nearest modulus switch (`q → 2N`), gadget weights — exact integer rounding |
| Negacyclic ring | `poly.zig` | `Poly(N)` over `Z_{2^32}[X]/(X^N+1)` — add/sub/negate/scalar, **exact** `O(N²)` schoolbook `mul` (wrapping `u32`, no FFT), monomial rotation `X^e` |
| Gadget | `gadget.zig` | signed (balanced) base-`2^b` decomposition into `ℓ` digits + `recompose`, with an explicit `maxError` bound |
| Parameters | `params.zig` | `Params` + validation; the `toy` set and the failure-probability ledger |
| Scheme | `tfhe.zig` | `Tfhe(P)`: LWE/GLWE/GGSW keygen·encrypt·decrypt, bootstrap-key + key-switch-key gen, `sampleExtract`, `keySwitch`, `decomposeGlwe`, LUT builder, and `clearBootstrap` (the cleartext oracle) |

## The gated Fable core

`Tfhe(P)` exposes four functions behind `gate.fable_core_implemented` (currently
`false`; each `@panic("TODO(fable/core)")`):

- `externalProduct(ggsw, glwe)` — GGSW ⊠ GLWE (decompose + dot with the GGSW
  rows); the noise-growth heart.
- `cmux(ctrl, d0, d1)` — the encrypted selector `d0 + ctrl ⊠ (d1 − d0)`.
- `blindRotate(bsk, lut, b̃, ã)` — the accumulator loop of `n` CMux over the
  bootstrap key (the rotation exponents live here).
- `bootstrap(bsk, ksk, lut, ct)` — mod-switch → blind-rotate → sample-extract →
  key-switch → fresh LWE.

## Usage (once the core lands)

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

The mechanical surface is usable and tested standalone today (the ring, the
gadget, `sampleExtract`/`keySwitch`, and the `clearBootstrap` cleartext oracle).

## Verify

```
zig build test-tfhe --summary all                    # Debug
zig build test-tfhe -Doptimize=ReleaseFast --summary all
```

24 pass / 5 skip (Debug and ReleaseFast). The skips are the core-dependent
end-to-end anchors (programmable gate, 2-input AND, unlimited-depth chain,
corrupted-key control, noise budget) that light up when the gate flips. Real
today: the ring/gadget/torus tests, the LWE/GLWE round-trips, the sample-extract
and key-switch anchors, the cleartext LUT+rotation oracle over 64 random bits,
and three deliberately-broken positive controls (sign-dropped sample extraction,
dropped-level gadget decomposition, wrong-sign rotation exponent) proving the
harness has teeth before the core exists.

Provenance: clean-room from the TFHE (ePrint 2016/870) and FHEW (EUROCRYPT 2015)
papers; no third-party source ported and no implementation studied as a design
reference. **No external byte-exact KAT exists** for gate bootstrapping —
verified by property (homomorphic gate + unlimited-depth chain) + positive
controls + the cleartext oracle. See `SPEC.md`. No `NOTICE` entry required
(CONVENTIONS.md §5).
