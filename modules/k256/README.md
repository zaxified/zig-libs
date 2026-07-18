# k256 — asm-accelerated pure-Zig secp256k1

`k256` is a performance-specialized secp256k1 — the fast alternative to
`std.crypto.ecc.Secp256k1`. std's curve is portable pure-Zig (a fiat-crypto
Montgomery field, no asm), which leaves it ~9–14× slower than libsecp256k1
(hand-written asm + the GLV endomorphism + wNAF). Every Bitcoin/Lightning module
in this repo (`bip340`, `taproot`, `musig2`, `adaptor`, `frost`, `sphinx`,
`bolt3`, `bolt8`) rides std's curve today. k256 keeps the collection's
**zero-C/no-libc** invariant (inline asm is still native Zig) while pulling in the
three techniques std forgoes:

- the **special-prime (Solinas) reduction** for `p = 2^256 − 2^32 − 977`
  (`2^256 ≡ 2^32 + 977`, folded instead of a generic Montgomery reduce),
- the **GLV endomorphism** (`k = k1 + k2·λ`, both ≈ √n) for ~40% fewer doublings
  on variable-base multiplies,
- an **amd64 `MULX/ADX`** field multiply/square.

Realistic target: **~2–4× libsecp256k1** (parity with decades-tuned asm-grade C
is not expected; ~9–14× → ~2–4× is the win). This is NOT a std-gap fill — std
already has secp256k1 — it is a *performance-specialized reimplementation*
justified by the measured gap plus the collection's thesis that native Zig should
be usable INSTEAD of linking a C crypto library. See `SPEC.md §Dedup`.

## Status: SCAFFOLD (portable oracle real; two Fable cores gated)

The **portable path is real, constant-time, and byte-exact against
`std.crypto.ecc.Secp256k1` + the 19 official BIP340 vectors** — it is the
correctness oracle. Two irreducible cores are gated off, the portable path
standing in until a Fable agent fills them:

| Gate flag | Core | Portable fallback (the oracle it must match) |
|---|---|---|
| `gate.field_asm_implemented` | `fast_core.fieldMul` / `fast_core.fieldSq` — amd64 `MULX/ADX` field mul + square | `field.mulPortable` / `field.sqPortable` (wide-int Solinas) |
| `gate.glv_scalarmul_implemented` | `group.mulPublicGlv` — GLV+wNAF variable-base scalarmul | `group.mulPublicDoubleAdd` |

The GLV **decomposition** (`scalar.splitScalar`, the lattice constants) is already
real and tested byte-exact vs std, so the gated scalarmul core has a proven
reference to build on.

## Usage

The API mirrors `std.crypto.ecc.Secp256k1` so consumers can be rewired with
minimal churn:

```zig
const k256 = @import("k256");

// Field arithmetic over p = 2^256 − 2^32 − 977.
const a = try k256.Fe.fromBytes(a_be, .big);
const b = try k256.Fe.fromBytes(b_be, .big);
const prod = a.mul(b);          // Solinas reduce (or gated MULX/ADX core)
const inv = a.invert();

// Curve group.
const P = k256.Secp256k1.basePoint;
const Q = try P.mul(scalar_be, .big);       // constant-time (secret scalar)
const R = try Q.mulPublic(scalar_be, .big); // variable-time (public scalar)
const xy = R.affineCoordinates();

// Signatures (the end-to-end anchor).
const sig = try k256.sign.bip340Sign(secret_key, msg, aux_rand);
const ok  = k256.sign.bip340Verify(pubkey_xonly, msg, sig);
const ok2 = k256.sign.ecdsaVerify(pubkey_sec1, msg, sig_rs);
```

`k256.Scalar` (arithmetic mod the group order `n`) is re-exported from std on
purpose — the scalar field is a negligible slice of a signature's cost and has no
special form worth accelerating; k256 spends its complexity budget on the field
and the point multiply. See `SPEC.md §Scope`.

## Verify

```
zig build test-k256 --summary all                       # Debug
zig build test-k256 -Doptimize=ReleaseFast --summary all
K256_BENCH=1 zig build test-k256 -Doptimize=ReleaseFast # opt-in ns/op baseline
```

18 pass / 2 skip in both Debug and ReleaseFast (the 2 skips are the gated
core-vs-portable differentials, which light up when a core lands — a skip is not
a green light). The suite includes the field/group/scalar differentials vs
`std.crypto.ecc.Secp256k1` (thousands of random inputs, bit-exact via `toBytes`),
the GLV decomposition + β-endomorphism checks, the 19 official BIP340 vectors
(8 sign rows byte-exact, all 19 verify rows), an ECDSA differential against std's
signer, and a broken-Solinas-constant positive control the harness flags RED.

Measured on this host (ReleaseFast, portable path — the SCAFFOLD baseline, not
the accelerated target): field mul **25 ns/op** vs std 59, field sq **47** vs 100,
constant-time base-point scalarmul **192 µs** vs std 219, ECDSA verify **238 µs**
vs std 815. The gated `MULX/ADX` field core + GLV push toward the
~2–4×-libsecp256k1 target; the owner-verify + Fable phases produce the real
accelerated numbers.

Provenance: clean-room from the secp256k1 domain parameters + BIP340 public spec;
libsecp256k1 studied as the technique reference (special-prime reduction, GLV,
`MULX/ADX` field). Validated bit-exact vs `std.crypto.ecc.Secp256k1` + the
official BIP340 vectors. Asm is amd64-only with a portable fallback everywhere.
See the `NOTICE` entry.
