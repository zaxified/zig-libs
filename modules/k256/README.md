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

## Status: core phase done (both Fable cores implemented and gated ON)

The **portable path is real, constant-time, and byte-exact against
`std.crypto.ecc.Secp256k1` + the 19 official BIP340 vectors** — it is the
correctness oracle and the non-amd64 fallback. The two irreducible cores below
are now IMPLEMENTED, with `gate.field_asm_implemented` /
`gate.glv_scalarmul_implemented` both flipped to `true`, so the
core-vs-portable differentials in `oracle_test.zig` run live (not skipped):

| Gate flag | Core | Portable fallback (the oracle it's pinned against) |
|---|---|---|
| `gate.field_asm_implemented` | `fast_core.fieldMul` / `fast_core.fieldSq` — amd64 `MULX/ADX` field mul + square | `field.mulPortable` / `field.sqPortable` (wide-int Solinas) |
| `gate.glv_scalarmul_implemented` | `group.mulPublicGlv` — GLV+wNAF variable-base scalarmul | `group.mulPublicDoubleAdd` |

The GLV **decomposition** (`scalar.splitScalar`, the lattice constants) is
real and tested byte-exact vs std, and both gated cores now build on it for
real — see `gate.zig` for the exact cut-lines and `SPEC.md`'s Performance
status section for measured numbers.

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
const ok2 = k256.sign.ecdsaVerify(pubkey_sec1, msg, sig_rs);      // malleable, like std
const ok3 = k256.sign.ecdsaVerifyLowS(pubkey_sec1, msg, sig_rs);  // rejects the high-S twin

// Recoverable ECDSA (RFC 6979 deterministic sign + public-key recovery —
// e.g. Lightning BOLT#11's invoice signature).
const rsig = try k256.ecdsa_recover.sign(privkey, hash32);
const q = try k256.ecdsa_recover.recoverPubkey(hash32, rsig.r, rsig.s, rsig.recid);
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

Green in both Debug and ReleaseFast (the one skip is the opt-in
`K256_BENCH` micro-benchmark, gated behind an env var, not a core gap — both
Fable cores are implemented and their differentials run for real). The suite
includes the field/group/scalar differentials vs `std.crypto.ecc.Secp256k1`
(thousands of random inputs, bit-exact via `toBytes`), the core-vs-portable
differentials for the amd64 `MULX/ADX` field core and the GLV scalarmul core,
the GLV decomposition + β-endomorphism checks, the 19 official BIP340 vectors
(8 sign rows byte-exact, all 19 verify rows), an ECDSA differential against std's
signer, a malleability test that builds the `(r, n − s)` twin of every std
signature and pins that `ecdsaVerify` takes both while `ecdsaVerifyLowS` takes
exactly one, a broken-Solinas-constant positive control the harness flags RED, and
`ecdsa_recover`'s own sign/recover round-trip + tampered-signature tests
(originally `lninvoice`'s, moved here — general secp256k1 machinery, not
BOLT#11-specific).

Measured on this host (ReleaseFast, accelerated MULX/ADX + GLV + comb-base
path vs std): ECDSA/BIP340 verify **~2–3.5× libsecp256k1** (field mul ~2.9×,
ECDSA verify ~2.5× libsecp / ~6.5× std), BIP340/ECDSA sign **~2.3×
libsecp256k1** via the fixed-base comb table (`group.combMulBase`) — both
signature paths land inside the module's ~2–4×-libsecp256k1 target. See
`SPEC.md`'s Performance status section for the full breakdown.

Provenance: clean-room from the secp256k1 domain parameters + the public
BIP340 specification. Design reference: bitcoin-core/libsecp256k1 (**MIT**,
Copyright (c) 2013 Pieter Wuille et al.) — studied for the technique shape only:
the special-prime (Solinas) field reduction for p = 2^256 − 2^32 − 977 (fold the
high half by 2^32+977), the GLV endomorphism decomposition, and the amd64
`MULX/ADX` field multiply the gated core mirrors. No source ported. The
secp256k1 domain parameters (p, n, G, the curve constant b, and the GLV λ/β +
lattice basis) are public curve facts; the specific integer constants match
`std.crypto.ecc.Secp256k1` (Zig std, MIT), which is ALSO used as the byte-exact
correctness oracle (differential tests), not as a design reference. The
`kat_vectors.zig` transcription of the official `bip-0340/test-vectors.csv` is a
public BIP spec artifact used as a test oracle, not copied from any
implementation's test suite. Asm is amd64-only with a portable fallback
everywhere.