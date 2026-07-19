# p256 — asm-accelerated pure-Zig NIST P-256

`p256` is a performance-specialized NIST P-256 — the fast alternative to
`std.crypto.ecc.P256`. std's curve is portable pure-Zig (a fiat-crypto
Montgomery field, no asm, no endomorphism), which leaves it several× slower than
OpenSSL's nistz256 (measured ~16× ECDSA sign / ~9× verify vs OpenSSL on the
audited host). That gap sits on the **P2 HTTPS-API hot path** (per-request JWT
ES256 verify, TLS), on **2FA/WebAuthn** (`ctap2pin`), on `spake2plus`, and on the
P-256 suites of `hpke`/`voprf`/`mls`/`jwe` — every one of them rides
`std.crypto.ecc.P256` today, and we cannot patch std. p256 keeps the collection's
**zero-C/no-libc** invariant (inline asm is still native Zig) while pulling in the
techniques std forgoes:

- the **P-256 special-prime (Solinas) reduction** for
  `p = 2^256 − 2^224 + 2^192 + 2^96 − 1` (`2^256 ≡ 2^224 − 2^192 − 2^96 + 1`,
  folded instead of a generic Montgomery reduce),
- **windowed + fixed-base-comb** constant-time scalar multiplies — P-256 has **no**
  efficiently-computable endomorphism, so (unlike k256/secp256k1) there is no GLV,
- an **amd64 `MULX/ADX`** field multiply/square.

Realistic target: **~2–3× OpenSSL nistz256** (the sibling `k256` secp256k1 arc hit
~2.5× libsecp256k1 with the same recipe). This is NOT a std-gap fill — std already
has P-256 — it is a *performance-specialized reimplementation* justified by the
measured gap plus the collection's thesis that native Zig should be usable
INSTEAD of linking a C crypto library. See `SPEC.md §Dedup`.

## Status: SCAFFOLD (portable oracle real; two Fable cores gated off)

The **portable path is real, constant-time, and byte-exact against
`std.crypto.ecc.P256` + the RFC 6979 ECDSA-P256 vectors + std's ECDSA signer** —
it is the correctness oracle. Two irreducible cores are gated off as `@panic`
stubs, the portable path standing in until a Fable agent fills them:

| Gate flag | Core | Portable fallback (the oracle it must match) |
|---|---|---|
| `gate.field_asm_implemented` | `fast_core.fieldMul` / `fast_core.fieldSq` — amd64 `MULX/ADX` field mul + square + P-256 Solinas fold | `field.mulPortable` / `field.sqPortable` (wide-int Solinas) |
| `gate.fast_scalarmul_implemented` | `group.combMulBaseFast` (fixed-base comb `k·G`) + `group.mulCtWindowed` (CT windowed variable-base) | `group.mulDoubleAddCt` / `basePoint.mulDoubleAddCt` |

## Usage

The API mirrors `std.crypto.ecc.P256` so consumers can be rewired with minimal
churn:

```zig
const p256 = @import("p256");

// Field arithmetic over p = 2^256 − 2^224 + 2^192 + 2^96 − 1.
const a = try p256.Fe.fromBytes(a_be, .big);
const b = try p256.Fe.fromBytes(b_be, .big);
const prod = a.mul(b);          // Solinas reduce (or gated MULX/ADX core)
const inv = a.invert();

// Curve group (a = −3).
const P = p256.P256.basePoint;
const Q = try P.mul(scalar_be, .big);       // constant-time (secret scalar)
const R = try Q.mulPublic(scalar_be, .big); // variable-time (public scalar)
const xy = R.affineCoordinates();

// ECDSA-P256/SHA-256 (the end-to-end anchor).
const sig = try p256.sign.ecdsaSign(secret_key, msg, nonce_k);
const ok  = p256.sign.ecdsaVerify(pubkey_sec1, msg, sig);
```

`p256.Scalar` (arithmetic mod the group order `n`) is re-exported from std on
purpose — the scalar field is a negligible slice of a signature's cost and has no
special form worth accelerating; p256 spends its complexity budget on the field
and the point multiply. See `SPEC.md §Scope`.

## Verify

```
zig build test-p256 --summary all                       # Debug
zig build test-p256 -Doptimize=ReleaseFast --summary all
P256_BENCH=1 zig build test-p256 -Doptimize=ReleaseFast # opt-in ns/op baseline
```

19 pass / 4 skip in both Debug and ReleaseFast (the skips are the 3 gated
core-vs-portable differentials — they light up when a core lands, a skip is NOT a
green light — plus the opt-in bench). The suite includes the field/group
differentials vs `std.crypto.ecc.P256` (thousands of random inputs, bit-exact via
`toBytes`), the reduction fold-boundary edge sweep, the RFC 6979 ECDSA-P256/SHA-256
vectors (verified by both p256 and std), an ECDSA differential against std's
signer (both directions: p256 verifies std's signatures, and std verifies
p256-produced ones), and a broken-Solinas-constant positive control the harness
flags RED.

Provenance: clean-room from the NIST P-256 domain parameters; OpenSSL's nistz256
studied as the technique reference (the P-256 Solinas reduction, `MULX/ADX`
field). Validated bit-exact vs `std.crypto.ecc.P256` + the RFC 6979 ECDSA-P256
vectors. Asm is amd64-only with a portable fallback everywhere. See the `NOTICE`
entry.
