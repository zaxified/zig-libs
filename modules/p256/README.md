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

- a **Montgomery-domain field** for `p = 2^256 − 2^224 + 2^192 + 2^96 − 1` whose REDC
  exploits the prime's shape (`−p⁻¹ ≡ 1 (mod 2^64)`: each round's quotient digit is the
  low limb); the NIST special-prime (Solinas) reduction
  (`2^256 ≡ 2^224 − 2^192 − 2^96 + 1`) is kept as an independent portable oracle,
- **windowed + fixed-base-comb** constant-time scalar multiplies — P-256 has **no**
  efficiently-computable endomorphism, so (unlike k256/secp256k1) there is no GLV,
- an **amd64 `MULX/ADX`** field multiply/square.

The original target was **~2–3× OpenSSL nistz256** (the sibling `k256` secp256k1 arc hit
~2.5× libsecp256k1 with the same recipe); the module now measures at or near OpenSSL
(the card's **Performance:** line in `SPEC.md`). This is NOT a std-gap fill — std already
has P-256 — it is a *performance-specialized reimplementation* justified by the
measured gap plus the collection's thesis that native Zig should be usable
INSTEAD of linking a C crypto library. See `SPEC.md §Dedup`.

## Performance

`zig build bench-p256` measures sign, verify, ECDH and key generation against OpenSSL's nistz256; the card's
**Performance:** line in `SPEC.md` holds the current ratios, and `SPEC.md` § Performance describes the method. Against
`std.crypto.sign.ecdsa.EcdsaP256Sha256` this module is about 10× faster on sign and about 3× on verify (one host).
`P256.mul` recognises the base point and redirects to the fixed-base comb, because std's signer computes `R` as
`basePoint.mul(k)`, so std's generic `Ecdsa` over this group takes the fast path too.

## Cores and gates

The **portable path is real, constant-time, and byte-exact against
`std.crypto.ecc.P256` + the RFC 6979 ECDSA-P256 vectors + std's ECDSA signer** —
it is the correctness oracle and the non-amd64 fallback. Both irreducible cores
are implemented and every gate flag is `true`, so the core-vs-portable
differentials run for real (bit-exact vs the oracle + std); flipping a flag back
to `false` restores the proven portable fallback:

| Gate flag | Core (implemented) | Portable fallback (the oracle it matches bit-for-bit) |
|---|---|---|
| `gate.field_asm_implemented` | `fast_core.montMul` / `montSq` (`montMulRegs` / `montSqRegs`) — amd64 `MULX/ADX` product + Montgomery REDC; `fast_core.fieldMul` / `fieldSq` (signed NIST word-shuffle Solinas reduction, HMV Alg. 2.29) are kept as a differential oracle | `field.montMulPortable` (portable REDC; `field.mulPortable` / `sqPortable` are the wide-int Solinas oracle) |
| `gate.fast_scalarmul_implemented` | `group.combMulBaseFast` (fixed-base comb `k·G` over a comptime affine table, w = 6) + `group.mulCtWindowed` (CT windowed variable-base) — `blackBox`-guarded masked CT gather | `group.mulDoubleAddCt` / `basePoint.mulDoubleAddCt` |
| `gate.fast_invert_implemented` | `modinv.invert` — constant-time Bernstein–Yang safegcd (62-bit batches), shared by `Fe.invert` and `Scalar.invert` | `Fe.invertFermat` (`a^(p−2)`) / std's fiat scalar inverse |

The PUBLIC verify path (`mulPublic` / `mulDoubleBasePublic`) additionally runs in
Jacobian coordinates (vartime, public inputs only): `u1·G` from the same
fixed-base table with no doublings, `u2·Q` by wNAF over a batch-normalised
affine table — byte-exact vs the plain ladder + std at the point level.

## Usage

The API mirrors `std.crypto.ecc.P256` so consumers can be rewired with minimal
churn:

```zig
const p256 = @import("p256");

// Field arithmetic over p = 2^256 − 2^224 + 2^192 + 2^96 − 1.
const a = try p256.Fe.fromBytes(a_be, .big);
const b = try p256.Fe.fromBytes(b_be, .big);
const prod = a.mul(b);          // Montgomery multiply (MULX/ADX core where present, portable REDC elsewhere)
const inv = a.invert();

// Curve group (a = −3).
const P = p256.P256.basePoint;
const Q = try P.mul(scalar_be, .big);       // constant-time (secret scalar)
const R = try Q.mulPublic(scalar_be, .big); // variable-time wNAF (public scalar)
const xy = R.affineCoordinates();

// ECDSA-P256/SHA-256 (the end-to-end anchor).
const sig = try p256.sign.ecdsaSign(&secret_key, msg, &nonce_k);
// Or let RFC 6979 derive the nonce (no RNG, reproducible, KAT'd byte-exact):
const dsig = try p256.sign.ecdsaSignDeterministic(&secret_key, msg);
const ok  = p256.sign.ecdsaVerify(pubkey_sec1, msg, sig);

// ECDSA over any hash: `Ecdsa(Hash)` has `EcdsaP256Sha256`'s surface
// (`EcdsaP256Sha256 = Ecdsa(Sha256)`); a digest over 32 bytes is cut to its
// leftmost 256 bits. Signatures are byte-identical to std's `Ecdsa(P256, Hash)`.
const Es384 = p256.Ecdsa(std.crypto.hash.sha2.Sha384);
const kp = try Es384.KeyPair.generateDeterministic(seed);
const s384 = try kp.sign(msg, null);
try s384.verify(msg, kp.public_key);

// ECDH: x of secret · peer, 32 bytes big-endian. The peer is a compressed or
// uncompressed SEC1 point, validated (canonical, on the curve, not the identity);
// the secret must be in [1, n − 1]. `ecdhInto` takes the secret by pointer and
// leaves no residue on the dead stack.
const shared = try p256.ecdh(secret_be, peer_sec1);
var out: [32]u8 = undefined;
try p256.ecdhInto(&out, &secret_be, peer_sec1);

// X.509/OCSP/CMS carry the signature as DER; JWS/COSE/XML-DSig use raw r||s.
const raw = p256.sign.derToRaw(sig_der) orelse return error.BadSignature;
var der_buf: [p256.sign.der_max_len]u8 = undefined;
const der = p256.sign.rawToDer(raw, &der_buf);
```

`p256.Scalar` (arithmetic mod the group order `n`) is a thin wrapper over std's
fiat scalar field with the same public surface, except `invert`, which is this
module's safegcd (`modinv.zig`) — the rest of the scalar field is a negligible
slice of a signature's cost and has no special form worth accelerating; p256
spends its complexity budget on the field, the inverses and the point multiply. See `SPEC.md §Scope`.

## Stack use

No allocation, no globals; the cost is stack. Every secret-scalar entry point
(`P256.mul`, `ecdh`/`ecdhInto`, the ECDSA signers, key generation) runs its body
one frame down and then zeroes the stack it dirtied (`burn.zig`: `mul_burn` 16 KiB,
`affine_burn` 4 KiB, `sign_burn` 8 KiB), so the burn counts toward the need.
Measured depth of the deepest call (bytes dirtied below the caller,
burn included): **22.9 KiB in Debug** (`ecdhInto`; `sign` 21.0, `verify` 19.1,
`generate` 18.3, `mul` 16.5 KiB) and **17.5 KiB in ReleaseFast** (`sign`; `generate` 17.0,
`ecdhInto` 16.5, `mul` 16.2, `verify` 9.0 KiB; the public-input `mulPublic` 1.5 KiB).
**Give a thread that calls them at least 64 KiB of free stack**: about 2.8x the
worst measured depth, which absorbs the caller's own frames and the build modes
not measured here. Embedded or coroutine stacks smaller than that need a bigger one
for these calls. A test (`stack use: ...` in `src/stackprobe2_test.zig`) pins the three
burn sizes, runs seven entry points in a 64 KiB thread and fails if one needs more than 32 KiB.

## Verify

```
zig build test-p256 --summary all                       # Debug
zig build test-p256 -Doptimize=ReleaseFast --summary all
P256_BENCH=1 zig build test-p256 -Doptimize=ReleaseFast # opt-in ns/op baseline
```

Green in both Debug and ReleaseFast (the single skip is the opt-in
bench). On amd64+ADX+BMI2 the three gated core-vs-portable differentials run for
real (field asm == portable, comb/windowed == CT ladder + std); on a non-amd64
host the field differential skips — a skip there means "core not present on this
build", never a green light. The suite includes the field/group differentials vs
`std.crypto.ecc.P256` (thousands of random inputs, bit-exact via `toBytes`), the
reduction fold-boundary edge sweep, the RFC 6979 ECDSA-P256/SHA-256 vectors
(verified by both p256 and std, **and reproduced byte-exactly** by
`ecdsaSignDeterministic` — note std's own deterministic signing is not RFC 6979,
so it cannot stand in for that), an ECDSA differential against std's signer (both
directions: p256 verifies std's signatures, and std verifies p256-produced ones),
**241 Wycheproof ECDSA-P256/SHA-256 P1363 vectors** (173 must verify, 68 must
not — run through both `ecdsaVerify` and the std-generic path, so the two cannot
drift apart unnoticed) and **484 Wycheproof DER vectors** (310 malformed
encodings) behind `derToRaw`, the SHA-512 (554 DER + 311 P1363) and SHA3-256 (482 DER)
Wycheproof files through `Ecdsa(Hash)` and `sign.ecdsaVerifyDigest`, **363 Wycheproof
ECDH vectors** and the NIST CAVP 186-4 SigVer/SigGen/KeyPair/PKV and ECC CDH rows
(`tools/gen_vectors.py` regenerates them), and two positive controls — a broken-Solinas-constant
reduction and a corrupted-comb-table gather — the harness flags RED.

Provenance: clean-room from the NIST P-256 domain parameters. Design
reference: OpenSSL nistz256 (**Apache-2.0**; the Gueron–Krasnov "Fast prime
field elliptic-curve cryptography with 256-bit primes" technique) — studied for
the technique shape only: the special-prime (Solinas) field reduction for
p = 2^256 − 2^224 + 2^192 + 2^96 − 1 (fold the high half by
M = 2^224 − 2^192 − 2^96 + 1 / the signed s1..s9 word-shuffle), and the amd64
`MULX/ADX` field multiply the amd64 core mirrors. No source ported. The NIST
P-256 domain parameters (p, n, G, the curve constant b, a = −3) are public curve
facts; the specific integer constants match `std.crypto.ecc.P256` (Zig std,
MIT), which is ALSO used as the byte-exact correctness oracle (differential
tests), not as a design reference. The end-to-end ECDSA anchor transcribes the
ECDSA-P256/SHA-256 vectors from RFC 6979 Appendix A.2.5, a public IETF spec
artifact used as a test oracle. P-256 has no efficiently-computable
endomorphism, so — unlike `k256` — there is no GLV construction to attribute.
Asm is amd64-only with a portable fallback everywhere.