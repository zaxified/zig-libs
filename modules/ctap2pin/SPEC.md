# ctap2pin — SPEC

CTAP 2.1 `pinUvAuthProtocol` One and Two; see [README.md](README.md) for
purpose and API. Provenance: see [NOTICE](NOTICE).

## Design

- **Source of truth**: FIDO Alliance CTAP 2.1, §6.5.6 (abstract
  interface: `initialize`/`encapsulate`/`encrypt`/`decrypt`/
  `authenticate`/`verify`), §6.5.7 (Protocol One), §6.5.8 (Protocol Two).
  The two protocols are exposed as concrete namespaces `One` and `Two`
  (their key/signature/framing types genuinely differ), with the wire
  enum `Protocol` and comptime dispatch `Impl(protocol)` on top. There is
  no `initialize`/`regenerate` state: all randomness (the platform ECDH
  scalar, the protocol-Two IV) is a caller input, so the module is
  deterministic, KAT-able, and RNG-agnostic (std 0.16 has no
  `std.crypto.random`).
- **std recon (confirmed against `lib/std/crypto`, 0.16.0)**:
  - `core.aes.Aes256` is the raw block cipher only (`initEnc`/`initDec`,
    per-block ctx `encrypt`/`decrypt`); std's modes are AEADs (GCM, CCM,
    OCB) — **CBC is absent**, so `Aes256Cbc` here implements it
    (encrypt `c_i = E(p_i XOR c_{i-1})`, decrypt `p_i = D(c_i) XOR
    c_{i-1}`), no padding, per the CTAP2 requirement that plaintexts are
    whole blocks.
  - `ecc.P256`: `fromAffineCoordinates` re-checks the curve equation
    (peer COSE-key validation), `Fe.fromBytes(.big)` rejects
    non-canonical coordinates, `mul(scalar, .big)` is the constant-time
    scalar-mult, `affineCoordinates().x.toBytes(.big)` yields Z, and
    `scalar.rejectNonCanonical` screens the private scalar (zero is
    additionally rejected explicitly — `mul` would surface it as
    `IdentityElement`, but as the wrong error meaning).
  - `kdf.hkdf.HkdfSha256.extract/expand`, `auth.hmac.sha2.HmacSha256`,
    `hash.sha2.Sha256` — direct fits for both KDFs and both MACs.
  - `timing_safe.eql` — both `verify`s compare MACs in constant time and
    fail closed (wrong-length signature → `false`, never a panic).

## Threat-model notes

- CBC provides **no integrity**: CTAP2 pairs every ciphertext with a
  `pinUvAuthParam` MAC. Callers must `verify` before acting on decrypted
  data (the tests demonstrate tamper detection via the MAC, not via
  decrypt).
- Protocol One's zero IV is per the spec and safe only because every
  encrypted payload in CTAP2 is protected by fresh key agreement;
  Protocol Two's random IV must be fresh per encryption — the caller owns
  that (parameter, deliberately).
- The shared secret is per-transaction: callers should
  `std.crypto.secureZero` it after use.
- `verify` truncation (Protocol One) still compares constant-time over
  the full 16 bytes; a 32-byte (full-HMAC) signature is rejected by
  length, not truncated.

## Validation

No official CTAP2 pinUvAuthProtocol KAT table exists; each composed
primitive is anchored byte-exact to its own official vector
(`kat_vectors.zig`), and the protocol layer is proven by two-sided
round-trips (`kat_test.zig`):

| Piece | Oracle | Assertion |
|---|---|---|
| AES-256-CBC | NIST SP 800-38A F.2.5/F.2.6 | byte-exact, both directions |
| HKDF-SHA-256 | RFC 5869 A.1 | PRK + OKM byte-exact |
| P-256 ECDH | RFC 5903 §8.1 | both pubkeys + Z (`girx`) byte-exact |
| HMAC-SHA-256 | RFC 4231 §4.3 TC2 | byte-exact |
| Protocols One/Two | round-trip | two-sided `encapsulate` agreement; `decrypt∘encrypt = id`; `verify∘authenticate = true`; tamper/length rejection |

25/25 tests green in Debug and ReleaseFast (`zig build test-ctap2pin
[-Doptimize=ReleaseFast]`).

## Non-goals

- CBOR / COSE_Key codecs and the `clientPin` command framing (a future
  `ctap2` module's job; this module is the pure crypto layer beneath it).
- PIN policy (hashing, retries, `pinUvAuthToken` state machines).
- Protocol One's platform-side per-command key regeneration policy
  (callers regenerate by supplying a fresh scalar).
