# sealedbox — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see ./README.md (no NOTICE entry — public NaCl standard, no third-party code).

## Design & invariants

- **Sealed box = ephemeral keypair + box:** generate an ephemeral X25519 keypair per message,
  derive the nonce as `blake2b(ephemeral_pk ++ recipient_pk)` (the NaCl seal convention), box the
  plaintext, and prepend the ephemeral public key. `open` recomputes the nonce and unboxes; a
  forged/tampered ciphertext fails the Poly1305 tag (authenticated). Modeled after libsodium
  `crypto_box_seal` / Go `nacl/box` — the public NaCl sealed-box standard; a thin layer over
  `std.crypto` (X25519 + XSalsa20-Poly1305 as provided by std). Original work of the zig-libs
  authors (MIT); no NOTICE entry needed (public NaCl standard, no third-party code).
- **Allocation-free**, reentrant; keys are fixed-size arrays. `publicFromSecret` /
  `keyPairFromSecretKey` recover a keypair from a stored secret (via std `X25519.recoverPublicKey`)
  so a persisted secret round-trips. Serialization is fixed-size base64/hex with typed errors.
- **No bespoke crypto:** every primitive comes from `std.crypto` — this module composes, it does
  not implement, cryptographic primitives.

## Threat model / out of scope

- **Confidentiality + integrity to the recipient**, and **sender anonymity** (no sender key, so a
  message carries no sender identity). Tampering is detected (AEAD tag).
- **No sender authentication** — by design; the recipient cannot tell *who* sent a sealed box (a
  full box with both keys, which this module does not expose, is needed for authenticated sender).
- **No forward secrecy** beyond the per-message ephemeral key; recipient secret-key compromise
  decrypts all past sealed boxes to that key.
- **No primitive weakening:** X25519/XSalsa20-Poly1305/BLAKE2b are used exactly as `std.crypto`
  provides them — no custom KDF, no reduced-round variant, no home-rolled AEAD. Nonce derivation is
  deterministic-but-collision-safe by construction (fresh ephemeral key per call ⇒ fresh nonce
  input per call); the module never accepts a caller-supplied nonce that could be reused.
- **Out of scope:** key management/storage, secret zeroization, side-channel hardening beyond what
  `std.crypto` provides, and the full `crypto_box` (authenticated two-party) API.

## Verification

RFC 7748-cross-checked X25519 KATs, end-to-end serialize→deserialize→seal→open, tamper/forgery
rejection, and malformed-key-input typed errors. 9 tests. Run: `zig build test-sealedbox`.

## Backlog / deferred

- **Pre-public security/similarity review** — `sealedbox` is explicitly on the repo's pre-public
  security-gate checklist (see /docs/pre-public-review.md) alongside `hashdigest`, pending a
  dedicated adversarial pass before any release; not yet run.
- No other gaps found — the full `crypto_box` (authenticated two-party) API and secret zeroization
  are documented out-of-scope, not v1 gaps.

## Status

`extract · any · util · reentrant` + deps: none (`std.crypto` only) — canonical source is
`pub const meta` in src/root.zig.
