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
rejection, and malformed-key-input typed errors. Run: `zig build test-sealedbox`.

**External anchor for the seal/open composition (`kat_test.zig` / `kat_vectors.zig`, added
2026-07-28):** the tests above only round-trip through this module's own `seal`/`open` — a shared
misreading of the spec on both sides would still pass. Two independent anchors close that:

1. **Underlying `crypto_box_easy` layer** — the classic djb/NaCl `crypto_box` test vector (Alice's
   secret key + Bob's public key = RFC 7748 §6.1's own X25519 test keypairs, a fixed nonce, and a
   published ciphertext) from libsodium's `test/default/box.c` + `box.exp`
   (github.com/jedisct1/libsodium, fetched 2026-07-28). `std.crypto.nacl.Box.seal`/`.open` — the
   primitive `SealedBox` composes on top of — reproduces the published 147-byte
   `tag ‖ ciphertext` byte-exact on the first try.
2. **The full `crypto_box_seal` composition** (ephemeral key + BLAKE2b nonce + box) — libsodium's
   *own* test suite (`test/default/box_seal.c`) cannot publish a fixed expected ciphertext because
   `crypto_box_seal` uses a random ephemeral key by construction (confirmed by reading that file:
   it only checks a random round-trip). This module's `seal(io, ...)` takes its ephemeral-key
   entropy through the caller-supplied `io: std.Io`, so a test `Io` whose `.random` returns a fixed
   32-byte seed (RFC 7748 "Alice", reused as an arbitrary constant) makes the *entire* composition
   deterministic through the real, unmodified `seal()` — no source change. The expected output was
   computed independently via **PyNaCl** (a CFFI binding to the real libsodium C library, not this
   module) directly calling `crypto_scalarmult_base` / `crypto_generichash` (BLAKE2b-192) /
   `crypto_box` in the same order as libsodium's own `crypto_box_seal.c`
   (confirmed by reading that file). Result: byte-exact match on the first run — no
   interoperability divergence found. Teeth confirmed: corrupting one byte of the expected vector
   produces a real, reported mismatch (verified, then reverted).
3. **What remains unanchored, and why that's the honest limit:** libsodium's own published test
   data for `crypto_box_seal` itself is inherently non-deterministic (random ephemeral key), so no
   third-party-*published* fixed `crypto_box_seal` ciphertext exists anywhere to paste in; the
   vector above is the closest achievable substitute (real libsodium code, fixed inputs we chose),
   not a vector libsodium itself publishes.

## Backlog / deferred

- **Reviewed 2026-07-10** (adversarial security pass, alongside `hashdigest`) — clean: faithful
  `std.crypto` wrapper, no accidental weakening (key/nonce reuse, truncation, or a silent fallback
  to something weaker) found.
- No other gaps found — the full `crypto_box` (authenticated two-party) API and secret zeroization
  are documented out-of-scope, not v1 gaps.

## Status

`extract · any · util · reentrant` + deps: none (`std.crypto` only) — canonical source is
`pub const meta` in src/root.zig.
