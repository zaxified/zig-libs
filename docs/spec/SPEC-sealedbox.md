# SPEC — `sealedbox`

**Purpose** — Anonymous-sender public-key encryption: encrypt a message to a recipient's X25519
public key such that only the recipient can open it, and the sender is not identified (NaCl
`crypto_box_seal`). Plus base64/hex serialization of keys. For enrollment / one-way secrets where
the sender has no long-term key.

**Model after / Seed** — libsodium `crypto_box_seal` / Go `nacl/box` (the sealed-box construction).
A thin layer over `std.crypto` (X25519 + XSalsa20-Poly1305 as provided by std). Extracted from the
authors' axp `sealed.zig` (Apache-2.0, relicensed MIT). Construction is the public NaCl standard.

**Design & invariants**
- **Sealed box = ephemeral keypair + box:** generate an ephemeral X25519 keypair per message, derive
  the nonce as `blake2b(ephemeral_pk ++ recipient_pk)` (the NaCl seal convention), box the plaintext,
  and prepend the ephemeral public key. `open` recomputes the nonce and unboxes; a forged/tampered
  ciphertext fails the Poly1305 tag (authenticated).
- **Allocation-free**, reentrant; keys are fixed-size arrays. `publicFromSecret` /
  `keyPairFromSecretKey` recover a keypair from a stored secret (via std `X25519.recoverPublicKey`)
  so a persisted secret round-trips. Serialization is fixed-size base64/hex with typed errors.
- All primitives come from `std.crypto` — no bespoke crypto.

**Threat model / out of scope**
- **Confidentiality + integrity to the recipient**, and **sender anonymity** (no sender key, so a
  message carries no sender identity). Tampering is detected (AEAD tag).
- **No sender authentication** — by design; the recipient cannot tell *who* sent a sealed box (if
  you need authenticated sender, use a full box with both keys, which this module does not expose).
- **No forward secrecy** beyond the per-message ephemeral key; recipient secret-key compromise
  decrypts all past sealed boxes to that key.
- **Out of scope:** key management/storage, secret zeroization, side-channel hardening beyond what
  `std.crypto` provides, and the full `crypto_box` (authenticated two-party) API.

**Verification** — RFC 7748-cross-checked X25519 KATs, end-to-end serialize→deserialize→seal→open,
tamper/forgery rejection, and malformed-key-input typed errors. 9 tests.

**Status** — `extract · any · util · reentrant` · deps: none (`std.crypto` only).
