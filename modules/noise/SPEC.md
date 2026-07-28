# noise — SPEC

See `README.md` for the consumer-facing API summary and Provenance note.

## Design

- **Patterns as data.** `patterns.zig`'s `HandshakePattern` mirrors the
  spec's §7.2 grammar directly: pre-message patterns (§7.2) plus a list of
  per-message token sequences (§7.1's token vocabulary lives in
  `token.zig`'s `Token`). `NN`/`NK`/`XX`/`IK` (spec §9) are filled in as
  real `[]const []const Token` data. The rest of the §9 catalog (`NX`,
  `XN`, `XK`, `KN`, `KK`, `KX`, `IN`, `IX`, the one-way `N`/`K`/`X`
  patterns, PSK-modifier and deferred variants) is not yet scaffolded —
  add entries following the same shape when a consumer needs them.
- **Suite as a comptime binding, not a runtime vtable.** `state.Suite(DH,
  Cipher, Hash)` (spec §4) returns a namespace with `CipherState` /
  `SymmetricState` / `HandshakeState` monomorphized on the three primitive
  choices, so a consumer picks its suite once at compile time — no dynamic
  dispatch, no `anytype` at the call site, mirroring how `wireguard`
  already fixes its own (different) suite at compile time.
- **`CipherState.k`, `SymmetricState.ck`/`.h`** use the literal byte widths
  the spec itself assigns: `k` is always 32 bytes (every spec-listed AEAD
  uses a 32-byte key), while `ck`/`h` are `HASHLEN` bytes
  (`Hash.digest_length`) — matching spec §5.1/§5.2 verbatim rather than
  deriving `k`'s width from `Cipher.key_length`.

## Status

**Implemented.** Every §5 method — `CipherState.{initializeKey, hasKey,
setNonce, encryptWithAd, decryptWithAd, rekey}`, `SymmetricState.
{initializeSymmetric, mixKey, mixHash, mixKeyAndHash, getHandshakeHash,
encryptAndHash, decryptAndHash, split}`, `HandshakeState.{initialize,
writeMessage, readMessage}` — is real: no `@panic`/TODO stub remains in
`state.zig`. DH exchange, AEAD seal/open, and the HKDF/HMAC ratchet are
all wired up over the comptime-bound `Suite(DH, Cipher, Hash)`.

The implementation follows the plan that used to live in this section
(§5.1 nonce encoding for `CipherState`, a from-scratch HKDF ratchet for
`SymmetricState` generic over `Hash` — not imported from `wireguard`,
since this module has zero deps — and the §5.3 `WriteMessage`/
`ReadMessage` token-by-token pseudocode for `HandshakeState`).

## Verification

Per `CONVENTIONS.md` §7's "Protocol codecs" tier: golden/known-answer
vectors anchor this module. `state.zig` embeds six official noise-c
vectors (the `cacophony` JSON format, from rweather/noise-c's `vectors/`
directory), transcribed as byte literals and run end-to-end through
`HandshakeState`/`CipherState`: `Noise_NN_25519_ChaChaPoly_SHA256`,
`Noise_NK_25519_ChaChaPoly_SHA256`, `Noise_XX_25519_ChaChaPoly_SHA256`
(covers both `es` and `se` token directions), `Noise_IK_25519_ChaChaPoly_
SHA256` (covers `es`+`ss`+`se`), `Noise_XX_25519_ChaChaPoly_BLAKE2s` (a
second hash function), and `Noise_IK_25519_ChaChaPoly_SHA512` (HASHLEN=64
truncation to 32-byte keys). Each vector checks every transport-message
ciphertext AND the final `handshake_hash`, byte-exact. Beyond the KATs:
`SymmetricState`'s HKDF is checked against RFC 5869 HKDF with empty info;
self-consistency round-trips exercise all four patterns with generated
(non-vector) ephemerals; a tampered-message test asserts AEAD auth
failure; a fuzz test asserts `HandshakeState.readMessage` never panics on
arbitrary bytes. Also exercised indirectly end-to-end by the sibling
`bolt8` module, whose BOLT#8 appendix vectors run over this framework.

snow's and cacophony's own vector JSON files (same `cacophony` format)
were not additionally consulted — the noise-c set already covers every
pattern/hash/DH combination this module implements, so they would be
redundant, not a stronger check.
