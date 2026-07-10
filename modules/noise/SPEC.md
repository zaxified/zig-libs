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

## Status (2026-07-10)

Compiling scaffold only. Every §5 method — `CipherState.{initializeKey,
hasKey, setNonce, encryptWithAd, decryptWithAd, rekey}`,
`SymmetricState.{initializeSymmetric, mixKey, mixHash, mixKeyAndHash,
getHandshakeHash, encryptAndHash, decryptAndHash, split}`,
`HandshakeState.{initialize, writeMessage, readMessage}` — is a
`@panic("TODO(agent): ...")` stub. No DH exchange, no AEAD seal/open, no
HKDF/HMAC ratchet is wired up. The module compiles and its tests (pattern
data + type-shape checks) pass; nothing that would touch the panicking
stubs is exercised.

## Fill-in plan (future pass)

1. **`CipherState`**: wire the suite's `Cipher` (an AEAD from
   `std.crypto.aead.*`) for `encryptWithAd`/`decryptWithAd`, following the
   spec's own nonce-encoding rule for `n` (spec §5.1) rather than
   WireGuard's framing (that framing belongs to the `wireguard` module,
   not here).
2. **`SymmetricState`**: an HKDF ratchet over the suite's `Hash`. The
   `wireguard` module's `noise.zig` (`kdf1`/`kdf2`/`kdf3` over
   `std.crypto.kdf.hkdf.Hkdf`) is a useful *shape* reference for how this
   codebase idiomatically drives `std.crypto.kdf.hkdf` — but do not import
   from `wireguard`; reimplement locally, generic over `Hash`, since this
   module has zero deps.
3. **`HandshakeState`**: drive `pattern.message_patterns[message_index]`
   token-by-token per the spec §5.3 `WriteMessage`/`ReadMessage`
   pseudocode, incrementing `message_index` and returning `Split()`'s pair
   once the pattern is exhausted.

## Verification (future pass)

Per `CONVENTIONS.md` §7's "Protocol codecs" tier: golden/known-answer
vectors are the right oracle here. The official Noise vectors (the
`cacophony` JSON vector format) live in rweather/noise-c's `vectors/`
directory on GitHub, and in snow's / cacophony's own vector files — none
are consulted yet, since there is no crypto implementation to check them
against in this pass.
