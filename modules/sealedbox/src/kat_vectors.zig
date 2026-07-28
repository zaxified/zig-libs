// SPDX-License-Identifier: MIT
//! External vector for the `crypto_box_seal` *composition* itself (ephemeral
//! keypair + nonce derivation + box), not just its underlying X25519 math
//! (already RFC 7748-anchored inline in `root.zig`'s own tests).
//!
//! **Why this vector exists at all**: `crypto_box_seal` uses a *random*
//! ephemeral key by design, so libsodium's own test suite
//! (`test/default/box_seal.c`, fetched 2026-07-28 from
//! https://raw.githubusercontent.com/jedisct1/libsodium/master/test/default/box_seal.c)
//! only checks a random round-trip (seal then open, compare plaintexts) —
//! it does not and cannot publish a fixed expected ciphertext. That rules
//! out a literal "paste libsodium's own KAT" anchor.
//!
//! What *is* achievable: `std.crypto.nacl.SealedBox.seal(io, ...)` takes its
//! entropy through the caller-supplied `io: std.Io` (via
//! `X25519.KeyPair.generate(io)` -> `io.random(...)`) — the sole seam that
//! decides the ephemeral key. Supplying an `Io` whose `random` returns a
//! fixed byte string turns the *entire* `crypto_box_seal` composition
//! deterministic through the real, unmodified `seal()` code path (no source
//! change, no monkey-patching of this module or std — see `kat_test.zig`'s
//! `FixedRandom`, which copies `std.testing.io`'s vtable and overrides only
//! the `random` function pointer).
//!
//! With the ephemeral key pinned, the expected output below was computed
//! **independently, via real libsodium** — not derived from this module's
//! own output — using PyNaCl (https://pypi.org/project/PyNaCl/, a CFFI
//! binding to the actual libsodium C library, version checked via
//! `python3 -c "import nacl; print(nacl.__version__)"` = 1.5.0 at time of
//! writing) to call libsodium's own primitives directly:
//!   - `crypto_scalarmult_base(esk)` -> ephemeral public key
//!   - `crypto_generichash(epk || recipient_pk, digest_size=24)` -> nonce
//!     (BLAKE2b, libsodium's own `crypto_box_seal.c` nonce derivation —
//!     fetched 2026-07-28 from
//!     https://raw.githubusercontent.com/jedisct1/libsodium/master/src/libsodium/crypto_box/crypto_box_seal.c,
//!     confirmed byte-for-byte identical in argument order to this module's
//!     `std.crypto.nacl.SealedBox.createNonce(pk1, pk2)`)
//!   - `crypto_box(msg, nonce, recipient_pk, esk)` -> the box (tag||ciphertext)
//!   - `sealed = epk || box`
//! This reconstructs libsodium's own `crypto_box_seal` algorithm with an
//! ephemeral key WE chose, using libsodium's own code to compute the
//! expected answer — a genuine external anchor, not a self-round-trip.
//!
//! Key material: the "ephemeral" secret and the recipient keypair are both
//! RFC 7748 §6.1's well-known Alice/Bob X25519 test vectors (reused here
//! purely as arbitrary fixed 32-byte constants, already present in this
//! module's own RFC-7748 KAT test) — not invented, not derived from this
//! module's other output.
//!
//! Underlying primitive cross-check (separate from the seal composition):
//! the classic djb/NaCl `crypto_box` vector (same Alice/Bob keys, a fixed
//! nonce, and a published ciphertext) from libsodium's
//! `test/default/box.c` + `box.exp` (fetched 2026-07-28) round-trips
//! byte-exact through `std.crypto.nacl.Box.seal`/`.open` — see
//! `kat_test.zig`'s "classic NaCl box vector" test. That confirms the
//! X25519+XSalsa20-Poly1305 layer `SealedBox` composes on top of is itself
//! correct against an independent implementation, closing the other half of
//! the gap.

/// RFC 7748 §6.1 "Bob" keypair — used here as the sealed-box recipient.
pub const recipient_pk_hex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
pub const recipient_sk_hex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

/// RFC 7748 §6.1 "Alice" secret key, reused as a fixed 32-byte value fed
/// into `io.random()` so the ephemeral X25519 keypair becomes deterministic.
pub const fixed_ephemeral_seed_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";

pub const message = "sealed box KAT: cbor/sealedbox external anchor";

/// `epk (32) || crypto_box(message, nonce, recipient_pk, esk) (16 tag + msg.len)`
/// computed independently via PyNaCl (real libsodium), as described above.
pub const expected_sealed_hex =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" ++
    "fa109a544d0b8c8c170ca2eac5deaf4dd462cdaa8d9c2333bf1e6b31ac2f136b0" ++
    "c3a310493357ca5955bd6ff69d974610d026f9edab56917908510263820";

// ── underlying crypto_box_easy layer cross-check (djb/NaCl classic vector,
//    libsodium test/default/box.c + box.exp, fetched 2026-07-28) ──────────

pub const box_alice_sk_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
pub const box_bob_pk_hex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
pub const box_nonce_hex = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
pub const box_message_hex =
    "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ff" ++
    "ce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb" ++
    "310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1" ++
    "fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705";
/// `tag (16 bytes) || ciphertext (131 bytes)`, from `box.exp`.
pub const box_expected_ciphertext_hex =
    "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76c" ++
    "e48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c9" ++
    "7271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e52" ++
    "6ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5";
