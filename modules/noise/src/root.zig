// SPDX-License-Identifier: MIT
//! noise — the generic Noise Protocol Framework (https://noiseprotocol.org,
//! spec revision 34): handshake patterns as data (`patterns.zig`) plus a
//! comptime-parameterized DH/cipher/hash `Suite` (`state.zig`), reusable
//! for any Noise-based protocol.
//!
//! This is deliberately distinct from — and has ZERO dependency on — the
//! `wireguard` module's `noise.zig`/`handshake.zig`, which hard-wire
//! WireGuard's fixed `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` instantiation
//! (a specialized, already-implemented KDF/handshake for one protocol).
//! This module is the general framework: any pattern, any of the spec's
//! named DH/AEAD/hash choices.
//!
//! **Status: implemented.** The `CipherState`/`SymmetricState`/`HandshakeState`
//! methods (spec §5) are wired up over the comptime-parameterized `Suite`: DH
//! exchange, AEAD seal/open, and the HKDF/HMAC ratchet all run. The
//! handshake-pattern *data* (`NN`/`NK`/`XX`/`IK` token sequences, spec §7/§9)
//! is real as well (patterns are pure specification text, not crypto). See
//! `SPEC.md` and the official test vectors it references.
//!
//! Provenance: clean-room from the Noise Protocol Framework spec rev 34
//! (noiseprotocol.org) — a public spec, not copyrightable expression, so no
//! NOTICE entry would be strictly required for the spec citation alone;
//! however this module also names design references (API/behavior SHAPE
//! only, no source copied): cacophony (Haskell, BSD-2-Clause), noise-c
//! (github.com/rweather/noise-c, BSD-2-Clause), snow (Rust, Apache-2.0 OR
//! MIT). See `../../NOTICE` and `README.md`'s "Provenance" section.

const std = @import("std");
const chachapoly = @import("chachapoly");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Noise Protocol Framework rev 34 (noiseprotocol.org); design ref cacophony/noise-c/snow - shape only, no source copied",
    // The spec §4.2 `ChaChaPoly` cipher comes from the `chachapoly` sibling
    // (SIMD ChaCha20-Poly1305, byte-exact to std) rather than std, so the
    // AEAD is not the bottleneck for a `CipherState` carrying bulk transport
    // records. `Suite` stays generic — std's AEAD is still bindable, and the
    // official noise-c vectors are run under BOTH (see state.zig).
    .deps = .{"chachapoly"},
};

pub const token = @import("token.zig");
pub const Token = token.Token;

pub const patterns = @import("patterns.zig");
pub const HandshakePattern = patterns.HandshakePattern;

pub const state = @import("state.zig");
pub const Suite = state.Suite;

// ── convenience suite alias ──────────────────────────────────────────────
//
// The three primitive families a Noise suite binds (spec §4): DH, Cipher
// (AEAD), Hash. Only `Noise_*_25519_ChaChaPoly_SHA256` is instantiated as a
// top-level convenience alias here; the other spec-named combinations are
// reserved (all reachable via `Suite(...)` directly) for whichever
// crypto-implementation pass needs them:
//
//   pub const Aes256GcmSuite = Suite(std.crypto.dh.X25519, std.crypto.aead.aes_gcm.Aes256Gcm, std.crypto.hash.sha2.Sha256);
//   pub const Sha512Suite    = Suite(std.crypto.dh.X25519, ChaCha20Poly1305, std.crypto.hash.sha2.Sha512);
//   pub const Blake2sSuite   = Suite(std.crypto.dh.X25519, ChaCha20Poly1305, std.crypto.hash.blake2.Blake2s256);
//   pub const Blake2bSuite   = Suite(std.crypto.dh.X25519, ChaCha20Poly1305, std.crypto.hash.blake2.Blake2b512);

/// The spec §4.2 `ChaChaPoly` cipher this module DEFAULTS to: the SIMD
/// `chachapoly` sibling, byte-exact to `std.crypto.aead.chacha_poly.
/// ChaCha20Poly1305` (that module's differential anchors it over every
/// block-boundary edge length; `state.zig` re-proves it on the official
/// noise-c vectors). Re-exported so downstream Noise-based protocols
/// (`bolt8`, `tenantkex`) can bind the same AEAD without taking their own
/// `chachapoly` dependency.
///
/// `Suite` is and stays generic over the AEAD — std's type remains bindable
/// (`cipherName` maps both to the same spec §8 `ChaChaPoly` fragment, so the
/// choice cannot reach the wire), which is what keeps std usable as a
/// differential oracle.
pub const ChaCha20Poly1305 = chachapoly.ChaCha20Poly1305;

/// `Noise_*_25519_ChaChaPoly_SHA256` primitive family — the default suite.
pub const DefaultSuite = Suite(
    std.crypto.dh.X25519,
    ChaCha20Poly1305,
    std.crypto.hash.sha2.Sha256,
);

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = token;
    _ = patterns;
    _ = state;
}

test "meta.deps is exactly {chachapoly} (the AEAD; NOT wireguard)" {
    // The point of the assertion has always been that `noise` does not depend
    // on `wireguard` (they are the framework and one hard-wired instantiation
    // of it, not layers). `chachapoly` is the one permitted edge: the spec
    // §4.2 AEAD implementation.
    try std.testing.expectEqual(@as(usize, 1), meta.deps.len);
    try std.testing.expectEqualStrings("chachapoly", meta.deps[0]);
}

test "DefaultSuite binds the chachapoly sibling, and the spec §8 name is unchanged by that" {
    // Both implementations must produce the SAME protocol name — the name is
    // hashed into the initial chaining key, so a fork here is a wire-format
    // change masquerading as an implementation detail.
    try std.testing.expectEqual(chachapoly.ChaCha20Poly1305, DefaultSuite.AeadCipher);
    const StdSuite = Suite(
        std.crypto.dh.X25519,
        std.crypto.aead.chacha_poly.ChaCha20Poly1305,
        std.crypto.hash.sha2.Sha256,
    );
    var ours: DefaultSuite.HandshakeState = .{};
    var theirs: StdSuite.HandshakeState = .{};
    ours.initialize(patterns.NN, true, "", null, null, null, null, &.{});
    theirs.initialize(patterns.NN, true, "", null, null, null, null, &.{});
    try std.testing.expectEqualSlices(
        u8,
        &theirs.symmetric_state.getHandshakeHash(),
        &ours.symmetric_state.getHandshakeHash(),
    );
}

test "the swap is inert: chachapoly and std AEAD constants are identical" {
    const Std = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const Ours = chachapoly.ChaCha20Poly1305;
    try std.testing.expectEqual(Std.key_length, Ours.key_length);
    try std.testing.expectEqual(Std.nonce_length, Ours.nonce_length);
    try std.testing.expectEqual(Std.tag_length, Ours.tag_length);
}

test "DefaultSuite: DHLEN/HASHLEN match X25519 + SHA256" {
    try std.testing.expectEqual(@as(usize, 32), DefaultSuite.DHLEN);
    try std.testing.expectEqual(@as(usize, 32), DefaultSuite.HASHLEN);
}

test "patterns: XX has 3 messages; IK/NK have a responder pre-message; NN has none" {
    try std.testing.expectEqual(@as(usize, 3), patterns.XX.message_patterns.len);
    try std.testing.expectEqualSlices(Token, &.{.s}, patterns.IK.pre_message_responder);
    try std.testing.expectEqualSlices(Token, &.{.s}, patterns.NK.pre_message_responder);
    try std.testing.expectEqual(@as(usize, 0), patterns.NN.pre_message_responder.len);
}
