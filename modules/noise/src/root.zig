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
//! **Status: compiling scaffold only, no crypto implemented.** Every
//! `CipherState`/`SymmetricState`/`HandshakeState` method (spec §5) is a
//! `@panic("TODO(agent): ...")` stub — no DH exchange, no AEAD seal/open,
//! no HKDF/HMAC ratchet is wired up yet. The handshake-pattern *data*
//! (`NN`/`NK`/`XX`/`IK` token sequences, spec §7/§9) is real, since
//! patterns are pure specification text, not crypto. See `SPEC.md` for the
//! fill-in plan and where the official test vectors live.
//!
//! Provenance: clean-room from the Noise Protocol Framework spec rev 34
//! (noiseprotocol.org) — a public spec, not copyrightable expression, so no
//! NOTICE entry would be strictly required for the spec citation alone;
//! however this module also names design references (API/behavior SHAPE
//! only, no source copied): cacophony (Haskell, BSD-2-Clause), noise-c
//! (github.com/rweather/noise-c, BSD-2-Clause), snow (Rust, Apache-2.0 OR
//! MIT). See `../../NOTICE` and `README.md`'s "Provenance" section.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Noise Protocol Framework rev 34 (noiseprotocol.org); design ref cacophony/noise-c/snow - shape only, no source copied",
    .deps = .{},
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
//   pub const Sha512Suite    = Suite(std.crypto.dh.X25519, std.crypto.aead.chacha_poly.ChaCha20Poly1305, std.crypto.hash.sha2.Sha512);
//   pub const Blake2sSuite   = Suite(std.crypto.dh.X25519, std.crypto.aead.chacha_poly.ChaCha20Poly1305, std.crypto.hash.blake2.Blake2s256);
//   pub const Blake2bSuite   = Suite(std.crypto.dh.X25519, std.crypto.aead.chacha_poly.ChaCha20Poly1305, std.crypto.hash.blake2.Blake2b512);

/// `Noise_*_25519_ChaChaPoly_SHA256` primitive family — the default suite.
pub const DefaultSuite = Suite(
    std.crypto.dh.X25519,
    std.crypto.aead.chacha_poly.ChaCha20Poly1305,
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

test "meta.deps is empty (this module depends on nothing, incl. wireguard)" {
    try std.testing.expectEqual(@as(usize, 0), meta.deps.len);
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
