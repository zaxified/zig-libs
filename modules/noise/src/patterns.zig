// SPDX-License-Identifier: MIT
//! Noise Protocol Framework handshake patterns (spec rev 34, §7 grammar +
//! §9 pattern catalog). This is pure specification DATA (token sequences),
//! not crypto — filled in for real from noiseprotocol.org and cross-checked
//! against the well-known canonical listings for `NN`/`NK`/`XX`/`IK`.
//!
//! Only these four fundamental patterns are reserved for now; the rest of
//! the §9 catalog (NX, XN, XK, KN, KK, KX, IN, IX, the one-way N/K/X
//! patterns, PSK-modifier and deferred variants, …) is future work — add
//! entries to this file following the same `HandshakePattern` shape.

const std = @import("std");
const Token = @import("token.zig").Token;

/// A named handshake pattern: which static/ephemeral keys are already known
/// before the handshake starts (the pre-message patterns, spec §7.2) plus
/// the token sequence for each of the actual handshake messages exchanged,
/// starting with the initiator's first message and alternating direction.
pub const HandshakePattern = struct {
    /// Pattern name, e.g. `"NN"`, `"XX"`, `"IK"` — combined with the DH/
    /// cipher/hash names to build the full protocol name string (spec §8,
    /// e.g. `"Noise_IK_25519_ChaChaPoly_SHA256"`).
    name: []const u8,
    /// Pre-message pattern known to have been sent by the initiator before
    /// the first real message (empty if the initiator has no such
    /// out-of-band-known key for this pattern).
    pre_message_initiator: []const Token = &.{},
    /// Pre-message pattern known to have been sent by the responder before
    /// the first real message (empty if the responder has no such
    /// out-of-band-known key for this pattern).
    pre_message_responder: []const Token = &.{},
    /// The token sequence for each handshake message, alternating
    /// initiator/responder starting with the initiator's first message.
    message_patterns: []const []const Token,
};

// ── the catalog (spec §9) ────────────────────────────────────────────────

/// `NN`: no static keys at all — fully unauthenticated, ephemeral-only DH.
/// `-> e` `<- e, ee`
pub const NN = HandshakePattern{
    .name = "NN",
    .message_patterns = &.{
        &.{.e},
        &.{ .e, .ee },
    },
};

/// `NK`: the initiator authenticates the responder's static key (known in
/// advance, out of band); the initiator itself remains anonymous.
/// pre: `<- s` then `-> e, es` `<- e, ee`
pub const NK = HandshakePattern{
    .name = "NK",
    .pre_message_responder = &.{.s},
    .message_patterns = &.{
        &.{ .e, .es },
        &.{ .e, .ee },
    },
};

/// `XX`: mutual authentication; both static keys are transmitted
/// (encrypted) during the handshake itself — neither side knows the
/// other's static key ahead of time.
/// `-> e` `<- e, ee, s, es` `-> s, se`
pub const XX = HandshakePattern{
    .name = "XX",
    .message_patterns = &.{
        &.{.e},
        &.{ .e, .ee, .s, .es },
        &.{ .s, .se },
    },
};

/// `IK`: the initiator knows the responder's static key in advance and
/// transmits its own static key immediately (encrypted) in the first
/// message; the responder authenticates the initiator by the end of its
/// own first (and only) reply message.
/// pre: `<- s` then `-> e, es, s, ss` `<- e, ee, se`
pub const IK = HandshakePattern{
    .name = "IK",
    .pre_message_responder = &.{.s},
    .message_patterns = &.{
        &.{ .e, .es, .s, .ss },
        &.{ .e, .ee, .se },
    },
};

// ── tests: exact token sequences, double-check against the spec ─────────

test "NN: -> e ; <- e, ee" {
    try std.testing.expectEqual(@as(usize, 0), NN.pre_message_initiator.len);
    try std.testing.expectEqual(@as(usize, 0), NN.pre_message_responder.len);
    try std.testing.expectEqual(@as(usize, 2), NN.message_patterns.len);
    try std.testing.expectEqualSlices(Token, &.{.e}, NN.message_patterns[0]);
    try std.testing.expectEqualSlices(Token, &.{ .e, .ee }, NN.message_patterns[1]);
}

test "NK: pre <- s ; -> e, es ; <- e, ee" {
    try std.testing.expectEqual(@as(usize, 0), NK.pre_message_initiator.len);
    try std.testing.expectEqualSlices(Token, &.{.s}, NK.pre_message_responder);
    try std.testing.expectEqual(@as(usize, 2), NK.message_patterns.len);
    try std.testing.expectEqualSlices(Token, &.{ .e, .es }, NK.message_patterns[0]);
    try std.testing.expectEqualSlices(Token, &.{ .e, .ee }, NK.message_patterns[1]);
}

test "XX: -> e ; <- e, ee, s, es ; -> s, se" {
    try std.testing.expectEqual(@as(usize, 0), XX.pre_message_initiator.len);
    try std.testing.expectEqual(@as(usize, 0), XX.pre_message_responder.len);
    try std.testing.expectEqual(@as(usize, 3), XX.message_patterns.len);
    try std.testing.expectEqualSlices(Token, &.{.e}, XX.message_patterns[0]);
    try std.testing.expectEqualSlices(Token, &.{ .e, .ee, .s, .es }, XX.message_patterns[1]);
    try std.testing.expectEqualSlices(Token, &.{ .s, .se }, XX.message_patterns[2]);
}

test "IK: pre <- s ; -> e, es, s, ss ; <- e, ee, se" {
    try std.testing.expectEqual(@as(usize, 0), IK.pre_message_initiator.len);
    try std.testing.expectEqualSlices(Token, &.{.s}, IK.pre_message_responder);
    try std.testing.expectEqual(@as(usize, 2), IK.message_patterns.len);
    try std.testing.expectEqualSlices(Token, &.{ .e, .es, .s, .ss }, IK.message_patterns[0]);
    try std.testing.expectEqualSlices(Token, &.{ .e, .ee, .se }, IK.message_patterns[1]);
}

test "catalog: every pattern's name matches its own const identifier" {
    try std.testing.expectEqualStrings("NN", NN.name);
    try std.testing.expectEqualStrings("NK", NK.name);
    try std.testing.expectEqualStrings("XX", XX.name);
    try std.testing.expectEqualStrings("IK", IK.name);
}
