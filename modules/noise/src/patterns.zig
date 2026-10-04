// SPDX-License-Identifier: MIT
//! Noise Protocol Framework handshake patterns (spec rev 34, §7 grammar +
//! §9 pattern catalog). This is pure specification DATA (token sequences),
//! not crypto — filled in for real from noiseprotocol.org and cross-checked
//! against the well-known canonical listings for `NN`/`NK`/`XX`/`IK`.
//!
//! The whole rev-34 catalog is here: the three one-way patterns (§7.4), the
//! twelve fundamental interactive ones (§7.5) and the twenty-three deferred
//! ones (§7.6). PSK modifiers (§9.2, `psk0`..`pskN`, combinable with `+`)
//! are applied by `withPsk` at comptime or by `parse` into a `Storage` at
//! run time; `parseProtocolName` splits a full `Noise_XXpsk3_25519_…` name.
//! Every pattern is checked byte-exact against the cacophony vectors (see
//! `state.zig`). The `fallback` modifier (§10.2) is not implemented.

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

// ── the catalog (spec §7.4–§7.6) ────────────────────────────────────────

fn hp(comptime name: []const u8, comptime pre_i: []const Token, comptime pre_r: []const Token, comptime msgs: []const []const Token) HandshakePattern {
    return .{ .name = name, .pre_message_initiator = pre_i, .pre_message_responder = pre_r, .message_patterns = msgs };
}

// One-way (§7.4): a single message from initiator to responder.

/// `N`: `<- s` … `-> e, es`
pub const N = hp("N", &.{}, &.{.s}, &.{&.{ .e, .es }});
/// `K`: `-> s`, `<- s` … `-> e, es, ss`
pub const K = hp("K", &.{.s}, &.{.s}, &.{&.{ .e, .es, .ss }});
/// `X`: `<- s` … `-> e, es, s, ss`
pub const X = hp("X", &.{}, &.{.s}, &.{&.{ .e, .es, .s, .ss }});

// Fundamental interactive (§7.5).

/// `NN`: no static keys at all — fully unauthenticated, ephemeral-only DH.
/// `-> e` `<- e, ee`
pub const NN = hp("NN", &.{}, &.{}, &.{ &.{.e}, &.{ .e, .ee } });
/// `NK`: the initiator authenticates the responder's static key (known in
/// advance, out of band); the initiator itself remains anonymous.
/// pre: `<- s` then `-> e, es` `<- e, ee`
pub const NK = hp("NK", &.{}, &.{.s}, &.{ &.{ .e, .es }, &.{ .e, .ee } });
/// `NX`: `-> e` `<- e, ee, s, es`
pub const NX = hp("NX", &.{}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .s, .es } });
/// `KN`: `-> s` … `-> e` `<- e, ee, se`
pub const KN = hp("KN", &.{.s}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .se } });
/// `KK`: `-> s`, `<- s` … `-> e, es, ss` `<- e, ee, se`
pub const KK = hp("KK", &.{.s}, &.{.s}, &.{ &.{ .e, .es, .ss }, &.{ .e, .ee, .se } });
/// `KX`: `-> s` … `-> e` `<- e, ee, se, s, es`
pub const KX = hp("KX", &.{.s}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .se, .s, .es } });
/// `XN`: `-> e` `<- e, ee` `-> s, se`
pub const XN = hp("XN", &.{}, &.{}, &.{ &.{.e}, &.{ .e, .ee }, &.{ .s, .se } });
/// `XK`: `<- s` … `-> e, es` `<- e, ee` `-> s, se`
pub const XK = hp("XK", &.{}, &.{.s}, &.{ &.{ .e, .es }, &.{ .e, .ee }, &.{ .s, .se } });
/// `XX`: mutual authentication; both static keys are transmitted
/// (encrypted) during the handshake itself — neither side knows the
/// other's static key ahead of time.
/// `-> e` `<- e, ee, s, es` `-> s, se`
pub const XX = hp("XX", &.{}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .s, .es }, &.{ .s, .se } });
/// `IN`: `-> e, s` `<- e, ee, se`
pub const IN = hp("IN", &.{}, &.{}, &.{ &.{ .e, .s }, &.{ .e, .ee, .se } });
/// `IK`: the initiator knows the responder's static key in advance and
/// transmits its own static key immediately (encrypted) in the first
/// message; the responder authenticates the initiator by the end of its
/// own first (and only) reply message.
/// pre: `<- s` then `-> e, es, s, ss` `<- e, ee, se`
pub const IK = hp("IK", &.{}, &.{.s}, &.{ &.{ .e, .es, .s, .ss }, &.{ .e, .ee, .se } });
/// `IX`: `-> e, s` `<- e, ee, se, s, es`
pub const IX = hp("IX", &.{}, &.{}, &.{ &.{ .e, .s }, &.{ .e, .ee, .se, .s, .es } });

// Deferred (§7.6): a DH moved to a later message (the "1" marks which
// side's authentication is deferred).

pub const NK1 = hp("NK1", &.{}, &.{.s}, &.{ &.{.e}, &.{ .e, .ee, .es } });
pub const NX1 = hp("NX1", &.{}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .s }, &.{.es} });
pub const X1N = hp("X1N", &.{}, &.{}, &.{ &.{.e}, &.{ .e, .ee }, &.{.s}, &.{.se} });
pub const X1K = hp("X1K", &.{}, &.{.s}, &.{ &.{ .e, .es }, &.{ .e, .ee }, &.{.s}, &.{.se} });
pub const XK1 = hp("XK1", &.{}, &.{.s}, &.{ &.{.e}, &.{ .e, .ee, .es }, &.{ .s, .se } });
pub const X1K1 = hp("X1K1", &.{}, &.{.s}, &.{ &.{.e}, &.{ .e, .ee, .es }, &.{.s}, &.{.se} });
pub const X1X = hp("X1X", &.{}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .s, .es }, &.{.s}, &.{.se} });
pub const XX1 = hp("XX1", &.{}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .s }, &.{ .es, .s, .se } });
pub const X1X1 = hp("X1X1", &.{}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .s }, &.{ .es, .s }, &.{.se} });
pub const K1N = hp("K1N", &.{.s}, &.{}, &.{ &.{.e}, &.{ .e, .ee }, &.{.se} });
pub const K1K = hp("K1K", &.{.s}, &.{.s}, &.{ &.{ .e, .es }, &.{ .e, .ee }, &.{.se} });
pub const KK1 = hp("KK1", &.{.s}, &.{.s}, &.{ &.{.e}, &.{ .e, .ee, .se, .es } });
pub const K1K1 = hp("K1K1", &.{.s}, &.{.s}, &.{ &.{.e}, &.{ .e, .ee, .es }, &.{.se} });
pub const K1X = hp("K1X", &.{.s}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .s, .es }, &.{.se} });
pub const KX1 = hp("KX1", &.{.s}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .se, .s }, &.{.es} });
pub const K1X1 = hp("K1X1", &.{.s}, &.{}, &.{ &.{.e}, &.{ .e, .ee, .s }, &.{ .se, .es } });
pub const I1N = hp("I1N", &.{}, &.{}, &.{ &.{ .e, .s }, &.{ .e, .ee }, &.{.se} });
pub const I1K = hp("I1K", &.{}, &.{.s}, &.{ &.{ .e, .es, .s }, &.{ .e, .ee }, &.{.se} });
pub const IK1 = hp("IK1", &.{}, &.{.s}, &.{ &.{ .e, .s }, &.{ .e, .ee, .se, .es } });
pub const I1K1 = hp("I1K1", &.{}, &.{.s}, &.{ &.{ .e, .s }, &.{ .e, .ee, .es }, &.{.se} });
pub const I1X = hp("I1X", &.{}, &.{}, &.{ &.{ .e, .s }, &.{ .e, .ee, .s, .es }, &.{.se} });
pub const IX1 = hp("IX1", &.{}, &.{}, &.{ &.{ .e, .s }, &.{ .e, .ee, .se, .s }, &.{.es} });
pub const I1X1 = hp("I1X1", &.{}, &.{}, &.{ &.{ .e, .s }, &.{ .e, .ee, .s }, &.{ .se, .es } });

/// Every named base pattern, for lookup by name.
pub const catalog = [_]HandshakePattern{
    N,    K,   X,   NN,  NK,   NX,   KN,  KK,   KX,   XN,  XK,  XX,  IN,   IK,  IX,
    NK1,  NX1, X1N, X1K, XK1,  X1K1, X1X, XX1,  X1X1, K1N, K1K, KK1, K1K1, K1X, KX1,
    K1X1, I1N, I1K, IK1, I1K1, I1X,  IX1, I1X1,
};

/// The base pattern called `name` (case-sensitive, as the spec spells it).
pub fn byName(name: []const u8) ?HandshakePattern {
    for (catalog) |p| if (std.mem.eql(u8, p.name, name)) return p;
    return null;
}

// ── PSK modifiers (spec §9.2) ────────────────────────────────────────────

/// Most handshake messages a supported pattern has (the deferred ones reach
/// four), and most tokens one message can carry once PSKs are added.
pub const max_messages = 4;
pub const max_tokens = 8;
/// Longest pattern name a `Storage` holds (`X1X1psk0+psk1+psk2+psk3+psk4`).
pub const max_name_len = 32;

pub const ParseError = error{
    /// Not a catalog name, or the modifier list is not `psk<n>[+psk<n>…]`.
    UnknownPattern,
    /// `psk<n>` with `n` beyond the pattern's message count, or the same
    /// position twice.
    InvalidModifier,
    /// `fallback` (spec §10.2) and other modifiers this module does not
    /// implement.
    UnsupportedModifier,
};

/// Backing store for a pattern built at run time: `HandshakePattern` holds
/// slices, so they have to point somewhere that outlives it. Keep the
/// `Storage` alive (and unmoved) while the pattern is in use.
pub const Storage = struct {
    name_buf: [max_name_len]u8 = undefined,
    tokens: [max_messages][max_tokens]Token = undefined,
    slices: [max_messages][]const Token = undefined,

    /// `base` with a `psk` token at each of `positions` (spec §9.2:
    /// `psk0` first in the first message, `pskN` last in message N),
    /// named `base.name ++ "psk<n>+…"`.
    pub fn applyPsk(self: *Storage, base: HandshakePattern, positions: []const u8) ParseError!HandshakePattern {
        const n = base.message_patterns.len;
        if (n > max_messages) return error.InvalidModifier;
        var w: std.Io.Writer = .fixed(&self.name_buf);
        w.writeAll(base.name) catch return error.InvalidModifier;
        for (positions, 0..) |pos, i| {
            if (pos > n) return error.InvalidModifier;
            for (positions[0..i]) |prev| if (prev == pos) return error.InvalidModifier;
            w.print("{s}psk{d}", .{ if (i == 0) "" else "+", pos }) catch return error.InvalidModifier;
        }
        for (base.message_patterns, 0..) |mp, m| {
            var len: usize = 0;
            const front = m == 0 and std.mem.indexOfScalar(u8, positions, 0) != null;
            const back = std.mem.indexOfScalar(u8, positions, @intCast(m + 1)) != null;
            if (mp.len + @intFromBool(front) + @intFromBool(back) > max_tokens) return error.InvalidModifier;
            if (front) {
                self.tokens[m][len] = .psk;
                len += 1;
            }
            @memcpy(self.tokens[m][len..][0..mp.len], mp);
            len += mp.len;
            if (back) {
                self.tokens[m][len] = .psk;
                len += 1;
            }
            self.slices[m] = self.tokens[m][0..len];
        }
        return .{
            .name = w.buffered(),
            .pre_message_initiator = base.pre_message_initiator,
            .pre_message_responder = base.pre_message_responder,
            .message_patterns = self.slices[0..n],
        };
    }

    /// The pattern a spec name denotes: a catalog name optionally followed
    /// by PSK modifiers, `"XX"`, `"XXpsk3"`, `"NNpsk0+psk2"`.
    pub fn parse(self: *Storage, name: []const u8) ParseError!HandshakePattern {
        // The base name is the catalog name followed by nothing or by a
        // modifier (which starts lower-case). At most one catalog name
        // qualifies: where one name extends another (`K`, `KK`, `KK1`) the
        // extension starts with an upper-case letter or a digit.
        const base = for (catalog) |p| {
            if (!std.mem.startsWith(u8, name, p.name)) continue;
            const rest = name[p.name.len..];
            if (rest.len == 0 or std.ascii.isLower(rest[0])) break p;
        } else return error.UnknownPattern;
        const mods = name[base.name.len..];
        if (mods.len == 0) return base;
        var positions: [max_messages + 1]u8 = undefined;
        var np: usize = 0;
        var it = std.mem.splitScalar(u8, mods, '+');
        while (it.next()) |m| {
            // Any other lower-case modifier (`fallback`, §10.2) is
            // UnsupportedModifier.
            if (!std.mem.startsWith(u8, m, "psk") or m.len != 4 or !std.ascii.isDigit(m[3]))
                return if (m.len != 0 and std.ascii.isLower(m[0])) error.UnsupportedModifier else error.UnknownPattern;
            if (np == positions.len) return error.InvalidModifier;
            positions[np] = m[3] - '0';
            np += 1;
        }
        return self.applyPsk(base, positions[0..np]);
    }
};

/// `base` with PSK modifiers, built at comptime: `withPsk(XX, &.{3})` is
/// `XXpsk3`.
pub fn withPsk(comptime base: HandshakePattern, comptime positions: []const u8) HandshakePattern {
    return comptime buildWithPsk(base, positions);
}

fn buildWithPsk(comptime base: HandshakePattern, comptime positions: []const u8) HandshakePattern {
    var st: Storage = .{};
    const p = st.applyPsk(base, positions) catch |e| @compileError("noise.withPsk: " ++ @errorName(e));
    var msgs: [p.message_patterns.len][]const Token = undefined;
    for (p.message_patterns, 0..) |mp, i| {
        const frozen = mp[0..mp.len].*;
        msgs[i] = &frozen;
    }
    const name = p.name[0..p.name.len].*;
    const frozen_msgs = msgs;
    return .{
        .name = &name,
        .pre_message_initiator = base.pre_message_initiator,
        .pre_message_responder = base.pre_message_responder,
        .message_patterns = &frozen_msgs,
    };
}

/// A full protocol name split into its parts (spec §8):
/// `Noise_<pattern>_<dh>_<cipher>_<hash>`.
pub const ProtocolName = struct {
    pattern: HandshakePattern,
    dh: []const u8,
    cipher: []const u8,
    hash: []const u8,
};

/// Split and resolve `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`. The pattern
/// borrows `storage`; the three algorithm names borrow `name` and are not
/// checked against any suite (`Suite.matches` does that).
pub fn parseProtocolName(storage: *Storage, name: []const u8) ParseError!ProtocolName {
    var it = std.mem.splitScalar(u8, name, '_');
    const prefix = it.next() orelse return error.UnknownPattern;
    if (!std.mem.eql(u8, prefix, "Noise")) return error.UnknownPattern;
    const pat = it.next() orelse return error.UnknownPattern;
    const dh = it.next() orelse return error.UnknownPattern;
    const cipher = it.next() orelse return error.UnknownPattern;
    const hash = it.next() orelse return error.UnknownPattern;
    if (it.next() != null) return error.UnknownPattern;
    return .{ .pattern = try storage.parse(pat), .dh = dh, .cipher = cipher, .hash = hash };
}

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

test "catalog: every pattern's name matches its own const identifier, and names are unique" {
    inline for (@typeInfo(@This()).@"struct".decls) |d| {
        const v = @field(@This(), d.name);
        if (@TypeOf(v) == HandshakePattern) try std.testing.expectEqualStrings(d.name, v.name);
    }
    try std.testing.expectEqual(@as(usize, 38), catalog.len);
    for (catalog, 0..) |a, i| for (catalog[i + 1 ..]) |b| try std.testing.expect(!std.mem.eql(u8, a.name, b.name));
}

test "psk modifiers: placement per spec §9.2, names, refusals" {
    // §9.2: psk0 opens the first message, pskN closes message N.
    const xx3 = withPsk(XX, &.{3});
    try std.testing.expectEqualStrings("XXpsk3", xx3.name);
    try std.testing.expectEqualSlices(Token, &.{ .s, .se, .psk }, xx3.message_patterns[2]);
    try std.testing.expectEqualSlices(Token, &.{.e}, xx3.message_patterns[0]);
    const nn02 = withPsk(NN, &.{ 0, 2 });
    try std.testing.expectEqualStrings("NNpsk0+psk2", nn02.name);
    try std.testing.expectEqualSlices(Token, &.{ .psk, .e }, nn02.message_patterns[0]);
    try std.testing.expectEqualSlices(Token, &.{ .e, .ee, .psk }, nn02.message_patterns[1]);

    var st: Storage = .{};
    const p = try st.parse("NNpsk0+psk2");
    try std.testing.expectEqualStrings("NNpsk0+psk2", p.name);
    try std.testing.expectEqualSlices(Token, &.{ .psk, .e }, p.message_patterns[0]);
    // Longest catalog prefix: "KK1psk..." is KK1, not KK or K.
    try std.testing.expectEqualStrings("KK1", (try st.parse("KK1")).name);
    try std.testing.expectEqual(@as(usize, 2), (try st.parse("KK1psk2")).message_patterns.len);
    try std.testing.expectEqualStrings("K", (try st.parse("K")).name);
    try std.testing.expectError(error.InvalidModifier, st.parse("NNpsk3")); // NN has 2 messages
    try std.testing.expectError(error.InvalidModifier, st.parse("NNpsk1+psk1"));
    try std.testing.expectError(error.UnsupportedModifier, st.parse("XXfallback"));
    try std.testing.expectError(error.UnsupportedModifier, st.parse("XXfallback+psk0"));
    try std.testing.expectError(error.UnknownPattern, st.parse("QQ"));
    try std.testing.expectError(error.UnknownPattern, st.parse(""));
    try std.testing.expectError(error.UnsupportedModifier, st.parse("XXpsk"));
    try std.testing.expectError(error.UnsupportedModifier, st.parse("XXpsk12"));
    try std.testing.expectError(error.UnknownPattern, st.parse("XX+psk1"));
}

test "parseProtocolName: the spec §8 examples" {
    var st: Storage = .{};
    const a = try parseProtocolName(&st, "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s");
    try std.testing.expectEqualStrings("XXpsk3", a.pattern.name);
    try std.testing.expectEqualStrings("25519", a.dh);
    try std.testing.expectEqualStrings("ChaChaPoly", a.cipher);
    try std.testing.expectEqualStrings("BLAKE2s", a.hash);
    const b = try parseProtocolName(&st, "Noise_N_448_AESGCM_SHA512");
    try std.testing.expectEqualStrings("N", b.pattern.name);
    try std.testing.expectEqualStrings("448", b.dh);
    for ([_][]const u8{ "", "Noise", "Noise_XX", "Noise_XX_25519_ChaChaPoly", "Noise_XX_25519_ChaChaPoly_SHA256_x", "noise_XX_25519_ChaChaPoly_SHA256", "NoisePSK_XX_25519_ChaChaPoly_SHA256" }) |n|
        try std.testing.expectError(error.UnknownPattern, parseProtocolName(&st, n));
}
