// SPDX-License-Identifier: MIT

//! quic-crypto.version — the per-QUIC-version constants of the crypto seam:
//! RFC 9001 (v1) and RFC 9369 (v2) differ ONLY in the Initial salt, the four
//! HKDF labels, the Retry Integrity key/nonce and the two-bit long-header
//! packet-type codes. Everything else (AEADs, nonce, header-protection masks,
//! the `"tls13 "` HKDF prefix) is identical, so a `Version` is threaded into
//! the `*For` derivation functions and the Retry functions rather than forking
//! the module. The unsuffixed v1 entry points (`deriveInitialSecrets`,
//! `derivePacketKeys`, `advanceKeys`) are unchanged and mean `.v1`.
//!
//! Version NEGOTIATION (RFC 8999 / 9368), the version-information transport
//! parameter and choosing which version a packet belongs to are the
//! transport's job; this file only maps a decided version to constants.

const std = @import("std");

/// The QUIC versions this seam knows. The integer value is the on-wire
/// `Version` field of a long header.
pub const Version = enum(u32) {
    /// RFC 9000 / RFC 9001.
    v1 = 0x00000001,
    /// RFC 9369 §3.1.
    v2 = 0x6b3343cf,

    /// Map an on-wire Version field to a known version; `null` for anything
    /// else (including Version Negotiation's 0 and greased versions).
    pub fn fromWire(v: u32) ?Version {
        return switch (v) {
            0x00000001 => .v1,
            0x6b3343cf => .v2,
            else => null,
        };
    }

    /// The on-wire Version field value.
    pub fn wire(self: Version) u32 {
        return @intFromEnum(self);
    }

    /// HKDF-Extract salt for the Initial secret (RFC 9001 §5.2 / RFC 9369 §3.3.1).
    pub fn initialSalt(self: Version) *const [20]u8 {
        return switch (self) {
            .v1 => &initial_salt_v1,
            .v2 => &initial_salt_v2,
        };
    }

    /// The HKDF-Expand-Label labels (RFC 9001 §5.1/§6.1, RFC 9369 §3.3.2).
    pub fn labels(self: Version) Labels {
        return switch (self) {
            .v1 => .{ .key = "quic key", .iv = "quic iv", .hp = "quic hp", .ku = "quic ku" },
            .v2 => .{ .key = "quicv2 key", .iv = "quicv2 iv", .hp = "quicv2 hp", .ku = "quicv2 ku" },
        };
    }

    /// AES-128-GCM key of the Retry Integrity Tag (RFC 9001 §5.8 / RFC 9369 §3.3.3).
    pub fn retryKey(self: Version) *const [16]u8 {
        return switch (self) {
            .v1 => &retry_key_v1,
            .v2 => &retry_key_v2,
        };
    }

    /// AES-128-GCM nonce of the Retry Integrity Tag.
    pub fn retryNonce(self: Version) *const [12]u8 {
        return switch (self) {
            .v1 => &retry_nonce_v1,
            .v2 => &retry_nonce_v2,
        };
    }

    /// The 2-bit Long Packet Type field for `t` (RFC 9000 §17.2 for v1,
    /// RFC 9369 §3.2 for v2).
    pub fn longPacketTypeBits(self: Version, t: LongPacketType) u2 {
        return switch (self) {
            .v1 => switch (t) {
                .initial => 0b00,
                .zero_rtt => 0b01,
                .handshake => 0b10,
                .retry => 0b11,
            },
            .v2 => switch (t) {
                .retry => 0b00,
                .initial => 0b01,
                .zero_rtt => 0b10,
                .handshake => 0b11,
            },
        };
    }

    /// Inverse of `longPacketTypeBits` (total: every 2-bit value is a type).
    pub fn longPacketTypeFromBits(self: Version, bits: u2) LongPacketType {
        return switch (self) {
            .v1 => switch (bits) {
                0b00 => .initial,
                0b01 => .zero_rtt,
                0b10 => .handshake,
                0b11 => .retry,
            },
            .v2 => switch (bits) {
                0b00 => .retry,
                0b01 => .initial,
                0b10 => .zero_rtt,
                0b11 => .handshake,
            },
        };
    }
};

/// The four version-dependent HKDF-Expand-Label labels.
pub const Labels = struct {
    key: []const u8,
    iv: []const u8,
    hp: []const u8,
    ku: []const u8,
};

/// Long-header packet types that carry a 2-bit type code (RFC 9000 §17.2).
pub const LongPacketType = enum { initial, zero_rtt, handshake, retry };

/// RFC 9001 §5.2: the fixed QUIC v1 Initial salt.
pub const initial_salt_v1: [20]u8 = .{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

/// RFC 9369 §3.3.1: the QUIC v2 Initial salt (first 20 bytes of
/// sha256("QUICv2 salt")).
pub const initial_salt_v2: [20]u8 = .{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

/// RFC 9001 §5.8: Retry Integrity key / nonce, QUIC v1.
pub const retry_key_v1: [16]u8 = .{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
pub const retry_nonce_v1: [12]u8 = .{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

/// RFC 9369 §3.3.3: Retry Integrity key / nonce, QUIC v2.
pub const retry_key_v2: [16]u8 = .{
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
};
pub const retry_nonce_v2: [12]u8 = .{
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "salts: v1 = RFC 9001 §5.2, v2 = RFC 9369 §3.3.1 (sha256 of the RFC's phrase)" {
    try testing.expectEqualSlices(u8, &hexTo(20, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), Version.v1.initialSalt());
    try testing.expectEqualSlices(u8, &hexTo(20, "0dede3def700a6db819381be6e269dcbf9bd2ed9"), Version.v2.initialSalt());
    // RFC 9369 §3.3.1: "the first 20 bytes of the sha256sum of "QUICv2 salt"".
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("QUICv2 salt", &h, .{});
    try testing.expectEqualSlices(u8, h[0..20], Version.v2.initialSalt());
}

test "wire values: v1 = 1, v2 = sha256(\"QUICv2 version number\")[0..4] (RFC 9369 §3.1)" {
    try testing.expectEqual(@as(u32, 1), Version.v1.wire());
    try testing.expectEqual(@as(u32, 0x6b3343cf), Version.v2.wire());
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("QUICv2 version number", &h, .{});
    try testing.expectEqual(std.mem.readInt(u32, h[0..4], .big), Version.v2.wire());
    try testing.expectEqual(Version.v1, Version.fromWire(1).?);
    try testing.expectEqual(Version.v2, Version.fromWire(0x6b3343cf).?);
    try testing.expect(Version.fromWire(0) == null); // Version Negotiation
    try testing.expect(Version.fromWire(0x709a50c4) == null); // v2 draft codepoint: not v2
}

test "Retry key/nonce constants are what the RFCs' secrets derive with the version's labels" {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    // RFC 9001 §5.8 secret.
    const s1 = hexTo(32, "d9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e");
    try testing.expectEqualSlices(u8, Version.v1.retryKey(), &std.crypto.tls.hkdfExpandLabel(Hkdf, s1, "quic key", "", 16));
    try testing.expectEqualSlices(u8, Version.v1.retryNonce(), &std.crypto.tls.hkdfExpandLabel(Hkdf, s1, "quic iv", "", 12));
    // RFC 9369 §3.3.3 secret = sha256("QUICv2 retry secret").
    const s2 = hexTo(32, "c4dd2484d681aefa4ff4d69c2c20299984a765a5d3c31982f38fc74162155e9f");
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("QUICv2 retry secret", &h, .{});
    try testing.expectEqualSlices(u8, &s2, &h);
    try testing.expectEqualSlices(u8, Version.v2.retryKey(), &std.crypto.tls.hkdfExpandLabel(Hkdf, s2, "quicv2 key", "", 16));
    try testing.expectEqualSlices(u8, Version.v2.retryNonce(), &std.crypto.tls.hkdfExpandLabel(Hkdf, s2, "quicv2 iv", "", 12));
    // And the published values themselves.
    try testing.expectEqualSlices(u8, &hexTo(16, "8fb4b01b56ac48e260fbcbcead7ccc92"), Version.v2.retryKey());
    try testing.expectEqualSlices(u8, &hexTo(12, "d86969bc2d7c6d9990efb04a"), Version.v2.retryNonce());
}

test "labels: v1 quic *, v2 quicv2 * (RFC 9369 §3.3.2)" {
    const l1 = Version.v1.labels();
    try testing.expectEqualStrings("quic key", l1.key);
    try testing.expectEqualStrings("quic iv", l1.iv);
    try testing.expectEqualStrings("quic hp", l1.hp);
    try testing.expectEqualStrings("quic ku", l1.ku);
    const l2 = Version.v2.labels();
    try testing.expectEqualStrings("quicv2 key", l2.key);
    try testing.expectEqualStrings("quicv2 iv", l2.iv);
    try testing.expectEqualStrings("quicv2 hp", l2.hp);
    try testing.expectEqualStrings("quicv2 ku", l2.ku);
}

test "long packet types: v1 RFC 9000 §17.2, v2 RFC 9369 §3.2; bits <-> type round-trips" {
    try testing.expectEqual(@as(u2, 0b00), Version.v1.longPacketTypeBits(.initial));
    try testing.expectEqual(@as(u2, 0b01), Version.v1.longPacketTypeBits(.zero_rtt));
    try testing.expectEqual(@as(u2, 0b10), Version.v1.longPacketTypeBits(.handshake));
    try testing.expectEqual(@as(u2, 0b11), Version.v1.longPacketTypeBits(.retry));
    try testing.expectEqual(@as(u2, 0b01), Version.v2.longPacketTypeBits(.initial));
    try testing.expectEqual(@as(u2, 0b10), Version.v2.longPacketTypeBits(.zero_rtt));
    try testing.expectEqual(@as(u2, 0b11), Version.v2.longPacketTypeBits(.handshake));
    try testing.expectEqual(@as(u2, 0b00), Version.v2.longPacketTypeBits(.retry));
    for ([_]Version{ .v1, .v2 }) |v| {
        for (std.enums.values(LongPacketType)) |t| {
            try testing.expectEqual(t, v.longPacketTypeFromBits(v.longPacketTypeBits(t)));
        }
    }
}
