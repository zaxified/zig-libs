// SPDX-License-Identifier: MIT

//! 48-bit MAC (EUI-48) address helper shared by the l2disco codecs.
//!
//! Deliberately small: a value type over `[6]u8` with parse/format for the
//! canonical `aa:bb:cc:dd:ee:ff` text form (`-` accepted as a separator on
//! parse), plus the handful of predicates the discovery protocols care
//! about (broadcast / multicast / locally-administered).

const std = @import("std");

/// A 48-bit IEEE 802 MAC address, stored in transmission (big-endian) order.
pub const Mac = struct {
    octets: [6]u8,

    pub const zero: Mac = .{ .octets = @splat(0) };
    pub const broadcast: Mac = .{ .octets = @splat(0xff) };

    /// `aa:bb:cc:dd:ee:ff` (or `-`-separated); two hex digits per octet,
    /// case-insensitive. Returns null on any deviation.
    pub fn parse(text: []const u8) ?Mac {
        if (text.len != 17) return null;
        var m: Mac = undefined;
        var i: usize = 0;
        while (i < 6) : (i += 1) {
            const off = i * 3;
            if (i != 0) {
                const sep = text[off - 1];
                if (sep != ':' and sep != '-') return null;
            }
            const hi = hexNibble(text[off]) orelse return null;
            const lo = hexNibble(text[off + 1]) orelse return null;
            m.octets[i] = (@as(u8, hi) << 4) | lo;
        }
        return m;
    }

    pub const text_len = 17;

    /// Formats as lowercase `aa:bb:cc:dd:ee:ff` into `buf` (needs
    /// `text_len` bytes); returns the written slice.
    pub fn format(m: Mac, buf: []u8) []const u8 {
        std.debug.assert(buf.len >= text_len);
        const digits = "0123456789abcdef";
        for (m.octets, 0..) |b, i| {
            const off = i * 3;
            if (i != 0) buf[off - 1] = ':';
            buf[off] = digits[b >> 4];
            buf[off + 1] = digits[b & 0xf];
        }
        return buf[0..text_len];
    }

    pub fn eql(a: Mac, b: Mac) bool {
        return std.mem.eql(u8, &a.octets, &b.octets);
    }

    pub fn isBroadcast(m: Mac) bool {
        return m.eql(broadcast);
    }

    /// Group (multicast) bit — LSB of the first octet.
    pub fn isMulticast(m: Mac) bool {
        return m.octets[0] & 0x01 != 0;
    }

    /// Locally-administered bit — second-LSB of the first octet.
    pub fn isLocallyAdministered(m: Mac) bool {
        return m.octets[0] & 0x02 != 0;
    }

    pub fn isZero(m: Mac) bool {
        return m.eql(zero);
    }
};

fn hexNibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

test "Mac parse + format round-trip" {
    const m = Mac.parse("00:1B:21:3c:9d:F8").?;
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x1b, 0x21, 0x3c, 0x9d, 0xf8 }, &m.octets);

    var buf: [Mac.text_len]u8 = undefined;
    try std.testing.expectEqualStrings("00:1b:21:3c:9d:f8", m.format(&buf));

    // Dash separator accepted.
    const d = Mac.parse("00-1b-21-3c-9d-f8").?;
    try std.testing.expect(m.eql(d));
}

test "Mac parse rejects malformed input" {
    try std.testing.expectEqual(@as(?Mac, null), Mac.parse(""));
    try std.testing.expectEqual(@as(?Mac, null), Mac.parse("00:1b:21:3c:9d"));
    try std.testing.expectEqual(@as(?Mac, null), Mac.parse("00:1b:21:3c:9d:f"));
    try std.testing.expectEqual(@as(?Mac, null), Mac.parse("00:1b:21:3c:9d:fg"));
    try std.testing.expectEqual(@as(?Mac, null), Mac.parse("00.1b.21.3c.9d.f8"));
    try std.testing.expectEqual(@as(?Mac, null), Mac.parse("001b:21:3c:9d:f8x"));
}

test "Mac predicates" {
    try std.testing.expect(Mac.broadcast.isBroadcast());
    try std.testing.expect(Mac.broadcast.isMulticast());
    try std.testing.expect(Mac.zero.isZero());
    // LLDP nearest-bridge group address is multicast, not broadcast.
    const lldp_dst = Mac.parse("01:80:c2:00:00:0e").?;
    try std.testing.expect(lldp_dst.isMulticast());
    try std.testing.expect(!lldp_dst.isBroadcast());
    const laa = Mac.parse("02:00:00:00:00:01").?;
    try std.testing.expect(laa.isLocallyAdministered());
}
