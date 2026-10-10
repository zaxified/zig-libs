// SPDX-License-Identifier: MIT

//! b64ct — constant-time padded standard base64 ENCODING (RFC 4648 §4), for
//! the one secret this module writes as base64: the AUTH PLAIN / AUTH LOGIN
//! credential (the password).
//!
//! `std.base64.standard.Encoder` looks every 6-bit group up in its alphabet
//! table — a load address indexed by the secret (memcheck: `ctgrind.sh smtp`,
//! target `auth`, 2026-10-10). Here every character is computed
//! arithmetically: each range decision is a borrow turned into a mask, never
//! a branch or an index. Output is byte-identical to std's. Decoding is not
//! needed for secrets (server challenges are public) and stays std's.

const std = @import("std");

/// Encoded length of `n` octets, with `=` padding (std's `calcSize`).
pub fn encodedLen(n: usize) usize {
    return (n + 2) / 3 * 4;
}

/// 0xff when `a >= b` (both < 256), else 0 — from the borrow of `b-1 - a`.
inline fn ge(a: u8, b: u8) u8 {
    return @truncate((@as(u16, b) -% 1 -% a) >> 8);
}

/// One sextet (0..63) to its alphabet character, branch- and table-free.
inline fn sextet(v: u8) u8 {
    var c: u8 = v +% 'A';
    c +%= ge(v, 26) & 6; // 'a' - 'A' - 26
    c +%= ge(v, 52) & @as(u8, @bitCast(@as(i8, -75))); // '0' - 'a' - 26
    c +%= ge(v, 62) & @as(u8, @bitCast(@as(i8, -15))); // '+' - '0' - 10
    c +%= ge(v, 63) & 3; // '/' - '+'
    return c;
}

/// Encodes `src` into the front of `out` (`out.len >= encodedLen(src.len)`)
/// and returns the written slice.
pub fn encode(out: []u8, src: []const u8) []const u8 {
    const len = encodedLen(src.len);
    std.debug.assert(out.len >= len);
    var o: usize = 0;
    var i: usize = 0;
    while (i + 3 <= src.len) : (i += 3) {
        const a = src[i];
        const b = src[i + 1];
        const c = src[i + 2];
        out[o] = sextet(a >> 2);
        out[o + 1] = sextet(((a & 3) << 4) | (b >> 4));
        out[o + 2] = sextet(((b & 15) << 2) | (c >> 6));
        out[o + 3] = sextet(c & 63);
        o += 4;
    }
    switch (src.len - i) {
        0 => {},
        1 => {
            const a = src[i];
            out[o] = sextet(a >> 2);
            out[o + 1] = sextet((a & 3) << 4);
            out[o + 2] = '=';
            out[o + 3] = '=';
        },
        2 => {
            const a = src[i];
            const b = src[i + 1];
            out[o] = sextet(a >> 2);
            out[o + 1] = sextet(((a & 3) << 4) | (b >> 4));
            out[o + 2] = sextet((b & 15) << 2);
            out[o + 3] = '=';
        },
        else => unreachable,
    }
    return out[0..len];
}

test "encode is byte-identical to std for every length 0..300 and every byte value" {
    var src: [300]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 157 +% 11);
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    const codec = std.base64.standard.Encoder;
    for ([_][]const u8{ &src, &all }) |s| {
        for (0..s.len + 1) |n| {
            var ours: [400]u8 = undefined;
            var theirs: [400]u8 = undefined;
            try std.testing.expectEqual(codec.calcSize(n), encodedLen(n));
            try std.testing.expectEqualStrings(codec.encode(&theirs, s[0..n]), encode(&ours, s[0..n]));
        }
    }
}
