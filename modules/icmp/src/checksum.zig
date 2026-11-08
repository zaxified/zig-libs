// SPDX-License-Identifier: MIT

//! RFC 1071 internet checksum building blocks (ones'-complement sum of
//! big-endian 16-bit words, odd tail padded with a zero byte).
//!
//! `sum` accumulates in `u64`, so no input length can overflow it (a `u32`
//! accumulator overflows past 131074 bytes of `0xffff` words).

const std = @import("std");

/// Fold `x` into 16 bits by end-around carry.
fn fold(x: u64) u16 {
    var s = x;
    while (s >> 16 != 0) s = (s & 0xffff) + (s >> 16);
    return @intCast(s);
}

/// Ones'-complement sum of `bytes` added to `initial`, folded to 16 bits
/// (the result is always <= 0xffff). Chain calls by passing the previous
/// result as `initial`; an odd-length slice is padded with a zero byte, so
/// only the LAST slice of a chain may have odd length. Not complemented:
/// pass the final value to `finish`.
pub fn sum(bytes: []const u8, initial: u32) u32 {
    var s: u64 = initial;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) s += std.mem.readInt(u16, bytes[i..][0..2], .big);
    if (i < bytes.len) s += @as(u64, bytes[i]) << 8;
    return fold(s);
}

/// The checksum for a folded `sum`: fold again and complement. Verifying a
/// received message is `sum(msg, 0) == 0xffff` (equivalently `finish == 0`).
pub fn finish(s: u32) u16 {
    return ~fold(s);
}

/// RFC 1071 checksum over `bytes` in host byte order (store it big-endian).
pub fn checksum(bytes: []const u8) u16 {
    return finish(sum(bytes, 0));
}

test "sum/finish match known vectors and chain" {
    // RFC 1071 §3 example.
    const b = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    try std.testing.expectEqual(@as(u32, 0xddf2), sum(&b, 0));
    try std.testing.expectEqual(@as(u16, 0x220d), finish(sum(&b, 0)));
    try std.testing.expectEqual(finish(sum(b[4..], sum(b[0..4], 0))), checksum(&b));
    try std.testing.expectEqual(@as(u16, 0xffff), checksum(&.{}));
    try std.testing.expectEqual(@as(u16, 0xfeff), checksum(&.{0x01}));
}

test "sum does not overflow on a long all-ones input" {
    const big: [1 << 18]u8 = @splat(0xff);
    try std.testing.expectEqual(@as(u32, 0xffff), sum(&big, 0));
    try std.testing.expectEqual(@as(u16, 0), checksum(&big));
}
