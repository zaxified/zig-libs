// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GU, gu-a). Every test name ends with its finding
//! ID; report: ~/CML/20261029-panic-sweep/aescbc-sweep.report.md.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const Aes128 = std.crypto.core.aes.Aes128;

const max = std.math.maxInt(usize);

test "maxUpdateLen: a huge in_len saturates instead of overflowing (sweep AC-1)" {
    const key: [16]u8 = @splat(1);
    const iv: [16]u8 = @splat(2);
    var e = root.StreamEncryptor(Aes128, .pkcs7).init(&key, iv);
    var d = root.StreamDecryptor(Aes128, .pkcs7).init(&key, iv);
    try testing.expectEqual(max - 15, e.maxUpdateLen(max));
    try testing.expectEqual(max - 15, d.maxUpdateLen(max));
    // A buffered tail makes the sum overflow even for a smaller in_len.
    e.tail_len = 5;
    d.tail_len = 16;
    try testing.expectEqual(max - 15, e.maxUpdateLen(max - 2));
    try testing.expectEqual(max - 15, d.maxUpdateLen(max));
}

test "padded lengths: no wrap near the top of usize (sweep AC-2)" {
    try testing.expectEqual(max, root.paddedLenPkcs7(max));
    try testing.expectEqual(max, root.paddedLenPkcs7(max - 15));
    try testing.expectEqual(max, root.paddedLen(max - 3));
    try testing.expectEqual(max, root.paddedLenZero(max));
    try testing.expectEqual(max, root.paddedLenZero(max - 1));
    // Unchanged where it fits.
    try testing.expectEqual(@as(usize, 16), root.paddedLenPkcs7(0));
    try testing.expectEqual(@as(usize, 32), root.paddedLenPkcs7(16));
    try testing.expectEqual(@as(usize, 0), root.paddedLenZero(0));
    try testing.expectEqual(@as(usize, 16), root.paddedLenZero(1));
    try testing.expectEqual(@as(usize, 16), root.paddedLenZero(16));
    // A saturated length is "too big for any buffer", not a wrap to a small one.
    var small: [64]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, root.padPkcs7("x", small[0..0]));
    try testing.expect(root.paddedLenPkcs7(max) > small.len);
}

fn expectInPlace(comptime pad: anytype, msg_len: usize, msg_at: usize, out_at: usize) !void {
    // Reference: padding into separate storage.
    var msg: [20]u8 = undefined;
    for (msg[0..msg_len], 0..) |*b, i| b.* = @intCast(0x41 + i);
    var want: [48]u8 = @splat(0);
    const n_want = try pad(msg[0..msg_len], &want);

    var buf: [80]u8 = @splat(0);
    @memcpy(buf[msg_at..][0..msg_len], msg[0..msg_len]);
    const n = try pad(buf[msg_at..][0..msg_len], buf[out_at..]);
    try testing.expectEqual(n_want, n);
    try testing.expectEqualSlices(u8, want[0..n_want], buf[out_at..][0..n]);
}

fn padIso10126Fixed(msg: []const u8, out: []u8) error{BufferTooSmall}!usize {
    // The random fill sits in the non-final pad bytes only; compare lengths
    // and the message part through `expectInPlace`'s equality on a fixed seed.
    var prng = std.Random.DefaultPrng.init(7);
    return root.padIso10126(msg, out, prng.random());
}

test "pad*: out may alias msg, in place or shifted either way (sweep AC-3)" {
    inline for (.{ root.padPkcs7, root.padAnsiX923, root.padIso7816, root.padZero, padIso10126Fixed }) |pad| {
        for ([_]usize{ 0, 1, 5, 15, 16, 17 }) |len| {
            try expectInPlace(pad, len, 0, 0); // exact alias
            try expectInPlace(pad, len, 3, 0); // out before msg
            try expectInPlace(pad, len, 0, 3); // out after msg (overlapping)
        }
    }
}
