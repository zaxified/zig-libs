// SPDX-License-Identifier: MIT

//! No-panic sweep (wave GP) regression tests.

const std = @import("std");
const root = @import("root.zig");

test "counterWouldWrap / counterWouldWrap64 are total on huge lengths (sweep CP-1)" {
    const top = std.math.maxInt(usize);
    // `len + 63` overflowed here (panic in safe builds, wrap -> "fits" in ReleaseFast).
    try std.testing.expect(root.counterWouldWrap(top, 0));
    try std.testing.expect(root.counterWouldWrap(top - 62, 0));
    try std.testing.expect(!root.counterWouldWrap64(top, 0)); // 2^58 blocks fit a 64-bit counter
    try std.testing.expect(root.counterWouldWrap64(top, std.math.maxInt(u64)));
    // boundaries unchanged
    try std.testing.expect(!root.counterWouldWrap(0, std.math.maxInt(u32)));
    try std.testing.expect(!root.counterWouldWrap(64, std.math.maxInt(u32)));
    try std.testing.expect(root.counterWouldWrap(65, std.math.maxInt(u32)));
    try std.testing.expect(!root.counterWouldWrap(64 * (1 << 32), 0));
    try std.testing.expect(root.counterWouldWrap(64 * (1 << 32) + 1, 0));
}

test "decrypt refuses a ciphertext beyond the block counter before the MAC (sweep REV-CP-1)" {
    const refuse = root.test_hooks.refuse;
    var m: [16]u8 = @splat(0xaa);
    // 64 * (2^32 - 1) bytes is the last length from counter 1; one more wraps.
    try std.testing.expect(!refuse(&m, 64 * ((1 << 32) - 1)));
    try std.testing.expectEqual(@as(u8, 0xaa), m[0]);
    try std.testing.expect(refuse(&m, 64 * ((1 << 32) - 1) + 1));
    for (m) |b| try std.testing.expectEqual(@as(u8, 0), b);
    try std.testing.expect(refuse(&m, std.math.maxInt(usize)));
}

test "AEAD overlap: in place, m before c (decrypt) and c before m (encrypt) match the disjoint result (sweep REV-CP-2)" {
    const A = root.ChaCha20Poly1305;
    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i * 7 + 1);
    for (&nonce, 0..) |*b, i| b.* = @intCast(i + 3);
    var ad: [40]u8 = undefined;
    for (&ad, 0..) |*b, i| b.* = @intCast(i * 3);
    const lens = [_]usize{ 100, 129, 300, 600, 1100 }; // + 40 AD > 128: wide path
    for (lens) |n| {
        var pt: [1100]u8 = undefined;
        for (pt[0..n], 0..) |*b, i| b.* = @intCast((i * 31 + 5) & 0xff);
        var ref_c: [1100]u8 = undefined;
        var ref_tag: [16]u8 = undefined;
        A.encrypt(ref_c[0..n], &ref_tag, pt[0..n], &ad, nonce, key);
        for ([_]usize{ 0, 1, 7, 63, 64, 65, 200 }) |d| {
            // decrypt with m = c - d inside one buffer
            var buf: [1100 + 200]u8 = undefined;
            @memcpy(buf[d..][0..n], ref_c[0..n]);
            const c: []const u8 = buf[d..][0..n];
            const m: []u8 = buf[0..n];
            try A.decrypt(m, c, ref_tag, &ad, nonce, key);
            try std.testing.expectEqualSlices(u8, pt[0..n], buf[0..n]);
            // encrypt with c = m - d inside one buffer
            @memcpy(buf[d..][0..n], pt[0..n]);
            var tag: [16]u8 = undefined;
            A.encrypt(buf[0..n], &tag, buf[d..][0..n], &ad, nonce, key);
            try std.testing.expectEqualSlices(u8, ref_c[0..n], buf[0..n]);
            try std.testing.expectEqualSlices(u8, &ref_tag, &tag);
        }
    }
}
