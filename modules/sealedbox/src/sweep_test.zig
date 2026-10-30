// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GP). Each test names the finding it kills.

const std = @import("std");
const sb = @import("root.zig");

test "sealedLen saturates instead of wrapping (sweep SB-1)" {
    try std.testing.expectEqual(@as(usize, sb.overhead), sb.sealedLen(0));
    try std.testing.expectEqual(@as(usize, 10 + sb.overhead), sb.sealedLen(10));
    try std.testing.expectEqual(std.math.maxInt(usize), sb.sealedLen(std.math.maxInt(usize)));
    try std.testing.expectEqual(std.math.maxInt(usize), sb.sealedLen(std.math.maxInt(usize) - sb.overhead + 1));
    // A wrapped length would look like a tiny, valid output size to `seal`.
    const kp = sb.KeyPair.generate(std.testing.io);
    var out: [8]u8 = undefined;
    try std.testing.expectError(error.InvalidBufferSize, sb.seal(std.testing.io, &out, "", kp.public_key));
}

test "open: every ciphertext shorter than the overhead, and a low-order ephemeral key, are errors (sweep SB-clean)" {
    const kp = sb.KeyPair.generate(std.testing.io);
    var out: [0]u8 = undefined;
    for (0..sb.overhead) |len| {
        var buf: [sb.overhead]u8 = @splat(0);
        try std.testing.expectError(error.InvalidCiphertext, sb.open(&out, buf[0..len], &kp));
    }
    // All-zero ephemeral key (a low-order point) with an overhead-sized box.
    const zero: [sb.overhead]u8 = @splat(0);
    if (sb.open(&out, &zero, &kp)) |_| return error.TestUnexpectedResult else |e| switch (e) {
        error.IdentityElement, error.WeakPublicKey, error.AuthenticationFailed => {},
        else => return e,
    }
}
