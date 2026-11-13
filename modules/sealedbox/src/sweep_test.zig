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

// ── mutation-run gaps, 2026-11-13 (see CHANGELOG) ───────────────────────────

test "open: an `out` buffer of the wrong size is InvalidCiphertext, in both directions" {
    // `sealed.len != out.len + overhead` was a `>` in a surviving mutant: an
    // oversized `out` got past the guard and reached `decrypt`'s length assert
    // (a panic in ReleaseSafe, an out-of-bounds copy in ReleaseFast).
    const io = std.testing.io;
    const kp = sb.KeyPair.generate(io);
    var sealed: [10 + sb.overhead]u8 = undefined;
    try sb.seal(io, &sealed, "0123456789", kp.public_key);
    var small: [9]u8 = undefined;
    try std.testing.expectError(error.InvalidCiphertext, sb.open(&small, &sealed, &kp));
    var large: [11]u8 = undefined;
    try std.testing.expectError(error.InvalidCiphertext, sb.open(&large, &sealed, &kp));
    var exact: [10]u8 = undefined;
    try sb.open(&exact, &sealed, &kp);
    try std.testing.expectEqualStrings("0123456789", &exact);
}

test "sealAlloc and openAlloc free their buffer on every error (no leak under the testing allocator)" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const kp = sb.KeyPair.generate(io);
    // seal fails (all-zero recipient key is a low-order point) after the allocation.
    const zero: [sb.public_length]u8 = @splat(0);
    try std.testing.expectError(error.IdentityElement, sb.sealAlloc(gpa, io, "abc", zero));
    // open fails (forged tag) after the allocation.
    const sealed = try sb.sealAlloc(gpa, io, "abc", kp.public_key);
    defer gpa.free(sealed);
    const forged = try gpa.dupe(u8, sealed);
    defer gpa.free(forged);
    forged[sb.public_length] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, sb.openAlloc(gpa, forged, &kp));
}

test "parseSecretKeyBase64: a 44-char text with `==` (31 bytes) is rejected and `out` is zeroed" {
    // 44 characters pass the length guard, b64ct decodes them to 31 bytes into
    // `out`, and only the `got.len` check refuses them.
    var raw: [31]u8 = undefined;
    for (&raw, 0..) |*b, i| b.* = @truncate(i + 1);
    var text: [sb.base64_sk_len]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&text, &raw);
    try std.testing.expectEqualSlices(u8, "==", text[42..]);
    var out: [sb.secret_length]u8 = undefined;
    @memset(&out, 0xaa);
    try std.testing.expectError(error.InvalidKeyEncoding, sb.parseSecretKeyBase64(&out, &text));
    try std.testing.expectEqualSlices(u8, &@as([sb.secret_length]u8, @splat(0)), &out);
}
