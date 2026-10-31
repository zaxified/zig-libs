// SPDX-License-Identifier: MIT
//! No-panic sweep tests for stun, wave GV. Findings ST-1 .. ST-3, see
//! ~/CML/20261029-panic-sweep/stun-sweep.report.md.
const std = @import("std");
const testing = std.testing;
const stun = @import("root.zig");

const big = 70_000; // a caller buffer larger than the 16-bit attribute region

fn newBuilder(buf: []u8) !stun.Builder {
    return stun.Builder.init(buf, .request, .binding, @as(stun.TransactionId, @splat(7)));
}

test "addAttribute: a value over 65535 bytes is ValueTooLong, not a trap (sweep ST-1)" {
    const buf = try testing.allocator.alloc(u8, 2 * big);
    defer testing.allocator.free(buf);
    const value = try testing.allocator.alloc(u8, 65_536);
    defer testing.allocator.free(value);
    @memset(value, 'x');
    var b = try newBuilder(buf);
    try testing.expectError(error.ValueTooLong, b.addAttribute(0x8022, value));
    // Nothing was written: the message is still the bare header.
    try testing.expectEqual(@as(usize, stun.header_len), b.finish().len);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, buf[2..4], .big));
}

test "addAttribute: the attribute region stops at the 16-bit length field (sweep ST-2)" {
    const buf = try testing.allocator.alloc(u8, big);
    defer testing.allocator.free(buf);
    const value = try testing.allocator.alloc(u8, 65_528);
    defer testing.allocator.free(value);
    @memset(value, 'x');
    var b = try newBuilder(buf);
    try b.addAttribute(0x8022, value); // region = 4 + 65528 = 65532
    try testing.expectEqual(@as(u16, 65_532), std.mem.readInt(u16, buf[2..4], .big));
    // 65532 + 8 would be 65540: refused, message unchanged.
    try testing.expectError(error.BufferTooSmall, b.addAttribute(0x8022, "abcd"));
    try testing.expectEqual(@as(usize, stun.header_len + 65_532), b.finish().len);
    try testing.expectEqual(@as(u16, 65_532), std.mem.readInt(u16, buf[2..4], .big));
    // The result still decodes.
    const m = try stun.decode(b.finish());
    try testing.expectEqual(@as(u16, 65_532), m.length);
}

test "addMessageIntegrity: refused when the 24 bytes would outgrow the length field (sweep ST-2)" {
    const buf = try testing.allocator.alloc(u8, big);
    defer testing.allocator.free(buf);
    const value = try testing.allocator.alloc(u8, 65_512);
    defer testing.allocator.free(value);
    @memset(value, 'x');
    var b = try newBuilder(buf);
    try b.addAttribute(0x8022, value); // region = 65516; +24 = 65540
    try testing.expectError(error.BufferTooSmall, b.addMessageIntegrity("key"));
    try testing.expectEqual(@as(usize, stun.header_len + 65_516), b.finish().len);
    // 65516 + 8 = 65524 still fits FINGERPRINT.
    try b.addFingerprint();
    try testing.expect((try stun.decode(b.finish())).verifyFingerprint());
}

test "addFingerprint: refused when the 8 bytes would outgrow the length field (sweep ST-2)" {
    const buf = try testing.allocator.alloc(u8, big);
    defer testing.allocator.free(buf);
    const value = try testing.allocator.alloc(u8, 65_524);
    defer testing.allocator.free(value);
    @memset(value, 'x');
    var b = try newBuilder(buf);
    try b.addAttribute(0x8022, value); // region = 65528; +8 = 65536
    try testing.expectError(error.BufferTooSmall, b.addFingerprint());
    try testing.expectEqual(@as(usize, stun.header_len + 65_528), b.finish().len);
}
