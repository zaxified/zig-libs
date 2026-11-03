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

test "bindingResponse/findCovered: MESSAGE-INTEGRITY-SHA256 also ends the covered region; findCovered finds MI itself (sweep audit GV-A4)" {
    var rb: [256]u8 = undefined;
    var out: [256]u8 = undefined;
    const from: stun.AddressPort = .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = 4000 };
    var b = try newBuilder(&rb);
    try b.addAttribute(0x001C, &@as([32]u8, @splat(0))); // MESSAGE-INTEGRITY-SHA256
    try b.addAttribute(0x0006, "alice"); // USERNAME behind it
    try b.addAttribute(0x0030, "zz"); // unknown comprehension-required behind it
    const m = try stun.decode(b.finish());
    try testing.expect(m.find(0x0006) != null);
    try testing.expect(m.findCovered(0x0006) == null);
    try testing.expect(m.findCovered(0x001C) != null);
    // No 420 for the attribute behind the MAC.
    const resp = try stun.decode(try stun.bindingResponse(m, from, &out, .{}));
    try testing.expectEqual(stun.Class.success_response, resp.class);

    // The same with the SHA-1 MESSAGE-INTEGRITY.
    var b2 = try newBuilder(&rb);
    try b2.addAttribute(0x0008, &@as([20]u8, @splat(0)));
    try b2.addAttribute(0x0006, "alice");
    const m2 = try stun.decode(b2.finish());
    try testing.expect(m2.findCovered(0x0008) != null);
    try testing.expect(m2.findCovered(0x0006) == null);
    // A request without any MAC: findCovered sees every attribute.
    var b3 = try newBuilder(&rb);
    try b3.addAttribute(0x0006, "alice");
    try testing.expect((try stun.decode(b3.finish())).findCovered(0x0006) != null);
}

test "addMessageIntegrity / addFingerprint: the exact boundaries of the 16-bit length field (sweep audit GV-A5)" {
    const buf = try testing.allocator.alloc(u8, big);
    defer testing.allocator.free(buf);
    const value = try testing.allocator.alloc(u8, 65_520);
    defer testing.allocator.free(value);
    @memset(value, 'x');
    // MESSAGE-INTEGRITY: region 65508 + 24 = 65532 fits, 65512 + 24 = 65536 does not.
    var b = try newBuilder(buf);
    try b.addAttribute(0x8022, value[0..65_504]);
    try b.addMessageIntegrity("key");
    try testing.expectEqual(@as(u16, 65_532), std.mem.readInt(u16, buf[2..4], .big));
    try testing.expect((try stun.decode(b.finish())).verifyMessageIntegrity("key"));
    var b2 = try newBuilder(buf);
    try b2.addAttribute(0x8022, value[0..65_508]);
    try testing.expectError(error.BufferTooSmall, b2.addMessageIntegrity("key"));
    try testing.expectEqual(@as(usize, stun.header_len + 65_512), b2.finish().len);
    // FINGERPRINT: region 65524 + 8 = 65532 fits (65528 + 8 is refused above).
    var b3 = try newBuilder(buf);
    try b3.addAttribute(0x8022, value[0..65_520]);
    try b3.addFingerprint();
    try testing.expectEqual(@as(u16, 65_532), std.mem.readInt(u16, buf[2..4], .big));
    try testing.expect((try stun.decode(b3.finish())).verifyFingerprint());
}

test "addAttribute: a 65535-byte value fits the u16 but not the message: BufferTooSmall, a 65536-byte one is ValueTooLong (sweep audit GV-A8)" {
    const buf = try testing.allocator.alloc(u8, 2 * big);
    defer testing.allocator.free(buf);
    const value = try testing.allocator.alloc(u8, 65_536);
    defer testing.allocator.free(value);
    @memset(value, 'x');
    var b = try newBuilder(buf);
    try testing.expectError(error.BufferTooSmall, b.addAttribute(0x8022, value[0..65_535]));
    try testing.expectError(error.ValueTooLong, b.addAttribute(0x8022, value));
    try testing.expectEqual(@as(usize, stun.header_len), b.finish().len);
}

test "MESSAGE-INTEGRITY-SHA256 / addAddress / addChangeRequest: refusals leave the message untouched, boundaries of the 16-bit length field" {
    const buf = try testing.allocator.alloc(u8, big);
    defer testing.allocator.free(buf);
    const value = try testing.allocator.alloc(u8, 65_520);
    defer testing.allocator.free(value);
    @memset(value, 'x');
    // Tag length out of range: refused before anything is written.
    var b = try newBuilder(buf);
    for ([_]u8{ 0, 15, 17, 33, 36, 255 }) |t|
        try testing.expectError(error.InvalidTagLength, b.addMessageIntegritySha256("k", t));
    try testing.expectEqual(@as(usize, stun.header_len), b.finish().len);
    // Region 65496 (4 + 65492) + 4 + 32 = 65532 fits (the 16-bit field maxes at 65535)...
    try b.addAttribute(0x8022, value[0 .. 65_496 - 4]);
    try b.addMessageIntegritySha256("key", 32);
    try testing.expectEqual(@as(u16, 65_532), std.mem.readInt(u16, buf[2..4], .big));
    try testing.expect((try stun.decode(b.finish())).verifyMessageIntegritySha256("key"));
    // ... while 65500 + 36 = 65536 does not, but a 16-byte tag does.
    var b2 = try newBuilder(buf);
    try b2.addAttribute(0x8022, value[0 .. 65_500 - 4]);
    try testing.expectError(error.BufferTooSmall, b2.addMessageIntegritySha256("key", 32));
    try testing.expectEqual(@as(usize, stun.header_len + 65_500), b2.finish().len);
    try b2.addMessageIntegritySha256("key", 16);
    try testing.expect((try stun.decode(b2.finish())).verifyMessageIntegritySha256("key"));
    // addAddress / addChangeRequest into a tiny buffer.
    var tiny: [32]u8 = undefined;
    var b3 = try stun.Builder.init(&tiny, .request, .binding, @splat(1));
    try testing.expectError(error.BufferTooSmall, b3.addAddress(0x0020, .{ .v6 = @splat(1) }, 1));
    try testing.expectEqual(@as(usize, stun.header_len), b3.finish().len);
    try b3.addChangeRequest(true, true);
    try testing.expectError(error.BufferTooSmall, b3.addChangeRequest(true, true));
}

test "hostile accessors: address/uint32/changeRequest/verifyMessageIntegritySha256 over short and odd values" {
    var rb: [128]u8 = undefined;
    var b = try newBuilder(&rb);
    try b.addAttribute(0x802C, &[_]u8{ 0, 1, 0, 1 }); // IPv4 family, value too short
    try b.addAttribute(0x802B, &[_]u8{ 0, 9, 0, 1, 1, 1, 1, 1 }); // unknown family
    try b.addAttribute(0x0003, &[_]u8{ 0, 0 }); // CHANGE-REQUEST of 2 bytes
    try b.addAttribute(0x001C, &[_]u8{ 1, 2, 3 }); // 3-byte tag
    const m = try stun.decode(b.finish());
    try testing.expectError(error.MalformedAttribute, m.otherAddress());
    try testing.expectError(error.UnknownAddressFamily, m.responseOrigin());
    try testing.expectError(error.MalformedAttribute, m.changeRequest());
    try testing.expect(!m.verifyMessageIntegritySha256("k"));
    try testing.expect((try m.alternateServer()) == null);
    try testing.expect(!stun.looksLikeStun(rb[0..3]));
}

test "PASSWORD-ALGORITHM(S) / USERHASH / covered accessors / bindingResponse SHA-256: hostile and oversized inputs (review M2)" {
    var buf: [512]u8 = undefined;
    var b = try newBuilder(&buf);
    // 253 bytes of parameters, and a list that outgrows 252 bytes: ValueTooLong, nothing written.
    try testing.expectError(error.ValueTooLong, b.addPasswordAlgorithm(.{ .algorithm = 1, .params = &@as([253]u8, @splat(1)) }));
    const many: [70]stun.PasswordAlgorithm = @splat(.{ .algorithm = 2 });
    try testing.expectError(error.ValueTooLong, b.addPasswordAlgorithms(&many));
    try testing.expectEqual(@as(usize, stun.header_len), b.finish().len);
    // Every prefix of a valid list parses or fails cleanly.
    var b2 = try newBuilder(&buf);
    try b2.addPasswordAlgorithms(&.{ .{ .algorithm = 2, .params = "xyz" }, .{ .algorithm = 1 } });
    const full = try stun.decode(b2.finish());
    const v = full.find(0x8002).?.value;
    for (0..v.len + 1) |n| {
        var it: stun.PasswordAlgorithmIterator = .{ .rest = v[0..n] };
        while (true) {
            const e = it.next() catch break;
            if (e == null) break;
        }
    }
    // Truncated attribute values of the covered accessors.
    var scratch: [32]u8 = @splat(0);
    for ([_]usize{ 0, 1, 3, 4, 7, 8, 19 }) |vl| {
        var rb3: [128]u8 = undefined;
        var b3 = try newBuilder(&rb3);
        try b3.addAttribute(0x802C, scratch[0..vl]);
        try b3.addAttribute(0x0003, scratch[0..vl]);
        try b3.addMessageIntegrity("k");
        const m = try stun.decode(b3.finish());
        _ = m.addressCovered(0x802C) catch {};
        _ = m.uint32Covered(0x0003) catch {};
        _ = m.mappedAddressCovered() catch {};
    }
    // bindingResponse with an SHA-256 key and every tag value, into a too-small buffer too.
    var rq: [128]u8 = undefined;
    var rb = try newBuilder(&rq);
    try rb.addUsername("u");
    try rb.addMessageIntegritySha256("k", 32);
    const req = try stun.decode(rb.finish());
    const from: stun.AddressPort = .{ .ip = .{ .v4 = .{ 1, 2, 3, 4 } }, .port = 1 };
    var small: [40]u8 = undefined;
    for (0..256) |t| {
        _ = stun.bindingResponse(req, from, &small, .{ .integrity_key_sha256 = "k", .integrity_sha256_tag = @intCast(t) }) catch {};
        _ = stun.bindingResponse(req, from, &buf, .{ .integrity_key_sha256 = "k", .integrity_sha256_tag = @intCast(t) }) catch {};
    }
}
