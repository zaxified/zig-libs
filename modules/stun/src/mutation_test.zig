// SPDX-License-Identifier: MIT

//! Tests added by the 2026-11-18 whole-module mutation audit: each one pins a
//! behaviour that a mutant of `root.zig` could change without any earlier test
//! noticing (large method numbers, header validation order, exact-fit buffers,
//! boundary lengths of fixed-size attributes, padding of error responses,
//! URI host characters, the `query` retransmission cap, ...).

const std = @import("std");
const stun = @import("root.zig");
const netaddr = @import("netaddr");

const testing = std.testing;

const txid: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
const from: stun.AddressPort = .{ .ip = .{ .v4 = .{ 203, 0, 113, 9 } }, .port = 4989 };

// Attribute type codes (RFC 8489 / 5780 / 8656), spelled as numbers so the
// tests do not lean on the module's own enum.
const t_username: u16 = 0x0006;
const t_mi: u16 = 0x0008;
const t_realm: u16 = 0x0014;
const t_nonce: u16 = 0x0015;
const t_mi256: u16 = 0x001C;
const t_pwalg: u16 = 0x001D;
const t_userhash: u16 = 0x001E;
const t_xor_mapped: u16 = 0x0020;
const t_fingerprint: u16 = 0x8028;

// ── message type: bit layout ────────────────────────────────────────────────

/// RFC 8489 §5, written bit by bit: M0..M3 at bits 0..3, C0 at bit 4,
/// M4..M6 at bits 5..7, C1 at bit 8, M7..M11 at bits 9..13.
fn refType(class: u2, method: u12) u16 {
    var t: u16 = 0;
    for (0..12) |k| {
        if ((method >> @intCast(k)) & 1 == 0) continue;
        const pos: usize = if (k < 4) k else if (k < 7) k + 1 else k + 2;
        t |= @as(u16, 1) << @intCast(pos);
    }
    if (class & 1 != 0) t |= @as(u16, 1) << 4;
    if (class & 2 != 0) t |= @as(u16, 1) << 8;
    return t;
}

test "message type: encode, decodeClass, decodeMethod and decode agree with the RFC 8489 §5 layout for every class and method" {
    var hdr: [20]u8 = @splat(0);
    std.mem.writeInt(u32, hdr[4..8], stun.magic_cookie, .big);
    for (0..4) |ci| {
        for (0..4096) |mi| {
            const class: stun.Class = @fromBackingInt(@intCast(ci));
            const method: stun.Method = @fromBackingInt(@intCast(mi));
            const want = refType(@intCast(ci), @intCast(mi));
            try testing.expectEqual(want, stun.encodeType(class, method));
            try testing.expectEqual(class, stun.decodeClass(want));
            try testing.expectEqual(@as(u12, @intCast(mi)), stun.decodeMethod(want));
            std.mem.writeInt(u16, hdr[0..2], want, .big);
            const m = try stun.decode(&hdr);
            const mb: u12 = @backingInt(m.method);
            try testing.expectEqual(class, m.class);
            try testing.expectEqual(@as(u12, @intCast(mi)), mb);
        }
    }
}

test "Builder.init: short buffers are BufferTooSmall, the header is complete, and class and method are written" {
    var buf: [64]u8 = undefined;
    for (0..20) |n| try testing.expectError(error.BufferTooSmall, stun.Builder.init(buf[0..n], .request, .binding, txid));
    @memset(&buf, 0xFF);
    const method: stun.Method = @fromBackingInt(0x0ABC);
    const b = try stun.Builder.init(buf[0..20], .error_response, method, txid);
    const m = try stun.decode(b.finish());
    try testing.expectEqual(stun.Class.error_response, m.class);
    try testing.expectEqual(method, m.method);
    try testing.expectEqual(@as(u16, 0), m.length);
    try testing.expectEqualSlices(u8, &txid, &m.transaction_id);
}

// ── Builder: exact fits, boundaries, padding ────────────────────────────────

test "Builder.addAttribute: an exact fit is accepted, one byte less is BufferTooSmall, padding fills with pad" {
    var exact: [28]u8 = @splat(0xFF);
    var b = try stun.Builder.init(&exact, .request, .binding, txid);
    try b.addAttribute(0x7001, "abcd");
    try testing.expectEqual(@as(usize, 28), b.finish().len);
    var short: [27]u8 = undefined;
    var b2 = try stun.Builder.init(&short, .request, .binding, txid);
    try testing.expectError(error.BufferTooSmall, b2.addAttribute(0x7001, "abcd"));
    // 5 bytes pad to 8: 20 + 4 + 8 = 32 bytes are needed, 27 are not enough.
    var b3 = try stun.Builder.init(short[0..27], .request, .binding, txid);
    try testing.expectError(error.BufferTooSmall, b3.addAttribute(0x7001, "abcde"));
    var fit: [32]u8 = @splat(0xFF);
    var b4 = try stun.Builder.init(&fit, .request, .binding, txid);
    b4.pad = 0x20;
    try b4.addAttribute(0x7001, "abcde");
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x20, 0x20 }, fit[29..32]);
}

test "Builder.addAttribute: the attribute region never outgrows the 16-bit length field" {
    const big = try testing.allocator.alloc(u8, 70_000);
    defer testing.allocator.free(big);
    const value = try testing.allocator.alloc(u8, 65_532);
    defer testing.allocator.free(value);
    @memset(value, 0x55);
    var b = try stun.Builder.init(big, .request, .binding, txid);
    // 4 + 65532 = 65536 does not fit 16 bits; 4 + 65528 = 65532 does.
    try testing.expectError(error.BufferTooSmall, b.addAttribute(0x7001, value));
    try b.addAttribute(0x7001, value[0..65_528]);
    try testing.expectEqual(@as(u16, 65_532), (try stun.decode(b.finish())).length);
    try testing.expectError(error.BufferTooSmall, b.addAttribute(0x7002, ""));
}

test "Builder.addErrorCode: 300 and 699 are accepted, a 763-byte reason survives byte for byte" {
    var buf: [1024]u8 = undefined;
    var b = try stun.Builder.init(&buf, .error_response, .binding, txid);
    try b.addErrorCode(300, "");
    try testing.expectEqual(@as(u16, 300), (try (try stun.decode(b.finish())).errorCode()).?.code);
    var b2 = try stun.Builder.init(&buf, .error_response, .binding, txid);
    try b2.addErrorCode(699, "x");
    try testing.expectEqual(@as(u16, 699), (try (try stun.decode(b2.finish())).errorCode()).?.code);
    var reason: [764]u8 = undefined;
    for (&reason, 0..) |*c, i| c.* = @intCast('a' + i % 26);
    var b3 = try stun.Builder.init(&buf, .error_response, .binding, txid);
    try b3.addErrorCode(420, reason[0..763]);
    const ec = (try (try stun.decode(b3.finish())).errorCode()).?;
    try testing.expectEqual(@as(u16, 420), ec.code);
    try testing.expectEqualSlices(u8, reason[0..763], ec.reason);
    var b4 = try stun.Builder.init(&buf, .error_response, .binding, txid);
    try testing.expectError(error.ValueTooLong, b4.addErrorCode(420, &reason));
}

test "Builder.addUnknownAttributes: 64 types are accepted in order, 65 are ValueTooLong" {
    var buf: [256]u8 = undefined;
    var types: [65]u16 = undefined;
    for (&types, 0..) |*t, i| t.* = @intCast(0x7000 + i);
    var b = try stun.Builder.init(&buf, .error_response, .binding, txid);
    try b.addUnknownAttributes(types[0..64]);
    const m = try stun.decode(b.finish());
    const a = m.find(0x000A).?;
    try testing.expectEqual(@as(usize, 128), a.value.len);
    for (types[0..64], 0..) |t, i| try testing.expectEqual(t, std.mem.readInt(u16, a.value[i * 2 ..][0..2], .big));
    var b2 = try stun.Builder.init(&buf, .error_response, .binding, txid);
    try testing.expectError(error.ValueTooLong, b2.addUnknownAttributes(&types));
}

test "Builder: MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256 and FINGERPRINT fit a buffer exactly, not one byte less" {
    var buf: [128]u8 = undefined;
    var b = try stun.Builder.init(buf[0..44], .request, .binding, txid);
    try b.addMessageIntegrity("k");
    var b2 = try stun.Builder.init(buf[0..43], .request, .binding, txid);
    try testing.expectError(error.BufferTooSmall, b2.addMessageIntegrity("k"));
    var b3 = try stun.Builder.init(buf[0..28], .request, .binding, txid);
    try b3.addFingerprint();
    var b4 = try stun.Builder.init(buf[0..27], .request, .binding, txid);
    try testing.expectError(error.BufferTooSmall, b4.addFingerprint());
    var tag: u8 = 16;
    while (tag <= 32) : (tag += 4) {
        const n: usize = 20 + 4 + tag;
        var b5 = try stun.Builder.init(buf[0..n], .request, .binding, txid);
        try b5.addMessageIntegritySha256("k", tag);
        var b6 = try stun.Builder.init(buf[0 .. n - 1], .request, .binding, txid);
        try testing.expectError(error.BufferTooSmall, b6.addMessageIntegritySha256("k", tag));
    }
    // Every other tag length is refused, whatever the buffer.
    for ([_]u8{ 0, 4, 12, 15, 17, 18, 19, 20 + 14, 33, 34, 36, 255 }) |bad| {
        var b7 = try stun.Builder.init(&buf, .request, .binding, txid);
        try testing.expectError(error.InvalidTagLength, b7.addMessageIntegritySha256("k", bad));
    }
}

test "Builder.addChangeRequest and Message.changeRequest: all four flag combinations, bit for bit" {
    var buf: [64]u8 = undefined;
    const cases = [_]struct { ip: bool, port: bool, v: u32 }{
        .{ .ip = false, .port = false, .v = 0 },
        .{ .ip = false, .port = true, .v = 2 },
        .{ .ip = true, .port = false, .v = 4 },
        .{ .ip = true, .port = true, .v = 6 },
    };
    for (cases) |c| {
        var b = try stun.Builder.init(&buf, .request, .binding, txid);
        try b.addChangeRequest(c.ip, c.port);
        const m = try stun.decode(b.finish());
        try testing.expectEqual(c.v, (try m.uint32(0x0003)).?);
        const cr = (try m.changeRequest()).?;
        try testing.expectEqual(c.ip, cr.change_ip);
        try testing.expectEqual(c.port, cr.change_port);
    }
}

test "Builder.addPasswordAlgorithm(s): the 252-byte limits are exact" {
    var buf: [512]u8 = undefined;
    const params: [253]u8 = @splat(0x61);
    var b = try stun.Builder.init(&buf, .request, .binding, txid);
    try b.addPasswordAlgorithm(.{ .algorithm = 2, .params = params[0..252] });
    const e = (try (try stun.decode(b.finish())).passwordAlgorithm()).?;
    try testing.expectEqual(@as(u16, 2), e.algorithm);
    try testing.expectEqualSlices(u8, params[0..252], e.params);
    var b2 = try stun.Builder.init(&buf, .request, .binding, txid);
    try testing.expectError(error.ValueTooLong, b2.addPasswordAlgorithm(.{ .algorithm = 2, .params = &params }));
    // 63 empty entries are 252 bytes: accepted; a 64th is not.
    var algs: [64]stun.PasswordAlgorithm = undefined;
    for (&algs, 0..) |*a, i| a.* = .{ .algorithm = @intCast(i + 1) };
    var b3 = try stun.Builder.init(&buf, .request, .binding, txid);
    try b3.addPasswordAlgorithms(algs[0..63]);
    var it = (try stun.decode(b3.finish())).passwordAlgorithms().?;
    var n: u16 = 0;
    while (try it.next()) |a| {
        n += 1;
        try testing.expectEqual(n, a.algorithm);
    }
    try testing.expectEqual(@as(u16, 63), n);
    var b4 = try stun.Builder.init(&buf, .request, .binding, txid);
    try testing.expectError(error.ValueTooLong, b4.addPasswordAlgorithms(&algs));
}

test "Builder.addAddress: XOR-RELAYED-ADDRESS is XOR-encoded like XOR-MAPPED-ADDRESS" {
    var buf: [128]u8 = undefined;
    const v6 = netaddr.parseIp("2001:db8::1").?;
    for ([_]netaddr.Ip{ from.ip, v6 }) |ip| {
        var b = try stun.Builder.init(&buf, .success_response, .binding, txid);
        try b.addAddress(0x0016, ip, 4989); // XOR-RELAYED-ADDRESS
        try b.addAddress(0x0012, ip, 4989); // XOR-PEER-ADDRESS
        try b.addAddress(t_xor_mapped, ip, 4989);
        const m = try stun.decode(b.finish());
        const want = m.find(t_xor_mapped).?.value;
        try testing.expectEqualSlices(u8, want, m.find(0x0016).?.value);
        try testing.expectEqualSlices(u8, want, m.find(0x0012).?.value);
        try testing.expect((try m.address(0x0016)).?.ip.eql(ip));
        try testing.expectEqual(@as(u16, 4989), (try m.address(0x0016)).?.port);
    }
}

// ── decode: header validation ───────────────────────────────────────────────

fn header(type_: u16, length: u16, cookie: u32, buf: *[32]u8) []const u8 {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[0..2], type_, .big);
    std.mem.writeInt(u16, buf[2..4], length, .big);
    std.mem.writeInt(u32, buf[4..8], cookie, .big);
    return buf;
}

test "decode: every header check reports its own error, in the documented order" {
    var buf: [32]u8 = undefined;
    // Shorter than a header: Truncated, whatever the bytes say.
    @memset(&buf, 0xFF);
    try testing.expectError(error.Truncated, stun.decode(buf[0..19]));
    try testing.expectError(error.Truncated, stun.decode(buf[0..0]));
    // Either of the two top bits set: NotStun.
    try testing.expectError(error.NotStun, stun.decode(header(0x4001, 0, stun.magic_cookie, &buf)[0..20]));
    try testing.expectError(error.NotStun, stun.decode(header(0x8001, 0, stun.magic_cookie, &buf)[0..20]));
    try testing.expectError(error.NotStun, stun.decode(header(0xC001, 0, stun.magic_cookie, &buf)[0..20]));
    // A length that is not a multiple of 4: BadLength (before the cookie is looked at).
    for ([_]u16{ 1, 2, 3, 5, 6, 7, 9, 10, 11 }) |l| {
        try testing.expectError(error.BadLength, stun.decode(header(0x0001, l, stun.magic_cookie, &buf)));
        try testing.expectError(error.BadLength, stun.decode(header(0x0001, l, 0, &buf)));
    }
    // Every single cookie bit matters.
    for (0..32) |k| {
        const c = stun.magic_cookie ^ (@as(u32, 1) << @intCast(k));
        try testing.expectError(error.BadCookie, stun.decode(header(0x0001, 0, c, &buf)[0..20]));
    }
    // The length field must fit the datagram, exactly or with room to spare.
    try testing.expectError(error.Truncated, stun.decode(header(0x0001, 16, stun.magic_cookie, &buf)));
    _ = try stun.decode(header(0x0001, 12, stun.magic_cookie, &buf));
    // Trailing bytes behind the declared length are cut off.
    const m = try stun.decode(header(0x0001, 4, stun.magic_cookie, &buf));
    try testing.expectEqual(@as(usize, 24), m.bytes.len);
    try testing.expectEqual(@as(u16, 4), m.length);
}

test "looksLikeStun: a bare header is STUN, a datagram with trailing bytes is not" {
    var buf: [32]u8 = undefined;
    try testing.expect(stun.looksLikeStun(header(0x0001, 0, stun.magic_cookie, &buf)[0..20]));
    try testing.expect(!stun.looksLikeStun(header(0x0001, 0, stun.magic_cookie, &buf)[0..24]));
    try testing.expect(stun.looksLikeStun(header(0x0001, 4, stun.magic_cookie, &buf)[0..24]));
    try testing.expect(!stun.looksLikeStun(header(0x0001, 0, stun.magic_cookie, &buf)[0..19]));
    try testing.expect(!stun.looksLikeStun(header(0x0001, 0, stun.magic_cookie ^ 1, &buf)[0..20]));
}

test "attribute iterator: an empty attribute at the very end is seen; a 3-byte tail is not an attribute" {
    var buf: [32]u8 = undefined;
    var b = try stun.Builder.init(&buf, .request, .binding, txid);
    try b.addAttribute(0x7001, "abcd");
    try b.addAttribute(0x7002, "");
    const m = try stun.decode(b.finish());
    try testing.expectEqual(@as(usize, 0), m.find(0x7002).?.value.len);
    try testing.expectEqual(@as(usize, 28), m.find(0x7002).?.offset);
    // An unaligned region (cannot come out of `decode`): the 3 bytes behind
    // the header hold no attribute.
    var it: stun.AttributeIterator = .{ .msg = buf[0..23] };
    try testing.expect(it.next() == null);
}

// ── attribute accessors: lengths and families ───────────────────────────────

test "Message accessors: fixed-size attributes reject every other length" {
    var buf: [128]u8 = undefined;
    const filler: [40]u8 = @splat(0x33);
    for ([_]usize{ 0, 3, 5, 8 }) |n| {
        var b = try stun.Builder.init(&buf, .request, .binding, txid);
        try b.addAttribute(0x0024, filler[0..n]); // PRIORITY
        try b.addAttribute(t_userhash, filler[0..n]);
        const m = try stun.decode(b.finish());
        try testing.expectError(error.MalformedAttribute, m.uint32(0x0024));
        try testing.expectError(error.MalformedAttribute, m.uint32Covered(0x0024));
        try testing.expectError(error.MalformedAttribute, m.userhash());
    }
    for ([_]usize{ 31, 33, 36 }) |n| {
        var b = try stun.Builder.init(&buf, .request, .binding, txid);
        try b.addAttribute(t_userhash, filler[0..n]);
        try testing.expectError(error.MalformedAttribute, (try stun.decode(b.finish())).userhash());
    }
    var b = try stun.Builder.init(&buf, .request, .binding, txid);
    try b.addAttribute(t_userhash, filler[0..32]);
    try b.addUint32(0x0024, 0x01020304);
    const m = try stun.decode(b.finish());
    try testing.expectEqualSlices(u8, filler[0..32], &(try m.userhash()).?);
    try testing.expectEqual(@as(u32, 0x01020304), (try m.uint32(0x0024)).?);
    try testing.expectEqual(@as(u32, 0x01020304), (try m.uint32Covered(0x0024)).?);
}

test "decodeAddress: every length and family boundary, through the public accessors" {
    var buf: [128]u8 = undefined;
    var body: [20]u8 = @splat(0x77);
    body[0] = 0;
    body[2] = 0x12;
    body[3] = 0x34;
    const Case = struct { len: usize, family: u8, err: ?anyerror };
    const cases = [_]Case{
        .{ .len = 0, .family = 1, .err = error.MalformedAttribute },
        .{ .len = 3, .family = 1, .err = error.MalformedAttribute },
        .{ .len = 4, .family = 3, .err = error.UnknownAddressFamily },
        .{ .len = 4, .family = 1, .err = error.MalformedAttribute },
        .{ .len = 7, .family = 1, .err = error.MalformedAttribute },
        .{ .len = 8, .family = 1, .err = null },
        .{ .len = 19, .family = 2, .err = error.MalformedAttribute },
        .{ .len = 20, .family = 2, .err = null },
        .{ .len = 20, .family = 0, .err = error.UnknownAddressFamily },
    };
    for (cases) |c| {
        var v = body;
        v[1] = c.family;
        var b = try stun.Builder.init(&buf, .success_response, .binding, txid);
        try b.addAttribute(t_xor_mapped, v[0..c.len]);
        try b.addAttribute(0x0001, v[0..c.len]);
        const m = try stun.decode(b.finish());
        if (c.err) |e| {
            try testing.expectError(e, m.xorMappedAddress());
            try testing.expectError(e, m.plainMappedAddress());
        } else {
            try testing.expect((try m.xorMappedAddress()) != null);
            try testing.expect((try m.plainMappedAddress()) != null);
        }
    }
}

test "mappedAddress and mappedAddressCovered fall back to a plain MAPPED-ADDRESS, and only to that" {
    var buf: [128]u8 = undefined;
    const ip = netaddr.parseIp("198.51.100.7").?;
    var b = try stun.Builder.init(&buf, .success_response, .binding, txid);
    try b.addMappedAddress(ip, 1234, false);
    const plain = try stun.decode(b.finish());
    try testing.expect((try plain.mappedAddress()).?.ip.eql(ip));
    try testing.expectEqual(@as(u16, 1234), (try plain.mappedAddress()).?.port);
    try testing.expect((try plain.mappedAddressCovered()).?.ip.eql(ip));
    try testing.expect((try plain.xorMappedAddress()) == null);
    var b2 = try stun.Builder.init(&buf, .success_response, .binding, txid);
    try b2.addSoftware("none here");
    const none = try stun.decode(b2.finish());
    try testing.expect((try none.mappedAddress()) == null);
    try testing.expect((try none.mappedAddressCovered()) == null);
}

test "ERROR-CODE: 3 bytes are malformed, 4 are an empty reason, only the low 3 class bits count" {
    var buf: [64]u8 = undefined;
    var b = try stun.Builder.init(&buf, .error_response, .binding, txid);
    try b.addAttribute(0x0009, &.{ 0, 0, 4 });
    try testing.expectError(error.MalformedAttribute, (try stun.decode(b.finish())).errorCode());
    var b2 = try stun.Builder.init(&buf, .error_response, .binding, txid);
    try b2.addAttribute(0x0009, &.{ 0, 0, 4, 1 });
    const e = (try (try stun.decode(b2.finish())).errorCode()).?;
    try testing.expectEqual(@as(u16, 401), e.code);
    try testing.expectEqual(@as(usize, 0), e.reason.len);
    // Reserved bits above the class (RFC 8489 §14.8): ignored.
    var b3 = try stun.Builder.init(&buf, .error_response, .binding, txid);
    try b3.addAttribute(0x0009, &.{ 0xFF, 0xFF, 0x0B, 5, 'o', 'k' });
    const e3 = (try (try stun.decode(b3.finish())).errorCode()).?;
    try testing.expectEqual(@as(u16, 305), e3.code);
    try testing.expectEqualStrings("ok", e3.reason);
}

// ── integrity: crafted attribute lengths, absent attributes ─────────────────

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// A message `[SOFTWARE][attr]` whose last attribute has `vlen` value bytes;
/// returns the message and the attribute's offset.
fn craft(buf: []u8, code: u16, vlen: usize) !struct { msg: []u8, off: usize } {
    var b = try stun.Builder.init(buf, .request, .binding, txid);
    try b.addSoftware("abcd");
    const off = b.len;
    const zeros: [64]u8 = @splat(0);
    try b.addAttribute(code, zeros[0..vlen]);
    return .{ .msg = buf[0..b.len], .off = off };
}

fn patchedHeader(msg: []const u8, patched_len: usize) [4]u8 {
    var h: [4]u8 = undefined;
    @memcpy(h[0..2], msg[0..2]);
    std.mem.writeInt(u16, h[2..4], @intCast(patched_len), .big);
    return h;
}

test "verifyFingerprint: only a 4-byte value can verify" {
    var buf: [64]u8 = undefined;
    for ([_]usize{ 0, 3, 4, 5, 8 }) |vlen| {
        const c = try craft(&buf, t_fingerprint, vlen);
        if (vlen >= 4) {
            const h = patchedHeader(c.msg, c.off - 20 + 8);
            var crc = std.hash.Crc32.init();
            crc.update(&h);
            crc.update(c.msg[4..c.off]);
            std.mem.writeInt(u32, c.msg[c.off + 4 ..][0..4], crc.final() ^ stun.fingerprint_xor, .big);
        }
        try testing.expectEqual(vlen == 4, (try stun.decode(c.msg)).verifyFingerprint());
    }
}

test "verifyMessageIntegrity: only a 20-byte value can verify" {
    var buf: [96]u8 = undefined;
    for ([_]usize{ 0, 16, 19, 20, 21, 24 }) |vlen| {
        const c = try craft(&buf, t_mi, vlen);
        if (vlen >= 20) {
            const h = patchedHeader(c.msg, c.off - 20 + 24);
            var mac: [20]u8 = undefined;
            var hm = HmacSha1.init("key");
            hm.update(&h);
            hm.update(c.msg[4..c.off]);
            hm.final(&mac);
            @memcpy(c.msg[c.off + 4 ..][0..20], &mac);
        }
        try testing.expectEqual(vlen == 20, (try stun.decode(c.msg)).verifyMessageIntegrity("key"));
    }
}

test "verifyMessageIntegritySha256: a tag verifies only at 16, 20, 24, 28 or 32 bytes" {
    var buf: [128]u8 = undefined;
    for ([_]usize{ 0, 12, 15, 16, 17, 18, 19, 20, 22, 24, 28, 30, 32, 33, 36 }) |n| {
        const c = try craft(&buf, t_mi256, n);
        if (n >= 1 and n <= 32) {
            const h = patchedHeader(c.msg, c.off - 20 + 4 + n);
            var mac: [32]u8 = undefined;
            var hm = HmacSha256.init("key");
            hm.update(&h);
            hm.update(c.msg[4..c.off]);
            hm.final(&mac);
            @memcpy(c.msg[c.off + 4 ..][0..n], mac[0..n]);
        }
        const legal = n >= 16 and n <= 32 and n % 4 == 0;
        try testing.expectEqual(legal, (try stun.decode(c.msg)).verifyMessageIntegritySha256("key"));
    }
}

test "verify*: a message without the attribute never verifies" {
    var buf: [64]u8 = undefined;
    var b = try stun.Builder.init(&buf, .request, .binding, txid);
    try b.addSoftware("abcd");
    const m = try stun.decode(b.finish());
    try testing.expect(!m.verifyFingerprint());
    try testing.expect(!m.verifyMessageIntegrity("key"));
    try testing.expect(!m.verifyMessageIntegritySha256("key"));
}

// ── bindingResponse ─────────────────────────────────────────────────────────

fn expectPadding(msg: stun.Message, typ: u16, pad: u8) !void {
    var it = msg.attributes();
    while (it.next()) |a| {
        if (a.type != typ) continue;
        const padded = (a.value.len + 3) & ~@as(usize, 3);
        try testing.expect(padded > a.value.len);
        for (msg.bytes[a.offset + 4 + a.value.len .. a.offset + 4 + padded]) |x| try testing.expectEqual(pad, x);
        return;
    }
    return error.TestUnexpectedResult;
}

test "bindingResponse: error responses pad with opts.pad too" {
    var rbuf: [128]u8 = undefined;
    var out: [256]u8 = undefined;
    // 420: "Unknown Attribute" is 17 bytes.
    var b = try stun.Builder.init(&rbuf, .request, .binding, txid);
    try b.addAttribute(0x7001, "");
    const e420 = try stun.decode(try stun.bindingResponse(try stun.decode(b.finish()), from, &out, .{ .pad = 0x20 }));
    try testing.expectEqual(@as(u16, 420), (try e420.errorCode()).?.code);
    try expectPadding(e420, 0x0009, 0x20);
    // 400: "Bad Request" is 11 bytes.
    const b2 = try stun.Builder.init(&rbuf, .request, .binding, txid);
    const e400 = try stun.decode(try stun.bindingResponse(try stun.decode(b2.finish()), from, &out, .{ .integrity_key = "k", .pad = 0x20 }));
    try testing.expectEqual(@as(u16, 400), (try e400.errorCode()).?.code);
    try expectPadding(e400, 0x0009, 0x20);
    // 401: "Unauthorized" is 12 bytes -> 16 with the 4-byte header: no pad. 400's check above covers it.
    var b3 = try stun.Builder.init(&rbuf, .request, .binding, txid);
    try b3.addUsername("u");
    try b3.addMessageIntegrity("other");
    const e401 = try stun.decode(try stun.bindingResponse(try stun.decode(b3.finish()), from, &out, .{ .integrity_key = "k", .pad = 0x20 }));
    try testing.expectEqual(@as(u16, 401), (try e401.errorCode()).?.code);
}

test "bindingResponse: only Binding requests are answered" {
    var rbuf: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const other_method: stun.Method = @fromBackingInt(0x002);
    const b = try stun.Builder.init(&rbuf, .request, other_method, txid);
    try testing.expectError(error.NotBindingRequest, stun.bindingResponse(try stun.decode(b.finish()), from, &out, .{}));
    const b2 = try stun.Builder.init(&rbuf, .indication, .binding, txid);
    try testing.expectError(error.NotBindingRequest, stun.bindingResponse(try stun.decode(b2.finish()), from, &out, .{}));
}

test "bindingResponse: the comprehension-required boundary is 0x8000, and understood attributes pass" {
    var rbuf: [128]u8 = undefined;
    var out: [256]u8 = undefined;
    // 0x8000 is comprehension-optional: answered; 0x7FFF is required: a 420 naming it.
    var b = try stun.Builder.init(&rbuf, .request, .binding, txid);
    try b.addAttribute(0x8000, "");
    const ok = try stun.decode(try stun.bindingResponse(try stun.decode(b.finish()), from, &out, .{}));
    try testing.expectEqual(stun.Class.success_response, ok.class);
    var b2 = try stun.Builder.init(&rbuf, .request, .binding, txid);
    try b2.addAttribute(0x7FFF, "");
    const bad = try stun.decode(try stun.bindingResponse(try stun.decode(b2.finish()), from, &out, .{}));
    try testing.expectEqual(@as(u16, 420), (try bad.errorCode()).?.code);
    try testing.expectEqualSlices(u8, &.{ 0x7F, 0xFF }, bad.find(0x000A).?.value);
    // The STUN attributes a Binding server handles itself never earn a 420.
    for ([_]u16{ t_username, t_realm, t_nonce, t_pwalg, t_userhash }) |t| {
        var b3 = try stun.Builder.init(&rbuf, .request, .binding, txid);
        try b3.addAttribute(t, "xxxx");
        const r = try stun.decode(try stun.bindingResponse(try stun.decode(b3.finish()), from, &out, .{}));
        try testing.expectEqual(stun.Class.success_response, r.class);
    }
}

test "bindingResponse: 40 unknown attributes are reported as the first 32, each once" {
    var rbuf: [256]u8 = undefined;
    var out: [256]u8 = undefined;
    var b = try stun.Builder.init(&rbuf, .request, .binding, txid);
    for (0..40) |i| try b.addAttribute(@intCast(0x7000 + i), "");
    const r = try stun.decode(try stun.bindingResponse(try stun.decode(b.finish()), from, &out, .{}));
    try testing.expectEqual(@as(u16, 420), (try r.errorCode()).?.code);
    const v = r.find(0x000A).?.value;
    try testing.expectEqual(@as(usize, 64), v.len);
    for (0..32) |i| try testing.expectEqual(@as(u16, @intCast(0x7000 + i)), std.mem.readInt(u16, v[i * 2 ..][0..2], .big));
}

test "bindingResponse: the SHA-256 tag option is honoured at every legal length and falls back to 32 otherwise" {
    var rbuf: [128]u8 = undefined;
    var out: [256]u8 = undefined;
    var b = try stun.Builder.init(&rbuf, .request, .binding, txid);
    try b.addUsername("u");
    try b.addMessageIntegritySha256("k", 32);
    const req = try stun.decode(b.finish());
    const cases = [_]struct { opt: u8, want: usize }{
        .{ .opt = 16, .want = 16 },  .{ .opt = 20, .want = 20 }, .{ .opt = 24, .want = 24 },
        .{ .opt = 28, .want = 28 },  .{ .opt = 32, .want = 32 }, .{ .opt = 0, .want = 32 },
        .{ .opt = 12, .want = 32 },  .{ .opt = 15, .want = 32 }, .{ .opt = 17, .want = 32 },
        .{ .opt = 18, .want = 32 },  .{ .opt = 33, .want = 32 }, .{ .opt = 36, .want = 32 },
        .{ .opt = 255, .want = 32 },
    };
    for (cases) |c| {
        const r = try stun.decode(try stun.bindingResponse(req, from, &out, .{ .integrity_key_sha256 = "k", .integrity_sha256_tag = c.opt }));
        try testing.expectEqual(c.want, r.find(t_mi256).?.value.len);
        try testing.expect(r.verifyMessageIntegritySha256("k"));
    }
}

// ── parseUri ────────────────────────────────────────────────────────────────

test "parseUri: query rules, case and the transport key" {
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:example.org?transport=udp"));
    try testing.expectError(error.InvalidUri, stun.parseUri("stuns:example.org?transport=udp"));
    const u = try stun.parseUri("turn:example.org?TRANSPORT=TCP");
    try testing.expectEqual(stun.Uri.Transport.tcp, u.transport.?);
    const turns = try stun.parseUri("TURNS:example.org?Transport=udp");
    try testing.expectEqual(stun.Uri.Transport.udp, turns.transport.?);
    try testing.expectError(error.InvalidUri, stun.parseUri("turn:example.org?transpor=udp"));
    try testing.expectError(error.InvalidUri, stun.parseUri("turn:example.org?transport=sctp"));
}

test "parseUri: host rules" {
    try testing.expectError(error.InvalidUri, stun.parseUri("stun::3478"));
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:"));
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:[]"));
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:[::1"));
    try testing.expectEqualStrings("::ffff:1.2.3.4", (try stun.parseUri("stun:[::ffff:1.2.3.4]:99")).host);
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:[::g]"));
    // Every sub-delim / unreserved character an RFC 3986 reg-name may carry.
    for ("-._~%!$&'()*+,;=") |c| {
        var text: [16]u8 = undefined;
        const s = try std.fmt.bufPrint(&text, "stun:a{c}b", .{c});
        const u = try stun.parseUri(s);
        try testing.expectEqual(@as(usize, 3), u.host.len);
        try testing.expectEqual(c, u.host[1]);
    }
    for ("@/#\x80 ") |c| {
        var text: [16]u8 = undefined;
        const s = try std.fmt.bufPrint(&text, "stun:a{c}b", .{c});
        try testing.expectError(error.InvalidUri, stun.parseUri(s));
    }
    // Digits and letters.
    try testing.expectEqualStrings("a1.b2", (try stun.parseUri("stun:a1.b2")).host);
}

test "parseUri: ports" {
    try testing.expectEqual(@as(u16, 1), (try stun.parseUri("stun:h:1")).port);
    try testing.expectEqual(@as(u16, 65535), (try stun.parseUri("stun:h:65535")).port);
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:h:0"));
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:h:65536"));
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:h:"));
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:[::1]x3478"));
    try testing.expectError(error.InvalidUri, stun.parseUri("stun:[::1]x"));
    try testing.expectEqual(@as(u16, 3478), (try stun.parseUri("stun:[::1]")).port);
    try testing.expectEqual(@as(u16, 5349), (try stun.parseUri("turns:h")).port);
    try testing.expectEqual(@as(u16, 5349), (try stun.parseUri("stuns:h")).port);
    try testing.expectEqual(@as(u16, 3478), (try stun.parseUri("turn:h")).port);
}

// ── query: what the retransmission cap and the reply filter do on the wire ──

const ScriptServer = struct {
    io: std.Io,
    sock: std.Io.net.Socket,
    mode: enum { count, garbage, indication_first, no_mapped },
    seen: usize = 0,

    fn run(self: *ScriptServer) void {
        while (true) {
            var req_buf: [512]u8 = undefined;
            const inc = self.sock.receiveTimeout(self.io, &req_buf, .{ .duration = .{ .raw = .fromMilliseconds(300), .clock = .awake } }) catch return;
            const req = stun.decode(inc.data) catch return;
            self.seen += 1;
            var out: [128]u8 = undefined;
            switch (self.mode) {
                .count => {},
                .garbage => self.sock.send(self.io, &inc.from, "abc") catch return,
                .indication_first => {
                    var ib = stun.Builder.init(&out, .indication, .binding, req.transaction_id) catch return;
                    ib.addMappedAddress(netaddr.parseIp("198.51.100.66").?, 1, true) catch return;
                    self.sock.send(self.io, &inc.from, ib.finish()) catch return;
                    var b = stun.Builder.init(&out, .success_response, .binding, req.transaction_id) catch return;
                    b.addMappedAddress(netaddr.parseIp("203.0.113.9").?, 4989, true) catch return;
                    self.sock.send(self.io, &inc.from, b.finish()) catch return;
                    return;
                },
                .no_mapped => {
                    var b = stun.Builder.init(&out, .success_response, .binding, req.transaction_id) catch return;
                    b.addSoftware("no address here") catch return;
                    self.sock.send(self.io, &inc.from, b.finish()) catch return;
                    return;
                },
            }
        }
    }
};

fn scriptRun(mode: @FieldType(ScriptServer, "mode"), opts: stun.QueryOptions) !struct { result: anyerror!stun.AddressPort, seen: usize } {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const bind_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    const server_sock = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer server_sock.close(io);
    var srv: ScriptServer = .{ .io = io, .sock = server_sock, .mode = mode };
    var th = try std.Thread.spawn(.{}, ScriptServer.run, .{&srv});
    var buf: [512]u8 = undefined;
    const result = stun.query(io, server_sock.address, .{ 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7 }, &buf, opts);
    th.join();
    return .{ .result = result, .seen = srv.seen };
}

test "query: timeout_ms is a cap on sends too: a send due exactly at the cap is not made" {
    // RTO 100 ms, cap 100 ms: the first send is at 0, the second would be at
    // 100 ms = the cap, so a silent server sees exactly one request.
    const r = try scriptRun(.count, .{ .rto_ms = 100, .timeout_ms = 100 });
    try testing.expectError(error.Timeout, r.result);
    try testing.expectEqual(@as(usize, 1), r.seen);
}

test "query: a datagram that is not STUN is reported, not swallowed, when nothing better comes" {
    const r = try scriptRun(.garbage, .{ .rto_ms = 20, .max_requests = 2, .last_wait_factor = 4, .timeout_ms = 3000 });
    try testing.expectError(error.Truncated, r.result);
    try testing.expectEqual(@as(usize, 2), r.seen);
}

test "query: an indication for our transaction is not the answer" {
    const r = try scriptRun(.indication_first, .{ .rto_ms = 40, .timeout_ms = 3000 });
    const ap = try r.result;
    try testing.expect(ap.ip.eql(netaddr.parseIp("203.0.113.9").?));
    try testing.expectEqual(@as(u16, 4989), ap.port);
}

test "query: a success response without a mapped address is NoMappedAddress" {
    const r = try scriptRun(.no_mapped, .{ .rto_ms = 40, .timeout_ms = 3000 });
    try testing.expectError(error.NoMappedAddress, r.result);
}
