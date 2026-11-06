// SPDX-License-Identifier: MIT

//! Tests added by wave 2 of the whole-module mutation run of 2026-11-06:
//! each decides a mutant of wave 1 that survived (guards, error mappings and
//! size arithmetic of the record layer; the handshake engine's are in
//! `mutation3_test.zig`).

const std = @import("std");
const testing = std.testing;
const record = @import("record.zig");
const inbound = @import("inbound.zig");
const outbound = @import("outbound.zig");

const secret32: [32]u8 = @splat(4);

/// A protected record carrying `inner` (content, type, padding) as it is, sealed under
/// `secret32` at sequence 0 with AES-128-GCM: for inner texts `Protection.seal` refuses.
fn sealInner(out: []u8, inner: []const u8) []u8 {
    var key: [32]u8 = undefined;
    var iv: [12]u8 = undefined;
    _ = record.Protection.trafficKeyIv(.aes_128_gcm_sha256, &secret32, &key, &iv) catch unreachable;
    const len = inner.len + record.tag_len;
    out[0..5].* = .{ 23, 3, 3, @intCast(len >> 8), @intCast(len & 0xff) };
    var tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(out[5..][0..inner.len], &tag, inner, out[0..5], iv, key[0..16].*);
    @memcpy(out[5 + inner.len ..][0..16], &tag);
    return out[0 .. 5 + len];
}

var joiner_buf: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
var rec_buf: [5 + 16402 + 16]u8 = undefined;

fn protectedIn() !inbound.Inbound {
    var in = inbound.Inbound.init(&joiner_buf);
    try in.installRx(.aes_128_gcm_sha256, &secret32);
    return in;
}

test "record: trafficKeyIv refuses a secret of the wrong length" {
    var key: [32]u8 = undefined;
    var iv: [12]u8 = undefined;
    const buf: [64]u8 = @splat(7);
    const Case = struct { s: record.CipherSuite, n: usize };
    for ([_]Case{ .{ .s = .aes_128_gcm_sha256, .n = 32 }, .{ .s = .aes_256_gcm_sha384, .n = 48 }, .{ .s = .chacha20_poly1305_sha256, .n = 32 } }) |c| {
        try testing.expectError(error.BadKeyLength, record.Protection.trafficKeyIv(c.s, buf[0 .. c.n + 1], &key, &iv));
        try testing.expectError(error.BadKeyLength, record.Protection.trafficKeyIv(c.s, buf[0 .. c.n - 1], &key, &iv));
        _ = try record.Protection.trafficKeyIv(c.s, buf[0..c.n], &key, &iv);
    }
}

test "inbound: a record that opens but whose inner text is over 2^14 + 1, all zero, or out of sequence" {
    // Inner text of 2^14 + 2 octets (content, then type): RecordOverflow after the MAC.
    var inner: [16386]u8 = @splat(1);
    inner[16385] = 23;
    var in = try protectedIn();
    in.app_data_ok = true;
    try testing.expectError(error.RecordOverflow, in.next(sealInner(&rec_buf, &inner)));
    // The same bound exactly is application data.
    in = try protectedIn();
    in.app_data_ok = true;
    const r = try in.next(sealInner(&rec_buf, inner[1..]));
    try testing.expectEqual(@as(usize, 16384), r.event.app_data.len);
    // An inner text of zeros has no content type (RFC 8446 §5.4): unexpected_message.
    in = try protectedIn();
    try testing.expectError(error.UnexpectedMessage, in.next(sealInner(&rec_buf, &.{0})));
    // A receive sequence at 2^64 - 1 is exhausted, whatever the record.
    in = try protectedIn();
    in.rx.seq = std.math.maxInt(u64);
    try testing.expectError(error.SequenceExhausted, in.next(sealInner(&rec_buf, &.{ 'h', 'i', 23 })));
}

test "inbound: an early-data record that fails its MAC is skipped only within the budget, to the octet" {
    var in = try protectedIn();
    in.skip_early = 21;
    var rec: [26]u8 = @splat(9);
    rec[0..5].* = .{ 23, 3, 3, 0, 21 };
    const r = try in.next(&rec);
    try testing.expect(r.event == .need_more);
    try testing.expectEqual(@as(usize, 26), r.consumed);
    try testing.expectEqual(@as(usize, 0), in.skip_early);
    in = try protectedIn();
    in.skip_early = 20;
    try testing.expectError(error.BadRecordMac, in.next(&rec));
}

test "inbound: while protected, a plaintext record over 2^14 is an overflow and a plaintext alert is at most two octets" {
    var in = try protectedIn();
    var hdr = [_]u8{ 22, 3, 3, 0x40, 0x01 };
    try testing.expectError(error.RecordOverflow, in.next(&hdr));
    in = try protectedIn();
    var alert3 = [_]u8{ 21, 3, 3, 0, 3, 1, 0, 0 };
    try testing.expectError(error.UnexpectedMessage, in.next(&alert3));
}

test "inbound: plaintext application data is not skipped while a handshake message is half held" {
    var in = inbound.Inbound.init(&joiner_buf);
    in.skip_early = 100;
    var rec = [_]u8{ 22, 3, 3, 0, 6, 1, 0, 0, 10, 0xaa, 0xbb, 23, 3, 3, 0, 1, 0 };
    try testing.expectError(error.UnexpectedMessage, in.next(&rec));
}

test "inbound: a protected alert or application data while a handshake message is half held is interleaving" {
    var in = try protectedIn();
    try in.joiner.push(&.{ 1, 0, 0, 10, 0xaa, 0xbb });
    try testing.expectError(error.UnexpectedMessage, in.next(sealInner(&rec_buf, &.{ 2, 40, 21 })));
    in = try protectedIn();
    in.app_data_ok = true;
    try in.joiner.push(&.{ 1, 0, 0, 10, 0xaa, 0xbb });
    try testing.expectError(error.UnexpectedMessage, in.next(sealInner(&rec_buf, &.{ 'h', 'i', 23 })));
}

test "inbound: more warning alerts than max_warning_alerts are unexpected_message" {
    var in = inbound.Inbound.init(&joiner_buf);
    var stream: [7 * 5]u8 = undefined;
    for (0..5) |i| stream[i * 7 ..][0..7].* = .{ 21, 3, 3, 0, 2, 1, 90 };
    try testing.expectError(error.UnexpectedMessage, in.next(&stream));
    // Four are ignored.
    in = inbound.Inbound.init(&joiner_buf);
    const r = try in.next(stream[0 .. 4 * 7]);
    try testing.expect(r.event == .need_more);
}

test "outbound: slot reserves one more record overhead when the free space is a whole number of records" {
    var buf: [outbound.alert_reserve + 2 * 517]u8 = undefined;
    var ob = outbound.Outbound.init(&buf);
    ob.max_fragment = 512;
    // 1034 free, 517 per record: exactly two records, 5 octets of header each.
    try testing.expectEqual(@as(usize, 1034 - 2 * 5), ob.slot().len);
}

test "outbound: max_fragment above 2^14 is clamped to 2^14" {
    var buf: [3 * record.max_record_len]u8 = undefined;
    var ob = outbound.Outbound.init(&buf);
    ob.max_fragment = 0xffff;
    const s = ob.slot();
    @memset(s[0 .. record.max_plaintext_len + 1], 0x55);
    try ob.commit(.handshake, record.max_plaintext_len + 1);
    const h = record.parseHeader(ob.pending()[0..5]);
    try testing.expectEqual(@as(u16, record.max_plaintext_len), h.length);
    const h2 = record.parseHeader(ob.pending()[5 + h.length ..][0..5]);
    try testing.expectEqual(@as(u16, 1), h2.length);
}

test "outbound: committing nothing makes one empty record" {
    var buf: [128]u8 = undefined;
    var ob = outbound.Outbound.init(&buf);
    try ob.commit(.application_data, 0);
    try testing.expectEqualSlices(u8, &.{ 23, 3, 3, 0, 0 }, ob.pending());
}

test "outbound: write fits a buffer to the octet" {
    var buf: [7]u8 = undefined;
    var ob = outbound.Outbound.init(&buf);
    try ob.write(.alert, &.{ 1, 0 });
    try testing.expectEqual(@as(usize, 7), ob.len);
    ob.discard(7);
    try testing.expectError(error.OutputFull, ob.write(.alert, &.{ 1, 0, 0 }));
}

test "outbound: QUIC keeps handshake data only, to the octet, and wipes what write copied" {
    var buf: [16]u8 = @splat(0);
    var q = outbound.Outbound.init(&buf);
    q.quic = true;
    try testing.expectError(error.OutputFull, q.commit(.handshake, 17));
    try q.commit(.handshake, 16);
    try testing.expectEqual(@as(usize, 16), q.len);
    q.wipe();
    // write: only handshake data, and everything it copied is wiped.
    var q2 = outbound.Outbound.init(&buf);
    q2.quic = true;
    try q2.write(.alert, &.{ 1, 0 });
    try q2.write(.change_cipher_spec, &.{1});
    try testing.expectEqual(@as(usize, 0), q2.len);
    try q2.write(.handshake, "abc");
    try testing.expectEqual(@as(usize, 3), q2.len);
    q2.wipe();
    try testing.expect(std.mem.allEqual(u8, &buf, 0));
}
