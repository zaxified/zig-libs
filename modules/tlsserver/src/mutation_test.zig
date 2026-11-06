// SPDX-License-Identifier: MIT

//! Tests added by the whole-module mutation run of 2026-11-06: each pins a
//! guard that no earlier test exercised (a mutant of it survived).

const std = @import("std");
const testing = std.testing;
const record = @import("record.zig");
const inbound = @import("inbound.zig");
const hello = @import("hello.zig");
const messages = @import("messages.zig");
const outbound = @import("outbound.zig");
const clientauth = @import("clientauth.zig");
const server = @import("server.zig");
const alert = @import("alert.zig");

fn allZero(b: []const u8) bool {
    for (b) |c| if (c != 0) return false;
    return true;
}

test "record: init and initKeyIv refuse a secret or key one octet too long or too short" {
    var p: record.Protection = undefined;
    const buf: [64]u8 = @splat(7);
    const iv: [12]u8 = @splat(1);
    const Case = struct { s: record.CipherSuite, secret: usize, key: usize };
    for ([_]Case{
        .{ .s = .aes_128_gcm_sha256, .secret = 32, .key = 16 },
        .{ .s = .aes_256_gcm_sha384, .secret = 48, .key = 32 },
        .{ .s = .chacha20_poly1305_sha256, .secret = 32, .key = 32 },
    }) |c| {
        try testing.expectError(error.BadKeyLength, record.Protection.init(&p, c.s, buf[0 .. c.secret + 1]));
        try testing.expectError(error.BadKeyLength, record.Protection.init(&p, c.s, buf[0 .. c.secret - 1]));
        try record.Protection.init(&p, c.s, buf[0..c.secret]);
        try testing.expectError(error.BadKeyLength, record.Protection.initKeyIv(&p, c.s, buf[0 .. c.key + 1], &iv));
        try testing.expectError(error.BadKeyLength, record.Protection.initKeyIv(&p, c.s, buf[0 .. c.key - 1], &iv));
        try record.Protection.initKeyIv(&p, c.s, buf[0..c.key], &iv);
    }
}

test "record: trafficKeyIv clears the half of a 16-octet key it does not fill; wipe zeroes the state" {
    var key: [32]u8 = @splat(0xff);
    var iv: [12]u8 = undefined;
    const secret: [32]u8 = @splat(3);
    const n = try record.Protection.trafficKeyIv(.aes_128_gcm_sha256, &secret, &key, &iv);
    try testing.expectEqual(@as(usize, 16), n);
    try testing.expect(allZero(key[16..]));

    var p: record.Protection = undefined;
    try record.Protection.init(&p, .chacha20_poly1305_sha256, &secret);
    p.seq = 5;
    p.wipe();
    try testing.expect(allZero(std.mem.asBytes(&p)));
}

test "record: open refuses a record shorter than a header, longer than it declares, and over the ciphertext limit" {
    var p: record.Protection = undefined;
    const secret: [32]u8 = @splat(3);
    try record.Protection.init(&p, .aes_128_gcm_sha256, &secret);
    var rec: [5 + 16641 + 1]u8 = @splat(0);
    for (0..5) |n| try testing.expectError(error.BadRecordLength, p.open(rec[0..n]));
    // Declares 17 octets, carries 18.
    rec[0..5].* = .{ 23, 3, 3, 0, 17 };
    try testing.expectError(error.BadRecordLength, p.open(rec[0 .. 5 + 18]));
    // Exactly the ciphertext limit is read (and fails its MAC); one more is an overflow.
    rec[0..5].* = .{ 23, 3, 3, 0x41, 0x00 };
    try testing.expectError(error.BadRecordMac, p.open(rec[0 .. 5 + 16640]));
    rec[0..5].* = .{ 23, 3, 3, 0x41, 0x01 };
    try testing.expectError(error.RecordOverflow, p.open(rec[0 .. 5 + 16641]));
}

test "record: an inner content type of 1 is a type, not padding" {
    var tx: record.Protection = undefined;
    var rx: record.Protection = undefined;
    const secret: [32]u8 = @splat(3);
    try record.Protection.init(&tx, .aes_128_gcm_sha256, &secret);
    try record.Protection.init(&rx, .aes_128_gcm_sha256, &secret);
    var buf: [64]u8 = undefined;
    @memcpy(buf[5..8], "abc");
    const t: record.ContentType = @fromBackingInt(1);
    const sealed = try tx.seal(&buf, 3, t, 0);
    const o = try rx.open(sealed);
    try testing.expect(o.content_type == t);
    try testing.expectEqualStrings("abc", o.content);
}

var mut_joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;

test "inbound: a plaintext record over 2^14 is refused at its header; a skipped early-data record may be ciphertext-sized" {
    var in = inbound.Inbound.init(&mut_joiner);
    var hdr = [_]u8{ 22, 3, 3, 0x40, 0x01 };
    try testing.expectError(error.RecordOverflow, in.next(&hdr));
    hdr = .{ 22, 3, 3, 0x40, 0x00 };
    try testing.expect((try in.next(&hdr)).event == .need_more);
    // Early data skipped after a HelloRetryRequest is ciphertext: 2^14 + 1 passes the header check.
    var in2 = inbound.Inbound.init(&mut_joiner);
    in2.skip_early = 100;
    hdr = .{ 23, 3, 3, 0x40, 0x01 };
    try testing.expect((try in2.next(&hdr)).event == .need_more);
}

test "inbound: a plaintext alert while a handshake message is half held is interleaving" {
    var in = inbound.Inbound.init(&mut_joiner);
    // A handshake header announcing 10 octets, 2 of them present.
    var rec = [_]u8{ 22, 3, 3, 0, 6, 1, 0, 0, 10, 0xaa, 0xbb, 21, 3, 3, 0, 2, 2, 40 };
    try testing.expectError(error.UnexpectedMessage, in.next(&rec));
}

test "inbound: alertFor maps each error to its alert" {
    const D = alert.Description;
    try testing.expectEqual(@as(?D, .unexpected_message), inbound.alertFor(error.UnexpectedMessage));
    try testing.expectEqual(@as(?D, .decode_error), inbound.alertFor(error.DecodeError));
    try testing.expectEqual(@as(?D, .decode_error), inbound.alertFor(error.HandshakeTooLarge));
    try testing.expectEqual(@as(?D, .record_overflow), inbound.alertFor(error.RecordOverflow));
    try testing.expectEqual(@as(?D, .bad_record_mac), inbound.alertFor(error.BadRecordMac));
    try testing.expectEqual(@as(?D, .illegal_parameter), inbound.alertFor(error.IllegalParameter));
    try testing.expectEqual(@as(?D, .internal_error), inbound.alertFor(error.SequenceExhausted));
    try testing.expectEqual(@as(?D, null), inbound.alertFor(error.PeerAborted));
}

test "inbound: Joiner.reset forgets delivered and held octets; Inbound.wipe drops the key and the joiner" {
    var buf: [100]u8 = undefined;
    var j = inbound.Joiner.init(&buf);
    try j.push(&.{ 1, 0, 0, 0, 2, 0, 0, 0 });
    _ = (try j.next()).?;
    try testing.expect(!j.isEmpty());
    j.reset();
    try testing.expect(j.isEmpty());
    try testing.expect(allZero(buf[0..8]));

    var in = inbound.Inbound.init(&mut_joiner);
    const secret: [32]u8 = @splat(4);
    try in.installRx(.aes_128_gcm_sha256, &secret);
    try testing.expect(in.protected);
    try in.joiner.push(&.{ 1, 0, 0, 4, 1, 2 });
    in.wipe();
    try testing.expect(!in.protected);
    try testing.expect(allZero(std.mem.asBytes(&in.rx)));
    try testing.expect(allZero(mut_joiner[0..6]));
    try testing.expect(in.joiner.isEmpty());
}

const Ext = struct { u16, []const u8 };

fn helloBody(buf: []u8, exts: []const Ext) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeInt(u16, 0x0303, .big) catch unreachable;
    w.splatByteAll(7, 32) catch unreachable;
    w.writeByte(0) catch unreachable;
    w.writeInt(u16, 2, .big) catch unreachable;
    w.writeInt(u16, 0x1301, .big) catch unreachable;
    w.writeAll(&.{ 1, 0 }) catch unreachable;
    var total: usize = 0;
    for (exts) |e| total += 4 + e[1].len;
    w.writeInt(u16, @intCast(total), .big) catch unreachable;
    for (exts) |e| {
        w.writeInt(u16, e[0], .big) catch unreachable;
        w.writeInt(u16, @intCast(e[1].len), .big) catch unreachable;
        w.writeAll(e[1]) catch unreachable;
    }
    return w.buffered();
}

test "hello: malformed extension bodies are decode errors, well-formed ones are kept" {
    var buf: [512]u8 = undefined;
    const bad = [_]Ext{
        .{ 10, &.{ 0, 3, 0, 1, 2 } }, // supported_groups: odd
        .{ 10, &.{ 0, 0 } }, // empty
        .{ 13, &.{ 0, 3, 0, 1, 2 } },
        .{ 50, &.{ 0, 3, 0, 1, 2 } },
        .{ 34, &.{ 0, 3, 0, 1, 2 } },
        .{ 43, &.{ 3, 3, 4, 3 } }, // supported_versions: odd
        .{ 11, &.{0} }, // ec_point_formats: empty
        .{ 11, &.{ 1, 0, 9 } }, // trailing octet
        .{ 19, &.{0} },
        .{ 20, &.{0} },
        .{ 44, &.{ 0, 0 } }, // cookie: empty
        .{ 45, &.{0} },
        .{ 5, &.{ 1, 0, 3, 0, 5, 0, 0, 0 } }, // status_request: a responder id cut short
        .{ 5, &.{ 1, 0, 0, 0, 0, 9 } }, // trailing octet
        .{ 41, &.{ 0, 0, 0, 2, 1, 0xaa } }, // PSK: no identities
        .{ 41, &.{ 0, 7, 0, 1, 0xaa, 0, 0, 0, 0, 0, 0 } }, // no binders
        .{ 41, &.{ 0, 7, 0, 1, 0xaa, 0, 0, 0, 0, 0, 2, 1, 0xaa, 9 } }, // trailing octet
    };
    for (bad) |e| {
        const b = helloBody(&buf, &.{e});
        try testing.expectError(error.DecodeError, hello.parseClientHello(b));
    }
    const good = helloBody(&buf, &.{
        .{ 10, &.{ 0, 2, 0, 29 } },
        .{ 13, &.{ 0, 2, 4, 3 } },
        .{ 19, &.{ 1, 0 } },
        .{ 20, &.{ 1, 2 } },
        .{ 44, &.{ 0, 1, 9 } },
        .{ 45, &.{ 1, 1 } },
    });
    const ch = try hello.parseClientHello(good);
    try testing.expect(ch.supported_groups_raw != null);
    try testing.expect(ch.signature_algorithms_raw != null);
    try testing.expect(ch.client_certificate_types != null);
    try testing.expect(ch.server_certificate_types != null);
    try testing.expect(ch.cookie != null);
    try testing.expect(ch.psk_key_exchange_modes != null);
    try testing.expectEqual(@as(usize, 6), ch.extension_count);
}

test "messages: a selected PSK identity is written; the u16 list length is exact at 65535" {
    const r: [32]u8 = @splat(1);
    var out: [200]u8 = undefined;
    const m = try messages.serverHello(&out, .{ .random = &r, .legacy_session_id_echo = "", .cipher_suite = 0x1301, .key_share = null, .selected_identity = 7 });
    try testing.expectEqualSlices(u8, &.{ 0, 41, 0, 2, 0, 7 }, m[44..50]);

    const big = try testing.allocator.alloc(u8, 70000);
    defer testing.allocator.free(big);
    const ok = try testing.allocator.alloc(u8, 65531);
    defer testing.allocator.free(ok);
    @memset(ok, 0);
    const one = try messages.encryptedExtensions(big, &.{.{ .type = 99, .data = ok }});
    try testing.expectEqual(@as(usize, 4 + 2 + 4 + 65531), one.len);
    const over = try testing.allocator.alloc(u8, 65532);
    defer testing.allocator.free(over);
    @memset(over, 0);
    try testing.expectError(error.FieldTooLong, messages.encryptedExtensions(big, &.{.{ .type = 99, .data = over }}));
}

test "messages: a certificate or OCSP staple over 2^24 - 1 octets is FieldTooLong" {
    const huge = try testing.allocator.alloc(u8, 1 << 24);
    defer testing.allocator.free(huge);
    var out: [128]u8 = undefined;
    try testing.expectError(error.FieldTooLong, messages.certificate(&out, "", &.{.{ .cert_data = huge }}));
    try testing.expectError(error.FieldTooLong, messages.certificate(&out, "", &.{.{ .cert_data = &.{ 1, 2, 3 }, .ocsp_response = huge }}));
}

test "clientauth: an Ed25519 key of the wrong length is a bad certificate" {
    var der: [2 + 41]u8 = undefined;
    der[0..14].* = .{ 0x30, 0x29, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x20, 0x00, 0, 0 };
    @memset(der[12..], 9);
    try testing.expectError(error.BadCertificate, clientauth.rawPublicKey(&der));
}

test "outbound: wipe and wipeKey zero the key, the buffer written so far and the QUIC levels" {
    var buf: [1024]u8 = undefined;
    @memset(&buf, 0);
    var ob = outbound.Outbound.init(&buf);
    const secret: [32]u8 = @splat(5);
    try ob.installTx(.aes_128_gcm_sha256, &secret);
    try ob.write(.handshake, "hello world");
    const n = ob.pending().len;
    try testing.expect(n > 11);
    try testing.expect(!allZero(buf[0..n]));
    ob.wipeKey();
    try testing.expect(!ob.protected);
    try testing.expect(allZero(std.mem.asBytes(&ob.tx)));
    try ob.installTx(.aes_128_gcm_sha256, &secret);
    ob.wipe();
    try testing.expect(!ob.protected);
    try testing.expect(allZero(std.mem.asBytes(&ob.tx)));
    try testing.expect(allZero(buf[0..n]));
    try testing.expectEqual(@as(usize, 0), ob.len);

    var q = outbound.Outbound.init(&buf);
    q.quic = true;
    q.quic_lens[0] = 5;
    try testing.expectError(error.BadKeyLength, q.installTx(.aes_128_gcm_sha256, secret[0..31]));
    q.wipe();
    try testing.expect(allZero(std.mem.asBytes(&q.quic_lens)));
}

test "server: alertFor maps each failure to its alert" {
    const D = alert.Description;
    const E = server.Error;
    const table = [_]struct { E, ?D }{
        .{ error.HandshakeFailure, .handshake_failure },
        .{ error.ProtocolVersion, .protocol_version },
        .{ error.MissingExtension, .missing_extension },
        .{ error.DecryptError, .decrypt_error },
        .{ error.AccessDenied, .access_denied },
        .{ error.NoApplicationProtocol, .no_application_protocol },
        .{ error.InternalError, .internal_error },
        .{ error.OutputFull, null },
        .{ error.Closed, null },
        .{ error.NotConnected, null },
        .{ error.WrongTransport, null },
        .{ error.NoSignatureRequested, null },
        .{ error.TooManyKeyUpdates, .unexpected_message },
        .{ error.TooMuchEarlyData, .unexpected_message },
        .{ error.CertificateRequired, .certificate_required },
        .{ error.EchInvalidInner, .illegal_parameter },
        .{ error.EchInvalidOuterExtension, .illegal_parameter },
        .{ error.EchInvalidPadding, .illegal_parameter },
        .{ error.EchOfferChanged, .illegal_parameter },
        .{ error.EchDecryptionFailed, .decrypt_error },
        .{ error.UnsupportedExtension, .unsupported_extension },
        .{ error.BadCertificate, .bad_certificate },
        .{ error.UnsupportedCertificate, .unsupported_certificate },
        .{ error.CertificateRevoked, .certificate_revoked },
        .{ error.CertificateExpired, .certificate_expired },
        .{ error.UnknownCa, .unknown_ca },
        .{ error.CertificateUnknown, .certificate_unknown },
        .{ error.DecodeError, .decode_error },
        .{ error.IllegalParameter, .illegal_parameter },
    };
    for (table) |t| try testing.expectEqual(t[1], server.alertFor(t[0]));
}
