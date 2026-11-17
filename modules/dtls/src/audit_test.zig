// SPDX-License-Identifier: MIT

//! Killing tests from the 2026-11-17 whole-module mutation audit (see SPEC
//! "Audit 2026-11-17"). Each test pins a boundary or a refusal that no other
//! test reached: exact-size buffers, one-past-the-limit lengths, and the
//! state a helper must leave behind.

const std = @import("std");
const testing = std.testing;
const record = @import("record.zig");
const record12 = @import("record12.zig");
const handshake = @import("handshake.zig");
const flight = @import("flight.zig");
const aead = @import("aead.zig");
const prf12 = @import("prf12.zig");
const suitehash = @import("suitehash.zig");
const ep = @import("Endpoint.zig");
const conn13 = @import("Connection.zig");

// ── record.zig ───────────────────────────────────────────────────────────

test "audit: encodeUnified needs exactly its header length, for every header shape" {
    const cid = [_]u8{ 1, 2, 3 };
    for ([_]?[]const u8{ null, &cid }) |c| for ([_]record.SeqNumLen{ .short, .long }) |sl| for ([_]?u16{ null, 7 }) |len| {
        const hdr: record.UnifiedHeader = .{ .cid = c, .seq_len = sl, .length = len, .epoch_low = 3, .seq_wire = 0x12 };
        var big: [32]u8 = undefined;
        const want = (try record.encodeUnified(hdr, &big)).len;
        try testing.expectEqual(1 + (if (c) |x| x.len else 0) + @as(usize, if (sl == .short) 1 else 2) + @as(usize, if (len != null) 2 else 0), want);
        var exact: [32]u8 = undefined;
        try testing.expectEqualSlices(u8, big[0..want], try record.encodeUnified(hdr, exact[0..want]));
        try testing.expectError(error.BufferTooShort, record.encodeUnified(hdr, exact[0 .. want - 1]));
    };
}

test "audit: encodePlaintext refuses a 12-byte buffer and fills a 13-byte one" {
    var out: [13]u8 = undefined;
    const hdr: record.PlaintextHeader = .{ .content_type = 22, .epoch = 1, .sequence_number = 2, .length = 3 };
    try testing.expectError(error.BufferTooShort, record.encodePlaintext(hdr, out[0..12]));
    try testing.expectEqual(@as(usize, 13), (try record.encodePlaintext(hdr, &out)).len);
}

test "audit: reconstructSequenceNumber at the half-window edges and at the top of the 48-bit space (RFC 9000 A.3)" {
    // candidate + hwin == expected: still moves up a window (`<=`).
    try testing.expectEqual(@as(u48, 0x340), record.reconstructSequenceNumber(0x2BF, .short, 0x40));
    // candidate == expected + hwin: stays (`>`, not `>=`).
    try testing.expectEqual(@as(u48, 0x290), record.reconstructSequenceNumber(0x20F, .short, 0x90));
    // Moving up would leave the 48-bit space: the candidate stays below.
    try testing.expectEqual(@as(u48, 0xFFFF_FFFF_FF10), record.reconstructSequenceNumber(0xFFFF_FFFF_FFE0, .short, 0x10));
}

// ── record12.zig ─────────────────────────────────────────────────────────

test "audit: record12 seal/open with exact buffers, an empty plaintext, and a fragment past u16" {
    for ([_]record12.Bulk{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 }) |bulk| {
        const keys: record12.DirKeys = .{ .bulk = bulk, .key = @splat(0x11), .iv = @splat(0x22) };
        const pt = "exact";
        const n = record.plaintext_header_len + pt.len + bulk.overhead();
        var out: [64]u8 = undefined;
        try testing.expectError(error.BufferTooShort, record12.seal(&keys, 1, 5, 23, pt, out[0 .. n - 1]));
        const rec = try record12.seal(&keys, 1, 5, 23, pt, out[0..n]);
        try testing.expectEqual(n, rec.len);
        const hdr = try record.decodePlaintext(rec);
        var o: [16]u8 = undefined;
        try testing.expectError(error.BufferTooShort, record12.open(&keys, hdr, rec[13..], o[0 .. pt.len - 1]));
        try testing.expectEqualStrings(pt, try record12.open(&keys, hdr, rec[13..], o[0..pt.len]));
        // An empty plaintext: the fragment is exactly the overhead.
        const e = try record12.seal(&keys, 1, 6, 23, "", &out);
        const eh = try record.decodePlaintext(e);
        try testing.expectEqual(@as(usize, 0), (try record12.open(&keys, eh, e[13..], &o)).len);
        try testing.expectError(error.RecordTooShort, record12.open(&keys, eh, e[13 .. e.len - 1], &o));
    }
    // A fragment longer than u16 is refused, not truncated into the length field.
    const keys: record12.DirKeys = .{ .bulk = .chacha20_poly1305, .key = @splat(0x11), .iv = @splat(0x22) };
    const big = try testing.allocator.alloc(u8, 70000);
    defer testing.allocator.free(big);
    @memset(big, 0);
    try testing.expectError(error.BufferTooShort, record12.seal(&keys, 1, 1, 23, big[0 .. 65536 - 16], big));
    // ... while exactly u16 fits (fragment 65535 bytes).
    const out = try testing.allocator.alloc(u8, 13 + 65535);
    defer testing.allocator.free(out);
    try testing.expectEqual(@as(usize, 13 + 65535), (try record12.seal(&keys, 1, 1, 23, big[0 .. 65535 - 16], out)).len);
}

// ── handshake.zig ────────────────────────────────────────────────────────

test "audit: Reassembler takes a message exactly its buffer size, refuses one byte more" {
    var buf: [8]u8 = undefined;
    var seen: [8]bool = undefined;
    var r = handshake.Reassembler.init(&buf, &seen);
    r.reset();
    const body = "12345678";
    const got = try r.feed(.{ .msg_type = 1, .length = 8, .message_seq = 0, .fragment_offset = 0, .fragment_length = 8 }, body);
    try testing.expectEqualStrings(body, got.?);
    try testing.expectError(error.BufferTooSmall, r.feed(.{ .msg_type = 1, .length = 9, .message_seq = 1, .fragment_offset = 0, .fragment_length = 9 }, "123456789"));
    // The same limits when an empty fragment latched a header and a
    // disagreeing one re-latches (nothing committed yet).
    try testing.expectEqual(@as(?[]const u8, null), try r.feed(.{ .msg_type = 1, .length = 4, .message_seq = 2, .fragment_offset = 0, .fragment_length = 0 }, ""));
    try testing.expectError(error.BufferTooSmall, r.feed(.{ .msg_type = 1, .length = 9, .message_seq = 2, .fragment_offset = 0, .fragment_length = 9 }, "123456789"));
    try testing.expectEqualStrings(body, (try r.feed(.{ .msg_type = 1, .length = 8, .message_seq = 2, .fragment_offset = 0, .fragment_length = 8 }, body)).?);
}

// ── flight.zig ───────────────────────────────────────────────────────────

test "audit: encodeAck refuses more than u16 bytes of record numbers and a short buffer" {
    const rns = try testing.allocator.alloc(flight.RecordNumber, 4096);
    defer testing.allocator.free(rns);
    @memset(rns, .{ .epoch = 0, .sequence_number = 0 });
    const big = try testing.allocator.alloc(u8, 2 + 4096 * 16);
    defer testing.allocator.free(big);
    try testing.expectError(error.TooManyRecords, flight.encodeAck(rns, big));
    var out: [2 + 2 * 16]u8 = undefined;
    try testing.expectError(error.BufferTooShort, flight.encodeAck(rns[0..2], out[0 .. out.len - 1]));
    try testing.expectEqual(out.len, (try flight.encodeAck(rns[0..2], &out)).len);
}

test "audit: decodeAck refuses a body that is not a whole number of record numbers" {
    var buf: [2 + 17]u8 = @splat(0);
    std.mem.writeInt(u16, buf[0..2], 17, .big);
    var out: [4]flight.RecordNumber = undefined;
    try testing.expectError(error.BufferTooShort, flight.decodeAck(&buf, &out));
}

test "audit: FlightTracker — an ACK matches epoch AND sequence, a repeat ACK is a no-op, clear empties" {
    var sent: [4]flight.RecordNumber = undefined;
    var t = flight.FlightTracker.init(&sent);
    try t.markSent(.{ .epoch = 2, .sequence_number = 7 });
    try t.markSent(.{ .epoch = 2, .sequence_number = 8 });
    t.markAcked(.{ .epoch = 3, .sequence_number = 7 }); // other epoch: not ours
    try testing.expectEqual(@as(usize, 2), t.pending().len);
    t.markAcked(.{ .epoch = 2, .sequence_number = 8 });
    t.markAcked(.{ .epoch = 2, .sequence_number = 8 }); // stale slot must not match
    try testing.expectEqual(@as(usize, 1), t.pending().len);
    t.clear();
    try testing.expect(t.allAcked());
}

// ── aead.zig ─────────────────────────────────────────────────────────────

test "audit: Protection opens an empty body (ciphertext == tag) and refuses a short output buffer" {
    const P = aead.Protection(@import("aesgcm").Aes128Gcm);
    const key: [P.key_length]u8 = @splat(7);
    const iv: [P.nonce_length]u8 = @splat(9);
    var ct: [32]u8 = undefined;
    const n = try P.protect(&key, iv, 1, 2, "", "ad", &ct);
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try P.unprotect(&key, iv, 1, 2, ct[0..n], "ad", &out));
    const mlen = try P.protect(&key, iv, 1, 3, "abcd", "ad", &ct);
    try testing.expectError(error.BufferTooShort, P.unprotect(&key, iv, 1, 3, ct[0..mlen], "ad", out[0..3]));
}

// ── prf12.zig / suitehash.zig ────────────────────────────────────────────

test "audit: prf12 exporter context: 65535 bytes fit, 65536 are ContextTooLong" {
    const master: [prf12.master_secret_len]u8 = @splat(1);
    const r: [32]u8 = @splat(2);
    const ctx = try testing.allocator.alloc(u8, 65536);
    defer testing.allocator.free(ctx);
    @memset(ctx, 3);
    var out: [16]u8 = undefined;
    try prf12.exportKeyingMaterial(.sha256, &master, &r, &r, "EXPERIMENTAL x", ctx[0..65535], &out);
    try testing.expectError(error.ContextTooLong, prf12.exportKeyingMaterial(.sha256, &master, &r, &r, "EXPERIMENTAL x", ctx, &out));
}

test "audit: macEql is false when EITHER side has the wrong length" {
    const a: [32]u8 = @splat(5);
    try testing.expect(suitehash.macEql(.sha256, &a, &a));
    try testing.expect(!suitehash.macEql(.sha256, a[0..31], &a));
    try testing.expect(!suitehash.macEql(.sha256, &a, a[0..31]));
}

// ── Endpoint.zig ─────────────────────────────────────────────────────────

test "audit: Endpoint hands over to 1.2 only on NegotiatedDtls12, not on any other 1.3 error" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x31)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    const both = [_]conn13.ProtocolVersion{ .dtls13, .dtls12 };
    var c = try ep.Endpoint.clientInit(.{ .role = .client, .versions = &both, .psk_identity = "id", .psk = "a pre-shared key" });
    defer c.deinit();
    var out: [4096]u8 = undefined;
    _ = try c.startHandshake(rnd, 0, &out);
    // A plaintext handshake record whose body is not a ServerHello.
    const junk = [_]u8{ 22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    if (c.handleFlight(&junk, rnd, 0, &out)) |_| {} else |_| {}
    try testing.expectEqual(conn13.ProtocolVersion.dtls13, c.version());
}

// ── messages.zig ─────────────────────────────────────────────────────────

const m = @import("messages.zig");

/// `enc(out)` must refuse every buffer shorter than its output with
/// BufferTooShort and fill one of exactly that size identically.
fn expectExactOut(ctx: anytype) !void {
    const big = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(big);
    const want = try testing.allocator.dupe(u8, try ctx.enc(big));
    defer testing.allocator.free(want);
    const out = try testing.allocator.alloc(u8, want.len);
    defer testing.allocator.free(out);
    for (0..want.len) |k| try testing.expectError(error.BufferTooShort, ctx.enc(out[0..k]));
    try testing.expectEqualSlices(u8, want, try ctx.enc(out));
}

const exts2 = [_]m.Extension{ .{ .ext_type = 1, .data = "ab" }, .{ .ext_type = 2, .data = "" } };

test "audit: every messages encoder needs exactly its output length" {
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeSupportedVersionsClientHello(&.{ m.version_dtls13, m.legacy_version_dtls12 }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeSupportedVersionsServerHello(m.version_dtls13, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeExtensions(&exts2, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeCookieExtension("cookie", o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodePskKeyExchangeModes(&.{ .psk_ke, .psk_dhe_ke }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeOfferedPsks(.{ .identities = &.{.{ .identity = "id", .obfuscated_ticket_age = 5 }}, .binders = &.{"0123456789abcdef0123456789abcdef"} }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeU16ListExtension(&.{ 1, 2, 3 }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeKeyShareClientHello(&.{ .{ .group = 0x1d, .key_exchange = "k1" }, .{ .group = 0x17, .key_exchange = "key2" } }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeKeyShareServerHello(.{ .group = 0x1d, .key_exchange = "key" }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeKeyShareHelloRetryRequest(0x1d, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeClientHello(.{ .random = @splat(1), .legacy_session_id = "sid", .cipher_suites = &.{ 0x1301, 0x1303 }, .extensions = &exts2 }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeServerHello(.{ .random = @splat(2), .legacy_session_id_echo = "sid", .cipher_suite = 0x1301, .extensions = &exts2 }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeAlpn(&.{ "h2", "coap" }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeFinished(.{ .verify_data = "0123456789abcdef0123456789abcdef" }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeCertificate("ctx", &.{ "cert-one", "c2" }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeCertificate("ctx", &.{}, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeCertificateVerify(.{ .algorithm = 0x0403, .signature = "sig" }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m.encodeCertificateRequest(.{ .certificate_request_context = "rc", .extensions = &exts2 }, o);
        }
    }{});
}

test "audit: messages encoders refuse a list one past its length field and take one at the limit" {
    const a = testing.allocator;
    const big = try a.alloc(u8, (1 << 24) + 64);
    defer a.free(big);
    @memset(big, 0x5a);
    const out = try a.alloc(u8, (1 << 24) + 64);
    defer a.free(out);

    // supported_versions (ClientHello): a u8 byte count.
    const vers = try a.alloc([2]u8, 128);
    defer a.free(vers);
    @memset(vers, m.version_dtls13);
    try testing.expectError(error.ListTooLong, m.encodeSupportedVersionsClientHello(vers, out));
    // Extensions block: a u16 byte count.
    try testing.expectError(error.ListTooLong, m.encodeExtensions(&.{.{ .ext_type = 1, .data = big[0..65532] }}, out));
    _ = try m.encodeExtensions(&.{.{ .ext_type = 1, .data = big[0..65531] }}, out);
    // Cookie.
    try testing.expectError(error.ListTooLong, m.encodeCookieExtension(big[0..65536], out));
    _ = try m.encodeCookieExtension(big[0..65535], out);
    // psk_key_exchange_modes: 1..255 entries.
    const modes = try a.alloc(m.PskKeyExchangeMode, 256);
    defer a.free(modes);
    @memset(modes, .psk_dhe_ke);
    try testing.expectError(error.Malformed, m.encodePskKeyExchangeModes(modes[0..0], out));
    try testing.expectError(error.Malformed, m.encodePskKeyExchangeModes(modes, out));
    _ = try m.encodePskKeyExchangeModes(modes[0..255], out);
    // pre_shared_key: identities and binders each a u16 byte count, binders <= 255 bytes.
    try testing.expectError(error.ListTooLong, m.encodeOfferedPsks(.{ .identities = &.{.{ .identity = big[0..65530], .obfuscated_ticket_age = 0 }}, .binders = &.{} }, out));
    _ = try m.encodeOfferedPsks(.{ .identities = &.{.{ .identity = big[0..65529], .obfuscated_ticket_age = 0 }}, .binders = &.{} }, out);
    const binders = try a.alloc([]const u8, 256);
    defer a.free(binders);
    @memset(binders, big[0..255]);
    try testing.expectError(error.ListTooLong, m.encodeOfferedPsks(.{ .identities = &.{}, .binders = binders }, out));
    binders[255] = big[0..254]; // 255 * 256 + 255 = 65535 bytes
    _ = try m.encodeOfferedPsks(.{ .identities = &.{}, .binders = binders }, out);
    try testing.expectError(error.ListTooLong, m.encodeOfferedPsks(.{ .identities = &.{}, .binders = &.{big[0..256]} }, out));
    _ = try m.encodeOfferedPsks(.{ .identities = &.{}, .binders = &.{big[0..255]} }, out);
    // u16 lists.
    const vals = try a.alloc(u16, 32768);
    defer a.free(vals);
    @memset(vals, 1);
    try testing.expectError(error.ListTooLong, m.encodeU16ListExtension(vals, out));
    // key_share.
    try testing.expectError(error.ListTooLong, m.encodeKeyShareClientHello(&.{.{ .group = 1, .key_exchange = big[0..65532] }}, out));
    _ = try m.encodeKeyShareClientHello(&.{.{ .group = 1, .key_exchange = big[0..65531] }}, out);
    try testing.expectError(error.ListTooLong, m.encodeKeyShareClientHello(&.{.{ .group = 1, .key_exchange = big[0..65536] }}, out));
    try testing.expectError(error.ListTooLong, m.encodeKeyShareServerHello(.{ .group = 1, .key_exchange = big[0..65536] }, out));
    _ = try m.encodeKeyShareServerHello(.{ .group = 1, .key_exchange = big[0..65535] }, out);
    // Hellos: legacy_session_id <= 32, cipher_suites a u16 byte count.
    var sid: [33]u8 = @splat(7);
    try testing.expectError(error.Malformed, m.encodeClientHello(.{ .random = @splat(1), .legacy_session_id = &sid, .cipher_suites = &.{1}, .extensions = &.{} }, out));
    _ = try m.encodeClientHello(.{ .random = @splat(1), .legacy_session_id = sid[0..32], .cipher_suites = &.{1}, .extensions = &.{} }, out);
    try testing.expectError(error.ListTooLong, m.encodeClientHello(.{ .random = @splat(1), .legacy_session_id = "", .cipher_suites = vals, .extensions = &.{} }, out));
    try testing.expectError(error.Malformed, m.encodeServerHello(.{ .random = @splat(1), .legacy_session_id_echo = &sid, .cipher_suite = 1, .extensions = &.{} }, out));
    _ = try m.encodeServerHello(.{ .random = @splat(1), .legacy_session_id_echo = sid[0..32], .cipher_suite = 1, .extensions = &.{} }, out);
    // ALPN: names 1..255 bytes, the list a u16 byte count.
    try testing.expectError(error.Malformed, m.encodeAlpn(&.{big[0..256]}, out));
    _ = try m.encodeAlpn(&.{big[0..255]}, out);
    const names = try a.alloc([]const u8, 257);
    defer a.free(names);
    @memset(names, big[0..255]);
    try testing.expectError(error.ListTooLong, m.encodeAlpn(names, out));
    names[255] = big[0..254]; // 255 * 256 + 255 = 65535 bytes
    _ = try m.encodeAlpn(names[0..256], out);
    // Certificate: context <= 255, entries 1..2^24-1, the list a u24.
    try testing.expectError(error.Malformed, m.encodeCertificate(big[0..256], &.{"c"}, out));
    _ = try m.encodeCertificate(big[0..255], &.{"c"}, out);
    try testing.expectError(error.Malformed, m.encodeCertificate("", &.{""}, out));
    try testing.expectError(error.Malformed, m.encodeCertificate("", &.{big[0 .. 1 << 24]}, out));
    try testing.expectError(error.ListTooLong, m.encodeCertificate("", &.{big[0 .. (1 << 24) - 1]}, out));
    _ = try m.encodeCertificate("", &.{big[0 .. (1 << 24) - 6]}, out);
    // CertificateVerify / CertificateRequest.
    try testing.expectError(error.ListTooLong, m.encodeCertificateVerify(.{ .algorithm = 1, .signature = big[0..65536] }, out));
    _ = try m.encodeCertificateVerify(.{ .algorithm = 1, .signature = big[0..65535] }, out);
    try testing.expectError(error.Malformed, m.encodeCertificateRequest(.{ .certificate_request_context = big[0..256], .extensions = &.{} }, out));
    _ = try m.encodeCertificateRequest(.{ .certificate_request_context = big[0..255], .extensions = &.{} }, out);
}

test "audit: messages decoders at their edges" {
    // supported_versions in a ServerHello is exactly two bytes.
    try testing.expectError(error.Malformed, m.decodeSupportedVersionsServerHello(&.{ 0xfe, 0xfc, 0 }));
    // An extension header cut inside the block.
    var ext_out: [4]m.Extension = undefined;
    try testing.expectError(error.Malformed, m.decodeExtensions(&.{ 0, 3, 0, 1, 0 }, &ext_out));
    // psk_key_exchange_modes: an empty list decodes; capacity is exact.
    var modes: [1]m.PskKeyExchangeMode = undefined;
    try testing.expectEqual(@as(usize, 0), (try m.decodePskKeyExchangeModes(&.{0}, &modes)).len);
    try testing.expectEqual(@as(usize, 1), (try m.decodePskKeyExchangeModes(&.{ 1, 1 }, &modes)).len);
    try testing.expectError(error.TooManyExtensions, m.decodePskKeyExchangeModes(&.{ 2, 1, 0 }, &modes));
    // u16 lists: capacity is exact.
    var u16s: [2]u16 = undefined;
    try testing.expectEqual(@as(usize, 2), (try m.decodeU16ListExtension(&.{ 0, 4, 0, 1, 0, 2 }, &u16s)).len);
    try testing.expectError(error.TooManyExtensions, m.decodeU16ListExtension(&.{ 0, 6, 0, 1, 0, 2, 0, 3 }, &u16s));
    // filterU16ListExtension: empty list, odd length, only wanted values, bounded output.
    try testing.expectEqual(@as(usize, 0), (try m.filterU16ListExtension(&.{ 0, 0 }, &.{1}, &u16s)).len);
    try testing.expectError(error.BufferTooShort, m.filterU16ListExtension(&.{0}, &.{1}, &u16s));
    try testing.expectError(error.Malformed, m.filterU16ListExtension(&.{ 0, 3, 0, 1, 0 }, &.{1}, &u16s));
    const f = try m.filterU16ListExtension(&.{ 0, 4, 0, 1, 0, 2 }, &.{2}, &u16s);
    try testing.expectEqualSlices(u16, &.{2}, f);
    const g = try m.filterU16ListExtension(&.{ 0, 6, 0, 1, 0, 2, 0, 3 }, &.{ 1, 2, 3 }, u16s[0..1]);
    try testing.expectEqualSlices(u16, &.{1}, g);
    // key_share: a trailing cut entry; an empty key_exchange at the very end.
    var ks: [2]m.KeyShareEntry = undefined;
    try testing.expectError(error.Malformed, m.decodeKeyShareClientHello(&.{ 0, 2, 0, 0x1d }, &ks));
    const one = try m.decodeKeyShareClientHello(&.{ 0, 4, 0, 0x1d, 0, 0 }, &ks);
    try testing.expectEqual(@as(usize, 1), one.len);
    try testing.expectEqual(@as(usize, 0), one[0].key_exchange.len);
    try testing.expectEqual(@as(usize, 0), (try m.decodeKeyShareServerHello(&.{ 0, 0x1d, 0, 0 })).key_exchange.len);
    // pre_shared_key decoder.
    var ids: [1]m.PskIdentity = undefined;
    var bs: [1][]const u8 = undefined;
    // identity length overruns the identities block
    try testing.expectError(error.Malformed, m.decodeOfferedPsks(&.{ 0, 9, 0, 10, 'a', 'b', 'c', 0, 0, 0, 0, 0, 2, 1, 0 }, &ids, &bs));
    // binders block longer than the buffer
    try testing.expectError(error.BufferTooShort, m.decodeOfferedPsks(&.{ 0, 7, 0, 1, 'a', 0, 0, 0, 0, 0, 9, 1, 0 }, &ids, &bs));
    // a binder overruns its block
    try testing.expectError(error.Malformed, m.decodeOfferedPsks(&.{ 0, 7, 0, 1, 'a', 0, 0, 0, 0, 0, 2, 5, 0, 0, 0, 0, 0, 0 }, &ids, &bs));
    // capacity is exact
    const ok = try m.decodeOfferedPsks(&.{ 0, 7, 0, 1, 'a', 0, 0, 0, 0, 0, 2, 1, 0xbb }, &ids, &bs);
    try testing.expectEqual(@as(usize, 1), ok.identities.len);
    try testing.expectError(error.TooManyExtensions, m.decodeOfferedPsks(&.{ 0, 14, 0, 1, 'a', 0, 0, 0, 0, 0, 1, 'b', 0, 0, 0, 0, 0, 4, 1, 0, 1, 0 }, &ids, &bs));
    try testing.expectError(error.TooManyExtensions, m.decodeOfferedPsks(&.{ 0, 0, 0, 4, 1, 0, 1, 0 }, &ids, &bs));
    // Hellos: a 33-byte session id is Malformed even when the buffer ends there; 32 is fine.
    var hello: [35]u8 = @splat(0);
    hello[34] = 33;
    try testing.expectError(error.Malformed, m.decodeClientHello(&hello, &ext_out));
    try testing.expectError(error.Malformed, m.decodeServerHello(&hello, &ext_out));
    var out: [256]u8 = undefined;
    const sid32: [32]u8 = @splat(3);
    const ch = try m.encodeClientHello(.{ .random = @splat(1), .legacy_session_id = &sid32, .cipher_suites = &.{0x1301}, .extensions = &exts2 }, &out);
    try testing.expectEqual(@as(usize, 32), (try m.decodeClientHello(ch, &ext_out)).legacy_session_id.len);
    const sh = try m.encodeServerHello(.{ .random = @splat(1), .legacy_session_id_echo = &sid32, .cipher_suite = 0x1301, .extensions = &exts2 }, &out);
    try testing.expectEqual(@as(usize, 32), (try m.decodeServerHello(sh, &ext_out)).legacy_session_id_echo.len);
    // An odd cipher_suites length is Malformed, also when the buffer ends right after it.
    var odd: [38]u8 = @splat(0);
    std.mem.writeInt(u16, odd[36..38], 1, .big);
    try testing.expectError(error.Malformed, m.decodeClientHello(&odd, &ext_out));
    var odd2: [44]u8 = @splat(0);
    std.mem.writeInt(u16, odd2[36..38], 3, .big);
    try testing.expectError(error.Malformed, m.decodeClientHello(&odd2, &ext_out));
    // Certificate: a cut entry header at the end of the list, a zero-length entry.
    var ce: [2]m.CertificateEntry = undefined;
    try testing.expectError(error.Malformed, m.decodeCertificate(&.{ 0, 0, 0, 2, 0, 0 }, &ce));
    try testing.expectError(error.Malformed, m.decodeCertificate(&.{ 0, 0, 0, 5, 0, 0, 0, 0, 0 }, &ce));
}

// ── messages12.zig ───────────────────────────────────────────────────────

const m12 = @import("messages12.zig");

test "audit: every messages12 encoder needs exactly its output length" {
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m12.encodeClientHello(.{ .random = @splat(1), .session_id = "s", .cookie = "ck", .cipher_suites = &.{ 0xc02b, 0xc02c }, .extensions = &.{} }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m12.encodeHelloVerifyRequest("cookie", o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m12.encodeServerHello(.{ .random = @splat(2), .session_id = "s", .cipher_suite = 0xc02b, .extensions = &.{} }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m12.encodeCertificate(&.{ "leaf", "ca" }, o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m12.encodeEcdhParams(0x1d, "point", o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m12.encodeOpaque16("identity", o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m12.encodePoint("point", o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m12.encodeSigned(0x0403, "sig", o);
        }
    }{});
    try expectExactOut(struct {
        fn enc(_: @This(), o: []u8) ![]u8 {
            return m12.encodeCertificateRequest(&.{ 0x0403, 0x0804 }, o);
        }
    }{});
    // A ServerHello with no extensions ends right after compression_method
    // (no empty extensions block), and decodes back at exactly that length.
    var out: [64]u8 = undefined;
    const sh = try m12.encodeServerHello(.{ .random = @splat(2), .cipher_suite = 0xc02b, .extensions = &.{} }, &out);
    try testing.expectEqual(@as(usize, 2 + 32 + 1 + 3), sh.len);
    var ext: [4]m12.Extension = undefined;
    try testing.expectEqual(@as(u16, 0xc02b), (try m12.decodeServerHello(sh, &ext)).cipher_suite);
}

test "audit: messages12 encoders refuse one past each limit and take the limit" {
    const a = testing.allocator;
    const big = try a.alloc(u8, (1 << 24) + 64);
    defer a.free(big);
    @memset(big, 0x5a);
    const out = try a.alloc(u8, (1 << 24) + 64);
    defer a.free(out);
    const suites = try a.alloc(u16, 32768);
    defer a.free(suites);
    @memset(suites, 0xc02b);
    // ClientHello: session_id <= 32, cookie <= 255, 1..32767 suites.
    try testing.expectError(error.Malformed, m12.encodeClientHello(.{ .random = @splat(1), .session_id = big[0..33], .cipher_suites = suites[0..1], .extensions = &.{} }, out));
    _ = try m12.encodeClientHello(.{ .random = @splat(1), .session_id = big[0..32], .cipher_suites = suites[0..1], .extensions = &.{} }, out);
    try testing.expectError(error.Malformed, m12.encodeClientHello(.{ .random = @splat(1), .cookie = big[0..256], .cipher_suites = suites[0..1], .extensions = &.{} }, out));
    _ = try m12.encodeClientHello(.{ .random = @splat(1), .cookie = big[0..255], .cipher_suites = suites[0..1], .extensions = &.{} }, out);
    try testing.expectError(error.ListTooLong, m12.encodeClientHello(.{ .random = @splat(1), .cipher_suites = &.{}, .extensions = &.{} }, out));
    try testing.expectError(error.ListTooLong, m12.encodeClientHello(.{ .random = @splat(1), .cipher_suites = suites, .extensions = &.{} }, out));
    _ = try m12.encodeClientHello(.{ .random = @splat(1), .cipher_suites = suites[0..32767], .extensions = &.{} }, out);
    // HelloVerifyRequest cookie <= 255.
    try testing.expectError(error.Malformed, m12.encodeHelloVerifyRequest(big[0..256], out));
    _ = try m12.encodeHelloVerifyRequest(big[0..255], out);
    // ServerHello session_id <= 32.
    try testing.expectError(error.Malformed, m12.encodeServerHello(.{ .random = @splat(1), .session_id = big[0..33], .cipher_suite = 1, .extensions = &.{} }, out));
    _ = try m12.encodeServerHello(.{ .random = @splat(1), .session_id = big[0..32], .cipher_suite = 1, .extensions = &.{} }, out);
    // Certificate: entries 1..2^24-1 bytes, the list a u24.
    try testing.expectError(error.Malformed, m12.encodeCertificate(&.{""}, out));
    try testing.expectError(error.Malformed, m12.encodeCertificate(&.{big[0 .. 1 << 24]}, out));
    try testing.expectError(error.ListTooLong, m12.encodeCertificate(&.{big[0 .. (1 << 24) - 1]}, out));
    _ = try m12.encodeCertificate(&.{big[0 .. (1 << 24) - 4]}, out);
    // Points 1..255 bytes.
    try testing.expectError(error.Malformed, m12.encodeEcdhParams(1, "", out));
    try testing.expectError(error.Malformed, m12.encodeEcdhParams(1, big[0..256], out));
    _ = try m12.encodeEcdhParams(1, big[0..255], out);
    try testing.expectError(error.Malformed, m12.encodePoint("", out));
    try testing.expectError(error.Malformed, m12.encodePoint(big[0..256], out));
    _ = try m12.encodePoint(big[0..255], out);
    // u16-length opaques.
    try testing.expectError(error.ListTooLong, m12.encodeOpaque16(big[0..65536], out));
    _ = try m12.encodeOpaque16(big[0..65535], out);
    try testing.expectError(error.ListTooLong, m12.encodeSigned(1, big[0..65536], out));
    _ = try m12.encodeSigned(1, big[0..65535], out);
    // CertificateRequest: 1..32767 schemes.
    try testing.expectError(error.ListTooLong, m12.encodeCertificateRequest(&.{}, out));
    try testing.expectError(error.ListTooLong, m12.encodeCertificateRequest(suites, out));
    _ = try m12.encodeCertificateRequest(suites[0..32767], out);
}

test "audit: messages12 decoders at their edges" {
    var out: [512]u8 = undefined;
    var ext: [4]m12.Extension = undefined;
    // ClientHello: trailing bytes after the extensions block.
    const ch = try m12.encodeClientHello(.{ .random = @splat(1), .cipher_suites = &.{0xc02b}, .extensions = &.{.{ .ext_type = 23, .data = "" }} }, &out);
    var tail: [512]u8 = undefined;
    @memcpy(tail[0..ch.len], ch);
    tail[ch.len] = 0;
    try testing.expectError(error.Malformed, m12.decodeClientHello(tail[0 .. ch.len + 1], &ext));
    // ClientHello: 33-byte session id (32 is fine); no suites; odd suites; no compression.
    const ch32 = try m12.encodeClientHello(.{ .random = @splat(1), .session_id = &@as([32]u8, @splat(9)), .cipher_suites = &.{0xc02b}, .extensions = &.{} }, &out);
    try testing.expectEqual(@as(usize, 32), (try m12.decodeClientHello(ch32, &ext)).session_id.len);
    var ch33: [512]u8 = undefined;
    @memcpy(ch33[0..ch32.len], ch32);
    ch33[34] = 33;
    @memcpy(ch33[35 + 33 ..][0 .. ch32.len - 67], ch32[67..]);
    ch33[67] = 9;
    try testing.expectError(error.Malformed, m12.decodeClientHello(ch33[0 .. ch32.len + 1], &ext));
    // random(34) sid(0) cookie(0) cs_len(2) suites comp_len comp
    var hello: [44]u8 = @splat(0);
    hello[38] = 1;
    try testing.expectError(error.Malformed, m12.decodeClientHello(hello[0..40], &ext));
    std.mem.writeInt(u16, hello[36..38], 3, .big);
    hello[38] = 0;
    hello[41] = 1;
    try testing.expectError(error.Malformed, m12.decodeClientHello(hello[0..43], &ext));
    std.mem.writeInt(u16, hello[36..38], 2, .big);
    hello[40] = 0;
    try testing.expectError(error.Malformed, m12.decodeClientHello(hello[0..41], &ext));
    // HelloVerifyRequest with an empty cookie.
    try testing.expectEqual(@as(usize, 0), (try m12.decodeHelloVerifyRequest(&.{ 0xfe, 0xff, 0 })).cookie.len);
    // ServerHello: 33-byte session id; a buffer cut before cipher_suite.
    const sh32 = try m12.encodeServerHello(.{ .random = @splat(1), .session_id = &@as([32]u8, @splat(9)), .cipher_suite = 0xc02b, .extensions = &.{} }, &out);
    var sh33: [80]u8 = undefined;
    @memcpy(sh33[0..sh32.len], sh32);
    sh33[34] = 33;
    @memcpy(sh33[68..][0..3], sh32[67..70]);
    sh33[67] = 9;
    try testing.expectError(error.Malformed, m12.decodeServerHello(sh33[0 .. sh32.len + 1], &ext));
    var short_sh: [36]u8 = @splat(0);
    try testing.expectError(error.Malformed, m12.decodeServerHello(&short_sh, &ext));
    // Certificate leaf: too short; total disagreeing with the buffer; a cut entry header; an empty entry.
    try testing.expectError(error.Malformed, m12.decodeCertificateLeaf(&.{ 0, 0 }));
    try testing.expectError(error.Malformed, m12.decodeCertificateLeaf(&.{ 0, 0, 4, 0, 0, 1, 'x', 0, 0, 1, 'y' }));
    try testing.expectError(error.Malformed, m12.decodeCertificateLeaf(&.{ 0, 0, 2, 0, 0 }));
    try testing.expectError(error.Malformed, m12.decodeCertificateLeaf(&.{ 0, 0, 3, 0, 0, 0 }));
    // ECDH params: short, wrong curve type, empty point.
    try testing.expectError(error.Malformed, m12.decodeEcdhParams(&.{ 3, 0, 0x1d }));
    try testing.expectError(error.Malformed, m12.decodeEcdhParams(&.{ 1, 0, 0x1d, 1, 7 }));
    try testing.expectError(error.Malformed, m12.decodeEcdhParams(&.{ 3, 0, 0x1d, 0, 7 }));
    // opaque16: one byte is Malformed, an empty opaque decodes.
    try testing.expectError(error.Malformed, m12.decodeOpaque16(&.{0}));
    try testing.expectEqual(@as(usize, 0), (try m12.decodeOpaque16(&.{ 0, 0 })).data.len);
    // Point: empty, length mismatch, one byte.
    try testing.expectError(error.Malformed, m12.decodePoint(&.{0}));
    try testing.expectError(error.Malformed, m12.decodePoint(&.{ 1, 7, 8 }));
    try testing.expectEqualSlices(u8, &.{7}, try m12.decodePoint(&.{ 1, 7 }));
    // Signed: short, empty signature.
    try testing.expectError(error.Malformed, m12.decodeSigned(&.{ 4, 3, 0 }));
    try testing.expectError(error.Malformed, m12.decodeSigned(&.{ 4, 3, 0, 0 }));
    // CertificateRequest: empty, no types, no schemes, odd schemes, trailing.
    try testing.expectError(error.Malformed, m12.decodeCertificateRequest(&.{}));
    try testing.expectError(error.Malformed, m12.decodeCertificateRequest(&.{ 0, 0, 2, 4, 3, 0, 0 }));
    try testing.expectError(error.Malformed, m12.decodeCertificateRequest(&.{ 1, 64, 0, 0, 0, 0 }));
    try testing.expectError(error.Malformed, m12.decodeCertificateRequest(&.{ 1, 64, 0, 3, 4, 3, 1, 0, 0 }));
    try testing.expectError(error.Malformed, m12.decodeCertificateRequest(&.{ 1, 64, 0, 2, 4, 3, 0, 0, 9 }));
    _ = try m12.decodeCertificateRequest(&.{ 1, 64, 0, 2, 4, 3, 0, 0 });
    // ec_point_formats: a list whose length byte disagrees is not "uncompressed".
    try testing.expect(!m12.pointFormatsIncludeUncompressed(&.{ 1, 0, 9 }));
    try testing.expect(m12.pointFormatsIncludeUncompressed(&.{ 1, 0 }));
}

// ── certauth.zig ─────────────────────────────────────────────────────────

test "audit: an Ed25519 SPKI with a 33-byte key is InvalidPublicKey, not its first 32 bytes" {
    const certauth = @import("certauth.zig");
    const orig = @import("certauth_kat_vectors.zig").ed25519_cert_der;
    _ = try certauth.parseLeafPublicKey(&orig);
    // Lengths in this certificate: Certificate 30 82 01 1a, TBS 30 81 cd,
    // SPKI 30 2a (offset 133), BIT STRING 03 21 00 (offset 142), key ends
    // at 177. One extra key byte grows all four by one.
    var buf: [orig.len + 1]u8 = undefined;
    @memcpy(buf[0..177], orig[0..177]);
    buf[177] = 0;
    @memcpy(buf[178..], orig[177..]);
    try testing.expectEqual(@as(u8, 0x2a), buf[134]);
    try testing.expectEqual(@as(u8, 0x21), buf[143]);
    buf[3] += 1;
    buf[6] += 1;
    buf[134] += 1;
    buf[143] += 1;
    try testing.expectError(error.InvalidPublicKey, certauth.parseLeafPublicKey(&buf));
}

// ── Connection12.zig ─────────────────────────────────────────────────────

const c12 = @import("Connection12.zig");
const C12 = c12.Connection12;
const S12 = @import("suite12.zig").CipherSuite12;
const cert_kat = @import("certauth_kat_vectors.zig");
const HT = m12.HandshakeType;

var audit_csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x44)));
fn ent() conn13.Entropy {
    return .{ .seeded_for_test = audit_csprng.random() };
}

const only12 = [_]conn13.ProtocolVersion{.dtls12};
const psk_suites = [_]S12{ .psk_with_aes_128_gcm_sha256, .ecdhe_psk_with_chacha20_poly1305_sha256 };

fn psk12(role: conn13.Role) conn13.Config {
    return .{ .role = role, .versions = &only12, .psk_identity = "device-12", .psk = "a 1.2 pre-shared key", .cipher_suites12 = &psk_suites };
}

var audit_server_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;
fn ecdsa12(role: conn13.Role) conn13.Config {
    const suites = comptime &[_]S12{.ecdhe_ecdsa_with_aes_128_gcm_sha256};
    if (role == .server) {
        audit_server_sk = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable;
        return .{ .role = .server, .versions = &only12, .key_exchange = .cert_dhe, .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = .{ .ecdsa_p256 = &audit_server_sk } }, .cipher_suites12 = suites, .now_sec = 1798761600 };
    }
    return .{ .role = .client, .versions = &only12, .key_exchange = .cert_dhe, .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der }, .expected_peer_name = "dtls-test-server", .cipher_suites12 = suites, .now_sec = 1798761600 };
}

/// One plaintext epoch-0 handshake record holding one whole message.
fn hsRec(buf: []u8, rseq: u48, t: u8, mseq: u16, body: []const u8) []u8 {
    _ = record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = rseq, .length = @intCast(handshake.header_len + body.len) }, buf) catch unreachable;
    handshake.encodeHeader(.{ .msg_type = t, .length = @intCast(body.len), .message_seq = mseq, .fragment_offset = 0, .fragment_length = @intCast(body.len) }, buf[13..][0..handshake.header_len]);
    @memcpy(buf[13 + handshake.header_len ..][0..body.len], body);
    return buf[0 .. 13 + handshake.header_len + body.len];
}

const Msg = struct { t: u8, body: []const u8 };

/// The messages as consecutive records (record seq and message_seq from
/// `first`), one datagram.
fn flightOf(buf: []u8, first: u16, msgs: []const Msg) []u8 {
    var n: usize = 0;
    for (msgs, 0..) |mm, i| n += hsRec(buf[n..], @as(u48, first) + @as(u48, @intCast(i)), mm.t, first + @as(u16, @intCast(i)), mm.body).len;
    return buf[0..n];
}

const ri_ext: m12.Extension = .{ .ext_type = m12.ext_renegotiation_info, .data = &m12.renegotiation_info_initial };
const ems_ext: m12.Extension = .{ .ext_type = m12.ext_extended_master_secret, .data = "" };

fn serverHello(buf: []u8, suite: S12, exts: []const m12.Extension) []u8 {
    return m12.encodeServerHello(.{ .random = @splat(7), .cipher_suite = @backingInt(suite), .extensions = exts }, buf) catch unreachable;
}

/// A fresh client (its ClientHello sent) fed `msgs` as the server's flight.
fn clientFed(cfg: conn13.Config, msgs: []const Msg) !C12 {
    var c = try C12.clientInit(cfg);
    errdefer c.deinit();
    var out: [4096]u8 = undefined;
    _ = try c.startHandshake(ent(), 0, &out);
    var dg: [4096]u8 = undefined;
    _ = try c.handleFlight(flightOf(&dg, 0, msgs), ent(), 0, &out);
    return c;
}

fn expectClientError(want: anyerror, cfg: conn13.Config, msgs: []const Msg) !void {
    if (clientFed(cfg, msgs)) |c| {
        var cc = c;
        cc.deinit();
        return error.TestExpectedError;
    } else |e| try testing.expectEqual(want, e);
}

test "audit: dtls12 client refuses a malformed or unoffered ServerHello" {
    var b: [512]u8 = undefined;
    const psk = psk12(.client);
    // Version, compression, suite.
    var sh = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext });
    sh[1] = 0xff;
    try expectClientError(error.UnsupportedVersion, psk, &.{.{ .t = HT.server_hello, .body = sh }});
    sh = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext });
    sh[34 + 1 + 2] = 1;
    try expectClientError(error.Malformed, psk, &.{.{ .t = HT.server_hello, .body = sh }});
    try expectClientError(error.NoCipherSuiteOverlap, psk, &.{.{ .t = HT.server_hello, .body = serverHello(&b, .ecdhe_ecdsa_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext }) }});
    // Extensions.
    try expectClientError(error.SecureRenegotiationRequired, psk, &.{.{ .t = HT.server_hello, .body = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ .{ .ext_type = m12.ext_renegotiation_info, .data = &.{ 1, 0 } }, ems_ext }) }});
    try expectClientError(error.Malformed, psk, &.{.{ .t = HT.server_hello, .body = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, .{ .ext_type = m12.ext_extended_master_secret, .data = "x" } }) }});
    try expectClientError(error.Malformed, psk, &.{.{ .t = HT.server_hello, .body = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext, .{ .ext_type = m12.ext_ec_point_formats, .data = &.{ 1, 1 } } }) }});
    var alpn_b: [32]u8 = undefined;
    const h2 = try m.encodeAlpn(&.{"h2"}, &alpn_b);
    try expectClientError(error.Malformed, psk, &.{.{ .t = HT.server_hello, .body = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext, .{ .ext_type = m12.ext_alpn, .data = h2 } }) }});
    var with_alpn = psk;
    with_alpn.alpn_protocols = &.{"coap"};
    try expectClientError(error.Malformed, with_alpn, &.{.{ .t = HT.server_hello, .body = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext, .{ .ext_type = m12.ext_alpn, .data = h2 } }) }});
    // The selected protocol is recorded as soon as the ServerHello is taken.
    var alpn_c: [32]u8 = undefined;
    const coap = try m.encodeAlpn(&.{"coap"}, &alpn_c);
    var c = try clientFed(with_alpn, &.{.{ .t = HT.server_hello, .body = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext, .{ .ext_type = m12.ext_alpn, .data = coap } }) }});
    defer c.deinit();
    try testing.expectEqualStrings("coap", c.negotiatedAlpn().?);
}

test "audit: dtls12 client refuses out-of-place or malformed server flight messages" {
    var b: [512]u8 = undefined;
    const psk = psk12(.client);
    const sh_psk = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext });
    // PSK: no Certificate / CertificateRequest; the hint takes the whole SKE; SHD is empty; one SKE only.
    try expectClientError(error.UnexpectedMessage, psk, &.{ .{ .t = HT.server_hello, .body = sh_psk }, .{ .t = HT.certificate, .body = &.{ 0, 0, 0 } } });
    try expectClientError(error.UnexpectedMessage, psk, &.{ .{ .t = HT.server_hello, .body = sh_psk }, .{ .t = HT.certificate_request, .body = &.{ 1, 64, 0, 2, 4, 3, 0, 0 } } });
    try expectClientError(error.Malformed, psk, &.{ .{ .t = HT.server_hello, .body = sh_psk }, .{ .t = HT.server_key_exchange, .body = &.{ 0, 1, 'h', 9 } } });
    try expectClientError(error.Malformed, psk, &.{ .{ .t = HT.server_hello, .body = sh_psk }, .{ .t = HT.server_hello_done, .body = &.{0} } });
    try expectClientError(error.UnexpectedMessage, psk, &.{ .{ .t = HT.server_hello, .body = sh_psk }, .{ .t = HT.server_key_exchange, .body = &.{ 0, 0 } }, .{ .t = HT.server_key_exchange, .body = &.{ 0, 0 } } });
    // ECDHE_PSK: the group must be one we offer and the point its size, nothing after it.
    var b2: [512]u8 = undefined;
    const sh_epsk = serverHello(&b2, .ecdhe_psk_with_chacha20_poly1305_sha256, &.{ ri_ext, ems_ext });
    const pt: [32]u8 = @splat(9);
    var ske: [64]u8 = undefined;
    ske[0..2].* = .{ 0, 0 };
    const params = try m12.encodeEcdhParams(0x001d, &pt, ske[2..]);
    var trailing: [64]u8 = undefined;
    @memcpy(trailing[0 .. 2 + params.len], ske[0 .. 2 + params.len]);
    trailing[2 + params.len] = 0;
    try expectClientError(error.Malformed, psk, &.{ .{ .t = HT.server_hello, .body = sh_epsk }, .{ .t = HT.server_key_exchange, .body = trailing[0 .. 3 + params.len] } });
    var bad_group = ske;
    bad_group[3..5].* = .{ 0x12, 0x34 };
    try expectClientError(error.UnsupportedGroup, psk, &.{ .{ .t = HT.server_hello, .body = sh_epsk }, .{ .t = HT.server_key_exchange, .body = bad_group[0 .. 2 + params.len] } });
    var short_pt: [64]u8 = undefined;
    short_pt[0..2].* = .{ 0, 0 };
    const p31 = try m12.encodeEcdhParams(0x001d, pt[0..31], short_pt[2..]);
    try expectClientError(error.MissingKeyShare, psk, &.{ .{ .t = HT.server_hello, .body = sh_epsk }, .{ .t = HT.server_key_exchange, .body = short_pt[0 .. 2 + p31.len] } });
    // ECDHE_ECDSA: a ServerKeyExchange before the Certificate.
    var b3: [512]u8 = undefined;
    const sh_ec = serverHello(&b3, .ecdhe_ecdsa_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext });
    var ske_ec: [128]u8 = undefined;
    const pe = try m12.encodeEcdhParams(0x001d, &pt, &ske_ec);
    const sg = try m12.encodeSigned(0x0403, "sig", ske_ec[pe.len..]);
    try expectClientError(error.UnexpectedMessage, ecdsa12(.client), &.{ .{ .t = HT.server_hello, .body = sh_ec }, .{ .t = HT.server_key_exchange, .body = ske_ec[0 .. pe.len + sg.len] } });
}

fn hvrBody(buf: []u8, version: [2]u8, cookie: []const u8) []u8 {
    const h = m12.encodeHelloVerifyRequest(cookie, buf) catch unreachable;
    h[0..2].* = version;
    return h;
}

test "audit: dtls12 client HelloVerifyRequest: version, empty cookie, at most three" {
    var b: [64]u8 = undefined;
    const psk = psk12(.client);
    try expectClientError(error.UnsupportedVersion, psk, &.{.{ .t = HT.hello_verify_request, .body = hvrBody(&b, .{ 0xfd, 0xff }, "ck") }});
    try expectClientError(error.UnsupportedVersion, psk, &.{.{ .t = HT.hello_verify_request, .body = hvrBody(&b, .{ 0xfe, 0xfc }, "ck") }});
    try expectClientError(error.IllegalHelloRetryRequest, psk, &.{.{ .t = HT.hello_verify_request, .body = hvrBody(&b, .{ 0xfe, 0xff }, "") }});
    // DTLS 1.2's own version number is accepted in an HVR too.
    var c = try clientFed(psk, &.{.{ .t = HT.hello_verify_request, .body = hvrBody(&b, .{ 0xfe, 0xfd }, "ck") }});
    defer c.deinit();
    var out: [4096]u8 = undefined;
    var dg: [256]u8 = undefined;
    // Two more are answered; a fourth is refused.
    for (1..3) |i| {
        const r = try c.handleFlight(hsRec(&dg, @intCast(i), HT.hello_verify_request, @intCast(i), hvrBody(&b, .{ 0xfe, 0xff }, "ck")), ent(), 0, &out);
        try testing.expect(r.out.len > 0);
    }
    try testing.expectError(error.IllegalHelloRetryRequest, c.handleFlight(hsRec(&dg, 3, HT.hello_verify_request, 3, hvrBody(&b, .{ 0xfe, 0xff }, "ck")), ent(), 0, &out));
}

fn clientHello12(buf: []u8, suites: []const u16, exts: []const m12.Extension) []u8 {
    return m12.encodeClientHello(.{ .random = @splat(3), .cipher_suites = suites, .extensions = exts }, buf) catch unreachable;
}

/// The handshake message types in a plaintext flight.
fn flightTypes(fl: []const u8, types: []u8) []u8 {
    var n: usize = 0;
    var p: usize = 0;
    while (p + 13 <= fl.len) {
        const hdr = record.decodePlaintext(fl[p..]) catch break;
        if (hdr.content_type == 22 and hdr.epoch == 0) {
            types[n] = fl[p + 13];
            n += 1;
        }
        p += 13 + hdr.length;
    }
    return types[0..n];
}

/// The ServerHello extensions of a server's first fl.
fn shExtension(fl: []const u8, ext_type: u16) ?[]const u8 {
    const hdr = record.decodePlaintext(fl) catch return null;
    const body = fl[13 + handshake.header_len .. 13 + hdr.length];
    var ext: [8]m12.Extension = undefined;
    const sh = m12.decodeServerHello(body, &ext) catch return null;
    return m12.findExtension(sh.extensions, ext_type);
}

test "audit: dtls12 server refuses a bad ClientHello and answers a good one exactly" {
    var b: [512]u8 = undefined;
    var dg: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const psk_cs = [_]u16{@backingInt(S12.psk_with_aes_128_gcm_sha256)};
    {
        var s = try C12.serverInit(psk12(.server));
        defer s.deinit();
        const ch = clientHello12(&b, &psk_cs, &.{ ri_ext, ems_ext });
        ch[0] = 0xfd;
        try testing.expectError(error.UnsupportedVersion, s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, ch), ent(), 0, &out));
        ch[0] = 0xfe;
        ch[1] = 0xfe;
        try testing.expectError(error.UnsupportedVersion, s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, ch), ent(), 0, &out));
        ch[1] = 0xfd;
        ch[34 + 1 + 1 + 2 + 2 + 1] = 1; // the only compression method is not null
        try testing.expectError(error.Malformed, s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, ch), ent(), 0, &out));
        const pf = clientHello12(&b, &psk_cs, &.{ ri_ext, ems_ext, .{ .ext_type = m12.ext_ec_point_formats, .data = &.{ 1, 1 } } });
        try testing.expectError(error.Malformed, s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, pf), ent(), 0, &out));
        // A suite of a key exchange this server is not configured for is never picked.
        const ec_only = [_]u16{@backingInt(S12.ecdhe_ecdsa_with_aes_128_gcm_sha256)};
        var cfg = psk12(.server);
        cfg.cipher_suites12 = &.{ .ecdhe_ecdsa_with_aes_128_gcm_sha256, .psk_with_aes_128_gcm_sha256 };
        var s2 = try C12.serverInit(cfg);
        defer s2.deinit();
        var gb2: [16]u8 = undefined;
        var sb2: [16]u8 = undefined;
        const ec_exts = [_]m12.Extension{ ri_ext, ems_ext, .{ .ext_type = m12.ext_supported_groups, .data = try m.encodeSupportedGroups(&.{ 0x001d, 0x0017 }, &gb2) }, .{ .ext_type = m12.ext_signature_algorithms, .data = try m.encodeSignatureAlgorithms(&.{ 0x0403, 0x0804 }, &sb2) } };
        try testing.expectError(error.NoCipherSuiteOverlap, s2.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, clientHello12(&b, &ec_only, &ec_exts)), ent(), 0, &out));
    }
    {
        // EMS not required: a ClientHello without it is answered.
        var cfg = psk12(.server);
        cfg.require_extended_master_secret = false;
        var s = try C12.serverInit(cfg);
        defer s.deinit();
        const r = try s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, clientHello12(&b, &psk_cs, &.{ri_ext})), ent(), 0, &out);
        try testing.expect(r.out.len > 0);
        // Plain PSK without a hint: ServerHello, ServerHelloDone, no ServerKeyExchange,
        // no ec_point_formats even though the client sent supported_groups.
        var t: [8]u8 = undefined;
        try testing.expectEqualSlices(u8, &.{ HT.server_hello, HT.server_hello_done }, flightTypes(r.out, &t));
    }
    {
        var s = try C12.serverInit(psk12(.server));
        defer s.deinit();
        var gb: [16]u8 = undefined;
        const groups = try m.encodeSupportedGroups(&.{0x001d}, &gb);
        const r = try s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, clientHello12(&b, &psk_cs, &.{ ri_ext, ems_ext, .{ .ext_type = m12.ext_supported_groups, .data = groups } })), ent(), 0, &out);
        try testing.expectEqual(@as(?[]const u8, null), shExtension(r.out, m12.ext_ec_point_formats));
    }
}

test "audit: dtls12 server ALPN: ignored when not configured or not offered, the client's list searched for ours" {
    var b: [512]u8 = undefined;
    var dg: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    var ab: [32]u8 = undefined;
    const offer = try m.encodeAlpn(&.{ "h2", "coap" }, &ab);
    const psk_cs = [_]u16{@backingInt(S12.psk_with_aes_128_gcm_sha256)};
    {
        var s = try C12.serverInit(psk12(.server));
        defer s.deinit();
        const r = try s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, clientHello12(&b, &psk_cs, &.{ ri_ext, ems_ext, .{ .ext_type = m12.ext_alpn, .data = offer } })), ent(), 0, &out);
        try testing.expectEqual(@as(?[]const u8, null), shExtension(r.out, m12.ext_alpn));
        try testing.expectEqual(@as(?[]const u8, null), s.negotiatedAlpn());
    }
    var cfg = psk12(.server);
    cfg.alpn_protocols = &.{"coap"};
    {
        var s = try C12.serverInit(cfg);
        defer s.deinit();
        _ = try s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, clientHello12(&b, &psk_cs, &.{ ri_ext, ems_ext })), ent(), 0, &out);
        try testing.expectEqual(@as(?[]const u8, null), s.negotiatedAlpn());
    }
    {
        var s = try C12.serverInit(cfg);
        defer s.deinit();
        const r = try s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, clientHello12(&b, &psk_cs, &.{ ri_ext, ems_ext, .{ .ext_type = m12.ext_alpn, .data = offer } })), ent(), 0, &out);
        try testing.expectEqualStrings("coap", s.negotiatedAlpn().?);
        try testing.expectEqualStrings("coap", try m.decodeAlpnSelected(shExtension(r.out, m12.ext_alpn).?));
    }
}

/// Server answered `ch`; feed it `msgs` as the client's second flight.
fn serverFed(cfg: conn13.Config, ch: []const u8, msgs: []const Msg) !void {
    var s = try C12.serverInit(cfg);
    defer s.deinit();
    var out: [4096]u8 = undefined;
    var dg: [2048]u8 = undefined;
    _ = try s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, ch), ent(), 0, &out);
    _ = try s.handleFlight(flightOf(&dg, 1, msgs), ent(), 0, &out);
}

test "audit: dtls12 server refuses a malformed ClientKeyExchange" {
    var b: [512]u8 = undefined;
    var gb: [16]u8 = undefined;
    const groups = try m.encodeSupportedGroups(&.{0x001d}, &gb);
    // PSK: nothing after the identity.
    const ch_psk = clientHello12(&b, &.{@backingInt(S12.psk_with_aes_128_gcm_sha256)}, &.{ ri_ext, ems_ext });
    var cke: [64]u8 = undefined;
    const id = try m12.encodeOpaque16("device-12", &cke);
    cke[id.len] = 0;
    try testing.expectError(error.Malformed, serverFed(psk12(.server), ch_psk, &.{.{ .t = HT.client_key_exchange, .body = cke[0 .. id.len + 1] }}));
    // ECDHE_PSK: the point must be the group's size.
    var b2: [512]u8 = undefined;
    const ch_e = clientHello12(&b2, &.{@backingInt(S12.ecdhe_psk_with_chacha20_poly1305_sha256)}, &.{ ri_ext, ems_ext, .{ .ext_type = m12.ext_supported_groups, .data = groups } });
    const pt: [31]u8 = @splat(9);
    const p = try m12.encodePoint(&pt, cke[id.len..]);
    try testing.expectError(error.MissingKeyShare, serverFed(psk12(.server), ch_e, &.{.{ .t = HT.client_key_exchange, .body = cke[0 .. id.len + p.len] }}));
}

fn drive12(client: *C12, server: *C12) !void {
    var a: [8192]u8 = undefined;
    var bb: [8192]u8 = undefined;
    var to_server: []const u8 = try client.startHandshake(ent(), 0, &a);
    for (0..8) |_| {
        const s = try server.handleFlight(to_server, ent(), 0, &bb);
        if (client.isConnected() and server.isConnected()) return;
        const c = try client.handleFlight(s.out, ent(), 0, &a);
        if (client.isConnected() and server.isConnected()) return;
        to_server = c.out;
    }
    return error.TestHandshakeDidNotComplete;
}

test "audit: dtls12 API before and after the handshake" {
    // A 1.3-only config is no 1.2 server.
    const only13 = [_]conn13.ProtocolVersion{.dtls13};
    var c13cfg = psk12(.server);
    c13cfg.versions = &only13;
    try testing.expectError(error.InvalidVersions, C12.serverInit(c13cfg));
    var client = try C12.clientInit(psk12(.client));
    defer client.deinit();
    var server = try C12.serverInit(psk12(.server));
    defer server.deinit();
    var buf: [20000]u8 = undefined;
    var o2: [20000]u8 = undefined;
    // Before the handshake.
    try testing.expectError(error.WrongState, server.startHandshake(ent(), 0, &buf));
    try testing.expectError(error.NotConnected, client.send("x", &buf));
    try testing.expectError(error.NotConnected, client.recv(&@as([20]u8, @splat(0)), &buf));
    var km: [16]u8 = undefined;
    try testing.expectError(error.NotConnected, client.exportKeyingMaterial("EXPERIMENTAL x", null, &km));
    try drive12(&client, &server);
    try testing.expectError(error.WrongState, client.startHandshake(ent(), 0, &buf));
    try testing.expectEqual(@as(?[]const u8, null), client.negotiatedAlpn());
    // Record size: 2^14 bytes of plaintext, not one more.
    const big: [16385]u8 = @splat(1);
    try testing.expectError(error.BufferTooShort, client.send(&big, &buf));
    const rec = try client.send(big[0..16384], &buf);
    try testing.expectEqual(@as(usize, 16384), (try server.recv(rec, &o2)).len);
    // Each record its own sequence number.
    const r1 = try client.send("one", &buf);
    try testing.expectEqualStrings("one", try server.recv(r1, &o2));
    const r2 = try client.send("two", &buf);
    try testing.expectEqualStrings("two", try server.recv(r2, &o2));
    // Short / truncated / empty-handshake / unknown-epoch records.
    try testing.expectError(error.RecordTooShort, server.recv(r2[0..12], &o2));
    var hdr13: [13]u8 = undefined;
    _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = 9, .length = 0 }, &hdr13);
    try testing.expectError(error.ReceivedPostHandshakeMessage, client.recv(&hdr13, &o2));
    _ = try record.encodePlaintext(.{ .content_type = 23, .epoch = 1, .sequence_number = 9, .length = 5 }, &hdr13);
    try testing.expectError(error.RecordTooShort, client.recv(&hdr13, &o2));
    const e2 = try record12.seal(&client.write_keys, 2, 50, 23, "epoch two", &buf);
    try testing.expectError(error.Malformed, server.recv(e2, &o2));
    // An encrypted alert of the wrong size.
    const bad_alert = try record12.seal(&client.write_keys, 1, 60, 21, "abc", &buf);
    try testing.expectError(error.Malformed, server.recv(bad_alert, &o2));
    // Only a handshake record to the SERVER asks for its last flight again.
    var a0: [15]u8 = undefined;
    _ = try record.encodePlaintext(.{ .content_type = 21, .epoch = 0, .sequence_number = 70, .length = 2 }, &a0);
    a0[13..15].* = .{ 1, 0 };
    try testing.expectError(error.ReceivedPostHandshakeMessage, server.recv(&a0, &o2));
    try testing.expectEqual(@as(?[]const u8, null), try server.poll(0, &o2));
    var h0: [13 + 12]u8 = undefined;
    _ = hsRec(&h0, 71, HT.finished, 9, "");
    try testing.expectError(error.ReceivedPostHandshakeMessage, client.recv(&h0, &o2));
    try testing.expectEqual(@as(?[]const u8, null), try client.poll(0, &o2));
    var hs1: [64]u8 = undefined;
    const h1 = try record12.seal(&server.write_keys, 1, 80, 22, &@as([12]u8, @splat(0)), &hs1);
    try testing.expectError(error.ReceivedPostHandshakeMessage, client.recv(h1, &o2));
    try testing.expectEqual(@as(?[]const u8, null), try client.poll(0, &o2));
    // Sequence-number ceiling.
    client.send_seq[1] = std.math.maxInt(u48);
    try testing.expectError(error.SequenceNumberExhausted, client.send("x", &buf));
    // No exporter without the extended master secret (a non-RFC 7627 peer).
    server.ems = false;
    try testing.expectError(error.ExtendedMasterSecretRequired, server.exportKeyingMaterial("EXPERIMENTAL x", null, &km));
}

test "audit: dtls12 PSK of 512 bytes works, 513 is KeyExchangeFailed (plain PSK premaster sizing)" {
    // Plain PSK's premaster is 2 + psk.len zero bytes + 2 + psk; the buffer
    // used to hold only 2 + 80 + 2 + 512, so 297..512-byte PSKs overflowed it.
    const long: [513]u8 = @splat(0x61);
    for ([_]usize{ 296, 297, 512 }) |n| for (psk_suites) |suite| {
        var cc = psk12(.client);
        var sc = psk12(.server);
        cc.psk = long[0..n];
        sc.psk = long[0..n];
        cc.cipher_suites12 = &.{suite};
        sc.cipher_suites12 = &.{suite};
        var client = try C12.clientInit(cc);
        defer client.deinit();
        var server = try C12.serverInit(sc);
        defer server.deinit();
        try drive12(&client, &server);
    };
    var cc = psk12(.client);
    var sc = psk12(.server);
    cc.psk = &long;
    sc.psk = &long;
    var client = try C12.clientInit(cc);
    defer client.deinit();
    var server = try C12.serverInit(sc);
    defer server.deinit();
    try testing.expectError(error.KeyExchangeFailed, drive12(&client, &server));
}

test "audit: dtls12 fromDualClientHello body bounds" {
    const body: [2049]u8 = @splat(0);
    try testing.expectError(error.Malformed, C12.fromDualClientHello(psk12(.client), body[0..33], 0, 0));
    try testing.expectError(error.Malformed, C12.fromDualClientHello(psk12(.client), &body, 0, 0));
    var lo = try C12.fromDualClientHello(psk12(.client), body[0..34], 0, 0);
    lo.deinit();
    var hi = try C12.fromDualClientHello(psk12(.client), body[0..2048], 0, 0);
    hi.deinit();
}

// ── Connection.zig ───────────────────────────────────────────────────────

test "audit: Config.validate — at most two versions, the ALPN list up to its 256-byte cap" {
    const three = [_]conn13.ProtocolVersion{ .dtls13, .dtls12, .dtls13 };
    var cfg: conn13.Config = .{ .role = .client, .psk_identity = "id", .psk = "a pre-shared key", .versions = &three };
    try testing.expectError(error.InvalidVersions, cfg.validate());
    cfg.versions = &.{.dtls13};
    // The whole list: 2 + sum(1 + len) <= 256.
    const name: [254]u8 = @splat('a');
    cfg.alpn_protocols = &.{&name};
    try testing.expectError(error.InvalidAlpnProtocols, cfg.validate());
    cfg.alpn_protocols = &.{name[0..253]};
    try cfg.validate();
}

fn ccsAt(buf: []u8, rseq: u48, body: []const u8) []u8 {
    _ = record.encodePlaintext(.{ .content_type = 20, .epoch = 0, .sequence_number = rseq, .length = @intCast(body.len) }, buf) catch unreachable;
    @memcpy(buf[13..][0..body.len], body);
    return buf[0 .. 13 + body.len];
}

test "audit: dtls12 client after its final flight: Finished only in epoch 1, CCS exact, unexpected CCS ignored" {
    var b: [512]u8 = undefined;
    const sh_psk = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext });
    var dg: [512]u8 = undefined;
    var out: [4096]u8 = undefined;
    {
        // A CCS before the ServerHelloDone is ignored, nothing is resent.
        var c = try clientFed(psk12(.client), &.{.{ .t = HT.server_hello, .body = sh_psk }});
        defer c.deinit();
        const r = try c.handleFlight(ccsAt(&dg, 1, &.{1}), ent(), 0, &out);
        try testing.expectEqual(@as(usize, 0), r.out.len);
    }
    var c = try clientFed(psk12(.client), &.{ .{ .t = HT.server_hello, .body = sh_psk }, .{ .t = HT.server_hello_done, .body = "" } });
    defer c.deinit();
    // CCS bodies other than {1}.
    try testing.expectError(error.Malformed, c.handleFlight(ccsAt(&dg, 2, &.{2}), ent(), 0, &out));
    try testing.expectError(error.Malformed, c.handleFlight(ccsAt(&dg, 2, &.{ 1, 1 }), ent(), 0, &out));
    // A plaintext Finished, or any other plaintext message, where the Finished is due.
    try testing.expectError(error.UnexpectedMessage, c.handleFlight(hsRec(&dg, 2, HT.finished, 2, &@as([12]u8, @splat(0))), ent(), 0, &out));
    try testing.expectError(error.UnexpectedMessage, c.handleFlight(hsRec(&dg, 2, HT.server_hello_done, 2, ""), ent(), 0, &out));
    // An encrypted Finished with the wrong verify_data.
    var rec: [128]u8 = undefined;
    const ccs = ccsAt(&dg, 2, &.{1});
    var msg: [12 + 12]u8 = undefined;
    handshake.encodeHeader(.{ .msg_type = HT.finished, .length = 12, .message_seq = 2, .fragment_offset = 0, .fragment_length = 12 }, msg[0..12]);
    @memset(msg[12..], 0x77);
    const fin = try record12.seal(&c.read_keys, 1, 0, 22, &msg, &rec);
    var both: [256]u8 = undefined;
    @memcpy(both[0..ccs.len], ccs);
    @memcpy(both[ccs.len..][0..fin.len], fin);
    try testing.expectError(error.FinishedVerifyFailed, c.handleFlight(both[0 .. ccs.len + fin.len], ent(), 0, &out));
}

fn pskCke(buf: []u8) []u8 {
    return m12.encodeOpaque16("device-12", buf) catch unreachable;
}

test "audit: dtls12 server message order: ClientHello first, one ClientKeyExchange, no CertificateVerify without a certificate" {
    var b: [512]u8 = undefined;
    var dg: [512]u8 = undefined;
    var out: [4096]u8 = undefined;
    var kb: [64]u8 = undefined;
    {
        var s = try C12.serverInit(psk12(.server));
        defer s.deinit();
        try testing.expectError(error.UnexpectedMessage, s.handleFlight(hsRec(&dg, 0, HT.client_key_exchange, 0, pskCke(&kb)), ent(), 0, &out));
    }
    const ch = clientHello12(&b, &.{@backingInt(S12.psk_with_aes_128_gcm_sha256)}, &.{ ri_ext, ems_ext });
    try testing.expectError(error.UnexpectedMessage, serverFed(psk12(.server), ch, &.{ .{ .t = HT.client_key_exchange, .body = pskCke(&kb) }, .{ .t = HT.client_key_exchange, .body = pskCke(&kb) } }));
    try testing.expectError(error.UnexpectedMessage, serverFed(psk12(.server), ch, &.{ .{ .t = HT.client_key_exchange, .body = pskCke(&kb) }, .{ .t = HT.certificate_verify, .body = &.{ 4, 3, 0, 1, 0 } } }));
}

test "audit: dtls12 server datagram framing, duplicates and lengths" {
    var b: [512]u8 = undefined;
    var dg: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const ch = clientHello12(&b, &.{@backingInt(S12.psk_with_aes_128_gcm_sha256)}, &.{ ri_ext, ems_ext });
    {
        // A non-DTLS record version.
        var s = try C12.serverInit(psk12(.server));
        defer s.deinit();
        const r = hsRec(&dg, 0, HT.client_hello, 0, ch);
        r[1] = 3;
        r[2] = 3;
        try testing.expectError(error.Malformed, s.handleFlight(r, ent(), 0, &out));
        // Five stray bytes after the record; an empty 13-byte record is fine.
        const r2 = hsRec(&dg, 0, HT.client_hello, 0, ch);
        @memset(dg[r2.len..][0..5], 0);
        try testing.expectError(error.Malformed, s.handleFlight(dg[0 .. r2.len + 5], ent(), 0, &out));
        _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = 1, .length = 0 }, dg[r2.len..]);
        const ok = try s.handleFlight(dg[0 .. r2.len + 13], ent(), 0, &out);
        try testing.expect(ok.out.len > 0);
        // The same record again (same record number) is dropped silently; a
        // retransmitted ClientHello (new record number) gets the flight again,
        // and only that one call does.
        const again = try s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, ch), ent(), 0, &out);
        try testing.expectEqual(@as(usize, 0), again.out.len);
        const re = try s.handleFlight(hsRec(&dg, 5, HT.client_hello, 0, ch), ent(), 0, &out);
        try testing.expect(re.out.len > 0);
        const quiet = try s.handleFlight(ccsAt(&dg, 6, &.{1}), ent(), 0, &out);
        try testing.expectEqual(@as(usize, 0), quiet.out.len);
    }
    {
        // A message longer than max_message_len; one of exactly that length is accepted (in progress).
        var s = try C12.serverInit(psk12(.server));
        defer s.deinit();
        _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = 0, .length = 12 + 4 }, &dg);
        handshake.encodeHeader(.{ .msg_type = HT.client_hello, .length = c12.max_message_len + 1, .message_seq = 0, .fragment_offset = 0, .fragment_length = 4 }, dg[13..25]);
        try testing.expectError(error.FlightTooLarge, s.handleFlight(dg[0..29], ent(), 0, &out));
        handshake.encodeHeader(.{ .msg_type = HT.client_hello, .length = c12.max_message_len, .message_seq = 0, .fragment_offset = 0, .fragment_length = 4 }, dg[13..25]);
        const r = try s.handleFlight(dg[0..29], ent(), 0, &out);
        try testing.expect(r.need_more_data);
        // A fragment longer than its record.
        _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = 1, .length = 12 + 4 }, &dg);
        handshake.encodeHeader(.{ .msg_type = HT.client_hello, .length = 10, .message_seq = 0, .fragment_offset = 0, .fragment_length = 10 }, dg[13..25]);
        try testing.expectError(error.Malformed, s.handleFlight(dg[0..29], ent(), 0, &out));
    }
}

test "audit: dtls12 stateless HelloVerifyRequest keeps no state: a repeated cookieless ClientHello gets another HVR" {
    var cfg = psk12(.server);
    cfg.hello_retry = .{ .cookie_secret = "cookie secret", .peer_binding = "peer" };
    var s = try C12.serverInit(cfg);
    defer s.deinit();
    var b: [512]u8 = undefined;
    var dg: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const ch = clientHello12(&b, &.{@backingInt(S12.psk_with_aes_128_gcm_sha256)}, &.{ ri_ext, ems_ext });
    for (0..3) |i| {
        const r = try s.handleFlight(hsRec(&dg, @intCast(i), HT.client_hello, 0, ch), ent(), 0, &out);
        var t: [4]u8 = undefined;
        try testing.expectEqualSlices(u8, &.{HT.hello_verify_request}, flightTypes(r.out, &t));
    }
}

test "audit: dtls12 client ClientHello: ALPN offered with EMS and RI, more than 16 suites, exact output buffer, sequence ceiling" {
    var cfg = psk12(.client);
    cfg.alpn_protocols = &.{"coap"};
    var c = try C12.clientInit(cfg);
    defer c.deinit();
    var out: [4096]u8 = undefined;
    const fl = try c.startHandshake(ent(), 0, &out);
    var ext: [8]m12.Extension = undefined;
    const ch = try m12.decodeClientHello(fl[25..], &ext);
    try testing.expect(m12.findExtension(ch.extensions, m12.ext_alpn) != null);
    try testing.expect(m12.findExtension(ch.extensions, m12.ext_extended_master_secret) != null);
    try testing.expect(m12.findExtension(ch.extensions, m12.ext_renegotiation_info) != null);
    // Exact buffer / one byte short.
    {
        var c2 = try C12.clientInit(cfg);
        defer c2.deinit();
        var o2: [4096]u8 = undefined;
        try testing.expectError(error.BufferTooShort, c2.startHandshake(ent(), 0, o2[0 .. fl.len - 1]));
        var c3 = try C12.clientInit(cfg);
        defer c3.deinit();
        try testing.expectEqual(fl.len, (try c3.startHandshake(ent(), 0, o2[0..fl.len])).len);
    }
    // At most 16 suites go into the ClientHello.
    var many: [17]S12 = @splat(.psk_with_aes_128_gcm_sha256);
    var cfg17 = psk12(.client);
    cfg17.cipher_suites12 = &many;
    var c17 = try C12.clientInit(cfg17);
    defer c17.deinit();
    const f17 = try c17.startHandshake(ent(), 0, &out);
    try testing.expectEqual(@as(usize, 32), (try m12.decodeClientHello(f17[25..], &ext)).cipher_suites_raw.len);
    // The epoch-0 sequence ceiling.
    var cmax = try C12.clientInit(psk12(.client));
    defer cmax.deinit();
    cmax.send_seq[0] = std.math.maxInt(u48);
    try testing.expectError(error.SequenceNumberExhausted, cmax.startHandshake(ent(), 0, &out));
}

test "audit: dtls12 certificate options: a PSK identity hint does not leak into ECDHE_ECDSA, no CertificateRequest under PSK, an optional client certificate may be absent" {
    {
        var sc = ecdsa12(.server);
        sc.psk_identity_hint = "hint";
        var client = try C12.clientInit(ecdsa12(.client));
        defer client.deinit();
        var server = try C12.serverInit(sc);
        defer server.deinit();
        try drive12(&client, &server);
    }
    {
        var sc = psk12(.server);
        sc.request_client_cert = true;
        sc.peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der };
        var s = try C12.serverInit(sc);
        defer s.deinit();
        var b: [512]u8 = undefined;
        var dg: [1024]u8 = undefined;
        var out: [4096]u8 = undefined;
        const r = try s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, clientHello12(&b, &.{@backingInt(S12.psk_with_aes_128_gcm_sha256)}, &.{ ri_ext, ems_ext })), ent(), 0, &out);
        var t: [8]u8 = undefined;
        try testing.expectEqualSlices(u8, &.{ HT.server_hello, HT.server_hello_done }, flightTypes(r.out, &t));
    }
    {
        var sc = ecdsa12(.server);
        sc.request_client_cert = true;
        sc.peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der };
        var client = try C12.clientInit(ecdsa12(.client));
        defer client.deinit();
        var server = try C12.serverInit(sc);
        defer server.deinit();
        try drive12(&client, &server);
    }
}

// ── Connection12, audit run 2 (2026-11-17) ───────────────────────────────

const psk_cs12 = [_]u16{@backingInt(S12.psk_with_aes_128_gcm_sha256)};

/// One plaintext epoch-0 record holding one fragment of a message.
fn hsFrag(buf: []u8, rseq: u48, t: u8, mseq: u16, total: u24, off: u24, frag: []const u8) []u8 {
    _ = record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = rseq, .length = @intCast(handshake.header_len + frag.len) }, buf) catch unreachable;
    handshake.encodeHeader(.{ .msg_type = t, .length = total, .message_seq = mseq, .fragment_offset = off, .fragment_length = @intCast(frag.len) }, buf[13..][0..handshake.header_len]);
    @memcpy(buf[13 + handshake.header_len ..][0..frag.len], frag);
    return buf[0 .. 13 + handshake.header_len + frag.len];
}

/// `flightOf` with the record sequence numbers starting at `rseq0`.
fn flightAt(buf: []u8, rseq0: u48, mseq0: u16, msgs: []const Msg) []u8 {
    var n: usize = 0;
    for (msgs, 0..) |mm, i| n += hsRec(buf[n..], rseq0 + @as(u48, @intCast(i)), mm.t, mseq0 + @as(u16, @intCast(i)), mm.body).len;
    return buf[0..n];
}

/// `fl` with its (last) epoch-1 record — the Finished — re-sealed under
/// `keys` with `extra` appended to the verify_data and its first byte xored
/// with `flip`.
fn forgeFinished(fl: []const u8, keys: *const record12.DirKeys, extra: []const u8, flip: u8, out: []u8) ![]u8 {
    var p: usize = 0;
    var at: usize = fl.len;
    while (p + 13 <= fl.len) {
        const h = try record.decodePlaintext(fl[p..]);
        if (h.epoch == 1) at = p;
        p += 13 + h.length;
    }
    const h = try record.decodePlaintext(fl[at..]);
    var pt: [64]u8 = undefined;
    const plain = try record12.open(keys, h, fl[at + 13 ..][0..h.length], &pt);
    const hh = try handshake.decodeHeader(plain);
    const vd_len = plain.len - handshake.header_len;
    const n = vd_len + extra.len;
    var msg: [96]u8 = undefined;
    handshake.encodeHeader(.{ .msg_type = hh.msg_type, .length = @intCast(n), .message_seq = hh.message_seq, .fragment_offset = 0, .fragment_length = @intCast(n) }, msg[0..handshake.header_len]);
    @memcpy(msg[handshake.header_len..][0..vd_len], plain[handshake.header_len..]);
    msg[handshake.header_len] ^= flip;
    @memcpy(msg[handshake.header_len + vd_len ..][0..extra.len], extra);
    @memcpy(out[0..at], fl[0..at]);
    const rec = try record12.seal(keys, 1, h.sequence_number, 22, msg[0 .. handshake.header_len + n], out[at..]);
    return out[0 .. at + rec.len];
}

test "audit: dtls12 stateless server: a retransmitted ClientHello is answered again, one answer per datagram" {
    var cfg = psk12(.server);
    cfg.hello_retry = .{ .cookie_secret = "dtls12 audit cookie secret", .peer_binding = "198.51.100.7:5684" };
    var s = try C12.serverInit(cfg);
    defer s.deinit();
    var b: [512]u8 = undefined;
    var dg: [2048]u8 = undefined;
    var out: [4096]u8 = undefined;
    const ch = clientHello12(&b, &psk_cs12, &.{ ri_ext, ems_ext });
    const rec_len = hsRec(&dg, 0, HT.client_hello, 0, ch).len;
    var first: [256]u8 = undefined;
    const r1 = try s.handleFlight(dg[0..rec_len], ent(), 0, &out);
    const n1 = r1.out.len;
    try testing.expect(n1 > 0 and n1 <= first.len);
    @memcpy(first[0..n1], r1.out);
    // The identical datagram again (our HelloVerifyRequest was lost): the
    // server kept nothing, so it answers again, byte for byte.
    try testing.expectEqualSlices(u8, first[0..n1], (try s.handleFlight(dg[0..rec_len], ent(), 0, &out)).out);
    // Two ClientHello records in one datagram: one answer.
    const second = hsRec(dg[rec_len..], 1, HT.client_hello, 0, ch);
    try testing.expectEqual(n1, (try s.handleFlight(dg[0 .. rec_len + second.len], ent(), 0, &out)).out.len);
    // Two ClientHello messages in one record: one answer.
    const msg_len = handshake.header_len + ch.len;
    _ = hsRec(&dg, 2, HT.client_hello, 0, ch); // its record header is rewritten for two messages
    _ = record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = 2, .length = @intCast(2 * msg_len) }, &dg) catch unreachable;
    @memcpy(dg[13 + msg_len ..][0..msg_len], dg[13..][0..msg_len]);
    try testing.expectEqual(n1, (try s.handleFlight(dg[0 .. 13 + 2 * msg_len], ent(), 0, &out)).out.len);
}

test "audit: dtls12 client: a server flight retransmitted inside the same datagram is answered once" {
    var b: [512]u8 = undefined;
    const sh = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext });
    const msgs = [_]Msg{ .{ .t = HT.server_hello, .body = sh }, .{ .t = HT.server_hello_done, .body = "" } };
    var out: [4096]u8 = undefined;
    var dg: [4096]u8 = undefined;
    var c1 = try C12.clientInit(psk12(.client));
    defer c1.deinit();
    _ = try c1.startHandshake(ent(), 0, &out);
    const n_once = (try c1.handleFlight(flightAt(&dg, 0, 0, &msgs), ent(), 0, &out)).out.len;
    try testing.expect(n_once > 0);
    var c2 = try C12.clientInit(psk12(.client));
    defer c2.deinit();
    _ = try c2.startHandshake(ent(), 0, &out);
    const a = flightAt(&dg, 0, 0, &msgs).len;
    const a2 = flightAt(dg[a..], 10, 0, &msgs).len;
    try testing.expectEqual(n_once, (try c2.handleFlight(dg[0 .. a + a2], ent(), 0, &out)).out.len);
}

test "audit: dtls12 after the handshake: handleFlight resends nothing, and a client owes no flight for a peer's epoch-1 handshake record" {
    var c = try C12.clientInit(psk12(.client));
    defer c.deinit();
    var sc = psk12(.server);
    sc.require_peer_cert = true; // no CertificateRequest in PSK: nothing to require
    var s = try C12.serverInit(sc);
    defer s.deinit();
    try drive12(&c, &s);
    var dg: [256]u8 = undefined;
    var out: [4096]u8 = undefined;
    // A retransmitted ClientKeyExchange (message_seq 1) with a fresh record number.
    const r = try s.handleFlight(hsRec(&dg, 40, HT.client_key_exchange, 1, "x"), ent(), 0, &out);
    try testing.expectEqual(@as(usize, 0), r.out.len);
    // The server's Finished again, under epoch 1: reported, but the client
    // has no flight to resend.
    var rb: [64]u8 = undefined;
    const rec = try record12.seal(&s.write_keys, 1, s.send_seq[1], 22, &.{ 20, 0, 0, 0 }, &rb);
    s.send_seq[1] += 1;
    try testing.expectError(error.ReceivedPostHandshakeMessage, c.recv(rec, &out));
    try testing.expectEqual(@as(?[]const u8, null), try c.poll(1_000_000, &out));
    // The client's Finished again: the server owes its last flight.
    const crec = try record12.seal(&c.write_keys, 1, c.send_seq[1], 22, &.{ 20, 0, 0, 0 }, &rb);
    c.send_seq[1] += 1;
    try testing.expectError(error.ReceivedPostHandshakeMessage, s.recv(crec, &out));
    try testing.expect((try s.poll(1_000_000, &out)) != null);
}

test "audit: dtls12 stateless server: a fragment of a different ClientHello does not complete the one in progress" {
    var s = try C12.serverInit(psk12(.server));
    defer s.deinit();
    var b: [512]u8 = undefined;
    var dg: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const ch = clientHello12(&b, &psk_cs12, &.{ ri_ext, ems_ext });
    const k = ch.len / 2;
    const total: u24 = @intCast(ch.len);
    const r1 = try s.handleFlight(hsFrag(&dg, 0, HT.client_hello, 0, total, 0, ch[0..k]), ent(), 0, &out);
    try testing.expect(r1.need_more_data and r1.out.len == 0);
    const r2 = try s.handleFlight(hsFrag(&dg, 1, HT.client_hello, 1, total, @intCast(k), ch[k..]), ent(), 0, &out);
    try testing.expectEqual(@as(usize, 0), r2.out.len);
    const r3 = try s.handleFlight(hsFrag(&dg, 2, HT.client_hello, 0, total, @intCast(k), ch[k..]), ent(), 0, &out);
    try testing.expect(r3.out.len > 0);
}

test "audit: dtls12 Finished: one byte too long or one bit off is refused on both sides" {
    var c = try C12.clientInit(psk12(.client));
    defer c.deinit();
    var s = try C12.serverInit(psk12(.server));
    defer s.deinit();
    var a: [4096]u8 = undefined;
    var bb: [4096]u8 = undefined;
    var f: [4096]u8 = undefined;
    const ch = try c.startHandshake(ent(), 0, &a);
    const f4 = try s.handleFlight(ch, ent(), 0, &bb);
    const fin = try c.handleFlight(f4.out, ent(), 0, &a);
    try testing.expectError(error.FinishedVerifyFailed, s.handleFlight(try forgeFinished(fin.out, &c.write_keys, &.{0}, 0, &f), ent(), 0, &bb));
    try testing.expectError(error.FinishedVerifyFailed, s.handleFlight(try forgeFinished(fin.out, &c.write_keys, "", 1, &f), ent(), 0, &bb));
    const sf = try s.handleFlight(fin.out, ent(), 0, &bb);
    try testing.expect(sf.done);
    try testing.expectError(error.FinishedVerifyFailed, c.handleFlight(try forgeFinished(sf.out, &s.write_keys, &.{0}, 0, &f), ent(), 0, &a));
    try testing.expect((try c.handleFlight(sf.out, ent(), 0, &a)).done);
}

test "audit: dtls12 server never picks a configured suite of the other key-exchange family" {
    var cfg = ecdsa12(.server);
    cfg.cipher_suites12 = &.{ .psk_with_aes_128_gcm_sha256, .ecdhe_ecdsa_with_aes_128_gcm_sha256 };
    var s = try C12.serverInit(cfg);
    defer s.deinit();
    var b: [512]u8 = undefined;
    var dg: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    try testing.expectError(error.NoCipherSuiteOverlap, s.handleFlight(hsRec(&dg, 0, HT.client_hello, 0, clientHello12(&b, &psk_cs12, &.{ ri_ext, ems_ext })), ent(), 0, &out));
}

test "audit: dtls12 queue retry: a duplicate seen in an earlier call does not trigger a resend" {
    var b: [512]u8 = undefined;
    const sh = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext });
    var c = try clientFed(psk12(.client), &.{.{ .t = HT.server_hello, .body = sh }});
    defer c.deinit();
    var dg: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    // A retransmitted ServerHello, and a forged ServerHelloDone (message 2,
    // a body where none belongs) that is queued.
    const n1 = hsRec(&dg, 1, HT.server_hello, 0, sh).len;
    const n2 = hsRec(dg[n1..], 2, HT.server_hello_done, 2, &.{0}).len;
    _ = try c.handleFlight(dg[0 .. n1 + n2], ent(), 0, &out);
    // The genuine ServerKeyExchange: the queued forgery fails it, the retry
    // from live bytes succeeds, and there is nothing to send.
    const r = try c.handleFlight(hsRec(&dg, 3, HT.server_key_exchange, 1, &.{ 0, 0 }), ent(), 0, &out);
    try testing.expectEqual(@as(usize, 0), r.out.len);
}

test "audit: dtls12 queue retry: once the queue is dropped, later overlaps are plain errors" {
    var b: [512]u8 = undefined;
    const sh = serverHello(&b, .psk_with_aes_128_gcm_sha256, &.{ ri_ext, ems_ext });
    var c = try clientFed(psk12(.client), &.{.{ .t = HT.server_hello, .body = sh }});
    defer c.deinit();
    var dg: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    // A fragment of message 2 (queued), then message 1: the queued fragment
    // starts message 2.
    const n1 = hsFrag(&dg, 1, HT.server_hello_done, 2, 4, 0, &.{ 1, 1 }).len;
    const n2 = hsRec(dg[n1..], 2, HT.server_key_exchange, 1, &.{ 0, 0 }).len;
    _ = try c.handleFlight(dg[0 .. n1 + n2], ent(), 0, &out);
    // A fragment contradicting the queued bytes: the retry from live bytes
    // restarts message 2 with it.
    _ = try c.handleFlight(hsFrag(&dg, 3, HT.server_hello_done, 2, 4, 0, &.{ 2, 2 }), ent(), 0, &out);
    // A fragment contradicting those LIVE bytes is an error: no queue is involved.
    try testing.expectError(error.OverlappingFragment, c.handleFlight(hsFrag(&dg, 4, HT.server_hello_done, 2, 4, 0, &.{ 3, 3 }), ent(), 0, &out));
}
