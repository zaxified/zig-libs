// SPDX-License-Identifier: MIT

//! Killing tests from the 2026-11-26 whole-module mutation run of dtls (see SPEC "Audit").
//! Each test pins a boundary or a refusal that no earlier test reached.

const std = @import("std");
const testing = std.testing;
const aesgcm = @import("aesgcm");
const rsa = @import("rsa");
const aead = @import("aead.zig");
const record = @import("record.zig");
const record12 = @import("record12.zig");
const messages = @import("messages.zig");
const m12 = @import("messages12.zig");
const c12 = @import("Connection12.zig");
const conn13 = @import("Connection.zig");
const suite12 = @import("suite12.zig");
const handshake = @import("handshake.zig");
const sig12 = @import("sig12.zig");
const certauth = @import("certauth.zig");
const flight = @import("flight.zig");
const cert_kat = @import("certauth_kat_vectors.zig");

// ── aead.zig ─────────────────────────────────────────────────────────────

test "mutation 2026-11-26: aead protectCtx / unprotectCtx refuse short buffers and tags" {
    const A = aesgcm.Aes128Gcm;
    const P = aead.Protection(A);
    const key: [16]u8 = @splat(7);
    var ctx: A.Context = undefined;
    A.Context.initInto(&ctx, &key);
    const iv: [12]u8 = @splat(3);
    const pt = "0123456789"; // 10 bytes + 16 tag = 26
    var out: [64]u8 = undefined;
    try testing.expectError(error.BufferTooShort, P.protectCtx(&ctx, iv, 2, 7, pt, "hdr", out[0..25]));
    try testing.expectEqual(@as(usize, 26), try P.protectCtx(&ctx, iv, 2, 7, pt, "hdr", out[0..26]));
    var ct: [26]u8 = undefined;
    @memcpy(&ct, out[0..26]);
    var back: [16]u8 = undefined;
    try testing.expectError(error.RecordTooShort, P.unprotectCtx(&ctx, iv, 2, 7, ct[0..15], "hdr", &back));
    try testing.expectError(error.BufferTooShort, P.unprotectCtx(&ctx, iv, 2, 7, &ct, "hdr", back[0..9]));
    try testing.expectEqual(@as(usize, 10), try P.unprotectCtx(&ctx, iv, 2, 7, &ct, "hdr", back[0..10]));
    try testing.expectEqualSlices(u8, pt, back[0..10]);
}

// ── handshake.zig ────────────────────────────────────────────────────────

test "mutation 2026-11-26: Reassembler.reset clears the latched header" {
    var buf: [16]u8 = undefined;
    var seen: [16]bool = undefined;
    var r = handshake.Reassembler.init(&buf, &seen);
    const hdr: handshake.HandshakeHeader = .{ .msg_type = 1, .length = 10, .message_seq = 3, .fragment_offset = 0, .fragment_length = 4 };
    try testing.expect((try r.feed(hdr, "abcd")) == null);
    try testing.expect(r.total_len != null and r.message_seq != null);
    r.reset();
    try testing.expect(r.total_len == null);
    try testing.expect(r.message_seq == null);
    try testing.expectEqual(@as(usize, 0), r.received_bytes);
}

// ── record.zig ───────────────────────────────────────────────────────────

/// A `tls12_cid` record (RFC 9146 §4): type 25, DTLS 1.2 version, epoch 1, sequence number 7, `cid_len`
/// bytes of CID, a 2-byte length (`declared`), then `have` payload bytes.
fn cidRecord(out: []u8, cid_len: usize, declared: u16, have: usize) []u8 {
    out[0] = 25;
    out[1] = 0xfe;
    out[2] = 0xfd;
    std.mem.writeInt(u16, out[3..5], 1, .big);
    @memset(out[5..11], 0);
    out[10] = 7;
    @memset(out[11..][0..cid_len], 0xc1);
    std.mem.writeInt(u16, out[11 + cid_len ..][0..2], declared, .big);
    @memset(out[13 + cid_len ..][0..have], 0xaa);
    return out[0 .. 13 + cid_len + have];
}

test "mutation 2026-11-26: nextDatagramCid splits tls12_cid records at their wire length" {
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    var cat: [160]u8 = undefined;
    const cid_len = 4;
    const r1 = cidRecord(&a, cid_len, 5, 5); // 22 bytes
    const r2 = cidRecord(&b, cid_len, 5, 5); // 22 bytes
    @memcpy(cat[0..22], r1);
    @memcpy(cat[22..44], r2);
    // Two records, room for one: split after the first.
    var s = record.nextDatagramCid(cat[0..44], 22, cid_len);
    try testing.expectEqual(@as(usize, 22), s.datagram.len);
    try testing.expectEqual(@as(usize, 22), s.rest.len);
    s = record.nextDatagramCid(cat[0..44], 30, cid_len);
    try testing.expectEqual(@as(usize, 22), s.datagram.len);
    s = record.nextDatagramCid(cat[0..44], 44, cid_len);
    try testing.expectEqual(@as(usize, 44), s.datagram.len);
    try testing.expectEqual(@as(usize, 0), s.rest.len);

    // The last record is header-only (zero payload): it still has its wire length 17, so a limit of 30
    // splits it off instead of falling back to "the whole datagram".
    const z = cidRecord(&b, cid_len, 0, 0);
    try testing.expectEqual(@as(usize, 17), z.len);
    @memcpy(cat[22..39], z);
    s = record.nextDatagramCid(cat[0..39], 30, cid_len);
    try testing.expectEqual(@as(usize, 22), s.datagram.len);
    try testing.expectEqual(@as(usize, 17), s.rest.len);
    // exact fit of a payload-carrying last record
    const e = cidRecord(&b, cid_len, 5, 5);
    @memcpy(cat[22..44], e);
    s = record.nextDatagramCid(cat[0..44], 30, cid_len);
    try testing.expectEqual(@as(usize, 22), s.datagram.len);

    // A truncated tail (declared 50, 5 present) or a header cut short is unparseable: the whole datagram.
    const t = cidRecord(&b, cid_len, 50, 5);
    @memcpy(cat[22 .. 22 + t.len], t);
    s = record.nextDatagramCid(cat[0 .. 22 + t.len], 30, cid_len);
    try testing.expectEqual(22 + t.len, s.datagram.len);
    @memcpy(cat[22..36], b[0..14]);
    s = record.nextDatagramCid(cat[0..36], 30, cid_len);
    try testing.expectEqual(@as(usize, 36), s.datagram.len);

    // A record that fills `max_len` exactly ends the datagram even when what follows is unparseable.
    @memcpy(cat[22..25], &[_]u8{ 0, 0, 0 });
    s = record.nextDatagramCid(cat[0..25], 22, cid_len);
    try testing.expectEqual(@as(usize, 22), s.datagram.len);
    try testing.expectEqual(@as(usize, 3), s.rest.len);
}

test "mutation 2026-11-26: reconstructSequenceNumber uses 16 bits for a long sequence number and the tie rules" {
    try testing.expectEqual(@as(u48, 0x14321), record.reconstructSequenceNumber(0x12345, .long, 0x4321));
    // candidate more than half a window above the expectation: one window down
    try testing.expectEqual(@as(u48, 250), record.reconstructSequenceNumber(265, .short, 250));
    // candidate exactly half a window below: the upper one (tie goes up)
    try testing.expectEqual(@as(u48, 628), record.reconstructSequenceNumber(499, .short, 116));
}

// ── record12.zig ─────────────────────────────────────────────────────────

fn testKeys() record12.DirKeys {
    var k: record12.DirKeys = .{ .bulk = .aes_128_gcm };
    for (&k.key, 0..) |*b, i| b.* = @intCast(i + 1);
    for (&k.iv, 0..) |*b, i| b.* = @intCast(0x40 + i);
    return k;
}

test "mutation 2026-11-26: record12 CID header decode boundaries" {
    var buf: [100]u8 = undefined;
    for ([_]usize{ 0, 4, record12.max_cid_len }) |cl| {
        const rec = cidRecord(&buf, cl, 0, 0);
        const h = try record12.decodeCidHeader(rec, cl); // exactly the header: accepted
        try testing.expectEqual(cl, h.cid.len);
        try testing.expectError(error.Malformed, record12.decodeCidHeader(rec[0 .. rec.len - 1], cl));
    }
    _ = cidRecord(&buf, 33, 0, 0);
    try testing.expectError(error.Malformed, record12.decodeCidHeader(buf[0..60], 33));
    // each of the three leading bytes alone is enough to refuse
    for ([_]usize{ 0, 1, 2 }) |i| {
        const rec = cidRecord(&buf, 4, 0, 0);
        rec[i] ^= 1;
        try testing.expectError(error.Malformed, record12.decodeCidHeader(rec, 4));
    }
}

test "mutation 2026-11-26: record12 sealCid / openCid size guards" {
    const keys = testKeys();
    var out: [70000]u8 = undefined;
    var back: [70000]u8 = undefined;
    var out2: [70000]u8 = undefined;
    const cid33: [33]u8 = @splat(1);
    const cid32: [32]u8 = @splat(1);
    try testing.expectError(error.BufferTooShort, record12.sealCid(&keys, 1, 2, 23, "x", &cid33, &out));
    const rec32 = try record12.sealCid(&keys, 1, 2, 23, "x", &cid32, &out2);
    try testing.expectEqual(record12.CidHeader.len(32) + 1 + 1 + 24, rec32.len);

    // the exact-fit output buffer
    const exact = record12.CidHeader.len(4) + 10 + 1 + 24;
    try testing.expectError(error.BufferTooShort, record12.sealCid(&keys, 1, 2, 23, "0123456789", "abcd", out[0 .. exact - 1]));
    const rec = try record12.sealCid(&keys, 1, 2, 23, "0123456789", "abcd", out[0..exact]);
    try testing.expectEqual(exact, rec.len);

    // the 16-bit fragment length: 65535 is the largest
    const zeros: [65511]u8 = @splat(0x55);
    const big = try record12.sealCid(&keys, 1, 2, 23, zeros[0..65510], &cid32, &out2);
    try testing.expectEqual(@as(u16, 0xffff), std.mem.readInt(u16, big[11 + 32 ..][0..2], .big));
    try testing.expectError(error.BufferTooShort, record12.sealCid(&keys, 1, 2, 23, &zeros, &cid32, &out));

    // openCid: a fragment no longer than the overhead is too short; the output buffer fits the inner text exactly
    const hdr = try record12.decodeCidHeader(rec, 4);
    const frag = rec[record12.CidHeader.len(4)..];
    try testing.expectError(error.RecordTooShort, record12.openCid(&keys, hdr, frag[0..24], &back));
    try testing.expectError(error.RecordTooShort, record12.openCid(&keys, hdr, frag[0..23], &back));
    try testing.expectError(error.BufferTooShort, record12.openCid(&keys, hdr, frag, back[0..10]));
    const o = try record12.openCid(&keys, hdr, frag, back[0..11]);
    try testing.expectEqualSlices(u8, "0123456789", o.plaintext);

    // an authentic record whose inner plaintext is all zeros (type 0, content zeros) has no real type
    const zrec = try record12.sealCid(&keys, 1, 2, 0, &[_]u8{ 0, 0, 0 }, "abcd", &out2);
    const zhdr = try record12.decodeCidHeader(zrec, 4);
    try testing.expectError(error.DecryptionFailed, record12.openCid(&keys, zhdr, zrec[record12.CidHeader.len(4)..], &back));
}

// ── sig12.zig ────────────────────────────────────────────────────────────

test "mutation 2026-11-26: sig12 PKCS#1 v1.5 uses the hash its scheme names" {
    var sk: rsa.SecretKey = undefined;
    try rsa.SecretKey.fromDer(&sk, &cert_kat.rsa12_key_der);
    const pk = try certauth.parseLeafPublicKey(&cert_kat.rsa12_cert_der);
    var prng = std.Random.DefaultPrng.init(5);
    var sig: [1024]u8 = undefined;
    const content = "signed content";
    const s256 = try sig12.sign(sig12.rsa_pkcs1_sha256, .{ .rsa = &sk }, null, content, prng.random(), &sig);
    var keep256: [1024]u8 = undefined;
    @memcpy(keep256[0..s256.len], s256);
    const l256 = s256.len;
    const s384 = try sig12.sign(sig12.rsa_pkcs1_sha384, .{ .rsa = &sk }, null, content, prng.random(), &sig);
    try sig12.verify(sig12.rsa_pkcs1_sha256, pk, content, keep256[0..l256]);
    try sig12.verify(sig12.rsa_pkcs1_sha384, pk, content, s384);
    try testing.expectError(error.CertVerifyFailed, sig12.verify(sig12.rsa_pkcs1_sha256, pk, content, s384));
    try testing.expectError(error.CertVerifyFailed, sig12.verify(sig12.rsa_pkcs1_sha384, pk, content, keep256[0..l256]));
}

// ── messages.zig ─────────────────────────────────────────────────────────

var big_ext_data: [70000]u8 = @splat(0x5a);

test "mutation 2026-11-26: a hello / CertificateRequest encoder at its tightest buffer still reports an oversized extension list" {
    const big: messages.Extension = .{ .ext_type = 21, .data = &big_ext_data };
    var out: [64]u8 = undefined;
    const ch: messages.ClientHello = .{ .random = @splat(1), .legacy_session_id = "", .cipher_suites = &.{0x1301}, .extensions = &.{big} };
    try testing.expectError(error.ListTooLong, messages.encodeClientHello(ch, out[0..42]));
    const sh: messages.ServerHello = .{ .random = @splat(1), .legacy_session_id_echo = "", .cipher_suite = 0x1301, .extensions = &.{big} };
    try testing.expectError(error.ListTooLong, messages.encodeServerHello(sh, out[0..38]));
    try testing.expectError(error.ListTooLong, messages.encodeCertificateRequest(.{ .certificate_request_context = "", .extensions = &.{big} }, out[0..1]));
}

test "mutation 2026-11-26: filterU16ListExtension refuses a list cut short" {
    var out: [4]u16 = undefined;
    try testing.expectError(error.BufferTooShort, messages.filterU16ListExtension(&.{ 0, 4, 0, 1 }, &.{1}, &out));
}

test "mutation 2026-11-26: use_srtp encoder limits (255-byte MKI, 32768 profiles)" {
    var buf: [70000]u8 = undefined;
    const mki255: [255]u8 = @splat(9);
    const mki256: [256]u8 = @splat(9);
    const ok = try messages.encodeUseSrtp(&.{1}, &mki255, &buf);
    try testing.expectEqual(@as(usize, 2 + 2 + 1 + 255), ok.len);
    try testing.expectError(error.Malformed, messages.encodeUseSrtp(&.{1}, &mki256, &buf));
    var profiles: [32768]u16 = @splat(1);
    try testing.expectError(error.ListTooLong, messages.encodeUseSrtp(&profiles, "", &buf));
}

test "mutation 2026-11-26: leafStatus short, zero-length and duplicated extensions" {
    // fewer than four bytes left for a header
    try testing.expectError(error.Malformed, messages.leafStatus(&.{ 1, 2, 3 }));
    // a header-only (zero-length) unknown extension is skipped
    const ok = try messages.leafStatus(&.{ 0xff, 0xff, 0, 0 });
    try testing.expect(ok.ocsp_response == null and ok.sct_list == null);
    // a length running past the end
    try testing.expectError(error.Malformed, messages.leafStatus(&.{ 0xff, 0xff, 0, 5, 1 }));
    // status_request twice
    const one = [_]u8{ 0, 5, 0, 5, 1, 0, 0, 1, 0xAA };
    try testing.expectError(error.Malformed, messages.leafStatus(&(one ++ one)));
    _ = try messages.leafStatus(&one);
}

test "mutation 2026-11-26: CertificateStatus encoder limits and exact fit" {
    var small: [16]u8 = undefined;
    try testing.expectError(error.Malformed, messages.encodeCertificateStatus("", &small));
    try testing.expectError(error.BufferTooShort, messages.encodeCertificateStatus("abcd", small[0..7]));
    try testing.expectEqual(@as(usize, 8), (try messages.encodeCertificateStatus("abcd", small[0..8])).len);
    const big = try testing.allocator.alloc(u8, 0x1000004);
    defer testing.allocator.free(big);
    const resp = try testing.allocator.alloc(u8, 0x1000000);
    defer testing.allocator.free(resp);
    @memset(resp, 7);
    try testing.expectError(error.Malformed, messages.encodeCertificateStatus(resp, big));
    try testing.expectEqual(@as(usize, 0xFFFFFF + 4), (try messages.encodeCertificateStatus(resp[0..0xFFFFFF], big)).len);
}

test "mutation 2026-11-26: stapled Certificate encoder limits (OCSP 65527, SCT 65531, entry extensions 65535) and reserve" {
    const out = try testing.allocator.alloc(u8, 140000);
    defer testing.allocator.free(out);
    const blob = try testing.allocator.alloc(u8, 70000);
    defer testing.allocator.free(blob);
    @memset(blob, 3);
    const certs = [_][]const u8{"cert"};
    // OCSP: 0 and 65528 are refused, 65527 fits
    try testing.expectError(error.Malformed, messages.encodeCertificateStapled("", &certs, .{ .ocsp_response = blob[0..0] }, out));
    try testing.expectError(error.Malformed, messages.encodeCertificateStapled("", &certs, .{ .ocsp_response = blob[0..65528] }, out));
    try testing.expectError(error.Malformed, messages.encodeCertificateStapled("", &certs, .{ .ocsp_response = blob[0..65600] }, out));
    _ = try messages.encodeCertificateStapled("", &certs, .{ .ocsp_response = blob[0..65527] }, out);
    // SCT list: <= 2 and 65532 are refused, 65531 fits
    try testing.expectError(error.Malformed, messages.encodeCertificateStapled("", &certs, .{ .sct_list = blob[0..2] }, out));
    try testing.expectError(error.Malformed, messages.encodeCertificateStapled("", &certs, .{ .sct_list = blob[0..65532] }, out));
    _ = try messages.encodeCertificateStapled("", &certs, .{ .sct_list = blob[0..65531] }, out);
    // the two together: entry extensions of 65536 are refused, 65535 fit
    try testing.expectError(error.Malformed, messages.encodeCertificateStapled("", &certs, .{ .ocsp_response = blob[0..30000], .sct_list = blob[0..35524] }, out));
    const full = try messages.encodeCertificateStapled("", &certs, .{ .ocsp_response = blob[0..30000], .sct_list = blob[0..35523] }, out);
    try testing.expect(full.len > 65535);
    // the encoder reserves two bytes beyond what it writes for a staple / an SCT list: the smallest accepting buffer
    for ([_]messages.LeafStatus{ .{ .ocsp_response = "ocsp-bytes" }, .{ .sct_list = "\x00\x04abcd" } }) |leaf| {
        const l = (try messages.encodeCertificateStapled("", &certs, leaf, out)).len;
        try testing.expectError(error.BufferTooShort, messages.encodeCertificateStapled("", &certs, leaf, out[0 .. l + 1]));
        try testing.expectEqual(l, (try messages.encodeCertificateStapled("", &certs, leaf, out[0 .. l + 2])).len);
    }
}

test "mutation 2026-11-26: decodeCertificate refuses an entry extension running past the list" {
    var entries: [2]messages.CertificateEntry = undefined;
    const buf = [_]u8{ 0, 0, 0, 6, 0, 0, 1, 0xAA, 0xFF, 0xFF };
    try testing.expectError(error.Malformed, messages.decodeCertificate(&buf, &entries));
}

// ── messages12.zig ───────────────────────────────────────────────────────

test "mutation 2026-11-26: m12 encodeClientHello fits an exact buffer and no smaller" {
    const ch: m12.ClientHello = .{ .random = @splat(1), .cipher_suites = &.{0xc02b}, .extensions = &.{} };
    var big: [128]u8 = undefined;
    const l = (try m12.encodeClientHello(ch, &big)).len;
    try testing.expectError(error.BufferTooShort, m12.encodeClientHello(ch, big[0 .. l - 1]));
    try testing.expectEqual(l, (try m12.encodeClientHello(ch, big[0..l])).len);
    // at the tightest buffer (the fixed part only) an oversized extension list is still reported as such
    const ext: messages.Extension = .{ .ext_type = 21, .data = &big_ext_data };
    const ch_big: m12.ClientHello = .{ .random = @splat(1), .cipher_suites = &.{0xc02b}, .extensions = &.{ext} };
    try testing.expectError(error.ListTooLong, m12.encodeClientHello(ch_big, big[0..42]));
}

test "mutation 2026-11-26: m12 decodeCertificateList shape refusals" {
    var out: [2][]const u8 = undefined;
    try testing.expectError(error.Malformed, m12.decodeCertificateList(&.{ 0, 0 }, &out));
    try testing.expectEqual(@as(usize, 0), (try m12.decodeCertificateList(&.{ 0, 0, 0 }, &out)).len);
    // the length word must equal what follows, in both directions
    try testing.expectError(error.Malformed, m12.decodeCertificateList(&.{ 0, 0, 0, 0, 0, 1, 0xAA }, &out));
    try testing.expectError(error.Malformed, m12.decodeCertificateList(&.{ 0, 0, 9, 0, 0, 1, 0xAA }, &out));
    // one or two stray bytes after the last entry
    try testing.expectError(error.Malformed, m12.decodeCertificateList(&.{ 0, 0, 6, 0, 0, 1, 0xAA, 1, 2 }, &out));
    // more entries than the caller's buffer
    try testing.expectError(error.Malformed, m12.decodeCertificateList(&.{ 0, 0, 12, 0, 0, 1, 1, 0, 0, 1, 2, 0, 0, 1, 3 }, &out));
    // an empty entry; an entry longer than the rest
    try testing.expectError(error.Malformed, m12.decodeCertificateList(&.{ 0, 0, 4, 0, 0, 0, 0xAA }, &out));
    try testing.expectError(error.Malformed, m12.decodeCertificateList(&.{ 0, 0, 4, 0, 0, 9, 0xAA }, &out));
    const two = try m12.decodeCertificateList(&.{ 0, 0, 8, 0, 0, 1, 0xAA, 0, 0, 1, 0xBB }, &out);
    try testing.expectEqual(@as(usize, 2), two.len);
}

// ── Connection12.zig ─────────────────────────────────────────────────────

const v12 = [_]conn13.ProtocolVersion{.dtls12};

fn pskCfg(role: conn13.Role) conn13.Config {
    return .{ .role = role, .versions = &v12, .psk_identity = "device-12", .psk = "a 1.2 pre-shared key", .cipher_suites12 = &.{.psk_with_aes_128_gcm_sha256} };
}

const Pair = struct {
    client: c12.Connection12,
    server: c12.Connection12,
    a: [8192]u8 = undefined,
    b: [8192]u8 = undefined,

    fn connect(self: *Pair, with_cid: bool) !void {
        var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x42)));
        const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
        var cc = pskCfg(.client);
        var sc = pskCfg(.server);
        if (with_cid) {
            cc.connection_id = "cidC";
            sc.connection_id = "cidS-long";
        }
        self.client = try c12.Connection12.clientInit(cc);
        self.server = try c12.Connection12.serverInit(sc);
        var to_server: []const u8 = try self.client.startHandshake(rnd, 0, &self.a);
        var rounds: usize = 0;
        while (rounds < 8) : (rounds += 1) {
            const sr = try self.server.handleFlight(to_server, rnd, 0, &self.b);
            if (self.client.isConnected() and self.server.isConnected()) return;
            const cr = try self.client.handleFlight(sr.out, rnd, 0, &self.a);
            if (self.client.isConnected() and self.server.isConnected()) return;
            to_server = cr.out;
        }
        return error.TestHandshakeDidNotComplete;
    }
};

test "mutation 2026-11-26: Connection12 fresh state, deinit flags, empty and CID-less datagrams" {
    var fresh = try c12.Connection12.clientInit(pskCfg(.client));
    try testing.expect(fresh.sessionTicket() == null);
    try testing.expect(fresh.negotiatedSuite() == null);
    var buf: [256]u8 = undefined;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(1)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    try testing.expectError(error.WrongState, fresh.handleFlight(&.{}, rnd, 0, &buf));
    try testing.expect((try fresh.poll(0, &buf)) == null);
    fresh.ticket_live = true;
    fresh.keys_live = true;
    fresh.ecdhe_live = true;
    fresh.deinit();
    try testing.expect(!fresh.ticket_live and !fresh.keys_live and !fresh.ecdhe_live);

    var pair: Pair = undefined;
    try pair.connect(false);
    try testing.expect(pair.client.negotiatedSuite() != null);
    // an empty datagram is refused without a panic
    if (pair.client.recv(&.{}, &buf)) |_| return error.TestUnexpectedResult else |_| {}
    // a tls12_cid record on a connection that negotiated no CID
    var rec: [64]u8 = undefined;
    const r = cidRecord(&rec, 0, 5, 5);
    try testing.expectError(error.Malformed, pair.client.recv(r, &buf));
}

var hs_rseq: u48 = 0;

fn hsRecord(t: u8, seq: u16, body: []const u8, out: []u8) []const u8 {
    var hh: [handshake.header_len]u8 = undefined;
    handshake.encodeHeader(.{ .msg_type = t, .length = @intCast(body.len), .message_seq = seq, .fragment_offset = 0, .fragment_length = @intCast(body.len) }, &hh);
    _ = record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = hs_rseq, .length = @intCast(body.len + 12) }, out) catch unreachable;
    @memcpy(out[13..25], &hh);
    @memcpy(out[25..][0..body.len], body);
    return out[0 .. 25 + body.len];
}

const ems_x = m12.Extension{ .ext_type = m12.ext_extended_master_secret, .data = &.{} };
const ri_x = m12.Extension{ .ext_type = m12.ext_renegotiation_info, .data = &m12.renegotiation_info_initial };

/// The client `cfg` after startHandshake sees a ServerHello carrying `extra` (plus EMS and RI).
fn clientSees(cfg: conn13.Config, extra: m12.Extension) !void {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(10)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var client = try c12.Connection12.clientInit(cfg);
    var out: [4096]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &out);
    var body_buf: [512]u8 = undefined;
    const body = try m12.encodeServerHello(.{ .random = @splat(2), .cipher_suite = 0x00a8, .extensions = &.{ ems_x, ri_x, extra } }, &body_buf);
    var rec: [600]u8 = undefined;
    _ = try client.handleFlight(hsRecord(2, 0, body, &rec), rnd, 0, &out);
}

/// A PSK server `cfg` answering a ClientHello that carries `extra` (plus EMS).
fn serverSees(cfg: conn13.Config, extra: m12.Extension) ![]const u16 {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(9)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var server = try c12.Connection12.serverInit(cfg);
    var body_buf: [512]u8 = undefined;
    const body = try m12.encodeClientHello(.{ .random = @splat(1), .cipher_suites = &.{0x00a8}, .extensions = &.{ ems_x, extra } }, &body_buf);
    var rec: [700]u8 = undefined;
    var out: [4096]u8 = undefined;
    const r = try server.handleFlight(hsRecord(1, 0, body, &rec), rnd, 0, &out);
    const sh = r.out[record.plaintext_header_len + handshake.header_len ..];
    var ext: [16]m12.Extension = undefined;
    const dec = try m12.decodeServerHello(sh[0 .. std.mem.readInt(u16, r.out[11..13], .big) - handshake.header_len], &ext);
    const S = struct {
        var types: [16]u16 = undefined;
    };
    for (dec.extensions, 0..) |e, i| S.types[i] = e.ext_type;
    return S.types[0..dec.extensions.len];
}

test "mutation 2026-11-26: Connection12 client refuses malformed or unoffered ServerHello extensions" {
    const base = pskCfg(.client);
    // use_srtp: not offered, two profiles, an MKI, a profile we did not offer
    const srtp = struct {
        fn ext(buf: []u8, profiles: []const u16, mki: []const u8) m12.Extension {
            return .{ .ext_type = messages.ext_use_srtp, .data = messages.encodeUseSrtp(profiles, mki, buf) catch unreachable };
        }
    };
    var sb: [32]u8 = undefined;
    try testing.expectError(error.Malformed, clientSees(base, srtp.ext(&sb, &.{1}, "")));
    var with_srtp = base;
    with_srtp.srtp_profiles = &.{ 1, 2 };
    try clientSees(with_srtp, srtp.ext(&sb, &.{2}, ""));
    try testing.expectError(error.Malformed, clientSees(with_srtp, srtp.ext(&sb, &.{ 1, 2 }, "")));
    try testing.expectError(error.Malformed, clientSees(with_srtp, srtp.ext(&sb, &.{1}, "m")));
    try testing.expectError(error.Malformed, clientSees(with_srtp, srtp.ext(&sb, &.{3}, "")));
    // ALPN not offered
    try testing.expectError(error.Malformed, clientSees(base, .{ .ext_type = m12.ext_alpn, .data = &.{ 0, 3, 2, 'h', '2' } }));
    // status_request: not requested, or carrying data
    try testing.expectError(error.Malformed, clientSees(base, .{ .ext_type = messages.ext_status_request, .data = &.{} }));
    var with_ocsp = base;
    with_ocsp.request_ocsp = true;
    try testing.expectError(error.Malformed, clientSees(with_ocsp, .{ .ext_type = messages.ext_status_request, .data = &.{1} }));
    // connection_id: not offered; malformed; 33 bytes; exactly 32 bytes
    const cid_ext = struct {
        fn ext(data: []const u8) m12.Extension {
            return .{ .ext_type = conn13.ext_connection_id, .data = data };
        }
    };
    try testing.expectError(error.Malformed, clientSees(base, cid_ext.ext(&.{ 1, 7 })));
    var with_cid = base;
    with_cid.connection_id = "abcd";
    try testing.expectError(error.Malformed, clientSees(with_cid, cid_ext.ext(&.{})));
    try testing.expectError(error.Malformed, clientSees(with_cid, cid_ext.ext(&.{ 2, 1 })));
    try testing.expectError(error.Malformed, clientSees(with_cid, cid_ext.ext(&.{ 1, 7, 8 })));
    var c33: [34]u8 = @splat(5);
    c33[0] = 33;
    try testing.expectError(error.Malformed, clientSees(with_cid, cid_ext.ext(&c33)));
    var c32: [33]u8 = @splat(5);
    c32[0] = 32;
    try clientSees(with_cid, cid_ext.ext(&c32));
}

test "mutation 2026-11-26: Connection12 server: use_srtp is ignored unconfigured, the CID offer is checked and 32 bytes taken" {
    const base = pskCfg(.server);
    // an unusable use_srtp offer is of no concern to a server without profiles
    _ = try serverSees(base, .{ .ext_type = messages.ext_use_srtp, .data = &.{} });
    var with_cid = base;
    with_cid.connection_id = "abcd";
    const cid_ext = struct {
        fn ext(data: []const u8) m12.Extension {
            return .{ .ext_type = conn13.ext_connection_id, .data = data };
        }
    };
    try testing.expectError(error.Malformed, serverSees(with_cid, cid_ext.ext(&.{})));
    try testing.expectError(error.Malformed, serverSees(with_cid, cid_ext.ext(&.{ 3, 1 })));
    var c32: [33]u8 = @splat(5);
    c32[0] = 32;
    const types = try serverSees(with_cid, cid_ext.ext(&c32));
    try testing.expect(std.mem.indexOfScalar(u16, types, conn13.ext_connection_id) != null);
}

test "mutation 2026-11-26: Connection12 recv on a CID connection: record checks and the post-handshake resend flag" {
    var pair: Pair = undefined;
    try pair.connect(true);
    var buf: [256]u8 = undefined;
    var rec: [300]u8 = undefined;
    const sk = &pair.server.write_keys;
    // a good CID record from the server opens at the client
    const good = try record12.sealCid(sk, 1, 40, 23, "hello", "cidC", &rec);
    try testing.expectEqualStrings("hello", try pair.client.recv(good, &buf));
    // the wrong CID
    const wrong = try record12.sealCid(sk, 1, 41, 23, "hello", "cidX", &rec);
    try testing.expectError(error.Malformed, pair.client.recv(wrong, &buf));
    // the wrong epoch
    const ep2 = try record12.sealCid(sk, 2, 42, 23, "hello", "cidC", &rec);
    try testing.expectError(error.Malformed, pair.client.recv(ep2, &buf));
    // a record cut short of its declared length
    const full = try record12.sealCid(sk, 1, 43, 23, "hello", "cidC", &rec);
    try testing.expectError(error.RecordTooShort, pair.client.recv(full[0 .. full.len - 1], &buf));
    // an alert is exactly two bytes
    const al3 = try record12.sealCid(sk, 1, 44, 21, "abc", "cidC", &rec);
    try testing.expectError(error.Malformed, pair.client.recv(al3, &buf));
    const al2 = try record12.sealCid(sk, 1, 45, 21, &.{ 1, 0 }, "cidC", &rec);
    try testing.expectError(error.ReceivedAlert, pair.client.recv(al2, &buf));
    try testing.expectEqual(@as(?[2]u8, .{ 1, 0 }), pair.client.peer_alert);
    // empty and non-CID datagrams are refused once a CID is negotiated
    if (pair.client.recv(&.{}, &buf)) |_| return error.TestUnexpectedResult else |_| {}
    // the side that sent the last flight schedules a resend when a handshake record arrives late
    const hs = try record12.sealCid(&pair.client.write_keys, 1, 46, 22, "late", "cidS-long", &rec);
    try testing.expect(!pair.server.resend_pending);
    try testing.expectError(error.ReceivedPostHandshakeMessage, pair.server.recv(hs, &buf));
    try testing.expect(pair.server.resend_pending);
}

// ── Connection.zig ───────────────────────────────────────────────────────

test "mutation 2026-11-26: Config.validate accepts 16 SRTP profiles and a 32-byte connection id" {
    var cfg: conn13.Config = .{ .role = .client, .psk_identity = "id", .psk = "k" };
    const profiles: [16]u16 = @splat(1);
    cfg.srtp_profiles = &profiles;
    try cfg.validate();
    const p17: [17]u16 = @splat(1);
    cfg.srtp_profiles = &p17;
    try testing.expectError(error.InvalidSrtpProfiles, cfg.validate());
    cfg.srtp_profiles = &.{};
    const c32: [32]u8 = @splat(1);
    cfg.connection_id = &c32;
    try cfg.validate();
    const c33: [33]u8 = @splat(1);
    cfg.connection_id = &c33;
    try testing.expectError(error.InvalidConnectionId, cfg.validate());
}

fn pair13(cid_c: ?[]const u8, cid_s: ?[]const u8, client: *conn13.Connection, server: *conn13.Connection) !void {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x77)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    client.* = try conn13.Connection.clientInit(.{ .role = .client, .psk_identity = "id", .psk = "k", .connection_id = cid_c });
    server.* = try conn13.Connection.serverInit(.{ .role = .server, .psk_identity = "id", .psk = "k", .connection_id = cid_s });
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &b1);
    const f2 = try server.handleFlight(ch, rnd, 0, &b2);
    const cf = try client.handleFlight(f2.out, rnd, 0, &b1);
    if (!cf.done) return error.TestHandshakeDidNotComplete;
    const sf = try server.handleFlight(cf.out, rnd, 0, &b2);
    if (!sf.done) return error.TestHandshakeDidNotComplete;
}

test "mutation 2026-11-26: connection-id management preconditions of a 1.3 connection" {
    var fresh = try conn13.Connection.clientInit(.{ .role = .client, .psk_identity = "id", .psk = "k", .connection_id = "cidA" });
    try testing.expectError(error.NotConnected, fresh.offerConnectionIds(&.{"cidA"}, .spare));
    try testing.expectError(error.NotConnected, fresh.requestConnectionIds(1));

    var c: conn13.Connection = undefined;
    var s: conn13.Connection = undefined;
    try pair13(null, null, &c, &s);
    try testing.expectError(error.ConnectionIdNotNegotiated, c.offerConnectionIds(&.{"ab"}, .spare));
    try testing.expectError(error.ConnectionIdNotNegotiated, c.requestConnectionIds(1));

    try pair13("cidA", "cidBB", &c, &s);
    try testing.expectError(error.InvalidConnectionId, c.offerConnectionIds(&.{}, .spare));
    try testing.expectError(error.InvalidConnectionId, c.offerConnectionIds(&.{ "cidA", "cidB", "cidC", "cidD", "cidE" }, .spare));
    try testing.expectError(error.InvalidConnectionId, c.requestConnectionIds(0));
    try c.offerConnectionIds(&.{ "cidA", "cidB", "cidC", "cidD" }, .spare);
    try testing.expectError(error.ConnectionIdUpdatePending, c.offerConnectionIds(&.{"cidA"}, .spare));
    try testing.expectError(error.ConnectionIdUpdatePending, c.requestConnectionIds(1));
}

// ── Connection12.zig: handshake message order and Finished checks ────────

/// A PSK client waiting for the server's final flight, and that flight (`f6`, in a global buffer).
var f6_buf: [4096]u8 = undefined;

fn toWaitServerFinished(cl: *c12.Connection12, sv: *c12.Connection12, rnd: conn13.Entropy) ![]const u8 {
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    cl.* = try c12.Connection12.clientInit(pskCfg(.client));
    sv.* = try c12.Connection12.serverInit(pskCfg(.server));
    const ch = try cl.startHandshake(rnd, 0, &a);
    const f4 = try sv.handleFlight(ch, rnd, 0, &b);
    const f5 = try cl.handleFlight(f4.out, rnd, 0, &a);
    const f6 = try sv.handleFlight(f5.out, rnd, 0, &b);
    @memcpy(f6_buf[0..f6.out.len], f6.out);
    return f6_buf[0..f6.out.len];
}

/// The server's ChangeCipherSpec of `f6`, then one epoch-1 handshake message (`t`, `body`) sealed under the
/// server's write keys with the Finished's message sequence number.
fn forgedFinal(f6: []const u8, sv: *const c12.Connection12, t: u8, body: []const u8, out: []u8) ![]const u8 {
    const ccs_len = record.plaintext_header_len + 1;
    var plain: [64]u8 = undefined;
    const h2 = try record.decodePlaintext(f6[ccs_len..]);
    const legit = try record12.open(&sv.write_keys, h2, f6[ccs_len + record.plaintext_header_len ..][0..h2.length], &plain);
    const hh = try handshake.decodeHeader(legit);
    var msg: [64]u8 = undefined;
    handshake.encodeHeader(.{ .msg_type = t, .length = @intCast(body.len), .message_seq = hh.message_seq, .fragment_offset = 0, .fragment_length = @intCast(body.len) }, msg[0..handshake.header_len]);
    @memcpy(msg[handshake.header_len..][0..body.len], body);
    @memcpy(out[0..ccs_len], f6[0..ccs_len]);
    const sealed = try record12.seal(&sv.write_keys, 1, 0, 22, msg[0 .. handshake.header_len + body.len], out[ccs_len..]);
    return out[0 .. ccs_len + sealed.len];
}

test "mutation 2026-11-26: Connection12 client: only a correct Finished ends the handshake" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x55)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl: c12.Connection12 = undefined;
    var sv: c12.Connection12 = undefined;
    var out: [4096]u8 = undefined;
    var dg: [512]u8 = undefined;
    const bad12: [12]u8 = @splat(7);
    const bad5: [5]u8 = @splat(7);
    // the genuine flight completes (control)
    var f6 = try toWaitServerFinished(&cl, &sv, rnd);
    try testing.expect((try cl.handleFlight(f6, rnd, 0, &out)).done);
    // a message that is not Finished
    f6 = try toWaitServerFinished(&cl, &sv, rnd);
    try testing.expectError(error.UnexpectedMessage, cl.handleFlight(try forgedFinal(f6, &sv, 0, "", &dg), rnd, 0, &out));
    // Finished with the wrong verify data, and with the wrong length
    f6 = try toWaitServerFinished(&cl, &sv, rnd);
    try testing.expectError(error.FinishedVerifyFailed, cl.handleFlight(try forgedFinal(f6, &sv, 20, &bad12, &dg), rnd, 0, &out));
    f6 = try toWaitServerFinished(&cl, &sv, rnd);
    try testing.expectError(error.FinishedVerifyFailed, cl.handleFlight(try forgedFinal(f6, &sv, 20, &bad5, &dg), rnd, 0, &out));
}

test "mutation 2026-11-26: Connection12 server: Finished before ClientKeyExchange and an unrequested Certificate are refused" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x56)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var out: [4096]u8 = undefined;
    var rec: [700]u8 = undefined;
    for ([_]u8{ 20, 11 }) |t| {
        var cl = try c12.Connection12.clientInit(pskCfg(.client));
        var sv = try c12.Connection12.serverInit(pskCfg(.server));
        var a: [2048]u8 = undefined;
        var b: [2048]u8 = undefined;
        var to_sv: []const u8 = try cl.startHandshake(rnd, 0, &a);
        while (sv.state != c12.State.wait_client_flight) {
            const r = try sv.handleFlight(to_sv, rnd, 0, &b);
            if (sv.state == c12.State.wait_client_flight) break;
            to_sv = (try cl.handleFlight(r.out, rnd, 0, &a)).out;
        }
        const body = [_]u8{ 0, 0, 0 };
        hs_rseq = 50;
        defer hs_rseq = 0;
        try testing.expectError(error.UnexpectedMessage, sv.handleFlight(hsRecord(t, @intCast(sv.next_recv_seq), &body, &rec), rnd, 0, &out));
    }
}

test "mutation 2026-11-26: Connection12 client: a CertificateStatus nobody announced is refused" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x57)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var client = try c12.Connection12.clientInit(pskCfg(.client));
    var out: [4096]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &out);
    var body_buf: [256]u8 = undefined;
    const body = try m12.encodeServerHello(.{ .random = @splat(2), .cipher_suite = 0x00a8, .extensions = &.{ ems_x, ri_x } }, &body_buf);
    var rec: [400]u8 = undefined;
    _ = try client.handleFlight(hsRecord(2, 0, body, &rec), rnd, 0, &out);
    const status = [_]u8{ 1, 0, 0, 2, 0xAA, 0xBB };
    hs_rseq = 50;
    defer hs_rseq = 0;
    try testing.expectError(error.UnexpectedMessage, client.handleFlight(hsRecord(22, 1, &status, &rec), rnd, 0, &out));
}

// ── Connection12: resumption, tickets, certificate mode, CID during the handshake ─────

const tlsresume = @import("tlsresume");
const certverify = @import("tls13").certverify;
const TestTicketer12 = conn13.StekTicketer(tlsresume.stek.DefaultRing);
const now_s: i64 = 1798761600; // 2027-01-01, after the fixtures' notBefore
const ext_ticket: u16 = tlsresume.ticket12.extension_type;

fn newRing() tlsresume.stek.DefaultRing {
    var ring: tlsresume.stek.DefaultRing = .init();
    ring.rotate(7, &@as([32]u8, @splat(0x24)), now_s);
    return ring;
}

fn pskTicketCfg(role: conn13.Role, tkr: *const TestTicketer12) conn13.Config {
    var c = pskCfg(role);
    c.now_sec = now_s;
    switch (role) {
        .server => c.tickets = .{ .ticketer = tkr.ticketer() },
        .client => c.session_tickets12 = true,
    }
    return c;
}

fn driveFull(cl: *c12.Connection12, sv: *c12.Connection12, rnd: conn13.Entropy) !void {
    var a: [8192]u8 = undefined;
    var b: [8192]u8 = undefined;
    var to_server: []const u8 = try cl.startHandshake(rnd, 0, &a);
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        const sr = try sv.handleFlight(to_server, rnd, 0, &b);
        if (cl.isConnected() and sv.isConnected()) return;
        const cr = try cl.handleFlight(sr.out, rnd, 0, &a);
        if (cl.isConnected() and sv.isConnected()) return;
        to_server = cr.out;
    }
    return error.TestHandshakeDidNotComplete;
}

fn freshTicket(tkr: *const TestTicketer12, seed: u8) !conn13.SessionTicket12 {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(seed)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl = try c12.Connection12.clientInit(pskTicketCfg(.client, tkr));
    var sv = try c12.Connection12.serverInit(pskTicketCfg(.server, tkr));
    try driveFull(&cl, &sv, rnd);
    return (cl.sessionTicket() orelse return error.TestNoTicket).*;
}

/// Like `toWaitServerFinished` for any pair of configs: `cl` waits for the server's final flight (returned).
fn toWaitCfg(cl: *c12.Connection12, sv: *c12.Connection12, rnd: conn13.Entropy, ccfg: conn13.Config, scfg: conn13.Config) ![]const u8 {
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    cl.* = try c12.Connection12.clientInit(ccfg);
    sv.* = try c12.Connection12.serverInit(scfg);
    const ch = try cl.startHandshake(rnd, 0, &a);
    const f4 = try sv.handleFlight(ch, rnd, 0, &b);
    const f5 = try cl.handleFlight(f4.out, rnd, 0, &a);
    const f6 = try sv.handleFlight(f5.out, rnd, 0, &b);
    @memcpy(f6_buf[0..f6.out.len], f6.out);
    return f6_buf[0..f6.out.len];
}

fn findCcs(fl: []const u8) []const u8 {
    var p: usize = 0;
    while (p < fl.len) {
        const h = record.decodePlaintext(fl[p..]) catch unreachable;
        const n = record.plaintext_header_len + h.length;
        if (h.content_type == 20) return fl[p..][0..n];
        p += n;
    }
    unreachable;
}

/// The ChangeCipherSpec of `fl`, then one epoch-1 handshake message (`t`, `body`, message sequence `seq`) sealed under `keys`.
fn forgedAt(fl: []const u8, keys: *const record12.DirKeys, seq: u16, t: u8, body: []const u8, out: []u8) ![]const u8 {
    const ccs = findCcs(fl);
    var msg: [64]u8 = undefined;
    handshake.encodeHeader(.{ .msg_type = t, .length = @intCast(body.len), .message_seq = seq, .fragment_offset = 0, .fragment_length = @intCast(body.len) }, msg[0..handshake.header_len]);
    @memcpy(msg[handshake.header_len..][0..body.len], body);
    @memcpy(out[0..ccs.len], ccs);
    const sealed = try record12.seal(keys, 1, 0, 22, msg[0 .. handshake.header_len + body.len], out[ccs.len..]);
    return out[0 .. ccs.len + sealed.len];
}

test "mutation 2026-11-26: Connection12 server: only a correct client Finished ends an abbreviated handshake" {
    var ring = newRing();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var t = try freshTicket(&tkr, 0x61);
    defer t.wipe();
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x62)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cc = pskTicketCfg(.client, &tkr);
    cc.resumption12 = &t;
    var cl = try c12.Connection12.clientInit(cc);
    var sv = try c12.Connection12.serverInit(pskTicketCfg(.server, &tkr));
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    var dg: [512]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &a);
    const f2 = try sv.handleFlight(ch, rnd, 0, &b);
    try testing.expect(!sv.isConnected());
    const f3 = try cl.handleFlight(f2.out, rnd, 0, &a);
    try testing.expect(f3.done);
    const bad12: [12]u8 = @splat(7);
    const bad5: [5]u8 = @splat(7);
    // an epoch-0 handshake message of another type than Finished (the generic epoch check lets it through to this state)
    var ep0: [100]u8 = undefined;
    hs_rseq = 50;
    defer hs_rseq = 0;
    try testing.expectError(error.UnexpectedMessage, sv.handleFlight(hsRecord(1, @intCast(sv.next_recv_seq), &bad12, &ep0), rnd, 0, &b));
    try testing.expectError(error.UnexpectedMessage, sv.handleFlight(try forgedFinal(f3.out, &cl, 0, "", &dg), rnd, 0, &b));
    try testing.expectError(error.UnexpectedMessage, sv.handleFlight(try forgedFinal(f3.out, &cl, 1, &bad12, &dg), rnd, 0, &b));
    try testing.expectError(error.FinishedVerifyFailed, sv.handleFlight(try forgedFinal(f3.out, &cl, 20, &bad12, &dg), rnd, 0, &b));
    try testing.expectError(error.FinishedVerifyFailed, sv.handleFlight(try forgedFinal(f3.out, &cl, 20, &bad5, &dg), rnd, 0, &b));
    const done = try sv.handleFlight(f3.out, rnd, 0, &b);
    try testing.expect(done.done and sv.resumed());
}

test "mutation 2026-11-26: Connection12 client: a ticket nobody announced, a Finished before an announced ticket, ticket size limits" {
    var ring = newRing();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x63)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var out: [4096]u8 = undefined;
    var rec: [700]u8 = undefined;
    var dg: [512]u8 = undefined;
    var cl: c12.Connection12 = undefined;
    var sv: c12.Connection12 = undefined;
    hs_rseq = 50;
    defer hs_rseq = 0;
    // (a) no ticket was announced: a NewSessionTicket is refused
    _ = try toWaitCfg(&cl, &sv, rnd, pskCfg(.client), pskCfg(.server));
    try testing.expect(!cl.ticket_expected);
    try testing.expectError(error.UnexpectedMessage, cl.handleFlight(hsRecord(4, @intCast(cl.next_recv_seq), "", &rec), rnd, 0, &out));
    // (b) announced, but the Finished comes without it
    const bad12: [12]u8 = @splat(7);
    const f6 = try toWaitCfg(&cl, &sv, rnd, pskTicketCfg(.client, &tkr), pskTicketCfg(.server, &tkr));
    try testing.expect(cl.ticket_expected);
    try testing.expectError(error.UnexpectedMessage, cl.handleFlight(try forgedAt(f6, &sv.write_keys, @intCast(cl.next_recv_seq), 20, &bad12, &dg), rnd, 0, &out));
    // (c) the ticket is kept up to max_ticket_len; an empty one withdraws, a longer one is not kept
    const blob: [513]u8 = @splat(0xab);
    for ([_]usize{ 0, 512, 513 }) |len| {
        _ = try toWaitCfg(&cl, &sv, rnd, pskTicketCfg(.client, &tkr), pskTicketCfg(.server, &tkr));
        var nb: [600]u8 = undefined;
        const nst: tlsresume.ticket12.NewSessionTicket12 = .{ .lifetime_hint_s = 100, .ticket = blob[0..len] };
        const body = try nst.encode(&nb);
        _ = try cl.handleFlight(hsRecord(4, @intCast(cl.next_recv_seq), body, &rec), rnd, 0, &out);
        if (len == 512) {
            const kept = cl.sessionTicket() orelse return error.TestTicketNotKept;
            try testing.expectEqual(@as(u16, 512), kept.ticket_len);
        } else try testing.expect(cl.sessionTicket() == null);
    }
}

fn ticketState(st: *[65]u8, version: u8, suite: u16, ems: u8, issued: i64, lifetime: u32) void {
    @memset(st, 0x33);
    st[0] = version;
    std.mem.writeInt(u16, st[1..3], suite, .big);
    st[3] = ems;
    std.mem.writeInt(i64, st[4..12], issued, .big);
    std.mem.writeInt(u32, st[12..16], lifetime, .big);
}

/// A PSK server is offered a ClientHello carrying a ticket sealed from `state`: does it resume?
fn resumesFrom(tkr: *const TestTicketer12, state: []const u8) !bool {
    var blob_buf: [256]u8 = undefined;
    const tk = tkr.ticketer();
    const blob = tk.seal(tk.ctx, state, @splat(5), &blob_buf) orelse return error.TestSealFailed;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x71)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var sv = try c12.Connection12.serverInit(pskTicketCfg(.server, tkr));
    const t_ext: m12.Extension = .{ .ext_type = ext_ticket, .data = blob };
    const exts = [_]m12.Extension{ ems_x, ri_x, t_ext };
    const sid: [32]u8 = @splat(4);
    var body_buf: [512]u8 = undefined;
    const body = try m12.encodeClientHello(.{ .random = @splat(1), .session_id = &sid, .cipher_suites = &.{0x00a8}, .extensions = &exts }, &body_buf);
    var rec: [700]u8 = undefined;
    var out: [4096]u8 = undefined;
    _ = try sv.handleFlight(hsRecord(1, 0, body, &rec), rnd, 0, &out);
    return sv.abbreviated;
}

test "mutation 2026-11-26: Connection12 server resumes only from a well-formed, fresh ticket of the same EMS use" {
    var ring = newRing();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var st: [65]u8 = undefined;
    const psk_suite: u16 = 0x00a8;
    ticketState(&st, conn13.ticket12_state_version, psk_suite, 1, now_s, 100);
    try testing.expect(try resumesFrom(&tkr, st[0..64])); // control
    try testing.expect(!(try resumesFrom(&tkr, st[0..65]))); // one byte too long, version right
    try testing.expect(!(try resumesFrom(&tkr, st[0..63]))); // one byte short
    ticketState(&st, 3, psk_suite, 1, now_s, 100);
    try testing.expect(!(try resumesFrom(&tkr, st[0..64]))); // wrong version, length right
    ticketState(&st, conn13.ticket12_state_version, psk_suite, 1, now_s - 100, 100);
    try testing.expect(try resumesFrom(&tkr, st[0..64])); // age == lifetime is still valid
    ticketState(&st, conn13.ticket12_state_version, psk_suite, 1, now_s - 101, 100);
    try testing.expect(!(try resumesFrom(&tkr, st[0..64])));
    ticketState(&st, conn13.ticket12_state_version, psk_suite, 0, now_s, 100);
    try testing.expect(!(try resumesFrom(&tkr, st[0..64]))); // the ticket's session had no EMS, this hello does
}

fn resumingClientSees(suite_code: u16, with_ems: bool) !void {
    var ticket: conn13.SessionTicket12 = .{ .suite = .psk_with_aes_128_gcm_sha256, .master = @splat(9), .ems = true, .ticket = @splat(0xab), .ticket_len = 32, .lifetime_hint_s = 3600, .received_at_s = now_s };
    var cfg = pskCfg(.client);
    cfg.cipher_suites12 = &.{ .psk_with_aes_128_gcm_sha256, .ecdhe_psk_with_chacha20_poly1305_sha256 };
    cfg.resumption12 = &ticket;
    cfg.require_extended_master_secret = false;
    cfg.now_sec = now_s;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x72)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var client = try c12.Connection12.clientInit(cfg);
    var out: [4096]u8 = undefined;
    const ch = try client.startHandshake(rnd, 0, &out);
    const sid: [32]u8 = ch[25 + 35 ..][0..32].*;
    const tk_ext: m12.Extension = .{ .ext_type = ext_ticket, .data = &.{} };
    const with = [_]m12.Extension{ ems_x, ri_x, tk_ext };
    const without = [_]m12.Extension{ ri_x, tk_ext };
    var body_buf: [512]u8 = undefined;
    const body = try m12.encodeServerHello(.{ .random = @splat(2), .session_id = &sid, .cipher_suite = suite_code, .extensions = if (with_ems) &with else &without }, &body_buf);
    var rec: [600]u8 = undefined;
    _ = try client.handleFlight(hsRecord(2, 0, body, &rec), rnd, 0, &out);
    try testing.expect(client.abbreviated);
}

test "mutation 2026-11-26: Connection12 client resumes only into its ticket's suite and EMS use" {
    const psk: u16 = 0x00a8;
    const other: u16 = @backingInt(suite12.CipherSuite12.ecdhe_psk_with_chacha20_poly1305_sha256);
    try resumingClientSees(psk, true);
    try testing.expectError(error.Malformed, resumingClientSees(other, true));
    try testing.expectError(error.ExtendedMasterSecretRequired, resumingClientSees(psk, false));
}

fn finalFlightAfterHello(cfg: conn13.Config, suite_code: u16) !void {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x73)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var client = try c12.Connection12.clientInit(cfg);
    var out: [4096]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &out);
    var body_buf: [256]u8 = undefined;
    const body = try m12.encodeServerHello(.{ .random = @splat(2), .cipher_suite = suite_code, .extensions = &.{ ems_x, ri_x } }, &body_buf);
    var rec: [400]u8 = undefined;
    _ = try client.handleFlight(hsRecord(2, 0, body, &rec), rnd, 0, &out);
    hs_rseq = 50;
    defer hs_rseq = 0;
    _ = try client.handleFlight(hsRecord(14, 1, &.{}, &rec), rnd, 0, &out); // ServerHelloDone
}

test "mutation 2026-11-26: Connection12 client: ServerHelloDone before the Certificate / ServerKeyExchange it needs" {
    const ecdsa: conn13.Config = .{
        .role = .client,
        .versions = &v12,
        .key_exchange = .cert_dhe,
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .expected_peer_name = "dtls-test-server",
        .cipher_suites12 = &.{.ecdhe_ecdsa_with_aes_128_gcm_sha256},
        .now_sec = now_s,
    };
    try testing.expectError(error.PeerCertificateRequired, finalFlightAfterHello(ecdsa, 0xc02b));
    var epsk = pskCfg(.client);
    epsk.cipher_suites12 = &.{.ecdhe_psk_with_chacha20_poly1305_sha256};
    const code: u16 = @backingInt(suite12.CipherSuite12.ecdhe_psk_with_chacha20_poly1305_sha256);
    try testing.expectError(error.MissingKeyShare, finalFlightAfterHello(epsk, code));
}

var server_ecdsa_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;

fn serverEcdsa() certverify.SecretKey {
    server_ecdsa_sk = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable;
    return .{ .ecdsa_p256 = &server_ecdsa_sk };
}

fn ecdsaServerCfg() conn13.Config {
    return .{
        .role = .server,
        .versions = &v12,
        .key_exchange = .cert_dhe,
        .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = serverEcdsa() },
        .cipher_suites12 = &.{.ecdhe_ecdsa_with_aes_128_gcm_sha256},
        .now_sec = now_s,
    };
}

fn ecdsaClientCfg() conn13.Config {
    return .{
        .role = .client,
        .versions = &v12,
        .key_exchange = .cert_dhe,
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .expected_peer_name = "dtls-test-server",
        .cipher_suites12 = &.{.ecdhe_ecdsa_with_aes_128_gcm_sha256},
        .now_sec = now_s,
    };
}

test "mutation 2026-11-26: Connection12 server requiring a client certificate refuses an empty Certificate message at once" {
    var scfg = ecdsaServerCfg();
    scfg.request_client_cert = true;
    scfg.require_peer_cert = true;
    scfg.peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der };
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x74)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl = try c12.Connection12.clientInit(ecdsaClientCfg());
    var sv = try c12.Connection12.serverInit(scfg);
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &a);
    _ = try sv.handleFlight(ch, rnd, 0, &b);
    try testing.expectEqual(c12.State.wait_client_flight, sv.state);
    var rec: [100]u8 = undefined;
    hs_rseq = 50;
    defer hs_rseq = 0;
    try testing.expectError(error.PeerCertificateRequired, sv.handleFlight(hsRecord(11, @intCast(sv.next_recv_seq), &.{ 0, 0, 0 }, &rec), rnd, 0, &b));
}

fn serverHelloTypes(out: []const u8) ![]const u16 {
    var ext: [16]m12.Extension = undefined;
    const sh = out[record.plaintext_header_len + handshake.header_len ..];
    const dec = try m12.decodeServerHello(sh[0 .. std.mem.readInt(u16, out[11..13], .big) - handshake.header_len], &ext);
    const S = struct {
        var types: [16]u16 = undefined;
    };
    for (dec.extensions, 0..) |e, i| S.types[i] = e.ext_type;
    return S.types[0..dec.extensions.len];
}

test "mutation 2026-11-26: Connection12 server: an abbreviated ServerHello answers only the extensions an abbreviated handshake uses" {
    var ring = newRing();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x75)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var scfg = ecdsaServerCfg();
    scfg.tickets = .{ .ticketer = tkr.ticketer() };
    var ccfg = ecdsaClientCfg();
    ccfg.session_tickets12 = true;
    var cl = try c12.Connection12.clientInit(ccfg);
    var sv = try c12.Connection12.serverInit(scfg);
    try driveFull(&cl, &sv, rnd);
    const t = (cl.sessionTicket() orelse return error.TestNoTicket).*;

    // the server now has a staple and an SCT list to offer; the hello asks for both but sends no groups
    scfg.cert.?.ocsp_response = "\x30\x03\x0a\x01\x00";
    scfg.cert.?.sct_list = "\x00\x06\x00\x04\x05\x06\x07\x08";
    var sv2 = try c12.Connection12.serverInit(scfg);
    const t_ext: m12.Extension = .{ .ext_type = ext_ticket, .data = t.identity() };
    const exts = [_]m12.Extension{
        ems_x,
        ri_x,
        t_ext,
        .{ .ext_type = messages.ext_status_request, .data = &messages.status_request_ocsp },
        .{ .ext_type = messages.ext_signed_certificate_timestamp, .data = &.{} },
    };
    const sid: [32]u8 = @splat(4);
    var body_buf: [700]u8 = undefined;
    const body = try m12.encodeClientHello(.{ .random = @splat(1), .session_id = &sid, .cipher_suites = &.{0xc02b}, .extensions = &exts }, &body_buf);
    var rec: [900]u8 = undefined;
    var out: [4096]u8 = undefined;
    const r = try sv2.handleFlight(hsRecord(1, 0, body, &rec), rnd, 0, &out);
    try testing.expect(sv2.abbreviated);
    const types = try serverHelloTypes(r.out);
    try testing.expectEqualSlices(u16, &.{ m12.ext_renegotiation_info, m12.ext_extended_master_secret, ext_ticket }, types);
}

test "mutation 2026-11-26: Connection12 client: a message_seq half the space ahead is queued, not taken for a duplicate" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x76)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl = try c12.Connection12.clientInit(pskCfg(.client));
    var out: [4096]u8 = undefined;
    _ = try cl.startHandshake(rnd, 0, &out);
    var rec: [64]u8 = undefined;
    hs_rseq = 50;
    defer hs_rseq = 0;
    const r = try cl.handleFlight(hsRecord(2, 0x8000, "x", &rec), rnd, 0, &out);
    try testing.expectEqual(@as(usize, 0), r.out.len); // a duplicate would have resent the ClientHello
}

const alpn_a: [120]u8 = @splat('a');
const alpn_b: [120]u8 = @splat('b');

fn alpnClientHello(max_dg: u16, out: []u8) ![]const u8 {
    var cfg = pskCfg(.client);
    cfg.alpn_protocols = &.{ &alpn_a, &alpn_b };
    cfg.max_datagram_len = max_dg;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x77)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl = try c12.Connection12.clientInit(cfg);
    return cl.startHandshake(rnd, 0, out);
}

test "mutation 2026-11-26: Connection12 emitFlight: a record of exactly max_datagram_len is sent whole" {
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    const whole = (try alpnClientHello(0, &a)).len;
    try testing.expect(whole > 200);
    try testing.expectEqual(whole, (try alpnClientHello(@intCast(whole), &b)).len);
    try testing.expect((try alpnClientHello(@intCast(whole - 1), &b)).len > whole);
}

test "mutation 2026-11-26: Connection12 handshake with a CID: record form, CID, length and epoch are checked" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x78)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cc = pskCfg(.client);
    cc.connection_id = "\xc1\xc1\xc1\xc1";
    var sc = pskCfg(.server);
    sc.connection_id = "cidS-long";
    var cl: c12.Connection12 = undefined;
    var sv: c12.Connection12 = undefined;
    _ = try toWaitCfg(&cl, &sv, rnd, cc, sc);
    try testing.expect(cl.cid_negotiated);
    var out: [256]u8 = undefined;
    var rec: [100]u8 = undefined;
    // the wrong CID
    var r = cidRecord(&rec, 4, 5, 5);
    r[11] = 0xc2;
    try testing.expectError(error.Malformed, cl.handleFlight(r, rnd, 0, &out));
    // declared length longer than the datagram
    r = cidRecord(&rec, 4, 50, 5);
    try testing.expectError(error.Malformed, cl.handleFlight(r, rnd, 0, &out));
    // a CID record of another epoch than 1
    r = cidRecord(&rec, 4, 5, 5);
    std.mem.writeInt(u16, r[3..5], 2, .big);
    try testing.expectError(error.Malformed, cl.handleFlight(r, rnd, 0, &out));
    // a protected record in the RFC 6347 form once a CID is in force
    _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 1, .sequence_number = 3, .length = 16 }, &rec);
    @memset(rec[13..29], 0xaa);
    try testing.expectError(error.Malformed, cl.handleFlight(rec[0..29], rnd, 0, &out));
    // a CID record on a connection that negotiated none
    var plain = try c12.Connection12.clientInit(pskCfg(.client));
    var a: [4096]u8 = undefined;
    _ = try plain.startHandshake(rnd, 0, &a);
    r = cidRecord(&rec, 0, 5, 5);
    try testing.expectError(error.Malformed, plain.handleFlight(r, rnd, 0, &out));
}

test "mutation 2026-11-26: Connection12 stateless server answers a datagram of two ClientHellos with one HelloVerifyRequest" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x79)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var s = pskCfg(.server);
    s.hello_retry = .{ .cookie_secret = "cookie secret", .peer_binding = "198.51.100.7:5684" };
    var cl = try c12.Connection12.clientInit(pskCfg(.client));
    var sv = try c12.Connection12.serverInit(s);
    var a: [2048]u8 = undefined;
    var b: [2048]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &a);
    const one = try sv.handleFlight(ch, rnd, 0, &b);
    const hvr_len = one.out.len;
    var twice: [1024]u8 = undefined;
    @memcpy(twice[0..ch.len], ch);
    @memcpy(twice[ch.len..][0..ch.len], ch);
    twice[ch.len + 10] = 9; // the second copy under another record number
    const two = try sv.handleFlight(twice[0 .. 2 * ch.len], rnd, 0, &b);
    try testing.expectEqual(hvr_len, two.out.len);
}

// ── DTLS 1.3: forged post-handshake and 0-RTT records, tickets, ServerHello ─────────

const cert_now = cert_kat.valid_now_sec;

fn ring13() tlsresume.stek.DefaultRing {
    var ring: tlsresume.stek.DefaultRing = .init();
    ring.rotate(1, &@as([32]u8, @splat(0x42)), cert_now);
    return ring;
}

fn certServer13() conn13.Config {
    return .{
        .role = .server,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{ .chain = &.{&cert_kat.server_cert_der}, .private_key = serverEcdsa() },
        .now_sec = cert_now,
    };
}

fn certClient13() conn13.Config {
    return .{
        .role = .client,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .now_sec = cert_now,
        .require_peer_cert = true,
    };
}

/// AEAD-seals `inner` (DTLSInnerPlaintext, content type last) as an AES-128-GCM unified-header record with a one-byte
/// sequence number, under `keys` of a DTLS 1.3 connection (the way `Connection.protectRecord` does).
fn sealInner(keys: anytype, epoch: u64, seq: u48, cid: ?[]const u8, inner: []const u8, out: []u8) ![]const u8 {
    const hdr: record.UnifiedHeader = .{ .epoch_low = @truncate(epoch), .seq_len = .short, .seq_wire = @truncate(seq), .cid = cid, .length = @intCast(inner.len + 16) };
    const hs = try record.encodeUnified(hdr, out);
    const A = aead.Protection(aesgcm.Aes128Gcm);
    const n = try A.protect(keys.key[0..16], keys.iv, epoch, seq, inner, out[0..hs.len], out[hs.len..]);
    const seq_off: usize = 1 + if (cid) |c| c.len else 0;
    try aead.encryptSequenceNumberAes(keys.sn_key[0..16], out[hs.len..][0..16], out[seq_off..][0..1]);
    return out[0 .. hs.len + n];
}

/// A post-handshake handshake message (type `hs_type`, the header fields as given) from `from`, sealed under its
/// application keys, carrying the message_seq `to` expects.
fn rawPost(from: *conn13.Connection, to: *const conn13.Connection, hs_type: u8, length: u24, offset: u24, frag: []const u8, out: []u8) ![]const u8 {
    return rawPostSeq(from, to.peer_message_seq orelse from.message_seq, hs_type, length, offset, frag, out);
}

fn rawPostSeq(from: *conn13.Connection, msg_seq: u16, hs_type: u8, length: u24, offset: u24, frag: []const u8, out: []u8) ![]const u8 {
    var inner: [1100]u8 = undefined;
    handshake.encodeHeader(.{ .msg_type = hs_type, .length = length, .message_seq = msg_seq, .fragment_offset = offset, .fragment_length = @intCast(frag.len) }, inner[0..handshake.header_len]);
    @memcpy(inner[handshake.header_len..][0..frag.len], frag);
    const n = handshake.header_len + frag.len;
    inner[n] = 22;
    const rec = try sealInner(&from.write_keys, from.write_epoch, from.send_seq, from.peerConnectionId(), inner[0 .. n + 1], out);
    from.send_seq += 1;
    return rec;
}

test "mutation 2026-11-26: DTLS 1.3 NewConnectionId parsing: fragment fields, size limits, spare ring" {
    var c: conn13.Connection = undefined;
    var s: conn13.Connection = undefined;
    try pair13("cidA", "cidBB", &c, &s);
    var wire: [600]u8 = undefined;
    var plain: [256]u8 = undefined;
    const posted = error.ReceivedPostHandshakeMessage;
    const body = [_]u8{ 0, 5, 4, 'c', 'i', 'd', 'X', 1 }; // usage 1: a spare
    // a fragment of a message that is not whole is refused (offset, or length beyond the fragment)
    try testing.expectError(error.Malformed, c.recv(try rawPost(&s, &c, 10, body.len + 1, 1, &body, &wire), &plain));
    try testing.expectError(error.Malformed, c.recv(try rawPost(&s, &c, 10, body.len + 3, 0, &body, &wire), &plain));
    // bodies too short for their own length fields
    try testing.expectError(error.Malformed, c.recv(try rawPost(&s, &c, 10, 1, 0, &.{0}, &wire), &plain));
    try testing.expectError(error.Malformed, c.recv(try rawPost(&s, &c, 10, 2, 0, &.{ 0, 0 }, &wire), &plain));
    // 17 CIDs are more than the engine takes
    var many: [37]u8 = undefined;
    std.mem.writeInt(u16, many[0..2], 34, .big);
    for (0..17) |i| {
        many[2 + 2 * i] = 1;
        many[3 + 2 * i] = 'z';
    }
    many[36] = 1;
    try testing.expectError(error.Malformed, c.recv(try rawPost(&s, &c, 10, 37, 0, &many, &wire), &plain));
    // the control: the well-formed message is taken
    try testing.expectError(posted, c.recv(try rawPost(&s, &c, 10, body.len, 0, &body, &wire), &plain));
    // a CID of exactly max_cid_len is taken, and switched to at once (RFC 9147 §9: cid_immediate is 0)
    var big: [2 + 1 + 32 + 1]u8 = undefined;
    std.mem.writeInt(u16, big[0..2], 33, .big);
    big[2] = 32;
    @memset(big[3..35], 0x5c);
    big[35] = 0; // usage 0: switch at once
    try testing.expectError(posted, c.recv(try rawPost(&s, &c, 10, big.len, 0, &big, &wire), &plain));
    try testing.expectEqual(@as(usize, 32), c.peerConnectionId().?.len);
    // more spares than the ring holds: the oldest is dropped, nothing overflows
    for (0..conn13.max_cid_spares + 2) |_| {
        try testing.expectError(posted, c.recv(try rawPost(&s, &c, 10, body.len, 0, &body, &wire), &plain));
    }
}

test "mutation 2026-11-26: DTLS 1.3 RequestConnectionId parsing" {
    var c: conn13.Connection = undefined;
    var s: conn13.Connection = undefined;
    try pair13("cidA", "cidBB", &c, &s);
    var wire: [200]u8 = undefined;
    var plain: [64]u8 = undefined;
    // length 2 with a one-byte fragment, and an offset, are refused
    try testing.expectError(error.Malformed, s.recv(try rawPost(&c, &s, 9, 2, 0, &.{1}, &wire), &plain));
    try testing.expectError(error.Malformed, s.recv(try rawPost(&c, &s, 9, 1, 1, &.{1}, &wire), &plain));
    // asking for no CIDs is refused
    try testing.expectError(error.Malformed, s.recv(try rawPost(&c, &s, 9, 1, 0, &.{0}, &wire), &plain));
    try testing.expectError(error.ReceivedPostHandshakeMessage, s.recv(try rawPost(&c, &s, 9, 1, 0, &.{2}, &wire), &plain));
    try testing.expectEqual(@as(u8, 2), s.connectionIdsRequested());
    // without a negotiated CID the message is not legal at all
    var c2: conn13.Connection = undefined;
    var s2: conn13.Connection = undefined;
    try pair13(null, null, &c2, &s2);
    try testing.expectError(error.Malformed, s2.recv(try rawPost(&c2, &s2, 9, 1, 0, &.{1}, &wire), &plain));
}

fn deliverPost(to: *conn13.Connection, bytes: []const u8) !void {
    var rest = bytes;
    var plain: [600]u8 = undefined;
    while (rest.len > 0) {
        const dec = try record.decodeUnified(rest, 0);
        const n = dec.consumed + (dec.hdr.length orelse return error.TestBadRecord);
        if (to.recv(rest[0..n], &plain)) |_| return error.TestUnexpectedData else |e| switch (e) {
            error.ReceivedAck, error.ReceivedPostHandshakeMessage => {},
            else => return e,
        }
        rest = rest[n..];
    }
}

var sf_buf: [2048]u8 = undefined;

/// A full handshake of `ccfg` against `scfg`; the server's final flight (post-handshake records, undelivered).
fn connectPair(cl: *conn13.Connection, sv: *conn13.Connection, ccfg: conn13.Config, scfg: conn13.Config, seed: u8) ![]const u8 {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(seed)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    cl.* = try conn13.Connection.clientInit(ccfg);
    sv.* = try conn13.Connection.serverInit(scfg);
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    const f2 = try sv.handleFlight(ch, rnd, 0, &b2);
    const cf = try cl.handleFlight(f2.out, rnd, 0, &b1);
    if (!cf.done) return error.TestHandshakeDidNotComplete;
    const sf = try sv.handleFlight(cf.out, rnd, 0, &b2);
    if (!sf.done) return error.TestHandshakeDidNotComplete;
    @memcpy(sf_buf[0..sf.out.len], sf.out);
    return sf_buf[0..sf.out.len];
}

fn ticket13(tkr: *const TestTicketer12, seed: u8, lifetime_s: u32, max_early: u32) !conn13.SessionTicket {
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer(), .lifetime_s = lifetime_s, .max_early_data = max_early };
    var cl: conn13.Connection = undefined;
    var sv: conn13.Connection = undefined;
    const sf = try connectPair(&cl, &sv, certClient13(), scfg, seed);
    try deliverPost(&cl, sf);
    return (cl.sessionTicket() orelse return error.TestNoTicket).*;
}

fn clientKeepsForgedTicket(tkr: *const TestTicketer12, lifetime: u32, len: usize) !bool {
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer() };
    var cl: conn13.Connection = undefined;
    var sv: conn13.Connection = undefined;
    _ = try connectPair(&cl, &sv, certClient13(), scfg, 0xc1); // the genuine ticket stays undelivered
    const blob: [513]u8 = @splat(0xab);
    var nb: [800]u8 = undefined;
    const nst: tlsresume.ticket.NewSessionTicket = .{ .ticket_lifetime = lifetime, .ticket_age_add = 1, .ticket_nonce = &.{0}, .ticket = blob[0..len], .extensions = &.{} };
    const body = try nst.encode(&nb);
    var wire: [1000]u8 = undefined;
    var plain: [2048]u8 = undefined;
    try testing.expectError(error.ReceivedPostHandshakeMessage, cl.recv(try rawPost(&sv, &cl, 4, @intCast(body.len), 0, body, &wire), &plain));
    return cl.sessionTicket() != null;
}

test "mutation 2026-11-26: DTLS 1.3 client keeps a NewSessionTicket only with a lifetime and up to max_ticket_len bytes" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    try testing.expect(!(try clientKeepsForgedTicket(&tkr, 0, 16)));
    try testing.expect(try clientKeepsForgedTicket(&tkr, 100, 16));
    try testing.expect(try clientKeepsForgedTicket(&tkr, 100, conn13.max_ticket_len));
    try testing.expect(!(try clientKeepsForgedTicket(&tkr, 100, conn13.max_ticket_len + 1)));
    try testing.expect(!(try clientKeepsForgedTicket(&tkr, 0, conn13.max_ticket_len + 1)));
}

test "mutation 2026-11-26: DTLS 1.3 server issues no ticket without a lifetime, nor after a PSK handshake" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer(), .lifetime_s = 0 };
    var cl: conn13.Connection = undefined;
    var sv: conn13.Connection = undefined;
    _ = try connectPair(&cl, &sv, certClient13(), scfg, 0xc2);
    try testing.expect(!sv.connectionIdUpdatePending());
    scfg.tickets.?.lifetime_s = 3600;
    _ = try connectPair(&cl, &sv, certClient13(), scfg, 0xc3);
    try testing.expect(sv.connectionIdUpdatePending()); // control: a ticket is queued
    // a PSK handshake leaves no resumption master secret to issue one from
    const psk_s: conn13.Config = .{ .role = .server, .psk_identity = "id", .psk = "k", .tickets = .{ .ticketer = tkr.ticketer() } };
    _ = try connectPair(&cl, &sv, .{ .role = .client, .psk_identity = "id", .psk = "k" }, psk_s, 0xc4);
    try testing.expect(!sv.connectionIdUpdatePending());
}

test "mutation 2026-11-26: DTLS 1.3 server resumes a ticket at exactly its lifetime, not a second later" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var t = try ticket13(&tkr, 0xb0, 60, 0);
    defer t.wipe();
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer(), .lifetime_s = 60 };
    var ccfg = certClient13();
    ccfg.resumption = &t;
    var cl: conn13.Connection = undefined;
    var sv: conn13.Connection = undefined;
    scfg.now_sec = cert_now + 60;
    _ = try connectPair(&cl, &sv, ccfg, scfg, 0xb1);
    try testing.expect(sv.resumed());
    scfg.now_sec = cert_now + 61;
    _ = try connectPair(&cl, &sv, ccfg, scfg, 0xb2);
    try testing.expect(!sv.resumed());
}

/// Does a server whose clock is `skew_s` seconds past the ticket's issue take 0-RTT from a client resuming at its issue time?
fn earlyAccepted(tkr: *const TestTicketer12, t: *const conn13.SessionTicket, skew_s: i64, offer: bool, seed: u8) !bool {
    var reg = tlsresume.replay.StrikeRegister.init(testing.allocator, 16, 121_000);
    defer reg.deinit();
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer(), .max_early_data = 1000, .replay = conn13.strikeRegisterGuard(&reg) };
    scfg.now_sec = cert_now + skew_s;
    var ccfg = certClient13();
    ccfg.resumption = t;
    if (offer) ccfg.early_data = "0-RTT hello";
    var cl: conn13.Connection = undefined;
    var sv: conn13.Connection = undefined;
    _ = try connectPair(&cl, &sv, ccfg, scfg, seed);
    try testing.expect(sv.resumed());
    try testing.expectEqual(cl.earlyDataAccepted(), sv.earlyDataAccepted());
    return sv.earlyDataAccepted();
}

test "mutation 2026-11-26: DTLS 1.3 0-RTT: the age skew bound is inclusive, and early data nobody offered is not taken" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var t = try ticket13(&tkr, 0xb3, 12 * 3600, 1000);
    defer t.wipe();
    try testing.expect(try earlyAccepted(&tkr, &t, 0, true, 0xb4));
    try testing.expect(try earlyAccepted(&tkr, &t, 60, true, 0xb5)); // exactly max_age_skew_s
    try testing.expect(!(try earlyAccepted(&tkr, &t, 61, true, 0xb6)));
    try testing.expect(!(try earlyAccepted(&tkr, &t, 0, false, 0xb7))); // the client offered none
}

fn startOut(t: *const conn13.SessionTicket, early: []const u8, buf: []u8) ![]const u8 {
    var ccfg = certClient13();
    ccfg.resumption = t;
    ccfg.early_data = early;
    var cl = try conn13.Connection.clientInit(ccfg);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xd0)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    return cl.startHandshake(rnd, 0, buf);
}

test "mutation 2026-11-26: DTLS 1.3 client 0-RTT records use the short sequence number and fit an exactly-sized buffer" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var t = try ticket13(&tkr, 0xd1, 12 * 3600, 1000);
    defer t.wipe();
    var a: [4096]u8 = undefined;
    const first = try startOut(&t, "0123456789", &a);
    const full = first.len;
    const ch_len = record.plaintext_header_len + (try record.decodePlaintext(first)).length;
    try testing.expect(full > ch_len);
    try testing.expect((try record.decodeUnified(first[ch_len..], 0)).hdr.seq_len == .short);
    var b: [4096]u8 = undefined;
    try testing.expectEqual(full, (try startOut(&t, "0123456789", b[0..full])).len);
    try testing.expectError(error.BufferTooShort, startOut(&t, "0123456789", b[0 .. full - 1]));
}

const EarlySpec = struct {
    seq: u48 = 0,
    /// DTLSInnerPlaintext of the forged epoch-1 record (content type last); ignored when `raw` is set
    inner: []const u8 = &.{},
    /// bytes appended as they are
    raw: ?[]const u8 = null,
    twice: bool = false,
};

/// A server taking `limit` bytes of 0-RTT is given the client's ClientHello followed, in one datagram, by forged records.
/// Returns how many bytes of early data it kept (copied to `kept`), or the handshake error.
fn earlyFeed(tkr: *const TestTicketer12, limit: u32, specs: []const EarlySpec, kept: *[4096]u8) !usize {
    return earlyFeedCid(tkr, limit, specs, kept, false);
}

fn earlyFeedCid(tkr: *const TestTicketer12, limit: u32, specs: []const EarlySpec, kept: *[4096]u8, cid: bool) !usize {
    var t = try ticket13(tkr, 0xe0, 12 * 3600, limit);
    defer t.wipe();
    var reg = tlsresume.replay.StrikeRegister.init(testing.allocator, 16, 121_000);
    defer reg.deinit();
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer(), .max_early_data = limit, .replay = conn13.strikeRegisterGuard(&reg) };
    var ccfg = certClient13();
    ccfg.resumption = &t;
    ccfg.early_data = "x";
    if (cid) {
        ccfg.connection_id = "cidC";
        scfg.connection_id = "cidS";
    }
    var cl = try conn13.Connection.clientInit(ccfg);
    var sv = try conn13.Connection.serverInit(scfg);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xe1)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const first = try cl.startHandshake(rnd, 0, &b1);
    const ch_len = record.plaintext_header_len + (try record.decodePlaintext(first)).length;
    var dg: [8192]u8 = undefined;
    @memcpy(dg[0..ch_len], first[0..ch_len]);
    var n: usize = ch_len;
    for (specs) |sp| {
        const piece = if (sp.raw) |r| blk: {
            @memcpy(dg[n..][0..r.len], r);
            break :blk dg[n..][0..r.len];
        } else try sealInner(&cl.early_keys, 1, sp.seq, null, sp.inner, dg[n..]);
        n += piece.len;
        if (sp.twice) {
            @memcpy(dg[n..][0..piece.len], dg[n - piece.len ..][0..piece.len]);
            n += piece.len;
        }
    }
    const f2 = try sv.handleFlight(dg[0..n], rnd, 0, &b2);
    const cf = try cl.handleFlight(f2.out, rnd, 0, &b1);
    _ = try sv.handleFlight(cf.out, rnd, 0, &b2);
    try testing.expect(sv.earlyDataAccepted());
    const d = sv.earlyData();
    @memcpy(kept[0..d.len], d);
    return d.len;
}

fn plaintextRecord(out: []u8, content_type: u8, seq: u48, body_len: usize) []const u8 {
    _ = record.encodePlaintext(.{ .content_type = content_type, .epoch = 0, .sequence_number = seq, .length = @intCast(body_len) }, out) catch unreachable;
    @memset(out[record.plaintext_header_len..][0..body_len], 0xee);
    return out[0 .. record.plaintext_header_len + body_len];
}

test "mutation 2026-11-26: DTLS 1.3 server 0-RTT intake: sequence reconstruction, replays, padding, content type, limit" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var kept: [4096]u8 = undefined;
    const app: u8 = 23;
    // two records whose sequence numbers (120, then 240) are only reconstructed correctly against the largest seen so far
    const r1 = [_]u8{ 'A', 'A', 'A', app };
    const r2 = [_]u8{ 'B', 'B', 'B', app };
    var n = try earlyFeed(&tkr, 1000, &.{ .{ .seq = 120, .inner = &r1 }, .{ .seq = 240, .inner = &r2 } }, &kept);
    try testing.expectEqualStrings("AAABBB", kept[0..n]);
    // a record delivered twice is kept once
    n = try earlyFeed(&tkr, 1000, &.{.{ .seq = 7, .inner = &r1, .twice = true }}, &kept);
    try testing.expectEqualStrings("AAA", kept[0..n]);
    // an authentic record with nothing but padding / with no payload at all is malformed
    try testing.expectError(error.Malformed, earlyFeed(&tkr, 1000, &.{.{ .seq = 1, .inner = &.{ 0, 0, 0 } }}, &kept));
    try testing.expectError(error.Malformed, earlyFeed(&tkr, 1000, &.{.{ .seq = 1, .inner = &.{} }}, &kept));
    // only application data travels as early data
    try testing.expectError(error.UnexpectedMessage, earlyFeed(&tkr, 1000, &.{.{ .seq = 1, .inner = &.{ 'x', 22 } }}, &kept));
    // a record whose ciphertext is shorter than a tag is dropped, never read past
    var short_rec: [20]u8 = undefined;
    const hdr_len = (try record.encodeUnified(.{ .epoch_low = 1, .seq_len = .short, .seq_wire = 3, .cid = null, .length = 10 }, &short_rec)).len;
    @memset(short_rec[hdr_len..][0..10], 0x77);
    n = try earlyFeed(&tkr, 1000, &.{.{ .raw = short_rec[0 .. hdr_len + 10] }}, &kept);
    try testing.expectEqual(@as(usize, 0), n);
    // the early-data limit: exactly the limit is taken, one byte more is refused
    var big: [1002]u8 = @splat(0x61);
    big[1001] = app;
    n = try earlyFeed(&tkr, 1000, &.{.{ .seq = 1, .inner = big[1..] }}, &kept);
    try testing.expectEqual(@as(usize, 1000), n);
    try testing.expectError(error.UnexpectedMessage, earlyFeed(&tkr, 1000, &.{.{ .seq = 1, .inner = big[0..] }}, &kept));
    // other (plaintext) records behind the ClientHello: a truncated one is malformed, one that fills the datagram is not
    var junk: [8192]u8 = undefined;
    const exact = plaintextRecord(&junk, 21, 77, 5);
    n = try earlyFeed(&tkr, 1000, &.{.{ .raw = exact }}, &kept);
    try testing.expectEqual(@as(usize, 0), n);
    var cut: [64]u8 = undefined;
    const trunc = plaintextRecord(&cut, 21, 78, 5);
    try testing.expectError(error.Malformed, earlyFeed(&tkr, 1000, &.{.{ .raw = trunc[0 .. trunc.len - 1] }}, &kept));
}

test "mutation 2026-11-26: DTLS 1.3 resumed server: other records filling the whole datagram fit the scratch buffer" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var t = try ticket13(&tkr, 0xe2, 12 * 3600, 1000);
    defer t.wipe();
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer() };
    var ccfg = certClient13();
    ccfg.resumption = &t;
    var cl = try conn13.Connection.clientInit(ccfg);
    var sv = try conn13.Connection.serverInit(scfg);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xe3)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    _ = try sv.handleFlight(ch, rnd, 0, &b2);
    try testing.expect(sv.resumed());
    // a datagram of epoch-1 (0-RTT) records only leaves nothing for the handshake: the flight is incomplete
    var short_rec: [20]u8 = undefined;
    const hdr_len = (try record.encodeUnified(.{ .epoch_low = 1, .seq_len = .short, .seq_wire = 3, .cid = null, .length = 10 }, &short_rec)).len;
    @memset(short_rec[hdr_len..][0..10], 0x77);
    const none = try sv.handleFlight(short_rec[0 .. hdr_len + 10], rnd, 0, &b2);
    try testing.expect(none.need_more_data and none.out.len == 0);
    // a datagram of plaintext records that takes all the room the receiver has: they fit the scratch buffer exactly
    const room = sv.rx_flight.len - sv.rx_flight_len;
    var junk: [6000]u8 = undefined;
    const rec = plaintextRecord(&junk, 21, 77, room - record.plaintext_header_len);
    try notError(sv.handleFlight(rec, rnd, 0, &b2), error.FlightTooLarge);
}

fn clientSeesPskExt(ext_data: []const u8, ticket_suite: conn13.CipherSuite) !void {
    var t: conn13.SessionTicket = .{ .suite = ticket_suite, .psk = @splat(0x11), .ticket = @splat(0xab), .ticket_len = 32, .ticket_age_add = 7, .lifetime_s = 3600, .received_at_s = cert_now, .max_early_data = 0 };
    var ccfg = certClient13();
    ccfg.cipher_suites = &.{ .aes_128_gcm_sha256, .aes_256_gcm_sha384 };
    ccfg.resumption = &t;
    var cl = try conn13.Connection.clientInit(ccfg);
    var sv = try conn13.Connection.serverInit(certServer13());
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xf0)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    const f2 = try sv.handleFlight(ch, rnd, 0, &b2); // a full handshake: the server cannot open the ticket
    const h = try record.decodePlaintext(f2.out);
    const hh = try handshake.decodeHeader(f2.out[record.plaintext_header_len..]);
    var exts: [8]messages.Extension = undefined;
    const sh = try messages.decodeServerHello(f2.out[record.plaintext_header_len + handshake.header_len ..][0 .. h.length - handshake.header_len], &exts);
    var exts2: [9]messages.Extension = undefined;
    @memcpy(exts2[0..sh.extensions.len], sh.extensions);
    exts2[sh.extensions.len] = .{ .ext_type = @backingInt(messages.ExtensionType.pre_shared_key), .data = ext_data };
    var nb: [512]u8 = undefined;
    const nbody = try messages.encodeServerHello(.{ .random = sh.random, .legacy_session_id_echo = sh.legacy_session_id_echo, .cipher_suite = sh.cipher_suite, .extensions = exts2[0 .. sh.extensions.len + 1] }, &nb);
    var dg: [700]u8 = undefined;
    _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = h.sequence_number, .length = @intCast(handshake.header_len + nbody.len) }, &dg);
    handshake.encodeHeader(.{ .msg_type = hh.msg_type, .length = @intCast(nbody.len), .message_seq = hh.message_seq, .fragment_offset = 0, .fragment_length = @intCast(nbody.len) }, dg[record.plaintext_header_len..][0..handshake.header_len]);
    @memcpy(dg[record.plaintext_header_len + handshake.header_len ..][0..nbody.len], nbody);
    _ = try cl.handleFlight(dg[0 .. record.plaintext_header_len + handshake.header_len + nbody.len], rnd, 0, &b1);
}

test "mutation 2026-11-26: DTLS 1.3 client checks a ServerHello pre_shared_key: size, identity, hash" {
    try testing.expectError(error.Malformed, clientSeesPskExt(&.{0}, .aes_128_gcm_sha256));
    try testing.expectError(error.Malformed, clientSeesPskExt(&.{ 0, 0, 0 }, .aes_128_gcm_sha256));
    try testing.expectError(error.NoMatchingPskIdentity, clientSeesPskExt(&.{ 0, 1 }, .aes_128_gcm_sha256));
    try testing.expectError(error.NoCipherSuiteOverlap, clientSeesPskExt(&.{ 0, 0 }, .aes_256_gcm_sha384));
}

test "mutation 2026-11-26: DTLS 1.3 stateless server: refuse_fragmented_client_hello looks only at whole-ClientHello candidates" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xf1)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    const cfg: conn13.Config = .{ .role = .server, .psk_identity = "id", .psk = "k", .hello_retry = .{ .cookie_secret = "cookie secret", .peer_binding = "198.51.100.7:4433", .refuse_fragmented_client_hello = true } };
    var out: [2048]u8 = undefined;
    var dg: [100]u8 = undefined;
    const hdr = struct {
        fn frag(buf: []u8, content_type: u8, msg_type: u8, offset: u24, total: u24, frag_len: u24) []const u8 {
            const body = 12 + frag_len;
            _ = record.encodePlaintext(.{ .content_type = content_type, .epoch = 0, .sequence_number = 5, .length = @intCast(body) }, buf) catch unreachable;
            handshake.encodeHeader(.{ .msg_type = msg_type, .length = total, .message_seq = 0, .fragment_offset = offset, .fragment_length = frag_len }, buf[13..25]);
            @memset(buf[25..][0..frag_len], 0x42);
            return buf[0 .. 13 + body];
        }
    };
    const ch_type = @backingInt(messages.HandshakeType.client_hello);
    // the control: a fragmented ClientHello is refused as such
    var sv = try conn13.Connection.serverInit(cfg);
    try testing.expectError(error.FragmentedClientHello, sv.handleFlight(hdr.frag(&dg, 22, ch_type, 5, 100, 10), rnd, 0, &out));
    // the same fragment under another handshake type, or inside another record type, is none of its business
    sv = try conn13.Connection.serverInit(cfg);
    if (sv.handleFlight(hdr.frag(&dg, 22, 20, 5, 100, 10), rnd, 0, &out)) |_| {} else |e| try testing.expect(e != error.FragmentedClientHello);
    sv = try conn13.Connection.serverInit(cfg);
    if (sv.handleFlight(hdr.frag(&dg, 21, ch_type, 5, 100, 10), rnd, 0, &out)) |_| {} else |e| try testing.expect(e != error.FragmentedClientHello);
    // a record declaring more bytes than the datagram holds is left to the normal parse
    sv = try conn13.Connection.serverInit(cfg);
    const r = hdr.frag(&dg, 22, ch_type, 5, 100, 10);
    if (sv.handleFlight(r[0 .. r.len - 4], rnd, 0, &out)) |_| {} else |e| try testing.expect(e != error.FragmentedClientHello);
}

test "mutation 2026-11-26: DTLS 1.3 server flight with a message larger than one record (no max_datagram_len) is fragmented, not refused" {
    var scfg = certServer13();
    var staple: [1800]u8 = undefined;
    staple[0] = 0x30;
    staple[1] = 0x82;
    std.mem.writeInt(u16, staple[2..4], 1796, .big);
    @memset(staple[4..], 0x5a);
    scfg.cert.?.ocsp_response = &staple;
    var ccfg = certClient13();
    ccfg.request_ocsp = true;
    var cl = try conn13.Connection.clientInit(ccfg);
    var sv = try conn13.Connection.serverInit(scfg);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xf2)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [8192]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    const f2 = try sv.handleFlight(ch, rnd, 0, &b2);
    try testing.expect(f2.out.len > 1800);
}

test "mutation 2026-11-26: DTLS 1.3 connection-id message retransmissions beyond the record ring still complete on an ACK; a record number of another sequence does not" {
    var c: conn13.Connection = undefined;
    var s: conn13.Connection = undefined;
    try pair13("cidA", "cidBB", &c, &s);
    var w: [512]u8 = undefined;
    var p: [512]u8 = undefined;
    try c.offerConnectionIds(&.{"cidX"}, .spare);
    const sent_seq = c.send_seq;
    const sent_epoch = c.write_epoch;
    // an ACK naming the same epoch under another sequence number is not an ACK of the message
    var ack_body: [64]u8 = undefined;
    const forged_body = try flight.encodeAck(&.{.{ .epoch = sent_epoch, .sequence_number = sent_seq + 7 }}, &ack_body);
    var inner: [64]u8 = undefined;
    @memcpy(inner[0..forged_body.len], forged_body);
    inner[forged_body.len] = 26;
    const first = (try c.poll(1_000_000, &w)).?;
    try testing.expectError(error.ReceivedPostHandshakeMessage, s.recv(first, &p));
    var wire: [200]u8 = undefined;
    const forged = try sealInner(&s.write_keys, s.write_epoch, s.send_seq, s.peerConnectionId(), inner[0 .. forged_body.len + 1], &wire);
    s.send_seq += 1;
    try testing.expectError(error.ReceivedAck, c.recv(forged, &p));
    try testing.expect(c.connectionIdUpdatePending());
    // more retransmissions than the ring of sent record numbers holds
    var t: u64 = 1_000_000;
    for (0..10) |_| {
        t += 1_000_000;
        const again = (try c.poll(t, &w)).?;
        try testing.expectError(error.ReceivedPostHandshakeMessage, s.recv(again, &p));
    }
    const ack = (try s.poll(t, &w)).?;
    try testing.expectError(error.ReceivedAck, c.recv(ack, &p));
    try testing.expect(!c.connectionIdUpdatePending());
}

// ── round 3: DTLS 1.2 staple / certificate-request order, DTLS 1.3 server flights, resumption suite ─────

fn ecdsaStapleHandshake(len: usize) !void {
    var blob: [2200]u8 = @splat(0x5a);
    blob[0] = 0x30;
    var scfg = ecdsaServerCfg();
    scfg.cert.?.ocsp_response = blob[0..len];
    var ccfg = ecdsaClientCfg();
    ccfg.request_ocsp = true;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x7a)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl = try c12.Connection12.clientInit(ccfg);
    var sv = try c12.Connection12.serverInit(scfg);
    try driveFull(&cl, &sv, rnd);
    try testing.expectEqual(len, cl.peerOcspResponse().?.len);
}

test "mutation 2026-11-26: Connection12 client keeps a stapled OCSP response of exactly max_staple_len and refuses one byte more" {
    try ecdsaStapleHandshake(conn13.max_staple_len);
    try testing.expectError(error.Malformed, ecdsaStapleHandshake(conn13.max_staple_len + 1));
}

fn clientSeesStatusFirst() !void {
    var cfg = ecdsaClientCfg();
    cfg.request_ocsp = true;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x7b)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var client = try c12.Connection12.clientInit(cfg);
    var out: [4096]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &out);
    var body_buf: [256]u8 = undefined;
    const sh = try m12.encodeServerHello(.{ .random = @splat(2), .cipher_suite = 0xc02b, .extensions = &.{ ems_x, ri_x, .{ .ext_type = messages.ext_status_request, .data = &.{} } } }, &body_buf);
    var rec: [400]u8 = undefined;
    _ = try client.handleFlight(hsRecord(2, 0, sh, &rec), rnd, 0, &out);
    try testing.expect(client.ocsp_expected);
    hs_rseq = 50;
    defer hs_rseq = 0;
    const status = [_]u8{ 1, 0, 0, 2, 0xAA, 0xBB };
    _ = try client.handleFlight(hsRecord(22, 1, &status, &rec), rnd, 0, &out); // before any Certificate
}

test "mutation 2026-11-26: Connection12 client: an announced CertificateStatus before the Certificate is out of order" {
    try testing.expectError(error.UnexpectedMessage, clientSeesStatusFirst());
}

test "mutation 2026-11-26: Connection12 server that asked for a client certificate refuses a ClientKeyExchange before it" {
    var scfg = ecdsaServerCfg();
    scfg.request_client_cert = true;
    scfg.peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der };
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x7c)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl = try c12.Connection12.clientInit(ecdsaClientCfg());
    var sv = try c12.Connection12.serverInit(scfg);
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &a);
    _ = try sv.handleFlight(ch, rnd, 0, &b);
    try testing.expect(sv.cert_requested);
    var rec: [100]u8 = undefined;
    hs_rseq = 50;
    defer hs_rseq = 0;
    try testing.expectError(error.UnexpectedMessage, sv.handleFlight(hsRecord(16, @intCast(sv.next_recv_seq), &.{ 0, 0, 0 }, &rec), rnd, 0, &b));
}

const Fm = struct { t: u8, body: []const u8 };

/// The client `ccfg` receives the genuine ServerHello and EncryptedExtensions of a certificate-mode server, followed by
/// `msgs` forged under that server's handshake keys.
fn clientSeesFlight(ccfg: conn13.Config, msgs: []const Fm) !void {
    var cl = try conn13.Connection.clientInit(ccfg);
    var sv = try conn13.Connection.serverInit(certServer13());
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xf3)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    const f2 = try sv.handleFlight(ch, rnd, 0, &b2);
    const h0 = try record.decodePlaintext(f2.out);
    const n0 = record.plaintext_header_len + h0.length;
    const d1 = try record.decodeUnified(f2.out[n0..], 0);
    const n1 = d1.consumed + (d1.hdr.length orelse return error.TestBadRecord);
    var dg: [16384]u8 = undefined;
    @memcpy(dg[0 .. n0 + n1], f2.out[0 .. n0 + n1]);
    var n: usize = n0 + n1;
    for (msgs, 0..) |m, i| {
        var inner: [8192]u8 = undefined;
        handshake.encodeHeader(.{ .msg_type = m.t, .length = @intCast(m.body.len), .message_seq = @intCast(2 + i), .fragment_offset = 0, .fragment_length = @intCast(m.body.len) }, inner[0..handshake.header_len]);
        @memcpy(inner[handshake.header_len..][0..m.body.len], m.body);
        inner[handshake.header_len + m.body.len] = 22;
        const r = try sealInner(&sv.hs_write_keys, 2, @intCast(1 + i), null, inner[0 .. handshake.header_len + m.body.len + 1], dg[n..]);
        n += r.len;
    }
    _ = try cl.handleFlight(dg[0..n], rnd, 0, &b1);
}

const hs_certificate: u8 = 11;
const hs_finished: u8 = 20;

fn stapledBody(buf: []u8, leaf: messages.LeafStatus) []const u8 {
    const certs = [_][]const u8{"cert"};
    return messages.encodeCertificateStapled("", &certs, leaf, buf) catch unreachable;
}

fn notError(r: anytype, not: anyerror) !void {
    if (r) |_| {} else |e| try testing.expect(e != not);
}

test "mutation 2026-11-26: DTLS 1.3 client: Certificate extensions are taken only when asked for, up to max_staple_len" {
    var buf: [4200]u8 = undefined;
    var blob: [2049]u8 = undefined;
    @memset(&blob, 0x5a);
    // an OCSP response / SCT list nobody asked for
    try testing.expectError(error.Malformed, clientSeesFlight(certClient13(), &.{.{ .t = hs_certificate, .body = stapledBody(&buf, .{ .ocsp_response = "ocsp" }) }}));
    try testing.expectError(error.Malformed, clientSeesFlight(certClient13(), &.{.{ .t = hs_certificate, .body = stapledBody(&buf, .{ .sct_list = "\x00\x04abcd" }) }}));
    var asked = certClient13();
    asked.request_ocsp = true;
    asked.request_scts = true;
    // asked for: exactly max_staple_len is taken (the flight then lacks its end), one byte more is refused
    std.mem.writeInt(u16, blob[0..2], 2046, .big);
    try notError(clientSeesFlight(asked, &.{.{ .t = hs_certificate, .body = stapledBody(&buf, .{ .ocsp_response = blob[0..2048] }) }}), error.Malformed);
    try notError(clientSeesFlight(asked, &.{.{ .t = hs_certificate, .body = stapledBody(&buf, .{ .sct_list = blob[0..2048] }) }}), error.Malformed);
    std.mem.writeInt(u16, blob[0..2], 2047, .big);
    try testing.expectError(error.Malformed, clientSeesFlight(asked, &.{.{ .t = hs_certificate, .body = stapledBody(&buf, .{ .ocsp_response = blob[0..2049] }) }}));
    try testing.expectError(error.Malformed, clientSeesFlight(asked, &.{.{ .t = hs_certificate, .body = stapledBody(&buf, .{ .sct_list = blob[0..2049] }) }}));
}

test "mutation 2026-11-26: DTLS 1.3 client: an empty Certificate is not run through chain verification; a Certificate without CertificateVerify is malformed" {
    var chain_cfg = certClient13();
    chain_cfg.peer_verify = .{ .chain = .{ .trust_anchors = &.{&cert_kat.anchor_cert_der} } };
    try notError(clientSeesFlight(chain_cfg, &.{.{ .t = hs_certificate, .body = &.{ 0, 0, 0, 0 } }}), error.CertificateRejected);
    var buf: [200]u8 = undefined;
    const fin: [32]u8 = @splat(9);
    try testing.expectError(error.Malformed, clientSeesFlight(certClient13(), &.{ .{ .t = hs_certificate, .body = stapledBody(&buf, .{}) }, .{ .t = hs_finished, .body = &fin } }));
}

test "mutation 2026-11-26: DTLS 1.3 resumption keeps the ticket's hash when choosing the suite" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var scfg = certServer13();
    scfg.cipher_suites = &.{ .aes_256_gcm_sha384, .aes_128_gcm_sha256 };
    scfg.tickets = .{ .ticketer = tkr.ticketer() };
    var ccfg = certClient13();
    ccfg.cipher_suites = &.{ .aes_128_gcm_sha256, .aes_256_gcm_sha384 };
    var cl: conn13.Connection = undefined;
    var sv: conn13.Connection = undefined;
    const sf = try connectPair(&cl, &sv, ccfg, scfg, 0xf4);
    try testing.expectEqual(conn13.CipherSuite.aes_256_gcm_sha384, sv.suite);
    try deliverPost(&cl, sf);
    var t = (cl.sessionTicket() orelse return error.TestNoTicket).*;
    defer t.wipe();
    // the server now prefers the other hash, but the ticket's PSK belongs to SHA-384
    scfg.cipher_suites = &.{ .aes_128_gcm_sha256, .aes_256_gcm_sha384 };
    ccfg.resumption = &t;
    _ = try connectPair(&cl, &sv, ccfg, scfg, 0xf5);
    try testing.expect(sv.resumed());
    try testing.expectEqual(conn13.CipherSuite.aes_256_gcm_sha384, sv.suite);
}

// ── round 4: ServerHello / ClientHello extension forging, message_seq wrap ─────

fn clientSeesShExt(ccfg: conn13.Config, ext_type: u16, ext_data: []const u8) !void {
    var cl = try conn13.Connection.clientInit(ccfg);
    var sv = try conn13.Connection.serverInit(certServer13());
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xf7)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    const f2 = try sv.handleFlight(ch, rnd, 0, &b2);
    const h = try record.decodePlaintext(f2.out);
    const hh = try handshake.decodeHeader(f2.out[record.plaintext_header_len..]);
    var exts: [8]messages.Extension = undefined;
    const sh = try messages.decodeServerHello(f2.out[record.plaintext_header_len + handshake.header_len ..][0 .. h.length - handshake.header_len], &exts);
    var exts2: [9]messages.Extension = undefined;
    @memcpy(exts2[0..sh.extensions.len], sh.extensions);
    exts2[sh.extensions.len] = .{ .ext_type = ext_type, .data = ext_data };
    var nb: [512]u8 = undefined;
    const nbody = try messages.encodeServerHello(.{ .random = sh.random, .legacy_session_id_echo = sh.legacy_session_id_echo, .cipher_suite = sh.cipher_suite, .extensions = exts2[0 .. sh.extensions.len + 1] }, &nb);
    var dg: [700]u8 = undefined;
    _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = h.sequence_number, .length = @intCast(handshake.header_len + nbody.len) }, &dg);
    handshake.encodeHeader(.{ .msg_type = hh.msg_type, .length = @intCast(nbody.len), .message_seq = hh.message_seq, .fragment_offset = 0, .fragment_length = @intCast(nbody.len) }, dg[record.plaintext_header_len..][0..handshake.header_len]);
    @memcpy(dg[record.plaintext_header_len + handshake.header_len ..][0..nbody.len], nbody);
    _ = try cl.handleFlight(dg[0 .. record.plaintext_header_len + handshake.header_len + nbody.len], rnd, 0, &b1);
}

test "mutation 2026-11-26: DTLS 1.3 client parses a ServerHello connection_id strictly, and only when it offered one" {
    var with = certClient13();
    with.connection_id = "abcd";
    const t = conn13.ext_connection_id;
    try testing.expectError(error.Malformed, clientSeesShExt(with, t, &.{}));
    try testing.expectError(error.Malformed, clientSeesShExt(with, t, &.{ 2, 1 }));
    var c33: [34]u8 = @splat(5);
    c33[0] = 33;
    try testing.expectError(error.Malformed, clientSeesShExt(with, t, &c33));
    try testing.expectError(error.Malformed, clientSeesShExt(certClient13(), t, &.{ 1, 7 }));
}

const ChEdit = struct {
    extra: []const messages.Extension = &.{},
    drop: ?u16 = null,
    /// replaces the data of the pre_shared_key extension
    psk_data: ?[]const u8 = null,
};

/// `sv` receives the ClientHello of a client with `ccfg`, its extensions edited as `edit` says.
fn serverSeesCh(sv: *conn13.Connection, ccfg: conn13.Config, edit: ChEdit) !void {
    var cl = try conn13.Connection.clientInit(ccfg);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xf8)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    const hh = try handshake.decodeHeader(ch[record.plaintext_header_len..]);
    const body = ch[record.plaintext_header_len + handshake.header_len ..][0..hh.length];
    var exts: [32]messages.Extension = undefined;
    const dec = try messages.decodeClientHello(body, &exts);
    var cs: [16]u16 = undefined;
    var n_cs: usize = 0;
    var it = messages.CipherSuiteIter{ .raw = dec.cipher_suites_raw };
    while (it.next()) |c| {
        cs[n_cs] = c;
        n_cs += 1;
    }
    var all: [40]messages.Extension = undefined;
    var m: usize = 0;
    for (dec.extensions) |e| {
        if (edit.drop) |d| if (e.ext_type == d) continue;
        all[m] = e;
        if (edit.psk_data) |pd| if (e.ext_type == @backingInt(messages.ExtensionType.pre_shared_key)) {
            all[m].data = pd;
        };
        m += 1;
    }
    @memcpy(all[m..][0..edit.extra.len], edit.extra);
    m += edit.extra.len;
    var nb: [2048]u8 = undefined;
    const nbody = try messages.encodeClientHello(.{ .random = dec.random, .legacy_session_id = dec.legacy_session_id, .cipher_suites = cs[0..n_cs], .extensions = all[0..m] }, &nb);
    var dg: [2200]u8 = undefined;
    _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = 0, .length = @intCast(handshake.header_len + nbody.len) }, &dg);
    handshake.encodeHeader(.{ .msg_type = hh.msg_type, .length = @intCast(nbody.len), .message_seq = hh.message_seq, .fragment_offset = 0, .fragment_length = @intCast(nbody.len) }, dg[record.plaintext_header_len..][0..handshake.header_len]);
    @memcpy(dg[record.plaintext_header_len + handshake.header_len ..][0..nbody.len], nbody);
    _ = try sv.handleFlight(dg[0 .. record.plaintext_header_len + handshake.header_len + nbody.len], rnd, 0, &b2);
}

fn serverSeesHello(sv: *conn13.Connection, extra: []const messages.Extension) !void {
    return serverSeesCh(sv, certClient13(), .{ .extra = extra });
}

test "mutation 2026-11-26: DTLS 1.3 server reads use_srtp, connection_id, status_request and SCT offers exactly" {
    const cid_t = conn13.ext_connection_id;
    // a use_srtp offer is of no concern to a server without profiles, however malformed
    var sv = try conn13.Connection.serverInit(certServer13());
    try serverSeesHello(&sv, &.{.{ .ext_type = messages.ext_use_srtp, .data = &.{} }});
    // connection_id: malformed offers are refused; 32 bytes are taken, 33 are declined without an answer
    var cfg = certServer13();
    cfg.connection_id = "abcd";
    sv = try conn13.Connection.serverInit(cfg);
    try testing.expectError(error.Malformed, serverSeesHello(&sv, &.{.{ .ext_type = cid_t, .data = &.{} }}));
    sv = try conn13.Connection.serverInit(cfg);
    try testing.expectError(error.Malformed, serverSeesHello(&sv, &.{.{ .ext_type = cid_t, .data = &.{ 5, 1 } }}));
    var c32: [33]u8 = @splat(5);
    c32[0] = 32;
    sv = try conn13.Connection.serverInit(cfg);
    try serverSeesHello(&sv, &.{.{ .ext_type = cid_t, .data = &c32 }});
    try testing.expect(sv.cid_negotiated);
    var c33: [34]u8 = @splat(5);
    c33[0] = 33;
    sv = try conn13.Connection.serverInit(cfg);
    try serverSeesHello(&sv, &.{.{ .ext_type = cid_t, .data = &c33 }});
    try testing.expect(!sv.cid_negotiated);
    // status_request: one OCSP byte is enough; another type or an empty offer is not
    sv = try conn13.Connection.serverInit(certServer13());
    try serverSeesHello(&sv, &.{.{ .ext_type = messages.ext_status_request, .data = &.{1} }});
    try testing.expect(sv.ocsp_requested);
    sv = try conn13.Connection.serverInit(certServer13());
    try serverSeesHello(&sv, &.{.{ .ext_type = messages.ext_status_request, .data = &.{2} }});
    try testing.expect(!sv.ocsp_requested);
    sv = try conn13.Connection.serverInit(certServer13());
    try serverSeesHello(&sv, &.{.{ .ext_type = 0x7a01, .data = &.{1} }});
    try testing.expect(!sv.ocsp_requested);
    // SCT: only the empty extension of that type
    sv = try conn13.Connection.serverInit(certServer13());
    try serverSeesHello(&sv, &.{.{ .ext_type = messages.ext_signed_certificate_timestamp, .data = &.{} }});
    try testing.expect(sv.sct_requested);
    sv = try conn13.Connection.serverInit(certServer13());
    try serverSeesHello(&sv, &.{.{ .ext_type = 0x7a02, .data = &.{} }});
    try testing.expect(!sv.sct_requested);
}

test "mutation 2026-11-26: DTLS 1.3 post-handshake message_seq exactly half the space away is not a retransmission" {
    var c: conn13.Connection = undefined;
    var s: conn13.Connection = undefined;
    try pair13("cidA", "cidBB", &c, &s);
    var wire: [200]u8 = undefined;
    var plain: [64]u8 = undefined;
    const far = (c.peer_message_seq orelse s.message_seq) +% 0x8000;
    try testing.expectError(error.ReceivedPostHandshakeMessage, c.recv(try rawPostSeq(&s, far, 10, 8, 0, &.{ 0, 5, 4, 'c', 'i', 'd', 'X', 1 }, &wire), &plain));
    try testing.expectEqual(@as(u8, 0), c.ack_queue_len); // a retransmission would be re-ACKed
}

// ── round 5: offered PSKs, tickets and early data in the ClientHello, client certificates ─────

fn pskRefusal(cfg: conn13.Config, ccfg: conn13.Config, data: []const u8) anyerror {
    var sv = conn13.Connection.serverInit(cfg) catch |e| return e;
    if (serverSeesCh(&sv, ccfg, .{ .psk_data = data })) |_| return error.TestUnexpectedSuccess else |e| return e;
}

test "mutation 2026-11-26: DTLS 1.3 PSK server: empty identity / binder lists, a missing binder and a short binder are refused" {
    const cfg: conn13.Config = .{ .role = .server, .psk_identity = "id", .psk = "k" };
    const ccfg: conn13.Config = .{ .role = .client, .psk_identity = "id", .psk = "k" };
    var no_ids: [4 + 33]u8 = @splat(7);
    no_ids[0..4].* = .{ 0, 0, 0, 33 };
    no_ids[4] = 32;
    var short: [10 + 2 + 32]u8 = @splat(7);
    short[0..10].* = .{ 0, 8, 0, 2, 'i', 'd', 0, 0, 0, 0 };
    short[10..12].* = .{ 0, 32 };
    short[12] = 31;
    const cases = [_][]const u8{ &.{ 0, 0, 0, 0 }, &no_ids, &.{ 0, 8, 0, 2, 'i', 'd', 0, 0, 0, 0, 0, 0 }, &short };
    for (cases) |data| {
        const e = pskRefusal(cfg, ccfg, data);
        try testing.expect(e == error.NoMatchingPskIdentity or e == error.Malformed);
    }
}

test "mutation 2026-11-26: DTLS 1.3 server with tickets: an offer without identities, without binders or without psk_dhe_ke is a full handshake" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var t = try ticket13(&tkr, 0xb8, 12 * 3600, 0);
    defer t.wipe();
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer() };
    var ccfg = certClient13();
    ccfg.resumption = &t;
    var sv = try conn13.Connection.serverInit(scfg);
    try serverSeesCh(&sv, ccfg, .{}); // the control: the untouched offer resumes
    try testing.expect(sv.resumed());
    sv = try conn13.Connection.serverInit(scfg);
    try serverSeesCh(&sv, ccfg, .{ .psk_data = &.{ 0, 0, 0, 0 } });
    try testing.expect(!sv.resumed());
    // the genuine ticket with no binder list behind it
    var offer: [2 + 2 + conn13.max_ticket_len + 4 + 2]u8 = undefined;
    const idn: usize = t.ticket_len;
    std.mem.writeInt(u16, offer[0..2], @intCast(2 + idn + 4), .big);
    std.mem.writeInt(u16, offer[2..4], @intCast(idn), .big);
    @memcpy(offer[4..][0..idn], t.identity());
    @memset(offer[4 + idn ..][0..6], 0);
    sv = try conn13.Connection.serverInit(scfg);
    try serverSeesCh(&sv, ccfg, .{ .psk_data = offer[0 .. 4 + idn + 6] });
    try testing.expect(!sv.resumed());
    // a binder of 31 bytes behind the genuine ticket
    var ob: [2 + 2 + conn13.max_ticket_len + 4 + 2 + 32]u8 = undefined;
    @memcpy(ob[0 .. 4 + idn + 4], offer[0 .. 4 + idn + 4]);
    std.mem.writeInt(u16, ob[4 + idn + 4 ..][0..2], 32, .big);
    ob[4 + idn + 6] = 31;
    @memset(ob[4 + idn + 7 ..][0..31], 0x5a);
    sv = try conn13.Connection.serverInit(scfg);
    try testing.expectError(error.Malformed, serverSeesCh(&sv, ccfg, .{ .psk_data = ob[0 .. 4 + idn + 38] }));
    // no psk_key_exchange_modes: only psk_dhe_ke resumes
    sv = try conn13.Connection.serverInit(scfg);
    try serverSeesCh(&sv, ccfg, .{ .drop = @backingInt(messages.ExtensionType.psk_key_exchange_modes) });
    try testing.expect(!sv.resumed());
}

test "mutation 2026-11-26: DTLS 1.3 server refuses 0-RTT on a ticket that never allowed it" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var t = try ticket13(&tkr, 0xb9, 12 * 3600, 0);
    defer t.wipe();
    t.max_early_data = 1000; // a client that believes otherwise
    try testing.expect(!(try earlyAccepted(&tkr, &t, 0, true, 0xba)));
}

var client_ecdsa_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;

fn clientEcdsa() certverify.SecretKey {
    client_ecdsa_sk = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.client_secret_key_bytes) catch unreachable;
    return .{ .ecdsa_p256 = &client_ecdsa_sk };
}

test "mutation 2026-11-26: DTLS 1.3 server: a client Certificate without CertificateVerify is malformed" {
    var scfg = certServer13();
    scfg.request_client_cert = true;
    scfg.peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der };
    var ccfg = certClient13();
    ccfg.cert = .{ .chain = &.{&cert_kat.client_cert_der}, .private_key = clientEcdsa() };
    var cl = try conn13.Connection.clientInit(ccfg);
    var sv = try conn13.Connection.serverInit(scfg);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xf9)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    const f2 = try sv.handleFlight(ch, rnd, 0, &b2);
    _ = try cl.handleFlight(f2.out, rnd, 0, &b1);
    // the client's final flight, forged: its Certificate and then a Finished, no CertificateVerify
    var buf: [200]u8 = undefined;
    const cert_body = stapledBody(&buf, .{});
    const fin: [32]u8 = @splat(9);
    const msgs = [_]Fm{ .{ .t = hs_certificate, .body = cert_body }, .{ .t = hs_finished, .body = &fin } };
    var dg: [1024]u8 = undefined;
    var n: usize = 0;
    for (msgs, 0..) |m, i| {
        var inner: [300]u8 = undefined;
        handshake.encodeHeader(.{ .msg_type = m.t, .length = @intCast(m.body.len), .message_seq = @intCast(1 + i), .fragment_offset = 0, .fragment_length = @intCast(m.body.len) }, inner[0..handshake.header_len]);
        @memcpy(inner[handshake.header_len..][0..m.body.len], m.body);
        inner[handshake.header_len + m.body.len] = 22;
        const r = try sealInner(&cl.hs_write_keys, 2, @intCast(i), null, inner[0 .. handshake.header_len + m.body.len + 1], dg[n..]);
        n += r.len;
    }
    try testing.expectError(error.Malformed, sv.handleFlight(dg[0..n], rnd, 0, &b2));
}

test "mutation 2026-11-26: DTLS 1.3 connection ids: a record without the negotiated CID is refused, an empty own CID cannot be re-offered, the extra ring wraps" {
    var c: conn13.Connection = undefined;
    var s: conn13.Connection = undefined;
    try pair13("cidA", "cidBB", &c, &s);
    var out: [200]u8 = undefined;
    var plain: [64]u8 = undefined;
    try testing.expectError(error.Malformed, c.recv(try sealInner(&s.write_keys, s.write_epoch, s.send_seq, null, &.{ 'h', 'i', 23 }, &out), &plain));
    var c2: conn13.Connection = undefined;
    var s2: conn13.Connection = undefined;
    try pair13("", "cidBB", &c2, &s2);
    try testing.expectError(error.ConnectionIdNotNegotiated, c2.offerConnectionIds(&.{"ab"}, .spare));
    // four extras fill the ring; a fifth offer pushes the oldest out
    var w: [512]u8 = undefined;
    var p: [512]u8 = undefined;
    try c.offerConnectionIds(&.{ "c1c1", "c2c2", "c3c3", "c4c4" }, .spare);
    const rec = (try c.poll(1_000_000, &w)).?;
    try testing.expectError(error.ReceivedPostHandshakeMessage, s.recv(rec, &p));
    const ack = (try s.poll(1_000_000, &w)).?;
    try testing.expectError(error.ReceivedAck, c.recv(ack, &p));
    try c.offerConnectionIds(&.{"c5c5"}, .spare);
}

// ── round 6 ─────────────────────────────────────────────────────────────

test "mutation 2026-11-26: Connection12 stateless server: a queued later message does not outlive the HelloVerifyRequest" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x7d)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var s = pskCfg(.server);
    s.hello_retry = .{ .cookie_secret = "cookie secret", .peer_binding = "198.51.100.7:5684" };
    var cl = try c12.Connection12.clientInit(pskCfg(.client));
    var sv = try c12.Connection12.serverInit(s);
    var a: [2048]u8 = undefined;
    var b: [2048]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &a);
    const alone = try sv.handleFlight(ch, rnd, 0, &b);
    const hvr_len = alone.out.len;
    // a whole message of message_seq 1 (it is queued behind the ClientHello), then the ClientHello of message_seq 0
    var dg: [512]u8 = undefined;
    var stray_rec: [64]u8 = undefined;
    hs_rseq = 7;
    defer hs_rseq = 0;
    const stray = hsRecord(20, 1, &(@as([12]u8, @splat(3))), &stray_rec);
    @memcpy(dg[0..stray.len], stray);
    @memcpy(dg[stray.len..][0..ch.len], ch);
    const r = try sv.handleFlight(dg[0 .. stray.len + ch.len], rnd, 0, &b);
    try testing.expectEqual(hvr_len, r.out.len);
}

test "mutation 2026-11-26: DTLS 1.3 with 32-byte connection ids and 16-bit sequence numbers in both the handshake and application epochs" {
    const cid_c: [32]u8 = @splat(0x31);
    const cid_s: [32]u8 = @splat(0x32);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x7e)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl = try conn13.Connection.clientInit(.{ .role = .client, .psk_identity = "id", .psk = "k", .connection_id = &cid_c });
    var sv = try conn13.Connection.serverInit(.{ .role = .server, .psk_identity = "id", .psk = "k", .connection_id = &cid_s });
    sv.hs2.send_seq = 300; // the server's handshake-epoch records carry 16-bit sequence numbers
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    const f2 = try sv.handleFlight(ch, rnd, 0, &b2);
    const cf = try cl.handleFlight(f2.out, rnd, 0, &b1);
    try testing.expect(cf.done);
    const sf = try sv.handleFlight(cf.out, rnd, 0, &b2);
    try testing.expect(sf.done);
    sv.send_seq = 300; // and so do its application records
    var w: [256]u8 = undefined;
    var p: [256]u8 = undefined;
    const rec = try sv.send("long sequence number", &w);
    try testing.expectEqualStrings("long sequence number", try cl.recv(rec, &p));
}

test "mutation 2026-11-26: DTLS 1.3 server not resuming: 0-RTT records are not taken out of its final flight" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x7f)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl = try conn13.Connection.clientInit(certClient13());
    var sv = try conn13.Connection.serverInit(certServer13());
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    _ = try sv.handleFlight(ch, rnd, 0, &b2);
    try testing.expect(!sv.resumed());
    var short_rec: [20]u8 = undefined;
    const hdr_len = (try record.encodeUnified(.{ .epoch_low = 1, .seq_len = .short, .seq_wire = 3, .cid = null, .length = 10 }, &short_rec)).len;
    @memset(short_rec[hdr_len..][0..10], 0x77);
    // not stripped as early data: the record is judged as a (bad) final flight, not waited for
    if (sv.handleFlight(short_rec[0 .. hdr_len + 10], rnd, 0, &b2)) |r| try testing.expect(!r.need_more_data) else |_| {}
}

test "mutation 2026-11-26: DTLS 1.3 0-RTT intake steps over a record that carries the connection id" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var kept: [4096]u8 = undefined;
    // flags: fixed bits, C, no S (one-byte sequence number), L, epoch 3; then the server's CID, sequence number, length 5, payload
    const rec = [_]u8{ 0x37, 'c', 'i', 'd', 'S', 1, 0, 5, 1, 2, 3, 4, 5 };
    const n = try earlyFeedCid(&tkr, 1000, &.{.{ .raw = &rec }}, &kept, true);
    try testing.expectEqual(@as(usize, 0), n);
}

// ── round 7: HelloRetryRequest with another hash, forged ticket state ─────

fn clientCh2HasPsk(hrr_suite: u16) !bool {
    var t: conn13.SessionTicket = .{ .suite = .aes_128_gcm_sha256, .psk = @splat(0x11), .ticket = @splat(0xab), .ticket_len = 32, .ticket_age_add = 7, .lifetime_s = 3600, .received_at_s = cert_now, .max_early_data = 0 };
    var ccfg = certClient13();
    ccfg.cipher_suites = &.{ .aes_128_gcm_sha256, .aes_256_gcm_sha384 };
    ccfg.resumption = &t;
    var cl = try conn13.Connection.clientInit(ccfg);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0xfa)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch1 = try cl.startHandshake(rnd, 0, &b1);
    const hh1 = try handshake.decodeHeader(ch1[record.plaintext_header_len..]);
    var exts1: [32]messages.Extension = undefined;
    const dec1 = try messages.decodeClientHello(ch1[record.plaintext_header_len + handshake.header_len ..][0..hh1.length], &exts1);
    var vb: [4]u8 = undefined;
    const versions = try messages.encodeSupportedVersionsServerHello(messages.version_dtls13, &vb);
    var ckb: [16]u8 = undefined;
    const cookie = try messages.encodeCookieExtension("ck", &ckb);
    var nb: [128]u8 = undefined;
    const nbody = try messages.encodeServerHello(.{ .random = messages.hello_retry_request_random, .legacy_session_id_echo = dec1.legacy_session_id, .cipher_suite = hrr_suite, .extensions = &.{
        .{ .ext_type = @backingInt(messages.ExtensionType.supported_versions), .data = versions },
        .{ .ext_type = @backingInt(messages.ExtensionType.cookie), .data = cookie },
    } }, &nb);
    var dg: [300]u8 = undefined;
    _ = try record.encodePlaintext(.{ .content_type = 22, .epoch = 0, .sequence_number = 0, .length = @intCast(handshake.header_len + nbody.len) }, &dg);
    handshake.encodeHeader(.{ .msg_type = @backingInt(messages.HandshakeType.server_hello), .length = @intCast(nbody.len), .message_seq = 0, .fragment_offset = 0, .fragment_length = @intCast(nbody.len) }, dg[record.plaintext_header_len..][0..handshake.header_len]);
    @memcpy(dg[record.plaintext_header_len + handshake.header_len ..][0..nbody.len], nbody);
    const r = try cl.handleFlight(dg[0 .. record.plaintext_header_len + handshake.header_len + nbody.len], rnd, 0, &b2);
    const hh2 = try handshake.decodeHeader(r.out[record.plaintext_header_len..]);
    var exts2: [32]messages.Extension = undefined;
    const dec2 = try messages.decodeClientHello(r.out[record.plaintext_header_len + handshake.header_len ..][0..hh2.length], &exts2);
    for (dec2.extensions) |e| {
        if (e.ext_type == @backingInt(messages.ExtensionType.pre_shared_key)) return true;
    }
    return false;
}

test "mutation 2026-11-26: DTLS 1.3 client drops its ticket from ClientHello2 when the retry names a suite of another hash" {
    try testing.expect(try clientCh2HasPsk(0x1301)); // the ticket's own hash: kept
    try testing.expect(!(try clientCh2HasPsk(0x1302))); // SHA-384: dropped (RFC 8446 §4.1.4)
}

fn resumesFromState13(tkr: *const TestTicketer12, psk_len_byte: u8) !bool {
    var st: [57]u8 = @splat(0x44);
    st[0] = 3; // ticket_state_version
    std.mem.writeInt(u16, st[1..3], 0x1301, .big);
    std.mem.writeInt(i64, st[3..11], cert_now, .big);
    std.mem.writeInt(u32, st[11..15], 7, .big);
    std.mem.writeInt(u32, st[15..19], 3600, .big);
    std.mem.writeInt(u32, st[19..23], 0, .big);
    st[23] = psk_len_byte;
    st[56] = 0; // no ALPN
    var blob_buf: [256]u8 = undefined;
    const tk = tkr.ticketer();
    const blob = tk.seal(tk.ctx, &st, @splat(5), &blob_buf) orelse return error.TestSealFailed;
    var arr: [conn13.max_ticket_len]u8 = @splat(0);
    @memcpy(arr[0..blob.len], blob);
    var t: conn13.SessionTicket = .{ .suite = .aes_128_gcm_sha256, .psk = @splat(0x44), .ticket = arr, .ticket_len = @intCast(blob.len), .ticket_age_add = 7, .lifetime_s = 3600, .received_at_s = cert_now, .max_early_data = 0 };
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer() };
    var ccfg = certClient13();
    ccfg.resumption = &t;
    var sv = try conn13.Connection.serverInit(scfg);
    try serverSeesCh(&sv, ccfg, .{});
    return sv.resumed();
}

test "mutation 2026-11-26: DTLS 1.3 server resumes only from a ticket state whose PSK length matches its hash" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    try testing.expect(try resumesFromState13(&tkr, 32)); // control: a well-formed state
    try testing.expect(!(try resumesFromState13(&tkr, 31)));
}

// ── wipes of state and of decrypt output (2026-11-26, burn/wipe batch) ───────────────────────────────

fn allZero(b: []const u8) bool {
    return std.mem.allEqual(u8, b, 0);
}

test "mutation 2026-11-26: SessionTicket.wipe and SessionTicket12.wipe clear the stored secret" {
    var t: conn13.SessionTicket = .{ .suite = .aes_128_gcm_sha256, .psk = @splat(0x11), .ticket = @splat(0xab), .ticket_len = 32, .ticket_age_add = 7, .lifetime_s = 3600, .received_at_s = 0, .max_early_data = 0 };
    try testing.expect(!allZero(&t.psk));
    t.wipe();
    try testing.expect(allZero(&t.psk));
    var t12: conn13.SessionTicket12 = .{ .suite = .psk_with_aes_128_gcm_sha256, .master = @splat(0x22), .ems = true, .ticket = @splat(0xcd), .ticket_len = 32, .lifetime_hint_s = 0, .received_at_s = 0 };
    try testing.expect(!allZero(&t12.master));
    t12.wipe();
    try testing.expect(allZero(&t12.master));
}

test "mutation 2026-11-26: DirKeys.wipe clears the key, the IV and the expanded AES-GCM schedule" {
    inline for (.{ record12.Bulk.aes_128_gcm, record12.Bulk.aes_256_gcm }) |bulk| {
        var k: record12.DirKeys = .{ .bulk = bulk };
        for (&k.key, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
        for (&k.iv, 0..) |*b, i| b.* = @truncate(i * 5 + 3);
        k.prepare();
        try testing.expect(!allZero(&k.key));
        try testing.expect(!allZero(&k.iv));
        try testing.expect(!allZero(std.mem.asBytes(&k.gcm)));
        k.wipe();
        try testing.expect(allZero(&k.key));
        try testing.expect(allZero(&k.iv));
        try testing.expect(allZero(std.mem.asBytes(&k.gcm)));
        try testing.expect(k.gcm == .none);
    }
}

fn ecdhePskCfg(role: conn13.Role) conn13.Config {
    var c = pskCfg(role);
    c.cipher_suites12 = &.{.ecdhe_psk_with_chacha20_poly1305_sha256};
    return c;
}

test "mutation 2026-11-26: Connection12 wipes the server's ECDHE secret after the ClientKeyExchange and every secret on deinit" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5d)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var a: [8192]u8 = undefined;
    var b: [8192]u8 = undefined;

    // ECDHE_PSK: the server holds its ECDHE secret between its first flight and the ClientKeyExchange.
    var ec = try c12.Connection12.clientInit(ecdhePskCfg(.client));
    var es = try c12.Connection12.serverInit(ecdhePskCfg(.server));
    const ch = try ec.startHandshake(rnd, 0, &a);
    const f1 = try es.handleFlight(ch, rnd, 0, &b);
    try testing.expect(es.ecdhe_live);
    try testing.expect(!allZero(&es.ecdhe_secret));
    const f2 = try ec.handleFlight(f1.out, rnd, 0, &a);
    _ = try es.handleFlight(f2.out, rnd, 0, &b);
    try testing.expect(!es.ecdhe_live);
    try testing.expect(allZero(&es.ecdhe_secret));

    // deinit while the secret is live
    var ec2 = try c12.Connection12.clientInit(ecdhePskCfg(.client));
    var es2 = try c12.Connection12.serverInit(ecdhePskCfg(.server));
    const ch2 = try ec2.startHandshake(rnd, 0, &a);
    _ = try es2.handleFlight(ch2, rnd, 0, &b);
    try testing.expect(!allZero(&es2.ecdhe_secret));
    es2.deinit();
    try testing.expect(allZero(&es2.ecdhe_secret));

    // deinit of a connected client holding a session ticket: master secret and the ticket's copy
    var ring = newRing();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var cl = try c12.Connection12.clientInit(pskTicketCfg(.client, &tkr));
    var sv = try c12.Connection12.serverInit(pskTicketCfg(.server, &tkr));
    try driveFull(&cl, &sv, rnd);
    try testing.expect(cl.sessionTicket() != null);
    try testing.expect(!allZero(&cl.master));
    try testing.expect(!allZero(&cl.ticket.master));
    cl.deinit();
    try testing.expect(allZero(&cl.master));
    try testing.expect(allZero(&cl.ticket.master));
}

test "mutation 2026-11-26: DTLS 1.3 server wipes the kept master secret once the client's Finished is processed" {
    var ring = ring13();
    const tkr: TestTicketer12 = .{ .ring = &ring };
    var scfg = certServer13();
    scfg.tickets = .{ .ticketer = tkr.ticketer() };
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5e)));
    const rnd: conn13.Entropy = .{ .seeded_for_test = csprng.random() };
    var cl = try conn13.Connection.clientInit(certClient13());
    var sv = try conn13.Connection.serverInit(scfg);
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    const ch = try cl.startHandshake(rnd, 0, &b1);
    const f2 = try sv.handleFlight(ch, rnd, 0, &b2);
    try testing.expect(sv.master_live);
    try testing.expect(!allZero(&sv.master_secret));
    const cf = try cl.handleFlight(f2.out, rnd, 0, &b1);
    const sf = try sv.handleFlight(cf.out, rnd, 0, &b2);
    try testing.expect(sf.done);
    try testing.expect(!sv.master_live);
    try testing.expect(allZero(&sv.master_secret));
}

test "mutation 2026-11-26: record12.open and openCid leave no plaintext in `out` when the tag fails" {
    const pt = "the secret application data, longer than a block";
    inline for (.{ record12.Bulk.aes_128_gcm, record12.Bulk.aes_256_gcm, record12.Bulk.aes_128_ccm, record12.Bulk.aes_128_ccm_8, record12.Bulk.chacha20_poly1305 }) |bulk| {
        inline for (.{ false, true }) |prep| {
            var k: record12.DirKeys = .{ .bulk = bulk };
            for (&k.key, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
            for (&k.iv, 0..) |*b, i| b.* = @truncate(i * 5 + 3);
            if (prep) k.prepare();
            var wire: [256]u8 = undefined;
            var out: [128]u8 = @splat(0xa5);

            const sealed = try record12.seal(&k, 1, 2, 23, pt, &wire);
            sealed[sealed.len - 1] ^= 1; // the last tag byte
            const hdr = try record.decodePlaintext(sealed);
            try testing.expectError(error.DecryptionFailed, record12.open(&k, hdr, sealed[record.plaintext_header_len..], &out));
            try testing.expect(allZero(out[0..pt.len]));

            const cid = [_]u8{ 1, 2, 3, 4 };
            out = @splat(0xa5);
            const sealed_cid = try record12.sealCid(&k, 1, 2, 23, pt, &cid, &wire);
            sealed_cid[sealed_cid.len - 1] ^= 1;
            const ch = try record12.decodeCidHeader(sealed_cid, cid.len);
            try testing.expectError(error.DecryptionFailed, record12.openCid(&k, ch, sealed_cid[record12.CidHeader.len(cid.len)..][0..ch.length], &out));
            try testing.expect(allZero(out[0 .. pt.len + 1]));
        }
    }
}

test "mutation 2026-11-26: Connection12.recv wipes the plaintext of a replayed record (RFC 6347 and CID forms)" {
    inline for (.{ false, true }) |with_cid| {
        var pair: Pair = undefined;
        try pair.connect(with_cid);
        var wire: [256]u8 = undefined;
        const msg = "replay me, a secret payload";
        const rec = try pair.client.send(msg, &wire);
        var out: [128]u8 = undefined;
        try testing.expectEqualStrings(msg, try pair.server.recv(rec, &out));
        var out2: [128]u8 = @splat(0xa5);
        try testing.expectError(error.ReplayedRecord, pair.server.recv(rec, &out2));
        try testing.expect(allZero(out2[0..msg.len]));
    }
}
