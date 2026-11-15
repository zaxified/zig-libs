// SPDX-License-Identifier: MIT

//! Tests. Every vector is built by hand from the byte layouts in HAProxy's
//! doc/proxy-protocol.txt (v1 § 2.1, v2 § 2.2); none comes from another
//! implementation's suite.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const netaddr = @import("netaddr");
const crc32c = @import("crc32c");
const pp = @import("root.zig");

const hex = testkit.hex;
const sig = hex.literal("0d0a0d0a000d0a515549540a");

fn expectHeader(res: pp.ParseResult) !pp.Parsed {
    switch (res) {
        .header => |p| return p,
        else => return error.NotAHeader,
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) netaddr.Ip {
    return .{ .v4 = .{ a, b, c, d } };
}

fn inet(ip: netaddr.Ip, port: u16) pp.Addr {
    return .{ .inet = .{ .ip = ip, .port = port } };
}

// ── v1 ──────────────────────────────────────────────────────────────────────

test "v1: TCP4" {
    const line = "PROXY TCP4 192.168.0.1 10.0.0.2 56324 443\r\nGET / HTTP/1.1\r\n";
    const p = try expectHeader(try pp.parse(line));
    try testing.expectEqual(@as(usize, 43), p.consumed);
    try testing.expectEqual(@as(u2, 1), p.h.version);
    try testing.expectEqual(pp.Family.tcp4, p.h.family);
    try testing.expectEqual(pp.Command.proxy, p.h.command);
    try testing.expect(p.h.source.?.eql(inet(v4(192, 168, 0, 1), 56324)));
    try testing.expect(p.h.destination.?.eql(inet(v4(10, 0, 0, 2), 443)));
    try testing.expectEqual(@as(usize, 0), p.h.tlvs.len);
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n", line[p.consumed..]);
}

test "v1: TCP6, compressed and mapped forms" {
    const p = try expectHeader(try pp.parse("PROXY TCP6 ::1 2001:db8::2 4660 443\r\n"));
    try testing.expectEqual(pp.Family.tcp6, p.h.family);
    try testing.expect(p.h.source.?.eql(inet(netaddr.Ip.ipv6_loopback, 4660)));
    const want: netaddr.Ip = .{ .v6 = hex.literal("20010db8000000000000000000000002") };
    try testing.expect(p.h.destination.?.eql(inet(want, 443)));
    const m = try expectHeader(try pp.parse("PROXY TCP6 ::ffff:1.2.3.4 ::1 0 65535\r\n"));
    try testing.expect(m.h.source.?.eql(inet(.{ .v6 = hex.literal("00000000000000000000ffff01020304") }, 0)));
    try testing.expect(m.h.destination.?.eql(inet(netaddr.Ip.ipv6_loopback, 65535)));
}

test "v1: UNKNOWN ignores the rest of the line" {
    const a = try expectHeader(try pp.parse("PROXY UNKNOWN\r\nrest"));
    try testing.expectEqual(@as(usize, 15), a.consumed);
    try testing.expectEqual(pp.Family.unspec, a.h.family);
    try testing.expect(a.h.source == null and a.h.destination == null);
    const b = try expectHeader(try pp.parse("PROXY UNKNOWN ffff::ffff ::1 65535 65535 junk \x01\xff\r\n"));
    try testing.expectEqual(pp.Family.unspec, b.h.family);
    try testing.expect(b.h.source == null);
}

test "v1: the 107-byte limit" {
    var line: [200]u8 = undefined;
    @memcpy(line[0..14], "PROXY UNKNOWN ");
    @memset(line[14..105], 'x');
    @memcpy(line[105..107], "\r\n");
    const p = try expectHeader(try pp.parse(line[0..107]));
    try testing.expectEqual(@as(usize, 107), p.consumed);
    // One byte more: the CRLF falls outside the window.
    @memset(line[14..106], 'x');
    @memcpy(line[106..108], "\r\n");
    try testing.expectError(error.Malformed, pp.parse(line[0..108]));
    // 107 bytes with no CRLF at all: refused rather than waiting for more.
    @memset(line[14..107], 'x');
    try testing.expectError(error.Malformed, pp.parse(line[0..107]));
    // 106 bytes without LF: more may come.
    try testing.expectEqual(@as(usize, 1), (try pp.parse(line[0..106])).need_more);
}

test "v1: the longest TCP6 line fits" {
    const l = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
    try testing.expect(l.len <= pp.max_v1_len);
    const p = try expectHeader(try pp.parse(l));
    try testing.expectEqual(l.len, p.consumed);
}

test "v1: malformed forms" {
    const bad = [_][]const u8{
        "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n", // bare LF
        "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\r\n", // stray CR
        "PROXY  TCP4 1.2.3.4 5.6.7.8 1 2\r\n", // double space
        "PROXY TCP4 1.2.3.4  5.6.7.8 1 2\r\n",
        "PROXY TCP4 1.2.3.4 5.6.7.8 1 2 \r\n", // trailing space
        "PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n", // missing field
        "PROXY TCP4 1.2.3.4 5.6.7.8 1 2 3\r\n", // extra field
        "PROXY TCP4 1.2.3.4 5.6.7.8 65536 2\r\n",
        "PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n", // leading zero
        "PROXY TCP4 1.2.3.4 5.6.7.8 -1 2\r\n",
        "PROXY TCP4 1.2.3.4 5.6.7.8 1 \r\n",
        "PROXY TCP4 256.2.3.4 5.6.7.8 1 2\r\n",
        "PROXY TCP4 ::1 ::1 1 2\r\n", // wrong family
        "PROXY TCP6 1.2.3.4 1.2.3.4 1 2\r\n",
        "PROXY TCP6 ::1%eth0 ::1 1 2\r\n", // zone
        "PROXY tcp4 1.2.3.4 5.6.7.8 1 2\r\n", // case
        "PROXY UDP4 1.2.3.4 5.6.7.8 1 2\r\n",
        "PROXY UNKNOWNX\r\n",
        "PROXY \r\n",
        "PROXY\r\n\r\n\r\n", // no space after PROXY, caught as absent below
    };
    for (bad[0 .. bad.len - 1]) |b| try testing.expectError(error.Malformed, pp.parse(b));
    try testing.expect(try pp.parse(bad[bad.len - 1]) == .absent);
}

test "v1: split delivery asks for more at every cut" {
    const line = "PROXY TCP4 192.168.0.1 10.0.0.2 56324 443\r\n";
    for (0..line.len) |k| {
        const r = try pp.parse(line[0..k]);
        switch (r) {
            .need_more => |n| {
                try testing.expect(n >= 1);
                try testing.expect(k + n <= line.len);
            },
            else => return error.ExpectedNeedMore,
        }
    }
    _ = try expectHeader(try pp.parse(line));
}

// ── absent ──────────────────────────────────────────────────────────────────

test "absent: HTTP and TLS bytes are left alone" {
    try testing.expect(try pp.parse("GET / HTTP/1.1\r\nHost: x\r\n\r\n") == .absent);
    try testing.expect(try pp.parse("POST /a HTTP/1.1\r\n") == .absent);
    // A TLS ClientHello record header and handshake start.
    try testing.expect(try pp.parse(&hex.literal("160301020001000100fc0303")) == .absent);
    try testing.expect(try pp.parse("PROXX TCP4") == .absent);
    try testing.expect(try pp.parse("\r\n\r\n\x01") == .absent);
    // v2 signature differing in its last byte.
    try testing.expect(try pp.parse(&hex.literal("0d0a0d0a000d0a515549540b2111000c")) == .absent);
}

test "absent: empty and partial prefixes need more" {
    try testing.expectEqual(@as(usize, 1), (try pp.parse("")).need_more);
    try testing.expectEqual(@as(usize, 1), (try pp.parse("PROXY")).need_more);
    try testing.expectEqual(@as(usize, 5), (try pp.parse("P")).need_more);
    try testing.expectEqual(@as(usize, 11), (try pp.parse("\r")).need_more);
    try testing.expectEqual(@as(usize, 4), (try pp.parse(sig[0..8])).need_more);
    // The signature complete: now the 16 fixed bytes are what is missing.
    try testing.expectEqual(@as(usize, 4), (try pp.parse(&sig)).need_more);
}

// ── v2 ──────────────────────────────────────────────────────────────────────

const tcp4_hdr = sig ++ hex.literal("2111000c" ++ "c0a80001" ++ "0a000002" ++ "1f90" ++ "0050");
const tcp6_hdr = sig ++ hex.literal("21210024" ++ "00000000000000000000000000000001" ++ "20010db8000000000000000000000002" ++ "1234" ++ "01bb");

test "v2: TCP4" {
    const p = try expectHeader(try pp.parse(&(tcp4_hdr ++ "tail".*)));
    try testing.expectEqual(@as(usize, 28), p.consumed);
    try testing.expectEqual(@as(u2, 2), p.h.version);
    try testing.expectEqual(pp.Command.proxy, p.h.command);
    try testing.expectEqual(pp.Family.tcp4, p.h.family);
    try testing.expect(p.h.source.?.eql(inet(v4(192, 168, 0, 1), 8080)));
    try testing.expect(p.h.destination.?.eql(inet(v4(10, 0, 0, 2), 80)));
    try testing.expectEqual(@as(usize, 0), p.h.tlvs.len);
}

test "v2: TCP6" {
    const p = try expectHeader(try pp.parse(&tcp6_hdr));
    try testing.expectEqual(@as(usize, 52), p.consumed);
    try testing.expectEqual(pp.Family.tcp6, p.h.family);
    try testing.expect(p.h.source.?.eql(inet(netaddr.Ip.ipv6_loopback, 0x1234)));
    try testing.expect(p.h.destination.?.eql(inet(.{ .v6 = hex.literal("20010db8000000000000000000000002") }, 443)));
}

test "v2: UDP4 and UDP6 share the address layouts" {
    var a = tcp4_hdr;
    a[13] = 0x12;
    const p = try expectHeader(try pp.parse(&a));
    try testing.expectEqual(pp.Family.udp4, p.h.family);
    try testing.expect(p.h.source.?.eql(inet(v4(192, 168, 0, 1), 8080)));
    var b = tcp6_hdr;
    b[13] = 0x22;
    const q = try expectHeader(try pp.parse(&b));
    try testing.expectEqual(pp.Family.udp6, q.h.family);
    try testing.expectEqual(@as(u16, 443), q.h.destination.?.inet.port);
}

test "v2: UNIX stream and datagram, NUL padding removed" {
    var b: [16 + 216]u8 = @splat(0);
    @memcpy(b[0..12], &sig);
    b[12] = 0x21;
    b[13] = 0x31;
    std.mem.writeInt(u16, b[14..16], 216, .big);
    @memcpy(b[16..][0..12], "/run/src.soc");
    @memcpy(b[16 + 108 ..][0..12], "/run/dst.soc");
    const p = try expectHeader(try pp.parse(&b));
    try testing.expectEqual(pp.Family.unix_stream, p.h.family);
    try testing.expectEqualStrings("/run/src.soc", p.h.source.?.unix);
    try testing.expectEqualStrings("/run/dst.soc", p.h.destination.?.unix);
    b[13] = 0x32;
    // A path filling all 108 bytes has no NUL.
    @memset(b[16..][0..108], 'a');
    const q = try expectHeader(try pp.parse(&b));
    try testing.expectEqual(pp.Family.unix_dgram, q.h.family);
    try testing.expectEqual(@as(usize, 108), q.h.source.?.unix.len);
}

test "v2: LOCAL ignores family, addresses and TLVs" {
    var a = tcp4_hdr;
    a[12] = 0x20;
    const p = try expectHeader(try pp.parse(&a));
    try testing.expectEqual(pp.Command.local, p.h.command);
    try testing.expect(p.h.source == null and p.h.destination == null);
    try testing.expectEqual(@as(usize, 28), p.consumed);
    // Unknown family byte and a nonsense body are fine for LOCAL.
    const l = sig ++ hex.literal("20ee0003ffffff");
    const q = try expectHeader(try pp.parse(&l));
    try testing.expectEqual(pp.Command.local, q.h.command);
    try testing.expectEqual(@as(usize, 19), q.consumed);
    // Empty LOCAL.
    const e = sig ++ hex.literal("20000000");
    try testing.expectEqual(@as(usize, 16), (try expectHeader(try pp.parse(&e))).consumed);
}

test "v2: PROXY with UNSPEC family carries no addresses" {
    const u = sig ++ hex.literal("21000004c0a80001");
    const p = try expectHeader(try pp.parse(&u));
    try testing.expectEqual(pp.Family.unspec, p.h.family);
    try testing.expectEqual(pp.Command.proxy, p.h.command);
    try testing.expect(p.h.source == null);
    try testing.expectEqual(@as(usize, 20), p.consumed);
}

test "v2: malformed fixed fields" {
    var a = tcp4_hdr;
    a[12] = 0x11; // version 1 in the binary form
    try testing.expectError(error.Malformed, pp.parse(&a));
    a[12] = 0x31;
    try testing.expectError(error.Malformed, pp.parse(&a));
    a[12] = 0x22; // command 2
    try testing.expectError(error.Malformed, pp.parse(&a));
    a[12] = 0x21;
    for ([_]u8{ 0x01, 0x10, 0x13, 0x23, 0x30, 0x33, 0x41, 0xff }) |f| {
        a[13] = f;
        try testing.expectError(error.Malformed, pp.parse(&a));
    }
}

test "v2: address block shorter than the family needs" {
    // TCP4 with 11 bytes, TCP6 with 35, UNIX with 215.
    const t4 = sig ++ hex.literal("2111000b" ++ "c0a800010a000002" ++ "1f9000");
    try testing.expectError(error.Malformed, pp.parse(&t4));
    var t6 = tcp6_hdr;
    std.mem.writeInt(u16, t6[14..16], 35, .big);
    try testing.expectError(error.Malformed, pp.parse(t6[0..51]));
    var u: [16 + 215]u8 = @splat(0);
    @memcpy(u[0..12], &sig);
    u[12] = 0x21;
    u[13] = 0x31;
    std.mem.writeInt(u16, u[14..16], 215, .big);
    try testing.expectError(error.Malformed, pp.parse(&u));
}

test "v2: size cap, default 536" {
    var big: [16]u8 = undefined;
    @memcpy(big[0..12], &sig);
    big[12] = 0x21;
    big[13] = 0x11;
    // 520 payload bytes = exactly 536: accepted as far as the cap goes.
    std.mem.writeInt(u16, big[14..16], 520, .big);
    try testing.expectEqual(@as(usize, 520), (try pp.parse(&big)).need_more);
    std.mem.writeInt(u16, big[14..16], 521, .big);
    try testing.expectError(error.TooLarge, pp.parse(&big));
    std.mem.writeInt(u16, big[14..16], 65535, .big);
    try testing.expectError(error.TooLarge, pp.parse(&big));
    // A configured cap, both ways.
    try testing.expectEqual(@as(usize, 65535), (try pp.parseOpts(&big, .{ .max_v2_len = 65551 })).need_more);
    std.mem.writeInt(u16, big[14..16], 12, .big);
    try testing.expectError(error.TooLarge, pp.parseOpts(&big, .{ .max_v2_len = 27 }));
    try testing.expectEqual(@as(usize, 12), (try pp.parseOpts(&big, .{ .max_v2_len = 28 })).need_more);
}

test "v2: split delivery asks for more at every cut" {
    for ([_][]const u8{ &tcp4_hdr, &tcp6_hdr }) |h| {
        for (0..h.len) |k| {
            switch (try pp.parse(h[0..k])) {
                .need_more => |n| {
                    try testing.expect(n >= 1);
                    try testing.expect(k + n <= h.len);
                },
                else => return error.ExpectedNeedMore,
            }
        }
        _ = try expectHeader(try pp.parse(h));
    }
}

// ── TLVs ────────────────────────────────────────────────────────────────────

fn tlvHeader(comptime tlvs: []const u8) [28 + tlvs.len]u8 {
    var h = tcp4_hdr ++ tlvs[0..tlvs.len].*;
    std.mem.writeInt(u16, h[14..16], @intCast(12 + tlvs.len), .big);
    return h;
}

test "TLV: typed helpers" {
    const t = comptime hex.literal(
        "010002" ++ "6832" ++ // ALPN "h2"
            "020009" ++ "6578616d706c652e" ++ "31" ++ // authority "example.1"
            "040002" ++ "0000" ++ // NOOP
            "050003" ++ "010203" ++ // unique id
            "300002" ++ "6e73" ++ // netns "ns"
            "ea0005" ++ "01766365ab" ++ // AWS
            "ee0005" ++ "0100000007" ++ // Azure
            "e00004" ++ "deadbeef", // GCP
    );
    const buf = tlvHeader(&t);
    const p = try expectHeader(try pp.parse(&buf));
    const h = p.h;
    try testing.expectEqualStrings("h2", (try h.alpn()).?);
    try testing.expectEqualStrings("example.1", (try h.authority()).?);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, (try h.uniqueId()).?);
    try testing.expectEqualStrings("ns", (try h.netns()).?);
    try testing.expectEqualSlices(u8, &hex.literal("01766365ab"), (try h.aws()).?);
    try testing.expectEqualSlices(u8, &hex.literal("0100000007"), (try h.azure()).?);
    try testing.expectEqualSlices(u8, &hex.literal("deadbeef"), (try h.gcp()).?);
    try testing.expect((try h.ssl()) == null);
    try testing.expect((try h.crc32cValue()) == null);
    var it = h.tlvIterator();
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 8), n);
}

test "TLV: SSL with sub-TLVs" {
    const ssl = comptime hex.literal(
        "200029" ++ "07" ++ "00000000" ++ // client: ssl+cert_conn+cert_sess, verified
            "210007" ++ "544c5376312e33" ++ // version "TLSv1.3"
            "220005" ++ "636c69656e" ++ // CN "clien"
            "230003" ++ "414553" ++ // cipher "AES"
            "240003" ++ "525341" ++ // sig alg "RSA"
            "250003" ++ "454344", // key alg "ECD"
    );
    const buf = tlvHeader(&ssl);
    const h = (try expectHeader(try pp.parse(&buf))).h;
    const s = (try h.ssl()).?;
    try testing.expect(s.usesSsl() and s.certConn() and s.certSess() and s.verified());
    try testing.expectEqualStrings("TLSv1.3", (try s.version()).?);
    try testing.expectEqualStrings("clien", (try s.cn()).?);
    try testing.expectEqualStrings("AES", (try s.cipher()).?);
    try testing.expectEqualStrings("RSA", (try s.sigAlg()).?);
    try testing.expectEqualStrings("ECD", (try s.keyAlg()).?);
    // Plain TCP (client = 0), failed verification, no sub-TLVs.
    const bare = comptime hex.literal("200005" ++ "00" ++ "00000001");
    const b2 = tlvHeader(&bare);
    const s2 = (try (try expectHeader(try pp.parse(&b2))).h.ssl()).?;
    try testing.expect(!s2.usesSsl() and !s2.verified());
    try testing.expect((try s2.version()) == null);
    // Too short for the fixed part.
    try testing.expectError(error.Malformed, pp.Ssl.parse(&hex.literal("01000000")));
    // A sub-TLV running past the SSL value.
    const bad = comptime pp.Ssl.parse(&hex.literal("0100000000" ++ "21000500")) catch unreachable;
    try testing.expectError(error.Malformed, bad.version());
}

test "TLV: bounds are checked at parse time" {
    // Length runs one byte past the payload.
    const a = comptime hex.literal("010003" ++ "6832");
    try testing.expectError(error.Malformed, pp.parse(&tlvHeader(&a)));
    // A header shorter than 3 bytes.
    const b = comptime hex.literal("0100");
    try testing.expectError(error.Malformed, pp.parse(&tlvHeader(&b)));
    // Empty value is fine.
    const c = comptime hex.literal("010000");
    const h = (try expectHeader(try pp.parse(&tlvHeader(&c)))).h;
    try testing.expectEqual(@as(usize, 0), (try h.alpn()).?.len);
    // The iterator on a hand-made hostile Header does not trust it.
    const hostile: pp.Header = .{ .tlvs = &hex.literal("01ffff00") };
    try testing.expectError(error.Malformed, hostile.alpn());
    var it = hostile.tlvIterator();
    try testing.expectError(error.Malformed, it.next());
}

test "CRC32C: good, bad, malformed" {
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const hdr: pp.Header = .{ .family = .tcp4, .source = inet(v4(1, 2, 3, 4), 1000), .destination = inet(v4(5, 6, 7, 8), 80) };
    try pp.writeV2Crc(&w, hdr, &hex.literal("010002" ++ "6832"));
    const bytes = w.buffered();
    const p = try expectHeader(try pp.parse(bytes));
    const stored = (try p.h.crc32cValue()).?;
    // Independent recomputation: zero the field and hash in one go.
    var copy: [128]u8 = undefined;
    @memcpy(copy[0..bytes.len], bytes);
    @memset(copy[bytes.len - 4 .. bytes.len], 0);
    try testing.expectEqual(crc32c.hash(copy[0..bytes.len]), stored);
    try testing.expectEqualStrings("h2", (try p.h.alpn()).?);
    // Flip one bit anywhere past the signature: refused (as BadChecksum, or
    // Malformed/another error when the flip breaks the framing first).
    for (12..bytes.len) |i| {
        if (i == bytes.len - 7) continue; // the CRC TLV's own type byte: a header without a CRC is valid
        @memcpy(copy[0..bytes.len], bytes);
        copy[i] ^= 0x04;
        if (pp.parse(copy[0..bytes.len])) |r| {
            switch (r) {
                .header => return error.CorruptHeaderAccepted,
                else => {},
            }
        } else |_| {}
    }
    // Specifically a corrupted payload byte is BadChecksum.
    @memcpy(copy[0..bytes.len], bytes);
    copy[17] ^= 1;
    try testing.expectError(error.BadChecksum, pp.parse(copy[0..bytes.len]));
    // A CRC TLV of 3 bytes, and two CRC TLVs.
    const short = comptime hex.literal("030003" ++ "000000");
    try testing.expectError(error.Malformed, pp.parse(&tlvHeader(&short)));
    const two = comptime hex.literal("030004" ++ "00000000" ++ "030004" ++ "00000000");
    try testing.expectError(error.Malformed, pp.parse(&tlvHeader(&two)));
}

// ── read ────────────────────────────────────────────────────────────────────

const lb: netaddr.Prefix = .{ .addr = v4(10, 0, 0, 0), .bits = 8 };
const trusted_opts: pp.ReadOptions = .{ .peer = v4(10, 1, 2, 3), .trusted = &.{lb} };

test "read: header consumed, the rest left for the protocol" {
    var r: std.Io.Reader = .fixed(&(tcp4_hdr ++ "GET /".*));
    var buf: [pp.default_max_v2_len]u8 = undefined;
    const h = (try pp.read(&r, &buf, trusted_opts)).?;
    try testing.expect(h.source.?.eql(inet(v4(192, 168, 0, 1), 8080)));
    try testing.expectEqualStrings("GET /", r.buffered());
}

test "read: absent leaves every byte in place" {
    var r: std.Io.Reader = .fixed("GET / HTTP/1.1\r\n\r\n");
    var buf: [pp.default_max_v2_len]u8 = undefined;
    try testing.expect((try pp.read(&r, &buf, trusted_opts)) == null);
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", r.buffered());
    var ebuf: [pp.default_max_v2_len]u8 = undefined;
    var e = testkit.fuzz.ChunkedReader.init("", .{}, &ebuf);
    try testing.expect((try pp.read(&e.interface, &buf, trusted_opts)) == null);
    var e2 = testkit.fuzz.ChunkedReader.init("", .{}, &ebuf);
    try testing.expectError(error.Missing, pp.read(&e2.interface, &buf, .{ .peer = v4(10, 1, 2, 3), .trusted = &.{lb}, .required = true }));
    var r2: std.Io.Reader = .fixed("GET /");
    try testing.expectError(error.Missing, pp.read(&r2, &buf, .{ .peer = v4(10, 1, 2, 3), .trusted = &.{lb}, .required = true }));
    try testing.expectEqualStrings("GET /", r2.buffered());
}

test "read: untrusted peers, and the empty list refuses everything" {
    var buf: [pp.default_max_v2_len]u8 = undefined;
    const input = "PROXY TCP4 1.1.1.1 2.2.2.2 1 2\r\nrest";
    var a: std.Io.Reader = .fixed(input);
    try testing.expectError(error.UntrustedPeer, pp.read(&a, &buf, .{ .peer = v4(192, 0, 2, 1), .trusted = &.{lb} }));
    try testing.expectEqual(input.len, a.bufferedLen());
    var b: std.Io.Reader = .fixed(input);
    try testing.expectError(error.UntrustedPeer, pp.read(&b, &buf, .{ .peer = v4(10, 1, 2, 3) }));
    var c: std.Io.Reader = .fixed(&tcp4_hdr);
    try testing.expectError(error.UntrustedPeer, pp.read(&c, &buf, .{ .peer = null, .trusted = &.{lb} }));
    // A malformed header from an untrusted peer is also just untrusted.
    var d: std.Io.Reader = .fixed("PROXY TCP4 garbage\r\n");
    try testing.expectError(error.UntrustedPeer, pp.read(&d, &buf, .{ .peer = v4(192, 0, 2, 1) }));
    // The same from a trusted peer is Malformed.
    var e: std.Io.Reader = .fixed("PROXY TCP4 garbage\r\n");
    try testing.expectError(error.Malformed, pp.read(&e, &buf, trusted_opts));
    // An untrusted peer sending HTTP is not an error.
    var f: std.Io.Reader = .fixed("GET / HTTP/1.1\r\n");
    try testing.expect((try pp.read(&f, &buf, .{ .peer = v4(192, 0, 2, 1) })) == null);
}

test "read: an untrusted peer's partial signature prefix is not an error" {
    var buf: [pp.default_max_v2_len]u8 = undefined;
    const other = v4(192, 0, 2, 1);
    // "PRO" then EOF: not Truncated, bytes stay.
    var a: std.Io.Reader = .fixed("PRO");
    try testing.expect((try pp.read(&a, &buf, .{ .peer = other, .trusted = &.{lb} })) == null);
    var abuf: [pp.default_max_v2_len]u8 = undefined;
    var a1 = testkit.fuzz.ChunkedReader.init("PRO", .{}, &abuf);
    try testing.expect((try pp.read(&a1.interface, &buf, .{ .peer = other, .trusted = &.{lb} })) == null);
    try testing.expectEqual(@as(usize, 3), a1.interface.bufferedLen());
    // The same prefix of the v2 signature.
    var a2: std.Io.Reader = .fixed(sig[0..5]);
    try testing.expect((try pp.read(&a2, &buf, .{ .peer = other })) == null);
    try testing.expectEqual(@as(usize, 5), a2.bufferedLen());
    // required still reports the missing header.
    var a3: std.Io.Reader = .fixed("PRO");
    try testing.expectError(error.Missing, pp.read(&a3, &buf, .{ .peer = other, .required = true }));
    // A reader buffer of 3 bytes: not TooLarge for an untrusted peer ...
    var rbuf: [3]u8 = undefined;
    var cr = testkit.fuzz.ChunkedReader.init("PROXY TCP4 1.1.1.1 2.2.2.2 1 2\r\n", .{}, &rbuf);
    try testing.expect((try pp.read(&cr.interface, &buf, .{ .peer = other })) == null);
    // ... but still TooLarge for a trusted one.
    var cr2 = testkit.fuzz.ChunkedReader.init("PROXY TCP4 1.1.1.1 2.2.2.2 1 2\r\n", .{}, &rbuf);
    try testing.expectError(error.TooLarge, pp.read(&cr2.interface, &buf, trusted_opts));
    // A trusted peer that stops inside the prefix stays Truncated.
    var big: [pp.default_max_v2_len]u8 = undefined;
    var t = testkit.fuzz.ChunkedReader.init("PRO", .{}, &big);
    try testing.expectError(error.Truncated, pp.read(&t.interface, &buf, trusted_opts));
    // A similar-looking protocol is not a header for anybody.
    var h1: std.Io.Reader = .fixed("PROPFIND / HTTP/1.1\r\n");
    try testing.expect((try pp.read(&h1, &buf, .{ .peer = other })) == null);
    var h2: std.Io.Reader = .fixed("PROPFIND / HTTP/1.1\r\n");
    try testing.expect((try pp.read(&h2, &buf, trusted_opts)) == null);
    try testing.expectEqual(@as(usize, 21), h2.bufferedLen());
}

test "read: an IPv4-mapped peer matches an IPv4 prefix" {
    var buf: [pp.default_max_v2_len]u8 = undefined;
    var r: std.Io.Reader = .fixed("PROXY UNKNOWN\r\n");
    const mapped: netaddr.Ip = .{ .v6 = hex.literal("00000000000000000000ffff0a010203") };
    const h = (try pp.read(&r, &buf, .{ .peer = mapped, .trusted = &.{lb} })).?;
    try testing.expectEqual(pp.Family.unspec, h.family);
}

test "read: delivered in one-byte chunks, and truncated" {
    var rbuf: [pp.default_max_v2_len]u8 = undefined;
    var buf: [pp.default_max_v2_len]u8 = undefined;
    var cr = testkit.fuzz.ChunkedReader.init(&(tcp6_hdr ++ "x".*), .{}, &rbuf);
    const h = (try pp.read(&cr.interface, &buf, trusted_opts)).?;
    try testing.expectEqual(pp.Family.tcp6, h.family);
    try testing.expectEqual(@as(u16, 443), h.destination.?.inet.port);
    var v1 = testkit.fuzz.ChunkedReader.init("PROXY TCP4 1.2.3.4 5.6.7.8 9 10\r\n", .{}, &rbuf);
    try testing.expectEqual(@as(u16, 10), (try pp.read(&v1.interface, &buf, trusted_opts)).?.destination.?.inet.port);
    // The stream ends inside the header.
    var t = testkit.fuzz.ChunkedReader.init(tcp4_hdr[0..20], .{}, &rbuf);
    try testing.expectError(error.Truncated, pp.read(&t.interface, &buf, trusted_opts));
    // The transport fails.
    var f = testkit.fuzz.ChunkedReader.init(&tcp4_hdr, .{ .fail_at = 5 }, &rbuf);
    try testing.expectError(error.ReadFailed, pp.read(&f.interface, &buf, trusted_opts));
}

test "read: buffers too small for the header" {
    var rbuf: [40]u8 = undefined;
    var buf: [16]u8 = undefined;
    var cr = testkit.fuzz.ChunkedReader.init(&tcp6_hdr, .{}, &rbuf);
    try testing.expectError(error.TooLarge, pp.read(&cr.interface, &buf, trusted_opts));
    var big: [pp.default_max_v2_len]u8 = undefined;
    var cr2 = testkit.fuzz.ChunkedReader.init(&tcp4_hdr, .{}, &big);
    try testing.expectError(error.TooLarge, pp.read(&cr2.interface, &buf, trusted_opts));
}

// ── writer ──────────────────────────────────────────────────────────────────

test "writeV1: exact text" {
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try pp.writeV1(&w, .{ .version = 1, .family = .tcp4, .source = inet(v4(192, 168, 0, 1), 56324), .destination = inet(v4(10, 0, 0, 2), 443) });
    try testing.expectEqualStrings("PROXY TCP4 192.168.0.1 10.0.0.2 56324 443\r\n", w.buffered());
    w = .fixed(&out);
    try pp.writeV1(&w, .{ .family = .tcp6, .source = inet(netaddr.Ip.ipv6_loopback, 1), .destination = inet(.{ .v6 = hex.literal("20010db8000000000000000000000002") }, 2) });
    try testing.expectEqualStrings("PROXY TCP6 ::1 2001:db8::2 1 2\r\n", w.buffered());
    w = .fixed(&out);
    try pp.writeV1(&w, .{});
    try testing.expectEqualStrings("PROXY UNKNOWN\r\n", w.buffered());
    w = .fixed(&out);
    try pp.writeV1(&w, .{ .command = .local, .family = .tcp4 });
    try testing.expectEqualStrings("PROXY UNKNOWN\r\n", w.buffered());
}

test "writeV1: refusals" {
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try testing.expectError(error.Unsupported, pp.writeV1(&w, .{ .family = .udp4 }));
    try testing.expectError(error.Unsupported, pp.writeV1(&w, .{ .family = .unix_stream }));
    try testing.expectError(error.InvalidHeader, pp.writeV1(&w, .{ .family = .tcp4 }));
    try testing.expectError(error.InvalidHeader, pp.writeV1(&w, .{ .family = .tcp4, .source = inet(netaddr.Ip.ipv6_loopback, 1), .destination = inet(v4(1, 2, 3, 4), 1) }));
    try testing.expectError(error.InvalidHeader, pp.writeV1(&w, .{ .family = .tcp6, .source = inet(v4(1, 2, 3, 4), 1), .destination = inet(netaddr.Ip.ipv6_loopback, 1) }));
}

test "writeV2: exact bytes" {
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try pp.writeV2(&w, .{ .family = .tcp4, .source = inet(v4(192, 168, 0, 1), 8080), .destination = inet(v4(10, 0, 0, 2), 80) }, "");
    try testing.expectEqualSlices(u8, &tcp4_hdr, w.buffered());
    w = .fixed(&out);
    try pp.writeV2(&w, .{ .family = .tcp6, .source = inet(netaddr.Ip.ipv6_loopback, 0x1234), .destination = inet(.{ .v6 = hex.literal("20010db8000000000000000000000002") }, 443) }, "");
    try testing.expectEqualSlices(u8, &tcp6_hdr, w.buffered());
    w = .fixed(&out);
    try pp.writeV2(&w, .{ .command = .local }, "");
    try testing.expectEqualSlices(u8, &(sig ++ hex.literal("20000000")), w.buffered());
}

test "writeV2: a unix path with an embedded NUL does not round-trip, so it is refused" {
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const h: pp.Header = .{ .family = .unix_stream, .source = .{ .unix = "ab\x00cd" }, .destination = .{ .unix = "x" } };
    try testing.expectError(error.InvalidHeader, pp.writeV2(&w, h, ""));
    const h2: pp.Header = .{ .family = .unix_stream, .source = .{ .unix = "x" }, .destination = .{ .unix = "\x00" } };
    try testing.expectError(error.InvalidHeader, pp.writeV2(&w, h2, ""));
    // A clean path still round-trips.
    const ok: pp.Header = .{ .family = .unix_stream, .source = .{ .unix = "/run/a" }, .destination = .{ .unix = "/run/b" } };
    try pp.writeV2(&w, ok, "");
    const p = try expectHeader(try pp.parse(w.buffered()));
    try testing.expectEqualStrings("/run/a", p.h.source.?.unix);
}

test "writeV2: refusals" {
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try testing.expectError(error.InvalidHeader, pp.writeV2(&w, .{ .family = .tcp4 }, ""));
    try testing.expectError(error.InvalidHeader, pp.writeV2(&w, .{ .family = .unix_stream, .source = .{ .unix = "a" }, .destination = inet(v4(1, 1, 1, 1), 1) }, ""));
    const long: [109]u8 = @splat('a');
    try testing.expectError(error.InvalidHeader, pp.writeV2(&w, .{ .family = .unix_dgram, .source = .{ .unix = &long }, .destination = .{ .unix = "b" } }, ""));
    try testing.expectError(error.InvalidHeader, pp.writeV2(&w, .{}, &hex.literal("0100")));
    try testing.expectError(error.InvalidHeader, pp.writeV2Crc(&w, .{}, &hex.literal("030004" ++ "00000000")));
    const huge: [70000]u8 = @splat(0);
    try testing.expectError(error.InvalidHeader, pp.writeV2(&w, .{}, &huge)); // not a TLV chain
    // A well-formed chain that is too long: 30 TLVs of 2400 bytes.
    var chain: [66000]u8 = @splat(0);
    var at: usize = 0;
    while (at + 3000 <= chain.len) : (at += 3000) {
        chain[at] = 0x04;
        std.mem.writeInt(u16, chain[at + 1 ..][0..2], 2997, .big);
    }
    try testing.expectError(error.TooLarge, pp.writeV2(&w, .{}, chain[0..at]));
}

test "round trip: every family, command and TLV area, with and without CRC" {
    const unix_a = "/tmp/a.sock";
    const heads = [_]pp.Header{
        .{ .family = .tcp4, .source = inet(v4(1, 2, 3, 4), 0), .destination = inet(v4(255, 255, 255, 255), 65535) },
        .{ .family = .udp4, .source = inet(v4(0, 0, 0, 0), 1), .destination = inet(v4(8, 8, 8, 8), 53) },
        .{ .family = .tcp6, .source = inet(netaddr.Ip.ipv6_loopback, 1), .destination = inet(.{ .v6 = @splat(0xab) }, 2) },
        .{ .family = .udp6, .source = inet(.{ .v6 = @splat(0) }, 5), .destination = inet(netaddr.Ip.ipv6_loopback, 6) },
        .{ .family = .unix_stream, .source = .{ .unix = unix_a }, .destination = .{ .unix = "" } },
        .{ .family = .unix_dgram, .source = .{ .unix = "x" }, .destination = .{ .unix = unix_a } },
        .{ .family = .unspec },
        .{ .command = .local },
    };
    const areas = [_][]const u8{ "", &hex.literal("010002" ++ "6832"), &hex.literal("050003" ++ "aabbcc" ++ "040000") };
    for (heads) |h| for (areas) |area| for ([_]bool{ false, true }) |crc| {
        var out: [400]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        if (crc) try pp.writeV2Crc(&w, h, area) else try pp.writeV2(&w, h, area);
        const bytes = w.buffered();
        const p = try expectHeader(try pp.parse(bytes));
        try testing.expectEqual(bytes.len, p.consumed);
        try testing.expectEqual(h.command, p.h.command);
        try testing.expectEqual(h.family, p.h.family);
        const has_addr = h.command == .proxy and h.family != .unspec;
        try testing.expectEqual(has_addr, p.h.source != null);
        if (has_addr) {
            try testing.expect(p.h.source.?.eql(h.source.?));
            try testing.expect(p.h.destination.?.eql(h.destination.?));
        }
        // LOCAL and UNSPEC discard the payload, TLVs included.
        if (has_addr) {
            const want = bytes.len - 16 - (switch (h.family) {
                .tcp4, .udp4 => @as(usize, 12),
                .tcp6, .udp6 => 36,
                else => 216,
            });
            try testing.expectEqual(want, p.h.tlvs.len);
            try testing.expectEqualSlices(u8, area, p.h.tlvs[0..area.len]);
            try testing.expectEqual(crc, (try p.h.crc32cValue()) != null);
        }
    };
}

test "round trip: v1" {
    const hs = [_]pp.Header{
        .{ .version = 1, .family = .tcp4, .source = inet(v4(1, 2, 3, 4), 0), .destination = inet(v4(255, 255, 255, 255), 65535) },
        .{ .version = 1, .family = .tcp6, .source = inet(.{ .v6 = @splat(0xab) }, 9), .destination = inet(netaddr.Ip.ipv6_loopback, 10) },
        .{ .version = 1, .family = .tcp6, .source = inet(.{ .v6 = hex.literal("00000000000000000000ffff01020304") }, 9), .destination = inet(.{ .v6 = @splat(0xff) }, 10) },
        .{ .version = 1 },
    };
    for (hs) |h| {
        var out: [128]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        try pp.writeV1(&w, h);
        const p = try expectHeader(try pp.parse(w.buffered()));
        try testing.expectEqual(w.buffered().len, p.consumed);
        try testing.expectEqual(h.family, p.h.family);
        if (h.source) |s| try testing.expect(s.eql(p.h.source.?)) else try testing.expect(p.h.source == null);
        if (h.destination) |d| try testing.expect(d.eql(p.h.destination.?));
    }
}

// ── no-panic sweep ──────────────────────────────────────────────────────────

test "no-panic sweep: every pub entry point on hostile bytes" {
    // Safety checks are on in the test build, so an overflow or an
    // out-of-bounds read in any of these is a failure.
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rnd = prng.random();
    var raw: [700]u8 = undefined;
    var rbuf: [pp.default_max_v2_len]u8 = undefined;
    var buf: [pp.default_max_v2_len]u8 = undefined;
    var sink: [256]u8 = undefined;
    for (0..20000) |i| {
        const n = rnd.uintLessThan(usize, raw.len + 1);
        rnd.bytes(raw[0..n]);
        // Bias half of the inputs toward the two prefixes.
        switch (i % 4) {
            0 => if (n >= 12) @memcpy(raw[0..12], &sig),
            1 => if (n >= 6) @memcpy(raw[0..6], "PROXY "),
            else => {},
        }
        if (i % 4 == 0 and n >= 16) raw[12] = 0x20 | (raw[12] & 1);
        if (i % 4 == 0 and n >= 16) std.mem.writeInt(u16, raw[14..16], @intCast(rnd.uintLessThan(usize, @min(n - 15, 600))), .big);
        const input = raw[0..n];
        _ = pp.parse(input) catch {};
        _ = pp.parseOpts(input, .{ .max_v2_len = rnd.uintLessThan(usize, 70000) }) catch {};
        _ = findHostile(input);
        _ = pp.Ssl.parse(input) catch {};
        var it: pp.TlvIterator = .{ .rest = input };
        while (it.next() catch null) |_| {}
        var r: std.Io.Reader = .fixed(input);
        _ = pp.read(&r, &buf, .{ .peer = v4(10, 0, 0, 1), .trusted = &.{lb} }) catch {};
        var cr = testkit.fuzz.ChunkedReader.init(input, .{ .chunks = .{ 3, 1, 7, 1, 1, 1, 1, 1 }, .n_chunks = 3 }, &rbuf);
        _ = pp.read(&cr.interface, &buf, .{ .peer = v4(10, 0, 0, 1), .trusted = &.{lb}, .required = i % 2 == 0 }) catch {};
        var w: std.Io.Writer = .fixed(&sink);
        _ = pp.writeV2(&w, .{ .family = .tcp4 }, input) catch {};
        w = .fixed(&sink);
        _ = pp.writeV2Crc(&w, .{ .command = .local }, input) catch {};
        w = .fixed(&sink);
        const fam: pp.Family = @fromBackingInt(@intCast(rnd.uintLessThan(u8, 7)));
        const h: pp.Header = .{ .family = fam, .source = if (rnd.boolean()) .{ .unix = input } else inet(v4(1, 1, 1, 1), 1), .destination = .{ .unix = input[0..@min(n, 109)] } };
        _ = pp.writeV2(&w, h, "") catch {};
        w = .fixed(&sink);
        _ = pp.writeV1(&w, h) catch {};
    }
}

fn findHostile(tlvs: []const u8) bool {
    const h: pp.Header = .{ .tlvs = tlvs };
    _ = h.alpn() catch return false;
    _ = h.authority() catch return false;
    _ = h.uniqueId() catch return false;
    _ = h.netns() catch return false;
    _ = h.crc32cValue() catch return false;
    _ = h.aws() catch return false;
    _ = h.azure() catch return false;
    _ = h.gcp() catch return false;
    const s = (h.ssl() catch return false) orelse return true;
    _ = s.version() catch return false;
    _ = s.cn() catch return false;
    _ = s.cipher() catch return false;
    _ = s.sigAlg() catch return false;
    _ = s.keyAlg() catch return false;
    return true;
}
