// SPDX-License-Identifier: MIT

//! dtls.messages12 — DTLS 1.2 handshake message BODIES (RFC 6347 §4.2,
//! RFC 5246 §7.4, RFC 8422 §5, RFC 4279 §2/§3, RFC 5489 §2). The 12-byte
//! DTLS handshake header is `handshake.zig`'s and is the same in both
//! versions. Every decoder is bounds-checked and consumes its input exactly:
//! trailing bytes, short fields and impossible lengths are
//! `error.Malformed`, never a panic.
//!
//! The extension-list codec is `messages.zig`'s (`encodeExtensions` /
//! `decodeExtensions`, duplicate types rejected); the one difference in 1.2
//! is that a Hello's extension block may be ABSENT altogether (RFC 5246
//! §7.4.1.2: "the presence of extensions can be detected by determining
//! whether there are bytes following the compression_methods").

const std = @import("std");
const messages = @import("messages.zig");

pub const Error = messages.MessageError;
pub const Extension = messages.Extension;

pub const HandshakeType = struct {
    pub const client_hello: u8 = 1;
    pub const server_hello: u8 = 2;
    /// RFC 6347 §4.2.1.
    pub const hello_verify_request: u8 = 3;
    pub const certificate: u8 = 11;
    pub const server_key_exchange: u8 = 12;
    pub const certificate_request: u8 = 13;
    pub const server_hello_done: u8 = 14;
    pub const certificate_verify: u8 = 15;
    pub const client_key_exchange: u8 = 16;
    pub const finished: u8 = 20;
};

pub const ext_supported_groups: u16 = 10;
/// RFC 8422 §5.1.2.
pub const ext_ec_point_formats: u16 = 11;
pub const ext_signature_algorithms: u16 = 13;
pub const ext_alpn: u16 = 16;
/// RFC 7627 §5.1.
pub const ext_extended_master_secret: u16 = 23;
pub const ext_supported_versions: u16 = 43;
/// RFC 5746 §3.2.
pub const ext_renegotiation_info: u16 = 0xff01;
/// RFC 5746 §3.3: TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
pub const empty_renegotiation_info_scsv: u16 = 0x00ff;

pub const version_dtls12 = [2]u8{ 0xfe, 0xfd };
/// RFC 6347 §4.2.1: a HelloVerifyRequest SHOULD carry DTLS 1.0 ({254,255})
/// "regardless of the version of TLS that is expected to be negotiated".
pub const version_dtls10 = [2]u8{ 0xfe, 0xff };

/// RFC 8446 §4.1.3's downgrade sentinel, DTLS form: a server able to speak
/// (D)TLS 1.3 that negotiates 1.2 puts these in the last 8 bytes of
/// `ServerHello.random`; a 1.3-capable client that sees them refuses.
pub const downgrade_sentinel_12 = [8]u8{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };

/// RFC 8422 §5.4 `ECCurveType.named_curve`.
pub const curve_type_named: u8 = 3;

/// RFC 6347 §4.2.1: `opaque cookie<0..2^8-1>`.
pub const max_cookie_len = 255;

fn optionalExtensions(buf: []const u8, out: []Extension) Error![]Extension {
    if (buf.len == 0) return out[0..0];
    const exts = messages.decodeExtensions(buf, out) catch |e| return switch (e) {
        error.BufferTooShort => error.Malformed,
        else => e,
    };
    const used = 2 + @as(usize, std.mem.readInt(u16, buf[0..2], .big));
    if (used != buf.len) return error.Malformed;
    return exts;
}

pub fn findExtension(exts: []const Extension, ext_type: u16) ?[]const u8 {
    for (exts) |e| if (e.ext_type == ext_type) return e.data;
    return null;
}

// ── ClientHello (RFC 6347 §4.2.1) ───────────────────────────────────────

pub const ClientHello = struct {
    random: [32]u8,
    session_id: []const u8 = &.{},
    cookie: []const u8 = &.{},
    cipher_suites: []const u16,
    extensions: []const Extension,
};

pub fn encodeClientHello(ch: ClientHello, out: []u8) Error![]u8 {
    if (ch.session_id.len > 32 or ch.cookie.len > max_cookie_len) return error.Malformed;
    const cs_len = ch.cipher_suites.len * 2;
    if (cs_len == 0 or cs_len > 0xfffe) return error.ListTooLong;
    const need = 2 + 32 + 1 + ch.session_id.len + 1 + ch.cookie.len + 2 + cs_len + 2;
    if (out.len < need) return error.BufferTooShort;
    var i: usize = 0;
    out[0..2].* = version_dtls12;
    @memcpy(out[2..34], &ch.random);
    i = 34;
    out[i] = @intCast(ch.session_id.len);
    @memcpy(out[i + 1 ..][0..ch.session_id.len], ch.session_id);
    i += 1 + ch.session_id.len;
    out[i] = @intCast(ch.cookie.len);
    @memcpy(out[i + 1 ..][0..ch.cookie.len], ch.cookie);
    i += 1 + ch.cookie.len;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(cs_len), .big);
    i += 2;
    for (ch.cipher_suites) |cs| {
        std.mem.writeInt(u16, out[i..][0..2], cs, .big);
        i += 2;
    }
    out[i] = 1; // compression_methods: just "null" (RFC 5246 §7.4.1.2)
    out[i + 1] = 0;
    i += 2;
    const ext = try messages.encodeExtensions(ch.extensions, out[i..]);
    return out[0 .. i + ext.len];
}

pub const DecodedClientHello = struct {
    version: [2]u8,
    random: [32]u8,
    session_id: []const u8,
    cookie: []const u8,
    /// Byte offset of the cookie length byte in the body, so a client can
    /// splice a HelloVerifyRequest cookie into a hello it already built.
    cookie_offset: usize,
    cipher_suites_raw: []const u8,
    compression_methods: []const u8,
    extensions: []Extension,
};

pub fn decodeClientHello(buf: []const u8, ext_out: []Extension) Error!DecodedClientHello {
    if (buf.len < 35) return error.Malformed;
    var i: usize = 34;
    const sid_len = buf[i];
    if (sid_len > 32 or buf.len < i + 1 + sid_len + 1) return error.Malformed;
    const sid = buf[i + 1 ..][0..sid_len];
    i += 1 + sid_len;
    const cookie_offset = i;
    const ck_len = buf[i];
    if (buf.len < i + 1 + ck_len + 2) return error.Malformed;
    const cookie = buf[i + 1 ..][0..ck_len];
    i += 1 + ck_len;
    const cs_len: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
    if (cs_len == 0 or cs_len % 2 != 0 or buf.len < i + 2 + cs_len + 1) return error.Malformed;
    const cs = buf[i + 2 ..][0..cs_len];
    i += 2 + cs_len;
    const comp_len = buf[i];
    if (comp_len == 0 or buf.len < i + 1 + comp_len) return error.Malformed;
    const comp = buf[i + 1 ..][0..comp_len];
    i += 1 + comp_len;
    return .{
        .version = buf[0..2].*,
        .random = buf[2..34].*,
        .session_id = sid,
        .cookie = cookie,
        .cookie_offset = cookie_offset,
        .cipher_suites_raw = cs,
        .compression_methods = comp,
        .extensions = try optionalExtensions(buf[i..], ext_out),
    };
}

pub fn offersSuite(cipher_suites_raw: []const u8, suite: u16) bool {
    var i: usize = 0;
    while (i + 2 <= cipher_suites_raw.len) : (i += 2) {
        if (std.mem.readInt(u16, cipher_suites_raw[i..][0..2], .big) == suite) return true;
    }
    return false;
}

// ── HelloVerifyRequest (RFC 6347 §4.2.1) ────────────────────────────────

pub fn encodeHelloVerifyRequest(cookie: []const u8, out: []u8) Error![]u8 {
    if (cookie.len > max_cookie_len) return error.Malformed;
    if (out.len < 3 + cookie.len) return error.BufferTooShort;
    out[0..2].* = version_dtls10;
    out[2] = @intCast(cookie.len);
    @memcpy(out[3..][0..cookie.len], cookie);
    return out[0 .. 3 + cookie.len];
}

pub const HelloVerifyRequest = struct { version: [2]u8, cookie: []const u8 };

pub fn decodeHelloVerifyRequest(buf: []const u8) Error!HelloVerifyRequest {
    if (buf.len < 3 or buf.len != 3 + @as(usize, buf[2])) return error.Malformed;
    return .{ .version = buf[0..2].*, .cookie = buf[3..] };
}

// ── ServerHello (RFC 5246 §7.4.1.3) ─────────────────────────────────────

pub const ServerHello = struct {
    random: [32]u8,
    session_id: []const u8 = &.{},
    cipher_suite: u16,
    extensions: []const Extension,
};

pub fn encodeServerHello(sh: ServerHello, out: []u8) Error![]u8 {
    if (sh.session_id.len > 32) return error.Malformed;
    const head = 2 + 32 + 1 + sh.session_id.len + 3;
    if (out.len < head) return error.BufferTooShort;
    out[0..2].* = version_dtls12;
    @memcpy(out[2..34], &sh.random);
    out[34] = @intCast(sh.session_id.len);
    @memcpy(out[35..][0..sh.session_id.len], sh.session_id);
    var i = 35 + sh.session_id.len;
    std.mem.writeInt(u16, out[i..][0..2], sh.cipher_suite, .big);
    out[i + 2] = 0;
    i += 3;
    if (sh.extensions.len == 0) return out[0..i];
    const ext = try messages.encodeExtensions(sh.extensions, out[i..]);
    return out[0 .. i + ext.len];
}

pub const DecodedServerHello = struct {
    version: [2]u8,
    random: [32]u8,
    session_id: []const u8,
    cipher_suite: u16,
    compression_method: u8,
    extensions: []Extension,
};

pub fn decodeServerHello(buf: []const u8, ext_out: []Extension) Error!DecodedServerHello {
    if (buf.len < 35) return error.Malformed;
    const sid_len = buf[34];
    if (sid_len > 32 or buf.len < 35 + @as(usize, sid_len) + 3) return error.Malformed;
    const i = 35 + @as(usize, sid_len);
    return .{
        .version = buf[0..2].*,
        .random = buf[2..34].*,
        .session_id = buf[35..][0..sid_len],
        .cipher_suite = std.mem.readInt(u16, buf[i..][0..2], .big),
        .compression_method = buf[i + 2],
        .extensions = try optionalExtensions(buf[i + 3 ..], ext_out),
    };
}

// ── Certificate (RFC 5246 §7.4.2) ───────────────────────────────────────

pub fn encodeCertificate(chain: []const []const u8, out: []u8) Error![]u8 {
    var total: usize = 0;
    for (chain) |c| {
        if (c.len == 0 or c.len > 0xffffff) return error.Malformed;
        total += 3 + c.len;
    }
    if (total > 0xffffff) return error.ListTooLong;
    if (out.len < 3 + total) return error.BufferTooShort;
    std.mem.writeInt(u24, out[0..3], @intCast(total), .big);
    var i: usize = 3;
    for (chain) |c| {
        std.mem.writeInt(u24, out[i..][0..3], @intCast(c.len), .big);
        @memcpy(out[i + 3 ..][0..c.len], c);
        i += 3 + c.len;
    }
    return out[0..i];
}

/// Validates the whole `certificate_list` framing and returns the leaf (or
/// null for an empty list — a client's "no certificate", RFC 5246 §7.4.6).
pub fn decodeCertificateLeaf(buf: []const u8) Error!?[]const u8 {
    if (buf.len < 3) return error.Malformed;
    const total: usize = std.mem.readInt(u24, buf[0..3], .big);
    if (total != buf.len - 3) return error.Malformed;
    var i: usize = 3;
    var leaf: ?[]const u8 = null;
    while (i < buf.len) {
        if (buf.len - i < 3) return error.Malformed;
        const n: usize = std.mem.readInt(u24, buf[i..][0..3], .big);
        if (n == 0 or n > buf.len - i - 3) return error.Malformed;
        if (leaf == null) leaf = buf[i + 3 ..][0..n];
        i += 3 + n;
    }
    return leaf;
}

// ── ServerKeyExchange / ClientKeyExchange (RFC 8422 §5.4/§5.7, RFC 4279
// §2, RFC 5489 §2) ───────────────────────────────────────────────────────

/// `ServerECDHParams`: `curve_type(1)=named_curve || namedcurve(2) ||
/// opaque point<1..2^8-1>`.
pub fn encodeEcdhParams(group: u16, point: []const u8, out: []u8) Error![]u8 {
    if (point.len == 0 or point.len > 255) return error.Malformed;
    if (out.len < 4 + point.len) return error.BufferTooShort;
    out[0] = curve_type_named;
    std.mem.writeInt(u16, out[1..3], group, .big);
    out[3] = @intCast(point.len);
    @memcpy(out[4..][0..point.len], point);
    return out[0 .. 4 + point.len];
}

pub const EcdhParams = struct {
    group: u16,
    point: []const u8,
    /// The encoded params (what the RFC 8422 §5.4 signature covers).
    raw: []const u8,
};

/// Decodes a `ServerECDHParams` at the front of `buf`; `rest` is what
/// follows it.
pub fn decodeEcdhParams(buf: []const u8) Error!struct { params: EcdhParams, rest: []const u8 } {
    if (buf.len < 4 or buf[0] != curve_type_named) return error.Malformed;
    const n: usize = buf[3];
    if (n == 0 or buf.len < 4 + n) return error.Malformed;
    return .{
        .params = .{ .group = std.mem.readInt(u16, buf[1..3], .big), .point = buf[4..][0..n], .raw = buf[0 .. 4 + n] },
        .rest = buf[4 + n ..],
    };
}

/// `opaque psk_identity_hint<0..2^16-1>` / `psk_identity<0..2^16-1>`.
pub fn encodeOpaque16(data: []const u8, out: []u8) Error![]u8 {
    if (data.len > 0xffff) return error.ListTooLong;
    if (out.len < 2 + data.len) return error.BufferTooShort;
    std.mem.writeInt(u16, out[0..2], @intCast(data.len), .big);
    @memcpy(out[2..][0..data.len], data);
    return out[0 .. 2 + data.len];
}

pub fn decodeOpaque16(buf: []const u8) Error!struct { data: []const u8, rest: []const u8 } {
    if (buf.len < 2) return error.Malformed;
    const n: usize = std.mem.readInt(u16, buf[0..2], .big);
    if (buf.len < 2 + n) return error.Malformed;
    return .{ .data = buf[2..][0..n], .rest = buf[2 + n ..] };
}

/// `opaque point<1..2^8-1>` (ClientECDiffieHellmanPublic, RFC 8422 §5.7).
pub fn encodePoint(point: []const u8, out: []u8) Error![]u8 {
    if (point.len == 0 or point.len > 255) return error.Malformed;
    if (out.len < 1 + point.len) return error.BufferTooShort;
    out[0] = @intCast(point.len);
    @memcpy(out[1..][0..point.len], point);
    return out[0 .. 1 + point.len];
}

pub fn decodePoint(buf: []const u8) Error![]const u8 {
    if (buf.len < 2 or buf.len != 1 + @as(usize, buf[0])) return error.Malformed;
    return buf[1..];
}

/// `digitally-signed` (RFC 5246 §4.7): `SignatureAndHashAlgorithm(2) ||
/// opaque signature<0..2^16-1>`, consuming `buf` exactly.
pub fn encodeSigned(scheme: u16, signature: []const u8, out: []u8) Error![]u8 {
    if (signature.len > 0xffff) return error.ListTooLong;
    if (out.len < 4 + signature.len) return error.BufferTooShort;
    std.mem.writeInt(u16, out[0..2], scheme, .big);
    std.mem.writeInt(u16, out[2..4], @intCast(signature.len), .big);
    @memcpy(out[4..][0..signature.len], signature);
    return out[0 .. 4 + signature.len];
}

pub const Signed = struct { scheme: u16, signature: []const u8 };

pub fn decodeSigned(buf: []const u8) Error!Signed {
    if (buf.len < 4) return error.Malformed;
    const n: usize = std.mem.readInt(u16, buf[2..4], .big);
    if (n == 0 or buf.len != 4 + n) return error.Malformed;
    return .{ .scheme = std.mem.readInt(u16, buf[0..2], .big), .signature = buf[4..] };
}

// ── CertificateRequest (RFC 5246 §7.4.4) ────────────────────────────────

/// RFC 5246 §7.4.4 `ClientCertificateType`: rsa_sign(1), ecdsa_sign(64)
/// (RFC 8422 §5.5).
pub const cert_type_rsa_sign: u8 = 1;
pub const cert_type_ecdsa_sign: u8 = 64;

pub fn encodeCertificateRequest(schemes: []const u16, out: []u8) Error![]u8 {
    const sl = schemes.len * 2;
    if (sl == 0 or sl > 0xfffe) return error.ListTooLong;
    if (out.len < 3 + 2 + sl + 2) return error.BufferTooShort;
    out[0] = 2;
    out[1] = cert_type_ecdsa_sign;
    out[2] = cert_type_rsa_sign;
    std.mem.writeInt(u16, out[3..5], @intCast(sl), .big);
    var i: usize = 5;
    for (schemes) |s| {
        std.mem.writeInt(u16, out[i..][0..2], s, .big);
        i += 2;
    }
    std.mem.writeInt(u16, out[i..][0..2], 0, .big); // no certificate_authorities
    return out[0 .. i + 2];
}

pub const CertificateRequest = struct { cert_types: []const u8, schemes_raw: []const u8 };

pub fn decodeCertificateRequest(buf: []const u8) Error!CertificateRequest {
    if (buf.len < 1) return error.Malformed;
    const nt: usize = buf[0];
    if (nt == 0 or buf.len < 1 + nt + 2) return error.Malformed;
    var i = 1 + nt;
    const sl: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
    if (sl == 0 or sl % 2 != 0 or buf.len < i + 2 + sl + 2) return error.Malformed;
    const schemes = buf[i + 2 ..][0..sl];
    i += 2 + sl;
    const cal: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
    if (buf.len != i + 2 + cal) return error.Malformed;
    return .{ .cert_types = buf[1..][0..nt], .schemes_raw = schemes };
}

/// RFC 8422 §5.1.2: `ECPointFormatList` holding only `uncompressed` (0).
pub const ec_point_formats_uncompressed = [_]u8{ 1, 0 };

/// RFC 5746 §3.2: the `renegotiation_info` body of an INITIAL handshake —
/// an empty `renegotiated_connection<0..255>`.
pub const renegotiation_info_initial = [_]u8{0};

/// RFC 8422 §5.1.2: a peer that sends `ec_point_formats` MUST include
/// `uncompressed`.
pub fn pointFormatsIncludeUncompressed(data: []const u8) bool {
    if (data.len < 2 or data.len != 1 + @as(usize, data[0])) return false;
    return std.mem.indexOfScalar(u8, data[1..], 0) != null;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "messages12: ClientHello with cookie round-trips; cookie offset points at the cookie length byte" {
    var buf: [256]u8 = undefined;
    const ems = [_]Extension{.{ .ext_type = ext_extended_master_secret, .data = &.{} }};
    const body = try encodeClientHello(.{ .random = @splat(7), .cookie = "cookie!", .cipher_suites = &.{ 0xc02b, 0x00ff }, .extensions = &ems }, &buf);
    var ext: [8]Extension = undefined;
    const d = try decodeClientHello(body, &ext);
    try testing.expectEqualStrings("cookie!", d.cookie);
    try testing.expectEqual(@as(u8, 7), body[d.cookie_offset]);
    try testing.expect(offersSuite(d.cipher_suites_raw, 0x00ff));
    try testing.expectEqual(@as(usize, 1), d.extensions.len);
    // Absent extension block is legal in 1.2 (RFC 5246 §7.4.1.2).
    const no_ext = body[0 .. body.len - 6];
    const d2 = try decodeClientHello(no_ext, &ext);
    try testing.expectEqual(@as(usize, 0), d2.extensions.len);
    // Every truncation is a typed error.
    for (0..body.len) |n| {
        if (n == no_ext.len) continue;
        _ = decodeClientHello(body[0..n], &ext) catch continue;
        return error.TestUnexpectedResult;
    }
}

test "messages12: HelloVerifyRequest (RFC 6347 §4.2.1) uses DTLS 1.0 and is exact-length" {
    var buf: [64]u8 = undefined;
    const hvr = try encodeHelloVerifyRequest("abc", &buf);
    try testing.expectEqualSlices(u8, &.{ 0xfe, 0xff, 3, 'a', 'b', 'c' }, hvr);
    try testing.expectEqualStrings("abc", (try decodeHelloVerifyRequest(hvr)).cookie);
    try testing.expectError(error.Malformed, decodeHelloVerifyRequest(hvr[0..5]));
}

test "messages12: Certificate, ServerECDHParams, digitally-signed, CertificateRequest round trips and rejections" {
    var buf: [256]u8 = undefined;
    const cert = try encodeCertificate(&.{ "leaf", "ca" }, &buf);
    try testing.expectEqualStrings("leaf", (try decodeCertificateLeaf(cert)).?);
    try testing.expectEqual(@as(?[]const u8, null), try decodeCertificateLeaf(&.{ 0, 0, 0 }));
    try testing.expectError(error.Malformed, decodeCertificateLeaf(cert[0 .. cert.len - 1]));

    const p = try encodeEcdhParams(0x1d, &@as([32]u8, @splat(9)), &buf);
    const dp = try decodeEcdhParams(p);
    try testing.expectEqual(@as(u16, 0x1d), dp.params.group);
    try testing.expectEqual(@as(usize, 0), dp.rest.len);

    const s = try encodeSigned(0x0403, "sig", &buf);
    try testing.expectEqual(@as(u16, 0x0403), (try decodeSigned(s)).scheme);
    try testing.expectError(error.Malformed, decodeSigned(s[0 .. s.len - 1]));

    const cr = try encodeCertificateRequest(&.{ 0x0403, 0x0804 }, &buf);
    const dcr = try decodeCertificateRequest(cr);
    try testing.expectEqual(@as(usize, 4), dcr.schemes_raw.len);
    try testing.expectError(error.Malformed, decodeCertificateRequest(cr[0 .. cr.len - 1]));
}
