// SPDX-License-Identifier: MIT

//! tlsserver.messages — the handshake messages a TLS 1.3 server writes
//! (RFC 8446 §4): ServerHello, HelloRetryRequest, EncryptedExtensions,
//! CertificateRequest, Certificate, CertificateVerify, Finished, each with
//! its four-octet handshake header, into a caller's buffer.
//!
//! Every encoder returns the whole message (header ‖ body), the octets the
//! transcript hashes and the record layer frames. Nothing is chosen here:
//! the state machine passes the negotiated values in. Extension order in
//! the ServerHello is fixed — `pre_shared_key`, `key_share`, `cookie`,
//! `supported_versions` — the order RFC 8448's traces use.

const std = @import("std");

pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,
    _,
};

/// RFC 8446 §4.1.3: the `random` that marks a ServerHello as a
/// HelloRetryRequest (SHA-256 of "HelloRetryRequest").
pub const hello_retry_request_random = [32]u8{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

/// `supported_versions` value of TLS 1.3.
pub const tls13_version: u16 = 0x0304;

pub const Error = error{
    /// `out` cannot hold the message.
    BufferTooSmall,
    /// A field longer than its length prefix can say (a > 2^24 − 1
    /// certificate, a > 2^16 − 1 extension, a > 255 octet ALPN name …).
    FieldTooLong,
};

pub const Extension = struct {
    type: u16,
    data: []const u8,
};

/// A cursor writing big-endian fields and length-prefixed vectors.
const Writer = struct {
    out: []u8,
    n: usize = 0,

    fn bytes(w: *Writer, b: []const u8) Error!void {
        if (w.out.len - w.n < b.len) return error.BufferTooSmall;
        @memcpy(w.out[w.n..][0..b.len], b);
        w.n += b.len;
    }
    fn int(w: *Writer, comptime T: type, v: T) Error!void {
        var b: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
        std.mem.writeInt(T, &b, v, .big);
        try w.bytes(&b);
    }
    /// Reserve an `L` length prefix; `close` fills it in.
    fn open(w: *Writer, comptime L: type) Error!usize {
        try w.int(L, 0);
        return w.n;
    }
    fn close(w: *Writer, comptime L: type, at: usize) Error!void {
        const len = w.n - at;
        if (len > std.math.maxInt(L)) return error.FieldTooLong;
        const size = @divExact(@typeInfo(L).int.bits, 8);
        std.mem.writeInt(L, w.out[at - size ..][0..size], @intCast(len), .big);
    }
    fn vec(w: *Writer, comptime L: type, b: []const u8) Error!void {
        if (b.len > std.math.maxInt(L)) return error.FieldTooLong;
        try w.int(L, @intCast(b.len));
        try w.bytes(b);
    }
    fn extension(w: *Writer, e: Extension) Error!void {
        try w.int(u16, e.type);
        try w.vec(u16, e.data);
    }
    /// Start a handshake message: type and a u24 length to close.
    fn message(w: *Writer, t: HandshakeType) Error!usize {
        try w.int(u8, @backingInt(t));
        return w.open(u24);
    }
    fn done(w: *Writer, at: usize) Error![]u8 {
        try w.close(u24, at);
        return w.out[0..w.n];
    }
};

pub const KeyShare = struct {
    group: u16,
    key_exchange: []const u8,
};

pub const ServerHello = struct {
    random: *const [32]u8,
    /// The client's `legacy_session_id`, echoed (≤ 32 octets).
    legacy_session_id_echo: []const u8,
    cipher_suite: u16,
    /// The server's share (absent only for psk_ke, which this server does
    /// not do; kept optional for that mode's sake).
    key_share: ?KeyShare,
    /// The index of the client's PSK identity the server accepted.
    selected_identity: ?u16 = null,
};

/// RFC 8446 §4.1.3.
pub fn serverHello(out: []u8, sh: ServerHello) Error![]u8 {
    var w: Writer = .{ .out = out };
    const at = try w.message(.server_hello);
    try helloFixed(&w, sh.random, sh.legacy_session_id_echo, sh.cipher_suite);
    const exts = try w.open(u16);
    if (sh.selected_identity) |i| {
        try w.int(u16, 41);
        try w.int(u16, 2);
        try w.int(u16, i);
    }
    if (sh.key_share) |ks| {
        try w.int(u16, 51);
        const e = try w.open(u16);
        try w.int(u16, ks.group);
        try w.vec(u16, ks.key_exchange);
        try w.close(u16, e);
    }
    try supportedVersions(&w);
    try w.close(u16, exts);
    return w.done(at);
}

pub const HelloRetryRequest = struct {
    legacy_session_id_echo: []const u8,
    cipher_suite: u16,
    /// The group the client must offer a share for (absent when only the
    /// cookie is asked back).
    selected_group: ?u16,
    cookie: ?[]const u8 = null,
};

/// RFC 8446 §4.1.4: a ServerHello with `hello_retry_request_random`.
pub fn helloRetryRequest(out: []u8, hrr: HelloRetryRequest) Error![]u8 {
    var w: Writer = .{ .out = out };
    const at = try w.message(.server_hello);
    try helloFixed(&w, &hello_retry_request_random, hrr.legacy_session_id_echo, hrr.cipher_suite);
    const exts = try w.open(u16);
    if (hrr.selected_group) |g| {
        try w.int(u16, 51);
        try w.int(u16, 2);
        try w.int(u16, g);
    }
    if (hrr.cookie) |c| {
        try w.int(u16, 44);
        const e = try w.open(u16);
        if (c.len == 0) return error.FieldTooLong; // `opaque cookie<1..2^16-1>`
        try w.vec(u16, c);
        try w.close(u16, e);
    }
    try supportedVersions(&w);
    try w.close(u16, exts);
    return w.done(at);
}

fn helloFixed(w: *Writer, random: *const [32]u8, session_id: []const u8, suite: u16) Error!void {
    if (session_id.len > 32) return error.FieldTooLong;
    try w.int(u16, 0x0303);
    try w.bytes(random);
    try w.vec(u8, session_id);
    try w.int(u16, suite);
    try w.int(u8, 0); // legacy_compression_method
}

fn supportedVersions(w: *Writer) Error!void {
    try w.int(u16, 43);
    try w.int(u16, 2);
    try w.int(u16, tls13_version);
}

/// RFC 8446 §4.3.1: the extensions in the given order.
pub fn encryptedExtensions(out: []u8, exts: []const Extension) Error![]u8 {
    var w: Writer = .{ .out = out };
    const at = try w.message(.encrypted_extensions);
    const list = try w.open(u16);
    for (exts) |e| try w.extension(e);
    try w.close(u16, list);
    return w.done(at);
}

/// The ALPN extension body naming one protocol (RFC 7301 §3.1: the server's
/// list has exactly one name).
pub fn alpnData(out: []u8, protocol: []const u8) Error![]u8 {
    if (protocol.len == 0) return error.FieldTooLong; // `opaque ProtocolName<1..2^8-1>`
    var w: Writer = .{ .out = out };
    const list = try w.open(u16);
    try w.vec(u8, protocol);
    try w.close(u16, list);
    return out[0..w.n];
}

pub const CertificateEntry = struct {
    /// The DER certificate.
    cert_data: []const u8,
    /// A DER OCSPResponse, sent as this entry's `status_request` extension
    /// (RFC 8446 §4.4.2.1: a `CertificateStatus` of type ocsp), after
    /// `extensions`.
    ocsp_response: ?[]const u8 = null,
    extensions: []const Extension = &.{},
};

/// RFC 8446 §4.4.2: the chain, leaf first. A server's
/// `certificate_request_context` is empty.
pub fn certificate(out: []u8, context: []const u8, entries: []const CertificateEntry) Error![]u8 {
    var w: Writer = .{ .out = out };
    const at = try w.message(.certificate);
    try w.vec(u8, context);
    const list = try w.open(u24);
    for (entries) |e| {
        if (e.cert_data.len == 0 or e.cert_data.len > std.math.maxInt(u24)) return error.FieldTooLong;
        try w.int(u24, @intCast(e.cert_data.len));
        try w.bytes(e.cert_data);
        const exts = try w.open(u16);
        for (e.extensions) |x| try w.extension(x);
        if (e.ocsp_response) |o| {
            // `opaque OCSPResponse<1..2^24-1>`
            if (o.len == 0 or o.len > std.math.maxInt(u24)) return error.FieldTooLong;
            try w.int(u16, 5);
            const st = try w.open(u16);
            try w.int(u8, 1);
            try w.int(u24, @intCast(o.len));
            try w.bytes(o);
            try w.close(u16, st);
        }
        try w.close(u16, exts);
    }
    try w.close(u24, list);
    return w.done(at);
}

pub const CertificateRequest = struct {
    /// Empty during the handshake (RFC 8446 §4.3.2).
    context: []const u8 = "",
    /// The schemes the server accepts in the client's CertificateVerify
    /// and on its chain (`signature_algorithms`), non-empty.
    signature_algorithms: []const u16,
    /// DER DistinguishedNames of the CAs the server trusts
    /// (`certificate_authorities`, RFC 8446 §4.2.4); none: not sent.
    authorities: []const []const u8 = &.{},
};

/// RFC 8446 §4.3.2: `signature_algorithms`, then `certificate_authorities`
/// (RFC 8448 §6 sends the first alone).
pub fn certificateRequest(out: []u8, cr: CertificateRequest) Error![]u8 {
    if (cr.signature_algorithms.len == 0) return error.FieldTooLong; // `<2..2^16-2>`
    var w: Writer = .{ .out = out };
    const at = try w.message(.certificate_request);
    try w.vec(u8, cr.context);
    const exts = try w.open(u16);
    try w.int(u16, 13);
    const sa = try w.open(u16);
    const list = try w.open(u16);
    for (cr.signature_algorithms) |s| try w.int(u16, s);
    try w.close(u16, list);
    try w.close(u16, sa);
    if (cr.authorities.len != 0) {
        try w.int(u16, 47);
        const ca = try w.open(u16);
        const names = try w.open(u16);
        // `opaque DistinguishedName<1..2^16-1>`
        for (cr.authorities) |dn| {
            if (dn.len == 0) return error.FieldTooLong;
            try w.vec(u16, dn);
        }
        try w.close(u16, names);
        try w.close(u16, ca);
    }
    try w.close(u16, exts);
    return w.done(at);
}

/// RFC 8446 §4.4.3.
pub fn certificateVerify(out: []u8, scheme: u16, signature: []const u8) Error![]u8 {
    var w: Writer = .{ .out = out };
    const at = try w.message(.certificate_verify);
    try w.int(u16, scheme);
    try w.vec(u16, signature);
    return w.done(at);
}

/// RFC 8446 §4.4.4.
pub fn finished(out: []u8, verify_data: []const u8) Error![]u8 {
    var w: Writer = .{ .out = out };
    const at = try w.message(.finished);
    try w.bytes(verify_data);
    return w.done(at);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const kat = @import("message_kat_vectors.zig");
const hello = @import("hello.zig");

/// A field of an RFC message, to rebuild the message from its parts. In a
/// ServerHello with an empty session id the first extension starts at 44
/// (header 4, version 2, random 32, session id 1, suite 2, compression 1,
/// extensions length 2), so a key_share's key at 52 (+6 behind a
/// pre_shared_key).
fn slice(m: []const u8, from: usize, len: usize) []const u8 {
    return m[from..][0..len];
}

test "RFC 8448 §3 ServerHello, rebuilt from its fields" {
    const m = &kat.rfc8448_s3_server_hello;
    var out: [128]u8 = undefined;
    const got = try serverHello(&out, .{
        .random = m[6..38],
        .legacy_session_id_echo = "",
        .cipher_suite = 0x1301,
        .key_share = .{ .group = 0x001d, .key_exchange = slice(m, 52, 32) },
    });
    try testing.expectEqualSlices(u8, m, got);
}

test "RFC 8448 §4 ServerHello: pre_shared_key first" {
    const m = &kat.rfc8448_s4_server_hello;
    var out: [128]u8 = undefined;
    const got = try serverHello(&out, .{
        .random = m[6..38],
        .legacy_session_id_echo = "",
        .cipher_suite = 0x1301,
        .key_share = .{ .group = 0x001d, .key_exchange = slice(m, 58, 32) },
        .selected_identity = 0,
    });
    try testing.expectEqualSlices(u8, m, got);
}

test "RFC 8448 §5 HelloRetryRequest and ServerHello (secp256r1)" {
    const hrr = &kat.rfc8448_s5_hello_retry_request;
    // The cookie is the one ClientHello2 echoes back.
    const ch2 = try hello.parseClientHello(kat.rfc8448_s5_ch2[4..]);
    var out: [256]u8 = undefined;
    const got = try helloRetryRequest(&out, .{
        .legacy_session_id_echo = "",
        .cipher_suite = 0x1301,
        .selected_group = 0x0017,
        .cookie = ch2.cookie.?,
    });
    try testing.expectEqualSlices(u8, hrr, got);

    const sh = &kat.rfc8448_s5_server_hello;
    const got2 = try serverHello(&out, .{
        .random = sh[6..38],
        .legacy_session_id_echo = "",
        .cipher_suite = 0x1301,
        .key_share = .{ .group = 0x0017, .key_exchange = slice(sh, 52, 65) },
    });
    try testing.expectEqualSlices(u8, sh, got2);
}

test "RFC 8448 EncryptedExtensions (§3, §4 with early_data, §5)" {
    var out: [64]u8 = undefined;
    const groups3 = [_]u8{ 0, 0x12, 0, 0x1d, 0, 0x17, 0, 0x18, 0, 0x19, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4 };
    const rsl = [_]u8{ 0x40, 0x01 };
    try testing.expectEqualSlices(u8, &kat.rfc8448_s3_encrypted_extensions, try encryptedExtensions(&out, &.{
        .{ .type = 10, .data = &groups3 },
        .{ .type = 28, .data = &rsl },
        .{ .type = 0, .data = "" },
    }));
    try testing.expectEqualSlices(u8, &kat.rfc8448_s4_encrypted_extensions, try encryptedExtensions(&out, &.{
        .{ .type = 10, .data = &groups3 },
        .{ .type = 28, .data = &rsl },
        .{ .type = 0, .data = "" },
        .{ .type = 42, .data = "" },
    }));
    try testing.expectEqualSlices(u8, &kat.rfc8448_s5_encrypted_extensions, try encryptedExtensions(&out, &.{
        .{ .type = 10, .data = &.{ 0, 6, 0, 0x17, 0, 0x18, 0, 0x1d } },
        .{ .type = 28, .data = &rsl },
        .{ .type = 0, .data = "" },
    }));
}

test "RFC 8448 §3 Certificate, CertificateVerify, Finished" {
    const c = &kat.rfc8448_s3_certificate;
    // 0b | len3 | ctx 00 | list len3 | cert len3 (0x1b0) | DER | ext len 0000
    const der = slice(c, 11, 0x1b0);
    var out: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, c, try certificate(&out, "", &.{.{ .cert_data = der }}));

    const cv = &kat.rfc8448_s3_certificate_verify;
    try testing.expectEqualSlices(u8, cv, try certificateVerify(&out, 0x0804, cv[8..]));

    const f = &kat.rfc8448_s3_server_finished;
    try testing.expectEqualSlices(u8, f, try finished(&out, f[4..]));
}

test "RFC 8448 §6 CertificateRequest; certificate_authorities" {
    const cr = &kat.rfc8448_s6_certificate_request;
    var out: [128]u8 = undefined;
    // 0d | len3 | ctx 00 | exts len2 | 000d | len2 | list len2 (0x1e) | schemes
    var schemes: [15]u16 = undefined;
    for (&schemes, 0..) |*s, i| s.* = std.mem.readInt(u16, cr[13 + 2 * i ..][0..2], .big);
    try testing.expectEqualSlices(u8, cr, try certificateRequest(&out, .{ .signature_algorithms = &schemes }));

    const m = try certificateRequest(&out, .{ .signature_algorithms = &.{0x0403}, .authorities = &.{ "AB", "C" } });
    const sa = "\x00\x0d\x00\x04\x00\x02\x04\x03";
    const ca = "\x00\x2f\x00\x09\x00\x07" ++ "\x00\x02AB" ++ "\x00\x01C";
    try testing.expectEqualSlices(u8, "\x0d\x00\x00\x18" ++ "\x00" ++ "\x00\x15" ++ sa ++ ca, m);
    try testing.expectError(error.FieldTooLong, certificateRequest(&out, .{ .signature_algorithms = &.{} }));
    try testing.expectError(error.FieldTooLong, certificateRequest(&out, .{ .signature_algorithms = &.{0x0403}, .authorities = &.{""} }));
}

test "ALPN extension body; a chain with an OCSP staple on the leaf" {
    var a: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0, 3, 2, 'h', '2' }, try alpnData(&a, "h2"));
    try testing.expectError(error.FieldTooLong, alpnData(&a, ""));
    var long: [256]u8 = @splat('x');
    var b: [300]u8 = undefined;
    try testing.expectError(error.FieldTooLong, alpnData(&b, &long));

    var out: [128]u8 = undefined;
    const m = try certificate(&out, "", &.{
        .{ .cert_data = "LEAF", .ocsp_response = &.{ 0x30, 0x03, 0x0a, 0x01, 0x00 } },
        .{ .cert_data = "CA" },
    });
    const leaf = "\x00\x00\x04LEAF" ++ "\x00\x0d" ++ "\x00\x05\x00\x09" ++ "\x01\x00\x00\x05\x30\x03\x0a\x01\x00";
    const ca = "\x00\x00\x02CA" ++ "\x00\x00";
    // header (body 33) ‖ empty context ‖ list length 29 ‖ entries
    try testing.expectEqualSlices(u8, "\x0b\x00\x00\x21" ++ "\x00" ++ "\x00\x00\x1d" ++ leaf ++ ca, m);
}

test "buffer too small, fields too long" {
    var out: [8]u8 = undefined;
    const r: [32]u8 = @splat(1);
    try testing.expectError(error.BufferTooSmall, serverHello(&out, .{ .random = &r, .legacy_session_id_echo = "", .cipher_suite = 0x1301, .key_share = null }));
    var big: [128]u8 = undefined;
    try testing.expectError(error.FieldTooLong, serverHello(&big, .{ .random = &r, .legacy_session_id_echo = &@as([33]u8, @splat(0)), .cipher_suite = 0x1301, .key_share = null }));
    try testing.expectError(error.FieldTooLong, helloRetryRequest(&big, .{ .legacy_session_id_echo = "", .cipher_suite = 0x1301, .selected_group = null, .cookie = "" }));
    try testing.expectError(error.FieldTooLong, certificate(&big, "", &.{.{ .cert_data = "" }}));
    try testing.expectError(error.FieldTooLong, certificate(&big, "", &.{.{ .cert_data = "x", .ocsp_response = "" }}));
    // Every prefix of the output buffer short of the message is refused.
    var full: [128]u8 = undefined;
    const m = try serverHello(&full, .{ .random = &r, .legacy_session_id_echo = "abc", .cipher_suite = 0x1302, .key_share = .{ .group = 0x1d, .key_exchange = &r }, .selected_identity = 3 });
    for (0..m.len) |n| try testing.expectError(error.BufferTooSmall, serverHello(big[0..n], .{ .random = &r, .legacy_session_id_echo = "abc", .cipher_suite = 0x1302, .key_share = .{ .group = 0x1d, .key_exchange = &r }, .selected_identity = 3 }));
}
