// SPDX-License-Identifier: MIT

//! tlsserver.clientauth — client certificates (RFC 8446 §4.3.2, §4.4.2,
//! §4.4.3): the client's Certificate and CertificateVerify decoded, the
//! leaf's public key read, and the verifier the server hands the chain to.
//!
//! Decoding is zero-copy and allocation-free, like `hello`: a Certificate
//! is checked whole when it is decoded, then walked with an iterator that
//! cannot fail. Strictness follows rustls 0.23 (`CertificatePayloadTls13`,
//! `ExpectCertificate`): a malformed message is `decode_error`; a
//! certificate entry carrying any extension is `unsupported_extension`
//! (the server's CertificateRequest asks for none, RFC 8446 §4.4.2: the
//! client's extensions must answer the request's); a
//! `certificate_request_context` other than the empty one the server sent
//! is `illegal_parameter`.
//!
//! The chain's trust is the `ClientCertVerifier`'s: the server gives it the
//! DER chain, leaf first, and the time. `X509Verifier` is the one built in:
//! RFC 5280 path validation to the caller's trust anchors with the
//! `clientAuth` extended key usage (`x509.verifyChain`), as rustls
//! `WebPkiClientVerifier`.

const std = @import("std");
const x509 = @import("x509");
const rsa = @import("rsa");
const certverify = @import("tls13").certverify;
const p521 = @import("p521");

pub const Error = error{
    /// A malformed message (`decode_error`).
    DecodeError,
    /// A `certificate_request_context` the server did not send
    /// (`illegal_parameter`).
    IllegalParameter,
    /// A certificate entry with an extension (`unsupported_extension`).
    UnsupportedExtension,
};

/// Why a client chain is refused, one alert each (RFC 8446 §6.2; the
/// mapping of rustls `send_cert_verify_error_alert`).
pub const VerifyError = error{
    /// Malformed, or not for this use (`bad_certificate`).
    BadCertificate,
    /// A key or algorithm this server cannot use, or a certificate not
    /// meant for client authentication (`unsupported_certificate`).
    UnsupportedCertificate,
    /// `certificate_revoked`.
    CertificateRevoked,
    /// Outside its validity period (`certificate_expired`).
    CertificateExpired,
    /// No path to a trust anchor (`unknown_ca`).
    UnknownCa,
    /// Valid, but refused by the application (`access_denied`).
    AccessDenied,
    /// Anything else (`certificate_unknown`).
    CertificateUnknown,
};

/// The most certificates a client chain may have (rustls has no count
/// cap, only the message size; BoringSSL none either). A longer chain is
/// `bad_certificate`.
pub const max_chain_len = 16;

/// The longest client leaf the server keeps (for `Server.peerCertificate`
/// and the session tickets); a longer leaf is `bad_certificate`.
pub const max_leaf_len = 4096;

/// Checks a client's chain. `chain` is DER, leaf first, never empty, valid
/// only during the call; `now_s` is the `ClientAuth.clock`'s time in
/// seconds since the Unix epoch.
pub const ClientCertVerifier = struct {
    ctx: ?*const anyopaque = null,
    verify: *const fn (ctx: ?*const anyopaque, chain: []const []const u8, now_s: i64) VerifyError!void,
};

/// RFC 5280 path validation of a client chain to `anchors` with the
/// `clientAuth` extended key usage, through `x509.verifyChain` (rustls
/// `WebPkiClientVerifier`). The leaf's names are not checked: which client
/// identities may do what is the application's question, asked of
/// `Server.peerCertificate` after the handshake.
pub const X509Verifier = struct {
    /// Scratch for `x509.verifyChain` (the path it builds), freed before
    /// `verify` returns; shared by every connection that uses the verifier,
    /// so thread-safe if those run on several threads.
    gpa: std.mem.Allocator,
    /// The trust anchors (DER).
    anchors: []const []const u8,
    /// `x509.Options.revocation`: CRLs the caller supplies.
    revocation: ?x509.chain.Revocation = null,
    max_intermediates: u32 = 8,

    /// The verifier points at `self`: it must outlive every `Server` whose
    /// `Config.client_auth` holds it.
    pub fn verifier(self: *const X509Verifier) ClientCertVerifier {
        return .{ .ctx = self, .verify = verifyChain };
    }

    fn verifyChain(ctx: ?*const anyopaque, chain: []const []const u8, now_s: i64) VerifyError!void {
        const self: *const X509Verifier = @ptrCast(@alignCast(ctx.?));
        _ = x509.verifyChain(self.gpa, chain, self.anchors, .{
            .now_sec = now_s,
            .required_eku = .client_auth,
            .revocation = self.revocation,
            .max_intermediates = self.max_intermediates,
        }) catch |err| return mapChainError(err);
    }
};

/// `x509.verifyChain`'s failures as alerts.
fn mapChainError(err: x509.chain.VerifyChainError) VerifyError {
    return switch (err) {
        error.CertificateExpired, error.CertificateNotYetValid => error.CertificateExpired,
        error.CertificateRevoked => error.CertificateRevoked,
        error.NoTrustedPath => error.UnknownCa,
        // rustls `UnknownRevocationStatus`.
        error.RevocationStatusUnknown => error.CertificateUnknown,
        error.ExtendedKeyUsageMismatch, error.WeakSignatureAlgorithm, error.UnsupportedPssParams => error.UnsupportedCertificate,
        error.OutOfMemory => error.CertificateUnknown,
        // A signature in the chain that does not verify included (RFC 8446
        // §6.2 `bad_certificate`; rustls answers `decrypt_error`).
        else => error.BadCertificate,
    };
}

/// A client's Certificate message (RFC 8446 §4.4.2), checked whole.
pub const Certificate = struct {
    /// The `certificate_list` body.
    list: []const u8,

    pub fn isEmpty(c: Certificate) bool {
        return c.list.len == 0;
    }

    /// The certificates (DER), leaf first.
    pub fn certificates(c: Certificate) CertIter {
        return .{ .r = .{ .buf = c.list } };
    }
};

pub const CertIter = struct {
    r: Reader,

    pub fn next(it: *CertIter) ?[]const u8 {
        if (it.r.left() == 0) return null;
        const der = it.r.vec(u24) catch unreachable; // checked by `parseCertificate`
        _ = it.r.vec(u16) catch unreachable;
        return der;
    }
};

/// Decode a client Certificate *body*. `context` is the
/// `certificate_request_context` the server sent.
pub fn parseCertificate(body: []const u8, context: []const u8) Error!Certificate {
    var r: Reader = .{ .buf = body };
    const ctx = try r.vec(u8);
    const list = try r.vec(u24);
    try r.done();
    var e: Reader = .{ .buf = list };
    while (e.left() != 0) {
        // `opaque cert_data<1..2^24-1>`.
        if ((try e.vec(u24)).len == 0) return error.DecodeError;
        const exts = try e.vec(u16);
        // Well-formed extensions first (rustls reads them before refusing).
        var x: Reader = .{ .buf = exts };
        while (x.left() != 0) {
            _ = try x.int(u16);
            _ = try x.vec(u16);
        }
        if (exts.len != 0) return error.UnsupportedExtension;
    }
    // After the decode: a malformed message is decode_error whatever its
    // context (rustls reads the whole payload first).
    if (!std.mem.eql(u8, ctx, context)) return error.IllegalParameter;
    return .{ .list = list };
}

pub const CertificateVerify = struct {
    scheme: u16,
    signature: []const u8,
};

/// Decode a CertificateVerify *body* (RFC 8446 §4.4.3).
pub fn parseCertificateVerify(body: []const u8) Error!CertificateVerify {
    var r: Reader = .{ .buf = body };
    const scheme = try r.int(u16);
    const sig = try r.vec(u16);
    try r.done();
    return .{ .scheme = scheme, .signature = sig };
}

/// The leaf's public key for `certverify.verify`, through `x509.spkiOf`
/// (bounds-checked; std's certificate parser is not safe on hostile DER).
/// RSA (rsaEncryption), ECDSA P-256 / P-384 / P-521, Ed25519, ML-DSA — the
/// keys `certverify` verifies with (as `dtls.certauth.parseLeafPublicKey`).
pub fn leafPublicKey(der: []const u8) VerifyError!certverify.PublicKey {
    const spki = x509.spkiOf(der) catch return error.BadCertificate;
    const bits = spki.key_bits;
    if (spki.algorithmIs(&x509.safe.oid_rsa_encryption))
        return .{ .rsa = rsa.PublicKey.fromDer(bits) catch return error.BadCertificate };
    if (spki.algorithmIs(&x509.safe.oid_ec_public_key)) {
        const curve = spki.namedCurveOid() orelse return error.UnsupportedCertificate;
        if (std.mem.eql(u8, curve, &x509.safe.oid_prime256v1))
            return .{ .ecdsa_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(bits) catch return error.BadCertificate };
        if (std.mem.eql(u8, curve, &x509.safe.oid_secp384r1))
            return .{ .ecdsa_p384 = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(bits) catch return error.BadCertificate };
        if (std.mem.eql(u8, curve, &x509.safe.oid_secp521r1))
            return .{ .ecdsa_p521 = p521.EcdsaP521Sha512.PublicKey.fromSec1(bits) catch return error.BadCertificate };
        return error.UnsupportedCertificate;
    }
    if (spki.algorithmIs(&x509.safe.oid_ed25519)) {
        const n = std.crypto.sign.Ed25519.PublicKey.encoded_length;
        if (bits.len != n) return error.BadCertificate;
        return .{ .ed25519 = std.crypto.sign.Ed25519.PublicKey.fromBytes(bits[0..n].*) catch return error.BadCertificate };
    }
    // ML-DSA (RFC 9881): the encoded key, borrowed from `der`.
    if (x509.MlDsa.map.get(spki.algorithm_oid)) |set| {
        // A key of another length is a malformed certificate, not a
        // signature that fails (independent review 2026-10-21, LOW).
        switch (set) {
            inline else => |c| if (bits.len != x509.MlDsa.Impl(c).PublicKey.encoded_length) return error.BadCertificate,
        }
        return switch (set) {
            .ml_dsa_44 => .{ .mldsa44 = bits },
            .ml_dsa_65 => .{ .mldsa65 = bits },
            .ml_dsa_87 => .{ .mldsa87 = bits },
        };
    }
    // id-RSASSA-PSS keys …
    return error.UnsupportedCertificate;
}

/// RFC 8446 §4.4.2.2, RFC 5280 §4.2.1.3: a leaf whose `keyUsage` is present
/// must assert `digitalSignature` to sign a CertificateVerify
/// (`unsupported_certificate` otherwise; BoringSSL `ssl_cert_check_key_usage`
/// checks it in the TLS layer whatever the verifier). Read from a copy
/// `x509.safe` vetted: std's DER walk is not safe on hostile input.
pub fn checkLeafKeyUsage(der: []const u8) VerifyError!void {
    if (der.len > max_leaf_len) return error.BadCertificate;
    var scratch: [max_leaf_len + x509.safe.parse_slack]u8 = undefined;
    const cert = x509.safe.safeCertificate(der, &scratch) catch return error.BadCertificate;
    const exts = (x509.extensions.findExtensions(cert) catch return error.BadCertificate) orelse return;
    var it = x509.extensions.iterate(exts, cert);
    while (it.next() catch return error.BadCertificate) |e| {
        if (e.id != .key_usage) continue;
        const ku = x509.extensions.parseKeyUsage(e.value) catch return error.BadCertificate;
        if (!ku.digital_signature) return error.UnsupportedCertificate;
    }
}

/// A cursor with length-prefixed reads (`u24` included: `@sizeOf(u24)` is
/// 4, so widths come from `@bitSizeOf`).
const Reader = struct {
    buf: []const u8,
    at: usize = 0,

    fn left(r: *const Reader) usize {
        return r.buf.len - r.at;
    }
    fn take(r: *Reader, n: usize) Error![]const u8 {
        if (r.left() < n) return error.DecodeError;
        defer r.at += n;
        return r.buf[r.at..][0..n];
    }
    fn int(r: *Reader, comptime T: type) Error!T {
        const n = @divExact(@bitSizeOf(T), 8);
        return std.mem.readInt(T, (try r.take(n))[0..n], .big);
    }
    fn vec(r: *Reader, comptime L: type) Error![]const u8 {
        return r.take(try r.int(L));
    }
    fn done(r: *const Reader) Error!void {
        if (r.left() != 0) return error.DecodeError;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn certMsg(comptime ctx: []const u8, comptime entries: []const struct { []const u8, []const u8 }) []const u8 {
    comptime {
        var list: []const u8 = "";
        for (entries) |e| list = list ++ be(u24, e[0].len) ++ e[0] ++ be(u16, e[1].len) ++ e[1];
        return be(u8, ctx.len) ++ ctx ++ be(u24, list.len) ++ list;
    }
}

fn be(comptime T: type, comptime v: usize) []const u8 {
    comptime {
        var b: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
        std.mem.writeInt(T, &b, v, .big);
        const out = b;
        return &out;
    }
}

test "parseCertificate: entries in order, empty list" {
    const c = try parseCertificate(comptime certMsg("", &.{ .{ "leaf", "" }, .{ "ca", "" } }), "");
    var it = c.certificates();
    try testing.expectEqualStrings("leaf", it.next().?);
    try testing.expectEqualStrings("ca", it.next().?);
    try testing.expectEqual(null, it.next());
    try testing.expect((try parseCertificate(comptime certMsg("", &.{}), "")).isEmpty());
}

test "parseCertificate: refusals" {
    // An entry extension (status_request) was not asked for.
    try testing.expectError(error.UnsupportedExtension, parseCertificate(comptime certMsg("", &.{.{ "leaf", "\x00\x05\x00\x00" }}), ""));
    // A malformed extension block is decode_error first.
    try testing.expectError(error.DecodeError, parseCertificate(comptime certMsg("", &.{.{ "leaf", "\x00\x05\x00\x09" }}), ""));
    // Another context than the one sent.
    try testing.expectError(error.IllegalParameter, parseCertificate(comptime certMsg("x", &.{.{ "leaf", "" }}), ""));
    // An empty cert_data, a short list, trailing octets.
    try testing.expectError(error.DecodeError, parseCertificate(comptime certMsg("", &.{.{ "", "" }}), ""));
    const ok = comptime certMsg("", &.{.{ "leaf", "" }});
    try testing.expectError(error.DecodeError, parseCertificate(ok[0 .. ok.len - 1], ""));
    try testing.expectError(error.DecodeError, parseCertificate(ok ++ "\x00", ""));
    try testing.expectError(error.DecodeError, parseCertificate("", ""));
}

test "parseCertificateVerify" {
    const v = try parseCertificateVerify("\x08\x04\x00\x03abc");
    try testing.expectEqual(@as(u16, 0x0804), v.scheme);
    try testing.expectEqualStrings("abc", v.signature);
    try testing.expectError(error.DecodeError, parseCertificateVerify("\x08\x04\x00\x03ab"));
    try testing.expectError(error.DecodeError, parseCertificateVerify("\x08\x04\x00\x02abc"));
    try testing.expectError(error.DecodeError, parseCertificateVerify("\x08"));
}

test "leafPublicKey: the test certificates" {
    const certs = @import("test_certs.zig");
    try testing.expect(try leafPublicKey(&certs.p256_cert) == .ecdsa_p256);
    try testing.expect(try leafPublicKey(&certs.p384_cert) == .ecdsa_p384);
    try testing.expect(try leafPublicKey(&certs.ed25519_cert) == .ed25519);
    try testing.expect(try leafPublicKey(&certs.rsa2048_cert) == .rsa);
    try testing.expectError(error.BadCertificate, leafPublicKey("\x30\x03\x02\x01\x00"));
}

test "checkLeafKeyUsage: digitalSignature or no keyUsage at all" {
    const certs = @import("test_certs.zig");
    const client_certs = @import("client_certs.zig");
    try checkLeafKeyUsage(&client_certs.p256_cert); // digitalSignature
    try checkLeafKeyUsage(&certs.p256_cert); // no keyUsage
    // The CA's keyUsage is keyCertSign + cRLSign only.
    try testing.expectError(error.UnsupportedCertificate, checkLeafKeyUsage(&client_certs.ca_cert));
    try testing.expectError(error.BadCertificate, checkLeafKeyUsage("GARBAGE"));
}

test "leafPublicKey: P-521 and ML-DSA leaves give their own key kinds" {
    const kv = @import("key_vectors.zig");
    const b64ct = @import("b64ct");
    for (kv.cases) |c| {
        const want: ?std.meta.Tag(certverify.PublicKey) = switch (c.kind) {
            .ecdsa_p521 => .ecdsa_p521,
            .mldsa44 => .mldsa44,
            .mldsa65 => .mldsa65,
            .mldsa87 => .mldsa87,
            else => null,
        };
        const tag = want orelse continue;
        const begin = "-----BEGIN CERTIFICATE-----\n";
        const at = std.mem.indexOf(u8, c.cert_pem, begin).? + begin.len;
        const end = std.mem.indexOfPos(u8, c.cert_pem, at, "-----END").?;
        var der_buf: [8192]u8 = undefined;
        const der = try b64ct.standard.decodeIgnoring(&der_buf, c.cert_pem[at..end], b64ct.pem_whitespace);
        const pk = try leafPublicKey(der);
        try std.testing.expectEqual(tag, std.meta.activeTag(pk));
    }
}
