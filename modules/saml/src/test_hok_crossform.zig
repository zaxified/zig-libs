// SPDX-License-Identifier: MIT
//! Holder-of-Key CROSS-FORM matching: the `<SubjectConfirmation>` names the key
//! in one form (an `<ds:X509Certificate>`, or a bare `<ds:KeyValue>`) while the
//! caller supplied the other (`presented_holder_key`, or
//! `presented_holder_cert_der`).
//!
//! Unlike `test_hok.zig` / `test_hok_keyvalue.zig`, the certificates here are
//! REAL — cross-form matching extracts their `SubjectPublicKeyInfo` — so:
//!
//!   * the RSA cases mint a key with `rsa.generate` and a self-signed
//!     certificate for it with `rsa.selfSignedCert`, which makes the key the
//!     test compares against an independent value (it is the generator's
//!     output, not something read back out of the certificate);
//!   * the EC cases use a P-256 certificate produced out of band by OpenSSL 3.5
//!     (`openssl req -x509 -key <prime256v1 key>`), with the public point taken
//!     from a SEPARATE OpenSSL command (`openssl ec -pubout -text`) rather than
//!     from this module's own extractor — so the positive tests cannot pass by
//!     the extractor agreeing with itself.
//!
//! Every positive case is paired with a negative one: a matcher that always
//! returned true would pass the positive tests alone.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const rsa = @import("rsa");
const fx = @import("fixtures.zig");
const sign = @import("test_sign.zig");

const hok_method = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
const ds_ns_decl = "http://www.w3.org/2000/09/xmldsig#";
const dsig11_ns_decl = "http://www.w3.org/2009/xmldsig11#";
const p256_oid = "urn:oid:1.2.840.10045.3.1.7";

const nameid =
    "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.org</saml:NameID>";

const conditions =
    "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
    "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>";

// ── fixtures ────────────────────────────────────────────────────────────────

/// A self-signed P-256 certificate, `CN=hok-ec-test`, generated out of band:
///
///   openssl ecparam -name prime256v1 -genkey -noout -out ec.key
///   openssl req -new -x509 -key ec.key -subj /CN=hok-ec-test -days 7300 \
///           -sha256 -outform DER -out ec.der
const ec_cert_der = [_]u8{
    0x30, 0x82, 0x01, 0x80, 0x30, 0x82, 0x01, 0x27, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x35, 0x0e, 0x34, 0xa4, 0x30, 0x47, 0x27, 0xae, 0xed,
    0xfc, 0x3f, 0xee, 0xa7, 0x05, 0x58, 0xc7, 0x80, 0xcb, 0xca, 0x29, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b,
    0x68, 0x6f, 0x6b, 0x2d, 0x65, 0x63, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x32, 0x37, 0x32, 0x32, 0x34,
    0x33, 0x33, 0x31, 0x5a, 0x17, 0x0d, 0x34, 0x36, 0x30, 0x37, 0x32, 0x32,
    0x32, 0x32, 0x34, 0x33, 0x33, 0x31, 0x5a, 0x30, 0x16, 0x31, 0x14, 0x30,
    0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x68, 0x6f, 0x6b, 0x2d,
    0x65, 0x63, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06,
    0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x97, 0x7f,
    0x4e, 0xa9, 0xef, 0x58, 0xf0, 0x4b, 0x74, 0xa4, 0x1f, 0xcb, 0xbe, 0x3e,
    0xfc, 0x05, 0x4c, 0x93, 0x82, 0x8e, 0x93, 0x90, 0xa4, 0x22, 0x22, 0x9d,
    0x54, 0x83, 0xc8, 0xfa, 0x22, 0xe5, 0xee, 0x27, 0x82, 0x4f, 0xce, 0x11,
    0x0b, 0x8d, 0xf4, 0xfa, 0x29, 0x97, 0x9e, 0x12, 0x0e, 0x20, 0x7a, 0x2d,
    0x4e, 0x15, 0x9c, 0xf6, 0xee, 0x1c, 0x77, 0x77, 0x9e, 0x08, 0x8a, 0x1e,
    0x99, 0x26, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0xaf, 0xbc, 0x2c, 0xc8, 0xeb, 0xdb, 0xb5,
    0x9c, 0x3c, 0xde, 0xc4, 0xdd, 0x22, 0xb6, 0x89, 0x36, 0xc0, 0x3f, 0xbd,
    0x1c, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0xaf, 0xbc, 0x2c, 0xc8, 0xeb, 0xdb, 0xb5, 0x9c, 0x3c, 0xde,
    0xc4, 0xdd, 0x22, 0xb6, 0x89, 0x36, 0xc0, 0x3f, 0xbd, 0x1c, 0x30, 0x0f,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x5c, 0x12,
    0x34, 0x45, 0xca, 0xf5, 0xbc, 0xf0, 0x99, 0x6b, 0x1f, 0x37, 0x18, 0xe8,
    0x3e, 0x00, 0x93, 0x65, 0x53, 0x27, 0xd3, 0x6f, 0x0b, 0xe2, 0xb0, 0x0a,
    0x97, 0xea, 0x63, 0xf7, 0x4e, 0x03, 0x02, 0x20, 0x6d, 0xf5, 0xbe, 0x77,
    0x88, 0xd2, 0x18, 0xbe, 0x6c, 0x49, 0xa1, 0x0d, 0xda, 0x1e, 0xce, 0xfe,
    0x34, 0x4e, 0x7c, 0xc3, 0xb7, 0xe0, 0x17, 0xfc, 0x55, 0x7a, 0xec, 0x36,
    0x44, 0x09, 0x31, 0x3e,
};

/// `ec_cert_der`'s public point, uncompressed SEC1 — from `openssl ec -in
/// ec.key -pubout -text`, i.e. an oracle independent of this module.
const ec_point_uncompressed = [_]u8{
    0x04, 0x97, 0x7f, 0x4e, 0xa9, 0xef, 0x58, 0xf0, 0x4b, 0x74, 0xa4, 0x1f,
    0xcb, 0xbe, 0x3e, 0xfc, 0x05, 0x4c, 0x93, 0x82, 0x8e, 0x93, 0x90, 0xa4,
    0x22, 0x22, 0x9d, 0x54, 0x83, 0xc8, 0xfa, 0x22, 0xe5, 0xee, 0x27, 0x82,
    0x4f, 0xce, 0x11, 0x0b, 0x8d, 0xf4, 0xfa, 0x29, 0x97, 0x9e, 0x12, 0x0e,
    0x20, 0x7a, 0x2d, 0x4e, 0x15, 0x9c, 0xf6, 0xee, 0x1c, 0x77, 0x77, 0x9e,
    0x08, 0x8a, 0x1e, 0x99, 0x26,
};

/// The SAME point, compressed (`0x02 || X`, Y's last byte 0x26 being even).
/// A different byte string naming the same key — the case a byte-equality
/// matcher gets wrong.
const ec_point_compressed = [_]u8{0x02} ++ ec_point_uncompressed[1..33].*;

/// A DIFFERENT, on-curve P-256 point (a second `openssl ecparam -genkey`).
const ec_point_other = [_]u8{
    0x04, 0xcf, 0x7d, 0xe4, 0xee, 0xe0, 0x91, 0x79, 0x56, 0x71, 0x0e, 0x66,
    0xfa, 0x9c, 0x80, 0xec, 0xba, 0x6f, 0x21, 0x1d, 0x9a, 0x32, 0xf8, 0xd7,
    0x88, 0xd9, 0x65, 0x52, 0xa3, 0x78, 0xd5, 0xb9, 0xb4, 0xf6, 0x99, 0x63,
    0xaf, 0xa5, 0x7d, 0xe6, 0x1f, 0xa9, 0xda, 0x62, 0x92, 0xaa, 0x21, 0x3d,
    0xde, 0x64, 0x40, 0xc0, 0x63, 0x67, 0x32, 0x4b, 0xd7, 0x0d, 0xbf, 0x6e,
    0x65, 0xd4, 0x9e, 0xbf, 0x20,
};

// ── helpers ─────────────────────────────────────────────────────────────────

fn b64(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const out = try alloc.alloc(u8, encoder.calcSize(data.len));
    _ = encoder.encode(out, data);
    return out;
}

fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

fn baseConfig(idp_key: @import("xmldsig").VerifyKey) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = idp_key,
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = fx.t_valid,
        .expected_in_response_to = fx.request_id,
    };
}

fn mintResponse(alloc: std.mem.Allocator, confirmation: []const u8) !sign.Signed {
    const after_issuer = try std.fmt.allocPrint(alloc, "<saml:Subject>{s}{s}</saml:Subject>{s}", .{ nameid, confirmation, conditions });
    defer alloc.free(after_issuer);
    var signed = try sign.signAssertion(alloc, 0x4B37E4, fx.idp_entity_id, "_hokxf01", "2024-06-01T12:00:00Z", after_issuer);
    errdefer signed.deinit(alloc);
    const resp = try sign.wrapInResponse(alloc, signed.xml);
    alloc.free(signed.xml);
    signed.xml = resp;
    return signed;
}

fn x509Confirmation(alloc: std.mem.Allocator, cert_der: []const u8) ![]u8 {
    const cert_b64 = try b64(alloc, cert_der);
    defer alloc.free(cert_b64);
    return std.fmt.allocPrint(alloc, "<saml:SubjectConfirmation Method=\"{s}\"><saml:SubjectConfirmationData>" ++
        "<ds:KeyInfo xmlns:ds=\"{s}\"><ds:X509Data>" ++
        "<ds:X509Certificate>{s}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" ++
        "</saml:SubjectConfirmationData></saml:SubjectConfirmation>", .{ hok_method, ds_ns_decl, cert_b64 });
}

fn rsaKeyValueConfirmation(alloc: std.mem.Allocator, pk: rsa.PublicKey) ![]u8 {
    var n_buf: [rsa.max_modulus_len]u8 = undefined;
    const n_len = (pk.n.bits() + 7) / 8;
    try pk.n.toBytes(n_buf[0..n_len], .big);
    var e_buf: [rsa.max_modulus_len]u8 = undefined;
    try pk.e.toBytes(&e_buf, .big);

    const mod_b64 = try b64(alloc, n_buf[0..n_len]);
    defer alloc.free(mod_b64);
    const exp_b64 = try b64(alloc, stripLeadingZeros(&e_buf));
    defer alloc.free(exp_b64);

    return std.fmt.allocPrint(alloc, "<saml:SubjectConfirmation Method=\"{s}\"><saml:SubjectConfirmationData>" ++
        "<ds:KeyInfo xmlns:ds=\"{s}\"><ds:KeyValue><ds:RSAKeyValue>" ++
        "<ds:Modulus>{s}</ds:Modulus><ds:Exponent>{s}</ds:Exponent>" ++
        "</ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>" ++
        "</saml:SubjectConfirmationData></saml:SubjectConfirmation>", .{ hok_method, ds_ns_decl, mod_b64, exp_b64 });
}

fn ecKeyValueConfirmation(alloc: std.mem.Allocator, sec1: []const u8) ![]u8 {
    const pt_b64 = try b64(alloc, sec1);
    defer alloc.free(pt_b64);
    return std.fmt.allocPrint(alloc, "<saml:SubjectConfirmation Method=\"{s}\"><saml:SubjectConfirmationData>" ++
        "<ds:KeyInfo xmlns:ds=\"{s}\" xmlns:dsig11=\"{s}\"><ds:KeyValue><dsig11:ECKeyValue>" ++
        "<dsig11:NamedCurve URI=\"{s}\"/><dsig11:PublicKey>{s}</dsig11:PublicKey>" ++
        "</dsig11:ECKeyValue></ds:KeyValue></ds:KeyInfo>" ++
        "</saml:SubjectConfirmationData></saml:SubjectConfirmation>", .{ hok_method, ds_ns_decl, dsig11_ns_decl, p256_oid, pt_b64 });
}

const RsaCert = struct {
    der: []u8,
    public_key: rsa.PublicKey,

    fn deinit(self: *RsaCert, alloc: std.mem.Allocator) void {
        alloc.free(self.der);
    }
};

/// A real self-signed RSA certificate plus the key it names — the key comes
/// from the generator, NOT from reading the certificate back.
fn mintRsaCert(alloc: std.mem.Allocator, seed: u64) !RsaCert {
    var prng = std.Random.DefaultPrng.init(seed);
    const kp = try rsa.generate(prng.random(), 1024, 65537);
    const der = try rsa.selfSignedCert(alloc, kp.secret_key, kp.public_key, std.crypto.hash.sha2.Sha256, .{
        .common_name = "hok-rsa-test",
        .not_before = "240101000000Z",
        .not_after = "340101000000Z",
    });
    return .{ .der = der, .public_key = kp.public_key };
}

// ── cross-form: <X509Certificate> in the confirmation vs a presented key ─────

test "HoK cross-form: X509Certificate vs a presented RSA key -> accepted" {
    const alloc = testing.allocator;
    var cert = try mintRsaCert(alloc, 0xC0FFEE01);
    defer cert.deinit(alloc);

    const conf = try x509Confirmation(alloc, cert.der);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    // Only the bare key is configured — the confirmation carries a certificate.
    cfg.presented_holder_key = .{ .rsa = cert.public_key };
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK cross-form: X509Certificate vs a DIFFERENT presented RSA key -> HolderOfKeyMismatch" {
    const alloc = testing.allocator;
    var cert = try mintRsaCert(alloc, 0xC0FFEE01);
    defer cert.deinit(alloc);
    var other = try mintRsaCert(alloc, 0xC0FFEE02); // a different key entirely
    defer other.deinit(alloc);

    const conf = try x509Confirmation(alloc, cert.der);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .rsa = other.public_key };
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK cross-form: an RSA certificate never matches an EC presented key" {
    // Algorithm confusion guard: the comparison is per-algorithm, so an RSA
    // certificate cannot be confirmed by any EC point, whatever its bytes.
    const alloc = testing.allocator;
    var cert = try mintRsaCert(alloc, 0xC0FFEE03);
    defer cert.deinit(alloc);

    const conf = try x509Confirmation(alloc, cert.der);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .ec_sec1 = &ec_point_uncompressed };
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK cross-form: P-256 X509Certificate vs a presented SEC1 point -> accepted" {
    const alloc = testing.allocator;
    const conf = try x509Confirmation(alloc, &ec_cert_der);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .ec_sec1 = &ec_point_uncompressed };
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK cross-form: the COMPRESSED encoding of the same point still matches" {
    // The point of comparing key parameters rather than bytes: the presenter
    // authenticated with the same key, encoded differently.
    const alloc = testing.allocator;
    const conf = try x509Confirmation(alloc, &ec_cert_der);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .ec_sec1 = &ec_point_compressed };
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK cross-form: P-256 X509Certificate vs a DIFFERENT point -> HolderOfKeyMismatch" {
    const alloc = testing.allocator;
    const conf = try x509Confirmation(alloc, &ec_cert_der);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .ec_sec1 = &ec_point_other };
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK cross-form: an off-curve presented point can never match" {
    // Not a public key at all: `fromSec1` rejects it, so it is not silently
    // treated as an opaque blob that happens to compare equal to something.
    const alloc = testing.allocator;
    const conf = try x509Confirmation(alloc, &ec_cert_der);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    const off_curve = [_]u8{0x04} ++ ([_]u8{0xA1} ** 32) ++ ([_]u8{0xB2} ** 32);
    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .ec_sec1 = &off_curve };
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, s.xml, cfg));
}

// ── cross-form: <ds:KeyValue> in the confirmation vs a presented certificate ─

test "HoK cross-form: RSAKeyValue vs a presented RSA certificate -> accepted" {
    const alloc = testing.allocator;
    var cert = try mintRsaCert(alloc, 0xBEEF0001);
    defer cert.deinit(alloc);

    const conf = try rsaKeyValueConfirmation(alloc, cert.public_key);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    // Only the certificate is configured — the confirmation carries a bare key.
    cfg.presented_holder_cert_der = cert.der;
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK cross-form: RSAKeyValue vs a DIFFERENT presented certificate -> HolderOfKeyMismatch" {
    const alloc = testing.allocator;
    var cert = try mintRsaCert(alloc, 0xBEEF0001);
    defer cert.deinit(alloc);
    var other = try mintRsaCert(alloc, 0xBEEF0002);
    defer other.deinit(alloc);

    const conf = try rsaKeyValueConfirmation(alloc, cert.public_key);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = other.der;
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK cross-form: ECKeyValue vs a presented P-256 certificate -> accepted" {
    const alloc = testing.allocator;
    const conf = try ecKeyValueConfirmation(alloc, &ec_point_uncompressed);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &ec_cert_der;
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK cross-form: a COMPRESSED ECKeyValue point matches the same certificate" {
    const alloc = testing.allocator;
    const conf = try ecKeyValueConfirmation(alloc, &ec_point_compressed);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &ec_cert_der;
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK cross-form: a DIFFERENT ECKeyValue point vs the certificate -> HolderOfKeyMismatch" {
    const alloc = testing.allocator;
    const conf = try ecKeyValueConfirmation(alloc, &ec_point_other);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &ec_cert_der;
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK cross-form: an RSAKeyValue never matches a P-256 certificate" {
    const alloc = testing.allocator;
    var cert = try mintRsaCert(alloc, 0xBEEF0003);
    defer cert.deinit(alloc);

    // The confirmation names an RSA key; the presented certificate is EC. The
    // forms are both "reducible", but the algorithms differ, so no match — and
    // no comparison could succeed, so it is reported as incomparable.
    const conf = try rsaKeyValueConfirmation(alloc, cert.public_key);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &ec_cert_der;
    try testing.expectError(error.HolderOfKeyCrossFormUnsupported, saml.consumeResponseXml(alloc, s.xml, cfg));
}

// ── fail-closed: nothing reducible to a key ─────────────────────────────────

test "HoK cross-form: a truncated certificate in the confirmation fails closed" {
    // Every prefix of a real certificate: none may be accepted, and none may
    // panic (this is the untrusted-DER path — run in Debug, where the std
    // `Certificate.parse` hazard would abort the process).
    const alloc = testing.allocator;
    var cfg_key: rsa.PublicKey = undefined;
    {
        var cert = try mintRsaCert(alloc, 0xDEAD0001);
        defer cert.deinit(alloc);
        cfg_key = cert.public_key;
    }

    for ([_]usize{ 0, 1, 2, 3, 8, 32, 64, 100, 150, 200 }) |cut| {
        if (cut > ec_cert_der.len) continue;
        const conf = try x509Confirmation(alloc, ec_cert_der[0..cut]);
        defer alloc.free(conf);
        var s = try mintResponse(alloc, conf);
        defer s.deinit(alloc);

        var cfg = baseConfig(s.key);
        cfg.subject_confirmation = .holder_of_key;
        cfg.presented_holder_key = .{ .rsa = cfg_key };
        if (saml.consumeResponseXml(alloc, s.xml, cfg)) |*res| {
            @constCast(res).deinit();
            try testing.expect(false); // a truncated certificate must never confirm
        } else |e| {
            try testing.expect(e == error.HolderOfKeyCrossFormUnsupported or e == error.HolderOfKeyMismatch);
        }
    }
}

test "HoK cross-form: a same-form match still wins when a cross-form pairing is also present" {
    // Both forms configured and both named: the same-form certificate compare
    // confirms before any cross-form work happens (a regression guard on the
    // ordering, not on the verdict).
    const alloc = testing.allocator;
    var cert = try mintRsaCert(alloc, 0xFEED0001);
    defer cert.deinit(alloc);

    const conf = try x509Confirmation(alloc, cert.der);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = cert.der;
    cfg.presented_holder_key = .{ .ec_sec1 = &ec_point_uncompressed }; // wrong, unused
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}
