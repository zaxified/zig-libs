// SPDX-License-Identifier: MIT
//! Holder-of-Key subject confirmation carrying a bare `<ds:KeyValue>` (no
//! `<X509Certificate>`): an `<RSAKeyValue>` matched to a presented
//! `rsa.PublicKey`, or an `<ECKeyValue>` matched to a presented SEC1 P-256 point.
//! The match is purely structural (base64 + big-endian integer / byte compare) —
//! no signature op and no DER parsing.
//!
//! Like `test_hok.zig`, each case mints a fresh signed assertion (see
//! `test_sign.zig`) because the HoK confirmation lives inside the signed
//! assertion. For the RSA case the presented key is the very key the assertion is
//! signed with (its modulus/exponent are serialized straight into the
//! `<RSAKeyValue>`) — that exercises the exact integer-equality path a real key
//! would. The EC point is an opaque SEC1-shaped blob: the match never parses it,
//! so a blob exercises the real code path.

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

/// Mint a signed Response whose Subject carries `confirmation`.
fn mintResponse(alloc: std.mem.Allocator, confirmation: []const u8) !sign.Signed {
    const after_issuer = try std.fmt.allocPrint(alloc, "<saml:Subject>{s}{s}</saml:Subject>{s}", .{ nameid, confirmation, conditions });
    defer alloc.free(after_issuer);
    var signed = try sign.signAssertion(alloc, 0x4B37E4, fx.idp_entity_id, "_hokkv01", "2024-06-01T12:00:00Z", after_issuer);
    errdefer signed.deinit(alloc);
    const resp = try sign.wrapInResponse(alloc, signed.xml);
    alloc.free(signed.xml);
    signed.xml = resp;
    return signed;
}

/// Build a HoK confirmation carrying an `<RSAKeyValue>` for `pk`.
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

/// Build a HoK confirmation carrying an `<dsig11:ECKeyValue>` for `sec1`.
fn ecKeyValueConfirmation(alloc: std.mem.Allocator, sec1: []const u8) ![]u8 {
    const pt_b64 = try b64(alloc, sec1);
    defer alloc.free(pt_b64);
    return std.fmt.allocPrint(alloc, "<saml:SubjectConfirmation Method=\"{s}\"><saml:SubjectConfirmationData>" ++
        "<ds:KeyInfo xmlns:ds=\"{s}\" xmlns:dsig11=\"{s}\"><ds:KeyValue><dsig11:ECKeyValue>" ++
        "<dsig11:NamedCurve URI=\"{s}\"/><dsig11:PublicKey>{s}</dsig11:PublicKey>" ++
        "</dsig11:ECKeyValue></ds:KeyValue></ds:KeyInfo>" ++
        "</saml:SubjectConfirmationData></saml:SubjectConfirmation>", .{ hok_method, ds_ns_decl, dsig11_ns_decl, p256_oid, pt_b64 });
}

/// Build a HoK confirmation carrying only an `<X509Certificate>` blob.
fn x509Confirmation(alloc: std.mem.Allocator, cert_der: []const u8) ![]u8 {
    const cert_b64 = try b64(alloc, cert_der);
    defer alloc.free(cert_b64);
    return std.fmt.allocPrint(alloc, "<saml:SubjectConfirmation Method=\"{s}\"><saml:SubjectConfirmationData>" ++
        "<ds:KeyInfo xmlns:ds=\"{s}\"><ds:X509Data>" ++
        "<ds:X509Certificate>{s}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" ++
        "</saml:SubjectConfirmationData></saml:SubjectConfirmation>", .{ hok_method, ds_ns_decl, cert_b64 });
}

// A SEC1-shaped uncompressed P-256 point (0x04 || X(32) || Y(32)). Opaque:
// byte-compared, never parsed.
const presented_point = [_]u8{0x04} ++ ([_]u8{0xA1} ** 32) ++ ([_]u8{0xB2} ** 32);

test "HoK KeyValue: RSAKeyValue matching presented rsa key -> accepted" {
    const alloc = testing.allocator;

    // The confirmation embeds the SIGNING key's RSAKeyValue, so learn that key
    // from a probe (deterministic keygen from the shared seed), build the
    // confirmation, then mint the real assertion (same seed -> same key).
    var probe = try sign.signAssertion(alloc, 0x4B37E4, fx.idp_entity_id, "_probe", "2024-06-01T12:00:00Z", "<saml:Subject></saml:Subject>");
    const pk = probe.key.rsa;
    probe.deinit(alloc);

    const conf = try rsaKeyValueConfirmation(alloc, pk);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .rsa = s.key.rsa };
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK KeyValue: RSAKeyValue not matching presented rsa key -> HolderOfKeyMismatch" {
    const alloc = testing.allocator;
    // Confirmation carries the signing key's RSAKeyValue; presented is a DIFFERENT key.
    var s = blk: {
        var probe = try sign.signAssertion(alloc, 0x4B37E4, fx.idp_entity_id, "_probe", "2024-06-01T12:00:00Z", "<saml:Subject></saml:Subject>");
        const pk = probe.key.rsa;
        probe.deinit(alloc);
        const conf = try rsaKeyValueConfirmation(alloc, pk);
        defer alloc.free(conf);
        break :blk try mintResponse(alloc, conf);
    };
    defer s.deinit(alloc);

    var prng = std.Random.DefaultPrng.init(0xDEAD5555);
    const other = try rsa.generate(prng.random(), 1024, 65537);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .rsa = other.public_key };
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK KeyValue: ECKeyValue matching presented sec1 point -> accepted" {
    const alloc = testing.allocator;
    const conf = try ecKeyValueConfirmation(alloc, &presented_point);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .ec_sec1 = &presented_point };
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK KeyValue: ECKeyValue not matching presented sec1 point -> HolderOfKeyMismatch" {
    const alloc = testing.allocator;
    const conf = try ecKeyValueConfirmation(alloc, &presented_point);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    const wrong = [_]u8{0x04} ++ ([_]u8{0x00} ** 64);
    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .ec_sec1 = &wrong };
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK KeyValue: ECKeyValue with wrong NamedCurve -> HolderOfKeyMismatch" {
    const alloc = testing.allocator;
    const pt_b64 = try b64(alloc, &presented_point);
    defer alloc.free(pt_b64);
    // A non-P-256 NamedCurve must not match even with identical point bytes.
    const conf = try std.fmt.allocPrint(alloc, "<saml:SubjectConfirmation Method=\"{s}\"><saml:SubjectConfirmationData>" ++
        "<ds:KeyInfo xmlns:ds=\"{s}\" xmlns:dsig11=\"{s}\"><ds:KeyValue><dsig11:ECKeyValue>" ++
        "<dsig11:NamedCurve URI=\"urn:oid:1.3.132.0.34\"/><dsig11:PublicKey>{s}</dsig11:PublicKey>" ++
        "</dsig11:ECKeyValue></ds:KeyValue></ds:KeyInfo>" ++
        "</saml:SubjectConfirmationData></saml:SubjectConfirmation>", .{ hok_method, ds_ns_decl, dsig11_ns_decl, pt_b64 });
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .ec_sec1 = &presented_point };
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK KeyValue: no presented cert nor key -> PresentedKeyMissing" {
    const alloc = testing.allocator;
    const conf = try ecKeyValueConfirmation(alloc, &presented_point);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    // Neither presented_holder_cert_der nor presented_holder_key set.
    try testing.expectError(error.PresentedKeyMissing, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK KeyValue: confirmation is X509 but only a bare key configured -> HolderOfKeyCrossFormUnsupported" {
    const alloc = testing.allocator;
    const cert = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xAB, 0xCD } ++ ([_]u8{0x77} ** 40);
    const conf = try x509Confirmation(alloc, &cert);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    var prng = std.Random.DefaultPrng.init(0x1111);
    const key = try rsa.generate(prng.random(), 1024, 65537);
    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .rsa = key.public_key };
    try testing.expectError(error.HolderOfKeyCrossFormUnsupported, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK KeyValue: confirmation is KeyValue but only a cert configured -> HolderOfKeyCrossFormUnsupported" {
    const alloc = testing.allocator;
    const conf = try ecKeyValueConfirmation(alloc, &presented_point);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    const cert = [_]u8{ 0x30, 0x82, 0x01, 0x00 } ++ ([_]u8{0x42} ** 32);
    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &cert;
    try testing.expectError(error.HolderOfKeyCrossFormUnsupported, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "HoK KeyValue: both cert and key configured, KeyValue confirmation matches on the key (positive control)" {
    const alloc = testing.allocator;
    const conf = try ecKeyValueConfirmation(alloc, &presented_point);
    defer alloc.free(conf);
    var s = try mintResponse(alloc, conf);
    defer s.deinit(alloc);

    const cert = [_]u8{ 0x30, 0x82, 0x01, 0x00 } ++ ([_]u8{0x42} ** 32);
    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &cert; // present but irrelevant to a KeyValue confirmation
    cfg.presented_holder_key = .{ .ec_sec1 = &presented_point };
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}
