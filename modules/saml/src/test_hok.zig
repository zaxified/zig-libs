// SPDX-License-Identifier: MIT
//! Holder-of-Key (`urn:oasis:names:tc:SAML:2.0:cm:holder-of-key`) subject
//! confirmation. The HoK `<SubjectConfirmationData>` carries a `<ds:KeyInfo>`
//! with the subject's certificate; the relying party confirms the presenter
//! actually holds that key by supplying the transport certificate DER
//! (`Config.presented_holder_cert_der`), matched by X.509-DER byte-equality.
//!
//! The HoK confirmation lives inside the signed assertion, so each test mints a
//! fresh signed assertion (see test_sign.zig). The "certificate DER" here is an
//! opaque byte blob: the match is a byte comparison that never parses the DER
//! (Zig 0.16 `std.crypto.Certificate.parse` panic hazard), so an arbitrary blob
//! exercises the exact code path a real cert would.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const sign = @import("test_sign.zig");

const hok_method = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
const ds_ns_decl = "http://www.w3.org/2000/09/xmldsig#";

const nameid =
    "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.org</saml:NameID>";

const conditions =
    "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
    "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>";

const bearer_confirmation =
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
    "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
    "</saml:SubjectConfirmation>";

// An opaque "certificate DER" — the presenter's transport cert. Byte-compared,
// never parsed.
const presented_der = [_]u8{
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0xde, 0xad, 0xbe, 0xef,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x13, 0x37, 0xca, 0xfe,
};

fn b64(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const out = try alloc.alloc(u8, encoder.calcSize(data.len));
    _ = encoder.encode(out, data);
    return out;
}

fn hokConfirmation(alloc: std.mem.Allocator, cert_der: []const u8, with_data_attrs: bool) ![]u8 {
    const cert_b64 = try b64(alloc, cert_der);
    defer alloc.free(cert_b64);
    const data_attrs = if (with_data_attrs)
        " NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\""
    else
        "";
    return std.fmt.allocPrint(alloc, "<saml:SubjectConfirmation Method=\"{s}\"><saml:SubjectConfirmationData{s}>" ++
        "<ds:KeyInfo xmlns:ds=\"{s}\"><ds:X509Data>" ++
        "<ds:X509Certificate>{s}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" ++
        "</saml:SubjectConfirmationData></saml:SubjectConfirmation>", .{ hok_method, data_attrs, ds_ns_decl, cert_b64 });
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
    var signed = try sign.signAssertion(alloc, 0x40C0DE, fx.idp_entity_id, "_hok01", "2024-06-01T12:00:00Z", after_issuer);
    errdefer signed.deinit(alloc);
    const resp = try sign.wrapInResponse(alloc, signed.xml);
    alloc.free(signed.xml);
    signed.xml = resp;
    return signed;
}

test "HoK: matching presented cert accepted (policy .holder_of_key)" {
    const alloc = testing.allocator;
    const conf = try hokConfirmation(alloc, &presented_der, true);
    defer alloc.free(conf);
    var signed = try mintResponse(alloc, conf);
    defer signed.deinit(alloc);

    var cfg = baseConfig(signed.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &presented_der;
    var res = try saml.consumeResponseXml(alloc, signed.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK: matching presented cert accepted under .either policy" {
    const alloc = testing.allocator;
    const conf = try hokConfirmation(alloc, &presented_der, true);
    defer alloc.free(conf);
    var signed = try mintResponse(alloc, conf);
    defer signed.deinit(alloc);

    var cfg = baseConfig(signed.key);
    cfg.subject_confirmation = .either;
    cfg.presented_holder_cert_der = &presented_der;
    var res = try saml.consumeResponseXml(alloc, signed.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK: KeyInfo present but SubjectConfirmationData omits Recipient/InResponseTo/NotOnOrAfter -> still accepted" {
    const alloc = testing.allocator;
    const conf = try hokConfirmation(alloc, &presented_der, false); // no data attrs
    defer alloc.free(conf);
    var signed = try mintResponse(alloc, conf);
    defer signed.deinit(alloc);

    var cfg = baseConfig(signed.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &presented_der;
    var res = try saml.consumeResponseXml(alloc, signed.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "HoK: non-matching presented cert -> HolderOfKeyMismatch" {
    const alloc = testing.allocator;
    const conf = try hokConfirmation(alloc, &presented_der, true);
    defer alloc.free(conf);
    var signed = try mintResponse(alloc, conf);
    defer signed.deinit(alloc);

    const wrong = [_]u8{0x99} ** 32;
    var cfg = baseConfig(signed.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &wrong;
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(alloc, signed.xml, cfg));
}

test "HoK: method present but policy is bearer-only -> SubjectConfirmationMethodNotAllowed" {
    const alloc = testing.allocator;
    const conf = try hokConfirmation(alloc, &presented_der, true);
    defer alloc.free(conf);
    var signed = try mintResponse(alloc, conf);
    defer signed.deinit(alloc);

    // Default subject_confirmation = .bearer; even a matching presented cert must
    // not satisfy a HoK confirmation.
    var cfg = baseConfig(signed.key);
    cfg.presented_holder_cert_der = &presented_der;
    try testing.expectError(error.SubjectConfirmationMethodNotAllowed, saml.consumeResponseXml(alloc, signed.xml, cfg));
}

test "HoK: required but no presented key -> PresentedKeyMissing" {
    const alloc = testing.allocator;
    const conf = try hokConfirmation(alloc, &presented_der, true);
    defer alloc.free(conf);
    var signed = try mintResponse(alloc, conf);
    defer signed.deinit(alloc);

    var cfg = baseConfig(signed.key);
    cfg.subject_confirmation = .holder_of_key;
    // presented_holder_cert_der stays null.
    try testing.expectError(error.PresentedKeyMissing, saml.consumeResponseXml(alloc, signed.xml, cfg));
}

test "HoK: Bearer confirmation rejected when policy is holder_of_key -> SubjectConfirmationMethodNotAllowed" {
    const alloc = testing.allocator;
    var signed = try mintResponse(alloc, bearer_confirmation);
    defer signed.deinit(alloc);

    var cfg = baseConfig(signed.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &presented_der;
    try testing.expectError(error.SubjectConfirmationMethodNotAllowed, saml.consumeResponseXml(alloc, signed.xml, cfg));
}

test "HoK: Bearer still accepted under .either policy (positive control)" {
    const alloc = testing.allocator;
    var signed = try mintResponse(alloc, bearer_confirmation);
    defer signed.deinit(alloc);

    var cfg = baseConfig(signed.key);
    cfg.subject_confirmation = .either;
    var res = try saml.consumeResponseXml(alloc, signed.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}
