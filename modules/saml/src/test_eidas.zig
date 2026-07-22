// SPDX-License-Identifier: MIT
//! Two eIDAS assertion-consumption checks:
//!   - **Sender-vouches** subject confirmation
//!     (`urn:oasis:names:tc:SAML:2.0:cm:sender-vouches`): trust derives entirely
//!     from the already-verified assertion signature; no key/recipient binding is
//!     applied, but the assertion `<Conditions>` are still enforced.
//!   - **Level of Assurance** minimum (`Config.required_loa`): the returned
//!     `<AuthnContextClassRef>` must meet the required eIDAS level (low <
//!     substantial < high) or, for a non-eIDAS class ref, match exactly.
//!
//! Each case mints a fresh signed assertion (see `test_sign.zig`).

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const sign = @import("test_sign.zig");

const nameid =
    "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.org</saml:NameID>";

const sv_confirmation =
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:sender-vouches\"/>";

const bearer_confirmation =
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
    "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
    "</saml:SubjectConfirmation>";

const conditions_valid =
    "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
    "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>";

const conditions_expired =
    "<saml:Conditions NotBefore=\"2024-06-01T11:00:00Z\" NotOnOrAfter=\"2024-06-01T11:30:00Z\">" ++
    "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>";

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

/// Mint a signed Response: Subject(nameid+confirmation) + conditions + optional
/// AuthnStatement body (raw XML, e.g. an AuthnContext).
fn mint(alloc: std.mem.Allocator, confirmation: []const u8, conditions_xml: []const u8, authn_xml: []const u8) !sign.Signed {
    const after_issuer = try std.fmt.allocPrint(alloc, "<saml:Subject>{s}{s}</saml:Subject>{s}{s}", .{ nameid, confirmation, conditions_xml, authn_xml });
    defer alloc.free(after_issuer);
    var signed = try sign.signAssertion(alloc, 0xE1DA5, fx.idp_entity_id, "_eidas01", "2024-06-01T12:00:00Z", after_issuer);
    errdefer signed.deinit(alloc);
    const resp = try sign.wrapInResponse(alloc, signed.xml);
    alloc.free(signed.xml);
    signed.xml = resp;
    return signed;
}

fn authnWithLoa(comptime loa: []const u8) []const u8 {
    return "<saml:AuthnStatement AuthnInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:AuthnContext><saml:AuthnContextClassRef>" ++ loa ++
        "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";
}

// ── sender-vouches ───────────────────────────────────────────────────────────

test "sender-vouches: accepted under .sender_vouches policy" {
    const alloc = testing.allocator;
    var s = try mint(alloc, sv_confirmation, conditions_valid, "");
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .sender_vouches;
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "sender-vouches: accepted under .either policy" {
    const alloc = testing.allocator;
    var s = try mint(alloc, sv_confirmation, conditions_valid, "");
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .either;
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "sender-vouches: rejected under default .bearer policy -> SubjectConfirmationMethodNotAllowed" {
    const alloc = testing.allocator;
    var s = try mint(alloc, sv_confirmation, conditions_valid, "");
    defer s.deinit(alloc);

    const cfg = baseConfig(s.key); // default subject_confirmation = .bearer
    try testing.expectError(error.SubjectConfirmationMethodNotAllowed, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "sender-vouches: assertion Conditions still enforced (expired -> AssertionExpired)" {
    const alloc = testing.allocator;
    var s = try mint(alloc, sv_confirmation, conditions_expired, "");
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .sender_vouches;
    try testing.expectError(error.AssertionExpired, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "sender-vouches policy: a Bearer confirmation is rejected -> SubjectConfirmationMethodNotAllowed" {
    const alloc = testing.allocator;
    var s = try mint(alloc, bearer_confirmation, conditions_valid, "");
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.subject_confirmation = .sender_vouches;
    try testing.expectError(error.SubjectConfirmationMethodNotAllowed, saml.consumeResponseXml(alloc, s.xml, cfg));
}

// ── Level of Assurance ───────────────────────────────────────────────────────

test "LoA: returned high meets required substantial -> accepted" {
    const alloc = testing.allocator;
    var s = try mint(alloc, bearer_confirmation, conditions_valid, authnWithLoa("http://eidas.europa.eu/LoA/high"));
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.required_loa = "http://eidas.europa.eu/LoA/substantial";
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("http://eidas.europa.eu/LoA/high", res.authn_context_class_ref.?);
}

test "LoA: returned substantial meets required substantial (equal) -> accepted" {
    const alloc = testing.allocator;
    var s = try mint(alloc, bearer_confirmation, conditions_valid, authnWithLoa("http://eidas.europa.eu/LoA/substantial"));
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.required_loa = "http://eidas.europa.eu/LoA/substantial";
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("http://eidas.europa.eu/LoA/substantial", res.authn_context_class_ref.?);
}

test "LoA: returned low below required high -> LevelOfAssuranceInsufficient" {
    const alloc = testing.allocator;
    var s = try mint(alloc, bearer_confirmation, conditions_valid, authnWithLoa("http://eidas.europa.eu/LoA/low"));
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.required_loa = "http://eidas.europa.eu/LoA/high";
    try testing.expectError(error.LevelOfAssuranceInsufficient, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "LoA: absent AuthnContextClassRef with a requirement -> LevelOfAssuranceInsufficient" {
    const alloc = testing.allocator;
    // AuthnStatement present but no AuthnContext/ClassRef.
    var s = try mint(alloc, bearer_confirmation, conditions_valid, "<saml:AuthnStatement AuthnInstant=\"2024-06-01T12:00:00Z\"/>");
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.required_loa = "http://eidas.europa.eu/LoA/low";
    try testing.expectError(error.LevelOfAssuranceInsufficient, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "LoA: no requirement (default null) accepts any/absent LoA (positive control)" {
    const alloc = testing.allocator;
    var s = try mint(alloc, bearer_confirmation, conditions_valid, authnWithLoa("http://eidas.europa.eu/LoA/low"));
    defer s.deinit(alloc);

    const cfg = baseConfig(s.key); // required_loa stays null
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("http://eidas.europa.eu/LoA/low", res.authn_context_class_ref.?);
}

test "LoA: non-eIDAS class ref requires an exact match -> accepted when equal" {
    const alloc = testing.allocator;
    const custom = "urn:example:loa:strong";
    var s = try mint(alloc, bearer_confirmation, conditions_valid, authnWithLoa("urn:example:loa:strong"));
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.required_loa = custom;
    var res = try saml.consumeResponseXml(alloc, s.xml, cfg);
    defer res.deinit();
    try testing.expectEqualStrings(custom, res.authn_context_class_ref.?);
}

test "LoA: non-eIDAS class ref mismatch -> LevelOfAssuranceInsufficient" {
    const alloc = testing.allocator;
    var s = try mint(alloc, bearer_confirmation, conditions_valid, authnWithLoa("urn:example:loa:weak"));
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.required_loa = "urn:example:loa:strong";
    try testing.expectError(error.LevelOfAssuranceInsufficient, saml.consumeResponseXml(alloc, s.xml, cfg));
}

test "LoA: eIDAS requirement against a non-eIDAS returned class ref -> LevelOfAssuranceInsufficient" {
    const alloc = testing.allocator;
    var s = try mint(alloc, bearer_confirmation, conditions_valid, authnWithLoa("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"));
    defer s.deinit(alloc);

    var cfg = baseConfig(s.key);
    cfg.required_loa = "http://eidas.europa.eu/LoA/low";
    try testing.expectError(error.LevelOfAssuranceInsufficient, saml.consumeResponseXml(alloc, s.xml, cfg));
}
