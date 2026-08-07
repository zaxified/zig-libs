// SPDX-License-Identifier: MIT
//! `<saml:Issuer>` enforcement — the P-05 / P-06 regression net.
//!
//! THE DEFECT THESE TESTS PIN. Every `<Issuer>` check in this module used to be
//! spelled `if (childEl(root, saml_ns, "Issuer")) |iss| { …compare… }`, and the
//! Assertion's own `<Issuer>` was not checked at all. Together that made
//! `Config.idp_entity_id` **opt-out by omission**: an attacker who simply
//! deleted the element skipped the comparison entirely, on every message type
//! this module consumes. That is an authentication bypass in the SP, not a
//! hygiene gap, and it is one defect with one fix — enforcement has to fail
//! CLOSED on a missing element wherever the profile mandates one.
//!
//! WHAT THE SPECS ACTUALLY SAY (fetched and read, not recalled):
//!
//!   * `saml-core-2.0-os` §2.3.3 "Element <Assertion>":
//!         <Issuer> [Required]
//!             The SAML authority that is making the claim(s) in the assertion.
//!             The issuer SHOULD be unambiguous to the intended relying
//!             parties.
//!     and the schema fragment for `AssertionType` declares
//!     `<element ref="saml:Issuer"/>` with no `minOccurs`, i.e. minOccurs=1.
//!
//!   * `saml-profiles-2.0-os` §4.1.4.2 "<Response> Usage":
//!         The <Issuer> element MAY be omitted, but if present it MUST contain
//!         the unique identifier of the issuing identity provider …
//!         It MUST contain at least one <Assertion>. Each assertion's <Issuer>
//!         element MUST contain the unique identifier of the issuing identity
//!         provider …
//!     So the RESPONSE-level element is genuinely optional and must stay that
//!     way; the ASSERTION-level one is not, and every Response carries an
//!     assertion. That is why closing the bypass at the assertion is both
//!     sufficient and spec-conformant.
//!
//!   * `saml-profiles-2.0-os` §4.4.4.1 "<LogoutRequest> Usage":
//!         The <Issuer> element MUST be present and MUST contain the unique
//!         identifier of the requesting entity …
//!   * `saml-profiles-2.0-os` §4.4.4.2 "<LogoutResponse> Usage":
//!         The <Issuer> element MUST be present and MUST contain the unique
//!         identifier of the responding entity …
//!   * `saml-profiles-2.0-os` §5.4.2 "<ArtifactResponse> Usage":
//!         The <Issuer> element MUST be present and MUST contain the unique
//!         identifier of the artifact issuer …
//!
//! CORRECTION TO THE AUDIT: the finding cited SAMLProf §4.1.4.3 as the source
//! of the SP's obligation to verify the assertion Issuer. It is not.
//! §4.1.4.3 "<Response> Message Processing Rules" lists signatures, Recipient,
//! NotOnOrAfter, InResponseTo, "valid in other respects" and Address, and never
//! mentions <Issuer>. §4.1.4.2 is the section that imposes the requirement.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const sign = @import("test_sign.zig");
const rsa = @import("rsa");

const samlp_decl = "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"";
const saml_decl = "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"";
const evil_entity_id = "https://attacker.example.net/saml";

/// The body of an otherwise perfectly valid assertion (Subject + Conditions),
/// shared by the cases below so the ONLY variable between them is the Issuer.
const valid_body =
    "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">bob@example.org</saml:NameID>" ++
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
    "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
    "</saml:SubjectConfirmation></saml:Subject>" ++
    "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
    "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>";

fn baseConfig(key: @import("xmldsig").VerifyKey) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = key,
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = fx.t_valid,
        .expected_in_response_to = fx.request_id,
    };
}

/// Wrap an assertion in a Response that carries NO Response-level `<Issuer>` —
/// the exact bypass shape: with the old code this was the whole of
/// `idp_entity_id` enforcement, so omitting it skipped every issuer check in
/// the request.
fn wrapInResponseWithoutIssuer(alloc: std.mem.Allocator, assertion_xml: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "<samlp:Response " ++ samlp_decl ++ " " ++ saml_decl ++ " " ++
        "ID=\"_resp_no_issuer\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\" " ++
        "Destination=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\">" ++
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" ++
        "{s}</samlp:Response>", .{assertion_xml});
}

// ── P-05 / P-06: the bypass itself ──────────────────────────────────────────

test "TEETH (P-05/P-06): assertion with NO <Issuer>, in a Response with no <Issuer>, is refused" {
    // THE BYPASS, end to end. Every element the old code consulted is absent,
    // so the old code performed ZERO comparisons against `idp_entity_id` and
    // returned a fully populated AuthnResult — an authenticated session for a
    // response that never named an issuer. The signature is genuine and covers
    // the issuer-less assertion, so `SignatureInvalid` cannot be what rejects
    // it; only the presence check can.
    const alloc = testing.allocator;

    var signed = try sign.signAssertionWithoutIssuer(alloc, 0x155_0001, "_noiss01", "2024-06-01T12:00:00Z", valid_body);
    defer signed.deinit(alloc);

    const resp = try wrapInResponseWithoutIssuer(alloc, signed.xml);
    defer alloc.free(resp);
    try testing.expect(std.mem.indexOf(u8, resp, "saml:Issuer") == null); // genuinely absent everywhere

    try testing.expectError(
        error.IssuerMissing,
        saml.consumeResponseXml(alloc, resp, baseConfig(signed.key)),
    );
}

test "TEETH (P-05): assertion <Issuer> naming a DIFFERENT entityID is refused" {
    // F1 proper: the assertion's own Issuer was never compared to anything.
    // Here the signature verifies under the configured `idp_key` — the
    // key-sharing-federation / proxy-IdP case the finding names — but the
    // assertion claims to come from someone else. Only an assertion-level
    // VALUE check can catch this; the Response-level element is correct.
    const alloc = testing.allocator;

    var signed = try sign.signAssertion(alloc, 0x155_0002, evil_entity_id, "_wrongiss01", "2024-06-01T12:00:00Z", valid_body);
    defer signed.deinit(alloc);

    const resp = try sign.wrapInResponse(alloc, signed.xml); // Response Issuer = the real IdP
    defer alloc.free(resp);

    try testing.expectError(
        error.IssuerMismatch,
        saml.consumeResponseXml(alloc, resp, baseConfig(signed.key)),
    );
}

test "TEETH (P-06): assertion with NO <Issuer> is refused even when the Response <Issuer> is correct" {
    // Isolates the assertion-level presence requirement from the Response-level
    // one: the Response names the right IdP, so the old code's single check
    // PASSED, and the assertion still asserted everything without ever naming
    // an issuer. SAMLCore §2.3.3 makes that malformed.
    const alloc = testing.allocator;

    var signed = try sign.signAssertionWithoutIssuer(alloc, 0x155_0003, "_noiss02", "2024-06-01T12:00:00Z", valid_body);
    defer signed.deinit(alloc);

    const resp = try sign.wrapInResponse(alloc, signed.xml);
    defer alloc.free(resp);

    try testing.expectError(
        error.IssuerMissing,
        saml.consumeResponseXml(alloc, resp, baseConfig(signed.key)),
    );
}

test "POSITIVE CONTROL: a Response with no <Issuer> but a correct assertion <Issuer> is ACCEPTED" {
    // SAMLProf §4.1.4.2: "The <Issuer> element MAY be omitted". Tightening the
    // Response level into a hard requirement would refuse conformant IdPs, so
    // this test exists to make that over-tightening fail. Without it, "make
    // omission fail closed" reads as license to require the element
    // everywhere, which the profile forbids.
    const alloc = testing.allocator;

    var signed = try sign.signAssertion(alloc, 0x155_0004, fx.idp_entity_id, "_okiss01", "2024-06-01T12:00:00Z", valid_body);
    defer signed.deinit(alloc);

    const resp = try wrapInResponseWithoutIssuer(alloc, signed.xml);
    defer alloc.free(resp);

    var res = try saml.consumeResponseXml(alloc, resp, baseConfig(signed.key));
    defer res.deinit();
    try testing.expectEqualStrings("bob@example.org", res.name_id);
}

// ── P-06: the other three consumers ─────────────────────────────────────────

const slo_idp_key_seed = 0x155_1000;

fn makeKey(seed: u64) !rsa.KeyPair {
    var prng = std.Random.DefaultPrng.init(seed);
    return rsa.generate(prng.random(), 1024, 65537);
}

test "TEETH (P-06): LogoutRequest with no <Issuer> is refused (SAMLProf 4.4.4.1)" {
    // Consumed via `.redirect_verified`, the legitimate "signature already
    // checked out of band" path — so nothing but the Issuer rule can reject
    // it. With the old code this request was ACCEPTED and returned
    // alice@example.org: an unauthenticated party could log the user out
    // without ever naming the IdP.
    const alloc = testing.allocator;
    const kp = try makeKey(slo_idp_key_seed + 1);

    const req = "<samlp:LogoutRequest " ++ samlp_decl ++ " " ++ saml_decl ++ " " ++
        "ID=\"_lr_noiss\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:NameID>alice@example.org</saml:NameID>" ++
        "</samlp:LogoutRequest>";

    try testing.expectError(error.IssuerMissing, saml.consumeLogoutRequestXml(alloc, req, .redirect_verified, .{
        .idp_entity_id = "https://idp.example.org/saml",
        .idp_key = .{ .rsa = kp.public_key },
        .now_unix = 1717243230,
    }));
}

test "TEETH (P-06): LogoutResponse with no <Issuer> is refused (SAMLProf 4.4.4.2)" {
    const alloc = testing.allocator;
    const kp = try makeKey(slo_idp_key_seed + 2);

    const resp = "<samlp:LogoutResponse " ++ samlp_decl ++ " " ++ saml_decl ++ " " ++
        "ID=\"_lresp_noiss\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\" InResponseTo=\"_lr_out_42\">" ++
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" ++
        "</samlp:LogoutResponse>";

    try testing.expectError(error.IssuerMissing, saml.consumeLogoutResponseXml(alloc, resp, .redirect_verified, .{
        .idp_entity_id = "https://idp.example.org/saml",
        .idp_key = .{ .rsa = kp.public_key },
        .now_unix = 1717243230,
        .expected_in_response_to = "_lr_out_42",
    }));
}

test "TEETH (P-06): ArtifactResponse with no <Issuer> is refused (SAMLProf 5.4.2)" {
    // `consumeArtifactResponseSoap` has no unsigned path, so the observable
    // here is weaker than the two above and rests on CHECK ORDER: the Issuer
    // rule runs before signature verification, so the old code reached
    // `SignatureMissing` and the fixed code stops at `IssuerMissing`. That
    // still makes the presence check load-bearing — remove it and this test
    // reports the wrong error — but unlike the LogoutRequest case it does not
    // demonstrate an outright accept.
    const alloc = testing.allocator;
    const kp = try makeKey(slo_idp_key_seed + 3);

    const soap = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>" ++
        "<samlp:ArtifactResponse " ++ samlp_decl ++ " " ++ saml_decl ++ " " ++
        "ID=\"_arresp_noiss\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\" InResponseTo=\"_ar002\">" ++
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" ++
        "</samlp:ArtifactResponse></soap:Body></soap:Envelope>";

    try testing.expectError(error.IssuerMissing, saml.consumeArtifactResponseSoap(alloc, soap, .{
        .idp_entity_id = "https://idp.example.org/saml",
        .idp_key = .{ .rsa = kp.public_key },
        .now_unix = 1717243200,
        .expected_in_response_to = "_ar002",
    }));
}
