// SPDX-License-Identifier: MIT
//! End-to-end tests for a **Response-level** enveloped signature (as opposed
//! to the far more common assertion-level one the shipped fixture carries):
//! `<ds:Signature>` is a direct child of `<samlp:Response>` and covers the
//! whole Response, per `verifyCovering`'s branch 2
//! (`config.signature_policy != .assertion`). Minted fresh with
//! `test_sign.signResponse`, over an UNSIGNED assertion, so the assertion-
//! level branch has nothing to find and these genuinely exercise the
//! Response-level path rather than falling back to it.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const sign = @import("test_sign.zig");

const response_id = "_m28resp";
const assertion_id = "_m28asrt";

/// A plain, UNSIGNED, self-contained assertion — same subject/conditions
/// shape as `fixtures.signed_response`'s, minus the `<ds:Signature>`.
const unsigned_assertion_xml = "<saml:Assertion ID=\"" ++ assertion_id ++ "\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
    "<saml:Issuer>" ++ fx.idp_entity_id ++ "</saml:Issuer>" ++
    "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.org</saml:NameID>" ++
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
    "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"" ++ fx.acs_url ++ "\" InResponseTo=\"" ++ fx.request_id ++ "\"/>" ++
    "</saml:SubjectConfirmation></saml:Subject>" ++
    "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
    "<saml:AudienceRestriction><saml:Audience>" ++ fx.sp_entity_id ++ "</saml:Audience></saml:AudienceRestriction></saml:Conditions>" ++
    "</saml:Assertion>";

fn mint(alloc: std.mem.Allocator, seed: u64) !sign.Signed {
    return sign.signResponse(alloc, seed, response_id, "2024-06-01T12:00:00Z", fx.acs_url, fx.request_id, fx.idp_entity_id, unsigned_assertion_xml);
}

fn cfg(idp_key: @import("xmldsig").VerifyKey, now: i64) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = idp_key,
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = now,
        .expected_in_response_to = fx.request_id,
    };
}

test "response-level signature: the positive control is genuinely accepted" {
    // Establishes the minted fixture itself is sound BEFORE the corruption
    // test below leans on it — a signature-policy-default (`.either`) config
    // reaching the Response-level branch because the assertion carries none
    // of its own.
    const alloc = testing.allocator;
    var signed = try mint(alloc, 0xB28_00D);
    defer signed.deinit(alloc);

    var res = try saml.consumeResponseXml(alloc, signed.xml, cfg(signed.key, fx.t_valid));
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expectEqualStrings(assertion_id, res.assertion_id);
}

test "M28 teeth: a genuinely Response-level signature that fails to verify is rejected (SignatureInvalid)" {
    // Nothing in the suite before this presented a STRUCTURALLY valid
    // Response-level `<ds:Signature>` (one reference, resolves to the
    // Response's own ID) whose RSA check simply fails — every existing
    // Response-level case either has no signature at all (`SignatureMissing`)
    // or one that is valid-but-mispointed (`SignatureWrappingDetected`,
    // `test_xsw.zig`'s "moved signature" case). Neither reaches
    // `if (!res.valid) return error.SignatureInvalid;` in `verifyCovering`'s
    // branch 2 (2026-09 A1 audit F9/M28) — its assertion-level twin (the
    // fixture's own tamper test in `test_xsw.zig`) is covered; this one
    // was not.
    const alloc = testing.allocator;
    var signed = try mint(alloc, 0xB28_BAD);
    defer signed.deinit(alloc);

    // Corrupt one base64 char of the (Response-level) SignatureValue. Still
    // structurally a well-formed, single-reference, correctly-pointed
    // signature -- xmldsig's RSA check is what now fails.
    const marker = "<ds:SignatureValue>";
    const at = std.mem.indexOf(u8, signed.xml, marker).? + marker.len + 4;
    signed.xml[at] = if (signed.xml[at] == 'A') 'B' else 'A';

    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(alloc, signed.xml, cfg(signed.key, fx.t_valid)));
}
