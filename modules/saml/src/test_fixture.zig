// SPDX-License-Identifier: MIT
//! End-to-end tests over a genuinely-signed SAML Response fixture (see
//! fixtures.zig for provenance): the positive control, full extraction, and the
//! conditions / subject-confirmation / status / issuer "teeth" — each a rejection
//! with a matching positive control.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");

fn baseConfig(now: i64) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = fx.idpKey(),
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = now,
        .expected_in_response_to = fx.request_id,
    };
}

test "fixture: valid signed Response verifies end-to-end and extracts the subject" {
    var res = try saml.consumeResponseXml(testing.allocator, fx.signed_response, baseConfig(fx.t_valid));
    defer res.deinit();

    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expectEqualStrings("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", res.name_id_format.?);
    try testing.expectEqualStrings("https://sp.example.org/metadata", res.name_id_sp_qualifier.?);
    try testing.expectEqualStrings("sess-abc-123", res.session_index.?);
    try testing.expectEqualStrings(
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        res.authn_context_class_ref.?,
    );
    try testing.expectEqualStrings(fx.assertion_id, res.assertion_id);
    try testing.expect(!res.one_time_use);
    try testing.expectEqual(@as(i64, 1717243500), res.session_not_on_or_after.?);

    // Attributes, including a multi-valued one.
    const email = res.attribute("email").?;
    try testing.expectEqual(@as(usize, 1), email.len);
    try testing.expectEqualStrings("alice@example.org", email[0]);
    const groups = res.attribute("groups").?;
    try testing.expectEqual(@as(usize, 2), groups.len);
    try testing.expectEqualStrings("admins", groups[0]);
    try testing.expectEqualStrings("staff", groups[1]);
    try testing.expect(res.attribute("nonexistent") == null);
}

test "fixture: POST binding (base64) decodes then verifies" {
    const enc = std.base64.standard.Encoder;
    const buf = try testing.allocator.alloc(u8, enc.calcSize(fx.signed_response.len));
    defer testing.allocator.free(buf);
    const field = enc.encode(buf, fx.signed_response);

    var res = try saml.consumeResponse(testing.allocator, field, baseConfig(fx.t_valid));
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "fixture: KeyInfo cert DER is surfaced (untrusted, for pinning)" {
    var res = try saml.consumeResponseXml(testing.allocator, fx.signed_response, baseConfig(fx.t_valid));
    defer res.deinit();
    // The fixture's assertion signature has no KeyInfo, so there is nothing to pin.
    try testing.expect(res.x509_cert_der == null);
}

// ── conditions teeth (config/clock only — the signed bytes are untouched) ─────

test "teeth: expired assertion (now past Conditions NotOnOrAfter) is rejected" {
    try testing.expectError(
        error.AssertionExpired,
        saml.consumeResponseXml(testing.allocator, fx.signed_response, baseConfig(fx.t_after)),
    );
}

test "teeth: assertion not yet valid (now before NotBefore) is rejected" {
    try testing.expectError(
        error.AssertionNotYetValid,
        saml.consumeResponseXml(testing.allocator, fx.signed_response, baseConfig(fx.t_before)),
    );
}

test "teeth: wrong audience (SP not named) is rejected" {
    var cfg = baseConfig(fx.t_valid);
    cfg.sp_entity_id = "https://evil.example.com/metadata";
    try testing.expectError(error.AudienceMismatch, saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg));
}

test "teeth: InResponseTo mismatch (wrong pending request id) is rejected" {
    var cfg = baseConfig(fx.t_valid);
    cfg.expected_in_response_to = "some-other-request";
    try testing.expectError(error.InResponseToMismatch, saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg));
}

test "teeth: solicited flow rejects when no request was pending" {
    var cfg = baseConfig(fx.t_valid);
    cfg.expected_in_response_to = null; // and allow_idp_initiated stays false
    try testing.expectError(error.InResponseToMismatch, saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg));
}

test "teeth: wrong configured issuer is rejected" {
    var cfg = baseConfig(fx.t_valid);
    cfg.idp_entity_id = "https://impostor.example.com/saml";
    try testing.expectError(error.IssuerMismatch, saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg));
}

// ── teeth for values inside the signed assertion: we can't edit those without
//    breaking the signature, so we alter the Response-level Destination (which is
//    OUTSIDE the signed assertion, so the signature stays valid) to drive the
//    Recipient check. ─────────────────────────────────────────────────────────

test "teeth: recipient mismatch is rejected" {
    // Move the Response Destination (unsigned) to a new ACS and configure that
    // ACS. The Bearer Recipient (inside the signed assertion) still points at the
    // original ACS, so it now mismatches -> RecipientMismatch, and the signature
    // is unaffected.
    const alloc = testing.allocator;
    const moved = try std.mem.replaceOwned(
        u8,
        alloc,
        fx.signed_response,
        "Destination=\"https://sp.example.org/acs\"",
        "Destination=\"https://sp.example.org/acs2\"",
    );
    defer alloc.free(moved);
    var cfg = baseConfig(fx.t_valid);
    cfg.acs_url = "https://sp.example.org/acs2";
    try testing.expectError(error.RecipientMismatch, saml.consumeResponseXml(alloc, moved, cfg));
}

test "teeth: non-Success Status is rejected" {
    // StatusCode is outside the signed assertion; flip it to Requester.
    const alloc = testing.allocator;
    const failed = try std.mem.replaceOwned(
        u8,
        alloc,
        fx.signed_response,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "urn:oasis:names:tc:SAML:2.0:status:Requester",
    );
    defer alloc.free(failed);
    try testing.expectError(error.StatusNotSuccess, saml.consumeResponseXml(alloc, failed, baseConfig(fx.t_valid)));
}

test "teeth: Response Destination mismatch is rejected" {
    const alloc = testing.allocator;
    const moved = try std.mem.replaceOwned(
        u8,
        alloc,
        fx.signed_response,
        "Destination=\"https://sp.example.org/acs\"",
        "Destination=\"https://sp.example.org/somewhere-else\"",
    );
    defer alloc.free(moved);
    // acs_url still the original -> Destination check fails.
    try testing.expectError(error.DestinationMismatch, saml.consumeResponseXml(alloc, moved, baseConfig(fx.t_valid)));
}

test "teeth: wrong configured key fails the signature" {
    // A syntactically valid but wrong RSA key (different modulus) -> the SignedInfo
    // signature no longer verifies.
    const alloc = testing.allocator;
    var cfg = baseConfig(fx.t_valid);
    const RsaPub = @FieldType(@import("xmldsig").VerifyKey, "rsa");
    const wrong = try RsaPub.fromBytes(&([_]u8{0xC5} ** 256), &[_]u8{ 0x01, 0x00, 0x01 });
    cfg.idp_key = .{ .rsa = wrong };
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(alloc, fx.signed_response, cfg));
}

test "teeth: clock skew lets a just-expired assertion through within tolerance" {
    // now is 1 second past NotOnOrAfter (1717243500) but skew covers it.
    var cfg = baseConfig(1717243501);
    cfg.clock_skew_secs = 60;
    var res = try saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);

    // With zero skew the same instant is rejected.
    cfg.clock_skew_secs = 0;
    try testing.expectError(error.AssertionExpired, saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg));
}
