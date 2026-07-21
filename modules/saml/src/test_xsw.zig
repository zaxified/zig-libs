// SPDX-License-Identifier: MIT
//! XML-Signature-Wrapping (XSW) attack suite — the module's headline security
//! tests. Every fixture here is a STRING manipulation of the genuinely-signed
//! `fixtures.signed_response`: an XSW attacker never holds the IdP signing key,
//! so a real attack can only wrap / inject / move the existing valid signature,
//! never forge a new one. Each attack must be rejected; a pristine control
//! passes.
//!
//! The defense mechanism under test (`signedTargetMatches` in root.zig): after
//! xmldsig proves a signature covers "the element whose ID = X", we resolve X to
//! a node POINTER and require it to be identical to the assertion we consume
//! (its unique-ID lookup is the same one xmldsig used, and `xml` forbids
//! duplicate IDs). A valid-but-mispointed signature is `SignatureWrappingDetected`.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");

const sig_open = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">";
const sig_close = "</ds:Signature>";
const asrt_open = "<saml:Assertion ID=";
const asrt_close = "</saml:Assertion>";

/// Return the inclusive substring of `hay` from `open` through the first `close`
/// after it.
fn block(hay: []const u8, open: []const u8, close: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, hay, open).?;
    const j = std.mem.indexOfPos(u8, hay, i, close).? + close.len;
    return hay[i..j];
}

fn cfg(now: i64) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = fx.idpKey(),
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = now,
        .expected_in_response_to = fx.request_id,
    };
}

// An evil assertion body (different ID, attacker NameID) that would authenticate
// the wrong subject if it were ever consumed.
const evil_subject_and_conditions =
    "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">attacker@evil.example</saml:NameID>" ++
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
    "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
    "</saml:SubjectConfirmation></saml:Subject>" ++
    "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
    "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>";

test "XSW control: the pristine signed fixture passes" {
    var res = try saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg(fx.t_valid));
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "XSW: tampering content under the signature breaks the digest" {
    const alloc = testing.allocator;
    // NameID/email value live inside the signed assertion; changing them must
    // invalidate the reference digest.
    const tampered = try std.mem.replaceOwned(u8, alloc, fx.signed_response, "alice@example.org", "mallory@evil.example");
    defer alloc.free(tampered);
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(alloc, tampered, cfg(fx.t_valid)));
}

test "XSW: stripping the signature entirely is rejected (no unsigned downgrade)" {
    const alloc = testing.allocator;
    const sig = block(fx.signed_response, sig_open, sig_close);
    const unsigned = try std.mem.replaceOwned(u8, alloc, fx.signed_response, sig, "");
    defer alloc.free(unsigned);
    try testing.expectError(error.SignatureMissing, saml.consumeResponseXml(alloc, unsigned, cfg(fx.t_valid)));
}

test "XSW: injected sibling assertion (attacker NameID) is rejected" {
    const alloc = testing.allocator;
    // A second, unsigned assertion inserted before the legit one. Two direct-
    // child assertions -> refused outright.
    const forged = "<saml:Assertion ID=\"_evilsibling\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>https://idp.example.org/saml</saml:Issuer>" ++ evil_subject_and_conditions ++ "</saml:Assertion>";
    const injected = try std.mem.replaceOwned(u8, alloc, fx.signed_response, "</samlp:Status>", "</samlp:Status>" ++ forged);
    defer alloc.free(injected);
    try testing.expectError(error.MultipleAssertions, saml.consumeResponseXml(alloc, injected, cfg(fx.t_valid)));
}

test "XSW: same-ID injected assertion is rejected at parse (duplicate ID guard)" {
    const alloc = testing.allocator;
    // Reuse the legit assertion's ID — the hardened parser refuses duplicate IDs.
    const forged = "<saml:Assertion ID=\"" ++ fx.assertion_id ++ "\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>https://idp.example.org/saml</saml:Issuer>" ++ evil_subject_and_conditions ++ "</saml:Assertion>";
    const injected = try std.mem.replaceOwned(u8, alloc, fx.signed_response, "</samlp:Status>", "</samlp:Status>" ++ forged);
    defer alloc.free(injected);
    try testing.expectError(error.MalformedResponse, saml.consumeResponseXml(alloc, injected, cfg(fx.t_valid)));
}

test "XSW: classic wrap — evil consumed assertion carries a signature pointing at a buried legit one" {
    const alloc = testing.allocator;
    const legit_asrt = block(fx.signed_response, asrt_open, asrt_close);
    const legit_sig = block(fx.signed_response, sig_open, sig_close);

    // The legit assertion, with its own signature removed, keeps ID = assertion_id
    // and is buried inside a wrapper. Exclusive C14N makes its canonical form
    // independent of this new position, so the *digest still matches*.
    const legit_nosig = try std.mem.replaceOwned(u8, alloc, legit_asrt, legit_sig, "");
    defer alloc.free(legit_nosig);

    // The evil, consumed assertion (different ID) carries a COPY of the legit
    // signature (which references #assertion_id) as a direct child.
    const evil = try std.fmt.allocPrint(alloc, "<saml:Assertion ID=\"_evilwrap\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>https://idp.example.org/saml</saml:Issuer>{s}{s}<wrapper>{s}</wrapper></saml:Assertion>", .{ legit_sig, evil_subject_and_conditions, legit_nosig });
    defer alloc.free(evil);

    const attack = try std.mem.replaceOwned(u8, alloc, fx.signed_response, legit_asrt, evil);
    defer alloc.free(attack);

    // The signature verifies (it genuinely covers the buried legit assertion),
    // but that element is NOT the consumed one -> wrapping detected.
    try testing.expectError(error.SignatureWrappingDetected, saml.consumeResponseXml(alloc, attack, cfg(fx.t_valid)));
}

test "XSW: moved signature — a Response-level signature referencing the assertion" {
    const alloc = testing.allocator;
    const legit_sig = block(fx.signed_response, sig_open, sig_close);

    // Remove the signature from the assertion, then re-attach it at Response
    // level (before Status). It still validly covers the assertion by ID, but a
    // Response-level signature must cover the Response element, not a child.
    const without = try std.mem.replaceOwned(u8, alloc, fx.signed_response, legit_sig, "");
    defer alloc.free(without);
    const replacement = try std.fmt.allocPrint(alloc, "{s}<samlp:Status>", .{legit_sig});
    defer alloc.free(replacement);
    const moved = try std.mem.replaceOwned(u8, alloc, without, "<samlp:Status>", replacement);
    defer alloc.free(moved);

    try testing.expectError(error.SignatureWrappingDetected, saml.consumeResponseXml(alloc, moved, cfg(fx.t_valid)));
}

test "XSW: signature Reference pointing at a non-existent decoy is rejected" {
    const alloc = testing.allocator;
    // Repoint the Reference URI to a decoy id. This both fails to resolve and
    // corrupts the signed SignedInfo octets -> invalid.
    const decoy = try std.mem.replaceOwned(u8, alloc, fx.signed_response, "URI=\"#" ++ fx.assertion_id ++ "\"", "URI=\"#_decoy\"");
    defer alloc.free(decoy);
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(alloc, decoy, cfg(fx.t_valid)));
}

test "XSW: response-signature policy rejects an assertion-only signature" {
    const alloc = testing.allocator;
    var c = cfg(fx.t_valid);
    c.signature_policy = .response; // require the Response be signed
    // The fixture signs only the Assertion -> nothing at Response level.
    try testing.expectError(error.SignatureMissing, saml.consumeResponseXml(alloc, fx.signed_response, c));
}
