// SPDX-License-Identifier: MIT
//! IdP certificate rollover: more than one trusted IdP verification key
//! (`Config.additional_idp_keys` and its twins on the SLO / Artifact configs).
//!
//! Anchor: the Response tests run over `fixtures.signed_response`, whose
//! signature was made by an INDEPENDENT toolchain (openssl + lxml), and the
//! encrypted case over `test_encrypted_external.zig`'s xmlsec1 ciphertext — so
//! "accepted under the second key" is a verdict about a signature this module
//! did not produce. The wrong/decoy keys are locally generated test material.
//! The SLO case is a CONSTRUCTED self round-trip, like the rest of `test_slo.zig`.
//!
//! Hostile-input properties pinned here: adding keys never weakens a check
//! that does not depend on the key — tamper, XSW, missing signature and the
//! `<KeyInfo>`-is-never-trusted rule all give the same verdict as with one key.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const rsa = @import("rsa");
const xmldsig = @import("xmldsig");

fn otherRsaKey(seed: u64) !xmldsig.VerifyKey {
    var prng = std.Random.DefaultPrng.init(seed);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    return .{ .rsa = kp.public_key };
}

/// A valid P-256 point (the generator) — a real EC key that did not sign
/// anything here, so an RSA signature checked against it is
/// `KeyAlgorithmMismatch` inside `xmldsig`.
fn p256Generator() [65]u8 {
    return std.crypto.ecc.P256.basePoint.toUncompressedSec1();
}

fn cfg(primary: xmldsig.VerifyKey, additional: []const xmldsig.VerifyKey) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = primary,
        .additional_idp_keys = additional,
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = fx.t_valid,
        .expected_in_response_to = fx.request_id,
    };
}

test "rollover: single-key config is unchanged (index 0)" {
    var res = try saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg(fx.idpKey(), &.{}));
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expectEqual(@as(usize, 0), res.idp_key_index);
}

test "rollover: EXTERNAL signature verifies under an ADDITIONAL key (index reports which)" {
    const old = try otherRsaKey(0x5011_0001);
    const decoy = try otherRsaKey(0x5011_0002);
    var res = try saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg(old, &.{ decoy, fx.idpKey() }));
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expectEqual(@as(usize, 2), res.idp_key_index);
}

test "rollover: the right key as primary with extras still reports index 0" {
    const next = try otherRsaKey(0x5011_0003);
    var res = try saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg(fx.idpKey(), &.{next}));
    defer res.deinit();
    try testing.expectEqual(@as(usize, 0), res.idp_key_index);
}

test "rollover: no configured key verifies -> SignatureInvalid" {
    const a = try otherRsaKey(0x5011_0004);
    const b = try otherRsaKey(0x5011_0005);
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg(a, &.{b})));
}

test "rollover: a key of the other algorithm is skipped, not fatal (EC primary, RSA additional)" {
    const point = p256Generator();
    const ec: xmldsig.VerifyKey = .{ .ecdsa_p256_sec1 = &point };
    var res = try saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg(ec, &.{fx.idpKey()}));
    defer res.deinit();
    try testing.expectEqual(@as(usize, 1), res.idp_key_index);
    // ... and an EC-only key set cannot accept the RSA signature at all.
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(testing.allocator, fx.signed_response, cfg(ec, &.{})));
}

test "rollover: tampered content is still SignatureInvalid with the signer in the set" {
    const alloc = testing.allocator;
    const tampered = try std.mem.replaceOwned(u8, alloc, fx.signed_response, "alice@example.org", "mallory@evil.example");
    defer alloc.free(tampered);
    const old = try otherRsaKey(0x5011_0006);
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(alloc, tampered, cfg(old, &.{fx.idpKey()})));
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(alloc, tampered, cfg(fx.idpKey(), &.{old})));
}

test "rollover: XSW classic wrap is still detected whichever key verifies" {
    // Same construction as `test_xsw.zig`'s classic wrap: the legit signature
    // is copied onto an evil consumed assertion and the legit assertion is
    // buried. The signature genuinely verifies — under the ADDITIONAL key here —
    // and must still be refused because it does not cover what is consumed.
    const alloc = testing.allocator;
    const sig_open = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">";
    const asrt_open = "<saml:Assertion ID=";
    const si = std.mem.indexOf(u8, fx.signed_response, sig_open).?;
    const legit_sig = fx.signed_response[si .. std.mem.indexOfPos(u8, fx.signed_response, si, "</ds:Signature>").? + "</ds:Signature>".len];
    const ai = std.mem.indexOf(u8, fx.signed_response, asrt_open).?;
    const legit_asrt = fx.signed_response[ai .. std.mem.indexOfPos(u8, fx.signed_response, ai, "</saml:Assertion>").? + "</saml:Assertion>".len];
    const legit_nosig = try std.mem.replaceOwned(u8, alloc, legit_asrt, legit_sig, "");
    defer alloc.free(legit_nosig);
    const evil = try std.fmt.allocPrint(alloc, "<saml:Assertion ID=\"_evilwrap\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>https://idp.example.org/saml</saml:Issuer>{s}" ++
        "<saml:Subject><saml:NameID>attacker@evil.example</saml:NameID>" ++
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
        "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
        "</saml:SubjectConfirmation></saml:Subject>" ++
        "<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>" ++
        "<wrapper>{s}</wrapper></saml:Assertion>", .{ legit_sig, legit_nosig });
    defer alloc.free(evil);
    const attack = try std.mem.replaceOwned(u8, alloc, fx.signed_response, legit_asrt, evil);
    defer alloc.free(attack);

    const old = try otherRsaKey(0x5011_0007);
    try testing.expectError(error.SignatureWrappingDetected, saml.consumeResponseXml(alloc, attack, cfg(old, &.{fx.idpKey()})));
}

test "rollover: an unsigned response is SignatureMissing regardless of the key set" {
    const alloc = testing.allocator;
    const sig_open = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">";
    const si = std.mem.indexOf(u8, fx.signed_response, sig_open).?;
    const legit_sig = fx.signed_response[si .. std.mem.indexOfPos(u8, fx.signed_response, si, "</ds:Signature>").? + "</ds:Signature>".len];
    const unsigned = try std.mem.replaceOwned(u8, alloc, fx.signed_response, legit_sig, "");
    defer alloc.free(unsigned);
    const old = try otherRsaKey(0x5011_0008);
    try testing.expectError(error.SignatureMissing, saml.consumeResponseXml(alloc, unsigned, cfg(old, &.{fx.idpKey()})));
}

test "rollover: LogoutRequest verifies under an additional key (CONSTRUCTED)" {
    const alloc = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5011_0009);
    var signer: rsa.KeyPair = undefined;
    try rsa.generate(&signer, prng.random(), 1024, 65537);
    const old = try otherRsaKey(0x5011_000A);
    const req = try saml.buildLogoutRequest(alloc, .{
        .id = "_lr_roll",
        .issue_instant = "2024-06-01T12:00:00Z",
        .issuer = fx.idp_entity_id,
        .name_id = "alice@example.org",
        .sign_with = .{ .rsa = &signer.secret_key },
    });
    defer alloc.free(req);
    var c: saml.LogoutRequestConfig = .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = old,
        .additional_idp_keys = &.{.{ .rsa = signer.public_key }},
        .now_unix = 1717243230,
    };
    var res = try saml.consumeLogoutRequestXml(alloc, req, .embedded, c);
    res.deinit();
    c.additional_idp_keys = &.{};
    try testing.expectError(error.SignatureInvalid, saml.consumeLogoutRequestXml(alloc, req, .embedded, c));
}
