// SPDX-License-Identifier: MIT
//! End-to-end tests for `<saml:EncryptedID>` (an encrypted Subject NameID) and
//! `<saml:EncryptedAttribute>` (an encrypted attribute inside an otherwise
//! cleartext AttributeStatement), the remaining eIDAS encrypt residual.
//!
//! Both live INSIDE the signed assertion, so — unlike the whole-assertion
//! EncryptedAssertion tests — the fixture's signed octets cannot be edited into
//! them. Each test mints a FRESH signed assertion (see test_sign.zig) whose
//! Subject / AttributeStatement already carries the encrypted wrapper, then
//! consumes it with the SP decryption key configured. Decryption happens on the
//! already-signature-verified assertion (authenticated by enclosure).

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const sign = @import("test_sign.zig");
const enc = @import("test_encutil.zig");

const subject_confirmation =
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
    "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
    "</saml:SubjectConfirmation>";

const conditions =
    "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
    "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>";

const cleartext_nameid =
    "<saml:NameID SPNameQualifier=\"https://sp.example.org/metadata\" Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.org</saml:NameID>";

/// A standalone NameID (declares its own xmlns:saml) — the EncryptedID plaintext.
const nameid_plaintext =
    "<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" SPNameQualifier=\"https://sp.example.org/metadata\" Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.org</saml:NameID>";

/// A standalone Attribute (declares its own xmlns:saml) — the EncryptedAttribute plaintext.
const attribute_plaintext =
    "<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"clearance\"><saml:AttributeValue>top-secret</saml:AttributeValue></saml:Attribute>";

fn baseConfig(now: i64, idp_key: @import("xmldsig").VerifyKey) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = idp_key,
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = now,
        .expected_in_response_to = fx.request_id,
    };
}

/// Mint a signed Response whose Subject uses `subject_inner` (a NameID or an
/// EncryptedID) and whose AttributeStatement is `attr_statement`.
fn mintResponse(alloc: std.mem.Allocator, subject_inner: []const u8, attr_statement: []const u8) !sign.Signed {
    const after_issuer = try std.fmt.allocPrint(alloc, "<saml:Subject>{s}{s}</saml:Subject>{s}{s}", .{ subject_inner, subject_confirmation, conditions, attr_statement });
    defer alloc.free(after_issuer);
    var signed = try sign.signAssertion(alloc, 0xEDA7, fx.idp_entity_id, "_encid01", "2024-06-01T12:00:00Z", after_issuer);
    errdefer signed.deinit(alloc);
    const resp = try sign.wrapInResponse(alloc, signed.xml);
    alloc.free(signed.xml);
    signed.xml = resp;
    return signed;
}

// ── EncryptedID ──────────────────────────────────────────────────────────────

test "EncryptedID: decrypts to the same NameID as the cleartext equivalent" {
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x5A11_E0DE);

    // Cleartext control.
    var clear_signed = try mintResponse(alloc, cleartext_nameid, "");
    defer clear_signed.deinit(alloc);
    var clear = try saml.consumeResponseXml(alloc, clear_signed.xml, baseConfig(fx.t_valid, clear_signed.key));
    defer clear.deinit();

    // Encrypted-ID variant.
    const enc_id = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedID", nameid_plaintext);
    defer alloc.free(enc_id);
    var enc_signed = try mintResponse(alloc, enc_id, "");
    defer enc_signed.deinit(alloc);
    var cfg = baseConfig(fx.t_valid, enc_signed.key);
    cfg.sp_decrypt_key = sp.secret_key;
    var res = try saml.consumeResponseXml(alloc, enc_signed.xml, cfg);
    defer res.deinit();

    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expectEqualStrings(clear.name_id, res.name_id);
    try testing.expectEqualStrings(clear.name_id_format.?, res.name_id_format.?);
    try testing.expectEqualStrings(clear.name_id_sp_qualifier.?, res.name_id_sp_qualifier.?);
}

test "EncryptedID: present but no sp_decrypt_key -> EncryptedIdUnsupported" {
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x5A11_E0DE);
    const enc_id = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedID", nameid_plaintext);
    defer alloc.free(enc_id);
    var signed = try mintResponse(alloc, enc_id, "");
    defer signed.deinit(alloc);
    // sp_decrypt_key stays null.
    try testing.expectError(
        error.EncryptedIdUnsupported,
        saml.consumeResponseXml(alloc, signed.xml, baseConfig(fx.t_valid, signed.key)),
    );
}

test "EncryptedID: wrong SP key -> IdDecryptionFailed (generic)" {
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x5A11_E0DE);
    const other = try enc.makeSpKey(0xDEAD_BEEF);
    const enc_id = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedID", nameid_plaintext);
    defer alloc.free(enc_id);
    var signed = try mintResponse(alloc, enc_id, "");
    defer signed.deinit(alloc);
    var cfg = baseConfig(fx.t_valid, signed.key);
    cfg.sp_decrypt_key = other.secret_key;
    try testing.expectError(error.IdDecryptionFailed, saml.consumeResponseXml(alloc, signed.xml, cfg));
}

// ── EncryptedAttribute ───────────────────────────────────────────────────────

const mixed_attr_statement =
    "<saml:AttributeStatement>" ++
    "<saml:Attribute Name=\"email\"><saml:AttributeValue>alice@example.org</saml:AttributeValue></saml:Attribute>" ++
    "{ENC}" ++
    "</saml:AttributeStatement>";

test "EncryptedAttribute: mixed cleartext + encrypted attributes all present" {
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x5A11_E0DE);

    const enc_attr = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedAttribute", attribute_plaintext);
    defer alloc.free(enc_attr);
    const stmt = try std.mem.replaceOwned(u8, alloc, mixed_attr_statement, "{ENC}", enc_attr);
    defer alloc.free(stmt);

    var signed = try mintResponse(alloc, cleartext_nameid, stmt);
    defer signed.deinit(alloc);
    var cfg = baseConfig(fx.t_valid, signed.key);
    cfg.sp_decrypt_key = sp.secret_key;
    var res = try saml.consumeResponseXml(alloc, signed.xml, cfg);
    defer res.deinit();

    // Cleartext attribute.
    try testing.expectEqualStrings("alice@example.org", res.attribute("email").?[0]);
    // Decrypted attribute merged alongside.
    const clearance = res.attribute("clearance") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), clearance.len);
    try testing.expectEqualStrings("top-secret", clearance[0]);
}

test "EncryptedAttribute: present but no sp_decrypt_key -> EncryptedAttributeUnsupported" {
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x5A11_E0DE);
    const enc_attr = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedAttribute", attribute_plaintext);
    defer alloc.free(enc_attr);
    const stmt = try std.mem.replaceOwned(u8, alloc, mixed_attr_statement, "{ENC}", enc_attr);
    defer alloc.free(stmt);
    var signed = try mintResponse(alloc, cleartext_nameid, stmt);
    defer signed.deinit(alloc);
    // sp_decrypt_key stays null.
    try testing.expectError(
        error.EncryptedAttributeUnsupported,
        saml.consumeResponseXml(alloc, signed.xml, baseConfig(fx.t_valid, signed.key)),
    );
}

test "EncryptedAttribute: wrong SP key -> AttributeDecryptionFailed (generic)" {
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x5A11_E0DE);
    const other = try enc.makeSpKey(0xDEAD_BEEF);
    const enc_attr = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedAttribute", attribute_plaintext);
    defer alloc.free(enc_attr);
    const stmt = try std.mem.replaceOwned(u8, alloc, mixed_attr_statement, "{ENC}", enc_attr);
    defer alloc.free(stmt);
    var signed = try mintResponse(alloc, cleartext_nameid, stmt);
    defer signed.deinit(alloc);
    var cfg = baseConfig(fx.t_valid, signed.key);
    cfg.sp_decrypt_key = other.secret_key;
    try testing.expectError(error.AttributeDecryptionFailed, saml.consumeResponseXml(alloc, signed.xml, cfg));
}

test "EncryptedID enclosure is authenticated: tampering the ciphertext breaks the signature" {
    // Flip a byte in the base64 CipherValue AFTER signing (a string edit of the
    // signed doc). The signature over the assertion covers the EncryptedID
    // ciphertext, so the tamper is caught BEFORE decryption is even attempted.
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x5A11_E0DE);
    const enc_id = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedID", nameid_plaintext);
    defer alloc.free(enc_id);
    var signed = try mintResponse(alloc, enc_id, "");
    defer signed.deinit(alloc);

    // Corrupt one CipherValue char inside the (now signed) document. Target the
    // CONTENT CipherValue (the last one), well past its opening tag.
    const last = std.mem.lastIndexOf(u8, signed.xml, "<xenc:CipherValue>").? + "<xenc:CipherValue>".len + 4;
    signed.xml[last] = if (signed.xml[last] == 'A') 'B' else 'A';

    var cfg = baseConfig(fx.t_valid, signed.key);
    cfg.sp_decrypt_key = sp.secret_key;
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(alloc, signed.xml, cfg));
}
