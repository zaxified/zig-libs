// SPDX-License-Identifier: MIT
//! Single Logout (SAML Core §3.7 / Bindings): build/sign/parse/verify for
//! `LogoutRequest` and `LogoutResponse`.
//!
//! ANCHORING: the RSA-SHA256/exclusive-C14N enveloped-signature PRIMITIVE these
//! build on is already externally anchored elsewhere in this module —
//! `test_fixture.zig` (openssl + lxml, byte-exact) and the W3C C14N vectors in
//! `xmldsig`. Every signed fixture in THIS file is a CONSTRUCTED, SELF
//! round-trip (a locally-generated RSA key signs, and this module's own
//! `xmldsig.verify` checks it) — exactly the precedent `test_sign.zig` set for
//! new content that has no external worked example (there is no OASIS-published
//! byte-exact LogoutRequest fixture to anchor against). What is new and
//! genuinely tested here is the ORCHESTRATION logic on top of that anchored
//! primitive: schema assembly, NameID/SessionIndex/status extraction, and —
//! most importantly — that the mandatory-signature and XSW pointer-pin
//! defenses are actually WIRED IN for this message type, not merely assumed
//! because they exist for Response/Assertion.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const xmldsig = @import("xmldsig");
const rsa = @import("rsa");
const enc = @import("test_encutil.zig");

const idp_entity_id = "https://idp.example.org/saml";
const issue_instant = "2024-06-01T12:00:00Z";
const t_now: i64 = 1717243200 + 30; // just after issue_instant

fn makeIdpKey(seed: u64) !rsa.KeyPair {
    var prng = std.Random.DefaultPrng.init(seed);
    return rsa.generate(prng.random(), 1024, 65537);
}

// ── LogoutRequest: build (unsigned), structural round-trip ──────────────────

test "buildLogoutRequest: well-formed, parses back, carries the fields" {
    const alloc = testing.allocator;
    const req = try saml.buildLogoutRequest(alloc, .{
        .id = "_lr001",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id, // SP entityID in real use; reused here for brevity
        .destination = "https://idp.example.org/slo",
        .name_id = "alice@example.org",
        .name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        .session_indexes = &.{ "sess-1", "sess-2" },
        .reason = "urn:oasis:names:tc:SAML:2.0:logout:user",
        .not_on_or_after = "2024-06-01T12:05:00Z",
    });
    defer alloc.free(req);

    try testing.expect(std.mem.indexOf(u8, req, "samlp:LogoutRequest") != null);
    try testing.expect(std.mem.indexOf(u8, req, "ID=\"_lr001\"") != null);
    try testing.expect(std.mem.indexOf(u8, req, "alice@example.org") != null);
    try testing.expect(std.mem.indexOf(u8, req, "sess-1") != null);
    try testing.expect(std.mem.indexOf(u8, req, "sess-2") != null);
    try testing.expect(std.mem.indexOf(u8, req, "ds:Signature") == null); // unsigned

    var doc = try @import("xml").parse(alloc, req, .{ .id_attr_names = &.{"ID"} });
    defer doc.deinit();
    try testing.expectEqualStrings("_lr001", doc.root.attr("", "ID").?);
}

// ── LogoutRequest: signed build -> consume, POST binding (CONSTRUCTED) ──────

fn baseRequestConfig(idp_key: xmldsig.VerifyKey) saml.LogoutRequestConfig {
    return .{
        .idp_entity_id = idp_entity_id,
        .idp_key = idp_key,
        .now_unix = t_now,
        .expected_destination = "https://sp.example.org/slo",
    };
}

test "LogoutRequest: signed build -> POST-field consume round-trips (CONSTRUCTED, self-signed)" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0001);

    const req = try saml.buildLogoutRequest(alloc, .{
        .id = "_lr_signed_01",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .destination = "https://sp.example.org/slo",
        .name_id = "alice@example.org",
        .session_indexes = &.{"sess-42"},
        .sign_with = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(req);
    try testing.expect(std.mem.indexOf(u8, req, "ds:Signature") != null);

    // Round-trip through the POST-field entry point (base64 wrapper).
    const enc_b64 = std.base64.standard.Encoder;
    const field = try alloc.alloc(u8, enc_b64.calcSize(req.len));
    defer alloc.free(field);
    _ = enc_b64.encode(field, req);

    var res = try saml.consumeLogoutRequest(alloc, field, baseRequestConfig(.{ .rsa = kp.public_key }));
    defer res.deinit();
    try testing.expectEqualStrings("_lr_signed_01", res.id);
    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expectEqual(@as(usize, 1), res.session_indexes.len);
    try testing.expectEqualStrings("sess-42", res.session_indexes[0]);
    try testing.expectEqual(@as(i64, 1717243200), res.issue_instant);
}

test "LogoutRequest: Issuer mismatch rejected" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0002);
    const req = try saml.buildLogoutRequest(alloc, .{
        .id = "_lr02",
        .issue_instant = issue_instant,
        .issuer = "https://not-the-idp.example.org",
        .name_id = "alice@example.org",
        .sign_with = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(req);
    try testing.expectError(
        error.IssuerMismatch,
        saml.consumeLogoutRequestXml(alloc, req, .embedded, baseRequestConfig(.{ .rsa = kp.public_key })),
    );
}

test "LogoutRequest: expired (NotOnOrAfter in the past) rejected" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0003);
    const req = try saml.buildLogoutRequest(alloc, .{
        .id = "_lr03",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .name_id = "alice@example.org",
        .not_on_or_after = "2020-01-01T00:00:00Z", // long past `t_now`
        .sign_with = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(req);
    try testing.expectError(
        error.RequestExpired,
        saml.consumeLogoutRequestXml(alloc, req, .embedded, baseRequestConfig(.{ .rsa = kp.public_key })),
    );
}

test "LogoutRequest: neither NameID nor EncryptedID present -> SubjectMissing" {
    // Hand-crafted: a well-formed, UNSIGNED LogoutRequest with no identity at
    // all — proves the extraction path fails closed rather than defaulting to
    // an empty NameID. Consumed via .redirect_verified since we only care
    // about the post-signature extraction logic here.
    const alloc = testing.allocator;
    const req = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " ++
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_lr04\" Version=\"2.0\" " ++
        "IssueInstant=\"2024-06-01T12:00:00Z\"><saml:Issuer>https://idp.example.org/saml</saml:Issuer>" ++
        "</samlp:LogoutRequest>";
    const kp = try makeIdpKey(0x510_0004);
    try testing.expectError(
        error.SubjectMissing,
        saml.consumeLogoutRequestXml(alloc, req, .redirect_verified, baseRequestConfig(.{ .rsa = kp.public_key })),
    );
}

// ── LogoutRequest: the mandatory-signature property, proven not assumed ─────
//
// Two REAL, both-supported code paths, the SAME bytes: `.embedded` requires
// and checks a `<ds:Signature>`; `.redirect_verified` is the legitimate
// "already checked out-of-band" path and does not look for one. Feeding
// identical UNSIGNED bytes through both and observing embedded reject /
// redirect_verified accept proves the `.embedded` rejection is attributable
// to the missing signature specifically — not to some other defect a
// signature-blind implementation would also reject on.

test "LogoutRequest: unsigned bytes rejected under .embedded, accepted under .redirect_verified (same bytes)" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0005);
    const req = try saml.buildLogoutRequest(alloc, .{
        .id = "_lr05",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .name_id = "alice@example.org",
        // sign_with left null: genuinely unsigned bytes.
    });
    defer alloc.free(req);
    try testing.expect(std.mem.indexOf(u8, req, "ds:Signature") == null);

    try testing.expectError(
        error.SignatureMissing,
        saml.consumeLogoutRequestXml(alloc, req, .embedded, baseRequestConfig(.{ .rsa = kp.public_key })),
    );

    var res = try saml.consumeLogoutRequestXml(alloc, req, .redirect_verified, baseRequestConfig(.{ .rsa = kp.public_key }));
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "LogoutRequest: flipped SignatureValue -> SignatureInvalid (distinct from SignatureMissing)" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0006);
    const req = try saml.buildLogoutRequest(alloc, .{
        .id = "_lr06",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .name_id = "alice@example.org",
        .sign_with = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(req);

    // Flip one base64 char inside <ds:SignatureValue>...</ds:SignatureValue>,
    // well past the opening tag, leaving XML structure and the digest intact.
    const tag = "<ds:SignatureValue>";
    const at = std.mem.indexOf(u8, req, tag).? + tag.len + 4;
    const mutable = try alloc.dupe(u8, req);
    defer alloc.free(mutable);
    mutable[at] = if (mutable[at] == 'A') 'B' else 'A';

    try testing.expectError(
        error.SignatureInvalid,
        saml.consumeLogoutRequestXml(alloc, mutable, .embedded, baseRequestConfig(.{ .rsa = kp.public_key })),
    );
}

// ── LogoutRequest: XSW — the pointer-pin defense, reproven for this message
//    type (not merely assumed because it exists for Response/Assertion) ─────

test "LogoutRequest XSW: signature moved to the top level, referencing a buried decoy -> SignatureWrappingDetected" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0007);

    // The genuinely-signed original: id "origID123", the real victim NameID.
    const orig = try saml.buildLogoutRequest(alloc, .{
        .id = "origID123",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .name_id = "victim@example.org",
        .sign_with = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(orig);

    const sig_start = std.mem.indexOf(u8, orig, "<ds:Signature").?;
    const sig_end = std.mem.indexOf(u8, orig, "</ds:Signature>").? + "</ds:Signature>".len;
    const sig_block = orig[sig_start..sig_end];

    var orig_no_sig: std.ArrayList(u8) = .empty;
    defer orig_no_sig.deinit(alloc);
    try orig_no_sig.appendSlice(alloc, orig[0..sig_start]);
    try orig_no_sig.appendSlice(alloc, orig[sig_end..]);

    // Attacker's forged outer LogoutRequest: its OWN NameID up top, the
    // MOVED (still validly-signed, still referencing "#origID123") signature
    // as its direct child (satisfying `.embedded`'s structural search), and
    // the original buried as a decoy nested element carrying the id the
    // Reference resolves to.
    const attack = try std.fmt.allocPrint(alloc, "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " ++
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"outerEvilID\" Version=\"2.0\" " ++
        "IssueInstant=\"{s}\"><saml:Issuer>{s}</saml:Issuer>{s}" ++
        "<saml:NameID>attacker-controlled-alias</saml:NameID>" ++
        "<decoy:Wrapper xmlns:decoy=\"urn:decoy\">{s}</decoy:Wrapper>" ++
        "</samlp:LogoutRequest>", .{ issue_instant, idp_entity_id, sig_block, orig_no_sig.items });
    defer alloc.free(attack);

    const result = saml.consumeLogoutRequestXml(alloc, attack, .embedded, baseRequestConfig(.{ .rsa = kp.public_key }));
    try testing.expectError(error.SignatureWrappingDetected, result);
}

// ── LogoutRequest: EncryptedID NameID (isolated via .redirect_verified — the
//    signed-enclosure-ordering property for THIS message shares the exact
//    same `decryptWrappedElement`/ordering code the already-tested
//    Assertion/EncryptedID path uses; not independently re-proven here) ─────

fn buildRequestWithEncryptedId(alloc: std.mem.Allocator, enc_id_xml: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " ++
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_lr_encid\" Version=\"2.0\" " ++
        "IssueInstant=\"{s}\"><saml:Issuer>{s}</saml:Issuer>{s}</samlp:LogoutRequest>", .{ issue_instant, idp_entity_id, enc_id_xml });
}

const nameid_plaintext = "<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " ++
    "Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.org</saml:NameID>";

test "LogoutRequest: EncryptedID decrypts to the expected NameID" {
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x510_ED01);
    const enc_id = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedID", nameid_plaintext);
    defer alloc.free(enc_id);
    const req = try buildRequestWithEncryptedId(alloc, enc_id);
    defer alloc.free(req);

    const kp = try makeIdpKey(0x510_0008);
    var cfg = baseRequestConfig(.{ .rsa = kp.public_key });
    cfg.sp_decrypt_key = sp.secret_key;
    var res = try saml.consumeLogoutRequestXml(alloc, req, .redirect_verified, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "LogoutRequest: EncryptedID present but no sp_decrypt_key -> EncryptedIdUnsupported" {
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x510_ED01);
    const enc_id = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedID", nameid_plaintext);
    defer alloc.free(enc_id);
    const req = try buildRequestWithEncryptedId(alloc, enc_id);
    defer alloc.free(req);

    const kp = try makeIdpKey(0x510_0009);
    try testing.expectError(
        error.EncryptedIdUnsupported,
        saml.consumeLogoutRequestXml(alloc, req, .redirect_verified, baseRequestConfig(.{ .rsa = kp.public_key })),
    );
}

test "LogoutRequest: EncryptedID wrong SP key -> IdDecryptionFailed (generic)" {
    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x510_ED01);
    const other = try enc.makeSpKey(0x510_ED02);
    const enc_id = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedID", nameid_plaintext);
    defer alloc.free(enc_id);
    const req = try buildRequestWithEncryptedId(alloc, enc_id);
    defer alloc.free(req);

    const kp = try makeIdpKey(0x510_000A);
    var cfg = baseRequestConfig(.{ .rsa = kp.public_key });
    cfg.sp_decrypt_key = other.secret_key;
    try testing.expectError(error.IdDecryptionFailed, saml.consumeLogoutRequestXml(alloc, req, .redirect_verified, cfg));
}

// ── LogoutResponse: build (unsigned + signed), consume, status handling ─────

fn baseResponseConfig(idp_key: xmldsig.VerifyKey, expected_irt: []const u8) saml.LogoutResponseConfig {
    return .{
        .idp_entity_id = idp_entity_id,
        .idp_key = idp_key,
        .now_unix = t_now,
        .expected_destination = "https://sp.example.org/slo/response",
        .expected_in_response_to = expected_irt,
    };
}

test "buildLogoutResponse: well-formed, parses back, defaults to Success" {
    const alloc = testing.allocator;
    const resp = try saml.buildLogoutResponse(alloc, .{
        .id = "_lresp01",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .in_response_to = "_lr_signed_01",
    });
    defer alloc.free(resp);
    try testing.expect(std.mem.indexOf(u8, resp, "samlp:LogoutResponse") != null);
    try testing.expect(std.mem.indexOf(u8, resp, "urn:oasis:names:tc:SAML:2.0:status:Success") != null);
}

test "LogoutResponse: signed build -> POST-field consume round-trips (CONSTRUCTED, self-signed)" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0101);
    const resp = try saml.buildLogoutResponse(alloc, .{
        .id = "_lresp02",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .destination = "https://sp.example.org/slo/response",
        .in_response_to = "_lr_out_42",
        .sign_with = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(resp);

    const enc_b64 = std.base64.standard.Encoder;
    const field = try alloc.alloc(u8, enc_b64.calcSize(resp.len));
    defer alloc.free(field);
    _ = enc_b64.encode(field, resp);

    var res = try saml.consumeLogoutResponse(alloc, field, baseResponseConfig(.{ .rsa = kp.public_key }, "_lr_out_42"));
    defer res.deinit();
    try testing.expectEqualStrings("_lresp02", res.id);
    try testing.expectEqualStrings("urn:oasis:names:tc:SAML:2.0:status:Success", res.status_code);
    try testing.expect(res.second_level_status_code == null);
    try testing.expectEqualStrings("_lr_out_42", res.in_response_to.?);
}

test "LogoutResponse: unsigned rejected under .embedded, accepted under .redirect_verified (same bytes)" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0102);
    const resp = try saml.buildLogoutResponse(alloc, .{
        .id = "_lresp03",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .in_response_to = "_lr_out_99",
    });
    defer alloc.free(resp);

    try testing.expectError(
        error.SignatureMissing,
        saml.consumeLogoutResponseXml(alloc, resp, .embedded, baseResponseConfig(.{ .rsa = kp.public_key }, "_lr_out_99")),
    );
    var res = try saml.consumeLogoutResponseXml(alloc, resp, .redirect_verified, baseResponseConfig(.{ .rsa = kp.public_key }, "_lr_out_99"));
    defer res.deinit();
    try testing.expectEqualStrings("_lresp03", res.id);
}

test "LogoutResponse: non-Success status -> StatusNotSuccess (checked, not assumed)" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0103);
    const resp = try saml.buildLogoutResponse(alloc, .{
        .id = "_lresp04",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .in_response_to = "_lr_out_1",
        .status_code = "urn:oasis:names:tc:SAML:2.0:status:Requester",
        .sign_with = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(resp);
    try testing.expectError(
        error.StatusNotSuccess,
        saml.consumeLogoutResponseXml(alloc, resp, .embedded, baseResponseConfig(.{ .rsa = kp.public_key }, "_lr_out_1")),
    );
}

test "LogoutResponse: InResponseTo mismatch rejected" {
    const alloc = testing.allocator;
    const kp = try makeIdpKey(0x510_0104);
    const resp = try saml.buildLogoutResponse(alloc, .{
        .id = "_lresp05",
        .issue_instant = issue_instant,
        .issuer = idp_entity_id,
        .in_response_to = "_lr_out_actual",
        .sign_with = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(resp);
    try testing.expectError(
        error.InResponseToMismatch,
        saml.consumeLogoutResponseXml(alloc, resp, .embedded, baseResponseConfig(.{ .rsa = kp.public_key }, "_lr_out_DIFFERENT")),
    );
}

test "LogoutResponse: nested (second-level) StatusCode extracted, e.g. PartialLogout" {
    // Hand-crafted structural test (unsigned, consumed via .redirect_verified)
    // — proves the second-level StatusCode extraction specifically, which
    // `buildLogoutResponse`'s Options do not emit (single-level only).
    const alloc = testing.allocator;
    const resp = "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " ++
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_lresp06\" Version=\"2.0\" " ++
        "IssueInstant=\"2024-06-01T12:00:00Z\" InResponseTo=\"_lr_out_7\">" ++
        "<saml:Issuer>https://idp.example.org/saml</saml:Issuer>" ++
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\">" ++
        "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:PartialLogout\"/>" ++
        "</samlp:StatusCode><samlp:StatusMessage>one participant failed</samlp:StatusMessage></samlp:Status>" ++
        "</samlp:LogoutResponse>";
    const kp = try makeIdpKey(0x510_0105);
    var res = try saml.consumeLogoutResponseXml(alloc, resp, .redirect_verified, baseResponseConfig(.{ .rsa = kp.public_key }, "_lr_out_7"));
    defer res.deinit();
    try testing.expectEqualStrings("urn:oasis:names:tc:SAML:2.0:status:Success", res.status_code);
    try testing.expectEqualStrings("urn:oasis:names:tc:SAML:2.0:status:PartialLogout", res.second_level_status_code.?);
    try testing.expectEqualStrings("one participant failed", res.status_message.?);
}

test "Z1: Decrypted.deinit wipes the recovered NameID before its buffer is freed" {
    // ReleaseFast only — see `test_encutil.FreeScanner` for why the safe lanes
    // cannot observe this.
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;

    const alloc = testing.allocator;
    const sp = try enc.makeSpKey(0x510_ED01);
    const enc_id = try enc.encryptedWrapper(alloc, sp.public_key, "EncryptedID", nameid_plaintext);
    defer alloc.free(enc_id);
    const req = try buildRequestWithEncryptedId(alloc, enc_id);
    defer alloc.free(req);

    // Markup that exists only in the decrypted `<saml:NameID>` octets: it is
    // never in the ciphertext, and the extracted `res.name_id` copies the text
    // content only, so a hit can come from nothing but the plaintext buffer.
    const needle = "nameid-format:emailAddress\">alice@example.org</saml:NameID>";
    var scan = enc.FreeScanner{ .child = alloc, .needle = needle };
    const sa = scan.allocator();

    const kp = try makeIdpKey(0x510_0008);
    var cfg = baseRequestConfig(.{ .rsa = kp.public_key });
    cfg.sp_decrypt_key = sp.secret_key;
    var res = try saml.consumeLogoutRequestXml(sa, req, .redirect_verified, cfg);
    defer res.deinit();

    // The decryption really happened, and the scanner really saw frees.
    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expect(scan.frees_seen > 0);
    try testing.expect(!scan.leaked_plaintext);
}
