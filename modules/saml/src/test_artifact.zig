// SPDX-License-Identifier: MIT
//! Artifact binding (SAML Bindings §3.6) — the `SAMLart` wire format and the
//! SOAP `ArtifactResolve`/`ArtifactResponse` message layer.
//!
//! This module only builds the SP's OUTGOING `ArtifactResolve` (the SP never
//! builds an `ArtifactResponse` — that is the IdP side, out of scope, same as
//! everywhere else in this module). To test `consumeArtifactResponseSoap` we
//! therefore need a stand-in "IdP-signed" `ArtifactResponse`, exactly the same
//! situation `test_sign.zig`/`test_fixture.zig` are already in for
//! `<samlp:Response>` (also an IdP-side message this module never builds) —
//! `signSoapMessage` below mirrors that established minted-fixture recipe
//! (RSA-SHA256 / exclusive C14N, `xmldsig`'s own verify path). CONSTRUCTED,
//! not external interop — see `test_sign.zig`'s header for why that is the
//! honest label here (no OASIS-published byte-exact ArtifactResponse fixture
//! exists to anchor against).

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const xml = @import("xml");
const xmldsig = @import("xmldsig");
const rsa = @import("rsa");

const Sha256 = std.crypto.hash.sha2.Sha256;
const ds_ns = "http://www.w3.org/2000/09/xmldsig#";
const exc_c14n_ns = "http://www.w3.org/2001/10/xml-exc-c14n#";
const c14n_ns = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"; // INCLUSIVE (not exclusive)
const sig_alg_rsa_sha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const dig_alg_sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const alg_enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const soap_ns = "http://schemas.xmlsoap.org/soap/envelope/";
const samlp_ns = "urn:oasis:names:tc:SAML:2.0:protocol";
const saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion";

const idp_entity_id = "https://idp.example.org/saml";

// ── Artifact (SAMLart) wire format ───────────────────────────────────────────

test "Artifact: encode/decode round-trips (raw and base64)" {
    const alloc = testing.allocator;
    const a: saml.Artifact = .{
        .endpoint_index = 7,
        .source_id = saml.sourceIdFromEntityId(idp_entity_id),
        .message_handle = [_]u8{0xAB} ** 20,
    };
    const raw = saml.encodeArtifact(a);
    try testing.expectEqual(@as(usize, 44), raw.len);
    // TypeCode is always 0x0004, big-endian.
    try testing.expectEqual(@as(u8, 0x00), raw[0]);
    try testing.expectEqual(@as(u8, 0x04), raw[1]);

    const back = try saml.decodeArtifact(&raw);
    try testing.expectEqual(a.endpoint_index, back.endpoint_index);
    try testing.expectEqualSlices(u8, &a.source_id, &back.source_id);
    try testing.expectEqualSlices(u8, &a.message_handle, &back.message_handle);

    const artifact_b64 = try saml.encodeArtifactBase64(alloc, a);
    defer alloc.free(artifact_b64);
    const back2 = try saml.decodeArtifactBase64(alloc, artifact_b64);
    try testing.expectEqual(a.endpoint_index, back2.endpoint_index);
    try testing.expectEqualSlices(u8, &a.source_id, &back2.source_id);
}

test "sourceIdFromEntityId: deterministic, 20 bytes, differs by entity" {
    const a = saml.sourceIdFromEntityId("https://idp.example.org/saml");
    const b = saml.sourceIdFromEntityId("https://idp.example.org/saml");
    const c = saml.sourceIdFromEntityId("https://other-idp.example.org/saml");
    try testing.expectEqualSlices(u8, &a, &b);
    try testing.expect(!std.mem.eql(u8, &a, &c));
}

test "decodeArtifact: wrong length -> InvalidArtifact" {
    try testing.expectError(error.InvalidArtifact, saml.decodeArtifact(&[_]u8{ 0, 4, 0, 0 }));
}

test "decodeArtifact: wrong type code -> UnsupportedTypeCode" {
    var raw = saml.encodeArtifact(.{
        .endpoint_index = 1,
        .source_id = [_]u8{0x01} ** 20,
        .message_handle = [_]u8{0x02} ** 20,
    });
    raw[1] = 0x05; // not the SAML 2.0 type code
    try testing.expectError(error.UnsupportedTypeCode, saml.decodeArtifact(&raw));
}

// ── buildArtifactResolveSoap ─────────────────────────────────────────────────

test "buildArtifactResolveSoap: unsigned, well-formed SOAP structure" {
    const alloc = testing.allocator;
    const artifact_b64 = try saml.encodeArtifactBase64(alloc, .{
        .endpoint_index = 0,
        .source_id = saml.sourceIdFromEntityId("https://sp.example.org/metadata"),
        .message_handle = [_]u8{0x99} ** 20,
    });
    defer alloc.free(artifact_b64);

    const soap_xml = try saml.buildArtifactResolveSoap(alloc, .{
        .id = "_ar001",
        .issue_instant = "2024-06-01T12:00:00Z",
        .issuer = "https://sp.example.org/metadata",
        .destination = "https://idp.example.org/ars",
        .artifact_b64 = artifact_b64,
    });
    defer alloc.free(soap_xml);

    var doc = try xml.parse(alloc, soap_xml, .{ .id_attr_names = &.{"ID"} });
    defer doc.deinit();
    try testing.expect(std.mem.eql(u8, doc.root.uri, soap_ns) and std.mem.eql(u8, doc.root.local, "Envelope"));
    try testing.expect(std.mem.indexOf(u8, soap_xml, "samlp:ArtifactResolve") != null);
    try testing.expect(std.mem.indexOf(u8, soap_xml, artifact_b64) != null);
    try testing.expect(std.mem.indexOf(u8, soap_xml, "ds:Signature") == null);
}

test "buildArtifactResolveSoap: signed output verifies through xmldsig.verify directly (independent verifier)" {
    const alloc = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xA47_0001);
    const kp = try rsa.generate(prng.random(), 1024, 65537);
    const artifact_b64 = try saml.encodeArtifactBase64(alloc, .{
        .endpoint_index = 0,
        .source_id = saml.sourceIdFromEntityId("https://sp.example.org/metadata"),
        .message_handle = [_]u8{0x77} ** 20,
    });
    defer alloc.free(artifact_b64);

    const soap_xml = try saml.buildArtifactResolveSoap(alloc, .{
        .id = "_ar002",
        .issue_instant = "2024-06-01T12:00:00Z",
        .issuer = "https://sp.example.org/metadata",
        .artifact_b64 = artifact_b64,
        .sign_with = .{ .rsa = kp.secret_key },
    });
    defer alloc.free(soap_xml);

    var doc = try xml.parse(alloc, soap_xml, .{ .id_attr_names = &.{"ID"} });
    defer doc.deinit();
    const body = findChild(doc.root, soap_ns, "Body").?;
    const resolve = firstElementChild(body).?;
    const sig = findChild(resolve, ds_ns, "Signature").?;

    var res = try xmldsig.verify(alloc, &doc, sig, .{ .key = .{ .rsa = kp.public_key } });
    defer res.deinit(alloc);
    try testing.expect(res.valid);
}

// ── consumeArtifactResponseSoap ──────────────────────────────────────────────

/// Mint a fake "IdP-signed" `<samlp:ArtifactResponse>` SOAP body — the same
/// two-pass RSA-SHA256/exclusive-C14N recipe `test_sign.zig` uses for
/// `<samlp:Response>`, since `saml` (SP-only) never builds this message type
/// either. `enclosed` is the raw XML of the message the artifact "resolved
/// to" (e.g. a minimal `<samlp:Response>`).
fn signArtifactResponse(alloc: std.mem.Allocator, seed: u64, id: []const u8, in_response_to: []const u8, status_code: []const u8, enclosed: []const u8) !struct { xml: []u8, key: rsa.PublicKey } {
    var prng = std.Random.DefaultPrng.init(seed);
    const kp = try rsa.generate(prng.random(), 1024, 65537);
    const digest_placeholder = "__TEST_DIGEST_PLACEHOLDER__";

    const assembled = try std.fmt.allocPrint(alloc, "<samlp:ArtifactResponse xmlns:samlp=\"{s}\" xmlns:saml=\"{s}\" ID=\"{s}\" Version=\"2.0\" " ++
        "IssueInstant=\"2024-06-01T12:00:00Z\" InResponseTo=\"{s}\">" ++
        "<saml:Issuer>{s}</saml:Issuer>" ++
        "<ds:Signature xmlns:ds=\"{s}\"><ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"{s}\"/>" ++
        "<ds:SignatureMethod Algorithm=\"{s}\"/>" ++
        "<ds:Reference URI=\"#{s}\"><ds:Transforms>" ++
        "<ds:Transform Algorithm=\"{s}\"/><ds:Transform Algorithm=\"{s}\"/>" ++
        "</ds:Transforms><ds:DigestMethod Algorithm=\"{s}\"/>" ++
        "<ds:DigestValue>{s}</ds:DigestValue></ds:Reference></ds:SignedInfo>" ++
        "<ds:SignatureValue></ds:SignatureValue></ds:Signature>" ++
        "<samlp:Status><samlp:StatusCode Value=\"{s}\"/></samlp:Status>" ++
        "{s}</samlp:ArtifactResponse>", .{
        samlp_ns,           saml_ns,       id,          in_response_to,
        idp_entity_id,      ds_ns,         exc_c14n_ns, sig_alg_rsa_sha256,
        id,                 alg_enveloped, exc_c14n_ns, dig_alg_sha256,
        digest_placeholder, status_code,   enclosed,
    });
    defer alloc.free(assembled);

    var doc1 = try xml.parse(alloc, assembled, .{ .id_attr_names = &.{"ID"} });
    defer doc1.deinit();
    const sig1 = findChild(doc1.root, ds_ns, "Signature").?;
    const ref_canon = try xmldsig.c14n.canonicalize(alloc, doc1.root, .{ .mode = .exclusive, .omit = sig1 });
    defer alloc.free(ref_canon);
    var dgst: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(ref_canon, &dgst, .{});
    const digest_b64 = try b64(alloc, &dgst);
    defer alloc.free(digest_b64);

    const with_digest = try std.mem.replaceOwned(u8, alloc, assembled, digest_placeholder, digest_b64);
    defer alloc.free(with_digest);

    var doc2 = try xml.parse(alloc, with_digest, .{ .id_attr_names = &.{"ID"} });
    defer doc2.deinit();
    const sig2 = findChild(doc2.root, ds_ns, "Signature").?;
    const si2 = findChild(sig2, ds_ns, "SignedInfo").?;
    const si_canon = try xmldsig.c14n.canonicalize(alloc, si2, .{ .mode = .exclusive });
    defer alloc.free(si_canon);

    var sig_buf: [rsa.max_modulus_len]u8 = undefined;
    const sig = try rsa.signPkcs1v15(kp.secret_key, Sha256, si_canon, &sig_buf);
    const sig_b64 = try b64(alloc, sig);
    defer alloc.free(sig_b64);

    const empty_sv = "<ds:SignatureValue></ds:SignatureValue>";
    const filled_sv = try std.fmt.allocPrint(alloc, "<ds:SignatureValue>{s}</ds:SignatureValue>", .{sig_b64});
    defer alloc.free(filled_sv);
    const signed = try std.mem.replaceOwned(u8, alloc, with_digest, empty_sv, filled_sv);
    defer alloc.free(signed);

    const soap_xml = try std.fmt.allocPrint(alloc, "<soap:Envelope xmlns:soap=\"{s}\"><soap:Body>{s}</soap:Body></soap:Envelope>", .{ soap_ns, signed });
    return .{ .xml = soap_xml, .key = kp.public_key };
}

const enclosed_response = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " ++
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp_enclosed\" Version=\"2.0\" " ++
    "IssueInstant=\"2024-06-01T12:00:00Z\"><saml:Issuer>https://idp.example.org/saml</saml:Issuer>" ++
    "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" ++
    "</samlp:Response>";

fn baseArtifactConfig(idp_key: xmldsig.VerifyKey, expected_irt: []const u8) saml.ArtifactResponseConfig {
    return .{
        .idp_entity_id = idp_entity_id,
        .idp_key = idp_key,
        .now_unix = 1717243200,
        .expected_in_response_to = expected_irt,
    };
}

test "consumeArtifactResponseSoap: happy path extracts the enclosed message" {
    const alloc = testing.allocator;
    const fake = try signArtifactResponse(alloc, 0xA47_0002, "_arresp01", "_ar002", "urn:oasis:names:tc:SAML:2.0:status:Success", enclosed_response);
    defer alloc.free(fake.xml);

    var res = try saml.consumeArtifactResponseSoap(alloc, fake.xml, baseArtifactConfig(.{ .rsa = fake.key }, "_ar002"));
    defer res.deinit(alloc);

    // Structural check on the re-serialized (exclusive-C14N) enclosed message
    // — a self round-trip through a DIFFERENT serialization, so we check
    // content, not byte-identity with the original snippet.
    var enc_doc = try xml.parse(alloc, res.enclosed_message_xml, .{});
    defer enc_doc.deinit();
    try testing.expect(std.mem.eql(u8, enc_doc.root.local, "Response"));
    try testing.expectEqualStrings("_resp_enclosed", enc_doc.root.attr("", "ID").?);
}

test "consumeArtifactResponseSoap: missing signature -> SignatureMissing" {
    const alloc = testing.allocator;
    const fake = try signArtifactResponse(alloc, 0xA47_0003, "_arresp02", "_ar003", "urn:oasis:names:tc:SAML:2.0:status:Success", enclosed_response);
    defer alloc.free(fake.xml);

    const sig_start = std.mem.indexOf(u8, fake.xml, "<ds:Signature").?;
    const sig_end = std.mem.indexOf(u8, fake.xml, "</ds:Signature>").? + "</ds:Signature>".len;
    const stripped = try std.mem.concat(alloc, u8, &.{ fake.xml[0..sig_start], fake.xml[sig_end..] });
    defer alloc.free(stripped);

    try testing.expectError(
        error.SignatureMissing,
        saml.consumeArtifactResponseSoap(alloc, stripped, baseArtifactConfig(.{ .rsa = fake.key }, "_ar003")),
    );
}

test "consumeArtifactResponseSoap: flipped SignatureValue -> SignatureInvalid (distinct from SignatureMissing)" {
    const alloc = testing.allocator;
    const fake = try signArtifactResponse(alloc, 0xA47_0004, "_arresp03", "_ar004", "urn:oasis:names:tc:SAML:2.0:status:Success", enclosed_response);
    defer alloc.free(fake.xml);

    const tag = "<ds:SignatureValue>";
    const at = std.mem.indexOf(u8, fake.xml, tag).? + tag.len + 4;
    fake.xml[at] = if (fake.xml[at] == 'A') 'B' else 'A';

    try testing.expectError(
        error.SignatureInvalid,
        saml.consumeArtifactResponseSoap(alloc, fake.xml, baseArtifactConfig(.{ .rsa = fake.key }, "_ar004")),
    );
}

test "consumeArtifactResponseSoap: InResponseTo mismatch rejected" {
    const alloc = testing.allocator;
    const fake = try signArtifactResponse(alloc, 0xA47_0005, "_arresp04", "_ar005_actual", "urn:oasis:names:tc:SAML:2.0:status:Success", enclosed_response);
    defer alloc.free(fake.xml);
    try testing.expectError(
        error.InResponseToMismatch,
        saml.consumeArtifactResponseSoap(alloc, fake.xml, baseArtifactConfig(.{ .rsa = fake.key }, "_ar005_DIFFERENT")),
    );
}

test "consumeArtifactResponseSoap: non-Success status -> StatusNotSuccess" {
    const alloc = testing.allocator;
    const fake = try signArtifactResponse(alloc, 0xA47_0006, "_arresp05", "_ar006", "urn:oasis:names:tc:SAML:2.0:status:Responder", enclosed_response);
    defer alloc.free(fake.xml);
    try testing.expectError(
        error.StatusNotSuccess,
        saml.consumeArtifactResponseSoap(alloc, fake.xml, baseArtifactConfig(.{ .rsa = fake.key }, "_ar006")),
    );
}

test "consumeArtifactResponseSoap: no enclosed message -> NoEnclosedMessage" {
    const alloc = testing.allocator;
    const fake = try signArtifactResponse(alloc, 0xA47_0007, "_arresp06", "_ar007", "urn:oasis:names:tc:SAML:2.0:status:Success", "");
    defer alloc.free(fake.xml);
    try testing.expectError(
        error.NoEnclosedMessage,
        saml.consumeArtifactResponseSoap(alloc, fake.xml, baseArtifactConfig(.{ .rsa = fake.key }, "_ar007")),
    );
}

// ── A1 audit F9 (M27): the ArtifactResponse XSW pin had no test ─────────────
//    (the equivalent pins on the Response, the decrypted assertion and the
//    LogoutRequest all had one; this bindingsig->ArtifactResponse alone did
//    not). Sibling-wrapping shape, same idea `test_xsw.zig` documents: a
//    genuinely valid signature whose Reference resolves to a DIFFERENT
//    element than the one actually being processed as the message root.

test "M27 teeth: ArtifactResponse XSW -- valid signature pointing at a SIBLING is rejected" {
    const alloc = testing.allocator;
    const fake = try signArtifactResponse(alloc, 0xA47_00F3, "_legit_ar", "_ar_f27", "urn:oasis:names:tc:SAML:2.0:status:Success", enclosed_response);
    defer alloc.free(fake.xml);

    // Pull the legitimately-signed `<samlp:ArtifactResponse>` block (ID
    // "_legit_ar") and the `<ds:Signature>` inside it back out of the SOAP
    // body `signArtifactResponse` built.
    const ar_open = "<samlp:ArtifactResponse";
    const ar_close = "</samlp:ArtifactResponse>";
    const ar_start = std.mem.indexOf(u8, fake.xml, ar_open).?;
    const ar_end = std.mem.indexOfPos(u8, fake.xml, ar_start, ar_close).? + ar_close.len;
    const legit_block = fake.xml[ar_start..ar_end];

    const sig_open = "<ds:Signature";
    const sig_close = "</ds:Signature>";
    const sig_start = std.mem.indexOfPos(u8, fake.xml, ar_start, sig_open).?;
    const sig_end = std.mem.indexOfPos(u8, fake.xml, sig_start, sig_close).? + sig_close.len;
    const sig_block = fake.xml[sig_start..sig_end];

    // The enveloped-signature transform removes only the specific `Signature`
    // node passed to `xmldsig.verify` from the canonicalized target -- not
    // "any" Signature descendant. So the legit block must have ITS OWN
    // signature stripped (`legit_nosig`) to reproduce the exact bytes that
    // were originally digested; the COPY that makes the decoy's signature
    // genuinely valid goes on the decoy instead. Same shape as
    // `test_xsw.zig`'s "classic wrap" for the Response/Assertion case.
    const legit_nosig = try std.mem.replaceOwned(u8, alloc, legit_block, sig_block, "");
    defer alloc.free(legit_nosig);

    // A decoy root, own ID, carrying a COPY of the legit signature plus its
    // OWN attacker-chosen Status + enclosed message -- so that if the pin
    // below were ever disabled, this attack would fully succeed and hand the
    // caller the attacker's forged enclosed message, not merely trip some
    // OTHER, unrelated structural check. Its Reference (`URI="#_legit_ar"`)
    // still resolves -- via the document's global ID index, same one
    // `xmldsig` used to verify -- to the REAL (now signature-stripped)
    // element sitting as a sibling, so the signature is genuinely valid;
    // only its TARGET is wrong.
    const evil_enclosed = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " ++
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp_evil\" Version=\"2.0\" " ++
        "IssueInstant=\"2024-06-01T12:00:00Z\"><saml:Issuer>https://evil.example.org/saml</saml:Issuer>" ++
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" ++
        "</samlp:Response>";
    const decoy = try std.fmt.allocPrint(
        alloc,
        "<samlp:ArtifactResponse xmlns:samlp=\"{s}\" xmlns:saml=\"{s}\" ID=\"_decoy_wrap\" Version=\"2.0\" " ++
            "IssueInstant=\"2024-06-01T12:00:00Z\" InResponseTo=\"_ar_f27\"><saml:Issuer>{s}</saml:Issuer>{s}" ++
            "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{s}</samlp:ArtifactResponse>",
        .{ samlp_ns, saml_ns, idp_entity_id, sig_block, evil_enclosed },
    );
    defer alloc.free(decoy);

    const wrapped = try std.fmt.allocPrint(
        alloc,
        "<soap:Envelope xmlns:soap=\"{s}\"><soap:Body>{s}{s}</soap:Body></soap:Envelope>",
        .{ soap_ns, decoy, legit_nosig },
    );
    defer alloc.free(wrapped);

    try testing.expectError(
        error.SignatureWrappingDetected,
        saml.consumeArtifactResponseSoap(alloc, wrapped, baseArtifactConfig(.{ .rsa = fake.key }, "_ar_f27")),
    );
}

// ── F12: the "unaffected" doc comment does not hold for an INCLUSIVE-C14N ────
//    inner signature ──────────────────────────────────────────────────────────

test "F12: exclusive-C14N extraction breaks an inner signature that used INCLUSIVE C14N" {
    // A1 audit F12: `ArtifactResponseResult.enclosed_message_xml`'s doc comment
    // claims "an embedded signature inside the enclosed message ... is
    // unaffected by having been extracted this way". True for an inner
    // signature that itself uses Exclusive C14N (the common case, and what
    // every OTHER fixture/helper in this file signs with). NOT true in
    // general: inclusive C14N of a subtree renders every namespace in scope,
    // including ones declared only on an ANCESTOR outside the subtree, and
    // extraction removes that ancestor. This reproduces the exact extraction
    // call `consumeArtifactResponseSoap` makes
    // (`xmldsig.c14n.canonicalize(alloc, enclosed, .{ .mode = .exclusive })`)
    // against a signature legitimately valid before it.
    const alloc = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xA47_00F1);
    const inner_kp = try rsa.generate(prng.random(), 1024, 65537);

    const inner_id = "_resp_inclusive";
    const digest_placeholder = "__INNER_DIGEST__";
    // The inner Response's OWN signature: enveloped + INCLUSIVE (not
    // exclusive) C14N transform over itself.
    const inner_template = try std.fmt.allocPrint(alloc, "<samlp:Response xmlns:samlp=\"{s}\" xmlns:saml=\"{s}\" ID=\"{s}\" Version=\"2.0\" " ++
        "IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>{s}</saml:Issuer>" ++
        "<ds:Signature xmlns:ds=\"{s}\"><ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"{s}\"/>" ++
        "<ds:SignatureMethod Algorithm=\"{s}\"/>" ++
        "<ds:Reference URI=\"#{s}\"><ds:Transforms>" ++
        "<ds:Transform Algorithm=\"{s}\"/><ds:Transform Algorithm=\"{s}\"/>" ++
        "</ds:Transforms><ds:DigestMethod Algorithm=\"{s}\"/>" ++
        "<ds:DigestValue>{s}</ds:DigestValue></ds:Reference></ds:SignedInfo>" ++
        "<ds:SignatureValue></ds:SignatureValue></ds:Signature>" ++
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" ++
        "</samlp:Response>", .{
        samlp_ns,      saml_ns, inner_id,           idp_entity_id,
        ds_ns,         c14n_ns, sig_alg_rsa_sha256, inner_id,
        alg_enveloped, c14n_ns, dig_alg_sha256,     digest_placeholder,
    });
    defer alloc.free(inner_template);

    // An ANCESTOR that declares a namespace NOT redeclared on the Response
    // itself -- in scope for inclusive C14N of the nested element, gone once
    // that element is extracted as a standalone root.
    const wrap = "<wrap:Outer xmlns:wrap=\"urn:test:outer\" xmlns:extra=\"urn:test:extra\">{s}</wrap:Outer>";

    const wrapped_for_digest = try std.fmt.allocPrint(alloc, wrap, .{inner_template});
    defer alloc.free(wrapped_for_digest);
    var doc1 = try xml.parse(alloc, wrapped_for_digest, .{ .id_attr_names = &.{"ID"} });
    defer doc1.deinit();
    const inner_el1 = firstElementChild(doc1.root).?;
    const inner_sig1 = findChild(inner_el1, ds_ns, "Signature").?;
    const ref_canon = try xmldsig.c14n.canonicalize(alloc, inner_el1, .{ .mode = .inclusive, .omit = inner_sig1 });
    defer alloc.free(ref_canon);
    var dgst: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(ref_canon, &dgst, .{});
    const digest_b64 = try b64(alloc, &dgst);
    defer alloc.free(digest_b64);

    const inner_with_digest = try std.mem.replaceOwned(u8, alloc, inner_template, digest_placeholder, digest_b64);
    defer alloc.free(inner_with_digest);
    const wrapped_with_digest = try std.fmt.allocPrint(alloc, wrap, .{inner_with_digest});
    defer alloc.free(wrapped_with_digest);
    var doc2 = try xml.parse(alloc, wrapped_with_digest, .{ .id_attr_names = &.{"ID"} });
    defer doc2.deinit();
    const inner_el2 = firstElementChild(doc2.root).?;
    const inner_sig2 = findChild(inner_el2, ds_ns, "Signature").?;
    const si2 = findChild(inner_sig2, ds_ns, "SignedInfo").?;
    const si_canon = try xmldsig.c14n.canonicalize(alloc, si2, .{ .mode = .inclusive });
    defer alloc.free(si_canon);
    var sig_buf: [rsa.max_modulus_len]u8 = undefined;
    const sig_bytes = try rsa.signPkcs1v15(inner_kp.secret_key, Sha256, si_canon, &sig_buf);
    const sig_b64 = try b64(alloc, sig_bytes);
    defer alloc.free(sig_b64);

    const empty_sv = "<ds:SignatureValue></ds:SignatureValue>";
    const filled_sv = try std.fmt.allocPrint(alloc, "<ds:SignatureValue>{s}</ds:SignatureValue>", .{sig_b64});
    defer alloc.free(filled_sv);
    const inner_signed = try std.mem.replaceOwned(u8, alloc, inner_with_digest, empty_sv, filled_sv);
    defer alloc.free(inner_signed);
    const wrapped_signed = try std.fmt.allocPrint(alloc, wrap, .{inner_signed});
    defer alloc.free(wrapped_signed);

    // Sanity: the inner signature IS valid in its original nested context --
    // a legitimate inclusive-C14N signature, not a broken construction.
    var doc3 = try xml.parse(alloc, wrapped_signed, .{ .id_attr_names = &.{"ID"} });
    defer doc3.deinit();
    const inner_el3 = firstElementChild(doc3.root).?;
    const inner_sig3 = findChild(inner_el3, ds_ns, "Signature").?;
    {
        var res = try xmldsig.verify(alloc, &doc3, inner_sig3, .{ .key = .{ .rsa = inner_kp.public_key } });
        defer res.deinit(alloc);
        try testing.expect(res.valid);
    }

    // The exact extraction `consumeArtifactResponseSoap` performs.
    const extracted_xml = try xmldsig.c14n.canonicalize(alloc, inner_el3, .{ .mode = .exclusive });
    defer alloc.free(extracted_xml);
    var extracted_doc = try xml.parse(alloc, extracted_xml, .{ .id_attr_names = &.{"ID"} });
    defer extracted_doc.deinit();
    const extracted_sig = findChild(extracted_doc.root, ds_ns, "Signature").?;
    var res2 = try xmldsig.verify(alloc, &extracted_doc, extracted_sig, .{ .key = .{ .rsa = inner_kp.public_key } });
    defer res2.deinit(alloc);
    // RED (would fail): the doc comment claims this stays valid. It does not
    // -- `xmlns:extra` was in scope for the digest above and is gone here.
    try testing.expect(!res2.valid);
}

// ── small test-only helpers ──────────────────────────────────────────────────

fn findChild(el: *const xml.Element, uri: []const u8, local: []const u8) ?*xml.Element {
    for (el.children) |c| switch (c.content) {
        .element => |child| if (std.mem.eql(u8, child.uri, uri) and std.mem.eql(u8, child.local, local)) return child,
        else => {},
    };
    return null;
}

fn firstElementChild(el: *const xml.Element) ?*xml.Element {
    for (el.children) |c| switch (c.content) {
        .element => |child| return child,
        else => {},
    };
    return null;
}

fn b64(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const e = std.base64.standard.Encoder;
    const out = try alloc.alloc(u8, e.calcSize(data.len));
    _ = e.encode(out, data);
    return out;
}
