// SPDX-License-Identifier: MIT
//! Killing tests from the whole-module mutation audit, second part:
//! Single Logout, the Artifact binding and IdP metadata. The messages that need
//! no signature are consumed with `.redirect_verified` (the Redirect binding's
//! signature is checked on the query string, not in the document); the signed
//! ones are minted with `test_mutants.signDoc`.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const xml = @import("xml");
const t = @import("test_mutants.zig");
const encutil = @import("test_encutil.zig");

const gpa = testing.allocator;

fn lrCfg(now: i64) saml.LogoutRequestConfig {
    return .{ .idp_entity_id = fx.idp_entity_id, .idp_key = fx.idpKey(), .now_unix = now };
}

fn lsCfg(now: i64) saml.LogoutResponseConfig {
    return .{ .idp_entity_id = fx.idp_entity_id, .idp_key = fx.idpKey(), .now_unix = now, .expected_in_response_to = "_lr1" };
}

const lr_opts: saml.LogoutRequestOptions = .{
    .id = "_lr1",
    .issue_instant = "2024-06-01T12:00:00Z",
    .issuer = fx.idp_entity_id,
    .name_id = "alice",
};

// ── LogoutRequest ────────────────────────────────────────────────────────────

test "LogoutRequest: every field is extracted, values are trimmed, times are parsed" {
    var o = lr_opts;
    o.destination = "https://sp.example.org/slo";
    o.name_id = "\n  alice \n";
    o.name_id_format = "urn:fmt";
    o.name_id_sp_qualifier = "spq";
    o.session_indexes = &.{ " s1 ", "s2" };
    o.reason = "urn:reason";
    o.not_on_or_after = "2024-06-01T12:05:00Z";
    const bytes = try saml.buildLogoutRequest(gpa, o);
    defer gpa.free(bytes);
    var r = try saml.consumeLogoutRequestXml(gpa, bytes, .redirect_verified, lrCfg(fx.t_valid));
    defer r.deinit();
    try testing.expectEqualStrings("_lr1", r.id);
    try testing.expectEqual(@as(i64, fx.t_valid), r.issue_instant);
    try testing.expectEqualStrings("alice", r.name_id);
    try testing.expectEqualStrings("urn:fmt", r.name_id_format.?);
    try testing.expectEqualStrings("spq", r.name_id_sp_qualifier.?);
    try testing.expectEqual(@as(usize, 2), r.session_indexes.len);
    try testing.expectEqualStrings("s1", r.session_indexes[0]);
    try testing.expectEqualStrings("s2", r.session_indexes[1]);
    try testing.expectEqualStrings("urn:reason", r.reason.?);
    try testing.expectEqual(@as(i64, fx.t_valid + 300), r.not_on_or_after.?);

    const plain = try saml.buildLogoutRequest(gpa, lr_opts);
    defer gpa.free(plain);
    var p = try saml.consumeLogoutRequestXml(gpa, plain, .redirect_verified, lrCfg(fx.t_valid));
    defer p.deinit();
    try testing.expect(p.name_id_format == null and p.name_id_sp_qualifier == null and p.reason == null and p.not_on_or_after == null);
    try testing.expectEqual(@as(usize, 0), p.session_indexes.len);
}

test "LogoutRequest: root element, Issuer, Destination and NotOnOrAfter are checked" {
    // another protocol message
    const resp = try saml.buildLogoutResponse(gpa, .{ .id = "_x", .issue_instant = "2024-06-01T12:00:00Z", .issuer = fx.idp_entity_id });
    defer gpa.free(resp);
    try testing.expectError(error.NotLogoutRequest, saml.consumeLogoutRequestXml(gpa, resp, .redirect_verified, lrCfg(fx.t_valid)));

    // Issuer: wrong, then absent
    var o = lr_opts;
    o.issuer = "https://other.example.org";
    const wrong = try saml.buildLogoutRequest(gpa, o);
    defer gpa.free(wrong);
    try testing.expectError(error.IssuerMismatch, saml.consumeLogoutRequestXml(gpa, wrong, .redirect_verified, lrCfg(fx.t_valid)));
    const ok = try saml.buildLogoutRequest(gpa, lr_opts);
    defer gpa.free(ok);
    const no_issuer = try t.replaceOnce(ok, "<saml:Issuer>" ++ fx.idp_entity_id ++ "</saml:Issuer>", "");
    defer gpa.free(no_issuer);
    try testing.expectError(error.IssuerMissing, saml.consumeLogoutRequestXml(gpa, no_issuer, .redirect_verified, lrCfg(fx.t_valid)));

    // Destination: compared only when both sides have one
    var d = lr_opts;
    d.destination = "https://sp.example.org/slo";
    const with_dest = try saml.buildLogoutRequest(gpa, d);
    defer gpa.free(with_dest);
    var cfg = lrCfg(fx.t_valid);
    cfg.expected_destination = "https://sp.example.org/other";
    try testing.expectError(error.DestinationMismatch, saml.consumeLogoutRequestXml(gpa, with_dest, .redirect_verified, cfg));
    cfg.expected_destination = "https://sp.example.org/slo";
    var r1 = try saml.consumeLogoutRequestXml(gpa, with_dest, .redirect_verified, cfg);
    r1.deinit();
    var r2 = try saml.consumeLogoutRequestXml(gpa, ok, .redirect_verified, cfg); // no Destination in the message
    r2.deinit();
    var r3 = try saml.consumeLogoutRequestXml(gpa, with_dest, .redirect_verified, lrCfg(fx.t_valid)); // none expected
    r3.deinit();

    // NotOnOrAfter = t_valid + 300, skew 60
    var n = lr_opts;
    n.not_on_or_after = "2024-06-01T12:05:00Z";
    const timed = try saml.buildLogoutRequest(gpa, n);
    defer gpa.free(timed);
    var r4 = try saml.consumeLogoutRequestXml(gpa, timed, .redirect_verified, lrCfg(fx.t_valid + 300 + 60 - 1));
    r4.deinit();
    try testing.expectError(error.RequestExpired, saml.consumeLogoutRequestXml(gpa, timed, .redirect_verified, lrCfg(fx.t_valid + 300 + 60)));
}

test "LogoutRequest: only <samlp:SessionIndex> children count; an EncryptedID that is not a NameID is refused" {
    const doc =
        "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_m1\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>" ++ fx.idp_entity_id ++ "</saml:Issuer><saml:NameID>n</saml:NameID>" ++
        "<samlp:SessionIndex>a</samlp:SessionIndex><saml:SessionIndex>b</saml:SessionIndex>" ++
        "<samlp:Other><samlp:SessionIndex>c</samlp:SessionIndex></samlp:Other></samlp:LogoutRequest>";
    var r = try saml.consumeLogoutRequestXml(gpa, doc, .redirect_verified, lrCfg(fx.t_valid));
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.session_indexes.len);
    try testing.expectEqualStrings("a", r.session_indexes[0]);

    var kp = try encutil.makeSpKey(0xE001);
    const enc = try encutil.encryptedWrapper(gpa, kp.public_key, "EncryptedID", "<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"a\"/>");
    defer gpa.free(enc);
    const bad = try t.replaceOnce(doc, "<saml:NameID>n</saml:NameID>", enc);
    defer gpa.free(bad);
    var cfg = lrCfg(fx.t_valid);
    try testing.expectError(error.EncryptedIdUnsupported, saml.consumeLogoutRequestXml(gpa, bad, .redirect_verified, cfg));
    cfg.sp_decrypt_key = &kp.secret_key;
    try testing.expectError(error.IdDecryptionFailed, saml.consumeLogoutRequestXml(gpa, bad, .redirect_verified, cfg));

    const good_enc = try encutil.encryptedWrapper(gpa, kp.public_key, "EncryptedID", "<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"f\" SPNameQualifier=\"q\">bob</saml:NameID>");
    defer gpa.free(good_enc);
    const good = try t.replaceOnce(doc, "<saml:NameID>n</saml:NameID>", good_enc);
    defer gpa.free(good);
    var g = try saml.consumeLogoutRequestXml(gpa, good, .redirect_verified, cfg);
    defer g.deinit();
    try testing.expectEqualStrings("bob", g.name_id);
    try testing.expectEqualStrings("f", g.name_id_format.?);
    try testing.expectEqualStrings("q", g.name_id_sp_qualifier.?);
}

test "LogoutRequest: an embedded signature over some other element is a wrapping attack" {
    const sb = try t.sigBlock(.{ .ref_id = "_decoy" });
    defer gpa.free(sb);
    const doc = try gpa.print("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_m2\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>{s}</saml:Issuer>{s}<saml:NameID>n</saml:NameID><samlp:Extensions ID=\"_decoy\"/></samlp:LogoutRequest>", .{ fx.idp_entity_id, sb });
    defer gpa.free(doc);
    var m = try t.signDoc(0xE002, doc, .{ .ref_id = "_decoy" });
    defer m.deinit();
    var cfg = lrCfg(fx.t_valid);
    cfg.idp_key = m.key;
    try testing.expectError(error.SignatureWrappingDetected, saml.consumeLogoutRequestXml(gpa, m.resp, .embedded, cfg));
    // the same bytes are fine when they are signed over the request itself
    const sb2 = try t.sigBlock(.{ .ref_id = "_m3" });
    defer gpa.free(sb2);
    const own = try gpa.print("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_m3\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>{s}</saml:Issuer>{s}<saml:NameID>n</saml:NameID></samlp:LogoutRequest>", .{ fx.idp_entity_id, sb2 });
    defer gpa.free(own);
    var m2 = try t.signDoc(0xE003, own, .{ .ref_id = "_m3" });
    defer m2.deinit();
    cfg.idp_key = m2.key;
    var r = try saml.consumeLogoutRequestXml(gpa, m2.resp, .embedded, cfg);
    r.deinit();
}

// ── LogoutResponse ───────────────────────────────────────────────────────────

test "LogoutResponse: root, Issuer, Destination, InResponseTo and status message are checked" {
    const req = try saml.buildLogoutRequest(gpa, lr_opts);
    defer gpa.free(req);
    try testing.expectError(error.NotLogoutResponse, saml.consumeLogoutResponseXml(gpa, req, .redirect_verified, lsCfg(fx.t_valid)));

    const base: saml.LogoutResponseOptions = .{ .id = "_ls1", .issue_instant = "2024-06-01T12:00:00Z", .issuer = fx.idp_entity_id, .in_response_to = "_lr1", .destination = "https://sp.example.org/slo", .status_message = "\n  done \n" };
    const ok = try saml.buildLogoutResponse(gpa, base);
    defer gpa.free(ok);
    var r = try saml.consumeLogoutResponseXml(gpa, ok, .redirect_verified, lsCfg(fx.t_valid));
    defer r.deinit();
    try testing.expectEqualStrings("done", r.status_message.?);
    try testing.expectEqualStrings("_lr1", r.in_response_to.?);
    try testing.expect(r.second_level_status_code == null);

    var wrong_issuer = base;
    wrong_issuer.issuer = "https://other.example.org";
    const wi = try saml.buildLogoutResponse(gpa, wrong_issuer);
    defer gpa.free(wi);
    try testing.expectError(error.IssuerMismatch, saml.consumeLogoutResponseXml(gpa, wi, .redirect_verified, lsCfg(fx.t_valid)));

    var cfg = lsCfg(fx.t_valid);
    cfg.expected_destination = "https://sp.example.org/other";
    try testing.expectError(error.DestinationMismatch, saml.consumeLogoutResponseXml(gpa, ok, .redirect_verified, cfg));
    cfg.expected_destination = "https://sp.example.org/slo";
    var r2 = try saml.consumeLogoutResponseXml(gpa, ok, .redirect_verified, cfg);
    r2.deinit();

    var no_irt = base;
    no_irt.in_response_to = null;
    const ni = try saml.buildLogoutResponse(gpa, no_irt);
    defer gpa.free(ni);
    try testing.expectError(error.InResponseToMismatch, saml.consumeLogoutResponseXml(gpa, ni, .redirect_verified, lsCfg(fx.t_valid)));
    var other_irt = base;
    other_irt.in_response_to = "_other";
    const oi = try saml.buildLogoutResponse(gpa, other_irt);
    defer gpa.free(oi);
    try testing.expectError(error.InResponseToMismatch, saml.consumeLogoutResponseXml(gpa, oi, .redirect_verified, lsCfg(fx.t_valid)));
}

test "LogoutResponse: an embedded signature over some other element is a wrapping attack; a non-Success status is refused" {
    const sb = try t.sigBlock(.{ .ref_id = "_decoy" });
    defer gpa.free(sb);
    const doc = try gpa.print("<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_ls2\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\" InResponseTo=\"_lr1\">" ++
        "<saml:Issuer>{s}</saml:Issuer>{s}<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status><samlp:Extensions ID=\"_decoy\"/></samlp:LogoutResponse>", .{ fx.idp_entity_id, sb });
    defer gpa.free(doc);
    var m = try t.signDoc(0xE004, doc, .{ .ref_id = "_decoy" });
    defer m.deinit();
    var cfg = lsCfg(fx.t_valid);
    cfg.idp_key = m.key;
    try testing.expectError(error.SignatureWrappingDetected, saml.consumeLogoutResponseXml(gpa, m.resp, .embedded, cfg));

    const bad = try saml.buildLogoutResponse(gpa, .{ .id = "_ls3", .issue_instant = "2024-06-01T12:00:00Z", .issuer = fx.idp_entity_id, .in_response_to = "_lr1", .status_code = "urn:oasis:names:tc:SAML:2.0:status:Responder" });
    defer gpa.free(bad);
    try testing.expectError(error.StatusNotSuccess, saml.consumeLogoutResponseXml(gpa, bad, .redirect_verified, lsCfg(fx.t_valid)));
}

// ── Artifact binding ─────────────────────────────────────────────────────────

test "Artifact: the wire layout is big-endian type code, endpoint index, source id, handle; length is exactly 44" {
    var a: saml.Artifact = .{ .endpoint_index = 0x0102, .source_id = @splat(0x11), .message_handle = @splat(0x22) };
    const raw = saml.encodeArtifact(a);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x04, 0x01, 0x02 }, raw[0..4]);
    try testing.expectEqualSlices(u8, &(@as([20]u8, @splat(0x11))), raw[4..24]);
    try testing.expectEqualSlices(u8, &(@as([20]u8, @splat(0x22))), raw[24..44]);
    const back = try saml.decodeArtifact(&raw);
    try testing.expectEqual(a.endpoint_index, back.endpoint_index);
    // lengths around 44
    var buf: [46]u8 = undefined;
    @memcpy(buf[0..44], &raw);
    buf[44] = 0;
    buf[45] = 0;
    try testing.expectError(error.InvalidArtifact, saml.decodeArtifact(buf[0..43]));
    try testing.expectError(error.InvalidArtifact, saml.decodeArtifact(buf[0..45]));
    try testing.expectError(error.InvalidArtifact, saml.decodeArtifact(buf[0..46]));
    // another type code is its own error, in either byte
    buf[1] = 0x05;
    try testing.expectError(error.UnsupportedTypeCode, saml.decodeArtifact(buf[0..44]));
    buf[1] = 0x04;
    buf[0] = 0x04;
    try testing.expectError(error.UnsupportedTypeCode, saml.decodeArtifact(buf[0..44]));
    // an endpoint index of 0x0400 decodes as 0x0400, not byte-swapped
    a.endpoint_index = 0x0400;
    const r2 = saml.encodeArtifact(a);
    try testing.expectEqual(@as(u16, 0x0400), (try saml.decodeArtifact(&r2)).endpoint_index);
}

const ArOpts = struct {
    root_local: []const u8 = "ArtifactResponse",
    envelope_local: []const u8 = "Envelope",
    issuer: []const u8 = fx.idp_entity_id,
    destination: ?[]const u8 = null,
    irt: []const u8 = "_ar-req",
    ext: []const u8 = "",
    enclosed: []const u8 = "<samlp:Response ID=\"_inner\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\"/>",
    ref_id: []const u8 = "_ar1",
};

fn arDoc(seed: u64, o: ArOpts) !t.Minted {
    const sb = try t.sigBlock(.{ .ref_id = o.ref_id });
    defer gpa.free(sb);
    const dest = if (o.destination) |d| try gpa.print(" Destination=\"{s}\"", .{d}) else try gpa.dupe(u8, "");
    defer gpa.free(dest);
    const doc = try gpa.print("<soap:{s} xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:unused=\"urn:unused\"><soap:Body>" ++
        "<samlp:{s} xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " ++
        "ID=\"_ar1\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\" InResponseTo=\"{s}\"{s}>" ++
        "<saml:Issuer>{s}</saml:Issuer>{s}" ++
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{s}{s}" ++
        "<samlp:Other ID=\"_decoy\"/></samlp:{s}></soap:Body></soap:{s}>", .{ o.envelope_local, o.root_local, o.irt, dest, o.issuer, sb, o.ext, o.enclosed, o.root_local, o.envelope_local });
    defer gpa.free(doc);
    return t.signDoc(seed, doc, .{ .ref_id = o.ref_id });
}

fn arCfg(key: @import("xmldsig").VerifyKey) saml.ArtifactResponseConfig {
    return .{ .idp_entity_id = fx.idp_entity_id, .idp_key = key, .now_unix = fx.t_valid, .expected_in_response_to = "_ar-req" };
}

test "ArtifactResponse: the enclosed message is the first element that is not Issuer/Signature/Status/Extensions, canonicalized exclusively" {
    var m = try arDoc(0xE010, .{ .ext = "<samlp:Extensions/>" });
    defer m.deinit();
    var res = try saml.consumeArtifactResponseSoap(gpa, m.resp, arCfg(m.key));
    defer res.deinit(gpa);
    try testing.expect(std.mem.startsWith(u8, res.enclosed_message_xml, "<samlp:Response"));
    // exclusive C14N keeps only the namespaces the element visibly uses
    try t.expectAbsent(res.enclosed_message_xml, "xmlns:unused");
    try t.expectAbsent(res.enclosed_message_xml, "xmlns:soap");
    try t.expectContains(res.enclosed_message_xml, "xmlns:samlp=");
}

test "ArtifactResponse: envelope, root, Issuer, Destination and the signed target are checked" {
    {
        var m = try arDoc(0xE011, .{ .envelope_local = "Other" });
        defer m.deinit();
        try testing.expectError(error.MalformedSoap, saml.consumeArtifactResponseSoap(gpa, m.resp, arCfg(m.key)));
    }
    {
        var m = try arDoc(0xE012, .{ .root_local = "Response" });
        defer m.deinit();
        try testing.expectError(error.NotArtifactResponse, saml.consumeArtifactResponseSoap(gpa, m.resp, arCfg(m.key)));
    }
    {
        var m = try arDoc(0xE013, .{ .issuer = "https://other.example.org" });
        defer m.deinit();
        try testing.expectError(error.IssuerMismatch, saml.consumeArtifactResponseSoap(gpa, m.resp, arCfg(m.key)));
    }
    {
        var m = try arDoc(0xE014, .{ .destination = "https://sp.example.org/art" });
        defer m.deinit();
        var cfg = arCfg(m.key);
        cfg.expected_destination = "https://sp.example.org/other";
        try testing.expectError(error.DestinationMismatch, saml.consumeArtifactResponseSoap(gpa, m.resp, cfg));
        cfg.expected_destination = "https://sp.example.org/art";
        var r = try saml.consumeArtifactResponseSoap(gpa, m.resp, cfg);
        r.deinit(gpa);
        cfg.expected_destination = null;
        var r2 = try saml.consumeArtifactResponseSoap(gpa, m.resp, cfg);
        r2.deinit(gpa);
    }
    {
        // a valid signature over a different element of the same message
        var m = try arDoc(0xE015, .{ .ref_id = "_decoy" });
        defer m.deinit();
        try testing.expectError(error.SignatureWrappingDetected, saml.consumeArtifactResponseSoap(gpa, m.resp, arCfg(m.key)));
    }
}

// ── IdP metadata ─────────────────────────────────────────────────────────────

const md_open = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" " ++
    "xmlns:mdui=\"urn:oasis:names:tc:SAML:metadata:ui\" xmlns:xml=\"http://www.w3.org/XML/1998/namespace\" entityID=\"https://idp.example.org\">";
const md_close = "</md:EntityDescriptor>";

fn idpDesc(inner: []const u8) ![]u8 {
    return gpa.print(md_open ++ "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">{s}</md:IDPSSODescriptor>" ++ md_close, .{inner});
}

fn keyDesc(use: ?[]const u8, b64cert: []const u8) ![]u8 {
    const u = if (use) |x| try gpa.print(" use=\"{s}\"", .{x}) else try gpa.dupe(u8, "");
    defer gpa.free(u);
    return gpa.print("<md:KeyDescriptor{s}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{s}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>", .{ u, b64cert });
}

test "parseIdpMetadata: only signing (or unmarked) keys and complete SSO endpoints are taken; the root must be an EntityDescriptor" {
    const k1 = try keyDesc("signing", "AQID");
    defer gpa.free(k1);
    const k2 = try keyDesc("encryption", "BAUG");
    defer gpa.free(k2);
    const k3 = try keyDesc(null, "BwgJ");
    defer gpa.free(k3);
    const inner = try std.mem.concat(gpa, u8, &.{
        k1,                                                                           k2,                                             k3,
        "<md:SingleSignOnService Binding=\"urn:b1\" Location=\"https://idp/sso1\"/>", "<md:SingleSignOnService Binding=\"urn:b2\"/>", "<md:SingleSignOnService Location=\"https://idp/sso3\"/>",
        "<md:SingleLogoutService Binding=\"urn:b4\" Location=\"https://idp/slo\"/>",
    });
    defer gpa.free(inner);
    const doc = try idpDesc(inner);
    defer gpa.free(doc);
    var md = try saml.parseIdpMetadata(gpa, doc);
    defer md.deinit();
    try testing.expectEqualStrings("https://idp.example.org", md.entity_id);
    try testing.expectEqual(@as(usize, 1), md.sso_endpoints.len);
    try testing.expectEqualStrings("https://idp/sso1", md.sso_endpoints[0].location);
    try testing.expectEqual(@as(usize, 2), md.signing_certs_der.len);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, md.signing_certs_der[0]);
    try testing.expectEqualSlices(u8, &.{ 7, 8, 9 }, md.signing_certs_der[1]);

    // wrong root, and an EntitiesDescriptor handed to the single-entity entry point
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadata(gpa, "<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"/>"));
    const wrong_ns = try t.replaceOnce(doc, "urn:oasis:names:tc:SAML:2.0:metadata", "urn:example:other");
    defer gpa.free(wrong_ns);
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadata(gpa, wrong_ns));
    // an entity that has no IdP descriptor
    try testing.expectError(error.NoIdpDescriptor, saml.parseIdpMetadata(gpa, md_open ++ "<md:SPSSODescriptor protocolSupportEnumeration=\"x\"/>" ++ md_close));
}

test "parseIdpMetadata: UIInfo entries are namespace-strict, trimmed, language-tagged and capped at max_ui_entries" {
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(gpa);
    try inner.appendSlice(gpa, "<md:Extensions><mdui:UIInfo>");
    try inner.appendSlice(gpa, "<mdui:DisplayName xml:lang=\"en\">\n  Name \n</mdui:DisplayName><mdui:Description>d</mdui:Description>");
    try inner.appendSlice(gpa, "<mdui:Logo height=\"16\" width=\"32\" xml:lang=\"cs\"> https://x/l.png </mdui:Logo>");
    try inner.appendSlice(gpa, "<mdui:Logo height=\"16\">no width</mdui:Logo><mdui:Logo width=\"x\" height=\"1\">bad</mdui:Logo>");
    try inner.appendSlice(gpa, "<md:DisplayName>wrong namespace</md:DisplayName><mdui:Keywords>ignored</mdui:Keywords>");
    try inner.appendSlice(gpa, "</mdui:UIInfo><mdui:UIInfo><mdui:DisplayName xml:lang=\"fr\">second block</mdui:DisplayName></mdui:UIInfo><md:Other><mdui:UIInfo><mdui:DisplayName>nested</mdui:DisplayName></mdui:UIInfo></md:Other><mdui:Other><mdui:DisplayName>sibling</mdui:DisplayName></mdui:Other></md:Extensions>");
    const doc = try idpDesc(inner.items);
    defer gpa.free(doc);
    var md = try saml.parseIdpMetadata(gpa, doc);
    defer md.deinit();
    const ui = md.ui_info;
    try testing.expectEqual(@as(usize, 2), ui.display_names.len);
    try testing.expectEqualStrings("Name", ui.display_names[0].value);
    try testing.expectEqualStrings("en", ui.display_names[0].lang);
    try testing.expectEqualStrings("second block", ui.display_names[1].value);
    try testing.expectEqual(@as(usize, 1), ui.descriptions.len);
    try testing.expectEqualStrings("", ui.descriptions[0].lang);
    try testing.expectEqual(@as(usize, 1), ui.logos.len);
    try testing.expectEqual(@as(u32, 32), ui.logos[0].width);
    try testing.expectEqual(@as(u32, 16), ui.logos[0].height);
    try testing.expectEqualStrings("https://x/l.png", ui.logos[0].url);
    try testing.expectEqualStrings("cs", ui.logos[0].lang);

    // each list stops at max_ui_entries
    var many: std.ArrayList(u8) = .empty;
    defer many.deinit(gpa);
    try many.appendSlice(gpa, "<md:Extensions><mdui:UIInfo>");
    var i: usize = 0;
    while (i < saml.max_ui_entries + 5) : (i += 1) {
        try many.appendSlice(gpa, "<mdui:DisplayName>n</mdui:DisplayName><mdui:Description>d</mdui:Description><mdui:Logo width=\"1\" height=\"1\">u</mdui:Logo>");
    }
    try many.appendSlice(gpa, "</mdui:UIInfo></md:Extensions>");
    const doc2 = try idpDesc(many.items);
    defer gpa.free(doc2);
    var md2 = try saml.parseIdpMetadata(gpa, doc2);
    defer md2.deinit();
    try testing.expectEqual(@as(usize, saml.max_ui_entries), md2.ui_info.display_names.len);
    try testing.expectEqual(@as(usize, saml.max_ui_entries), md2.ui_info.descriptions.len);
    try testing.expectEqual(@as(usize, saml.max_ui_entries), md2.ui_info.logos.len);
}

fn entity(id: []const u8) ![]u8 {
    return gpa.print("<md:EntityDescriptor entityID=\"{s}\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"/></md:EntityDescriptor>", .{id});
}

const agg_open = "<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">";

test "parseIdpMetadataFor: selection by entityID, ambiguity, entity budget and nesting depth" {
    const e1 = try entity("https://a");
    defer gpa.free(e1);
    const e2 = try entity("https://b");
    defer gpa.free(e2);
    const e2b = try entity("https://b");
    defer gpa.free(e2b);
    const noid = "<md:EntityDescriptor><md:IDPSSODescriptor/></md:EntityDescriptor>";

    const agg = try std.mem.concat(gpa, u8, &.{ agg_open, noid, e1, e2, "</md:EntitiesDescriptor>" });
    defer gpa.free(agg);
    var md = try saml.parseIdpMetadataFor(gpa, agg, "https://b", .{});
    md.deinit();
    try testing.expectError(error.EntityNotFound, saml.parseIdpMetadataFor(gpa, agg, "https://c", .{}));

    const dup = try std.mem.concat(gpa, u8, &.{ agg_open, e1, e2, e2b, "</md:EntitiesDescriptor>" });
    defer gpa.free(dup);
    try testing.expectError(error.AmbiguousEntity, saml.parseIdpMetadataFor(gpa, dup, "https://b", .{}));
    var one = try saml.parseIdpMetadataFor(gpa, dup, "https://a", .{});
    one.deinit();

    // a single entity as the document root
    const single = try std.mem.concat(gpa, u8, &.{"<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://s\"><md:IDPSSODescriptor/></md:EntityDescriptor>"});
    defer gpa.free(single);
    var s = try saml.parseIdpMetadataFor(gpa, single, "https://s", .{});
    s.deinit();
    try testing.expectError(error.EntityNotFound, saml.parseIdpMetadataFor(gpa, single, "https://other", .{}));
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(gpa, "<md:Other xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"/>", "x", .{}));

    // entity budget: every entity counts, found or not; three entities pass max 3 and fail max 2
    const three = try std.mem.concat(gpa, u8, &.{ agg_open, e1, e2, e2b, "</md:EntitiesDescriptor>" });
    defer gpa.free(three);
    var ok = try saml.parseIdpMetadataFor(gpa, three, "https://a", .{ .max_entities = 3 });
    ok.deinit();
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(gpa, three, "https://a", .{ .max_entities = 2 }));

    // nesting depth: k nested groups around one entity pass max_nesting = k and fail max_nesting = k - 1
    for ([_]u8{ 1, 3, 8 }) |k| {
        var doc: std.ArrayList(u8) = .empty;
        defer doc.deinit(gpa);
        var j: u8 = 0;
        while (j < k) : (j += 1) try doc.appendSlice(gpa, if (j == 0) agg_open else "<md:EntitiesDescriptor>");
        try doc.appendSlice(gpa, e1);
        j = 0;
        while (j < k) : (j += 1) try doc.appendSlice(gpa, "</md:EntitiesDescriptor>");
        var good = try saml.parseIdpMetadataFor(gpa, doc.items, "https://a", .{ .max_nesting = k });
        good.deinit();
        if (k > 1) try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(gpa, doc.items, "https://a", .{ .max_nesting = k - 1 }));
    }
    // and the default depth limit (8) stops a ninth level
    var deep: std.ArrayList(u8) = .empty;
    defer deep.deinit(gpa);
    var j: u8 = 0;
    while (j < 9) : (j += 1) try deep.appendSlice(gpa, if (j == 0) agg_open else "<md:EntitiesDescriptor>");
    try deep.appendSlice(gpa, e1);
    j = 0;
    while (j < 9) : (j += 1) try deep.appendSlice(gpa, "</md:EntitiesDescriptor>");
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadataFor(gpa, deep.items, "https://a", .{}));
}
