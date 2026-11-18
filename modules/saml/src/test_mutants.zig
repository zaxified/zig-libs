// SPDX-License-Identifier: MIT
//! Killing tests from the 2026-11-18 whole-module mutation audit of `root.zig`.
//! Each test names the behaviour it pins; the positive control sits beside the
//! refusal so a refusal cannot pass for the wrong reason. Documents that must
//! carry a valid signature are minted with `test_sign.zig` (or with `mintCustom`
//! below, when the signature algorithm or the id attribute has to differ).

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const sign = @import("test_sign.zig");
const xml = @import("xml");
const xmldsig = @import("xmldsig");
const rsa = @import("rsa");

const gpa = testing.allocator;
const ds_ns = "http://www.w3.org/2000/09/xmldsig#";

// ── shared builders ──────────────────────────────────────────────────────────

pub const nameid_xml = "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.org</saml:NameID>";
pub const bearer_xml =
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
    "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
    "</saml:SubjectConfirmation>";
pub const subject_xml = "<saml:Subject>" ++ nameid_xml ++ bearer_xml ++ "</saml:Subject>";
const audience_xml = "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction>";
pub const conditions_xml = "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++ audience_xml ++ "</saml:Conditions>";
/// Everything an assertion needs after `<saml:Issuer>`.
pub const base_after_issuer = subject_xml ++ conditions_xml;

pub fn baseCfg(key: xmldsig.VerifyKey) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = key,
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = fx.t_valid,
        .expected_in_response_to = fx.request_id,
    };
}

/// A signed assertion wrapped in a Response; `resp` is owned.
pub const Minted = struct {
    resp: []u8,
    key: xmldsig.VerifyKey,
    pub fn deinit(self: *Minted) void {
        gpa.free(self.resp);
        self.* = undefined;
    }
};

fn mint(seed: u64, after_issuer: []const u8) !Minted {
    var signed = try sign.signAssertion(gpa, seed, fx.idp_entity_id, "_mut01", "2024-06-01T12:00:00Z", after_issuer);
    defer signed.deinit(gpa);
    return .{ .resp = try sign.wrapInResponse(gpa, signed.xml), .key = signed.key };
}

pub fn replaceOnce(src: []const u8, needle: []const u8, with: []const u8) ![]u8 {
    try testing.expect(std.mem.find(u8, src, needle) != null);
    return std.mem.replaceOwned(u8, gpa, src, needle, with);
}

pub fn b64(data: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try gpa.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data);
    return out;
}

/// Insert a `<ds:KeyInfo>` carrying `der` right after the signature value.
/// KeyInfo is outside SignedInfo and inside the (omitted) enveloped Signature,
/// so the signature stays valid.
fn withKeyInfo(src: []const u8, der: []const u8) ![]u8 {
    const cert_b64 = try b64(der);
    defer gpa.free(cert_b64);
    const ki = try gpa.print("</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{s}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>", .{cert_b64});
    defer gpa.free(ki);
    return replaceOnce(src, "</ds:SignatureValue>", ki);
}

/// A signed assertion wrapped in a Response, optionally with a KeyInfo
/// certificate inside the assertion's signature.
pub fn mintA(seed: u64, after_issuer: []const u8, cert: ?[]const u8) !Minted {
    var signed = try sign.signAssertion(gpa, seed, fx.idp_entity_id, "_mut01", "2024-06-01T12:00:00Z", after_issuer);
    defer signed.deinit(gpa);
    const x = if (cert) |d| try withKeyInfo(signed.xml, d) else try gpa.dupe(u8, signed.xml);
    defer gpa.free(x);
    return .{ .resp = try sign.wrapInResponse(gpa, x), .key = signed.key };
}

const unsigned_assertion = "<saml:Assertion ID=\"_ua1\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\"><saml:Issuer>" ++ fx.idp_entity_id ++ "</saml:Issuer>" ++ base_after_issuer ++ "</saml:Assertion>";

/// A Response-level signed Response around `assertion_xml` (unsigned content).
fn mintR(seed: u64, assertion_xml: []const u8, cert: ?[]const u8) !Minted {
    var signed = try sign.signResponse(gpa, seed, "_rr1", "2024-06-01T12:00:00Z", fx.acs_url, fx.request_id, fx.idp_entity_id, assertion_xml);
    defer signed.deinit(gpa);
    const x = if (cert) |d| try withKeyInfo(signed.xml, d) else try gpa.dupe(u8, signed.xml);
    return .{ .resp = x, .key = signed.key };
}

pub fn otherRsaKey(seed: u64) !xmldsig.VerifyKey {
    var prng = std.Random.DefaultPrng.init(seed);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);
    return .{ .rsa = kp.public_key };
}

pub const SignOpts = struct {
    /// Name of the id attribute on signed elements.
    id_attr: []const u8 = "ID",
    /// Digest + RSA hash: sha256 (default) or the weak sha1.
    sha1: bool = false,
    /// The id the single Reference points at.
    ref_id: []const u8 = "_cust01",
};

const placeholder = "__DIGEST_PLACEHOLDER__";

/// `<ds:Signature>` with one enveloped+exclusive-C14N reference at `#ref_id`,
/// empty SignatureValue and a digest placeholder; for `signDoc`.
pub fn sigBlock(opts: SignOpts) ![]u8 {
    const sig_alg = if (opts.sha1) "http://www.w3.org/2000/09/xmldsig#rsa-sha1" else "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    const dig_alg = if (opts.sha1) "http://www.w3.org/2000/09/xmldsig#sha1" else "http://www.w3.org/2001/04/xmlenc#sha256";
    return gpa.print("<ds:Signature xmlns:ds=\"{s}\"><ds:SignedInfo>" ++
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"{s}\"/>" ++
        "<ds:Reference URI=\"#{s}\"><ds:Transforms>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "</ds:Transforms><ds:DigestMethod Algorithm=\"{s}\"/>" ++
        "<ds:DigestValue>" ++ placeholder ++ "</ds:DigestValue></ds:Reference></ds:SignedInfo>" ++
        "<ds:SignatureValue></ds:SignatureValue></ds:Signature>", .{ ds_ns, sig_alg, opts.ref_id, dig_alg });
}

fn findByAttr(el: *const xml.Element, name: []const u8, value: []const u8) ?*xml.Element {
    if (el.attr("", name)) |v| if (std.mem.eql(u8, v, value)) return @constCast(el);
    for (el.children) |c| switch (c.content) {
        .element => |child| if (findByAttr(child, name, value)) |f| return f,
        else => {},
    };
    return null;
}

/// Sign `assembled` (one `sigBlock` in it): the digest is taken over the
/// element whose id attribute is `opts.ref_id`, the Signature omitted.
pub fn signDoc(seed: u64, assembled: []const u8, opts: SignOpts) !Minted {
    var prng = std.Random.DefaultPrng.init(seed);
    var kp: rsa.KeyPair = undefined;
    try rsa.generate(&kp, prng.random(), 1024, 65537);

    var doc1 = try xml.parse(gpa, assembled, .{ .id_attr_names = &.{opts.id_attr} });
    defer doc1.deinit();
    const sig1 = findByLocal(doc1.root, "Signature").?;
    const target = findByAttr(doc1.root, opts.id_attr, opts.ref_id).?;
    const ref_canon = try xmldsig.c14n.canonicalize(gpa, target, .{ .mode = .exclusive, .omit = sig1 });
    defer gpa.free(ref_canon);
    var d1: [20]u8 = undefined;
    var d256: [32]u8 = undefined;
    const digest: []const u8 = if (opts.sha1) blk: {
        std.crypto.hash.Sha1.hash(ref_canon, &d1, .{});
        break :blk &d1;
    } else blk: {
        std.crypto.hash.sha2.Sha256.hash(ref_canon, &d256, .{});
        break :blk &d256;
    };
    const digest_b64 = try b64(digest);
    defer gpa.free(digest_b64);
    const with_digest = try std.mem.replaceOwned(u8, gpa, assembled, placeholder, digest_b64);
    defer gpa.free(with_digest);

    var doc2 = try xml.parse(gpa, with_digest, .{ .id_attr_names = &.{opts.id_attr} });
    defer doc2.deinit();
    const si = findByLocal(doc2.root, "SignedInfo").?;
    const si_canon = try xmldsig.c14n.canonicalize(gpa, si, .{ .mode = .exclusive });
    defer gpa.free(si_canon);
    var sig_buf: [512]u8 = undefined;
    const sig = if (opts.sha1)
        try rsa.signPkcs1v15(&kp.secret_key, std.crypto.hash.Sha1, si_canon, &sig_buf)
    else
        try rsa.signPkcs1v15(&kp.secret_key, std.crypto.hash.sha2.Sha256, si_canon, &sig_buf);
    const sig_b64 = try b64(sig);
    defer gpa.free(sig_b64);
    const filled = try gpa.print("<ds:SignatureValue>{s}</ds:SignatureValue>", .{sig_b64});
    defer gpa.free(filled);
    return .{
        .resp = try std.mem.replaceOwned(u8, gpa, with_digest, "<ds:SignatureValue></ds:SignatureValue>", filled),
        .key = .{ .rsa = kp.public_key },
    };
}

/// An assertion signed with `signDoc`, wrapped in a Response.
fn mintCustom(seed: u64, opts: SignOpts, after_issuer: []const u8) !Minted {
    const sb = try sigBlock(opts);
    defer gpa.free(sb);
    const assembled = try gpa.print("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" {s}=\"{s}\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>{s}</saml:Issuer>{s}{s}</saml:Assertion>", .{ opts.id_attr, opts.ref_id, fx.idp_entity_id, sb, after_issuer });
    defer gpa.free(assembled);
    const signed = try signDoc(seed, assembled, opts);
    defer gpa.free(signed.resp);
    const wrapped = try sign.wrapInResponse(gpa, signed.resp);
    return .{ .resp = wrapped, .key = signed.key };
}

pub fn findByLocal(el: *const xml.Element, local: []const u8) ?*xml.Element {
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (std.mem.eql(u8, child.local, local)) return child;
            if (findByLocal(child, local)) |f| return f;
        },
        else => {},
    };
    return null;
}

// ── redirect-binding inflate (ZeroPadded reader) ─────────────────────────────

test "decodeRedirectField: the inflate cap is exclusive: max-1 octets decode, max and more are refused" {
    // `Reader.appendRemaining(.limited(n))` cannot tell "exactly n" from "more
    // than n" without reading on, so a stream that inflates to exactly
    // `max_redirect_inflated` octets already reports StreamTooLong.
    const buf = try gpa.alloc(u8, saml.max_redirect_inflated + 1);
    defer gpa.free(buf);
    @memset(buf, 'a');

    const ok_field = try saml.encodeRedirectField(gpa, buf[0 .. saml.max_redirect_inflated - 1]);
    defer gpa.free(ok_field);
    const out = try saml.decodeRedirectField(gpa, ok_field);
    defer gpa.free(out);
    try testing.expectEqual(@as(usize, saml.max_redirect_inflated - 1), out.len);

    for ([_]usize{ saml.max_redirect_inflated, saml.max_redirect_inflated + 1 }) |n| {
        const big_field = try saml.encodeRedirectField(gpa, buf[0..n]);
        defer gpa.free(big_field);
        try testing.expectError(error.InvalidEncoding, saml.decodeRedirectField(gpa, big_field));
    }
}

test "decodeRedirectField: every strict prefix of a deflate stream is refused, whole streams of any length decode" {
    const dec = std.base64.standard.Decoder;
    // Short (fixed-Huffman), repetitive and varied (dynamic-Huffman) inputs.
    var varied: [900]u8 = undefined;
    for (&varied, 0..) |*b, i| b.* = @intCast('a' + (i * 7 + i / 5) % 23);
    const inputs = [_][]const u8{ "<a/>", "<samlp:LogoutRequest ID=\"_1\"/>", &varied, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
    for (inputs) |input| {
        const field = try saml.encodeRedirectField(gpa, input);
        defer gpa.free(field);
        const whole = try saml.decodeRedirectField(gpa, field);
        defer gpa.free(whole);
        try testing.expectEqualSlices(u8, input, whole);

        const raw = try gpa.alloc(u8, try dec.calcSizeForSlice(field));
        defer gpa.free(raw);
        try dec.decode(raw, field);
        var cut: usize = 0;
        while (cut < raw.len) : (cut += 1) {
            const enc = std.base64.standard.Encoder;
            const prefix_b64 = try gpa.alloc(u8, enc.calcSize(cut));
            defer gpa.free(prefix_b64);
            _ = enc.encode(prefix_b64, raw[0..cut]);
            try testing.expectError(error.InvalidEncoding, saml.decodeRedirectField(gpa, prefix_b64));
        }
    }
}

test "decodeRedirectField: a stream cut inside a stored block or inside a zero-decoding dynamic block is refused" {
    // Random bytes deflate to STORED blocks: a cut inside the payload makes the
    // decoder copy zero padding through `ZeroPadded.stream`. A text that is
    // nine tenths 'a' gets a dynamic block in which 'a' is the one-bit code
    // `0`, so a cut there makes zero padding decode as endless 'a's and the
    // reader is asked for more than one refill.
    var prng = std.Random.DefaultPrng.init(0x5A32);
    const rnd = try gpa.alloc(u8, 3000);
    defer gpa.free(rnd);
    prng.random().bytes(rnd);
    const skewed = try gpa.alloc(u8, 3000);
    defer gpa.free(skewed);
    for (skewed) |*b| b.* = if (prng.random().uintLessThan(u8, 10) == 0) 'b' + prng.random().uintLessThan(u8, 5) else 'a';
    for ([_][]const u8{ rnd, skewed }) |input| {
        const field = try saml.encodeRedirectField(gpa, input);
        defer gpa.free(field);
        const whole = try saml.decodeRedirectField(gpa, field);
        defer gpa.free(whole);
        try testing.expectEqualSlices(u8, input, whole);

        const dec = std.base64.standard.Decoder;
        const raw = try gpa.alloc(u8, try dec.calcSizeForSlice(field));
        defer gpa.free(raw);
        try dec.decode(raw, field);
        var cut: usize = 1;
        while (cut < raw.len) : (cut += if (cut + 40 < raw.len) 37 else 1) {
            const enc = std.base64.standard.Encoder;
            const prefix_b64 = try gpa.alloc(u8, enc.calcSize(cut));
            defer gpa.free(prefix_b64);
            _ = enc.encode(prefix_b64, raw[0..cut]);
            try testing.expectError(error.InvalidEncoding, saml.decodeRedirectField(gpa, prefix_b64));
        }
    }
}

test "decodeRedirectField: a long incompressible stream refills the reader and still decodes" {
    // Random bytes deflate to stored/dynamic blocks of about their own size, so
    // the decoder asks the zero-padded reader for more than once.
    var prng = std.Random.DefaultPrng.init(0x5A31);
    const data = try gpa.alloc(u8, 6000);
    defer gpa.free(data);
    prng.random().bytes(data);
    const field = try saml.encodeRedirectField(gpa, data);
    defer gpa.free(field);
    const out = try saml.decodeRedirectField(gpa, field);
    defer gpa.free(out);
    try testing.expectEqualSlices(u8, data, out);
}

// ── untrusted-document budgets ───────────────────────────────────────────────

test "parseIdpMetadata: an element count above the untrusted budget is MalformedMetadata" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.example.org\"><md:IDPSSODescriptor>");
    var i: usize = 0;
    while (i < saml.max_untrusted_elements + 10) : (i += 1) try buf.appendSlice(gpa, "<md:Extensions/>");
    try buf.appendSlice(gpa, "</md:IDPSSODescriptor></md:EntityDescriptor>");
    try testing.expectError(error.MalformedMetadata, saml.parseIdpMetadata(gpa, buf.items));
}

// ── Response shape ───────────────────────────────────────────────────────────

test "consumeResponseXml: the root must be samlp:Response in the SAML protocol namespace" {
    var m = try mint(0xA101, base_after_issuer);
    defer m.deinit();
    // positive control
    {
        var res = try saml.consumeResponseXml(gpa, m.resp, baseCfg(m.key));
        res.deinit();
    }
    // another local name
    {
        const a = try replaceOnce(m.resp, "<samlp:Response ", "<samlp:Foo ");
        defer gpa.free(a);
        const b = try replaceOnce(a, "</samlp:Response>", "</samlp:Foo>");
        defer gpa.free(b);
        try testing.expectError(error.NotSamlResponse, saml.consumeResponseXml(gpa, b, baseCfg(m.key)));
    }
    // right local name, other namespace
    {
        const a = try replaceOnce(m.resp, "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"", "xmlns:samlp=\"urn:example:not-saml\"");
        defer gpa.free(a);
        try testing.expectError(error.NotSamlResponse, saml.consumeResponseXml(gpa, a, baseCfg(m.key)));
    }
}

test "consumeResponseXml: a Response <Issuer> naming another IdP is refused even when the assertion's is right" {
    var m = try mint(0xA102, base_after_issuer);
    defer m.deinit();
    const evil = try replaceOnce(m.resp, "<saml:Issuer>https://idp.example.org/saml</saml:Issuer><samlp:Status>", "<saml:Issuer>https://evil.example.org</saml:Issuer><samlp:Status>");
    defer gpa.free(evil);
    try testing.expectError(error.IssuerMismatch, saml.consumeResponseXml(gpa, evil, baseCfg(m.key)));
}

// ── signature location policy, certificate, key index ───────────────────────

const der_blob = [_]u8{ 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x13, 0x37 };

fn expectAccepted(resp: []const u8, cfg: saml.Config) !saml.AuthnResult {
    return saml.consumeResponseXml(gpa, resp, cfg);
}

test "signature_policy: an assertion-level signature satisfies .assertion and .either, never .response" {
    var m = try mintA(0xB001, base_after_issuer, &der_blob);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    inline for (.{ saml.SignaturePolicy.assertion, .either }) |p| {
        cfg.signature_policy = p;
        var res = try expectAccepted(m.resp, cfg);
        defer res.deinit();
        // The certificate seen on the verifying signature is surfaced for pinning.
        try testing.expectEqualSlices(u8, &der_blob, res.x509_cert_der.?);
    }
    cfg.signature_policy = .response;
    try testing.expectError(error.SignatureMissing, saml.consumeResponseXml(gpa, m.resp, cfg));
}

test "signature_policy: a Response-level signature satisfies .response and .either, never .assertion" {
    var m = try mintR(0xB002, unsigned_assertion, &der_blob);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    inline for (.{ saml.SignaturePolicy.response, .either }) |p| {
        cfg.signature_policy = p;
        var res = try expectAccepted(m.resp, cfg);
        defer res.deinit();
        try testing.expectEqualSlices(u8, &der_blob, res.x509_cert_der.?);
    }
    cfg.signature_policy = .assertion;
    try testing.expectError(error.SignatureMissing, saml.consumeResponseXml(gpa, m.resp, cfg));
}

test "idp_key_index: the verifying key's position is reported for assertion- and Response-level signatures" {
    const wrong1 = try otherRsaKey(0xB0A1);
    const wrong2 = try otherRsaKey(0xB0A2);
    var a = try mintA(0xB003, base_after_issuer, null);
    defer a.deinit();
    var r = try mintR(0xB004, unsigned_assertion, null);
    defer r.deinit();
    inline for (.{ &a, &r }) |m| {
        var cfg = baseCfg(wrong1);
        const extra = [_]xmldsig.VerifyKey{ wrong2, m.key };
        cfg.additional_idp_keys = &extra;
        var res = try expectAccepted(m.resp, cfg);
        defer res.deinit();
        try testing.expectEqual(@as(usize, 2), res.idp_key_index);
        try testing.expect(res.x509_cert_der == null);
    }
}

// ── signature algorithm gates and the id attribute ───────────────────────────

test "allow_weak_sha1: an RSA-SHA1 / SHA-1 digest signature is refused by default and accepted only on request" {
    var m = try mintCustom(0xB010, .{ .sha1 = true }, base_after_issuer);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(gpa, m.resp, cfg));
    cfg.allow_weak_sha1 = true;
    var res = try expectAccepted(m.resp, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

test "id_attr: the configured id attribute drives signature resolution and assertion_id" {
    var m = try mintCustom(0xB011, .{ .id_attr = "Id" }, base_after_issuer);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    cfg.id_attr = "Id";
    var res = try expectAccepted(m.resp, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("_cust01", res.assertion_id);
    // With the default attribute name the reference does not resolve.
    cfg.id_attr = "ID";
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(gpa, m.resp, cfg));
}

test "max_c14n_output_len: the configured cap reaches the verifier (a cap below the assertion refuses it)" {
    var m = try mintA(0xB012, base_after_issuer, null);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    var ok = try expectAccepted(m.resp, cfg);
    ok.deinit();
    cfg.max_c14n_output_len = 64;
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(gpa, m.resp, cfg));
}

// ── EncryptedAssertion: where the signature sits, version, key index ─────────

const encutil = @import("test_encutil.zig");

fn encrypted(pk: rsa.PublicKey, plaintext: []const u8) ![]u8 {
    return encutil.encryptedWrapper(gpa, pk, "EncryptedAssertion", plaintext);
}

test "EncryptedAssertion: the inner signature satisfies .either/.assertion only; cert and key index come from it" {
    var kp = try encutil.makeSpKey(0xB020);
    var inner = try mintA(0xB021, base_after_issuer, &der_blob);
    defer inner.deinit();
    // Re-extract the bare signed assertion from the minted Response.
    const open = std.mem.find(u8, inner.resp, "<saml:Assertion").?;
    const close = std.mem.find(u8, inner.resp, "</saml:Assertion>").? + "</saml:Assertion>".len;
    const enc = try encrypted(kp.public_key, inner.resp[open..close]);
    defer gpa.free(enc);
    const resp = try sign.wrapInResponse(gpa, enc);
    defer gpa.free(resp);

    const wrong = try otherRsaKey(0xB022);
    var cfg = baseCfg(wrong);
    const extra = [_]xmldsig.VerifyKey{inner.key};
    cfg.additional_idp_keys = &extra;
    cfg.sp_decrypt_key = &kp.secret_key;
    inline for (.{ saml.SignaturePolicy.assertion, .either }) |p| {
        cfg.signature_policy = p;
        var res = try expectAccepted(resp, cfg);
        defer res.deinit();
        try testing.expectEqual(@as(usize, 1), res.idp_key_index);
        try testing.expectEqualSlices(u8, &der_blob, res.x509_cert_der.?);
    }
    cfg.signature_policy = .response;
    try testing.expectError(error.SignatureMissing, saml.consumeResponseXml(gpa, resp, cfg));
}

test "EncryptedAssertion: an outer (Response) signature satisfies .either/.response only; cert and key index come from it" {
    var kp = try encutil.makeSpKey(0xB023);
    const enc = try encrypted(kp.public_key, unsigned_assertion_selfcontained);
    defer gpa.free(enc);
    var m = try mintR(0xB024, enc, &der_blob);
    defer m.deinit();

    const wrong = try otherRsaKey(0xB025);
    var cfg = baseCfg(wrong);
    const extra = [_]xmldsig.VerifyKey{m.key};
    cfg.additional_idp_keys = &extra;
    cfg.sp_decrypt_key = &kp.secret_key;
    inline for (.{ saml.SignaturePolicy.response, .either }) |p| {
        cfg.signature_policy = p;
        var res = try expectAccepted(m.resp, cfg);
        defer res.deinit();
        try testing.expectEqual(@as(usize, 1), res.idp_key_index);
        try testing.expectEqualSlices(u8, &der_blob, res.x509_cert_der.?);
    }
    cfg.signature_policy = .assertion;
    try testing.expectError(error.SignatureMissing, saml.consumeResponseXml(gpa, m.resp, cfg));
}

const unsigned_assertion_selfcontained = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_ua1\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\"><saml:Issuer>" ++ fx.idp_entity_id ++ "</saml:Issuer>" ++ base_after_issuer ++ "</saml:Assertion>";

test "EncryptedAssertion: an unsigned plaintext is SignatureMissing; a Version other than 2.0 is refused before that" {
    var kp = try encutil.makeSpKey(0xB026);
    const key = try otherRsaKey(0xB027);
    var c2 = baseCfg(key);
    c2.sp_decrypt_key = &kp.secret_key;

    const enc = try encrypted(kp.public_key, unsigned_assertion_selfcontained);
    defer gpa.free(enc);
    const resp = try sign.wrapInResponse(gpa, enc);
    defer gpa.free(resp);
    try testing.expectError(error.SignatureMissing, saml.consumeResponseXml(gpa, resp, c2));

    const v11 = try replaceOnce(unsigned_assertion_selfcontained, "Version=\"2.0\"", "Version=\"1.1\"");
    defer gpa.free(v11);
    const enc2 = try encrypted(kp.public_key, v11);
    defer gpa.free(enc2);
    const resp2 = try sign.wrapInResponse(gpa, enc2);
    defer gpa.free(resp2);
    try testing.expectError(error.UnsupportedSamlVersion, saml.consumeResponseXml(gpa, resp2, c2));
}

test "EncryptedAssertion: an outer signature over some other element is a wrapping attack, not a signed Response" {
    var kp = try encutil.makeSpKey(0xB028);
    const enc = try encrypted(kp.public_key, unsigned_assertion_selfcontained);
    defer gpa.free(enc);
    const sb = try sigBlock(.{ .ref_id = "_decoy" });
    defer gpa.free(sb);
    const assembled = try gpa.print("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " ++
        "ID=\"_rr2\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\" Destination=\"{s}\" InResponseTo=\"{s}\">" ++
        "<saml:Issuer>{s}</saml:Issuer>{s}" ++
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" ++
        "<samlp:Extensions ID=\"_decoy\"/>{s}</samlp:Response>", .{ fx.acs_url, fx.request_id, fx.idp_entity_id, sb, enc });
    defer gpa.free(assembled);
    var m = try signDoc(0xB029, assembled, .{ .ref_id = "_decoy" });
    defer m.deinit();
    var cfg = baseCfg(m.key);
    cfg.sp_decrypt_key = &kp.secret_key;
    try testing.expectError(error.SignatureWrappingDetected, saml.consumeResponseXml(gpa, m.resp, cfg));
}

// ── Conditions / SubjectConfirmation time windows (boundary + skew) ──────────

const wide_conditions = "<saml:Conditions NotBefore=\"2024-06-01T11:00:00Z\" NotOnOrAfter=\"2024-06-01T13:00:00Z\">" ++ audience_xml ++ "</saml:Conditions>";
const wide_bearer =
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
    "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T13:00:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
    "</saml:SubjectConfirmation>";
/// NotBefore = t_valid + 600, NotOnOrAfter = t_valid + 1200.
const win_attrs = " NotBefore=\"2024-06-01T12:10:00Z\" NotOnOrAfter=\"2024-06-01T12:20:00Z\"";
const nb_t: i64 = fx.t_valid + 600;
const noa_t: i64 = fx.t_valid + 1200;

pub fn probe(m: Minted, cfg: saml.Config, now: i64, expect: ?anyerror) !void {
    var c = cfg;
    c.now_unix = now;
    if (expect) |e| {
        try testing.expectError(e, saml.consumeResponseXml(gpa, m.resp, c));
    } else {
        var r = try saml.consumeResponseXml(gpa, m.resp, c);
        r.deinit();
    }
}

/// The lower bound `nb_t` and the upper bound `noa_t` with the default 60 s
/// skew: the exact edges are the verdicts that tell `<` from `<=`, `>=` from `>`
/// and a skewed bound from a bare one.
pub fn probeWindow(m: Minted, cfg: saml.Config, lower: bool, upper: bool) !void {
    const skew = cfg.clock_skew_secs;
    if (lower) {
        try probe(m, cfg, nb_t - skew - 1, error.AssertionNotYetValid);
        try probe(m, cfg, nb_t - skew, null);
    }
    if (upper) {
        try probe(m, cfg, noa_t + skew - 1, null);
        try probe(m, cfg, noa_t + skew, error.AssertionExpired);
    }
}

test "time window: <Conditions> NotBefore / NotOnOrAfter edges with skew" {
    const after = "<saml:Subject>" ++ nameid_xml ++ wide_bearer ++ "</saml:Subject>" ++
        "<saml:Conditions" ++ win_attrs ++ ">" ++ audience_xml ++ "</saml:Conditions>";
    var m = try mintA(0xC001, after, null);
    defer m.deinit();
    try probeWindow(m, baseCfg(m.key), true, true);
}

test "time window: bearer SubjectConfirmationData NotOnOrAfter edge with skew" {
    const bearer = "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
        "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:20:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/></saml:SubjectConfirmation>";
    const after = "<saml:Subject>" ++ nameid_xml ++ bearer ++ "</saml:Subject>" ++ wide_conditions;
    var m = try mintA(0xC002, after, null);
    defer m.deinit();
    try probeWindow(m, baseCfg(m.key), false, true);
}

fn hokSc(attrs: []const u8) ![]u8 {
    const cb = try b64(&der_blob);
    defer gpa.free(cb);
    return gpa.print("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:holder-of-key\"><saml:SubjectConfirmationData{s}>" ++
        "<ds:KeyInfo xmlns:ds=\"{s}\"><ds:X509Data><ds:X509Certificate>{s}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" ++
        "</saml:SubjectConfirmationData></saml:SubjectConfirmation>", .{ attrs, ds_ns, cb });
}

fn subjectWith(scs: []const u8, conditions: []const u8) ![]u8 {
    return gpa.print("<saml:Subject>{s}{s}</saml:Subject>{s}", .{ nameid_xml, scs, conditions });
}

test "time window: Holder-of-Key SubjectConfirmationData NotBefore / NotOnOrAfter edges with skew" {
    const sc = try hokSc(win_attrs);
    defer gpa.free(sc);
    const after = try subjectWith(sc, wide_conditions);
    defer gpa.free(after);
    var m = try mintA(0xC003, after, null);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_cert_der = &der_blob;
    try probeWindow(m, cfg, true, true);
}

test "time window: sender-vouches SubjectConfirmationData NotBefore / NotOnOrAfter edges with skew" {
    const sc = "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:sender-vouches\"><saml:SubjectConfirmationData" ++ win_attrs ++ "/></saml:SubjectConfirmation>";
    const after = try subjectWith(sc, wide_conditions);
    defer gpa.free(after);
    var m = try mintA(0xC004, after, null);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    cfg.subject_confirmation = .sender_vouches;
    try probeWindow(m, cfg, true, true);
}

// ── SubjectConfirmation policy and error precedence ──────────────────────────

const bearer_bad_recipient =
    "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
    "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://evil.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
    "</saml:SubjectConfirmation>";
const sv_sc = "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:sender-vouches\"/>";
const hok_attrs = " NotOnOrAfter=\"2024-06-01T12:05:00Z\"";

fn mintSubject(seed: u64, scs: []const u8) !Minted {
    const after = try subjectWith(scs, conditions_xml);
    defer gpa.free(after);
    return mintA(seed, after, null);
}

test "subject_confirmation policy: a method is accepted under its own policy and .either, refused under the others" {
    const hok = try hokSc(hok_attrs);
    defer gpa.free(hok);
    const scs = [_][]const u8{ bearer_xml, hok, sv_sc };
    const own = [_]saml.SubjectConfirmationPolicy{ .bearer, .holder_of_key, .sender_vouches };
    for (scs, own, 0..) |sc, mine, i| {
        var m = try mintSubject(0xC010 + i, sc);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.presented_holder_cert_der = &der_blob;
        for ([_]saml.SubjectConfirmationPolicy{ .bearer, .holder_of_key, .sender_vouches, .either }) |p| {
            cfg.subject_confirmation = p;
            if (p == mine or p == .either) {
                var res = try expectAccepted(m.resp, cfg);
                res.deinit();
            } else {
                try testing.expectError(error.SubjectConfirmationMethodNotAllowed, saml.consumeResponseXml(gpa, m.resp, cfg));
            }
        }
    }
}

test "subject_confirmation: the FIRST failure is the one reported, whatever later confirmations say" {
    const hok = try hokSc(hok_attrs);
    defer gpa.free(hok);
    const Case = struct { scs: []const []const u8, policy: saml.SubjectConfirmationPolicy, err: anyerror, presented: bool };
    const cases = [_]Case{
        // 1. bearer fails (Recipient), then a disallowed HoK / sender-vouches
        .{ .scs = &.{ bearer_bad_recipient, hok }, .policy = .bearer, .err = error.RecipientMismatch, .presented = true },
        .{ .scs = &.{ bearer_bad_recipient, sv_sc }, .policy = .bearer, .err = error.RecipientMismatch, .presented = true },
        // 2. a disallowed HoK first, then a failing bearer
        .{ .scs = &.{ hok, bearer_bad_recipient }, .policy = .bearer, .err = error.SubjectConfirmationMethodNotAllowed, .presented = true },
        // 3. a failing HoK (no presented key), then a disallowed bearer
        .{ .scs = &.{ hok, bearer_xml }, .policy = .holder_of_key, .err = error.PresentedKeyMissing, .presented = false },
        // 4. a failing bearer, then a failing HoK (no presented key)
        .{ .scs = &.{ bearer_bad_recipient, hok }, .policy = .either, .err = error.RecipientMismatch, .presented = false },
        // 5. a failing sender-vouches-free document: nothing matched at all
        .{ .scs = &.{}, .policy = .either, .err = error.SubjectConfirmationFailed, .presented = false },
    };
    for (cases, 0..) |c, i| {
        const joined = try std.mem.concat(gpa, u8, c.scs);
        defer gpa.free(joined);
        var m = try mintSubject(0xC020 + i, joined);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.subject_confirmation = c.policy;
        if (c.presented) cfg.presented_holder_cert_der = &der_blob;
        try testing.expectError(c.err, saml.consumeResponseXml(gpa, m.resp, cfg));
    }
}

test "subject_confirmation: only <SubjectConfirmation> elements count" {
    const fake = "<saml:Other Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
        "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/></saml:Other>";
    var m = try mintSubject(0xC030, fake);
    defer m.deinit();
    try testing.expectError(error.SubjectConfirmationFailed, saml.consumeResponseXml(gpa, m.resp, baseCfg(m.key)));
}

// ── bearer / Holder-of-Key recipient and InResponseTo ────────────────────────

test "bearer: Recipient is required; InResponseTo needs an expectation unless IdP-initiated is allowed" {
    const no_recipient = "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
        "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" InResponseTo=\"req-9988776655\"/></saml:SubjectConfirmation>";
    var m1 = try mintSubject(0xC040, no_recipient);
    defer m1.deinit();
    try testing.expectError(error.RecipientMismatch, saml.consumeResponseXml(gpa, m1.resp, baseCfg(m1.key)));

    // InResponseTo present, nothing expected: refused (also with IdP-initiated allowed).
    var m2 = try mintSubject(0xC041, bearer_xml);
    defer m2.deinit();
    var cfg = baseCfg(m2.key);
    cfg.expected_in_response_to = null;
    try testing.expectError(error.InResponseToMismatch, saml.consumeResponseXml(gpa, m2.resp, cfg));
    cfg.allow_idp_initiated = true;
    try testing.expectError(error.InResponseToMismatch, saml.consumeResponseXml(gpa, m2.resp, cfg));

    // No InResponseTo at all: only an IdP-initiated flow accepts it.
    const unsolicited = "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
        "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\"/></saml:SubjectConfirmation>";
    var m3 = try mintSubject(0xC042, unsolicited);
    defer m3.deinit();
    var c3 = baseCfg(m3.key);
    try testing.expectError(error.InResponseToMismatch, saml.consumeResponseXml(gpa, m3.resp, c3));
    c3.allow_idp_initiated = true;
    var res = try expectAccepted(m3.resp, c3);
    res.deinit();
    c3.expected_in_response_to = null;
    var res2 = try expectAccepted(m3.resp, c3);
    res2.deinit();
}

test "holder-of-key: Recipient and InResponseTo, when present, must match; both are optional" {
    const Case = struct { attrs: []const u8, expect: ?anyerror };
    const cases = [_]Case{
        .{ .attrs = hok_attrs ++ " Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"", .expect = null },
        .{ .attrs = hok_attrs ++ " Recipient=\"https://evil.example.org/acs\"", .expect = error.RecipientMismatch },
        .{ .attrs = hok_attrs ++ " InResponseTo=\"req-other\"", .expect = error.InResponseToMismatch },
        .{ .attrs = hok_attrs, .expect = null },
    };
    for (cases, 0..) |c, i| {
        const sc = try hokSc(c.attrs);
        defer gpa.free(sc);
        var m = try mintSubject(0xC050 + i, sc);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.subject_confirmation = .holder_of_key;
        cfg.presented_holder_cert_der = &der_blob;
        try probe(m, cfg, fx.t_valid, c.expect);
        if (c.expect == null) {
            // an InResponseTo with no expectation configured is not an error for HoK
            cfg.expected_in_response_to = null;
            try probe(m, cfg, fx.t_valid, null);
        }
    }
    // Neither a presented certificate nor a presented key: nothing to compare with.
    const sc = try hokSc(hok_attrs);
    defer gpa.free(sc);
    var m = try mintSubject(0xC060, sc);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    cfg.subject_confirmation = .holder_of_key;
    try testing.expectError(error.PresentedKeyMissing, saml.consumeResponseXml(gpa, m.resp, cfg));
}

// ── Conditions and Audience ──────────────────────────────────────────────────

fn mintConditions(seed: u64, conditions: []const u8) !Minted {
    const after = try std.mem.concat(gpa, u8, &.{ subject_xml, conditions });
    defer gpa.free(after);
    return mintA(seed, after, null);
}

test "conditions: an audience is mandatory, unknown conditions are refused, restrictions are ANDed, OneTimeUse is reported" {
    const Case = struct { conditions: []const u8, expect: ?anyerror };
    const cases = [_]Case{
        .{ .conditions = "", .expect = error.AudienceMismatch },
        .{ .conditions = "<saml:Conditions NotOnOrAfter=\"2024-06-01T13:00:00Z\"/>", .expect = error.AudienceMismatch },
        .{ .conditions = "<saml:Conditions>" ++ audience_xml ++ "<saml:Condition/></saml:Conditions>", .expect = error.ConditionNotUnderstood },
        .{ .conditions = "<saml:Conditions>" ++ audience_xml ++ "<saml:AudienceRestriction><saml:Audience>https://other.example.org</saml:Audience></saml:AudienceRestriction></saml:Conditions>", .expect = error.AudienceMismatch },
        .{ .conditions = "<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://other.example.org</saml:Audience><saml:Audience>  https://sp.example.org/metadata \n</saml:Audience></saml:AudienceRestriction></saml:Conditions>", .expect = null },
        .{ .conditions = "<saml:Conditions><saml:AudienceRestriction><saml:Other>https://sp.example.org/metadata</saml:Other></saml:AudienceRestriction></saml:Conditions>", .expect = error.AudienceMismatch },
        .{ .conditions = "<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata/</saml:Audience></saml:AudienceRestriction></saml:Conditions>", .expect = error.AudienceMismatch },
    };
    for (cases, 0..) |c, i| {
        var m = try mintConditions(0xC070 + i, c.conditions);
        defer m.deinit();
        try probe(m, baseCfg(m.key), fx.t_valid, c.expect);
    }
    var m = try mintConditions(0xC080, "<saml:Conditions>" ++ audience_xml ++ "<saml:OneTimeUse/></saml:Conditions>");
    defer m.deinit();
    var res = try expectAccepted(m.resp, baseCfg(m.key));
    defer res.deinit();
    try testing.expect(res.one_time_use);
    try testing.expect(res.session_not_on_or_after == null);
}

// ── result extraction: trimming, attributes ──────────────────────────────────

test "result: values are trimmed, attributes are collected by name, foreign children and nameless attributes are ignored" {
    const after =
        "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\" SPNameQualifier=\"sp-q\">\n  alice  \n</saml:NameID>" ++ bearer_xml ++ "</saml:Subject>" ++
        conditions_xml ++
        "<saml:AuthnStatement SessionIndex=\"s-1\"><saml:AuthnContext><saml:AuthnContextClassRef>  urn:acr:one \n</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>" ++
        "<saml:AttributeStatement>" ++
        "<saml:Attribute Name=\"a\" FriendlyName=\"Fa\"><saml:AttributeValue> v1 </saml:AttributeValue><saml:Other>x</saml:Other><saml:AttributeValue>v2</saml:AttributeValue></saml:Attribute>" ++
        "<saml:Attribute FriendlyName=\"noname\"><saml:AttributeValue>z</saml:AttributeValue></saml:Attribute>" ++
        "<saml:Attribute Name=\"empty\"/><saml:Other><saml:Attribute Name=\"nested\"/></saml:Other>" ++
        "</saml:AttributeStatement>";
    var m = try mintA(0xC090, after, null);
    defer m.deinit();
    var res = try expectAccepted(m.resp, baseCfg(m.key));
    defer res.deinit();
    try testing.expectEqualStrings("alice", res.name_id);
    try testing.expectEqualStrings("sp-q", res.name_id_sp_qualifier.?);
    try testing.expectEqualStrings("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", res.name_id_format.?);
    try testing.expectEqualStrings("s-1", res.session_index.?);
    try testing.expectEqualStrings("urn:acr:one", res.authn_context_class_ref.?);
    try testing.expectEqual(@as(usize, 2), res.attributes.len);
    try testing.expectEqualStrings("a", res.attributes[0].name);
    try testing.expectEqualStrings("Fa", res.attributes[0].friendly_name.?);
    try testing.expectEqual(@as(usize, 2), res.attributes[0].values.len);
    try testing.expectEqualStrings("v1", res.attributes[0].values[0]);
    try testing.expectEqualStrings("v2", res.attributes[0].values[1]);
    try testing.expectEqualStrings("empty", res.attributes[1].name);
    try testing.expect(res.attributes[1].friendly_name == null);
    try testing.expectEqual(@as(usize, 0), res.attributes[1].values.len);
}

test "required_loa: an exact class ref, the eIDAS order, and an unknown presented class" {
    const after = subject_xml ++ conditions_xml ++
        "<saml:AuthnStatement><saml:AuthnContext><saml:AuthnContextClassRef>http://eidas.europa.eu/LoA/substantial</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";
    var m = try mintA(0xC0A0, after, null);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    const Case = struct { required: []const u8, expect: ?anyerror };
    const cases = [_]Case{
        .{ .required = "http://eidas.europa.eu/LoA/low", .expect = null },
        .{ .required = "http://eidas.europa.eu/LoA/substantial", .expect = null },
        .{ .required = "http://eidas.europa.eu/LoA/high", .expect = error.LevelOfAssuranceInsufficient },
        .{ .required = "urn:example:custom", .expect = error.LevelOfAssuranceInsufficient },
    };
    for (cases) |c| {
        cfg.required_loa = c.required;
        try probe(m, cfg, fx.t_valid, c.expect);
    }
    // a non-eIDAS class ref is compared exactly
    const after2 = subject_xml ++ conditions_xml ++
        "<saml:AuthnStatement><saml:AuthnContext><saml:AuthnContextClassRef>urn:example:custom</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";
    var m2 = try mintA(0xC0A1, after2, null);
    defer m2.deinit();
    var c2 = baseCfg(m2.key);
    c2.required_loa = "urn:example:custom";
    try probe(m2, c2, fx.t_valid, null);
    c2.required_loa = "urn:example:other";
    try probe(m2, c2, fx.t_valid, error.LevelOfAssuranceInsufficient);
    c2.required_loa = "http://eidas.europa.eu/LoA/low";
    try probe(m2, c2, fx.t_valid, error.LevelOfAssuranceInsufficient);
}

// ── outgoing messages: escaping, flags, indexes ─────────────────────────────

pub fn expectContains(hay: []const u8, needle: []const u8) !void {
    if (std.mem.find(u8, hay, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, hay });
        return error.TestExpectedContains;
    }
}

pub fn expectAbsent(hay: []const u8, needle: []const u8) !void {
    if (std.mem.find(u8, hay, needle) != null) {
        std.debug.print("unexpected {s} in {s}\n", .{ needle, hay });
        return error.TestUnexpectedContains;
    }
}

test "buildAuthnRequest: every markup character in an attribute or text value is escaped and round-trips" {
    const nasty = "a&b<c>d\"e";
    const out = try saml.buildAuthnRequest(gpa, .{
        .id = nasty,
        .issue_instant = nasty,
        .issuer = "i&<>j\"k",
        .acs_url = nasty,
        .destination = nasty,
        .name_id_format = nasty,
        .requested_authn_context = .{ .class_refs = &.{"r&<>s"} },
    });
    defer gpa.free(out);
    try expectContains(out, "ID=\"a&amp;b&lt;c&gt;d&quot;e\"");
    try expectContains(out, "<saml:Issuer>i&amp;&lt;&gt;j\"k</saml:Issuer>");
    try expectContains(out, "<saml:AuthnContextClassRef>r&amp;&lt;&gt;s</saml:AuthnContextClassRef>");
    var doc = try xml.parse(gpa, out, .{});
    defer doc.deinit();
    try testing.expectEqualStrings(nasty, doc.root.attr("", "ID").?);
    try testing.expectEqualStrings(nasty, doc.root.attr("", "Destination").?);
    try testing.expectEqualStrings(nasty, doc.root.attr("", "AssertionConsumerServiceURL").?);
}

test "buildAuthnRequest: ForceAuthn, IsPassive, AllowCreate, the ACS index and RequestedAuthnContext follow the options" {
    const base: saml.AuthnRequestOptions = .{ .id = "_1", .issue_instant = "2024-06-01T12:00:00Z", .issuer = "sp", .acs_url = "https://sp/acs" };
    {
        const out = try saml.buildAuthnRequest(gpa, base);
        defer gpa.free(out);
        try expectAbsent(out, "ForceAuthn");
        try expectAbsent(out, "IsPassive");
        try expectAbsent(out, "AttributeConsumingServiceIndex");
        try expectAbsent(out, "RequestedAuthnContext");
        try expectContains(out, "<samlp:NameIDPolicy AllowCreate=\"true\"/>");
    }
    {
        var o = base;
        o.force_authn = true;
        o.is_passive = true;
        o.attribute_consuming_service_index = 255;
        o.name_id_format = "urn:fmt";
        o.requested_authn_context = .{ .comparison = .minimum, .class_refs = &.{} };
        const out = try saml.buildAuthnRequest(gpa, o);
        defer gpa.free(out);
        try expectContains(out, " ForceAuthn=\"true\"");
        try expectContains(out, " IsPassive=\"true\"");
        try expectContains(out, " AttributeConsumingServiceIndex=\"255\"");
        try expectContains(out, "<samlp:NameIDPolicy Format=\"urn:fmt\" AllowCreate=\"true\"/>");
        try expectAbsent(out, "RequestedAuthnContext"); // an empty class list emits nothing
    }
    {
        var o = base;
        o.allow_create = false;
        o.name_id_format = "urn:fmt";
        o.requested_authn_context = .{ .comparison = .better, .class_refs = &.{"urn:acr"} };
        const out = try saml.buildAuthnRequest(gpa, o);
        defer gpa.free(out);
        try expectContains(out, "<samlp:NameIDPolicy Format=\"urn:fmt\"/>");
        try expectContains(out, "<samlp:RequestedAuthnContext Comparison=\"better\">");
    }
    {
        var o = base;
        o.allow_create = false;
        const out = try saml.buildAuthnRequest(gpa, o);
        defer gpa.free(out);
        try expectAbsent(out, "NameIDPolicy");
    }
}

const one_acs = [_]saml.AcsEndpoint{.{ .location = "https://sp.example.org/acs", .index = 0 }};

fn spMeta(entity_id: []const u8) ![]u8 {
    return saml.buildSpMetadata(gpa, .{ .entity_id = entity_id, .assertion_consumer_services = &one_acs });
}

test "buildSpMetadata: XML 1.0 Char boundaries decide InvalidXmlCharacter" {
    const valid = [_]u21{ 0x9, 0xA, 0xD, 0x20, 0x7F, 0x85, 0xD7FF, 0xE000, 0xFFFD, 0x10000, 0x10FFFF };
    const invalid = [_]u21{ 0x0, 0x1, 0x8, 0xB, 0xC, 0xE, 0x1F, 0xFFFE, 0xFFFF };
    var buf: [4]u8 = undefined;
    for (valid) |cp| {
        const n = try std.unicode.utf8Encode(cp, &buf);
        const eid = try gpa.print("urn:x{s}y", .{buf[0..n]});
        defer gpa.free(eid);
        const out = try spMeta(eid);
        gpa.free(out);
    }
    for (invalid) |cp| {
        const n = try std.unicode.utf8Encode(cp, &buf);
        const eid = try gpa.print("urn:x{s}y", .{buf[0..n]});
        defer gpa.free(eid);
        try testing.expectError(error.InvalidXmlCharacter, spMeta(eid));
    }
    // not valid UTF-8 at all
    try testing.expectError(error.InvalidXmlCharacter, spMeta("urn:x\xffy"));
}

test "buildSpMetadata: attribute and text escaping round-trips through the parser" {
    const eid = "urn:a&b<c>d\"e\tf\ng\rh";
    const names = [_]saml.LocalizedString{.{ .value = "n&<>\"\r'x", .lang = "en" }};
    const attrs = [_]saml.RequestedAttribute{.{ .name = "a&<>\"", .is_required = true }};
    const svc = [_]saml.AttributeConsumingService{.{ .index = 255, .is_default = false, .service_names = &names, .requested_attributes = &attrs }};
    const acs = [_]saml.AcsEndpoint{.{ .location = "https://sp.example.org/acs?a=1&b=2", .index = 255, .is_default = true }};
    const out = try saml.buildSpMetadata(gpa, .{
        .entity_id = eid,
        .assertion_consumer_services = &acs,
        .attribute_consuming_services = &svc,
        .encryption_certs_der = &.{"enc"},
        .authn_requests_signed = true,
        .want_assertions_signed = false,
    });
    defer gpa.free(out);
    try expectContains(out, "entityID=\"urn:a&amp;b&lt;c&gt;d&quot;e&#9;f&#10;g&#13;h\"");
    try expectContains(out, ">n&amp;&lt;&gt;\"&#13;'x</md:ServiceName>");
    try expectContains(out, " index=\"255\" isDefault=\"true\"/>");
    try expectContains(out, " index=\"255\" isDefault=\"false\">");
    try expectContains(out, " isRequired=\"true\"/>");
    try expectContains(out, " AuthnRequestsSigned=\"true\"");
    try expectContains(out, " WantAssertionsSigned=\"false\"");
    try expectContains(out, "xmlns:ds=");
    var doc = try xml.parse(gpa, out, .{});
    defer doc.deinit();
    try testing.expectEqualStrings(eid, doc.root.attr("", "entityID").?);
    const sd = findByLocal(doc.root, "ServiceName").?;
    const txt = try sd.textContent(gpa);
    defer gpa.free(txt);
    try testing.expectEqualStrings("n&<>\"\r'x", txt);
    const plain = try spMeta("urn:plain");
    defer gpa.free(plain);
    try expectAbsent(plain, "xmlns:ds=");
    try expectContains(plain, " AuthnRequestsSigned=\"false\"");
    try expectContains(plain, " WantAssertionsSigned=\"true\"");
}

test "buildSpMetadata: the validation limits" {
    const E = saml.SpMetadataError;
    const a = one_acs[0];
    const name = [_]saml.LocalizedString{.{ .value = "x" }};
    const ra = [_]saml.RequestedAttribute{.{ .name = "n" }};
    const long = try gpa.alloc(u8, 1025);
    defer gpa.free(long);
    @memset(long, 'a');

    try testing.expectError(E.InvalidEntityId, spMeta(""));
    gpa.free(try spMeta(long[0..1024]));
    try testing.expectError(E.InvalidEntityId, spMeta(long));
    try testing.expectError(E.NoAssertionConsumerService, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{} }));
    try testing.expectError(E.MissingRequiredValue, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{.{ .location = "", .index = 0 }} }));

    // duplicate ACS indexes, adjacent and not
    const dup_adj = [_]saml.AcsEndpoint{ .{ .location = "l", .index = 1 }, .{ .location = "l", .index = 1 } };
    const dup_far = [_]saml.AcsEndpoint{ .{ .location = "l", .index = 1 }, .{ .location = "l", .index = 2 }, .{ .location = "l", .index = 1 } };
    try testing.expectError(E.DuplicateIndex, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &dup_adj }));
    try testing.expectError(E.DuplicateIndex, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &dup_far }));
    // defaults: only a literal `true` counts, and one is allowed
    const two_true = [_]saml.AcsEndpoint{ .{ .location = "l", .index = 1, .is_default = true }, .{ .location = "l", .index = 2, .is_default = true } };
    const true_false = [_]saml.AcsEndpoint{ .{ .location = "l", .index = 1, .is_default = true }, .{ .location = "l", .index = 2, .is_default = false } };
    const false_false = [_]saml.AcsEndpoint{ .{ .location = "l", .index = 1, .is_default = false }, .{ .location = "l", .index = 2, .is_default = false } };
    try testing.expectError(E.MultipleDefaults, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &two_true }));
    gpa.free(try saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &true_false }));
    gpa.free(try saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &false_false }));
    gpa.free(try saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{.{ .location = "l", .index = 1, .is_default = true }} }));

    // SLO, certificates, formats
    try testing.expectError(E.MissingRequiredValue, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .single_logout_services = &.{.{ .binding = "", .location = "l" }} }));
    try testing.expectError(E.MissingRequiredValue, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .single_logout_services = &.{.{ .binding = "b", .location = "" }} }));
    try testing.expectError(E.MissingRequiredValue, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .signing_certs_der = &.{""} }));
    try testing.expectError(E.MissingRequiredValue, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .encryption_certs_der = &.{""} }));
    try testing.expectError(E.MissingRequiredValue, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .name_id_formats = &.{""} }));

    // AttributeConsumingService
    const S = saml.AttributeConsumingService;
    const bad_svcs = [_]S{
        .{ .index = 1, .service_names = &.{}, .requested_attributes = &ra },
        .{ .index = 1, .service_names = &name, .requested_attributes = &.{} },
        .{ .index = 1, .service_names = &name, .requested_attributes = &.{.{ .name = "" }} },
    };
    for (bad_svcs) |s| {
        try testing.expectError(E.MissingRequiredValue, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .attribute_consuming_services = &.{s} }));
    }
    const s1 = S{ .index = 1, .service_names = &name, .requested_attributes = &ra };
    const s2 = S{ .index = 2, .service_names = &name, .requested_attributes = &ra };
    try testing.expectError(E.DuplicateIndex, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .attribute_consuming_services = &.{ s1, s1 } }));
    try testing.expectError(E.DuplicateIndex, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .attribute_consuming_services = &.{ s1, s2, s1 } }));
    var d1 = s1;
    d1.is_default = true;
    var d2 = s2;
    d2.is_default = true;
    try testing.expectError(E.MultipleDefaults, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .attribute_consuming_services = &.{ d1, d2 } }));
    d2.is_default = false;
    gpa.free(try saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .attribute_consuming_services = &.{ d1, d2 } }));
    d1.is_default = false;
    gpa.free(try saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .attribute_consuming_services = &.{ d1, d2 } }));

    // Organization: every list needs an entry; a language tag may not be empty
    const O = saml.Organization;
    const orgs = [_]O{
        .{ .names = &.{}, .display_names = &name, .urls = &name },
        .{ .names = &name, .display_names = &.{}, .urls = &name },
        .{ .names = &name, .display_names = &name, .urls = &.{} },
    };
    for (orgs) |o| {
        try testing.expectError(E.MissingRequiredValue, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &.{a}, .organization = o }));
    }
    const empty_lang = [_]saml.LocalizedString{.{ .value = "x", .lang = "" }};
    try testing.expectError(E.MissingRequiredValue, saml.buildSpMetadata(gpa, .{
        .entity_id = "e",
        .assertion_consumer_services = &.{a},
        .organization = .{ .names = &empty_lang, .display_names = &name, .urls = &name },
    }));
}

test "buildSpMetadata: the metadata ID must be an ASCII NCName, and signing needs one" {
    const good = [_][]const u8{ "a", "_a", "a1", "a-b", "a.b", "a_b", "Z9" };
    const bad = [_][]const u8{ "", "1a", "-a", ".a", "a b", "a:b", "a/b", "@a", "[a", "`a", "{a", "a\x7f" };
    for (good) |id| gpa.free(try saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &one_acs, .id = id }));
    for (bad) |id| try testing.expectError(error.InvalidId, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &one_acs, .id = id }));
    // every ASCII character that is not allowed inside an NCName, in the second position
    var c: u8 = 0;
    while (c < 128) : (c += 1) {
        const allowed = std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.';
        const id = [_]u8{ 'a', c };
        const r = saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &one_acs, .id = &id });
        if (allowed) gpa.free(try r) else try testing.expectError(error.InvalidId, r);
    }
    var kp = try encutil.makeSpKey(0xD001);
    try testing.expectError(error.InvalidId, saml.buildSpMetadata(gpa, .{ .entity_id = "e", .assertion_consumer_services = &one_acs, .sign_with = .{ .rsa = &kp.secret_key } }));
}

test "buildSignedRedirectQuery: every byte is percent-encoded exactly when it is not unreserved" {
    var kp = try encutil.makeSpKey(0xD002);
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(gpa);
    const hex = "0123456789ABCDEF";
    for (all) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try expected.append(gpa, c);
        } else {
            try expected.appendSlice(gpa, &.{ '%', hex[c >> 4], hex[c & 15] });
        }
    }
    for ([_]saml.RedirectMessageKind{ .request, .response }) |kind| {
        const q = try saml.buildSignedRedirectQuery(gpa, .{ .kind = kind, .message_field = &all, .relay_state = &all, .key = .{ .rsa = &kp.secret_key } });
        defer gpa.free(q);
        const head = if (kind == .request) "SAMLRequest=" else "SAMLResponse=";
        const want = try gpa.print("{s}{s}&RelayState={s}&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=", .{ head, expected.items, expected.items });
        defer gpa.free(want);
        try testing.expect(std.mem.startsWith(u8, q, want));
    }
}

test "verifyRedirectSignature: the algorithm allow-list, additional keys and the three verdicts" {
    var kp = try encutil.makeSpKey(0xD003);
    const other = try encutil.makeSpKey(0xD004);
    const field = try saml.encodeRedirectField(gpa, "<samlp:LogoutRequest ID=\"_r\"/>");
    defer gpa.free(field);
    const q = try saml.buildSignedRedirectQuery(gpa, .{ .kind = .request, .message_field = field, .key = .{ .rsa = &kp.secret_key } });
    defer gpa.free(q);
    const sig_at = std.mem.find(u8, q, "&Signature=").? + "&Signature=".len;
    const sig_pct = q[sig_at..];
    // the signature is percent-encoded base64: undo %2B %2F %3D
    var sig_b64: std.ArrayList(u8) = .empty;
    defer sig_b64.deinit(gpa);
    var i: usize = 0;
    while (i < sig_pct.len) : (i += 1) {
        if (sig_pct[i] == '%') {
            try sig_b64.append(gpa, try std.fmt.parseInt(u8, sig_pct[i + 1 .. i + 3], 16));
            i += 2;
        } else try sig_b64.append(gpa, sig_pct[i]);
    }
    const alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    const o: saml.VerifyRedirectQueryOptions = .{ .kind = .request, .message_field = field, .sig_alg = alg, .signature_b64 = sig_b64.items, .key = kp.public_key };
    try testing.expect(try saml.verifyRedirectSignature(gpa, o));
    // wrong primary key, right key among the additional ones
    var v = o;
    v.key = other.public_key;
    try testing.expect(!try saml.verifyRedirectSignature(gpa, v));
    const extra = [_]rsa.PublicKey{ other.public_key, kp.public_key };
    v.additional_keys = &extra;
    try testing.expect(try saml.verifyRedirectSignature(gpa, v));
    const only_wrong = [_]rsa.PublicKey{other.public_key};
    v.additional_keys = &only_wrong;
    try testing.expect(!try saml.verifyRedirectSignature(gpa, v));
    // any other SigAlg is refused outright
    v = o;
    v.sig_alg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    try testing.expectError(error.UnsupportedAlgorithm, saml.verifyRedirectSignature(gpa, v));
}

test "Issuer: whitespace around the entityID is ignored, in the assertion and in the Response" {
    const padded = "\n   " ++ fx.idp_entity_id ++ " \t\n";
    var signed = try sign.signAssertion(gpa, 0xC0B0, padded, "_mut01", "2024-06-01T12:00:00Z", base_after_issuer);
    defer signed.deinit(gpa);
    const resp = try sign.wrapInResponse(gpa, signed.xml);
    defer gpa.free(resp);
    const resp2 = try replaceOnce(resp, "<saml:Issuer>https://idp.example.org/saml</saml:Issuer><samlp:Status>", "<saml:Issuer>\n\t https://idp.example.org/saml \r\n</saml:Issuer><samlp:Status>");
    defer gpa.free(resp2);
    var res = try expectAccepted(resp2, baseCfg(signed.key));
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

// ── Holder-of-Key: a decided mismatch outranks an incomparable cross-form pairing ──

fn hokWith(key_info_inner: []const u8) ![]u8 {
    return gpa.print("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:holder-of-key\"><saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
        "<ds:KeyInfo xmlns:ds=\"{s}\">{s}</ds:KeyInfo></saml:SubjectConfirmationData></saml:SubjectConfirmation>", .{ ds_ns, key_info_inner });
}

test "holder-of-key: a same-form mismatch is reported as a mismatch even when a cross-form pairing is incomparable" {
    const blob_a = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 }; // not a parsable certificate
    const blob_b = [_]u8{ 0x30, 0x03, 0x09, 0x08, 0x07 };
    const a64 = try b64(&blob_a);
    defer gpa.free(a64);
    const ec_point = std.crypto.ecc.P256.basePoint.toUncompressedSec1();

    // X509 in the confirmation, a different DER presented, plus a bare key that cannot be compared with a blob.
    {
        const ki = try gpa.print("<ds:X509Data><ds:X509Certificate>{s}</ds:X509Certificate></ds:X509Data>", .{a64});
        defer gpa.free(ki);
        const sc = try hokWith(ki);
        defer gpa.free(sc);
        var m = try mintSubject(0xC0C0, sc);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.subject_confirmation = .holder_of_key;
        cfg.presented_holder_cert_der = &blob_b;
        cfg.presented_holder_key = .{ .ec_sec1 = &ec_point };
        try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(gpa, m.resp, cfg));
        // only the incomparable pairing left: cross-form unsupported
        cfg.presented_holder_cert_der = null;
        try testing.expectError(error.HolderOfKeyCrossFormUnsupported, saml.consumeResponseXml(gpa, m.resp, cfg));
    }
    // KeyValue in the confirmation, a different key presented, plus a certificate that cannot be parsed.
    {
        const wrong = try otherRsaKey(0xC0C1);
        const sc = try hokWith("<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>AQID</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>");
        defer gpa.free(sc);
        var m = try mintSubject(0xC0C2, sc);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.subject_confirmation = .holder_of_key;
        cfg.presented_holder_cert_der = &blob_b;
        cfg.presented_holder_key = .{ .rsa = wrong.rsa };
        try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(gpa, m.resp, cfg));
        cfg.presented_holder_key = null;
        try testing.expectError(error.HolderOfKeyCrossFormUnsupported, saml.consumeResponseXml(gpa, m.resp, cfg));
    }
}

/// A 1025-bit public key (not a whole number of bytes), built without a secret half.
fn oddBitKey() !rsa.PublicKey {
    var n: [129]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xC0D0);
    prng.random().bytes(&n);
    n[0] = 0x01;
    n[128] |= 1;
    return rsa.PublicKey.fromBytes(&n, &.{ 0x01, 0x00, 0x01 });
}

test "holder-of-key: an RSAKeyValue is compared over the whole modulus (bit length not a multiple of 8) and the exponent" {
    const pk = try oddBitKey();
    var n_buf: [rsa.max_modulus_len]u8 = undefined;
    const n_len = (pk.n.bits() + 7) / 8;
    try pk.n.toBytes(n_buf[0..n_len], .big);
    const n_bytes = n_buf[0..n_len];
    const e3 = try rsa.PublicKey.fromBytes(n_bytes, &.{3});
    const n_b64 = try b64(n_bytes);
    defer gpa.free(n_b64);
    const kv_ki = try gpa.print("<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>\n {s} \n</ds:Modulus><ds:Exponent> AQAB </ds:Exponent></ds:RSAKeyValue></ds:KeyValue>", .{n_b64});
    defer gpa.free(kv_ki);
    const sc = try hokWith(kv_ki);
    defer gpa.free(sc);
    var m = try mintSubject(0xC0D2, sc);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .rsa = pk };
    var ok = try expectAccepted(m.resp, cfg);
    ok.deinit();
    cfg.presented_holder_key = .{ .rsa = e3 };
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(gpa, m.resp, cfg));
}

test "holder-of-key: an RSAKeyValue with a sign byte on the modulus or leading zeros on the exponent still matches" {
    const pk = try oddBitKey();
    var n_buf: [rsa.max_modulus_len + 1]u8 = undefined;
    n_buf[0] = 0;
    const n_len = (pk.n.bits() + 7) / 8;
    try pk.n.toBytes(n_buf[1 .. 1 + n_len], .big);
    const n_b64 = try b64(n_buf[0 .. 1 + n_len]);
    defer gpa.free(n_b64);
    const e_b64 = try b64(&.{ 0x00, 0x01, 0x00, 0x01 });
    defer gpa.free(e_b64);
    const ki = try gpa.print("<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>{s}</ds:Modulus><ds:Exponent>{s}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>", .{ n_b64, e_b64 });
    defer gpa.free(ki);
    const sc = try hokWith(ki);
    defer gpa.free(sc);
    var m = try mintSubject(0xC0D3, sc);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .rsa = pk };
    var ok = try expectAccepted(m.resp, cfg);
    ok.deinit();
}

const xf = @import("test_hok_crossform.zig");

test "holder-of-key: EC pairings tolerate whitespace around the curve URI, refuse crossed key types and unreadable certificates" {
    const point = xf.ec_point_uncompressed;
    const pt_b64 = try b64(&point);
    defer gpa.free(pt_b64);
    const ec_ki = try gpa.print("<ds:KeyValue><dsig11:ECKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\"><dsig11:NamedCurve URI=\"\n  urn:oid:1.2.840.10045.3.1.7 \t\"/>" ++
        "<dsig11:PublicKey>\n {s} \n</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue>", .{pt_b64});
    defer gpa.free(ec_ki);
    const cert_b64 = try b64(&xf.ec_cert_der);
    defer gpa.free(cert_b64);
    const x509_ki = try gpa.print("<ds:X509Data><ds:X509Certificate>\n {s} \n</ds:X509Certificate></ds:X509Data>", .{cert_b64});
    defer gpa.free(x509_ki);
    const rsa_key = (try otherRsaKey(0xC0E0)).rsa;

    // ECKeyValue vs a presented SEC1 point
    {
        const sc = try hokWith(ec_ki);
        defer gpa.free(sc);
        var m = try mintSubject(0xC0E1, sc);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.subject_confirmation = .holder_of_key;
        cfg.presented_holder_key = .{ .ec_sec1 = &point };
        var ok = try expectAccepted(m.resp, cfg);
        ok.deinit();
        // ... and vs the certificate holding the same point
        cfg.presented_holder_key = null;
        cfg.presented_holder_cert_der = &xf.ec_cert_der;
        var ok2 = try expectAccepted(m.resp, cfg);
        ok2.deinit();
    }
    // an EC certificate in the confirmation never matches a presented RSA key
    {
        const sc = try hokWith(x509_ki);
        defer gpa.free(sc);
        var m = try mintSubject(0xC0E2, sc);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.subject_confirmation = .holder_of_key;
        cfg.presented_holder_key = .{ .rsa = rsa_key };
        try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(gpa, m.resp, cfg));
        cfg.presented_holder_key = .{ .ec_sec1 = &point };
        var ok = try expectAccepted(m.resp, cfg);
        ok.deinit();
    }
    // a certificate text that is not base64 cannot be compared with a bare key
    {
        const sc = try hokWith("<ds:X509Data><ds:X509Certificate>%%%%</ds:X509Certificate></ds:X509Data>");
        defer gpa.free(sc);
        var m = try mintSubject(0xC0E3, sc);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.subject_confirmation = .holder_of_key;
        cfg.presented_holder_key = .{ .rsa = rsa_key };
        try testing.expectError(error.HolderOfKeyCrossFormUnsupported, saml.consumeResponseXml(gpa, m.resp, cfg));
    }
}

test "holder-of-key: an ECKeyValue with another curve never matches the certificate; an ECKeyValue cannot be compared with an RSA certificate" {
    const point = xf.ec_point_uncompressed;
    const pt_b64 = try b64(&point);
    defer gpa.free(pt_b64);
    const wrong_curve = try gpa.print("<ds:KeyValue><dsig11:ECKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\"><dsig11:NamedCurve URI=\"urn:oid:1.3.132.0.34\"/>" ++
        "<dsig11:PublicKey>{s}</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue>", .{pt_b64});
    defer gpa.free(wrong_curve);
    const right_curve = try gpa.print("<ds:KeyValue><dsig11:ECKeyValue xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\"><dsig11:NamedCurve URI=\"urn:oid:1.2.840.10045.3.1.7\"/>" ++
        "<dsig11:PublicKey>{s}</dsig11:PublicKey></dsig11:ECKeyValue></ds:KeyValue>", .{pt_b64});
    defer gpa.free(right_curve);

    {
        const sc = try hokWith(wrong_curve);
        defer gpa.free(sc);
        var m = try mintSubject(0xC0F0, sc);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.subject_confirmation = .holder_of_key;
        cfg.presented_holder_cert_der = &xf.ec_cert_der;
        try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(gpa, m.resp, cfg));
    }
    {
        var kp = try encutil.makeSpKey(0xC0F1);
        const rsa_cert = try rsa.selfSignedCert(gpa, &kp.secret_key, kp.public_key, std.crypto.hash.sha2.Sha256, .{ .common_name = "rsa-cert", .not_before = "240101000000Z", .not_after = "340101000000Z" });
        defer gpa.free(rsa_cert);
        const sc = try hokWith(right_curve);
        defer gpa.free(sc);
        var m = try mintSubject(0xC0F2, sc);
        defer m.deinit();
        var cfg = baseCfg(m.key);
        cfg.subject_confirmation = .holder_of_key;
        cfg.presented_holder_cert_der = rsa_cert;
        try testing.expectError(error.HolderOfKeyCrossFormUnsupported, saml.consumeResponseXml(gpa, m.resp, cfg));
    }
}

test "required_loa: a presented eIDAS 'low' meets only 'low'" {
    const after = subject_xml ++ conditions_xml ++
        "<saml:AuthnStatement><saml:AuthnContext><saml:AuthnContextClassRef>http://eidas.europa.eu/LoA/low</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";
    var m = try mintA(0xC0A2, after, null);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    cfg.required_loa = "http://eidas.europa.eu/LoA/low";
    try probe(m, cfg, fx.t_valid, null);
    cfg.required_loa = "http://eidas.europa.eu/LoA/substantial";
    try probe(m, cfg, fx.t_valid, error.LevelOfAssuranceInsufficient);
    cfg.required_loa = "http://eidas.europa.eu/LoA/high";
    try probe(m, cfg, fx.t_valid, error.LevelOfAssuranceInsufficient);
}

test "holder-of-key: a certificate's RSA key is compared with the presented key over modulus and exponent" {
    var kp = try encutil.makeSpKey(0xC0D5);
    const pk = kp.public_key;
    var n_buf: [rsa.max_modulus_len]u8 = undefined;
    const n_len = (pk.n.bits() + 7) / 8;
    try pk.n.toBytes(n_buf[0..n_len], .big);
    const same_n_e3 = try rsa.PublicKey.fromBytes(n_buf[0..n_len], &.{3});
    const cert = try rsa.selfSignedCert(gpa, &kp.secret_key, pk, std.crypto.hash.sha2.Sha256, .{ .common_name = "rsa-cert", .not_before = "240101000000Z", .not_after = "340101000000Z" });
    defer gpa.free(cert);
    const cert_b64 = try b64(cert);
    defer gpa.free(cert_b64);
    const ki = try gpa.print("<ds:X509Data><ds:X509Certificate>{s}</ds:X509Certificate></ds:X509Data>", .{cert_b64});
    defer gpa.free(ki);
    const sc = try hokWith(ki);
    defer gpa.free(sc);
    var m = try mintSubject(0xC0D6, sc);
    defer m.deinit();
    var cfg = baseCfg(m.key);
    cfg.subject_confirmation = .holder_of_key;
    cfg.presented_holder_key = .{ .rsa = pk };
    var ok = try expectAccepted(m.resp, cfg);
    ok.deinit();
    cfg.presented_holder_key = .{ .rsa = same_n_e3 };
    try testing.expectError(error.HolderOfKeyMismatch, saml.consumeResponseXml(gpa, m.resp, cfg));
}
