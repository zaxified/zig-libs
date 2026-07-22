// SPDX-License-Identifier: MIT
//! Test-only enveloped-signature SIGNER.
//!
//! The end-to-end fixture in `fixtures.zig` is signed by an INDEPENDENT
//! toolchain (openssl + lxml) and its private key is not kept, so its signed
//! octets cannot be edited. The EncryptedID / EncryptedAttribute / Holder-of-Key
//! variants all place new content INSIDE the signed assertion (an encrypted
//! NameID in the Subject, an encrypted Attribute in the AttributeStatement, a HoK
//! `<SubjectConfirmation>`), which no string manipulation of a signed document
//! can produce without breaking the digest. So these tests mint a FRESH signed
//! assertion under a locally-generated RSA key, exactly as `xmldsig`'s own
//! round-trip tests do (`xmldsig` verify + `xmldsig.c14n` canonicalization +
//! `rsa.signPkcs1v15` — no signing API is exposed by the modules themselves).
//!
//! Honesty: this is a CONSTRUCTED fixture (our canonicalizer feeds our verifier),
//! NOT cross-implementation interop. The byte-exact interop anchor stays the
//! openssl/lxml fixture (`test_fixture.zig`) and the NIST/RFC KATs in `xmlenc`;
//! these files prove the EncryptedID/EncryptedAttribute/HoK LOGIC on top.

const std = @import("std");
const xml = @import("xml");
const xmldsig = @import("xmldsig");
const rsa = @import("rsa");

const Sha256 = std.crypto.hash.sha2.Sha256;
const ds_ns = "http://www.w3.org/2000/09/xmldsig#";
const saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion";

const digest_placeholder = "__DIGEST_PLACEHOLDER__";

pub const Signed = struct {
    /// The full, self-contained signed `<saml:Assertion>` (owned by the caller).
    xml: []u8,
    /// The verify key to configure as `Config.idp_key`.
    key: xmldsig.VerifyKey,

    pub fn deinit(self: *Signed, alloc: std.mem.Allocator) void {
        alloc.free(self.xml);
        self.* = undefined;
    }
};

/// Build and sign a self-contained assertion. `id` is the assertion ID;
/// `after_issuer` is the raw XML of everything following `</saml:Issuer>` up to
/// (not including) `</saml:Assertion>` — Subject, Conditions, AuthnStatement,
/// AttributeStatement, etc. The enveloped RSA-SHA256 / exclusive-C14N signature
/// is inserted right after the Issuer, matching the fixture's layout.
pub fn signAssertion(
    alloc: std.mem.Allocator,
    seed: u64,
    issuer: []const u8,
    id: []const u8,
    issue_instant: []const u8,
    after_issuer: []const u8,
) !Signed {
    var prng = std.Random.DefaultPrng.init(seed);
    // 1024-bit is ample for RSA-SHA256 enveloped signing (min modulus ~62 bytes)
    // and keeps deterministic keygen fast across the many minted-fixture tests.
    const kp = try rsa.generate(prng.random(), 1024, 65537);

    const signed_info_inner =
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
        "<ds:Reference URI=\"#{s}\"><ds:Transforms>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" ++
        "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
        "</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" ++
        "<ds:DigestValue>{s}</ds:DigestValue></ds:Reference>";

    // Assemble the assertion with a placeholder digest + empty SignatureValue.
    // The whole `<ds:Signature>` is omitted when the reference digest is taken,
    // so the placeholder never affects it.
    const assembled = try std.fmt.allocPrint(alloc, "<saml:Assertion xmlns:saml=\"{s}\" ID=\"{s}\" Version=\"2.0\" IssueInstant=\"{s}\">" ++
        "<saml:Issuer>{s}</saml:Issuer>" ++
        "<ds:Signature xmlns:ds=\"{s}\"><ds:SignedInfo>" ++ signed_info_inner ++ "</ds:SignedInfo>" ++
        "<ds:SignatureValue></ds:SignatureValue></ds:Signature>" ++
        "{s}</saml:Assertion>", .{ saml_ns, id, issue_instant, issuer, ds_ns, id, digest_placeholder, after_issuer });
    defer alloc.free(assembled);

    // Pass 1 — reference digest over the assertion with the Signature omitted.
    var doc1 = try xml.parse(alloc, assembled, .{ .id_attr_names = &.{"ID"} });
    defer doc1.deinit();
    const sig1 = findByLocal(doc1.root, ds_ns, "Signature").?;
    const ref_canon = try xmldsig.c14n.canonicalize(alloc, doc1.root, .{ .mode = .exclusive, .omit = sig1 });
    defer alloc.free(ref_canon);
    var dgst: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(ref_canon, &dgst, .{});
    const digest_b64 = try b64(alloc, &dgst);
    defer alloc.free(digest_b64);

    // Splice the real digest into SignedInfo.
    const with_digest = try std.mem.replaceOwned(u8, alloc, assembled, digest_placeholder, digest_b64);
    defer alloc.free(with_digest);

    // Pass 2 — canonicalize SignedInfo in its real tree context and RSA-sign it.
    var doc2 = try xml.parse(alloc, with_digest, .{ .id_attr_names = &.{"ID"} });
    defer doc2.deinit();
    const si2 = findByLocal(doc2.root, ds_ns, "SignedInfo").?;
    const si_canon = try xmldsig.c14n.canonicalize(alloc, si2, .{ .mode = .exclusive });
    defer alloc.free(si_canon);

    var sig_buf: [512]u8 = undefined; // 2048-bit modulus = 256 bytes
    const sig = try rsa.signPkcs1v15(kp.secret_key, Sha256, si_canon, &sig_buf);
    const sig_b64 = try b64(alloc, sig);
    defer alloc.free(sig_b64);

    // Splice the SignatureValue in.
    const empty_sv = "<ds:SignatureValue></ds:SignatureValue>";
    const filled_sv = try std.fmt.allocPrint(alloc, "<ds:SignatureValue>{s}</ds:SignatureValue>", .{sig_b64});
    defer alloc.free(filled_sv);
    const final = try std.mem.replaceOwned(u8, alloc, with_digest, empty_sv, filled_sv);

    return .{ .xml = final, .key = .{ .rsa = kp.public_key } };
}

fn findByLocal(el: *const xml.Element, uri: []const u8, local: []const u8) ?*xml.Element {
    for (el.children) |c| switch (c.content) {
        .element => |child| {
            if (std.mem.eql(u8, child.uri, uri) and std.mem.eql(u8, child.local, local)) return child;
            if (findByLocal(child, uri, local)) |f| return f;
        },
        else => {},
    };
    return null;
}

fn b64(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try alloc.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data);
    return out;
}

// Sanity: the freshly-minted signed assertion verifies end-to-end through the
// public saml entry point (a self-signing/self-verifying control for the two
// suites that build on it).
test "test_sign: minted assertion verifies + extracts through consumeResponseXml" {
    const alloc = std.testing.allocator;
    const saml = @import("root.zig");
    const fx = @import("fixtures.zig");

    const after_issuer =
        "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">bob@example.org</saml:NameID>" ++
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
        "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
        "</saml:SubjectConfirmation></saml:Subject>" ++
        "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
        "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>";

    var signed = try signAssertion(alloc, 0x1234, fx.idp_entity_id, "_minted01", "2024-06-01T12:00:00Z", after_issuer);
    defer signed.deinit(alloc);

    const resp = try wrapInResponse(alloc, signed.xml);
    defer alloc.free(resp);

    var res = try saml.consumeResponseXml(alloc, resp, .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = signed.key,
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = fx.t_valid,
        .expected_in_response_to = fx.request_id,
    });
    defer res.deinit();
    try std.testing.expectEqualStrings("bob@example.org", res.name_id);
}

/// Wrap a signed assertion in a minimal `<samlp:Response>` (Status=Success). The
/// Response itself is unsigned; the assertion carries the signature (the module's
/// default `.either` policy accepts an assertion-level signature).
pub fn wrapInResponse(alloc: std.mem.Allocator, assertion_xml: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " ++
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp_minted\" Version=\"2.0\" " ++
        "IssueInstant=\"2024-06-01T12:00:00Z\" Destination=\"https://sp.example.org/acs\" " ++
        "InResponseTo=\"req-9988776655\"><saml:Issuer>https://idp.example.org/saml</saml:Issuer>" ++
        "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" ++
        "{s}</samlp:Response>", .{assertion_xml});
}
