// SPDX-License-Identifier: MIT
//! EXTERNAL anchor for the C14N **attribute sort key**, on `saml`'s own product
//! surface.
//!
//! Every other signed fixture in this module (`fixtures.zig`, `test_sign.zig`,
//! the `test_encrypted*` family) carries attributes from a single namespace, so
//! none of them can tell the canonicalizer's `(namespace-URI, local-name)` sort
//! key apart from a `(local-name, namespace-URI)` one — swap the two in
//! `xmldsig`'s `c14n.sortAttrs` and the whole `saml` suite stays green while the
//! layer every signature here rests on is silently wrong.
//!
//! This fixture is the same Response as `fixtures.signed_response`, except the
//! `<saml:Assertion>` (the element the signature covers) additionally carries
//! attributes in TWO foreign namespaces plus an unprefixed one, chosen so the
//! two candidate sort keys disagree:
//!
//!   attribute   namespace URI   local
//!   ID=…        ""              ID
//!   Version=…   ""              Version
//!   zz=…        ""              zz
//!   x:mm=…      urn:x:aa        mm
//!   y:aa=…      urn:x:bb        aa
//!
//!   (URI, local) → `… Version="2.0" zz="unprefixed-z" x:mm="in-x" y:aa="in-y"`
//!   (local, URI) → `… Version="2.0" y:aa="in-y" x:mm="in-x" zz="unprefixed-z"`
//!
//! PROVENANCE — produced ONCE, offline, by `xmlsec1` (C, OpenSSL backend, using
//! libxml2's own Exclusive C14N); nothing here shells out. The `DigestValue`
//! below is libxml2's verdict on that ordering, not ours.
//!
//! ```sh
//! openssl genrsa -out idp.pem 2048 && openssl rsa -in idp.pem -pubout -out idp_pub.pem
//! xmlsec1 --sign --lax-key-search --privkey-pem idp.pem \
//!         --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
//!         --output out.xml tmpl.xml
//! xmlsec1 --verify --lax-key-search --pubkey-pem idp_pub.pem \
//!         --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion out.xml   # => OK
//! ```
//!
//! The 2048-bit IdP key is throwaway TEST MATERIAL; the private half was
//! discarded after signing and does not appear here.

const std = @import("std");
const testing = std.testing;
const xmldsig = @import("xmldsig");
const saml = @import("root.zig");
const fx = @import("fixtures.zig");

const multi_ns_idp_pub_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3LTj4LPaiYn+beub0vb5
    \\JOsm0epSX2hVQ4zad4x4ZYcGPNC2UFwR8rVAghoQbMSIU+KpSgPpnpRrDQ4H1uxR
    \\T4+sBcTytSK8EwJUSCyZRHb/Ukx2CzZJHvQ/R3UK19Za/nR55w3CqPXIlqWcMGm+
    \\iiOduhaovalmb6+3ftN3C6zZPI/HcC7SET0t3GSbF2C3U0FlPOSaOp9D0HidzQUs
    \\GOCOcZy68s0Jzjiy3ehH1tob3ts6lxzK2koJ2LI4ydwbJLPN8xe2YVIUE8EqouCN
    \\T61nTu6kTjoCA5eoNgwfjRXp0ASj/blXP1ZsDz4L+ahf7eR9NOmx2tPaOJT7cVbG
    \\PwIDAQAB
    \\-----END PUBLIC KEY-----
;

fn multiNsIdpKey() xmldsig.VerifyKey {
    const RsaPub = @FieldType(xmldsig.VerifyKey, "rsa");
    const pk = RsaPub.fromPem(multi_ns_idp_pub_pem) catch unreachable;
    return .{ .rsa = pk };
}

const multi_ns_signed_response =
    \\<?xml version="1.0"?>
    \\<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp0011223344556677889900aabbcc" Version="2.0" IssueInstant="2024-06-01T12:00:00Z" Destination="https://sp.example.org/acs" InResponseTo="req-9988776655"><saml:Issuer>https://idp.example.org/saml</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:x="urn:x:aa" xmlns:y="urn:x:bb" ID="_a1b2c3d4e5f60718293a4b5c6d7e8f90" Version="2.0" IssueInstant="2024-06-01T12:00:00Z" zz="unprefixed-z" x:mm="in-x" y:aa="in-y"><saml:Issuer>https://idp.example.org/saml</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_a1b2c3d4e5f60718293a4b5c6d7e8f90"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>l8NRPQcn5uoKgCYm3AYLWs/c1e0z2AynzCxdwDZmCjY=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>VLG27bMNGRwQERr6o1d2sjeupEyw8blhuB7xSDowuCJoFhrMyvs5rxZp3bhHAyOA
    \\TFpDHiL8pfTOI9gcVgoILaqz4DHuUynhtfEgB5PFuonCWVBs7h6NISssnq86nn/O
    \\CxewMZ+sPHUtAn6GHDUKt5y1To3BRbDs2dL3r6ASoURHx6cm16I5jYndh2pcKsvz
    \\G4eZvtX7Yg8lURhXGS6ODoih0vRCKbz9QzUETS0pO4+r0M0VPjqk3TaMWaGHcYg0
    \\GcEe0r2TsdcM2wOML8EORxq2lioAqXk2+7xMTUL5ixsKih2wlUscdgOOZMyUhB8T
    \\heG6eB0S4BavkMBZA2DOmQ==</ds:SignatureValue></ds:Signature><saml:Subject><saml:NameID SPNameQualifier="https://sp.example.org/metadata" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.org</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-06-01T12:05:00Z" Recipient="https://sp.example.org/acs" InResponseTo="req-9988776655"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2024-06-01T11:59:00Z" NotOnOrAfter="2024-06-01T12:05:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2024-06-01T12:00:00Z" SessionIndex="sess-abc-123"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>alice@example.org</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>staff</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>
;

fn multiNsConfig() saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = multiNsIdpKey(),
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = fx.t_valid,
        .expected_in_response_to = fx.request_id,
    };
}

test "EXTERNAL anchor: xmlsec1-signed assertion with attributes in two namespaces is accepted end-to-end" {
    var res = try saml.consumeResponseXml(testing.allocator, multi_ns_signed_response, multiNsConfig());
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expectEqualStrings(fx.assertion_id, res.assertion_id);
    try testing.expectEqualStrings("sess-abc-123", res.session_index.?);
}

test "EXTERNAL anchor: the multi-namespace assertion really does discriminate the two sort keys" {
    // Guards the fixture: if a future edit reduces the assertion's attribute set
    // to something both candidate keys order identically, the anchor above stops
    // anchoring anything while still passing. Assert the discriminating shape is
    // present in the bytes themselves.
    const by_uri_then_local = " Version=\"2.0\" zz=\"unprefixed-z\" x:mm=\"in-x\" y:aa=\"in-y\"";
    const by_local_then_uri = " Version=\"2.0\" y:aa=\"in-y\" x:mm=\"in-x\" zz=\"unprefixed-z\"";
    try testing.expect(!std.mem.eql(u8, by_uri_then_local, by_local_then_uri));
    // The source document is NOT in canonical attribute order (xmlsec1 signed it
    // as written); what matters is that both foreign namespaces and the
    // unprefixed attribute are all on the signed element.
    try testing.expect(std.mem.indexOf(u8, multi_ns_signed_response, "xmlns:x=\"urn:x:aa\"") != null);
    try testing.expect(std.mem.indexOf(u8, multi_ns_signed_response, "xmlns:y=\"urn:x:bb\"") != null);
    try testing.expect(std.mem.indexOf(u8, multi_ns_signed_response, " zz=\"unprefixed-z\" x:mm=\"in-x\" y:aa=\"in-y\"") != null);
}
