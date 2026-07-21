// SPDX-License-Identifier: MIT
//! Shared test fixtures for the saml module.
//!
//! `signed_response` is a SAML 2.0 Response whose Assertion carries a genuine
//! enveloped RSA-SHA256 (exclusive-C14N) signature. PROVENANCE: it is not a
//! capture from a live IdP — it was generated with an INDEPENDENT toolchain
//! (openssl for the RSA-SHA256 signature, libxml2/lxml for Exclusive XML
//! Canonicalization) and openssl-verified, so a green verify here proves our
//! xmldsig C14N + RSA agree byte-for-byte with those reference implementations
//! (cross-tool interop), not merely with themselves. The 2048-bit key is test
//! material only. See SPEC.md section "Fixture provenance".

const std = @import("std");
const xmldsig = @import("xmldsig");

pub const signed_response =
    \\<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp0011223344556677889900aabbcc" Version="2.0" IssueInstant="2024-06-01T12:00:00Z" Destination="https://sp.example.org/acs" InResponseTo="req-9988776655"><saml:Issuer>https://idp.example.org/saml</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a1b2c3d4e5f60718293a4b5c6d7e8f90" Version="2.0" IssueInstant="2024-06-01T12:00:00Z"><saml:Issuer>https://idp.example.org/saml</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_a1b2c3d4e5f60718293a4b5c6d7e8f90"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>ODXjkjPZsSPy5GuZJd7NVTwd21hIDZNjlfzmZfEw9VA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>B6V1Du0Td1GM4JXRWTUnS3I3NeRUDFfX5NCeLwMlb3+dZXhm+RRQ76/IDMOebgqkHAGFmh5dATEhzr1PT0koUm5spuEHnTDgyxZOo4knnQVFULrgm4E6q1WWGWs0VclC5F9I9r/Hddl2dB6pFLcFykL3pbHi3MWMr1K/j9DpZot7pDVgM+3qmdzKs/EiB2EVfxA+LTqUtzKmM0Bb4dz/Ej2vt8nb7u7ah067yA8UXgx/gCpXq5hRqri+6YD4hNaATik8ZIjxt6W/tq2iD2iqUvhCuV71EIlXZtF3nPs+weypee8AuWOGzhk2b8GBG31anTbEBs6R4DjKnfAL5ToIOA==</ds:SignatureValue></ds:Signature><saml:Subject><saml:NameID SPNameQualifier="https://sp.example.org/metadata" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.org</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-06-01T12:05:00Z" Recipient="https://sp.example.org/acs" InResponseTo="req-9988776655"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2024-06-01T11:59:00Z" NotOnOrAfter="2024-06-01T12:05:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2024-06-01T12:00:00Z" SessionIndex="sess-abc-123"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>alice@example.org</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>staff</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>
;

pub const idp_pub_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjkp+LD7fR65XtpkBy+uJ
    \\+4keD872eQ+d9LP1r2Zuz5R9QoNQNdGH1R6cdny+UC6y4CFmtzjqlmdzeHxozTbo
    \\EyRZO5fkGySRGTpwzXqr2aQiMNOm3drJRafvUS+PV8bzJJJ0jHthRsY3PoaylZPO
    \\Ja7VJV5qhwjyQVAROJf4BS7voyY9903kvoh9oL0Og6cAHWCqHh36ir7lou8C9r7L
    \\Z+r/e8GlYdiNeiGj/f9HpJB8lNRMigvew8EbRY1WabYfyW4YgOeUuFsnAr6ZXIYl
    \\6IKglxuvHNE3CgpDLCl2K5/FAjtszAkwEmI1+KTUyyNnT8xB1Lo7YwmDYLio/xE5
    \\OwIDAQAB
    \\-----END PUBLIC KEY-----
;

/// Build the configured IdP RSA verify key from the test cert's SPKI PEM,
/// reaching the rsa.PublicKey type through xmldsig.VerifyKey (saml itself does
/// not depend on rsa).
pub fn idpKey() xmldsig.VerifyKey {
    const RsaPub = @FieldType(xmldsig.VerifyKey, "rsa");
    const pk = RsaPub.fromPem(idp_pub_pem) catch unreachable;
    return .{ .rsa = pk };
}

// Timestamps (Unix seconds) around the fixture's validity window.
pub const t_before = 1717239600; // 2024-06-01T11:00:00Z (before NotBefore)
pub const t_valid = 1717243200; // 2024-06-01T12:00:00Z (inside the window)
pub const t_after = 1717245000; // 2024-06-01T12:30:00Z (after NotOnOrAfter)

pub const sp_entity_id = "https://sp.example.org/metadata";
pub const acs_url = "https://sp.example.org/acs";
pub const idp_entity_id = "https://idp.example.org/saml";
pub const request_id = "req-9988776655";
pub const assertion_id = "_a1b2c3d4e5f60718293a4b5c6d7e8f90";
