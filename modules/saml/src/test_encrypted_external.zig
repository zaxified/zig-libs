// SPDX-License-Identifier: MIT
//! EXTERNAL-anchor test for the eIDAS encrypted-assertion path. `SPEC.md`
//! honestly labelled `test_encrypted.zig`'s fixtures CONSTRUCTED (this
//! module's own encryption helpers feeding its own decryptor) because no real
//! external `EncryptedAssertion` was available. One now is: `xmlsec1
//! --encrypt` (C, OpenSSL backend — genuinely independent of this codebase)
//! encrypted the module's EXISTING genuinely-signed assertion (the same
//! openssl+lxml `fixtures.signed_response` assertion `test_fixture.zig`
//! anchors) under a freshly-generated 2048-bit RSA keypair, producing a real
//! `<xenc:EncryptedData>`/`<xenc:EncryptedKey>` this file commits verbatim.
//!
//! Reproduction (for re-derivation only; the test asserts purely offline):
//! ```sh
//! xmlsec1 --encrypt --session-key aes-256 --pubkey-pem:spkey2 sp_pub.pem \
//!   --xml-data assertion_selfcontained.xml --output out.xml enc_template.xml
//! xmlsec1 --decrypt --privkey-pem:spkey2 sp_priv.pem out.xml   # => the exact
//!   self-contained signed assertion, byte-for-byte (confirmed before pasting)
//! ```
//! Because decryption recovers the SAME already-externally-anchored signed
//! assertion, decrypt -> signature-verify -> extract must yield the identical
//! `AuthnResult` the cleartext fixture in `test_fixture.zig` produces — this
//! is a genuine external fixture for the FULL encrypted-assertion pipeline,
//! not merely for `xmlenc`'s decrypt primitive in isolation.

const std = @import("std");
const testing = std.testing;
const rsa = @import("rsa");
const saml = @import("root.zig");
const fx = @import("fixtures.zig");

// A freshly generated 2048-bit RSA keypair, `openssl genrsa 2048`, TEST
// MATERIAL ONLY — this is the SP decryption key xmlsec1 encrypted under.
const sp_priv_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDLF3y7pbHUClju
    \\ahhXbxeXbo+qyxvjgtRNIYNjrA1Z+arB3YxNxjSScw/wZoMH75qrGupxI1OfLYIG
    \\fPgrl79Ulq38mYdqTCM6tufIQ3yIqxscyflGI+VFLuPDLMxkaWyBhDWaOVW/LKja
    \\8WU205JEcQuuB6g3Zo/rwzW4o39NON7RFaeohjTfe5zCdOB9vbkb4KqBwe9nGhMF
    \\ZiL2o5lrEKwyRWVvTfLf8cGskL6cwTUVS/VIUFbSmept1ukf5W9TH3tIz2qqW5Dj
    \\l27dD0SwWaXNt+OWWvEILOSAMSVHkXBvu+SbyYqet/BfZ1Y7ZRxrEFHn9ozOgSba
    \\mPm7mB8DAgMBAAECggEAH8UQ0hndc5oax1D5ddP/EMVO3Bzhw/lXVKmFcDYd8JFJ
    \\0QHjTNdQqggt2iFvJfKpc1LGkeRA1Im96V3rRIZ8e7MGjJlHwa0fZbPvFjjYZli9
    \\6Qb/Y6WB3Ay1vHZpktubCbew2utVKo7F61oPxz/ZhbNZbGPuQJxerzbeVH/fDikr
    \\nXTPWQGrd71ats31J7sEBt2+LTAJGwyPRqpos8mlxUjtx+oKd768hxX8UhFcwxOh
    \\u0J/wkBTI7DQN3R0gx4+yF/s5cpLPDPFzTv3vC/nHpmC4IAgwH+Nj4iZHjvsZKj3
    \\t1qgSUTbDbFuGUpe7AMX4pp+dhCGFpP53LMiLQFNoQKBgQD8U6wizL3O1pVethx+
    \\/1qgQMbvQfKBvFivrEdGJAZaoTo9oiSxhSXkBheAVEjfOuo4paWC3sh8LlZ6oyTO
    \\+YmDtNhZ+17PY5GJpbAt+eAFCUhUIWrCw6msN/t7EcjqDCi5rIH6pI6NI05xQF5S
    \\gG0c8YYOchvKAhJ0A3LxdCDN1wKBgQDODFWFtk0hlGpThOMeh6wEiFpt93CVCzNl
    \\dwsZ/wDjuMpE/ZqZs2P7IOgNzc0LuCD6qnm5T3WKb20wqLf+/gmRwhF2D27Idg7/
    \\U28R8Ec85K3/nnFBK2GCw3Q3nmzCqKWiFCw9K72HdOhaZXDjNXmMd5U5W7Xmeq02
    \\3mpHzR9atQKBgQDzg4zMyOslgtIE5Zv6tFWx8tIKdYqkyjCM2aavenTnYlHiyWjA
    \\Kc+3kGl939m0FheVM8fX1UmHDvFGycvsM8cS5KUnsgB+BYmfXdf5hv073wl+qAFw
    \\lYRaQGzjCPbtaW6kQmfujIFGlJxPj993n5muJSlLJ7TJ79X/QJTdkUVXYQKBgQCv
    \\6BvDMaWbu2cislproAwdOoNpSkvVEmDoiL7zjJ6nywTz7UZlXZ9HsAosbrxU+vc8
    \\yPluWQXSD9q6JfAfQ6XLyFC75+T+Qrv/Aq3aNLW8qMZbalrp9i0jQ9Yd/aSAcxYk
    \\zvANsR/3WrlbIytC7k48u4KsGz2p7KWgKDW34siX2QKBgQDknN3YXOKMSyw4rELf
    \\voAGk8NCMa07Y5qS+c/vnsaEeAG2mVrrzmPe3ybzllcvo+rSW82H+edjzUq8ZLYJ
    \\iN90J7ZBIckcUzpvc5mOz9TSS83Sf9eD+cjVZxtN7sTflqWIR8uTdcD7mFtqN0cd
    \\jh0YKuoiEhnQC/fHoX6PWHJDmQ==
    \\-----END PRIVATE KEY-----
;

fn spKey() !rsa.SecretKey {
    return rsa.SecretKey.fromPem(sp_priv_pem);
}

// The Response with its cleartext `<saml:Assertion>` swapped for a real
// `xmlsec1`-produced `<saml:EncryptedAssertion>` wrapping the SAME
// genuinely-signed assertion bytes `fx.signed_response` carries (made
// self-contained: it declares its own `xmlns:saml` instead of inheriting it
// from the Response, exactly as `test_encrypted.zig`'s own helper does —
// Exclusive-C14N is position-independent, so the existing IdP signature over
// it is unaffected by that declaration).
const response_with_encrypted_assertion =
    "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp0011223344556677889900aabbcc\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\" Destination=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"><saml:Issuer>https://idp.example.org/saml</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status><saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">\n" ++
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/>\n" ++
    "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" ++
    "<xenc:EncryptedKey>\n" ++
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>\n" ++
    "<ds:KeyInfo><ds:KeyName>spkey2</ds:KeyName></ds:KeyInfo>\n" ++
    "<xenc:CipherData><xenc:CipherValue>tqvMi5uBvVEjPHorSQ31HU/Ppu4D+48j3B5KMfFCEn0Dup0aao4ahnKCxMLZ9Xq6\n" ++
    "4xPUywoP04lJEALYGfWFOUrXTpTHQp8qTYTuFq01t8Bmxpqcv+aWqX/i3kq2YWg/\n" ++
    "CcS4AMd1wl9d+XHH9vjHDhFJ0DYRDDW7OcjhfpyTLWZ/8tthXEKmX5jbrq3cJ9Wr\n" ++
    "or/NVCEsjvCmWmlHqW4ISdCvC2Us8bIEVVCgqhyn37sIWkZuf5l4o32lao7IYOSH\n" ++
    "memt2xy8bf8ta7TynerkztB8NjpH/ftZ7kSZGmKmsVNYd2bTKq29p2iCJ+WYhOcm\n" ++
    "EDG6qKZGYavoxXcdktu/DA==</xenc:CipherValue></xenc:CipherData>\n" ++
    "</xenc:EncryptedKey>\n" ++
    "</ds:KeyInfo>\n" ++
    "<xenc:CipherData><xenc:CipherValue>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</xenc:CipherValue></xenc:CipherData>\n" ++
    "</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>";

fn baseConfig(now: i64) saml.Config {
    return .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = fx.idpKey(),
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = now,
        .expected_in_response_to = fx.request_id,
    };
}

test "EXTERNAL anchor: fixture count canary — 1 genuinely xmlsec1-encrypted EncryptedAssertion response" {
    const fixtures = [_][]const u8{response_with_encrypted_assertion};
    try testing.expectEqual(@as(usize, 1), fixtures.len);
    try testing.expect(fixtures[0].len > 3000);
}

test "EXTERNAL anchor: xmlsec1-encrypted EncryptedAssertion decrypts -> verifies -> extracts identically to the cleartext fixture" {
    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = try spKey();
    var res = try saml.consumeResponseXml(testing.allocator, response_with_encrypted_assertion, cfg);
    defer res.deinit();

    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expectEqualStrings("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", res.name_id_format.?);
    try testing.expectEqualStrings("https://sp.example.org/metadata", res.name_id_sp_qualifier.?);
    try testing.expectEqualStrings("sess-abc-123", res.session_index.?);
    try testing.expectEqualStrings(fx.assertion_id, res.assertion_id);
    const groups = res.attribute("groups").?;
    try testing.expectEqual(@as(usize, 2), groups.len);
    try testing.expectEqualStrings("admins", groups[0]);
    try testing.expectEqualStrings("staff", groups[1]);
}

test "EXTERNAL anchor: tampered ciphertext xmlsec1 itself refuses to decrypt is refused here too" {
    // One base64 character flipped in the content CipherValue (the same
    // tamper xmlsec1 --decrypt was confirmed, offline, to reject before this
    // test was written). Decrypt succeeds structurally but the AES-GCM tag no
    // longer verifies -> the generic, oracle-safe AssertionDecryptionFailed.
    const alloc = testing.allocator;
    const tampered = try std.mem.replaceOwned(
        u8,
        alloc,
        response_with_encrypted_assertion,
        "rcZbQ14ihdiLS6o3GRZZTq6jkh27qc3UcIH5FDtCLm7OwRgUuUlsH+xXhm4QxwAv",
        "rcZbQ14ihdiLS6o3GRZZTq6jkh27qc3UcIH5FDtCLm7OwRgUuUlsH+AXhm4QxwAv",
    );
    defer alloc.free(tampered);
    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = try spKey();
    try testing.expectError(error.AssertionDecryptionFailed, saml.consumeResponseXml(alloc, tampered, cfg));
}
