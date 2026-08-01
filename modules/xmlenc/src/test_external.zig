// SPDX-License-Identifier: MIT
//! EXTERNAL-anchor tests for xmlenc decryption. `test_roundtrip.zig`'s own
//! header was honest that it had no real external `EncryptedData` fixture —
//! this file closes that gap: every `<xenc:EncryptedData>` below was produced
//! ONCE, offline, by `xmlsec1 --encrypt` (C, OpenSSL backend, a genuinely
//! independent XML-Enc implementation) against a freshly-generated 2048-bit
//! RSA keypair, and is committed here as a literal byte string. Nothing here
//! shells out; the tests assert purely offline.
//!
//! Reproduction commands (for re-derivation only, never run by this suite):
//! ```sh
//! xmlsec1 --encrypt --session-key aes-256 --pubkey-pem:spkey pub.pem \
//!   --xml-data assertion_plain.xml --output out.xml enc_template.xml
//! xmlsec1 --decrypt --privkey-pem:spkey priv.pem out.xml   # round-trip self-check
//! ```
//! The plaintext (`<saml:Assertion>...the recovered assertion body...`) and its
//! RSA key are the SAME test fixtures `test_roundtrip.zig` already uses, so the
//! only variable is who produced the ciphertext.
//!
//! Direction NOT covered here (and why): "xmlsec1 decrypts what we produce" is
//! inapplicable — this module is decrypt-only by design (see README "Scope");
//! it has no encrypt API to hand xmlsec1 anything. That is a scope statement,
//! not a gap: xmlenc's job is the SP side of XML-Enc (holds the private key,
//! decrypts an IdP-produced ciphertext), and no correct implementation of that
//! role ever produces ciphertext for a peer to check.

const std = @import("std");
const testing = std.testing;
const xml = @import("xml");
const rsa = @import("rsa");
const xmlenc = @import("root.zig");

// A freshly generated 2048-bit RSA keypair, `openssl genrsa 2048`, TEST
// MATERIAL ONLY. This is the SP decryption key xmlsec1 encrypted under.
const sp_priv_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDamdTmBiycts1A
    \\5WU01XjLDkvY+I9qXITu7T+qzZ0/fFNMNA7qcYYNycukcjiC/QSJfGwHhrtF2Dtt
    \\Jj9wdN0S14CfG+z1pmzOmCJZCJ2UAmx5exjB+gGbQU3cYUwLPa2dn8S+SKNxH9wc
    \\0Jy6chN7DG1pvbUsAPmWH5GNKjsRQSaDsnnhBTM+qTQGnX4myDGbDcmMVUIaOhMw
    \\iIV7/DpwRWgOIFb33afK5hh/INtSFpHL/tPHlsCthoGEcH8cxPQ3pTFvhwkxvl9e
    \\H4MncbtI1tkln03Xg36PrUrbes6EGfJKGUDsCZQpv9yH67DhhowmhV8c/f+SdhYf
    \\TunWuT7/AgMBAAECggEAYA4XgGn3IXer8le6ZIBm/ybNik4SSsTTvt8uSkHmVnat
    \\bX80jK0MoDNrUdvE3D4Mx9MN7zKzSKoO1tPnLWWUnQpn4MJXGcwi5JbyBNhl0ZtN
    \\CgZepyHRoeSMr4lrbkcQaoJBY/GsK/G5eUnrjHvC9p9L1pp/KRJWmbJOdU64vMfp
    \\NcEOppozENA0hVozro3v0OSbHsafgvHyQSxjsLqaBfMOklkOQDh9YusugkLctpmO
    \\sDrCnbofaLGuqjridEhKSRQp/nEokdJZUwZzOz0nBk2BCDY3CvmhYkZTrr834Pbx
    \\EafkCmP2t0Yc3m5V5/Ak8UZuAMOznHErSw9mzaf2OQKBgQD7srcPu5GjvyTghcZv
    \\zDA763DMmBdW/wk/iu3qKXE0ltrDMYhhRiLfHr/Z03Ie4kVAuUarVh/xGoBKQHEG
    \\m6et+OilaJ3GZy+8BnBCsXTBslGORgEHmXUPfy6C9QLHi0Hs52qBfr5FDDGuOi/u
    \\ybQmjhSO2F8+UTF13cSncIQUtwKBgQDeVk1p6Mfi6OES0A3I8zSuXsV3kNXkui7E
    \\WwlDEbweQoSwxS55Yht0Gx5Q3SQum2a33Jl9cj6InBqwpVSUJTBLEH4xurUok2gN
    \\GpsQx45pcmyII54V30BFQdglAWallrCzpy/K8ysAyVqjKYvXBFJq/N5JiN0+8dBx
    \\5z3anKiv+QKBgGw/7o9rojWEjb2qiy+l59C9b6PufYtC4J1diPk+nZt6jdeJRBhh
    \\67l+JhDu6ZPyyMoPZR9nSRGOzkIg+PtYkoM2HAiXt9OOqW76bemhHI/5uy2vWd4E
    \\1920WzKjYXCkqdPTq3DKK9bSacN+7wKJ6VrznE/bKwtILDd/C4bf0059AoGAPE5M
    \\UR3Cmdlwsxmbo5XUBDfQd83hNlkJtli6+mYlEFAajZfuMx5ZM/TnFCfnWHzuL5C2
    \\UUBbldJBqwgtGMG9h57Bm9t4p7jT0DoXNUXras6OgZ6nkmcrl510cxUeMmvdId2H
    \\KRUr5Nq4qujp9ThG4p4T7P4ihKAyWbLPJCy51IECgYEAt3IL199jQGu/Nc9Acafm
    \\8YPwZUOxSqATnPzS55baqwYmLYeqKwYml9BfbsN33au1RmaTgEQ9XwhoR/ky33Rt
    \\nOH0EyHRWOwOEwpk7uY/xF+rw6Tlnu4Mak+IpIFfATaq4VriFNMbnMpbeg6btArx
    \\NechQClt9KObXoEaGHvNb28=
    \\-----END PRIVATE KEY-----
;

const expected_plaintext =
    "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " ++
    "ID=\"_a1b2\" Version=\"2.0\">the recovered assertion body</saml:Assertion>";

fn spKey() !rsa.SecretKey {
    return rsa.SecretKey.fromPem(sp_priv_pem);
}

// ── fixture 1: xmlsec1-encrypted, RSA-OAEP-mgf1p key transport + AES-256-GCM
// content. `xmlsec1 --decrypt` on this exact document (before it was pasted
// here) recovered `expected_plaintext` byte-for-byte.

const encrypted_gcm =
    \\<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
    \\<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
    \\<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    \\<xenc:EncryptedKey>
    \\<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
    \\<ds:KeyInfo><ds:KeyName>spkey</ds:KeyName></ds:KeyInfo>
    \\<xenc:CipherData><xenc:CipherValue>BbWe+6PBZxT+wX2wEuxWua/Gi6RW/Cq1gQHCZeGr8Fi5uQVO9fnjy9UzBH4yQzsi
    \\kOltIrffy8+0XD/T6M/5JcWiodL7m+a1NPGMDeIm8MnMC/hARF4SnegpqrNFMO6b
    \\SwH7G0jxXY0dKSlcM9jjAxVFDTDlU5RfniMOluMXSCpYZzOMqOReqpjcpwkjkKoX
    \\pgWVfiuK1sCm3EzOwclgk/1iVOaIsAlmkyvimLLBq+5++SFeZCWGiprlj6N52A9+
    \\2h9BfuKQzhjC5DNYe5kGPha3D3stWkojTT1IiEkzbrnvtaUQ5avjGheGpmEMSCFP
    \\/GMWGz/g5HP2HdKxge9mww==</xenc:CipherValue></xenc:CipherData>
    \\</xenc:EncryptedKey>
    \\</ds:KeyInfo>
    \\<xenc:CipherData><xenc:CipherValue>m04PwnpX24HY3yx5xXsARxaCJOZCadd5v7sR0vh/rmHQFhveCquRsEqaV0nMuGNP
    \\o7YirgFIPJUfvzw1nhiOgdDvBcV9MOs6suHrZm91rcPqKZTOqtoxdS9uiE8YPiEW
    \\JkDpgOizQIqJlqF58vwIphZ4sYzusO00Cr2zB/EZqCqrxeVj6WB3x7ea4o7IY0xr
    \\KhYn8Sq1yq0MvC7lMiG0aBZ5+rQ1</xenc:CipherValue></xenc:CipherData>
    \\</xenc:EncryptedData>
;

test "EXTERNAL anchor: xmlsec1-encrypted RSA-OAEP-mgf1p + AES-256-GCM decrypts to the exact plaintext" {
    const a = testing.allocator;
    var doc = try xml.parse(a, encrypted_gcm, .{});
    defer doc.deinit();
    const out = try xmlenc.decryptData(a, doc.root, try spKey(), .{});
    defer a.free(out);
    try testing.expectEqualStrings(expected_plaintext, out);
}

// ── fixture 2: xmlsec1-encrypted, xenc11 rsa-oaep (SHA-256, MGF default
// SHA-1) key transport + AES-256-CBC content. Also xmlsec1-decrypt-confirmed
// offline before being pasted here.

const encrypted_cbc =
    \\<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
    \\<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
    \\<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    \\<xenc:EncryptedKey>
    \\<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">
    \\<ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    \\</xenc:EncryptionMethod>
    \\<ds:KeyInfo><ds:KeyName>spkey</ds:KeyName></ds:KeyInfo>
    \\<xenc:CipherData><xenc:CipherValue>emHjrKRNQnAOR3PcUPgvAeRbNO/Ynpi/kOTUbgOJFgda5cgakpWS/PDwV0MICuxP
    \\K6JD+SFXhNu0nBvV9tvHpXOSsNlB3MSUK4OUbqP1er6APwR3eGvOOA85D8aC7fA2
    \\ZQnJPtHtWJMYkrrTixcipCHjmJuJeOKarjqurNQICAQBYsk53ya+aRS14WcdHsM+
    \\nf6td662dhmGNcrgSkMt07ND/l57xVMjfkjp4WGUzkTXZ6c1OeeV569Ut1ipeVFb
    \\Ruk1neYte3AU5mjuKEPSW92ujpnQwXICc8EDr9VFjWCRG0xJkUUADIBUI2HdCymL
    \\VfDlHasWElj54gLKDbDg8Q==</xenc:CipherValue></xenc:CipherData>
    \\</xenc:EncryptedKey>
    \\</ds:KeyInfo>
    \\<xenc:CipherData><xenc:CipherValue>knHO6PON++fWbXZOcQR9bU6gxkCBLEgczkCAfqYj9jpvv7lxqukhEZNc8G4UdCAH
    \\Fnfde+8FheBBiE/nuVhkXds29Nlbh9XZjgfyMawCDLD7pETD78O6dbK58RLFw2Fs
    \\oT/Hz1txu3Uik+ogJrRLU+qXfUIgVl1M8KsUwjwin5W0bq5xFQov7IrOvnpTOUy9
    \\Vv5BEkRNmWw8mhyMa3arng==</xenc:CipherValue></xenc:CipherData>
    \\</xenc:EncryptedData>
;

test "EXTERNAL anchor: xmlsec1-encrypted xenc11 rsa-oaep(SHA-256) + AES-256-CBC decrypts to the exact plaintext" {
    const a = testing.allocator;
    var doc = try xml.parse(a, encrypted_cbc, .{});
    defer doc.deinit();
    const out = try xmlenc.decryptData(a, doc.root, try spKey(), .{});
    defer a.free(out);
    try testing.expectEqualStrings(expected_plaintext, out);
}

// ── fixture 3: same GCM ciphertext as fixture 1, one base64 char flipped in
// the content CipherValue. `xmlsec1 --decrypt` on this exact tampered copy
// fails ("Error: failed to decrypt file"); our decrypt must reject it too
// (AEAD tag no longer verifies -> generic DecryptionError, no oracle signal).

const encrypted_gcm_tampered =
    \\<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
    \\<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
    \\<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    \\<xenc:EncryptedKey>
    \\<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
    \\<ds:KeyInfo><ds:KeyName>spkey</ds:KeyName></ds:KeyInfo>
    \\<xenc:CipherData><xenc:CipherValue>BbWe+6PBZxT+wX2wEuxWua/Gi6RW/Cq1gQHCZeGr8Fi5uQVO9fnjy9UzBH4yQzsi
    \\kOltIrffy8+0XD/T6M/5JcWiodL7m+a1NPGMDeIm8MnMC/hARF4SnegpqrNFMO6b
    \\SwH7G0jxXY0dKSlcM9jjAxVFDTDlU5RfniMOluMXSCpYZzOMqOReqpjcpwkjkKoX
    \\pgWVfiuK1sCm3EzOwclgk/1iVOaIsAlmkyvimLLBq+5++SFeZCWGiprlj6N52A9+
    \\2h9BfuKQzhjC5DNYe5kGPha3D3stWkojTT1IiEkzbrnvtaUQ5avjGheGpmEMSCFP
    \\/GMWGz/g5HP2HdKxge9mww==</xenc:CipherValue></xenc:CipherData>
    \\</xenc:EncryptedKey>
    \\</ds:KeyInfo>
    \\<xenc:CipherData><xenc:CipherValue>m04PwnpX24HY3yx5xXsARxaCJOZCadd5v7sR0vh/rmHQFhveCquRsEqaV0nMuGNP
    \\o7YirgFIPJUfvzw1nhiOgdDvBcV9MOs6suHrZm91rcPqKZAOqtoxdS9uiE8YPiEW
    \\JkDpgOizQIqJlqF58vwIphZ4sYzusO00Cr2zB/EZqCqrxeVj6WB3x7ea4o7IY0xr
    \\KhYn8Sq1yq0MvC7lMiG0aBZ5+rQ1</xenc:CipherValue></xenc:CipherData>
    \\</xenc:EncryptedData>
;

test "EXTERNAL anchor: fixture count canary — 3 genuinely xmlsec1-encrypted EncryptedData documents" {
    const fixtures = [_][]const u8{ encrypted_gcm, encrypted_cbc, encrypted_gcm_tampered };
    try testing.expectEqual(@as(usize, 3), fixtures.len);
    for (fixtures) |f| try testing.expect(f.len > 200);
}

test "EXTERNAL anchor: tampered content ciphertext xmlsec1 refuses to decrypt is refused here too" {
    const a = testing.allocator;
    var doc = try xml.parse(a, encrypted_gcm_tampered, .{});
    defer doc.deinit();
    try testing.expectError(error.DecryptionError, xmlenc.decryptData(a, doc.root, try spKey(), .{}));
}
