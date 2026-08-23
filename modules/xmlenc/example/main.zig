// SPDX-License-Identifier: MIT

//! What a SAML relying party does with `xmlenc`: hold the RSA private key,
//! decrypt a real `<xenc:EncryptedData>` produced by an independent
//! implementation, and see a tampered ciphertext refused with a named error
//! instead of returning corrupted plaintext.
//!
//! External judge: `xmlsec1 --encrypt` (C, OpenSSL backend). Both fixtures
//! below are copied verbatim from `modules/xmlenc/src/test_external.zig`,
//! which documents the exact offline provenance:
//!
//!   xmlsec1 --encrypt --session-key aes-256 --pubkey-pem:spkey pub.pem \
//!     --xml-data assertion_plain.xml --output out.xml enc_template.xml
//!   xmlsec1 --decrypt --privkey-pem:spkey priv.pem out.xml   # round-trip check
//!
//! `xmlsec1 --decrypt` recovered the exact plaintext below from the first
//! fixture before it was pasted here, and refused to decrypt the tampered
//! twin ("Error: failed to decrypt file") — this module has to agree on
//! both outcomes.

const std = @import("std");
const xml = @import("xml");
const rsa = @import("rsa");
const xmlenc = @import("xmlenc");

// A freshly generated 2048-bit RSA keypair, `openssl genrsa 2048` — TEST
// MATERIAL ONLY, the private half of the SP decryption key xmlsec1
// encrypted under.
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

// xmlsec1-encrypted RSA-OAEP-mgf1p key transport + AES-256-GCM content.
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

// Same ciphertext, one base64 character flipped in the content CipherValue
// ("...ZmPqKZTOqtoxdS9..." -> "...ZmPqKZAOqtoxdS9..."). `xmlsec1 --decrypt`
// refuses this exact document.
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

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    const gpa = gpa_state.allocator();

    const sk = try rsa.SecretKey.fromPem(sp_priv_pem);

    // A real xmlsec1-encrypted document: RSA-OAEP key transport wrapping an
    // AES-256-GCM content key, decrypted back to the exact plaintext
    // xmlsec1 itself recovered.
    {
        var doc = try xml.parse(gpa, encrypted_gcm, .{});
        defer doc.deinit();
        const out = try xmlenc.decryptData(gpa, doc.root, sk, .{});
        defer gpa.free(out);
        std.debug.print("decrypted {d} bytes: {s}\n", .{ out.len, out });
        if (!std.mem.eql(u8, out, expected_plaintext)) return error.UnexpectedPlaintext;
    }

    // The tampered twin: xmlsec1 --decrypt refuses this exact document
    // ("Error: failed to decrypt file") — the GCM tag no longer verifies.
    // This module must fail closed with the SAME named error every
    // cryptographic failure collapses to (never a padding/oracle signal).
    {
        var doc = try xml.parse(gpa, encrypted_gcm_tampered, .{});
        defer doc.deinit();
        if (xmlenc.decryptData(gpa, doc.root, sk, .{})) |plaintext| {
            gpa.free(plaintext);
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.DecryptionError => std.debug.print("rejected tampered ciphertext: DecryptionError (expected)\n", .{}),
            else => return err,
        }
    }
}
