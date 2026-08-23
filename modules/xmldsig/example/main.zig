// SPDX-License-Identifier: MIT

//! What a SAML relying party does with `xmldsig`: verify a real
//! `ds:Signature` against a caller-configured trust-anchor key (never
//! `KeyInfo`), see a tampered copy of the same document rejected at the
//! reference-digest level, and see a structurally-wrong input rejected by
//! name rather than panicking.
//!
//! External judge: `xmlsec1` (C, OpenSSL backend), a genuinely independent
//! XML-Signature implementation. Both fixtures below are copied verbatim
//! from `modules/xmldsig/src/test_external.zig`, which documents the exact
//! offline provenance:
//!
//!   xmlsec1 --sign --privkey-pem:mykey rsa_priv.pem --output out.xml tmpl.xml
//!   xmlsec1 --verify --lax-key-search --pubkey-pem rsa_pub.pem out.xml   # OK
//!
//! and, for the tampered copy (`Hello World` -> `Hello WORLD`),
//! `xmlsec1 --verify` on that exact document fails with
//! `Failure reason: REFERENCE` — the same failure mode (a reference digest
//! mismatch, not a signature-bytes mismatch) this module reports.

const std = @import("std");
const xml = @import("xml");
const rsa = @import("rsa");
const xmldsig = @import("xmldsig");

fn firstChild(parent: *const xml.Element, local: []const u8) ?*xml.Element {
    for (parent.children) |c| switch (c.content) {
        .element => |el| if (std.mem.eql(u8, el.local, local)) return el,
        else => {},
    };
    return null;
}

// 2048-bit RSA public key, `openssl genrsa 2048` + `openssl rsa -pubout` —
// throwaway test material, private half discarded after signing.
const rsa_pub_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2pnU5gYsnLbNQOVlNNV4
    \\yw5L2PiPalyE7u0/qs2dP3xTTDQO6nGGDcnLpHI4gv0EiXxsB4a7Rdg7bSY/cHTd
    \\EteAnxvs9aZszpgiWQidlAJseXsYwfoBm0FN3GFMCz2tnZ/EvkijcR/cHNCcunIT
    \\ewxtab21LAD5lh+RjSo7EUEmg7J54QUzPqk0Bp1+Jsgxmw3JjFVCGjoTMIiFe/w6
    \\cEVoDiBW992nyuYYfyDbUhaRy/7Tx5bArYaBhHB/HMT0N6Uxb4cJMb5fXh+DJ3G7
    \\SNbZJZ9N14N+j61K23rOhBnyShlA7AmUKb/ch+uw4YaMJoVfHP3/knYWH07p1rk+
    \\/wIDAQAB
    \\-----END PUBLIC KEY-----
;

// xmlsec1-signed enveloped RSA-SHA256, KeyInfo/KeyName stripped (this
// module's trust model never reads KeyInfo anyway).
const enveloped_signed =
    \\<Envelope xmlns="urn:demo" ID="obj-1">
    \\<Data>Hello World</Data>
    \\<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    \\<ds:SignedInfo>
    \\<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    \\<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    \\<ds:Reference URI="">
    \\<ds:Transforms>
    \\<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
    \\<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    \\</ds:Transforms>
    \\<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    \\<ds:DigestValue>Fsg+elQmbrEFjB6sb+b1WRqBsabSDdyQOKs4FYkHYuk=</ds:DigestValue>
    \\</ds:Reference>
    \\</ds:SignedInfo>
    \\<ds:SignatureValue>2MzkveGYojFLwWG7zX7b6brmc56sN1bWxsL0Y97OkULIZvC8JvycCX8lsFGbsbiP
    \\g1/gIwDH8WxJxEEbupKgHXOvV9WYi1XLXueVwJzoCFRbRQeAYxaMYg/1bsRW8l2S
    \\+okShFWnWc/StzJ9XcHc93epFQJ5QU8W+o5DPoXbcV5UL7uxPfUZT5DRd657Dwk4
    \\+8RY9nu0kF5qjs7+RaBNkwJ8MJO5dm1+sS3Wi7gH87F9Ea4UKcSpFaOOw81NWAeC
    \\XpztGoxKjIoD4gLQWsk5JtHxVMmZNRByDOEZkD2B/5CqXXlBmF1HnZo8UnCwsiT+
    \\8LUXhfR4sCO+bN1VnmIvfA==</ds:SignatureValue>
    \\</ds:Signature>
    \\</Envelope>
;

// The SAME bytes with "Hello World" -> "Hello WORLD": xmlsec1 --verify on
// this exact document fails with "Failure reason: REFERENCE".
const enveloped_tampered =
    \\<Envelope xmlns="urn:demo" ID="obj-1">
    \\<Data>Hello WORLD</Data>
    \\<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    \\<ds:SignedInfo>
    \\<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    \\<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    \\<ds:Reference URI="">
    \\<ds:Transforms>
    \\<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
    \\<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    \\</ds:Transforms>
    \\<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    \\<ds:DigestValue>Fsg+elQmbrEFjB6sb+b1WRqBsabSDdyQOKs4FYkHYuk=</ds:DigestValue>
    \\</ds:Reference>
    \\</ds:SignedInfo>
    \\<ds:SignatureValue>2MzkveGYojFLwWG7zX7b6brmc56sN1bWxsL0Y97OkULIZvC8JvycCX8lsFGbsbiP
    \\g1/gIwDH8WxJxEEbupKgHXOvV9WYi1XLXueVwJzoCFRbRQeAYxaMYg/1bsRW8l2S
    \\+okShFWnWc/StzJ9XcHc93epFQJ5QU8W+o5DPoXbcV5UL7uxPfUZT5DRd657Dwk4
    \\+8RY9nu0kF5qjs7+RaBNkwJ8MJO5dm1+sS3Wi7gH87F9Ea4UKcSpFaOOw81NWAeC
    \\XpztGoxKjIoD4gLQWsk5JtHxVMmZNRByDOEZkD2B/5CqXXlBmF1HnZo8UnCwsiT+
    \\8LUXhfR4sCO+bN1VnmIvfA==</ds:SignatureValue>
    \\</ds:Signature>
    \\</Envelope>
;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    const gpa = gpa_state.allocator();

    const key: xmldsig.VerifyKey = .{ .rsa = try rsa.PublicKey.fromPem(rsa_pub_pem) };

    // A real xmlsec1-signed document, verified against the SP's configured
    // key (never against the document's own KeyInfo, which this fixture
    // doesn't even carry).
    {
        var doc = try xml.parse(gpa, enveloped_signed, .{});
        defer doc.deinit();
        const sig = firstChild(doc.root, "Signature").?;
        var res = try xmldsig.verify(gpa, &doc, sig, .{ .key = key });
        defer res.deinit(gpa);
        std.debug.print("real xmlsec1 signature: valid={} digest_valid={}\n", .{ res.valid, res.references[0].digest_valid });
        if (!res.valid or !res.references[0].digest_valid) return error.ExpectedValid;
    }

    // The tampered twin: xmlsec1 itself rejects this with
    // "Failure reason: REFERENCE" (a digest mismatch, not a signature-bytes
    // mismatch) — this module's verdict has to disagree at the same layer.
    {
        var doc = try xml.parse(gpa, enveloped_tampered, .{});
        defer doc.deinit();
        const sig = firstChild(doc.root, "Signature").?;
        var res = try xmldsig.verify(gpa, &doc, sig, .{ .key = key });
        defer res.deinit(gpa);
        std.debug.print("tampered document: valid={} digest_valid={}\n", .{ res.valid, res.references[0].digest_valid });
        if (res.valid or res.references[0].digest_valid) return error.ExpectedInvalid;
    }

    // Negative case: an element that is not a `ds:Signature` at all — a
    // structural problem, reported by name rather than a panic.
    {
        var doc = try xml.parse(gpa, "<NotASignature/>", .{});
        defer doc.deinit();
        if (xmldsig.verify(gpa, &doc, doc.root, .{ .key = key })) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.MalformedSignature => std.debug.print("rejected non-Signature root: MalformedSignature (expected)\n", .{}),
            else => return err,
        }
    }
}
