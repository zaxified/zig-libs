// SPDX-License-Identifier: MIT
//! EXTERNAL-anchor tests for `verify()`, closing the gap the module's own
//! `SPEC.md` used to admit: the round-trip fixtures in `root.zig` are signed by
//! this module's OWN test scaffolding (the sibling `rsa`/`p256` signers), so a
//! green verify there proves internal self-consistency, not cross-tool interop.
//!
//! Every fixture below was produced ONCE, offline, by a genuinely independent
//! tool — `xmlsec1` (C, OpenSSL backend) or `signxml` (pure-Python) — and is
//! committed here as a literal byte string. The tests assert purely offline;
//! nothing here shells out. Provenance commands (for re-derivation only, never
//! run by the test suite):
//!
//! ```sh
//! xmlsec1 --sign --privkey-pem:mykey rsa_priv.pem --output out.xml tmpl.xml
//! xmlsec1 --verify --lax-key-search --pubkey-pem rsa_pub.pem out.xml
//! ```
//!
//! `signxml_enveloped_rsa_sha256`: signed by `signxml.XMLSigner` (pure Python,
//! shares NO code with xmlsec1/OpenSSL or with this module), then independently
//! confirmed with `xmlsec1 --verify --lax-key-search --id-attr:ID urn:demo:Envelope`
//! — so two mutually-independent external verifiers agree with our verifier on
//! the same bytes.
//!
//! All RSA/EC keys below are freshly generated, throwaway TEST MATERIAL ONLY
//! (`openssl genrsa 2048`, `openssl ecparam -name prime256v1 -genkey`); private
//! keys were discarded after signing and do not appear here.

const std = @import("std");
const testing = std.testing;
const xml = @import("xml");
const rsa = @import("rsa");
const p256 = @import("p256");
const xmldsig = @import("root.zig");
const verify = xmldsig.verify;

/// First direct-child element named `local` (namespace-blind — fine for this
/// file's fixtures, which have no colliding local names).
fn firstChild(parent: *const xml.Element, local: []const u8) ?*xml.Element {
    for (parent.children) |c| switch (c.content) {
        .element => |el| if (std.mem.eql(u8, el.local, local)) return el,
        else => {},
    };
    return null;
}

// ── keys (test material only) ───────────────────────────────────────────────

// 2048-bit RSA public key, `openssl genrsa 2048` + `openssl rsa -pubout`.
// Signs: enveloped_signed_rsa_sha256, enveloping_signed_rsa_sha256,
// enveloped_tampered_rsa_sha256, signxml_enveloped_rsa_sha256.
const ext_rsa_pub_pem =
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

// P-256 private scalar recovered from `openssl ecparam -genkey` (raw big-endian
// 32 bytes) — the corresponding public point is derived in-test via
// `P256.combMulBase`, the same pattern `root.zig`'s own ECDSA test uses.
// Signs: ecdsa_signed_p256_sha256.
const ext_ec_sk = [_]u8{
    0xfa, 0xbe, 0xac, 0xf2, 0x21, 0x9a, 0xae, 0x45, 0x0b, 0x91, 0x18, 0x85,
    0xd8, 0xbf, 0x60, 0x43, 0x63, 0x84, 0xc6, 0x42, 0xd0, 0x37, 0x67, 0x1b,
    0xd6, 0xc4, 0x77, 0x7e, 0xd8, 0xfa, 0x6b, 0x53,
};

fn extRsaKey() !rsa.PublicKey {
    return rsa.PublicKey.fromPem(ext_rsa_pub_pem);
}

fn extEcSec1() [65]u8 {
    return (p256.P256.combMulBase(ext_ec_sk, .big) catch unreachable).toUncompressedSec1();
}

// ── fixture 1: xmlsec1-signed, enveloped RSA-SHA256, no KeyInfo ─────────────
// `xmlsec1 --sign --privkey-pem:mykey ... ` then the KeyInfo/KeyName was
// stripped (our trust model never reads it); re-verified with
// `xmlsec1 --verify --lax-key-search --pubkey-pem rsa_pub.pem` after stripping.

const enveloped_signed_rsa_sha256 =
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

test "EXTERNAL anchor: xmlsec1-signed enveloped RSA-SHA256 accepted" {
    const a = testing.allocator;
    var doc = try xml.parse(a, enveloped_signed_rsa_sha256, .{});
    defer doc.deinit();
    const sig = firstChild(doc.root, "Signature").?;
    var res = try verify(a, &doc, sig, .{ .key = .{ .rsa = try extRsaKey() } });
    defer res.deinit(a);
    try testing.expect(res.valid);
    try testing.expectEqual(@as(usize, 1), res.references.len);
    try testing.expect(res.references[0].digest_valid);
}

// ── fixture 2: the SAME bytes, xmlsec1-confirmed tampered rejection ─────────
// `sed 's/Hello World/Hello WORLD/'` on the fixture above; `xmlsec1 --verify`
// on the tampered copy fails with `Failure reason: REFERENCE`. Our verify()
// must reject it for the same reason (reference digest mismatch), not merely
// "somehow" reject it.

const enveloped_tampered_rsa_sha256 =
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
    \\<ds:KeyInfo><ds:KeyName>mykey</ds:KeyName></ds:KeyInfo>
    \\</ds:Signature>
    \\</Envelope>
;

test "EXTERNAL anchor: tampered content xmlsec1 rejects (Failure reason: REFERENCE) is rejected here too" {
    const a = testing.allocator;
    var doc = try xml.parse(a, enveloped_tampered_rsa_sha256, .{});
    defer doc.deinit();
    const sig = firstChild(doc.root, "Signature").?;
    var res = try verify(a, &doc, sig, .{ .key = .{ .rsa = try extRsaKey() } });
    defer res.deinit(a);
    try testing.expect(!res.valid);
    try testing.expect(!res.references[0].digest_valid);
}

// ── fixture 3: xmlsec1-signed ENVELOPING RSA-SHA256 (Signature is the root,
// the signed content is a same-document Reference into a ds:Object) ────────

const enveloping_signed_rsa_sha256 =
    \\<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    \\<ds:SignedInfo>
    \\<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    \\<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    \\<ds:Reference URI="#object1">
    \\<ds:Transforms>
    \\<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    \\</ds:Transforms>
    \\<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    \\<ds:DigestValue>w97QGrCjXAMrcAkDAtQIVOKTbUFeFdD16HgCclmtWQY=</ds:DigestValue>
    \\</ds:Reference>
    \\</ds:SignedInfo>
    \\<ds:SignatureValue>SxixWQI6hKNgL2SjAkSqCeVJjVAFOEyCSo+J75Dm93boYtcXYdNDpbDuAUyP0maD
    \\J7DUYXUkmVMqAOOlr7W74qapaZo6wMhZ9A0NMoPVo4CCJ2GI6rBovhEeqHm8nmxd
    \\HCSIe5J5PMbBsR7TeeLe/ajwtjXw/0FqoC7FW3iZneodm9xz7BWP/f76T7uWkGye
    \\0PyFBDnk0lVNxcpm3j44tClzSzoM9ZI5SXclLj6cR0Cg1HO/sLI7ogHybB98S0tv
    \\g+x22HUPb6gxPJ7rlMVonECC60GdlrO0rEf44cqtnPQpEEfUzRzElCv9X3swkgoB
    \\7DxvmjUxBEjmSbrb6yF1TA==</ds:SignatureValue>
    \\<ds:KeyInfo><ds:KeyName>mykey</ds:KeyName></ds:KeyInfo>
    \\<ds:Object Id="object1"><Data xmlns="urn:demo">Enveloping payload</Data></ds:Object>
    \\</ds:Signature>
;

test "EXTERNAL anchor: xmlsec1-signed enveloping RSA-SHA256 (Signature is the document root) accepted" {
    const a = testing.allocator;
    var doc = try xml.parse(a, enveloping_signed_rsa_sha256, .{});
    defer doc.deinit();
    // Enveloping: the Signature IS the root; no enveloped-signature transform.
    var res = try verify(a, &doc, doc.root, .{ .key = .{ .rsa = try extRsaKey() } });
    defer res.deinit(a);
    try testing.expect(res.valid);
    try testing.expectEqual(@as(usize, 1), res.references.len);
    try testing.expect(res.references[0].digest_valid);
}

// ── fixture 4: xmlsec1-signed enveloped ECDSA-P256-SHA256 ───────────────────
// xmlsec1's OpenSSL backend emits the raw IEEE-P1363 r‖s form for XML-DSig
// ECDSA (confirmed: base64-decoded SignatureValue is exactly 64 bytes), which
// is exactly what this module requires (never DER).

const ecdsa_signed_p256_sha256 =
    \\<Envelope xmlns="urn:demo" ID="obj-1">
    \\<Data>ec-content</Data>
    \\<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    \\<ds:SignedInfo>
    \\<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    \\<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
    \\<ds:Reference URI="">
    \\<ds:Transforms>
    \\<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
    \\<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    \\</ds:Transforms>
    \\<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    \\<ds:DigestValue>+hLPDYMfIfPkDuQwKxnr1+Y3SRNwgxRDOvcK1sqg1NM=</ds:DigestValue>
    \\</ds:Reference>
    \\</ds:SignedInfo>
    \\<ds:SignatureValue>qb1h6fgDyPv3JP3Q3uOalWFC9JLyAzgYR1nnI/Cys2itr7O9SE090gNKXXMinCRw
    \\5fpRRq59IzNWy6RqTgD+pQ==</ds:SignatureValue>
    \\<ds:KeyInfo><ds:KeyName>eckey</ds:KeyName></ds:KeyInfo>
    \\</ds:Signature>
    \\</Envelope>
;

test "EXTERNAL anchor: xmlsec1-signed enveloped ECDSA-P256-SHA256 accepted" {
    const a = testing.allocator;
    var doc = try xml.parse(a, ecdsa_signed_p256_sha256, .{});
    defer doc.deinit();
    const sig = firstChild(doc.root, "Signature").?;
    const sec1 = extEcSec1();
    var res = try verify(a, &doc, sig, .{ .key = .{ .ecdsa_p256_sec1 = &sec1 } });
    defer res.deinit(a);
    try testing.expect(res.valid);
    try testing.expect(res.references[0].digest_valid);
}

// ── fixture 5: signxml-signed (independent pure-Python implementation),
// cross-confirmed by xmlsec1 ─────────────────────────────────────────────
//
// Signed with `signxml.XMLSigner(method=methods.enveloped,
// signature_algorithm="rsa-sha256", ...).sign(root, key=rsa_priv_pem,
// reference_uri="obj-1")` — this shares NO code with xmlsec1/OpenSSL. Then
// independently reconfirmed with
// `xmlsec1 --verify --lax-key-search --id-attr:ID urn:demo:Envelope out.xml`
// (the `--id-attr` hint is only needed so libxml2's XPointer engine treats
// `ID` as an XML ID attribute for signxml's own output; it does not change
// what bytes were signed). signxml emits a `<ds:KeyInfo><ds:KeyValue>` (not
// X509Certificate), which this module must simply ignore (never trust) —
// exercising that path with a REAL RSAKeyValue rather than the synthetic
// "Hello" blob `root.zig`'s own KeyInfo test uses.

const signxml_enveloped_rsa_sha256 =
    "<Envelope xmlns=\"urn:demo\" ID=\"obj-1\"><Data>Hello from signxml</Data>" ++
    "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>" ++
    "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" ++
    "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>" ++
    "<ds:Reference URI=\"#obj-1\"><ds:Transforms>" ++
    "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" ++
    "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>" ++
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" ++
    "<ds:DigestValue>QIeZU8zm4WKe0m+vevwn2pTBE9TpESKqJJB6G+kjcD0=</ds:DigestValue>" ++
    "</ds:Reference></ds:SignedInfo><ds:SignatureValue>" ++
    "CCxnR0BKeiXW/6iqtij7wVZF2nrIiLryBkZJgjeoBNg5F9HdBtI0ygY2rxnIvgsjMCBTs/MgOzscXvBmdCzxN2Kem5bwIFsQs/4W6kem7l7G91kkOggDUHRPL+AVmTZp8kOgwfq/KKfUITJ5ui0ociq/OMoji2li2oXzWgunWmMu8axM3IzGaHPpKeB7tQ/8uUp4xSOIYsPrcyAwWrjTugnwRPyfo/jvc7puRlh5DFHJ+IFzKRh8uiOnJGBB5m5BDYxj/FPxAZOhoJ+UUgcnGm0lCWz/VSAQp1adDEr6s4+voR3ItFxbAueL49XRge3iU94VTaB/QM5oknxQPcoS9w==" ++
    "</ds:SignatureValue><ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue>" ++
    "<ds:Modulus>2pnU5gYsnLbNQOVlNNV4yw5L2PiPalyE7u0/qs2dP3xTTDQO6nGGDcnLpHI4gv0EiXxsB4a7Rdg7bSY/cHTdEteAnxvs9aZszpgiWQidlAJseXsYwfoBm0FN3GFMCz2tnZ/EvkijcR/cHNCcunITewxtab21LAD5lh+RjSo7EUEmg7J54QUzPqk0Bp1+Jsgxmw3JjFVCGjoTMIiFe/w6cEVoDiBW992nyuYYfyDbUhaRy/7Tx5bArYaBhHB/HMT0N6Uxb4cJMb5fXh+DJ3G7SNbZJZ9N14N+j61K23rOhBnyShlA7AmUKb/ch+uw4YaMJoVfHP3/knYWH07p1rk+/w==</ds:Modulus>" ++
    "<ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></ds:Signature></Envelope>";

// ── fixture 6: xmlsec1-signed, attributes spanning TWO namespaces plus
// unprefixed ones — the external anchor for the C14N attribute SORT KEY ──────
//
// Every fixture above carries attributes from a single namespace (or none), so
// the `sortAttrs` key is under-determined by them: swapping it from
// (namespace-URI, local-name) to (local-name, namespace-URI) leaves all five
// green. This document is built so the two keys disagree. On the apex
// `<Envelope>`:
//
//   attribute      namespace URI   local
//   ID=…           ""              ID
//   zz=…           ""              zz
//   a:mm=…         urn:x:aa        mm
//   b:aa=…         urn:x:bb        aa
//
// (URI, local) → `ID zz a:mm b:aa`   ·   (local, URI) → `ID b:aa a:mm zz`
//
// libxml2, via `xmllint --exc-c14n`, emits the first of those, and xmlsec1's
// `DigestValue` below is over exactly those bytes — so this fixture pins the
// sort key to an implementation that shares no code with ours. Provenance
// (offline, never run by the suite):
//
// ```sh
// openssl genrsa -out priv.pem 2048 && openssl rsa -in priv.pem -pubout -out pub.pem
// xmlsec1 --sign --privkey-pem:mykey priv.pem --output out.xml tmpl.xml
// xmlsec1 --verify --lax-key-search --pubkey-pem pub.pem out.xml   # => OK
// ```
//
// The 2048-bit key is throwaway TEST MATERIAL; the private half was discarded.

const multi_ns_rsa_pub_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkwb0+ctwnT/MJXoywmsz
    \\c3M+68AjtFOU0KiVsWYHhqZJtAyW3usL2B911+JM09Ao8QCvu9egpMcghF+iRLO/
    \\l/3Zw6LIVMzIWga3toAWE+/viMhxdWp+kzkOWfP8uWGijC3mHnqXwQ6qJWGRgThK
    \\ykvtUxSa+dsNeB39+Lvdvjh4jdHOA3I20EYEtyxFFFJb8V5Z6oMeL+74khgrXI0c
    \\76pg9Im/uzS1Se+Na85T8W9ifk9sF+s3Ob/w635R8SaPq5CQqQiG7k/YLWwT8Xis
    \\hjHfIgHOBbAfbqwHlG3mq5tOmiTl0l3j19xrqbLY2ewrAsueHy9gXqeLWDJhRqwr
    \\wQIDAQAB
    \\-----END PUBLIC KEY-----
;

const multi_ns_signed_rsa_sha256 =
    \\<?xml version="1.0"?>
    \\<Envelope xmlns="urn:demo" xmlns:a="urn:x:aa" xmlns:b="urn:x:bb" ID="obj-multi-ns" zz="unprefixed-z" a:mm="in-a" b:aa="in-b">
    \\<Data b:zz="d-in-b" a:nn="d-in-a" k="d-plain">multi-namespace attribute ordering</Data>
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
    \\<ds:DigestValue>jnLutRldkyYXfU8gG41k1h2mI3jrtu8vkl5dTxMiiD8=</ds:DigestValue>
    \\</ds:Reference>
    \\</ds:SignedInfo>
    \\<ds:SignatureValue>MHNLZ1nxFhnRdlWJ9EmMYuJc5UrCgojgDunjKlsXcXgl5WZydALKfnJCHREIARA+
    \\PwmMmUjR1Efrc+FOUJsT1OMwUiGEfJDVF7IVT6AeRVTJVGeGldH1IJw2FI9zlBcT
    \\nhKVlmMVuAOhEZ350jw4lYH+dNzfnz2ed4p6eHegZchgxwltA6X+Qt0+3+qtVeI+
    \\3rqyXbG/cElDNBt1/RvLVIeNaFZKh55qoOl0mg+xwWMvixxnKUNkbqCgEh3CJ1lR
    \\aEzcjcuG4sTqBKw+nApd1nbCxLMSov2WK9BCQ0syLXCfuN91BKIbVfovFZu7BGTX
    \\dQJ+xYNvGrY8S5xvmz+GJQ==</ds:SignatureValue>
    \\<ds:KeyInfo><ds:KeyName>mykey</ds:KeyName></ds:KeyInfo>
    \\</ds:Signature>
    \\</Envelope>
;

test "EXTERNAL anchor: xmlsec1-signed document whose attributes span two namespaces pins the C14N sort key" {
    const a = testing.allocator;
    var doc = try xml.parse(a, multi_ns_signed_rsa_sha256, .{});
    defer doc.deinit();
    const sig = firstChild(doc.root, "Signature").?;
    const pk = try rsa.PublicKey.fromPem(multi_ns_rsa_pub_pem);
    var res = try verify(a, &doc, sig, .{ .key = .{ .rsa = pk } });
    defer res.deinit(a);
    try testing.expect(res.valid);
    try testing.expect(res.references[0].digest_valid);
}

test "EXTERNAL anchor: the multi-namespace fixture really does discriminate the two candidate sort keys" {
    // Guards the fixture itself: if someone edits the attribute set into
    // something the (local, URI) key would order identically, the anchor above
    // silently stops anchoring anything. Assert here, on the canonical bytes,
    // that the two keys disagree — so a future edit that neuters the fixture
    // fails loudly instead of passing.
    const a = testing.allocator;
    var doc = try xml.parse(a, multi_ns_signed_rsa_sha256, .{});
    defer doc.deinit();
    const sig = firstChild(doc.root, "Signature").?;
    const canon = try xmldsig.c14n.canonicalize(a, doc.root, .{ .mode = .exclusive, .omit = sig });
    defer a.free(canon);

    // The byte order libxml2 produced (see the provenance block above).
    const by_uri_then_local = "ID=\"obj-multi-ns\" zz=\"unprefixed-z\" a:mm=\"in-a\" b:aa=\"in-b\"";
    // What the (local, URI) key would have produced instead.
    const by_local_then_uri = "ID=\"obj-multi-ns\" b:aa=\"in-b\" a:mm=\"in-a\" zz=\"unprefixed-z\"";
    try testing.expect(!std.mem.eql(u8, by_uri_then_local, by_local_then_uri));
    try testing.expect(std.mem.indexOf(u8, canon, by_uri_then_local) != null);
    try testing.expect(std.mem.indexOf(u8, canon, by_local_then_uri) == null);
}

test "EXTERNAL anchor: fixture count canary — 6 genuinely external xmlsec1/signxml-signed documents" {
    // If this drops, a fixture was deleted/disabled rather than fixed — the
    // count itself is the guard against silent coverage loss.
    const fixtures = [_][]const u8{
        enveloped_signed_rsa_sha256,
        enveloped_tampered_rsa_sha256,
        enveloping_signed_rsa_sha256,
        ecdsa_signed_p256_sha256,
        signxml_enveloped_rsa_sha256,
        multi_ns_signed_rsa_sha256,
    };
    try testing.expectEqual(@as(usize, 6), fixtures.len);
    for (fixtures) |f| try testing.expect(f.len > 100);
}

test "EXTERNAL anchor: signxml-signed enveloped RSA-SHA256 accepted (independent of xmlsec1/OpenSSL)" {
    const a = testing.allocator;
    var doc = try xml.parse(a, signxml_enveloped_rsa_sha256, .{});
    defer doc.deinit();
    const sig = firstChild(doc.root, "Signature").?;
    var res = try verify(a, &doc, sig, .{ .key = .{ .rsa = try extRsaKey() } });
    defer res.deinit(a);
    try testing.expect(res.valid);
    try testing.expect(res.references[0].digest_valid);
    // signxml's KeyInfo carries a real RSAKeyValue, not X509Certificate — our
    // trust model never reads it, and we don't even parse RSAKeyValue, so no
    // cert is surfaced.
    try testing.expect(res.x509_cert_der == null);
}
