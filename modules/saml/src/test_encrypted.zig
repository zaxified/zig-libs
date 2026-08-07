// SPDX-License-Identifier: MIT
//! End-to-end tests for the eIDAS **encrypt profile**: a
//! `<saml:EncryptedAssertion>` is transparently decrypted (via `xmlenc`) and
//! then runs through the SAME signature-verify + XSW + validation path a
//! cleartext assertion does (decrypt-then-verify).
//!
//! Fixture construction: we take the module's GENUINELY-signed assertion (the
//! openssl+lxml fixture in `fixtures.zig`), make it self-contained (the bare
//! assertion inherits `xmlns:saml` from the Response, so we declare it on the
//! Assertion — Exclusive-C14N is position-independent, so the existing IdP
//! signature stays valid over it), then ENCRYPT those exact signed bytes into a
//! `<xenc:EncryptedData>` (AES-256-GCM content key wrapped with RSA-OAEP under a
//! locally-generated SP key) and wrap that in `<saml:EncryptedAssertion>` inside
//! a Response. Decrypting recovers the signed assertion verbatim, whose IdP
//! signature then verifies — proving decrypt → verify → extract end-to-end.
//!
//! These reuse the same encryption primitives `xmlenc`'s own round-trip tests
//! use; the byte-exact anchors live in `xmlenc` (NIST/RFC KATs) and `xmldsig`
//! (the openssl/lxml signature fixture). The SP RSA key is test material only.

const std = @import("std");
const testing = std.testing;
const xml = @import("xml");
const rsa = @import("rsa");
const xmlenc = @import("xmlenc");
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const encutil = @import("test_encutil.zig");

const Sha1 = std.crypto.hash.Sha1;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const xenc_ns = "http://www.w3.org/2001/04/xmlenc#";
const ds_ns = "http://www.w3.org/2000/09/xmldsig#";
const saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion";

const sig_open = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">";
const sig_close = "</ds:Signature>";
const asrt_open = "<saml:Assertion ID=";
const asrt_close = "</saml:Assertion>";
const asrt_open_selfcontained =
    "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=";

// ── generic test helpers ─────────────────────────────────────────────────────

fn block(hay: []const u8, open: []const u8, close: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, hay, open).?;
    const j = std.mem.indexOfPos(u8, hay, i, close).? + close.len;
    return hay[i..j];
}

/// A 1024-bit SP key, generated deterministically (test material only).
fn makeSpKey(seed: u64) !rsa.KeyPair {
    var prng = std.Random.DefaultPrng.init(seed);
    return rsa.generate(prng.random(), 1024, 65537);
}

fn b64(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try alloc.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data);
    return out;
}

fn gcmEncrypt256(alloc: std.mem.Allocator, key: [32]u8, msg: []const u8) ![]u8 {
    const iv = [_]u8{0x22} ** 12;
    const total = 12 + msg.len + 16;
    const out = try alloc.alloc(u8, total);
    @memcpy(out[0..12], &iv);
    var tag: [16]u8 = undefined;
    Aes256Gcm.encrypt(out[12 .. 12 + msg.len], &tag, msg, "", iv, key);
    @memcpy(out[12 + msg.len ..], &tag);
    return out;
}

fn oaepWrapCek(alloc: std.mem.Allocator, pk: rsa.PublicKey, cek: []const u8) ![]u8 {
    var prng = std.Random.DefaultPrng.init(0xABCDEF);
    const k = (pk.n.bits() + 7) / 8;
    const buf = try alloc.alloc(u8, k);
    defer alloc.free(buf);
    const ct = try rsa.encryptOaep(pk, Sha1, prng.random(), cek, "", buf);
    return alloc.dupe(u8, ct);
}

// ── fixture builders ─────────────────────────────────────────────────────────

/// The genuine signed assertion, made self-contained (declares its own
/// `xmlns:saml`). The IdP signature stays valid: Exclusive-C14N emits
/// `xmlns:saml` at the assertion apex whether declared here or inherited.
fn selfContainedAssertion(alloc: std.mem.Allocator) ![]u8 {
    const asrt = block(fx.signed_response, asrt_open, asrt_close);
    return std.mem.replaceOwned(u8, alloc, asrt, asrt_open, asrt_open_selfcontained);
}

/// Wrap arbitrary plaintext octets as an AES-256-GCM / RSA-OAEP
/// `<saml:EncryptedAssertion>` decryptable by `pk`'s private half.
fn encryptedAssertionXml(alloc: std.mem.Allocator, pk: rsa.PublicKey, plaintext: []const u8) ![]u8 {
    const cek = [_]u8{0xC5} ** 32;
    const wrapped = try oaepWrapCek(alloc, pk, &cek);
    defer alloc.free(wrapped);
    const content = try gcmEncrypt256(alloc, cek, plaintext);
    defer alloc.free(content);
    const cek_b64 = try b64(alloc, wrapped);
    defer alloc.free(cek_b64);
    const content_b64 = try b64(alloc, content);
    defer alloc.free(content_b64);

    return std.fmt.allocPrint(alloc,
        \\<saml:EncryptedAssertion xmlns:saml="{s}"><xenc:EncryptedData xmlns:xenc="{s}" xmlns:ds="{s}" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{s}rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>
    , .{ saml_ns, xenc_ns, ds_ns, xenc_ns, cek_b64, content_b64 });
}

/// The Response with its cleartext assertion swapped for `enc_xml`.
fn responseWithEncrypted(alloc: std.mem.Allocator, enc_xml: []const u8) ![]u8 {
    const asrt = block(fx.signed_response, asrt_open, asrt_close);
    return std.mem.replaceOwned(u8, alloc, fx.signed_response, asrt, enc_xml);
}

/// A Response carrying an EncryptedAssertion of the pristine signed assertion,
/// decryptable by `pk`. Caller frees.
fn encryptedResponse(alloc: std.mem.Allocator, pk: rsa.PublicKey) ![]u8 {
    const plaintext = try selfContainedAssertion(alloc);
    defer alloc.free(plaintext);
    const enc_xml = try encryptedAssertionXml(alloc, pk, plaintext);
    defer alloc.free(enc_xml);
    return responseWithEncrypted(alloc, enc_xml);
}

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

// ── the headline positive control ────────────────────────────────────────────

test "encrypted flow: decrypt -> verify -> extract yields the SAME AuthnResult as cleartext" {
    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_E0DE);

    // Cleartext path.
    var clear = try saml.consumeResponseXml(alloc, fx.signed_response, baseConfig(fx.t_valid));
    defer clear.deinit();

    // Encrypted path, same config plus the SP decryption key.
    const enc_resp = try encryptedResponse(alloc, kp.public_key);
    defer alloc.free(enc_resp);
    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = kp.secret_key;
    var enc = try saml.consumeResponseXml(alloc, enc_resp, cfg);
    defer enc.deinit();

    // Identical trusted outcome.
    try testing.expectEqualStrings(clear.name_id, enc.name_id);
    try testing.expectEqualStrings("alice@example.org", enc.name_id);
    try testing.expectEqualStrings(clear.name_id_format.?, enc.name_id_format.?);
    try testing.expectEqualStrings(clear.name_id_sp_qualifier.?, enc.name_id_sp_qualifier.?);
    try testing.expectEqualStrings(clear.session_index.?, enc.session_index.?);
    try testing.expectEqualStrings(clear.authn_context_class_ref.?, enc.authn_context_class_ref.?);
    try testing.expectEqualStrings(clear.assertion_id, enc.assertion_id);
    try testing.expectEqual(clear.session_not_on_or_after, enc.session_not_on_or_after);

    const cg = clear.attribute("groups").?;
    const eg = enc.attribute("groups").?;
    try testing.expectEqual(cg.len, eg.len);
    try testing.expectEqualStrings(cg[0], eg[0]);
    try testing.expectEqualStrings(cg[1], eg[1]);
    try testing.expectEqualStrings(clear.attribute("email").?[0], enc.attribute("email").?[0]);
}

test "Z1: the decrypted assertion body does not survive in any block consumeResponseXml releases" {
    // ReleaseFast ONLY — see `test_encutil.FreeScanner` for why the safe lanes
    // cannot observe a heap wipe at all.
    if (@import("builtin").mode != .ReleaseFast) return error.SkipZigTest;

    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_2E20);
    const enc_resp = try encryptedResponse(alloc, kp.public_key);
    defer alloc.free(enc_resp);

    // Markup that exists only in the DECRYPTED `<saml:Assertion>` octets: the
    // Response on the wire carries the ciphertext instead of the assertion, and
    // the extracted `AuthnResult` copies the NameID's text content without the
    // surrounding tags. So a hit can come from nothing but a module-owned copy
    // of the plaintext — `saml`'s own decrypt buffer, or the canonical form
    // `xmldsig.verify` builds from it while checking the IdP signature.
    const needle = ">alice@example.org</saml:NameID>";
    try testing.expect(std.mem.indexOf(u8, enc_resp, needle) == null);

    var scan = encutil.FreeScanner{ .child = alloc, .needle = needle };
    const sa = scan.allocator();

    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = kp.secret_key;
    var res = try saml.consumeResponseXml(sa, enc_resp, cfg);

    // The decryption + signature verification really happened, and the scanner
    // really watched frees go by.
    try testing.expectEqualStrings("alice@example.org", res.name_id);
    try testing.expect(scan.frees_seen > 0);
    try testing.expect(!scan.leaked_plaintext);

    // The result arena is the CALLER's copy (§2.1 Z2) — tear it down only after
    // the assertion above, so its release cannot colour the verdict.
    res.deinit();
}

test "encrypted flow: POST binding (base64) decodes then decrypts + verifies" {
    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_E0DE);
    const enc_resp = try encryptedResponse(alloc, kp.public_key);
    defer alloc.free(enc_resp);

    const enc = std.base64.standard.Encoder;
    const field = try alloc.alloc(u8, enc.calcSize(enc_resp.len));
    defer alloc.free(field);
    _ = enc.encode(field, enc_resp);

    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = kp.secret_key;
    var res = try saml.consumeResponse(alloc, field, cfg);
    defer res.deinit();
    try testing.expectEqualStrings("alice@example.org", res.name_id);
}

// ── teeth (each with the positive control above) ─────────────────────────────

test "teeth: encrypted assertion but no sp_decrypt_key -> EncryptedAssertionUnsupported (old behavior)" {
    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_E0DE);
    const enc_resp = try encryptedResponse(alloc, kp.public_key);
    defer alloc.free(enc_resp);
    // baseConfig leaves sp_decrypt_key null -> the opt-out refusal is preserved.
    try testing.expectError(
        error.EncryptedAssertionUnsupported,
        saml.consumeResponseXml(alloc, enc_resp, baseConfig(fx.t_valid)),
    );
}

test "teeth: wrong SP decryption key -> AssertionDecryptionFailed" {
    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_E0DE);
    const other = try makeSpKey(0xDEAD_BEEF); // different modulus
    const enc_resp = try encryptedResponse(alloc, kp.public_key);
    defer alloc.free(enc_resp);
    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = other.secret_key;
    try testing.expectError(error.AssertionDecryptionFailed, saml.consumeResponseXml(alloc, enc_resp, cfg));
}

test "teeth: tamper the assertion BEFORE encrypting -> caught by signature verify AFTER decryption" {
    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_E0DE);

    // Change the signed subject inside the plaintext, then encrypt THAT. The
    // ciphertext is well-formed and decrypts cleanly, but the recovered
    // assertion's IdP signature no longer matches -> decrypt-then-verify bites.
    const plaintext = try selfContainedAssertion(alloc);
    defer alloc.free(plaintext);
    const tampered = try std.mem.replaceOwned(u8, alloc, plaintext, "alice@example.org", "mallory@evil.example");
    defer alloc.free(tampered);
    const enc_xml = try encryptedAssertionXml(alloc, kp.public_key, tampered);
    defer alloc.free(enc_xml);
    const enc_resp = try responseWithEncrypted(alloc, enc_xml);
    defer alloc.free(enc_resp);

    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = kp.secret_key;
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(alloc, enc_resp, cfg));
}

test "teeth: a cleartext AND an encrypted assertion together -> MultipleAssertions (exactly-one spans both kinds)" {
    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_E0DE);
    const plaintext = try selfContainedAssertion(alloc);
    defer alloc.free(plaintext);
    const enc_xml = try encryptedAssertionXml(alloc, kp.public_key, plaintext);
    defer alloc.free(enc_xml);
    // Keep the cleartext assertion and ALSO inject an encrypted one.
    const injected = try std.fmt.allocPrint(alloc, "</samlp:Status>{s}", .{enc_xml});
    defer alloc.free(injected);
    const resp = try std.mem.replaceOwned(u8, alloc, fx.signed_response, "</samlp:Status>", injected);
    defer alloc.free(resp);

    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = kp.secret_key;
    try testing.expectError(error.MultipleAssertions, saml.consumeResponseXml(alloc, resp, cfg));
}

test "teeth: two encrypted assertions -> MultipleAssertions" {
    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_E0DE);
    const plaintext = try selfContainedAssertion(alloc);
    defer alloc.free(plaintext);
    const enc_xml = try encryptedAssertionXml(alloc, kp.public_key, plaintext);
    defer alloc.free(enc_xml);
    const one = try responseWithEncrypted(alloc, enc_xml);
    defer alloc.free(one);
    // Inject a second encrypted assertion just after the first.
    const doubled = try std.fmt.allocPrint(alloc, "{s}{s}", .{ enc_xml, enc_xml });
    defer alloc.free(doubled);
    const two = try std.mem.replaceOwned(u8, alloc, one, enc_xml, doubled);
    defer alloc.free(two);

    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = kp.secret_key;
    try testing.expectError(error.MultipleAssertions, saml.consumeResponseXml(alloc, two, cfg));
}

test "teeth: classic wrap INSIDE the decrypted assertion -> SignatureWrappingDetected" {
    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_E0DE);

    // Build an evil decrypted assertion (its own new ID) that carries a COPY of
    // the legit signature (which references #assertion_id) and buries the legit,
    // signature-stripped assertion (which still has ID=assertion_id). Exclusive
    // C14N makes the buried assertion's digest match regardless of position, so
    // the signature VERIFIES — but it covers the buried element, not the evil
    // root we would consume. The inner-document pointer-pin catches it.
    const selfc = try selfContainedAssertion(alloc);
    defer alloc.free(selfc);
    const legit_sig = block(selfc, sig_open, sig_close);
    const legit_nosig = try std.mem.replaceOwned(u8, alloc, selfc, legit_sig, "");
    defer alloc.free(legit_nosig);

    const evil = try std.fmt.allocPrint(alloc, "<saml:Assertion xmlns:saml=\"{s}\" ID=\"_evilwrap\" Version=\"2.0\" IssueInstant=\"2024-06-01T12:00:00Z\">" ++
        "<saml:Issuer>https://idp.example.org/saml</saml:Issuer>{s}" ++
        "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">attacker@evil.example</saml:NameID>" ++
        "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" ++
        "<saml:SubjectConfirmationData NotOnOrAfter=\"2024-06-01T12:05:00Z\" Recipient=\"https://sp.example.org/acs\" InResponseTo=\"req-9988776655\"/>" ++
        "</saml:SubjectConfirmation></saml:Subject>" ++
        "<saml:Conditions NotBefore=\"2024-06-01T11:59:00Z\" NotOnOrAfter=\"2024-06-01T12:05:00Z\">" ++
        "<saml:AudienceRestriction><saml:Audience>https://sp.example.org/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>" ++
        "<wrapper>{s}</wrapper></saml:Assertion>", .{ saml_ns, legit_sig, legit_nosig });
    defer alloc.free(evil);

    const enc_xml = try encryptedAssertionXml(alloc, kp.public_key, evil);
    defer alloc.free(enc_xml);
    const enc_resp = try responseWithEncrypted(alloc, enc_xml);
    defer alloc.free(enc_resp);

    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = kp.secret_key;
    try testing.expectError(error.SignatureWrappingDetected, saml.consumeResponseXml(alloc, enc_resp, cfg));
}

test "teeth: decrypted assertion with signature Reference repointed to a decoy -> SignatureInvalid" {
    const alloc = testing.allocator;
    const kp = try makeSpKey(0x5A11_E0DE);
    // Repoint the Reference URI before encrypting: corrupts SignedInfo -> invalid.
    const plaintext = try selfContainedAssertion(alloc);
    defer alloc.free(plaintext);
    const decoy = try std.mem.replaceOwned(u8, alloc, plaintext, "URI=\"#" ++ fx.assertion_id ++ "\"", "URI=\"#_decoy\"");
    defer alloc.free(decoy);
    const enc_xml = try encryptedAssertionXml(alloc, kp.public_key, decoy);
    defer alloc.free(enc_xml);
    const enc_resp = try responseWithEncrypted(alloc, enc_xml);
    defer alloc.free(enc_resp);

    var cfg = baseConfig(fx.t_valid);
    cfg.sp_decrypt_key = kp.secret_key;
    try testing.expectError(error.SignatureInvalid, saml.consumeResponseXml(alloc, enc_resp, cfg));
}
