// SPDX-License-Identifier: MIT
//! Round-trip + teeth tests for xmlenc decryption.
//!
//! Fixtures are CONSTRUCTED locally: we generate an RSA keypair, encrypt a CEK
//! (RSAES-OAEP or RSAES-PKCS1-v1_5), encrypt a plaintext `<saml:Assertion>`
//! with AES-GCM/CBC, wrap the two ciphertexts in the standard xmlenc XML, then
//! assert exact plaintext recovery through the public `decryptData` path. These
//! are self-consistency + interop-shape tests, NOT external byte-exact KATs —
//! the byte-exact anchors are the CBC core (NIST SP800-38A) and AES key unwrap
//! (RFC 3394) in root.zig, plus the sibling `rsa` module's own OAEP/OpenSSL
//! KATs. No real external SAML EncryptedAssertion fixture was available.

const std = @import("std");
const xml = @import("xml");
const rsa = @import("rsa");
const xmlenc = @import("root.zig");

const aes = std.crypto.core.aes;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

const xenc_ns = "http://www.w3.org/2001/04/xmlenc#";
const xenc11_ns = "http://www.w3.org/2009/xmlenc11#";
const ds_ns = "http://www.w3.org/2000/09/xmldsig#";

const plaintext_assertion =
    "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " ++
    "ID=\"_a1b2\" Version=\"2.0\">the recovered assertion body</saml:Assertion>";

// A single 1024-bit key, generated once per test run with a fixed seed (test
// keys only — deterministic generation is explicitly allowed for tests).
fn makeKey() !rsa.KeyPair {
    var prng = std.Random.DefaultPrng.init(0x5A_11_E0_DE);
    return rsa.generate(prng.random(), 1024, 65537);
}

fn b64(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try alloc.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data);
    return out;
}

// AES-CBC encrypt with XML-Enc padding: prepend a fixed IV, pad to the block
// size (final byte = pad length), CBC-encrypt.
fn cbcEncrypt(alloc: std.mem.Allocator, comptime Aes: type, key: anytype, msg: []const u8) ![]u8 {
    const bs = 16;
    const pad = bs - (msg.len % bs); // 1..bs
    const total = bs + msg.len + pad;
    const out = try alloc.alloc(u8, total);
    const iv = [_]u8{0x11} ** bs;
    @memcpy(out[0..bs], &iv);
    @memcpy(out[bs .. bs + msg.len], msg);
    // pad bytes: arbitrary except the last is the count.
    for (out[bs + msg.len .. total - 1]) |*p| p.* = 0;
    out[total - 1] = @intCast(pad);

    const ctx = Aes.initEnc(key);
    var prev = iv;
    var i: usize = bs;
    while (i < total) : (i += bs) {
        var block: [bs]u8 = out[i..][0..bs].*;
        for (0..bs) |j| block[j] ^= prev[j];
        var c: [bs]u8 = undefined;
        ctx.encrypt(&c, &block);
        @memcpy(out[i..][0..bs], &c);
        prev = c;
    }
    return out;
}

fn gcmEncrypt(alloc: std.mem.Allocator, comptime Gcm: type, key: anytype, msg: []const u8) ![]u8 {
    const iv = [_]u8{0x22} ** 12;
    const total = 12 + msg.len + 16;
    const out = try alloc.alloc(u8, total);
    @memcpy(out[0..12], &iv);
    var tag: [16]u8 = undefined;
    Gcm.encrypt(out[12 .. 12 + msg.len], &tag, msg, "", iv, key);
    @memcpy(out[12 + msg.len ..], &tag);
    return out;
}

fn oaepWrapCek(alloc: std.mem.Allocator, comptime Hash: type, pk: rsa.PublicKey, cek: []const u8) ![]u8 {
    var prng = std.Random.DefaultPrng.init(0xABCDEF);
    const k = (pk.n.bits() + 7) / 8;
    const buf = try alloc.alloc(u8, k);
    defer alloc.free(buf);
    const ct = try rsa.encryptOaep(pk, Hash, prng.random(), cek, "", buf);
    return alloc.dupe(u8, ct);
}

fn buildEncryptedData(
    alloc: std.mem.Allocator,
    content_alg: []const u8,
    key_alg: []const u8,
    wrapped_cek_b64: []const u8,
    content_b64: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(alloc,
        \\<xenc:EncryptedData xmlns:xenc="{s}" xmlns:ds="{s}" xmlns:x11="{s}" Type="http://www.w3.org/2001/04/xmlenc#Element">
        \\  <xenc:EncryptionMethod Algorithm="{s}"/>
        \\  <ds:KeyInfo>
        \\    <xenc:EncryptedKey>
        \\      <xenc:EncryptionMethod Algorithm="{s}"/>
        \\      <xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>
        \\    </xenc:EncryptedKey>
        \\  </ds:KeyInfo>
        \\  <xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>
        \\</xenc:EncryptedData>
    , .{ xenc_ns, ds_ns, xenc11_ns, content_alg, key_alg, wrapped_cek_b64, content_b64 });
}

// End-to-end helper: build the doc, parse, decrypt, return owned plaintext.
fn roundTrip(
    alloc: std.mem.Allocator,
    content_alg: []const u8,
    key_alg: []const u8,
    wrapped_cek: []const u8,
    content: []const u8,
    sk: rsa.SecretKey,
    options: xmlenc.Options,
) ![]u8 {
    const cek_b64 = try b64(alloc, wrapped_cek);
    defer alloc.free(cek_b64);
    const content_b64 = try b64(alloc, content);
    defer alloc.free(content_b64);
    const doc_src = try buildEncryptedData(alloc, content_alg, key_alg, cek_b64, content_b64);
    defer alloc.free(doc_src);
    var doc = try xml.parse(alloc, doc_src, .{});
    defer doc.deinit();
    return xmlenc.decryptData(alloc, doc.root, sk, options);
}

test "round-trip: OAEP-mgf1p (SHA1) + AES-256-GCM" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0xC5} ** 32;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);

    const out = try roundTrip(a, xenc11_ns ++ "aes256-gcm", xenc_ns ++ "rsa-oaep-mgf1p", wrapped, content, kp.secret_key, .{});
    defer a.free(out);
    try std.testing.expectEqualStrings(plaintext_assertion, out);
}

test "round-trip: OAEP-mgf1p (SHA1) + AES-128-GCM" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0x7A} ** 16;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes128Gcm, cek, plaintext_assertion);
    defer a.free(content);

    const out = try roundTrip(a, xenc11_ns ++ "aes128-gcm", xenc_ns ++ "rsa-oaep-mgf1p", wrapped, content, kp.secret_key, .{});
    defer a.free(out);
    try std.testing.expectEqualStrings(plaintext_assertion, out);
}

test "round-trip: OAEP-mgf1p (SHA1) + AES-256-CBC" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0x3B} ** 32;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try cbcEncrypt(a, aes.Aes256, cek, plaintext_assertion);
    defer a.free(content);

    const out = try roundTrip(a, xenc_ns ++ "aes256-cbc", xenc_ns ++ "rsa-oaep-mgf1p", wrapped, content, kp.secret_key, .{});
    defer a.free(out);
    try std.testing.expectEqualStrings(plaintext_assertion, out);
}

test "round-trip: OAEP-mgf1p (SHA1) + AES-128-CBC" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0x9F} ** 16;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try cbcEncrypt(a, aes.Aes128, cek, plaintext_assertion);
    defer a.free(content);

    const out = try roundTrip(a, xenc_ns ++ "aes128-cbc", xenc_ns ++ "rsa-oaep-mgf1p", wrapped, content, kp.secret_key, .{});
    defer a.free(out);
    try std.testing.expectEqualStrings(plaintext_assertion, out);
}

test "round-trip: xenc11 rsa-oaep (SHA256) + AES-256-GCM" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0x42} ** 32;
    const wrapped = try oaepWrapCek(a, Sha256, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);

    // rsa-oaep with explicit SHA-256 DigestMethod + mgf1sha256 MGF.
    const key_alg = xenc11_ns ++ "rsa-oaep";
    const cek_b64 = try b64(a, wrapped);
    defer a.free(cek_b64);
    const content_b64 = try b64(a, content);
    defer a.free(content_b64);
    const doc_src = try std.fmt.allocPrint(a,
        \\<xenc:EncryptedData xmlns:xenc="{s}" xmlns:ds="{s}" xmlns:x11="{s}">
        \\  <xenc:EncryptionMethod Algorithm="{s}aes256-gcm"/>
        \\  <ds:KeyInfo>
        \\    <xenc:EncryptedKey>
        \\      <xenc:EncryptionMethod Algorithm="{s}">
        \\        <ds:DigestMethod Algorithm="{s}sha256"/>
        \\        <x11:MGF Algorithm="{s}mgf1sha256"/>
        \\      </xenc:EncryptionMethod>
        \\      <xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>
        \\    </xenc:EncryptedKey>
        \\  </ds:KeyInfo>
        \\  <xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>
        \\</xenc:EncryptedData>
    , .{ xenc_ns, ds_ns, xenc11_ns, xenc11_ns, key_alg, xenc_ns, xenc11_ns, cek_b64, content_b64 });
    defer a.free(doc_src);
    var doc = try xml.parse(a, doc_src, .{});
    defer doc.deinit();
    const out = try xmlenc.decryptData(a, doc.root, kp.secret_key, .{});
    defer a.free(out);
    try std.testing.expectEqualStrings(plaintext_assertion, out);
}

test "round-trip via EncryptedAssertion wrapper convenience" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0x11} ** 32;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);
    const cek_b64 = try b64(a, wrapped);
    defer a.free(cek_b64);
    const content_b64 = try b64(a, content);
    defer a.free(content_b64);
    const ed = try buildEncryptedData(a, xenc11_ns ++ "aes256-gcm", xenc_ns ++ "rsa-oaep-mgf1p", cek_b64, content_b64);
    defer a.free(ed);
    const wrapper = try std.fmt.allocPrint(a, "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{s}</saml:EncryptedAssertion>", .{ed});
    defer a.free(wrapper);
    var doc = try xml.parse(a, wrapper, .{});
    defer doc.deinit();
    const out = try xmlenc.decryptAssertion(a, doc.root, kp.secret_key, .{});
    defer a.free(out);
    try std.testing.expectEqualStrings(plaintext_assertion, out);
}

test "round-trip: kw-aes256 symmetric key wrap + AES-256-GCM" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const kek = [_]u8{0x5A} ** 32;
    const cek = [_]u8{0x99} ** 32;
    // Wrap the CEK with RFC 3394 under the KEK (build the wrapped blob directly).
    var wrapped: [40]u8 = undefined;
    kwWrap(&kek, &cek, &wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);
    const out = try roundTrip(a, xenc11_ns ++ "aes256-gcm", xenc_ns ++ "kw-aes256", &wrapped, content, kp.secret_key, .{ .kek = &kek });
    defer a.free(out);
    try std.testing.expectEqualStrings(plaintext_assertion, out);
}

test "round-trip: RSAES-PKCS1-v1_5 gated by allow_weak_rsa15" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0x77} ** 32;
    const wrapped = try v15WrapCek(a, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);

    // Without opt-in -> refused.
    try std.testing.expectError(error.WeakRsa15NotAllowed, roundTrip(a, xenc11_ns ++ "aes256-gcm", xenc_ns ++ "rsa-1_5", wrapped, content, kp.secret_key, .{}));

    // With opt-in -> recovers.
    const out = try roundTrip(a, xenc11_ns ++ "aes256-gcm", xenc_ns ++ "rsa-1_5", wrapped, content, kp.secret_key, .{ .allow_weak_rsa15 = true });
    defer a.free(out);
    try std.testing.expectEqualStrings(plaintext_assertion, out);
}

// ── teeth (with positive controls above) ────────────────────────────────────

test "teeth: GCM tag tampering -> DecryptionError" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0xC5} ** 32;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);
    content[content.len - 1] ^= 0x80; // flip a tag bit
    try std.testing.expectError(error.DecryptionError, roundTrip(a, xenc11_ns ++ "aes256-gcm", xenc_ns ++ "rsa-oaep-mgf1p", wrapped, content, kp.secret_key, .{}));
}

test "teeth: CBC bad padding -> DecryptionError" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0x3B} ** 32;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try cbcEncrypt(a, aes.Aes256, cek, plaintext_assertion);
    defer a.free(content);
    // Corrupt the final ciphertext block so the recovered pad length is invalid
    // with overwhelming probability.
    content[content.len - 1] ^= 0xFF;
    content[content.len - 2] ^= 0xAA;
    try std.testing.expectError(error.DecryptionError, roundTrip(a, xenc_ns ++ "aes256-cbc", xenc_ns ++ "rsa-oaep-mgf1p", wrapped, content, kp.secret_key, .{}));
}

test "teeth: unknown content algorithm -> UnsupportedAlgorithm" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0xC5} ** 32;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);
    try std.testing.expectError(error.UnsupportedAlgorithm, roundTrip(a, "http://example.com/aes999", xenc_ns ++ "rsa-oaep-mgf1p", wrapped, content, kp.secret_key, .{}));
}

test "teeth: unknown key-transport algorithm -> UnsupportedAlgorithm" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0xC5} ** 32;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);
    try std.testing.expectError(error.UnsupportedAlgorithm, roundTrip(a, xenc11_ns ++ "aes256-gcm", "http://example.com/kt", wrapped, content, kp.secret_key, .{}));
}

test "teeth: AES-192 content algorithm -> UnsupportedAlgorithm (std gap)" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const cek = [_]u8{0xC5} ** 32;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);
    try std.testing.expectError(error.UnsupportedAlgorithm, roundTrip(a, xenc_ns ++ "aes192-cbc", xenc_ns ++ "rsa-oaep-mgf1p", wrapped, content, kp.secret_key, .{}));
}

test "teeth: wrong private key -> DecryptionError" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    // A different key (different seed) whose modulus differs.
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);
    const other = try rsa.generate(prng.random(), 1024, 65537);
    const cek = [_]u8{0xC5} ** 32;
    const wrapped = try oaepWrapCek(a, Sha1, kp.public_key, &cek);
    defer a.free(wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);
    try std.testing.expectError(error.DecryptionError, roundTrip(a, xenc11_ns ++ "aes256-gcm", xenc_ns ++ "rsa-oaep-mgf1p", wrapped, content, other.secret_key, .{}));
}

test "teeth: CipherReference rejected" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const doc_src =
        "<xenc:EncryptedData xmlns:xenc=\"" ++ xenc_ns ++ "\" xmlns:ds=\"" ++ ds_ns ++ "\">" ++
        "<xenc:EncryptionMethod Algorithm=\"" ++ xenc11_ns ++ "aes256-gcm\"/>" ++
        "<ds:KeyInfo><xenc:EncryptedKey>" ++
        "<xenc:EncryptionMethod Algorithm=\"" ++ xenc_ns ++ "rsa-oaep-mgf1p\"/>" ++
        "<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData>" ++
        "</xenc:EncryptedKey></ds:KeyInfo>" ++
        "<xenc:CipherData><xenc:CipherReference URI=\"http://evil/\"/></xenc:CipherData>" ++
        "</xenc:EncryptedData>";
    var doc = try xml.parse(a, doc_src, .{});
    defer doc.deinit();
    try std.testing.expectError(error.CipherReferenceUnsupported, xmlenc.decryptData(a, doc.root, kp.secret_key, .{}));
}

test "teeth: truncated CipherValue (not base64) -> MalformedStructure" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const doc_src =
        "<xenc:EncryptedData xmlns:xenc=\"" ++ xenc_ns ++ "\" xmlns:ds=\"" ++ ds_ns ++ "\">" ++
        "<xenc:EncryptionMethod Algorithm=\"" ++ xenc11_ns ++ "aes256-gcm\"/>" ++
        "<ds:KeyInfo><xenc:EncryptedKey>" ++
        "<xenc:EncryptionMethod Algorithm=\"" ++ xenc_ns ++ "rsa-oaep-mgf1p\"/>" ++
        "<xenc:CipherData><xenc:CipherValue>@@@notbase64@@@</xenc:CipherValue></xenc:CipherData>" ++
        "</xenc:EncryptedKey></ds:KeyInfo>" ++
        "<xenc:CipherData><xenc:CipherValue>QUJD</xenc:CipherValue></xenc:CipherData>" ++
        "</xenc:EncryptedData>";
    var doc = try xml.parse(a, doc_src, .{});
    defer doc.deinit();
    try std.testing.expectError(error.MalformedStructure, xmlenc.decryptData(a, doc.root, kp.secret_key, .{}));
}

test "teeth: kw-aes* without kek -> KekNotProvided" {
    const a = std.testing.allocator;
    const kp = try makeKey();
    const kek = [_]u8{0x5A} ** 32;
    const cek = [_]u8{0x99} ** 32;
    var wrapped: [40]u8 = undefined;
    kwWrap(&kek, &cek, &wrapped);
    const content = try gcmEncrypt(a, Aes256Gcm, cek, plaintext_assertion);
    defer a.free(content);
    try std.testing.expectError(error.KekNotProvided, roundTrip(a, xenc11_ns ++ "aes256-gcm", xenc_ns ++ "kw-aes256", &wrapped, content, kp.secret_key, .{}));
}

// ── local encryption helpers for the v1.5 and key-wrap fixtures ─────────────

fn v15WrapCek(alloc: std.mem.Allocator, pk: rsa.PublicKey, cek: []const u8) ![]u8 {
    // RSAES-PKCS1-v1_5 encode: EM = 0x00 02 PS(nonzero,>=8) 00 M, then RSAEP.
    const k = (pk.n.bits() + 7) / 8;
    std.debug.assert(k == 128); // 1024-bit test key
    var em: [128]u8 = undefined;
    em[0] = 0x00;
    em[1] = 0x02;
    const ps_len = k - cek.len - 3;
    var prng = std.Random.DefaultPrng.init(0x1234);
    for (em[2 .. 2 + ps_len]) |*p| {
        var v: u8 = 0;
        while (v == 0) v = prng.random().int(u8);
        p.* = v;
    }
    em[2 + ps_len] = 0x00;
    @memcpy(em[2 + ps_len + 1 ..], cek);
    const ct = try rsa.rsaep(128, em, pk);
    return alloc.dupe(u8, &ct);
}

// RFC 3394 wrap (encrypt side, mirror of root.zig's unwrap core) — test-only.
fn kwWrap(kek: []const u8, plaintext: []const u8, out: []u8) void {
    const n = plaintext.len / 8;
    var a: [8]u8 = .{ 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
    @memcpy(out[8..], plaintext);
    const r = out[8..];
    var j: usize = 0;
    while (j < 6) : (j += 1) {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var block: [16]u8 = undefined;
            @memcpy(block[0..8], &a);
            @memcpy(block[8..16], r[i * 8 ..][0..8]);
            switch (kek.len) {
                16 => aes.Aes128.initEnc(kek[0..16].*).encrypt(&block, &block),
                32 => aes.Aes256.initEnc(kek[0..32].*).encrypt(&block, &block),
                else => unreachable,
            }
            const t: u64 = @as(u64, n) * @as(u64, j) + @as(u64, i) + 1;
            @memcpy(&a, block[0..8]);
            var tb: [8]u8 = undefined;
            std.mem.writeInt(u64, &tb, t, .big);
            for (&a, tb) |*x, y| x.* ^= y;
            @memcpy(r[i * 8 ..][0..8], block[8..16]);
        }
    }
    @memcpy(out[0..8], &a);
}
