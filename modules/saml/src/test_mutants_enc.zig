// SPDX-License-Identifier: MIT
//! Killing tests from the whole-module mutation audit, third part:
//! the decryption options (`allow_weak_rsa15`, `decrypt_kek`) must reach
//! `xmlenc` on all three paths (EncryptedAssertion, EncryptedID,
//! EncryptedAttribute). The wrappers here use RSA-OAEP, RSA-1_5 or an AES key
//! wrap (RFC 3394, `kw-aes256`) for the content key, AES-256-GCM for the data.

const std = @import("std");
const testing = std.testing;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");
const sign = @import("test_sign.zig");
const rsa = @import("rsa");
const t = @import("test_mutants.zig");
const encutil = @import("test_encutil.zig");

const gpa = testing.allocator;
const aes = std.crypto.core.aes;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const xenc_ns = "http://www.w3.org/2001/04/xmlenc#";
const saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion";

const Transport = enum { oaep, v15, kw };

const kek256 = @as([32]u8, @splat(0x5A));

/// RFC 3394 wrap of `plaintext` (a multiple of 8 octets) under a 32-byte KEK.
fn kwWrap(kek: *const [32]u8, plaintext: []const u8, out: []u8) void {
    const n = plaintext.len / 8;
    var a: [8]u8 = @splat(0xA6);
    @memcpy(out[8..], plaintext);
    const r = out[8..];
    const ctx = aes.Aes256.initEnc(kek.*);
    var j: usize = 0;
    while (j < 6) : (j += 1) {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var block: [16]u8 = undefined;
            @memcpy(block[0..8], &a);
            @memcpy(block[8..16], r[i * 8 ..][0..8]);
            ctx.encrypt(&block, &block);
            const tt: u64 = @as(u64, n) * @as(u64, j) + @as(u64, i) + 1;
            @memcpy(&a, block[0..8]);
            var tb: [8]u8 = undefined;
            std.mem.writeInt(u64, &tb, tt, .big);
            for (&a, tb) |*x, y| x.* ^= y;
            @memcpy(r[i * 8 ..][0..8], block[8..16]);
        }
    }
    @memcpy(out[0..8], &a);
}

fn v15Wrap(pk: rsa.PublicKey, cek: []const u8) ![]u8 {
    // EM = 0x00 02 PS(nonzero, >= 8) 00 M, then RSAEP. The test key is 1024 bits.
    var em: [128]u8 = undefined;
    em[0] = 0x00;
    em[1] = 0x02;
    const ps_len = 128 - cek.len - 3;
    var prng = std.Random.DefaultPrng.init(0x1234);
    for (em[2 .. 2 + ps_len]) |*p| {
        var v: u8 = 0;
        while (v == 0) v = prng.random().int(u8);
        p.* = v;
    }
    em[2 + ps_len] = 0x00;
    @memcpy(em[2 + ps_len + 1 ..], cek);
    const ct = try rsa.rsaep(128, em, pk);
    return gpa.dupe(u8, &ct);
}

/// `<saml:{local}>` around AES-256-GCM encrypted `plaintext`, content key
/// transported as `transport`; decryptable with the SP key / `kek256`.
fn wrapper(local: []const u8, transport: Transport, pk: rsa.PublicKey, plaintext: []const u8) ![]u8 {
    const cek = @as([32]u8, @splat(0xC3));
    const wrapped: []u8 = switch (transport) {
        .oaep => blk: {
            var prng = std.Random.DefaultPrng.init(0xC0FFEE);
            var buf: [128]u8 = undefined;
            const ct = try rsa.encryptOaep(pk, std.crypto.hash.Sha1, prng.random(), &cek, "", &buf);
            break :blk try gpa.dupe(u8, ct);
        },
        .v15 => try v15Wrap(pk, &cek),
        .kw => blk: {
            const w = try gpa.alloc(u8, 40);
            kwWrap(&kek256, &cek, w);
            break :blk w;
        },
    };
    defer gpa.free(wrapped);
    const iv = @as([12]u8, @splat(0x33));
    const content = try gpa.alloc(u8, 12 + plaintext.len + 16);
    defer gpa.free(content);
    @memcpy(content[0..12], &iv);
    var tag: [16]u8 = undefined;
    Aes256Gcm.encrypt(content[12 .. 12 + plaintext.len], &tag, plaintext, "", iv, cek);
    @memcpy(content[12 + plaintext.len ..], &tag);
    const cek_b64 = try t.b64(wrapped);
    defer gpa.free(cek_b64);
    const content_b64 = try t.b64(content);
    defer gpa.free(content_b64);
    const alg = switch (transport) {
        .oaep => xenc_ns ++ "rsa-oaep-mgf1p",
        .v15 => xenc_ns ++ "rsa-1_5",
        .kw => xenc_ns ++ "kw-aes256",
    };
    return gpa.print("<saml:{s}><xenc:EncryptedData xmlns:xenc=\"{s}\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Type=\"{s}Element\">" ++
        "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/>" ++
        "<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"{s}\"/>" ++
        "<xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>" ++
        "<xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:{s}>", .{ local, xenc_ns, xenc_ns, alg, cek_b64, content_b64, local });
}

const Variant = struct { transport: Transport, weak: bool, kek: bool, ok: bool };
const variants = [_]Variant{
    .{ .transport = .oaep, .weak = false, .kek = false, .ok = true },
    .{ .transport = .v15, .weak = false, .kek = false, .ok = false },
    .{ .transport = .v15, .weak = true, .kek = false, .ok = true },
    .{ .transport = .kw, .weak = false, .kek = false, .ok = false },
    .{ .transport = .kw, .weak = false, .kek = true, .ok = true },
};

fn cfgFor(key: @import("xmldsig").VerifyKey, kp: *const rsa.KeyPair, v: Variant) saml.Config {
    var cfg = t.baseCfg(key);
    cfg.sp_decrypt_key = &kp.secret_key;
    cfg.allow_weak_rsa15 = v.weak;
    cfg.decrypt_kek = if (v.kek) &kek256 else null;
    return cfg;
}

test "EncryptedAssertion: RSA-1_5 only with allow_weak_rsa15, kw-aes256 only with decrypt_kek" {
    var kp = try encutil.makeSpKey(0xF001);
    var inner = try t.mintA(0xF002, t.base_after_issuer, null);
    defer inner.deinit();
    const open = std.mem.find(u8, inner.resp, "<saml:Assertion").?;
    const close = std.mem.find(u8, inner.resp, "</saml:Assertion>").? + "</saml:Assertion>".len;
    for (variants) |v| {
        const enc = try wrapper("EncryptedAssertion", v.transport, kp.public_key, inner.resp[open..close]);
        defer gpa.free(enc);
        const resp = try sign.wrapInResponse(gpa, enc);
        defer gpa.free(resp);
        const cfg = cfgFor(inner.key, &kp, v);
        if (v.ok) {
            var res = try saml.consumeResponseXml(gpa, resp, cfg);
            res.deinit();
        } else {
            try testing.expectError(error.AssertionDecryptionFailed, saml.consumeResponseXml(gpa, resp, cfg));
        }
    }
}

test "EncryptedID: RSA-1_5 only with allow_weak_rsa15, kw-aes256 only with decrypt_kek" {
    var kp = try encutil.makeSpKey(0xF003);
    for (variants, 0..) |v, i| {
        const enc = try wrapper("EncryptedID", v.transport, kp.public_key, "<saml:NameID xmlns:saml=\"" ++ saml_ns ++ "\">bob</saml:NameID>");
        defer gpa.free(enc);
        const after = try std.mem.concat(gpa, u8, &.{ "<saml:Subject>", enc, t.bearer_xml, "</saml:Subject>", t.conditions_xml });
        defer gpa.free(after);
        var m = try t.mintA(0xF010 + i, after, null);
        defer m.deinit();
        const cfg = cfgFor(m.key, &kp, v);
        if (v.ok) {
            var res = try saml.consumeResponseXml(gpa, m.resp, cfg);
            defer res.deinit();
            try testing.expectEqualStrings("bob", res.name_id);
        } else {
            try testing.expectError(error.IdDecryptionFailed, saml.consumeResponseXml(gpa, m.resp, cfg));
        }
    }
}

test "EncryptedAttribute: RSA-1_5 only with allow_weak_rsa15, kw-aes256 only with decrypt_kek" {
    var kp = try encutil.makeSpKey(0xF004);
    for (variants, 0..) |v, i| {
        const enc = try wrapper("EncryptedAttribute", v.transport, kp.public_key, "<saml:Attribute xmlns:saml=\"" ++ saml_ns ++ "\" Name=\"a\"><saml:AttributeValue>v</saml:AttributeValue></saml:Attribute>");
        defer gpa.free(enc);
        const after = try std.mem.concat(gpa, u8, &.{ t.base_after_issuer, "<saml:AttributeStatement>", enc, "</saml:AttributeStatement>" });
        defer gpa.free(after);
        var m = try t.mintA(0xF020 + i, after, null);
        defer m.deinit();
        const cfg = cfgFor(m.key, &kp, v);
        if (v.ok) {
            var res = try saml.consumeResponseXml(gpa, m.resp, cfg);
            defer res.deinit();
            try testing.expectEqualStrings("v", res.attribute("a").?[0]);
        } else {
            try testing.expectError(error.AttributeDecryptionFailed, saml.consumeResponseXml(gpa, m.resp, cfg));
        }
    }
}

test "EncryptedID / EncryptedAttribute without an SP key, and with a payload of the wrong kind" {
    var kp = try encutil.makeSpKey(0xF005);
    // EncryptedID whose plaintext is not a NameID
    const enc_id = try wrapper("EncryptedID", .oaep, kp.public_key, "<saml:Attribute xmlns:saml=\"" ++ saml_ns ++ "\" Name=\"a\"/>");
    defer gpa.free(enc_id);
    const after_id = try std.mem.concat(gpa, u8, &.{ "<saml:Subject>", enc_id, t.bearer_xml, "</saml:Subject>", t.conditions_xml });
    defer gpa.free(after_id);
    var m1 = try t.mintA(0xF030, after_id, null);
    defer m1.deinit();
    var cfg = t.baseCfg(m1.key);
    try testing.expectError(error.EncryptedIdUnsupported, saml.consumeResponseXml(gpa, m1.resp, cfg));
    cfg.sp_decrypt_key = &kp.secret_key;
    try testing.expectError(error.IdDecryptionFailed, saml.consumeResponseXml(gpa, m1.resp, cfg));

    // EncryptedAttribute whose plaintext is not an Attribute
    const enc_at = try wrapper("EncryptedAttribute", .oaep, kp.public_key, "<saml:NameID xmlns:saml=\"" ++ saml_ns ++ "\">x</saml:NameID>");
    defer gpa.free(enc_at);
    const after_at = try std.mem.concat(gpa, u8, &.{ t.base_after_issuer, "<saml:AttributeStatement>", enc_at, "</saml:AttributeStatement>" });
    defer gpa.free(after_at);
    var m2 = try t.mintA(0xF031, after_at, null);
    defer m2.deinit();
    var c2 = t.baseCfg(m2.key);
    try testing.expectError(error.EncryptedAttributeUnsupported, saml.consumeResponseXml(gpa, m2.resp, c2));
    c2.sp_decrypt_key = &kp.secret_key;
    try testing.expectError(error.AttributeDecryptionFailed, saml.consumeResponseXml(gpa, m2.resp, c2));
}
