// SPDX-License-Identifier: MIT

//! Dead-stack probe for the decryption entry points (`testkit.stackprobe`):
//! residue below the burn, and the RSA private components as needles in any
//! frame. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body
//! is type-checked in every mode). The fixture is built here: a 1024-bit key
//! generated from a fixed seed (test key), an OAEP-wrapped AES-256 CEK and an
//! AES-256-GCM content; the document lives for the whole test.

const std = @import("std");
const xml = @import("xml");
const rsa = @import("rsa");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

// Window above the 64 KiB burn and `rsa`'s own 200 KiB private-op burn.
const P = sp.Probe(.{ .window = 512 * 1024 });

const xenc_ns = "http://www.w3.org/2001/04/xmlenc#";
const xenc11_ns = "http://www.w3.org/2009/xmlenc11#";
const ds_ns = "http://www.w3.org/2000/09/xmldsig#";
const assertion =
    "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " ++
    "ID=\"_a1b2\" Version=\"2.0\">dead-stack probe</saml:Assertion>";

var kp: rsa.KeyPair = undefined;
var doc: xml.Document = undefined;
var wrapper: xml.Document = undefined;

fn b64(a: std.mem.Allocator, data: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try a.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data);
    return out;
}

fn build(a: std.mem.Allocator) !void {
    var prng = std.Random.DefaultPrng.init(0x5A_11_E0_DE);
    try rsa.generate(&kp, prng.random(), 1024, 65537);

    const cek = [_]u8{0xC5} ** 32;
    const iv = [_]u8{0x22} ** 12;
    var content: [12 + assertion.len + 16]u8 = undefined;
    @memcpy(content[0..12], &iv);
    var tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(content[12..][0..assertion.len], &tag, assertion, "", iv, cek);
    @memcpy(content[12 + assertion.len ..], &tag);

    var wrapped_buf: [128]u8 = undefined;
    const wrapped = try rsa.encryptOaep(kp.public_key, std.crypto.hash.Sha1, prng.random(), &cek, "", &wrapped_buf);

    const cek_b64 = try b64(a, wrapped);
    const content_b64 = try b64(a, &content);
    const src = try std.fmt.allocPrint(a,
        \\<xenc:EncryptedData xmlns:xenc="{s}" xmlns:ds="{s}" Type="{s}Element">
        \\  <xenc:EncryptionMethod Algorithm="{s}aes256-gcm"/>
        \\  <ds:KeyInfo>
        \\    <xenc:EncryptedKey>
        \\      <xenc:EncryptionMethod Algorithm="{s}rsa-oaep-mgf1p"/>
        \\      <xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>
        \\    </xenc:EncryptedKey>
        \\  </ds:KeyInfo>
        \\  <xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>
        \\</xenc:EncryptedData>
    , .{ xenc_ns, ds_ns, xenc_ns, xenc11_ns, xenc_ns, cek_b64, content_b64 });
    doc = try xml.parse(a, src, .{});

    const wsrc = try std.fmt.allocPrint(a, "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{s}</saml:EncryptedAssertion>", .{src});
    wrapper = try xml.parse(a, wsrc, .{});
}

test "STACKPROBE: no RSA private-key residue after any decryption entry point" {
    try sp.skipUnlessOptimized();
    const a = std.heap.page_allocator;
    try build(a);

    const sk = &kp.secret_key;
    const needles = &[_][]const u8{
        std.mem.asBytes(&sk.d),  std.mem.asBytes(&sk.p),  std.mem.asBytes(&sk.q),
        std.mem.asBytes(&sk.dp), std.mem.asBytes(&sk.dq), std.mem.asBytes(&sk.qinv),
    };

    // One-shot, RSA-class burn (`burn.decrypt_burn`).
    _ = try P.run("decryptData", root.decryptData, .{ a, doc.root, sk, .{} }, needles, .{});
    _ = try P.run("decryptAssertion", root.decryptAssertion, .{ a, wrapper.root, sk, .{} }, needles, .{});
    const d2 = try P.run("decryptDataToDocument", root.decryptDataToDocument, .{ a, doc.root, sk, .{} }, needles, .{});
    _ = d2;
}
