// SPDX-License-Identifier: MIT

//! Dead-stack probe for the decryption entry points (`testkit.stackprobe`):
//! residue below the burn, and as needles in any frame the RSA private
//! components, the recovered CEK, the unpadded RSA block, the AES-KW key and the
//! decoy digest. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body
//! is type-checked in every mode). The fixture is built here: a 1024-bit key
//! generated from a fixed seed (test key), an OAEP-wrapped AES-256 CEK and an
//! AES-256-GCM content; the document lives for the whole test.

const std = @import("std");
const xml = @import("xml");
const rsa = @import("rsa");
const aeskw = @import("aeskw");
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
var doc_v15: xml.Document = undefined;
var doc_kw: xml.Document = undefined;
var doc_decoy: xml.Document = undefined;

// Values the test knows and the module must not leave on the dead stack. Each
// is varied: a uniform splat is too uniform for a needle window.
const cek_oaep: [32]u8 = fillBytes(32, 0xC5);
const cek_v15: [32]u8 = fillBytes(32, 0x3B);
const cek_kw: [32]u8 = fillBytes(32, 0x71);
const kek: [32]u8 = fillBytes(32, 0xA9);

fn fillBytes(comptime n: usize, comptime seed: u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = @truncate((i * 37 + seed) ^ (i >> 1) ^ seed);
    return out;
}

fn b64(a: std.mem.Allocator, data: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const out = try a.alloc(u8, enc.calcSize(data.len));
    _ = enc.encode(out, data);
    return out;
}

const Content = [12 + assertion.len + 16]u8;

/// `assertion` as AES-256-GCM under `cek`: iv || ciphertext || tag.
fn gcmContent(cek: [32]u8) Content {
    var out: Content = undefined;
    const iv = @as([12]u8, @splat(0x22));
    @memcpy(out[0..12], &iv);
    var tag: [16]u8 = undefined;
    @import("aesgcm").Aes256Gcm.encrypt(out[12..][0..assertion.len], &tag, assertion, "", iv, cek);
    @memcpy(out[12 + assertion.len ..], &tag);
    return out;
}

/// The EncryptedData source: key transport `key_alg` (a full URI) over the
/// `wrapped` blob, content AES-256-GCM `content`.
fn encryptedDataSource(a: std.mem.Allocator, key_alg: []const u8, wrapped: []const u8, content: []const u8) ![]u8 {
    const cek_b64 = try b64(a, wrapped);
    const content_b64 = try b64(a, content);
    return try a.print(
        \\<xenc:EncryptedData xmlns:xenc="{s}" xmlns:ds="{s}" Type="{s}Element">
        \\  <xenc:EncryptionMethod Algorithm="{s}aes256-gcm"/>
        \\  <ds:KeyInfo>
        \\    <xenc:EncryptedKey>
        \\      <xenc:EncryptionMethod Algorithm="{s}"/>
        \\      <xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>
        \\    </xenc:EncryptedKey>
        \\  </ds:KeyInfo>
        \\  <xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>
        \\</xenc:EncryptedData>
    , .{ xenc_ns, ds_ns, xenc_ns, xenc_ns, key_alg, cek_b64, content_b64 });
}

/// RSAES-PKCS1-v1_5 block `0x00 0x02 PS 0x00 M` for a 128-byte modulus.
fn v15Block(msg: *const [32]u8) [128]u8 {
    var em: [128]u8 = undefined;
    em[0] = 0x00;
    em[1] = 0x02;
    for (em[2 .. 128 - 33], 0..) |*b, i| b.* = @intCast(1 + (i * 11) % 250);
    em[128 - 33] = 0x00;
    em[128 - 32 ..][0..32].* = msg.*;
    return em;
}

// Secrets that exist only inside the module's frames, recomputed here from
// what the test knows.
var oaep_em: [128]u8 = undefined; // RSADP of the OAEP blob = the encoded message
var v15_em: [128]u8 = undefined; // the PKCS#1 v1.5 block
var decoy_digest: [32]u8 = undefined; // SHA-256 of the decoy-CEK input

fn build(a: std.mem.Allocator) !void {
    var prng = std.Random.DefaultPrng.init(0x5A_11_E0_DE);
    try rsa.generate(&kp, prng.random(), 1024, 65537);

    // OAEP (SHA-1) key transport, AES-256-GCM content.
    var wrapped_buf: [128]u8 = undefined;
    const wrapped = try rsa.encryptOaep(kp.public_key, std.crypto.hash.Sha1, prng.random(), &cek_oaep, "", &wrapped_buf);
    const src = try encryptedDataSource(a, xenc_ns ++ "rsa-oaep-mgf1p", wrapped, &gcmContent(cek_oaep));
    doc = try xml.parse(a, src, .{});
    oaep_em = try rsa.rsadpCrt(128, wrapped_buf, &kp.secret_key);

    const wsrc = try a.print("<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{s}</saml:EncryptedAssertion>", .{src});
    wrapper = try xml.parse(a, wsrc, .{});

    // PKCS#1 v1.5 key transport (the opt-in `allow_weak_rsa15` path).
    v15_em = v15Block(&cek_v15);
    const ct = try rsa.rsaep(128, v15_em, kp.public_key);
    doc_v15 = try xml.parse(a, try encryptedDataSource(a, xenc_ns ++ "rsa-1_5", &ct, &gcmContent(cek_v15)), .{});

    // AES-256 key wrap under `kek`: the unwrap succeeds.
    var kw_blob: [40]u8 = undefined;
    _ = try aeskw.wrap(&kek, &cek_kw, &kw_blob);
    doc_kw = try xml.parse(a, try encryptedDataSource(a, xenc_ns ++ "kw-aes256", &kw_blob, &gcmContent(cek_kw)), .{});

    // A wrap of a 16-byte key for an AES-256 content: the unwrap yields a
    // decoy (SHA-256 over the domain label, the KEK and the blob, as
    // `aesKwUnwrap` builds it); the content fails, only the work is measured.
    var short_blob: [24]u8 = undefined;
    _ = try aeskw.wrap(&kek, cek_kw[0..16], &short_blob);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("zig-libs/xmlenc decoy CEK v1");
    h.update(&kek);
    h.update(&short_blob);
    h.final(&decoy_digest);
    doc_decoy = try xml.parse(a, try encryptedDataSource(a, xenc_ns ++ "kw-aes256", &short_blob, &gcmContent(decoy_digest)), .{});
}

test "STACKPROBE: no RSA private-key residue after any decryption entry point" {
    try sp.skipUnlessOptimized();
    const a = std.heap.page_allocator;
    try build(a);

    const sk = &kp.secret_key;
    const rsa_needles = [_][]const u8{
        std.mem.asBytes(&sk.d),  std.mem.asBytes(&sk.p),  std.mem.asBytes(&sk.q),
        std.mem.asBytes(&sk.dp), std.mem.asBytes(&sk.dq), std.mem.asBytes(&sk.qinv),
    };
    // The RSA key, the recovered CEK and the unpadded block (OAEP encoded
    // message / v1.5 block) of each transport.
    const needles = &(rsa_needles ++ [_][]const u8{ &cek_oaep, &oaep_em });
    const needles_v15 = &(rsa_needles ++ [_][]const u8{ &cek_v15, &v15_em });

    // One-shot, RSA-class burn (`burn.decrypt_burn`).
    _ = try P.run("decryptData", root.decryptData, .{ a, doc.root, sk, .{} }, needles, .{});
    _ = try P.run("decryptAssertion", root.decryptAssertion, .{ a, wrapper.root, sk, .{} }, needles, .{});
    const d2 = try P.run("decryptDataToDocument", root.decryptDataToDocument, .{ a, doc.root, sk, .{} }, needles, .{});
    _ = d2;
    _ = try P.run("decryptData rsa-1_5", root.decryptData, .{ a, doc_v15.root, sk, .{ .allow_weak_rsa15 = true } }, needles_v15, .{});
    // AES key wrap: the KEK is the secret input, the CEK the secret result;
    // the failing wrap adds the decoy digest.
    _ = try P.run("decryptData kw-aes256", root.decryptData, .{ a, doc_kw.root, sk, .{ .kek = &kek } }, &[_][]const u8{ &kek, &cek_kw }, .{});
    _ = try P.run("decryptData kw-aes256 decoy", root.decryptData, .{ a, doc_decoy.root, sk, .{ .kek = &kek } }, &[_][]const u8{ &kek, &decoy_digest }, .{});
}

// ── ECDH-ES arm ─────────────────────────────────────────────────────────────

const jwe = @import("jwe");
const P256 = std.crypto.ecc.P256;

/// The encrypt side's random draws, in the order `encryptData` makes them for a GCM content and an ECDH-ES key:
/// the content key, the IV, the ephemeral scalar. Fixed, so the probe knows every secret in advance; the counter
/// wraps, so each of the probe's repeated calls draws the same three.
const FixedDraws = struct {
    var n: usize = 0;
    const cek: [32]u8 = fillBytes(32, 0x4D);
    const iv: [12]u8 = fillBytes(12, 0x19);
    const eph: [32]u8 = fillBytes(32, 0x07); // top byte 0x07 < the group order's, so canonical
    fn fill(_: *anyopaque, buf: []u8) void {
        const src: []const u8 = switch (n % 3) {
            0 => &cek,
            1 => &iv,
            else => &eph,
        };
        std.debug.assert(src.len == buf.len);
        @memcpy(buf, src);
        n += 1;
    }
    fn random() std.Random {
        return .{ .ptr = undefined, .fillFn = fill };
    }
};

const ecdh_kdf_id = "probe-kdf-id";
const ecdh_party_u = "PU-probe";
const ecdh_party_v = "PV-probe";

var ec_recipient: jwe.ecdhes.EphemeralKeyPair = undefined;
var ec_doc: xml.Document = undefined;
var ec_z: [jwe.ecdhes.max_z_len]u8 = undefined;
var ec_kek: [32]u8 = undefined;

test "STACKPROBE: no ECDH-ES residue (static and ephemeral scalar, shared secret, derived KEK, CEK) after decryptData and encryptData" {
    try sp.skipUnlessOptimized();
    const a = std.heap.page_allocator;

    var prng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x6E)));
    jwe.ecdhes.generateEphemeral(&ec_recipient, .p256, .{ .fixed_for_test = prng.random() });
    const params: root.EcdhEs = .{
        .recipient = ec_recipient.public,
        .wrap_bits = 256,
        .algorithm_id = ecdh_kdf_id,
        .party_u_info = ecdh_party_u,
        .party_v_info = ecdh_party_v,
    };

    // What the module must not leave behind, recomputed from the fixed draws: Z = the ephemeral scalar times the
    // recipient's public key, KEK = SHA-256(counter || Z || OtherInfo) (ConcatKDF, one round for 32 bytes).
    const eph_priv: jwe.ecdhes.PrivateKey = .{ .p256 = FixedDraws.eph };
    const z = try jwe.ecdhes.deriveZ(&eph_priv, ec_recipient.public, &ec_z);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&.{ 0, 0, 0, 1 });
    h.update(z);
    h.update(ecdh_kdf_id ++ ecdh_party_u ++ ecdh_party_v);
    h.final(&ec_kek);

    FixedDraws.n = 0;
    const src = try root.encryptData(a, assertion, .{ .ecdh_es = params }, FixedDraws.random(), .{});
    ec_doc = try xml.parse(a, src, .{});

    const needles = &[_][]const u8{ &FixedDraws.eph, z, &ec_kek, &FixedDraws.cek, &ec_recipient.private.p256 };

    // Decryption: one-shot, burned (`burn.decrypt_burn`); the burn must cover the ECDH arm too.
    const ec_sk: root.EcPrivateKey = ec_recipient.private;
    const rec = try P.run("decryptData ecdh-es", root.decryptData, .{ a, ec_doc.root, undefined, .{ .ec_private_key = &ec_sk } }, needles, .{});
    _ = rec;

    // Encryption has no burn of its own; its dead stack is only checked for the three ECDH secrets and the CEK.
    FixedDraws.n = 0;
    _ = try P.run("encryptData ecdh-es", root.encryptData, .{ a, assertion, .{ .ecdh_es = params }, FixedDraws.random(), .{} }, needles, .{ .burn = false, .residue = false });
}
