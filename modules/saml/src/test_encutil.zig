// SPDX-License-Identifier: MIT
//! Test-only XML-Encryption WRAPPER builders, shared by the EncryptedID /
//! EncryptedAttribute suites. They mirror `test_encrypted.zig`'s primitives
//! (AES-256-GCM content key wrapped with RSA-OAEP-SHA1 under a locally-generated
//! SP key) but wrap an arbitrary child element name (`EncryptedID`,
//! `EncryptedAttribute`) around the `<xenc:EncryptedData>`. The byte-exact
//! anchors live in `xmlenc` (NIST/RFC KATs); the SP RSA key is test material.

const std = @import("std");
const rsa = @import("rsa");

const Sha1 = std.crypto.hash.Sha1;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const xenc_ns = "http://www.w3.org/2001/04/xmlenc#";
const ds_ns = "http://www.w3.org/2000/09/xmldsig#";
const saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion";

/// A 1024-bit SP key, generated deterministically (test material only).
pub fn makeSpKey(seed: u64) !rsa.KeyPair {
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
    const iv = [_]u8{0x33} ** 12;
    const total = 12 + msg.len + 16;
    const out = try alloc.alloc(u8, total);
    @memcpy(out[0..12], &iv);
    var tag: [16]u8 = undefined;
    Aes256Gcm.encrypt(out[12 .. 12 + msg.len], &tag, msg, "", iv, key);
    @memcpy(out[12 + msg.len ..], &tag);
    return out;
}

fn oaepWrapCek(alloc: std.mem.Allocator, pk: rsa.PublicKey, cek: []const u8) ![]u8 {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const k = (pk.n.bits() + 7) / 8;
    const buf = try alloc.alloc(u8, k);
    defer alloc.free(buf);
    const ct = try rsa.encryptOaep(pk, Sha1, prng.random(), cek, "", buf);
    return alloc.dupe(u8, ct);
}

/// Wrap `plaintext` (a serialized, namespace-well-formed `<saml:NameID>` /
/// `<saml:Attribute>`) as `<saml:{wrapper_local}>` around an AES-256-GCM /
/// RSA-OAEP `<xenc:EncryptedData Type="…#Element">` decryptable by `pk`'s private
/// half. The wrapper does NOT declare `xmlns:saml` (it inherits it from the
/// enclosing signed assertion).
pub fn encryptedWrapper(
    alloc: std.mem.Allocator,
    pk: rsa.PublicKey,
    wrapper_local: []const u8,
    plaintext: []const u8,
) ![]u8 {
    const cek = [_]u8{0xB7} ** 32;
    const wrapped = try oaepWrapCek(alloc, pk, &cek);
    defer alloc.free(wrapped);
    const content = try gcmEncrypt256(alloc, cek, plaintext);
    defer alloc.free(content);
    const cek_b64 = try b64(alloc, wrapped);
    defer alloc.free(cek_b64);
    const content_b64 = try b64(alloc, content);
    defer alloc.free(content_b64);

    return std.fmt.allocPrint(alloc, "<saml:{s}><xenc:EncryptedData xmlns:xenc=\"{s}\" xmlns:ds=\"{s}\" " ++
        "Type=\"http://www.w3.org/2001/04/xmlenc#Element\">" ++
        "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/>" ++
        "<ds:KeyInfo><xenc:EncryptedKey>" ++
        "<xenc:EncryptionMethod Algorithm=\"{s}rsa-oaep-mgf1p\"/>" ++
        "<xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>" ++
        "</xenc:EncryptedKey></ds:KeyInfo>" ++
        "<xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>" ++
        "</xenc:EncryptedData></saml:{s}>", .{ wrapper_local, xenc_ns, ds_ns, xenc_ns, cek_b64, content_b64, wrapper_local });
}

// ── CONVENTIONS §2.1 Z1 probe ────────────────────────────────────────────────

/// An allocator wrapper that inspects every block handed to `free` and records
/// whether `needle` was still present in it — the only way to observe a Z1 heap
/// wipe, since after `free` the bytes belong to the allocator again.
///
/// Useful ONLY under `-Doptimize=ReleaseFast`: `std.mem.Allocator.free` runs
/// `@memset(bytes, undefined)` before it reaches the vtable, so in Debug and
/// ReleaseSafe every freed block is already scrubbed to `0xaa` and this scanner
/// reports a clean result whatever the module under test does. Gate the test on
/// `builtin.mode` with `error.SkipZigTest` so the skip is visible.
pub const FreeScanner = struct {
    child: std.mem.Allocator,
    needle: []const u8,
    /// A block containing `needle` was released without being wiped.
    leaked_plaintext: bool = false,
    /// Blocks large enough to hold `needle` that were released at all — the
    /// positive control that the scanner is looking at something.
    frees_seen: usize = 0,

    pub fn allocator(self: *FreeScanner) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        } };
    }

    fn allocFn(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FreeScanner = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, a, ra);
    }
    fn resizeFn(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const self: *FreeScanner = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(m, a, n, ra);
    }
    fn remapFn(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const self: *FreeScanner = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(m, a, n, ra);
    }
    fn freeFn(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *FreeScanner = @ptrCast(@alignCast(ctx));
        if (m.len >= self.needle.len) {
            self.frees_seen += 1;
            if (std.mem.indexOf(u8, m, self.needle) != null) self.leaked_plaintext = true;
        }
        self.child.rawFree(m, a, ra);
    }
};
