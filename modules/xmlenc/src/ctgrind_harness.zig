// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh xmlenc`, which builds the
//! harness and prints the control table.
//!
//! Not wired into `zig build test-xmlenc`: memcheck's context count is valgrind's
//! own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! Every secret xmlenc handles on the decryption path: the relying party's RSA
//! private key (key transport), the symmetric key-encryption key (kw-aes*), and
//! through them the unwrapped content-encryption key. The secret members are
//! tainted in place AFTER the fixture document is built (the fixture needs the
//! public half only), the public half stays defined, and the public entry point
//! `decryptData` is driven end to end on a real `<xenc:EncryptedData>`:
//!
//!  * `oaep`  — rsa-oaep-mgf1p (SHA-1) key transport + AES-256-GCM content.
//!    Tainted: the secret members of `rsa.SecretKey` (d, p, q, dp, dq, qinv and
//!    the value fields of p_mont/q_mont); NOT n, e, n_mont or the slot L.
//!  * `cbc`   — the same key transport + AES-128-CBC content, which adds the
//!    XML-Enc unpadding of the recovered plaintext.
//!  * `rsa15` — rsa-1_5 key transport (`allow_weak_rsa15`) + AES-256-GCM: the
//!    branch-free PKCS#1 v1.5 unpadding and its decoy-CEK path.
//!  * `kw`    — kw-aes256 with the KEK tainted + AES-256-GCM, accepted, and the
//!    same with a flipped tag bit (rejected): the AES-KW unwrap, the CEK handed
//!    to the content pass, and the GCM tag verdict.
//!
//! The recovered plaintext is public by the API's contract (it is the caller's
//! to receive). It is formatted through the non-constant-time printer BEFORE it
//! is declassified, as the propagation witness: a non-zero `total` proves the
//! taint reached the output, so an in-file zero means "no branch found" rather
//! than "the taint never arrived".
//!
//! The verdict branches (accept / reject: `DecryptionError` is one value for
//! every failure) are the contexts the API discloses by design; the RSA, AES-KW,
//! CBC-unpad and GCM-tag contexts in `rsa`, `aeskw`, `aescbc` and `aesgcm` are
//! those modules' own rows and are itemised in `ctgrind-expected.tsv`.

const std = @import("std");
const builtin = @import("builtin");
const xmlenc = @import("root.zig");
const xml = @import("xml");
const rsa = @import("rsa");
const aesgcm = @import("aesgcm");

const memcheck = std.valgrind.memcheck;

const Target = enum { oaep, cbc, rsa15, kw };
const Taint = enum { yes, no };

const plaintext = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a\" Version=\"2.0\">ctgrind</saml:Assertion>";

fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
        return out;
    }
}

// A fixed 2048-bit key (the same KAT primes `jwt`'s harness uses).
const kat_e = [_]u8{ 0x01, 0x00, 0x01 };
const kat_p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
const kat_q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
const kat_n = hexLit("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) memcheck.makeMemUndefined(bytes);
}

fn taintMont(t: Taint, mp: anytype) void {
    taint(t, std.mem.asBytes(&mp.m));
    taint(t, std.mem.asBytes(&mp.n0inv));
    taint(t, std.mem.asBytes(&mp.r2));
    taint(t, std.mem.asBytes(&mp.one_mont));
}

fn taintKey(t: Taint, sk: *rsa.SecretKey) void {
    taint(t, std.mem.asBytes(&sk.d));
    taint(t, std.mem.asBytes(&sk.p));
    taint(t, std.mem.asBytes(&sk.q));
    taint(t, std.mem.asBytes(&sk.dp));
    taint(t, std.mem.asBytes(&sk.dq));
    taint(t, std.mem.asBytes(&sk.qinv));
    taintMont(t, &sk.p_mont);
    taintMont(t, &sk.q_mont);
}

const Fixture = struct {
    doc_buf: [8192]u8 = undefined,
    doc_len: usize = 0,

    fn src(self: *const Fixture) []const u8 {
        return self.doc_buf[0..self.doc_len];
    }
};

fn b64(out: []u8, data: []const u8) []const u8 {
    return std.base64.standard.Encoder.encode(out, data);
}

fn gcmContent(out: []u8, key: *const [32]u8, msg: []const u8, flip_tag: bool) []u8 {
    const iv = @as([12]u8, @splat(0x22));
    @memcpy(out[0..12], &iv);
    var tag: [16]u8 = undefined;
    aesgcm.Aes256Gcm.encrypt(out[12 .. 12 + msg.len], &tag, msg, "", iv, key.*);
    if (flip_tag) tag[3] ^= 1;
    @memcpy(out[12 + msg.len ..][0..16], &tag);
    return out[0 .. 12 + msg.len + 16];
}

fn cbcContent(out: []u8, key: *const [16]u8, msg: []const u8) []u8 {
    const bs = 16;
    const pad = bs - (msg.len % bs);
    const total = bs + msg.len + pad;
    const iv = @as([bs]u8, @splat(0x11));
    @memcpy(out[0..bs], &iv);
    @memcpy(out[bs .. bs + msg.len], msg);
    for (out[bs + msg.len .. total - 1]) |*p| p.* = 0;
    out[total - 1] = @intCast(pad);
    const ctx = std.crypto.core.aes.Aes128.initEnc(key.*);
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
    return out[0..total];
}

fn kwWrap(kek: *const [32]u8, key_data: []const u8, out: []u8) void {
    const n = key_data.len / 8;
    var a: [8]u8 = .{ 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
    @memcpy(out[8..][0..key_data.len], key_data);
    const r = out[8..][0..key_data.len];
    var j: usize = 0;
    while (j < 6) : (j += 1) {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var block: [16]u8 = undefined;
            @memcpy(block[0..8], &a);
            @memcpy(block[8..16], r[i * 8 ..][0..8]);
            std.crypto.core.aes.Aes256.initEnc(kek.*).encrypt(&block, &block);
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

fn build(fx: *Fixture, content_alg: []const u8, key_alg: []const u8, wrapped: []const u8, content: []const u8) !void {
    var wb: [1024]u8 = undefined;
    var cb: [1024]u8 = undefined;
    const w64 = b64(&wb, wrapped);
    const c64 = b64(&cb, content);
    const s = try std.fmt.bufPrint(&fx.doc_buf,
        \\<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
        \\<xenc:EncryptionMethod Algorithm="{s}"/>
        \\<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{s}"/>
        \\<xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>
        \\<xenc:CipherData><xenc:CipherValue>{s}</xenc:CipherValue></xenc:CipherData>
        \\</xenc:EncryptedData>
    , .{ content_alg, key_alg, w64, c64 });
    fx.doc_len = s.len;
}

fn publish(label: []const u8, bytes: []u8) void {
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..bytes.len], bytes);
    std.debug.print("ctgrind_result {s}={x}\n", .{ label, copy[0..bytes.len] });
    memcheck.makeMemDefined(bytes);
}

fn decryptAndReport(label: []const u8, doc: *const xml.Document, sk: *const rsa.SecretKey, opts: xmlenc.Options) void {
    if (xmlenc.decryptData(std.heap.page_allocator, doc.root, sk, opts)) |out| { // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
        publish(label, out);
        std.debug.print("ctgrind_result {s} ok\n", .{label});
    } else |e| {
        std.debug.print("ctgrind_result {s} err={t}\n", .{ label, e });
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const t = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var kp: rsa.KeyPair = undefined;
    try rsa.SecretKey.fromPrimes(&kp.secret_key, &kat_p, &kat_q, &kat_e);
    defer kp.secret_key.deinit();
    kp.public_key = try rsa.PublicKey.fromBytes(&kat_n, &kat_e);
    var prng = std.Random.DefaultPrng.init(0xC7_61_1D);
    const xenc = "http://www.w3.org/2001/04/xmlenc#";
    const xenc11 = "http://www.w3.org/2009/xmlenc11#";

    var fx: Fixture = .{};
    var content_buf: [512]u8 = undefined;
    var wrap_buf: [256]u8 = undefined;

    switch (target) {
        .oaep, .cbc => {
            const cek32 = @as([32]u8, @splat(0xC5));
            const cek16 = @as([16]u8, @splat(0x7A));
            const cek: []const u8 = if (target == .oaep) &cek32 else &cek16;
            const wrapped = try rsa.encryptOaep(kp.public_key, std.crypto.hash.Sha1, prng.random(), cek, "", &wrap_buf);
            if (target == .oaep) {
                const content = gcmContent(&content_buf, &cek32, plaintext, false);
                try build(&fx, xenc11 ++ "aes256-gcm", xenc ++ "rsa-oaep-mgf1p", wrapped, content);
            } else {
                const content = cbcContent(&content_buf, &cek16, plaintext);
                try build(&fx, xenc ++ "aes128-cbc", xenc ++ "rsa-oaep-mgf1p", wrapped, content);
            }
            var doc = try xml.parse(std.heap.page_allocator, fx.src(), .{}); // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
            defer doc.deinit();
            taintKey(t, &kp.secret_key);
            decryptAndReport(@tagName(target), &doc, &kp.secret_key, .{});
        },
        .rsa15 => {
            const cek = @as([32]u8, @splat(0xC5));
            // EM = 0x00 02 PS(nonzero, >= 8) 00 M, k = 256.
            var em: [256]u8 = undefined;
            em[0] = 0x00;
            em[1] = 0x02;
            const ps_len = em.len - cek.len - 3;
            for (em[2 .. 2 + ps_len]) |*p| {
                var v: u8 = 0;
                while (v == 0) v = prng.random().int(u8);
                p.* = v;
            }
            em[2 + ps_len] = 0x00;
            @memcpy(em[2 + ps_len + 1 ..], &cek);
            const ct = try rsa.rsaep(256, em, kp.public_key);
            const content = gcmContent(&content_buf, &cek, plaintext, false);
            try build(&fx, xenc11 ++ "aes256-gcm", xenc ++ "rsa-1_5", &ct, content);
            var doc = try xml.parse(std.heap.page_allocator, fx.src(), .{}); // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
            defer doc.deinit();
            taintKey(t, &kp.secret_key);
            decryptAndReport("rsa15", &doc, &kp.secret_key, .{ .allow_weak_rsa15 = true });
        },
        .kw => {
            var kek = @as([32]u8, @splat(0x3B));
            const cek = @as([32]u8, @splat(0xC5));
            var wrapped: [40]u8 = undefined;
            kwWrap(&kek, &cek, &wrapped);
            // The KEK is the secret: taint a copy held by the Options after the
            // fixture is built; the key-transport RSA key is unused here.
            for ([_]bool{ false, true }) |flip| {
                const content = gcmContent(&content_buf, &cek, plaintext, flip);
                try build(&fx, xenc11 ++ "aes256-gcm", xenc ++ "kw-aes256", &wrapped, content);
                var doc = try xml.parse(std.heap.page_allocator, fx.src(), .{}); // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
                defer doc.deinit();
                taint(t, &kek);
                decryptAndReport(if (flip) "kw-reject" else "kw-accept", &doc, &kp.secret_key, .{ .kek = &kek });
                // `decryptData` took a copy of nothing: the KEK stays tainted for
                // the second pass on purpose.
            }
        },
    }
}
