// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for `opensshDecryptSection`, the
//! public OpenSSH private-section decryptor that the `ssh` module calls
//! directly (outside `fromOpenSSH`'s burn). The section is built here:
//! bcrypt_pbkdf → key ‖ IV, then AES-256-CTR / -CBC over a known plaintext,
//! so the AES key, its expanded schedule, the IV and the CTR keystream are
//! all known needles. ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;
const aes = std.crypto.core.aes;

const P = sp.Probe(.{ .window = 96 * 1024 });

const passphrase = "rsa probe4 openssh passphrase";
const rounds: u32 = 2;

var salt: [16]u8 = undefined;
var kdfoptions: [4 + 16 + 4]u8 = undefined;
var key_iv: [48]u8 = undefined;
var plain: [256]u8 = undefined;
var ct_ctr: [256]u8 = undefined;
var ct_cbc: [256]u8 = undefined;
var keystream: [256]u8 = undefined;
var enc_sched: [@sizeOf(aes.AesEncryptCtx(aes.Aes256))]u8 = undefined;
var dec_sched: [@sizeOf(aes.AesDecryptCtx(aes.Aes256))]u8 = undefined;
var dst: [256]u8 = undefined;

fn setup() !void {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rsa probe4 salt", &h, .{});
    @memcpy(&salt, h[0..16]);
    std.mem.writeInt(u32, kdfoptions[0..4], 16, .big);
    @memcpy(kdfoptions[4..20], &salt);
    std.mem.writeInt(u32, kdfoptions[20..24], rounds, .big);
    try root.openssh.bcryptPbkdf(passphrase, &salt, rounds, &key_iv);

    // Plaintext with 8+ distinct bytes in every 16-byte window.
    var prng = std.Random.DefaultPrng.init(0x0551_D4C7);
    prng.random().bytes(&plain);

    const ectx = aes.Aes256.initEnc(key_iv[0..32].*);
    enc_sched = std.mem.toBytes(ectx);
    const dctx = aes.Aes256.initDec(key_iv[0..32].*);
    dec_sched = std.mem.toBytes(dctx);

    // CTR: keystream = E(iv + i), big-endian 128-bit counter.
    var ctr: u128 = std.mem.readInt(u128, key_iv[32..48], .big);
    var off: usize = 0;
    while (off < plain.len) : (off += 16) {
        var blk: [16]u8 = undefined;
        std.mem.writeInt(u128, &blk, ctr, .big);
        ectx.encrypt(keystream[off..][0..16], &blk);
        ctr +%= 1;
    }
    for (&ct_ctr, plain, keystream) |*c, p, k| c.* = p ^ k;

    // CBC encrypt.
    var prev: [16]u8 = key_iv[32..48].*;
    off = 0;
    while (off < plain.len) : (off += 16) {
        var x: [16]u8 = undefined;
        for (&x, plain[off..][0..16], prev) |*b, p, v| b.* = p ^ v;
        ectx.encrypt(ct_cbc[off..][0..16], &x);
        prev = ct_cbc[off..][0..16].*;
    }
}

test "STACKPROBE: opensshDecryptSection leaves no AES key, schedule or keystream on the dead stack" {
    try sp.skipUnlessOptimized();
    try setup();

    // Positive check of the fixture: both sections decrypt to `plain`.
    {
        const s = try root.opensshDecryptSection(&dst, "aes256-ctr", "bcrypt", &kdfoptions, &ct_ctr, passphrase);
        try std.testing.expectEqualSlices(u8, &plain, s.plain);
        const c = try root.opensshDecryptSection(&dst, "aes256-cbc", "bcrypt", &kdfoptions, &ct_cbc, passphrase);
        try std.testing.expectEqualSlices(u8, &plain, c.plain);
    }

    const ctr_needles = [_][]const u8{ key_iv[0..32], key_iv[32..48], enc_sched[32..], &keystream };
    _ = try P.run("opensshDecryptSection aes256-ctr", root.opensshDecryptSection, .{ &dst, "aes256-ctr", "bcrypt", &kdfoptions, &ct_ctr, passphrase }, &ctr_needles, .{});
    const cbc_needles = [_][]const u8{ key_iv[0..32], key_iv[32..48], dec_sched[0..], &plain };
    _ = try P.run("opensshDecryptSection aes256-cbc", root.opensshDecryptSection, .{ &dst, "aes256-cbc", "bcrypt", &kdfoptions, &ct_cbc, passphrase }, &cbc_needles, .{});
}

// ---- fromOpenSSH (mutation 2026-11-25: its own key_burn, now that it calls the unburned decryptor) ----

const Pk = sp.Probe(.{ .window = 512 * 1024, .max_windows = 1 << 17 });

fn katHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var b: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

// The module's own 2048-bit KAT key (public in this repository, as in the other probes).
const kat_p = katHex("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
const kat_q = katHex("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
const kat_n = katHex("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");
const kat_e = [_]u8{ 0x01, 0x00, 0x01 };

var os_pem: [4096]u8 = undefined;
var os_pem_len: usize = 0;
var os_key: root.SecretKey = undefined;
var os_secret: root.SecretKey = undefined;

const Wr = struct {
    buf: []u8,
    n: usize = 0,
    fn u32be(self: *Wr, v: u32) void {
        std.mem.writeInt(u32, self.buf[self.n..][0..4], v, .big);
        self.n += 4;
    }
    fn raw(self: *Wr, b: []const u8) void {
        @memcpy(self.buf[self.n..][0..b.len], b);
        self.n += b.len;
    }
    fn str(self: *Wr, b: []const u8) void {
        self.u32be(@intCast(b.len));
        self.raw(b);
    }
    /// ssh mpint of a big-endian magnitude (no leading zero bytes in `b`).
    fn mpint(self: *Wr, b: []const u8) void {
        const pad: u32 = if (b[0] & 0x80 != 0) 1 else 0;
        self.u32be(@as(u32, @intCast(b.len)) + pad);
        if (pad == 1) self.raw(&.{0});
        self.raw(b);
    }
};

fn fromOpenSSHW(o: *root.SecretKey) !void {
    return root.fromOpenSSH(o, os_pem[0..os_pem_len], passphrase);
}

test "STACKPROBE: fromOpenSSH leaves no key, AES key or keystream on the dead stack" {
    try sp.skipUnlessOptimized();
    try setup();

    try root.SecretKey.fromPrimes(&os_secret, &kat_p, &kat_q, &kat_e);
    defer os_secret.deinit();
    var d_be: [256]u8 = undefined;
    var qinv_be: [128]u8 = undefined;
    try os_secret.d.toBytes(&d_be, .big);
    try os_secret.qinv.toBytes(&qinv_be, .big);

    // The private section (n, e, d, iqmp, p, q), padded 1, 2, 3, ... to 16.
    var sec: [1400]u8 = undefined;
    var w = Wr{ .buf = &sec };
    w.u32be(0x0a0b0c0d);
    w.u32be(0x0a0b0c0d);
    w.str("ssh-rsa");
    w.mpint(&kat_n);
    w.mpint(&kat_e);
    w.mpint(&d_be);
    w.mpint(&qinv_be);
    w.mpint(&kat_p);
    w.mpint(&kat_q);
    w.str("probe");
    var pad: u8 = 1;
    while (w.n % 16 != 0) : (pad += 1) w.raw(&.{pad});
    const sec_len = w.n;

    // AES-256-CTR with the key || IV bcrypt_pbkdf derives (setup() above).
    const ectx = aes.Aes256.initEnc(key_iv[0..32].*);
    var ctr: u128 = std.mem.readInt(u128, key_iv[32..48], .big);
    var off: usize = 0;
    while (off < sec_len) : (off += 16) {
        var blk: [16]u8 = undefined;
        std.mem.writeInt(u128, &blk, ctr, .big);
        var ks: [16]u8 = undefined;
        ectx.encrypt(&ks, &blk);
        ctr +%= 1;
        for (sec[off..][0..16], ks) |*b, k| b.* ^= k;
    }

    var bin: [2048]u8 = undefined;
    var bw = Wr{ .buf = &bin };
    bw.raw("openssh-key-v1\x00");
    bw.str("aes256-ctr");
    bw.str("bcrypt");
    bw.str(&kdfoptions);
    bw.u32be(1);
    bw.str("ssh-rsa");
    bw.str(sec[0..sec_len]);

    const hdr = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    const ftr = "-----END OPENSSH PRIVATE KEY-----\n";
    var pw = Wr{ .buf = &os_pem };
    pw.raw(hdr);
    var b64: [2800]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&b64, bin[0..bw.n]);
    var i: usize = 0;
    while (i < enc.len) : (i += 70) {
        pw.raw(enc[i..@min(i + 70, enc.len)]);
        pw.raw("\n");
    }
    pw.raw(ftr);
    os_pem_len = pw.n;

    // Positive check of the fixture: the container loads and is the KAT key.
    try fromOpenSSHW(&os_key);
    var n_chk: [256]u8 = undefined;
    try os_key.n.toBytes(&n_chk, .big);
    try std.testing.expectEqualSlices(u8, &kat_n, &n_chk);
    os_key.deinit();

    var p_le = kat_p;
    std.mem.reverse(u8, &p_le);
    var q_le = kat_q;
    std.mem.reverse(u8, &q_le);
    var dp_be: [128]u8 = undefined;
    var dq_be: [128]u8 = undefined;
    try os_secret.dp.toBytes(&dp_be, .big);
    try os_secret.dq.toBytes(&dq_be, .big);
    const needles = [_][]const u8{
        &kat_p,                             &kat_q,                             &p_le,                          &q_le,
        &d_be,                              &dp_be,                             &dq_be,                         &qinv_be,
        std.mem.asBytes(&os_secret.d),      std.mem.asBytes(&os_secret.dp),     std.mem.asBytes(&os_secret.dq), std.mem.asBytes(&os_secret.qinv),
        std.mem.asBytes(&os_secret.p_mont), std.mem.asBytes(&os_secret.q_mont), key_iv[0..32],                  key_iv[32..48],
        enc_sched[32..],                    passphrase,
    };
    _ = try Pk.run("fromOpenSSH aes256-ctr", fromOpenSSHW, .{&os_key}, &needles, .{});
    os_key.deinit();
}
