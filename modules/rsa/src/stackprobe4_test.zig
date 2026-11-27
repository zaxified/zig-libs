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
