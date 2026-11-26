// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of the key-management and content
//! encryption primitives the older probes do not call: `alg.dirCek`,
//! `alg.rsaOaepWrap` / `rsaOaepUnwrap`, `alg.gcmkwWrap` / `gcmkwUnwrap`,
//! `enc.encrypt` / `enc.decrypt` (AES-GCM and AES-CBC-HMAC) and
//! `enc.cbc_hmac.encrypt` / `decrypt`. Residue below each burn; needles: the
//! CEK, the KEK, the RSA primes, the plaintext. ReleaseFast/ReleaseSmall only.
//! Coverage sweep 2026-11-26.

const std = @import("std");
const jwe = @import("root.zig");
const rsa = @import("rsa");
const sp = @import("testkit").stackprobe;

const alg = jwe.alg;
const enc = jwe.enc;
const P = sp.Probe(.{ .window = 512 * 1024, .max_windows = 1 << 17 });

// rsa's own 2048-bit KAT key (public in this repository).
const kat_p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
const kat_q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
const kat_e = [_]u8{ 0x01, 0x00, 0x01 };

fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    var b: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&b, hex) catch unreachable;
    return b;
}

var sk: rsa.SecretKey = undefined;
var cek: [64]u8 = undefined;
var kek: [32]u8 = undefined;
var shared: [32]u8 = undefined;
var cek_out: [64]u8 = undefined;
var wrapped: [512]u8 = undefined;
var wrapped_len: usize = 0;
var tag: [16]u8 = undefined;
var tag64: [32]u8 = undefined;
var pt: [48]u8 = undefined;
var ct: [64]u8 = undefined;
var pt_out: [64]u8 = undefined;
var ct_len: usize = 0;
var prng: std.Random.DefaultPrng = .init(5);
const iv12 = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
const iv16 = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

fn oaepWrapW(pk: rsa.PublicKey, out: []u8) !void {
    _ = try alg.rsaOaepWrap(pk, .sha256, .{ .csprng = prng.random() }, cek[0..32], out);
}
fn oaepUnwrapW(k: *const rsa.SecretKey, out: []u8) !void {
    _ = try alg.rsaOaepUnwrap(k, .sha256, wrapped[0..wrapped_len], out);
}
fn gcmkwWrapW(out: []u8, t: *[16]u8) !void {
    _ = try alg.gcmkwWrap(&kek, iv12, cek[0..32], out, t);
}
fn gcmkwUnwrapW(out: []u8) !void {
    _ = try alg.gcmkwUnwrap(&kek, iv12, tag, wrapped[0..32], out);
}
fn encGcmW(out: []u8, t: []u8) !void {
    _ = try enc.encrypt(.A256GCM, cek[0..32], &iv12, "aad", &pt, out, t);
}
fn decGcmW(out: []u8) !void {
    _ = try enc.decrypt(.A256GCM, cek[0..32], &iv12, "aad", ct[0..pt.len], &tag, out);
}
fn encCbcW(out: []u8, t: []u8) !void {
    _ = try enc.encrypt(.@"A128CBC-HS256", cek[0..32], &iv16, "aad", &pt, out, t);
}
fn decCbcW(out: []u8) !void {
    _ = try enc.decrypt(.@"A128CBC-HS256", cek[0..32], &iv16, "aad", ct[0..ct_len], tag64[0..16], out);
}
fn cbcEncW(out: []u8, t: []u8) !void {
    _ = try enc.cbc_hmac.encrypt(.@"A256CBC-HS512", cek[0..64], &iv16, "aad", &pt, out, t);
}
fn cbcDecW(out: []u8) !void {
    _ = try enc.cbc_hmac.decrypt(.@"A256CBC-HS512", cek[0..64], &iv16, "aad", ct[0..ct_len], tag64[0..32], out);
}

test "STACKPROBE: jwe key-management and content-encryption primitives leave no key or plaintext on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha512.hash("jwe probe3 cek", &cek, .{});
    std.crypto.hash.sha2.Sha256.hash("jwe probe3 kek", &kek, .{});
    std.crypto.hash.sha2.Sha256.hash("jwe probe3 shared", &shared, .{});
    var ph: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("jwe probe3 plaintext", &ph, .{});
    pt = ph[0..48].*;
    try rsa.SecretKey.fromPrimes(&sk, &kat_p, &kat_q, &kat_e);
    defer sk.deinit();
    const pk = sk.publicKey();
    var p_le = kat_p;
    std.mem.reverse(u8, &p_le);
    var q_le = kat_q;
    std.mem.reverse(u8, &q_le);

    // `dirCek` is a length check and a copy (no burn by design): the needles are the check.
    _ = try P.run("alg.dirCek", alg.dirCek, .{ @as([]const u8, &shared), 32, @as([]u8, &cek_out) }, &.{ &shared, cek_out[0..32] }, .{ .burn = false });

    _ = try P.run("alg.rsaOaepWrap", oaepWrapW, .{ pk, @as([]u8, &wrapped) }, &.{cek[0..32]}, .{});
    wrapped_len = (try alg.rsaOaepWrap(pk, .sha256, .{ .csprng = prng.random() }, cek[0..32], &wrapped)).len;
    _ = try P.run("alg.rsaOaepUnwrap", oaepUnwrapW, .{ &sk, @as([]u8, &cek_out) }, &.{ cek[0..32], &kat_p, &kat_q, &p_le, &q_le }, .{});

    _ = try P.run("alg.gcmkwWrap", gcmkwWrapW, .{ @as([]u8, &wrapped), &tag }, &.{ cek[0..32], &kek }, .{});
    _ = try alg.gcmkwWrap(&kek, iv12, cek[0..32], &wrapped, &tag);
    _ = try P.run("alg.gcmkwUnwrap", gcmkwUnwrapW, .{@as([]u8, &cek_out)}, &.{ cek[0..32], &kek }, .{});

    _ = try P.run("enc.encrypt A256GCM", encGcmW, .{ @as([]u8, &ct), @as([]u8, &tag) }, &.{ cek[0..32], &pt }, .{});
    _ = try enc.encrypt(.A256GCM, cek[0..32], &iv12, "aad", &pt, &ct, &tag);
    _ = try P.run("enc.decrypt A256GCM", decGcmW, .{@as([]u8, &pt_out)}, &.{ cek[0..32], &pt }, .{});

    _ = try P.run("enc.encrypt A128CBC-HS256", encCbcW, .{ @as([]u8, &ct), tag64[0..16] }, &.{ cek[0..32], &pt }, .{});
    ct_len = try enc.encrypt(.@"A128CBC-HS256", cek[0..32], &iv16, "aad", &pt, &ct, tag64[0..16]);
    _ = try P.run("enc.decrypt A128CBC-HS256", decCbcW, .{@as([]u8, &pt_out)}, &.{ cek[0..32], &pt }, .{});

    _ = try P.run("enc.cbc_hmac.encrypt A256CBC-HS512", cbcEncW, .{ @as([]u8, &ct), tag64[0..32] }, &.{ &cek, &pt }, .{});
    ct_len = try enc.cbc_hmac.encrypt(.@"A256CBC-HS512", &cek, &iv16, "aad", &pt, &ct, tag64[0..32]);
    _ = try P.run("enc.cbc_hmac.decrypt A256CBC-HS512", cbcDecW, .{@as([]u8, &pt_out)}, &.{ &cek, &pt }, .{});
}
