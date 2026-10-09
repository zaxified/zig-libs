// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the PUBLIC building blocks:
//! `keyschedule.*` and the record-protection / sequence-number helpers of
//! `aead.zig`. The handshake-level sweep lives in `stackprobe_test.zig`
//! (older engine, untouched). ReleaseFast only (`skipUnlessOptimized`, a
//! runtime skip, so the body is type-checked in every mode).
//!
//! Generic entry points are probed through non-generic wrappers that fix the
//! suite (SHA-256 / AES-128-GCM / ChaCha20-Poly1305); the wrappers hold no
//! secret by value.

const std = @import("std");
const sp = @import("testkit").stackprobe;
const keyschedule = @import("keyschedule.zig");
const aead = @import("aead.zig");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const P = sp.Probe(.{ .window = 64 * 1024 });

var secret: [32]u8 = undefined;
var secret2: [32]u8 = undefined;
var psk: [40]u8 = undefined;
var out: [32]u8 = undefined;
var out2: [32]u8 = undefined;
var out16: [16]u8 = undefined;
var out12: [12]u8 = undefined;
var th: [32]u8 = undefined;
var dhe: [32]u8 = undefined;
var key16: [16]u8 = undefined;
var key32: [32]u8 = undefined;
var iv: [12]u8 = undefined;
var seq: [2]u8 = undefined;
var sample: [16]u8 = undefined;
var pt: [200]u8 = undefined;
var ct: [200 + 16]u8 = undefined;
var back: [200]u8 = undefined;

fn fill() void {
    std.crypto.hash.sha2.Sha256.hash("dtls probe secret", &secret, .{});
    std.crypto.hash.sha2.Sha256.hash("dtls probe secret 2", &secret2, .{});
    std.crypto.hash.sha2.Sha256.hash("dtls probe transcript", &th, .{});
    std.crypto.hash.sha2.Sha256.hash("dtls probe dhe", &dhe, .{});
    std.crypto.hash.sha2.Sha256.hash("dtls probe key", &key32, .{});
    @memcpy(&key16, key32[0..16]);
    @memcpy(&iv, secret2[0..12]);
    @memcpy(psk[0..32], &secret2);
    @memcpy(psk[32..], "probepsk");
    @memcpy(&sample, secret[0..16]);
    seq = .{ 0x12, 0x34 };
    @memset(&pt, 0x5a);
}

fn expandWrap(o: *[32]u8, s: *const [32]u8, th_: []const u8) void {
    keyschedule.expandLabel(Hkdf, keyschedule.tls13_prefix, 32, o, s, "derived", th_);
}
fn hkdfWrap(o: *[16]u8, s: *const [32]u8) void {
    keyschedule.hkdfExpandLabel(Hkdf, 16, o, s, "key", "");
}
fn deriveSecretWrap(o: *[32]u8, s: *const [32]u8, th_: []const u8) void {
    keyschedule.deriveSecret(Hkdf, o, s, "c ap traffic", th_);
}
fn earlyWrap(o: *[32]u8, p: []const u8) void {
    keyschedule.earlySecret(Hkdf, o, p);
}
fn binderKeyWrap(o: *[32]u8, es: *const [32]u8, th_: []const u8) void {
    keyschedule.binderKey(Hkdf, o, es, th_);
}
fn binderWrap(o: *[32]u8, bk: *const [32]u8, th_: []const u8) void {
    keyschedule.pskBinder(Hkdf, Hmac, o, bk, th_);
}
fn hsWrap(o: *[32]u8, es: *const [32]u8, th_: []const u8, d: ?[]const u8) void {
    keyschedule.deriveHandshakeSecret(Hkdf, o, es, th_, d);
}
fn hsTrafficWrap(c: *[32]u8, s: *[32]u8, hs: *const [32]u8, th_: []const u8) void {
    keyschedule.deriveHandshakeTrafficSecrets(Hkdf, c, s, hs, th_);
}
fn masterWrap(o: *[32]u8, hs: *const [32]u8, th_: []const u8) void {
    keyschedule.deriveMasterSecret(Hkdf, o, hs, th_);
}
fn apTrafficWrap(c: *[32]u8, s: *[32]u8, ms: *const [32]u8, th_: []const u8) void {
    keyschedule.deriveApplicationTrafficSecrets(Hkdf, c, s, ms, th_);
}
fn finishedKeyWrap(o: *[32]u8, ts: *const [32]u8) void {
    keyschedule.deriveFinishedKey(Hkdf, 32, o, ts);
}
fn verifyDataWrap(o: *[32]u8, fk: *const [32]u8, th_: []const u8) void {
    keyschedule.computeFinishedVerifyData(Hmac, o, fk, th_);
}
fn keyIvWrap(k: *[16]u8, i: *[12]u8, ts: *const [32]u8) void {
    keyschedule.deriveTrafficKeyIv(Hkdf, 16, 12, k, i, ts);
}
fn snKeyWrap(o: *[16]u8, ts: *const [32]u8) void {
    keyschedule.deriveSequenceNumberKey(Hkdf, 16, o, ts);
}

const Gcm = aead.Protection(std.crypto.aead.aes_gcm.Aes128Gcm);
const Chacha = aead.Protection(std.crypto.aead.chacha_poly.ChaCha20Poly1305);

fn gcmSeal(k: *const [16]u8, n: [12]u8, p: []const u8, o: []u8) !usize {
    return Gcm.protect(k, n, 2, 7, p, "hdr", o);
}
fn gcmOpen(k: *const [16]u8, n: [12]u8, c: []const u8, o: []u8) !usize {
    return Gcm.unprotect(k, n, 2, 7, c, "hdr", o);
}
fn chachaSeal(k: *const [32]u8, n: [12]u8, p: []const u8, o: []u8) !usize {
    return Chacha.protect(k, n, 2, 7, p, "hdr", o);
}
fn chachaOpen(k: *const [32]u8, n: [12]u8, c: []const u8, o: []u8) !usize {
    return Chacha.unprotect(k, n, 2, 7, c, "hdr", o);
}

test "STACKPROBE: keyschedule building blocks leave no secret residue" {
    try sp.skipUnlessOptimized();
    fill();

    _ = try P.run("expandLabel", expandWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("hkdfExpandLabel", hkdfWrap, .{ &out16, &secret }, &.{ &secret, &out16 }, .{});
    _ = try P.run("deriveSecret", deriveSecretWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("earlySecret", earlyWrap, .{ &out, &psk }, &.{ &psk, &out }, .{});
    _ = try P.run("binderKey", binderKeyWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("pskBinder", binderWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("deriveHandshakeSecret psk_ke", hsWrap, .{ &out, &secret, &th, null }, &.{ &secret, &out }, .{});
    _ = try P.run("deriveHandshakeSecret psk_dhe_ke", hsWrap, .{ &out, &secret, &th, @as(?[]const u8, &dhe) }, &.{ &secret, &dhe, &out }, .{});
    _ = try P.run("deriveHandshakeTrafficSecrets", hsTrafficWrap, .{ &out, &out2, &secret, &th }, &.{ &secret, &out, &out2 }, .{});
    _ = try P.run("deriveMasterSecret", masterWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("deriveApplicationTrafficSecrets", apTrafficWrap, .{ &out, &out2, &secret, &th }, &.{ &secret, &out, &out2 }, .{});
    _ = try P.run("deriveFinishedKey", finishedKeyWrap, .{ &out, &secret }, &.{ &secret, &out }, .{});
    _ = try P.run("computeFinishedVerifyData", verifyDataWrap, .{ &out, &secret, &th }, &.{ &secret, &out }, .{});
    _ = try P.run("deriveTrafficKeyIv", keyIvWrap, .{ &out16, &out12, &secret }, &.{ &secret, &out16, &out12 }, .{});
    _ = try P.run("deriveSequenceNumberKey", snKeyWrap, .{ &out16, &secret }, &.{ &secret, &out16 }, .{});
}

test "STACKPROBE: record protection and sequence-number masks leave no key residue" {
    try sp.skipUnlessOptimized();
    fill();

    _ = try P.run("Protection(Aes128Gcm).protect", gcmSeal, .{ &key16, iv, &pt, &ct }, &.{&key16}, .{});
    const sealed = try gcmSeal(&key16, iv, &pt, &ct);
    _ = try P.run("Protection(Aes128Gcm).unprotect", gcmOpen, .{ &key16, iv, ct[0..sealed], &back }, &.{&key16}, .{});
    _ = try P.run("Protection(ChaCha20Poly1305).protect", chachaSeal, .{ &key32, iv, &pt, &ct }, &.{&key32}, .{});
    const sealed2 = try chachaSeal(&key32, iv, &pt, &ct);
    _ = try P.run("Protection(ChaCha20Poly1305).unprotect", chachaOpen, .{ &key32, iv, ct[0..sealed2], &back }, &.{&key32}, .{});

    _ = try P.run("encryptSequenceNumberAes 128", aead.encryptSequenceNumberAes, .{ @as([]const u8, &key16), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key16}, .{});
    _ = try P.run("encryptSequenceNumberAes 256", aead.encryptSequenceNumberAes, .{ @as([]const u8, &key32), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key32}, .{});
    _ = try P.run("encryptSequenceNumberChaCha20", aead.encryptSequenceNumberChaCha20, .{ @as([]const u8, &key32), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key32}, .{});
    _ = try P.run("decryptSequenceNumberAes", aead.decryptSequenceNumberAes, .{ @as([]const u8, &key16), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key16}, .{});
    _ = try P.run("decryptSequenceNumberChaCha20", aead.decryptSequenceNumberChaCha20, .{ @as([]const u8, &key32), @as([]const u8, &sample), @as([]u8, &seq) }, &.{&key32}, .{});
}
