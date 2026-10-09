// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for every secret-touching entry
//! point: Initial secrets, packet-key derivation and key update (one-shot
//! per epoch) and the per-packet work (AEAD seal/open, header-protection
//! masks). ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the
//! body is type-checked in every mode). Generic entry points go through
//! non-generic wrappers that fix the suite; the wrappers hold no secret by
//! value.

const std = @import("std");
const sp = @import("testkit").stackprobe;
const initial = @import("initial.zig");
const keyschedule = @import("keyschedule.zig");
const headerprot = @import("headerprot.zig");
const protection = @import("protection.zig");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Gcm = protection.Protection(std.crypto.aead.aes_gcm.Aes128Gcm);
const Chacha = protection.Protection(std.crypto.aead.chacha_poly.ChaCha20Poly1305);
const Keys16 = keyschedule.PacketKeys(16);
const Keys32 = keyschedule.PacketKeys(32);
const Ku = keyschedule.KeyUpdate(Hkdf, 32);

const P = sp.Probe(.{ .window = 64 * 1024 });

var secret: [32]u8 = undefined;
var key16: [16]u8 = undefined;
var key32: [32]u8 = undefined;
var iv: [12]u8 = undefined;
var dcid: [8]u8 = undefined;
var sample: [16]u8 = undefined;
var isec: initial.InitialSecrets = undefined;
var k16: Keys16 = undefined;
var k32: Keys32 = undefined;
var ku: Ku = undefined;
var pt: [120]u8 = undefined;
var ct: [120 + 16]u8 = undefined;
var back: [120]u8 = undefined;
var hdr: [22]u8 = undefined;

fn fill() void {
    std.crypto.hash.sha2.Sha256.hash("quic-crypto probe secret", &secret, .{});
    std.crypto.hash.sha2.Sha256.hash("quic-crypto probe key", &key32, .{});
    @memcpy(&key16, key32[0..16]);
    @memcpy(&iv, secret[0..12]);
    @memcpy(&dcid, secret[12..20]);
    @memcpy(&sample, secret[16..32]); // public sample must not overlap any key under test
    @memset(&pt, 0x5a);
    @memset(&hdr, 0xc3);
}

fn initWrap(o: *initial.InitialSecrets, d: []const u8) void {
    initial.deriveInitialSecrets(o, d);
}
fn initV2Wrap(o: *initial.InitialSecrets, d: []const u8) void {
    initial.deriveInitialSecretsFor(.v2, o, d);
}
fn keys16Wrap(o: *Keys16, s: *const [32]u8) void {
    keyschedule.derivePacketKeys(Hkdf, 16, o, s);
}
fn keys32V2Wrap(o: *Keys32, s: *const [32]u8) void {
    keyschedule.derivePacketKeysFor(.v2, Hkdf, 32, o, s);
}
fn advanceWrap(o: *Ku, s: *const [32]u8) void {
    keyschedule.advanceKeys(Hkdf, 32, o, s);
}
fn advanceV2Wrap(o: *Ku, s: *const [32]u8) void {
    keyschedule.advanceKeysFor(.v2, Hkdf, 32, o, s);
}
var mask_out: headerprot.Mask = undefined;
fn maskAes(k: []const u8, s: [16]u8) void {
    mask_out = headerprot.computeMaskAes(k, s);
}
fn maskChacha(k: []const u8, s: [16]u8) void {
    mask_out = headerprot.computeMaskChaCha20(k, s);
}
fn gcmSeal(k: *const [16]u8, p: []const u8, o: []u8) !usize {
    return Gcm.seal(k, iv, 7, &hdr, p, o);
}
fn gcmOpen(k: *const [16]u8, c: []const u8, o: []u8) !usize {
    return Gcm.open(k, iv, 7, &hdr, c, o);
}
fn chachaSeal(k: *const [32]u8, p: []const u8, o: []u8) !usize {
    return Chacha.seal(k, iv, 7, &hdr, p, o);
}
fn chachaOpen(k: *const [32]u8, c: []const u8, o: []u8) !usize {
    return Chacha.open(k, iv, 7, &hdr, c, o);
}

test "STACKPROBE: key derivation and key update leave no secret residue" {
    try sp.skipUnlessOptimized();
    fill();

    _ = try P.run("deriveInitialSecrets", initWrap, .{ &isec, &dcid }, &.{std.mem.asBytes(&isec)}, .{});
    _ = try P.run("deriveInitialSecretsFor v2", initV2Wrap, .{ &isec, &dcid }, &.{std.mem.asBytes(&isec)}, .{});
    _ = try P.run("derivePacketKeys", keys16Wrap, .{ &k16, &secret }, &.{ &secret, std.mem.asBytes(&k16) }, .{});
    _ = try P.run("derivePacketKeysFor v2 32", keys32V2Wrap, .{ &k32, &secret }, &.{ &secret, std.mem.asBytes(&k32) }, .{});
    _ = try P.run("advanceKeys", advanceWrap, .{ &ku, &secret }, &.{ &secret, std.mem.asBytes(&ku) }, .{});
    _ = try P.run("advanceKeysFor v2", advanceV2Wrap, .{ &ku, &secret }, &.{ &secret, std.mem.asBytes(&ku) }, .{});
}

test "STACKPROBE: per-packet AEAD and header-protection masks leave no key residue" {
    try sp.skipUnlessOptimized();
    fill();

    _ = try P.run("Protection(Aes128Gcm).seal", gcmSeal, .{ &key16, &pt, &ct }, &.{&key16}, .{});
    const n1 = try gcmSeal(&key16, &pt, &ct);
    _ = try P.run("Protection(Aes128Gcm).open", gcmOpen, .{ &key16, ct[0..n1], &back }, &.{&key16}, .{});
    _ = try P.run("Protection(ChaCha20Poly1305).seal", chachaSeal, .{ &key32, &pt, &ct }, &.{&key32}, .{});
    const n2 = try chachaSeal(&key32, &pt, &ct);
    _ = try P.run("Protection(ChaCha20Poly1305).open", chachaOpen, .{ &key32, ct[0..n2], &back }, &.{&key32}, .{});

    _ = try P.run("computeMaskAes 128", maskAes, .{ @as([]const u8, &key16), sample }, &.{&key16}, .{});
    _ = try P.run("computeMaskAes 256", maskAes, .{ @as([]const u8, &key32), sample }, &.{&key32}, .{});
    _ = try P.run("computeMaskChaCha20", maskChacha, .{ @as([]const u8, &key32), sample }, &.{&key32}, .{});
}
