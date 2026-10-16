// SPDX-License-Identifier: MIT

//! Dead-stack probe for the keyed entry points (`testkit.stackprobe`): residue
//! below each burn, and the AES key as a needle in any frame. ReleaseFast only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in
//! every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

const P = sp.Probe(.{ .window = 64 * 1024 });

var key: [32]u8 = undefined;
var ct: [1024]u8 = undefined;
var pt: [1024]u8 = undefined;
const msg: [1024]u8 = @splat(0x5a);
const iv: [16]u8 = @splat(3);

// `root.encrypt`/`decrypt` are generic over the cipher, which the engine cannot
// take as a function type; these wrappers hold pointers only.
fn enc(comptime Aes: type) fn (*const [Aes.key_bits / 8]u8, [16]u8, []const u8, []u8) root.Error!usize {
    return struct {
        fn f(k: *const [Aes.key_bits / 8]u8, v: [16]u8, in: []const u8, out: []u8) root.Error!usize {
            return root.encrypt(Aes, k, v, in, out);
        }
    }.f;
}

fn dec(comptime Aes: type) fn (*const [Aes.key_bits / 8]u8, [16]u8, []const u8, []u8) root.Error!usize {
    return struct {
        fn f(k: *const [Aes.key_bits / 8]u8, v: [16]u8, in: []const u8, out: []u8) root.Error!usize {
            return root.decrypt(Aes, k, v, in, out);
        }
    }.f;
}

fn ctsEnc256(k: *const [32]u8, v: [16]u8, in: []const u8, out: []u8) root.CtsError!usize {
    return root.encryptCts(Aes256, .cs3, k, v, in, out);
}
fn ctsDec256(k: *const [32]u8, v: [16]u8, in: []const u8, out: []u8) root.CtsError!usize {
    return root.decryptCts(Aes256, .cs3, k, v, in, out);
}

test "STACKPROBE: no key residue after encryptCts or decryptCts" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("aescbc probe key", &key, .{});
    // 1000 octets: a partial last block, so the stealing path runs.
    _ = try P.run("encryptCts Aes256", ctsEnc256, .{ &key, iv, msg[0..1000], &ct }, &.{&key}, .{});
    _ = try P.run("decryptCts Aes256", ctsDec256, .{ &key, iv, ct[0..1000], &pt }, &.{&key}, .{});
    try std.testing.expectEqualSlices(u8, msg[0..1000], pt[0..1000]);
}

var enc256: root.Encryptor(Aes256) = undefined;
var dec256: root.Decryptor(Aes256) = undefined;

fn initEnc256(k: *const [32]u8, v: [16]u8) void {
    enc256.initInto(k, v);
}
fn initDec256(k: *const [32]u8, v: [16]u8) void {
    dec256.initInto(k, v);
}
fn show(r: sp.Report) void {
    std.debug.print("  dirty {d} burn_top {d} burn_len {d} residue {d}\n", .{ r.dirty_depth, r.burn_top, r.burn_len, r.residue_bytes });
}
fn updEnc256(in: []const u8, out: []u8) root.Error!usize {
    return enc256.update(in, out);
}
fn updDec256(in: []const u8, out: []u8) root.Error!usize {
    return dec256.update(in, out);
}

test "STACKPROBE: Encryptor/Decryptor init (key schedule) and update (block loop)" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("aescbc probe key", &key, .{});
    // `init` holds the key: SCHEDULE burn (`burn.schedule_burn`).
    show(try P.run("Encryptor(Aes256).initInto", initEnc256, .{ &key, iv }, &.{&key}, .{}));
    show(try P.run("Decryptor(Aes256).initInto", initDec256, .{ &key, iv }, &.{&key}, .{}));
    // `update` runs over the caller's round keys: UPDATE burn (`burn.update_burn`).
    show(try P.run("Encryptor(Aes256).update", updEnc256, .{ &msg, &ct }, &.{&key}, .{}));
    show(try P.run("Decryptor(Aes256).update", updDec256, .{ &ct, &pt }, &.{&key}, .{}));
}

test "STACKPROBE: no AES-CBC key residue after encrypt or decrypt" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("aescbc probe key", &key, .{});
    const k128: *const [16]u8 = key[0..16];

    // Per-message calls on the data path: TIGHT burn (`burn.cbc_burn`).
    _ = try P.run("encrypt Aes256", enc(Aes256), .{ &key, iv, &msg, &ct }, &.{&key}, .{});
    _ = try P.run("decrypt Aes256", dec(Aes256), .{ &key, iv, &ct, &pt }, &.{&key}, .{});
    try std.testing.expectEqualSlices(u8, &msg, &pt);
    _ = try P.run("encrypt Aes128", enc(Aes128), .{ k128, iv, &msg, &ct }, &.{k128}, .{});
    _ = try P.run("decrypt Aes128", dec(Aes128), .{ k128, iv, &ct, &pt }, &.{k128}, .{});
    try std.testing.expectEqualSlices(u8, &msg, &pt);
}
