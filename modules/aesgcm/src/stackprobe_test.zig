// SPDX-License-Identifier: MIT

//! Dead-stack probe for the keyed entry points (`testkit.stackprobe`): residue
//! below each burn, and the key / the derived context as needles in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode).
//!
//! Only the pointer forms (`…Into`) are probed: the by-value `init`/`initWith`
//! return the `Context` (round keys) in the caller's result slot and
//! `encrypt`/`decrypt` take the key by value, so the engine would -- rightly --
//! find the key in the probe's own call frame. They are burned all the same.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var key: [32]u8 = undefined;
var ctx256: root.Aes256Gcm.Context = undefined;
var ctx128: root.Aes128Gcm.Context = undefined;
var ctx192: root.Aes192Gcm.Context = undefined;
var tag: [16]u8 = undefined;
var ct: [1024]u8 = undefined;
var pt: [1024]u8 = undefined;
const msg: [1024]u8 = @splat(0x5a);
const ad = "dead-stack probe";
const nonce: [12]u8 = @splat(7);

test "STACKPROBE: no AES-GCM key or round-key residue after any entry point" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("aesgcm probe key", &key, .{});
    const k128: *const [16]u8 = key[0..16];
    const ks = &[_][]const u8{&key};

    // Per-message calls on the data path: TIGHT burns (`burn.msg_burn`).
    _ = try P.run("Aes256Gcm.initInto", root.Aes256Gcm.initInto, .{ &ctx256, &key }, &.{ &key, std.mem.asBytes(&ctx256) }, .{});
    _ = try P.run("Aes128Gcm.initInto", root.Aes128Gcm.initInto, .{ &ctx128, k128 }, &.{ k128, std.mem.asBytes(&ctx128) }, .{});
    _ = try P.run("Aes256Gcm.initWithInto generic", root.Aes256Gcm.initWithInto, .{ &ctx256, .generic, &key }, &.{ &key, std.mem.asBytes(&ctx256) }, .{});
    if (root.available(.aesni))
        _ = try P.run("Aes256Gcm.initWithInto aesni", root.Aes256Gcm.initWithInto, .{ &ctx256, .aesni, &key }, &.{ &key, std.mem.asBytes(&ctx256) }, .{});

    _ = try P.run("Aes256Gcm.encryptInto", root.Aes256Gcm.encryptInto, .{ &ct, &tag, &msg, ad, nonce, &key }, ks, .{});
    _ = try P.run("Aes256Gcm.decryptInto", root.Aes256Gcm.decryptInto, .{ &pt, &ct, tag, ad, nonce, &key }, ks, .{});
    try std.testing.expectEqualSlices(u8, &msg, &pt);
    _ = try P.run("Aes128Gcm.encryptInto", root.Aes128Gcm.encryptInto, .{ &ct, &tag, &msg, ad, nonce, k128 }, &.{k128}, .{});
    _ = try P.run("Aes128Gcm.decryptInto", root.Aes128Gcm.decryptInto, .{ &pt, &ct, tag, ad, nonce, k128 }, &.{k128}, .{});
    try std.testing.expectEqualSlices(u8, &msg, &pt);

    // AES-192 (2026-10-10): both backends' key schedules and the stateless pair.
    const k192: *const [24]u8 = key[0..24];
    _ = try P.run("Aes192Gcm.initWithInto generic", root.Aes192Gcm.initWithInto, .{ &ctx192, .generic, k192 }, &.{ k192, std.mem.asBytes(&ctx192) }, .{});
    if (root.available(.aesni))
        _ = try P.run("Aes192Gcm.initWithInto aesni", root.Aes192Gcm.initWithInto, .{ &ctx192, .aesni, k192 }, &.{ k192, std.mem.asBytes(&ctx192) }, .{});
    _ = try P.run("Aes192Gcm.encryptInto", root.Aes192Gcm.encryptInto, .{ &ct, &tag, &msg, ad, nonce, k192 }, &.{k192}, .{});
    _ = try P.run("Aes192Gcm.decryptInto", root.Aes192Gcm.decryptInto, .{ &pt, &ct, tag, ad, nonce, k192 }, &.{k192}, .{});
    try std.testing.expectEqualSlices(u8, &msg, &pt);
}
