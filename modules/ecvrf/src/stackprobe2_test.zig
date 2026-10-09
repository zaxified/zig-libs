// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the entry points burned
//! 2026-10-09: `secretScalar`, `nonceGenerationString`, `nonceGeneration`
//! (the other entry points are in `stackprobe_test.zig`). One-shot calls,
//! SHA-512 only: key-sized burn. ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const ev = @import("ecvrf.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var sk: ev.SecretKey = undefined;
var h_string: ev.PublicKey = undefined;
var x: [32]u8 = undefined;
var k_string: [64]u8 = undefined;
var k: [32]u8 = undefined;

test "STACKPROBE: secretScalar and nonce generation leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("ecvrf probe2 sk", &sk, .{});
    std.crypto.hash.sha2.Sha256.hash("ecvrf probe2 h", &h_string, .{});
    _ = try P.run("secretScalar", ev.secretScalar, .{ &x, &sk }, &.{ &sk, &x }, .{});
    _ = try P.run("nonceGenerationString", ev.nonceGenerationString, .{ &k_string, &sk, h_string }, &.{ &sk, &k_string }, .{});
    _ = try P.run("nonceGeneration", ev.nonceGeneration, .{ &k, &sk, h_string }, &.{ &sk, &k }, .{});
}
