// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the X25519 key-generation
//! entry points added to the burn set 2026-10-09: `recoverPublicKeyInto`,
//! `KeyPair.generateDeterministicInto`, `KeyPair.generateInto` (the std-shaped
//! by-value wrappers call these). One-shot calls, so a generous burn.
//! ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;
const X25519 = root.X25519;

const P = sp.Probe(.{ .window = 64 * 1024 });

var seed: [32]u8 = undefined;
var out_pub: [32]u8 = undefined;
var kp: X25519.KeyPair = undefined;

test "STACKPROBE: X25519 key generation leaves no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("ct25519 probe2 seed", &seed, .{});
    _ = try P.run("X25519.recoverPublicKeyInto", X25519.recoverPublicKeyInto, .{ &out_pub, &seed }, &.{&seed}, .{});
    _ = try P.run("X25519.KeyPair.generateDeterministicInto", X25519.KeyPair.generateDeterministicInto, .{ &kp, &seed }, &.{ &seed, std.mem.asBytes(&kp) }, .{});
    _ = try P.run("X25519.KeyPair.generateInto", X25519.KeyPair.generateInto, .{ &kp, std.testing.io }, &.{std.mem.asBytes(&kp)}, .{});
}
