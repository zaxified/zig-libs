// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the Ed448 key-generation entry
//! points added 2026-10-09: `KeyPair.createInto`, `KeyPair.generateInto` (the
//! std-shaped by-value `create` / `generate` call these). One-shot calls, so a
//! generous burn (`sign_burn`). ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const ed = @import("ed448.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 96 * 1024 });

var seed: [57]u8 = undefined;
var kp: ed.KeyPair = undefined;

test "STACKPROBE: Ed448 key generation leaves no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("ed448 probe2 seed", seed[0..32], .{});
    var tail: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ed448 probe2 seed tail", &tail, .{});
    @memcpy(seed[32..], tail[0..25]);
    _ = try P.run("KeyPair.createInto", ed.KeyPair.createInto, .{ &kp, &seed }, &.{ &seed, std.mem.asBytes(&kp.secret_key) }, .{});
    _ = try P.run("KeyPair.generateInto", ed.KeyPair.generateInto, .{ &kp, std.testing.io }, &.{std.mem.asBytes(&kp.secret_key)}, .{});
}
