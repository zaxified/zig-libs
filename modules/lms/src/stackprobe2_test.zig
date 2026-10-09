// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the public building blocks
//! `core.deriveX` and `core.deriveRandomizer` burned 2026-10-09 (the tree and
//! signing entry points are in `stackprobe_test.zig`). Per-chain calls on the
//! signing path: tight burn (`derive_burn`). ReleaseFast only
//! (`skipUnlessOptimized`).

const std = @import("std");
const core = @import("core.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 16 * 1024 });

var id: [16]u8 = undefined;
var seed: [32]u8 = undefined;
var x: [32]u8 = undefined;

test "STACKPROBE: deriveX and deriveRandomizer leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("lms probe2 seed", &seed, .{});
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("lms probe2 id", &h, .{});
    @memcpy(&id, h[0..16]);
    _ = try P.run("core.deriveX", core.deriveX, .{ &x, &id, @as(u32, 3), @as(u16, 5), &seed }, &.{ &seed, &x }, .{});
    const c = try P.run("core.deriveRandomizer", core.deriveRandomizer, .{ &id, @as(u32, 3), &seed }, &.{&seed}, .{});
    _ = c;
}
