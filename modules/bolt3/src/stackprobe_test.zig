// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the three secret entry points:
//! residue below each burn, and the secret inputs / `out` buffers as needles in
//! any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the
//! body is type-checked in every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

// Window above the deepest burn (32 KiB one-shot ECC).
const P = sp.Probe(.{ .window = 64 * 1024 });

var base_secret: [32]u8 = undefined;
var pcs: [32]u8 = undefined;
var seed: [32]u8 = undefined;
var out: [32]u8 = undefined;

test "STACKPROBE: bolt3 key derivations leave no secret in any frame" {
    try sp.skipUnlessOptimized();
    // Distinct, canonical (< n: top byte 0) scalars.
    for (&base_secret, 0..) |*b, i| b.* = @intCast(0x11 + i);
    for (&pcs, 0..) |*b, i| b.* = @intCast(0x71 + i);
    for (&seed, 0..) |*b, i| b.* = @intCast(0xa0 + i);
    base_secret[0] = 0;
    pcs[0] = 0;

    _ = try P.run("derivePrivateKey", root.derivePrivateKey, .{ &out, &base_secret, &pcs }, &[_][]const u8{ &base_secret, &pcs, &out }, .{});
    _ = try P.run("deriveRevocationPrivateKey", root.deriveRevocationPrivateKey, .{ &out, &base_secret, &pcs }, &[_][]const u8{ &base_secret, &pcs, &out }, .{});
    // Per-commitment shachain: 48 hash steps, per channel update.
    _ = try P.run("perCommitmentSecret", root.perCommitmentSecret, .{ &out, &seed, root.max_index }, &[_][]const u8{ &seed, &out }, .{});
}
