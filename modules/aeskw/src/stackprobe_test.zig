// SPDX-License-Identifier: MIT

//! Dead-stack probe for `wrap` / `unwrap` (`testkit.stackprobe`): residue
//! below each burn, and the KEK, the key data and the output buffer as needles
//! in any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so
//! the body is type-checked in every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var kek: [32]u8 = undefined;
var plain: [32]u8 = undefined;
var wrapped: [40]u8 = undefined;
var out: [40]u8 = undefined;

test "STACKPROBE: no KEK or key-data residue after wrap / unwrap" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("aeskw probe kek", &kek, .{});
    std.crypto.hash.sha2.Sha256.hash("aeskw probe key data", &plain, .{});
    const secrets = [_][]const u8{ &kek, &plain, &out };

    _ = try P.run("wrap", root.wrap, .{ @as([]const u8, &kek), @as([]const u8, &plain), @as([]u8, &out) }, &secrets, .{});
    @memcpy(&wrapped, &out);
    const unwrapped_secrets = [_][]const u8{ &kek, &plain, &out };
    _ = try P.run("unwrap", root.unwrap, .{ @as([]const u8, &kek), @as([]const u8, &wrapped), @as([]u8, &out) }, &unwrapped_secrets, .{});
    try std.testing.expectEqualSlices(u8, &plain, out[0..32]);
}
