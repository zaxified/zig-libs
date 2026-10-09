// SPDX-License-Identifier: MIT

//! Dead-stack probe for `noise.keyedMac` on `testkit.stackprobe` (the older
//! `stackprobe_test.zig` covers the rest): residue below the burn, and the MAC
//! key as a needle in any frame. ReleaseFast only (`skipUnlessOptimized`, a
//! runtime skip, so the body is type-checked in every mode).

const std = @import("std");
const wg = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var key: [32]u8 = undefined;
var data: [116]u8 = undefined;

test "STACKPROBE: no MAC-key residue after noise.keyedMac" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("wireguard probe mac key", &key, .{});
    @memset(&data, 0x5a);
    const secrets = [_][]const u8{&key};
    _ = try P.run("noise.keyedMac", wg.noise.keyedMac, .{ @as([]const u8, &key), @as([]const u8, &data) }, &secrets, .{});
}
