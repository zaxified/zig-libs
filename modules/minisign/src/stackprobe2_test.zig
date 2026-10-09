// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the `RawSecretKey` codec
//! (`toBytes`, `fromBytes`) burned 2026-10-09; the signing / sealing paths are
//! in `stackprobe_test.zig`. Per-call codec burn (`codec_burn`).
//! ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const ms = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var wire_in: [ms.RawSecretKey.wire_length]u8 = undefined;
var wire_out: [ms.RawSecretKey.wire_length]u8 = undefined;
var raw: ms.RawSecretKey = undefined;
var raw_out: ms.RawSecretKey = undefined;

test "STACKPROBE: RawSecretKey codec leaves no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    var h: [64]u8 = undefined;
    var i: usize = 0;
    while (i < wire_in.len) : (i += 32) {
        std.crypto.hash.sha2.Sha256.hash(&[_]u8{ 'm', 's', @intCast(i) }, h[0..32], .{});
        const n = @min(32, wire_in.len - i);
        @memcpy(wire_in[i..][0..n], h[0..n]);
    }
    ms.RawSecretKey.fromBytes(&raw, &wire_in);
    _ = try P.run("RawSecretKey.fromBytes", ms.RawSecretKey.fromBytes, .{ &raw_out, &wire_in }, &.{ &wire_in, &raw_out.secret_key }, .{});
    _ = try P.run("RawSecretKey.toBytes", ms.RawSecretKey.toBytes, .{ &raw, &wire_out }, &.{ &raw.secret_key, &wire_out }, .{});
}
