// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `failure.createPadded`, the
//! padded BOLT#4 failure-packet builder the older probes do not call:
//! residue below its burn, the hop's shared secret as a needle.
//! ReleaseFast/ReleaseSmall only. Coverage sweep 2026-11-26.

const std = @import("std");
const sphinx = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var ss: [32]u8 = undefined;
var out: [2048]u8 = undefined;

test "STACKPROBE: failure.createPadded leaves no shared secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("sphinx probe4 shared secret", &ss, .{});
    _ = try P.run("failure.createPadded", sphinx.failure.createPadded, .{ @as([]u8, &out), &ss, @as([]const u8, "\x40\x02probe failure"), @as(u16, 256) }, &.{&ss}, .{});
}
