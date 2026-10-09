// SPDX-License-Identifier: MIT

//! Dead-stack probe on the shared engine (`testkit.stackprobe`) for the two
//! adaptor-secret entry points burned in the 2026-10-09 sweep:
//! `AdaptorPoint.fromSecret` and `adapt`. (`preSign` stays covered by the
//! older `stackprobe_test.zig`.) ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

// Window above the deepest burn (32 KiB one-shot ECC).
const P = sp.Probe(.{ .window = 64 * 1024 });

var t_secret: [32]u8 = undefined;
var presig: root.PreSignature = undefined;

test "STACKPROBE: adaptor fromSecret / adapt leave no adaptor secret in any frame" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("adaptor probe t", &t_secret, .{});
    t_secret[0] = 0; // < n
    presig = .{ .r = @splat(0x22), .s_prime = @splat(0x01), .needs_negation = true };
    presig.s_prime[0] = 0;

    _ = try P.run("AdaptorPoint.fromSecret", root.AdaptorPoint.fromSecret, .{&t_secret}, &[_][]const u8{&t_secret}, .{});
    _ = try P.run("adapt", root.adapt, .{ presig, &t_secret }, &[_][]const u8{&t_secret}, .{});
}
