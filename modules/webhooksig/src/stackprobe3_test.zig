// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `signWithPrefix`,
//! `verifyWithPrefix` and `verifyFormat`, the HMAC entry points
//! `stackprobe_test.zig` does not call: residue below each burn, the HMAC
//! secret as a needle. ReleaseFast/ReleaseSmall only. Coverage sweep 2026-11-26.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

const body = "{\"event\":\"dead-stack probe 3\"}";
var key: [32]u8 = undefined;
var out: [256]u8 = undefined;

const fmt512: root.Format = .{ .prefix = "v1=", .digest = .sha512, .encoding = .base64 };

test "STACKPROBE: signWithPrefix, verifyWithPrefix and verifyFormat leave no HMAC secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("webhooksig probe3 key", &key, .{});
    const secret: []const u8 = &key;
    const k = &[_][]const u8{&key};

    _ = try P.run("signWithPrefix", root.signWithPrefix, .{ "sha256=", secret, body, &out }, k, .{});
    var good: [128]u8 = undefined;
    const g = try root.signWithPrefix("sha256=", secret, body, &good);
    _ = try P.run("verifyWithPrefix (match)", root.verifyWithPrefix, .{ "sha256=", secret, body, g }, k, .{});
    var good512: [128]u8 = undefined;
    const g512 = try root.signFormat(fmt512, secret, body, &good512);
    _ = try P.run("verifyFormat sha512 b64 (match)", root.verifyFormat, .{ fmt512, secret, body, g512 }, k, .{});
    _ = try P.run("verifyFormat sha512 b64 (mismatch)", root.verifyFormat, .{ fmt512, secret, "other body", g512 }, k, .{});
}
