// SPDX-License-Identifier: MIT

//! Dead-stack probe for the secure-authentication key paths
//! (`testkit.stackprobe`): residue below each burn, and the MAC key, the update
//! key and the session keys as needles in any frame. ReleaseFast only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in every
//! mode).

const std = @import("std");
const sa = @import("root.zig").sa;
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var key: [32]u8 = undefined;
var update_key: [32]u8 = undefined;
var control_key: [32]u8 = undefined;
var monitoring_key: [32]u8 = undefined;
var out: [80]u8 = undefined;
var wrapped: [72]u8 = undefined;
var unwrapped: [64]u8 = undefined;
const challenge = "dnp3 probe challenge bytes";
const asdu = "dnp3 probe critical asdu";
const iv: [12]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

test "STACKPROBE: no key residue after the SA MAC and session-key paths" {
    try sp.skipUnlessOptimized();
    const Sha256 = std.crypto.hash.sha2.Sha256;
    Sha256.hash("dnp3 probe mac key", &key, .{});
    Sha256.hash("dnp3 probe update key", &update_key, .{});
    Sha256.hash("dnp3 probe control key", &control_key, .{});
    Sha256.hash("dnp3 probe monitoring key", &monitoring_key, .{});
    const k: []const u8 = &key;
    const secrets = [_][]const u8{ &key, &update_key, &control_key, &monitoring_key, &out, &unwrapped };

    _ = try P.run("mac.compute hmac_sha256_trunc_16", sa.mac.compute, .{ sa.HmacAlgorithm.hmac_sha256_trunc_16, k, @as([]const u8, asdu), @as(?[12]u8, null), @as([]u8, &out) }, &secrets, .{});
    _ = try P.run("mac.compute aes_gmac_trunc_12", sa.mac.compute, .{ sa.HmacAlgorithm.aes_gmac_trunc_12, k, @as([]const u8, asdu), @as(?[12]u8, iv), @as([]u8, &out) }, &secrets, .{});
    _ = try P.run("mac.computeTwo hmac_sha1_trunc_10", sa.mac.computeTwo, .{ sa.HmacAlgorithm.hmac_sha1_trunc_10, k, @as([]const u8, challenge), @as([]const u8, asdu), @as([]u8, &out) }, &secrets, .{});

    _ = try P.run("wrapSessionKeys", sa.wrapSessionKeys, .{ @as([]const u8, &update_key), @as([]const u8, &control_key), @as([]const u8, &monitoring_key), @as([]u8, &out) }, &secrets, .{});
    @memcpy(&wrapped, out[0..72]);
    _ = try P.run("unwrapSessionKeys", sa.unwrapSessionKeys, .{ @as([]const u8, &update_key), @as([]const u8, &wrapped), @as(usize, 32), @as([]u8, &unwrapped) }, &secrets, .{});
    try std.testing.expectEqualSlices(u8, &control_key, unwrapped[0..32]);
}
