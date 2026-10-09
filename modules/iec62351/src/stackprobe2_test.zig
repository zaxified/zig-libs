// SPDX-License-Identifier: MIT

//! Dead-stack probe for the GOOSE MAC entry points on `testkit.stackprobe` (the
//! older `stackprobe_test.zig` covers the ECDSA signers): residue below each
//! burn, and the MAC key as a needle in any frame. ReleaseFast only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in every
//! mode).

const std = @import("std");
const goose = @import("goose.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var key: [32]u8 = undefined;
var out: [32]u8 = undefined;
const domain = "goose probe domain bytes";
const iv: [12]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

test "STACKPROBE: no MAC-key residue after goose.computeMac / verifyMac" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("iec62351 probe mac key", &key, .{});
    const secrets = [_][]const u8{&key};
    const k: []const u8 = &key;
    const d: []const u8 = domain;

    _ = try P.run("computeMac hmac_sha256_128", goose.computeMac, .{ goose.MacAlgorithm.hmac_sha256_128, k, d, @as(?[12]u8, null), @as([]u8, &out) }, &secrets, .{});
    var good: [16]u8 = undefined;
    @memcpy(&good, out[0..16]);
    _ = try P.run("verifyMac hmac_sha256_128", goose.verifyMac, .{ goose.MacAlgorithm.hmac_sha256_128, k, d, @as(?[12]u8, null), @as([]const u8, &good) }, &secrets, .{});
    _ = try P.run("computeMac aes_gmac_128 (AES-256 key)", goose.computeMac, .{ goose.MacAlgorithm.aes_gmac_128, k, d, @as(?[12]u8, iv), @as([]u8, &out) }, &secrets, .{});
    _ = try P.run("computeMac aes_gmac_64 (AES-128 key)", goose.computeMac, .{ goose.MacAlgorithm.aes_gmac_64, k[0..16], d, @as(?[12]u8, iv), @as([]u8, &out) }, &secrets, .{});
}
