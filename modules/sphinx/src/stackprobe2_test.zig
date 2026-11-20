// SPDX-License-Identifier: MIT

//! Dead-stack probe on the shared engine (`testkit.stackprobe`) for the BOLT#4
//! key-derivation primitives burned in the sweep: `generateKey`
//! and `generateCipherStream`. (`construct`/`process`/`deriveHopSecrets` stay
//! covered by the older `stackprobe_test.zig`.) Tight per-hop burn (2 KiB).
//! ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const sphinx = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 16 * 1024 });

var shared: [32]u8 = undefined;
var key_out: [32]u8 = undefined;
var stream_out: [1300]u8 = undefined;

test "STACKPROBE: sphinx generateKey / generateCipherStream leave no secret in any frame" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("sphinx probe shared secret", &shared, .{});
    _ = try P.run("generateKey", sphinx.generateKey, .{ &key_out, sphinx.KeyType.rho, &shared }, &[_][]const u8{ &shared, &key_out }, .{});
    _ = try P.run("generateCipherStream", sphinx.generateCipherStream, .{ &key_out, @as([]u8, &stream_out) }, &[_][]const u8{ &key_out, &stream_out }, .{});
}

var um_key: [32]u8 = undefined;
var ammag_key: [32]u8 = undefined;
var packet_buf: [1024]u8 = undefined;
var secrets_buf: [2][32]u8 = undefined;

test "STACKPROBE: sphinx failure create / forward / unwrap leave no secret in any frame" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("sphinx failure probe secret", &shared, .{});
    sphinx.generateKey(&um_key, .um, &shared);
    sphinx.generateKey(&ammag_key, .ammag, &shared);
    const needles = &[_][]const u8{ &shared, &um_key, &ammag_key };
    _ = try P.run("failure.create", sphinx.failure.create, .{ @as([]u8, &packet_buf), &shared, @as([]const u8, "probe failure") }, needles, .{});
    _ = try P.run("failure.forward", sphinx.failure.forward, .{ @as([]u8, packet_buf[0..300]), &shared }, needles, .{});
    secrets_buf[0] = shared;
    secrets_buf[1] = shared;
    _ = try P.run("failure.unwrap", sphinx.failure.unwrap, .{ @as([]u8, packet_buf[0..300]), @as([]const [32]u8, &secrets_buf) }, needles, .{});
}
