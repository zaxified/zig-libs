// SPDX-License-Identifier: MIT

//! Dead-stack probe on the shared engine (`testkit.stackprobe`) for the BOLT#4
//! key-derivation primitives burned in the 2026-10-09 sweep: `generateKey`
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
