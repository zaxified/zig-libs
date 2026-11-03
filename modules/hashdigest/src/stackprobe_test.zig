// SPDX-License-Identifier: MIT

//! Dead-stack probe for `blake3Keyed` / `blake3DeriveKey` (`testkit.stackprobe`):
//! residue below each burn, and the key, the key material and the derived-key
//! output as needles in any frame. ReleaseFast/ReleaseSmall only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in every
//! mode). The 16 KiB burn depth in `root.zig` is checked by this probe (8 KiB
//! left 411 B of residue for 3000 bytes of material); with the
//! `defer burnStack()` lines removed (a mutated copy, see the SPEC) it reports
//! residue.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var key: [32]u8 = undefined;
var material: [20000]u8 = undefined; // 20 chunks: the wide-batch tree path runs
var out: [64]u8 = undefined;
var mac: [32]u8 = undefined;

test "STACKPROBE: no BLAKE3 key or key-material residue after blake3Keyed / blake3DeriveKey" {
    try sp.skipUnlessOptimized();
    // Fixed needle keys: SHA-256 of a label, high entropy, the same every run.
    std.crypto.hash.sha2.Sha256.hash("hashdigest probe key", &key, .{});
    var seed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hashdigest probe material", &seed, .{});
    for (&material, 0..) |*b, i| b.* = seed[i % 32] ^ @as(u8, @truncate(i / 32));

    const keyed_secrets = [_][]const u8{&key};
    _ = try P.run("blake3Keyed", root.blake3Keyed, .{ @as(*const [32]u8, &key), @as([]const u8, &material), @as([]u8, &mac) }, &keyed_secrets, .{});

    const derive_secrets = [_][]const u8{ material[0..64], &out };
    _ = try P.run("blake3DeriveKey", root.blake3DeriveKey, .{ @as([]const u8, "hashdigest probe context"), @as([]const u8, &material), @as([]u8, &out) }, &derive_secrets, .{});
}
