// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the entry points burned
//! 2026-10-09: `alg.pbes2DeriveKek` and `decryptCompact` for a `dir` token
//! (the ECDH-ES paths are in `stackprobe_test.zig`). One-shot calls:
//! `kdf_burn` / `content_burn`. ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const jwe = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 96 * 1024 });

var password: [20]u8 = undefined;
var salt: [16]u8 = undefined;
var kek: [32]u8 = undefined;
var shared: [16]u8 = undefined;
var rng = std.Random.DefaultPrng.init(0x6a77_655f_7072_6232);

test "STACKPROBE: pbes2DeriveKek and decryptCompact leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("jwe probe2 password", &h, .{});
    @memcpy(&password, h[0..20]);
    std.crypto.hash.sha2.Sha256.hash("jwe probe2 salt", &h, .{});
    @memcpy(&salt, h[0..16]);
    std.crypto.hash.sha2.Sha256.hash("jwe probe2 shared", &h, .{});
    @memcpy(&shared, h[0..16]);

    _ = try P.run("alg.pbes2DeriveKek", jwe.alg.pbes2DeriveKek, .{ jwe.alg.Pbes2Variant.hs256_a128kw, @as([]const u8, &password), @as([]const u8, &salt), @as(u32, 4), @as([]u8, &kek) }, &.{ &password, &kek }, .{});

    const gpa = std.heap.page_allocator; // global-alloc-ok: stack probe; a heap the scan never reads
    const token = try jwe.encryptCompact(gpa, .dir, .A128GCM, .{ .symmetric = &shared }, "attack at dawn", "", .{ .fixed_for_test = rng.random() }, .{});
    // The probe discards the plaintext; page_allocator memory is not reused by the scan.
    _ = try P.run("decryptCompact dir", jwe.decryptCompact, .{ gpa, jwe.KeyMaterial{ .symmetric = &shared }, @as([]const u8, token), jwe.DecryptOptions{} }, &.{&shared}, .{});
}
