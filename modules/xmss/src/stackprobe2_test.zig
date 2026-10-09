// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the public WOTS+ building
//! blocks burned 2026-10-09: `prfKeygen`, `wotsSkGen`, `wotsPkGen`,
//! `wotsSign`, `genLeaf` (`keyGen` / `sign` are in `stackprobe_test.zig`).
//! `prfKeygen` / `wotsSkGen` are per-chain calls: tight burn (`prf_burn`); the
//! others are one-shot (`burn_size`). ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const xmss = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 48 * 1024 });

var sk_seed: [32]u8 = undefined;
var pub_seed: [32]u8 = undefined;
var msg: [32]u8 = undefined;
var one: [32]u8 = undefined;
var sk_chains: [xmss.wots_len][32]u8 = undefined;
var adrs: xmss.Adrs = .{};
var adrs_bytes: [32]u8 = undefined;

test "STACKPROBE: WOTS+ building blocks leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("xmss probe2 sk_seed", &sk_seed, .{});
    std.crypto.hash.sha2.Sha256.hash("xmss probe2 pub_seed", &pub_seed, .{});
    std.crypto.hash.sha2.Sha256.hash("xmss probe2 msg", &msg, .{});
    adrs_bytes = adrs.toBytes();
    const flat: []u8 = std.mem.sliceAsBytes(sk_chains[0..]);
    _ = try P.run("prfKeygen", xmss.prfKeygen, .{ &one, &sk_seed, &pub_seed, &adrs_bytes }, &.{ &sk_seed, &one }, .{});
    _ = try P.run("wotsSkGen", xmss.wotsSkGen, .{ &sk_chains, &sk_seed, &pub_seed, &adrs }, &.{ &sk_seed, flat }, .{});
    _ = try P.run("wotsPkGen", xmss.wotsPkGen, .{ &sk_seed, &pub_seed, &adrs }, &.{&sk_seed}, .{});
    _ = try P.run("wotsSign", xmss.wotsSign, .{ &msg, &sk_seed, &pub_seed, &adrs }, &.{&sk_seed}, .{});
    _ = try P.run("genLeaf", xmss.genLeaf, .{ &sk_seed, &pub_seed, @as(u32, 3) }, &.{&sk_seed}, .{});
}
