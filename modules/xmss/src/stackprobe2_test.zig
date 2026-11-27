// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the public WOTS+ building
//! blocks burned: `prfKeygen`, `wotsSkGen`, `wotsPkGen`,
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
    // The chain values of the leaf the calls work on (2026-11-27, whole-module
    // mutation run: skipping the burn of `wotsPkGen` / `wotsSign` passed this
    // probe because their direct-call needles were `SK_SEED` only, and the
    // residue rule cannot see a frame that lies ABOVE the nested `wotsSkGen`
    // burn). `wotsPkGen` publishes only the last position of each chain, so
    // every other position (and the masked value fed to F) is secret;
    // `wotsSign` also publishes the positions from its digit up.
    const digits = xmss.msgToBaseW(&msg);
    var all: [xmss.wots_len]u8 = @splat(xmss.w - 1);
    _ = try P.run("wotsPkGen", xmss.wotsPkGen, .{ &sk_seed, &pub_seed, &adrs }, chainNeedles(&all), .{});
    _ = try P.run("wotsSign", xmss.wotsSign, .{ &msg, &sk_seed, &pub_seed, &adrs }, chainNeedles(&digits), .{});
    _ = try P.run("genLeaf", xmss.genLeaf, .{ &sk_seed, &pub_seed, @as(u32, 3) }, &.{&sk_seed}, .{});
}

const n = xmss.n;
var needle_store: [2 * xmss.wots_len * (xmss.w - 1) + 1][n]u8 = undefined;
var needle_slices: [needle_store.len][]const u8 = undefined;

/// `SK_SEED` plus, for every chain i of leaf 0, the values at positions
/// 0 .. below[i] - 1 and the masked value (`x XOR bitmask`) F is fed at each.
fn chainNeedles(below: *const [xmss.wots_len]u8) []const []const u8 {
    var k: usize = 0;
    needle_store[k] = sk_seed;
    k += 1;
    var a: xmss.Adrs = .{};
    a.setType(xmss.Adrs.type_ots);
    var starts: [xmss.wots_len][n]u8 = undefined;
    xmss.wotsSkGen(&starts, &sk_seed, &pub_seed, &a);
    for (&starts, below, 0..) |*value, upto, i| {
        a.setChainAddress(@intCast(i));
        var pos: u32 = 0;
        while (pos < upto) : (pos += 1) {
            needle_store[k] = value.*;
            k += 1;
            var m = a;
            m.setHashAddress(pos);
            m.setKeyAndMask(1);
            const bm = xmss.prf(&pub_seed, &m.toBytes());
            for (&needle_store[k], value.*, bm) |*o, x, y| o.* = x ^ y;
            k += 1;
            xmss.chain(value, pos, 1, &pub_seed, &a);
        }
    }
    for (0..k) |j| needle_slices[j] = &needle_store[j];
    return needle_slices[0..k];
}
