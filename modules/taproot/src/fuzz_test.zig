// SPDX-License-Identifier: MIT

//! Shared plumbing for taproot's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `TAPROOT_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `taproot-tree`, `taproot-tweak`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone almost never get
/// past the first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

// ── harnesses ───────────────────────────────────────────────────────────

const bip340 = @import("bip340");
const tree = @import("tree.zig");
const root = @import("root.zig");
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;

const TreeMark = Marker(enum { built, refused, root_recomputed, tampered_leaf_refused, single_leaf, deep });
const TweakMark = Marker(enum { genuine_accepted, key_refused, secret_matches_public, other_root_differs });

fn fuzzTreeSmith(_: void, s: *testing.Smith) !void {
    return fuzzTree(testing.Smith, s, testing.allocator);
}
test "fuzz: taproot trees built from random depth lists are complete and their paths recompute the root" {
    try testing.fuzz({}, fuzzTreeSmith, .{});
}
test "fuzz driver: TAPROOT_FUZZ (tree)" {
    try fuzz_driver.run(fuzzTree, .{ .prefix = "TAPROOT_FUZZ", .name = "taproot-tree" });
}
test "fuzz harness: tree, 400 seeds, reaches every outcome" {
    try TreeMark.reach(fuzzTree, "taproot-tree", 400);
}

fn randomInternalKey(k: *Cursor) ?bip340.XOnlyPublicKey {
    var b: [32]u8 = undefined;
    for (&b) |*x| x.* = k.byte();
    b[0] &= 0x7f;
    const sk = bip340.SecretKey.fromBytes(b) catch return null;
    return (bip340.PublicKey.fromSecretKey(&sk) catch return null).xonly;
}

/// Leaves of a random COMPLETE tree (depths in DFS order; built by splitting a
/// leaf in two), one of them maybe damaged. Whatever `buildFromLeaves`
/// accepts must be a complete tree whose every control-block path recomputes
/// the Merkle root from the leaf hash, and whose output key is the tweak of
/// that root; a changed script no longer recomputes it.
fn fuzzTree(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [96]u8 = undefined;
    const n_raw: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n_raw] };
    const internal = randomInternalKey(&k) orelse return;
    var depths: [12]u8 = undefined;
    var count: usize = 1;
    depths[0] = 0;
    const want = k.ranged(0, 11);
    while (count < want) {
        const at = k.ranged(0, @intCast(count - 1));
        if (depths[at] >= 6) break;
        var j = count;
        while (j > at + 1) : (j -= 1) depths[j] = depths[j - 1];
        depths[at] += 1;
        depths[at + 1] = depths[at];
        count += 1;
    }
    var damaged = false;
    if (want == 0) count = 0;
    if (k.ranged(0, 3) == 0 and count > 0) {
        depths[k.ranged(0, @intCast(count - 1))] = @truncate(k.ranged(0, 140));
        damaged = true;
    }
    var scripts: [12][12]u8 = undefined;
    var list: [12]tree.DepthLeaf = undefined;
    for (0..count) |i| {
        for (&scripts[i]) |*b| b.* = k.byte();
        const len = k.ranged(0, 12);
        list[i] = .{ .depth = depths[i], .version = if (k.ranged(0, 7) == 0) 0xc2 else 0xc0, .script = scripts[i][0..len] };
    }
    var info = tree.buildFromLeaves(gpa, internal, list[0..count]) catch |e| {
        // The only reason a validly-split tree may be refused is a tweak outside the group order (2^-128).
        if (!damaged and e != error.TweakOutOfRange) return error.GenuineTreeRefused;
        TreeMark.mark(.refused);
        return;
    };
    defer info.deinit(gpa);
    TreeMark.mark(.built);
    if (count == 0) {
        if (info.merkle_root != null) return error.EmptyTreeHasRoot;
        return;
    }
    if (count == 1) TreeMark.mark(.single_leaf);
    var kraft: u64 = 0;
    for (info.leaves, list[0..count]) |leaf, l| {
        if (leaf.path.len != l.depth) return error.PathLengthDiffers;
        kraft += @as(u64, 1) << @intCast(6 - @min(l.depth, 6));
        if (l.depth > 3) TreeMark.mark(.deep);
        // Recompute the root along the control-block path.
        var h = tree.tapLeafHash(l.version, l.script);
        if (!std.mem.eql(u8, &h, &leaf.leaf_hash)) return error.LeafHashDiffers;
        for (leaf.path) |node| h = tree.tapBranchHash(h, node);
        if (!std.mem.eql(u8, &h, &info.merkle_root.?)) return error.PathDoesNotRecomputeRoot;
        // A changed script no longer recomputes the root.
        var other_script: [13]u8 = undefined;
        @memcpy(other_script[0..l.script.len], l.script);
        other_script[l.script.len] = k.byte();
        var h2 = tree.tapLeafHash(l.version, other_script[0 .. l.script.len + 1]);
        for (leaf.path) |node| h2 = tree.tapBranchHash(h2, node);
        if (std.mem.eql(u8, &h2, &info.merkle_root.?)) return error.TamperedLeafRecomputesRoot;
    }
    if (kraft != 64) return error.TreeNotComplete;
    TreeMark.mark(.root_recomputed);
    TreeMark.mark(.tampered_leaf_refused);
    // Output key = tweak of the root; control block parity/length.
    const tw = try root.tweakPublicKey(internal, info.merkle_root);
    if (!std.mem.eql(u8, &tw.output.x, &info.output.x) or tw.output.parity != info.output.parity) return error.OutputKeyDiffers;
    var cb: [33 + 32 * 130]u8 = undefined;
    const block = info.controlBlock(0, &cb);
    if (block.len != 33 + 32 * info.leaves[0].path.len or block[0] & 1 != info.output.parity or !std.mem.eql(u8, block[1..33], &internal.toBytes())) return error.ControlBlockWrong;
}

fn fuzzTweakSmith(_: void, s: *testing.Smith) !void {
    return fuzzTweak(testing.Smith, s, testing.allocator);
}
test "fuzz: tweakSecretKey and tweakPublicKey agree" {
    try testing.fuzz({}, fuzzTweakSmith, .{});
}
test "fuzz driver: TAPROOT_FUZZ (tweak)" {
    try fuzz_driver.run(fuzzTweak, .{ .prefix = "TAPROOT_FUZZ", .name = "taproot-tweak" });
}
test "fuzz harness: tweak, 200 seeds, reaches every outcome" {
    try TweakMark.reach(fuzzTweak, "taproot-tweak", 200);
}

/// The private and public tweak agree: for a random secret `d` and Merkle
/// root, `tweakSecretKey(d)*G` has the x-coordinate `tweakPublicKey(P)` names;
/// a different root names a different key; a random 32 octets as internal key
/// is accepted exactly when it lifts to the curve.
fn fuzzTweak(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [96]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    var xb: [32]u8 = undefined;
    for (&xb) |*b| b.* = k.byte();
    var rb: [32]u8 = undefined;
    for (&rb) |*b| b.* = k.byte();
    const merkle: ?[32]u8 = if (k.byte() & 1 == 0) rb else null;
    if (bip340.XOnlyPublicKey.fromBytes(xb)) |xonly| {
        if (root.tweakPublicKey(xonly, merkle)) |_| {} else |_| return error.LiftableKeyRefused;
    } else |_| {
        if (root.tweakPublicKey(.{ .x = xb }, merkle)) |_| return error.UnliftableKeyAccepted else |_| {}
        TweakMark.mark(.key_refused);
    }
    var sb: [32]u8 = undefined;
    for (&sb) |*b| b.* = k.byte();
    sb[0] &= 0x7f;
    const sk = bip340.SecretKey.fromBytes(sb) catch return;
    const pk = (try bip340.PublicKey.fromSecretKey(&sk)).xonly;
    const tw = root.tweakPublicKey(pk, merkle) catch return error.GenuineTweakRefused; // out of range only at 2^-128
    TweakMark.mark(.genuine_accepted);
    var q: [32]u8 = undefined;
    try root.tweakSecretKey(&sk, merkle, &q);
    const qk = try bip340.SecretKey.fromBytes(q);
    const qp = (try bip340.PublicKey.fromSecretKey(&qk)).xonly;
    if (!std.mem.eql(u8, &qp.x, &tw.output.x)) return error.SecretAndPublicTweakDisagree;
    TweakMark.mark(.secret_matches_public);
    var other = rb;
    other[k.ranged(0, 31)] ^= @as(u8, 1) << @intCast(k.ranged(0, 7));
    const tw2 = root.tweakPublicKey(pk, if (merkle == null) other else other) catch return;
    if (merkle != null and std.mem.eql(u8, &merkle.?, &other)) return;
    if (std.mem.eql(u8, &tw2.output.x, &tw.output.x)) return error.OtherRootSameKey;
    TweakMark.mark(.other_root_differs);
}
