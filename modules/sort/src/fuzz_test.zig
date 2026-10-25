// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for sort: `SORT_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `SORT_FUZZ_ONLY` selects a harness by name).
//!
//! `sort-model`: a random element type (one per small-sort / partition
//! choice: 1, 4, 8, 17, 100 and 204 bytes), length, value pattern and entry
//! point (`unstable`, `stable` allocating, `stableBuffer` with the least and
//! with a full scratch, `selectNth` at a random index), then
//!   - an honest comparator: the result equals the model, `std.sort.block`
//!     (key for key for the unstable sort, byte for byte for the stable
//!     one, the k-th key and both sides of it for the selection);
//!   - a lying comparator, whose answers come from the fuzz source: the
//!     result is a permutation of the input.
//! The items — and the caller's scratch — sit against an unreadable page
//! (`testkit.guard`), at its tail or its head, so a read or write one
//! element out of bounds faults under the seed that made it: the sorts
//! index through `[*]T`, which no build mode bounds-checks.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const sort = @import("root.zig");
pub const fuzz_driver = testkit.fuzz.driver;

const Big = extern struct { key: u32, pad: [96]u8 };
const Huge = extern struct { key: u32, pad: [200]u8 };
const Ip17 = extern struct { tag: u8, b: [16]u8 };

const max_len = 6000;
const Items = testkit.guard.Guarded(max_len * @sizeOf(Huge));
// A different size, so a different type: one `Guarded` type is one region.
const Scratch = testkit.guard.Guarded(max_len * @sizeOf(Huge) + 1);

const Label = enum {
    t_u8,
    t_u32,
    t_u64,
    t_ip17,
    t_big,
    t_huge,
    unstable,
    stable_alloc,
    stable_min,
    stable_full,
    select,
    honest,
    liar,
    at_tail,
    at_head,
    len_le_20,
    len_gt_4096,
};

fn mark(l: Label) void {
    counts[@backingInt(l)] += 1;
    switch (l) {
        inline else => |c| fuzz_driver.hit(@tagName(c)),
    }
}
var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn make(comptime T: type, k: u64, i: usize) T {
    return switch (T) {
        u8, u32, u64 => @truncate(k),
        // The payload carries the index: equal keys stay distinguishable,
        // so the stable comparison sees any reordering.
        Big, Huge => blk: {
            var x: T = .{ .key = @truncate(k), .pad = @splat(0) };
            std.mem.writeInt(u64, x.pad[0..8], i, .little);
            break :blk x;
        },
        Ip17 => blk: {
            var x: Ip17 = .{ .tag = @truncate(k & 1), .b = @splat(0) };
            std.mem.writeInt(u64, x.b[0..8], k >> 1, .big);
            std.mem.writeInt(u64, x.b[8..16], i, .big);
            break :blk x;
        },
        else => @compileError("no make"),
    };
}

fn honestLess(comptime T: type) fn (void, T, T) bool {
    return struct {
        fn f(_: void, a: T, b: T) bool {
            return switch (T) {
                u8, u32, u64 => a < b,
                Big, Huge => a.key < b.key,
                // Order by the key half only: the index half makes equal
                // keys distinct elements.
                Ip17 => a.tag < b.tag or (a.tag == b.tag and std.mem.order(u8, a.b[0..8], b.b[0..8]) == .lt),
                else => unreachable,
            };
        }
    }.f;
}

fn sameKey(comptime T: type, a: T, b: T) bool {
    const less = honestLess(T);
    return !less({}, a, b) and !less({}, b, a);
}

/// A comparator whose every answer is drawn from the fuzz source.
fn liarLess(comptime S: type, comptime T: type) fn (*S, T, T) bool {
    return struct {
        fn f(s: *S, _: T, _: T) bool {
            return s.value(u8) & 1 == 1;
        }
    }.f;
}

fn digest(comptime T: type, v: []const T) [3]u64 {
    var d: [3]u64 = @splat(0);
    for (v) |e| {
        const h = std.hash.Wyhash.hash(0x5eed, std.mem.asBytes(&e));
        d[0] +%= h;
        d[1] +%= h *% h;
        d[2] ^= h;
    }
    return d;
}

const Alg = enum { unstable, stable_alloc, stable_min, stable_full, select };

fn fuzzModel(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    switch (src.valueRangeAtMost(u8, 0, 5)) {
        0 => try one(u8, S, src, gpa),
        1 => try one(u32, S, src, gpa),
        2 => try one(u64, S, src, gpa),
        3 => try one(Ip17, S, src, gpa),
        4 => try one(Big, S, src, gpa),
        else => try one(Huge, S, src, gpa),
    }
}

fn one(comptime T: type, comptime S: type, src: *S, gpa: std.mem.Allocator) !void {
    mark(switch (T) {
        u8 => .t_u8,
        u32 => .t_u32,
        u64 => .t_u64,
        Ip17 => .t_ip17,
        Big => .t_big,
        else => .t_huge,
    });
    // Lengths: often around the cuts (20, 32, 64, 4096), sometimes long.
    const len: usize = switch (src.valueRangeAtMost(u8, 0, 9)) {
        0...3 => src.valueRangeAtMost(u32, 0, 70),
        4...7 => src.valueRangeAtMost(u32, 0, 1200),
        8 => src.valueRangeAtMost(u32, 4000, 4200),
        else => src.valueRangeAtMost(u32, 0, if (@sizeOf(T) > 64) 1500 else max_len),
    };
    if (len <= 20) mark(.len_le_20);
    if (len > 4096) mark(.len_gt_4096);
    const at_tail = src.value(bool);
    mark(if (at_tail) .at_tail else .at_head);
    const bytes = if (at_tail) Items.tail(len * @sizeOf(T)) else Items.head(len * @sizeOf(T));
    const v: []T = @alignCast(std.mem.bytesAsSlice(T, bytes));

    // Values: a range from 2 to 2^64 wide, then an optional structure.
    const range: u64 = switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => 2,
        1 => 16,
        2 => 1000,
        else => std.math.maxInt(u64),
    };
    const shape = src.valueRangeAtMost(u8, 0, 5);
    var seed: u64 = src.value(u64);
    for (v, 0..) |*x, i| {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const r = (seed >> 11) % range;
        const k: u64 = switch (shape) {
            0, 1 => r,
            2 => i, // ascending
            3 => len - i, // descending
            4 => (i % 37) + (r & 1), // runs
            else => if (i + 8 < len) i else r, // sorted, noisy tail
        };
        x.* = make(T, k, i);
    }
    const in = try gpa.dupe(T, v);
    defer gpa.free(in);

    const alg: Alg = @fromBackingInt(@intCast(src.valueRangeAtMost(u8, 0, 4)));
    if (alg == .select and len == 0) return;
    const k = if (len > 0) src.index(len) else 0;
    const liar = src.valueRangeAtMost(u8, 0, 3) == 0;
    mark(if (liar) .liar else .honest);
    mark(switch (alg) {
        .unstable => .unstable,
        .stable_alloc => .stable_alloc,
        .stable_min => .stable_min,
        .stable_full => .stable_full,
        .select => .select,
    });

    if (liar) {
        try runAlg(T, *S, alg, gpa, v, k, src, liarLess(S, T));
        if (!std.mem.eql(u64, &digest(T, in), &digest(T, v))) return error.NotAPermutation;
        return;
    }
    try runAlg(T, void, alg, gpa, v, k, {}, honestLess(T));

    const model = try gpa.dupe(T, in);
    defer gpa.free(model);
    std.sort.block(T, model, {}, honestLess(T));
    switch (alg) {
        .unstable => {
            for (v, model) |a, b| if (!sameKey(T, a, b)) return error.UnstableOrderDiffers;
            if (!std.mem.eql(u64, &digest(T, in), &digest(T, v))) return error.NotAPermutation;
        },
        .stable_alloc, .stable_min, .stable_full => {
            if (!std.mem.eql(u8, std.mem.sliceAsBytes(model), std.mem.sliceAsBytes(v))) return error.StableOrderDiffers;
        },
        .select => {
            const less = honestLess(T);
            if (!sameKey(T, v[k], model[k])) return error.SelectedWrongElement;
            for (v[0..k]) |x| if (less({}, v[k], x)) return error.SelectLeftSideGreater;
            for (v[k + 1 ..]) |x| if (less({}, x, v[k])) return error.SelectRightSideLess;
            if (!std.mem.eql(u64, &digest(T, in), &digest(T, v))) return error.NotAPermutation;
        },
    }
}

fn runAlg(comptime T: type, comptime C: type, alg: Alg, gpa: std.mem.Allocator, v: []T, k: usize, ctx: C, comptime less: fn (C, T, T) bool) !void {
    switch (alg) {
        .unstable => sort.unstable(T, v, ctx, less),
        .stable_alloc => try sort.stable(T, gpa, v, ctx, less),
        .stable_min, .stable_full => {
            const n = if (alg == .stable_min) sort.stableScratchLen(v.len) else @max(v.len, sort.stableScratchLen(v.len));
            // The scratch against the other guard, at its tail.
            const sb = Scratch.tail(n * @sizeOf(T));
            const scratch: []T = @alignCast(std.mem.bytesAsSlice(T, sb));
            sort.stableBuffer(T, v, scratch, ctx, less);
        },
        .select => sort.selectNth(T, v, k, ctx, less),
    }
}

test "fuzz driver: SORT_FUZZ (model)" {
    try fuzz_driver.run(fuzzModel, .{ .prefix = "SORT_FUZZ", .name = "sort-model" });
}

test "fuzz harness: sort-model, 400 seeds, reaches every label" {
    counts = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        fuzzModel(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("sort-model seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (counts, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: sort-model label {t} never hit in 400 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
