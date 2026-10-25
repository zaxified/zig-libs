// SPDX-License-Identifier: MIT

//! Model tests: every sort here is checked against `std.sort.block` (stable,
//! independent code) over input patterns that drive each path of the port —
//! the always-insertion cut, the sorted/descending run check, each small
//! sort (network / general / fallback, picked by element size), both
//! partitions (Lomuto ≤ 96 bytes, Hoare above), the equal-to-ancestor
//! partition (many duplicates) and the heapsort fallback (a comparator that
//! answers at random exhausts the recursion budget).

const std = @import("std");
const sort = @import("root.zig");

const testing = std.testing;

/// Element types, one per small-sort / partition choice.
const Big = struct { key: u32, pad: [96]u8 = undefined }; // > 96 B: Hoare, fallback small sort
const Huge = struct { key: u32, pad: [200]u8 = undefined }; // 204 B * 48 > 4 KiB: fallback small sort
const Ip17 = extern struct { tag: u8, b: [16]u8 }; // netaddr.Ip shape: 17 B, align 1, general small sort

fn keyOf(comptime T: type, x: T) u64 {
    return switch (T) {
        u8, u16, u32, u64 => x,
        i32, i64 => @bitCast(@as(i64, x)),
        Big, Huge => x.key,
        Ip17 => std.mem.readInt(u64, x.b[8..16], .big) ^ (@as(u64, x.tag) << 56),
        else => @compileError("no key"),
    };
}

fn make(comptime T: type, k: u64) T {
    return switch (T) {
        u8, u16, u32, u64 => @truncate(k),
        i32 => @bitCast(@as(u32, @truncate(k))),
        i64 => @bitCast(k),
        Big, Huge => .{ .key = @truncate(k), .pad = @splat(@truncate(k)) },
        Ip17 => blk: {
            var ip: Ip17 = .{ .tag = @truncate(k & 1), .b = @splat(0) };
            std.mem.writeInt(u64, ip.b[8..16], k >> 1, .big);
            break :blk ip;
        },
        else => @compileError("no make"),
    };
}

fn lessBy(comptime T: type) fn (void, T, T) bool {
    return struct {
        fn f(_: void, a: T, b: T) bool {
            return switch (T) {
                u8, u16, u32, u64, i32, i64 => a < b,
                Big, Huge => a.key < b.key,
                Ip17 => a.tag < b.tag or (a.tag == b.tag and std.mem.order(u8, &a.b, &b.b) == .lt),
                else => unreachable,
            };
        }
    }.f;
}

const Pattern = enum { random, few_distinct, sorted, descending, saw, pipe_organ, sorted_tail_noise, all_equal, two_values };

fn fill(comptime T: type, out: []T, pattern: Pattern, r: std.Random) void {
    const n = out.len;
    for (out, 0..) |*x, i| {
        const k: u64 = switch (pattern) {
            .random => r.int(u64),
            .few_distinct => r.uintLessThan(u64, 5),
            .sorted => i,
            .descending => n - i,
            .saw => i % 37,
            .pipe_organ => if (i < n / 2) i else n - i,
            .sorted_tail_noise => if (i + 8 < n) i else r.int(u64),
            .all_equal => 7,
            .two_values => @intFromBool(r.boolean()),
        };
        x.* = make(T, k);
    }
}

fn checkAgainstModel(comptime T: type, gpa: std.mem.Allocator, in: []const T) !void {
    const ours = try gpa.dupe(T, in);
    defer gpa.free(ours);
    const model = try gpa.dupe(T, in);
    defer gpa.free(model);
    sort.unstable(T, ours, {}, lessBy(T));
    std.sort.block(T, model, {}, lessBy(T));
    // Unstable: equal keys may permute, so compare keys, and the multiset of
    // whole elements separately.
    for (ours, model) |a, b| try testing.expectEqual(keyOf(T, b), keyOf(T, a));
    try expectSameMultiset(T, gpa, in, ours);
}

fn expectSameMultiset(comptime T: type, gpa: std.mem.Allocator, a: []const T, b: []const T) !void {
    _ = gpa;
    try testing.expectEqual(a.len, b.len);
    try testing.expectEqual(multisetDigest(T, a), multisetDigest(T, b));
}

/// Order-independent digest of a multiset: the sum and the sum of squares
/// (mod 2^64) of each element's hash, plus their xor. A lost element and a
/// duplicated one change all three.
fn multisetDigest(comptime T: type, v: []const T) [3]u64 {
    var d: [3]u64 = @splat(0);
    for (v) |e| {
        const h = std.hash.Wyhash.hash(0x5eed, std.mem.asBytes(&e));
        d[0] +%= h;
        d[1] +%= h *% h;
        d[2] ^= h;
    }
    return d;
}

const lens = [_]usize{ 0, 1, 2, 3, 7, 8, 9, 13, 16, 17, 18, 20, 21, 31, 32, 33, 47, 48, 63, 64, 65, 100, 255, 256, 1000, 4097 };

fn sweep(comptime T: type) !void {
    var prng = std.Random.DefaultPrng.init(0x50_27);
    const r = prng.random();
    const gpa = testing.allocator;
    for (lens) |n| {
        const buf = try gpa.alloc(T, n);
        defer gpa.free(buf);
        for (std.enums.values(Pattern)) |p| {
            fill(T, buf, p, r);
            try checkAgainstModel(T, gpa, buf);
        }
    }
}

test "unstable matches the model: u8 (network small sort, many duplicates)" {
    try sweep(u8);
}
test "unstable matches the model: u64 (network small sort, unrolled Lomuto)" {
    try sweep(u64);
}
test "unstable matches the model: i32 (negative keys)" {
    try sweep(i32);
}
test "unstable matches the model: 17-byte align-1 struct (general small sort)" {
    try sweep(Ip17);
}
test "unstable matches the model: 100-byte struct (Hoare partition)" {
    try sweep(Big);
}
test "unstable matches the model: 204-byte struct (fallback small sort)" {
    try sweep(Huge);
}

test "unstable on a zero-sized type is a no-op" {
    var v: [5]void = @splat({});
    sort.unstable(void, &v, {}, struct {
        fn f(_: void, _: void, _: void) bool {
            return false;
        }
    }.f);
}

test "unstable: asc/desc helpers and a context" {
    var v = [_]i64{ 5, -3, 9, 0, 9, -3, 2, 11, 4, -8, 6, 1, 0, 3, -1, 7, 2, 9, 12, -5, 8, 6, 4, 2 };
    sort.unstable(i64, &v, {}, sort.asc(i64));
    try testing.expect(std.sort.isSorted(i64, &v, {}, std.sort.asc(i64)));
    sort.unstable(i64, &v, {}, sort.desc(i64));
    try testing.expect(std.sort.isSorted(i64, &v, {}, std.sort.desc(i64)));

    // Sort indices by a key held in the context.
    const keys = [_]u32{ 40, 10, 30, 20, 50, 0, 60, 70, 80, 90, 15, 25, 35, 45, 55, 65, 75, 85, 95, 5, 1, 2 };
    var idx: [keys.len]u8 = undefined;
    for (&idx, 0..) |*x, i| x.* = @intCast(i);
    sort.unstable(u8, &idx, &keys, struct {
        fn f(k: *const [keys.len]u32, a: u8, b: u8) bool {
            return k[a] < k[b];
        }
    }.f);
    for (idx[0 .. idx.len - 1], idx[1..]) |a, b| try testing.expect(keys[a] < keys[b]);
}

/// A comparator that answers at random: not an order at all. The sort must
/// still terminate (heapsort after the budget), stay in bounds, and return a
/// permutation of its input.
const Liar = struct {
    r: *std.Random.DefaultPrng,
    calls: *usize,
    fn lessT(comptime T: type) fn (Liar, T, T) bool {
        return struct {
            fn f(self: Liar, _: T, _: T) bool {
                self.calls.* += 1;
                return self.r.random().boolean();
            }
        }.f;
    }
};

fn liarSweep(comptime T: type) !void {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x11a2);
    var data_rng = std.Random.DefaultPrng.init(0xda7a);
    for (lens) |n| {
        const in = try gpa.alloc(T, n);
        defer gpa.free(in);
        fill(T, in, .random, data_rng.random());
        const v = try gpa.dupe(T, in);
        defer gpa.free(v);
        var calls: usize = 0;
        sort.unstable(T, v, Liar{ .r = &prng, .calls = &calls }, Liar.lessT(T));
        try expectSameMultiset(T, gpa, in, v);
        // O(n log n) comparisons even when the comparator lies.
        const lg = std.math.log2_int(usize, n | 1) + 1;
        try testing.expect(calls <= 64 * (n + 1) * lg);
    }
}

test "unstable with a lying comparator returns a permutation (every element size)" {
    try liarSweep(u8);
    try liarSweep(u64);
    try liarSweep(Ip17);
    try liarSweep(Big);
    try liarSweep(Huge);
}

test "unstable's heapsort fallback sorts on its own" {
    // The budget runs out only on adversarial input (or the liar above, whose
    // output cannot be checked for order), so the fallback's own output is
    // checked by calling it directly.
    const gpa = testing.allocator;
    const U = @import("unstable.zig").Unstable(u64, void, sort.asc(u64));
    var prng = std.Random.DefaultPrng.init(3);
    for ([_]usize{ 0, 1, 2, 33, 100, 1000 }) |n| {
        const v = try gpa.alloc(u64, n);
        defer gpa.free(v);
        for (v) |*x| x.* = prng.random().uintLessThan(u64, 50);
        const m = try gpa.dupe(u64, v);
        defer gpa.free(m);
        U.heapsort(v.ptr, v.len, {});
        std.sort.block(u64, m, {}, std.sort.asc(u64));
        try testing.expectEqualSlices(u64, m, v);
    }
}

// ── stable ──────────────────────────────────────────────────────────────────

/// Equal keys carry distinct tags, so any reordering among them is visible:
/// a stable sort must agree with `std.sort.block` byte for byte.
fn Tagged(comptime pad: usize) type {
    return extern struct {
        key: u32,
        tag: u32,
        pad: [pad]u8 = @splat(0),

        fn less(_: void, a: @This(), b: @This()) bool {
            return a.key < b.key;
        }
    };
}

const StableScratch = enum { alloc, min_buffer, full_buffer };

fn checkStable(comptime T: type, gpa: std.mem.Allocator, in: []const T, how: StableScratch) !void {
    const ours = try gpa.dupe(T, in);
    defer gpa.free(ours);
    const model = try gpa.dupe(T, in);
    defer gpa.free(model);
    switch (how) {
        .alloc => try sort.stable(T, gpa, ours, {}, T.less),
        .min_buffer, .full_buffer => {
            const n = if (how == .min_buffer) sort.stableScratchLen(in.len) else @max(in.len, sort.stableScratchLen(in.len));
            const scratch = try gpa.alloc(T, n);
            defer gpa.free(scratch);
            sort.stableBuffer(T, ours, scratch, {}, T.less);
        },
    }
    std.sort.block(T, model, {}, T.less);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(model), std.mem.sliceAsBytes(ours));
}

fn stableSweep(comptime T: type, extra_lens: []const usize) !void {
    var prng = std.Random.DefaultPrng.init(0x57ab1e);
    const r = prng.random();
    const gpa = testing.allocator;
    for ([2][]const usize{ &lens, extra_lens }) |set| for (set) |n| {
        const buf = try gpa.alloc(T, n);
        defer gpa.free(buf);
        for (std.enums.values(Pattern)) |p| {
            const keys = try gpa.alloc(u64, n);
            defer gpa.free(keys);
            fill(u64, keys, p, r);
            for (buf, keys, 0..) |*x, k, i| x.* = .{ .key = @truncate(k % 1000), .tag = @intCast(i) };
            for (std.enums.values(StableScratch)) |how| try checkStable(T, gpa, buf, how);
        }
    };
}

test "stable matches std.sort.block exactly: 8-byte tagged keys" {
    // 5000 and 20000: past the 64² cut where pre-sorted runs need ~√n.
    try stableSweep(Tagged(0), &.{ 5000, 20_000 });
}
test "stable matches std.sort.block exactly: 108-byte tagged keys" {
    try stableSweep(Tagged(100), &.{});
}
test "stable matches std.sort.block exactly: 4104-byte tagged keys (no stack scratch)" {
    // Fewer lengths: each element is 4 KiB.
    var prng = std.Random.DefaultPrng.init(9);
    const T = Tagged(4096);
    const gpa = testing.allocator;
    for ([_]usize{ 21, 50, 200 }) |n| {
        const buf = try gpa.alloc(T, n);
        defer gpa.free(buf);
        for (buf, 0..) |*x, i| x.* = .{ .key = prng.random().uintLessThan(u32, 8), .tag = @intCast(i) };
        for (std.enums.values(StableScratch)) |how| try checkStable(T, gpa, buf, how);
    }
}

test "stable: concatenated sorted and descending runs (the run detector's path)" {
    const T = Tagged(0);
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(77);
    const r = prng.random();
    for ([_]usize{ 100, 4096, 10_000 }) |n| {
        const buf = try gpa.alloc(T, n);
        defer gpa.free(buf);
        // Runs of random length, each ascending or strictly descending, keys
        // overlapping between runs so the merges interleave.
        var i: usize = 0;
        while (i < n) {
            const run = @min(n - i, 1 + r.uintLessThan(usize, 3 * std.math.sqrt(n)));
            const up = r.boolean();
            const start = r.uintLessThan(u32, 500);
            for (0..run) |j| buf[i + j] = .{ .key = if (up) start + @as(u32, @intCast(j / 2)) else start + @as(u32, @intCast(run - j)), .tag = @intCast(i + j) };
            i += run;
        }
        for (std.enums.values(StableScratch)) |how| try checkStable(T, gpa, buf, how);
    }
}

test "stable with a lying comparator returns a permutation" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x11a3);
    var data_rng = std.Random.DefaultPrng.init(0xda7b);
    inline for (.{ u8, u64, Ip17, Big, Huge }) |T| {
        for (lens) |n| {
            const in = try gpa.alloc(T, n);
            defer gpa.free(in);
            fill(T, in, .random, data_rng.random());
            for (std.enums.values(StableScratch)) |how| {
                const v = try gpa.dupe(T, in);
                defer gpa.free(v);
                var calls: usize = 0;
                const liar: Liar = .{ .r = &prng, .calls = &calls };
                switch (how) {
                    .alloc => try sort.stable(T, gpa, v, liar, Liar.lessT(T)),
                    .min_buffer, .full_buffer => {
                        const s = try gpa.alloc(T, if (how == .min_buffer) sort.stableScratchLen(n) else @max(n, sort.stableScratchLen(n)));
                        defer gpa.free(s);
                        sort.stableBuffer(T, v, s, liar, Liar.lessT(T));
                    },
                }
                try expectSameMultiset(T, gpa, in, v);
                const lg = std.math.log2_int(usize, n | 1) + 1;
                try testing.expect(calls <= 64 * (n + 1) * lg);
            }
        }
    }
}

test "stable reports OutOfMemory and leaves the input a permutation" {
    const T = Tagged(0);
    var v: [5000]T = undefined;
    for (&v, 0..) |*x, i| x.* = .{ .key = @intCast((i * 7919) % 1000), .tag = @intCast(i) };
    const before = v;
    try testing.expectError(error.OutOfMemory, sort.stable(T, testing.failing_allocator, &v, {}, T.less));
    try testing.expectEqualSlices(u8, std.mem.asBytes(&before), std.mem.asBytes(&v));
    // Small inputs never allocate: insertion sort, or scratch on the stack.
    var small: [300]T = undefined;
    for (&small, 0..) |*x, i| x.* = .{ .key = @intCast((i * 31) % 17), .tag = @intCast(i) };
    try sort.stable(T, testing.failing_allocator, &small, {}, T.less);
    try testing.expect(std.sort.isSorted(T, &small, {}, T.less));
}

// ── selectNth ───────────────────────────────────────────────────────────────

fn checkSelected(comptime T: type, gpa: std.mem.Allocator, in: []const T, v: []const T, index: usize, model_sorted: []const T) !void {
    const less = lessBy(T);
    try testing.expectEqual(keyOf(T, model_sorted[index]), keyOf(T, v[index]));
    for (v[0..index]) |x| try testing.expect(!less({}, v[index], x));
    for (v[index + 1 ..]) |x| try testing.expect(!less({}, x, v[index]));
    try expectSameMultiset(T, gpa, in, v);
}

fn selectSweep(comptime T: type) !void {
    var prng = std.Random.DefaultPrng.init(0x5e1ec7);
    const r = prng.random();
    const gpa = testing.allocator;
    for (lens) |n| {
        if (n == 0) continue;
        const in = try gpa.alloc(T, n);
        defer gpa.free(in);
        const v = try gpa.alloc(T, n);
        defer gpa.free(v);
        const model = try gpa.alloc(T, n);
        defer gpa.free(model);
        for (std.enums.values(Pattern)) |p| {
            fill(T, in, p, r);
            @memcpy(model, in);
            std.sort.block(T, model, {}, lessBy(T));
            // Every index for short slices; the ends, the middle and random
            // ones for long.
            const step = if (n <= 64) 1 else n / 23;
            var idx: usize = 0;
            while (idx < n) : (idx += step) {
                for ([_]usize{ idx, n - 1 - idx, r.uintLessThan(usize, n) }) |k| {
                    @memcpy(v, in);
                    sort.selectNth(T, v, k, {}, lessBy(T));
                    try checkSelected(T, gpa, in, v, k, model);
                }
            }
        }
    }
}

test "selectNth places the k-th element (u8, u64, Ip17, Big)" {
    try selectSweep(u8);
    try selectSweep(u64);
    try selectSweep(Ip17);
    try selectSweep(Big);
}

test "selectNth's median-of-medians fallback on its own" {
    // Reached in the real path only after 16 bad pivots; driven directly here.
    const gpa = testing.allocator;
    const Sel = @import("select.zig").Select(u64, void, lessBy(u64));
    var prng = std.Random.DefaultPrng.init(0xf00d);
    const r = prng.random();
    // 132 000: past 128 Ki, the ninther block shrinks to n/1024 (one case
    // only, it is slow in Debug).
    for ([_]usize{ 17, 18, 100, 1024, 1025, 3000, 132_000 }) |n| {
        const patterns: []const Pattern = if (n > 100_000) &.{.random} else &.{ .random, .few_distinct, .sorted, .descending, .pipe_organ };
        const in = try gpa.alloc(u64, n);
        defer gpa.free(in);
        const v = try gpa.alloc(u64, n);
        defer gpa.free(v);
        const model = try gpa.alloc(u64, n);
        defer gpa.free(model);
        for (patterns) |p| {
            fill(u64, in, p, r);
            @memcpy(model, in);
            std.sort.pdq(u64, model, {}, lessBy(u64));
            const ks: []const usize = if (n > 100_000) &.{n / 2} else &.{ 0, 1, n / 3, n / 2, n - 2, n - 1, r.uintLessThan(usize, n) };
            for (ks) |k| {
                @memcpy(v, in);
                Sel.medianOfMediansForTest(v, k, {});
                try checkSelected(u64, gpa, in, v, k, model);
            }
        }
    }
}

test "selectNth with a lying comparator returns a permutation" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x11a4);
    var data_rng = std.Random.DefaultPrng.init(0xda7c);
    inline for (.{ u8, u64, Ip17, Big }) |T| {
        for (lens) |n| {
            if (n == 0) continue;
            const in = try gpa.alloc(T, n);
            defer gpa.free(in);
            fill(T, in, .random, data_rng.random());
            for ([_]usize{ 0, n / 2, n - 1 }) |k| {
                const v = try gpa.dupe(T, in);
                defer gpa.free(v);
                var calls: usize = 0;
                sort.selectNth(T, v, k, Liar{ .r = &prng, .calls = &calls }, Liar.lessT(T));
                try expectSameMultiset(T, gpa, in, v);
            }
        }
    }
}

// ── byte-string order ───────────────────────────────────────────────────────

test "bytesLess agrees with std.mem.order on every length pair up to 20 and random bytes" {
    var prng = std.Random.DefaultPrng.init(0xb17e5);
    const r = prng.random();
    var a_buf: [40]u8 = undefined;
    var b_buf: [40]u8 = undefined;
    for (0..21) |la| for (0..21) |lb| for (0..200) |_| {
        r.bytes(a_buf[0..la]);
        // A shared prefix of random length, so the first difference lands
        // in every word position, the overlap tail and the byte loop.
        const common = r.uintAtMost(usize, @min(la, lb));
        @memcpy(b_buf[0..common], a_buf[0..common]);
        r.bytes(b_buf[common..lb]);
        if (r.boolean() and lb > common) b_buf[common] = if (common < la) a_buf[common] else b_buf[common];
        const a = a_buf[0..la];
        const b = b_buf[0..lb];
        try testing.expectEqual(std.mem.order(u8, a, b) == .lt, sort.bytesLess(a, b));
        try testing.expectEqual(std.mem.order(u8, b, a) == .lt, sort.bytesLess(b, a));
        try testing.expect(!sort.bytesLess(a, a));
    };
    // High bytes order above low ones (unsigned), and a prefix sorts first.
    try testing.expect(sort.bytesLess("\x7f", "\x80"));
    try testing.expect(sort.bytesLess("abcdefgh", "abcdefgh\x00"));
    try testing.expect(!sort.bytesLess("abcdefghi", "abcdefgh"));
}

test "asc/desc over byte strings sort lexicographically" {
    var v = [_][]const u8{ "pear", "apple", "", "apples", "app", "banana", "apple", "zebra-crossing!", "zebra", "\xff", "a" };
    sort.unstable([]const u8, &v, {}, sort.asc([]const u8));
    for (v[0 .. v.len - 1], v[1..]) |x, y| try testing.expect(std.mem.order(u8, x, y) != .gt);
    try sort.stable([]const u8, testing.allocator, &v, {}, sort.desc([]const u8));
    for (v[0 .. v.len - 1], v[1..]) |x, y| try testing.expect(std.mem.order(u8, x, y) != .lt);
}

// ── more broken orders, zero-sized types (review 2026-10-25) ────────────────

const LiarKind = enum { always, never, cyclic };

/// A comparator that is not an order, of a fixed shape: `always` (every
/// pair is "less" both ways), `never` (nothing is less: all "equal", which
/// IS a weak order and must sort to the input unchanged as a permutation),
/// `cyclic` (by key mod 3: 0 < 1 < 2 < 0).
fn shaped(comptime T: type, comptime kind: LiarKind) fn (void, T, T) bool {
    return struct {
        fn f(_: void, a: T, b: T) bool {
            return switch (kind) {
                .always => true,
                .never => false,
                .cyclic => blk: {
                    const x = keyMod3(T, a);
                    const y = keyMod3(T, b);
                    break :blk (x + 1) % 3 == y;
                },
            };
        }
        fn keyMod3(comptime U: type, x: U) u64 {
            return std.hash.Wyhash.hash(0, std.mem.asBytes(&x)) % 3;
        }
    }.f;
}

fn shapedSweep(comptime T: type, comptime kind: LiarKind, ns: []const usize) !void {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5ba9e);
    for (ns) |n| {
        const in = try gpa.alloc(T, n);
        defer gpa.free(in);
        prng.random().bytes(std.mem.sliceAsBytes(in));
        const v = try gpa.alloc(T, n);
        defer gpa.free(v);
        const s = try gpa.alloc(T, @max(n, sort.stableScratchLen(n)));
        defer gpa.free(s);
        inline for (0..5) |alg| {
            @memcpy(v, in);
            switch (alg) {
                0 => sort.unstable(T, v, {}, shaped(T, kind)),
                1 => try sort.stable(T, gpa, v, {}, shaped(T, kind)),
                2 => sort.stableBuffer(T, v, s[0..sort.stableScratchLen(n)], {}, shaped(T, kind)),
                3 => sort.stableBuffer(T, v, s, {}, shaped(T, kind)),
                else => if (n > 0) sort.selectNth(T, v, n / 2, {}, shaped(T, kind)),
            }
            try expectSameMultiset(T, gpa, in, v);
            // "Nothing is less" is a valid order: a stable sort keeps the input.
            if (kind == .never and (alg == 1 or alg == 2 or alg == 3))
                try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(in), std.mem.sliceAsBytes(v));
        }
    }
}

test "always-less, never-less and cyclic comparators return a permutation (every size, every entry point)" {
    const ns = [_]usize{ 0, 1, 2, 9, 20, 21, 33, 64, 65, 300, 1025, 5000 };
    inline for (.{ LiarKind.always, LiarKind.never, LiarKind.cyclic }) |kind| {
        try shapedSweep(u8, kind, &ns);
        try shapedSweep(u64, kind, &ns);
        try shapedSweep(Ip17, kind, &ns);
        try shapedSweep(Big, kind, &ns);
        try shapedSweep(Huge, kind, &.{ 0, 1, 21, 65, 300 });
        // 4104 bytes: no stack scratch, fallback small sort, Hoare partition.
        try shapedSweep(Tagged(4096), kind, &.{ 0, 1, 21, 65, 120 });
    }
}

test "selectNth with a random liar: Huge elements, and the median-of-medians fallback directly" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x11a5);
    var data_rng = std.Random.DefaultPrng.init(0xda7d);
    for ([_]usize{ 1, 17, 300, 1025 }) |n| {
        const in = try gpa.alloc(Huge, n);
        defer gpa.free(in);
        fill(Huge, in, .random, data_rng.random());
        const v = try gpa.dupe(Huge, in);
        defer gpa.free(v);
        var calls: usize = 0;
        sort.selectNth(Huge, v, n / 2, Liar{ .r = &prng, .calls = &calls }, Liar.lessT(Huge));
        try expectSameMultiset(Huge, gpa, in, v);
    }
    const Sel = @import("select.zig").Select(u64, Liar, Liar.lessT(u64));
    for ([_]usize{ 17, 100, 1025, 3000 }) |n| {
        const in = try gpa.alloc(u64, n);
        defer gpa.free(in);
        fill(u64, in, .random, data_rng.random());
        for ([_]usize{ 0, 1, n / 2, n - 1 }) |k| {
            const v = try gpa.dupe(u64, in);
            defer gpa.free(v);
            var calls: usize = 0;
            Sel.medianOfMediansForTest(v, k, .{ .r = &prng, .calls = &calls });
            try expectSameMultiset(u64, gpa, in, v);
        }
    }
}

test "zero-sized elements: every entry point returns at once" {
    const none = struct {
        fn f(_: void, _: void, _: void) bool {
            unreachable; // never called for a zero-sized type
        }
    }.f;
    var v: [100]void = @splat({});
    var s: [0]void = .{};
    try sort.stable(void, testing.failing_allocator, &v, {}, none);
    sort.stableBuffer(void, &v, &s, {}, none);
    sort.selectNth(void, &v, 99, {}, none);
    sort.unstable(void, &v, {}, none);
}
