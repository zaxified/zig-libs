// SPDX-License-Identifier: MIT

//! B4 (2026-11-18): the fallback sort's worst case is bounded. A block built
//! against libbzip2's pivot choice (`fallbackQSort3` picks the first, middle
//! or last element by an LCG seeded 0) makes the libbzip2 algorithm
//! quadratic; here the work counter must stop at the bound, and the sort must
//! still be right. Time-independent: work is counted, nothing is timed.

const std = @import("std");
const testing = std.testing;
const blocksort = @import("blocksort.zig");
const bz = @import("root.zig");

const gas: u32 = std.math.maxInt(u32);

/// McIlroy-style adversary for `fallbackQSort3` (the same control flow, keys
/// undecided until used as a pivot): every pivot is frozen as the smallest
/// value still undecided, so each partition removes one element.
const Sim = struct {
    keys: []u32,
    next: u32 = 0,

    fn key(s: *Sim, e: u32) u32 {
        return s.keys[e];
    }
    fn freeze(s: *Sim, e: u32) void {
        if (s.keys[e] == gas) {
            s.keys[e] = s.next;
            s.next += 1;
        }
    }
    fn simpleSort(s: *Sim, fmap: []u32, lo: i32, hi: i32) void {
        var i = lo;
        while (i <= hi) : (i += 1) s.freeze(fmap[@intCast(i)]);
    }
    fn cmp(s: *Sim, e: u32, med: u32) i64 {
        const k = s.keys[e];
        if (k == gas) return 1;
        return @as(i64, k) - @as(i64, med);
    }
    fn qsort3(s: *Sim, fmap: []u32, lo_st: i32, hi_st: i32) void {
        var stack_lo: [100]i32 = undefined;
        var stack_hi: [100]i32 = undefined;
        var sp: usize = 0;
        var r: u32 = 0;
        stack_lo[sp] = lo_st;
        stack_hi[sp] = hi_st;
        sp += 1;
        while (sp > 0) {
            sp -= 1;
            const lo = stack_lo[sp];
            const hi = stack_hi[sp];
            if (hi - lo < 10) {
                s.simpleSort(fmap, lo, hi);
                continue;
            }
            r = ((r *% 7621) +% 1) % 32768;
            const r3 = r % 3;
            const pe = if (r3 == 0) fmap[@intCast(lo)] else if (r3 == 1) fmap[@intCast((lo + hi) >> 1)] else fmap[@intCast(hi)];
            s.freeze(pe);
            const med = s.keys[pe];
            var un_lo = lo;
            var lt_lo = lo;
            var un_hi = hi;
            var gt_hi = hi;
            while (true) {
                while (true) {
                    if (un_lo > un_hi) break;
                    const n = s.cmp(fmap[@intCast(un_lo)], med);
                    if (n == 0) {
                        std.mem.swap(u32, &fmap[@intCast(un_lo)], &fmap[@intCast(lt_lo)]);
                        lt_lo += 1;
                        un_lo += 1;
                        continue;
                    }
                    if (n > 0) break;
                    un_lo += 1;
                }
                while (true) {
                    if (un_lo > un_hi) break;
                    const n = s.cmp(fmap[@intCast(un_hi)], med);
                    if (n == 0) {
                        std.mem.swap(u32, &fmap[@intCast(un_hi)], &fmap[@intCast(gt_hi)]);
                        gt_hi -= 1;
                        un_hi -= 1;
                        continue;
                    }
                    if (n < 0) break;
                    un_hi -= 1;
                }
                if (un_lo > un_hi) break;
                std.mem.swap(u32, &fmap[@intCast(un_lo)], &fmap[@intCast(un_hi)]);
                un_lo += 1;
                un_hi -= 1;
            }
            if (gt_hi < lt_lo) continue;
            var n = @min(lt_lo - lo, un_lo - lt_lo);
            fvswap(fmap, lo, un_lo - n, n);
            var m = @min(hi - gt_hi, gt_hi - un_hi);
            fvswap(fmap, un_lo, hi - m + 1, m);
            n = lo + un_lo - lt_lo - 1;
            m = hi - (gt_hi - un_hi) + 1;
            if (n - lo > hi - m) {
                stack_lo[sp] = lo;
                stack_hi[sp] = n;
                sp += 1;
                stack_lo[sp] = m;
                stack_hi[sp] = hi;
                sp += 1;
            } else {
                stack_lo[sp] = m;
                stack_hi[sp] = hi;
                sp += 1;
                stack_lo[sp] = lo;
                stack_hi[sp] = n;
                sp += 1;
            }
        }
    }
};

fn fvswap(fmap: []u32, p1_: i32, p2_: i32, n_: i32) void {
    var p1 = p1_;
    var p2 = p2_;
    var n = n_;
    while (n > 0) {
        std.mem.swap(u32, &fmap[@intCast(p1)], &fmap[@intCast(p2)]);
        p1 += 1;
        p2 += 1;
        n -= 1;
    }
}

const digit_count = 198;
fn digitByte(d: u32) u8 {
    var b: u32 = d; // 0..197 -> bytes 0..199 without 'W' (0x57) and 'Z' (0x5a)
    if (b >= 0x57) b += 1;
    if (b >= 0x5a) b += 1;
    return @intCast(b);
}

/// `m` units "ZYXW" d1 d2 d3 0xff whose keys make every fallback pivot the minimum.
fn adversarial(gpa: std.mem.Allocator, m: usize) ![]u8 {
    const keys = try gpa.alloc(u32, m);
    defer gpa.free(keys);
    @memset(keys, gas);
    const fmap = try gpa.alloc(u32, m);
    defer gpa.free(fmap);
    for (fmap, 0..) |*f, i| f.* = @intCast(i);
    var sim: Sim = .{ .keys = keys };
    sim.qsort3(fmap, 0, @intCast(m - 1));
    for (0..m) |i| sim.freeze(@intCast(i));
    const out = try gpa.alloc(u8, 8 * m);
    for (0..m) |t| {
        const u = m - 1 - t; // fmap index t <-> unit u (decreasing positions)
        const k = keys[t];
        const unit = out[8 * u ..][0..8];
        unit[0..4].* = "ZYXW".*;
        unit[4] = digitByte(k / (digit_count * digit_count));
        unit[5] = digitByte(k / digit_count % digit_count);
        unit[6] = digitByte(k % digit_count);
        unit[7] = 0xff;
    }
    return out;
}

/// Same units, keys in a pseudo-random order (the control).
fn shuffled(gpa: std.mem.Allocator, m: usize) ![]u8 {
    const keys = try gpa.alloc(u32, m);
    defer gpa.free(keys);
    for (keys, 0..) |*k, i| k.* = @intCast(i);
    var prng = std.Random.DefaultPrng.init(7);
    prng.random().shuffle(u32, keys);
    const out = try gpa.alloc(u8, 8 * m);
    for (0..m) |u| {
        const k = keys[u];
        const unit = out[8 * u ..][0..8];
        unit[0..4].* = "ZYXW".*;
        unit[4] = digitByte(k / (digit_count * digit_count));
        unit[5] = digitByte(k / digit_count % digit_count);
        unit[6] = digitByte(k % digit_count);
        unit[7] = 0xff;
    }
    return out;
}

fn sortStats(gpa: std.mem.Allocator, block: []const u8, fmap: []u32) !blocksort.FallbackStats {
    return sortStatsBudget(gpa, block, fmap, blocksort.fallback_work_factor * 1000);
}

fn sortStatsBudget(gpa: std.mem.Allocator, block: []const u8, fmap: []u32, work_permille: u64) !blocksort.FallbackStats {
    const n = block.len;
    const arr2 = try gpa.alloc(u32, n + blocksort.n_overshoot);
    defer gpa.free(arr2);
    const ftab = try gpa.alloc(u32, 65537);
    defer gpa.free(ftab);
    @memcpy(std.mem.sliceAsBytes(arr2)[0..n], block);
    var st: blocksort.FallbackStats = .{};
    blocksort.fallbackSortWith(fmap, arr2, ftab, n, .{ .work_permille = work_permille, .stats = &st });
    // The block bytes are restored in place.
    try testing.expectEqualSlices(u8, block, std.mem.sliceAsBytes(arr2)[0..n]);
    return st;
}

/// Rotation `a` of `block` sorts at or before rotation `b`.
fn rotationLe(block: []const u8, a: usize, b: usize) bool {
    const n = block.len;
    for (0..n) |i| {
        const x = block[(a + i) % n];
        const y = block[(b + i) % n];
        if (x != y) return x < y;
    }
    return true;
}

fn expectSortedRotations(block: []const u8, fmap: []const u32) !void {
    var seen = try testing.allocator.alloc(bool, block.len);
    defer testing.allocator.free(seen);
    @memset(seen, false);
    for (fmap) |p| {
        try testing.expect(!seen[p]);
        seen[p] = true;
    }
    for (fmap[0 .. fmap.len - 1], fmap[1..]) |a, b| try testing.expect(rotationLe(block, a, b));
}

test "B4: a block built against libbzip2's fallback pivots hits the work bound, and is still sorted" {
    const gpa = testing.allocator;
    const m = 4096; // 32 KiB: libbzip2's partition work on the "ZYXW" group alone is ~m^2/2 = 8.4 M
    const adv = try adversarial(gpa, m);
    defer gpa.free(adv);
    const fmap = try gpa.alloc(u32, adv.len);
    defer gpa.free(fmap);
    const st = try sortStats(gpa, adv, fmap);
    try expectSortedRotations(adv, fmap);
    try testing.expect(st.bounded >= 1);
    // The bounded call reached the bound (in thousandths of n * (log2 n + 1)).
    try testing.expect(st.peak_permille >= blocksort.fallback_work_factor * 1000);
    try testing.expect(st.work >= adv.len);
    // Every call stops at `fallback_work_factor * n * (log2(n) + 1)` plus one
    // range; the whole sort stays within that for the block as one call.
    const n: u64 = adv.len;
    const cap = blocksort.fallback_work_factor * n * (std.math.log2_int(u64, n) + 1);
    try testing.expect(st.work <= cap);
    try testing.expect(st.work < m * m / 2);

    // The same keys in a shuffled order: no call comes near the bound, so
    // every decision is libbzip2's (the golden tests pin the bytes).
    const ctl = try shuffled(gpa, m);
    defer gpa.free(ctl);
    const sc = try sortStats(gpa, ctl, fmap);
    try expectSortedRotations(ctl, fmap);
    try testing.expectEqual(@as(u32, 0), sc.bounded);
    try testing.expect(sc.peak_permille > 0 and sc.peak_permille < 4 * 1000);
    try testing.expect(sc.work >= ctl.len);
}

test "B4: the adversarial block round-trips through compress (default options) and decompress" {
    // A period-3 prefix burns the main sort's `work_factor` budget, so the
    // whole block goes to the fallback sort, whose libbzip2 form would be
    // quadratic on the units behind it: the encoder takes the bounded path
    // (measured in ReleaseFast: 270 ms before the bound, 29 ms after).
    const gpa = testing.allocator;
    const adv = try adversarial(gpa, 12_800);
    defer gpa.free(adv);
    const burner_len = adv.len / 8;
    const input = try gpa.alloc(u8, burner_len + adv.len);
    defer gpa.free(input);
    for (input[0..burner_len], 0..) |*b, i| b.* = "abc"[i % 3];
    @memcpy(input[burner_len..], adv);
    const z = try bz.compress(gpa, input, .{});
    defer gpa.free(z);
    const back = try bz.decompress(gpa, z, .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, input, back);
    // And the units alone (under 10 000 symbols: the fallback sort directly).
    const small = try adversarial(gpa, 1200);
    defer gpa.free(small);
    const zs = try bz.compress(gpa, small, .{});
    defer gpa.free(zs);
    const bs = try bz.decompress(gpa, zs, .{});
    defer gpa.free(bs);
    try testing.expectEqualSlices(u8, small, bs);
}

test "B4: a block sorted with the bound hit mid-call (pending ranges) has every rotation in order" {
    // A 4-letter random block, sorted once without a bound to learn the
    // costliest call's work, then with half of it as the bound: that call
    // stops with random, unsorted sub-ranges pending. Sorted rotations are
    // exactly what the BWT needs: a pending range left unsorted would write
    // a wrong transform.
    const gpa = testing.allocator;
    const block = try gpa.alloc(u8, 20_000);
    defer gpa.free(block);
    var prng = std.Random.DefaultPrng.init(0xb4b4);
    for (block) |*b| b.* = "acgt"[prng.random().uintLessThan(u8, 4)];
    const fmap = try gpa.alloc(u32, block.len);
    defer gpa.free(fmap);
    const free = try sortStatsBudget(gpa, block, fmap, std.math.maxInt(u32));
    try testing.expectEqual(@as(u32, 0), free.bounded);
    try expectSortedRotations(block, fmap);
    try testing.expect(free.peak_permille >= 2);
    const st = try sortStatsBudget(gpa, block, fmap, free.peak_permille / 2);
    try testing.expect(st.bounded >= 1);
    try testing.expect(st.pending_at_bound >= 1);
    try expectSortedRotations(block, fmap);
    // The same data through the encoder (its own sort, default bound) and back.
    const z = try bz.compress(gpa, block, .{});
    defer gpa.free(z);
    const back = try bz.decompress(gpa, z, .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, block, back);
}
