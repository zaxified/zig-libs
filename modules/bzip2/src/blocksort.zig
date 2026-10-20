// SPDX-License-Identifier: MIT

//! The Burrows-Wheeler block sort, ported from libbzip2 1.0.8 blocksort.c
//! (BSD-style licence, see ../NOTICE; altered: translated to Zig, the C
//! buffer aliasing replaced by typed slices). Two sorters: the main one
//! (radix pass, 3-way string quicksort, shell sort, bucket-pointer
//! synthesis) with a work budget, and the fallback O(n log^2 n) sorter
//! (Manber-Myers style doubling) for blocks that exhaust the budget. Which
//! one ran decides the order of identical rotations and with it the stored
//! `orig_ptr`, so both are kept decision for decision.

const std = @import("std");

/// Extra bytes copied past the block end so comparisons can run off it.
pub const n_overshoot = 2 + 12 + 18 + 2;
const n_radix = 2;
const n_qsort = 12;

inline fn ix(v: i32) usize {
    return @intCast(v);
}

// ── fallback sort ───────────────────────────────────────────────────────

fn fallbackSimpleSort(fmap: []u32, eclass: []const u32, lo: i32, hi: i32) void {
    if (lo == hi) return;
    var i: i32 = undefined;
    var j: i32 = undefined;
    if (hi - lo > 3) {
        i = hi - 4;
        while (i >= lo) : (i -= 1) {
            const tmp = fmap[ix(i)];
            const ec_tmp = eclass[tmp];
            j = i + 4;
            while (j <= hi and ec_tmp > eclass[fmap[ix(j)]]) : (j += 4) fmap[ix(j - 4)] = fmap[ix(j)];
            fmap[ix(j - 4)] = tmp;
        }
    }
    i = hi - 1;
    while (i >= lo) : (i -= 1) {
        const tmp = fmap[ix(i)];
        const ec_tmp = eclass[tmp];
        j = i + 1;
        while (j <= hi and ec_tmp > eclass[fmap[ix(j)]]) : (j += 1) fmap[ix(j - 1)] = fmap[ix(j)];
        fmap[ix(j - 1)] = tmp;
    }
}

fn fvswap(fmap: []u32, p1_: i32, p2_: i32, n_: i32) void {
    var p1 = p1_;
    var p2 = p2_;
    var n = n_;
    while (n > 0) {
        std.mem.swap(u32, &fmap[ix(p1)], &fmap[ix(p2)]);
        p1 += 1;
        p2 += 1;
        n -= 1;
    }
}

fn fallbackQSort3(fmap: []u32, eclass: []const u32, lo_st: i32, hi_st: i32) void {
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
            fallbackSimpleSort(fmap, eclass, lo, hi);
            continue;
        }

        r = ((r *% 7621) +% 1) % 32768;
        const r3 = r % 3;
        const med: u32 = if (r3 == 0)
            eclass[fmap[ix(lo)]]
        else if (r3 == 1)
            eclass[fmap[ix((lo + hi) >> 1)]]
        else
            eclass[fmap[ix(hi)]];

        var un_lo = lo;
        var lt_lo = lo;
        var un_hi = hi;
        var gt_hi = hi;

        while (true) {
            while (true) {
                if (un_lo > un_hi) break;
                const n = @as(i32, @bitCast(eclass[fmap[ix(un_lo)]])) -% @as(i32, @bitCast(med));
                if (n == 0) {
                    std.mem.swap(u32, &fmap[ix(un_lo)], &fmap[ix(lt_lo)]);
                    lt_lo += 1;
                    un_lo += 1;
                    continue;
                }
                if (n > 0) break;
                un_lo += 1;
            }
            while (true) {
                if (un_lo > un_hi) break;
                const n = @as(i32, @bitCast(eclass[fmap[ix(un_hi)]])) -% @as(i32, @bitCast(med));
                if (n == 0) {
                    std.mem.swap(u32, &fmap[ix(un_hi)], &fmap[ix(gt_hi)]);
                    gt_hi -= 1;
                    un_hi -= 1;
                    continue;
                }
                if (n < 0) break;
                un_hi -= 1;
            }
            if (un_lo > un_hi) break;
            std.mem.swap(u32, &fmap[ix(un_lo)], &fmap[ix(un_hi)]);
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

inline fn setBh(bh: []u32, z: usize) void {
    bh[z >> 5] |= @as(u32, 1) << @intCast(z & 31);
}
inline fn clearBh(bh: []u32, z: usize) void {
    bh[z >> 5] &= ~(@as(u32, 1) << @intCast(z & 31));
}
inline fn isSetBh(bh: []const u32, z: usize) bool {
    return bh[z >> 5] & (@as(u32, 1) << @intCast(z & 31)) != 0;
}

/// Sorts the rotations of the `nblock` bytes at the start of `eclass`'s
/// memory into `fmap`; `bhtab` is scratch (2 + nblock/32 words and the
/// sentinel words). Afterwards the block bytes are restored.
pub fn fallbackSort(fmap: []u32, eclass: []u32, bhtab: []u32, nblock: usize) void {
    var ftab: [257]i32 = undefined;
    var ftab_copy: [256]i32 = undefined;
    const eclass8 = std.mem.sliceAsBytes(eclass);

    @memset(&ftab, 0);
    for (0..nblock) |i| ftab[eclass8[i]] += 1;
    for (0..256) |i| ftab_copy[i] = ftab[i];
    for (1..257) |i| ftab[i] += ftab[i - 1];

    for (0..nblock) |i| {
        const j = eclass8[i];
        const k = ftab[j] - 1;
        ftab[j] = k;
        fmap[ix(k)] = @intCast(i);
    }

    const n_bhtab = 2 + nblock / 32;
    @memset(bhtab[0..n_bhtab], 0);
    for (0..256) |i| setBh(bhtab, ix(ftab[i]));

    for (0..32) |i| {
        setBh(bhtab, nblock + 2 * i);
        clearBh(bhtab, nblock + 2 * i + 1);
    }

    const nb: i32 = @intCast(nblock);
    var h: i32 = 1;
    while (true) {
        var j: u32 = 0;
        for (0..nblock) |i| {
            if (isSetBh(bhtab, i)) j = @intCast(i);
            var k: i32 = @as(i32, @intCast(fmap[i])) - h;
            if (k < 0) k += nb;
            eclass[ix(k)] = j;
        }

        var n_not_done: i32 = 0;
        var r: i32 = -1;
        while (true) {
            var k: usize = @intCast(r + 1);
            while (isSetBh(bhtab, k) and (k & 31) != 0) k += 1;
            if (isSetBh(bhtab, k)) {
                while (bhtab[k >> 5] == 0xffff_ffff) k += 32;
                while (isSetBh(bhtab, k)) k += 1;
            }
            const l: i32 = @as(i32, @intCast(k)) - 1;
            if (l >= nb) break;
            while (!isSetBh(bhtab, k) and (k & 31) != 0) k += 1;
            if (!isSetBh(bhtab, k)) {
                while (bhtab[k >> 5] == 0) k += 32;
                while (!isSetBh(bhtab, k)) k += 1;
            }
            r = @as(i32, @intCast(k)) - 1;
            if (r >= nb) break;

            if (r > l) {
                n_not_done += r - l + 1;
                fallbackQSort3(fmap, eclass, l, r);

                var cc: i64 = -1;
                var i = l;
                while (i <= r) : (i += 1) {
                    const cc1: i64 = eclass[fmap[ix(i)]];
                    if (cc != cc1) {
                        setBh(bhtab, ix(i));
                        cc = cc1;
                    }
                }
            }
        }

        h *= 2;
        if (h > nb or n_not_done == 0) break;
    }

    var j: usize = 0;
    for (0..nblock) |i| {
        while (ftab_copy[j] == 0) j += 1;
        ftab_copy[j] -= 1;
        eclass8[fmap[i]] = @intCast(j);
    }
}

// ── main sort ───────────────────────────────────────────────────────────

fn mainGtU(i1_: u32, i2_: u32, block: []const u8, quadrant: []const u16, nblock: u32, budget: *i32) bool {
    var a: usize = i1_;
    var b: usize = i2_;
    inline for (0..12) |_| {
        const c1 = block[a];
        const c2 = block[b];
        if (c1 != c2) return c1 > c2;
        a += 1;
        b += 1;
    }
    var k: i32 = @intCast(nblock + 8);
    while (true) {
        inline for (0..8) |_| {
            const c1 = block[a];
            const c2 = block[b];
            if (c1 != c2) return c1 > c2;
            const s1 = quadrant[a];
            const s2 = quadrant[b];
            if (s1 != s2) return s1 > s2;
            a += 1;
            b += 1;
        }
        if (a >= nblock) a -= nblock;
        if (b >= nblock) b -= nblock;
        k -= 8;
        budget.* -= 1;
        if (k < 0) break;
    }
    return false;
}

const incs = [14]i32{ 1, 4, 13, 40, 121, 364, 1093, 3280, 9841, 29524, 88573, 265720, 797161, 2391484 };

fn mainSimpleSort(ptr: []u32, block: []const u8, quadrant: []const u16, nblock: u32, lo: i32, hi: i32, d: u32, budget: *i32) void {
    const big_n = hi - lo + 1;
    if (big_n < 2) return;

    var hp: usize = 0;
    while (incs[hp] < big_n) hp += 1;
    var hp_i: i32 = @intCast(hp);
    hp_i -= 1;

    while (hp_i >= 0) : (hp_i -= 1) {
        const h = incs[@intCast(hp_i)];
        var i = lo + h;
        outer: while (true) {
            inline for (0..3) |_| {
                if (i > hi) break :outer;
                const v = ptr[ix(i)];
                var j = i;
                while (mainGtU(ptr[ix(j - h)] + d, v + d, block, quadrant, nblock, budget)) {
                    ptr[ix(j)] = ptr[ix(j - h)];
                    j = j - h;
                    if (j <= (lo + h - 1)) break;
                }
                ptr[ix(j)] = v;
                i += 1;
            }
            if (budget.* < 0) return;
        }
    }
}

fn mmed3(a_: u8, b_: u8, c: u8) u8 {
    var a = a_;
    var b = b_;
    if (a > b) std.mem.swap(u8, &a, &b);
    if (b > c) {
        b = c;
        if (a > b) b = a;
    }
    return b;
}

fn mvswap(ptr: []u32, p1_: i32, p2_: i32, n_: i32) void {
    var p1 = p1_;
    var p2 = p2_;
    var n = n_;
    while (n > 0) {
        std.mem.swap(u32, &ptr[ix(p1)], &ptr[ix(p2)]);
        p1 += 1;
        p2 += 1;
        n -= 1;
    }
}

fn mainQSort3(ptr: []u32, block: []const u8, quadrant: []const u16, nblock: u32, lo_st: i32, hi_st: i32, d_st: u32, budget: *i32) void {
    var stack_lo: [100]i32 = undefined;
    var stack_hi: [100]i32 = undefined;
    var stack_d: [100]u32 = undefined;
    var next_lo: [3]i32 = undefined;
    var next_hi: [3]i32 = undefined;
    var next_d: [3]u32 = undefined;
    var sp: usize = 0;

    stack_lo[0] = lo_st;
    stack_hi[0] = hi_st;
    stack_d[0] = d_st;
    sp = 1;

    while (sp > 0) {
        sp -= 1;
        const lo = stack_lo[sp];
        const hi = stack_hi[sp];
        const d = stack_d[sp];
        if (hi - lo < 20 or d > n_radix + n_qsort) {
            mainSimpleSort(ptr, block, quadrant, nblock, lo, hi, d, budget);
            if (budget.* < 0) return;
            continue;
        }

        const med: i32 = mmed3(block[ptr[ix(lo)] + d], block[ptr[ix(hi)] + d], block[ptr[ix((lo + hi) >> 1)] + d]);

        var un_lo = lo;
        var lt_lo = lo;
        var un_hi = hi;
        var gt_hi = hi;

        while (true) {
            while (true) {
                if (un_lo > un_hi) break;
                const n = @as(i32, block[ptr[ix(un_lo)] + d]) - med;
                if (n == 0) {
                    std.mem.swap(u32, &ptr[ix(un_lo)], &ptr[ix(lt_lo)]);
                    lt_lo += 1;
                    un_lo += 1;
                    continue;
                }
                if (n > 0) break;
                un_lo += 1;
            }
            while (true) {
                if (un_lo > un_hi) break;
                const n = @as(i32, block[ptr[ix(un_hi)] + d]) - med;
                if (n == 0) {
                    std.mem.swap(u32, &ptr[ix(un_hi)], &ptr[ix(gt_hi)]);
                    gt_hi -= 1;
                    un_hi -= 1;
                    continue;
                }
                if (n < 0) break;
                un_hi -= 1;
            }
            if (un_lo > un_hi) break;
            std.mem.swap(u32, &ptr[ix(un_lo)], &ptr[ix(un_hi)]);
            un_lo += 1;
            un_hi -= 1;
        }

        if (gt_hi < lt_lo) {
            stack_lo[sp] = lo;
            stack_hi[sp] = hi;
            stack_d[sp] = d + 1;
            sp += 1;
            continue;
        }

        var n = @min(lt_lo - lo, un_lo - lt_lo);
        mvswap(ptr, lo, un_lo - n, n);
        var m = @min(hi - gt_hi, gt_hi - un_hi);
        mvswap(ptr, un_lo, hi - m + 1, m);

        n = lo + un_lo - lt_lo - 1;
        m = hi - (gt_hi - un_hi) + 1;

        next_lo[0] = lo;
        next_hi[0] = n;
        next_d[0] = d;
        next_lo[1] = m;
        next_hi[1] = hi;
        next_d[1] = d;
        next_lo[2] = n + 1;
        next_hi[2] = m - 1;
        next_d[2] = d + 1;

        if (nextSize(&next_lo, &next_hi, 0) < nextSize(&next_lo, &next_hi, 1)) nextSwap(&next_lo, &next_hi, &next_d, 0, 1);
        if (nextSize(&next_lo, &next_hi, 1) < nextSize(&next_lo, &next_hi, 2)) nextSwap(&next_lo, &next_hi, &next_d, 1, 2);
        if (nextSize(&next_lo, &next_hi, 0) < nextSize(&next_lo, &next_hi, 1)) nextSwap(&next_lo, &next_hi, &next_d, 0, 1);

        for (0..3) |q| {
            stack_lo[sp] = next_lo[q];
            stack_hi[sp] = next_hi[q];
            stack_d[sp] = next_d[q];
            sp += 1;
        }
    }
}

inline fn nextSize(lo: *const [3]i32, hi: *const [3]i32, a: usize) i32 {
    return hi[a] - lo[a];
}
inline fn nextSwap(lo: *[3]i32, hi: *[3]i32, d: *[3]u32, a: usize, b: usize) void {
    std.mem.swap(i32, &lo[a], &lo[b]);
    std.mem.swap(i32, &hi[a], &hi[b]);
    std.mem.swap(u32, &d[a], &d[b]);
}

const set_mask: u32 = 1 << 21;
const clear_mask: u32 = ~set_mask;

inline fn bigFreq(ftab: []const u32, b: usize) u32 {
    return ftab[(b + 1) << 8] - ftab[b << 8];
}

fn mainSort(ptr: []u32, block: []u8, quadrant: []u16, ftab: []u32, nblock: u32, budget: *i32) void {
    var running_order: [256]u32 = undefined;
    var big_done: [256]bool = undefined;
    var copy_start: [256]i32 = undefined;
    var copy_end: [256]i32 = undefined;
    const nb: usize = nblock;

    @memset(ftab[0..65537], 0);

    var j: u32 = @as(u32, block[0]) << 8;
    var i: isize = @as(isize, @intCast(nb)) - 1;
    while (i >= 0) : (i -= 1) {
        const u: usize = @intCast(i);
        quadrant[u] = 0;
        j = (j >> 8) | (@as(u32, block[u]) << 8);
        ftab[j] += 1;
    }

    for (0..n_overshoot) |k| {
        block[nb + k] = block[k];
        quadrant[nb + k] = 0;
    }

    for (1..65537) |k| ftab[k] += ftab[k - 1];

    var s: u16 = @as(u16, block[0]) << 8;
    i = @as(isize, @intCast(nb)) - 1;
    while (i >= 0) : (i -= 1) {
        const u: usize = @intCast(i);
        s = (s >> 8) | (@as(u16, block[u]) << 8);
        const jj = ftab[s] - 1;
        ftab[s] = jj;
        ptr[jj] = @intCast(u);
    }

    for (0..256) |k| {
        big_done[k] = false;
        running_order[k] = @intCast(k);
    }

    {
        var h: usize = 1;
        while (true) {
            h = 3 * h + 1;
            if (h > 256) break;
        }
        while (true) {
            h = h / 3;
            var q: usize = h;
            while (q <= 255) : (q += 1) {
                const vv = running_order[q];
                var jq = q;
                while (bigFreq(ftab, running_order[jq - h]) > bigFreq(ftab, vv)) {
                    running_order[jq] = running_order[jq - h];
                    jq -= h;
                    if (jq <= h - 1) break;
                }
                running_order[jq] = vv;
            }
            if (h == 1) break;
        }
    }

    for (0..256) |oi| {
        const ss: usize = running_order[oi];

        // Step 1: quicksort the unsorted small buckets [ss, j], j != ss.
        for (0..256) |jj| {
            if (jj != ss) {
                const sb = (ss << 8) + jj;
                if (ftab[sb] & set_mask == 0) {
                    const lo: i32 = @intCast(ftab[sb] & clear_mask);
                    const hi: i32 = @as(i32, @intCast(ftab[sb + 1] & clear_mask)) - 1;
                    if (hi > lo) {
                        mainQSort3(ptr, block, quadrant, nblock, lo, hi, n_radix, budget);
                        if (budget.* < 0) return;
                    }
                }
                ftab[sb] |= set_mask;
            }
        }

        // Step 2: scan the big bucket to synthesise the small buckets [t, ss].
        for (0..256) |jj| {
            copy_start[jj] = @intCast(ftab[(jj << 8) + ss] & clear_mask);
            copy_end[jj] = @as(i32, @intCast(ftab[(jj << 8) + ss + 1] & clear_mask)) - 1;
        }
        {
            var q: i32 = @intCast(ftab[ss << 8] & clear_mask);
            while (q < copy_start[ss]) : (q += 1) {
                var k: i32 = @as(i32, @intCast(ptr[ix(q)])) - 1;
                if (k < 0) k += @intCast(nb);
                const c1 = block[ix(k)];
                if (!big_done[c1]) {
                    ptr[ix(copy_start[c1])] = @intCast(k);
                    copy_start[c1] += 1;
                }
            }
            q = @as(i32, @intCast(ftab[(ss + 1) << 8] & clear_mask)) - 1;
            while (q > copy_end[ss]) : (q -= 1) {
                var k: i32 = @as(i32, @intCast(ptr[ix(q)])) - 1;
                if (k < 0) k += @intCast(nb);
                const c1 = block[ix(k)];
                if (!big_done[c1]) {
                    ptr[ix(copy_end[c1])] = @intCast(k);
                    copy_end[c1] -= 1;
                }
            }
        }

        for (0..256) |jj| ftab[(jj << 8) + ss] |= set_mask;

        // Step 3: the big bucket is done; update the quadrant descriptors.
        big_done[ss] = true;

        if (oi < 255) {
            const bb_start: usize = ftab[ss << 8] & clear_mask;
            const bb_size: usize = (ftab[(ss + 1) << 8] & clear_mask) - bb_start;
            var shifts: u6 = 0;
            while ((bb_size >> shifts) > 65534) shifts += 1;

            var q: isize = @as(isize, @intCast(bb_size)) - 1;
            while (q >= 0) : (q -= 1) {
                const qu: usize = @intCast(q);
                const a2update = ptr[bb_start + qu];
                const q_val: u16 = @intCast(qu >> shifts);
                quadrant[a2update] = q_val;
                if (a2update < n_overshoot) quadrant[a2update + nb] = q_val;
            }
        }
    }
}

/// Sorts the rotations of `block[0..nblock]` (`nblock > 0`) into `ptr`.
/// `block` is `arr2`'s bytes (at least `nblock + n_overshoot` of them, then
/// room for the u16 quadrant array), `arr2` the same memory as `u32`s.
/// Returns `orig_ptr`, the position of rotation 0 in the sorted order.
pub fn blockSort(ptr: []u32, arr2: []u32, ftab: []u32, nblock: usize, work_factor: u32) u32 {
    const block = std.mem.sliceAsBytes(arr2);
    if (nblock < 10000) {
        fallbackSort(ptr, arr2, ftab, nblock);
    } else {
        var i = nblock + n_overshoot;
        if (i & 1 != 0) i += 1;
        const quadrant: []u16 = @alignCast(std.mem.bytesAsSlice(u16, block[i..][0 .. 2 * (nblock + n_overshoot)]));
        const wfact: i32 = @intCast(std.math.clamp(work_factor, 1, 100));
        var budget: i32 = @as(i32, @intCast(nblock)) * @divTrunc(wfact - 1, 3);
        mainSort(ptr, block, quadrant, ftab, @intCast(nblock), &budget);
        if (budget < 0) fallbackSort(ptr, arr2, ftab, nblock);
    }
    for (ptr[0..nblock], 0..) |p, k| if (p == 0) return @intCast(k);
    unreachable;
}
