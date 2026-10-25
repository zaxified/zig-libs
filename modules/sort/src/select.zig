// SPDX-License-Identifier: MIT

//! Introselect — Rust's `slice::select_nth_unstable`, ported from
//! `core::slice::sort::select` (Rust 1.93.1, see `../NOTICE`).
//!
//! Quickselect on ipnsort's pivot choice and branchless partition, with the
//! same "equal to the ancestor pivot" step for duplicates. After 16 rounds
//! it falls back to a quickselect whose pivot is a median of medians built
//! from Tukey's ninthers (Alexandrescu, "Fast Deterministic Selection",
//! SEA 2017), which keeps the worst case `O(n)`.

const std = @import("std");
const smallsort = @import("smallsort.zig");
const unstable = @import("unstable.zig");

/// Slices this short are insertion-sorted: the selection runs once, a better
/// small sort would not pay for its code.
const insertion_threshold = 16;
/// Quickselect rounds before the deterministic fallback; a constant, since a
/// `log n` budget would make the fallback `O(n log n)`.
const quickselect_limit = 16;

pub fn Select(comptime T: type, comptime Ctx: type, comptime lessThanFn: fn (Ctx, T, T) bool) type {
    return struct {
        const S = smallsort.Small(T, Ctx, lessThanFn);
        const U = unstable.Unstable(T, Ctx, lessThanFn);
        const lt = S.lt;

        pub fn select(v: []T, index: usize, ctx: Ctx) void {
            if (index >= v.len) @panic("sort.selectNth: index out of bounds");
            if (@sizeOf(T) == 0) return;
            const p = v.ptr;
            if (index == v.len - 1) {
                S.swapElems(&p[maxIndex(p, v.len, ctx)], &p[index]);
            } else if (index == 0) {
                S.swapElems(&p[minIndex(p, v.len, ctx)], &p[0]);
            } else {
                loop(p, v.len, index, ctx);
            }
        }

        fn loop(v_in: [*]T, len_in: usize, index_in: usize, ctx: Ctx) void {
            var v = v_in;
            var len = len_in;
            var index = index_in;
            var ancestor: ?*const T = null;
            var limit: u32 = quickselect_limit;
            while (true) {
                if (len <= insertion_threshold) {
                    if (len >= 2) S.insertionSortShiftLeft(v, len, 1, ctx);
                    return;
                }
                if (limit == 0) {
                    medianOfMedians(v, len, index, ctx);
                    return;
                }
                limit -= 1;
                const pivot_pos = U.choosePivot(v, len, ctx);
                if (ancestor) |a| {
                    if (!lt(ctx, a, &v[pivot_pos])) {
                        // The pivot is the slice's minimum: skip everything equal to it.
                        const mid = U.partition(.le, v, len, pivot_pos, ctx) + 1;
                        if (mid > index) return;
                        v += mid;
                        len -= mid;
                        index -= mid;
                        ancestor = null;
                        continue;
                    }
                }
                const mid = U.partition(.lt, v, len, pivot_pos, ctx);
                if (mid < index) {
                    ancestor = &v[mid];
                    v += mid + 1;
                    len -= mid + 1;
                    index -= mid + 1;
                } else if (mid > index) {
                    len = mid;
                } else return;
            }
        }

        fn minIndex(v: [*]const T, len: usize, ctx: Ctx) usize {
            var best: usize = 0;
            for (1..len) |i| {
                if (lt(ctx, &v[i], &v[best])) best = i;
            }
            return best;
        }

        fn maxIndex(v: [*]const T, len: usize, ctx: Ctx) usize {
            var best: usize = 0;
            for (1..len) |i| {
                if (lt(ctx, &v[best], &v[i])) best = i;
            }
            return best;
        }

        /// Deterministic `O(n)` selection of `v[k]`: a quickselect pivoting
        /// on the median of ninthers.
        fn medianOfMedians(v_in: [*]T, len_in: usize, k_in: usize, ctx: Ctx) void {
            var v = v_in;
            var len = len_in;
            var k = k_in;
            std.debug.assert(k < len);
            while (true) {
                if (len <= insertion_threshold) {
                    if (len >= 2) S.insertionSortShiftLeft(v, len, 1, ctx);
                    return;
                }
                // The ninther layout cannot reach the two ends.
                if (k == len - 1) {
                    S.swapElems(&v[maxIndex(v, len, ctx)], &v[k]);
                    return;
                } else if (k == 0) {
                    S.swapElems(&v[minIndex(v, len, ctx)], &v[0]);
                    return;
                }
                const p = medianOfNinthers(v, len, ctx);
                if (p == k) {
                    return;
                } else if (p > k) {
                    len = p;
                } else {
                    v += p + 1;
                    len -= p + 1;
                    k -= p + 1;
                }
            }
        }

        /// Gathers the median of each of `frac` ninthers into the middle
        /// block `v[lo..lo+frac]`, selects that block's median, and
        /// partitions the whole slice around it. Returns the pivot's place.
        fn medianOfNinthers(v: [*]T, len: usize, ctx: Ctx) usize {
            const frac = if (len <= 1024) len / 12 else if (len <= 128 * 1024) len / 64 else len / 1024;
            const pivot = frac / 2;
            const lo = len / 2 - pivot;
            const hi = frac + lo;
            const gap = (len - 9 * frac) / 4;
            var a = lo - 4 * frac - gap;
            var b = hi + gap;
            var i = lo;
            while (i < hi) : (i += 1) {
                ninther(v, ctx, a, i - frac, b, a + 1, i, b + 1, a + 2, i + frac, b + 2);
                a += 3;
                b += 3;
            }
            medianOfMedians(v + lo, frac, pivot, ctx);
            return U.partition(.lt, v, len, lo + pivot, ctx);
        }

        /// Puts the median of the nine elements at the given indices into
        /// `v[e]`, with smaller ones at lower and larger at higher indices of
        /// its own triple.
        fn ninther(v: [*]T, ctx: Ctx, a: usize, b_in: usize, c: usize, d_in: usize, e: usize, f_in: usize, g: usize, h_in: usize, i: usize) void {
            var b = medianIdx(v, ctx, a, b_in, c);
            var h = medianIdx(v, ctx, g, h_in, i);
            var d = d_in;
            var f = f_in;
            if (lt(ctx, &v[h], &v[b])) std.mem.swap(usize, &b, &h);
            if (lt(ctx, &v[f], &v[d])) std.mem.swap(usize, &d, &f);
            if (lt(ctx, &v[e], &v[d])) {
                // keep d
            } else if (lt(ctx, &v[f], &v[e])) {
                d = f;
            } else {
                if (lt(ctx, &v[e], &v[b])) {
                    S.swapElems(&v[e], &v[b]);
                } else if (lt(ctx, &v[h], &v[e])) {
                    S.swapElems(&v[e], &v[h]);
                }
                return;
            }
            if (lt(ctx, &v[d], &v[b])) {
                d = b;
            } else if (lt(ctx, &v[h], &v[d])) {
                d = h;
            }
            S.swapElems(&v[d], &v[e]);
        }

        fn medianIdx(v: [*]const T, ctx: Ctx, a_in: usize, b: usize, c_in: usize) usize {
            var a = a_in;
            var c = c_in;
            if (lt(ctx, &v[c], &v[a])) std.mem.swap(usize, &a, &c);
            if (lt(ctx, &v[c], &v[b])) return c;
            if (lt(ctx, &v[b], &v[a])) return a;
            return b;
        }

        /// Test seam: the deterministic fallback alone.
        pub fn medianOfMediansForTest(v: []T, k: usize, ctx: Ctx) void {
            medianOfMedians(v.ptr, v.len, k, ctx);
        }
    };
}
