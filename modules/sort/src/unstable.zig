// SPDX-License-Identifier: MIT

//! ipnsort — the unstable sort of Rust's `slice::sort_unstable` (Lukas
//! Bergdoll and Orson Peters), ported from `core::slice::sort::unstable` and
//! `shared::pivot` (Rust 1.93.1, see `../NOTICE`). Design:
//! https://github.com/Voultapher/sort-research-rs/blob/main/writeup/ipnsort_introduction/text.md
//!
//! Shape: insertion sort up to 20 elements; otherwise detect a fully sorted
//! or strictly descending input in one pass, else introsort-style quicksort
//! (recursion budget `2·⌊log2 n⌋`, then heapsort) with
//!   - pivot = recursive pseudo-median of three over ~n^0.53 samples (glidesort),
//!   - branchless Lomuto partition with a cyclic permutation for elements up
//!     to 96 bytes, a branchy cyclic Hoare partition above that,
//!   - an "equal to the ancestor pivot" partition that swallows duplicates,
//!   - type-dependent small sorts below 16–32 elements (`smallsort.zig`).

const std = @import("std");
const smallsort = @import("smallsort.zig");

/// Inputs up to this length are insertion-sorted outright (Rust's
/// `MAX_LEN_ALWAYS_INSERTION_SORT`: the i-cache matters more than the
/// comparisons for a cold call on a tiny slice).
pub const max_len_always_insertion = 20;
/// Larger elements use the branchy Hoare partition instead of branchless Lomuto.
pub const max_branchless_partition_size = 96;
/// Recursive pseudo-median above this length (Rust `PSEUDO_MEDIAN_REC_THRESHOLD`).
const pseudo_median_rec_threshold = 64;

pub fn Unstable(comptime T: type, comptime Ctx: type, comptime lessThanFn: fn (Ctx, T, T) bool) type {
    return struct {
        const S = smallsort.Small(T, Ctx, lessThanFn);
        const lt = S.lt;

        pub fn sort(v: []T, ctx: Ctx) void {
            if (@sizeOf(T) == 0) return; // all equal, and thus sorted
            if (v.len < 2) return;
            if (v.len <= max_len_always_insertion) {
                S.insertionSortShiftLeft(v.ptr, v.len, 1, ctx);
                return;
            }
            ipnsort(v.ptr, v.len, ctx);
        }

        noinline fn ipnsort(v: [*]T, len: usize, ctx: Ctx) void {
            const run = findExistingRun(v, len, ctx);
            if (run.len == len) {
                if (run.descending) std.mem.reverse(T, v[0..len]);
                return;
            }
            const limit: u32 = 2 * @as(u32, std.math.log2_int(usize, len | 1));
            quicksort(v, len, null, limit, ctx);
        }

        /// `limit` = imbalanced partitions left before heapsort takes over.
        /// `ancestor_pivot` = the pivot of the partition this slice is the
        /// right side of (it sits just below `v[0]` and is never moved).
        fn quicksort(v_in: [*]T, len_in: usize, ancestor_in: ?*const T, limit_in: u32, ctx: Ctx) void {
            var v = v_in;
            var len = len_in;
            var ancestor = ancestor_in;
            var limit = limit_in;
            while (true) {
                if (len <= S.unstable_threshold) {
                    S.unstableSmallSort(v, len, ctx);
                    return;
                }
                if (limit == 0) {
                    heapsort(v, len, ctx);
                    return;
                }
                limit -= 1;
                const pivot_pos = choosePivot(v, len, ctx);
                // A pivot not greater than the ancestor is the minimum of the
                // slice: split off everything equal to it in one pass. This is
                // what keeps many duplicates linear.
                if (ancestor) |p| {
                    if (!lt(ctx, p, &v[pivot_pos])) {
                        const num_le = partition(.le, v, len, pivot_pos, ctx);
                        v += num_le + 1;
                        len -= num_le + 1;
                        ancestor = null;
                        continue;
                    }
                }
                const num_lt = partition(.lt, v, len, pivot_pos, ctx);
                std.debug.assert(num_lt < len);
                // No benefit measured upstream from recursing into the shorter
                // side: the depth is already bounded by `limit`.
                quicksort(v, num_lt, ancestor, limit, ctx);
                ancestor = &v[num_lt];
                v += num_lt + 1;
                len -= num_lt + 1;
            }
        }

        pub const Mode = enum { lt, le };

        /// Moves every element `x` with `x < pivot` (mode `.lt`) or `!(pivot <
        /// x)` (mode `.le`) to the front, puts the pivot right after them and
        /// returns their count. The pivot is `v[pivot_pos]`.
        pub fn partition(comptime mode: Mode, v: [*]T, len: usize, pivot_pos: usize, ctx: Ctx) usize {
            if (len == 0) return 0;
            S.swapElems(&v[0], &v[pivot_pos]);
            // A local copy: the partition loop below then knows the pivot
            // cannot alias the elements it moves.
            const pivot = v[0];
            const num = if (@sizeOf(T) <= max_branchless_partition_size)
                partitionLomutoCyclic(mode, v + 1, len - 1, &pivot, ctx)
            else
                partitionHoareCyclic(mode, v + 1, len - 1, &pivot, ctx);
            std.debug.assert(num < len);
            S.swapElems(&v[0], &v[num]);
            return num;
        }

        inline fn goesLeft(comptime mode: Mode, ctx: Ctx, x: *const T, pivot: *const T) bool {
            return switch (mode) {
                .lt => lt(ctx, x, pivot),
                .le => !lt(ctx, pivot, x),
            };
        }

        /// Branchless Lomuto partition paired with a cyclic permutation
        /// (Bergdoll & Peters): one hole travels along the scan instead of a
        /// swap per element.
        /// https://github.com/Voultapher/sort-research-rs/blob/main/writeup/lomcyc_partition/text.md
        fn partitionLomutoCyclic(comptime mode: Mode, v: [*]T, len: usize, noalias pivot: *const T, ctx: Ctx) usize {
            if (len == 0) return 0;
            var gap_value: T = v[0];
            const State = struct { right: [*]T, gap: [*]T, num_lt: usize };
            var st: State = .{ .right = v + 1, .gap = v, .num_lt = 0 };
            const body = struct {
                inline fn f(s: *State, base: [*]T, c: Ctx, p: *const T) void {
                    const right_is_lt = goesLeft(mode, c, &s.right[0], p);
                    const left = base + s.num_lt;
                    s.gap[0] = left[0]; // may be the same slot: a self-copy
                    left[0] = s.right[0];
                    s.gap = s.right;
                    s.num_lt += @intFromBool(right_is_lt);
                    s.right += 1;
                }
            }.f;
            const unroll = if (@sizeOf(T) <= 16) 2 else 1;
            const unroll_end = @intFromPtr(v + (len - (unroll - 1)));
            while (@intFromPtr(st.right) < unroll_end) {
                inline for (0..unroll) |_| body(&st, v, ctx, pivot);
            }
            // The tail, then one last step with the saved first element as
            // `right`: it lands in the final gap and closes the cycle.
            const end = v + len;
            while (true) {
                const done = st.right == end;
                if (done) st.right = @ptrCast(&gap_value);
                body(&st, v, ctx, pivot);
                if (done) break;
            }
            return st.num_lt;
        }

        /// Hoare partition for large elements, moving each out-of-place pair
        /// through one saved hole (two copies per pair instead of a swap).
        fn partitionHoareCyclic(comptime mode: Mode, v: [*]T, len: usize, noalias pivot: *const T, ctx: Ctx) usize {
            if (len == 0) return 0;
            var left: usize = 0;
            var right: usize = len;
            var gap_value: T = undefined;
            var gap_pos: ?usize = null;
            while (true) {
                while (left < right and goesLeft(mode, ctx, &v[left], pivot)) left += 1;
                while (true) {
                    right -= 1;
                    if (left >= right or goesLeft(mode, ctx, &v[right], pivot)) break;
                }
                if (left >= right) break;
                if (gap_pos) |g| {
                    v[g] = v[left];
                } else {
                    gap_value = v[left];
                }
                gap_pos = right;
                v[left] = v[right];
                left += 1;
            }
            if (gap_pos) |g| v[g] = gap_value;
            return left;
        }

        /// Position of a pseudo-median sample of `v[0..len]`, `len >= 8`.
        pub fn choosePivot(v: [*]const T, len: usize, ctx: Ctx) usize {
            std.debug.assert(len >= 8);
            const n8 = len / 8;
            const a: usize = 0;
            const b = n8 * 4;
            const c = n8 * 7;
            const idx = if (len < pseudo_median_rec_threshold)
                median3(v, a, b, c, ctx)
            else
                median3Rec(v, a, b, c, n8, ctx);
            std.debug.assert(idx < len);
            return idx;
        }

        /// Median of three ~n/8-element regions' own pseudo-medians, recursing
        /// while a region holds 8 or more elements (samples ~n^0.528).
        fn median3Rec(v: [*]const T, a_in: usize, b_in: usize, c_in: usize, n: usize, ctx: Ctx) usize {
            var a = a_in;
            var b = b_in;
            var c = c_in;
            if (n * 8 >= pseudo_median_rec_threshold) {
                const n8 = n / 8;
                a = median3Rec(v, a, a + n8 * 4, a + n8 * 7, n8, ctx);
                b = median3Rec(v, b, b + n8 * 4, b + n8 * 7, n8, ctx);
                c = median3Rec(v, c, c + n8 * 4, c + n8 * 7, n8, ctx);
            }
            return median3(v, a, b, c, ctx);
        }

        inline fn median3(v: [*]const T, a: usize, b: usize, c: usize, ctx: Ctx) usize {
            const x = lt(ctx, &v[a], &v[b]);
            const y = lt(ctx, &v[a], &v[c]);
            if (x == y) {
                // Both false: a is the max, take max(b, c). Both true: a is
                // the min, take min(b, c). XOR with x flips between the two.
                const z = lt(ctx, &v[b], &v[c]);
                return if (z != x) c else b;
            }
            return a;
        }

        /// Heapsort, the `O(n log n)` guarantee once `limit` runs out. The
        /// same loop builds the heap and then pops it.
        pub noinline fn heapsort(v: [*]T, len: usize, ctx: Ctx) void {
            var i = len + len / 2;
            while (i > 0) {
                i -= 1;
                const sift_idx = if (i >= len) i - len else blk: {
                    S.swapElems(&v[0], &v[i]);
                    break :blk 0;
                };
                siftDown(v, @min(i, len), sift_idx, ctx);
            }
        }

        inline fn siftDown(v: [*]T, len: usize, node_in: usize, ctx: Ctx) void {
            var node = node_in;
            while (true) {
                var child = 2 * node + 1;
                if (child >= len) break;
                if (child + 1 < len) child += @intFromBool(lt(ctx, &v[child], &v[child + 1]));
                if (!lt(ctx, &v[node], &v[child])) break;
                S.swapElems(&v[node], &v[child]);
                node = child;
            }
        }

        const Run = struct { len: usize, descending: bool };

        /// Length of the run from `v[0]` (`v[0..2]` already known to be in
        /// it): while `v[n] < v[n-1]` (descending) or not (ascending). Small
        /// elements go four at a time, the comparisons and-ed under one
        /// branch (SPEC "Algorithm" point 5); a block that leaves the run is
        /// rescanned one by one, repeating up to four comparisons.
        inline fn scanRun(comptime descending: bool, v: [*]const T, len: usize, ctx: Ctx) usize {
            var n: usize = 2;
            if (@sizeOf(T) <= 16) {
                // Four steps per branch: the comparisons of a block are
                // and-ed, a block that leaves the run is rescanned singly.
                while (n + 4 <= len) {
                    var ok = true;
                    inline for (0..4) |j| ok = ok and (lt(ctx, &v[n + j], &v[n + j - 1]) == descending);
                    if (!ok) break;
                    n += 4;
                }
                while (n < len and lt(ctx, &v[n], &v[n - 1]) == descending) n += 1;
            } else {
                while (n < len and lt(ctx, &v[n], &v[n - 1]) == descending) n += 1;
            }
            return n;
        }

        /// The sorted run at the start of `v`: non-descending, or strictly
        /// descending (so reversing it keeps the sort's contract).
        pub fn findExistingRun(v: [*]const T, len: usize, ctx: Ctx) Run {
            if (len < 2) return .{ .len = len, .descending = false };
            const descending = lt(ctx, &v[1], &v[0]);
            const n = if (descending) scanRun(true, v, len, ctx) else scanRun(false, v, len, ctx);
            return .{ .len = n, .descending = descending };
        }
    };
}
