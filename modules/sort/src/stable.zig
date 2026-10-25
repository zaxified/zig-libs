// SPDX-License-Identifier: MIT

//! driftsort — the stable sort of Rust's `slice::sort` (Orson Peters and
//! Lukas Bergdoll), ported from `core::slice::sort::stable` (Rust 1.93.1, see
//! `../NOTICE`). Design:
//! https://github.com/Voultapher/sort-research-rs/blob/main/writeup/driftsort_introduction/text.md
//!
//! Shape: insertion sort up to 20 elements; otherwise one left-to-right scan
//! that cuts the input into runs — an existing sorted (or strictly
//! descending, reversed in place) run of at least ~√n elements is kept, any
//! other stretch becomes a lazy "unsorted" run — and merges them in the order
//! powersort's heuristic picks (Munro & Wild). Two adjacent unsorted runs that
//! still fit in the scratch merge logically (they just concatenate); a run is
//! physically sorted only when it must be merged, by a stable quicksort that
//! partitions through the scratch buffer without branches. The quicksort's
//! recursion budget falls back to this same loop in eager mode (small sorts
//! and merges only), which bounds the worst case at `O(n log n)`.

const std = @import("std");
const smallsort = @import("smallsort.zig");

pub const max_len_always_insertion = 20;
/// Scratch of up to this many bytes is taken whole (`min(n, 8 MB)`); above it,
/// the scratch shrinks toward `n - n/2` elements (Rust `MAX_FULL_ALLOC_BYTES`).
pub const max_full_alloc_bytes = 8_000_000;
/// Scratch kept on the stack instead of allocated (Rust: 4 KiB).
pub const stack_scratch_bytes = 4096;
/// Pre-sorted runs shorter than `min(64, n/2)` (n ≤ 4096) or ~√n are ignored.
const min_sqrt_run_len = 64;
const threshold = smallsort.general_threshold;

/// The least scratch (in elements) a stable sort of `len` elements needs.
pub fn minScratchLen(len: usize) usize {
    return @max(len - len / 2, smallsort.general_scratch_len);
}

/// The scratch the allocating entry point takes for `len` elements of `T`.
pub fn preferredScratchLen(comptime T: type, len: usize) usize {
    const max_full_alloc = max_full_alloc_bytes / @max(@sizeOf(T), 1);
    return @max(len - len / 2, @min(len, max_full_alloc), smallsort.general_scratch_len);
}

pub fn Stable(comptime T: type, comptime Ctx: type, comptime lessThanFn: fn (Ctx, T, T) bool) type {
    return struct {
        const S = smallsort.Small(T, Ctx, lessThanFn);
        const lt = S.lt;

        /// Takes the scratch from the stack when it fits in
        /// `stack_scratch_bytes`, else from `gpa` (before anything moves).
        pub fn sortAlloc(v: []T, ctx: Ctx, gpa: std.mem.Allocator) error{OutOfMemory}!void {
            if (@sizeOf(T) == 0 or v.len < 2) return;
            if (v.len <= max_len_always_insertion) {
                S.insertionSortShiftLeft(v.ptr, v.len, 1, ctx);
                return;
            }
            const want = preferredScratchLen(T, v.len);
            var stack_buf: [stack_scratch_bytes]u8 align(@alignOf(T)) = undefined;
            const stack_cap = stack_scratch_bytes / @sizeOf(T);
            if (stack_cap >= want) {
                driftsortMain(v.ptr, v.len, @ptrCast(&stack_buf), stack_cap, ctx);
                return;
            }
            const heap = try gpa.alloc(T, want);
            defer gpa.free(heap);
            driftsortMain(v.ptr, v.len, heap.ptr, heap.len, ctx);
        }

        /// `scratch.len >= minScratchLen(v.len)`, no overlap; panics
        /// otherwise, at every length (even where the scratch goes unused).
        pub fn sortBuffer(v: []T, scratch: []T, ctx: Ctx) void {
            if (@sizeOf(T) == 0) return;
            if (scratch.len < minScratchLen(v.len)) @panic("sort.stableBuffer: scratch shorter than sort.stableScratchLen(items.len)");
            // The partition and the merges assume the two never overlap.
            const v_lo = @intFromPtr(v.ptr);
            const s_lo = @intFromPtr(scratch.ptr);
            if (s_lo < v_lo + v.len * @sizeOf(T) and v_lo < s_lo + scratch.len * @sizeOf(T)) @panic("sort.stableBuffer: scratch overlaps items");
            if (v.len < 2) return;
            if (v.len <= max_len_always_insertion) {
                S.insertionSortShiftLeft(v.ptr, v.len, 1, ctx);
                return;
            }
            driftsortMain(v.ptr, v.len, scratch.ptr, scratch.len, ctx);
        }

        noinline fn driftsortMain(v: [*]T, len: usize, scratch: [*]T, scratch_len: usize, ctx: Ctx) void {
            // Small inputs: two small sorts and a merge beat a quicksort.
            const eager = len <= threshold * 2;
            drift(v, len, scratch, scratch_len, eager, ctx);
        }

        /// A run: its length and whether it is physically sorted yet.
        const Run = packed struct(usize) {
            sorted: bool,
            len: @Int(.unsigned, @bitSizeOf(usize) - 1),

            fn of(len: usize, sorted: bool) Run {
                return .{ .sorted = sorted, .len = @intCast(len) };
            }
        };

        /// The main loop. `eager`: never leave a run unsorted (small sorts
        /// and merges only) — the `O(n log n)` fallback of the quicksort.
        fn drift(v: [*]T, len: usize, scratch: [*]T, scratch_len: usize, eager: bool, ctx: Ctx) void {
            if (len < 2) return;
            const scale = mergeTreeScaleFactor(len);
            // A high bar for keeping a pre-sorted run: one such run forces
            // several merges and shrinks what the quicksort may take.
            const min_good_run_len = if (len <= min_sqrt_run_len * min_sqrt_run_len)
                @min(len - len / 2, min_sqrt_run_len)
            else
                sqrtApprox(len);

            // The powersort stack: runs[i] and the desired depth of the merge
            // node between runs[i] and the run after it. Depths are < 64 and
            // strictly increase up the stack, so 66 slots always suffice.
            var runs: [66]Run = undefined;
            var depths: [66]u8 = undefined;
            var stack_len: usize = 0;
            var scan: usize = 0;
            var prev = Run.of(0, true); // dummy
            while (true) {
                var next: Run = undefined;
                var depth: u8 = undefined;
                if (scan < len) {
                    next = createRun(v + scan, len - scan, scratch, scratch_len, min_good_run_len, eager, ctx);
                    depth = mergeTreeDepth(scan - prev.len, scan, scan + next.len, scale);
                } else {
                    next = Run.of(0, true);
                    depth = 0;
                }
                while (stack_len > 1 and depths[stack_len - 1] >= depth) {
                    const left = runs[stack_len - 1];
                    const merged_len = left.len + prev.len;
                    prev = logicalMerge(v + (scan - merged_len), merged_len, scratch, scratch_len, left, prev, ctx);
                    stack_len -= 1;
                }
                runs[stack_len] = prev;
                depths[stack_len] = depth;
                stack_len += 1;
                if (scan >= len) break;
                scan += next.len;
                prev = next;
            }
            if (!prev.sorted) stableQuicksort(v, len, scratch, scratch_len, ctx);
        }

        // Powersort merge-tree depth (Munro & Wild, "Nearly-Optimal
        // Mergesorts"): [0, n) rescaled to [0, 2^62), the depth of the node
        // between [a, b) and [b, c) is the leading zero count of the XOR of
        // their scaled midpoints (the /2 dropped: only relative depth counts).
        fn mergeTreeScaleFactor(n: usize) u64 {
            return std.math.divCeil(u64, @as(u64, 1) << 62, n) catch unreachable;
        }

        fn mergeTreeDepth(left: usize, mid: usize, right: usize, scale: u64) u8 {
            const x = @as(u64, left) + mid;
            const y = @as(u64, mid) + right;
            return @clz((scale *% x) ^ (scale *% y));
        }

        /// `2^ceil(log2(n)/2)` refined by one Newton step.
        fn sqrtApprox(n: usize) usize {
            const ilog = std.math.log2_int(usize, n | 1);
            const shift: std.math.Log2Int(usize) = @intCast((ilog + 1) / 2);
            return ((@as(usize, 1) << shift) + (n >> shift)) / 2;
        }

        /// Lazy logical runs, as in glidesort: two unsorted runs that still
        /// fit in the scratch stay unsorted and just grow.
        inline fn logicalMerge(v: [*]T, len: usize, scratch: [*]T, scratch_len: usize, left: Run, right: Run, ctx: Ctx) Run {
            if (len > scratch_len or left.sorted or right.sorted) {
                if (!left.sorted) stableQuicksort(v, left.len, scratch, scratch_len, ctx);
                if (!right.sorted) stableQuicksort(v + left.len, right.len, scratch, scratch_len, ctx);
                merge(v, len, scratch, scratch_len, left.len, ctx);
                return Run.of(len, true);
            }
            return Run.of(len, false);
        }

        /// The run at the start of `v`: an existing one of `min_good_run_len`
        /// or more (reversed if strictly descending), else a small-sorted run
        /// (eager) or an unsorted stretch of `min_good_run_len`.
        fn createRun(v: [*]T, len: usize, scratch: [*]T, scratch_len: usize, min_good_run_len: usize, eager: bool, ctx: Ctx) Run {
            if (len >= min_good_run_len) {
                const run = findExistingRun(v, len, ctx);
                if (run.len >= min_good_run_len) {
                    if (run.descending) std.mem.reverse(T, v[0..run.len]);
                    return Run.of(run.len, true);
                }
            }
            if (eager) {
                const n = @min(threshold, len);
                quicksort(v, n, scratch, scratch_len, 0, null, ctx); // goes straight to the small sort
                return Run.of(n, true);
            }
            return Run.of(@min(min_good_run_len, len), false);
        }

        fn stableQuicksort(v: [*]T, len: usize, scratch: [*]T, scratch_len: usize, ctx: Ctx) void {
            const limit: u32 = 2 * @as(u32, std.math.log2_int(usize, len | 1));
            quicksort(v, len, scratch, scratch_len, limit, null, ctx);
        }

        /// Stable quicksort through the scratch. `left_ancestor`: a copy of
        /// the pivot whose right side `v` is.
        noinline fn quicksort(v_in: [*]T, len_in: usize, scratch: [*]T, scratch_len: usize, limit_in: u32, left_ancestor_in: ?*const T, ctx: Ctx) void {
            const v = v_in;
            var len = len_in;
            var limit = limit_in;
            var left_ancestor = left_ancestor_in;
            var base: usize = 0; // `v + base` is the slice left to sort
            while (true) {
                const s = v + base;
                if (len <= threshold) {
                    S.smallSortGeneralWithScratch(s, len, scratch, ctx);
                    return;
                }
                if (limit == 0) {
                    drift(s, len, scratch, scratch_len, true, ctx);
                    return;
                }
                limit -= 1;
                const pivot_pos = choosePivot(s, len, ctx);
                const pivot_copy = s[pivot_pos];
                // Pivot equal to the left ancestor: split off everything equal
                // to it and do not recurse there (`O(n log k)` for k distinct).
                var equal = false;
                if (left_ancestor) |la| equal = !lt(ctx, la, &s[pivot_pos]);
                var left_len: usize = 0;
                if (!equal) {
                    left_len = stablePartition(.lt, s, len, scratch, scratch_len, pivot_pos, false, ctx);
                    equal = left_len == 0;
                }
                if (equal) {
                    const mid_eq = stablePartition(.le, s, len, scratch, scratch_len, pivot_pos, true, ctx);
                    base += mid_eq;
                    len -= mid_eq;
                    left_ancestor = null;
                    continue;
                }
                // Right side by recursion, left side by the next iteration.
                quicksort(s + left_len, len - left_len, scratch, scratch_len, limit, &pivot_copy, ctx);
                len = left_len;
            }
        }

        const Mode = enum { lt, le };

        inline fn goesLeft(comptime mode: Mode, ctx: Ctx, x: *const T, pivot: *const T) bool {
            return switch (mode) {
                .lt => lt(ctx, x, pivot),
                .le => !lt(ctx, pivot, x),
            };
        }

        /// Stable partition by `v[pivot_pos]`: elements going left are written
        /// from the start of the scratch, the rest from its end backwards, both
        /// branch-free; then copied back (the right side reversed again). The
        /// pivot is never compared with itself. Returns the left count.
        fn stablePartition(comptime mode: Mode, noalias v: [*]T, len: usize, noalias scratch: [*]T, scratch_len: usize, pivot_pos: usize, pivot_goes_left: bool, ctx: Ctx) usize {
            if (scratch_len < len or pivot_pos >= len) @panic("sort: stable partition scratch"); // unreachable: callers size the scratch
            const pivot = &v[pivot_pos];
            var st: PartitionState = .{ .scan = v, .num_left = 0, .rev = scratch + len, .base = scratch };
            const v_end = v + len;
            var loop_end = v + pivot_pos;
            while (true) {
                if (@sizeOf(T) <= 16) {
                    const unroll_end = @intFromPtr(v + (pivot_pos -| 3));
                    const end = if (loop_end == v_end) @intFromPtr(v + (len -| 3)) else unroll_end;
                    while (@intFromPtr(st.scan) < end) {
                        inline for (0..4) |_| st.one(goesLeft(mode, ctx, &st.scan[0], pivot));
                    }
                }
                while (st.scan != loop_end) st.one(goesLeft(mode, ctx, &st.scan[0], pivot));
                if (loop_end == v_end) break;
                st.one(pivot_goes_left);
                loop_end = v_end;
            }
            const nl = st.num_left;
            // A loop, not `@memcpy`: without libc that is compiler_rt's
            // `memcpy`, a call that cost 13 % of a stable sort of 16
            // distinct keys (2026-10-25); the loop vectorizes in place.
            if (@sizeOf(T) <= 16) {
                for (v[0..nl], scratch[0..nl]) |*d, x| d.* = x;
            } else @memcpy(v[0..nl], scratch[0..nl]);
            // The right side went in back to front: reverse it on the way back.
            // Small elements eight at a time through a fixed-size block (a
            // 32-byte record measured slower this way), which LLVM turns
            // into vector loads and lane shuffles (Rust's loop vectorizes on
            // its own; ours stayed scalar, written either way, 2026-10-25).
            var src = scratch + len;
            var dst = v + nl;
            const stop = scratch + nl;
            if (@sizeOf(T) <= 16) while (@intFromPtr(src) - @intFromPtr(stop) >= 8 * @sizeOf(T)) {
                src -= 8;
                const blk: [8]T = src[0..8].*;
                inline for (0..8) |j| dst[j] = blk[7 - j];
                dst += 8;
            };
            while (src != stop) {
                src -= 1;
                dst[0] = src[0];
                dst += 1;
            }
            return nl;
        }

        /// Rust's `PartitionState`: pointers, not indices — the loop body is a
        /// pointer select, a store and two increments.
        const PartitionState = struct {
            scan: [*]const T,
            num_left: usize,
            /// Starts one past the scratch end and moves down one slot per
            /// element; a right-going element lands at `rev + num_left`.
            rev: [*]T,
            base: [*]T,

            /// Called exactly `len` times: scratch then holds each element
            /// once, `num_left` from the front and the rest from the back
            /// (after `i` calls, `rev + num_left` = `base + len - 1 - right
            /// count`, always in bounds).
            inline fn one(st: *PartitionState, towards_left: bool) void {
                st.rev -= 1;
                const dst_base = if (towards_left) st.base else st.rev;
                dst_base[st.num_left] = st.scan[0];
                st.num_left += @intFromBool(towards_left);
                st.scan += 1;
            }
        };

        /// Merges the sorted runs `v[0..mid]` and `v[mid..len]` through the
        /// scratch, which holds a copy of the shorter one.
        fn merge(noalias v: [*]T, len: usize, noalias scratch: [*]T, scratch_len: usize, mid: usize, ctx: Ctx) void {
            if (mid == 0 or mid >= len or scratch_len < @min(mid, len - mid)) return;
            const left_len = mid;
            const right_len = len - mid;
            if (left_len <= right_len) {
                @memcpy(scratch[0..left_len], v[0..left_len]);
                // Forward: the saved left run against v[mid..].
                var left: usize = 0;
                var right = mid;
                var out: usize = 0;
                while (left != left_len and right != len) {
                    const take_left = !lt(ctx, &v[right], &scratch[left]);
                    v[out] = if (take_left) scratch[left] else v[right];
                    left += @intFromBool(take_left);
                    right += @intFromBool(!take_left);
                    out += 1;
                }
                // Whatever is left of the saved run fills the gap.
                @memcpy(v[out..][0 .. left_len - left], scratch[left..left_len]);
            } else {
                @memcpy(scratch[0..right_len], v[mid..len]);
                // Backward: v[0..mid] against the saved right run.
                var l_end = mid; // one past the next left element
                var r_end = right_len; // one past the next saved element
                var out = len;
                while (true) {
                    const l = l_end - 1;
                    const r = r_end - 1;
                    out -= 1;
                    const take_left = lt(ctx, &scratch[r], &v[l]);
                    v[out] = if (take_left) v[l] else scratch[r];
                    l_end = l + @intFromBool(!take_left);
                    r_end = r + @intFromBool(take_left);
                    if (l_end == 0 or r_end == 0) break;
                }
                // The saved run's remainder goes right after the left run's.
                @memcpy(v[l_end..][0..r_end], scratch[0..r_end]);
            }
        }

        // Shared with the unstable sort.
        fn choosePivot(v: [*]const T, len: usize, ctx: Ctx) usize {
            return @import("unstable.zig").Unstable(T, Ctx, lessThanFn).choosePivot(v, len, ctx);
        }

        const RunInfo = struct { len: usize, descending: bool };

        fn findExistingRun(v: [*]const T, len: usize, ctx: Ctx) RunInfo {
            const r = @import("unstable.zig").Unstable(T, Ctx, lessThanFn).findExistingRun(v, len, ctx);
            return .{ .len = r.len, .descending = r.descending };
        }
    };
}
