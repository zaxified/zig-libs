// SPDX-License-Identifier: MIT

//! Small-input sorts shared by the unstable and the stable sort: insertion
//! sort, the 9/13-element sorting networks, the stable 4/8-element sorts and
//! the bidirectional merge. Ported from Rust `core::slice::sort::shared::
//! smallsort` (1.93.1) — see `../NOTICE`.
//!
//! Every routine works on raw `[*]T` with indices the comparator cannot steer
//! out of range: whatever `lessThan` answers, reads and writes stay inside
//! the slice and its scratch. A comparator that is not a strict weak order
//! gets an unspecified permutation of its input back — never a lost or a
//! duplicated element (`bidirectionalMerge` reports the violation and the
//! callers restore a whole copy).

const std = @import("std");

/// Element size up to which the 32-element sorting-network small sort is used
/// (Rust `has_efficient_in_place_swap`: a swap is a register move).
pub const network_max_size = 8;
/// Upper bound on a stack scratch array (Rust `MAX_STACK_ARRAY_SIZE`).
pub const max_stack_array_size = 4096;
pub const fallback_threshold = 16;
pub const general_threshold = 32;
pub const general_scratch_len = general_threshold + 16;
pub const network_threshold = 32;
pub const network_scratch_len = network_threshold;

pub fn Small(comptime T: type, comptime Ctx: type, comptime lessThanFn: fn (Ctx, T, T) bool) type {
    return struct {
        pub inline fn lt(ctx: Ctx, a: *const T, b: *const T) bool {
            return lessThanFn(ctx, a.*, b.*);
        }

        /// Which small sort the unstable quicksort ends in, chosen per type.
        pub const Kind = enum { network, general, fallback };
        pub const unstable_kind: Kind = if (@sizeOf(T) <= network_max_size and
            @sizeOf(T) * network_scratch_len <= max_stack_array_size)
            .network
        else if (@sizeOf(T) * general_scratch_len <= max_stack_array_size)
            .general
        else
            .fallback;
        pub const unstable_threshold: usize = switch (unstable_kind) {
            .network => network_threshold,
            .general => general_threshold,
            .fallback => fallback_threshold,
        };

        pub fn unstableSmallSort(v: [*]T, len: usize, ctx: Ctx) void {
            switch (unstable_kind) {
                .network => smallSortNetwork(v, len, ctx),
                .general => smallSortGeneral(v, len, ctx),
                .fallback => if (len >= 2) insertionSortShiftLeft(v, len, 1, ctx),
            }
        }

        /// Sorts `v[0..len]` assuming `v[0..offset]` is sorted. `1 <= offset <= len`.
        pub fn insertionSortShiftLeft(v: [*]T, len: usize, offset: usize, ctx: Ctx) void {
            std.debug.assert(offset != 0 and offset <= len);
            var tail = offset;
            while (tail != len) : (tail += 1) insertTail(v, tail, ctx);
        }

        /// Sorts `v[0..tail+1]` assuming `v[0..tail]` is sorted. `tail >= 1`.
        pub inline fn insertTail(v: [*]T, tail: usize, ctx: Ctx) void {
            var sift = tail - 1;
            if (!lt(ctx, &v[tail], &v[sift])) return;
            const tmp = v[tail];
            var gap = tail;
            while (true) {
                v[gap] = v[sift];
                gap = sift;
                if (sift == 0) break;
                sift -= 1;
                if (!lt(ctx, &tmp, &v[sift])) break;
            }
            v[gap] = tmp;
        }

        /// Swaps two elements, the same one included. Not `std.mem.swap`: that
        /// one declares both pointers `noalias`, and a pivot or an extremum
        /// already in place swaps with itself.
        pub inline fn swapElems(a: *T, b: *T) void {
            const t = a.*;
            a.* = b.*;
            b.* = t;
        }

        /// Swaps `v[a]` and `v[b]` when `v[b] < v[a]`, without a branch.
        inline fn swapIfLess(v: [*]T, a: usize, b: usize, ctx: Ctx) void {
            const pa = &v[a];
            const pb = &v[b];
            const should = lt(ctx, pb, pa);
            const a_src = select(should, pb, pa);
            const b_src = select(should, pa, pb);
            const tmp = b_src.*;
            pa.* = a_src.*;
            pb.* = tmp;
        }

        /// `if (c) a else b` on pointers, steered toward a conditional move:
        /// the outcome of a sort comparison is a coin flip on random input.
        inline fn select(c: bool, a: anytype, b: @TypeOf(a)) @TypeOf(a) {
            const mask = -%@as(usize, @intFromBool(c));
            return @ptrFromInt((@intFromPtr(a) & mask) | (@intFromPtr(b) & ~mask));
        }

        // Optimal sorting networks, https://bertdobbelaere.github.io/sorting_networks.html
        // (same pairs as Rust's sort9_optimal / sort13_optimal).
        const net9 = [_][2]u8{
            .{ 0, 3 }, .{ 1, 7 }, .{ 2, 5 }, .{ 4, 8 }, .{ 0, 7 }, .{ 2, 4 }, .{ 3, 8 },
            .{ 5, 6 }, .{ 0, 2 }, .{ 1, 3 }, .{ 4, 5 }, .{ 7, 8 }, .{ 1, 4 }, .{ 3, 6 },
            .{ 5, 7 }, .{ 0, 1 }, .{ 2, 4 }, .{ 3, 5 }, .{ 6, 8 }, .{ 2, 3 }, .{ 4, 5 },
            .{ 6, 7 }, .{ 1, 2 }, .{ 3, 4 }, .{ 5, 6 },
        };
        const net13 = [_][2]u8{
            .{ 0, 12 },  .{ 1, 10 }, .{ 2, 9 },   .{ 3, 7 },  .{ 5, 11 },  .{ 6, 8 },
            .{ 1, 6 },   .{ 2, 3 },  .{ 4, 11 },  .{ 7, 9 },  .{ 8, 10 },  .{ 0, 4 },
            .{ 1, 2 },   .{ 3, 6 },  .{ 7, 8 },   .{ 9, 10 }, .{ 11, 12 }, .{ 4, 6 },
            .{ 5, 9 },   .{ 8, 11 }, .{ 10, 12 }, .{ 0, 5 },  .{ 3, 8 },   .{ 4, 7 },
            .{ 6, 11 },  .{ 9, 10 }, .{ 0, 1 },   .{ 2, 5 },  .{ 6, 9 },   .{ 7, 8 },
            .{ 10, 11 }, .{ 1, 3 },  .{ 2, 4 },   .{ 5, 6 },  .{ 9, 10 },  .{ 1, 2 },
            .{ 3, 4 },   .{ 5, 7 },  .{ 6, 8 },   .{ 2, 3 },  .{ 4, 5 },   .{ 6, 7 },
            .{ 8, 9 },   .{ 3, 4 },  .{ 5, 6 },
        };

        fn sortNetwork(v: [*]T, comptime pairs: []const [2]u8, ctx: Ctx) void {
            inline for (pairs) |p| swapIfLess(v, p[0], p[1], ctx);
        }

        /// Up to 32 elements of a register-sized type: a sorting network on
        /// each half (13 or 9 elements, insertion for the rest), then one
        /// bidirectional merge through a stack buffer.
        pub fn smallSortNetwork(v: [*]T, len: usize, ctx: Ctx) void {
            if (len < 2) return;
            std.debug.assert(len <= network_scratch_len);
            const half = len / 2;
            const no_merge = len < 18;
            var start: usize = 0;
            var region_len = if (no_merge) len else half;
            while (true) {
                const region = v + start;
                const presorted: usize = if (region_len >= 13) blk: {
                    sortNetwork(region, &net13, ctx);
                    break :blk 13;
                } else if (region_len >= 9) blk: {
                    sortNetwork(region, &net9, ctx);
                    break :blk 9;
                } else 1;
                insertionSortShiftLeft(region, region_len, presorted, ctx);
                if (no_merge) return;
                if (start != 0) break;
                start = half;
                region_len = len - half;
            }
            var scratch: [network_scratch_len]T = undefined;
            // A comparator that is not a strict weak order leaves the scratch
            // inconsistent; `v` still holds the two sorted halves, keep them.
            if (bidirectionalMerge(v, len, &scratch, ctx)) @memcpy(v[0..len], scratch[0..len]);
        }

        pub fn smallSortGeneral(v: [*]T, len: usize, ctx: Ctx) void {
            var scratch: [general_scratch_len]T = undefined;
            smallSortGeneralWithScratch(v, len, &scratch, ctx);
        }

        /// Up to 32 elements: both halves sorted into `scratch` (8- or
        /// 4-element stable sorts, then insertion), then merged back into
        /// `v`. Stable. `scratch` holds at least `len + 16` elements.
        pub fn smallSortGeneralWithScratch(noalias v: [*]T, len: usize, noalias scratch: [*]T, ctx: Ctx) void {
            if (len < 2) return;
            const half = len / 2;
            const presorted: usize = if (@sizeOf(T) <= 16 and len >= 16) blk: {
                sort8Stable(v, scratch, scratch + len, ctx);
                sort8Stable(v + half, scratch + half, scratch + len + 8, ctx);
                break :blk 8;
            } else if (len >= 8) blk: {
                sort4Stable(v, scratch, ctx);
                sort4Stable(v + half, scratch + half, ctx);
                break :blk 4;
            } else blk: {
                scratch[0] = v[0];
                scratch[half] = v[half];
                break :blk 1;
            };
            inline for (.{ 0, 1 }) |side| {
                const off = if (side == 0) 0 else half;
                const want = if (side == 0) half else len - half;
                const src = v + off;
                const dst = scratch + off;
                var i = presorted;
                while (i < want) : (i += 1) {
                    dst[i] = src[i];
                    insertTail(dst, i, ctx);
                }
            }
            // On an order violation the merge output is inconsistent; the
            // scratch is still a whole permutation of the input.
            if (!bidirectionalMerge(scratch, len, v, ctx)) @memcpy(v[0..len], scratch[0..len]);
        }

        /// Stable sort of `src[0..4]` into `dst[0..4]`; 5 comparisons, each
        /// element copied once.
        pub inline fn sort4Stable(noalias src: [*]const T, noalias dst: [*]T, ctx: Ctx) void {
            const c1 = lt(ctx, &src[1], &src[0]);
            const c2 = lt(ctx, &src[3], &src[2]);
            const a = src + @intFromBool(c1);
            const b = src + @intFromBool(!c1);
            const c = src + 2 + @intFromBool(c2);
            const d = src + 2 + @intFromBool(!c2);
            const c3 = lt(ctx, &c[0], &a[0]);
            const c4 = lt(ctx, &d[0], &b[0]);
            const min = select(c3, c, a);
            const max = select(c4, b, d);
            const unknown_left = select(c3, a, select(c4, c, b));
            const unknown_right = select(c4, d, select(c3, b, c));
            const c5 = lt(ctx, &unknown_right[0], &unknown_left[0]);
            const lo = select(c5, unknown_right, unknown_left);
            const hi = select(c5, unknown_left, unknown_right);
            dst[0] = min[0];
            dst[1] = lo[0];
            dst[2] = hi[0];
            dst[3] = max[0];
        }

        /// Stable sort of `src[0..8]` into `dst[0..8]` through `tmp[0..8]`.
        pub fn sort8Stable(noalias src: [*]const T, noalias dst: [*]T, noalias tmp: [*]T, ctx: Ctx) void {
            sort4Stable(src, tmp, ctx);
            sort4Stable(src + 4, tmp + 4, ctx);
            // A broken order can make the merge fail; `tmp` is still whole.
            if (!bidirectionalMerge(tmp, 8, dst, ctx)) @memcpy(dst[0..8], tmp[0..8]);
        }

        /// Merges `src[0..len/2]` and `src[len/2..len]` (each sorted) into
        /// `dst[0..len]` from both ends at once (quadsort's parity merge, two
        /// writes per step). `len >= 2`; `src` and `dst` do not overlap.
        /// Returns false when the comparator is not a strict weak order: the
        /// pointers then do not meet, and `dst` is not a permutation of `src`.
        pub fn bidirectionalMerge(noalias src: [*]const T, len: usize, noalias dst: [*]T, ctx: Ctx) bool {
            const half = len / 2;
            std.debug.assert(half != 0);
            var left: usize = 0;
            var right: usize = half;
            var out: usize = 0;
            // The `_rev` cursors run one below their next element; `+%` keeps
            // a cursor that underflows on a broken order from trapping, and
            // the check at the end catches it.
            var left_rev: usize = half - 1;
            var right_rev: usize = len - 1;
            var out_rev: usize = len - 1;
            for (0..half) |_| {
                // merge up
                const up_l = !lt(ctx, &src[right], &src[left]);
                dst[out] = src[if (up_l) left else right];
                left += @intFromBool(up_l);
                right += @intFromBool(!up_l);
                out += 1;
                // merge down
                const dn_l = !lt(ctx, &src[right_rev], &src[left_rev]);
                dst[out_rev] = src[if (dn_l) right_rev else left_rev];
                right_rev -%= @intFromBool(dn_l);
                left_rev -%= @intFromBool(!dn_l);
                out_rev -%= 1;
            }
            const left_end = left_rev +% 1;
            const right_end = right_rev +% 1;
            if (len % 2 != 0) {
                const left_nonempty = left < left_end;
                dst[out] = src[if (left_nonempty) left else right];
                left += @intFromBool(left_nonempty);
                right += @intFromBool(!left_nonempty);
            }
            return left == left_end and right == right_end;
        }
    };
}
