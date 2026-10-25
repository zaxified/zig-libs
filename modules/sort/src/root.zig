// SPDX-License-Identifier: MIT

//! sort — fast in-place sorting of slices: Rust's ipnsort as the unstable
//! sort, a drop-in for `std.sort.pdq` / `std.mem.sortUnstable` with the same
//! `(T, items, context, lessThan)` shape.
//!
//! Why not std: `std.sort.pdq` partitions with branches the CPU cannot
//! predict on random input and `std.sort.block` pays for its in-place
//! stability; Rust's `sort_unstable` (ipnsort, Rust ≥ 1.81) beats both by
//! 1.3–1.9× on the same keys (measured 2026-10-25, netaddr's `sort_mixed`).
//! This module is that algorithm, ported.
//!
//! Contract shared by every entry point: the comparator is a strict weak
//! order (`lessThan(a, a)` false, transitive). A comparator that breaks it
//! gets back an unspecified PERMUTATION of the input — no element lost or
//! duplicated, no read or write outside the slice, in every build mode. The
//! sorts still finish in `O(n log n)` comparisons; `selectNth` may take
//! `O(n²)` (as Rust's does). See SPEC.md.

const std = @import("std");

pub const meta = .{
    .doc = "Fast in-place sorting: Rust's ipnsort as a drop-in for std.sort.pdq.",
    .platform_note = "any (pure Zig, no allocation)",
    .targets = .{ .linux64, .linux32, .windows, .wasm32 },
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "Rust core::slice::sort (ipnsort, 1.93.1)",
    .deps = .{},
};

const unstable_impl = @import("unstable.zig");
const stable_impl = @import("stable.zig");
const select_impl = @import("select.zig");

/// Sorts `items` in place, not preserving the order of equal elements.
///
/// Rust's `slice::sort_unstable` (ipnsort): `O(n log n)` worst case, `O(n)`
/// on an input that is already sorted or strictly descending, linear-ish on
/// many duplicates. No allocation. Stack: the small sorts keep up to 4 KiB of
/// elements, plus a few element copies per frame — mind it for a very large
/// `T` (sort pointers or indices to such elements instead).
///
/// Same signature as `std.sort.pdq`, so a call site switches by name only.
pub fn unstable(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    unstable_impl.Unstable(T, @TypeOf(context), lessThanFn).sort(items, context);
}

/// Sorts `items` in place, keeping equal elements in their input order.
///
/// Rust's `slice::sort` (driftsort): `O(n log n)` worst case, `O(n)` on an
/// input made of a few long sorted or strictly descending runs, fast on many
/// duplicates. Takes scratch from `gpa` like Rust does — none for 20
/// elements or fewer, none when the scratch fits in 4 KiB of stack, otherwise
/// `max(n - n/2, min(n, 8 MB / @sizeOf(T)))` elements, freed before return.
/// `stableBuffer` is the allocation-free twin.
pub fn stable(
    comptime T: type,
    gpa: std.mem.Allocator,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) error{OutOfMemory}!void {
    return stable_impl.Stable(T, @TypeOf(context), lessThanFn).sortAlloc(items, context, gpa);
}

/// `stable` with caller-owned scratch: `scratch.len` must be at least
/// `stableScratchLen(items.len)`, and `scratch` must not overlap `items`
/// (panics otherwise, at every length). Extra scratch, up to
/// `items.len`, lets more of the input go through the quicksort and is
/// faster on random input; less than that is merged instead.
pub fn stableBuffer(
    comptime T: type,
    items: []T,
    scratch: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    stable_impl.Stable(T, @TypeOf(context), lessThanFn).sortBuffer(items, scratch, context);
}

/// The least scratch, in elements, `stableBuffer` accepts for `len` items:
/// `max(len - len/2, 48)`.
pub fn stableScratchLen(len: usize) usize {
    return stable_impl.minScratchLen(len);
}

/// Reorders `items` so that `items[index]` is the element a sort would put
/// there, everything before it is not greater and everything after it is not
/// less (the order within each side is unspecified). Panics when
/// `index >= items.len`.
///
/// Rust's `select_nth_unstable` / C++ `nth_element`: introselect over the
/// unstable sort's partition, falling back to a median-of-ninthers
/// quickselect, so `O(n)` worst case for an honest comparator (`O(n²)` for
/// one that breaks the order). No allocation. The tool for medians and
/// percentiles: `selectNth(T, v, v.len / 2, …)` then read `v[v.len / 2]`.
pub fn selectNth(
    comptime T: type,
    items: []T,
    index: usize,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    select_impl.Select(T, @TypeOf(context), lessThanFn).select(items, index, context);
}

/// Ascending `lessThan` for any of these sorts: the builtin `<` for
/// integers, floats (a NaN is not an order: it makes the result an
/// unspecified permutation) and anything else `<` accepts; lexicographic
/// byte order (`bytesLess`) for `[]const u8` and `[]u8`.
pub fn asc(comptime T: type) fn (void, T, T) bool {
    return struct {
        fn f(_: void, a: T, b: T) bool {
            if (comptime isBytes(T)) return bytesLess(a, b);
            return a < b;
        }
    }.f;
}

/// Descending twin of `asc`.
pub fn desc(comptime T: type) fn (void, T, T) bool {
    return struct {
        fn f(_: void, a: T, b: T) bool {
            if (comptime isBytes(T)) return bytesLess(b, a);
            return a > b;
        }
    }.f;
}

fn isBytes(comptime T: type) bool {
    return T == []const u8 or T == []u8;
}

/// `std.mem.order(u8, a, b) == .lt`, comparing eight bytes at a time as
/// big-endian words. `std.mem.order` walks byte by byte, and inlined into a
/// sort's branch-free loops it costs 1.7× Rust's `memcmp`-based slice order
/// on short strings (measured 2026-10-25, 100 000 strings of 4–24 bytes);
/// this one sorts the same strings 0.93× Rust.
pub inline fn bytesLess(a: []const u8, b: []const u8) bool {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i + 8 <= n) : (i += 8) {
        const x = std.mem.readInt(u64, a[i..][0..8], .big);
        const y = std.mem.readInt(u64, b[i..][0..8], .big);
        if (x != y) return x < y;
    }
    if (n >= 8) {
        // The last eight bytes of the common length, overlapping bytes the
        // loop already found equal.
        const x = std.mem.readInt(u64, a[n - 8 ..][0..8], .big);
        const y = std.mem.readInt(u64, b[n - 8 ..][0..8], .big);
        if (x != y) return x < y;
    } else {
        while (i < n) : (i += 1) {
            if (a[i] != b[i]) return a[i] < b[i];
        }
    }
    return a.len < b.len;
}

test {
    _ = @import("smallsort.zig");
    _ = @import("unstable.zig");
    _ = @import("stable.zig");
    _ = @import("select.zig");
    _ = @import("test_sort.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("audit_test.zig");
}
