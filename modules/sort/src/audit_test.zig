// SPDX-License-Identifier: MIT

//! Tests added by the 2026-10-25 mutation audit: each pins a behavior the
//! model tests in `test_sort.zig` left unchecked (a mutant survived there).
//! Values are compared against `std.sort.block` / `std.mem.order` models or
//! against the documented formulas.

const std = @import("std");
const builtin = @import("builtin");
const sort = @import("root.zig");
const stable_impl = @import("stable.zig");
const unstable_impl = @import("unstable.zig");
const linux = std.os.linux;

const testing = std.testing;

fn lessU32(_: void, a: u32, b: u32) bool {
    return a < b;
}

test "asc and desc are strict: equal operands are not less" {
    try testing.expect(!sort.asc(i32)({}, 5, 5));
    try testing.expect(!sort.desc(i32)({}, 5, 5));
    try testing.expect(sort.asc(i32)({}, 4, 5));
    try testing.expect(!sort.asc(i32)({}, 5, 4));
    try testing.expect(sort.desc(i32)({}, 5, 4));
    try testing.expect(!sort.desc(i32)({}, 4, 5));
    try testing.expect(!sort.asc(f64)({}, 1.5, 1.5));
    try testing.expect(!sort.desc(f64)({}, 1.5, 1.5));
    const a: []const u8 = "abc";
    const b: []const u8 = "abc";
    try testing.expect(!sort.asc([]const u8)({}, a, b));
    try testing.expect(!sort.desc([]const u8)({}, a, b));
    try testing.expect(sort.asc([]const u8)({}, "ab", "abc"));
    try testing.expect(sort.desc([]const u8)({}, "abc", "ab"));
}

test "findExistingRun: tiny inputs and an equal prefix" {
    const U = unstable_impl.Unstable(u32, void, lessU32);
    const cases = [_]struct { v: []const u32, len: usize, desc: bool }{
        .{ .v = &.{}, .len = 0, .desc = false },
        .{ .v = &.{4}, .len = 1, .desc = false },
        .{ .v = &.{ 2, 1 }, .len = 2, .desc = true },
        .{ .v = &.{ 1, 2 }, .len = 2, .desc = false },
        .{ .v = &.{ 3, 3 }, .len = 2, .desc = false },
        .{ .v = &.{ 2, 2, 1 }, .len = 2, .desc = false },
        .{ .v = &.{ 2, 2, 3 }, .len = 3, .desc = false },
        .{ .v = &.{ 3, 2, 2 }, .len = 2, .desc = true },
        .{ .v = &.{ 5, 4, 3, 2, 1 }, .len = 5, .desc = true },
        .{ .v = &.{ 1, 2, 3, 3, 4, 0 }, .len = 5, .desc = false },
    };
    for (cases) |c| {
        const r = U.findExistingRun(c.v.ptr, c.v.len, {});
        try testing.expectEqual(c.len, r.len);
        try testing.expectEqual(c.desc, r.descending);
    }
}

const Tag = struct {
    key: u32,
    tag: u32,
    fn less(_: void, a: Tag, b: Tag) bool {
        return a.key < b.key;
    }
};

test "stable: equal keys before a long strictly descending run keep their order" {
    // A non-strict "descending" detection would reverse the equal pair.
    const gpa = testing.allocator;
    for ([_]usize{ 40, 100, 300, 5000 }) |n| {
        const v = try gpa.alloc(Tag, n);
        defer gpa.free(v);
        v[0] = .{ .key = 10_000, .tag = 0 };
        v[1] = .{ .key = 10_000, .tag = 1 };
        for (v[2..], 2..) |*x, i| x.* = .{ .key = @intCast(10_000 - i), .tag = @intCast(i) };
        const m = try gpa.dupe(Tag, v);
        defer gpa.free(m);
        try sort.stable(Tag, gpa, v, {}, Tag.less);
        std.sort.block(Tag, m, {}, Tag.less);
        try testing.expectEqualSlices(Tag, m, v);
    }
}

test "scratch length formulas" {
    try testing.expectEqual(@as(usize, 48), sort.stableScratchLen(0));
    try testing.expectEqual(@as(usize, 48), sort.stableScratchLen(20));
    try testing.expectEqual(@as(usize, 48), sort.stableScratchLen(96));
    try testing.expectEqual(@as(usize, 51), sort.stableScratchLen(101));
    try testing.expectEqual(@as(usize, 5000), sort.stableScratchLen(10_000));
    const P = stable_impl.preferredScratchLen;
    // Small elements: the whole input (min(n, 8 MB / size)), at least 48.
    try testing.expectEqual(@as(usize, 48), P(u8, 3));
    try testing.expectEqual(@as(usize, 100), P(u8, 100));
    try testing.expectEqual(@as(usize, 1001), P(u8, 1001));
    // 1000-byte elements: 8 MB / 1000 = 8000 caps the "whole input" part and
    // n - n/2 takes over above 16 000 elements.
    const K = [1000]u8;
    try testing.expectEqual(@as(usize, 5000), P(K, 5000));
    try testing.expectEqual(@as(usize, 8000), P(K, 8000));
    try testing.expectEqual(@as(usize, 8000), P(K, 15_000));
    try testing.expectEqual(@as(usize, 10_000), P(K, 20_000));
    try testing.expectEqual(@as(usize, 10_001), P(K, 20_001));
    // Zero-sized types do not divide by zero.
    try testing.expectEqual(@as(usize, 100), P(void, 100));
}

test "stable allocates exactly the preferred scratch, and sorts with it" {
    const gpa = testing.allocator;
    inline for (.{ .{ Tag, 1000 }, .{ Big, 25 }, .{ Big, 32 }, .{ Big, 33 }, .{ Big, 70 } }) |c| {
        const T = c[0];
        const n = c[1];
        const v = try gpa.alloc(T, n);
        defer gpa.free(v);
        var prng = std.Random.DefaultPrng.init(n);
        for (v, 0..) |*x, i| x.* = mk(T, prng.random().uintLessThan(u32, 20), @intCast(i));
        const m = try gpa.dupe(T, v);
        defer gpa.free(m);
        var fa = testing.FailingAllocator.init(gpa, .{});
        try sort.stable(T, fa.allocator(), v, {}, T.less);
        std.sort.block(T, m, {}, T.less);
        try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(m), std.mem.sliceAsBytes(v));
        try testing.expectEqual(@as(usize, 1), fa.allocations);
        try testing.expectEqual(stable_impl.preferredScratchLen(T, n) * @sizeOf(T), fa.allocated_bytes);
    }
}

/// 208-byte elements: the stack scratch (4 KiB) holds 19 of them, so these
/// lengths allocate.
const Big = struct {
    key: u32,
    tag: u32,
    pad: [200]u8 = @splat(0),
    fn less(_: void, a: Big, b: Big) bool {
        return a.key < b.key;
    }
};

fn mk(comptime T: type, key: u32, tag: u32) T {
    var x: T = undefined;
    x = std.mem.zeroes(T);
    x.key = key;
    x.tag = tag;
    return x;
}

test "stableBuffer accepts a scratch right next to the items" {
    const gpa = testing.allocator;
    for ([_]usize{ 21, 100, 777 }) |n| {
        const need = sort.stableScratchLen(n);
        const buf = try gpa.alloc(Tag, n + need);
        defer gpa.free(buf);
        for ([_]bool{ true, false }) |scratch_after| {
            var prng = std.Random.DefaultPrng.init(n);
            const items = if (scratch_after) buf[0..n] else buf[need..];
            const scratch = if (scratch_after) buf[n..] else buf[0..need];
            for (items, 0..) |*x, i| x.* = .{ .key = prng.random().uintLessThan(u32, 30), .tag = @intCast(i) };
            const m = try gpa.dupe(Tag, items);
            defer gpa.free(m);
            sort.stableBuffer(Tag, items, scratch, {}, Tag.less);
            std.sort.block(Tag, m, {}, Tag.less);
            try testing.expectEqualSlices(Tag, m, items);
        }
    }
}

// ── panics: run in a forked child, expect an abort ──────────────────────────

const abort_signal: u32 = 6;

var debug_info_warm = false;

/// Load the executable's debug info once, before the first fork: a child that
/// panics symbolizes its stack trace, and a cold start pays for parsing the
/// DWARF again in every child (the same trick as `testkit.child`).
fn warmDebugInfo() void {
    if (debug_info_warm) return;
    debug_info_warm = true;
    var buf: [256]u8 = undefined;
    var sink: std.Io.Writer.Discarding = .init(&buf);
    std.debug.writeCurrentStackTrace(.{}, .{ .writer = &sink.writer, .mode = .no_color }) catch {};
}

/// Fork; the child runs `f(args)` (it returns normally with 0 when `f` does)
/// and is killed after 3 s of CPU. Returns how the child ended: the signal
/// number, or 1000 + the exit code.
fn forked(f: anytype, args: anytype) !u32 {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    warmDebugInfo();
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    const pid: linux.pid_t = @intCast(rc);
    if (pid == 0) {
        const lim: linux.rlimit = .{ .cur = 3, .max = 3 };
        _ = linux.setrlimit(.CPU, &lim);
        const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
        _ = linux.setrlimit(.CORE, &no_core);
        const null_fd = linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0);
        if (linux.errno(null_fd) == .SUCCESS) {
            _ = linux.dup2(@intCast(null_fd), 1);
            _ = linux.dup2(@intCast(null_fd), 2);
        }
        @call(.auto, f, args);
        linux.exit_group(0);
    }
    var st: i32 = 0;
    while (true) {
        const w = linux.wait4(pid, &st, 0, null);
        if (linux.errno(w) == .INTR) continue;
        if (linux.errno(w) != .SUCCESS) return error.WaitFailed;
        break;
    }
    const s: u32 = @bitCast(st);
    if (linux.W.IFEXITED(s)) return @as(u32, 1000) + linux.W.EXITSTATUS(s);
    return @backingInt(linux.W.TERMSIG(s));
}

fn callStableBuffer(items: []u32, scratch: []u32) void {
    sort.stableBuffer(u32, items, scratch, {}, lessU32);
}

fn callSelect(items: []u32, index: usize) void {
    sort.selectNth(u32, items, index, {}, lessU32);
}

test "stableBuffer panics on a scratch shorter than stableScratchLen" {
    const gpa = testing.allocator;
    const n = 200;
    const items = try gpa.alloc(u32, n);
    defer gpa.free(items);
    // A big allocation, a short slice of it: nothing faults if the check is gone.
    const big = try gpa.alloc(u32, 4 * n);
    defer gpa.free(big);
    for (items, 0..) |*x, i| x.* = @intCast((i * 7919) % 211);
    try testing.expectEqual(abort_signal, try forked(callStableBuffer, .{ items, big[0 .. sort.stableScratchLen(n) - 1] }));
    // The same call with exactly the least scratch is fine.
    try testing.expectEqual(@as(u32, 1000), try forked(callStableBuffer, .{ items, big[0..sort.stableScratchLen(n)] }));
}

test "stableBuffer panics when the scratch overlaps the items" {
    const gpa = testing.allocator;
    const n = 200;
    const need = sort.stableScratchLen(n);
    const buf = try gpa.alloc(u32, n + need);
    defer gpa.free(buf);
    for (buf, 0..) |*x, i| x.* = @intCast((i * 7919) % 211);
    // One element of overlap at either end.
    try testing.expectEqual(abort_signal, try forked(callStableBuffer, .{ buf[0..n], buf[n - 1 ..][0..need] }));
    try testing.expectEqual(abort_signal, try forked(callStableBuffer, .{ buf[need - 1 ..][0..n], buf[0..need] }));
    // Disjoint neighbours do not.
    try testing.expectEqual(@as(u32, 1000), try forked(callStableBuffer, .{ buf[0..n], buf[n..][0..need] }));
}

test "selectNth panics on an index past the end" {
    const gpa = testing.allocator;
    const items = try gpa.alloc(u32, 50);
    defer gpa.free(items);
    for (items, 0..) |*x, i| x.* = @intCast((i * 7919) % 211);
    try testing.expectEqual(abort_signal, try forked(callSelect, .{ items, 50 }));
    try testing.expectEqual(abort_signal, try forked(callSelect, .{ items, 51 }));
    try testing.expectEqual(@as(u32, 1000), try forked(callSelect, .{ items, 49 }));
}

// ── an adversarial comparator exhausts the recursion budgets ────────────────

/// McIlroy's "A Killer Adversary for Quicksort": the elements are indices;
/// their values are decided lazily, so that the pivot a quicksort picks is
/// always about to become an extreme. The order it settles on is consistent
/// (a strict weak order), so the output can be checked afterwards.
const Adversary = struct {
    val: []u32,
    gas: u32,
    nsolid: u32 = 0,
    candidate: u32 = 0,

    fn init(val: []u32) Adversary {
        @memset(val, @intCast(val.len));
        return .{ .val = val, .gas = @intCast(val.len) };
    }

    fn freeze(self: *Adversary, i: u32) void {
        self.val[i] = self.nsolid;
        self.nsolid += 1;
    }

    fn less(self: *Adversary, x: u32, y: u32) bool {
        if (self.val[x] == self.gas and self.val[y] == self.gas) {
            if (x == self.candidate) self.freeze(x) else self.freeze(y);
        }
        if (self.val[x] == self.gas) {
            self.candidate = x;
        } else if (self.val[y] == self.gas) {
            self.candidate = y;
        }
        return self.val[x] < self.val[y];
    }
};

fn checkAdversarial(comptime is_stable: bool, n: usize) !void {
    const gpa = testing.allocator;
    const val = try gpa.alloc(u32, n);
    defer gpa.free(val);
    const ids = try gpa.alloc(u32, n);
    defer gpa.free(ids);
    for (ids, 0..) |*x, i| x.* = @intCast(i);
    var adv: Adversary = .init(val);
    // Without this the adversary answers "ascending" to every adjacent pair
    // and the whole input is one sorted run: no quicksort at all. Element 5
    // is made the minimum, which ends the run after five elements.
    adv.freeze(5);
    if (is_stable) {
        try sort.stable(u32, gpa, ids, &adv, Adversary.less);
    } else {
        sort.unstable(u32, ids, &adv, Adversary.less);
    }
    // A permutation of the indices, with non-decreasing values (the ones
    // never frozen are all equal, and a stable sort keeps their input order).
    const seen = try gpa.alloc(bool, n);
    defer gpa.free(seen);
    @memset(seen, false);
    for (ids) |id| {
        try testing.expect(!seen[id]);
        seen[id] = true;
    }
    for (ids[1..], ids[0 .. n - 1]) |b, a| {
        try testing.expect(val[a] <= val[b]);
        if (is_stable and val[a] == val[b]) try testing.expect(a < b);
    }
}

test "unstable survives an adversary that exhausts the quicksort budget" {
    for ([_]usize{ 300, 4000 }) |n| try checkAdversarial(false, n);
}

test "stable survives an adversary that exhausts the quicksort budget" {
    for ([_]usize{ 300, 4000 }) |n| try checkAdversarial(true, n);
}

test "stableBuffer accepts an empty items slice that lies inside the scratch (sweep REV-sort-1)" {
    const gpa = testing.allocator;
    const buf = try gpa.alloc(u32, 64);
    defer gpa.free(buf);
    // `buf[10..10]` owns no bytes: it overlaps nothing, wherever its pointer is.
    try testing.expectEqual(@as(u32, 1000), try forked(callStableBuffer, .{ buf[10..10], buf[0..] }));
    // A non-empty items slice inside the scratch is still refused.
    try testing.expectEqual(abort_signal, try forked(callStableBuffer, .{ buf[10..12], buf[0..] }));
}
