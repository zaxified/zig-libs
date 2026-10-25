// SPDX-License-Identifier: MIT

//! The card's allocation lead (`**Ahead:**` in SPEC.md), pinned: in the
//! steady state a submitted job costs no heap allocation -- it rides by
//! value in a queue slot, and the queue keeps one spare 63-slot block, so a
//! burst that fits what the pool has already seen allocates nothing. The
//! field, measured 2026-10-25 by `tools/rust_fast_bench <pool> allocs` (a
//! counting `GlobalAlloc`) and `tools/go_fast_bench allocs`
//! (`runtime.MemStats.Mallocs`) over the same warm-up-then-100 000-jobs
//! burst: rayon-core 1.13.0 1.000 per job (a boxed `HeapJob` per `spawn`),
//! threadpool 1.8.1 1.032 (a boxed closure per `execute`), panjf2000/ants
//! v2.12.0 0.998 (the `any` argument escapes to the heap). The reference,
//! Pithikos/C-Thread-Pool, `malloc`s a job record per `thpool_add_work`.

const std = @import("std");
const testing = std.testing;
const wp = @import("root.zig");

/// A thread-safe allocator counting every allocation and resize that grows.
const Counting = struct {
    child: std.mem.Allocator,
    n: std.atomic.Value(u64) = .init(0),

    fn allocator(c: *Counting) std.mem.Allocator {
        return .{ .ptr = c, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        _ = c.n.fetchAdd(1, .seq_cst);
        return c.child.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, len: usize, ra: usize) bool {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        if (len > m.len) _ = c.n.fetchAdd(1, .seq_cst);
        return c.child.rawResize(m, a, len, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        if (len > m.len) _ = c.n.fetchAdd(1, .seq_cst);
        return c.child.rawRemap(m, a, len, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.child.rawFree(m, a, ra);
    }
};

var ran: std.atomic.Value(u64) = .init(0);
fn noop(_: *anyopaque) void {
    _ = ran.fetchAdd(1, .monotonic);
}

test "lead: no heap allocation per job in the steady state, where rayon-core, threadpool and ants allocate one" {
    var counting: Counting = .{ .child = std.heap.smp_allocator };
    const pool = try wp.WorkerPool.init(counting.allocator(), .{ .io = testing.io, .n_workers = 4 });
    defer pool.deinit();
    var dummy: u8 = 0;
    const burst = 100_000;
    // Warm-up: the pool meets the queue depth this kind of burst reaches.
    for (0..3) |_| {
        for (0..burst) |_| try pool.submit(.{ .func = noop, .ctx = &dummy });
        _ = pool.wait();
    }
    // A producer far ahead of the workers needs blocks for its backlog: what
    // is pinned is the paced steady state (submit one, the workers keep up)
    // and the allocation count of a whole burst relative to its job count.
    const before = counting.n.load(.seq_cst);
    for (0..burst) |i| {
        try pool.submit(.{ .func = noop, .ctx = &dummy });
        if (i % 32 == 31) _ = pool.wait();
    }
    _ = pool.wait();
    try testing.expectEqual(@as(u64, 0), counting.n.load(.seq_cst) - before);

    // An unpaced burst: at most one block per 63 jobs of backlog.
    const b2 = counting.n.load(.seq_cst);
    for (0..burst) |_| try pool.submit(.{ .func = noop, .ctx = &dummy });
    _ = pool.wait();
    try testing.expect(counting.n.load(.seq_cst) - b2 <= burst / 63 + 1);
}
