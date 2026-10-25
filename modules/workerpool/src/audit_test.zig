// SPDX-License-Identifier: MIT

//! Tests added by the grade-1 audit of `workerpool` (2026-10-25). Public API
//! and public fields only. Each test names the behaviour a mutant of
//! `root.zig` had left unchecked; two further tests (`regression:`) are the
//! reproducers of the two defects the review found, fixed the same day.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const root = @import("root.zig");
const WorkerPool = root.WorkerPool;

fn sleepMs(io: std.Io, ms: i64) void {
    var word = std.atomic.Value(u32).init(0);
    io.futexWaitTimeout(u32, &word.raw, 0, .{ .duration = .{
        .raw = .fromMilliseconds(ms),
        .clock = .awake,
    } }) catch {};
}

/// Poll `cond` every millisecond for at most `ms`; true when it became true.
fn pollTrue(io: std.Io, ms: i64, cond: *const std.atomic.Value(u32)) bool {
    var left = ms;
    while (left > 0) : (left -= 1) {
        if (cond.load(.seq_cst) != 0) return true;
        sleepMs(io, 1);
    }
    return cond.load(.seq_cst) != 0;
}

const Gate = struct {
    io: std.Io,
    open: std.atomic.Value(u32) = .init(0),
    entered: std.atomic.Value(u32) = .init(0),
    fn release(g: *Gate) void {
        g.open.store(1, .seq_cst);
        g.io.futexWake(u32, &g.open.raw, std.math.maxInt(u32));
    }
};

fn gatedJob(ctx: *anyopaque) void {
    const g: *Gate = @ptrCast(@alignCast(ctx));
    g.entered.store(1, .seq_cst);
    g.io.futexWake(u32, &g.entered.raw, std.math.maxInt(u32));
    while (g.open.load(.seq_cst) == 0) g.io.futexWaitUncancelable(u32, &g.open.raw, 0);
}

const Counter = struct {
    n: std.atomic.Value(u64) = .init(0),
};

fn incr(ctx: *anyopaque) void {
    const c: *Counter = @ptrCast(@alignCast(ctx));
    _ = c.n.fetchAdd(1, .monotonic);
}

const Flag = struct {
    v: std.atomic.Value(u32) = .init(0),
};

fn waitThread(pool: *WorkerPool, result: *std.atomic.Value(u32), done: *Flag) void {
    result.store(@intFromBool(pool.wait()), .seq_cst);
    done.v.store(1, .seq_cst);
}

fn shutdownNowThread(pool: *WorkerPool) void {
    pool.shutdownNow();
}

// ── lifecycle state ──────────────────────────────────────────────────────────

test "state: drain and shutdownNow both end in .stopped" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const a = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer a.deinit();
    try testing.expect(a.state.load(.seq_cst) == .running);
    a.drain();
    try testing.expect(a.state.load(.seq_cst) == .stopped);

    const b = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer b.deinit();
    b.shutdownNow();
    try testing.expect(b.state.load(.seq_cst) == .stopped);
    // wait() on a stopped pool answers at once: true after drain, false after
    // shutdownNow (its own dropped-jobs contract), never hangs.
    try testing.expect(a.wait());
    try testing.expect(b.wait() or b.completedCount() == b.submittedCount());
}

// ── wait bookkeeping ─────────────────────────────────────────────────────────

test "wait: a returning waiter unregisters itself (waiters back to 0)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();
    var c = Counter{};
    for (0..50) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(usize, 0), pool.waiters.load(.seq_cst));
    // A second round on an idle pool takes the early-return path.
    try testing.expect(pool.wait());
    try testing.expectEqual(@as(usize, 0), pool.waiters.load(.seq_cst));
    try testing.expectEqual(@as(u64, 50), c.n.load(.seq_cst));
}

test "wait: only returns after the running job has finished" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();
    var gate = Gate{ .io = io };
    try pool.submit(.{ .func = gatedJob, .ctx = &gate });
    try testing.expect(pollTrue(io, 2000, &gate.entered));

    var result = std.atomic.Value(u32).init(2);
    var done = Flag{};
    const th = try std.Thread.spawn(.{}, waitThread, .{ pool, &result, &done });
    sleepMs(io, 60);
    try testing.expectEqual(@as(u32, 0), done.v.load(.seq_cst)); // job still running
    try testing.expectEqual(@as(usize, 1), pool.workingCount());
    gate.release();
    try testing.expect(pollTrue(io, 2000, &done.v));
    th.join();
    try testing.expectEqual(@as(u32, 1), result.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0), pool.workingCount());
}

test "wait: a waiter arriving once shutdownNow has begun is told false at once" {
    // A gated job keeps `shutdownNow` inside its join, so the only thing that
    // can answer the NEW waiter is its own state check (`stopping_now`), not
    // the end-of-shutdown wake.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();
    var gate = Gate{ .io = io };
    var c = Counter{};
    try pool.submit(.{ .func = gatedJob, .ctx = &gate });
    try pool.submit(.{ .func = incr, .ctx = &c }); // queued behind it; will be dropped
    try testing.expect(pollTrue(io, 2000, &gate.entered));

    const sd = try std.Thread.spawn(.{}, shutdownNowThread, .{pool});
    var spins: usize = 0;
    while (pool.state.load(.seq_cst) == .running and spins < 5000) : (spins += 1) sleepMs(io, 1);
    try testing.expect(pool.state.load(.seq_cst) == .stopping_now);

    var result = std.atomic.Value(u32).init(2);
    var done = Flag{};
    const th = try std.Thread.spawn(.{}, waitThread, .{ pool, &result, &done });
    const answered = pollTrue(io, 500, &done.v); // gate is still closed
    gate.release();
    sd.join();
    th.join();
    try testing.expect(answered);
    try testing.expectEqual(@as(u32, 0), result.load(.seq_cst));
    try testing.expectEqual(@as(u64, 0), c.n.load(.seq_cst));
}

// ── bounded queue + shutdownNow ──────────────────────────────────────────────

test "max_queued: shutdownNow gives back the slot of every job it drops" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1, .max_queued = 4 });
    defer pool.deinit();
    pool.pause();
    var c = Counter{};
    for (0..4) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    try testing.expectError(error.QueueFull, pool.submit(.{ .func = incr, .ctx = &c }));
    try testing.expectEqual(@as(usize, 4), pool.queuedCount());
    pool.shutdownNow();
    try testing.expectEqual(@as(u64, 0), c.n.load(.seq_cst));
    try testing.expectEqual(@as(u64, 4), pool.dropped.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0), pool.queuedCount());
    try testing.expectEqual(@as(usize, 0), pool.queued.load(.seq_cst));
}

// ── idle accounting through a pause ──────────────────────────────────────────

test "pause: a worker parked on the pause counts as idle, and the count settles back after resume" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();
    var parked = std.atomic.Value(u32).init(0);
    // Wait for the worker's first park (empty queue).
    var i: usize = 0;
    while (pool.idle.load(.seq_cst) != 1 and i < 2000) : (i += 1) sleepMs(io, 1);
    try testing.expectEqual(@as(usize, 1), pool.idle.load(.seq_cst));
    _ = &parked;

    pool.pause();
    var c = Counter{};
    // The submit wakes the worker, which finds the pause and parks again, now
    // on the pause branch.
    try pool.submit(.{ .func = incr, .ctx = &c });
    sleepMs(io, 100);
    try testing.expectEqual(@as(u64, 0), c.n.load(.seq_cst));
    try testing.expectEqual(@as(usize, 1), pool.idle.load(.seq_cst));

    pool.@"resume"();
    try testing.expect(pool.wait());
    sleepMs(io, 100);
    try testing.expectEqual(@as(u64, 1), c.n.load(.seq_cst));
    try testing.expectEqual(@as(usize, 1), pool.idle.load(.seq_cst)); // parked once, not twice
}

// ── init: thread-spawn failure ───────────────────────────────────────────────

fn vmSizeBytes() ?usize {
    if (builtin.os.tag != .linux) return null;
    const linux = std.os.linux;
    var buf: [256]u8 = undefined;
    const raw = linux.open("/proc/self/statm", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(raw) != .SUCCESS) return null;
    const fd: i32 = @intCast(raw);
    defer _ = linux.close(fd);
    const got = linux.read(fd, &buf, buf.len);
    if (linux.errno(got) != .SUCCESS) return null;
    const n: usize = @intCast(got);
    var it = std.mem.tokenizeScalar(u8, buf[0..n], ' ');
    const first = it.next() orelse return null;
    const pages = std.fmt.parseInt(usize, first, 10) catch return null;
    return pages * std.heap.pageSize();
}

test "init: a thread-spawn failure after k workers started unwinds them all, leaks nothing" {
    // `std.Thread.spawn` maps a 16 MiB stack; capping the address space leaves
    // room for exactly `k` of them, so the (k+1)-th spawn fails and `init` must
    // stop + join the k running workers and free everything (testing.allocator
    // checks the free; a missing join/stop hangs or crashes here).
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const base = vmSizeBytes() orelse return error.SkipZigTest;
    const old = std.posix.getrlimit(.AS) catch return error.SkipZigTest;
    const stack = std.Thread.SpawnConfig.default_stack_size;
    for ([_]usize{ 0, 1, 2 }) |k| {
        const want = base + k * stack + 6 * 1024 * 1024;
        if (old.max != std.math.maxInt(@TypeOf(old.max)) and old.max < want) return error.SkipZigTest;
        std.posix.setrlimit(.AS, .{ .cur = want, .max = old.max }) catch return error.SkipZigTest;
        defer std.posix.setrlimit(.AS, old) catch {};
        const r = WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 6 });
        std.posix.setrlimit(.AS, old) catch {};
        if (r) |pool| {
            // The cap was not enforced (sandboxed environment): nothing to test.
            pool.deinit();
            return error.SkipZigTest;
        } else |err| {
            try testing.expectEqual(error.SpawnFailed, err);
        }
    }
}

// ── re-entrancy ──────────────────────────────────────────────────────────────

const Chain = struct {
    pool: *WorkerPool,
    left: std.atomic.Value(u32),
    ran: std.atomic.Value(u32) = .init(0),
    refused: std.atomic.Value(u32) = .init(0),
};

fn chainJob(ctx: *anyopaque) void {
    const c: *Chain = @ptrCast(@alignCast(ctx));
    _ = c.ran.fetchAdd(1, .seq_cst);
    if (c.left.fetchSub(1, .seq_cst) > 1) {
        c.pool.submit(.{ .func = chainJob, .ctx = ctx }) catch {
            _ = c.refused.fetchAdd(1, .seq_cst);
        };
    }
}

test "re-entrancy: a job that submits the next job; wait() covers the whole chain" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 3 });
    defer pool.deinit();
    for (0..20) |_| {
        var chain = Chain{ .pool = pool, .left = .init(300) };
        try pool.submit(.{ .func = chainJob, .ctx = &chain });
        // The follow-up is submitted before the job returns, so the counts are
        // never equal mid-chain: wait() must not return early.
        try testing.expect(pool.wait());
        try testing.expectEqual(@as(u32, 300), chain.ran.load(.seq_cst));
        try testing.expectEqual(@as(u32, 0), chain.refused.load(.seq_cst));
        try testing.expect(pool.drainedCleanly());
    }
}

test "re-entrancy: a job submitting while the pool drains is refused with Shutdown, nothing is lost" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 2 });
    defer pool.deinit();
    pool.pause();
    var chain = Chain{ .pool = pool, .left = .init(1000) };
    try pool.submit(.{ .func = chainJob, .ctx = &chain });
    pool.drain(); // overrides the pause; the chain is cut at the first refused submit
    try testing.expect(chain.ran.load(.seq_cst) >= 1);
    try testing.expect(chain.refused.load(.seq_cst) <= 1);
    try testing.expect(pool.drainedCleanly()); // every ACCEPTED job ran
    try testing.expectEqual(@as(usize, 0), pool.queuedCount());
}

// ── known defects (reproducers; gated off) ───────────────────────────────────

/// An allocator that, once armed, blocks its next allocation until released
/// and then refuses it. It sits behind `pool.queue.allocator` to hold a
/// `submit` inside the window between `submitted += 1` and its rollback.
const HoldAlloc = struct {
    backing: std.mem.Allocator,
    io: std.Io,
    armed: std.atomic.Value(u32) = .init(0),
    in_alloc: std.atomic.Value(u32) = .init(0),
    go: std.atomic.Value(u32) = .init(0),

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = std.mem.Allocator.noResize,
        .remap = std.mem.Allocator.noRemap,
        .free = free,
    };

    fn allocator(self: *HoldAlloc) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *HoldAlloc = @ptrCast(@alignCast(ctx));
        if (self.armed.cmpxchgStrong(1, 0, .seq_cst, .seq_cst) == null) {
            self.in_alloc.store(1, .seq_cst);
            while (self.go.load(.seq_cst) == 0) sleepMs(self.io, 1);
            return null;
        }
        return self.backing.rawAlloc(len, alignment, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *HoldAlloc = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, ret_addr);
    }
};

fn submitThread(pool: *WorkerPool, c: *Counter, out: *std.atomic.Value(u32)) void {
    const r = pool.submit(.{ .func = incr, .ctx = c });
    out.store(if (r) |_| 1 else |e| (if (e == error.SubmitFailed) 2 else 3), .seq_cst);
}

test "regression: wait() parked while a submit was in flight is released by that submit's rollback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();
    var c = Counter{};
    const block_slots = @TypeOf(pool.queue).block_slots;
    // Leave the pool idle with the next push needing a fresh queue block.
    for (0..block_slots - 1) |_| try pool.submit(.{ .func = incr, .ctx = &c });
    try testing.expect(pool.wait());

    var hold = HoldAlloc{ .backing = testing.allocator, .io = io };
    pool.queue.allocator = hold.allocator();
    defer pool.queue.allocator = testing.allocator;
    hold.armed.store(1, .seq_cst);
    var out = std.atomic.Value(u32).init(0);
    const sub = try std.Thread.spawn(.{}, submitThread, .{ pool, &c, &out });
    try testing.expect(pollTrue(io, 2000, &hold.in_alloc)); // submitted = N+1, push stuck

    var result = std.atomic.Value(u32).init(2);
    var done = Flag{};
    const wt = try std.Thread.spawn(.{}, waitThread, .{ pool, &result, &done });
    var i: usize = 0;
    while (pool.waiters.load(.seq_cst) == 0 and i < 2000) : (i += 1) sleepMs(io, 1);
    sleepMs(io, 100); // let it park on done_gen

    hold.go.store(1, .seq_cst); // the push fails; submitted rolls back to N
    sub.join();
    try testing.expectEqual(@as(u32, 2), out.load(.seq_cst)); // SubmitFailed
    const released = pollTrue(io, 500, &done.v); // idle again: wait() must return

    // Cleanup so the test ends either way: a real completion releases it.
    pool.queue.allocator = testing.allocator;
    if (!released) try pool.submit(.{ .func = incr, .ctx = &c });
    wt.join();
    try testing.expect(released);
}

const PauseProbe = struct {
    pool: *WorkerPool,
    job1_done: std.atomic.Value(u32) = .init(0),
    job2_ran_paused: std.atomic.Value(u32) = .init(0),
    job2_ran: std.atomic.Value(u32) = .init(0),
};

fn probeJob1(ctx: *anyopaque) void {
    const p: *PauseProbe = @ptrCast(@alignCast(ctx));
    p.job1_done.store(1, .seq_cst);
}

fn probeJob2(ctx: *anyopaque) void {
    const p: *PauseProbe = @ptrCast(@alignCast(ctx));
    if (p.pool.isPaused()) p.job2_ran_paused.store(1, .seq_cst);
    p.job2_ran.store(1, .seq_cst);
}

test "regression: a job submitted after pause() returned never starts" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const pool = try WorkerPool.init(testing.allocator, .{ .io = io, .n_workers = 1 });
    defer pool.deinit();
    var violations: usize = 0;
    for (0..30_000) |_| {
        var p = PauseProbe{ .pool = pool };
        try pool.submit(.{ .func = probeJob1, .ctx = &p });
        // Hit the worker right after it finished job 1, when it is between its
        // pause check and the queue's final re-check.
        while (p.job1_done.load(.seq_cst) == 0) std.atomic.spinLoopHint();
        pool.pause();
        try pool.submit(.{ .func = probeJob2, .ctx = &p });
        var spin: u32 = 0;
        while (spin < 20_000 and p.job2_ran.load(.seq_cst) == 0) : (spin += 1) std.atomic.spinLoopHint();
        if (p.job2_ran_paused.load(.seq_cst) != 0) violations += 1;
        pool.@"resume"();
        try testing.expect(pool.wait());
    }
    try testing.expectEqual(@as(usize, 0), violations);
}

const child = @import("testkit").child;

fn waitFromOwnJob(ctx: *anyopaque) void {
    const pool: *WorkerPool = @ptrCast(@alignCast(ctx));
    _ = pool.wait();
}

fn waitFromJobChild() u8 {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{}); // global-alloc-ok: a forked child, whose leak checks never run
    const pool = WorkerPool.init(std.heap.smp_allocator, .{ .io = threaded.io(), .n_workers = 1 }) catch return 3; // global-alloc-ok: same child
    pool.submit(.{ .func = waitFromOwnJob, .ctx = pool }) catch return 4;
    _ = pool.wait();
    return 0;
}

test "wait() from a job of the same pool panics instead of deadlocking (in a child process)" {
    // The detection (`current_pool`, set by each worker) is the only thing
    // between this and a deadlock: without it the child hangs.
    if (!child.supported) return error.SkipZigTest;
    const out = try child.run(waitFromJobChild, .{}, .{ .limit_ms = 5000 });
    try testing.expect(out.eql(.{ .signaled = @backingInt(std.posix.SIG.ABRT) }));
}
