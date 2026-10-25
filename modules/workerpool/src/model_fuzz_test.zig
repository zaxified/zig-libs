// SPDX-License-Identifier: MIT

//! Differential fuzz against an independent model (the card's
//! `**Evidence:** model-fuzz`). A drawn pool (1..4 workers, bounded or not,
//! with or without a spin) runs a drawn sequence of lifecycle operations on
//! real threads, and after every operation the pool is let SETTLE and then
//! compared with a sequential model of the same sequence.
//!
//! What makes a threaded pool comparable step by step: every job carries a
//! gate. A job whose gate is closed holds its worker until the harness opens
//! it; an open-gate job finishes at once. With one submitting thread the
//! queue is FIFO, so from any operation the pool must reach exactly one
//! state: workers take queued jobs in order until each of them is held by a
//! closed gate or the queue is empty (or nothing is taken while paused). The
//! model computes that state; the harness waits until the pool shows it --
//! `queuedCount`, `workingCount`, `completedCount`, `submittedCount`, and for
//! every job how often it started and finished -- and fails (`NotSettled`)
//! if the pool never gets there. Checked against the model:
//!   * `submit`: accepted, `QueueFull` exactly at `max_queued`, `Shutdown`
//!     after a shutdown; a refused job never runs;
//!   * every accepted job runs exactly once, in FIFO start order, never twice;
//!   * `pause`: a worker freed while paused takes nothing; `resume` restarts;
//!   * `wait` returns true once idle (false after a `shutdownNow` that
//!     dropped queued jobs);
//!   * `drain` runs everything queued, also over a pause;
//!   * `shutdownNow` finishes the running jobs and drops the queued ones,
//!     after it nothing is queued or running, and a `wait` blocked across
//!     it (or across a `drain`) is released with the right answer;
//!   * a burst from two submitting threads (unbounded pools) is all run.
//!
//! `WORKERPOOL_FUZZ=<runs>[,<seed>]` runs the deterministic driver; 60 seeds
//! run in every test run.

const std = @import("std");
const testing = std.testing;
const wp = @import("root.zig");
const fuzz_driver = @import("testkit").fuzz.driver;

const max_jobs = 96;

const Slot = struct {
    gate: std.atomic.Value(bool) = .init(true),
    runs: std.atomic.Value(u32) = .init(0),
    done: std.atomic.Value(u32) = .init(0),
};

fn jobFn(ctx: *anyopaque) void {
    const s: *Slot = @ptrCast(@alignCast(ctx));
    _ = s.runs.fetchAdd(1, .seq_cst);
    while (!s.gate.load(.seq_cst)) std.Thread.yield() catch {};
    _ = s.done.fetchAdd(1, .seq_cst);
}

const Status = enum { refused, queued, running, done, dropped };

const Model = struct {
    n_workers: usize,
    max_queued: usize,
    paused: bool = false,
    stopped: bool = false,
    queue: std.ArrayList(u32) = .empty,
    running: std.ArrayList(u32) = .empty,
    status: [max_jobs]Status = @splat(.refused),
    open: [max_jobs]bool = @splat(true),
    accepted: u64 = 0,
    completed: u64 = 0,
    used: u32 = 0,

    /// Workers take queued jobs in order until each is held or the queue is empty.
    fn settle(m: *Model) void {
        if (m.paused or m.stopped) return;
        while (m.running.items.len < m.n_workers and m.queue.items.len > 0) {
            const id = m.queue.orderedRemove(0);
            if (m.open[id]) {
                m.status[id] = .done;
                m.completed += 1;
            } else {
                m.status[id] = .running;
                m.running.appendAssumeCapacity(id);
            }
        }
    }

    fn openGate(m: *Model, id: u32) void {
        m.open[id] = true;
        if (m.status[id] == .running) {
            for (m.running.items, 0..) |r, i| if (r == id) {
                _ = m.running.orderedRemove(i);
                break;
            };
            m.status[id] = .done;
            m.completed += 1;
        }
    }
};

const Run = struct {
    pool: *wp.WorkerPool,
    slots: *[max_jobs]Slot,
    m: *Model,

    fn job(r: Run, id: u32) wp.Job {
        return .{ .func = jobFn, .ctx = &r.slots[id] };
    }

    /// Wait until the pool shows the model's state; `NotSettled` if it never does.
    fn check(r: Run) !void {
        const m = r.m;
        const deadline = std.Io.Timestamp.now(testing.io, .awake).nanoseconds + 10 * std.time.ns_per_s;
        while (true) {
            if (r.matches()) {
                // Hold it for a moment: a state passed through on the way to a
                // different one must not count.
                for (0..50) |_| std.Thread.yield() catch {};
                if (r.matches()) break;
            }
            for (r.slots[0..m.used]) |*s| if (s.runs.load(.seq_cst) > 1) return error.JobRanTwice;
            if (std.Io.Timestamp.now(testing.io, .awake).nanoseconds > deadline) return error.NotSettled;
            std.Thread.yield() catch {};
        }
        if (r.pool.isPaused() != m.paused) return error.PausedDiffers;
        if (r.pool.workerCount() != m.n_workers) return error.WorkerCountDiffers;
    }

    fn matches(r: Run) bool {
        const m = r.m;
        const p = r.pool;
        if (p.submittedCount() != m.accepted) return false;
        if (p.completedCount() != m.completed) return false;
        // After a shutdown nothing is queued or running any more.
        if (p.queuedCount() != m.queue.items.len) return false;
        if (p.workingCount() != m.running.items.len) return false;
        for (r.slots[0..m.used], 0..) |*s, i| {
            const want_runs: u32, const want_done: u32 = switch (m.status[i]) {
                .refused, .queued, .dropped => .{ 0, 0 },
                .running => .{ 1, 0 },
                .done => .{ 1, 1 },
            };
            if (s.runs.load(.seq_cst) != want_runs or s.done.load(.seq_cst) != want_done) return false;
        }
        return true;
    }

    fn submitOne(r: Run, gated: bool) !void {
        const m = r.m;
        if (m.used == max_jobs) return;
        const id = m.used;
        m.used += 1;
        r.slots[id].gate.store(!gated, .seq_cst);
        m.open[id] = !gated;
        const got = r.pool.submit(r.job(id));
        if (m.stopped) {
            if (got != error.Shutdown) return error.SubmitAfterShutdownDiffers;
            return;
        }
        if (m.max_queued != 0 and m.queue.items.len >= m.max_queued) {
            mark(.queue_full);
            if (got != error.QueueFull) return error.QueueFullDiffers;
            r.slots[id].gate.store(true, .seq_cst);
            m.open[id] = true;
            return;
        }
        try got;
        m.accepted += 1;
        m.status[id] = .queued;
        m.queue.appendAssumeCapacity(id);
        if (m.paused) mark(.submit_while_paused);
        m.settle();
    }

    fn openAll(r: Run) void {
        for (0..r.m.used) |i| {
            r.slots[i].gate.store(true, .seq_cst);
            r.m.openGate(@intCast(i));
        }
        r.m.settle();
    }
};

const Label = enum { queue_full, submit_while_paused, open_while_paused, wait, drain, shutdown_now, shutdown_now_drops, burst, spin, submit_after_shutdown, waiter_across_shutdown };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

fn burstWorker(r: Run, ids: []const u32) void {
    for (ids) |id| r.pool.submit(r.job(id)) catch unreachable;
}

fn shutdownNowThread(pool: *wp.WorkerPool) void {
    pool.shutdownNow();
}

/// A `wait` blocked across a shutdown; `out`: 1 = true, 2 = false.
fn waiterThread(pool: *wp.WorkerPool, out: *std.atomic.Value(u8)) void {
    out.store(if (pool.wait()) 1 else 2, .seq_cst);
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const n_workers: usize = src.valueRangeAtMost(u8, 1, 4);
    const max_queued: usize = if (src.valueRangeAtMost(u8, 0, 1) == 0) 0 else src.valueRangeAtMost(u8, 1, 6);
    const spin_ns: u64 = if (src.valueRangeAtMost(u8, 0, 3) == 0) 20_000 else 0;
    if (spin_ns != 0) mark(.spin);

    const slots = try gpa.create([max_jobs]Slot);
    defer gpa.destroy(slots);
    slots.* = @splat(.{});
    var m: Model = .{ .n_workers = n_workers, .max_queued = max_queued };
    try m.queue.ensureTotalCapacity(gpa, max_jobs);
    defer m.queue.deinit(gpa);
    try m.running.ensureTotalCapacity(gpa, max_jobs);
    defer m.running.deinit(gpa);

    const pool = try wp.WorkerPool.init(gpa, .{ .io = testing.io, .n_workers = n_workers, .spin_ns = spin_ns, .max_queued = max_queued });
    const r: Run = .{ .pool = pool, .slots = slots, .m = &m };
    // Whatever happens, no gate stays closed for the teardown.
    defer {
        for (slots) |*s| s.gate.store(true, .seq_cst);
        pool.deinit();
    }

    const steps = src.valueRangeAtMost(u8, 1, 40);
    for (0..steps) |_| {
        switch (src.valueRangeAtMost(u8, 0, 17)) {
            0...5 => try r.submitOne(src.valueRangeAtMost(u8, 0, 2) != 0),
            6, 7 => if (m.running.items.len > 0) {
                const id = m.running.items[src.index(m.running.items.len)];
                if (m.paused) mark(.open_while_paused);
                slots[id].gate.store(true, .seq_cst);
                m.openGate(id);
                m.settle();
            },
            8, 16 => if (!m.stopped) {
                pool.pause();
                m.paused = true;
            },
            9, 17 => if (!m.stopped) {
                pool.@"resume"();
                m.paused = false;
                m.settle();
            },
            10 => if (!m.stopped) {
                // wait: everything accepted must be able to finish.
                mark(.wait);
                r.openAll();
                if (m.paused) {
                    pool.@"resume"();
                    m.paused = false;
                    m.settle();
                }
                if (!pool.wait()) return error.WaitReturnedFalse;
                if (m.completed != m.accepted) return error.ModelNotIdle;
            },
            11 => if (!m.stopped and max_queued == 0 and m.used + 16 <= max_jobs) {
                // Two submitting threads, open-gate jobs only: order no longer
                // matters, all of them run or (paused / workers held) all wait.
                mark(.burst);
                var ids: [16]u32 = undefined;
                for (&ids, 0..) |*id, k| {
                    id.* = m.used + @as(u32, @intCast(k));
                    m.status[id.*] = .queued;
                    m.queue.appendAssumeCapacity(id.*);
                }
                m.used += 16;
                m.accepted += 16;
                const a = try std.Thread.spawn(.{}, burstWorker, .{ r, ids[0..8] });
                const b = try std.Thread.spawn(.{}, burstWorker, .{ r, ids[8..16] });
                a.join();
                b.join();
                m.settle();
            },
            12 => if (!m.stopped) {
                mark(.drain);
                r.openAll();
                // A `wait` blocked across the drain must come back true.
                var waited: std.atomic.Value(u8) = .init(0);
                const waiter = if (m.completed != m.accepted) try std.Thread.spawn(.{}, waiterThread, .{ pool, &waited }) else null;
                pool.drain();
                if (waiter) |w| {
                    mark(.waiter_across_shutdown);
                    w.join();
                    if (waited.load(.seq_cst) != 1) return error.WaiterAcrossDrainDiffers;
                }
                for (m.queue.items) |id| {
                    m.status[id] = .done;
                    m.completed += 1;
                }
                m.queue.clearRetainingCapacity();
                m.stopped = true;
                if (!pool.drainedCleanly()) return error.NotDrainedCleanly;
                if (!pool.wait()) return error.WaitAfterDrainFalse;
            },
            13 => if (!m.stopped) {
                mark(.shutdown_now);
                // Running jobs stay held until the pool has stopped taking
                // any: then the held ones finish and the queued ones drop.
                // With something queued there will be drops: a `wait` blocked
                // across the shutdown must be released, with false.
                var waited: std.atomic.Value(u8) = .init(0);
                const waiter = if (m.queue.items.len > 0) try std.Thread.spawn(.{}, waiterThread, .{ pool, &waited }) else null;
                const t = try std.Thread.spawn(.{}, shutdownNowThread, .{pool});
                while (true) {
                    if (pool.registerSubmitter()) |sub| {
                        var s = sub;
                        s.deinit();
                    } else |e| if (e == error.Shutdown) break;
                    std.Thread.yield() catch {};
                }
                for (m.running.items) |id| {
                    slots[id].gate.store(true, .seq_cst);
                    m.open[id] = true;
                    m.status[id] = .done;
                    m.completed += 1;
                }
                m.running.clearRetainingCapacity();
                t.join();
                if (waiter) |w| {
                    mark(.waiter_across_shutdown);
                    w.join();
                    if (waited.load(.seq_cst) != 2) return error.WaiterAcrossShutdownNowDiffers;
                }
                if (m.queue.items.len > 0) mark(.shutdown_now_drops);
                for (m.queue.items) |id| m.status[id] = .dropped;
                m.queue.clearRetainingCapacity();
                m.stopped = true;
                // `wait` is true iff idle: false only when something was dropped.
                if (pool.wait() != (m.completed == m.accepted)) return error.WaitAfterShutdownNowDiffers;
                if (pool.submittedCount() - pool.completedCount() != m.accepted - m.completed) return error.DroppedCountDiffers;
            },
            else => if (m.stopped) {
                mark(.submit_after_shutdown);
                try r.submitOne(false);
            } else try r.submitOne(false),
        }
        try r.check();
    }
}

test "model fuzz driver: WORKERPOOL_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "WORKERPOOL_FUZZ", .name = "workerpool-model", .default_limit_ms = 10_000 });
}

test "model fuzz: 60 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..60) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("workerpool model seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 60 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
