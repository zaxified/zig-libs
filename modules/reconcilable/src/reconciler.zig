// SPDX-License-Identifier: MIT
//! `Reconciler(Key, Ctx)` — the caller-driven convergence loop over
//! `WorkQueue(Key)`.
//!
//! The whole module is one sentence: *the caller says which keys may have
//! diverged, `tick` runs each one's idempotent reconcile pass at most once, and
//! whatever does not converge comes back on a backoff timer.* There is no
//! thread and no clock inside; see SPEC.md §2 for why.

const std = @import("std");
const resilience = @import("resilience");
const types = @import("types.zig");
const queue = @import("queue.zig");

const Instant = types.Instant;

pub fn Reconciler(comptime Key: type, comptime Ctx: type) type {
    return struct {
        const Self = @This();

        pub const Queue = queue.WorkQueue(Key);

        /// The reconcile pass. MUST be idempotent: it is called with a key, not
        /// with a delta, and may be called any number of times for one change.
        /// It observes actual state, compares it with desired state, applies
        /// the difference, and reports an `Outcome`.
        ///
        /// It may call `enqueue`/`enqueueAfter`/`forget` on its own reconciler
        /// re-entrantly, including for its own key — a self-enqueue is honoured
        /// after the pass returns, never inside the same tick.
        pub const ReconcileFn = *const fn (ctx: Ctx, key: Key, now: Instant) types.Outcome;

        q: Queue,
        ctx: Ctx,
        reconcileFn: ReconcileFn,
        opts: types.Options,
        counters: types.Stats,

        pub fn init(
            gpa: std.mem.Allocator,
            ctx: Ctx,
            reconcileFn: ReconcileFn,
            opts: types.Options,
        ) !Self {
            std.debug.assert(opts.capacity >= 1);
            return .{
                .q = try Queue.init(gpa, opts.capacity),
                .ctx = ctx,
                .reconcileFn = reconcileFn,
                .opts = opts,
                .counters = .{},
            };
        }

        pub fn deinit(self: *Self) void {
            self.q.deinit();
            self.* = undefined;
        }

        // ── admission ───────────────────────────────────────────────────────

        /// "This key may have diverged." Level-triggered: what is enqueued is
        /// the *identity* of a thing to re-examine, never a delta, so a lost
        /// coalescing is not a lost change.
        pub fn enqueue(self: *Self, key: Key) types.Error!types.Admission {
            const a = self.q.enqueue(key) catch |err| {
                self.counters.rejected += 1;
                self.counters.overflowed = true;
                return err;
            };
            self.countAdmission(a);
            return a;
        }

        /// As `enqueue`, but not before `now + delay_ns`.
        pub fn enqueueAfter(self: *Self, key: Key, now: Instant, delay_ns: u64) types.Error!types.Admission {
            const a = self.q.enqueueAfter(key, now, delay_ns) catch |err| {
                self.counters.rejected += 1;
                self.counters.overflowed = true;
                return err;
            };
            self.countAdmission(a);
            return a;
        }

        fn countAdmission(self: *Self, a: types.Admission) void {
            switch (a) {
                .admitted => self.counters.admitted += 1,
                .deduped, .promoted, .marked_dirty => self.counters.deduped += 1,
            }
        }

        /// Stop tracking `key` and reset its failure streak. Use when the
        /// desired state no longer contains it at all.
        pub fn forget(self: *Self, key: Key) bool {
            return self.q.forget(key);
        }

        // ── the loop ────────────────────────────────────────────────────────

        /// Run one pass of the loop at instant `now`.
        ///
        /// 1. every timer that has come due moves to the tail of the ready
        ///    FIFO, earliest deadline first;
        /// 2. up to `budget_per_tick` keys — but never more than were ready at
        ///    step 2's start — are reconciled in FIFO order;
        /// 3. each outcome is dispositioned (see SPEC.md §3).
        ///
        /// The "never more than were ready at the start" clause is the
        /// exactly-once-per-tick guarantee: a key re-enqueued by a pass in this
        /// tick is reconciled in the *next* tick, so one tick cannot spin
        /// forever on a self-re-enqueueing key.
        pub fn tick(self: *Self, now: Instant) types.TickReport {
            _ = self.q.promoteDue(now);

            const ready_at_start = self.q.ready_len;
            const budget = if (self.opts.budget_per_tick == 0)
                ready_at_start
            else
                @min(self.opts.budget_per_tick, ready_at_start);

            var done: u32 = 0;
            while (done < budget) : (done += 1) {
                const idx = self.q.takeReady() orelse break;
                const key = self.q.slotKey(idx);
                self.counters.reconciled += 1;
                const outcome = self.reconcileFn(self.ctx, key, now);
                self.apply(idx, now, outcome);
            }

            if (std.debug.runtime_safety) self.q.assertInvariants();

            return .{
                .reconciled = done,
                .ready = self.q.ready_len,
                .waiting = self.q.heap_len,
                .next_due = self.nextDue(now),
            };
        }

        fn apply(self: *Self, idx: u32, now: Instant, outcome: types.Outcome) void {
            switch (outcome) {
                .done => {
                    self.counters.converged += 1;
                    self.q.setSlotFailures(idx, 0);
                    self.q.finish(idx, now, .drop);
                },
                .requeue_after => |ns| {
                    // The caller chose the delay, so forget the streak — the
                    // rate limiter must not stretch a deliberate interval.
                    self.q.setSlotFailures(idx, 0);
                    self.q.finish(idx, now, .{ .after = ns });
                },
                .requeue => self.backoff(idx, now),
                .failed => |err| {
                    self.counters.failed += 1;
                    if (self.opts.on_error) |sink| sink.onErrorFn(sink.ctx, err);
                    self.backoff(idx, now);
                },
            }
        }

        fn backoff(self: *Self, idx: u32, now: Instant) void {
            self.counters.retried += 1;
            const failures = self.q.slotFailures(idx) + 1;
            self.q.setSlotFailures(idx, failures);

            if (self.opts.max_failures != 0 and failures >= self.opts.max_failures) {
                self.counters.abandoned += 1;
                self.q.finish(idx, now, .drop);
                return;
            }
            const delay_ms = self.opts.backoff.nextDelay(failures, self.opts.random);
            self.q.finish(idx, now, .{ .after = delay_ms *| std.time.ns_per_ms });
        }

        // ── queries ─────────────────────────────────────────────────────────

        /// The earliest instant at which `tick` would do work: `now` itself
        /// when something is already ready, else the earliest timer deadline,
        /// else null (idle). Feed into a `poll(2)` timeout — see the README for
        /// the loop skeleton.
        pub fn nextDue(self: *const Self, now: Instant) ?Instant {
            if (self.q.ready_len > 0) return now;
            return self.q.nextTimer();
        }

        /// Nanoseconds the caller may sleep before the next `tick` matters.
        /// `null` = idle indefinitely (wake on an external event instead).
        pub fn sleepFor(self: *const Self, now: Instant) ?u64 {
            const due = self.nextDue(now) orelse return null;
            return if (due <= now) 0 else due - now;
        }

        pub fn pending(self: *const Self) u32 {
            return self.q.tracked;
        }

        pub fn stats(self: *const Self) types.Stats {
            return self.counters;
        }

        /// Acknowledge an overflow after performing a full resync.
        pub fn clearOverflow(self: *Self) void {
            self.counters.overflowed = false;
        }

        pub fn failuresOf(self: *const Self, key: Key) ?u32 {
            return self.q.failuresOf(key);
        }

        pub fn contains(self: *const Self, key: Key) bool {
            return self.q.contains(key);
        }

        /// Drive the loop until nothing is ready and nothing is due, advancing
        /// a caller-held clock through the timer deadlines. Test and
        /// batch-convergence helper: in production the caller's own event loop
        /// plays this role. `max_ticks` bounds it so a never-converging
        /// reconcile function cannot hang a test.
        pub fn drain(self: *Self, start: Instant, max_ticks: u32) struct { now: Instant, ticks: u32 } {
            var now = start;
            var ticks: u32 = 0;
            while (ticks < max_ticks) : (ticks += 1) {
                const r = self.tick(now);
                const due = r.next_due orelse break;
                if (r.reconciled == 0 and r.ready == 0) {
                    if (due <= now) break;
                    now = due;
                } else if (due > now) {
                    now = due;
                }
            }
            return .{ .now = now, .ticks = ticks };
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A scripted reconcile target: records the order of calls and replays a
/// per-key outcome script.
const Recorder = struct {
    calls: std.ArrayList(u32) = .empty,
    gpa: std.mem.Allocator,
    outcome: types.Outcome = .done,
    /// Optional: fail the first N calls for every key, then converge.
    fail_first: u32 = 0,
    seen: std.AutoHashMapUnmanaged(u32, u32) = .empty,

    fn deinit(self: *Recorder) void {
        self.calls.deinit(self.gpa);
        self.seen.deinit(self.gpa);
    }

    fn reconcile(self: *Recorder, key: u32, now: Instant) types.Outcome {
        _ = now;
        self.calls.append(self.gpa, key) catch @panic("OOM");
        const gop = self.seen.getOrPut(self.gpa, key) catch @panic("OOM");
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
        if (gop.value_ptr.* <= self.fail_first) return .{ .failed = error.NotYet };
        return self.outcome;
    }
};

fn recorderFn(ctx: *Recorder, key: u32, now: Instant) types.Outcome {
    return ctx.reconcile(key, now);
}

const R = Reconciler(u32, *Recorder);

fn newRecorder() Recorder {
    return .{ .gpa = testing.allocator };
}

test "an enqueue burst produces exactly one reconcile" {
    var rec = newRecorder();
    defer rec.deinit();
    var r = try R.init(testing.allocator, &rec, recorderFn, .{ .capacity = 16 });
    defer r.deinit();

    for (0..50) |_| _ = try r.enqueue(1);
    const report = r.tick(0);

    try testing.expectEqual(@as(u32, 1), report.reconciled);
    try testing.expectEqual(@as(usize, 1), rec.calls.items.len);
    try testing.expectEqual(@as(u64, 1), r.stats().admitted);
    try testing.expectEqual(@as(u64, 49), r.stats().deduped);
    try testing.expectEqual(@as(u32, 0), r.pending());
}

test "FIFO order and a per-tick budget that cannot starve the tail" {
    var rec = newRecorder();
    defer rec.deinit();
    var r = try R.init(testing.allocator, &rec, recorderFn, .{ .capacity = 16, .budget_per_tick = 2 });
    defer r.deinit();

    for (0..6) |i| _ = try r.enqueue(@intCast(i));

    var tick_no: Instant = 0;
    while (r.pending() > 0) : (tick_no += 1) {
        const report = r.tick(tick_no);
        try testing.expect(report.reconciled <= 2);
    }
    try testing.expectEqual(@as(Instant, 3), tick_no); // ceil(6/2)
    try testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3, 4, 5 }, rec.calls.items);
}

test "a self-enqueue during a pass runs in the NEXT tick, not this one" {
    const Selfish = struct {
        r: ?*anyopaque = null,
        calls: u32 = 0,
        fn go(ctx: *@This(), key: u32, _: Instant) types.Outcome {
            ctx.calls += 1;
            if (ctx.calls < 3) {
                const self_r: *Reconciler(u32, *@This()) = @ptrCast(@alignCast(ctx.r.?));
                _ = self_r.enqueue(key) catch unreachable;
            }
            return .done;
        }
    };
    var s: Selfish = .{};
    const SR = Reconciler(u32, *Selfish);
    var r = try SR.init(testing.allocator, &s, Selfish.go, .{ .capacity = 4 });
    defer r.deinit();
    s.r = &r;

    _ = try r.enqueue(1);
    try testing.expectEqual(@as(u32, 1), r.tick(0).reconciled);
    try testing.expectEqual(@as(u32, 1), s.calls);
    try testing.expectEqual(@as(u32, 1), r.tick(1).reconciled);
    try testing.expectEqual(@as(u32, 2), s.calls);
    try testing.expectEqual(@as(u32, 1), r.tick(2).reconciled);
    try testing.expectEqual(@as(u32, 3), s.calls);
    try testing.expectEqual(@as(u32, 0), r.tick(3).reconciled);
}

test "F3: exactly-once-per-tick holds even with a nonzero budget_per_tick, not just the unlimited (0) case" {
    // `tick` computes `budget = @min(opts.budget_per_tick, ready_at_start)`;
    // the `ready_at_start` term is what stops a self-re-enqueueing key from
    // being reconciled twice in one tick. The only prior self-enqueue test
    // left `budget_per_tick` at its default 0, which takes the OTHER
    // branch (`budget = ready_at_start`) and never reaches the clamp at
    // all — so a regression that dropped `ready_at_start` from the min
    // entirely (using the raw configured budget) went undetected. Same
    // scenario as that test, but with a real nonzero budget bigger than
    // what is ready.
    const Selfish = struct {
        r: ?*anyopaque = null,
        calls: u32 = 0,
        fn go(ctx: *@This(), key: u32, _: Instant) types.Outcome {
            ctx.calls += 1;
            if (ctx.calls < 3) {
                const self_r: *Reconciler(u32, *@This()) = @ptrCast(@alignCast(ctx.r.?));
                _ = self_r.enqueue(key) catch unreachable;
            }
            return .done;
        }
    };
    var s: Selfish = .{};
    const SR = Reconciler(u32, *Selfish);
    // budget_per_tick = 5: far more than the single key that is ever ready
    // at once, so a broken clamp (ignoring ready_at_start) would let the
    // self-enqueue be immediately re-picked-up and reconciled again within
    // the SAME tick, instead of parking it for the next one.
    var r = try SR.init(testing.allocator, &s, Selfish.go, .{ .capacity = 4, .budget_per_tick = 5 });
    defer r.deinit();
    s.r = &r;

    _ = try r.enqueue(1);
    try testing.expectEqual(@as(u32, 1), r.tick(0).reconciled);
    try testing.expectEqual(@as(u32, 1), s.calls);
    try testing.expectEqual(@as(u32, 1), r.tick(1).reconciled);
    try testing.expectEqual(@as(u32, 2), s.calls);
    try testing.expectEqual(@as(u32, 1), r.tick(2).reconciled);
    try testing.expectEqual(@as(u32, 3), s.calls);
    try testing.expectEqual(@as(u32, 0), r.tick(3).reconciled);
}

test "failure backoff is exponential, capped, and reset by a success" {
    var rec = newRecorder();
    defer rec.deinit();
    rec.fail_first = 10;
    var r = try R.init(testing.allocator, &rec, recorderFn, .{
        .capacity = 4,
        .backoff = .{ .base_delay_ms = 1, .factor = 2.0, .max_delay_ms = 8, .jitter = .none },
    });
    defer r.deinit();

    _ = try r.enqueue(1);
    var now: Instant = 0;
    var delays: [6]u64 = undefined;
    for (&delays) |*d| {
        _ = r.tick(now);
        const due = r.nextDue(now).?;
        d.* = (due - now) / std.time.ns_per_ms;
        now = due;
    }
    try testing.expectEqualSlices(u64, &.{ 1, 2, 4, 8, 8, 8 }, &delays);

    // A success forgets the streak: the next failure starts at base again.
    rec.fail_first = 0;
    _ = r.tick(now);
    try testing.expectEqual(@as(u32, 0), r.pending());
    rec.fail_first = 100;
    _ = try r.enqueue(1);
    _ = r.tick(now);
    try testing.expectEqual(@as(u64, 1), (r.nextDue(now).? - now) / std.time.ns_per_ms);
}

test "F5: Stats.retried counts every backoff (requeue AND failed), like every other counter" {
    // `retried` is a documented public counter, incremented in `backoff`
    // (called on both `.requeue` and `.failed` outcomes), but was asserted
    // by no test — every sibling counter (admitted/deduped/rejected/
    // reconciled/converged/failed/abandoned/overflowed) is.
    var rec = newRecorder();
    defer rec.deinit();
    rec.fail_first = 3; // fails the first 3 reconciles, then succeeds
    var r = try R.init(testing.allocator, &rec, recorderFn, .{
        .capacity = 4,
        .backoff = .{ .base_delay_ms = 1, .factor = 2.0, .max_delay_ms = 8, .jitter = .none },
    });
    defer r.deinit();

    _ = try r.enqueue(1);
    var now: Instant = 0;
    for (0..3) |_| {
        _ = r.tick(now);
        now = r.nextDue(now).?;
    }
    try testing.expectEqual(@as(u64, 3), r.stats().retried);
    try testing.expectEqual(@as(u64, 3), r.stats().failed);

    // The 4th tick succeeds — no further backoff, retried stays at 3.
    _ = r.tick(now);
    try testing.expectEqual(@as(u64, 3), r.stats().retried);
    try testing.expectEqual(@as(u64, 1), r.stats().converged);
}

test "requeue_after is honoured exactly and does not accumulate backoff" {
    const Fixed = struct {
        n: u32 = 0,
        fn go(ctx: *@This(), _: u32, _: Instant) types.Outcome {
            ctx.n += 1;
            return .{ .requeue_after = 1000 };
        }
    };
    var f: Fixed = .{};
    const FR = Reconciler(u32, *Fixed);
    var r = try FR.init(testing.allocator, &f, Fixed.go, .{ .capacity = 4 });
    defer r.deinit();

    _ = try r.enqueue(1);
    var now: Instant = 0;
    for (0..5) |_| {
        _ = r.tick(now);
        const due = r.nextDue(now).?;
        try testing.expectEqual(now + 1000, due);
        now = due;
    }
    try testing.expectEqual(@as(u32, 5), f.n);
    try testing.expectEqual(@as(?u32, 0), r.failuresOf(1));
}

test "a huge requeue_after keeps the key, it does not silently converge" {
    // The caller-visible half of the `nil_due` sentinel collision: a large
    // `requeue_after` (the documented shape for a lease TTL / long poll
    // interval) saturates `now +| ns`, which used to equal the "nothing
    // deferred" sentinel and drop the key. `.done` and a far-future
    // `.requeue_after` must be distinguishable from outside the module.
    const Big = struct {
        n: u32 = 0,
        fn go(ctx: *@This(), _: u32, _: Instant) types.Outcome {
            ctx.n += 1;
            return .{ .requeue_after = std.math.maxInt(u64) };
        }
    };
    var f: Big = .{};
    const BR = Reconciler(u32, *Big);
    var r = try BR.init(testing.allocator, &f, Big.go, .{ .capacity = 4 });
    defer r.deinit();

    _ = try r.enqueue(1);
    _ = r.tick(0);
    try testing.expectEqual(@as(u32, 1), f.n);
    try testing.expectEqual(@as(u32, 1), r.pending());
    try testing.expect(r.nextDue(0) != null);
    try testing.expectEqual(@as(u64, 0), r.stats().converged);

    // Contrast: `.done` really does drop the key, so the caller can tell the
    // two outcomes apart by `pending()`.
    const Doner = struct {
        fn go(_: *void, _: u32, _: Instant) types.Outcome {
            return .done;
        }
    };
    var unit: void = {};
    const DR = Reconciler(u32, *void);
    var d = try DR.init(testing.allocator, &unit, Doner.go, .{ .capacity = 4 });
    defer d.deinit();
    _ = try d.enqueue(1);
    _ = d.tick(0);
    try testing.expectEqual(@as(u32, 0), d.pending());
}

test "max_failures abandons a hopeless key instead of retrying forever" {
    var rec = newRecorder();
    defer rec.deinit();
    rec.fail_first = 1000;
    var r = try R.init(testing.allocator, &rec, recorderFn, .{
        .capacity = 4,
        .max_failures = 3,
        .backoff = .{ .base_delay_ms = 1, .max_delay_ms = 1, .jitter = .none },
    });
    defer r.deinit();

    _ = try r.enqueue(1);
    const end = r.drain(0, 100);
    try testing.expectEqual(@as(usize, 3), rec.calls.items.len);
    try testing.expectEqual(@as(u32, 0), r.pending());
    try testing.expectEqual(@as(u64, 1), r.stats().abandoned);
    try testing.expect(end.ticks < 100);
}

test "AtCapacity rejects, counts, and raises the sticky overflow flag" {
    var rec = newRecorder();
    defer rec.deinit();
    var r = try R.init(testing.allocator, &rec, recorderFn, .{ .capacity = 2 });
    defer r.deinit();

    _ = try r.enqueue(1);
    _ = try r.enqueue(2);
    try testing.expectError(types.Error.AtCapacity, r.enqueue(3));
    try testing.expect(r.stats().overflowed);
    try testing.expectEqual(@as(u64, 1), r.stats().rejected);

    // Draining frees slots; a resync then re-admits the lost key.
    _ = r.drain(0, 10);
    _ = try r.enqueue(3);
    r.clearOverflow();
    try testing.expect(!r.stats().overflowed);
}

test "the error sink sees every failed outcome" {
    const Sink = struct {
        var count: u32 = 0;
        fn onErr(_: ?*anyopaque, err: anyerror) void {
            std.debug.assert(err == error.NotYet);
            count += 1;
        }
    };
    Sink.count = 0;
    var rec = newRecorder();
    defer rec.deinit();
    rec.fail_first = 3;
    var r = try R.init(testing.allocator, &rec, recorderFn, .{
        .capacity = 4,
        .backoff = .{ .base_delay_ms = 1, .max_delay_ms = 1, .jitter = .none },
        .on_error = .{ .onErrorFn = Sink.onErr },
    });
    defer r.deinit();

    _ = try r.enqueue(1);
    _ = r.drain(0, 50);
    try testing.expectEqual(@as(u32, 3), Sink.count);
    try testing.expectEqual(@as(u64, 3), r.stats().failed);
    try testing.expectEqual(@as(u64, 1), r.stats().converged);
}

test "ticking an empty reconciler is free and reports idle" {
    var rec = newRecorder();
    defer rec.deinit();
    var r = try R.init(testing.allocator, &rec, recorderFn, .{ .capacity = 4 });
    defer r.deinit();

    const report = r.tick(12345);
    try testing.expectEqual(@as(u32, 0), report.reconciled);
    try testing.expectEqual(@as(?Instant, null), report.next_due);
    try testing.expectEqual(@as(?u64, null), r.sleepFor(12345));
    try testing.expectEqual(@as(usize, 0), rec.calls.items.len);
}

test "sleepFor: zero when something is ready now, the exact gap when only a timer is pending" {
    // The only existing sleepFor test covers just the null (idle) branch —
    // both non-null arms (`due <= now -> 0`, `due > now -> due - now`) had
    // no coverage, including the underflow-prone subtraction if the clamp
    // were ever dropped.
    var rec = newRecorder();
    defer rec.deinit();
    var r = try R.init(testing.allocator, &rec, recorderFn, .{ .capacity = 4 });
    defer r.deinit();

    // Ready right now: nextDue == now, so sleepFor must be exactly 0.
    _ = try r.enqueue(1);
    try testing.expectEqual(@as(?u64, 0), r.sleepFor(100));

    // Drain it, then park a future timer: sleepFor must be the exact gap.
    _ = r.tick(100);
    _ = try r.enqueueAfter(2, 100, 5000);
    try testing.expectEqual(@as(?u64, 5000), r.sleepFor(100));
    try testing.expectEqual(@as(?u64, 3000), r.sleepFor(2100));

    // An overdue timer (deadline already in the past relative to `now`,
    // because nothing has ticked to promote it yet) must clamp to 0, not
    // underflow the unsigned subtraction into a huge wraparound value.
    try testing.expectEqual(@as(?u64, 0), r.sleepFor(10_000));
}

test "a struct key works and forget drops it" {
    const Filter = struct { ifindex: u32, handle: u32 };
    const Noop = struct {
        fn go(_: void, _: Filter, _: Instant) types.Outcome {
            return .done;
        }
    };
    const FR = Reconciler(Filter, void);
    var r = try FR.init(testing.allocator, {}, Noop.go, .{ .capacity = 4 });
    defer r.deinit();

    _ = try r.enqueue(.{ .ifindex = 2, .handle = 1 });
    _ = try r.enqueueAfter(.{ .ifindex = 2, .handle = 2 }, 0, 500);
    try testing.expectEqual(@as(u32, 2), r.pending());
    try testing.expect(r.forget(.{ .ifindex = 2, .handle = 2 }));
    try testing.expectEqual(@as(u32, 1), r.pending());
    _ = r.drain(0, 10);
    try testing.expectEqual(@as(u32, 0), r.pending());
}
