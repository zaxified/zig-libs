// SPDX-License-Identifier: MIT
//! Property tests over a deterministic simulation.
//!
//! **This module is self-anchored.** There is no published test vector for a
//! reconciler and no reference binary to interop with; controller-runtime's
//! semantics are documented prose, not a wire format. So the evidence here is
//! not "byte-exact vs an oracle" — it is invariants asserted over randomized,
//! seeded, fully deterministic runs of an injected-clock simulation, plus a
//! reference *model* (a plain per-key dirty bit) that the queue must agree
//! with. SPEC.md §8 says what an external anchor would have to be, and why
//! none exists.
//!
//! Everything below is reproducible: fixed seeds, no wall clock, no threads.

const std = @import("std");
const types = @import("types.zig");
const queue = @import("queue.zig");
const reconciler = @import("reconciler.zig");

const testing = std.testing;
const Instant = types.Instant;

const key_space = 24;

/// The system under test's world: counts calls per key and can be scripted.
const Sim = struct {
    calls: [key_space]u32 = @splat(0),
    last_call_at: [key_space]?Instant = @splat(null),
    order: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    outcome: types.Outcome = .done,

    fn deinit(self: *Sim) void {
        self.order.deinit(self.gpa);
    }

    fn reconcile(self: *Sim, key: u8, now: Instant) types.Outcome {
        self.calls[key] += 1;
        self.last_call_at[key] = now;
        self.order.append(self.gpa, key) catch @panic("OOM");
        return self.outcome;
    }
};

const SimReconciler = reconciler.Reconciler(u8, *Sim);

// ── P1: nothing lost, nothing duplicated ────────────────────────────────────

test "PROPERTY: one reconcile per enqueue burst, over random enqueue/tick interleavings" {
    var seed: u64 = 0;
    while (seed < 64) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();

        var sim: Sim = .{ .gpa = testing.allocator };
        defer sim.deinit();
        var r = try SimReconciler.init(testing.allocator, &sim, Sim.reconcile, .{
            .capacity = key_space,
            .budget_per_tick = rnd.uintLessThan(u32, 4), // 0..3, 0 = unlimited
        });
        defer r.deinit();

        // The reference model: one dirty bit per key. An enqueue sets it; a
        // reconcile clears it. A "burst" is a false->true transition, and the
        // guarantee under test is reconciles == bursts.
        var dirty: [key_space]bool = @splat(false);
        var bursts: u64 = 0;
        var enqueues: u64 = 0;
        var last_enqueue_at: [key_space]?Instant = @splat(null);

        var now: Instant = 0;
        var step: usize = 0;
        while (step < 400) : (step += 1) {
            now += rnd.uintLessThan(u64, 5);
            switch (rnd.uintLessThan(u8, 3)) {
                0, 1 => {
                    const k: u8 = @intCast(rnd.uintLessThan(u32, key_space));
                    if (!dirty[k]) bursts += 1;
                    dirty[k] = true;
                    last_enqueue_at[k] = now;
                    enqueues += 1;
                    _ = try r.enqueue(k);
                },
                else => {
                    const before = sim.order.items.len;
                    _ = r.tick(now);
                    for (sim.order.items[before..]) |k| dirty[k] = false;
                },
            }
        }
        // Quiesce.
        const end = r.drain(now, 1_000);
        for (sim.order.items) |k| dirty[k] = false;

        var total: u64 = 0;
        for (sim.calls) |c| total += c;

        // Exactly one reconcile per burst: nothing lost, nothing duplicated.
        try testing.expectEqual(bursts, total);
        // Dedup can only ever reduce work.
        try testing.expect(total <= enqueues);
        // Nothing left behind.
        try testing.expectEqual(@as(u32, 0), r.pending());
        for (dirty) |d| try testing.expect(!d);
        // Every key that was ever enqueued was reconciled after its last
        // enqueue — a stale reconcile would not count as convergence.
        for (0..key_space) |i| {
            if (last_enqueue_at[i]) |t| {
                try testing.expect(sim.last_call_at[i] != null);
                try testing.expect(sim.last_call_at[i].? >= t);
            }
        }
        try testing.expect(end.ticks < 1_000);
        try testing.expectEqual(total, r.stats().reconciled);
    }
}

// ── P2: FIFO fairness, no starvation under a budget ─────────────────────────

test "PROPERTY: FIFO order is preserved and position p runs within ceil((p+1)/budget) ticks" {
    var budget: u32 = 1;
    while (budget <= 8) : (budget += 1) {
        var sim: Sim = .{ .gpa = testing.allocator };
        defer sim.deinit();
        var r = try SimReconciler.init(testing.allocator, &sim, Sim.reconcile, .{
            .capacity = key_space,
            .budget_per_tick = budget,
        });
        defer r.deinit();

        for (0..key_space) |i| _ = try r.enqueue(@intCast(i));

        var tick_of: [key_space]?u32 = @splat(null);
        var t: u32 = 0;
        while (r.pending() > 0) : (t += 1) {
            const before = sim.order.items.len;
            const report = r.tick(t);
            try testing.expect(report.reconciled <= budget);
            for (sim.order.items[before..]) |k| tick_of[k] = t;
            try testing.expect(t < 100); // liveness: it must terminate
        }

        // FIFO: reconcile order == enqueue order.
        for (sim.order.items, 0..) |k, i| try testing.expectEqual(@as(u8, @intCast(i)), k);
        // No starvation: an explicit per-position bound.
        for (0..key_space) |p| {
            const bound: u32 = @intCast((p + budget) / budget - 1);
            try testing.expectEqual(bound, tick_of[p].?);
        }
    }
}

test "PROPERTY: a key re-announced every tick cannot starve a key enqueued once" {
    var sim: Sim = .{ .gpa = testing.allocator };
    defer sim.deinit();
    var r = try SimReconciler.init(testing.allocator, &sim, Sim.reconcile, .{
        .capacity = key_space,
        .budget_per_tick = 1,
    });
    defer r.deinit();

    _ = try r.enqueue(0); // the greedy key
    _ = try r.enqueue(1); // the quiet one, behind it

    var t: Instant = 0;
    while (t < 10) : (t += 1) {
        _ = try r.enqueue(0); // re-announce every tick
        _ = r.tick(t);
    }
    // The greedy key does not hold the head of the FIFO: it goes to the tail
    // each time it is re-admitted, so key 1 ran on the second tick.
    try testing.expect(sim.calls[1] >= 1);
    try testing.expectEqual(@as(u8, 0), sim.order.items[0]);
    try testing.expectEqual(@as(u8, 1), sim.order.items[1]);
}

// ── P3: backoff is monotone, capped, and reset by success ───────────────────

test "PROPERTY: un-jittered backoff is non-decreasing and never exceeds the cap" {
    const Failer = struct {
        fn go(_: void, _: u8, _: Instant) types.Outcome {
            return .{ .failed = error.Nope };
        }
    };
    const FR = reconciler.Reconciler(u8, void);

    var base: u64 = 1;
    while (base <= 32) : (base *= 2) {
        const cap: u64 = base * 9;
        var r = try FR.init(testing.allocator, {}, Failer.go, .{
            .capacity = 2,
            .backoff = .{ .base_delay_ms = base, .factor = 2.0, .max_delay_ms = cap, .jitter = .none },
        });
        defer r.deinit();

        _ = try r.enqueue(0);
        var now: Instant = 0;
        var prev: u64 = 0;
        var i: usize = 0;
        while (i < 30) : (i += 1) {
            _ = r.tick(now);
            const due = r.nextDue(now).?;
            const delay_ms = (due - now) / std.time.ns_per_ms;
            try testing.expect(delay_ms >= prev); // monotone
            try testing.expect(delay_ms <= cap); // capped
            if (i == 0) try testing.expectEqual(base, delay_ms);
            prev = delay_ms;
            now = due;
        }
        try testing.expectEqual(cap, prev); // it really reaches the cap
    }
}

test "PROPERTY: jittered backoff stays inside [0, cap] for every seed" {
    const Failer = struct {
        fn go(_: void, _: u8, _: Instant) types.Outcome {
            return .{ .failed = error.Nope };
        }
    };
    const FR = reconciler.Reconciler(u8, void);

    var seed: u64 = 0;
    while (seed < 32) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const cap: u64 = 1_000;
        var r = try FR.init(testing.allocator, {}, Failer.go, .{
            .capacity = 2,
            .backoff = .{ .base_delay_ms = 1, .factor = 2.0, .max_delay_ms = cap, .jitter = .full },
            .random = prng.random(),
        });
        defer r.deinit();

        _ = try r.enqueue(0);
        var now: Instant = 0;
        var i: usize = 0;
        var saw_below_cap = false;
        while (i < 40) : (i += 1) {
            _ = r.tick(now);
            const due = r.nextDue(now).?;
            const delay_ms = (due - now) / std.time.ns_per_ms;
            try testing.expect(delay_ms <= cap);
            if (i > 20 and delay_ms < cap) saw_below_cap = true;
            now = due + 1;
        }
        // Jitter is actually doing something: deep into the schedule the
        // un-jittered value would be pinned at the cap every time.
        try testing.expect(saw_below_cap);
    }
}

test "PROPERTY: a success resets the streak wherever it lands in the schedule" {
    const Scripted = struct {
        fail: bool = true,
        fn go(ctx: *@This(), _: u8, _: Instant) types.Outcome {
            return if (ctx.fail) .{ .failed = error.Nope } else .done;
        }
    };
    const SR = reconciler.Reconciler(u8, *Scripted);

    var fails_before_success: u32 = 1;
    while (fails_before_success <= 10) : (fails_before_success += 1) {
        var s: Scripted = .{};
        var r = try SR.init(testing.allocator, &s, Scripted.go, .{
            .capacity = 2,
            .backoff = .{ .base_delay_ms = 1, .factor = 2.0, .max_delay_ms = 64, .jitter = .none },
        });
        defer r.deinit();

        _ = try r.enqueue(0);
        var now: Instant = 0;
        var i: u32 = 0;
        while (i < fails_before_success) : (i += 1) {
            _ = r.tick(now);
            now = r.nextDue(now).?;
        }
        try testing.expectEqual(@as(?u32, fails_before_success), r.failuresOf(0));

        s.fail = false;
        _ = r.tick(now);
        try testing.expectEqual(@as(u32, 0), r.pending()); // converged, forgotten

        s.fail = true;
        _ = try r.enqueue(0);
        _ = r.tick(now);
        // Back to the base delay, not to where the old streak left off.
        try testing.expectEqual(@as(u64, 1), (r.nextDue(now).? - now) / std.time.ns_per_ms);
    }
}

// ── P4: the bound holds under a storm ───────────────────────────────────────

test "PROPERTY: tracked keys never exceed capacity, and overflow is loud, not silent" {
    const capacity: u32 = 8;
    var prng = std.Random.DefaultPrng.init(0xB0A7);
    const rnd = prng.random();

    var sim: Sim = .{ .gpa = testing.allocator };
    defer sim.deinit();
    var r = try SimReconciler.init(testing.allocator, &sim, Sim.reconcile, .{
        .capacity = capacity,
        .budget_per_tick = 1,
        .backoff = .{ .base_delay_ms = 1, .max_delay_ms = 4, .jitter = .none },
    });
    defer r.deinit();
    sim.outcome = .{ .failed = error.Nope }; // nothing ever converges: worst case

    var rejected: u64 = 0;
    var now: Instant = 0;
    var step: usize = 0;
    while (step < 20_000) : (step += 1) {
        now += rnd.uintLessThan(u64, 3) * std.time.ns_per_ms;
        const k: u8 = @intCast(rnd.uintLessThan(u32, key_space));
        if (rnd.boolean()) {
            if (r.enqueue(k)) |_| {} else |e| {
                try testing.expectEqual(types.Error.AtCapacity, e);
                rejected += 1;
            }
        } else {
            if (r.enqueueAfter(k, now, rnd.uintLessThan(u64, 10))) |_| {} else |_| {
                rejected += 1;
            }
        }
        if (rnd.uintLessThan(u8, 4) == 0) _ = r.tick(now);
        try testing.expect(r.pending() <= capacity);
    }

    // key_space (24) > capacity (8) and nothing converges, so rejection is
    // guaranteed — and it is visible, never silent.
    try testing.expect(rejected > 0);
    try testing.expectEqual(rejected, r.stats().rejected);
    try testing.expect(r.stats().overflowed);
    try testing.expect(r.pending() <= capacity);
}

test "PROPERTY: after overflow, a ROTATING resync re-admits everything that was refused" {
    // The recovery story for a bounded queue in a LEVEL-triggered controller:
    // the caller owns desired state, so it can always re-enumerate. This is
    // what makes rejecting (rather than evicting) safe.
    //
    // ⚠ It only works if the resync ROTATES. A caller that re-enumerates its
    // desired set from index 0 every round re-admits the same head keys every
    // time and starves the tail forever — the queue is full precisely when the
    // enumeration reaches the tail. That is a real property of any bounded
    // admission queue, and it is the caller's obligation, so it is asserted
    // here rather than only mentioned: the loop below resumes from the key
    // that was refused. See README "Overflow".
    const capacity: u32 = 4;
    var sim: Sim = .{ .gpa = testing.allocator };
    defer sim.deinit();
    var r = try SimReconciler.init(testing.allocator, &sim, Sim.reconcile, .{ .capacity = capacity });
    defer r.deinit();

    for (0..12) |i| {
        if (r.enqueue(@intCast(i))) |_| {} else |_| {}
    }
    try testing.expect(r.stats().overflowed);

    var now: Instant = 0;
    var guard: usize = 0;
    var cursor: usize = 0;
    while (guard < 100) : (guard += 1) {
        _ = r.tick(now);
        now += 1;
        // Resync from a rotating cursor, resuming where admission last failed.
        var n: usize = 0;
        while (n < 12) : (n += 1) {
            const i = (cursor + n) % 12;
            if (r.enqueue(@intCast(i))) |_| {} else |_| {
                cursor = i;
                break;
            }
        }
        if (n == 12) cursor = 0;
        var all_seen = true;
        for (0..12) |i| if (sim.calls[i] == 0) {
            all_seen = false;
        };
        if (all_seen) break;
    }
    for (0..12) |i| try testing.expect(sim.calls[i] > 0);
    r.clearOverflow();
    try testing.expect(!r.stats().overflowed);
}

// ── P5: no allocation after init ────────────────────────────────────────────

test "PROPERTY: the steady-state loop allocates nothing" {
    var sim: Sim = .{ .gpa = testing.allocator };
    defer sim.deinit();
    // Pre-grow the recorder so its own appends do not allocate during the run.
    try sim.order.ensureTotalCapacity(testing.allocator, 100_000);

    var r = try SimReconciler.init(testing.allocator, &sim, Sim.reconcile, .{
        .capacity = key_space,
        .budget_per_tick = 3,
        .backoff = .{ .base_delay_ms = 1, .max_delay_ms = 8, .jitter = .none },
    });
    defer r.deinit();

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    r.q.gpa = failing.allocator();

    var prng = std.Random.DefaultPrng.init(99);
    const rnd = prng.random();
    var now: Instant = 0;
    var step: usize = 0;
    while (step < 20_000) : (step += 1) {
        now += rnd.uintLessThan(u64, 2) * std.time.ns_per_ms;
        sim.outcome = if (rnd.uintLessThan(u8, 4) == 0) .{ .failed = error.Nope } else .done;
        const k: u8 = @intCast(rnd.uintLessThan(u32, key_space));
        if (r.enqueue(k)) |_| {} else |_| {}
        if (rnd.boolean()) {
            if (r.enqueueAfter(k, now, rnd.uintLessThan(u64, 5))) |_| {} else |_| {}
        }
        _ = r.tick(now);
    }
    try testing.expectEqual(@as(usize, 0), failing.allocations);
    try testing.expect(r.stats().reconciled > 1_000);

    r.q.gpa = testing.allocator; // restore for deinit
}

// ── P6: the queue agrees with a naive model of itself ───────────────────────

test "PROPERTY: WorkQueue matches a brute-force model of (ready set, timer map)" {
    const Q = queue.WorkQueue(u8);
    var prng = std.Random.DefaultPrng.init(0xFEED);
    const rnd = prng.random();

    var run: usize = 0;
    while (run < 32) : (run += 1) {
        var q = try Q.init(testing.allocator, key_space);
        defer q.deinit();

        // Model: per key, either absent, ready (with a FIFO sequence), or
        // waiting at a deadline.
        const Model = struct { state: enum { absent, ready, waiting }, due: u64, seq: u64 };
        var model: [key_space]Model = @splat(.{ .state = .absent, .due = 0, .seq = 0 });
        var seq: u64 = 0;

        var now: Instant = 0;
        var step: usize = 0;
        while (step < 300) : (step += 1) {
            now += rnd.uintLessThan(u64, 4);
            const k: u8 = @intCast(rnd.uintLessThan(u32, key_space));
            switch (rnd.uintLessThan(u8, 4)) {
                0 => {
                    _ = try q.enqueue(k);
                    if (model[k].state != .ready) {
                        seq += 1;
                        model[k] = .{ .state = .ready, .due = 0, .seq = seq };
                    }
                },
                1 => {
                    const d = rnd.uintLessThan(u64, 20);
                    _ = try q.enqueueAfter(k, now, d);
                    switch (model[k].state) {
                        .absent => {
                            seq += 1;
                            model[k] = .{ .state = .waiting, .due = now + d, .seq = seq };
                        },
                        .waiting => if (now + d < model[k].due) {
                            seq += 1;
                            model[k] = .{ .state = .waiting, .due = now + d, .seq = seq };
                        },
                        .ready => {},
                    }
                },
                2 => {
                    _ = q.forget(k);
                    model[k] = .{ .state = .absent, .due = 0, .seq = 0 };
                },
                else => {
                    // Promote + drain everything ready, exactly as the model does.
                    _ = q.promoteDue(now);
                    // The queue releases timers in (due, seq) order, so the
                    // model must too — otherwise the FIFO comparison below
                    // would be comparing against a different ordering.
                    var due_keys: [key_space]u8 = undefined;
                    var n_due: usize = 0;
                    for (model, 0..) |m, i| {
                        if (m.state == .waiting and m.due <= now) {
                            due_keys[n_due] = @intCast(i);
                            n_due += 1;
                        }
                    }
                    const Cmp = struct {
                        fn less(ctx: *const [key_space]Model, a: u8, b: u8) bool {
                            if (ctx[a].due != ctx[b].due) return ctx[a].due < ctx[b].due;
                            return ctx[a].seq < ctx[b].seq;
                        }
                    };
                    std.mem.sort(u8, due_keys[0..n_due], &model, Cmp.less);
                    for (due_keys[0..n_due]) |dk| {
                        seq += 1;
                        model[dk] = .{ .state = .ready, .due = 0, .seq = seq };
                    }
                    while (q.takeReady()) |idx| {
                        const got = q.slotKey(idx);
                        // The model's head is the smallest ready seq.
                        var best: ?u8 = null;
                        for (model, 0..) |m, i| {
                            if (m.state != .ready) continue;
                            if (best == null or m.seq < model[best.?].seq) best = @intCast(i);
                        }
                        try testing.expectEqual(best.?, got);
                        model[got] = .{ .state = .absent, .due = 0, .seq = 0 };
                        q.finish(idx, now, .drop);
                    }
                },
            }
            q.assertInvariants();

            // The model and the queue agree on membership and state.
            var expect_tracked: u32 = 0;
            for (model, 0..) |m, i| {
                const key: u8 = @intCast(i);
                switch (m.state) {
                    .absent => try testing.expect(!q.contains(key)),
                    .ready => {
                        try testing.expectEqual(Q.State.ready, q.stateOf(key).?);
                        expect_tracked += 1;
                    },
                    .waiting => {
                        try testing.expectEqual(Q.State.waiting, q.stateOf(key).?);
                        expect_tracked += 1;
                    },
                }
            }
            try testing.expectEqual(expect_tracked, q.tracked);
        }
    }
}
