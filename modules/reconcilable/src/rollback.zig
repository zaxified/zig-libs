// SPDX-License-Identifier: MIT
//! `RollbackTimer` — arm / confirm / overdue, the "apply a change and undo it
//! unless someone confirms in N" primitive.
//!
//! This exists because of a specific failure shape: a network change that
//! breaks connectivity also breaks the channel you would use to fix it. The
//! answer the industry converged on is a *staged* change with a
//! confirm-or-revert deadline — Juniper's `commit confirmed`, Cisco IOS-XE's
//! `configure replace ... commit timeout`, `netplan try`. Apply, start a timer,
//! and if the operator (or a health probe reachable only over the very path you
//! just changed) does not confirm before the timer expires, roll back
//! automatically.
//!
//! Three deliberate semantics, all tested:
//!
//! 1. **The deadline wins.** A `confirm` that arrives at or after the deadline
//!    is REFUSED (`.too_late`) and the timer still fires. A late confirmation
//!    cannot cancel a rollback, because by then the rollback may already be
//!    in flight and the two would race to leave the device in a state neither
//!    side believes it is in. Fail closed, toward the known-good config.
//! 2. **It fires exactly once.** `poll` returns `.expired` from precisely one
//!    call; every later call reports `.rolled_back`. A rollback executed twice
//!    is not idempotent in general (the second undo may undo the recovery).
//! 3. **No clock, no thread.** Like the rest of the module, `now` is supplied.
//!    `remaining` hands the reconciler exactly the delay it should sleep for,
//!    which is the whole integration surface — this file imports nothing from
//!    the reconciler, so it stays a movable 100 lines.
//!
//! Why it lives here rather than in its own module: see SPEC.md §7.

const std = @import("std");
const types = @import("types.zig");

const Instant = types.Instant;

pub const RollbackTimer = struct {
    pub const State = enum {
        /// Never armed, or reset.
        idle,
        /// A change is staged and unconfirmed.
        armed,
        /// Confirmed strictly before the deadline — the change is permanent.
        confirmed,
        /// The deadline passed unconfirmed and `poll` has reported it. The
        /// caller owns performing the actual rollback.
        rolled_back,
    };

    pub const Confirm = enum {
        /// Accepted: the staged change is now permanent.
        committed,
        /// The deadline had already passed. The rollback stands.
        too_late,
        /// Nothing was armed.
        not_armed,
    };

    pub const Status = enum {
        idle,
        /// Armed and still within the window.
        armed,
        /// **Roll back now.** Returned by exactly one `poll` call per arming.
        expired,
        confirmed,
        /// Already reported expired; the caller has been told.
        rolled_back,
    };

    state: State = .idle,
    armed_at: Instant = 0,
    deadline: Instant = 0,
    /// Increments on every `arm`. Lets a caller correlate an out-of-band
    /// confirmation with the arming it belongs to (a confirmation for
    /// generation 3 arriving after generation 4 was armed is stale).
    generation: u32 = 0,

    pub const idle: RollbackTimer = .{};

    /// Stage a change: confirm before `now + timeout_ns` or it will expire.
    /// Legal from any state — re-arming supersedes whatever came before.
    pub fn arm(t: *RollbackTimer, now: Instant, timeout_ns: u64) u32 {
        t.state = .armed;
        t.armed_at = now;
        t.deadline = now +| timeout_ns;
        t.generation +%= 1;
        return t.generation;
    }

    /// Confirm the staged change. Succeeds only while `now < deadline`.
    pub fn confirm(t: *RollbackTimer, now: Instant) Confirm {
        if (t.state != .armed) return .not_armed;
        if (now >= t.deadline) return .too_late;
        t.state = .confirmed;
        return .committed;
    }

    /// As `confirm`, but refuses a confirmation belonging to an earlier arming.
    pub fn confirmGeneration(t: *RollbackTimer, now: Instant, gen: u32) Confirm {
        if (gen != t.generation) return .not_armed;
        return t.confirm(now);
    }

    /// Ask what to do at `now`. The only state-advancing observation: an armed
    /// timer whose deadline has arrived transitions to `.rolled_back` and
    /// returns `.expired` — once.
    pub fn poll(t: *RollbackTimer, now: Instant) Status {
        return switch (t.state) {
            .idle => .idle,
            .confirmed => .confirmed,
            .rolled_back => .rolled_back,
            .armed => blk: {
                if (now < t.deadline) break :blk .armed;
                t.state = .rolled_back;
                break :blk .expired;
            },
        };
    }

    /// Nanoseconds left in the window, or null when nothing is pending. Hand
    /// this to `Outcome.requeue_after` so the reconciler wakes exactly at the
    /// deadline and not a tick later.
    pub fn remaining(t: *const RollbackTimer, now: Instant) ?u64 {
        if (t.state != .armed) return null;
        return if (now >= t.deadline) 0 else t.deadline - now;
    }

    /// Drop back to `.idle` (e.g. after the caller has executed the rollback).
    pub fn reset(t: *RollbackTimer) void {
        t.state = .idle;
        t.armed_at = 0;
        t.deadline = 0;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "armed timer fires at the deadline, exactly once" {
    var t: RollbackTimer = .idle;
    try testing.expectEqual(RollbackTimer.Status.idle, t.poll(0));

    _ = t.arm(100, 50); // deadline 150
    try testing.expectEqual(RollbackTimer.Status.armed, t.poll(100));
    try testing.expectEqual(RollbackTimer.Status.armed, t.poll(149));
    try testing.expectEqual(RollbackTimer.Status.expired, t.poll(150));
    try testing.expectEqual(RollbackTimer.Status.rolled_back, t.poll(150));
    try testing.expectEqual(RollbackTimer.Status.rolled_back, t.poll(1_000_000));
}

test "confirm inside the window commits and cancels the fire" {
    var t: RollbackTimer = .idle;
    _ = t.arm(0, 100);
    try testing.expectEqual(RollbackTimer.Confirm.committed, t.confirm(99));
    try testing.expectEqual(RollbackTimer.Status.confirmed, t.poll(1_000));
    try testing.expectEqual(RollbackTimer.Confirm.not_armed, t.confirm(1_000));
}

test "a confirmation at or after the deadline is REFUSED and the timer still fires" {
    // The safety property: a late confirm must not cancel a rollback that may
    // already be executing. Fail closed toward the known-good config.
    var t: RollbackTimer = .idle;
    _ = t.arm(0, 100);
    try testing.expectEqual(RollbackTimer.Confirm.too_late, t.confirm(100));
    try testing.expectEqual(RollbackTimer.Confirm.too_late, t.confirm(500));
    try testing.expectEqual(RollbackTimer.Status.expired, t.poll(500));
}

test "generation guards a stale out-of-band confirmation" {
    var t: RollbackTimer = .idle;
    const g1 = t.arm(0, 100);
    const g2 = t.arm(10, 100); // superseded before g1 was confirmed
    try testing.expect(g1 != g2);
    try testing.expectEqual(RollbackTimer.Confirm.not_armed, t.confirmGeneration(20, g1));
    try testing.expectEqual(RollbackTimer.Confirm.committed, t.confirmGeneration(20, g2));
}

test "remaining feeds requeue_after and saturates at the deadline" {
    var t: RollbackTimer = .idle;
    try testing.expectEqual(@as(?u64, null), t.remaining(0));
    _ = t.arm(1_000, 250);
    try testing.expectEqual(@as(?u64, 250), t.remaining(1_000));
    try testing.expectEqual(@as(?u64, 1), t.remaining(1_249));
    try testing.expectEqual(@as(?u64, 0), t.remaining(1_250));
    try testing.expectEqual(@as(?u64, 0), t.remaining(9_999));
    // Past the deadline the confirmation is refused and the timer still fires.
    try testing.expectEqual(RollbackTimer.Confirm.too_late, t.confirm(1_300));
    try testing.expectEqual(RollbackTimer.Status.expired, t.poll(2_000));
    try testing.expectEqual(@as(?u64, null), t.remaining(2_000));
}

test "arming saturates instead of wrapping" {
    var t: RollbackTimer = .idle;
    _ = t.arm(std.math.maxInt(Instant) - 5, 1_000);
    try testing.expectEqual(@as(Instant, std.math.maxInt(Instant)), t.deadline);
    try testing.expectEqual(RollbackTimer.Status.armed, t.poll(std.math.maxInt(Instant) - 1));
    try testing.expectEqual(RollbackTimer.Status.expired, t.poll(std.math.maxInt(Instant)));
}

test "re-arm supersedes an expired timer" {
    var t: RollbackTimer = .idle;
    _ = t.arm(0, 10);
    try testing.expectEqual(RollbackTimer.Status.expired, t.poll(10));
    _ = t.arm(20, 10);
    try testing.expectEqual(RollbackTimer.Status.armed, t.poll(25));
    try testing.expectEqual(RollbackTimer.Confirm.committed, t.confirm(29));
}

test "PROPERTY: over random interleavings, expired fires exactly once iff never confirmed in time" {
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const rnd = prng.random();

    var round: usize = 0;
    while (round < 20_000) : (round += 1) {
        var t: RollbackTimer = .idle;
        const start: Instant = rnd.uintLessThan(u64, 1_000);
        const window: u64 = rnd.uintLessThan(u64, 100) + 1;
        _ = t.arm(start, window);
        const deadline = start + window;

        var confirmed_in_time = false;
        var expired_count: u32 = 0;
        var now = start;

        var step: usize = 0;
        while (step < 12) : (step += 1) {
            now += rnd.uintLessThan(u64, 30);
            if (rnd.boolean()) {
                // Full characterisation of `confirm`: the result is a pure
                // function of (was armed, is before the deadline).
                const was_armed = t.state == .armed;
                const before = now < deadline;
                const res = t.confirm(now);
                switch (res) {
                    .committed => {
                        try testing.expect(was_armed and before);
                        confirmed_in_time = true;
                    },
                    .too_late => try testing.expect(was_armed and !before),
                    .not_armed => try testing.expect(!was_armed),
                }
            } else {
                const st = t.poll(now);
                if (st == .expired) {
                    expired_count += 1;
                    // Never before the deadline.
                    try testing.expect(now >= deadline);
                    try testing.expect(!confirmed_in_time);
                }
            }
        }
        // Drive it well past the deadline so the outcome is decided.
        const st = t.poll(deadline + 10_000);
        if (st == .expired) expired_count += 1;

        if (confirmed_in_time) {
            try testing.expectEqual(@as(u32, 0), expired_count);
            try testing.expectEqual(RollbackTimer.State.confirmed, t.state);
        } else {
            try testing.expectEqual(@as(u32, 1), expired_count);
            try testing.expectEqual(RollbackTimer.State.rolled_back, t.state);
        }
    }
}
