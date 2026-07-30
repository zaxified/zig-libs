// SPDX-License-Identifier: MIT
//! reconcilable — a generic desired-vs-actual reconciler: a bounded,
//! deduplicating work queue plus a caller-driven convergence loop, and the
//! confirm-or-revert timer that network changes need.
//!
//! The shape is Kubernetes controller-runtime's, because that is the
//! best-documented statement of the level-triggered control loop: you enqueue
//! the *identity* of something that may have diverged, an **idempotent**
//! reconcile pass compares desired with actual and applies the difference, and
//! whatever does not converge comes back later on an exponential backoff. What
//! is enqueued is never a delta, so a coalesced enqueue is not a lost change.
//!
//! ```zig
//! const reconcilable = @import("reconcilable");
//!
//! const Peer = [32]u8; // a WireGuard public key: a plain value, so it hashes
//!
//! fn reconcilePeer(world: *World, key: Peer, now: u64) reconcilable.Outcome {
//!     const want = world.desired.get(key) orelse {
//!         world.removePeer(key) catch |e| return .{ .failed = e };
//!         return .done;
//!     };
//!     const have = world.observePeer(key) catch |e| return .{ .failed = e };
//!     if (have.equals(want)) return .{ .requeue_after = 30 * std.time.ns_per_s };
//!     world.applyPeer(want) catch |e| return .{ .failed = e };
//!     return .requeue; // re-observe before declaring victory
//! }
//!
//! var r = try reconcilable.Reconciler(Peer, *World)
//!     .init(gpa, &world, reconcilePeer, .{ .capacity = 4096 });
//! defer r.deinit();
//!
//! // The caller owns the loop and the clock.
//! while (running) {
//!     const now = clock.now();
//!     const report = r.tick(now);
//!     const timeout_ms = if (r.sleepFor(now)) |ns| ns / std.time.ns_per_ms else -1;
//!     _ = try loop.poll(timeout_ms); // events call r.enqueue(...)
//!     _ = report;
//! }
//! ```
//!
//! No thread, no clock, no allocation after `init` — see SPEC.md.

const std = @import("std");

pub const meta = .{
    // No syscall, no clock, no thread: `tick` is handed the instant. The
    // `resilience` dep is used only for its pure `Retry`/`Jitter` value types.
    .platform = .any,
    .role = .util,
    // One owner drives enqueue/tick; the reconcile pass may re-enter the same
    // reconciler, but nothing here is internally synchronized.
    .concurrency = .single_owner,
    .model_after = "Kubernetes controller-runtime (documented Reconciler/Result contract + client-go workqueue dedup & rate limiting) + Juniper `commit confirmed` / Cisco `configure replace ... commit timeout` for the rollback timer",
    .deps = .{"resilience"},
};

const types = @import("types.zig");
const queue = @import("queue.zig");
const reconciler = @import("reconciler.zig");
const rollback = @import("rollback.zig");

// ── public API ──────────────────────────────────────────────────────────────

pub const Instant = types.Instant;
pub const Outcome = types.Outcome;
pub const Admission = types.Admission;
pub const Options = types.Options;
pub const Stats = types.Stats;
pub const TickReport = types.TickReport;
pub const ErrorSink = types.ErrorSink;
pub const Error = types.Error;

/// The caller-driven convergence loop. `Key` must be a plain value type (no
/// pointers or slices — see `types.assertPlainKey`); `Ctx` is whatever the
/// reconcile function needs, typically a `*World` pointer.
pub const Reconciler = reconciler.Reconciler;

/// The bounded deduplicating work queue underneath, exposed because it is
/// useful on its own (a scheduler that is not a reconciler).
pub const WorkQueue = queue.WorkQueue;

/// Confirm-or-revert timer for changes that can sever their own control path.
pub const RollbackTimer = rollback.RollbackTimer;

// ── tests ───────────────────────────────────────────────────────────────────
//
// Aggregator: a bare `@import` re-export does NOT pull a file's tests into the
// test binary (CONVENTIONS §6.3 — the dark-tests rule). Every submodule must
// be referenced from here.

test {
    _ = types;
    _ = queue;
    _ = reconciler;
    _ = rollback;
    _ = @import("props.zig");
}

const testing = std.testing;

test "README example: converge, stay converged, recover from a failure" {
    const World = struct {
        desired: [4]u8 = .{ 1, 1, 1, 1 },
        actual: [4]u8 = .{ 0, 0, 0, 0 },
        /// Applying key 2 fails until `heal` is set — the transient-failure arm.
        heal: bool = false,
        applies: u32 = 0,

        fn reconcile(w: *@This(), key: u8, now: Instant) Outcome {
            _ = now;
            if (w.actual[key] == w.desired[key])
                return .{ .requeue_after = 10 * std.time.ns_per_ms };
            if (key == 2 and !w.heal) return .{ .failed = error.LinkDown };
            w.actual[key] = w.desired[key];
            w.applies += 1;
            return .requeue; // re-observe before declaring victory
        }
    };

    var world: World = .{};
    var r = try Reconciler(u8, *World).init(testing.allocator, &world, World.reconcile, .{
        .capacity = 8,
        .backoff = .{ .base_delay_ms = 1, .max_delay_ms = 4, .jitter = .none },
    });
    defer r.deinit();

    for (0..4) |k| _ = try r.enqueue(@intCast(k));

    // Converge everything reachable. Key 2 keeps failing and backing off.
    var end = r.drain(0, 200);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 0, 1 }, &world.actual);
    try testing.expect(r.stats().failed > 0);

    // Heal the world; the backoff timer brings key 2 back with no new enqueue.
    world.heal = true;
    end = r.drain(end.now, 200);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 1, 1 }, &world.actual);

    // Steady state: every key is parked on its own 10ms re-observe timer and
    // nothing is applied again — the idempotence contract, observed.
    const applies_after_convergence = world.applies;
    _ = r.drain(end.now, 50);
    try testing.expectEqual(applies_after_convergence, world.applies);
    try testing.expectEqual(@as(u32, 4), r.pending());
}

test "RollbackTimer drives a reconcile pass through requeue_after" {
    const Change = struct {
        timer: RollbackTimer = .idle,
        applied: bool = false,
        reverted: bool = false,
        confirm_at: ?Instant = null,

        fn reconcile(c: *@This(), key: u8, now: Instant) Outcome {
            _ = key;
            if (!c.applied) {
                c.applied = true;
                _ = c.timer.arm(now, 100); // stage: confirm within 100ns
            }
            if (c.confirm_at) |t| if (now >= t) {
                _ = c.timer.confirm(now);
            };
            return switch (c.timer.poll(now)) {
                .armed => .{ .requeue_after = c.timer.remaining(now).? },
                .expired => blk: {
                    c.reverted = true;
                    break :blk .done;
                },
                else => .done,
            };
        }
    };

    // 1. Nobody confirms — the timer expires and the change is reverted.
    {
        var c: Change = .{};
        var r = try Reconciler(u8, *Change).init(testing.allocator, &c, Change.reconcile, .{ .capacity = 2 });
        defer r.deinit();
        _ = try r.enqueue(0);
        _ = r.drain(0, 50);
        try testing.expect(c.reverted);
    }
    // 2. A confirmation lands inside the window — no revert. Note that the
    //    confirmation is an EXTERNAL event: it has to wake the loop, because
    //    `requeue_after` parks the key exactly on the deadline and nothing
    //    else would look at the timer before it expires.
    {
        var c: Change = .{ .confirm_at = 40 };
        var r = try Reconciler(u8, *Change).init(testing.allocator, &c, Change.reconcile, .{ .capacity = 2 });
        defer r.deinit();
        _ = try r.enqueue(0);
        _ = r.tick(0); // apply + arm, parked until the deadline at 100
        _ = try r.enqueue(0); // the health probe answers at t=40
        _ = r.tick(40);
        _ = r.drain(40, 50);
        try testing.expect(!c.reverted);
        try testing.expectEqual(RollbackTimer.State.confirmed, c.timer.state);
    }
}

test "meta declares the sibling deps the build wires" {
    try testing.expectEqual(@as(usize, 1), meta.deps.len);
    try testing.expectEqualStrings("resilience", meta.deps[0]);
}
