// SPDX-License-Identifier: MIT

//! What a consumer does with `reconcilable`: converge a small set of DNS
//! records toward a desired state, tolerating a transiently-unavailable
//! upstream (backoff, no retry logic to write), and stage a riskier change
//! behind `RollbackTimer` — the "commit confirmed" pattern (Junos, IOS-XR)
//! the module names in its own doc comment.
//!
//! Built against the PUBLISHED module (`@import("reconcilable")`) only.

const std = @import("std");
const reconcilable = @import("reconcilable");

const Record = struct {
    desired_ip: u32,
    live_ip: u32 = 0,
    /// The simulated upstream API refuses writes before this instant — a
    /// transient failure `reconcilable`'s own backoff absorbs; nothing here
    /// implements retry by hand.
    upstream_flaky_until: u32 = 0,
    applies: u32 = 0,
};

/// A change staged behind a confirm-or-revert deadline: applied immediately,
/// but only permanent if something confirms it before the timer fires.
const RiskyChange = struct {
    applied: bool = false,
    reverted: bool = false,
    timer: reconcilable.RollbackTimer = .idle,
};

const World = struct {
    records: [2]Record,
    /// [0] gets health-confirmed in time; [1] never does and reverts.
    risky: [2]RiskyChange = .{ .{}, .{} },

    fn reconcile(w: *World, key: u8, now: reconcilable.Instant) reconcilable.Outcome {
        return switch (key) {
            0, 1 => w.reconcileRecord(key, now),
            2, 3 => w.reconcileRisky(key - 2, now),
            else => unreachable,
        };
    }

    fn reconcileRecord(w: *World, key: u8, now: reconcilable.Instant) reconcilable.Outcome {
        const r = &w.records[key];
        if (now < r.upstream_flaky_until)
            return .{ .failed = error.UpstreamUnavailable };
        r.live_ip = r.desired_ip;
        r.applies += 1;
        return .done;
    }

    fn reconcileRisky(w: *World, idx: u8, now: reconcilable.Instant) reconcilable.Outcome {
        const rc = &w.risky[idx];
        if (!rc.applied) {
            rc.applied = true;
            _ = rc.timer.arm(now, 20); // must be confirmed within 20 ticks
        }
        return switch (rc.timer.poll(now)) {
            .armed => .{ .requeue_after = rc.timer.remaining(now).? },
            .expired => blk: {
                rc.reverted = true;
                break :blk .done;
            },
            .confirmed, .idle, .rolled_back => .done,
        };
    }
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var world = World{
        .records = .{
            .{ .desired_ip = 0x0A00_0001 }, // applies on the first pass
            .{ .desired_ip = 0x0A00_0002, .upstream_flaky_until = 15 }, // retried until it lands
        },
    };

    var r = try reconcilable.Reconciler(u8, *World).init(gpa, &world, World.reconcile, .{
        .capacity = 8,
        .backoff = .{ .base_delay_ms = 2, .max_delay_ms = 8, .jitter = .none },
    });
    defer r.deinit();

    for (0..4) |k| _ = try r.enqueue(@intCast(k));

    // One tick at t=0: record 0 applies outright; record 1 hits the flaky
    // window and backs off; both risky changes apply and arm their 20-tick
    // rollback timers.
    _ = r.tick(0);
    std.debug.print("t=0: record0 applied={} risky0 applied={} risky1 applied={}\n", .{
        world.records[0].live_ip == world.records[0].desired_ip,
        world.risky[0].applied,
        world.risky[1].applied,
    });

    // An external health probe confirms risky change 0 well inside its
    // window. Confirming is NOT something the reconcile pass does on its
    // own — it is an out-of-band event — so the caller calls it directly on
    // the timer and then nudges the reconciler with `enqueue` so the next
    // pass notices before the parked `requeue_after` deadline arrives.
    _ = world.risky[0].timer.confirm(10);
    _ = try r.enqueue(2);
    _ = r.tick(10);

    // Nobody confirms risky change 1. Drain far enough (in reconcile PASSES,
    // not simulated ticks) to cross both its 20-tick deadline and record 1's
    // flaky window.
    _ = r.drain(10, 30);

    std.debug.print("risky0: reverted={} (confirmed in time)\n", .{world.risky[0].reverted});
    std.debug.print("risky1: reverted={} (nobody confirmed it)\n", .{world.risky[1].reverted});
    std.debug.print("record1: applied={} after {d} attempt(s)\n", .{
        world.records[1].live_ip == world.records[1].desired_ip,
        world.records[1].applies,
    });

    const stats = r.stats();
    std.debug.print("reconciler stats: passes={d} failed={d} pending={d}\n", .{
        stats.reconciled, stats.failed, r.pending(),
    });
}
