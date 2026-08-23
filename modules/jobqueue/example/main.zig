// SPDX-License-Identifier: MIT

//! What a background-worker consumer does with `jobqueue`: open a queue over
//! `kv`, enqueue a realistic mixed workload (several partitions, priorities,
//! a delayed job), dispatch it in priority/FIFO order, reject a duplicate
//! ack, ride a lease past its visibility timeout and watch the caller-driven
//! reaper requeue it with a bumped attempt count, drive one job through its
//! full `max_attempts` via `nack` backoff to the dead-letter queue, hit the
//! payload/field size caps, and finally close and reopen the queue over the
//! same store to prove the durable record of truth survives a "crash" with
//! one job leased-but-unacked.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. It also runs under a leak-checking
//! allocator, so it is a leak detector for the whole lifecycle below, not
//! just for one call each.

const std = @import("std");
const jobqueue = @import("jobqueue");
const kv = @import("kv");

/// A controllable wall clock (Unix-epoch nanoseconds), injected so the
/// schedule-driven paths (`delay_ns`/`run_at`/`nack` backoff visibility) are
/// deterministic — this module has no way to read the system clock from
/// outside its `Options.wall_clock` seam, which is exactly the point.
const FakeWall = struct {
    ns: i64 = 1_700_000_000 * std.time.ns_per_s, // a plausible non-zero epoch

    fn clock(self: *FakeWall) jobqueue.WallClock {
        return .{ .ctx = self, .nowFn = now };
    }
    fn now(ctx: ?*anyopaque) i64 {
        const self: *FakeWall = @ptrCast(@alignCast(ctx.?));
        return self.ns;
    }
    fn advance(self: *FakeWall, ns: u64) void {
        self.ns += @intCast(ns);
    }
};

/// A controllable monotonic clock (ns), injected so lease-expiry is
/// deterministic.
const FakeMono = struct {
    ns: u64 = 0,

    fn clock(self: *FakeMono) jobqueue.MonoClock {
        return .{ .ctx = self, .nowFn = now };
    }
    fn now(ctx: ?*anyopaque) u64 {
        const self: *FakeMono = @ptrCast(@alignCast(ctx.?));
        return self.ns;
    }
    fn advance(self: *FakeMono, ns: u64) void {
        self.ns += ns;
    }
};

const ms = std.time.ns_per_ms;
const s = std.time.ns_per_s;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();

    var wall: FakeWall = .{};
    var mono: FakeMono = .{};

    var q = try jobqueue.Queue.open(gpa, sim.storage(), "jobs.jq", .{
        .wall_clock = wall.clock(),
        .mono_clock = mono.clock(),
        .max_payload = 64,
    });
    defer q.close();

    // A realistic mixed workload: three partitions, three priorities, and
    // one job scheduled 30s into the future.
    {
        _ = try q.enqueue("email.send", "to:alice", .{ .partition = "email" });
        _ = try q.enqueue("email.send", "to:bob", .{ .partition = "email" });
        _ = try q.enqueue("report.build", "q3", .{ .partition = "reports", .priority = .low });
        _ = try q.enqueue("alert.page", "disk-full", .{ .priority = .critical });
        _ = try q.enqueue("email.send", "to:carol", .{ .partition = "email", .delay_ns = 30 * s });
        std.debug.assert(q.readyCount() == 5);
        std.debug.assert(q.totalCount() == 5);
        std.debug.print("enqueued 5 jobs across 3 partitions, one scheduled 30s out\n", .{});
    }

    // Dispatch order: an unfiltered dequeue picks the globally best job —
    // the critical alert jumps every partition's FIFO — then a
    // partition-filtered dequeue folds "email" in enqueue order.
    {
        const critical = (try q.dequeue(.{ .visibility_timeout_ns = 5 * s })).?;
        std.debug.assert(std.mem.eql(u8, critical.job_type, "alert.page"));
        try q.ack(critical);

        const alice = (try q.dequeue(.{ .partition = "email", .visibility_timeout_ns = 5 * s })).?;
        std.debug.assert(std.mem.eql(u8, alice.payload, "to:alice"));
        try q.ack(alice);
        std.debug.print("critical job dispatched ahead of FIFO, then partition FIFO honored\n", .{});
    }

    // Retried/duplicate operation: acking the same lease twice is rejected
    // by name, not silently accepted as a no-op.
    {
        const bob = (try q.dequeue(.{ .partition = "email", .visibility_timeout_ns = 5 * s })).?;
        try q.ack(bob);
        if (q.ack(bob)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.StaleLease => std.debug.print("double-ack correctly rejected: StaleLease\n", .{}),
            else => return err,
        }
    }

    // Scheduled visibility: the delayed "to:carol" stays invisible even
    // though it is the only thing left in "email", until the wall clock
    // reaches its schedule.
    {
        std.debug.assert((try q.dequeue(.{ .partition = "email", .visibility_timeout_ns = 5 * s })) == null);
        wall.advance(30 * s);
        const carol = (try q.dequeue(.{ .partition = "email", .visibility_timeout_ns = 5 * s })).?;
        std.debug.assert(std.mem.eql(u8, carol.payload, "to:carol"));
        try q.ack(carol);
        std.debug.print("delayed job stayed invisible until its schedule, then dispatched\n", .{});
    }

    // Lease-timeout expiry (an abandoned worker): lease the last job, let
    // its visibility timeout lapse without ack/nack, and sweep it back with
    // the caller-driven reaper. The attempt count bumps and the old lease
    // can no longer touch the job.
    {
        const lease1 = (try q.dequeue(.{ .visibility_timeout_ns = 10 * ms })).?;
        std.debug.assert(std.mem.eql(u8, lease1.job_type, "report.build"));
        std.debug.assert(lease1.attempt == 1);
        std.debug.assert(q.leasedCount() == 1);

        mono.advance(11 * ms);
        std.debug.assert(try q.reapExpiredLeases() == 1);
        std.debug.assert(q.leasedCount() == 0);
        std.debug.assert(q.readyCount() == 1);

        if (q.ack(lease1)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.StaleLease => std.debug.print("reaped lease can no longer ack: StaleLease\n", .{}),
            else => return err,
        }

        const lease2 = (try q.dequeue(.{ .visibility_timeout_ns = 5 * s })).?;
        std.debug.assert(lease2.attempt == 2); // second delivery, bumped by the reaper
        try q.ack(lease2);
        std.debug.print("lease-timeout sweep requeued the job with a bumped attempt count\n", .{});
    }

    // Retry-with-backoff to dead-letter: drive one job through its full
    // max_attempts via explicit nack, checking the backoff actually gates
    // redelivery in between, then confirm the DLQ snapshot.
    {
        _ = try q.enqueue("flaky.job", "boom", .{ .max_attempts = 3 });

        var attempt: u32 = 1;
        while (attempt <= 3) : (attempt += 1) {
            const lease = (try q.dequeue(.{ .visibility_timeout_ns = 5 * s })).?;
            std.debug.assert(lease.attempt == attempt);
            try q.nack(lease, .{ .backoff_ns = 20 * ms });
            if (attempt < 3) {
                // Backoff not elapsed yet: not redispatchable until it is.
                std.debug.assert((try q.dequeue(.{ .visibility_timeout_ns = 5 * s })) == null);
                wall.advance(20 * ms);
            }
        }

        std.debug.assert(q.deadLetterCount() == 1);
        std.debug.assert(q.readyCount() == 0);
        std.debug.assert((try q.dequeue(.{ .visibility_timeout_ns = 5 * s })) == null);

        const dead = try q.deadLetterList(gpa);
        defer jobqueue.Queue.freeDeadLetterList(gpa, dead);
        std.debug.assert(dead.len == 1);
        std.debug.assert(std.mem.eql(u8, dead[0].job_type, "flaky.job"));
        std.debug.assert(dead[0].attempts == 3);
        std.debug.print("job exhausted max_attempts via nack backoff and landed in the DLQ\n", .{});
    }

    // Capacity limits: the payload and field-length caps are enforced by
    // name, and a rejected enqueue leaves no partial job behind.
    {
        const before_total = q.totalCount();
        const oversized_payload = "x" ** 100; // > Options.max_payload (64)
        if (q.enqueue("t", oversized_payload, .{})) |_| {
            unreachable;
        } else |err| switch (err) {
            error.PayloadTooLarge => std.debug.print("oversized payload correctly rejected: PayloadTooLarge\n", .{}),
            else => return err,
        }
        const oversized_type = "x" ** (jobqueue.max_field_len + 1);
        if (q.enqueue(oversized_type, "ok", .{})) |_| {
            unreachable;
        } else |err| switch (err) {
            error.FieldTooLarge => std.debug.print("oversized job_type correctly rejected: FieldTooLarge\n", .{}),
            else => return err,
        }
        std.debug.assert(q.totalCount() == before_total); // rejected cleanly, no partial state
    }

    // Crash recovery: close with one job leased-but-unacked, reopen over the
    // same store, and confirm the durable record of truth wins — the acked
    // job stays gone, the unacked lease reappears ready (a lease is
    // in-memory only), and the durable id counter keeps counting.
    {
        _ = try q.enqueue("t", "will-be-acked", .{});
        const to_ack = (try q.dequeue(.{ .visibility_timeout_ns = 5 * s })).?;
        try q.ack(to_ack);

        _ = try q.enqueue("t", "will-be-orphaned", .{});
        _ = (try q.dequeue(.{ .visibility_timeout_ns = 5 * s })).?; // leased, then "the process crashes"

        q.close();
        q = try jobqueue.Queue.open(gpa, sim.storage(), "jobs.jq", .{
            .wall_clock = wall.clock(),
            .mono_clock = mono.clock(),
            .max_payload = 64,
        });

        // The earlier dead-lettered "flaky.job" is durable too (dead-lettered
        // jobs stay indexed, never deleted), so it survives recovery
        // alongside the orphan — only the acked job is actually gone.
        std.debug.assert(q.totalCount() == 2);
        std.debug.assert(q.readyCount() == 1);
        std.debug.assert(q.leasedCount() == 0); // the lease itself never persisted
        std.debug.assert(q.deadLetterCount() == 1);

        const recovered = (try q.dequeue(.{ .visibility_timeout_ns = 5 * s })).?;
        std.debug.assert(std.mem.eql(u8, recovered.payload, "will-be-orphaned"));
        try q.ack(recovered);
        std.debug.print("reopen over the same store recovered the orphaned lease, dropped the acked job\n", .{});
    }
}
