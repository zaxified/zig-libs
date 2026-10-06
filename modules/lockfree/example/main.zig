// SPDX-License-Identifier: MIT

//! What a worker-pool consumer does with `lockfree`: build the shared
//! reclamation domain, register a worker as an EBR participant, drive a
//! Michael-Scott MPMC queue through enqueue/dequeue (packed words, then a
//! record type through the generic `Queue(T)`), and tear everything down in
//! the order the module documents (queue, then pool, then domain). Then the
//! bounded ring: drop-on-full pushes and an in-place single consumer.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const lockfree = @import("lockfree");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // `lockfree.Atomic` spelled the way a consumer spells it. This is here
    // rather than in the module's own tests because only an outside caller can
    // prove the RE-EXPORT exists: the alias was public inside `atomic.zig` for
    // its whole life while `root.zig` published its four neighbours and not it,
    // so nothing in the module could tell the difference. Delete the export and
    // this file stops compiling.
    var flag = lockfree.Atomic(u32).init(0);
    if (flag.fetchAdd(7, .acq_rel) != 0 or flag.load(.acquire) != 7)
        return error.AtomicAliasMisbehaved;

    // A tight domain (one slot) so the registry-exhaustion error is easy to
    // trigger and name from outside.
    var domain = try lockfree.Domain.init(gpa, .{ .max_participants = 1 });
    defer domain.deinit();

    const worker = try domain.register();

    // The single slot is now taken: a second registration must fail by a
    // nameable error, not silently succeed or crash.
    _ = domain.register() catch |err| switch (err) {
        error.TooManyParticipants => std.debug.print("second worker correctly refused a slot\n", .{}),
    };

    const Pool = lockfree.NodePool(lockfree.Node);
    var node_pool = Pool.init(gpa);

    var queue = try lockfree.MpmcQueue.init(&node_pool, &domain);

    // Three units of work, packed as (producer_id << 32 | seq) the way a
    // real worker pool tags them for provenance.
    const producer_id: u64 = 7;
    var seq: u64 = 0;
    while (seq < 3) : (seq += 1) {
        try queue.enqueue(worker, (producer_id << 32) | seq);
    }

    std.debug.print("draining queue in FIFO order:\n", .{});
    var drained: u64 = 0;
    while (queue.dequeue(worker)) |value| {
        const pid = value >> 32;
        const item_seq = value & 0xffff_ffff;
        std.debug.print("  producer={d} seq={d}\n", .{ pid, item_seq });
        drained += 1;
    }
    if (drained != 3) return error.UnexpectedDrainCount;

    // Queue is now empty: dequeue returns null, not an error.
    if (queue.dequeue(worker) != null) return error.ExpectedEmptyQueue;

    // The queue is generic: a job record instead of a packed word. Several
    // queues share one domain — reclamation is per node, not per queue.
    const Job = struct { id: u32, name: [8]u8 };
    const JobQueue = lockfree.Queue(Job);
    var job_pool = JobQueue.Pool.init(gpa);
    var jobs = try JobQueue.init(&job_pool, &domain);
    try jobs.enqueue(worker, .{ .id = 1, .name = "compress".* });
    const job = jobs.dequeue(worker) orelse return error.ExpectedJob;
    std.debug.print("job {d}: {s}\n", .{ job.id, &job.name });
    jobs.deinit();

    // Teardown in the order the module documents: queue first (drains any
    // still-linked nodes back to the pool), then the pool, then the domain —
    // unregistering the worker before the domain goes away.
    queue.deinit();
    domain.unregister(worker);
    try node_pool.verifyQuiescent(); // canary: every freed node still holds intact poison
    node_pool.deinit();
    try job_pool.verifyQuiescent();
    job_pool.deinit();

    try boundedRing(gpa);
}

/// The bounded ring: no domain, no pool, no allocation after `init` — what a
/// request worker uses to hand records to one exporter thread without ever
/// waiting on it.
fn boundedRing(gpa: std.mem.Allocator) !void {
    const Record = struct { status: u16, path: [32]u8 };
    const Ring = lockfree.BoundedQueue(Record, 4, .{ .consumers = .single });
    // The slots live inside the value: a big ring belongs on the heap.
    const ring = try gpa.create(Ring);
    defer gpa.destroy(ring);
    ring.init();

    const fill = struct {
        fn f(status: u16, out: *Record) void {
            out.status = status;
            @memset(&out.path, 0);
            @memcpy(out.path[0..2], "/x");
        }
    }.f;
    // Five records into four slots: the fifth is refused, never waited on.
    var accepted: usize = 0;
    for ([_]u16{ 200, 201, 404, 500, 503 }) |status| {
        if (ring.pushWith(status, fill)) accepted += 1;
    }
    std.debug.print("ring accepted {d}, refused {d}\n", .{ accepted, ring.refusedCount() });
    if (accepted != Ring.capacity or ring.refusedCount() != 1) return error.UnexpectedRefusals;

    // The one consumer reads each record in place, then releases its slot.
    while (ring.front()) |rec| {
        std.debug.print("  status={d}\n", .{rec.status});
        ring.advance();
    }
    if (!ring.isEmpty()) return error.ExpectedEmptyRing;
}
