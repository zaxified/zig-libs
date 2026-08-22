// SPDX-License-Identifier: MIT

//! What a worker-pool consumer does with `lockfree`: build the shared
//! reclamation domain, register a worker as an EBR participant, drive a
//! Michael-Scott MPMC queue through enqueue/dequeue, and tear everything
//! down in the order the module documents (queue, then pool, then domain).
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

    // Teardown in the order the module documents: queue first (drains any
    // still-linked nodes back to the pool), then the pool, then the domain —
    // unregistering the worker before the domain goes away.
    queue.deinit();
    domain.unregister(worker);
    try node_pool.verifyQuiescent(); // canary: every freed node still holds intact poison
    node_pool.deinit();
}
