// SPDX-License-Identifier: MIT

//! bounded — a fixed-capacity, allocation-free MPMC queue (Dmitry Vyukov's
//! bounded queue: one sequence number per slot, one CAS per operation, no
//! lock, no allocation, no reclamation). The counterpart of crossbeam's
//! `ArrayQueue`, beside the unbounded Michael-Scott `mpmc.Queue`.
//!
//! What it is for: handing work or records from many threads to one or more
//! consumers when the producer must never wait — a full queue refuses the item
//! (`push` returns false) and counts the refusal, so a caller can drop on full
//! (telemetry, access logs) or back off and retry (work hand-off).
//!
//! **Protocol.** Slot `i` of a ring of `capacity` slots carries `seq`, set to
//! `i` at `init`. Positions `tail` (producers) and `head` (consumers) only
//! grow; position `pos` lives in slot `pos mod capacity`, and on lap `k` of
//! that slot:
//!
//!  • `seq == pos`         — free for the producer of `pos`;
//!  • `seq == pos + 1`     — holds the item of `pos`, ready for its consumer;
//!  • `seq == pos + capacity` — consumed; free for the producer of
//!                           `pos + capacity` (the next lap).
//!
//! A producer claims `pos` by CAS on `tail` only after reading `seq == pos`,
//! writes the item, then publishes with a release store `seq = pos + 1`. A
//! consumer claims `pos` by CAS on `head` only after an acquire read of
//! `seq == pos + 1`, copies the item, then frees the slot with a release store
//! `seq = pos + capacity`. The CASes need no ordering of their own: each slot's
//! item is handed between exactly two threads through that slot's `seq`
//! (release → acquire, message passing), and the CAS only decides WHICH thread
//! owns a position. Exactly one CAS can move `tail` (or `head`) off a given
//! value, so a position has one producer and one consumer — no item is written
//! twice or read twice.
//!
//! **What "full" and "empty" mean here (honest scope).** `push` refuses when
//! the slot at `tail` has not been freed by its consumer yet, and `pop` reports
//! empty when the slot at `head` has not been published by its producer yet.
//! A thread pre-empted between its claim and its publish (or free) therefore
//! makes the queue read empty (or full) at that position while items behind it
//! wait: the queue is not linearizable in that corner, exactly like crossbeam's
//! `ArrayQueue` and Vyukov's original. Nothing is lost or reordered — once the
//! stalled thread finishes, every item comes out in position order — and a
//! caller that treats `false`/`null` as "not now" is correct.
//!
//! **Consumers.** `.multi` (the default) lets any number of threads `pop`.
//! `.single` promises exactly one consumer thread: `pop` then needs no CAS,
//! and `front`/`advance` read the oldest item in place, so a large `T` is never
//! copied through the stack. Calling `pop`/`front`/`advance` from two threads
//! of a `.single` queue is a data race the type cannot detect.

const std = @import("std");
const atomic = @import("atomic.zig");

pub const Consumers = enum {
    /// Exactly one thread ever pops. Enables `front`/`advance`; `pop` is
    /// CAS-free.
    single,
    /// Any number of threads pop; each pop claims its position by CAS.
    multi,
};

pub const Options = struct {
    consumers: Consumers = .multi,
};

/// A bounded MPMC (or MPSC, with `.consumers = .single`) queue of `T` with
/// `capacity` slots stored inline. `capacity` must be a power of two and at
/// least 2. Initialise in place with `init` — the slot array is part of the
/// value, so a large queue belongs on the heap (`allocator.create`) or in a
/// static, not on the stack.
pub fn BoundedQueue(comptime T: type, comptime capacity_: usize, comptime opts: Options) type {
    if (capacity_ < 2 or !std.math.isPowerOfTwo(capacity_)) {
        // Capacity 1 is not merely small, it is wrong for this protocol: a
        // slot's "free for the next lap" value `pos + capacity` would equal
        // its "holds the item" value `pos + 1`, so a second push would
        // overwrite an unconsumed item.
        @compileError("BoundedQueue capacity must be a power of two and at least 2");
    }
    return struct {
        const Self = @This();
        pub const capacity: usize = capacity_;
        const mask: usize = capacity - 1;

        const Slot = struct {
            seq: std.atomic.Value(usize),
            item: T,
        };

        slots: [capacity]Slot,
        /// Next position a producer claims. On its own cache line: producers
        /// and consumers hammer different counters.
        tail: std.atomic.Value(usize) align(atomic.cache_line),
        /// Next position a consumer claims.
        head: std.atomic.Value(usize) align(atomic.cache_line),
        /// Pushes refused because the queue was full.
        refused: std.atomic.Value(u64) align(atomic.cache_line),

        /// Initialise in place: every slot free for lap 0, nothing refused.
        pub fn init(q: *Self) void {
            for (&q.slots, 0..) |*s, i| {
                s.seq = .init(i);
                s.item = undefined;
            }
            q.tail = .init(0);
            q.head = .init(0);
            q.refused = .init(0);
        }

        /// From any thread: append `item`. False — and counted in
        /// `refusedCount` — when the queue is full; the item is then not
        /// stored.
        pub fn push(q: *Self, item: T) bool {
            return q.pushWith(item, copyItem);
        }

        fn copyItem(item: T, out: *T) void {
            out.* = item;
        }

        /// From any thread: claim a slot and let `fill(source, slot)` write
        /// the item in place, so a large `T` is never built on the stack and
        /// copied. `fill` runs after the claim and before the publish: it must
        /// not block, and a consumer waits on this position until it returns.
        /// False — and counted — when the queue is full; `fill` is then not
        /// called.
        pub fn pushWith(q: *Self, source: anytype, comptime fill: fn (@TypeOf(source), *T) void) bool {
            var pos = q.tail.load(.monotonic);
            while (true) {
                const slot = &q.slots[pos & mask];
                // Acquire: pairs with the consumer's release store that freed
                // this slot, so its read of the previous item happens-before
                // our overwrite.
                const seq = slot.seq.load(.acquire);
                const diff: isize = @bitCast(seq -% pos);
                if (diff == 0) {
                    // Free for `pos`. Claim it; a lost CAS hands back the
                    // position another producer moved `tail` to.
                    if (q.tail.cmpxchgWeak(pos, pos +% 1, .monotonic, .monotonic)) |actual| {
                        pos = actual;
                        continue;
                    }
                    fill(source, &slot.item);
                    // Release: publishes the item to the consumer of `pos`.
                    slot.seq.store(pos +% 1, .release);
                    return true;
                } else if (diff < 0) {
                    // The slot still holds the item of `pos - capacity`: full.
                    _ = q.refused.fetchAdd(1, .monotonic);
                    return false;
                } else {
                    // Another producer claimed `pos` already; catch up.
                    pos = q.tail.load(.monotonic);
                }
            }
        }

        /// Pop the oldest item, or null when the queue reads empty (see the
        /// file comment for what "empty" means under a stalled producer). From
        /// any thread for `.multi`; from the one consumer thread for `.single`.
        pub fn pop(q: *Self) ?T {
            if (opts.consumers == .single) {
                const item = (q.front() orelse return null).*;
                q.advance();
                return item;
            }
            var pos = q.head.load(.monotonic);
            while (true) {
                const slot = &q.slots[pos & mask];
                // Acquire: pairs with the producer's publish, so the item
                // write happens-before our copy.
                const seq = slot.seq.load(.acquire);
                const diff: isize = @bitCast(seq -% (pos +% 1));
                if (diff == 0) {
                    if (q.head.cmpxchgWeak(pos, pos +% 1, .monotonic, .monotonic)) |actual| {
                        pos = actual;
                        continue;
                    }
                    const item = slot.item;
                    // Release: our copy happens-before the next lap's write.
                    slot.seq.store(pos +% capacity, .release);
                    return item;
                } else if (diff < 0) {
                    // Not yet published for this lap: empty at `pos`.
                    return null;
                } else {
                    // Another consumer took `pos` already; catch up.
                    pos = q.head.load(.monotonic);
                }
            }
        }

        /// `.single` only, from the one consumer thread: the oldest item in
        /// place, or null when empty. Valid until `advance`; a producer cannot
        /// reuse the slot before then.
        pub fn front(q: *Self) ?*T {
            comptime requireSingle("front");
            // Only this thread writes `head`.
            const pos = q.head.load(.monotonic);
            const slot = &q.slots[pos & mask];
            // With one consumer `seq` is `pos` (not yet published) or
            // `pos + 1` (published); acquire pairs with the publish.
            if (slot.seq.load(.acquire) != pos +% 1) return null;
            return &slot.item;
        }

        /// `.single` only, from the one consumer thread: release the item
        /// `front` returned. Calling it when `front` returned null is a bug
        /// (asserted in safe builds).
        pub fn advance(q: *Self) void {
            comptime requireSingle("advance");
            const pos = q.head.load(.monotonic);
            const slot = &q.slots[pos & mask];
            std.debug.assert(slot.seq.load(.monotonic) == pos +% 1);
            // Release: our reads of the item happen-before the next lap's
            // producer overwrites it.
            slot.seq.store(pos +% capacity, .release);
            q.head.store(pos +% 1, .monotonic);
        }

        fn requireSingle(comptime name: []const u8) void {
            if (opts.consumers != .single)
                @compileError(name ++ " needs .consumers = .single: with several consumers the slot it points at can be taken and reused by another one");
        }

        /// Pushes refused because the queue was full, since `init`.
        pub fn refusedCount(q: *const Self) u64 {
            return q.refused.load(.monotonic);
        }

        /// Items claimed by producers and not yet claimed by consumers, at
        /// one instant (a snapshot; stale as soon as it returns). Counts items
        /// whose producer has claimed but not yet published them.
        pub fn len(q: *const Self) usize {
            while (true) {
                const t = q.tail.load(.seq_cst);
                const h = q.head.load(.seq_cst);
                // `head` never passes `tail` (a consumer claims `pos` only
                // after its producer published it), so if `tail` did not move
                // while `head` was read, `t - h` was the length at that read.
                if (q.tail.load(.seq_cst) == t) return @min(t -% h, capacity);
            }
        }

        pub fn isEmpty(q: *const Self) bool {
            return q.len() == 0;
        }

        pub fn isFull(q: *const Self) bool {
            return q.len() == capacity;
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn sequential(comptime consumers: Consumers) !void {
    const Q = BoundedQueue(u64, 4, .{ .consumers = consumers });
    var q: Q = undefined;
    q.init();
    try testing.expect(q.isEmpty());
    for (0..4) |i| try testing.expect(q.push(i));
    try testing.expect(q.isFull());
    try testing.expectEqual(@as(usize, 4), q.len());
    // Full: refused, counted, and the queue is unchanged.
    try testing.expect(!q.push(99));
    try testing.expect(!q.push(98));
    try testing.expectEqual(@as(u64, 2), q.refusedCount());
    try testing.expectEqual(@as(?u64, 0), q.pop());
    try testing.expectEqual(@as(usize, 3), q.len());
    // The freed slot takes the next lap's item, behind the older ones.
    try testing.expect(q.push(4));
    for (1..5) |i| try testing.expectEqual(@as(?u64, i), q.pop());
    try testing.expectEqual(@as(?u64, null), q.pop());
    try testing.expect(q.isEmpty());

    // Many laps over every slot, at every fill level 1..capacity: a wrong
    // lap arithmetic (`pos + capacity` vs `pos + 1`) shows here as a lost,
    // repeated or refused item.
    var next_in: u64 = 100;
    var next_out: u64 = 100;
    for (0..64) |round| {
        const fill = round % 4 + 1;
        for (0..fill) |_| {
            try testing.expect(q.push(next_in));
            next_in += 1;
        }
        for (0..fill) |_| {
            try testing.expectEqual(@as(?u64, next_out), q.pop());
            next_out += 1;
        }
        try testing.expectEqual(@as(?u64, null), q.pop());
    }
    try testing.expectEqual(@as(u64, 2), q.refusedCount());
}

test "BoundedQueue: FIFO, full refuses and counts, slots reused over many laps (multi)" {
    try sequential(.multi);
}

test "BoundedQueue: FIFO, full refuses and counts, slots reused over many laps (single)" {
    try sequential(.single);
}

test "BoundedQueue: capacity 2, the smallest the protocol allows, never overwrites" {
    var q: BoundedQueue(u32, 2, .{}) = undefined;
    q.init();
    try testing.expect(q.push(1));
    try testing.expect(q.push(2));
    try testing.expect(!q.push(3));
    try testing.expectEqual(@as(?u32, 1), q.pop());
    try testing.expect(q.push(3));
    try testing.expect(!q.push(4));
    try testing.expectEqual(@as(?u32, 2), q.pop());
    try testing.expectEqual(@as(?u32, 3), q.pop());
    try testing.expectEqual(@as(?u32, null), q.pop());
}

const Big = struct { id: u64, body: [64]u8 };

fn fillBig(id: u64, out: *Big) void {
    out.id = id;
    @memset(&out.body, @truncate(id));
}

test "BoundedQueue: pushWith fills in place; front/advance read in place (single)" {
    var q: BoundedQueue(Big, 4, .{ .consumers = .single }) = undefined;
    q.init();
    try testing.expectEqual(@as(?*Big, null), q.front());
    try testing.expect(q.pushWith(@as(u64, 7), fillBig));
    try testing.expect(q.pushWith(@as(u64, 8), fillBig));
    const f = q.front().?;
    // In place: the pointer is the slot itself, and stays put until advance.
    try testing.expect(f == &q.slots[0].item);
    try testing.expectEqual(@as(u64, 7), f.id);
    try testing.expectEqual(@as(u8, 7), f.body[63]);
    try testing.expect(q.front().? == f);
    q.advance();
    try testing.expectEqual(@as(u64, 8), q.front().?.id);
    q.advance();
    try testing.expectEqual(@as(?*Big, null), q.front());
    for (0..4) |i| try testing.expect(q.pushWith(@as(u64, i), fillBig));
    try testing.expect(!q.pushWith(@as(u64, 9), fillBig));
    try testing.expectEqual(@as(u64, 1), q.refusedCount());
}

test "BoundedQueue: a producer stalled between claim and publish reads as empty, then nothing is lost or reordered" {
    // The non-linearizable corner the file comment owns up to, driven by
    // hand: producer A claims position 0 and stalls; B publishes position 1.
    inline for (.{ Consumers.multi, Consumers.single }) |c| {
        var q: BoundedQueue(u64, 4, .{ .consumers = c }) = undefined;
        q.init();
        // A: claim position 0 without publishing.
        try testing.expectEqual(@as(?usize, null), q.tail.cmpxchgStrong(0, 1, .monotonic, .monotonic));
        // B: a full push lands at position 1.
        try testing.expect(q.push(11));
        try testing.expectEqual(@as(usize, 2), q.len());
        // The consumer waits on position 0: empty, and B's item is not
        // handed out ahead of A's.
        try testing.expectEqual(@as(?u64, null), q.pop());
        // A finishes.
        q.slots[0].item = 10;
        q.slots[0].seq.store(1, .release);
        try testing.expectEqual(@as(?u64, 10), q.pop());
        try testing.expectEqual(@as(?u64, 11), q.pop());
        try testing.expectEqual(@as(?u64, null), q.pop());
    }
}

test "BoundedQueue: a consumer stalled between claim and free reads as full to the next lap" {
    var q: BoundedQueue(u64, 2, .{}) = undefined;
    q.init();
    try testing.expect(q.push(1));
    try testing.expect(q.push(2));
    // A consumer claims position 0 and stalls before freeing the slot.
    try testing.expectEqual(@as(?usize, null), q.head.cmpxchgStrong(0, 1, .monotonic, .monotonic));
    // Position 2 maps to the unfreed slot 0: refused, item 1 not overwritten.
    try testing.expect(!q.push(3));
    try testing.expectEqual(@as(u64, 1), q.slots[0].item);
    // Another consumer takes position 1 meanwhile.
    try testing.expectEqual(@as(?u64, 2), q.pop());
    // The stalled consumer finishes.
    q.slots[0].seq.store(0 + 2, .release);
    try testing.expect(q.push(3));
    try testing.expectEqual(@as(?u64, 3), q.pop());
}

test "BoundedQueue: len under a concurrent push/pop never reports more than the queue ever held" {
    // One thread alternates push and pop, so the queue holds 0 or 1 items at
    // every instant; another reads `len`. `head` and `tail` are two loads: if
    // `tail` is not re-checked, both can move between them, `head` lands past
    // the `tail` that was read, and `t - h` wraps to a huge count.
    const Q = BoundedQueue(u64, 64, .{ .consumers = .single });
    const q = try testing.allocator.create(Q);
    defer testing.allocator.destroy(q);
    q.init();
    const Churn = struct {
        fn run(ring: *Q, done: *std.atomic.Value(bool)) void {
            for (0..2_000_000) |i| {
                std.debug.assert(ring.push(i));
                std.debug.assert(ring.pop() != null);
            }
            done.store(true, .release);
        }
    };
    var done: std.atomic.Value(bool) = .init(false);
    const t = try std.Thread.spawn(.{}, Churn.run, .{ q, &done });
    var worst: usize = 0;
    while (!done.load(.acquire)) worst = @max(worst, q.len());
    t.join();
    try testing.expect(worst <= 1);
}
