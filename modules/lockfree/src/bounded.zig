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
/// static, not on the stack. For a capacity known only at run time, or one
/// that is not a power of two, see `ArrayQueue`.
pub fn BoundedQueue(comptime T: type, comptime capacity_: usize, comptime opts: Options) type {
    if (capacity_ < 2 or !std.math.isPowerOfTwo(capacity_)) {
        // Capacity 1 is not merely small, it is wrong for this layout: a
        // slot's "free for the next lap" value `pos + capacity` would equal
        // its "holds the item" value `pos + 1`, so a second push would
        // overwrite an unconsumed item. (`ArrayQueue` spaces laps by at
        // least 2 and takes capacity 1.)
        @compileError("BoundedQueue capacity must be a power of two and at least 2");
    }
    return Ring(T, capacity_, opts);
}

/// The same queue with its capacity chosen at run time — any value from 1
/// up — and its slots on the heap: crossbeam's `ArrayQueue::new(cap)`.
/// `init(allocator, capacity)` / `deinit(allocator)`; `capacity()` is a
/// method here. Positions are *stamps* `lap * one_lap + index`, `one_lap`
/// the smallest power of two at least `capacity` (and at least 2): a
/// position's slot is a mask, and the step past a lap's last slot jumps to
/// the next lap's index 0. Every per-slot rule is `BoundedQueue`'s, whose
/// positions are the special case `one_lap == capacity`.
pub fn ArrayQueue(comptime T: type, comptime opts: Options) type {
    return Ring(T, null, opts);
}

const stripe_bits = 2;
const refused_stripes = 1 << stripe_bits;

/// The refusal stripe of the calling thread, from its stack address: each
/// thread's stack is its own mapping, and those sit at aligned distances, so
/// the address (above the page) goes through a multiplicative hash and the
/// stripe is its top bits. Not a thread id — no syscall, no TLS.
inline fn refusedStripe() usize {
    var probe: u8 = 0;
    const a: u64 = @intFromPtr(&probe) >> 12;
    return @intCast((a *% 0x9E3779B97F4A7C15) >> (64 - stripe_bits));
}

fn Ring(comptime T: type, comptime fixed: ?usize, comptime opts: Options) type {
    return struct {
        const Self = @This();

        const Slot = struct {
            seq: std.atomic.Value(usize),
            item: T,
        };

        /// `BoundedQueue`: the slot count, a comptime constant.
        /// `ArrayQueue`: a method, `q.capacity()`.
        pub const capacity = if (fixed) |n| n else capacityOf;

        /// `BoundedQueue`: `init(q)` in place. `ArrayQueue`:
        /// `init(allocator, capacity) !ArrayQueue`, freed by `deinit`.
        pub const init = if (fixed == null) initHeap else initInPlace;

        slots: if (fixed) |n| [n]Slot else []Slot,
        /// `ArrayQueue` only: the distance between one slot's positions on
        /// consecutive laps (see `ArrayQueue`). Read-only after `init`.
        one_lap: if (fixed == null) usize else void,
        /// Next position a producer claims. On its own cache line: producers
        /// and consumers hammer different counters.
        tail: std.atomic.Value(usize) align(atomic.cache_line),
        /// Next position a consumer claims.
        head: std.atomic.Value(usize) align(atomic.cache_line),
        /// Pushes refused because the queue was full, striped: producers
        /// spinning on a full ring all refuse, and one shared counter made
        /// their `lock xadd`s fight over a line — `bounded_4x4` 1.0 → 1.2×
        /// crossbeam (no counter), up to 1.7× (2026-10-14). A refusal adds to
        /// the stripe its thread's stack address picks; `refusedCount` sums.
        refused: [refused_stripes]atomic.CachePadded(std.atomic.Value(u64)) align(atomic.cache_line),

        /// Initialise in place: every slot free for lap 0, nothing refused.
        fn initInPlace(q: *Self) void {
            for (&q.slots, 0..) |*s, i| {
                s.seq = .init(i);
                s.item = undefined;
            }
            q.one_lap = {};
            q.tail = .init(0);
            q.head = .init(0);
            q.refused = @splat(.init(.init(0)));
        }

        pub const InitError = error{
            /// `capacity` is 0, or too large to space its laps.
            InvalidCapacity,
        } || std.mem.Allocator.Error;

        fn initHeap(allocator: std.mem.Allocator, capacity_: usize) InitError!Self {
            if (capacity_ == 0) return error.InvalidCapacity;
            const one_lap = std.math.ceilPowerOfTwo(usize, @max(capacity_, 2)) catch return error.InvalidCapacity;
            const slots = try allocator.alloc(Slot, capacity_);
            for (slots, 0..) |*s, i| {
                s.seq = .init(i);
                s.item = undefined;
            }
            return .{
                .slots = slots,
                .one_lap = one_lap,
                .tail = .init(0),
                .head = .init(0),
                .refused = @splat(.init(.init(0))),
            };
        }

        /// `ArrayQueue` only: free the slots. No thread may be inside an
        /// operation; unread items are dropped (Zig has no destructors —
        /// `pop` them first if they own memory).
        pub fn deinit(q: *Self, allocator: std.mem.Allocator) void {
            if (fixed != null) @compileError("BoundedQueue owns no memory: there is nothing to deinit");
            allocator.free(q.slots);
            q.* = undefined;
        }

        fn capacityOf(q: *const Self) usize {
            return q.slots.len;
        }

        inline fn slotCount(q: *const Self) usize {
            return if (fixed) |n| n else q.slots.len;
        }

        inline fn lapLen(q: *const Self) usize {
            return if (fixed) |n| n else q.one_lap;
        }

        inline fn slotAt(q: *Self, pos: usize) *Slot {
            return &q.slots[pos & (q.lapLen() - 1)];
        }

        /// The position after `pos`: the next index, or the next lap's index
        /// 0 after a lap's last slot (for `BoundedQueue` both are `pos + 1`).
        inline fn after(q: *const Self, pos: usize) usize {
            if (fixed != null) return pos +% 1;
            const i = pos & (q.one_lap - 1);
            return if (i + 1 < q.slots.len) pos +% 1 else (pos - i) +% q.one_lap;
        }

        /// Positions before `pos` that hold a slot: `pos` itself for
        /// `BoundedQueue`; whole laps of `capacity` plus the index otherwise.
        /// The lap count wraps only after 2^64 / one_lap laps.
        inline fn ordinal(q: *const Self, pos: usize) usize {
            if (fixed != null) return pos;
            return (pos >> @intCast(@ctz(q.one_lap))) *% q.slots.len +% (pos & (q.one_lap - 1));
        }

        /// From any thread: append `item`. False — and counted in
        /// `refusedCount` — when the queue is full; the item is then not
        /// stored (the caller still has it).
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
            var backoff: atomic.Backoff = .{};
            while (true) {
                const slot = q.slotAt(pos);
                // Acquire: pairs with the consumer's release store that freed
                // this slot, so its read of the previous item happens-before
                // our overwrite.
                const seq = slot.seq.load(.acquire);
                const diff: isize = @bitCast(seq -% pos);
                if (diff == 0) {
                    // Free for `pos`. Claim it; a lost CAS hands back the
                    // position another producer moved `tail` to. Release on
                    // success: a `len` that reads this `tail` also sees the
                    // `head` that freed the slot (its consumer moved `head`
                    // before the slot's release store we acquired above).
                    if (q.tail.cmpxchgWeak(pos, q.after(pos), .release, .monotonic)) |actual| {
                        pos = actual;
                        backoff.spin();
                        continue;
                    }
                    fill(source, &slot.item);
                    // Release: publishes the item to the consumer of `pos`.
                    slot.seq.store(pos +% 1, .release);
                    return true;
                } else if (diff < 0) {
                    // The slot still holds the item of the previous lap: full.
                    _ = q.refused[refusedStripe()].value.fetchAdd(1, .monotonic);
                    return false;
                } else {
                    // Another producer claimed `pos` already; catch up.
                    pos = q.tail.load(.monotonic);
                }
            }
        }

        /// From any thread, `.multi` only: append `item`, and when the queue
        /// is full make room by taking the oldest item, which is returned
        /// (crossbeam's `force_push`; a "latest N" buffer). Null when there
        /// was room. Not counted in `refusedCount`.
        ///
        /// When full, the producer takes the oldest position `old` exactly as
        /// a consumer would (a CAS on `head`), and then, instead of freeing
        /// the slot for the next lap's position `pos`, claims `pos` itself
        /// (a CAS on `tail`) and writes its item there. That CAS cannot fail:
        /// only a thread that sees the slot free for `pos` (no one — it is
        /// not freed) or that took `old` (we did) may move `tail` off `pos`.
        /// Waits (spins) while the oldest position is mid-hand-off — claimed
        /// by its producer but not published, or by a consumer but not freed
        /// — the same stalled-thread corner as `push` and `pop`.
        pub fn forcePush(q: *Self, item: T) ?T {
            comptime if (opts.consumers != .multi)
                @compileError("forcePush needs .consumers = .multi: it takes the oldest item as a second consumer would");
            var pos = q.tail.load(.monotonic);
            var backoff: atomic.Backoff = .{};
            while (true) {
                const slot = q.slotAt(pos);
                const seq = slot.seq.load(.acquire);
                const diff: isize = @bitCast(seq -% pos);
                if (diff == 0) {
                    if (q.tail.cmpxchgWeak(pos, q.after(pos), .release, .monotonic)) |actual| {
                        pos = actual;
                        backoff.spin();
                        continue;
                    }
                    slot.item = item;
                    slot.seq.store(pos +% 1, .release);
                    return null;
                } else if (diff < 0) {
                    // Full at `pos`: the slot holds the previous lap's `old`.
                    // Acquire above paired with its publish when `seq` says
                    // published, so the item is ours to copy once `old` is.
                    const old = pos -% q.lapLen();
                    if (seq == old +% 1 and q.head.cmpxchgStrong(old, q.after(old), .release, .monotonic) == null) {
                        const evicted = slot.item;
                        // Release, for `len`, as in `pushWith`.
                        const moved = q.tail.cmpxchgStrong(pos, q.after(pos), .release, .monotonic);
                        std.debug.assert(moved == null);
                        slot.item = item;
                        slot.seq.store(pos +% 1, .release);
                        return evicted;
                    }
                    // `old` is mid-hand-off, or a consumer took it first (the
                    // slot is then about to be freed for `pos`): look again.
                    backoff.spin();
                    pos = q.tail.load(.monotonic);
                } else {
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
            var backoff: atomic.Backoff = .{};
            while (true) {
                const slot = q.slotAt(pos);
                // Acquire: pairs with the producer's publish, so the item
                // write happens-before our copy.
                const seq = slot.seq.load(.acquire);
                const diff: isize = @bitCast(seq -% (pos +% 1));
                if (diff == 0) {
                    // Release on success: pairs with `len`'s load of `head`,
                    // so a `len` that sees this `head` sees the `tail` its
                    // producer claimed before publishing (acquired above).
                    if (q.head.cmpxchgWeak(pos, q.after(pos), .release, .monotonic)) |actual| {
                        pos = actual;
                        backoff.spin();
                        continue;
                    }
                    const item = slot.item;
                    // Release: our copy happens-before the next lap's write.
                    slot.seq.store(pos +% q.lapLen(), .release);
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
            const slot = q.slotAt(pos);
            // With one consumer `seq` is `pos` (not yet published) or
            // `pos + 1` (published); acquire pairs with the publish.
            if (slot.seq.load(.acquire) != pos +% 1) return null;
            return &slot.item;
        }

        /// `.single` only, from the one consumer thread: release the item
        /// `front` returned. A no-op when nothing is published at `head`
        /// (`front` returned null): releasing an unpublished slot would
        /// stall every producer behind it (sweep LF-4).
        ///
        /// Call it only after a `front` that returned non-null, and once per
        /// such `front`. The no-op above cannot tell a stale `front` from a
        /// fresh one: if `front` returned null and a producer published
        /// before this call, or `advance` is called twice after one `front`
        /// while the next slot is already published, the unread item is
        /// released and lost (sweep REV-lockfree-4).
        pub fn advance(q: *Self) void {
            comptime requireSingle("advance");
            const pos = q.head.load(.monotonic);
            const slot = q.slotAt(pos);
            if (slot.seq.load(.monotonic) != pos +% 1) return;
            // `head` first, with release, for `len`: a reader that sees it
            // sees the `tail` that published this item, and a producer that
            // acquires the freed slot below carries it on to its own `tail`.
            q.head.store(q.after(pos), .release);
            // Release: our reads of the item happen-before the next lap's
            // producer overwrites it.
            slot.seq.store(pos +% q.lapLen(), .release);
        }

        fn requireSingle(comptime name: []const u8) void {
            if (opts.consumers != .single)
                @compileError(name ++ " needs .consumers = .single: with several consumers the slot it points at can be taken and reused by another one");
        }

        /// Pushes refused because the queue was full, since `init`. A sum of
        /// stripes: exact once the producers have stopped, otherwise a
        /// snapshot that may miss refusals still landing.
        pub fn refusedCount(q: *const Self) u64 {
            var n: u64 = 0;
            for (&q.refused) |*c| n += c.value.load(.monotonic);
            return n;
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
                // That needs the release stores of `tail` and `head` above:
                // with relaxed ones an arm64 reader saw `head` past the
                // `tail` it read and `t - h` wrapped (tag 2026-10-06 matrix;
                // x86's ordered stores hide it).
                if (q.tail.load(.seq_cst) == t) return @min(q.ordinal(t) -% q.ordinal(h), q.slotCount());
            }
        }

        pub fn isEmpty(q: *const Self) bool {
            return q.len() == 0;
        }

        pub fn isFull(q: *const Self) bool {
            return q.len() == q.slotCount();
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

fn sequentialArray(comptime consumers: Consumers, cap: usize) !void {
    const Q = ArrayQueue(u64, .{ .consumers = consumers });
    var q = try Q.init(testing.allocator, cap);
    defer q.deinit(testing.allocator);
    try testing.expectEqual(cap, q.capacity());
    try testing.expect(q.isEmpty());
    for (0..cap) |i| try testing.expect(q.push(i));
    try testing.expect(q.isFull());
    try testing.expectEqual(cap, q.len());
    try testing.expect(!q.push(99));
    try testing.expectEqual(@as(u64, 1), q.refusedCount());
    for (0..cap) |i| try testing.expectEqual(@as(?u64, i), q.pop());
    try testing.expectEqual(@as(?u64, null), q.pop());
    // Many laps at every fill level 1..capacity: the jump from a lap's last
    // slot to the next lap's index 0 runs on every slot, and `len` counts
    // across it.
    var next_in: u64 = 100;
    var next_out: u64 = 100;
    for (0..8 * cap + 7) |round| {
        const fill = round % cap + 1;
        for (0..fill) |_| {
            try testing.expect(q.push(next_in));
            next_in += 1;
        }
        try testing.expectEqual(fill, q.len());
        for (0..fill) |_| {
            try testing.expectEqual(@as(?u64, next_out), q.pop());
            next_out += 1;
        }
        try testing.expectEqual(@as(?u64, null), q.pop());
        try testing.expectEqual(@as(usize, 0), q.len());
    }
    try testing.expectEqual(@as(u64, 1), q.refusedCount());
}

test "ArrayQueue: any run-time capacity from 1 — FIFO, full refuses and counts, laps over every slot" {
    for ([_]usize{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 100 }) |cap| {
        try sequentialArray(.multi, cap);
        try sequentialArray(.single, cap);
    }
}

test "ArrayQueue: capacity 0, or too large to space its laps, is refused" {
    const Q = ArrayQueue(u8, .{});
    try testing.expectError(error.InvalidCapacity, Q.init(testing.allocator, 0));
    try testing.expectError(error.InvalidCapacity, Q.init(testing.allocator, std.math.maxInt(usize)));
}

test "ArrayQueue: front/advance read in place (single)" {
    var q = try ArrayQueue(Big, .{ .consumers = .single }).init(testing.allocator, 3);
    defer q.deinit(testing.allocator);
    for (0..3) |i| try testing.expect(q.pushWith(@as(u64, i), fillBig));
    try testing.expect(!q.pushWith(@as(u64, 9), fillBig));
    for (0..3) |i| {
        try testing.expectEqual(@as(u64, i), q.front().?.id);
        q.advance();
    }
    try testing.expectEqual(@as(?*Big, null), q.front());
}

fn latestN(q: anytype, cap: usize) !void {
    // Below capacity forcePush is a push.
    for (0..cap) |i| try testing.expectEqual(@as(?u64, null), q.forcePush(i));
    try testing.expect(q.isFull());
    // Full: each forcePush hands back the oldest item and keeps the newest.
    for (cap..cap + 3 * cap + 1) |i| {
        try testing.expectEqual(@as(?u64, i - cap), q.forcePush(i));
        try testing.expectEqual(cap, q.len());
    }
    const last = cap + 3 * cap + 1;
    for (last - cap..last) |i| try testing.expectEqual(@as(?u64, i), q.pop());
    try testing.expectEqual(@as(?u64, null), q.pop());
    try testing.expectEqual(@as(u64, 0), q.refusedCount());
    // A plain push still refuses on full after evictions.
    for (0..cap) |i| try testing.expect(q.push(i));
    try testing.expect(!q.push(7));
}

test "forcePush keeps the latest N, handing back the oldest, for BoundedQueue and ArrayQueue" {
    var b: BoundedQueue(u64, 4, .{}) = undefined;
    b.init();
    try latestN(&b, 4);
    for ([_]usize{ 1, 2, 3, 5 }) |cap| {
        var a = try ArrayQueue(u64, .{}).init(testing.allocator, cap);
        defer a.deinit(testing.allocator);
        try latestN(&a, cap);
    }
}
