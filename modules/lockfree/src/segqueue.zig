// SPDX-License-Identifier: MIT

//! segqueue — an unbounded MPMC queue of fixed-size blocks that needs no
//! participant handles and no epoch domain: the counterpart of crossbeam's
//! `SegQueue`, beside the Michael-Scott `mpmc.Queue` (one node and one EBR pin
//! per item) and the bounded `BoundedQueue`. Designed here (2026-10-14);
//! crossbeam's source was not read.
//!
//! **Positions.** `tail` (producers) and `head` (consumers) are `u64`
//! positions that only grow; each block of `block_slots` slots covers one
//! *lap* of `lap = block_slots + 1` positions. Offset `o = pos mod lap` names
//! slot `o` of the lap's block for `o < block_slots`; the last offset,
//! `o == block_slots`, is the *closed* position — no slot, it marks "the
//! next block is being installed". A position is claimed by one CAS on its
//! index (`pos → pos + 1`), so it has exactly one producer and exactly one
//! consumer. Positions are never reused (2^64 does not wrap), so a CAS on an
//! index cannot be fooled by an old value coming back — the ABA that a
//! recycled block address would cause is impossible here because no CAS ever
//! compares a block pointer.
//!
//! **Push.** Read `tail` (seq_cst) and, after it, `tail_block`. Offset closed
//! → wait for the installer. Offset `block_slots - 1` (the last slot) → have
//! the next block ready BEFORE claiming (spare or allocator), so nothing can
//! fail after a claim. CAS `tail` `pos → pos + 1`. The winner of the last slot
//! has moved `tail` onto the closed position; it installs: `tail_block = nb`,
//! `b.next = nb`, then `tail = pos + 2` (the next lap's offset 0). Then write
//! the item and publish it: slot state `written` (release).
//!
//! **Pop.** Decide emptiness from `head` and `tail` (equal → empty,
//! linearized at the `tail` load; a remembered lower bound of `tail` on the
//! head line spares most pops that load). Else read `head_block` and CAS
//! `head` `pos → pos + 1`. The winner of the last slot waits for `b.next`
//! (its producer, the installer, has claimed and stores it shortly), then
//! moves `head_block` and `head` to the next lap. Then wait for the slot's
//! `written` (its producer claimed but may not have written yet), copy the
//! item, and store `read` (release) — a plain store, no read-modify-write on
//! anything shared.
//!
//! **Reclamation: scanned later, not counted.** The last slot's consumer,
//! once it has stored its own `read`, *retires* the block: it pushes it on the
//! `pending` stack. Other consumers of that block may still be copying. Each
//! retire first takes the whole `pending` stack (one swap) and scans every
//! block on it: a block whose every slot reads `read` is recycled, any other
//! goes back on the stack. A block is so scanned one hand-off after its own,
//! when its stragglers are almost always done; a straggler that is not (pre-
//! empted mid-copy) keeps only its own block waiting. An earlier version
//! counted reads with one `fetchAdd` per pop on a per-block counter; the
//! consumers contending for that line doubled the 4×4 wall time
//! (2026-10-14).
//!
//! **Why the block pointer read before the CAS is the right block.** A lap's
//! block is stored into `tail_block` before `tail` leaves that lap's closed
//! predecessor, and `tail` moves off a lap only through that lap's closed
//! position. A producer that loaded `pos` (acquire: it synchronizes with the
//! installer's store through the release sequence of CASes since) and then
//! `tail_block` sees at least `pos`'s block; it sees a LATER block only if
//! the next install has begun, which needs `tail` past `pos`, and then its
//! CAS from `pos` fails. So a successful CAS proves the block it read is
//! `pos`'s. Same for `head`/`head_block`. No block pointer is dereferenced
//! before a successful claim.
//!
//! **Why a block is not freed under a thread still using it.** Every access
//! to a block's memory comes from a thread that has claimed one of its
//! positions, and comes before that position's `read` store: the producer
//! (install, item, `written`) before its consumer's acquire of `written`,
//! which precedes the consumer's `read`; the consumer (`next`, item) before
//! its own `read` (release). The last slot's consumer touches the block after
//! its `read` only to push it on `pending`, before which no scanner can reach
//! it. A scanner frees a block only after acquire-loading `read` from all of
//! its slots, so every one of those accesses happens-before the free. A
//! block on `pending` belongs to the one retire that swapped it off. A thread
//! that only LOADED a block pointer and lost its CAS never touched the block.
//!
//! **Progress (honest scope).** Lock-free except two waits, both on a thread
//! that has already claimed and has a bounded, allocation-free tail of work:
//! producers meeting the closed position wait for its installer (three
//! stores), and a consumer waits for its own slot's producer between that
//! producer's claim and its item write. A thread pre-empted inside either
//! window stalls the others behind it until it runs — the same corner as
//! `BoundedQueue` (Vyukov) and, per its documentation, crossbeam's queues.
//!
//! **Memory.** One spare block is kept for reuse, so a steady flow allocates
//! nothing; a recycled block beyond the spare goes back to the allocator,
//! which must therefore be thread-safe (any thread may free). An idle queue
//! keeps at most the retired blocks of its last hand-offs on `pending` until
//! the next one or `deinit`. In safety-checked builds a block's item bytes
//! are poisoned (`0xA5`) when it is created and when it is recycled, so an
//! item read before its publish, or from a block recycled too early, comes
//! out as a value nobody enqueued — what the stress driver's `corrupted`
//! verdict catches.

const std = @import("std");
const atomic = @import("atomic.zig");

/// After a lost claim CAS: spin `2^step` pause hints, `step` growing to
/// `cap_step` — not `Backoff.spin`'s 6. Every lost CAS still moved the line
/// to the loser, so contenders that retry soon keep the line in flight;
/// spreading them further lets a winner claim several positions while the
/// line stays in its cache. Measured 2026-10-14 (i7-7920HQ, 4 Mi items,
/// median of 15 runs, ms) for caps 6 / 8 / 10: 4×4 155 / 135 / 94, 8×8
/// 230 / 184 / 131, 1×4 146 / 80 / 84, 4×1 81 / 74 / 74, 1×1 and 2×2 flat.
/// A pop pays the long spins only after ten straight losses, i.e. only
/// when other pops are winning.
const CasBackoff = struct {
    step: u6 = 0,
    const cap_step: u6 = 10;

    fn spin(b: *CasBackoff) void {
        var i: usize = 0;
        const limit = @as(usize, 1) << b.step;
        while (i < limit) : (i += 1) std.atomic.spinLoopHint();
        if (b.step < cap_step) b.step += 1;
    }
};

/// Waiting on another thread that has claimed and has a short, bounded
/// tail of work left (an install, a hand-off, an item write): poll with one
/// pause hint, so the wait ends within a pause of the store, and yield the
/// CPU only after a long run of polls (the other thread is then probably not
/// running). `Backoff.pause` doubles its spin each round instead, and on the
/// block hand-off that overshot a ~300 ns window by microseconds once every
/// lap (2026-10-14, measured).
const Waiter = struct {
    polls: u32 = 0,
    const spin_polls: u32 = 1 << 12;

    fn wait(w: *Waiter) void {
        if (w.polls < spin_polls) {
            w.polls += 1;
            std.atomic.spinLoopHint();
        } else {
            std.Thread.yield() catch {};
        }
    }
};

pub const Options = struct {
    /// Slots per block. `block_slots + 1` must be a power of two, so that a
    /// position's lap and offset are a shift and a mask. The default 63 makes
    /// a lap of 64; tests use 1 and 3 to put every item near a block hand-off.
    block_slots: usize = 63,
};

/// An unbounded MPMC queue of `T`. Any thread may `push`/`pop`; no
/// registration. `T` is copied in and out and may be any type.
pub fn SegQueue(comptime T: type, comptime opts: Options) type {
    return Impl(T, opts, .none);
}

/// Deliberate bugs for the stress driver's positive controls (tests only;
/// `SegQueue` is always `.none`).
const Fault = enum {
    none,
    /// `pop` copies the item without waiting for `written` (and `push`
    /// dawdles between claim and write, so the race is hit in optimized
    /// builds too).
    skip_ready_wait,
    /// A block's items are poisoned when it is retired, as if it were freed
    /// without the scan — under any reader still copying. (Really recycling
    /// it would also reset slot states under waiting readers and hang the
    /// run instead of failing it.)
    free_unscanned,
    /// `pop` stores `read` before copying the item, so the block can be
    /// recycled (and its items poisoned) under the copy. The copy is delayed,
    /// or the window is a few instructions and the stress never hits it;
    /// `recycle` parks a displaced spare on a graveyard instead of freeing it.
    read_before_copy,
};

fn Impl(comptime T: type, comptime opts: Options, comptime fault: Fault) type {
    if (opts.block_slots < 1 or !std.math.isPowerOfTwo(opts.block_slots + 1)) {
        @compileError("SegQueue block_slots + 1 must be a power of two (block_slots >= 1)");
    }
    return struct {
        const Self = @This();
        pub const block_slots: usize = opts.block_slots;
        const lap: u64 = opts.block_slots + 1;
        /// The offset of the closed position (also the slot count).
        const closed: u64 = opts.block_slots;

        const poison: u8 = 0xA5;

        /// Slot states, in order; each written by one thread: `written` by
        /// the slot's producer, `read` by its consumer.
        const empty: u32 = 0;
        const written: u32 = 1;
        const read: u32 = 2;

        const Slot = struct {
            value: T,
            state: std.atomic.Value(u32),
        };

        pub const Block = struct {
            slots: [opts.block_slots]Slot,
            /// The next lap's block, stored once by the installer.
            next: std.atomic.Value(?*Block),
            /// Link on `pending`; owned by whoever holds the block.
            pending_next: ?*Block,

            fn reset(b: *Block) void {
                for (&b.slots) |*s| s.state = .init(empty);
                poisonItems(b);
                b.next = .init(null);
                b.pending_next = null;
            }

            fn poisonItems(b: *Block) void {
                if (!std.debug.runtime_safety) return;
                for (&b.slots) |*s| @memset(std.mem.asBytes(&s.value), poison);
            }

            fn allRead(b: *const Block) bool {
                for (&b.slots) |*s| {
                    if (s.state.load(.acquire) != read) return false;
                }
                return true;
            }
        };

        const End = struct {
            index: std.atomic.Value(u64),
            block: std.atomic.Value(*Block),
            /// Head only: a `tail` value some consumer has read — a lower
            /// bound of `tail`, since `tail` only grows. A `pos` below it has
            /// a producer, so `pop` reads `tail` itself (the line producers
            /// CAS) only once the consumers catch up with it. Racy stores
            /// may lower it; a lower bound stays a lower bound.
            tail_seen: std.atomic.Value(u64) = .init(0),
        };

        /// Consumers' end. A line of its own: consumers CAS `index`.
        head: atomic.CachePadded(End) align(atomic.cache_line),
        /// Producers' end, padded like `head`.
        tail: atomic.CachePadded(End) align(atomic.cache_line),
        /// Retired blocks not yet seen fully read: a stack pushed by CAS and
        /// emptied by one swap, so a block on it has no owner but the stack.
        pending: std.atomic.Value(?*Block) align(atomic.cache_line),
        /// One recycled block kept for the next install; swapped, never
        /// dereferenced while shared.
        spare: std.atomic.Value(?*Block),
        allocator: std.mem.Allocator,
        /// The `read_before_copy` control's displaced spares, freed at
        /// `deinit` (a zero-size field otherwise).
        graveyard: if (fault == .read_before_copy) std.atomic.Value(?*Block) else void,

        /// An empty queue with its first block. `allocator` must be
        /// thread-safe: blocks are allocated by producers and freed by
        /// consumers.
        pub fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!Self {
            const b = try allocator.create(Block);
            b.reset();
            return .{
                .head = .init(.{ .index = .init(0), .block = .init(b) }),
                .tail = .init(.{ .index = .init(0), .block = .init(b) }),
                .pending = .init(null),
                .spare = .init(null),
                .allocator = allocator,
                .graveyard = if (fault == .read_before_copy) .init(null) else {},
            };
        }

        /// Free every block. The caller guarantees no thread is inside
        /// `push`/`pop`; unread items are dropped (Zig has no destructors —
        /// `pop` them first if they own memory).
        pub fn deinit(self: *Self) void {
            var cur: ?*Block = self.head.value.block.load(.monotonic);
            while (cur) |b| {
                cur = b.next.load(.monotonic);
                self.allocator.destroy(b);
            }
            var p = self.pending.load(.monotonic);
            while (p) |b| {
                p = b.pending_next;
                self.allocator.destroy(b);
            }
            if (self.spare.load(.monotonic)) |s| self.allocator.destroy(s);
            if (fault == .read_before_copy) {
                var g = self.graveyard.load(.monotonic);
                while (g) |b| {
                    g = b.pending_next;
                    self.allocator.destroy(b);
                }
            }
            self.* = undefined;
        }

        /// A block for the next install: the spare, else a fresh one.
        fn takeBlock(self: *Self) std.mem.Allocator.Error!*Block {
            const b = self.spare.swap(null, .acquire) orelse try self.allocator.create(Block);
            b.reset();
            return b;
        }

        /// Reuse a block nobody references any more (all slots read, or a
        /// pre-allocated block that lost its claim): keep it as the spare,
        /// freeing whatever spare it displaces.
        fn recycle(self: *Self, b: *Block) void {
            b.poisonItems();
            const old = self.spare.swap(b, .acq_rel) orelse return;
            // The positive control recycles (poisons, resets, reuses) under a
            // reader but never frees: a real free would crash the test run
            // instead of failing it with a verdict.
            if (fault == .read_before_copy) {
                var top = self.graveyard.load(.monotonic);
                while (true) {
                    old.pending_next = top;
                    top = self.graveyard.cmpxchgWeak(top, old, .release, .monotonic) orelse return;
                }
            }
            self.allocator.destroy(old);
        }

        fn deferBlock(self: *Self, b: *Block) void {
            var top = self.pending.load(.monotonic);
            while (true) {
                b.pending_next = top;
                top = self.pending.cmpxchgWeak(top, b, .release, .monotonic) orelse return;
            }
        }

        /// `b`'s last position has been consumed and `head` is past it:
        /// recycle what `pending` holds fully read, then park `b` there.
        fn retire(self: *Self, b: *Block) void {
            if (fault == .free_unscanned) b.poisonItems();
            var list = self.pending.swap(null, .acquire);
            while (list) |x| {
                list = x.pending_next;
                if (x.allRead()) self.recycle(x) else self.deferBlock(x);
            }
            self.deferBlock(b);
        }

        /// Append `value`. Fails only when a new block is needed and the
        /// allocator refuses it; the queue is then unchanged.
        pub fn push(self: *Self, value: T) std.mem.Allocator.Error!void {
            // The next lap's block, taken before claiming a lap's last slot
            // and handed back if the claim goes to another thread.
            var next_block: ?*Block = null;
            defer if (next_block) |nb| self.recycle(nb);

            var waiter: Waiter = .{};
            var lost: CasBackoff = .{};
            while (true) {
                const pos = self.tail.value.index.load(.seq_cst);
                const off = pos % lap;
                if (off == closed) {
                    // The last slot's claimant is installing the next block.
                    waiter.wait();
                    continue;
                }
                if (off == closed - 1 and next_block == null) next_block = try self.takeBlock();
                const b = self.tail.value.block.load(.seq_cst);
                if (self.tail.value.index.cmpxchgWeak(pos, pos + 1, .seq_cst, .monotonic) != null) {
                    lost.spin();
                    continue;
                }
                if (off == closed - 1) {
                    // `tail` sits on the closed position: only we move it.
                    // The block goes in before the index leaves the closed
                    // position, so whoever reads the new index reads it.
                    const nb = next_block.?;
                    next_block = null;
                    self.tail.value.block.store(nb, .seq_cst);
                    b.next.store(nb, .release);
                    self.tail.value.index.store(pos + 2, .seq_cst);
                }
                const slot = &b.slots[@intCast(off)];
                if (fault == .skip_ready_wait) {
                    // Widen the claim-to-write window the bug races on: in
                    // optimized code it is a few instructions wide.
                    for (0..256) |_| std.atomic.spinLoopHint();
                }
                slot.value = value;
                slot.state.store(written, .release);
                return;
            }
        }

        /// Remove and return the oldest item, or `null` if the queue is
        /// empty.
        pub fn pop(self: *Self) ?T {
            var waiter: Waiter = .{};
            var lost: CasBackoff = .{};
            while (true) {
                const pos = self.head.value.index.load(.seq_cst);
                const off = pos % lap;
                if (off == closed) {
                    // The last slot's consumer is moving `head` on.
                    waiter.wait();
                    continue;
                }
                // `head` never passes `tail`, so equal is empty; less means
                // `pos` already has a producer (it may not have written yet).
                if (pos >= self.head.value.tail_seen.load(.acquire)) {
                    const t = self.tail.value.index.load(.seq_cst);
                    if (pos == t) return null;
                    self.head.value.tail_seen.store(t, .release);
                }
                const b = self.head.value.block.load(.seq_cst);
                if (self.head.value.index.cmpxchgWeak(pos, pos + 1, .seq_cst, .monotonic) != null) {
                    lost.spin();
                    continue;
                }
                const last = off == closed - 1;
                if (last) {
                    // Our slot's producer is the installer; it has claimed,
                    // so `next` is coming.
                    var w: Waiter = .{};
                    const nb = while (true) {
                        if (b.next.load(.acquire)) |n| break n;
                        w.wait();
                    };
                    self.head.value.block.store(nb, .seq_cst);
                    self.head.value.index.store(pos + 2, .seq_cst);
                }
                const slot = &b.slots[@intCast(off)];
                if (fault != .skip_ready_wait) {
                    var w: Waiter = .{};
                    while (slot.state.load(.acquire) == empty) w.wait();
                }
                if (fault == .read_before_copy) {
                    slot.state.store(read, .release);
                    for (0..256) |_| std.atomic.spinLoopHint();
                }
                const value = slot.value;
                if (fault != .read_before_copy) slot.state.store(read, .release);
                if (last) self.retire(b);
                return value;
            }
        }

        /// Items claimed by producers and not yet by consumers, from one
        /// consistent snapshot of both ends. An item whose producer has
        /// claimed but not finished writing counts.
        pub fn len(self: *const Self) usize {
            while (true) {
                const t = self.tail.value.index.load(.seq_cst);
                const h = self.head.value.index.load(.seq_cst);
                if (self.tail.value.index.load(.seq_cst) == t) return @intCast(slotsBefore(t) - slotsBefore(h));
            }
        }

        /// Whether `pop` would have found the queue empty at this instant.
        pub fn isEmpty(self: *const Self) bool {
            const h = self.head.value.index.load(.seq_cst);
            return h == self.tail.value.index.load(.seq_cst);
        }

        /// Slot positions before `pos`: whole laps of `block_slots`, plus
        /// the offset — the closed position's offset is `block_slots`, the
        /// lap's full count, so it needs no special case.
        fn slotsBefore(pos: u64) u64 {
            return pos / lap * closed + pos % lap;
        }
    };
}

// ── tests: single-threaded first, the stress driver below ───────────────────

const testing = std.testing;

fn fifoAcrossBlocks(comptime slots: usize) !void {
    const Q = SegQueue(u64, .{ .block_slots = slots });
    var q = try Q.init(testing.allocator);
    defer q.deinit();
    // Several rounds, so emptied blocks are recycled through `pending` and
    // the spare, and slot states are reset correctly on reuse.
    for (0..5) |round| {
        const n: u64 = 10 * slots + 3;
        for (0..n) |i| try q.push(round * 1000 + i);
        try testing.expectEqual(@as(usize, n), q.len());
        try testing.expect(!q.isEmpty());
        for (0..n) |i| try testing.expectEqual(@as(?u64, round * 1000 + i), q.pop());
        try testing.expectEqual(@as(?u64, null), q.pop());
        try testing.expect(q.isEmpty());
        try testing.expectEqual(@as(usize, 0), q.len());
    }
}

test "SegQueue is FIFO across block hand-offs, for one-slot, three-slot and default blocks" {
    try fifoAcrossBlocks(1);
    try fifoAcrossBlocks(3);
    try fifoAcrossBlocks(63);
}

test "SegQueue len counts across laps and the closed position" {
    const Q = SegQueue(u32, .{ .block_slots = 3 });
    var q = try Q.init(testing.allocator);
    defer q.deinit();
    for (0..7) |i| {
        try q.push(@intCast(i));
        try testing.expectEqual(i + 1, q.len());
    }
    for (0..7) |i| {
        _ = q.pop();
        try testing.expectEqual(6 - i, q.len());
    }
    try testing.expectEqual(@as(u64, 0), Q.slotsBefore(0));
    try testing.expectEqual(@as(u64, 3), Q.slotsBefore(3)); // the closed position
    try testing.expectEqual(@as(u64, 3), Q.slotsBefore(4)); // next lap, offset 0
    try testing.expectEqual(@as(u64, 5), Q.slotsBefore(6));
}

test "SegQueue carries a payload wider than a word" {
    const Item = struct { a: u64, b: [3]u32, tag: u8 };
    var q = try SegQueue(Item, .{ .block_slots = 7 }).init(testing.allocator);
    defer q.deinit();
    for (0..100) |i| try q.push(.{ .a = i, .b = .{ @intCast(i), @intCast(i * 2), @intCast(i * 3) }, .tag = @truncate(i) });
    for (0..100) |i| {
        const it = q.pop().?;
        try testing.expectEqual(@as(u64, i), it.a);
        try testing.expectEqual([3]u32{ @intCast(i), @intCast(i * 2), @intCast(i * 3) }, it.b);
        try testing.expectEqual(@as(u8, @truncate(i)), it.tag);
    }
    try testing.expectEqual(@as(?Item, null), q.pop());
}

test "SegQueue push that cannot get a block fails before claiming: the queue is unchanged" {
    const Q = SegQueue(u64, .{ .block_slots = 3 });
    // Allocation 0 is `init`'s block; the second block is needed at the
    // third push (the lap's last slot).
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    var q = try Q.init(failing.allocator());
    defer q.deinit();
    try q.push(1);
    try q.push(2);
    try testing.expectError(error.OutOfMemory, q.push(3));
    try testing.expectEqual(@as(usize, 2), q.len());
    // The claim was never made: the last slot is still free, and the queue
    // keeps working once the allocator does.
    failing.fail_index = std.math.maxInt(usize);
    try q.push(3);
    try q.push(4);
    for (1..5) |i| try testing.expectEqual(@as(?u64, i), q.pop());
    try testing.expectEqual(@as(?u64, null), q.pop());
}

test "SegQueue resets its first block: init on reused, dirty memory" {
    // A fresh page reads as zeroes, which happen to be an empty slot and a
    // null link; reused memory does not. Every byte 0xFF: a slot state that
    // is not `empty` and a `next` that is not null, unless `init` resets.
    const Q = SegQueue(u64, .{ .block_slots = 3 });
    var buf: [@sizeOf(Q.Block) + 64]u8 align(64) = undefined;
    @memset(&buf, 0xFF);
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    var q = try Q.init(fba.allocator());
    defer q.deinit();
    try testing.expect(q.isEmpty());
    try testing.expectEqual(@as(?u64, null), q.pop());
    try q.push(7);
    try testing.expectEqual(@as(?u64, 7), q.pop());
}

test "SegQueue keeps one spare block: a steady flow stops allocating" {
    const Q = SegQueue(u64, .{ .block_slots = 3 });
    var counting = std.testing.FailingAllocator.init(testing.allocator, .{});
    var q = try Q.init(counting.allocator());
    defer q.deinit();
    // Fill and drain one lap at a time. A drained block waits on `pending`
    // for the next hand-off's scan, then becomes the spare the install after
    // that takes: two laps of warm-up, then three blocks circulate.
    for (0..6) |i| try q.push(i);
    for (0..6) |_| _ = q.pop();
    const after_warmup = counting.allocations;
    for (0..50) |r| {
        for (0..3) |i| try q.push(r * 3 + i);
        for (0..3) |i| try testing.expectEqual(@as(?u64, r * 3 + i), q.pop());
    }
    try testing.expectEqual(after_warmup, counting.allocations);
}

// ── concurrent: the harness's stress driver ─────────────────────────────────

const harness = @import("harness.zig");

fn Adapter(comptime Q: type) type {
    return struct {
        q: *Q,
        const Self = @This();
        pub const ThreadCtx = void;
        pub fn initThread(self: *Self) !ThreadCtx {
            _ = self;
        }
        pub fn deinitThread(self: *Self, ctx: ThreadCtx) void {
            _ = self;
            _ = ctx;
        }
        pub fn enqueue(self: *Self, ctx: ThreadCtx, v: u64) !void {
            _ = ctx;
            try self.q.push(v);
        }
        pub fn dequeue(self: *Self, ctx: ThreadCtx) ?u64 {
            _ = ctx;
            return self.q.pop();
        }
    };
}

fn stress(comptime Q: type, cfg: harness.StressConfig) !harness.Verdict {
    var q = try Q.init(testing.allocator);
    defer q.deinit();
    var adapter: Adapter(Q) = .{ .q = &q };
    const v = try harness.runStress(Adapter(Q), &adapter, cfg, testing.allocator);
    if (v == .clean) try testing.expect(q.isEmpty());
    return v;
}

test "SEGQUEUE: N×M stress, no lost/dup/corrupt/reordered item, for 1-, 3- and 63-slot blocks" {
    const cfg: harness.StressConfig = .{ .producers = 8, .consumers = 8, .per_producer = 50_000 };
    // One-slot blocks: every push installs a block and every pop frees one,
    // so the hand-off and the reclaim run on every item.
    try testing.expectEqual(harness.Verdict.clean, try stress(SegQueue(u64, .{ .block_slots = 1 }), cfg));
    try testing.expectEqual(harness.Verdict.clean, try stress(SegQueue(u64, .{ .block_slots = 3 }), cfg));
    try testing.expectEqual(harness.Verdict.clean, try stress(SegQueue(u64, .{}), cfg));
}

test "SEGQUEUE: N×1 and 1×N stress" {
    try testing.expectEqual(harness.Verdict.clean, try stress(SegQueue(u64, .{ .block_slots = 3 }), .{ .producers = 8, .consumers = 1, .per_producer = 50_000 }));
    try testing.expectEqual(harness.Verdict.clean, try stress(SegQueue(u64, .{ .block_slots = 3 }), .{ .producers = 1, .consumers = 8, .per_producer = 200_000 }));
}

/// A positive control must bite in at least one of a few rounds. The teeth
/// are the poisoned item bytes, written only in safety-checked builds.
fn expectCaught(comptime Q: type) !void {
    if (!std.debug.runtime_safety) return error.SkipZigTest;
    for (0..6) |_| {
        if (try stress(Q, .{ .producers = 6, .consumers = 6, .per_producer = 50_000 }) != .clean) return;
    }
    return error.TestExpectedCaught;
}

test "SEGQUEUE DRIVER TEETH: a pop that skips the ready wait is caught (high probability)" {
    try expectCaught(Impl(u64, .{ .block_slots = 3 }, .skip_ready_wait));
}

test "SEGQUEUE DRIVER TEETH: a block freed at retire, without the scan, is caught (high probability)" {
    try expectCaught(Impl(u64, .{ .block_slots = 3 }, .free_unscanned));
}

test "SEGQUEUE DRIVER TEETH: a pop that stores read before copying is caught (high probability)" {
    try expectCaught(Impl(u64, .{ .block_slots = 3 }, .read_before_copy));
}
