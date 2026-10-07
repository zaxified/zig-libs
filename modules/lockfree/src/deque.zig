// SPDX-License-Identifier: MIT

//! deque — a Chase-Lev work-stealing deque: one OWNER thread pushes and pops
//! at the bottom (LIFO, for cache locality of the work it just created), any
//! number of THIEF threads steal from the top (FIFO, the oldest work). The
//! counterpart of crossbeam's `deque` (`Worker::new_lifo` + `Stealer`), and
//! the structure a work-stealing scheduler gives each worker.
//!
//! References: Chase & Lev, "Dynamic Circular Work-Stealing Deque" (SPAA
//! 2005), and Lê, Pop, Cohen & Zappa Nardelli, "Correct and Efficient
//! Work-Stealing for Weak Memory Models" (PPoPP 2013), whose C11 version
//! places two fences this file cannot write — see "Ordering" below.
//!
//! **Protocol.** Indices `top` (thieves) and `bottom` (owner) only grow,
//! except that `pop` lowers `bottom` by one while it decides. The items are
//! the positions `top ≤ i < bottom`, position `i` in slot `i mod capacity` of
//! the current buffer.
//!
//!  • `push` (owner): write slot `bottom`, then publish `bottom + 1`.
//!  • `pop` (owner): announce `bottom - 1`, then read `top`. More than one item
//!    left → the bottom one is the owner's, no CAS. Exactly one → race the
//!    thieves for it with a CAS on `top`. None → put `bottom` back.
//!  • `steal` (thief): read `top`, then `bottom`; if `top < bottom`, read the
//!    item at `top` and claim it with a CAS `top → top + 1`. A lost CAS is
//!    `.retry`: someone else took that position.
//!
//! **Ordering — `seq_cst` where the two ends meet, because Zig 0.16 has no
//! fence.** The paper's `pop` is "store `bottom`; seq_cst fence; load `top`"
//! and its `steal` is "load `top`; seq_cst fence; load `bottom`". Without
//! `@fence` the substitute — the same one `ebr.zig` uses (SPEC §4a) — is to
//! make the four accesses themselves `.seq_cst`: `pop`'s store of `bottom`
//! and load of `top`, `steal`'s loads of `top` and `bottom`, and every CAS on
//! `top`. They then share the single total order S, and S forbids the
//! store-buffering outcome in which `pop` takes the bottom item without a CAS
//! while a thief takes the same item:
//!
//!   Suppose `pop` lowered `bottom` to `b`, read `top = t < b` (so took slot
//!   `b` uncontested), and a thief claimed position `b` — so it read
//!   `top = b` and `bottom > b`, i.e. the value before `pop`'s store. A
//!   `seq_cst` load that reads a value older than a `seq_cst` store must
//!   precede that store in S: thief-load(bottom) <S pop-store(bottom). By
//!   program order thief-load(top) <S thief-load(bottom), and pop-store(bottom)
//!   <S pop-load(top). The CAS that made `top = b` precedes the thief's load
//!   that read it, so it precedes `pop`'s load of `top` in S too, and that load
//!   — `top` only grows — must read at least `b`. It read `t < b`:
//!   contradiction. When exactly one item is left both sides CAS `top` from
//!   the same value and exactly one CAS wins.
//!
//! `push`'s publish of `bottom` is `.release` and the thief's `seq_cst` load
//! of `bottom` acquires it: message passing, so the slot write happens-before
//! the thief's slot read (the §7.1 `msqueue-*-rel-acq` shape). The owner's
//! own accesses (its reads of `bottom` and of the buffer pointer, restoring
//! `bottom`) need no ordering: it is their only writer.
//!
//! **Slots are atomic, so `T` is word-sized.** A thief reads the item at
//! `top` BEFORE its claiming CAS, and if the CAS loses, the owner may be
//! writing that very slot on its next lap. With a plain `T` that read is a
//! data race even though the value is then thrown away; with an atomic
//! (monotonic) slot it is merely stale. So `T` must fit `std.atomic.Value`
//! and at most a machine word — a pointer, an index or a small integer, which
//! is what a scheduler queues anyway (crossbeam allows any `T` and accepts the
//! racy read). Larger payloads: queue pointers to them.
//!
//! **Growth, and why thieves need no epoch pin.** A full `push` allocates a
//! buffer twice the size, copies the live positions, and publishes it with a
//! release store; a thief acquires the pointer after reading `bottom`, so it
//! sees a buffer holding the position it read. The OLD buffer is not freed:
//! a thief that loaded the pointer just before the swap may still read from
//! it (harmlessly — the owner never writes an old buffer again, and a stale
//! read only loses the CAS). Old buffers are kept until `deinit`; capacities
//! double, so together they hold fewer slots than the current buffer, and
//! the deque never shrinks. crossbeam frees them through its epoch scheme
//! instead; keeping them is what lets `steal` stay a handful of loads and one
//! CAS, with no participant to register. (The trade-off is SPEC §4c.)
//!
//! **Threads.** `push` and `pop` from the owner thread only — two owners is a
//! data race the type cannot detect. `steal`, `len` and `isEmpty` from any
//! thread. `init` and `deinit` with no other thread touching the deque.

const std = @import("std");
const atomic = @import("atomic.zig");

/// What a `steal` got.
pub fn Steal(comptime T: type) type {
    return union(enum) {
        /// The deque read empty.
        empty,
        /// Another thief (or the owner's `pop` of the last item) claimed the
        /// position first. Not empty — trying again may succeed.
        retry,
        /// The oldest item, now this thief's.
        success: T,
    };
}

/// A growable Chase-Lev work-stealing deque of `T`. `T` must be atomic-capable
/// (integer, bool, enum, pointer or optional pointer) and at most one machine
/// word; see the file comment for why.
pub fn Deque(comptime T: type) type {
    if (@sizeOf(T) > @sizeOf(usize)) {
        @compileError("Deque item type " ++ @typeName(T) ++ " is wider than a machine word: a thief reads a slot it may then lose, so slots are atomic — queue a pointer or an index instead");
    }
    return struct {
        const Self = @This();

        const Buffer = struct {
            /// `capacity - 1`; capacity is a power of two.
            mask: usize,
            slots: []std.atomic.Value(T),

            fn create(allocator: std.mem.Allocator, slot_count: usize) !*Buffer {
                const b = try allocator.create(Buffer);
                errdefer allocator.destroy(b);
                const slots = try allocator.alloc(std.atomic.Value(T), slot_count);
                b.* = .{ .mask = slot_count - 1, .slots = slots };
                return b;
            }

            fn destroy(b: *Buffer, allocator: std.mem.Allocator) void {
                allocator.free(b.slots);
                allocator.destroy(b);
            }

            fn put(b: *Buffer, i: isize, item: T) void {
                b.slots[@as(usize, @bitCast(i)) & b.mask].store(item, .monotonic);
            }

            fn get(b: *const Buffer, i: isize) T {
                return b.slots[@as(usize, @bitCast(i)) & b.mask].load(.monotonic);
            }
        };

        // Plain (non-wrapping) index arithmetic throughout: positions are
        // `isize` and grow by one per push, so overflow needs 2^63 pushes.

        /// Next position a thief claims. Only grows, only by CAS.
        top: std.atomic.Value(isize) align(atomic.cache_line),
        /// One past the owner's newest item. Written by the owner only.
        bottom: std.atomic.Value(isize) align(atomic.cache_line),
        /// The current buffer. Written by the owner only (on growth).
        buffer: std.atomic.Value(*Buffer),
        /// Buffers replaced by growth, kept for thieves still reading them and
        /// freed by `deinit`. Owner only.
        retired: std.ArrayListUnmanaged(*Buffer),
        allocator: std.mem.Allocator,

        /// An empty deque whose first buffer holds `min_capacity` items
        /// (rounded up to a power of two, at least 2). It grows on demand.
        pub fn init(allocator: std.mem.Allocator, min_capacity: usize) !Self {
            const cap = std.math.ceilPowerOfTwo(usize, @max(min_capacity, 2)) catch return error.OutOfMemory;
            const b = try Buffer.create(allocator, cap);
            return .{
                .top = .init(0),
                .bottom = .init(0),
                .buffer = .init(b),
                .retired = .empty,
                .allocator = allocator,
            };
        }

        /// Free every buffer. No other thread may touch the deque any more;
        /// items still in it are dropped (they are plain values).
        pub fn deinit(d: *Self) void {
            d.buffer.load(.monotonic).destroy(d.allocator);
            for (d.retired.items) |b| b.destroy(d.allocator);
            d.retired.deinit(d.allocator);
            d.* = undefined;
        }

        /// Owner only: add `item` at the bottom. `error.OutOfMemory` only when
        /// the deque is full and cannot grow; the item is then not added.
        pub fn push(d: *Self, item: T) error{OutOfMemory}!void {
            const b = d.bottom.load(.monotonic);
            // Acquire: pairs with a thief's claiming CAS, so its read of the
            // slot we are about to reuse happens-before our overwrite.
            const t = d.top.load(.acquire);
            var buf = d.buffer.load(.monotonic);
            if (b - t > @as(isize, @intCast(buf.mask))) buf = try d.grow(buf, t, b);
            buf.put(b, item);
            // Release: the slot write happens-before a thief's read of it,
            // through the thief's load of `bottom`.
            d.bottom.store(b + 1, .release);
        }

        /// Owner only, with `bottom - top == capacity`: a buffer twice the
        /// size holding positions `t..b`, published for thieves.
        fn grow(d: *Self, old: *Buffer, t: isize, b: isize) error{OutOfMemory}!*Buffer {
            // Reserve the retired entry first: once the new buffer is
            // published the old one must be kept, and that must not fail.
            try d.retired.ensureUnusedCapacity(d.allocator, 1);
            const new = try Buffer.create(d.allocator, (old.mask + 1) * 2);
            var i = t;
            while (i < b) : (i += 1) new.put(i, old.get(i));
            // Release: the copies happen-before any thief's read through the
            // new pointer (it acquires the pointer below).
            d.buffer.store(new, .release);
            d.retired.appendAssumeCapacity(old);
            return new;
        }

        /// Owner only: take the newest item, or null when the deque is empty
        /// (every item pushed so far was popped or stolen).
        pub fn pop(d: *Self) ?T {
            const b = d.bottom.load(.monotonic) - 1;
            const buf = d.buffer.load(.monotonic);
            // seq_cst store, then seq_cst load of `top`: the Dekker pair of
            // the file comment. Announcing `b` first is what stops a thief
            // that reads it from taking position `b`.
            d.bottom.store(b, .seq_cst);
            const t = d.top.load(.seq_cst);
            if (t > b) {
                // Empty: every position below the old bottom is claimed.
                d.bottom.store(b + 1, .monotonic);
                return null;
            }
            const item = buf.get(b);
            if (t == b) {
                // The last item: thieves may be claiming it too. Exactly one
                // CAS moves `top` off `t`.
                const won = d.top.cmpxchgStrong(t, t + 1, .seq_cst, .monotonic) == null;
                d.bottom.store(b + 1, .monotonic);
                return if (won) item else null;
            }
            // More than one: `t < b`, and no thief can claim position `b` —
            // a thief that saw the old bottom loses the race the comment proves.
            return item;
        }

        /// Any thread: take the oldest item.
        pub fn steal(d: *Self) Steal(T) {
            // seq_cst, and `top` before `bottom`: the thief's half of the
            // Dekker pair.
            const t = d.top.load(.seq_cst);
            const b = d.bottom.load(.seq_cst);
            if (t >= b) return .empty;
            // Acquire: pairs with `grow`'s publish, so a buffer published
            // before the push of position `t` (which our load of `bottom`
            // saw) is seen with its copies.
            const buf = d.buffer.load(.acquire);
            // Read BEFORE the claim: after it the owner may reuse the slot.
            // If the claim loses, the value is stale and dropped.
            const item = buf.get(t);
            if (d.top.cmpxchgStrong(t, t + 1, .seq_cst, .monotonic) != null) return .retry;
            return .{ .success = item };
        }

        /// Any thread: items not yet claimed, at one instant (a snapshot,
        /// stale as soon as it returns; may count the item an owner's `pop`
        /// is deciding about).
        pub fn len(d: *const Self) usize {
            while (true) {
                const t = d.top.load(.seq_cst);
                const b = d.bottom.load(.seq_cst);
                // `top` only grows, so if it still reads `t`, it was `t` when
                // `bottom` was read and the pair is one instant. Without the
                // re-check the owner can push and pop-the-last (moving `top`)
                // between the two loads, and `b - t` counts items that never
                // coexisted (the concurrent test below saw 2 for a deque that
                // never held more than 1).
                if (d.top.load(.seq_cst) != t) continue;
                const n = b - t;
                // Negative while an owner's `pop` of an empty deque has
                // lowered `bottom` and not yet put it back: empty.
                return if (n > 0) @intCast(n) else 0;
            }
        }

        pub fn isEmpty(d: *const Self) bool {
            return d.len() == 0;
        }

        /// Owner (or quiescent): slots in the current buffer.
        pub fn capacity(d: *const Self) usize {
            return d.buffer.load(.monotonic).mask + 1;
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Deque: owner pops LIFO, thieves steal FIFO, empty reads empty" {
    var d = try Deque(u64).init(testing.allocator, 8);
    defer d.deinit();
    try testing.expectEqual(@as(?u64, null), d.pop());
    try testing.expectEqual(Steal(u64).empty, d.steal());
    for (1..6) |i| try d.push(i);
    try testing.expectEqual(@as(usize, 5), d.len());
    try testing.expectEqual(@as(?u64, 5), d.pop());
    try testing.expectEqual(Steal(u64){ .success = 1 }, d.steal());
    try testing.expectEqual(Steal(u64){ .success = 2 }, d.steal());
    try testing.expectEqual(@as(?u64, 4), d.pop());
    // One left: both ends reach it, whichever comes first takes it.
    try testing.expectEqual(@as(?u64, 3), d.pop());
    try testing.expectEqual(@as(?u64, null), d.pop());
    try testing.expectEqual(Steal(u64).empty, d.steal());
    try testing.expect(d.isEmpty());
    // An empty pop restored `bottom`: the deque still works.
    try d.push(7);
    try testing.expectEqual(Steal(u64){ .success = 7 }, d.steal());
    try testing.expectEqual(@as(?u64, null), d.pop());
}

test "Deque: the last item goes to exactly one of pop and steal" {
    var d = try Deque(u32).init(testing.allocator, 2);
    defer d.deinit();
    try d.push(1);
    try testing.expectEqual(Steal(u32){ .success = 1 }, d.steal());
    try testing.expectEqual(@as(?u32, null), d.pop());
    try d.push(2);
    try testing.expectEqual(@as(?u32, 2), d.pop());
    try testing.expectEqual(Steal(u32).empty, d.steal());
}

test "Deque: growth from capacity 2 keeps every item and both orders" {
    var d = try Deque(usize).init(testing.allocator, 1);
    defer d.deinit();
    try testing.expectEqual(@as(usize, 2), d.capacity());
    // Steal a few first so the live range does not start at slot 0: the copy
    // must follow positions, not slot indices.
    for (0..3) |i| try d.push(i);
    for (0..3) |i| try testing.expectEqual(Steal(usize){ .success = i }, d.steal());
    for (3..1003) |i| try d.push(i);
    try testing.expect(d.capacity() >= 1000);
    try testing.expectEqual(@as(usize, 1000), d.len());
    // Oldest from the top, newest from the bottom, nothing lost in between.
    for (3..503) |i| try testing.expectEqual(Steal(usize){ .success = i }, d.steal());
    var i: usize = 1003;
    while (i > 503) {
        i -= 1;
        try testing.expectEqual(@as(?usize, i), d.pop());
    }
    try testing.expectEqual(@as(?usize, null), d.pop());
}

test "Deque: positions wrap the buffer many times without growing" {
    var d = try Deque(u64).init(testing.allocator, 4);
    defer d.deinit();
    var next_in: u64 = 0;
    var next_out: u64 = 0;
    for (0..1000) |round| {
        const fill = round % 4 + 1;
        for (0..fill) |_| {
            try d.push(next_in);
            next_in += 1;
        }
        for (0..fill) |_| {
            try testing.expectEqual(Steal(u64){ .success = next_out }, d.steal());
            next_out += 1;
        }
    }
    try testing.expectEqual(@as(usize, 4), d.capacity());
}

test "Deque: a thief stalled between its reads and its claim loses to the owner" {
    // Driven by hand. A thief reads `top` and `bottom` and the item, then the
    // owner pops the last item (its CAS moves `top`), then the thief's CAS
    // must fail: `.retry`, and the item is not handed out twice.
    var d = try Deque(u64).init(testing.allocator, 4);
    defer d.deinit();
    try d.push(42);
    const t = d.top.load(.seq_cst);
    try testing.expect(t < d.bottom.load(.seq_cst));
    const seen = d.buffer.load(.acquire).get(t);
    try testing.expectEqual(@as(u64, 42), seen);
    try testing.expectEqual(@as(?u64, 42), d.pop());
    try testing.expect(d.top.cmpxchgStrong(t, t + 1, .seq_cst, .monotonic) != null);
    try testing.expectEqual(Steal(u64).empty, d.steal());
}

test "Deque: a stalled thief reading a retired buffer still loses or reads its position" {
    // A thief loads the buffer pointer, the owner grows (the old buffer is
    // retired, not freed), and the thief reads its position from the OLD
    // buffer: the value there is still the item of that position, because
    // the owner never writes a retired buffer again.
    var d = try Deque(u64).init(testing.allocator, 2);
    defer d.deinit();
    try d.push(10);
    try d.push(11);
    const old = d.buffer.load(.acquire);
    try d.push(12); // grows
    try testing.expect(d.buffer.load(.acquire) != old);
    try testing.expectEqual(@as(usize, 1), d.retired.items.len);
    try testing.expectEqual(@as(u64, 10), old.get(0));
    try testing.expectEqual(Steal(u64){ .success = 10 }, d.steal());
    try testing.expectEqual(@as(?u64, 12), d.pop());
    try testing.expectEqual(@as(?u64, 11), d.pop());
}

test "Deque: a push that cannot grow fails cleanly and keeps the deque intact" {
    // Allow init's two allocations, then refuse: the third push needs a
    // bigger buffer.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 2 });
    var d = try Deque(u64).init(failing.allocator(), 2);
    defer d.deinit();
    try d.push(1);
    try d.push(2);
    try testing.expectError(error.OutOfMemory, d.push(3));
    try testing.expectEqual(@as(usize, 2), d.len());
    try testing.expectEqual(@as(?u64, 2), d.pop());
    try testing.expectEqual(Steal(u64){ .success = 1 }, d.steal());
}

test "Deque: pointer payloads" {
    var items = [_]u32{ 1, 2, 3 };
    var d = try Deque(*u32).init(testing.allocator, 2);
    defer d.deinit();
    for (&items) |*p| try d.push(p);
    try testing.expectEqual(&items[2], d.pop().?);
    try testing.expectEqual(Steal(*u32){ .success = &items[0] }, d.steal());
}

test "Deque: len from another thread never goes negative while the owner pops an empty deque" {
    // An empty `pop` lowers `bottom` below `top` for a moment before putting
    // it back, so a concurrent `len` can read `bottom - top = -1`; it must
    // report 0, not cast -1 (a panic in safe builds, a huge count otherwise).
    var d = try Deque(u64).init(testing.allocator, 4);
    defer d.deinit();
    const Owner = struct {
        fn run(dq: *Deque(u64), done: *std.atomic.Value(bool)) void {
            // Every iteration: an empty pop (the negative transient) and a
            // push + pop-the-last (which moves `top`, the torn-pair window).
            for (0..2_000_000) |i| {
                std.debug.assert(dq.pop() == null);
                dq.push(i) catch unreachable;
                std.debug.assert(dq.pop() == i);
            }
            done.store(true, .release);
        }
    };
    var done: std.atomic.Value(bool) = .init(false);
    const t = try std.Thread.spawn(.{}, Owner.run, .{ &d, &done });
    var worst: usize = 0;
    while (!done.load(.acquire)) worst = @max(worst, d.len());
    t.join();
    try testing.expect(worst <= 1);
}
