// SPDX-License-Identifier: MIT
//! `WorkQueue(Key)` — the bounded, deduplicating, timer-backed work queue the
//! reconciler drives. Independently useful and independently testable; it
//! knows nothing about reconciling.
//!
//! Structure (all of it allocated exactly once, at `init`):
//!
//! - a **slot arena** of `capacity` entries, addressed by `u32` index. Slot
//!   addresses are stable for the queue's lifetime, which is what lets the
//!   FIFO and the timer heap link through them by index;
//! - a **hash index** `Key -> slot`, pre-sized to `capacity` so `enqueue`
//!   never rehashes and never allocates;
//! - an intrusive doubly-linked **ready FIFO** (`prev`/`next` in the slot);
//! - an **indexed binary min-heap** of waiting slots, ordered by
//!   `(due_at, seq)`. Each slot stores its own heap position, so removing or
//!   rescheduling a waiting key is an exact O(log n) operation.
//!
//! The indexed heap is the reason the bound holds. The textbook alternative —
//! push a new heap node on every reschedule and skip stale ones on pop — makes
//! the heap grow with the *number of reschedules* rather than the number of
//! keys, which is unbounded in exactly the workload a reconciler generates
//! (one key flapping forever). See SPEC.md §5 and the bound test at the bottom
//! of this file.
//!
//! Every slot is in exactly one of four states, and the invariant
//! `tracked == ready_len + heap_len + running_len <= capacity` is checked by
//! `assertInvariants` (debug builds and tests).

const std = @import("std");
const types = @import("types.zig");

const Instant = types.Instant;
const Admission = types.Admission;

pub const nil: u32 = std.math.maxInt(u32);

pub fn WorkQueue(comptime Key: type) type {
    types.assertPlainKey(Key);

    return struct {
        const Self = @This();

        pub const State = enum(u8) { free, ready, waiting, running };

        pub const Slot = struct {
            key: Key,
            state: State,
            /// Ready-FIFO links when `.ready`; `next` doubles as the free-list
            /// link when `.free`.
            prev: u32,
            next: u32,
            /// Index into `heap` when `.waiting`, else `nil`.
            heap_pos: u32,
            /// Scheduled wake instant when `.waiting`.
            due_at: Instant,
            /// Tiebreak for equal `due_at`, so promotion order is deterministic.
            seq: u64,
            /// Consecutive failed reconciles; drives the caller's backoff.
            failures: u32,
            /// `enqueue` arrived while `.running` — re-queue immediately when
            /// the pass returns.
            dirty: bool,
            /// `enqueueAfter` arrived while `.running`; `null` = none. The
            /// earliest such request wins, and `dirty` beats all of them.
            ///
            /// This is an `?Instant` and not an in-band sentinel on purpose:
            /// `now +| delay_ns` saturates at `maxInt(Instant)`, which is a
            /// legal (if very distant) deadline, so any in-band "none" value
            /// would be forgeable by a caller asking for a long delay — and
            /// the key would then be dropped instead of parked.
            dirty_due: ?Instant,
            /// `forget` arrived while `.running` — drop when the pass returns,
            /// whatever the pass asks for.
            force_drop: bool,
        };

        /// The earlier of two optional deadlines; `null` means "not requested"
        /// and therefore never wins over a real deadline.
        fn earlierDue(a: ?Instant, b: ?Instant) ?Instant {
            const x = a orelse return b;
            const y = b orelse return x;
            return @min(x, y);
        }

        gpa: std.mem.Allocator,
        slots: []Slot,
        heap: []u32,
        index: std.AutoHashMapUnmanaged(Key, u32),
        capacity: u32,
        free_head: u32,
        ready_head: u32,
        ready_tail: u32,
        ready_len: u32,
        heap_len: u32,
        running_len: u32,
        tracked: u32,
        seq_counter: u64,

        pub fn init(gpa: std.mem.Allocator, capacity: u32) !Self {
            std.debug.assert(capacity >= 1);
            const slots = try gpa.alloc(Slot, capacity);
            errdefer gpa.free(slots);
            const heap = try gpa.alloc(u32, capacity);
            errdefer gpa.free(heap);

            var index: std.AutoHashMapUnmanaged(Key, u32) = .empty;
            errdefer index.deinit(gpa);
            // Pre-size once so no later `enqueue` can allocate or rehash.
            try index.ensureTotalCapacity(gpa, capacity);

            for (slots, 0..) |*s, i| {
                s.* = .{
                    .key = undefined,
                    .state = .free,
                    .prev = nil,
                    .next = if (i + 1 < capacity) @intCast(i + 1) else nil,
                    .heap_pos = nil,
                    .due_at = 0,
                    .seq = 0,
                    .failures = 0,
                    .dirty = false,
                    .dirty_due = null,
                    .force_drop = false,
                };
            }

            return .{
                .gpa = gpa,
                .slots = slots,
                .heap = heap,
                .index = index,
                .capacity = capacity,
                .free_head = 0,
                .ready_head = nil,
                .ready_tail = nil,
                .ready_len = 0,
                .heap_len = 0,
                .running_len = 0,
                .tracked = 0,
                .seq_counter = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            self.index.deinit(self.gpa);
            self.gpa.free(self.heap);
            self.gpa.free(self.slots);
            self.* = undefined;
        }

        // ── admission ───────────────────────────────────────────────────────

        /// Queue `key` to run as soon as the caller drains. Idempotent: a key
        /// already ready keeps its FIFO position (so a hot key cannot starve a
        /// cold one by re-announcing itself), a waiting key is pulled forward,
        /// a running key is marked dirty.
        pub fn enqueue(self: *Self, key: Key) types.Error!Admission {
            if (self.index.get(key)) |idx| {
                const s = &self.slots[idx];
                switch (s.state) {
                    .ready => return .deduped,
                    .waiting => {
                        self.heapRemove(idx);
                        self.readyPush(idx);
                        return .promoted;
                    },
                    .running => {
                        s.dirty = true;
                        return .marked_dirty;
                    },
                    .free => unreachable,
                }
            }
            const idx = try self.allocSlot(key);
            self.readyPush(idx);
            return .admitted;
        }

        /// Queue `key` to run at `now + delay_ns`. For an already-waiting key
        /// the **earlier** deadline wins (a reconciler that learns of a sooner
        /// obligation must not have it pushed out); an already-ready key stays
        /// ready, since immediate work outranks deferred work.
        pub fn enqueueAfter(self: *Self, key: Key, now: Instant, delay_ns: u64) types.Error!Admission {
            const due = now +| delay_ns;
            if (self.index.get(key)) |idx| {
                const s = &self.slots[idx];
                switch (s.state) {
                    .ready => return .deduped,
                    .waiting => {
                        if (due < s.due_at) self.reschedule(idx, due);
                        return .deduped;
                    },
                    .running => {
                        s.dirty_due = earlierDue(s.dirty_due, due);
                        return .marked_dirty;
                    },
                    .free => unreachable,
                }
            }
            const idx = try self.allocSlot(key);
            self.heapPush(idx, due);
            return .admitted;
        }

        /// Drop the key entirely, including its failure streak. Returns false
        /// if it was not tracked. A `.running` key cannot be forgotten
        /// mid-pass — its dirty flags are cleared instead, so it is dropped
        /// when the pass returns.
        pub fn forget(self: *Self, key: Key) bool {
            const idx = self.index.get(key) orelse return false;
            const s = &self.slots[idx];
            switch (s.state) {
                .ready => self.readyRemove(idx),
                .waiting => self.heapRemove(idx),
                .running => {
                    s.dirty = false;
                    s.dirty_due = null;
                    s.failures = 0;
                    s.force_drop = true;
                    return true;
                },
                .free => unreachable,
            }
            self.freeSlot(idx);
            return true;
        }

        // ── draining ────────────────────────────────────────────────────────

        /// Move every waiting key whose deadline has arrived to the tail of the
        /// ready FIFO, earliest-deadline first. Returns how many moved.
        pub fn promoteDue(self: *Self, now: Instant) u32 {
            var moved: u32 = 0;
            while (self.heap_len > 0) {
                const idx = self.heap[0];
                if (self.slots[idx].due_at > now) break;
                self.heapRemove(idx);
                self.readyPush(idx);
                moved += 1;
            }
            return moved;
        }

        /// Take the head of the ready FIFO and mark it `.running`. The caller
        /// MUST pair every `takeReady` with exactly one `finish`.
        pub fn takeReady(self: *Self) ?u32 {
            const idx = self.ready_head;
            if (idx == nil) return null;
            self.readyRemove(idx);
            const s = &self.slots[idx];
            s.state = .running;
            s.dirty = false;
            s.dirty_due = null;
            s.force_drop = false;
            self.running_len += 1;
            return idx;
        }

        /// How a finished pass disposes of its slot.
        pub const Finish = union(enum) {
            /// Drop the key (converged, or abandoned).
            drop,
            /// Re-run after this many nanoseconds from `now`.
            after: u64,
        };

        /// Close out a `takeReady`. A re-enqueue that arrived *during* the pass
        /// overrides `disposition`: an immediate `enqueue` wins outright, and a
        /// deferred one wins if it is sooner than what the pass asked for.
        /// That is what makes a mid-pass enqueue impossible to lose.
        pub fn finish(self: *Self, idx: u32, now: Instant, disposition: Finish) void {
            const s = &self.slots[idx];
            std.debug.assert(s.state == .running);
            self.running_len -= 1;
            s.state = .free; // provisional; every branch below re-states it

            if (s.force_drop) {
                s.force_drop = false;
                self.freeSlot(idx);
                return;
            }
            if (s.dirty) {
                s.dirty = false;
                s.dirty_due = null;
                self.readyPush(idx);
                return;
            }
            const asked: ?Instant = switch (disposition) {
                .drop => null,
                .after => |d| now +| d,
            };
            const due = earlierDue(asked, s.dirty_due) orelse {
                // Neither the pass nor a mid-pass request wants this key back.
                s.dirty_due = null;
                self.freeSlot(idx);
                return;
            };
            s.dirty_due = null;
            if (due <= now) {
                self.readyPush(idx);
            } else {
                self.heapPush(idx, due);
            }
        }

        // ── queries ─────────────────────────────────────────────────────────

        pub fn contains(self: *const Self, key: Key) bool {
            return self.index.contains(key);
        }

        pub fn stateOf(self: *const Self, key: Key) ?State {
            const idx = self.index.get(key) orelse return null;
            return self.slots[idx].state;
        }

        pub fn failuresOf(self: *const Self, key: Key) ?u32 {
            const idx = self.index.get(key) orelse return null;
            return self.slots[idx].failures;
        }

        /// Earliest instant at which `promoteDue` would move something, or null.
        pub fn nextTimer(self: *const Self) ?Instant {
            if (self.heap_len == 0) return null;
            return self.slots[self.heap[0]].due_at;
        }

        pub fn slotKey(self: *const Self, idx: u32) Key {
            return self.slots[idx].key;
        }

        pub fn slotFailures(self: *const Self, idx: u32) u32 {
            return self.slots[idx].failures;
        }

        pub fn setSlotFailures(self: *Self, idx: u32, n: u32) void {
            self.slots[idx].failures = n;
        }

        // ── internals ───────────────────────────────────────────────────────

        fn allocSlot(self: *Self, key: Key) types.Error!u32 {
            if (self.free_head == nil) return types.Error.AtCapacity;
            const idx = self.free_head;
            const s = &self.slots[idx];
            self.free_head = s.next;
            s.* = .{
                .key = key,
                .state = .free,
                .prev = nil,
                .next = nil,
                .heap_pos = nil,
                .due_at = 0,
                .seq = 0,
                .failures = 0,
                .dirty = false,
                .dirty_due = null,
                .force_drop = false,
            };
            // Capacity was reserved in `init`, so this cannot allocate.
            self.index.putAssumeCapacityNoClobber(key, idx);
            self.tracked += 1;
            return idx;
        }

        fn freeSlot(self: *Self, idx: u32) void {
            const s = &self.slots[idx];
            _ = self.index.remove(s.key);
            s.state = .free;
            s.prev = nil;
            s.heap_pos = nil;
            s.next = self.free_head;
            self.free_head = idx;
            self.tracked -= 1;
        }

        fn nextSeq(self: *Self) u64 {
            self.seq_counter += 1;
            return self.seq_counter;
        }

        // ready FIFO (intrusive, doubly linked)

        fn readyPush(self: *Self, idx: u32) void {
            const s = &self.slots[idx];
            s.state = .ready;
            s.heap_pos = nil;
            s.seq = self.nextSeq();
            s.prev = self.ready_tail;
            s.next = nil;
            if (self.ready_tail == nil) {
                self.ready_head = idx;
            } else {
                self.slots[self.ready_tail].next = idx;
            }
            self.ready_tail = idx;
            self.ready_len += 1;
        }

        fn readyRemove(self: *Self, idx: u32) void {
            const s = &self.slots[idx];
            std.debug.assert(s.state == .ready);
            if (s.prev == nil) self.ready_head = s.next else self.slots[s.prev].next = s.next;
            if (s.next == nil) self.ready_tail = s.prev else self.slots[s.next].prev = s.prev;
            s.prev = nil;
            s.next = nil;
            self.ready_len -= 1;
        }

        // indexed binary min-heap over (due_at, seq)

        fn earlier(self: *const Self, a: u32, b: u32) bool {
            const sa = &self.slots[a];
            const sb = &self.slots[b];
            if (sa.due_at != sb.due_at) return sa.due_at < sb.due_at;
            return sa.seq < sb.seq;
        }

        fn heapPlace(self: *Self, pos: u32, idx: u32) void {
            self.heap[pos] = idx;
            self.slots[idx].heap_pos = pos;
        }

        fn heapPush(self: *Self, idx: u32, due: Instant) void {
            const s = &self.slots[idx];
            s.state = .waiting;
            s.due_at = due;
            s.seq = self.nextSeq();
            s.prev = nil;
            s.next = nil;
            const pos = self.heap_len;
            self.heap_len += 1;
            self.heapPlace(pos, idx);
            self.siftUp(pos);
        }

        fn heapRemove(self: *Self, idx: u32) void {
            const s = &self.slots[idx];
            std.debug.assert(s.state == .waiting);
            const pos = s.heap_pos;
            std.debug.assert(pos != nil and pos < self.heap_len);
            s.heap_pos = nil;
            self.heap_len -= 1;
            if (pos == self.heap_len) return; // it was the last element
            const moved = self.heap[self.heap_len];
            self.heapPlace(pos, moved);
            self.siftDown(pos);
            self.siftUp(pos);
        }

        /// Change a waiting key's deadline in place — the operation that keeps
        /// the heap exactly as long as the number of waiting keys.
        fn reschedule(self: *Self, idx: u32, due: Instant) void {
            const s = &self.slots[idx];
            std.debug.assert(s.state == .waiting);
            s.due_at = due;
            s.seq = self.nextSeq();
            const pos = s.heap_pos;
            self.siftDown(pos);
            self.siftUp(self.slots[idx].heap_pos);
        }

        fn siftUp(self: *Self, start: u32) void {
            var pos = start;
            const idx = self.heap[pos];
            while (pos > 0) {
                const parent = (pos - 1) / 2;
                const pidx = self.heap[parent];
                if (!self.earlier(idx, pidx)) break;
                self.heapPlace(pos, pidx);
                pos = parent;
            }
            self.heapPlace(pos, idx);
        }

        fn siftDown(self: *Self, start: u32) void {
            var pos = start;
            const idx = self.heap[pos];
            while (true) {
                const left = pos * 2 + 1;
                if (left >= self.heap_len) break;
                const right = left + 1;
                var best = left;
                if (right < self.heap_len and self.earlier(self.heap[right], self.heap[left]))
                    best = right;
                const bidx = self.heap[best];
                if (!self.earlier(bidx, idx)) break;
                self.heapPlace(pos, bidx);
                pos = best;
            }
            self.heapPlace(pos, idx);
        }

        /// The structural bound, checked rather than commented. Called from the
        /// tests and from `Reconciler.tick` in safe builds.
        pub fn assertInvariants(self: *const Self) void {
            std.debug.assert(self.tracked == self.ready_len + self.heap_len + self.running_len);
            std.debug.assert(self.tracked <= self.capacity);
            std.debug.assert(self.heap_len <= self.capacity);
            std.debug.assert(self.ready_len <= self.capacity);
            std.debug.assert(self.index.count() == self.tracked);
            var i: u32 = 0;
            while (i < self.heap_len) : (i += 1) {
                std.debug.assert(self.slots[self.heap[i]].heap_pos == i);
                std.debug.assert(self.slots[self.heap[i]].state == .waiting);
                if (i > 0) std.debug.assert(!self.earlier(self.heap[i], self.heap[(i - 1) / 2]));
            }
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const Q = WorkQueue(u32);

test "enqueue admits once and dedups thereafter" {
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    try testing.expectEqual(types.Admission.admitted, try q.enqueue(1));
    try testing.expectEqual(types.Admission.deduped, try q.enqueue(1));
    try testing.expectEqual(types.Admission.deduped, try q.enqueue(1));
    try testing.expectEqual(@as(u32, 1), q.ready_len);
    try testing.expectEqual(@as(u32, 1), q.tracked);
    q.assertInvariants();
}

test "ready FIFO order, and a re-enqueue does not jump the line" {
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    for ([_]u32{ 10, 20, 30 }) |k| _ = try q.enqueue(k);
    _ = try q.enqueue(30); // already ready — must not move to the front
    _ = try q.enqueue(10);

    var seen: [3]u32 = undefined;
    for (&seen) |*slot| {
        const idx = q.takeReady().?;
        slot.* = q.slotKey(idx);
        q.finish(idx, 0, .drop);
    }
    try testing.expectEqualSlices(u32, &.{ 10, 20, 30 }, &seen);
    try testing.expectEqual(@as(u32, 0), q.tracked);
}

test "enqueueAfter parks on the timer; promoteDue releases in deadline order" {
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    _ = try q.enqueueAfter(1, 0, 300);
    _ = try q.enqueueAfter(2, 0, 100);
    _ = try q.enqueueAfter(3, 0, 200);
    try testing.expectEqual(@as(u32, 3), q.heap_len);
    try testing.expectEqual(@as(?Instant, 100), q.nextTimer());

    try testing.expectEqual(@as(u32, 0), q.promoteDue(50));
    try testing.expectEqual(@as(u32, 2), q.promoteDue(200));

    try testing.expectEqual(@as(u32, 2), q.slotKey(q.takeReady().?));
    try testing.expectEqual(@as(u32, 3), q.slotKey(q.takeReady().?));
    q.assertInvariants();
}

test "immediate enqueue pulls a waiting key forward; earlier deadline wins" {
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    _ = try q.enqueueAfter(1, 0, 1000);
    try testing.expectEqual(types.Admission.promoted, try q.enqueue(1));
    try testing.expectEqual(@as(u32, 0), q.heap_len);
    try testing.expectEqual(@as(u32, 1), q.ready_len);

    const idx = q.takeReady().?;
    q.finish(idx, 0, .drop);

    _ = try q.enqueueAfter(2, 0, 1000);
    _ = try q.enqueueAfter(2, 0, 10); // sooner: must win
    try testing.expectEqual(@as(?Instant, 10), q.nextTimer());
    _ = try q.enqueueAfter(2, 0, 5000); // later: must be ignored
    try testing.expectEqual(@as(?Instant, 10), q.nextTimer());
    try testing.expectEqual(@as(u32, 1), q.heap_len);
    q.assertInvariants();
}

test "a mid-pass enqueue survives a drop disposition" {
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    _ = try q.enqueue(7);
    const idx = q.takeReady().?;
    // The "reconcile" re-announces its own key while running.
    try testing.expectEqual(types.Admission.marked_dirty, try q.enqueue(7));
    q.finish(idx, 0, .drop);
    try testing.expectEqual(@as(u32, 1), q.ready_len);
    try testing.expectEqual(Q.State.ready, q.stateOf(7).?);
}

test "a mid-pass enqueueAfter beats a longer disposition" {
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    _ = try q.enqueue(7);
    const idx = q.takeReady().?;
    _ = try q.enqueueAfter(7, 100, 10); // due 110
    q.finish(idx, 100, .{ .after = 5000 }); // would be due 5100
    try testing.expectEqual(@as(?Instant, 110), q.nextTimer());
}

test "a mid-pass enqueueAfter survives a drop disposition" {
    // The sibling test above ("beats a longer disposition") only exercises
    // `.after` dispositions racing a mid-pass enqueueAfter. A `.drop`
    // disposition (the pass converged) must NOT discard a re-check that
    // arrived while it was running — `finish` takes @min(asked, dirty_due)
    // where `asked` is null for `.drop`, so dirty_due alone must win.
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    _ = try q.enqueue(7);
    const idx = q.takeReady().?;
    _ = try q.enqueueAfter(7, 100, 10); // due 110, arrives mid-pass
    q.finish(idx, 100, .drop); // the pass says "converged, drop it"

    // The deferred re-check must have survived: key is still tracked and
    // parked on its timer, not gone.
    try testing.expect(q.contains(7));
    try testing.expectEqual(@as(?Instant, 110), q.nextTimer());
    try testing.expectEqual(Q.State.waiting, q.stateOf(7).?);
    q.assertInvariants();
}

test "a saturating disposition parks the key instead of dropping it" {
    // `nil_due` used to be `maxInt(Instant)`, which is also what `now +| d`
    // saturates to for a large `after` delay — so "re-run in a very long time"
    // was indistinguishable from "converged, drop it". A caller asking for a
    // far-future deadline must still be able to tell the two apart: the key
    // stays tracked and parked on a timer.
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    _ = try q.enqueue(7);
    const idx = q.takeReady().?;
    q.finish(idx, 100, .{ .after = std.math.maxInt(u64) });

    try testing.expect(q.contains(7));
    try testing.expectEqual(Q.State.waiting, q.stateOf(7).?);
    try testing.expectEqual(@as(u32, 1), q.tracked);
    // And it is genuinely distinguishable from `.drop`, which does free it.
    try testing.expect(q.nextTimer() != null);
    q.assertInvariants();

    const idx2 = blk: {
        _ = q.promoteDue(std.math.maxInt(Instant));
        break :blk q.takeReady().?;
    };
    q.finish(idx2, std.math.maxInt(Instant), .drop);
    try testing.expect(!q.contains(7));
    try testing.expectEqual(@as(u32, 0), q.tracked);
    q.assertInvariants();
}

test "a saturating mid-pass enqueueAfter survives a drop disposition" {
    // Second site of the same sentinel collision: `enqueueAfter` on a
    // `.running` key folded the request into `dirty_due` with a plain `@min`,
    // so a saturating deadline left `dirty_due` at the "none" sentinel and the
    // request vanished when the pass then said `.drop`.
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    _ = try q.enqueue(7);
    const idx = q.takeReady().?;
    _ = try q.enqueueAfter(7, 100, std.math.maxInt(u64)); // saturates
    q.finish(idx, 100, .drop);

    try testing.expect(q.contains(7));
    try testing.expectEqual(Q.State.waiting, q.stateOf(7).?);
    try testing.expect(q.nextTimer() != null);
    q.assertInvariants();
}

test "capacity is a hard admission bound" {
    var q = try Q.init(testing.allocator, 4);
    defer q.deinit();

    for (0..4) |i| _ = try q.enqueue(@intCast(i));
    try testing.expectError(types.Error.AtCapacity, q.enqueue(99));
    try testing.expectError(types.Error.AtCapacity, q.enqueueAfter(98, 0, 10));
    // An already-tracked key is still accepted at capacity — dedup, not growth.
    try testing.expectEqual(types.Admission.deduped, try q.enqueue(0));
    try testing.expectEqual(@as(u32, 4), q.tracked);
    q.assertInvariants();
}

test "forget removes a ready or waiting key and its streak" {
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    _ = try q.enqueue(1);
    _ = try q.enqueueAfter(2, 0, 100);
    try testing.expect(q.forget(1));
    try testing.expect(q.forget(2));
    try testing.expect(!q.forget(3));
    try testing.expectEqual(@as(u32, 0), q.tracked);
    try testing.expectEqual(@as(u32, 0), q.heap_len);
    try testing.expectEqual(@as(u32, 0), q.ready_len);
}

test "BOUND: the timer heap never grows past capacity under endless rescheduling" {
    // This is the test the indexed heap exists for. With lazy deletion (push a
    // fresh node per reschedule, skip stale ones on pop) `heap_len` would grow
    // once per iteration below — 40_000 nodes for 8 keys — and the assertion
    // would fail. Nothing here is asserted in a comment.
    var q = try Q.init(testing.allocator, 8);
    defer q.deinit();

    var prng = std.Random.DefaultPrng.init(0xB0DE);
    const rnd = prng.random();

    for (0..8) |i| _ = try q.enqueueAfter(@intCast(i), 0, 1_000_000);

    var now: Instant = 0;
    var iter: usize = 0;
    while (iter < 40_000) : (iter += 1) {
        const key = rnd.uintLessThan(u32, 8);
        now += rnd.uintLessThan(u64, 100);
        switch (rnd.uintLessThan(u8, 3)) {
            // reschedule sooner (the decrease-key path)
            0 => _ = try q.enqueueAfter(key, now, rnd.uintLessThan(u64, 50)),
            // pull forward, run, and park again (remove + push)
            1 => {
                _ = try q.enqueue(key);
                _ = q.promoteDue(now);
                if (q.takeReady()) |idx| q.finish(idx, now, .{ .after = 10_000 });
            },
            // let time pass and re-park whatever came due
            else => {
                _ = q.promoteDue(now);
                while (q.takeReady()) |idx| q.finish(idx, now, .{ .after = 500 });
            },
        }
        try testing.expect(q.heap_len <= q.capacity);
        try testing.expect(q.tracked <= q.capacity);
        try testing.expect(q.ready_len <= q.capacity);
    }
    q.assertInvariants();
    try testing.expect(q.tracked <= 8);
}

test "BOUND: the slot arena is allocated once and never moves" {
    var q = try Q.init(testing.allocator, 16);
    defer q.deinit();

    const slots_ptr = q.slots.ptr;
    const heap_ptr = q.heap.ptr;

    // After init, no admission path may allocate. A failing allocator proves
    // it rather than a claim in the docs.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    q.gpa = failing.allocator();

    var now: Instant = 0;
    for (0..16) |i| _ = try q.enqueue(@intCast(i));
    var round: usize = 0;
    while (round < 200) : (round += 1) {
        now += 7;
        _ = q.promoteDue(now);
        while (q.takeReady()) |idx| q.finish(idx, now, .{ .after = 3 });
        for (0..16) |i| {
            if (q.enqueue(@intCast(i))) |_| {} else |_| {}
        }
    }
    try testing.expectEqual(slots_ptr, q.slots.ptr);
    try testing.expectEqual(heap_ptr, q.heap.ptr);
    try testing.expectEqual(@as(usize, 0), failing.allocations);

    q.gpa = testing.allocator; // restore for deinit
}

test "heap ordering matches a sorted reference over random deadlines" {
    var q = try Q.init(testing.allocator, 64);
    defer q.deinit();

    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();

    var expected: [64]u64 = undefined;
    for (0..64) |i| {
        const due = rnd.uintLessThan(u64, 10_000) + 1;
        expected[i] = due;
        _ = try q.enqueueAfter(@intCast(i), 0, due);
    }
    std.mem.sort(u64, &expected, {}, std.sort.asc(u64));

    var out: [64]u64 = undefined;
    var n: usize = 0;
    while (q.heap_len > 0) {
        const due = q.nextTimer().?;
        _ = q.promoteDue(due);
        while (q.takeReady()) |idx| {
            out[n] = due;
            n += 1;
            q.finish(idx, due, .drop);
        }
    }
    try testing.expectEqual(@as(usize, 64), n);
    try testing.expectEqualSlices(u64, &expected, &out);
}
