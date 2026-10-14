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
//! **Slots are atomic, so any `T` works.** A thief reads the item at `top`
//! BEFORE its claiming CAS, and if the CAS loses, the owner may be writing
//! that very slot on its next lap. With a plain `T` that read would be a data
//! race even though the value is then thrown away; with atomic (monotonic)
//! slots it is merely stale. A `T` that fits one `std.atomic.Value` (integer,
//! bool, enum, pointer, optional pointer, at most a word) is one atomic; any
//! other `T` is stored as its bytes in an array of atomic words, copied word
//! by word (2026-10-14). Such a read can be torn — words of two laps — but
//! only when the owner has reused the slot, which needs `top` past the
//! position, so the claim CAS fails and the torn value is dropped. A
//! successful claim proves every word read was the position's own.
//!
//! **Flavours and batches.** `Deque(T)`'s owner pops LIFO (above);
//! `FifoDeque(T)`'s owner pops the oldest item through the same CAS on `top`
//! that thieves use, never lowering `bottom`. `stealBatch*` move about half
//! of a victim's items into the caller's own deque: from a FIFO victim with
//! one CAS `top → top + n`, from a LIFO victim as `n` single steals (see
//! `batch`). `Injector(T)` is the global entry queue that feeds such deques.
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
const segqueue = @import("segqueue.zig");

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

        const Self = @This();

        pub fn isEmpty(r: Self) bool {
            return r == .empty;
        }

        pub fn isRetry(r: Self) bool {
            return r == .retry;
        }

        pub fn isSuccess(r: Self) bool {
            return r == .success;
        }

        /// The stolen item, or null for `.empty` and `.retry`.
        pub fn item(r: Self) ?T {
            return switch (r) {
                .success => |v| v,
                .empty, .retry => null,
            };
        }

        /// This result if it is a success, else `f(context)`'s if that is
        /// one; otherwise `.retry` if either said retry, else `.empty`
        /// (crossbeam's `or_else`).
        pub fn orElse(r: Self, context: anytype, comptime f: fn (@TypeOf(context)) Self) Self {
            if (r == .success) return r;
            const next = f(context);
            if (next == .success) return next;
            return if (r == .retry or next == .retry) .retry else .empty;
        }

        /// Steal attempts in turn — `next(context)` until it returns null —
        /// and stop at the first success; otherwise `.retry` if any attempt
        /// said retry, else `.empty` (crossbeam's `collect` over victims:
        /// `.retry` means "not provably empty, try the round again").
        pub fn first(context: anytype, comptime next: fn (@TypeOf(context)) ?Self) Self {
            var retry = false;
            while (next(context)) |r| switch (r) {
                .success => return r,
                .retry => retry = true,
                .empty => {},
            };
            return if (retry) .retry else .empty;
        }
    };
}

/// Which end the owner pops from.
pub const Flavor = enum {
    /// The owner pops the newest item (crossbeam's `Worker::new_lifo`): the
    /// work it just created, still in cache.
    lifo,
    /// The owner pops the oldest item, as thieves do (`Worker::new_fifo`).
    fifo,
};

/// Items moved by one `stealBatch*` call unless a limit is given: half of
/// the victim's items, rounded up, and at most this many.
pub const default_batch_limit: usize = 32;

/// A growable Chase-Lev work-stealing deque of `T` whose owner pops LIFO.
/// `T` may be any type; see the file comment for how slots are copied.
pub fn Deque(comptime T: type) type {
    return DequeOf(T, .lifo, .none);
}

/// The same deque with a FIFO owner: `pop` takes the oldest item, through the
/// same claim on `top` that thieves use.
pub fn FifoDeque(comptime T: type) type {
    return DequeOf(T, .fifo, .none);
}

/// Deliberate bugs for the stress driver's positive controls (tests only).
const Fault = enum {
    none,
    /// A LIFO victim's batch claimed with one CAS `top → top + n`, as for a
    /// FIFO victim — the shape SPEC §4c's backlog proves unsound.
    lifo_batch_one_cas,
};

/// Whether `T` fits one `std.atomic.Value` slot; other types are copied as
/// an array of atomic words.
fn oneWord(comptime T: type) bool {
    if (@sizeOf(T) > @sizeOf(usize)) return false;
    return switch (@typeInfo(T)) {
        .int, .bool, .@"enum" => true,
        .pointer => |ptr| ptr.size != .slice,
        .optional => |o| switch (@typeInfo(o.child)) {
            .pointer => |ptr| ptr.size != .slice,
            else => false,
        },
        else => false,
    };
}

/// A slot of `T`: one atomic value, or `T`'s bytes in atomic words. Every
/// access is a monotonic atomic, so a thief's read of a slot the owner may be
/// rewriting is stale, never a data race; a torn wide read is thrown away
/// with the claim CAS it loses.
fn SlotOf(comptime T: type) type {
    if (oneWord(T)) return struct {
        v: std.atomic.Value(T),
        inline fn put(s: *@This(), item: T) void {
            s.v.store(item, .monotonic);
        }
        inline fn get(s: *const @This()) T {
            return s.v.load(.monotonic);
        }
    };
    const n_words = (@sizeOf(T) + @sizeOf(usize) - 1) / @sizeOf(usize);
    return struct {
        w: [n_words]std.atomic.Value(usize),
        inline fn put(s: *@This(), item: T) void {
            var words: [n_words]usize = @splat(0);
            @memcpy(std.mem.asBytes(&words)[0..@sizeOf(T)], std.mem.asBytes(&item));
            for (&s.w, words) |*a, w| a.store(w, .monotonic);
        }
        inline fn get(s: *const @This()) T {
            var words: [n_words]usize = undefined;
            for (&words, &s.w) |*w, *a| w.* = a.load(.monotonic);
            var out: T = undefined;
            @memcpy(std.mem.asBytes(&out), std.mem.asBytes(&words)[0..@sizeOf(T)]);
            return out;
        }
    };
}

fn DequeOf(comptime T: type, comptime flavor: Flavor, comptime fault: Fault) type {
    return struct {
        const Self = @This();
        pub const Item = T;
        const Slot = SlotOf(T);

        const Buffer = struct {
            /// `capacity - 1`; capacity is a power of two.
            mask: usize,
            slots: []Slot,

            fn create(allocator: std.mem.Allocator, slot_count: usize) !*Buffer {
                const b = try allocator.create(Buffer);
                errdefer allocator.destroy(b);
                const slots = try allocator.alloc(Slot, slot_count);
                b.* = .{ .mask = slot_count - 1, .slots = slots };
                return b;
            }

            fn destroy(b: *Buffer, allocator: std.mem.Allocator) void {
                allocator.free(b.slots);
                allocator.destroy(b);
            }

            fn put(b: *Buffer, i: isize, item: T) void {
                b.slots[@as(usize, @bitCast(i)) & b.mask].put(item);
            }

            pub fn get(b: *const Buffer, i: isize) T {
                return b.slots[@as(usize, @bitCast(i)) & b.mask].get();
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

        /// The owner's view: `push`, `pop`, `len`, `isEmpty`, `capacity`.
        /// Hand it to the one owner thread (crossbeam's `Worker`).
        pub const Worker = struct {
            deque: *Self,

            pub fn push(w: Worker, item_: T) error{OutOfMemory}!void {
                return w.deque.push(item_);
            }
            pub fn pop(w: Worker) ?T {
                return w.deque.pop();
            }
            pub fn len(w: Worker) usize {
                return w.deque.len();
            }
            pub fn isEmpty(w: Worker) bool {
                return w.deque.isEmpty();
            }
            pub fn capacity(w: Worker) usize {
                return w.deque.capacity();
            }
        };

        /// A thief's view: `steal`, the `stealBatch*` family, `len`,
        /// `isEmpty`. Copy it to as many threads as you like (crossbeam's
        /// `Stealer`, which is `Clone`).
        pub const Stealer = struct {
            deque: *Self,

            pub fn steal(s: Stealer) Steal(T) {
                return s.deque.steal();
            }
            pub fn stealBatch(s: Stealer, dest: anytype) error{OutOfMemory}!Steal(void) {
                return s.deque.stealBatch(dest);
            }
            pub fn stealBatchWithLimit(s: Stealer, dest: anytype, limit: usize) error{OutOfMemory}!Steal(void) {
                return s.deque.stealBatchWithLimit(dest, limit);
            }
            pub fn stealBatchAndPop(s: Stealer, dest: anytype) error{OutOfMemory}!Steal(T) {
                return s.deque.stealBatchAndPop(dest);
            }
            pub fn stealBatchWithLimitAndPop(s: Stealer, dest: anytype, limit: usize) error{OutOfMemory}!Steal(T) {
                return s.deque.stealBatchWithLimitAndPop(dest, limit);
            }
            pub fn len(s: Stealer) usize {
                return s.deque.len();
            }
            pub fn isEmpty(s: Stealer) bool {
                return s.deque.isEmpty();
            }
        };

        pub fn worker(d: *Self) Worker {
            return .{ .deque = d };
        }

        pub fn stealer(d: *Self) Stealer {
            return .{ .deque = d };
        }

        /// Owner only: add `item` at the bottom. `error.OutOfMemory` only when
        /// the deque is full and cannot grow; the item is then not added.
        pub fn push(d: *Self, item_: T) error{OutOfMemory}!void {
            const b = d.bottom.load(.monotonic);
            // Acquire: pairs with a thief's claiming CAS, so its read of the
            // slot we are about to reuse happens-before our overwrite.
            const t = d.top.load(.acquire);
            var buf = d.buffer.load(.monotonic);
            if (b - t > @as(isize, @intCast(buf.mask))) {
                // Cold, and out of line: with growth inlined, `push` was a
                // call with a full prologue in the owner's loop (2026-10-14,
                // deque_owner 1.12× crossbeam).
                @branchHint(.cold);
                buf = try d.grow(buf, t, b);
            }
            buf.put(b, item_);
            // Release: the slot write happens-before a thief's read of it,
            // through the thief's load of `bottom`.
            d.bottom.store(b + 1, .release);
        }

        /// Owner only, with `bottom - top == capacity`: a buffer twice the
        /// size holding positions `t..b`, published for thieves.
        noinline fn grow(d: *Self, old: *Buffer, t: isize, b: isize) error{OutOfMemory}!*Buffer {
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

        /// Owner only: room for `n` more items without growing, so the
        /// `n` slots past `bottom` can be written and then published at once.
        /// Returns the buffer they are in.
        fn reserve(d: *Self, n: usize) error{OutOfMemory}!*Buffer {
            const b = d.bottom.load(.monotonic);
            // Acquire, as in `push`: the slots past `bottom` that thieves
            // freed are ours to overwrite only after their reads.
            const t = d.top.load(.acquire);
            var buf = d.buffer.load(.monotonic);
            while (@as(usize, @intCast(b - t)) + n > buf.mask + 1) buf = try d.grow(buf, t, b);
            return buf;
        }

        /// Owner only: take an item — the newest for `Deque`, the oldest for
        /// `FifoDeque` — or null when the deque is empty (every item pushed so
        /// far was popped or stolen).
        pub fn pop(d: *Self) ?T {
            if (flavor == .fifo) return d.popOldest();
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
            const item_ = buf.get(b);
            if (t == b) {
                // The last item: thieves may be claiming it too. Exactly one
                // CAS moves `top` off `t`.
                const won = d.top.cmpxchgStrong(t, t + 1, .seq_cst, .monotonic) == null;
                d.bottom.store(b + 1, .monotonic);
                return if (won) item_ else null;
            }
            // More than one: `t < b`, and no thief can claim position `b` —
            // a thief that saw the old bottom loses the race the comment proves.
            return item_;
        }

        /// FIFO owner: claim `top` like a thief. `bottom` is ours and never
        /// lowered, so there is no Dekker pair — owner and thieves meet only
        /// at the CAS, and the slot needs no re-validation: only this thread
        /// writes slots.
        fn popOldest(d: *Self) ?T {
            const b = d.bottom.load(.monotonic);
            const buf = d.buffer.load(.monotonic);
            var t = d.top.load(.seq_cst);
            while (t < b) {
                const item_ = buf.get(t);
                t = d.top.cmpxchgWeak(t, t + 1, .seq_cst, .seq_cst) orelse return item_;
            }
            return null;
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
            const item_ = buf.get(t);
            if (d.top.cmpxchgStrong(t, t + 1, .seq_cst, .monotonic) != null) return .retry;
            return .{ .success = item_ };
        }

        /// From `dest`'s owner thread: move about half of this deque's items
        /// (at most `default_batch_limit`) into `dest` — a `Deque`/`FifoDeque`
        /// of the same `T` or its `Worker`. `.success` when at least one item
        /// moved. `error.OutOfMemory` only when `dest` could not grow; nothing
        /// is then taken.
        pub fn stealBatch(d: *Self, dest: anytype) error{OutOfMemory}!Steal(void) {
            return d.stealBatchWithLimit(dest, default_batch_limit);
        }

        /// `stealBatch` moving at most `limit` (≥ 1) items.
        pub fn stealBatchWithLimit(d: *Self, dest: anytype, limit: usize) error{OutOfMemory}!Steal(void) {
            return switch (try d.batch(destDeque(dest), limit, false)) {
                .empty => .empty,
                .retry => .retry,
                .success => .{ .success = {} },
            };
        }

        /// `stealBatch`, returning the oldest stolen item instead of moving it.
        pub fn stealBatchAndPop(d: *Self, dest: anytype) error{OutOfMemory}!Steal(T) {
            return d.batch(destDeque(dest), default_batch_limit, true);
        }

        /// `stealBatchAndPop` taking at most `limit` (≥ 1) items in all.
        pub fn stealBatchWithLimitAndPop(d: *Self, dest: anytype, limit: usize) error{OutOfMemory}!Steal(T) {
            return d.batch(destDeque(dest), limit, true);
        }

        /// One batch: up to half the items, at most `limit`, written into the
        /// slots past `dest`'s bottom (invisible to `dest`'s thieves, which
        /// read only below it) and published there together once claimed.
        /// With `keep_first`, the oldest item is returned instead.
        ///
        /// The claim depends on the victim's flavour. FIFO: one CAS `top →
        /// top + n` — sound because the owner never lowers `bottom` and claims
        /// through `top` too, so the `n` positions read below `bottom` stay
        /// ours unless `top` moves, which fails the CAS; and the owner cannot
        /// overwrite their slots while `top` is still `t` (`push` grows
        /// instead). LIFO: `n` single steals — one CAS by `n` there is
        /// unsound (SPEC §4c backlog): the owner pops from the bottom without
        /// a CAS while it sees more than one item, down into the batch.
        fn batch(d: *Self, dest: anytype, limit: usize, comptime keep_first: bool) error{OutOfMemory}!Steal(T) {
            std.debug.assert(limit >= 1);
            std.debug.assert(@intFromPtr(dest) != @intFromPtr(d));
            const t = d.top.load(.seq_cst);
            const b = d.bottom.load(.seq_cst);
            if (t >= b) return .empty;
            const n = @min((@as(usize, @intCast(b - t)) + 1) / 2, limit);
            const to_dest = if (keep_first) n - 1 else n;
            const dest_buf = try dest.reserve(to_dest);
            const db = dest.bottom.load(.monotonic);
            var first_item: T = undefined;
            var moved: isize = 0;
            switch (if (fault == .lifo_batch_one_cas) Flavor.fifo else flavor) {
                .fifo => {
                    // Acquire: as in `steal`.
                    const buf = d.buffer.load(.acquire);
                    var i: usize = 0;
                    if (keep_first) {
                        first_item = buf.get(t);
                        i = 1;
                    }
                    while (i < n) : (i += 1) {
                        dest_buf.put(db + moved, buf.get(t + @as(isize, @intCast(i))));
                        moved += 1;
                    }
                    if (d.top.cmpxchgStrong(t, t + @as(isize, @intCast(n)), .seq_cst, .monotonic) != null) return .retry;
                },
                .lifo => {
                    var taken: usize = 0;
                    while (taken < n) {
                        const got = switch (d.steal()) {
                            .success => |v| v,
                            .empty => if (taken == 0) return .empty else break,
                            .retry => if (taken == 0) return .retry else break,
                        };
                        if (keep_first and taken == 0) {
                            first_item = got;
                        } else {
                            dest_buf.put(db + moved, got);
                            moved += 1;
                        }
                        taken += 1;
                    }
                },
            }
            // Release, as in `push`: publishes the slots to `dest`'s thieves.
            if (moved > 0) dest.bottom.store(db + moved, .release);
            return .{ .success = first_item };
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

/// The deque behind a `stealBatch*` destination: a deque pointer or its
/// `Worker` view.
fn destDeque(dest: anytype) DestPtr(@TypeOf(dest)) {
    const D = @TypeOf(dest);
    if (@typeInfo(D) == .pointer) return dest;
    return dest.deque;
}

fn DestPtr(comptime D: type) type {
    if (@typeInfo(D) == .pointer) return D;
    return @FieldType(D, "deque");
}

/// A global FIFO entry queue for a work-stealing scheduler (crossbeam's
/// `Injector`): any thread `push`es, any thread `steal`s one item or a batch
/// into its own worker deque. Unbounded and handle-free — a `SegQueue` — so
/// `steal` never answers `.retry`.
pub fn Injector(comptime T: type) type {
    return struct {
        const Self = @This();
        const Queue = segqueue.SegQueue(T, .{});

        queue: Queue,

        /// `allocator` must be thread-safe (see `SegQueue`).
        pub fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!Self {
            return .{ .queue = try Queue.init(allocator) };
        }

        /// No thread may be inside an operation; unread items are dropped.
        pub fn deinit(inj: *Self) void {
            inj.queue.deinit();
        }

        /// Any thread. Fails only when a new block cannot be allocated.
        pub fn push(inj: *Self, item_: T) std.mem.Allocator.Error!void {
            return inj.queue.push(item_);
        }

        /// Any thread: the oldest item, or `.empty`.
        pub fn steal(inj: *Self) Steal(T) {
            return if (inj.queue.pop()) |v| .{ .success = v } else .empty;
        }

        /// From `dest`'s owner thread: move about half of the queued items (at
        /// most `default_batch_limit`) into `dest`, as `Deque.stealBatch`.
        pub fn stealBatch(inj: *Self, dest: anytype) error{OutOfMemory}!Steal(void) {
            return inj.stealBatchWithLimit(dest, default_batch_limit);
        }

        pub fn stealBatchWithLimit(inj: *Self, dest: anytype, limit: usize) error{OutOfMemory}!Steal(void) {
            return switch (try inj.batch(destDeque(dest), limit, false)) {
                .success => .{ .success = {} },
                .empty => .empty,
                .retry => unreachable,
            };
        }

        pub fn stealBatchAndPop(inj: *Self, dest: anytype) error{OutOfMemory}!Steal(T) {
            return inj.batch(destDeque(dest), default_batch_limit, true);
        }

        pub fn stealBatchWithLimitAndPop(inj: *Self, dest: anytype, limit: usize) error{OutOfMemory}!Steal(T) {
            return inj.batch(destDeque(dest), limit, true);
        }

        /// Pops one item at a time (each a claim of its own), written past
        /// `dest`'s bottom and published together.
        fn batch(inj: *Self, dest: anytype, limit: usize, comptime keep_first: bool) error{OutOfMemory}!Steal(T) {
            std.debug.assert(limit >= 1);
            const queued = inj.queue.len();
            if (queued == 0) return .empty;
            const n = @min((queued + 1) / 2, limit);
            const dest_buf = try dest.reserve(if (keep_first) n - 1 else n);
            const db = dest.bottom.load(.monotonic);
            var first_item: T = undefined;
            var moved: isize = 0;
            var taken: usize = 0;
            while (taken < n) : (taken += 1) {
                const got = inj.queue.pop() orelse break;
                if (keep_first and taken == 0) {
                    first_item = got;
                } else {
                    dest_buf.put(db + moved, got);
                    moved += 1;
                }
            }
            if (taken == 0) return .empty;
            if (moved > 0) dest.bottom.store(db + moved, .release);
            return .{ .success = first_item };
        }

        pub fn len(inj: *const Self) usize {
            return inj.queue.len();
        }

        pub fn isEmpty(inj: *const Self) bool {
            return inj.queue.isEmpty();
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

test "Steal helpers: is*, item, orElse, first (crossbeam's or_else and collect)" {
    const S = Steal(u8);
    const ok: S = .{ .success = 5 };
    try testing.expect(ok.isSuccess() and !ok.isEmpty() and !ok.isRetry());
    try testing.expectEqual(@as(?u8, 5), ok.item());
    try testing.expectEqual(@as(?u8, null), @as(S, .retry).item());
    const F = struct {
        fn give(r: S) S {
            return r;
        }
    };
    const empty: S = .empty;
    const retry: S = .retry;
    try testing.expectEqual(ok, empty.orElse(ok, F.give));
    try testing.expectEqual(ok, ok.orElse(retry, F.give));
    try testing.expectEqual(retry, empty.orElse(retry, F.give));
    try testing.expectEqual(retry, retry.orElse(empty, F.give));
    try testing.expectEqual(empty, empty.orElse(empty, F.give));
    const It = struct {
        rs: []const S,
        i: usize = 0,
        fn next(it: *@This()) ?S {
            if (it.i == it.rs.len) return null;
            it.i += 1;
            return it.rs[it.i - 1];
        }
    };
    var a: It = .{ .rs = &.{ .empty, .retry, .{ .success = 1 }, .{ .success = 2 } } };
    try testing.expectEqual(S{ .success = 1 }, S.first(&a, It.next));
    try testing.expectEqual(@as(usize, 3), a.i); // stopped at the success
    var b: It = .{ .rs = &.{ .empty, .retry, .empty } };
    try testing.expectEqual(S.retry, S.first(&b, It.next));
    var c: It = .{ .rs = &.{ .empty, .empty } };
    try testing.expectEqual(S.empty, S.first(&c, It.next));
}

test "Worker and Stealer views reach the same deque" {
    var d = try Deque(u32).init(testing.allocator, 4);
    defer d.deinit();
    const w = d.worker();
    const st = d.stealer();
    const st2 = st; // a Stealer is a plain copy
    try w.push(1);
    try w.push(2);
    try w.push(3);
    try testing.expectEqual(@as(usize, 3), st.len());
    try testing.expectEqual(@as(?u32, 1), st2.steal().item());
    try testing.expectEqual(@as(?u32, 3), w.pop());
    try testing.expectEqual(@as(?u32, 2), st.steal().item());
    try testing.expect(w.isEmpty() and st.isEmpty());
}

test "FifoDeque: the owner pops oldest first, alongside thieves, and across growth" {
    var d = try FifoDeque(u64).init(testing.allocator, 2);
    defer d.deinit();
    for (0..5) |i| try d.push(i);
    try testing.expectEqual(@as(?u64, 0), d.pop());
    try testing.expectEqual(Steal(u64){ .success = 1 }, d.steal());
    try testing.expectEqual(@as(?u64, 2), d.pop());
    for (5..100) |i| try d.push(i);
    for (3..100) |i| try testing.expectEqual(@as(?u64, i), d.pop());
    try testing.expectEqual(@as(?u64, null), d.pop());
    try testing.expectEqual(Steal(u64).empty, d.steal());
    // `bottom` was never lowered: an empty pop leaves nothing to restore.
    try d.push(7);
    try testing.expectEqual(@as(?u64, 7), d.pop());
}

fn batchCase(comptime Victim: type, comptime Dest: type) !void {
    var v = try Victim.init(testing.allocator, 4);
    defer v.deinit();
    var dest = try Dest.init(testing.allocator, 2);
    defer dest.deinit();
    try testing.expectEqual(Steal(void).empty, try v.stealBatch(&dest));
    for (0..9) |i| try v.push(i);
    // Half of 9, rounded up: 5 items, the oldest five; dest grows for them.
    try testing.expectEqual(Steal(void){ .success = {} }, try v.stealBatch(&dest));
    try testing.expectEqual(@as(usize, 4), v.len());
    try testing.expectEqual(@as(usize, 5), dest.len());
    for (0..5) |i| try testing.expectEqual(Steal(u64){ .success = i }, dest.steal());
    // A limit caps the batch; AndPop returns the oldest and moves the rest.
    try testing.expectEqual(Steal(u64){ .success = 5 }, try v.stealBatchWithLimitAndPop(dest.worker(), 2));
    try testing.expectEqual(@as(usize, 1), dest.len());
    try testing.expectEqual(Steal(u64){ .success = 6 }, dest.steal());
    try testing.expectEqual(@as(usize, 2), v.len());
    // Limit 1 with AndPop moves nothing into dest.
    try testing.expectEqual(Steal(u64){ .success = 7 }, try v.stealBatchWithLimitAndPop(&dest, 1));
    try testing.expect(dest.isEmpty());
    try testing.expectEqual(Steal(u64){ .success = 8 }, try v.stealBatchAndPop(&dest));
    try testing.expect(v.isEmpty());
    try testing.expectEqual(Steal(u64).empty, try v.stealBatchAndPop(&dest));
}

test "stealBatch*: half rounded up, the oldest items, limit honoured — every victim × dest flavour" {
    try batchCase(Deque(u64), Deque(u64));
    try batchCase(Deque(u64), FifoDeque(u64));
    try batchCase(FifoDeque(u64), Deque(u64));
    try batchCase(FifoDeque(u64), FifoDeque(u64));
}

test "stealBatch into a dest that cannot grow fails before taking anything" {
    var v = try FifoDeque(u64).init(testing.allocator, 8);
    defer v.deinit();
    for (0..8) |i| try v.push(i);
    // Two allocations for init; the batch of 4 needs dest to grow past 2.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 2 });
    var dest = try FifoDeque(u64).init(failing.allocator(), 2);
    defer dest.deinit();
    try testing.expectError(error.OutOfMemory, v.stealBatch(&dest));
    try testing.expectEqual(@as(usize, 8), v.len());
    try testing.expect(dest.isEmpty());
}

test "Deque carries items wider than a word, through growth, pop and steal" {
    const Item = struct { id: u64, tag: [3]u32, flag: bool };
    var d = try Deque(Item).init(testing.allocator, 2);
    defer d.deinit();
    for (0..50) |i| try d.push(.{ .id = i, .tag = .{ @intCast(i), 7, @intCast(i * 2) }, .flag = i % 2 == 0 });
    for (0..10) |i| {
        const it = d.steal().item().?;
        try testing.expectEqual(@as(u64, i), it.id);
        try testing.expectEqual([3]u32{ @intCast(i), 7, @intCast(i * 2) }, it.tag);
        try testing.expectEqual(i % 2 == 0, it.flag);
    }
    var i: u64 = 50;
    while (i > 10) {
        i -= 1;
        try testing.expectEqual(i, d.pop().?.id);
    }
    try testing.expectEqual(@as(?Item, null), d.pop());
    // A slice is two words: the word path too.
    var s = try FifoDeque([]const u8).init(testing.allocator, 2);
    defer s.deinit();
    try s.push("ab");
    try s.push("cde");
    try testing.expectEqualStrings("ab", s.steal().item().?);
    try testing.expectEqualStrings("cde", s.pop().?);
}

test "Injector: push, steal, batches into a worker" {
    var inj = try Injector(u32).init(testing.allocator);
    defer inj.deinit();
    var w = try Deque(u32).init(testing.allocator, 2);
    defer w.deinit();
    try testing.expectEqual(Steal(u32).empty, inj.steal());
    try testing.expectEqual(Steal(u32).empty, try inj.stealBatchAndPop(&w));
    for (0..10) |i| try inj.push(@intCast(i));
    try testing.expectEqual(Steal(u32){ .success = 0 }, inj.steal());
    // 9 left: a batch of 5 (half rounded up), the oldest returned.
    try testing.expectEqual(Steal(u32){ .success = 1 }, try inj.stealBatchAndPop(&w));
    try testing.expectEqual(@as(usize, 4), w.len());
    try testing.expectEqual(@as(usize, 4), inj.len());
    // 4 left: half is 2, under the limit of 3.
    try testing.expectEqual(Steal(void){ .success = {} }, try inj.stealBatchWithLimit(w.worker(), 3));
    try testing.expectEqual(@as(usize, 6), w.len());
    try testing.expectEqual(@as(usize, 2), inj.len());
    // A LIFO worker pops its newest first; the batches arrived in order.
    for ([_]u32{ 7, 6, 5, 4, 3, 2 }) |want| try testing.expectEqual(@as(?u32, want), w.pop());
    try testing.expectEqual(@as(?u32, 8), inj.steal().item());
    try testing.expectEqual(@as(?u32, 9), inj.steal().item());
    try testing.expect(inj.isEmpty());
}

test "DEQUE BATCH DRIVER TEETH: one CAS by n on a LIFO victim is caught (high probability)" {
    const harness = @import("harness.zig");
    const D = DequeOf(u64, .lifo, .lifo_batch_one_cas);
    var detected = false;
    var round: usize = 0;
    while (round < 6 and !detected) : (round += 1) {
        var d = try D.init(testing.allocator, 64);
        defer d.deinit();
        detected = try harness.DequeStressMode(D, .{ .batch = true }).run(&d, 4, 200_000, 700 + round, testing.allocator) != .clean;
    }
    try testing.expect(detected);
}
