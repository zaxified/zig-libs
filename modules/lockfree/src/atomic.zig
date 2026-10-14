// SPDX-License-Identifier: MIT

//! atomic — mechanical, non-safety-critical helpers over `std.atomic`. None
//! of this is Fable-core: it is the typed plumbing (backoff, cache-line
//! padding) the lock-free algorithms sit on, plus a plain `SpinLock` used
//! ONLY by the harness's reference oracle (`RefQueue`) — the lock-free code
//! paths never touch it. The memory-ordering *decisions* live in `ebr.zig`
//! and `mpmc.zig`; this file only re-exports the primitives.
//!
//! (Zig 0.16 has no `std.Thread.Mutex`/`Condition` — CONVENTIONS §2 — so the
//! oracle's mutual exclusion is a `std.atomic`-based test-and-test-and-set
//! spinlock. That is a deliberate, documented choice for a *test-only*
//! coarse lock; it is never on any lock-free path.)

const std = @import("std");

/// Alias so code spells the atomic type through the module: `lockfree.Atomic`.
/// Generic, so it has no body until something instantiates it — see the test at
/// the foot of this file, which is the only instantiation in the repository and
/// the only reason a broken edit to this line does not compile green.
pub fn Atomic(comptime T: type) type {
    return std.atomic.Value(T);
}

/// L1 cache line width for the target — used to pad hot atomics apart and
/// avoid false sharing between producer/consumer counters. Mechanical.
pub const cache_line: usize = std.atomic.cache_line;

/// Pad a value out to a full cache line to prevent false sharing when two
/// threads hammer neighbouring fields. Mechanical layout helper.
pub fn CachePadded(comptime T: type) type {
    return struct {
        value: T,
        _pad: [pad_len]u8 = [_]u8{0} ** pad_len,

        const pad_len = if (@sizeOf(T) % cache_line == 0)
            0
        else
            cache_line - (@sizeOf(T) % cache_line);

        pub fn init(v: T) @This() {
            return .{ .value = v };
        }
    };
}

/// Exponential spin/yield backoff for CAS-retry loops. A contended CAS loop
/// that busy-spins wastes a core and can livelock the winner; this widens the
/// pause geometrically, then hands off the CPU. Mechanical — it affects
/// throughput/fairness, never correctness (a correct CAS loop is correct with
/// or without backoff).
pub const Backoff = struct {
    step: u6 = 0,

    /// After this many doublings, stop spinning and yield the OS thread.
    const spin_ceiling: u6 = 6;
    /// Hard ceiling on doublings so `step` never overflows its bit width.
    const step_ceiling: u6 = 16;

    pub fn reset(self: *Backoff) void {
        self.step = 0;
    }

    /// One backoff iteration. Spins for `2^step` pause hints while under the
    /// ceiling, then switches to yielding the OS thread.
    pub fn pause(self: *Backoff) void {
        if (self.step <= spin_ceiling) {
            var i: usize = 0;
            const limit = @as(usize, 1) << @intCast(self.step);
            while (i < limit) : (i += 1) std.atomic.spinLoopHint();
        } else {
            std.Thread.yield() catch {};
        }
        if (self.step < step_ceiling) self.step += 1;
    }

    /// Backoff after a lost CAS: spin `2^step` pause hints, never yield. A
    /// lost CAS means another thread made progress, so there is nothing to
    /// wait for; the pause only spreads the retries out so the contended
    /// cache line is not taken from its new owner at once.
    pub fn spin(self: *Backoff) void {
        var i: usize = 0;
        const limit = @as(usize, 1) << @intCast(@min(self.step, spin_ceiling));
        while (i < limit) : (i += 1) std.atomic.spinLoopHint();
        if (self.step <= spin_ceiling) self.step += 1;
    }
};

/// Test-and-test-and-set spinlock. **Test-only** mutual exclusion for the
/// harness reference oracle; NOT a lock-free primitive and never used on a
/// lock-free path. Built on `std.atomic` because 0.16 removed
/// `std.Thread.Mutex`.
pub const SpinLock = struct {
    state: std.atomic.Value(u32) = .init(unlocked),

    const unlocked: u32 = 0;
    const locked: u32 = 1;

    pub fn lock(self: *SpinLock) void {
        while (true) {
            // Fast path: try to grab an unlocked lock outright.
            if (self.state.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null) return;
            // Slow path: spin on a plain load (no bus-locking) until it looks
            // free, then retry the CAS. Classic TTAS to cut cache-line churn.
            while (self.state.load(.monotonic) != unlocked) std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        self.state.store(unlocked, .release);
    }
};

// ── tests (all mechanical, all run today) ────────────────────────────────────

const testing = std.testing;

test "Atomic instantiates, and is the type it claims to alias" {
    // `check-pubfn-reach` cannot analyse a generic body: there is none until
    // something instantiates it. Nothing in this repository instantiated
    // `Atomic`, so a deliberate semantic error in its body left
    // `test-lockfree`, `check-pubfn-reach` AND `example-lockfree` green — the
    // same class 924a3148 closed for six other generics.
    const A = Atomic(u32);

    // The property that makes it an ALIAS rather than merely something
    // atomic-shaped: it must hand back the very type it names. A body that
    // wrapped the value in a struct of its own would still compile, still
    // load and store, and still be wrong.
    try testing.expect(A == std.atomic.Value(u32));
    // …and it must be a function OF T, not a constant type.
    try testing.expect(Atomic(u64) != A);

    var v: A = .init(7);
    try testing.expectEqual(@as(u32, 7), v.load(.monotonic));
    try testing.expectEqual(@as(u32, 7), v.fetchAdd(5, .acq_rel)); // returns the PREVIOUS value
    try testing.expectEqual(@as(u32, 12), v.load(.acquire));
    v.store(3, .release);
    try testing.expect(v.cmpxchgStrong(3, 9, .acq_rel, .monotonic) == null); // CAS won
    // CAS lost: the value is 9, not the 4 that was expected, and the failure
    // hands back what was actually there.
    try testing.expectEqual(@as(u32, 9), v.cmpxchgStrong(4, 5, .acq_rel, .monotonic).?);
    try testing.expectEqual(@as(u32, 9), v.load(.monotonic));
}

test "Backoff escalates then yields without overflow" {
    var b: Backoff = .{};
    // Drive it well past both ceilings; must not panic / overflow `step`.
    var i: usize = 0;
    while (i < 64) : (i += 1) b.pause();
    try testing.expect(b.step == Backoff.step_ceiling);
    b.reset();
    try testing.expect(b.step == 0);
}

test "CachePadded rounds a small type up to at least one cache line" {
    const P = CachePadded(u32);
    try testing.expect(@sizeOf(P) >= cache_line);
    const p = P.init(7);
    try testing.expectEqual(@as(u32, 7), p.value);
}

const SpinCounter = struct {
    lock: SpinLock = .{},
    n: u64 = 0,

    fn bump(self: *SpinCounter, iters: u64) void {
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            self.lock.lock();
            self.n += 1;
            self.lock.unlock();
        }
    }
};

/// A pointer to `T` whose low bits — zero in any `*T`, by `T`'s alignment —
/// carry a small tag (crossbeam-epoch's tagged `Shared`): a mark bit for a
/// logically deleted node, a version to defeat ABA in a CAS, and so on.
pub fn TaggedPtr(comptime T: type) type {
    return struct {
        raw: usize,

        const Self = @This();
        /// How many tag bits `T`'s alignment leaves free (0 for align 1).
        pub const tag_bits: comptime_int = @ctz(@as(usize, @alignOf(T)));
        pub const tag_mask: usize = (1 << tag_bits) - 1;
        pub const null_ptr: Self = .{ .raw = 0 };

        /// `tag` must fit `tag_mask` (asserted).
        pub fn init(p: ?*T, tag_: usize) Self {
            std.debug.assert(tag_ & ~tag_mask == 0);
            return .{ .raw = @intFromPtr(p) | tag_ };
        }

        pub fn ptr(s: Self) ?*T {
            return @ptrFromInt(s.raw & ~tag_mask);
        }

        pub fn tag(s: Self) usize {
            return s.raw & tag_mask;
        }

        pub fn withTag(s: Self, tag_: usize) Self {
            std.debug.assert(tag_ & ~tag_mask == 0);
            return .{ .raw = (s.raw & ~tag_mask) | tag_ };
        }

        pub fn isNull(s: Self) bool {
            return s.raw & ~tag_mask == 0;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.raw == b.raw;
        }
    };
}

/// An atomic `TaggedPtr(T)` (crossbeam-epoch's `Atomic<T>`): pointer and tag
/// change together in one word, and the tag alone can be set, cleared or
/// flipped with one read-modify-write. Loads take no guard here — reading
/// EBR-managed memory through the result is safe only while pinned, as
/// with any pointer into a `Domain`'s structure.
pub fn TaggedAtomic(comptime T: type) type {
    return struct {
        raw: std.atomic.Value(usize),

        const Self = @This();
        pub const Ptr = TaggedPtr(T);

        pub fn init(p: Ptr) Self {
            return .{ .raw = .init(p.raw) };
        }

        pub fn load(self: *const Self, comptime order: std.builtin.AtomicOrder) Ptr {
            return .{ .raw = self.raw.load(order) };
        }

        pub fn store(self: *Self, p: Ptr, comptime order: std.builtin.AtomicOrder) void {
            self.raw.store(p.raw, order);
        }

        pub fn swap(self: *Self, p: Ptr, comptime order: std.builtin.AtomicOrder) Ptr {
            return .{ .raw = self.raw.swap(p.raw, order) };
        }

        /// Null on success, else the value found (pointer and tag compared).
        pub fn cmpxchgWeak(self: *Self, expected: Ptr, new: Ptr, comptime success: std.builtin.AtomicOrder, comptime failure: std.builtin.AtomicOrder) ?Ptr {
            const r = self.raw.cmpxchgWeak(expected.raw, new.raw, success, failure) orelse return null;
            return .{ .raw = r };
        }

        pub fn cmpxchgStrong(self: *Self, expected: Ptr, new: Ptr, comptime success: std.builtin.AtomicOrder, comptime failure: std.builtin.AtomicOrder) ?Ptr {
            const r = self.raw.cmpxchgStrong(expected.raw, new.raw, success, failure) orelse return null;
            return .{ .raw = r };
        }

        /// Set tag bits; returns the previous value. The pointer is untouched.
        pub fn fetchOrTag(self: *Self, tag_: usize, comptime order: std.builtin.AtomicOrder) Ptr {
            std.debug.assert(tag_ & ~Ptr.tag_mask == 0);
            return .{ .raw = self.raw.fetchOr(tag_, order) };
        }

        /// Keep only the tag bits set in `tag_`; returns the previous value.
        pub fn fetchAndTag(self: *Self, tag_: usize, comptime order: std.builtin.AtomicOrder) Ptr {
            std.debug.assert(tag_ & ~Ptr.tag_mask == 0);
            return .{ .raw = self.raw.fetchAnd(tag_ | ~Ptr.tag_mask, order) };
        }

        /// Flip tag bits; returns the previous value.
        pub fn fetchXorTag(self: *Self, tag_: usize, comptime order: std.builtin.AtomicOrder) Ptr {
            std.debug.assert(tag_ & ~Ptr.tag_mask == 0);
            return .{ .raw = self.raw.fetchXor(tag_, order) };
        }
    };
}

test "TaggedPtr and TaggedAtomic keep pointer and tag apart" {
    const Node = struct { v: u64 };
    var n1: Node = .{ .v = 1 };
    var n2: Node = .{ .v = 2 };
    const P = TaggedPtr(Node);
    try std.testing.expectEqual(3, P.tag_bits);
    const a = P.init(&n1, 5);
    try std.testing.expectEqual(&n1, a.ptr().?);
    try std.testing.expectEqual(@as(usize, 5), a.tag());
    try std.testing.expectEqual(&n1, a.withTag(2).ptr().?);
    try std.testing.expect(P.null_ptr.isNull() and P.null_ptr.withTag(1).isNull());
    try std.testing.expectEqual(@as(?*Node, null), P.null_ptr.withTag(7).ptr());
    var at = TaggedAtomic(Node).init(a);
    try std.testing.expect(at.load(.acquire).eql(a));
    try std.testing.expect(at.fetchOrTag(2, .acq_rel).eql(a));
    try std.testing.expectEqual(@as(usize, 7), at.load(.monotonic).tag());
    _ = at.fetchAndTag(1, .acq_rel);
    try std.testing.expectEqual(@as(usize, 1), at.load(.monotonic).tag());
    _ = at.fetchXorTag(3, .acq_rel);
    try std.testing.expectEqual(@as(usize, 2), at.load(.monotonic).tag());
    try std.testing.expectEqual(&n1, at.load(.monotonic).ptr().?);
    // The CAS compares the tag too: a stale tag fails even with the right pointer.
    try std.testing.expect(at.cmpxchgStrong(P.init(&n1, 0), P.init(&n2, 0), .acq_rel, .acquire) != null);
    try std.testing.expectEqual(@as(?TaggedPtr(Node), null), at.cmpxchgStrong(P.init(&n1, 2), P.init(&n2, 4), .acq_rel, .acquire));
    try std.testing.expectEqual(&n2, at.swap(P.null_ptr, .acq_rel).ptr().?);
    try std.testing.expect(at.load(.monotonic).isNull());
    // Align-1 types leave no tag bits.
    try std.testing.expectEqual(0, TaggedPtr(u8).tag_bits);
}

test "SpinLock gives exact mutual exclusion across real threads" {
    const per_thread: u64 = 50_000;
    const n_threads = 4;
    var c: SpinCounter = .{};
    var threads: [n_threads]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, SpinCounter.bump, .{ &c, per_thread });
    for (&threads) |*t| t.join();
    // If the lock leaked a single increment, this would be < expected.
    try testing.expectEqual(per_thread * n_threads, c.n);
}

test "Backoff.spin widens up to the spin ceiling and never goes past it" {
    var b: Backoff = .{};
    for (0..Backoff.spin_ceiling + 1) |i| {
        try std.testing.expectEqual(@as(u6, @intCast(i)), b.step);
        b.spin();
    }
    try std.testing.expectEqual(Backoff.spin_ceiling + 1, b.step);
    b.spin(); // saturated: still spins 2^spin_ceiling, step stays put
    try std.testing.expectEqual(Backoff.spin_ceiling + 1, b.step);
}
