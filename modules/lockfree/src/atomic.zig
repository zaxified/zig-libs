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

/// Alias so code here spells the atomic type through the module. Generic, so
/// it has no body until something instantiates it — see the test at the foot
/// of this file, which is the only instantiation in the repository and the
/// only reason a broken edit to this line does not compile green.
///
/// NOT re-exported by `root.zig` today (its four neighbours below are), so a
/// consumer cannot yet spell `lockfree.Atomic`; whether it should be is an
/// API question, not a defect in this line.
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
