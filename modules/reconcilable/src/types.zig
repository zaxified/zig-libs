// SPDX-License-Identifier: MIT
//! Shared value types for the reconciler: the reconcile `Outcome`, tuning
//! `Options`, counters, and the comptime key contract.

const std = @import("std");
const resilience = @import("resilience");

/// A monotonic instant in nanoseconds. The module never reads a clock — every
/// `now` is supplied by the caller (see SPEC.md §2), so the origin is
/// irrelevant and only differences matter. `resilience.Clock.monotonic` is the
/// obvious production source; tests pass a counter.
pub const Instant = u64;

/// What a reconcile pass concluded. Mirrors controller-runtime's documented
/// `(Result, error)` contract — see SPEC.md §3 for the mapping table.
pub const Outcome = union(enum) {
    /// Converged. The key is dropped from the queue and its failure streak is
    /// reset ("forgotten"), so the next failure starts at the base delay.
    done,
    /// Not converged, no self-chosen delay: come back as soon as the rate
    /// limiter allows. Counts as a failure for backoff purposes — the same
    /// meaning controller-runtime gives `Result{Requeue: true}`.
    requeue,
    /// Come back after exactly this many nanoseconds (a lease TTL, a rollback
    /// deadline, an external poll interval). **Forgets** the failure streak,
    /// like controller-runtime's `RequeueAfter`: the caller chose the delay,
    /// so the rate limiter must not also stretch it.
    requeue_after: u64,
    /// The pass failed. Backoff-scheduled exactly like `.requeue`; the error
    /// is additionally surfaced to `Options.on_error` and counted.
    failed: anyerror,
};

/// Disposition of a single `enqueue`/`enqueueAfter` call — useful for metrics
/// and for asserting dedup in tests.
pub const Admission = enum {
    /// A key that was not tracked is now queued.
    admitted,
    /// The key was already queued; the call collapsed into the pending item
    /// (this is the dedup guarantee, not an error).
    deduped,
    /// The key was waiting on a timer and has been pulled forward to ready.
    promoted,
    /// The key is mid-reconcile; the request was recorded and will be honoured
    /// after the in-flight pass returns.
    marked_dirty,
};

pub const Error = error{
    /// The queue is at its configured `capacity` and this key is not already
    /// tracked. Nothing was enqueued and `Stats.rejected` was incremented.
    /// See SPEC.md §5 — the recovery is a caller-driven full resync, which a
    /// level-triggered reconciler can always perform.
    AtCapacity,
};

/// Optional error sink. Kept as the repo's `{ctx, fn}` seam rather than a
/// log call so the module has no ambient globals and no logging opinion.
pub const ErrorSink = struct {
    ctx: ?*anyopaque = null,
    onErrorFn: *const fn (?*anyopaque, anyerror) void,
};

pub const Options = struct {
    /// Hard upper bound on **distinct tracked keys**. All per-key storage is
    /// allocated once at `init` and never grows, so this is simultaneously the
    /// memory bound and the admission bound (SPEC.md §5). Must be ≥ 1.
    capacity: u32,
    /// Maximum reconcile passes per `tick`. 0 = "everything that is ready at
    /// the top of the tick". This is the module's rate limiter: the caller
    /// owns the loop, so throughput is `budget / tick period` — expressed in
    /// the caller's own clock, with no second clock inside the module.
    budget_per_tick: u32 = 0,
    /// Per-item failure backoff. Only `base_delay_ms`, `factor`, `max_delay_ms`
    /// and `jitter` are consulted; `max_attempts`/`retryable` belong to
    /// `resilience.run` and are ignored here (see `max_failures` below for the
    /// give-up knob).
    backoff: resilience.Retry = .{
        .base_delay_ms = 5,
        .factor = 2.0,
        .max_delay_ms = 30_000,
        .jitter = .full,
    },
    /// Randomness for jitter. `null` with a jittered flavour degrades to the
    /// un-jittered schedule (documented `resilience.Retry` behaviour), which is
    /// what the deterministic tests rely on.
    random: ?std.Random = null,
    /// Consecutive failures after which a key is abandoned (dropped, counted in
    /// `Stats.abandoned`). 0 = never give up — the default, because a
    /// reconciler that forgets a desired key leaves the world permanently
    /// diverged. Set it only when an external alarm takes over.
    max_failures: u32 = 0,
    /// Where `.failed` errors go. `null` = discard.
    on_error: ?ErrorSink = null,
};

/// Monotonic counters. Cheap enough to read every tick; a consumer can diff
/// them into `metrics` counters.
pub const Stats = struct {
    /// `enqueue`/`enqueueAfter` calls that admitted a new key.
    admitted: u64 = 0,
    /// Calls that collapsed into an already-tracked key (the dedup win).
    deduped: u64 = 0,
    /// Calls rejected with `error.AtCapacity`.
    rejected: u64 = 0,
    /// Reconcile passes invoked.
    reconciled: u64 = 0,
    /// Passes that returned `.done`.
    converged: u64 = 0,
    /// Passes that returned `.requeue` or `.failed` (i.e. took backoff).
    retried: u64 = 0,
    /// Passes that returned `.failed`.
    failed: u64 = 0,
    /// Keys dropped by `max_failures`.
    abandoned: u64 = 0,
    /// Sticky: at least one `error.AtCapacity` happened, so the caller's view
    /// of desired state may no longer be fully represented in the queue and a
    /// full resync is required. Cleared only by `clearOverflow`.
    overflowed: bool = false,
};

/// What one `tick` did, and when the caller should come back.
pub const TickReport = struct {
    /// Reconcile passes run in this tick.
    reconciled: u32,
    /// Keys still ready to run (budget exhausted, or re-enqueued mid-tick).
    ready: u32,
    /// Keys parked on a timer.
    waiting: u32,
    /// Earliest instant at which `tick` would do work: `now` if `ready > 0`,
    /// else the earliest timer deadline, else null (idle). Feed this straight
    /// into a `poll(2)`/`epoll_wait` timeout.
    next_due: ?Instant,
};

/// Compile-time key contract: a key must be a **plain value** — no pointers,
/// no slices. Two reasons, both load-bearing:
///
///  1. **Ownership.** A queued key outlives the call that enqueued it, so a
///     slice key would make the queue borrow caller memory of unknown lifetime.
///     Plain keys are copied into the slot arena and own nothing.
///  2. **Hashing.** `std.AutoHashMapUnmanaged` needs `autoHash`, which refuses
///     pointers anyway; failing here gives a message that says what to do.
///
/// Intern strings to an index, or use a fixed-size array (`[32]u8` for a
/// WireGuard public key, `struct { ifindex: u32, handle: u32 }` for a `tc`
/// filter) — both are plain values and both hash.
pub fn assertPlainKey(comptime Key: type) void {
    switch (@typeInfo(Key)) {
        .int, .bool, .float, .@"enum", .void => {},
        .pointer => @compileError(
            "reconcilable: key type '" ++ @typeName(Key) ++
                "' contains a pointer or slice. A queued key outlives the enqueue call, " ++
                "so it must own its bytes: intern strings to an integer id, or use a " ++
                "fixed-size array key such as [32]u8.",
        ),
        .array => |a| assertPlainKey(a.child),
        .optional => |o| assertPlainKey(o.child),
        .@"struct" => |s| {
            inline for (s.fields) |f| assertPlainKey(f.type);
        },
        .@"union" => |u| {
            inline for (u.fields) |f| assertPlainKey(f.type);
        },
        else => @compileError(
            "reconcilable: key type '" ++ @typeName(Key) ++ "' is not a plain value type.",
        ),
    }
}

test "assertPlainKey accepts the shapes the consumers actually use" {
    assertPlainKey(u64);
    assertPlainKey([32]u8);
    assertPlainKey(struct { ifindex: u32, handle: u32 });
    assertPlainKey(enum { a, b });
    assertPlainKey(struct { id: u16, mac: [6]u8 });
}

test "Outcome is a small tagged union" {
    const o: Outcome = .{ .requeue_after = 1000 };
    try std.testing.expect(o == .requeue_after);
    try std.testing.expectEqual(@as(u64, 1000), o.requeue_after);
}
