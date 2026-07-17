// SPDX-License-Identifier: MIT

//! ebr — epoch-based reclamation. This file is split down the middle:
//!
//!  • **Mechanical storage / bookkeeping (real today):** the `Domain` (a
//!    global epoch counter + a fixed registry of participant slots), the
//!    per-thread `Participant` (its pinned local epoch, its in-use flag, and
//!    its three epoch-indexed limbo bags of retired nodes), and participant
//!    `register`/`unregister`. These are just typed storage + slot
//!    allocation; they contain no reclamation-safety logic.
//!
//!  • **THE FABLE CORE (gated `@panic` stubs — see `gate.zig`):** the four
//!    functions where one wrong memory ordering is a use-after-free —
//!    `enterCritical` (pin), `exitCritical` (unpin), `retire` (stage a node),
//!    and `tryAdvance` (the safe-reclaim predicate). These are the reason the
//!    module exists; they are left for a Fable agent.
//!
//! **Why EBR and not hazard pointers (SPEC has the full argument):** the
//! immediate consumer is the P2 DL4 in-process worker pool — a *fixed,
//! trusted* roster of threads registered once at pool construction, none of
//! which stalls indefinitely inside a critical section. EBR fits that shape:
//! one epoch publish per critical section (vs. a per-protected-pointer store
//! + fence on the hazard-pointer path), higher throughput, a smaller API. The
//! price — a stalled reader stalls reclamation (unbounded garbage) — is a
//! non-issue for a closed pool with short critical sections. The disqualifier
//! for EBR would be untrusted/unbounded threads or long blocking sections;
//! neither applies to DL4. If a future consumer needs bounded per-node
//! reclamation latency, hazard pointers become the next increment (SPEC).
//!
//! Reference design: Keir Fraser's epoch reclamation (PhD thesis, 2004) as
//! realized in crossbeam-epoch — a global epoch that advances only when every
//! pinned participant has been observed in the current epoch, with retired
//! nodes freed two epochs later (the "two grace periods" rule).

const std = @import("std");
const gate = @import("gate.zig");

/// A retired object awaiting safe reclamation: a type-erased pointer plus the
/// callback that will actually free it (e.g. return it to a `NodePool`). The
/// callback runs only once EBR proves no thread can still reach `ptr`.
pub const Retired = struct {
    ptr: *anyopaque,
    ctx: *anyopaque,
    reclaim: *const fn (ctx: *anyopaque, ptr: *anyopaque) void,
};

pub const Config = struct {
    /// Fixed upper bound on concurrently-registered threads. A worker pool
    /// knows its width at construction, so a fixed registry (no growth, no
    /// lock) is the right storage. Mechanical.
    max_participants: usize = 128,
};

/// Number of epoch-indexed limbo bags. Three is the minimum that lets the
/// "reclaim two epochs behind" rule never touch a bag a reader could still be
/// in: current, one-behind (draining), two-behind (safe to free).
pub const num_epochs = 3;

/// Per-thread reclamation state. Registered once, owned by exactly one thread
/// (single-owner) between register/unregister. The storage here is
/// mechanical; the *meaning* of `local_epoch` (a publish that orders against
/// `tryAdvance`) is the Fable core's responsibility.
pub const Participant = struct {
    /// The epoch this participant last pinned, or `unpinned` when outside any
    /// critical section. A concurrent `tryAdvance` reads this to decide
    /// whether it is safe to advance the global epoch.
    local_epoch: std.atomic.Value(u64),
    /// Registry-slot occupancy. Mechanical (register/unregister flip it).
    in_use: std.atomic.Value(bool),
    /// Limbo bags indexed by `epoch % num_epochs`. `retire` appends to the
    /// current bag; `tryAdvance` drains the two-behind bag. Storage only.
    bags: [num_epochs]std.ArrayListUnmanaged(Retired),

    /// Sentinel `local_epoch` value meaning "not inside a critical section".
    pub const unpinned: u64 = std.math.maxInt(u64);

    fn initInPlace(self: *Participant) void {
        self.local_epoch = .init(unpinned);
        self.in_use = .init(false);
        for (&self.bags) |*b| b.* = .empty;
    }

    fn deinitBags(self: *Participant, allocator: std.mem.Allocator) void {
        for (&self.bags) |*b| b.deinit(allocator);
    }
};

/// A pin token. Constructed by `enterCritical`, released (unpins) by
/// `release`. RAII-ish: hold it exactly as long as you hold references into
/// EBR-managed memory.
pub const Guard = struct {
    domain: *Domain,
    participant: *Participant,

    /// End the critical section (unpin). Delegates to the Fable core.
    pub fn release(self: Guard) void {
        self.domain.exitCritical(self.participant);
    }
};

pub const RegisterError = error{
    /// Every participant slot is occupied — `max_participants` too small for
    /// the actual thread count. Mechanical, not a safety condition.
    TooManyParticipants,
};

/// The reclamation domain: one global epoch + a fixed participant registry.
/// One `Domain` backs one lock-free structure (or a set that share a
/// reclamation lifetime).
pub const Domain = struct {
    /// Monotonically increasing global epoch. Advances only via `tryAdvance`.
    global_epoch: std.atomic.Value(u64),
    participants: []Participant,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) std.mem.Allocator.Error!Domain {
        const parts = try allocator.alloc(Participant, cfg.max_participants);
        for (parts) |*p| p.initInPlace();
        return .{
            .global_epoch = .init(0),
            .participants = parts,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Domain) void {
        for (self.participants) |*p| p.deinitBags(self.allocator);
        self.allocator.free(self.participants);
        self.* = undefined;
    }

    /// Read the current global epoch. Mechanical accessor (tests + the core).
    pub fn epoch(self: *const Domain) u64 {
        return self.global_epoch.load(.acquire);
    }

    /// Claim a participant slot for the calling thread. Mechanical: a linear
    /// scan + CAS on `in_use`. Returns a stable pointer the caller keeps for
    /// the lifetime of its participation.
    pub fn register(self: *Domain) RegisterError!*Participant {
        for (self.participants) |*p| {
            if (p.in_use.cmpxchgStrong(false, true, .acquire, .monotonic) == null) {
                p.local_epoch.store(Participant.unpinned, .release);
                return p;
            }
        }
        return RegisterError.TooManyParticipants;
    }

    /// Release a participant slot. Mechanical. Caller must be unpinned and
    /// must have drained its limbo bags (asserted in Debug) — leaking retired
    /// nodes on unregister would be a real bug, but detecting it is
    /// bookkeeping, not the reclamation-safety core.
    pub fn unregister(self: *Domain, p: *Participant) void {
        _ = self;
        std.debug.assert(p.local_epoch.load(.monotonic) == Participant.unpinned);
        if (std.debug.runtime_safety) {
            for (&p.bags) |*b| std.debug.assert(b.items.len == 0);
        }
        p.in_use.store(false, .release);
    }

    // ── THE FABLE CORE — gated `@panic` stubs ────────────────────────────────
    //
    // A Fable agent replaces each body below with a real, memory-ordering-
    // correct implementation and flips `gate.fable_core_implemented`. Until
    // then these panic; the harness's core-dependent tests SKIP.

    /// Pin: enter a critical section. Must publish the current global epoch
    /// into `p.local_epoch` such that any `tryAdvance` running concurrently
    /// either observes this pin (and refuses to advance past it) or is itself
    /// safe to reclaim ahead of it. This is the load-of-global then
    /// store-to-local with the acquire/release (or seq-cst) ordering that a
    /// naive implementation gets subtly wrong.
    pub fn enterCritical(self: *Domain, p: *Participant) Guard {
        _ = self;
        _ = p;
        @panic("TODO(fable/core): EBR enterCritical — publish global_epoch into participant.local_epoch with ordering that makes a concurrent tryAdvance either see this pin or be safe to reclaim past it (Fraser epoch pin)");
    }

    /// Unpin: leave a critical section. Must store `unpinned` with release
    /// ordering so a later `tryAdvance` cannot conclude this participant is
    /// still holding a reference into a bag it is about to free.
    pub fn exitCritical(self: *Domain, p: *Participant) void {
        _ = self;
        _ = p;
        @panic("TODO(fable/core): EBR exitCritical — store Participant.unpinned with release ordering so a subsequent tryAdvance sees the unpin");
    }

    /// Retire a node: stage `r` into this participant's current-epoch limbo
    /// bag. Must NOT free anything — freeing is deferred to `tryAdvance` two
    /// epochs later. Appending is nearly mechanical, but the choice of WHICH
    /// bag (which epoch snapshot to read, and its ordering against a
    /// concurrent advance) is part of the safety argument, so it stays core.
    pub fn retire(self: *Domain, p: *Participant, r: Retired) std.mem.Allocator.Error!void {
        _ = self;
        _ = p;
        _ = r;
        @panic("TODO(fable/core): EBR retire — append r to the participant's (global_epoch % num_epochs) limbo bag; it must not be reclaimed until two epoch advances prove no participant can still hold a reference");
    }

    /// The safe-reclaim predicate. Scan every in-use participant; if all
    /// pinned ones are pinned at the current global epoch, advance the global
    /// epoch by one and drain (`reclaim`) the caller's now-two-behind limbo
    /// bag. The single place where one wrong memory ordering — or advancing
    /// while a straggler is still pinned one epoch back — is a use-after-free.
    pub fn tryAdvance(self: *Domain, p: *Participant) void {
        _ = self;
        _ = p;
        @panic("TODO(fable/core): EBR tryAdvance — if every pinned participant is at global_epoch, CAS-advance the epoch and reclaim the two-behind bag; the ordering + the all-observed predicate are the UAF-critical kernel");
    }
};

// ── tests (mechanical bookkeeping only; the core is exercised by harness) ────

const testing = std.testing;

test "domain init/deinit with an empty registry" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 8 });
    defer d.deinit();
    try testing.expectEqual(@as(u64, 0), d.epoch());
    try testing.expectEqual(@as(usize, 8), d.participants.len);
}

test "register hands out distinct slots and unregister frees them for reuse" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 2 });
    defer d.deinit();

    const a = try d.register();
    const b = try d.register();
    try testing.expect(a != b);
    try testing.expect(a.in_use.load(.monotonic) and b.in_use.load(.monotonic));

    // Registry full → mechanical error, not a panic.
    try testing.expectError(error.TooManyParticipants, d.register());

    d.unregister(a);
    const c = try d.register(); // reuses a's slot
    try testing.expectEqual(a, c);
    d.unregister(b);
    d.unregister(c);
}

test "fresh participant is unpinned with empty limbo bags" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer d.deinit();
    const p = try d.register();
    try testing.expectEqual(Participant.unpinned, p.local_epoch.load(.monotonic));
    for (&p.bags) |*b| try testing.expectEqual(@as(usize, 0), b.items.len);
    d.unregister(p);
}
