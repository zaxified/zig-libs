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
//!  • **THE FABLE CORE (implemented — `gate.fable_core_implemented` is on):**
//!    the four functions where one wrong memory ordering is a use-after-free —
//!    `enterCritical` (pin), `exitCritical` (unpin), `retire` (stage a node),
//!    and `tryAdvance` (the safe-reclaim predicate). Each carries its memory-
//!    ordering argument in its doc comment; the full grace-period safety
//!    theorem lives at `tryAdvance`.
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
const atomic = @import("atomic.zig");

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
    /// NOTE: `tryAdvance` deliberately does NOT consult this flag — it scans
    /// `local_epoch` of every slot instead. Rationale: `register`'s CAS on
    /// `in_use` is acquire, not seq_cst, so a scan keyed on `in_use` could
    /// read a stale `false` for a slot that has already registered AND pinned,
    /// silently dropping that pin from the safe-to-advance predicate (a
    /// use-after-free). `local_epoch` of an unregistered slot is always
    /// `unpinned` (init + the register/unregister contract), so scanning all
    /// slots' `local_epoch` is both sufficient and race-free.
    in_use: std.atomic.Value(bool),
    /// Limbo bags indexed by `epoch % num_epochs`. `retire` appends to the
    /// current bag; `tryAdvance` drains bags that are ≥ 2 epochs old. Bags
    /// (and `bag_epoch`) are single-owner: only the owning thread ever touches
    /// them, so they need no atomicity — the epoch VALUES they are keyed by
    /// carry all cross-thread meaning.
    bags: [num_epochs]std.ArrayListUnmanaged(Retired),
    /// The epoch tag of the garbage currently in `bags[i]` (meaningful only
    /// while `bags[i]` is non-empty). Single-owner, plain field. This makes
    /// the reclaim predicate exact — "drain bag i iff observed_epoch −
    /// bag_epoch[i] ≥ 2" — instead of inferring age from bag position, which
    /// becomes ambiguous once the epoch wraps the 3-bag ring (bag `E % 3` may
    /// hold garbage tagged `E` or `E-3`; only the tag disambiguates).
    bag_epoch: [num_epochs]u64,

    /// Sentinel `local_epoch` value meaning "not inside a critical section".
    pub const unpinned: u64 = std.math.maxInt(u64);

    fn initInPlace(self: *Participant) void {
        self.local_epoch = .init(unpinned);
        self.in_use = .init(false);
        for (&self.bags) |*b| b.* = .empty;
        self.bag_epoch = @splat(0);
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

    /// Release a participant slot. Caller must be unpinned (asserted).
    ///
    /// Self-draining, may briefly block: any garbage still in this
    /// participant's limbo bags is reclaimed here by spinning `tryAdvance`
    /// (unpinned, with backoff) until the bags empty. The scaffold's original
    /// contract — "caller must have drained its bags" — is not satisfiable
    /// deterministically by a caller: draining needs the global epoch to move
    /// ≥ 2 past the last retire, and any concurrently pinned thread (e.g. one
    /// the OS preempted mid-pin) stalls that for as long as it likes, so a
    /// finite "drain then unregister" dance in the caller always has a losing
    /// schedule (observed as a rare unregister-assert abort in the gated
    /// stress test). Waiting is safe here: bags are single-owner, the spin
    /// runs unpinned (it cannot stall anyone else's reclamation), and it
    /// terminates under the module's own liveness contract — no thread stays
    /// pinned forever (per-attempt pins in `mpmc`; SPEC §2). A lone or last
    /// participant self-drains deterministically (its own scans see no other
    /// pins, so every `tryAdvance` advances). A non-blocking alternative —
    /// migrating leftovers to a domain-global limbo, crossbeam-style — is a
    /// documented next increment.
    pub fn unregister(self: *Domain, p: *Participant) void {
        std.debug.assert(p.local_epoch.load(.monotonic) == Participant.unpinned);
        var backoff: atomic.Backoff = .{};
        while (remainingGarbage(p) != 0) {
            self.tryAdvance(p);
            if (remainingGarbage(p) == 0) break;
            backoff.pause();
        }
        p.in_use.store(false, .release);
    }

    fn remainingGarbage(p: *const Participant) usize {
        var n: usize = 0;
        for (&p.bags) |*b| n += b.items.len;
        return n;
    }

    // ── THE FABLE CORE ───────────────────────────────────────────────────────
    //
    // Memory-model discipline for the whole kernel (see also the theorem at
    // `tryAdvance`): Zig 0.16 has no standalone fence (`@fence` was removed),
    // so the classic Fraser/crossbeam recipe — "store the pin, then a seq_cst
    // fence, then read shared pointers" — is not expressible. The sound
    // substitute used here is to make every reclamation-relevant atomic access
    // itself `.seq_cst`: the pin store, the unpin-visible scan loads, every
    // load/CAS of `global_epoch`, and (in `mpmc.zig`) every load/CAS of the
    // queue's head/tail/next pointers. All those operations then belong to the
    // single total order S that C11/LLVM guarantees over seq_cst operations,
    // and S is what forbids the store-buffering interleaving ("the scan misses
    // a pin AND the pinned thread reads a pre-unlink pointer") that acquire/
    // release alone permits. Each function below documents its own role in
    // that argument.

    /// Pin: enter a critical section.
    ///
    /// Ordering: `global_epoch` load `.seq_cst`, `local_epoch` store
    /// `.seq_cst`. Both must be seq_cst — this pair is one half of the Dekker
    /// interlock with `tryAdvance`:
    ///
    ///  • The **store** must be seq_cst so that it is ordered in S *before*
    ///    every shared-pointer load this thread subsequently performs (S is
    ///    consistent with program order). A release store would NOT give this:
    ///    release orders prior accesses before the store, but later loads may
    ///    still be satisfied "ahead" of it (store→load reordering — real on
    ///    x86 store buffers). With a plain release pin, a concurrent
    ///    `tryAdvance` scan could read the *pre-pin* `unpinned` value while
    ///    this thread's head-load has already returned a pre-unlink pointer —
    ///    the scan then advances twice past us and frees the node we hold:
    ///    use-after-free.
    ///  • The **load** must be seq_cst so the pinned value ε is anchored in S:
    ///    the CAS that published ε precedes our load in S, which is what the
    ///    grace-period proof uses to bound every reference-holder's pin by the
    ///    retirer's epoch read (see `tryAdvance`).
    ///
    /// The pinned value may be momentarily stale (the global epoch can advance
    /// between our load and our store — we are unpinned during that window, so
    /// nothing blocks an advance). That is SAFE, not a bug: a stale pin only
    /// makes us a straggler that conservatively blocks the next advance; the
    /// proof at `tryAdvance` never assumes the pin equals the current epoch.
    /// Hence no publish-revalidate loop is needed.
    pub fn enterCritical(self: *Domain, p: *Participant) Guard {
        // Single-owner discipline: no nested pins on one participant.
        std.debug.assert(p.local_epoch.load(.monotonic) == Participant.unpinned);
        const e = self.global_epoch.load(.seq_cst);
        p.local_epoch.store(e, .seq_cst);
        return .{ .domain = self, .participant = p };
    }

    /// Unpin: leave a critical section.
    ///
    /// Ordering: `.release` is necessary and sufficient. Necessary: every
    /// access this thread made to EBR-protected nodes (including plain,
    /// non-atomic reads of `Node.value`) must happen-before any reclaimer's
    /// free of those nodes. The chain is: our node accesses →(program order)
    /// this release store → a `tryAdvance` scan's seq_cst (⊇ acquire) load
    /// that reads it (synchronizes-with) → that thread's epoch CAS → the
    /// freeing thread's epoch load → the free. One release/acquire pair per
    /// hop; the poison memset in the pool therefore cannot race with our last
    /// read. Sufficient: unlike the pin, the unpin needs no store→load
    /// interlock — after unpinning we hold no references, so a scan that
    /// misses this store errs only toward NOT advancing (blocking reclamation
    /// briefly), never toward freeing early. Conservative direction = safe.
    pub fn exitCritical(self: *Domain, p: *Participant) void {
        _ = self;
        std.debug.assert(p.local_epoch.load(.monotonic) != Participant.unpinned);
        p.local_epoch.store(Participant.unpinned, .release);
    }

    /// Retire a node: stage `r` into this participant's limbo bag for the
    /// epoch read *now* from `global_epoch`. Frees nothing on this path unless
    /// the target bag still holds provably-expired garbage from three epochs
    /// ago (ring reuse), which is drained first.
    ///
    /// Contract: the caller must be pinned, and must call this *after* the
    /// store/CAS that made the node unreachable (the unlink). Ordering: the
    /// `global_epoch` load is `.seq_cst` and program-order-after the unlink
    /// CAS, so in S: unlink <S this load. The grace-period proof needs exactly
    /// that — the tag e' read here is ≥ (in S) any epoch value observed by any
    /// thread that could still have obtained a pre-unlink pointer, which is
    /// what bounds all reference-holders' pins by e' (see `tryAdvance`).
    ///
    /// Why the tag must be read from `global_epoch` and not taken from the
    /// caller's pin: the pin may lag the global epoch by one (stale pin, see
    /// `enterCritical`). Tagging with the (possibly older) pin value would
    /// free one epoch too early relative to a reference-holder pinned at the
    /// current epoch — a use-after-free. Reading fresh can only yield a tag ≥
    /// the pin, i.e. only defer reclamation. Conservative direction = safe.
    pub fn retire(self: *Domain, p: *Participant, r: Retired) std.mem.Allocator.Error!void {
        std.debug.assert(p.local_epoch.load(.monotonic) != Participant.unpinned);
        const e = self.global_epoch.load(.seq_cst);
        const idx: usize = @intCast(e % num_epochs);
        if (p.bags[idx].items.len != 0 and p.bag_epoch[idx] != e) {
            // Ring reuse: this bag's garbage is tagged e−3, e−6, … (same
            // residue mod 3, and a thread's epoch reads are monotone, so the
            // old tag is strictly smaller). e − tag ≥ 3 > 2 ⇒ its grace
            // period has long expired; drain before mixing in new garbage.
            std.debug.assert(e - p.bag_epoch[idx] >= num_epochs);
            drainBag(p, idx);
        }
        try p.bags[idx].append(self.allocator, r);
        p.bag_epoch[idx] = e;
    }

    /// The safe-reclaim predicate: reclaim this participant's expired limbo
    /// bags, and try to advance the global epoch by one.
    ///
    /// Reclaim rule: bag i may be drained iff `observed_epoch − bag_epoch[i]
    /// ≥ 2` — garbage retired at epoch e' is freed only once the caller has
    /// observed (or itself created, via the CAS) epoch ≥ e'+2. That is the
    /// classic two-grace-period window; with the mod-3 bags it means the bag
    /// being drained is never one a reader could still be pinned in.
    ///
    /// Advance rule: scan every slot's `local_epoch` (`.seq_cst`); if every
    /// pinned value equals the observed epoch E, CAS `global_epoch` E→E+1
    /// (`.seq_cst`). A pinned straggler at E−1 (or a stale pin at any older
    /// epoch) blocks the advance — that is the mechanism, not an error path.
    ///
    /// ── Grace-period safety theorem (why e'+2 is enough, and where every
    ///    ordering is load-bearing) ──────────────────────────────────────────
    ///
    /// Claim: when a thread F drains a bag with tag e' (so F's seq_cst
    /// epoch-read — or its own successful CAS — yielded E_f ≥ e'+2), no other
    /// thread holds, or can still obtain, a pointer to any node in that bag.
    ///
    /// Let N be such a node, unlinked by CAS U and retired by thread R whose
    /// retire-read returned e' (U <S retire-read, program order — `retire`'s
    /// contract). All stores to the queue's pointer atomics are seq_cst
    /// (mpmc.zig), so a seq_cst load ordered after U in S must observe the
    /// unlink; only a load L <S U can return a pre-unlink pointer.
    ///
    /// 1. **Bounding reference-holders.** Any thread T holding a pointer to N
    ///    obtained it via a seq_cst pointer-load L_T <S U, and T's pin
    ///    sequence (pin-load returning ε, pin-store P_T) is program-order —
    ///    hence S-order — before L_T. So: CAS-publishing-ε <S pin-load <S P_T
    ///    <S L_T <S U <S retire-read(=e'). `global_epoch` values are monotone
    ///    along S, therefore **ε ≤ e'**.
    /// 2. **Ref-holders block the advance to e'+2.** For global to reach
    ///    e'+2, some thread A CASes e'+1→e'+2; A's program order is: load
    ///    global (=e'+1) <S scan <S CAS. Consider A's scan-load of T's slot,
    ///    while T is still pinned at ε ≤ e':
    ///      • If it reads ε: ε ≤ e' < e'+1 = E fails the predicate — A aborts.
    ///      • If it misses the pin (reads the pre-pin value): a seq_cst load
    ///        may not read a value hb/mo-older than the latest seq_cst store
    ///        to that location preceding it in S, so the miss forces
    ///        scan <S P_T. Chaining: CAS-to-(e'+1) <S A's global-load <S scan
    ///        <S P_T <S L_T <S U <S retire-read — so the retire-read must have
    ///        returned ≥ e'+1, contradicting retire-read = e'. **The miss
    ///        cannot happen.** (This step is exactly the Dekker interlock; it
    ///        is why the pin store, the scan loads, the epoch accesses and the
    ///        queue pointer accesses must ALL be seq_cst — demote any one of
    ///        them to acquire/release and this contradiction evaporates.)
    ///      • If it reads a post-P_T value (T's later unpin/re-pin), T has
    ///        exited the critical section and dropped the reference; the
    ///        release(unpin)→acquire(scan) edge then makes T's last node
    ///        access happen-before A's CAS, and hence — through the CAS→
    ///        F's-epoch-read release/acquire edge (RMW release sequence) —
    ///        happen-before F's free. No data race with the poison memset.
    ///    So every reference-holder must unpin before global can reach e'+2;
    ///    F drains only at E_f ≥ e'+2, hence after they all exited.
    /// 3. **No new references.** A thread whose pointer-load is >S U reads
    ///    post-unlink values; head/tail are already past N and next-pointers
    ///    only lead away from it, so N is unreachable. A reused address
    ///    cannot alias N earlier than this theorem allows precisely because
    ///    reuse requires this reclamation (see the ABA note in `mpmc.zig`).
    ///
    /// Liveness note: the advance CAS may fail (another thread advanced
    /// first) — that is success for the system; this call simply returns and
    /// the caller's bags are drained against the newer epoch on a later call.
    /// tryAdvance never loops and never blocks.
    pub fn tryAdvance(self: *Domain, p: *Participant) void {
        const e = self.global_epoch.load(.seq_cst);
        reclaimExpired(p, e);

        // The safe-to-advance predicate: every pinned participant has been
        // observed AT the current epoch. Scans local_epoch of ALL slots —
        // deliberately not gated on `in_use` (see the field's doc comment):
        // unregistered slots read `unpinned` and pass; a mid-registration
        // slot that has already pinned MUST be counted, and is.
        for (self.participants) |*q| {
            const le = q.local_epoch.load(.seq_cst);
            if (le != Participant.unpinned and le != e) return;
        }

        if (self.global_epoch.cmpxchgStrong(e, e + 1, .seq_cst, .seq_cst) != null) return;
        // We created epoch e+1; one more bag of ours may just have expired.
        reclaimExpired(p, e + 1);
    }

    /// Drain every bag of `p` whose grace period has expired at `observed`.
    /// Single-owner (only `p`'s thread calls this with its own bags). The
    /// subtraction cannot underflow: a thread's epoch reads are monotone
    /// (same-location seq_cst loads in one thread), so `observed` ≥ every tag
    /// this participant has ever recorded.
    fn reclaimExpired(p: *Participant, observed: u64) void {
        for (0..num_epochs) |i| {
            if (p.bags[i].items.len != 0 and observed - p.bag_epoch[i] >= 2) {
                drainBag(p, i);
            }
        }
    }

    /// Run the reclaim callback on everything in bag `i`, then reset it
    /// (keeping capacity, so steady-state retire/drain cycles do not
    /// reallocate). Callers guarantee the grace period has expired.
    fn drainBag(p: *Participant, i: usize) void {
        const bag = &p.bags[i];
        for (bag.items) |r| r.reclaim(r.ctx, r.ptr);
        bag.clearRetainingCapacity();
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
