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

/// A retired object awaiting safe reclamation: a type-erased pointer plus the
/// callback that will actually free it (e.g. return it to a `NodePool`). The
/// callback runs only once EBR proves no thread can still reach `ptr`.
pub const Retired = struct {
    ptr: *anyopaque,
    ctx: *anyopaque,
    reclaim: *const fn (ctx: *anyopaque, ptr: *anyopaque) void,
};

pub const Config = struct {
    /// Participant slots allocated at `init` — the first chunk of the
    /// registry. With `growable` (the default), a `register` that finds every
    /// slot taken appends another chunk of this size (lock-free, never
    /// removed before `deinit`); without it, it fails `TooManyParticipants`.
    /// A worker pool that knows its width sizes this and never grows.
    max_participants: usize = 128,
    /// Whether `register` may add chunks of slots past `max_participants`
    /// (crossbeam's collectors register any number of threads).
    growable: bool = true,
    /// Limbo entries pre-allocated per bag, per participant, at `init` — the
    /// "bounded reserve" that makes `retire` allocation-free. `retire` runs
    /// pinned and *after* the unlink, so it is the one place in this module
    /// where an allocator failure cannot be handed back to the caller (see
    /// `retire`); the reserve moves that allocation to `init`, where the
    /// failure IS surfaceable. Bags keep their capacity across drains
    /// (`clearRetainingCapacity`), so the reserve is permanent and steady
    /// state never touches the allocator at all. Beyond the reserve `retire`
    /// still tries to grow the bag, and degrades safely (never fatally) if it
    /// cannot. Costs `max_participants * num_epochs * bag_reserve *
    /// @sizeOf(Retired)` bytes at `init`; set to 0 to opt out.
    bag_reserve: usize = 16,
    /// `advanceAmortized` runs `tryAdvance` once per this many calls (and
    /// whenever the caller asks for it unconditionally, e.g. on an empty
    /// dequeue). `tryAdvance` scans every slot's `local_epoch`, so calling it
    /// after each retire costs `max_participants` seq_cst loads per operation;
    /// this spreads the scan out. Liveness only — the reclaim predicate and
    /// every ordering are unchanged — and the price is limbo garbage of up to
    /// about `advance_period` nodes per participant per epoch. 0 counts as 1.
    advance_period: u32 = 64,
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
    /// Aligned to a cache line, so each participant's struct starts a line
    /// of its own: neighbouring threads' pins never share one.
    local_epoch: std.atomic.Value(u64) align(std.atomic.cache_line),
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
    /// Set by `unregister` when the departing thread still had limbo garbage it
    /// could not drain without waiting on someone else's pin. The slot then
    /// stays `in_use` and its bags stay put; any participant's next
    /// `tryAdvance` CASes this flag `true`→`false` to take **exclusive**
    /// ownership of the orphaned bags, drains whatever has expired, and frees
    /// the slot once they are empty (re-setting the flag if they are not).
    ///
    /// The CAS is the ONLY mutual exclusion over a departed slot's bags — bags
    /// are single-owner storage, and this transfers that ownership. Its
    /// `.acquire` success ordering pairs with `unregister`'s `.release` store,
    /// which is what makes the departing thread's final bag / `bag_epoch`
    /// writes visible to the adopter. Deliberately the SAME ordering pair the
    /// registry already uses for `in_use` (`register`'s acquire CAS ⇄
    /// `unregister`'s release store), so it introduces no new lowering — see
    /// SPEC §7.
    orphaned: std.atomic.Value(bool),
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
    /// How many retired nodes this participant had to abandon because its
    /// limbo bag could not grow (reserve exhausted *and* the allocator
    /// failed). Single-owner plain counter, like the bags themselves — read it
    /// through `Domain.droppedRetires` when the domain is quiescent. Nonzero
    /// means pool slots were permanently withheld from reuse (never freed, so
    /// never a use-after-free); see `retire`.
    dropped_retires: usize,
    /// Calls to `Domain.advanceAmortized` since its last `tryAdvance`.
    /// Single-owner plain counter.
    since_advance: u32,
    /// Open `enterCritical`s beyond the outermost (crossbeam's nested
    /// guards): only the outermost pins and only its exit unpins. Touched
    /// only when nesting — whether the participant is pinned at all is its
    /// own `local_epoch`, so the plain pin+unpin pair writes nothing else
    /// (a depth store there cost it 25 %, 2026-10-14). Single-owner.
    nested_pins: u32,
    /// Owner-private mirror of "inside a critical section" (`local_epoch !=
    /// unpinned`), so the misuse checks below read a plain field of the
    /// owner's own line instead of an atomic (sweep LF-1). Written only by
    /// the owning thread, in `enterCritical` / `exitCritical`.
    pinned: bool,
    /// This slot's position in the registry, chunk after chunk
    /// (`Domain.slotIndex`). Fixed at the chunk's creation.
    index: usize,

    /// Sentinel `local_epoch` value meaning "not inside a critical section".
    pub const unpinned: u64 = std.math.maxInt(u64);

    /// Whether this participant is inside a critical section. From its
    /// owner thread (the field is the owner's).
    pub fn isPinned(self: *const Participant) bool {
        return self.local_epoch.load(.monotonic) != unpinned;
    }

    fn initInPlace(self: *Participant, index: usize) void {
        self.local_epoch = .init(unpinned);
        self.in_use = .init(false);
        self.orphaned = .init(false);
        for (&self.bags) |*b| b.* = .empty;
        self.bag_epoch = @splat(0);
        self.dropped_retires = 0;
        self.since_advance = 0;
        self.nested_pins = 0;
        self.pinned = false;
        self.index = index;
    }

    fn deinitBags(self: *Participant, allocator: std.mem.Allocator) void {
        for (&self.bags) |*b| b.deinit(allocator);
    }
};

/// Messages of the checked panics on EBR misuse (sweep LF-1); kept as
/// constants so the tests can look for them.
pub const msg_enter_pinned = "lockfree: enterCritical on a participant that is already pinned (use enterCriticalNested)";
pub const msg_exit_unpinned = "lockfree: exitCritical on a participant that is not pinned";
pub const msg_repin_unpinned = "lockfree: repin on a participant that is not pinned";
pub const msg_retire_unpinned = "lockfree: retire on a participant that is not pinned (retire runs inside the pin, after the unlink)";
pub const msg_unregister_unowned = "lockfree: unregister of a participant that is not registered (double unregister, or already handed off as an orphan)";
pub const msg_unregister_pinned = "lockfree: unregister of a participant that is still pinned";

/// A pin token. Constructed by `enterCritical` (or `Domain.pin`), released
/// (unpins) by `release`. RAII-ish: hold it exactly as long as you hold
/// references into EBR-managed memory. Guards nest: an inner one's `release`
/// leaves the participant pinned until the outermost is released.
///
/// Release each guard exactly once. A double `release` of the OUTERMOST guard
/// is a checked panic (`msg_exit_unpinned`), but while guards are nested a
/// second release of an inner one just decrements the nesting count again and
/// unpins the outer section early: a guard carries no per-guard state, so
/// that is undetectable (sweep REV-lockfree-3).
pub const Guard = struct {
    domain: *Domain,
    participant: *Participant,

    /// End the critical section (unpin). Delegates to the Fable core.
    pub fn release(self: Guard) void {
        self.domain.exitCritical(self.participant);
    }

    /// Re-pin at the current epoch without leaving the critical section, so
    /// a long-running pinned thread stops holding the epoch back
    /// (crossbeam's `repin`). Every reference read under this guard is
    /// INVALID afterwards — exactly as after `release`. Only the outermost
    /// guard re-pins; under nested guards this does nothing.
    pub fn repin(self: Guard) void {
        self.domain.repin(self.participant);
    }

    /// Unpin, run `f(context)`, pin again (crossbeam's `repin_after`): for a
    /// blocking call in the middle of a pinned loop. References read before
    /// are invalid afterwards. Under nested guards `f` runs pinned.
    pub fn repinAfter(self: Guard, context: anytype, comptime f: anytype) @typeInfo(@TypeOf(f)).@"fn".return_type.? {
        const p = self.participant;
        if (p.nested_pins != 0) return f(context);
        self.domain.exitCritical(p);
        defer _ = self.domain.enterCritical(p);
        return f(context);
    }

    /// Reclaim this participant's expired garbage now and try to advance the
    /// epoch (crossbeam's `flush`).
    pub fn flush(self: Guard) void {
        self.domain.tryAdvance(self.participant);
    }

    /// Stage `r` for reclamation once no thread can reach it — the caller's
    /// unlink must come first (`Domain.retire`; crossbeam's `defer_unchecked`).
    pub fn retire(self: Guard, r: Retired) void {
        self.domain.retire(self.participant, r);
    }
};

pub const RegisterError = error{
    /// Every participant slot is occupied and the registry may not grow
    /// (`Config.growable = false`) — `max_participants` too small for the
    /// actual thread count. Mechanical, not a safety condition.
    TooManyParticipants,
} || std.mem.Allocator.Error;

pub const PinError = RegisterError || error{
    /// This thread already holds default participants (`Domain.pin`) of
    /// `max_thread_domains` domains; `unregisterCurrentThread` frees one.
    TooManyDomainsPerThread,
};

/// Domains one thread can `pin` through its default participant at once.
pub const max_thread_domains = 16;

/// A registry chunk appended when the slots before it are all taken.
const Chunk = struct {
    slots: []Participant,
    /// The next chunk; stored once, by the appending CAS.
    next: std.atomic.Value(?*Chunk),
};

/// The calling thread's default participants, keyed by `Domain.id` (never
/// by address: a later domain at a freed one's address must not inherit
/// its entry). Id 0 is a free entry.
const ThreadEntry = struct { id: u64 = 0, participant: ?*Participant = null };
threadlocal var thread_entries: [max_thread_domains]ThreadEntry = @splat(.{});
var next_domain_id: std.atomic.Value(u64) = .init(1);

/// The reclamation domain: one global epoch + a fixed participant registry.
/// One `Domain` backs one lock-free structure (or a set that share a
/// reclamation lifetime).
pub const Domain = struct {
    /// Monotonically increasing global epoch. Advances only via `tryAdvance`.
    global_epoch: std.atomic.Value(u64),
    participants: []Participant,
    allocator: std.mem.Allocator,
    /// How many slots are currently orphaned (see `Participant.orphaned`). A
    /// hint only: `tryAdvance` reads it `.monotonic` on its hot path and skips
    /// the orphan scan when it reads zero. A stale zero costs nothing — the
    /// orphan is adopted by a later `tryAdvance`; reclamation in EBR is
    /// eventual by construction (garbage sits in a bag until *somebody*
    /// advances). Nothing about the grace-period proof depends on this
    /// counter, which is why it may be `.monotonic`.
    orphan_count: std.atomic.Value(usize),
    /// `Config.advance_period`.
    advance_period: u32,
    /// Chunks past `participants`, appended by `register` (see `Chunk`).
    more: std.atomic.Value(?*Chunk),
    /// `Config.growable`, `Config.bag_reserve`.
    growable: bool,
    bag_reserve: usize,
    /// Unique for the process's lifetime: keys the per-thread default
    /// participants (`pin`).
    id: u64,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) std.mem.Allocator.Error!Domain {
        const parts = try allocSlots(allocator, cfg.max_participants, 0, cfg.bag_reserve);
        return .{
            .global_epoch = .init(0),
            .participants = parts,
            .allocator = allocator,
            .orphan_count = .init(0),
            .advance_period = @max(cfg.advance_period, 1),
            .more = .init(null),
            .growable = cfg.growable,
            .bag_reserve = cfg.bag_reserve,
            .id = next_domain_id.fetchAdd(1, .monotonic),
        };
    }

    /// `n` unregistered slots numbered from `first_index`, each with its
    /// limbo reserve.
    fn allocSlots(allocator: std.mem.Allocator, n: usize, first_index: usize, bag_reserve: usize) std.mem.Allocator.Error![]Participant {
        const parts = try allocator.alloc(Participant, n);
        errdefer allocator.free(parts);
        for (parts, first_index..) |*p, i| p.initInPlace(i);
        // Pre-allocate the limbo reserve HERE, where a failure is just an
        // `error.OutOfMemory` out of `init`, so that `retire` — which runs
        // pinned, after the unlink, with no way to hand an error back — has
        // somewhere to stage a node without calling the allocator. Bags are
        // `.empty` at this point, so deinitting a partially-reserved set is
        // safe. See `Config.bag_reserve` and `retire`.
        errdefer for (parts) |*p| p.deinitBags(allocator);
        for (parts) |*p| {
            for (&p.bags) |*b| try b.ensureTotalCapacity(allocator, bag_reserve);
        }
        return parts;
    }

    /// Every slot of the registry, chunk after chunk. The links are read
    /// `.seq_cst`: `tryAdvance`'s scan relies on it (see `register`).
    const SlotIter = struct {
        slots: []Participant,
        i: usize = 0,
        link: *const std.atomic.Value(?*Chunk),

        fn next(it: *SlotIter) ?*Participant {
            while (it.i == it.slots.len) {
                const c = it.link.load(.seq_cst) orelse return null;
                it.slots = c.slots;
                it.i = 0;
                it.link = &c.next;
            }
            it.i += 1;
            return &it.slots[it.i - 1];
        }
    };

    fn slotIter(self: *const Domain) SlotIter {
        return .{ .slots = self.participants, .link = &self.more };
    }

    /// Free the registry. Any garbage still sitting in a limbo bag — including
    /// an orphaned slot's (see `unregister`) — has its *staging storage* freed
    /// but its reclaim callback is deliberately NOT run: the callback returns
    /// a node to a pool that the consumer's teardown order may already have
    /// destroyed (the harness deinits pool before domain), so running it here
    /// would be the use-after-free this module exists to prevent. The effect is
    /// the same conservative direction `retire`'s abandon path takes — the
    /// nodes are never reused, never freed twice, and the storage they occupy
    /// is released by the pool's own `deinit`. Call `orphanedSlots()` before
    /// teardown if a consumer wants to assert nothing was left behind.
    ///
    /// Threads that used `pin` should `unregisterCurrentThread` first; an
    /// entry they keep is inert (it names this domain's id, never reused).
    pub fn deinit(self: *Domain) void {
        for (&thread_entries) |*e| {
            if (e.id == self.id) e.* = .{};
        }
        for (self.participants) |*p| p.deinitBags(self.allocator);
        self.allocator.free(self.participants);
        var c = self.more.load(.monotonic);
        while (c) |chunk| {
            c = chunk.next.load(.monotonic);
            for (chunk.slots) |*p| p.deinitBags(self.allocator);
            self.allocator.free(chunk.slots);
            self.allocator.destroy(chunk);
        }
        self.* = undefined;
    }

    /// The registry index of `p`, stable while it is registered: lets a
    /// structure over this domain keep per-participant state in an array (the
    /// first chunk's slots are `0..max_participants`, later chunks continue
    /// the numbering). Mechanical.
    pub fn slotIndex(self: *const Domain, p: *const Participant) usize {
        _ = self;
        return p.index;
    }

    /// Read the current global epoch. Mechanical accessor (tests + the core).
    pub fn epoch(self: *const Domain) u64 {
        return self.global_epoch.load(.acquire);
    }

    /// Claim a participant slot for the calling thread. Mechanical: a linear
    /// scan + CAS on `in_use`. Returns a stable pointer the caller keeps for
    /// the lifetime of its participation.
    ///
    /// When every slot is taken and the registry is `growable`, a chunk of
    /// `max_participants` new slots is allocated, its first slot claimed
    /// before anyone can see it, and the chunk appended to the end of the
    /// chain by a `.seq_cst` CAS on the last link. **Why a scan cannot miss
    /// a thread that registered in a chunk it did not reach** (the theorem at
    /// `tryAdvance`, step 2, "misses the pin"): the scan reached the end of
    /// the chain by a `.seq_cst` load of a link that read null, so that load
    /// precedes, in S, the CAS that later stored the chunk there; every
    /// thread registered in that chunk read the link (or is the appender)
    /// before its pin store. So scan <S P_T — the same order the theorem
    /// derives from a missed slot, and it reaches the same contradiction.
    pub fn register(self: *Domain) RegisterError!*Participant {
        var it = self.slotIter();
        while (it.next()) |p| {
            if (p.in_use.cmpxchgStrong(false, true, .acquire, .monotonic) == null) {
                p.local_epoch.store(Participant.unpinned, .release);
                return p;
            }
        }
        if (!self.growable) return RegisterError.TooManyParticipants;
        return self.appendChunk();
    }

    fn appendChunk(self: *Domain) RegisterError!*Participant {
        const n = self.participants.len;
        const chunk = try self.allocator.create(Chunk);
        errdefer self.allocator.destroy(chunk);
        // Index the slots after the last chunk's; fixed below once the
        // chunk's place in the chain is known.
        const slots = try allocSlots(self.allocator, @max(n, 1), 0, self.bag_reserve);
        chunk.* = .{ .slots = slots, .next = .init(null) };
        const mine = &slots[0];
        mine.in_use = .init(true);
        var link: *std.atomic.Value(?*Chunk) = &self.more;
        var first_index = n;
        while (true) {
            if (link.load(.seq_cst)) |c| {
                first_index += c.slots.len;
                link = &c.next;
                continue;
            }
            for (slots, first_index..) |*p, i| p.index = i;
            // Release (⊂ seq_cst) publishes the slots' initial state to a
            // scanner that loads this link.
            if (link.cmpxchgStrong(null, chunk, .seq_cst, .seq_cst) == null) return mine;
        }
    }

    /// Upper bound on the `tryAdvance` attempts `unregister` makes before it
    /// hands its leftover garbage off instead of draining it itself.
    ///
    /// A lone or last participant drains deterministically: its own scan sees
    /// no other pins, so every attempt advances the epoch by one, and garbage
    /// tagged `e'` is freed once the epoch reaches `e'+2` — at most one
    /// generation per bag, i.e. `num_epochs` bags plus the two-epoch window.
    /// Anything beyond that means some OTHER thread's pin is blocking the
    /// advance, and no number of further attempts is guaranteed to help — that
    /// is precisely the case this bound refuses to spin on.
    const max_unregister_advances = num_epochs + 2;

    /// Release a participant slot. Caller must be unpinned (checked panic `msg_unregister_pinned`).
    /// **Non-blocking: never waits on another thread.**
    ///
    /// Two phases. First a BOUNDED self-drain (`max_unregister_advances`
    /// `tryAdvance` attempts, no backoff, no retry loop): this is the common
    /// case and it completes deterministically for a lone or last participant,
    /// so a single-threaded teardown still leaves nothing behind. If garbage
    /// remains — which can only mean a concurrently pinned peer is blocking the
    /// epoch, e.g. one the OS preempted mid-pin — the slot is **orphaned**
    /// instead: `orphaned` is published, `in_use` stays set (the bags are still
    /// live storage), and the call returns. Any participant's next
    /// `tryAdvance` adopts the slot, drains what has expired, and frees it.
    ///
    /// This replaces the previous unbounded `while (remainingGarbage) {
    /// tryAdvance; backoff.pause(); }` spin. That spin could not deadlock (the
    /// spinner is unpinned, so it stalls nobody else's reclamation) and it
    /// terminated under the module's liveness contract — no thread stays pinned
    /// forever (SPEC §2) — but its termination *depended on other threads*,
    /// which is exactly the property a lock-free module should not have. The
    /// scaffold's original contract, "caller must have drained its bags", is
    /// not satisfiable deterministically by a caller either: draining needs the
    /// global epoch to move ≥ 2 past the last retire, and any pinned peer
    /// stalls that for as long as it likes, so a finite "drain then unregister"
    /// dance in the caller always has a losing schedule (observed as a rare
    /// unregister-assert abort in the gated stress test).
    ///
    /// **Ordering:** unchanged from before for every reclamation-relevant
    /// atomic. The one new access is the `orphaned` `.release` store, which
    /// publishes the departing thread's final bag / `bag_epoch` writes to
    /// whichever adopter wins the `.acquire` CAS in `adoptOrphans` — the same
    /// release/acquire pair the registry already uses for `in_use`. The
    /// grace-period theorem at `tryAdvance` is untouched: it never named the
    /// draining thread, only the epoch it observed, and `adoptOrphans` re-reads
    /// the epoch after acquiring the slot (see there).
    pub fn unregister(self: *Domain, p: *Participant) void {
        if (p.pinned) @panic(msg_unregister_pinned); // nested_pins != 0 implies pinned
        // Double unregister: a freed slot may already belong to another thread
        // (clearing its `in_use` would steal it), an orphan would be counted
        // twice (sweep REV-lockfree-2).
        if (!p.in_use.load(.monotonic) or p.orphaned.load(.monotonic)) @panic(msg_unregister_unowned);
        var attempts: usize = 0;
        while (remainingGarbage(p) != 0 and attempts < max_unregister_advances) : (attempts += 1) {
            self.tryAdvance(p);
        }
        if (remainingGarbage(p) != 0) {
            // Hand off. `in_use` deliberately stays `true`: the slot is not
            // free until its garbage is gone, and `tryAdvance`'s scan reads
            // `local_epoch` (= `unpinned` here), never `in_use`, so an orphan
            // slot cannot block an epoch advance.
            _ = self.orphan_count.fetchAdd(1, .monotonic);
            p.orphaned.store(true, .release);
            return;
        }
        p.in_use.store(false, .release);
    }

    /// Adopt any orphaned slot: take exclusive ownership of its bags, reclaim
    /// what has expired, and free the slot when they are empty. Called from
    /// `tryAdvance`; a no-op (one `.monotonic` load) when there are none.
    ///
    /// Why this is safe to do from a foreign thread. The grace-period theorem
    /// (`tryAdvance`) is a statement about a bag's tag and the epoch the
    /// draining thread observed — it never names *which* thread drains. Two
    /// obligations remain, and both are discharged here:
    ///
    ///  1. **Exclusivity.** Bags are single-owner storage. The
    ///     `true`→`false` CAS on `orphaned` has exactly one winner, and the
    ///     departing thread has already returned, so the winner is the sole
    ///     accessor. Its `.acquire` success ordering pairs with `unregister`'s
    ///     `.release` store, making the departing thread's last bag and
    ///     `bag_epoch` writes visible.
    ///  2. **No epoch underflow.** `reclaimExpired` computes
    ///     `observed - bag_epoch[i]`, which is safe only when `observed` is at
    ///     least the tag. For a thread's OWN bags that holds by per-thread
    ///     monotonicity of its epoch reads. For a foreign bag it does not — so
    ///     the epoch is re-read HERE, after the acquiring CAS. The departing
    ///     thread's tag-producing `global_epoch` read happens-before its
    ///     release store, which happens-before our acquiring CAS, which
    ///     precedes this load in program order; read-read coherence on
    ///     `global_epoch` then forbids this load from returning a value older
    ///     than the tag. (Passing the caller's earlier `e` would NOT be sound:
    ///     that load can precede the orphan's retire in the modification
    ///     order.)
    fn adoptOrphans(self: *Domain) void {
        if (self.orphan_count.load(.monotonic) == 0) return;
        var it = self.slotIter();
        while (it.next()) |q| {
            if (!q.orphaned.load(.monotonic)) continue;
            if (q.orphaned.cmpxchgStrong(true, false, .acquire, .monotonic) != null) continue;
            // Exclusive owner of q's bags from here.
            const eo = self.global_epoch.load(.seq_cst);
            reclaimExpired(q, eo);
            if (remainingGarbage(q) == 0) {
                _ = self.orphan_count.fetchSub(1, .monotonic);
                q.in_use.store(false, .release);
            } else {
                // Still expiring — publish it back for a later adopter.
                q.orphaned.store(true, .release);
            }
        }
    }

    /// Slots whose owner has departed but whose limbo garbage has not expired
    /// yet. Mechanical accessor for tests and teardown assertions.
    pub fn orphanedSlots(self: *const Domain) usize {
        return self.orphan_count.load(.monotonic);
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
    ///
    ///
    /// The participant must be unpinned (checked panic `msg_enter_pinned`);
    /// `enterCriticalNested` (and `pin`) also take an already pinned one. The
    /// check reads the owner-private `pinned` field, not `local_epoch`: a
    /// load of the `local_epoch` the previous `exitCritical` just stored —
    /// store-forwarded, on the path to the `xchg` — cost +25 % on a pin+unpin
    /// pair (`epoch_pin` 1.00 → 1.25× crossbeam, 2026-10-14).
    pub fn enterCritical(self: *Domain, p: *Participant) Guard {
        if (p.pinned) @panic(msg_enter_pinned);
        p.pinned = true;
        const e = self.global_epoch.load(.seq_cst);
        p.local_epoch.store(e, .seq_cst);
        return .{ .domain = self, .participant = p };
    }

    /// `enterCritical` that also nests (crossbeam's nested guards): on an
    /// already pinned participant it only counts (`nested_pins`), and the
    /// participant stays pinned at the outer pin's epoch, which covers every
    /// reference the inner section reads — the theorem bounds
    /// reference-holders by their pin store, and the outer one precedes
    /// every load of the inner section. `exitCritical` undoes either.
    pub fn enterCriticalNested(self: *Domain, p: *Participant) Guard {
        // Owner-private: this thread is the only writer of its pin.
        if (!p.pinned) return self.enterCritical(p);
        p.nested_pins += 1;
        return .{ .domain = self, .participant = p };
    }

    /// Outermost pin only: move the pin to the current epoch (`Guard.repin`).
    /// The same seq_cst load + seq_cst store as `enterCritical`. The store
    /// replaces the old pin in one step; as a release store it also ends the
    /// old section for a scanner that reads it (the theorem's "post-P_T
    /// value" case — the caller has dropped its references, as after an
    /// unpin), and as a seq_cst store it is the new section's pin.
    pub fn repin(self: *Domain, p: *Participant) void {
        if (!p.pinned) @panic(msg_repin_unpinned);
        if (p.nested_pins != 0) return;
        const e = self.global_epoch.load(.seq_cst);
        if (p.local_epoch.load(.monotonic) == e) return;
        p.local_epoch.store(e, .seq_cst);
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
        if (!p.pinned) @panic(msg_exit_unpinned);
        if (p.nested_pins != 0) {
            p.nested_pins -= 1;
            return;
        }
        p.pinned = false;
        p.local_epoch.store(Participant.unpinned, .release);
    }

    /// Pin through this thread's default participant, registering one on the
    /// thread's first call (crossbeam's `Collector::register` + `pin` behind
    /// a thread-local handle). Up to `max_thread_domains` domains per thread;
    /// `unregisterCurrentThread` releases the participant (Zig has no
    /// thread-exit hook, so this is explicit).
    ///
    /// A thread that exits WITHOUT `unregisterCurrentThread` leaks its slot
    /// (`in_use` stays set and its garbage is never adopted: it is not
    /// orphaned). A long-lived thread that pins many short-lived domains
    /// without ever calling it keeps their entries in its 16-entry table and
    /// eventually gets `TooManyDomainsPerThread` (sweep REV-lockfree-5).
    pub fn pin(self: *Domain) PinError!Guard {
        return self.enterCriticalNested(try self.currentParticipant());
    }

    /// This thread's default participant (see `pin`), registered on first use.
    pub fn currentParticipant(self: *Domain) PinError!*Participant {
        for (&thread_entries) |*e| {
            if (e.id == self.id) return e.participant.?;
        }
        const free = for (&thread_entries) |*e| {
            if (e.id == 0) break e;
        } else return error.TooManyDomainsPerThread;
        const p = try self.register();
        free.* = .{ .id = self.id, .participant = p };
        return p;
    }

    /// Release the calling thread's default participant, if it has one. The
    /// thread must not be pinned through it.
    pub fn unregisterCurrentThread(self: *Domain) void {
        for (&thread_entries) |*e| {
            if (e.id == self.id) {
                self.unregister(e.participant.?);
                e.* = .{};
                return;
            }
        }
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
    ///
    /// **Infallible, by construction and by necessity.** `retire`'s contract
    /// puts it after the unlink and inside the pin: by then the node is gone
    /// from the structure and its payload has been handed to the caller, so
    /// there is nothing left to roll back and no error the caller could act
    /// on — which is why the sole caller (`mpmc.dequeue`, a `?u64`) used to
    /// `@panic` on `error.OutOfMemory`. Two mechanisms remove that panic
    /// without touching a single ordering on the success path:
    ///  1. `Config.bag_reserve` limbo entries per bag are pre-allocated at
    ///     `init`, so staging a node needs no allocator at all until one
    ///     epoch's garbage from one thread exceeds the reserve; and bags keep
    ///     capacity across drains, so steady state stays allocation-free.
    ///  2. If the reserve *is* exceeded and the grow also fails, the node is
    ///     **abandoned**: not staged, and — critically — not freed. Of the
    ///     three possible responses, freeing it inline is a use-after-free
    ///     (readers may still hold it) and aborting the process loses all
    ///     memory rather than one node; abandoning is the only one that is
    ///     safe in the reclamation sense. An abandoned node is never returned
    ///     to the pool, hence never re-acquired, hence can never alias a live
    ///     node — the same "conservative direction" the rest of this file
    ///     takes. It is not a heap leak either: the node is a `NodePool`
    ///     slot, which `NodePool.deinit` destroys at teardown regardless; the
    ///     loss is bounded pool capacity, counted in `dropped_retires` and
    ///     readable via `droppedRetires` so a caller can assert on it.
    ///
    /// The epoch tag is left untouched on the abandon path: the bag is
    /// unchanged, and an empty bag's tag is meaningless (`reclaimExpired`
    /// only looks at non-empty bags).
    pub fn retire(self: *Domain, p: *Participant, r: Retired) void {
        if (!p.pinned) @panic(msg_retire_unpinned);
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
        p.bags[idx].append(self.allocator, r) catch {
            p.dropped_retires += 1;
            return;
        };
        p.bag_epoch[idx] = e;
    }

    /// Total nodes abandoned by `retire` across all participant slots (see
    /// `retire`). Nonzero means the limbo reserve was exhausted under a
    /// failing allocator and that many pool slots were withheld from reuse —
    /// safe, but worth alerting on. Reads plain single-owner counters, so
    /// call it when the domain is quiescent (same contract as
    /// `NodePool.verifyQuiescent`), not from a racing thread.
    pub fn droppedRetires(self: *const Domain) usize {
        var n: usize = 0;
        var it = self.slotIter();
        while (it.next()) |p| n += p.dropped_retires;
        return n;
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
        // Inherit any departed participant's leftover garbage. Costs one
        // `.monotonic` load when there is none, which is the steady state.
        self.adoptOrphans();

        // The safe-to-advance predicate: every pinned participant has been
        // observed AT the current epoch. Scans local_epoch of ALL slots —
        // deliberately not gated on `in_use` (see the field's doc comment):
        // unregistered slots read `unpinned` and pass; a mid-registration
        // slot that has already pinned MUST be counted, and is.
        var it = self.slotIter();
        while (it.next()) |q| {
            const le = q.local_epoch.load(.seq_cst);
            if (le != Participant.unpinned and le != e) return;
        }

        if (self.global_epoch.cmpxchgStrong(e, e + 1, .seq_cst, .seq_cst) != null) return;
        // We created epoch e+1; one more bag of ours may just have expired.
        reclaimExpired(p, e + 1);
    }

    /// `tryAdvance` once every `Config.advance_period` calls by `p`, or now
    /// when `force` is set. Liveness only: when the scan runs moves no line of
    /// the theorem above, so a caller may skip it as freely as `tryAdvance`
    /// itself may lose its CAS. A caller that goes idle (an empty dequeue, a
    /// drain loop) passes `force`, so its own bags still empty without help.
    pub fn advanceAmortized(self: *Domain, p: *Participant, force: bool) void {
        p.since_advance += 1;
        if (!force and p.since_advance < self.advance_period) return;
        p.since_advance = 0;
        self.tryAdvance(p);
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
    var d = try Domain.init(testing.allocator, .{ .max_participants = 2, .growable = false });
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

// ── the bounded limbo reserve + the no-panic retire failure path ────────────

/// A reclaim callback that only counts, so these tests need no node pool.
fn countingReclaim(ctx: *anyopaque, ptr: *anyopaque) void {
    _ = ptr;
    const n: *usize = @ptrCast(@alignCast(ctx));
    n.* += 1;
}

test "init pre-allocates the limbo reserve, so retire never touches the allocator" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 2, .bag_reserve = 8 });
    defer d.deinit();
    for (d.participants) |*q| {
        for (&q.bags) |*b| try testing.expect(b.capacity >= 8);
    }

    // Swap in an allocator that fails EVERY request: the reserve alone must
    // carry `bag_reserve` retires per bag. (Frees pass through, so `deinit`
    // still works; restored below for tidiness.)
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
    d.allocator = failing.allocator();

    const p = try d.register();
    var freed: usize = 0;
    var victims: [8]u64 = @splat(0);
    for (&victims) |*v| {
        const g = d.enterCritical(p);
        d.retire(p, .{ .ptr = v, .ctx = &freed, .reclaim = countingReclaim });
        g.release();
    }
    // All eight fit in the reserve: nothing allocated, nothing abandoned.
    try testing.expectEqual(@as(usize, 0), failing.allocations);
    try testing.expectEqual(@as(usize, 0), d.droppedRetires());
    try testing.expectEqual(@as(usize, 8), Domain.remainingGarbage(p));

    d.allocator = testing.allocator;
    d.unregister(p); // self-drains; every victim is reclaimed
    try testing.expectEqual(@as(usize, 8), freed);
}

test "unregister never waits on a pinned peer: it orphans the slot and a peer's tryAdvance adopts it" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 4, .bag_reserve = 4 });
    defer d.deinit();
    const a = try d.register();
    const b = try d.register();

    var freed: usize = 0;
    var victims: [3]u64 = @splat(0);
    for (&victims) |*v| {
        const g = d.enterCritical(a);
        d.retire(a, .{ .ptr = v, .ctx = &freed, .reclaim = countingReclaim });
        g.release();
    }

    // `b` pins and STAYS pinned — the OS-preempted peer of the F4 finding.
    // The epoch can move at most one step past b's pinned value, never the two
    // `a`'s garbage needs, so `a` can never drain its own bags.
    const held = d.enterCritical(b);

    // The load-bearing line. Before the fix this was an unbounded
    // `while (remainingGarbage(p) != 0) { tryAdvance; backoff.pause(); }` and
    // it NEVER RETURNS on this schedule — the RED here is a hang, not a
    // failed assert.
    d.unregister(a);

    // Handed off, not dropped and not freed early: freeing under a pin is the
    // one outcome that would be a use-after-free.
    try testing.expectEqual(@as(usize, 1), d.orphanedSlots());
    try testing.expectEqual(@as(usize, 0), freed);
    // The slot is still occupied — its bags are live storage — but it is
    // `unpinned`, so it cannot block anyone's epoch advance.
    try testing.expect(a.in_use.load(.monotonic));
    try testing.expectEqual(Participant.unpinned, a.local_epoch.load(.monotonic));

    held.release();

    // Adoption is opportunistic: whichever participant next advances inherits
    // the orphan. Bounded here so a regression fails instead of hanging.
    var i: usize = 0;
    while (i < 16 and d.orphanedSlots() != 0) : (i += 1) d.tryAdvance(b);
    try testing.expectEqual(@as(usize, 0), d.orphanedSlots());
    try testing.expectEqual(victims.len, freed);
    try testing.expectEqual(@as(usize, 0), Domain.remainingGarbage(a));

    // …and the slot is genuinely free again, not merely drained.
    try testing.expect(!a.in_use.load(.monotonic));
    const c = try d.register();
    try testing.expectEqual(a, c);
    d.unregister(c);
    d.unregister(b);
}

test "unregister's bounded self-drain still reclaims everything when nobody else is pinned" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 4, .bag_reserve = 4 });
    defer d.deinit();
    const a = try d.register();
    const b = try d.register(); // registered but never pinned

    var freed: usize = 0;
    var victims: [4]u64 = @splat(0);
    for (&victims) |*v| {
        const g = d.enterCritical(a);
        d.retire(a, .{ .ptr = v, .ctx = &freed, .reclaim = countingReclaim });
        g.release();
    }
    d.unregister(a);
    // No hand-off was needed: `max_unregister_advances` is enough for a
    // participant whose scans see no other pin.
    try testing.expectEqual(@as(usize, 0), d.orphanedSlots());
    try testing.expectEqual(victims.len, freed);
    try testing.expect(!a.in_use.load(.monotonic));
    d.unregister(b);
}

test "retire abandons (never panics, never frees early) when the bag cannot grow" {
    // No reserve + an allocator that fails every request ⇒ the very first
    // retire hits the exhausted path.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
    var d = try Domain.init(testing.allocator, .{ .max_participants = 1, .bag_reserve = 0 });
    defer d.deinit();
    d.allocator = failing.allocator();

    const p = try d.register();
    var freed: usize = 0;
    var a: u64 = 1;
    var b: u64 = 2;

    for ([_]*u64{ &a, &b }) |v| {
        const g = d.enterCritical(p);
        d.retire(p, .{ .ptr = v, .ctx = &freed, .reclaim = countingReclaim });
        g.release();
    }

    // Abandoned, not staged — and above all NOT reclaimed: freeing under a
    // possible reader is the one outcome that would be a use-after-free.
    try testing.expectEqual(@as(usize, 2), d.droppedRetires());
    try testing.expectEqual(@as(usize, 0), freed);
    try testing.expectEqual(@as(usize, 0), Domain.remainingGarbage(p));

    // The domain stays usable: once the allocator recovers, retire resumes
    // staging and draining normally.
    d.allocator = testing.allocator;
    var c: u64 = 3;
    const g = d.enterCritical(p);
    d.retire(p, .{ .ptr = &c, .ctx = &freed, .reclaim = countingReclaim });
    g.release();
    try testing.expectEqual(@as(usize, 2), d.droppedRetires()); // unchanged
    d.unregister(p); // self-drains: only `c` was ever staged
    try testing.expectEqual(@as(usize, 1), freed);
}

test "a queue dequeue survives a failing allocator: value returned, node not freed" {
    const mpmc = @import("mpmc.zig");

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
    var d = try Domain.init(testing.allocator, .{ .max_participants = 1, .bag_reserve = 0 });
    defer d.deinit();
    var np = mpmc.MpmcQueue.Pool.init(testing.allocator);
    defer np.deinit();
    var q = try mpmc.MpmcQueue.init(&np, &d);

    const p = try d.register();
    try q.enqueue(p, 0xC0FFEE);
    try q.enqueue(p, 0xBEEF);

    // Now starve the limbo bags. This is the path that used to `@panic`.
    d.allocator = failing.allocator();
    try testing.expectEqual(@as(?u64, 0xC0FFEE), q.dequeue(p));
    try testing.expectEqual(@as(?u64, 0xBEEF), q.dequeue(p));
    try testing.expectEqual(@as(?u64, null), q.dequeue(p));
    try testing.expectEqual(@as(usize, 2), d.droppedRetires());

    // The abandoned nodes were never released back to the pool, so no live
    // node can alias them and the free list is still intact-poisoned.
    try np.verifyQuiescent();

    d.allocator = testing.allocator;
    d.unregister(p);
    q.deinit();
    // `np.deinit` destroys the abandoned slots too — a bounded loss of pool
    // capacity, not a heap leak (testing.allocator would flag one).
}

test "a participant pinned at the CURRENT epoch does not block one advance" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 2 });
    defer d.deinit();
    const a = try d.register();
    const b = try d.register();
    const g = d.enterCritical(b); // pinned at epoch 0, the current one
    d.tryAdvance(a);
    try testing.expectEqual(@as(u64, 1), d.epoch());
    d.tryAdvance(a); // now b is a straggler at 0: blocked
    try testing.expectEqual(@as(u64, 1), d.epoch());
    g.release();
    d.unregister(a);
    d.unregister(b);
}

test "garbage is reclaimed after exactly two advances (the grace period), not before, not later" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer d.deinit();
    const p = try d.register();
    var freed: usize = 0;
    var v: u64 = 0;
    const g = d.enterCritical(p);
    d.retire(p, .{ .ptr = &v, .ctx = &freed, .reclaim = countingReclaim });
    g.release();

    d.tryAdvance(p); // 0 → 1
    try testing.expectEqual(@as(u64, 1), d.epoch());
    try testing.expectEqual(@as(usize, 0), freed);
    d.tryAdvance(p); // 1 → 2: the bag tagged 0 is now two epochs old
    try testing.expectEqual(@as(u64, 2), d.epoch());
    try testing.expectEqual(@as(usize, 1), freed);
    d.unregister(p);
}

test "retire drains a bag left from num_epochs ago before reusing its slot" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 2, .bag_reserve = 1 });
    defer d.deinit();
    const p = try d.register();
    const q = try d.register();
    var freed: usize = 0;
    var x: u64 = 0;
    var y: u64 = 0;

    var g = d.enterCritical(p);
    d.retire(p, .{ .ptr = &x, .ctx = &freed, .reclaim = countingReclaim }); // bag 0, epoch 0
    g.release();
    // Someone else advances the epoch three times; p never scans its own bags.
    for (0..num_epochs) |_| d.tryAdvance(q);
    try testing.expectEqual(@as(u64, num_epochs), d.epoch());
    try testing.expectEqual(@as(usize, 0), freed);

    g = d.enterCritical(p);
    d.retire(p, .{ .ptr = &y, .ctx = &freed, .reclaim = countingReclaim }); // bag 0 again
    g.release();
    try testing.expectEqual(@as(usize, 1), freed); // x went first, in retire itself
    try testing.expectEqual(@as(usize, 1), Domain.remainingGarbage(p));
    d.unregister(p);
    d.unregister(q);
}

test "fresh participant is unpinned with empty limbo bags" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer d.deinit();
    const p = try d.register();
    try testing.expectEqual(Participant.unpinned, p.local_epoch.load(.monotonic));
    for (&p.bags) |*b| try testing.expectEqual(@as(usize, 0), b.items.len);
    d.unregister(p);
}

test "advanceAmortized scans once per period, and at once when forced" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 2, .advance_period = 4 });
    defer d.deinit();
    const p = try d.register();
    defer d.unregister(p);
    // A lone unpinned participant advances the epoch on every tryAdvance.
    for (0..3) |_| d.advanceAmortized(p, false);
    try testing.expectEqual(@as(u64, 0), d.epoch());
    d.advanceAmortized(p, false); // fourth call: the scan runs
    try testing.expectEqual(@as(u64, 1), d.epoch());
    d.advanceAmortized(p, true); // forced, though the period restarted
    try testing.expectEqual(@as(u64, 2), d.epoch());
    for (0..3) |_| d.advanceAmortized(p, false);
    try testing.expectEqual(@as(u64, 2), d.epoch());
}

test "advance_period 0 counts as 1" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 1, .advance_period = 0 });
    defer d.deinit();
    const p = try d.register();
    defer d.unregister(p);
    d.advanceAmortized(p, false);
    try testing.expectEqual(@as(u64, 1), d.epoch());
}

test "slotIndex is the registry position" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 3 });
    defer d.deinit();
    const a = try d.register();
    const b = try d.register();
    try testing.expectEqual(@as(usize, 0), d.slotIndex(a));
    try testing.expectEqual(@as(usize, 1), d.slotIndex(b));
    d.unregister(a);
    d.unregister(b);
}

// ── crossbeam parity: growth, nesting, repin, the per-thread default ────────

test "a growable registry appends chunks past max_participants, numbered on, and reuses freed slots first" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 2 });
    defer d.deinit();
    var ps: [7]*Participant = undefined;
    for (&ps, 0..) |*p, i| {
        p.* = try d.register();
        try testing.expectEqual(i, d.slotIndex(p.*));
    }
    // A slot in a later chunk counts in the advance predicate like any other.
    _ = d.enterCritical(ps[6]);
    const e = d.epoch();
    d.tryAdvance(ps[0]); // ps[6] pinned at e: one advance is allowed
    d.tryAdvance(ps[0]); // now ps[6] lags: blocked
    try testing.expectEqual(e + 1, d.epoch());
    d.exitCritical(ps[6]);
    d.tryAdvance(ps[0]);
    try testing.expectEqual(e + 2, d.epoch());
    d.unregister(ps[3]);
    try testing.expectEqual(ps[3], try d.register());
    for (ps) |p| d.unregister(p);
}

test "nested pins (enterCriticalNested, pin): only the outermost pins and only its exit unpins" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 2 });
    defer d.deinit();
    const p = try d.register();
    defer d.unregister(p);
    const other = try d.register();
    defer d.unregister(other);
    try testing.expect(!p.isPinned());
    const outer = d.enterCritical(p);
    const pinned_at = p.local_epoch.load(.monotonic);
    const inner = d.enterCriticalNested(p);
    try testing.expectEqual(pinned_at, p.local_epoch.load(.monotonic));
    d.tryAdvance(other);
    d.tryAdvance(other); // blocked by p's pin
    inner.release();
    try testing.expect(p.isPinned());
    try testing.expectEqual(pinned_at, p.local_epoch.load(.monotonic));
    try testing.expectEqual(pinned_at + 1, d.epoch());
    outer.release();
    try testing.expect(!p.isPinned());
    try testing.expectEqual(Participant.unpinned, p.local_epoch.load(.monotonic));
    d.tryAdvance(other);
    try testing.expectEqual(pinned_at + 2, d.epoch());
}

test "repin moves the pin to the current epoch; repinAfter unpins around the call; both skip nested guards" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 2 });
    defer d.deinit();
    const p = try d.register();
    defer d.unregister(p);
    const other = try d.register();
    defer d.unregister(other);
    const g = d.enterCritical(p);
    d.tryAdvance(other);
    d.tryAdvance(other); // blocked: p lags
    const e = d.epoch();
    try testing.expect(p.local_epoch.load(.monotonic) < e);
    g.repin();
    try testing.expectEqual(e, p.local_epoch.load(.monotonic));
    d.tryAdvance(other);
    try testing.expectEqual(e + 1, d.epoch());
    // Nested: repin is a no-op, the pin stays.
    const inner = d.enterCriticalNested(p);
    inner.repin();
    try testing.expectEqual(e, p.local_epoch.load(.monotonic));
    const Probe = struct {
        fn seen(q: *Participant) u64 {
            return q.local_epoch.load(.monotonic);
        }
    };
    try testing.expectEqual(e, inner.repinAfter(p, Probe.seen));
    inner.release();
    // Outermost: unpinned while the callback runs, pinned again after.
    try testing.expectEqual(Participant.unpinned, g.repinAfter(p, Probe.seen));
    try testing.expect(p.isPinned());
    try testing.expectEqual(d.epoch(), p.local_epoch.load(.monotonic));
    g.release();
}

test "flush reclaims expired garbage through the guard" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer d.deinit();
    const p = try d.register();
    defer d.unregister(p);
    var freed: usize = 0;
    var dummy: u8 = 0;
    {
        const g = d.enterCritical(p);
        g.retire(.{ .ptr = &dummy, .ctx = &freed, .reclaim = countingReclaim });
        g.release();
    }
    const g = d.enterCritical(p);
    g.flush();
    g.repin();
    g.flush();
    g.repin();
    g.flush();
    g.release();
    try testing.expectEqual(@as(usize, 1), freed);
}

test "pin uses one default participant per thread and domain; unregisterCurrentThread releases it" {
    var a = try Domain.init(testing.allocator, .{ .max_participants = 1, .growable = false });
    defer a.deinit();
    var b = try Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer b.deinit();
    const ga = try a.pin();
    const gb = try b.pin();
    try testing.expect(ga.participant != gb.participant);
    const ga2 = try a.pin(); // same thread, same domain: the same participant, nested
    try testing.expectEqual(ga.participant, ga2.participant);
    ga2.release();
    ga.release();
    gb.release();
    // Another thread gets its own participant: with a fixed one-slot
    // registry it cannot, until this thread lets go.
    const T = struct {
        fn run(d: *Domain, out: *?PinError) void {
            if (d.pin()) |g| {
                g.release();
                d.unregisterCurrentThread();
                out.* = null;
            } else |err| out.* = err;
        }
    };
    var res: ?PinError = null;
    var t = try std.Thread.spawn(.{}, T.run, .{ &a, &res });
    t.join();
    try testing.expectEqual(@as(?PinError, error.TooManyParticipants), res);
    a.unregisterCurrentThread();
    t = try std.Thread.spawn(.{}, T.run, .{ &a, &res });
    t.join();
    try testing.expectEqual(@as(?PinError, null), res);
    b.unregisterCurrentThread();
}

test "a thread's default entries are keyed by domain id: a new domain never inherits a dead one's" {
    var first = try Domain.init(testing.allocator, .{ .max_participants = 1 });
    const g = try first.pin();
    g.release();
    const old_id = first.id;
    first.deinit(); // clears this thread's entry
    var second = try Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer second.deinit();
    try testing.expect(second.id != old_id);
    const p = try second.currentParticipant();
    try testing.expectEqual(&second.participants[0], p);
    second.unregisterCurrentThread();
}

test "pin refuses past max_thread_domains domains on one thread" {
    var ds: [max_thread_domains + 1]Domain = undefined;
    for (&ds) |*d| d.* = try Domain.init(testing.allocator, .{ .max_participants = 1, .bag_reserve = 0 });
    defer for (&ds) |*d| d.deinit();
    for (ds[0..max_thread_domains]) |*d| (try d.pin()).release();
    try testing.expectError(error.TooManyDomainsPerThread, ds[max_thread_domains].pin());
    ds[0].unregisterCurrentThread();
    (try ds[max_thread_domains].pin()).release();
    for (ds[1..]) |*d| d.unregisterCurrentThread();
}

test "an orphaned slot in a later chunk is adopted and drained like one in the first" {
    var d = try Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer d.deinit();
    const a = try d.register();
    defer d.unregister(a);
    const b = try d.register(); // in the appended chunk
    try testing.expectEqual(@as(usize, 1), d.slotIndex(b));
    var freed: usize = 0;
    var dummy: u8 = 0;
    const ga = d.enterCritical(a); // holds the epoch back
    const gb = d.enterCritical(b);
    gb.retire(.{ .ptr = &dummy, .ctx = &freed, .reclaim = countingReclaim });
    gb.release();
    d.unregister(b); // cannot drain past a's pin: orphaned
    try testing.expectEqual(@as(usize, 1), d.orphanedSlots());
    ga.release();
    for (0..4) |_| d.tryAdvance(a);
    try testing.expectEqual(@as(usize, 0), d.orphanedSlots());
    try testing.expectEqual(@as(usize, 1), freed);
    try testing.expect(!b.in_use.load(.monotonic));
}
