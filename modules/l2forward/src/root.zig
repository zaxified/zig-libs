// SPDX-License-Identifier: MIT
//! l2forward — the E-LAN edge forwarding table for a multi-tenant L2VPN fabric.
//!
//! This is the forwarding *brain* a provider edge (PE) runs: given a customer
//! Ethernet frame's `{ I-SID, destination MAC, ingress }` it decides **where to
//! send it into the fabric** — to one remote PE (a learned unicast), replicated
//! to the I-SID's member PEs (a BUM/unknown flood), or **nowhere at all** when
//! the frame came out of the core. It pairs with the sibling `l2encap` codec,
//! which builds the actual on-wire frame: `l2encap` carries the tenant tag / TTL
//! / split-horizon *fields*; `l2forward` owns the *state* (per-tenant MAC
//! learning + membership) those fields are computed from. The two agree by
//! construction — same 24-bit **I-SID**, same 16-bit **PE id**, same full-mesh
//! split-horizon rule.
//!
//! ## Full-mesh split horizon (RFC 4762 §4.4, RFC 7432 §8.3.1)
//! Members are the **remote** PEs, and the PE-to-PE mesh is full: every PE is
//! reachable from every other in one hop. So a frame that arrived **from the
//! core** must never be sent back into the core — not to the PE it came from,
//! and not to any other PE either, because that PE received its own copy
//! directly from the ingress PE. Sending "members − source" is therefore not a
//! weaker version of the rule, it is the replication storm the rule exists to
//! prevent: with N members each relay produces N−2 further copies, i.e.
//! `(N−1)(N−2)^(k−1)` frames at hop k, bounded only by `l2encap`'s TTL.
//! `forward` takes the missing input — `Ingress` — so that this decision is
//! expressible at all; excluding a source PE from a member set never was.
//!
//! Pure, deterministic, **time-injected** and **bounded**:
//!   * no clock — every entry point that ages state takes a caller-supplied
//!     monotonic `now: Time` (abstract ticks in the caller's own unit), so the
//!     same `(ops, now)` stream yields the same decisions on every run;
//!   * no sockets, no threads, no owned timers — the caller drives all I/O and
//!     the ageing tick;
//!   * every table is capacity-capped (see `Options`): a MAC-flooding attacker
//!     cannot grow the learning table without limit (see the DoS note below).
//!
//! ## Data model
//! Two independent per-tenant structures, keyed by I-SID (tenant isolation is
//! the top-level key — the same MAC in two I-SIDs is two unrelated entries):
//!   1. **Membership** — the set of remote PEs participating in an I-SID, which
//!      the caller populates from the control plane (SPB I-SID TLVs / EVPN
//!      route imports). `addMember` / `removeMember` / `isMember`. This module
//!      never learns membership from data-plane frames; it is control-plane
//!      state the caller owns. **So is the tenant slot itself**: only the
//!      control-plane entry points (`addIsid`, `addMember`, `learnStatic`)
//!      create an I-SID. `learn` — the data-plane one — refuses an I-SID the
//!      caller never configured (`error.UnknownIsid`) and allocates nothing, so
//!      received traffic can never spend the `max_isids` budget.
//!   2. **FDB** (802.1D-style forwarding database) — customer MAC → remote PE,
//!      learned from received frames (`learn`), each entry carrying the `now`
//!      it was last (re)learned at so ageing is a comparison, not an owned
//!      countdown. A `static` variant (`learnStatic`) is never aged and is not
//!      overwritten by dynamic learning.
//!
//! ## Forward decision
//! `forward(isid, dst_mac, ingress, now, out)` classifies `dst_mac` and returns:
//!   * `.core` ingress → **`Decision.local_only`**, always: a frame received
//!     from the core is delivered to local access circuits and never re-enters
//!     the fabric (the split-horizon rule above). No FDB lookup is made.
//!   * `.access` ingress, **known unicast** — `dst_mac` is a fresh FDB hit in
//!     `isid` → `Decision.unicast(pe)`: send to that one remote PE.
//!   * `.access` ingress, **BUM** (Broadcast, Unknown-unicast, or Multicast) →
//!     `Decision.flood(set)`: the I-SID's member PEs — all of them, since the
//!     local PE is by definition not in its own member set — written into the
//!     caller-supplied `out` buffer in ascending PE-id order (deterministic).
//!     `dst_mac` is BUM when it is the broadcast address (all-ones), a
//!     multicast/group address (the I/G bit — the LSB of the first octet — is
//!     set), or a unicast that misses the FDB.
//!
//! ## MAC mobility / hijack (EVPN RFC 7432 §15)
//! A source MAC arriving from a different PE is a **move**, and the frame that
//! causes one is unauthenticated: a spoofed source MAC redirects a station's
//! entire unicast flow to whoever sent it. Two properties keep that bounded:
//!   * **it is never silent** — `learn` returns a `LearnOutcome`, so `.moved`
//!     is a signal the caller can alarm on, rate-limit or answer with a
//!     `learnStatic` pin. A table that accepts moves without telling anyone is
//!     a traffic-redirection primitive;
//!   * **it is counted** — `Options.max_mac_moves` moves inside
//!     `Options.mac_move_window` trip duplicate-MAC detection: that move is
//!     refused and the MAC is **quarantined**, meaning no binding is trusted
//!     and the MAC floods to every member PE (which still reaches the real
//!     station) until the window lapses. Flooding, not freezing on whichever
//!     party won the last race — a freeze would let the attacker lock in the
//!     binding it stole. `forget` / `learnStatic` clear a quarantine early.
//!
//! ## Ageing
//! `tick(now)` reclaims dynamic FDB entries older than `Options.aging_ticks`;
//! an expired entry's MAC reverts to unknown-unicast (floods again until
//! relearned). Because `forward`/`lookup` already treat an over-age entry as a
//! miss, `tick` is *memory reclamation only* — forwarding is correct between
//! ticks and `tick` may safely no-op under allocator pressure.
//!
//! ## DoS bound (the central threat of a learning FDB)
//! A source-MAC flood (an attacker spraying novel source MACs to blow up the
//! learning table) is bounded per tenant by `Options.max_macs_per_isid`. When a
//! tenant's FDB is full, `learn` first reclaims that tenant's already-expired
//! entries; if it is still full, a **new** MAC is rejected (`error.FdbFull`) —
//! learning fails closed, existing entries are untouched, and the unlearned MAC
//! simply forwards as unknown-unicast (floods) exactly as a real bridge degrades
//! to flooding when its CAM is full. The per-tenant cap means a flood in one
//! I-SID can never evict another tenant's entries. Total worst-case memory is
//! `max_isids × max_macs_per_isid` FDB entries plus `max_isids ×
//! max_pes_per_isid` membership entries — and that ceiling is reachable only by
//! the **control plane**, because `learn` cannot create a tenant (see the data
//! model above): an attacker with no control-plane access is confined to the
//! I-SIDs the operator actually provisioned.
//!
//! Provenance: clean-room from public specifications (IEEE 802.1D MAC learning /
//! ageing FDB, IEEE 802.1ah PBB I-SID service scoping, IEEE 802.1aq SPB / EVPN
//! RFC 7432 ingress replication + split-horizon). A public spec is not a
//! copyrightable work and no third-party source was ported — see `/NOTICE` (no
//! entry required).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    .platform = .any,
    .role = .util,
    // One thread/loop owns it, lock-free by design — no cross-thread scaling
    // over one shared `Table` (unlike the RCU'd Linux bridge FDB this module
    // is modelled after). See SPEC.md "Concurrency ceiling" for the accepted
    // production shape (one forwarding thread per PE) and what a multi-core-
    // per-PE consumer would need instead.
    .concurrency = .single_owner,
    .model_after = "802.1D MAC-learning/ageing FDB + EVPN/SPB ingress replication with split-horizon, per-I-SID",
    .deps = .{}, // std only
};

// ── plain field types (match l2encap's conventions exactly) ──────────────────

/// Tenant service identifier — 24-bit, the same width and tenant-isolation role
/// as `l2encap.Fields.isid`. Two I-SIDs never share a MAC-learning domain.
pub const Isid = u24;

/// Fabric-scoped remote-PE id — 16-bit, the same width as `l2encap`'s ingress
/// PE id (its SPB source nickname / EVPN ingress-PE identity).
pub const PeId = u16;

/// A customer Ethernet MAC address (6 octets, on-wire order). The I/G bit — the
/// least-significant bit of the first octet — distinguishes group (multicast)
/// from individual (unicast) addresses.
pub const Mac = [6]u8;

/// Abstract monotonic time. The caller chooses the unit (seconds, milliseconds,
/// frames — whatever it also expresses `Options.aging_ticks` in); this module
/// never interprets it beyond ordering and subtraction.
pub const Time = u64;

/// The broadcast destination — all ones. Also matches the multicast predicate
/// (its I/G bit is set), so it is a strict subset of BUM.
pub const broadcast: Mac = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// ── BUM classification (pure, exposed for callers/tests) ─────────────────────

/// True iff `mac` is the all-ones broadcast address.
pub fn isBroadcast(mac: Mac) bool {
    return std.mem.allEqual(u8, &mac, 0xFF);
}

/// True iff `mac` is a group (multicast) address: the I/G bit — the LSB of the
/// first octet — is set. Broadcast is the all-ones special case and also
/// satisfies this predicate.
pub fn isMulticast(mac: Mac) bool {
    return mac[0] & 0x01 != 0;
}

/// True iff a frame to `dst` must be treated as BUM purely from the destination
/// address itself (broadcast or multicast). An *unknown-unicast* is also BUM but
/// only relative to a given FDB, so it is decided inside `forward`, not here.
pub fn isBumAddress(dst: Mac) bool {
    return isMulticast(dst); // broadcast ⊂ multicast (I/G bit set)
}

// ── configuration ────────────────────────────────────────────────────────────

/// Capacity caps + ageing time, fixed at `init`. Every cap is a hard DoS bound;
/// the defaults are generous but finite. Units of `aging_ticks` are the caller's
/// (see `Time`); the 802.1D default ageing time is 300 seconds.
pub const Options = struct {
    /// Max number of distinct I-SIDs that may hold membership or FDB state.
    max_isids: usize = 4096,
    /// Max member PEs per I-SID — also the maximum size of any flood
    /// replication set, so the caller sizes its `forward` buffer to this.
    max_pes_per_isid: usize = 256,
    /// Max learned MACs per I-SID — the per-tenant MAC-flood bound. Static
    /// entries count against it too.
    max_macs_per_isid: usize = 8192,
    /// A dynamic FDB entry older than this (in `Time` units) is expired: treated
    /// as a miss by `forward`/`lookup` and reclaimed by `tick`. Static entries
    /// ignore it. `0` means every dynamic entry is immediately stale.
    aging_ticks: Time = 300,
    /// MAC-mobility limit (EVPN RFC 7432 §15.1 duplicate-MAC detection): the
    /// number of moves of the *same* MAC inside `mac_move_window` that trips
    /// duplicate detection. The move that reaches this count is **refused** and
    /// the MAC is quarantined (see `LearnOutcome.duplicate_detected`). `0`
    /// disables move acceptance entirely — the first move quarantines.
    max_mac_moves: u8 = 5,
    /// The sliding window (in `Time` units) `max_mac_moves` is counted over, and
    /// also how long a quarantine holds. RFC 7432 §15.1 (verified against the
    /// RFC text, 2026-08-07): "a PE that detects a MAC mobility event via local
    /// learning starts an M-second timer (with a default value of M = 180), and
    /// if it detects N MAC moves before the timer expires (with a default value
    /// of N = 5), it concludes that a duplicate-MAC situation has occurred."
    ///
    /// **Deliberate deviation:** the same clause says the PE "MUST alert the
    /// operator and stop … until a corrective action is taken by the operator".
    /// That is a BGP-EVPN control-plane rule about withdrawing MAC/IP
    /// Advertisement routes; this module is a local FDB with no control plane to
    /// alert, so a quarantine instead lapses with the window. A deployment that
    /// wants the RFC's operator-clears-it behaviour sets `mac_move_window` to
    /// something long and calls `forget` as the corrective action.
    mac_move_window: Time = 180,
};

// ── decisions & errors ───────────────────────────────────────────────────────

/// Where a frame entered this PE. This is the input the full-mesh split-horizon
/// rule is decided from; without it the rule is not expressible (see the module
/// header). The caller knows it from the port the frame arrived on: a customer
/// access circuit, or the fabric-facing core (in which case `l2encap.decode`
/// already yielded the `ingress_pe` that replicated it).
pub const Ingress = union(enum) {
    /// A local access circuit (customer-facing port). The frame may be
    /// replicated into the fabric.
    access,
    /// The core, ingress-replicated by remote PE `pe`. RFC 4762 §4.4 /
    /// RFC 7432 §8.3.1: it must not be forwarded back into the fabric at all.
    core: PeId,
};

/// The forward decision for one frame.
pub const Decision = union(enum) {
    /// Known unicast: send to exactly this one remote PE.
    unicast: PeId,
    /// BUM / unknown-unicast from an access circuit: replicate to these member
    /// PEs. The slice is a prefix of the caller's `out` buffer, ascending by PE
    /// id (deterministic). May be empty (the I-SID has no members, or is
    /// unknown).
    flood: []const PeId,
    /// The frame arrived from the core: deliver it to local access circuits
    /// only and put **nothing** back into the fabric — full-mesh split horizon
    /// (RFC 4762 §4.4, RFC 7432 §8.3.1). Local delivery is the caller's job;
    /// this module models the fabric side, and the fabric side is empty.
    local_only,
};

pub const AddMemberError = error{
    /// A new I-SID would exceed `Options.max_isids`.
    TooManyIsids,
    /// This I-SID already has `Options.max_pes_per_isid` members.
    TooManyMembers,
    OutOfMemory,
};

pub const AddIsidError = error{
    /// A new I-SID would exceed `Options.max_isids`.
    TooManyIsids,
    OutOfMemory,
};

/// Errors of the **data-plane** entry point `learn`. Note what is *not* here:
/// `TooManyIsids`. A received frame can never create a tenant, so it can never
/// consume the I-SID budget either — it is refused with `UnknownIsid` first.
pub const LearnError = error{
    /// No such tenant. `learn` is the data-plane entry point and the tenant slot
    /// is control-plane state (`addIsid` / `addMember` / `learnStatic` create
    /// it), so a frame carrying an I-SID the control plane never configured is
    /// refused outright — it does not allocate anything. Fail closed: the caller
    /// should drop the frame.
    UnknownIsid,
    /// This I-SID's FDB is full (`Options.max_macs_per_isid`) and no expired
    /// entry could be reclaimed to make room — the new MAC is not learned and
    /// forwards as unknown-unicast (floods). Existing entries are untouched.
    FdbFull,
    OutOfMemory,
};

/// Errors of the **control-plane** pinning entry point `learnStatic`, which
/// (like `addMember`) may create the tenant slot and therefore can hit the
/// I-SID cap.
pub const LearnStaticError = error{
    /// A new I-SID would exceed `Options.max_isids`.
    TooManyIsids,
    /// See `LearnError.FdbFull`.
    FdbFull,
    OutOfMemory,
};

/// What a `learn` call actually did. `learn` returns this instead of `void`
/// because a **move is a security event**: the frame that causes one is
/// unauthenticated data-plane input (see the module header), and a move
/// silently redirects a station's entire unicast flow to whoever sent it. The
/// caller — not this table — owns the policy response (alarm, ACL, pin the MAC
/// with `learnStatic`), and it cannot exercise any policy over an event it is
/// never told about.
pub const LearnOutcome = enum {
    /// The MAC was not in the FDB (or its quarantine had lapsed): a fresh
    /// binding was installed.
    learned,
    /// The MAC was already bound to this same PE: only its age was refreshed.
    /// Nothing about the forwarding decision changed.
    refreshed,
    /// **The MAC moved**: it was bound to a different PE and is now bound to
    /// `src_pe`. Legitimate station mobility looks exactly like a hijack here;
    /// the move counter (`moveCount`) is how the caller tells them apart.
    moved,
    /// This move reached `Options.max_mac_moves` inside
    /// `Options.mac_move_window` — RFC 7432 §15 duplicate-MAC detection. The
    /// move is **refused**, and the MAC is quarantined: `lookup`/`forward` now
    /// report it as unknown so it floods to every member PE (which still
    /// reaches the real station) instead of being unicast to whichever party
    /// won the last race. The quarantine lapses `mac_move_window` after it
    /// started, or immediately on `forget` / `learnStatic`.
    duplicate_detected,
    /// Refused: this MAC is quarantined and the window has not lapsed. Nothing
    /// changed — in particular a quarantine cannot be *extended* by continuing
    /// to send, so an attacker cannot hold a MAC in quarantine indefinitely.
    denied_duplicate,
    /// The MAC is administratively pinned by `learnStatic`; dynamic learning
    /// leaves it alone (no error, no change).
    static_pinned,
};

pub const ForwardError = error{
    /// `out` is smaller than this I-SID's split-horizon replication set. Size
    /// `out` to `Options.max_pes_per_isid` to make this unreachable.
    BufferTooSmall,
};

// ── table ─────────────────────────────────────────────────────────────────────

const FdbEntry = struct {
    pe: PeId,
    /// The `now` this entry was last learned/refreshed at; ageing is
    /// `now - learned_at > aging_ticks`. Ignored when `static`.
    learned_at: Time,
    /// Start of the current MAC-mobility window: the `now` of the first move
    /// counted in `moves`, or — once `duplicate` is set — the instant the
    /// quarantine began. Never advanced while quarantined.
    move_window_start: Time = 0,
    /// Moves of this MAC counted inside the current window (saturating).
    moves: u8 = 0,
    /// Administratively pinned: never aged, never overwritten by dynamic
    /// `learn`. Installed by `learnStatic`, removed only by `forget`/`deinit`.
    static: bool = false,
    /// Quarantined by duplicate-MAC detection: the binding is not trusted by
    /// anybody, so `lookup`/`forward` report a miss (the MAC floods) until the
    /// window lapses and a fresh `learn` re-establishes it.
    duplicate: bool = false,
};

const PeSet = std.AutoHashMapUnmanaged(PeId, void);
const Fdb = std.AutoHashMapUnmanaged(Mac, FdbEntry);

const IsidEntry = struct {
    members: PeSet = .empty,
    fdb: Fdb = .empty,

    fn deinit(self: *IsidEntry, alloc: Allocator) void {
        self.members.deinit(alloc);
        self.fdb.deinit(alloc);
    }
};

/// The per-PE E-LAN forwarding table. `single_owner`: one thread/loop owns an
/// instance; it holds no internal lock. Create with `init`, free with `deinit`.
pub const Table = struct {
    alloc: Allocator,
    options: Options,
    isids: std.AutoHashMapUnmanaged(Isid, IsidEntry) = .empty,

    pub fn init(alloc: Allocator, options: Options) Table {
        return .{ .alloc = alloc, .options = options };
    }

    pub fn deinit(self: *Table) void {
        var it = self.isids.iterator();
        while (it.next()) |kv| kv.value_ptr.deinit(self.alloc);
        self.isids.deinit(self.alloc);
    }

    // ── membership (control-plane populated) ─────────────────────────────────

    /// **Provision a tenant** (idempotent): create `isid`'s (empty) state so
    /// that the data plane may learn in it. This is the control-plane act that
    /// `learn` deliberately cannot perform — see `LearnError.UnknownIsid`. It
    /// exists as its own entry point because a tenant is legitimately
    /// member-less (a single-PE I-SID with only local access circuits), so
    /// `addMember` is not a sufficient provisioning path.
    pub fn addIsid(self: *Table, isid: Isid) AddIsidError!void {
        _ = try self.getOrCreateIsid(isid);
    }

    /// Deprovision a tenant: drop its membership *and* its FDB. Returns true if
    /// the I-SID existed. After this, `learn` on `isid` fails with
    /// `UnknownIsid` again.
    pub fn removeIsid(self: *Table, isid: Isid) bool {
        const kv = self.isids.fetchRemove(isid) orelse return false;
        var ie = kv.value;
        ie.deinit(self.alloc);
        return true;
    }

    /// Add `pe` to `isid`'s member set (idempotent). Creating the I-SID counts
    /// against `max_isids`; a brand-new I-SID starts with zero members, so
    /// `TooManyMembers` can only arise on an already-populated I-SID.
    pub fn addMember(self: *Table, isid: Isid, pe: PeId) AddMemberError!void {
        const ie = try self.getOrCreateIsid(isid);
        if (!ie.members.contains(pe) and ie.members.count() >= self.options.max_pes_per_isid)
            return error.TooManyMembers;
        try ie.members.put(self.alloc, pe, {});
    }

    /// Remove `pe` from `isid`'s member set. No-op if the I-SID or PE is
    /// absent. Also purges every FDB entry (static or dynamic) still pointing
    /// at `pe` (F8): left alone, known-unicast frames for those MACs would
    /// keep being sent to a non-member for up to `aging_ticks` (default 300 s)
    /// — a black-hole window the caller had no way to shorten. Purging here
    /// instead makes those MACs immediately unknown, so the next frame for
    /// them floods to the remaining members (the correct fallback) rather
    /// than being silently dropped by forwarding to a PE that is no longer
    /// there. Same victims-then-remove shape as `pruneIsid`, for the same
    /// iterator-invalidation reason.
    pub fn removeMember(self: *Table, isid: Isid, pe: PeId) void {
        const ie = self.isids.getPtr(isid) orelse return;
        _ = ie.members.remove(pe);

        var victims: std.ArrayList(Mac) = .empty;
        defer victims.deinit(self.alloc);
        var it = ie.fdb.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.pe == pe)
                victims.append(self.alloc, kv.key_ptr.*) catch break;
        }
        for (victims.items) |mac| _ = ie.fdb.remove(mac);
    }

    /// True iff `pe` is a member of `isid`.
    pub fn isMember(self: *const Table, isid: Isid, pe: PeId) bool {
        const ie = self.isids.getPtr(isid) orelse return false;
        return ie.members.contains(pe);
    }

    /// Number of member PEs in `isid` (0 if the I-SID is unknown).
    pub fn memberCount(self: *const Table, isid: Isid) usize {
        const ie = self.isids.getPtr(isid) orelse return 0;
        return ie.members.count();
    }

    // ── learning (data-plane) ────────────────────────────────────────────────

    /// Learn (or refresh) that customer MAC `src_mac` in tenant `isid` is
    /// reachable behind remote PE `src_pe`, as of `now`. **Data plane**: the
    /// argument values come from a received frame and are not authenticated, so
    /// this entry point is the module's whole attack surface and is deliberately
    /// the most constrained one.
    ///
    ///   * `isid` must already exist (`addIsid` / `addMember` / `learnStatic`).
    ///     A frame carrying an unconfigured I-SID is refused with `UnknownIsid`
    ///     and allocates nothing — a received frame never creates tenant state.
    ///   * A *move* (the MAC was bound to another PE) is accepted but **counted
    ///     and reported**: `LearnOutcome.moved`. `max_mac_moves` moves inside
    ///     `mac_move_window` trip RFC 7432 §15 duplicate-MAC detection — that
    ///     move is refused and the MAC is quarantined (floods) until the window
    ///     lapses.
    ///   * A MAC pinned by `learnStatic` is not overwritten (`static_pinned`).
    ///   * New MACs beyond the per-tenant cap are rejected (`FdbFull`) after a
    ///     reclaim attempt — see the module DoS note.
    ///
    /// The returned `LearnOutcome` is the caller's only notification of a MAC
    /// hijack; ignoring it (`_ = try …`) is choosing to run without one.
    pub fn learn(self: *Table, isid: Isid, src_mac: Mac, src_pe: PeId, now: Time) LearnError!LearnOutcome {
        // Data-plane frames do not provision tenants: no getOrCreateIsid here.
        const ie = self.isids.getPtr(isid) orelse return error.UnknownIsid;
        if (ie.fdb.getPtr(src_mac)) |e| {
            if (e.static) return .static_pinned; // administratively pinned
            if (e.duplicate) {
                // Quarantined. A lapsed window lets the MAC be re-established
                // from scratch; an unlapsed one refuses without touching a
                // thing, so the quarantine cannot be extended by sending more.
                if (!self.quarantineLapsed(e.*, now)) return .denied_duplicate;
                e.* = .{ .pe = src_pe, .learned_at = now };
                return .learned;
            }
            if (e.pe == src_pe) {
                e.learned_at = now;
                return .refreshed;
            }
            // A move. Count it inside the mobility window.
            if (!self.inMoveWindow(e.*, now)) {
                e.move_window_start = now;
                e.moves = 0;
            }
            e.moves +|= 1;
            if (e.moves >= self.options.max_mac_moves) {
                // RFC 7432 §15: too many moves in the window. Refuse THIS move
                // and trust neither binding — the MAC floods until the
                // quarantine lapses, which still reaches the real station.
                e.duplicate = true;
                e.move_window_start = now;
                return .duplicate_detected;
            }
            e.pe = src_pe;
            e.learned_at = now;
            return .moved;
        }
        try self.insertNewMac(ie, src_mac, .{ .pe = src_pe, .learned_at = now }, now);
        return .learned;
    }

    /// Install a **static** entry: MAC `mac` in `isid` is pinned behind `pe`,
    /// never aged, never overwritten by dynamic `learn`, and never quarantined.
    /// Overwrites whatever (static, dynamic or quarantined) was there. Still
    /// counts against the per-tenant cap. Control plane: unlike `learn` it may
    /// create the I-SID, and so can fail with `TooManyIsids`.
    ///
    /// `now` is the caller's current time. A static entry's own
    /// `learned_at` is irrelevant (it is never aged), but `now` still has to
    /// be the REAL current time because a full FDB is pruned of expired
    /// *dynamic* entries before this insert is rejected — hard-coding `now =
    /// 0` here made every dynamic entry look age-0 to that prune, so it
    /// reclaimed nothing and a full-of-stale-junk FDB rejected an
    /// administrative pin with `FdbFull` even when a `learn` at the same
    /// instant would have reclaimed the space and succeeded.
    pub fn learnStatic(self: *Table, isid: Isid, mac: Mac, pe: PeId, now: Time) LearnStaticError!void {
        const ie = try self.getOrCreateIsid(isid);
        if (ie.fdb.getPtr(mac)) |e| {
            e.* = .{ .pe = pe, .learned_at = 0, .static = true };
            return;
        }
        try self.insertNewMac(ie, mac, .{ .pe = pe, .learned_at = 0, .static = true }, now);
    }

    /// Delete a learned MAC (static or dynamic) from `isid`. Returns true if an
    /// entry was removed.
    pub fn forget(self: *Table, isid: Isid, mac: Mac) bool {
        const ie = self.isids.getPtr(isid) orelse return false;
        return ie.fdb.remove(mac);
    }

    // ── lookup & the forward decision ────────────────────────────────────────

    /// The remote PE a fresh, known unicast to `dst_mac` in `isid` would go to,
    /// or null (unknown, expired, or quarantined by duplicate-MAC detection).
    /// Read-only: does not mutate or reclaim (an expired entry is simply
    /// reported as a miss; `tick` reclaims it later).
    pub fn lookup(self: *const Table, isid: Isid, dst_mac: Mac, now: Time) ?PeId {
        const ie = self.isids.getPtr(isid) orelse return null;
        const e = ie.fdb.getPtr(dst_mac) orelse return null;
        // A quarantined MAC has no trusted binding: report a miss so the frame
        // floods to every member (which still reaches the real station) rather
        // than being unicast to whoever won the last move race.
        if (e.duplicate) return null;
        if (self.isExpired(e.*, now)) return null;
        return e.pe;
    }

    /// Moves of `mac` counted in the current mobility window (0 if unknown).
    /// The caller's hijack signal alongside `LearnOutcome.moved`.
    pub fn moveCount(self: *const Table, isid: Isid, mac: Mac) u8 {
        const ie = self.isids.getPtr(isid) orelse return 0;
        const e = ie.fdb.getPtr(mac) orelse return 0;
        return e.moves;
    }

    /// True iff `mac` is currently quarantined by duplicate-MAC detection (it
    /// floods instead of being unicast). Cleared by `forget` / `learnStatic`,
    /// or by a `learn` after `Options.mac_move_window` has lapsed.
    pub fn isQuarantined(self: *const Table, isid: Isid, mac: Mac) bool {
        const ie = self.isids.getPtr(isid) orelse return false;
        const e = ie.fdb.getPtr(mac) orelse return false;
        return e.duplicate;
    }

    /// Decide where a frame `{ isid, dst_mac, ingress }` goes as of `now`.
    /// `.core` ingress → `local_only` (never back into the fabric — RFC 4762
    /// §4.4 / RFC 7432 §8.3.1); `.access` ingress: a known unicast →
    /// `unicast(pe)`, and broadcast / multicast / unknown-unicast →
    /// `flood(set)` where `set` is `isid`'s members, written into `out`
    /// (ascending, deterministic). Size `out` to `max_pes_per_isid`.
    /// Read-only (no mutation, no reclamation).
    pub fn forward(self: *const Table, isid: Isid, dst_mac: Mac, ingress: Ingress, now: Time, out: []PeId) ForwardError!Decision {
        // Full-mesh split horizon, decided BEFORE any table lookup: every other
        // PE already received its own copy from the ingress PE, so relaying —
        // unicast or BUM — would multiply the frame, not deliver it.
        if (ingress == .core) return .local_only;
        if (!isBumAddress(dst_mac)) {
            if (self.lookup(isid, dst_mac, now)) |pe| return .{ .unicast = pe };
            // fall through: unknown unicast is BUM relative to this FDB
        }
        return .{ .flood = try self.replicationSet(isid, ingress, out) };
    }

    /// The replication set for a BUM frame with the given `ingress`, ascending
    /// by PE id, into `out`. Exposed directly for callers that have already
    /// classified the frame as BUM.
    ///
    /// * `.core` → **empty**, always. Full-mesh split horizon (RFC 4762 §4.4:
    ///   a PE must not forward a frame received on one mesh PW onto another;
    ///   RFC 7432 §8.3.1 for EVPN ingress replication). Members are the remote
    ///   PEs and the mesh is full, so every one of them already got its own copy
    ///   from the ingress PE — "members − src_pe" would be a relay, and relays
    ///   compound: `(N−1)(N−2)^(k−1)` copies at hop k.
    /// * `.access` → every member of `isid` (the local PE is never in its own
    ///   member set, so there is nothing to exclude).
    pub fn replicationSet(self: *const Table, isid: Isid, ingress: Ingress, out: []PeId) ForwardError![]const PeId {
        if (ingress == .core) return out[0..0];
        const ie = self.isids.getPtr(isid) orelse return out[0..0];
        var n: usize = 0;
        var it = ie.members.keyIterator();
        while (it.next()) |pe_ptr| {
            if (n >= out.len) return error.BufferTooSmall;
            out[n] = pe_ptr.*;
            n += 1;
        }
        std.mem.sort(PeId, out[0..n], {}, std.sort.asc(PeId));
        return out[0..n];
    }

    // ── ageing ───────────────────────────────────────────────────────────────

    /// Reclaim every dynamic FDB entry older than `Options.aging_ticks` across
    /// all I-SIDs. Static entries are kept. Memory reclamation only —
    /// `forward`/`lookup` already treat an over-age entry as a miss, so this can
    /// safely make no progress under allocator pressure (a partially-reclaimed
    /// table stays correct; the rest is caught on the next tick).
    pub fn tick(self: *Table, now: Time) void {
        var it = self.isids.iterator();
        while (it.next()) |kv| self.pruneIsid(kv.value_ptr, now);
    }

    /// Number of FDB entries currently held for `isid` (0 if unknown). Counts
    /// entries still physically present, including over-age ones not yet
    /// reclaimed by `tick`.
    pub fn fdbCount(self: *const Table, isid: Isid) usize {
        const ie = self.isids.getPtr(isid) orelse return 0;
        return ie.fdb.count();
    }

    /// Number of I-SIDs currently holding any membership or FDB state.
    pub fn isidCount(self: *const Table) usize {
        return self.isids.count();
    }

    // ── internals ────────────────────────────────────────────────────────────

    fn isExpired(self: *const Table, e: FdbEntry, now: Time) bool {
        if (e.static) return false;
        // A live quarantine outlives ageing: reclaiming the entry would erase
        // the duplicate flag and hand the MAC straight back to the attacker.
        if (e.duplicate and !self.quarantineLapsed(e, now)) return false;
        const age = if (now >= e.learned_at) now - e.learned_at else 0;
        return age > self.options.aging_ticks;
    }

    /// Ticks elapsed since `e.move_window_start`, clamped to 0 for a
    /// non-monotonic `now` exactly as `isExpired` clamps ageing.
    fn sinceWindowStart(e: FdbEntry, now: Time) Time {
        return if (now >= e.move_window_start) now - e.move_window_start else 0;
    }

    /// True iff a move at `now` still falls inside `e`'s current move window.
    fn inMoveWindow(self: *const Table, e: FdbEntry, now: Time) bool {
        return e.moves > 0 and sinceWindowStart(e, now) <= self.options.mac_move_window;
    }

    /// True iff a quarantine started at `e.move_window_start` has expired.
    fn quarantineLapsed(self: *const Table, e: FdbEntry, now: Time) bool {
        return sinceWindowStart(e, now) > self.options.mac_move_window;
    }

    fn getOrCreateIsid(self: *Table, isid: Isid) error{ TooManyIsids, OutOfMemory }!*IsidEntry {
        if (self.isids.getPtr(isid)) |ie| return ie;
        if (self.isids.count() >= self.options.max_isids) return error.TooManyIsids;
        const gop = try self.isids.getOrPut(self.alloc, isid);
        // Not found (we just checked getPtr) — initialize the empty maps.
        gop.value_ptr.* = .{};
        return gop.value_ptr;
    }

    /// Insert a MAC not currently present, enforcing the per-tenant cap: when
    /// full, reclaim this I-SID's expired dynamic entries first; if still full,
    /// reject with `FdbFull`.
    fn insertNewMac(self: *Table, ie: *IsidEntry, mac: Mac, entry: FdbEntry, now: Time) error{ FdbFull, OutOfMemory }!void {
        if (ie.fdb.count() >= self.options.max_macs_per_isid) {
            self.pruneIsid(ie, now);
            if (ie.fdb.count() >= self.options.max_macs_per_isid) return error.FdbFull;
        }
        try ie.fdb.put(self.alloc, mac, entry);
    }

    /// Remove `ie`'s expired dynamic entries. Collects victims into a scratch
    /// list (safe removal — the map iterator would be invalidated by in-place
    /// removal); on scratch-allocation failure it reclaims what it gathered and
    /// leaves the rest for a later tick (see `tick`'s contract).
    fn pruneIsid(self: *Table, ie: *IsidEntry, now: Time) void {
        var victims: std.ArrayList(Mac) = .empty;
        defer victims.deinit(self.alloc);
        var it = ie.fdb.iterator();
        while (it.next()) |kv| {
            if (self.isExpired(kv.value_ptr.*, now))
                victims.append(self.alloc, kv.key_ptr.*) catch break;
        }
        for (victims.items) |mac| _ = ie.fdb.remove(mac);
    }
};

// ── tests (deterministic: injected `now`, no real clock) ─────────────────────

const testing = std.testing;

fn macOf(last: u8) Mac {
    return .{ 0x02, 0, 0, 0, 0, last }; // locally-administered, unicast (I/G=0)
}

fn testTable() Table {
    return Table.init(testing.allocator, .{
        .max_isids = 64,
        .max_pes_per_isid = 16,
        .max_macs_per_isid = 8,
        .aging_ticks = 100,
    });
}

test "BUM classification: broadcast, multicast, unicast" {
    try testing.expect(isBroadcast(broadcast));
    try testing.expect(isMulticast(broadcast)); // broadcast ⊂ multicast
    try testing.expect(isBumAddress(broadcast));

    const group: Mac = .{ 0x01, 0x00, 0x5E, 0, 0, 1 }; // IPv4 multicast OUI, I/G set
    try testing.expect(!isBroadcast(group));
    try testing.expect(isMulticast(group));
    try testing.expect(isBumAddress(group));

    const uni = macOf(9); // 0x02… I/G bit clear
    try testing.expect(!isBroadcast(uni));
    try testing.expect(!isMulticast(uni));
    try testing.expect(!isBumAddress(uni));
}

test "known unicast: learn then forward returns the single PE; a different MAC floods" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(10, 2);
    try t.addMember(10, 5);
    _ = try t.learn(10, macOf(0xAA), 2, 0); // M behind PE 2

    var buf: [16]PeId = undefined;
    const d = try t.forward(10, macOf(0xAA), .access, 0, &buf);
    try testing.expectEqual(Decision{ .unicast = 2 }, d);

    // An unlearned unicast in the same I-SID is unknown → flood to every member.
    const d2 = try t.forward(10, macOf(0xBB), .access, 0, &buf);
    try testing.expectEqualSlices(PeId, &.{ 2, 5 }, d2.flood);
}

test "full-mesh split horizon: access BUM floods every member; core BUM floods nobody" {
    var t = testTable();
    defer t.deinit();
    // Insert members out of order to prove the output ordering is sorted, not
    // insertion/hash order.
    try t.addMember(7, 4);
    try t.addMember(7, 2);
    try t.addMember(7, 3);

    var buf: [16]PeId = undefined;
    // From a local access circuit: ingress-replicate to all members, ascending.
    // Members are the REMOTE PEs, so there is nothing here to exclude.
    const d = try t.forward(7, broadcast, .access, 0, &buf);
    try testing.expectEqualSlices(PeId, &.{ 2, 3, 4 }, d.flood);

    // RFC 4762 §4.4 / RFC 7432 §8.3.1: a BUM frame that arrived from the core
    // is never put back into the fabric — not to the PE it came from, and not
    // to the other members either (they got their own copy from the ingress
    // PE). "Members − src_pe" here is precisely the relay that storms.
    try testing.expectEqual(Decision.local_only, try t.forward(7, broadcast, .{ .core = 3 }, 0, &buf));
    try testing.expectEqual(@as(usize, 0), (try t.replicationSet(7, .{ .core = 3 }, &buf)).len);
}

test "hostile peer: a lying ingress_pe cannot buy a relay — every core BUM replicates to nobody" {
    // The frame's claimed ingress PE is attacker-controlled: it rides in
    // `l2encap`'s header and nothing authenticates it. Under the old
    // "members − src_pe" rule a peer that stamped a NON-member id (or another
    // member's id) got its frame relayed to 3 or 2 further PEs, each of which
    // relayed again. The rule must not depend on that field's value at all.
    var t = testTable();
    defer t.deinit();
    try t.addMember(7, 2);
    try t.addMember(7, 3);
    try t.addMember(7, 4);

    var buf: [16]PeId = undefined;
    const claims = [_]PeId{ 2, 3, 4, 99, 0, std.math.maxInt(PeId) }; // members, non-members, edges
    for (claims) |claimed| {
        const ingress: Ingress = .{ .core = claimed };
        try testing.expectEqual(@as(usize, 0), (try t.replicationSet(7, ingress, &buf)).len);
        try testing.expectEqual(Decision.local_only, try t.forward(7, broadcast, ingress, 0, &buf));
        // A known unicast from the core is not relayed either: the destination
        // PE already had its own copy delivered directly (full mesh).
        _ = try t.learn(7, macOf(0xC1), 2, 0);
        try testing.expectEqual(Decision.local_only, try t.forward(7, macOf(0xC1), ingress, 0, &buf));
    }
}

test "no BUM storm: a relayed copy in a converged 4-PE fabric dies at hop 1" {
    // Faithful composition of the module's own decisions across a full mesh:
    // PE 1 receives one broadcast on an access port; every PE that receives a
    // core copy asks this table what to do with it. Before the fix each of the
    // 3 first-hop copies produced 2 more, and those 2 each produced 2 more —
    // `(N-1)(N-2)^(k-1)` copies at hop k, stopped only by l2encap's TTL 64.
    const pes = [_]PeId{ 1, 2, 3, 4 };
    var tables: [4]Table = undefined;
    for (&tables) |*tbl| tbl.* = testTable();
    defer for (&tables) |*tbl| tbl.deinit();
    for (&tables, 0..) |*tbl, i| {
        for (pes) |pe| if (pe != pes[i]) try tbl.addMember(11, pe); // members = the OTHER PEs
    }

    var buf: [16]PeId = undefined;
    var copies: usize = 0;
    // Hop 0: the access-ingress replication at PE 1.
    var queue: [64]PeId = undefined;
    var q_len: usize = 0;
    const first = try tables[0].forward(11, broadcast, .access, 0, &buf);
    for (first.flood) |pe| {
        copies += 1;
        queue[q_len] = pe;
        q_len += 1;
    }
    try testing.expectEqual(@as(usize, 3), copies); // 2, 3, 4 — one copy each

    // Hops 1..8: every PE holding a core-received copy consults its own table.
    var hop: usize = 0;
    while (hop < 8 and q_len > 0) : (hop += 1) {
        var next: [64]PeId = undefined;
        var n_len: usize = 0;
        for (queue[0..q_len]) |pe| {
            const d = try tables[pe - 1].forward(11, broadcast, .{ .core = 1 }, 0, &buf);
            switch (d) {
                .local_only => {}, // delivered to local ACs; nothing re-enters the fabric
                // The queue is capped so a regression storms the COUNT rather
                // than overrunning this test's own buffer.
                .flood => |set| for (set) |to| {
                    copies += 1;
                    if (n_len < next.len) {
                        next[n_len] = to;
                        n_len += 1;
                    }
                },
                .unicast => |to| {
                    copies += 1;
                    if (n_len < next.len) {
                        next[n_len] = to;
                        n_len += 1;
                    }
                },
            }
        }
        @memcpy(queue[0..n_len], next[0..n_len]);
        q_len = n_len;
    }
    try testing.expectEqual(@as(usize, 0), q_len); // the frame stops after hop 0
    try testing.expectEqual(@as(usize, 3), copies); // exactly one copy per remote PE
}

test "tenant isolation: a MAC learned in I-SID A does not affect I-SID B" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(100, 2);
    try t.addMember(200, 8);
    _ = try t.learn(100, macOf(0x11), 2, 0); // M behind PE 2, only in A

    var buf: [16]PeId = undefined;
    // In A: known unicast to PE 2.
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(100, macOf(0x11), .access, 0, &buf));
    // In B: the very same MAC is unknown → floods B's members, never unicast(2).
    const d = try t.forward(200, macOf(0x11), .access, 0, &buf);
    try testing.expectEqualSlices(PeId, &.{8}, d.flood);
    try testing.expect(t.lookup(200, macOf(0x11), 0) == null);
    try testing.expect(t.lookup(100, macOf(0x11), 0) != null);
}

test "BUM classification drives flood: broadcast, multicast, unknown-unicast flood; known unicast does not" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(1, 2);
    try t.addMember(1, 3);
    _ = try t.learn(1, macOf(0x55), 2, 0);

    var buf: [16]PeId = undefined;
    // known unicast → unicast, NOT flood
    try testing.expect((try t.forward(1, macOf(0x55), .access, 0, &buf)) == .unicast);
    // broadcast → flood
    try testing.expect((try t.forward(1, broadcast, .access, 0, &buf)) == .flood);
    // multicast → flood
    const group: Mac = .{ 0x33, 0x33, 0, 0, 0, 1 }; // IPv6 multicast, I/G set
    try testing.expect((try t.forward(1, group, .access, 0, &buf)) == .flood);
    // unknown unicast → flood
    try testing.expect((try t.forward(1, macOf(0x66), .access, 0, &buf)) == .flood);
}

test "MAC move: relearn behind a new PE updates the decision (last-writer-wins)" {
    var t = testTable();
    defer t.deinit();
    var buf: [16]PeId = undefined;
    try t.addIsid(3); // the tenant is control-plane state; the data plane fills it
    _ = try t.learn(3, macOf(0x77), 2, 0);
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(3, macOf(0x77), .access, 5, &buf));
    _ = try t.learn(3, macOf(0x77), 7, 10); // same MAC, now seen from PE 7
    try testing.expectEqual(Decision{ .unicast = 7 }, try t.forward(3, macOf(0x77), .access, 20, &buf));
    try testing.expectEqual(@as(usize, 1), t.fdbCount(3)); // a move, not a second entry
}

// Regression (audit F5 / P-09): a MAC move is unauthenticated data-plane
// traffic redirection. Before the fix `learn` was plain last-writer-wins with
// no counter, no limit and no return value, so one hostile frame with a spoofed
// source MAC silently pointed a station's entire unicast flow at the attacker's
// PE and kept it there for as long as the attacker refreshed it. The contract
// now is: every move is REPORTED to the caller and COUNTED, and a MAC that
// flaps `max_mac_moves` times inside `mac_move_window` is quarantined — no
// binding is trusted, the MAC floods (which still reaches the real station),
// and the refused move is not installed (EVPN RFC 7432 §15).
test "MAC hijack: a move is reported and counted, and a flapping MAC is quarantined, not stolen" {
    var t = Table.init(testing.allocator, .{
        .max_isids = 64,
        .max_pes_per_isid = 16,
        .max_macs_per_isid = 8,
        .aging_ticks = 10,
        .max_mac_moves = 3,
        .mac_move_window = 50,
    });
    defer t.deinit();
    try t.addMember(1, 2); // the victim station's real PE
    try t.addMember(1, 9); // the attacker's PE
    var buf: [16]PeId = undefined;
    const victim = macOf(0x42);

    // Normal learning: no move, nothing to report.
    try testing.expectEqual(LearnOutcome.learned, try t.learn(1, victim, 2, 0));
    try testing.expectEqual(LearnOutcome.refreshed, try t.learn(1, victim, 2, 1));
    try testing.expectEqual(@as(u8, 0), t.moveCount(1, victim));
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(1, victim, .access, 1, &buf));

    // ONE hostile frame steals the entry. The steal is still accepted — real
    // mobility is indistinguishable from it — but it is no longer SILENT: the
    // caller is told it happened and the move is counted.
    try testing.expectEqual(LearnOutcome.moved, try t.learn(1, victim, 9, 2));
    try testing.expectEqual(@as(u8, 1), t.moveCount(1, victim));
    try testing.expectEqual(@as(?PeId, 9), t.lookup(1, victim, 2));

    // The victim answers, the attacker steals again: the flap is now bounded.
    try testing.expectEqual(LearnOutcome.moved, try t.learn(1, victim, 2, 3));
    try testing.expectEqual(@as(u8, 2), t.moveCount(1, victim));
    try testing.expectEqual(LearnOutcome.duplicate_detected, try t.learn(1, victim, 9, 4));
    try testing.expect(t.isQuarantined(1, victim));

    // The refused move did not install the attacker, and the frame floods to
    // every member instead of being unicast to whoever won the last race.
    try testing.expect(t.lookup(1, victim, 4) == null);
    try testing.expectEqualSlices(PeId, &.{ 2, 9 }, (try t.forward(1, victim, .access, 4, &buf)).flood);

    // Nothing the attacker sends re-opens the entry, and sending does not
    // EXTEND the quarantine either (its window start is pinned at detection).
    var k: Time = 5;
    while (k < 50) : (k += 5) {
        try testing.expectEqual(LearnOutcome.denied_duplicate, try t.learn(1, victim, 9, k));
        try testing.expect(t.lookup(1, victim, k) == null);
    }
    // Nor does ageing quietly reclaim the entry and hand the MAC straight back:
    // at t=54 the entry is 51 ticks old against aging_ticks=10, yet the live
    // quarantine outlives it.
    t.tick(54);
    try testing.expectEqual(@as(usize, 1), t.fdbCount(1));
    try testing.expect(t.isQuarantined(1, victim));

    // Past the window the MAC is learnable again, from scratch (self-healing —
    // a quarantine is not a permanent black hole for a legitimate station).
    try testing.expectEqual(LearnOutcome.learned, try t.learn(1, victim, 2, 56));
    try testing.expect(!t.isQuarantined(1, victim));
    try testing.expectEqual(@as(u8, 0), t.moveCount(1, victim));
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(1, victim, .access, 56, &buf));

    // A static pin is above all of this: it is neither moved nor quarantined.
    try t.learnStatic(1, victim, 2, 60);
    try testing.expectEqual(LearnOutcome.static_pinned, try t.learn(1, victim, 9, 60));
    try testing.expectEqual(@as(?PeId, 2), t.lookup(1, victim, 60));
}

// Regression (audit F3 / P-10): the module documents tenant state as
// "control-plane state the caller owns", but `learn` called `getOrCreateIsid`
// unconditionally, so a data-plane frame carrying an I-SID nobody configured
// allocated a fresh tenant slot (two hash maps). An attacker with no
// control-plane access could therefore walk `max_isids` — the documented
// worst-case footprint — entirely from received frames. The pre-fix test suite
// only ever pinned the *cap*, never that an unconfigured I-SID is refused.
test "data plane cannot create tenants: learn on an unconfigured I-SID is refused, not allocated" {
    var t = Table.init(testing.allocator, .{ .max_isids = 4, .max_pes_per_isid = 4, .max_macs_per_isid = 4 });
    defer t.deinit();

    // The walk an attacker performs: novel I-SIDs, one frame each. Every one is
    // refused, and — the part that matters — nothing is allocated for any of
    // them. Before the fix the first 4 silently provisioned tenants and the
    // rest failed with TooManyIsids, i.e. the budget was spent by traffic.
    var isid: Isid = 1;
    while (isid <= 100) : (isid += 1) {
        try testing.expectError(error.UnknownIsid, t.learn(isid, macOf(@truncate(isid)), 7, 0));
        try testing.expectEqual(@as(usize, 0), t.isidCount());
    }
    try testing.expectEqual(@as(usize, 0), t.fdbCount(1));
    try testing.expectEqual(@as(usize, 0), t.memberCount(1));

    // The control plane provisions; only then does the data plane learn. All
    // three control-plane entry points create the slot.
    try t.addIsid(1);
    try testing.expectEqual(LearnOutcome.learned, try t.learn(1, macOf(1), 7, 0));
    try t.addMember(2, 5);
    try testing.expectEqual(LearnOutcome.learned, try t.learn(2, macOf(2), 5, 0));
    try t.learnStatic(3, macOf(3), 6, 0);
    try testing.expectEqual(LearnOutcome.learned, try t.learn(3, macOf(4), 6, 0));
    try testing.expectEqual(@as(usize, 3), t.isidCount());

    // Deprovisioning closes the door again (and frees the tenant's FDB).
    try testing.expect(t.removeIsid(1));
    try testing.expect(!t.removeIsid(1)); // idempotent
    try testing.expectEqual(@as(usize, 2), t.isidCount());
    try testing.expectError(error.UnknownIsid, t.learn(1, macOf(1), 7, 0));
}

test "ageing: fresh → unicast; past aging_ticks the entry is gone → flood; relearn refreshes" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(4, 8);
    _ = try t.learn(4, macOf(0x88), 2, 1000); // learned at t=1000, aging=100

    var buf: [16]PeId = undefined;
    // t=1100: age exactly 100 == aging_ticks → still fresh (boundary).
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(4, macOf(0x88), .access, 1100, &buf));
    // t=1101: age 101 > 100 → expired, treated as unknown → flood (lazy).
    try testing.expect((try t.forward(4, macOf(0x88), .access, 1101, &buf)) == .flood);
    // The stale entry lingers until a tick reclaims it.
    try testing.expectEqual(@as(usize, 1), t.fdbCount(4));
    t.tick(1101);
    try testing.expectEqual(@as(usize, 0), t.fdbCount(4));
    // Relearn refreshes the age: fresh again well past the original expiry.
    _ = try t.learn(4, macOf(0x88), 2, 1101);
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(4, macOf(0x88), .access, 1200, &buf));
}

test "static entry is never aged and not overwritten by dynamic learn" {
    var t = testTable();
    defer t.deinit();
    try t.learnStatic(5, macOf(0x99), 2, 0);
    var buf: [16]PeId = undefined;
    // Never expires, even far past any aging window.
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(5, macOf(0x99), .access, std.math.maxInt(Time), &buf));
    t.tick(std.math.maxInt(Time));
    try testing.expectEqual(@as(usize, 1), t.fdbCount(5));
    // Dynamic learn does not move a static entry.
    _ = try t.learn(5, macOf(0x99), 7, 10);
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(5, macOf(0x99), .access, 10, &buf));
    // forget removes it.
    try testing.expect(t.forget(5, macOf(0x99)));
    try testing.expect(t.lookup(5, macOf(0x99), 10) == null);
}

test "learnStatic pins an already-dynamic entry: it stops ageing after the upgrade" {
    var t = testTable(); // aging_ticks = 100
    defer t.deinit();
    try t.addIsid(6);
    _ = try t.learn(6, macOf(0xAA), 2, 0); // dynamic, learned at t=0
    // Still dynamic: it would expire past the aging window.
    try testing.expect(t.lookup(6, macOf(0xAA), 1000) == null);

    // Re-learn at t=0 doesn't matter here; pin it via learnStatic instead.
    try t.learnStatic(6, macOf(0xAA), 3, 0);
    // Now pinned behind PE 3, and never expires — even far past the window
    // that would have aged out the original dynamic entry.
    try testing.expectEqual(@as(?PeId, 3), t.lookup(6, macOf(0xAA), 1000));
    try testing.expectEqual(@as(?PeId, 3), t.lookup(6, macOf(0xAA), std.math.maxInt(Time)));
    t.tick(std.math.maxInt(Time));
    try testing.expectEqual(@as(usize, 1), t.fdbCount(6)); // not reclaimed
}

test "isExpired clock-skew clamp: now before learned_at is treated as age 0 (fresh), not a crash" {
    var t = testTable(); // aging_ticks = 100
    defer t.deinit();
    // Learn "in the future" relative to a later query with a smaller `now`
    // (e.g. a clock adjustment). age must clamp to 0, never underflow.
    try t.addIsid(7);
    _ = try t.learn(7, macOf(0xBB), 2, 1_000);
    var buf: [16]PeId = undefined;
    const d = try t.forward(7, macOf(0xBB), .access, 10, &buf); // now(10) < learned_at(1000)
    try testing.expectEqual(Decision{ .unicast = 2 }, d);
    try testing.expectEqual(@as(?PeId, 2), t.lookup(7, macOf(0xBB), 0));
}

test "capacity: per-tenant MAC-flood is bounded; existing entries unaffected; reclaim on ageing" {
    var t = testTable(); // max_macs_per_isid = 8, aging = 100
    defer t.deinit();
    // Fill the FDB to its cap with fresh entries at t=0.
    try t.addIsid(6);
    var i: u8 = 0;
    while (i < 8) : (i += 1) _ = try t.learn(6, macOf(i), 2, 0);
    try testing.expectEqual(@as(usize, 8), t.fdbCount(6));

    // A 9th novel MAC while full and nothing expired → rejected, not grown.
    try testing.expectError(error.FdbFull, t.learn(6, macOf(200), 2, 0));
    try testing.expectEqual(@as(usize, 8), t.fdbCount(6));
    // An existing MAC is still refreshable while full (a move/refresh, no growth).
    _ = try t.learn(6, macOf(0), 3, 0);
    try testing.expectEqual(@as(usize, 8), t.fdbCount(6));
    try testing.expectEqual(@as(?PeId, 3), t.lookup(6, macOf(0), 0));

    // Once the table has aged out, learning reclaims and admits the new MAC.
    _ = try t.learn(6, macOf(201), 2, 1000); // at full + all others expired (age 1000>100)
    // insertNewMac pruned the 8 expired entries, then inserted 201.
    try testing.expectEqual(@as(usize, 1), t.fdbCount(6));
    try testing.expectEqual(@as(?PeId, 2), t.lookup(6, macOf(201), 1000));
}

test "F4: learnStatic reclaims expired dynamic entries too, not just dynamic learn" {
    // learnStatic hard-coded now=0 into insertNewMac's prune call, so
    // pruneIsid(ie, 0) computed age 0 for every entry (the clock-skew clamp
    // turns `now < learned_at` into age 0) and reclaimed nothing — an
    // operator's administrative MAC pin was rejected with FdbFull even
    // though a dynamic `learn` at the very same instant would have reclaimed
    // the space and succeeded. Same scenario as the dynamic-path capacity
    // test above, but through learnStatic.
    var t = testTable(); // max_macs_per_isid = 8, aging = 100
    defer t.deinit();
    try t.addIsid(6);
    var i: u8 = 0;
    while (i < 8) : (i += 1) _ = try t.learn(6, macOf(i), 2, 0);
    try testing.expectEqual(@as(usize, 8), t.fdbCount(6));

    // Well past the aging window: every dynamic entry above is expired
    // (age 1000 > 100). A static pin passing the real current time must
    // reclaim them, exactly as the dynamic path does.
    try t.learnStatic(6, macOf(201), 2, 1000);
    try testing.expectEqual(@as(usize, 1), t.fdbCount(6));
    try testing.expectEqual(@as(?PeId, 2), t.lookup(6, macOf(201), 1000));
}

test "capacity: I-SID and member caps are enforced" {
    var t = Table.init(testing.allocator, .{ .max_isids = 2, .max_pes_per_isid = 2, .max_macs_per_isid = 4 });
    defer t.deinit();
    try t.addMember(1, 10);
    try t.addMember(2, 10);
    try testing.expectError(error.TooManyIsids, t.addMember(3, 10)); // 3rd I-SID
    try testing.expectError(error.TooManyIsids, t.addIsid(3)); // ditto, explicit
    try testing.expectError(error.TooManyIsids, t.learnStatic(3, macOf(1), 10, 0)); // ditto, control plane
    // The data plane never gets as far as the I-SID cap: an unconfigured I-SID
    // is refused before anything is allocated (it cannot create a tenant at all,
    // so it cannot consume the budget either).
    try testing.expectError(error.UnknownIsid, t.learn(3, macOf(1), 10, 0));
    // Member cap within an existing I-SID.
    try t.addMember(1, 11); // 2nd member of I-SID 1 (at cap now)
    try testing.expectError(error.TooManyMembers, t.addMember(1, 12));
    try t.addMember(1, 10); // re-adding an existing member is fine (idempotent)
    try testing.expectEqual(@as(usize, 2), t.memberCount(1));
}

test "membership: add/remove/isMember; removeMember purges the FDB entries behind that PE (F8)" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(9, 4);
    try t.addMember(9, 5);
    _ = try t.learn(9, macOf(0x01), 4, 0); // behind the PE about to be removed
    _ = try t.learn(9, macOf(0x02), 5, 0); // behind a DIFFERENT, still-member PE
    try testing.expect(t.isMember(9, 4));
    t.removeMember(9, 4);
    try testing.expect(!t.isMember(9, 4));
    // F8: previously "still in the FDB until it ages" (up to `aging_ticks`,
    // 300s at production defaults) — a black-hole window with no API to
    // shorten it. `removeMember` now purges FDB entries pointing at the
    // removed PE immediately, so the MAC is unknown again and the next frame
    // floods to the remaining members instead of being sent nowhere.
    try testing.expectEqual(@as(?PeId, null), t.lookup(9, macOf(0x01), 0));
    // A MAC behind a DIFFERENT, still-current member must be untouched.
    try testing.expectEqual(@as(?PeId, 5), t.lookup(9, macOf(0x02), 0));
}

test "determinism: identical (ops, now) streams produce identical decisions" {
    const Run = struct {
        fn drive() [4]PeId {
            var t = Table.init(testing.allocator, .{});
            defer t.deinit();
            // Add members in a scrambled order; the sorted flood set must be
            // insertion-order-independent.
            t.addMember(1, 40) catch unreachable;
            t.addMember(1, 10) catch unreachable;
            t.addMember(1, 30) catch unreachable;
            t.addMember(1, 20) catch unreachable;
            var buf: [8]PeId = undefined;
            const d = t.forward(1, broadcast, .access, 0, &buf) catch unreachable;
            var out: [4]PeId = undefined;
            @memcpy(&out, d.flood[0..4]);
            return out;
        }
    };
    try testing.expectEqual([4]PeId{ 10, 20, 30, 40 }, Run.drive());
    try testing.expectEqual(Run.drive(), Run.drive());
}

// Permanent positive control (CONVENTIONS/brief): prove the split-horizon
// assertion has teeth. This control was rewritten with the fix for the
// full-mesh rule (RFC 4762 §4.4 / RFC 7432 §8.3.1): it used to pin
// "members − src_pe" as *correct* and the full member set as *broken*, when in
// fact BOTH relay a core-received frame back into the fabric and both storm.
// The genuinely broken variant is now the one this module used to compute.
test "positive control: 'members − src_pe' is a relay, and it is what storms the fabric" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(1, 2);
    try t.addMember(1, 3);
    try t.addMember(1, 4);
    const src: PeId = 3;
    const ingress: Ingress = .{ .core = src };

    var buf: [16]PeId = undefined;
    // The correct set for a core-received BUM frame is EMPTY — nothing at all
    // goes back into the fabric.
    const correct = try t.replicationSet(1, ingress, &buf);
    try testing.expectEqual(@as(usize, 0), correct.len);

    // The broken variant: the old rule, every member except the source. It is
    // non-empty, so each of the N−1 PEs that received the ingress replication
    // would relay to N−2 more, and so on — the storm. If `replicationSet` ever
    // regressed to this, the split-horizon and no-storm tests above go RED.
    var broken: [16]PeId = undefined;
    var n: usize = 0;
    var it = t.isids.getPtr(1).?.members.keyIterator();
    while (it.next()) |pe_ptr| {
        if (pe_ptr.* == src) continue;
        broken[n] = pe_ptr.*;
        n += 1;
    }
    std.mem.sort(PeId, broken[0..n], {}, std.sort.asc(PeId));
    try testing.expectEqualSlices(PeId, &.{ 2, 4 }, broken[0..n]);
    try testing.expect(!std.mem.eql(PeId, correct, broken[0..n]));
    // Each relayed copy is itself relayable → unbounded but for l2encap's TTL.
    try testing.expect(broken[0..n].len > 0);
}

test "forward: BufferTooSmall when out cannot hold the replication set" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(1, 2);
    try t.addMember(1, 3);
    try t.addMember(1, 4);
    var tiny: [1]PeId = undefined; // room for 1, need 2 after excluding src
    try testing.expectError(error.BufferTooSmall, t.forward(1, broadcast, .access, 0, &tiny));
}

test "forward on an unknown I-SID floods to an empty set" {
    var t = testTable();
    defer t.deinit();
    var buf: [16]PeId = undefined;
    const d = try t.forward(12345, broadcast, .access, 0, &buf);
    try testing.expectEqual(@as(usize, 0), d.flood.len);
}

test "deinit frees all nested membership + FDB maps (leak check via testing.allocator)" {
    var t = testTable();
    defer t.deinit();
    var isid: Isid = 0;
    while (isid < 5) : (isid += 1) {
        try t.addMember(isid, 1);
        try t.addMember(isid, 2);
        var m: u8 = 0;
        while (m < 4) : (m += 1) _ = try t.learn(isid, macOf(m), 1, 0);
        try t.learnStatic(isid, macOf(0xFE), 2, 0);
    }
    try testing.expectEqual(@as(usize, 5), t.isidCount());
    // No explicit frees here: testing.allocator asserts no leak at deinit.
}

// External anchor (2026-08-01): a real Linux bridge, `bridge fdb show`.
//
// `Options.aging_ticks`'s default (300) is documented above as "the 802.1D
// default ageing time is 300 seconds" — a claim read from the spec until now.
// It was checked once against a REAL kernel bridge in a throwaway unprivileged
// namespace (`unshare --user --net`, a plain 3-port `br0` over veth pairs, no
// `-Z`/tcpdump involved — a Python `AF_PACKET` socket and `ip`/`bridge` did the
// observing): `ip -d link show br0` reported `ageing_time 30000` — centiseconds,
// i.e. exactly 300 s — confirming the constant this module ships is the real
// 802.1D default, not merely the spec's stated one. Frozen here as a literal;
// this test does not touch a socket or a namespace, it only pins the number.
//
// The same live bridge also confirmed, qualitatively (see SPEC.md — not
// wired in as an automated assertion, because it is either not expressible in
// this module's abstract {Isid, PeId, Mac, Time} terms, or genuinely
// timing-dependent and therefore flake-prone, exactly the class of test this
// audit was told to avoid):
//   - learn-on-receipt: a frame's source MAC appeared in `bridge fdb show`
//     against its ingress port immediately, before any forwarding decision;
//   - flood-on-unknown-dst: a frame to an unlearned/broadcast destination
//     reached every other port;
//   - learned-unicast is NOT flooded: once a destination MAC was learned
//     behind one port, a frame to it reached only that port, not the third;
//   - age-out: with `ageing_time` lowered to 2 s, the dynamic entry vanished
//     from `bridge fdb show` after the ageing window elapsed.
// All four match this module's documented learn/flood/forward/tick semantics.
test "external anchor: our default aging_ticks matches a live kernel bridge's default ageing_time" {
    // Captured 2026-08-01: `ip -d link show br0` on a freshly created bridge
    // (no explicit ageing_time set) reported `ageing_time 30000` (centiseconds).
    const kernel_bridge_default_ageing_time_centiseconds: u64 = 30000;
    const kernel_bridge_default_ageing_time_seconds = kernel_bridge_default_ageing_time_centiseconds / 100;
    const default_options = Options{};
    try testing.expectEqual(kernel_bridge_default_ageing_time_seconds, default_options.aging_ticks);
}

test {
    std.testing.refAllDecls(@This());
}

test "SELF: default FDB memory footprint is documented in bytes, not just entry count" {
    // SPEC.md's "Deliberately generous defaults" section already documented
    // the entry-count product (4096 x 8192 FDB entries) as "large by
    // construction", but not what that costs in actual memory an operator
    // has to provision for -- an entry count alone under-communicates the
    // risk on an edge PE with a modest memory budget. This pins the byte
    // estimate SPEC.md/README.md now state, so a future `FdbEntry`/`Mac`
    // size change re-triggers a doc check here instead of the docs quietly
    // drifting stale (the pattern noted by the audit for the entry-count
    // number itself).
    const raw_bytes_per_entry = @sizeOf(Mac) + @sizeOf(FdbEntry);
    const default_options = Options{};
    const worst_case_entries = default_options.max_isids * default_options.max_macs_per_isid;
    const worst_case_bytes = worst_case_entries * raw_bytes_per_entry;
    // Lower bound: `AutoHashMapUnmanaged`'s own bookkeeping (control bytes,
    // load-factor headroom) adds more on top, not less -- this is a floor,
    // and the documented figure says so.
    try testing.expect(worst_case_bytes >= 500 * 1024 * 1024); // ~500 MiB floor, matches SPEC.md
}

test "external anchor: our MAC-move defaults are RFC 7432 §15.1's stated N and M" {
    // Not a style assertion. Every duplicate-MAC test below configures its own
    // small N so it can trip the limit in a few calls, which leaves the shipped
    // defaults pinned by nothing: raising `max_mac_moves` to 255 keeps the whole
    // suite green while making the hijack refusal practically unreachable.
    // RFC 7432 §15.1 states M = 180 and N = 5; those are the numbers a reader of
    // the doc comment above is entitled to get.
    const d: Options = .{};
    try testing.expectEqual(@as(u8, 5), d.max_mac_moves);
    try testing.expectEqual(@as(Time, 180), d.mac_move_window);
}
