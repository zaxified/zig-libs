// SPDX-License-Identifier: MIT
//! l2forward — the E-LAN edge forwarding table for a multi-tenant L2VPN fabric.
//!
//! This is the forwarding *brain* a provider edge (PE) runs: given a customer
//! Ethernet frame's `{ I-SID, destination MAC, source PE }` it decides **where
//! to send it** — to one remote PE (a learned unicast), or replicated to the
//! I-SID's member PEs minus the source (a BUM/unknown flood). It pairs with the
//! sibling `l2encap` codec, which builds the actual on-wire frame: `l2encap`
//! carries the tenant tag / TTL / split-horizon *fields*; `l2forward` owns the
//! *state* (per-tenant MAC learning + membership) those fields are computed
//! from. The two agree by construction — same 24-bit **I-SID**, same 16-bit
//! **PE id**, same split-horizon rule (never replicate a BUM frame back toward
//! the PE it arrived from).
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
//!      state the caller owns.
//!   2. **FDB** (802.1D-style forwarding database) — customer MAC → remote PE,
//!      learned from received frames (`learn`), each entry carrying the `now`
//!      it was last (re)learned at so ageing is a comparison, not an owned
//!      countdown. A `static` variant (`learnStatic`) is never aged and is not
//!      overwritten by dynamic learning.
//!
//! ## Forward decision
//! `forward(isid, dst_mac, src_pe, now, out)` classifies `dst_mac` and returns:
//!   * **known unicast** — `dst_mac` is a fresh FDB hit in `isid` →
//!     `Decision.unicast(pe)`: send to that one remote PE.
//!   * **BUM** (Broadcast, Unknown-unicast, or Multicast) →
//!     `Decision.flood(set)`: the I-SID's member PEs **minus `src_pe`**
//!     (split-horizon), written into the caller-supplied `out` buffer in
//!     ascending PE-id order (deterministic). `dst_mac` is BUM when it is the
//!     broadcast address (all-ones), a multicast/group address (the I/G bit —
//!     the LSB of the first octet — is set), or a unicast that misses the FDB.
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
//! max_pes_per_isid` membership entries.
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
    .concurrency = .single_owner, // one thread/loop owns it, lock-free by design
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
};

// ── decisions & errors ───────────────────────────────────────────────────────

/// The forward decision for one frame.
pub const Decision = union(enum) {
    /// Known unicast: send to exactly this one remote PE.
    unicast: PeId,
    /// BUM / unknown-unicast: replicate to these member PEs. The slice is a
    /// prefix of the caller's `out` buffer, ascending by PE id (deterministic),
    /// already split-horizon-filtered (never contains the source PE). May be
    /// empty (the I-SID has no other members, or is unknown).
    flood: []const PeId,
};

pub const AddMemberError = error{
    /// A new I-SID would exceed `Options.max_isids`.
    TooManyIsids,
    /// This I-SID already has `Options.max_pes_per_isid` members.
    TooManyMembers,
    OutOfMemory,
};

pub const LearnError = error{
    /// A new I-SID would exceed `Options.max_isids`.
    TooManyIsids,
    /// This I-SID's FDB is full (`Options.max_macs_per_isid`) and no expired
    /// entry could be reclaimed to make room — the new MAC is not learned and
    /// forwards as unknown-unicast (floods). Existing entries are untouched.
    FdbFull,
    OutOfMemory,
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
    /// Administratively pinned: never aged, never overwritten by dynamic
    /// `learn`. Installed by `learnStatic`, removed only by `forget`/`deinit`.
    static: bool = false,
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

    /// Add `pe` to `isid`'s member set (idempotent). Creating the I-SID counts
    /// against `max_isids`; a brand-new I-SID starts with zero members, so
    /// `TooManyMembers` can only arise on an already-populated I-SID.
    pub fn addMember(self: *Table, isid: Isid, pe: PeId) AddMemberError!void {
        const ie = try self.getOrCreateIsid(isid);
        if (!ie.members.contains(pe) and ie.members.count() >= self.options.max_pes_per_isid)
            return error.TooManyMembers;
        try ie.members.put(self.alloc, pe, {});
    }

    /// Remove `pe` from `isid`'s member set. No-op if the I-SID or PE is absent.
    /// Does not touch the FDB (a MAC may still be learned behind a former
    /// member until it ages out).
    pub fn removeMember(self: *Table, isid: Isid, pe: PeId) void {
        const ie = self.isids.getPtr(isid) orelse return;
        _ = ie.members.remove(pe);
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
    /// reachable behind remote PE `src_pe`, as of `now`. Re-learning an existing
    /// dynamic MAC refreshes its age and — if it now arrives from a different PE
    /// — accepts the move (last-writer-wins). A MAC pinned by `learnStatic` is
    /// **not** overwritten by dynamic learning (the static entry wins, no
    /// error). New MACs beyond the per-tenant cap are rejected (`FdbFull`) after
    /// a reclaim attempt — see the module DoS note.
    pub fn learn(self: *Table, isid: Isid, src_mac: Mac, src_pe: PeId, now: Time) LearnError!void {
        const ie = try self.getOrCreateIsid(isid);
        if (ie.fdb.getPtr(src_mac)) |e| {
            if (e.static) return; // static entries are administratively pinned
            e.pe = src_pe; // accept move (last-writer-wins)
            e.learned_at = now;
            return;
        }
        try self.insertNewMac(ie, src_mac, .{ .pe = src_pe, .learned_at = now }, now);
    }

    /// Install a **static** entry: MAC `mac` in `isid` is pinned behind `pe`,
    /// never aged and never overwritten by dynamic `learn`. Overwrites whatever
    /// (static or dynamic) was there. Still counts against the per-tenant cap.
    pub fn learnStatic(self: *Table, isid: Isid, mac: Mac, pe: PeId) LearnError!void {
        const ie = try self.getOrCreateIsid(isid);
        if (ie.fdb.getPtr(mac)) |e| {
            e.* = .{ .pe = pe, .learned_at = 0, .static = true };
            return;
        }
        try self.insertNewMac(ie, mac, .{ .pe = pe, .learned_at = 0, .static = true }, 0);
    }

    /// Delete a learned MAC (static or dynamic) from `isid`. Returns true if an
    /// entry was removed.
    pub fn forget(self: *Table, isid: Isid, mac: Mac) bool {
        const ie = self.isids.getPtr(isid) orelse return false;
        return ie.fdb.remove(mac);
    }

    // ── lookup & the forward decision ────────────────────────────────────────

    /// The remote PE a fresh, known unicast to `dst_mac` in `isid` would go to,
    /// or null (unknown or expired). Read-only: does not mutate or reclaim (an
    /// expired entry is simply reported as a miss; `tick` reclaims it later).
    pub fn lookup(self: *const Table, isid: Isid, dst_mac: Mac, now: Time) ?PeId {
        const ie = self.isids.getPtr(isid) orelse return null;
        const e = ie.fdb.getPtr(dst_mac) orelse return null;
        if (self.isExpired(e.*, now)) return null;
        return e.pe;
    }

    /// Decide where a frame `{ isid, dst_mac, src_pe }` goes as of `now`. A
    /// known unicast → `unicast(pe)`; broadcast, multicast, or unknown-unicast →
    /// `flood(set)` where `set` is `isid`'s members minus `src_pe`, written into
    /// `out` (ascending, deterministic). Size `out` to `max_pes_per_isid`.
    /// Read-only (no mutation, no reclamation).
    pub fn forward(self: *const Table, isid: Isid, dst_mac: Mac, src_pe: PeId, now: Time, out: []PeId) ForwardError!Decision {
        if (!isBumAddress(dst_mac)) {
            if (self.lookup(isid, dst_mac, now)) |pe| return .{ .unicast = pe };
            // fall through: unknown unicast is BUM relative to this FDB
        }
        return .{ .flood = try self.replicationSet(isid, src_pe, out) };
    }

    /// The split-horizon replication set for a BUM frame that arrived from
    /// `src_pe`: every member of `isid` except `src_pe`, ascending by PE id,
    /// into `out`. Exposed directly for callers that have already classified the
    /// frame as BUM. A `src_pe` that is not a member excludes nothing (all
    /// members are returned).
    pub fn replicationSet(self: *const Table, isid: Isid, src_pe: PeId, out: []PeId) ForwardError![]const PeId {
        const ie = self.isids.getPtr(isid) orelse return out[0..0];
        var n: usize = 0;
        var it = ie.members.keyIterator();
        while (it.next()) |pe_ptr| {
            const pe = pe_ptr.*;
            if (pe == src_pe) continue; // split-horizon: never back to the source PE
            if (n >= out.len) return error.BufferTooSmall;
            out[n] = pe;
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
        const age = if (now >= e.learned_at) now - e.learned_at else 0;
        return age > self.options.aging_ticks;
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
    fn insertNewMac(self: *Table, ie: *IsidEntry, mac: Mac, entry: FdbEntry, now: Time) LearnError!void {
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
    try t.learn(10, macOf(0xAA), 2, 0); // M behind PE 2

    var buf: [16]PeId = undefined;
    const d = try t.forward(10, macOf(0xAA), 5, 0, &buf);
    try testing.expectEqual(Decision{ .unicast = 2 }, d);

    // An unlearned unicast in the same I-SID is unknown → flood (members − src 5)
    const d2 = try t.forward(10, macOf(0xBB), 5, 0, &buf);
    try testing.expectEqualSlices(PeId, &.{2}, d2.flood);
}

test "split-horizon flood: members {2,3,4}, src 3 → exactly {2,4}, ascending" {
    var t = testTable();
    defer t.deinit();
    // Insert members out of order to prove the output ordering is sorted, not
    // insertion/hash order.
    try t.addMember(7, 4);
    try t.addMember(7, 2);
    try t.addMember(7, 3);

    var buf: [16]PeId = undefined;
    const d = try t.forward(7, broadcast, 3, 0, &buf);
    try testing.expectEqualSlices(PeId, &.{ 2, 4 }, d.flood); // 3 excluded, ascending

    // src PE that is not a member excludes nothing → all three members.
    const d2 = try t.forward(7, broadcast, 99, 0, &buf);
    try testing.expectEqualSlices(PeId, &.{ 2, 3, 4 }, d2.flood);
}

test "tenant isolation: a MAC learned in I-SID A does not affect I-SID B" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(100, 2);
    try t.addMember(200, 8);
    try t.learn(100, macOf(0x11), 2, 0); // M behind PE 2, only in A

    var buf: [16]PeId = undefined;
    // In A: known unicast to PE 2.
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(100, macOf(0x11), 9, 0, &buf));
    // In B: the very same MAC is unknown → floods B's members, never unicast(2).
    const d = try t.forward(200, macOf(0x11), 9, 0, &buf);
    try testing.expectEqualSlices(PeId, &.{8}, d.flood);
    try testing.expect(t.lookup(200, macOf(0x11), 0) == null);
    try testing.expect(t.lookup(100, macOf(0x11), 0) != null);
}

test "BUM classification drives flood: broadcast, multicast, unknown-unicast flood; known unicast does not" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(1, 2);
    try t.addMember(1, 3);
    try t.learn(1, macOf(0x55), 2, 0);

    var buf: [16]PeId = undefined;
    // known unicast → unicast, NOT flood
    try testing.expect((try t.forward(1, macOf(0x55), 9, 0, &buf)) == .unicast);
    // broadcast → flood
    try testing.expect((try t.forward(1, broadcast, 9, 0, &buf)) == .flood);
    // multicast → flood
    const group: Mac = .{ 0x33, 0x33, 0, 0, 0, 1 }; // IPv6 multicast, I/G set
    try testing.expect((try t.forward(1, group, 9, 0, &buf)) == .flood);
    // unknown unicast → flood
    try testing.expect((try t.forward(1, macOf(0x66), 9, 0, &buf)) == .flood);
}

test "MAC move: relearn behind a new PE updates the decision (last-writer-wins)" {
    var t = testTable();
    defer t.deinit();
    var buf: [16]PeId = undefined;
    try t.learn(3, macOf(0x77), 2, 0);
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(3, macOf(0x77), 9, 5, &buf));
    try t.learn(3, macOf(0x77), 7, 10); // same MAC, now seen from PE 7
    try testing.expectEqual(Decision{ .unicast = 7 }, try t.forward(3, macOf(0x77), 9, 20, &buf));
    try testing.expectEqual(@as(usize, 1), t.fdbCount(3)); // a move, not a second entry
}

test "ageing: fresh → unicast; past aging_ticks the entry is gone → flood; relearn refreshes" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(4, 8);
    try t.learn(4, macOf(0x88), 2, 1000); // learned at t=1000, aging=100

    var buf: [16]PeId = undefined;
    // t=1100: age exactly 100 == aging_ticks → still fresh (boundary).
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(4, macOf(0x88), 9, 1100, &buf));
    // t=1101: age 101 > 100 → expired, treated as unknown → flood (lazy).
    try testing.expect((try t.forward(4, macOf(0x88), 9, 1101, &buf)) == .flood);
    // The stale entry lingers until a tick reclaims it.
    try testing.expectEqual(@as(usize, 1), t.fdbCount(4));
    t.tick(1101);
    try testing.expectEqual(@as(usize, 0), t.fdbCount(4));
    // Relearn refreshes the age: fresh again well past the original expiry.
    try t.learn(4, macOf(0x88), 2, 1101);
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(4, macOf(0x88), 9, 1200, &buf));
}

test "static entry is never aged and not overwritten by dynamic learn" {
    var t = testTable();
    defer t.deinit();
    try t.learnStatic(5, macOf(0x99), 2);
    var buf: [16]PeId = undefined;
    // Never expires, even far past any aging window.
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(5, macOf(0x99), 9, std.math.maxInt(Time), &buf));
    t.tick(std.math.maxInt(Time));
    try testing.expectEqual(@as(usize, 1), t.fdbCount(5));
    // Dynamic learn does not move a static entry.
    try t.learn(5, macOf(0x99), 7, 10);
    try testing.expectEqual(Decision{ .unicast = 2 }, try t.forward(5, macOf(0x99), 9, 10, &buf));
    // forget removes it.
    try testing.expect(t.forget(5, macOf(0x99)));
    try testing.expect(t.lookup(5, macOf(0x99), 10) == null);
}

test "learnStatic pins an already-dynamic entry: it stops ageing after the upgrade" {
    var t = testTable(); // aging_ticks = 100
    defer t.deinit();
    try t.learn(6, macOf(0xAA), 2, 0); // dynamic, learned at t=0
    // Still dynamic: it would expire past the aging window.
    try testing.expect(t.lookup(6, macOf(0xAA), 1000) == null);

    // Re-learn at t=0 doesn't matter here; pin it via learnStatic instead.
    try t.learnStatic(6, macOf(0xAA), 3);
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
    try t.learn(7, macOf(0xBB), 2, 1_000);
    var buf: [16]PeId = undefined;
    const d = try t.forward(7, macOf(0xBB), 9, 10, &buf); // now(10) < learned_at(1000)
    try testing.expectEqual(Decision{ .unicast = 2 }, d);
    try testing.expectEqual(@as(?PeId, 2), t.lookup(7, macOf(0xBB), 0));
}

test "capacity: per-tenant MAC-flood is bounded; existing entries unaffected; reclaim on ageing" {
    var t = testTable(); // max_macs_per_isid = 8, aging = 100
    defer t.deinit();
    // Fill the FDB to its cap with fresh entries at t=0.
    var i: u8 = 0;
    while (i < 8) : (i += 1) try t.learn(6, macOf(i), 2, 0);
    try testing.expectEqual(@as(usize, 8), t.fdbCount(6));

    // A 9th novel MAC while full and nothing expired → rejected, not grown.
    try testing.expectError(error.FdbFull, t.learn(6, macOf(200), 2, 0));
    try testing.expectEqual(@as(usize, 8), t.fdbCount(6));
    // An existing MAC is still refreshable while full (a move/refresh, no growth).
    try t.learn(6, macOf(0), 3, 0);
    try testing.expectEqual(@as(usize, 8), t.fdbCount(6));
    try testing.expectEqual(@as(?PeId, 3), t.lookup(6, macOf(0), 0));

    // Once the table has aged out, learning reclaims and admits the new MAC.
    try t.learn(6, macOf(201), 2, 1000); // at full + all others expired (age 1000>100)
    // insertNewMac pruned the 8 expired entries, then inserted 201.
    try testing.expectEqual(@as(usize, 1), t.fdbCount(6));
    try testing.expectEqual(@as(?PeId, 2), t.lookup(6, macOf(201), 1000));
}

test "capacity: I-SID and member caps are enforced" {
    var t = Table.init(testing.allocator, .{ .max_isids = 2, .max_pes_per_isid = 2, .max_macs_per_isid = 4 });
    defer t.deinit();
    try t.addMember(1, 10);
    try t.addMember(2, 10);
    try testing.expectError(error.TooManyIsids, t.addMember(3, 10)); // 3rd I-SID
    try testing.expectError(error.TooManyIsids, t.learn(3, macOf(1), 10, 0));
    // Member cap within an existing I-SID.
    try t.addMember(1, 11); // 2nd member of I-SID 1 (at cap now)
    try testing.expectError(error.TooManyMembers, t.addMember(1, 12));
    try t.addMember(1, 10); // re-adding an existing member is fine (idempotent)
    try testing.expectEqual(@as(usize, 2), t.memberCount(1));
}

test "membership: add/remove/isMember; removeMember leaves the FDB intact" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(9, 4);
    try t.learn(9, macOf(0x01), 4, 0);
    try testing.expect(t.isMember(9, 4));
    t.removeMember(9, 4);
    try testing.expect(!t.isMember(9, 4));
    // The MAC learned behind the former member is still in the FDB until it ages.
    try testing.expectEqual(@as(?PeId, 4), t.lookup(9, macOf(0x01), 0));
}

test "determinism: identical (ops, now) streams produce identical decisions" {
    const Run = struct {
        fn drive() [3]PeId {
            var t = Table.init(testing.allocator, .{});
            defer t.deinit();
            // Add members in a scrambled order; the sorted flood set must be
            // insertion-order-independent.
            t.addMember(1, 40) catch unreachable;
            t.addMember(1, 10) catch unreachable;
            t.addMember(1, 30) catch unreachable;
            t.addMember(1, 20) catch unreachable;
            var buf: [8]PeId = undefined;
            const d = t.forward(1, broadcast, 20, 0, &buf) catch unreachable; // exclude 20
            var out: [3]PeId = undefined;
            @memcpy(&out, d.flood[0..3]);
            return out;
        }
    };
    try testing.expectEqual([3]PeId{ 10, 30, 40 }, Run.drive());
    try testing.expectEqual(Run.drive(), Run.drive());
}

// Permanent positive control (CONVENTIONS/brief): prove the split-horizon
// assertion has teeth. A deliberately-broken replication that INCLUDES the
// source PE must produce a different (wrong) set — one that contains `src_pe` —
// so that if `replicationSet` ever stopped excluding the source, the
// split-horizon test above would go RED.
test "positive control: a flood set that keeps the source PE contradicts split-horizon" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(1, 2);
    try t.addMember(1, 3);
    try t.addMember(1, 4);
    const src: PeId = 3;

    var buf: [16]PeId = undefined;
    const correct = try t.replicationSet(1, src, &buf);
    // The correct, split-horizoned set never contains the source PE.
    try testing.expect(std.mem.indexOfScalar(PeId, correct, src) == null);
    try testing.expectEqualSlices(PeId, &.{ 2, 4 }, correct);

    // The broken variant: every member including the source. It DOES contain the
    // source PE and differs from the correct set — exactly the regression the
    // split-horizon test would catch.
    var broken: [16]PeId = undefined;
    var n: usize = 0;
    var it = t.isids.getPtr(1).?.members.keyIterator();
    while (it.next()) |pe_ptr| {
        broken[n] = pe_ptr.*;
        n += 1;
    }
    std.mem.sort(PeId, broken[0..n], {}, std.sort.asc(PeId));
    try testing.expect(std.mem.indexOfScalar(PeId, broken[0..n], src) != null);
    try testing.expect(!std.mem.eql(PeId, correct, broken[0..n]));
    try testing.expectEqualSlices(PeId, &.{ 2, 3, 4 }, broken[0..n]);
}

test "forward: BufferTooSmall when out cannot hold the replication set" {
    var t = testTable();
    defer t.deinit();
    try t.addMember(1, 2);
    try t.addMember(1, 3);
    try t.addMember(1, 4);
    var tiny: [1]PeId = undefined; // room for 1, need 2 after excluding src
    try testing.expectError(error.BufferTooSmall, t.forward(1, broadcast, 9, 0, &tiny));
}

test "forward on an unknown I-SID floods to an empty set" {
    var t = testTable();
    defer t.deinit();
    var buf: [16]PeId = undefined;
    const d = try t.forward(12345, broadcast, 1, 0, &buf);
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
        while (m < 4) : (m += 1) try t.learn(isid, macOf(m), 1, 0);
        try t.learnStatic(isid, macOf(0xFE), 2);
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
