// SPDX-License-Identifier: MIT

//! The IS-IS link-state database for ONE level (ISO/IEC 10589 §7.3): a store
//! keyed by LSP-ID, the update process (`insert` → newer-comparison → SRM/SSN
//! flooding flags), time-injected aging + `MaxAge`/`ZeroAgeLifetime` purge, and
//! the CSNP/PSNP database-synchronisation reconcile. Pure and single-owner: no
//! threads, no owned timers, no sockets — the caller supplies `now` and drives
//! all I/O. Builds on the sibling `isis` codec for LSP + LSP-Entries wire bytes;
//! the flooding transmit loop and SPF are later consumers of the flags this
//! maintains.
//!
//! The newer-LSP comparison itself lives in `compare.zig` (the correctness
//! core). This file owns the store, the flag sets, aging, and SNP handling.
//!
//! ## Time-injection contract
//! Identical convention to the sibling `isis-adj` FSM: the store never reads a
//! wall clock. Every entry point that cares about time takes a caller-supplied
//! monotonic `now: Time` (abstract ticks in the caller's own unit); a stored
//! LSP's Remaining Lifetime is *derived* from the `now` at which it was set, so
//! aging is a comparison, never an owned countdown. Given the same `(ops, now)`
//! stream the database and its flag state are fully deterministic.
//!
//! ## Capacity / DoS bound
//! The store never grows without limit. A new distinct LSP-ID is admitted only
//! while `count() < capacity`; past that, `insert` returns `error.DatabaseFull`
//! (the store is left unchanged) rather than evicting a valid link-state record.
//! An adversary flooding distinct LSP-IDs is therefore bounded by `capacity`.
//! (ISO's LSPDBOverload response — setting the overload bit in our own LSP — is
//! a documented hook, deferred to the LSP-generation layer.)

const std = @import("std");
const isis = @import("isis");
const compare_mod = @import("compare.zig");

pub const Ordering = compare_mod.Ordering;
pub const LspVersion = compare_mod.LspVersion;
pub const compare = compare_mod.compare;

/// A caller-supplied monotonic timestamp — abstract ticks in the caller's own
/// unit (same convention as `isis-adj`). Lifetimes/thresholds are in that same
/// unit.
pub const Time = u64;

/// An 8-octet LSP-ID: system-id (6) + pseudonode-id (1) + LSP-number (1).
pub const LspId = [8]u8;

/// The comptime ceiling on the number of circuits (interfaces) a store tracks
/// SRM/SSN flags for. The per-LSP flag sets are fixed-size bitsets of this
/// width, so there is no per-interface allocation. An interface index is a
/// `u8 < interface_count <= max_interfaces`.
pub const max_interfaces: u8 = 32;

/// The per-interface flag bitset (SRM or SSN), one bit per circuit index.
pub const InterfaceSet = std.bit_set.IntegerBitSet(max_interfaces);

/// ISO 10589 default `ZeroAgeLifetime` (60 s in the reference unit): how long a
/// purged (zero-lifetime) header is retained so the purge floods before removal.
pub const default_zero_age_lifetime: u16 = 60;

/// Default capacity — the DoS bound on distinct stored LSPs. Modest by default;
/// a real deployment sizes it to the fabric.
pub const default_capacity: usize = 4096;

/// Default self-refresh threshold: when a self-originated LSP's Remaining
/// Lifetime falls to/below this, `tick` flags it for refresh rather than letting
/// it expire. ISO's relationship is refresh (`maximumLSPGenerationInterval`,
/// ~900 s) well before `MaxAge` (~1200 s); 300 is the corresponding headroom.
pub const default_refresh_threshold: u16 = 300;

/// Static per-database configuration. Immutable for the life of the `Lsdb`.
pub const Config = struct {
    /// Our own 6-octet system id. An LSP whose LSP-ID begins with these six
    /// octets is *self-originated* — aged toward refresh, never purged by aging.
    local_system_id: [6]u8,
    /// How many circuits this store maintains flooding flags for
    /// (`<= max_interfaces`). Bounds the SRM/SSN "set on all" loops.
    interface_count: u8 = 4,
    /// The set of circuits that are **broadcast** (LAN). On these, receipt of an
    /// LSP is *not* acknowledged with an SSN/PSNP (the DIS's periodic CSNP does
    /// the sync); on point-to-point circuits (the default — empty set) it is.
    /// This is the only ISO LAN-vs-P2P distinction the flag matrix needs.
    broadcast_interfaces: InterfaceSet = InterfaceSet.initEmpty(),
    /// The DoS bound on distinct stored LSPs (see the file-level Capacity note).
    capacity: usize = default_capacity,
    /// `ZeroAgeLifetime`: purge-hold duration, in `Time` units.
    zero_age_lifetime: u16 = default_zero_age_lifetime,
    /// Self-originated refresh threshold, in `Time` units.
    refresh_threshold: u16 = default_refresh_threshold,
};

pub const InsertError = error{
    /// The store is at `capacity` and this is a new distinct LSP-ID.
    DatabaseFull,
} || std.mem.Allocator.Error || isis.pdu.DecodeError;

/// The outcome of an `insert`.
pub const InsertResult = struct {
    /// How the incoming LSP compared to the stored copy (or `.newer` for a
    /// brand-new one). A purge received for an unknown LSP — which is ignored,
    /// see `insert` — reports `.same` with `stored = false`.
    ordering: Ordering,
    /// Whether the incoming LSP was stored (a strictly newer copy, or new).
    stored: bool,
    lsp_id: LspId,
};

/// What one `tick` changed, in counts (the per-LSP effects are recorded on the
/// entries themselves — read them via the flag queries and `entriesNeedingRefresh`).
pub const AgeReport = struct {
    /// Entries whose Remaining Lifetime reached zero this tick and entered the
    /// purge hold (their SRM was set on every interface to flood the purge).
    entered_purge: usize = 0,
    /// Purge-hold entries whose `ZeroAgeLifetime` elapsed and were removed.
    removed: usize = 0,
    /// Self-originated entries newly flagged for refresh this tick.
    refresh_flagged: usize = 0,
};

/// A read-only view of a stored entry, aged to the `now` passed to the query.
pub const EntryView = struct {
    lsp_id: LspId,
    sequence_number: u32,
    /// Remaining Lifetime aged down to `now` (0 for a purge or a request
    /// placeholder).
    remaining_lifetime: u16,
    checksum: u16,
    flags: isis.pdu.LspFlags,
    self_originated: bool,
    /// In the `ZeroAgeLifetime` purge hold (a zero-lifetime header awaiting
    /// removal).
    is_purge: bool,
    /// A zero-sequence placeholder created to *request* an LSP a neighbour's SNP
    /// advertised that we lack; carries no PDU bytes yet.
    is_request: bool,
    /// The owned raw PDU bytes (empty for a request placeholder). Valid until
    /// this LSP is replaced, removed, or the store is deinit'd.
    bytes: []const u8,
};

/// One stored LSP. Owns its PDU bytes (copied on insert). Remaining Lifetime is
/// derived: `remainingLifetime(now)` ages `initial_lifetime` down from `set_now`.
const Entry = struct {
    sequence_number: u32,
    /// The Remaining Lifetime value captured when this copy was set.
    initial_lifetime: u16,
    checksum: u16,
    flags: isis.pdu.LspFlags,
    /// The `now` at which this copy was set — the anchor age is derived from.
    set_now: Time,
    /// Once the LSP is a purge (received with, or aged to, zero lifetime), the
    /// `now` at/after which it is removed from the database. `null` while active.
    purge_deadline: ?Time,
    self_originated: bool,
    /// Set by `tick` when a self-originated LSP nears expiry; cleared when the
    /// owner re-inserts a fresher copy.
    refresh_pending: bool,
    /// A zero-sequence request placeholder (no PDU bytes) created from an SNP for
    /// an LSP we lack. Skipped by aging; replaced when the real LSP arrives.
    is_request: bool,
    /// Transient mark used by the CSNP completeness sweep — do not read outside a
    /// single `reconcileCsnp` call.
    snp_seen: bool,
    /// Owned raw PDU bytes (the LSP as `[0..pdu_length]`); empty for a request
    /// placeholder.
    bytes: []u8,
    /// Per-interface Send-Routing-Message flag: this LSP must be flooded out the
    /// set circuits.
    srm: InterfaceSet,
    /// Per-interface Send-Sequence-Numbers flag: a PSNP entry for this LSP must
    /// be sent out the set circuits.
    ssn: InterfaceSet,

    fn remainingLifetime(e: *const Entry, now: Time) u16 {
        if (e.purge_deadline != null or e.is_request) return 0;
        const elapsed: Time = if (now > e.set_now) now - e.set_now else 0;
        if (elapsed >= e.initial_lifetime) return 0;
        return e.initial_lifetime - @as(u16, @intCast(elapsed));
    }

    fn versionAt(e: *const Entry, now: Time) LspVersion {
        return .{
            .sequence_number = e.sequence_number,
            .remaining_lifetime = e.remainingLifetime(now),
            .checksum = e.checksum,
        };
    }
};

const EntryMap = std.AutoHashMapUnmanaged(LspId, Entry);

/// The link-state database. Single-owner: one caller/loop drives it; it holds no
/// shared state and takes a lock nowhere.
pub const Lsdb = struct {
    alloc: std.mem.Allocator,
    cfg: Config,
    map: EntryMap = .empty,

    pub fn init(alloc: std.mem.Allocator, cfg: Config) Lsdb {
        std.debug.assert(cfg.interface_count <= max_interfaces);
        return .{ .alloc = alloc, .cfg = cfg };
    }

    pub fn deinit(self: *Lsdb) void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.bytes.len > 0) self.alloc.free(kv.value_ptr.bytes);
        }
        self.map.deinit(self.alloc);
    }

    /// Number of stored LSP-IDs (includes request placeholders).
    pub fn count(self: *const Lsdb) usize {
        return self.map.count();
    }

    // ── the update process (ISO 10589 §7.3.15) ──────────────────────────────

    /// Apply a received (or locally generated) LSP. `bytes` is decoded with the
    /// `isis` codec first — a malformed PDU is a typed error and the store is
    /// left **unchanged** (nothing is mutated before the decode succeeds).
    ///
    /// `arrival_iface` is the circuit the LSP arrived on, or `null` for a
    /// locally-originated LSP (which floods out every circuit and is never
    /// acked). The SRM/SSN outcome per comparison result (see SPEC §SRM/SSN):
    ///
    /// - **newer / new** — store it; set SRM on every interface *except* the
    ///   arrival one (flood onward), clear SRM on arrival, set SSN on arrival iff
    ///   it is point-to-point (ack via PSNP), clear SSN elsewhere.
    /// - **same** — clear SRM on arrival (the sender has it), set SSN on arrival
    ///   iff point-to-point.
    /// - **older** — set SRM on arrival (re-send our newer copy), clear SSN on
    ///   arrival.
    ///
    /// A purge (zero Remaining Lifetime) for an LSP **not** in the database is
    /// ignored — there is nothing to purge, and it is deliberately not stored so
    /// a zero-lifetime flood cannot grow the database.
    pub fn insert(self: *Lsdb, bytes: []const u8, arrival_iface: ?u8, now: Time) InsertError!InsertResult {
        const lsp = try isis.Lsp.decode(bytes);
        const id = lsp.lsp_id;
        const incoming: LspVersion = .{
            .sequence_number = lsp.sequence_number,
            .remaining_lifetime = lsp.remaining_lifetime,
            .checksum = lsp.checksum,
        };

        if (self.map.getPtr(id)) |e| {
            // A placeholder is a request (sequence 0) — any real LSP is newer.
            const ord = if (e.is_request) Ordering.newer else compare(incoming, e.versionAt(now));
            switch (ord) {
                .newer => {
                    try self.fillEntry(e, lsp, bytes, now);
                    self.applyNewer(e, arrival_iface);
                },
                .same => self.applySame(e, arrival_iface),
                .older => self.applyOlder(e, arrival_iface),
            }
            return .{ .ordering = ord, .stored = ord == .newer, .lsp_id = id };
        }

        // No stored copy.
        if (lsp.remaining_lifetime == 0) {
            // Purge for an unknown LSP → ignore (nothing to purge; not stored).
            return .{ .ordering = .same, .stored = false, .lsp_id = id };
        }
        if (self.map.count() >= self.cfg.capacity) return error.DatabaseFull;
        const gop = try self.map.getOrPut(self.alloc, id);
        gop.value_ptr.* = try self.newEntry(lsp, bytes, now);
        self.applyNewer(gop.value_ptr, arrival_iface);
        return .{ .ordering = .newer, .stored = true, .lsp_id = id };
    }

    /// Build a fresh owned entry from a decoded LSP (dupes the PDU bytes).
    fn newEntry(self: *Lsdb, lsp: isis.Lsp, bytes: []const u8, now: Time) !Entry {
        const owned = try self.alloc.dupe(u8, bytes[0..lsp.pdu_length]);
        return .{
            .sequence_number = lsp.sequence_number,
            .initial_lifetime = lsp.remaining_lifetime,
            .checksum = lsp.checksum,
            .flags = lsp.flags,
            .set_now = now,
            .purge_deadline = if (lsp.remaining_lifetime == 0) now + self.cfg.zero_age_lifetime else null,
            .self_originated = std.mem.eql(u8, lsp.lsp_id[0..6], &self.cfg.local_system_id),
            .refresh_pending = false,
            .is_request = false,
            .snp_seen = false,
            .bytes = owned,
            .srm = InterfaceSet.initEmpty(),
            .ssn = InterfaceSet.initEmpty(),
        };
    }

    /// Replace an existing entry's contents with a newer decoded LSP (frees the
    /// old bytes, dupes the new). Resets purge/refresh/request state; the caller
    /// then re-applies the flooding flags.
    fn fillEntry(self: *Lsdb, e: *Entry, lsp: isis.Lsp, bytes: []const u8, now: Time) !void {
        const owned = try self.alloc.dupe(u8, bytes[0..lsp.pdu_length]);
        if (e.bytes.len > 0) self.alloc.free(e.bytes);
        e.bytes = owned;
        e.sequence_number = lsp.sequence_number;
        e.initial_lifetime = lsp.remaining_lifetime;
        e.checksum = lsp.checksum;
        e.flags = lsp.flags;
        e.set_now = now;
        e.purge_deadline = if (lsp.remaining_lifetime == 0) now + self.cfg.zero_age_lifetime else null;
        e.self_originated = std.mem.eql(u8, lsp.lsp_id[0..6], &self.cfg.local_system_id);
        e.refresh_pending = false;
        e.is_request = false;
    }

    fn setSsnIfP2p(self: *Lsdb, e: *Entry, iface: u8) void {
        if (!self.cfg.broadcast_interfaces.isSet(iface)) e.ssn.set(iface);
    }

    fn applyNewer(self: *Lsdb, e: *Entry, arrival_iface: ?u8) void {
        e.srm = InterfaceSet.initEmpty();
        e.ssn = InterfaceSet.initEmpty();
        var i: u8 = 0;
        while (i < self.cfg.interface_count) : (i += 1) {
            if (arrival_iface) |a| if (i == a) continue;
            e.srm.set(i);
        }
        if (arrival_iface) |a| self.setSsnIfP2p(e, a);
    }

    fn applySame(self: *Lsdb, e: *Entry, arrival_iface: ?u8) void {
        if (arrival_iface) |a| {
            e.srm.unset(a);
            self.setSsnIfP2p(e, a);
        }
    }

    fn applyOlder(_: *Lsdb, e: *Entry, arrival_iface: ?u8) void {
        if (arrival_iface) |a| {
            e.srm.set(a);
            e.ssn.unset(a);
        }
    }

    // ── aging + purge (ISO 10589 §7.3.16.4) ─────────────────────────────────

    /// Advance database aging to `now`. Each active entry's Remaining Lifetime is
    /// re-derived; on reaching zero a **non-self** LSP enters the purge hold
    /// (retained as a zero-lifetime header, SRM set on every interface to flood
    /// the purge) and is removed after `ZeroAgeLifetime`. A **self-originated**
    /// LSP is never purged by aging — nearing/reaching expiry it is flagged for
    /// refresh (the owner must re-originate it with a higher sequence number).
    pub fn tick(self: *Lsdb, now: Time) AgeReport {
        var rep: AgeReport = .{};

        // Pass 1: age active entries; enter purge or flag refresh. No removals
        // here, so the iterator is not invalidated.
        var it = self.map.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr;
            if (e.is_request or e.purge_deadline != null) continue;
            const rem = e.remainingLifetime(now);
            if (e.self_originated) {
                if (rem <= self.cfg.refresh_threshold and !e.refresh_pending) {
                    e.refresh_pending = true;
                    rep.refresh_flagged += 1;
                }
                continue;
            }
            if (rem == 0) {
                e.purge_deadline = now + self.cfg.zero_age_lifetime;
                self.setSrmAll(e);
                rep.entered_purge += 1;
            }
        }

        // Pass 2: remove purge-hold entries whose ZeroAgeLifetime elapsed.
        // Removal invalidates the iterator, so re-scan after each removal.
        // Purge removals are rare (only at ZeroAgeLifetime expiry), so the
        // re-scan cost is negligible and the pass allocates nothing.
        while (true) {
            var rit = self.map.iterator();
            const victim: ?LspId = blk: {
                while (rit.next()) |kv| {
                    if (kv.value_ptr.purge_deadline) |dl| {
                        if (now >= dl) break :blk kv.key_ptr.*;
                    }
                }
                break :blk null;
            };
            const key = victim orelse break;
            if (self.map.getPtr(key)) |e| {
                if (e.bytes.len > 0) self.alloc.free(e.bytes);
            }
            _ = self.map.remove(key);
            rep.removed += 1;
        }

        return rep;
    }

    fn setSrmAll(self: *Lsdb, e: *Entry) void {
        var i: u8 = 0;
        while (i < self.cfg.interface_count) : (i += 1) e.srm.set(i);
    }

    // ── flooding-flag queries (the flooding layer's read/clear surface) ─────

    /// The union of SRM flags across all LSPs — the set of interfaces that have
    /// something queued to flood.
    pub fn interfacesWithSrm(self: *const Lsdb) InterfaceSet {
        var acc = InterfaceSet.initEmpty();
        var it = self.map.iterator();
        while (it.next()) |kv| acc.setUnion(kv.value_ptr.srm);
        return acc;
    }

    /// The SRM flag set for one LSP, or `null` if it is not stored.
    pub fn srmSet(self: *const Lsdb, id: LspId) ?InterfaceSet {
        const e = self.map.getPtr(id) orelse return null;
        return e.srm;
    }

    /// The SSN flag set for one LSP, or `null` if it is not stored.
    pub fn ssnSet(self: *const Lsdb, id: LspId) ?InterfaceSet {
        const e = self.map.getPtr(id) orelse return null;
        return e.ssn;
    }

    /// Clear the SRM flag for `id` on `iface` — the flooding layer calls this
    /// after transmitting the LSP out that circuit.
    pub fn clearSrm(self: *Lsdb, id: LspId, iface: u8) void {
        if (self.map.getPtr(id)) |e| e.srm.unset(iface);
    }

    /// Clear the SSN flag for `id` on `iface` — called after the PSNP ack for it
    /// has been sent out that circuit.
    pub fn clearSsn(self: *Lsdb, id: LspId, iface: u8) void {
        if (self.map.getPtr(id)) |e| e.ssn.unset(iface);
    }

    /// Iterate the LSPs with SRM set on `iface` — the flooding loop for one
    /// circuit. Read `bytes` to transmit, then `clearSrm`. Do not mutate the
    /// store while iterating.
    pub fn srmIterator(self: *const Lsdb, iface: u8) FlagIterator {
        return .{ .it = self.map.iterator(), .iface = iface, .want_srm = true, .now = 0 };
    }

    /// Iterate the LSPs with SSN set on `iface` — to build a PSNP for one
    /// circuit.
    pub fn ssnIterator(self: *const Lsdb, iface: u8) FlagIterator {
        return .{ .it = self.map.iterator(), .iface = iface, .want_srm = false, .now = 0 };
    }

    pub const FlagIterator = struct {
        it: EntryMap.Iterator,
        iface: u8,
        want_srm: bool,
        now: Time,

        /// Yields the LSP-ID and owned PDU bytes of the next flagged LSP.
        pub fn next(fi: *FlagIterator) ?struct { lsp_id: LspId, bytes: []const u8 } {
            while (fi.it.next()) |kv| {
                const set = if (fi.want_srm) kv.value_ptr.srm else kv.value_ptr.ssn;
                if (set.isSet(fi.iface)) {
                    return .{ .lsp_id = kv.key_ptr.*, .bytes = kv.value_ptr.bytes };
                }
            }
            return null;
        }
    };

    // ── read access ─────────────────────────────────────────────────────────

    /// A read-only view of the stored LSP `id` aged to `now`, or `null`.
    pub fn get(self: *const Lsdb, id: LspId, now: Time) ?EntryView {
        const e = self.map.getPtr(id) orelse return null;
        return viewOf(id, e, now);
    }

    /// The current (aged) Remaining Lifetime of `id`, or `null` if not stored.
    pub fn remainingLifetime(self: *const Lsdb, id: LspId, now: Time) ?u16 {
        const e = self.map.getPtr(id) orelse return null;
        return e.remainingLifetime(now);
    }

    fn viewOf(id: LspId, e: *const Entry, now: Time) EntryView {
        return .{
            .lsp_id = id,
            .sequence_number = e.sequence_number,
            .remaining_lifetime = e.remainingLifetime(now),
            .checksum = e.checksum,
            .flags = e.flags,
            .self_originated = e.self_originated,
            .is_purge = e.purge_deadline != null,
            .is_request = e.is_request,
            .bytes = e.bytes,
        };
    }

    /// Iterate every stored entry (including purges and request placeholders) as
    /// an `EntryView` aged to `now`. Used to find refresh-pending self LSPs and
    /// for diagnostics.
    pub fn iterator(self: *const Lsdb, now: Time) ViewIterator {
        return .{ .it = self.map.iterator(), .now = now };
    }

    pub const ViewIterator = struct {
        it: EntryMap.Iterator,
        now: Time,

        pub fn next(vi: *ViewIterator) ?EntryView {
            const kv = vi.it.next() orelse return null;
            return viewOf(kv.key_ptr.*, kv.value_ptr, vi.now);
        }
    };

    /// Whether the self-originated LSP `id` has been flagged for refresh by
    /// `tick` (the owner should re-originate it with a higher sequence number).
    pub fn refreshPending(self: *const Lsdb, id: LspId) bool {
        const e = self.map.getPtr(id) orelse return false;
        return e.refresh_pending;
    }

    // ── CSNP / PSNP database sync (ISO 10589 §7.3.15.2) ─────────────────────

    /// Summarise the database into LSP-Entries for a CSNP covering the inclusive
    /// LSP-ID range `[start_id, end_id]`. Fills `out` (in the map's iteration
    /// order) and returns the count written — bounded by `out.len` (the caller
    /// sizes it / paginates). Request placeholders are skipped (we do not
    /// advertise LSPs we do not actually hold). Lifetimes are aged to `now`.
    pub fn summarise(self: *const Lsdb, out: []isis.tlvs.LspEntry, start_id: LspId, end_id: LspId, now: Time) usize {
        var n: usize = 0;
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (n >= out.len) break;
            const e = kv.value_ptr;
            if (e.is_request) continue;
            const id = kv.key_ptr.*;
            if (!inRange(id, start_id, end_id)) continue;
            out[n] = .{
                .remaining_lifetime = e.remainingLifetime(now),
                .lsp_id = id,
                .sequence_number = e.sequence_number,
                .checksum = e.checksum,
            };
            n += 1;
        }
        return n;
    }

    /// Reconcile a received **PSNP** on `iface`: process each advertised
    /// LSP-Entry against the store, setting SRM (we hold a newer copy → flood it)
    /// or SSN (they hold a newer copy, or we lack it → request via PSNP) per the
    /// per-entry matrix. A PSNP is a *partial* summary, so no completeness
    /// inference is made (unlike `reconcileCsnp`). A malformed LSP-Entries TLV
    /// terminates the walk safely (no over-read); entries parsed before it are
    /// applied.
    pub fn reconcilePsnp(self: *Lsdb, psnp: isis.Psnp, iface: u8, now: Time) void {
        _ = self.reconcileEntriesMarking(psnp.tlv_bytes, iface, now);
    }

    /// Reconcile a received **CSNP** on `iface`. A CSNP is a *complete* summary
    /// of the inclusive range `[start_lsp_id, end_lsp_id]`, so beyond the
    /// per-entry matrix it also drives **completeness**: any LSP we hold in that
    /// range that the CSNP did *not* list — the neighbour lacks it — gets SRM set
    /// on `iface` (we flood it to them). If the TLV walk hits malformed bytes the
    /// completeness sweep is skipped (a corrupt CSNP must not trigger a mass
    /// re-flood).
    pub fn reconcileCsnp(self: *Lsdb, csnp: isis.Csnp, iface: u8, now: Time) void {
        const start = csnp.start_lsp_id;
        const end = csnp.end_lsp_id;

        // Clear the transient "seen" mark on our in-range entries.
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (inRange(kv.key_ptr.*, start, end)) kv.value_ptr.snp_seen = false;
        }

        const clean = self.reconcileEntriesMarking(csnp.tlv_bytes, iface, now);

        // Completeness: our in-range, real (non-request) LSPs the CSNP omitted →
        // the neighbour lacks them → flood (SRM on this circuit).
        if (clean) {
            var it2 = self.map.iterator();
            while (it2.next()) |kv| {
                const e = kv.value_ptr;
                if (e.is_request) continue;
                if (!inRange(kv.key_ptr.*, start, end)) continue;
                if (!e.snp_seen) e.srm.set(iface);
            }
        }
    }

    /// Shared walk: for each LSP-Entries (#9) TLV in `tlv_bytes`, apply the
    /// per-entry reconcile and set the `snp_seen` mark on matched entries.
    /// Returns whether the whole TLV region parsed cleanly.
    fn reconcileEntriesMarking(self: *Lsdb, tlv_bytes: []const u8, iface: u8, now: Time) bool {
        var tlv_it = isis.tlv.TlvIterator.init(tlv_bytes);
        while (tlv_it.next() catch return false) |t| {
            if (t.code != isis.tlvs.code.lsp_entries) continue;
            var ei = isis.tlvs.LspEntryIterator.init(t.value);
            while (ei.next() catch return false) |entry| {
                self.reconcileOne(entry, iface, now);
            }
        }
        return true;
    }

    fn reconcileOne(self: *Lsdb, entry: isis.tlvs.LspEntry, iface: u8, now: Time) void {
        const their: LspVersion = .{
            .sequence_number = entry.sequence_number,
            .remaining_lifetime = entry.remaining_lifetime,
            .checksum = entry.checksum,
        };
        if (self.map.getPtr(entry.lsp_id)) |e| {
            e.snp_seen = true;
            if (e.is_request) {
                // We already want it — keep requesting.
                self.setSsnIfP2p(e, iface);
                return;
            }
            switch (compare(their, e.versionAt(now))) {
                // Their copy is newer → request it (SSN → PSNP).
                .newer => self.setSsnIfP2p(e, iface),
                // Ours is newer → flood ours to them (SRM).
                .older => e.srm.set(iface),
                // In sync → stop flooding it to them (implicit ack).
                .same => e.srm.unset(iface),
            }
        } else {
            // We lack it. A summary entry that is itself an all-zero purge for an
            // unknown LSP carries nothing to request → ignore.
            if (entry.sequence_number == 0 and entry.remaining_lifetime == 0 and entry.checksum == 0) return;
            self.requestMissing(entry.lsp_id, iface);
        }
    }

    /// Create a zero-sequence request placeholder for an LSP a neighbour listed
    /// that we lack, and set SSN so a PSNP request is emitted. Bounded by
    /// `capacity`: if the store is full the request is dropped (a later CSNP
    /// retries) rather than growing the database — an SNP-flood cannot exhaust
    /// memory. An allocation failure likewise drops the request.
    fn requestMissing(self: *Lsdb, id: LspId, iface: u8) void {
        if (self.map.getPtr(id) == null and self.map.count() >= self.cfg.capacity) return;
        const gop = self.map.getOrPut(self.alloc, id) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .sequence_number = 0,
                .initial_lifetime = 0,
                .checksum = 0,
                .flags = isis.pdu.LspFlags.fromByte(0),
                .set_now = 0,
                .purge_deadline = null,
                .self_originated = false,
                .refresh_pending = false,
                .is_request = true,
                .snp_seen = true,
                .bytes = &.{},
                .srm = InterfaceSet.initEmpty(),
                .ssn = InterfaceSet.initEmpty(),
            };
        }
        self.setSsnIfP2p(gop.value_ptr, iface);
    }
};

/// Inclusive byte-wise (lexicographic) LSP-ID range test — the ordering a CSNP's
/// `[start, end]` uses.
fn inRange(id: LspId, start: LspId, end: LspId) bool {
    return std.mem.order(u8, &id, &start) != .lt and std.mem.order(u8, &id, &end) != .gt;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

const sys_local: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_other: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };

fn testCfg() Config {
    return .{ .local_system_id = sys_local, .interface_count = 4, .capacity = 8 };
}

/// Build an LSP PDU for `sys` into `buf` and return the wire slice.
fn buildLsp(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16, csum: u16) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num },
        .sequence_number = seq,
        .checksum = csum,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finish();
}

fn idOf(sys: [6]u8, lsp_num: u8) LspId {
    return .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num };
}

test "insert of a new LSP stores it and sets the newer SRM/SSN matrix" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();

    var buf: [128]u8 = undefined;
    const wire = buildLsp(&buf, sys_other, 0, 1, 1000, 0x1111);
    const r = try db.insert(wire, 2, 0);
    try testing.expect(r.stored);
    try testing.expectEqual(Ordering.newer, r.ordering);

    const id = idOf(sys_other, 0);
    const srm = db.srmSet(id).?;
    // SRM on {0,1,3}, NOT on arrival iface 2.
    try testing.expect(srm.isSet(0) and srm.isSet(1) and srm.isSet(3));
    try testing.expect(!srm.isSet(2));
    // SSN only on arrival iface 2 (point-to-point).
    const ssn = db.ssnSet(id).?;
    try testing.expect(ssn.isSet(2));
    try testing.expectEqual(@as(usize, 1), ssn.count());
}

test "duplicate (same) insert: SSN on arrival, no SRM" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf: [128]u8 = undefined;
    const wire = buildLsp(&buf, sys_other, 0, 5, 1000, 0x1111);
    _ = try db.insert(wire, 1, 0); // first time (newer)
    const id = idOf(sys_other, 0);
    db.clearSrm(id, 0);
    db.clearSrm(id, 2);
    db.clearSrm(id, 3); // pretend we flooded it everywhere

    // Same LSP arrives again on iface 3.
    const r = try db.insert(wire, 3, 1);
    try testing.expectEqual(Ordering.same, r.ordering);
    try testing.expect(!r.stored);
    const srm = db.srmSet(id).?;
    try testing.expectEqual(@as(usize, 0), srm.count()); // no new SRM
    try testing.expect(db.ssnSet(id).?.isSet(3)); // SSN (ack) on arrival
}

test "older insert: SRM on arrival only" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf1: [128]u8 = undefined;
    var buf2: [128]u8 = undefined;
    const newer = buildLsp(&buf1, sys_other, 0, 10, 1000, 0x1111);
    _ = try db.insert(newer, 1, 0);
    const id = idOf(sys_other, 0);
    db.clearSrm(id, 0);
    db.clearSrm(id, 2);
    db.clearSrm(id, 3);

    // An older sequence arrives on iface 3.
    const older = buildLsp(&buf2, sys_other, 0, 4, 1000, 0x1111);
    const r = try db.insert(older, 3, 1);
    try testing.expectEqual(Ordering.older, r.ordering);
    try testing.expect(!r.stored);
    const srm = db.srmSet(id).?;
    try testing.expect(srm.isSet(3)); // re-send our newer copy out arrival
    try testing.expectEqual(@as(usize, 1), srm.count());
    // Stored copy is still the newer sequence.
    try testing.expectEqual(@as(u32, 10), db.get(id, 1).?.sequence_number);
}

test "newer sequence replaces and re-floods" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf1: [128]u8 = undefined;
    var buf2: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&buf1, sys_other, 0, 1, 1000, 0x1111), 0, 0);
    const id = idOf(sys_other, 0);
    // A newer sequence on iface 1.
    const r = try db.insert(buildLsp(&buf2, sys_other, 0, 2, 1000, 0x2222), 1, 5);
    try testing.expect(r.stored);
    try testing.expectEqual(@as(u32, 2), db.get(id, 5).?.sequence_number);
    const srm = db.srmSet(id).?;
    try testing.expect(srm.isSet(0) and srm.isSet(2) and srm.isSet(3) and !srm.isSet(1));
}

test "locally-originated LSP (null arrival) floods every interface, no SSN" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf: [128]u8 = undefined;
    const wire = buildLsp(&buf, sys_local, 0, 1, 1200, 0x3333);
    _ = try db.insert(wire, null, 0);
    const id = idOf(sys_local, 0);
    const srm = db.srmSet(id).?;
    try testing.expectEqual(@as(usize, 4), srm.count());
    try testing.expectEqual(@as(usize, 0), db.ssnSet(id).?.count());
    try testing.expect(db.get(id, 0).?.self_originated);
}

test "malformed LSP bytes are a typed error, store unchanged" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    try testing.expectError(error.BadDiscriminator, db.insert(&([_]u8{0xFF} ** 30), 0, 0));
    try testing.expectEqual(@as(usize, 0), db.count());
}

test "capacity bound: a flood of distinct LSP-IDs is refused, not grown" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 3 });
    defer db.deinit();
    var buf: [128]u8 = undefined;
    var i: u8 = 0;
    while (i < 3) : (i += 1) {
        _ = try db.insert(buildLsp(&buf, sys_other, i, 1, 1000, 0x1111), 0, 0);
    }
    try testing.expectEqual(@as(usize, 3), db.count());
    // The 4th distinct LSP-ID is refused.
    try testing.expectError(error.DatabaseFull, db.insert(buildLsp(&buf, sys_other, 9, 1, 1000, 0x1111), 0, 0));
    try testing.expectEqual(@as(usize, 3), db.count());
    // But updating an existing LSP-ID still works at capacity.
    const r = try db.insert(buildLsp(&buf, sys_other, 0, 2, 1000, 0x2222), 0, 1);
    try testing.expect(r.stored);
    try testing.expectEqual(@as(usize, 3), db.count());
}

test "purge for an unknown LSP is ignored (not stored)" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf: [128]u8 = undefined;
    const purge = buildLsp(&buf, sys_other, 0, 3, 0, 0); // zero lifetime
    const r = try db.insert(purge, 1, 0);
    try testing.expect(!r.stored);
    try testing.expectEqual(@as(usize, 0), db.count());
}

test "aging: keeps before expiry, purges at expiry, removes after ZeroAge" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8, .zero_age_lifetime = 60 });
    defer db.deinit();
    var buf: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 100, 0x1111), 0, 0);
    const id = idOf(sys_other, 0);

    // Just before expiry (t=99): still present, lifetime 1.
    _ = db.tick(99);
    try testing.expectEqual(@as(u16, 1), db.remainingLifetime(id, 99).?);
    try testing.expect(!db.get(id, 99).?.is_purge);

    // At expiry (t=100): enters purge, lifetime 0, SRM set on all interfaces.
    const r1 = db.tick(100);
    try testing.expectEqual(@as(usize, 1), r1.entered_purge);
    try testing.expect(db.get(id, 100).?.is_purge);
    try testing.expectEqual(@as(u16, 0), db.remainingLifetime(id, 100).?);
    try testing.expectEqual(@as(usize, 2), db.srmSet(id).?.count());

    // Before ZeroAge hold ends (t=159): still held.
    _ = db.tick(159);
    try testing.expect(db.get(id, 159) != null);
    // After ZeroAge (t=160 = 100+60): removed.
    const r2 = db.tick(160);
    try testing.expectEqual(@as(usize, 1), r2.removed);
    try testing.expect(db.get(id, 160) == null);
}

test "self-originated near expiry is flagged for refresh, never purged" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8, .refresh_threshold = 50 });
    defer db.deinit();
    var buf: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&buf, sys_local, 0, 1, 100, 0x1111), null, 0);
    const id = idOf(sys_local, 0);

    // t=49: lifetime 51 > threshold 50 → not yet flagged.
    _ = db.tick(49);
    try testing.expect(!db.refreshPending(id));
    // t=60: lifetime 40 <= threshold → refresh flagged, NOT purged.
    const r = db.tick(60);
    try testing.expectEqual(@as(usize, 1), r.refresh_flagged);
    try testing.expectEqual(@as(usize, 0), r.entered_purge);
    try testing.expect(db.refreshPending(id));
    // Even past its lifetime, a self LSP is not removed by aging.
    _ = db.tick(500);
    try testing.expect(db.get(id, 500) != null);
    try testing.expect(!db.get(id, 500).?.is_purge);
}

test "CSNP reconcile: lack→SSN, we-newer→SRM, they-newer→SSN, complete-missing→SRM" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 16 });
    defer db.deinit();
    var buf: [128]u8 = undefined;

    // We hold LSP #0 seq 10 (we are newer than the CSNP's seq 5) and LSP #1
    // seq 1 (the CSNP is newer, seq 9). We LACK #2 (the CSNP lists it). We hold
    // #3 which the CSNP does NOT list at all (completeness → flood).
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 10, 1000, 0x1111), 0, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 1, 1, 1000, 0x2222), 0, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 3, 7, 1000, 0x4444), 0, 0);
    // Clear the SRM the inserts set so the CSNP effect is what we assert.
    for ([_]u8{ 0, 1, 3 }) |n| {
        db.clearSrm(idOf(sys_other, n), 0);
        db.clearSrm(idOf(sys_other, n), 1);
    }

    // Build a CSNP covering the whole range listing #0(seq5), #1(seq9), #2(seq3).
    var cbuf: [256]u8 = undefined;
    var cb = isis.pdu.CsnpBuilder.init(&cbuf, .{
        .source_id = .{ sys_other[0], sys_other[1], sys_other[2], sys_other[3], sys_other[4], sys_other[5], 0 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xFF),
    }) catch unreachable;
    const entries = [_]isis.tlvs.LspEntry{
        .{ .remaining_lifetime = 1000, .lsp_id = idOf(sys_other, 0), .sequence_number = 5, .checksum = 0x1111 },
        .{ .remaining_lifetime = 1000, .lsp_id = idOf(sys_other, 1), .sequence_number = 9, .checksum = 0x9999 },
        .{ .remaining_lifetime = 1000, .lsp_id = idOf(sys_other, 2), .sequence_number = 3, .checksum = 0x3333 },
    };
    isis.tlvs.addLspEntries(&cb.tlvs, &entries) catch unreachable;
    const cwire = cb.finish();
    const csnp = try isis.Csnp.decode(cwire);

    db.reconcileCsnp(csnp, 1, 0);

    // #0: ours (seq10) newer than CSNP (seq5) → SRM on iface 1.
    try testing.expect(db.srmSet(idOf(sys_other, 0)).?.isSet(1));
    // #1: CSNP (seq9) newer than ours (seq1) → SSN on iface 1.
    try testing.expect(db.ssnSet(idOf(sys_other, 1)).?.isSet(1));
    // #2: we lack it → a request placeholder with SSN on iface 1.
    try testing.expect(db.get(idOf(sys_other, 2), 0).?.is_request);
    try testing.expect(db.ssnSet(idOf(sys_other, 2)).?.isSet(1));
    // #3: we hold it but the CSNP omitted it → completeness → SRM on iface 1.
    try testing.expect(db.srmSet(idOf(sys_other, 3)).?.isSet(1));
}

test "summarise fills LSP-Entries for the range, skipping request placeholders" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 16 });
    defer db.deinit();
    var buf: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 4, 900, 0x1111), 0, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 1, 6, 900, 0x2222), 0, 0);

    var out: [8]isis.tlvs.LspEntry = undefined;
    const n = db.summarise(&out, @splat(0), @splat(0xFF), 0);
    try testing.expectEqual(@as(usize, 2), n);
    // Both entries present with their sequence numbers (order is map-defined).
    var seen0 = false;
    var seen1 = false;
    for (out[0..n]) |e| {
        if (e.sequence_number == 4) seen0 = true;
        if (e.sequence_number == 6) seen1 = true;
    }
    try testing.expect(seen0 and seen1);
}

test "determinism: identical (ops, now) streams yield identical flag state" {
    const Run = struct {
        fn drive(alloc: std.mem.Allocator) !struct { srm0: usize, ssn0: usize, cnt: usize } {
            var db = Lsdb.init(alloc, testCfg());
            defer db.deinit();
            var buf: [128]u8 = undefined;
            _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 1000, 0x1111), 2, 0);
            _ = try db.insert(buildLsp(&buf, sys_other, 1, 1, 1000, 0x2222), 1, 0);
            _ = try db.insert(buildLsp(&buf, sys_other, 0, 2, 1000, 0x3333), 0, 5);
            _ = db.tick(10);
            return .{
                .srm0 = db.srmSet(idOf(sys_other, 0)).?.count(),
                .ssn0 = db.ssnSet(idOf(sys_other, 0)).?.count(),
                .cnt = db.count(),
            };
        }
    };
    const a = try Run.drive(testing.allocator);
    const b = try Run.drive(testing.allocator);
    try testing.expectEqual(a.srm0, b.srm0);
    try testing.expectEqual(a.ssn0, b.ssn0);
    try testing.expectEqual(a.cnt, b.cnt);
}

test "broadcast interface: newer LSP received on it is not SSN-acked" {
    var bcast = InterfaceSet.initEmpty();
    bcast.set(2);
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 4, .capacity = 8, .broadcast_interfaces = bcast });
    defer db.deinit();
    var buf: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 1000, 0x1111), 2, 0);
    const id = idOf(sys_other, 0);
    // Arrived on broadcast iface 2 → no SSN anywhere.
    try testing.expectEqual(@as(usize, 0), db.ssnSet(id).?.count());
    // SRM still set on the other circuits.
    try testing.expect(db.srmSet(id).?.isSet(0));
}

test "srmIterator walks the LSPs queued for one circuit" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 1000, 0x1111), null, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 1, 1, 1000, 0x2222), null, 0);
    var it = db.srmIterator(0);
    var n: usize = 0;
    while (it.next()) |item| {
        try testing.expect(item.bytes.len > 0);
        n += 1;
    }
    try testing.expectEqual(@as(usize, 2), n);
}
