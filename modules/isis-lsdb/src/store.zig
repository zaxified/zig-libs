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

/// How long a request placeholder (see `Config.request_timeout`) is retained
/// before `tick` drops it. ISO 10589's `completeSNPInterval` default is 10 s, so
/// 60 covers several CSNP retries of a genuinely-slow neighbour while still
/// bounding how long a fabricated SNP entry can occupy the request budget.
pub const default_request_timeout: u16 = 60;

/// The top of ISO/IEC 10589's LSP sequence space. The space is the **linear**
/// range `[1, 2^32-1]` (§7.3.16.1 — there is no wrap-around); a system that
/// would need to exceed it must purge the LSP and wait `MaxAge` before
/// restarting at 1. See `Lsdb.insert`'s `error.SequenceExhausted`.
pub const max_sequence_number: u32 = 0xFFFF_FFFF;

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
    /// The sub-budget, inside `capacity`, for **request placeholders** — the
    /// zero-sequence stubs `reconcileCsnp`/`reconcilePsnp` create for LSPs a
    /// neighbour advertised that we lack. `null` ⇒ `max(1, capacity / 4)`.
    /// Placeholders are created from unauthenticated SNP bytes, so they are
    /// budgeted *separately* from real LSPs: an SNP listing fabricated LSP-IDs
    /// can consume at most this many entries and can therefore never deny
    /// admission to a genuine LSP. See `requestBudget`.
    request_capacity: ?usize = null,
    /// How long, in `Time` units, a request placeholder is retained before
    /// `tick` drops it (the next CSNP re-creates it if the LSP is still wanted).
    /// Without this a placeholder for an LSP that never arrives is immortal.
    request_timeout: u16 = default_request_timeout,
};

pub const InsertError = error{
    /// The store is at `capacity` and this is a new distinct LSP-ID.
    DatabaseFull,
    /// ISO/IEC 10589 §7.3.16.1 sequence exhaustion: a **locally originated**
    /// LSP was offered at `max_sequence_number`. Originating there would leave
    /// the LSP impossible to supersede, so the store refuses it; the owner must
    /// purge the LSP and wait `MaxAge` before restarting at sequence 1.
    SequenceExhausted,
    /// ISO/IEC 10589 §7.3.14.2 e): an LSP **received from a circuit** whose ISO
    /// Fletcher checksum does not check out. The standard's `corruptedLSPReceived`
    /// circuit event; the PDU is discarded and the store is left unchanged. Also
    /// returned for a live LSP carrying a zero checksum (RFC 3719 §7). See
    /// `insert`'s "§7.3.14.2 receive validation" note.
    CorruptedLsp,
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
    /// Non-`null` when a **received** LSP carried our own system-id and would
    /// otherwise have been accepted (ISO/IEC 10589 §7.3.16.1 own-LSP rule): the
    /// challenger's sequence number. Nothing was stored. The owner must
    /// re-originate that LSP at `self_challenge + 1` (or purge it, if it is no
    /// longer relevant) — this is the receive-side counterpart of
    /// `refresh_pending`, which only fires on natural aging.
    self_challenge: ?u32 = null,
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
    /// Request placeholders whose `Config.request_timeout` elapsed without the
    /// requested LSP ever arriving, and which were dropped this tick.
    requests_expired: usize = 0,
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
    /// The highest sequence number a **peer** has claimed for this
    /// self-originated LSP-ID (ISO/IEC 10589 §7.3.16.1 own-LSP rule). `0` when
    /// unchallenged. The owner must re-originate above this value.
    challenge_sequence: u32,
    /// The owned raw PDU bytes (empty for a request placeholder). Valid until
    /// this LSP is replaced, removed, or the store is deinit'd.
    ///
    /// **For a purge (`is_purge`) these are the LSP header alone** — ISO/IEC
    /// 10589 §7.3.16.4 b). Whatever TLV body the zero-lifetime PDU arrived with
    /// is not retained and is therefore not observable by any reader, and not
    /// re-flooded: `isis.Lsp.decode(bytes).tlv_bytes` is empty and
    /// `pdu_length == isis.pdu.lsp_fixed_len`. See `Lsdb.retainHeaderOnly`.
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
    /// an LSP we lack. Skipped by aging; dropped by `tick` once
    /// `Config.request_timeout` elapses (`set_now` is the creation instant);
    /// replaced when the real LSP arrives.
    is_request: bool,
    /// The highest sequence number a peer has claimed for this self-originated
    /// LSP-ID; `0` when unchallenged. Set by `insert`'s §7.3.16.1 own-LSP rule,
    /// cleared when the owner re-originates.
    challenge_seq: u32,
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
    /// How many entries in `map` are request placeholders — the quantity the
    /// separate request budget is enforced against (kept incrementally so
    /// `requestMissing` stays O(1); an SNP with `n` entries must not cost O(n²)).
    request_count: usize = 0,

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
    ///
    /// ## The own-LSP rule (ISO/IEC 10589 §7.3.16.1)
    /// An LSP **received from a circuit** (`arrival_iface != null`) whose LSP-ID
    /// carries our own system-id is *never* accepted, however "newer" it
    /// compares. Only this system may originate its own LSPs; a neighbour's copy
    /// is at best stale and at worst hostile (a zero-lifetime purge of our own
    /// LSP, or a `max_sequence_number` injection that would lock us out of the
    /// sequence space forever). The standard's remedy — mirrored by FRRouting's
    /// `own_lsp` branch in `isis_pdu.c:process_lsp`, which calls `lsp_inc_seqno`
    /// and re-floods — is to **re-originate at the challenger's sequence + 1**.
    /// Since LSP generation is deferred (SPEC §8), this store instead:
    ///   - keeps its own copy untouched,
    ///   - sets `refresh_pending` and records `challenge_sequence` on it,
    ///   - sets SRM on **every** circuit (FRR floods the corrected LSP on all,
    ///     including the arrival one — the sender's copy is wrong), and
    ///   - reports `self_challenge = <their sequence>` in the `InsertResult`.
    /// If we hold no copy of that LSP-ID at all, it is likewise refused (FRR
    /// purges such an LSP rather than adopting it) and reported the same way.
    ///
    /// ## Sequence exhaustion (ISO/IEC 10589 §7.3.16.1)
    /// The sequence space is linear `[1, 2^32-1]`. A **local** origination
    /// (`arrival_iface == null`) at `max_sequence_number` is refused with
    /// `error.SequenceExhausted` rather than stored: a copy at the top of the
    /// space can never be superseded, so the owner must purge it and wait
    /// `MaxAge` before restarting at 1. (Refusing *at* the top rather than
    /// beyond it is deliberate — there is no "beyond" to detect.)
    ///
    /// ## §7.3.14.2 receive validation (the ISO Fletcher checksum)
    /// ISO/IEC 10589 §7.3.14.2 e): "An IS receiving a LSP with an incorrect LSP
    /// Checksum or with an invalid PDU syntax shall 1) generate a
    /// corruptedLSPReceived circuit event, 2) discard the PDU." That discard is
    /// what makes the §7.3.16.1(d) checksum tie-break safe, so it runs **first**,
    /// before any comparison — see `compare.zig`. A failure is
    /// `error.CorruptedLsp` and the store is untouched.
    ///
    /// Three cases are deliberately *not* validated, each because validating
    /// them would break a conformant network:
    /// 1. **A locally originated LSP** (`arrival_iface == null`). §7.3.14.2 is a
    ///    receive rule; §7.3.11 makes stamping the generator's job
    ///    (`isis.pdu.LspBuilder.finishStamped`), and this store is the generator's
    ///    sink, not its auditor.
    /// 2. **A purge** (zero Remaining Lifetime). §7.3.16.4 b) keeps only the LSP
    ///    header, so the body the checksum covered is gone; §7.3.16.4's note 36
    ///    states that a check of a zero-Remaining-Lifetime LSP "succeeds even
    ///    though the data portion is not present", and
    ///    `draft-li-isis-error-lsp-processing` §4 Figure 1 makes it explicit —
    ///    test Remaining Lifetime **first**, and never checksum a purge. This
    ///    exemption does not re-open the content-replacement hole *because*
    ///    §7.3.16.4 b) is enforced on the store side: a purge is retained as its
    ///    header alone (`dupeRetainedBytes`), so an attacker who sends one
    ///    replaces content with **no** content however many TLVs the PDU
    ///    carried. Without that retention rule the exemption would be exactly a
    ///    content-injection path no checksum defends (audit BD-20). A purge a
    ///    peer can send at all is then the unauthenticated-IS-IS exposure RFC
    ///    5304/5310 addresses, not one a checksum ever defended.
    /// 3. Nothing else. In particular a **zero checksum** on a live LSP is
    ///    *rejected*, not waved through: a correctly computed ISO 8473 checksum
    ///    can never be zero (RFC 3719 §7), so zero means "not computed", and
    ///    RFC 3719 §7 directs that such an LSP be treated as a checksum error and
    ///    discarded (revising §7.3.14.2(i)'s purge-instead behaviour, which "has
    ///    proved to be disruptive in practice"). Accepting it would leave clause
    ///    (d) reachable with `checksum = 0`, i.e. the whole hole still open.
    ///
    /// **What this does and does not buy.** Fletcher is unkeyed, so it stops
    /// corruption, not an adversary: an on-link attacker can compute a valid
    /// checksum for forged content as easily as we can. What it removes is the
    /// specific primitive where *arbitrary* checksum bytes at an *equal*
    /// sequence number sufficed. Authentication (RFC 5304/5310, `SPEC.md` §8)
    /// remains the only defence against a deliberate on-link forger.
    pub fn insert(self: *Lsdb, bytes: []const u8, arrival_iface: ?u8, now: Time) InsertError!InsertResult {
        const lsp = try isis.Lsp.decode(bytes);
        const id = lsp.lsp_id;
        const is_self = std.mem.eql(u8, id[0..6], &self.cfg.local_system_id);

        // §7.3.14.2 e) — before the §7.3.16.1 comparison, before the own-LSP
        // rule, before any mutation.
        if (arrival_iface != null and lsp.remaining_lifetime != 0) {
            switch (try isis.pdu.checkLspChecksum(bytes)) {
                .good => {},
                .bad, .not_present => return error.CorruptedLsp,
            }
        }

        // §7.3.16.1 sequence exhaustion — checked before any mutation.
        if (is_self and arrival_iface == null and lsp.sequence_number == max_sequence_number)
            return error.SequenceExhausted;

        const incoming: LspVersion = .{
            .sequence_number = lsp.sequence_number,
            .remaining_lifetime = lsp.remaining_lifetime,
            .checksum = lsp.checksum,
        };

        // §7.3.16.1 own-LSP rule: a received copy of OUR LSP is never accepted.
        const from_peer = arrival_iface != null;
        if (is_self and from_peer) {
            if (self.map.getPtr(id)) |e| {
                const ord = if (e.is_request) Ordering.newer else compare(incoming, e.versionAt(now));
                if (ord != .newer) {
                    // Stale or identical: the ordinary matrix is right (and does
                    // not touch the stored copy).
                    if (ord == .same) self.applySame(e, arrival_iface) else self.applyOlder(e, arrival_iface);
                    return .{ .ordering = ord, .stored = false, .lsp_id = id };
                }
                e.refresh_pending = true;
                e.challenge_seq = @max(e.challenge_seq, lsp.sequence_number);
                // Only a real copy can be re-asserted; a placeholder has no
                // bytes to flood (see `reconcileOne`, which never creates one
                // for a self LSP-ID).
                if (!e.is_request) {
                    self.setSrmAll(e);
                    e.ssn = InterfaceSet.initEmpty();
                }
                return .{ .ordering = ord, .stored = false, .lsp_id = id, .self_challenge = lsp.sequence_number };
            }
            // We hold no copy of an LSP-ID that is ours to originate. Refuse it
            // (FRR purges rather than adopts) and tell the owner.
            return .{ .ordering = .newer, .stored = false, .lsp_id = id, .self_challenge = lsp.sequence_number };
        }

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

    /// ISO/IEC 10589 §7.3.16.4 b): **"retain only the LSP header"**. The octets
    /// this store keeps for a copy of `lsp` — the whole PDU while it is active,
    /// the 27-octet LSP header alone once it is a purge (zero Remaining
    /// Lifetime).
    ///
    /// ## Why a purge is stored header-only, and why not simply rejected
    /// A purge is deliberately exempt from the §7.3.14.2 e) checksum discard
    /// (`insert`, exemption 2): its body is gone by definition, so the carried
    /// checksum cannot cover it. That exemption is only sound while the body
    /// really is discarded. Storing a zero-lifetime PDU's TLVs would make the
    /// purge a **content-injection path that no checksum defends** — an on-link
    /// party could replace a stored LSP's body with arbitrary TLVs simply by
    /// stamping Remaining Lifetime 0 (bounded, but only by `ZeroAgeLifetime`).
    /// Retaining the header closes it: `EntryView.bytes` for a purge decodes to
    /// an empty TLV region, so no reader — SPF, hostname lookup, the flooding
    /// layer that re-transmits these very bytes — can observe the injected body.
    ///
    /// A full-bodied purge is **accepted and truncated**, not discarded. ISO's
    /// purger transmits header-only, so a body means a non-conformant (or
    /// hostile) sender; but discarding it would let anyone *block* a legitimate
    /// purge from propagating by appending one octet to it. Liberal in what we
    /// accept, strict in what we retain.
    ///
    /// The header is kept **verbatim** apart from the two fields that describe
    /// the truncation itself (PDU Length, and Remaining Lifetime for the aging
    /// path — see `retainHeaderOnly`). In particular the Checksum field is left
    /// as it arrived: §7.3.16.4's note 36 has the check "succeed even though the
    /// data portion is not present", i.e. the field survives the purge and is
    /// simply not re-verified.
    fn dupeRetainedBytes(self: *Lsdb, lsp: isis.Lsp, bytes: []const u8) ![]u8 {
        if (lsp.remaining_lifetime != 0) return self.alloc.dupe(u8, bytes[0..lsp.pdu_length]);
        const hdr = try self.alloc.dupe(u8, bytes[0..isis.pdu.lsp_fixed_len]);
        stampPurgeHeader(hdr);
        return hdr;
    }

    /// Build a fresh owned entry from a decoded LSP (dupes the PDU bytes).
    fn newEntry(self: *Lsdb, lsp: isis.Lsp, bytes: []const u8, now: Time) !Entry {
        const owned = try self.dupeRetainedBytes(lsp, bytes);
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
            .challenge_seq = 0,
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
        const owned = try self.dupeRetainedBytes(lsp, bytes);
        if (e.bytes.len > 0) self.alloc.free(e.bytes);
        // The placeholder is being satisfied — give its slot back to the budget.
        if (e.is_request) self.request_count -= 1;
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
        e.challenge_seq = 0;
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
                self.retainHeaderOnly(e);
                self.setSrmAll(e);
                rep.entered_purge += 1;
            }
        }

        // Pass 2: remove purge-hold entries whose ZeroAgeLifetime elapsed, and
        // request placeholders whose `request_timeout` elapsed. Removal
        // invalidates the iterator, so re-scan after each removal. Purge
        // removals are rare (only at ZeroAgeLifetime expiry), so the re-scan
        // cost is negligible and the pass allocates nothing.
        while (true) {
            var rit = self.map.iterator();
            const victim: ?LspId = blk: {
                while (rit.next()) |kv| {
                    const e = kv.value_ptr;
                    // ISO/IEC 10589 §7.3.15.2: an SNP entry for an LSP we lack
                    // makes us *request* it; the request is re-established by
                    // the neighbour's next periodic CSNP. Holding the
                    // placeholder past that window serves nothing and lets one
                    // SNP full of fabricated LSP-IDs occupy the database
                    // forever, so it is timed out.
                    if (e.is_request) {
                        if (now >= e.set_now + self.cfg.request_timeout) break :blk kv.key_ptr.*;
                        continue;
                    }
                    if (e.purge_deadline) |dl| {
                        if (now >= dl) break :blk kv.key_ptr.*;
                    }
                }
                break :blk null;
            };
            const key = victim orelse break;
            var was_request = false;
            if (self.map.getPtr(key)) |e| {
                if (e.bytes.len > 0) self.alloc.free(e.bytes);
                was_request = e.is_request;
            }
            _ = self.map.remove(key);
            if (was_request) {
                self.request_count -= 1;
                rep.requests_expired += 1;
            } else {
                rep.removed += 1;
            }
        }

        return rep;
    }

    fn setSrmAll(self: *Lsdb, e: *Entry) void {
        var i: u8 = 0;
        while (i < self.cfg.interface_count) : (i += 1) e.srm.set(i);
    }

    /// ISO/IEC 10589 §7.3.16.4 b) for the **aging** path: an entry whose
    /// Remaining Lifetime has just reached zero becomes a purge, so the body it
    /// was holding must go the same way a received purge's does
    /// (`dupeRetainedBytes`) — these are the very octets `srmIterator` hands the
    /// flooding layer to re-transmit, and a purge is flooded as a header.
    ///
    /// It also stamps Remaining Lifetime 0 into the retained header. Without
    /// that the "purge" this store floods would carry the lifetime the LSP was
    /// *originated* with, i.e. it would not be a purge at all and the removal
    /// would never propagate.
    ///
    /// Unlike the receive path this cannot report an error (`tick` has no error
    /// union), so the shrink is best-effort: if reallocation fails the body is
    /// still erased in place and PDU Length still says "header only", so no
    /// reader and no re-flood can observe it — only the allocation stays larger
    /// than it needs to be.
    fn retainHeaderOnly(self: *Lsdb, e: *Entry) void {
        if (e.bytes.len < isis.pdu.lsp_fixed_len) return; // request placeholder
        if (e.bytes.len > isis.pdu.lsp_fixed_len) {
            if (self.alloc.realloc(e.bytes, isis.pdu.lsp_fixed_len)) |shrunk| {
                e.bytes = shrunk;
            } else |_| {
                @memset(e.bytes[isis.pdu.lsp_fixed_len..], 0);
            }
        }
        stampPurgeHeader(e.bytes);
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
            .challenge_sequence = e.challenge_seq,
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
        // ISO/IEC 10589 §7.3.16.1 own-LSP rule, SNP side: we never *request* an
        // LSP that is ours to originate, so a summary entry for our own
        // system-id can only ever mean "flood ours" or "the owner must
        // re-originate" — never SSN, and never a placeholder.
        const is_self = std.mem.eql(u8, entry.lsp_id[0..6], &self.cfg.local_system_id);
        if (is_self) {
            const e = self.map.getPtr(entry.lsp_id) orelse return;
            e.snp_seen = true;
            if (e.is_request) return;
            switch (compare(their, e.versionAt(now))) {
                // They claim a newer copy of our own LSP → assert ownership
                // (flood ours) and tell the owner to re-originate above it.
                .newer => {
                    e.refresh_pending = true;
                    e.challenge_seq = @max(e.challenge_seq, entry.sequence_number);
                    e.srm.set(iface);
                },
                // Ours is newer → flood it to them.
                .older => e.srm.set(iface),
                // In sync → stop flooding it to them.
                .same => e.srm.unset(iface),
            }
            return;
        }
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
            self.requestMissing(entry.lsp_id, iface, now);
        }
    }

    /// The ceiling on concurrently-held request placeholders — `capacity / 4` by
    /// default, never above `capacity`. Placeholders are minted from
    /// *unauthenticated* SNP bytes, so they get a budget of their own: however
    /// many LSP-IDs a hostile SNP fabricates, at least `capacity - budget` slots
    /// stay available to genuine LSPs.
    fn requestBudget(self: *const Lsdb) usize {
        return @min(self.cfg.capacity, self.cfg.request_capacity orelse @max(1, self.cfg.capacity / 4));
    }

    /// Create a zero-sequence request placeholder for an LSP a neighbour listed
    /// that we lack, and set SSN so a PSNP request is emitted. Bounded twice:
    /// by `capacity` (the store never grows without limit) and by
    /// `requestBudget` (placeholders never crowd out real LSPs). Over either
    /// bound the request is dropped — a later CSNP retries — rather than
    /// admitted. An allocation failure likewise drops the request. The
    /// placeholder's `set_now` is the creation instant, from which `tick` times
    /// it out after `Config.request_timeout`.
    fn requestMissing(self: *Lsdb, id: LspId, iface: u8, now: Time) void {
        if (self.map.getPtr(id) == null) {
            if (self.map.count() >= self.cfg.capacity) return;
            if (self.request_count >= self.requestBudget()) return;
        }
        const gop = self.map.getOrPut(self.alloc, id) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .sequence_number = 0,
                .initial_lifetime = 0,
                .checksum = 0,
                .flags = isis.pdu.LspFlags.fromByte(0),
                .set_now = now,
                .purge_deadline = null,
                .self_originated = false,
                .refresh_pending = false,
                .is_request = true,
                .challenge_seq = 0,
                .snp_seen = true,
                .bytes = &.{},
                .srm = InterfaceSet.initEmpty(),
                .ssn = InterfaceSet.initEmpty(),
            };
            self.request_count += 1;
        }
        self.setSsnIfP2p(gop.value_ptr, iface);
    }
};

/// Rewrite the two header fields that describe a §7.3.16.4 b) truncation: PDU
/// Length becomes the header length (so the TLV region a decoder derives is
/// empty), and Remaining Lifetime becomes 0 (so the retained header *is* a
/// purge on the wire). Offsets per ISO 10589 §9.8 / `isis.Lsp.decode`. Every
/// other header octet — LSP-ID, Sequence Number, Checksum, flags — is left as it
/// stood; those are what §7.3.16.1 and the CSNP summary still reason over.
fn stampPurgeHeader(hdr: []u8) void {
    std.debug.assert(hdr.len >= isis.pdu.lsp_fixed_len);
    std.mem.writeInt(u16, hdr[8..10], @intCast(isis.pdu.lsp_fixed_len), .big);
    std.mem.writeInt(u16, hdr[10..12], 0, .big);
}

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

/// Build an LSP PDU for `sys` into `buf` and return the wire slice, carrying the
/// ISO 10589 §7.3.11 checksum a conformant originator stamps. Fixtures used to
/// pass a hand-picked placeholder here (`0x1111`, `0x9999`, …); those PDUs were
/// simply invalid — Wireshark grades them "Bad" (see `goldens.zig`) — and only
/// went unnoticed because no layer checked. They are corrected, not exempted:
/// `insert` now enforces §7.3.14.2 on the receive path.
fn buildLsp(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16) []const u8 {
    var b = lspBuilder(buf, sys, lsp_num, seq, life);
    return b.finishStamped();
}

fn lspBuilder(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16) isis.pdu.LspBuilder {
    return isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
}

/// Build an LSP carrying `csum` verbatim — a wire image only a corrupt or
/// hostile sender produces. Used by the §7.3.14.2 regression tests below.
fn buildLspRawCsum(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16, csum: u16) []const u8 {
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
    const wire = buildLsp(&buf, sys_other, 0, 1, 1000);
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
    const wire = buildLsp(&buf, sys_other, 0, 5, 1000);
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
    const newer = buildLsp(&buf1, sys_other, 0, 10, 1000);
    _ = try db.insert(newer, 1, 0);
    const id = idOf(sys_other, 0);
    db.clearSrm(id, 0);
    db.clearSrm(id, 2);
    db.clearSrm(id, 3);

    // An older sequence arrives on iface 3.
    const older = buildLsp(&buf2, sys_other, 0, 4, 1000);
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
    _ = try db.insert(buildLsp(&buf1, sys_other, 0, 1, 1000), 0, 0);
    const id = idOf(sys_other, 0);
    // A newer sequence on iface 1.
    const r = try db.insert(buildLsp(&buf2, sys_other, 0, 2, 1000), 1, 5);
    try testing.expect(r.stored);
    try testing.expectEqual(@as(u32, 2), db.get(id, 5).?.sequence_number);
    const srm = db.srmSet(id).?;
    try testing.expect(srm.isSet(0) and srm.isSet(2) and srm.isSet(3) and !srm.isSet(1));
}

test "locally-originated LSP (null arrival) floods every interface, no SSN" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf: [128]u8 = undefined;
    const wire = buildLsp(&buf, sys_local, 0, 1, 1200);
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
        _ = try db.insert(buildLsp(&buf, sys_other, i, 1, 1000), 0, 0);
    }
    try testing.expectEqual(@as(usize, 3), db.count());
    // The 4th distinct LSP-ID is refused.
    try testing.expectError(error.DatabaseFull, db.insert(buildLsp(&buf, sys_other, 9, 1, 1000), 0, 0));
    try testing.expectEqual(@as(usize, 3), db.count());
    // But updating an existing LSP-ID still works at capacity.
    const r = try db.insert(buildLsp(&buf, sys_other, 0, 2, 1000), 0, 1);
    try testing.expect(r.stored);
    try testing.expectEqual(@as(usize, 3), db.count());
}

test "purge for an unknown LSP is ignored (not stored)" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf: [128]u8 = undefined;
    const purge = buildLsp(&buf, sys_other, 0, 3, 0); // zero lifetime
    const r = try db.insert(purge, 1, 0);
    try testing.expect(!r.stored);
    try testing.expectEqual(@as(usize, 0), db.count());
}

test "aging: keeps before expiry, purges at expiry, removes after ZeroAge" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8, .zero_age_lifetime = 60 });
    defer db.deinit();
    var buf: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 100), 0, 0);
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
    _ = try db.insert(buildLsp(&buf, sys_local, 0, 1, 100), null, 0);
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
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 10, 1000), 0, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 1, 1, 1000), 0, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 3, 7, 1000), 0, 0);
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
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 4, 900), 0, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 1, 6, 900), 0, 0);

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
            _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 1000), 2, 0);
            _ = try db.insert(buildLsp(&buf, sys_other, 1, 1, 1000), 1, 0);
            _ = try db.insert(buildLsp(&buf, sys_other, 0, 2, 1000), 0, 5);
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
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 1000), 2, 0);
    const id = idOf(sys_other, 0);
    // Arrived on broadcast iface 2 → no SSN anywhere.
    try testing.expectEqual(@as(usize, 0), db.ssnSet(id).?.count());
    // SRM still set on the other circuits.
    try testing.expect(db.srmSet(id).?.isSet(0));
}

// ── regression: ISO 10589 receive-side self-defences (hostile on-link peer) ───
//
// IS-IS in this deployment model is unauthenticated (SPEC §8 defers RFC
// 5304/5310), so every input below is one an on-link party can simply send.

/// Build a CSNP over the whole LSP-ID range listing `entries`.
fn buildCsnp(buf: []u8, entries: []const isis.tlvs.LspEntry) []const u8 {
    var cb = isis.pdu.CsnpBuilder.init(buf, .{
        .source_id = .{ 0xDE, 0xAD, 0, 0, 0, 0, 0 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xFF),
    }) catch unreachable;
    isis.tlvs.addLspEntries(&cb.tlvs, entries) catch unreachable;
    return cb.finish();
}

/// `n` LSP-Entries for LSP-IDs that do not exist anywhere and never will.
fn fabricatedEntries(comptime n: u8) [n]isis.tlvs.LspEntry {
    var out: [n]isis.tlvs.LspEntry = undefined;
    for (&out, 0..) |*e, i| e.* = .{
        .remaining_lifetime = 1000,
        .lsp_id = idOf(.{ 0xDE, 0xAD, 0, 0, 0, @intCast(i) }, 0),
        .sequence_number = 1,
        .checksum = 0x4242,
    };
    return out;
}

test "hostile CSNP: fabricated LSP-IDs cannot starve genuine LSPs (request budget)" {
    // capacity 8 ⇒ default request budget max(1, 8/4) = 2.
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();

    var cbuf: [512]u8 = undefined;
    const entries = fabricatedEntries(8);
    const csnp = try isis.Csnp.decode(buildCsnp(&cbuf, &entries));
    db.reconcileCsnp(csnp, 1, 0);

    // Placeholders are budgeted separately, not admitted wholesale.
    try testing.expectEqual(@as(usize, 2), db.count());

    // ...so genuine LSPs still get in — the availability property the module's
    // capacity note claims (root.zig:29-33) and which F1 showed was false.
    var buf: [128]u8 = undefined;
    var n: u8 = 0;
    while (n < 6) : (n += 1) {
        const r = try db.insert(buildLsp(&buf, sys_other, n, 1, 1000), 0, 0);
        try testing.expect(r.stored);
    }
    try testing.expectEqual(@as(usize, 8), db.count());
}

test "request placeholders are not immortal: they time out and return their slot" {
    var db = Lsdb.init(testing.allocator, .{
        .local_system_id = sys_local,
        .interface_count = 2,
        .capacity = 8,
        .request_capacity = 4,
        .request_timeout = 60,
    });
    defer db.deinit();

    var cbuf: [512]u8 = undefined;
    const entries = fabricatedEntries(4);
    const csnp = try isis.Csnp.decode(buildCsnp(&cbuf, &entries));
    db.reconcileCsnp(csnp, 1, 0);
    try testing.expectEqual(@as(usize, 4), db.count());

    // Just inside the request window: still requested.
    const r1 = db.tick(59);
    try testing.expectEqual(@as(usize, 0), r1.requests_expired);
    try testing.expectEqual(@as(usize, 4), db.count());

    // At the window: dropped (a later CSNP re-requests, as the code anticipates).
    const r2 = db.tick(60);
    try testing.expectEqual(@as(usize, 4), r2.requests_expired);
    try testing.expectEqual(@as(usize, 0), r2.removed);
    try testing.expectEqual(@as(usize, 0), db.count());

    // The budget came back with them.
    db.reconcileCsnp(csnp, 1, 60);
    try testing.expectEqual(@as(usize, 4), db.count());
}

test "own LSP (§7.3.16.1): a peer's purge of our self-originated LSP is refused" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 4, .capacity = 8, .zero_age_lifetime = 60 });
    defer db.deinit();
    var buf: [128]u8 = undefined;
    var pbuf: [128]u8 = undefined;

    _ = try db.insert(buildLsp(&buf, sys_local, 0, 5, 1200), null, 0);
    const id = idOf(sys_local, 0);
    for ([_]u8{ 0, 1, 2, 3 }) |i| db.clearSrm(id, i);

    // The attack: a lifetime-0, seq-6 header for OUR LSP-ID arrives on iface 1.
    const r = try db.insert(buildLsp(&pbuf, sys_local, 0, 6, 0), 1, 1);
    try testing.expect(!r.stored);
    try testing.expectEqual(@as(?u32, 6), r.self_challenge);

    // Our copy is untouched and is NOT in the purge hold.
    const v = db.get(id, 1).?;
    try testing.expectEqual(@as(u32, 5), v.sequence_number);
    try testing.expect(!v.is_purge);
    try testing.expectEqual(@as(u32, 6), v.challenge_sequence);
    // The owner is signalled, and we re-assert on every circuit (FRR's own_lsp
    // branch floods the corrected LSP on all circuits, arrival included).
    try testing.expect(db.refreshPending(id));
    try testing.expectEqual(@as(usize, 4), db.srmSet(id).?.count());
    try testing.expectEqual(@as(usize, 0), db.ssnSet(id).?.count());

    // Far past ZeroAgeLifetime our own LSP is still there (F2: it was deleted).
    _ = db.tick(500);
    try testing.expect(db.get(id, 500) != null);
}

test "own LSP (§7.3.16.1): a peer cannot claim the top of our sequence space" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf: [128]u8 = undefined;
    const id = idOf(sys_local, 1);

    // An LSP-ID of ours that we are not currently originating.
    const r = try db.insert(buildLsp(&buf, sys_local, 1, max_sequence_number, 1000), 2, 0);
    try testing.expect(!r.stored);
    try testing.expectEqual(@as(?u32, max_sequence_number), r.self_challenge);
    try testing.expect(db.get(id, 0) == null);

    // We can still originate it — the lockout (F3) is gone.
    const own = try db.insert(buildLsp(&buf, sys_local, 1, 7, 1000), null, 1);
    try testing.expect(own.stored);
    try testing.expectEqual(@as(u32, 7), db.get(id, 1).?.sequence_number);
}

test "sequence exhaustion (§7.3.16.1): originating at the top of the space is a typed error" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf: [128]u8 = undefined;

    // A copy at 2^32-1 could never be superseded → refuse to originate it; ISO
    // requires purge-and-wait-MaxAge instead.
    try testing.expectError(
        error.SequenceExhausted,
        db.insert(buildLsp(&buf, sys_local, 0, max_sequence_number, 1000), null, 0),
    );
    try testing.expectEqual(@as(usize, 0), db.count());

    // A *neighbour's* LSP at the top of the space is unaffected — the rule is
    // about our own origination, not about what we may store for others.
    const r = try db.insert(buildLsp(&buf, sys_other, 0, max_sequence_number, 1000), 0, 0);
    try testing.expect(r.stored);
}

test "own LSP: purge AND sequence-lockout together still leave us able to re-originate" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8, .zero_age_lifetime = 60 });
    defer db.deinit();
    var b0: [128]u8 = undefined;
    var b1: [128]u8 = undefined;
    const id0 = idOf(sys_local, 0);
    const id1 = idOf(sys_local, 1);

    _ = try db.insert(buildLsp(&b0, sys_local, 0, 5, 1200), null, 0);

    // The whole attack in one pass on one circuit: purge the live fragment,
    // and claim 2^32-1 for a fragment we hold none of.
    _ = try db.insert(buildLsp(&b0, sys_local, 0, 6, 0), 1, 1);
    _ = try db.insert(buildLsp(&b1, sys_local, 1, max_sequence_number, 1000), 1, 1);

    _ = db.tick(500); // far past ZeroAgeLifetime

    try testing.expectEqual(@as(u32, 5), db.get(id0, 500).?.sequence_number);
    try testing.expect(db.get(id1, 500) == null);

    // The owner re-originates above the recorded challenge; both land.
    const challenge = db.get(id0, 500).?.challenge_sequence;
    try testing.expectEqual(@as(u32, 6), challenge);
    try testing.expect((try db.insert(buildLsp(&b0, sys_local, 0, challenge + 1, 1200), null, 501)).stored);
    try testing.expect((try db.insert(buildLsp(&b1, sys_local, 1, 7, 1200), null, 501)).stored);
    try testing.expectEqual(@as(u32, 7), db.get(id0, 501).?.sequence_number);
    try testing.expectEqual(@as(u32, 7), db.get(id1, 501).?.sequence_number);
    // Re-origination clears the challenge record.
    try testing.expectEqual(@as(u32, 0), db.get(id0, 501).?.challenge_sequence);
    try testing.expect(!db.refreshPending(id0));
}

test "own LSP: an SNP never makes us request our own LSP-ID" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var buf: [128]u8 = undefined;
    var cbuf: [512]u8 = undefined;

    _ = try db.insert(buildLsp(&buf, sys_local, 0, 5, 1200), null, 0);
    const id0 = idOf(sys_local, 0);
    const id1 = idOf(sys_local, 1);
    db.clearSrm(id0, 0);
    db.clearSrm(id0, 1);

    // A neighbour summarises OUR LSP-IDs: fragment 0 at a higher sequence than
    // ours, fragment 1 which we do not originate at all.
    const entries = [_]isis.tlvs.LspEntry{
        .{ .remaining_lifetime = 1000, .lsp_id = id0, .sequence_number = 99, .checksum = 0x9999 },
        .{ .remaining_lifetime = 1000, .lsp_id = id1, .sequence_number = 99, .checksum = 0x9999 },
    };
    const csnp = try isis.Csnp.decode(buildCsnp(&cbuf, &entries));
    db.reconcileCsnp(csnp, 1, 0);

    // No placeholder for an LSP-ID that is ours to originate, and no SSN: we
    // never ask a neighbour for our own LSP.
    try testing.expect(db.get(id1, 0) == null);
    try testing.expectEqual(@as(usize, 1), db.count());
    try testing.expectEqual(@as(usize, 0), db.ssnSet(id0).?.count());
    // Instead: assert ownership (SRM) and tell the owner to re-originate.
    try testing.expect(db.srmSet(id0).?.isSet(1));
    try testing.expect(db.refreshPending(id0));
    try testing.expectEqual(@as(u32, 99), db.get(id0, 0).?.challenge_sequence);
}

// ── regression: ISO 10589 §7.3.14.2 e) — discard a bad-checksum LSP on receipt ─
//
// The clause the §7.3.16.1(d) tie-break presupposes. Without it, an equal
// sequence number plus an arbitrary checksum byte-pair is enough to replace a
// stored LSP's content and have us re-flood it (audit W2-28 / `isis` F3).

/// Build an LSP carrying a Dynamic Hostname (#137) TLV, so a replacement is
/// observable as *content*, not just as header fields.
fn buildNamedLsp(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16, name: []const u8, overload: bool) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = overload, .is_type = 1 },
    }) catch unreachable;
    isis.tlvs.addHostname(&b.tlvs, name) catch unreachable;
    return b.finishStamped();
}

fn hostnameOf(db: *Lsdb, id: LspId, now: Time) ?[]const u8 {
    const view = db.get(id, now) orelse return null;
    const lsp = isis.Lsp.decode(view.bytes) catch return null;
    return isis.tlv.findFirst(lsp.tlv_bytes, isis.tlvs.code.dynamic_hostname) catch null;
}

test "§7.3.14.2: equal sequence + forged checksum can no longer replace an LSP's content" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    const id = idOf(sys_other, 0);

    // The legitimate LSP, as a conformant neighbour originates it.
    var good: [128]u8 = undefined;
    const legit = buildNamedLsp(&good, sys_other, 0, 9, 1000, "legit", false);
    try testing.expect((try db.insert(legit, 2, 0)).stored);
    for ([_]u8{ 0, 1, 3 }) |i| db.clearSrm(id, i);

    // The attack (audit PROBE-B): the SAME LSP-ID at the SAME sequence number,
    // different content, and an arbitrary checksum. §7.3.16.1(d) would have
    // called it `.newer`; §7.3.14.2 discards it before the comparison runs.
    var evil: [128]u8 = undefined;
    var eb = isis.pdu.LspBuilder.init(&evil, .{
        .remaining_lifetime = 1000,
        .lsp_id = id,
        .sequence_number = 9,
        .checksum = 0xDEAD,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = true, .is_type = 1 },
    }) catch unreachable;
    try isis.tlvs.addHostname(&eb.tlvs, "EVIL!");
    try testing.expectError(error.CorruptedLsp, db.insert(eb.finish(), 1, 1));

    // Nothing moved: content, flags, sequence, and the flooding flags.
    try testing.expectEqualStrings("legit", hostnameOf(&db, id, 1).?);
    try testing.expect(!db.get(id, 1).?.flags.overload);
    try testing.expectEqual(@as(u32, 9), db.get(id, 1).?.sequence_number);
    try testing.expectEqual(@as(usize, 0), db.srmSet(id).?.count());
    try testing.expectEqual(@as(usize, 1), db.count());
}

test "§7.3.14.2: a zero checksum on a live LSP is a checksum error (RFC 3719 §7)" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    const id = idOf(sys_other, 0);

    var good: [128]u8 = undefined;
    _ = try db.insert(buildNamedLsp(&good, sys_other, 0, 9, 1000, "legit", false), 2, 0);

    // Zero is the "not computed" marker, not a value — waving it through would
    // leave clause (d) reachable with `checksum = 0`, i.e. the hole still open.
    var evil: [128]u8 = undefined;
    var eb = isis.pdu.LspBuilder.init(&evil, .{
        .remaining_lifetime = 1000,
        .lsp_id = id,
        .sequence_number = 9,
        .checksum = 0,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = true, .is_type = 1 },
    }) catch unreachable;
    try isis.tlvs.addHostname(&eb.tlvs, "EVIL!");
    try testing.expectError(error.CorruptedLsp, db.insert(eb.finish(), 1, 1));
    try testing.expectEqualStrings("legit", hostnameOf(&db, id, 1).?);

    // Same for a brand-new LSP-ID: a live LSP with no checksum never enters.
    var fresh: [128]u8 = undefined;
    try testing.expectError(
        error.CorruptedLsp,
        db.insert(buildLspRawCsum(&fresh, sys_other, 5, 1, 1000, 0), 1, 1),
    );
    try testing.expectEqual(@as(usize, 1), db.count());
}

test "§7.3.14.2: one flipped body octet is discarded, the stored copy survives" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    const id = idOf(sys_other, 0);

    var good: [128]u8 = undefined;
    const legit = buildNamedLsp(&good, sys_other, 0, 9, 1000, "legit", false);
    _ = try db.insert(legit, 2, 0);

    // Corrupt exactly one octet of the covered region, keeping the checksum —
    // the memory-corruption case §7.3.11 exists to detect.
    var corrupt: [128]u8 = undefined;
    @memcpy(corrupt[0..legit.len], legit);
    corrupt[legit.len - 1] ^= 0x01;
    try testing.expectError(error.CorruptedLsp, db.insert(corrupt[0..legit.len], 1, 1));
    try testing.expectEqualStrings("legit", hostnameOf(&db, id, 1).?);
}

test "§7.3.14.2 exemptions: purge, local origination, and in-transit aging still pass" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 4, .capacity = 8 });
    defer db.deinit();

    // (1) Local origination is not a receive path: the generation layer stamps
    // (`LspBuilder.finishStamped`), so an unstamped local insert is accepted.
    var lbuf: [128]u8 = undefined;
    try testing.expect((try db.insert(buildLspRawCsum(&lbuf, sys_local, 0, 1, 1200, 0), null, 0)).stored);

    // (2) A purge keeps only the header (§7.3.16.4 b), so its checksum cannot
    // match the body it was computed over. `draft-li-isis-error-lsp-processing`
    // §4 Fig 1: test Remaining Lifetime first, never checksum a purge.
    var obuf: [128]u8 = undefined;
    const other_id = idOf(sys_other, 0);
    _ = try db.insert(buildNamedLsp(&obuf, sys_other, 0, 4, 1000, "peer", false), 1, 0);
    var pbuf: [128]u8 = undefined;
    const purge = buildLspRawCsum(&pbuf, sys_other, 0, 5, 0, 0xBEEF); // stale checksum
    const pr = try db.insert(purge, 1, 1);
    try testing.expect(pr.stored);
    try testing.expect(db.get(other_id, 1).?.is_purge);
    // ...and the zero-checksum form some implementations send is equally fine.
    var p2: [128]u8 = undefined;
    _ = try db.insert(buildLspRawCsum(&p2, sys_other, 1, 5, 0, 0), 1, 1);

    // (3) §7.3.16.3 requires a transit IS to DECREMENT Remaining Lifetime
    // without recomputing the checksum — §7.3.11 excludes that field precisely
    // so it can. An LSP aged in flight must still be accepted.
    var abuf: [128]u8 = undefined;
    const fresh = buildNamedLsp(&abuf, sys_other, 2, 2, 1200, "aged", false);
    var aged: [128]u8 = undefined;
    @memcpy(aged[0..fresh.len], fresh);
    std.mem.writeInt(u16, aged[10..12], 137, .big); // as a neighbour would
    try testing.expect((try db.insert(aged[0..fresh.len], 1, 2)).stored);
    try testing.expectEqual(@as(u16, 137), db.get(idOf(sys_other, 2), 2).?.remaining_lifetime);
}

// ── regression: ISO 10589 §7.3.16.4 b) — a purge is retained as a HEADER ─────
//
// The purge is exempt from the §7.3.14.2 e) checksum discard above (its body is
// gone by definition, so the carried checksum cannot cover it). That exemption
// is sound only while the body really is discarded — otherwise "zero Remaining
// Lifetime" is a content-injection primitive that no checksum defends, which is
// exactly what the checksum work was meant to close. Audit BD-20.

/// Build a zero-lifetime LSP that nevertheless carries a full TLV body, with a
/// checksum of the sender's choosing: the wire image of a hostile purge. No
/// conformant IS emits this — §7.3.16.4 b) makes the purger send the header —
/// and an on-link party needs nothing but a socket to send it.
fn buildFatPurge(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, name: []const u8, csum: u16) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = 0,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num },
        .sequence_number = seq,
        .checksum = csum,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = true, .is_type = 1 },
    }) catch unreachable;
    isis.tlvs.addHostname(&b.tlvs, name) catch unreachable;
    return b.finish();
}

test "§7.3.16.4 b): a hostile purge's TLV body is not retained and not re-flooded" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    const id = idOf(sys_other, 0);

    // A conformant neighbour's LSP, whose content a reader can observe.
    var good: [128]u8 = undefined;
    _ = try db.insert(buildNamedLsp(&good, sys_other, 0, 4, 1000, "legit", false), 1, 0);
    try testing.expectEqualStrings("legit", hostnameOf(&db, id, 0).?);

    // The attack: a zero-lifetime PDU for the same LSP-ID at a higher sequence,
    // carrying a body and any checksum at all. It IS a valid purge (§7.3.16.1 —
    // a higher sequence wins) and is stored as one; what must not survive is the
    // body it smuggled.
    var evil: [128]u8 = undefined;
    const r = try db.insert(buildFatPurge(&evil, sys_other, 0, 5, "EVIL!", 0xBEEF), 1, 1);
    try testing.expect(r.stored);
    const v = db.get(id, 1).?;
    try testing.expect(v.is_purge);

    // §7.3.16.4 b): only the header is retained.
    try testing.expectEqual(@as(usize, isis.pdu.lsp_fixed_len), v.bytes.len);
    const stored = try isis.Lsp.decode(v.bytes);
    try testing.expectEqual(@as(u16, isis.pdu.lsp_fixed_len), stored.pdu_length);
    try testing.expectEqual(@as(usize, 0), stored.tlv_bytes.len);
    // Nothing a reader can observe — not the injected name, not the old one.
    try testing.expect(hostnameOf(&db, id, 1) == null);
    // The header fields the comparison and the CSNP summary still need survive.
    try testing.expectEqual(@as(u32, 5), stored.sequence_number);
    try testing.expectEqual(@as(u16, 0), stored.remaining_lifetime);

    // And the flooding layer re-transmits exactly those header octets: the
    // purge is SRM-flagged on every circuit, and what it hands out is a header.
    var it = db.srmIterator(0);
    const queued = it.next().?;
    try testing.expectEqual(@as(usize, isis.pdu.lsp_fixed_len), queued.bytes.len);
    try testing.expectEqual(@as(usize, 0), (try isis.Lsp.decode(queued.bytes)).tlv_bytes.len);

    // Truncation is per-copy, not sticky: the next legitimate LSP for this
    // LSP-ID is stored with its body intact and is observable again.
    var back: [128]u8 = undefined;
    try testing.expect((try db.insert(buildNamedLsp(&back, sys_other, 0, 6, 1000, "back", false), 1, 2)).stored);
    try testing.expect(!db.get(id, 2).?.is_purge);
    try testing.expectEqualStrings("back", hostnameOf(&db, id, 2).?);
}

test "§7.3.16.4 b): an LSP that AGES into the purge hold is flooded as a header, lifetime 0" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8, .zero_age_lifetime = 60 });
    defer db.deinit();
    const id = idOf(sys_other, 0);

    var buf: [128]u8 = undefined;
    _ = try db.insert(buildNamedLsp(&buf, sys_other, 0, 4, 100, "peer", false), 1, 0);
    try testing.expectEqualStrings("peer", hostnameOf(&db, id, 0).?);

    // At expiry the entry enters the purge hold with SRM set on every circuit
    // "to flood the purge" — so the bytes it hands out must BE a purge.
    try testing.expectEqual(@as(usize, 1), db.tick(100).entered_purge);
    const v = db.get(id, 100).?;
    try testing.expect(v.is_purge);
    const stored = try isis.Lsp.decode(v.bytes);
    try testing.expectEqual(@as(usize, 0), stored.tlv_bytes.len);
    // Remaining Lifetime 0 on the wire, not the 100 it was originated with —
    // otherwise the "purge" we flood is an ordinary LSP and the removal never
    // propagates.
    try testing.expectEqual(@as(u16, 0), stored.remaining_lifetime);
    try testing.expectEqual(@as(u16, isis.pdu.lsp_fixed_len), stored.pdu_length);

    // A neighbour receiving those exact octets records a purge, not a live LSP.
    var peer = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer peer.deinit();
    _ = try peer.insert(buildNamedLsp(&buf, sys_other, 0, 4, 100, "peer", false), 1, 0);
    _ = try peer.insert(v.bytes, 0, 1);
    try testing.expect(peer.get(id, 1).?.is_purge);
    try testing.expect(hostnameOf(&peer, id, 1) == null);
}

// ── regression: §7.3.16.4 b) retains the header's CHECKSUM verbatim ──────────
//
// `stampPurgeHeader` rewrites exactly two fields (PDU Length, Remaining
// Lifetime). Leaving the Checksum field alone is a decision, not an oversight:
// note 36 has the check "succeed even though the data portion is not present",
// i.e. the field survives a purge and is simply not re-verified. Nothing pinned
// it — the audit zeroed the checksum in `dupeRetainedBytes` and all three
// dependent suites stayed green (BD-25). The consequence a zeroing would have is
// not local: the retained octets are what `srmIterator` re-floods, and a peer
// holding the same purge compares the incoming checksum against its own under
// §7.3.16.1 — with the stored copy a purge, clause (d) does not apply, so an
// altered checksum makes an identical purge compare `.older` and the peer
// re-sends its copy back at us. A purge ping-pong, from one zeroed field.

test "§7.3.16.4 b): the retained purge header keeps its Checksum verbatim, on both paths" {
    const id = idOf(sys_other, 0);

    // (1) Receive path (`dupeRetainedBytes`): a purge arriving with a body is
    // truncated to its header, and that header carries the checksum it arrived
    // with — the same value the entry reports to `summarise`.
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var good: [128]u8 = undefined;
    _ = try db.insert(buildNamedLsp(&good, sys_other, 0, 4, 1000, "legit", false), 1, 0);
    var evil: [128]u8 = undefined;
    _ = try db.insert(buildFatPurge(&evil, sys_other, 0, 5, "EVIL!", 0xBEEF), 1, 1);
    const v = db.get(id, 1).?;
    try testing.expect(v.is_purge);
    try testing.expectEqual(@as(u16, 0xBEEF), (try isis.Lsp.decode(v.bytes)).checksum);
    // The flooded octets and the CSNP summary must agree, or a neighbour's SNP
    // reconciliation sees a difference that does not exist.
    try testing.expectEqual(v.checksum, (try isis.Lsp.decode(v.bytes)).checksum);

    // (2) Aging path (`retainHeaderOnly`): an LSP that ages into the purge hold
    // keeps the checksum of the copy that expired.
    var aged = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8, .zero_age_lifetime = 60 });
    defer aged.deinit();
    var abuf: [128]u8 = undefined;
    const live = buildNamedLsp(&abuf, sys_other, 0, 4, 100, "peer", false);
    const live_csum = (try isis.Lsp.decode(live)).checksum;
    try testing.expect(live_csum != 0); // §7.3.11 never yields zero (RFC 3719 §7)
    _ = try aged.insert(live, 1, 0);
    try testing.expectEqual(@as(usize, 1), aged.tick(100).entered_purge);
    try testing.expectEqual(live_csum, (try isis.Lsp.decode(aged.get(id, 100).?.bytes)).checksum);

    // (3) The consequence, end to end: a peer that already holds this purge must
    // recognise our re-flooded header as IDENTICAL (§7.3.16.1(a)) and stay
    // quiet. If the retained header's checksum were rewritten, clause (a) would
    // miss, clause (d) would not fire (the stored copy is a purge), and the peer
    // would grade it `.older` and re-send its copy back out the arrival circuit.
    var peer = Lsdb.init(testing.allocator, testCfg());
    defer peer.deinit();
    var pgood: [128]u8 = undefined;
    _ = try peer.insert(buildNamedLsp(&pgood, sys_other, 0, 4, 1000, "legit", false), 1, 0);
    var pevil: [128]u8 = undefined;
    _ = try peer.insert(buildFatPurge(&pevil, sys_other, 0, 5, "EVIL!", 0xBEEF), 1, 1);
    var i: u8 = 0;
    while (i < 4) : (i += 1) peer.clearSrm(id, i); // that flood already happened
    const r = try peer.insert(v.bytes, 0, 2);
    try testing.expectEqual(Ordering.same, r.ordering);
    try testing.expect(!peer.srmSet(id).?.isSet(0));
}

test "srmIterator walks the LSPs queued for one circuit" {
    var db = Lsdb.init(testing.allocator, testCfg());
    defer db.deinit();
    var buf: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 1000), null, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 1, 1, 1000), null, 0);
    var it = db.srmIterator(0);
    var n: usize = 0;
    while (it.next()) |item| {
        try testing.expect(item.bytes.len > 0);
        n += 1;
    }
    try testing.expectEqual(@as(usize, 2), n);
}
