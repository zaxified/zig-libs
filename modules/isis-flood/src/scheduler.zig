// SPDX-License-Identifier: MIT

//! The IS-IS flooding transmit scheduler (ISO/IEC 10589 §7.3.15 + §7.3.16.3/.4)
//! for point-to-point circuits: turn the `isis-lsdb` per-interface SRM (flood an
//! LSP) and SSN (acknowledge/request via a PSNP) flag sets into the concrete,
//! ordered PDUs to transmit, with correct pacing, and update the LSDB flags as it
//! goes.
//!
//! Pure and time-injected, exactly like the sibling `isis-adj` FSM and the
//! `isis-lsdb` store: the scheduler owns no clock, no timer, and no socket. The
//! caller supplies a monotonic `now`, the set of interfaces that currently hold
//! an Up adjacency (derived from `isis-adj`, an INPUT here — this module does not
//! depend on `isis-adj`), a caller-owned `out` slice for the effects and a
//! caller-owned `scratch` byte buffer to serialise SNP PDUs into, and calls
//! `poll`. It then physically sends the returned effects. Determinism: the same
//! `(lsdb state, now sequence, up set)` yields the same effects.
//!
//! ## The retransmit / pacing model (P2P) — where SRM is *actually* cleared
//! On a point-to-point circuit an LSP is flooded and then **retransmitted** every
//! `minimum_lsp_transmission_interval` (ISO `minimumLSPTransmissionInterval`,
//! default 5) until the neighbour **acknowledges** it with a PSNP. Sending the LSP
//! does **not** clear its SRM flag — the `isis-lsdb` clears SRM only on the ack
//! path (`reconcilePsnp`, whose per-entry `same` result unsets SRM on the circuit)
//! or on a superseding update. So this scheduler never clears SRM itself; it only
//! tracks a per-`(lsp, iface)` **last-sent time** and re-emits an SRM-flagged LSP
//! once `now - last_sent >= interval`. (The broadcast/LAN rule — SRM cleared on
//! send, the DIS's CSNP doing the sync — is deliberately out of scope; see
//! `../SPEC.md`.)
//!
//! ## The CSNP series (ISO/IEC 10589 §7.3.15.2) — a range is a *claim*
//! A CSNP asserts that it lists **every** LSP the sender holds in the inclusive
//! `[Start, End]` range it carries; a receiver that holds an in-range LSP the
//! CSNP omitted concludes the sender lacks it and floods it back. So a summary
//! that does not fit one buffer may never round its last range up to
//! `FF…FF` — it advertises only the sub-range it actually enumerated, sets
//! `truncated`, and resumes from `End + 1` on the next `poll` (per circuit).
//! The cadence timer is re-armed only when a series reaches the top of the
//! space. See `emitCsnp`.
//!
//! The last-sent map is bounded by the number of currently-SRM-flagged
//! `(lsp, iface)` pairs — itself bounded by the LSDB's own capacity — because each
//! `poll` first prunes entries whose SRM is no longer set (acked, cleared, or the
//! LSP removed). Nothing grows without limit.

const std = @import("std");
const isis = @import("isis");
const lsdb_mod = @import("isis-lsdb");
const snp = @import("snp.zig");

/// Caller-supplied monotonic tick — same abstract unit as `isis-lsdb`/`isis-adj`.
/// The intervals below are in this same unit.
pub const Time = lsdb_mod.Time;
pub const LspId = lsdb_mod.LspId;
pub const InterfaceSet = lsdb_mod.InterfaceSet;
pub const Lsdb = lsdb_mod.Lsdb;
pub const LspEntry = isis.tlvs.LspEntry;

/// The comptime ceiling on circuits, inherited from `isis-lsdb` (the flag bitset
/// width). An interface index is a `u8 < max_interfaces`.
pub const max_interfaces = lsdb_mod.max_interfaces;

/// ISO 10589 `minimumLSPTransmissionInterval` (§7.3.16.3/.4): the minimum gap
/// between retransmissions of one LSP on a circuit. Default 5 (seconds, in the
/// reference unit).
pub const default_min_lsp_transmission_interval: Time = 5;

/// ISO 10589 `completeSNPInterval` (§7.3.15.2): the periodic CSNP cadence on a
/// circuit. Default 10 (seconds).
pub const default_complete_snp_interval: Time = 10;

/// Default per-PDU entry cap = one #9 TLV (see `snp.max_entries_per_pdu`).
pub const default_lsp_entries_per_pdu: usize = snp.max_entries_per_pdu;

/// The comptime ceiling on entries collected for one interface's PSNP/CSNP
/// summary in a single `poll` (a stack buffer, no allocation). A DB larger than
/// this is summarised in **several** polls for that circuit: each poll advertises
/// a narrower `[start, end]` window that it can enumerate completely, and the
/// next poll resumes at the following LSP-ID (see `emitCsnp` and `../SPEC.md`).
/// A CSNP never claims a range whose contents it did not list.
pub const max_summary_entries: usize = 256;

/// The kind of PDU an `Effect` tells the caller to transmit.
pub const PduKind = enum { lsp, psnp, csnp };

/// One thing to physically send: the circuit, the PDU kind, and the bytes. For a
/// `.lsp` the bytes point into the LSDB's owned copy (zero-copy); for `.psnp` /
/// `.csnp` they point into the caller's `scratch` buffer. Both are valid until
/// the next `poll` or the next mutation of the LSDB — read/send them before then.
pub const Effect = struct {
    iface: u8,
    kind: PduKind,
    bytes: []const u8,
};

/// The outcome of a `poll`.
pub const PollResult = struct {
    /// The ordered effects to transmit — a prefix of the caller's `out` slice.
    effects: []const Effect,
    /// The absolute time (in `now` units) at which the caller should next `poll`:
    /// the minimum over the next paced LSP retransmit and the next periodic CSNP.
    /// `null` when there is nothing pending (no Up interface). When `truncated`,
    /// this is `now` (poll again immediately to make progress).
    next_wakeup: ?Time,
    /// The `out` slice, the `scratch` buffer, or a per-interface burst budget
    /// filled before all pending work was emitted — or a CSNP series that has
    /// not yet advertised the top of the LSP-ID space (§7.3.15.2, see the file
    /// header). The caller should send what it got and `poll` again immediately
    /// (`next_wakeup == now`).
    truncated: bool,
};

/// Static per-scheduler configuration. Immutable for the life of the `Scheduler`.
pub const Config = struct {
    /// Our 6-octet system id — stamped into the source-id of the CSNP/PSNP we
    /// generate (system-id ++ a zero circuit-id octet).
    local_system_id: [6]u8,
    /// Emit L2 (else L1) CSNP/PSNP PDU types. One `Scheduler` serves one level.
    is_l2: bool = false,
    /// `minimumLSPTransmissionInterval`: the per-`(lsp, iface)` retransmit gate.
    min_lsp_transmission_interval: Time = default_min_lsp_transmission_interval,
    /// `completeSNPInterval`: the periodic CSNP cadence per circuit.
    complete_snp_interval: Time = default_complete_snp_interval,
    /// Entries packed into each generated PSNP/CSNP (`1..=snp.max_entries_per_pdu`).
    /// Set small in tests to force chunking; a real deployment leaves it at the
    /// one-TLV maximum.
    lsp_entries_per_pdu: usize = default_lsp_entries_per_pdu,
    /// The maximum LSP transmit effects emitted for one circuit in one `poll` — a
    /// simple burst/output bound standing in for ISO's fine-grained inter-LSP
    /// transmit pacing (see `../SPEC.md §pacing`). Hitting it sets `truncated`.
    max_lsps_per_iface_per_poll: usize = 64,
    /// Pace LSP retransmission by `min_lsp_transmission_interval`. `false` disables
    /// the last-sent gate (re-send an SRM-flagged LSP on every poll) — this is the
    /// module's **positive control**: a test flips it off to prove the pacing gate
    /// has teeth (without it the pace-boundary test would go RED).
    pace_lsp_retransmit: bool = true,
};

/// The per-`(lsp, iface)` key of the last-sent map.
const Key = struct { id: LspId, iface: u8 };

/// The point-to-point flooding transmit scheduler. Single-owner: one caller/loop
/// drives it; it holds no shared state and takes a lock nowhere. Allocator-backed
/// only for the bounded last-sent map (see the file header for the bound).
pub const Scheduler = struct {
    alloc: std.mem.Allocator,
    cfg: Config,
    /// Last transmit time per SRM-flagged `(lsp, iface)`. Pruned every `poll`.
    last_sent: std.AutoHashMapUnmanaged(Key, Time) = .empty,
    /// Reusable victim scratch for the prune sweep (avoids per-poll allocation
    /// after warmup; safe removal without invalidating the map iterator).
    victims: std.ArrayListUnmanaged(Key) = .empty,
    /// Absolute next-CSNP time per circuit, and whether it has been primed.
    csnp_next: [max_interfaces]Time = @splat(0),
    csnp_primed: [max_interfaces]bool = @splat(false),
    /// Resume point of an in-progress CSNP series per circuit: the LSP-ID the
    /// next CSNP's advertised range must start at. `min_lsp_id` means no series
    /// is in progress (the next cadence tick starts a fresh one). A database
    /// larger than one summary buffer is advertised across several polls; until
    /// the series reaches `max_lsp_id` the cadence timer is not re-armed.
    csnp_cursor: [max_interfaces]LspId = @splat(snp.min_lsp_id),

    pub fn init(alloc: std.mem.Allocator, cfg: Config) Scheduler {
        std.debug.assert(cfg.lsp_entries_per_pdu >= 1 and cfg.lsp_entries_per_pdu <= snp.max_entries_per_pdu);
        return .{ .alloc = alloc, .cfg = cfg };
    }

    pub fn deinit(self: *Scheduler) void {
        self.last_sent.deinit(self.alloc);
        self.victims.deinit(self.alloc);
    }

    fn sourceId(self: *const Scheduler) [7]u8 {
        var s: [7]u8 = undefined;
        @memcpy(s[0..6], &self.cfg.local_system_id);
        s[6] = 0; // circuit-id octet (P2P: zero)
        return s;
    }

    /// Drop last-sent entries whose SRM is no longer set — the map's bound. Safe:
    /// collect victims first (read-only walk), then remove.
    fn prune(self: *Scheduler, db: *Lsdb) void {
        self.victims.clearRetainingCapacity();
        var it = self.last_sent.iterator();
        while (it.next()) |e| {
            const set = db.srmSet(e.key_ptr.id);
            const still = set != null and set.?.isSet(e.key_ptr.iface);
            if (!still) self.victims.append(self.alloc, e.key_ptr.*) catch break;
        }
        for (self.victims.items) |k| _ = self.last_sent.remove(k);
    }

    /// One scheduling pass. Emits (into `out`) the LSP/PSNP/CSNP effects due at
    /// `now` for every interface in `up`, updating the LSDB flags (clearing SSN as
    /// PSNPs are produced) and the internal pacing/CSNP timers. Returns the effect
    /// prefix, the next-wakeup deadline, and whether output was truncated.
    ///
    /// `scratch` holds the serialised PSNP/CSNP bytes; size it for the SNP PDUs of
    /// one poll (a few hundred bytes per PDU). `out` bounds the effect count.
    pub fn poll(self: *Scheduler, now: Time, up: InterfaceSet, db: *Lsdb, out: []Effect, scratch: []u8) PollResult {
        self.prune(db);

        var n_eff: usize = 0;
        var scratch_used: usize = 0;
        var truncated = false;
        var wake: ?Time = null;

        var iface: u8 = 0;
        outer: while (iface < max_interfaces) : (iface += 1) {
            if (!up.isSet(iface)) continue;

            if (!self.csnp_primed[iface]) {
                self.csnp_next[iface] = now; // fire an initial CSNP on first sight
                self.csnp_primed[iface] = true;
            }

            // ── 1. LSP transmit + retransmit pacing (SRM) ───────────────────────
            var sent_this_iface: usize = 0;
            var sit = db.srmIterator(iface);
            while (sit.next()) |item| {
                const key: Key = .{ .id = item.lsp_id, .iface = iface };
                const last = self.last_sent.get(key);
                const eligible = !self.cfg.pace_lsp_retransmit or last == null or
                    now >= last.? +| self.cfg.min_lsp_transmission_interval;
                if (eligible) {
                    if (sent_this_iface >= self.cfg.max_lsps_per_iface_per_poll) {
                        truncated = true;
                        wake = minOpt(wake, now);
                        break; // per-iface burst cap: stop LSPs on this circuit
                    }
                    if (n_eff >= out.len) {
                        truncated = true;
                        wake = minOpt(wake, now);
                        break :outer;
                    }
                    out[n_eff] = .{ .iface = iface, .kind = .lsp, .bytes = item.bytes };
                    n_eff += 1;
                    sent_this_iface += 1;
                    // Best-effort pacing record; on OOM we simply may re-send next
                    // poll (bounded by out.len), never a crash.
                    self.last_sent.put(self.alloc, key, now) catch {};
                    // P2P: SRM stays set — cleared by the ack path in isis-lsdb.
                    wake = minOpt(wake, now +| self.cfg.min_lsp_transmission_interval);
                } else {
                    wake = minOpt(wake, last.? +| self.cfg.min_lsp_transmission_interval);
                }
            }

            // ── 2. PSNP acks / requests (SSN) — chunked ─────────────────────────
            if (self.emitPsnp(now, iface, db, out, &n_eff, scratch, &scratch_used)) {
                truncated = true;
                wake = minOpt(wake, now);
                break :outer;
            }

            // ── 3. Periodic CSNP (§7.3.15.2) ────────────────────────────────────
            if (now >= self.csnp_next[iface]) {
                const r = self.emitCsnp(now, iface, db, out, &n_eff, scratch, &scratch_used);
                if (r.more) {
                    // The series has not yet reached max_lsp_id: the caller must
                    // poll again immediately so the rest of the database is
                    // advertised. The cadence timer stays un-armed (it is still
                    // in the past) until the series completes.
                    truncated = true;
                    wake = minOpt(wake, now);
                } else {
                    self.csnp_next[iface] = now +| self.cfg.complete_snp_interval;
                }
                if (r.out_of_room) {
                    truncated = true;
                    wake = minOpt(wake, now);
                    break :outer;
                }
            }
            wake = minOpt(wake, self.csnp_next[iface]);
        }

        return .{
            .effects = out[0..n_eff],
            .next_wakeup = if (truncated) now else wake,
            .truncated = truncated,
        };
    }

    /// Emit the PSNP PDUs for one circuit: drain the SSN-flagged LSPs, chunked,
    /// clearing SSN as each PDU is produced. Returns `true` iff it ran out of
    /// `out` room or `scratch` space (truncated).
    fn emitPsnp(
        self: *Scheduler,
        now: Time,
        iface: u8,
        db: *Lsdb,
        out: []Effect,
        n_eff: *usize,
        scratch: []u8,
        scratch_used: *usize,
    ) bool {
        var entries: [max_summary_entries]LspEntry = undefined;
        var m: usize = 0;

        // `db.get(item.lsp_id, now) orelse continue` below can only skip an
        // entry `ssnIterator` cannot re-resolve if `Lsdb` ever yields a
        // flagged id it does not also hold — audited as W2 `isis-flood` F4 on
        // the theory that this could strand the SSN flag forever. Traced
        // against `Lsdb` (2026-08-08): `FlagIterator.next` walks the SAME
        // live `self.map` that `get` looks up (`store.zig` `ssnIterator` /
        // `get`), so any id it yields is by construction present; the only
        // removal path (`Lsdb.tick`'s `self.map.remove`, `store.zig:634`)
        // deletes the entry from every future iteration too, so a removed
        // id is never yielded to begin with. There is no interleaving inside
        // one synchronous `emitPsnp` call (single-owner, no concurrency) that
        // could desync the two. The `orelse continue` is therefore
        // unreachable dead code under `Lsdb`'s current invariants, not a live
        // stranded-flag bug — left as defensive fail-safety rather than
        // `unreachable`, since that invariant lives in a different module.
        var qit = db.ssnIterator(iface);
        while (qit.next()) |item| {
            if (m >= entries.len) break;
            const v = db.get(item.lsp_id, now) orelse continue;
            entries[m] = .{
                .remaining_lifetime = v.remaining_lifetime,
                .lsp_id = item.lsp_id,
                .sequence_number = v.sequence_number,
                .checksum = v.checksum,
            };
            m += 1;
        }
        if (m == 0) return false; // nothing to ack

        snp.sortEntries(entries[0..m]);

        // `Config.lsp_entries_per_pdu` is caller-supplied and `init`'s
        // `std.debug.assert` is the only thing that keeps it `>= 1` — and
        // that assert is compiled OUT in ReleaseFast. Without this clamp a
        // caller-constructed `Config{ .lsp_entries_per_pdu = 0 }` makes `j ==
        // i` forever (see `emitCsnp`'s sibling clamp for the sharper failure
        // mode this exact gap causes there). See CHANGELOG.
        const per = @max(@as(usize, 1), self.cfg.lsp_entries_per_pdu);
        const src = self.sourceId();
        var i: usize = 0;
        while (i < m) {
            const j = @min(i + per, m);
            if (n_eff.* >= out.len) return true;
            const built = snp.buildPsnp(scratch[scratch_used.*..], src, self.cfg.is_l2, entries[i..j]) catch return true;

            out[n_eff.*] = .{ .iface = iface, .kind = .psnp, .bytes = built };
            n_eff.* += 1;
            scratch_used.* += built.len;

            // A PSNP has now acknowledged/requested these LSPs → clear SSN.
            for (entries[i..j]) |e| db.clearSsn(e.lsp_id, iface);
            i = j;
        }
        return false;
    }

    /// The outcome of one circuit's CSNP burst.
    const CsnpProgress = struct {
        /// `out`/`scratch` filled before the window's PDUs were all emitted.
        out_of_room: bool,
        /// The series has not yet advertised up to `max_lsp_id`; the caller must
        /// poll again (the cursor holds the resume point).
        more: bool,
    };

    /// Emit the CSNP PDUs for one circuit.
    ///
    /// **ISO/IEC 10589 §7.3.15.2**: a CSNP is a *complete* summary of the
    /// inclusive `[Start LSP ID, End LSP ID]` range it advertises. A receiver
    /// that holds an LSP inside that range which the CSNP did **not** list
    /// concludes the sender lacks it and floods it back (sets SRM); the sibling
    /// `isis-lsdb.reconcileCsnp` implements exactly that receive rule. So the
    /// advertised range is a *claim* about coverage, and this function may only
    /// claim what it actually enumerated.
    ///
    /// The summary buffer is finite (`max_summary_entries`) and `isis-lsdb`'s
    /// `summarise` fills it in hash order, so "the first N of the range" is not
    /// even a well-defined prefix. Therefore: ask for one more entry than we can
    /// advertise, and if the window is over-full **narrow the window** (halve it
    /// by LSP-ID) and re-count until what came back is provably the *whole*
    /// content of `[start, end]`. That window is then advertised honestly, the
    /// cursor moves to `end + 1`, and the rest of the database follows on the
    /// next poll(s). The previous behaviour — emit the first 256 entries and
    /// still stamp `max_lsp_id` on the last chunk — made every omitted LSP look
    /// absent to the peer, which re-flooded them on every cadence tick forever.
    fn emitCsnp(
        self: *Scheduler,
        now: Time,
        iface: u8,
        db: *Lsdb,
        out: []Effect,
        n_eff: *usize,
        scratch: []u8,
        scratch_used: *usize,
    ) CsnpProgress {
        // One slot more than we will ever advertise: a return of
        // `max_summary_entries + 1` proves the window holds more than we can
        // enumerate; anything less proves the window is complete.
        var entries: [max_summary_entries + 1]LspEntry = undefined;

        const start = self.csnp_cursor[iface];
        var end = snp.max_lsp_id;
        var m = db.summarise(&entries, start, end, now);
        if (m > max_summary_entries) {
            // Over-full: we cannot enumerate this window, so we must not claim
            // it. Binary-search the LARGEST end whose window we can enumerate
            // (largest, not merely any, so a sparse ID space does not cost one
            // poll per halving). `good` is complete by construction — a single
            // LSP-ID holds at most one entry — and `bad` is over-full; each step
            // strictly shrinks the gap, so this ends after at most 64 rounds.
            var good = start;
            var bad = end;
            while (true) {
                const mid = snp.midpoint(good, bad);
                if (std.mem.eql(u8, &mid, &good)) break; // bad == good + 1
                if (db.summarise(&entries, start, mid, now) > max_summary_entries) bad = mid else good = mid;
            }
            end = good;
            m = db.summarise(&entries, start, end, now); // refill for the chosen window
        }

        snp.sortEntries(entries[0..m]);

        // See the identical clamp + comment in `emitPsnp`. Here the gap is
        // sharper than a stalled loop: with `per == 0` and `m > 0`, `j ==
        // i == 0` on the first pass, `j >= m` is false, and `chunk_end =
        // entries[j - 1]` underflows `j - 1` (`usize` 0 - 1). In
        // Debug/ReleaseSafe that is a caught "integer overflow" panic; in
        // ReleaseFast — where safety checks (and `init`'s guarding assert)
        // are BOTH compiled out — it is an out-of-bounds read at an
        // address `usize.max` slots past `entries`, undefined behaviour on
        // a public function driven entirely by caller-supplied `Config`.
        const per = @max(@as(usize, 1), self.cfg.lsp_entries_per_pdu);
        const src = self.sourceId();
        var i: usize = 0;
        var advertised_to: ?LspId = null;
        // A CSNP with no entries still emits exactly one PDU covering its window.
        var first = true;
        while (i < m or first) {
            first = false;
            const j = @min(i + per, m);
            if (n_eff.* >= out.len) return self.csnpDone(iface, advertised_to, true);

            // The first chunk starts at the cursor; each later chunk starts one
            // past the previous chunk's last entry, so the chunks tile the
            // window with no gap and no overlap. The final chunk ends at the
            // window's proven end — never at a value we did not enumerate.
            const chunk_start = if (i == 0) start else snp.successor(entries[i - 1].lsp_id);
            const chunk_end = if (j >= m) end else entries[j - 1].lsp_id;
            const built = snp.buildCsnp(scratch[scratch_used.*..], src, self.cfg.is_l2, chunk_start, chunk_end, entries[i..j]) catch
                return self.csnpDone(iface, advertised_to, true);

            out[n_eff.*] = .{ .iface = iface, .kind = .csnp, .bytes = built };
            n_eff.* += 1;
            scratch_used.* += built.len;
            advertised_to = chunk_end;
            i = j;
        }
        return self.csnpDone(iface, advertised_to, false);
    }

    /// Park the CSNP series cursor after a burst: `advertised_to` is the highest
    /// LSP-ID actually covered by an emitted PDU (null if none was emitted). The
    /// series is complete only once it has covered `max_lsp_id`.
    fn csnpDone(self: *Scheduler, iface: u8, advertised_to: ?LspId, out_of_room: bool) CsnpProgress {
        const to = advertised_to orelse
            return .{ .out_of_room = out_of_room, .more = true }; // cursor unchanged: retry
        if (std.mem.eql(u8, &to, &snp.max_lsp_id)) {
            self.csnp_cursor[iface] = snp.min_lsp_id; // series complete
            return .{ .out_of_room = out_of_room, .more = false };
        }
        self.csnp_cursor[iface] = snp.successor(to);
        return .{ .out_of_room = out_of_room, .more = true };
    }
};

fn minOpt(a: ?Time, b: Time) ?Time {
    return if (a) |x| @min(x, b) else b;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const sys_local: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_other: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };

fn idOf(sys: [6]u8, lsp_num: u8) LspId {
    return .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num };
}

/// Build an LSP the way a conformant originator does: ISO 10589 §7.3.11 makes
/// computing the Checksum the generating IS's job, so these fixtures stamp it.
/// They used to pass a `csum` argument of hand-picked filler (0x1111, 0x2222,
/// 0x1000+n) — values Wireshark grades "Bad" — which every test below then fed
/// to `Lsdb.insert` on an *arrival* interface. That is a receive, so ISO 10589
/// §7.3.14.2 e) discards it; the fixtures were modelling a PDU no IS-IS
/// implementation would accept. No test here asserts a particular checksum
/// *value*, so nothing is lost by computing it — the one place that needed the
/// value to match (the PSNP ack below) now derives it from the LSP itself.
fn buildLsp(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16) []const u8 {
    return buildLspId(buf, idOf(sys, lsp_num), seq, life);
}

/// Build an LSP with an explicit 8-octet LSP-ID (the `sys ++ pseudonode ++
/// fragment` split matters when a test needs more than 256 distinct ids).
fn buildLspId(buf: []u8, id: LspId, seq: u32, life: u16) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = id,
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finishStamped();
}

/// The `n`-th distinct LSP-ID of `sys`: pseudonode byte + fragment byte together
/// give 65536 ids, so a test can exceed `max_summary_entries`.
fn idNth(sys: [6]u8, n: u16) LspId {
    return .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], @intCast(n >> 8), @truncate(n) };
}

fn oneUp(iface: u8) InterfaceSet {
    var s = InterfaceSet.initEmpty();
    s.set(iface);
    return s;
}

/// The circuit the tests below receive another system's LSPs on.
///
/// Six fixtures used to insert `sys_other`'s LSP with `arrival_iface = null` —
/// the **local-origination** path — purely because that arms SRM on every
/// circuit in one call. No such state exists on a real box: an LSP whose LSP-ID
/// does not carry our system-id always arrived on some circuit, and arriving is
/// what the flooding matrix is defined over. The shortcut also hid the ISO
/// §7.3.15 split-horizon rule (SRM on every circuit *except* the arrival one)
/// behind a state where there is no arrival circuit to except.
///
/// Receiving on circuit 1 while every test polls `oneUp(0)` keeps every expected
/// count identical and makes the SRM set the real one: `{0}` rather than
/// `{0, 1}`. `arrivalDb` asserts exactly that, so the difference cannot go
/// unnoticed if the matrix changes.
const arrival: u8 = 1;

/// A 2-circuit store holding `sys_other`'s LSP as **received on `arrival`**,
/// with the resulting flag set asserted: SRM on circuit 0 only (split horizon),
/// SSN on the arrival circuit only (the P2P ack, which no test below polls for
/// since none brings circuit 1 Up).
fn arrivalDb(db: *Lsdb, wire: []const u8, id: LspId) !void {
    _ = try db.insert(wire, arrival, 0);
    const srm = db.srmSet(id).?;
    try testing.expect(srm.isSet(0) and !srm.isSet(arrival));
    try testing.expectEqual(@as(usize, 1), srm.count());
    try testing.expect(db.ssnSet(id).?.isSet(arrival));
}

fn countKind(effects: []const Effect, kind: PduKind) usize {
    var n: usize = 0;
    for (effects) |e| if (e.kind == kind) {
        n += 1;
    };
    return n;
}

fn testCfg() Config {
    return .{ .local_system_id = sys_local };
}

test "SRM drain + pace: one send, no re-send within the interval, re-send after" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .min_lsp_transmission_interval = 5 });
    defer sched.deinit();

    var lbuf: [128]u8 = undefined;
    try arrivalDb(&db, buildLsp(&lbuf, sys_other, 0, 1, 1000), idOf(sys_other, 0));
    const up = oneUp(0);

    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;

    // First poll: the LSP is flooded on iface 0.
    const r0 = sched.poll(0, up, &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 1), countKind(r0.effects, .lsp));

    // Immediate re-poll within the interval: no re-send (SRM still set = P2P).
    const r1 = sched.poll(1, up, &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 0), countKind(r1.effects, .lsp));

    // Just before the boundary (t=4 < 0+5): still no re-send.
    try testing.expectEqual(@as(usize, 0), countKind(sched.poll(4, up, &db, &out, &scratch).effects, .lsp));

    // At the boundary (t=5 >= 0+5): retransmit (SRM never cleared by us on P2P).
    const r5 = sched.poll(5, up, &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 1), countKind(r5.effects, .lsp));
}

test "positive control: unpaced re-sends every poll; the pace-boundary test needs the gate" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var lbuf: [128]u8 = undefined;
    try arrivalDb(&db, buildLsp(&lbuf, sys_other, 0, 1, 1000), idOf(sys_other, 0));
    const up = oneUp(0);
    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;

    // Paced scheduler: second poll within the interval emits nothing.
    var paced = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .min_lsp_transmission_interval = 5, .pace_lsp_retransmit = true });
    defer paced.deinit();
    _ = paced.poll(0, up, &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 0), countKind(paced.poll(1, up, &db, &out, &scratch).effects, .lsp));

    // Unpaced scheduler (gate disabled): second poll re-sends immediately — this
    // is what the pacing gate prevents. If pacing regressed to this, the boundary
    // test above would go RED.
    var unpaced = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .min_lsp_transmission_interval = 5, .pace_lsp_retransmit = false });
    defer unpaced.deinit();
    _ = unpaced.poll(0, up, &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 1), countKind(unpaced.poll(1, up, &db, &out, &scratch).effects, .lsp));
}

test "ack clears retransmit: a PSNP that reconciles SRM stops the re-send" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .min_lsp_transmission_interval = 5 });
    defer sched.deinit();

    var lbuf: [128]u8 = undefined;
    const lsp = buildLsp(&lbuf, sys_other, 0, 1, 1000);
    const id = idOf(sys_other, 0);
    try arrivalDb(&db, lsp, id);
    const up = oneUp(0);
    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;

    _ = sched.poll(0, up, &db, &out, &scratch); // flooded on iface 0, SRM still set
    try testing.expect(db.srmSet(id).?.isSet(0));

    // The neighbour ACKs with a PSNP echoing the same (seq, life, csum) → isis-lsdb
    // clears SRM on the ack path (per-entry `same` ⇒ unset SRM).
    var pbuf: [128]u8 = undefined;
    // The checksum is the one the LSP actually carries (§7.3.11), not a literal:
    // `same` requires all three of (seq, life, csum) to match, so a stale literal
    // here would make the ack a no-op and quietly disarm this test.
    const ack = [_]LspEntry{.{
        .remaining_lifetime = 1000,
        .lsp_id = id,
        .sequence_number = 1,
        .checksum = try isis.pdu.computeLspChecksum(lsp),
    }};
    const pw = try snp.buildPsnp(&pbuf, .{ 0, 0, 0, 0, 0, 0xB, 0 }, false, &ack);
    db.reconcilePsnp(try isis.Psnp.decode(pw), 0, 1);
    try testing.expect(!db.srmSet(id).?.isSet(0)); // acked

    // After the interval, no re-send — the ack cleared SRM.
    try testing.expectEqual(@as(usize, 0), countKind(sched.poll(10, up, &db, &out, &scratch).effects, .lsp));
}

test "SSN -> PSNP: exactly the flagged LSPs, decoded, and SSN cleared" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, testCfg());
    defer sched.deinit();

    // Two LSPs arrive on P2P iface 0 → SSN set on iface 0 for both (ack pending).
    var b0: [128]u8 = undefined;
    var b1: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&b0, sys_other, 0, 3, 900), 0, 0);
    _ = try db.insert(buildLsp(&b1, sys_other, 1, 7, 800), 0, 0);
    const id0 = idOf(sys_other, 0);
    const id1 = idOf(sys_other, 1);
    try testing.expect(db.ssnSet(id0).?.isSet(0) and db.ssnSet(id1).?.isSet(0));

    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;
    const r = sched.poll(0, oneUp(0), &db, &out, &scratch);

    // One PSNP on iface 0 carrying exactly the two entries.
    try testing.expectEqual(@as(usize, 1), countKind(r.effects, .psnp));
    var seen0 = false;
    var seen1 = false;
    for (r.effects) |e| {
        if (e.kind != .psnp) continue;
        const ps = try isis.Psnp.decode(e.bytes);
        var it = isis.tlvs.LspEntryIterator.init((try isis.tlv.findFirst(ps.tlv_bytes, isis.tlvs.code.lsp_entries)).?);
        while (try it.next()) |entry| {
            if (std.mem.eql(u8, &entry.lsp_id, &id0)) {
                seen0 = true;
                try testing.expectEqual(@as(u32, 3), entry.sequence_number);
                try testing.expectEqual(@as(u16, 900), entry.remaining_lifetime);
            }
            if (std.mem.eql(u8, &entry.lsp_id, &id1)) {
                seen1 = true;
                try testing.expectEqual(@as(u32, 7), entry.sequence_number);
            }
        }
    }
    try testing.expect(seen0 and seen1);
    // SSN cleared on iface 0 (the ack has been produced).
    try testing.expect(!db.ssnSet(id0).?.isSet(0));
    try testing.expect(!db.ssnSet(id1).?.isSet(0));
}

test "periodic CSNP: emitted on cadence, not every poll, summarising the DB" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 16 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .complete_snp_interval = 10 });
    defer sched.deinit();

    var buf: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 4, 900), 0, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 1, 6, 900), 0, 0);
    // Clear SRM so only the CSNP is under test on iface 0.
    for ([_]u8{ 0, 1 }) |n| db.clearSrm(idOf(sys_other, n), 0);
    // These arrived on iface 0 → SSN on iface 0; clear it too.
    for ([_]u8{ 0, 1 }) |n| db.clearSsn(idOf(sys_other, n), 0);

    const up = oneUp(0);
    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;

    // t=0: initial CSNP fires; it summarises both LSPs.
    const r0 = sched.poll(0, up, &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 1), countKind(r0.effects, .csnp));
    var seen0 = false;
    var seen1 = false;
    for (r0.effects) |e| {
        if (e.kind != .csnp) continue;
        const cs = try isis.Csnp.decode(e.bytes);
        var it = isis.tlvs.LspEntryIterator.init((try isis.tlv.findFirst(cs.tlv_bytes, isis.tlvs.code.lsp_entries)).?);
        while (try it.next()) |entry| {
            if (entry.lsp_id[7] == 0) seen0 = true;
            if (entry.lsp_id[7] == 1) seen1 = true;
        }
    }
    try testing.expect(seen0 and seen1);

    // t=5: within the interval → no CSNP.
    try testing.expectEqual(@as(usize, 0), countKind(sched.poll(5, up, &db, &out, &scratch).effects, .csnp));
    // t=9: still within → none.
    try testing.expectEqual(@as(usize, 0), countKind(sched.poll(9, up, &db, &out, &scratch).effects, .csnp));
    // t=10: cadence → CSNP again.
    try testing.expectEqual(@as(usize, 1), countKind(sched.poll(10, up, &db, &out, &scratch).effects, .csnp));
}

test "CSNP chunking: contiguous [start,end] ranges tile the DB with no gap/overlap" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 16 });
    defer db.deinit();
    // Tiny per-PDU cap forces chunking with only a few LSPs.
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .lsp_entries_per_pdu = 2 });
    defer sched.deinit();

    var buf: [128]u8 = undefined;
    var n: u8 = 0;
    while (n < 5) : (n += 1) {
        _ = try db.insert(buildLsp(&buf, sys_other, n, 1, 900), 0, 0);
        db.clearSrm(idOf(sys_other, n), 0);
        db.clearSsn(idOf(sys_other, n), 0);
    }

    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    const r = sched.poll(0, oneUp(0), &db, &out, &scratch);

    // 5 entries, 2 per PDU → 3 CSNPs.
    try testing.expectEqual(@as(usize, 3), countKind(r.effects, .csnp));

    // Ranges tile [00…00, FF…FF] contiguously: each start == previous end + 1,
    // first start == min, last end == max; every LSP falls in exactly one range.
    var prev_end: ?LspId = null;
    var total_entries: usize = 0;
    var idx: usize = 0;
    for (r.effects) |e| {
        if (e.kind != .csnp) continue;
        const cs = try isis.Csnp.decode(e.bytes);
        if (idx == 0) {
            try testing.expectEqual(snp.min_lsp_id, cs.start_lsp_id);
        } else {
            try testing.expectEqual(snp.successor(prev_end.?), cs.start_lsp_id); // no gap/overlap
        }
        prev_end = cs.end_lsp_id;
        var it = isis.tlvs.LspEntryIterator.init((try isis.tlv.findFirst(cs.tlv_bytes, isis.tlvs.code.lsp_entries)).?);
        while (try it.next()) |entry| {
            // Every entry lies within its CSNP's advertised range.
            try testing.expect(std.mem.order(u8, &entry.lsp_id, &cs.start_lsp_id) != .lt);
            try testing.expect(std.mem.order(u8, &entry.lsp_id, &cs.end_lsp_id) != .gt);
            total_entries += 1;
        }
        idx += 1;
    }
    try testing.expectEqual(snp.max_lsp_id, prev_end.?); // last range ends at the top
    try testing.expectEqual(@as(usize, 5), total_entries); // full coverage, no loss
}

test "up-interface gating: SRM on a down iface is not sent; sent once it is Up" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 4, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, testCfg());
    defer sched.deinit();

    var lbuf: [128]u8 = undefined;
    // Arrives on iface 2 → SRM on {0,1,3}, none on 2.
    _ = try db.insert(buildLsp(&lbuf, sys_other, 0, 1, 1000), 2, 0);

    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;

    // Only iface 2 Up — but SRM is not set on 2, so nothing to flood there.
    try testing.expectEqual(@as(usize, 0), countKind(sched.poll(0, oneUp(2), &db, &out, &scratch).effects, .lsp));
    // Bring iface 1 Up (SRM is set there) → it floods.
    try testing.expectEqual(@as(usize, 1), countKind(sched.poll(0, oneUp(1), &db, &out, &scratch).effects, .lsp));
}

test "next-wakeup is the min of the next paced retransmit and the next CSNP" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var lbuf: [128]u8 = undefined;
    try arrivalDb(&db, buildLsp(&lbuf, sys_other, 0, 1, 1000), idOf(sys_other, 0));
    const up = oneUp(0);
    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;

    // interval 5, csnp 10 → after sending, retransmit gate (now+5) is the min.
    var s1 = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .min_lsp_transmission_interval = 5, .complete_snp_interval = 10 });
    defer s1.deinit();
    const r0 = s1.poll(0, up, &db, &out, &scratch);
    try testing.expectEqual(@as(?Time, 5), r0.next_wakeup); // min(0+5 LSP, 10 CSNP)

    // interval 100, csnp 10 → the CSNP cadence is the min.
    var s2 = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .min_lsp_transmission_interval = 100, .complete_snp_interval = 10 });
    defer s2.deinit();
    const r1 = s2.poll(0, up, &db, &out, &scratch);
    try testing.expectEqual(@as(?Time, 10), r1.next_wakeup); // min(0+100 LSP, 10 CSNP)

    // No Up interface → nothing pending.
    try testing.expectEqual(@as(?Time, null), s2.poll(0, InterfaceSet.initEmpty(), &db, &out, &scratch).next_wakeup);
}

/// A full ordered snapshot of one `poll`'s effects — (iface, kind, bytes) per
/// entry, in the order emitted — so two runs can be compared for byte-exact
/// determinism, not just per-kind counts. Owns its `bytes` copies; call
/// `deinit`.
const EffectItem = struct { iface: u8, kind: PduKind, bytes: []u8 };

const EffectSnapshot = struct {
    items: std.ArrayList(EffectItem),

    fn capture(alloc: std.mem.Allocator, effects: []const Effect) !EffectSnapshot {
        var items: std.ArrayList(EffectItem) = .empty;
        errdefer {
            for (items.items) |it| alloc.free(it.bytes);
            items.deinit(alloc);
        }
        for (effects) |e| {
            const owned = try alloc.dupe(u8, e.bytes);
            try items.append(alloc, .{ .iface = e.iface, .kind = e.kind, .bytes = owned });
        }
        return .{ .items = items };
    }

    fn deinit(self: *EffectSnapshot, alloc: std.mem.Allocator) void {
        for (self.items.items) |it| alloc.free(it.bytes);
        self.items.deinit(alloc);
    }

    fn expectEqual(a: EffectSnapshot, b: EffectSnapshot) !void {
        try testing.expectEqual(a.items.items.len, b.items.items.len);
        for (a.items.items, b.items.items) |x, y| {
            try testing.expectEqual(x.iface, y.iface);
            try testing.expectEqual(x.kind, y.kind);
            try testing.expectEqualSlices(u8, x.bytes, y.bytes);
        }
    }
};

test "determinism: identical (lsdb ops, now, up) yield identical effects, order and bytes included" {
    // F2: the previous version of this test compared only three per-kind
    // COUNTS (lsp/psnp/csnp) and next_wakeup between two runs, never the
    // Effect order or bytes. But LSP transmit order comes from
    // `db.srmIterator`, a bare AutoHashMap iterator whose iteration order is
    // a function of insertion history (probed separately: the same 12 LSP
    // IDs inserted forward vs. reverse DO come out of `srmIterator` in a
    // different order — see the module finding). The file's own
    // determinism contract ("the same (lsdb state, now sequence, up set)
    // yields the same effects") is about *content*-determinism, which is
    // stronger than three counts can pin. This drives the same script
    // twice (identical insertion order both times, so this specific
    // scenario IS expected to be byte-identical) and asserts the full
    // ordered (iface, kind, bytes) sequence, not just counts.
    const Run = struct {
        fn drive(alloc: std.mem.Allocator) !struct { snap: EffectSnapshot, wake: ?Time } {
            var db = Lsdb.init(alloc, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 16 });
            defer db.deinit();
            var sched = Scheduler.init(alloc, .{ .local_system_id = sys_local, .lsp_entries_per_pdu = 2 });
            defer sched.deinit();
            var buf: [128]u8 = undefined;
            // Arrive on iface 0; flood out iface 1 (up) so split horizon
            // doesn't suppress every .lsp send, leaving a non-trivial
            // sequence to compare.
            _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 900), 0, 0);
            _ = try db.insert(buildLsp(&buf, sys_other, 1, 1, 900), 0, 0);
            _ = try db.insert(buildLsp(&buf, sys_other, 2, 1, 900), 0, 0);
            var out: [32]Effect = undefined;
            var scratch: [1024]u8 = undefined;
            const r = sched.poll(0, oneUp(1), &db, &out, &scratch);
            return .{ .snap = try EffectSnapshot.capture(alloc, r.effects), .wake = r.next_wakeup };
        }
    };
    var a = try Run.drive(testing.allocator);
    defer a.snap.deinit(testing.allocator);
    var b = try Run.drive(testing.allocator);
    defer b.snap.deinit(testing.allocator);

    try testing.expect(a.snap.items.items.len > 0); // teeth: something was actually emitted
    try a.snap.expectEqual(b.snap);
    try testing.expectEqual(a.wake, b.wake);
}

test "truncation: a full out slice reports truncated and next_wakeup == now" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 16 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, testCfg());
    defer sched.deinit();
    var buf: [128]u8 = undefined;
    var n: u8 = 0;
    while (n < 4) : (n += 1) {
        try arrivalDb(&db, buildLsp(&buf, sys_other, n, 1, 900), idOf(sys_other, n));
    }
    // out holds only 2 effects but 4 LSPs want flooding on iface 0.
    var out: [2]Effect = undefined;
    var scratch: [512]u8 = undefined;
    const r = sched.poll(7, oneUp(0), &db, &out, &scratch);
    try testing.expect(r.truncated);
    try testing.expectEqual(@as(usize, 2), r.effects.len);
    try testing.expectEqual(@as(?Time, 7), r.next_wakeup); // == now: poll again immediately
}

// ── ISO/IEC 10589 §7.3.15.2: an advertised CSNP range is a COVERAGE CLAIM ────
//
// The hostile input needs no malformed packet: a neighbour merely floods more
// LSPs into the area than one summary buffer holds. The stock `isis-lsdb`
// capacity is 4096 and `max_summary_entries` is 256, so a 257-LSP area — an
// ordinary IS-IS deployment — reaches this. §7.3.15.2 makes a receiver treat an
// LSP it holds inside a CSNP's `[Start, End]` range that the CSNP did not list
// as one the sender lacks, and flood it back (`isis-lsdb.reconcileCsnp`
// implements that rule). The defect these two tests pin: the last chunk's End
// was unconditionally FF…FF, so the series claimed the entire LSP-ID space
// while listing only the first 256 entries `summarise` happened to return in
// hash order — and reported `truncated = false`, so the caller never polled for
// the rest. The result was a permanent re-flood of (DB − 256) LSPs per cadence
// tick, per circuit, forever.

const hostile_lsp_count: u16 = 300; // the audit's reproducer size (> 256)

fn fillHostileDb(db: *Lsdb, arrival_iface: ?u8) !void {
    var buf: [128]u8 = undefined;
    var n: u16 = 0;
    while (n < hostile_lsp_count) : (n += 1) {
        _ = try db.insert(buildLspId(&buf, idNth(sys_other, n), 1 + @as(u32, n), 900), arrival_iface, 0);
    }
}

test "hostile peer: a >256-LSP CSNP series never claims a range it did not enumerate" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 512 });
    defer db.deinit();
    try fillHostileDb(&db, 0); // arrived on iface 0 → no SRM there; SSN cleared below
    var sched = Scheduler.init(testing.allocator, testCfg());
    defer sched.deinit();
    var k: u16 = 0;
    while (k < hostile_lsp_count) : (k += 1) db.clearSsn(idNth(sys_other, k), 0);

    var out: [64]Effect = undefined;
    var scratch: [16 * 1024]u8 = undefined;

    var covered: std.AutoHashMapUnmanaged(LspId, void) = .empty;
    defer covered.deinit(testing.allocator);

    var prev_end: ?LspId = null;
    var first_truncated = false;
    var completed = false;
    var polls: usize = 0;
    while (polls < 64) : (polls += 1) {
        const r = sched.poll(0, oneUp(0), &db, &out, &scratch);
        if (polls == 0) first_truncated = r.truncated;
        for (r.effects) |e| {
            if (e.kind != .csnp) continue;
            const cs = try isis.Csnp.decode(e.bytes);

            // The whole (multi-poll) series still tiles the space contiguously.
            if (prev_end) |p| {
                try testing.expectEqual(snp.successor(p), cs.start_lsp_id);
            } else {
                try testing.expectEqual(snp.min_lsp_id, cs.start_lsp_id);
            }
            prev_end = cs.end_lsp_id;

            var listed: std.AutoHashMapUnmanaged(LspId, void) = .empty;
            defer listed.deinit(testing.allocator);
            if (try isis.tlv.findFirst(cs.tlv_bytes, isis.tlvs.code.lsp_entries)) |tlv| {
                var it = isis.tlvs.LspEntryIterator.init(tlv);
                while (try it.next()) |entry| {
                    try listed.put(testing.allocator, entry.lsp_id, {});
                    try covered.put(testing.allocator, entry.lsp_id, {});
                }
            }

            // THE RULE (§7.3.15.2): every LSP we hold inside the advertised
            // range must appear in this CSNP. One omission = one re-flood.
            var j: u16 = 0;
            while (j < hostile_lsp_count) : (j += 1) {
                const id = idNth(sys_other, j);
                const in_range = std.mem.order(u8, &id, &cs.start_lsp_id) != .lt and
                    std.mem.order(u8, &id, &cs.end_lsp_id) != .gt;
                if (in_range and !listed.contains(id)) return error.CsnpClaimedAnLspItDidNotList;
            }
        }
        if (!r.truncated) {
            completed = true;
            break;
        }
    }

    try testing.expect(first_truncated); // the caller is TOLD there is more
    try testing.expect(completed); // the series terminates …
    try testing.expectEqual(snp.max_lsp_id, prev_end.?); // … having reached the top
    try testing.expectEqual(@as(usize, hostile_lsp_count), covered.count()); // all of it
}

test "hostile peer: a >256-LSP CSNP series makes a peer holding the same DB re-flood nothing" {
    // The receive-side oracle: `isis-lsdb.reconcileCsnp` is an independent
    // implementation of the §7.3.15.2 completeness rule, written for the
    // opposite direction — exactly what a real IS-IS neighbour (e.g. FRR
    // isisd) does with our PDUs. Feed our series to a peer that already holds
    // every LSP we hold: it must ask for nothing and re-flood nothing.
    var mine = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 512 });
    defer mine.deinit();
    // A third router: the LSPs are sys_other's, so neither DB owns them.
    const sys_peer: [6]u8 = .{ 0, 0, 0, 0, 0, 0xC };
    var peer = Lsdb.init(testing.allocator, .{ .local_system_id = sys_peer, .interface_count = 2, .capacity = 512 });
    defer peer.deinit();
    try fillHostileDb(&mine, 0);
    try fillHostileDb(&peer, 0); // identical contents, arrived on iface 0 → no SRM there

    var sched = Scheduler.init(testing.allocator, testCfg());
    defer sched.deinit();
    var k: u16 = 0;
    while (k < hostile_lsp_count) : (k += 1) {
        mine.clearSsn(idNth(sys_other, k), 0);
        peer.clearSsn(idNth(sys_other, k), 0);
    }

    var out: [64]Effect = undefined;
    var scratch: [16 * 1024]u8 = undefined;
    var polls: usize = 0;
    while (polls < 64) : (polls += 1) {
        const r = sched.poll(0, oneUp(0), &mine, &out, &scratch);
        for (r.effects) |e| {
            if (e.kind != .csnp) continue;
            peer.reconcileCsnp(try isis.Csnp.decode(e.bytes), 0, 0);
        }
        if (!r.truncated) break;
    }

    // Not one LSP is marked for re-flood back at us, and none is requested.
    var reflooded: usize = 0;
    var requested: usize = 0;
    k = 0;
    while (k < hostile_lsp_count) : (k += 1) {
        const id = idNth(sys_other, k);
        if (peer.srmSet(id).?.isSet(0)) reflooded += 1;
        if (peer.ssnSet(id).?.isSet(0)) requested += 1;
    }
    try testing.expectEqual(@as(usize, 0), reflooded);
    try testing.expectEqual(@as(usize, 0), requested);
}

test "split horizon: a received LSP is never scheduled back out its arrival circuit" {
    // What the six `arrival_iface = null` fixtures could not state. With no
    // arrival circuit there is no circuit to except, so SRM was set on all of
    // them and "does the scheduler respect the exception" was untestable here.
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .min_lsp_transmission_interval = 5 });
    defer sched.deinit();

    var lbuf: [128]u8 = undefined;
    try arrivalDb(&db, buildLsp(&lbuf, sys_other, 0, 1, 1000), idOf(sys_other, 0));

    // Both circuits Up, polled across several retransmit periods: the LSP is
    // transmitted repeatedly on circuit 0 and not once on the arrival circuit.
    var both = oneUp(0);
    both.set(arrival);
    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;
    var on_zero: usize = 0;
    var on_arrival: usize = 0;
    for ([_]Time{ 0, 5, 10, 15 }) |t| {
        for (sched.poll(t, both, &db, &out, &scratch).effects) |e| {
            if (e.kind != .lsp) continue;
            if (e.iface == arrival) on_arrival += 1 else on_zero += 1;
        }
    }
    try testing.expectEqual(@as(usize, 4), on_zero);
    try testing.expectEqual(@as(usize, 0), on_arrival);
}

test "last-sent map is pruned when SRM clears (bounded by the SRM-flagged set)" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, testCfg());
    defer sched.deinit();
    var lbuf: [128]u8 = undefined;
    const id = idOf(sys_other, 0);
    try arrivalDb(&db, buildLsp(&lbuf, sys_other, 0, 1, 1000), id);
    var out: [8]Effect = undefined;
    var scratch: [256]u8 = undefined;

    _ = sched.poll(0, oneUp(0), &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 1), sched.last_sent.count()); // tracked

    // Ack clears SRM; the next poll prunes the now-stale last-sent entry.
    db.clearSrm(id, 0);
    _ = sched.poll(1, oneUp(0), &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 0), sched.last_sent.count()); // pruned
}

// ── fail-open guard: Config.lsp_entries_per_pdu is caller-supplied, and
// `init`'s `std.debug.assert(cfg.lsp_entries_per_pdu >= 1 ...)` is the ONLY
// thing that ever kept it there — an assert the compiler removes entirely in
// ReleaseFast. Found while building `example/main.zig` (2026-08-23): the
// example's own happy path never sets this to 0 (it always goes through
// `init` with a sane default or a positive override, same as every existing
// test in this file), so nothing here was ever red — the gap was found by
// reading `emitPsnp`/`emitCsnp` while writing the example, not by the example
// itself failing. Fixed at both use sites with `@max(1, ...)` rather than
// relying on the constructor-time assert (CONVENTIONS: fix the invariant
// where it is used, not only where it is declared) — see CHANGELOG.

test "fail-open guard: lsp_entries_per_pdu == 0 does not underflow emitCsnp / stall emitPsnp" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var lbuf: [128]u8 = undefined;
    // SSN lands on `arrival` (1), which is also the interface polled below —
    // exercises emitPsnp's chunker. The DB being non-empty also makes the
    // very first poll's periodic CSNP non-trivial (m > 0) — exercises
    // emitCsnp's chunker, where the underflow actually lived.
    try arrivalDb(&db, buildLsp(&lbuf, sys_other, 0, 1, 1000), idOf(sys_other, 0));

    // Bypass `Scheduler.init`'s public-API guard on purpose: its assert is
    // the only thing a Debug/ReleaseSafe build uses to keep this value
    // sane, and a ReleaseFast build has no such backstop at all — so a
    // ReleaseFast caller can reach `poll` with this value exactly as this
    // struct literal does.
    var sched: Scheduler = .{
        .alloc = testing.allocator,
        .cfg = .{ .local_system_id = sys_local, .lsp_entries_per_pdu = 0 },
    };
    defer sched.deinit();

    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    // Must terminate and make real progress (not underflow, not spin
    // emitting zero-entry PDUs forever) on the very first call — the
    // underflow this guards against fired on emitCsnp's first pass.
    const r0 = sched.poll(0, oneUp(arrival), &db, &out, &scratch);
    try testing.expect(countKind(r0.effects, .psnp) >= 1); // the SSN entry was drained
    try testing.expect(!db.ssnSet(idOf(sys_other, 0)).?.isSet(arrival)); // actually acked, not spun on
    _ = sched.poll(1, oneUp(arrival), &db, &out, &scratch); // a second poll: still terminates
}

test "fail-open guard: lsp_entries_per_pdu == 0 does not underflow emitCsnp's entries[j-1]" {
    // The sibling test above polls the interface carrying the pending SSN,
    // so `emitPsnp`'s own `per == 0` stall (bounded by `out.len`) fills
    // `out` and the outer loop breaks before ever reaching `emitCsnp` for
    // that interface — it proves emitPsnp's half of the gap, not
    // emitCsnp's. This test polls iface 0 instead, which has NO SSN
    // pending (arrivalDb only sets SSN on `arrival`), so `emitPsnp` returns
    // immediately ("nothing to ack") and control reaches the periodic CSNP
    // — which fires unconditionally on an interface's first poll — with a
    // non-empty database (`m == 1`) and `per == 0`. That is exactly the
    // `entries[j - 1]` underflow this test guards.
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var lbuf: [128]u8 = undefined;
    try arrivalDb(&db, buildLsp(&lbuf, sys_other, 0, 1, 1000), idOf(sys_other, 0));
    try testing.expect(db.ssnSet(idOf(sys_other, 0)).?.count() == 1); // only on `arrival`, not iface 0

    var sched: Scheduler = .{
        .alloc = testing.allocator,
        .cfg = .{ .local_system_id = sys_local, .lsp_entries_per_pdu = 0 },
    };
    defer sched.deinit();

    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    const r0 = sched.poll(0, oneUp(0), &db, &out, &scratch);
    try testing.expect(countKind(r0.effects, .csnp) >= 1); // the periodic CSNP still fired
}
