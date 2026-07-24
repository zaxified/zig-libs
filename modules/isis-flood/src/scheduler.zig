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
/// this is summarised only up to this many entries per poll for that circuit — a
/// documented cap, sized generously for the intended fabric (see `../SPEC.md`).
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
    /// filled before all pending work was emitted. The caller should send what it
    /// got and `poll` again immediately (`next_wakeup == now`).
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
            if (self.emitSnp(.psnp, now, iface, db, out, &n_eff, scratch, &scratch_used)) |t| {
                if (t) {
                    truncated = true;
                    wake = minOpt(wake, now);
                    break :outer;
                }
            }

            // ── 3. Periodic CSNP (§7.3.15.2) ────────────────────────────────────
            if (now >= self.csnp_next[iface]) {
                if (self.emitSnp(.csnp, now, iface, db, out, &n_eff, scratch, &scratch_used)) |t| {
                    if (t) {
                        truncated = true;
                        wake = minOpt(wake, now);
                        break :outer;
                    }
                }
                self.csnp_next[iface] = now +| self.cfg.complete_snp_interval;
            }
            wake = minOpt(wake, self.csnp_next[iface]);
        }

        return .{
            .effects = out[0..n_eff],
            .next_wakeup = if (truncated) now else wake,
            .truncated = truncated,
        };
    }

    /// Emit the SNP PDUs for one circuit. For `.psnp` it drains the SSN-flagged
    /// LSPs (clearing SSN as each PDU is produced); for `.csnp` it summarises the
    /// whole DB into contiguously-tiled ranges. Returns `true` iff it ran out of
    /// `out` room or `scratch` space (truncated) — otherwise `false`; `null` is
    /// never returned (the optional keeps the call sites uniform).
    fn emitSnp(
        self: *Scheduler,
        comptime kind: PduKind,
        now: Time,
        iface: u8,
        db: *Lsdb,
        out: []Effect,
        n_eff: *usize,
        scratch: []u8,
        scratch_used: *usize,
    ) ?bool {
        var entries: [max_summary_entries]LspEntry = undefined;
        var m: usize = 0;

        switch (kind) {
            .psnp => {
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
            },
            .csnp => {
                m = db.summarise(&entries, snp.min_lsp_id, snp.max_lsp_id, now);
                // m == 0 is legal: one empty CSNP over the whole range still emits.
            },
            .lsp => unreachable,
        }

        snp.sortEntries(entries[0..m]);

        const per = self.cfg.lsp_entries_per_pdu;
        const src = self.sourceId();
        var i: usize = 0;
        // A CSNP with no entries still emits exactly one covering PDU.
        var first = true;
        while (i < m or (kind == .csnp and first)) {
            first = false;
            const j = @min(i + per, m);
            if (n_eff.* >= out.len) return true;

            const built = switch (kind) {
                .psnp => snp.buildPsnp(scratch[scratch_used.*..], src, self.cfg.is_l2, entries[i..j]) catch return true,
                .csnp => blk: {
                    const start = if (i == 0) snp.min_lsp_id else snp.successor(entries[i - 1].lsp_id);
                    const end = if (j >= m) snp.max_lsp_id else entries[j - 1].lsp_id;
                    break :blk snp.buildCsnp(scratch[scratch_used.*..], src, self.cfg.is_l2, start, end, entries[i..j]) catch return true;
                },
                .lsp => unreachable,
            };

            out[n_eff.*] = .{ .iface = iface, .kind = kind, .bytes = built };
            n_eff.* += 1;
            scratch_used.* += built.len;

            // A PSNP has now acknowledged/requested these LSPs → clear SSN.
            if (kind == .psnp) {
                for (entries[i..j]) |e| db.clearSsn(e.lsp_id, iface);
            }
            i = j;
        }
        return false;
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

fn buildLsp(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16, csum: u16) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = idOf(sys, lsp_num),
        .sequence_number = seq,
        .checksum = csum,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finish();
}

fn oneUp(iface: u8) InterfaceSet {
    var s = InterfaceSet.initEmpty();
    s.set(iface);
    return s;
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
    _ = try db.insert(buildLsp(&lbuf, sys_other, 0, 1, 1000, 0x1111), null, 0); // SRM on all
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
    _ = try db.insert(buildLsp(&lbuf, sys_other, 0, 1, 1000, 0x1111), null, 0);
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
    _ = try db.insert(buildLsp(&lbuf, sys_other, 0, 1, 1000, 0x1111), null, 0);
    const id = idOf(sys_other, 0);
    const up = oneUp(0);
    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;

    _ = sched.poll(0, up, &db, &out, &scratch); // flooded on iface 0, SRM still set
    try testing.expect(db.srmSet(id).?.isSet(0));

    // The neighbour ACKs with a PSNP echoing the same (seq, life, csum) → isis-lsdb
    // clears SRM on the ack path (per-entry `same` ⇒ unset SRM).
    var pbuf: [128]u8 = undefined;
    const ack = [_]LspEntry{.{ .remaining_lifetime = 1000, .lsp_id = id, .sequence_number = 1, .checksum = 0x1111 }};
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
    _ = try db.insert(buildLsp(&b0, sys_other, 0, 3, 900, 0x1111), 0, 0);
    _ = try db.insert(buildLsp(&b1, sys_other, 1, 7, 800, 0x2222), 0, 0);
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
    _ = try db.insert(buildLsp(&buf, sys_other, 0, 4, 900, 0x1111), 0, 0);
    _ = try db.insert(buildLsp(&buf, sys_other, 1, 6, 900, 0x2222), 0, 0);
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
        _ = try db.insert(buildLsp(&buf, sys_other, n, 1, 900, 0x1000 + @as(u16, n)), 0, 0);
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
    _ = try db.insert(buildLsp(&lbuf, sys_other, 0, 1, 1000, 0x1111), 2, 0);

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
    _ = try db.insert(buildLsp(&lbuf, sys_other, 0, 1, 1000, 0x1111), null, 0); // SRM on all
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

test "determinism: identical (lsdb ops, now, up) yield identical effects" {
    const Run = struct {
        fn drive(alloc: std.mem.Allocator) !struct { lsp: usize, psnp: usize, csnp: usize, wake: ?Time } {
            var db = Lsdb.init(alloc, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 16 });
            defer db.deinit();
            var sched = Scheduler.init(alloc, .{ .local_system_id = sys_local, .lsp_entries_per_pdu = 2 });
            defer sched.deinit();
            var buf: [128]u8 = undefined;
            _ = try db.insert(buildLsp(&buf, sys_other, 0, 1, 900, 0x1111), 0, 0);
            _ = try db.insert(buildLsp(&buf, sys_other, 1, 1, 900, 0x2222), 0, 0);
            _ = try db.insert(buildLsp(&buf, sys_other, 2, 1, 900, 0x3333), 0, 0);
            var out: [32]Effect = undefined;
            var scratch: [1024]u8 = undefined;
            const r = sched.poll(0, oneUp(0), &db, &out, &scratch);
            return .{ .lsp = countKind(r.effects, .lsp), .psnp = countKind(r.effects, .psnp), .csnp = countKind(r.effects, .csnp), .wake = r.next_wakeup };
        }
    };
    const a = try Run.drive(testing.allocator);
    const b = try Run.drive(testing.allocator);
    try testing.expectEqual(a.lsp, b.lsp);
    try testing.expectEqual(a.psnp, b.psnp);
    try testing.expectEqual(a.csnp, b.csnp);
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
        _ = try db.insert(buildLsp(&buf, sys_other, n, 1, 900, 0x1000 + @as(u16, n)), null, 0); // SRM on all
    }
    // out holds only 2 effects but 4 LSPs want flooding on iface 0.
    var out: [2]Effect = undefined;
    var scratch: [512]u8 = undefined;
    const r = sched.poll(7, oneUp(0), &db, &out, &scratch);
    try testing.expect(r.truncated);
    try testing.expectEqual(@as(usize, 2), r.effects.len);
    try testing.expectEqual(@as(?Time, 7), r.next_wakeup); // == now: poll again immediately
}

test "last-sent map is pruned when SRM clears (bounded by the SRM-flagged set)" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, testCfg());
    defer sched.deinit();
    var lbuf: [128]u8 = undefined;
    _ = try db.insert(buildLsp(&lbuf, sys_other, 0, 1, 1000, 0x1111), null, 0);
    const id = idOf(sys_other, 0);
    var out: [8]Effect = undefined;
    var scratch: [256]u8 = undefined;

    _ = sched.poll(0, oneUp(0), &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 1), sched.last_sent.count()); // tracked

    // Ack clears SRM; the next poll prunes the now-stale last-sent entry.
    db.clearSrm(id, 0);
    _ = sched.poll(1, oneUp(0), &db, &out, &scratch);
    try testing.expectEqual(@as(usize, 0), sched.last_sent.count()); // pruned
}
