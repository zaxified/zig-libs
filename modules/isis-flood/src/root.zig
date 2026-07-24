// SPDX-License-Identifier: MIT
//! isis-flood — the IS-IS flooding transmit scheduler (ISO/IEC 10589 §7.3.15 +
//! §7.3.16.3/.4) for point-to-point circuits: drain the `isis-lsdb` per-interface
//! SRM (send LSP) and SSN (send PSNP) flag sets into the ordered list of PDUs to
//! transmit, pace LSP (re)transmission by `minimumLSPTransmissionInterval`, emit
//! periodic CSNPs for database synchronisation, and update the LSDB flags as it
//! goes. Pure and time-injected — no threads, no owned timers, no sockets: the
//! caller supplies `now` + the set of interfaces with an Up adjacency and
//! performs the actual sends; this module decides WHAT to send WHEN. P2P first
//! (LAN DIS-driven flooding is deferred — see `SPEC.md`).
//!
//! ## Layers
//! - `scheduler` — the `Scheduler`: `poll(now, up, lsdb, out, scratch)` turns the
//!   flags into `Effect`s, paces LSP retransmits via a per-`(lsp, iface)`
//!   last-sent map, drains SSN into PSNPs, drives the periodic CSNP cadence, and
//!   returns the next-wakeup deadline. The pacing gate has a positive-control knob.
//! - `snp` — the CSNP/PSNP serialisation + chunking leaf: build a PDU into a
//!   scratch buffer via the `isis` builders, cap entries per PDU, and tile a CSNP
//!   series into contiguous, gap-free `[start, end]` LSP-ID ranges.
//!
//! ## Time-injection contract
//! Identical to the siblings `isis-adj` and `isis-lsdb`: the scheduler never reads
//! a clock. `poll` takes a caller-supplied monotonic `now`; the pacing/CSNP
//! deadlines are derived from the `now` values it was last called with. Given the
//! same `(lsdb state, now sequence, up set)` the effects are fully deterministic.
//!
//! ## What clears SRM
//! On P2P, sending an LSP does **not** clear its SRM flag — `isis-lsdb` clears SRM
//! only when a PSNP acknowledges it (`reconcilePsnp`). This scheduler retransmits
//! an SRM-flagged LSP every `minimumLSPTransmissionInterval` until that happens;
//! it clears only SSN (as it produces each PSNP). See `SPEC.md`.
//!
//! Provenance: pure spec-only clean-room from ISO/IEC 10589 §7.3.15/.16 (a public
//! spec — merger doctrine); no third-party implementation source consulted or
//! ported. Like the sibling `isis` codec + `isis-adj` FSM it needs no /NOTICE
//! entry (its ISO clause cites live in `SPEC.md`).

const std = @import("std");
const isis = @import("isis");
const lsdb_mod = @import("isis-lsdb");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §7.3.15 flooding + §7.3.16.3/.4 transmission pacing",
    .deps = .{ "isis", "isis-lsdb" },
};

pub const scheduler = @import("scheduler.zig");
pub const snp = @import("snp.zig");

// ── the most-used surface, re-exported ───────────────────────────────────────
pub const Scheduler = scheduler.Scheduler;
pub const Config = scheduler.Config;
pub const Effect = scheduler.Effect;
pub const PduKind = scheduler.PduKind;
pub const PollResult = scheduler.PollResult;
pub const Time = scheduler.Time;
pub const LspId = scheduler.LspId;
pub const InterfaceSet = scheduler.InterfaceSet;
pub const max_interfaces = scheduler.max_interfaces;
pub const default_min_lsp_transmission_interval = scheduler.default_min_lsp_transmission_interval;
pub const default_complete_snp_interval = scheduler.default_complete_snp_interval;

test {
    _ = @import("scheduler.zig");
    _ = @import("snp.zig");
}

test "meta is well-formed" {
    try std.testing.expectEqual(.any, meta.platform);
    try std.testing.expectEqual(.util, meta.role);
    try std.testing.expectEqual(.single_owner, meta.concurrency);
}

// ── integration: two nodes flood + acknowledge through the scheduler ──────────

const testing = std.testing;

const sys_a: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };

fn buildLsp(buf: []u8, sys: [6]u8, seq: u32) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, 0 },
        .sequence_number = seq,
        .checksum = 0xABCD,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finish();
}

fn up0() InterfaceSet {
    var s = InterfaceSet.initEmpty();
    s.set(0);
    return s;
}

// A originates an LSP. Its scheduler floods it out the P2P link; B ingests it and
// its scheduler produces the PSNP ack; feeding that ack back into A clears A's SRM
// (retransmit stops). The whole flood→ack loop runs through both schedulers and
// the `isis` wire codec — the second side is built, not assumed.
test "flood an LSP, ack it back, and the retransmit stops (both sides real)" {
    const lsdb = lsdb_mod;

    var a_db = lsdb.Lsdb.init(testing.allocator, .{ .local_system_id = sys_a, .interface_count = 1, .capacity = 8 });
    defer a_db.deinit();
    var b_db = lsdb.Lsdb.init(testing.allocator, .{ .local_system_id = sys_b, .interface_count = 1, .capacity = 8 });
    defer b_db.deinit();

    var a_sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_a, .min_lsp_transmission_interval = 5 });
    defer a_sched.deinit();
    var b_sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_b });
    defer b_sched.deinit();

    var lbuf: [128]u8 = undefined;
    const lsp_a = buildLsp(&lbuf, sys_a, 1);
    const id_a: LspId = .{ 0, 0, 0, 0, 0, 0xA, 0, 0 };
    _ = try a_db.insert(lsp_a, null, 0); // A originates → SRM on the link

    var out: [16]Effect = undefined;
    var scratch: [512]u8 = undefined;

    // A floods the LSP. Feed every flooded LSP into B.
    const ra = a_sched.poll(0, up0(), &a_db, &out, &scratch);
    var flooded = false;
    for (ra.effects) |e| {
        if (e.kind != .lsp) continue;
        _ = try b_db.insert(e.bytes, 0, 0); // B learns A's LSP; SSN set on iface 0
        flooded = true;
    }
    try testing.expect(flooded);
    try testing.expect(b_db.get(id_a, 0) != null); // B converged on A's LSP
    try testing.expect(b_db.ssnSet(id_a).?.isSet(0)); // B owes an ack

    // B produces the PSNP ack. Feed it back into A.
    var out_b: [16]Effect = undefined;
    var scratch_b: [512]u8 = undefined;
    const rb = b_sched.poll(0, up0(), &b_db, &out_b, &scratch_b);
    var acked = false;
    for (rb.effects) |e| {
        if (e.kind != .psnp) continue;
        a_db.reconcilePsnp(try isis.Psnp.decode(e.bytes), 0, 1); // A's SRM clears
        acked = true;
    }
    try testing.expect(acked);
    try testing.expect(!a_db.srmSet(id_a).?.isSet(0)); // acknowledged
    try testing.expect(!b_db.ssnSet(id_a).?.isSet(0)); // B's SSN cleared on send

    // A no longer retransmits the acked LSP, even past the interval.
    const ra2 = a_sched.poll(10, up0(), &a_db, &out, &scratch);
    var resent = false;
    for (ra2.effects) |e| {
        if (e.kind == .lsp) resent = true;
    }
    try testing.expect(!resent);
}
