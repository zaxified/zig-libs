// SPDX-License-Identifier: MIT

//! External anchor: Wireshark 4.6.4 (sharkd, via `scripts/dissect.py`).
//!
//! `isis-flood`'s own `ANCHOR-TASKS.tsv` row before this file read `SELF`,
//! justified as "SPEC.md: no external oracle needed, wire exercised via
//! sibling isis codec only". Per the audit brief a sibling's anchor does not
//! transfer: the fact that CSNP/PSNP bytes pass through the already-anchored
//! `isis` codec says nothing about whether *this* module places the right
//! flooding-specific content into that wire format. What needs an outside
//! oracle is the Source-ID, the `[Start, End]` LSP-ID range a CSNP advertises
//! (both the all-zeros/all-ones full-database sentinel this module's periodic
//! summary uses AND a genuine non-sentinel partial range produced by its own
//! chunking/tiling — a wrong bound placement round-trips through our own
//! decoder undetected), the 16-octet LSP-Entries (#9) record's field order
//! (Remaining Lifetime, LSP-ID, Sequence Number, Checksum), and the L1/L2 PDU
//! type codes this module selects for CSNP (24/25) and PSNP (26/27) — none of
//! which the sibling `isis` codec's own anchor (see `modules/isis/src/
//! goldens.zig`) exercised with these specific flooding shapes, and none of
//! which `isis-lsdb`'s anchor (which covers the *read*/reconcile side) checks
//! either — this file anchors the *transmit* side's own construction.
//!
//! Every vector below is produced by calling this module's own top-level
//! `Scheduler.poll` against a real `isis-lsdb.Lsdb` — not by calling the leaf
//! `snp.zig` builders directly, and not a hand-derived expected value. That
//! exercises the sorting, range-tiling, chunking and Source-ID construction
//! `poll` performs on top of `snp.buildCsnp`/`buildPsnp`, i.e. exactly the
//! logic this module adds over its siblings. The resulting wire bytes were
//! then fed through Wireshark's real IS-IS dissector.
//!
//! What this deliberately does NOT claim to anchor: the SRM/SSN flag state
//! machine, the retransmit pacing gate, and the CSNP cadence timer (SPEC.md
//! §3/§4/§6) are pure in-memory scheduling decisions with no wire
//! representation — a dissector can grade the bytes of a PDU that was
//! produced, never *whether*/*when* it should have been, so none of that is
//! touched here; it stays covered only by the existing unit tests in
//! `scheduler.zig`. Multi-TLV-per-PDU packing is also out of scope: this
//! module always emits exactly one #9 TLV per PDU (`snp.zig`'s own doc
//! comment), so there is no multi-TLV-per-PDU shape to dissect — the SPEC §8
//! deferred item stays deferred.
//!
//! The `dissect.py` runs happened once, interactively, while writing this
//! file. The frozen byte arrays plus the quoted Wireshark output below are
//! what makes the anchor re-checkable without re-running the tool — the test
//! suite itself never invokes `dissect.py`/`sharkd`/`text2pcap` (no new build
//! dependency).
//!
//! ## Re-anchored: the fixture LSPs now carry a real §7.3.11 checksum
//!
//! Every vector here was first captured from fixture LSPs built with a
//! hand-picked Checksum field (0xaee7, 0x2222, 0x3000+n, 0x4444, 0x1000+n).
//! Those values are **wrong** — Wireshark grades that class of LSP
//! `isis.lsp.checksum.status == "Bad"` — and they were then handed to
//! `Lsdb.insert` on an arrival interface, i.e. as a *receive*. ISO 10589
//! §7.3.14.2 e) says a receiver discards such an LSP, so the fixtures were
//! modelling a PDU no conformant IS-IS would have accepted; they only survived
//! because nothing verified the field. The fixtures now build through
//! `LspBuilder.finishStamped` (§7.3.11: the source IS computes the checksum
//! when the LSP is generated), which changes the 2 checksum octets inside each
//! LSP-Entry — so every vector below was re-dissected, and each golden records
//! the command and the `frame.protocols` line proving the frame reached the
//! real `isis.csnp`/`isis.psnp` dissector rather than a `data` fallback.
//!
//! Wireshark does **not** grade the checksum octets inside an LSP-Entry (there
//! they are opaque payload), so each golden additionally records a dissection
//! of the *LSP itself*, where Wireshark computes ISO 8473 independently and
//! reports `isis.lsp.checksum.status`. That, not our own arithmetic, is what
//! says the new entry checksums are the right values.

const std = @import("std");
const isis = @import("isis");
const lsdb_mod = @import("isis-lsdb");
const scheduler = @import("scheduler.zig");
const snp = @import("snp.zig");
const Scheduler = scheduler.Scheduler;
const Effect = scheduler.Effect;
const LspId = scheduler.LspId;
const testing = std.testing;

const sys_local: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };

fn up0() scheduler.InterfaceSet {
    var s = scheduler.InterfaceSet.initEmpty();
    s.set(0);
    return s;
}

// ── Golden 1: L1 CSNP, full-database range, two LSP-Entries in one #9 TLV ───
// ── — one with a non-zero pseudonode+fragment and a high-bit sequence ───────
// ── number ───────────────────────────────────────────────────────────────────
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 21 01 06 18 01 00 03 00 43 00
//   00 00 00 00 0a 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff 09 20 01
//   f4 11 22 33 44 55 66 00 01 00 00 00 02 6e 27 03 84 11 22 33 44 55 66 09 0a
//   80 00 00 07 6c 91'
//
// Wireshark printed (verbatim, trimmed to the load-bearing lines):
//   frame.protocols == "eth:llc:osi:isis:isis.csnp"
//   isis.type == 24 = ...1 1000 = PDU Type: L1 CSNP (24)
//   isis.csnp.pdu_length == 67 = PDU length: 67
//   isis.csnp.source_id == 0000.0000.000a = Source-ID: 0000.0000.000a
//   isis.csnp.source_circuit == 00: = Source-ID-Circuit: 00
//   isis.csnp.start_lsp_id == 0000.0000.0000.00-00 = Start LSP-ID: 0000.0000.0000.00-00
//   isis.csnp.end_lsp_id == ffff.ffff.ffff.ff-ff = End LSP-ID: ffff.ffff.ffff.ff-ff
//   isis.csnp.clv.type == 9 = Type: 9
//   isis.csnp.clv.length == 32 = Length: 32
//   isis.csnp.lsp_seq_num == 0x00000002 = LSP Sequence Number: 0x00000002
//   isis.csnp.lsp_remain_life == 500 = Remaining Lifetime: 500
//   isis.csnp.lsp_checksum == 0x6e27 = LSP checksum: 0x6e27
//   isis.csnp.lsp_id == 1122.3344.5566.00-01 = LSP-ID: 1122.3344.5566.00-01
//   isis.csnp.lsp_seq_num == 0x80000007 = LSP Sequence Number: 0x80000007
//   isis.csnp.lsp_remain_life == 900 = Remaining Lifetime: 900
//   isis.csnp.lsp_checksum == 0x6c91 = LSP checksum: 0x6c91
//   isis.csnp.lsp_id == 1122.3344.5566.09-0a = LSP-ID: 1122.3344.5566.09-0a
// (No expert info of any kind on this or any other vector in this file —
// checked via --json.)
//
// The two summarised LSPs, dissected on their own so Wireshark grades the
// checksum it cannot grade inside an LSP-Entry:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 1b 01
//   f4 11 22 33 44 55 66 00 01 00 00 00 02 6e 27 01'
//     frame.protocols == "eth:llc:osi:isis:isis.lsp"
//     isis.lsp.checksum == 0x6e27 = Checksum: 0x6e27 [correct]
//     isis.lsp.checksum.status == "Good" = Checksum Status: Good
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 1b 03
//   84 11 22 33 44 55 66 09 0a 80 00 00 07 6c 91 01'
//     frame.protocols == "eth:llc:osi:isis:isis.lsp"
//     isis.lsp.checksum == 0x6c91 = Checksum: 0x6c91 [correct]
//     isis.lsp.checksum.status == "Good" = Checksum Status: Good
//
// Confirms: the Source-ID splits as system-id(6)+circuit(1) exactly where
// `Scheduler.sourceId()` places it; the full-database summary's range is
// exactly the `snp.min_lsp_id`/`snp.max_lsp_id` all-zeros/all-ones sentinel;
// two entries pack into one #9 TLV in ascending LSP-ID order (`sortEntries`);
// and the 16-octet record layout is Remaining Lifetime(2) / LSP-ID(8) /
// Sequence Number(4, big-endian, high bit 0x80000007 intact) / Checksum(2) —
// matching `isis.tlvs.LspEntry`'s field order exactly, with a non-zero
// pseudonode (0x09) and fragment (0x0a) that no prior isis-flood test used.
const golden1_csnp_l1_full = [_]u8{
    0x83, 0x21, 0x01, 0x06, 0x18, 0x01, 0x00, 0x03,
    0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x09, 0x20, 0x01, 0xf4, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x6e, 0x27, 0x03, 0x84, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x09, 0x0a, 0x80, 0x00, 0x00,
    0x07, 0x6c, 0x91,
};

test "golden L1 CSNP full range (Wireshark-anchored): Scheduler.poll reproduces the exact bytes" {
    var db = lsdb_mod.Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local });
    defer sched.deinit();

    const id_a: LspId = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x09, 0x0a };
    const id_b: LspId = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x01 };
    var buf_a: [256]u8 = undefined;
    var buf_b: [256]u8 = undefined;
    var la = try isis.pdu.LspBuilder.init(&buf_a, .{
        .remaining_lifetime = 900,
        .lsp_id = id_a,
        .sequence_number = 0x8000_0007,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    // §7.3.11 stamping, not a placeholder: these arrive on iface 0, so
    // §7.3.14.2 e) would discard a "Bad" LSP before it ever reached the LSDB.
    _ = try db.insert(la.finishStamped(), 0, 0);
    var lb = try isis.pdu.LspBuilder.init(&buf_b, .{
        .remaining_lifetime = 500,
        .lsp_id = id_b,
        .sequence_number = 2,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    _ = try db.insert(lb.finishStamped(), 0, 0);

    // Only the periodic CSNP is under test: clear the SRM/SSN this arrival set.
    db.clearSrm(id_a, 0);
    db.clearSrm(id_b, 0);
    db.clearSsn(id_a, 0);
    db.clearSsn(id_b, 0);

    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    const r = sched.poll(0, up0(), &db, &out, &scratch);

    var found = false;
    for (r.effects) |e| {
        if (e.kind != .csnp) continue;
        try testing.expectEqualSlices(u8, &golden1_csnp_l1_full, e.bytes);
        found = true;
    }
    try testing.expect(found);
}

// ── Golden 2: L2 CSNP, a genuine partial (non-sentinel) range from ──────────
// ── this module's own chunking/tiling of 3 LSPs at a 1-entry-per-PDU cap ────
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 21 01 06 19 01 00 03 00 33 00
//   00 00 00 00 0a 00 22 33 44 55 66 77 00 02 22 33 44 55 66 77 00 02 09 10 02
//   58 22 33 44 55 66 77 00 02 00 00 00 03 33 f9'
//
// Wireshark printed:
//   frame.protocols == "eth:llc:osi:isis:isis.csnp"
//   isis.type == 25 = ...1 1001 = PDU Type: L2 CSNP (25)
//   isis.csnp.pdu_length == 51 = PDU length: 51
//   isis.csnp.source_id == 0000.0000.000a = Source-ID: 0000.0000.000a
//   isis.csnp.start_lsp_id == 2233.4455.6677.00-02 = Start LSP-ID: 2233.4455.6677.00-02
//   isis.csnp.end_lsp_id == 2233.4455.6677.00-02 = End LSP-ID: 2233.4455.6677.00-02
//   isis.csnp.clv.type == 9 = Type: 9
//   isis.csnp.clv.length == 16 = Length: 16
//   isis.csnp.lsp_seq_num == 0x00000003 = LSP Sequence Number: 0x00000003
//   isis.csnp.lsp_remain_life == 600 = Remaining Lifetime: 600
//   isis.csnp.lsp_checksum == 0x33f9 = LSP checksum: 0x33f9
//   isis.csnp.lsp_id == 2233.4455.6677.00-02 = LSP-ID: 2233.4455.6677.00-02
//
// The summarised LSP on its own, so Wireshark grades the checksum:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 1b 02
//   58 22 33 44 55 66 77 00 02 00 00 00 03 33 f9 01'
//     frame.protocols == "eth:llc:osi:isis:isis.lsp"
//     isis.lsp.checksum == 0x33f9 = Checksum: 0x33f9 [correct]
//     isis.lsp.checksum.status == "Good" = Checksum Status: Good
//
// This is the middle of 3 CSNPs generated from 5 5-per-poll... actually 3
// LSPs at `lsp_entries_per_pdu = 1`: chunk 0 covers [00...00, ...00-01] (the
// first LSP), chunk 1 (this one) covers exactly the single middle LSP-ID
// (`start == end == successor(chunk 0's last id)`, per SPEC.md §5's tiling
// rule for a singleton group), chunk 2 covers [...00-03, ff...ff]. A wrong
// bound placement (e.g. using the *next* group's first id instead of
// `successor` of the *previous* group's last id) would round-trip through
// our own decoder undetected but shows up here as a range that does not
// abut its neighbours — Wireshark confirms this range is exactly the
// singleton `2233.4455.6677.00-02`, not off by one either direction.
const golden2_csnp_l2_partial = [_]u8{
    0x83, 0x21, 0x01, 0x06, 0x19, 0x01, 0x00, 0x03,
    0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
    0x02, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
    0x02, 0x09, 0x10, 0x02, 0x58, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x03, 0x33, 0xf9,
};

test "golden L2 CSNP partial range (Wireshark-anchored): Scheduler.poll's own chunking reproduces the exact bytes" {
    var db = lsdb_mod.Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 16 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .is_l2 = true, .lsp_entries_per_pdu = 1 });
    defer sched.deinit();

    var buf: [256]u8 = undefined;
    var n: u8 = 0;
    while (n < 3) : (n += 1) {
        const id: LspId = .{ 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0, n + 1 };
        var b = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 600,
            .lsp_id = id,
            .sequence_number = 3,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        _ = try db.insert(b.finishStamped(), 0, 0);
        db.clearSrm(id, 0);
        db.clearSsn(id, 0);
    }

    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    const r = sched.poll(0, up0(), &db, &out, &scratch);

    var idx: usize = 0;
    var checked = false;
    for (r.effects) |e| {
        if (e.kind != .csnp) continue;
        idx += 1;
        if (idx == 2) {
            try testing.expectEqualSlices(u8, &golden2_csnp_l2_partial, e.bytes);
            checked = true;
        }
    }
    try testing.expectEqual(@as(usize, 3), idx); // 3 LSPs, 1 per PDU -> 3 CSNPs
    try testing.expect(checked);
}

// ── Golden 3: L1 PSNP — Source-ID + one LSP-Entry (SSN ack path) ────────────
//
// Wireshark reuses the `isis.csnp.*` field names for PSNP LSP-Entries too
// (its own naming choice, not a mismatch — the 16-octet record is identical
// in both PDUs and the dissector shares one subtree definition for it).
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 11 01 06 1a 01 00 03 00 23 00
//   00 00 00 00 0a 00 09 10 03 84 11 22 33 44 55 66 09 0a 80 00 00 07 6c 91'
//
// Wireshark printed:
//   frame.protocols == "eth:llc:osi:isis:isis.psnp"
//   isis.type == 26 = ...1 1010 = PDU Type: L1 PSNP (26)
//   isis.psnp.pdu_length == 35 = PDU length: 35
//   isis.psnp.source_id == 0000.0000.000a = Source-ID: 0000.0000.000a
//   isis.psnp.source_circuit == 00: = Source-ID-Circuit: 00
//   isis.psnp.clv.type == 9 = Type: 9
//   isis.psnp.clv.length == 16 = Length: 16
//   isis.csnp.lsp_seq_num == 0x80000007 = LSP Sequence Number: 0x80000007
//   isis.csnp.lsp_remain_life == 900 = Remaining Lifetime: 900
//   isis.csnp.lsp_checksum == 0x6c91 = LSP checksum: 0x6c91
//   isis.csnp.lsp_id == 1122.3344.5566.09-0a = LSP-ID: 1122.3344.5566.09-0a
//
// The acknowledged LSP on its own (same bytes as Golden 1's second entry):
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 1b 03
//   84 11 22 33 44 55 66 09 0a 80 00 00 07 6c 91 01'
//     frame.protocols == "eth:llc:osi:isis:isis.lsp"
//     isis.lsp.checksum.status == "Good" = Checksum Status: Good
const golden3_psnp_l1 = [_]u8{
    0x83, 0x11, 0x01, 0x06, 0x1a, 0x01, 0x00, 0x03,
    0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x09, 0x10, 0x03, 0x84, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x09, 0x0a, 0x80, 0x00, 0x00,
    0x07, 0x6c, 0x91,
};

test "golden L1 PSNP (Wireshark-anchored): Scheduler.poll's SSN-drain reproduces the exact bytes" {
    var db = lsdb_mod.Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local });
    defer sched.deinit();

    const id_a: LspId = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x09, 0x0a };
    var buf: [256]u8 = undefined;
    var la = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 900,
        .lsp_id = id_a,
        .sequence_number = 0x8000_0007,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    _ = try db.insert(la.finishStamped(), 0, 0); // arrives on iface 0 -> SSN set there

    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    const r = sched.poll(0, up0(), &db, &out, &scratch);

    var found = false;
    for (r.effects) |e| {
        if (e.kind != .psnp) continue;
        try testing.expectEqualSlices(u8, &golden3_psnp_l1, e.bytes);
        found = true;
    }
    try testing.expect(found);
}

// ── Golden 4: L2 PSNP — the L2 type code (27) counterpart to Golden 3 ───────
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 11 01 06 1b 01 00 03 00 23 00
//   00 00 00 00 0a 00 09 10 02 bc 22 33 44 55 66 77 00 01 00 00 00 09 2d fa'
//
// Wireshark printed:
//   frame.protocols == "eth:llc:osi:isis:isis.psnp"
//   isis.type == 27 = ...1 1011 = PDU Type: L2 PSNP (27)
//   isis.psnp.pdu_length == 35 = PDU length: 35
//   isis.psnp.source_id == 0000.0000.000a = Source-ID: 0000.0000.000a
//   isis.csnp.lsp_seq_num == 0x00000009 = LSP Sequence Number: 0x00000009
//   isis.csnp.lsp_remain_life == 700 = Remaining Lifetime: 700
//   isis.csnp.lsp_checksum == 0x2dfa = LSP checksum: 0x2dfa
//   isis.csnp.lsp_id == 2233.4455.6677.00-01 = LSP-ID: 2233.4455.6677.00-01
//
// The acknowledged LSP on its own, so Wireshark grades the checksum:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 1b 02
//   bc 22 33 44 55 66 77 00 01 00 00 00 09 2d fa 01'
//     frame.protocols == "eth:llc:osi:isis:isis.lsp"
//     isis.lsp.checksum == 0x2dfa = Checksum: 0x2dfa [correct]
//     isis.lsp.checksum.status == "Good" = Checksum Status: Good
const golden4_psnp_l2 = [_]u8{
    0x83, 0x11, 0x01, 0x06, 0x1b, 0x01, 0x00, 0x03,
    0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x09, 0x10, 0x02, 0xbc, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x09, 0x2d, 0xfa,
};

test "golden L2 PSNP (Wireshark-anchored): Scheduler.poll selects the L2 PSNP type code" {
    var db = lsdb_mod.Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .is_l2 = true });
    defer sched.deinit();

    const id_a: LspId = .{ 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0, 1 };
    var buf: [256]u8 = undefined;
    var la = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 700,
        .lsp_id = id_a,
        .sequence_number = 9,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    _ = try db.insert(la.finishStamped(), 0, 0);

    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    const r = sched.poll(0, up0(), &db, &out, &scratch);

    var found = false;
    for (r.effects) |e| {
        if (e.kind != .psnp) continue;
        try testing.expectEqualSlices(u8, &golden4_psnp_l2, e.bytes);
        found = true;
    }
    try testing.expect(found);
}

// ── Golden 5: the first CSNP of a TRUNCATED series — the range this module ──
// ── may claim when the database does not fit one summary buffer ─────────────
//
// Added with the ISO 10589 §7.3.15.2 coverage fix. The other four goldens all
// come from databases small enough to summarise in one window, so none of them
// exercises the case the fix is about: a database larger than
// `max_summary_entries`, where the last chunk's End LSP-ID must be the last
// entry actually enumerated and NOT the `FF…FF` sentinel. This vector is the
// first CSNP of a 300-LSP series at `lsp_entries_per_pdu = 2`; its End is a
// real LSP-ID, and a third-party dissector agrees that is what the field says.
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 21 01 06 18 01 00 03 00 43 00
//   00 00 00 00 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0b 00 01 09 20 03
//   84 00 00 00 00 00 0b 00 00 00 00 00 01 a6 4c 03 84 00 00 00 00 00 0b 00 01
//   00 00 00 02 9e 52'
//
// Wireshark 4.6.4 printed (verbatim, trimmed to the load-bearing lines):
//   frame.protocols == "eth:llc:osi:isis:isis.csnp"
//   isis.type == 24 = ...1 1000 = PDU Type: L1 CSNP (24)
//   isis.csnp.pdu_length == 67 = PDU length: 67
//   isis.csnp.source_id == 0000.0000.000a = Source-ID: 0000.0000.000a
//   isis.csnp.start_lsp_id == 0000.0000.0000.00-00 = Start LSP-ID: 0000.0000.0000.00-00
//   isis.csnp.end_lsp_id == 0000.0000.000b.00-01 = End LSP-ID: 0000.0000.000b.00-01
//   isis.csnp.clv.type == 9 = Type: 9
//   isis.csnp.clv.length == 32 = Length: 32
//   isis.csnp.lsp_checksum == 0xa64c = LSP checksum: 0xa64c
//   isis.csnp.lsp_id == 0000.0000.000b.00-00 = LSP-ID: 0000.0000.000b.00-00
//   isis.csnp.lsp_checksum == 0x9e52 = LSP checksum: 0x9e52
//   isis.csnp.lsp_id == 0000.0000.000b.00-01 = LSP-ID: 0000.0000.000b.00-01
//
// The two listed LSPs on their own, so Wireshark grades their checksums:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 1b 03
//   84 00 00 00 00 00 0b 00 00 00 00 00 01 a6 4c 01'
//     frame.protocols == "eth:llc:osi:isis:isis.lsp"
//     isis.lsp.checksum == 0xa64c = Checksum: 0xa64c [correct]
//     isis.lsp.checksum.status == "Good" = Checksum Status: Good
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 1b 03
//   84 00 00 00 00 00 0b 00 01 00 00 00 02 9e 52 01'
//     frame.protocols == "eth:llc:osi:isis:isis.lsp"
//     isis.lsp.checksum == 0x9e52 = Checksum: 0x9e52 [correct]
//     isis.lsp.checksum.status == "Good" = Checksum Status: Good
//
// No `data` fallback (the frame reached the real IS-IS CSNP dissector) and no
// expert-info item. Both listed LSP-IDs lie inside the advertised range, and
// the range stops at the second of them: the 298 LSPs this PDU does not list
// are all OUTSIDE what it claims, which is the whole point — a peer running
// the §7.3.15.2 completeness check on this range concludes nothing about them.
const golden5_csnp_truncated_series = [_]u8{
    0x83, 0x21, 0x01, 0x06, 0x18, 0x01, 0x00, 0x03,
    0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
    0x01, 0x09, 0x20, 0x03, 0x84, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0xa6, 0x4c, 0x03, 0x84, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x9e, 0x52,
};

test "golden truncated CSNP series (Wireshark-anchored): the End LSP-ID is enumerated, not FF…FF" {
    var db = lsdb_mod.Lsdb.init(testing.allocator, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 512 });
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_local, .lsp_entries_per_pdu = 2 });
    defer sched.deinit();

    // 300 LSPs — more than `max_summary_entries` (256), so the series cannot be
    // advertised in one window.
    var buf: [256]u8 = undefined;
    var n: u16 = 0;
    while (n < 300) : (n += 1) {
        const id: LspId = .{ 0, 0, 0, 0, 0, 0x0B, @intCast(n >> 8), @truncate(n) };
        var lb = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 900,
            .lsp_id = id,
            .sequence_number = 1 + @as(u32, n),
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        _ = try db.insert(lb.finishStamped(), 0, 0);
        db.clearSsn(id, 0); // only the periodic CSNP is under test
    }

    var out: [4]Effect = undefined;
    var scratch: [4096]u8 = undefined;
    const r = sched.poll(0, up0(), &db, &out, &scratch);

    var found = false;
    for (r.effects) |e| {
        if (e.kind != .csnp) continue;
        try testing.expectEqualSlices(u8, &golden5_csnp_truncated_series, e.bytes);
        found = true;
        break;
    }
    try testing.expect(found);
    // The series is not finished, and the caller is told so.
    try testing.expect(r.truncated);
}
