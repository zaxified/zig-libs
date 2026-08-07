// SPDX-License-Identifier: MIT

//! External anchor: Wireshark 4.6.4 (sharkd, via `scripts/dissect.py`).
//!
//! `isis-lsdb`'s own ANCHOR-TASKS.tsv row before this file: the §7.3.16.1
//! checksum tie-break was cross-checked against FRRouting `isis_lsp.c`, but the
//! rest of the KAT table — the LSP-ID/sequence/lifetime/flags/checksum bytes
//! this module stores and compares — was hand-authored only, with no oracle
//! outside the author's own reading of ISO/IEC 10589.
//!
//! The sibling `isis` codec was separately anchored (see `modules/isis/src/
//! goldens.zig`), but per the audit brief a sibling's anchor does not transfer:
//! what has to be checked is the LSP *content this module reads and produces
//! comparisons over*, and specifically the parts its sibling's goldens never
//! exercised — a **non-zero pseudonode byte and a non-zero LSP (fragment)
//! number** (every `isis` golden used `.., 0, 0}`), the **high-bit sequence
//! number** that is the crux of `compare`'s unsigned-vs-signed KAT case (every
//! `isis` golden used a small sequence number), and a **real, Wireshark-
//! verified-correct ISO 8473 Fletcher checksum** (every `isis` golden used
//! `checksum = 0`, "not in use" — never a checksum Wireshark actually graded).
//!
//! Provenance of the checksum value below: computed by this test's author from
//! the published Fletcher-checksum-with-correction algorithm (ISO/IEC 8473
//! Annex C / RFC 905 Annex B — the same construction FRR's `lib/checksum.c
//! fletcher_checksum()` implements), over the LSP body from the LSP-ID field
//! (byte 12) to the end of the PDU, i.e. excluding PDU Length and Remaining
//! Lifetime. That hand computation is **not** what makes this an anchor — it
//! is only how the candidate byte pair was produced. The anchor is that
//! `scripts/dissect.py`, i.e. Wireshark's own independent Fletcher
//! implementation, was then asked to grade it and reported `[correct]` /
//! `"Good"`. Both LSP goldens below are fed through `Lsdb.insert`/
//! `reconcileCsnp` (not just the sibling codec) so the assertions exercise
//! *this* module's read path, per the audit brief's no-transfer rule.
//!
//! The `dissect.py` runs happened once, interactively, while writing this
//! file. The frozen byte arrays plus the quoted Wireshark output below are what
//! makes the anchor re-checkable without re-running the tool — the test suite
//! itself never invokes `dissect.py`/`sharkd`/`text2pcap` (no new build
//! dependency).

const std = @import("std");
const isis = @import("isis");
const store = @import("store.zig");
const Lsdb = store.Lsdb;
const testing = std.testing;

// ── Golden 1: L2 LSP — non-zero pseudonode + fragment, high-bit sequence ────
// ── number, full flags nibble, and a real Fletcher checksum ─────────────────
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 14 01 00 03 00 1b 03
//   84 aa bb cc dd ee ff 07 03 80 00 00 07 ae e7 d7'
//
// Wireshark printed (verbatim, trimmed to the load-bearing lines):
//   isis.type == 20 = ...1 0100 = PDU Type: L2 LSP (20)
//   isis.lsp.pdu_length == 27 = PDU length: 27
//   isis.lsp.remaining_life == 900 = Remaining lifetime: 900
//   isis.lsp.lsp_id == aabb.ccdd.eeff.07-03 = LSP-ID: aabb.ccdd.eeff.07-03
//   isis.lsp.sequence_number == 0x80000007 = Sequence number: 0x80000007
//   isis.lsp.checksum == 0xaee7 = Checksum: 0xaee7 [correct]
//   isis.lsp.checksum.status == "Good" = Checksum Status: Good
//   frame[43:1] == d7: = Type block(0xd7): Partition Repair:1, Attached
//     bits:10, Overload bit:1, IS type:3
//   isis.lsp.partition_repair == True = 1... .... = Partition Repair: Supported
//   isis.lsp.att == 10 = .101 0... = Attachment: 10
//   isis.lsp.overload == True = .... .1.. = Overload bit: Set
//   isis.lsp.is_type == 3 = .... ..11 = Type of Intermediate System: Level 2 (3)
//
// This confirms, independently of our own decoder/builder: the LSP-ID splits
// as system-id(6) + pseudonode(1)=0x07 + LSP-number(1)=0x03 exactly where
// `LspId = [8]u8` assumes; the sequence number is big-endian with the high bit
// (0x80000007) intact — the exact shape `compare`'s unsigned-vs-signed KAT case
// turns on; Remaining Lifetime is a big-endian u16 at byte 10; and the flags
// octet's bit positions (partition-repair = 0x80, attached = bits 6-3, overload
// = 0x04, is-type = bits 1-0) match `isis.pdu.LspFlags.fromByte`/`toByte`
// exactly. Wireshark additionally decomposes the "Attached" nibble into
// error/expense/delay/default-metric sub-bits and (mis-)renders their bit
// position as if they lived at byte-7/6/5/4 of the *whole* flags octet rather
// than within the 4-bit nibble — the same class of masked-subfield display
// quirk already noted for the old-style IS-Reachability metric bits in
// `modules/isis/src/goldens.zig` (Golden 6). It does not affect the nibble's
// raw value, which the "Attachment: 10" line reports and which matches our
// 0xA exactly; `isis`/`isis-lsdb` model `attached` as an opaque `u4` and never
// decode those sub-bits, so this is Wireshark's dissector quirk, not a
// wire-format bug on either side.
const golden_lsp_bytes = [_]u8{
    0x83, 0x1b, 0x01, 0x06, 0x14, 0x01, 0x00, 0x03,
    0x00, 0x1b, 0x03, 0x84, 0xaa, 0xbb, 0xcc, 0xdd,
    0xee, 0xff, 0x07, 0x03, 0x80, 0x00, 0x00, 0x07,
    0xae, 0xe7, 0xd7,
};

const golden_lsp_id: store.LspId = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x07, 0x03 };
const golden_lsp_system_id: [6]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

test "golden LSP (Wireshark-anchored): our builder reproduces the exact bytes" {
    var buf: [64]u8 = undefined;
    var b = try isis.pdu.LspBuilder.init(&buf, .{
        .is_l2 = true,
        .remaining_lifetime = 900,
        .lsp_id = golden_lsp_id,
        .sequence_number = 0x8000_0007,
        .checksum = 0xaee7,
        .flags = .{ .partition_repair = true, .attached = 0xA, .overload = true, .is_type = 3 },
    });
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_lsp_bytes, wire);
}

test "golden LSP (Wireshark-anchored): Lsdb.insert stores exactly the fields Wireshark confirmed" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = golden_lsp_system_id, .interface_count = 2 });
    defer db.deinit();

    // Originated locally (`arrival_iface = null`): this LSP-ID carries
    // `local_system_id`, and ISO/IEC 10589 §7.3.16.1's own-LSP rule means only
    // this system may originate it — a copy arriving on a circuit is refused
    // (asserted at the end of this test), so the *storing* path for a self LSP
    // is the local one.
    const r = try db.insert(&golden_lsp_bytes, null, 100);
    try testing.expect(r.stored);
    try testing.expectEqual(golden_lsp_id, r.lsp_id);

    const view = db.get(golden_lsp_id, 100).?;
    // Sequence number: big-endian, high bit intact — Wireshark: 0x80000007.
    try testing.expectEqual(@as(u32, 0x8000_0007), view.sequence_number);
    // Remaining Lifetime aged 0 ticks from insert — Wireshark: 900.
    try testing.expectEqual(@as(u16, 900), view.remaining_lifetime);
    // Checksum carried verbatim — Wireshark: 0xaee7, graded "Good".
    try testing.expectEqual(@as(u16, 0xaee7), view.checksum);
    // The LSP-ID's first 6 octets are the system id — Wireshark's
    // "aabb.ccdd.eeff.07-03" split — so this LSP is detected as self-originated
    // when `local_system_id` matches it.
    try testing.expect(view.self_originated);
    // Flags round-trip through the store untouched.
    try testing.expect(view.flags.partition_repair);
    try testing.expectEqual(@as(u4, 0xA), view.flags.attached);
    try testing.expect(view.flags.overload);
    try testing.expectEqual(@as(u2, 3), view.flags.is_type);

    // ISO/IEC 10589 §7.3.14.2 e), on the Wireshark-anchored bytes: bumping the
    // sequence number without recomputing the Fletcher checksum leaves 0xaee7
    // stale — exactly the state Wireshark grades "Bad" — so the LSP is
    // discarded on receipt, before the §7.3.16.1 machinery is reached at all.
    var hostile = golden_lsp_bytes;
    hostile[23] = 0x08; // sequence number low octet: 0x8000_0007 → 0x8000_0008
    try testing.expectError(error.CorruptedLsp, db.insert(&hostile, 1, 101));
    try testing.expectEqual(@as(u32, 0x8000_0007), db.get(golden_lsp_id, 101).?.sequence_number);
    try testing.expect(!db.refreshPending(golden_lsp_id));

    // ISO/IEC 10589 §7.3.16.1 own-LSP rule, on the same bytes with the checksum
    // recomputed as a conformant (or merely competent) sender would: the *same*
    // LSP-ID arriving from a neighbour at a higher sequence number
    // (0x80000008 > the golden's 0x80000007) is refused, not adopted, and the
    // owner is told to re-originate above the challenger.
    _ = try isis.pdu.stampLspChecksum(&hostile);
    const c = try db.insert(&hostile, 1, 101);
    try testing.expect(!c.stored);
    try testing.expectEqual(@as(?u32, 0x8000_0008), c.self_challenge);
    try testing.expectEqual(@as(u32, 0x8000_0007), db.get(golden_lsp_id, 101).?.sequence_number);
    try testing.expect(db.refreshPending(golden_lsp_id));
}

// ── Not a bug: a placeholder checksum used by this module's existing KAT ────
// ── fixtures is correctly graded "Bad" by Wireshark ─────────────────────────
//
// Command (same LSP bytes, checksum field overwritten with the arbitrary
// 0x1111 `store.zig` test fixtures use as a placeholder):
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 14 01 00 03 00 1b 03
//   84 aa bb cc dd ee ff 07 03 80 00 00 07 11 11 d7'
//
// Wireshark printed:
//   isis.lsp.checksum == 0x1111 = Checksum: 0x1111 incorrect, should be 0xaee7
//   isis.lsp.checksum.status == "Bad" = Checksum Status: Bad
//   isis.lsp.bad_checksum = Bad checksum [should be 0xaee7]
//
// This is expected, not a finding: per SPEC.md §2/§8, `isis-lsdb` neither
// computes nor verifies the ISO Fletcher checksum — it is a raw field the
// comparison and store treat opaquely (LSP generation/receive-validation is
// explicitly deferred to a later module). The existing KAT fixtures'
// `0x1111`/`0x2222`/... placeholders are therefore *supposed* to fail a real
// Fletcher check; Wireshark confirming that is the tool working, not this
// module being wrong.
//
// Also checked: with the checksum field zeroed (`0x0000`, ISO 10589's
// "checksumming not in use" convention), Wireshark reports
// `isis.lsp.checksum.status == "Not present"` rather than "Bad" — it does not
// try to grade an all-zero checksum, consistent with the spec's convention.
// `isis-lsdb` does not special-case a zero checksum either (§7.3.16.1's
// checksum tie-break in `compare.zig` treats it as an ordinary value), which
// is the already-anchored (FRR-cross-checked) behaviour this task does not
// revisit.

// ── Golden 2: CSNP LSP-Entries — non-zero pseudonode + fragment ─────────────
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 21 01 06 18 01 00 03 00 33 11
//   22 33 44 55 66 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff 09 10 02
//   2b 11 22 33 44 55 66 09 0a 00 00 00 42 99 aa'
//
// Wireshark printed:
//   isis.type == 24 = ...1 1000 = PDU Type: L1 CSNP (24)
//   isis.csnp.pdu_length == 51 = PDU length: 51
//   isis.csnp.source_id == 1122.3344.5566 = Source-ID: 1122.3344.5566
//   isis.csnp.start_lsp_id == 0000.0000.0000.00-00 = Start LSP-ID
//   isis.csnp.end_lsp_id == ffff.ffff.ffff.ff-ff = End LSP-ID
//   frame[50:18] == 09:10:... = LSP entries (t=9, l=16)
//   isis.csnp.lsp_seq_num == 0x00000042 = LSP Sequence Number: 0x00000042
//   isis.csnp.lsp_remain_life == 555 = Remaining Lifetime: 555
//   isis.csnp.lsp_checksum == 0x99aa = LSP checksum: 0x99aa
//   isis.csnp.lsp_id == 1122.3344.5566.09-0a = LSP-ID: 1122.3344.5566.09-0a
//
// Confirms the LSP-Entries (#9) 16-octet record layout `store.zig`'s
// `reconcileCsnp`/`reconcileEntriesMarking`/`summarise` walk
// (`isis.tlvs.LspEntryIterator`/`addLspEntries`) with a non-zero pseudonode
// (0x09) and LSP-number (0x0a) neither sibling golden ever used.
const golden_csnp_bytes = [_]u8{
    0x83, 0x21, 0x01, 0x06, 0x18, 0x01, 0x00, 0x03,
    0x00, 0x33, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x09, 0x10, 0x02, 0x2b, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x09, 0x0a, 0x00, 0x00, 0x00,
    0x42, 0x99, 0xaa,
};

const golden_csnp_entry_id: store.LspId = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x09, 0x0a };

test "golden CSNP LSP-Entry (Wireshark-anchored): our builder reproduces the exact bytes" {
    var buf: [64]u8 = undefined;
    var b = try isis.pdu.CsnpBuilder.init(&buf, .{
        .source_id = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xff),
    });
    const entries = [_]isis.tlvs.LspEntry{
        .{ .remaining_lifetime = 555, .lsp_id = golden_csnp_entry_id, .sequence_number = 0x42, .checksum = 0x99aa },
    };
    try isis.tlvs.addLspEntries(&b.tlvs, &entries);
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_csnp_bytes, wire);
}

test "golden CSNP LSP-Entry (Wireshark-anchored): Lsdb.reconcileCsnp requests exactly this LSP-ID" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = .{ 0, 0, 0, 0, 0, 0xEE }, .interface_count = 2, .capacity = 8 });
    defer db.deinit();

    const csnp = try isis.Csnp.decode(&golden_csnp_bytes);
    db.reconcileCsnp(csnp, 1, 0);

    // We lacked it → a zero-sequence request placeholder was created for
    // *exactly* the Wireshark-confirmed LSP-ID (pseudonode 0x09, fragment
    // 0x0a), with SSN set to request it.
    const view = db.get(golden_csnp_entry_id, 0).?;
    try testing.expect(view.is_request);
    try testing.expect(db.ssnSet(golden_csnp_entry_id).?.isSet(1));
}

// ── Golden 3: PSNP path + L2 CSNP/PSNP type codes ────────────────────────────
//
// The `isis-lsdb` ANCHOR-TASKS.tsv row before this section: golden 2 above
// exercised only `Lsdb.reconcileCsnp` with an `is_l2 = false` (L1, type 24)
// CSNP. Two things this module's own API surface exercises were never
// separately fed to an independent dissector: `Lsdb.reconcilePsnp` (the PSNP
// path entirely) and the L2 (25/27) type codes for either PDU. The three
// goldens below close that — same LSP-Entries record layout already confirmed
// by golden 2, driven with fresh field values through `PsnpBuilder`/
// `CsnpBuilder` and `reconcilePsnp`/`reconcileCsnp`, and separately with
// `is_l2 = true`.

// Golden 3a: L1 PSNP (PDU type 26) — the PSNP path, not exercised above.
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 11 01 06 1a 01 00 03 00 23 11
//   22 33 44 55 66 00 09 10 01 41 11 22 33 44 55 66 0c 0d 00 00 00 99 56 78'
//
// Wireshark printed:
//   frame.protocols == "eth:llc:osi:isis:isis.psnp" (full PSNP dissection)
//   isis.type == 26 = ...1 1010 = PDU Type: L1 PSNP (26)
//   isis.psnp.pdu_length == 35 = PDU length: 35
//   isis.psnp.source_id == 1122.3344.5566 = Source-ID
//   frame[34:18] == 09:10:... = LSP entries (t=9, l=16)
//   isis.csnp.lsp_seq_num == 0x00000099 (PSNP reuses the CSNP field names)
//   isis.csnp.lsp_remain_life == 321
//   isis.csnp.lsp_checksum == 0x5678
//   isis.csnp.lsp_id == 1122.3344.5566.0c-0d
const golden_psnp_l1_bytes = [_]u8{
    0x83, 0x11, 0x01, 0x06, 0x1a, 0x01, 0x00, 0x03,
    0x00, 0x23, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x00, 0x09, 0x10, 0x01, 0x41, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x0c, 0x0d, 0x00, 0x00, 0x00,
    0x99, 0x56, 0x78,
};

const golden_psnp_entry_id: store.LspId = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x0c, 0x0d };

fn buildPsnpEntry(b: *isis.pdu.PsnpBuilder) !void {
    const entries = [_]isis.tlvs.LspEntry{
        .{ .remaining_lifetime = 321, .lsp_id = golden_psnp_entry_id, .sequence_number = 0x99, .checksum = 0x5678 },
    };
    try isis.tlvs.addLspEntries(&b.tlvs, &entries);
}

test "golden PSNP LSP-Entry (Wireshark-anchored): our builder reproduces the exact bytes" {
    var buf: [64]u8 = undefined;
    var b = try isis.pdu.PsnpBuilder.init(&buf, .{
        .source_id = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00 },
    });
    try buildPsnpEntry(&b);
    try testing.expectEqualSlices(u8, &golden_psnp_l1_bytes, b.finish());
}

test "golden PSNP LSP-Entry (Wireshark-anchored): Lsdb.reconcilePsnp requests exactly this LSP-ID" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = .{ 0, 0, 0, 0, 0, 0xEE }, .interface_count = 2, .capacity = 8 });
    defer db.deinit();

    const psnp = try isis.Psnp.decode(&golden_psnp_l1_bytes);
    db.reconcilePsnp(psnp, 1, 0);

    // We lacked it → a zero-sequence request placeholder for exactly the
    // Wireshark-confirmed LSP-ID (pseudonode 0x0c, fragment 0x0d), SSN set.
    const view = db.get(golden_psnp_entry_id, 0).?;
    try testing.expect(view.is_request);
    try testing.expect(db.ssnSet(golden_psnp_entry_id).?.isSet(1));
}

// Golden 3b: L2 CSNP (PDU type 25) — the L2 CSNP type code, not exercised
// above (golden 2 used only is_l2 = false / type 24). Same LSP-Entry field
// values as golden 2, so the type code is the only variable.
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 21 01 06 19 01 00 03 00 33 11
//   22 33 44 55 66 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff 09 10 02
//   2b 11 22 33 44 55 66 09 0a 00 00 00 42 99 aa'
//
// Wireshark printed:
//   frame.protocols == "eth:llc:osi:isis:isis.csnp" (full CSNP dissection)
//   isis.type == 25 = ...1 1001 = PDU Type: L2 CSNP (25)
//   isis.csnp.pdu_length == 51 = PDU length: 51
//   isis.csnp.source_id == 1122.3344.5566
//   isis.csnp.lsp_seq_num == 0x00000042
//   isis.csnp.lsp_remain_life == 555
//   isis.csnp.lsp_checksum == 0x99aa
//   isis.csnp.lsp_id == 1122.3344.5566.09-0a
const golden_csnp_l2_bytes = [_]u8{
    0x83, 0x21, 0x01, 0x06, 0x19, 0x01, 0x00, 0x03,
    0x00, 0x33, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x09, 0x10, 0x02, 0x2b, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x09, 0x0a, 0x00, 0x00, 0x00,
    0x42, 0x99, 0xaa,
};

test "golden L2 CSNP LSP-Entry (Wireshark-anchored): our builder reproduces the exact bytes" {
    var buf: [64]u8 = undefined;
    var b = try isis.pdu.CsnpBuilder.init(&buf, .{
        .is_l2 = true,
        .source_id = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xff),
    });
    const entries = [_]isis.tlvs.LspEntry{
        .{ .remaining_lifetime = 555, .lsp_id = golden_csnp_entry_id, .sequence_number = 0x42, .checksum = 0x99aa },
    };
    try isis.tlvs.addLspEntries(&b.tlvs, &entries);
    try testing.expectEqualSlices(u8, &golden_csnp_l2_bytes, b.finish());
}

test "golden L2 CSNP LSP-Entry (Wireshark-anchored): Lsdb.reconcileCsnp recognizes the L2 type code and requests exactly this LSP-ID" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = .{ 0, 0, 0, 0, 0, 0xEE }, .interface_count = 2, .capacity = 8 });
    defer db.deinit();

    const csnp = try isis.Csnp.decode(&golden_csnp_l2_bytes);
    try testing.expectEqual(isis.header.PduType.l2_csnp, csnp.header.pdu_type);
    db.reconcileCsnp(csnp, 1, 0);

    const view = db.get(golden_csnp_entry_id, 0).?;
    try testing.expect(view.is_request);
    try testing.expect(db.ssnSet(golden_csnp_entry_id).?.isSet(1));
}

// Golden 3c: L2 PSNP (PDU type 27) — the L2 PSNP type code, not exercised
// above. Same LSP-Entry field values as golden 3a, so the type code is the
// only variable.
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 11 01 06 1b 01 00 03 00 23 11
//   22 33 44 55 66 00 09 10 01 41 11 22 33 44 55 66 0c 0d 00 00 00 99 56 78'
//
// Wireshark printed:
//   frame.protocols == "eth:llc:osi:isis:isis.psnp" (full PSNP dissection)
//   isis.type == 27 = ...1 1011 = PDU Type: L2 PSNP (27)
//   isis.psnp.pdu_length == 35 = PDU length: 35
//   isis.psnp.source_id == 1122.3344.5566
//   isis.csnp.lsp_seq_num == 0x00000099
//   isis.csnp.lsp_remain_life == 321
//   isis.csnp.lsp_checksum == 0x5678
//   isis.csnp.lsp_id == 1122.3344.5566.0c-0d
const golden_psnp_l2_bytes = [_]u8{
    0x83, 0x11, 0x01, 0x06, 0x1b, 0x01, 0x00, 0x03,
    0x00, 0x23, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x00, 0x09, 0x10, 0x01, 0x41, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x0c, 0x0d, 0x00, 0x00, 0x00,
    0x99, 0x56, 0x78,
};

test "golden L2 PSNP LSP-Entry (Wireshark-anchored): our builder reproduces the exact bytes" {
    var buf: [64]u8 = undefined;
    var b = try isis.pdu.PsnpBuilder.init(&buf, .{
        .is_l2 = true,
        .source_id = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00 },
    });
    try buildPsnpEntry(&b);
    try testing.expectEqualSlices(u8, &golden_psnp_l2_bytes, b.finish());
}

test "golden L2 PSNP LSP-Entry (Wireshark-anchored): Lsdb.reconcilePsnp recognizes the L2 type code and requests exactly this LSP-ID" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = .{ 0, 0, 0, 0, 0, 0xEE }, .interface_count = 2, .capacity = 8 });
    defer db.deinit();

    const psnp = try isis.Psnp.decode(&golden_psnp_l2_bytes);
    try testing.expectEqual(isis.header.PduType.l2_psnp, psnp.header.pdu_type);
    db.reconcilePsnp(psnp, 1, 0);

    const view = db.get(golden_psnp_entry_id, 0).?;
    try testing.expect(view.is_request);
    try testing.expect(db.ssnSet(golden_psnp_entry_id).?.isSet(1));
}
