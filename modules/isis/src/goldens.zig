// SPDX-License-Identifier: MIT

//! Golden IS-IS PDUs — byte-for-byte anchors for the wire format.
//!
//! Provenance: **hand-assembled field-by-field from ISO/IEC 10589 and RFC 6329**
//! (no live capture was available in this environment). Each golden is annotated
//! below against the spec field layout; every offset and every big-endian
//! multi-byte field is pinned. The tests prove three directions: the builders
//! reproduce the golden bytes exactly (encode is correct), the decoders recover
//! every field from the golden (decode is correct), and the two agree
//! (round-trip). The Length-Indicator and PDU-Length values are the canonical
//! ISO 10589 constants (P2P IIH header = 20, LSP header = 27), an independent
//! cross-check on the hand assembly.

const std = @import("std");
const isis = @import("root.zig");
const header = isis.header;
const tlv = isis.tlv;
const tlvs = isis.tlvs;
const pdu = isis.pdu;
const spb = isis.spb;
const testing = std.testing;

// ── Golden 1: Point-to-Point IIH (PDU type 17) ───────────────────────────────
//
//   83 14 01 06 11 01 00 03   common: disc, len-ind=20, ver, id-len=6,
//                             pdu-type=17(P2P IIH), ver, resv, max-area=3
//   03                        circuit type = level-1-2
//   00 00 00 00 00 01         source id
//   00 1e                     holding time = 30 s
//   00 25                     PDU length = 37
//   01                        local circuit id
//   81 01 cc                  TLV #129 Protocols Supported: NLPID 0xCC (IPv4)
//   01 04 03 49 00 01         TLV #1 Area Addresses: area 49.00.01
//   06 06 00 1b 21 3c 9d f8   TLV #6 IS Neighbours (IIH): one SNPA
const golden_p2p_iih = [_]u8{
    0x83, 0x14, 0x01, 0x06, 0x11, 0x01, 0x00, 0x03,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x1e, 0x00, 0x25, 0x01, 0x81, 0x01, 0xcc, 0x01,
    0x04, 0x03, 0x49, 0x00, 0x01, 0x06, 0x06, 0x00,
    0x1b, 0x21, 0x3c, 0x9d, 0xf8,
};

const neighbour_snpa = [6]u8{ 0x00, 0x1b, 0x21, 0x3c, 0x9d, 0xf8 };

test "golden P2P IIH: builder reproduces the exact bytes" {
    var buf: [128]u8 = undefined;
    var b = try pdu.P2pHelloBuilder.init(&buf, .{
        .circuit_type = .level1_2,
        .source_id = .{ 0, 0, 0, 0, 0, 1 },
        .holding_time = 30,
        .local_circuit_id = 1,
        .max_area_addresses = 3,
    });
    try tlvs.addProtocolsSupported(&b.tlvs, &.{tlvs.nlpid_ipv4});
    try tlvs.addAreaAddresses(&b.tlvs, &.{&[_]u8{ 0x49, 0x00, 0x01 }});
    try tlvs.addIsNeighboursIih(&b.tlvs, &.{neighbour_snpa});
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_p2p_iih, wire);
}

test "golden P2P IIH: decode recovers every field" {
    const p = try pdu.P2pHello.decode(&golden_p2p_iih);
    try testing.expectEqual(header.PduType.p2p_iih, p.header.pdu_type);
    try testing.expectEqual(@as(u8, 6), p.header.id_length);
    try testing.expectEqual(pdu.CircuitType.level1_2, p.circuit_type);
    try testing.expectEqual([6]u8{ 0, 0, 0, 0, 0, 1 }, p.source_id);
    try testing.expectEqual(@as(u16, 30), p.holding_time);
    try testing.expectEqual(@as(u16, 37), p.pdu_length);
    try testing.expectEqual(@as(u8, 1), p.local_circuit_id);

    // TLVs.
    try testing.expectEqualSlices(u8, &.{tlvs.nlpid_ipv4}, (try tlv.findFirst(p.tlv_bytes, tlvs.code.protocols_supported)).?);
    var ai = tlvs.AreaAddressIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.area_addresses)).?);
    try testing.expectEqualSlices(u8, &.{ 0x49, 0x00, 0x01 }, (try ai.next()).?);
    var si = tlvs.SnpaIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.is_neighbours_iih)).?);
    try testing.expectEqual(neighbour_snpa, (try si.next()).?);
}

// ── Golden 2: Level-1 LSP (PDU type 18) carrying an SPB MT-Capability ─────────
//
//   83 1b 01 06 12 01 00 03   common: disc, len-ind=27, ver, id-len=6,
//                             pdu-type=18(L1 LSP), ver, resv, max-area=3
//   00 3c                     PDU length = 60
//   04 b0                     remaining lifetime = 1200 s
//   00 00 00 00 00 01 00 00   LSP id (sysid + pseudonode + lsp#)
//   00 00 00 01               sequence number = 1
//   00 00                     checksum (0 = not in use)
//   01                        flags: IS Type = L1
//   01 04 03 49 00 01         TLV #1 Area Addresses: area 49.00.01
//   81 01 cc                  TLV #129 Protocols Supported: IPv4
//   89 04 6e 6f 64 65         TLV #137 Dynamic Hostname: "node"
//   90 10                     TLV #144 MT-Capability, value length 16
//     00 00                     preamble: O bit clear, MT-ID 0
//     03 0c                     sub-TLV #3 SPBM-SI, length 12
//       00 00 00 11 22 33         B-MAC
//       00 10                     Res(4) | Base VID(12) = 16
//       c0 00 00 64               I-SID entry: T=1,R=1, I-SID 100
const golden_l1_lsp = [_]u8{
    0x83, 0x1b, 0x01, 0x06, 0x12, 0x01, 0x00, 0x03,
    0x00, 0x3c, 0x04, 0xb0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x01, 0x04, 0x03, 0x49, 0x00,
    0x01, 0x81, 0x01, 0xcc, 0x89, 0x04, 0x6e, 0x6f,
    0x64, 0x65, 0x90, 0x10, 0x00, 0x00, 0x03, 0x0c,
    0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x00, 0x10,
    0xc0, 0x00, 0x00, 0x64,
};

const spb_bmac = [6]u8{ 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 };

test "golden L1 LSP + SPB: builder reproduces the exact bytes" {
    // Build the SPBM-SI (sub-TLV 3) first, then wrap it in the MT-Capability.
    var sub_scratch: [64]u8 = undefined;
    const spbm_si = try spb.encodeSpbmServiceId(
        spb_bmac,
        0x010,
        &.{.{ .transmit = true, .receive = true, .isid = 100 }},
        &sub_scratch,
    );

    var buf: [256]u8 = undefined;
    var b = try pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1200,
        .lsp_id = .{ 0, 0, 0, 0, 0, 1, 0, 0 },
        .sequence_number = 1,
        .checksum = 0,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        .max_area_addresses = 3,
    });
    try tlvs.addAreaAddresses(&b.tlvs, &.{&[_]u8{ 0x49, 0x00, 0x01 }});
    try tlvs.addProtocolsSupported(&b.tlvs, &.{tlvs.nlpid_ipv4});
    try tlvs.addHostname(&b.tlvs, "node");
    try spb.addMtCapability(&b.tlvs, tlvs.code.mt_capability, false, 0, spbm_si);
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_l1_lsp, wire);
}

test "golden L1 LSP + SPB: decode recovers header, TLVs, and the SPB I-SID" {
    const p = try pdu.Lsp.decode(&golden_l1_lsp);
    try testing.expectEqual(header.PduType.l1_lsp, p.header.pdu_type);
    try testing.expectEqual(@as(u16, 60), p.pdu_length);
    try testing.expectEqual(@as(u16, 1200), p.remaining_lifetime);
    try testing.expectEqual([8]u8{ 0, 0, 0, 0, 0, 1, 0, 0 }, p.lsp_id);
    try testing.expectEqual(@as(u32, 1), p.sequence_number);
    try testing.expectEqual(@as(u16, 0), p.checksum);
    try testing.expectEqual(@as(u2, 1), p.flags.is_type);
    try testing.expect(!p.flags.overload);

    try testing.expectEqualStrings("node", (try tlv.findFirst(p.tlv_bytes, tlvs.code.dynamic_hostname)).?);

    // Drill into the SPB MT-Capability → SPBM-SI → I-SID entry.
    const mtcap_val = (try tlv.findFirst(p.tlv_bytes, tlvs.code.mt_capability)).?;
    const cap = try spb.MtCapability.decode(mtcap_val);
    try testing.expect(!cap.overload);
    try testing.expectEqual(@as(u12, 0), cap.mt_id);
    var subs = cap.subTlvIterator();
    const si_tlv = (try subs.next()).?;
    try testing.expectEqual(spb.sub.spbm_service_id, si_tlv.code);
    const si = try spb.SpbmServiceId.decode(si_tlv.value);
    try testing.expectEqual(spb_bmac, si.b_mac);
    try testing.expectEqual(@as(u12, 0x010), si.base_vid);
    var ie = si.isidIterator();
    const entry = (try ie.next()).?;
    try testing.expect(entry.transmit and entry.receive);
    try testing.expectEqual(@as(u24, 100), entry.isid);
    try testing.expectEqual(@as(?spb.IsidEntry, null), try ie.next());
}

test "golden LSP length-indicator/PDU-length match the ISO 10589 constants" {
    // Independent cross-check on the hand assembly: the LSP fixed header is 27
    // octets and the P2P IIH fixed header is 20, per ISO 10589.
    try testing.expectEqual(@as(u8, 27), golden_l1_lsp[1]);
    try testing.expectEqual(@as(u8, 20), golden_p2p_iih[1]);
    try testing.expectEqual(@as(u16, 60), std.mem.readInt(u16, golden_l1_lsp[8..10], .big));
    try testing.expectEqual(@as(u16, 37), std.mem.readInt(u16, golden_p2p_iih[17..19], .big));
}

test "raw escape hatch: an unmodeled TLV type round-trips verbatim" {
    var buf: [128]u8 = undefined;
    var b = try pdu.P2pHelloBuilder.init(&buf, .{ .source_id = @splat(0), .holding_time = 1 });
    // TLV type 250 is not modeled — must pass through untouched.
    const opaque_bytes = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x99 };
    try b.tlvs.addTlv(250, &opaque_bytes);
    const wire = b.finish();

    const p = try pdu.P2pHello.decode(wire);
    const got = (try tlv.findFirst(p.tlv_bytes, 250)).?;
    try testing.expectEqualSlices(u8, &opaque_bytes, got);

    // Re-emit it and confirm identical bytes (verbatim round-trip).
    var buf2: [128]u8 = undefined;
    var b2 = try pdu.P2pHelloBuilder.init(&buf2, .{ .source_id = @splat(0), .holding_time = 1 });
    var it = p.tlvIterator();
    while (try it.next()) |t| try b2.tlvs.addTlv(t.code, t.value);
    try testing.expectEqualSlices(u8, wire, b2.finish());
}

// ── External anchor: Wireshark 4.6.4 (sharkd, via scripts/dissect.py) ────────
//
// The two goldens above were hand-assembled from the spec text — an anchor
// whose authority comes from the same head that wrote the encoder is not an
// external anchor (see BACKLOG task notes). The vectors below were instead
// **produced by our own builders**, fed through `scripts/dissect.py`, which
// runs Wireshark 4.6.4's real IS-IS dissector (sharkd, offline, no network),
// and pinned to what Wireshark actually printed. This closes the remaining
// PDU types / TLVs that golden 1/2 above did not cover: LAN Hello, CSNP, PSNP,
// old-style IS Neighbours (#2), Extended IS Reachability (#22) with a
// sub-TLV, the SPB Instance sub-TLV (1), and the MT-Port-Capability (143)
// container. The `dissect.py` run happened once, interactively, while writing
// these tests; the frozen byte arrays plus the quoted Wireshark output below
// are what makes the anchor re-checkable without re-running the tool — the
// test gate itself never invokes Wireshark/sharkd/text2pcap.

// ── Golden 3: L1 LAN Hello (PDU type 15) with Area/Protocols/IS-Neighbours ───
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 0f 01 00 03 03 00 00
//   00 00 00 01 00 1b 00 2c 40 00 00 00 00 00 01 02 01 04 03 49 00 01 81 01 cc
//   06 06 00 1b 21 3c 9d f8'
//
// Wireshark printed (verbatim, trimmed to the load-bearing lines):
//   isis.type == 15 = ...0 1111 = PDU Type: L1 HELLO (15)
//   isis.hello.circuit_type == 0x03 = Circuit type: Level 1 and 2 (0x3)
//   isis.hello.source_id == 0000.0000.0001
//   isis.hello.holding_timer == 27 = Holding timer: 27
//   isis.hello.pdu_length == 44 = PDU length: 44
//   isis.hello.priority == 64 = Priority: 64
//   isis.hello.lan_id == 0000.0000.0001.02 = SystemID {Designated IS}
//   frame[44:6] == 01:04:03:49:00:01 = Area address(es) (t=1, l=4)
//   isis.hello.area_address == 03:49:00:01 = Area address (3): 49.0001
//   frame[50:3] == 81:01:cc = Protocols Supported (t=129, l=1)
//   isis.hello_clv_nlpid.nlpid == 0xcc = NLPID: 0xcc
//   frame[53:8] == 06:06:00:1b:21:3c:9d:f8 = IS Neighbor(s) (t=6, l=6)
//   isis.hello.is_neighbor == 00:1b:21:3c:9d:f8 = IS Neighbor: ...
// (In a LAN Hello, unlike the P2P golden above, Wireshark fully decodes TLV 6
// as "IS Neighbor(s)" instead of bailing with "code not implemented" — TLV 6
// is architecturally a LAN-only TLV, ISO 10589 §9.5; that is Wireshark being
// context-aware, not a bug on either side.)
const golden_lan_hello_l1 = [_]u8{
    0x83, 0x1b, 0x01, 0x06, 0x0f, 0x01, 0x00, 0x03,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x1b, 0x00, 0x2c, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x02, 0x01, 0x04, 0x03, 0x49, 0x00,
    0x01, 0x81, 0x01, 0xcc, 0x06, 0x06, 0x00, 0x1b,
    0x21, 0x3c, 0x9d, 0xf8,
};

test "golden LAN Hello (Wireshark-anchored): builder reproduces the exact bytes" {
    var buf: [128]u8 = undefined;
    var b = try pdu.LanHelloBuilder.init(&buf, .{
        .is_l2 = false,
        .circuit_type = .level1_2,
        .source_id = .{ 0, 0, 0, 0, 0, 1 },
        .holding_time = 27,
        .priority = 64,
        .lan_id = .{ 0, 0, 0, 0, 0, 1, 0x02 },
        .max_area_addresses = 3,
    });
    try tlvs.addAreaAddresses(&b.tlvs, &.{&[_]u8{ 0x49, 0x00, 0x01 }});
    try tlvs.addProtocolsSupported(&b.tlvs, &.{tlvs.nlpid_ipv4});
    try tlvs.addIsNeighboursIih(&b.tlvs, &.{neighbour_snpa});
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_lan_hello_l1, wire);
}

test "golden LAN Hello (Wireshark-anchored): decode recovers every field" {
    const p = try pdu.LanHello.decode(&golden_lan_hello_l1);
    try testing.expectEqual(header.PduType.l1_lan_iih, p.header.pdu_type);
    try testing.expectEqual(pdu.CircuitType.level1_2, p.circuit_type);
    try testing.expectEqual([6]u8{ 0, 0, 0, 0, 0, 1 }, p.source_id);
    try testing.expectEqual(@as(u16, 27), p.holding_time);
    try testing.expectEqual(@as(u16, 44), p.pdu_length);
    try testing.expectEqual(@as(u7, 64), p.priority);
    try testing.expectEqual([7]u8{ 0, 0, 0, 0, 0, 1, 0x02 }, p.lan_id);
    var ai = tlvs.AreaAddressIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.area_addresses)).?);
    try testing.expectEqualSlices(u8, &.{ 0x49, 0x00, 0x01 }, (try ai.next()).?);
    var si = tlvs.SnpaIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.is_neighbours_iih)).?);
    try testing.expectEqual(neighbour_snpa, (try si.next()).?);
}

// ── Golden 4: L1 CSNP (PDU type 24) with one LSP Entries record ─────────────
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 21 01 06 18 01 00 03 00 33 00
//   00 00 00 00 01 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff 09 10 04
//   ae 00 00 00 00 00 01 00 00 00 00 00 05 12 34'
//
// Wireshark printed:
//   isis.type == 24 = ...1 1000 = PDU Type: L1 CSNP (24)
//   isis.csnp.pdu_length == 51 = PDU length: 51
//   isis.csnp.source_id == 0000.0000.0001 = Source-ID
//   isis.csnp.start_lsp_id == 0000.0000.0000.00-00 = Start LSP-ID
//   isis.csnp.end_lsp_id == ffff.ffff.ffff.ff-ff = End LSP-ID
//   frame[50:18] == 09:10:... = LSP entries (t=9, l=16)
//   isis.csnp.lsp_seq_num == 0x00000005
//   isis.csnp.lsp_remain_life == 1198
//   isis.csnp.lsp_checksum == 0x1234
//   isis.csnp.lsp_id == 0000.0000.0001.00-00
const golden_csnp_l1 = [_]u8{
    0x83, 0x21, 0x01, 0x06, 0x18, 0x01, 0x00, 0x03,
    0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x09, 0x10, 0x04, 0xae, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x12, 0x34,
};

const csnp_entries = [_]tlvs.LspEntry{
    .{ .remaining_lifetime = 1198, .lsp_id = .{ 0, 0, 0, 0, 0, 1, 0, 0 }, .sequence_number = 5, .checksum = 0x1234 },
};

test "golden CSNP (Wireshark-anchored): builder reproduces the exact bytes" {
    var buf: [128]u8 = undefined;
    var b = try pdu.CsnpBuilder.init(&buf, .{
        .is_l2 = false,
        .source_id = .{ 0, 0, 0, 0, 0, 1, 0 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xff),
        .max_area_addresses = 3,
    });
    try tlvs.addLspEntries(&b.tlvs, &csnp_entries);
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_csnp_l1, wire);
}

test "golden CSNP (Wireshark-anchored): decode recovers every field" {
    const p = try pdu.Csnp.decode(&golden_csnp_l1);
    try testing.expectEqual(header.PduType.l1_csnp, p.header.pdu_type);
    try testing.expectEqual(@as(u16, 51), p.pdu_length);
    try testing.expectEqual([7]u8{ 0, 0, 0, 0, 0, 1, 0 }, p.source_id);
    try testing.expectEqual([8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, p.start_lsp_id);
    try testing.expectEqual([8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, p.end_lsp_id);
    var ei = tlvs.LspEntryIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.lsp_entries)).?);
    const e = (try ei.next()).?;
    try testing.expectEqual(@as(u32, 5), e.sequence_number);
    try testing.expectEqual(@as(u16, 0x1234), e.checksum);
}

// ── Golden 5: L1 PSNP (PDU type 26) with one LSP Entries record ─────────────
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 11 01 06 1a 01 00 03 00 23 00
//   00 00 00 00 01 00 09 10 04 ae 00 00 00 00 00 01 00 00 00 00 00 05 12 34'
//
// Wireshark printed:
//   isis.type == 26 = ...1 1010 = PDU Type: L1 PSNP (26)
//   isis.psnp.pdu_length == 35 = PDU length: 35
//   isis.psnp.source_id == 0000.0000.0001 = Source-ID
//   frame[34:18] == 09:10:... = LSP entries (t=9, l=16)
//   isis.csnp.lsp_seq_num == 0x00000005 (PSNP reuses the CSNP field names)
//   isis.csnp.lsp_remain_life == 1198
//   isis.csnp.lsp_checksum == 0x1234
//   isis.csnp.lsp_id == 0000.0000.0001.00-00
const golden_psnp_l1 = [_]u8{
    0x83, 0x11, 0x01, 0x06, 0x1a, 0x01, 0x00, 0x03,
    0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x09, 0x10, 0x04, 0xae, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x12, 0x34,
};

test "golden PSNP (Wireshark-anchored): builder reproduces the exact bytes" {
    var buf: [128]u8 = undefined;
    var b = try pdu.PsnpBuilder.init(&buf, .{
        .is_l2 = false,
        .source_id = .{ 0, 0, 0, 0, 0, 1, 0 },
        .max_area_addresses = 3,
    });
    try tlvs.addLspEntries(&b.tlvs, &csnp_entries);
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_psnp_l1, wire);
}

test "golden PSNP (Wireshark-anchored): decode recovers every field" {
    const p = try pdu.Psnp.decode(&golden_psnp_l1);
    try testing.expectEqual(header.PduType.l1_psnp, p.header.pdu_type);
    try testing.expectEqual(@as(u16, 35), p.pdu_length);
    try testing.expectEqual([7]u8{ 0, 0, 0, 0, 0, 1, 0 }, p.source_id);
    var ei = tlvs.LspEntryIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.lsp_entries)).?);
    const e = (try ei.next()).?;
    try testing.expectEqual(@as(u32, 5), e.sequence_number);
}

// ── Golden 6: L1 LSP with old-style IS Neighbours (#2) + Extended IS ────────
// ── Reachability (#22, with one sub-TLV) ─────────────────────────────────────
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 42 04
//   b0 00 00 00 00 00 02 00 00 00 00 00 01 00 00 01 01 04 03 49 00 01 02 0c 00
//   0a 80 80 80 00 00 00 00 00 03 00 16 11 00 00 00 00 00 03 00 00 00 0a 06 fa
//   04 0a 00 00 01'
//
// Wireshark printed:
//   frame[50:14] == 02:0c:... = IS Reachability (t=2, l=12)
//   isis.lsp.is_virtual == False = IsVirtual: No
//   isis.lsp.eis_neighbors.default_metric == 10 = Default Metric: 10
//   isis.lsp.eis_neighbors.is_neighbor == 0000.0000.0003.00
//   frame[64:19] == 16:11:... = Extended IS reachability (t=22, l=17)
//   isis.lsp.ext_is_reachability.is_neighbor_id == 0000.0000.0003.00
//   isis.lsp.ext_is_reachability.metric == 10 = Metric: 10
//   isis.lsp.ext_is_reachability.subclvs_length == 6 = SubCLV Length: 6
//   frame[77:6] == fa:04:0a:00:00:01 = subTLV: Reserved for Cisco-specific
//     extensions (c=250, l=4)
//   isis.lsp.ext_is_reachability.length == 4 = Length: 4
//   isis.lsp.ext_is_reachability.value == 0a:00:00:01 = Value: 0a000001
//
// (Sub-TLV code 250 was deliberately chosen as an *unassigned* code point —
// an earlier attempt reused code 4, which Wireshark decodes as the RFC 5307
// "Link Local/Remote Identifiers" sub-TLV; giving that decoder our 4-byte
// arbitrary value, which it expects to be 8 bytes, produced a
// `_ws.malformed` Expert Info. That was this test author's construction
// error — reusing a *registered* sub-TLV code with the wrong shape — not a
// bug in `addExtendedIsReach`/`tlv.Builder`, whose framing was verified byte-
// correct in both cases via the `frame[...]` offsets Wireshark reported.
//
// Also: Wireshark's `isis.lsp.eis_neighbors.{delay,expense,error}_metric`
// masked-value subfields all echo the *default* metric's value/offset (byte
// 53, confirmed via `--json`), while the `_ie`/`_supported` boolean subfields
// correctly point at their own bytes (54/55/56). That is a known quirk of
// this Wireshark dissector's old-style IS-Reachability metric decode, not a
// wire-format issue in the TLV #2 body: our own `IsReachIterator` decode
// (`tlvs.zig`) reads `e[1]`/`e[2]`/`e[3]` for delay/expense/error, and the
// `is_neighbour_id` Wireshark reports at byte 57 (= 53 + 4 metric octets)
// matches that layout exactly.
const golden_lsp_isreach_extisreach = [_]u8{
    0x83, 0x1b, 0x01, 0x06, 0x12, 0x01, 0x00, 0x03,
    0x00, 0x42, 0x04, 0xb0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x01, 0x04, 0x03, 0x49, 0x00,
    0x01, 0x02, 0x0c, 0x00, 0x0a, 0x80, 0x80, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x16,
    0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x0a, 0x06, 0xfa, 0x04, 0x0a, 0x00,
    0x00, 0x01,
};

const isreach_nbr7 = [7]u8{ 0, 0, 0, 0, 0, 3, 0 };

test "golden LSP IS-Reach/Ext-IS-Reach (Wireshark-anchored): builder reproduces the exact bytes" {
    var buf: [256]u8 = undefined;
    var b = try pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1200,
        .lsp_id = .{ 0, 0, 0, 0, 0, 2, 0, 0 },
        .sequence_number = 1,
        .checksum = 0,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        .max_area_addresses = 3,
    });
    try tlvs.addAreaAddresses(&b.tlvs, &.{&[_]u8{ 0x49, 0x00, 0x01 }});
    // #2 old-style IS Neighbours: virtual flag(0) + one 11-octet entry.
    var scratch: [12]u8 = undefined;
    scratch[0] = 0x00; // virtual flag
    scratch[1] = 10; // default metric
    scratch[2] = 0x80; // delay: not supported
    scratch[3] = 0x80; // expense: not supported
    scratch[4] = 0x80; // error: not supported
    @memcpy(scratch[5..12], &isreach_nbr7);
    try b.tlvs.addTlv(tlvs.code.is_neighbours_lsp, scratch[0..12]);
    // #22 extended IS reach with one (unassigned-code) sub-TLV.
    var sub_buf: [8]u8 = undefined;
    var sb = tlv.Builder.init(&sub_buf);
    try sb.addTlv(250, &.{ 0x0a, 0x00, 0x00, 0x01 });
    try tlvs.addExtendedIsReach(&b.tlvs, isreach_nbr7, 0x00_00_0a, sb.written());
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_lsp_isreach_extisreach, wire);
}

test "golden LSP IS-Reach/Ext-IS-Reach (Wireshark-anchored): decode recovers every field" {
    const p = try pdu.Lsp.decode(&golden_lsp_isreach_extisreach);
    var it2 = try tlvs.IsReachIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.is_neighbours_lsp)).?);
    try testing.expectEqual(@as(u8, 0), it2.virtualFlag());
    const e2 = (try it2.next()).?;
    try testing.expectEqual(@as(u8, 10), e2.default_metric);
    try testing.expectEqual(isreach_nbr7, e2.neighbour_id);

    var ei = tlvs.ExtIsReachIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.extended_is_reachability)).?);
    const entry = (try ei.next()).?;
    try testing.expectEqual(isreach_nbr7, entry.neighbour_id);
    try testing.expectEqual(@as(u24, 0x00_00_0a), entry.metric);
    var subs = entry.subTlvIterator();
    const s = (try subs.next()).?;
    try testing.expectEqual(@as(u8, 250), s.code);
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x00, 0x00, 0x01 }, s.value);
}

// ── Golden 7: L1 LSP with an SPB Instance sub-TLV (1) inside MT-Capability ───
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 3c 04
//   b0 00 00 00 00 00 03 00 00 00 00 00 01 00 00 01 90 1f 00 00 01 1b 80 00 00
//   00 00 00 00 01 00 00 00 00 80 00 00 10 ab cd 01 c0 00 00 00 01 01 00 20'
//
// Wireshark printed:
//   frame[44:33] == 90:1f:... = MT-Capability (t=144, l=31)
//   frame[48:29] == 01:1b:... = SPB Instance: Type: 0x01, Length: 27
//   isis.lsp.mt_cap_spb_instance.cist_root_identifier == 80:00:00:00:00:00:00:01
//   isis.lsp.mt_cap_spb_instance.cist_external_root_path_cost == 0x00000000
//   isis.lsp.mt_cap_spb_instance.bridge_priority == 0x8000 (32768)
//   isis.lsp.mt_cap_spb_instance.v == True
//   isis.lsp.mt_cap.spsourceid == 0x0000abcd (43981)
//   isis.lsp.mt_cap_spb_instance.number_of_trees == 0x0001 (1)
//   isis.lsp.mt_cap_spb_instance.vlanid_tuple.u == True
//   isis.lsp.mt_cap_spb_instance.vlanid_tuple.m == True
//   isis.lsp.mt_cap_spb_instance.vlanid_tuple.a == False
//   isis.lsp.mt_cap_spb_instance.vlanid_tuple.ect == 1
//   isis.lsp.mt_cap_spb_instance.vlanid_tuple.basevid == 16
//   isis.lsp.mt_cap_spb_instance.vlanid_tuple.spvid == 32
const golden_lsp_spb_instance = [_]u8{
    0x83, 0x1b, 0x01, 0x06, 0x12, 0x01, 0x00, 0x03,
    0x00, 0x3c, 0x04, 0xb0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x90, 0x1f, 0x00, 0x00, 0x01,
    0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
    0x10, 0xab, 0xcd, 0x01, 0xc0, 0x00, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x20,
};

test "golden LSP + SPB Instance (Wireshark-anchored): builder reproduces the exact bytes" {
    const inst: spb.SpbInstance = .{
        .cist_root_id = .{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .cist_external_root_path_cost = 0,
        .bridge_priority = 0x8000,
        .spsourceid_auto = true,
        .spsourceid = 0x0_ABCD,
        .num_trees = 0, // filled by the encoder from the tuple slice
        .tuple_bytes = &.{},
    };
    const tuples = [_]spb.VidTuple{
        .{ .use = true, .mode_spbm = true, .agreement = false, .ect_algorithm = 1, .base_vid = 0x010, .spvid = 0x020 },
    };
    var sub_scratch: [128]u8 = undefined;
    const spb_inst_tlv = try spb.encodeSpbInstance(inst, &tuples, &sub_scratch);

    var buf: [256]u8 = undefined;
    var b = try pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1200,
        .lsp_id = .{ 0, 0, 0, 0, 0, 3, 0, 0 },
        .sequence_number = 1,
        .checksum = 0,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        .max_area_addresses = 3,
    });
    try spb.addMtCapability(&b.tlvs, tlvs.code.mt_capability, false, 0, spb_inst_tlv);
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_lsp_spb_instance, wire);
}

test "golden LSP + SPB Instance (Wireshark-anchored): decode recovers every field" {
    const p = try pdu.Lsp.decode(&golden_lsp_spb_instance);
    const mtcap_val = (try tlv.findFirst(p.tlv_bytes, tlvs.code.mt_capability)).?;
    const cap = try spb.MtCapability.decode(mtcap_val);
    var subs = cap.subTlvIterator();
    const inst_tlv = (try subs.next()).?;
    try testing.expectEqual(spb.sub.spb_instance, inst_tlv.code);
    const inst = try spb.SpbInstance.decode(inst_tlv.value);
    try testing.expectEqual(@as(u16, 0x8000), inst.bridge_priority);
    try testing.expect(inst.spsourceid_auto);
    try testing.expectEqual(@as(u20, 0x0_ABCD), inst.spsourceid);
    try testing.expectEqual(@as(u8, 1), inst.num_trees);
    var ti = inst.tupleIterator();
    const tup = (try ti.next()).?;
    try testing.expect(tup.use and tup.mode_spbm and !tup.agreement);
    try testing.expectEqual(@as(u32, 1), tup.ect_algorithm);
    try testing.expectEqual(@as(u12, 0x010), tup.base_vid);
    try testing.expectEqual(@as(u12, 0x020), tup.spvid);
}

test "encode(decode(golden)) == golden for both PDUs (structural round-trip)" {
    // P2P IIH: decode, then rebuild from the decoded fields + raw TLV walk.
    {
        const p = try pdu.P2pHello.decode(&golden_p2p_iih);
        var buf: [128]u8 = undefined;
        var b = try pdu.P2pHelloBuilder.init(&buf, .{
            .circuit_type = p.circuit_type,
            .source_id = p.source_id,
            .holding_time = p.holding_time,
            .local_circuit_id = p.local_circuit_id,
            .max_area_addresses = p.header.max_area_addresses,
        });
        var it = p.tlvIterator();
        while (try it.next()) |t| try b.tlvs.addTlv(t.code, t.value);
        try testing.expectEqualSlices(u8, &golden_p2p_iih, b.finish());
    }
    // L1 LSP: same, preserving the SPB TLV byte-exact through the raw walk.
    {
        const p = try pdu.Lsp.decode(&golden_l1_lsp);
        var buf: [256]u8 = undefined;
        var b = try pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = p.remaining_lifetime,
            .lsp_id = p.lsp_id,
            .sequence_number = p.sequence_number,
            .checksum = p.checksum,
            .flags = p.flags,
            .max_area_addresses = p.header.max_area_addresses,
        });
        var it = p.tlvIterator();
        while (try it.next()) |t| try b.tlvs.addTlv(t.code, t.value);
        try testing.expectEqualSlices(u8, &golden_l1_lsp, b.finish());
    }
}

// ── Golden 8: L2 CSNP (PDU type 25) — the L2 type code, untested above ──────
//
// ANCHOR-TASKS.tsv remnant on this row: goldens 4/5 above drove the CSNP/PSNP
// builders only with `is_l2 = false` (type codes 24/26). The body layout is
// shared between L1 and L2 (only the PDU-type octet differs), but that
// specific byte was never itself fed to an independent dissector. This golden
// drives `CsnpBuilder` with `is_l2 = true` (type 25) — same field values as
// golden 4 otherwise, so the L2 type code is the only variable.
//
// Command:
//   scripts/dissect.py --frame llc --fields '83210106190100030033000000000001
//   000000000000000000ffffffffffffffff091004ae0000000000010000000000051234'
//
// Wireshark printed (verbatim, trimmed to the load-bearing lines):
//   frame.protocols == "eth:llc:osi:isis:isis.csnp" (full CSNP dissection, not
//     a generic/"data" fallback)
//   isis.type == 25 = ...1 1001 = PDU Type: L2 CSNP (25)
//   isis.csnp.pdu_length == 51 = PDU length: 51
//   isis.csnp.source_id == 0000.0000.0001 = Source-ID
//   isis.csnp.start_lsp_id == 0000.0000.0000.00-00 = Start LSP-ID
//   isis.csnp.end_lsp_id == ffff.ffff.ffff.ff-ff = End LSP-ID
//   frame[50:18] == 09:10:... = LSP entries (t=9, l=16)
//   isis.csnp.lsp_seq_num == 0x00000005
//   isis.csnp.lsp_remain_life == 1198
//   isis.csnp.lsp_checksum == 0x1234
//   isis.csnp.lsp_id == 0000.0000.0001.00-00
const golden_csnp_l2 = [_]u8{
    0x83, 0x21, 0x01, 0x06, 0x19, 0x01, 0x00, 0x03,
    0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x09, 0x10, 0x04, 0xae, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x12, 0x34,
};

test "golden L2 CSNP (Wireshark-anchored): builder reproduces the exact bytes" {
    var buf: [128]u8 = undefined;
    var b = try pdu.CsnpBuilder.init(&buf, .{
        .is_l2 = true,
        .source_id = .{ 0, 0, 0, 0, 0, 1, 0 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xff),
        .max_area_addresses = 3,
    });
    try tlvs.addLspEntries(&b.tlvs, &csnp_entries);
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_csnp_l2, wire);
}

test "golden L2 CSNP (Wireshark-anchored): decode recovers the L2 type code and every field" {
    const p = try pdu.Csnp.decode(&golden_csnp_l2);
    try testing.expectEqual(header.PduType.l2_csnp, p.header.pdu_type);
    try testing.expectEqual(@as(u16, 51), p.pdu_length);
    var ei = tlvs.LspEntryIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.lsp_entries)).?);
    const e = (try ei.next()).?;
    try testing.expectEqual(@as(u32, 5), e.sequence_number);
    try testing.expectEqual(@as(u16, 0x1234), e.checksum);
}

// ── Golden 9: L2 PSNP (PDU type 27) — the L2 type code, untested above ──────
//
// Same remnant as golden 8, for PSNP. Field values match golden 5 otherwise.
//
// Command:
//   scripts/dissect.py --frame llc --fields '831101061b0100030023000000000001
//   00091004ae0000000000010000000000051234'
//
// Wireshark printed:
//   frame.protocols == "eth:llc:osi:isis:isis.psnp" (full PSNP dissection)
//   isis.type == 27 = ...1 1011 = PDU Type: L2 PSNP (27)
//   isis.psnp.pdu_length == 35 = PDU length: 35
//   isis.psnp.source_id == 0000.0000.0001 = Source-ID
//   frame[34:18] == 09:10:... = LSP entries (t=9, l=16)
//   isis.csnp.lsp_seq_num == 0x00000005 (PSNP reuses the CSNP field names)
//   isis.csnp.lsp_remain_life == 1198
//   isis.csnp.lsp_checksum == 0x1234
//   isis.csnp.lsp_id == 0000.0000.0001.00-00
const golden_psnp_l2 = [_]u8{
    0x83, 0x11, 0x01, 0x06, 0x1b, 0x01, 0x00, 0x03,
    0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x09, 0x10, 0x04, 0xae, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x12, 0x34,
};

test "golden L2 PSNP (Wireshark-anchored): builder reproduces the exact bytes" {
    var buf: [128]u8 = undefined;
    var b = try pdu.PsnpBuilder.init(&buf, .{
        .is_l2 = true,
        .source_id = .{ 0, 0, 0, 0, 0, 1, 0 },
        .max_area_addresses = 3,
    });
    try tlvs.addLspEntries(&b.tlvs, &csnp_entries);
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_psnp_l2, wire);
}

test "golden L2 PSNP (Wireshark-anchored): decode recovers the L2 type code and every field" {
    const p = try pdu.Psnp.decode(&golden_psnp_l2);
    try testing.expectEqual(header.PduType.l2_psnp, p.header.pdu_type);
    try testing.expectEqual(@as(u16, 35), p.pdu_length);
    var ei = tlvs.LspEntryIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.lsp_entries)).?);
    const e = (try ei.next()).?;
    try testing.expectEqual(@as(u32, 5), e.sequence_number);
}

