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
