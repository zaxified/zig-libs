// SPDX-License-Identifier: MIT

//! Tests that came out of the 2026-11-17 whole-module mutation of `isis`: each
//! one pins a boundary, an offset or a flag bit that the older suites left
//! unobserved (exact-fit buffers, byte order of fields whose test values were
//! symmetric, fields only ever built with their defaults).

const std = @import("std");
const isis = @import("root.zig");
const testing = std.testing;

const header = isis.header;
const tlv = isis.tlv;
const tlvs = isis.tlvs;
const pdu = isis.pdu;
const spb = isis.spb;
const checksum = isis.checksum;

const src6 = [6]u8{ 1, 2, 3, 4, 5, 6 };
const lan7 = [7]u8{ 1, 2, 3, 4, 5, 6, 7 };
const lsp_id = [8]u8{ 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8 };

// -- checksum ---------------------------------------------------------------

test "checksum.compute refuses a buffer shorter than the two checksum octets" {
    try testing.expectError(error.ChecksumFieldOutOfRange, checksum.compute(&.{}, 0));
    try testing.expectError(error.ChecksumFieldOutOfRange, checksum.compute(&.{0x01}, 0));
    _ = try checksum.compute(&.{ 0x01, 0x02 }, 0);
}

test "checksum.verify needs both accumulators zero" {
    // [1, 253]: C0 = 254, C1 = 255 = 0 (mod 255): only C1 vanishes.
    try testing.expect(!checksum.verify(&.{ 1, 253 }));
    // [1, 254]: C0 = 0, C1 = 1: only C0 vanishes.
    try testing.expect(!checksum.verify(&.{ 1, 254 }));
}

// -- common header ----------------------------------------------------------

test "header.decode: length indicator 8, a non-default max-area and the reserved octet" {
    const w = [_]u8{ 0x83, 8, 1, 6, 0x11, 1, 0x5A, 5 };
    const h = try header.decode(&w);
    try testing.expectEqual(@as(u8, 8), h.length_indicator);
    try testing.expectEqual(@as(u8, 5), h.max_area_addresses);
    try testing.expectEqual(@as(u8, 0x5A), h.reserved);
}

test "header.encode refuses a buffer shorter than 8 octets and accepts exactly 8" {
    const h: header.CommonHeader = .{ .length_indicator = 20, .pdu_type = .p2p_iih, .id_length = 6, .max_area_addresses = 3 };
    var small: [7]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, header.encode(h, &small));
    try testing.expectError(error.BufferTooSmall, header.encode(h, small[0..0]));
    var exact: [8]u8 = undefined;
    try header.encode(h, &exact);
}

test "PduType.isHello is true for each of the three hello types only" {
    try testing.expect(header.PduType.l1_lan_iih.isHello());
    try testing.expect(header.PduType.l2_lan_iih.isHello());
    try testing.expect(header.PduType.p2p_iih.isHello());
    try testing.expect(!header.PduType.l1_lsp.isHello());
    try testing.expect(!header.PduType.l2_psnp.isHello());
}

// -- TLV framework ----------------------------------------------------------

test "TlvIterator.reset restarts the walk" {
    const bytes = [_]u8{ 1, 1, 0xAA, 2, 0 };
    var it = tlv.TlvIterator.init(&bytes);
    _ = try it.next();
    _ = try it.next();
    try testing.expect((try it.next()) == null);
    it.reset();
    const first = (try it.next()).?;
    try testing.expectEqual(@as(u8, 1), first.code);
}

test "Builder.addTlv fits exactly and refuses one octet less; remaining counts down" {
    var buf: [5]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    try testing.expectEqual(@as(usize, 5), b.remaining());
    try b.addTlv(7, &.{ 1, 2, 3 });
    try testing.expectEqual(@as(usize, 0), b.remaining());
    try testing.expectEqual(@as(usize, 5), b.written().len);
    var b2 = tlv.Builder.init(buf[0..4]);
    try testing.expectError(error.BufferTooSmall, b2.addTlv(7, &.{ 1, 2, 3 }));
}

// -- typed TLVs -------------------------------------------------------------

test "addAreaAddresses: a 254-octet area fills the TLV exactly, 255 is refused" {
    var buf: [300]u8 = undefined;
    const a254: [254]u8 = @splat(0xAB);
    var b = tlv.Builder.init(&buf);
    try tlvs.addAreaAddresses(&b, &.{&a254});
    try testing.expectEqual(@as(u8, 255), b.written()[1]);
    const a255: [255]u8 = @splat(0xAB);
    var b2 = tlv.Builder.init(&buf);
    try testing.expectError(error.ValueTooLong, tlvs.addAreaAddresses(&b2, &.{&a255}));
}

test "addIsNeighboursIih: 42 SNPAs fit, the 43rd is refused" {
    var buf: [300]u8 = undefined;
    const macs: [43][6]u8 = @splat(src6);
    var b = tlv.Builder.init(&buf);
    try tlvs.addIsNeighboursIih(&b, macs[0..42]);
    try testing.expectEqual(@as(u8, 252), b.written()[1]);
    var b2 = tlv.Builder.init(&buf);
    try testing.expectError(error.ValueTooLong, tlvs.addIsNeighboursIih(&b2, macs[0..43]));
}

test "IsReachIterator: the flag-only value, and four distinct metrics" {
    var empty = try tlvs.IsReachIterator.init(&.{0x00});
    try testing.expect((try empty.next()) == null);
    try testing.expectError(error.BadTlvLength, tlvs.IsReachIterator.init(&.{}));

    const v = [_]u8{ 0x80, 1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16 };
    var it = try tlvs.IsReachIterator.init(&v);
    try testing.expectEqual(@as(u8, 0x80), it.virtualFlag());
    const e = (try it.next()).?;
    try testing.expectEqual(@as(u8, 1), e.default_metric);
    try testing.expectEqual(@as(u8, 2), e.delay_metric);
    try testing.expectEqual(@as(u8, 3), e.expense_metric);
    try testing.expectEqual(@as(u8, 4), e.error_metric);
    try testing.expectEqual([7]u8{ 10, 11, 12, 13, 14, 15, 16 }, e.neighbour_id);
    try testing.expect((try it.next()) == null);
}

test "ExtIsReachIterator accepts an entry that ends exactly at the value end" {
    const v = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 0, 0, 9, 0 };
    var it = tlvs.ExtIsReachIterator.init(&v);
    const e = (try it.next()).?;
    try testing.expectEqual(@as(u24, 9), e.metric);
    try testing.expectEqual(@as(usize, 0), e.sub_tlvs.len);
    try testing.expect((try it.next()) == null);
}

test "addExtendedIsReach: 244 sub-TLV octets fill the TLV exactly, 245 is refused" {
    var buf: [400]u8 = undefined;
    const sub: [245]u8 = @splat(0x55);
    var b = tlv.Builder.init(&buf);
    try tlvs.addExtendedIsReach(&b, lan7, 5, sub[0..244]);
    try testing.expectEqual(@as(u8, 255), b.written()[1]);
    var b2 = tlv.Builder.init(&buf);
    try testing.expectError(error.ValueTooLong, tlvs.addExtendedIsReach(&b2, lan7, 5, sub[0..245]));
}

test "addLspEntries: 15 entries fit, the 16th is refused" {
    var buf: [400]u8 = undefined;
    const e: tlvs.LspEntry = .{ .remaining_lifetime = 1, .lsp_id = lsp_id, .sequence_number = 2, .checksum = 3 };
    const entries: [16]tlvs.LspEntry = @splat(e);
    var b = tlv.Builder.init(&buf);
    try tlvs.addLspEntries(&b, entries[0..15]);
    try testing.expectEqual(@as(u8, 240), b.written()[1]);
    var b2 = tlv.Builder.init(&buf);
    try testing.expectError(error.ValueTooLong, tlvs.addLspEntries(&b2, entries[0..16]));
}

// -- PDU builders and decoders ----------------------------------------------

test "every builder refuses a buffer below its fixed header and accepts exactly that size" {
    var buf: [64]u8 = undefined;
    const lf: pdu.LanHelloFields = .{ .source_id = src6, .holding_time = 9, .lan_id = lan7 };
    try testing.expectError(error.BufferTooSmall, pdu.LanHelloBuilder.init(buf[0..26], lf));
    try testing.expectError(error.BufferTooSmall, pdu.LanHelloBuilder.init(buf[0..0], lf));
    var lb = try pdu.LanHelloBuilder.init(buf[0..27], lf);
    try testing.expectEqual(@as(usize, 27), lb.finish().len);

    const pf: pdu.P2pHelloFields = .{ .source_id = src6, .holding_time = 9 };
    try testing.expectError(error.BufferTooSmall, pdu.P2pHelloBuilder.init(buf[0..19], pf));
    try testing.expectError(error.BufferTooSmall, pdu.P2pHelloBuilder.init(buf[0..0], pf));
    var pb = try pdu.P2pHelloBuilder.init(buf[0..20], pf);
    try testing.expectEqual(@as(usize, 20), pb.finish().len);

    const sf: pdu.LspFields = .{ .remaining_lifetime = 1, .lsp_id = lsp_id, .sequence_number = 2, .flags = pdu.LspFlags.fromByte(0) };
    try testing.expectError(error.BufferTooSmall, pdu.LspBuilder.init(buf[0..26], sf));
    try testing.expectError(error.BufferTooSmall, pdu.LspBuilder.init(buf[0..0], sf));
    var sb = try pdu.LspBuilder.init(buf[0..27], sf);
    try testing.expectEqual(@as(usize, 27), sb.finish().len);

    const cf: pdu.CsnpFields = .{ .source_id = lan7, .start_lsp_id = lsp_id, .end_lsp_id = lsp_id };
    try testing.expectError(error.BufferTooSmall, pdu.CsnpBuilder.init(buf[0..32], cf));
    try testing.expectError(error.BufferTooSmall, pdu.CsnpBuilder.init(buf[0..0], cf));
    var cb = try pdu.CsnpBuilder.init(buf[0..33], cf);
    try testing.expectEqual(@as(usize, 33), cb.finish().len);

    const nf: pdu.PsnpFields = .{ .source_id = lan7 };
    try testing.expectError(error.BufferTooSmall, pdu.PsnpBuilder.init(buf[0..16], nf));
    try testing.expectError(error.BufferTooSmall, pdu.PsnpBuilder.init(buf[0..0], nf));
    var nb = try pdu.PsnpBuilder.init(buf[0..17], nf);
    try testing.expectEqual(@as(usize, 17), nb.finish().len);
}

test "a PDU with no TLVs decodes at exactly its fixed length; a shorter buffer is TruncatedBody" {
    var buf: [64]u8 = undefined;
    const lw = blk: {
        var b = try pdu.LanHelloBuilder.init(&buf, .{ .source_id = src6, .holding_time = 9, .lan_id = lan7 });
        break :blk b.finish();
    };
    try testing.expectEqual(@as(usize, 0), (try pdu.LanHello.decode(lw)).tlv_bytes.len);
    try testing.expectError(error.TruncatedBody, pdu.LanHello.decode(lw[0..20]));

    var buf2: [64]u8 = undefined;
    const pw = blk: {
        var b = try pdu.P2pHelloBuilder.init(&buf2, .{ .source_id = src6, .holding_time = 9 });
        break :blk b.finish();
    };
    try testing.expectEqual(@as(usize, 0), (try pdu.P2pHello.decode(pw)).tlv_bytes.len);
    try testing.expectError(error.TruncatedBody, pdu.P2pHello.decode(pw[0..19]));

    var buf3: [64]u8 = undefined;
    const cw = blk: {
        var b = try pdu.CsnpBuilder.init(&buf3, .{ .source_id = lan7, .start_lsp_id = lsp_id, .end_lsp_id = lsp_id });
        break :blk b.finish();
    };
    try testing.expectEqual(@as(usize, 0), (try pdu.Csnp.decode(cw)).tlv_bytes.len);
    try testing.expectError(error.TruncatedBody, pdu.Csnp.decode(cw[0..32]));

    var buf4: [64]u8 = undefined;
    const nw = blk: {
        var b = try pdu.PsnpBuilder.init(&buf4, .{ .source_id = lan7 });
        break :blk b.finish();
    };
    try testing.expectEqual(@as(usize, 0), (try pdu.Psnp.decode(nw)).tlv_bytes.len);
    try testing.expectError(error.TruncatedBody, pdu.Psnp.decode(nw[0..16]));

    var buf5: [64]u8 = undefined;
    const sw = blk: {
        var b = try pdu.LspBuilder.init(&buf5, .{ .remaining_lifetime = 1, .lsp_id = lsp_id, .sequence_number = 2, .flags = pdu.LspFlags.fromByte(0) });
        break :blk b.finish();
    };
    try testing.expectEqual(@as(usize, 0), (try pdu.Lsp.decode(sw)).tlv_bytes.len);
    try testing.expectError(error.TruncatedBody, pdu.Lsp.decode(sw[0..26]));
}

test "decoded TLV iterators walk the TLVs of LAN IIH, CSNP and PSNP" {
    var buf: [128]u8 = undefined;
    {
        var b = try pdu.LanHelloBuilder.init(&buf, .{ .source_id = src6, .holding_time = 9, .lan_id = lan7 });
        try b.tlvs.addTlv(0x42, &.{ 1, 2 });
        const p = try pdu.LanHello.decode(b.finish());
        var it = p.tlvIterator();
        try testing.expectEqual(@as(u8, 0x42), (try it.next()).?.code);
    }
    {
        var b = try pdu.CsnpBuilder.init(&buf, .{ .source_id = lan7, .start_lsp_id = lsp_id, .end_lsp_id = lsp_id });
        try b.tlvs.addTlv(0x43, &.{ 1, 2 });
        const p = try pdu.Csnp.decode(b.finish());
        var it = p.tlvIterator();
        try testing.expectEqual(@as(u8, 0x43), (try it.next()).?.code);
    }
    {
        var b = try pdu.PsnpBuilder.init(&buf, .{ .source_id = lan7 });
        try b.tlvs.addTlv(0x44, &.{ 1, 2 });
        const p = try pdu.Psnp.decode(b.finish());
        var it = p.tlvIterator();
        try testing.expectEqual(@as(u8, 0x44), (try it.next()).?.code);
    }
}

test "every builder writes its Maximum Area Addresses octet" {
    var buf: [64]u8 = undefined;
    {
        var b = try pdu.LanHelloBuilder.init(&buf, .{ .source_id = src6, .holding_time = 9, .lan_id = lan7, .max_area_addresses = 7 });
        try testing.expectEqual(@as(u8, 7), (try pdu.LanHello.decode(b.finish())).header.max_area_addresses);
    }
    {
        var b = try pdu.P2pHelloBuilder.init(&buf, .{ .source_id = src6, .holding_time = 9, .max_area_addresses = 7 });
        try testing.expectEqual(@as(u8, 7), (try pdu.P2pHello.decode(b.finish())).header.max_area_addresses);
    }
    {
        var b = try pdu.LspBuilder.init(&buf, .{ .remaining_lifetime = 1, .lsp_id = lsp_id, .sequence_number = 2, .flags = pdu.LspFlags.fromByte(0), .max_area_addresses = 7 });
        try testing.expectEqual(@as(u8, 7), (try pdu.Lsp.decode(b.finish())).header.max_area_addresses);
    }
    {
        var b = try pdu.CsnpBuilder.init(&buf, .{ .source_id = lan7, .start_lsp_id = lsp_id, .end_lsp_id = lsp_id, .max_area_addresses = 7 });
        try testing.expectEqual(@as(u8, 7), (try pdu.Csnp.decode(b.finish())).header.max_area_addresses);
    }
    {
        var b = try pdu.PsnpBuilder.init(&buf, .{ .source_id = lan7, .max_area_addresses = 7 });
        try testing.expectEqual(@as(u8, 7), (try pdu.Psnp.decode(b.finish())).header.max_area_addresses);
    }
}

test "the Length Indicator must EQUAL the fixed header length, below or above" {
    var buf: [64]u8 = undefined;
    var b = try pdu.LspBuilder.init(&buf, .{ .remaining_lifetime = 1, .lsp_id = lsp_id, .sequence_number = 2, .flags = pdu.LspFlags.fromByte(0) });
    const w = b.finish();
    var m: [27]u8 = undefined;
    @memcpy(&m, w);
    m[1] = pdu.lsp_fixed_len - 1;
    try testing.expectError(error.LengthIndicatorMismatch, pdu.Lsp.decode(&m));
    m[1] = pdu.lsp_fixed_len + 1;
    try testing.expectError(error.LengthIndicatorMismatch, pdu.Lsp.decode(&m));
    m[1] = pdu.lsp_fixed_len;
    _ = try pdu.Lsp.decode(&m);
}

test "bytes after the PDU Length field are not part of the TLV region or the checksum region" {
    var buf: [64]u8 = undefined;
    var b = try pdu.LspBuilder.init(&buf, .{ .remaining_lifetime = 1200, .lsp_id = lsp_id, .sequence_number = 7, .flags = pdu.LspFlags.fromByte(0x03) });
    try tlvs.addHostname(&b.tlvs, "r1");
    const w = b.finishStamped();
    const want = try pdu.computeLspChecksum(w);
    try testing.expectEqual(pdu.ChecksumStatus.good, try pdu.checkLspChecksum(w));

    // The same LSP followed by four octets of link-layer padding.
    var padded: [64]u8 = undefined;
    @memcpy(padded[0..w.len], w);
    @memcpy(padded[w.len..][0..4], &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF });
    const pw = padded[0 .. w.len + 4];
    try testing.expectEqual(w.len - pdu.lsp_fixed_len, (try pdu.Lsp.decode(pw)).tlv_bytes.len);
    try testing.expectEqual(w.len - pdu.lsp_checksum_base, (try pdu.lspChecksumRegion(pw)).len);
    try testing.expectEqual(want, try pdu.computeLspChecksum(pw));
    try testing.expectEqual(pdu.ChecksumStatus.good, try pdu.checkLspChecksum(pw));
}

test "LSP: the checksum field byte order, in the builder, the decoder and the stamp" {
    var buf: [64]u8 = undefined;
    var b = try pdu.LspBuilder.init(&buf, .{ .remaining_lifetime = 0x0102, .lsp_id = lsp_id, .sequence_number = 0x03040506, .checksum = 0x1234, .flags = pdu.LspFlags.fromByte(0x03) });
    const w = b.finish();
    try testing.expectEqual(@as(u8, 0x12), w[24]);
    try testing.expectEqual(@as(u8, 0x34), w[25]);
    const d = try pdu.Lsp.decode(w);
    try testing.expectEqual(@as(u16, 0x1234), d.checksum);
    try testing.expectEqual(@as(u16, 0x0102), d.remaining_lifetime);
    try testing.expectEqual(@as(u32, 0x03040506), d.sequence_number);

    var out: [64]u8 = undefined;
    @memcpy(out[0..w.len], w);
    const stamped = try pdu.stampLspChecksum(out[0..w.len]);
    try testing.expect(stamped != 0);
    try testing.expectEqual(stamped, std.mem.readInt(u16, out[24..26], .big));
    try testing.expectEqual(stamped, (try pdu.Lsp.decode(out[0..w.len])).checksum);
}

test "LspFlags: each bit alone, all four attached bits, both is_type bits" {
    try testing.expect(pdu.LspFlags.fromByte(0x80).partition_repair);
    try testing.expect(!pdu.LspFlags.fromByte(0x40).partition_repair);
    try testing.expectEqual(@as(u4, 0xF), pdu.LspFlags.fromByte(0x78).attached);
    try testing.expectEqual(@as(u4, 0x8), pdu.LspFlags.fromByte(0x40).attached);
    try testing.expect(pdu.LspFlags.fromByte(0x04).overload);
    try testing.expectEqual(@as(u2, 3), pdu.LspFlags.fromByte(0x03).is_type);
    try testing.expectEqual(@as(u2, 2), pdu.LspFlags.fromByte(0x02).is_type);
    try testing.expectEqual(@as(u2, 1), pdu.LspFlags.fromByte(0x01).is_type);
    for ([_]u8{ 0x00, 0x80, 0x78, 0x04, 0x03, 0x02, 0xFF }) |byte| {
        try testing.expectEqual(byte, pdu.LspFlags.fromByte(byte).toByte());
    }
}

test "CSNP: the start and end LSP ids and the source id decode from their own octets" {
    var buf: [64]u8 = undefined;
    const start = [8]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const end = [8]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    var b = try pdu.CsnpBuilder.init(&buf, .{ .source_id = .{ 9, 8, 7, 6, 5, 4, 3 }, .start_lsp_id = start, .end_lsp_id = end });
    const d = try pdu.Csnp.decode(b.finish());
    try testing.expectEqual(start, d.start_lsp_id);
    try testing.expectEqual(end, d.end_lsp_id);
    try testing.expectEqual([7]u8{ 9, 8, 7, 6, 5, 4, 3 }, d.source_id);
}

// -- SPB --------------------------------------------------------------------

test "MtCapability: a bare preamble decodes, the full 12-bit MT-ID is kept" {
    const m = try spb.MtCapability.decode(&.{ 0x8F, 0xFF });
    try testing.expect(m.overload);
    try testing.expectEqual(@as(u12, 0xFFF), m.mt_id);
    try testing.expectEqual(@as(usize, 0), m.sub_tlvs.len);
}

test "addMtCapability: 253 sub-TLV octets fill the TLV exactly, 254 is refused" {
    var buf: [400]u8 = undefined;
    const sub: [254]u8 = @splat(0x77);
    var b = tlv.Builder.init(&buf);
    try spb.addMtCapability(&b, 144, false, 0, sub[0..253]);
    try testing.expectEqual(@as(u8, 255), b.written()[1]);
    var b2 = tlv.Builder.init(&buf);
    try testing.expectError(error.ValueTooLong, spb.addMtCapability(&b2, 144, false, 0, sub[0..254]));
}

const inst: spb.SpbInstance = .{
    .cist_root_id = .{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
    .cist_external_root_path_cost = 0x01020304,
    .bridge_priority = 0x0506,
    .spsourceid_auto = true,
    .spsourceid = 0xABCDE,
    .num_trees = 0,
    .tuple_bytes = &.{},
};

test "SpbInstance: a value with no tuples decodes; every fixed field from its own octets" {
    var out: [64]u8 = undefined;
    const enc = try spb.encodeSpbInstance(inst, &.{}, &out);
    // `enc` is the whole sub-TLV (type, length, value); decode the value.
    try testing.expectEqual(@as(usize, 2 + spb.SpbInstance.fixed_len), enc.len);
    const d = try spb.SpbInstance.decode(enc[2..]);
    try testing.expectEqual(inst.cist_root_id, d.cist_root_id);
    try testing.expectEqual(@as(u32, 0x01020304), d.cist_external_root_path_cost);
    try testing.expectEqual(@as(u16, 0x0506), d.bridge_priority);
    try testing.expect(d.spsourceid_auto);
    try testing.expectEqual(@as(u20, 0xABCDE), d.spsourceid);
    try testing.expectEqual(@as(u8, 0), d.num_trees);

    // The wire octets themselves (big endian), independent of the decoder.
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, enc[2 + 8 ..][0..4]);
    try testing.expectEqualSlices(u8, &.{ 0x05, 0x06 }, enc[2 + 12 ..][0..2]);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x1A, 0xBC, 0xDE }, enc[2 + 14 ..][0..4]);
}

test "SPSourceID keeps its bit 19 and does not reach the V bit" {
    var v: [spb.SpbInstance.fixed_len]u8 = @splat(0);
    std.mem.writeInt(u32, v[14..18], 0x0008_0000, .big);
    const d = try spb.SpbInstance.decode(&v);
    try testing.expectEqual(@as(u20, 0x80000), d.spsourceid);
    try testing.expect(!d.spsourceid_auto);
}

test "VidTuple flag bits and VID masks, one at a time" {
    const Case = struct { flags: u8, use: bool, m: bool, a: bool };
    const cases = [_]Case{
        .{ .flags = 0x80, .use = true, .m = false, .a = false },
        .{ .flags = 0x40, .use = false, .m = true, .a = false },
        .{ .flags = 0x20, .use = false, .m = false, .a = true },
        .{ .flags = 0x10, .use = false, .m = false, .a = false },
    };
    for (cases) |c| {
        var buf: [64]u8 = undefined;
        const t: spb.VidTuple = .{ .use = c.use, .mode_spbm = c.m, .agreement = c.a, .ect_algorithm = 0x0C0DE001, .base_vid = 0xABC, .spvid = 0xFFF };
        const enc = try spb.encodeSpbInstance(inst, &.{t}, &buf);
        // The flag octet is the first octet of the tuple.
        try testing.expectEqual(c.flags & 0xE0, enc[2 + spb.SpbInstance.fixed_len]);
        const d = try spb.SpbInstance.decode(enc[2..]);
        var it = d.tupleIterator();
        const got = (try it.next()).?;
        try testing.expectEqual(t, got);
        try testing.expect((try it.next()) == null);
    }
    // A flag octet decoded on its own, including the unused low bits.
    var it = spb.VidTupleIterator{ .buf = &.{ 0x10, 0, 0, 0, 1, 0x12, 0x3F, 0xFF } };
    const g = (try it.next()).?;
    try testing.expect(!g.use and !g.mode_spbm and !g.agreement);
    try testing.expectEqual(@as(u12, 0x123), g.base_vid);
    try testing.expectEqual(@as(u12, 0xFFF), g.spvid);
}

test "VidTupleIterator and IsidIterator refuse a trailing partial record" {
    var it = spb.VidTupleIterator{ .buf = &.{ 0, 0, 0, 0, 0, 0, 0 } };
    try testing.expectError(error.BadLength, it.next());
    var is = spb.IsidIterator{ .buf = &.{ 0, 0, 0 } };
    try testing.expectError(error.BadLength, is.next());
}

test "encodeSpbInstance: exact fit, a too small buffer outranks too many tuples, 256 tuples" {
    var out: [64]u8 = undefined;
    const t: spb.VidTuple = .{ .use = true, .mode_spbm = true, .agreement = false, .ect_algorithm = 1, .base_vid = 2, .spvid = 3 };
    const need = 2 + spb.SpbInstance.fixed_len + 8;
    _ = try spb.encodeSpbInstance(inst, &.{t}, out[0..need]);
    try testing.expectError(error.BufferTooSmall, spb.encodeSpbInstance(inst, &.{t}, out[0 .. need - 1]));

    const many: [256]spb.VidTuple = @splat(t);
    // Buffer too small is reported before the tuple count is looked at.
    try testing.expectError(error.BufferTooSmall, spb.encodeSpbInstance(inst, &many, out[0..]));
    var big: [4096]u8 = undefined;
    try testing.expectError(error.ValueTooLong, spb.encodeSpbInstance(inst, &many, &big));
}

test "SpbmServiceId: a value with no I-SIDs decodes, the base VID keeps 12 bits" {
    const v = [_]u8{ 1, 2, 3, 4, 5, 6, 0x0F, 0xFF };
    const d = try spb.SpbmServiceId.decode(&v);
    try testing.expectEqual(@as(u12, 0xFFF), d.base_vid);
    try testing.expectEqual(@as(usize, 0), d.isid_bytes.len);
    try testing.expectEqual([6]u8{ 1, 2, 3, 4, 5, 6 }, d.b_mac);
}

test "encodeSpbmServiceId: 61 I-SIDs fit, the 62nd is refused" {
    var out: [400]u8 = undefined;
    const e: spb.IsidEntry = .{ .transmit = true, .receive = false, .isid = 0x123456 };
    const many: [62]spb.IsidEntry = @splat(e);
    const ok = try spb.encodeSpbmServiceId(src6, 0x123, many[0..61], &out);
    try testing.expectEqual(@as(u8, 252), ok[1]);
    try testing.expectError(error.ValueTooLong, spb.encodeSpbmServiceId(src6, 0x123, many[0..62], &out));
}

test "IsidEntry and SpbInstance round trips use the receive/transmit and A bits on their own" {
    var out: [64]u8 = undefined;
    const e: spb.IsidEntry = .{ .transmit = false, .receive = true, .isid = 0xABCDEF };
    const enc = try spb.encodeSpbmServiceId(src6, 0x7FF, &.{e}, &out);
    const d = try spb.SpbmServiceId.decode(enc[2..]);
    try testing.expectEqual(@as(u12, 0x7FF), d.base_vid);
    var it = d.isidIterator();
    try testing.expectEqual(e, (try it.next()).?);
}

// -- top-level dispatch -----------------------------------------------------

test "isis.decode dispatches the level-2 variants and keeps the bytes of an unmodeled PDU" {
    var buf: [64]u8 = undefined;
    {
        var b = try pdu.LanHelloBuilder.init(&buf, .{ .is_l2 = true, .source_id = src6, .holding_time = 9, .lan_id = lan7 });
        try testing.expect((try isis.decode(b.finish())) == .lan_hello);
    }
    {
        var b = try pdu.LspBuilder.init(&buf, .{ .is_l2 = true, .remaining_lifetime = 1, .lsp_id = lsp_id, .sequence_number = 2, .flags = pdu.LspFlags.fromByte(0) });
        try testing.expect((try isis.decode(b.finish())) == .lsp);
    }
    {
        var b = try pdu.CsnpBuilder.init(&buf, .{ .is_l2 = true, .source_id = lan7, .start_lsp_id = lsp_id, .end_lsp_id = lsp_id });
        try testing.expect((try isis.decode(b.finish())) == .csnp);
    }
    {
        var b = try pdu.PsnpBuilder.init(&buf, .{ .is_l2 = true, .source_id = lan7 });
        try testing.expect((try isis.decode(b.finish())) == .psnp);
    }
    // PDU type 1 is not modeled: `.other` carries the whole input.
    var w: [10]u8 = undefined;
    try header.encode(.{ .length_indicator = 10, .pdu_type = @as(header.PduType, @fromBackingInt(1)), .id_length = 6, .max_area_addresses = 3 }, w[0..8]);
    w[8] = 0xAA;
    w[9] = 0xBB;
    switch (try isis.decode(&w)) {
        .other => |o| try testing.expectEqual(@as(usize, 10), o.bytes.len),
        else => return error.WrongVariant,
    }
}
