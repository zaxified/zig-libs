// SPDX-License-Identifier: MIT

//! SPB (IEEE 802.1aq / RFC 6329) IS-IS TLVs — the fabric control-plane subset.
//!
//! SPB nodal information rides inside the **MT-Capability TLV (code 144)**
//! (RFC 6329; the TLV container itself is from RFC 6165) which appears in LSPs,
//! and the **MT-Port-Capability TLV (code 143)** which appears in IIH PDUs.
//! Both open with the same 2-octet preamble — one **O** (overload) bit, three
//! reserved bits, and a 12-bit **MT-ID** — followed by a bounds-checked sub-TLV
//! stream (`tlv.TlvIterator`). This file models the container preamble plus the
//! two sub-TLVs the SPBM fabric needs:
//!
//! - **SPB Instance (sub-TLV type 1)** — the node's SPSourceID, bridge
//!   priority, CIST root, and its ECT-VID tuples (RFC 6329 §3.5.2).
//! - **SPBM Service Identifier and Unicast Address, "SPBM-SI"
//!   (sub-TLV type 3)** — a B-MAC + Base VID and the node's I-SID memberships,
//!   each with its Transmit/Receive bits (RFC 6329 §3.5.4).
//!
//! Other SPB sub-TLVs (SPB-Inst Opaque type 2, SPBV type 4; and the
//! MT-Port-Cap sub-TLVs SPB-MCID type 4, SPB-Digest type 5, SPB-B-VID type 6)
//! are **not** modeled as typed structs here — they stay reachable through the
//! raw `tlv.TlvIterator` over the container's sub-TLV bytes. See SPEC.md.
//!
//! Type numbers are from RFC 6329's IANA registrations, cross-checked against
//! the IANA IS-IS TLV / sub-TLV code-point registries. Provenance: clean-room
//! from RFC 6329 / RFC 6165; see /NOTICE (none required).

const std = @import("std");
const tlv = @import("tlv.zig");

/// Sub-TLV type numbers carried within the MT-Capability TLV (code 144),
/// per RFC 6329.
pub const sub = struct {
    pub const spb_instance: u8 = 1;
    pub const spb_instance_opaque: u8 = 2;
    pub const spbm_service_id: u8 = 3; // "SPBM-SI"
    pub const spbv_mac_address: u8 = 4;
};

pub const ParseError = error{
    /// The container preamble (2 octets) or a fixed sub-TLV record does not fit.
    BadLength,
};

// ── MT-Capability / MT-Port-Capability container preamble ────────────────────

/// The decoded head of an MT-Capability (144) or MT-Port-Capability (143) TLV:
/// the O/MT-ID preamble plus the raw sub-TLV bytes (walk with
/// `tlv.TlvIterator`).
pub const MtCapability = struct {
    /// The O (overload) bit of the preamble.
    overload: bool,
    /// The 12-bit Multi-Topology identifier.
    mt_id: u12,
    /// The sub-TLV stream that follows the preamble.
    sub_tlvs: []const u8,

    /// Decodes the preamble of an MT-Capability TLV *value*. `value` is the TLV
    /// value slice (what `tlv.TlvIterator` yields for code 143/144).
    pub fn decode(value: []const u8) ParseError!MtCapability {
        if (value.len < 2) return error.BadLength;
        const word = std.mem.readInt(u16, value[0..2], .big);
        return .{
            .overload = (word & 0x8000) != 0,
            .mt_id = @intCast(word & 0x0FFF),
            .sub_tlvs = value[2..],
        };
    }

    /// A bounds-checked walk of the sub-TLVs.
    pub fn subTlvIterator(m: MtCapability) tlv.TlvIterator {
        return tlv.TlvIterator.init(m.sub_tlvs);
    }
};

/// Builds an MT-Capability (or MT-Port-Capability) TLV: emits the 2-octet
/// preamble and the caller's already-serialized sub-TLV block as one TLV value.
/// `tlv_code` is `tlvs.code.mt_capability` (144, in LSPs) or
/// `tlvs.code.mt_port_capability` (143, in IIH PDUs).
pub fn addMtCapability(
    b: *tlv.Builder,
    tlv_code: u8,
    overload: bool,
    mt_id: u12,
    sub_tlvs: []const u8,
) tlv.BuildError!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    if (2 + sub_tlvs.len > scratch.len) return error.ValueTooLong;
    const word: u16 = (if (overload) @as(u16, 0x8000) else 0) | @as(u16, mt_id);
    std.mem.writeInt(u16, scratch[0..2], word, .big);
    @memcpy(scratch[2..][0..sub_tlvs.len], sub_tlvs);
    try b.addTlv(tlv_code, scratch[0 .. 2 + sub_tlvs.len]);
}

// ── SPB Instance sub-TLV (type 1) ────────────────────────────────────────────

/// One ECT-VID tuple of an SPB Instance sub-TLV (8 octets): the U/M/A flags,
/// the ECT-ALGORITHM, and the Base-VID/SPVID pair.
pub const VidTuple = struct {
    /// U bit — this bridge is using this ECT-ALGORITHM.
    use: bool,
    /// M bit — SPBM (true) vs SPBV (false) mode for this VID.
    mode_spbm: bool,
    /// A bit — the auto-allocation/agreement flag.
    agreement: bool,
    /// The 32-bit ECT-ALGORITHM identifier.
    ect_algorithm: u32,
    /// The 12-bit Base VID associated with this SPT set.
    base_vid: u12,
    /// The 12-bit Shortest-Path VID for this node.
    spvid: u12,
};

/// The SPB Instance sub-TLV (RFC 6329 §3.5.2). Fixed fields plus a bounded run
/// of `VidTuple`s (walk with `tupleIterator`, which is bounds-checked).
pub const SpbInstance = struct {
    /// 8-octet CIST Root Identifier (bridge priority + system id), carried raw.
    cist_root_id: [8]u8,
    cist_external_root_path_cost: u32,
    bridge_priority: u16,
    /// V bit — the SPSourceID was auto-allocated.
    spsourceid_auto: bool,
    /// 20-bit SPSourceID used to construct multicast DAs.
    spsourceid: u20,
    num_trees: u8,
    /// The tuple bytes (`num_trees` × 8), each an ECT-VID `VidTuple`.
    tuple_bytes: []const u8,

    /// Fixed prefix length before the VID tuples begin.
    pub const fixed_len: usize = 8 + 4 + 2 + 4 + 1;

    pub fn decode(value: []const u8) ParseError!SpbInstance {
        if (value.len < fixed_len) return error.BadLength;
        const word = std.mem.readInt(u32, value[14..18], .big); // R(11)|V(1)|SPSourceID(20)
        const num_trees = value[18];
        const tuples = value[fixed_len..];
        // Bound the tuple run to exactly num_trees × 8 octets, no over-read.
        if (@as(usize, num_trees) * 8 > tuples.len) return error.BadLength;
        return .{
            .cist_root_id = value[0..8].*,
            .cist_external_root_path_cost = std.mem.readInt(u32, value[8..12], .big),
            .bridge_priority = std.mem.readInt(u16, value[12..14], .big),
            .spsourceid_auto = (word & (1 << 20)) != 0,
            .spsourceid = @intCast(word & 0xF_FFFF),
            .num_trees = num_trees,
            .tuple_bytes = tuples[0 .. @as(usize, num_trees) * 8],
        };
    }

    pub fn tupleIterator(s: SpbInstance) VidTupleIterator {
        return .{ .buf = s.tuple_bytes };
    }
};

/// Walks the 8-octet ECT-VID tuples of an SPB Instance sub-TLV.
pub const VidTupleIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn next(it: *VidTupleIterator) ParseError!?VidTuple {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 8 > it.buf.len) return error.BadLength;
        const t = it.buf[it.pos..][0..8];
        const flags = t[0];
        const ect = std.mem.readInt(u32, t[1..5], .big);
        const vids = std.mem.readInt(u24, t[5..8], .big); // BaseVID(12)|SPVID(12)
        it.pos += 8;
        return .{
            .use = (flags & 0x80) != 0,
            .mode_spbm = (flags & 0x40) != 0,
            .agreement = (flags & 0x20) != 0,
            .ect_algorithm = ect,
            .base_vid = @intCast(vids >> 12),
            .spvid = @intCast(vids & 0x0FFF),
        };
    }
};

/// Builds an SPB Instance (type 1) sub-TLV into `out` (a caller scratch buffer),
/// returning the filled prefix. Compose it into an MT-Capability container via
/// `addMtCapability`.
pub fn encodeSpbInstance(inst: SpbInstance, tuples: []const VidTuple, out: []u8) tlv.BuildError![]const u8 {
    const total = 2 + SpbInstance.fixed_len + tuples.len * 8; // + sub-TLV code/len
    if (total > out.len) return error.BufferTooSmall;
    if (tuples.len > 255) return error.ValueTooLong;
    var v: [SpbInstance.fixed_len + 255 * 8]u8 = undefined;
    @memcpy(v[0..8], &inst.cist_root_id);
    std.mem.writeInt(u32, v[8..12], inst.cist_external_root_path_cost, .big);
    std.mem.writeInt(u16, v[12..14], inst.bridge_priority, .big);
    const word: u32 = (if (inst.spsourceid_auto) @as(u32, 1) << 20 else 0) | @as(u32, inst.spsourceid);
    std.mem.writeInt(u32, v[14..18], word, .big);
    v[18] = @intCast(tuples.len);
    var n: usize = SpbInstance.fixed_len;
    for (tuples) |t| {
        v[n] = (if (t.use) @as(u8, 0x80) else 0) |
            (if (t.mode_spbm) @as(u8, 0x40) else 0) |
            (if (t.agreement) @as(u8, 0x20) else 0);
        std.mem.writeInt(u32, v[n + 1 ..][0..4], t.ect_algorithm, .big);
        const vids: u24 = (@as(u24, t.base_vid) << 12) | @as(u24, t.spvid);
        std.mem.writeInt(u24, v[n + 5 ..][0..3], vids, .big);
        n += 8;
    }
    var b = tlv.Builder.init(out);
    try b.addTlv(sub.spb_instance, v[0..n]);
    return b.written();
}

// ── SPBM Service Identifier and Unicast Address sub-TLV (type 3) ──────────────

/// One I-SID membership entry of an SPBM-SI sub-TLV (4 octets): the T/R bits
/// and the 24-bit I-SID.
pub const IsidEntry = struct {
    /// T bit — Transmit allowed (installed as a multicast transmitter).
    transmit: bool,
    /// R bit — Receive allowed.
    receive: bool,
    /// The 24-bit service identifier.
    isid: u24,
};

/// The SPBM Service Identifier and Unicast Address sub-TLV (RFC 6329 §3.5.4):
/// a B-MAC + Base VID header and a bounded run of I-SID entries.
pub const SpbmServiceId = struct {
    /// The 6-octet backbone MAC (B-MAC) this node advertises for the service.
    b_mac: [6]u8,
    /// The 12-bit Base VID (low 12 bits of the 2-octet Res|Base-VID field).
    base_vid: u12,
    /// The I-SID entry bytes (4 octets each). Walk with `isidIterator`.
    isid_bytes: []const u8,

    /// Fixed prefix length before the I-SID entries begin.
    pub const fixed_len: usize = 6 + 2;

    pub fn decode(value: []const u8) ParseError!SpbmServiceId {
        if (value.len < fixed_len) return error.BadLength;
        const bv = std.mem.readInt(u16, value[6..8], .big); // Res(4)|BaseVID(12)
        const entries = value[fixed_len..];
        // I-SID entries are 4 octets each; a partial trailing entry is malformed.
        if (entries.len % 4 != 0) return error.BadLength;
        return .{
            .b_mac = value[0..6].*,
            .base_vid = @intCast(bv & 0x0FFF),
            .isid_bytes = entries,
        };
    }

    pub fn isidIterator(s: SpbmServiceId) IsidIterator {
        return .{ .buf = s.isid_bytes };
    }
};

/// Walks the 4-octet I-SID entries of an SPBM-SI sub-TLV.
pub const IsidIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn next(it: *IsidIterator) ParseError!?IsidEntry {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 4 > it.buf.len) return error.BadLength;
        const e = it.buf[it.pos..][0..4];
        it.pos += 4;
        return .{
            .transmit = (e[0] & 0x80) != 0,
            .receive = (e[0] & 0x40) != 0,
            .isid = std.mem.readInt(u24, e[1..4], .big),
        };
    }
};

/// Builds an SPBM-SI (type 3) sub-TLV into `out`, returning the filled prefix.
pub fn encodeSpbmServiceId(b_mac: [6]u8, base_vid: u12, isids: []const IsidEntry, out: []u8) tlv.BuildError![]const u8 {
    if (isids.len > (255 - SpbmServiceId.fixed_len) / 4) return error.ValueTooLong;
    var v: [tlv.max_value_len]u8 = undefined;
    @memcpy(v[0..6], &b_mac);
    std.mem.writeInt(u16, v[6..8], @as(u16, base_vid), .big); // reserved high bits = 0
    var n: usize = SpbmServiceId.fixed_len;
    for (isids) |e| {
        v[n] = (if (e.transmit) @as(u8, 0x80) else 0) | (if (e.receive) @as(u8, 0x40) else 0);
        std.mem.writeInt(u24, v[n + 1 ..][0..3], e.isid, .big);
        n += 4;
    }
    var bld = tlv.Builder.init(out);
    try bld.addTlv(sub.spbm_service_id, v[0..n]);
    return bld.written();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "MT-Capability preamble: O bit + 12-bit MT-ID + sub-TLV bytes" {
    var buf: [64]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    try addMtCapability(&b, 144, true, 0x001, &.{ 0x03, 0x00 }); // one empty SPBM-SI-shaped sub-TLV
    var it = tlv.TlvIterator.init(b.written());
    const t = (try it.next()).?;
    try testing.expectEqual(@as(u8, 144), t.code);
    const cap = try MtCapability.decode(t.value);
    try testing.expect(cap.overload);
    try testing.expectEqual(@as(u12, 1), cap.mt_id);
    var subs = cap.subTlvIterator();
    const s = (try subs.next()).?;
    try testing.expectEqual(@as(u8, 3), s.code);
}

test "SPBM-SI sub-TLV round-trips B-MAC + Base VID + I-SID T/R bits" {
    const bmac = [6]u8{ 0x00, 0x00, 0x00, 0x11, 0x22, 0x33 };
    const isids = [_]IsidEntry{
        .{ .transmit = true, .receive = true, .isid = 0x00_0064 }, // 100, both
        .{ .transmit = false, .receive = true, .isid = 0xAB_CDEF },
    };
    var scratch: [64]u8 = undefined;
    const sub_tlv = try encodeSpbmServiceId(bmac, 0x010, &isids, &scratch);

    // Decode it back through the sub-TLV walk.
    var it = tlv.TlvIterator.init(sub_tlv);
    const t = (try it.next()).?;
    try testing.expectEqual(sub.spbm_service_id, t.code);
    const si = try SpbmServiceId.decode(t.value);
    try testing.expectEqual(bmac, si.b_mac);
    try testing.expectEqual(@as(u12, 0x010), si.base_vid);
    var ie = si.isidIterator();
    const e0 = (try ie.next()).?;
    try testing.expect(e0.transmit and e0.receive);
    try testing.expectEqual(@as(u24, 100), e0.isid);
    const e1 = (try ie.next()).?;
    try testing.expect(!e1.transmit and e1.receive);
    try testing.expectEqual(@as(u24, 0xAB_CDEF), e1.isid);
    try testing.expectEqual(@as(?IsidEntry, null), try ie.next());
}

test "SPB Instance sub-TLV round-trips SPSourceID + ECT-VID tuples" {
    const inst: SpbInstance = .{
        .cist_root_id = .{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .cist_external_root_path_cost = 0,
        .bridge_priority = 0x8000,
        .spsourceid_auto = true,
        .spsourceid = 0x0_ABCD,
        .num_trees = 0, // filled by encoder from the tuple slice
        .tuple_bytes = &.{},
    };
    const tuples = [_]VidTuple{
        .{ .use = true, .mode_spbm = true, .agreement = false, .ect_algorithm = 0x00_00_00_01, .base_vid = 0x010, .spvid = 0x020 },
    };
    var scratch: [128]u8 = undefined;
    const sub_tlv = try encodeSpbInstance(inst, &tuples, &scratch);

    var it = tlv.TlvIterator.init(sub_tlv);
    const t = (try it.next()).?;
    try testing.expectEqual(sub.spb_instance, t.code);
    const back = try SpbInstance.decode(t.value);
    try testing.expectEqual(@as(u20, 0x0_ABCD), back.spsourceid);
    try testing.expect(back.spsourceid_auto);
    try testing.expectEqual(@as(u16, 0x8000), back.bridge_priority);
    try testing.expectEqual(@as(u8, 1), back.num_trees);
    var ti = back.tupleIterator();
    const tup = (try ti.next()).?;
    try testing.expect(tup.use and tup.mode_spbm and !tup.agreement);
    try testing.expectEqual(@as(u32, 1), tup.ect_algorithm);
    try testing.expectEqual(@as(u12, 0x010), tup.base_vid);
    try testing.expectEqual(@as(u12, 0x020), tup.spvid);
    try testing.expectEqual(@as(?VidTuple, null), try ti.next());
}

test "SPBM-SI with a partial I-SID entry is rejected" {
    // 6 B-MAC + 2 base-vid + 3 stray bytes (not a multiple of 4).
    const value = [_]u8{0} ** 8 ++ [_]u8{ 0x80, 0x00, 0x64 };
    try testing.expectError(error.BadLength, SpbmServiceId.decode(&value));
}

test "SPB Instance num-trees larger than the tuple bytes is rejected" {
    var value = [_]u8{0} ** (SpbInstance.fixed_len);
    value[18] = 5; // claims 5 trees, no tuple bytes follow
    try testing.expectError(error.BadLength, SpbInstance.decode(&value));
}

test "MT-Capability preamble shorter than 2 octets is rejected" {
    try testing.expectError(error.BadLength, MtCapability.decode(&.{0x00}));
}
