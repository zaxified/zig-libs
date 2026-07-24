// SPDX-License-Identifier: MIT

//! IS-IS PDU bodies (ISO/IEC 10589): the type-specific fixed header that sits
//! between the common header (`header.zig`) and the TLV stream (`tlv.zig`), for
//! the IIH (Hello), LSP, CSNP, and PSNP PDUs.
//!
//! Each `Xxx.decode` validates the common header, checks the PDU type, reads
//! the fixed body fields, and delimits the TLV region using the body's "PDU
//! Length" field — bounded to `[fixed_len, buf.len]` so a lying length can
//! never push the TLV walk outside the buffer. `tlvIterator()` then walks the
//! TLVs with the shared bounds-checked `tlv.TlvIterator`. The builders write the
//! fixed header, hand back a `tlv.Builder` positioned after it, and backfill the
//! PDU Length on `finish`.
//!
//! ## System-id length
//! This first increment models the bodies for the **default 6-octet system id**
//! (the MAC-sized id SPB uses, ID-Length byte 0 or 6). A PDU whose common
//! header declares any other ID length decodes at the common-header layer but
//! `UnsupportedIdLength` here — the field widths (source-id, LAN-id, LSP-id) are
//! id-length-dependent and only the 6-octet case is wired. The raw TLV walk is
//! id-length-independent and always available.

const std = @import("std");
const header = @import("header.zig");
const tlv = @import("tlv.zig");

const PduType = header.PduType;
const CommonHeader = header.CommonHeader;

/// The only system-id length whose typed bodies are modeled here.
pub const modeled_id_length: u8 = 6;

pub const DecodeError = header.DecodeError || error{
    /// The common header's PDU type is not the one this decoder expects.
    WrongPduType,
    /// The system-id length is not the modeled 6 octets (see the file docs).
    UnsupportedIdLength,
    /// The buffer is shorter than this PDU type's fixed header.
    TruncatedBody,
    /// The body's PDU Length field is < the fixed header or > the buffer.
    BadPduLength,
};

pub const BuildError = tlv.BuildError;

fn checkCommon(bytes: []const u8, want: []const PduType) DecodeError!CommonHeader {
    const h = try header.decode(bytes);
    if (h.id_length != modeled_id_length) return error.UnsupportedIdLength;
    for (want) |w| {
        if (h.pdu_type == w) return h;
    }
    return error.WrongPduType;
}

/// Validates a body's PDU Length field and returns the delimited TLV slice.
fn tlvRegion(bytes: []const u8, fixed_len: usize, pdu_len_off: usize) DecodeError![]const u8 {
    const pdu_length: usize = std.mem.readInt(u16, bytes[pdu_len_off..][0..2], .big);
    if (pdu_length < fixed_len or pdu_length > bytes.len) return error.BadPduLength;
    return bytes[fixed_len..pdu_length];
}

/// The circuit-type field low 2 bits (ISO 10589): which levels this circuit runs.
pub const CircuitType = enum(u2) {
    reserved0 = 0,
    level1 = 1,
    level2 = 2,
    level1_2 = 3,
};

// ── IIH: LAN Hello (types 15/16) ─────────────────────────────────────────────

pub const lan_iih_fixed_len: usize = 27;

/// A decoded LAN IIH body (ISO 10589 §9.5). `source_id` is 6 octets; `lan_id`
/// is 7 (the DIS system id + pseudonode). TLVs follow.
pub const LanHello = struct {
    header: CommonHeader,
    circuit_type: CircuitType,
    source_id: [6]u8,
    holding_time: u16,
    pdu_length: u16,
    priority: u7,
    /// LAN ID (a.k.a. LAN DIS): 6-octet system id + 1-octet pseudonode id.
    lan_id: [7]u8,
    tlv_bytes: []const u8,

    pub fn decode(bytes: []const u8) DecodeError!LanHello {
        const h = try checkCommon(bytes, &.{ .l1_lan_iih, .l2_lan_iih });
        if (bytes.len < lan_iih_fixed_len) return error.TruncatedBody;
        const region = try tlvRegion(bytes, lan_iih_fixed_len, 17);
        return .{
            .header = h,
            .circuit_type = @enumFromInt(@as(u2, @intCast(bytes[8] & 0x03))),
            .source_id = bytes[9..15].*,
            .holding_time = std.mem.readInt(u16, bytes[15..17], .big),
            .pdu_length = std.mem.readInt(u16, bytes[17..19], .big),
            .priority = @intCast(bytes[19] & 0x7F),
            .lan_id = bytes[20..27].*,
            .tlv_bytes = region,
        };
    }

    pub fn tlvIterator(p: LanHello) tlv.TlvIterator {
        return tlv.TlvIterator.init(p.tlv_bytes);
    }
};

pub const LanHelloFields = struct {
    is_l2: bool = false,
    circuit_type: CircuitType = .level1_2,
    source_id: [6]u8,
    holding_time: u16,
    priority: u7 = 64,
    lan_id: [7]u8,
    max_area_addresses: u8 = header.default_max_area_addresses,
};

/// Builds a LAN IIH. Write the fixed header, add TLVs on the returned builder,
/// then `finish`.
pub const LanHelloBuilder = struct {
    buf: []u8,
    tlvs: tlv.Builder,

    pub fn init(buf: []u8, f: LanHelloFields) error{BufferTooSmall}!LanHelloBuilder {
        if (buf.len < lan_iih_fixed_len) return error.BufferTooSmall;
        header.encode(.{
            .length_indicator = lan_iih_fixed_len,
            .pdu_type = if (f.is_l2) .l2_lan_iih else .l1_lan_iih,
            .id_length = modeled_id_length,
            .max_area_addresses = f.max_area_addresses,
        }, buf[0..header.common_header_len]) catch unreachable;
        buf[8] = @intFromEnum(f.circuit_type);
        @memcpy(buf[9..15], &f.source_id);
        std.mem.writeInt(u16, buf[15..17], f.holding_time, .big);
        std.mem.writeInt(u16, buf[17..19], 0, .big); // PDU length, backfilled
        buf[19] = @as(u8, f.priority); // top bit reserved, zero
        @memcpy(buf[20..27], &f.lan_id);
        return .{ .buf = buf, .tlvs = tlv.Builder.init(buf[lan_iih_fixed_len..]) };
    }

    pub fn finish(b: *LanHelloBuilder) []const u8 {
        const total: u16 = @intCast(lan_iih_fixed_len + b.tlvs.pos);
        std.mem.writeInt(u16, b.buf[17..19], total, .big);
        return b.buf[0..total];
    }
};

// ── IIH: Point-to-Point Hello (type 17) ──────────────────────────────────────

pub const p2p_iih_fixed_len: usize = 20;

/// A decoded P2P IIH body (ISO 10589 §9.7).
pub const P2pHello = struct {
    header: CommonHeader,
    circuit_type: CircuitType,
    source_id: [6]u8,
    holding_time: u16,
    pdu_length: u16,
    local_circuit_id: u8,
    tlv_bytes: []const u8,

    pub fn decode(bytes: []const u8) DecodeError!P2pHello {
        const h = try checkCommon(bytes, &.{.p2p_iih});
        if (bytes.len < p2p_iih_fixed_len) return error.TruncatedBody;
        const region = try tlvRegion(bytes, p2p_iih_fixed_len, 17);
        return .{
            .header = h,
            .circuit_type = @enumFromInt(@as(u2, @intCast(bytes[8] & 0x03))),
            .source_id = bytes[9..15].*,
            .holding_time = std.mem.readInt(u16, bytes[15..17], .big),
            .pdu_length = std.mem.readInt(u16, bytes[17..19], .big),
            .local_circuit_id = bytes[19],
            .tlv_bytes = region,
        };
    }

    pub fn tlvIterator(p: P2pHello) tlv.TlvIterator {
        return tlv.TlvIterator.init(p.tlv_bytes);
    }
};

pub const P2pHelloFields = struct {
    circuit_type: CircuitType = .level1_2,
    source_id: [6]u8,
    holding_time: u16,
    local_circuit_id: u8 = 1,
    max_area_addresses: u8 = header.default_max_area_addresses,
};

pub const P2pHelloBuilder = struct {
    buf: []u8,
    tlvs: tlv.Builder,

    pub fn init(buf: []u8, f: P2pHelloFields) error{BufferTooSmall}!P2pHelloBuilder {
        if (buf.len < p2p_iih_fixed_len) return error.BufferTooSmall;
        header.encode(.{
            .length_indicator = p2p_iih_fixed_len,
            .pdu_type = .p2p_iih,
            .id_length = modeled_id_length,
            .max_area_addresses = f.max_area_addresses,
        }, buf[0..header.common_header_len]) catch unreachable;
        buf[8] = @intFromEnum(f.circuit_type);
        @memcpy(buf[9..15], &f.source_id);
        std.mem.writeInt(u16, buf[15..17], f.holding_time, .big);
        std.mem.writeInt(u16, buf[17..19], 0, .big);
        buf[19] = f.local_circuit_id;
        return .{ .buf = buf, .tlvs = tlv.Builder.init(buf[p2p_iih_fixed_len..]) };
    }

    pub fn finish(b: *P2pHelloBuilder) []const u8 {
        const total: u16 = @intCast(p2p_iih_fixed_len + b.tlvs.pos);
        std.mem.writeInt(u16, b.buf[17..19], total, .big);
        return b.buf[0..total];
    }
};

// ── LSP (types 18/20) ────────────────────────────────────────────────────────

pub const lsp_fixed_len: usize = 27;

/// The LSP flags octet (ISO 10589 §9.8): partition-repair, attached-metric
/// bits, LSP-DB overload, and IS Type.
pub const LspFlags = struct {
    partition_repair: bool,
    /// The four "Attached" bits (error/expense/delay/default metric), kept raw.
    attached: u4,
    overload: bool,
    /// IS Type: 1 = L1, 3 = L1L2 (ISO 10589).
    is_type: u2,

    pub fn fromByte(b: u8) LspFlags {
        return .{
            .partition_repair = (b & 0x80) != 0,
            .attached = @intCast((b >> 3) & 0x0F),
            .overload = (b & 0x04) != 0,
            .is_type = @intCast(b & 0x03),
        };
    }

    pub fn toByte(f: LspFlags) u8 {
        return (if (f.partition_repair) @as(u8, 0x80) else 0) |
            (@as(u8, f.attached) << 3) |
            (if (f.overload) @as(u8, 0x04) else 0) |
            @as(u8, f.is_type);
    }
};

/// A decoded LSP body (ISO 10589 §9.8). The checksum is carried as a raw field;
/// this codec does not compute or verify the ISO Fletcher checksum (see SPEC).
pub const Lsp = struct {
    header: CommonHeader,
    pdu_length: u16,
    remaining_lifetime: u16,
    /// 8-octet LSP id: system-id (6) + pseudonode (1) + LSP number (1).
    lsp_id: [8]u8,
    sequence_number: u32,
    checksum: u16,
    flags: LspFlags,
    tlv_bytes: []const u8,

    pub fn decode(bytes: []const u8) DecodeError!Lsp {
        const h = try checkCommon(bytes, &.{ .l1_lsp, .l2_lsp });
        if (bytes.len < lsp_fixed_len) return error.TruncatedBody;
        const region = try tlvRegion(bytes, lsp_fixed_len, 8);
        return .{
            .header = h,
            .pdu_length = std.mem.readInt(u16, bytes[8..10], .big),
            .remaining_lifetime = std.mem.readInt(u16, bytes[10..12], .big),
            .lsp_id = bytes[12..20].*,
            .sequence_number = std.mem.readInt(u32, bytes[20..24], .big),
            .checksum = std.mem.readInt(u16, bytes[24..26], .big),
            .flags = LspFlags.fromByte(bytes[26]),
            .tlv_bytes = region,
        };
    }

    pub fn tlvIterator(p: Lsp) tlv.TlvIterator {
        return tlv.TlvIterator.init(p.tlv_bytes);
    }
};

pub const LspFields = struct {
    is_l2: bool = false,
    remaining_lifetime: u16,
    lsp_id: [8]u8,
    sequence_number: u32,
    /// Checksum to stamp verbatim; 0 means "checksumming not in use" (ISO 10589).
    checksum: u16 = 0,
    flags: LspFlags,
    max_area_addresses: u8 = header.default_max_area_addresses,
};

pub const LspBuilder = struct {
    buf: []u8,
    tlvs: tlv.Builder,

    pub fn init(buf: []u8, f: LspFields) error{BufferTooSmall}!LspBuilder {
        if (buf.len < lsp_fixed_len) return error.BufferTooSmall;
        header.encode(.{
            .length_indicator = lsp_fixed_len,
            .pdu_type = if (f.is_l2) .l2_lsp else .l1_lsp,
            .id_length = modeled_id_length,
            .max_area_addresses = f.max_area_addresses,
        }, buf[0..header.common_header_len]) catch unreachable;
        std.mem.writeInt(u16, buf[8..10], 0, .big); // PDU length, backfilled
        std.mem.writeInt(u16, buf[10..12], f.remaining_lifetime, .big);
        @memcpy(buf[12..20], &f.lsp_id);
        std.mem.writeInt(u32, buf[20..24], f.sequence_number, .big);
        std.mem.writeInt(u16, buf[24..26], f.checksum, .big);
        buf[26] = f.flags.toByte();
        return .{ .buf = buf, .tlvs = tlv.Builder.init(buf[lsp_fixed_len..]) };
    }

    pub fn finish(b: *LspBuilder) []const u8 {
        const total: u16 = @intCast(lsp_fixed_len + b.tlvs.pos);
        std.mem.writeInt(u16, b.buf[8..10], total, .big);
        return b.buf[0..total];
    }
};

// ── CSNP / PSNP (types 24/25, 26/27) ─────────────────────────────────────────

pub const csnp_fixed_len: usize = 33;
pub const psnp_fixed_len: usize = 17;

/// A decoded CSNP body (ISO 10589 §9.10): a source id and the [start, end]
/// LSP-id range it summarises, followed by LSP Entries (#9) TLVs.
pub const Csnp = struct {
    header: CommonHeader,
    pdu_length: u16,
    /// 7-octet source id: system id (6) + circuit id (1).
    source_id: [7]u8,
    start_lsp_id: [8]u8,
    end_lsp_id: [8]u8,
    tlv_bytes: []const u8,

    pub fn decode(bytes: []const u8) DecodeError!Csnp {
        const h = try checkCommon(bytes, &.{ .l1_csnp, .l2_csnp });
        if (bytes.len < csnp_fixed_len) return error.TruncatedBody;
        const region = try tlvRegion(bytes, csnp_fixed_len, 8);
        return .{
            .header = h,
            .pdu_length = std.mem.readInt(u16, bytes[8..10], .big),
            .source_id = bytes[10..17].*,
            .start_lsp_id = bytes[17..25].*,
            .end_lsp_id = bytes[25..33].*,
            .tlv_bytes = region,
        };
    }

    pub fn tlvIterator(p: Csnp) tlv.TlvIterator {
        return tlv.TlvIterator.init(p.tlv_bytes);
    }
};

pub const CsnpFields = struct {
    is_l2: bool = false,
    source_id: [7]u8,
    start_lsp_id: [8]u8,
    end_lsp_id: [8]u8,
    max_area_addresses: u8 = header.default_max_area_addresses,
};

pub const CsnpBuilder = struct {
    buf: []u8,
    tlvs: tlv.Builder,

    pub fn init(buf: []u8, f: CsnpFields) error{BufferTooSmall}!CsnpBuilder {
        if (buf.len < csnp_fixed_len) return error.BufferTooSmall;
        header.encode(.{
            .length_indicator = csnp_fixed_len,
            .pdu_type = if (f.is_l2) .l2_csnp else .l1_csnp,
            .id_length = modeled_id_length,
            .max_area_addresses = f.max_area_addresses,
        }, buf[0..header.common_header_len]) catch unreachable;
        std.mem.writeInt(u16, buf[8..10], 0, .big);
        @memcpy(buf[10..17], &f.source_id);
        @memcpy(buf[17..25], &f.start_lsp_id);
        @memcpy(buf[25..33], &f.end_lsp_id);
        return .{ .buf = buf, .tlvs = tlv.Builder.init(buf[csnp_fixed_len..]) };
    }

    pub fn finish(b: *CsnpBuilder) []const u8 {
        const total: u16 = @intCast(csnp_fixed_len + b.tlvs.pos);
        std.mem.writeInt(u16, b.buf[8..10], total, .big);
        return b.buf[0..total];
    }
};

/// A decoded PSNP body (ISO 10589 §9.11): a source id followed by LSP Entries
/// (#9) TLVs acknowledging/requesting specific LSPs.
pub const Psnp = struct {
    header: CommonHeader,
    pdu_length: u16,
    source_id: [7]u8,
    tlv_bytes: []const u8,

    pub fn decode(bytes: []const u8) DecodeError!Psnp {
        const h = try checkCommon(bytes, &.{ .l1_psnp, .l2_psnp });
        if (bytes.len < psnp_fixed_len) return error.TruncatedBody;
        const region = try tlvRegion(bytes, psnp_fixed_len, 8);
        return .{
            .header = h,
            .pdu_length = std.mem.readInt(u16, bytes[8..10], .big),
            .source_id = bytes[10..17].*,
            .tlv_bytes = region,
        };
    }

    pub fn tlvIterator(p: Psnp) tlv.TlvIterator {
        return tlv.TlvIterator.init(p.tlv_bytes);
    }
};

pub const PsnpFields = struct {
    is_l2: bool = false,
    source_id: [7]u8,
    max_area_addresses: u8 = header.default_max_area_addresses,
};

pub const PsnpBuilder = struct {
    buf: []u8,
    tlvs: tlv.Builder,

    pub fn init(buf: []u8, f: PsnpFields) error{BufferTooSmall}!PsnpBuilder {
        if (buf.len < psnp_fixed_len) return error.BufferTooSmall;
        header.encode(.{
            .length_indicator = psnp_fixed_len,
            .pdu_type = if (f.is_l2) .l2_psnp else .l1_psnp,
            .id_length = modeled_id_length,
            .max_area_addresses = f.max_area_addresses,
        }, buf[0..header.common_header_len]) catch unreachable;
        std.mem.writeInt(u16, buf[8..10], 0, .big);
        @memcpy(buf[10..17], &f.source_id);
        return .{ .buf = buf, .tlvs = tlv.Builder.init(buf[psnp_fixed_len..]) };
    }

    pub fn finish(b: *PsnpBuilder) []const u8 {
        const total: u16 = @intCast(psnp_fixed_len + b.tlvs.pos);
        std.mem.writeInt(u16, b.buf[8..10], total, .big);
        return b.buf[0..total];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const tlvs = @import("tlvs.zig");

test "P2P IIH builds, PDU length backfills, decodes with TLVs" {
    var buf: [128]u8 = undefined;
    var b = try P2pHelloBuilder.init(&buf, .{
        .source_id = .{ 0, 0, 0, 0, 0, 1 },
        .holding_time = 30,
        .local_circuit_id = 1,
    });
    try tlvs.addProtocolsSupported(&b.tlvs, &.{tlvs.nlpid_ipv4});
    try tlvs.addAreaAddresses(&b.tlvs, &.{&[_]u8{ 0x49, 0x00, 0x01 }});
    const wire = b.finish();

    const p = try P2pHello.decode(wire);
    try testing.expectEqual(PduType.p2p_iih, p.header.pdu_type);
    try testing.expectEqual(@as(u16, 30), p.holding_time);
    try testing.expectEqual(@as(u8, 1), p.local_circuit_id);
    try testing.expectEqual(@as(u16, @intCast(wire.len)), p.pdu_length);
    // TLVs present.
    try testing.expectEqualSlices(u8, &.{tlvs.nlpid_ipv4}, (try tlv.findFirst(p.tlv_bytes, tlvs.code.protocols_supported)).?);
}

test "LAN IIH round-trips source-id, priority, LAN-id" {
    var buf: [128]u8 = undefined;
    var b = try LanHelloBuilder.init(&buf, .{
        .is_l2 = true,
        .source_id = .{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 },
        .holding_time = 27,
        .priority = 100,
        .lan_id = .{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02 },
    });
    const m1 = [6]u8{ 0x00, 0x1b, 0x21, 0x3c, 0x9d, 0xf8 };
    try tlvs.addIsNeighboursIih(&b.tlvs, &.{m1});
    const wire = b.finish();

    const p = try LanHello.decode(wire);
    try testing.expectEqual(PduType.l2_lan_iih, p.header.pdu_type);
    try testing.expectEqual(@as(u7, 100), p.priority);
    try testing.expectEqual(@as(u8, 0x02), p.lan_id[6]);
    var si = tlvs.SnpaIterator.init((try tlv.findFirst(p.tlv_bytes, tlvs.code.is_neighbours_iih)).?);
    try testing.expectEqual(m1, (try si.next()).?);
}

test "LSP flags octet packs/unpacks and body round-trips" {
    const flags: LspFlags = .{ .partition_repair = false, .attached = 0, .overload = true, .is_type = 1 };
    try testing.expectEqual(@as(u8, 0x04 | 0x01), flags.toByte());
    try testing.expectEqual(flags, LspFlags.fromByte(flags.toByte()));

    var buf: [128]u8 = undefined;
    var b = try LspBuilder.init(&buf, .{
        .remaining_lifetime = 1200,
        .lsp_id = .{ 0, 0, 0, 0, 0, 1, 0, 0 },
        .sequence_number = 1,
        .flags = flags,
    });
    try tlvs.addHostname(&b.tlvs, "node-a");
    const wire = b.finish();
    const p = try Lsp.decode(wire);
    try testing.expect(p.flags.overload);
    try testing.expectEqual(@as(u32, 1), p.sequence_number);
    try testing.expectEqualStrings("node-a", (try tlv.findFirst(p.tlv_bytes, tlvs.code.dynamic_hostname)).?);
}

test "CSNP / PSNP carry LSP Entries and round-trip" {
    const entries = [_]tlvs.LspEntry{
        .{ .remaining_lifetime = 1000, .lsp_id = .{ 0, 0, 0, 0, 0, 1, 0, 0 }, .sequence_number = 3, .checksum = 0x1111 },
    };
    var cbuf: [128]u8 = undefined;
    var cb = try CsnpBuilder.init(&cbuf, .{
        .source_id = .{ 0, 0, 0, 0, 0, 1, 0 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xFF),
    });
    try tlvs.addLspEntries(&cb.tlvs, &entries);
    const cwire = cb.finish();
    const c = try Csnp.decode(cwire);
    try testing.expectEqual(@as(u8, 0xFF), c.end_lsp_id[0]);
    var ci = tlvs.LspEntryIterator.init((try tlv.findFirst(c.tlv_bytes, tlvs.code.lsp_entries)).?);
    try testing.expectEqual(@as(u32, 3), (try ci.next()).?.sequence_number);

    var pbuf: [128]u8 = undefined;
    var pb = try PsnpBuilder.init(&pbuf, .{ .source_id = .{ 0, 0, 0, 0, 0, 2, 0 } });
    try tlvs.addLspEntries(&pb.tlvs, &entries);
    const pwire = pb.finish();
    const ps = try Psnp.decode(pwire);
    try testing.expectEqual(@as(u8, 2), ps.source_id[5]);
}

test "wrong PDU type and unsupported id-length are typed errors" {
    var buf: [64]u8 = undefined;
    var b = try P2pHelloBuilder.init(&buf, .{ .source_id = @splat(0), .holding_time = 1 });
    const wire = b.finish();
    // Decoding a P2P IIH as an LSP is WrongPduType.
    try testing.expectError(error.WrongPduType, Lsp.decode(wire));
    // Force a non-6 id-length in the common header.
    var mangled: [64]u8 = undefined;
    @memcpy(mangled[0..wire.len], wire);
    mangled[3] = 7; // ID length 7
    try testing.expectError(error.UnsupportedIdLength, P2pHello.decode(mangled[0..wire.len]));
}

test "body PDU-length lying beyond the buffer is rejected" {
    var buf: [64]u8 = undefined;
    var b = try P2pHelloBuilder.init(&buf, .{ .source_id = @splat(0), .holding_time = 1 });
    const wire = b.finish();
    var mangled: [64]u8 = undefined;
    @memcpy(mangled[0..wire.len], wire);
    std.mem.writeInt(u16, mangled[17..19], 0xFFFF, .big); // claim 65535-byte PDU
    try testing.expectError(error.BadPduLength, P2pHello.decode(mangled[0..wire.len]));
    // And a PDU length below the fixed header.
    std.mem.writeInt(u16, mangled[17..19], 5, .big);
    try testing.expectError(error.BadPduLength, P2pHello.decode(mangled[0..wire.len]));
}

test "TruncatedBody when the buffer is shorter than the fixed header" {
    // Length-indicator 8 passes the common-header check, but a P2P IIH needs a
    // 20-octet fixed header — only 10 bytes here, so the body decode trips.
    const short = [_]u8{ 0x83, 0x08, 0x01, 0x06, 0x11, 0x01, 0x00, 0x03, 0x03, 0x00 };
    try testing.expectError(error.TruncatedBody, P2pHello.decode(&short));
}
