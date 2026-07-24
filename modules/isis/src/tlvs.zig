// SPDX-License-Identifier: MIT

//! Typed models for the common IS-IS TLVs, layered on the bounds-checked
//! `tlv.TlvIterator`. Each model is a **view** over a value subslice (no copy,
//! no allocation) plus, where useful, a nested bounds-checked iterator for a
//! repeated inner structure. Any TLV code not modeled here is still reachable
//! as a `tlv.RawTlv` — the raw escape hatch — and round-trips verbatim.
//!
//! Modeled codes (numbers from ISO/IEC 10589 and the IANA IS-IS TLV registry):
//!
//! | Code | Name                       | Source            |
//! |------|----------------------------|-------------------|
//! | 1    | Area Addresses             | ISO 10589         |
//! | 2    | IS Neighbours (LSP)        | ISO 10589 §9.8    |
//! | 6    | IS Neighbours (IIH SNPAs)  | ISO 10589 §9.5/9.7|
//! | 9    | LSP Entries                | ISO 10589 §9.10   |
//! | 22   | Extended IS Reachability   | RFC 5305          |
//! | 129  | Protocols Supported        | RFC 1195          |
//! | 137  | Dynamic Hostname           | RFC 5301          |
//!
//! Provenance: clean-room from the specs above; see /NOTICE (none required).

const std = @import("std");
const tlv = @import("tlv.zig");

/// IANA / ISO 10589 TLV code points for the modeled TLVs. Unmodeled codes stay
/// reachable through the raw walker.
pub const code = struct {
    pub const area_addresses: u8 = 1;
    pub const is_neighbours_lsp: u8 = 2;
    pub const is_neighbours_iih: u8 = 6;
    pub const padding: u8 = 8;
    pub const lsp_entries: u8 = 9;
    pub const authentication: u8 = 10;
    pub const extended_is_reachability: u8 = 22;
    pub const ip_interface_address: u8 = 132;
    pub const protocols_supported: u8 = 129;
    pub const dynamic_hostname: u8 = 137;
    /// MT-Port-Capability (RFC 6165 / RFC 6329) — carried in IIH PDUs.
    pub const mt_port_capability: u8 = 143;
    /// MT-Capability (RFC 6329) — carried in LSPs; holds the SPB sub-TLVs.
    pub const mt_capability: u8 = 144;
};

/// NLPID values seen in a Protocols Supported (#129) TLV.
pub const nlpid_ipv4: u8 = 0xCC;
pub const nlpid_ipv6: u8 = 0x8E;

pub const ParseError = error{
    /// A TLV value's length is not consistent with its fixed record structure.
    BadTlvLength,
};

// ── #1 Area Addresses ────────────────────────────────────────────────────────

/// Walks an Area Addresses (#1) value: repeated `len(1) || area(len)` records.
/// Each yielded slice is one area address (a variable-length NSAP area prefix),
/// a subslice of the input.
pub const AreaAddressIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) AreaAddressIterator {
        return .{ .buf = value };
    }

    pub fn next(it: *AreaAddressIterator) ParseError!?[]const u8 {
        if (it.pos == it.buf.len) return null;
        const len: usize = it.buf[it.pos];
        if (it.pos + 1 + len > it.buf.len) return error.BadTlvLength;
        const area = it.buf[it.pos + 1 ..][0..len];
        it.pos += 1 + len;
        return area;
    }
};

/// Appends an Area Addresses (#1) TLV built from a slice of area prefixes.
pub fn addAreaAddresses(b: *tlv.Builder, areas: []const []const u8) (tlv.BuildError || ParseError)!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    var n: usize = 0;
    for (areas) |area| {
        if (area.len > 255 or n + 1 + area.len > scratch.len) return error.ValueTooLong;
        scratch[n] = @intCast(area.len);
        @memcpy(scratch[n + 1 ..][0..area.len], area);
        n += 1 + area.len;
    }
    try b.addTlv(code.area_addresses, scratch[0..n]);
}

// ── #6 IS Neighbours (IIH) — a list of 6-octet SNPA (MAC) addresses ──────────

/// Walks an IS Neighbours (#6) value: a flat list of 6-octet SNPA addresses.
pub const SnpaIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) SnpaIterator {
        return .{ .buf = value };
    }

    pub fn next(it: *SnpaIterator) ParseError!?[6]u8 {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 6 > it.buf.len) return error.BadTlvLength;
        const mac = it.buf[it.pos..][0..6].*;
        it.pos += 6;
        return mac;
    }
};

pub fn addIsNeighboursIih(b: *tlv.Builder, snpas: []const [6]u8) tlv.BuildError!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    var n: usize = 0;
    for (snpas) |mac| {
        if (n + 6 > scratch.len) return error.ValueTooLong;
        @memcpy(scratch[n..][0..6], &mac);
        n += 6;
    }
    try b.addTlv(code.is_neighbours_iih, scratch[0..n]);
}

// ── #2 IS Neighbours (LSP, old-style ISO 10589 §9.8) ─────────────────────────

/// One old-style IS reachability entry: four 1-octet metrics (default/delay/
/// expense/error, each with its I/E and supported flags kept raw) and the
/// 7-octet neighbour id (system-id + pseudonode).
pub const IsReachEntry = struct {
    default_metric: u8,
    delay_metric: u8,
    expense_metric: u8,
    error_metric: u8,
    neighbour_id: [7]u8,
};

/// Walks an IS Neighbours (#2) value: a 1-octet Virtual Flag followed by
/// repeated 11-octet entries. `virtualFlag` reads the leading flag.
pub const IsReachIterator = struct {
    buf: []const u8,
    pos: usize = 1, // skip the leading Virtual Flag octet

    pub fn init(value: []const u8) ParseError!IsReachIterator {
        if (value.len < 1) return error.BadTlvLength;
        return .{ .buf = value };
    }

    pub fn virtualFlag(it: *const IsReachIterator) u8 {
        return it.buf[0];
    }

    pub fn next(it: *IsReachIterator) ParseError!?IsReachEntry {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 11 > it.buf.len) return error.BadTlvLength;
        const e = it.buf[it.pos..][0..11];
        it.pos += 11;
        return .{
            .default_metric = e[0],
            .delay_metric = e[1],
            .expense_metric = e[2],
            .error_metric = e[3],
            .neighbour_id = e[4..11].*,
        };
    }
};

// ── #22 Extended IS Reachability (RFC 5305) — the sub-TLV bearer ─────────────

/// One Extended IS Reachability entry: a 7-octet neighbour id, a 24-bit metric,
/// and the raw sub-TLV block (walk it with `tlv.TlvIterator`). The sub-TLV
/// length is validated against the entry, so `sub_tlvs` never escapes the value.
pub const ExtIsReachEntry = struct {
    neighbour_id: [7]u8,
    metric: u24,
    /// The sub-TLV bytes for this neighbour (may be empty). Walk with
    /// `tlv.TlvIterator` — the same bounds-checked machinery.
    sub_tlvs: []const u8,

    /// Convenience: a bounds-checked walk of this entry's sub-TLVs.
    pub fn subTlvIterator(e: ExtIsReachEntry) tlv.TlvIterator {
        return tlv.TlvIterator.init(e.sub_tlvs);
    }
};

/// Walks an Extended IS Reachability (#22) value: repeated
/// `neighbour(7) || metric(3) || sub_len(1) || sub_tlvs(sub_len)` records.
pub const ExtIsReachIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) ExtIsReachIterator {
        return .{ .buf = value };
    }

    pub fn next(it: *ExtIsReachIterator) ParseError!?ExtIsReachEntry {
        if (it.pos == it.buf.len) return null;
        // Fixed prefix: 7 (neighbour) + 3 (metric) + 1 (sub-TLV length).
        if (it.pos + 11 > it.buf.len) return error.BadTlvLength;
        const neighbour = it.buf[it.pos..][0..7].*;
        const metric: u24 = std.mem.readInt(u24, it.buf[it.pos + 7 ..][0..3], .big);
        const sub_len: usize = it.buf[it.pos + 10];
        const sub_start = it.pos + 11;
        if (sub_start + sub_len > it.buf.len) return error.BadTlvLength;
        const sub_tlvs = it.buf[sub_start..][0..sub_len];
        it.pos = sub_start + sub_len;
        return .{ .neighbour_id = neighbour, .metric = metric, .sub_tlvs = sub_tlvs };
    }
};

/// Appends one Extended IS Reachability (#22) TLV with a single neighbour entry
/// and an already-serialized sub-TLV block. (One entry keeps the encoder simple;
/// the decoder handles any number.)
pub fn addExtendedIsReach(
    b: *tlv.Builder,
    neighbour_id: [7]u8,
    metric: u24,
    sub_tlvs: []const u8,
) tlv.BuildError!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    if (11 + sub_tlvs.len > scratch.len) return error.ValueTooLong;
    @memcpy(scratch[0..7], &neighbour_id);
    std.mem.writeInt(u24, scratch[7..10], metric, .big);
    scratch[10] = @intCast(sub_tlvs.len);
    @memcpy(scratch[11..][0..sub_tlvs.len], sub_tlvs);
    try b.addTlv(code.extended_is_reachability, scratch[0 .. 11 + sub_tlvs.len]);
}

// ── #129 Protocols Supported / #137 Dynamic Hostname ─────────────────────────

/// Appends a Protocols Supported (#129) TLV: a flat list of NLPID octets.
pub fn addProtocolsSupported(b: *tlv.Builder, nlpids: []const u8) tlv.BuildError!void {
    try b.addTlv(code.protocols_supported, nlpids);
}

/// Appends a Dynamic Hostname (#137) TLV.
pub fn addHostname(b: *tlv.Builder, name: []const u8) tlv.BuildError!void {
    try b.addTlv(code.dynamic_hostname, name);
}

// ── #9 LSP Entries (for CSNP / PSNP) ─────────────────────────────────────────

/// One entry of an LSP Entries (#9) TLV: a 16-octet record naming an LSP and
/// its sequence/lifetime/checksum, as summarised in an SNP.
pub const LspEntry = struct {
    remaining_lifetime: u16,
    /// 8-octet LSP id: system-id (6) + pseudonode (1) + LSP number (1).
    lsp_id: [8]u8,
    sequence_number: u32,
    checksum: u16,
};

/// Walks an LSP Entries (#9) value: repeated 16-octet records.
pub const LspEntryIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) LspEntryIterator {
        return .{ .buf = value };
    }

    pub fn next(it: *LspEntryIterator) ParseError!?LspEntry {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 16 > it.buf.len) return error.BadTlvLength;
        const e = it.buf[it.pos..][0..16];
        it.pos += 16;
        return .{
            .remaining_lifetime = std.mem.readInt(u16, e[0..2], .big),
            .lsp_id = e[2..10].*,
            .sequence_number = std.mem.readInt(u32, e[10..14], .big),
            .checksum = std.mem.readInt(u16, e[14..16], .big),
        };
    }
};

/// Appends an LSP Entries (#9) TLV from a slice of entries.
pub fn addLspEntries(b: *tlv.Builder, entries: []const LspEntry) tlv.BuildError!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    var n: usize = 0;
    for (entries) |e| {
        if (n + 16 > scratch.len) return error.ValueTooLong;
        std.mem.writeInt(u16, scratch[n..][0..2], e.remaining_lifetime, .big);
        @memcpy(scratch[n + 2 ..][0..8], &e.lsp_id);
        std.mem.writeInt(u32, scratch[n + 10 ..][0..4], e.sequence_number, .big);
        std.mem.writeInt(u16, scratch[n + 14 ..][0..2], e.checksum, .big);
        n += 16;
    }
    try b.addTlv(code.lsp_entries, scratch[0..n]);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "area addresses round-trip, including empty and multiple" {
    var buf: [64]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    const area1 = [_]u8{ 0x49, 0x00, 0x01 };
    const area2 = [_]u8{ 0x49, 0x00, 0x02, 0xaa };
    try addAreaAddresses(&b, &.{ &area1, &area2 });
    var it = tlv.TlvIterator.init(b.written());
    const t = (try it.next()).?;
    try testing.expectEqual(code.area_addresses, t.code);
    var ai = AreaAddressIterator.init(t.value);
    try testing.expectEqualSlices(u8, &area1, (try ai.next()).?);
    try testing.expectEqualSlices(u8, &area2, (try ai.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try ai.next());
}

test "area address record lying about its length is a typed error" {
    var ai = AreaAddressIterator.init(&[_]u8{ 0x05, 0x49, 0x00 }); // says 5, has 2
    try testing.expectError(error.BadTlvLength, ai.next());
}

test "IS neighbours (IIH) SNPA list round-trips" {
    var buf: [64]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    const m1 = [6]u8{ 0x00, 0x1b, 0x21, 0x3c, 0x9d, 0xf8 };
    const m2 = [6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    try addIsNeighboursIih(&b, &.{ m1, m2 });
    const val = (try tlv.findFirst(b.written(), code.is_neighbours_iih)).?;
    var si = SnpaIterator.init(val);
    try testing.expectEqual(m1, (try si.next()).?);
    try testing.expectEqual(m2, (try si.next()).?);
    try testing.expectEqual(@as(?[6]u8, null), try si.next());
    // A trailing partial SNPA is rejected.
    var bad = SnpaIterator.init(&[_]u8{ 0, 0, 0, 0, 0 });
    try testing.expectError(error.BadTlvLength, bad.next());
}

test "old-style IS reachability entries decode with the virtual flag" {
    const value = [_]u8{0x00} // virtual flag
        ++ [_]u8{ 0x0a, 0x80, 0x80, 0x80 } // metrics: default 10, others "not supported"
        ++ [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 }; // neighbour id
    var it = try IsReachIterator.init(&value);
    try testing.expectEqual(@as(u8, 0), it.virtualFlag());
    const e = (try it.next()).?;
    try testing.expectEqual(@as(u8, 0x0a), e.default_metric);
    try testing.expectEqual(@as(u8, 0x02), e.neighbour_id[5]);
    try testing.expectEqual(@as(?IsReachEntry, null), try it.next());
    // Truncated (empty) value has no virtual flag → error.
    try testing.expectError(error.BadTlvLength, IsReachIterator.init(&.{}));
}

test "extended IS reachability with sub-TLVs round-trips and nests safely" {
    // Build a sub-TLV block (one sub-TLV: code 4, value = 4-byte link id).
    var sub_buf: [32]u8 = undefined;
    var sb = tlv.Builder.init(&sub_buf);
    try sb.addTlv(4, &.{ 0x0a, 0x00, 0x00, 0x01 });

    var buf: [64]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    const nbr = [7]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00 };
    try addExtendedIsReach(&b, nbr, 0x0a_00_00, sb.written());

    const val = (try tlv.findFirst(b.written(), code.extended_is_reachability)).?;
    var it = ExtIsReachIterator.init(val);
    const e = (try it.next()).?;
    try testing.expectEqual(nbr, e.neighbour_id);
    try testing.expectEqual(@as(u24, 0x0a_00_00), e.metric);
    // Walk the nested sub-TLVs with the same bounds-checked iterator.
    var subs = e.subTlvIterator();
    const s = (try subs.next()).?;
    try testing.expectEqual(@as(u8, 4), s.code);
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x00, 0x00, 0x01 }, s.value);
    try testing.expectEqual(@as(?tlv.RawTlv, null), try subs.next());
    try testing.expectEqual(@as(?ExtIsReachEntry, null), try it.next());
}

test "extended IS reachability sub-length lie is rejected" {
    // neighbour(7) + metric(3) + sub_len=200 but no sub bytes present.
    const value = [_]u8{ 0, 0, 0, 0, 0, 0, 0 } ++ [_]u8{ 0, 0, 0 } ++ [_]u8{200};
    var it = ExtIsReachIterator.init(&value);
    try testing.expectError(error.BadTlvLength, it.next());
}

test "LSP entries round-trip (CSNP/PSNP payload)" {
    var buf: [64]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    const entries = [_]LspEntry{
        .{ .remaining_lifetime = 1198, .lsp_id = .{ 0, 0, 0, 0, 0, 1, 0, 0 }, .sequence_number = 5, .checksum = 0x1234 },
        .{ .remaining_lifetime = 900, .lsp_id = .{ 0, 0, 0, 0, 0, 2, 0, 0 }, .sequence_number = 9, .checksum = 0xabcd },
    };
    try addLspEntries(&b, &entries);
    const val = (try tlv.findFirst(b.written(), code.lsp_entries)).?;
    var it = LspEntryIterator.init(val);
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u16, 1198), a.remaining_lifetime);
    try testing.expectEqual(@as(u32, 5), a.sequence_number);
    try testing.expectEqual(@as(u16, 0x1234), a.checksum);
    const b2 = (try it.next()).?;
    try testing.expectEqual(@as(u8, 2), b2.lsp_id[5]);
    try testing.expectEqual(@as(?LspEntry, null), try it.next());
}

test "protocols supported and hostname are flat values" {
    var buf: [64]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    try addProtocolsSupported(&b, &.{ nlpid_ipv4, nlpid_ipv6 });
    try addHostname(&b, "node-a");
    try testing.expectEqualSlices(u8, &.{ nlpid_ipv4, nlpid_ipv6 }, (try tlv.findFirst(b.written(), code.protocols_supported)).?);
    try testing.expectEqualStrings("node-a", (try tlv.findFirst(b.written(), code.dynamic_hostname)).?);
}
