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
//! | 135  | Extended IP Reachability   | RFC 5305 §4       |
//! | 236  | IPv6 Reachability          | RFC 5308 §2       |
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
    pub const extended_ip_reachability: u8 = 135;
    pub const ipv6_reachability: u8 = 236;
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

// ── #135 Extended IP Reachability (RFC 5305 §4) / #236 IPv6 Reachability (RFC 5308 §2) ──

/// One Extended IP Reachability (#135) entry: `metric(4) || control(1) ||
/// prefix(ceil(len/8)) [|| sub_len(1) || sub_tlvs]`, control = Up/Down (0x80),
/// sub-TLVs present (0x40), prefix length (low 6 bits, 0..32).
pub const ExtIpReachEntry = struct {
    metric: u32,
    /// The Up/Down bit (RFC 5305 §4.1): set on a prefix leaked from a higher
    /// level into a lower one (RFC 5302), so it is not leaked back up.
    up_down: bool = false,
    prefix_len: u8,
    /// The prefix, host bits cleared (a sender's stray bits past `prefix_len`
    /// are not part of the prefix and are masked off on decode).
    prefix: [4]u8,
    /// The prefix sub-TLV block, empty if none (walk with `tlv.TlvIterator`).
    sub_tlvs: []const u8 = &.{},
};

/// Clear the bits of `bytes` past the first `len` bits.
fn maskPrefix(bytes: []u8, len: u8) void {
    for (bytes, 0..) |*b, i| {
        const lo = i * 8;
        if (len >= lo + 8) continue;
        if (len <= lo) {
            b.* = 0;
        } else {
            const keep: u3 = @intCast(len - lo); // 1..7 bits of this octet
            b.* &= ~(@as(u8, 0xff) >> keep);
        }
    }
}

/// Walks an Extended IP Reachability (#135) value.
pub const ExtIpReachIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) ExtIpReachIterator {
        return .{ .buf = value };
    }

    /// `BadTlvLength` for a truncated entry or a prefix length above 32.
    pub fn next(it: *ExtIpReachIterator) ParseError!?ExtIpReachEntry {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 5 > it.buf.len) return error.BadTlvLength;
        const metric = std.mem.readInt(u32, it.buf[it.pos..][0..4], .big);
        const ctl = it.buf[it.pos + 4];
        const plen: u8 = ctl & 0x3f;
        if (plen > 32) return error.BadTlvLength;
        const nbytes: usize = (plen + 7) / 8;
        var p = it.pos + 5;
        if (p + nbytes > it.buf.len) return error.BadTlvLength;
        var prefix: [4]u8 = @splat(0);
        @memcpy(prefix[0..nbytes], it.buf[p..][0..nbytes]);
        maskPrefix(&prefix, plen);
        p += nbytes;
        var subs: []const u8 = &.{};
        if ((ctl & 0x40) != 0) {
            if (p >= it.buf.len) return error.BadTlvLength;
            const sl: usize = it.buf[p];
            if (p + 1 + sl > it.buf.len) return error.BadTlvLength;
            subs = it.buf[p + 1 ..][0..sl];
            p += 1 + sl;
        }
        it.pos = p;
        return .{ .metric = metric, .up_down = (ctl & 0x80) != 0, .prefix_len = plen, .prefix = prefix, .sub_tlvs = subs };
    }
};

/// Appends one Extended IP Reachability (#135) TLV with a single entry.
pub fn addExtIpReach(b: *tlv.Builder, e: ExtIpReachEntry) (tlv.BuildError || ParseError)!void {
    if (e.prefix_len > 32) return error.BadTlvLength;
    var scratch: [tlv.max_value_len]u8 = undefined;
    const nbytes: usize = (e.prefix_len + 7) / 8;
    const has_sub = e.sub_tlvs.len != 0;
    const total = 5 + nbytes + (if (has_sub) 1 + e.sub_tlvs.len else 0);
    if (total > scratch.len or e.sub_tlvs.len > 255) return error.ValueTooLong;
    std.mem.writeInt(u32, scratch[0..4], e.metric, .big);
    scratch[4] = e.prefix_len | (if (e.up_down) @as(u8, 0x80) else 0) | (if (has_sub) @as(u8, 0x40) else 0);
    var pfx = e.prefix;
    maskPrefix(&pfx, e.prefix_len);
    @memcpy(scratch[5..][0..nbytes], pfx[0..nbytes]);
    if (has_sub) {
        scratch[5 + nbytes] = @intCast(e.sub_tlvs.len);
        @memcpy(scratch[6 + nbytes ..][0..e.sub_tlvs.len], e.sub_tlvs);
    }
    try b.addTlv(code.extended_ip_reachability, scratch[0..total]);
}

/// One IPv6 Reachability (#236) entry: `metric(4) || control(1) ||
/// prefix_len(1) || prefix(ceil(len/8)) [|| sub_len(1) || sub_tlvs]`, control =
/// Up/Down (0x80), External (0x40), sub-TLVs present (0x20).
pub const Ipv6ReachEntry = struct {
    metric: u32,
    up_down: bool = false,
    /// The X bit: the prefix was redistributed from another protocol.
    external: bool = false,
    prefix_len: u8,
    prefix: [16]u8,
    sub_tlvs: []const u8 = &.{},
};

/// Walks an IPv6 Reachability (#236) value.
pub const Ipv6ReachIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) Ipv6ReachIterator {
        return .{ .buf = value };
    }

    /// `BadTlvLength` for a truncated entry or a prefix length above 128.
    pub fn next(it: *Ipv6ReachIterator) ParseError!?Ipv6ReachEntry {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 6 > it.buf.len) return error.BadTlvLength;
        const metric = std.mem.readInt(u32, it.buf[it.pos..][0..4], .big);
        const ctl = it.buf[it.pos + 4];
        const plen = it.buf[it.pos + 5];
        if (plen > 128) return error.BadTlvLength;
        const nbytes: usize = (@as(usize, plen) + 7) / 8;
        var p = it.pos + 6;
        if (p + nbytes > it.buf.len) return error.BadTlvLength;
        var prefix: [16]u8 = @splat(0);
        @memcpy(prefix[0..nbytes], it.buf[p..][0..nbytes]);
        maskPrefix(&prefix, plen);
        p += nbytes;
        var subs: []const u8 = &.{};
        if ((ctl & 0x20) != 0) {
            if (p >= it.buf.len) return error.BadTlvLength;
            const sl: usize = it.buf[p];
            if (p + 1 + sl > it.buf.len) return error.BadTlvLength;
            subs = it.buf[p + 1 ..][0..sl];
            p += 1 + sl;
        }
        it.pos = p;
        return .{
            .metric = metric,
            .up_down = (ctl & 0x80) != 0,
            .external = (ctl & 0x40) != 0,
            .prefix_len = plen,
            .prefix = prefix,
            .sub_tlvs = subs,
        };
    }
};

/// Appends one IPv6 Reachability (#236) TLV with a single entry.
pub fn addIpv6Reach(b: *tlv.Builder, e: Ipv6ReachEntry) (tlv.BuildError || ParseError)!void {
    if (e.prefix_len > 128) return error.BadTlvLength;
    var scratch: [tlv.max_value_len]u8 = undefined;
    const nbytes: usize = (@as(usize, e.prefix_len) + 7) / 8;
    const has_sub = e.sub_tlvs.len != 0;
    const total = 6 + nbytes + (if (has_sub) 1 + e.sub_tlvs.len else 0);
    if (total > scratch.len or e.sub_tlvs.len > 255) return error.ValueTooLong;
    std.mem.writeInt(u32, scratch[0..4], e.metric, .big);
    scratch[4] = (if (e.up_down) @as(u8, 0x80) else 0) | (if (e.external) @as(u8, 0x40) else 0) | (if (has_sub) @as(u8, 0x20) else 0);
    scratch[5] = e.prefix_len;
    var pfx = e.prefix;
    maskPrefix(&pfx, e.prefix_len);
    @memcpy(scratch[6..][0..nbytes], pfx[0..nbytes]);
    if (has_sub) {
        scratch[6 + nbytes] = @intCast(e.sub_tlvs.len);
        @memcpy(scratch[7 + nbytes ..][0..e.sub_tlvs.len], e.sub_tlvs);
    }
    try b.addTlv(code.ipv6_reachability, scratch[0..total]);
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

test "extended IP reachability: RFC 5305 §4 layout, masking, up/down, sub-TLVs" {
    // 10.1.0.0/16 metric 20; 192.0.2.128/25 metric 5 with U/D set and one sub-TLV.
    const value = [_]u8{ 0, 0, 0, 20, 16, 10, 1 } ++
        [_]u8{ 0, 0, 0, 5, 0x80 | 0x40 | 25, 192, 0, 2, 0xff, 3, 1, 1, 0xaa };
    var it = ExtIpReachIterator.init(&value);
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u32, 20), a.metric);
    try testing.expectEqual(@as(u8, 16), a.prefix_len);
    try testing.expectEqualSlices(u8, &.{ 10, 1, 0, 0 }, &a.prefix);
    try testing.expect(!a.up_down and a.sub_tlvs.len == 0);
    const b = (try it.next()).?;
    try testing.expect(b.up_down);
    try testing.expectEqual(@as(u8, 25), b.prefix_len);
    // Host bits past /25 are masked: 0xff in the last octet keeps only the top bit.
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 0x80 }, &b.prefix);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 0xaa }, b.sub_tlvs);
    try testing.expectEqual(@as(?ExtIpReachEntry, null), try it.next());
}

test "extended IP reachability: default route, host route, builder round trip" {
    var buf: [128]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    try addExtIpReach(&b, .{ .metric = 1, .prefix_len = 0, .prefix = @splat(0) });
    try addExtIpReach(&b, .{ .metric = 0xFFFF_FFFF, .prefix_len = 32, .prefix = .{ 1, 2, 3, 4 }, .up_down = true, .sub_tlvs = &.{ 9, 0 } });
    var ti = tlv.TlvIterator.init(b.written());
    const t0 = (try ti.next()).?;
    try testing.expectEqual(code.extended_ip_reachability, t0.code);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 1, 0 }, t0.value);
    var it = ExtIpReachIterator.init((try ti.next()).?.value);
    const h = (try it.next()).?;
    try testing.expectEqual(@as(u32, 0xFFFF_FFFF), h.metric);
    try testing.expectEqual(@as(u8, 32), h.prefix_len);
    try testing.expect(h.up_down);
    try testing.expectEqualSlices(u8, &.{ 9, 0 }, h.sub_tlvs);
}

test "extended IP reachability: lies and out-of-range lengths are typed errors" {
    var it1 = ExtIpReachIterator.init(&.{ 0, 0, 0, 1, 33, 1, 2, 3, 4, 5 }); // /33
    try testing.expectError(error.BadTlvLength, it1.next());
    var it2 = ExtIpReachIterator.init(&.{ 0, 0, 0, 1, 24, 10, 1 }); // /24 needs 3 bytes
    try testing.expectError(error.BadTlvLength, it2.next());
    var it3 = ExtIpReachIterator.init(&.{ 0, 0, 0, 1, 0x40 | 8, 10, 9, 1 }); // sub_len 9, 1 byte present
    try testing.expectError(error.BadTlvLength, it3.next());
    var it4 = ExtIpReachIterator.init(&.{ 0, 0, 0 });
    try testing.expectError(error.BadTlvLength, it4.next());
    var none: [0]u8 = .{};
    var b = tlv.Builder.init(&none);
    try testing.expectError(error.BadTlvLength, addExtIpReach(&b, .{ .metric = 0, .prefix_len = 33, .prefix = @splat(0) }));
}

test "IPv6 reachability: RFC 5308 §2 layout, flags, masking, round trip" {
    // 2001:db8::/32 metric 10, X set; a /62 with U/D and a sub-TLV.
    var buf: [128]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    var p1: [16]u8 = @splat(0);
    p1[0..4].* = .{ 0x20, 0x01, 0x0d, 0xb8 };
    try addIpv6Reach(&b, .{ .metric = 10, .external = true, .prefix_len = 32, .prefix = p1 });
    var p2 = p1;
    p2[4..8].* = .{ 0, 1, 0, 3 }; // bit 63 set: stray, past /62 below
    try addIpv6Reach(&b, .{ .metric = 256, .up_down = true, .prefix_len = 62, .prefix = p2, .sub_tlvs = &.{ 1, 1, 7 } });
    var ti = tlv.TlvIterator.init(b.written());
    const t0 = (try ti.next()).?;
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 10, 0x40, 32, 0x20, 0x01, 0x0d, 0xb8 }, t0.value);
    var it = Ipv6ReachIterator.init(t0.value);
    const a = (try it.next()).?;
    try testing.expect(a.external and !a.up_down);
    try testing.expectEqualSlices(u8, &p1, &a.prefix);
    var it2 = Ipv6ReachIterator.init((try ti.next()).?.value);
    const c = (try it2.next()).?;
    try testing.expect(c.up_down and !c.external);
    try testing.expectEqual(@as(u8, 62), c.prefix_len);
    // /62 keeps bits 0..61: the last octet 0x03 (bits 56..63) keeps 0x00 (top 6 bits of 0b11 -> 0)
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0 }, c.prefix[0..8]);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 7 }, c.sub_tlvs);
}

test "IPv6 reachability: lies and out-of-range lengths are typed errors" {
    var it1 = Ipv6ReachIterator.init(&.{ 0, 0, 0, 1, 0, 129, 0 });
    try testing.expectError(error.BadTlvLength, it1.next());
    var it2 = Ipv6ReachIterator.init(&.{ 0, 0, 0, 1, 0, 64, 1, 2 }); // /64 needs 8 bytes
    try testing.expectError(error.BadTlvLength, it2.next());
    var it3 = Ipv6ReachIterator.init(&.{ 0, 0, 0, 1, 0x20, 0, 5 }); // S set, sub_len 5 with none
    try testing.expectError(error.BadTlvLength, it3.next());
    var it4 = Ipv6ReachIterator.init(&.{ 0, 0, 0, 1, 0x20, 0 }); // S set, sub_len missing
    try testing.expectError(error.BadTlvLength, it4.next());
    var it5 = Ipv6ReachIterator.init(&.{ 0, 0, 0, 1, 0 });
    try testing.expectError(error.BadTlvLength, it5.next());
}
