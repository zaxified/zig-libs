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
    /// Extended Sequence Number (RFC 7602 section 3).
    pub const extended_sequence_number: u8 = 11;
    /// Purge Originator Identification (RFC 6232).
    pub const purge_originator: u8 = 13;
    /// IP Internal Reachability (RFC 1195, legacy narrow metrics).
    pub const ip_internal_reachability: u8 = 128;
    /// IP External Reachability (RFC 1195, legacy narrow metrics).
    pub const ip_external_reachability: u8 = 130;
    /// IPv6 Interface Address (RFC 5308 section 3).
    pub const ipv6_interface_address: u8 = 232;
    /// MT Intermediate Systems (RFC 5120 section 7.2).
    pub const mt_is_reachability: u8 = 222;
    /// Multi-Topology (RFC 5120 section 7.1), carried in IIHs and LSP fragment 0.
    pub const multi_topology: u8 = 229;
    /// MT IP Reachability (RFC 5120 section 7.3).
    pub const mt_ip_reachability: u8 = 235;
    /// MT IPv6 Reachability (RFC 5120 section 7.4).
    pub const mt_ipv6_reachability: u8 = 237;
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

/// Serialises one #135 entry into `scratch`, returning its length.
fn writeExtIpReach(scratch: []u8, e: ExtIpReachEntry) (tlv.BuildError || ParseError)!usize {
    if (e.prefix_len > 32) return error.BadTlvLength;
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
    return total;
}

/// Appends one Extended IP Reachability (#135) TLV with a single entry.
pub fn addExtIpReach(b: *tlv.Builder, e: ExtIpReachEntry) (tlv.BuildError || ParseError)!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    const n = try writeExtIpReach(&scratch, e);
    try b.addTlv(code.extended_ip_reachability, scratch[0..n]);
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

/// Serialises one #236 entry into `scratch`, returning its length.
fn writeIpv6Reach(scratch: []u8, e: Ipv6ReachEntry) (tlv.BuildError || ParseError)!usize {
    if (e.prefix_len > 128) return error.BadTlvLength;
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
    return total;
}

/// Appends one IPv6 Reachability (#236) TLV with a single entry.
pub fn addIpv6Reach(b: *tlv.Builder, e: Ipv6ReachEntry) (tlv.BuildError || ParseError)!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    const n = try writeIpv6Reach(&scratch, e);
    try b.addTlv(code.ipv6_reachability, scratch[0..n]);
}

// ── #128 / #130 legacy IP reachability (RFC 1195 section 5.2) ────────────────

/// One legacy IP reachability entry: four 1-octet metrics, IP address and
/// subnet mask. The default metric octet is `U/D(1) | I/E(1) | metric(6)`
/// (RFC 5302 section 3.1 reuses the top bit as Up/Down); the delay, expense
/// and error octets are `S(1) | I/E(1) | metric(6)` and stay raw (S = 1 means
/// "not supported"), like `IsReachEntry`.
pub const IpReachEntry = struct {
    /// The 6-bit default metric value.
    default_metric: u6,
    /// The default metric's I/E bit: an external metric type.
    default_external: bool = false,
    /// Up/Down bit of the default metric octet (RFC 5302).
    up_down: bool = false,
    delay_metric: u8 = 0x80,
    expense_metric: u8 = 0x80,
    error_metric: u8 = 0x80,
    address: [4]u8,
    mask: [4]u8,

    /// The prefix length when `mask` is contiguous (a run of ones from the
    /// top), else null.
    pub fn prefixLen(e: IpReachEntry) ?u8 {
        const m = std.mem.readInt(u32, &e.mask, .big);
        const ones = @clz(~m);
        const expect: u32 = if (ones == 0) 0 else ~@as(u32, 0) << @intCast(32 - ones);
        if (ones == 32) return 32;
        if (m != expect) return null;
        return @intCast(ones);
    }
};

/// Walks a legacy IP reachability (#128 or #130) value: repeated 12-octet records.
pub const IpReachIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) IpReachIterator {
        return .{ .buf = value };
    }

    pub fn next(it: *IpReachIterator) ParseError!?IpReachEntry {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 12 > it.buf.len) return error.BadTlvLength;
        const e = it.buf[it.pos..][0..12];
        it.pos += 12;
        return .{
            .default_metric = @intCast(e[0] & 0x3f),
            .default_external = (e[0] & 0x40) != 0,
            .up_down = (e[0] & 0x80) != 0,
            .delay_metric = e[1],
            .expense_metric = e[2],
            .error_metric = e[3],
            .address = e[4..8].*,
            .mask = e[8..12].*,
        };
    }
};

/// Appends a legacy IP reachability TLV (`code.ip_internal_reachability` or
/// `code.ip_external_reachability`) from a slice of entries.
pub fn addIpReach(b: *tlv.Builder, tlv_code: u8, entries: []const IpReachEntry) tlv.BuildError!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    var n: usize = 0;
    for (entries) |e| {
        if (n + 12 > scratch.len) return error.ValueTooLong;
        scratch[n] = @as(u8, e.default_metric) | (if (e.default_external) @as(u8, 0x40) else 0) | (if (e.up_down) @as(u8, 0x80) else 0);
        scratch[n + 1] = e.delay_metric;
        scratch[n + 2] = e.expense_metric;
        scratch[n + 3] = e.error_metric;
        @memcpy(scratch[n + 4 ..][0..4], &e.address);
        @memcpy(scratch[n + 8 ..][0..4], &e.mask);
        n += 12;
    }
    try b.addTlv(tlv_code, scratch[0..n]);
}

// ── #132 IP Interface Address / #232 IPv6 Interface Address ──────────────────

/// Walks an IP Interface Address (#132, RFC 1195) value: a flat list of 4-octet addresses.
pub const Ipv4AddressIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) Ipv4AddressIterator {
        return .{ .buf = value };
    }

    pub fn next(it: *Ipv4AddressIterator) ParseError!?[4]u8 {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 4 > it.buf.len) return error.BadTlvLength;
        const a = it.buf[it.pos..][0..4].*;
        it.pos += 4;
        return a;
    }
};

/// Walks an IPv6 Interface Address (#232, RFC 5308 section 3) value: a flat list of 16-octet addresses.
pub const Ipv6AddressIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) Ipv6AddressIterator {
        return .{ .buf = value };
    }

    pub fn next(it: *Ipv6AddressIterator) ParseError!?[16]u8 {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 16 > it.buf.len) return error.BadTlvLength;
        const a = it.buf[it.pos..][0..16].*;
        it.pos += 16;
        return a;
    }
};

/// Appends an IP Interface Address (#132) TLV.
pub fn addIpv4InterfaceAddresses(b: *tlv.Builder, addrs: []const [4]u8) tlv.BuildError!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    var n: usize = 0;
    for (addrs) |a| {
        if (n + 4 > scratch.len) return error.ValueTooLong;
        @memcpy(scratch[n..][0..4], &a);
        n += 4;
    }
    try b.addTlv(code.ip_interface_address, scratch[0..n]);
}

/// Appends an IPv6 Interface Address (#232) TLV.
pub fn addIpv6InterfaceAddresses(b: *tlv.Builder, addrs: []const [16]u8) tlv.BuildError!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    var n: usize = 0;
    for (addrs) |a| {
        if (n + 16 > scratch.len) return error.ValueTooLong;
        @memcpy(scratch[n..][0..16], &a);
        n += 16;
    }
    try b.addTlv(code.ipv6_interface_address, scratch[0..n]);
}

// ── #13 Purge Originator Identification (RFC 6232) ───────────────────────────

/// The Purge Originator Identification (#13) TLV: the system-id of the IS that
/// generated or inserted the purge and, when it received the purge from a
/// neighbour, that neighbour's system-id. Six-octet system-ids (the modeled ID length).
pub const PurgeOriginator = struct {
    originator: [6]u8,
    /// The upstream IS the purge was received from; present when the count is 2.
    sender: ?[6]u8 = null,

    /// `BadTlvLength` unless the count octet is 1 or 2 and the value has exactly that many ids.
    pub fn decode(value: []const u8) ParseError!PurgeOriginator {
        if (value.len < 1) return error.BadTlvLength;
        const n = value[0];
        if (n != 1 and n != 2) return error.BadTlvLength;
        if (value.len != 1 + @as(usize, n) * 6) return error.BadTlvLength;
        return .{ .originator = value[1..7].*, .sender = if (n == 2) value[7..13].* else null };
    }
};

/// Appends a Purge Originator Identification (#13) TLV.
pub fn addPurgeOriginator(b: *tlv.Builder, p: PurgeOriginator) tlv.BuildError!void {
    var v: [13]u8 = undefined;
    v[0] = if (p.sender != null) 2 else 1;
    @memcpy(v[1..7], &p.originator);
    if (p.sender) |s| @memcpy(v[7..13], &s);
    try b.addTlv(code.purge_originator, v[0..if (p.sender != null) 13 else 7]);
}

// ── #11 Extended Sequence Number (RFC 7602) ──────────────────────────────────

/// The Extended Sequence Number (#11) TLV: a 64-bit session sequence number
/// and a 32-bit packet sequence number (RFC 7602 section 3).
pub const ExtSeqNum = struct {
    session: u64,
    packet: u32,

    /// `BadTlvLength` unless the value is exactly 12 octets.
    pub fn decode(value: []const u8) ParseError!ExtSeqNum {
        if (value.len != 12) return error.BadTlvLength;
        return .{
            .session = std.mem.readInt(u64, value[0..8], .big),
            .packet = std.mem.readInt(u32, value[8..12], .big),
        };
    }
};

/// Appends an Extended Sequence Number (#11) TLV.
pub fn addExtSeqNum(b: *tlv.Builder, e: ExtSeqNum) tlv.BuildError!void {
    var v: [12]u8 = undefined;
    std.mem.writeInt(u64, v[0..8], e.session, .big);
    std.mem.writeInt(u32, v[8..12], e.packet, .big);
    try b.addTlv(code.extended_sequence_number, &v);
}

// ── multi-topology TLVs (RFC 5120) ───────────────────────────────────────────

/// A multi-topology TLV value split into its 12-bit MT ID and the entries after
/// the 2-octet preamble (#222 / #235 / #237: the 4 high bits are reserved,
/// sent as zero and ignored on receipt). RFC 5120 says a TLV with MT ID 0 is
/// ignored; `split` reports it as `MtIdZero` so the caller can skip it.
pub const MtValue = struct {
    mt_id: u12,
    entries: []const u8,

    pub const Error = ParseError || error{MtIdZero};

    pub fn split(value: []const u8) Error!MtValue {
        if (value.len < 2) return error.BadTlvLength;
        const id: u12 = @truncate(std.mem.readInt(u16, value[0..2], .big));
        if (id == 0) return error.MtIdZero;
        return .{ .mt_id = id, .entries = value[2..] };
    }

    /// The entries of an MT IS Neighbors (#222) value, as for #22.
    pub fn isReach(m: MtValue) ExtIsReachIterator {
        return ExtIsReachIterator.init(m.entries);
    }
    /// The entries of an MT IP Reachability (#235) value, as for #135.
    pub fn ipReach(m: MtValue) ExtIpReachIterator {
        return ExtIpReachIterator.init(m.entries);
    }
    /// The entries of an MT IPv6 Reachability (#237) value, as for #236.
    pub fn ipv6Reach(m: MtValue) Ipv6ReachIterator {
        return Ipv6ReachIterator.init(m.entries);
    }
};

/// One component of a Multi-Topology (#229) TLV: `O(1) A(1) R(2) MT-ID(12)`.
pub const MtComponent = struct {
    mt_id: u12,
    overload: bool = false,
    attach: bool = false,
};

/// Walks a Multi-Topology (#229) value: 2-octet components.
pub const MtComponentIterator = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(value: []const u8) MtComponentIterator {
        return .{ .buf = value };
    }

    pub fn next(it: *MtComponentIterator) ParseError!?MtComponent {
        if (it.pos == it.buf.len) return null;
        if (it.pos + 2 > it.buf.len) return error.BadTlvLength;
        const w = std.mem.readInt(u16, it.buf[it.pos..][0..2], .big);
        it.pos += 2;
        return .{ .mt_id = @truncate(w), .overload = (w & 0x8000) != 0, .attach = (w & 0x4000) != 0 };
    }
};

/// Appends a Multi-Topology (#229) TLV.
pub fn addMultiTopology(b: *tlv.Builder, comps: []const MtComponent) tlv.BuildError!void {
    var scratch: [tlv.max_value_len]u8 = undefined;
    var n: usize = 0;
    for (comps) |c| {
        if (n + 2 > scratch.len) return error.ValueTooLong;
        const w: u16 = @as(u16, c.mt_id) | (if (c.overload) @as(u16, 0x8000) else 0) | (if (c.attach) @as(u16, 0x4000) else 0);
        std.mem.writeInt(u16, scratch[n..][0..2], w, .big);
        n += 2;
    }
    try b.addTlv(code.multi_topology, scratch[0..n]);
}

fn mtPreamble(scratch: []u8, mt_id: u12) void {
    std.mem.writeInt(u16, scratch[0..2], mt_id, .big);
}

/// Appends an MT IS Neighbors (#222) TLV with one entry (as `addExtendedIsReach`).
pub fn addMtIsReach(b: *tlv.Builder, mt_id: u12, neighbour_id: [7]u8, metric: u24, sub_tlvs: []const u8) (tlv.BuildError || ParseError)!void {
    if (mt_id == 0) return error.BadTlvLength;
    var scratch: [tlv.max_value_len]u8 = undefined;
    if (13 + sub_tlvs.len > scratch.len or sub_tlvs.len > 255) return error.ValueTooLong;
    mtPreamble(&scratch, mt_id);
    @memcpy(scratch[2..9], &neighbour_id);
    std.mem.writeInt(u24, scratch[9..12], metric, .big);
    scratch[12] = @intCast(sub_tlvs.len);
    @memcpy(scratch[13..][0..sub_tlvs.len], sub_tlvs);
    try b.addTlv(code.mt_is_reachability, scratch[0 .. 13 + sub_tlvs.len]);
}

/// Appends an MT IP Reachability (#235) TLV with one entry (as `addExtIpReach`).
pub fn addMtIpReach(b: *tlv.Builder, mt_id: u12, e: ExtIpReachEntry) (tlv.BuildError || ParseError)!void {
    if (mt_id == 0) return error.BadTlvLength;
    var scratch: [tlv.max_value_len]u8 = undefined;
    mtPreamble(&scratch, mt_id);
    const n = try writeExtIpReach(scratch[2..], e);
    try b.addTlv(code.mt_ip_reachability, scratch[0 .. 2 + n]);
}

/// Appends an MT IPv6 Reachability (#237) TLV with one entry (as `addIpv6Reach`).
pub fn addMtIpv6Reach(b: *tlv.Builder, mt_id: u12, e: Ipv6ReachEntry) (tlv.BuildError || ParseError)!void {
    if (mt_id == 0) return error.BadTlvLength;
    var scratch: [tlv.max_value_len]u8 = undefined;
    mtPreamble(&scratch, mt_id);
    const n = try writeIpv6Reach(scratch[2..], e);
    try b.addTlv(code.mt_ipv6_reachability, scratch[0 .. 2 + n]);
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

test "legacy IP reachability: layout, flags, contiguous mask" {
    var buf: [64]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    try addIpReach(&b, code.ip_internal_reachability, &.{
        .{ .default_metric = 10, .address = .{ 10, 0, 0, 0 }, .mask = .{ 255, 0, 0, 0 } },
        .{ .default_metric = 63, .default_external = true, .up_down = true, .delay_metric = 5, .address = .{ 192, 0, 2, 0 }, .mask = .{ 255, 0, 255, 0 } },
    });
    const v = (try tlv.findFirst(b.written(), code.ip_internal_reachability)).?;
    try testing.expectEqualSlices(u8, &.{ 10, 0x80, 0x80, 0x80, 10, 0, 0, 0, 255, 0, 0, 0 }, v[0..12]);
    try testing.expectEqual(@as(u8, 0x80 | 0x40 | 63), v[12]);
    var it = IpReachIterator.init(v);
    const a = (try it.next()).?;
    try testing.expectEqual(@as(?u8, 8), a.prefixLen());
    const c = (try it.next()).?;
    try testing.expect(c.default_external and c.up_down);
    try testing.expectEqual(@as(u6, 63), c.default_metric);
    try testing.expectEqual(@as(u8, 5), c.delay_metric);
    try testing.expectEqual(@as(?u8, null), c.prefixLen());
    try testing.expectEqual(@as(?IpReachEntry, null), try it.next());
    var bad = IpReachIterator.init(v[0..11]);
    try testing.expectError(error.BadTlvLength, bad.next());
    const z: IpReachEntry = .{ .default_metric = 0, .address = @splat(0), .mask = @splat(0) };
    try testing.expectEqual(@as(?u8, 0), z.prefixLen());
    var f = z;
    f.mask = @splat(255);
    try testing.expectEqual(@as(?u8, 32), f.prefixLen());
    f.mask = .{ 255, 255, 255, 254 };
    try testing.expectEqual(@as(?u8, 31), f.prefixLen());
}

test "interface address TLVs round-trip and refuse partial records" {
    var buf: [128]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    try addIpv4InterfaceAddresses(&b, &.{ .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 } });
    var a6: [16]u8 = @splat(0);
    a6[0] = 0xfe;
    a6[1] = 0x80;
    try addIpv6InterfaceAddresses(&b, &.{a6});
    var it = Ipv4AddressIterator.init((try tlv.findFirst(b.written(), code.ip_interface_address)).?);
    try testing.expectEqual([4]u8{ 10, 0, 0, 1 }, (try it.next()).?);
    try testing.expectEqual([4]u8{ 10, 0, 0, 2 }, (try it.next()).?);
    try testing.expectEqual(@as(?[4]u8, null), try it.next());
    var it6 = Ipv6AddressIterator.init((try tlv.findFirst(b.written(), code.ipv6_interface_address)).?);
    try testing.expectEqual(a6, (try it6.next()).?);
    try testing.expectEqual(@as(?[16]u8, null), try it6.next());
    var p4 = Ipv4AddressIterator.init(&.{ 1, 2, 3 });
    try testing.expectError(error.BadTlvLength, p4.next());
    var p6 = Ipv6AddressIterator.init(&@as([15]u8, @splat(0)));
    try testing.expectError(error.BadTlvLength, p6.next());
}

test "purge originator (RFC 6232): one or two ids, nothing else" {
    var buf: [64]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    const o = [6]u8{ 0, 0, 0, 0, 0, 1 };
    const s = [6]u8{ 0, 0, 0, 0, 0, 2 };
    try addPurgeOriginator(&b, .{ .originator = o });
    try addPurgeOriginator(&b, .{ .originator = o, .sender = s });
    var ti = tlv.TlvIterator.init(b.written());
    const t1 = (try ti.next()).?;
    try testing.expectEqual(code.purge_originator, t1.code);
    try testing.expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 1 }, t1.value);
    const p1 = try PurgeOriginator.decode(t1.value);
    try testing.expectEqual(@as(?[6]u8, null), p1.sender);
    const p2 = try PurgeOriginator.decode((try ti.next()).?.value);
    try testing.expectEqual(s, p2.sender.?);
    try testing.expectEqual(o, p2.originator);
    try testing.expectError(error.BadTlvLength, PurgeOriginator.decode(&.{}));
    try testing.expectError(error.BadTlvLength, PurgeOriginator.decode(&.{ 0, 1, 2, 3, 4, 5, 6 }));
    try testing.expectError(error.BadTlvLength, PurgeOriginator.decode(&.{ 3, 1, 2, 3, 4, 5, 6 }));
    try testing.expectError(error.BadTlvLength, PurgeOriginator.decode(&.{ 2, 1, 2, 3, 4, 5, 6 })); // count 2, one id
    try testing.expectError(error.BadTlvLength, PurgeOriginator.decode(&.{ 1, 1, 2, 3, 4, 5, 6, 7 })); // count 1, extra octet
}

test "extended sequence number (RFC 7602): 12 octets, session then packet" {
    var buf: [32]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    try addExtSeqNum(&b, .{ .session = 0x0102030405060708, .packet = 0x0a0b0c0d });
    try testing.expectEqualSlices(u8, &.{ 11, 12, 1, 2, 3, 4, 5, 6, 7, 8, 0x0a, 0x0b, 0x0c, 0x0d }, b.written());
    const e = try ExtSeqNum.decode((try tlv.findFirst(b.written(), code.extended_sequence_number)).?);
    try testing.expectEqual(@as(u64, 0x0102030405060708), e.session);
    try testing.expectEqual(@as(u32, 0x0a0b0c0d), e.packet);
    try testing.expectError(error.BadTlvLength, ExtSeqNum.decode(&@as([11]u8, @splat(0))));
    try testing.expectError(error.BadTlvLength, ExtSeqNum.decode(&@as([13]u8, @splat(0))));
}

test "multi-topology TLVs (RFC 5120): preamble, entries, MT ID 0 ignored" {
    var buf: [128]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    const nbr = [7]u8{ 0, 0, 0, 0, 0, 3, 0 };
    try addMtIsReach(&b, 2, nbr, 77, &.{ 4, 1, 9 });
    try addMtIpReach(&b, 0xabc, .{ .metric = 5, .prefix_len = 24, .prefix = .{ 10, 1, 2, 0 } });
    try addMtIpv6Reach(&b, 3, .{ .metric = 6, .external = true, .prefix_len = 8, .prefix = @as([16]u8, @splat(0xff)) });
    var ti = tlv.TlvIterator.init(b.written());
    const t222 = (try ti.next()).?;
    try testing.expectEqual(code.mt_is_reachability, t222.code);
    try testing.expectEqualSlices(u8, &.{ 0, 2 }, t222.value[0..2]);
    const m1 = try MtValue.split(t222.value);
    try testing.expectEqual(@as(u12, 2), m1.mt_id);
    var mi1 = m1.isReach();
    const e1 = (try mi1.next()).?;
    try testing.expectEqual(nbr, e1.neighbour_id);
    try testing.expectEqual(@as(u24, 77), e1.metric);
    try testing.expectEqualSlices(u8, &.{ 4, 1, 9 }, e1.sub_tlvs);
    const t235 = (try ti.next()).?;
    try testing.expectEqual(code.mt_ip_reachability, t235.code);
    const m2 = try MtValue.split(t235.value);
    try testing.expectEqual(@as(u12, 0xabc), m2.mt_id);
    try testing.expectEqual(@as(u8, 0x0a), t235.value[0]);
    var mi2 = m2.ipReach();
    const e2 = (try mi2.next()).?;
    try testing.expectEqual(@as(u8, 24), e2.prefix_len);
    try testing.expectEqual(@as(u32, 5), e2.metric);
    const t237 = (try ti.next()).?;
    try testing.expectEqual(code.mt_ipv6_reachability, t237.code);
    const m3 = try MtValue.split(t237.value);
    var mi3 = m3.ipv6Reach();
    const e3 = (try mi3.next()).?;
    try testing.expect(e3.external);
    try testing.expectEqual(@as(u8, 0xff), e3.prefix[0]);
    // The reserved high bits are ignored on receipt; MT ID 0 is reported.
    try testing.expectEqual(@as(u12, 7), (try MtValue.split(&.{ 0xf0, 7 })).mt_id);
    try testing.expectError(error.MtIdZero, MtValue.split(&.{ 0xf0, 0 }));
    try testing.expectError(error.BadTlvLength, MtValue.split(&.{1}));
    var none: [64]u8 = undefined;
    var nb = tlv.Builder.init(&none);
    try testing.expectError(error.BadTlvLength, addMtIpReach(&nb, 0, .{ .metric = 0, .prefix_len = 0, .prefix = @splat(0) }));
    try testing.expectError(error.BadTlvLength, addMtIsReach(&nb, 0, nbr, 0, &.{}));
    try testing.expectError(error.BadTlvLength, addMtIpv6Reach(&nb, 0, .{ .metric = 0, .prefix_len = 0, .prefix = @splat(0) }));
}

test "multi-topology (#229) components carry O/A and the 12-bit id" {
    var buf: [32]u8 = undefined;
    var b = tlv.Builder.init(&buf);
    try addMultiTopology(&b, &.{ .{ .mt_id = 0 }, .{ .mt_id = 2, .overload = true }, .{ .mt_id = 4095, .attach = true } });
    try testing.expectEqualSlices(u8, &.{ 229, 6, 0, 0, 0x80, 2, 0x4f, 0xff }, b.written());
    var it = MtComponentIterator.init((try tlv.findFirst(b.written(), code.multi_topology)).?);
    try testing.expectEqual(MtComponent{ .mt_id = 0 }, (try it.next()).?);
    try testing.expectEqual(MtComponent{ .mt_id = 2, .overload = true }, (try it.next()).?);
    try testing.expectEqual(MtComponent{ .mt_id = 4095, .attach = true }, (try it.next()).?);
    try testing.expectEqual(@as(?MtComponent, null), try it.next());
    var bad = MtComponentIterator.init(&.{ 0, 1, 2 });
    _ = try bad.next();
    try testing.expectError(error.BadTlvLength, bad.next());
}
