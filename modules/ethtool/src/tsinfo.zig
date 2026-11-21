// SPDX-License-Identifier: MIT
//! `TSINFO_GET` — timestamping capabilities (`ethtool -T <dev>`), the first
//! stop when setting up PTP.
//!
//! The reply carries three capability bitsets and the PTP hardware clock:
//!
//! * `timestamping` — `SOF_TIMESTAMPING_*` flags (`ETH_SS_SOF_TIMESTAMPING`:
//!   `"hardware-transmit"`, `"software-receive"`, `"hardware-raw-clock"`, …).
//! * `tx_types` — hardware transmit timestamp modes (`off`, `on`, `onestep-sync`, …).
//! * `rx_filters` — hardware receive filters (`none`, `all`, `ptpv2-event`, …).
//! * `phc_index` — `/dev/ptp<N>`; **absent** when the device has no PTP clock,
//!   which `ethtool -T` prints as "none". That is why it is optional here and
//!   not defaulted to 0 (clock 0 is a real clock).
//!
//! All three bitsets are plain capability lists. With a verbose reply they
//! carry the kernel's names; with a compact one, bare bit numbers, resolved
//! through `Ethtool.stringSet` (`.sof_timestamping`, `.ts_tx_types`,
//! `.ts_rx_filters`). Unprivileged. Newer kernels add per-device statistics
//! and a hardware-timestamp-provider nest; those are not decoded here and
//! stay reachable through `Ethtool.raw`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");

pub const Error = codec.Error || error{OutOfMemory};

/// `ETHTOOL_MSG_TSINFO_GET` reply. Owns its bitsets — free with `deinit`.
pub const TsInfo = struct {
    device: header.Device = .{},
    timestamping: ?bitset.Bitset = null,
    tx_types: ?bitset.Bitset = null,
    rx_filters: ?bitset.Bitset = null,
    /// PTP hardware clock index; null = the device has none.
    phc_index: ?u32 = null,
    /// Timestamping counters, when the request asked for statistics (`tsInfoStats`) and the driver keeps them.
    stats: ?TsStats = null,
    /// The hardware timestamp provider (a PHC and how precise it is), when the kernel reports one.
    provider: ?TsProvider = null,
    /// Where the timestamps come from, and the PHY that makes them.
    source: ?u32 = null,
    phy_index: ?u32 = null,

    pub fn deinit(t: *TsInfo, gpa: std.mem.Allocator) void {
        inline for (.{ "timestamping", "tx_types", "rx_filters" }) |name| {
            if (@field(t, name)) |*b| b.deinit(gpa);
        }
        t.* = .{};
    }

    /// Does the device have a PTP hardware clock?
    pub fn hasPhc(t: TsInfo) bool {
        return t.phc_index != null;
    }
};

/// The `ETHTOOL_A_TSINFO_STATS` nest.
pub const TsStats = struct {
    tx_pkts: ?u64 = null,
    tx_lost: ?u64 = null,
    tx_err: ?u64 = null,
    tx_onestep_pkts_unconfirmed: ?u64 = null,
};

/// A hardware timestamp provider: the PTP clock index and its qualifier (0 precise, 1 approximate).
pub const TsProvider = struct {
    index: ?u32 = null,
    qualifier: ?u32 = null,
};

fn asU64(a: codec.Attr) codec.Error!u64 {
    if (a.data.len != 8) return error.BadLength;
    return std.mem.readInt(u64, a.data[0..8], @import("builtin").cpu.arch.endian());
}

pub fn parseTsStats(nest_bytes: []const u8) codec.Error!TsStats {
    var out: TsStats = .{};
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.TS_STAT.TX_PKTS => out.tx_pkts = try asU64(a),
        uapi.TS_STAT.TX_LOST => out.tx_lost = try asU64(a),
        uapi.TS_STAT.TX_ERR => out.tx_err = try asU64(a),
        uapi.TS_STAT.TX_ONESTEP_PKTS_UNCONFIRMED => out.tx_onestep_pkts_unconfirmed = try asU64(a),
        else => {},
    };
    return out;
}

pub fn parseTsProvider(nest_bytes: []const u8) codec.Error!TsProvider {
    var out: TsProvider = .{};
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.TS_HWTSTAMP_PROVIDER.INDEX => out.index = try a.asU32(),
        uapi.TS_HWTSTAMP_PROVIDER.QUALIFIER => out.qualifier = try a.asU32(),
        else => {},
    };
    return out;
}

pub fn parseTsInfo(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!TsInfo {
    var out: TsInfo = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.TSINFO.HEADER => out.device = try header.parse(a.data),
        uapi.TSINFO.TIMESTAMPING => try parseOnce(gpa, &out.timestamping, a.data),
        uapi.TSINFO.TX_TYPES => try parseOnce(gpa, &out.tx_types, a.data),
        uapi.TSINFO.RX_FILTERS => try parseOnce(gpa, &out.rx_filters, a.data),
        uapi.TSINFO.PHC_INDEX => out.phc_index = try a.asU32(),
        uapi.TSINFO.STATS => out.stats = try parseTsStats(a.data),
        uapi.TSINFO.HWTSTAMP_PROVIDER => out.provider = try parseTsProvider(a.data),
        uapi.TSINFO.HWTSTAMP_SOURCE => out.source = try a.asU32(),
        uapi.TSINFO.HWTSTAMP_PHYINDEX => out.phy_index = try a.asU32(),
        else => {},
    };
    return out;
}

/// A bitset attribute may appear once; a second one is a malformed reply (and
/// must not leak the first).
fn parseOnce(gpa: std.mem.Allocator, slot: *?bitset.Bitset, data: []const u8) Error!void {
    if (slot.* != null) return error.BadLength;
    slot.* = try bitset.parse(gpa, data);
}

/// Encode a complete `ETHTOOL_MSG_TSINFO_GET` request. `form` picks the bitset
/// encoding of the reply. `Ethtool.tsInfo` sends exactly this.
pub fn buildTsInfo(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
) header.Error![]u8 {
    return buildTsInfoWith(gpa, family_id, seq, target, form, false);
}

/// `buildTsInfo`, asking for the statistics nest too (`ETHTOOL_FLAG_STATS`) — what `Ethtool.tsInfoStats` sends.
pub fn buildTsInfoWith(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
    stats: bool,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.TSINFO_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.TSINFO.HEADER, .{ .target = target, .compact_bitsets = form.compactFlag(), .stats = stats });
    return header.finishRequest(gpa, &msg, h);
}

// ── TSCONFIG ───────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_TSCONFIG_GET` reply: the hardware timestamping configuration of a device (`SIOCGHWTSTAMP`'s
/// netlink form). Owns its bitsets — free with `deinit`.
pub const TsConfig = struct {
    device: header.Device = .{},
    provider: ?TsProvider = null,
    /// The enabled TX timestamp types and RX filters (`HWTSTAMP_TX_*`, `HWTSTAMP_FILTER_*`), one bit each.
    tx_types: ?bitset.Bitset = null,
    rx_filters: ?bitset.Bitset = null,
    /// `HWTSTAMP_FLAG_*`.
    flags: ?bitset.Bitset = null,

    pub fn deinit(c: *TsConfig, gpa: std.mem.Allocator) void {
        inline for (.{ "tx_types", "rx_filters", "flags" }) |name| {
            if (@field(c, name)) |*b| b.deinit(gpa);
        }
        c.* = .{};
    }
};

pub fn parseTsConfig(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!TsConfig {
    var out: TsConfig = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.TSCONFIG.HEADER => out.device = try header.parse(a.data),
        uapi.TSCONFIG.HWTSTAMP_PROVIDER => out.provider = try parseTsProvider(a.data),
        uapi.TSCONFIG.TX_TYPES => try parseOnce(gpa, &out.tx_types, a.data),
        uapi.TSCONFIG.RX_FILTERS => try parseOnce(gpa, &out.rx_filters, a.data),
        uapi.TSCONFIG.HWTSTAMP_FLAGS => try parseOnce(gpa, &out.flags, a.data),
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_TSCONFIG_SET` parameters: the provider to use and the bits to switch, each set by name **or** by
/// index (not both: `InvalidRequest`). A set field is sent, an empty one is left out.
pub const TsConfigSet = struct {
    provider: ?struct { index: u32, qualifier: u32 = 0 } = null,
    tx_types: []const bitset.NamedValue = &.{},
    tx_types_by_index: []const bitset.IndexedValue = &.{},
    rx_filters: []const bitset.NamedValue = &.{},
    rx_filters_by_index: []const bitset.IndexedValue = &.{},
    flags: []const bitset.NamedValue = &.{},
    flags_by_index: []const bitset.IndexedValue = &.{},
};

pub const BuildError = bitset.BuildError || header.Error;

pub fn buildTsConfig(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.TSCONFIG_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.TSCONFIG.HEADER, .{ .target = target, .compact_bitsets = form.compactFlag() });
    return header.finishRequest(gpa, &msg, h);
}

pub fn buildSetTsConfig(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    set: TsConfigSet,
) BuildError![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.TSCONFIG_SET, .seq = seq });
    try header.append(gpa, &msg, uapi.TSCONFIG.HEADER, .{ .target = target });
    if (set.provider) |p| {
        const nest = try codec.nestBegin(gpa, &msg, uapi.TSCONFIG.HWTSTAMP_PROVIDER | codec.NLA_F_NESTED);
        try codec.appendAttrU32(gpa, &msg, uapi.TS_HWTSTAMP_PROVIDER.INDEX, p.index);
        try codec.appendAttrU32(gpa, &msg, uapi.TS_HWTSTAMP_PROVIDER.QUALIFIER, p.qualifier);
        codec.nestEnd(&msg, nest) catch return error.InvalidRequest;
    }
    try bitset.appendMasked(gpa, &msg, uapi.TSCONFIG.TX_TYPES, set.tx_types_by_index, set.tx_types);
    try bitset.appendMasked(gpa, &msg, uapi.TSCONFIG.RX_FILTERS, set.rx_filters_by_index, set.rx_filters);
    try bitset.appendMasked(gpa, &msg, uapi.TSCONFIG.HWTSTAMP_FLAGS, set.flags_by_index, set.flags);
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "TSINFO reply: the three capability sets and the PHC index" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.TSINFO.HEADER, .{ .target = .byIndex(2) });
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.TIMESTAMPING, 32, &.{0b1_0101}, null);
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.TX_TYPES, 4, &.{0b0011}, null);
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.RX_FILTERS, 16, &.{0b1}, null);
    try codec.appendAttrU32(gpa, &list, uapi.TSINFO.PHC_INDEX, 0);

    var t = try parseTsInfo(gpa, list.items);
    defer t.deinit(gpa);
    try testing.expectEqual(@as(?u32, 2), t.device.index);
    try testing.expect(t.hasPhc());
    try testing.expectEqual(@as(?u32, 0), t.phc_index); // clock 0 is a clock
    try testing.expect(t.timestamping.?.isSet(0) and !t.timestamping.?.isSet(1) and t.timestamping.?.isSet(2));
    try testing.expectEqual(@as(u32, 3), t.timestamping.?.count());
    try testing.expectEqual(@as(u32, 2), t.tx_types.?.count());
    try testing.expect(t.rx_filters.?.isSet(0));
}

test "TSINFO reply: no PHC is null; a verbose reply keeps its names" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendNameList(gpa, &list, uapi.TSINFO.TIMESTAMPING, &.{ "software-transmit", "software-receive" });
    var t = try parseTsInfo(gpa, list.items);
    defer t.deinit(gpa);
    try testing.expect(!t.hasPhc());
    try testing.expect(t.tx_types == null and t.rx_filters == null);
    try testing.expectEqual(@as(?bool, true), t.timestamping.?.isSetByName("software-receive"));
    try testing.expectEqual(@as(?bool, false), t.timestamping.?.isSetByName("hardware-transmit"));

    var e = try parseTsInfo(gpa, &.{});
    defer e.deinit(gpa);
    try testing.expect(e.timestamping == null and !e.hasPhc());
}

test "TSINFO reply: malformed input is a typed error and leaks nothing" {
    const gpa = testing.allocator;
    // PHC_INDEX with one byte.
    try testing.expectError(error.BadLength, parseTsInfo(gpa, &.{ 0x05, 0x00, 0x05, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.Truncated, parseTsInfo(gpa, &.{ 0x40, 0x00, 0x02, 0x00, 1 }));
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.RX_FILTERS, 8, &.{1}, null);
    try bitset.appendCompact(gpa, &list, uapi.TSINFO.RX_FILTERS, 8, &.{1}, null);
    try testing.expectError(error.BadLength, parseTsInfo(gpa, list.items));
}

test "TSINFO_GET request: command, device, compact flag" {
    const gpa = testing.allocator;
    const msg = try buildTsInfo(gpa, 23, 8, .byName("eth0"), .compact);
    defer gpa.free(msg);
    try testing.expectEqual(uapi.MSG.TSINFO_GET, msg[16]);
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    const h = (try it.next()).?;
    try testing.expectEqual(uapi.TSINFO.HEADER, h.type & codec.NLA_TYPE_MASK);
    var hit: codec.AttrIterator = .{ .buf = h.data };
    try testing.expectEqualStrings("eth0", (try hit.next()).?.asString());
    try testing.expectEqual(uapi.FLAG.COMPACT_BITSETS, try (try hit.next()).?.asU32());
    try testing.expect((try it.next()) == null);
    try testing.expectError(error.InvalidRequest, buildTsInfo(gpa, 23, 8, .byName(""), .verbose));
}

test "parseTsInfo decodes the statistics nest, the provider, the source and the PHY index" {
    const gpa = testing.allocator;
    const endian = @import("builtin").cpu.arch.endian();
    var stats: std.ArrayList(u8) = .empty;
    defer stats.deinit(gpa);
    var q: [8]u8 = undefined;
    std.mem.writeInt(u64, &q, 11, endian);
    try codec.appendAttr(gpa, &stats, uapi.TS_STAT.TX_PKTS, &q);
    std.mem.writeInt(u64, &q, 2, endian);
    try codec.appendAttr(gpa, &stats, uapi.TS_STAT.TX_LOST, &q);
    var prov: std.ArrayList(u8) = .empty;
    defer prov.deinit(gpa);
    try codec.appendAttrU32(gpa, &prov, uapi.TS_HWTSTAMP_PROVIDER.INDEX, 3);
    try codec.appendAttrU32(gpa, &prov, uapi.TS_HWTSTAMP_PROVIDER.QUALIFIER, 1);
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try codec.appendAttrU32(gpa, &l, uapi.TSINFO.PHC_INDEX, 3);
    try codec.appendAttr(gpa, &l, uapi.TSINFO.STATS, stats.items);
    try codec.appendAttr(gpa, &l, uapi.TSINFO.HWTSTAMP_PROVIDER, prov.items);
    try codec.appendAttrU32(gpa, &l, uapi.TSINFO.HWTSTAMP_SOURCE, 2);
    try codec.appendAttrU32(gpa, &l, uapi.TSINFO.HWTSTAMP_PHYINDEX, 5);
    var t = try parseTsInfo(gpa, l.items);
    defer t.deinit(gpa);
    try testing.expectEqual(@as(?u64, 11), t.stats.?.tx_pkts);
    try testing.expectEqual(@as(?u64, 2), t.stats.?.tx_lost);
    try testing.expectEqual(@as(?u64, null), t.stats.?.tx_err);
    try testing.expectEqual(@as(?u32, 3), t.provider.?.index);
    try testing.expectEqual(@as(?u32, 1), t.provider.?.qualifier);
    try testing.expectEqual(@as(?u32, 2), t.source);
    try testing.expectEqual(@as(?u32, 5), t.phy_index);
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try codec.appendAttr(gpa, &bad, uapi.TSINFO.STATS, &.{ 0x06, 0x00, uapi.TS_STAT.TX_ERR, 0x00, 1, 2, 0, 0 });
    try testing.expectError(error.BadLength, parseTsInfo(gpa, bad.items));

    const msg = try buildTsInfoWith(gpa, 23, 1, .byIndex(2), .compact, true);
    defer gpa.free(msg);
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    var ht = (try it.next()).?.nested();
    var flags: u32 = 0;
    while (try ht.next()) |a| if (a.type == uapi.HEADER.FLAGS) {
        flags = try a.asU32();
    };
    try testing.expectEqual(uapi.FLAG.COMPACT_BITSETS | uapi.FLAG.STATS, flags);
}

test "TSCONFIG: a reply decodes, a set carries the provider and masked bitsets and refuses both keyings" {
    if (@import("builtin").cpu.arch.endian() != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var prov: std.ArrayList(u8) = .empty;
    defer prov.deinit(gpa);
    try codec.appendAttrU32(gpa, &prov, uapi.TS_HWTSTAMP_PROVIDER.INDEX, 2);
    try codec.appendAttrU32(gpa, &prov, uapi.TS_HWTSTAMP_PROVIDER.QUALIFIER, 0);
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try header.append(gpa, &l, uapi.TSCONFIG.HEADER, .{ .target = .byName("eth0") });
    try codec.appendAttr(gpa, &l, uapi.TSCONFIG.HWTSTAMP_PROVIDER, prov.items);
    var c = try parseTsConfig(gpa, l.items);
    defer c.deinit(gpa);
    try testing.expectEqualStrings("eth0", c.device.name());
    try testing.expectEqual(@as(?u32, 2), c.provider.?.index);
    try testing.expect(c.tx_types == null);

    const msg = try buildSetTsConfig(gpa, 23, 1, .byIndex(2), .{
        .provider = .{ .index = 4, .qualifier = 1 },
        .tx_types = &.{.{ .name = "on", .on = true }},
        .rx_filters_by_index = &.{.{ .index = 12, .on = true }},
    });
    defer gpa.free(msg);
    try testing.expectEqual(uapi.MSG.TSCONFIG_SET, msg[16]);
    var seen: u8 = 0;
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    while (try it.next()) |a| switch (a.type) {
        uapi.TSCONFIG.HWTSTAMP_PROVIDER => {
            seen |= 1;
            const p = try parseTsProvider(a.data);
            try testing.expectEqual(@as(?u32, 4), p.index);
            try testing.expectEqual(@as(?u32, 1), p.qualifier);
        },
        uapi.TSCONFIG.TX_TYPES => seen |= 2,
        uapi.TSCONFIG.RX_FILTERS => seen |= 4,
        uapi.TSCONFIG.HWTSTAMP_FLAGS => seen |= 8,
        else => {},
    };
    try testing.expectEqual(@as(u8, 7), seen);
    try testing.expectError(error.InvalidRequest, buildSetTsConfig(gpa, 23, 1, .byIndex(2), .{
        .flags = &.{.{ .name = "x", .on = true }},
        .flags_by_index = &.{.{ .index = 0, .on = true }},
    }));
}
