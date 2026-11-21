// SPDX-License-Identifier: MIT
//! `EEE_GET`/`SET` (Energy-Efficient Ethernet, `ethtool --show-eee`) and
//! `FEC_GET`/`SET` (forward error correction, `ethtool --show-fec`).
//!
//! Both follow the family's usual rules (see `params.zig`): every reply field
//! is optional ("this driver does not say"), and every SET field is optional
//! ("leave it alone"). Both carry bitsets of *link modes*, so the
//! supported-versus-advertised split of `link.zig` applies:
//!
//! * `Eee.ours`: **value** = link modes EEE is advertised for, **mask** =
//!   link modes EEE is supported on. Use `Bitset.isSet` / `Bitset.inMask`.
//! * `Fec.modes`: the FEC modes (`None`, `RS`, `BaseR`, `LLRS`, …); with a
//!   verbose reply they carry the kernel's names. `Fec.active` is a **bit
//!   index** into that set, not a mode number — look it up with
//!   `Fec.activeName`.
//!
//! `FEC_STATS` (the per-lane corrected/uncorrected counters) is not decoded;
//! it is reachable through `Ethtool.raw`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");

pub const Error = codec.Error || error{OutOfMemory};
pub const BuildError = bitset.BuildError || header.Error;

// ── EEE ────────────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_EEE_GET` reply. Owns its bitsets — free with `deinit`.
pub const Eee = struct {
    device: header.Device = .{},
    /// Value = EEE advertised per link mode, mask = EEE supported per link mode.
    ours: ?bitset.Bitset = null,
    /// Link modes the partner advertises EEE for.
    peer: ?bitset.Bitset = null,
    /// EEE negotiated and running on the link now.
    active: ?bool = null,
    enabled: ?bool = null,
    tx_lpi_enabled: ?bool = null,
    /// TX LPI timer, microseconds.
    tx_lpi_timer: ?u32 = null,

    pub fn deinit(e: *Eee, gpa: std.mem.Allocator) void {
        if (e.ours) |*b| b.deinit(gpa);
        if (e.peer) |*b| b.deinit(gpa);
        e.* = .{};
    }
};

pub fn parseEee(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!Eee {
    var out: Eee = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.EEE.HEADER => out.device = try header.parse(a.data),
        uapi.EEE.MODES_OURS => {
            if (out.ours != null) return error.BadLength;
            out.ours = try bitset.parse(gpa, a.data);
        },
        uapi.EEE.MODES_PEER => {
            if (out.peer != null) return error.BadLength;
            out.peer = try bitset.parse(gpa, a.data);
        },
        uapi.EEE.ACTIVE => out.active = (try a.asU8()) != 0,
        uapi.EEE.ENABLED => out.enabled = (try a.asU8()) != 0,
        uapi.EEE.TX_LPI_ENABLED => out.tx_lpi_enabled = (try a.asU8()) != 0,
        uapi.EEE.TX_LPI_TIMER => out.tx_lpi_timer = try a.asU32(),
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_EEE_SET` parameters.
pub const EeeSet = struct {
    enabled: ?bool = null,
    tx_lpi_enabled: ?bool = null,
    /// Microseconds.
    tx_lpi_timer: ?u32 = null,
    /// Link modes to advertise EEE for — a delta, bits not listed stay as they
    /// are. Give them by index **or** by name, not both (`InvalidRequest`).
    advertise: []const bitset.IndexedValue = &.{},
    advertise_names: []const bitset.NamedValue = &.{},
};

pub fn appendEeeSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    set: EeeSet,
) bitset.BuildError!void {
    if (set.advertise.len != 0 and set.advertise_names.len != 0) return error.InvalidRequest;
    try bitset.appendMasked(gpa, list, uapi.EEE.MODES_OURS, set.advertise, set.advertise_names);
    if (set.enabled) |v| try codec.appendAttrU8(gpa, list, uapi.EEE.ENABLED, @intFromBool(v));
    if (set.tx_lpi_enabled) |v| try codec.appendAttrU8(gpa, list, uapi.EEE.TX_LPI_ENABLED, @intFromBool(v));
    if (set.tx_lpi_timer) |v| try codec.appendAttrU32(gpa, list, uapi.EEE.TX_LPI_TIMER, v);
}

/// Encode a complete `ETHTOOL_MSG_EEE_GET` request. `form` picks the bitset
/// encoding of the reply. `Ethtool.eee` sends exactly this.
pub fn buildEee(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.EEE_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.EEE.HEADER, .{ .target = target, .compact_bitsets = form.compactFlag() });
    return header.finishRequest(gpa, &msg, h);
}

/// Encode a complete `ETHTOOL_MSG_EEE_SET` request. `Ethtool.setEee` sends
/// exactly this.
pub fn buildSetEee(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    set: EeeSet,
) BuildError![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.EEE_SET, .seq = seq });
    try header.append(gpa, &msg, uapi.EEE.HEADER, .{ .target = target });
    try appendEeeSet(gpa, &msg, set);
    return header.finishRequest(gpa, &msg, h);
}

// ── FEC ────────────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_FEC_GET` reply. Owns its bitset — free with `deinit`.
pub const Fec = struct {
    device: header.Device = .{},
    /// Value = modes currently configured, mask = modes the device supports.
    modes: ?bitset.Bitset = null,
    /// Automatic FEC selection.
    auto: ?bool = null,
    /// **Bit index** of the active mode in `modes`' universe.
    active: ?u32 = null,
    /// The error counters, when the request asked for statistics and the driver has them (`fecStats`).
    stats: ?FecStats = null,

    pub fn deinit(f: *Fec, gpa: std.mem.Allocator) void {
        if (f.modes) |*b| b.deinit(gpa);
        f.* = .{};
    }

    /// The kernel's name of the active mode (`"RS"`, `"BaseR"`, …), when the
    /// reply was verbose and named that bit. Null otherwise.
    pub fn activeName(f: Fec) ?[]const u8 {
        const idx = f.active orelse return null;
        const m = f.modes orelse return null;
        return m.nameOf(idx);
    }
};

/// Most lanes a FEC counter reports separately (`ETHTOOL_MAX_LANES`).
pub const max_fec_lanes = 8;

/// One FEC counter: the total over the port and, when the driver reports them, one value per lane.
pub const FecCounter = struct {
    /// Null when the driver does not report a total (the kernel's "not set" all-ones value).
    total: ?u64 = null,
    lane_values: [max_fec_lanes]u64 = @splat(0),
    lane_count: u8 = 0,

    pub fn lanes(c: *const FecCounter) []const u64 {
        return c.lane_values[0..c.lane_count];
    }
};

/// The `ETHTOOL_A_FEC_STATS` nest. A counter the driver does not keep is null.
pub const FecStats = struct {
    corrected_blocks: ?FecCounter = null,
    uncorrectable_blocks: ?FecCounter = null,
    corrected_bits: ?FecCounter = null,
    /// The nest has a histogram of errors per block (not decoded).
    has_histogram: bool = false,
};

const stat_not_set: u64 = std.math.maxInt(u64);

/// `u64 total` followed by up to `max_fec_lanes` `u64` per-lane values, host order.
fn parseFecCounter(data: []const u8) codec.Error!FecCounter {
    if (data.len < 8 or data.len % 8 != 0 or data.len / 8 - 1 > max_fec_lanes) return error.BadLength;
    const endian = @import("builtin").cpu.arch.endian();
    var c: FecCounter = .{};
    const total = std.mem.readInt(u64, data[0..8], endian);
    if (total != stat_not_set) c.total = total;
    var i: usize = 8;
    while (i < data.len) : (i += 8) {
        c.lane_values[c.lane_count] = std.mem.readInt(u64, data[i..][0..8], endian);
        c.lane_count += 1;
    }
    return c;
}

pub fn parseFecStats(nest_bytes: []const u8) codec.Error!FecStats {
    var out: FecStats = .{};
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.FEC_STAT.CORRECTED => out.corrected_blocks = try parseFecCounter(a.data),
        uapi.FEC_STAT.UNCORR => out.uncorrectable_blocks = try parseFecCounter(a.data),
        uapi.FEC_STAT.CORR_BITS => out.corrected_bits = try parseFecCounter(a.data),
        uapi.FEC_STAT.HIST => out.has_histogram = true,
        else => {},
    };
    return out;
}

pub fn parseFec(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!Fec {
    var out: Fec = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.FEC.HEADER => out.device = try header.parse(a.data),
        uapi.FEC.MODES => {
            if (out.modes != null) return error.BadLength;
            out.modes = try bitset.parse(gpa, a.data);
        },
        uapi.FEC.AUTO => out.auto = (try a.asU8()) != 0,
        uapi.FEC.ACTIVE => out.active = try a.asU32(),
        uapi.FEC.STATS => out.stats = try parseFecStats(a.data),
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_FEC_SET` parameters.
pub const FecSet = struct {
    auto: ?bool = null,
    /// FEC modes to switch on or off — a delta. By index **or** by name, not
    /// both (`InvalidRequest`).
    modes: []const bitset.IndexedValue = &.{},
    mode_names: []const bitset.NamedValue = &.{},
};

pub fn appendFecSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    set: FecSet,
) bitset.BuildError!void {
    try bitset.appendMasked(gpa, list, uapi.FEC.MODES, set.modes, set.mode_names);
    if (set.auto) |v| try codec.appendAttrU8(gpa, list, uapi.FEC.AUTO, @intFromBool(v));
}

/// Encode a complete `ETHTOOL_MSG_FEC_GET` request. `Ethtool.fec` sends exactly
/// this.
pub fn buildFec(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
) header.Error![]u8 {
    return buildFecWith(gpa, family_id, seq, target, form, false);
}

/// `buildFec`, asking for the statistics nest too (`ETHTOOL_FLAG_STATS`) — what `Ethtool.fecStats` sends.
pub fn buildFecWith(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
    stats: bool,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.FEC_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.FEC.HEADER, .{ .target = target, .compact_bitsets = form.compactFlag(), .stats = stats });
    return header.finishRequest(gpa, &msg, h);
}

/// Encode a complete `ETHTOOL_MSG_FEC_SET` request. `Ethtool.setFec` sends
/// exactly this.
pub fn buildSetFec(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    set: FecSet,
) BuildError![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.FEC_SET, .seq = seq });
    try header.append(gpa, &msg, uapi.FEC.HEADER, .{ .target = target });
    try appendFecSet(gpa, &msg, set);
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Split a built request into its attribute bytes (past nlmsghdr + genlmsghdr)
/// and check the frame's command.
fn requestAttrs(msg: []const u8, cmd: u8) ![]const u8 {
    try testing.expect(msg.len >= 20);
    try testing.expectEqual(cmd, msg[16]);
    return msg[20..];
}

test "EEE reply: all fields, ours as (advertised, supported) and peer" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.EEE.HEADER, .{ .target = .byIndex(3) });
    // supported: 100baseT_Full(3), 1000baseT_Full(5); advertised: only 1000.
    try bitset.appendCompact(gpa, &list, uapi.EEE.MODES_OURS, 32, &.{1 << 5}, &.{(1 << 3) | (1 << 5)});
    try bitset.appendCompact(gpa, &list, uapi.EEE.MODES_PEER, 32, &.{1 << 5}, null);
    try codec.appendAttrU8(gpa, &list, uapi.EEE.ACTIVE, 1);
    try codec.appendAttrU8(gpa, &list, uapi.EEE.ENABLED, 1);
    try codec.appendAttrU8(gpa, &list, uapi.EEE.TX_LPI_ENABLED, 0);
    try codec.appendAttrU32(gpa, &list, uapi.EEE.TX_LPI_TIMER, 17);

    var e = try parseEee(gpa, list.items);
    defer e.deinit(gpa);
    try testing.expectEqual(@as(?u32, 3), e.device.index);
    try testing.expectEqual(@as(?bool, true), e.active);
    try testing.expectEqual(@as(?bool, true), e.enabled);
    try testing.expectEqual(@as(?bool, false), e.tx_lpi_enabled);
    try testing.expectEqual(@as(?u32, 17), e.tx_lpi_timer);
    try testing.expect(e.ours.?.inMask(uapi.LINK_MODE.@"100baseT_Full"));
    try testing.expect(!e.ours.?.isSet(uapi.LINK_MODE.@"100baseT_Full"));
    try testing.expect(e.ours.?.isSet(uapi.LINK_MODE.@"1000baseT_Full"));
    try testing.expect(e.peer.?.isSet(uapi.LINK_MODE.@"1000baseT_Full"));
}

test "EEE reply: absent attributes stay null, an empty reply is legal" {
    const gpa = testing.allocator;
    var e = try parseEee(gpa, &.{});
    defer e.deinit(gpa);
    try testing.expect(e.ours == null and e.peer == null);
    try testing.expect(e.active == null and e.enabled == null);
    try testing.expect(e.tx_lpi_enabled == null and e.tx_lpi_timer == null);
}

test "EEE reply: malformed input is a typed error and leaks nothing" {
    const gpa = testing.allocator;
    // u8 field with four bytes.
    try testing.expectError(error.BadLength, parseEee(gpa, &.{ 0x08, 0x00, 0x05, 0x00, 1, 0, 0, 0 }));
    // u32 field with one byte.
    try testing.expectError(error.BadLength, parseEee(gpa, &.{ 0x05, 0x00, 0x07, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.Truncated, parseEee(gpa, &.{ 0x40, 0x00, 0x02, 0x00, 1 }));
    // A duplicated bitset (the first one is freed by the errdefer).
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try bitset.appendCompact(gpa, &list, uapi.EEE.MODES_OURS, 32, &.{1}, null);
    try bitset.appendCompact(gpa, &list, uapi.EEE.MODES_OURS, 32, &.{1}, null);
    try testing.expectError(error.BadLength, parseEee(gpa, list.items));
}

test "EEE_GET request: command, device and compact flag" {
    const gpa = testing.allocator;
    const msg = try buildEee(gpa, 23, 9, .byName("eth0"), .compact);
    defer gpa.free(msg);
    const attrs = try requestAttrs(msg, uapi.MSG.EEE_GET);
    var it: codec.AttrIterator = .{ .buf = attrs };
    const h = (try it.next()).?;
    try testing.expectEqual(uapi.EEE.HEADER, h.type & codec.NLA_TYPE_MASK);
    var hit: codec.AttrIterator = .{ .buf = h.data };
    try testing.expectEqualStrings("eth0", (try hit.next()).?.asString());
    try testing.expectEqual(uapi.FLAG.COMPACT_BITSETS, try (try hit.next()).?.asU32());
    try testing.expect((try it.next()) == null);
}

test "EEE_SET request: only what was asked for" {
    const gpa = testing.allocator;
    const msg = try buildSetEee(gpa, 23, 9, .byIndex(3), .{
        .enabled = true,
        .tx_lpi_timer = 100,
        .advertise = &.{.{ .index = uapi.LINK_MODE.@"1000baseT_Full", .on = true }},
    });
    defer gpa.free(msg);
    const attrs = try requestAttrs(msg, uapi.MSG.EEE_SET);
    var it: codec.AttrIterator = .{ .buf = attrs };
    _ = (try it.next()).?; // header
    const ours = (try it.next()).?;
    try testing.expectEqual(uapi.EEE.MODES_OURS, ours.type & codec.NLA_TYPE_MASK);
    var bs = try bitset.parse(gpa, ours.data);
    defer bs.deinit(gpa);
    try testing.expect(bs.isSet(uapi.LINK_MODE.@"1000baseT_Full"));
    const en = (try it.next()).?;
    try testing.expectEqual(uapi.EEE.ENABLED, en.type);
    try testing.expectEqual(@as(u8, 1), try en.asU8());
    const t = (try it.next()).?;
    try testing.expectEqual(uapi.EEE.TX_LPI_TIMER, t.type);
    try testing.expectEqual(@as(u32, 100), try t.asU32());
    try testing.expect((try it.next()) == null); // tx_lpi_enabled not sent

    // An empty set is a header-only no-op.
    const empty = try buildSetEee(gpa, 23, 9, .byIndex(3), .{});
    defer gpa.free(empty);
    var eit: codec.AttrIterator = .{ .buf = try requestAttrs(empty, uapi.MSG.EEE_SET) };
    _ = (try eit.next()).?;
    try testing.expect((try eit.next()) == null);
}

test "EEE_SET and FEC_SET reject modes given both by index and by name" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidRequest, buildSetEee(gpa, 23, 1, .byIndex(1), .{
        .advertise = &.{.{ .index = 1, .on = true }},
        .advertise_names = &.{.{ .name = "x", .on = true }},
    }));
    try testing.expectError(error.InvalidRequest, buildSetFec(gpa, 23, 1, .byIndex(1), .{
        .modes = &.{.{ .index = 1, .on = true }},
        .mode_names = &.{.{ .name = "RS", .on = true }},
    }));
    // A bad device name and an out-of-range bit index.
    try testing.expectError(error.InvalidRequest, buildSetEee(gpa, 23, 1, .byName(""), .{}));
    try testing.expectError(error.InvalidRequest, buildSetFec(gpa, 23, 1, .byIndex(1), .{
        .modes = &.{.{ .index = bitset.max_bits, .on = true }},
    }));
}

test "FEC reply: auto, active bit index resolved to its name" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.FEC.HEADER, .{ .target = .byIndex(4) });
    // A verbose masked set: bit 2 "RS" set, bit 1 "BaseR" supported but off.
    try bitset.appendNamedValues(gpa, &list, uapi.FEC.MODES, &.{ .{ .name = "RS", .on = true }, .{ .name = "BaseR", .on = false } });
    try codec.appendAttrU8(gpa, &list, uapi.FEC.AUTO, 0);
    try codec.appendAttrU32(gpa, &list, uapi.FEC.ACTIVE, 2);

    var f = try parseFec(gpa, list.items);
    defer f.deinit(gpa);
    try testing.expectEqual(@as(?bool, false), f.auto);
    try testing.expectEqual(@as(?u32, 2), f.active);
    // Name-keyed entries carry no index, so the name lookup is null — and
    // honestly so, rather than invented.
    try testing.expect(f.activeName() == null);
    try testing.expect(f.modes.?.isSetByName("RS").?);
    try testing.expect(!f.modes.?.isSetByName("BaseR").?);
}

test "FEC reply: activeName with an indexed+named verbose set" {
    const gpa = testing.allocator;
    var bits: std.ArrayList(u8) = .empty;
    defer bits.deinit(gpa);
    // Hand-built verbose bitset nest contents: BITS{ BIT{INDEX=2,NAME="RS",VALUE} }.
    const nest = try codec.nestBegin(gpa, &bits, uapi.FEC.MODES | codec.NLA_F_NESTED);
    const bs_bits = try codec.nestBegin(gpa, &bits, uapi.BITSET.BITS | codec.NLA_F_NESTED);
    const bit = try codec.nestBegin(gpa, &bits, uapi.BITSET_BITS.BIT | codec.NLA_F_NESTED);
    try codec.appendAttrU32(gpa, &bits, uapi.BITSET_BIT.INDEX, 2);
    try codec.appendAttrString(gpa, &bits, uapi.BITSET_BIT.NAME, "RS");
    try codec.appendAttr(gpa, &bits, uapi.BITSET_BIT.VALUE, &.{});
    try codec.nestEnd(&bits, bit);
    try codec.nestEnd(&bits, bs_bits);
    try codec.nestEnd(&bits, nest);
    try codec.appendAttrU32(gpa, &bits, uapi.FEC.ACTIVE, 2);

    var f = try parseFec(gpa, bits.items);
    defer f.deinit(gpa);
    try testing.expectEqualStrings("RS", f.activeName().?);
    try testing.expect(f.auto == null);
    // An active index the set does not name stays null.
    f.active = 9;
    try testing.expect(f.activeName() == null);
}

test "FEC reply: malformed input is a typed error" {
    const gpa = testing.allocator;
    try testing.expectError(error.BadLength, parseFec(gpa, &.{ 0x08, 0x00, 0x03, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.BadLength, parseFec(gpa, &.{ 0x05, 0x00, 0x04, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.Truncated, parseFec(gpa, &.{ 0x40, 0x00, 0x02, 0x00, 1 }));
    var e = try parseFec(gpa, &.{});
    e.deinit(gpa);
}

test "FEC_SET request: auto, and modes by name" {
    const gpa = testing.allocator;
    const msg = try buildSetFec(gpa, 23, 3, .byName("eth0"), .{
        .auto = false,
        .mode_names = &.{.{ .name = "RS", .on = true }},
    });
    defer gpa.free(msg);
    var it: codec.AttrIterator = .{ .buf = try requestAttrs(msg, uapi.MSG.FEC_SET) };
    _ = (try it.next()).?;
    const modes = (try it.next()).?;
    try testing.expectEqual(uapi.FEC.MODES, modes.type & codec.NLA_TYPE_MASK);
    var bs = try bitset.parse(gpa, modes.data);
    defer bs.deinit(gpa);
    try testing.expectEqual(true, bs.isSetByName("RS").?);
    const auto = (try it.next()).?;
    try testing.expectEqual(uapi.FEC.AUTO, auto.type);
    try testing.expectEqual(@as(u8, 0), try auto.asU8());
    try testing.expect((try it.next()) == null);
}

test "FEC_GET request carries the compact flag only when asked" {
    const gpa = testing.allocator;
    const v = try buildFec(gpa, 23, 1, .byIndex(2), .verbose);
    defer gpa.free(v);
    const c = try buildFec(gpa, 23, 1, .byIndex(2), .compact);
    defer gpa.free(c);
    try testing.expectEqual(uapi.MSG.FEC_GET, v[16]);
    try testing.expect(c.len > v.len); // the FLAGS attribute is the difference
}

test "parseFec decodes the statistics nest: totals, per-lane values, 'not set' and a ragged counter" {
    const gpa = testing.allocator;
    const endian = @import("builtin").cpu.arch.endian();
    var nest: std.ArrayList(u8) = .empty;
    defer nest.deinit(gpa);
    var corr: [24]u8 = undefined; // total + 2 lanes
    std.mem.writeInt(u64, corr[0..8], 100, endian);
    std.mem.writeInt(u64, corr[8..16], 60, endian);
    std.mem.writeInt(u64, corr[16..24], 40, endian);
    try codec.appendAttr(gpa, &nest, uapi.FEC_STAT.CORRECTED, &corr);
    var unset: [8]u8 = undefined;
    std.mem.writeInt(u64, &unset, std.math.maxInt(u64), endian);
    try codec.appendAttr(gpa, &nest, uapi.FEC_STAT.UNCORR, &unset);
    var bits: [8]u8 = undefined;
    std.mem.writeInt(u64, &bits, 7, endian);
    try codec.appendAttr(gpa, &nest, uapi.FEC_STAT.CORR_BITS, &bits);
    const hist = try codec.nestBegin(gpa, &nest, uapi.FEC_STAT.HIST);
    try codec.nestEnd(&nest, hist);

    var outer: std.ArrayList(u8) = .empty;
    defer outer.deinit(gpa);
    try codec.appendAttrU8(gpa, &outer, uapi.FEC.AUTO, 1);
    try codec.appendAttr(gpa, &outer, uapi.FEC.STATS, nest.items);
    var f = try parseFec(gpa, outer.items);
    defer f.deinit(gpa);
    const st = f.stats.?;
    try testing.expectEqual(@as(?u64, 100), st.corrected_blocks.?.total);
    try testing.expectEqualSlices(u64, &.{ 60, 40 }, st.corrected_blocks.?.lanes());
    try testing.expectEqual(@as(?u64, null), st.uncorrectable_blocks.?.total);
    try testing.expectEqual(@as(usize, 0), st.uncorrectable_blocks.?.lanes().len);
    try testing.expectEqual(@as(?u64, 7), st.corrected_bits.?.total);
    try testing.expect(st.has_histogram);

    // No stats nest, no stats; a counter that is not whole u64s, or has too many lanes, is refused.
    var plain = try parseFec(gpa, &.{});
    defer plain.deinit(gpa);
    try testing.expect(plain.stats == null);
    try testing.expectError(error.BadLength, parseFecStats(&.{ 0x07, 0x00, 0x02, 0x00, 1, 2, 3, 0 }));
    var long: std.ArrayList(u8) = .empty;
    defer long.deinit(gpa);
    try codec.appendAttr(gpa, &long, uapi.FEC_STAT.CORRECTED, &@as([8 * 10]u8, @splat(0)));
    try testing.expectError(error.BadLength, parseFecStats(long.items));

    // The request asks for statistics with the header flag.
    const msg = try buildFecWith(gpa, 23, 1, .byIndex(2), .compact, true);
    defer gpa.free(msg);
    var it: codec.AttrIterator = .{ .buf = msg[20..] };
    const hdr = (try it.next()).?;
    var ht = hdr.nested();
    var flags: u32 = 0;
    while (try ht.next()) |a| if (a.type == uapi.HEADER.FLAGS) {
        flags = try a.asU32();
    };
    try testing.expectEqual(uapi.FLAG.COMPACT_BITSETS | uapi.FLAG.STATS, flags);
}
