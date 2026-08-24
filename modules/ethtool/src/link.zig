// SPDX-License-Identifier: MIT
//! Link settings and state: `LINKINFO_GET`/`SET`, `LINKMODES_GET`/`SET` and
//! `LINKSTATE_GET`.
//!
//! These are three separate messages because they change at three different
//! rates: `LINKINFO` is the physical wiring (port, PHY address, MDI-X),
//! `LINKMODES` is the negotiation configuration *and* its outcome (autoneg,
//! speed, duplex, the supported/advertised link-mode bitsets), and `LINKSTATE`
//! is whether the thing is up right now.
//!
//! **Speed and duplex in a `LINKMODES` reply are the negotiated result** when
//! autoneg is on; they are the forced configuration when it is off. `SPEED` is
//! a u32 on the wire but `SPEED_UNKNOWN` is `-1` in `linux/ethtool.h`, so
//! `LinkModes.speedMbps` returns null for `0xffffffff` rather than 4294967295.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");

pub const Error = codec.Error || error{OutOfMemory};

/// What the `build*` encoders below can fail with: `header.Error` for the
/// request header (an impossible device name is caught locally), plus whatever
/// the attribute appenders raise.
pub const BuildError = Error || header.Error;

// ── LINKINFO ───────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_LINKINFO_GET` reply. Everything is optional: a driver that does
/// not implement a field simply omits it.
pub const LinkInfo = struct {
    device: header.Device = .{},
    port: ?uapi.Port = null,
    /// The MDIO address of the PHY, when there is one.
    phyaddr: ?u8 = null,
    /// Current MDI/MDI-X *status* (`invalid` = unknown).
    tp_mdix: ?uapi.MdiX = null,
    /// MDI/MDI-X *control* setting (`invalid` = the PHY has no control).
    tp_mdix_ctrl: ?uapi.MdiX = null,
    transceiver: ?uapi.Transceiver = null,
};

pub fn parseLinkInfo(attr_bytes: []const u8) codec.Error!LinkInfo {
    var out: LinkInfo = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.LINKINFO.HEADER => out.device = try header.parse(a.data),
        uapi.LINKINFO.PORT => out.port = @enumFromInt(try a.asU8()),
        uapi.LINKINFO.PHYADDR => out.phyaddr = try a.asU8(),
        uapi.LINKINFO.TP_MDIX => out.tp_mdix = @enumFromInt(try a.asU8()),
        uapi.LINKINFO.TP_MDIX_CTRL => out.tp_mdix_ctrl = @enumFromInt(try a.asU8()),
        uapi.LINKINFO.TRANSCEIVER => out.transceiver = @enumFromInt(try a.asU8()),
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_LINKINFO_SET` parameters. Only `port` and `tp_mdix_ctrl` are
/// writable in practice; the kernel rejects the rest.
pub const LinkInfoSet = struct {
    port: ?uapi.Port = null,
    tp_mdix_ctrl: ?uapi.MdiX = null,
};

pub fn appendLinkInfoSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    set: LinkInfoSet,
) std.mem.Allocator.Error!void {
    if (set.port) |p| try codec.appendAttrU8(gpa, list, uapi.LINKINFO.PORT, @intFromEnum(p));
    if (set.tp_mdix_ctrl) |m| try codec.appendAttrU8(gpa, list, uapi.LINKINFO.TP_MDIX_CTRL, @intFromEnum(m));
}

/// Encode a complete `ETHTOOL_MSG_LINKINFO_GET` request. The result is the
/// whole datagram — `nlmsghdr`, `genlmsghdr`, header nest — owned by the
/// caller, who frees it with `gpa`. `Ethtool.linkInfo` sends exactly this.
pub fn buildLinkInfo(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{
        .family_id = family_id,
        .cmd = uapi.MSG.LINKINFO_GET,
        .seq = seq,
    });
    try header.append(gpa, &msg, uapi.LINKINFO.HEADER, .{ .target = target });
    return header.finishRequest(gpa, &msg, h);
}

/// Encode a complete `ETHTOOL_MSG_LINKINFO_SET` request. `Ethtool.setLinkInfo`
/// sends exactly this.
pub fn buildSetLinkInfo(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    set: LinkInfoSet,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{
        .family_id = family_id,
        .cmd = uapi.MSG.LINKINFO_SET,
        .seq = seq,
    });
    try header.append(gpa, &msg, uapi.LINKINFO.HEADER, .{ .target = target });
    try appendLinkInfoSet(gpa, &msg, set);
    return header.finishRequest(gpa, &msg, h);
}

// ── LINKMODES ──────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_LINKMODES_GET` reply. Owns its bitsets — free with `deinit`.
pub const LinkModes = struct {
    device: header.Device = .{},
    autoneg: ?bool = null,
    /// Raw `ETHTOOL_A_LINKMODES_SPEED`; see `speedMbps`.
    speed: ?u32 = null,
    duplex: ?uapi.Duplex = null,
    master_slave_cfg: ?uapi.MasterSlaveCfg = null,
    master_slave_state: ?uapi.MasterSlaveState = null,
    lanes: ?u32 = null,
    rate_matching: ?u8 = null,
    /// What this device supports and advertises. The *value* half is what is
    /// advertised; the *mask* half is what is supported at all — which is why
    /// `Bitset.inMask` matters here and `isSet` alone would mislead.
    ours: ?bitset.Bitset = null,
    /// What the link partner advertises, when autoneg completed.
    peer: ?bitset.Bitset = null,

    pub fn deinit(lm: *LinkModes, gpa: std.mem.Allocator) void {
        if (lm.ours) |*b| b.deinit(gpa);
        if (lm.peer) |*b| b.deinit(gpa);
        lm.* = .{};
    }

    /// Negotiated (or forced) speed in Mb/s, or null when the kernel reported
    /// `SPEED_UNKNOWN` — which is what a link that is down reports.
    pub fn speedMbps(lm: LinkModes) ?u32 {
        const s = lm.speed orelse return null;
        return if (s == uapi.SPEED_UNKNOWN) null else s;
    }

    /// Does this device *support* the link mode with the given bit index?
    /// (Supported, not necessarily advertised — see `advertises`.)
    pub fn supports(lm: LinkModes, mode_bit: u32) bool {
        const o = lm.ours orelse return false;
        return o.inMask(mode_bit);
    }

    /// Does this device currently *advertise* the link mode?
    pub fn advertises(lm: LinkModes, mode_bit: u32) bool {
        const o = lm.ours orelse return false;
        return o.isSet(mode_bit);
    }
};

pub fn parseLinkModes(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!LinkModes {
    var out: LinkModes = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.LINKMODES.HEADER => out.device = try header.parse(a.data),
        uapi.LINKMODES.AUTONEG => out.autoneg = (try a.asU8()) != 0,
        uapi.LINKMODES.SPEED => out.speed = try a.asU32(),
        uapi.LINKMODES.DUPLEX => out.duplex = @enumFromInt(try a.asU8()),
        uapi.LINKMODES.MASTER_SLAVE_CFG => out.master_slave_cfg = @enumFromInt(try a.asU8()),
        uapi.LINKMODES.MASTER_SLAVE_STATE => out.master_slave_state = @enumFromInt(try a.asU8()),
        uapi.LINKMODES.LANES => out.lanes = try a.asU32(),
        uapi.LINKMODES.RATE_MATCHING => out.rate_matching = try a.asU8(),
        uapi.LINKMODES.OURS => {
            if (out.ours != null) return error.BadLength;
            out.ours = try bitset.parse(gpa, a.data);
        },
        uapi.LINKMODES.PEER => {
            if (out.peer != null) return error.BadLength;
            out.peer = try bitset.parse(gpa, a.data);
        },
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_LINKMODES_SET` parameters.
///
/// The kernel's rule, which this module does not paper over: with
/// `autoneg = true` you set what is *advertised* (`advertise`); with
/// `autoneg = false` you force `speed` + `duplex` and the advertisement is
/// ignored. Sending a speed/duplex while autoneg stays on is accepted by the
/// kernel and does nothing useful.
pub const LinkModesSet = struct {
    autoneg: ?bool = null,
    speed_mbps: ?u32 = null,
    duplex: ?uapi.Duplex = null,
    lanes: ?u32 = null,
    master_slave_cfg: ?uapi.MasterSlaveCfg = null,
    /// Link modes to advertise, by bit index. Bits not listed are left alone
    /// (the request bitset carries a mask), so this is a delta, not a
    /// replacement.
    advertise: []const bitset.IndexedValue = &.{},
};

pub fn appendLinkModesSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    set: LinkModesSet,
) bitset.Error!void {
    // Attribute order carries no meaning to the kernel, but this one matches
    // what `ethtool -s <dev> speed … duplex … autoneg …` emits, so the golden
    // comparison is a plain byte compare instead of a set comparison.
    if (set.speed_mbps) |s| try codec.appendAttrU32(gpa, list, uapi.LINKMODES.SPEED, s);
    if (set.duplex) |d| try codec.appendAttrU8(gpa, list, uapi.LINKMODES.DUPLEX, @intFromEnum(d));
    if (set.autoneg) |v| try codec.appendAttrU8(gpa, list, uapi.LINKMODES.AUTONEG, @intFromBool(v));
    if (set.master_slave_cfg) |m|
        try codec.appendAttrU8(gpa, list, uapi.LINKMODES.MASTER_SLAVE_CFG, @intFromEnum(m));
    if (set.lanes) |l| try codec.appendAttrU32(gpa, list, uapi.LINKMODES.LANES, l);
    if (set.advertise.len != 0)
        try bitset.appendIndexedValues(gpa, list, uapi.LINKMODES.OURS, set.advertise);
}

/// Encode a complete `ETHTOOL_MSG_LINKMODES_GET` request. `form` picks the
/// bitset encoding the reply will use, and it does so through the request
/// header's `FLAGS` word — which is why it is part of the message rather than
/// of the sending. `Ethtool.linkModes` sends exactly this.
pub fn buildLinkModes(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{
        .family_id = family_id,
        .cmd = uapi.MSG.LINKMODES_GET,
        .seq = seq,
    });
    try header.append(gpa, &msg, uapi.LINKMODES.HEADER, .{
        .target = target,
        .compact_bitsets = form.compactFlag(),
    });
    return header.finishRequest(gpa, &msg, h);
}

/// Encode a complete `ETHTOOL_MSG_LINKMODES_SET` request.
/// `Ethtool.setLinkModes` sends exactly this.
pub fn buildSetLinkModes(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    set: LinkModesSet,
) BuildError![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{
        .family_id = family_id,
        .cmd = uapi.MSG.LINKMODES_SET,
        .seq = seq,
    });
    try header.append(gpa, &msg, uapi.LINKMODES.HEADER, .{ .target = target });
    try appendLinkModesSet(gpa, &msg, set);
    return header.finishRequest(gpa, &msg, h);
}

// ── LINKSTATE ──────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_LINKSTATE_GET` reply.
pub const LinkState = struct {
    device: header.Device = .{},
    /// Carrier state. Null means the driver could not tell.
    link: ?bool = null,
    /// Signal quality index, on PHYs that report one (802.3bw/bp automotive).
    sqi: ?u32 = null,
    sqi_max: ?u32 = null,
    /// Why the link is down, when the driver knows. Only meaningful when
    /// `link` is false.
    ext_state: ?uapi.LinkExtState = null,
    /// A per-`ext_state` refinement — the sub-enums in `linux/ethtool.h` are
    /// disjoint per state, so this is deliberately left as a raw number
    /// instead of being decoded into a false single enum.
    ext_substate: ?u8 = null,
    /// How many times the link has gone down since the interface came up.
    ext_down_cnt: ?u32 = null,
};

pub fn parseLinkState(attr_bytes: []const u8) codec.Error!LinkState {
    var out: LinkState = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.LINKSTATE.HEADER => out.device = try header.parse(a.data),
        uapi.LINKSTATE.LINK => out.link = (try a.asU8()) != 0,
        uapi.LINKSTATE.SQI => out.sqi = try a.asU32(),
        uapi.LINKSTATE.SQI_MAX => out.sqi_max = try a.asU32(),
        uapi.LINKSTATE.EXT_STATE => out.ext_state = @enumFromInt(try a.asU8()),
        uapi.LINKSTATE.EXT_SUBSTATE => out.ext_substate = try a.asU8(),
        uapi.LINKSTATE.EXT_DOWN_CNT => out.ext_down_cnt = try a.asU32(),
        else => {},
    };
    return out;
}

/// Encode a complete `ETHTOOL_MSG_LINKSTATE_GET` request. `Ethtool.linkState`
/// sends exactly this.
pub fn buildLinkState(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{
        .family_id = family_id,
        .cmd = uapi.MSG.LINKSTATE_GET,
        .seq = seq,
    });
    try header.append(gpa, &msg, uapi.LINKSTATE.HEADER, .{ .target = target });
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "LINKINFO decodes the five u8 fields and tolerates a partial reply" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.LINKINFO.HEADER, .{ .target = .byIndex(2) });
    try codec.appendAttrU8(gpa, &list, uapi.LINKINFO.PORT, @intFromEnum(uapi.Port.fibre));
    try codec.appendAttrU8(gpa, &list, uapi.LINKINFO.PHYADDR, 2);
    try codec.appendAttrU8(gpa, &list, uapi.LINKINFO.TP_MDIX, @intFromEnum(uapi.MdiX.mdi_x));

    const li = try parseLinkInfo(list.items);
    try testing.expectEqual(@as(?u32, 2), li.device.index);
    try testing.expectEqual(uapi.Port.fibre, li.port.?);
    try testing.expectEqual(@as(?u8, 2), li.phyaddr);
    try testing.expectEqual(uapi.MdiX.mdi_x, li.tp_mdix.?);
    // Not sent → not invented.
    try testing.expect(li.transceiver == null);
    try testing.expect(li.tp_mdix_ctrl == null);
}

test "LINKMODES: speedMbps maps SPEED_UNKNOWN to null" {
    var lm: LinkModes = .{ .speed = 1000 };
    try testing.expectEqual(@as(?u32, 1000), lm.speedMbps());
    lm.speed = uapi.SPEED_UNKNOWN;
    try testing.expect(lm.speedMbps() == null);
    lm.speed = null;
    try testing.expect(lm.speedMbps() == null);
}

test "LINKMODES: supports vs advertises come from the two halves of one bitset" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrU8(gpa, &list, uapi.LINKMODES.AUTONEG, 1);
    try codec.appendAttrU32(gpa, &list, uapi.LINKMODES.SPEED, 1000);
    try codec.appendAttrU8(gpa, &list, uapi.LINKMODES.DUPLEX, @intFromEnum(uapi.Duplex.full));
    // Supported = bits 0..5 (10/100/1000, half+full); advertised = only 5.
    const value = [_]u32{1 << 5};
    const mask = [_]u32{0b11_1111};
    try bitset.appendCompact(gpa, &list, uapi.LINKMODES.OURS, 32, &value, &mask);

    var lm = try parseLinkModes(gpa, list.items);
    defer lm.deinit(gpa);
    try testing.expectEqual(@as(?bool, true), lm.autoneg);
    try testing.expectEqual(uapi.Duplex.full, lm.duplex.?);
    try testing.expect(lm.supports(uapi.LINK_MODE.@"100baseT_Full"));
    try testing.expect(!lm.advertises(uapi.LINK_MODE.@"100baseT_Full"));
    try testing.expect(lm.advertises(uapi.LINK_MODE.@"1000baseT_Full"));
    try testing.expect(!lm.supports(uapi.LINK_MODE.Autoneg)); // bit 6, outside the mask
    // No PEER bitset in the reply → nothing invented.
    try testing.expect(lm.peer == null);
}

test "LINKMODES: a duplicated bitset attribute is a malformed reply, not a leak" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const value = [_]u32{1};
    try bitset.appendCompact(gpa, &list, uapi.LINKMODES.OURS, 32, &value, null);
    try bitset.appendCompact(gpa, &list, uapi.LINKMODES.OURS, 32, &value, null);
    try testing.expectError(error.BadLength, parseLinkModes(gpa, list.items));
}

test "LINKSTATE decodes link/SQI/ext-state, and leaves substate raw" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrU8(gpa, &list, uapi.LINKSTATE.LINK, 0);
    try codec.appendAttrU32(gpa, &list, uapi.LINKSTATE.SQI, 3);
    try codec.appendAttrU32(gpa, &list, uapi.LINKSTATE.SQI_MAX, 7);
    try codec.appendAttrU8(gpa, &list, uapi.LINKSTATE.EXT_STATE, @intFromEnum(uapi.LinkExtState.cable_issue));
    try codec.appendAttrU8(gpa, &list, uapi.LINKSTATE.EXT_SUBSTATE, 2);
    try codec.appendAttrU32(gpa, &list, uapi.LINKSTATE.EXT_DOWN_CNT, 11);

    const ls = try parseLinkState(list.items);
    try testing.expectEqual(@as(?bool, false), ls.link);
    try testing.expectEqual(@as(?u32, 3), ls.sqi);
    try testing.expectEqual(@as(?u32, 7), ls.sqi_max);
    try testing.expectEqual(uapi.LinkExtState.cable_issue, ls.ext_state.?);
    try testing.expectEqual(@as(?u8, 2), ls.ext_substate);
    try testing.expectEqual(@as(?u32, 11), ls.ext_down_cnt);
}

test "malformed link replies are typed errors" {
    const gpa = testing.allocator;
    // A u8 field carrying four bytes.
    try testing.expectError(error.BadLength, parseLinkInfo(&.{ 0x08, 0x00, 0x02, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.BadLength, parseLinkState(&.{ 0x08, 0x00, 0x02, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.Truncated, parseLinkModes(gpa, &.{ 0x40, 0x00, 0x03, 0x00, 1 }));
}

test "LINKMODES_SET encodes only what was asked for" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendLinkModesSet(gpa, &list, .{ .autoneg = false, .speed_mbps = 100, .duplex = .full });
    var it: codec.AttrIterator = .{ .buf = list.items };
    try testing.expectEqual(@as(u32, 100), try (try it.next()).?.asU32()); // speed
    try testing.expectEqual(@as(u8, 1), try (try it.next()).?.asU8()); // duplex full
    try testing.expectEqual(@as(u8, 0), try (try it.next()).?.asU8()); // autoneg off
    try testing.expect((try it.next()) == null);

    // Advertisement-only form (autoneg stays whatever it was).
    list.clearRetainingCapacity();
    try appendLinkModesSet(gpa, &list, .{
        .autoneg = true,
        .advertise = &.{.{ .index = uapi.LINK_MODE.@"1000baseT_Full", .on = true }},
    });
    var lm = try parseLinkModes(gpa, list.items);
    defer lm.deinit(gpa);
    try testing.expect(lm.advertises(uapi.LINK_MODE.@"1000baseT_Full"));
}
