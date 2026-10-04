// SPDX-License-Identifier: MIT
//! Radio and interface configuration, channel survey and power save — the
//! `iw … set channel|freq|txpower|type|power_save`, `iw phy … interface add`,
//! `iw dev … del` and `iw dev … survey dump` half of nl80211.
//!
//! Every request builder here is pinned byte-for-byte against `iw` 6.17 in
//! `goldens.zig` (captured inside `unshare -rn` against `lo` and a wiphy index
//! that does not exist, so the kernel refused each one and nothing on the host
//! changed — only the request bytes matter). Constants are from the kernel
//! UAPI `linux/nl80211.h`.
//!
//! ## Who a command targets
//!
//! A radio-wide setting (`SET_WIPHY`) can name the radio (`NL80211_ATTR_WIPHY`,
//! what `iw phy <phy> …` sends) or any netdev on it (`NL80211_ATTR_IFINDEX`,
//! what `iw dev <dev> …` sends); the kernel resolves the radio either way.
//! `Target` is that choice.
//!
//! ## Channel description
//!
//! `iw` sends a full chandef: `WIPHY_FREQ`, `WIPHY_FREQ_OFFSET` (0), the
//! `CHANNEL_WIDTH`, the legacy `WIPHY_CHANNEL_TYPE` when the width has one
//! (20 MHz no-HT, HT20, HT40±) and `CENTER_FREQ1` — then `CENTER_FREQ2` for
//! 80+80. `Channel` refuses a chandef the kernel would refuse anyway (a centre
//! that does not put the primary 20 MHz on a 20 MHz boundary inside the
//! channel), so a bad one fails here with `error.InvalidRequest`, not as an
//! `EINVAL` from the driver.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");

/// What a radio-wide setting is addressed to.
pub const Target = union(enum) {
    /// The radio's index (`iw phy phy<N>` / `phy#<N>`).
    wiphy: u32,
    /// Any netdev on the radio (`iw dev <dev>`).
    ifindex: u32,
};

/// `iw … set txpower auto|limit <mBm>|fixed <mBm>`. mBm = 1/100 dBm.
pub const TxPower = union(enum) {
    auto,
    limit_mbm: u32,
    fixed_mbm: u32,
};

/// A channel definition (`iw … set freq <control> [<width> <center1> [<center2>]]`).
pub const Channel = struct {
    /// The primary (control) channel, MHz.
    freq_mhz: u32,
    width: uapi.ChanWidth = .@"20_noht",
    /// Centre of the whole channel. Defaults to `freq_mhz` for 20 MHz and
    /// narrower; required for 40 MHz and wider.
    center1_mhz: ?u32 = null,
    /// Centre of the second segment — 80+80 only.
    center2_mhz: ?u32 = null,

    /// Primary channel `freq` at 20 MHz without HT (`iw … set channel N`).
    pub fn legacy(freq_mhz: u32) Channel {
        return .{ .freq_mhz = freq_mhz };
    }

    /// The `WIPHY_CHANNEL_TYPE` this width has, or null for VHT-and-later
    /// widths that only exist as a chandef.
    fn channelType(c: Channel, cf1: u32) ?u32 {
        return switch (c.width) {
            .@"20_noht" => uapi.CHAN.NO_HT,
            .@"20" => uapi.CHAN.HT20,
            .@"40" => if (cf1 < c.freq_mhz) uapi.CHAN.HT40MINUS else uapi.CHAN.HT40PLUS,
            else => null,
        };
    }

    /// The validated centre frequency, or `error.InvalidRequest`.
    fn center1(c: Channel) error{InvalidRequest}!u32 {
        if (c.freq_mhz == 0) return error.InvalidRequest;
        if (c.width == .@"80p80") {
            if (c.center2_mhz == null) return error.InvalidRequest;
        } else if (c.center2_mhz != null) return error.InvalidRequest;
        const mhz: u32 = if (c.width == .@"80p80") 80 else c.width.megahertz() orelse
            return error.InvalidRequest;
        if (mhz <= 20) {
            const cf = c.center1_mhz orelse return c.freq_mhz;
            if (cf != c.freq_mhz) return error.InvalidRequest;
            return cf;
        }
        // Wider than 20 MHz: the primary 20 MHz channel sits at an odd
        // multiple of 10 MHz from the centre (±10, ±30, … < width/2), or the
        // channel does not tile into 20 MHz sub-channels around it.
        const cf = c.center1_mhz orelse return error.InvalidRequest;
        const d = if (cf > c.freq_mhz) cf - c.freq_mhz else c.freq_mhz - cf;
        if (d >= mhz / 2 or d % 20 != 10) return error.InvalidRequest;
        return cf;
    }
};

fn begin(gpa: std.mem.Allocator, list: *std.ArrayList(u8), family_id: u16, seq: u32, cmd: u8, dump: bool) !usize {
    const flags: u16 = codec.NLM_F_REQUEST | codec.NLM_F_ACK | (if (dump) codec.NLM_F_DUMP else 0);
    const hdr = try codec.appendHeader(gpa, list, family_id, flags, seq, 0);
    try genl.appendHeader(gpa, list, cmd, uapi.family_version);
    return hdr;
}

fn appendTarget(gpa: std.mem.Allocator, list: *std.ArrayList(u8), t: Target) !void {
    switch (t) {
        .wiphy => |w| try codec.appendAttrU32(gpa, list, uapi.ATTR.WIPHY, w),
        .ifindex => |i| try codec.appendAttrU32(gpa, list, uapi.ATTR.IFINDEX, i),
    }
}

pub const BuildError = std.mem.Allocator.Error || error{InvalidRequest};

/// `NL80211_CMD_SET_WIPHY` with `WIPHY_TX_POWER_SETTING` [+ `_LEVEL`].
pub fn buildSetTxPower(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: Target, power: TxPower) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try begin(gpa, &list, family_id, seq, uapi.CMD.SET_WIPHY, false);
    try appendTarget(gpa, &list, target);
    switch (power) {
        .auto => try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY_TX_POWER_SETTING, uapi.TX_POWER.AUTOMATIC),
        .limit_mbm => |l| {
            try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY_TX_POWER_SETTING, uapi.TX_POWER.LIMITED);
            try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY_TX_POWER_LEVEL, l);
        },
        .fixed_mbm => |f| {
            try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY_TX_POWER_SETTING, uapi.TX_POWER.FIXED);
            try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY_TX_POWER_LEVEL, f);
        },
    }
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// `NL80211_CMD_SET_WIPHY` with a full chandef (see the file header).
pub fn buildSetChannel(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: Target, ch: Channel) BuildError![]u8 {
    const cf1 = try ch.center1();
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try begin(gpa, &list, family_id, seq, uapi.CMD.SET_WIPHY, false);
    try appendTarget(gpa, &list, target);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY_FREQ, ch.freq_mhz);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY_FREQ_OFFSET, 0);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.CHANNEL_WIDTH, @intFromEnum(ch.width));
    if (ch.channelType(cf1)) |t| try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY_CHANNEL_TYPE, t);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.CENTER_FREQ1, cf1);
    if (ch.center2_mhz) |c2| try codec.appendAttrU32(gpa, &list, uapi.ATTR.CENTER_FREQ2, c2);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// `NL80211_CMD_NEW_INTERFACE` (`iw phy <phy> interface add <name> type <t>`).
/// `name` is 1…15 bytes (IFNAMSIZ with its NUL), sent NUL-terminated.
pub fn buildNewInterface(gpa: std.mem.Allocator, family_id: u16, seq: u32, wiphy: u32, name: []const u8, iftype: uapi.Iftype) BuildError![]u8 {
    if (name.len == 0 or name.len >= 16) return error.InvalidRequest;
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try begin(gpa, &list, family_id, seq, uapi.CMD.NEW_INTERFACE, false);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.WIPHY, wiphy);
    // AttrTooLong cannot happen for a name checked to < 16 bytes above.
    codec.appendAttrString(gpa, &list, uapi.ATTR.IFNAME, name) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.AttrTooLong => error.InvalidRequest,
    };
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFTYPE, @intFromEnum(iftype));
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// `NL80211_CMD_DEL_INTERFACE` (`iw dev <dev> del`).
pub fn buildDelInterface(gpa: std.mem.Allocator, family_id: u16, seq: u32, ifindex: u32) BuildError![]u8 {
    return buildIfindexCmd(gpa, family_id, seq, uapi.CMD.DEL_INTERFACE, ifindex, false);
}

/// `NL80211_CMD_SET_INTERFACE` with a new type (`iw dev <dev> set type <t>`).
pub fn buildSetInterfaceType(gpa: std.mem.Allocator, family_id: u16, seq: u32, ifindex: u32, iftype: uapi.Iftype) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try begin(gpa, &list, family_id, seq, uapi.CMD.SET_INTERFACE, false);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, ifindex);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFTYPE, @intFromEnum(iftype));
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// `NL80211_CMD_SET_POWER_SAVE` (`iw dev <dev> set power_save on|off`).
pub fn buildSetPowerSave(gpa: std.mem.Allocator, family_id: u16, seq: u32, ifindex: u32, on: bool) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try begin(gpa, &list, family_id, seq, uapi.CMD.SET_POWER_SAVE, false);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, ifindex);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PS_STATE, if (on) uapi.PS.ENABLED else uapi.PS.DISABLED);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// `NL80211_CMD_GET_POWER_SAVE` (`iw dev <dev> get power_save`).
pub fn buildGetPowerSave(gpa: std.mem.Allocator, family_id: u16, seq: u32, ifindex: u32) BuildError![]u8 {
    return buildIfindexCmd(gpa, family_id, seq, uapi.CMD.GET_POWER_SAVE, ifindex, false);
}

/// `NL80211_CMD_GET_SURVEY` dump (`iw dev <dev> survey dump`).
pub fn buildGetSurvey(gpa: std.mem.Allocator, family_id: u16, seq: u32, ifindex: u32) BuildError![]u8 {
    return buildIfindexCmd(gpa, family_id, seq, uapi.CMD.GET_SURVEY, ifindex, true);
}

fn buildIfindexCmd(gpa: std.mem.Allocator, family_id: u16, seq: u32, cmd: u8, ifindex: u32, dump: bool) BuildError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try begin(gpa, &list, family_id, seq, cmd, dump);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, ifindex);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// The power-save state in a `GET_POWER_SAVE` reply's attributes, or null
/// when the reply carries none.
pub fn parsePowerSave(attrs: []const u8) codec.Error!?bool {
    var it: codec.AttrIterator = .{ .buf = attrs };
    while (try it.next()) |a| {
        if (a.type == uapi.ATTR.PS_STATE) return (try a.asU32()) != uapi.PS.DISABLED;
    }
    return null;
}

/// One channel of a survey dump (`iw dev <dev> survey dump`). Every counter is
/// optional because drivers report different subsets; times are milliseconds
/// since the driver started counting.
pub const Survey = struct {
    ifindex: ?u32 = null,
    frequency_mhz: u32 = 0,
    /// kHz on top of `frequency_mhz` (S1G); 0 elsewhere.
    frequency_offset_khz: u32 = 0,
    /// Noise floor, dBm.
    noise_dbm: ?i8 = null,
    /// The channel the interface is currently on.
    in_use: bool = false,
    active_ms: ?u64 = null,
    busy_ms: ?u64 = null,
    ext_busy_ms: ?u64 = null,
    rx_ms: ?u64 = null,
    tx_ms: ?u64 = null,
    scan_ms: ?u64 = null,
    bss_rx_ms: ?u64 = null,
};

/// Parse one `NEW_SURVEY_RESULTS` message's attributes. Null when it carries
/// no `SURVEY_INFO` or no frequency (nothing to attribute the counters to).
pub fn parseSurvey(attrs: []const u8) codec.Error!?Survey {
    var out: Survey = .{};
    var info: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = attrs };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.IFINDEX => out.ifindex = try a.asU32(),
        uapi.ATTR.SURVEY_INFO => info = a.data,
        else => {},
    };
    const data = info orelse return null;
    var have_freq = false;
    var si: codec.AttrIterator = .{ .buf = data };
    while (try si.next()) |a| switch (a.type) {
        uapi.SURVEY_INFO.FREQUENCY => {
            out.frequency_mhz = try a.asU32();
            have_freq = true;
        },
        uapi.SURVEY_INFO.FREQUENCY_OFFSET => out.frequency_offset_khz = try a.asU32(),
        // u8 on the wire, signed dBm (the kernel puts an s8 there).
        uapi.SURVEY_INFO.NOISE => out.noise_dbm = @bitCast(try a.asU8()),
        uapi.SURVEY_INFO.IN_USE => out.in_use = true,
        uapi.SURVEY_INFO.TIME => out.active_ms = try asU64(a),
        uapi.SURVEY_INFO.TIME_BUSY => out.busy_ms = try asU64(a),
        uapi.SURVEY_INFO.TIME_EXT_BUSY => out.ext_busy_ms = try asU64(a),
        uapi.SURVEY_INFO.TIME_RX => out.rx_ms = try asU64(a),
        uapi.SURVEY_INFO.TIME_TX => out.tx_ms = try asU64(a),
        uapi.SURVEY_INFO.TIME_SCAN => out.scan_ms = try asU64(a),
        uapi.SURVEY_INFO.TIME_BSS_RX => out.bss_rx_ms = try asU64(a),
        else => {},
    };
    if (!have_freq) return null;
    return out;
}

fn asU64(a: codec.Attr) codec.Error!u64 {
    if (a.data.len != 8) return error.BadLength;
    return std.mem.readInt(u64, a.data[0..8], @import("builtin").cpu.arch.endian());
}

// ── tests (validation; the byte goldens live in goldens.zig) ───────────────

const testing = std.testing;

test "Channel: centres that do not tile are refused, the rest are accepted" {
    // 20 MHz: the centre is the primary channel itself.
    try testing.expectEqual(@as(u32, 2437), try Channel.legacy(2437).center1());
    try testing.expectError(error.InvalidRequest, (Channel{ .freq_mhz = 2437, .center1_mhz = 2447 }).center1());
    // 40 MHz: ±10 only (HT40+ / HT40-).
    try testing.expectEqual(@as(u32, 2447), try (Channel{ .freq_mhz = 2437, .width = .@"40", .center1_mhz = 2447 }).center1());
    try testing.expectError(error.InvalidRequest, (Channel{ .freq_mhz = 2437, .width = .@"40", .center1_mhz = 2457 }).center1());
    try testing.expectError(error.InvalidRequest, (Channel{ .freq_mhz = 2437, .width = .@"40" }).center1());
    // 80 MHz: ±10 or ±30 (5180 primary of the 5210-centred block is -30).
    try testing.expectEqual(@as(u32, 5210), try (Channel{ .freq_mhz = 5180, .width = .@"80", .center1_mhz = 5210 }).center1());
    try testing.expectEqual(@as(u32, 5210), try (Channel{ .freq_mhz = 5200, .width = .@"80", .center1_mhz = 5210 }).center1());
    // 40 MHz away is past the edge of an 80 MHz channel; 20 away is not on a
    // 20 MHz boundary.
    try testing.expectError(error.InvalidRequest, (Channel{ .freq_mhz = 5170, .width = .@"80", .center1_mhz = 5210 }).center1());
    try testing.expectError(error.InvalidRequest, (Channel{ .freq_mhz = 5190, .width = .@"80", .center1_mhz = 5210 }).center1());
    // 160 MHz reaches ±70.
    try testing.expectEqual(@as(u32, 5250), try (Channel{ .freq_mhz = 5180, .width = .@"160", .center1_mhz = 5250 }).center1());
    // 80+80 needs its second segment; nothing else may have one.
    try testing.expectError(error.InvalidRequest, (Channel{ .freq_mhz = 5180, .width = .@"80p80", .center1_mhz = 5210 }).center1());
    _ = try (Channel{ .freq_mhz = 5180, .width = .@"80p80", .center1_mhz = 5210, .center2_mhz = 5775 }).center1();
    try testing.expectError(error.InvalidRequest, (Channel{ .freq_mhz = 5180, .width = .@"80", .center1_mhz = 5210, .center2_mhz = 5775 }).center1());
    try testing.expectError(error.InvalidRequest, Channel.legacy(0).center1());
}

/// The value of attribute `t` in a built request (after nlmsghdr + genlmsghdr).
fn attrU32(req: []const u8, t: u16) !?u32 {
    var it: codec.AttrIterator = .{ .buf = req[20..] };
    while (try it.next()) |a| if (a.type == t) return try a.asU32();
    return null;
}

test "buildSetChannel: HT20 carries channel type HT20, 80+80 carries its second centre" {
    // NL80211_CHAN_WIDTH_20 is the HT 20 MHz channel, so its legacy channel
    // type is NL80211_CHAN_HT20 (1) — not NO_HT (0), which is width 20_noht.
    const ht20 = try buildSetChannel(testing.allocator, 41, 1, .{ .ifindex = 3 }, .{ .freq_mhz = 2412, .width = .@"20" });
    defer testing.allocator.free(ht20);
    try testing.expectEqual(@as(?u32, uapi.CHAN.HT20), try attrU32(ht20, uapi.ATTR.WIPHY_CHANNEL_TYPE));
    try testing.expectEqual(@as(?u32, 1), try attrU32(ht20, uapi.ATTR.CHANNEL_WIDTH));
    try testing.expectEqual(@as(?u32, 2412), try attrU32(ht20, uapi.ATTR.CENTER_FREQ1));
    // 80+80: the second 80 MHz segment's centre travels in CENTER_FREQ2
    // (161); a VHT width has no legacy channel type.
    const p = try buildSetChannel(testing.allocator, 41, 1, .{ .wiphy = 0 }, .{
        .freq_mhz = 5180,
        .width = .@"80p80",
        .center1_mhz = 5210,
        .center2_mhz = 5775,
    });
    defer testing.allocator.free(p);
    try testing.expectEqual(@as(?u32, 5775), try attrU32(p, uapi.ATTR.CENTER_FREQ2));
    try testing.expectEqual(@as(?u32, 5210), try attrU32(p, uapi.ATTR.CENTER_FREQ1));
    try testing.expectEqual(@as(?u32, null), try attrU32(p, uapi.ATTR.WIPHY_CHANNEL_TYPE));
    try testing.expectEqual(@as(?u32, 0), try attrU32(p, uapi.ATTR.WIPHY));
}

test "buildNewInterface refuses empty and over-long names" {
    try testing.expectError(error.InvalidRequest, buildNewInterface(testing.allocator, 41, 1, 0, "", .monitor));
    // 16 bytes + NUL does not fit IFNAMSIZ (16).
    try testing.expectError(error.InvalidRequest, buildNewInterface(testing.allocator, 41, 1, 0, "abcdefghijklmnop", .monitor));
    const ok = try buildNewInterface(testing.allocator, 41, 1, 0, "abcdefghijklmno", .monitor);
    testing.allocator.free(ok);
}

test "parseSurvey: every counter, signed noise, and messages without a channel" {
    const gpa = testing.allocator;
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    try codec.appendAttrU32(gpa, &a, uapi.ATTR.IFINDEX, 3);
    const n = try codec.nestBegin(gpa, &a, codec.NLA_F_NESTED | uapi.ATTR.SURVEY_INFO);
    try codec.appendAttrU32(gpa, &a, uapi.SURVEY_INFO.FREQUENCY, 5180);
    try codec.appendAttrU32(gpa, &a, uapi.SURVEY_INFO.FREQUENCY_OFFSET, 500);
    try codec.appendAttrU8(gpa, &a, uapi.SURVEY_INFO.NOISE, 0xa1); // -95 dBm as an s8
    try codec.appendAttr(gpa, &a, uapi.SURVEY_INFO.IN_USE, &.{});
    const times = [_]u16{
        uapi.SURVEY_INFO.TIME,        uapi.SURVEY_INFO.TIME_BUSY, uapi.SURVEY_INFO.TIME_EXT_BUSY,
        uapi.SURVEY_INFO.TIME_RX,     uapi.SURVEY_INFO.TIME_TX,   uapi.SURVEY_INFO.TIME_SCAN,
        uapi.SURVEY_INFO.TIME_BSS_RX,
    };
    for (times, 0..) |t, i| {
        var v: [8]u8 = undefined;
        std.mem.writeInt(u64, &v, 1000 + i, @import("builtin").cpu.arch.endian());
        try codec.appendAttr(gpa, &a, t, &v);
    }
    try codec.nestEnd(&a, n);
    const s = (try parseSurvey(a.items)).?;
    try testing.expectEqual(@as(?u32, 3), s.ifindex);
    try testing.expectEqual(@as(u32, 5180), s.frequency_mhz);
    try testing.expectEqual(@as(?i8, -95), s.noise_dbm);
    try testing.expectEqual(@as(u32, 500), s.frequency_offset_khz);
    try testing.expect(s.in_use);
    try testing.expectEqual(@as(?u64, 1000), s.active_ms);
    try testing.expectEqual(@as(?u64, 1001), s.busy_ms);
    try testing.expectEqual(@as(?u64, 1002), s.ext_busy_ms);
    try testing.expectEqual(@as(?u64, 1003), s.rx_ms);
    try testing.expectEqual(@as(?u64, 1004), s.tx_ms);
    try testing.expectEqual(@as(?u64, 1005), s.scan_ms);
    try testing.expectEqual(@as(?u64, 1006), s.bss_rx_ms);

    // No SURVEY_INFO at all, or one without a frequency: nothing to report.
    try testing.expect((try parseSurvey(&.{ 8, 0, 3, 0, 3, 0, 0, 0 })) == null);
    try testing.expect((try parseSurvey(&.{ 12, 0, 84, 0x80, 5, 0, 2, 0, 0xa1, 0, 0, 0 })) == null);
    // A 4-byte TIME is malformed.
    try testing.expectError(error.BadLength, parseSurvey(&.{
        20, 0, 84, 0x80,
        8,  0, 1,  0,
        0x3c, 0x14, 0, 0, // FREQUENCY 5180
        8,    0,    4, 0,
        1, 0, 0, 0, // TIME, 4 bytes
    }));
}

test "parsePowerSave: on, off, absent, malformed" {
    try testing.expectEqual(@as(?bool, true), try parsePowerSave(&.{ 8, 0, 93, 0, 1, 0, 0, 0 }));
    try testing.expectEqual(@as(?bool, false), try parsePowerSave(&.{ 8, 0, 93, 0, 0, 0, 0, 0 }));
    try testing.expectEqual(@as(?bool, null), try parsePowerSave(&.{ 8, 0, 3, 0, 1, 0, 0, 0 }));
    try testing.expectError(error.BadLength, parsePowerSave(&.{ 5, 0, 93, 0, 1, 0, 0, 0 }));
}
