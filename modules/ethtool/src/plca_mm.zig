// SPDX-License-Identifier: MIT
//! `PLCA_GET_CFG` / `PLCA_SET_CFG` / `PLCA_GET_STATUS` (IEEE 802.3cg Physical Layer Collision Avoidance for 10BASE-T1S
//! multidrop Ethernet, `ethtool --get-plca-cfg`, `--set-plca-cfg`, `--get-plca-status`) and `MM_GET` / `MM_SET` (IEEE
//! 802.3br / 802.1Qbu MAC merge layer: frame preemption, `ethtool --show-mm`, `--set-mm`).
//!
//! Every attribute is optional in a reply: the kernel sends what the driver implements. Reading is unprivileged; a
//! SET needs **CAP_NET_ADMIN**. Widths are the kernel's policy's: PLCA's version is a `u16`, its flags `u8`, its
//! counts and timers `u32`; MM's flags are `u8`, its sizes and times `u32`, its statistics `u64`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");

// ── PLCA ───────────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_PLCA_GET_CFG` reply.
pub const PlcaCfg = struct {
    device: header.Device = .{},
    /// The IEEE 802.3cg register map version the PHY reports.
    version: ?u16 = null,
    enabled: ?bool = null,
    /// How many nodes the coordinator (node 0) serves.
    node_cnt: ?u32 = null,
    /// This node's ID (0 is the coordinator, 255 means unconfigured).
    node_id: ?u32 = null,
    /// Transmit opportunity timer, in bit times.
    to_timer: ?u32 = null,
    /// Extra frames a node may send in one opportunity.
    burst_cnt: ?u32 = null,
    /// How long, in bit times, a node waits for a burst continuation.
    burst_timer: ?u32 = null,
};

pub fn parsePlcaCfg(attr_bytes: []const u8) codec.Error!PlcaCfg {
    var out: PlcaCfg = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.PLCA.HEADER => out.device = try header.parse(a.data),
        uapi.PLCA.VERSION => out.version = try a.asU16(),
        uapi.PLCA.ENABLED => out.enabled = (try a.asU8()) != 0,
        uapi.PLCA.NODE_CNT => out.node_cnt = try a.asU32(),
        uapi.PLCA.NODE_ID => out.node_id = try a.asU32(),
        uapi.PLCA.TO_TMR => out.to_timer = try a.asU32(),
        uapi.PLCA.BURST_CNT => out.burst_cnt = try a.asU32(),
        uapi.PLCA.BURST_TMR => out.burst_timer = try a.asU32(),
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_PLCA_GET_STATUS` reply.
pub const PlcaStatus = struct {
    device: header.Device = .{},
    /// Whether the node currently sees a working PLCA cycle (the beacon).
    status: ?bool = null,
};

pub fn parsePlcaStatus(attr_bytes: []const u8) codec.Error!PlcaStatus {
    var out: PlcaStatus = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.PLCA.HEADER => out.device = try header.parse(a.data),
        uapi.PLCA.STATUS => out.status = (try a.asU8()) != 0,
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_PLCA_SET_CFG` parameters: only the fields that are set are sent. `node_id` is at most 255 (the
/// kernel's policy), `node_cnt` 1..255 and `burst_cnt` at most 255; a value outside is `InvalidRequest`.
pub const PlcaSet = struct {
    enabled: ?bool = null,
    node_cnt: ?u32 = null,
    node_id: ?u32 = null,
    to_timer: ?u32 = null,
    burst_cnt: ?u32 = null,
    burst_timer: ?u32 = null,
};

pub const BuildError = header.Error;

pub fn buildPlcaCfg(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: header.Target) header.Error![]u8 {
    return buildGet(gpa, family_id, seq, uapi.MSG.PLCA_GET_CFG, uapi.PLCA.HEADER, target, false);
}

pub fn buildPlcaStatus(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: header.Target) header.Error![]u8 {
    return buildGet(gpa, family_id, seq, uapi.MSG.PLCA_GET_STATUS, uapi.PLCA.HEADER, target, false);
}

fn buildGet(gpa: std.mem.Allocator, family_id: u16, seq: u32, cmd: u8, hdr_attr: u16, target: header.Target, stats: bool) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = cmd, .seq = seq });
    try header.append(gpa, &msg, hdr_attr, .{ .target = target, .stats = stats });
    return header.finishRequest(gpa, &msg, h);
}

pub fn buildSetPlca(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: header.Target, set: PlcaSet) BuildError![]u8 {
    if (set.node_id) |v| if (v > 255) return error.InvalidRequest;
    if (set.node_cnt) |v| if (v == 0 or v > 255) return error.InvalidRequest;
    if (set.burst_cnt) |v| if (v > 255) return error.InvalidRequest;
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.PLCA_SET_CFG, .seq = seq });
    try header.append(gpa, &msg, uapi.PLCA.HEADER, .{ .target = target });
    if (set.enabled) |v| try codec.appendAttrU8(gpa, &msg, uapi.PLCA.ENABLED, @intFromBool(v));
    if (set.node_id) |v| try codec.appendAttrU32(gpa, &msg, uapi.PLCA.NODE_ID, v);
    if (set.node_cnt) |v| try codec.appendAttrU32(gpa, &msg, uapi.PLCA.NODE_CNT, v);
    if (set.to_timer) |v| try codec.appendAttrU32(gpa, &msg, uapi.PLCA.TO_TMR, v);
    if (set.burst_cnt) |v| try codec.appendAttrU32(gpa, &msg, uapi.PLCA.BURST_CNT, v);
    if (set.burst_timer) |v| try codec.appendAttrU32(gpa, &msg, uapi.PLCA.BURST_TMR, v);
    return header.finishRequest(gpa, &msg, h);
}

// ── MAC merge ──────────────────────────────────────────────────────────────

/// `enum ethtool_mm_verify_status`.
pub const MmVerifyStatus = enum(u8) {
    unknown = 0,
    initial = 1,
    verifying = 2,
    succeeded = 3,
    failed = 4,
    disabled = 5,
    _,
};

/// The `ETHTOOL_A_MM_STATS` nest: counters of the merge layer.
pub const MmStats = struct {
    reassembly_errors: ?u64 = null,
    smd_errors: ?u64 = null,
    reassembly_ok: ?u64 = null,
    rx_frag_count: ?u64 = null,
    tx_frag_count: ?u64 = null,
    hold_count: ?u64 = null,
};

/// `ETHTOOL_MSG_MM_GET` reply.
pub const Mm = struct {
    device: header.Device = .{},
    /// The preemptable MAC is enabled.
    pmac_enabled: ?bool = null,
    /// Preemption is enabled for transmission.
    tx_enabled: ?bool = null,
    /// Preemption is active (the verification, if any, succeeded).
    tx_active: ?bool = null,
    /// The smallest fragment this side sends, and the smallest the peer must accept, in bytes.
    tx_min_frag_size: ?u32 = null,
    rx_min_frag_size: ?u32 = null,
    verify_enabled: ?bool = null,
    verify_status: ?MmVerifyStatus = null,
    /// Milliseconds between verification attempts, and the most the driver supports.
    verify_time: ?u32 = null,
    max_verify_time: ?u32 = null,
    /// Present when the request asked for statistics (`mmStats`) and the driver keeps them.
    stats: ?MmStats = null,
};

fn parseMmStats(nest_bytes: []const u8) codec.Error!MmStats {
    var out: MmStats = .{};
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.MM_STAT.REASSEMBLY_ERRORS => out.reassembly_errors = try asU64(a),
        uapi.MM_STAT.SMD_ERRORS => out.smd_errors = try asU64(a),
        uapi.MM_STAT.REASSEMBLY_OK => out.reassembly_ok = try asU64(a),
        uapi.MM_STAT.RX_FRAG_COUNT => out.rx_frag_count = try asU64(a),
        uapi.MM_STAT.TX_FRAG_COUNT => out.tx_frag_count = try asU64(a),
        uapi.MM_STAT.HOLD_COUNT => out.hold_count = try asU64(a),
        else => {},
    };
    return out;
}

fn asU64(a: codec.Attr) codec.Error!u64 {
    if (a.data.len != 8) return error.BadLength;
    return std.mem.readInt(u64, a.data[0..8], @import("builtin").cpu.arch.endian());
}

pub fn parseMm(attr_bytes: []const u8) codec.Error!Mm {
    var out: Mm = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.MM.HEADER => out.device = try header.parse(a.data),
        uapi.MM.PMAC_ENABLED => out.pmac_enabled = (try a.asU8()) != 0,
        uapi.MM.TX_ENABLED => out.tx_enabled = (try a.asU8()) != 0,
        uapi.MM.TX_ACTIVE => out.tx_active = (try a.asU8()) != 0,
        uapi.MM.TX_MIN_FRAG_SIZE => out.tx_min_frag_size = try a.asU32(),
        uapi.MM.RX_MIN_FRAG_SIZE => out.rx_min_frag_size = try a.asU32(),
        uapi.MM.VERIFY_ENABLED => out.verify_enabled = (try a.asU8()) != 0,
        uapi.MM.VERIFY_STATUS => out.verify_status = @fromBackingInt(@intCast(try a.asU8())),
        uapi.MM.VERIFY_TIME => out.verify_time = try a.asU32(),
        uapi.MM.MAX_VERIFY_TIME => out.max_verify_time = try a.asU32(),
        uapi.MM.STATS => out.stats = try parseMmStats(a.data),
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_MM_SET` parameters. The verification time is 1..128 ms (the kernel's policy).
pub const MmSet = struct {
    verify_enabled: ?bool = null,
    verify_time: ?u32 = null,
    tx_enabled: ?bool = null,
    pmac_enabled: ?bool = null,
    tx_min_frag_size: ?u32 = null,
};

pub fn buildMm(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: header.Target, stats: bool) header.Error![]u8 {
    return buildGet(gpa, family_id, seq, uapi.MSG.MM_GET, uapi.MM.HEADER, target, stats);
}

pub fn buildSetMm(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: header.Target, set: MmSet) BuildError![]u8 {
    if (set.verify_time) |v| if (v < 1 or v > 128) return error.InvalidRequest;
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.MM_SET, .seq = seq });
    try header.append(gpa, &msg, uapi.MM.HEADER, .{ .target = target });
    if (set.verify_enabled) |v| try codec.appendAttrU8(gpa, &msg, uapi.MM.VERIFY_ENABLED, @intFromBool(v));
    if (set.verify_time) |v| try codec.appendAttrU32(gpa, &msg, uapi.MM.VERIFY_TIME, v);
    if (set.tx_enabled) |v| try codec.appendAttrU8(gpa, &msg, uapi.MM.TX_ENABLED, @intFromBool(v));
    if (set.pmac_enabled) |v| try codec.appendAttrU8(gpa, &msg, uapi.MM.PMAC_ENABLED, @intFromBool(v));
    if (set.tx_min_frag_size) |v| try codec.appendAttrU32(gpa, &msg, uapi.MM.TX_MIN_FRAG_SIZE, v);
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

fn u64Attr(gpa: std.mem.Allocator, list: *std.ArrayList(u8), t: u16, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, native_endian);
    try codec.appendAttr(gpa, list, t, &b);
}

test "PLCA: config and status decode, and a set sends only what is set, within the kernel's bounds" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try header.append(gpa, &l, uapi.PLCA.HEADER, .{ .target = .byName("eth1") });
    try codec.appendAttrU16(gpa, &l, uapi.PLCA.VERSION, 0xa10);
    try codec.appendAttrU8(gpa, &l, uapi.PLCA.ENABLED, 1);
    try codec.appendAttrU32(gpa, &l, uapi.PLCA.NODE_CNT, 8);
    try codec.appendAttrU32(gpa, &l, uapi.PLCA.NODE_ID, 0);
    try codec.appendAttrU32(gpa, &l, uapi.PLCA.TO_TMR, 32);
    try codec.appendAttrU32(gpa, &l, uapi.PLCA.BURST_CNT, 2);
    try codec.appendAttrU32(gpa, &l, uapi.PLCA.BURST_TMR, 128);
    const c = try parsePlcaCfg(l.items);
    try testing.expectEqualStrings("eth1", c.device.name());
    try testing.expectEqual(@as(?u16, 0xa10), c.version);
    try testing.expectEqual(@as(?bool, true), c.enabled);
    try testing.expectEqual(@as(?u32, 8), c.node_cnt);
    try testing.expectEqual(@as(?u32, 0), c.node_id);
    try testing.expectEqual(@as(?u32, 32), c.to_timer);
    try testing.expectEqual(@as(?u32, 2), c.burst_cnt);
    try testing.expectEqual(@as(?u32, 128), c.burst_timer);
    var wrong: std.ArrayList(u8) = .empty;
    defer wrong.deinit(gpa);
    try codec.appendAttr(gpa, &wrong, uapi.PLCA.VERSION, &.{ 1, 2, 3 });
    try testing.expectError(error.BadLength, parsePlcaCfg(wrong.items));

    var st: std.ArrayList(u8) = .empty;
    defer st.deinit(gpa);
    try codec.appendAttrU8(gpa, &st, uapi.PLCA.STATUS, 1);
    try testing.expectEqual(@as(?bool, true), (try parsePlcaStatus(st.items)).status);

    const msg = try buildSetPlca(gpa, 23, 1, .byIndex(3), .{ .enabled = true, .node_id = 2, .node_cnt = 4 });
    defer gpa.free(msg);
    try testing.expectEqual(uapi.MSG.PLCA_SET_CFG, msg[16]);
    const back = try parsePlcaCfg(msg[20..]);
    try testing.expectEqual(@as(?bool, true), back.enabled);
    try testing.expectEqual(@as(?u32, 2), back.node_id);
    try testing.expectEqual(@as(?u32, 4), back.node_cnt);
    try testing.expectEqual(@as(?u32, null), back.to_timer);
    try testing.expectError(error.InvalidRequest, buildSetPlca(gpa, 23, 1, .byIndex(3), .{ .node_id = 256 }));
    try testing.expectError(error.InvalidRequest, buildSetPlca(gpa, 23, 1, .byIndex(3), .{ .node_cnt = 0 }));
    try testing.expectError(error.InvalidRequest, buildSetPlca(gpa, 23, 1, .byIndex(3), .{ .burst_cnt = 256 }));
    const get = try buildPlcaStatus(gpa, 23, 2, .byName("eth1"));
    defer gpa.free(get);
    try testing.expectEqual(uapi.MSG.PLCA_GET_STATUS, get[16]);
}

test "MM: a reply with statistics decodes, the request asks for them, a set stays within 1..128 ms" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var stats: std.ArrayList(u8) = .empty;
    defer stats.deinit(gpa);
    try u64Attr(gpa, &stats, uapi.MM_STAT.REASSEMBLY_ERRORS, 1);
    try u64Attr(gpa, &stats, uapi.MM_STAT.SMD_ERRORS, 2);
    try u64Attr(gpa, &stats, uapi.MM_STAT.REASSEMBLY_OK, 3);
    try u64Attr(gpa, &stats, uapi.MM_STAT.RX_FRAG_COUNT, 4);
    try u64Attr(gpa, &stats, uapi.MM_STAT.TX_FRAG_COUNT, 5);
    try u64Attr(gpa, &stats, uapi.MM_STAT.HOLD_COUNT, 6);
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try codec.appendAttrU8(gpa, &l, uapi.MM.PMAC_ENABLED, 1);
    try codec.appendAttrU8(gpa, &l, uapi.MM.TX_ENABLED, 1);
    try codec.appendAttrU8(gpa, &l, uapi.MM.TX_ACTIVE, 0);
    try codec.appendAttrU32(gpa, &l, uapi.MM.TX_MIN_FRAG_SIZE, 60);
    try codec.appendAttrU32(gpa, &l, uapi.MM.RX_MIN_FRAG_SIZE, 124);
    try codec.appendAttrU8(gpa, &l, uapi.MM.VERIFY_ENABLED, 1);
    try codec.appendAttrU8(gpa, &l, uapi.MM.VERIFY_STATUS, 3);
    try codec.appendAttrU32(gpa, &l, uapi.MM.VERIFY_TIME, 10);
    try codec.appendAttrU32(gpa, &l, uapi.MM.MAX_VERIFY_TIME, 128);
    try codec.appendAttr(gpa, &l, uapi.MM.STATS, stats.items);
    const m = try parseMm(l.items);
    try testing.expectEqual(@as(?bool, true), m.pmac_enabled);
    try testing.expectEqual(@as(?bool, false), m.tx_active);
    try testing.expectEqual(@as(?u32, 124), m.rx_min_frag_size);
    try testing.expectEqual(@as(?MmVerifyStatus, .succeeded), m.verify_status);
    try testing.expectEqual(@as(?u32, 128), m.max_verify_time);
    try testing.expectEqual(@as(?u64, 6), m.stats.?.hold_count);
    try testing.expectEqual(@as(?u64, 1), m.stats.?.reassembly_errors);
    try testing.expectEqual(@as(?u64, 5), m.stats.?.tx_frag_count);
    const none = try parseMm(&.{});
    try testing.expect(none.stats == null);
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try codec.appendAttr(gpa, &bad, uapi.MM.STATS, &.{ 0x06, 0x00, uapi.MM_STAT.SMD_ERRORS, 0x00, 1, 2, 0, 0 });
    try testing.expectError(error.BadLength, parseMm(bad.items));

    const get = try buildMm(gpa, 23, 1, .byIndex(2), true);
    defer gpa.free(get);
    var it: codec.AttrIterator = .{ .buf = get[20..] };
    var ht = (try it.next()).?.nested();
    var flags: u32 = 0;
    while (try ht.next()) |a| if (a.type == uapi.HEADER.FLAGS) {
        flags = try a.asU32();
    };
    try testing.expectEqual(uapi.FLAG.STATS, flags);

    const set = try buildSetMm(gpa, 23, 2, .byName("eth0"), .{ .verify_enabled = true, .verify_time = 20, .tx_enabled = true });
    defer gpa.free(set);
    try testing.expectEqual(uapi.MSG.MM_SET, set[16]);
    const sm = try parseMm(set[20..]);
    try testing.expectEqual(@as(?u32, 20), sm.verify_time);
    try testing.expectEqual(@as(?bool, true), sm.verify_enabled);
    try testing.expectEqual(@as(?bool, null), sm.pmac_enabled);
    try testing.expectError(error.InvalidRequest, buildSetMm(gpa, 23, 2, .byName("eth0"), .{ .verify_time = 0 }));
    try testing.expectError(error.InvalidRequest, buildSetMm(gpa, 23, 2, .byName("eth0"), .{ .verify_time = 129 }));
}
