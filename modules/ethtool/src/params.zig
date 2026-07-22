// SPDX-License-Identifier: MIT
//! The four "device tuning parameter" message pairs, which share one shape:
//! `RINGS`, `COALESCE`, `PAUSE` and `CHANNELS`.
//!
//! Every field is optional in both directions, and that is load-bearing:
//!
//! * **In a reply**, an absent attribute means "this driver does not implement
//!   this knob" — not zero. `ethtool -g` prints `n/a` for exactly those. So
//!   every field here is an optional, and nothing is defaulted.
//! * **In a request**, an absent attribute means "leave it alone". A SET
//!   carries only what the caller wants changed; the kernel merges it with the
//!   current values. That is why the `*Set` structs are all-optional too, and
//!   why sending an empty one is a legal no-op rather than a wipe.
//!
//! `PAUSE` additionally has an optional statistics nest which the driver only
//! attaches when the request set `ETHTOOL_FLAG_STATS`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");

// ── RINGS ──────────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_RINGS_GET` reply. `*_max` are the hardware ceilings, the rest
/// are the current settings.
pub const Rings = struct {
    device: header.Device = .{},
    rx_max: ?u32 = null,
    rx_mini_max: ?u32 = null,
    rx_jumbo_max: ?u32 = null,
    tx_max: ?u32 = null,
    rx: ?u32 = null,
    rx_mini: ?u32 = null,
    rx_jumbo: ?u32 = null,
    tx: ?u32 = null,
    rx_buf_len: ?u32 = null,
    tcp_data_split: ?uapi.TcpDataSplit = null,
    cqe_size: ?u32 = null,
    tx_push: ?bool = null,
    rx_push: ?bool = null,
    tx_push_buf_len: ?u32 = null,
    tx_push_buf_len_max: ?u32 = null,
    hds_thresh: ?u32 = null,
    hds_thresh_max: ?u32 = null,
};

pub fn parseRings(attr_bytes: []const u8) codec.Error!Rings {
    var out: Rings = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.RINGS.HEADER => out.device = try header.parse(a.data),
        uapi.RINGS.RX_MAX => out.rx_max = try a.asU32(),
        uapi.RINGS.RX_MINI_MAX => out.rx_mini_max = try a.asU32(),
        uapi.RINGS.RX_JUMBO_MAX => out.rx_jumbo_max = try a.asU32(),
        uapi.RINGS.TX_MAX => out.tx_max = try a.asU32(),
        uapi.RINGS.RX => out.rx = try a.asU32(),
        uapi.RINGS.RX_MINI => out.rx_mini = try a.asU32(),
        uapi.RINGS.RX_JUMBO => out.rx_jumbo = try a.asU32(),
        uapi.RINGS.TX => out.tx = try a.asU32(),
        uapi.RINGS.RX_BUF_LEN => out.rx_buf_len = try a.asU32(),
        uapi.RINGS.TCP_DATA_SPLIT => out.tcp_data_split = @enumFromInt(try a.asU8()),
        uapi.RINGS.CQE_SIZE => out.cqe_size = try a.asU32(),
        uapi.RINGS.TX_PUSH => out.tx_push = (try a.asU8()) != 0,
        uapi.RINGS.RX_PUSH => out.rx_push = (try a.asU8()) != 0,
        uapi.RINGS.TX_PUSH_BUF_LEN => out.tx_push_buf_len = try a.asU32(),
        uapi.RINGS.TX_PUSH_BUF_LEN_MAX => out.tx_push_buf_len_max = try a.asU32(),
        uapi.RINGS.HDS_THRESH => out.hds_thresh = try a.asU32(),
        uapi.RINGS.HDS_THRESH_MAX => out.hds_thresh_max = try a.asU32(),
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_RINGS_SET` parameters — every field optional, absent = unchanged.
pub const RingsSet = struct {
    rx: ?u32 = null,
    rx_mini: ?u32 = null,
    rx_jumbo: ?u32 = null,
    tx: ?u32 = null,
    rx_buf_len: ?u32 = null,
    tcp_data_split: ?uapi.TcpDataSplit = null,
    cqe_size: ?u32 = null,
    tx_push: ?bool = null,
    rx_push: ?bool = null,
    tx_push_buf_len: ?u32 = null,
    hds_thresh: ?u32 = null,

    pub fn isEmpty(s: RingsSet) bool {
        return std.meta.eql(s, RingsSet{});
    }
};

pub fn appendRingsSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    set: RingsSet,
) std.mem.Allocator.Error!void {
    if (set.rx) |v| try codec.appendAttrU32(gpa, list, uapi.RINGS.RX, v);
    if (set.rx_mini) |v| try codec.appendAttrU32(gpa, list, uapi.RINGS.RX_MINI, v);
    if (set.rx_jumbo) |v| try codec.appendAttrU32(gpa, list, uapi.RINGS.RX_JUMBO, v);
    if (set.tx) |v| try codec.appendAttrU32(gpa, list, uapi.RINGS.TX, v);
    if (set.rx_buf_len) |v| try codec.appendAttrU32(gpa, list, uapi.RINGS.RX_BUF_LEN, v);
    if (set.tcp_data_split) |v|
        try codec.appendAttrU8(gpa, list, uapi.RINGS.TCP_DATA_SPLIT, @intFromEnum(v));
    if (set.cqe_size) |v| try codec.appendAttrU32(gpa, list, uapi.RINGS.CQE_SIZE, v);
    if (set.tx_push) |v| try codec.appendAttrU8(gpa, list, uapi.RINGS.TX_PUSH, @intFromBool(v));
    if (set.rx_push) |v| try codec.appendAttrU8(gpa, list, uapi.RINGS.RX_PUSH, @intFromBool(v));
    if (set.tx_push_buf_len) |v| try codec.appendAttrU32(gpa, list, uapi.RINGS.TX_PUSH_BUF_LEN, v);
    if (set.hds_thresh) |v| try codec.appendAttrU32(gpa, list, uapi.RINGS.HDS_THRESH, v);
}

// ── CHANNELS ───────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_CHANNELS_GET` reply.
pub const Channels = struct {
    device: header.Device = .{},
    rx_max: ?u32 = null,
    tx_max: ?u32 = null,
    other_max: ?u32 = null,
    combined_max: ?u32 = null,
    rx_count: ?u32 = null,
    tx_count: ?u32 = null,
    other_count: ?u32 = null,
    combined_count: ?u32 = null,
};

pub fn parseChannels(attr_bytes: []const u8) codec.Error!Channels {
    var out: Channels = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.CHANNELS.HEADER => out.device = try header.parse(a.data),
        uapi.CHANNELS.RX_MAX => out.rx_max = try a.asU32(),
        uapi.CHANNELS.TX_MAX => out.tx_max = try a.asU32(),
        uapi.CHANNELS.OTHER_MAX => out.other_max = try a.asU32(),
        uapi.CHANNELS.COMBINED_MAX => out.combined_max = try a.asU32(),
        uapi.CHANNELS.RX_COUNT => out.rx_count = try a.asU32(),
        uapi.CHANNELS.TX_COUNT => out.tx_count = try a.asU32(),
        uapi.CHANNELS.OTHER_COUNT => out.other_count = try a.asU32(),
        uapi.CHANNELS.COMBINED_COUNT => out.combined_count = try a.asU32(),
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_CHANNELS_SET` parameters.
pub const ChannelsSet = struct {
    rx_count: ?u32 = null,
    tx_count: ?u32 = null,
    other_count: ?u32 = null,
    combined_count: ?u32 = null,

    pub fn isEmpty(s: ChannelsSet) bool {
        return std.meta.eql(s, ChannelsSet{});
    }
};

pub fn appendChannelsSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    set: ChannelsSet,
) std.mem.Allocator.Error!void {
    if (set.rx_count) |v| try codec.appendAttrU32(gpa, list, uapi.CHANNELS.RX_COUNT, v);
    if (set.tx_count) |v| try codec.appendAttrU32(gpa, list, uapi.CHANNELS.TX_COUNT, v);
    if (set.other_count) |v| try codec.appendAttrU32(gpa, list, uapi.CHANNELS.OTHER_COUNT, v);
    if (set.combined_count) |v| try codec.appendAttrU32(gpa, list, uapi.CHANNELS.COMBINED_COUNT, v);
}

// ── COALESCE ───────────────────────────────────────────────────────────────

/// `ETHTOOL_MSG_COALESCE_GET` reply. The kernel only sends the knobs the
/// driver declared support for, so a mostly-null `Coalesce` is normal.
pub const Coalesce = struct {
    device: header.Device = .{},
    rx_usecs: ?u32 = null,
    rx_max_frames: ?u32 = null,
    rx_usecs_irq: ?u32 = null,
    rx_max_frames_irq: ?u32 = null,
    tx_usecs: ?u32 = null,
    tx_max_frames: ?u32 = null,
    tx_usecs_irq: ?u32 = null,
    tx_max_frames_irq: ?u32 = null,
    stats_block_usecs: ?u32 = null,
    use_adaptive_rx: ?bool = null,
    use_adaptive_tx: ?bool = null,
    pkt_rate_low: ?u32 = null,
    rx_usecs_low: ?u32 = null,
    rx_max_frames_low: ?u32 = null,
    tx_usecs_low: ?u32 = null,
    tx_max_frames_low: ?u32 = null,
    pkt_rate_high: ?u32 = null,
    rx_usecs_high: ?u32 = null,
    rx_max_frames_high: ?u32 = null,
    tx_usecs_high: ?u32 = null,
    tx_max_frames_high: ?u32 = null,
    rate_sample_interval: ?u32 = null,
    use_cqe_mode_tx: ?bool = null,
    use_cqe_mode_rx: ?bool = null,
    tx_aggr_max_bytes: ?u32 = null,
    tx_aggr_max_frames: ?u32 = null,
    tx_aggr_time_usecs: ?u32 = null,
};

pub fn parseCoalesce(attr_bytes: []const u8) codec.Error!Coalesce {
    var out: Coalesce = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.COALESCE.HEADER => out.device = try header.parse(a.data),
        uapi.COALESCE.RX_USECS => out.rx_usecs = try a.asU32(),
        uapi.COALESCE.RX_MAX_FRAMES => out.rx_max_frames = try a.asU32(),
        uapi.COALESCE.RX_USECS_IRQ => out.rx_usecs_irq = try a.asU32(),
        uapi.COALESCE.RX_MAX_FRAMES_IRQ => out.rx_max_frames_irq = try a.asU32(),
        uapi.COALESCE.TX_USECS => out.tx_usecs = try a.asU32(),
        uapi.COALESCE.TX_MAX_FRAMES => out.tx_max_frames = try a.asU32(),
        uapi.COALESCE.TX_USECS_IRQ => out.tx_usecs_irq = try a.asU32(),
        uapi.COALESCE.TX_MAX_FRAMES_IRQ => out.tx_max_frames_irq = try a.asU32(),
        uapi.COALESCE.STATS_BLOCK_USECS => out.stats_block_usecs = try a.asU32(),
        uapi.COALESCE.USE_ADAPTIVE_RX => out.use_adaptive_rx = (try a.asU8()) != 0,
        uapi.COALESCE.USE_ADAPTIVE_TX => out.use_adaptive_tx = (try a.asU8()) != 0,
        uapi.COALESCE.PKT_RATE_LOW => out.pkt_rate_low = try a.asU32(),
        uapi.COALESCE.RX_USECS_LOW => out.rx_usecs_low = try a.asU32(),
        uapi.COALESCE.RX_MAX_FRAMES_LOW => out.rx_max_frames_low = try a.asU32(),
        uapi.COALESCE.TX_USECS_LOW => out.tx_usecs_low = try a.asU32(),
        uapi.COALESCE.TX_MAX_FRAMES_LOW => out.tx_max_frames_low = try a.asU32(),
        uapi.COALESCE.PKT_RATE_HIGH => out.pkt_rate_high = try a.asU32(),
        uapi.COALESCE.RX_USECS_HIGH => out.rx_usecs_high = try a.asU32(),
        uapi.COALESCE.RX_MAX_FRAMES_HIGH => out.rx_max_frames_high = try a.asU32(),
        uapi.COALESCE.TX_USECS_HIGH => out.tx_usecs_high = try a.asU32(),
        uapi.COALESCE.TX_MAX_FRAMES_HIGH => out.tx_max_frames_high = try a.asU32(),
        uapi.COALESCE.RATE_SAMPLE_INTERVAL => out.rate_sample_interval = try a.asU32(),
        uapi.COALESCE.USE_CQE_MODE_TX => out.use_cqe_mode_tx = (try a.asU8()) != 0,
        uapi.COALESCE.USE_CQE_MODE_RX => out.use_cqe_mode_rx = (try a.asU8()) != 0,
        uapi.COALESCE.TX_AGGR_MAX_BYTES => out.tx_aggr_max_bytes = try a.asU32(),
        uapi.COALESCE.TX_AGGR_MAX_FRAMES => out.tx_aggr_max_frames = try a.asU32(),
        uapi.COALESCE.TX_AGGR_TIME_USECS => out.tx_aggr_time_usecs = try a.asU32(),
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_COALESCE_SET` parameters. Only the knobs a caller realistically
/// tunes are modelled; the rest of the 28-attribute space is reachable through
/// `Ethtool.raw`.
pub const CoalesceSet = struct {
    rx_usecs: ?u32 = null,
    rx_max_frames: ?u32 = null,
    tx_usecs: ?u32 = null,
    tx_max_frames: ?u32 = null,
    rx_usecs_irq: ?u32 = null,
    tx_usecs_irq: ?u32 = null,
    stats_block_usecs: ?u32 = null,
    use_adaptive_rx: ?bool = null,
    use_adaptive_tx: ?bool = null,
    use_cqe_mode_rx: ?bool = null,
    use_cqe_mode_tx: ?bool = null,

    pub fn isEmpty(s: CoalesceSet) bool {
        return std.meta.eql(s, CoalesceSet{});
    }
};

pub fn appendCoalesceSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    set: CoalesceSet,
) std.mem.Allocator.Error!void {
    if (set.rx_usecs) |v| try codec.appendAttrU32(gpa, list, uapi.COALESCE.RX_USECS, v);
    if (set.rx_max_frames) |v| try codec.appendAttrU32(gpa, list, uapi.COALESCE.RX_MAX_FRAMES, v);
    if (set.rx_usecs_irq) |v| try codec.appendAttrU32(gpa, list, uapi.COALESCE.RX_USECS_IRQ, v);
    if (set.tx_usecs) |v| try codec.appendAttrU32(gpa, list, uapi.COALESCE.TX_USECS, v);
    if (set.tx_max_frames) |v| try codec.appendAttrU32(gpa, list, uapi.COALESCE.TX_MAX_FRAMES, v);
    if (set.tx_usecs_irq) |v| try codec.appendAttrU32(gpa, list, uapi.COALESCE.TX_USECS_IRQ, v);
    if (set.stats_block_usecs) |v| try codec.appendAttrU32(gpa, list, uapi.COALESCE.STATS_BLOCK_USECS, v);
    if (set.use_adaptive_rx) |v|
        try codec.appendAttrU8(gpa, list, uapi.COALESCE.USE_ADAPTIVE_RX, @intFromBool(v));
    if (set.use_adaptive_tx) |v|
        try codec.appendAttrU8(gpa, list, uapi.COALESCE.USE_ADAPTIVE_TX, @intFromBool(v));
    if (set.use_cqe_mode_rx) |v|
        try codec.appendAttrU8(gpa, list, uapi.COALESCE.USE_CQE_MODE_RX, @intFromBool(v));
    if (set.use_cqe_mode_tx) |v|
        try codec.appendAttrU8(gpa, list, uapi.COALESCE.USE_CQE_MODE_TX, @intFromBool(v));
}

// ── PAUSE ──────────────────────────────────────────────────────────────────

/// The optional `ETHTOOL_A_PAUSE_STATS` nest — only present when the request
/// asked with `ETHTOOL_FLAG_STATS` *and* the driver implements it.
pub const PauseStats = struct {
    tx_frames: ?u64 = null,
    rx_frames: ?u64 = null,
};

/// `ETHTOOL_MSG_PAUSE_GET` reply.
pub const Pause = struct {
    device: header.Device = .{},
    /// Pause-frame capability is being auto-negotiated.
    autoneg: ?bool = null,
    /// Honour incoming pause frames.
    rx: ?bool = null,
    /// Emit pause frames.
    tx: ?bool = null,
    stats: ?PauseStats = null,
    stats_src: ?uapi.StatsSrc = null,
};

pub fn parsePause(attr_bytes: []const u8) codec.Error!Pause {
    var out: Pause = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.PAUSE.HEADER => out.device = try header.parse(a.data),
        uapi.PAUSE.AUTONEG => out.autoneg = (try a.asU8()) != 0,
        uapi.PAUSE.RX => out.rx = (try a.asU8()) != 0,
        uapi.PAUSE.TX => out.tx = (try a.asU8()) != 0,
        uapi.PAUSE.STATS_SRC => out.stats_src = @enumFromInt(try a.asU32()),
        uapi.PAUSE.STATS => {
            var s: PauseStats = .{};
            var inner: codec.AttrIterator = .{ .buf = a.data };
            while (try inner.next()) |x| switch (x.type) {
                uapi.PAUSE_STAT.TX_FRAMES => s.tx_frames = try readU64(x),
                uapi.PAUSE_STAT.RX_FRAMES => s.rx_frames = try readU64(x),
                else => {},
            };
            out.stats = s;
        },
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_PAUSE_SET` parameters.
pub const PauseSet = struct {
    autoneg: ?bool = null,
    rx: ?bool = null,
    tx: ?bool = null,

    pub fn isEmpty(s: PauseSet) bool {
        return std.meta.eql(s, PauseSet{});
    }
};

pub fn appendPauseSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    set: PauseSet,
) std.mem.Allocator.Error!void {
    if (set.autoneg) |v| try codec.appendAttrU8(gpa, list, uapi.PAUSE.AUTONEG, @intFromBool(v));
    if (set.rx) |v| try codec.appendAttrU8(gpa, list, uapi.PAUSE.RX, @intFromBool(v));
    if (set.tx) |v| try codec.appendAttrU8(gpa, list, uapi.PAUSE.TX, @intFromBool(v));
}

/// Statistics counters in this family are u64 and the kernel pads them to an
/// 8-byte boundary with a dedicated `*_PAD` attribute, so the payload is always
/// exactly 8 bytes; anything else is a malformed reply.
pub fn readU64(a: codec.Attr) codec.Error!u64 {
    if (a.data.len != 8) return error.BadLength;
    return std.mem.readInt(u64, a.data[0..8], native_endian);
}

const native_endian = @import("builtin").cpu.arch.endian();

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "RINGS: absent attributes stay null (n/a), they do not become zero" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.RINGS.HEADER, .{ .target = .byIndex(2) });
    try codec.appendAttrU32(gpa, &list, uapi.RINGS.RX_MAX, 4096);
    try codec.appendAttrU32(gpa, &list, uapi.RINGS.RX, 256);
    try codec.appendAttrU8(gpa, &list, uapi.RINGS.TX_PUSH, 0);

    const r = try parseRings(list.items);
    try testing.expectEqual(@as(?u32, 4096), r.rx_max);
    try testing.expectEqual(@as(?u32, 256), r.rx);
    try testing.expectEqual(@as(?bool, false), r.tx_push);
    try testing.expect(r.rx_mini_max == null); // "n/a", not 0
    try testing.expect(r.tx == null);
}

test "RINGS_SET encodes only the fields that were set" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expect((RingsSet{}).isEmpty());
    try appendRingsSet(gpa, &list, .{});
    try testing.expectEqual(@as(usize, 0), list.items.len);

    try appendRingsSet(gpa, &list, .{ .rx = 512 });
    try testing.expect(!(RingsSet{ .rx = 512 }).isEmpty());
    var it: codec.AttrIterator = .{ .buf = list.items };
    const a = (try it.next()).?;
    try testing.expectEqual(uapi.RINGS.RX, a.type);
    try testing.expectEqual(@as(u32, 512), try a.asU32());
    try testing.expect((try it.next()) == null);
}

test "CHANNELS round-trips through its own encoder" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendChannelsSet(gpa, &list, .{ .combined_count = 4, .rx_count = 1 });
    const c = try parseChannels(list.items);
    try testing.expectEqual(@as(?u32, 4), c.combined_count);
    try testing.expectEqual(@as(?u32, 1), c.rx_count);
    try testing.expect(c.tx_count == null);
}

test "COALESCE decodes u32 knobs and u8 booleans" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendCoalesceSet(gpa, &list, .{
        .rx_usecs = 3,
        .tx_max_frames = 16,
        .use_adaptive_rx = true,
        .use_cqe_mode_tx = false,
    });
    const c = try parseCoalesce(list.items);
    try testing.expectEqual(@as(?u32, 3), c.rx_usecs);
    try testing.expectEqual(@as(?u32, 16), c.tx_max_frames);
    try testing.expectEqual(@as(?bool, true), c.use_adaptive_rx);
    try testing.expectEqual(@as(?bool, false), c.use_cqe_mode_tx);
    try testing.expect(c.rx_usecs_high == null);
}

test "PAUSE decodes the optional statistics nest" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendPauseSet(gpa, &list, .{ .autoneg = true, .rx = true, .tx = false });
    try codec.appendAttrU32(gpa, &list, uapi.PAUSE.STATS_SRC, @intFromEnum(uapi.StatsSrc.pmac));
    const nest = try codec.nestBegin(gpa, &list, uapi.PAUSE.STATS);
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, 42, native_endian);
    try codec.appendAttr(gpa, &list, uapi.PAUSE_STAT.TX_FRAMES, &raw);
    codec.nestEnd(&list, nest);

    const p = try parsePause(list.items);
    try testing.expectEqual(@as(?bool, true), p.autoneg);
    try testing.expectEqual(@as(?bool, false), p.tx);
    try testing.expectEqual(uapi.StatsSrc.pmac, p.stats_src.?);
    try testing.expectEqual(@as(?u64, 42), p.stats.?.tx_frames);
    try testing.expect(p.stats.?.rx_frames == null);
}

test "PAUSE without ETHTOOL_FLAG_STATS has no statistics nest at all" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendPauseSet(gpa, &list, .{ .autoneg = true });
    const p = try parsePause(list.items);
    try testing.expect(p.stats == null); // not an empty struct — absent
}

test "malformed parameter replies are typed errors, never a panic" {
    // A u32 field carrying one byte.
    try testing.expectError(error.BadLength, parseRings(&.{ 0x05, 0x00, 0x02, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.BadLength, parseChannels(&.{ 0x05, 0x00, 0x02, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.BadLength, parseCoalesce(&.{ 0x05, 0x00, 0x02, 0x00, 1, 0, 0, 0 }));
    // A u8 field carrying four.
    try testing.expectError(error.BadLength, parsePause(&.{ 0x08, 0x00, 0x02, 0x00, 1, 0, 0, 0 }));
    // A 4-byte "u64" counter.
    try testing.expectError(error.BadLength, parsePause(&.{
        0x0c, 0x00, 0x05, 0x80, // PAUSE_STATS nest
        0x08, 0x00, 0x02, 0x00, 1, 0, 0, 0, // TX_FRAMES, only 4 bytes
    }));
    // Truncated TLV.
    try testing.expectError(error.Truncated, parseRings(&.{ 0x40, 0x00, 0x02, 0x00 }));
}

test "fuzz: parameter decoders never crash" {
    try testing.fuzz({}, fuzzParams, .{});
}

fn fuzzParams(_: void, smith: *std.testing.Smith) !void {
    var raw: [256]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const buf = raw[0..len];
    if (parseRings(buf)) |v| std.mem.doNotOptimizeAway(&v) else |_| {}
    if (parseChannels(buf)) |v| std.mem.doNotOptimizeAway(&v) else |_| {}
    if (parseCoalesce(buf)) |v| std.mem.doNotOptimizeAway(&v) else |_| {}
    if (parsePause(buf)) |v| std.mem.doNotOptimizeAway(&v) else |_| {}
}
