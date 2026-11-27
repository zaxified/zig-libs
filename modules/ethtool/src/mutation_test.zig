// SPDX-License-Identifier: MIT
//! Tests asked for by the 2026-11-27 whole-module mutation run. Every expected
//! value is derived from the kernel UAPI / the documented contract of the
//! function under test (attribute number <-> field of the same name, the
//! limits in the doc comments), never from what the code printed.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");
const link = @import("link.zig");
const params = @import("params.zig");
const features = @import("features.zig");
const stats = @import("stats.zig");
const moduleinfo = @import("moduleinfo.zig");
const eee_fec = @import("eee_fec.zig");
const wol = @import("wol.zig");
const privflags = @import("privflags.zig");
const debug = @import("debug.zig");
const plca_mm = @import("plca_mm.zig");
const phy_tunnel = @import("phy_tunnel.zig");
const tsinfo = @import("tsinfo.zig");
const rss = @import("rss.zig");

const testing = std.testing;
const m_gpa = testing.allocator;
const native_endian = @import("builtin").cpu.arch.endian();

// ── helpers ────────────────────────────────────────────────────────────────

fn attrAt(bytes: []const u8, t: u16) !?codec.Attr {
    var it: codec.AttrIterator = .{ .buf = bytes };
    while (try it.next()) |a| {
        if (a.type == t) return a;
    }
    return null;
}

fn expectU32Attr(bytes: []const u8, t: u16, v: u32) !void {
    const a = (try attrAt(bytes, t)) orelse return error.MissingAttribute;
    try testing.expectEqual(v, try a.asU32());
}

fn expectU8Attr(bytes: []const u8, t: u16, v: u8) !void {
    const a = (try attrAt(bytes, t)) orelse return error.MissingAttribute;
    try testing.expectEqual(v, try a.asU8());
}

fn expectNoAttr(bytes: []const u8, t: u16) !void {
    try testing.expect((try attrAt(bytes, t)) == null);
}

fn attrCount(bytes: []const u8) !usize {
    var it: codec.AttrIterator = .{ .buf = bytes };
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    return n;
}

fn u16Attr(list: *std.ArrayList(u8), t: u16, v: u16) !void {
    try codec.appendAttrU16(m_gpa, list, t, v);
}

fn u32Attr(list: *std.ArrayList(u8), t: u16, v: u32) !void {
    try codec.appendAttrU32(m_gpa, list, t, v);
}

fn u8Attr(list: *std.ArrayList(u8), t: u16, v: u8) !void {
    try codec.appendAttrU8(m_gpa, list, t, v);
}

fn u64Attr(list: *std.ArrayList(u8), t: u16, v: u64) !void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, v, native_endian);
    try codec.appendAttr(m_gpa, list, t, &raw);
}

/// A `*_HEADER` nest naming ifindex 7.
fn hdrNest(list: *std.ArrayList(u8), attr: u16) !void {
    try header.append(m_gpa, list, attr, .{ .target = .{ .index = 7 } });
}

/// The `STATS`/`FLAGS` word of a built request's header nest (null = absent).
fn requestFlags(msg: []const u8) !?u32 {
    const d = try attrAt(msg[20..], 1);
    const nest = d orelse return error.MissingHeader;
    const f = try attrAt(nest.data, uapi.HEADER.FLAGS);
    if (f) |a| return try a.asU32();
    return null;
}

// ── params: RINGS / CHANNELS / COALESCE / PAUSE ────────────────────────────

const rings_u32 = .{
    .{ "rx_max", uapi.RINGS.RX_MAX },
    .{ "rx_mini_max", uapi.RINGS.RX_MINI_MAX },
    .{ "rx_jumbo_max", uapi.RINGS.RX_JUMBO_MAX },
    .{ "tx_max", uapi.RINGS.TX_MAX },
    .{ "rx", uapi.RINGS.RX },
    .{ "rx_mini", uapi.RINGS.RX_MINI },
    .{ "rx_jumbo", uapi.RINGS.RX_JUMBO },
    .{ "tx", uapi.RINGS.TX },
    .{ "rx_buf_len", uapi.RINGS.RX_BUF_LEN },
    .{ "cqe_size", uapi.RINGS.CQE_SIZE },
    .{ "tx_push_buf_len", uapi.RINGS.TX_PUSH_BUF_LEN },
    .{ "tx_push_buf_len_max", uapi.RINGS.TX_PUSH_BUF_LEN_MAX },
    .{ "hds_thresh", uapi.RINGS.HDS_THRESH },
    .{ "hds_thresh_max", uapi.RINGS.HDS_THRESH_MAX },
};

test "mutation 2026-11-27: RINGS reply: every attribute lands in the field of its name" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try hdrNest(&list, uapi.RINGS.HEADER);
    inline for (rings_u32, 0..) |e, i| try u32Attr(&list, e[1], 1000 + @as(u32, i));
    try u8Attr(&list, uapi.RINGS.TCP_DATA_SPLIT, 2);
    try u8Attr(&list, uapi.RINGS.TX_PUSH, 1);
    try u8Attr(&list, uapi.RINGS.RX_PUSH, 0);
    const r = try params.parseRings(list.items);
    try testing.expectEqual(@as(?u32, 7), r.device.index);
    inline for (rings_u32, 0..) |e, i| {
        try testing.expectEqual(@as(?u32, 1000 + @as(u32, i)), @field(r, e[0]));
    }
    try testing.expectEqual(@as(?uapi.TcpDataSplit, .enabled), r.tcp_data_split);
    try testing.expectEqual(@as(?bool, true), r.tx_push);
    try testing.expectEqual(@as(?bool, false), r.rx_push);
}

test "mutation 2026-11-27: RINGS_SET: every field is encoded, nothing else is" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try params.appendRingsSet(m_gpa, &list, .{
        .rx = 11,
        .rx_mini = 12,
        .rx_jumbo = 13,
        .tx = 14,
        .rx_buf_len = 15,
        .tcp_data_split = .enabled,
        .cqe_size = 16,
        .tx_push = true,
        .rx_push = false,
        .tx_push_buf_len = 17,
        .hds_thresh = 18,
    });
    try expectU32Attr(list.items, uapi.RINGS.RX, 11);
    try expectU32Attr(list.items, uapi.RINGS.RX_MINI, 12);
    try expectU32Attr(list.items, uapi.RINGS.RX_JUMBO, 13);
    try expectU32Attr(list.items, uapi.RINGS.TX, 14);
    try expectU32Attr(list.items, uapi.RINGS.RX_BUF_LEN, 15);
    try expectU8Attr(list.items, uapi.RINGS.TCP_DATA_SPLIT, 2);
    try expectU32Attr(list.items, uapi.RINGS.CQE_SIZE, 16);
    try expectU8Attr(list.items, uapi.RINGS.TX_PUSH, 1);
    try expectU8Attr(list.items, uapi.RINGS.RX_PUSH, 0);
    try expectU32Attr(list.items, uapi.RINGS.TX_PUSH_BUF_LEN, 17);
    try expectU32Attr(list.items, uapi.RINGS.HDS_THRESH, 18);
    try testing.expectEqual(@as(usize, 11), try attrCount(list.items));
}

test "mutation 2026-11-27: CHANNELS reply and CHANNELS_SET: every field is its own attribute" {
    const names = .{
        .{ "rx_max", uapi.CHANNELS.RX_MAX },
        .{ "tx_max", uapi.CHANNELS.TX_MAX },
        .{ "other_max", uapi.CHANNELS.OTHER_MAX },
        .{ "combined_max", uapi.CHANNELS.COMBINED_MAX },
        .{ "rx_count", uapi.CHANNELS.RX_COUNT },
        .{ "tx_count", uapi.CHANNELS.TX_COUNT },
        .{ "other_count", uapi.CHANNELS.OTHER_COUNT },
        .{ "combined_count", uapi.CHANNELS.COMBINED_COUNT },
    };
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try hdrNest(&list, uapi.CHANNELS.HEADER);
    inline for (names, 0..) |e, i| try u32Attr(&list, e[1], 2000 + @as(u32, i));
    const c = try params.parseChannels(list.items);
    try testing.expectEqual(@as(?u32, 7), c.device.index);
    inline for (names, 0..) |e, i| {
        try testing.expectEqual(@as(?u32, 2000 + @as(u32, i)), @field(c, e[0]));
    }

    var set_bytes: std.ArrayList(u8) = .empty;
    defer set_bytes.deinit(m_gpa);
    try params.appendChannelsSet(m_gpa, &set_bytes, .{ .rx_count = 21, .tx_count = 22, .other_count = 23, .combined_count = 24 });
    try expectU32Attr(set_bytes.items, uapi.CHANNELS.RX_COUNT, 21);
    try expectU32Attr(set_bytes.items, uapi.CHANNELS.TX_COUNT, 22);
    try expectU32Attr(set_bytes.items, uapi.CHANNELS.OTHER_COUNT, 23);
    try expectU32Attr(set_bytes.items, uapi.CHANNELS.COMBINED_COUNT, 24);
    try testing.expectEqual(@as(usize, 4), try attrCount(set_bytes.items));
}

const coalesce_u32 = .{
    .{ "rx_usecs", uapi.COALESCE.RX_USECS },
    .{ "rx_max_frames", uapi.COALESCE.RX_MAX_FRAMES },
    .{ "rx_usecs_irq", uapi.COALESCE.RX_USECS_IRQ },
    .{ "rx_max_frames_irq", uapi.COALESCE.RX_MAX_FRAMES_IRQ },
    .{ "tx_usecs", uapi.COALESCE.TX_USECS },
    .{ "tx_max_frames", uapi.COALESCE.TX_MAX_FRAMES },
    .{ "tx_usecs_irq", uapi.COALESCE.TX_USECS_IRQ },
    .{ "tx_max_frames_irq", uapi.COALESCE.TX_MAX_FRAMES_IRQ },
    .{ "stats_block_usecs", uapi.COALESCE.STATS_BLOCK_USECS },
    .{ "pkt_rate_low", uapi.COALESCE.PKT_RATE_LOW },
    .{ "rx_usecs_low", uapi.COALESCE.RX_USECS_LOW },
    .{ "rx_max_frames_low", uapi.COALESCE.RX_MAX_FRAMES_LOW },
    .{ "tx_usecs_low", uapi.COALESCE.TX_USECS_LOW },
    .{ "tx_max_frames_low", uapi.COALESCE.TX_MAX_FRAMES_LOW },
    .{ "pkt_rate_high", uapi.COALESCE.PKT_RATE_HIGH },
    .{ "rx_usecs_high", uapi.COALESCE.RX_USECS_HIGH },
    .{ "rx_max_frames_high", uapi.COALESCE.RX_MAX_FRAMES_HIGH },
    .{ "tx_usecs_high", uapi.COALESCE.TX_USECS_HIGH },
    .{ "tx_max_frames_high", uapi.COALESCE.TX_MAX_FRAMES_HIGH },
    .{ "rate_sample_interval", uapi.COALESCE.RATE_SAMPLE_INTERVAL },
    .{ "tx_aggr_max_bytes", uapi.COALESCE.TX_AGGR_MAX_BYTES },
    .{ "tx_aggr_max_frames", uapi.COALESCE.TX_AGGR_MAX_FRAMES },
    .{ "tx_aggr_time_usecs", uapi.COALESCE.TX_AGGR_TIME_USECS },
};
const coalesce_bool = .{
    .{ "use_adaptive_rx", uapi.COALESCE.USE_ADAPTIVE_RX },
    .{ "use_adaptive_tx", uapi.COALESCE.USE_ADAPTIVE_TX },
    .{ "use_cqe_mode_tx", uapi.COALESCE.USE_CQE_MODE_TX },
    .{ "use_cqe_mode_rx", uapi.COALESCE.USE_CQE_MODE_RX },
};

test "mutation 2026-11-27: COALESCE reply: every attribute lands in the field of its name" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try hdrNest(&list, uapi.COALESCE.HEADER);
    inline for (coalesce_u32, 0..) |e, i| try u32Attr(&list, e[1], 3000 + @as(u32, i));
    // alternate polarity so a flipped read cannot pass
    inline for (coalesce_bool, 0..) |e, i| try u8Attr(&list, e[1], @as(u8, @intFromBool(i % 2 == 0)));
    const c = try params.parseCoalesce(list.items);
    try testing.expectEqual(@as(?u32, 7), c.device.index);
    inline for (coalesce_u32, 0..) |e, i| {
        try testing.expectEqual(@as(?u32, 3000 + @as(u32, i)), @field(c, e[0]));
    }
    inline for (coalesce_bool, 0..) |e, i| {
        try testing.expectEqual(@as(?bool, i % 2 == 0), @field(c, e[0]));
    }
}

test "mutation 2026-11-27: COALESCE_SET: every field is encoded, nothing else is" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try params.appendCoalesceSet(m_gpa, &list, .{
        .rx_usecs = 31,
        .rx_max_frames = 32,
        .tx_usecs = 33,
        .tx_max_frames = 34,
        .rx_usecs_irq = 35,
        .tx_usecs_irq = 36,
        .stats_block_usecs = 37,
        .use_adaptive_rx = true,
        .use_adaptive_tx = false,
        .use_cqe_mode_rx = true,
        .use_cqe_mode_tx = false,
    });
    try expectU32Attr(list.items, uapi.COALESCE.RX_USECS, 31);
    try expectU32Attr(list.items, uapi.COALESCE.RX_MAX_FRAMES, 32);
    try expectU32Attr(list.items, uapi.COALESCE.TX_USECS, 33);
    try expectU32Attr(list.items, uapi.COALESCE.TX_MAX_FRAMES, 34);
    try expectU32Attr(list.items, uapi.COALESCE.RX_USECS_IRQ, 35);
    try expectU32Attr(list.items, uapi.COALESCE.TX_USECS_IRQ, 36);
    try expectU32Attr(list.items, uapi.COALESCE.STATS_BLOCK_USECS, 37);
    try expectU8Attr(list.items, uapi.COALESCE.USE_ADAPTIVE_RX, 1);
    try expectU8Attr(list.items, uapi.COALESCE.USE_ADAPTIVE_TX, 0);
    try expectU8Attr(list.items, uapi.COALESCE.USE_CQE_MODE_RX, 1);
    try expectU8Attr(list.items, uapi.COALESCE.USE_CQE_MODE_TX, 0);
    try testing.expectEqual(@as(usize, 11), try attrCount(list.items));
}

test "mutation 2026-11-27: PAUSE reply, PAUSE_SET and the isEmpty of every SET struct" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try hdrNest(&list, uapi.PAUSE.HEADER);
    try u8Attr(&list, uapi.PAUSE.AUTONEG, 1);
    try u8Attr(&list, uapi.PAUSE.RX, 0);
    try u8Attr(&list, uapi.PAUSE.TX, 1);
    try u32Attr(&list, uapi.PAUSE.STATS_SRC, 2);
    const nest = try codec.nestBegin(m_gpa, &list, uapi.PAUSE.STATS | codec.NLA_F_NESTED);
    try u64Attr(&list, uapi.PAUSE_STAT.TX_FRAMES, 0x1_0000_0001);
    try u64Attr(&list, uapi.PAUSE_STAT.RX_FRAMES, 0x2_0000_0002);
    try codec.nestEnd(&list, nest);
    const p = try params.parsePause(list.items);
    try testing.expectEqual(@as(?u32, 7), p.device.index);
    try testing.expectEqual(@as(?bool, true), p.autoneg);
    try testing.expectEqual(@as(?bool, false), p.rx);
    try testing.expectEqual(@as(?bool, true), p.tx);
    try testing.expectEqual(@as(?uapi.StatsSrc, .pmac), p.stats_src);
    try testing.expectEqual(@as(?u64, 0x1_0000_0001), p.stats.?.tx_frames);
    try testing.expectEqual(@as(?u64, 0x2_0000_0002), p.stats.?.rx_frames);

    // a pause counter is exactly 8 bytes: longer is as malformed as shorter
    for ([_]usize{ 7, 9, 16 }) |len| {
        var bad: std.ArrayList(u8) = .empty;
        defer bad.deinit(m_gpa);
        const n = try codec.nestBegin(m_gpa, &bad, uapi.PAUSE.STATS | codec.NLA_F_NESTED);
        const body: [16]u8 = @splat(0);
        try codec.appendAttr(m_gpa, &bad, uapi.PAUSE_STAT.TX_FRAMES, body[0..len]);
        try codec.nestEnd(&bad, n);
        try testing.expectError(error.BadLength, params.parsePause(bad.items));
    }

    var set_bytes: std.ArrayList(u8) = .empty;
    defer set_bytes.deinit(m_gpa);
    try params.appendPauseSet(m_gpa, &set_bytes, .{ .autoneg = true, .rx = false, .tx = true });
    try expectU8Attr(set_bytes.items, uapi.PAUSE.AUTONEG, 1);
    try expectU8Attr(set_bytes.items, uapi.PAUSE.RX, 0);
    try expectU8Attr(set_bytes.items, uapi.PAUSE.TX, 1);
    try testing.expectEqual(@as(usize, 3), try attrCount(set_bytes.items));

    try testing.expect(params.ChannelsSet.isEmpty(.{}));
    try testing.expect(!params.ChannelsSet.isEmpty(.{ .rx_count = 1 }));
    try testing.expect(params.CoalesceSet.isEmpty(.{}));
    try testing.expect(!params.CoalesceSet.isEmpty(.{ .rx_usecs = 1 }));
    try testing.expect(params.PauseSet.isEmpty(.{}));
    try testing.expect(!params.PauseSet.isEmpty(.{ .rx = false }));
    try testing.expect(params.RingsSet.isEmpty(.{}));
    try testing.expect(!params.RingsSet.isEmpty(.{ .tx = 0 }));
}

// ── bitset ─────────────────────────────────────────────────────────────────

fn bsWords(list: *std.ArrayList(u8), t: u16, words: []const u32) !void {
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(m_gpa);
    for (words) |w| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, w, native_endian);
        try raw.appendSlice(m_gpa, &b);
    }
    try codec.appendAttr(m_gpa, list, t, raw.items);
}

fn bsFlag(list: *std.ArrayList(u8), t: u16) !void {
    try codec.appendAttr(m_gpa, list, t, &.{});
}

fn bsBit(list: *std.ArrayList(u8), index: ?u32, name: ?[]const u8, value: bool) !void {
    const n = try codec.nestBegin(m_gpa, list, uapi.BITSET_BITS.BIT | codec.NLA_F_NESTED);
    if (index) |i| try u32Attr(list, uapi.BITSET_BIT.INDEX, i);
    if (name) |s| try codec.appendAttrString(m_gpa, list, uapi.BITSET_BIT.NAME, s);
    if (value) try bsFlag(list, uapi.BITSET_BIT.VALUE);
    try codec.nestEnd(list, n);
}

test "mutation 2026-11-27: inMask and maskCount: the size bound, the masked/NOMASK split, compact sets without a mask" {
    // verbose NOMASK list with SIZE 8: bits 0..7 are in scope, 8 is not
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        try bsFlag(&raw, uapi.BITSET.NOMASK);
        try u32Attr(&raw, uapi.BITSET.SIZE, 8);
        const n = try codec.nestBegin(m_gpa, &raw, uapi.BITSET.BITS | codec.NLA_F_NESTED);
        try bsBit(&raw, 2, "two", false);
        try bsBit(&raw, 5, "five", false);
        try codec.nestEnd(&raw, n);
        var bs = try bitset.parse(m_gpa, raw.items);
        defer bs.deinit(m_gpa);
        try testing.expect(bs.inMask(7));
        try testing.expect(!bs.inMask(8));
    }
    // a listed bit without an index still counts in a NOMASK list, not in a masked one
    for ([_]bool{ true, false }) |nomask| {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        if (nomask) try bsFlag(&raw, uapi.BITSET.NOMASK);
        const n = try codec.nestBegin(m_gpa, &raw, uapi.BITSET.BITS | codec.NLA_F_NESTED);
        try bsBit(&raw, 1, "a", true);
        try bsBit(&raw, null, "b", true);
        try codec.nestEnd(&raw, n);
        var bs = try bitset.parse(m_gpa, raw.items);
        defer bs.deinit(m_gpa);
        try testing.expectEqual(@as(u32, if (nomask) 2 else 1), bs.maskCount());
    }
    // compact NOMASK list with SIZE 8: everything below SIZE is in scope
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        try bsFlag(&raw, uapi.BITSET.NOMASK);
        try u32Attr(&raw, uapi.BITSET.SIZE, 8);
        try bsWords(&raw, uapi.BITSET.VALUE, &.{0b101});
        var bs = try bitset.parse(m_gpa, raw.items);
        defer bs.deinit(m_gpa);
        try testing.expectEqual(@as(u32, 8), bs.maskCount());
        try testing.expectEqual(@as(u32, 2), bs.count());
        try testing.expect(bs.inMask(7));
        try testing.expect(!bs.inMask(8));
    }
    // compact, no mask and no SIZE: the value words are all there is to go by
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        try bsWords(&raw, uapi.BITSET.VALUE, &.{0b100});
        var bs = try bitset.parse(m_gpa, raw.items);
        defer bs.deinit(m_gpa);
        try testing.expect(bs.inMask(2));
        try testing.expect(!bs.inMask(1));
    }
}

test "mutation 2026-11-27: bitset decode: the SIZE and word ceilings are exact, duplicates and mixed encodings are refused" {
    const max: u32 = bitset.max_bits;
    const words_max = max / 32;
    var zeros: [words_max + 1]u32 = @splat(0);
    // SIZE == max_bits is the last accepted size, one more is refused
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        try u32Attr(&raw, uapi.BITSET.SIZE, max);
        try bsWords(&raw, uapi.BITSET.VALUE, zeros[0..words_max]);
        var bs = try bitset.parse(m_gpa, raw.items);
        bs.deinit(m_gpa);
    }
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        try u32Attr(&raw, uapi.BITSET.SIZE, max + 1);
        try testing.expectError(error.BadLength, bitset.parse(m_gpa, raw.items));
    }
    // without a SIZE the word count itself is capped at max_bits / 32
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        try bsWords(&raw, uapi.BITSET.VALUE, zeros[0..words_max]);
        var bs = try bitset.parse(m_gpa, raw.items);
        bs.deinit(m_gpa);
    }
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        try bsWords(&raw, uapi.BITSET.VALUE, zeros[0 .. words_max + 1]);
        try testing.expectError(error.BadLength, bitset.parse(m_gpa, raw.items));
    }
    // a second MASK, a second BITS, a MASK beside BITS
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        try bsWords(&raw, uapi.BITSET.MASK, &.{1});
        try bsWords(&raw, uapi.BITSET.MASK, &.{1});
        try testing.expectError(error.BadLength, bitset.parse(m_gpa, raw.items));
    }
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        for (0..2) |_| {
            const n = try codec.nestBegin(m_gpa, &raw, uapi.BITSET.BITS | codec.NLA_F_NESTED);
            try bsBit(&raw, 1, "a", true);
            try codec.nestEnd(&raw, n);
        }
        try testing.expectError(error.BadLength, bitset.parse(m_gpa, raw.items));
    }
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        const n = try codec.nestBegin(m_gpa, &raw, uapi.BITSET.BITS | codec.NLA_F_NESTED);
        try bsBit(&raw, 1, "a", true);
        try codec.nestEnd(&raw, n);
        try bsWords(&raw, uapi.BITSET.MASK, &.{1});
        try testing.expectError(error.BadLength, bitset.parse(m_gpa, raw.items));
    }
    // a MASK longer than ceil(SIZE / 32) words, and a VALUE longer
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        try u32Attr(&raw, uapi.BITSET.SIZE, 32);
        try bsWords(&raw, uapi.BITSET.VALUE, &.{1});
        try bsWords(&raw, uapi.BITSET.MASK, &.{ 1, 1 });
        try testing.expectError(error.BadLength, bitset.parse(m_gpa, raw.items));
    }
    // two NAMEs in one bit
    {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(m_gpa);
        const n = try codec.nestBegin(m_gpa, &raw, uapi.BITSET.BITS | codec.NLA_F_NESTED);
        const b = try codec.nestBegin(m_gpa, &raw, uapi.BITSET_BITS.BIT | codec.NLA_F_NESTED);
        try codec.appendAttrString(m_gpa, &raw, uapi.BITSET_BIT.NAME, "x");
        try codec.appendAttrString(m_gpa, &raw, uapi.BITSET_BIT.NAME, "y");
        try codec.nestEnd(&raw, b);
        try codec.nestEnd(&raw, n);
        try testing.expectError(error.BadLength, bitset.parse(m_gpa, raw.items));
    }
}

test "mutation 2026-11-27: appendCompact refuses a value or mask that is not exactly ceil(size/32) words" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    // value longer than the size says
    try testing.expectError(error.InvalidRequest, bitset.appendCompact(m_gpa, &list, 1, 32, &.{ 1, 2 }, null));
    // mask shorter than the size says (value is right)
    try testing.expectError(error.InvalidRequest, bitset.appendCompact(m_gpa, &list, 1, 64, &.{ 1, 2 }, &.{1}));
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

// ── stats / string sets ────────────────────────────────────────────────────

fn grpNest(list: *std.ArrayList(u8), id: u32) !void {
    const n = try codec.nestBegin(m_gpa, list, uapi.STATS.GRP | codec.NLA_F_NESTED);
    try u32Attr(list, uapi.STATS_GRP.ID, id);
    try codec.nestEnd(list, n);
}

test "mutation 2026-11-27: STATS_GET: at most max_groups groups" {
    for ([_]usize{ stats.max_groups, stats.max_groups + 1 }) |count| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        for (0..count) |i| try grpNest(&list, @intCast(i % 4));
        if (count > stats.max_groups) {
            try testing.expectError(error.BadLength, stats.parse(m_gpa, list.items));
        } else {
            var st = try stats.parse(m_gpa, list.items);
            defer st.deinit(m_gpa);
            try testing.expectEqual(count, st.groups.len);
        }
    }
}

test "mutation 2026-11-27: STATS_GET: a group holds at most max_stats_per_group counters and as many buckets" {
    const cap = stats.max_stats_per_group;
    for ([_]usize{ cap, cap + 1 }) |count| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        const g = try codec.nestBegin(m_gpa, &list, uapi.STATS.GRP | codec.NLA_F_NESTED);
        const s = try codec.nestBegin(m_gpa, &list, uapi.STATS_GRP.STAT | codec.NLA_F_NESTED);
        for (0..count) |i| try u64Attr(&list, @intCast(i + 1), i);
        try codec.nestEnd(&list, s);
        try codec.nestEnd(&list, g);
        if (count > cap) {
            try testing.expectError(error.BadLength, stats.parse(m_gpa, list.items));
        } else {
            var st = try stats.parse(m_gpa, list.items);
            defer st.deinit(m_gpa);
            try testing.expectEqual(cap, st.groups[0].stats.len);
        }
    }
    // empty bucket nests are 4 bytes each, so the cap is reachable for both directions
    for ([_]u16{ uapi.STATS_GRP.HIST_RX, uapi.STATS_GRP.HIST_TX }) |dir| {
        for ([_]usize{ cap, cap + 1 }) |count| {
            var list: std.ArrayList(u8) = .empty;
            defer list.deinit(m_gpa);
            const g = try codec.nestBegin(m_gpa, &list, uapi.STATS.GRP | codec.NLA_F_NESTED);
            for (0..count) |_| try codec.appendAttr(m_gpa, &list, dir, &.{});
            try codec.nestEnd(&list, g);
            if (count > cap) {
                try testing.expectError(error.BadLength, stats.parse(m_gpa, list.items));
            } else {
                var st = try stats.parse(m_gpa, list.items);
                defer st.deinit(m_gpa);
                const got = if (dir == uapi.STATS_GRP.HIST_RX) st.groups[0].hist_rx.len else st.groups[0].hist_tx.len;
                try testing.expectEqual(cap, got);
            }
        }
    }
}

test "mutation 2026-11-27: STATS_GET: padding attributes are skipped, histogram buckets keep low, hi and value" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    const g = try codec.nestBegin(m_gpa, &list, uapi.STATS.GRP | codec.NLA_F_NESTED);
    const s = try codec.nestBegin(m_gpa, &list, uapi.STATS_GRP.STAT | codec.NLA_F_NESTED);
    try u64Attr(&list, 3, 99);
    try codec.appendAttr(m_gpa, &list, 77, &.{}); // a padding attribute: no payload
    try codec.nestEnd(&list, s);
    const h = try codec.nestBegin(m_gpa, &list, uapi.STATS_GRP.HIST_RX | codec.NLA_F_NESTED);
    try u32Attr(&list, uapi.STATS_GRP.HIST_BKT_LOW, 5);
    try u32Attr(&list, uapi.STATS_GRP.HIST_BKT_HI, 10);
    try u64Attr(&list, uapi.STATS_GRP.HIST_VAL, 7);
    try codec.nestEnd(&list, h);
    try codec.nestEnd(&list, g);
    var st = try stats.parse(m_gpa, list.items);
    defer st.deinit(m_gpa);
    try testing.expectEqual(@as(usize, 1), st.groups[0].stats.len);
    try testing.expectEqual(@as(?u64, 99), st.groups[0].value(3));
    try testing.expectEqual(@as(usize, 1), st.groups[0].hist_rx.len);
    try testing.expectEqual(@as(u32, 5), st.groups[0].hist_rx[0].low);
    try testing.expectEqual(@as(u32, 10), st.groups[0].hist_rx[0].hi);
    try testing.expectEqual(@as(u64, 7), st.groups[0].hist_rx[0].value);
}

test "mutation 2026-11-27: groupName knows exactly the four standard groups" {
    try testing.expectEqualStrings("eth-phy", stats.groupName(.eth_phy).?);
    try testing.expectEqualStrings("rmon", stats.groupName(.rmon).?);
    try testing.expect(stats.groupName(@fromBackingInt(@intCast(4))) == null);
    try testing.expect(stats.groupName(@fromBackingInt(@intCast(200))) == null);
}

fn stringSetsHeader(list: *std.ArrayList(u8)) !void {
    try hdrNest(list, uapi.STRSET.HEADER);
}

test "mutation 2026-11-27: STRSET_GET: the device, the set limit, the COUNT ceiling and a string with no value" {
    // device
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        try stringSetsHeader(&list);
        var ss = try stats.parseStringSets(m_gpa, list.items);
        defer ss.deinit(m_gpa);
        try testing.expectEqual(@as(?u32, 7), ss.device.index);
    }
    // at most max_groups sets
    for ([_]usize{ stats.max_groups, stats.max_groups + 1 }) |count| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        const outer = try codec.nestBegin(m_gpa, &list, uapi.STRSET.STRINGSETS | codec.NLA_F_NESTED);
        for (0..count) |_| {
            const one = try codec.nestBegin(m_gpa, &list, uapi.STRINGSETS.STRINGSET | codec.NLA_F_NESTED);
            try codec.nestEnd(&list, one);
        }
        try codec.nestEnd(&list, outer);
        if (count > stats.max_groups) {
            try testing.expectError(error.BadLength, stats.parseStringSets(m_gpa, list.items));
        } else {
            var ss = try stats.parseStringSets(m_gpa, list.items);
            defer ss.deinit(m_gpa);
            try testing.expectEqual(count, ss.sets.len);
        }
    }
    // COUNT == max_strings is the last accepted count
    for ([_]u32{ stats.max_strings, stats.max_strings + 1 }) |count| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        const outer = try codec.nestBegin(m_gpa, &list, uapi.STRSET.STRINGSETS | codec.NLA_F_NESTED);
        const one = try codec.nestBegin(m_gpa, &list, uapi.STRINGSETS.STRINGSET | codec.NLA_F_NESTED);
        try u32Attr(&list, uapi.STRINGSET.COUNT, count);
        try codec.nestEnd(&list, one);
        try codec.nestEnd(&list, outer);
        if (count > stats.max_strings) {
            try testing.expectError(error.BadLength, stats.parseStringSets(m_gpa, list.items));
        } else {
            var ss = try stats.parseStringSets(m_gpa, list.items);
            defer ss.deinit(m_gpa);
            try testing.expectEqual(@as(?u32, stats.max_strings), ss.sets[0].count);
        }
    }
    // a string with an index but no value is refused
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        const outer = try codec.nestBegin(m_gpa, &list, uapi.STRSET.STRINGSETS | codec.NLA_F_NESTED);
        const one = try codec.nestBegin(m_gpa, &list, uapi.STRINGSETS.STRINGSET | codec.NLA_F_NESTED);
        const strs = try codec.nestBegin(m_gpa, &list, uapi.STRINGSET.STRINGS | codec.NLA_F_NESTED);
        const st = try codec.nestBegin(m_gpa, &list, uapi.STRINGS.STRING | codec.NLA_F_NESTED);
        try u32Attr(&list, uapi.STRING.INDEX, 3);
        try codec.nestEnd(&list, st);
        try codec.nestEnd(&list, strs);
        try codec.nestEnd(&list, one);
        try codec.nestEnd(&list, outer);
        try testing.expectError(error.BadLength, stats.parseStringSets(m_gpa, list.items));
    }
}

// ── features ───────────────────────────────────────────────────────────────

fn featBits(list: *std.ArrayList(u8), t: u16) !void {
    try bitset.appendCompact(m_gpa, list, t, 32, &.{1}, &.{1});
}

test "mutation 2026-11-27: FEATURES: a second WANTED, ACTIVE or NOCHANGE bitset is malformed, nothing leaks" {
    for ([_]u16{ uapi.FEATURES.HW, uapi.FEATURES.WANTED, uapi.FEATURES.ACTIVE, uapi.FEATURES.NOCHANGE }) |t| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        try featBits(&list, t);
        try featBits(&list, t);
        try testing.expectError(error.BadLength, features.parse(m_gpa, list.items));
    }
    for ([_]u16{ uapi.FEATURES.WANTED, uapi.FEATURES.ACTIVE }) |t| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        try featBits(&list, t);
        try featBits(&list, t);
        try testing.expectError(error.BadLength, features.parseSetResult(m_gpa, list.items));
    }
}

test "mutation 2026-11-27: a SET reply with no bitsets (bare ACK) honoured everything" {
    const r: features.SetResult = .{};
    try testing.expect(r.fullyHonoured());
    try testing.expect(r.honouredAt(3));
    try testing.expectEqual(@as(?bool, true), r.honouredByName("tx-tcp-segmentation"));
    try testing.expectEqual(@as(?bool, null), r.newStateAt(3));
}

// ── link ───────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: LINKMODES reply: master/slave, lanes, rate matching, the peer set; a second PEER is refused" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try u8Attr(&list, uapi.LINKMODES.MASTER_SLAVE_CFG, 2);
    try u8Attr(&list, uapi.LINKMODES.MASTER_SLAVE_STATE, 3);
    try u32Attr(&list, uapi.LINKMODES.LANES, 4);
    try u8Attr(&list, uapi.LINKMODES.RATE_MATCHING, 1);
    try bitset.appendCompact(m_gpa, &list, uapi.LINKMODES.PEER, 32, &.{0b110}, &.{0b111});
    var lm = try link.parseLinkModes(m_gpa, list.items);
    defer lm.deinit(m_gpa);
    try testing.expectEqual(@as(?uapi.MasterSlaveCfg, .master_preferred), lm.master_slave_cfg);
    try testing.expectEqual(@as(?uapi.MasterSlaveState, .slave), lm.master_slave_state);
    try testing.expectEqual(@as(?u32, 4), lm.lanes);
    try testing.expectEqual(@as(?u8, 1), lm.rate_matching);
    try testing.expect(lm.peer.?.isSet(1) and lm.peer.?.isSet(2) and !lm.peer.?.isSet(0));
    try bitset.appendCompact(m_gpa, &list, uapi.LINKMODES.PEER, 32, &.{1}, &.{1});
    try testing.expectError(error.BadLength, link.parseLinkModes(m_gpa, list.items));
}

test "mutation 2026-11-27: LINKINFO_SET and LINKMODES_SET encode every field they carry" {
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(m_gpa);
    try link.appendLinkInfoSet(m_gpa, &a, .{ .port = .da, .tp_mdix_ctrl = .mdi_x });
    try expectU8Attr(a.items, uapi.LINKINFO.PORT, 5);
    try expectU8Attr(a.items, uapi.LINKINFO.TP_MDIX_CTRL, 2);
    try testing.expectEqual(@as(usize, 2), try attrCount(a.items));

    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(m_gpa);
    try link.appendLinkModesSet(m_gpa, &b, .{ .speed_mbps = 1000, .duplex = .full, .autoneg = false, .master_slave_cfg = .slave_force, .lanes = 4 });
    try expectU32Attr(b.items, uapi.LINKMODES.SPEED, 1000);
    try expectU8Attr(b.items, uapi.LINKMODES.DUPLEX, 1);
    try expectU8Attr(b.items, uapi.LINKMODES.AUTONEG, 0);
    try expectU8Attr(b.items, uapi.LINKMODES.MASTER_SLAVE_CFG, 5);
    try expectU32Attr(b.items, uapi.LINKMODES.LANES, 4);
    try testing.expectEqual(@as(usize, 5), try attrCount(b.items));
}

// ── module EEPROM, EEE/FEC, WOL, debug ─────────────────────────────────────

test "mutation 2026-11-27: EEPROM reply: the device, and exactly max_eeprom_read bytes are the last accepted" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try hdrNest(&list, uapi.MODULE_EEPROM.HEADER);
    const full: [moduleinfo.max_eeprom_read]u8 = @splat(0xab);
    try codec.appendAttr(m_gpa, &list, uapi.MODULE_EEPROM.DATA, &full);
    var e = try moduleinfo.parseEeprom(m_gpa, list.items);
    defer e.deinit(m_gpa);
    try testing.expectEqual(@as(?u32, 7), e.device.index);
    try testing.expectEqual(@as(usize, moduleinfo.max_eeprom_read), e.data.len);

    var longer: std.ArrayList(u8) = .empty;
    defer longer.deinit(m_gpa);
    const over: [moduleinfo.max_eeprom_read + 1]u8 = @splat(0);
    try codec.appendAttr(m_gpa, &longer, uapi.MODULE_EEPROM.DATA, &over);
    try testing.expectError(error.BadLength, moduleinfo.parseEeprom(m_gpa, longer.items));
}

test "mutation 2026-11-27: EEE: a second PEER set is refused; SET by name only and by index only are both fine; every SET field is encoded" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try bitset.appendCompact(m_gpa, &list, uapi.EEE.MODES_PEER, 32, &.{1}, &.{1});
    try bitset.appendCompact(m_gpa, &list, uapi.EEE.MODES_PEER, 32, &.{1}, &.{1});
    try testing.expectError(error.BadLength, eee_fec.parseEee(m_gpa, list.items));

    var names_only: std.ArrayList(u8) = .empty;
    defer names_only.deinit(m_gpa);
    try eee_fec.appendEeeSet(m_gpa, &names_only, .{ .advertise_names = &.{.{ .name = "100baseT/Full", .on = true }} });
    try testing.expect((try attrAt(names_only.items, uapi.EEE.MODES_OURS)) != null);

    var index_only: std.ArrayList(u8) = .empty;
    defer index_only.deinit(m_gpa);
    try eee_fec.appendEeeSet(m_gpa, &index_only, .{ .advertise = &.{.{ .index = 5, .on = true }} });
    try testing.expect((try attrAt(index_only.items, uapi.EEE.MODES_OURS)) != null);

    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(m_gpa);
    try eee_fec.appendEeeSet(m_gpa, &all, .{ .enabled = false, .tx_lpi_enabled = true, .tx_lpi_timer = 300 });
    try expectU8Attr(all.items, uapi.EEE.ENABLED, 0);
    try expectU8Attr(all.items, uapi.EEE.TX_LPI_ENABLED, 1);
    try expectU32Attr(all.items, uapi.EEE.TX_LPI_TIMER, 300);
    try testing.expectEqual(@as(usize, 3), try attrCount(all.items));
}

test "mutation 2026-11-27: FEC: the device, a second MODES set, and the counter length rules" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try hdrNest(&list, uapi.FEC.HEADER);
    var fec = try eee_fec.parseFec(m_gpa, list.items);
    defer fec.deinit(m_gpa);
    try testing.expectEqual(@as(?u32, 7), fec.device.index);

    var dup: std.ArrayList(u8) = .empty;
    defer dup.deinit(m_gpa);
    try bitset.appendCompact(m_gpa, &dup, uapi.FEC.MODES, 32, &.{1}, &.{1});
    try bitset.appendCompact(m_gpa, &dup, uapi.FEC.MODES, 32, &.{1}, &.{1});
    try testing.expectError(error.BadLength, eee_fec.parseFec(m_gpa, dup.items));

    // a counter is a u64 total plus up to 8 u64 lane values
    const body: [96]u8 = @splat(0);
    const cases = [_]struct { len: usize, ok: bool }{
        .{ .len = 8, .ok = true },
        .{ .len = 12, .ok = false },
        .{ .len = 72, .ok = true }, // total + 8 lanes
        .{ .len = 80, .ok = false }, // total + 9 lanes
    };
    for (cases) |c| {
        var nest: std.ArrayList(u8) = .empty;
        defer nest.deinit(m_gpa);
        try codec.appendAttr(m_gpa, &nest, uapi.FEC_STAT.CORRECTED, body[0..c.len]);
        if (c.ok) {
            const st = try eee_fec.parseFecStats(nest.items);
            try testing.expectEqual(@as(u8, @intCast(c.len / 8 - 1)), st.corrected_blocks.?.lane_count);
        } else {
            try testing.expectError(error.BadLength, eee_fec.parseFecStats(nest.items));
        }
    }
}

test "mutation 2026-11-27: wipe zeroes what it is given" {
    var buf = [_]u8{ 1, 2, 3, 4, 5, 6 };
    wol.wipe(&buf);
    const zero: [6]u8 = @splat(0);
    try testing.expectEqual(zero, buf);
}

test "mutation 2026-11-27: DEBUG: names, the device, a second MSGMASK, the compact flag, and the vclock ceiling" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try hdrNest(&list, uapi.DEBUG.HEADER);
    const outer = try codec.nestBegin(m_gpa, &list, uapi.DEBUG.MSGMASK | codec.NLA_F_NESTED);
    const bits = try codec.nestBegin(m_gpa, &list, uapi.BITSET.BITS | codec.NLA_F_NESTED);
    try bsBit(&list, 0, "drv", true);
    try bsBit(&list, 1, "link", false);
    try codec.nestEnd(&list, bits);
    try codec.nestEnd(&list, outer);
    var d = try debug.parseDebug(m_gpa, list.items);
    defer d.deinit(m_gpa);
    try testing.expectEqual(@as(?u32, 7), d.device.index);
    try testing.expectEqual(@as(?bool, true), d.isOn("drv"));
    try testing.expectEqual(@as(?bool, false), d.isOn("link"));
    try testing.expectEqual(@as(?bool, null), d.isOn("nosuch"));

    // a second MSGMASK
    const outer2 = try codec.nestBegin(m_gpa, &list, uapi.DEBUG.MSGMASK | codec.NLA_F_NESTED);
    try codec.nestEnd(&list, outer2);
    try testing.expectError(error.BadLength, debug.parseDebug(m_gpa, list.items));

    // the form decides the compact flag of the request
    const compact = try debug.buildDebug(m_gpa, 30, 1, .{ .index = 7 }, .compact);
    defer m_gpa.free(compact);
    try testing.expectEqual(@as(?u32, uapi.FLAG.COMPACT_BITSETS), try requestFlags(compact));
    const verbose = try debug.buildDebug(m_gpa, 30, 1, .{ .index = 7 }, .verbose);
    defer m_gpa.free(verbose);
    try testing.expectEqual(@as(?u32, null), try requestFlags(verbose));

    // PHC_VCLOCKS: the device, and max_vclocks entries are the last accepted
    var vc: std.ArrayList(u8) = .empty;
    defer vc.deinit(m_gpa);
    try hdrNest(&vc, uapi.PHC_VCLOCKS.HEADER);
    const idx: [debug.max_vclocks + 1]u32 = @splat(3);
    try bsWords(&vc, uapi.PHC_VCLOCKS.INDEX, idx[0..debug.max_vclocks]);
    var v = try debug.parsePhcVclocks(m_gpa, vc.items);
    defer v.deinit(m_gpa);
    try testing.expectEqual(@as(?u32, 7), v.device.index);
    try testing.expectEqual(@as(usize, debug.max_vclocks), v.indexes.len);
    var vc2: std.ArrayList(u8) = .empty;
    defer vc2.deinit(m_gpa);
    try bsWords(&vc2, uapi.PHC_VCLOCKS.INDEX, idx[0 .. debug.max_vclocks + 1]);
    try testing.expectError(error.BadLength, debug.parsePhcVclocks(m_gpa, vc2.items));
}

// ── PLCA / MM ──────────────────────────────────────────────────────────────

test "mutation 2026-11-27: PLCA status carries its device; MM reply: every attribute lands in the field of its name" {
    var st: std.ArrayList(u8) = .empty;
    defer st.deinit(m_gpa);
    try hdrNest(&st, uapi.PLCA.HEADER);
    try u8Attr(&st, uapi.PLCA.STATUS, 1);
    const ps = try plca_mm.parsePlcaStatus(st.items);
    try testing.expectEqual(@as(?u32, 7), ps.device.index);
    try testing.expectEqual(@as(?bool, true), ps.status);

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try hdrNest(&list, uapi.MM.HEADER);
    try u8Attr(&list, uapi.MM.PMAC_ENABLED, 1);
    try u8Attr(&list, uapi.MM.TX_ENABLED, 0);
    try u8Attr(&list, uapi.MM.TX_ACTIVE, 1);
    try u32Attr(&list, uapi.MM.TX_MIN_FRAG_SIZE, 60);
    try u32Attr(&list, uapi.MM.RX_MIN_FRAG_SIZE, 124);
    try u8Attr(&list, uapi.MM.VERIFY_ENABLED, 0);
    try u8Attr(&list, uapi.MM.VERIFY_STATUS, 3);
    try u32Attr(&list, uapi.MM.VERIFY_TIME, 10);
    try u32Attr(&list, uapi.MM.MAX_VERIFY_TIME, 128);
    const nest = try codec.nestBegin(m_gpa, &list, uapi.MM.STATS | codec.NLA_F_NESTED);
    try u64Attr(&list, uapi.MM_STAT.REASSEMBLY_ERRORS, 11);
    try u64Attr(&list, uapi.MM_STAT.SMD_ERRORS, 12);
    try u64Attr(&list, uapi.MM_STAT.REASSEMBLY_OK, 13);
    try u64Attr(&list, uapi.MM_STAT.RX_FRAG_COUNT, 14);
    try u64Attr(&list, uapi.MM_STAT.TX_FRAG_COUNT, 15);
    try u64Attr(&list, uapi.MM_STAT.HOLD_COUNT, 16);
    try codec.nestEnd(&list, nest);
    const mm = try plca_mm.parseMm(list.items);
    try testing.expectEqual(@as(?u32, 7), mm.device.index);
    try testing.expectEqual(@as(?bool, true), mm.pmac_enabled);
    try testing.expectEqual(@as(?bool, false), mm.tx_enabled);
    try testing.expectEqual(@as(?bool, true), mm.tx_active);
    try testing.expectEqual(@as(?u32, 60), mm.tx_min_frag_size);
    try testing.expectEqual(@as(?u32, 124), mm.rx_min_frag_size);
    try testing.expectEqual(@as(?bool, false), mm.verify_enabled);
    try testing.expectEqual(@as(?plca_mm.MmVerifyStatus, .succeeded), mm.verify_status);
    try testing.expectEqual(@as(?u32, 10), mm.verify_time);
    try testing.expectEqual(@as(?u32, 128), mm.max_verify_time);
    const ms = mm.stats.?;
    try testing.expectEqual(@as(?u64, 11), ms.reassembly_errors);
    try testing.expectEqual(@as(?u64, 12), ms.smd_errors);
    try testing.expectEqual(@as(?u64, 13), ms.reassembly_ok);
    try testing.expectEqual(@as(?u64, 14), ms.rx_frag_count);
    try testing.expectEqual(@as(?u64, 15), ms.tx_frag_count);
    try testing.expectEqual(@as(?u64, 16), ms.hold_count);

    // a counter is exactly 8 bytes
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(m_gpa);
    const n = try codec.nestBegin(m_gpa, &bad, uapi.MM.STATS | codec.NLA_F_NESTED);
    const nine: [9]u8 = @splat(0);
    try codec.appendAttr(m_gpa, &bad, uapi.MM_STAT.HOLD_COUNT, &nine);
    try codec.nestEnd(&bad, n);
    try testing.expectError(error.BadLength, plca_mm.parseMm(bad.items));
}

test "mutation 2026-11-27: PLCA and MM requests: no stats flag unless asked, the kernel's limits are inclusive, every SET field is encoded" {
    const cfg = try plca_mm.buildPlcaCfg(m_gpa, 30, 1, .{ .index = 7 });
    defer m_gpa.free(cfg);
    try testing.expectEqual(@as(?u32, null), try requestFlags(cfg));
    const status = try plca_mm.buildPlcaStatus(m_gpa, 30, 1, .{ .index = 7 });
    defer m_gpa.free(status);
    try testing.expectEqual(@as(?u32, null), try requestFlags(status));

    // node_id <= 255, node_cnt 1..255, burst_cnt <= 255: the bounds themselves are fine
    const edge = try plca_mm.buildSetPlca(m_gpa, 30, 1, .{ .index = 7 }, .{ .node_id = 255, .node_cnt = 255, .burst_cnt = 255 });
    m_gpa.free(edge);
    const one = try plca_mm.buildSetPlca(m_gpa, 30, 1, .{ .index = 7 }, .{ .node_cnt = 1 });
    m_gpa.free(one);
    try testing.expectError(error.InvalidRequest, plca_mm.buildSetPlca(m_gpa, 30, 1, .{ .index = 7 }, .{ .node_id = 256 }));
    try testing.expectError(error.InvalidRequest, plca_mm.buildSetPlca(m_gpa, 30, 1, .{ .index = 7 }, .{ .node_cnt = 256 }));
    try testing.expectError(error.InvalidRequest, plca_mm.buildSetPlca(m_gpa, 30, 1, .{ .index = 7 }, .{ .burst_cnt = 256 }));
    try testing.expectError(error.InvalidRequest, plca_mm.buildSetPlca(m_gpa, 30, 1, .{ .index = 7 }, .{ .node_cnt = 0 }));

    const all = try plca_mm.buildSetPlca(m_gpa, 30, 1, .{ .index = 7 }, .{ .enabled = true, .node_cnt = 8, .node_id = 3, .to_timer = 32, .burst_cnt = 4, .burst_timer = 128 });
    defer m_gpa.free(all);
    try expectU8Attr(all[20..], uapi.PLCA.ENABLED, 1);
    try expectU32Attr(all[20..], uapi.PLCA.NODE_CNT, 8);
    try expectU32Attr(all[20..], uapi.PLCA.NODE_ID, 3);
    try expectU32Attr(all[20..], uapi.PLCA.TO_TMR, 32);
    try expectU32Attr(all[20..], uapi.PLCA.BURST_CNT, 4);
    try expectU32Attr(all[20..], uapi.PLCA.BURST_TMR, 128);

    // MM_SET: verification time 1..128 ms, bounds inclusive
    for ([_]u32{ 1, 128 }) |t| {
        const m = try plca_mm.buildSetMm(m_gpa, 30, 1, .{ .index = 7 }, .{ .verify_time = t });
        m_gpa.free(m);
    }
    for ([_]u32{ 0, 129 }) |t| {
        try testing.expectError(error.InvalidRequest, plca_mm.buildSetMm(m_gpa, 30, 1, .{ .index = 7 }, .{ .verify_time = t }));
    }
    const mm = try plca_mm.buildSetMm(m_gpa, 30, 1, .{ .index = 7 }, .{ .verify_enabled = true, .verify_time = 20, .tx_enabled = false, .pmac_enabled = true, .tx_min_frag_size = 124 });
    defer m_gpa.free(mm);
    try expectU8Attr(mm[20..], uapi.MM.VERIFY_ENABLED, 1);
    try expectU32Attr(mm[20..], uapi.MM.VERIFY_TIME, 20);
    try expectU8Attr(mm[20..], uapi.MM.TX_ENABLED, 0);
    try expectU8Attr(mm[20..], uapi.MM.PMAC_ENABLED, 1);
    try expectU32Attr(mm[20..], uapi.MM.TX_MIN_FRAG_SIZE, 124);
}

// ── PHY / tunnel info ──────────────────────────────────────────────────────

test "mutation 2026-11-27: PHY reply: a 64-byte name fits, 65 does not; the device and the upstream SFP name are kept" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try hdrNest(&list, uapi.PHY.HEADER);
    const long: [phy_tunnel.max_phy_name]u8 = @splat('d');
    try codec.appendAttrString(m_gpa, &list, uapi.PHY.DRVNAME, &long);
    try codec.appendAttrString(m_gpa, &list, uapi.PHY.UPSTREAM_SFP_NAME, "sfp-up");
    try codec.appendAttrString(m_gpa, &list, uapi.PHY.DOWNSTREAM_SFP_NAME, "sfp-down");
    const phy = try phy_tunnel.parsePhy(list.items);
    try testing.expectEqual(@as(?u32, 7), phy.device.index);
    try testing.expectEqualStrings(&long, phy.driverName());
    try testing.expectEqualStrings("sfp-up", phy.upstreamSfpName());
    try testing.expectEqualStrings("sfp-down", phy.downstreamSfpName());

    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(m_gpa);
    const over: [phy_tunnel.max_phy_name + 1]u8 = @splat('d');
    try codec.appendAttrString(m_gpa, &bad, uapi.PHY.DRVNAME, &over);
    try testing.expectError(error.BadLength, phy_tunnel.parsePhy(bad.items));
}

fn tunnelTable(list: *std.ArrayList(u8), entries: usize) !void {
    const t = try codec.nestBegin(m_gpa, list, uapi.TUNNEL_UDP.TABLE | codec.NLA_F_NESTED);
    try u32Attr(list, uapi.TUNNEL_UDP_TABLE.SIZE, 4);
    for (0..entries) |i| {
        const e = try codec.nestBegin(m_gpa, list, uapi.TUNNEL_UDP_TABLE.ENTRY | codec.NLA_F_NESTED);
        try codec.appendAttrBe16(m_gpa, list, uapi.TUNNEL_UDP_ENTRY.PORT, @intCast(4789 + i));
        try u32Attr(list, uapi.TUNNEL_UDP_ENTRY.TYPE, 0);
        try codec.nestEnd(list, e);
    }
    try codec.nestEnd(list, t);
}

test "mutation 2026-11-27: TUNNEL_INFO: the device, the type set, and the table and entry ceilings are exact" {
    // device + one table whose type set decodes
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        try hdrNest(&list, uapi.TUNNEL_INFO.HEADER);
        const ports = try codec.nestBegin(m_gpa, &list, uapi.TUNNEL_INFO.UDP_PORTS | codec.NLA_F_NESTED);
        const t = try codec.nestBegin(m_gpa, &list, uapi.TUNNEL_UDP.TABLE | codec.NLA_F_NESTED);
        try bitset.appendCompact(m_gpa, &list, uapi.TUNNEL_UDP_TABLE.TYPES, 32, &.{0b11}, &.{0b11});
        try codec.nestEnd(&list, t);
        try codec.nestEnd(&list, ports);
        var ti = try phy_tunnel.parseTunnelInfo(m_gpa, list.items);
        defer ti.deinit(m_gpa);
        try testing.expectEqual(@as(?u32, 7), ti.device.index);
        try testing.expectEqual(@as(u32, 2), ti.tables[0].types.?.count());
    }
    // a second TYPES set in one table
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        const ports = try codec.nestBegin(m_gpa, &list, uapi.TUNNEL_INFO.UDP_PORTS | codec.NLA_F_NESTED);
        const t = try codec.nestBegin(m_gpa, &list, uapi.TUNNEL_UDP.TABLE | codec.NLA_F_NESTED);
        try bitset.appendCompact(m_gpa, &list, uapi.TUNNEL_UDP_TABLE.TYPES, 32, &.{1}, &.{1});
        try bitset.appendCompact(m_gpa, &list, uapi.TUNNEL_UDP_TABLE.TYPES, 32, &.{1}, &.{1});
        try codec.nestEnd(&list, t);
        try codec.nestEnd(&list, ports);
        try testing.expectError(error.BadLength, phy_tunnel.parseTunnelInfo(m_gpa, list.items));
    }
    // at most max_entries entries per table
    for ([_]usize{ phy_tunnel.max_entries, phy_tunnel.max_entries + 1 }) |count| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        const ports = try codec.nestBegin(m_gpa, &list, uapi.TUNNEL_INFO.UDP_PORTS | codec.NLA_F_NESTED);
        try tunnelTable(&list, count);
        try codec.nestEnd(&list, ports);
        if (count > phy_tunnel.max_entries) {
            try testing.expectError(error.BadLength, phy_tunnel.parseTunnelInfo(m_gpa, list.items));
        } else {
            var ti = try phy_tunnel.parseTunnelInfo(m_gpa, list.items);
            defer ti.deinit(m_gpa);
            try testing.expectEqual(count, ti.tables[0].entries.len);
        }
    }
    // at most max_tables tables
    for ([_]usize{ phy_tunnel.max_tables, phy_tunnel.max_tables + 1 }) |count| {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(m_gpa);
        const ports = try codec.nestBegin(m_gpa, &list, uapi.TUNNEL_INFO.UDP_PORTS | codec.NLA_F_NESTED);
        for (0..count) |_| try tunnelTable(&list, 1);
        try codec.nestEnd(&list, ports);
        if (count > phy_tunnel.max_tables) {
            try testing.expectError(error.BadLength, phy_tunnel.parseTunnelInfo(m_gpa, list.items));
        } else {
            var ti = try phy_tunnel.parseTunnelInfo(m_gpa, list.items);
            defer ti.deinit(m_gpa);
            try testing.expectEqual(count, ti.tables.len);
        }
    }
    // the request carries the compact flag only when asked
    const c = try phy_tunnel.buildTunnelInfo(m_gpa, 30, 1, .{ .index = 7 }, .compact);
    defer m_gpa.free(c);
    try testing.expectEqual(@as(?u32, uapi.FLAG.COMPACT_BITSETS), try requestFlags(c));
}

// ── timestamping ───────────────────────────────────────────────────────────

test "mutation 2026-11-27: TS stats are exactly 8 bytes, the fourth counter decodes; TSCONFIG keeps its three sets; its request takes the form" {
    var st: std.ArrayList(u8) = .empty;
    defer st.deinit(m_gpa);
    try u64Attr(&st, uapi.TS_STAT.TX_ONESTEP_PKTS_UNCONFIRMED, 44);
    const ts = try tsinfo.parseTsStats(st.items);
    try testing.expectEqual(@as(?u64, 44), ts.tx_onestep_pkts_unconfirmed);

    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(m_gpa);
    const nine: [9]u8 = @splat(0);
    try codec.appendAttr(m_gpa, &bad, uapi.TS_STAT.TX_PKTS, &nine);
    try testing.expectError(error.BadLength, tsinfo.parseTsStats(bad.items));

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try bitset.appendCompact(m_gpa, &list, uapi.TSCONFIG.TX_TYPES, 32, &.{0b1}, &.{0b1});
    try bitset.appendCompact(m_gpa, &list, uapi.TSCONFIG.RX_FILTERS, 32, &.{0b10}, &.{0b10});
    try bitset.appendCompact(m_gpa, &list, uapi.TSCONFIG.HWTSTAMP_FLAGS, 32, &.{0b100}, &.{0b100});
    var c = try tsinfo.parseTsConfig(m_gpa, list.items);
    defer c.deinit(m_gpa);
    try testing.expect(c.tx_types.?.isSet(0) and !c.tx_types.?.isSet(1));
    try testing.expect(c.rx_filters.?.isSet(1) and !c.rx_filters.?.isSet(0));
    try testing.expect(c.flags.?.isSet(2) and !c.flags.?.isSet(0));

    const msg = try tsinfo.buildTsConfig(m_gpa, 30, 1, .{ .index = 7 }, .compact);
    defer m_gpa.free(msg);
    try testing.expectEqual(@as(?u32, uapi.FLAG.COMPACT_BITSETS), try requestFlags(msg));
}

// ── header / uapi ──────────────────────────────────────────────────────────

test "mutation 2026-11-27: interface names: 15 bytes fit IFNAMSIZ, 16 do not, on the way out and on the way in" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(m_gpa);
    try header.append(m_gpa, &list, 1, .{ .target = .{ .name = "fifteen-chars-x" } });
    try testing.expectError(error.InvalidRequest, header.append(m_gpa, &list, 1, .{ .target = .{ .name = "sixteen-chars-xx" } }));

    var rep: std.ArrayList(u8) = .empty;
    defer rep.deinit(m_gpa);
    try codec.appendAttrString(m_gpa, &rep, uapi.HEADER.DEV_NAME, "sixteen-chars-xx");
    try testing.expectError(error.BadLength, header.parse(rep.items));
}

test "mutation 2026-11-27: every ETHTOOL_MSG_*_NTF is a notification" {
    inline for (.{ "LINKINFO", "LINKMODES", "DEBUG", "WOL", "FEATURES", "PRIVFLAGS", "RINGS", "CHANNELS", "COALESCE", "PAUSE", "EEE", "CABLE_TEST", "CABLE_TEST_TDR", "FEC", "MODULE", "PLCA", "MM", "MODULE_FW_FLASH", "PHY", "PSE", "RSS" }) |name| {
        try testing.expect(uapi.isNotification(@field(uapi.REPLY, name ++ "_NTF")));
    }
}

test "mutation 2026-11-27: buildSetWol reserves its builder up front: one buffer, one copy, never a growth" {
    var fa = std.testing.FailingAllocator.init(m_gpa, .{});
    const a = fa.allocator();
    const secret = [uapi.sopass_len]u8{ 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34 };
    // well past the 128 bytes a growing ArrayList starts with
    var entries: [20]bitset.NamedValue = undefined;
    for (&entries) |*e| e.* = .{ .name = "magicsecure", .on = true };
    const msg = try wol.buildSetWol(a, 23, 1, .{ .name = "eth0" }, .{ .mode_names = &entries, .sopass = secret });
    wol.wipe(msg);
    a.free(msg);
    // the builder (reserved once) and the datagram copied out of it
    try testing.expectEqual(@as(usize, 2), fa.alloc_index);
    try testing.expectEqual(@as(usize, 0), fa.resize_index);
}
