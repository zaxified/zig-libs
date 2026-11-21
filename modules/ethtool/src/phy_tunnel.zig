// SPDX-License-Identifier: MIT
//! `PHY_GET` (the PHYs a device has: `ethtool --show-phys`) and `TUNNEL_INFO_GET` (the UDP tunnel ports a NIC offloads:
//! `ethtool --show-tunnels`). Both are read-only and unprivileged; both answer `NotSupported` on a kernel or device
//! without them.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");

pub const Error = codec.Error || error{OutOfMemory};

// ── PHY ────────────────────────────────────────────────────────────────────

/// Longest PHY driver / device name kept.
pub const max_phy_name = 64;

/// `ETHTOOL_MSG_PHY_GET` reply. No allocation.
pub const Phy = struct {
    device: header.Device = .{},
    /// The PHY's index on the device.
    index: ?u32 = null,
    drvname_buf: [max_phy_name]u8 = @splat(0),
    drvname_len: u8 = 0,
    name_buf: [max_phy_name]u8 = @splat(0),
    name_len: u8 = 0,
    /// What the PHY hangs off: the MAC (0) or another PHY (1, with `upstream_index`).
    upstream_type: ?u32 = null,
    upstream_index: ?u32 = null,
    upstream_sfp_buf: [max_phy_name]u8 = @splat(0),
    upstream_sfp_len: u8 = 0,
    downstream_sfp_buf: [max_phy_name]u8 = @splat(0),
    downstream_sfp_len: u8 = 0,

    pub fn driverName(p: *const Phy) []const u8 {
        return p.drvname_buf[0..p.drvname_len];
    }
    pub fn name(p: *const Phy) []const u8 {
        return p.name_buf[0..p.name_len];
    }
    pub fn upstreamSfpName(p: *const Phy) []const u8 {
        return p.upstream_sfp_buf[0..p.upstream_sfp_len];
    }
    pub fn downstreamSfpName(p: *const Phy) []const u8 {
        return p.downstream_sfp_buf[0..p.downstream_sfp_len];
    }
};

fn copyName(buf: *[max_phy_name]u8, len: *u8, a: codec.Attr) codec.Error!void {
    const s = a.asString();
    if (s.len > max_phy_name) return error.BadLength;
    @memcpy(buf[0..s.len], s);
    len.* = @intCast(s.len);
}

pub fn parsePhy(attr_bytes: []const u8) codec.Error!Phy {
    var out: Phy = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.PHY.HEADER => out.device = try header.parse(a.data),
        uapi.PHY.INDEX => out.index = try a.asU32(),
        uapi.PHY.DRVNAME => try copyName(&out.drvname_buf, &out.drvname_len, a),
        uapi.PHY.NAME => try copyName(&out.name_buf, &out.name_len, a),
        uapi.PHY.UPSTREAM_TYPE => out.upstream_type = try a.asU32(),
        uapi.PHY.UPSTREAM_INDEX => out.upstream_index = try a.asU32(),
        uapi.PHY.UPSTREAM_SFP_NAME => try copyName(&out.upstream_sfp_buf, &out.upstream_sfp_len, a),
        uapi.PHY.DOWNSTREAM_SFP_NAME => try copyName(&out.downstream_sfp_buf, &out.downstream_sfp_len, a),
        else => {},
    };
    return out;
}

pub fn buildPhy(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: header.Target) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.PHY_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.PHY.HEADER, .{ .target = target });
    return header.finishRequest(gpa, &msg, h);
}

// ── tunnel offload info ────────────────────────────────────────────────────

/// Most tables and entries per table one reply is decoded for (the kernel's tables are a handful, each of a few
/// entries); more is `BadLength`.
pub const max_tables = 16;
pub const max_entries = 64;

pub const TunnelEntry = struct {
    /// UDP port, host order (the kernel sends it in network order).
    port: ?u16 = null,
    /// The tunnel type's bit index: 0 VXLAN, 1 GENEVE, 2 VXLAN-GPE.
    tunnel_type: ?u32 = null,
};

pub const TunnelTable = struct {
    /// How many ports the table can hold.
    size: ?u32 = null,
    /// The tunnel types the table accepts (a bitset; named in a verbose reply).
    types: ?bitset.Bitset = null,
    entries: []TunnelEntry = &.{},
};

/// `ETHTOOL_MSG_TUNNEL_INFO_GET` reply. Owns its tables — free with `deinit`.
pub const TunnelInfo = struct {
    device: header.Device = .{},
    tables: []TunnelTable = &.{},

    pub fn deinit(t: *TunnelInfo, gpa: std.mem.Allocator) void {
        for (t.tables) |*tb| {
            if (tb.types) |*b| b.deinit(gpa);
            gpa.free(tb.entries);
        }
        gpa.free(t.tables);
        t.* = .{};
    }
};

fn parseEntry(data: []const u8) codec.Error!TunnelEntry {
    var out: TunnelEntry = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        uapi.TUNNEL_UDP_ENTRY.PORT => out.port = try a.asBe16(),
        uapi.TUNNEL_UDP_ENTRY.TYPE => out.tunnel_type = try a.asU32(),
        else => {},
    };
    return out;
}

fn parseTable(gpa: std.mem.Allocator, data: []const u8) Error!TunnelTable {
    var out: TunnelTable = .{};
    errdefer {
        if (out.types) |*b| b.deinit(gpa);
        gpa.free(out.entries);
    }
    var entries: std.ArrayList(TunnelEntry) = .empty;
    errdefer entries.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        uapi.TUNNEL_UDP_TABLE.SIZE => out.size = try a.asU32(),
        uapi.TUNNEL_UDP_TABLE.TYPES => {
            if (out.types != null) return error.BadLength;
            out.types = try bitset.parse(gpa, a.data);
        },
        uapi.TUNNEL_UDP_TABLE.ENTRY => {
            if (entries.items.len >= max_entries) return error.BadLength;
            try entries.append(gpa, try parseEntry(a.data));
        },
        else => {},
    };
    out.entries = try entries.toOwnedSlice(gpa);
    return out;
}

pub fn parseTunnelInfo(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!TunnelInfo {
    var out: TunnelInfo = .{};
    errdefer out.deinit(gpa);
    var tables: std.ArrayList(TunnelTable) = .empty;
    errdefer {
        for (tables.items) |*tb| {
            if (tb.types) |*b| b.deinit(gpa);
            gpa.free(tb.entries);
        }
        tables.deinit(gpa);
    }
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.TUNNEL_INFO.HEADER => out.device = try header.parse(a.data),
        uapi.TUNNEL_INFO.UDP_PORTS => {
            var jt: codec.AttrIterator = .{ .buf = a.data };
            while (try jt.next()) |ta| {
                if (ta.type != uapi.TUNNEL_UDP.TABLE) continue;
                if (tables.items.len >= max_tables) return error.BadLength;
                var tb = try parseTable(gpa, ta.data);
                tables.append(gpa, tb) catch |e| {
                    if (tb.types) |*b| b.deinit(gpa);
                    gpa.free(tb.entries);
                    return e;
                };
            }
        },
        else => {},
    };
    out.tables = try tables.toOwnedSlice(gpa);
    return out;
}

pub fn buildTunnelInfo(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: header.Target, form: header.BitsetForm) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.TUNNEL_INFO_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.TUNNEL_INFO.HEADER, .{ .target = target, .compact_bitsets = form.compactFlag() });
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parsePhy decodes the names, the index and the upstream" {
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try codec.appendAttrU32(gpa, &l, uapi.PHY.INDEX, 2);
    try codec.appendAttrString(gpa, &l, uapi.PHY.DRVNAME, "Micrel KSZ9031");
    try codec.appendAttrString(gpa, &l, uapi.PHY.NAME, "eth0:02");
    try codec.appendAttrU32(gpa, &l, uapi.PHY.UPSTREAM_TYPE, 1);
    try codec.appendAttrU32(gpa, &l, uapi.PHY.UPSTREAM_INDEX, 1);
    try codec.appendAttrString(gpa, &l, uapi.PHY.DOWNSTREAM_SFP_NAME, "sfp0");
    const p = try parsePhy(l.items);
    try testing.expectEqual(@as(?u32, 2), p.index);
    try testing.expectEqualStrings("Micrel KSZ9031", p.driverName());
    try testing.expectEqualStrings("eth0:02", p.name());
    try testing.expectEqual(@as(?u32, 1), p.upstream_type);
    try testing.expectEqual(@as(?u32, 1), p.upstream_index);
    try testing.expectEqualStrings("sfp0", p.downstreamSfpName());
    try testing.expectEqual(@as(usize, 0), p.upstreamSfpName().len);
    var long: std.ArrayList(u8) = .empty;
    defer long.deinit(gpa);
    try codec.appendAttrString(gpa, &long, uapi.PHY.NAME, &@as([100]u8, @splat('x')));
    try testing.expectError(error.BadLength, parsePhy(long.items));
    const msg = try buildPhy(gpa, 23, 1, .byName("eth0"));
    defer gpa.free(msg);
    try testing.expectEqual(uapi.MSG.PHY_GET, msg[16]);
}

test "parseTunnelInfo decodes tables with a size, a type set and big-endian ports" {
    const gpa = testing.allocator;
    var entry1: std.ArrayList(u8) = .empty;
    defer entry1.deinit(gpa);
    try codec.appendAttr(gpa, &entry1, uapi.TUNNEL_UDP_ENTRY.PORT, &.{ 0x12, 0xb5 }); // 4789 (VXLAN)
    try codec.appendAttrU32(gpa, &entry1, uapi.TUNNEL_UDP_ENTRY.TYPE, 0);
    var entry2: std.ArrayList(u8) = .empty;
    defer entry2.deinit(gpa);
    try codec.appendAttr(gpa, &entry2, uapi.TUNNEL_UDP_ENTRY.PORT, &.{ 0x17, 0xc1 }); // 6081 (Geneve)
    try codec.appendAttrU32(gpa, &entry2, uapi.TUNNEL_UDP_ENTRY.TYPE, 1);
    var table: std.ArrayList(u8) = .empty;
    defer table.deinit(gpa);
    try codec.appendAttrU32(gpa, &table, uapi.TUNNEL_UDP_TABLE.SIZE, 4);
    try codec.appendAttr(gpa, &table, uapi.TUNNEL_UDP_TABLE.ENTRY, entry1.items);
    try codec.appendAttr(gpa, &table, uapi.TUNNEL_UDP_TABLE.ENTRY, entry2.items);
    var ports: std.ArrayList(u8) = .empty;
    defer ports.deinit(gpa);
    try codec.appendAttr(gpa, &ports, uapi.TUNNEL_UDP.TABLE, table.items);
    try codec.appendAttr(gpa, &ports, uapi.TUNNEL_UDP.TABLE, table.items);
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try codec.appendAttr(gpa, &l, uapi.TUNNEL_INFO.UDP_PORTS, ports.items);
    var t = try parseTunnelInfo(gpa, l.items);
    defer t.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), t.tables.len);
    try testing.expectEqual(@as(?u32, 4), t.tables[0].size);
    try testing.expectEqual(@as(usize, 2), t.tables[1].entries.len);
    try testing.expectEqual(@as(?u16, 4789), t.tables[0].entries[0].port);
    try testing.expectEqual(@as(?u16, 6081), t.tables[0].entries[1].port);
    try testing.expectEqual(@as(?u32, 1), t.tables[0].entries[1].tunnel_type);

    // A port that is not two bytes is refused, and the half-built result does not leak (testing.allocator checks).
    var bad_entry: std.ArrayList(u8) = .empty;
    defer bad_entry.deinit(gpa);
    try codec.appendAttr(gpa, &bad_entry, uapi.TUNNEL_UDP_ENTRY.PORT, &.{ 1, 2, 3 });
    var bad_table: std.ArrayList(u8) = .empty;
    defer bad_table.deinit(gpa);
    try codec.appendAttr(gpa, &bad_table, uapi.TUNNEL_UDP_TABLE.ENTRY, entry1.items);
    try codec.appendAttr(gpa, &bad_table, uapi.TUNNEL_UDP_TABLE.ENTRY, bad_entry.items);
    var bad_ports: std.ArrayList(u8) = .empty;
    defer bad_ports.deinit(gpa);
    try codec.appendAttr(gpa, &bad_ports, uapi.TUNNEL_UDP.TABLE, bad_table.items);
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try codec.appendAttr(gpa, &bad, uapi.TUNNEL_INFO.UDP_PORTS, bad_ports.items);
    try testing.expectError(error.BadLength, parseTunnelInfo(gpa, bad.items));
    var e = try parseTunnelInfo(gpa, &.{});
    defer e.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), e.tables.len);
    const msg = try buildTunnelInfo(gpa, 23, 1, .byIndex(2), .compact);
    defer gpa.free(msg);
    try testing.expectEqual(uapi.MSG.TUNNEL_INFO_GET, msg[16]);
}
