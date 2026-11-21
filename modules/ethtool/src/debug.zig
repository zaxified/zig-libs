// SPDX-License-Identifier: MIT
//! `DEBUG_GET`/`SET` — the driver's message level (`ethtool <dev>`'s "Current message level", `ethtool -s <dev>
//! msglvl <n>`), and `PHC_VCLOCKS_GET` — the PTP virtual clocks of a device's hardware clock (`ethtool -T`'s
//! sibling for the vclock indexes).
//!
//! The message level is a bitset of `NETIF_MSG_*` classes (`drv`, `probe`, `link`, `timer`, `ifdown`, `ifup`,
//! `rx_err`, `tx_err`, `tx_queued`, `intr`, `tx_done`, `rx_status`, `pktdata`, `hw`, `wol`). The kernel names the
//! bits in a verbose reply; a compact reply is the bare mask. Reading is unprivileged, a SET needs
//! **CAP_NET_ADMIN**.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");
const bitset = @import("bitset.zig");

pub const Error = codec.Error || error{OutOfMemory};
pub const BuildError = bitset.BuildError || header.Error;

/// `ETHTOOL_MSG_DEBUG_GET` reply. Owns its bitset — free with `deinit`.
pub const Debug = struct {
    device: header.Device = .{},
    /// One bit per message class.
    msgmask: ?bitset.Bitset = null,

    pub fn deinit(d: *Debug, gpa: std.mem.Allocator) void {
        if (d.msgmask) |*b| b.deinit(gpa);
        d.* = .{};
    }

    /// Is the message class called `name` on? Null when the reply carries no names (compact) or does not mention it.
    pub fn isOn(d: Debug, name: []const u8) ?bool {
        const m = d.msgmask orelse return null;
        return m.isSetByName(name);
    }
};

pub fn parseDebug(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!Debug {
    var out: Debug = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.DEBUG.HEADER => out.device = try header.parse(a.data),
        uapi.DEBUG.MSGMASK => {
            if (out.msgmask != null) return error.BadLength;
            out.msgmask = try bitset.parse(gpa, a.data);
        },
        else => {},
    };
    return out;
}

/// `ETHTOOL_MSG_DEBUG_SET` parameters: the classes to switch, by name **or** by index (not both:
/// `InvalidRequest`). Empty = a legal no-op.
pub const DebugSet = struct {
    msgmask: []const bitset.NamedValue = &.{},
    msgmask_by_index: []const bitset.IndexedValue = &.{},
};

pub fn buildDebug(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    form: header.BitsetForm,
) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.DEBUG_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.DEBUG.HEADER, .{ .target = target, .compact_bitsets = form.compactFlag() });
    return header.finishRequest(gpa, &msg, h);
}

pub fn buildSetDebug(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    target: header.Target,
    set: DebugSet,
) BuildError![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.DEBUG_SET, .seq = seq });
    try header.append(gpa, &msg, uapi.DEBUG.HEADER, .{ .target = target });
    try bitset.appendMasked(gpa, &msg, uapi.DEBUG.MSGMASK, set.msgmask_by_index, set.msgmask);
    return header.finishRequest(gpa, &msg, h);
}

// ── PHC virtual clocks ─────────────────────────────────────────────────────

/// Most virtual clocks one reply is read for (the kernel's own cap is lower; a longer array is `BadLength`).
pub const max_vclocks = 1024;

/// `ETHTOOL_MSG_PHC_VCLOCKS_GET` reply. Owns the index list — free with `deinit`.
pub const PhcVclocks = struct {
    device: header.Device = .{},
    /// The number of virtual clocks the kernel reports.
    num: ?u32 = null,
    /// The PHC indexes (`/dev/ptpN`) of those clocks.
    indexes: []i32 = &.{},

    pub fn deinit(p: *PhcVclocks, gpa: std.mem.Allocator) void {
        gpa.free(p.indexes);
        p.* = .{};
    }
};

pub fn parsePhcVclocks(gpa: std.mem.Allocator, attr_bytes: []const u8) Error!PhcVclocks {
    var out: PhcVclocks = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.PHC_VCLOCKS.HEADER => out.device = try header.parse(a.data),
        uapi.PHC_VCLOCKS.NUM => out.num = try a.asU32(),
        uapi.PHC_VCLOCKS.INDEX => {
            // `s32 index[num]`, host order, no per-element attribute.
            if (a.data.len % 4 != 0 or a.data.len / 4 > max_vclocks) return error.BadLength;
            if (out.indexes.len != 0) return error.BadLength;
            const list = try gpa.alloc(i32, a.data.len / 4);
            for (list, 0..) |*v, i| v.* = std.mem.readInt(i32, a.data[i * 4 ..][0..4], @import("builtin").cpu.arch.endian());
            out.indexes = list;
        },
        else => {},
    };
    return out;
}

pub fn buildPhcVclocks(gpa: std.mem.Allocator, family_id: u16, seq: u32, target: header.Target) header.Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(gpa);
    const h = try header.beginRequest(gpa, &msg, .{ .family_id = family_id, .cmd = uapi.MSG.PHC_VCLOCKS_GET, .seq = seq });
    try header.append(gpa, &msg, uapi.PHC_VCLOCKS.HEADER, .{ .target = target });
    return header.finishRequest(gpa, &msg, h);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

test "parsePhcVclocks reads the count and the s32 array; a ragged or repeated array is refused" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrU32(gpa, &list, uapi.PHC_VCLOCKS.NUM, 3);
    var idx: [12]u8 = undefined;
    std.mem.writeInt(i32, idx[0..4], 4, native_endian);
    std.mem.writeInt(i32, idx[4..8], 7, native_endian);
    std.mem.writeInt(i32, idx[8..12], -1, native_endian);
    try codec.appendAttr(gpa, &list, uapi.PHC_VCLOCKS.INDEX, &idx);
    var p = try parsePhcVclocks(gpa, list.items);
    defer p.deinit(gpa);
    try testing.expectEqual(@as(?u32, 3), p.num);
    try testing.expectEqualSlices(i32, &.{ 4, 7, -1 }, p.indexes);

    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try codec.appendAttr(gpa, &bad, uapi.PHC_VCLOCKS.INDEX, &.{ 1, 2, 3 });
    try testing.expectError(error.BadLength, parsePhcVclocks(gpa, bad.items));
    var twice: std.ArrayList(u8) = .empty;
    defer twice.deinit(gpa);
    try codec.appendAttr(gpa, &twice, uapi.PHC_VCLOCKS.INDEX, idx[0..4]);
    try codec.appendAttr(gpa, &twice, uapi.PHC_VCLOCKS.INDEX, idx[0..4]);
    try testing.expectError(error.BadLength, parsePhcVclocks(gpa, twice.items));
    var e = try parsePhcVclocks(gpa, &.{});
    defer e.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), e.indexes.len);
}

test "debug: a verbose reply names the classes; the set request carries a masked bitset; the get names the device" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    const get = try buildDebug(gpa, 23, 1, .byName("eth0"), .compact);
    defer gpa.free(get);
    try testing.expectEqual(uapi.MSG.DEBUG_GET, get[16]);
    var it: codec.AttrIterator = .{ .buf = get[20..] };
    const hdr = (try it.next()).?;
    try testing.expectEqual(uapi.DEBUG.HEADER, hdr.type);
    const dev = try header.parse(hdr.data);
    try testing.expectEqualStrings("eth0", dev.name());

    const set = try buildSetDebug(gpa, 23, 2, .byIndex(2), .{ .msgmask = &.{ .{ .name = "link", .on = true }, .{ .name = "hw", .on = false } } });
    defer gpa.free(set);
    try testing.expectEqual(uapi.MSG.DEBUG_SET, set[16]);
    var jt: codec.AttrIterator = .{ .buf = set[20..] };
    var saw_mask = false;
    while (try jt.next()) |a| if (a.type == uapi.DEBUG.MSGMASK) {
        saw_mask = true;
    };
    try testing.expect(saw_mask);
    try testing.expectError(error.InvalidRequest, buildSetDebug(gpa, 23, 2, .byIndex(2), .{
        .msgmask = &.{.{ .name = "link", .on = true }},
        .msgmask_by_index = &.{.{ .index = 1, .on = true }},
    }));

    // Parse of a reply carrying a verbose bitset: reuse the set message's bitset as the reply's.
    var reply: std.ArrayList(u8) = .empty;
    defer reply.deinit(gpa);
    try header.append(gpa, &reply, uapi.DEBUG.HEADER, .{ .target = .byIndex(2) });
    var d = try parseDebug(gpa, reply.items);
    defer d.deinit(gpa);
    try testing.expect(d.msgmask == null);
    try testing.expectEqual(@as(?bool, null), d.isOn("link"));
}
