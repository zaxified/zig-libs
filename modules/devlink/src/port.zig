// SPDX-License-Identifier: MIT
//! Ports: `DEVLINK_CMD_PORT_GET` (dump and single), `PORT_SET`, `PORT_SPLIT`
//! and `PORT_UNSPLIT`.
//!
//! A devlink port is *not* a netdev. It is the switch-side object; whether a
//! netdev is attached to it, and what it is called, is one of its attributes
//! (`PORT_NETDEV_IFINDEX` / `PORT_NETDEV_NAME`) and is frequently absent — a
//! CPU port, an unused port or a `pci_vf` representor may have none.
//!
//! ```text
//! BUS_NAME / DEV_NAME / PORT_INDEX      the handle
//! PORT_TYPE               u16   what it is now      (notset/auto/eth/ib)
//! PORT_DESIRED_TYPE       u16   what it was asked to be
//! PORT_NETDEV_IFINDEX     u32  ─┐ the attached netdev, when there is one
//! PORT_NETDEV_NAME        str  ─┘
//! PORT_IBDEV_NAME         str   the attached InfiniBand device, likewise
//! PORT_FLAVOUR            u16   physical / cpu / dsa / pci_pf / pci_vf / …
//! PORT_NUMBER             u32   the front-panel port this belongs to
//! PORT_SPLIT_SUBPORT_NUMBER u32 which lane of it, when split
//! PORT_SPLIT_COUNT        u32   ─┐ splitting
//! PORT_SPLIT_GROUP        u32   ─┤
//! PORT_SPLITTABLE         u8    ─┤
//! PORT_LANES              u32   ─┘
//! PORT_PCI_PF_NUMBER      u16   ─┐ which PCI function this port represents;
//! PORT_PCI_VF_NUMBER      u16   ─┤ only the one matching FLAVOUR is present
//! PORT_PCI_SF_NUMBER      u32   ─┘
//! PORT_CONTROLLER_NUMBER  u32   which controller (0 = local host)
//! PORT_EXTERNAL           u8    the function is on an external host
//! PORT_FUNCTION           nest  hw addr / state / caps — see SPEC.md
//! ```
//!
//! ## Splitting
//!
//! `PORT_SPLIT` turns one 100G physical port into e.g. four 25G ones; the
//! kernel replies with an ACK and the new ports appear as *new* devlink ports
//! with the same `PORT_NUMBER` and distinct `PORT_SPLIT_SUBPORT_NUMBER`. The
//! split port itself disappears. `PORT_UNSPLIT` reverses it and takes only the
//! port handle — the count is implied.
//!
//! Both need **CAP_NET_ADMIN**, and both are rejected outright unless
//! `PORT_SPLITTABLE` is set on the port.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const handle = @import("handle.zig");
const request = @import("request.zig");
const genl = @import("genetlink");

pub const Error = error{ OutOfMemory, InvalidRequest };

/// One devlink port. Self-contained; no allocation.
pub const Port = struct {
    handle: handle.Owned = .{},
    index: ?u32 = null,
    type: ?uapi.PortType = null,
    desired_type: ?uapi.PortType = null,
    flavour: ?uapi.PortFlavour = null,

    netdev_ifindex: ?u32 = null,
    netdev_name_buf: [uapi.ifnamesize]u8 = @splat(0),
    netdev_name_len: u8 = 0,
    ibdev_name_buf: [uapi.name_max]u8 = @splat(0),
    ibdev_name_len: u8 = 0,

    /// The front-panel port number this (possibly split) port belongs to.
    number: ?u32 = null,
    split_subport_number: ?u32 = null,
    split_count: ?u32 = null,
    split_group: ?u32 = null,
    splittable: ?bool = null,
    lanes: ?u32 = null,

    pci_pf_number: ?u16 = null,
    pci_vf_number: ?u16 = null,
    pci_sf_number: ?u32 = null,
    controller_number: ?u32 = null,
    external: ?bool = null,
    /// The port carries a `DEVLINK_ATTR_PORT_FUNCTION` nest (hardware address,
    /// admin state, capabilities). Not decoded — see SPEC.md.
    has_function: bool = false,

    pub fn netdevName(p: *const Port) []const u8 {
        return p.netdev_name_buf[0..p.netdev_name_len];
    }

    pub fn ibdevName(p: *const Port) []const u8 {
        return p.ibdev_name_buf[0..p.ibdev_name_len];
    }

    /// The port handle, for feeding straight back into a `PORT_SET`/`SPLIT`.
    /// Borrows `p`; null when the reply carried no index.
    pub fn portHandle(p: *const Port) ?handle.PortHandle {
        return .{ .handle = p.handle.borrow(), .index = p.index orelse return null };
    }

    /// Is this port one lane of a split front-panel port? True exactly when
    /// the kernel gave it a subport number.
    pub fn isSplit(p: Port) bool {
        return p.split_subport_number != null;
    }
};

/// Decode one `DEVLINK_CMD_PORT_GET`/`PORT_NEW` message.
pub fn parse(attr_bytes: []const u8) codec.Error!Port {
    var p: Port = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.BUS_NAME => try uapi.copyName(&p.handle.bus_buf, &p.handle.bus_len, a),
        uapi.ATTR.DEV_NAME => try uapi.copyName(&p.handle.dev_buf, &p.handle.dev_len, a),
        uapi.ATTR.PORT_INDEX => p.index = try a.asU32(),
        uapi.ATTR.PORT_TYPE => p.type = @enumFromInt(try a.asU16()),
        uapi.ATTR.PORT_DESIRED_TYPE => p.desired_type = @enumFromInt(try a.asU16()),
        uapi.ATTR.PORT_FLAVOUR => p.flavour = @enumFromInt(try a.asU16()),
        uapi.ATTR.PORT_NETDEV_IFINDEX => p.netdev_ifindex = try a.asU32(),
        uapi.ATTR.PORT_NETDEV_NAME => try uapi.copyName(&p.netdev_name_buf, &p.netdev_name_len, a),
        uapi.ATTR.PORT_IBDEV_NAME => try uapi.copyName(&p.ibdev_name_buf, &p.ibdev_name_len, a),
        uapi.ATTR.PORT_NUMBER => p.number = try a.asU32(),
        uapi.ATTR.PORT_SPLIT_SUBPORT_NUMBER => p.split_subport_number = try a.asU32(),
        uapi.ATTR.PORT_SPLIT_COUNT => p.split_count = try a.asU32(),
        uapi.ATTR.PORT_SPLIT_GROUP => p.split_group = try a.asU32(),
        uapi.ATTR.PORT_SPLITTABLE => p.splittable = (try a.asU8()) != 0,
        uapi.ATTR.PORT_LANES => p.lanes = try a.asU32(),
        uapi.ATTR.PORT_PCI_PF_NUMBER => p.pci_pf_number = try a.asU16(),
        uapi.ATTR.PORT_PCI_VF_NUMBER => p.pci_vf_number = try a.asU16(),
        uapi.ATTR.PORT_PCI_SF_NUMBER => p.pci_sf_number = try a.asU32(),
        uapi.ATTR.PORT_CONTROLLER_NUMBER => p.controller_number = try a.asU32(),
        uapi.ATTR.PORT_EXTERNAL => p.external = (try a.asU8()) != 0,
        uapi.ATTR.PORT_FUNCTION => p.has_function = true,
        else => {},
    };
    return p;
}

// ── request builders ───────────────────────────────────────────────────────

/// Attributes of a `DEVLINK_CMD_PORT_SET`: the port handle, then the desired
/// type. Needs **CAP_NET_ADMIN**.
///
/// Setting `.notset` is what `devlink port set … type auto` does *not* do —
/// the CLI's `auto` maps to `PortType.auto`, and `notset` is a value the
/// kernel reports but does not accept. It is rejected here rather than sent.
pub fn appendSetType(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    p: handle.PortHandle,
    t: uapi.PortType,
) Error!void {
    if (t == .notset) return error.InvalidRequest;
    try handle.appendPort(gpa, list, p);
    try codec.appendAttrU16(gpa, list, uapi.ATTR.PORT_TYPE, @intFromEnum(t));
}

/// Attributes of a `DEVLINK_CMD_PORT_SPLIT`. `count` must be at least 2 —
/// splitting into one is not a split, and the kernel answers EINVAL.
pub fn appendSplit(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    p: handle.PortHandle,
    count: u32,
) Error!void {
    if (count < 2) return error.InvalidRequest;
    try handle.appendPort(gpa, list, p);
    try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_SPLIT_COUNT, count);
}

/// Attributes of a `DEVLINK_CMD_PORT_UNSPLIT` — the port handle and nothing
/// else.
pub fn appendUnsplit(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    p: handle.PortHandle,
) Error!void {
    try handle.appendPort(gpa, list, p);
}

// ── complete requests ──────────────────────────────────────────────────────
//
// The appenders above produce attributes; these produce a whole message the
// caller can hand to a socket. `client.zig` calls exactly these, so each
// command has one encoder rather than one here and a twin there.

/// Build a `DEVLINK_CMD_PORT_GET` **dump** — every port on the system, which
/// is what `Devlink.ports` sends. The `filter` that method takes is applied to
/// the *replies*, not to this message; see `client.zig`'s header.
pub fn buildPorts(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
) request.Error![]u8 {
    return request.buildSimple(gpa, family_id, seq, uapi.CMD.PORT_GET, true, null);
}

/// Build a `DEVLINK_CMD_PORT_GET` for one port — what `Devlink.port` sends.
pub fn buildPort(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    p: handle.PortHandle,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.PORT_GET, false);
    errdefer b.deinit();
    try handle.appendPort(gpa, &b.list, p);
    return b.finish();
}

/// Build a `DEVLINK_CMD_PORT_SET` — what `Devlink.setPortType` sends. Needs
/// **CAP_NET_ADMIN** on the socket that sends it.
pub fn buildSetPortType(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    p: handle.PortHandle,
    t: uapi.PortType,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.PORT_SET, false);
    errdefer b.deinit();
    try appendSetType(gpa, &b.list, p, t);
    return b.finish();
}

/// Build a `DEVLINK_CMD_PORT_SPLIT` — what `Devlink.splitPort` sends.
pub fn buildSplitPort(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    p: handle.PortHandle,
    count: u32,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.PORT_SPLIT, false);
    errdefer b.deinit();
    try appendSplit(gpa, &b.list, p, count);
    return b.finish();
}

/// Build a `DEVLINK_CMD_PORT_UNSPLIT` — what `Devlink.unsplitPort` sends.
pub fn buildUnsplitPort(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    p: handle.PortHandle,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.PORT_UNSPLIT, false);
    errdefer b.deinit();
    try appendUnsplit(gpa, &b.list, p);
    return b.finish();
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

/// Build a reply resembling one physical port of an mlx5 card.
fn buildPortReply(gpa: std.mem.Allocator, list: *std.ArrayList(u8)) !void {
    try handle.append(gpa, list, .pci("0000:65:00.0"));
    try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_INDEX, 1);
    try codec.appendAttrU16(gpa, list, uapi.ATTR.PORT_TYPE, @intFromEnum(uapi.PortType.eth));
    try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_NETDEV_IFINDEX, 4);
    try codec.appendAttrString(gpa, list, uapi.ATTR.PORT_NETDEV_NAME, "enp101s0f0np0");
    try codec.appendAttrU16(gpa, list, uapi.ATTR.PORT_FLAVOUR, @intFromEnum(uapi.PortFlavour.physical));
    try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_NUMBER, 0);
    try codec.appendAttrU8(gpa, list, uapi.ATTR.PORT_SPLITTABLE, 1);
    try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_LANES, 4);
}

test "parse decodes a physical port with an attached netdev" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try buildPortReply(gpa, &list);

    const p = try parse(list.items);
    try testing.expectEqualStrings("pci", p.handle.bus());
    try testing.expectEqual(@as(?u32, 1), p.index);
    try testing.expectEqual(@as(?uapi.PortType, .eth), p.type);
    try testing.expectEqual(@as(?uapi.PortFlavour, .physical), p.flavour);
    try testing.expectEqual(@as(?u32, 4), p.netdev_ifindex);
    try testing.expectEqualStrings("enp101s0f0np0", p.netdevName());
    try testing.expectEqual(@as(?u32, 0), p.number);
    try testing.expectEqual(@as(?bool, true), p.splittable);
    try testing.expectEqual(@as(?u32, 4), p.lanes);
    try testing.expect(!p.isSplit());

    const ph = p.portHandle().?;
    try testing.expectEqual(@as(u32, 1), ph.index);
    try testing.expectEqualStrings("0000:65:00.0", ph.handle.dev);
}

test "parse decodes a pci_vf representor with no netdev at all" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .pci("0000:65:00.0"));
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_INDEX, 65535);
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_TYPE, @intFromEnum(uapi.PortType.notset));
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_FLAVOUR, @intFromEnum(uapi.PortFlavour.pci_vf));
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_PCI_PF_NUMBER, 0);
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_PCI_VF_NUMBER, 3);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_CONTROLLER_NUMBER, 0);
    try codec.appendAttrU8(gpa, &list, uapi.ATTR.PORT_EXTERNAL, 0);
    const fn_nest = try codec.nestBegin(gpa, &list, uapi.ATTR.PORT_FUNCTION);
    codec.nestEnd(&list, fn_nest);

    const p = try parse(list.items);
    try testing.expectEqual(@as(?uapi.PortFlavour, .pci_vf), p.flavour);
    try testing.expectEqual(@as(?uapi.PortType, .notset), p.type);
    try testing.expectEqual(@as(usize, 0), p.netdevName().len);
    try testing.expectEqual(@as(?u32, null), p.netdev_ifindex);
    try testing.expectEqual(@as(?u16, 3), p.pci_vf_number);
    try testing.expectEqual(@as(?u16, 0), p.pci_pf_number);
    try testing.expectEqual(@as(?u32, null), p.pci_sf_number);
    try testing.expectEqual(@as(?bool, false), p.external);
    try testing.expect(p.has_function);
}

test "parse decodes a split lane" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .pci("0000:65:00.0"));
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_INDEX, 2);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_NUMBER, 0);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_SPLIT_SUBPORT_NUMBER, 1);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_SPLIT_GROUP, 0);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_SPLIT_COUNT, 4);

    const p = try parse(list.items);
    try testing.expect(p.isSplit());
    try testing.expectEqual(@as(?u32, 1), p.split_subport_number);
    try testing.expectEqual(@as(?u32, 4), p.split_count);
    // The subport belongs to the same front-panel port as its siblings.
    try testing.expectEqual(@as(?u32, 0), p.number);
}

test "parse: an unknown enum value survives instead of being rejected" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_FLAVOUR, 250);
    const p = try parse(list.items);
    try testing.expectEqual(@as(u16, 250), @intFromEnum(p.flavour.?));
}

test "parse: a wrong-width attribute is a typed error" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // PORT_TYPE is u16; a u32 payload must not be read as one.
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_TYPE, 2);
    try testing.expectError(error.BadLength, parse(list.items));

    // An over-long netdev name.
    list.clearRetainingCapacity();
    try codec.appendAttrString(gpa, &list, uapi.ATTR.PORT_NETDEV_NAME, "n" ** uapi.ifnamesize ++ "x");
    try testing.expectError(error.BadLength, parse(list.items));
}

test "appendSetType builds the bytes devlink port set emits" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendSetType(gpa, &list, .{ .handle = .pci("0000:00:00.0"), .index = 1 }, .eth);
    try testing.expectEqualSlices(u8, &.{
        0x06, 0x00, 0x04, 0x00, // len 6, PORT_TYPE
        0x02, 0x00, 0x00, 0x00, // eth, padded
    }, list.items[36..]);
}

test "appendSetType refuses `notset`, which the kernel would refuse anyway" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.InvalidRequest, appendSetType(
        gpa,
        &list,
        .{ .handle = .pci("0000:00:00.0"), .index = 1 },
        .notset,
    ));
}

test "appendSplit refuses a count below two" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const p: handle.PortHandle = .{ .handle = .pci("0000:00:00.0"), .index = 1 };
    try testing.expectError(error.InvalidRequest, appendSplit(gpa, &list, p, 0));
    try testing.expectError(error.InvalidRequest, appendSplit(gpa, &list, p, 1));
    try appendSplit(gpa, &list, p, 2);
    try testing.expectEqual(@as(usize, 44), list.items.len);
}

test "fuzz: port decoding never crashes" {
    try testing.fuzz({}, fuzzPort, .{});
}

fn fuzzPort(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    if (parse(buf[0..len])) |p| std.mem.doNotOptimizeAway(&p) else |_| {}
}

test "buildPorts dumps; buildPort names one port" {
    const gpa = testing.allocator;

    const dump = try buildPorts(gpa, 0x19, 3);
    defer gpa.free(dump);
    var it: codec.MessageIterator = .{ .buf = dump };
    var m = (try it.next()).?;
    try testing.expect(m.flags & codec.NLM_F_DUMP != 0);
    var p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.PORT_GET, p.cmd);
    try testing.expectEqual(@as(usize, 0), p.attrs.len);

    const one = try buildPort(gpa, 0x19, 3, .{ .handle = .pci("0000:65:00.0"), .index = 7 });
    defer gpa.free(one);
    it = .{ .buf = one };
    m = (try it.next()).?;
    try testing.expect(m.flags & codec.NLM_F_DUMP == 0);
    p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.PORT_GET, p.cmd);
    const decoded = try parse(p.attrs);
    try testing.expectEqual(@as(?u32, 7), decoded.index);
    try testing.expectEqualStrings("0000:65:00.0", decoded.handle.dev());
    // A GET names the port and says nothing about its type.
    try testing.expectEqual(@as(?uapi.PortType, null), decoded.type);
}

test "the port write builders carry the command and the argument" {
    const gpa = testing.allocator;
    const ph: handle.PortHandle = .{ .handle = .pci("0000:65:00.0"), .index = 2 };

    const set = try buildSetPortType(gpa, 0x19, 4, ph, .ib);
    defer gpa.free(set);
    var it: codec.MessageIterator = .{ .buf = set };
    var m = (try it.next()).?;
    var p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.PORT_SET, p.cmd);
    try testing.expectEqual(@as(?uapi.PortType, .ib), (try parse(p.attrs)).type);

    const split = try buildSplitPort(gpa, 0x19, 4, ph, 4);
    defer gpa.free(split);
    it = .{ .buf = split };
    m = (try it.next()).?;
    p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.PORT_SPLIT, p.cmd);
    try testing.expectEqual(@as(?u32, 4), (try parse(p.attrs)).split_count);

    // UNSPLIT takes the port handle and nothing else: no count, ever.
    const unsplit = try buildUnsplitPort(gpa, 0x19, 4, ph);
    defer gpa.free(unsplit);
    it = .{ .buf = unsplit };
    m = (try it.next()).?;
    p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.PORT_UNSPLIT, p.cmd);
    const u = try parse(p.attrs);
    try testing.expectEqual(@as(?u32, 2), u.index);
    try testing.expectEqual(@as(?u32, null), u.split_count);
}

test "the port builders refuse what the appenders refuse" {
    const gpa = testing.allocator;
    const ph: handle.PortHandle = .{ .handle = .pci("0000:65:00.0"), .index = 2 };
    try testing.expectError(error.InvalidRequest, buildSetPortType(gpa, 0x19, 1, ph, .notset));
    try testing.expectError(error.InvalidRequest, buildSplitPort(gpa, 0x19, 1, ph, 1));
    try testing.expectError(error.InvalidRequest, buildPort(gpa, 0x19, 1, .{
        .handle = .{ .bus = "", .dev = "d" },
        .index = 1,
    }));
}
