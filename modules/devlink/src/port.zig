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
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

pub const Error = error{ OutOfMemory, InvalidRequest };

/// Longest hardware address a function carries (`MAX_ADDR_LEN`).
pub const max_hw_addr = 32;

/// The contents of a port's `DEVLINK_ATTR_PORT_FUNCTION` nest: the PCI function (VF or subfunction) behind the
/// port. Every field is optional; the kernel reports what the driver implements.
pub const Function = struct {
    hw_addr_buf: [max_hw_addr]u8 = @splat(0),
    hw_addr_len: u8 = 0,
    has_hw_addr: bool = false,
    state: ?uapi.FnState = null,
    opstate: ?uapi.FnOpstate = null,
    /// The capability bits that are set (`uapi.FN_CAP`); the selector the kernel echoes is not kept.
    caps: ?u32 = null,
    max_io_eqs: ?u32 = null,
    /// The function has a devlink instance of its own (a subfunction's auxiliary device).
    has_devlink: bool = false,

    pub fn hwAddr(f: *const Function) ?[]const u8 {
        return if (f.has_hw_addr) f.hw_addr_buf[0..f.hw_addr_len] else null;
    }

    pub fn hasCap(f: Function, cap: u32) bool {
        return ((f.caps orelse 0) & cap) != 0;
    }
};

/// Decode the contents of a `DEVLINK_ATTR_PORT_FUNCTION` nest. Unknown attributes are skipped.
pub fn parseFunction(nest_bytes: []const u8) codec.Error!Function {
    var f: Function = .{};
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.FN_ATTR.HW_ADDR => {
            if (a.data.len > max_hw_addr) return error.BadLength;
            @memcpy(f.hw_addr_buf[0..a.data.len], a.data);
            f.hw_addr_len = @intCast(a.data.len);
            f.has_hw_addr = true;
        },
        uapi.FN_ATTR.STATE => f.state = @fromBackingInt(@intCast(try a.asU8())),
        uapi.FN_ATTR.OPSTATE => f.opstate = @fromBackingInt(@intCast(try a.asU8())),
        uapi.FN_ATTR.CAPS => {
            // struct nla_bitfield32 { u32 value; u32 selector; }
            if (a.data.len != 8) return error.BadLength;
            f.caps = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        uapi.FN_ATTR.MAX_IO_EQS => f.max_io_eqs = try a.asU32(),
        uapi.FN_ATTR.DEVLINK => f.has_devlink = true,
        else => {},
    };
    return f;
}

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
    /// The port carries a `DEVLINK_ATTR_PORT_FUNCTION` nest.
    has_function: bool = false,
    /// The decoded nest (hardware address, state, capabilities, ...), when the port has one.
    function: ?Function = null,

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
        uapi.ATTR.PORT_TYPE => p.type = @fromBackingInt(@intCast(try a.asU16())),
        uapi.ATTR.PORT_DESIRED_TYPE => p.desired_type = @fromBackingInt(@intCast(try a.asU16())),
        uapi.ATTR.PORT_FLAVOUR => p.flavour = @fromBackingInt(@intCast(try a.asU16())),
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
        uapi.ATTR.PORT_FUNCTION => {
            p.has_function = true;
            p.function = try parseFunction(a.data);
        },
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
    try codec.appendAttrU16(gpa, list, uapi.ATTR.PORT_TYPE, @backingInt(t));
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

/// What a `PORT_SET` can change in a port's function (`devlink port function set`). At least one field.
pub const FunctionSet = struct {
    /// The function's hardware (MAC) address, 1..32 bytes.
    hw_addr: ?[]const u8 = null,
    /// Activate or deactivate the function (`.active`, `.inactive`).
    state: ?uapi.FnState = null,
    /// Capability bits to change: the bits of `selector` are set to the matching bits of `value`.
    caps: ?struct { value: u32, selector: u32 } = null,
    /// How many IO event queues the function may use.
    max_io_eqs: ?u32 = null,
};

/// Attributes of a `DEVLINK_CMD_PORT_SET` that changes the port's function: the port handle and a
/// `DEVLINK_ATTR_PORT_FUNCTION` nest. Needs **CAP_NET_ADMIN**. Refused when nothing is set, when a state is not
/// `inactive`/`active`, when the address is empty or longer than 32 bytes, or when `caps.value` has bits outside
/// `caps.selector` (the kernel's bitfield32 validation).
pub fn appendSetFunction(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    p: handle.PortHandle,
    f: FunctionSet,
) Error!void {
    if (f.hw_addr == null and f.state == null and f.caps == null and f.max_io_eqs == null) return error.InvalidRequest;
    if (f.hw_addr) |a| if (a.len == 0 or a.len > max_hw_addr) return error.InvalidRequest;
    if (f.state) |s| if (s != .inactive and s != .active) return error.InvalidRequest;
    if (f.caps) |c| if (c.value & ~c.selector != 0) return error.InvalidRequest;
    try handle.appendPort(gpa, list, p);
    const nest = try codec.nestBegin(gpa, list, uapi.ATTR.PORT_FUNCTION);
    if (f.hw_addr) |a| try appendBytes(gpa, list, uapi.FN_ATTR.HW_ADDR, a);
    if (f.state) |s| try codec.appendAttrU8(gpa, list, uapi.FN_ATTR.STATE, @backingInt(s));
    if (f.caps) |c| {
        var bf: [8]u8 = undefined;
        std.mem.writeInt(u32, bf[0..4], c.value, native_endian);
        std.mem.writeInt(u32, bf[4..8], c.selector, native_endian);
        try appendBytes(gpa, list, uapi.FN_ATTR.CAPS, &bf);
    }
    if (f.max_io_eqs) |n| try codec.appendAttrU32(gpa, list, uapi.FN_ATTR.MAX_IO_EQS, n);
    codec.nestEnd(list, nest) catch return error.InvalidRequest;
}

fn appendBytes(gpa: std.mem.Allocator, list: *std.ArrayList(u8), attr_type: u16, bytes: []const u8) Error!void {
    codec.appendAttr(gpa, list, attr_type, bytes) catch |e| switch (e) {
        error.AttrTooLong => return error.InvalidRequest,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// A new subfunction port (`devlink port add <dev> flavour pcisf pfnum N [sfnum M] [controller C]`).
pub const NewPort = struct {
    /// The PCI physical function the subfunction belongs to.
    pf_number: u16,
    /// The subfunction number; null lets the driver pick one when it can.
    sf_number: ?u32 = null,
    /// The controller (0 = the local host).
    controller: ?u32 = null,
    /// The wanted port index; null lets the kernel assign it.
    index: ?u32 = null,
};

/// Attributes of a `DEVLINK_CMD_PORT_NEW`: the device handle and the port's flavour (always a PCI subfunction, the
/// one flavour the kernel's `port_new` creates), PF number and optional SF number, controller and index. Needs
/// **CAP_NET_ADMIN**; the reply is the new port.
pub fn appendNewPort(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    n: NewPort,
) Error!void {
    try handle.append(gpa, list, h);
    try codec.appendAttrU16(gpa, list, uapi.ATTR.PORT_FLAVOUR, @backingInt(uapi.PortFlavour.pci_sf));
    try codec.appendAttrU16(gpa, list, uapi.ATTR.PORT_PCI_PF_NUMBER, n.pf_number);
    if (n.sf_number) |s| try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_PCI_SF_NUMBER, s);
    if (n.controller) |c| try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_CONTROLLER_NUMBER, c);
    if (n.index) |i| try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_INDEX, i);
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

/// Build a `DEVLINK_CMD_PORT_SET` that changes the port's function — what `Devlink.setPortFunction` sends. Needs
/// **CAP_NET_ADMIN**.
pub fn buildSetPortFunction(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    p: handle.PortHandle,
    f: FunctionSet,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.PORT_SET, false);
    errdefer b.deinit();
    try appendSetFunction(gpa, &b.list, p, f);
    return b.finish();
}

/// Build a `DEVLINK_CMD_PORT_NEW` — what `Devlink.newPort` sends. Needs **CAP_NET_ADMIN**.
pub fn buildNewPort(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    n: NewPort,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.PORT_NEW, false);
    errdefer b.deinit();
    try appendNewPort(gpa, &b.list, h, n);
    return b.finish();
}

/// Build a `DEVLINK_CMD_PORT_DEL` — what `Devlink.delPort` sends. Needs **CAP_NET_ADMIN**; the port must be a
/// subfunction in the inactive, detached state.
pub fn buildDelPort(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    p: handle.PortHandle,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.PORT_DEL, false);
    errdefer b.deinit();
    try handle.appendPort(gpa, &b.list, p);
    return b.finish();
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

/// Build a reply resembling one physical port of an mlx5 card.
fn buildPortReply(gpa: std.mem.Allocator, list: *std.ArrayList(u8)) !void {
    try handle.append(gpa, list, .pci("0000:65:00.0"));
    try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_INDEX, 1);
    try codec.appendAttrU16(gpa, list, uapi.ATTR.PORT_TYPE, @backingInt(uapi.PortType.eth));
    try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_NETDEV_IFINDEX, 4);
    try codec.appendAttrString(gpa, list, uapi.ATTR.PORT_NETDEV_NAME, "enp101s0f0np0");
    try codec.appendAttrU16(gpa, list, uapi.ATTR.PORT_FLAVOUR, @backingInt(uapi.PortFlavour.physical));
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
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_TYPE, @backingInt(uapi.PortType.notset));
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_FLAVOUR, @backingInt(uapi.PortFlavour.pci_vf));
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_PCI_PF_NUMBER, 0);
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_PCI_VF_NUMBER, 3);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_CONTROLLER_NUMBER, 0);
    try codec.appendAttrU8(gpa, &list, uapi.ATTR.PORT_EXTERNAL, 0);
    const fn_nest = try codec.nestBegin(gpa, &list, uapi.ATTR.PORT_FUNCTION);
    try codec.nestEnd(&list, fn_nest);

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
    try testing.expectEqual(@as(u16, 250), @backingInt(p.flavour.?));
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
    try codec.appendAttrString(gpa, &list, uapi.ATTR.PORT_NETDEV_NAME, strRepeat("n", uapi.ifnamesize) ++ "x");
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

/// PORT_GET reply attribute lists for `fuzzPort`, in the format `Smith.slice` reads (see
/// `testkit.fuzz`): a little-endian u32 length, then the frame.
///
/// ⭐ Built at run time by the value tests' own builders and this module's own
/// encoders rather than quoted as hex. A devlink attribute is a netlink TLV,
/// whose length and scalars are HOST byte order, so a hex corpus would be a
/// little-endian one and the counts pinned below would be false on a
/// big-endian target instead of failing there.
const Corpus = struct {
    scratch: [4096]u8 = undefined,
    store: [4096]u8 = undefined,
    used: usize = 0,
    entries: [8][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *Corpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *Corpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        // The physical port of an mlx5 card, netdev and all.
        var physical: std.ArrayList(u8) = .empty;
        try buildPortReply(gpa, &physical);
        self.push(physical.items);

        // A pci_vf representor: no netdev, a PORT_FUNCTION nest, and the
        // flavour-specific PCI numbers.
        var vf: std.ArrayList(u8) = .empty;
        try handle.append(gpa, &vf, .pci("0000:65:00.0"));
        try codec.appendAttrU32(gpa, &vf, uapi.ATTR.PORT_INDEX, 65535);
        try codec.appendAttrU16(gpa, &vf, uapi.ATTR.PORT_TYPE, @backingInt(uapi.PortType.notset));
        try codec.appendAttrU16(gpa, &vf, uapi.ATTR.PORT_FLAVOUR, @backingInt(uapi.PortFlavour.pci_vf));
        try codec.appendAttrU16(gpa, &vf, uapi.ATTR.PORT_PCI_PF_NUMBER, 0);
        try codec.appendAttrU16(gpa, &vf, uapi.ATTR.PORT_PCI_VF_NUMBER, 3);
        try codec.appendAttrU32(gpa, &vf, uapi.ATTR.PORT_CONTROLLER_NUMBER, 0);
        try codec.appendAttrU8(gpa, &vf, uapi.ATTR.PORT_EXTERNAL, 0);
        const fn_nest = try codec.nestBegin(gpa, &vf, uapi.ATTR.PORT_FUNCTION);
        try codec.nestEnd(&vf, fn_nest);
        self.push(vf.items);

        // One lane of a split port.
        var split: std.ArrayList(u8) = .empty;
        try handle.append(gpa, &split, .pci("0000:65:00.0"));
        try codec.appendAttrU32(gpa, &split, uapi.ATTR.PORT_INDEX, 2);
        try codec.appendAttrU32(gpa, &split, uapi.ATTR.PORT_NUMBER, 0);
        try codec.appendAttrU32(gpa, &split, uapi.ATTR.PORT_SPLIT_SUBPORT_NUMBER, 1);
        try codec.appendAttrU32(gpa, &split, uapi.ATTR.PORT_SPLIT_GROUP, 0);
        try codec.appendAttrU32(gpa, &split, uapi.ATTR.PORT_SPLIT_COUNT, 4);
        self.push(split.items);

        // A bare handle: every optional absent.
        var bare: std.ArrayList(u8) = .empty;
        try handle.append(gpa, &bare, .{ .bus = "netdevsim", .dev = "netdevsim1" });
        self.push(bare.items);

        // ── the refusals ───────────────────────────────────────────────────
        // An attribute header declaring 0x40 octets over a 2-octet buffer.
        self.push(&[_]u8{ 0x40, 0x00 });
        // A DEV_NAME longer than the handle can hold: rejected, not truncated.
        var oversize: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &oversize, uapi.ATTR.DEV_NAME, &@as([65]u8, @splat('x')));
        self.push(oversize.items);
        // PORT_INDEX with a 2-octet payload where a u32 belongs.
        var narrow: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &narrow, uapi.ATTR.PORT_INDEX, &.{ 1, 0 });
        self.push(narrow.items);

        return self.entries[0..self.n];
    }
};

const fz = @import("fuzz_test.zig");
const PortMark = fz.Marker(enum { decoded, refused });

test "fuzz: port decoding never crashes" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzPortSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: DEVLINK_FUZZ (port)" {
    try fz.fuzz_driver.run(fuzzPort, .{ .prefix = "DEVLINK_FUZZ", .name = "devlink-port" });
}

test "fuzz harness: port, 500 seeds, reaches every outcome" {
    try PortMark.reach(fuzzPort, "devlink-port", 500);
}

fn fuzzPortSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzPort(std.testing.Smith, smith, testing.allocator);
}

fn fuzzPort(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var corpus: Corpus = .{};
    const entries = corpus.build() catch return;
    var buf: [256]u8 = undefined;
    // ⚠ One `src.slice` call, never `src.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `parse` was handed an empty attribute
    // list with the reply sitting unread in `buf`.
    //
    // ⛔ And it looked HEALTHIER that way. Measured 2026-09-07 over the corpus
    // above: **0 of 7 seeds non-empty and 7 of 7 "decoded" before, 7 of 7
    // non-empty and 4 decoded after.** An empty attribute list is a legal
    // devlink reply — every field of a port is optional — so `parse("")`
    // succeeds, and the collapsed harness scored a perfect 7 of 7 while never
    // once entering the TLV walk.
    const len: usize = fz.drawInput(S, src, &buf, entries);
    if (parse(buf[0..len])) |p| {
        std.mem.doNotOptimizeAway(&p);
        PortMark.mark(.decoded);
    } else |_| PortMark.mark(.refused);
}

test "corpus: every port seed reaches the parser, and the decoded count is pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over
    // the SAME corpus the harness gets. `nonempty` is the reach claim and the
    // only check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. The parse counts
    // are pinned rather than asserted `> 0`: a corpus of nothing but refusals
    // would score full marks on reach while exercising only the error path.
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var decoded: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (parse(buf[0..len])) |_| {
            decoded += 1;
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 4), decoded);
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

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

test "parse decodes a subfunction's function nest" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .pci("0000:65:00.0"));
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_INDEX, 0x10001);
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.PORT_FLAVOUR, @backingInt(uapi.PortFlavour.pci_sf));
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_PCI_SF_NUMBER, 88);
    const nest = try codec.nestBegin(gpa, &list, uapi.ATTR.PORT_FUNCTION);
    try codec.appendAttr(gpa, &list, uapi.FN_ATTR.HW_ADDR, &.{ 0x00, 0x00, 0x00, 0x00, 0x88, 0x88 });
    try codec.appendAttrU8(gpa, &list, uapi.FN_ATTR.STATE, 1);
    try codec.appendAttrU8(gpa, &list, uapi.FN_ATTR.OPSTATE, 1);
    var bf: [8]u8 = undefined;
    std.mem.writeInt(u32, bf[0..4], uapi.FN_CAP.ROCE | uapi.FN_CAP.IPSEC_CRYPTO, native_endian);
    std.mem.writeInt(u32, bf[4..8], 0xf, native_endian);
    try codec.appendAttr(gpa, &list, uapi.FN_ATTR.CAPS, &bf);
    try codec.appendAttrU32(gpa, &list, uapi.FN_ATTR.MAX_IO_EQS, 12);
    const dl = try codec.nestBegin(gpa, &list, uapi.FN_ATTR.DEVLINK);
    try codec.nestEnd(&list, dl);
    try codec.nestEnd(&list, nest);

    const p = try parse(list.items);
    try testing.expect(p.has_function);
    const f = p.function.?;
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0x88, 0x88 }, f.hwAddr().?);
    try testing.expectEqual(@as(?uapi.FnState, .active), f.state);
    try testing.expectEqual(@as(?uapi.FnOpstate, .attached), f.opstate);
    try testing.expect(f.hasCap(uapi.FN_CAP.ROCE));
    try testing.expect(!f.hasCap(uapi.FN_CAP.MIGRATABLE));
    try testing.expect(f.hasCap(uapi.FN_CAP.IPSEC_CRYPTO));
    try testing.expectEqual(@as(?u32, 12), f.max_io_eqs);
    try testing.expect(f.has_devlink);

    // An empty nest decodes to an empty function; a malformed one is an error, never a panic.
    try testing.expect((try parseFunction(&.{})).state == null);
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try codec.appendAttr(gpa, &bad, uapi.FN_ATTR.CAPS, &.{ 1, 2, 3 });
    try testing.expectError(error.BadLength, parseFunction(bad.items));
    var long: std.ArrayList(u8) = .empty;
    defer long.deinit(gpa);
    try codec.appendAttr(gpa, &long, uapi.FN_ATTR.HW_ADDR, &@as([33]u8, @splat(1)));
    try testing.expectError(error.BadLength, parseFunction(long.items));
}

test "buildSetPortFunction sends the port handle and a function nest; refusals never reach the wire" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    const ph: handle.PortHandle = .{ .handle = .pci("0000:65:00.0"), .index = 0x10001 };
    const msg = try buildSetPortFunction(gpa, 0x19, 3, ph, .{
        .hw_addr = &.{ 0x02, 0, 0, 0, 0, 1 },
        .state = .active,
        .caps = .{ .value = uapi.FN_CAP.ROCE, .selector = uapi.FN_CAP.ROCE | uapi.FN_CAP.MIGRATABLE },
        .max_io_eqs = 8,
    });
    defer gpa.free(msg);
    const pl = try genl.splitPayload(msg[16..]);
    try testing.expectEqual(uapi.CMD.PORT_SET, pl.cmd);
    var it: codec.AttrIterator = .{ .buf = pl.attrs };
    var saw_fn = false;
    while (try it.next()) |a| {
        if (a.type == uapi.ATTR.PORT_INDEX) try testing.expectEqual(@as(u32, 0x10001), try a.asU32());
        if (a.type != uapi.ATTR.PORT_FUNCTION) continue;
        saw_fn = true;
        const f = try parseFunction(a.data);
        try testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0, 0, 1 }, f.hwAddr().?);
        try testing.expectEqual(@as(?uapi.FnState, .active), f.state);
        try testing.expectEqual(@as(?u32, uapi.FN_CAP.ROCE), f.caps);
        try testing.expectEqual(@as(?u32, 8), f.max_io_eqs);
        // The selector is on the wire next to the value.
        var jt = a.nested();
        while (try jt.next()) |x| if (x.type == uapi.FN_ATTR.CAPS) {
            try testing.expectEqual(uapi.FN_CAP.ROCE | uapi.FN_CAP.MIGRATABLE, std.mem.readInt(u32, x.data[4..8], native_endian));
        };
    }
    try testing.expect(saw_fn);

    try testing.expectError(error.InvalidRequest, buildSetPortFunction(gpa, 0x19, 3, ph, .{}));
    try testing.expectError(error.InvalidRequest, buildSetPortFunction(gpa, 0x19, 3, ph, .{ .hw_addr = &.{} }));
    try testing.expectError(error.InvalidRequest, buildSetPortFunction(gpa, 0x19, 3, ph, .{ .hw_addr = &@as([33]u8, @splat(1)) }));
    try testing.expectError(error.InvalidRequest, buildSetPortFunction(gpa, 0x19, 3, ph, .{ .state = @fromBackingInt(@intCast(2)) }));
    try testing.expectError(error.InvalidRequest, buildSetPortFunction(gpa, 0x19, 3, ph, .{ .caps = .{ .value = 2, .selector = 1 } }));
}

test "buildNewPort asks for a pci_sf port and buildDelPort names the port" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    const msg = try buildNewPort(gpa, 0x19, 4, .pci("0000:06:00.0"), .{ .pf_number = 0, .sf_number = 88, .controller = 1 });
    defer gpa.free(msg);
    const pl = try genl.splitPayload(msg[16..]);
    try testing.expectEqual(uapi.CMD.PORT_NEW, pl.cmd);
    const p = try parse(pl.attrs);
    try testing.expectEqualStrings("0000:06:00.0", p.handle.dev());
    try testing.expectEqual(@as(?uapi.PortFlavour, .pci_sf), p.flavour);
    try testing.expectEqual(@as(?u16, 0), p.pci_pf_number);
    try testing.expectEqual(@as(?u32, 88), p.pci_sf_number);
    try testing.expectEqual(@as(?u32, 1), p.controller_number);
    try testing.expectEqual(@as(?u32, null), p.index);

    const bare = try buildNewPort(gpa, 0x19, 4, .pci("0000:06:00.0"), .{ .pf_number = 2, .index = 77 });
    defer gpa.free(bare);
    const bp = try parse((try genl.splitPayload(bare[16..])).attrs);
    try testing.expectEqual(@as(?u32, null), bp.pci_sf_number);
    try testing.expectEqual(@as(?u32, 77), bp.index);

    const del = try buildDelPort(gpa, 0x19, 5, .{ .handle = .pci("0000:06:00.0"), .index = 0x10058 });
    defer gpa.free(del);
    const dpl = try genl.splitPayload(del[16..]);
    try testing.expectEqual(uapi.CMD.PORT_DEL, dpl.cmd);
    try testing.expectEqual(@as(?u32, 0x10058), (try parse(dpl.attrs)).index);
    try testing.expectError(error.InvalidRequest, buildNewPort(gpa, 0x19, 4, .{ .bus = "", .dev = "x" }, .{ .pf_number = 0 }));
}
