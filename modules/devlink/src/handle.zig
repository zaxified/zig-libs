// SPDX-License-Identifier: MIT
//! The **handle** — the `DEVLINK_ATTR_BUS_NAME` + `DEVLINK_ATTR_DEV_NAME` pair
//! that names one devlink instance, and the `+ DEVLINK_ATTR_PORT_INDEX` triple
//! that names one of its ports.
//!
//! ```text
//! pci/0000:65:00.0        bus_name = "pci", dev_name = "0000:65:00.0"
//! pci/0000:65:00.0/3      … port_index = 3
//! netdevsim/netdevsim1    bus_name = "netdevsim"
//! auxiliary/mlx5_core.eth.0
//! ```
//!
//! This is devlink's answer to ethtool's per-message `*_HEADER` nest, and it is
//! deliberately *not* a nest: the two strings sit as ordinary top-level
//! attributes of every message, request and reply alike. There is no ifindex
//! form — devlink identifies a device by its bus address, not by a netdev, and
//! a devlink instance may have no netdev at all.
//!
//! Two types, for two lifetimes. `Handle` borrows its strings and is what a
//! caller passes *in*; `Owned` copies them into inline buffers and is what a
//! decoder hands *back*, so a decoded device outlives the socket's receive
//! buffer.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");

pub const Error = error{ OutOfMemory, InvalidRequest };

/// A devlink instance, by borrowed strings. Cheap to pass by value; the slices
/// must outlive the request that is built from it.
pub const Handle = struct {
    bus: []const u8,
    dev: []const u8,

    /// A PCI-bus handle: `Handle.pci("0000:65:00.0")`.
    pub fn pci(addr: []const u8) Handle {
        return .{ .bus = "pci", .dev = addr };
    }

    /// Parse the `bus/dev` form the `devlink` CLI takes. The returned slices
    /// **borrow `s`**. A trailing `/port` is rejected here — use
    /// `PortHandle.parse` for that — so a port string cannot silently be taken
    /// for a device.
    pub fn parse(s: []const u8) error{InvalidHandle}!Handle {
        const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidHandle;
        const h: Handle = .{ .bus = s[0..slash], .dev = s[slash + 1 ..] };
        if (std.mem.indexOfScalar(u8, h.dev, '/') != null) return error.InvalidHandle;
        h.validate() catch return error.InvalidHandle;
        return h;
    }

    /// Reject locally what the kernel would reject with EINVAL, and what would
    /// not fit an `Owned` on the way back.
    pub fn validate(h: Handle) error{InvalidRequest}!void {
        if (h.bus.len == 0 or h.bus.len > uapi.bus_name_max) return error.InvalidRequest;
        if (h.dev.len == 0 or h.dev.len > uapi.dev_name_max) return error.InvalidRequest;
        if (std.mem.indexOfScalar(u8, h.bus, 0) != null) return error.InvalidRequest;
        if (std.mem.indexOfScalar(u8, h.dev, 0) != null) return error.InvalidRequest;
    }

    pub fn eql(a: Handle, b: Handle) bool {
        return std.mem.eql(u8, a.bus, b.bus) and std.mem.eql(u8, a.dev, b.dev);
    }
};

/// One port of a devlink instance.
pub const PortHandle = struct {
    handle: Handle,
    index: u32,

    /// Parse the `bus/dev/index` form the `devlink` CLI takes. The strings
    /// borrow `s`.
    pub fn parse(s: []const u8) error{InvalidHandle}!PortHandle {
        const last = std.mem.lastIndexOfScalar(u8, s, '/') orelse return error.InvalidHandle;
        const h = try Handle.parse(s[0..last]);
        const idx = std.fmt.parseInt(u32, s[last + 1 ..], 10) catch return error.InvalidHandle;
        return .{ .handle = h, .index = idx };
    }
};

/// A handle decoded out of a reply, with both strings copied inline so it
/// outlives the receive buffer.
pub const Owned = struct {
    bus_buf: [uapi.bus_name_max]u8 = @splat(0),
    bus_len: u8 = 0,
    dev_buf: [uapi.dev_name_max]u8 = @splat(0),
    dev_len: u8 = 0,

    pub fn bus(o: *const Owned) []const u8 {
        return o.bus_buf[0..o.bus_len];
    }

    pub fn dev(o: *const Owned) []const u8 {
        return o.dev_buf[0..o.dev_len];
    }

    /// A borrowed view, valid as long as `o` is. Handy for feeding a decoded
    /// device straight back into a follow-up request.
    pub fn borrow(o: *const Owned) Handle {
        return .{ .bus = o.bus(), .dev = o.dev() };
    }

    /// Did the reply carry both halves? A message with only one is malformed
    /// as far as this module is concerned — half a handle names nothing.
    pub fn isComplete(o: Owned) bool {
        return o.bus_len != 0 and o.dev_len != 0;
    }

    pub fn eql(o: *const Owned, h: Handle) bool {
        return o.borrow().eql(h);
    }

    /// Render as `bus/dev`, the form the `devlink` CLI prints and parses.
    pub fn format(o: Owned, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{s}/{s}", .{ o.bus(), o.dev() });
    }
};

// ── request side ───────────────────────────────────────────────────────────

/// Append `BUS_NAME` + `DEV_NAME`, in that order — the order the real
/// `devlink` binary emits and the goldens pin.
pub fn append(gpa: std.mem.Allocator, list: *std.ArrayList(u8), h: Handle) Error!void {
    try h.validate();
    codec.appendAttrString(gpa, list, uapi.ATTR.BUS_NAME, h.bus) catch |e| switch (e) {
        error.AttrTooLong => return error.InvalidRequest,
        error.OutOfMemory => return error.OutOfMemory,
    };
    codec.appendAttrString(gpa, list, uapi.ATTR.DEV_NAME, h.dev) catch |e| switch (e) {
        error.AttrTooLong => return error.InvalidRequest,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Append a port handle: the device handle, then `PORT_INDEX`.
pub fn appendPort(gpa: std.mem.Allocator, list: *std.ArrayList(u8), p: PortHandle) Error!void {
    try append(gpa, list, p.handle);
    try codec.appendAttrU32(gpa, list, uapi.ATTR.PORT_INDEX, p.index);
}

// ── reply side ─────────────────────────────────────────────────────────────

/// Pull the handle out of a message's top-level attributes. Unknown
/// attributes are skipped, so this works on any devlink reply — every one of
/// them carries the pair.
pub fn parse(attr_bytes: []const u8) codec.Error!Owned {
    var o: Owned = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.BUS_NAME => try uapi.copyName(&o.bus_buf, &o.bus_len, a),
        uapi.ATTR.DEV_NAME => try uapi.copyName(&o.dev_buf, &o.dev_len, a),
        else => {},
    };
    return o;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

test "append emits BUS_NAME then DEV_NAME, NUL-terminated and padded" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try append(gpa, &list, .pci("0000:00:00.0"));
    try testing.expectEqualSlices(u8, &.{
        0x08, 0x00, 0x01, 0x00, // len 8, BUS_NAME
        'p',  'c',  'i',  0x00,
        0x11, 0x00, 0x02, 0x00, // len 17, DEV_NAME
        '0',  '0',  '0',  '0',
        ':',  '0',  '0',  ':',
        '0',  '0',  '.',  '0',
        0x00, 0x00, 0x00, 0x00, // NUL + pad to 4
    }, list.items);
}

test "appendPort adds PORT_INDEX after the handle" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendPort(gpa, &list, .{ .handle = .pci("0000:00:00.0"), .index = 1 });
    try testing.expectEqual(@as(usize, 28 + 8), list.items.len);
    try testing.expectEqualSlices(u8, &.{
        0x08, 0x00, 0x03, 0x00,
        0x01, 0x00, 0x00, 0x00,
    }, list.items[28..]);
}

test "an impossible handle is rejected locally, not by the kernel" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.InvalidRequest, append(gpa, &list, .{ .bus = "", .dev = "d" }));
    try testing.expectError(error.InvalidRequest, append(gpa, &list, .{ .bus = "pci", .dev = "" }));
    try testing.expectError(error.InvalidRequest, append(gpa, &list, .{
        .bus = "a" ** (uapi.bus_name_max + 1),
        .dev = "d",
    }));
    try testing.expectError(error.InvalidRequest, append(gpa, &list, .{
        .bus = "pci",
        .dev = "d" ** (uapi.dev_name_max + 1),
    }));
    // An embedded NUL would make the kernel see a shorter name than intended.
    try testing.expectError(error.InvalidRequest, append(gpa, &list, .{ .bus = "p\x00i", .dev = "d" }));
}

test "Handle.parse accepts bus/dev and refuses a port string" {
    const h = try Handle.parse("pci/0000:65:00.0");
    try testing.expectEqualStrings("pci", h.bus);
    try testing.expectEqualStrings("0000:65:00.0", h.dev);

    try testing.expectError(error.InvalidHandle, Handle.parse("pci/0000:65:00.0/3"));
    try testing.expectError(error.InvalidHandle, Handle.parse("nothing-here"));
    try testing.expectError(error.InvalidHandle, Handle.parse("/dev"));
    try testing.expectError(error.InvalidHandle, Handle.parse("bus/"));
}

test "PortHandle.parse splits off the trailing index" {
    const p = try PortHandle.parse("pci/0000:65:00.0/3");
    try testing.expectEqualStrings("pci", p.handle.bus);
    try testing.expectEqualStrings("0000:65:00.0", p.handle.dev);
    try testing.expectEqual(@as(u32, 3), p.index);

    try testing.expectError(error.InvalidHandle, PortHandle.parse("pci/0000:65:00.0"));
    try testing.expectError(error.InvalidHandle, PortHandle.parse("pci/0000:65:00.0/x"));
    try testing.expectError(error.InvalidHandle, PortHandle.parse("pci/0000:65:00.0/4294967296"));
}

test "parse recovers the handle and reports a half one as incomplete" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try append(gpa, &list, .{ .bus = "netdevsim", .dev = "netdevsim1" });
    // A sibling attribute the walker must skip.
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_INDEX, 7);

    const o = try parse(list.items);
    try testing.expect(o.isComplete());
    try testing.expectEqualStrings("netdevsim", o.bus());
    try testing.expectEqualStrings("netdevsim1", o.dev());
    try testing.expect(o.eql(.{ .bus = "netdevsim", .dev = "netdevsim1" }));
    try testing.expect(!o.eql(.pci("0000:00:00.0")));

    list.clearRetainingCapacity();
    try codec.appendAttrString(gpa, &list, uapi.ATTR.BUS_NAME, "pci");
    try testing.expect(!(try parse(list.items)).isComplete());
}

test "parse bounds an over-long name instead of overrunning the buffer" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrString(gpa, &list, uapi.ATTR.DEV_NAME, "d" ** (uapi.dev_name_max + 1));
    try testing.expectError(error.BadLength, parse(list.items));

    // A truncated TLV is a typed error too.
    try testing.expectError(error.Truncated, parse(&.{ 0x40, 0x00, 0x01, 0x00, 0x01 }));
}

test "Owned formats as the CLI's bus/dev" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try append(gpa, &list, .pci("0000:65:00.0"));
    const o = try parse(list.items);
    const s = try std.fmt.allocPrint(gpa, "{f}", .{o});
    defer gpa.free(s);
    try testing.expectEqualStrings("pci/0000:65:00.0", s);
}
