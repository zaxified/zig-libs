// SPDX-License-Identifier: MIT
//! `DEVLINK_CMD_RELOAD` — `devlink dev reload`.
//!
//! ```text
//! request:  BUS_NAME / DEV_NAME
//!           NETNS_PID | NETNS_FD | NETNS_ID   u32   (optional: move the instance)
//!           RELOAD_ACTION                     u8    (optional: driver_reinit / fw_activate)
//!           RELOAD_LIMITS                     bitfield32 (optional: no_reset)
//! reply:    RELOAD_ACTIONS_PERFORMED          bitfield32 (what the driver actually did)
//! ```
//!
//! The attribute order is the one `devlink` itself sends (handle, netns,
//! action, limits — checked against iproute2 6.19.0 captures in
//! `goldens.zig`). Every attribute is optional; a bare reload is the handle
//! alone, which the kernel treats as `driver_reinit` with no limits.
//!
//! **Destructive.** A reload re-instantiates the driver: netdevs and ports of
//! the device disappear and come back, and with a `netns` attribute the whole
//! devlink instance moves to another network namespace. It needs
//! `CAP_NET_ADMIN`. Nothing here is a dry run.
//!
//! Limits are a bitfield on the wire (`value`, `selector`); `devlink` sends
//! the limit as one bit in `value` and the kernel's whole valid mask as the
//! `selector`, and so does this module.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const handle = @import("handle.zig");
const request = @import("request.zig");

const native = @import("builtin").cpu.arch.endian();

pub const BuildError = error{ OutOfMemory, InvalidRequest };

/// `enum devlink_reload_action`. Non-exhaustive: a newer kernel's action
/// round-trips through the performed-actions bitmask.
pub const Action = enum(u8) {
    driver_reinit = 1,
    fw_activate = 2,
    _,
};

/// `enum devlink_reload_limit` — the constraint on how disruptive the reload
/// may be. `unspecified` (no constraint) and `no_reset` are the two the kernel
/// UAPI names today; `devlink` itself only ever sends `no_reset`.
pub const Limit = enum(u8) {
    unspecified = 0,
    no_reset = 1,
    _,
};

/// `DEVLINK_RELOAD_LIMITS_VALID_MASK` for the limits above (bits 0 and 1).
/// A limit outside it would be rejected by the kernel, so it is rejected here.
pub const limits_valid_mask: u32 = 0b11;

/// Where to move the devlink instance to. Exactly one of the three kernel
/// selectors, which is why this is a union.
pub const Netns = union(enum) {
    /// `NETNS_PID` — a process in the target namespace (`devlink … netns <pid>`).
    pid: u32,
    /// `NETNS_FD` — an open namespace file descriptor (`netns <name>`).
    fd: u32,
    /// `NETNS_ID` — a namespace id (`netns id <n>`).
    id: u32,
};

/// What a reload asks for. The default is a plain reload (handle only).
pub const Options = struct {
    action: ?Action = null,
    limit: ?Limit = null,
    netns: ?Netns = null,
};

/// What the driver reported having done (`RELOAD_ACTIONS_PERFORMED`).
pub const Performed = struct {
    /// Bit `1 << action` per action performed, as on the wire.
    mask: u32 = 0,

    pub fn did(p: Performed, a: Action) bool {
        const n = @backingInt(a);
        if (n >= 32) return false;
        return p.mask & (@as(u32, 1) << @intCast(n)) != 0;
    }
};

/// Decode a `RELOAD` reply. A reply without the attribute (an older kernel,
/// or a bare ACK) is `Performed{}` with an empty mask.
pub fn parseReply(attr_bytes: []const u8) codec.Error!Performed {
    var out: Performed = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.RELOAD_ACTIONS_PERFORMED => {
            if (a.data.len != 8) return error.BadLength;
            // bitfield32: value, then selector. The kernel sets both to the
            // performed set; only bits the selector covers are meaningful.
            const value = std.mem.readInt(u32, a.data[0..4], native);
            const selector = std.mem.readInt(u32, a.data[4..8], native);
            out.mask = value & selector;
        },
        else => {},
    };
    return out;
}

/// Attributes of a `DEVLINK_CMD_RELOAD`. Needs **CAP_NET_ADMIN**; re-instantiates
/// the driver.
pub fn appendReload(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    opts: Options,
) BuildError!void {
    if (opts.limit) |l| {
        const n = @backingInt(l);
        if (n >= 32 or (@as(u32, 1) << @intCast(n)) & limits_valid_mask == 0)
            return error.InvalidRequest;
    }
    try handle.append(gpa, list, h);
    if (opts.netns) |ns| switch (ns) {
        .pid => |v| try codec.appendAttrU32(gpa, list, uapi.ATTR.NETNS_PID, v),
        .fd => |v| try codec.appendAttrU32(gpa, list, uapi.ATTR.NETNS_FD, v),
        .id => |v| try codec.appendAttrU32(gpa, list, uapi.ATTR.NETNS_ID, v),
    };
    if (opts.action) |a| try codec.appendAttrU8(gpa, list, uapi.ATTR.RELOAD_ACTION, @backingInt(a));
    if (opts.limit) |l| {
        // bitfield32 { value, selector }, host byte order like every other u32.
        var bf: [8]u8 = undefined;
        std.mem.writeInt(u32, bf[0..4], @as(u32, 1) << @intCast(@backingInt(l)), native);
        std.mem.writeInt(u32, bf[4..8], limits_valid_mask, native);
        codec.appendAttr(gpa, list, uapi.ATTR.RELOAD_LIMITS, &bf) catch |e| switch (e) {
            error.AttrTooLong => return error.InvalidRequest, // 8 bytes cannot be too long
            error.OutOfMemory => return error.OutOfMemory,
        };
    }
}

/// Build a `DEVLINK_CMD_RELOAD` — what `Devlink.reload` sends.
pub fn buildReload(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    opts: Options,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.RELOAD, false);
    errdefer b.deinit();
    try appendReload(gpa, &b.list, h, opts);
    return b.finish();
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "a bare reload is the handle alone" {
    const gpa = testing.allocator;
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    var h: std.ArrayList(u8) = .empty;
    defer h.deinit(gpa);
    try appendReload(gpa, &a, .pci("0000:00:00.0"), .{});
    try handle.append(gpa, &h, .pci("0000:00:00.0"));
    try testing.expectEqualSlices(u8, h.items, a.items);
}

test "attribute order is netns, action, limits" {
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try appendReload(gpa, &l, .pci("0000:00:00.0"), .{
        .action = .fw_activate,
        .limit = .no_reset,
        .netns = .{ .id = 5 },
    });
    var it: codec.AttrIterator = .{ .buf = l.items };
    var seen: [8]u16 = undefined;
    var n: usize = 0;
    while (try it.next()) |a| : (n += 1) seen[n] = a.type;
    try testing.expectEqualSlices(u16, &.{
        uapi.ATTR.BUS_NAME,
        uapi.ATTR.DEV_NAME,
        uapi.ATTR.NETNS_ID,
        uapi.ATTR.RELOAD_ACTION,
        uapi.ATTR.RELOAD_LIMITS,
    }, seen[0..n]);
}

test "netns selectors map to their own attribute" {
    const gpa = testing.allocator;
    const cases = [_]struct { ns: Netns, ty: u16 }{
        .{ .ns = .{ .pid = 1 }, .ty = uapi.ATTR.NETNS_PID },
        .{ .ns = .{ .fd = 2 }, .ty = uapi.ATTR.NETNS_FD },
        .{ .ns = .{ .id = 3 }, .ty = uapi.ATTR.NETNS_ID },
    };
    for (cases, 0..) |c, i| {
        var l: std.ArrayList(u8) = .empty;
        defer l.deinit(gpa);
        try appendReload(gpa, &l, .pci("0000:00:00.0"), .{ .netns = c.ns });
        var it: codec.AttrIterator = .{ .buf = l.items };
        _ = try it.next();
        _ = try it.next();
        const a = (try it.next()).?;
        try testing.expectEqual(c.ty, a.type);
        try testing.expectEqual(@as(u32, @intCast(i + 1)), try a.asU32());
    }
}

test "a limit outside the valid mask is refused locally" {
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try testing.expectError(error.InvalidRequest, appendReload(gpa, &l, .pci("0000:00:00.0"), .{ .limit = @fromBackingInt(@intCast(2)) }));
    try testing.expectError(error.InvalidRequest, appendReload(gpa, &l, .pci("0000:00:00.0"), .{ .limit = @fromBackingInt(@intCast(40)) }));
    try testing.expectEqual(@as(usize, 0), l.items.len);
    // The unspecified limit is inside the mask: bit 0, selector 3.
    try appendReload(gpa, &l, .pci("0000:00:00.0"), .{ .limit = .unspecified });
    const tail = l.items[l.items.len - 12 ..];
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, tail[4..8], native));
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, tail[8..12], native));
}

test "an invalid handle is refused" {
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try testing.expectError(error.InvalidRequest, appendReload(gpa, &l, .pci(""), .{}));
}

fn replyWith(gpa: std.mem.Allocator, list: *std.ArrayList(u8), value: u32, selector: u32) !void {
    var bf: [8]u8 = undefined;
    std.mem.writeInt(u32, bf[0..4], value, native);
    std.mem.writeInt(u32, bf[4..8], selector, native);
    try codec.appendAttr(gpa, list, uapi.ATTR.RELOAD_ACTIONS_PERFORMED, &bf);
}

test "parseReply decodes the performed actions" {
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try handle.append(gpa, &l, .pci("0000:00:00.0"));
    try replyWith(gpa, &l, 0b110, 0b110);
    const p = try parseReply(l.items);
    try testing.expect(p.did(.driver_reinit));
    try testing.expect(p.did(.fw_activate));
    try testing.expect(!p.did(@fromBackingInt(@intCast(3))));
    try testing.expect(!p.did(@fromBackingInt(@intCast(200))));
}

test "parseReply honours the selector and tolerates a missing attribute" {
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try replyWith(gpa, &l, 0b110, 0b100);
    const p = try parseReply(l.items);
    try testing.expect(!p.did(.driver_reinit));
    try testing.expect(p.did(.fw_activate));
    try testing.expectEqual(@as(u32, 0), (try parseReply(&.{})).mask);
}

test "parseReply rejects a wrong-width bitfield" {
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try codec.appendAttrU32(gpa, &l, uapi.ATTR.RELOAD_ACTIONS_PERFORMED, 6);
    try testing.expectError(error.BadLength, parseReply(l.items));
}

test "parseReply never panics on arbitrary bytes" {
    var prng = std.Random.DefaultPrng.init(0x7e10ad);
    const r = prng.random();
    var buf: [96]u8 = undefined;
    for (0..2000) |_| {
        const n = r.uintLessThan(usize, buf.len + 1);
        r.bytes(buf[0..n]);
        _ = parseReply(buf[0..n]) catch {};
    }
}
