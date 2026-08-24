// SPDX-License-Identifier: MIT
//! The embedded switch: `DEVLINK_CMD_ESWITCH_GET` and `ESWITCH_SET`.
//!
//! ```text
//! BUS_NAME / DEV_NAME
//! ESWITCH_MODE         u16   legacy / switchdev / switchdev_inactive
//! ESWITCH_INLINE_MODE  u8    none / link / network / transport
//! ESWITCH_ENCAP_MODE   u8    none / basic
//! ```
//!
//! Note the widths: **`MODE` is a u16 and the other two are u8**, which is the
//! kind of asymmetry that makes a copy-pasted decoder produce plausible
//! nonsense. The real `devlink dev eswitch set` capture in `goldens.zig` pins
//! all three.
//!
//! `ESWITCH_GET` is one of the few devlink *reads* that is **privileged**: the
//! kernel marks it `GENL_ADMIN_PERM`, so it answers `EPERM` to an ordinary
//! user rather than `EOPNOTSUPP`. That is worth knowing before diagnosing a
//! permission error as a missing feature.
//!
//! Switching a card from `legacy` to `switchdev` is a heavyweight, disruptive
//! operation: it tears down the existing VF netdevs and re-creates the eswitch
//! ports as representors. It is not a configuration tweak.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const handle = @import("handle.zig");
const request = @import("request.zig");
const genl = @import("genetlink");

pub const BuildError = error{ OutOfMemory, InvalidRequest };

/// The eswitch's current configuration. Every field is optional: a driver
/// that supports mode but not inline mode simply omits the latter.
pub const Eswitch = struct {
    handle: handle.Owned = .{},
    mode: ?uapi.EswitchMode = null,
    inline_mode: ?uapi.InlineMode = null,
    encap_mode: ?uapi.EncapMode = null,

    /// Is the device forwarding through its embedded switch (as opposed to
    /// the legacy SR-IOV path)? Null when the driver did not report a mode.
    pub fn isSwitchdev(e: Eswitch) ?bool {
        const m = e.mode orelse return null;
        return m == .switchdev or m == .switchdev_inactive;
    }
};

/// Decode one `DEVLINK_CMD_ESWITCH_GET` reply.
pub fn parse(attr_bytes: []const u8) codec.Error!Eswitch {
    var e: Eswitch = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.BUS_NAME => try uapi.copyName(&e.handle.bus_buf, &e.handle.bus_len, a),
        uapi.ATTR.DEV_NAME => try uapi.copyName(&e.handle.dev_buf, &e.handle.dev_len, a),
        uapi.ATTR.ESWITCH_MODE => e.mode = @enumFromInt(try a.asU16()),
        uapi.ATTR.ESWITCH_INLINE_MODE => e.inline_mode = @enumFromInt(try a.asU8()),
        uapi.ATTR.ESWITCH_ENCAP_MODE => e.encap_mode = @enumFromInt(try a.asU8()),
        else => {},
    };
    return e;
}

/// What an `ESWITCH_SET` changes. A null field is left alone — the kernel
/// applies only the attributes present, so an all-null request is rejected
/// here rather than sent as a no-op the kernel would answer EINVAL to.
pub const Set = struct {
    mode: ?uapi.EswitchMode = null,
    inline_mode: ?uapi.InlineMode = null,
    encap_mode: ?uapi.EncapMode = null,
};

/// Attributes of a `DEVLINK_CMD_ESWITCH_SET`. Needs **CAP_NET_ADMIN**.
pub fn appendSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    set: Set,
) BuildError!void {
    if (set.mode == null and set.inline_mode == null and set.encap_mode == null)
        return error.InvalidRequest;
    try handle.append(gpa, list, h);
    if (set.mode) |m| try codec.appendAttrU16(gpa, list, uapi.ATTR.ESWITCH_MODE, @intFromEnum(m));
    if (set.inline_mode) |m| try codec.appendAttrU8(gpa, list, uapi.ATTR.ESWITCH_INLINE_MODE, @intFromEnum(m));
    if (set.encap_mode) |m| try codec.appendAttrU8(gpa, list, uapi.ATTR.ESWITCH_ENCAP_MODE, @intFromEnum(m));
}

/// Attributes of a `DEVLINK_CMD_ESWITCH_GET` — the handle alone.
pub fn appendGet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
) handle.Error!void {
    try handle.append(gpa, list, h);
}

// ── complete requests ──────────────────────────────────────────────────────

/// Build a `DEVLINK_CMD_ESWITCH_GET` — what `Devlink.eswitch` sends. The
/// kernel marks this read `GENL_ADMIN_PERM`, so an unprivileged sender gets
/// `EPERM` rather than an answer.
pub fn buildEswitch(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.ESWITCH_GET, false);
    errdefer b.deinit();
    try appendGet(gpa, &b.list, h);
    return b.finish();
}

/// Build a `DEVLINK_CMD_ESWITCH_SET` — what `Devlink.setEswitch` sends. Needs
/// **CAP_NET_ADMIN**, and changing the mode tears down and re-creates the
/// device's VF netdevs.
pub fn buildSetEswitch(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    set: Set,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.ESWITCH_SET, false);
    errdefer b.deinit();
    try appendSet(gpa, &b.list, h, set);
    return b.finish();
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

test "parse reads all three fields at their own widths" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .pci("0000:65:00.0"));
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.ESWITCH_MODE, 1);
    try codec.appendAttrU8(gpa, &list, uapi.ATTR.ESWITCH_INLINE_MODE, 2);
    try codec.appendAttrU8(gpa, &list, uapi.ATTR.ESWITCH_ENCAP_MODE, 1);

    const e = try parse(list.items);
    try testing.expectEqual(@as(?uapi.EswitchMode, .switchdev), e.mode);
    try testing.expectEqual(@as(?uapi.InlineMode, .network), e.inline_mode);
    try testing.expectEqual(@as(?uapi.EncapMode, .basic), e.encap_mode);
    try testing.expectEqual(@as(?bool, true), e.isSwitchdev());
    try testing.expectEqualStrings("0000:65:00.0", e.handle.dev());
}

test "parse: legacy mode, and a driver that reports only the mode" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.ESWITCH_MODE, 0);
    const e = try parse(list.items);
    try testing.expectEqual(@as(?uapi.EswitchMode, .legacy), e.mode);
    try testing.expectEqual(@as(?bool, false), e.isSwitchdev());
    try testing.expectEqual(@as(?uapi.InlineMode, null), e.inline_mode);

    // Nothing reported at all.
    try testing.expectEqual(@as(?bool, null), (try parse(&.{})).isSwitchdev());
}

test "parse: switchdev_inactive still counts as switchdev" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.ESWITCH_MODE, 2);
    try testing.expectEqual(@as(?bool, true), (try parse(list.items)).isSwitchdev());
}

test "parse: a mode sent at the wrong width is a malformed reply" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // The asymmetry this module warns about: MODE is u16, not u8.
    try codec.appendAttrU8(gpa, &list, uapi.ATTR.ESWITCH_MODE, 1);
    try testing.expectError(error.BadLength, parse(list.items));

    list.clearRetainingCapacity();
    try codec.appendAttrU16(gpa, &list, uapi.ATTR.ESWITCH_INLINE_MODE, 1);
    try testing.expectError(error.BadLength, parse(list.items));
}

test "appendSet emits only what was asked for" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendSet(gpa, &list, .pci("0000:00:00.0"), .{ .mode = .switchdev });
    try testing.expectEqualSlices(u8, &.{
        0x06, 0x00, 0x19, 0x00,
        0x01, 0x00, 0x00, 0x00,
    }, list.items[28..]);

    list.clearRetainingCapacity();
    try appendSet(gpa, &list, .pci("0000:00:00.0"), .{ .encap_mode = .none });
    try testing.expectEqualSlices(u8, &.{
        0x05, 0x00, 0x3e, 0x00,
        0x00, 0x00, 0x00, 0x00,
    }, list.items[28..]);
}

test "appendSet refuses an empty change" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.InvalidRequest, appendSet(gpa, &list, .pci("0000:00:00.0"), .{}));
}

test "appendSet round-trips through parse" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendSet(gpa, &list, .pci("0000:00:00.0"), .{
        .mode = .legacy,
        .inline_mode = .transport,
        .encap_mode = .basic,
    });
    const e = try parse(list.items);
    try testing.expectEqual(@as(?uapi.EswitchMode, .legacy), e.mode);
    try testing.expectEqual(@as(?uapi.InlineMode, .transport), e.inline_mode);
    try testing.expectEqual(@as(?uapi.EncapMode, .basic), e.encap_mode);
}

test "buildEswitch asks; buildSetEswitch sends only what was asked for" {
    const gpa = testing.allocator;
    const h: handle.Handle = .pci("0000:65:00.0");

    const get = try buildEswitch(gpa, 0x19, 13, h);
    defer gpa.free(get);
    var it: codec.MessageIterator = .{ .buf = get };
    var m = (try it.next()).?;
    try testing.expect((try it.next()) == null);
    try testing.expectEqual(@as(u16, 0x19), m.type);
    try testing.expectEqual(@as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK), m.flags);
    try testing.expectEqual(@as(u32, 13), m.seq);
    try testing.expectEqual(@as(u32, 0), m.pid);
    var p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.ESWITCH_GET, p.cmd);
    try testing.expectEqual(uapi.family_version, m.payload[1]);
    // A GET carries the handle and no mode of any kind.
    const asked = try parse(p.attrs);
    try testing.expectEqualStrings("0000:65:00.0", asked.handle.dev());
    try testing.expectEqual(@as(?uapi.EswitchMode, null), asked.mode);
    try testing.expectEqual(@as(?uapi.InlineMode, null), asked.inline_mode);
    try testing.expectEqual(@as(?uapi.EncapMode, null), asked.encap_mode);

    const set = try buildSetEswitch(gpa, 0x19, 14, h, .{ .mode = .switchdev });
    defer gpa.free(set);
    it = .{ .buf = set };
    m = (try it.next()).?;
    p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.ESWITCH_SET, p.cmd);
    const sent = try parse(p.attrs);
    try testing.expectEqual(@as(?uapi.EswitchMode, .switchdev), sent.mode);
    // The two the caller left null are absent, not defaulted to `none`.
    try testing.expectEqual(@as(?uapi.InlineMode, null), sent.inline_mode);
    try testing.expectEqual(@as(?uapi.EncapMode, null), sent.encap_mode);

    // An empty change is refused here rather than sent for the kernel to
    // answer EINVAL to.
    try testing.expectError(error.InvalidRequest, buildSetEswitch(gpa, 0x19, 1, h, .{}));
    try testing.expectError(error.InvalidRequest, buildEswitch(gpa, 0x19, 1, .{ .bus = "pci", .dev = "" }));
}
