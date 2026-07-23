// SPDX-License-Identifier: MIT
//! Driver parameters: `DEVLINK_CMD_PARAM_GET` (dump and by name) and
//! `DEVLINK_CMD_PARAM_SET`.
//!
//! ## The shape
//!
//! ```text
//! BUS_NAME / DEV_NAME               (+ PORT_INDEX for a port parameter)
//! PARAM                       nest
//!   PARAM_NAME                string
//!   PARAM_GENERIC             flag     present ⇒ a kernel-defined name
//!   PARAM_TYPE                u8       ← decides the width of every value below
//!   PARAM_VALUES_LIST         nest
//!     PARAM_VALUE             nest     once per configuration mode
//!       PARAM_VALUE_DATA      dynamic  ← width per PARAM_TYPE; absent ⇒ unset
//!       PARAM_VALUE_CMODE     u8       runtime / driverinit / permanent
//! ```
//!
//! ## The part that makes this different from every other devlink object
//!
//! **`PARAM_VALUE_DATA` has no fixed width.** The kernel declares it `dynamic`
//! and decides its size from `PARAM_TYPE`, which arrives *in the same nest* —
//! so a decoder cannot be a flat attribute-to-field table. It has to read
//! `PARAM_TYPE` first and then dispatch. This module reads the whole `PARAM`
//! nest in one pass to find the type, then walks `PARAM_VALUES_LIST` in a
//! second pass, because the kernel does not promise `PARAM_TYPE` comes first.
//!
//! A `PARAM_TYPE` this module does not know is not an error: the value is kept
//! as `.unknown` with its raw bytes, so a future kernel type is visible rather
//! than silently dropped.
//!
//! ## One parameter, three values
//!
//! A parameter has one value *per configuration mode*, and they routinely
//! differ: `enable_roce` can be on at runtime and off in the driverinit value
//! that will be applied after the next `devlink dev reload`. Asking "what is
//! this parameter set to" is therefore always "…in which cmode".
//!
//! A `PARAM_VALUE` nest with a `CMODE` but **no `DATA`** is normal and means
//! "this mode is supported but currently unset" — most often `permanent` on a
//! device whose NVM has never been written.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const handle = @import("handle.zig");

pub const ParseError = codec.Error || error{OutOfMemory};
pub const BuildError = error{ OutOfMemory, InvalidRequest };

/// The most `PARAM_VALUE` entries kept for one parameter. The kernel defines
/// exactly three configuration modes; the slack is for a future one, and the
/// cap is what stops a hostile nest from turning into unbounded allocation.
pub const max_values = 16;

/// A bounded byte string, used for the `string` and `binary` parameter types
/// and copied inline so a decoded parameter outlives the receive buffer.
pub const Bytes = struct {
    buf: [uapi.value_max]u8 = @splat(0),
    len: u8 = 0,

    pub fn get(b: *const Bytes) []const u8 {
        return b.buf[0..b.len];
    }

    pub fn from(s: []const u8) error{InvalidRequest}!Bytes {
        if (s.len > uapi.value_max) return error.InvalidRequest;
        var b: Bytes = .{ .len = @intCast(s.len) };
        @memcpy(b.buf[0..s.len], s);
        return b;
    }
};

/// A parameter's value, in the shape its `PARAM_TYPE` declares.
pub const Value = union(enum) {
    uint8: u8,
    uint16: u16,
    uint32: u32,
    uint64: u64,
    /// `DEVLINK_VAR_ATTR_TYPE_STRING` / `NUL_STRING`, NUL stripped.
    string: Bytes,
    /// A flag's value **is** the presence of `PARAM_VALUE_DATA`; the attribute
    /// itself has an empty payload.
    flag: bool,
    binary: Bytes,
    /// A `PARAM_TYPE` this module does not model, with the payload kept as-is.
    unknown: Bytes,

    /// Any of the four integer widths, widened. Null for the others.
    pub fn asInt(v: Value) ?u64 {
        return switch (v) {
            .uint8 => |x| x,
            .uint16 => |x| x,
            .uint32 => |x| x,
            .uint64 => |x| x,
            else => null,
        };
    }

    /// The string/binary/unknown payload. Null for the others.
    pub fn asBytes(v: *const Value) ?[]const u8 {
        return switch (v.*) {
            .string, .binary, .unknown => |*b| b.get(),
            else => null,
        };
    }

    /// The `PARAM_TYPE` this value would be sent as.
    pub fn paramType(v: Value) uapi.ParamType {
        return switch (v) {
            .uint8 => .u8_,
            .uint16 => .u16_,
            .uint32 => .u32_,
            .uint64 => .u64_,
            .string => .string,
            .flag => .flag,
            .binary => .binary,
            .unknown => .binary,
        };
    }
};

/// One `PARAM_VALUE` nest: a configuration mode and the value in it.
pub const ParamValue = struct {
    cmode: ?uapi.ParamCmode = null,
    /// Null when the nest carried a `CMODE` but no `DATA` — "supported, but
    /// not currently set". Distinct from a value that happens to be zero.
    value: ?Value = null,
};

/// One driver parameter. `values` is heap-allocated; free with `deinit`.
pub const Param = struct {
    handle: handle.Owned = .{},
    /// Present on a **port** parameter (`DEVLINK_CMD_PORT_PARAM_GET`).
    port_index: ?u32 = null,
    name_buf: [uapi.name_max]u8 = @splat(0),
    name_len: u8 = 0,
    /// `PARAM_GENERIC` — the name is one of the kernel's own
    /// (`enable_roce`, `fw_load_policy`, …) rather than driver-specific.
    generic: bool = false,
    type: ?uapi.ParamType = null,
    values: []ParamValue = &.{},

    pub fn name(p: *const Param) []const u8 {
        return p.name_buf[0..p.name_len];
    }

    /// The value in one configuration mode, or null when the parameter does
    /// not support that mode. Note the double optional this deliberately
    /// flattens is kept apart at the call site: a present entry with a null
    /// `.value` means "supported but unset".
    pub fn forCmode(p: *const Param, cmode: uapi.ParamCmode) ?*const ParamValue {
        for (p.values) |*v| {
            if (v.cmode == cmode) return v;
        }
        return null;
    }

    /// Does a reload change this parameter's effective value? True when the
    /// runtime and driverinit values are both present and differ.
    pub fn reloadWouldChange(p: *const Param) bool {
        const rt = (p.forCmode(.runtime) orelse return false).value orelse return false;
        const di = (p.forCmode(.driverinit) orelse return false).value orelse return false;
        return !valuesEqual(rt, di);
    }

    pub fn deinit(p: *Param, gpa: std.mem.Allocator) void {
        gpa.free(p.values);
        p.values = &.{};
    }
};

fn valuesEqual(a: Value, b: Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .uint8, .uint16, .uint32, .uint64 => a.asInt().? == b.asInt().?,
        .flag => |x| x == b.flag,
        .string, .binary, .unknown => std.mem.eql(u8, a.asBytes().?, b.asBytes().?),
    };
}

/// Free a slice of parameters and everything they own.
pub fn freeAll(gpa: std.mem.Allocator, list: []Param) void {
    for (list) |*p| p.deinit(gpa);
    gpa.free(list);
}

// ── decoding ───────────────────────────────────────────────────────────────

/// Decode `PARAM_VALUE_DATA` according to `t`. The width checks are the
/// kernel's own policy, applied on the way in: a `u32` parameter whose value
/// arrives 8 bytes wide is a malformed reply, not a number to guess at.
fn decodeData(t: uapi.ParamType, a: codec.Attr) codec.Error!Value {
    return switch (t) {
        .u8_ => .{ .uint8 = try a.asU8() },
        .u16_ => .{ .uint16 = try a.asU16() },
        .u32_ => .{ .uint32 = try a.asU32() },
        .u64_ => .{ .uint64 = try uapi.asU64(a) },
        .flag => .{ .flag = true }, // presence is the value
        .string, .nul_string => blk: {
            var b: Bytes = .{};
            try uapi.copyName(&b.buf, &b.len, a);
            break :blk .{ .string = b };
        },
        .binary => blk: {
            if (a.data.len > uapi.value_max) return error.BadLength;
            var b: Bytes = .{ .len = @intCast(a.data.len) };
            @memcpy(b.buf[0..a.data.len], a.data);
            break :blk .{ .binary = b };
        },
        _ => blk: {
            if (a.data.len > uapi.value_max) return error.BadLength;
            var b: Bytes = .{ .len = @intCast(a.data.len) };
            @memcpy(b.buf[0..a.data.len], a.data);
            break :blk .{ .unknown = b };
        },
    };
}

/// Decode the contents of one `DEVLINK_ATTR_PARAM` nest.
pub fn parseNest(gpa: std.mem.Allocator, nest_bytes: []const u8) ParseError!Param {
    var p: Param = .{};

    // Pass 1: everything but the values, because the values cannot be read
    // until `PARAM_TYPE` is known and the kernel does not promise it first.
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.PARAM_NAME => try uapi.copyName(&p.name_buf, &p.name_len, a),
        uapi.ATTR.PARAM_GENERIC => p.generic = true,
        uapi.ATTR.PARAM_TYPE => p.type = @enumFromInt(try a.asU8()),
        else => {},
    };

    var values: std.ArrayList(ParamValue) = .empty;
    errdefer values.deinit(gpa);

    // Pass 2: the values list, now that the type is known.
    var it2: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it2.next()) |a| {
        if (a.type != uapi.ATTR.PARAM_VALUES_LIST) continue;
        var vals: codec.AttrIterator = .{ .buf = a.data };
        while (try vals.next()) |ve| {
            if (ve.type != uapi.ATTR.PARAM_VALUE) continue;
            if (values.items.len >= max_values) return error.BadLength;
            var pv: ParamValue = .{};
            var inner: codec.AttrIterator = .{ .buf = ve.data };
            while (try inner.next()) |x| switch (x.type) {
                uapi.ATTR.PARAM_VALUE_CMODE => pv.cmode = @enumFromInt(try x.asU8()),
                uapi.ATTR.PARAM_VALUE_DATA => {
                    // Without a declared type there is no way to know how wide
                    // this is; keeping the bytes is the only honest answer.
                    const t = p.type orelse .binary;
                    pv.value = try decodeData(t, x);
                },
                else => {},
            };
            try values.append(gpa, pv);
        }
    }
    p.values = try values.toOwnedSlice(gpa);
    return p;
}

/// Decode one `DEVLINK_CMD_PARAM_GET`/`PARAM_NEW` message. A message with no
/// `PARAM` nest yields a parameter with an empty name — which `parseAll` in
/// `client.zig` treats as "not a parameter message" and skips.
pub fn parse(gpa: std.mem.Allocator, attr_bytes: []const u8) ParseError!Param {
    var out: Param = .{};
    var found = false;
    errdefer out.deinit(gpa);

    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.BUS_NAME => try uapi.copyName(&out.handle.bus_buf, &out.handle.bus_len, a),
        uapi.ATTR.DEV_NAME => try uapi.copyName(&out.handle.dev_buf, &out.handle.dev_len, a),
        uapi.ATTR.PORT_INDEX => out.port_index = try a.asU32(),
        uapi.ATTR.PARAM => {
            if (found) continue; // one PARAM nest per message
            var inner = try parseNest(gpa, a.data);
            inner.handle = out.handle;
            inner.port_index = out.port_index;
            out = inner;
            found = true;
        },
        else => {},
    };
    return out;
}

// ── request builders ───────────────────────────────────────────────────────

/// Attributes of a `DEVLINK_CMD_PARAM_GET` for one named parameter.
pub fn appendGetByName(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    param_name: []const u8,
) BuildError!void {
    try handle.append(gpa, list, h);
    try appendName(gpa, list, param_name);
}

fn appendName(gpa: std.mem.Allocator, list: *std.ArrayList(u8), param_name: []const u8) BuildError!void {
    if (param_name.len == 0 or param_name.len > uapi.name_max) return error.InvalidRequest;
    if (std.mem.indexOfScalar(u8, param_name, 0) != null) return error.InvalidRequest;
    codec.appendAttrString(gpa, list, uapi.ATTR.PARAM_NAME, param_name) catch |e| switch (e) {
        error.AttrTooLong => return error.InvalidRequest,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Attributes of a `DEVLINK_CMD_PARAM_SET`: handle, name, type, cmode, value.
/// Needs **CAP_NET_ADMIN**.
///
/// The `PARAM_TYPE` sent is derived from `value`'s variant, so it can never
/// disagree with the width of the data that follows it — the one mistake this
/// message shape invites.
///
/// A `.flag` value of `false` is expressed by *omitting* `PARAM_VALUE_DATA`,
/// which is how the kernel's flag policy reads "off".
pub fn appendSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    param_name: []const u8,
    cmode: uapi.ParamCmode,
    value: Value,
) BuildError!void {
    try handle.append(gpa, list, h);
    try appendName(gpa, list, param_name);
    try codec.appendAttrU8(gpa, list, uapi.ATTR.PARAM_TYPE, @intFromEnum(value.paramType()));
    try codec.appendAttrU8(gpa, list, uapi.ATTR.PARAM_VALUE_CMODE, @intFromEnum(cmode));
    switch (value) {
        .uint8 => |x| try codec.appendAttrU8(gpa, list, uapi.ATTR.PARAM_VALUE_DATA, x),
        .uint16 => |x| try codec.appendAttrU16(gpa, list, uapi.ATTR.PARAM_VALUE_DATA, x),
        .uint32 => |x| try codec.appendAttrU32(gpa, list, uapi.ATTR.PARAM_VALUE_DATA, x),
        .uint64 => |x| try uapi.appendAttrU64(gpa, list, uapi.ATTR.PARAM_VALUE_DATA, x),
        .flag => |on| if (on) codec.appendAttr(gpa, list, uapi.ATTR.PARAM_VALUE_DATA, &.{}) catch |e| switch (e) {
            error.AttrTooLong => unreachable, // empty payload
            error.OutOfMemory => return error.OutOfMemory,
        },
        .string => |*b| codec.appendAttrString(gpa, list, uapi.ATTR.PARAM_VALUE_DATA, b.get()) catch |e| switch (e) {
            error.AttrTooLong => return error.InvalidRequest,
            error.OutOfMemory => return error.OutOfMemory,
        },
        .binary, .unknown => |*b| codec.appendAttr(gpa, list, uapi.ATTR.PARAM_VALUE_DATA, b.get()) catch |e| switch (e) {
            error.AttrTooLong => return error.InvalidRequest,
            error.OutOfMemory => return error.OutOfMemory,
        },
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

const ValueSpec = struct { cmode: uapi.ParamCmode, data: ?[]const u8 };

/// Build a `DEVLINK_ATTR_PARAM` nest with raw `PARAM_VALUE_DATA` payloads, so
/// a test can feed a width the type does not declare.
fn buildParam(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    param_name: []const u8,
    t: ?u8,
    generic: bool,
    specs: []const ValueSpec,
) !void {
    const nest = try codec.nestBegin(gpa, list, uapi.ATTR.PARAM);
    try codec.appendAttrString(gpa, list, uapi.ATTR.PARAM_NAME, param_name);
    if (generic) try codec.appendAttr(gpa, list, uapi.ATTR.PARAM_GENERIC, &.{});
    const vl = try codec.nestBegin(gpa, list, uapi.ATTR.PARAM_VALUES_LIST);
    for (specs) |s| {
        const v = try codec.nestBegin(gpa, list, uapi.ATTR.PARAM_VALUE);
        if (s.data) |d| try codec.appendAttr(gpa, list, uapi.ATTR.PARAM_VALUE_DATA, d);
        try codec.appendAttrU8(gpa, list, uapi.ATTR.PARAM_VALUE_CMODE, @intFromEnum(s.cmode));
        codec.nestEnd(list, v);
    }
    codec.nestEnd(list, vl);
    // Deliberately last: the decoder must not depend on PARAM_TYPE coming
    // before the values it describes.
    if (t) |x| try codec.appendAttrU8(gpa, list, uapi.ATTR.PARAM_TYPE, x);
    codec.nestEnd(list, nest);
}

test "parse dispatches the value width on PARAM_TYPE, even when it comes last" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .pci("0000:65:00.0"));
    try buildParam(gpa, &list, "max_macs", @intFromEnum(uapi.ParamType.u32_), true, &.{
        .{ .cmode = .driverinit, .data = &.{ 0x80, 0x00, 0x00, 0x00 } },
    });

    var p = try parse(gpa, list.items);
    defer p.deinit(gpa);
    try testing.expectEqualStrings("max_macs", p.name());
    try testing.expect(p.generic);
    try testing.expectEqual(@as(?uapi.ParamType, .u32_), p.type);
    try testing.expectEqualStrings("0000:65:00.0", p.handle.dev());
    try testing.expectEqual(@as(usize, 1), p.values.len);

    const di = p.forCmode(.driverinit).?;
    try testing.expectEqual(@as(?u64, 128), di.value.?.asInt());
    try testing.expectEqual(Value{ .uint32 = 128 }, di.value.?);
    try testing.expect(p.forCmode(.runtime) == null);
}

test "parse handles every declared type" {
    const gpa = testing.allocator;
    const cases = [_]struct { t: uapi.ParamType, data: []const u8, want: Value }{
        .{ .t = .u8_, .data = &.{7}, .want = .{ .uint8 = 7 } },
        .{ .t = .u16_, .data = &.{ 0x01, 0x02 }, .want = .{ .uint16 = 0x0201 } },
        .{ .t = .u32_, .data = &.{ 1, 0, 0, 0 }, .want = .{ .uint32 = 1 } },
        .{ .t = .u64_, .data = &.{ 0, 0, 0, 0, 0, 0, 0, 1 }, .want = .{ .uint64 = 1 << 56 } },
        .{ .t = .flag, .data = &.{}, .want = .{ .flag = true } },
    };
    for (cases) |c| {
        if (native_endian != .little and (c.t == .u16_ or c.t == .u32_ or c.t == .u64_)) continue;
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try buildParam(gpa, &list, "p", @intFromEnum(c.t), false, &.{
            .{ .cmode = .runtime, .data = c.data },
        });
        var p = try parse(gpa, list.items);
        defer p.deinit(gpa);
        try testing.expectEqual(c.want, p.forCmode(.runtime).?.value.?);
    }

    // Strings are their own case: the payload keeps its NUL on the wire.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try buildParam(gpa, &list, "p", @intFromEnum(uapi.ParamType.string), false, &.{
        .{ .cmode = .permanent, .data = "flash\x00" },
    });
    var p = try parse(gpa, list.items);
    defer p.deinit(gpa);
    try testing.expectEqualStrings("flash", p.forCmode(.permanent).?.value.?.asBytes().?);
}

test "a declared width the data does not match is a malformed reply" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // Declared u32, sent 8 bytes wide.
    try buildParam(gpa, &list, "p", @intFromEnum(uapi.ParamType.u32_), false, &.{
        .{ .cmode = .runtime, .data = &.{ 0, 0, 0, 0, 0, 0, 0, 0 } },
    });
    try testing.expectError(error.BadLength, parse(gpa, list.items));
}

test "an unknown PARAM_TYPE keeps the raw bytes instead of dropping the value" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try buildParam(gpa, &list, "future", 200, false, &.{
        .{ .cmode = .runtime, .data = &.{ 0xde, 0xad } },
    });
    var p = try parse(gpa, list.items);
    defer p.deinit(gpa);
    try testing.expectEqual(@as(u8, 200), @intFromEnum(p.type.?));
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, p.forCmode(.runtime).?.value.?.asBytes().?);
}

test "a cmode with no data is 'supported but unset', not absent" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try buildParam(gpa, &list, "enable_roce", @intFromEnum(uapi.ParamType.flag), true, &.{
        .{ .cmode = .runtime, .data = &.{} },
        .{ .cmode = .permanent, .data = null },
    });
    var p = try parse(gpa, list.items);
    defer p.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), p.values.len);
    try testing.expectEqual(Value{ .flag = true }, p.forCmode(.runtime).?.value.?);
    // Present entry, absent value.
    try testing.expect(p.forCmode(.permanent) != null);
    try testing.expect(p.forCmode(.permanent).?.value == null);
}

test "reloadWouldChange compares runtime against driverinit" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try buildParam(gpa, &list, "enable_roce", @intFromEnum(uapi.ParamType.u8_), true, &.{
        .{ .cmode = .runtime, .data = &.{1} },
        .{ .cmode = .driverinit, .data = &.{0} },
    });
    var p = try parse(gpa, list.items);
    defer p.deinit(gpa);
    try testing.expect(p.reloadWouldChange());

    list.clearRetainingCapacity();
    try buildParam(gpa, &list, "enable_roce", @intFromEnum(uapi.ParamType.u8_), true, &.{
        .{ .cmode = .runtime, .data = &.{1} },
        .{ .cmode = .driverinit, .data = &.{1} },
    });
    var q = try parse(gpa, list.items);
    defer q.deinit(gpa);
    try testing.expect(!q.reloadWouldChange());

    // A parameter with only one cmode cannot be changed by a reload.
    list.clearRetainingCapacity();
    try buildParam(gpa, &list, "x", @intFromEnum(uapi.ParamType.u8_), false, &.{
        .{ .cmode = .runtime, .data = &.{1} },
    });
    var r = try parse(gpa, list.items);
    defer r.deinit(gpa);
    try testing.expect(!r.reloadWouldChange());
}

test "a values list longer than max_values is refused, not allocated" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var specs: [max_values + 1]ValueSpec = undefined;
    for (&specs) |*s| s.* = .{ .cmode = .runtime, .data = &.{1} };
    try buildParam(gpa, &list, "p", @intFromEnum(uapi.ParamType.u8_), false, &specs);
    try testing.expectError(error.BadLength, parse(gpa, list.items));
}

test "hostile nesting is a typed error" {
    const gpa = testing.allocator;
    // PARAM nest claiming more than the buffer holds.
    try testing.expectError(error.Truncated, parse(gpa, &.{ 0x40, 0x00, 0x50, 0x00, 0x01 }));
    // Inner values-list TLV truncated.
    try testing.expectError(error.Truncated, parse(gpa, &.{
        0x0c, 0x00, 0x50, 0x00, // PARAM nest, len 12
        0x40, 0x00, 0x54, 0x00, // PARAM_VALUES_LIST claiming 64 bytes
        0x00, 0x00, 0x00, 0x00,
    }));
}

test "appendSet derives PARAM_TYPE from the value, so they cannot disagree" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendSet(gpa, &list, .pci("0000:00:00.0"), "max_macs", .driverinit, .{ .uint32 = 128 });
    try testing.expectEqualSlices(u8, &.{
        0x0d, 0x00, 0x51, 0x00, // PARAM_NAME, len 13
        'm',  'a',  'x',  '_',
        'm',  'a',  'c',  's',
        0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x53, 0x00, // PARAM_TYPE
        0x03, 0x00, 0x00, 0x00, // u32_ = 3
        0x05, 0x00, 0x57, 0x00, // PARAM_VALUE_CMODE
        0x01, 0x00, 0x00, 0x00, // driverinit = 1
        0x08, 0x00, 0x56, 0x00, // PARAM_VALUE_DATA
        0x80, 0x00, 0x00, 0x00,
    }, list.items[28..]);
}

test "appendSet expresses a false flag by omitting the data attribute" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var on: std.ArrayList(u8) = .empty;
    defer on.deinit(gpa);
    var off: std.ArrayList(u8) = .empty;
    defer off.deinit(gpa);
    try appendSet(gpa, &on, .pci("0000:00:00.0"), "enable_roce", .runtime, .{ .flag = true });
    try appendSet(gpa, &off, .pci("0000:00:00.0"), "enable_roce", .runtime, .{ .flag = false });
    // "on" carries exactly one extra 4-byte TLV: the empty DATA attribute.
    try testing.expectEqual(off.items.len + 4, on.items.len);
    try testing.expectEqualSlices(u8, off.items, on.items[0..off.items.len]);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x00, 0x56, 0x00 }, on.items[off.items.len..]);
}

test "appendSet round-trips through the decoder for every integer width" {
    const gpa = testing.allocator;
    const vals = [_]Value{
        .{ .uint8 = 0xff },
        .{ .uint16 = 0xbeef },
        .{ .uint32 = 0xdeadbeef },
        .{ .uint64 = 0x0123456789abcdef },
        .{ .string = try Bytes.from("driver") },
    };
    for (vals) |v| {
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);
        try appendSet(gpa, &msg, .pci("0000:00:00.0"), "p", .runtime, v);

        // Re-shape the flat SET attributes into the nested GET form and decode.
        var reply: std.ArrayList(u8) = .empty;
        defer reply.deinit(gpa);
        const nest = try codec.nestBegin(gpa, &reply, uapi.ATTR.PARAM);
        try codec.appendAttrString(gpa, &reply, uapi.ATTR.PARAM_NAME, "p");
        try codec.appendAttrU8(gpa, &reply, uapi.ATTR.PARAM_TYPE, @intFromEnum(v.paramType()));
        const vl = try codec.nestBegin(gpa, &reply, uapi.ATTR.PARAM_VALUES_LIST);
        const one = try codec.nestBegin(gpa, &reply, uapi.ATTR.PARAM_VALUE);
        // Copy the DATA attribute verbatim out of the request.
        var it: codec.AttrIterator = .{ .buf = msg.items };
        while (try it.next()) |a| {
            if (a.type == uapi.ATTR.PARAM_VALUE_DATA)
                try codec.appendAttr(gpa, &reply, uapi.ATTR.PARAM_VALUE_DATA, a.data);
        }
        try codec.appendAttrU8(gpa, &reply, uapi.ATTR.PARAM_VALUE_CMODE, @intFromEnum(uapi.ParamCmode.runtime));
        codec.nestEnd(&reply, one);
        codec.nestEnd(&reply, vl);
        codec.nestEnd(&reply, nest);

        var p = try parse(gpa, reply.items);
        defer p.deinit(gpa);
        try testing.expectEqual(v, p.forCmode(.runtime).?.value.?);
    }
}

test "appendSet rejects a name the kernel would reject" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const h: handle.Handle = .pci("0000:00:00.0");
    try testing.expectError(error.InvalidRequest, appendSet(gpa, &list, h, "", .runtime, .{ .flag = true }));
    try testing.expectError(error.InvalidRequest, appendSet(gpa, &list, h, "a\x00b", .runtime, .{ .flag = true }));
    try testing.expectError(error.InvalidRequest, appendSet(
        gpa,
        &list,
        h,
        "n" ** (uapi.name_max + 1),
        .runtime,
        .{ .flag = true },
    ));
}

test "Bytes.from bounds the value length" {
    try testing.expectError(error.InvalidRequest, Bytes.from("v" ** (uapi.value_max + 1)));
    const b = try Bytes.from("v" ** uapi.value_max);
    try testing.expectEqual(@as(usize, uapi.value_max), b.get().len);
}

test "fuzz: parameter decoding never crashes" {
    try testing.fuzz({}, fuzzParam, .{});
}

fn fuzzParam(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    if (parse(testing.allocator, buf[0..len])) |p| {
        var v = p;
        _ = v.reloadWouldChange();
        v.deinit(testing.allocator);
    } else |_| {}
}
