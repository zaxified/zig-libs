// SPDX-License-Identifier: MIT
//! Pluggable-transceiver (SFP/SFP+/QSFP/CMIS) access: `MODULE_GET`/`MODULE_SET`
//! for the low-power-mode policy, and `MODULE_EEPROM_GET` for raw pages off the
//! module's I2C EEPROM.
//!
//! ## What this does and does not do
//!
//! `MODULE_EEPROM_GET` returns **raw bytes** — a window into SFF-8472 /
//! SFF-8636 / CMIS memory chosen by (page, bank, i2c address, offset, length).
//! This module hands those bytes back and stops there: decoding vendor strings,
//! wavelengths, DOM voltages and per-lane power out of them is a completely
//! separate spec family and is deliberately **not** in v1 (see SPEC.md). What
//! is here is enough to fetch a page and hand it to a decoder — which is also
//! what `ethtool -m` does before its own pretty-printer runs.
//!
//! The kernel caps one request at 128 bytes (`ETHTOOL_MODULE_EEPROM_MAX_LEN`
//! in `net/ethtool/module.c`), so a full 256-byte page is two requests; that
//! ceiling is enforced here rather than being learned from an `EINVAL`.
//!
//! On a device with no pluggable module — which is every NIC with a fixed
//! copper PHY — both messages answer `EOPNOTSUPP`. That is normal, not a
//! failure, and the client maps it to `error.NotSupported`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const header = @import("header.zig");

/// `ETHTOOL_MODULE_EEPROM_MAX_LEN` — the kernel's per-request ceiling.
pub const max_eeprom_read: u32 = 128;

/// `ETHTOOL_MSG_MODULE_GET` reply.
pub const ModuleInfo = struct {
    device: header.Device = .{},
    /// The configured low-power-mode policy.
    power_mode_policy: ?uapi.ModulePowerModePolicy = null,
    /// The mode the module is actually in right now.
    power_mode: ?uapi.ModulePowerMode = null,
};

pub fn parse(attr_bytes: []const u8) codec.Error!ModuleInfo {
    var out: ModuleInfo = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.MODULE.HEADER => out.device = try header.parse(a.data),
        uapi.MODULE.POWER_MODE_POLICY => out.power_mode_policy = @enumFromInt(try a.asU8()),
        uapi.MODULE.POWER_MODE => out.power_mode = @enumFromInt(try a.asU8()),
        else => {},
    };
    return out;
}

pub fn appendSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    policy: uapi.ModulePowerModePolicy,
) std.mem.Allocator.Error!void {
    try codec.appendAttrU8(gpa, list, uapi.MODULE.POWER_MODE_POLICY, @intFromEnum(policy));
}

/// Which window of the module's EEPROM to read.
pub const EepromRequest = struct {
    /// Byte offset within the page.
    offset: u32 = 0,
    /// Bytes to read; 1..=`max_eeprom_read`.
    length: u32 = max_eeprom_read,
    /// Page number (0 = the base page).
    page: u8 = 0,
    /// Bank number, for CMIS modules with banked pages.
    bank: u8 = 0,
    /// I2C address the page lives at — `0x50` for the base memory,
    /// `0x51` for SFF-8472 diagnostics.
    i2c_address: u8 = uapi.I2C_ADDRESS_LOW,
};

pub fn appendEepromRequest(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    req: EepromRequest,
) (std.mem.Allocator.Error || error{InvalidRequest})!void {
    if (req.length == 0 or req.length > max_eeprom_read) return error.InvalidRequest;
    // The kernel's policy allows only the two SFF I2C addresses; anything else
    // would be a bus scan, and it says so with EINVAL.
    if (req.i2c_address != uapi.I2C_ADDRESS_LOW and req.i2c_address != uapi.I2C_ADDRESS_HIGH)
        return error.InvalidRequest;
    try codec.appendAttrU32(gpa, list, uapi.MODULE_EEPROM.LENGTH, req.length);
    try codec.appendAttrU32(gpa, list, uapi.MODULE_EEPROM.OFFSET, req.offset);
    try codec.appendAttrU8(gpa, list, uapi.MODULE_EEPROM.PAGE, req.page);
    try codec.appendAttrU8(gpa, list, uapi.MODULE_EEPROM.BANK, req.bank);
    try codec.appendAttrU8(gpa, list, uapi.MODULE_EEPROM.I2C_ADDRESS, req.i2c_address);
}

/// `ETHTOOL_MSG_MODULE_EEPROM_GET` reply — raw bytes, undecoded on purpose.
/// Owns `data`.
pub const Eeprom = struct {
    device: header.Device = .{},
    data: []u8 = &.{},

    pub fn deinit(e: *Eeprom, gpa: std.mem.Allocator) void {
        gpa.free(e.data);
        e.* = .{};
    }
};

pub fn parseEeprom(gpa: std.mem.Allocator, attr_bytes: []const u8) (codec.Error || error{OutOfMemory})!Eeprom {
    var out: Eeprom = .{};
    errdefer out.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.MODULE_EEPROM.HEADER => out.device = try header.parse(a.data),
        uapi.MODULE_EEPROM.DATA => {
            if (out.data.len != 0) return error.BadLength;
            if (a.data.len > max_eeprom_read) return error.BadLength;
            out.data = try gpa.dupe(u8, a.data);
        },
        else => {},
    };
    return out;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const native_endian = @import("builtin").cpu.arch.endian();

test "MODULE_GET decodes the two power-mode fields" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try header.append(gpa, &list, uapi.MODULE.HEADER, .{ .target = .byIndex(4) });
    try appendSet(gpa, &list, .auto);
    try codec.appendAttrU8(gpa, &list, uapi.MODULE.POWER_MODE, @intFromEnum(uapi.ModulePowerMode.high));

    const m = try parse(list.items);
    try testing.expectEqual(@as(?u32, 4), m.device.index);
    try testing.expectEqual(uapi.ModulePowerModePolicy.auto, m.power_mode_policy.?);
    try testing.expectEqual(uapi.ModulePowerMode.high, m.power_mode.?);
}

test "EEPROM request encodes the ethtool -m attribute order" {
    if (native_endian != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendEepromRequest(gpa, &list, .{ .length = 1, .offset = 0 });
    try testing.expectEqualSlices(u8, &.{
        0x08, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, // LENGTH = 1
        0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // OFFSET = 0
        0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // PAGE = 0
        0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // BANK = 0
        0x05, 0x00, 0x06, 0x00, 0x50, 0x00, 0x00, 0x00, // I2C_ADDRESS = 0x50
    }, list.items);
}

test "EEPROM request refuses what the kernel would EINVAL" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.InvalidRequest, appendEepromRequest(gpa, &list, .{ .length = 0 }));
    try testing.expectError(error.InvalidRequest, appendEepromRequest(gpa, &list, .{ .length = 129 }));
    try testing.expectError(error.InvalidRequest, appendEepromRequest(gpa, &list, .{ .i2c_address = 0x30 }));
    try appendEepromRequest(gpa, &list, .{ .i2c_address = uapi.I2C_ADDRESS_HIGH, .page = 2, .bank = 1 });
}

test "EEPROM reply hands back raw bytes and bounds them" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttr(gpa, &list, uapi.MODULE_EEPROM.DATA, &.{ 0x03, 0x04, 0x07 });
    var e = try parseEeprom(gpa, list.items);
    defer e.deinit(gpa);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x04, 0x07 }, e.data);

    // More than the kernel's own ceiling is a malformed reply.
    list.clearRetainingCapacity();
    const big = [_]u8{0} ** (max_eeprom_read + 1);
    try codec.appendAttr(gpa, &list, uapi.MODULE_EEPROM.DATA, &big);
    try testing.expectError(error.BadLength, parseEeprom(gpa, list.items));
}

test "malformed module replies are typed errors" {
    const gpa = testing.allocator;
    try testing.expectError(error.BadLength, parse(&.{ 0x08, 0x00, 0x02, 0x00, 1, 0, 0, 0 }));
    try testing.expectError(error.Truncated, parseEeprom(gpa, &.{ 0x40, 0x00, 0x07, 0x00, 1 }));
}
