// SPDX-License-Identifier: MIT
//! Device enumeration (`DEVLINK_CMD_GET`) and device information
//! (`DEVLINK_CMD_INFO_GET`).
//!
//! ## `DEVLINK_CMD_GET`
//!
//! The dump form (`devlink dev show`) answers with one message per registered
//! devlink instance, each carrying little more than its handle:
//!
//! ```text
//! BUS_NAME       string
//! DEV_NAME       string
//! RELOAD_FAILED  u8      (optional; 1 = the last `devlink dev reload` failed)
//! DEV_STATS      nested  (reload statistics — see the deferred list in SPEC.md)
//! NESTED_DEVLINK nested  (a linecard's or SF's own instance)
//! ```
//!
//! **A machine with no SmartNIC and no switch ASIC answers with an empty
//! dump** — `NLMSG_DONE` and nothing else. That is the normal case on a laptop
//! or an ordinary server: devlink is implemented by mlx5, mlx4, ice, bnxt,
//! nfp, mlxsw, prestera, netdevsim and a handful of others; an e1000e or a
//! Wi-Fi radio registers no instance at all.
//!
//! ## `DEVLINK_CMD_INFO_GET`
//!
//! ```text
//! BUS_NAME / DEV_NAME
//! INFO_DRIVER_NAME          string
//! INFO_SERIAL_NUMBER        string
//! INFO_BOARD_SERIAL_NUMBER  string
//! INFO_VERSION_FIXED    nested { INFO_VERSION_NAME, INFO_VERSION_VALUE }  ─┐ repeated,
//! INFO_VERSION_RUNNING  nested { … }                                      ├─ once per
//! INFO_VERSION_STORED   nested { … }                                     ─┘ version
//! ```
//!
//! The three version nests are *repeated sibling attributes*, not one nest
//! containing many — so the decoder appends rather than replaces, and the
//! `kind` that distinguishes "burned into the board" from "running right now"
//! from "flashed and waiting for a reload" is the attribute type itself.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const handle = @import("handle.zig");

pub const ParseError = codec.Error || error{ OutOfMemory, TooManyVersions };

/// Ceiling on the number of version-nest attributes `parseInfo` will collect
/// per reply. No real driver reports anywhere close to this many (double- and
/// triple-digit counts are typical for the largest firmware bundles) — the
/// cap exists because the reply is untrusted-boundary data and the version
/// list otherwise grows one `ArrayList.append` per attribute with no bound at
/// all, unlike `resource.zig`'s `max_nodes`/`param.zig`'s `max_values`, which
/// already cap their own repeated-nest lists the same way.
pub const max_versions = 4096;

// ── DEVLINK_CMD_GET ────────────────────────────────────────────────────────

/// One registered devlink instance. Self-contained: no allocation, safe to
/// keep in a plain slice.
pub const Device = struct {
    handle: handle.Owned = .{},
    /// `DEVLINK_ATTR_RELOAD_FAILED` — the previous reload left the driver in a
    /// broken state. Absent on a kernel or driver that does not report it.
    reload_failed: ?bool = null,
    /// The instance publishes reload statistics (`DEVLINK_ATTR_DEV_STATS`).
    /// The nest itself is not decoded — see SPEC.md.
    has_reload_stats: bool = false,
    /// The instance carries a `DEVLINK_ATTR_NESTED_DEVLINK` — it stands for
    /// another devlink instance (a linecard, or a subfunction's own).
    nested: bool = false,
};

/// Decode one `DEVLINK_CMD_GET`/`NEW` message's attribute bytes.
pub fn parseDevice(attr_bytes: []const u8) codec.Error!Device {
    var d: Device = .{};
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.BUS_NAME => try uapi.copyName(&d.handle.bus_buf, &d.handle.bus_len, a),
        uapi.ATTR.DEV_NAME => try uapi.copyName(&d.handle.dev_buf, &d.handle.dev_len, a),
        uapi.ATTR.RELOAD_FAILED => d.reload_failed = (try a.asU8()) != 0,
        uapi.ATTR.DEV_STATS => d.has_reload_stats = true,
        uapi.ATTR.NESTED_DEVLINK => d.nested = true,
        else => {},
    };
    return d;
}

// ── DEVLINK_CMD_INFO_GET ───────────────────────────────────────────────────

/// Which of the three version nests a `Version` came out of.
pub const VersionKind = enum {
    /// `INFO_VERSION_FIXED` — burned into the board; cannot change without
    /// replacing hardware.
    fixed,
    /// `INFO_VERSION_RUNNING` — what the device is executing now.
    running,
    /// `INFO_VERSION_STORED` — flashed into non-volatile memory, and will
    /// become `running` after the next reset. Differing from `running` is how
    /// "a firmware update is pending a reboot" is visible.
    stored,
};

/// One name/value pair out of a version nest, copied inline.
pub const Version = struct {
    kind: VersionKind,
    name_buf: [uapi.name_max]u8 = @splat(0),
    name_len: u8 = 0,
    value_buf: [uapi.value_max]u8 = @splat(0),
    value_len: u8 = 0,

    pub fn name(v: *const Version) []const u8 {
        return v.name_buf[0..v.name_len];
    }

    pub fn value(v: *const Version) []const u8 {
        return v.value_buf[0..v.value_len];
    }
};

/// A device's identity and firmware inventory. `versions` is heap-allocated;
/// free with `deinit`.
pub const Info = struct {
    handle: handle.Owned = .{},
    driver_name_buf: [uapi.name_max]u8 = @splat(0),
    driver_name_len: u8 = 0,
    serial_buf: [uapi.value_max]u8 = @splat(0),
    serial_len: u8 = 0,
    board_serial_buf: [uapi.value_max]u8 = @splat(0),
    board_serial_len: u8 = 0,
    versions: []Version = &.{},

    pub fn driverName(i: *const Info) []const u8 {
        return i.driver_name_buf[0..i.driver_name_len];
    }

    /// The device's serial number, usually the PCI DSN. **Personally
    /// identifying for a machine** — it is stable across reinstalls — so treat
    /// it the way you would a MAC address.
    pub fn serialNumber(i: *const Info) []const u8 {
        return i.serial_buf[0..i.serial_len];
    }

    /// The *board's* serial number, which on a multi-port card is shared by
    /// every function on it.
    pub fn boardSerialNumber(i: *const Info) []const u8 {
        return i.board_serial_buf[0..i.board_serial_len];
    }

    /// The first version of `kind` named `n`, or null.
    pub fn find(i: *const Info, kind: VersionKind, n: []const u8) ?*const Version {
        for (i.versions) |*v| {
            if (v.kind == kind and std.mem.eql(u8, v.name(), n)) return v;
        }
        return null;
    }

    /// Is a firmware update flashed but not yet activated? True when some
    /// version name exists in both `stored` and `running` with different
    /// values. A device that reports no `stored` versions always answers false.
    pub fn hasPendingUpdate(i: *const Info) bool {
        for (i.versions) |*v| {
            if (v.kind != .stored) continue;
            const running = i.find(.running, v.name()) orelse continue;
            if (!std.mem.eql(u8, running.value(), v.value())) return true;
        }
        return false;
    }

    pub fn deinit(i: *Info, gpa: std.mem.Allocator) void {
        gpa.free(i.versions);
        i.versions = &.{};
    }
};

fn kindOf(attr_type: u16) ?VersionKind {
    return switch (attr_type) {
        uapi.ATTR.INFO_VERSION_FIXED => .fixed,
        uapi.ATTR.INFO_VERSION_RUNNING => .running,
        uapi.ATTR.INFO_VERSION_STORED => .stored,
        else => null,
    };
}

/// Decode one `DEVLINK_CMD_INFO_GET` reply. Free the result with `deinit`.
pub fn parseInfo(gpa: std.mem.Allocator, attr_bytes: []const u8) ParseError!Info {
    var info: Info = .{};
    var versions: std.ArrayList(Version) = .empty;
    errdefer versions.deinit(gpa);

    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.BUS_NAME => try uapi.copyName(&info.handle.bus_buf, &info.handle.bus_len, a),
        uapi.ATTR.DEV_NAME => try uapi.copyName(&info.handle.dev_buf, &info.handle.dev_len, a),
        uapi.ATTR.INFO_DRIVER_NAME => try uapi.copyName(&info.driver_name_buf, &info.driver_name_len, a),
        uapi.ATTR.INFO_SERIAL_NUMBER => try uapi.copyName(&info.serial_buf, &info.serial_len, a),
        uapi.ATTR.INFO_BOARD_SERIAL_NUMBER => try uapi.copyName(&info.board_serial_buf, &info.board_serial_len, a),
        else => {
            const kind = kindOf(a.type) orelse continue;
            var v: Version = .{ .kind = kind };
            var inner: codec.AttrIterator = .{ .buf = a.data };
            var saw_name = false;
            while (try inner.next()) |x| switch (x.type) {
                uapi.ATTR.INFO_VERSION_NAME => {
                    try uapi.copyName(&v.name_buf, &v.name_len, x);
                    saw_name = true;
                },
                uapi.ATTR.INFO_VERSION_VALUE => try uapi.copyName(&v.value_buf, &v.value_len, x),
                else => {},
            };
            // A nest with no NAME identifies nothing; the kernel always sends
            // one, so its absence is a malformed reply rather than an
            // anonymous version to be silently kept.
            if (!saw_name) return error.BadLength;
            if (versions.items.len >= max_versions) return error.TooManyVersions;
            try versions.append(gpa, v);
        },
    };
    info.versions = try versions.toOwnedSlice(gpa);
    return info;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

fn appendVersion(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr: u16,
    n: []const u8,
    v: []const u8,
) !void {
    const nest = try codec.nestBegin(gpa, list, attr);
    try codec.appendAttrString(gpa, list, uapi.ATTR.INFO_VERSION_NAME, n);
    try codec.appendAttrString(gpa, list, uapi.ATTR.INFO_VERSION_VALUE, v);
    codec.nestEnd(list, nest);
}

test "parseDevice reads the handle and the optional flags" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .pci("0000:65:00.0"));
    try codec.appendAttrU8(gpa, &list, uapi.ATTR.RELOAD_FAILED, 0);
    const stats = try codec.nestBegin(gpa, &list, uapi.ATTR.DEV_STATS);
    codec.nestEnd(&list, stats);

    const d = try parseDevice(list.items);
    try testing.expect(d.handle.isComplete());
    try testing.expectEqualStrings("pci", d.handle.bus());
    try testing.expectEqualStrings("0000:65:00.0", d.handle.dev());
    try testing.expectEqual(@as(?bool, false), d.reload_failed);
    try testing.expect(d.has_reload_stats);
    try testing.expect(!d.nested);
}

test "parseDevice on a bare handle leaves the optionals absent" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .{ .bus = "netdevsim", .dev = "netdevsim1" });
    const d = try parseDevice(list.items);
    try testing.expectEqual(@as(?bool, null), d.reload_failed);
    try testing.expect(!d.has_reload_stats);
}

test "parseInfo collects the three version kinds as repeated siblings" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .pci("0000:65:00.0"));
    try codec.appendAttrString(gpa, &list, uapi.ATTR.INFO_DRIVER_NAME, "mlx5_core");
    try codec.appendAttrString(gpa, &list, uapi.ATTR.INFO_SERIAL_NUMBER, "MT0000X00000");
    try codec.appendAttrString(gpa, &list, uapi.ATTR.INFO_BOARD_SERIAL_NUMBER, "MT0000X00000");
    try appendVersion(gpa, &list, uapi.ATTR.INFO_VERSION_FIXED, "fw.psid", "MT_0000000000");
    try appendVersion(gpa, &list, uapi.ATTR.INFO_VERSION_RUNNING, "fw.version", "22.35.1012");
    try appendVersion(gpa, &list, uapi.ATTR.INFO_VERSION_RUNNING, "fw", "22.35.1012");
    try appendVersion(gpa, &list, uapi.ATTR.INFO_VERSION_STORED, "fw.version", "22.36.1010");

    var info = try parseInfo(gpa, list.items);
    defer info.deinit(gpa);

    try testing.expectEqualStrings("mlx5_core", info.driverName());
    try testing.expectEqualStrings("MT0000X00000", info.serialNumber());
    try testing.expectEqualStrings("MT0000X00000", info.boardSerialNumber());
    try testing.expectEqual(@as(usize, 4), info.versions.len);

    try testing.expectEqualStrings("MT_0000000000", info.find(.fixed, "fw.psid").?.value());
    try testing.expectEqualStrings("22.35.1012", info.find(.running, "fw.version").?.value());
    try testing.expectEqualStrings("22.36.1010", info.find(.stored, "fw.version").?.value());
    // Same name, different nest: the kinds must not collide.
    try testing.expect(info.find(.stored, "fw") == null);
    try testing.expect(info.find(.fixed, "nope") == null);

    // stored != running for "fw.version" ⇒ an update is waiting for a reset.
    try testing.expect(info.hasPendingUpdate());
}

test "parseInfo: matching stored and running versions are not a pending update" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendVersion(gpa, &list, uapi.ATTR.INFO_VERSION_RUNNING, "fw.version", "1.2.3");
    try appendVersion(gpa, &list, uapi.ATTR.INFO_VERSION_STORED, "fw.version", "1.2.3");
    var info = try parseInfo(gpa, list.items);
    defer info.deinit(gpa);
    try testing.expect(!info.hasPendingUpdate());
}

test "parseInfo: an unnamed version nest is a malformed reply" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const nest = try codec.nestBegin(gpa, &list, uapi.ATTR.INFO_VERSION_RUNNING);
    try codec.appendAttrString(gpa, &list, uapi.ATTR.INFO_VERSION_VALUE, "1.0");
    codec.nestEnd(&list, nest);
    try testing.expectError(error.BadLength, parseInfo(gpa, list.items));
}

test "parseInfo: the version list is capped, not grown one append at a time forever" {
    // `parseInfo`'s reply is untrusted-boundary data (a netlink socket, not
    // necessarily this host's real kernel), and the version list used to grow
    // with no bound at all -- one `ArrayList.append` per version-nest
    // attribute, unlike `resource.zig`/`param.zig`'s own repeated-nest lists,
    // which already cap. `max_versions + 1` distinct nests must be rejected;
    // `max_versions` exactly must still be accepted.
    const gpa = testing.allocator;
    var over: std.ArrayList(u8) = .empty;
    defer over.deinit(gpa);
    var i: usize = 0;
    while (i < max_versions + 1) : (i += 1) {
        try appendVersion(gpa, &over, uapi.ATTR.INFO_VERSION_RUNNING, "n", "v");
    }
    try testing.expectError(error.TooManyVersions, parseInfo(gpa, over.items));

    var exact: std.ArrayList(u8) = .empty;
    defer exact.deinit(gpa);
    i = 0;
    while (i < max_versions) : (i += 1) {
        try appendVersion(gpa, &exact, uapi.ATTR.INFO_VERSION_RUNNING, "n", "v");
    }
    var info = try parseInfo(gpa, exact.items);
    defer info.deinit(gpa);
    try testing.expectEqual(@as(usize, max_versions), info.versions.len);
}

test "parseInfo: hostile input is a typed error, never a read past the end" {
    const gpa = testing.allocator;
    // A nest claiming more bytes than the buffer holds.
    try testing.expectError(error.Truncated, parseInfo(gpa, &.{ 0x40, 0x00, 0x65, 0x00, 0x01 }));
    // A version nest whose inner TLV is truncated.
    try testing.expectError(error.Truncated, parseInfo(gpa, &.{
        0x09, 0x00, 0x65, 0x00, // nest len 9, INFO_VERSION_RUNNING
        0x20, 0x00, 0x67, 0x00, // inner len 32 — more than the 5 bytes present
        0x00,
    }));
    // An over-long driver name.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try codec.appendAttrString(gpa, &list, uapi.ATTR.INFO_DRIVER_NAME, "d" ** (uapi.name_max + 1));
    try testing.expectError(error.BadLength, parseInfo(gpa, list.items));
}

test "fuzz: device and info decoding never crash" {
    try testing.fuzz({}, fuzzDev, .{});
}

fn fuzzDev(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    if (parseDevice(buf[0..len])) |d| std.mem.doNotOptimizeAway(&d) else |_| {}
    if (parseInfo(testing.allocator, buf[0..len])) |info| {
        var v = info;
        _ = v.hasPendingUpdate();
        v.deinit(testing.allocator);
    } else |_| {}
}
