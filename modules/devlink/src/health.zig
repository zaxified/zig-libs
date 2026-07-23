// SPDX-License-Identifier: MIT
//! Health reporters: `DEVLINK_CMD_HEALTH_REPORTER_GET` (dump and single) and
//! `DEVLINK_CMD_HEALTH_REPORTER_RECOVER`.
//!
//! A health reporter is a named fault domain a driver watches — `fw`,
//! `fw_fatal`, `tx`, `rx`, `hw`. When it trips, the driver records an error,
//! optionally takes a dump, and optionally recovers itself. The counters are
//! the useful part: `err_count` rising without `recover_count` following it is
//! a device that is failing and *not* healing.
//!
//! ```text
//! BUS_NAME / DEV_NAME  (+ PORT_INDEX for a per-port reporter)
//! HEALTH_REPORTER                    nest
//!   HEALTH_REPORTER_NAME             string
//!   HEALTH_REPORTER_STATE            u8    0 healthy / 1 error
//!   HEALTH_REPORTER_ERR_COUNT        u64
//!   HEALTH_REPORTER_RECOVER_COUNT    u64
//!   HEALTH_REPORTER_DUMP_TS          u64   seconds  ─┐ both describe the same
//!   HEALTH_REPORTER_DUMP_TS_NS       u64   nanos    ─┘ dump; 0 = none taken
//!   HEALTH_REPORTER_GRACEFUL_PERIOD  u64   ms between auto-recoveries
//!   HEALTH_REPORTER_AUTO_RECOVER     u8
//!   HEALTH_REPORTER_AUTO_DUMP        u8
//! ```
//!
//! `RECOVER` asks the driver to run its recovery routine now. It needs
//! **CAP_NET_ADMIN**, it is synchronous, and on most drivers it resets part or
//! all of the device — so it is emphatically not a health *check*. The
//! read-only question ("is it healthy") is answered by `GET`.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
const handle = @import("handle.zig");

pub const BuildError = error{ OutOfMemory, InvalidRequest };

/// One health reporter. Self-contained; no allocation.
pub const Reporter = struct {
    handle: handle.Owned = .{},
    /// Present on a per-port reporter.
    port_index: ?u32 = null,
    name_buf: [uapi.name_max]u8 = @splat(0),
    name_len: u8 = 0,
    state: ?uapi.HealthState = null,
    /// How many times this domain has faulted since the driver loaded.
    err_count: ?u64 = null,
    /// How many of those faults the driver recovered from.
    recover_count: ?u64 = null,
    /// Timestamp of the last dump, in seconds and in nanoseconds. Both are 0
    /// when no dump has ever been taken.
    dump_ts: ?u64 = null,
    dump_ts_ns: ?u64 = null,
    /// Minimum time between automatic recoveries, in milliseconds.
    graceful_period: ?u64 = null,
    auto_recover: ?bool = null,
    auto_dump: ?bool = null,

    pub fn name(r: *const Reporter) []const u8 {
        return r.name_buf[0..r.name_len];
    }

    pub fn isHealthy(r: Reporter) ?bool {
        const s = r.state orelse return null;
        return s == .healthy;
    }

    /// Faults this reporter has *not* recovered from. Null unless the driver
    /// reported both counters.
    ///
    /// Note the saturating subtraction: `recover_count` can legitimately
    /// exceed `err_count` because a manual `RECOVER` bumps it without a fault
    /// having occurred, so the difference is clamped at zero rather than
    /// wrapping into a very large number.
    pub fn unrecoveredCount(r: Reporter) ?u64 {
        const e = r.err_count orelse return null;
        const c = r.recover_count orelse return null;
        return if (e > c) e - c else 0;
    }

    /// Has a dump been taken and not yet cleared?
    pub fn hasDump(r: Reporter) bool {
        return (r.dump_ts orelse 0) != 0 or (r.dump_ts_ns orelse 0) != 0;
    }
};

/// Decode the contents of one `DEVLINK_ATTR_HEALTH_REPORTER` nest.
pub fn parseNest(nest_bytes: []const u8) codec.Error!Reporter {
    var r: Reporter = .{};
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.HEALTH_REPORTER_NAME => try uapi.copyName(&r.name_buf, &r.name_len, a),
        uapi.ATTR.HEALTH_REPORTER_STATE => r.state = @enumFromInt(try a.asU8()),
        uapi.ATTR.HEALTH_REPORTER_ERR_COUNT => r.err_count = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_RECOVER_COUNT => r.recover_count = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_DUMP_TS => r.dump_ts = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_DUMP_TS_NS => r.dump_ts_ns = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_GRACEFUL_PERIOD => r.graceful_period = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_AUTO_RECOVER => r.auto_recover = (try a.asU8()) != 0,
        uapi.ATTR.HEALTH_REPORTER_AUTO_DUMP => r.auto_dump = (try a.asU8()) != 0,
        else => {},
    };
    return r;
}

/// Decode one `DEVLINK_CMD_HEALTH_REPORTER_GET` message. A message with no
/// reporter nest yields a reporter with an empty name.
pub fn parse(attr_bytes: []const u8) codec.Error!Reporter {
    var out: Reporter = .{};
    var found = false;
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.BUS_NAME => try uapi.copyName(&out.handle.bus_buf, &out.handle.bus_len, a),
        uapi.ATTR.DEV_NAME => try uapi.copyName(&out.handle.dev_buf, &out.handle.dev_len, a),
        uapi.ATTR.PORT_INDEX => out.port_index = try a.asU32(),
        uapi.ATTR.HEALTH_REPORTER => {
            if (found) continue;
            var inner = try parseNest(a.data);
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

fn appendReporterName(gpa: std.mem.Allocator, list: *std.ArrayList(u8), n: []const u8) BuildError!void {
    if (n.len == 0 or n.len > uapi.name_max) return error.InvalidRequest;
    if (std.mem.indexOfScalar(u8, n, 0) != null) return error.InvalidRequest;
    codec.appendAttrString(gpa, list, uapi.ATTR.HEALTH_REPORTER_NAME, n) catch |e| switch (e) {
        error.AttrTooLong => return error.InvalidRequest,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Attributes of a `DEVLINK_CMD_HEALTH_REPORTER_GET` for one named reporter.
pub fn appendGet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    reporter: []const u8,
) BuildError!void {
    try handle.append(gpa, list, h);
    try appendReporterName(gpa, list, reporter);
}

/// Attributes of a `DEVLINK_CMD_HEALTH_REPORTER_RECOVER`. Needs
/// **CAP_NET_ADMIN**, and typically resets the device.
pub fn appendRecover(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    reporter: []const u8,
) BuildError!void {
    try handle.append(gpa, list, h);
    try appendReporterName(gpa, list, reporter);
}

/// Attributes of a `DEVLINK_CMD_HEALTH_REPORTER_GET` for a **port**'s
/// reporter. Same command; the port index is what selects the port's reporter
/// set rather than the device's.
pub fn appendPortGet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    p: handle.PortHandle,
    reporter: []const u8,
) BuildError!void {
    try handle.appendPort(gpa, list, p);
    try appendReporterName(gpa, list, reporter);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

const ReporterSpec = struct {
    name: []const u8,
    state: u8 = 0,
    err_count: u64 = 0,
    recover_count: u64 = 0,
    dump_ts: u64 = 0,
    auto_recover: u8 = 1,
};

fn buildReporterReply(gpa: std.mem.Allocator, list: *std.ArrayList(u8), s: ReporterSpec) !void {
    try handle.append(gpa, list, .pci("0000:65:00.0"));
    const nest = try codec.nestBegin(gpa, list, uapi.ATTR.HEALTH_REPORTER);
    try codec.appendAttrString(gpa, list, uapi.ATTR.HEALTH_REPORTER_NAME, s.name);
    try codec.appendAttrU8(gpa, list, uapi.ATTR.HEALTH_REPORTER_STATE, s.state);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.HEALTH_REPORTER_ERR_COUNT, s.err_count);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.HEALTH_REPORTER_RECOVER_COUNT, s.recover_count);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.HEALTH_REPORTER_DUMP_TS, s.dump_ts);
    try uapi.appendAttrU64(gpa, list, uapi.ATTR.HEALTH_REPORTER_GRACEFUL_PERIOD, 60000);
    try codec.appendAttrU8(gpa, list, uapi.ATTR.HEALTH_REPORTER_AUTO_RECOVER, s.auto_recover);
    try codec.appendAttrU8(gpa, list, uapi.ATTR.HEALTH_REPORTER_AUTO_DUMP, 1);
    codec.nestEnd(list, nest);
}

test "parse decodes a healthy reporter with no faults" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try buildReporterReply(gpa, &list, .{ .name = "fw" });

    const r = try parse(list.items);
    try testing.expectEqualStrings("fw", r.name());
    try testing.expectEqualStrings("0000:65:00.0", r.handle.dev());
    try testing.expectEqual(@as(?bool, true), r.isHealthy());
    try testing.expectEqual(@as(?u64, 0), r.unrecoveredCount());
    try testing.expectEqual(@as(?u64, 60000), r.graceful_period);
    try testing.expectEqual(@as(?bool, true), r.auto_recover);
    try testing.expect(!r.hasDump());
}

test "parse decodes a reporter in error with an unrecovered fault" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try buildReporterReply(gpa, &list, .{
        .name = "fw_fatal",
        .state = 1,
        .err_count = 3,
        .recover_count = 1,
        .dump_ts = 1723000000,
        .auto_recover = 0,
    });

    const r = try parse(list.items);
    try testing.expectEqual(@as(?bool, false), r.isHealthy());
    try testing.expectEqual(@as(?uapi.HealthState, .@"error"), r.state);
    try testing.expectEqual(@as(?u64, 2), r.unrecoveredCount());
    try testing.expect(r.hasDump());
    try testing.expectEqual(@as(?bool, false), r.auto_recover);
}

test "unrecoveredCount clamps rather than wrapping when recoveries exceed faults" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // A manual RECOVER bumps recover_count without an error having happened.
    try buildReporterReply(gpa, &list, .{ .name = "tx", .err_count = 1, .recover_count = 4 });
    const r = try parse(list.items);
    try testing.expectEqual(@as(?u64, 0), r.unrecoveredCount());
}

test "a reporter with no counters answers null rather than zero" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const nest = try codec.nestBegin(gpa, &list, uapi.ATTR.HEALTH_REPORTER);
    try codec.appendAttrString(gpa, &list, uapi.ATTR.HEALTH_REPORTER_NAME, "rx");
    codec.nestEnd(&list, nest);
    const r = try parse(list.items);
    try testing.expectEqual(@as(?u64, null), r.unrecoveredCount());
    try testing.expectEqual(@as(?bool, null), r.isHealthy());
}

test "a port reporter keeps its port index" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try handle.append(gpa, &list, .pci("0000:65:00.0"));
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.PORT_INDEX, 2);
    const nest = try codec.nestBegin(gpa, &list, uapi.ATTR.HEALTH_REPORTER);
    try codec.appendAttrString(gpa, &list, uapi.ATTR.HEALTH_REPORTER_NAME, "rx");
    codec.nestEnd(&list, nest);
    const r = try parse(list.items);
    try testing.expectEqual(@as(?u32, 2), r.port_index);
    try testing.expectEqualStrings("rx", r.name());
}

test "a nanosecond-only dump timestamp still counts as a dump" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const nest = try codec.nestBegin(gpa, &list, uapi.ATTR.HEALTH_REPORTER);
    try uapi.appendAttrU64(gpa, &list, uapi.ATTR.HEALTH_REPORTER_DUMP_TS_NS, 42);
    codec.nestEnd(&list, nest);
    try testing.expect((try parse(list.items)).hasDump());
}

test "hostile reporter input is a typed error" {
    const gpa = testing.allocator;
    try testing.expectError(error.Truncated, parse(&.{ 0x40, 0x00, 0x72, 0x00, 0x01 }));

    // ERR_COUNT is u64; a u32 payload must not be read as one.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const nest = try codec.nestBegin(gpa, &list, uapi.ATTR.HEALTH_REPORTER);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.HEALTH_REPORTER_ERR_COUNT, 1);
    codec.nestEnd(&list, nest);
    try testing.expectError(error.BadLength, parse(list.items));

    // An over-long reporter name.
    list.clearRetainingCapacity();
    const n2 = try codec.nestBegin(gpa, &list, uapi.ATTR.HEALTH_REPORTER);
    try codec.appendAttrString(gpa, &list, uapi.ATTR.HEALTH_REPORTER_NAME, "r" ** (uapi.name_max + 1));
    codec.nestEnd(&list, n2);
    try testing.expectError(error.BadLength, parse(list.items));
}

test "appendRecover and appendGet build the same handle + name shape" {
    const gpa = testing.allocator;
    var g: std.ArrayList(u8) = .empty;
    defer g.deinit(gpa);
    var r: std.ArrayList(u8) = .empty;
    defer r.deinit(gpa);
    try appendGet(gpa, &g, .pci("0000:00:00.0"), "fw");
    try appendRecover(gpa, &r, .pci("0000:00:00.0"), "fw");
    // The commands differ; the attributes do not.
    try testing.expectEqualSlices(u8, g.items, r.items);

    try testing.expectError(error.InvalidRequest, appendGet(gpa, &g, .pci("0000:00:00.0"), ""));
    try testing.expectError(error.InvalidRequest, appendRecover(gpa, &r, .pci("0000:00:00.0"), "a\x00b"));
}

test "appendPortGet puts the port index between the handle and the name" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendPortGet(gpa, &list, .{ .handle = .pci("0000:00:00.0"), .index = 2 }, "rx");
    var it: codec.AttrIterator = .{ .buf = list.items };
    try testing.expectEqual(uapi.ATTR.BUS_NAME, (try it.next()).?.type);
    try testing.expectEqual(uapi.ATTR.DEV_NAME, (try it.next()).?.type);
    try testing.expectEqual(uapi.ATTR.PORT_INDEX, (try it.next()).?.type);
    try testing.expectEqual(uapi.ATTR.HEALTH_REPORTER_NAME, (try it.next()).?.type);
}

test "fuzz: reporter decoding never crashes" {
    try testing.fuzz({}, fuzzHealth, .{});
}

fn fuzzHealth(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len = smith.valueRangeAtMost(u16, 0, buf.len);
    if (parse(buf[0..len])) |r| {
        _ = r.unrecoveredCount();
        _ = r.hasDump();
    } else |_| {}
}
