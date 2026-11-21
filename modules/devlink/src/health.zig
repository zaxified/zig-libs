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
const request = @import("request.zig");
const genl = @import("genetlink");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

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
    /// The window, in milliseconds, in which errors count as one burst (one recovery).
    burst_period: ?u64 = null,

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
        uapi.ATTR.HEALTH_REPORTER_STATE => r.state = @fromBackingInt(@intCast(try a.asU8())),
        uapi.ATTR.HEALTH_REPORTER_ERR_COUNT => r.err_count = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_RECOVER_COUNT => r.recover_count = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_DUMP_TS => r.dump_ts = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_DUMP_TS_NS => r.dump_ts_ns = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_GRACEFUL_PERIOD => r.graceful_period = try uapi.asU64(a),
        uapi.ATTR.HEALTH_REPORTER_AUTO_RECOVER => r.auto_recover = (try a.asU8()) != 0,
        uapi.ATTR.HEALTH_REPORTER_AUTO_DUMP => r.auto_dump = (try a.asU8()) != 0,
        uapi.ATTR.HEALTH_REPORTER_BURST_PERIOD => r.burst_period = try uapi.asU64(a),
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

// ── the reporter's message (diagnose, dump) ────────────────────────────────

/// A value in a reporter's message.
pub const FmsgValue = union(enum) {
    flag,
    u8: u8,
    u16: u16,
    u32: u32,
    u64: u64,
    /// A string (`NLA_STRING` / `NLA_NUL_STRING`), without the terminator; borrowed from the message.
    string: []const u8,
    /// Anything else (`NLA_BINARY`, a type this decoder does not know); borrowed.
    binary: []const u8,
};

/// One element of a reporter's message, in wire order.
pub const FmsgItem = union(enum) {
    /// `{`
    obj_start,
    /// A named pair opens: its `name` and `value` (or a nested object/array) follow, then `end`.
    pair_start,
    /// `[`
    arr_start,
    /// Closes the innermost open object, pair or array.
    end,
    name: []const u8,
    value: FmsgValue,
};

pub const FmsgError = codec.Error || error{
    /// More `end` items than starts, or the message ends inside an open nest.
    Unbalanced,
    /// Nesting deeper than `Fmsg.max_depth`.
    TooDeep,
};

/// A reporter's `diagnose` or `dump` answer: `DEVLINK_ATTR_FMSG`, a self-describing message — objects, arrays and
/// named pairs whose values carry a type tag — sent as one flat run of attributes (a nest-start flag, a nest-end
/// flag, a name, a type, a value) that may be split over several netlink messages. `bytes` is that run: the
/// payloads of every `FMSG` nest, concatenated in order.
pub const Fmsg = struct {
    /// Deepest nesting `iterator` follows.
    pub const max_depth = 64;

    bytes: []const u8,

    pub fn iterator(f: Fmsg) FmsgIterator {
        return .{ .it = .{ .buf = f.bytes } };
    }

    /// Walks the whole message once: the nesting balances and every value decodes.
    pub fn validate(f: Fmsg) FmsgError!void {
        var it = f.iterator();
        while (try it.next()) |_| {}
    }

    /// The value of the first pair named `pair_name`, at any depth; null when there is none or its value is a
    /// nest rather than a plain value.
    pub fn find(f: Fmsg, pair_name: []const u8) FmsgError!?FmsgValue {
        var it = f.iterator();
        var want = false;
        while (try it.next()) |item| switch (item) {
            .name => |n| want = std.mem.eql(u8, n, pair_name),
            .value => |v| {
                if (want) return v;
            },
            .pair_start, .obj_start, .arr_start, .end => want = false,
        };
        return null;
    }
};

pub const FmsgIterator = struct {
    it: codec.AttrIterator,
    depth: usize = 0,
    value_type: ?u8 = null,

    pub fn next(self: *FmsgIterator) FmsgError!?FmsgItem {
        while (try self.it.next()) |a| switch (a.type) {
            uapi.ATTR.FMSG_OBJ_NEST_START => return self.open(.obj_start),
            uapi.ATTR.FMSG_PAIR_NEST_START => return self.open(.pair_start),
            uapi.ATTR.FMSG_ARR_NEST_START => return self.open(.arr_start),
            uapi.ATTR.FMSG_NEST_END => {
                if (self.depth == 0) return error.Unbalanced;
                self.depth -= 1;
                return .end;
            },
            uapi.ATTR.FMSG_OBJ_NAME => return .{ .name = a.asString() },
            uapi.ATTR.FMSG_OBJ_VALUE_TYPE => self.value_type = try a.asU8(),
            uapi.ATTR.FMSG_OBJ_VALUE_DATA => {
                const t = self.value_type orelse 11;
                self.value_type = null;
                return .{ .value = switch (t) {
                    6 => .flag,
                    1 => .{ .u8 = try a.asU8() },
                    2 => .{ .u16 = try a.asU16() },
                    3 => .{ .u32 = try a.asU32() },
                    4 => .{ .u64 = try uapi.asU64(a) },
                    5, 10 => .{ .string = a.asString() },
                    else => .{ .binary = a.data },
                } };
            },
            else => {},
        };
        if (self.depth != 0) return error.Unbalanced;
        return null;
    }

    fn open(self: *FmsgIterator, item: FmsgItem) FmsgError!?FmsgItem {
        if (self.depth >= Fmsg.max_depth) return error.TooDeep;
        self.depth += 1;
        return item;
    }
};

/// Gathers a reporter's message from the replies of a `diagnose` or `dump`: `feed` each reply's attributes,
/// then `finish`.
pub const FmsgCollector = struct {
    list: std.ArrayList(u8) = .empty,

    pub fn deinit(c: *FmsgCollector, gpa: std.mem.Allocator) void {
        c.list.deinit(gpa);
    }

    /// Appends the payload of every `DEVLINK_ATTR_FMSG` nest among `attr_bytes`. `max_bytes` bounds what is kept
    /// (`error.BadLength` past it).
    pub fn feed(c: *FmsgCollector, gpa: std.mem.Allocator, attr_bytes: []const u8, max_bytes: usize) (codec.Error || error{OutOfMemory})!void {
        var it: codec.AttrIterator = .{ .buf = attr_bytes };
        while (try it.next()) |a| {
            if (a.type != uapi.ATTR.FMSG) continue;
            if (a.data.len > max_bytes -| c.list.items.len) return error.BadLength;
            try c.list.appendSlice(gpa, a.data);
        }
    }

    /// The message, owned by the caller (`gpa.free(f.bytes)`).
    pub fn finish(c: *FmsgCollector, gpa: std.mem.Allocator) error{OutOfMemory}!Fmsg {
        return .{ .bytes = try c.list.toOwnedSlice(gpa) };
    }
};

/// Largest reporter message `Devlink.healthDiagnose`/`healthDump` keep.
pub const max_fmsg_bytes = 4 << 20;

// ── request builders ───────────────────────────────────────────────────────

fn appendReporterName(gpa: std.mem.Allocator, list: *std.ArrayList(u8), n: []const u8) BuildError!void {
    if (n.len == 0 or n.len > uapi.name_max) return error.InvalidRequest;
    if (std.mem.findScalar(u8, n, 0) != null) return error.InvalidRequest;
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

/// What `HEALTH_REPORTER_SET` can change. At least one field.
pub const ReporterSet = struct {
    /// Minimum time between automatic recoveries, in milliseconds.
    graceful_period: ?u64 = null,
    auto_recover: ?bool = null,
    auto_dump: ?bool = null,
    /// The window in which errors count as one burst, in milliseconds.
    burst_period: ?u64 = null,
};

/// Attributes of a `DEVLINK_CMD_HEALTH_REPORTER_SET`. Needs **CAP_NET_ADMIN**. Refused when nothing is set.
pub fn appendSet(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    h: handle.Handle,
    reporter: []const u8,
    s: ReporterSet,
) BuildError!void {
    if (s.graceful_period == null and s.auto_recover == null and s.auto_dump == null and s.burst_period == null)
        return error.InvalidRequest;
    try handle.append(gpa, list, h);
    try appendReporterName(gpa, list, reporter);
    if (s.graceful_period) |v| try uapi.appendAttrU64(gpa, list, uapi.ATTR.HEALTH_REPORTER_GRACEFUL_PERIOD, v);
    if (s.auto_recover) |v| try codec.appendAttrU8(gpa, list, uapi.ATTR.HEALTH_REPORTER_AUTO_RECOVER, @intFromBool(v));
    if (s.auto_dump) |v| try codec.appendAttrU8(gpa, list, uapi.ATTR.HEALTH_REPORTER_AUTO_DUMP, @intFromBool(v));
    if (s.burst_period) |v| try uapi.appendAttrU64(gpa, list, uapi.ATTR.HEALTH_REPORTER_BURST_PERIOD, v);
}

// ── complete requests ──────────────────────────────────────────────────────

/// Build one of the commands that take a reporter name and nothing else: `DIAGNOSE`, `DUMP_GET` (a dump),
/// `DUMP_CLEAR`, `TEST`.
fn buildNamed(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    cmd: u8,
    dump: bool,
    h: handle.Handle,
    reporter: []const u8,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, cmd, dump);
    errdefer b.deinit();
    try appendGet(gpa, &b.list, h, reporter);
    return b.finish();
}

/// Build a `DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE` — what `Devlink.healthDiagnose` sends. Read-only on the driver
/// side, but needs **CAP_NET_ADMIN**.
pub fn buildDiagnoseHealthReporter(gpa: std.mem.Allocator, family_id: u16, seq: u32, h: handle.Handle, reporter: []const u8) request.Error![]u8 {
    return buildNamed(gpa, family_id, seq, uapi.CMD.HEALTH_REPORTER_DIAGNOSE, false, h, reporter);
}

/// Build a `DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET` (a dump, as the kernel registers it) — what `Devlink.healthDump`
/// sends: the dump the driver took when the reporter last tripped. Needs **CAP_NET_ADMIN**.
pub fn buildDumpHealthReporter(gpa: std.mem.Allocator, family_id: u16, seq: u32, h: handle.Handle, reporter: []const u8) request.Error![]u8 {
    return buildNamed(gpa, family_id, seq, uapi.CMD.HEALTH_REPORTER_DUMP_GET, true, h, reporter);
}

/// Build a `DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR` — what `Devlink.clearHealthDump` sends. Needs
/// **CAP_NET_ADMIN**.
pub fn buildClearHealthDump(gpa: std.mem.Allocator, family_id: u16, seq: u32, h: handle.Handle, reporter: []const u8) request.Error![]u8 {
    return buildNamed(gpa, family_id, seq, uapi.CMD.HEALTH_REPORTER_DUMP_CLEAR, false, h, reporter);
}

/// Build a `DEVLINK_CMD_HEALTH_REPORTER_TEST` — what `Devlink.testHealthReporter` sends: the driver raises a test
/// error on the reporter, which may run its recovery. Needs **CAP_NET_ADMIN**.
pub fn buildTestHealthReporter(gpa: std.mem.Allocator, family_id: u16, seq: u32, h: handle.Handle, reporter: []const u8) request.Error![]u8 {
    return buildNamed(gpa, family_id, seq, uapi.CMD.HEALTH_REPORTER_TEST, false, h, reporter);
}

/// Build a `DEVLINK_CMD_HEALTH_REPORTER_SET` — what `Devlink.setHealthReporter` sends. Needs **CAP_NET_ADMIN**.
pub fn buildSetHealthReporter(gpa: std.mem.Allocator, family_id: u16, seq: u32, h: handle.Handle, reporter: []const u8, s: ReporterSet) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.HEALTH_REPORTER_SET, false);
    errdefer b.deinit();
    try appendSet(gpa, &b.list, h, reporter, s);
    return b.finish();
}

/// Build a `DEVLINK_CMD_HEALTH_REPORTER_GET` **dump** — every reporter on the
/// system, which is what `Devlink.healthReporters` sends. The `filter` that
/// method takes is applied to the replies, not to this message.
pub fn buildHealthReporters(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
) request.Error![]u8 {
    return request.buildSimple(gpa, family_id, seq, uapi.CMD.HEALTH_REPORTER_GET, true, null);
}

/// Build a `DEVLINK_CMD_HEALTH_REPORTER_GET` for one named reporter — what
/// `Devlink.healthReporter` sends.
pub fn buildHealthReporter(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    reporter: []const u8,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.HEALTH_REPORTER_GET, false);
    errdefer b.deinit();
    try appendGet(gpa, &b.list, h, reporter);
    return b.finish();
}

/// Build a `DEVLINK_CMD_HEALTH_REPORTER_RECOVER` — what
/// `Devlink.recoverHealthReporter` sends. Needs **CAP_NET_ADMIN**, and
/// typically resets the device: this is not a health check.
pub fn buildRecoverHealthReporter(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    h: handle.Handle,
    reporter: []const u8,
) request.Error![]u8 {
    var b = try request.begin(gpa, family_id, seq, uapi.CMD.HEALTH_REPORTER_RECOVER, false);
    errdefer b.deinit();
    try appendRecover(gpa, &b.list, h, reporter);
    return b.finish();
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
    try codec.nestEnd(list, nest);
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
    try codec.nestEnd(&list, nest);
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
    try codec.nestEnd(&list, nest);
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
    try codec.nestEnd(&list, nest);
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
    try codec.nestEnd(&list, nest);
    try testing.expectError(error.BadLength, parse(list.items));

    // An over-long reporter name.
    list.clearRetainingCapacity();
    const n2 = try codec.nestBegin(gpa, &list, uapi.ATTR.HEALTH_REPORTER);
    try codec.appendAttrString(gpa, &list, uapi.ATTR.HEALTH_REPORTER_NAME, strRepeat("r", uapi.name_max + 1));
    try codec.nestEnd(&list, n2);
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

/// HEALTH_REPORTER_GET reply attribute lists for `fuzzHealth`, in the format `Smith.slice` reads (see
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

        // A healthy reporter with no faults.
        var healthy: std.ArrayList(u8) = .empty;
        try buildReporterReply(gpa, &healthy, .{ .name = "fw" });
        self.push(healthy.items);

        // One in error with an unrecovered fault and a dump waiting.
        var faulted: std.ArrayList(u8) = .empty;
        try buildReporterReply(gpa, &faulted, .{
            .name = "fw_fatal",
            .state = 1,
            .err_count = 7,
            .recover_count = 2,
            .dump_ts = 1690000000,
            .auto_recover = 0,
        });
        self.push(faulted.items);

        // ── the refusals and the degenerate shapes ─────────────────────────
        // The handle without the reporter nest the parser is looking for.
        var no_nest: std.ArrayList(u8) = .empty;
        try handle.append(gpa, &no_nest, .pci("0000:65:00.0"));
        self.push(no_nest.items);
        // An empty reporter nest.
        var empty_nest: std.ArrayList(u8) = .empty;
        try handle.append(gpa, &empty_nest, .pci("0000:65:00.0"));
        {
            const nest = try codec.nestBegin(gpa, &empty_nest, uapi.ATTR.HEALTH_REPORTER);
            try codec.nestEnd(&empty_nest, nest);
        }
        self.push(empty_nest.items);
        // An ERR_COUNT of four octets where a u64 belongs.
        var narrow: std.ArrayList(u8) = .empty;
        {
            const nest = try codec.nestBegin(gpa, &narrow, uapi.ATTR.HEALTH_REPORTER);
            try codec.appendAttrString(gpa, &narrow, uapi.ATTR.HEALTH_REPORTER_NAME, "fw");
            try codec.appendAttrU32(gpa, &narrow, uapi.ATTR.HEALTH_REPORTER_ERR_COUNT, 7);
            try codec.nestEnd(&narrow, nest);
        }
        self.push(narrow.items);
        // An attribute header declaring 0x40 octets over a 2-octet buffer.
        self.push(&[_]u8{ 0x40, 0x00 });

        return self.entries[0..self.n];
    }
};

const fz = @import("fuzz_test.zig");
const HealthMark = fz.Marker(enum { decoded, refused, named });

test "fuzz: reporter decoding never crashes" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzHealthSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: DEVLINK_FUZZ (health)" {
    try fz.fuzz_driver.run(fuzzHealth, .{ .prefix = "DEVLINK_FUZZ", .name = "devlink-health" });
}

test "fuzz harness: health, 500 seeds, reaches every outcome" {
    try HealthMark.reach(fuzzHealth, "devlink-health", 500);
}

fn fuzzHealthSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzHealth(std.testing.Smith, smith, testing.allocator);
}

fn fuzzHealth(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
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
    // above: **0 of 6 seeds non-empty, 6 of 6 "decoded" and 0 of them carrying
    // a reporter name before; 6 of 6 non-empty, 4 decoded and 2 named after.**
    // An empty attribute list is a legal devlink reply — every field is
    // optional — so `parse("")` succeeds, and the collapsed harness scored a
    // perfect 6 of 6 while never entering the reporter nest.
    const len: usize = fz.drawInput(S, src, &buf, entries);
    if (parse(buf[0..len])) |r| {
        _ = r.unrecoveredCount();
        _ = r.hasDump();
        HealthMark.mark(.decoded);
        if (r.name().len != 0) HealthMark.mark(.named);
    } else |_| HealthMark.mark(.refused);
}

test "corpus: every reporter seed reaches the parser, and the decoded count is pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over
    // the SAME corpus the harness gets. `nonempty` is the reach claim and the
    // only check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. The parse counts
    // are pinned rather than asserted `> 0`: a corpus of nothing but refusals
    // would score full marks on reach while exercising only the error path.
    //
    // `named` is the second number, and it is the one that matters here:
    // `parse` answers with an all-absent `Reporter` for a reply that carries
    // no reporter nest at all, so "decoded" alone would count a corpus that
    // never reached the nest walk as a full success.
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var decoded: usize = 0;
    var named: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (parse(buf[0..len])) |r| {
            decoded += 1;
            if (r.name().len != 0) named += 1;
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 4), decoded);
    try testing.expectEqual(@as(usize, 2), named);
}

test "the health builders: dump vs one reporter, GET vs RECOVER" {
    const gpa = testing.allocator;
    const h: handle.Handle = .pci("0000:65:00.0");

    const dump = try buildHealthReporters(gpa, 0x19, 11);
    defer gpa.free(dump);
    var it: codec.MessageIterator = .{ .buf = dump };
    var m = (try it.next()).?;
    try testing.expect(m.flags & codec.NLM_F_DUMP != 0);
    var p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.HEALTH_REPORTER_GET, p.cmd);
    try testing.expectEqual(@as(usize, 0), p.attrs.len);

    const one = try buildHealthReporter(gpa, 0x19, 11, h, "fw_fatal");
    defer gpa.free(one);
    it = .{ .buf = one };
    m = (try it.next()).?;
    try testing.expectEqual(@as(u16, codec.NLM_F_REQUEST | codec.NLM_F_ACK), m.flags);
    try testing.expectEqual(@as(u32, 11), m.seq);
    p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.HEALTH_REPORTER_GET, p.cmd);
    try testing.expectEqual(uapi.family_version, m.payload[1]);

    // Same attributes, different command — the difference between asking how a
    // reporter is and resetting the device.
    const recover = try buildRecoverHealthReporter(gpa, 0x19, 11, h, "fw_fatal");
    defer gpa.free(recover);
    it = .{ .buf = recover };
    m = (try it.next()).?;
    p = try genl.splitPayload(m.payload);
    try testing.expectEqual(uapi.CMD.HEALTH_REPORTER_RECOVER, p.cmd);
    try testing.expectEqual(one.len, recover.len);
    try testing.expectEqualSlices(u8, one[20..], recover[20..]);
    // The reporter name is the top-level attribute, not a nest, on the way out.
    var attrs: codec.AttrIterator = .{ .buf = p.attrs };
    var named = false;
    while (try attrs.next()) |a| {
        if (a.type == uapi.ATTR.HEALTH_REPORTER_NAME) {
            try testing.expectEqualStrings("fw_fatal", a.asString());
            named = true;
        }
        try testing.expect(a.type != uapi.ATTR.HEALTH_REPORTER);
    }
    try testing.expect(named);

    try testing.expectError(error.InvalidRequest, buildHealthReporter(gpa, 0x19, 1, h, ""));
    try testing.expectError(error.InvalidRequest, buildRecoverHealthReporter(gpa, 0x19, 1, h, "a\x00b"));
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

fn flagAttr(gpa: std.mem.Allocator, list: *std.ArrayList(u8), t: u16) !void {
    try codec.appendAttr(gpa, list, t, &.{});
}

fn valueAttrs(gpa: std.mem.Allocator, list: *std.ArrayList(u8), type_tag: u8, data: []const u8) !void {
    try codec.appendAttrU8(gpa, list, uapi.ATTR.FMSG_OBJ_VALUE_TYPE, type_tag);
    try codec.appendAttr(gpa, list, uapi.ATTR.FMSG_OBJ_VALUE_DATA, data);
}

/// One pair `name: u32 value`.
fn u32Pair(gpa: std.mem.Allocator, list: *std.ArrayList(u8), name: []const u8, v: u32) !void {
    try flagAttr(gpa, list, uapi.ATTR.FMSG_PAIR_NEST_START);
    try codec.appendAttrString(gpa, list, uapi.ATTR.FMSG_OBJ_NAME, name);
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, @import("builtin").cpu.arch.endian());
    try valueAttrs(gpa, list, 3, &b);
    try flagAttr(gpa, list, uapi.ATTR.FMSG_NEST_END);
}

test "Fmsg decodes objects, pairs, arrays and every value type, across two messages" {
    const gpa = testing.allocator;
    const endian = @import("builtin").cpu.arch.endian();

    // First message: the start of the object and its first pair.
    var m1: std.ArrayList(u8) = .empty;
    defer m1.deinit(gpa);
    try handle.append(gpa, &m1, .pci("0000:65:00.0"));
    {
        const nest = try codec.nestBegin(gpa, &m1, uapi.ATTR.FMSG);
        try flagAttr(gpa, &m1, uapi.ATTR.FMSG_OBJ_NEST_START);
        try u32Pair(gpa, &m1, "events", 7);
        try codec.nestEnd(&m1, nest);
    }
    // Second message: a string, a flag, an array of u64, a nested object, and the closing of the object.
    var m2: std.ArrayList(u8) = .empty;
    defer m2.deinit(gpa);
    try handle.append(gpa, &m2, .pci("0000:65:00.0"));
    {
        const nest = try codec.nestBegin(gpa, &m2, uapi.ATTR.FMSG);
        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_PAIR_NEST_START);
        try codec.appendAttrString(gpa, &m2, uapi.ATTR.FMSG_OBJ_NAME, "state");
        try valueAttrs(gpa, &m2, 10, "healthy\x00");
        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_NEST_END);

        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_PAIR_NEST_START);
        try codec.appendAttrString(gpa, &m2, uapi.ATTR.FMSG_OBJ_NAME, "armed");
        try valueAttrs(gpa, &m2, 6, &.{});
        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_NEST_END);

        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_PAIR_NEST_START);
        try codec.appendAttrString(gpa, &m2, uapi.ATTR.FMSG_OBJ_NAME, "counters");
        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_ARR_NEST_START);
        var q: [8]u8 = undefined;
        std.mem.writeInt(u64, &q, 5, endian);
        try valueAttrs(gpa, &m2, 4, &q);
        std.mem.writeInt(u64, &q, 1 << 40, endian);
        try valueAttrs(gpa, &m2, 4, &q);
        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_NEST_END);
        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_NEST_END);

        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_PAIR_NEST_START);
        try codec.appendAttrString(gpa, &m2, uapi.ATTR.FMSG_OBJ_NAME, "blob");
        try valueAttrs(gpa, &m2, 11, &.{ 0xde, 0xad });
        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_NEST_END);
        try valueAttrs(gpa, &m2, 1, &.{9}); // an array element outside a pair, as the kernel writes them
        try valueAttrs(gpa, &m2, 2, &.{ 1, 0 });
        try flagAttr(gpa, &m2, uapi.ATTR.FMSG_NEST_END); // closes the object
        try codec.nestEnd(&m2, nest);
    }

    var c: FmsgCollector = .{};
    defer c.deinit(gpa);
    try c.feed(gpa, m1.items, max_fmsg_bytes);
    try c.feed(gpa, m2.items, max_fmsg_bytes);
    const f = try c.finish(gpa);
    defer gpa.free(f.bytes);
    try f.validate();

    var it = f.iterator();
    try testing.expectEqual(FmsgItem.obj_start, (try it.next()).?);
    try testing.expectEqual(FmsgItem.pair_start, (try it.next()).?);
    try testing.expectEqualStrings("events", (try it.next()).?.name);
    try testing.expectEqual(@as(u32, 7), (try it.next()).?.value.u32);
    try testing.expectEqual(FmsgItem.end, (try it.next()).?);

    try testing.expectEqual(@as(u32, 7), (try f.find("events")).?.u32);
    try testing.expectEqualStrings("healthy", (try f.find("state")).?.string);
    try testing.expect((try f.find("armed")).? == .flag);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, (try f.find("blob")).?.binary);
    try testing.expect((try f.find("nothing")) == null);
    // `counters` holds an array, not a plain value: `find` does not guess.
    try testing.expect((try f.find("counters")) == null);

    // Depth: the walk of the whole message ends at depth zero, a lone end or an unclosed start does not.
    var items: usize = 0;
    var walk = f.iterator();
    while (try walk.next()) |_| items += 1;
    try testing.expectEqual(@as(usize, 27), items);
}

test "Fmsg refuses an unbalanced or too deep message and a nest of the wrong width" {
    const gpa = testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try flagAttr(gpa, &l, uapi.ATTR.FMSG_NEST_END);
    try testing.expectError(error.Unbalanced, (Fmsg{ .bytes = l.items }).validate());

    var open: std.ArrayList(u8) = .empty;
    defer open.deinit(gpa);
    try flagAttr(gpa, &open, uapi.ATTR.FMSG_OBJ_NEST_START);
    try testing.expectError(error.Unbalanced, (Fmsg{ .bytes = open.items }).validate());

    var deep: std.ArrayList(u8) = .empty;
    defer deep.deinit(gpa);
    for (0..Fmsg.max_depth + 1) |_| try flagAttr(gpa, &deep, uapi.ATTR.FMSG_ARR_NEST_START);
    try testing.expectError(error.TooDeep, (Fmsg{ .bytes = deep.items }).validate());

    var wide: std.ArrayList(u8) = .empty;
    defer wide.deinit(gpa);
    try valueAttrs(gpa, &wide, 3, &.{ 1, 2 }); // a u32 with two bytes
    try testing.expectError(error.BadLength, (Fmsg{ .bytes = wide.items }).validate());

    // A value without a type tag is kept as bytes, not guessed at.
    var untyped: std.ArrayList(u8) = .empty;
    defer untyped.deinit(gpa);
    try codec.appendAttr(gpa, &untyped, uapi.ATTR.FMSG_OBJ_VALUE_DATA, &.{ 1, 2, 3 });
    var it = (Fmsg{ .bytes = untyped.items }).iterator();
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, (try it.next()).?.value.binary);

    // The collector's bound.
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    const nest = try codec.nestBegin(gpa, &m, uapi.ATTR.FMSG);
    try u32Pair(gpa, &m, "x", 1);
    try codec.nestEnd(&m, nest);
    var c: FmsgCollector = .{};
    defer c.deinit(gpa);
    try testing.expectError(error.BadLength, c.feed(gpa, m.items, 8));
}

test "diagnose, dump, clear, test and set requests" {
    if (@import("builtin").cpu.arch.endian() != .little) return error.SkipZigTest;
    const gpa = testing.allocator;
    const h: handle.Handle = .pci("0000:65:00.0");

    const cases = [_]struct { build: *const fn (std.mem.Allocator, u16, u32, handle.Handle, []const u8) request.Error![]u8, cmd: u8, dump: bool }{
        .{ .build = buildDiagnoseHealthReporter, .cmd = uapi.CMD.HEALTH_REPORTER_DIAGNOSE, .dump = false },
        .{ .build = buildDumpHealthReporter, .cmd = uapi.CMD.HEALTH_REPORTER_DUMP_GET, .dump = true },
        .{ .build = buildClearHealthDump, .cmd = uapi.CMD.HEALTH_REPORTER_DUMP_CLEAR, .dump = false },
        .{ .build = buildTestHealthReporter, .cmd = uapi.CMD.HEALTH_REPORTER_TEST, .dump = false },
    };
    for (cases) |c| {
        const msg = try c.build(gpa, 0x19, 2, h, "fw");
        defer gpa.free(msg);
        const flags = std.mem.readInt(u16, msg[6..8], .little);
        try testing.expectEqual(c.dump, flags & codec.NLM_F_DUMP != 0);
        const pl = try genl.splitPayload(msg[16..]);
        try testing.expectEqual(c.cmd, pl.cmd);
        const r = try parse(pl.attrs);
        try testing.expectEqualStrings("0000:65:00.0", r.handle.dev());
        // The name is a top-level attribute, as in `recover`, not a nest.
        var it: codec.AttrIterator = .{ .buf = pl.attrs };
        var named = false;
        while (try it.next()) |a| {
            if (a.type == uapi.ATTR.HEALTH_REPORTER_NAME) {
                named = true;
                try testing.expectEqualStrings("fw", a.asString());
            }
        }
        try testing.expect(named);
        try testing.expectError(error.InvalidRequest, c.build(gpa, 0x19, 2, h, ""));
    }

    const set = try buildSetHealthReporter(gpa, 0x19, 3, h, "fw", .{ .graceful_period = 1500, .auto_recover = true, .auto_dump = false, .burst_period = 600 });
    defer gpa.free(set);
    const sp = try genl.splitPayload(set[16..]);
    try testing.expectEqual(uapi.CMD.HEALTH_REPORTER_SET, sp.cmd);
    var it: codec.AttrIterator = .{ .buf = sp.attrs };
    var seen: u8 = 0;
    while (try it.next()) |a| switch (a.type) {
        uapi.ATTR.HEALTH_REPORTER_GRACEFUL_PERIOD => {
            seen |= 1;
            try testing.expectEqual(@as(u64, 1500), try uapi.asU64(a));
        },
        uapi.ATTR.HEALTH_REPORTER_AUTO_RECOVER => {
            seen |= 2;
            try testing.expectEqual(@as(u8, 1), try a.asU8());
        },
        uapi.ATTR.HEALTH_REPORTER_AUTO_DUMP => {
            seen |= 4;
            try testing.expectEqual(@as(u8, 0), try a.asU8());
        },
        uapi.ATTR.HEALTH_REPORTER_BURST_PERIOD => {
            seen |= 8;
            try testing.expectEqual(@as(u64, 600), try uapi.asU64(a));
        },
        else => {},
    };
    try testing.expectEqual(@as(u8, 15), seen);
    try testing.expectError(error.InvalidRequest, buildSetHealthReporter(gpa, 0x19, 3, h, "fw", .{}));
}
