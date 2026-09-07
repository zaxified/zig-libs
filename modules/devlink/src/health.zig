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

// ── complete requests ──────────────────────────────────────────────────────

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
    try codec.appendAttrString(gpa, &list, uapi.ATTR.HEALTH_REPORTER_NAME, "r" ** (uapi.name_max + 1));
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

test "fuzz: reporter decoding never crashes" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzHealth, .{ .corpus = try corpus.build() });
}

fn fuzzHealth(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
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
    const len: usize = smith.slice(&buf);
    if (parse(buf[0..len])) |r| {
        _ = r.unrecoveredCount();
        _ = r.hasDump();
    } else |_| {}
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
