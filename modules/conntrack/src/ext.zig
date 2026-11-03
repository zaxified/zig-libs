// SPDX-License-Identifier: MIT
//! ctnetlink wire extensions (survey 2026-11-02): the pure, I/O-free half of
//! everything beyond "dump, get, insert, delete, flush, events" — the dump
//! variants (zero-counters, dying, unconfirmed), the server-side dump filter
//! with its client-side twin, the statistics messages and the expectation
//! subsystem's dump. Nothing here opens a socket; `root.zig` drives it.
//!
//! Provenance: clean-room from the kernel UAPI headers
//! (`nfnetlink_conntrack.h`) and the MIT-licensed `ti-mo/conntrack` v0.6.0
//! README / godoc for what a user expects to find. No libnetfilter_conntrack or
//! conntrack-tools source was read.

const std = @import("std");
const builtin = @import("builtin");
const netlink = @import("netlink");
const codec = netlink.codec;
const wire = @import("wire.zig");
const Family = wire.Family;
const Flow = wire.Flow;
const Tuple = wire.Tuple;
const DecodeError = wire.DecodeError;
const CTA = wire.CTA;

// ── message types ───────────────────────────────────────────────────────────

/// NFNL_SUBSYS_CTNETLINK_EXP — the expectation subsystem id.
pub const NFNL_SUBSYS_CTNETLINK_EXP: u16 = 2;
pub const IPCTNL_MSG_EXP_NEW: u8 = 0;
pub const IPCTNL_MSG_EXP_GET: u8 = 1;
pub const IPCTNL_MSG_EXP_DELETE: u8 = 2;
pub const IPCTNL_MSG_EXP_GET_STATS_CPU: u8 = 3;

pub const msg_ct_get_ctrzero = wire.msgType(wire.NFNL_SUBSYS_CTNETLINK, wire.IPCTNL_MSG_CT_GET_CTRZERO);
pub const msg_ct_get_stats_cpu = wire.msgType(wire.NFNL_SUBSYS_CTNETLINK, wire.IPCTNL_MSG_CT_GET_STATS_CPU);
pub const msg_ct_get_stats = wire.msgType(wire.NFNL_SUBSYS_CTNETLINK, wire.IPCTNL_MSG_CT_GET_STATS);
pub const msg_ct_get_dying = wire.msgType(wire.NFNL_SUBSYS_CTNETLINK, wire.IPCTNL_MSG_CT_GET_DYING);
pub const msg_ct_get_unconfirmed = wire.msgType(wire.NFNL_SUBSYS_CTNETLINK, wire.IPCTNL_MSG_CT_GET_UNCONFIRMED);
pub const msg_exp_new = wire.msgType(NFNL_SUBSYS_CTNETLINK_EXP, IPCTNL_MSG_EXP_NEW);
pub const msg_exp_get = wire.msgType(NFNL_SUBSYS_CTNETLINK_EXP, IPCTNL_MSG_EXP_GET);
pub const msg_exp_get_stats_cpu = wire.msgType(NFNL_SUBSYS_CTNETLINK_EXP, IPCTNL_MSG_EXP_GET_STATS_CPU);

/// `enum ctattr_expect` — attributes of an expectation.
pub const CTA_EXPECT = struct {
    pub const MASTER: u16 = 1;
    pub const TUPLE: u16 = 2;
    pub const MASK: u16 = 3;
    pub const TIMEOUT: u16 = 4;
    pub const ID: u16 = 5;
    pub const HELP_NAME: u16 = 6;
    pub const ZONE: u16 = 7;
    pub const FLAGS: u16 = 8;
    pub const CLASS: u16 = 9;
    pub const NAT: u16 = 10;
    pub const FN: u16 = 11;
};

/// `enum ctattr_stats_cpu` — attributes of one CPU's counters.
pub const CTA_STATS = struct {
    pub const SEARCHED: u16 = 1;
    pub const FOUND: u16 = 2;
    pub const NEW: u16 = 3;
    pub const INVALID: u16 = 4;
    pub const IGNORE: u16 = 5;
    pub const DELETE: u16 = 6;
    pub const DELETE_LIST: u16 = 7;
    pub const INSERT: u16 = 8;
    pub const INSERT_FAILED: u16 = 9;
    pub const DROP: u16 = 10;
    pub const EARLY_DROP: u16 = 11;
    pub const ERROR: u16 = 12;
    pub const SEARCH_RESTART: u16 = 13;
    pub const CLASH_RESOLVE: u16 = 14;
    pub const CHAIN_TOOLONG: u16 = 15;
};

/// `enum ctattr_stats_global`.
pub const CTA_STATS_GLOBAL = struct {
    pub const ENTRIES: u16 = 1;
    pub const MAX_ENTRIES: u16 = 2;
};

// ── dump variants and the dump filter ───────────────────────────────────────

/// Which kernel list a flow dump walks.
pub const DumpKind = enum {
    /// The hash table: what `conntrack -L` prints.
    table,
    /// The table, and every flow's counters are zeroed after being read
    /// (`IPCTNL_MSG_CT_GET_CTRZERO`, `conntrack -L -z`). A write in disguise:
    /// the counters it returns are the last ones anyone will see.
    zero_counters,
    /// Flows that are dying and waiting for their last reference
    /// (`IPCTNL_MSG_CT_GET_DYING`, `conntrack -L dying`).
    dying,
    /// Flows not yet confirmed into the table
    /// (`IPCTNL_MSG_CT_GET_UNCONFIRMED`, `conntrack -L unconfirmed`).
    unconfirmed,
};

/// A connmark filter: an entry matches when `(flow.mark & mask) == value`
/// (a missing mark reads as 0, like the kernel's).
pub const MarkFilter = struct {
    value: u32,
    mask: u32 = 0xffff_ffff,
};

/// A status filter: an entry matches when `(flow.status & mask) == value`.
/// With `mask == null` the mask is `value` itself, i.e. "all of these bits
/// are set" — the kernel's rule when only `CTA_STATUS` is sent.
pub const StatusFilter = struct {
    value: u32,
    mask: ?u32 = null,
};

/// What to keep of a dump. Sent to the kernel as `CTA_MARK`/`CTA_MARK_MASK`,
/// `CTA_STATUS`/`CTA_STATUS_MASK` and `CTA_ZONE` (the dump family goes in the
/// `nfgenmsg` as for an unfiltered dump), **and applied again on the client**
/// (`matches`). The second pass is not redundancy for its own sake: a kernel
/// that predates an attribute (mark filter 4.20, status 5.15, zone 6.8) does
/// not reject it, it answers an *unfiltered* dump, and a caller who asked for
/// one mark must never be handed all of them. On a new kernel the client
/// pass drops nothing.
pub const DumpFilter = struct {
    mark: ?MarkFilter = null,
    status: ?StatusFilter = null,
    /// Only flows of this conntrack zone; a flow without `CTA_ZONE` is zone 0.
    zone: ?u16 = null,

    pub fn matches(f: DumpFilter, flow: *const Flow) bool {
        if (f.mark) |m| {
            if (((flow.mark orelse 0) & m.mask) != m.value) return false;
        }
        if (f.status) |s| {
            const mask = s.mask orelse s.value;
            if (((flow.status orelse 0) & mask) != s.value) return false;
        }
        if (f.zone) |z| {
            if ((flow.zone orelse 0) != z) return false;
        }
        return true;
    }
};

/// What a flow dump asks for. `family` scopes it kernel-side.
pub const FlowQuery = struct {
    family: Family = .unspec,
    kind: DumpKind = .table,
    filter: ?DumpFilter = null,
};

/// Largest flow-dump request: header, `nfgenmsg`, mark + mask, status + mask,
/// zone (each attribute padded to 8 bytes).
pub const flow_dump_max_len = codec.header_len + wire.nfgenmsg_len + 5 * 8;

/// A flow-dump request built in place: no allocation, so the dump engines
/// stay allocation-free on the request side.
pub const FlowDumpRequest = struct {
    buf: [flow_dump_max_len]u8 = undefined,
    len: usize = 0,

    pub fn bytes(r: *const FlowDumpRequest) []const u8 {
        return r.buf[0..r.len];
    }
};

fn putAttr(r: *FlowDumpRequest, ty: u16, payload: []const u8) void {
    const native = builtin.cpu.arch.endian();
    std.mem.writeInt(u16, r.buf[r.len..][0..2], @intCast(4 + payload.len), native);
    std.mem.writeInt(u16, r.buf[r.len + 2 ..][0..2], ty, native);
    @memcpy(r.buf[r.len + 4 ..][0..payload.len], payload);
    // Padding is already zero: `buildFlowDump` clears the whole buffer.
    r.len += 4 + (payload.len + 3) / 4 * 4;
}

fn putBe32(r: *FlowDumpRequest, ty: u16, v: u32) void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    putAttr(r, ty, &b);
}

/// The complete request of a flow dump (`NLM_F_REQUEST | NLM_F_DUMP`). An
/// unfiltered `.table` query is byte-identical to `wire.buildDumpRequest`.
pub fn buildFlowDump(seq: u32, q: FlowQuery) FlowDumpRequest {
    const native = builtin.cpu.arch.endian();
    var r: FlowDumpRequest = .{};
    @memset(&r.buf, 0);
    const ty: u16 = switch (q.kind) {
        .table => wire.msg_ct_get,
        .zero_counters => msg_ct_get_ctrzero,
        .dying => msg_ct_get_dying,
        .unconfirmed => msg_ct_get_unconfirmed,
    };
    std.mem.writeInt(u16, r.buf[4..6], ty, native);
    std.mem.writeInt(u16, r.buf[6..8], codec.NLM_F_REQUEST | codec.NLM_F_DUMP, native);
    std.mem.writeInt(u32, r.buf[8..12], seq, native);
    r.buf[codec.header_len] = @backingInt(q.family);
    r.buf[codec.header_len + 1] = wire.NFNETLINK_V0;
    r.len = codec.header_len + wire.nfgenmsg_len;
    if (q.filter) |f| {
        if (f.mark) |m| {
            putBe32(&r, CTA.MARK, m.value);
            putBe32(&r, CTA.MARK_MASK, m.mask);
        }
        if (f.status) |s| {
            putBe32(&r, CTA.STATUS, s.value);
            if (s.mask) |m| putBe32(&r, CTA.STATUS_MASK, m);
        }
        if (f.zone) |z| {
            var b: [2]u8 = undefined;
            std.mem.writeInt(u16, &b, z, .big);
            putAttr(&r, CTA.ZONE, &b);
        }
    }
    std.mem.writeInt(u32, r.buf[0..4], @intCast(r.len), native);
    return r;
}

// ── statistics ──────────────────────────────────────────────────────────────

/// One CPU's conntrack counters (`conntrack -S`). Counters a kernel does not
/// report stay 0.
pub const CpuStats = struct {
    cpu: u16 = 0,
    searched: u32 = 0,
    found: u32 = 0,
    new: u32 = 0,
    invalid: u32 = 0,
    ignore: u32 = 0,
    delete: u32 = 0,
    delete_list: u32 = 0,
    insert: u32 = 0,
    insert_failed: u32 = 0,
    drop: u32 = 0,
    early_drop: u32 = 0,
    errors: u32 = 0,
    search_restart: u32 = 0,
    clash_resolve: u32 = 0,
    chain_toolong: u32 = 0,
};

/// The table's occupancy (`conntrack -C`, `nf_conntrack_count`/`_max`).
pub const GlobalStats = struct {
    entries: u32 = 0,
    max_entries: u32 = 0,
};

/// One expectation-subsystem CPU counter record (`conntrack -S expect`).
pub const ExpectStats = struct {
    cpu: u16 = 0,
    new: u32 = 0,
    create: u32 = 0,
    delete: u32 = 0,
};

/// Decode one `IPCTNL_MSG_CT_GET_STATS_CPU` message payload. The CPU number is
/// the `nfgenmsg` `res_id` (big-endian).
pub fn decodeCpuStats(payload: []const u8) DecodeError!CpuStats {
    const hdr = try wire.parseNfgenmsg(payload);
    var out: CpuStats = .{ .cpu = hdr.res_id };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        CTA_STATS.SEARCHED => out.searched = try a.asBe32(),
        CTA_STATS.FOUND => out.found = try a.asBe32(),
        CTA_STATS.NEW => out.new = try a.asBe32(),
        CTA_STATS.INVALID => out.invalid = try a.asBe32(),
        CTA_STATS.IGNORE => out.ignore = try a.asBe32(),
        CTA_STATS.DELETE => out.delete = try a.asBe32(),
        CTA_STATS.DELETE_LIST => out.delete_list = try a.asBe32(),
        CTA_STATS.INSERT => out.insert = try a.asBe32(),
        CTA_STATS.INSERT_FAILED => out.insert_failed = try a.asBe32(),
        CTA_STATS.DROP => out.drop = try a.asBe32(),
        CTA_STATS.EARLY_DROP => out.early_drop = try a.asBe32(),
        CTA_STATS.ERROR => out.errors = try a.asBe32(),
        CTA_STATS.SEARCH_RESTART => out.search_restart = try a.asBe32(),
        CTA_STATS.CLASH_RESOLVE => out.clash_resolve = try a.asBe32(),
        CTA_STATS.CHAIN_TOOLONG => out.chain_toolong = try a.asBe32(),
        else => {},
    };
    return out;
}

/// Decode the single `IPCTNL_MSG_CT_GET_STATS` answer.
pub fn decodeGlobalStats(payload: []const u8) DecodeError!GlobalStats {
    const hdr = try wire.parseNfgenmsg(payload);
    var out: GlobalStats = .{};
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        CTA_STATS_GLOBAL.ENTRIES => out.entries = try a.asBe32(),
        CTA_STATS_GLOBAL.MAX_ENTRIES => out.max_entries = try a.asBe32(),
        else => {},
    };
    return out;
}

/// Decode one expectation-subsystem CPU counter message (`new`, `create`,
/// `delete`; attribute numbers 1..3).
pub fn decodeExpectStats(payload: []const u8) DecodeError!ExpectStats {
    const hdr = try wire.parseNfgenmsg(payload);
    var out: ExpectStats = .{ .cpu = hdr.res_id };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        1 => out.new = try a.asBe32(),
        2 => out.create = try a.asBe32(),
        3 => out.delete = try a.asBe32(),
        else => {},
    };
    return out;
}

/// `IPCTNL_MSG_CT_GET_STATS_CPU` (a dump: one message per CPU).
pub fn buildStatsCpuDump(seq: u32) [codec.header_len + wire.nfgenmsg_len]u8 {
    return bareRequest(msg_ct_get_stats_cpu, codec.NLM_F_REQUEST | codec.NLM_F_DUMP, seq);
}

/// `IPCTNL_MSG_CT_GET_STATS` (not a dump: one message).
pub fn buildStatsGlobal(seq: u32) [codec.header_len + wire.nfgenmsg_len]u8 {
    return bareRequest(msg_ct_get_stats, codec.NLM_F_REQUEST, seq);
}

/// `IPCTNL_MSG_EXP_GET_STATS_CPU` (a dump).
pub fn buildExpectStatsDump(seq: u32) [codec.header_len + wire.nfgenmsg_len]u8 {
    return bareRequest(msg_exp_get_stats_cpu, codec.NLM_F_REQUEST | codec.NLM_F_DUMP, seq);
}

fn bareRequest(ty: u16, flags: u16, seq: u32) [codec.header_len + wire.nfgenmsg_len]u8 {
    const native = builtin.cpu.arch.endian();
    var req: [codec.header_len + wire.nfgenmsg_len]u8 = @splat(0);
    std.mem.writeInt(u32, req[0..4], req.len, native);
    std.mem.writeInt(u16, req[4..6], ty, native);
    std.mem.writeInt(u16, req[6..8], flags, native);
    std.mem.writeInt(u32, req[8..12], seq, native);
    // nfgen_family AF_UNSPEC, version 0, res_id 0.
    return req;
}

// ── expectations ────────────────────────────────────────────────────────────

pub const Name = wire.Name;

/// One expectation — a related connection the kernel is waiting for (FTP data
/// channel, SIP media): `conntrack -L expect`.
pub const Expect = struct {
    family: Family = .unspec,
    /// The flow that created it.
    master: Tuple = .{},
    /// The connection being waited for.
    tuple: Tuple = .{},
    /// Which bits of `tuple` must match.
    mask: Tuple = .{},
    /// Seconds until it expires.
    timeout: ?u32 = null,
    id: ?u32 = null,
    helper: ?Name = null,
    zone: ?u16 = null,
    flags: ?u32 = null,
    class: ?u32 = null,
    fn_name: ?Name = null,
};

/// Decode one `IPCTNL_MSG_EXP_NEW` message payload (dump record or event).
/// Unknown attributes are skipped, malformed lengths rejected, as for flows.
pub fn decodeExpect(payload: []const u8) DecodeError!Expect {
    const hdr = try wire.parseNfgenmsg(payload);
    var out: Expect = .{ .family = @fromBackingInt(@intCast(hdr.family)) };
    var it = hdr.attrIterator();
    while (try it.next()) |a| switch (a.type) {
        CTA_EXPECT.MASTER => out.master = try wire.decodeTuple(a.data),
        CTA_EXPECT.TUPLE => out.tuple = try wire.decodeTuple(a.data),
        CTA_EXPECT.MASK => out.mask = try wire.decodeTuple(a.data),
        CTA_EXPECT.TIMEOUT => out.timeout = try a.asBe32(),
        CTA_EXPECT.ID => out.id = try a.asBe32(),
        CTA_EXPECT.HELP_NAME => out.helper = try Name.fromAttr(a.data),
        CTA_EXPECT.ZONE => out.zone = try a.asBe16(),
        CTA_EXPECT.FLAGS => out.flags = try a.asBe32(),
        CTA_EXPECT.CLASS => out.class = try a.asBe32(),
        CTA_EXPECT.FN => out.fn_name = try Name.fromAttr(a.data),
        else => {},
    };
    return out;
}

/// `IPCTNL_MSG_EXP_GET` + `NLM_F_DUMP`. Caller-controlled content is the
/// family only.
pub fn buildExpectDump(seq: u32, family: Family) [codec.header_len + wire.nfgenmsg_len]u8 {
    var req = bareRequest(msg_exp_get, codec.NLM_F_REQUEST | codec.NLM_F_DUMP, seq);
    req[codec.header_len] = @backingInt(family);
    return req;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A message of `ty` with an `nfgenmsg` (`family`, `res_id`) and `attrs`,
/// framed in the host's byte order like a kernel reply.
fn testMessage(gpa: std.mem.Allocator, list: *std.ArrayList(u8), ty: u16, family: Family, res_id: u16, attrs: []const u8) !void {
    const hdr = try codec.appendHeader(gpa, list, ty, 0, 1, 0);
    try wire.appendNfgenmsg(gpa, list, family, res_id);
    try list.appendSlice(gpa, attrs);
    codec.finishHeader(list, hdr);
}

fn firstPayload(buf: []const u8) !codec.Message {
    var it: codec.MessageIterator = .{ .buf = buf };
    return (try it.next()).?;
}

test "buildFlowDump: an unfiltered table dump is byte-identical to buildDumpRequest" {
    inline for (.{ Family.unspec, Family.ipv4, Family.ipv6 }) |fam| {
        const got = buildFlowDump(77, .{ .family = fam });
        const want = wire.buildDumpRequest(77, fam);
        try testing.expectEqualSlices(u8, &want, got.bytes());
    }
}

test "buildFlowDump: kinds select the message type, and every one is a dump" {
    const cases = [_]struct { k: DumpKind, ty: u16 }{
        .{ .k = .table, .ty = 0x0101 },
        .{ .k = .zero_counters, .ty = 0x0103 },
        .{ .k = .dying, .ty = 0x0106 },
        .{ .k = .unconfirmed, .ty = 0x0107 },
    };
    for (cases) |c| {
        const got = buildFlowDump(5, .{ .kind = c.k });
        const m = try firstPayload(got.bytes());
        try testing.expectEqual(c.ty, m.type);
        try testing.expect(m.flags & codec.NLM_F_DUMP == codec.NLM_F_DUMP);
        try testing.expectEqual(@as(u32, 5), m.seq);
    }
}

test "buildFlowDump: the filter attributes are big-endian, mask omitted only for status" {
    const got = buildFlowDump(9, .{
        .family = .ipv4,
        .filter = .{
            .mark = .{ .value = 0x0102_0304, .mask = 0xff00_ff00 },
            .status = .{ .value = IPS_ASSURED },
            .zone = 0x0506,
        },
    });
    const m = try firstPayload(got.bytes());
    const hdr = try wire.parseNfgenmsg(m.payload);
    try testing.expectEqual(@as(u8, 2), hdr.family);
    var it = hdr.attrIterator();
    var seen: u32 = 0;
    while (try it.next()) |a| {
        switch (a.type) {
            CTA.MARK => try testing.expectEqual(@as(u32, 0x0102_0304), try a.asBe32()),
            CTA.MARK_MASK => try testing.expectEqual(@as(u32, 0xff00_ff00), try a.asBe32()),
            CTA.STATUS => try testing.expectEqual(@as(u32, IPS_ASSURED), try a.asBe32()),
            CTA.ZONE => try testing.expectEqual(@as(u16, 0x0506), try a.asBe16()),
            else => return error.UnexpectedAttribute, // no STATUS_MASK without a mask
        }
        seen += 1;
    }
    try testing.expectEqual(@as(u32, 4), seen);
    // The exact bytes of the mark pair, so a host-order write cannot pass.
    var pair: [8]u8 = .{ 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04 };
    std.mem.writeInt(u16, pair[0..2], 8, builtin.cpu.arch.endian());
    std.mem.writeInt(u16, pair[2..4], CTA.MARK, builtin.cpu.arch.endian());
    try testing.expect(std.mem.find(u8, got.bytes(), &pair) != null);
}

const IPS_ASSURED = wire.IPS.ASSURED;

test "DumpFilter.matches follows the kernel's rules, mark, status, zone" {
    var f: Flow = .{};
    // No filter keeps everything; a missing attribute reads as zero.
    try testing.expect((DumpFilter{}).matches(&f));
    try testing.expect((DumpFilter{ .mark = .{ .value = 0 } }).matches(&f));
    try testing.expect(!(DumpFilter{ .mark = .{ .value = 1 } }).matches(&f));
    try testing.expect((DumpFilter{ .zone = 0 }).matches(&f));
    try testing.expect(!(DumpFilter{ .zone = 3 }).matches(&f));

    f.mark = 0x1234;
    f.status = IPS_ASSURED | wire.IPS.CONFIRMED;
    f.zone = 7;
    // Masked mark, exact mark (default mask), a value with bits outside its mask never matches.
    try testing.expect((DumpFilter{ .mark = .{ .value = 0x1200, .mask = 0xff00 } }).matches(&f));
    try testing.expect((DumpFilter{ .mark = .{ .value = 0x1234 } }).matches(&f));
    try testing.expect(!(DumpFilter{ .mark = .{ .value = 0x1234, .mask = 0xff00 } }).matches(&f));
    try testing.expect(!(DumpFilter{ .mark = .{ .value = 0x1235 } }).matches(&f));
    // Status: bare value = all bits set; explicit mask = those bits equal the value.
    try testing.expect((DumpFilter{ .status = .{ .value = IPS_ASSURED } }).matches(&f));
    try testing.expect(!(DumpFilter{ .status = .{ .value = IPS_ASSURED | wire.IPS.SEEN_REPLY } }).matches(&f));
    try testing.expect((DumpFilter{ .status = .{ .value = 0, .mask = wire.IPS.SEEN_REPLY } }).matches(&f));
    try testing.expect(!(DumpFilter{ .status = .{ .value = 0, .mask = IPS_ASSURED } }).matches(&f));
    // All three at once.
    try testing.expect((DumpFilter{ .mark = .{ .value = 0x1234 }, .status = .{ .value = IPS_ASSURED }, .zone = 7 }).matches(&f));
    try testing.expect(!(DumpFilter{ .mark = .{ .value = 0x1234 }, .status = .{ .value = IPS_ASSURED }, .zone = 8 }).matches(&f));
}

test "decodeCpuStats: res_id is the CPU, every counter is big-endian" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    // Distinct, asymmetric values: a host-order read of any of them differs.
    const vals = [_]struct { t: u16, v: u32 }{
        .{ .t = CTA_STATS.SEARCHED, .v = 0x01020304 },
        .{ .t = CTA_STATS.FOUND, .v = 0x11121314 },
        .{ .t = CTA_STATS.NEW, .v = 0x21222324 },
        .{ .t = CTA_STATS.INVALID, .v = 0x31323334 },
        .{ .t = CTA_STATS.IGNORE, .v = 0x41424344 },
        .{ .t = CTA_STATS.DELETE, .v = 0x51525354 },
        .{ .t = CTA_STATS.DELETE_LIST, .v = 0x61626364 },
        .{ .t = CTA_STATS.INSERT, .v = 0x71727374 },
        .{ .t = CTA_STATS.INSERT_FAILED, .v = 0x81828384 },
        .{ .t = CTA_STATS.DROP, .v = 0x91929394 },
        .{ .t = CTA_STATS.EARLY_DROP, .v = 0xa1a2a3a4 },
        .{ .t = CTA_STATS.ERROR, .v = 0xb1b2b3b4 },
        .{ .t = CTA_STATS.SEARCH_RESTART, .v = 0xc1c2c3c4 },
        .{ .t = CTA_STATS.CLASH_RESOLVE, .v = 0xd1d2d3d4 },
        .{ .t = CTA_STATS.CHAIN_TOOLONG, .v = 0xe1e2e3e4 },
        .{ .t = 99, .v = 5 }, // unknown: skipped
    };
    for (vals) |v| try codec.appendAttrBe32(gpa, &attrs, v.t, v.v);
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try testMessage(gpa, &msg, msg_ct_get_stats_cpu, .unspec, 0x0203, attrs.items);
    const m = try firstPayload(msg.items);
    const s = try decodeCpuStats(m.payload);
    try testing.expectEqual(@as(u16, 0x0203), s.cpu);
    try testing.expectEqual(@as(u32, 0x01020304), s.searched);
    try testing.expectEqual(@as(u32, 0x11121314), s.found);
    try testing.expectEqual(@as(u32, 0x21222324), s.new);
    try testing.expectEqual(@as(u32, 0x31323334), s.invalid);
    try testing.expectEqual(@as(u32, 0x41424344), s.ignore);
    try testing.expectEqual(@as(u32, 0x51525354), s.delete);
    try testing.expectEqual(@as(u32, 0x61626364), s.delete_list);
    try testing.expectEqual(@as(u32, 0x71727374), s.insert);
    try testing.expectEqual(@as(u32, 0x81828384), s.insert_failed);
    try testing.expectEqual(@as(u32, 0x91929394), s.drop);
    try testing.expectEqual(@as(u32, 0xa1a2a3a4), s.early_drop);
    try testing.expectEqual(@as(u32, 0xb1b2b3b4), s.errors);
    try testing.expectEqual(@as(u32, 0xc1c2c3c4), s.search_restart);
    try testing.expectEqual(@as(u32, 0xd1d2d3d4), s.clash_resolve);
    try testing.expectEqual(@as(u32, 0xe1e2e3e4), s.chain_toolong);
}

test "decodeCpuStats / decodeGlobalStats: a wrong-sized counter is BadLength, a short header Truncated" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try codec.appendAttrBe16(gpa, &attrs, CTA_STATS.FOUND, 1);
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try testMessage(gpa, &msg, msg_ct_get_stats_cpu, .unspec, 0, attrs.items);
    const m = try firstPayload(msg.items);
    try testing.expectError(error.BadLength, decodeCpuStats(m.payload));
    attrs.clearRetainingCapacity();
    try codec.appendAttrBe16(gpa, &attrs, CTA_STATS_GLOBAL.ENTRIES, 1);
    msg.clearRetainingCapacity();
    try testMessage(gpa, &msg, msg_ct_get_stats, .unspec, 0, attrs.items);
    try testing.expectError(error.BadLength, decodeGlobalStats((try firstPayload(msg.items)).payload));
    try testing.expectError(error.Truncated, decodeCpuStats(&.{ 0, 0 }));
    try testing.expectError(error.Truncated, decodeGlobalStats(&.{}));
}

test "decodeGlobalStats: entries and max_entries, big-endian" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try codec.appendAttrBe32(gpa, &attrs, CTA_STATS_GLOBAL.ENTRIES, 0x0000_1234);
    try codec.appendAttrBe32(gpa, &attrs, CTA_STATS_GLOBAL.MAX_ENTRIES, 0x0004_0000);
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try testMessage(gpa, &msg, msg_ct_get_stats, .unspec, 0, attrs.items);
    const m = try firstPayload(msg.items);
    const g = try decodeGlobalStats(m.payload);
    try testing.expectEqual(@as(u32, 0x1234), g.entries);
    try testing.expectEqual(@as(u32, 0x40000), g.max_entries);
}

test "decodeExpectStats: three counters and the CPU" {
    const gpa = testing.allocator;
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try codec.appendAttrBe32(gpa, &attrs, 1, 0x0a0b0c0d);
    try codec.appendAttrBe32(gpa, &attrs, 2, 0x1a1b1c1d);
    try codec.appendAttrBe32(gpa, &attrs, 3, 0x2a2b2c2d);
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try testMessage(gpa, &msg, msg_exp_get_stats_cpu, .unspec, 5, attrs.items);
    const s = try decodeExpectStats((try firstPayload(msg.items)).payload);
    try testing.expectEqual(@as(u16, 5), s.cpu);
    try testing.expectEqual(@as(u32, 0x0a0b0c0d), s.new);
    try testing.expectEqual(@as(u32, 0x1a1b1c1d), s.create);
    try testing.expectEqual(@as(u32, 0x2a2b2c2d), s.delete);
}

test "stats and expectation dump requests: type, flags, family" {
    const cases = [_]struct { req: [20]u8, ty: u16, dump: bool }{
        .{ .req = buildStatsCpuDump(3), .ty = 0x0104, .dump = true },
        .{ .req = buildStatsGlobal(3), .ty = 0x0105, .dump = false },
        .{ .req = buildExpectStatsDump(3), .ty = 0x0203, .dump = true },
        .{ .req = buildExpectDump(3, .ipv6), .ty = 0x0201, .dump = true },
    };
    for (cases) |c| {
        const m = try firstPayload(&c.req);
        try testing.expectEqual(c.ty, m.type);
        try testing.expectEqual(c.dump, m.flags & codec.NLM_F_DUMP == codec.NLM_F_DUMP);
        try testing.expect(m.flags & codec.NLM_F_REQUEST != 0);
    }
    try testing.expectEqual(@as(u8, 10), buildExpectDump(3, .ipv6)[codec.header_len]);
}

fn tupleNest(gpa: std.mem.Allocator, list: *std.ArrayList(u8), ty: u16, t: Tuple) !void {
    try wire.appendTuple(gpa, list, ty, t);
}

test "decodeExpect: master, tuple, mask and the scalars" {
    const gpa = testing.allocator;
    const master: Tuple = .{ .src = .{ .v4 = .{ 10, 0, 0, 1 } }, .dst = .{ .v4 = .{ 10, 0, 0, 2 } }, .proto = wire.IPPROTO.TCP, .src_port = 40000, .dst_port = 21 };
    const want: Tuple = .{ .src = .{ .v4 = .{ 10, 0, 0, 2 } }, .dst = .{ .v4 = .{ 10, 0, 0, 1 } }, .proto = wire.IPPROTO.TCP, .src_port = 0, .dst_port = 20000 };
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try tupleNest(gpa, &attrs, CTA_EXPECT.MASTER, master);
    try tupleNest(gpa, &attrs, CTA_EXPECT.TUPLE, want);
    try tupleNest(gpa, &attrs, CTA_EXPECT.MASK, want);
    try codec.appendAttrBe32(gpa, &attrs, CTA_EXPECT.TIMEOUT, 0x0102_0304);
    try codec.appendAttrBe32(gpa, &attrs, CTA_EXPECT.ID, 0x0a0b_0c0d);
    try codec.appendAttr(gpa, &attrs, CTA_EXPECT.HELP_NAME, "ftp\x00");
    try codec.appendAttrBe16(gpa, &attrs, CTA_EXPECT.ZONE, 0x0506);
    try codec.appendAttrBe32(gpa, &attrs, CTA_EXPECT.FLAGS, 0x1122_3344);
    try codec.appendAttrBe32(gpa, &attrs, CTA_EXPECT.CLASS, 0x5566_7788);
    try codec.appendAttr(gpa, &attrs, CTA_EXPECT.FN, "nf_nat_ftp\x00");
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try testMessage(gpa, &msg, msg_exp_new, .ipv4, 0, attrs.items);
    const e = try decodeExpect((try firstPayload(msg.items)).payload);
    try testing.expectEqual(Family.ipv4, e.family);
    try testing.expectEqual(@as(?u16, 40000), e.master.src_port);
    try testing.expectEqual(@as(?u16, 20000), e.tuple.dst_port);
    try testing.expectEqual(@as(?u16, 20000), e.mask.dst_port);
    try testing.expectEqual(@as(?u32, 0x01020304), e.timeout);
    try testing.expectEqual(@as(?u32, 0x0a0b0c0d), e.id);
    try testing.expectEqualStrings("ftp", e.helper.?.slice());
    try testing.expectEqual(@as(?u16, 0x0506), e.zone);
    try testing.expectEqual(@as(?u32, 0x11223344), e.flags);
    try testing.expectEqual(@as(?u32, 0x55667788), e.class);
    try testing.expectEqualStrings("nf_nat_ftp", e.fn_name.?.slice());
}

test "decodeExpect: hostile names, lengths and truncations are errors, never a panic" {
    const gpa = testing.allocator;
    // A 16-byte name with no NUL, and a 40-byte one: both over the limit.
    var attrs: std.ArrayList(u8) = .empty;
    defer attrs.deinit(gpa);
    try codec.appendAttr(gpa, &attrs, CTA_EXPECT.HELP_NAME, "0123456789abcdef");
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try testMessage(gpa, &msg, msg_exp_new, .ipv4, 0, attrs.items);
    try testing.expectError(error.BadLength, decodeExpect((try firstPayload(msg.items)).payload));
    // 15 characters without a NUL is the longest legal unterminated name.
    try testing.expectEqualStrings("0123456789abcde", (try Name.fromAttr("0123456789abcde")).slice());
    try testing.expectEqual(@as(usize, 0), (try Name.fromAttr("")).slice().len);
    // A NUL ends the name; what follows it is ignored.
    try testing.expectEqualStrings("ab", (try Name.fromAttr("ab\x00cdefghijklmnopqrstuvwxyz")).slice());
    // Wrong-sized scalar.
    attrs.clearRetainingCapacity();
    try codec.appendAttrBe16(gpa, &attrs, CTA_EXPECT.TIMEOUT, 1);
    msg.clearRetainingCapacity();
    try testMessage(gpa, &msg, msg_exp_new, .ipv4, 0, attrs.items);
    try testing.expectError(error.BadLength, decodeExpect((try firstPayload(msg.items)).payload));
    // Every truncation of a good message is an error or a value.
    attrs.clearRetainingCapacity();
    try codec.appendAttrBe32(gpa, &attrs, CTA_EXPECT.TIMEOUT, 9);
    try codec.appendAttr(gpa, &attrs, CTA_EXPECT.HELP_NAME, "sip\x00");
    msg.clearRetainingCapacity();
    try testMessage(gpa, &msg, msg_exp_new, .ipv4, 0, attrs.items);
    const p = (try firstPayload(msg.items)).payload;
    var cut: usize = 0;
    while (cut <= p.len) : (cut += 1) _ = decodeExpect(p[0..cut]) catch {};
}
