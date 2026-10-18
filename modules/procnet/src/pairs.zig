// SPDX-License-Identifier: MIT

//! The kernel's "header line / value line" counter files:
//! `/proc/net/snmp`, `/proc/net/netstat`, and their per-process twins
//! `/proc/<pid>/net/snmp`, `/proc/<pid>/net/netstat`. One parser serves all.
//!
//!     IpExt: InNoRoutes InTruncatedPkts ... InOctets OutOctets ...
//!     IpExt: 65 0 ... 94074242337 36195828540 ...
//!
//! Every `(section, name) -> value` is kept — `TcpExt`, `IpExt`, `MPTcpExt`,
//! `Ip`, `Icmp`, `IcmpMsg`, `Tcp`, `Udp`, `UdpLite`, whatever the kernel
//! prints, including counters a later kernel adds. Where `prometheus/procfs`
//! has one struct field per known counter, this keeps a flat table and looks
//! counters up by name, so a new kernel counter needs no new code.
//!
//! ## ⚠ "Per process" network counters are per NETWORK NAMESPACE
//!
//! `/proc/<pid>/net/*` shows the network namespace of `<pid>`, not anything
//! the process did: every process in the same namespace reads the same
//! numbers, and `/proc/net` is simply `/proc/self/net`. So the Prometheus
//! `process_network_receive_bytes_total` / `process_network_transmit_bytes_total`
//! (which `client_golang` fills from `IpExt InOctets` / `OutOctets` of
//! `/proc/self/net/netstat`) are the byte counts of the whole namespace — on
//! a host, of the whole machine's IP traffic; in a container, of the container.
//! This module reproduces the data faithfully and does not pretend otherwise.

const std = @import("std");
const procnet = @import("root.zig");

/// One counter: `section` is the line prefix without its colon (`"IpExt"`).
/// Slices borrow from the text the table was parsed from.
pub const Pair = struct {
    section: []const u8,
    name: []const u8,
    /// The counter. A few `snmp` entries are signed (`Tcp MaxConn` is `-1`
    /// for "no limit"); they appear here as the two's-complement `u64`,
    /// `@bitCast` it to `i64` to read them.
    value: u64,
};

pub const PairTable = struct {
    entries: []Pair,
    /// Non-null when the table owns the bytes the entries borrow from (it was
    /// read from `/proc`); null when parsed from a caller's slice.
    text: ?[]u8 = null,
    /// The file was longer than the read limit.
    truncated: bool = false,

    pub fn deinit(t: PairTable, gpa: std.mem.Allocator) void {
        gpa.free(t.entries);
        if (t.text) |x| gpa.free(x);
    }

    /// The value of `name` in `section` (first match), or null.
    pub fn get(t: *const PairTable, section: []const u8, name: []const u8) ?u64 {
        for (t.entries) |e| {
            if (std.mem.eql(u8, e.section, section) and std.mem.eql(u8, e.name, name)) return e.value;
        }
        return null;
    }

    /// `IpExt InOctets` / `OutOctets` — the two counters a Prometheus process
    /// collector exports as `process_network_{receive,transmit}_bytes_total`.
    /// Null unless the table has both. Namespace-wide; see the file header.
    pub fn ipExtOctets(t: *const PairTable) ?struct { in: u64, out: u64 } {
        const i = t.get("IpExt", "InOctets") orelse return null;
        const o = t.get("IpExt", "OutOctets") orelse return null;
        return .{ .in = i, .out = o };
    }
};

/// The largest `snmp`/`netstat` file read: 1 MiB (real ones are ~7 KiB).
pub const read_limit: usize = 1 << 20;

fn sectionOf(line: []const u8) ?[]const u8 {
    const c = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    if (c == 0) return null;
    return line[0..c];
}

fn parseValue(tok: []const u8) ?u64 {
    if (std.fmt.parseInt(u64, tok, 10)) |v| return v else |_| {}
    const s = std.fmt.parseInt(i64, tok, 10) catch return null;
    return @bitCast(s);
}

/// Parse a header/value counter file. Lines are taken in pairs; a pair whose
/// two lines carry different section names is not a pair (the first line is
/// dropped and the scan resumes at the next, so one stray line cannot shift
/// every later pair), and a pair with different token counts is dropped whole.
/// A value that is not a number drops that one counter. The entries BORROW
/// `text`. Never fails except on allocation.
pub fn parsePairs(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error!PairTable {
    var out: std.ArrayList(Pair) = .empty;
    errdefer out.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    var pending: ?[]const u8 = lines.next();
    while (pending) |head| {
        const sec = sectionOf(head) orelse {
            pending = lines.next();
            continue;
        };
        const val_line = lines.next() orelse break;
        const vsec = sectionOf(val_line) orelse {
            // Not a value line at all; it may be a header of its own, so resync on it.
            pending = val_line;
            continue;
        };
        if (!std.mem.eql(u8, sec, vsec)) {
            pending = val_line;
            continue;
        }
        pending = lines.next();

        const start = out.items.len;
        var names = std.mem.tokenizeAny(u8, head[sec.len + 1 ..], " \t\r");
        var vals = std.mem.tokenizeAny(u8, val_line[vsec.len + 1 ..], " \t\r");
        var mismatch = false;
        while (true) {
            const n = names.next();
            const v = vals.next();
            if (n == null and v == null) break;
            if (n == null or v == null) {
                mismatch = true;
                break;
            }
            const value = parseValue(v.?) orelse continue;
            try out.append(gpa, .{ .section = sec, .name = n.?, .value = value });
        }
        if (mismatch) out.shrinkRetainingCapacity(start);
    }
    return .{ .entries = try out.toOwnedSlice(gpa) };
}

fn readTable(gpa: std.mem.Allocator, io: std.Io, path: []const u8) std.mem.Allocator.Error!PairTable {
    const f = procnet.readVirtualFileReporting(gpa, io, path, read_limit) orelse
        return .{ .entries = try gpa.alloc(Pair, 0) };
    errdefer gpa.free(f.bytes);
    var t = try parsePairs(gpa, f.bytes);
    t.text = f.bytes;
    t.truncated = f.truncated;
    return t;
}

/// `/proc/net/netstat` (`TcpExt`, `IpExt`, `MPTcpExt`): the caller's network
/// namespace. Empty when the file is absent. Free with `deinit`.
pub fn readNetstat(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!PairTable {
    return readTable(gpa, io, "/proc/net/netstat");
}

/// `/proc/net/snmp` (`Ip`, `Icmp`, `IcmpMsg`, `Tcp`, `Udp`, `UdpLite`): the
/// caller's network namespace. Empty when absent.
pub fn readSnmp(gpa: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error!PairTable {
    return readTable(gpa, io, "/proc/net/snmp");
}

/// `/proc/<pid>/net/netstat` (or `/proc/self/net/netstat`): the network
/// namespace of that process — see the file header. Empty when the process is
/// gone or unreadable.
pub fn readPidNetstat(gpa: std.mem.Allocator, io: std.Io, ref: procnet.ProcRef) std.mem.Allocator.Error!PairTable {
    var pb: [64]u8 = undefined;
    const path = ref.path(&pb, "net/netstat") orelse return .{ .entries = try gpa.alloc(Pair, 0) };
    return readTable(gpa, io, path);
}

/// `/proc/<pid>/net/snmp`; see `readPidNetstat`.
pub fn readPidSnmp(gpa: std.mem.Allocator, io: std.Io, ref: procnet.ProcRef) std.mem.Allocator.Error!PairTable {
    var pb: [64]u8 = undefined;
    const path = ref.path(&pb, "net/snmp") orelse return .{ .entries = try gpa.alloc(Pair, 0) };
    return readTable(gpa, io, path);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");

const real_netstat = @embedFile("testdata/netstat.txt");
const real_snmp = @embedFile("testdata/snmp.txt");

/// Independent count of how many counters a well-formed file declares: the
/// header tokens minus the section name, over the even lines.
fn declaredCounters(text: []const u8) usize {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    var i: usize = 0;
    while (it.next()) |line| : (i += 1) {
        if (line.len == 0 or i % 2 == 1) continue;
        var t = std.mem.tokenizeScalar(u8, line, ' ');
        _ = t.next();
        while (t.next()) |_| n += 1;
    }
    return n;
}

test "parsePairs: real /proc/net/netstat capture, every pair kept" {
    const t = try parsePairs(testing.allocator, real_netstat);
    defer t.deinit(testing.allocator);
    try testing.expectEqual(declaredCounters(real_netstat), t.entries.len);
    try testing.expect(t.entries.len > 150);
    try testing.expectEqual(@as(?u64, 94074242337), t.get("IpExt", "InOctets"));
    try testing.expectEqual(@as(?u64, 36195828540), t.get("IpExt", "OutOctets"));
    try testing.expectEqual(@as(?u64, 65), t.get("IpExt", "InNoRoutes"));
    try testing.expectEqual(@as(?u64, 67280), t.get("IpExt", "InMcastPkts"));
    try testing.expectEqual(@as(?u64, 133054), t.get("IpExt", "InBcastPkts"));
    try testing.expectEqual(@as(?u64, 0), t.get("IpExt", "ReasmOverlaps")); // the last header token
    try testing.expectEqual(@as(?u64, 106), t.get("TcpExt", "PruneCalled"));
    try testing.expectEqual(@as(?u64, 180), t.get("TcpExt", "OutOfWindowIcmps"));
    try testing.expectEqual(@as(?u64, 625026), t.get("TcpExt", "TW"));
    try testing.expectEqual(@as(?u64, 0), t.get("MPTcpExt", "WinProbe")); // last of the third section
    try testing.expectEqual(@as(?u64, null), t.get("IpExt", "NoSuchCounter"));
    try testing.expectEqual(@as(?u64, null), t.get("Ip", "InOctets"));
    const o = t.ipExtOctets().?;
    try testing.expectEqual(@as(u64, 94074242337), o.in);
    try testing.expectEqual(@as(u64, 36195828540), o.out);
}

test "parsePairs: real /proc/net/snmp capture, signed MaxConn" {
    const t = try parsePairs(testing.allocator, real_snmp);
    defer t.deinit(testing.allocator);
    try testing.expectEqual(declaredCounters(real_snmp), t.entries.len);
    try testing.expectEqual(@as(?u64, 1), t.get("Ip", "Forwarding"));
    try testing.expectEqual(@as(?u64, 64), t.get("Ip", "DefaultTTL"));
    try testing.expectEqual(@as(?u64, 146707582), t.get("Ip", "InReceives"));
    try testing.expectEqual(@as(?u64, 138833508), t.get("Ip", "OutTransmits"));
    try testing.expectEqual(@as(?u64, 323975), t.get("Icmp", "InMsgs"));
    try testing.expectEqual(@as(?u64, 317816), t.get("IcmpMsg", "InType0"));
    try testing.expectEqual(@as(?u64, 57), t.get("Tcp", "CurrEstab"));
    try testing.expectEqual(@as(?u64, 430497), t.get("Tcp", "OutRsts"));
    const max_conn = t.get("Tcp", "MaxConn").?;
    try testing.expectEqual(@as(i64, -1), @as(i64, @bitCast(max_conn)));
    try testing.expect(t.get("Udp", "InDatagrams") != null);
    try testing.expect(t.ipExtOctets() == null); // IpExt is netstat's, not snmp's
}

test "parsePairs: crafted shapes" {
    // Count mismatch drops that pair only.
    {
        const t = try parsePairs(testing.allocator, "A: x y z\nA: 1 2\nB: p q\nB: 3 4\n");
        defer t.deinit(testing.allocator);
        try testing.expectEqual(@as(usize, 2), t.entries.len);
        try testing.expectEqual(@as(?u64, 3), t.get("B", "p"));
        try testing.expectEqual(@as(?u64, null), t.get("A", "x"));
    }
    // A stray line before the pairs does not shift them (resync on section name).
    {
        const t = try parsePairs(testing.allocator, "A: a\nB: b c\nB: 1 2\nC: d\nC: 9\n");
        defer t.deinit(testing.allocator);
        try testing.expectEqual(@as(?u64, 1), t.get("B", "b"));
        try testing.expectEqual(@as(?u64, 2), t.get("B", "c"));
        try testing.expectEqual(@as(?u64, 9), t.get("C", "d"));
        try testing.expectEqual(@as(?u64, null), t.get("A", "a"));
    }
    // A non-numeric value drops that counter, not its neighbours; negatives wrap.
    {
        const t = try parsePairs(testing.allocator, "T: a b c d\nT: 1 zz -7 18446744073709551615\n");
        defer t.deinit(testing.allocator);
        try testing.expectEqual(@as(usize, 3), t.entries.len);
        try testing.expectEqual(@as(?u64, 1), t.get("T", "a"));
        try testing.expectEqual(@as(?u64, null), t.get("T", "b"));
        try testing.expectEqual(@as(i64, -7), @as(i64, @bitCast(t.get("T", "c").?)));
        try testing.expectEqual(std.math.maxInt(u64), t.get("T", "d").?);
    }
    // CRLF, extra spaces, tabs, a value that overflows i64 and u64, duplicates (first wins).
    {
        const t = try parsePairs(testing.allocator, "X:  a\tb  \r\nX: 1   2 \r\nX: a\nX: 5\nY: o\nY: 99999999999999999999999\n");
        defer t.deinit(testing.allocator);
        try testing.expectEqual(@as(?u64, 1), t.get("X", "a"));
        try testing.expectEqual(@as(?u64, 2), t.get("X", "b"));
        try testing.expectEqual(@as(?u64, null), t.get("Y", "o"));
        try testing.expectEqual(@as(usize, 3), t.entries.len);
    }
    // Degenerate inputs.
    for ([_][]const u8{ "", "\n", "A: x\n", "A: x", ":\n:\n", "no colon\nat all\n", "A:\nA:\n", "\n\n\nA: q\n" }) |s| {
        const t = try parsePairs(testing.allocator, s);
        defer t.deinit(testing.allocator);
        try testing.expectEqual(@as(usize, 0), t.entries.len);
    }
    // No trailing newline still pairs.
    {
        const t = try parsePairs(testing.allocator, "Z: k\nZ: 8");
        defer t.deinit(testing.allocator);
        try testing.expectEqual(@as(?u64, 8), t.get("Z", "k"));
    }
}

test "ipExtOctets needs both counters" {
    const t = try parsePairs(testing.allocator, "IpExt: InOctets\nIpExt: 5\n");
    defer t.deinit(testing.allocator);
    try testing.expect(t.ipExtOctets() == null);
}

test "live: net/netstat and net/snmp for self, by pid, and system-wide agree" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const a = try readPidNetstat(testing.allocator, io, .self);
    defer a.deinit(testing.allocator);
    if (a.entries.len == 0) return error.SkipZigTest; // no netstat file in this sandbox
    try testing.expect(!a.truncated);
    const oct = a.ipExtOctets() orelse return error.SkipZigTest;

    // /proc/net is /proc/self/net: the same namespace, so the counters only grow.
    const sys = try readNetstat(testing.allocator, io);
    defer sys.deinit(testing.allocator);
    try testing.expectEqual(a.entries.len, sys.entries.len);
    try testing.expect(sys.get("IpExt", "InOctets").? >= oct.in);

    const my_pid: u32 = @intCast(std.os.linux.getpid());
    const b = try readPidNetstat(testing.allocator, io, .{ .pid = my_pid });
    defer b.deinit(testing.allocator);
    try testing.expectEqual(a.entries.len, b.entries.len);
    try testing.expect(b.get("IpExt", "InOctets").? >= oct.in);

    const s1 = try readSnmp(testing.allocator, io);
    defer s1.deinit(testing.allocator);
    try testing.expect(s1.get("Ip", "DefaultTTL") != null);
    const s2 = try readPidSnmp(testing.allocator, io, .self);
    defer s2.deinit(testing.allocator);
    try testing.expectEqual(s1.entries.len, s2.entries.len);
    try testing.expect(s2.get("Ip", "InReceives").? >= s1.get("Ip", "InReceives").?);

    const gone = try readPidNetstat(testing.allocator, io, .{ .pid = 4_294_967_000 });
    defer gone.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), gone.entries.len);
}

test "parsePairs: an empty section name is no pair; ipExtOctets needs InOctets as well" {
    const gpa = testing.allocator;
    const empty = try parsePairs(gpa, ": a b\n: 1 2\n");
    defer empty.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), empty.entries.len);
    const only_out = try parsePairs(gpa, "IpExt: OutOctets\nIpExt: 5\n");
    defer only_out.deinit(gpa);
    try testing.expect(only_out.ipExtOctets() == null);
}
