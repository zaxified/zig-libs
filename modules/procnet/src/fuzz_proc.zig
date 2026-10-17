// SPDX-License-Identifier: MIT

//! Test-only: deterministic fuzz harnesses for the prometheus/procfs-parity
//! parsers (`pidstat`, `pidfiles`, `pairs`, `unix`), on the testkit driver.
//!
//! Each harness is generic over its source of choices
//! (`fn (comptime S, *S, gpa) anyerror!void`): `std.testing.Smith` under
//! `--fuzz`, `testkit.fuzz.Rng` (a seeded PRNG) under the driver. Every choice
//! — a real capture or crafted sample, how many octets to damage and where,
//! whether to cut it short, or arbitrary bytes — is a draw, so a seed
//! reproduces one input: `PROCNET_FUZZ=1,<seed>`.
//!
//!     PROCNET_FUZZ=<runs>[,<first seed>]   the verdict run (unset: skipped)
//!     PROCNET_FUZZ_ONLY=<substring>        one harness
//!
//! Beyond "never panics, never leaks" each harness states an invariant: the
//! full-stat parser must agree with the 5-field `parseProcStat` on whether a
//! line parses at all, borrowed slices must lie inside the input text, and so
//! on. The always-on test below runs a few hundred seeds of each in every
//! ordinary test run and fails if a harness stops reaching its parser's
//! success path.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const procnet = @import("root.zig");

const interesting = " \t\n:()-0123456789abcdefx@/\r\x00\xff";

/// One input: arbitrary bytes (1 draw in 8), or a damaged copy of a sample.
fn draw(comptime S: type, src: *S, samples: []const []const u8, buf: []u8) []const u8 {
    if (src.valueRangeAtMost(u8, 0, 7) == 0) {
        const n = src.slice(buf[0..@min(buf.len, 512)]);
        return buf[0..n];
    }
    const sample = samples[src.index(samples.len)];
    const len = @min(sample.len, buf.len);
    @memcpy(buf[0..len], sample[0..len]);
    if (len == 0) return buf[0..0];
    const muts = src.valueRangeAtMost(u8, 0, 12);
    var i: u8 = 0;
    while (i < muts) : (i += 1) {
        const at = src.index(len);
        buf[at] = switch (src.valueRangeAtMost(u8, 0, 3)) {
            0 => src.value(u8),
            1 => ' ',
            2 => '\n',
            else => interesting[src.index(interesting.len)],
        };
    }
    const cut = if (src.valueRangeAtMost(u8, 0, 3) == 0) src.index(len + 1) else len;
    return buf[0..cut];
}

fn inside(text: []const u8, s: []const u8) bool {
    if (s.len == 0) return true;
    const t0 = @intFromPtr(text.ptr);
    const s0 = @intFromPtr(s.ptr);
    return s0 >= t0 and s0 + s.len <= t0 + text.len;
}

/// A harness for `check`, over `samples`; `id` indexes the reach counters.
fn Harness(
    comptime id: usize,
    comptime samples: []const []const u8,
    comptime check: fn (text: []const u8, gpa: std.mem.Allocator) anyerror!bool,
) type {
    return struct {
        pub fn run(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
            var buf: [16 * 1024]u8 = undefined;
            const text = draw(S, src, samples, &buf);
            if (try check(text, gpa)) reach[id] += 1;
        }
    };
}

var reach: [8]usize = @splat(0);

// ── the checks ───────────────────────────────────────────────────────────────

fn checkStat(text: []const u8, _: std.mem.Allocator) anyerror!bool {
    const a = procnet.parsePidStat(text);
    const b = procnet.parseProcStatWithPage(text, 4096);
    // Two parsers, one question: is this a stat line?
    try testing.expectEqual(a == null, b == null);
    const s = a orelse return false;
    const e = b.?;
    try testing.expect(s.comm().len <= procnet.comm_max);
    try testing.expect(s.fields >= 2 and s.fields <= 42);
    try testing.expectEqual(s.pid, e.pid);
    try testing.expectEqual(s.state, e.state);
    try testing.expectEqualStrings(s.comm(), e.name());
    if (s.ppid >= 0 and s.ppid <= std.math.maxInt(u32)) try testing.expectEqual(@as(i64, e.ppid), s.ppid);
    if (s.rss > 0 and s.rss < (1 << 50)) try testing.expectEqual(@as(u64, @intCast(s.rss)) * 4, e.rss_kb);
    _ = s.cpuSeconds();
    _ = s.startTimeSeconds(0);
    _ = s.residentBytes(65536);
    return true;
}

fn checkLimits(text: []const u8, _: std.mem.Allocator) anyerror!bool {
    const l = procnet.parseLimits(text);
    var rows: usize = 0;
    for (l.rows) |r| {
        if (r != null) rows += 1;
    }
    try testing.expect(rows + l.skipped_rows <= text.len + 1);
    return rows > 0;
}

fn checkStatus(text: []const u8, _: std.mem.Allocator) anyerror!bool {
    const s = procnet.parsePidStatus(text);
    try testing.expect(s.name().len <= procnet.comm_max);
    try testing.expect(s.nspids().len <= 32);
    for (s.cpuRanges()) |r| try testing.expect(r.first <= r.last);
    try testing.expect(s.cpus_allowed_count >= s.cpuRanges().len or s.cpus_allowed_len == 0);
    _ = s.totalCtxtSwitches();
    return s.name().len > 0 or s.vm_rss > 0 or s.threads > 0;
}

fn checkIo(text: []const u8, _: std.mem.Allocator) anyerror!bool {
    const p = procnet.parsePidIo(text);
    return p.fields > 0;
}

fn checkCgroup(text: []const u8, gpa: std.mem.Allocator) anyerror!bool {
    const l = try procnet.parseCgroups(gpa, text);
    defer l.deinit(gpa);
    for (l.entries) |e| {
        try testing.expect(inside(text, e.controllers) and inside(text, e.path));
        try testing.expect(std.mem.indexOfScalar(u8, e.controllers, ':') == null);
        var it = e.controllerIterator();
        while (it.next()) |_| {}
    }
    return l.entries.len > 0;
}

fn checkCmdline(text: []const u8, _: std.mem.Allocator) anyerror!bool {
    var it = procnet.pidfiles.cmdlineArgs(text);
    var total: usize = 0;
    var n: usize = 0;
    while (it.next()) |a| {
        try testing.expect(inside(text, a));
        total += a.len + 1;
        n += 1;
        try testing.expect(n <= text.len + 1);
    }
    try testing.expect(total <= text.len + 1);
    return n > 1;
}

fn checkPairs(text: []const u8, gpa: std.mem.Allocator) anyerror!bool {
    const t = try procnet.parsePairs(gpa, text);
    defer t.deinit(gpa);
    for (t.entries) |e| {
        try testing.expect(inside(text, e.section) and inside(text, e.name));
        try testing.expect(t.get(e.section, e.name) != null);
    }
    _ = t.ipExtOctets();
    return t.entries.len > 0;
}

fn checkUnix(text: []const u8, gpa: std.mem.Allocator) anyerror!bool {
    const rows = try procnet.parseUnix(gpa, text);
    defer gpa.free(rows);
    for (rows) |*r| {
        try testing.expect(r.path().len <= procnet.unix.path_max);
        _ = r.isListening();
        _ = r.isAbstract();
        _ = r.typeName();
        _ = r.stateName();
    }
    return rows.len > 0;
}

// ── samples ──────────────────────────────────────────────────────────────────

const stat_samples = [_][]const u8{
    @embedFile("testdata/pid_stat.txt"),
    "1 (systemd) S 0 1 1 0 -1 4194560 55321 3271011 40 4482 106 88 1058 621 20 0 1 0 3 170939904 2237 18446744073709551615 0 0 0 0 0 0 671173123 4096 1260 1 0 0 17 3 0 0 0 0 0 0 0 0 0 0",
    "1234 ((sd-pam)) S 1233 1233 1233 0 -1 1077936384 10 0 0 0 0 0 0 0 20 0 1 0 5 170000000 200 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0",
    "42 (my) (weird) name) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 300 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0",
    "5 (old) S 1 5 5 0 -1 64 1 2 3 4 10 20 0 0 20 0 1 0 77 8192 3 18446744073709551615",
};

const limits_samples = [_][]const u8{
    @embedFile("testdata/pid_limits.txt"),
    "Limit Soft Limit Hard Limit Units\nMax open files 1024 4096 files\nMax stack size 8388608\nMax cpu time\tunlimited\tunlimited\tseconds\r\n",
};

const status_samples = [_][]const u8{
    @embedFile("testdata/pid_status.txt"),
    "Name:\tkworker/0:0H-kblockd\nState:\tI (idle)\nPid:\t10\nPPid:\t2\nUid:\t0\t0\t0\t0\nNSpid:\t4242\t17\t1\nCpus_allowed_list:\t0-2,5,8-9\nvoluntary_ctxt_switches:\t5\nnonvoluntary_ctxt_switches:\t7\nCapEff:\tffffffffffffffff\nVmRSS:\t18446744073709551615 kB\n",
};

const io_samples = [_][]const u8{
    @embedFile("testdata/pid_io.txt"),
    "rchar: 1\nwchar: 2\nsyscr: 3\nsyscw: 4\nread_bytes: 5\nwrite_bytes: 6\ncancelled_write_bytes: 7\n",
};

const cgroup_samples = [_][]const u8{
    @embedFile("testdata/pid_cgroup.txt"),
    "12:cpu,cpuacct:/docker/abc\n11:pids:/a:b:c\n1:name=systemd:/\n0::/x (deleted)\n",
};

const cmdline_samples = [_][]const u8{
    "prog\x00--flag\x00a b c\x00",
    "a\x00\x00b\x00",
    "nginx: master process",
    "\x00",
};

const pairs_samples = [_][]const u8{
    @embedFile("testdata/netstat.txt"),
    @embedFile("testdata/snmp.txt"),
    "A: x y z\nA: 1 2\nB: p q\nB: 3 -4\nIpExt: InOctets OutOctets\nIpExt: 5 6\n",
};

const unix_samples = [_][]const u8{
    @embedFile("testdata/unix.txt"),
    "Num       RefCount Protocol Flags    Type St Inode Path\nffff8881: 00000002 00000000 00010000 0001 01 777 @/tmp/.X11-unix/X0\nffff8882: 00000003 00000000 00000000 0005 04 778 /run/my app/sock x\nffff8883: 00000002 00000000 00000000 0002 01 779\n",
};

const StatH = Harness(0, &stat_samples, checkStat);
const LimitsH = Harness(1, &limits_samples, checkLimits);
const StatusH = Harness(2, &status_samples, checkStatus);
const IoH = Harness(3, &io_samples, checkIo);
const CgroupH = Harness(4, &cgroup_samples, checkCgroup);
const CmdlineH = Harness(5, &cmdline_samples, checkCmdline);
const PairsH = Harness(6, &pairs_samples, checkPairs);
const UnixH = Harness(7, &unix_samples, checkUnix);

// ── the driver (verdict runs) ────────────────────────────────────────────────

test "fuzz driver: PROCNET_FUZZ pidstat" {
    try fuzz_driver.run(StatH.run, .{ .prefix = "PROCNET_FUZZ", .name = "procnet-pidstat" });
}
test "fuzz driver: PROCNET_FUZZ limits" {
    try fuzz_driver.run(LimitsH.run, .{ .prefix = "PROCNET_FUZZ", .name = "procnet-limits" });
}
test "fuzz driver: PROCNET_FUZZ status" {
    try fuzz_driver.run(StatusH.run, .{ .prefix = "PROCNET_FUZZ", .name = "procnet-status" });
}
test "fuzz driver: PROCNET_FUZZ io" {
    try fuzz_driver.run(IoH.run, .{ .prefix = "PROCNET_FUZZ", .name = "procnet-io" });
}
test "fuzz driver: PROCNET_FUZZ cgroup" {
    try fuzz_driver.run(CgroupH.run, .{ .prefix = "PROCNET_FUZZ", .name = "procnet-cgroup" });
}
test "fuzz driver: PROCNET_FUZZ cmdline" {
    try fuzz_driver.run(CmdlineH.run, .{ .prefix = "PROCNET_FUZZ", .name = "procnet-cmdline" });
}
test "fuzz driver: PROCNET_FUZZ pairs" {
    try fuzz_driver.run(PairsH.run, .{ .prefix = "PROCNET_FUZZ", .name = "procnet-pairs" });
}
test "fuzz driver: PROCNET_FUZZ unix" {
    try fuzz_driver.run(UnixH.run, .{ .prefix = "PROCNET_FUZZ", .name = "procnet-unix" });
}

// ── always on: a few hundred seeds of each, and they must reach the parser ───

fn runSeeds(comptime H: type, seeds: usize) !void {
    for (0..seeds) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        H.run(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("procnet fuzz seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
}

test "fuzz harnesses: 400 seeds each in every test run, all reach their parser" {
    reach = @splat(0);
    try runSeeds(StatH, 400);
    try runSeeds(LimitsH, 400);
    try runSeeds(StatusH, 400);
    try runSeeds(IoH, 400);
    try runSeeds(CgroupH, 400);
    try runSeeds(CmdlineH, 400);
    try runSeeds(PairsH, 400);
    try runSeeds(UnixH, 400);
    const names = [_][]const u8{ "pidstat", "limits", "status", "io", "cgroup", "cmdline", "pairs", "unix" };
    for (reach, names) |n, name| {
        if (n == 0) {
            std.debug.print("procnet fuzz: harness {s} never produced a result in 400 seeds\n", .{name});
            return error.HarnessDoesNotReach;
        }
    }
}
