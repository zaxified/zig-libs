// SPDX-License-Identifier: MIT

//! `/proc/<pid>/stat`, every field `prometheus/procfs` `ProcStat` reads, plus
//! the two conversions a process collector needs (CPU seconds, start time).
//!
//! `process.zig`'s `ProcessEntry` is the cheap 5-field view `listProcesses`
//! builds for hundreds of pids; `PidStat` is the full record for one process.

const std = @import("std");
const procnet = @import("root.zig");

/// The kernel's `USER_HZ` (`sysconf(_SC_CLK_TCK)`): the unit of `utime`,
/// `stime`, `cutime`, `cstime`, `starttime` and `delayacct_blkio_ticks`. It is
/// 100 on every Linux ABI that matters (it is a userspace-visible constant,
/// independent of the kernel's internal `CONFIG_HZ`); `prometheus/procfs` uses
/// the same constant. A caller who wants the libc value reads
/// `sysconf(_SC_CLK_TCK)` itself — this module does not link libc.
pub const user_hz: u64 = 100;

/// One `/proc/<pid>/stat` record. Field names follow `proc(5)`; the numbering
/// in the comments is `proc(5)`'s `(N)`. A field the line does not carry (an
/// older kernel prints fewer; a truncated or crafted line) reads 0, and
/// `fields` says how many fields the line really had.
pub const PidStat = struct {
    pid: u32,
    comm_buf: [procnet.comm_max]u8 = @splat(0),
    comm_len: u8 = 0,
    /// (3) `R` running, `S` sleeping, `D` disk sleep, `Z` zombie, `T` stopped, `I` idle...
    state: u8,
    ppid: i64 = 0,
    pgrp: i64 = 0,
    session: i64 = 0,
    /// (7) controlling terminal, as `tty_nr`.
    tty_nr: i64 = 0,
    tpgid: i64 = 0,
    flags: u64 = 0,
    minflt: u64 = 0,
    cminflt: u64 = 0,
    majflt: u64 = 0,
    cmajflt: u64 = 0,
    /// (14) user-mode time in `user_hz` ticks.
    utime: u64 = 0,
    /// (15) kernel-mode time in `user_hz` ticks.
    stime: u64 = 0,
    cutime: i64 = 0,
    cstime: i64 = 0,
    priority: i64 = 0,
    nice: i64 = 0,
    num_threads: i64 = 0,
    /// (22) time the process started after boot, in `user_hz` ticks.
    starttime: u64 = 0,
    /// (23) virtual memory size in BYTES.
    vsize: u64 = 0,
    /// (24) resident set size in PAGES (see `residentBytes`). Signed in the
    /// kernel (`%ld`); a negative value reads as given.
    rss: i64 = 0,
    rsslim: u64 = 0,
    startcode: u64 = 0,
    endcode: u64 = 0,
    startstack: u64 = 0,
    /// (39) CPU last executed on.
    processor: u64 = 0,
    rt_priority: u64 = 0,
    policy: u64 = 0,
    delayacct_blkio_ticks: u64 = 0,
    guest_time: i64 = 0,
    cguest_time: i64 = 0,
    /// How many whitespace-separated fields followed `comm` (`state` is the
    /// first). 42 on a kernel that prints everything `PidStat` reads; fewer on
    /// an older one.
    fields: u8 = 0,

    /// The process name, clamped to `procnet.comm_max`.
    pub fn comm(s: *const PidStat) []const u8 {
        return s.comm_buf[0..s.comm_len];
    }

    /// Total CPU time (user + system) in seconds: `(utime + stime) / USER_HZ`.
    /// The `process_cpu_seconds_total` of a Prometheus process collector.
    pub fn cpuSeconds(s: *const PidStat) f64 {
        return @as(f64, @floatFromInt(s.utime +| s.stime)) / @as(f64, @floatFromInt(user_hz));
    }

    /// Process start as a Unix timestamp: `btime + starttime / USER_HZ`, with
    /// `btime` the boot time from `/proc/stat` (`procnet.Stat.btime`). The
    /// `process_start_time_seconds` of a process collector.
    pub fn startTimeSeconds(s: *const PidStat, btime: u64) f64 {
        return @as(f64, @floatFromInt(btime)) + @as(f64, @floatFromInt(s.starttime)) / @as(f64, @floatFromInt(user_hz));
    }

    /// Resident set size in bytes for pages of `page_size` bytes; a negative
    /// `rss` reads as 0 and the product saturates.
    pub fn residentBytes(s: *const PidStat, page_size: usize) u64 {
        const pages: u64 = if (s.rss < 0) 0 else @intCast(s.rss);
        return pages *| page_size;
    }

    /// `residentBytes` with this machine's page size.
    pub fn residentBytesNow(s: *const PidStat) u64 {
        return s.residentBytes(std.heap.pageSize());
    }
};

fn uint(toks: []const []const u8, i: usize) u64 {
    if (i >= toks.len) return 0;
    return std.fmt.parseInt(u64, toks[i], 10) catch 0;
}

fn int(toks: []const []const u8, i: usize) i64 {
    if (i >= toks.len) return 0;
    return std.fmt.parseInt(i64, toks[i], 10) catch 0;
}

/// Parse one `/proc/<pid>/stat` line. `comm` is everything between the FIRST
/// `(` and the LAST `)` — the kernel does not escape either, and a process can
/// name itself `a) (b` — so the fields after it start at the last `)`.
/// Returns null if there is no `(...)`, the pid is not a number, or `state` or
/// `ppid` is missing; any later field that is missing or not a number reads 0.
/// Pure and allocation-free.
pub fn parsePidStat(line: []const u8) ?PidStat {
    const lp = std.mem.indexOfScalar(u8, line, '(') orelse return null;
    const rp = std.mem.lastIndexOfScalar(u8, line, ')') orelse return null;
    if (rp <= lp) return null;
    const pid = std.fmt.parseInt(u32, std.mem.trim(u8, line[0..lp], " \t\n"), 10) catch return null;

    var toks: [42][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, line[rp + 1 ..], " \t\n");
    while (n < toks.len) {
        toks[n] = it.next() orelse break;
        n += 1;
    }
    if (n < 2 or toks[0].len == 0) return null;
    const t = toks[0..n];

    // Index 0 is `state` (proc(5) field 3); the comments name the field.
    var s: PidStat = .{ .pid = pid, .state = t[0][0] };
    s.comm_len = @intCast(procnet.copyClamped(&s.comm_buf, line[lp + 1 .. rp]));
    s.fields = @intCast(n);
    s.ppid = int(t, 1);
    s.pgrp = int(t, 2);
    s.session = int(t, 3);
    s.tty_nr = int(t, 4);
    s.tpgid = int(t, 5);
    s.flags = uint(t, 6);
    s.minflt = uint(t, 7);
    s.cminflt = uint(t, 8);
    s.majflt = uint(t, 9);
    s.cmajflt = uint(t, 10);
    s.utime = uint(t, 11);
    s.stime = uint(t, 12);
    s.cutime = int(t, 13);
    s.cstime = int(t, 14);
    s.priority = int(t, 15);
    s.nice = int(t, 16);
    s.num_threads = int(t, 17);
    // 18 itrealvalue: obsolete, always 0.
    s.starttime = uint(t, 19);
    s.vsize = uint(t, 20);
    s.rss = int(t, 21);
    s.rsslim = uint(t, 22);
    s.startcode = uint(t, 23);
    s.endcode = uint(t, 24);
    s.startstack = uint(t, 25);
    // 26..34: kstkesp kstkeip signal blocked sigignore sigcatch wchan nswap
    // cnswap — obsolete or zero on current kernels. 35 exit_signal.
    s.processor = uint(t, 36);
    s.rt_priority = uint(t, 37);
    s.policy = uint(t, 38);
    s.delayacct_blkio_ticks = uint(t, 39);
    s.guest_time = int(t, 40);
    s.cguest_time = int(t, 41);
    return s;
}

/// Read and parse `/proc/<pid>/stat` (or `/proc/self/stat`). Null if the
/// process is gone, unreadable or its line is malformed. No allocation.
pub fn readPidStat(io: std.Io, ref: procnet.ProcRef) ?PidStat {
    var pb: [64]u8 = undefined;
    const path = ref.path(&pb, "stat") orelse return null;
    var buf: [4096]u8 = undefined;
    const text = procnet.readVirtualFileInto(io, path, &buf) orelse return null;
    return parsePidStat(text);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

// A real capture of this machine's own `/proc/self/stat` (kernel 7.0, 2026-10-17).
const real_stat = @embedFile("testdata/pid_stat.txt");

test "parsePidStat: every field of a real capture" {
    const s = parsePidStat(real_stat).?;
    try testing.expectEqual(@as(u32, 3667450), s.pid);
    try testing.expectEqualStrings("cat", s.comm());
    try testing.expectEqual(@as(u8, 'R'), s.state);
    try testing.expectEqual(@as(i64, 3667449), s.ppid);
    try testing.expectEqual(@as(i64, 3667450), s.pgrp);
    try testing.expectEqual(@as(i64, 3667449), s.session);
    try testing.expectEqual(@as(i64, 0), s.tty_nr);
    try testing.expectEqual(@as(i64, -1), s.tpgid);
    try testing.expectEqual(@as(u64, 4194304), s.flags);
    try testing.expectEqual(@as(u64, 516), s.minflt);
    try testing.expectEqual(@as(i64, 20), s.priority);
    try testing.expectEqual(@as(i64, 0), s.nice);
    try testing.expectEqual(@as(i64, 1), s.num_threads);
    try testing.expectEqual(@as(u64, 76867616), s.starttime);
    try testing.expectEqual(@as(u64, 18214912), s.vsize);
    try testing.expectEqual(@as(i64, 1873), s.rss);
    try testing.expectEqual(@as(u64, 18446744073709551615), s.rsslim);
    try testing.expectEqual(@as(u64, 104762815475712), s.startcode);
    try testing.expectEqual(@as(u64, 104762820518893), s.endcode);
    try testing.expectEqual(@as(u64, 140721451274304), s.startstack);
    try testing.expectEqual(@as(u64, 0), s.processor);
    try testing.expectEqual(@as(u64, 0), s.rt_priority);
    try testing.expectEqual(@as(u64, 0), s.policy);
    try testing.expectEqual(@as(u8, 42), s.fields);
}

test "parsePidStat: distinct values in every position (field-index map)" {
    // Field N carries the value N so a shifted index shows up as a wrong number.
    const line = "77 (idx) Z 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42\n";
    const s = parsePidStat(line).?;
    // Token i (after `state` = 0) holds the value i + 1 for ppid... below.
    try testing.expectEqual(@as(i64, 1), s.ppid);
    try testing.expectEqual(@as(i64, 2), s.pgrp);
    try testing.expectEqual(@as(i64, 3), s.session);
    try testing.expectEqual(@as(i64, 4), s.tty_nr);
    try testing.expectEqual(@as(i64, 5), s.tpgid);
    try testing.expectEqual(@as(u64, 6), s.flags);
    try testing.expectEqual(@as(u64, 7), s.minflt);
    try testing.expectEqual(@as(u64, 8), s.cminflt);
    try testing.expectEqual(@as(u64, 9), s.majflt);
    try testing.expectEqual(@as(u64, 10), s.cmajflt);
    try testing.expectEqual(@as(u64, 11), s.utime);
    try testing.expectEqual(@as(u64, 12), s.stime);
    try testing.expectEqual(@as(i64, 13), s.cutime);
    try testing.expectEqual(@as(i64, 14), s.cstime);
    try testing.expectEqual(@as(i64, 15), s.priority);
    try testing.expectEqual(@as(i64, 16), s.nice);
    try testing.expectEqual(@as(i64, 17), s.num_threads);
    try testing.expectEqual(@as(u64, 19), s.starttime);
    try testing.expectEqual(@as(u64, 20), s.vsize);
    try testing.expectEqual(@as(i64, 21), s.rss);
    try testing.expectEqual(@as(u64, 22), s.rsslim);
    try testing.expectEqual(@as(u64, 23), s.startcode);
    try testing.expectEqual(@as(u64, 24), s.endcode);
    try testing.expectEqual(@as(u64, 25), s.startstack);
    try testing.expectEqual(@as(u64, 36), s.processor);
    try testing.expectEqual(@as(u64, 37), s.rt_priority);
    try testing.expectEqual(@as(u64, 38), s.policy);
    try testing.expectEqual(@as(u64, 39), s.delayacct_blkio_ticks);
    try testing.expectEqual(@as(i64, 40), s.guest_time);
    try testing.expectEqual(@as(i64, 41), s.cguest_time);
}

test "parsePidStat: comm with spaces, parentheses and ') (' inside" {
    const tail = " S 5 6 7 0 -1 0 0 0 0 0 100 50 0 0 20 0 3 0 1000 4096 7 0 0 0 0 0 0 0 0 0 0 0 0 17 2 0 0 0 0 0";
    const s1 = parsePidStat("9 (a) (b)" ++ tail).?;
    try testing.expectEqualStrings("a) (b", s1.comm());
    try testing.expectEqual(@as(u64, 100), s1.utime);
    try testing.expectEqual(@as(i64, 5), s1.ppid);
    const s2 = parsePidStat("9 ((sd-pam))" ++ tail).?;
    try testing.expectEqualStrings("(sd-pam)", s2.comm());
    const s3 = parsePidStat("9 (my proc name)" ++ tail).?;
    try testing.expectEqualStrings("my proc name", s3.comm());
    try testing.expectEqual(@as(i64, 7), s3.rss);
    const s4 = parsePidStat("9 ()" ++ tail).?;
    try testing.expectEqualStrings("", s4.comm());
    // ")" and "(" in the comm that look like fields: " 99 " is part of the name.
    const s5 = parsePidStat("9 (x ) 99 ( y)" ++ tail).?;
    try testing.expectEqualStrings("x ) 99 ( y", s5.comm());
    try testing.expectEqual(@as(u64, 50), s5.stime);
}

test "parsePidStat: older kernels print fewer fields, missing ones read 0" {
    // A pre-3.x line stops after `delayacct_blkio_ticks` / earlier.
    const s = parsePidStat("5 (old) S 1 5 5 0 -1 64 1 2 3 4 10 20 0 0 20 0 1 0 77 8192 3 18446744073709551615").?;
    try testing.expectEqual(@as(u64, 10), s.utime);
    try testing.expectEqual(@as(u64, 77), s.starttime);
    try testing.expectEqual(@as(i64, 3), s.rss);
    try testing.expectEqual(@as(u64, 0), s.processor);
    try testing.expectEqual(@as(i64, 0), s.guest_time);
    try testing.expectEqual(@as(u8, 23), s.fields);
}

test "parsePidStat: malformed lines" {
    try testing.expectEqual(@as(?PidStat, null), parsePidStat(""));
    try testing.expectEqual(@as(?PidStat, null), parsePidStat("1 (x"));
    try testing.expectEqual(@as(?PidStat, null), parsePidStat("1 x) S 1"));
    try testing.expectEqual(@as(?PidStat, null), parsePidStat(") (")); // close before open
    try testing.expectEqual(@as(?PidStat, null), parsePidStat("x (a) S 1"));
    try testing.expectEqual(@as(?PidStat, null), parsePidStat("-3 (a) S 1"));
    try testing.expectEqual(@as(?PidStat, null), parsePidStat("1 (a)")); // no state
    try testing.expectEqual(@as(?PidStat, null), parsePidStat("1 (a) S")); // no ppid
    // Garbage in a numeric slot reads 0 rather than dropping the process.
    const s = parsePidStat("1 (a) S x y z").?;
    try testing.expectEqual(@as(i64, 0), s.ppid);
    // Overlong comm is clamped, not dropped.
    const long = "1 (" ++ strRepeat("n", 200) ++ ") S 1 1";
    try testing.expectEqual(@as(usize, procnet.comm_max), parsePidStat(long).?.comm().len);
    // A 20-digit number past u64 reads 0.
    try testing.expectEqual(@as(u64, 0), parsePidStat("1 (a) S 1 1 1 1 1 1 1 1 1 1 1 99999999999999999999999").?.stime);
}

test "PidStat: cpuSeconds, startTimeSeconds, residentBytes" {
    const s = parsePidStat("4 (c) S 1 1 1 0 -1 0 0 0 0 0 250 175 0 0 20 0 1 0 12345 1000000 10 0").?;
    try testing.expectApproxEqAbs(@as(f64, 4.25), s.cpuSeconds(), 1e-9); // (250 + 175) / 100
    try testing.expectApproxEqAbs(@as(f64, 1_700_000_123.45), s.startTimeSeconds(1_700_000_000), 1e-6);
    try testing.expectEqual(@as(u64, 10 * 4096), s.residentBytes(4096));
    try testing.expectEqual(@as(u64, 10 * 65536), s.residentBytes(65536));
    try testing.expectEqual(@as(u64, 10 * std.heap.pageSize()), s.residentBytesNow());
    // Saturation and negative rss.
    var big = s;
    big.utime = std.math.maxInt(u64);
    big.rss = std.math.maxInt(i64);
    try testing.expect(big.cpuSeconds() > 1e17);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), big.residentBytes(65536));
    big.rss = -5;
    try testing.expectEqual(@as(u64, 0), big.residentBytes(4096));
}

test "readPidStat: this process, by .self and by pid" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;

    const a = readPidStat(io, .self) orelse return error.SkipZigTest;
    // Under qemu-user (the big-endian lane: qemu-mips) `/proc/self/stat` is
    // qemu's own synthesis — pid, comm, ppid, num_threads, starttime and
    // startstack, every other field 0 — not the kernel's; no real process has
    // a zero `vsize`.
    if (a.vsize == 0) return error.SkipZigTest;
    const my_pid: u32 = @intCast(std.os.linux.getpid());
    try testing.expectEqual(my_pid, a.pid);
    try testing.expect(a.vsize > 0);
    try testing.expect(a.rss > 0);
    try testing.expect(a.num_threads >= 1);
    try testing.expect(a.fields >= 40);
    try testing.expect(a.comm().len > 0);
    try testing.expect(a.starttime > 0);

    const b = readPidStat(io, .{ .pid = my_pid }).?;
    try testing.expectEqual(a.pid, b.pid);
    try testing.expectEqualStrings(a.comm(), b.comm());
    try testing.expectEqual(a.starttime, b.starttime);
    // A pid that cannot exist (pid_max is below 2^22).
    try testing.expectEqual(@as(?PidStat, null), readPidStat(io, .{ .pid = 4_294_967_000 }));
}

test "PidStat.residentBytes: a negative rss reads as zero at any magnitude" {
    var s = parsePidStat("1 (a) S 0").?;
    s.rss = -1;
    try testing.expectEqual(@as(u64, 0), s.residentBytes(4096));
    s.rss = std.math.minInt(i64);
    try testing.expectEqual(@as(u64, 0), s.residentBytes(4096));
    s.rss = 3;
    try testing.expectEqual(@as(u64, 3 * 16384), s.residentBytes(16384));
}

test "parsePidStat: a close-paren before the open-paren is no comm" {
    try testing.expect(parsePidStat("12 ) (x S 1") == null);
    try testing.expect(parsePidStat("12 )( S 1") == null);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * 2 + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
