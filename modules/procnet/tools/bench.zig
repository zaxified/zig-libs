// SPDX-License-Identifier: MIT

//! Comparative benchmark: `procnet` against prometheus/procfs v0.21.1 (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-procnet` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs a local go >= 1.26
//! and github.com/prometheus/procfs v0.21.1 in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`; `GOTOOLCHAIN=local`, `GOPROXY=off`). Run
//! from the repository root. Linux only (it reads /proc).
//!
//! Every row is "read THIS process's /proc file and parse it", the same file on
//! both sides, the same number of times: the cost is the open/read/close
//! syscalls plus the parse, and procfs has no parse-from-bytes entry point
//! (`Proc.Stat`, `Proc.Limits`, ... open the file themselves; the parsers are
//! unexported), so there are no `parse_*` rows.
//!   pid_stat     readPidStat(.self)        vs Proc.Stat()
//!   pid_limits   readPidLimits(.self)      vs Proc.Limits()
//!   pid_status   readPidStatus(.self)      vs Proc.NewStatus()
//!   pid_io       readPidIo(.self)          vs Proc.IO()
//!   fd_count     countFds(.self)           vs Proc.FileDescriptorsLen()
//!   pid_netstat  readPidNetstat(.self)     vs Proc.Netstat()
//!   net_unix     readUnix                  vs FS.NetUNIX()
//!   net_dev      readNetDev                vs FS.NetDev()
//!   stat         readStat                  vs FS.Stat()
//! The two sides are different processes, so utime/vsize/fd counts legitimately
//! differ; the result count is an invariant both compute identically (a
//! diverging parse shows up as a count mismatch before any timing is read):
//!   pid_stat     1 if pid is this process, state is R/S/D, vsize > 0, starttime > 0
//!   pid_limits   wrapping sum of every soft limit except `Max open files` (the Go
//!                runtime raises its soft RLIMIT_NOFILE), unlimited = 2^64-1, masked to 63 bits
//!   pid_status   uid + 7*gid + 1e9 if tgid == pid == this process and 0 < VmRSS <= VmSize
//!   pid_io       1 if rchar > 0 and syscr > 0
//!   fd_count     1 if 3 <= count < 256 (each side's own descriptors differ)
//!   pid_netstat  1 if IpExt InOctets and OutOctets are both > 0
//!   net_unix     1 if the table is not empty
//!   net_dev      10 * interfaces + 1 if `lo` is present
//!   stat         10 * per-CPU rows + 1 if btime > 1.5e9
//! Work per op differs where the APIs do: procfs's Stat() parses every /proc/stat
//! line (intr, softirq, ...) where ours skips the ones it does not type, and its
//! NetUNIX/NetDev/Netstat build typed rows / maps with per-row allocation; that is
//! what each library's public call costs and is what the ratio compares.
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best. Ratios are ours/procfs by wall time; the verdict is the
//! WORST ratio over the rows. Arguments filter rows.

const std = @import("std");
const bench = @import("testkit").bench;
const procnet = @import("procnet");

const bench_name = "bench-procnet";
const work_dir = ".zig-cache/bench-procnet";
const go_dir = "modules/procnet/tools/go_bench";
const ref_short = "procfs";
const ref_card = "prometheus/procfs v0.21.1";

const names = [_][]const u8{ "pid_stat", "pid_limits", "pid_status", "pid_io", "fd_count", "pid_netstat", "net_unix", "net_dev", "stat" };

const gpa = std.heap.smp_allocator;

fn b2u(b: bool) u64 {
    return @intFromBool(b);
}

fn once(io: std.Io, w: usize, pid: u64) u64 {
    switch (w) {
        0 => {
            const s = procnet.readPidStat(io, .self) orelse return 0;
            return b2u(s.pid == pid and (s.state == 'R' or s.state == 'S' or s.state == 'D') and s.vsize > 0 and s.starttime > 0);
        },
        1 => {
            const l = procnet.readPidLimits(io, .self) orelse return 0;
            var sum: u64 = 0;
            for (l.rows, 0..) |row, i| {
                if (i == @backingInt(procnet.Resource.open_files)) continue;
                const r = row orelse continue;
                sum +%= r.soft orelse std.math.maxInt(u64);
            }
            return sum & 0x7fffffffffffffff;
        },
        2 => {
            const s = procnet.readPidStatus(io, .self) orelse return 0;
            const ok = s.tgid == pid and s.pid == pid and s.vm_rss > 0 and s.vm_size >= s.vm_rss;
            return s.uids[0] + 7 * s.gids[0] + 1_000_000_000 * b2u(ok);
        },
        3 => {
            const s = procnet.readPidIo(io, .self) orelse return 0;
            return b2u(s.rchar > 0 and s.syscr > 0);
        },
        4 => {
            const n = procnet.countFds(io, .self) orelse return 0;
            return b2u(n >= 3 and n < 256);
        },
        5 => {
            const t = procnet.readPidNetstat(gpa, io, .self) catch return 0;
            defer t.deinit(gpa);
            const o = t.ipExtOctets() orelse return 0;
            return b2u(o.in > 0 and o.out > 0);
        },
        6 => {
            const t = procnet.readUnix(gpa, io) catch return 0;
            defer t.deinit(gpa);
            return b2u(t.entries.len > 0);
        },
        7 => {
            const d = procnet.readNetDev(gpa, io) catch return 0;
            defer gpa.free(d);
            var lo = false;
            for (d) |*e| lo = lo or std.mem.eql(u8, e.name(), "lo");
            return d.len * 10 + b2u(lo);
        },
        8 => {
            const s = procnet.readStat(gpa, io) catch return 0;
            defer s.deinit(gpa);
            return s.cpus.len * 10 + b2u(s.btime > 1_500_000_000);
        },
        else => unreachable,
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;
    const pid: u64 = @intCast(std.os.linux.getpid());

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<14} {s:>11} {s:>11} {s:>8} {s:>7} {s:>7}  count\n", .{ "row", "ours ns", ref_short ++ " ns", "ratio", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        for (0..rounds) |_| {
            go.add(try bench.foreignArgv(arena, io, bench_name, &.{ exe, name }, name, null));
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ io, wi, pid }, true));
        }
        const ratio = ours.best_ns / go.best_ns;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        max_spread = @max(max_spread, @max(ours.spread(false), go.spread(false)));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<14} {d:>11.0} {d:>11.0} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, ratio, 100 * ours.spread(false), 100 * go.spread(false), ours.count, if (same) "" else " ≠ " ++ ref_short });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}
