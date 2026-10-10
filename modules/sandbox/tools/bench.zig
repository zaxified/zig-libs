// SPDX-License-Identifier: MIT

//! Comparative benchmark: `sandbox`'s seccomp filter builder against libseccomp
//! (the system library, the reference named by the maturity card), the program
//! behind the `**Performance:**` line of the card (CONVENTIONS.md §9, kept
//! instrument kind 3). Only the seccomp part has a speed axis: the other steps
//! (no-new-privs, uid drop, rlimits, Landlock) are single syscalls whose cost
//! is the kernel's.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-sandbox` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`
//! against the system libseccomp, header /usr/include/seccomp.h, library
//! `libseccomp.so.2` in `LIBSECCOMP_DIR` or the path below), Linux x86-64, and
//! permission to install a seccomp filter in a child process (no root). Run
//! from the repository root.
//!
//! The same allow-list goes to both sides: `seccomp.default_allowlist` (the
//! module's network-server preset, ~100 syscalls), deny action kill-process.
//! Workloads:
//!   build        compiling the allow-list into a BPF program: ours
//!                `seccomp.build`; theirs `seccomp_init` + one `seccomp_rule_add`
//!                per syscall + `seccomp_export_bpf_mem` (not loaded). One-time
//!                startup cost, count = syscalls.
//!   sys_<probe>  what the FILTER COSTS EVERY SYSCALL, the cost that matters in
//!                a sandboxed server's hot loop: a process installs the filter
//!                and times 100 back-to-back raw syscalls of <probe> -- `read`
//!                (the first entry of our list), `epoll` (epoll_wait, timeout
//!                0, mid-list), `futex` (wake), `gettid` (late in the list) --
//!                wall time, kernel included. Ours: our program installed by
//!                the C measuring process via prctl (so both sides run under
//!                the identical loop); theirs: libseccomp's default
//!                optimisation (`@ref`, the reference) and, as `alt`, the
//!                binary-tree layout (`SCMP_FLTATR_CTL_OPTIMIZE = 2`, the one
//!                the card's survey says libseccomp builds), which gives the
//!                `/fast` column.
//! The unfiltered cost of each probe and the program lengths are printed first
//! for context: a ratio of totals close to 1 can hide a large ratio of the
//! filter's own cost.
//!
//! Method (shared driver at the bottom, with one addition for the `sys_` rows
//! -- `ours_foreign`): each side doubles its batch until it takes over 100 ms
//! and keeps the best of five; per workload the sides alternate for
//! `BENCH_ROUNDS` (default 3) rounds, each keeping its best. `build` is by
//! user-mode cycles, the `sys_` rows by wall time. Arguments filter workloads
//! by substring (no card line then).

const std = @import("std");
const builtin = @import("builtin");
const sandbox = @import("sandbox");

const bench_name = "bench-sandbox";
const work_dir = ".zig-cache/bench-sandbox";
const default_lib_dir = "/usr/lib/x86_64-linux-gnu";
const probes = [_][]const u8{ "read", "epoll", "futex", "gettid" };

const Op = struct { gpa: void = {} };

const Ctx = struct {
    gpa: std.mem.Allocator,
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    const prog = sandbox.seccomp.buildDefault(x.gpa, .kill_process) catch unreachable;
    defer x.gpa.free(prog);
    std.mem.doNotOptimizeAway(prog.ptr);
    return sandbox.seccomp.default_allowlist.len;
}

pub fn main(init: std.process.Init) !u8 {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) {
        std.debug.print("{s}: Linux x86-64 only\n", .{bench_name});
        return 1;
    }
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var ctx: Ctx = .{ .gpa = std.heap.smp_allocator };
    const list = sandbox.seccomp.default_allowlist;
    var txt: std.Io.Writer.Allocating = .init(arena);
    for (list) |s| try txt.writer.print("{d}\n", .{@intFromEnum(s)});
    try dir.writeFile(io, .{ .sub_path = "allow.txt", .data = txt.written() });
    const prog = try sandbox.seccomp.buildDefault(arena, .kill_process);
    try dir.writeFile(io, .{ .sub_path = "ours.bpf", .data = std.mem.sliceAsBytes(prog) });

    const lib_dir = init.environ_map.get("LIBSECCOMP_DIR") orelse default_lib_dir;
    const libseccomp = try std.fmt.allocPrint(arena, "{s}/libseccomp.so.2", .{lib_dir});
    const exe = try buildForeign(arena, io, abs, "modules/sandbox/tools/c_bench/foreign_bench.c", &.{libseccomp});

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const info = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, "info" } });
    if (info.term != .exited or info.term.exited != 0) {
        std.debug.print("{s}: foreign info failed:\n{s}\n", .{ bench_name, info.stderr });
        return 1;
    }
    try w.print("{s}ours: {d} instructions, {d} syscalls\n", .{ info.stdout, prog.len, list.len });
    // Unfiltered baseline for context (not part of any ratio).
    for (probes) |p| {
        var banner: []const u8 = undefined;
        const name = try std.fmt.allocPrint(arena, "sys_{s}@none", .{p});
        const row = try foreign(arena, io, exe, abs, name, &banner);
        try w.print("unfiltered {s}: {d:.0} ns per 100 syscalls\n", .{ p, row.ns });
    }
    try w.flush();

    var ws: std.ArrayList(Work) = .empty;
    try ws.append(arena, .{ .name = "build", .op = .{}, .ref = "build" });
    for (probes) |p| {
        try ws.append(arena, .{
            .name = try std.fmt.allocPrint(arena, "sys_{s}", .{p}),
            .op = .{},
            .ref = try std.fmt.allocPrint(arena, "sys_{s}@ref", .{p}),
            .alt = try std.fmt.allocPrint(arena, "sys_{s}@tree", .{p}),
            .ours_foreign = try std.fmt.allocPrint(arena, "sys_{s}@ours", .{p}),
        });
    }

    const s = try drive(io, arena, &.{exe}, abs, &ctx, ws.items, filters, rounds, w);
    try w.print("reference: {s}\nworst ours/libseccomp = {d:.3} (best {d:.3}); worst vs the faster of the two layouts = {d:.3}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× libseccomp <version> (default layout) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

// ---- comparison driver (the same in every crypto module's tools/bench.zig) ----

/// One timed side: per-op wall time and user-mode cycles (0 = no counter).
const Row = struct { ns: f64, cycles: f64 = 0, count: u64 };

/// Best and worst of the rounds of one side.
const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    best_cyc: f64 = std.math.inf(f64),
    worst_cyc: f64 = 0,
    count: u64 = 0,

    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.best_cyc = @min(s.best_cyc, r.cycles);
        s.worst_cyc = @max(s.worst_cyc, r.cycles);
        s.count = r.count;
    }
    fn best(s: Side, cyc: bool) f64 {
        return if (cyc) s.best_cyc else s.best_ns;
    }
    fn spread(s: Side, cyc: bool) f64 {
        return if (cyc) s.worst_cyc / s.best_cyc - 1 else s.worst_ns / s.best_ns - 1;
    }
};

/// This thread's user-mode cycle counter (`perf stat -e cycles:u`).
const Cycles = struct {
    fd: ?i32,

    fn open() Cycles {
        if (@import("builtin").os.tag != .linux) return .{ .fd = null };
        const linux = std.os.linux;
        var attr: linux.perf_event_attr = .{
            .type = .HARDWARE,
            .config = @intFromEnum(linux.PERF.COUNT.HW.CPU_CYCLES),
            .flags = .{ .exclude_kernel = true, .exclude_hv = true },
        };
        const rc = linux.perf_event_open(&attr, 0, -1, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return .{ .fd = null };
        return .{ .fd = @intCast(rc) };
    }

    fn read(c: Cycles) u64 {
        const fd = c.fd orelse return 0;
        var v: u64 = 0;
        _ = std.os.linux.read(fd, @ptrCast(&v), @sizeOf(u64));
        return v;
    }
};

fn timeIt(io: std.Io, cyc: Cycles, x: *Ctx) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(x));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var best_cycles: u64 = std.math.maxInt(u64);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        const c0 = cyc.read();
        for (0..n) |_| count = once(x);
        best_cycles = @min(best_cycles, cyc.read() - c0);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    const nf: f64 = @floatFromInt(n);
    return .{ .ns = @as(f64, @floatFromInt(best)) / nf, .cycles = @as(f64, @floatFromInt(best_cycles)) / nf, .count = count };
}

/// Run the foreign program for one workload: `<exe> <work dir> <name>`, which
/// prints `name \t ns/op \t cycles/op \t count` and its banner on stderr.
fn foreign(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8, banner: *[]const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    banner.* = res.stderr;
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const cycles = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .cycles = cycles, .count = count };
}

/// One workload: `op` for our side, the foreign program's workload `ref`
/// (the reference) and optionally `alt` (a second implementation in the
/// field, for the `fastest` ratio); `*_exe` index the foreign programs.
/// `ours_foreign`: when set, OUR side is also taken from the foreign program,
/// running that workload name (sandbox: a filter is irreversible and acts on
/// the whole process, so every `sys_` row runs both sides' filters inside the
/// same measuring process instead of in this one).
const Work = struct { name: []const u8, op: Op, ref: []const u8, alt: ?[]const u8 = null, ref_exe: usize = 0, alt_exe: usize = 0, ours_foreign: ?[]const u8 = null };

const Summary = struct {
    best_ref: f64 = std.math.inf(f64),
    worst_ref: f64 = 0,
    /// Worst of ours / min(ref, alt) over the workloads that have an `alt`.
    worst_fast: ?f64 = null,
    max_spread: f64 = 0,
    banner: []const u8 = "",
    alt_banner: []const u8 = "",
};

fn drive(io: std.Io, arena: std.mem.Allocator, exes: []const []const u8, abs: []const u8, ctx: *Ctx, ws: []const Work, filters: []const [:0]const u8, rounds: usize, w: *std.Io.Writer) !Summary {
    const cyc: Cycles = .open();
    var s: Summary = .{};
    var metric_cycles = true;
    var mismatch = false;
    try w.print("{s:<18} {s:>11} {s:>11} {s:>11} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "ref ns", "alt ns", "/ref", "/fast", "spr us", "spr rf", "spr al" });
    try w.flush();
    for (ws) |x| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, x.name, f) != null;
            if (!hit) continue;
        }
        ctx.op = x.op;
        var ours: Side = .{};
        var ref: Side = .{};
        var alt: Side = .{};
        // The sides alternate, `rounds` times, each keeping its best: timed one
        // after the other they would see different loads of a shared machine.
        for (0..rounds) |_| {
            ref.add(try foreign(arena, io, exes[x.ref_exe], abs, x.ref, &s.banner));
            if (x.ours_foreign) |n| {
                var sink_banner: []const u8 = undefined;
                ours.add(try foreign(arena, io, exes[x.ref_exe], abs, n, &sink_banner));
            } else ours.add(timeIt(io, cyc, ctx));
            if (x.alt) |a| alt.add(try foreign(arena, io, exes[x.alt_exe], abs, a, &s.alt_banner));
        }
        const by_cyc = ours.best_cyc > 0 and ref.best_cyc > 0 and (x.alt == null or alt.best_cyc > 0);
        metric_cycles = metric_cycles and by_cyc;
        const r_ref = ours.best(by_cyc) / ref.best(by_cyc);
        s.worst_ref = @max(s.worst_ref, r_ref);
        s.best_ref = @min(s.best_ref, r_ref);
        var r_fast: f64 = r_ref;
        if (x.alt != null) {
            r_fast = ours.best(by_cyc) / @min(ref.best(by_cyc), alt.best(by_cyc));
            s.worst_fast = @max(s.worst_fast orelse 0, r_fast);
        }
        const spr_alt = if (x.alt != null) alt.spread(by_cyc) else 0;
        s.max_spread = @max(s.max_spread, @max(ours.spread(by_cyc), @max(ref.spread(by_cyc), spr_alt)));
        const same = ours.count == ref.count and (x.alt == null or ours.count == alt.count);
        mismatch = mismatch or !same;
        try w.print("{s:<18} {d:>11.0} {d:>11.0} {d:>11.0} {d:>7.3} {d:>7.3} {d:>5.1}% {d:>5.1}% {d:>5.1}%  {d}{s}\n", .{
            x.name,        ours.best_ns, ref.best_ns,               if (x.alt != null) alt.best_ns else 0,
            r_ref,         r_fast,       100 * ours.spread(by_cyc), 100 * ref.spread(by_cyc),
            100 * spr_alt, ours.count,
            if (same) "" else " ≠",
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (metric_cycles) "user-mode cycles" else "wall time", 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    try w.flush();
    if (mismatch) {
        std.debug.print("{s}: FAILED -- an output size differs between the sides\n", .{bench_name});
        return error.CountMismatch;
    }
    return s;
}

/// The foreign program, built from `src` with `zig cc -O3 -march=native`
/// against `libs` (shared objects named by path, so no headers are needed).
fn buildForeign(arena: std.mem.Allocator, io: std.Io, abs: []const u8, src: []const u8, libs: []const []const u8) ![]const u8 {
    const exe = try std.fmt.allocPrint(arena, "{s}/foreign_bench", .{abs});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "zig", "cc", "-O3", "-march=native", src });
    try argv.appendSlice(arena, libs);
    try argv.appendSlice(arena, &.{ "-o", exe });
    std.debug.print("{s}: building the foreign side ({s}) ...\n", .{ bench_name, src });
    const cc = try std.process.run(arena, io, .{ .argv = argv.items });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("{s}: zig cc failed:\n{s}\n", .{ bench_name, cc.stderr });
        return error.ForeignBuildFailed;
    }
    return exe;
}

/// Run the foreign program once in a non-timing mode (`interop`, `keygen`).
fn foreignOnce(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, mode: []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, mode } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed in {s}:\n{s}\n", .{ bench_name, mode, res.stderr });
        return error.ForeignFailed;
    }
}
