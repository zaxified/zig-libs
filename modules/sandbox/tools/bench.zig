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
//! Method (`testkit.bench`, with one addition for the `sys_` rows
//! -- `ours_foreign`): each side doubles its batch until it takes over 100 ms
//! and keeps the best of five; per workload the sides alternate for
//! `BENCH_ROUNDS` (default 3) rounds, each keeping its best. `build` is by
//! user-mode cycles, the `sys_` rows by wall time. Arguments filter workloads
//! by substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
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
    for (list) |s| try txt.writer.print("{d}\n", .{@backingInt(s)});
    try dir.writeFile(io, .{ .sub_path = "allow.txt", .data = txt.written() });
    const prog = try sandbox.seccomp.buildDefault(arena, .kill_process);
    try dir.writeFile(io, .{ .sub_path = "ours.bpf", .data = std.mem.sliceAsBytes(prog) });

    const lib_dir = init.environ_map.get("LIBSECCOMP_DIR") orelse default_lib_dir;
    const libseccomp = try arena.print("{s}/libseccomp.so.2", .{lib_dir});
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/sandbox/tools/c_bench/foreign_bench.c", &.{libseccomp});

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
        const name = try arena.print("sys_{s}@none", .{p});
        const row = try bench.foreign(arena, io, bench_name, exe, abs, name, &banner);
        try w.print("unfiltered {s}: {d:.0} ns per 100 syscalls\n", .{ p, row.ns });
    }
    try w.flush();

    var ws: std.ArrayList(Work) = .empty;
    try ws.append(arena, .{ .name = "build", .op = .{}, .ref = "build" });
    for (probes) |p| {
        try ws.append(arena, .{
            .name = try arena.print("sys_{s}", .{p}),
            .op = .{},
            .ref = try arena.print("sys_{s}@ref", .{p}),
            .alt = try arena.print("sys_{s}@tree", .{p}),
            .ours_foreign = try arena.print("sys_{s}@ours", .{p}),
        });
    }

    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/libseccomp = {d:.3} (best {d:.3}); worst vs the faster of the two layouts = {d:.3}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× libseccomp <version> (default layout) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
