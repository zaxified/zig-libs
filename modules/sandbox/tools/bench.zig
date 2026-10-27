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
//! What the card GRADES per syscall (owner 2026-10-27) is not those wall-time
//! rows -- the filter is ~4 ns of a ~550 ns syscall and the rows swing by up to
//! 16 % between runs -- but the BPF instructions the kernel executes: every
//! program's cost for each allowed syscall (mean, worst) and for a denied one,
//! counted by `cbpf.zig` (the oracle's interpreter). Programs: ours
//! (`buildDefault`, and `buildRulesWith` `.tree`), libseccomp's two layouts
//! (exported by the C side), and the other builders in the field,
//! go-seccomp-bpf v1.6.0 and seccompiler 0.5.0 (`tools/foreign_steps/`, built
//! with the host's `go` / `cargo` when present -- their sources were read
//! before the first build, 2026-10-27). `ref` = ours `buildDefault` against
//! libseccomp's default layout, `fastest` = ours at its best layout against
//! the cheapest program measured, each the worst of the three ratios. The
//! `build` row (filter compile time) keeps its place in the `ref` range.
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
const cbpf = @import("cbpf.zig");

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
    var names: std.Io.Writer.Allocating = .init(arena);
    for (list) |sys| try names.writer.print("{t}\n", .{sys});
    try dir.writeFile(io, .{ .sub_path = "names.txt", .data = names.written() });
    const steps = try stepsTable(arena, io, dir, abs, w);
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
    try w.print("the sys_ rows are context, not graded: the syscall itself dominates them (see the unfiltered lines)\n", .{});
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.3}–{d:.2}× libseccomp <version> (filter build; BPF instructions per syscall, default layouts) · fastest {d:.2}× {s} (BPF instructions per syscall) (measured <today>)\n", .{ s.best_ref, @max(steps.ref, s.best_ref), steps.fastest, steps.fastest_name });
    try w.flush();
    return 0;
}

// ── the graded per-syscall cost: BPF instructions executed ─────────────────

const Cost = struct {
    mean: f64,
    worst: f64,
    denied: f64,

    /// The worst of the three ratios a/b.
    fn ratio(a: Cost, b: Cost) f64 {
        return @max(a.mean / b.mean, @max(a.worst / b.worst, a.denied / b.denied));
    }
};

/// Instructions `prog` runs for each syscall of the list (all must be
/// allowed) and for one denied number past them all.
fn cost(prog: []const cbpf.Insn) !Cost {
    const list = sandbox.seccomp.default_allowlist;
    var sum: usize = 0;
    var worst: usize = 0;
    for (list) |sys| {
        var n: usize = 0;
        const d: cbpf.Data = .{ .nr = @intCast(@backingInt(sys)), .arch = cbpf.audit_arch_x86_64, .args = @splat(0) };
        if (try cbpf.runCounting(prog, d, &n) != 0x7fff_0000) return error.NotAllowed;
        sum += n;
        worst = @max(worst, n);
    }
    var n: usize = 0;
    const den: cbpf.Data = .{ .nr = 1023, .arch = cbpf.audit_arch_x86_64, .args = @splat(0) };
    if (try cbpf.runCounting(prog, den, &n) == 0x7fff_0000) return error.DeniedAllowed;
    return .{ .mean = @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(list.len)), .worst = @floatFromInt(worst), .denied = @floatFromInt(n) };
}

const Steps = struct { ref: f64, fastest: f64, fastest_name: []const u8 };

/// Builds the Go and Rust builders' programs when their toolchains are here
/// (`tools/foreign_steps/`; a missing toolchain drops that row, said so),
/// counts every program's cost per syscall and prints the table. `ref`: ours
/// (`buildDefault`) against libseccomp's default layout; `fastest`: ours at
/// its best layout against the cheapest program in the field.
fn stepsTable(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, abs: []const u8, w: *std.Io.Writer) !Steps {
    const Row = struct { name: []const u8, cost: Cost, len: usize, ours: bool };
    var rows: std.ArrayList(Row) = .empty;
    const list = sandbox.seccomp.default_allowlist;
    var rules: std.ArrayList(sandbox.seccomp.Rule) = .empty;
    for (list) |sys| try rules.append(arena, .{ .sysno = sys });
    const ours_default = try sandbox.seccomp.buildDefault(arena, .kill_process);
    const ours_tree = try sandbox.seccomp.buildRulesWith(arena, rules.items, .kill_process, .{ .dispatch = .tree });
    try rows.append(arena, .{ .name = "ours buildDefault", .cost = try cost(ours_default), .len = ours_default.len, .ours = true });
    try rows.append(arena, .{ .name = "ours rules .tree", .cost = try cost(ours_tree), .len = ours_tree.len, .ours = true });
    for ([_][]const u8{ "lib_default.bpf", "lib_tree.bpf" }, [_][]const u8{ "libseccomp default", "libseccomp optimize 2" }) |file, name| {
        const raw = try dir.readFileAlloc(io, file, arena, .limited(1 << 20));
        const p = try cbpf.parseProgram(arena, raw);
        try rows.append(arena, .{ .name = name, .cost = try cost(p), .len = p.len, .ours = false });
    }
    const Foreign = struct { name: []const u8, build: []const []const u8, run: []const u8, input: []const u8 };
    const go_exe = try std.fmt.allocPrint(arena, "{s}/go_steps", .{abs});
    const rs_dir = try std.fmt.allocPrint(arena, "{s}/cargo", .{abs});
    const rs_exe = try std.fmt.allocPrint(arena, "{s}/release/foreign_steps", .{rs_dir});
    const foreign = [_]Foreign{
        .{ .name = "go-seccomp-bpf v1.6.0", .build = &.{ "env", "GOTOOLCHAIN=local", "go", "-C", "modules/sandbox/tools/foreign_steps/go", "build", "-o", go_exe, "." }, .run = go_exe, .input = "names.txt" },
        .{ .name = "seccompiler 0.5.0", .build = &.{ "cargo", "build", "--quiet", "--release", "--locked", "--manifest-path", "modules/sandbox/tools/foreign_steps/rust/Cargo.toml", "--target-dir", rs_dir }, .run = rs_exe, .input = "allow.txt" },
    };
    for (foreign) |f| {
        const b = std.process.run(arena, io, .{ .argv = f.build }) catch |e| {
            try w.print("steps: {s} not measured (build: {t})\n", .{ f.name, e });
            continue;
        };
        if (b.term != .exited or b.term.exited != 0) {
            try w.print("steps: {s} not measured (build failed)\n{s}\n", .{ f.name, b.stderr });
            continue;
        }
        const out_name = try std.fmt.allocPrint(arena, "{s}.bpf", .{f.name[0..2]});
        const in_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ abs, f.input });
        const out_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ abs, out_name });
        const r = try std.process.run(arena, io, .{ .argv = &.{ f.run, in_path, out_path } });
        if (r.term != .exited or r.term.exited != 0) {
            try w.print("steps: {s} not measured (run failed)\n{s}\n", .{ f.name, r.stderr });
            continue;
        }
        const p = try cbpf.parseProgram(arena, try dir.readFileAlloc(io, out_name, arena, .limited(1 << 20)));
        try rows.append(arena, .{ .name = f.name, .cost = try cost(p), .len = p.len, .ours = false });
    }
    try w.print("BPF instructions per syscall (the default allow-list, {d} syscalls; a classic-BPF interpreter with the kernel checker's rules):\n", .{list.len});
    try w.print("  {s:<24} {s:>6} {s:>8} {s:>6} {s:>7}\n", .{ "program", "length", "allowed", "worst", "denied" });
    for (rows.items) |r| try w.print("  {s:<24} {d:>6} {d:>8.1} {d:>6.0} {d:>7.0}\n", .{ r.name, r.len, r.cost.mean, r.cost.worst, r.cost.denied });
    var best_ours: ?Row = null;
    var best_field: ?Row = null;
    for (rows.items) |r| {
        const slot = if (r.ours) &best_ours else &best_field;
        if (slot.* == null or r.cost.mean < slot.*.?.cost.mean) slot.* = r;
    }
    const ref = Cost.ratio(rows.items[0].cost, rows.items[2].cost);
    const fastest = Cost.ratio(best_ours.?.cost, best_field.?.cost);
    try w.print("steps: ours buildDefault / libseccomp default = {d:.3}; {s} / fastest ({s}) = {d:.3} (worst of allowed mean, worst, denied)\n", .{ ref, best_ours.?.name, best_field.?.name, fastest });
    try w.flush();
    return .{ .ref = ref, .fastest = fastest, .fastest_name = best_field.?.name };
}
