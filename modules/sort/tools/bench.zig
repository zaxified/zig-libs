// SPDX-License-Identifier: MIT

//! Comparative benchmark: `sort` against Rust's std (`sort_unstable`, `sort`,
//! `select_nth_unstable` — the reference, the same algorithms) and C++
//! libstdc++ (`std::sort`, `std::stable_sort`, `std::nth_element` — the
//! second implementation in the field). The program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9 kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-sort` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `cargo` (no
//! crates: `tools/rust_bench` uses std only, built with
//! `-C target-cpu=native` like our `-mcpu=native`) and `g++` (`tools/cpp_bench`,
//! `-O3 -march=native`). Run from the repository root. Arguments filter
//! workloads by substring; `BENCH_ROUNDS` (default 3) sets the rounds.
//!
//! A workload is `<alg>_<type>_<pattern>_<n>`. One op = copy the input into a
//! scratch slice, then sort it (or select its middle element). Every side
//! generates the input itself, the same way:
//!
//!   splitmix64, seed 0x5eed, one `next()` per value below, in index order;
//!   pattern  rand  next()          dup16 next() % 16
//!            asc   i               desc  n - i
//!            saw   i % 1000        tail  i < n - n/100 ? i : next()
//!   type     u64   the value       u32   value >> 32 (dup16: value)
//!            rec   {key = value, a = i, b = ~i, c = 3i}, compared by key
//!            str   per element: len = 4 + next() % 21, then len bytes
//!                  'a' + next() % 26 (pattern is always rand); compared as bytes
//!
//! `count` — the sides must agree, or the run fails: for a sort, the sum over
//! every 61st position i of (i + 1) · (the element's key; str: len + first
//! byte; a stable rec sort: its `a`, so the order of equal keys counts); for a
//! select, the key that lands at n / 2. Ratios by user-mode cycles (every
//! side counts them). The sides alternate per round and every round of every
//! side is a fresh process, ours included (`--one`, see `main`).

const std = @import("std");
const sort = @import("sort");
const bench = @import("testkit").bench;

const bench_name = "bench-sort";
const work_dir = ".zig-cache/bench-sort";

const Alg = enum { u, s, sel };
const Ty = enum { u64, u32, rec, str };
const Pat = enum { rand, dup16, asc, desc, saw, tail };
const Op = struct { alg: Alg, ty: Ty, pat: Pat, n: usize };

const Rec = struct { key: u64, a: u64, b: u64, c: u64 };

const names = [_][]const u8{
    // unstable
    "u_u64_rand_1k",     "u_u64_rand_100k",  "u_u64_rand_1m",
    "u_u64_dup16_100k",  "u_u64_asc_100k",   "u_u64_desc_100k",
    "u_u64_saw_100k",    "u_u64_tail_100k",  "u_u32_rand_100k",
    "u_rec_rand_1k",     "u_rec_rand_100k",  "u_str_rand_1k",
    "u_str_rand_100k",
    // stable
      "s_u64_rand_1k",    "s_u64_rand_100k",
    "s_u64_rand_1m",     "s_u64_dup16_100k", "s_u64_asc_100k",
    "s_u64_desc_100k",   "s_u64_saw_100k",   "s_u64_tail_100k",
    "s_u32_rand_100k",   "s_rec_rand_1k",    "s_rec_rand_100k",
    "s_rec_dup16_100k",  "s_str_rand_1k",    "s_str_rand_100k",
    // select the median
    "sel_u64_rand_100k", "sel_u64_rand_1m",  "sel_u64_dup16_1m",
    "sel_u64_asc_1m",
};

fn parseOp(name: []const u8) Op {
    var it = std.mem.tokenizeScalar(u8, name, '_');
    const alg = std.meta.stringToEnum(Alg, it.next().?).?;
    const ty = std.meta.stringToEnum(Ty, it.next().?).?;
    const pat = std.meta.stringToEnum(Pat, it.next().?).?;
    const ns = it.next().?;
    const mult: usize = switch (ns[ns.len - 1]) {
        'k' => 1000,
        'm' => 1_000_000,
        else => unreachable,
    };
    return .{ .alg = alg, .ty = ty, .pat = pat, .n = mult * (std.fmt.parseInt(usize, ns[0 .. ns.len - 1], 10) catch unreachable) };
}

const SplitMix = struct {
    s: u64,
    fn next(r: *SplitMix) u64 {
        r.s +%= 0x9e3779b97f4a7c15;
        var z = r.s;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }
};

fn value(r: *SplitMix, pat: Pat, i: usize, n: usize) u64 {
    return switch (pat) {
        .rand => r.next(),
        .dup16 => r.next() % 16,
        .asc => i,
        .desc => n - i,
        .saw => i % 1000,
        .tail => if (i < n - n / 100) i else r.next(),
    };
}

/// Inputs and scratch for the op being timed.
const Ctx = struct {
    op: Op = undefined,
    gpa: std.mem.Allocator,
    in_u64: []u64 = &.{},
    in_u32: []u32 = &.{},
    in_rec: []Rec = &.{},
    in_str: [][]const u8 = &.{},
    w_u64: []u64 = &.{},
    w_u32: []u32 = &.{},
    w_rec: []Rec = &.{},
    w_str: [][]const u8 = &.{},
    /// The op the inputs were generated for.
    prepared: ?Op = null,
    gen: std.heap.ArenaAllocator,

    /// Generate the inputs when the op changed. `once` calls it, so it runs
    /// in the first (doubling) batch of `bench.timeIt`, never in the five
    /// timed ones.
    fn prepare(c: *Ctx) !void {
        if (c.prepared) |p| if (std.meta.eql(p, c.op)) return;
        _ = c.gen.reset(.free_all);
        const arena = c.gen.allocator();
        const n = c.op.n;
        var r: SplitMix = .{ .s = 0x5eed };
        switch (c.op.ty) {
            .u64 => {
                c.in_u64 = try arena.alloc(u64, n);
                for (c.in_u64, 0..) |*x, i| x.* = value(&r, c.op.pat, i, n);
                c.w_u64 = try arena.alloc(u64, n);
            },
            .u32 => {
                c.in_u32 = try arena.alloc(u32, n);
                for (c.in_u32, 0..) |*x, i| {
                    const v = value(&r, c.op.pat, i, n);
                    x.* = if (c.op.pat == .rand) @intCast(v >> 32) else @intCast(v);
                }
                c.w_u32 = try arena.alloc(u32, n);
            },
            .rec => {
                c.in_rec = try arena.alloc(Rec, n);
                for (c.in_rec, 0..) |*x, i| x.* = .{ .key = value(&r, c.op.pat, i, n), .a = i, .b = ~@as(u64, i), .c = 3 *% @as(u64, i) };
                c.w_rec = try arena.alloc(Rec, n);
            },
            .str => {
                c.in_str = try arena.alloc([]const u8, n);
                for (c.in_str) |*s| {
                    const len: usize = @intCast(4 + r.next() % 21);
                    const b = try arena.alloc(u8, len);
                    for (b) |*ch| ch.* = @intCast('a' + r.next() % 26);
                    s.* = b;
                }
                c.w_str = try arena.alloc([]const u8, n);
            },
        }
        c.prepared = c.op;
    }
};

fn lessU64(_: void, a: u64, b: u64) bool {
    return a < b;
}
fn lessU32(_: void, a: u32, b: u32) bool {
    return a < b;
}
fn lessRec(_: void, a: Rec, b: Rec) bool {
    return a.key < b.key;
}
/// The module's byte order: `std.mem.order` is a byte loop (README).
const lessStr = sort.asc([]const u8);

/// Sampled, so that the harness costs little next to a cheap sort (an
/// ascending input sorts in one pass): every 61st position.
const stride = 61;

fn checksum(c: *const Ctx) u64 {
    var k: u64 = 0;
    var i: usize = 0;
    while (i < c.op.n) : (i += stride) {
        const key: u64 = switch (c.op.ty) {
            .u64 => c.w_u64[i],
            .u32 => c.w_u32[i],
            .rec => if (c.op.alg == .s) c.w_rec[i].a else c.w_rec[i].key,
            .str => c.w_str[i].len + c.w_str[i][0],
        };
        k +%= (i + 1) *% key;
    }
    return k;
}

fn sortAs(comptime T: type, alg: Alg, gpa: std.mem.Allocator, w: []T, in: []const T, comptime less: fn (void, T, T) bool) void {
    @memcpy(w, in);
    switch (alg) {
        .u => sort.unstable(T, w, {}, less),
        .s => sort.stable(T, gpa, w, {}, less) catch @panic("bench-sort: out of memory"),
        .sel => sort.selectNth(T, w, w.len / 2, {}, less),
    }
}

fn once(c: *Ctx) u64 {
    c.prepare() catch @panic("bench-sort: out of memory");
    switch (c.op.ty) {
        .u64 => sortAs(u64, c.op.alg, c.gpa, c.w_u64, c.in_u64, lessU64),
        .u32 => sortAs(u32, c.op.alg, c.gpa, c.w_u32, c.in_u32, lessU32),
        .rec => sortAs(Rec, c.op.alg, c.gpa, c.w_rec, c.in_rec, lessRec),
        .str => sortAs([]const u8, c.op.alg, c.gpa, c.w_str, c.in_str, lessStr),
    }
    if (c.op.alg == .sel) return switch (c.op.ty) {
        .u64 => c.w_u64[c.op.n / 2],
        else => unreachable, // only u64 select workloads
    };
    return checksum(c);
}

/// `sort.stable` is timed through its allocating entry point, like Rust's
/// `sort`, which allocates per call. glibc serves Rust's from memory it kept
/// after the first call (its mmap threshold adapts upward), so ours comes
/// from a FixedBufferAllocator, whose free of the last block hands it back:
/// the same steady state. (smp_allocator maps and unmaps 800 KB per call
/// and the page faults cost more than the sort.)
fn timeOne(io: std.Io, name: []const u8) !bench.Row {
    const fba_buf = try std.heap.page_allocator.alloc(u8, 16 << 20);
    var fba: std.heap.FixedBufferAllocator = .init(fba_buf);
    var ctx: Ctx = .{ .gpa = fba.allocator(), .gen = .init(std.heap.page_allocator), .op = parseOp(name) };
    const cyc: bench.Cycles = .open();
    defer cyc.close();
    return bench.timeIt(io, cyc, once, .{&ctx}, false);
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    // `<self> --one <work dir> <workload>`: our side of one round, printed
    // like a foreign side. Every round of every side is a fresh process:
    // where a process's buffers land (ASLR, and with it 4K aliasing between
    // input, items and scratch) moves a small row by up to 15 %, and
    // best-of-rounds over fresh foreign processes against one long-lived
    // process of ours would hand the foreign sides that luck (measured: stable
    // `u64` 1k 0.99× and 1.13× in two runs of the same binary).
    if (args.len == 4 and std.mem.eql(u8, args[1], "--one")) {
        const r = try timeOne(io, args[3]);
        var buf: [256]u8 = undefined;
        var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
        try stdout.interface.print("{s}\t{d}\t{d}\t{d}\n", .{ args[3], r.ns, r.cycles, r.count });
        try stdout.interface.flush();
        return 0;
    }

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const self = try cwd.realPathFileAlloc(io, args[0], arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    // BENCH_JCC_SAFE=1: the foreign sides built with the Intel JCC-erratum
    // mitigation (no jump crossing or ending on a 32-byte boundary), for a
    // run of THIS program built the same way (tools/README.md). On a CPU
    // with the erratum fix (Skylake..Coffee Lake) layout luck alone moves a
    // row by up to 25 % otherwise (measured here: stable `rec` 1k 0.98× in
    // one build, 1.25× in the next, same source).
    const jcc_safe = if (init.environ_map.get("BENCH_JCC_SAFE")) |v| std.mem.eql(u8, v, "1") else false;
    const rust = buildRust(arena, io, init.environ_map, abs, jcc_safe) catch return 1;
    const cc: []const []const u8 = if (jcc_safe) &.{ "g++", "-std=c++20", "-Wa,-mbranches-within-32B-boundaries" } else &.{ "g++", "-std=c++20" };
    const cpp = bench.buildForeign(arena, io, bench_name, cc, abs, "modules/sort/tools/cpp_bench/main.cpp", &.{}) catch return 1;

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<18} {s:>11} {s:>11} {s:>11} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "ref ns", "alt ns", "/ref", "/fast", "spr us", "spr rf", "spr al" });
    try w.flush();
    var sum: bench.Summary = .{};
    for (names) |name| {
        if (!bench.selected(name, filters)) continue;
        var ours: bench.Side = .{};
        var ref: bench.Side = .{};
        var alt: bench.Side = .{};
        for (0..rounds) |_| {
            ref.add(bench.foreign(arena, io, bench_name, rust, abs, name, &sum.banner) catch return 1);
            ours.add(bench.foreignArgv(arena, io, bench_name, &.{ self, "--one", abs, name }, name, null) catch return 1);
            alt.add(bench.foreign(arena, io, bench_name, cpp, abs, name, &sum.alt_banner) catch return 1);
        }
        const l = bench.score(ours, ref, alt, false);
        sum.add(l);
        const by = l.by_cycles;
        try w.print("{s:<18} {d:>11.0} {d:>11.0} {d:>11.0} {d:>7.3} {d:>7.3} {d:>5.1}% {d:>5.1}% {d:>5.1}%  {d}{s}\n", .{
            name,                  ours.best_ns,         ref.best_ns,          alt.best_ns, l.ref, l.fast,
            100 * ours.spread(by), 100 * ref.spread(by), 100 * alt.spread(by), ours.count,
            if (!l.same_count) " ≠" else "",
        });
        try w.flush();
    }
    try w.print("rounds: {d}, each side a fresh process per round; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (sum.by_cycles) "user-mode cycles" else "wall time", 100 * sum.max_spread, if (sum.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (sum.mismatch) {
        try w.writeAll("bench-sort: FAILED -- an output count differs between the sides\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/ref = {d:.3} (best {d:.3}); worst ours/fastest = {d:.3}\n", .{ sum.worst_ref, sum.best_ref, sum.worst_fast orelse sum.worst_ref });
    try w.print("ref: {s}\nalt: {s}\n", .{ std.mem.trimEnd(u8, sum.banner, "\n"), std.mem.trimEnd(u8, sum.alt_banner, "\n") });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Rust std 1.93.1 · fastest {d:.2}× (measured <today>)\n", .{ sum.best_ref, sum.worst_ref, sum.worst_fast orelse sum.worst_ref });
    try w.flush();
    return 0;
}

const rust_manifest = "modules/sort/tools/rust_bench/Cargo.toml";

/// Build the Rust side offline (std only, `Cargo.lock` committed) for the
/// native CPU, matching our ReleaseFast `-mcpu=native`.
fn buildRust(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, abs: []const u8, jcc_safe: bool) ![]const u8 {
    var env = try environ.clone(arena);
    try env.put("CARGO_NET_OFFLINE", "true");
    try env.put("RUSTFLAGS", if (jcc_safe) "-C target-cpu=native -C llvm-args=-x86-branches-within-32B-boundaries" else "-C target-cpu=native");
    const target = try arena.print("{s}/rust-target{s}", .{ abs, if (jcc_safe) "-jcc" else "" });
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const b = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--locked", "--manifest-path", rust_manifest, "--target-dir", target },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t})\n", .{ bench_name, e });
        return e;
    };
    if (b.term != .exited or b.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, b.stderr });
        return error.RustBuildFailed;
    }
    return arena.print("{s}/release/rust_bench", .{target});
}
