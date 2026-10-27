// SPDX-License-Identifier: MIT

//! The fuzz driver's cost per input against the field, the program behind
//! the `**Performance:**` line of testkit's maturity card (CONVENTIONS.md §9,
//! kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-testkit` runs it (always
//! ReleaseFast). Needs `cargo` (the crates in
//! `tools/proptest_rust/Cargo.lock`, fetched once; read before the first
//! build: four build scripts that only ask `rustc` its version or probe a
//! cfg, no proc macros) and `clang` with its libFuzzer runtime
//! (`libclang_rt.fuzzer_no_main`). Run from the repository root.
//!
//! The property, the same on every side: a byte string of at most 160 bytes
//! mapped to hex digits and decoded (`hex`), or the same plus two heap
//! allocations per input (`alloc`). One op is 10 000 inputs, so every row is
//! the cost of 10 000 inputs:
//! - ours: one `fuzz.driver` call over 10 000 seeds (its set-up, the seed
//!   file mapped, is paid per call as a runner pays it per harness); the
//!   seeds run on from batch to batch as a runner's do. `+seedfile` rows run
//!   it with a seed file, as `MOD_FUZZ_SEEDFILE` -- what a runner always sets.
//! - ref, proptest 1.11.0 (`tools/proptest_rust`): one `TestRunner::run` of
//!   10 000 cases on a fresh runner, the driver's length distribution;
//! - fastest candidate, libFuzzer (`tools/libfuzzer_c`): 10 000 consecutive
//!   inputs of one in-process run, timed from inside its callback, so
//!   mutation and coverage upkeep between inputs count. Its lengths are its
//!   own (`-max_len=160`).
//! Ratios by WALL time on every side: the seed file's cost is kernel time,
//! which user-mode cycles do not count (measured 2026-10-17: 1.43× by
//! cycles, 29× by the clock), and the foreign sides count no cycles.
//!
//! A second table times the driver against a bare seed loop over the same
//! harness -- `DefaultPrng.init(seed)`, an `Rng`, the harness, a
//! `SafeAllocator` over the same backing allocator -- so the ratio is exactly
//! what the driver adds (watchdog timestamps, the seed file, reach
//! bookkeeping). Printed for information; the card quotes the field.

const std = @import("std");
const testkit = @import("testkit");
const bench = testkit.bench;
const driver = testkit.fuzz.driver;

const bench_name = "bench-testkit";
const work_dir = ".zig-cache/bench-testkit";
const batch = 10_000;

fn hexHarness(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var sbuf: [160]u8 = undefined;
    const s = sbuf[0..src.slice(&sbuf)];
    for (s) |*b| b.* = "0123456789abcdef"[b.* & 15];
    var out: [80]u8 = undefined;
    _ = testkit.hex.into(&out, s[0 .. s.len & ~@as(usize, 1)]) catch unreachable;
    std.mem.doNotOptimizeAway(&out);
}

fn allocHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var sbuf: [160]u8 = undefined;
    const s = sbuf[0..src.slice(&sbuf)];
    for (s) |*b| b.* = "0123456789abcdef"[b.* & 15];
    const a = try gpa.alloc(u8, s.len / 2 + 1);
    defer gpa.free(a);
    const c = try gpa.dupe(u8, s);
    defer gpa.free(c);
    _ = try testkit.hex.into(a, c[0 .. c.len & ~@as(usize, 1)]);
    std.mem.doNotOptimizeAway(a);
}

const Op = enum { hex, hex_seedfile, alloc, alloc_seedfile };

const Ctx = struct {
    gpa: std.mem.Allocator,
    seed_fd: ?i32,
    first: u64 = 0,
    op: Op = .hex,
};

/// Our side of a `bench.drive` row: the driver over one batch, the harness
/// and the seed file chosen at comptime.
fn once(x: *Ctx) usize {
    return switch (x.op) {
        .hex => viaDriver(hexHarness, false)(x),
        .hex_seedfile => viaDriver(hexHarness, true)(x),
        .alloc => viaDriver(allocHarness, false)(x),
        .alloc_seedfile => viaDriver(allocHarness, true)(x),
    };
}

fn bare(comptime harness: anytype) fn (*Ctx) usize {
    return struct {
        fn f(x: *Ctx) usize {
            // The allocator a hand-written 0.17 loop hands its harness: one
            // leak-checking `SafeAllocator` for the run, as the driver's
            // (renewed per batch of seeds there).
            var sa: std.heap.SafeAllocator = .init(x.gpa, .{ .stack_trace_frames = 0 });
            defer _ = sa.deinit();
            for (0..batch) |i| {
                var prng = std.Random.DefaultPrng.init(x.first + i);
                var rng: testkit.fuzz.Rng = .{ .r = prng.random() };
                harness(testkit.fuzz.Rng, &rng, sa.allocator()) catch unreachable;
            }
            x.first += batch;
            return batch;
        }
    }.f;
}

fn viaDriver(comptime harness: anytype, comptime with_seedfile: bool) fn (*Ctx) usize {
    return struct {
        fn f(x: *Ctx) usize {
            driver.runSeedsReporting(harness, "bench", .{ .runs = batch, .first = x.first }, x.gpa, if (with_seedfile) x.seed_fd else null, false) catch unreachable;
            x.first += batch;
            return batch;
        }
    }.f;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var da: std.heap.DebugAllocator(.{ .stack_trace_frames = 0 }) = .init; // global-alloc-ok: the same allocator the driver gives a harness, on both sides of the comparison
    defer _ = da.deinit();
    const seed_path = work_dir ++ "/seed";
    const rc = std.os.linux.open(seed_path, .{ .ACCMODE = .RDWR, .CREAT = true, .TRUNC = true }, 0o644);
    const seed_fd: ?i32 = if (std.os.linux.errno(rc) == .SUCCESS) @intCast(rc) else null;
    var ctx: Ctx = .{ .gpa = da.allocator(), .seed_fd = seed_fd };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;

    // The field: proptest (the reference) and libFuzzer (the fastest
    // candidate), with `-Djcc-safe` padded like our side (their prebuilt
    // runtimes, Rust's std and libFuzzer's archive, are not).
    const arena = init.arena.allocator();
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const jcc_safe = init.environ_map.get("BENCH_JCC_SAFE") != null;
    const rs_exe = try buildRust(arena, io, init.environ_map, jcc_safe);
    const lf_exe = try buildLibFuzzer(arena, io, abs, jcc_safe);
    const work = [_]bench.Work(Op){
        .{ .name = "hex", .op = .hex, .ref = "hex", .alt = "hex", .alt_exe = 1, .wall_only = true },
        .{ .name = "hex+seedfile", .op = .hex_seedfile, .ref = "hex", .alt = "hex", .alt_exe = 1, .wall_only = true },
        .{ .name = "alloc", .op = .alloc, .ref = "alloc", .alt = "alloc", .alt_exe = 1, .wall_only = true },
        .{ .name = "alloc+seedfile", .op = .alloc_seedfile, .ref = "alloc", .alt = "alloc", .alt_exe = 1, .wall_only = true },
    };
    try w.print("ns per {d} inputs; ref = proptest, alt = libFuzzer\n", .{batch});
    const f = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ rs_exe, lf_exe }, .abs = abs, .rounds = rounds }, &ctx, once, work, w);
    try w.print("ref:  {s}\nalt:  {s}\n\n", .{ std.mem.trimEnd(u8, f.banner, "\n"), std.mem.trimEnd(u8, f.alt_banner, "\n") });
    try w.flush();

    // name, ours, ref (a comptime tuple: `timeIt` takes the op at comptime)
    const rows = .{
        .{ "hex", viaDriver(hexHarness, false), bare(hexHarness) },
        .{ "hex+seedfile", viaDriver(hexHarness, true), bare(hexHarness) },
        .{ "alloc", viaDriver(allocHarness, false), bare(allocHarness) },
        .{ "alloc+seedfile", viaDriver(allocHarness, true), bare(allocHarness) },
    };

    const cyc: bench.Cycles = .open();
    defer cyc.close();
    var s: bench.Summary = .{};
    try w.writeAll("the driver against a bare seed loop (information, not on the card); ns per input\n");
    try w.print("{s:<16} {s:>12} {s:>12} {s:>7} {s:>6} {s:>6}\n", .{ "workload", "driver ns", "bare ns", "/bare", "spr d", "spr b" });
    inline for (rows) |r| {
        var ours: bench.Side = .{};
        var ref: bench.Side = .{};
        for (0..rounds) |_| {
            ref.add(bench.timeIt(io, cyc, r[2], .{&ctx}, true));
            ours.add(bench.timeIt(io, cyc, r[1], .{&ctx}, true));
        }
        const l = bench.score(ours, ref, null, false);
        s.add(l);
        try w.print("{s:<16} {d:>12.0} {d:>12.0} {d:>7.3} {d:>5.1}% {d:>5.1}%\n", .{ r[0], ours.best_ns / batch, ref.best_ns / batch, l.ref, 100 * ours.spread(l.by_cycles), 100 * ref.spread(l.by_cycles) });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (s.by_cycles) "user-mode cycles" else "wall time", 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× proptest 1.11.0 · fastest {d:.2}× libFuzzer (LLVM, in-process{s}) · driver {d:.2}–{d:.2}× a bare seed loop (measured <today>)\n", .{
        f.best_ref, f.worst_ref, f.worst_fast orelse 0, if (jcc_safe) "; JCC-padded, runtimes prebuilt" else "", s.best_ref, s.worst_ref,
    });
    try w.flush();
    if (seed_fd) |fd| _ = std.os.linux.close(fd);
    return 0;
}

/// `cargo build --release --locked --offline` of `tools/proptest_rust`, for
/// the host CPU like our side.
fn buildRust(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, jcc_safe: bool) ![]const u8 {
    var env = try environ.clone(arena);
    const target_dir = if (jcc_safe) ".zig-cache/proptest_rust-jcc" else ".zig-cache/proptest_rust";
    try env.put("RUSTFLAGS", if (jcc_safe) "-C target-cpu=native -C llvm-args=-x86-branches-within-32B-boundaries" else "-C target-cpu=native");
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", "modules/testkit/tools/proptest_rust/Cargo.toml", "--target-dir", target_dir },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- the reference is proptest\n", .{ bench_name, e });
        return error.RustBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.RustBuildFailed;
    }
    return try arena.print("{s}/release/proptest_bench", .{target_dir});
}

/// `tools/libfuzzer_c` with clang (`zig cc` has no libFuzzer), linked against
/// clang's own `libclang_rt.fuzzer_no_main`.
fn buildLibFuzzer(arena: std.mem.Allocator, io: std.Io, abs: []const u8, jcc_safe: bool) ![]const u8 {
    const rd = std.process.run(arena, io, .{ .argv = &.{ "clang", "-print-resource-dir" } }) catch |e| {
        std.debug.print("{s}: could not run clang ({t}) -- the fastest candidate is libFuzzer\n", .{ bench_name, e });
        return error.ClangMissing;
    };
    const runtime = try arena.print("{s}/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a", .{std.mem.trimEnd(u8, rd.stdout, "\n")});
    const cc: []const []const u8 = if (jcc_safe)
        &.{ "clang", "-fsanitize=fuzzer-no-link", "-mbranches-within-32B-boundaries" }
    else
        &.{ "clang", "-fsanitize=fuzzer-no-link" };
    return bench.buildForeign(arena, io, bench_name, cc, abs, "modules/testkit/tools/libfuzzer_c/libfuzzer_bench.c", &.{ runtime, "-lstdc++", "-lm", "-lpthread" });
}
