// SPDX-License-Identifier: MIT

//! Comparative benchmark: `procrun` against Go `os/exec` (go 1.26.8; the
//! reference) with Rust `std::process` (cargo, std only) as the second
//! candidate for the `fastest` column -- the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-procrun` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `go` (std only,
//! `GOPROXY=off`) and `cargo` (no dependencies; `--locked --offline`, built into
//! `.zig-cache/bench-procrun/target`). Run from the repository root.
//!
//! Every side runs the same child commands, each foreign side in its own
//! process (`tools/go_bench`, `tools/rust_bench`; they time themselves exactly
//! as this side does: double the batch until it takes over 100 ms, best of
//! five; sides alternate for BENCH_ROUNDS (default 3) rounds, each keeping its
//! best). One op = the whole batch. All children are absolute paths
//! (/bin/true, /bin/cat, /usr/bin/head), so no PATH lookup is in the number.
//!
//!   spawn_true         200 x /bin/true, one after the other, stdin/stdout/stderr
//!                      all /dev/null. ours: `run` with `.ignore` x3 (no pumps);
//!                      Go: `Command.Run()` with nil stdio; Rust: `status()`
//!                      with `Stdio::null()` x3. count = clean exits (200)
//!   capture_100m       `head -c 104857600 /dev/zero`, stdout captured whole.
//!                      ours: `run`, cap 128 MiB, stdout pipe drained by a
//!                      thread, stderr `.ignore`; Go: `Output()` (a goroutine
//!                      copies into a bytes.Buffer; nil stderr is kept in a small
//!                      saver); Rust: `output()` (stdout AND stderr piped, one
//!                      poll loop in the calling thread). count = bytes
//!   cat_roundtrip      32 MiB (a fixed byte pattern) through `cat`, stdin body
//!                      in, stdout captured. ours: `run` with `.stdin = .pipe`
//!                      (writer thread + drainer thread); Go: `Stdin =
//!                      bytes.Reader` (goroutine) + `Output()`; Rust: writer
//!                      thread + `wait_with_output()`. count = bytes + the sum of
//!                      the output bytes (the sum and a byte-for-byte check are
//!                      done on the FIRST op only, outside the clock on every
//!                      side; later ops check the length)
//!   capture_small_cap  INFO. The 100 MiB producer with a 1 KiB cap: ours `run`
//!                      with max_output_bytes = 1024 (keeps the prefix, keeps
//!                      draining); Go: StdoutPipe + io.LimitReader(1 KiB), then
//!                      io.Copy(io.Discard); Rust: piped stdout, read_exact(1 KiB),
//!                      then io::copy to io::sink. Not like-for-like (ours
//!                      discards inside the drain thread, the others in the
//!                      caller), hence out of the verdict. count = 1024
//!   concurrent_true    8 threads (goroutines) x 50 x /bin/true, all stdio
//!                      /dev/null; ours: std.Thread each calling `run`. count =
//!                      clean exits (400)
//!
//! The ratios are by wall time (a spawn benchmark's user-mode cycles are mostly
//! the kernel's and the children's). Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const procrun = @import("procrun");
const Work = bench.Work(Op);

const bench_name = "bench-procrun";
const work_dir = ".zig-cache/bench-procrun";
const go_dir = "modules/procrun/tools/go_bench";
const cargo_manifest = "modules/procrun/tools/rust_bench/Cargo.toml";
const gpa = std.heap.smp_allocator;

const big_bytes: usize = 100 << 20;
const cat_bytes: usize = 32 << 20;
const small_cap: usize = 1024;

const Kind = enum { spawn_true, capture_100m, cat_roundtrip, capture_small_cap, concurrent_true };
const Op = struct { kind: Kind };

const Ctx = struct {
    io: std.Io,
    op: Op = undefined,
    cat_input: []u8,
    cat_sum: ?u64 = null,
};

fn runQuiet(io: std.Io) bool {
    var out = procrun.run(gpa, io, .{
        .argv = &.{"/bin/true"},
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }, "") catch return false;
    defer out.deinit(gpa);
    return out.term == .exited and out.term.exited == 0;
}

fn sequentialTrue(io: std.Io, n: usize, hits: *std.atomic.Value(u64)) void {
    for (0..n) |_| {
        if (runQuiet(io)) _ = hits.fetchAdd(1, .monotonic);
    }
}

fn fail(what: []const u8, e: anyerror) noreturn {
    std.debug.panic("{s}: {s} failed: {t}", .{ bench_name, what, e });
}

fn bigProducer(io: std.Io, cap: usize) procrun.Output {
    var digits: [24]u8 = undefined;
    const count_arg = std.fmt.bufPrint(&digits, "{d}", .{big_bytes}) catch unreachable;
    return procrun.run(gpa, io, .{
        .argv = &.{ "/usr/bin/head", "-c", count_arg, "/dev/zero" },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
        .max_output_bytes = cap,
    }, "") catch |e| fail("head", e);
}

fn once(x: *Ctx) usize {
    const io = x.io;
    switch (x.op.kind) {
        .spawn_true => {
            var hits: std.atomic.Value(u64) = .init(0);
            sequentialTrue(io, 200, &hits);
            return hits.load(.monotonic);
        },
        .capture_100m => {
            var out = bigProducer(io, 128 << 20);
            defer out.deinit(gpa);
            return out.stdout.len;
        },
        .cat_roundtrip => {
            var out = procrun.run(gpa, io, .{
                .argv = &.{"/bin/cat"},
                .stdin = .pipe,
                .stdout = .pipe,
                .stderr = .ignore,
                .max_output_bytes = 64 << 20,
            }, x.cat_input) catch |e| fail("cat", e);
            defer out.deinit(gpa);
            if (out.stdout.len != x.cat_input.len) std.debug.panic("{s}: cat returned {d} bytes", .{ bench_name, out.stdout.len });
            if (x.cat_sum == null) {
                if (!std.mem.eql(u8, out.stdout, x.cat_input)) @panic("cat output differs");
                var s: u64 = 0;
                for (out.stdout) |b| s += b;
                x.cat_sum = s;
            }
            return out.stdout.len + x.cat_sum.?;
        },
        .capture_small_cap => {
            var out = bigProducer(io, small_cap);
            defer out.deinit(gpa);
            if (!out.truncated_stdout) @panic("expected a truncated capture");
            return out.stdout.len;
        },
        .concurrent_true => {
            var hits: std.atomic.Value(u64) = .init(0);
            var threads: [8]std.Thread = undefined;
            for (&threads) |*t| t.* = std.Thread.spawn(.{}, sequentialTrue, .{ io, 50, &hits }) catch |e| fail("thread spawn", e);
            for (threads) |t| t.join();
            return hits.load(.monotonic);
        },
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

    const input = try arena.alloc(u8, cat_bytes);
    for (input, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    var ctx: Ctx = .{ .io = io, .cat_input = input };

    const go_exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });

    var env = try init.environ_map.clone(arena);
    const target = try arena.print("{s}/target", .{abs});
    try env.put("CARGO_TARGET_DIR", target);
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const built = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", cargo_manifest },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return 1;
    };
    if (built.term != .exited or built.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, built.stderr });
        return 1;
    }
    const rust_exe = try arena.print("{s}/release/rust_bench", .{target});

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;

    var ws: std.ArrayList(Work) = .empty;
    for (std.enums.values(Kind)) |k| {
        try ws.append(arena, .{
            .name = @tagName(k),
            .op = .{ .kind = k },
            .ref = @tagName(k),
            .alt = @tagName(k),
            .ref_exe = 0,
            .alt_exe = 1,
            .info = k == .capture_small_cap,
            .wall_only = true,
        });
    }

    const s = bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ go_exe, rust_exe }, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("reference: {s}\nalt: {s}\nworst ours/go = {d:.3} (best {d:.3})", .{ std.mem.trimEnd(u8, s.banner, "\n"), std.mem.trimEnd(u8, s.alt_banner, "\n"), s.worst_ref, s.best_ref });
    if (s.worst_fast) |wf| try w.print("; worst ours/min(go, rust) = {d:.3}", .{wf});
    try w.writeByte('\n');
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go os/exec 1.26.8 · fastest {d:.2}× worst vs the faster of Go os/exec 1.26.8 and Rust std::process 1.93.1 (measured 2026-10-20)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0 });
    try w.flush();
    return 0;
}
