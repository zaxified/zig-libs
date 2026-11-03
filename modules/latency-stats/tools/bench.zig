// SPDX-License-Identifier: MIT

//! Comparative benchmark: `latency-stats`' `Histogram` against the three
//! serious HdrHistogram implementations, the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-latency-stats [-- args]`
//! runs it (always ReleaseFast); `zig build check-interop` compiles it. Run
//! from the repository root. CPU-bound loops only.
//!
//! The candidates (all with the same config: lowest 1, highest 3.6e12,
//! 3 significant figures, u64/i64 counts, no resize, no atomics):
//!   c     HdrHistogram_c 0.11.10 (CC0 / BSD-2-Clause), `hdr_histogram.c`
//!         built from the pinned release tarball with `cc -O3 -march=native`
//!         (needs `HDRHISTOGRAM_C_DIR`, see tools/README.md)
//!   rust  `hdrhistogram` 7.6.0 (MIT OR Apache-2.0), default features off,
//!         lto fat (`cargo build --release --locked --offline`)
//!   go    `hdrhistogram-go` v1.4.0 (MIT), `go build`
//! Default: reference = c, alt (fastest candidate) = rust; `--ref=c|rust|go`
//! and `--alt=c|rust|go|none` choose another pair (the card's fastest is the
//! quickest of the three per row, found by running the pairs).
//!
//! One op = 100000 fixed-seed values (log-uniform 100 us .. 100 ms, 1 % in
//! 1-3 s; `values.bin` written here, read by every foreign side):
//!   record            reset, then record every value (count = total_count)
//!   record_corrected  reset, then record every value with coordinated-omission
//!                     correction at a 1 ms expected interval (about 1.1 M
//!                     recorded samples; ours batches a run of synthetic
//!                     samples per counts slot, the three others record one
//!                     by one -- same result, checked by the count)
//!   percentiles       1000 value-at-percentile queries at ranks whose
//!                     round-half-up and ceil agree (so every candidate asks
//!                     for the same rank), count = sum of the values
//!   merge             reset a histogram, record one sample (1) into it, add a
//!                     populated one (a real add of every counts slot)
//!   merge_empty       reset a histogram, add a populated one into the empty
//!                     one (the Rust crate and, since 2026-11-02, this module
//!                     copy the counts instead of adding; C and Go add)
//!   mean_stddev       mean and standard deviation of the distribution
//! The Welford `Accumulator` and `compute` (the other half of the module) have
//! no serious foreign library: ping/fping print the same numbers from a few
//! lines of C, and pairing them with a toy would measure nothing, so they are
//! not benchmarked. Wire interop (HdrHistogram V2 compressed) is checked
//! against C and Go before any timing; Rust's crate is built without its
//! serialization feature.
//!
//! Method (`testkit.bench`): each side doubles its batch until it takes over
//! 100 ms and keeps the best of five; the sides alternate for `BENCH_ROUNDS`
//! (default 3) rounds, each keeping its best. The foreign sides count no
//! cycles, so ratios are by wall time. A count that differs between sides
//! fails the run. `-Djcc-safe` (`BENCH_JCC_SAFE`) builds the C and Rust sides
//! with the Intel JCC-erratum padding too; Go's assembler pads by default.

const std = @import("std");
const bench = @import("testkit").bench;
const ls = @import("latency-stats");

// Like this collection's libc-free executables (qap's), the driver installs
// fastmem's memset/memcpy: Zig's compiler_rt memset is byte-wise, and `reset`
// (a 184 KB memset here) and `merge` would otherwise measure that, not the
// module. Stated on the card.
comptime {
    @import("fastmem").exportSymbols();
}

const bench_name = "bench-latency-stats";
const work_dir = ".zig-cache/bench-latency-stats";
const go_dir = "modules/latency-stats/tools/go_bench";
const c_src = "modules/latency-stats/tools/c_bench/foreign_bench.c";
const rust_manifest = "modules/latency-stats/tools/rust_bench/Cargo.toml";
const default_c_dir = ".zig-cache/hdrhistogram-c-0.11.10";

const highest: u64 = 3_600_000_000_000;
const n_values = 100_000;
const interval: u64 = 1_000_000;

const Op = enum { record, record_corrected, percentiles, merge, merge_empty, mean_stddev };
const Work = bench.Work(Op);

const Ctx = struct {
    op: Op = .record,
    vals: []const u64,
    h: *ls.Histogram,
    src: *const ls.Histogram,
};

fn once(c: *Ctx) u64 {
    switch (c.op) {
        .record => {
            c.h.reset();
            for (c.vals) |v| c.h.record(v);
            return c.h.totalCount();
        },
        .record_corrected => {
            c.h.reset();
            for (c.vals) |v| c.h.recordCorrected(v, interval);
            return c.h.totalCount();
        },
        .percentiles => {
            var sum: u64 = 0;
            for (0..1000) |j| sum +%= c.src.valueAtPercentile((100.0 * @as(f64, @floatFromInt(j)) + 0.7) / 1000.0);
            return sum;
        },
        .merge => {
            c.h.reset();
            c.h.record(1);
            c.h.add(c.src) catch unreachable;
            return c.h.totalCount();
        },
        .merge_empty => {
            c.h.reset();
            c.h.add(c.src) catch unreachable;
            return c.h.totalCount();
        },
        .mean_stddev => {
            return @as(u64, @intFromFloat(c.src.mean())) + @as(u64, @intFromFloat(c.src.stdDev()));
        },
    }
}

fn makeValues(arena: std.mem.Allocator) ![]u64 {
    var prng = std.Random.DefaultPrng.init(0x6c61746e63792d73);
    const r = prng.random();
    const vals = try arena.alloc(u64, n_values);
    for (vals) |*v| {
        if (r.uintLessThan(u32, 100) == 0) {
            v.* = 1_000_000_000 + r.uintLessThan(u64, 2_000_000_000);
        } else {
            const u = r.float(f64);
            v.* = @intFromFloat(100_000.0 * std.math.pow(f64, 10.0, 3.0 * u));
        }
    }
    return vals;
}

const Cand = enum { c, rust, go };

fn parseCand(s: []const u8) ?Cand {
    return std.meta.stringToEnum(Cand, s);
}

fn run(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8, env: ?*const std.process.Environ.Map) !void {
    const res = std.process.run(arena, io, .{ .argv = argv, .environ_map = env }) catch |e| {
        std.debug.print("{s}: could not run {s} ({t})\n", .{ bench_name, argv[0], e });
        return error.BuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed:\n{s}\n", .{ bench_name, argv[0], res.stderr });
        return error.BuildFailed;
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    var ref_c: Cand = .c;
    var alt_c: ?Cand = .rust;
    var filter_list: std.ArrayList([:0]const u8) = .empty;
    for (args[1..]) |a| {
        if (std.mem.startsWith(u8, a, "--ref=")) {
            ref_c = parseCand(a[6..]) orelse return error.BadArgument;
        } else if (std.mem.startsWith(u8, a, "--alt=")) {
            alt_c = if (std.mem.eql(u8, a[6..], "none")) null else (parseCand(a[6..]) orelse return error.BadArgument);
        } else try filter_list.append(arena, a);
    }
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;
    const jcc_safe = init.environ_map.get("BENCH_JCC_SAFE") != null;

    const vals = try makeValues(arena);
    try dir.writeFile(io, .{ .sub_path = "values.bin", .data = std.mem.sliceAsBytes(vals) });

    // Our side.
    var src = try ls.Histogram.init(arena, .{ .highest = highest, .sigfigs = 3 });
    for (vals) |v| src.record(v);
    var h = try ls.Histogram.init(arena, .{ .highest = highest, .sigfigs = 3 });

    // The foreign sides, built once, offline.
    const c_dir = init.environ_map.get("HDRHISTOGRAM_C_DIR") orelse default_c_dir;
    const c_exe = try arena.print("{s}/c_bench", .{abs});
    {
        std.debug.print("{s}: building the C side from {s} ...\n", .{ bench_name, c_dir });
        const inc = try arena.print("-I{s}/include", .{c_dir});
        const lib = try arena.print("{s}/src/hdr_histogram.c", .{c_dir});
        const lib_log = try arena.print("{s}/src/hdr_histogram_log.c", .{c_dir});
        const lib_enc = try arena.print("{s}/src/hdr_encoding.c", .{c_dir});
        const lib_time = try arena.print("{s}/src/hdr_time.c", .{c_dir});
        const src_dir = try arena.print("-I{s}/src", .{c_dir});
        try run(arena, io, &.{
            "cc",    "-O3",   "-march=native", if (jcc_safe) "-Wa,-mbranches-within-32B-boundaries" else "-DNO_JCC_PADDING",
            inc,     src_dir, c_src,           lib,
            lib_log, lib_enc, lib_time,        "-lz",
            "-lm",   "-o",    c_exe,
        }, null);
    }
    var cenv = try init.environ_map.clone(arena);
    try cenv.put("RUSTFLAGS", if (jcc_safe) "-C target-cpu=native -C llvm-args=-x86-branches-within-32B-boundaries" else "-C target-cpu=native");
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    try run(arena, io, &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", rust_manifest }, &cenv);
    const rust_exe = "modules/latency-stats/tools/rust_bench/target/release/latency_stats_rust_bench";
    const go_exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });

    // Interop before timing: C and Go decode what we encode (exactly our
    // counts), and we decode what each of them encodes.
    {
        var aw: std.Io.Writer.Allocating = .init(arena);
        try ls.wire.encodeCompressed(&src, arena, &aw.writer);
        const b64 = std.base64.standard.Encoder;
        const text = try arena.alloc(u8, b64.calcSize(aw.written().len));
        _ = b64.encode(text, aw.written());
        try dir.writeFile(io, .{ .sub_path = "ours.b64", .data = text });
        try bench.foreignOnce(arena, io, bench_name, c_exe, abs, "interop");
        try bench.foreignOnce(arena, io, bench_name, go_exe, abs, "interop");
        for ([_][]const u8{ "c.b64", "go.b64" }) |theirs| {
            const t = try dir.readFileAlloc(io, theirs, arena, .limited(1 << 22));
            const dec = std.base64.standard.Decoder;
            const raw = try arena.alloc(u8, try dec.calcSizeForSlice(std.mem.trimEnd(u8, t, "\r\n ")));
            try dec.decode(raw, std.mem.trimEnd(u8, t, "\r\n "));
            const got = ls.wire.decode(arena, raw, .{}) catch |e| {
                std.debug.print("{s}: FAILED -- cannot decode {s} ({t})\n", .{ bench_name, theirs, e });
                return 1;
            };
            if (!std.mem.eql(u64, got.counts, src.counts) or got.totalCount() != src.totalCount()) {
                std.debug.print("{s}: FAILED -- {s} decodes to a different histogram\n", .{ bench_name, theirs });
                return 1;
            }
        }
        std.debug.print("{s}: wire interop OK (C and Go decode ours exactly; we decode theirs exactly)\n", .{bench_name});
    }

    const exes = [_][]const u8{ c_exe, rust_exe, go_exe };
    const names = [_][]const u8{ "HdrHistogram_c 0.11.10", "hdrhistogram 7.6.0 (Rust)", "hdrhistogram-go v1.4.0" };
    const ops = [_]struct { op: Op, wl: []const u8 }{
        .{ .op = .record, .wl = "record" },
        .{ .op = .record_corrected, .wl = "record_corrected" },
        .{ .op = .percentiles, .wl = "percentiles" },
        .{ .op = .merge, .wl = "merge" },
        .{ .op = .merge_empty, .wl = "merge_empty" },
        .{ .op = .mean_stddev, .wl = "mean_stddev" },
    };
    var ws: std.ArrayList(Work) = .empty;
    for (ops) |o| try ws.append(arena, .{
        .name = o.wl,
        .op = o.op,
        .ref = o.wl,
        .alt = if (alt_c != null) o.wl else null,
        .ref_exe = @backingInt(ref_c),
        .alt_exe = if (alt_c) |a| @backingInt(a) else 0,
    });

    var ctx: Ctx = .{ .vals = vals, .h = &h, .src = &src };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &exes, .abs = abs, .filters = filter_list.items, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s} ({s})\nalt: {s}\nworst ours/ref = {d:.3} (best {d:.3}), worst ours/min(ref,alt) = {d:.3}\n", .{
        names[@backingInt(ref_c)],
        std.mem.trimEnd(u8, s.banner, "\n"),
        if (alt_c) |a| names[@backingInt(a)] else "none",
        s.worst_ref,
        s.best_ref,
        s.worst_fast orelse 0,
    });
    try w.flush();
    return 0;
}
