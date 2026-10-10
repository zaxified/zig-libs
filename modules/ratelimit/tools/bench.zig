// SPDX-License-Identifier: MIT

//! Comparative benchmark: `ratelimit` against golang.org/x/time v0.15.0 `rate`
//! (the reference), the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-ratelimit` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! golang.org/x/time in the module cache (pinned by `tools/go_bench/go.mod` /
//! `go.sum`, the same version the xrate vector capture pins; `GOPROXY=off`).
//! Run from the repository root.
//!
//! Workloads -- a sequence of 4096 requests (1024 client keys drawn at random,
//! fixed seed, 37 us apart); the clock is injected on both sides (ours
//! `allowAt`, Go's `AllowN(t, 1)`), so neither pays for reading it. One op =
//! the whole sequence. Every pass starts one second after the previous one and
//! buckets refill in far less, so each pass answers identically (count =
//! requests allowed, which must agree or the run fails):
//!   bucket  one bucket (20000/s, burst 50, ~28 % denied): ours `TokenBucket`
//!           `allowAt`, Go one `rate.Limiter`
//!   keyed   per-client limiting (5/s, burst 2): ours `Limiter.allowAt` (hash
//!           map + LRU list + idle sweep + key cap), Go the usual
//!           `map[string]*rate.Limiter` under a `sync.Mutex`, a limiter made on
//!           first sight. x/time/rate has no keyed limiter, key cap, LRU or
//!           idle expiry -- ours does more per call, and the ratio says so.
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); per workload the sides alternate for BENCH_ROUNDS (default 3)
//! rounds, each keeping its best. Ratios are ours/Go by wall time; the verdict
//! is the WORST ratio. Arguments filter workloads.

const std = @import("std");
const ratelimit = @import("ratelimit");

const bench_name = "bench-ratelimit";
const work_dir = ".zig-cache/bench-ratelimit";
const go_dir = "modules/ratelimit/tools/go_bench";
const ref_short = "Go";
const ref_card = "golang.org/x/time v0.15.0 rate";

const net_base: ?[]const u8 = null;
const info_only = [_][]const u8{};
const names = [_][]const u8{ "bucket", "keyed" };
const N = 4096;
const n_keys = 1024;
const bucket_cfg: ratelimit.TokenBucket.Config = .{ .rate_per_s = 20000, .burst = 50 };
const keyed_rate = 5.0;
const keyed_burst = 2;
const t0: u64 = 1_000_000_000_000;

const Data = struct {
    keys: [n_keys][]const u8,
    idx: [N]u16,
    at: [N]u64,
    bucket: ratelimit.TokenBucket,
    limiter: *ratelimit.Limiter,
};

var pass: u64 = 0;

fn once(d_const: *const Data, w: usize) u64 {
    const d: *Data = @constCast(d_const);
    pass += 1;
    const base = t0 + pass * std.time.ns_per_s;
    var n: u64 = 0;
    if (w == 0) {
        for (d.at) |a| {
            if (d.bucket.allowAt(bucket_cfg, base + a).allowed) n += 1;
        }
    } else {
        for (d.idx, d.at) |i, a| {
            if (d.limiter.allowAt(d.keys[i], base + a).allowed) n += 1;
        }
    }
    return n;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var prng = std.Random.DefaultPrng.init(0x7a7e_11);
    const r = prng.random();
    var d: Data = undefined;
    var fk: std.Io.Writer.Allocating = .init(arena);
    for (0..n_keys) |i| {
        d.keys[i] = try std.fmt.allocPrint(arena, "10.{d}.{d}.{d}", .{ i >> 8, i & 255, (i *% 7) & 255 });
        try fk.writer.print("{s}\n", .{d.keys[i]});
    }
    var fs: std.Io.Writer.Allocating = .init(arena);
    for (0..N) |j| {
        d.idx[j] = r.uintLessThan(u16, n_keys);
        d.at[j] = j * 37_000;
        try fs.writer.print("{d}\t{d}\n", .{ d.idx[j], d.at[j] });
    }
    try dir.writeFile(io, .{ .sub_path = "keys.txt", .data = fk.written() });
    try dir.writeFile(io, .{ .sub_path = "seq.tsv", .data = fs.written() });
    var fc: std.Io.Writer.Allocating = .init(arena);
    try fc.writer.print("{d}\t{d}\t{d}\t{d}\n", .{ bucket_cfg.rate_per_s, bucket_cfg.burst, keyed_rate, keyed_burst });
    try dir.writeFile(io, .{ .sub_path = "cfg.txt", .data = fc.written() });
    d.bucket = .full(bucket_cfg, t0);
    d.limiter = try arena.create(ratelimit.Limiter);
    d.limiter.* = ratelimit.Limiter.init(std.heap.smp_allocator, .{ .rate_per_s = keyed_rate, .burst = keyed_burst, .max_keys = 4096, .key = .forwarded_ip });
    return d;
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
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var d: Data = try setup(arena, io, dir);

    const exe = try goBuild(arena, io, init.environ_map, abs);
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: Side = .{};
        var go: Side = .{};
        for (0..rounds) |_| {
            go.add(try goRun(arena, io, exe, abs, name));
            ours.add(timeIt(io, &d, wi));
        }
        const gross = ours.best_ns / go.best_ns;
        // `net_base` (a workload name): the cost of the HTTP stacks both sides
        // carry is that workload; the module's own ratio is what is left over.
        var net: f64 = std.math.nan(f64);
        if (net_base) |nb| {
            if (std.mem.eql(u8, nb, name)) {
                base_ours = ours.best_ns;
                base_ref = go.best_ns;
            } else if (base_ref != 0 and go.best_ns > base_ref) {
                net = (ours.best_ns - base_ours) / (go.best_ns - base_ref);
            }
        }
        const ratio = if (net_base != null and !std.math.isNan(net)) net else gross;
        const info = for (info_only) |n| {
            if (std.mem.eql(u8, n, name)) break true;
        } else false;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(), go.spread()));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(), 100 * go.spread(), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ " ++ ref_short });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
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

// ---- comparison driver (the same in every stdlib-Go-referenced bench) ----

const Row = struct { ns: f64, count: u64 };

const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    count: u64 = 0,
    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.count = r.count;
    }
    fn spread(s: Side) f64 {
        return s.worst_ns / s.best_ns - 1;
    }
};

fn timeIt(io: std.Io, d: *const Data, w: usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(d, w));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: u64 = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = once(d, w);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

/// Build the Go side once (`go build`), so the timed runs do not pay for it.
fn goBuild(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, abs: []const u8) ![]const u8 {
    var env = try environ.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try std.fmt.allocPrint(arena, "{s}/go_bench", .{abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = go_dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return error.GoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: go build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.GoBuildFailed;
    }
    return exe;
}

/// Run the Go side for one workload: `<exe> <work dir> <name>` prints
/// `name \t ns/op \t count`.
fn goRun(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: Go side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count };
}
