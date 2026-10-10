// SPDX-License-Identifier: MIT

//! Comparative benchmark: `brotli` against google/brotli's C library (the
//! reference, libbrotlienc / libbrotlidec), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-brotli` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `zig` on PATH (it
//! builds `tools/c_bench/foreign_bench.c` with `zig cc -O3 -march=native`) and
//! the system google/brotli (`libbrotlienc.so.1`, `libbrotlidec.so.1`,
//! `libbrotlicommon.so.1`, headers in /usr/include/brotli; paths below or
//! `LIBBROTLI_DIR`). Run from the repository root.
//!
//! Payloads (what an HTTP server precompresses or inflates), written into
//! `.zig-cache/bench-brotli/` from fixed seeds: `json` (~128 KiB array of
//! API-style records), `html` (~128 KiB page: shell + repeated table rows and
//! text), `text` (the 152 KB English prose `src/testdata/alice29.txt`).
//!
//! Workloads: `c_<effort>_<payload>` compresses the payload (ours: `compressWith`
//! at that effort; theirs: `BrotliEncoderCompress` at the paired quality, lgwin
//! 22), `d_<payload>` decompresses the stream the reference made at quality 9
//! (ours: `decompress`, allocating its output per call as an HTTP client does;
//! theirs: `BrotliDecoderDecompress` into a preallocated buffer). The reported
//! count is the UNCOMPRESSED bytes covered, so it agrees on both sides.
//!
//! ⚠ The two encoders do not reach the same compressed size. The effort ↔
//! quality pairing in `pairs` below is chosen by compressed size (the closest
//! reference quality on average over the payloads, printed before timing) so a
//! ratio compares like with like; the size ratio itself is printed per
//! workload and belongs next to the speed ratio when reading the result.
//!
//! Method (shared driver at the bottom): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them (they do not
//! move with the clock), else by wall time. Before timing anything our decoder
//! must reproduce each payload from the reference's stream. Arguments filter
//! workloads by substring (no card line then).

const std = @import("std");
const brotli = @import("brotli");

const bench_name = "bench-brotli";
const work_dir = ".zig-cache/bench-brotli";
const default_lib_dir = "/usr/lib/x86_64-linux-gnu";
const payload_names = [_][]const u8{ "json", "html", "text" };

/// Our effort ↔ the reference quality it is compared with (see header).
const pairs = [_]struct { effort: brotli.Effort, quality: u8 }{
    .{ .effort = .fast, .quality = 4 },
    .{ .effort = .default, .quality = 6 },
    .{ .effort = .best, .quality = 9 },
};

const Op = struct { decompress: bool, effort: brotli.Effort, payload: usize };

const Ctx = struct {
    gpa: std.mem.Allocator,
    inputs: [payload_names.len][]u8,
    ref_br: [payload_names.len][]u8,
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    const i = x.op.payload;
    if (x.op.decompress) {
        const out = brotli.decompress(x.gpa, x.ref_br[i], .{}) catch unreachable;
        defer x.gpa.free(out);
        std.mem.doNotOptimizeAway(out.ptr);
        return out.len;
    }
    const out = brotli.compressWith(x.gpa, x.inputs[i], .{ .effort = x.op.effort }) catch unreachable;
    defer x.gpa.free(out);
    std.mem.doNotOptimizeAway(out.ptr);
    return x.inputs[i].len;
}

const words = [_][]const u8{ "order", "customer", "invoice", "shipment", "warehouse", "payment", "refund", "account", "status", "pending", "active", "archived", "north", "south", "east", "west", "premium", "standard", "express", "ground" };

fn genJson(arena: std.mem.Allocator, r: std.Random) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeAll("{\"data\":[");
    var i: usize = 0;
    while (out.written().len < 128 * 1024) : (i += 1) {
        if (i > 0) try w.writeAll(",");
        try w.print("{{\"id\":{d},\"uuid\":\"{x:0>8}-{x:0>4}-{x:0>4}-{x:0>4}-{x:0>12}\",\"name\":\"{s} {s} {d}\",\"status\":\"{s}\",\"email\":\"user{d}@example.com\",\"balance\":{d}.{d:0>2},\"tags\":[\"{s}\",\"{s}\"],\"created_at\":\"2026-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:00Z\",\"active\":{s}}}", .{
            1000 + i,                                r.int(u32),                              r.int(u16),                              r.int(u16),                       r.int(u16),                  r.int(u48),
            words[r.uintLessThan(usize, words.len)], words[r.uintLessThan(usize, words.len)], r.uintLessThan(u32, 500),                words[r.uintLessThan(usize, 12)], r.uintLessThan(u32, 100000), r.uintLessThan(u32, 90000),
            r.uintLessThan(u32, 100),                words[r.uintLessThan(usize, words.len)], words[r.uintLessThan(usize, words.len)], 1 + r.uintLessThan(u32, 12),      1 + r.uintLessThan(u32, 28), r.uintLessThan(u32, 24),
            r.uintLessThan(u32, 60),                 if (r.boolean()) "true" else "false",
        });
    }
    try w.print("],\"total\":{d}}}", .{i});
    return out.toOwnedSlice();
}

fn genHtml(arena: std.mem.Allocator, r: std.Random) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeAll("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Orders overview</title>\n<link rel=\"stylesheet\" href=\"/static/app.css\"><script src=\"/static/app.js\" defer></script></head>\n<body class=\"layout\"><header><nav class=\"main-nav\"><ul><li><a href=\"/\">Home</a></li><li><a href=\"/orders\">Orders</a></li><li><a href=\"/customers\">Customers</a></li><li><a href=\"/reports\">Reports</a></li></ul></nav></header>\n<main><h1>Orders overview</h1><table class=\"data-table\"><thead><tr><th>Id</th><th>Customer</th><th>Status</th><th>Total</th><th>Note</th></tr></thead><tbody>\n");
    var i: usize = 0;
    while (out.written().len < 128 * 1024) : (i += 1) {
        try w.print("<tr class=\"row {s}\" data-id=\"{d}\"><td><a href=\"/orders/{d}\">#{d}</a></td><td>{s} {s}</td><td><span class=\"badge badge-{s}\">{s}</span></td><td class=\"num\">{d}.{d:0>2}</td><td>Shipped via {s} from the {s} {s}; see <em>{s}</em> for details.</td></tr>\n", .{
            words[r.uintLessThan(usize, 20)],        10000 + i,                               10000 + i,                               10000 + i,
            words[r.uintLessThan(usize, words.len)], words[r.uintLessThan(usize, words.len)], words[r.uintLessThan(usize, 12)],        words[r.uintLessThan(usize, 12)],
            r.uintLessThan(u32, 90000),              r.uintLessThan(u32, 100),                words[r.uintLessThan(usize, words.len)], words[r.uintLessThan(usize, words.len)],
            words[r.uintLessThan(usize, words.len)], words[r.uintLessThan(usize, words.len)],
        });
    }
    try w.writeAll("</tbody></table></main><footer><p>&copy; 2026 Example Corp. All rights reserved.</p></footer></body></html>\n");
    return out.toOwnedSlice();
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

    var prng = std.Random.DefaultPrng.init(0xb207_11b3);
    const r = prng.random();
    var ctx: Ctx = undefined;
    ctx.gpa = std.heap.smp_allocator;
    ctx.inputs[0] = try genJson(arena, r);
    ctx.inputs[1] = try genHtml(arena, r);
    ctx.inputs[2] = try cwd.readFileAlloc(io, "modules/brotli/src/testdata/alice29.txt", arena, .limited(1 << 22));
    for (payload_names, 0..) |n, i|
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}.bin", .{n}), .data = ctx.inputs[i] });

    const lib_dir = init.environ_map.get("LIBBROTLI_DIR") orelse default_lib_dir;
    const libs = [_][]const u8{
        try std.fmt.allocPrint(arena, "{s}/libbrotlienc.so.1", .{lib_dir}),
        try std.fmt.allocPrint(arena, "{s}/libbrotlidec.so.1", .{lib_dir}),
        try std.fmt.allocPrint(arena, "{s}/libbrotlicommon.so.1", .{lib_dir}),
    };
    const exe = try buildForeign(arena, io, abs, "modules/brotli/tools/c_bench/foreign_bench.c", &libs);

    // Reference streams (quality 9) and every quality's size, then interop.
    const prep = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, "prep" } });
    if (prep.term != .exited or prep.term.exited != 0) {
        std.debug.print("{s}: foreign prep failed:\n{s}\n", .{ bench_name, prep.stderr });
        return 1;
    }
    std.debug.print("reference compressed sizes (lgwin 22):\n{s}", .{prep.stdout});
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.writeAll("our compressed sizes:\n");
    for (payload_names, 0..) |n, i| {
        const rb = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "{s}.ref.br", .{n}), arena, .limited(1 << 24));
        ctx.ref_br[i] = rb;
        const back = try brotli.decompress(arena, rb, .{});
        if (!std.mem.eql(u8, back, ctx.inputs[i])) {
            std.debug.print("{s}: FAILED -- our decoder does not reproduce {s} from the reference stream\n", .{ bench_name, n });
            return 1;
        }
        try w.print("  {s} ({d} B):", .{ n, ctx.inputs[i].len });
        inline for (@typeInfo(brotli.Effort).@"enum".fields) |f| {
            const e: brotli.Effort = @enumFromInt(f.value);
            const c = try brotli.compressWith(arena, ctx.inputs[i], .{ .effort = e });
            const rt = try brotli.decompress(arena, c, .{});
            if (!std.mem.eql(u8, rt, ctx.inputs[i])) return error.RoundTrip;
            try w.print("  {s} {d}", .{ f.name, c.len });
        }
        try w.writeAll("\n");
    }
    try w.flush();

    var ws: std.ArrayList(Work) = .empty;
    for (payload_names, 0..) |n, i| {
        for (pairs) |p| {
            const name = try std.fmt.allocPrint(arena, "c_{s}_{s}", .{ @tagName(p.effort), n });
            const ref = try std.fmt.allocPrint(arena, "c{d}_{s}", .{ p.quality, n });
            try ws.append(arena, .{ .name = name, .op = .{ .decompress = false, .effort = p.effort, .payload = i }, .ref = ref });
        }
        const name = try std.fmt.allocPrint(arena, "d_{s}", .{n});
        try ws.append(arena, .{ .name = name, .op = .{ .decompress = true, .effort = .default, .payload = i }, .ref = name });
    }

    const s = try drive(io, arena, &.{exe}, abs, &ctx, ws.items, filters, rounds, w);
    try w.print("reference: {s}\nworst ours/google-brotli = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× google/brotli <version> (C, one-shot) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
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
const Work = struct { name: []const u8, op: Op, ref: []const u8, alt: ?[]const u8 = null, ref_exe: usize = 0, alt_exe: usize = 0 };

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
            ours.add(timeIt(io, cyc, ctx));
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
