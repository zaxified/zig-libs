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
//! text), `text` (the 152 KB English prose `src/testdata/alice29.txt`),
//! `font` (200 KB of binary data shaped like a TrueType font,
//! `interop_corpus.fontLike` — R12: binary data with sections).
//!
//! Workloads: `c_<effort>_<payload>` compresses the payload (ours: `compressWith`
//! at that effort; theirs: `BrotliEncoderCompress` at the paired quality, lgwin
//! 22), `d_<payload>` decompresses the stream the reference made at quality 9
//! into a preallocated buffer of the payload size + 1 on both sides (ours:
//! `decompressInto`; theirs: `BrotliDecoderDecompress`); `d_<payload>_alloc`
//! is ours allocating its output per call, as `decompress` does for an HTTP
//! client -- printed for information, not in the verdict, since the
//! reference has no such call to pair it with. The reported
//! count is the UNCOMPRESSED bytes covered, so it agrees on both sides.
//!
//! Pairing: `.qN` stands in for google/brotli quality N (`Effort`), so
//! `c_qN_<payload>` is timed against `cN_<payload>` (since 2026-10-15; before,
//! each effort was paired with the quality closest in size, recomputed every
//! run, because the levels had names of their own). The streams are not
//! byte-identical, so the sizes are printed beside the reference's and the
//! quality closest in size is printed too: a level whose closest quality is
//! not its own is a ratio finding, not a pairing to change.
//!
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Ratios
//! are ours/theirs by user-mode cycles when both sides count them (they do not
//! move with the clock), else by wall time. Before timing anything our decoder
//! must reproduce each payload from the reference's stream. Arguments filter
//! workloads by substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
const brotli = @import("brotli");

const bench_name = "bench-brotli";
const work_dir = ".zig-cache/bench-brotli";
const default_lib_dir = "/usr/lib/x86_64-linux-gnu";
const payload_names = [_][]const u8{ "json", "html", "text", "font" };

const n_efforts = @typeInfo(brotli.Effort).@"enum".field_names.len;
const n_qualities = 12;

/// The reference quality closest to `ours` (one size per payload) by the
/// sum of |ln(ours / theirs)| over the payloads.
fn closestQuality(ours: [payload_names.len]usize, theirs: [payload_names.len][n_qualities]usize) u8 {
    var best: u8 = 0;
    var best_d: f64 = std.math.inf(f64);
    for (0..n_qualities) |q| {
        var d: f64 = 0;
        for (ours, theirs) |o, t| {
            if (t[q] == 0) return error_quality;
            d += @abs(@log(@as(f64, @floatFromInt(o)) / @as(f64, @floatFromInt(t[q]))));
        }
        if (d < best_d) {
            best_d = d;
            best = @intCast(q);
        }
    }
    return best;
}
const error_quality = 0xff;

/// `prep`'s report: "<payload>: N bytes" then "  qQ  SIZE" lines.
fn parseRefSizes(text: []const u8) [payload_names.len][n_qualities]usize {
    var out: [payload_names.len][n_qualities]usize = @splat(@splat(0));
    var cur: ?usize = null;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const first = it.next() orelse continue;
        if (first[0] == 'q') {
            const q = std.fmt.parseInt(usize, first[1..], 10) catch continue;
            const size = std.fmt.parseInt(usize, it.next() orelse continue, 10) catch continue;
            if (cur) |i| if (q < n_qualities) {
                out[i][q] = size;
            };
        } else {
            cur = null;
            for (payload_names, 0..) |n, i| {
                if (first.len == n.len + 1 and std.mem.startsWith(u8, first, n) and first[n.len] == ':') cur = i;
            }
        }
    }
    return out;
}

const Op = struct { decompress: bool, effort: brotli.Effort, payload: usize, alloc: bool = false };

const Ctx = struct {
    gpa: std.mem.Allocator,
    inputs: [payload_names.len][]u8,
    ref_br: [payload_names.len][]u8,
    /// `decompressInto`'s buffers: the payload size + 1, as the reference's.
    dec_buf: [payload_names.len][]u8 = undefined,
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    const i = x.op.payload;
    if (x.op.decompress and !x.op.alloc) {
        const out = brotli.decompressInto(x.gpa, x.dec_buf[i], x.ref_br[i], .{}) catch unreachable;
        std.mem.doNotOptimizeAway(out.ptr);
        return out.len;
    }
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
    ctx.inputs[3] = try brotli.interop_corpus.fontLike(arena, 200_000, 0xf0f7);
    for (payload_names, 0..) |n, i|
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.bin", .{n}), .data = ctx.inputs[i] });

    const lib_dir = init.environ_map.get("LIBBROTLI_DIR") orelse default_lib_dir;
    const libs = [_][]const u8{
        try arena.print("{s}/libbrotlienc.so.1", .{lib_dir}),
        try arena.print("{s}/libbrotlidec.so.1", .{lib_dir}),
        try arena.print("{s}/libbrotlicommon.so.1", .{lib_dir}),
    };
    const exe = try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, "modules/brotli/tools/c_bench/foreign_bench.c", &libs);

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
    const efforts = comptime std.enums.values(brotli.Effort);
    var our_sizes: [n_efforts][payload_names.len]usize = undefined;
    for (payload_names, 0..) |n, i| {
        const rb = try dir.readFileAlloc(io, try arena.print("{s}.ref.br", .{n}), arena, .limited(1 << 24));
        ctx.ref_br[i] = rb;
        ctx.dec_buf[i] = try arena.alloc(u8, ctx.inputs[i].len + 1);
        const back = try brotli.decompress(arena, rb, .{});
        if (!std.mem.eql(u8, back, ctx.inputs[i])) {
            std.debug.print("{s}: FAILED -- our decoder does not reproduce {s} from the reference stream\n", .{ bench_name, n });
            return 1;
        }
        try w.print("  {s} ({d} B):", .{ n, ctx.inputs[i].len });
        for (efforts, 0..) |e, k| {
            const c = try brotli.compressWith(arena, ctx.inputs[i], .{ .effort = e });
            const rt = try brotli.decompress(arena, c, .{});
            if (!std.mem.eql(u8, rt, ctx.inputs[i])) return error.RoundTrip;
            try w.print("  {s} {d}", .{ @tagName(e), c.len });
            our_sizes[k][i] = c.len;
        }
        try w.writeAll("\n");
    }
    const ref_sizes = parseRefSizes(prep.stdout);
    try w.writeAll("closest reference quality by size (pairing is by name):");
    for (our_sizes, efforts) |ours, e| {
        const q = closestQuality(ours, ref_sizes);
        if (q == error_quality) {
            std.debug.print("{s}: could not read the reference's sizes from prep\n", .{bench_name});
            return 1;
        }
        try w.print("  {s}->q{d}{s}", .{ @tagName(e), q, if (q == e.quality()) "" else " (!)" });
    }
    try w.writeAll("\n");
    try w.flush();

    var ws: std.ArrayList(Work) = .empty;
    for (payload_names, 0..) |n, i| {
        for (efforts) |effort| {
            const name = try arena.print("c_{s}_{s}", .{ @tagName(effort), n });
            const ref = try arena.print("c{d}_{s}", .{ effort.quality(), n });
            try ws.append(arena, .{ .name = name, .op = .{ .decompress = false, .effort = effort, .payload = i }, .ref = ref });
        }
        const name = try arena.print("d_{s}", .{n});
        try ws.append(arena, .{ .name = name, .op = .{ .decompress = true, .effort = .q6, .payload = i }, .ref = name });
        const aname = try arena.print("d_{s}_alloc", .{n});
        try ws.append(arena, .{ .name = aname, .op = .{ .decompress = true, .effort = .q6, .payload = i, .alloc = true }, .ref = name, .info = true });
    }

    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w);
    try w.print("reference: {s}\nworst ours/google-brotli = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× google/brotli <version> (C, one-shot) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}
