// SPDX-License-Identifier: MIT

//! Comparative benchmark: `dataframe` against pandas (the reference) and polars or
//! DuckDB (`BENCH_ALT`, default polars), all single-threaded over the same tables.
//! The program behind the `**Performance:**` line (CONVENTIONS.md §9 kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-dataframe` runs it (ReleaseFast).
//! Needs the venv of `modules/tabular/tools/README.md` (`BENCH_PY`, default
//! `.zig-cache/tabular-oracle-venv/bin/python`). Run from the repository root.
//! Tables are written to `.zig-cache/bench-dataframe/`, read by `tools/bench_py.py`.
//!
//! Table L: 1 M rows `k_int` (1 000 keys), `k2` (10), `k_hi` (200 000), `k_nul` (1 000,
//! 1 % null), `k_txt` (1 000 strings), `v`, `w` (multiples of 0.25), `n` (row number).
//! R: 100 000 rows (`k_hi`, `rv`), half of L's keys. T: 1 000 rows (`k_txt`, `tv`).
//! The same tables and the same foreign rows as `tabular`'s bench, whose `f_` rows these
//! are; `sort_*` and `pivot` are new with the verbs. Each side does the same verb to a
//! materialized result; the count (rows + |floor(sum of one output column)|) must agree
//! on all sides.
//!
//! I/O rows (D4B): `read_csv` parses the bytes of L written once as CSV (`l.csv`, the
//! foreign side reads the same file into memory before the clock), inference on, no
//! hints; count = rows + sum of `v`. The three writers (`write_csv`, `write_json`
//! records, `write_ndjson`) serialize L into an in-memory writer; their count is the
//! OUTPUT BYTE LENGTH, which holds only where the engines' text agrees.

const std = @import("std");
const bench = @import("testkit").bench;
const df = @import("dataframe");
const Value = df.Value;
const Frame = df.Frame;

const rows_l: usize = 1_000_000;
const rows_r: usize = 100_000;
const rows_t: usize = 1_000;

const Op = enum { read_csv, write_csv, write_json, write_ndjson, group_int, group_null, group_hi, group_txt, group_two, group_stats, join_inner, join_left, join_txt, sort_float, sort_two, sort_txt, filter, pivot, distinct, melt, mutate, rolling, cumsum };

const Ctx = struct { op: Op = .group_int, l: Frame, r: Frame, t: Frame, csv: []const u8 };

fn frameSum(f: Frame, name: []const u8) f64 {
    const c = f.column(name).?;
    var s: f64 = 0;
    for (0..f.len) |ri| s += c.get(ri).asFloat() orelse 0;
    return s;
}

fn cnt(rows: usize, s: f64) u64 {
    return rows + @as(u64, @intFromFloat(@abs(@floor(s))));
}

fn firstN(f: Frame) f64 {
    return f.cell(0, "n").?.asFloat().?;
}

fn lastN(f: Frame) f64 {
    return f.cell(f.len - 1, "n").?.asFloat().?;
}

/// `BENCH_RETAIN=1`: one arena reset between calls, a pipeline that keeps its pages,
/// instead of a fresh one per call (the default, and what the card quotes).
var retained: ?std.heap.ArenaAllocator = null;

/// `BENCH_HUGE=1`: a fresh arena per call as by default, over `df.big_block_allocator`.
var huge_arena = false;

fn once(c: *Ctx) u64 {
    if (retained) |*r| {
        defer _ = r.reset(.retain_capacity);
        return run(r.allocator(), c) catch |e| @panic(@errorName(e));
    }
    var arena = std.heap.ArenaAllocator.init(if (huge_arena) df.big_block_allocator else std.heap.page_allocator);
    defer arena.deinit();
    return run(arena.allocator(), c) catch |e| @panic(@errorName(e));
}

fn run(a: std.mem.Allocator, c: *Ctx) !u64 {
    const s_v: df.AggCol = .{ .src = "v", .out = "s", .func = .sum };
    const m_w: df.AggCol = .{ .src = "w", .out = "m", .func = .mean };
    switch (c.op) {
        .read_csv => {
            const o = try df.readCsv(a, c.csv, .{});
            return cnt(o.len, frameSum(o, "v"));
        },
        .write_csv => {
            var w = std.Io.Writer.Allocating.init(a);
            try df.writeCsv(a, &w.writer, c.l, .{});
            return w.written().len;
        },
        .write_json => {
            var w = std.Io.Writer.Allocating.init(a);
            try df.writeJson(&w.writer, c.l, .records);
            return w.written().len;
        },
        .write_ndjson => {
            var w = std.Io.Writer.Allocating.init(a);
            try df.writeNdjson(&w.writer, c.l);
            return w.written().len;
        },
        .group_int => {
            const o = try df.aggregate(a, c.l, .{ .group_by = &.{"k_int"}, .aggs = &.{ s_v, m_w } });
            return cnt(o.len, frameSum(o, "s"));
        },
        .group_null => {
            const o = try df.aggregate(a, c.l, .{ .group_by = &.{"k_nul"}, .aggs = &.{ s_v, m_w } });
            return cnt(o.len, frameSum(o, "s"));
        },
        .group_hi => {
            const o = try df.aggregate(a, c.l, .{ .group_by = &.{"k_hi"}, .aggs = &.{s_v} });
            return cnt(o.len, frameSum(o, "s"));
        },
        .group_txt => {
            const o = try df.aggregate(a, c.l, .{ .group_by = &.{"k_txt"}, .aggs = &.{ s_v, m_w } });
            return cnt(o.len, frameSum(o, "s"));
        },
        .group_two => {
            const o = try df.aggregate(a, c.l, .{ .group_by = &.{ "k_int", "k2" }, .aggs = &.{s_v} });
            return cnt(o.len, frameSum(o, "s"));
        },
        .group_stats => {
            const o = try df.aggregate(a, c.l, .{ .group_by = &.{"k_int"}, .aggs = &.{
                .{ .src = "v", .out = "c", .func = .count },
                .{ .src = "w", .out = "sd", .func = .std },
                .{ .src = "w", .out = "md", .func = .median },
            } });
            return cnt(o.len, frameSum(o, "c"));
        },
        .join_inner => {
            const o = try df.join(a, c.l, c.r, .{ .on = "k_hi", .how = .inner });
            return cnt(o.len, frameSum(o, "rv"));
        },
        .join_left => {
            const o = try df.join(a, c.l, c.r, .{ .on = "k_hi", .how = .left });
            return cnt(o.len, frameSum(o, "rv"));
        },
        .join_txt => {
            const o = try df.join(a, c.l, c.t, .{ .on = "k_txt", .how = .inner });
            return cnt(o.len, frameSum(o, "tv"));
        },
        .sort_float => {
            const o = try df.sort(a, c.l, .{ .key = "v" });
            return cnt(o.len, firstN(o));
        },
        .sort_two => {
            const o = try df.sort(a, c.l, .{ .key = "k_int", .then_by = &.{.{ .key = "v", .dir = .desc }} });
            return cnt(o.len, firstN(o));
        },
        .sort_txt => {
            const o = try df.sort(a, c.l, .{ .key = "k_txt" });
            return cnt(o.len, firstN(o));
        },
        .filter => {
            const o = try df.filter(a, c.l, .{ .where = &.{
                .{ .col = "v", .op = .gt, .value = .{ .float = 0 } },
                .{ .col = "k_int", .op = .lt, .value = .{ .int = 500 } },
            } });
            return cnt(o.len, frameSum(o, "v"));
        },
        .pivot => {
            const o = try df.pivot(a, c.l, .{ .row_key = "k_int", .col_key = "k2", .value_col = "v" });
            var s: f64 = 0;
            for (o.data[1..]) |col| {
                for (0..o.len) |ri| s += col.get(ri).asFloat() orelse 0;
            }
            return cnt(o.len, s);
        },
        .distinct => {
            const o = try df.distinct(a, c.l, .{ .keys = &.{"k_hi"} });
            return cnt(o.len, frameSum(o, "v"));
        },
        .melt => {
            const o = try df.unpivot(a, c.l, .{ .id_cols = &.{"n"}, .value_cols = &.{ "v", "w" } });
            return cnt(o.len, frameSum(o, "value"));
        },
        .mutate => {
            const o = try df.map(a, c.l, .{ .out = "p", .lhs = .{ .col = "v" }, .op = .mul, .rhs = .{ .col = "w" } });
            return cnt(o.len, lastN(o));
        },
        .rolling => {
            const o = try df.rolling(a, c.l, .{ .value_col = "v", .out = "p", .window = 20 });
            return cnt(o.len, lastN(o));
        },
        .cumsum => {
            const o = try df.cumsum(a, c.l, .{ .value_col = "v", .out = "p" });
            return cnt(o.len, o.column("p").?.float.values[o.len - 1]);
        },
    }
}

/// xorshift64*: both sides read the files, so its quality hardly matters. The same
/// stream as `tabular`'s bench, so the tables are the same.
const Rng = struct {
    s: u64,
    fn next(r: *Rng) u64 {
        r.s ^= r.s >> 12;
        r.s ^= r.s << 25;
        r.s ^= r.s >> 27;
        return r.s *% 0x9E3779B97F4A7C15;
    }
    fn below(r: *Rng, n: u64) i64 {
        return @intCast(r.next() % n);
    }
    fn quarter(r: *Rng) f64 {
        return @as(f64, @floatFromInt(r.below(4_000_000))) * 0.25 - 500_000;
    }
};

const Tables = struct { l: Frame, r: Frame, t: Frame, csv: []const u8 };

fn makeTables(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Tables {
    var rng: Rng = .{ .s = 0x7ab1e5eed };
    const names = try a.alloc([]const u8, rows_t);
    for (names, 0..) |*n, i| n.* = try a.print("key-{d:0>6}", .{i * 7919 % 100_000});

    const lcols = try a.dupe(df.Column, &.{
        .{ .name = "k_int", .type = .int }, .{ .name = "k2", .type = .int },
        .{ .name = "k_hi", .type = .int },  .{ .name = "k_txt", .type = .text },
        .{ .name = "v", .type = .float },   .{ .name = "w", .type = .float },
        .{ .name = "n", .type = .int },     .{ .name = "k_nul", .type = .float },
    });
    var lb = try df.FrameBuilder.init(a, lcols, rows_l);
    const ki = try a.alloc(i64, rows_l);
    const k2 = try a.alloc(i64, rows_l);
    const kh = try a.alloc(i64, rows_l);
    const nn = try a.alloc(i64, rows_l);
    const vv = try a.alloc(f64, rows_l);
    const ww = try a.alloc(f64, rows_l);
    const kn = try a.alloc(f64, rows_l);
    var txt: std.ArrayList(u8) = .empty;
    for (0..rows_l) |i| {
        const t = names[@intCast(rng.below(rows_t))];
        ki[i] = rng.below(1000);
        k2[i] = rng.below(10);
        kh[i] = rng.below(200_000);
        nn[i] = @intCast(i);
        vv[i] = rng.quarter();
        ww[i] = rng.quarter();
        const nul = rng.below(100) == 0;
        kn[i] = if (nul) std.math.nan(f64) else @floatFromInt(rng.below(1000));
        try txt.appendSlice(a, t);
        try txt.append(a, '\n');
        try lb.appendRow(&.{ .{ .int = ki[i] }, .{ .int = k2[i] }, .{ .int = kh[i] }, .{ .text = t }, .{ .float = vv[i] }, .{ .float = ww[i] }, .{ .int = nn[i] }, if (nul) .null else .{ .float = kn[i] } });
    }
    try dir.writeFile(io, .{ .sub_path = "k_int.i64", .data = std.mem.sliceAsBytes(ki) });
    try dir.writeFile(io, .{ .sub_path = "k2.i64", .data = std.mem.sliceAsBytes(k2) });
    try dir.writeFile(io, .{ .sub_path = "k_hi.i64", .data = std.mem.sliceAsBytes(kh) });
    try dir.writeFile(io, .{ .sub_path = "n.i64", .data = std.mem.sliceAsBytes(nn) });
    try dir.writeFile(io, .{ .sub_path = "v.f64", .data = std.mem.sliceAsBytes(vv) });
    try dir.writeFile(io, .{ .sub_path = "w.f64", .data = std.mem.sliceAsBytes(ww) });
    try dir.writeFile(io, .{ .sub_path = "k_nul.f64", .data = std.mem.sliceAsBytes(kn) });
    try dir.writeFile(io, .{ .sub_path = "k_txt.txt", .data = txt.items });

    const rcols = try a.dupe(df.Column, &.{ .{ .name = "k_hi", .type = .int }, .{ .name = "rv", .type = .float } });
    var rb = try df.FrameBuilder.init(a, rcols, rows_r);
    const rk = try a.alloc(i64, rows_r);
    const rv = try a.alloc(f64, rows_r);
    for (0..rows_r) |i| {
        rk[i] = @intCast(i * 2); // every second key of k_hi's range
        rv[i] = rng.quarter();
        try rb.appendRow(&.{ .{ .int = rk[i] }, .{ .float = rv[i] } });
    }
    try dir.writeFile(io, .{ .sub_path = "r_k_hi.i64", .data = std.mem.sliceAsBytes(rk) });
    try dir.writeFile(io, .{ .sub_path = "r_rv.f64", .data = std.mem.sliceAsBytes(rv) });

    const tcols = try a.dupe(df.Column, &.{ .{ .name = "k_txt", .type = .text }, .{ .name = "tv", .type = .float } });
    var tb = try df.FrameBuilder.init(a, tcols, rows_t);
    const tv = try a.alloc(f64, rows_t);
    var ttxt: std.ArrayList(u8) = .empty;
    for (names, 0..) |n, i| {
        tv[i] = rng.quarter();
        try ttxt.appendSlice(a, n);
        try ttxt.append(a, '\n');
        try tb.appendRow(&.{ .{ .text = n }, .{ .float = tv[i] } });
    }
    try dir.writeFile(io, .{ .sub_path = "t_tv.f64", .data = std.mem.sliceAsBytes(tv) });
    try dir.writeFile(io, .{ .sub_path = "t_k_txt.txt", .data = ttxt.items });
    const lf = try lb.toOwned();
    // L as CSV once, outside every timed part: `read_csv` parses these bytes, the
    // foreign sides read the same file.
    var cw = std.Io.Writer.Allocating.init(a);
    try df.writeCsv(a, &cw.writer, lf, .{});
    try dir.writeFile(io, .{ .sub_path = "l.csv", .data = cw.written() });
    return .{ .l = lf, .r = try rb.toOwned(), .t = try tb.toOwned(), .csv = cw.written() };
}

fn wrapper(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, abs: []const u8, py: []const u8, engine: []const u8) ![]const u8 {
    const name = try a.print("{s}.sh", .{engine});
    const body = try a.print("#!/bin/sh\nexec {s} modules/dataframe/tools/bench_py.py {s} \"$1\" \"$2\"\n", .{ py, engine });
    try dir.writeFile(io, .{ .sub_path = name, .data = body, .flags = .{ .permissions = .executable_file } });
    return a.print("{s}/{s}", .{ abs, name });
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var arena_s = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_s.deinit();
    const a = arena_s.allocator();

    const work = ".zig-cache/bench-dataframe";
    try std.Io.Dir.cwd().createDirPath(io, work);
    var dir = try std.Io.Dir.cwd().openDir(io, work, .{});
    defer dir.close(io);
    const cwd_abs = try std.process.currentPathAlloc(io, a);
    const abs = try a.print("{s}/{s}", .{ cwd_abs, work });

    const env = init.environ_map;
    const py_rel = env.get("BENCH_PY") orelse ".zig-cache/tabular-oracle-venv/bin/python";
    const py = if (std.fs.path.isAbsolute(py_rel)) py_rel else try a.print("{s}/{s}", .{ cwd_abs, py_rel });
    const alt = env.get("BENCH_ALT") orelse "polars";
    const rounds: usize = if (env.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    huge_arena = env.get("BENCH_HUGE") != null;
    if (env.get("BENCH_RETAIN") != null) retained = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const tb = try makeTables(a, io, dir);
    var ctx: Ctx = .{ .l = tb.l, .r = tb.r, .t = tb.t, .csv = tb.csv };

    const pandas_exe = try wrapper(a, io, dir, abs, py, "pandas");
    const alt_exe = try wrapper(a, io, dir, abs, py, alt);
    const alt_is_polars = std.mem.eql(u8, alt, "polars");

    const W = bench.Work(Op);
    var ws: std.ArrayList(W) = .empty;
    inline for (std.enums.values(Op)) |op| {
        const no_alt = !alt_is_polars and (op == .mutate or op == .rolling or op == .cumsum or op == .pivot or op == .read_csv or op == .write_csv or op == .write_json or op == .write_ndjson);
        try ws.append(a, .{ .name = @tagName(op), .op = op, .ref = @tagName(op), .alt = if (no_alt) null else @tagName(op), .ref_exe = 0, .alt_exe = 1, .wall_only = true });
    }

    const args = try init.minimal.args.toSlice(a);
    var outbuf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &outbuf);
    const s = try bench.drive(io, a, .{
        .name = "bench-dataframe",
        .exes = &.{ pandas_exe, alt_exe },
        .abs = abs,
        .filters = args[1..],
        .rounds = rounds,
    }, &ctx, once, ws.items, &out.interface);
    try out.interface.print("banner ref: {s}alt: {s}worst ours/pandas {d:.3}, worst ours/fastest-of-(pandas,{s}) {d:.3}\n", .{ s.banner, s.alt_banner, s.worst_ref, alt, s.worst_fast orelse 0 });
    try out.interface.flush();
}
