// SPDX-License-Identifier: MIT

//! Comparative benchmark: `tabular` against pandas (the reference) and polars or
//! DuckDB (`BENCH_ALT`, default polars), all single-threaded over the same tables.
//! The program behind the `**Performance:**` line (CONVENTIONS.md §9 kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-tabular` runs it (ReleaseFast).
//! Needs the venv of `tools/README.md` (`BENCH_PY`, default
//! `.zig-cache/tabular-oracle-venv/bin/python`). Run from the repository root.
//! Tables are written to `.zig-cache/bench-tabular/`, read by `tools/bench_py.py`.
//!
//! Table L: 1 M rows `k_int` (1 000 keys), `k2` (10), `k_hi` (200 000), `k_nul` (1 000,
//! 1 % null), `k_txt`
//! (1 000 strings), `v`, `w` (multiples of 0.25), `n` (row number). R: 100 000 rows
//! (`k_hi`, `rv`), half of L's keys. T: 1 000 rows (`k_txt`, `tv`).
//!
//! What each side does: the same verb to a materialized result. Ours is `dataset`'s row
//! store, 32-byte `Value`s under a slice per row. Verbs that BUILD rows (`join_*`, `melt`,
//! `mutate`, `rolling`, `cumsum`) write every output cell at 32 bytes, where pandas moves
//! 8-byte columns or, for an appended column, shares the untouched ones. Those are the
//! worst rows and every row counts; see SPEC § Backlog. `BENCH_RETAIN=1` shows how much
//! of them is 4 KiB page faults. `group_null` is the key path real data hits: a key
//! column with nulls cannot use the int table and goes through canonical bytes.
//! The `f_` rows are the verbs of `tabular.frame` on `dataset.Frame`, against the same
//! foreign row. The count (rows + |floor(sum of one output column)|) must agree on all sides.

const std = @import("std");
const bench = @import("testkit").bench;
const tabular = @import("tabular");
const dataset = @import("dataset");
const t0 = tabular.transforms;
const t1 = tabular.series;
const Value = dataset.Value;
const Dataset = dataset.Dataset;

const rows_l: usize = 1_000_000;
const rows_r: usize = 100_000;
const rows_t: usize = 1_000;

const Op = enum { group_int, group_null, group_hi, group_txt, group_two, group_stats, join_inner, join_left, join_txt, sort_float, sort_two, sort_txt, filter, pivot, distinct, melt, mutate, rolling, cumsum, f_mutate, f_rolling, f_cumsum, f_join_inner, f_join_left, f_join_txt };

const Ctx = struct { op: Op = .group_int, l: Dataset, r: Dataset, t: Dataset, fl: dataset.Frame, fr: dataset.Frame, ft: dataset.Frame };

/// The foreign side of an `f_` row is the same verb as its row-store row.
fn refName(comptime op: Op) []const u8 {
    const n = @tagName(op);
    return if (std.mem.startsWith(u8, n, "f_")) n[2..] else n;
}

fn frameSum(f: dataset.Frame, name: []const u8) f64 {
    const c = f.column(name).?;
    var s: f64 = 0;
    for (c.float.values) |x| s += x;
    return s;
}

fn colSum(d: Dataset, name: []const u8) f64 {
    const ci = d.columnIndex(name).?;
    var s: f64 = 0;
    for (d.rows) |r| s += r[ci].asFloat() orelse 0;
    return s;
}

fn cnt(rows: usize, s: f64) u64 {
    return rows + @as(u64, @intFromFloat(@abs(@floor(s))));
}

fn firstN(d: Dataset) f64 {
    return d.rows[0][d.columnIndex("n").?].asFloat().?;
}

fn lastN(d: Dataset) f64 {
    return d.rows[d.rows.len - 1][d.columnIndex("n").?].asFloat().?;
}

/// `BENCH_RETAIN=1`: one arena reset between calls, a pipeline that keeps its pages,
/// instead of a fresh one per call (the default, and what the card quotes). It shows
/// how much of a row is the kernel handing out pages: numpy madvises huge pages on
/// its big arrays, our output block is plain 4 KiB faults under `page_allocator`.
var retained: ?std.heap.ArenaAllocator = null;

/// `BENCH_HUGE=1`: a fresh arena per call as by default, its big blocks 2 MiB aligned and
/// madvised for huge pages, what numpy does for its big arrays *(inferred)*. Linux only,
/// and the kernel's `transparent_hugepage/enabled` must not be `never`.
var huge_arena = false;
const huge_size = 2 * 1024 * 1024;

const huge_vtable: std.mem.Allocator.VTable = .{
    .alloc = hugeAlloc,
    .resize = std.mem.Allocator.noResize,
    .remap = std.mem.Allocator.noRemap,
    .free = hugeFree,
};
const huge_child: std.mem.Allocator = .{ .ptr = undefined, .vtable = &huge_vtable };

fn hugeAlloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
    const pa = std.heap.page_allocator;
    if (len < huge_size) return pa.rawAlloc(len, alignment, ret);
    const al = std.mem.Alignment.fromByteUnits(@max(alignment.toByteUnits(), huge_size));
    const p = pa.rawAlloc(len, al, ret) orelse return null;
    _ = std.os.linux.madvise(@alignCast(p), len, std.os.linux.MADV.HUGEPAGE);
    return p;
}

fn hugeFree(_: *anyopaque, mem: []u8, alignment: std.mem.Alignment, ret: usize) void {
    std.heap.page_allocator.rawFree(mem, alignment, ret);
}

fn once(c: *Ctx) u64 {
    if (retained) |*r| {
        defer _ = r.reset(.retain_capacity);
        return run(r.allocator(), c) catch |e| @panic(@errorName(e));
    }
    var arena = std.heap.ArenaAllocator.init(if (huge_arena) huge_child else std.heap.page_allocator);
    defer arena.deinit();
    return run(arena.allocator(), c) catch |e| @panic(@errorName(e));
}

fn run(a: std.mem.Allocator, c: *Ctx) !u64 {
    const s_v: t0.AggCol = .{ .src = "v", .out = "s", .func = .sum };
    const m_w: t0.AggCol = .{ .src = "w", .out = "m", .func = .mean };
    switch (c.op) {
        .group_int => {
            const o = try t0.aggregate(a, c.l, .{ .group_by = &.{"k_int"}, .aggs = &.{ s_v, m_w } });
            return cnt(o.rows.len, colSum(o, "s"));
        },
        .group_null => {
            const o = try t0.aggregate(a, c.l, .{ .group_by = &.{"k_nul"}, .aggs = &.{ s_v, m_w } });
            return cnt(o.rows.len, colSum(o, "s"));
        },
        .group_hi => {
            const o = try t0.aggregate(a, c.l, .{ .group_by = &.{"k_hi"}, .aggs = &.{s_v} });
            return cnt(o.rows.len, colSum(o, "s"));
        },
        .group_txt => {
            const o = try t0.aggregate(a, c.l, .{ .group_by = &.{"k_txt"}, .aggs = &.{ s_v, m_w } });
            return cnt(o.rows.len, colSum(o, "s"));
        },
        .group_two => {
            const o = try t0.aggregate(a, c.l, .{ .group_by = &.{ "k_int", "k2" }, .aggs = &.{s_v} });
            return cnt(o.rows.len, colSum(o, "s"));
        },
        .group_stats => {
            const o = try t0.aggregate(a, c.l, .{ .group_by = &.{"k_int"}, .aggs = &.{
                .{ .src = "v", .out = "c", .func = .count },
                .{ .src = "w", .out = "sd", .func = .std },
                .{ .src = "w", .out = "md", .func = .median },
            } });
            return cnt(o.rows.len, colSum(o, "c"));
        },
        .join_inner => {
            const o = try t1.join(a, c.l, c.r, .{ .on = "k_hi", .how = .inner });
            return cnt(o.rows.len, colSum(o, "rv"));
        },
        .join_left => {
            const o = try t1.join(a, c.l, c.r, .{ .on = "k_hi", .how = .left });
            return cnt(o.rows.len, colSum(o, "rv"));
        },
        .join_txt => {
            const o = try t1.join(a, c.l, c.t, .{ .on = "k_txt", .how = .inner });
            return cnt(o.rows.len, colSum(o, "tv"));
        },
        .sort_float => {
            const o = try t0.sort(a, c.l, .{ .key = "v" });
            return cnt(o.rows.len, firstN(o));
        },
        .sort_two => {
            const o = try t0.sort(a, c.l, .{ .key = "k_int", .then_by = &.{.{ .key = "v", .dir = .desc }} });
            return cnt(o.rows.len, firstN(o));
        },
        .sort_txt => {
            const o = try t0.sort(a, c.l, .{ .key = "k_txt" });
            return cnt(o.rows.len, firstN(o));
        },
        .filter => {
            const o = try t0.filter(a, c.l, .{ .where = &.{
                .{ .col = "v", .op = .gt, .value = .{ .float = 0 } },
                .{ .col = "k_int", .op = .lt, .value = .{ .int = 500 } },
            } });
            return cnt(o.rows.len, colSum(o, "v"));
        },
        .pivot => {
            const o = try t0.pivot(a, c.l, .{ .row_key = "k_int", .col_key = "k2", .value_col = "v" });
            var s: f64 = 0;
            for (o.rows) |r| for (r[1..]) |x| {
                s += x.asFloat() orelse 0;
            };
            return cnt(o.rows.len, s);
        },
        .distinct => {
            const o = try t1.distinct(a, c.l, .{ .keys = &.{"k_hi"} });
            return cnt(o.rows.len, colSum(o, "v"));
        },
        .melt => {
            const o = try t0.unpivot(a, c.l, .{ .id_cols = &.{"n"}, .value_cols = &.{ "v", "w" } });
            return cnt(o.rows.len, colSum(o, "value"));
        },
        .mutate => {
            const o = try t0.map(a, c.l, .{ .out = "p", .lhs = .{ .col = "v" }, .op = .mul, .rhs = .{ .col = "w" } });
            return cnt(o.rows.len, lastN(o));
        },
        .rolling => {
            const o = try t1.rolling(a, c.l, .{ .value_col = "v", .out = "p", .window = 20 });
            return cnt(o.rows.len, lastN(o));
        },
        .cumsum => {
            const o = try t1.cumsum(a, c.l, .{ .value_col = "v", .out = "p" });
            return cnt(o.rows.len, o.rows[o.rows.len - 1][o.columns.len - 1].asFloat().?);
        },
        .f_mutate => {
            const o = try tabular.frame.map(a, c.fl, .{ .out = "p", .lhs = .{ .col = "v" }, .op = .mul, .rhs = .{ .col = "w" } });
            return cnt(o.len, @floatFromInt(o.column("n").?.int.values[o.len - 1]));
        },
        .f_rolling => {
            const o = try tabular.frame.rolling(a, c.fl, .{ .value_col = "v", .out = "p", .window = 20 });
            return cnt(o.len, @floatFromInt(o.column("n").?.int.values[o.len - 1]));
        },
        .f_cumsum => {
            const o = try tabular.frame.cumsum(a, c.fl, .{ .value_col = "v", .out = "p" });
            return cnt(o.len, o.column("p").?.float.values[o.len - 1]);
        },
        .f_join_inner => {
            const o = try tabular.frame.join(a, c.fl, c.fr, .{ .on = "k_hi", .how = .inner });
            return cnt(o.len, frameSum(o, "rv"));
        },
        .f_join_left => {
            const o = try tabular.frame.join(a, c.fl, c.fr, .{ .on = "k_hi", .how = .left });
            return cnt(o.len, frameSum(o, "rv"));
        },
        .f_join_txt => {
            const o = try tabular.frame.join(a, c.fl, c.ft, .{ .on = "k_txt", .how = .inner });
            return cnt(o.len, frameSum(o, "tv"));
        },
    }
}

/// xorshift64*: both sides read the files, so its quality hardly matters.
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

const Tables = struct { l: Dataset, r: Dataset, t: Dataset };

fn makeTables(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Tables {
    var rng: Rng = .{ .s = 0x7ab1e5eed };
    const names = try a.alloc([]const u8, rows_t);
    for (names, 0..) |*n, i| n.* = try a.print("key-{d:0>6}", .{i * 7919 % 100_000});

    const lcols = try a.dupe(dataset.Column, &.{
        .{ .name = "k_int", .type = .int }, .{ .name = "k2", .type = .int },
        .{ .name = "k_hi", .type = .int },  .{ .name = "k_txt", .type = .text },
        .{ .name = "v", .type = .float },   .{ .name = "w", .type = .float },
        .{ .name = "n", .type = .int },     .{ .name = "k_nul", .type = .float },
    });
    const lrows = try a.alloc([]const Value, rows_l);
    const ki = try a.alloc(i64, rows_l);
    const k2 = try a.alloc(i64, rows_l);
    const kh = try a.alloc(i64, rows_l);
    const nn = try a.alloc(i64, rows_l);
    const vv = try a.alloc(f64, rows_l);
    const ww = try a.alloc(f64, rows_l);
    const kn = try a.alloc(f64, rows_l);
    var txt: std.ArrayList(u8) = .empty;
    for (lrows, 0..) |*row, i| {
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
        row.* = try a.dupe(Value, &.{ .{ .int = ki[i] }, .{ .int = k2[i] }, .{ .int = kh[i] }, .{ .text = t }, .{ .float = vv[i] }, .{ .float = ww[i] }, .{ .int = nn[i] }, if (nul) .null else .{ .float = kn[i] } });
    }
    try dir.writeFile(io, .{ .sub_path = "k_int.i64", .data = std.mem.sliceAsBytes(ki) });
    try dir.writeFile(io, .{ .sub_path = "k2.i64", .data = std.mem.sliceAsBytes(k2) });
    try dir.writeFile(io, .{ .sub_path = "k_hi.i64", .data = std.mem.sliceAsBytes(kh) });
    try dir.writeFile(io, .{ .sub_path = "n.i64", .data = std.mem.sliceAsBytes(nn) });
    try dir.writeFile(io, .{ .sub_path = "v.f64", .data = std.mem.sliceAsBytes(vv) });
    try dir.writeFile(io, .{ .sub_path = "w.f64", .data = std.mem.sliceAsBytes(ww) });
    try dir.writeFile(io, .{ .sub_path = "k_nul.f64", .data = std.mem.sliceAsBytes(kn) });
    try dir.writeFile(io, .{ .sub_path = "k_txt.txt", .data = txt.items });

    const rcols = try a.dupe(dataset.Column, &.{ .{ .name = "k_hi", .type = .int }, .{ .name = "rv", .type = .float } });
    const rrows = try a.alloc([]const Value, rows_r);
    const rk = try a.alloc(i64, rows_r);
    const rv = try a.alloc(f64, rows_r);
    for (rrows, 0..) |*row, i| {
        rk[i] = @intCast(i * 2); // every second key of k_hi's range
        rv[i] = rng.quarter();
        row.* = try a.dupe(Value, &.{ .{ .int = rk[i] }, .{ .float = rv[i] } });
    }
    try dir.writeFile(io, .{ .sub_path = "r_k_hi.i64", .data = std.mem.sliceAsBytes(rk) });
    try dir.writeFile(io, .{ .sub_path = "r_rv.f64", .data = std.mem.sliceAsBytes(rv) });

    const tcols = try a.dupe(dataset.Column, &.{ .{ .name = "k_txt", .type = .text }, .{ .name = "tv", .type = .float } });
    const trows = try a.alloc([]const Value, rows_t);
    const tv = try a.alloc(f64, rows_t);
    var ttxt: std.ArrayList(u8) = .empty;
    for (trows, names, 0..) |*row, n, i| {
        tv[i] = rng.quarter();
        try ttxt.appendSlice(a, n);
        try ttxt.append(a, '\n');
        row.* = try a.dupe(Value, &.{ .{ .text = n }, .{ .float = tv[i] } });
    }
    try dir.writeFile(io, .{ .sub_path = "t_tv.f64", .data = std.mem.sliceAsBytes(tv) });
    try dir.writeFile(io, .{ .sub_path = "t_k_txt.txt", .data = ttxt.items });
    return .{ .l = .{ .columns = lcols, .rows = lrows }, .r = .{ .columns = rcols, .rows = rrows }, .t = .{ .columns = tcols, .rows = trows } };
}

fn wrapper(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, abs: []const u8, py: []const u8, engine: []const u8) ![]const u8 {
    const name = try a.print("{s}.sh", .{engine});
    const body = try a.print("#!/bin/sh\nexec {s} modules/tabular/tools/bench_py.py {s} \"$1\" \"$2\"\n", .{ py, engine });
    try dir.writeFile(io, .{ .sub_path = name, .data = body, .flags = .{ .permissions = .executable_file } });
    return a.print("{s}/{s}", .{ abs, name });
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var arena_s = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_s.deinit();
    const a = arena_s.allocator();

    const work = ".zig-cache/bench-tabular";
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
    var ctx: Ctx = .{ .l = tb.l, .r = tb.r, .t = tb.t, .fl = try dataset.Frame.fromDataset(a, tb.l), .fr = try dataset.Frame.fromDataset(a, tb.r), .ft = try dataset.Frame.fromDataset(a, tb.t) };

    const pandas_exe = try wrapper(a, io, dir, abs, py, "pandas");
    const alt_exe = try wrapper(a, io, dir, abs, py, alt);
    const alt_is_polars = std.mem.eql(u8, alt, "polars");

    const W = bench.Work(Op);
    var ws: std.ArrayList(W) = .empty;
    inline for (std.enums.values(Op)) |op| {
        const no_alt = !alt_is_polars and (op == .mutate or op == .rolling or op == .cumsum or op == .pivot or op == .f_mutate or op == .f_rolling or op == .f_cumsum);
        try ws.append(a, .{ .name = @tagName(op), .op = op, .ref = comptime refName(op), .alt = if (no_alt) null else comptime refName(op), .ref_exe = 0, .alt_exe = 1, .wall_only = true });
    }

    const args = try init.minimal.args.toSlice(a);
    var outbuf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &outbuf);
    const s = try bench.drive(io, a, .{
        .name = "bench-tabular",
        .exes = &.{ pandas_exe, alt_exe },
        .abs = abs,
        .filters = args[1..],
        .rounds = rounds,
    }, &ctx, once, ws.items, &out.interface);
    try out.interface.print("banner ref: {s}alt: {s}worst ours/pandas {d:.3}, worst ours/fastest-of-(pandas,{s}) {d:.3}\n", .{ s.banner, s.alt_banner, s.worst_ref, alt, s.worst_fast orelse 0 });
    try out.interface.flush();
}
