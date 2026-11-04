// SPDX-License-Identifier: MIT

//! Comparative benchmark: `dataset` against two Go libraries. REFERENCE:
//! `github.com/go-gota/gota` v0.12.0 (Apache-2.0, `tools/go_bench_gota`), the
//! Go DataFrame with a boxed `Element` per cell, which is this module's table
//! model; it has no wire format and no nullable row-wise builder, so it is
//! paired on the two column reads only (`col_f64`, `col_text`). FASTEST (and
//! the only side for the other ops): Apache Arrow for Go,
//! `github.com/apache/arrow-go/v18` v18.8.0 (Apache-2.0, `tools/go_bench`),
//! a typed columnar store. Rows not paired with gota are `fast_only`.
//! The program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-dataset` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.25+ and
//! arrow-go v18.8.0 with its dependencies in the module cache (`GOPROXY=off`;
//! `go -C modules/dataset/tools/go_bench mod download` once, with network).
//! Run from the repository root.
//!
//! The table, identical on both sides (each generates it from these formulas,
//! i = 0..19999; nothing is read from disk):
//!   id   int64          i
//!   price float64       i * 0.25 + (i % 97)             (exact in binary)
//!   name utf8           "item-" ++ ((i * 2654435761) % 100000)
//!   ts   timestamp[us]  1700000000000000 + i * 1000003  (UTC)
//!   flag bool           i % 3 == 0
//!   qty  int64, nullable  null when i % 7 == 0, else (i * 37) % 1000
//! Ours: `Dataset` with columns int/float/text/timestamp/bool/int, `Value`
//! cells (null = `.null`). Arrow's side: one record batch, validity bitmap on
//! `qty` only, the Go allocator.
//!
//! One op = one pass over the whole table. Both sides do the same work:
//!   build     rows -> table, one row at a time (ours `Builder.appendRow` +
//!             `toOwned`; Go `RecordBuilder` per-field `Append` + `NewRecordBatch`).
//!             Ours is into an arena that is reset per op (the module's memory
//!             model), Go allocates and lets the GC reclaim. Count = rows.
//!   encode    table -> bytes (ours `serialize`; Go `ipc.NewWriter` stream,
//!             schema + one batch + EOS, into a `bytes.Buffer`). The FORMATS
//!             DIFFER (private wire vs Arrow IPC stream), see the wire sizes
//!             printed by main. Count = rows.
//!   decode    bytes -> table (ours `deserialize`; Go `ipc.NewReader`, `Next`,
//!             `RecordBatch`), each side from its own bytes. Count = rows.
//!   col_f64   column access: the `price` column as a float64 slice, summed
//!             (ours `Dataset.floatColumn` into the arena, which is what the
//!             module offers; Go `Float64Values()`, zero-copy). Count = the sum.
//!   col_i64   the nullable `qty` column summed over non-null cells (ours
//!             `columnIndex` once + a loop over rows; Go `IsValid`/`Value`).
//!   col_text  total byte length of `name` (ours a loop over rows; Go
//!             `String.Value`).
//!   col_misc  a pass over id, ts and flag (sum of id + ts % 1009, plus one per
//!             true flag).
//! The `f_` rows are the same ops on `Frame` against the same Go rows: `f_build`
//! `FrameBuilder`, `f_encode` `serializeFrame`, `f_decode` `deserializeFrame`,
//! `f_col_f64` `Frame.floatColumn` (no copy), the others the typed arrays.
//! The column ops read the table that came OFF THE WIRE on each side (decoded
//! from its own bytes), so equal counts also check that decode returned the
//! same content. The Go side prints the wire size and its banner on stderr.

const std = @import("std");
const bench = @import("testkit").bench;
const dataset = @import("dataset");

const ref_short = "gota";
const ref_card = "Go gota v0.12.0";
const fast_card = "Apache Arrow Go arrow-go v18.8.0";
const bench_name = "bench-dataset";
const work_dir = ".zig-cache/bench-dataset";
const go_dir = "modules/dataset/tools/go_bench";
const nrows = 20000;

const Op = enum { build, encode, decode, col_f64, col_i64, col_text, col_misc, f_build, f_encode, f_decode, f_col_f64, f_col_i64, f_col_text, f_col_misc };

const columns = [_]dataset.Column{
    .{ .name = "id", .type = .int },
    .{ .name = "price", .type = .float },
    .{ .name = "name", .type = .text },
    .{ .name = "ts", .type = .timestamp },
    .{ .name = "flag", .type = .bool },
    .{ .name = "qty", .type = .int },
};

const Ctx = struct {
    op: Op = .build,
    work: std.heap.ArenaAllocator,
    names: [nrows][]const u8 = undefined,
    table: dataset.Dataset = undefined, // built, encoded, decoded: what the column ops read
    built: dataset.Dataset = undefined, // what `encode` reads
    wire: []const u8 = &.{},
    frame: dataset.Frame = undefined, // decoded from `wire`
    fbuilt: dataset.Frame = undefined, // what `f_encode` reads
};

fn cellsFor(c: *const Ctx, i: usize, cells: *[6]dataset.Value) void {
    cells[0] = .{ .int = @intCast(i) };
    cells[1] = .{ .float = @as(f64, @floatFromInt(i)) * 0.25 + @as(f64, @floatFromInt(i % 97)) };
    cells[2] = .{ .text = c.names[i] };
    cells[3] = .{ .int = 1700000000000000 + @as(i64, @intCast(i)) * 1000003 };
    cells[4] = .{ .bool = i % 3 == 0 };
    cells[5] = if (i % 7 == 0) .null else .{ .int = @intCast((i * 37) % 1000) };
}

fn buildTable(c: *const Ctx, a: std.mem.Allocator) !dataset.Dataset {
    var b = dataset.Builder.init(a, &columns);
    var cells: [6]dataset.Value = undefined;
    for (0..nrows) |i| {
        cellsFor(c, i, &cells);
        try b.appendRow(&cells);
    }
    return b.toOwned();
}

fn once(c: *Ctx) u64 {
    _ = c.work.reset(.retain_capacity);
    const a = c.work.allocator();
    switch (c.op) {
        .build => {
            const d = buildTable(c, a) catch @panic("bench-dataset: build");
            return d.rows.len;
        },
        .encode => {
            const w = dataset.serialize(a, c.built) catch @panic("bench-dataset: encode");
            std.mem.doNotOptimizeAway(w.ptr);
            return c.built.rows.len;
        },
        .decode => {
            const d = dataset.deserialize(a, c.wire) catch @panic("bench-dataset: decode");
            return d.rows.len;
        },
        .col_f64 => {
            const v = c.table.floatColumn(a, "price") catch @panic("bench-dataset: col_f64");
            var s: f64 = 0;
            for (v) |x| s += x;
            return @intFromFloat(s);
        },
        .col_i64 => {
            const qi = c.table.columnIndex("qty").?;
            var s: i64 = 0;
            for (c.table.rows) |r| switch (r[qi]) {
                .int => |x| s += x,
                else => {},
            };
            return @intCast(s);
        },
        .col_text => {
            const ni = c.table.columnIndex("name").?;
            var s: u64 = 0;
            for (c.table.rows) |r| switch (r[ni]) {
                .text => |t| s += t.len,
                else => {},
            };
            return s;
        },
        .col_misc => {
            const ii = c.table.columnIndex("id").?;
            const ti = c.table.columnIndex("ts").?;
            const fi = c.table.columnIndex("flag").?;
            var s: u64 = 0;
            for (c.table.rows) |r| {
                s +%= @as(u64, @bitCast(r[ii].int));
                s +%= @as(u64, @bitCast(r[ti].int)) % 1009;
                if (r[fi].bool) s += 1;
            }
            return s;
        },
        .f_build => {
            var b = dataset.FrameBuilder.init(a, &columns, nrows) catch @panic("bench-dataset: f_build");
            var cells: [6]dataset.Value = undefined;
            for (0..nrows) |i| {
                cellsFor(c, i, &cells);
                b.appendRow(&cells) catch @panic("bench-dataset: f_build");
            }
            const f = b.toOwned() catch @panic("bench-dataset: f_build");
            return f.len;
        },
        .f_encode => {
            const w = dataset.serializeFrame(a, c.fbuilt) catch @panic("bench-dataset: f_encode");
            std.mem.doNotOptimizeAway(w.ptr);
            return c.fbuilt.len;
        },
        .f_decode => {
            const f = dataset.deserializeFrame(a, c.wire) catch @panic("bench-dataset: f_decode");
            return f.len;
        },
        .f_col_f64 => {
            const v = c.frame.floatColumn(a, "price") catch @panic("bench-dataset: f_col_f64");
            var s: f64 = 0;
            for (v) |x| s += x;
            return @intFromFloat(s);
        },
        .f_col_i64 => {
            const q = c.frame.column("qty").?.int;
            var s: i64 = 0;
            for (q.values) |x| s += x; // a null holds 0
            return @intCast(s);
        },
        .f_col_text => {
            const n = c.frame.column("name").?.text;
            return n.offsets[c.frame.len] - n.offsets[0];
        },
        .f_col_misc => {
            const ids = c.frame.column("id").?.int.values;
            const ts = c.frame.column("ts").?.int.values;
            const fl = c.frame.column("flag").?.bool.values;
            var s: u64 = 0;
            for (ids, ts, fl) |i, t, f| {
                s +%= @as(u64, @bitCast(i));
                s +%= @as(u64, @bitCast(t)) % 1009;
                if (f) s += 1;
            }
            return s;
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
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    var ctx: Ctx = .{ .work = .init(std.heap.page_allocator) };
    for (&ctx.names, 0..) |*n, i| n.* = try arena.print("item-{d}", .{(i * 2654435761) % 100000});
    ctx.built = try buildTable(&ctx, arena);
    ctx.wire = try dataset.serialize(arena, ctx.built);
    ctx.table = try dataset.deserialize(arena, ctx.wire);
    ctx.frame = try dataset.deserializeFrame(arena, ctx.wire);
    ctx.fbuilt = try dataset.Frame.fromDataset(arena, ctx.built);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const gota = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = "modules/dataset/tools/go_bench_gota", .abs = abs, .out = "go_bench_gota" });
    const W = bench.Work(Op);
    // Reference = gota (a boxed Element per cell; exe 1), fastest = Arrow Go
    // (exe 0), on the two column reads gota can do. Where gota has no such
    // operation (no wire format, no row-wise nullable builder) Arrow is the
    // only foreign side and its row is `fast_only`: it counts for the
    // `fastest` ratio, never for the reference's.
    const ws = [_]W{
        .{ .name = "build", .op = .build, .ref = "build", .fast_only = true },
        .{ .name = "encode", .op = .encode, .ref = "encode", .fast_only = true },
        .{ .name = "decode", .op = .decode, .ref = "decode", .fast_only = true },
        .{ .name = "col_f64", .op = .col_f64, .ref = "col_f64", .ref_exe = 1, .alt = "col_f64", .alt_exe = 0 },
        .{ .name = "col_i64", .op = .col_i64, .ref = "col_i64", .fast_only = true },
        .{ .name = "col_text", .op = .col_text, .ref = "col_text", .ref_exe = 1, .alt = "col_text", .alt_exe = 0 },
        .{ .name = "col_misc", .op = .col_misc, .ref = "col_misc", .fast_only = true },
        .{ .name = "f_build", .op = .f_build, .ref = "build", .fast_only = true },
        .{ .name = "f_encode", .op = .f_encode, .ref = "encode", .fast_only = true },
        .{ .name = "f_decode", .op = .f_decode, .ref = "decode", .fast_only = true },
        .{ .name = "f_col_f64", .op = .f_col_f64, .ref = "col_f64", .fast_only = true },
        .{ .name = "f_col_i64", .op = .f_col_i64, .ref = "col_i64", .fast_only = true },
        .{ .name = "f_col_text", .op = .f_col_text, .ref = "col_text", .fast_only = true },
        .{ .name = "f_col_misc", .op = .f_col_misc, .ref = "col_misc", .fast_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("ours wire bytes: {d} ({d} rows)\n", .{ ctx.wire.len, nrows });
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{ exe, gota },
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2}); worst ours/fastest = {d:.2}\n", .{ ref_short, s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× {s} (measured <today>)\n", .{ s.best_ref, s.worst_ref, ref_card, s.worst_fast orelse 0, fast_card });
    try w.flush();
    return 0;
}
