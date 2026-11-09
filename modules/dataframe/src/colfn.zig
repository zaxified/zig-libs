// SPDX-License-Identifier: MIT
//! Column and frame functions of dataframe S2 wave W3: `item`, `uniqueCounts`, `hist`
//! (polars `Series.item`/`unique_counts`/`hist`), the callback folds across columns
//! (`foldColumns` = polars `fold`/`reduce`, pandas `df.apply(axis=1)` with a running value;
//! `cumFoldColumns` = `cum_fold`/`cum_reduce`; `cumSumHorizontal`) and `alignFrames`
//! (polars `align_frames`). The data-only fold over the binary operators is
//! `Expr.fold`. Original work of the zig-libs authors (MIT); the engines' documentation
//! was read, no source.

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const sp = @import("spec.zig");
const verbs = @import("verbs.zig");
const st = @import("structure.zig");
const callback = @import("callback.zig");
const expr = @import("expr.zig");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const Value = vm.Value;

/// `error.NotOneValue`: `item` over something that is not exactly one value (polars
/// raises `ValueError`, pandas `Series.item()` too). `error.BadArgument`: bin edges not
/// ascending or fewer than two, a bin count of 0, an empty `on`.
pub const ColfnError = st.StructureError || verbs.Error || error{ NotOneValue, BadArgument };

fn mustIndex(f: Frame, name: []const u8) ColfnError!usize {
    return f.columnIndex(name) orelse error.NoSuchColumn;
}

// ── item, unique_counts ──────────────────────────────────────────────────────

/// polars `DataFrame.item()` / `Series.item()`, pandas `Series.item()`: the one value of a
/// frame of one row and one column (`col` null), or of the one row of column `col`. Any
/// other shape is `error.NotOneValue`. The value borrows from the frame.
pub fn item(f: Frame, col: ?[]const u8) ColfnError!Value {
    if (f.len != 1) return error.NotOneValue;
    if (col) |c| return f.columnAt(try mustIndex(f, c)).get(0);
    if (f.columns.len != 1) return error.NotOneValue;
    return f.columnAt(0).get(0);
}

/// polars `unique_counts`: how often each distinct value of `col` occurs, in order of first
/// appearance; a null (or NaN) is one value. One `.int` column named `col`.
pub fn uniqueCounts(a: std.mem.Allocator, f: Frame, col: []const u8) ColfnError!Frame {
    const ci = try mustIndex(f, col);
    const fac = try verbs.factorKeys(a, f, &.{ci});
    const counts = try a.alloc(i64, fac.groups());
    @memset(counts, 0);
    for (fac.ids) |g| counts[g] += 1;
    const cols = try a.alloc(Column, 1);
    cols[0] = .{ .name = f.columns[ci].name, .type = .int };
    const data = try a.alloc(ColumnData, 1);
    data[0] = .{ .int = .{ .values = counts } };
    return .{ .columns = cols, .data = data, .len = counts.len };
}

// ── hist ─────────────────────────────────────────────────────────────────────

pub const HistSpec = struct {
    col: []const u8,
    /// Ascending bin edges, at least two (`edges.len - 1` bins). Empty: `bin_count` equal
    /// bins between the column's smallest and largest value.
    bins: []const f64 = &.{},
    bin_count: usize = 10,
    /// The `breakpoint` column: the bin's right edge.
    include_breakpoint: bool = true,
    /// The `category` column: the bin as text, `[lo, hi]` for the first and `(lo, hi]` for
    /// the others.
    include_category: bool = true,
};

/// Most bins `hist` builds.
pub const max_hist_bins: usize = 1 << 20;

fn numberText(a: std.mem.Allocator, x: f64) std.mem.Allocator.Error![]const u8 {
    // polars labels bins with up to six decimals, trailing zeros trimmed down to one.
    const t = try a.print("{d:.6}", .{x});
    if (std.mem.findScalar(u8, t, '.') == null) return t;
    var end = t.len;
    while (end > 0 and t[end - 1] == '0' and t[end - 2] != '.') end -= 1;
    return t[0..end];
}

/// polars `Series.hist(bins, bin_count, include_category, include_breakpoint)`: the
/// numeric cells of `spec.col` counted per bin, bins closed on the right except the first,
/// which also takes its left edge. Columns `breakpoint` (float), `category` (text) and
/// `count` (int). A cell that is missing, not a number or outside every bin is not counted.
/// With `bin_count` and one distinct value the edges are that value -/+ 0.5 (polars); with
/// no values at all they are 0 to 1. The category's numbers print with up to six decimals, as polars
/// does (`2.0`, `3.333333`).
pub fn hist(a: std.mem.Allocator, f: Frame, spec: HistSpec) ColfnError!Frame {
    const ci = try mustIndex(f, spec.col);
    const col = f.columnAt(ci);
    var edges: []f64 = undefined;
    if (spec.bins.len > 0) {
        if (spec.bins.len < 2 or spec.bins.len - 1 > max_hist_bins) return error.BadArgument;
        for (spec.bins[0 .. spec.bins.len - 1], spec.bins[1..]) |l, r| if (!(l < r)) return error.BadArgument;
        edges = try a.dupe(f64, spec.bins);
    } else {
        if (spec.bin_count == 0 or spec.bin_count > max_hist_bins) return error.BadArgument;
        var lo: f64 = std.math.inf(f64);
        var hi: f64 = -std.math.inf(f64);
        for (0..f.len) |ri| {
            const v = col.get(ri);
            if (keys.isMissing(v)) continue;
            const x = v.asFloat() orelse continue;
            lo = @min(lo, x);
            hi = @max(hi, x);
        }
        if (lo <= hi and !(std.math.isFinite(lo) and std.math.isFinite(hi))) return error.BadArgument;
        // Finite ends whose distance overflows (-1e308 .. 1e308) would make NaN edges.
        if (lo <= hi and !std.math.isFinite(hi - lo)) return error.BadArgument;
        if (lo > hi) {
            lo = 0;
            hi = 1;
        } else if (lo == hi) {
            lo -= 0.5;
            hi += 0.5;
        }
        edges = try a.alloc(f64, spec.bin_count + 1);
        const n: f64 = @floatFromInt(spec.bin_count);
        for (edges, 0..) |*e, i| e.* = lo + @as(f64, @floatFromInt(i)) * ((hi - lo) / n);
        edges[spec.bin_count] = hi;
    }
    const nbins = edges.len - 1;
    const counts = try a.alloc(i64, nbins);
    @memset(counts, 0);
    for (0..f.len) |ri| {
        const v = col.get(ri);
        if (keys.isMissing(v)) continue;
        const x = v.asFloat() orelse continue;
        if (x < edges[0] or x > edges[nbins]) continue;
        // The first edge at or above x is e[b + 1] for x in (e[b], e[b + 1]]; x == e[0] falls in bin 0.
        var lo: usize = 0;
        var hi: usize = edges.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (edges[mid] < x) lo = mid + 1 else hi = mid;
        }
        const b = if (lo == 0) 0 else lo - 1;
        counts[@min(b, nbins - 1)] += 1;
    }
    var cols: std.ArrayList(Column) = .empty;
    var data: std.ArrayList(ColumnData) = .empty;
    if (spec.include_breakpoint) {
        try cols.append(a, .{ .name = "breakpoint", .type = .float });
        try data.append(a, .{ .float = .{ .values = edges[1..] } });
    }
    if (spec.include_category) {
        const cells = try a.alloc(Value, nbins);
        defer a.free(cells);
        for (cells, 0..) |*c, i| {
            const open: []const u8 = if (i == 0) "[" else "(";
            c.* = .{ .text = try std.mem.concat(a, u8, &.{ open, try numberText(a, edges[i]), ", ", try numberText(a, edges[i + 1]), "]" }) };
        }
        try cols.append(a, .{ .name = "category", .type = .text });
        try data.append(a, try fm.columnFromCells(a, cells));
    }
    try cols.append(a, .{ .name = "count", .type = .int });
    try data.append(a, .{ .int = .{ .values = counts } });
    return .{ .columns = cols.items, .data = data.items, .len = nbins };
}

// ── folds across columns ─────────────────────────────────────────────────────

pub const FoldSpec = struct {
    /// The columns folded, in this order; empty = every column.
    cols: []const []const u8 = &.{},
    /// The result column: replaced in place when the frame has one of that name, else
    /// appended.
    out: []const u8,
    /// polars `fold(acc, ...)`: the start value. null starts with the first column
    /// (polars `reduce`).
    acc: ?Value = null,
    /// The result type (as `MapRowsSpec.type`); null = the cells decide.
    type: ?ColumnType = null,
};

fn foldIdxs(a: std.mem.Allocator, f: Frame, cols: []const []const u8) ColfnError![]const usize {
    if (cols.len == 0) {
        const all = try a.alloc(usize, f.columns.len);
        for (all, 0..) |*x, i| x.* = i;
        return all;
    }
    const out = try a.alloc(usize, cols.len);
    for (out, cols) |*x, c| x.* = try mustIndex(f, c);
    return out;
}

/// polars `fold(acc, function, exprs)` / `reduce(function, exprs)`, with the caller's own
/// function: per row, `acc = func(ctx, a, acc, cell)` over the columns in order. `func`:
/// `fn (C, std.mem.Allocator, acc: Value, cell: Value) E!Value`. With no start value the
/// first column's cell starts; a frame with no columns gives null. Nulls are handed to
/// `func` as they are (polars' `fold` does the same). For the binary operators as data see
/// `Expr.fold`.
pub fn foldColumns(a: std.mem.Allocator, f: Frame, spec: FoldSpec, ctx: anytype, comptime func: anytype) (callback.ErrorOf(func) || ColfnError)!Frame {
    const E = callback.ErrorOf(func);
    const idxs = try foldIdxs(a, f, spec.cols);
    const W = struct {
        user: @TypeOf(ctx),
        idxs: []const usize,
        acc: ?Value,
        fn call(w: @This(), al: std.mem.Allocator, row: callback.Row) E!Value {
            var acc = w.acc;
            for (w.idxs) |ci| {
                const x = row.at(ci);
                acc = if (acc) |ac| try @as(E!Value, func(w.user, al, ac, x)) else x;
            }
            return acc orelse .null;
        }
    };
    return callback.mapRows(a, f, .{ .out = spec.out, .type = spec.type }, W{ .user = ctx, .idxs = idxs, .acc = spec.acc }, W.call);
}

pub const CumFoldSpec = struct {
    /// The columns folded, in this order; empty = every column.
    cols: []const []const u8 = &.{},
    /// The start value; null = the first column starts.
    acc: ?Value = null,
};

/// polars `cum_fold` / `cum_reduce`: the running value after each column, a column per
/// folded column (named after it; polars returns them as one struct column). Row by row,
/// `acc = func(ctx, a, acc, cell)`; with `acc` null the first column's cell is the first
/// running value, with a start value the first column already folds it in. Result types
/// come from the cells.
pub fn cumFoldColumns(a: std.mem.Allocator, f: Frame, spec: CumFoldSpec, ctx: anytype, comptime func: anytype) (callback.ErrorOf(func) || ColfnError)!Frame {
    const E = callback.ErrorOf(func);
    try @import("core.zig").checkRowsU32(f.len);
    const idxs = try foldIdxs(a, f, spec.cols);
    const builders = try a.alloc(fm.ColBuilder, idxs.len);
    for (builders) |*b| b.* = .{ .a = a, .hint = @min(f.len, fm.max_row_hint) };
    for (0..f.len) |ri| {
        var acc = spec.acc;
        for (idxs, builders) |ci, *b| {
            const x = f.columnAt(ci).get(ri);
            acc = if (acc) |ac| try @as(E!Value, func(ctx, a, ac, x)) else x;
            try b.append(acc.?);
        }
    }
    const cols = try a.alloc(Column, idxs.len);
    const data = try a.alloc(ColumnData, idxs.len);
    for (cols, data, builders, idxs) |*c, *d, *b, ci| {
        d.* = b.finish();
        c.* = .{ .name = f.columns[ci].name, .type = switch (d.*) {
            .nulls, .float => .float,
            .int => .int,
            .bool => .bool,
            .decimal => .decimal,
            .text, .boxed => .text,
            .categorical => .categorical,
            .list => .list,
            .@"struct" => .@"struct",
        } };
    }
    return .{ .columns = cols, .data = data, .len = f.len };
}

fn addCells(_: void, a: std.mem.Allocator, acc: Value, x: Value) expr.ExprError!Value {
    return expr.binaryValue(a, .add, acc, x);
}

/// polars `cum_sum_horizontal(*columns)`: per row the running sum across `cols`. A null (or
/// NaN) cell makes the running sum null from there on (polars' result, nulls propagate;
/// `horizontal(.sum)` skips them instead). Int sums that overflow are null. Columns named
/// after the inputs, as `cumFoldColumns`.
pub fn cumSumHorizontal(a: std.mem.Allocator, f: Frame, cols: []const []const u8) (expr.ExprError || ColfnError || callback.CallbackError)!Frame {
    return cumFoldColumns(a, f, .{ .cols = cols }, {}, addCells);
}

// ── align_frames ─────────────────────────────────────────────────────────────

pub const AlignSpec = struct {
    /// The key columns every frame has; the result frames hold every key found in any of
    /// them.
    on: []const []const u8,
    /// Sort the keys descending.
    reverse: bool = false,
};

/// polars `align_frames(*frames, on=, reverse=)`: every frame re-indexed to the sorted union
/// of the key values of all of them; a key a frame lacks gets a row of nulls in its other
/// columns. The key columns come first. A frame with a repeated key repeats that row, as the
/// left join it is built from. Key columns must have the same type in every frame
/// (`error.SchemaMismatch`).
pub fn alignFrames(a: std.mem.Allocator, frames: []const Frame, spec: AlignSpec) ColfnError![]const Frame {
    if (spec.on.len == 0) return error.BadArgument;
    const out = try a.alloc(Frame, frames.len);
    if (frames.len == 0) return out;
    const key_frames = try a.alloc(Frame, frames.len);
    for (key_frames, frames) |*k, fr| k.* = try verbs.select(a, fr, spec.on);
    const all = try st.concat(a, key_frames, .vertical);
    const uniq = try verbs.distinct(a, all, .{ .keys = spec.on });
    const then = try a.alloc(sp.SortKey, spec.on.len - 1);
    const dir: sp.SortDir = if (spec.reverse) .desc else .asc;
    for (then, spec.on[1..]) |*t, k| t.* = .{ .key = k, .dir = dir };
    const sorted = try verbs.sort(a, uniq, .{ .key = spec.on[0], .dir = dir, .then_by = then });
    for (out, frames) |*o, fr| o.* = try verbs.joinChecked(a, sorted, fr, .{ .keys = spec.on, .how = .left });
    return out;
}
