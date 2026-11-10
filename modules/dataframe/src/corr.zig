// SPDX-License-Identifier: MIT
//! The pairwise correlation and covariance matrices of a frame's numeric columns
//! (survey row 41): pandas `DataFrame.corr(method=, min_periods=)` and
//! `DataFrame.cov(min_periods=, ddof=)`, polars `DataFrame.corr()`.
//!
//! Each pair uses the rows where both cells are present (pandas' pairwise-complete
//! rule; polars `corr` has no missing values to skip). Missing is null or NaN, the
//! module's one rule. A pair with fewer than `min_periods` such rows, or none left after
//! `ddof`, is null; a column with no spread gives a NaN correlation (pandas). The result
//! is one row per column: a text column `column` with the names (pandas puts them in the
//! index; this module has none), then one float column per selected column, in order.
//! Original work of the zig-libs authors (MIT).

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const sp = @import("spec.zig");
const core = @import("core.zig");
const dtype = @import("dtype.zig");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;

pub const CorrError = sp.Error || error{
    /// A named column that is not int, float or decimal.
    NotNumeric,
    /// The result would name a column twice (`cols` lists one twice, or a column is
    /// called `column`).
    DuplicateColumn,
};

const Error = CorrError;

pub const CorrMethod = enum {
    /// Pearson's product-moment correlation (pandas and polars default).
    pearson,
    /// Spearman's rank correlation: Pearson's over the ranks, ties given their average
    /// rank, ranked per pair over its complete rows (pandas).
    spearman,
};

pub const CorrSpec = struct {
    /// Columns to correlate; empty = every int, float and decimal column.
    cols: []const []const u8 = &.{},
    method: CorrMethod = .pearson,
    /// Fewest complete rows a pair needs, else null (pandas `min_periods`; at least 1).
    min_periods: usize = 1,
};

pub const CovSpec = struct {
    cols: []const []const u8 = &.{},
    min_periods: usize = 1,
    /// Delta degrees of freedom: the sum of products is divided by `n - ddof`
    /// (pandas default 1, the sample covariance).
    ddof: u32 = 1,
};

/// Most element visits one call may make (pairs times rows): a frame of many columns
/// is a quadratic number of pairs. Past it `error.TooLarge`.
pub const max_corr_work: usize = 1 << 31;

/// Most cells of the result matrix (columns squared): a frame of no rows, or of one, has
/// `max_corr_work` room for 65 000 columns, whose matrix is billions of cells (sweep A-3).
/// 2^26, 8192 columns. Past it `error.TooLarge`.
pub const max_corr_cells: usize = 1 << 26;

const Stat = enum { corr, cov };

pub fn corr(a: std.mem.Allocator, f: Frame, spec: CorrSpec) Error!Frame {
    return matrix(a, f, spec.cols, spec.min_periods, .corr, spec.method, 0);
}

pub fn cov(a: std.mem.Allocator, f: Frame, spec: CovSpec) Error!Frame {
    return matrix(a, f, spec.cols, spec.min_periods, .cov, .pearson, spec.ddof);
}

fn isNumeric(t: ColumnType) bool {
    return dtype.isNumeric(t) or t == .decimal;
}

fn matrix(a: std.mem.Allocator, f: Frame, cols_in: []const []const u8, min_periods: usize, stat: Stat, method: CorrMethod, ddof: u32) Error!Frame {
    try core.checkRowsU32(f.len);
    var idx: std.ArrayList(usize) = .empty;
    if (cols_in.len == 0) {
        for (f.columns, 0..) |c, ci| if (isNumeric(c.type)) try idx.append(a, ci);
    } else {
        var names = try fm.NameIndex.init(a, f.columns);
        defer names.deinit(a);
        for (cols_in) |n| {
            const ci = names.get(n) orelse return error.NoSuchColumn;
            if (!isNumeric(f.columns[ci].type)) return error.NotNumeric;
            try idx.append(a, ci);
        }
    }
    const k = idx.items.len;
    const matrix_cells = std.math.mul(usize, k, k) catch return error.TooLarge;
    if (matrix_cells > max_corr_cells) return error.TooLarge;
    const pairs = std.math.mul(usize, k, k + 1) catch return error.TooLarge;
    const work = std.math.mul(usize, pairs / 2, f.len) catch return error.TooLarge;
    if (work > max_corr_work) return error.TooLarge;

    // The columns as floats, NaN for a missing cell (the one missing rule).
    const vals = try a.alloc([]f64, k);
    for (vals, idx.items) |*v, ci| {
        v.* = try a.alloc(f64, f.len);
        const col = f.columnAt(ci);
        for (v.*, 0..) |*x, ri| {
            const cell = col.get(ri);
            x.* = if (keys.isMissing(cell)) std.math.nan(f64) else cell.asFloat() orelse std.math.nan(f64);
        }
    }

    const out = try a.alloc([]Value, k);
    for (out) |*row| row.* = try a.alloc(Value, k);
    const xs = try a.alloc(f64, f.len);
    const ys = try a.alloc(f64, f.len);
    const order = try a.alloc(u32, f.len);
    const need = @max(min_periods, 1);
    for (0..k) |i| for (i..k) |j| {
        var n: usize = 0;
        for (vals[i], vals[j]) |x, y| {
            if (std.math.isNan(x) or std.math.isNan(y)) continue;
            xs[n] = x;
            ys[n] = y;
            n += 1;
        }
        const v: Value = blk: {
            if (n < need) break :blk .null;
            if (stat == .corr and method == .spearman) {
                rankAverage(xs[0..n], order[0..n]);
                rankAverage(ys[0..n], order[0..n]);
            }
            break :blk switch (stat) {
                .corr => .{ .float = pearson(xs[0..n], ys[0..n]) },
                .cov => if (n <= ddof) .null else .{ .float = comoment(xs[0..n], ys[0..n]) / @as(f64, @floatFromInt(n - ddof)) },
            };
        };
        out[i][j] = v;
        out[j][i] = v;
    };

    // `column` then one float column per selected column.
    const columns = try a.alloc(Column, k + 1);
    const data = try a.alloc(ColumnData, k + 1);
    columns[0] = .{ .name = "column", .type = .text };
    const name_cells = try a.alloc(Value, k);
    for (name_cells, idx.items) |*c, ci| c.* = .{ .text = f.columns[ci].name };
    data[0] = try fm.columnFromCells(a, name_cells);
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    try seen.put(a, "column", {});
    for (idx.items, 0..) |ci, j| {
        const name = f.columns[ci].name;
        if ((try seen.getOrPut(a, name)).found_existing) return error.DuplicateColumn;
        columns[j + 1] = .{ .name = name, .type = .float };
        const cells = try a.alloc(Value, k);
        for (cells, 0..) |*c, i| c.* = out[i][j];
        data[j + 1] = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = columns, .data = data, .len = k };
}

pub const CorrWithError = CorrError || error{
    /// The two frames have a different number of rows (pandas aligns on the row index and
    /// would take the common labels; this module has no index, so rows pair by position).
    LengthMismatch,
};

pub const CorrWithSpec = struct {
    /// Pearson (default) or Spearman, per column pair over its complete rows.
    method: CorrMethod = .pearson,
    /// pandas `drop`: only the columns both frames have; false lists every column of either
    /// frame, a one-sided one with a null correlation.
    drop: bool = false,
};

/// pandas `DataFrame.corrwith(other, axis=0, drop=, method=)` of two frames: each column
/// named in both is correlated with its namesake, row by position (pandas aligns on the row
/// index, which this module does not have: frames of different length are
/// `error.LengthMismatch`, not a common-label intersection; `other` is a frame, never a
/// Series; `axis=1` is not built). A pair uses the rows where both cells are present, like
/// `corr`; no complete row is null, no spread NaN. A column both frames have must be int,
/// float or decimal (`error.NotNumeric`; pandas raises `TypeError` on a text one). The
/// result is a frame of `column` (text) and `corr` (float): the shared columns in the left
/// frame's order, then (unless `drop`) the one-sided ones sorted by name, as pandas' Series
/// index, each with a null correlation (pandas NaN). Work is capped by `max_corr_work`.
pub fn corrWith(a: std.mem.Allocator, left: Frame, right: Frame, spec: CorrWithSpec) CorrWithError!Frame {
    try core.checkRowsU32(left.len);
    if (left.len != right.len) return error.LengthMismatch;
    var lnames = try fm.NameIndex.init(a, left.columns);
    defer lnames.deinit(a);
    var rnames = try fm.NameIndex.init(a, right.columns);
    defer rnames.deinit(a);

    const Row = struct { name: []const u8, li: ?usize, ri: ?usize };
    var rows: std.ArrayList(Row) = .empty;
    defer rows.deinit(a);
    for (left.columns, 0..) |c, li| {
        if (lnames.get(c.name) != li) continue; // a repeated name: the first column answers
        if (rnames.get(c.name)) |ri| try rows.append(a, .{ .name = c.name, .li = li, .ri = ri });
    }
    const shared = rows.items.len;
    if (!spec.drop) {
        for (left.columns, 0..) |c, li| {
            if (lnames.get(c.name) == li and rnames.get(c.name) == null) try rows.append(a, .{ .name = c.name, .li = li, .ri = null });
        }
        for (right.columns, 0..) |c, ri| {
            if (rnames.get(c.name) == ri and lnames.get(c.name) == null) try rows.append(a, .{ .name = c.name, .li = null, .ri = ri });
        }
        std.mem.sort(Row, rows.items[shared..], {}, struct {
            fn lt(_: void, x: Row, y: Row) bool {
                return std.mem.lessThan(u8, x.name, y.name);
            }
        }.lt);
    }
    const work = std.math.mul(usize, shared, left.len) catch return error.TooLarge;
    if (work > max_corr_work) return error.TooLarge;

    const names = try a.alloc(Value, rows.items.len);
    const outs = try a.alloc(Value, rows.items.len);
    const xs = try a.alloc(f64, left.len);
    const ys = try a.alloc(f64, left.len);
    const order = try a.alloc(u32, left.len);
    for (rows.items, names, outs, 0..) |r, *nc, *oc, k| {
        nc.* = .{ .text = r.name };
        oc.* = .null;
        if (k >= shared) continue;
        const lc = left.columns[r.li.?];
        const rc = right.columns[r.ri.?];
        if (!isNumeric(lc.type) or !isNumeric(rc.type)) return error.NotNumeric;
        const lcol = left.columnAt(r.li.?);
        const rcol = right.columnAt(r.ri.?);
        var n: usize = 0;
        for (0..left.len) |ri| {
            const x = lcol.get(ri);
            const y = rcol.get(ri);
            if (keys.isMissing(x) or keys.isMissing(y)) continue;
            const fx = x.asFloat() orelse continue;
            const fy = y.asFloat() orelse continue;
            if (std.math.isNan(fx) or std.math.isNan(fy)) continue;
            xs[n] = fx;
            ys[n] = fy;
            n += 1;
        }
        if (n < 1) continue;
        if (spec.method == .spearman) {
            rankAverage(xs[0..n], order[0..n]);
            rankAverage(ys[0..n], order[0..n]);
        }
        oc.* = .{ .float = pearson(xs[0..n], ys[0..n]) };
    }
    const columns = try a.alloc(Column, 2);
    columns[0] = .{ .name = "column", .type = .text };
    columns[1] = .{ .name = "corr", .type = .float };
    const data = try a.alloc(ColumnData, 2);
    data[0] = try fm.columnFromCells(a, names);
    data[1] = try fm.columnFromCells(a, outs);
    return .{ .columns = columns, .data = data, .len = rows.items.len };
}

/// Sum of (x - mean x)(y - mean y), two passes (the means first), as numpy and pandas.
/// Also the window `rolling_cov`'s numerics.
pub fn comoment(xs: []const f64, ys: []const f64) f64 {
    const n: f64 = @floatFromInt(xs.len);
    var mx: f64 = 0;
    var my: f64 = 0;
    for (xs, ys) |x, y| {
        mx += x;
        my += y;
    }
    mx /= n;
    my /= n;
    var s: f64 = 0;
    for (xs, ys) |x, y| s += (x - mx) * (y - my);
    return s;
}

/// Pearson's r of two equally long slices, two-pass; NaN when a side has no spread.
/// Also the window `rolling_corr`'s numerics.
pub fn pearson(xs: []const f64, ys: []const f64) f64 {
    const n: f64 = @floatFromInt(xs.len);
    var mx: f64 = 0;
    var my: f64 = 0;
    for (xs, ys) |x, y| {
        mx += x;
        my += y;
    }
    mx /= n;
    my /= n;
    var sxy: f64 = 0;
    var sxx: f64 = 0;
    var syy: f64 = 0;
    for (xs, ys) |x, y| {
        const dx = x - mx;
        const dy = y - my;
        sxy += dx * dy;
        sxx += dx * dx;
        syy += dy * dy;
    }
    // No spread on a side: 0 / 0, NaN (pandas). Clamped into [-1, 1] against rounding.
    const r = sxy / @sqrt(sxx * syy);
    return if (std.math.isNan(r)) r else std.math.clamp(r, -1, 1);
}

/// Replaces `v` by its ranks (1-based, ties their average) in place; `order` is scratch
/// of the same length.
fn rankAverage(v: []f64, order: []u32) void {
    for (order, 0..) |*o, i| o.* = @intCast(i); // `checkRowsU32` holds the length
    std.mem.sortUnstable(u32, order, v, struct {
        fn lt(vals: []f64, l: u32, r: u32) bool {
            return vals[l] < vals[r] or (vals[l] == vals[r] and l < r);
        }
    }.lt);
    var i: usize = 0;
    // A run's ranks are written once the run is known; later runs read other entries.
    while (i < order.len) {
        var j = i + 1;
        const x = v[order[i]];
        while (j < order.len and v[order[j]] == x) j += 1;
        const r = (@as(f64, @floatFromInt(i + 1)) + @as(f64, @floatFromInt(j))) / 2;
        for (order[i..j]) |o| v[o] = r;
        i = j;
    }
}
