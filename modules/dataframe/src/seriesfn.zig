// SPDX-License-Identifier: MIT
//! Functions over one column (survey rows 62, 69, 87, 88, 89): run-length encoding,
//! peaks, autocorrelation, entropy, NaN-propagating extremes, `max_by`/`min_by`, the
//! distinct count, first/last valid position, `arg_true`/`arg_unique`, `asof` by a
//! sorted column, `extend_constant`. A `Series` is the module's view of one column; the
//! results are values, positions, or a new column. Semantics are pandas' and polars'
//! documented ones; original work of the zig-libs authors (MIT).

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const sp = @import("spec.zig");
const verbs = @import("verbs.zig");
const Column = vm.Column;
const Value = vm.Value;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const Series = fm.Series;
const isMissing = keys.isMissing;

pub const Error = sp.ColumnsError;

fn mustIndex(f: Frame, name: []const u8) Error!usize {
    return f.columnIndex(name) orelse error.NoSuchColumn;
}

/// The same cell for run-length purposes: missing equals missing (null with null, NaN
/// with NaN), numbers by value, other kinds by kind and value.
fn sameRun(x: Value, y: Value) bool {
    const xn = x == .float and std.math.isNan(x.float);
    const yn = y == .float and std.math.isNan(y.float);
    if (xn or yn) return xn and yn;
    if (x == .null or y == .null) return x == .null and y == .null;
    const xnum = x == .int or x == .float or x == .decimal;
    const ynum = y == .int or y == .float or y == .decimal;
    if (xnum != ynum) return false;
    if (!xnum and std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return x.order(y) == .eq;
}

fn appendColumn(a: std.mem.Allocator, f: Frame, col: Column, data: ColumnData) Error!Frame {
    if (f.columnIndex(col.name) != null) return error.DuplicateColumn;
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = col;
    const out = try a.alloc(ColumnData, w + 1);
    for (out[0..w], 0..) |*d, i| d.* = f.columnAt(i);
    out[w] = data;
    return .{ .columns = cols, .data = out, .len = f.len };
}

/// polars `rle`: one row per run of equal consecutive cells, columns `len` (int) and
/// `value` (the run's cell, the series' declared type).
pub fn rle(a: std.mem.Allocator, s: Series) Error!Frame {
    var lens: std.ArrayList(Value) = .empty;
    var vals: std.ArrayList(Value) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        const v = s.get(i);
        var j = i + 1;
        while (j < s.len and sameRun(s.get(j), v)) j += 1;
        try lens.append(a, .{ .int = @intCast(j - i) });
        try vals.append(a, v);
        i = j;
    }
    const cols = try a.dupe(Column, &.{ .{ .name = "len", .type = .int }, .{ .name = "value", .type = s.type } });
    const data = try a.alloc(ColumnData, 2);
    data[0] = try fm.columnFromCells(a, lens.items);
    data[1] = try fm.columnFromCells(a, vals.items);
    return .{ .columns = cols, .data = data, .len = lens.items.len };
}

/// polars `rle_id`: a run number per row, 0 for the first run, appended as `out`.
pub fn rleId(a: std.mem.Allocator, f: Frame, col: []const u8, out: []const u8) Error!Frame {
    const s = f.series(col) orelse return error.NoSuchColumn;
    const ids = try a.alloc(i64, f.len);
    var id: i64 = 0;
    for (ids, 0..) |*o, ri| {
        if (ri > 0 and !sameRun(s.get(ri), s.get(ri - 1))) id += 1;
        o.* = id;
    }
    return appendColumn(a, f, .{ .name = out, .type = .int }, .{ .int = .{ .values = ids } });
}

pub const Peak = enum { max, min };

/// polars `peak_max`/`peak_min`: a cell above (below) both its neighbours, at either end
/// the one neighbour there is. Three-valued as polars answers: a missing or non-numeric
/// cell is null, a comparison with a missing neighbour is unknown, and the cell is a peak
/// when no comparison is false and none is unknown. (polars 2.1 compares an END cell with
/// 0 instead of leaving the missing neighbour out, so there its answer depends on the
/// sign; and it counts NaN as the greatest number, this module as missing. Both differ
/// on purpose, `oracle2_test.zig`.)
pub fn peaks(a: std.mem.Allocator, f: Frame, col: []const u8, which: Peak, out: []const u8) Error!Frame {
    const s = f.series(col) orelse return error.NoSuchColumn;
    const cells = try a.alloc(Value, f.len);
    const num = struct {
        fn get(v: Value) ?f64 {
            if (isMissing(v)) return null;
            return v.asFloat();
        }
    }.get;
    for (cells, 0..) |*c, i| {
        const x = num(s.get(i)) orelse {
            c.* = .null;
            continue;
        };
        var unknown = false;
        var ok = f.len >= 2;
        for ([_]?usize{ if (i > 0) i - 1 else null, if (i + 1 < f.len) i + 1 else null }) |j| {
            const n = j orelse continue;
            const y = num(s.get(n)) orelse {
                unknown = true;
                continue;
            };
            ok = ok and (if (which == .max) x > y else x < y);
        }
        c.* = if (!ok) .{ .bool = false } else if (unknown) .null else .{ .bool = true };
    }
    return appendColumn(a, f, .{ .name = out, .type = .bool }, try fm.columnFromCells(a, cells));
}

/// pandas `Series.autocorr(lag)`: Pearson's correlation of `x[t]` with `x[t - lag]` over
/// the pairs where both are numbers; null below two pairs or with no variance.
pub fn autocorr(s: Series, lag: usize) ?f64 {
    if (lag >= s.len) return null;
    var n: f64 = 0;
    var mx: f64 = 0;
    var my: f64 = 0;
    var cxy: f64 = 0;
    var cxx: f64 = 0;
    var cyy: f64 = 0;
    for (lag..s.len) |t| {
        const xv = s.get(t);
        const yv = s.get(t - lag);
        if (isMissing(xv) or isMissing(yv)) continue;
        const x = xv.asFloat() orelse continue;
        const y = yv.asFloat() orelse continue;
        n += 1;
        const dx = x - mx;
        mx += dx / n;
        const dy = y - my;
        my += dy / n;
        cxy += dx * (y - my);
        cxx += dx * (x - mx);
        cyy += dy * (y - my);
    }
    if (n < 2 or cxx == 0 or cyy == 0) return null;
    return cxy / @sqrt(cxx * cyy);
}

/// polars `entropy(base, normalize)`: `-sum(p log p)` over the present numbers, `p` the
/// value over their sum when `normalize`, else the values themselves; null when there
/// are none or (normalized) they sum to 0.
pub fn entropy(s: Series, base: f64, normalize: bool) ?f64 {
    var sum: f64 = 0;
    var n: usize = 0;
    for (0..s.len) |i| {
        const v = s.get(i);
        if (isMissing(v)) continue;
        sum += v.asFloat() orelse continue;
        n += 1;
    }
    if (n == 0 or (normalize and sum == 0)) return null;
    var h: f64 = 0;
    for (0..s.len) |i| {
        const v = s.get(i);
        if (isMissing(v)) continue;
        const x = v.asFloat() orelse continue;
        const p = if (normalize) x / sum else x;
        if (p > 0) h -= p * @log(p);
    }
    return h / @log(base);
}

/// polars `nan_max`/`nan_min`: the extreme number, but NaN as soon as one cell is NaN
/// (null cells are skipped); null when there is no number.
pub fn nanExtreme(s: Series, which: Peak) Value {
    var best: Value = .null;
    for (0..s.len) |i| {
        const v = s.get(i);
        if (v == .float and std.math.isNan(v.float)) return v;
        if (v == .null or v.asFloat() == null) continue;
        if (best == .null) {
            best = v;
            continue;
        }
        const o = v.order(best);
        if ((which == .max and o == .gt) or (which == .min and o == .lt)) best = v;
    }
    return best;
}

/// polars `max_by`/`min_by`: the `col` cell of the first row where `by` is largest
/// (smallest) among its present values; null when `by` has none.
pub fn extremeBy(f: Frame, col: []const u8, by: []const u8, which: Peak) Error!Value {
    const c = f.series(col) orelse return error.NoSuchColumn;
    const b = f.series(by) orelse return error.NoSuchColumn;
    var best: ?usize = null;
    for (0..f.len) |i| {
        const v = b.get(i);
        if (isMissing(v)) continue;
        if (best) |k| {
            const o = v.order(b.get(k));
            if ((which == .max and o == .gt) or (which == .min and o == .lt)) best = i;
        } else best = i;
    }
    return if (best) |k| c.get(k) else .null;
}

/// Distinct cells (pandas `nunique`, polars `n_unique`; polars' `approx_n_unique` is the
/// same count, exact here). Missing cells count as one value when `count_missing`
/// (polars), not at all otherwise (pandas' `dropna=True`).
pub fn nUnique(a: std.mem.Allocator, f: Frame, col: []const u8, count_missing: bool) Error!usize {
    const ci = try mustIndex(f, col);
    const fac = try verbs.factorKeys(a, f, &.{ci});
    var n = fac.groups();
    if (!count_missing) {
        for (fac.firsts) |r| {
            if (isMissing(f.columnAt(ci).get(r))) n -= 1;
        }
    }
    return n;
}

/// pandas `first_valid_index`/`last_valid_index` over one column: the first (last) row
/// that is not missing.
pub fn firstValid(s: Series) ?usize {
    for (0..s.len) |i| if (!isMissing(s.get(i))) return i;
    return null;
}

pub fn lastValid(s: Series) ?usize {
    var i = s.len;
    while (i > 0) {
        i -= 1;
        if (!isMissing(s.get(i))) return i;
    }
    return null;
}

/// polars `arg_true`: the rows whose cell is `true`.
pub fn argTrue(a: std.mem.Allocator, s: Series) Error![]const usize {
    var out: std.ArrayList(usize) = .empty;
    for (0..s.len) |i| {
        const v = s.get(i);
        if (v == .bool and v.bool) try out.append(a, i);
    }
    return out.toOwnedSlice(a);
}

/// polars `arg_unique`: the first row of each distinct cell, in row order; missing
/// cells are one value.
pub fn argUnique(a: std.mem.Allocator, f: Frame, col: []const u8) Error![]const usize {
    const ci = try mustIndex(f, col);
    const fac = try verbs.factorKeys(a, f, &.{ci});
    const out = try a.alloc(usize, fac.groups());
    for (out, fac.firsts) |*o, r| o.* = r;
    return out;
}

/// pandas `Series.asof(where)` without an index: the last row whose cell in the sorted
/// (ascending) column `s` is at most `v`, missing cells skipped; null when none.
pub fn asofIndex(s: Series, v: Value) ?usize {
    if (isMissing(v)) return null;
    var lo: usize = 0;
    var hi: usize = s.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const c = s.get(mid);
        // Missing cells sort first as `Value.order` puts null; NaN would go last.
        const le = if (c == .null) true else if (isMissing(c)) false else c.order(v) != .gt;
        if (le) lo = mid + 1 else hi = mid;
    }
    var i = lo;
    while (i > 0) {
        i -= 1;
        if (!isMissing(s.get(i))) return i;
    }
    return null;
}

/// polars `extend_constant(value, n)`: the series and `n` more cells of `v`, as a new
/// column (the declared type kept).
pub fn extendConstant(a: std.mem.Allocator, s: Series, v: Value, n: usize) Error!Series {
    const total = std.math.add(usize, s.len, n) catch return error.TooLarge;
    if (total > sp.max_join_cells) return error.TooLarge;
    const cells = try a.alloc(Value, total);
    defer a.free(cells);
    for (cells[0..s.len], 0..) |*c, i| c.* = s.get(i);
    @memset(cells[s.len..], v);
    return .{ .name = s.name, .type = s.type, .data = try fm.columnFromCells(a, cells), .len = total };
}
