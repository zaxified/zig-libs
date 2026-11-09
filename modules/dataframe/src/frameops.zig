// SPDX-License-Identifier: MIT
//! Whole-frame operations and time windows (survey rows 19, 20, 26, 51): arithmetic
//! between frames and with a scalar, `compare`, `dot`, interpolation by another column
//! or to the nearest value, `group_by_dynamic` / sub-daily `resample`, and `upsample`.
//! Rows have no labels here, so "aligned" means by row position and column name; each
//! verb says where that departs from pandas' index alignment. Original work of the
//! zig-libs authors (MIT).

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const core = @import("core.zig");
const sp = @import("spec.zig");
const verbs = @import("verbs.zig");
const ex = @import("expr.zig");
const dtf = @import("dtfn.zig");
const rs = @import("reshape.zig");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const isMissing = keys.isMissing;

pub const FrameOpsError = sp.ColumnsError || error{
    /// Frames whose shape or columns the verb needs to agree, and do not.
    SchemaMismatch,
    /// An operator that is not arithmetic, a duration that is not one, an unusable
    /// argument.
    BadArgument,
};

const Error = FrameOpsError;

fn mustIndex(f: Frame, name: []const u8) Error!usize {
    return f.columnIndex(name) orelse error.NoSuchColumn;
}

fn checkRows(f: Frame) Error!void {
    return core.checkRowsU32(f.len);
}

fn isArith(op: ex.Binary) bool {
    return switch (op) {
        .add, .sub, .mul, .div, .floordiv, .mod, .pow, .min, .max => true,
        else => false,
    };
}

/// The declared type of a column of arithmetic results: one numeric kind is that kind,
/// a float among them float, decimal with int decimal; none `.float`.
fn resultType(cells: []Value) ColumnType {
    var int = false;
    var float = false;
    var dec = false;
    for (cells) |c| switch (c) {
        .int => int = true,
        .float => float = true,
        .decimal => dec = true,
        else => {},
    };
    if (float) {
        for (cells) |*c| {
            // Read before the write: `c.* = .{ ... c ... }` writes the tag into `c.*` first
            // (result location), and the read then sees the new tag (finding MA, D5).
            if (c.* == .int or c.* == .decimal) {
                const x = c.asFloat().?;
                c.* = .{ .float = x };
            }
        }
        return .float;
    }
    if (dec) {
        for (cells) |*c| {
            if (c.* == .int) {
                const x: i128 = c.int;
                c.* = .{ .decimal = x * vm.decimal_scale };
            }
        }
        return .decimal;
    }
    return if (int) .int else .float;
}

fn binary(a: std.mem.Allocator, op: ex.Binary, l: Value, r: Value) Error!Value {
    return ex.binaryValue(a, op, l, r) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.TooLarge,
    };
}

pub const ArithSpec = struct {
    /// Used for a cell missing on one side only (pandas' `fill_value`); a cell missing
    /// on both stays missing. null: a missing operand gives null.
    fill_value: ?Value = null,
};

/// `f op g` cell by cell (pandas `df.add(other)`, `df1 + df2`, … `pow`; polars'
/// frame operators): columns matched by name, `f`'s order then `g`'s new ones (pandas
/// sorts a union that differs; polars needs equal schemas), rows by position up to the
/// longer frame. A column or row only one side has is null (unless `fill_value`).
/// `Expr`'s arithmetic: int op int stays int, overflow null, `div` and `pow` float.
pub fn arith(a: std.mem.Allocator, f: Frame, g: Frame, op: ex.Binary, spec: ArithSpec) Error!Frame {
    if (!isArith(op)) return error.BadArgument;
    try checkRows(f);
    try checkRows(g);
    const rows = @max(f.len, g.len);
    var f_names = try fm.NameIndex.init(a, f.columns);
    defer f_names.deinit(a);
    var g_names = try fm.NameIndex.init(a, g.columns);
    defer g_names.deinit(a);
    var names: std.ArrayList([]const u8) = .empty;
    for (f.columns) |c| try names.append(a, c.name);
    for (g.columns) |c| if (f_names.get(c.name) == null) try names.append(a, c.name);
    // The shorter frame is padded with nulls: width x height may outgrow the inputs, capped.
    try verbs.growthWithin(
        std.math.mul(usize, names.items.len, rows) catch return error.TooLarge,
        (f.columns.len *| f.len) +| (g.columns.len *| g.len),
    );
    const cols = try a.alloc(Column, names.items.len);
    const data = try a.alloc(ColumnData, names.items.len);
    const cells = try a.alloc(Value, rows);
    defer a.free(cells);
    for (names.items, cols, data) |n, *c, *d| {
        const fi = f_names.get(n);
        const gi = g_names.get(n);
        for (cells, 0..) |*o, ri| {
            var l: Value = if (fi != null and ri < f.len) f.columnAt(fi.?).get(ri) else .null;
            var r: Value = if (gi != null and ri < g.len) g.columnAt(gi.?).get(ri) else .null;
            if (spec.fill_value) |fv| {
                if (isMissing(l) and !isMissing(r)) l = fv;
                if (isMissing(r) and !isMissing(l)) r = fv;
            }
            o.* = try binary(a, op, l, r);
        }
        c.* = .{ .name = n, .type = resultType(cells) };
        d.* = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cols, .data = data, .len = rows };
}

pub const ArithScalarSpec = struct {
    /// Columns to compute; empty = every numeric (`.int`, `.float`, `.decimal`) column.
    /// The others are kept as they are.
    cols: []const []const u8 = &.{},
    /// `value op cell` (pandas `radd`, `rsub`, …) rather than `cell op value`.
    reverse: bool = false,
};

/// Every chosen column `op value` (pandas `df + 1`, `df.mul(2)`, `df.rsub(1)`).
pub fn arithScalar(a: std.mem.Allocator, f: Frame, op: ex.Binary, value: Value, spec: ArithScalarSpec) Error!Frame {
    if (!isArith(op)) return error.BadArgument;
    const pick = try a.alloc(bool, f.columns.len);
    defer a.free(pick);
    for (pick, f.columns) |*p, c| p.* = spec.cols.len == 0 and (c.type == .int or c.type == .float or c.type == .decimal);
    for (spec.cols) |n| pick[try mustIndex(f, n)] = true;
    const cols = try a.dupe(Column, f.columns);
    const data = try a.alloc(ColumnData, f.columns.len);
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (data, 0..) |*d, ci| {
        d.* = f.columnAt(ci);
        if (!pick[ci]) continue;
        for (cells, 0..) |*o, ri| {
            const v = f.columnAt(ci).get(ri);
            o.* = if (spec.reverse) try binary(a, op, value, v) else try binary(a, op, v, value);
        }
        cols[ci].type = resultType(cells);
        d.* = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cols, .data = data, .len = f.len };
}

fn sameCell(x: Value, y: Value) bool {
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

/// pandas `compare(other)`: the cells that differ. Both frames must have the same
/// column names in the same order and the same length (`error.SchemaMismatch`, as
/// pandas raises). The output has `row` (the position), then `{column}_self` and
/// `{column}_other` for each column with a difference (pandas' two-level columns,
/// flattened), only the rows with one; an equal cell there is null. NaN equals NaN.
pub fn compare(a: std.mem.Allocator, f: Frame, g: Frame) Error!Frame {
    try checkRows(f);
    if (f.len != g.len or f.columns.len != g.columns.len) return error.SchemaMismatch;
    for (f.columns, g.columns) |x, y| if (!std.mem.eql(u8, x.name, y.name)) return error.SchemaMismatch;
    const diff_col = try a.alloc(bool, f.columns.len);
    @memset(diff_col, false);
    var rows: std.ArrayList(usize) = .empty;
    for (0..f.len) |ri| {
        var any = false;
        for (0..f.columns.len) |ci| {
            if (!sameCell(f.columnAt(ci).get(ri), g.columnAt(ci).get(ri))) {
                diff_col[ci] = true;
                any = true;
            }
        }
        if (any) try rows.append(a, ri);
    }
    var cols: std.ArrayList(Column) = .empty;
    var data: std.ArrayList(ColumnData) = .empty;
    const cells = try a.alloc(Value, rows.items.len);
    defer a.free(cells);
    for (cells, rows.items) |*c, r| c.* = .{ .int = @intCast(r) };
    try cols.append(a, .{ .name = "row", .type = .int });
    try data.append(a, try fm.columnFromCells(a, cells));
    for (f.columns, 0..) |c, ci| {
        if (!diff_col[ci]) continue;
        inline for (.{ "_self", "_other" }, 0..) |suffix, side| {
            for (cells, rows.items) |*o, r| {
                const x = f.columnAt(ci).get(r);
                const y = g.columnAt(ci).get(r);
                o.* = if (sameCell(x, y)) .null else if (side == 0) x else y;
            }
            try cols.append(a, .{ .name = try std.mem.concat(a, u8, &.{ c.name, suffix }), .type = c.type });
            try data.append(a, try fm.columnFromCells(a, cells));
        }
    }
    try keys.uniqueNames(a, cols.items);
    return .{ .columns = cols.items, .data = data.items, .len = rows.items.len };
}

/// pandas `df.dot(other)`: the matrix product of `f`'s columns (`f.len x k`) with
/// `g` (`k` rows, one per column of `f`, by position: no index to align), one float
/// column per column of `g`. A missing or non-numeric cell is NaN and spreads, as in
/// numpy. At most `max_aggregate_cells` output cells and as many multiply-adds per
/// output row.
pub fn dot(a: std.mem.Allocator, f: Frame, g: Frame) Error!Frame {
    if (g.len != f.columns.len) return error.SchemaMismatch;
    const n_out = std.math.mul(usize, f.len, g.columns.len) catch return error.TooLarge;
    if (n_out > sp.max_aggregate_cells) return error.TooLarge;
    const work = std.math.mul(usize, n_out, @max(f.columns.len, 1)) catch return error.TooLarge;
    if (work > 1 << 30) return error.TooLarge;
    const x = rs.toFloatMatrix(a, f, &.{}) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.TooLarge,
    };
    const y = rs.toFloatMatrix(a, g, &.{}) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.TooLarge,
    };
    const k = f.columns.len;
    const m = g.columns.len;
    const cols = try a.alloc(Column, m);
    const data = try a.alloc(ColumnData, m);
    for (0..m) |j| {
        const out = try a.alloc(f64, f.len);
        for (out, 0..) |*o, i| {
            var s: f64 = 0;
            for (0..k) |p| s += x.data[i * k + p] * y.data[p * m + j];
            o.* = s;
        }
        cols[j] = .{ .name = g.columns[j].name, .type = .float };
        data[j] = .{ .float = .{ .values = out } };
    }
    return .{ .columns = cols, .data = data, .len = f.len };
}

// ── interpolation ───────────────────────────────────────────────────────────

pub const InterpolateSpec = struct {
    col: []const u8,
    /// `linear`: on a straight line between the present neighbours, by row position or,
    /// with `by`, by that column's values (polars `interpolate_by`, pandas
    /// `method="values"`/`"time"`); `nearest`: the nearest present value (a tie takes
    /// the earlier, as scipy's `nearest`).
    method: enum { linear, nearest } = .linear,
    /// The x of each row: a numeric or temporal column; null = the row position.
    by: ?[]const u8 = null,
    /// The output column; null replaces `col`.
    out: ?[]const u8 = null,
};

const Pt = struct { x: f64, y: f64 };

fn ptLess(_: void, l: Pt, r: Pt) bool {
    return l.x < r.x;
}

fn xOf(v: Value) ?f64 {
    if (isMissing(v)) return null;
    if (v.asFloat()) |x| return x;
    return if (dtf.instantOf(v)) |us| @floatFromInt(us) else null;
}

/// Fill the missing numbers of `col` from the present ones; a gap before the first or
/// after the last present x stays null (polars; pandas' `limit_direction` default fills
/// the trailing gap by repeating). The output is float.
pub fn interpolate(a: std.mem.Allocator, f: Frame, spec: InterpolateSpec) Error!Frame {
    try checkRows(f);
    const ci = try mustIndex(f, spec.col);
    const bi: ?usize = if (spec.by) |b| try mustIndex(f, b) else null;
    var pts: std.ArrayList(Pt) = .empty;
    defer pts.deinit(a);
    const ys = f.columnAt(ci);
    for (0..f.len) |ri| {
        const v = ys.get(ri);
        if (isMissing(v)) continue;
        const y = v.asFloat() orelse continue;
        const x = if (bi) |b| xOf(f.columnAt(b).get(ri)) orelse continue else @as(f64, @floatFromInt(ri));
        try pts.append(a, .{ .x = x, .y = y });
    }
    std.mem.sort(Pt, pts.items, {}, ptLess);
    const out = try a.alloc(Value, f.len);
    defer a.free(out);
    for (out, 0..) |*o, ri| {
        const v = ys.get(ri);
        if (!isMissing(v) and v.asFloat() != null) {
            o.* = .{ .float = v.asFloat().? };
            continue;
        }
        o.* = .null;
        const x = if (bi) |b| xOf(f.columnAt(b).get(ri)) orelse continue else @as(f64, @floatFromInt(ri));
        const p = pts.items;
        if (p.len == 0 or x < p[0].x or x > p[p.len - 1].x) continue;
        // First point with x >= this x.
        var lo: usize = 0;
        var hi: usize = p.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (p[mid].x < x) lo = mid + 1 else hi = mid;
        }
        if (p[lo].x == x) {
            o.* = .{ .float = p[lo].y };
            continue;
        }
        const l = p[lo - 1];
        const r = p[lo];
        o.* = .{ .float = switch (spec.method) {
            .linear => l.y + (r.y - l.y) * (x - l.x) / (r.x - l.x),
            .nearest => if (x - l.x <= r.x - x) l.y else r.y,
        } };
    }
    const name = spec.out orelse spec.col;
    const data = try fm.columnFromCells(a, out);
    if (f.columnIndex(name)) |oi| {
        const cols = try a.dupe(Column, f.columns);
        cols[oi].type = .float;
        const d = try a.alloc(ColumnData, f.columns.len);
        for (d, 0..) |*x, i| x.* = f.columnAt(i);
        d[oi] = data;
        return .{ .columns = cols, .data = d, .len = f.len };
    }
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = .{ .name = name, .type = .float };
    const d = try a.alloc(ColumnData, w + 1);
    for (d[0..w], 0..) |*x, i| x.* = f.columnAt(i);
    d[w] = data;
    return .{ .columns = cols, .data = d, .len = f.len };
}

// ── time windows ────────────────────────────────────────────────────────────

pub const DynamicSpec = struct {
    /// The temporal column (see `dtfn`: microsecond ints or ISO text).
    index: []const u8,
    /// Window length and step, a polars duration (`"1h"`, `"15m"`, `"1mo"`): windows
    /// `[start, start + every)` from 1970-01-01 (weeks from Monday), labelled by their
    /// start in the index column (polars' `closed="left"`, `label="left"`).
    every: []const u8,
    /// Group columns before the window (polars `group_by`).
    by: []const []const u8 = &.{},
    aggs: []const sp.AggCol,
};

/// polars `group_by_dynamic` with `period = every`, pandas `resample(rule)` at any
/// frequency: the rows of each window (and `by` group) aggregated, skipping missing
/// values; sorted by the groups, then the window. A row with no readable time is
/// dropped. Windows with no rows are not made (polars; pandas' `resample` makes them:
/// `upsample` the result for that).
pub fn groupByDynamic(a: std.mem.Allocator, f: Frame, spec: DynamicSpec) Error!Frame {
    const ii = try mustIndex(f, spec.index);
    const d = dtf.parseDuration(spec.every) orelse return error.BadArgument;
    if (!((d.months > 0 and d.us == 0) or (d.months == 0 and d.us > 0))) return error.BadArgument;
    const win_name = "\x00window";
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    for (cells, 0..) |*c, ri| {
        const v = f.columnAt(ii).get(ri);
        c.* = if (isMissing(v)) .null else try dtf.truncate(a, v, d);
    }
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = .{ .name = win_name, .type = f.columns[ii].type };
    const data = try a.alloc(ColumnData, w + 1);
    for (data[0..w], 0..) |*x, i| x.* = f.columnAt(i);
    data[w] = try fm.columnFromCells(a, cells);
    var with: Frame = .{ .columns = cols, .data = data, .len = f.len };
    with = try verbs.dropna(a, with, .{ .subset = &.{win_name} });
    const gb = try a.alloc([]const u8, spec.by.len + 1);
    @memcpy(gb[0..spec.by.len], spec.by);
    gb[spec.by.len] = win_name;
    const g = try verbs.aggregate(a, with, .{ .group_by = gb, .aggs = spec.aggs, .skip_na = true, .sort_groups = true });
    return verbs.rename(a, g, &.{.{ .from = win_name, .to = spec.index }});
}

pub const UpsampleSpec = struct {
    /// The temporal column.
    time: []const u8,
    /// The step, a polars duration.
    every: []const u8,
};

/// Most rows `upsample` makes.
pub const max_upsample_rows: usize = 1 << 22;

/// polars `upsample`, pandas `asfreq`: a row for every step from the first time to the
/// last, the input's rows where their time is a step (several if it repeats), the other
/// cells null; times off the grid are dropped. Sorted by time. Times match as cells: an
/// int or a date exactly, ISO timestamp text as the text `formatIsoTimestamp` writes.
pub fn upsample(a: std.mem.Allocator, f: Frame, spec: UpsampleSpec) Error!Frame {
    try checkRows(f);
    const ti = try mustIndex(f, spec.time);
    const d = dtf.parseDuration(spec.every) orelse return error.BadArgument;
    if (d.months < 0 or d.us < 0 or (d.months == 0 and d.us == 0)) return error.BadArgument;
    var lo: ?usize = null;
    var lo_us: i64 = 0;
    var hi_us: i64 = 0;
    for (0..f.len) |ri| {
        const us = dtf.instantOf(f.columnAt(ti).get(ri)) orelse continue;
        if (lo == null) {
            lo = ri;
            lo_us = us;
            hi_us = us;
            continue;
        }
        if (us < lo_us) {
            lo = ri;
            lo_us = us;
        }
        hi_us = @max(hi_us, us);
    }
    if (lo == null) return verbs.takeRows(a, f, &.{});
    const start = f.columnAt(ti).get(lo.?);
    var grid: std.ArrayList(Value) = .empty;
    var k: i64 = 0;
    while (true) : (k += 1) {
        if (grid.items.len >= max_upsample_rows) return error.TooLarge;
        const step: dtf.Duration = .{
            .months = std.math.mul(i64, d.months, k) catch return error.TooLarge,
            .us = std.math.mul(i64, d.us, k) catch return error.TooLarge,
        };
        const v = try dtf.offsetBy(a, start, step);
        const us = dtf.instantOf(v) orelse break;
        if (us > hi_us) break;
        try grid.append(a, v);
    }
    const gcols = try a.dupe(Column, &.{f.columns[ti]});
    const gdata = try a.alloc(ColumnData, 1);
    gdata[0] = try fm.columnFromCells(a, grid.items);
    const g: Frame = .{ .columns = gcols, .data = gdata, .len = grid.items.len };
    // Rename the right key so the join keeps the left (grid) one.
    const rcols = try a.dupe(Column, f.columns);
    rcols[ti].name = "\x00time";
    const right: Frame = .{ .columns = rcols, .data = f.data, .len = f.len };
    const j = try verbs.joinChecked(a, g, right, .{ .on = f.columns[ti].name, .right_on = &.{"\x00time"}, .how = .left, .null_keys = .no_match });
    const names = try a.alloc([]const u8, f.columns.len);
    for (names, f.columns) |*n, c| n.* = c.name;
    return verbs.select(a, j, names);
}
