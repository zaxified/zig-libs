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
const tz = @import("tz");
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
        if (cols[ci].type != .timestamp) cols[ci].time_zone = null;
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
            try cols.append(a, .{ .name = try std.mem.concat(a, u8, &.{ c.name, suffix }), .type = c.type, .time_zone = c.time_zone });
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
    /// the earlier, as scipy's `nearest`). `slinear` (scipy's linear spline) is the
    /// same line between the known points; `zero` holds the previous known value
    /// (scipy's zeroth-order spline). pandas runs the last three through SciPy; neither
    /// engine's oracle here has it (see SPEC).
    method: enum { linear, nearest, slinear, zero } = .linear,
    /// The x of each row: a numeric or temporal column; null = the row position.
    by: ?[]const u8 = null,
    /// The output column; null replaces `col`.
    out: ?[]const u8 = null,
    /// Fill at most this many consecutive missing cells from each present neighbour
    /// (pandas `limit`); null = no limit. Counted in rows, from the neighbour on the
    /// side `limit_direction` names.
    limit: ?usize = null,
    /// Which present neighbour a missing cell may be filled from (pandas
    /// `limit_direction`): `forward` from the one before it (a gap after the last present
    /// value is filled by repeating it), `backward` from the one after it (a gap before
    /// the first), `both` from either. null (the default) is polars': interior gaps
    /// only, a gap before the first or after the last present value stays null; with a
    /// `limit` the interior is counted from the left, as `forward`.
    limit_direction: ?enum { forward, backward, both } = null,
    /// Fill only the gaps with a present value on both sides (`inside`) or only those
    /// without (`outside`, which repeats the nearest present value; pandas
    /// `limit_area`). null = both kinds.
    limit_area: ?enum { inside, outside } = null,
};

const Pt = struct { x: f64, y: f64 };

fn ptLess(_: void, l: Pt, r: Pt) bool {
    return l.x < r.x;
}

fn isPresentNum(v: Value) bool {
    return !isMissing(v) and v.asFloat() != null;
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
    // The nearest present row before / after each row, for `limit*`.
    const none = std.math.maxInt(usize);
    const prev = try a.alloc(usize, f.len);
    defer a.free(prev);
    const next = try a.alloc(usize, f.len);
    defer a.free(next);
    {
        var last: usize = none;
        for (prev, 0..) |*pv, ri| {
            pv.* = last;
            if (isPresentNum(ys.get(ri))) last = ri;
        }
        last = none;
        var ri = f.len;
        while (ri > 0) {
            ri -= 1;
            next[ri] = last;
            if (isPresentNum(ys.get(ri))) last = ri;
        }
    }
    const lim = spec.limit orelse std.math.maxInt(usize);
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
        if (p.len == 0) continue;
        const has_prev = prev[ri] != none;
        const has_next = next[ri] != none;
        if (spec.limit_area) |area| {
            if ((area == .inside) != (has_prev and has_next)) continue;
        }
        const from_prev = has_prev and ri - prev[ri] <= lim;
        const from_next = has_next and next[ri] - ri <= lim;
        const in_range = x >= p[0].x and x <= p[p.len - 1].x;
        const ok = if (spec.limit_direction) |dir| switch (dir) {
            .forward => from_prev,
            .backward => from_next,
            .both => from_prev or from_next,
        } else in_range and (!has_prev or from_prev);
        if (!ok) continue;
        if (!in_range) {
            // Beyond the known points: repeat the nearest one.
            o.* = .{ .float = if (x < p[0].x) p[0].y else p[p.len - 1].y };
            continue;
        }
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
            .linear, .slinear => l.y + (r.y - l.y) * (x - l.x) / (r.x - l.x),
            .nearest => if (x - l.x <= r.x - x) l.y else r.y,
            .zero => l.y,
        } };
    }
    const name = spec.out orelse spec.col;
    const data = try fm.columnFromCells(a, out);
    if (f.columnIndex(name)) |oi| {
        const cols = try a.dupe(Column, f.columns);
        cols[oi].type = .float;
        cols[oi].time_zone = null;
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

/// Which ends of a dynamic window `[lower, lower + period]` belong to it (polars
/// `group_by_dynamic(closed=)`; pandas `closed=` knows `left` and `right`).
pub const DynamicClosed = enum { left, right, both, none };

/// The value the window is labelled with (polars `label=`, pandas `label=`).
pub const DynamicLabel = enum {
    /// The window's lower bound.
    left,
    /// Its upper bound (`lower + period`).
    right,
    /// The first (smallest) time among the rows of the window (polars `datapoint`).
    datapoint,
};

/// Where the first window of a group starts (polars `start_by`): the grid is `every`
/// apart from there.
pub const StartBy = enum {
    /// The epoch grid (weeks from Monday 1970-01-05, months from January 1970): the first window
    /// is the grid window holding the first time.
    window,
    /// The group's first time.
    datapoint,
    monday,
    tuesday,
    wednesday,
    thursday,
    friday,
    saturday,
    sunday,
};

/// pandas `resample(origin=)`: the instant the grid of fixed-length bins is counted from.
/// Calendar bins (`every` in months) ignore it.
pub const Origin = enum {
    /// 1970-01-01 (weeks: Monday 1970-01-05), polars' alignment.
    epoch,
    /// The group's first time.
    start,
    /// Midnight of the group's first day (pandas' default).
    start_day,
    /// The group's last time.
    end,
    /// Midnight at or after the group's last time.
    end_day,
};

pub const DynamicSpec = struct {
    /// The temporal column (see `dtfn`: microsecond ints or ISO text).
    index: []const u8,
    /// Window length and step, a polars duration (`"1h"`, `"15m"`, `"1mo"`): windows
    /// `[start, start + every)` from 1970-01-01 (weeks from Monday), labelled by their
    /// start in the index column (polars' `closed="left"`, `label="left"`). Ignored when
    /// `rule` is set.
    every: []const u8 = "",
    /// pandas `resample(rule)`: a frequency string instead of `every`, with the
    /// engine's defaults for `closed`, `label` and the grid. Accepted: `[n]` then
    /// `D`, `h`/`H`, `min`/`T`, `s`/`S`, `ms`/`L`, `us`/`U` (fixed bins, grid origin
    /// `start_day` unless `origin` is set), `MS`, `QS`, `YS`/`AS` (calendar bins
    /// labelled by their first day, `n` must be 1), `ME`/`M`, `QE`/`Q`, `YE`/`Y`/`A`
    /// (calendar bins labelled by their last day), `W` and `W-SUN`..`W-SAT` (weeks
    /// ending on that day, labelled by it). `B` (business days) and other anchors are
    /// `error.BadArgument`. `closed`, `label` and `start_by` are then not read; the bins
    /// of the end-labelled rules are whole days, so a time on the last day belongs to
    /// the bin ending on it, as pandas.
    rule: ?[]const u8 = null,
    /// polars `period`: the window's length when it is not `every` (windows then overlap
    /// or leave gaps); null = `every`.
    period: ?[]const u8 = null,
    /// polars and pandas `offset`: every window is moved by it (a duration, may be negative).
    offset: ?[]const u8 = null,
    closed: DynamicClosed = .left,
    label: DynamicLabel = .left,
    start_by: StartBy = .window,
    /// pandas `origin`; null = `.epoch`, or `.start_day` when `rule` is set (the engines
    /// disagree on this default: polars counts from the epoch, which is what a plain
    /// `every` has always done here, pandas from the first midnight).
    origin: ?Origin = null,
    /// polars `include_boundaries`: add `_lower_boundary` and `_upper_boundary` before the
    /// index column.
    include_boundaries: bool = false,
    /// Group columns before the window (polars `group_by`).
    by: []const []const u8 = &.{},
    aggs: []const sp.AggCol,
};

/// Most (row, window) pairs one `groupByDynamic` call makes (overlapping windows put a row
/// in several).
pub const max_dynamic_memberships: usize = 1 << 24;

const us_per_day_i: i64 = 86_400_000_000;

/// What `rule` stands for, or null when it is not one of the accepted rules.
const RuleSpec = struct {
    every: dtf.Duration,
    closed: DynamicClosed = .left,
    label: DynamicLabel = .left,
    /// Label by the last day of the window (the end-anchored rules), not its first.
    label_last_day: bool = false,
    start_by: StartBy = .window,
    fixed: bool = false,
};

fn parseRule(rule: []const u8) ?RuleSpec {
    var i: usize = 0;
    while (i < rule.len and std.ascii.isDigit(rule[i])) i += 1;
    const n: i64 = if (i == 0) 1 else std.fmt.parseInt(i64, rule[0..i], 10) catch return null;
    if (n <= 0) return null;
    const u = rule[i..];
    const eq = std.mem.eql;
    const fixed = struct {
        fn mk(per: i64, k: i64) ?RuleSpec {
            return .{ .every = .{ .us = std.math.mul(i64, per, k) catch return null }, .fixed = true };
        }
    }.mk;
    if (eq(u8, u, "D")) return fixed(us_per_day_i, n);
    if (eq(u8, u, "h") or eq(u8, u, "H")) return fixed(3_600_000_000, n);
    if (eq(u8, u, "min") or eq(u8, u, "T")) return fixed(60_000_000, n);
    if (eq(u8, u, "s") or eq(u8, u, "S")) return fixed(1_000_000, n);
    if (eq(u8, u, "ms") or eq(u8, u, "L")) return fixed(1000, n);
    if (eq(u8, u, "us") or eq(u8, u, "U")) return fixed(1, n);
    const cal = struct {
        fn mk(months: i64, end: bool) RuleSpec {
            return .{ .every = .{ .months = months }, .label = if (end) .right else .left, .label_last_day = end };
        }
    }.mk;
    if (n == 1) {
        if (eq(u8, u, "MS")) return cal(1, false);
        if (eq(u8, u, "QS")) return cal(3, false);
        if (eq(u8, u, "YS") or eq(u8, u, "AS")) return cal(12, false);
        if (eq(u8, u, "ME") or eq(u8, u, "M")) return cal(1, true);
        if (eq(u8, u, "QE") or eq(u8, u, "Q")) return cal(3, true);
        if (eq(u8, u, "YE") or eq(u8, u, "Y") or eq(u8, u, "A")) return cal(12, true);
    }
    // W, W-SUN ... W-SAT: weeks whose last day is the named one, so they start the day after.
    if (eq(u8, u, "W") or (u.len == 5 and eq(u8, u[0..2], "W-"))) {
        const day = if (u.len == 1) "SUN" else u[2..5];
        const names = [_][]const u8{ "MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN" };
        for (names, 0..) |nm, k| {
            if (!eq(u8, nm, day)) continue;
            const starts = [_]StartBy{ .tuesday, .wednesday, .thursday, .friday, .saturday, .sunday, .monday };
            const wk = std.math.mul(i64, 7 * us_per_day_i, n) catch return null;
            return .{ .every = .{ .us = wk, .weeks = n }, .label = .right, .label_last_day = true, .start_by = starts[k] };
        }
    }
    return null;
}

/// The epoch day `d` of an instant and its weekday, Monday = 0 (1970-01-01 was a Thursday).
fn weekdayOfDay(day: i64) i64 {
    return @mod(day + 3, 7);
}

fn originFor(spec_origin: Origin, start_by: StartBy, every: dtf.Duration, first: i64, last: i64) ?i64 {
    // Weekday and datapoint starts (polars) take precedence; they are the only ones a
    // plain `every` spells.
    switch (start_by) {
        .window => {},
        .datapoint => return first,
        else => {
            const want: i64 = @backingInt(start_by) - @backingInt(StartBy.monday);
            const day = @divFloor(first, us_per_day_i);
            const back = @mod(weekdayOfDay(day) - want, 7);
            return std.math.mul(i64, day - back, us_per_day_i) catch null;
        },
    }
    // Calendar bins count from January 1970 whatever `origin` says (pandas ignores it there).
    if (every.months > 0) return 0;
    return switch (spec_origin) {
        .epoch => if (every.months == 0 and every.weeks != 0 and @mod(every.us, 7 * us_per_day_i) == 0) 4 * us_per_day_i else 0,
        .start => first,
        .start_day => std.math.mul(i64, @divFloor(first, us_per_day_i), us_per_day_i) catch null,
        .end => last,
        .end_day => blk: {
            const d = @divFloor(last, us_per_day_i) + @as(i64, @intFromBool(@mod(last, us_per_day_i) != 0));
            break :blk std.math.mul(i64, d, us_per_day_i) catch null;
        },
    };
}

/// The grid of one group: windows `[lower(k), lower(k) + period]`.
const Grid = struct {
    origin: i64,
    every: dtf.Duration,
    offset: dtf.Duration,
    period: dtf.Duration,

    fn lower(g: Grid, k: i64) ?i64 {
        const base = dtf.stepInstant(g.origin, g.every, k) orelse return null;
        return dtf.stepInstant(base, g.offset, 1);
    }

    fn upper(g: Grid, lo: i64) ?i64 {
        return dtf.stepInstant(lo, g.period, 1);
    }

    /// The largest `k` with `lower(k) <= t` (`< t` when `strict`), null when out of range.
    fn indexAtOrBefore(g: Grid, t: i64, strict: bool) ?i64 {
        const avg: f64 = if (g.every.months > 0) @as(f64, @floatFromInt(g.every.months)) * 30.436875 * 86400e6 else @floatFromInt(g.every.us);
        const rel: f64 = @as(f64, @floatFromInt(t)) - @as(f64, @floatFromInt(g.origin));
        var k: i64 = @intFromFloat(std.math.clamp(@floor(rel / avg), -1e15, 1e15));
        const ok = struct {
            fn f(gg: Grid, kk: i64, tt: i64, st: bool) ?bool {
                const l = gg.lower(kk) orelse return null;
                return if (st) l < tt else l <= tt;
            }
        }.f;
        var guard: usize = 0;
        while (ok(g, k + 1, t, strict) orelse false) : (guard += 1) {
            k += 1;
            if (guard > 100_000) return null;
        }
        while (!(ok(g, k, t, strict) orelse return null)) : (guard += 1) {
            k -= 1;
            if (guard > 100_000) return null;
        }
        return k;
    }
};

/// An aggregate cell that holds an instant, however the aggregate typed it.
fn intOf(v: Value) ?i64 {
    return switch (v) {
        .int => |x| x,
        .float => |x| if (std.math.isFinite(x) and @abs(x) < 9.0e18) @intFromFloat(x) else null,
        else => null,
    };
}

fn inWindow(closed: DynamicClosed, t: i64, lo: i64, up: i64) bool {
    return switch (closed) {
        .left => t >= lo and t < up,
        .right => t > lo and t <= up,
        .both => t >= lo and t <= up,
        .none => t > lo and t < up,
    };
}

/// The general `groupByDynamic` over a zoned index: the windows are cut on the zone's wall
/// clock (polars `group_by_dynamic` and pandas `resample` of a tz-aware column agree: a day
/// is local midnight to local midnight, 23 or 25 hours across a DST change, a month starts on
/// the local first). So the algorithm runs on that clock, over a naive copy of the frame, and
/// the labels and boundaries it makes are read back in the zone (`compatible`: a boundary in
/// a gap is the first instant after it).
fn groupByDynamicGeneral(a: std.mem.Allocator, f: Frame, spec: DynamicSpec) Error!Frame {
    const ii = try mustIndex(f, spec.index);
    const zn = f.columns[ii].time_zone orelse return groupByDynamicNaive(a, f, spec);
    const zone = tz.find(zn) orelse return error.BadArgument;
    try checkRows(f);
    const cols = try a.dupe(Column, f.columns);
    cols[ii].time_zone = null;
    const data = try a.alloc(ColumnData, f.columns.len);
    for (data, 0..) |*d, i| d.* = f.columnAt(i);
    const wall = try a.alloc(Value, f.len);
    defer a.free(wall);
    for (wall, 0..) |*c, ri| {
        const v = f.columnAt(ii).get(ri);
        c.* = if (isMissing(v)) .null else try dtf.toLocal(a, v, zone);
    }
    data[ii] = try fm.columnFromCells(a, wall);
    const out = try groupByDynamicNaive(a, .{ .columns = cols, .data = data, .len = f.len }, spec);
    const ocols = try a.dupe(Column, out.columns);
    const odata = try a.alloc(ColumnData, out.columns.len);
    for (odata, 0..) |*d, i| d.* = out.columnAt(i);
    const back = try a.alloc(Value, out.len);
    defer a.free(back);
    // Which output columns hold instants read off the wall-clock copy: a `by` key named like
    // the index, the boundaries, the index label, and each aggregate whose source is the
    // index (min/max/first/last ...). Matched by position, never by name, so an aggregate
    // `out` that repeats another column's name cannot pick the wrong column.
    const nby = spec.by.len;
    const extra: usize = if (spec.include_boundaries) 2 else 0;
    for (ocols, odata, 0..) |*c, *d, ci| {
        const is_time = if (ci < nby)
            std.mem.eql(u8, c.name, spec.index)
        else if (ci < nby + extra + 1)
            true
        else
            std.mem.eql(u8, spec.aggs[ci - nby - extra - 1].src, spec.index);
        if (!is_time or c.type != .timestamp) continue;
        for (back, 0..) |*b, ri| {
            const v = d.get(ri);
            b.* = if (isMissing(v)) .null else try dtf.fromLocal(a, v, zone, .compatible);
        }
        d.* = try fm.columnFromCells(a, back);
        c.time_zone = zn;
    }
    return .{ .columns = ocols, .data = odata, .len = out.len };
}

/// The general `groupByDynamic` on a naive index: see `DynamicSpec`.
fn groupByDynamicNaive(a: std.mem.Allocator, f: Frame, spec: DynamicSpec) Error!Frame {
    try checkRows(f);
    const ii = try mustIndex(f, spec.index);
    var every: dtf.Duration = undefined;
    var closed = spec.closed;
    var label = spec.label;
    var start_by = spec.start_by;
    var label_last_day = false;
    var origin_kind: Origin = spec.origin orelse .epoch;
    if (spec.rule) |r| {
        const rs_ = parseRule(r) orelse return error.BadArgument;
        every = rs_.every;
        // The end-anchored rules fix their bins (whole days, left closed, labelled by the
        // last day); the others take `closed` and `label` as given, like pandas.
        label_last_day = rs_.label_last_day;
        if (rs_.label_last_day) {
            closed = .left;
            label = .right;
        }
        if (rs_.start_by != .window) start_by = rs_.start_by;
        origin_kind = spec.origin orelse .start_day;
    } else {
        every = dtf.parseDuration(spec.every) orelse return error.BadArgument;
    }
    if (!((every.months > 0 and every.us == 0) or (every.months == 0 and every.us > 0))) return error.BadArgument;
    const period: dtf.Duration = if (spec.period) |ps| (dtf.parseDuration(ps) orelse return error.BadArgument) else every;
    if (period.months < 0 or period.us < 0 or (period.months == 0 and period.us == 0)) return error.BadArgument;
    const offset: dtf.Duration = if (spec.offset) |os| (dtf.parseDuration(os) orelse return error.BadArgument) else .{};
    // Weekday starts and a calendar `rule` keep the grid on whole days / months; a month
    // grid has no weekday.
    if (every.months > 0 and start_by != .window and start_by != .datapoint) return error.BadArgument;

    // Per group: first and last time.
    const nby = spec.by.len;
    const ids = try a.alloc(u32, f.len);
    defer a.free(ids);
    var ng: usize = 1;
    @memset(ids, 0);
    if (nby > 0) {
        const pidx = try a.alloc(usize, nby);
        defer a.free(pidx);
        for (spec.by, pidx) |name, *ix| ix.* = f.columnIndex(name) orelse return error.NoSuchColumn;
        const rows = try verbs.keyRows(a, f, pidx);
        const pos = try a.alloc(usize, nby);
        defer a.free(pos);
        for (pos, 0..) |*p, i| p.* = i;
        const fac = try keys.factorize(a, rows, pos, .as_null);
        @memcpy(ids, fac.ids);
        ng = fac.groups();
    }
    const firsts = try a.alloc(i64, ng);
    defer a.free(firsts);
    const lasts = try a.alloc(i64, ng);
    defer a.free(lasts);
    const seen = try a.alloc(bool, ng);
    defer a.free(seen);
    @memset(seen, false);
    const ts = try a.alloc(?i64, f.len);
    defer a.free(ts);
    var ref: ?Value = null;
    var ref_us: i64 = 0;
    const icol = f.columnAt(ii);
    for (ts, 0..) |*t, ri| {
        const cell = icol.get(ri);
        t.* = dtf.instantOf(cell);
        const x = t.* orelse continue;
        if (ref == null) {
            ref = cell;
            ref_us = x;
        }
        const g = ids[ri];
        if (!seen[g]) {
            seen[g] = true;
            firsts[g] = x;
            lasts[g] = x;
        } else {
            firsts[g] = @min(firsts[g], x);
            lasts[g] = @max(lasts[g], x);
        }
    }
    const grids = try a.alloc(?Grid, ng);
    defer a.free(grids);
    const k0 = try a.alloc(i64, ng);
    defer a.free(k0);
    for (0..ng) |g| {
        grids[g] = null;
        if (!seen[g]) continue;
        const org = originFor(origin_kind, start_by, every, firsts[g], lasts[g]) orelse return error.TooLarge;
        const gr: Grid = .{ .origin = org, .every = every, .offset = offset, .period = period };
        k0[g] = gr.indexAtOrBefore(firsts[g], closed == .right) orelse return error.TooLarge;
        grids[g] = gr;
    }

    // Every (row, window) pair.
    var rows_idx: std.ArrayList(u32) = .empty;
    defer rows_idx.deinit(a);
    var lowers: std.ArrayList(i64) = .empty;
    defer lowers.deinit(a);
    for (ts, 0..) |t_opt, ri| {
        const t = t_opt orelse continue;
        const g = ids[ri];
        const gr = grids[g].?;
        var k = gr.indexAtOrBefore(t, false) orelse return error.TooLarge;
        var span: usize = 0;
        while (k >= k0[g]) : (k -= 1) {
            const lo = gr.lower(k) orelse break;
            const up = gr.upper(lo) orelse std.math.maxInt(i64);
            if (up < t) break;
            if (inWindow(closed, t, lo, up)) {
                if (rows_idx.items.len >= max_dynamic_memberships) return error.TooLarge;
                try rows_idx.append(a, @intCast(ri));
                try lowers.append(a, lo);
            }
            span += 1;
            if (span > 1 << 16) return error.TooLarge;
        }
    }

    // The pairs were made in row order, so the replicated frame is in row order within
    // each window (`first`/`last` read it so).
    const m = rows_idx.items.len;
    const lo_cells = try a.alloc(Value, m);
    defer a.free(lo_cells);
    const ts_cells = try a.alloc(Value, m);
    defer a.free(ts_cells);
    for (rows_idx.items, lowers.items, lo_cells, ts_cells) |ri, lo, *lc, *tc| {
        lc.* = .{ .int = lo };
        tc.* = .{ .int = ts[ri].? };
    }
    // Replicate only the columns the result reads (index, `by` keys, aggregate sources), and
    // refuse a replica past the cell cap before allocating it.
    const need = try a.alloc(bool, f.columns.len);
    defer a.free(need);
    @memset(need, false);
    need[ii] = true;
    for (spec.by) |name| need[f.columnIndex(name).?] = true;
    for (spec.aggs) |ag| {
        if (f.columnIndex(ag.src)) |ci| need[ci] = true;
    }
    var nneed: usize = 0;
    for (need) |x| nneed += @intFromBool(x);
    if (m > sp.max_join_cells / (nneed + 2)) return error.TooLarge;
    const ncols = try a.alloc(Column, nneed);
    const ndata = try a.alloc(ColumnData, nneed);
    var ni: usize = 0;
    for (need, 0..) |x, ci| {
        if (!x) continue;
        ncols[ni] = f.columns[ci];
        ndata[ni] = f.columnAt(ci);
        ni += 1;
    }
    const base = try verbs.takeRows(a, .{ .columns = ncols, .data = ndata, .len = f.len }, rows_idx.items);
    const lo_name = "\x00lo";
    const ts_name = "\x00ts";
    const w = base.columns.len;
    const cols = try a.alloc(Column, w + 2);
    @memcpy(cols[0..w], base.columns);
    cols[w] = .{ .name = lo_name, .type = .int };
    cols[w + 1] = .{ .name = ts_name, .type = .int };
    const data = try a.alloc(ColumnData, w + 2);
    for (data[0..w], 0..) |*x, i| x.* = base.columnAt(i);
    data[w] = try fm.columnFromCells(a, lo_cells);
    data[w + 1] = try fm.columnFromCells(a, ts_cells);
    const with: Frame = .{ .columns = cols, .data = data, .len = base.len };

    const gb = try a.alloc([]const u8, nby + 1);
    @memcpy(gb[0..nby], spec.by);
    gb[nby] = lo_name;
    const naggs = spec.aggs.len;
    const aggs = try a.alloc(sp.AggCol, naggs + 1);
    @memcpy(aggs[0..naggs], spec.aggs);
    aggs[naggs] = .{ .src = ts_name, .out = "\x00dp", .func = .min };
    const g = try verbs.aggregate(a, with, .{ .group_by = gb, .aggs = aggs, .skip_na = true, .sort_groups = true });

    // Assemble: by columns, [boundaries], the index column, the aggregates.
    const n = g.len;
    const lo_col = g.columnAt(nby);
    const dp_col = g.columnAt(nby + 1 + naggs);
    const lab = try a.alloc(Value, n);
    defer a.free(lab);
    const lo_out = try a.alloc(Value, if (spec.include_boundaries) n else 0);
    defer a.free(lo_out);
    const up_out = try a.alloc(Value, if (spec.include_boundaries) n else 0);
    defer a.free(up_out);
    const at = struct {
        fn cell(al: std.mem.Allocator, r: ?Value, r_us: i64, us: i64) error{OutOfMemory}!Value {
            const rv = r orelse return .null;
            const d = std.math.sub(i64, us, r_us) catch return .null;
            return dtf.offsetBy(al, rv, .{ .us = d });
        }
    }.cell;
    for (0..n) |i| {
        const lo = intOf(lo_col.get(i)) orelse {
            lab[i] = .null;
            if (spec.include_boundaries) {
                lo_out[i] = .null;
                up_out[i] = .null;
            }
            continue;
        };
        const up = dtf.stepInstant(lo, period, 1);
        if (spec.include_boundaries) {
            lo_out[i] = try at(a, ref, ref_us, lo);
            up_out[i] = if (up) |u| try at(a, ref, ref_us, u) else .null;
        }
        const shown: ?i64 = switch (label) {
            .left => lo,
            .right => up,
            .datapoint => intOf(dp_col.get(i)),
        };
        var sv = shown;
        if (label_last_day and label == .right and sv != null) sv = std.math.sub(i64, sv.?, us_per_day_i) catch null;
        lab[i] = if (sv) |u| try at(a, ref, ref_us, u) else .null;
    }
    const extra: usize = if (spec.include_boundaries) 2 else 0;
    const ocols = try a.alloc(Column, nby + extra + 1 + naggs);
    const odata = try a.alloc(ColumnData, ocols.len);
    for (0..nby) |i| {
        ocols[i] = g.columns[i];
        odata[i] = g.columnAt(i);
    }
    const it = f.columns[ii].type;
    if (spec.include_boundaries) {
        ocols[nby] = .{ .name = "_lower_boundary", .type = it, .time_zone = f.columns[ii].time_zone };
        odata[nby] = try fm.columnFromCells(a, lo_out);
        ocols[nby + 1] = .{ .name = "_upper_boundary", .type = it, .time_zone = f.columns[ii].time_zone };
        odata[nby + 1] = try fm.columnFromCells(a, up_out);
    }
    ocols[nby + extra] = .{ .name = spec.index, .type = it, .time_zone = f.columns[ii].time_zone };
    odata[nby + extra] = try fm.columnFromCells(a, lab);
    for (0..naggs) |i| {
        ocols[nby + extra + 1 + i] = g.columns[nby + 1 + i];
        odata[nby + extra + 1 + i] = g.columnAt(nby + 1 + i);
    }
    return .{ .columns = ocols, .data = odata, .len = n };
}

/// polars `group_by_dynamic`, pandas `resample`: the rows of each window (and `by` group)
/// aggregated, skipping missing values; sorted by the groups, then the window. A row with
/// no readable time is dropped. Windows with no rows are not made (polars; pandas'
/// `resample` makes them: `upsample` the result for that). With the default options
/// the windows tile the epoch grid (`period = every`); `DynamicSpec` lists what else
/// polars and pandas take.
pub fn groupByDynamic(a: std.mem.Allocator, f: Frame, spec: DynamicSpec) Error!Frame {
    const plain = spec.rule == null and spec.period == null and spec.offset == null and spec.closed == .left and
        spec.label == .left and spec.start_by == .window and spec.origin == null and !spec.include_boundaries;
    if (!plain) return groupByDynamicGeneral(a, f, spec);
    const ii = try mustIndex(f, spec.index);
    const d = dtf.parseDuration(spec.every) orelse return error.BadArgument;
    if (!((d.months > 0 and d.us == 0) or (d.months == 0 and d.us > 0))) return error.BadArgument;
    const win_name = "\x00window";
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    // A zoned index is cut on its wall clock (see `groupByDynamicGeneral`).
    const zone: ?*const tz.Zone = if (f.columns[ii].time_zone) |zn| (tz.find(zn) orelse return error.BadArgument) else null;
    for (cells, 0..) |*c, ri| {
        const v = f.columnAt(ii).get(ri);
        c.* = if (isMissing(v)) .null else if (zone) |z| try dtf.roundToZoned(a, v, d, .floor, z) else try dtf.truncate(a, v, d);
    }
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = .{ .name = win_name, .type = f.columns[ii].type, .time_zone = f.columns[ii].time_zone };
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
