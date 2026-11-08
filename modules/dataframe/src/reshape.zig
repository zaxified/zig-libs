// SPDX-License-Identifier: MIT
//! The fourth wave of D2's survey rows (5, 8, 20, 25, 38, 53, 55, 66, 69, 80, 89):
//! group filters and numbers, inequality and ordered joins, multi-value pivots,
//! dummies, `combine_first`/`update`, row repeats and scatters, `drop_nans`,
//! `match_to_schema`, `hash_rows`, `between_time`, and a float matrix. Semantics are
//! pandas' and polars' documented ones, the choice stated where they differ. Original
//! work of the zig-libs authors (MIT).

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const sp = @import("spec.zig");
const core = @import("core.zig");
const verbs = @import("verbs.zig");
const ex = @import("expr.zig");
const an = @import("analysis.zig");
const st = @import("structure.zig");
const dtf = @import("dtfn.zig");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;
const isMissing = keys.isMissing;

pub const ReshapeError = sp.ColumnsError || error{
    /// A frame whose schema `matchToSchema` cannot make the asked one.
    SchemaMismatch,
    /// A position outside the frame (`scatter`).
    IndexOutOfBounds,
    /// A count or argument the verb cannot use (a negative repeat, a bad time text,
    /// `scatter` values of the wrong count).
    BadArgument,
    /// A cast `matchToSchema` was allowed to do failed.
    CastFailed,
};

const Error = ReshapeError;

fn mustIndex(f: Frame, name: []const u8) Error!usize {
    return f.columnIndex(name) orelse error.NoSuchColumn;
}

fn checkRows(f: Frame) Error!void {
    return core.checkRowsU32(f.len);
}

fn nameIdxs(a: std.mem.Allocator, f: Frame, names: []const []const u8) Error![]const usize {
    const out = try a.alloc(usize, names.len);
    for (out, names) |*o, n| o.* = try mustIndex(f, n);
    return out;
}

fn shared(a: std.mem.Allocator, f: Frame) Error![]ColumnData {
    const data = try a.alloc(ColumnData, f.columns.len);
    for (data, 0..) |*d, ci| d.* = f.columnAt(ci);
    return data;
}

fn liftAnalysis(e: an.AnalysisError) Error {
    return switch (e) {
        error.BadEdges, error.Unmatched, error.BadArgument => error.BadArgument,
        inline else => |x| x,
    };
}

fn liftStructure(e: st.StructureError) Error {
    return switch (e) {
        error.LengthMismatch => error.SchemaMismatch,
        error.BadPattern => error.BadArgument, // a `Selector.matches` pattern
        inline else => |x| x,
    };
}

// ── group filter / ngroup ───────────────────────────────────────────────────

pub const GroupFilterSpec = struct {
    by: []const []const u8,
    /// The per-group value the predicate reads (`AggCol.out` is only a scratch name).
    agg: sp.AggCol,
    op: sp.CmpOp,
    value: Value = .null,
};

/// The rows of the groups whose aggregate satisfies `agg op value` (pandas
/// `groupby(...).filter(lambda g: ...)` for one statistic, polars
/// `group_by(...).having(...)`), in input order. The aggregate skips missing values; a
/// missing key is a group.
pub fn groupFilter(a: std.mem.Allocator, f: Frame, spec: GroupFilterSpec) Error!Frame {
    try checkRows(f);
    const idxs = try nameIdxs(a, f, spec.by);
    const g = try verbs.aggregate(a, f, .{ .group_by = spec.by, .aggs = &.{spec.agg}, .skip_na = true });
    const fac = try verbs.factorKeys(a, f, idxs);
    const vals = g.columnAt(spec.by.len);
    const p: sp.Predicate = .{ .col = "", .op = spec.op, .value = spec.value };
    const kept = try a.alloc(u32, f.len);
    var n: usize = 0;
    for (fac.ids, 0..) |gid, ri| {
        kept[n] = @intCast(ri);
        n += @intFromBool(core.holds(p, vals.get(gid)));
    }
    return verbs.takeRows(a, f, kept[0..n]);
}

pub const NgroupSpec = struct {
    by: []const []const u8,
    out: []const u8 = "ngroup",
    /// Numbered in key order (pandas' `groupby(sort=True)` default); false: first seen.
    sort: bool = true,
};

/// pandas `groupby(...).ngroup()`: the group's number on every row of it; a row with a
/// missing key gets null (pandas' `dropna=True`).
pub fn ngroup(a: std.mem.Allocator, f: Frame, spec: NgroupSpec) Error!Frame {
    const r = an.factorize(a, f, .{ .cols = spec.by, .out = spec.out, .sort = spec.sort, .missing = .null }) catch |e| return liftAnalysis(e);
    return r.frame;
}

// ── joins ───────────────────────────────────────────────────────────────────

pub const JoinPredicate = struct { left: []const u8, op: sp.CmpOp, right: []const u8 };

/// Most (left row, right row) pairs `joinWhere` looks at.
pub const max_join_where_pairs: usize = 1 << 26;

fn compareHolds(op: sp.CmpOp, l: Value, r: Value) bool {
    if (isMissing(l) or isMissing(r)) return false;
    const ln = l == .int or l == .float or l == .decimal;
    const rn = r == .int or r == .float or r == .decimal;
    if (ln != rn) return false;
    if (!ln and std.meta.activeTag(l) != std.meta.activeTag(r)) return false;
    const o = l.order(r);
    return switch (op) {
        .eq => o == .eq,
        .ne => o != .eq,
        .lt => o == .lt,
        .le => o != .gt,
        .gt => o == .gt,
        .ge => o != .lt,
        .is_null, .not_null => false,
    };
}

/// polars `join_where`: every (left, right) pair for which all `preds` hold, left
/// columns then right ones, a right name the left has gets `suffix` (polars
/// `"_right"`). A missing cell satisfies no comparison; `is_null`/`not_null` are not
/// comparisons and are `error.BadArgument`. Pairs looked at are capped at
/// `max_join_where_pairs`, output cells at `max_join_cells`.
pub fn joinWhere(a: std.mem.Allocator, left: Frame, right: Frame, preds: []const JoinPredicate, suffix: []const u8) Error!Frame {
    try checkRows(left);
    try checkRows(right);
    const li = try a.alloc(usize, preds.len);
    const ri = try a.alloc(usize, preds.len);
    for (preds, li, ri) |p, *l, *r| {
        if (p.op == .is_null or p.op == .not_null) return error.BadArgument;
        l.* = try mustIndex(left, p.left);
        r.* = try mustIndex(right, p.right);
    }
    const pairs = std.math.mul(usize, left.len, right.len) catch return error.TooLarge;
    if (pairs > max_join_where_pairs) return error.TooLarge;
    var lrows: std.ArrayList(u32) = .empty;
    var rrows: std.ArrayList(u32) = .empty;
    const width = left.columns.len + right.columns.len;
    for (0..left.len) |x| {
        for (0..right.len) |y| {
            var ok = true;
            for (preds, li, ri) |p, lc, rc| {
                if (!compareHolds(p.op, left.columnAt(lc).get(x), right.columnAt(rc).get(y))) {
                    ok = false;
                    break;
                }
            }
            if (!ok) continue;
            const cells = std.math.mul(usize, lrows.items.len + 1, @max(width, 1)) catch return error.TooLarge;
            if (cells > sp.max_join_cells) return error.TooLarge;
            try lrows.append(a, @intCast(x));
            try rrows.append(a, @intCast(y));
        }
    }
    const cols = try a.alloc(Column, width);
    const data = try a.alloc(ColumnData, width);
    for (left.columns, 0..) |c, i| {
        cols[i] = c;
        data[i] = try verbs.take(a, left.columnAt(i), lrows.items, false);
    }
    var left_names = try fm.NameIndex.init(a, left.columns);
    defer left_names.deinit(a);
    for (right.columns, 0..) |c, i| {
        const k = left.columns.len + i;
        cols[k] = c;
        if (left_names.get(c.name) != null) cols[k].name = try std.mem.concat(a, u8, &.{ c.name, suffix });
        data[k] = try verbs.take(a, right.columnAt(i), rrows.items, false);
    }
    try keys.uniqueNames(a, cols);
    return .{ .columns = cols, .data = data, .len = lrows.items.len };
}

pub const MergeOrderedSpec = struct {
    on: []const []const u8,
    /// pandas' `fill_method="ffill"`: carry the last present cell forward after the
    /// ordered outer join.
    fill_forward: bool = false,
    /// Appended to a right column whose name the left has (pandas' `"_y"`; the left
    /// keeps its name, where pandas would write `"_x"`).
    suffix: []const u8 = "_y",
};

/// pandas `merge_ordered(left, right, on, how="outer")`: a full outer join on `on`,
/// the keys coalesced, sorted by the keys (missing last), optionally forward-filled.
pub fn mergeOrdered(a: std.mem.Allocator, left: Frame, right: Frame, spec: MergeOrderedSpec) Error!Frame {
    if (spec.on.len == 0) return error.NoSuchColumn;
    // With `fill_forward` each side gets a marker column, to tell the cells the join left
    // empty from the cells the side had empty itself.
    const l = if (spec.fill_forward) try withMarker(a, left, left_mark) else left;
    const r = if (spec.fill_forward) try withMarker(a, right, right_mark) else right;
    const j = try verbs.join(a, l, r, .{ .keys = spec.on, .how = .full, .suffix = spec.suffix, .coalesce_keys = true });
    const then = try a.alloc(sp.SortKey, spec.on.len - 1);
    for (then, spec.on[1..]) |*t, k| t.* = .{ .key = k };
    var out = try verbs.sort(a, j, .{ .key = spec.on[0], .then_by = then, .missing = .last });
    if (spec.fill_forward) out = try fillGaps(a, out, left, spec.on);
    return out;
}

const left_mark = "\x00merge-left";
const right_mark = "\x00merge-right";

fn withMarker(a: std.mem.Allocator, f: Frame, name: []const u8) Error!Frame {
    const ones = try a.alloc(Value, f.len);
    @memset(ones, .{ .int = 1 });
    const cols = try a.alloc(Column, f.columns.len + 1);
    @memcpy(cols[0..f.columns.len], f.columns);
    cols[f.columns.len] = .{ .name = name, .type = .int };
    const data = try a.alloc(ColumnData, f.columns.len + 1);
    for (data[0..f.columns.len], 0..) |*d, i| d.* = f.columnAt(i);
    data[f.columns.len] = try fm.columnFromCells(a, ones);
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// pandas' `fill_method="ffill"`: in a row one side has no match for, that side's
/// columns take the values of its last row that had one (those may be null themselves);
/// a cell the side had empty is not filled. The markers are dropped.
fn fillGaps(a: std.mem.Allocator, f: Frame, left: Frame, on: []const []const u8) Error!Frame {
    const li = f.columnIndex(left_mark) orelse return error.NoSuchColumn;
    const ri = f.columnIndex(right_mark) orelse return error.NoSuchColumn;
    const data = try a.alloc(ColumnData, f.columns.len);
    const cells = try a.alloc(Value, f.len);
    const keep = try a.alloc([]const u8, f.columns.len - 2);
    var left_names = try fm.NameIndex.init(a, left.columns);
    defer left_names.deinit(a);
    var k: usize = 0;
    for (f.columns, 0..) |c, ci| {
        data[ci] = f.columnAt(ci);
        if (ci == li or ci == ri) continue;
        keep[k] = c.name;
        k += 1;
        var is_key = false;
        for (on) |n| is_key = is_key or std.mem.eql(u8, n, c.name);
        if (is_key) continue;
        const mark = f.columnAt(if (left_names.get(c.name) != null) li else ri);
        var last: Value = .null;
        for (cells, 0..) |*x, row| {
            if (mark.get(row) != .null) last = f.columnAt(ci).get(row);
            x.* = last;
        }
        data[ci] = try fm.columnFromCells(a, cells);
    }
    return verbs.select(a, .{ .columns = f.columns, .data = data, .len = f.len }, keep);
}

/// polars `merge_sorted`: two frames of the same schema, each sorted by `key`, as one
/// sorted frame (stable: on a tie the left's rows first).
pub fn mergeSorted(a: std.mem.Allocator, left: Frame, right: Frame, key: []const u8) Error!Frame {
    const c = st.concat(a, &.{ left, right }, .vertical) catch |e| return liftStructure(e);
    return verbs.sort(a, c, .{ .key = key });
}

// ── multi-value pivot ───────────────────────────────────────────────────────

pub const PivotManySpec = struct {
    row_key: []const u8,
    col_key: []const u8,
    /// Value columns; each gives one block of output columns named
    /// `{value}{separator}{column key}` (polars' names with several `values`).
    values: []const []const u8,
    agg: sp.AggFn = .sum,
    q: f64 = 0.5,
    skip_na: bool = false,
    fill_value: ?f64 = null,
    separator: []const u8 = "_",
};

/// `pivot` with several value columns (pandas `pivot_table(values=[...])`, polars
/// `pivot(values=[...])`): one `pivot` per value, side by side, joined on the row key.
/// All the blocks together hold at most `max_pivot_cells` cells (row keys x column keys x
/// values), else `error.TooLarge`.
pub fn pivotMany(a: std.mem.Allocator, f: Frame, spec: PivotManySpec) Error!Frame {
    if (spec.values.len == 0) return error.NoSuchColumn;
    var out: ?Frame = null;
    // `pivot` caps one block; the blocks together are capped at the same `max_pivot_cells`.
    var cells: usize = 0;
    for (spec.values) |v| {
        var p = try verbs.pivot(a, f, .{ .row_key = spec.row_key, .col_key = spec.col_key, .value_col = v, .agg = spec.agg, .q = spec.q, .skip_na = spec.skip_na, .fill_value = spec.fill_value });
        const block = std.math.mul(usize, p.len, p.columns.len - 1) catch return error.TooLarge;
        cells = std.math.add(usize, cells, block) catch return error.TooLarge;
        if (cells > sp.max_pivot_cells) return error.TooLarge;
        const cols = try a.dupe(Column, p.columns);
        for (cols[1..]) |*c| c.name = try std.mem.concat(a, u8, &.{ v, spec.separator, c.name });
        p.columns = cols;
        if (out) |o| {
            // The row keys come out in one order for one frame, but a join on the key
            // does not lean on that.
            const rk = try a.alloc(Column, cols.len);
            @memcpy(rk, cols);
            rk[0].name = try std.mem.concat(a, u8, &.{ spec.row_key, "\x00right" });
            p.columns = rk;
            const j = try verbs.join(a, o, p, .{ .on = spec.row_key, .right_on = &.{rk[0].name}, .how = .left });
            out = j;
        } else out = p;
    }
    return out.?;
}

pub const PivotKeysSpec = struct {
    /// Row key columns (pandas `pivot_table(index=[...])`, polars `index=[...]`).
    row_keys: []const []const u8,
    /// Column key columns; a column is named by their texts joined with `separator`.
    col_keys: []const []const u8,
    values: []const []const u8,
    agg: sp.AggFn = .sum,
    q: f64 = 0.5,
    skip_na: bool = false,
    fill_value: ?f64 = null,
    separator: []const u8 = "_",
};

/// `pivotMany` with several row and column key columns: the row keys come out as
/// their own columns (pandas' MultiIndex rows, flattened), then
/// `{value}{sep}{key1}{sep}{key2}…` per value and column-key combination.
pub fn pivotKeys(a: std.mem.Allocator, f: Frame, spec: PivotKeysSpec) Error!Frame {
    try checkRows(f);
    if (spec.row_keys.len == 0 or spec.col_keys.len == 0) return error.NoSuchColumn;
    const rk_name = "\x00rk";
    const ck_name = "\x00ck";
    const fac = an.factorize(a, f, .{ .cols = spec.row_keys, .out = rk_name }) catch |e| return liftAnalysis(e);
    const cidx = try nameIdxs(a, f, spec.col_keys);
    const texts = try a.alloc(Value, f.len);
    var buf: std.ArrayList(u8) = .empty;
    for (texts, 0..) |*o, ri| {
        buf = .empty;
        for (cidx, 0..) |ci, k| {
            if (k > 0) try buf.appendSlice(a, spec.separator);
            const v = f.columnAt(ci).get(ri);
            const tv = ex.castValue(a, v, .text) catch return error.OutOfMemory;
            try buf.appendSlice(a, if (tv == .text) tv.text else "null");
        }
        o.* = .{ .text = buf.items };
    }
    const w = fac.frame.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], fac.frame.columns);
    cols[w] = .{ .name = ck_name, .type = .text };
    const data = try a.alloc(ColumnData, w + 1);
    for (data[0..w], 0..) |*d, i| d.* = fac.frame.columnAt(i);
    data[w] = try fm.columnFromCells(a, texts);
    const work: Frame = .{ .columns = cols, .data = data, .len = f.len };
    const p = try pivotMany(a, work, .{ .row_key = rk_name, .col_key = ck_name, .values = spec.values, .agg = spec.agg, .q = spec.q, .skip_na = spec.skip_na, .fill_value = spec.fill_value, .separator = spec.separator });
    // Code `i` is row `i` of the uniques; -1 (a missing key cell) reads as nulls.
    const idx = try a.alloc(u32, p.len);
    const codes = p.columnAt(0);
    for (idx, 0..) |*o, r| {
        const c = codes.get(r);
        o.* = if (c == .int and c.int >= 0) @intCast(c.int) else keys.none;
    }
    const nk = spec.row_keys.len;
    const out_cols = try a.alloc(Column, nk + p.columns.len - 1);
    const out_data = try a.alloc(ColumnData, out_cols.len);
    for (0..nk) |k| {
        out_cols[k] = fac.uniques.columns[k];
        out_data[k] = try verbs.take(a, fac.uniques.columnAt(k), idx, true);
    }
    for (p.columns[1..], 1..) |c, k| {
        out_cols[nk + k - 1] = c;
        out_data[nk + k - 1] = p.columnAt(k);
    }
    try keys.uniqueNames(a, out_cols);
    return .{ .columns = out_cols, .data = out_data, .len = p.len };
}

// ── dummies ─────────────────────────────────────────────────────────────────

pub const DummiesSpec = struct {
    /// Columns to encode; empty = every text and bool column (pandas' default:
    /// object and categorical columns).
    cols: []const []const u8 = &.{},
    separator: []const u8 = "_",
    /// Leave out the first value's column (pandas `drop_first`).
    drop_first: bool = false,
    /// A column for missing cells too (pandas `dummy_na`).
    dummy_na: bool = false,
};

/// pandas `get_dummies`, polars `to_dummies`: each encoded column replaced by one int
/// 0/1 column per distinct present value, `{column}{separator}{value}`, the values in
/// sorted order (pandas; polars' values come out as `u8`, here `.int`). The other
/// columns keep their order, the dummies follow (pandas).
pub fn dummies(a: std.mem.Allocator, f: Frame, spec: DummiesSpec) Error!Frame {
    try checkRows(f);
    var enc: std.ArrayList(usize) = .empty;
    if (spec.cols.len == 0) {
        for (f.columns, 0..) |c, i| {
            if (c.type == .text or c.type == .bool or c.type == .date) try enc.append(a, i);
        }
    } else for (spec.cols) |n| try enc.append(a, try mustIndex(f, n));
    const is_enc = try a.alloc(bool, f.columns.len);
    @memset(is_enc, false);
    for (enc.items) |i| is_enc[i] = true;
    var cols: std.ArrayList(Column) = .empty;
    var data: std.ArrayList(ColumnData) = .empty;
    // The dummies of all encoded columns together, `cols` naming one twice included.
    var dummy_cells: usize = 0;
    for (f.columns, 0..) |c, i| {
        if (is_enc[i]) continue;
        try cols.append(a, c);
        try data.append(a, f.columnAt(i));
    }
    for (enc.items) |ci| {
        const fac = try verbs.factorKeys(a, f, &.{ci});
        const col = f.columnAt(ci);
        // Present values, sorted.
        var firsts: std.ArrayList(u32) = .empty;
        var has_missing = false;
        for (fac.firsts) |r| {
            if (isMissing(col.get(r))) has_missing = true else try firsts.append(a, r);
        }
        const Ctx = struct {
            col: ColumnData,
            fn less(c: @This(), x: u32, y: u32) bool {
                return c.col.get(x).order(c.col.get(y)) == .lt;
            }
        };
        std.mem.sort(u32, firsts.items, Ctx{ .col = col }, Ctx.less);
        const start: usize = @intFromBool(spec.drop_first and firsts.items.len > 0);
        const n_out = firsts.items.len - start + @intFromBool(spec.dummy_na and has_missing);
        const cells_total = std.math.mul(usize, n_out, f.len) catch return error.TooLarge;
        dummy_cells = std.math.add(usize, dummy_cells, cells_total) catch return error.TooLarge;
        if (dummy_cells > sp.max_aggregate_cells) return error.TooLarge;
        for (firsts.items[start..]) |r| {
            const v = col.get(r);
            const label: []const u8 = if (v == .text) v.text else blk: {
                const t = ex.castValue(a, v, .text) catch return error.OutOfMemory;
                break :blk if (t == .text) t.text else "null";
            };
            const bits = try a.alloc(i64, f.len);
            for (bits, 0..) |*b, ri| {
                const c = col.get(ri);
                b.* = @intFromBool(!isMissing(c) and c.eql(v));
            }
            try cols.append(a, .{ .name = try std.mem.concat(a, u8, &.{ f.columns[ci].name, spec.separator, label }), .type = .int });
            try data.append(a, .{ .int = .{ .values = bits } });
        }
        if (spec.dummy_na and has_missing) {
            const bits = try a.alloc(i64, f.len);
            for (bits, 0..) |*b, ri| b.* = @intFromBool(isMissing(col.get(ri)));
            try cols.append(a, .{ .name = try std.mem.concat(a, u8, &.{ f.columns[ci].name, spec.separator, "null" }), .type = .int });
            try data.append(a, .{ .int = .{ .values = bits } });
        }
    }
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    for (cols.items) |c| {
        const gop = try seen.getOrPut(a, c.name);
        if (gop.found_existing) return error.DuplicateColumn;
    }
    return .{ .columns = cols.items, .data = data.items, .len = f.len };
}

// ── combine_first / update ──────────────────────────────────────────────────

/// pandas `combine_first` by row position (this module has no index): `f`'s cell where
/// it is present, else `g`'s of the same column; `f`'s columns then `g`'s new ones, as
/// many rows as the longer frame. `f`'s declared types.
pub fn combineFirst(a: std.mem.Allocator, f: Frame, g: Frame) Error!Frame {
    try checkRows(f);
    try checkRows(g);
    const rows = @max(f.len, g.len);
    // Both frames' columns, each as tall as the taller one: padding is capped.
    try verbs.growthWithin(
        std.math.mul(usize, std.math.add(usize, f.columns.len, g.columns.len) catch return error.TooLarge, rows) catch return error.TooLarge,
        (f.columns.len *| f.len) +| (g.columns.len *| g.len),
    );
    var cols: std.ArrayList(Column) = .empty;
    var data: std.ArrayList(ColumnData) = .empty;
    const cells = try a.alloc(Value, rows);
    defer a.free(cells);
    var g_names = try fm.NameIndex.init(a, g.columns);
    defer g_names.deinit(a);
    var f_names = try fm.NameIndex.init(a, f.columns);
    defer f_names.deinit(a);
    for (f.columns, 0..) |c, ci| {
        const other: ?usize = g_names.get(c.name);
        const fc = f.columnAt(ci);
        for (cells, 0..) |*o, ri| {
            const v: Value = if (ri < f.len) fc.get(ri) else .null;
            o.* = if (!isMissing(v)) v else if (other) |gi| (if (ri < g.len) g.columnAt(gi).get(ri) else .null) else v;
        }
        try cols.append(a, c);
        try data.append(a, try fm.columnFromCells(a, cells));
    }
    for (g.columns, 0..) |c, gi| {
        if (f_names.get(c.name) != null) continue;
        const gc = g.columnAt(gi);
        for (cells, 0..) |*o, ri| o.* = if (ri < g.len) gc.get(ri) else .null;
        try cols.append(a, c);
        try data.append(a, try fm.columnFromCells(a, cells));
    }
    return .{ .columns = cols.items, .data = data.items, .len = rows };
}

/// pandas `update(other)` by row position: every present cell of `g` overwrites `f`'s
/// cell of the same column and row; `g`'s other columns and rows past `f` are ignored.
/// A new frame (pandas updates in place).
pub fn update(a: std.mem.Allocator, f: Frame, g: Frame) Error!Frame {
    try checkRows(f);
    const data = try shared(a, f);
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    var g_names = try fm.NameIndex.init(a, g.columns);
    defer g_names.deinit(a);
    for (f.columns, 0..) |c, ci| {
        const gi = g_names.get(c.name) orelse continue;
        const fc = f.columnAt(ci);
        const gc = g.columnAt(gi);
        for (cells, 0..) |*o, ri| {
            const v: Value = if (ri < g.len) gc.get(ri) else .null;
            o.* = if (!isMissing(v)) v else fc.get(ri);
        }
        data[ci] = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = f.columns, .data = data, .len = f.len };
}

// ── repeat / scatter / drop_nans ────────────────────────────────────────────

pub const Repeat = union(enum) {
    /// Every row this many times (pandas `df.loc[df.index.repeat(n)]`).
    times: usize,
    /// Each row as many times as its int cell in this column (pandas' `repeat` with a
    /// per-row count, polars `repeat_by` flattened); a missing count is 0, a negative
    /// one `error.BadArgument`.
    by: []const u8,
};

/// Rows repeated in place, in order (pandas `Series.repeat`/`index.repeat`). Output
/// cells capped at `max_join_cells`.
pub fn repeatRows(a: std.mem.Allocator, f: Frame, how: Repeat) Error!Frame {
    try checkRows(f);
    var total: usize = 0;
    const counts = try a.alloc(usize, f.len);
    defer a.free(counts);
    const bc: ?ColumnData = switch (how) {
        .times => null,
        .by => |n| f.columnAt(try mustIndex(f, n)),
    };
    for (counts, 0..) |*c, ri| {
        c.* = switch (how) {
            .times => |t| t,
            .by => blk: {
                const v = bc.?.get(ri);
                if (isMissing(v)) break :blk 0;
                const k = v.asInt() orelse return error.BadArgument;
                if (k < 0) return error.BadArgument;
                break :blk std.math.cast(usize, k) orelse return error.TooLarge;
            },
        };
        total = std.math.add(usize, total, c.*) catch return error.TooLarge;
    }
    const cells = std.math.mul(usize, total, @max(f.columns.len, 1)) catch return error.TooLarge;
    if (cells > sp.max_join_cells or total >= keys.none) return error.TooLarge;
    const idx = try a.alloc(u32, total);
    var at: usize = 0;
    for (counts, 0..) |c, ri| {
        @memset(idx[at..][0..c], @intCast(ri));
        at += c;
    }
    return verbs.takeRows(a, f, idx);
}

pub const ScatterSpec = struct {
    col: []const u8,
    /// Row positions, a negative one from the end (polars `scatter`).
    idx: []const i64,
    /// One per position, or one for all.
    values: []const Value,
};

/// polars `Series.scatter`, pandas `df.iloc[idx, col] = values`: the column with the
/// cells at `idx` set; a later position overwrites an earlier one.
pub fn scatter(a: std.mem.Allocator, f: Frame, spec: ScatterSpec) Error!Frame {
    const ci = try mustIndex(f, spec.col);
    if (!(spec.values.len == 1 or spec.values.len == spec.idx.len)) return error.BadArgument;
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    const col = f.columnAt(ci);
    for (cells, 0..) |*c, ri| c.* = col.get(ri);
    const n: i64 = @intCast(f.len);
    for (spec.idx, 0..) |i, k| {
        const r = if (i < 0) n + i else i;
        if (r < 0 or r >= n) return error.IndexOutOfBounds;
        cells[@intCast(r)] = if (spec.values.len == 1) spec.values[0] else spec.values[k];
    }
    const data = try shared(a, f);
    data[ci] = try fm.columnFromCells(a, cells);
    return .{ .columns = f.columns, .data = data, .len = f.len };
}

/// polars `drop_nans`: drop the rows with a NaN float in `subset` (empty = every
/// column); a null is kept (`dropna` drops both).
pub fn dropNans(a: std.mem.Allocator, f: Frame, subset: []const []const u8) Error!Frame {
    try checkRows(f);
    const idxs: []const usize = if (subset.len == 0) blk: {
        const all = try a.alloc(usize, f.columns.len);
        for (all, 0..) |*x, i| x.* = i;
        break :blk all;
    } else try nameIdxs(a, f, subset);
    const kept = try a.alloc(u32, f.len);
    var n: usize = 0;
    for (0..f.len) |ri| {
        var nan = false;
        for (idxs) |ci| {
            const v = f.columnAt(ci).get(ri);
            nan = nan or (v == .float and std.math.isNan(v.float));
        }
        kept[n] = @intCast(ri);
        n += @intFromBool(!nan);
    }
    return verbs.takeRows(a, f, kept[0..n]);
}

// ── schema ──────────────────────────────────────────────────────────────────

pub const MatchSchemaSpec = struct {
    /// A schema column the frame lacks: `error.SchemaMismatch` (polars' default
    /// `"raise"`) or a column of nulls (`"insert"`).
    missing_columns: enum { raise, insert } = .raise,
    /// A frame column the schema lacks: `error.SchemaMismatch` (`"raise"`) or dropped
    /// (`"ignore"`).
    extra_columns: enum { raise, ignore } = .raise,
    /// A column of another type: `error.SchemaMismatch` (polars forbids by default), or
    /// cast with `cast`'s rule, an unconvertible cell `error.CastFailed`.
    cast: bool = false,
};

/// polars `match_to_schema`: the frame's columns in `schema`'s order and types.
pub fn matchToSchema(a: std.mem.Allocator, f: Frame, schema: []const Column, spec: MatchSchemaSpec) Error!Frame {
    var f_names = try fm.NameIndex.init(a, f.columns);
    defer f_names.deinit(a);
    // Each cast converts its one column (a cast of the whole frame per column copies the
    // schema and the arrays of every column, O(schema x width) arena memory).
    const casted = try a.alloc(?ColumnData, schema.len);
    @memset(casted, null);
    for (schema, casted) |c, *cd| {
        const ci = f_names.get(c.name) orelse continue;
        if (f.columns[ci].type == c.type) continue;
        if (!spec.cast) return error.SchemaMismatch;
        const one_data = [1]ColumnData{f.columnAt(ci)};
        const one: Frame = .{ .columns = f.columns[ci..][0..1], .data = &one_data, .len = f.len };
        const r = ex.cast(a, one, .{ .col = c.name, .to = c.type, .on_error = .fail }) catch |e| return switch (e) {
            error.CastFailed => error.CastFailed,
            error.OutOfMemory => error.OutOfMemory,
            else => error.SchemaMismatch,
        };
        cd.* = r.data[0];
    }
    if (spec.extra_columns == .raise) {
        var in_schema: std.StringHashMapUnmanaged(void) = .empty;
        defer in_schema.deinit(a);
        for (schema) |s| try in_schema.put(a, s.name, {});
        for (f.columns) |c| {
            if (!in_schema.contains(c.name)) return error.SchemaMismatch;
        }
    }
    const cols = try a.dupe(Column, schema);
    const data = try a.alloc(ColumnData, schema.len);
    for (schema, data, casted) |c, *d, cd| {
        if (f_names.get(c.name)) |ci| {
            d.* = cd orelse f.columnAt(ci);
        } else {
            if (spec.missing_columns == .raise) return error.SchemaMismatch;
            d.* = .nulls;
        }
    }
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    for (cols) |c| {
        const gop = try seen.getOrPut(a, c.name);
        if (gop.found_existing) return error.DuplicateColumn;
    }
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// A row-major `rows x cols` matrix of floats (pandas `to_numpy(dtype=float)`, polars
/// `to_numpy`): a number as `f64`, anything missing or not a number NaN.
pub const Matrix = struct { rows: usize, cols: usize, data: []f64 };

pub fn toFloatMatrix(a: std.mem.Allocator, f: Frame, names: []const []const u8) Error!Matrix {
    const idxs: []const usize = if (names.len == 0) blk: {
        const all = try a.alloc(usize, f.columns.len);
        for (all, 0..) |*x, i| x.* = i;
        break :blk all;
    } else try nameIdxs(a, f, names);
    const n = std.math.mul(usize, f.len, idxs.len) catch return error.TooLarge;
    const out = try a.alloc(f64, n);
    for (0..f.len) |ri| {
        for (idxs, 0..) |ci, k| {
            const v = f.columnAt(ci).get(ri);
            out[ri * idxs.len + k] = if (v == .null) std.math.nan(f64) else v.asFloat() orelse std.math.nan(f64);
        }
    }
    return .{ .rows = f.len, .cols = idxs.len, .data = out };
}

// ── hash_rows ───────────────────────────────────────────────────────────────

/// polars `hash_rows(seed)`: a 64-bit hash of each row's cells, as an `.int` column
/// (the bits of a `u64`). Equal rows (by key equality: `1` and `1.0` equal, null and NaN
/// equal) hash equal. The values are this module's (Wyhash over the canonical key
/// encoding), not polars'.
pub fn hashRows(a: std.mem.Allocator, f: Frame, seed: u64, out: []const u8) Error!Frame {
    const hs = try a.alloc(i64, f.len);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    for (hs, 0..) |*h, ri| {
        buf.clearRetainingCapacity();
        for (0..f.columns.len) |ci| try keys.encode(a, &buf, f.columnAt(ci).get(ri), .as_null);
        h.* = @bitCast(std.hash.Wyhash.hash(seed, buf.items));
    }
    if (f.columnIndex(out) != null) return error.DuplicateColumn;
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = .{ .name = out, .type = .int };
    const data = try a.alloc(ColumnData, w + 1);
    for (data[0..w], 0..) |*d, i| d.* = f.columnAt(i);
    data[w] = .{ .int = .{ .values = hs } };
    return .{ .columns = cols, .data = data, .len = f.len };
}

// ── between_time ────────────────────────────────────────────────────────────

pub const BetweenTimeSpec = struct {
    /// A temporal column (see `dtfn`): microsecond ints or ISO text.
    col: []const u8,
    /// `HH:MM[:SS[.ffffff]]`; `start > end` wraps past midnight (pandas).
    start: []const u8,
    end: []const u8,
    inclusive: enum { both, left, right, neither } = .both,
};

/// pandas `between_time` (and `at_time` with `start == end`) on a column: the rows
/// whose time of day is in the window; a missing or unreadable time is dropped.
pub fn betweenTime(a: std.mem.Allocator, f: Frame, spec: BetweenTimeSpec) Error!Frame {
    try checkRows(f);
    const ci = try mustIndex(f, spec.col);
    const lo = timeOfDay(spec.start) orelse return error.BadArgument;
    const hi = timeOfDay(spec.end) orelse return error.BadArgument;
    const day: i64 = 86_400 * vm.timestamp_units_per_second;
    const kept = try a.alloc(u32, f.len);
    var n: usize = 0;
    const incl_lo = spec.inclusive == .both or spec.inclusive == .left;
    const incl_hi = spec.inclusive == .both or spec.inclusive == .right;
    for (0..f.len) |ri| {
        const us = dtf.instantOf(f.columnAt(ci).get(ri)) orelse continue;
        const t = @mod(us, day);
        const after_lo = if (incl_lo) t >= lo else t > lo;
        const before_hi = if (incl_hi) t <= hi else t < hi;
        const in = if (lo <= hi) after_lo and before_hi else after_lo or before_hi;
        kept[n] = @intCast(ri);
        n += @intFromBool(in);
    }
    return verbs.takeRows(a, f, kept[0..n]);
}

/// `HH:MM`, `HH:MM:SS` or `HH:MM:SS.ffffff` as microseconds into the day.
fn timeOfDay(t: []const u8) ?i64 {
    var buf: [64]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "1970-01-01T{s}Z", .{t}) catch return null;
    return vm.parseIsoTimestamp(s);
}
