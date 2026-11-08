// SPDX-License-Identifier: MIT
//! Verbs that run a caller's function (survey row 21, and the predicate form of row
//! 25's group filter): pandas `Series.map`/`DataFrame.apply(axis=1)`/
//! `rolling().apply`/`groupby().apply`/`groupby().filter`, polars `map_elements`/
//! `map_rows`/`rolling_map`/`map_groups`/`group_by().filter`.
//!
//! The function is a `comptime` parameter, so each call site is its own instantiation
//! and the call is direct (inlined where the compiler likes), never through a pointer.
//! Every callback has the shape `fn (ctx: C, a: std.mem.Allocator, input) E!Output`:
//! `ctx` is whatever the caller passes (a struct of settings or accumulators, a
//! pointer for state the callback changes, `{}` for none), `a` is the verb's allocator
//! (an arena, as everywhere in this module) for anything the callback builds, and `E`
//! is any error set; a callback that cannot fail may return the output plainly. A
//! callback's error stops the verb and is returned from it as it is.
//!
//! What a callback returns is checked and copied before the next call, so it may
//! point into a buffer it reuses: a cell that is not of the declared `out_type` is
//! `error.WrongOutputType`, a group frame with other columns than the first group's is
//! `error.SchemaMismatch`, groups that together grow the frame past `max_join_cells`
//! cells beyond the input are `error.TooLarge`. A returned frame is read through
//! `ColumnData.get`, as every verb reads a hand-built one (short arrays read as null),
//! and rebuilt, so every result is well-formed whatever the callback hands back.
//! Original work of the zig-libs authors (MIT).

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const sp = @import("spec.zig");
const core = @import("core.zig");
const verbs = @import("verbs.zig");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;

pub const CallbackError = sp.Error || error{
    /// A callback's cell is not one the declared `out_type` holds (a text where an int
    /// was declared; an int is taken for a float, converted, nothing else is), or holds
    /// a hand-made list view that runs backwards (`start > end`).
    WrongOutputType,
    /// A `mapGroups` callback returned a frame whose columns (count, names or types)
    /// differ from the first group's.
    SchemaMismatch,
};

/// The verb's errors and the callback's own.
pub fn ErrorOf(comptime func: anytype) type {
    const R = @typeInfo(@TypeOf(func)).@"fn".return_type orelse
        @compileError("a dataframe callback needs a concrete return type");
    return switch (@typeInfo(R)) {
        .error_union => |eu| CallbackError || eu.error_set,
        else => CallbackError,
    };
}

/// Declares the result column of `mapElements`, `mapRows` and `rollingMap`.
pub const OutColumn = struct {
    /// Its name. Replaced in place when the frame has a column of that name (pandas
    /// `df[c] = ...`, polars `with_columns`), else appended. Empty: the input column's
    /// name (`mapElements`, `rollingMap`), so the column is replaced.
    name: []const u8 = "",
    /// The type every non-null result must have (polars `return_dtype`); null = the
    /// cells decide: one kind of cell is that type, none a float column of nulls
    /// (pandas' NaN), a mix a text-declared column of mixed cells (pandas' `object`).
    type: ?ColumnType = null,
    /// `Column.inner` of a list or struct result.
    inner: []const Column = &.{},
};

pub const MapElementsSpec = struct {
    col: []const u8,
    out: OutColumn = .{},
    /// A missing cell (null or NaN) gives null without a call (polars' `skip_nulls`,
    /// its default). false: the callback sees it (pandas' `na_action=None`).
    skip_missing: bool = true,
};

pub const MapRowsSpec = struct {
    /// The result column: replaced in place when the frame has one of that name, else
    /// appended.
    out: []const u8,
    /// As `OutColumn.type` and `OutColumn.inner`.
    type: ?ColumnType = null,
    inner: []const Column = &.{},
};

/// A row of a frame, handed to a `mapRows` callback: a view, nothing copied.
pub const Row = struct {
    frame: Frame,
    index: usize,

    /// The cell of column `ci` (by position: no lookup); null past the columns.
    pub fn at(r: Row, ci: usize) Value {
        return r.frame.columnAt(ci).get(r.index);
    }

    /// The cell of the column named `name`, or null when there is none (a scan of the
    /// columns: resolve the index once with `frame.columnIndex` in a hot callback).
    pub fn get(r: Row, name: []const u8) ?Value {
        return r.frame.cell(r.index, name);
    }
};

pub const RollingMapSpec = struct {
    col: []const u8,
    out: OutColumn = .{},
    /// Rows in a window; 0 makes every row null.
    window: usize,
    /// Fewest present (not null, not NaN) cells a window needs for a call; null =
    /// `window` (pandas' `min_periods`, polars' `min_samples`). Short of it, null.
    min_periods: ?usize = null,
    /// As `Rolling.center`.
    center: bool = false,
    /// Windows per partition (polars `rolling_map(...).over(...)`); empty = one.
    partition_by: []const []const u8 = &.{},
};

/// The groups of `mapGroups` and `filterGroups`: rows with equal cells in `by`, a
/// missing key a group of its own, first-seen order; empty `by` = one group of every row.
pub const GroupsSpec = struct {
    by: []const []const u8,
};

/// Most element visits `rollingMap` makes (window x rows, summed over partitions): the
/// cells handed to callbacks.
pub const max_rolling_map_work = sp.max_rolling_work;

// ── results ─────────────────────────────────────────────────────────────────

/// `v` as a cell of type `ty`, or null when that type does not hold it.
fn fit(v: Value, ty: ColumnType) ?Value {
    if (v == .null) return v;
    return switch (ty) {
        .int, .timestamp, .duration => if (v == .int) v else null,
        .float => switch (v) {
            .float => v,
            .int => |i| .{ .float = @floatFromInt(i) },
            else => null,
        },
        .text, .date, .categorical => if (v == .text) v else null,
        .bool => if (v == .bool) v else null,
        .decimal => if (v == .decimal) v else null,
        .list => if (v == .list) v else null,
        .@"struct" => if (v == .record) v else null,
    };
}

/// The type the stored cells call for, when none was declared.
fn inferred(d: ColumnData) ColumnType {
    return switch (d) {
        .nulls, .float => .float,
        .int => .int,
        .bool => .bool,
        .decimal => .decimal,
        .text, .boxed => .text,
        .categorical => .categorical,
        .list => .list,
        .@"struct" => .@"struct",
    };
}

fn checked(v: Value, out: OutColumn) CallbackError!Value {
    if (!viewsOk(v, 0)) return error.WrongOutputType;
    const ty = out.type orelse return v;
    return fit(v, ty) orelse error.WrongOutputType;
}

/// Whether every list view in `v`, at every level it is read, has `start <= end`: a
/// view a callback built by hand is the one cell no storage made, and a backwards one
/// would make `ListView.len` overflow. The walk is the copy's own (each element is
/// copied after it); past `max_nesting_depth` a nested value reads as null.
fn viewsOk(v: Value, depth: u8) bool {
    switch (vm.Value.capped(v, depth)) {
        .list => |l| {
            if (l.start > l.end) return false;
            for (0..l.len()) |i| if (!viewsOk(l.get(i), depth + 1)) return false;
        },
        .record => |r| for (0..r.len()) |i| if (!viewsOk(r.get(i), depth + 1)) return false,
        else => {},
    }
    return true;
}

/// The finished column: the declared type (or the inferred one), a categorical one
/// dictionary-encoded.
fn finishColumn(a: std.mem.Allocator, data: ColumnData, len: usize, name: []const u8, out: OutColumn) CallbackError!struct { Column, ColumnData } {
    const ty = out.type orelse inferred(data);
    const d = if (ty == .categorical) try fm.encodeCategorical(a, data, len) else data;
    return .{ .{ .name = name, .type = ty, .inner = out.inner }, d };
}

/// `f` with `col` in place of the column of its name, or appended.
fn withResult(a: std.mem.Allocator, f: Frame, col: Column, data: ColumnData) CallbackError!Frame {
    const at = f.columnIndex(col.name);
    const w = f.columns.len + @intFromBool(at == null);
    const cols = try a.alloc(Column, w);
    const ds = try a.alloc(ColumnData, w);
    for (f.columns, 0..) |c, ci| {
        cols[ci] = c;
        ds[ci] = f.columnAt(ci);
    }
    const ci = at orelse f.columns.len;
    cols[ci] = col;
    ds[ci] = data;
    return .{ .columns = cols, .data = ds, .len = f.len };
}

// ── element-wise and row-wise ───────────────────────────────────────────────

/// `out` = `func(ctx, a, cell)` for each cell of `spec.col`: pandas `Series.map(f)`,
/// polars `map_elements(f, return_dtype=)`. `func`: `fn (C, std.mem.Allocator, Value)
/// E!Value`.
pub fn mapElements(a: std.mem.Allocator, f: Frame, spec: MapElementsSpec, ctx: anytype, comptime func: anytype) ErrorOf(func)!Frame {
    const E = ErrorOf(func);
    try core.checkRowsU32(f.len);
    const ci = f.columnIndex(spec.col) orelse return error.NoSuchColumn;
    const col = f.columnAt(ci);
    var b: fm.ColBuilder = .{ .a = a, .hint = @min(f.len, fm.max_row_hint) };
    for (0..f.len) |ri| {
        const v = col.get(ri);
        if (spec.skip_missing and keys.isMissing(v)) {
            try b.appendNull();
            continue;
        }
        const r = try @as(E!Value, func(ctx, a, v));
        try b.append(try checked(r, spec.out));
    }
    const name = if (spec.out.name.len > 0) spec.out.name else spec.col;
    const c, const d = try finishColumn(a, b.finish(), f.len, name, spec.out);
    return withResult(a, f, c, d);
}

/// `out` = `func(ctx, a, row)` for each row: pandas `DataFrame.apply(f, axis=1)`,
/// polars `map_rows` (one output column; for several, call once per column or build
/// a struct cell). `func`: `fn (C, std.mem.Allocator, Row) E!Value`.
pub fn mapRows(a: std.mem.Allocator, f: Frame, spec: MapRowsSpec, ctx: anytype, comptime func: anytype) ErrorOf(func)!Frame {
    const E = ErrorOf(func);
    try core.checkRowsU32(f.len);
    const out: OutColumn = .{ .name = spec.out, .type = spec.type, .inner = spec.inner };
    var b: fm.ColBuilder = .{ .a = a, .hint = @min(f.len, fm.max_row_hint) };
    for (0..f.len) |ri| {
        const r = try @as(E!Value, func(ctx, a, Row{ .frame = f, .index = ri }));
        try b.append(try checked(r, out));
    }
    const c, const d = try finishColumn(a, b.finish(), f.len, spec.out, out);
    return withResult(a, f, c, d);
}

// ── rolling ─────────────────────────────────────────────────────────────────

/// `out` = `func(ctx, a, window)` for each row's window of `spec.col`'s cells: pandas
/// `rolling(w).apply(f, raw=True)`, polars `rolling_map(f, window_size)`. The window
/// is the cells as they are, missing ones included (pandas hands NaN in); a window with
/// fewer than `min_periods` present cells is null without a call. Rows in order within
/// a partition. `func`: `fn (C, std.mem.Allocator, []const Value) E!Value`. All windows
/// together hand at most `max_rolling_map_work` cells to callbacks, else
/// `error.TooLarge` before the first call.
pub fn rollingMap(a: std.mem.Allocator, f: Frame, spec: RollingMapSpec, ctx: anytype, comptime func: anytype) ErrorOf(func)!Frame {
    const E = ErrorOf(func);
    try core.checkRowsU32(f.len);
    const ci = f.columnIndex(spec.col) orelse return error.NoSuchColumn;
    const name = if (spec.out.name.len > 0) spec.out.name else spec.col;
    const n = f.len;
    const parts = try groupsOf(a, f, spec.partition_by);
    // The whole call's work, before any callback runs.
    var work: usize = 0;
    for (0..parts.count) |g| {
        const m = parts.sizeOf(g);
        work +|= m *| @min(spec.window, m);
        if (work > max_rolling_map_work) return error.TooLarge;
    }
    const out = try a.alloc(Value, n);
    @memset(out, .null);
    const cells = try a.alloc(Value, n);
    const present = try a.alloc(u32, n + 1); // prefix counts of present cells
    const col = f.columnAt(ci);
    const min_p = spec.min_periods orelse spec.window;
    const lead = if (spec.center) (spec.window -| 1) / 2 else 0;
    for (0..if (spec.window > 0) parts.count else 0) |g| {
        const m = parts.sizeOf(g);
        for (cells[0..m], 0..) |*c, k| c.* = col.get(parts.row(g, k));
        present[0] = 0;
        for (cells[0..m], 0..) |c, k| present[k + 1] = present[k] + @intFromBool(!keys.isMissing(c));
        for (0..m) |k| {
            const end = @min(m, k +| lead +| 1);
            const start = @min((k +| lead +| 1) -| spec.window, end);
            if (present[end] - present[start] < min_p) continue;
            const r = try @as(E!Value, func(ctx, a, cells[start..end]));
            // Copied now: the callback may reuse what it returned.
            out[parts.row(g, k)] = try fm.copyValue(a, try checked(r, spec.out), 0);
        }
    }
    const c, const d = try finishColumn(a, try fm.columnFromCells(a, out), n, name, spec.out);
    return withResult(a, f, c, d);
}

// ── groups ──────────────────────────────────────────────────────────────────

/// The row partition of `by` (empty: one group of every row, none of no rows).
const Groups = struct {
    count: usize,
    /// Group of each row; null with one group.
    ids: ?[]const u32 = null,
    mem: ?keys.Members = null,
    /// Rows of the frame (the one group's size when `mem` is null).
    all: usize = 0,

    fn sizeOf(g: Groups, k: usize) usize {
        return if (g.mem) |m| m.of(k).len else g.all;
    }
    fn row(g: Groups, k: usize, i: usize) usize {
        return if (g.mem) |m| m.of(k)[i] else i;
    }
    fn rowsOf(g: Groups, a: std.mem.Allocator, k: usize) CallbackError![]const u32 {
        if (g.mem) |m| return m.of(k);
        const r = try a.alloc(u32, g.all);
        for (r, 0..) |*x, i| x.* = @intCast(i); // `checkRowsU32` holds
        return r;
    }
};

fn groupsOf(a: std.mem.Allocator, f: Frame, by: []const []const u8) CallbackError!Groups {
    if (by.len == 0) return .{ .count = @intFromBool(f.len > 0), .all = f.len };
    const idx = try a.alloc(usize, by.len);
    var names = try fm.NameIndex.init(a, f.columns);
    defer names.deinit(a);
    for (by, idx) |nm, *ix| ix.* = names.get(nm) orelse return error.NoSuchColumn;
    const fac = try verbs.factorKeys(a, f, idx);
    return .{ .count = fac.groups(), .ids = fac.ids, .mem = try keys.members(a, fac.ids, fac.groups()), .all = f.len };
}

/// Each group's rows as a frame through `func(ctx, a, group) E!Frame`, the results
/// stacked in group order (first seen): pandas `groupby(...).apply(f)`, polars
/// `group_by(...).map_groups(f)`. Every result must have the first result's columns
/// (count, names, types; `Column.inner` is the first's), else `error.SchemaMismatch`;
/// all of them together may hold at most `max_join_cells` cells beyond the input's,
/// else `error.TooLarge`. A frame of no rows has no group: the result is its columns
/// with no rows (the callback never ran to give a schema).
pub fn mapGroups(a: std.mem.Allocator, f: Frame, spec: GroupsSpec, ctx: anytype, comptime func: anytype) ErrorOf(func)!Frame {
    const E = ErrorOf(func);
    try core.checkRowsU32(f.len);
    const gs = try groupsOf(a, f, spec.by);
    if (gs.count == 0) {
        const data = try a.alloc(ColumnData, f.columns.len);
        @memset(data, .nulls);
        return .{ .columns = f.columns, .data = data, .len = 0 };
    }
    const in_cells = f.len *| f.columns.len;
    var columns: []Column = &.{};
    var builders: []fm.ColBuilder = &.{};
    var rows: usize = 0;
    for (0..gs.count) |g| {
        const sub = try verbs.takeRows(a, f, try gs.rowsOf(a, g));
        const r = try @as(E!Frame, func(ctx, a, sub));
        if (g == 0) {
            columns = try dupeColumns(a, r.columns);
            builders = try a.alloc(fm.ColBuilder, columns.len);
            for (builders) |*b| b.* = .{ .a = a, .hint = 0 };
        } else if (!sameSchema(columns, r.columns)) return error.SchemaMismatch;
        // Checked before a cell is copied: a result claiming a huge `len` costs nothing.
        rows = std.math.add(usize, rows, r.len) catch return error.TooLarge;
        try core.checkRowsU32(rows);
        try verbs.growthWithin(rows *| columns.len, in_cells);
        for (builders, 0..) |*b, ci| {
            const d = r.columnAt(ci);
            for (0..r.len) |ri| {
                const v = d.get(ri);
                // A boxed column (at any level) may hold views no storage made.
                if (!viewsOk(v, 0)) return error.WrongOutputType;
                try b.append(v);
            }
        }
    }
    const data = try a.alloc(ColumnData, columns.len);
    for (data, builders) |*d, *b| d.* = b.finish();
    return fm.encodeDeclared(a, .{ .columns = columns, .data = data, .len = rows });
}

/// The rows of the groups `pred(ctx, a, group) E!bool` keeps, in input order: pandas
/// `groupby(...).filter(f)`, polars `group_by(...)` with a predicate over the group. The
/// statistic form (`agg op value`, no callback) is `groupFilter`.
pub fn filterGroups(a: std.mem.Allocator, f: Frame, spec: GroupsSpec, ctx: anytype, comptime pred: anytype) ErrorOf(pred)!Frame {
    const E = ErrorOf(pred);
    try core.checkRowsU32(f.len);
    const gs = try groupsOf(a, f, spec.by);
    const keep = try a.alloc(bool, gs.count);
    for (keep, 0..) |*k, g| {
        const sub = try verbs.takeRows(a, f, try gs.rowsOf(a, g));
        k.* = try @as(E!bool, pred(ctx, a, sub));
    }
    const kept = try a.alloc(u32, f.len);
    var n: usize = 0;
    for (0..f.len) |ri| {
        const g = if (gs.ids) |ids| ids[ri] else 0;
        kept[n] = @intCast(ri);
        n += @intFromBool(keep[g]);
    }
    return verbs.takeRows(a, f, kept[0..n]);
}

fn sameSchema(want: []const Column, got: []const Column) bool {
    if (want.len != got.len) return false;
    for (want, got) |w, g| {
        if (w.type != g.type or !std.mem.eql(u8, w.name, g.name)) return false;
    }
    return true;
}

/// The first group's columns, names and the declared inner columns copied (the callback
/// may have built them in a buffer it reuses), `max_nesting_depth` levels at most.
fn dupeColumns(a: std.mem.Allocator, cols: []const Column) CallbackError![]Column {
    return dupeColumnsAt(a, cols, 0);
}

fn dupeColumnsAt(a: std.mem.Allocator, cols: []const Column, depth: u8) CallbackError![]Column {
    const out = try a.alloc(Column, cols.len);
    for (out, cols) |*o, c| {
        o.* = .{
            .name = try a.dupe(u8, c.name),
            .type = c.type,
            .inner = if (depth + 1 >= vm.max_nesting_depth) &.{} else try dupeColumnsAt(a, c.inner, depth + 1),
        };
    }
    return out;
}
