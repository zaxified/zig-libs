// SPDX-License-Identifier: MIT
//! The verbs on `Frame`. Each takes `(allocator, Frame, Spec)` and returns a new
//! `Frame`; nothing is mutated. They give the same cells as the row verbs of the same
//! name in `tabular` (`verbs_test.zig` checks it on generated tables of every column
//! shape), which are pinned to pandas and polars by `tabular`'s oracle vectors. A
//! column of mixed kinds is `.boxed` and takes the same path through `Value`, so
//! nothing is refused for being untyped.
//!
//! **A result borrows from its input.** Untouched columns are shared, not copied, so the
//! input (and the spec's names) must stay alive as long as the result. Pass an arena: a
//! result has no `deinit`, and temporaries (key rows, number arrays, row indexes) stay in
//! it until it goes, so a wide `aggregate` over a big frame holds about 40 bytes per row
//! per aggregate that takes the slow path.

const std = @import("std");
const vm = @import("value.zig");
const fm = @import("frame.zig");
const core = @import("core.zig");
const keys = @import("keys.zig");
const sp = @import("spec.zig");
const win = @import("window.zig");
const ex = @import("expr.zig");
const jsonio = @import("jsonio.zig");
const Column = vm.Column;
const ColumnType = vm.ColumnType;
const Value = vm.Value;
const ColumnData = fm.ColumnData;
const Frame = fm.Frame;

pub const Error = sp.Error;

fn mustIndex(f: Frame, name: []const u8) Error!usize {
    return f.columnIndex(name) orelse error.NoSuchColumn;
}

/// Column positions by name for a verb that resolves many names. A few names scan the
/// columns; many build a `NameIndex` once, since a scan per name is quadratic in the
/// width (a `pivot` or `transpose` makes frames of millions of columns).
pub const Names = struct {
    f: Frame,
    idx: ?fm.NameIndex = null,

    const scan_below = 16;

    pub fn init(a: std.mem.Allocator, f: Frame, count: usize) Error!Names {
        if (count < scan_below or f.columns.len < scan_below) return .{ .f = f };
        return .{ .f = f, .idx = try fm.NameIndex.init(a, f.columns) };
    }

    pub fn deinit(n: *Names, a: std.mem.Allocator) void {
        if (n.idx) |*i| i.deinit(a);
    }

    pub fn of(n: Names, name: []const u8) Error!usize {
        if (n.idx) |i| return i.get(name) orelse error.NoSuchColumn;
        return mustIndex(n.f, name);
    }
};

/// A verb may create at most `sp.max_join_cells` cells beyond the cells its inputs hold
/// (padding a shorter frame to a longer one's height multiplies width by height, not by
/// anything the caller handed over): `error.TooLarge` past that.
pub fn growthWithin(out_cells: usize, in_cells: usize) Error!void {
    if (out_cells > in_cells +| sp.max_join_cells) return error.TooLarge;
}

/// A hand-built frame may have fewer arrays than columns: those read as null.
inline fn colOf(f: Frame, ci: usize) ColumnData {
    return if (ci < f.data.len) f.data[ci] else .nulls;
}

fn bitsLen(rows: usize) usize {
    return rows / 64 + @intFromBool(rows % 64 != 0);
}

/// One bit per row, every row present.
/// Every row's bit set, and no bit past `rows` (a reader that counts whole words, as a
/// consumer of the public arrays may, sees exactly `rows`).
fn allValid(a: std.mem.Allocator, rows: usize) Error![]u64 {
    const bits = try a.alloc(u64, bitsLen(rows));
    @memset(bits, ~@as(u64, 0));
    if (rows % 64 != 0) bits[bits.len - 1] = (@as(u64, 1) << @intCast(rows % 64)) - 1;
    return bits;
}

inline fn clearBit(bits: []u64, row: usize) void {
    bits[row / 64] &= ~(@as(u64, 1) << @intCast(row % 64));
}

inline fn testBit(bits: []const u64, row: usize) bool {
    return (bits[row / 64] >> @intCast(row % 64)) & 1 == 1;
}

/// Numbers of one column as `Value.asFloat` reads them, a missing cell as 0, and which
/// cells were present (`valid == null`: all of them). `xs` may borrow from the column.
const Floats = struct { xs: []const f64, valid: ?[]const u64 };

fn readFloats(a: std.mem.Allocator, col: ColumnData, rows: usize) Error!Floats {
    switch (col) {
        .float => |c| if (c.valid == null and c.values.len == rows) return .{ .xs = c.values, .valid = null },
        .int => |c| if (c.valid == null and c.values.len == rows) {
            const xs = try a.alloc(f64, rows);
            for (xs, c.values) |*x, v| x.* = @floatFromInt(v);
            return .{ .xs = xs, .valid = null };
        },
        else => {},
    }
    const xs = try a.alloc(f64, rows);
    const bits = try allValid(a, rows);
    var any_missing = false;
    for (xs, 0..) |*x, ri| {
        if (col.get(ri).asFloat()) |v| {
            x.* = v;
        } else {
            x.* = 0;
            clearBit(bits, ri);
            any_missing = true;
        }
    }
    return .{ .xs = xs, .valid = if (any_missing) bits else null };
}

fn readOperand(a: std.mem.Allocator, f: Frame, op: sp.Operand) Error!Floats {
    switch (op) {
        .col => |name| return readFloats(a, colOf(f, try mustIndex(f, name)), f.len),
        .num => |n| {
            const xs = try a.alloc(f64, f.len);
            @memset(xs, n);
            return .{ .xs = xs, .valid = null };
        },
    }
}

/// `f` plus one column, every other column shared.
fn appended(a: std.mem.Allocator, f: Frame, col: Column, data: ColumnData) Error!Frame {
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = col;
    const out = try a.alloc(ColumnData, w + 1);
    for (out[0..w], 0..) |*d, ci| d.* = colOf(f, ci);
    out[w] = data;
    return .{ .columns = cols, .data = out, .len = f.len };
}

/// `out = lhs op rhs` appended as a float column (`MapSpec`).
pub fn map(a: std.mem.Allocator, f: Frame, spec: sp.MapSpec) Error!Frame {
    const unary = spec.op == .abs or spec.op == .sqrt;
    const lhs = try readOperand(a, f, spec.lhs);
    const rhs: Floats = if (unary) .{ .xs = &.{}, .valid = null } else try readOperand(a, f, spec.rhs);
    const out = try a.alloc(f64, f.len);
    const as_null = spec.on_missing == .null;

    // Present in the result; only `.null` mode ever clears a bit.
    var valid: ?[]u64 = null;
    if (as_null and (lhs.valid != null or rhs.valid != null)) {
        const bits = try allValid(a, f.len);
        if (lhs.valid) |v| {
            for (bits, v) |*b, x| b.* &= x;
        }
        if (rhs.valid) |v| {
            for (bits, v) |*b, x| b.* &= x;
        }
        valid = bits;
    }

    const l = lhs.xs;
    const r = rhs.xs;
    switch (spec.op) {
        .add => for (out, l, r) |*o, x, y| {
            o.* = x + y;
        },
        .sub => for (out, l, r) |*o, x, y| {
            o.* = x - y;
        },
        .mul => for (out, l, r) |*o, x, y| {
            o.* = x * y;
        },
        .min => for (out, l, r) |*o, x, y| {
            o.* = @min(x, y);
        },
        .max => for (out, l, r) |*o, x, y| {
            o.* = @max(x, y);
        },
        .abs => for (out, l) |*o, x| {
            o.* = @abs(x);
        },
        .div => for (out, l, r, 0..) |*o, x, y, ri| {
            if (y == 0) {
                o.* = 0;
                if (as_null) {
                    if (valid == null) valid = try allValid(a, f.len);
                    clearBit(valid.?, ri);
                }
            } else {
                o.* = x / y;
            }
        },
        .sqrt => for (out, l, 0..) |*o, x, ri| {
            if (x < 0) {
                o.* = 0;
                if (as_null) {
                    if (valid == null) valid = try allValid(a, f.len);
                    clearBit(valid.?, ri);
                }
            } else {
                o.* = @sqrt(x);
            }
        },
    }
    // A null cell holds 0 in `values` (`TypedColumn`'s contract).
    if (valid) |bits| {
        for (out, 0..) |*o, ri| {
            if (!testBit(bits, ri)) o.* = 0;
        }
    }
    return appended(a, f, .{ .name = spec.out, .type = spec.out_type }, .{ .float = .{ .values = out, .valid = valid } });
}

fn valueFloats(a: std.mem.Allocator, f: Frame, name: []const u8) Error![]const f64 {
    return (try readFloats(a, colOf(f, try mustIndex(f, name)), f.len)).xs;
}

fn appendFloats(a: std.mem.Allocator, f: Frame, name: []const u8, out: []const f64) Error!Frame {
    return appended(a, f, .{ .name = name, .type = .float }, .{ .float = .{ .values = out } });
}

/// Running sum of `value_col` appended as column `out` (pandas `cumsum`, polars
/// `cum_sum`): a missing cell is skipped and its row is null, an all-int column stays
/// int (null from an overflow on). `window` with `.cum_sum`, one partition.
pub fn cumsum(a: std.mem.Allocator, f: Frame, spec: sp.ColSpec) win.WindowError!Frame {
    return win.window(a, f, .{ .value_col = spec.value_col, .out = spec.out, .op = .cum_sum });
}

/// A rolling window aggregate of `value_col` appended as float column `out` (pandas
/// `rolling(window).agg()`, polars `rolling_*`): missing cells are skipped, and a row
/// whose window holds fewer than `window` values is null (pandas' `min_periods`
/// default). `std_sample` is the sample (n - 1) deviation. `window` with `.rolling`.
pub fn rolling(a: std.mem.Allocator, f: Frame, spec: sp.RollSpec) win.WindowError!Frame {
    const func: win.WinFn = switch (spec.func) {
        .mean => .mean,
        .sum => .sum,
        .std_sample => .std,
        .min => .min,
        .max => .max,
    };
    return win.window(a, f, .{ .value_col = spec.value_col, .out = spec.out, .op = .{ .rolling = .{ .window = spec.window, .func = func } } });
}

// ── filter ──────────────────────────────────────────────────────────────────

inline fn markFn(comptime all: bool, keep: *u8, h: bool) void {
    if (all) {
        keep.* &= @intFromBool(h);
    } else {
        keep.* |= @intFromBool(h);
    }
}

fn markTyped(comptime T: type, comptime op: sp.CmpOp, comptime all: bool, keep: []u8, xs: []const T, y: T) void {
    for (keep, xs) |*k, x| {
        const h = switch (op) {
            .eq => x == y,
            // A NaN cell is missing, and `ne` holds for no missing cell.
            .ne => x != y and x == x,
            .lt => x < y,
            .le => x <= y,
            .gt => x > y,
            .ge => x >= y,
            .is_null, .not_null => unreachable,
        };
        markFn(all, k, h);
    }
}

fn markPredicate(comptime all: bool, keep: []u8, col: ColumnData, p: sp.Predicate) void {
    const typed_op = p.op != .is_null and p.op != .not_null;
    if (typed_op and col == .float and p.value == .float and col.float.valid == null and col.float.values.len == keep.len) {
        const xs = col.float.values;
        const y = p.value.float;
        if (std.math.isNan(y)) {
            if (all) @memset(keep, 0);
            return;
        }
        switch (p.op) {
            .is_null, .not_null => unreachable,
            inline else => |op| markTyped(f64, op, all, keep, xs, y),
        }
        return;
    }
    if (typed_op and col == .int and p.value == .int and col.int.valid == null and col.int.values.len == keep.len) {
        const xs = col.int.values;
        const y = p.value.int;
        switch (p.op) {
            .is_null, .not_null => unreachable,
            inline else => |op| markTyped(i64, op, all, keep, xs, y),
        }
        return;
    }
    for (keep, 0..) |*k, ri| markFn(all, k, core.holds(p, col.get(ri)));
}

/// The rows `idx` names of every column, in `columns`' order. A selection of all the rows
/// in order shares the input instead.
pub fn takeRows(a: std.mem.Allocator, f: Frame, idx: []const u32) Error!Frame {
    const data = try a.alloc(ColumnData, f.columns.len);
    const same = isIdentity(idx, f.len);
    for (data, 0..) |*d, ci| d.* = if (same) colOf(f, ci) else try take(a, colOf(f, ci), idx, false);
    return .{ .columns = f.columns, .data = data, .len = idx.len };
}

fn checkRowIndexes(f: Frame) Error!void {
    return core.checkRowsU32(f.len);
}

/// The rows `spec.where` keeps (`Predicate` says what a missing cell matches). A kept
/// column is copied; all rows kept shares them.
pub fn filter(a: std.mem.Allocator, f: Frame, spec: sp.FilterSpec) Error!Frame {
    try checkRowIndexes(f);
    const idxs = try a.alloc(usize, spec.where.len);
    for (spec.where, idxs) |p, *ci| ci.* = try mustIndex(f, p.col);
    const keep = try a.alloc(u8, f.len);
    defer a.free(keep);
    const all = spec.mode == .all;
    @memset(keep, @intFromBool(all));
    for (spec.where, idxs) |p, ci| {
        if (all) markPredicate(true, keep, colOf(f, ci), p) else markPredicate(false, keep, colOf(f, ci), p);
    }
    const kept = try a.alloc(u32, f.len);
    var n: usize = 0;
    for (keep, 0..) |k, ri| {
        kept[n] = @intCast(ri);
        n += k;
    }
    return takeRows(a, f, kept[0..n]);
}

// ── keys of a whole column ──────────────────────────────────────────────────

/// A numeric column as ints, a missing cell (null, NaN) as one value no cell has: that
/// one key is its own group, as `.as_null` says, and the int table still fits. null when
/// a cell is not a whole number or the whole i64 range is taken.
fn intsWithMissing(a: std.mem.Allocator, col: ColumnData, rows: usize) Error!?[]const i64 {
    switch (col) {
        .int => |c| {
            if (c.values.len != rows) return null;
            if (c.valid == null) return c.values;
        },
        .float => |c| if (c.values.len != rows) return null,
        else => return null,
    }
    const out = try a.alloc(i64, rows);
    const missing = try allValid(a, rows);
    var lo: i64 = std.math.maxInt(i64);
    var hi: i64 = std.math.minInt(i64);
    var any_missing = false;
    for (out, 0..) |*o, ri| {
        const v = col.get(ri);
        if (keys.isMissing(v)) {
            clearBit(missing, ri);
            any_missing = true;
            continue;
        }
        const x = keys.exactInt(v) orelse return null;
        o.* = x;
        lo = @min(lo, x);
        hi = @max(hi, x);
    }
    if (!any_missing) return out;
    const sentinel: i64 = if (lo > std.math.minInt(i64))
        lo - 1
    else if (hi < std.math.maxInt(i64))
        hi + 1
    else
        return null;
    for (out, 0..) |*o, ri| {
        if (!testBit(missing, ri)) o.* = sentinel;
    }
    return out;
}

/// Every cell of a text column, when none is null. The slices borrow from the column.
fn plainTexts(a: std.mem.Allocator, col: ColumnData, rows: usize) Error!?[]const []const u8 {
    if (col != .text or col.text.valid != null or rows == 0) return null;
    const out = try a.alloc([]const u8, rows);
    for (out, 0..) |*o, ri| o.* = col.text.at(ri) orelse return null;
    return out;
}

const pos_zero = [_]usize{0};

fn factorColumn(a: std.mem.Allocator, f: Frame, ci: usize) Error!keys.Factors {
    const col = colOf(f, ci);
    if (f.len > 0) {
        if (try intsWithMissing(a, col, f.len)) |xs| return keys.factorizeInts(a, xs);
        if (try plainTexts(a, col, f.len)) |xs| return keys.factorizeTexts(a, xs);
    }
    return keys.factorize(a, try keyRows(a, f, &.{ci}), &pos_zero, .as_null);
}

/// Dense group ids, first-seen order, as `keys.factorizeMany` gives a row verb.
pub fn factorKeys(a: std.mem.Allocator, f: Frame, idxs: []const usize) Error!keys.Factors {
    if (idxs.len == 0) return keys.factorize(a, try keyRows(a, f, idxs), idxs, .as_null);
    const first = try factorColumn(a, f, idxs[0]);
    if (idxs.len == 1) return first;
    const more = try a.alloc(keys.Factors, idxs.len - 1);
    defer a.free(more);
    for (more, idxs[1..]) |*m, ci| m.* = try factorColumn(a, f, ci);
    return keys.combine(a, first.ids, first.groups(), more);
}

// ── distinct ────────────────────────────────────────────────────────────────

/// One row per distinct key (`spec.keys`, empty = every column), the kept rows in
/// input order; `keep` picks which occurrence (pandas `drop_duplicates`, polars `unique`).
pub fn distinct(a: std.mem.Allocator, f: Frame, spec: sp.DistinctSpec) Error!Frame {
    try checkRowIndexes(f);
    const n_keys = if (spec.keys.len == 0) f.columns.len else spec.keys.len;
    const idxs = try a.alloc(usize, n_keys);
    var names = try Names.init(a, f, spec.keys.len);
    defer names.deinit(a);
    for (idxs, 0..) |*ix, i| ix.* = if (spec.keys.len == 0) i else try names.of(spec.keys[i]);
    const fac = try factorKeys(a, f, idxs);
    switch (spec.keep) {
        .first => return takeRows(a, f, fac.firsts),
        .last => {
            const idx = try a.alloc(u32, fac.groups());
            for (fac.ids, 0..) |g, ri| idx[g] = @intCast(ri);
            // The kept rows in their input order, as pandas and polars keep them.
            std.mem.sort(u32, idx, {}, std.sort.asc(u32));
            return takeRows(a, f, idx);
        },
        .none => {
            const cnt = try a.alloc(u32, fac.groups());
            defer a.free(cnt);
            @memset(cnt, 0);
            for (fac.ids) |g| cnt[g] += 1;
            var idx: std.ArrayList(u32) = .empty;
            for (fac.firsts, cnt) |ri, c| {
                if (c == 1) try idx.append(a, ri);
            }
            return takeRows(a, f, idx.items);
        },
    }
}

// ── aggregate ───────────────────────────────────────────────────────────────

/// Every cell of a numeric column as `f64`, when every cell is a number; what
/// `accumulateClean` runs on. Otherwise null, and `accumulate` reads key rows.
fn cleanValues(a: std.mem.Allocator, col: ColumnData, rows: usize) Error!?[]const f64 {
    switch (col) {
        .float => |c| return if (c.valid == null and c.values.len == rows) c.values else null,
        .int => |c| {
            if (c.valid != null or c.values.len != rows) return null;
            const xs = try a.alloc(f64, rows);
            for (xs, c.values) |*x, v| x.* = @floatFromInt(v);
            return xs;
        },
        .decimal => |c| {
            if (c.valid != null or c.values.len != rows) return null;
            const xs = try a.alloc(f64, rows);
            for (xs, 0..) |*x, ri| x.* = col.get(ri).asFloat().?;
            return xs;
        },
        else => return null,
    }
}

/// Group by `group_by` and aggregate (`AggFn`), one row per group in first-seen order,
/// or sorted with `sort_groups` (pandas `groupby().agg()`, polars `group_by().agg()`).
pub fn aggregate(a: std.mem.Allocator, f: Frame, spec: sp.AggregateSpec) Error!Frame {
    return aggregateImpl(a, f, spec, true);
}

/// Per group, the rows `count` (missing cells skipped when `skip`) or `size` counts, from the
/// ids and the column's array: no key rows. false when the column is not a plain typed one.
fn countFromIds(col: ColumnData, ids: []const u32, size: bool, skip: bool, cells: []Value) bool {
    if (!size and skip) {
        switch (col) {
            .int => |c| if (c.values.len != ids.len) return false,
            .float => |c| if (c.values.len != ids.len) return false,
            .bool => |c| if (c.values.len != ids.len) return false,
            .decimal => |c| if (c.values.len != ids.len) return false,
            .text => |c| if (c.offsets.len != ids.len + 1) return false,
            else => return false,
        }
    }
    @memset(cells, .{ .int = 0 });
    for (ids, 0..) |g, ri| {
        if (!size and skip) {
            const present = switch (col) {
                .float => |c| c.isValid(ri) and !std.math.isNan(c.values[ri]),
                .int => |c| c.isValid(ri),
                .bool => |c| c.isValid(ri),
                .decimal => |c| c.isValid(ri),
                .text => |c| c.isValid(ri),
                else => unreachable,
            };
            if (!present) continue;
        }
        cells[g].int += 1;
    }
    return true;
}

/// The element column of `implode`'s list: the source column, unnamed.
fn implodedInner(a: std.mem.Allocator, src: Column) Error![]const Column {
    const inner = try a.alloc(Column, 1);
    inner[0] = .{ .name = "", .type = src.type, .inner = src.inner };
    return inner;
}

fn aggregateImpl(a: std.mem.Allocator, f: Frame, spec: sp.AggregateSpec, typed: bool) Error!Frame {
    try checkRowIndexes(f);
    const gidx = try nameIdxs(a, f, spec.group_by);
    const sidx = try a.alloc(usize, spec.aggs.len);
    for (spec.aggs, sidx) |ag, *ci| ci.* = try mustIndex(f, ag.src);
    const rate_idx: ?usize = if (spec.fx) |fx| try mustIndex(f, fx.rate_col) else null;

    const fac = try factorKeys(a, f, gidx);
    const n = fac.groups();
    try core.aggregateCellsWithin(n, spec.aggs.len);

    const cols = try a.alloc(Column, gidx.len + spec.aggs.len);
    for (gidx, 0..) |ci, i| cols[i] = f.columns[ci];
    for (spec.aggs, 0..) |ag, i| {
        const ty = core.aggOutType(f.columns, sidx[i], ag.func, rate_idx != null);
        // `first`, `min`, `mode`… of a nested column keep its declared inner columns.
        cols[gidx.len + i] = .{ .name = ag.out, .type = ty, .inner = if (ag.func == .implode)
            try implodedInner(a, f.columns[sidx[i]])
        else if (ty == f.columns[sidx[i]].type) f.columns[sidx[i]].inner else &.{} };
    }
    try keys.uniqueNames(a, cols);

    const data = try a.alloc(ColumnData, cols.len);
    for (gidx, data[0..gidx.len]) |ci, *d| d.* = try take(a, colOf(f, ci), fac.firsts, false);
    for (spec.aggs, sidx, data[gidx.len..]) |ag, ci, *d| {
        const cells = try a.alloc(Value, n);
        const sink: core.Sink = .{ .cells = cells, .stride = 1, .offset = 0 };
        const clean = if (rate_idx == null and core.cleanFn(ag.func)) try cleanValues(a, colOf(f, ci), f.len) else null;
        const opts: core.Opts = .{ .q = ag.q, .ddof = ag.ddof, .interp = ag.interpolation };
        if (typed and rate_idx == null and (ag.func == .count or ag.func == .size) and
            countFromIds(colOf(f, ci), fac.ids, ag.func == .size, spec.skip_na, cells))
        {
            // counted from the ids
        } else if (clean) |vals| {
            try core.accumulateClean(a, vals, fac.ids, n, ag.func, opts, spec.skip_na, sink);
        } else if (rate_idx) |ri| {
            const rows = try keyRows(a, f, &.{ ci, ri });
            try core.accumulate(a, rows, fac.ids, n, 0, 1, ag.func, opts, spec.skip_na, sink);
        } else {
            const rows = try keyRows(a, f, &.{ci});
            try core.accumulate(a, rows, fac.ids, n, 0, null, ag.func, opts, spec.skip_na, sink);
        }
        if (ag.min_count > 0 and (ag.func == .sum or ag.func == .prod)) {
            const present = try a.alloc(usize, n);
            defer a.free(present);
            @memset(present, 0);
            const col = colOf(f, ci);
            for (fac.ids, 0..) |g, ri| {
                const v = col.get(ri);
                present[g] += @intFromBool(!keys.isMissing(v) and v.asFloat() != null);
            }
            for (cells, present) |*c, p| {
                if (p < ag.min_count) c.* = .null;
            }
        }
        d.* = try fm.columnFromCells(a, cells);
    }

    var out: Frame = .{ .columns = cols, .data = data, .len = n };
    // No group columns: the one result row has no key to be missing, and a subset of
    // none would mean every column (found in review 2026-11-07; `tabular` has it too).
    if (spec.drop_missing_keys and gidx.len > 0) out = try dropna(a, out, .{ .subset = spec.group_by });
    if (spec.sort_groups and gidx.len > 0) {
        const then = try a.alloc(sp.SortKey, gidx.len - 1);
        for (then, cols[1..gidx.len]) |*t, c| t.* = .{ .key = c.name };
        out = try sort(a, out, .{ .key = cols[0].name, .then_by = then, .missing = .last });
    }
    return out;
}

// ── unpivot ─────────────────────────────────────────────────────────────────

fn repeatRows(a: std.mem.Allocator, rows: usize, m: usize, total: usize) Error![]const u32 {
    const idx = try a.alloc(u32, total);
    var at: usize = 0;
    for (0..rows) |ri| {
        for (0..m) |_| {
            idx[at] = @intCast(ri);
            at += 1;
        }
    }
    return idx;
}

fn repeatTyped(comptime T: type, a: std.mem.Allocator, c: fm.TypedColumn(T), rows: usize, m: usize, total: usize) Error!?fm.TypedColumn(T) {
    if (c.valid != null or c.values.len != rows) return null;
    const out = try a.alloc(T, total);
    var at: usize = 0;
    for (c.values) |x| {
        @memset(out[at..][0..m], x);
        at += m;
    }
    return .{ .values = out };
}

/// What `take` of `repeatRows` gives for a typed column with no nulls and a full array: each
/// cell `m` times. null for any other column.
fn repeatPlain(a: std.mem.Allocator, col: ColumnData, rows: usize, m: usize, total: usize) Error!?ColumnData {
    switch (col) {
        .int => |c| return if (try repeatTyped(i64, a, c, rows, m, total)) |r| .{ .int = r } else null,
        .float => |c| return if (try repeatTyped(f64, a, c, rows, m, total)) |r| .{ .float = r } else null,
        .bool => |c| return if (try repeatTyped(bool, a, c, rows, m, total)) |r| .{ .bool = r } else null,
        .decimal => |c| return if (try repeatTyped(i128, a, c, rows, m, total)) |r| .{ .decimal = r } else null,
        else => return null,
    }
}

/// Columns that are all one plain typed kind (no nulls, full arrays), woven row by row.
fn weave(comptime T: type, comptime tag: []const u8, a: std.mem.Allocator, cols: []const ColumnData, rows: usize, total: usize) Error!?ColumnData {
    // No rows: only a float array is kept as it is (no cells to infer from otherwise).
    if (rows == 0 and !std.mem.eql(u8, tag, "float")) return null;
    for (cols) |c| {
        if (c != @field(ColumnData, tag)) return null;
        const t = @field(c, tag);
        if (t.valid != null or t.values.len != rows) return null;
    }
    const out = try a.alloc(T, total);
    for (cols, 0..) |c, k| {
        var at = k;
        for (@field(c, tag).values) |x| {
            out[at] = x;
            at += cols.len;
        }
    }
    return @unionInit(ColumnData, tag, .{ .values = out });
}

/// The melted columns woven row by row, in the array their cells' tags call for.
fn interleave(a: std.mem.Allocator, f: Frame, vals: []const usize, total: usize, typed: bool) Error!ColumnData {
    const cols = try a.alloc(ColumnData, vals.len);
    defer a.free(cols);
    for (cols, vals) |*c, vi| c.* = colOf(f, vi);
    if (typed and vals.len > 0) {
        if (try weave(f64, "float", a, cols, f.len, total)) |r| return r;
        if (try weave(i64, "int", a, cols, f.len, total)) |r| return r;
        if (try weave(bool, "bool", a, cols, f.len, total)) |r| return r;
        if (try weave(i128, "decimal", a, cols, f.len, total)) |r| return r;
    }
    const out = try a.alloc(Value, total);
    for (cols, 0..) |c, k| {
        var at = k;
        for (0..f.len) |ri| {
            out[at] = c.get(ri);
            at += cols.len;
        }
    }
    return fm.columnFromCells(a, out);
}

/// Wide to long (pandas `melt`, polars `unpivot`): one row per input row and melted
/// column, the id columns, then `out_key` (the melted column's name) and `out_value`.
pub fn unpivot(a: std.mem.Allocator, f: Frame, spec: sp.UnpivotSpec) Error!Frame {
    return unpivotImpl(a, f, spec, true);
}

fn unpivotImpl(a: std.mem.Allocator, f: Frame, spec: sp.UnpivotSpec, typed: bool) Error!Frame {
    try checkRowIndexes(f);
    const id_idxs = try nameIdxs(a, f, spec.id_cols);
    var val_idxs: std.ArrayList(usize) = .empty;
    if (spec.value_cols.len > 0) {
        for (spec.value_cols) |name| try val_idxs.append(a, try mustIndex(f, name));
    } else {
        col_loop: for (0..f.columns.len) |ci| {
            for (id_idxs) |ii| if (ii == ci) continue :col_loop;
            try val_idxs.append(a, ci);
        }
    }
    const vals = val_idxs.items;
    const value_type: ColumnType = if (vals.len > 0) f.columns[vals[0]].type else .text;
    const cols = try a.alloc(Column, id_idxs.len + 2);
    for (id_idxs, 0..) |ii, i| cols[i] = f.columns[ii];
    cols[id_idxs.len] = .{ .name = spec.out_key, .type = .text };
    cols[id_idxs.len + 1] = .{ .name = spec.out_value, .type = value_type };
    try keys.uniqueNames(a, cols);

    const total = std.math.mul(usize, f.len, vals.len) catch return error.TooLarge;
    if (total > sp.max_unpivot_cells) return error.TooLarge;

    const data = try a.alloc(ColumnData, cols.len);
    // The row index of every output row is only built if an id column needs it: a plain typed
    // column is repeated straight from its array.
    var idx: ?[]const u32 = null;
    for (id_idxs, data[0..id_idxs.len]) |ci, *d| {
        if (typed) if (try repeatPlain(a, colOf(f, ci), f.len, vals.len, total)) |r| {
            d.* = r;
            continue;
        };
        if (idx == null) idx = try repeatRows(a, f.len, vals.len, total);
        d.* = try take(a, colOf(f, ci), idx.?, false);
    }

    data[id_idxs.len] = try meltedNames(a, f, vals, total);
    data[id_idxs.len + 1] = try interleave(a, f, vals, total, typed);
    return .{ .columns = cols, .data = data, .len = total };
}

/// The melted names, repeated: every row the same run of bytes. Past a `Value` a cell, so
/// a long name or one listed many times, they are boxed and point at the one name, what
/// the row verb's cells cost. That cost is capped by `max_unpivot_cells`.
fn meltedNames(a: std.mem.Allocator, f: Frame, vals: []const usize, total: usize) Error!ColumnData {
    var run: usize = 0;
    for (vals) |vi| run +|= f.columns[vi].name.len;
    const size = std.math.mul(usize, run, f.len) catch std.math.maxInt(usize);
    if (size / @sizeOf(Value) > total) {
        const out = try a.alloc(Value, total);
        var i: usize = 0;
        for (0..f.len) |_| {
            for (vals) |vi| {
                out[i] = .{ .text = f.columns[vi].name };
                i += 1;
            }
        }
        return .{ .boxed = out };
    }
    const offsets = try a.alloc(usize, total + 1);
    const bytes = try a.alloc(u8, size);
    var at: usize = 0;
    var cell: usize = 0;
    for (0..f.len) |_| {
        for (vals) |vi| {
            const name = f.columns[vi].name;
            offsets[cell] = at;
            @memcpy(bytes[at..][0..name.len], name);
            at += name.len;
            cell += 1;
        }
    }
    offsets[total] = at;
    return .{ .text = .{ .offsets = offsets, .bytes = bytes } };
}

// ── join ────────────────────────────────────────────────────────────────────

fn nameIdxs(a: std.mem.Allocator, f: Frame, names: []const []const u8) Error![]const usize {
    const idxs = try a.alloc(usize, names.len);
    var lk = try Names.init(a, f, names.len);
    defer lk.deinit(a);
    for (names, 0..) |name, i| idxs[i] = try lk.of(name);
    return idxs;
}

fn joinKeyIdxs(a: std.mem.Allocator, f: Frame, spec: sp.JoinSpec) Error![]const usize {
    return nameIdxs(a, f, if (spec.keys.len > 0) spec.keys else &.{spec.on});
}

/// The key cells as rows of their own, for the keyed path every shape of key can take.
/// The `keys` machinery reads rows, and this is what gives a Frame's join the row verb's
/// key equality without a second implementation of it.
pub fn keyRows(a: std.mem.Allocator, f: Frame, idxs: []const usize) Error![]const []const Value {
    const w = idxs.len;
    const n = std.math.mul(usize, f.len, w) catch return error.TooLarge;
    const cells = try a.alloc(Value, n);
    const rows = try a.alloc([]const Value, f.len);
    for (idxs, 0..) |ci, k| {
        const col = colOf(f, ci);
        for (0..f.len) |ri| cells[ri * w + k] = col.get(ri);
    }
    for (rows, 0..) |*r, ri| r.* = cells[ri * w ..][0..w];
    return rows;
}

/// Every cell of a single int column, when that is all a key is. No rows then.
fn plainInts(f: Frame, idxs: []const usize) ?[]const i64 {
    if (idxs.len != 1 or f.len == 0) return null;
    const col = colOf(f, idxs[0]);
    if (col != .int or col.int.valid != null or col.int.values.len != f.len) return null;
    return col.int.values;
}

const Lookup = struct {
    /// `hits[i]` = the build side's group of probe row `i`, or `keys.none`.
    hits: []u32,
    /// Group of each build row.
    ids: []u32,
    groups: usize,
};

fn lookupKeys(a: std.mem.Allocator, build: Frame, bk: []const usize, probe: Frame, pk: []const usize, skip_null: bool) Error!Lookup {
    const hits = try a.alloc(u32, probe.len);
    if (plainInts(build, bk)) |bi| {
        if (plainInts(probe, pk)) |pi| {
            const g = try keys.factorizeInts(a, bi);
            try keys.probeInts(&g.table, pi, hits);
            return .{ .hits = hits, .ids = g.ids, .groups = g.groups() };
        }
    }
    const positions = struct {
        fn of(al: std.mem.Allocator, n: usize) Error![]const usize {
            const p = try al.alloc(usize, n);
            for (p, 0..) |*x, i| x.* = i;
            return p;
        }
    };
    const bpos = try positions.of(a, bk.len);
    const ppos = try positions.of(a, pk.len);
    const g = try keys.factorize(a, try keyRows(a, build, bk), bpos, .as_null);
    try keys.probeAll(a, &g.table, try keyRows(a, probe, pk), ppos, .as_null, skip_null, hits);
    return .{ .hits = hits, .ids = g.ids, .groups = g.groups() };
}

fn takeTyped(comptime T: type, a: std.mem.Allocator, c: fm.TypedColumn(T), idx: []const u32, has_none: bool) Error!fm.TypedColumn(T) {
    const out = try a.alloc(T, idx.len);
    if (c.valid == null and !has_none) {
        var fits = true;
        for (idx) |i| fits = fits and i < c.values.len;
        if (fits) {
            // A permutation reads a column all over: ask for the cache line a few rows ahead.
            const ahead = 16;
            const n = idx.len;
            const head = if (n > ahead) n - ahead else 0;
            for (out[0..head], idx[0..head], 0..) |*o, i, j| {
                @prefetch(&c.values[idx[j + ahead]], .{}); // j + ahead < n, and `fits` bounds the index
                o.* = c.values[i];
            }
            for (out[head..], idx[head..]) |*o, i| o.* = c.values[i];
            return .{ .values = out };
        }
    }
    if (c.valid) |src_bits| {
        if (!has_none) {
            // Bit and value together and no branch on either: nulls are not predictable.
            var fits = true;
            for (idx) |i| fits = fits and i < c.values.len and i / 64 < src_bits.len;
            if (fits) {
                const bits = try a.alloc(u64, bitsLen(idx.len));
                @memset(bits, 0);
                const zero = std.mem.zeroes(T);
                for (out, idx, 0..) |*o, i, ri| {
                    const b: u64 = (src_bits[i / 64] >> @intCast(i % 64)) & 1;
                    o.* = if (b != 0) c.values[i] else zero;
                    bits[ri / 64] |= b << @intCast(ri % 64);
                }
                var nulls = false;
                for (bits, 0..) |w, k| {
                    const in_word = @min(idx.len - k * 64, 64);
                    const want = if (in_word == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(in_word)) - 1;
                    nulls = nulls or w != want;
                }
                return .{ .values = out, .valid = if (nulls) bits else null };
            }
        }
    }
    const bits = try allValid(a, idx.len);
    var any_null = false;
    for (out, idx, 0..) |*o, i, ri| {
        if (i != keys.none and c.isValid(i)) {
            o.* = c.values[i];
        } else {
            o.* = std.mem.zeroes(T);
            clearBit(bits, ri);
            any_null = true;
        }
    }
    return .{ .values = out, .valid = if (any_null) bits else null };
}

fn takeText(a: std.mem.Allocator, c: fm.TextColumn, idx: []const u32) Error!fm.TextColumn {
    // `at` checks a hand-built column once here; the copy below reads the same offsets.
    var total: usize = 0;
    var any_null = false;
    for (idx) |i| {
        if (i != keys.none) {
            if (c.at(i)) |t| {
                total = std.math.add(usize, total, t.len) catch return error.TooLarge;
                continue;
            }
        }
        any_null = true;
    }
    // Room past the end: a short text copies a whole block, a call's worth of work less.
    const copy_block = 16;
    const offsets = try a.alloc(usize, idx.len + 1);
    const block = try a.alloc(u8, std.math.add(usize, total, copy_block) catch return error.TooLarge);
    const src = c.bytes;
    var at: usize = 0;
    if (!any_null) {
        for (idx, offsets[0..idx.len]) |i, *o| {
            o.* = at;
            const lo = c.offsets[i];
            const n = c.offsets[i + 1] - lo;
            if (n <= copy_block and lo + copy_block <= src.len) {
                block[at..][0..copy_block].* = src[lo..][0..copy_block].*;
            } else {
                @memcpy(block[at..][0..n], src[lo..][0..n]);
            }
            at += n;
        }
        offsets[idx.len] = at;
        return .{ .offsets = offsets, .bytes = block[0..total] };
    }
    const bits = try allValid(a, idx.len);
    for (idx, 0..) |i, ri| {
        offsets[ri] = at;
        const t = if (i == keys.none) null else c.at(i);
        if (t) |s| {
            @memcpy(block[at..][0..s.len], s);
            at += s.len;
        } else {
            clearBit(bits, ri);
        }
    }
    offsets[idx.len] = at;
    return .{ .offsets = offsets, .bytes = block[0..total], .valid = bits };
}

/// A list column's rows `idx`: the offsets rebuilt and the elements gathered through one
/// index of element positions (`take` on the element column), so a nested level costs
/// one gather, not one per row.
fn takeList(a: std.mem.Allocator, c: fm.ListColumn, idx: []const u32, depth: u8) Error!fm.ListColumn {
    const offsets = try a.alloc(u32, idx.len + 1);
    var total: usize = 0;
    var any_null = false;
    for (idx, 0..) |i, ri| {
        offsets[ri] = @intCast(total); // checked below as it grows
        const l = if (i == keys.none) null else c.at(i);
        if (l) |v| {
            total += v.len();
            if (total > std.math.maxInt(u32)) return error.TooLarge;
        } else any_null = true;
    }
    offsets[idx.len] = @intCast(total);
    const pos = try a.alloc(u32, total);
    defer a.free(pos);
    var at: usize = 0;
    for (idx) |i| {
        const l = if (i == keys.none) null else c.at(i);
        if (l) |v| for (v.start..v.end) |e| {
            pos[at] = @intCast(e);
            at += 1;
        };
    }
    const items = try a.create(ColumnData);
    items.* = try takeAt(a, c.items.*, pos, false, depth + 1);
    var valid: ?[]u64 = null;
    if (any_null) {
        const bits = try allValid(a, idx.len);
        for (idx, 0..) |i, ri| if (i == keys.none or c.at(i) == null) clearBit(bits, ri);
        valid = bits;
    }
    return .{ .offsets = offsets, .items = items, .valid = valid };
}

/// A struct column's rows `idx`: every field taken with the same index.
fn takeStruct(a: std.mem.Allocator, c: *const fm.StructColumn, idx: []const u32, has_none: bool, depth: u8) Error!*const fm.StructColumn {
    const children = try a.alloc(ColumnData, c.names.len);
    for (children, 0..) |*d, k| {
        const child: ColumnData = if (k < c.children.len) c.children[k] else .nulls;
        d.* = try takeAt(a, child, idx, has_none, depth + 1);
    }
    var valid: ?[]u64 = null;
    if (c.valid != null or has_none) {
        const bits = try allValid(a, idx.len);
        var any_null = false;
        for (idx, 0..) |i, ri| if (i == keys.none or !c.isValid(i)) {
            clearBit(bits, ri);
            any_null = true;
        };
        if (any_null) valid = bits;
    }
    const st = try a.create(fm.StructColumn);
    st.* = .{ .names = c.names, .children = children, .len = idx.len, .valid = valid };
    return st;
}

/// The rows `idx` names of one column, `keys.none` as null.
pub fn take(a: std.mem.Allocator, col: ColumnData, idx: []const u32, has_none: bool) Error!ColumnData {
    return takeAt(a, col, idx, has_none, 0);
}

/// `take` of a column `depth` levels below the frame; past `max_nesting_depth` the
/// cells are null, as every walker reads them.
fn takeAt(a: std.mem.Allocator, col: ColumnData, idx: []const u32, has_none: bool, depth: u8) Error!ColumnData {
    switch (col) {
        .nulls => return .nulls,
        .int => |c| return .{ .int = try takeTyped(i64, a, c, idx, has_none) },
        .float => |c| return .{ .float = try takeTyped(f64, a, c, idx, has_none) },
        .bool => |c| return .{ .bool = try takeTyped(bool, a, c, idx, has_none) },
        .decimal => |c| return .{ .decimal = try takeTyped(i128, a, c, idx, has_none) },
        .text => |c| return .{ .text = try takeText(a, c, idx) },
        // The codes are taken, the dictionary shared: a value no row keeps stays in it,
        // as in pandas (unused categories) and polars.
        .categorical => |c| return .{ .categorical = .{ .codes = try takeTyped(u32, a, c.codes, idx, has_none), .dict = c.dict } },
        // The field names are shared, as a categorical's dictionary is.
        .list => |c| return if (depth >= vm.max_nesting_depth) .nulls else .{ .list = try takeList(a, c, idx, depth) },
        .@"struct" => |c| return if (depth >= vm.max_nesting_depth) .nulls else .{ .@"struct" = try takeStruct(a, c, idx, has_none, depth) },
        .boxed => |c| {
            const out = try a.alloc(Value, idx.len);
            for (out, idx) |*o, i| o.* = if (i != keys.none and i < c.len) c[i] else .null;
            return .{ .boxed = out };
        },
    }
}

fn isIdentity(idx: []const u32, rows: usize) bool {
    if (idx.len != rows) return false;
    for (idx, 0..) |x, i| {
        if (x != i) return false;
    }
    return true;
}

fn hasNone(idx: []const u32) bool {
    for (idx) |x| {
        if (x == keys.none) return true;
    }
    return false;
}

/// Join two frames on key columns (`JoinSpec`: inner, left, right, full, semi, anti,
/// cross; composite keys, `right_on`, suffixes, the null-key rule, pandas' `indicator`,
/// `validate` and `sort`, polars' `coalesce = false`). Without `on` or `keys` the key is
/// the column names both sides have (pandas `on=None`), in the left's order. A left side
/// that comes out row for row as it went in (a left join on a unique right key, say) is
/// shared, not copied.
pub fn join(a: std.mem.Allocator, left: Frame, right: Frame, spec: sp.JoinSpec) sp.JoinError!Frame {
    return joinImpl(a, left, right, spec, true);
}

/// `join` for a spec that asks no `validate`: the plain `Error` set. Used by the verbs
/// built on `join`, none of which sets it.
pub fn joinChecked(a: std.mem.Allocator, left: Frame, right: Frame, spec: sp.JoinSpec) Error!Frame {
    std.debug.assert(spec.validate == .none);
    return joinImpl(a, left, right, spec, true) catch |e| switch (e) {
        error.ValidationFailed => unreachable, // `validate` is `.none`, the only source
        else => |x| x,
    };
}

/// The names both frames have, in the left's order.
fn commonColumns(a: std.mem.Allocator, left: Frame, right: Frame) Error![]const []const u8 {
    var rn = try fm.NameIndex.init(a, right.columns);
    defer rn.deinit(a);
    var out: std.ArrayList([]const u8) = .empty;
    for (left.columns) |c| {
        if (rn.get(c.name) != null) try out.append(a, c.name);
    }
    return out.items;
}

fn joinImpl(a: std.mem.Allocator, left: Frame, right: Frame, spec_in: sp.JoinSpec, typed: bool) sp.JoinError!Frame {
    // A row index is a u32 and `keys.none` is its top value. Only a hand-built frame can
    // be this long: a `Dataset`'s rows are a real slice.
    try core.checkRowsU32(left.len);
    try core.checkRowsU32(right.len);
    var spec = spec_in;
    const cross = spec.how == .cross;
    if (!cross and spec.on.len == 0 and spec.keys.len == 0 and spec.right_on.len == 0) {
        spec.keys = try commonColumns(a, left, right);
        if (spec.keys.len == 0) return error.NoSuchColumn;
    }
    const lk: []const usize = if (cross) &.{} else try joinKeyIdxs(a, left, spec);
    const rk: []const usize = if (cross) &.{} else if (spec.right_on.len > 0)
        try nameIdxs(a, right, spec.right_on)
    else
        try joinKeyIdxs(a, right, spec);
    if (lk.len != rk.len) return error.NoSuchColumn;
    const skip_null = spec.null_keys == .no_match;

    if (spec.validate != .none and !cross) {
        const need_left = spec.validate == .one_to_one or spec.validate == .one_to_many;
        const need_right = spec.validate == .one_to_one or spec.validate == .many_to_one;
        if (need_left) {
            const fl = try lookupKeys(a, left, lk, right, rk, skip_null);
            if (fl.groups != left.len) return error.ValidationFailed;
        }
        if (need_right) {
            const fr = try lookupKeys(a, right, rk, left, lk, skip_null);
            if (fr.groups != right.len) return error.ValidationFailed;
        }
    }

    if (spec.how == .semi or spec.how == .anti) {
        const found = try lookupKeys(a, right, rk, left, lk, skip_null);
        var kept: std.ArrayList(u32) = .empty;
        for (found.hits, 0..) |h, ri| {
            if ((spec.how == .semi) == (h != keys.none)) try kept.append(a, @intCast(ri));
        }
        const data = try a.alloc(ColumnData, left.columns.len);
        const same = isIdentity(kept.items, left.len);
        for (data, 0..) |*d, ci| d.* = if (same) colOf(left, ci) else try take(a, colOf(left, ci), kept.items, false);
        return .{ .columns = left.columns, .data = data, .len = kept.items.len };
    }

    const rmask = try a.alloc(bool, right.columns.len);
    @memset(rmask, false);
    if (!spec.keep_right_keys) for (rk) |ci| {
        rmask[ci] = true;
    };
    var keep: std.ArrayList(usize) = .empty;
    for (rmask, 0..) |is_key, ci| if (!is_key) try keep.append(a, ci);
    const rsfx: ?[]const u8 = spec.suffix orelse if (spec.keep_right_keys) "_right" else null;
    const cols = try a.alloc(Column, left.columns.len + keep.items.len);
    @memcpy(cols[0..left.columns.len], left.columns);
    var left_names = try Names.init(a, left, if (rsfx != null) keep.items.len else 0);
    defer left_names.deinit(a);
    for (keep.items, cols[left.columns.len..]) |ci, *c| {
        c.* = right.columns[ci];
        if (rsfx) |sfx| {
            if (left_names.of(c.name)) |_| c.name = try a.print("{s}{s}", .{ c.name, sfx }) else |_| {}
        }
    }
    if (spec.left_suffix) |lsfx| {
        // The kept right columns' original names: a left column sharing one is renamed.
        var kept_right = try fm.NameIndex.init(a, right.columns);
        defer kept_right.deinit(a);
        for (cols[0..left.columns.len]) |*c| {
            if (kept_right.get(c.name)) |ri| {
                if (!rmask[ri]) c.name = try a.print("{s}{s}", .{ c.name, lsfx });
            }
        }
    }
    // A suffixed name the left side also has would be unreachable: number it.
    if (rsfx != null or spec.left_suffix != null) try keys.uniqueNames(a, cols);

    const pairs = if (cross) try crossPairs(a, left.len, right.len, cols.len) else try keyedPairs(a, left, lk, right, rk, spec, skip_null, cols.len, typed);

    const data = try a.alloc(ColumnData, cols.len);
    const left_has_none = !pairs.left_identity and hasNone(pairs.left);
    const right_has_none = hasNone(pairs.right);
    const left_same = pairs.left_identity or isIdentity(pairs.left, left.len);
    for (data[0..left.columns.len], 0..) |*d, ci| {
        d.* = if (left_same) colOf(left, ci) else try take(a, colOf(left, ci), pairs.left, left_has_none);
    }
    for (keep.items, data[left.columns.len..]) |ci, *d| {
        d.* = try take(a, colOf(right, ci), pairs.right, right_has_none);
    }
    if ((spec.coalesce_keys or spec.sort) and left_has_none) {
        // A right-only row takes its key cells from the right, in key order, as the row
        // verb does. The kinds may differ between the sides.
        for (lk, rk) |l, m| {
            const out = try a.alloc(Value, pairs.left.len);
            const col = data[l];
            const from = colOf(right, m);
            for (out, pairs.left, pairs.right, 0..) |*o, li, ri, at| {
                o.* = if (li == keys.none) from.get(ri) else col.get(at);
            }
            data[l] = try fm.columnFromCells(a, out);
        }
    }
    var out: Frame = .{ .columns = cols, .data = data, .len = pairs.right.len };
    if (spec.indicator) |name| {
        const cells = try a.alloc(Value, out.len);
        defer a.free(cells);
        for (cells, 0..) |*c, i| {
            const l = if (pairs.left_identity) i else pairs.left[i];
            const lnone = if (pairs.left_identity) false else l == keys.none;
            c.* = .{ .text = if (lnone) "right_only" else if (pairs.right[i] == keys.none) "left_only" else "both" };
        }
        const ncols = try a.alloc(Column, cols.len + 1);
        @memcpy(ncols[0..cols.len], cols);
        ncols[cols.len] = .{ .name = name, .type = .text };
        try keys.uniqueNames(a, ncols);
        const ndata = try a.alloc(ColumnData, ncols.len);
        @memcpy(ndata[0..cols.len], data);
        ndata[cols.len] = try fm.columnFromCells(a, cells);
        out = .{ .columns = ncols, .data = ndata, .len = out.len };
    }
    if (spec.sort and lk.len > 0) {
        const dirs = try a.alloc(sp.SortDir, lk.len);
        @memset(dirs, .asc);
        out = try takeRows(a, out, try sortedRows(a, out, lk, dirs, .last));
    }
    return out;
}

/// `left_identity`: the left rows are 0, 1, 2, ... (`left` is empty, not built).
const Pairs = struct { left: []const u32, right: []const u32, left_identity: bool = false };

/// Running output-row count, refused past `sp.max_join_cells` like the row verb.
fn pairsAdd(total: usize, n: usize, width: usize) Error!usize {
    const t = std.math.add(usize, total, n) catch return error.TooLarge;
    const cells = std.math.mul(usize, t, @max(width, 1)) catch return error.TooLarge;
    if (cells > sp.max_join_cells) return error.TooLarge;
    return t;
}

fn crossPairs(a: std.mem.Allocator, l: usize, r: usize, width: usize) Error!Pairs {
    const total = std.math.mul(usize, l, r) catch return error.TooLarge;
    _ = try pairsAdd(total, 0, width);
    if (total == 0) return .{ .left = &.{}, .right = &.{} };
    const li = try a.alloc(u32, total);
    const ri = try a.alloc(u32, total);
    var at: usize = 0;
    for (0..l) |x| {
        for (0..r) |y| {
            li[at] = @intCast(x);
            ri[at] = @intCast(y);
            at += 1;
        }
    }
    return .{ .left = li, .right = ri };
}

fn keyedPairs(a: std.mem.Allocator, left: Frame, lk: []const usize, right: Frame, rk: []const usize, spec: sp.JoinSpec, skip_null: bool, width: usize, typed: bool) Error!Pairs {
    const drive_right = spec.how == .right;
    const build = if (drive_right) left else right;
    const probe = if (drive_right) right else left;
    const bk = if (drive_right) lk else rk;
    const pk = if (drive_right) rk else lk;

    const found = try lookupKeys(a, build, bk, probe, pk, skip_null);
    const none = keys.none;
    const keep_unmatched = spec.how != .inner;

    // A build side with no repeated key, joined from the left or inner: each probe row has
    // one partner at most, so the pairs come out in one pass over the hits with no member
    // lists, and a left join keeps every row in place.
    if (typed and !drive_right and (spec.how == .left or spec.how == .inner) and found.groups == found.ids.len) {
        const row_of = try a.alloc(u32, found.groups);
        defer a.free(row_of);
        for (found.ids, 0..) |g, ri| row_of[g] = @intCast(ri);
        const ri_out = try a.alloc(u32, found.hits.len);
        if (spec.how == .left) {
            for (ri_out, found.hits) |*o, h| o.* = if (h == none) none else row_of[h];
            _ = try pairsAdd(ri_out.len, 0, width);
            return .{ .left = &.{}, .right = ri_out, .left_identity = true };
        }
        const li_out = try a.alloc(u32, found.hits.len);
        var at: usize = 0;
        for (found.hits, 0..) |h, pi| {
            li_out[at] = @intCast(pi);
            ri_out[at] = if (h == none) none else row_of[h];
            at += @intFromBool(h != none);
        }
        _ = try pairsAdd(at, 0, width);
        return .{ .left = li_out[0..at], .right = ri_out[0..at] };
    }
    const mem = try keys.members(a, found.ids, found.groups);

    var total: usize = 0;
    for (found.hits) |h| {
        total += if (h != none) mem.of(h).len else @intFromBool(keep_unmatched);
        if (total > sp.max_join_cells) return error.TooLarge;
    }
    total = try pairsAdd(total, 0, width);

    var only_right: std.ArrayList(u32) = .empty;
    if (spec.how == .full) {
        const seen = try a.alloc(bool, found.groups);
        defer a.free(seen);
        @memset(seen, false);
        for (found.hits) |h| {
            if (h != none) seen[h] = true;
        }
        for (found.ids, 0..) |g, ri| {
            if (!seen[g]) {
                try only_right.append(a, @intCast(ri));
                total = try pairsAdd(total, 1, width);
            }
        }
    }

    const li = try a.alloc(u32, total);
    const ri = try a.alloc(u32, total);
    var at: usize = 0;
    if (drive_right) {
        for (found.hits, 0..) |h, pi| {
            if (h == none) {
                li[at] = none;
                ri[at] = @intCast(pi);
                at += 1;
            } else {
                for (mem.of(h)) |mi| {
                    li[at] = mi;
                    ri[at] = @intCast(pi);
                    at += 1;
                }
            }
        }
    } else {
        for (found.hits, 0..) |h, pi| {
            if (h == none) {
                if (keep_unmatched) {
                    li[at] = @intCast(pi);
                    ri[at] = none;
                    at += 1;
                }
            } else {
                for (mem.of(h)) |mi| {
                    li[at] = @intCast(pi);
                    ri[at] = mi;
                    at += 1;
                }
            }
        }
        for (only_right.items) |r| {
            li[at] = none;
            ri[at] = r;
            at += 1;
        }
    }
    return .{ .left = li, .right = ri };
}

// ── dropna ──────────────────────────────────────────────────────────────────

fn subsetIdxs(a: std.mem.Allocator, f: Frame, subset: []const []const u8) Error![]const usize {
    const n = if (subset.len == 0) f.columns.len else subset.len;
    const idxs = try a.alloc(usize, n);
    var lk = try Names.init(a, f, subset.len);
    defer lk.deinit(a);
    for (idxs, 0..) |*ix, i| ix.* = if (subset.len == 0) i else try lk.of(subset[i]);
    return idxs;
}

/// Drop the rows with a missing cell (null, or a NaN float) in `subset` (pandas
/// `dropna`, polars `drop_nulls`); `how = .all` drops only a row missing in all of them,
/// `thresh` keeps a row with at least that many present cells (pandas `thresh`).
pub fn dropna(a: std.mem.Allocator, f: Frame, spec: sp.DropNaSpec) Error!Frame {
    try checkRowIndexes(f);
    const idxs = try subsetIdxs(a, f, spec.subset);
    const missing = try a.alloc(u32, f.len);
    defer a.free(missing);
    @memset(missing, 0);
    for (idxs) |ci| {
        const col = colOf(f, ci);
        for (missing, 0..) |*m, ri| m.* += @intFromBool(keys.isMissing(col.get(ri)));
    }
    const kept = try a.alloc(u32, f.len);
    var n: usize = 0;
    for (missing, 0..) |m, ri| {
        const drop_row = if (spec.thresh) |t| idxs.len - m < t else switch (spec.how) {
            .any => m > 0,
            .all => m == idxs.len and idxs.len > 0,
        };
        kept[n] = @intCast(ri);
        n += @intFromBool(!drop_row);
    }
    return takeRows(a, f, kept[0..n]);
}

// ── sort ────────────────────────────────────────────────────────────────────

/// One column's cells as rows one cell wide, for the `keys` machinery.
fn cellRows(a: std.mem.Allocator, f: Frame, ci: usize) Error![]const []const Value {
    return keyRows(a, f, &.{ci});
}

/// One sort key as bitwise-comparable u64s: straight images for an all-int or all-float
/// column (nulls placed later by the flag pass), otherwise ranks of the distinct values
/// under `Value.order`. `tabular`'s row `sort` computes the same keys.
fn sortKeyColumn(a: std.mem.Allocator, f: Frame, ci: usize, dir: sp.SortDir, out: []u64, typed: bool) Error!void {
    const col = colOf(f, ci);
    var ints = false;
    var floats = false;
    var other = false;
    switch (col) {
        .nulls => {},
        .int => ints = true,
        .float => floats = true,
        .boxed => |c| for (0..f.len) |ri| switch (if (ri < c.len) c[ri] else Value.null) {
            .int => ints = true,
            .float => floats = true,
            .null => {},
            else => other = true,
        },
        // A typed column of one other kind; an all-null one sorts as the image path's 0.
        else => {
            for (0..f.len) |ri| other = other or col.get(ri) != .null;
        },
    }
    if (typed and col == .float and col.float.values.len == f.len and col.float.valid == null) {
        for (out, col.float.values) |*k, x| k.* = keys.floatKey(x);
    } else if (typed and col == .int and col.int.values.len == f.len and col.int.valid == null) {
        for (out, col.int.values) |*k, x| k.* = keys.intKey(x);
    } else if (!other and !(ints and floats)) {
        for (out, 0..) |*k, ri| k.* = switch (col.get(ri)) {
            .int => |i| keys.intKey(i),
            .float => |x| keys.floatKey(x),
            else => 0, // a null: placed by the flag pass
        };
    } else {
        const rows = try cellRows(a, f, ci);
        const fac = try keys.factorize(a, rows, &.{0}, .own);
        defer a.free(fac.ids);
        const order = try a.alloc(u32, fac.groups());
        defer a.free(order);
        for (order, 0..) |*o, i| o.* = @intCast(i);
        const Ctx = struct {
            rows: []const []const Value,
            firsts: []const u32,
            fn lt(c: @This(), l: u32, m: u32) bool {
                return c.rows[c.firsts[l]][0].order(c.rows[c.firsts[m]][0]) == .lt;
            }
        };
        const ctx: Ctx = .{ .rows = rows, .firsts = fac.firsts };
        std.mem.sort(u32, order, ctx, Ctx.lt);
        const rank = try a.alloc(u64, fac.groups());
        defer a.free(rank);
        var cur: u64 = 0;
        for (order, 0..) |o, i| {
            // Canonical keys already merge equals; a tie left over still ranks equal.
            if (i > 0 and ctx.lt(order[i - 1], o)) cur += 1;
            rank[o] = cur;
        }
        for (fac.ids, out) |id, *k| k.* = rank[id];
    }
    if (dir == .desc) {
        for (out) |*k| k.* = ~k.*;
    }
}

const MissingPos = @FieldType(sp.SortSpec, "missing");

/// Stable sort by `key`/`dir`, ties broken by `then_by` in order (pandas
/// `sort_values`, polars `sort`); `missing` places null and NaN. LSD over the key
/// columns: a radix pass per key, and one for its missing cells where there are any.
pub fn sort(a: std.mem.Allocator, f: Frame, spec: sp.SortSpec) Error!Frame {
    return sortImpl(a, f, spec, true);
}

fn sortImpl(a: std.mem.Allocator, f: Frame, spec: sp.SortSpec, typed: bool) Error!Frame {
    try checkRowIndexes(f);
    const n = 1 + spec.then_by.len;
    const idxs = try a.alloc(usize, n);
    const dirs = try a.alloc(sp.SortDir, n);
    const places = try a.alloc(MissingPos, n);
    idxs[0] = try mustIndex(f, spec.key);
    dirs[0] = spec.dir;
    places[0] = spec.missing;
    for (spec.then_by, 0..) |tb, i| {
        idxs[1 + i] = try mustIndex(f, tb.key);
        dirs[1 + i] = tb.dir;
        places[1 + i] = tb.missing orelse spec.missing;
    }
    return takeRows(a, f, try sortedRowsPer(a, f, idxs, dirs, places, typed));
}

/// The row order `sort` gives, by column positions.
pub fn sortedRows(a: std.mem.Allocator, f: Frame, idxs: []const usize, dirs: []const sp.SortDir, missing: MissingPos) Error![]const u32 {
    return sortedRowsImpl(a, f, idxs, dirs, missing, true);
}

fn sortedRowsImpl(a: std.mem.Allocator, f: Frame, idxs: []const usize, dirs: []const sp.SortDir, missing: MissingPos, typed: bool) Error![]const u32 {
    const places = try a.alloc(MissingPos, idxs.len);
    defer a.free(places);
    @memset(places, missing);
    return sortedRowsPer(a, f, idxs, dirs, places, typed);
}

/// False only when no cell of `col` is one `missing` places apart: an int array or a float
/// array of the frame's length with no null, and (unless `.auto`, where a NaN is a value)
/// no NaN.
fn mayHaveMissing(col: ColumnData, rows: usize, missing: MissingPos) bool {
    switch (col) {
        .int => |c| return c.valid != null or c.values.len != rows,
        .float => |c| {
            if (c.valid != null or c.values.len != rows) return true;
            if (missing == .auto) return false;
            for (c.values) |x| if (std.math.isNan(x)) return true;
            return false;
        },
        else => return true,
    }
}

/// `sortedRows` with a placement of missing cells per key.
pub fn sortedRowsPer(a: std.mem.Allocator, f: Frame, idxs: []const usize, dirs: []const sp.SortDir, places: []const MissingPos, typed: bool) Error![]const u32 {
    try checkRowIndexes(f);
    const pairs = try a.alloc(keys.Pair, f.len);
    defer a.free(pairs);
    for (pairs, 0..) |*p, i| p.idx = @intCast(i);
    const vals = try a.alloc(u64, f.len);
    defer a.free(vals);
    var k = idxs.len;
    while (k > 0) {
        k -= 1;
        const ci = idxs[k];
        const missing = places[k];
        try sortKeyColumn(a, f, ci, dirs[k], vals, typed);
        for (pairs) |*p| p.key = vals[p.idx];
        try keys.radixSort(a, pairs);

        // `.auto`: a null is the lowest value, so first ascending, last descending,
        // and a NaN stays where the value pass put it. `.first`/`.last`: every
        // missing cell goes there, whatever the direction.
        const front = switch (missing) {
            .auto => dirs[k] == .asc,
            .first => true,
            .last => false,
        };
        const col = colOf(f, ci);
        // A plain typed column with nothing the pass would flag: the pass would only
        // rewrite keys the next one overwrites, after a random read of every cell.
        if (typed and !mayHaveMissing(col, f.len, missing)) continue;
        var flagged = false;
        for (pairs) |*p| {
            const c = col.get(p.idx);
            const hit = if (missing == .auto) c == .null else keys.isMissing(c);
            flagged = flagged or hit;
            p.key = if (hit == front) 0 else 1;
        }
        if (flagged) try keys.radixSort(a, pairs);
    }
    const order = try a.alloc(u32, f.len);
    for (order, pairs) |*o, p| o.* = p.idx;
    return order;
}

// ── pivot ───────────────────────────────────────────────────────────────────

/// A key cell's canonical text, the name of a pivot column.
fn appendValueKey(a: std.mem.Allocator, buf: *std.ArrayList(u8), v: Value) Error!void {
    switch (v) {
        .null => try buf.append(a, 0),
        .bool => |b| try buf.append(a, if (b) '1' else '0'),
        .int => |i| try buf.print(a, "{d}", .{i}),
        .float => |x| try buf.print(a, "{d}", .{x}),
        .text => |t| try buf.appendSlice(a, t),
        .decimal => |r| try buf.print(a, "d{d}", .{r}), // raw i128, exact key
        .list, .record => {
            var out: std.Io.Writer.Allocating = .init(a);
            defer out.deinit();
            jsonio.writeValue(&out.writer, v, null, 0) catch return error.OutOfMemory; // an Allocating writer fails only so
            try buf.appendSlice(a, out.written());
        },
    }
}

/// `row_key` x `col_key` -> `agg(value_col)` (pandas `pivot_table`, polars `pivot`).
/// Output: `row_key` first (rows in first-seen order), then one column per distinct
/// `col_key`, numeric-aware ascending, named by the key's text. A cell no row fell
/// into is null, or `fill_value`. Two keys printing alike get numbered names.
pub fn pivot(a: std.mem.Allocator, f: Frame, spec: sp.PivotSpec) Error!Frame {
    return pivotImpl(a, f, spec, true);
}

/// For the differential tests only: `pivot` through key rows of boxed cells, which is the
/// specification of the typed path.
pub const test_hooks = struct {
    pub fn joinCells(a: std.mem.Allocator, left: Frame, right: Frame, spec: sp.JoinSpec) sp.JoinError!Frame {
        return joinImpl(a, left, right, spec, false);
    }
    pub fn aggregateCells(a: std.mem.Allocator, f: Frame, spec: sp.AggregateSpec) Error!Frame {
        return aggregateImpl(a, f, spec, false);
    }
    pub fn unpivotCells(a: std.mem.Allocator, f: Frame, spec: sp.UnpivotSpec) Error!Frame {
        return unpivotImpl(a, f, spec, false);
    }
    pub fn sortCells(a: std.mem.Allocator, f: Frame, spec: sp.SortSpec) Error!Frame {
        return sortImpl(a, f, spec, false);
    }
    pub fn pivotCells(a: std.mem.Allocator, f: Frame, spec: sp.PivotSpec) Error!Frame {
        return pivotImpl(a, f, spec, false);
    }
};

fn pivotImpl(a: std.mem.Allocator, f: Frame, spec: sp.PivotSpec, typed: bool) Error!Frame {
    try checkRowIndexes(f);
    const rki = try mustIndex(f, spec.row_key);
    const cki = try mustIndex(f, spec.col_key);
    const vi = try mustIndex(f, spec.value_col);
    // The three columns as rows, the shape the key and accumulator machinery reads. The
    // typed path factorizes each key column on its own array and reads the value column
    // as numbers where `aggregate` does, and builds no rows at all.
    const rows: []const []const Value = if (typed) &.{} else try keyRows(a, f, &.{ rki, cki, vi });

    const rf = if (typed) try factorColumn(a, f, rki) else try keys.factorize(a, rows, &.{0}, .as_null);
    defer a.free(rf.ids);
    const cf = if (typed) try factorColumn(a, f, cki) else try keys.factorize(a, rows, &.{1}, .as_null);
    defer a.free(cf.ids);
    const nr = rf.groups();
    const nc = cf.groups();
    const n_cells = std.math.mul(usize, nr, nc) catch return error.TooLarge;
    if (n_cells > sp.max_pivot_cells) return error.TooLarge;
    if (spec.margins and (std.math.mul(usize, nr + 1, nc + 1) catch return error.TooLarge) > sp.max_pivot_cells) return error.TooLarge;

    // Column keys, with the numeric order decided once and each key parsed once.
    const Ck = struct { name: []const u8, num: f64, id: u32 };
    const cks = try a.alloc(Ck, nc);
    defer a.free(cks);
    var numeric = true;
    for (cks, cf.firsts, 0..) |*ck, first, id| {
        var buf: std.ArrayList(u8) = .empty;
        try appendValueKey(a, &buf, if (typed) colOf(f, cki).get(first) else rows[first][1]);
        const name = try buf.toOwnedSlice(a);
        // As `cast` reads numbers (no hex, no digit separators). "nan" parses: a NaN
        // compares false both ways, so the
        // numeric order would not be a total order; such a set stays lexicographic.
        const num = ex.parseNumber(name) orelse std.math.nan(f64);
        if (std.math.isNan(num)) numeric = false;
        ck.* = .{ .name = name, .num = num, .id = @intCast(id) };
    }
    const Less = struct {
        fn byName(_: void, l: Ck, m: Ck) bool {
            return std.mem.order(u8, l.name, m.name) == .lt;
        }
        fn byNum(_: void, l: Ck, m: Ck) bool {
            return l.num < m.num;
        }
    };
    if (!spec.sort_columns) {} else if (numeric) std.mem.sort(Ck, cks, {}, Less.byNum) else std.mem.sort(Ck, cks, {}, Less.byName);

    // What the cells hold: `fill_value` on a numeric function, promoting an int column
    // when it is not whole; on any other it stays null, no number belongs there.
    var cell_type = core.aggOutType(f.columns, vi, spec.agg, false);
    var fill: Value = .null;
    var promote = false;
    const fv: ?f64 = spec.fill_value orelse spec.fill.asFloat();
    if (fv) |x| switch (cell_type) {
        .float => fill = .{ .float = x },
        .int => {
            if (Value.floatToInt(i64, x)) |i| {
                if (@as(f64, @floatFromInt(i)) == x) fill = .{ .int = i };
            }
            if (fill == .null) {
                cell_type = .float;
                promote = true;
                fill = .{ .float = x };
            }
        },
        .decimal => fill = (Value{ .float = x }).cast(.decimal) orelse .null,
        else => {},
    } else switch (spec.fill) {
        .text => {
            fill = spec.fill;
            cell_type = .text;
        },
        .bool => {
            fill = spec.fill;
            cell_type = .bool;
        },
        else => {},
    }
    const cols = try a.alloc(Column, 1 + nc + @intFromBool(spec.margins));
    cols[0] = .{ .name = spec.row_key, .type = f.columns[rki].type };
    for (cks, 0..) |ck, i| cols[1 + i] = .{ .name = ck.name, .type = cell_type };
    if (spec.margins) cols[1 + nc] = .{ .name = spec.margins_name, .type = cell_type };
    // Int 1 and text "1" are two keys that print alike; a key may print as `row_key`.
    try keys.uniqueNames(a, cols);

    const ids = try a.alloc(u32, f.len);
    defer a.free(ids);
    const present = try a.alloc(bool, n_cells);
    defer a.free(present);
    @memset(present, false);
    for (ids, rf.ids, cf.ids) |*id, r, c| {
        id.* = @intCast(r * nc + c); // < n_cells <= max_pivot_cells: fits
        present[id.*] = true;
    }
    const tmp = try a.alloc(Value, n_cells);
    defer a.free(tmp);
    const sink: core.Sink = .{ .cells = tmp, .stride = 1, .offset = 0 };
    const opts: core.Opts = .{ .q = spec.q };
    const clean = if (typed and core.cleanFn(spec.agg)) try cleanValues(a, colOf(f, vi), f.len) else null;
    const Acc = struct {
        a: std.mem.Allocator,
        f: Frame,
        vi: usize,
        rows: []const []const Value,
        clean: ?[]const f64,
        typed: bool,
        spec: sp.PivotSpec,
        opts: core.Opts,
        fn run(s: @This(), idv: []const u32, n: usize, out: core.Sink) Error!void {
            if (s.clean) |vals| {
                try core.accumulateClean(s.a, vals, idv, n, s.spec.agg, s.opts, s.spec.skip_na, out);
            } else if (s.typed) {
                try core.accumulate(s.a, try keyRows(s.a, s.f, &.{s.vi}), idv, n, 0, null, s.spec.agg, s.opts, s.spec.skip_na, out);
            } else {
                try core.accumulate(s.a, s.rows, idv, n, 2, null, s.spec.agg, s.opts, s.spec.skip_na, out);
            }
        }
    };
    const acc: Acc = .{ .a = a, .f = f, .vi = vi, .rows = rows, .clean = clean, .typed = typed, .spec = spec, .opts = opts };
    try acc.run(ids, n_cells, sink);

    // The margins: the function over every row of a row key, of a column key, of all.
    var row_margin: []Value = &.{};
    var col_margin: []Value = &.{};
    var corner: [1]Value = .{.null};
    if (spec.margins) {
        row_margin = try a.alloc(Value, nr);
        col_margin = try a.alloc(Value, nc);
        try acc.run(rf.ids, nr, .{ .cells = row_margin, .stride = 1, .offset = 0 });
        try acc.run(cf.ids, nc, .{ .cells = col_margin, .stride = 1, .offset = 0 });
        const zeros = try a.alloc(u32, f.len);
        defer a.free(zeros);
        @memset(zeros, 0);
        if (f.len > 0) try acc.run(zeros, 1, .{ .cells = &corner, .stride = 1, .offset = 0 });
        if (promote) {
            for (row_margin) |*m| if (m.* == .int) {
                m.* = .{ .float = @floatFromInt(m.int) };
            };
            for (col_margin) |*m| if (m.* == .int) {
                m.* = .{ .float = @floatFromInt(m.int) };
            };
            if (corner[0] == .int) corner[0] = .{ .float = @floatFromInt(corner[0].int) };
        }
    }

    const out_rows = nr + @intFromBool(spec.margins);
    const data = try a.alloc(ColumnData, cols.len);
    if (spec.margins) {
        const key_cells = try a.alloc(Value, out_rows);
        defer a.free(key_cells);
        for (key_cells[0..nr], rf.firsts) |*c, first| c.* = colOf(f, rki).get(first);
        key_cells[nr] = .{ .text = spec.margins_name };
        data[0] = try fm.columnFromCells(a, key_cells);
        switch (f.columns[rki].type) {
            .text, .categorical, .date => {},
            else => cols[0].type = .text,
        }
    } else data[0] = try take(a, colOf(f, rki), rf.firsts, false);
    const cells = try a.alloc(Value, out_rows);
    defer a.free(cells);
    for (cks, data[1 .. 1 + nc]) |ck, *d| {
        for (cells[0..nr], 0..) |*o, r| {
            const id = r * nc + ck.id;
            o.* = if (present[id]) tmp[id] else fill;
            if (promote and o.* == .int) {
                const x: f64 = @floatFromInt(o.int);
                o.* = .{ .float = x };
            }
        }
        if (spec.margins) cells[nr] = col_margin[ck.id];
        d.* = try fm.columnFromCells(a, cells);
    }
    if (spec.margins) {
        for (cells[0..nr], row_margin) |*o, m| o.* = m;
        cells[nr] = corner[0];
        data[1 + nc] = try fm.columnFromCells(a, cells);
    }
    return .{ .columns = cols, .data = data, .len = out_rows };
}

// ── columns: select, drop, rename, fillna ───────────────────────────────────

fn project(a: std.mem.Allocator, f: Frame, idxs: []const usize) Error!Frame {
    const cols = try a.alloc(Column, idxs.len);
    const data = try a.alloc(ColumnData, idxs.len);
    for (idxs, cols, data) |ci, *c, *d| {
        c.* = f.columns[ci];
        d.* = colOf(f, ci);
    }
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// Keep exactly `names`, in that order (pandas `df[names]`, polars `select`). The
/// columns are shared, not copied.
pub fn select(a: std.mem.Allocator, f: Frame, names: []const []const u8) sp.ColumnsError!Frame {
    const idxs = try a.alloc(usize, names.len);
    // A hash set, not a scan of the earlier names: `names` is spec data.
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(a);
    var lk = try Names.init(a, f, names.len);
    defer lk.deinit(a);
    for (names, 0..) |n, i| {
        const gop = try seen.getOrPut(a, n);
        if (gop.found_existing) return error.DuplicateColumn;
        idxs[i] = try lk.of(n);
    }
    return project(a, f, idxs);
}

/// Remove `names` (each must exist); the rest keep their order (pandas `drop`, polars
/// `drop`).
pub fn drop(a: std.mem.Allocator, f: Frame, names: []const []const u8) Error!Frame {
    const gone = try a.alloc(bool, f.columns.len);
    defer a.free(gone);
    @memset(gone, false);
    var lk = try Names.init(a, f, names.len);
    defer lk.deinit(a);
    for (names) |n| gone[try lk.of(n)] = true;
    var idxs: std.ArrayList(usize) = .empty;
    for (gone, 0..) |g, ci| if (!g) try idxs.append(a, ci);
    return project(a, f, idxs.items);
}

/// Rename columns; the data is shared (only the schema is new). Each `from` must
/// exist; renames apply at once (`a→b, b→a` swaps).
pub fn rename(a: std.mem.Allocator, f: Frame, renames: []const sp.Rename) sp.ColumnsError!Frame {
    const cols = try a.dupe(Column, f.columns);
    const touched = try a.alloc(bool, f.columns.len);
    defer a.free(touched);
    @memset(touched, false);
    for (renames) |rn| {
        const ci = try mustIndex(f, rn.from);
        if (touched[ci]) return error.DuplicateColumn; // the same column renamed twice
        touched[ci] = true;
        cols[ci].name = rn.to;
    }
    for (cols, 0..) |c, i| {
        if (!touched[i]) continue;
        for (cols, 0..) |o, j| if (i != j and std.mem.eql(u8, c.name, o.name)) return error.DuplicateColumn;
    }
    const data = try a.alloc(ColumnData, f.columns.len);
    for (data, 0..) |*d, ci| d.* = colOf(f, ci);
    return .{ .columns = cols, .data = data, .len = f.len };
}

/// Write `spec.value` into every missing cell (null, NaN) of `subset`, or each of
/// `per_column`'s values into its column (pandas `fillna`, polars `fill_null` +
/// `fill_nan`), at most `limit` cells per column (pandas `limit`). A column with nothing
/// missing is shared.
pub fn fillna(a: std.mem.Allocator, f: Frame, spec: sp.FillNaSpec) Error!Frame {
    const data = try a.alloc(ColumnData, f.columns.len);
    for (data, 0..) |*d, ci| d.* = colOf(f, ci);
    if (spec.per_column.len > 0) {
        var lk = try Names.init(a, f, spec.per_column.len);
        defer lk.deinit(a);
        for (spec.per_column) |pc| {
            const ci = try lk.of(pc.col);
            data[ci] = try fillColumn(a, data[ci], f.len, pc.value, spec.limit);
        }
    } else {
        for (try subsetIdxs(a, f, spec.subset)) |ci| data[ci] = try fillColumn(a, data[ci], f.len, spec.value, spec.limit);
    }
    return .{ .columns = f.columns, .data = data, .len = f.len };
}

/// `col` with its first `limit` missing cells replaced by `value`; shared when none is.
fn fillColumn(a: std.mem.Allocator, col: ColumnData, rows: usize, value: Value, limit: ?usize) Error!ColumnData {
    var any = false;
    for (0..rows) |ri| {
        if (keys.isMissing(col.get(ri))) {
            any = true;
            break;
        }
    }
    if (!any or limit == 0) return col;
    const cells = try a.alloc(Value, rows);
    defer a.free(cells);
    var left = limit orelse std.math.maxInt(usize);
    for (cells, 0..) |*c, ri| {
        const v = col.get(ri);
        if (left > 0 and keys.isMissing(v)) {
            c.* = value;
            left -= 1;
        } else c.* = v;
    }
    return fm.columnFromCells(a, cells);
}

test "allValid sets no bit past rows (fuzz note: validity bits past len)" {
    for ([_]usize{ 0, 1, 63, 64, 65, 130 }) |rows| {
        const bits = try allValid(std.testing.allocator, rows);
        defer std.testing.allocator.free(bits);
        var n: usize = 0;
        for (bits) |w| n += @popCount(w);
        try std.testing.expectEqual(rows, n);
    }
}
