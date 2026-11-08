// SPDX-License-Identifier: MIT
//! Window functions, optionally per group: pandas' `groupby(...).shift/rolling/
//! cumsum/rank/transform`, polars' `.over(...)`, SQL's `OVER (PARTITION BY ...)`.
//! One verb, `window`: partition, compute one column in each partition, in row order
//! within it, and put the result back at the rows' original places. Taken from
//! `tabular`'s `window` (the same authors, MIT), whose row verb is the oracle here; the
//! per-partition functions are its code unchanged, they read a slice of cells.
//!
//! These follow pandas' skip-NA defaults, unlike `cumsum` and `rolling` (which read a
//! missing cell as 0, `tabular`'s historical rule): a missing value is skipped and a
//! row whose value is missing gets null where pandas' NaN stays NaN.
//!
//! An all-int column stays exact: `cum_sum`, `cum_prod`, `cum_min`, `cum_max`, `diff` and
//! `transform` `sum` give int in i64, as pandas and polars (2^53 + 1 survives, which
//! f64 would lose), and null from an overflow on, where they wrap. Anything else, and
//! the rest of `transform`'s functions, go through f64 like `aggregate`.

const std = @import("std");
const ds = @import("value.zig");
const fm = @import("frame.zig");
const keys = @import("keys.zig");
const t0 = @import("spec.zig");
const ex = @import("expr.zig");
const verbs = @import("verbs.zig");
const core = @import("core.zig");
const Frame = fm.Frame;
const ColumnData = fm.ColumnData;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

/// `BadFill`: a `shift` fill no type of the column can hold (a word in an int column).
pub const WindowError = error{ NoSuchColumn, OutOfMemory, TooLarge, InvalidDecay, BadFill };
const Error = WindowError;

/// Most element visits one `rolling`/time-window call may do: as `max_rolling_work`.
pub const max_window_work: usize = 1 << 30;

/// The first eight are `tabular`'s; the rest were added after the move (survey row
/// 29): `prod`, `sem` (std / sqrt n), `skew` and `kurt` (pandas' bias-corrected sample
/// skewness, null below 3 values, and excess kurtosis, below 4), `first` and `last`
/// (the window's first / last present value), `nunique` (distinct present values),
/// `quantile` (at `q`, type 7). `std`/`var`/`sem` divide by `n - ddof`.
pub const WinFn = enum { mean, sum, std, @"var", min, max, count, median, prod, sem, skew, kurt, first, last, nunique, quantile };

pub const Rolling = struct {
    window: usize,
    func: WinFn = .mean,
    /// Least non-missing values in the window for a result; null = `window`
    /// (pandas), except `count`, for which it is 0. With 0, a window of no values gives
    /// `sum` 0 and `count` 0 and the others null, as pandas and polars do.
    min_periods: ?usize = null,
    /// Label the window's middle row rather than its last (pandas' `center`).
    center: bool = false,
    /// `quantile`'s probability.
    q: f64 = 0.5,
    /// `std`/`var`/`sem`'s delta degrees of freedom (pandas' and polars' `ddof`).
    ddof: u32 = 1,
};

pub const RollingTime = struct {
    /// The partition's time column: `.int` cells (e.g. microseconds in a
    /// `.timestamp` column) ascending within the partition; a row breaking the
    /// order or with a missing time gets null.
    time_col: []const u8,
    /// Window `(t - period, t]`, in the time column's units (pandas' `"7D"`,
    /// polars' `rolling_*_by`). `> 0`, else every row is null.
    period: i64,
    func: WinFn = .mean,
    min_periods: usize = 1,
    q: f64 = 0.5,
    ddof: u32 = 1,
};

pub const Ewm = struct {
    /// Exactly one of the four, else `error.InvalidDecay` (pandas' `ewm`).
    alpha: ?f64 = null,
    span: ?f64 = null,
    com: ?f64 = null,
    halflife: ?f64 = null,
    adjust: bool = true,
    /// pandas' `ignore_na`: true lets a missing row not age the history.
    ignore_na: bool = false,
    min_periods: usize = 0,
    func: enum { mean, @"var", std } = .mean,
};

pub const RankMethod = enum { average, min, max, first, dense };

pub const WindowOp = union(enum) {
    /// Lag (`n` > 0) or lead (`n` < 0); rows off the end get `fill`, which keeps the
    /// column's type where it can (7.0 in an int column is 7), turns an int column float
    /// where it cannot (0.5), and is `error.BadFill` otherwise.
    shift: struct { n: i64 = 1, fill: Value = .null },
    /// `x[i] - x[i-n]`, null where either is missing or off the end.
    diff: i64,
    /// `x[i] / x[i-n] - 1`, same rule (pandas 3: no implicit fill).
    pct_change: i64,
    cum_sum,
    cum_prod,
    cum_min,
    cum_max,
    /// 0, 1, 2, ... (pandas' `cumcount`), missing cells included.
    cum_count,
    /// 1, 2, 3, ... (SQL's `row_number()`).
    row_number,
    rolling: Rolling,
    rolling_time: RollingTime,
    /// Every row sees the partition's prefix, itself included. `min_periods` 0 = 1.
    expanding: struct { func: WinFn = .mean, min_periods: usize = 1, q: f64 = 0.5, ddof: u32 = 1 },
    ewm: Ewm,
    /// 1-based rank by `Value.order`; a missing cell gets null. `dense` and the
    /// others follow pandas' method names.
    rank: struct { method: RankMethod = .average, descending: bool = false },
    /// Carry the last non-missing value forward at most `limit` rows (null = no
    /// limit). A cell of any kind.
    ffill: ?usize,
    /// Carry the next non-missing value backward.
    bfill: ?usize,
    /// Linear, by row position, between non-missing numbers. Leading gaps stay null;
    /// trailing ones too unless `extend_last`: pandas' default fills them with the
    /// last value, polars leaves them null.
    interpolate: struct { extend_last: bool = false },
    /// The partition's aggregate, on every row of it (pandas' `transform`). Takes
    /// `AggFn`, skipping missing cells.
    transform: struct { func: t0.AggFn, q: f64 = 0.5 },
};

pub const WindowSpec = struct {
    value_col: []const u8,
    out: []const u8,
    op: WindowOp,
    /// Empty = one partition, the whole table.
    partition_by: []const []const u8 = &.{},
};

const missing = keys.isMissing;

fn outType(f: Frame, vi: usize, op: WindowOp) ColumnType {
    return switch (op) {
        .shift, .ffill, .bfill => f.columns[vi].type,
        .cum_count, .row_number => .int,
        .transform => |t| switch (t.func) {
            .sum, .mean, .std, .@"var", .median, .quantile, .prod, .sem, .skew, .kurt => .float,
            .count, .nunique, .size, .arg_min, .arg_max => .int,
            .any, .all => .bool,
            .sum_exact => .decimal,
            .min, .max, .first, .last, .mode => f.columns[vi].type,
        },
        .rank => |r| if (r.method == .average) .float else .int,
        else => .float,
    };
}

/// Append `spec.out` computed per partition. Row order and the other columns are
/// untouched (shared). Sort first when the window depends on an order (`sort`, then
/// this).
pub fn window(a: std.mem.Allocator, f: Frame, spec: WindowSpec) Error!Frame {
    return windowImpl(a, f, spec, true);
}

/// For the differential tests only: the cell-by-cell path `window` falls back to, which
/// is the specification of the typed one.
pub const test_hooks = struct {
    pub fn windowCells(a: std.mem.Allocator, f: Frame, spec: WindowSpec) Error!Frame {
        return windowImpl(a, f, spec, false);
    }
};

fn windowImpl(a: std.mem.Allocator, f: Frame, spec: WindowSpec, typed: bool) Error!Frame {
    if (f.len >= keys.none) return error.TooLarge;
    const vi = f.columnIndex(spec.value_col) orelse return error.NoSuchColumn;
    const pidx = try a.alloc(usize, spec.partition_by.len);
    defer a.free(pidx);
    for (spec.partition_by, pidx) |name, *ix| ix.* = f.columnIndex(name) orelse return error.NoSuchColumn;
    const time_ci: ?usize = switch (spec.op) {
        .rolling_time => |rt| f.columnIndex(rt.time_col) orelse return error.NoSuchColumn,
        else => null,
    };
    const vcol = f.columnAt(vi);

    // An all-int column, for the verbs that keep it exact.
    const int_col = blk: {
        if (f.columns[vi].type != .int) break :blk false;
        // Typed storage that holds ints (or nothing) cannot hold anything else.
        if (typed and (vcol == .int or vcol == .nulls)) break :blk true;
        for (0..f.len) |ri| {
            const v = vcol.get(ri);
            if (v != .int and !missing(v)) break :blk false;
        }
        break :blk true;
    };
    var out_type = outType(f, vi, spec.op);
    switch (spec.op) {
        .cum_sum, .cum_prod, .cum_min, .cum_max, .diff => if (int_col) {
            out_type = .int;
        },
        .transform => |tr| if (int_col and tr.func == .sum) {
            out_type = .int;
        },
        else => {},
    }
    var op = spec.op;
    var promote = false;
    if (op == .shift and !missing(op.shift.fill)) {
        const fill = op.shift.fill;
        const same = try castFill(a, fill, out_type);
        if (same) |c| {
            op.shift.fill = c;
        } else if (out_type == .int and fill == .float) {
            out_type = .float;
            promote = true;
        } else return error.BadFill;
    }

    if (typed and !promote) {
        if (try windowTyped(a, f, vi, pidx, op, int_col)) |col| {
            return withColumn(a, f, .{ .name = spec.out, .type = out_type }, col);
        }
    }

    const out = try a.alloc(Value, f.len);
    defer a.free(out);
    const fac = try partitions(a, f, pidx);
    defer a.free(fac.ids);

    if (op == .transform and int_col and op.transform.func == .sum) {
        try transformIntSum(a, vcol, fac, out);
    } else if (op == .transform) {
        try transform(a, f, vi, fac, op.transform.func, op.transform.q, out);
    } else {
        const mem = try keys.members(a, fac.ids, fac.groups());
        const cells = try a.alloc(Value, f.len);
        defer a.free(cells);
        const res = try a.alloc(Value, f.len);
        defer a.free(res);
        const times = try a.alloc(?i64, if (time_ci != null) f.len else 0);
        defer a.free(times);
        const tcol: ColumnData = if (time_ci) |tc| f.columnAt(tc) else .nulls;
        for (0..fac.groups()) |g| {
            const idx = mem.of(g);
            for (idx, cells[0..idx.len]) |ri, *c| c.* = vcol.get(ri);
            if (time_ci != null) {
                for (idx, times[0..idx.len]) |ri, *t| {
                    const tv = tcol.get(ri);
                    t.* = if (tv == .int) tv.int else null;
                }
            }
            try computeOne(a, cells[0..idx.len], if (time_ci != null) times[0..idx.len] else &.{}, op, int_col, res[0..idx.len]);
            for (idx, res[0..idx.len]) |ri, v| out[ri] = v;
        }
    }

    if (promote) {
        for (out) |*v| {
            if (v.* == .int) {
                const x: f64 = @floatFromInt(v.int);
                v.* = .{ .float = x };
            }
        }
    }
    return withColumn(a, f, .{ .name = spec.out, .type = out_type }, try fm.columnFromCells(a, out));
}

fn withColumn(a: std.mem.Allocator, f: Frame, col: Column, data_col: ColumnData) Error!Frame {
    const w = f.columns.len;
    const cols = try a.alloc(Column, w + 1);
    @memcpy(cols[0..w], f.columns);
    cols[w] = col;
    const data = try a.alloc(ColumnData, w + 1);
    for (data[0..w], 0..) |*d, ci| d.* = f.columnAt(ci);
    data[w] = data_col;
    return .{ .columns = cols, .data = data, .len = f.len };
}

// ── typed path ──────────────────────────────────────────────────────────────
// `cum_*`, `shift` (null fill) and `rolling` over a plain int or float column read the
// array and its validity bits directly and build the output array: the same cells as the
// cell path below (`test_hooks.windowCells`), which stays the fallback for the rest.

const Part = struct { ids: ?[]const u32 = null, ng: usize = 1 };

inline fn isV(valid: ?[]const u64, i: usize) bool {
    const v = valid orelse return true;
    return (v[i >> 6] >> @as(u6, @intCast(i & 63))) & 1 == 1;
}

inline fn rowOf(comptime contig: bool, idx: []const u32, k: usize) usize {
    return if (contig) k else idx[k];
}

/// An output array under construction. A null cell holds 0.
fn Out(comptime T: type) type {
    return struct {
        vals: []T,
        bits: []u64,
        n_valid: usize = 0,

        fn init(a: std.mem.Allocator, n: usize) Error!@This() {
            const bits = try a.alloc(u64, (n + 63) / 64);
            @memset(bits, 0);
            return .{ .vals = try a.alloc(T, n), .bits = bits };
        }
        inline fn put(o: *@This(), i: usize, x: T) void {
            o.vals[i] = x;
            o.bits[i >> 6] |= @as(u64, 1) << @as(u6, @intCast(i & 63));
            o.n_valid += 1;
        }
        inline fn putNull(o: *@This(), i: usize) void {
            o.vals[i] = 0;
        }
        /// Rows `lo..hi` were written as valid values.
        fn markValid(o: *@This(), lo: usize, hi: usize) void {
            var i = lo;
            while (i < hi and i & 63 != 0) : (i += 1) o.bits[i >> 6] |= @as(u64, 1) << @as(u6, @intCast(i & 63));
            while (i + 64 <= hi) : (i += 64) o.bits[i >> 6] = ~@as(u64, 0);
            while (i < hi) : (i += 1) o.bits[i >> 6] |= @as(u64, 1) << @as(u6, @intCast(i & 63));
            o.n_valid += hi - lo;
        }
        /// What `columnFromCells` gives for these cells: no valid cell is `.nulls`, all
        /// valid has no bitmap.
        fn finish(o: *const @This()) ColumnData {
            if (o.n_valid == 0) return .nulls;
            const valid: ?[]const u64 = if (o.n_valid == o.vals.len) null else o.bits;
            return if (T == f64) .{ .float = .{ .values = o.vals, .valid = valid } } else .{ .int = .{ .values = o.vals, .valid = valid } };
        }
    };
}

fn windowTyped(a: std.mem.Allocator, f: Frame, vi: usize, pidx: []const usize, op: WindowOp, int_col: bool) Error!?ColumnData {
    switch (op) {
        .cum_sum, .cum_prod, .cum_min, .cum_max, .rolling => {},
        .shift => |s| if (s.fill != .null) return null,
        else => return null,
    }
    const n = f.len;
    const col = f.columnAt(vi);
    switch (col) {
        .float => |c| if (!plainTyped(f64, c, n) or int_col) return null,
        .int => |c| if (!plainTyped(i64, c, n)) return null,
        else => return null,
    }
    if (n == 0) return .nulls;
    var part: Part = .{};
    if (pidx.len > 0) {
        const pc = if (pidx.len == 1) f.columnAt(pidx[0]) else .nulls;
        if (pc == .int and pc.int.valid == null and pc.int.values.len == n) {
            const fac = try keys.factorizeInts(a, pc.int.values);
            part = .{ .ids = fac.ids, .ng = fac.groups() };
        } else {
            const fac = try partitions(a, f, pidx);
            part = .{ .ids = fac.ids, .ng = fac.groups() };
        }
    }
    defer if (part.ids) |ids| a.free(ids);
    return switch (col) {
        .float => |c| try runTyped(f64, a, c, part, op, int_col, n),
        .int => |c| try runTyped(i64, a, c, part, op, int_col, n),
        else => unreachable, // checked above
    };
}

fn noNan(xs: []const f64) bool {
    var bad = false;
    for (xs) |x| bad = bad or x != x;
    return !bad;
}

fn plainTyped(comptime T: type, c: fm.TypedColumn(T), n: usize) bool {
    if (c.values.len != n) return false;
    if (c.valid) |v| return v.len * 64 >= n;
    return true;
}

/// `shift` by one row (either way) in partitions, in one pass over the rows: each group keeps
/// the cell of its previous row (the next one, going backwards) instead of the partitions
/// being gathered and scattered. The same cells as `shiftKernel` per group.
fn shiftByOne(comptime T: type, a: std.mem.Allocator, c: fm.TypedColumn(T), ids: []const u32, ng: usize, forward: bool, n: usize) Error!ColumnData {
    var out = try Out(T).init(a, n);
    const Carry = struct { v: T = 0, st: u8 = 0 }; // 0: no earlier row, 1: its cell, 2: it was null
    const carry = try a.alloc(Carry, ng);
    defer a.free(carry);
    @memset(carry, .{});
    var k: usize = 0;
    while (k < n) : (k += 1) {
        const r = if (forward) k else n - 1 - k;
        const cr = &carry[ids[r]];
        if (cr.st == 1) out.put(r, cr.v) else out.putNull(r);
        if (isV(c.valid, r)) {
            cr.* = .{ .v = c.values[r], .st = 1 };
        } else cr.st = 2;
    }
    return out.finish();
}

fn runTyped(comptime T: type, a: std.mem.Allocator, c: fm.TypedColumn(T), part: Part, op: WindowOp, int_col: bool, n: usize) Error!ColumnData {
    if (op == .shift and (op.shift.n == 1 or op.shift.n == -1)) {
        if (part.ids) |ids| return shiftByOne(T, a, c, ids, part.ng, op.shift.n == 1, n);
    }
    const mem: ?keys.Members = if (part.ids) |ids| try keys.members(a, ids, part.ng) else null;
    defer if (mem) |m| {
        a.free(m.offs);
        a.free(m.rows);
    };
    const ng: usize = if (mem != null) part.ng else 1;
    switch (op) {
        .cum_sum, .cum_prod, .cum_min, .cum_max => if (int_col) {
            var out = try Out(i64).init(a, n);
            for (0..ng) |g| {
                const idx: []const u32 = if (mem) |m| m.of(g) else &.{};
                const cnt = if (mem != null) idx.len else n;
                switch (op) {
                    inline .cum_sum, .cum_prod, .cum_min, .cum_max => |_, tag| {
                        if (mem == null) cumIntKernel(true, tag, c.valid, if (T == i64) c.values else unreachable, idx, cnt, &out) else cumIntKernel(false, tag, c.valid, if (T == i64) c.values else unreachable, idx, cnt, &out);
                    },
                    else => unreachable,
                }
            }
            return out.finish();
        } else {
            var out = try Out(f64).init(a, n);
            for (0..ng) |g| {
                const idx: []const u32 = if (mem) |m| m.of(g) else &.{};
                const cnt = if (mem != null) idx.len else n;
                switch (op) {
                    inline .cum_sum, .cum_prod, .cum_min, .cum_max => |_, tag| {
                        if (mem == null) cumFloatKernel(T, true, tag, c, idx, cnt, &out) else cumFloatKernel(T, false, tag, c, idx, cnt, &out);
                    },
                    else => unreachable,
                }
            }
            return out.finish();
        },
        .shift => |s| {
            var out = try Out(T).init(a, n);
            for (0..ng) |g| {
                const idx: []const u32 = if (mem) |m| m.of(g) else &.{};
                const cnt = if (mem != null) idx.len else n;
                if (mem == null) shiftKernel(T, true, c, s.n, idx, cnt, &out) else shiftKernel(T, false, c, s.n, idx, cnt, &out);
            }
            return out.finish();
        },
        .rolling => |r| {
            var out = try Out(f64).init(a, n);
            if (r.window == 0) return out.finish(); // every cell null
            const buf = try a.alloc(f64, @min(r.window, n));
            defer a.free(buf);
            const clean = c.valid == null and (T != f64 or noNan(c.values));
            for (0..ng) |g| {
                const idx: []const u32 = if (mem) |m| m.of(g) else &.{};
                const cnt = if (mem != null) idx.len else n;
                if (mem == null) try rollingKernel(T, true, c, r, clean, buf, idx, cnt, &out) else try rollingKernel(T, false, c, r, clean, buf, idx, cnt, &out);
            }
            return out.finish();
        },
        else => unreachable, // `windowTyped` let nothing else in
    }
}

/// `cumInt` over typed ints.
fn cumIntKernel(comptime contig: bool, comptime kind: std.meta.Tag(WindowOp), valid: ?[]const u64, vals: []const i64, idx: []const u32, m: usize, out: *Out(i64)) void {
    var acc: i64 = 0;
    var have = false;
    var dead = false;
    for (0..m) |k| {
        const r = rowOf(contig, idx, k);
        if (dead or !isV(valid, r)) {
            out.putNull(r);
            continue;
        }
        const x = vals[r];
        if (have) {
            const next: ?i64 = switch (kind) {
                .cum_sum => std.math.add(i64, acc, x) catch null,
                .cum_prod => std.math.mul(i64, acc, x) catch null,
                .cum_min => @min(acc, x),
                else => @max(acc, x),
            };
            if (next) |nx| {
                acc = nx;
            } else {
                dead = true;
                out.putNull(r);
                continue;
            }
        } else {
            acc = x;
            have = true;
        }
        out.put(r, acc);
    }
}

/// The float `cum_*` branch of `computeOne`: a missing cell (null, NaN) is null and
/// does not move the running value.
fn cumFloatKernel(comptime T: type, comptime contig: bool, comptime kind: std.meta.Tag(WindowOp), c: fm.TypedColumn(T), idx: []const u32, m: usize, out: *Out(f64)) void {
    var acc: f64 = 0;
    var have = false;
    var from: usize = 0;
    if (contig and T == f64 and c.valid == null and m > 0) {
        // The run of numbers before the first NaN: no bit tests, the bitmap set at once.
        if (c.values[0] == c.values[0]) {
            acc = c.values[0];
            have = true;
            out.vals[0] = acc;
            from = 1;
            while (from < m) : (from += 1) {
                const x = c.values[from];
                if (x != x) break;
                acc = switch (kind) {
                    .cum_sum => acc + x,
                    .cum_prod => acc * x,
                    .cum_min => @min(acc, x),
                    else => @max(acc, x),
                };
                out.vals[from] = acc;
            }
            out.markValid(0, from);
        }
    }
    for (from..m) |k| {
        const r = rowOf(contig, idx, k);
        if (!isV(c.valid, r)) {
            out.putNull(r);
            continue;
        }
        const x: f64 = if (T == f64) c.values[r] else @floatFromInt(c.values[r]);
        if (x != x) {
            out.putNull(r);
            continue;
        }
        acc = if (have) switch (kind) {
            .cum_sum => acc + x,
            .cum_prod => acc * x,
            .cum_min => @min(acc, x),
            else => @max(acc, x),
        } else x;
        have = true;
        out.put(r, acc);
    }
}

/// `shift` with a null fill: the cell `by` rows behind (ahead for negative), as it is.
fn shiftKernel(comptime T: type, comptime contig: bool, c: fm.TypedColumn(T), by: i64, idx: []const u32, m: usize, out: *Out(T)) void {
    for (0..m) |k| {
        const r = rowOf(contig, idx, k);
        const j = offset(k, by, m) orelse {
            out.putNull(r);
            continue;
        };
        const sr = rowOf(contig, idx, j);
        if (isV(c.valid, sr)) out.put(r, c.values[sr]) else out.putNull(r);
    }
}

/// `rolling` over typed cells, group of `m` rows: the same windows, the same order of
/// additions, `winStat` for everything but `sum` and `mean`.
fn rollingKernel(comptime T: type, comptime contig: bool, c: fm.TypedColumn(T), r: Rolling, clean: bool, buf: []f64, idx: []const u32, m: usize, out: *Out(f64)) Error!void {
    const w = @min(r.window, m);
    const work = std.math.mul(usize, m, w) catch return error.TooLarge;
    if (work > max_window_work) return error.TooLarge;
    const min_p = r.min_periods orelse (if (r.func == .count) 0 else r.window);
    const lead = if (r.center) (r.window - 1) / 2 else 0;
    const need = @max(min_p, needed(r.func));
    const sum_like = r.func == .sum or r.func == .mean;
    const Row = struct {
        fn at(i: usize, cc: fm.TypedColumn(T), rr: Rolling, bf: []f64, ix: []const u32, mm: usize, ld: usize, nd: usize, sl: bool, o: *Out(f64)) void {
            const end = @min(mm, i +| ld +| 1); // exclusive
            const logical_end = i +| ld +| 1;
            const start = logical_end -| rr.window;
            const row = rowOf(contig, ix, i);
            var k: usize = 0;
            var s: f64 = 0;
            if (start < end) {
                for (start..end) |j| {
                    const sr = rowOf(contig, ix, j);
                    if (!isV(cc.valid, sr)) continue;
                    const x: f64 = if (T == f64) cc.values[sr] else @floatFromInt(cc.values[sr]);
                    if (x != x) continue;
                    if (sl) {
                        s += x;
                    } else bf[k] = x;
                    k += 1;
                }
            }
            if (k < nd) {
                o.putNull(row);
                return;
            }
            if (sl) {
                o.put(row, if (rr.func == .sum) s else s / @as(f64, @floatFromInt(k)));
            } else switch (winStat(bf[0..k], rr.func, .{ .q = rr.q, .ddof = rr.ddof })) {
                .float => |x| o.put(row, x),
                else => o.putNull(row),
            }
        }
    };
    // Rows whose whole window is inside the group, on a column with nothing missing: the
    // sum of each is the same left-to-right chain of additions, so four rows' chains run
    // side by side in one vector (lane j is row i + j; each lane's additions are the scalar
    // ones, in the scalar order).
    var lo: usize = m;
    var hi: usize = m;
    if (contig and T == f64 and clean and sum_like and r.window >= 1 and r.window <= m and need <= r.window) {
        lo = (r.window - 1) -| lead;
        hi = if (m > lead) m - lead else 0; // rows i < hi have i + lead + 1 <= m
        if (lo > hi) lo = hi;
    }
    var i: usize = 0;
    while (i < lo) : (i += 1) Row.at(i, c, r, buf, idx, m, lead, need, sum_like, out);
    if (T == f64 and contig) {
        const V = 4;
        const wf: @Vector(V, f64) = @splat(@floatFromInt(r.window));
        while (i + V <= hi) : (i += V) {
            const base = i + lead + 1 - r.window;
            var sv: @Vector(V, f64) = @splat(0);
            for (0..r.window) |t| {
                const x: @Vector(V, f64) = c.values[base + t ..][0..V].*;
                sv += x;
            }
            if (r.func == .mean) sv /= wf;
            out.vals[i..][0..V].* = sv;
        }
        out.markValid(lo, i);
    }
    while (i < m) : (i += 1) Row.at(i, c, r, buf, idx, m, lead, need, sum_like, out);
}

/// Dense partition ids, first-seen order, as the row verb's `keys.factorize` gives them.
fn partitions(a: std.mem.Allocator, f: Frame, pidx: []const usize) Error!keys.Factors {
    const rows = try verbs.keyRows(a, f, pidx);
    const pos = try a.alloc(usize, pidx.len);
    for (pos, 0..) |*p, i| p.* = i;
    return keys.factorize(a, rows, pos, .as_null);
}

/// `fill` in the column's type, if it stays the same value there.
fn castFill(a: std.mem.Allocator, fill: Value, ty: ColumnType) Error!?Value {
    const c = ex.castValue(a, fill, ty) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null, // castValue compiles nothing; no other error reaches here
    };
    if (c == .null) return null;
    const both_num = c.asFloat() != null and fill.asFloat() != null;
    const both_text = c == .text and fill == .text;
    const both_bool = c == .bool and fill == .bool;
    if ((both_num or both_text or both_bool) and c.order(fill) == .eq) return c;
    return null;
}

fn transform(a: std.mem.Allocator, f: Frame, vi: usize, fac: keys.Factors, func: t0.AggFn, q: f64, out: []Value) Error!void {
    // The partition keys are already ids: aggregate over a two-column frame of them and
    // the value column, which is shared, not copied.
    const cols = [_]Column{ .{ .name = "g", .type = .int }, .{ .name = "v", .type = f.columns[vi].type } };
    const gs = try a.alloc(i64, f.len);
    defer a.free(gs);
    for (gs, fac.ids) |*x, g| x.* = g;
    const data = [_]ColumnData{ .{ .int = .{ .values = gs } }, f.columnAt(vi) };
    const res = try verbs.aggregate(a, .{ .columns = &cols, .data = &data, .len = f.len }, .{
        .group_by = &.{"g"},
        .aggs = &.{.{ .src = "v", .out = "r", .func = func, .q = q }},
        .skip_na = true,
    });
    // Ids are first-seen, and so are the aggregate's rows.
    const r = res.columnAt(1);
    for (fac.ids, out) |g, *o| o.* = r.get(g);
}

fn numOrNull(v: Value) ?f64 {
    const x = v.asFloat() orelse return null;
    return if (std.math.isNan(x)) null else x;
}

fn transformIntSum(a: std.mem.Allocator, vcol: ColumnData, fac: keys.Factors, out: []Value) Error!void {
    const sums = try a.alloc(i64, fac.groups());
    defer a.free(sums);
    @memset(sums, 0);
    const over = try a.alloc(bool, fac.groups());
    defer a.free(over);
    @memset(over, false);
    for (fac.ids, 0..) |g, ri| {
        const v = vcol.get(ri);
        if (v != .int) continue;
        const s = @addWithOverflow(sums[g], v.int);
        if (s[1] != 0) over[g] = true else sums[g] = s[0];
    }
    for (fac.ids, out) |g, *o| o.* = if (over[g]) .null else .{ .int = sums[g] };
}

/// `cum_*` over an all-int partition. An overflow nulls that row and all after it: no
/// later total can be right. Missing rows are null and do not move the total.
fn cumInt(cells: []const Value, op: WindowOp, out: []Value) void {
    var acc: ?i64 = null;
    var dead = false;
    for (cells, out) |c, *o| {
        if (c != .int or dead) {
            o.* = .null;
            continue;
        }
        const x = c.int;
        if (acc) |v| {
            const next = switch (op) {
                .cum_sum => std.math.add(i64, v, x) catch null,
                .cum_prod => std.math.mul(i64, v, x) catch null,
                .cum_min => @min(v, x),
                else => @max(v, x),
            };
            if (next == null) {
                dead = true;
                o.* = .null;
                continue;
            }
            acc = next;
        } else acc = x;
        o.* = .{ .int = acc.? };
    }
}

fn computeOne(a: std.mem.Allocator, cells: []const Value, times: []const ?i64, op: WindowOp, int_col: bool, out: []Value) Error!void {
    const n = cells.len;
    switch (op) {
        .shift => |s| {
            for (out, 0..) |*o, i| {
                const j = offset(i, s.n, n);
                o.* = if (j) |k| cells[k] else s.fill;
            }
        },
        .diff, .pct_change => |p| {
            for (out, 0..) |*o, i| {
                o.* = .null;
                const k = offset(i, p, n) orelse continue;
                if (int_col and op == .diff) {
                    if (cells[i] != .int or cells[k] != .int) continue;
                    const dv = std.math.sub(i64, cells[i].int, cells[k].int) catch continue;
                    o.* = .{ .int = dv };
                    continue;
                }
                const x = numOrNull(cells[i]) orelse continue;
                const y = numOrNull(cells[k]) orelse continue;
                o.* = .{ .float = if (op == .diff) x - y else x / y - 1 };
            }
        },
        .cum_sum, .cum_prod, .cum_min, .cum_max => {
            if (int_col) return cumInt(cells, op, out);
            var acc: ?f64 = null;
            for (cells, out) |c, *o| {
                const x = numOrNull(c) orelse {
                    o.* = .null;
                    continue;
                };
                acc = if (acc) |v| switch (op) {
                    .cum_sum => v + x,
                    .cum_prod => v * x,
                    .cum_min => @min(v, x),
                    else => @max(v, x),
                } else x;
                o.* = .{ .float = acc.? };
            }
        },
        .cum_count => for (out, 0..) |*o, i| {
            o.* = .{ .int = @intCast(i) };
        },
        .row_number => for (out, 0..) |*o, i| {
            o.* = .{ .int = @intCast(i + 1) };
        },
        .rolling => |r| try rolling(a, cells, r, out),
        .rolling_time => |r| try rollingTime(a, cells, times, r, out),
        .expanding => |e| try expanding(a, cells, e.func, @max(e.min_periods, 1), .{ .q = e.q, .ddof = e.ddof }, out),
        .ewm => |e| try ewm(cells, e, out),
        .rank => |r| try rank(a, cells, r.method, r.descending, out),
        .ffill => |limit| {
            var last: ?Value = null;
            var since: usize = 0;
            for (cells, out) |c, *o| {
                if (!missing(c)) {
                    last = c;
                    since = 0;
                    o.* = c;
                    continue;
                }
                since += 1;
                o.* = if (last != null and (limit == null or since <= limit.?)) last.? else .null;
            }
        },
        .bfill => |limit| {
            var next: ?Value = null;
            var since: usize = 0;
            var i = n;
            while (i > 0) {
                i -= 1;
                if (!missing(cells[i])) {
                    next = cells[i];
                    since = 0;
                    out[i] = cells[i];
                    continue;
                }
                since += 1;
                out[i] = if (next != null and (limit == null or since <= limit.?)) next.? else .null;
            }
        },
        .interpolate => |ip| {
            var prev: ?usize = null;
            for (cells, out, 0..) |c, *o, i| {
                const x = numOrNull(c);
                o.* = if (x) |v| .{ .float = v } else .null;
                if (x == null) continue;
                if (prev) |p| {
                    const y0 = numOrNull(cells[p]).?;
                    const steps: f64 = @floatFromInt(i - p);
                    for (out[p + 1 .. i], 1..) |*g, k| {
                        g.* = .{ .float = y0 + (x.? - y0) * @as(f64, @floatFromInt(k)) / steps };
                    }
                }
                prev = i;
            }
            if (ip.extend_last) {
                if (prev) |p| {
                    for (out[p + 1 ..]) |*g| g.* = out[p];
                }
            }
        },
        .transform => unreachable, // `window` handles it whole, not per partition
    }
}

/// The index `n` rows behind `i` (ahead for negative `n`), when in range.
fn offset(i: usize, by: i64, n: usize) ?usize {
    const target = std.math.sub(i128, @intCast(i), by) catch return null;
    if (target < 0 or target >= n) return null;
    return @intCast(target);
}

const StatOpts = struct { q: f64 = 0.5, ddof: u32 = 1 };

fn winStat(vals: []f64, func: WinFn, o: StatOpts) Value {
    const n = vals.len;
    switch (func) {
        .prod => {
            var p: f64 = 1;
            for (vals) |x| p *= x;
            return .{ .float = p };
        },
        .first => return .{ .float = vals[0] },
        .last => return .{ .float = vals[n - 1] },
        .nunique => {
            std.mem.sort(f64, vals, {}, std.sort.asc(f64));
            var u: usize = 0;
            for (vals, 0..) |x, i| u += @intFromBool(i == 0 or x != vals[i - 1]);
            return .{ .float = @floatFromInt(u) };
        },
        .quantile => {
            if (!(o.q >= 0 and o.q <= 1)) return .null;
            return core.quantileInPlace(vals, o.q);
        },
        .sem, .skew, .kurt => {
            var s: core.Moments = .{};
            for (vals) |x| s.add4(x);
            return core.momentResult(s, if (func == .sem) .sem else if (func == .skew) .skew else .kurt, o.ddof);
        },
        .std, .@"var" => if (o.ddof != 1) {
            var s: core.Moments = .{};
            for (vals) |x| s.add2(x);
            return core.momentResult(s, if (func == .std) .std else .@"var", o.ddof);
        },
        else => {},
    }
    switch (func) {
        .count => return .{ .float = @floatFromInt(n) },
        .sum, .mean => {
            var s: f64 = 0;
            for (vals) |x| s += x;
            return .{ .float = if (func == .sum) s else s / @as(f64, @floatFromInt(n)) };
        },
        .min => {
            var m = vals[0];
            for (vals) |x| m = @min(m, x);
            return .{ .float = m };
        },
        .max => {
            var m = vals[0];
            for (vals) |x| m = @max(m, x);
            return .{ .float = m };
        },
        .std, .@"var" => {
            if (n < 2) return .null;
            var mean: f64 = 0;
            var m2: f64 = 0;
            for (vals, 1..) |x, k| {
                const dl = x - mean;
                mean += dl / @as(f64, @floatFromInt(k));
                m2 += dl * (x - mean);
            }
            const v = m2 / @as(f64, @floatFromInt(n - 1));
            return .{ .float = if (func == .std) @sqrt(v) else v };
        },
        .median => {
            const h = n / 2;
            keys.selectKth(vals, h);
            if (n % 2 == 1) return .{ .float = vals[h] };
            var lo = vals[0];
            for (vals[0..h]) |x| lo = @max(lo, x);
            return .{ .float = (lo + vals[h]) / 2 };
        },
        else => unreachable, // the switch above returned
    }
}

/// The values a function needs at all: `count` and `sum` have an answer for none.
fn needed(func: WinFn) usize {
    return @intFromBool(func != .count and func != .sum);
}

fn rolling(a: std.mem.Allocator, cells: []const Value, r: Rolling, out: []Value) Error!void {
    const n = cells.len;
    if (r.window == 0) {
        @memset(out, .null);
        return;
    }
    const w = @min(r.window, n);
    const work = std.math.mul(usize, n, w) catch return error.TooLarge;
    if (work > max_window_work) return error.TooLarge;
    const min_p = r.min_periods orelse (if (r.func == .count) 0 else r.window);
    const buf = try a.alloc(f64, w);
    defer a.free(buf);
    // Centered: the label is `(window - 1) / 2` rows before the window's end, as in
    // pandas (an even window leans forward by one row less than it looks back).
    const lead = if (r.center) (r.window - 1) / 2 else 0;
    for (out, 0..) |*o, i| {
        const end = @min(n, i +| lead +| 1); // exclusive
        const logical_end = i +| lead +| 1;
        const start = logical_end -| r.window;
        var k: usize = 0;
        if (start < end) {
            for (cells[start..end]) |c| {
                if (numOrNull(c)) |x| {
                    buf[k] = x;
                    k += 1;
                }
            }
        }
        o.* = if (k >= @max(min_p, needed(r.func))) winStat(buf[0..k], r.func, .{ .q = r.q, .ddof = r.ddof }) else .null;
    }
}

fn rollingTime(a: std.mem.Allocator, cells: []const Value, times: []const ?i64, r: RollingTime, out: []Value) Error!void {
    const n = cells.len;
    const buf = try a.alloc(f64, n);
    defer a.free(buf);
    var start: usize = 0;
    var work: usize = 0;
    var prev: ?i64 = null;
    for (out, 0..) |*o, i| {
        o.* = .null;
        const t = times[i] orelse continue;
        if (r.period <= 0) continue;
        if (prev != null and t < prev.?) continue;
        prev = t;
        // A time so early that subtracting overflows has no row before its window.
        const lo = std.math.sub(i64, t, r.period) catch std.math.minInt(i64);
        while (start < i and (times[start] == null or times[start].? <= lo)) start += 1;
        var k: usize = 0;
        for (cells[start .. i + 1]) |c| {
            if (numOrNull(c)) |x| {
                buf[k] = x;
                k += 1;
            }
        }
        work += i + 1 - start;
        if (work > max_window_work) return error.TooLarge;
        if (k >= @max(r.min_periods, needed(r.func))) o.* = winStat(buf[0..k], r.func, .{ .q = r.q, .ddof = r.ddof });
    }
}

fn expanding(a: std.mem.Allocator, cells: []const Value, func: WinFn, min_p: usize, so: StatOpts, out: []Value) Error!void {
    const late = switch (func) {
        .mean, .sum, .min, .max, .count, .median => false,
        .std, .@"var" => so.ddof != 1,
        else => true,
    };
    if (late) {
        // The functions added after the move: the prefix, recomputed per row, capped
        // as a window is.
        const n = cells.len;
        const work = std.math.mul(usize, n, n) catch return error.TooLarge;
        if (work > max_window_work) return error.TooLarge;
        const prefix = try a.alloc(f64, n);
        defer a.free(prefix);
        const scratch = try a.alloc(f64, n);
        defer a.free(scratch);
        var k: usize = 0;
        for (cells, out) |c, *ov| {
            if (numOrNull(c)) |x| {
                prefix[k] = x;
                k += 1;
            }
            if (k < @max(min_p, needed(func))) {
                ov.* = .null;
                continue;
            }
            @memcpy(scratch[0..k], prefix[0..k]);
            ov.* = winStat(scratch[0..k], func, so);
        }
        return;
    }
    if (func == .median) {
        // Insertion into a sorted prefix: O(n^2) moves, capped as a window is.
        const n = cells.len;
        const work = std.math.mul(usize, n, n) catch return error.TooLarge;
        if (work > max_window_work) return error.TooLarge;
        const buf = try a.alloc(f64, n);
        defer a.free(buf);
        var k: usize = 0;
        for (cells, out) |c, *o| {
            if (numOrNull(c)) |x| {
                var j = k;
                while (j > 0 and buf[j - 1] > x) : (j -= 1) buf[j] = buf[j - 1];
                buf[j] = x;
                k += 1;
            }
            if (k < min_p) {
                o.* = .null;
                continue;
            }
            o.* = .{ .float = if (k % 2 == 1) buf[k / 2] else (buf[k / 2 - 1] + buf[k / 2]) / 2 };
        }
        return;
    }
    var sum: f64 = 0;
    var mn = std.math.inf(f64);
    var mx = -std.math.inf(f64);
    var mean: f64 = 0;
    var m2: f64 = 0;
    var k: f64 = 0;
    for (cells, out) |c, *o| {
        if (numOrNull(c)) |x| {
            k += 1;
            sum += x;
            mn = @min(mn, x);
            mx = @max(mx, x);
            const dl = x - mean;
            mean += dl / k;
            m2 += dl * (x - mean);
        }
        if (k < @as(f64, @floatFromInt(min_p))) {
            o.* = if (func == .count) .{ .float = k } else .null;
            continue;
        }
        o.* = switch (func) {
            .count => .{ .float = k },
            .sum => .{ .float = sum },
            .mean => .{ .float = sum / k },
            .min => .{ .float = mn },
            .max => .{ .float = mx },
            .@"var" => if (k < 2) .null else .{ .float = m2 / (k - 1) },
            .std => if (k < 2) .null else .{ .float = @sqrt(m2 / (k - 1)) },
            else => unreachable, // above
        };
    }
}

fn ewmAlpha(e: Ewm) Error!f64 {
    var given: u8 = 0;
    var alpha: f64 = 0;
    if (e.alpha) |x| {
        given += 1;
        if (!(x > 0 and x <= 1)) return error.InvalidDecay;
        alpha = x;
    }
    if (e.span) |x| {
        given += 1;
        if (!(x >= 1)) return error.InvalidDecay;
        alpha = 2 / (x + 1);
    }
    if (e.com) |x| {
        given += 1;
        if (!(x >= 0)) return error.InvalidDecay;
        alpha = 1 / (1 + x);
    }
    if (e.halflife) |x| {
        given += 1;
        if (!(x > 0)) return error.InvalidDecay;
        alpha = 1 - @exp(-std.math.ln2 / x);
    }
    if (given != 1 or !std.math.isFinite(alpha) or alpha <= 0) return error.InvalidDecay;
    return alpha;
}

/// Weighted mean and (with the reliability-weights correction pandas' `bias=False`
/// documents) weighted variance, online, weights decaying by row or by observation.
fn ewm(cells: []const Value, e: Ewm, out: []Value) Error!void {
    const alpha = try ewmAlpha(e);
    const decay = 1 - alpha;
    const new_w: f64 = if (e.adjust) 1 else alpha;
    var mean: ?f64 = null;
    var cov: f64 = 0;
    var sum_w: f64 = 0;
    var sum_w2: f64 = 0;
    var old_w: f64 = 0;
    var seen: usize = 0;
    for (cells, out) |c, *o| {
        const x = numOrNull(c);
        if (x != null) seen += 1;
        if (mean) |m| {
            if (x != null or !e.ignore_na) {
                sum_w *= decay;
                sum_w2 *= decay * decay;
                old_w *= decay;
                if (x) |v| {
                    const m1 = (old_w * m + new_w * v) / (old_w + new_w);
                    cov = (old_w * (cov + (m - m1) * (m - m1)) + new_w * (v - m1) * (v - m1)) / (old_w + new_w);
                    mean = m1;
                    sum_w += new_w;
                    sum_w2 += new_w * new_w;
                    old_w += new_w;
                    if (!e.adjust) {
                        sum_w /= old_w;
                        sum_w2 /= old_w * old_w;
                        old_w = 1;
                    }
                }
            }
        } else if (x) |v| {
            mean = v;
            sum_w = 1;
            sum_w2 = 1;
            old_w = 1;
        }
        if (mean == null or seen < @max(e.min_periods, 1)) {
            o.* = .null;
            continue;
        }
        o.* = switch (e.func) {
            .mean => .{ .float = mean.? },
            .@"var", .std => blk: {
                const num = sum_w * sum_w;
                const den = num - sum_w2;
                if (!(den > 0)) break :blk .null;
                const v = num / den * cov;
                break :blk .{ .float = if (e.func == .std) @sqrt(v) else v };
            },
        };
    }
}

fn rank(a: std.mem.Allocator, cells: []const Value, method: RankMethod, desc: bool, out: []Value) Error!void {
    var order: std.ArrayList(u32) = .empty;
    defer order.deinit(a);
    for (cells, 0..) |c, i| {
        if (!missing(c)) try order.append(a, @intCast(i));
    }
    const Ctx = struct {
        cells: []const Value,
        desc: bool,
        fn lt(s: @This(), l: u32, m: u32) bool {
            const o = s.cells[l].order(s.cells[m]);
            return if (s.desc) o == .gt else o == .lt;
        }
    };
    const ctx: Ctx = .{ .cells = cells, .desc = desc };
    std.mem.sort(u32, order.items, ctx, Ctx.lt); // stable: `first` keeps row order
    @memset(out, .null);
    const xs = order.items;
    var i: usize = 0;
    var dense: i64 = 0;
    while (i < xs.len) {
        var j = i + 1;
        while (j < xs.len and !ctx.lt(xs[i], xs[j])) j += 1;
        dense += 1;
        for (xs[i..j], i..) |ri, k| {
            out[ri] = switch (method) {
                .first => .{ .int = @intCast(k + 1) },
                .min => .{ .int = @intCast(i + 1) },
                .max => .{ .int = @intCast(j) },
                .dense => .{ .int = dense },
                .average => .{ .float = @as(f64, @floatFromInt(i + 1 + j)) / 2 },
            };
        }
        i = j;
    }
}

// ── tests ───────────────────────────────────────────────────────────────────
