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
const corr = @import("corr.zig");
const dtype = @import("dtype.zig");
const Frame = fm.Frame;
const ColumnData = fm.ColumnData;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

/// `BadFill`: a `shift` fill no type of the column can hold (a word in an int column).
/// `BadOption`: a combination of options no engine defines or this verb does not carry
/// (`forward` with `center`, `weights` of the wrong length, a `win_type` with a function
/// other than `mean`/`sum`, a non-positive window parameter).
pub const WindowError = error{ NoSuchColumn, OutOfMemory, TooLarge, InvalidDecay, BadFill, BadOption };
const Error = WindowError;

/// Most element visits one `rolling`/time-window call may do: as `max_rolling_work`.
pub const max_window_work: usize = 1 << 30;

/// The first eight are `tabular`'s; the rest were added after the move (survey row
/// 29): `prod`, `sem` (std / sqrt n), `skew` and `kurt` (pandas' bias-corrected sample
/// skewness, null below 3 values, and excess kurtosis, below 4), `first` and `last`
/// (the window's first / last present value), `nunique` (distinct present values),
/// `quantile` (at `q`, type 7). `std`/`var`/`sem` divide by `n - ddof`.
pub const WinFn = enum { mean, sum, std, @"var", min, max, count, median, prod, sem, skew, kurt, first, last, nunique, quantile };

/// Which ends of a window belong to it (pandas `closed=`, polars `rolling_*_by(closed=)`).
/// For a window of rows pandas counts `window` rows ending at the row; `left` and `both`
/// then start one row earlier, `left` and `neither` stop one row earlier. For a time
/// window `(t - period, t]` is `right`, `[t - period, t)` `left`, `[t - period, t]` `both`.
pub const Closed = enum { right, left, both, neither };

/// A named window shape for `Rolling.win_type` (pandas `rolling(win_type=)`, which hands the
/// name to `scipy.signal.windows`): the symmetric window of `window` points, as scipy's
/// default `sym=True`. The parameters are scipy's keyword arguments.
/// `dpss`, `chebwin` and `taylor` are not here (Backlog: they need an eigen-solver,
/// Chebyshev polynomials with an FFT, and an iterative design).
pub const WinType = union(enum) {
    boxcar,
    triang,
    hamming,
    hann,
    bartlett,
    barthann,
    blackman,
    blackmanharris,
    nuttall,
    flattop,
    parzen,
    bohman,
    cosine,
    exponential: struct { tau: f64 },
    gaussian: struct { std: f64 },
    general_gaussian: struct { p: f64, sig: f64 },
    kaiser: struct { beta: f64 },
};

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
    /// pandas `closed=` for a window of rows (`Closed`); `.right` is the plain window.
    /// polars' `rolling_*` has none.
    closed: Closed = .right,
    /// pandas `step=`: evaluate every `step`-th row (0, 1, 2, ... of the partition) only.
    /// pandas returns just those rows; this verb keeps the table's length and leaves
    /// the other rows null (`take` every `step`-th row to get pandas' shape). 0 and 1:
    /// every row.
    step: usize = 1,
    /// pandas `FixedForwardWindowIndexer(window)`: the window starts at the row instead
    /// of ending at it (rows `i .. i + window`). Like pandas it refuses `center` and a
    /// `closed` other than `.right` (`error.BadOption`).
    forward: bool = false,
    /// polars `rolling_*(window_size, weights=)`: element `j` of the window is multiplied
    /// by `weights[j]` (`weights.len` must equal `window`). `sum` is `sum w x`, `mean` is
    /// `sum w x / sum w`, `min`/`max` those of the products `w x`, `var`/`std` the weighted
    /// variance `sum w (x - mean)^2 / sum w` (polars 2.1; `ddof` is not read). Other
    /// functions are `error.BadOption`. A missing cell is skipped and its weight not
    /// counted (pandas' rule for its weighted windows; polars panics on nulls here).
    weights: ?[]const f64 = null,
    /// pandas `rolling(window, win_type=)`: `weights` from a named shape. Only `sum` (the
    /// weighted sum, as pandas) and `mean` (weighted mean) are carried: pandas' weighted
    /// `var`/`std` use a streaming update whose result is not the weighted variance of the
    /// window (it differs for an asymmetric window), so they are `error.BadOption` here.
    win_type: ?WinType = null,
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
    /// Which ends of `(t - period, t]` belong to the window (`Closed`; polars
    /// `rolling_*_by(closed=)`, pandas `rolling("2D", closed=)`).
    closed: Closed = .right,
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
    /// `sum` is the exponentially weighted sum (pandas `ewm().sum()`, polars `ewm_sum`): the
    /// previous sum decays by `1 - alpha`, the new value is added whole. pandas refuses
    /// `adjust=False` and polars has no `adjust` for it; both compute this one, so
    /// `adjust` is not read.
    func: enum { mean, @"var", std, sum } = .mean,
    /// pandas `ewm(halflife=, times=)`: the integer instants of this column (microseconds
    /// for a timestamp) set the age between two rows instead of the row count: the
    /// history is multiplied by `0.5^(dt / halflife)` per step, `halflife` is then a
    /// span in the column's units and the one decay parameter (pandas additionally
    /// accepts `alpha`/`span`/`com` beside it to set the weight of the newest value; this
    /// verb takes `halflife` only). `func` `mean` only, as pandas (its `var`, `std` and
    /// `sum` refuse `times`). A row whose time is missing, or earlier than the row
    /// before it, is null and does not move the state.
    times_col: ?[]const u8 = null,
};

/// polars `ewm_mean_by` / `ewm_sum_by`: `y_i = (1 - a_i) y_prev + a_i x_i` with
/// `a_i = 1 - 0.5^(dt / half_life)` (mean), or `y_i = y_prev 0.5^(dt / half_life) + x_i`
/// (sum), `dt` the time since the previous present value. A missing cell is null and
/// skipped (the next present value measures its `dt` from the last present one). The mean
/// equals pandas' `ewm(halflife, times, adjust=False)` on data without gaps.
pub const EwmBy = struct {
    /// Integer instants, ascending within the partition (as `RollingTime.time_col`).
    time_col: []const u8,
    /// In the time column's units, `> 0`.
    half_life: i64,
    func: enum { mean, sum } = .mean,
};

/// pandas `ewm().cov(other)` and `.corr(other)`: the same decay parameters as `Ewm`
/// (`times_col` and `func` are not read), a row counts when both cells are present.
/// `bias` as pandas (`false`: the reliability-weights correction).
pub const EwmPair = struct {
    other: []const u8,
    ewm: Ewm,
    bias: bool = false,
};

pub const RankMethod = enum { average, min, max, first, dense };

/// Where `rank` puts the missing cells (pandas `na_option`): `keep` leaves them null,
/// `top` / `bottom` rank them below / above every number, all tied with each other.
pub const RankNa = enum { keep, top, bottom };

/// The rank of a row's value among the present values of its window (pandas
/// `rolling(w).rank()` and `expanding().rank()`, polars `rolling_rank`; survey row 29).
/// Numbers only, as the other window functions: a null, NaN or non-numeric cell is
/// missing, does not count, and a row whose own value is missing gets null. The result is
/// float whatever the method (pandas).
pub const RollingRank = struct {
    /// Rows in the window, ending at the row (or around it with `center`); null = the
    /// partition's prefix (`expanding`). 0 makes every row null.
    window: ?usize,
    /// Fewest present values in the window for a result; null = `window` (pandas'
    /// rolling default), 1 for an expanding window.
    min_periods: ?usize = null,
    /// As `Rolling.center`. The row ranked is the labelled one, the window's middle.
    center: bool = false,
    /// pandas' `average`, `min` and `max`; also `first` (ties in row order) and `dense`
    /// (distinct values), as the `rank` operation.
    method: RankMethod = .average,
    /// pandas `ascending=False`.
    descending: bool = false,
    /// Divide by the present values in the window (`dense`: by its distinct values),
    /// pandas' `pct`.
    pct: bool = false,
    /// polars `rolling_rank_by(by, window_size)`: a window of time `(t - period, t]` over
    /// this integer column instead of `window` rows (`window` is then not read). Only
    /// `closed` `.right` and `.both` (the row itself is in its window).
    time_col: ?[]const u8 = null,
    period: i64 = 0,
    closed: Closed = .right,
};

/// Correlation or covariance of the value column with `other` over each row's window
/// (pandas `rolling(w).corr(other)`/`cov(other)` and their `expanding()` forms, polars
/// `rolling_corr`/`rolling_cov`; survey row 29). A window uses its pairwise-complete
/// rows (both cells present), the two-pass numerics of the `corr` verb. Float result.
pub const RollingPair = struct {
    /// The second column.
    other: []const u8,
    /// As `RollingRank.window`: null = expanding.
    window: ?usize,
    /// Fewest complete pairs for a result; null = `window` (pandas), 1 expanding.
    min_periods: ?usize = null,
    center: bool = false,
    /// `cov`: the sum of products is divided by `n - ddof`; `n <= ddof` is null.
    /// `corr` does not read it (it cancels).
    ddof: u32 = 1,
    /// pandas `rolling("2D").corr(other)`: a window of time `(t - period, t]` over this
    /// integer column instead of `window` rows (`window` is then not read, and the
    /// default `min_periods` is 1). polars has no `_by` corr/cov.
    time_col: ?[]const u8 = null,
    period: i64 = 0,
    closed: Closed = .right,
};

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
    /// polars `ewm_mean_by` / `ewm_sum_by` (`EwmBy`).
    ewm_by: EwmBy,
    /// pandas `ewm().cov(other)` (`EwmPair`).
    ewm_cov: EwmPair,
    /// pandas `ewm().corr(other)` (`EwmPair`).
    ewm_corr: EwmPair,
    /// 1-based rank by `Value.order`; a missing cell gets null. `dense` and the
    /// others follow pandas' method names.
    /// `pct` divides each rank by the count of ranked rows (pandas `pct=True`; with `dense`
    /// by the largest rank), so the result is a float. `na_option` as `RankNa` (pandas;
    /// polars' `rank` has neither).
    rank: struct { method: RankMethod = .average, descending: bool = false, pct: bool = false, na_option: RankNa = .keep },
    /// The rank within a rolling or expanding window (`RollingRank`).
    rolling_rank: RollingRank,
    /// Pearson's correlation with another column per window (`RollingPair`).
    rolling_corr: RollingPair,
    /// Covariance with another column per window (`RollingPair`).
    rolling_cov: RollingPair,
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

/// What a window result looks like next to the table (polars `over(mapping_strategy=)`).
pub const Mapping = enum {
    /// One value per row, at the row's place (the default; polars `group_to_rows`).
    group_to_rows,
    /// Each row gets the partition's whole result as a list, in the partition's
    /// (`order_by`) order (polars `join`). The column is `.list`.
    join,
    /// The rows come out partition by partition (first-seen order of the partitions; polars
    /// does not promise an order of groups and showed another one under `order_by`), each
    /// in its `order_by` order, so the table is reordered, one row per result (polars
    /// `explode`).
    explode,
};

pub const WindowSpec = struct {
    value_col: []const u8,
    out: []const u8,
    op: WindowOp,
    /// Empty = one partition, the whole table.
    partition_by: []const []const u8 = &.{},
    /// polars `over(order_by=)`: each partition is sorted by these columns (stable, a
    /// missing cell first, as polars' default) before the operation runs and the result is
    /// put back at the rows' places. Empty = the table's row order. Not read by
    /// `transform` (its aggregates do not depend on order, `first`/`last`/`implode` aside).
    order_by: []const []const u8 = &.{},
    /// Sort `order_by` descending (polars `descending=True`).
    order_descending: bool = false,
    /// Run each partition from its last row to its first (polars `cum_sum(reverse=True)` and
    /// the other `cum_*`; for the other operations the usual `x[::-1]` idiom): the result
    /// is put back at the rows' places. Not read by `transform`.
    reverse: bool = false,
    mapping: Mapping = .group_to_rows,
};

const missing = keys.isMissing;

/// The type an aggregate of a column of the width type `st` has (W11), where it is not the
/// plain `aggOutType`'s: polars' table. `sum` of Int8, Int16, UInt8, UInt16 is Int64 and of
/// Int32, UInt32, UInt64, Float32 keeps the type (an overflow is null here, polars wraps);
/// `prod` of an integer is Int64 (UInt64 keeps); Float32 stays Float32 for `sum`, `prod`,
/// `mean`, `median`, `std`, `var`, `quantile`, `sem`, `skew`, `kurt` (computed in f64,
/// rounded once, so it may differ from polars by an f32 ulp). The rest (`min`, `max`,
/// `first`, `last`, `mode` keep the type; `mean` of an integer is Float64; the counts are
/// Int64, where polars says UInt32) is `aggOutType`'s: null here.
pub fn aggWidthType(st: ColumnType, func: t0.AggFn) ?ColumnType {
    if (st == .float32) return switch (func) {
        .sum, .prod, .mean, .median, .std, .@"var", .quantile, .sem, .skew, .kurt => .float32,
        else => null,
    };
    // Int64 too (polars: `sum` of an Int64 is Int64): the caller passes it only when every
    // stored cell is an int (`verbs.aggregateImpl`), a declared Int64 holding floats keeps Float64.
    if (!dtype.isInteger(st)) return null;
    return switch (func) {
        .sum => switch (st) {
            .int8, .int16, .uint8, .uint16 => .int,
            else => st,
        },
        .prod => if (st == .uint64) .uint64 else .int,
        else => null,
    };
}

/// A running type for `cum_sum`/`cum_prod`/`diff` of the width type `st` (W11), polars'
/// table: `cum_sum` and `cum_prod` as the aggregates, `cum_min`/`cum_max` keep the type,
/// `diff` keeps a signed type and makes an unsigned one the next wider signed (UInt64: Int64).
fn widthWindowType(st: ColumnType, op: WindowOp) ?ColumnType {
    if (!dtype.isWidth(st)) return null;
    const is_f32 = st == .float32;
    return switch (op) {
        .cum_sum => aggWidthType(st, .sum),
        .cum_prod => aggWidthType(st, .prod),
        .cum_min, .cum_max => st,
        .diff => switch (st) {
            .uint8 => .int16,
            .uint16 => .int32,
            .uint32, .uint64 => .int,
            else => st,
        },
        .transform => |t| aggWidthType(st, t.func),
        // polars keeps Float32 through the arithmetic of a window; the rest is a float.
        .pct_change, .rolling, .rolling_time, .expanding, .ewm, .ewm_by, .interpolate => if (is_f32) .float32 else null,
        else => null,
    };
}

/// Fix the cells `aggregate` made for `ty` = `aggWidthType` (W11): an integer `sum`/`prod`
/// is recomputed exactly in an `i128` (the f64 the accumulator keeps is exact only to 2^53)
/// and fitted to `ty` (out of range: null; a missing cell adds nothing), a Float32 result is
/// rounded to f32. Other results are left as they are.
pub fn fixWidthAgg(a: std.mem.Allocator, st: ColumnType, func: t0.AggFn, ty: ColumnType, col: ColumnData, ids: []const u32, skip: bool, cells: []Value) std.mem.Allocator.Error!void {
    _ = skip;
    if (ty == .float32) {
        for (cells) |*c| if (c.* == .float) {
            c.* = .{ .float = dtype.roundF32(c.float) };
        };
        return;
    }
    if (!dtype.isInteger(ty) or !dtype.isInteger(st) or (func != .sum and func != .prod)) return;
    const n = cells.len;
    const acc = try a.alloc(i128, n);
    defer a.free(acc);
    @memset(acc, if (func == .prod) 1 else 0);
    const dead = try a.alloc(bool, n);
    defer a.free(dead);
    @memset(dead, false);
    for (ids, 0..) |g, ri| {
        if (dead[g]) continue;
        const x = dtype.exactI128(col.get(ri)) orelse continue;
        acc[g] = (if (func == .sum) std.math.add(i128, acc[g], x) else std.math.mul(i128, acc[g], x)) catch {
            dead[g] = true;
            continue;
        };
    }
    for (cells, acc, dead) |*c, x, d| c.* = if (d) .null else (dtype.fitInt(x, ty) orelse .null);
}

fn outType(f: Frame, vi: usize, op: WindowOp) ColumnType {
    if (widthWindowType(f.columns[vi].type, op)) |t| return t;
    return switch (op) {
        .shift, .ffill, .bfill => f.columns[vi].type,
        .cum_count, .row_number => .int,
        .transform => |t| switch (t.func) {
            .sum, .mean, .std, .@"var", .median, .quantile, .prod, .sem, .skew, .kurt => .float,
            .count, .nunique, .size, .arg_min, .arg_max => .int,
            .any, .all => .bool,
            .sum_exact => .decimal,
            .min, .max, .first, .last, .mode => f.columns[vi].type,
            .implode => .list,
        },
        .rank => |r| if (r.method == .average or r.pct) .float else .int,
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
    try core.checkRowsU32(f.len);
    const vi = f.columnIndex(spec.value_col) orelse return error.NoSuchColumn;
    const pidx = try a.alloc(usize, spec.partition_by.len);
    defer a.free(pidx);
    if (spec.partition_by.len > 0) {
        // One lookup per name, not a scan of the columns (sweep S2-6).
        var nm = try fm.NameIndex.init(a, f.columns);
        defer nm.deinit(a);
        for (spec.partition_by, pidx) |name, *ix| ix.* = nm.get(name) orelse return error.NoSuchColumn;
    }
    const time_ci: ?usize = if (timeColName(spec.op)) |name| (f.columnIndex(name) orelse return error.NoSuchColumn) else null;
    const other_ci: ?usize = switch (spec.op) {
        .rolling_corr, .rolling_cov => |rp| f.columnIndex(rp.other) orelse return error.NoSuchColumn,
        .ewm_cov, .ewm_corr => |ep| f.columnIndex(ep.other) orelse return error.NoSuchColumn,
        else => null,
    };
    const oidx = try a.alloc(usize, spec.order_by.len);
    defer a.free(oidx);
    for (spec.order_by, oidx) |name, *ix| ix.* = f.columnIndex(name) orelse return error.NoSuchColumn;
    const reorder = spec.order_by.len > 0 or spec.reverse;
    // The typed kernels know neither an order, a reversal nor a mapping.
    const plain_layout = !reorder and spec.mapping == .group_to_rows;
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
    // A column of an integer width (W11): the exact cell verbs run in an i128 and the result type is polars'.
    const wint = dtype.isWidth(f.columns[vi].type) and dtype.isInteger(f.columns[vi].type);
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
        } else if (out_type == .float32 and fill.asFloat() != null) {
            // polars: a literal fill is weak beside a Float32 column, cast to f32.
            op.shift.fill = .{ .float = dtype.roundF32(fill.asFloat().?) };
        } else if (dtype.isInteger(out_type) and fill == .float) {
            out_type = .float;
            promote = true;
        } else return error.BadFill;
    }

    if (typed and !promote and plain_layout and !dtype.isWidth(f.columns[vi].type)) {
        if (try windowTyped(a, f, vi, pidx, op, int_col)) |col| {
            return withColumn(a, f, .{ .name = spec.out, .type = out_type, .time_zone = Column.zoneFor(f.columns[vi], out_type) }, col);
        }
    }

    const out = try a.alloc(Value, f.len);
    defer a.free(out);
    const fac = try partitions(a, f, pidx);
    defer a.free(fac.ids);

    if (op == .transform and int_col and op.transform.func == .sum) {
        try transformIntSum(a, vcol, fac, out);
    } else if (op == .transform) {
        try transform(a, f, vi, fac.ids, fac.groups(), op.transform.func, op.transform.q, out);
    } else {
        const mem = try keys.members(a, fac.ids, fac.groups());
        try checkTotalWork(op, GroupSizes{ .mem = mem, .n = f.len }, fac.groups());
        var time_work: usize = 0;
        const cells = try a.alloc(Value, f.len);
        defer a.free(cells);
        const res = try a.alloc(Value, f.len);
        defer a.free(res);
        const times = try a.alloc(?i64, if (time_ci != null) f.len else 0);
        defer a.free(times);
        const tcol: ColumnData = if (time_ci) |tc| f.columnAt(tc) else .nulls;
        const others = try a.alloc(Value, if (other_ci != null) f.len else 0);
        defer a.free(others);
        const ocol: ColumnData = if (other_ci) |oc| f.columnAt(oc) else .nulls;
        const sidx = try a.alloc(u32, if (reorder) f.len else 0);
        defer a.free(sidx);
        // `win_type` weights depend on the call only: generated once, on the first partition,
        // not per partition (each is up to `max_window_points` Bessel/cos evaluations).
        var win_weights: ?[]f64 = null;
        defer if (win_weights) |w| a.free(w);
        for (0..fac.groups()) |g| {
            if (win_weights == null and op == .rolling) {
                const r = op.rolling;
                if (r.win_type) |wt| {
                    if (r.weights == null and r.closed == .right and (r.func == .mean or r.func == .sum)) {
                        win_weights = try windowWeights(a, wt, r.window);
                    }
                }
            }
            var idx = mem.of(g);
            if (reorder) {
                const sorted = sidx[0..idx.len];
                @memcpy(sorted, idx);
                if (oidx.len > 0) {
                    const ctx: OrderCtx = .{ .f = f, .cols = oidx, .desc = spec.order_descending };
                    std.mem.sort(u32, sorted, ctx, OrderCtx.lt);
                }
                if (spec.reverse) std.mem.reverse(u32, sorted);
                idx = sorted;
            }
            for (idx, cells[0..idx.len]) |ri, *c| c.* = vcol.get(ri);
            if (time_ci != null) {
                for (idx, times[0..idx.len]) |ri, *t| {
                    const tv = tcol.get(ri);
                    t.* = if (tv == .int) tv.int else null;
                }
            }
            if (other_ci != null) {
                for (idx, others[0..idx.len]) |ri, *o| o.* = ocol.get(ri);
            }
            const ctx: Extra = .{
                .times = if (time_ci != null) times[0..idx.len] else &.{},
                .others = if (other_ci != null) others[0..idx.len] else &.{},
                .weights = win_weights,
                .out_ty = out_type,
            };
            try computeOne(a, cells[0..idx.len], ctx, op, int_col or wint, &time_work, res[0..idx.len]);
            for (idx, res[0..idx.len]) |ri, v| out[ri] = v;
        }
        // The int cells of a promoted column become floats on every mapping path.
        if (promote) {
            for (out) |*v| {
                if (v.* == .int or v.* == .uint) {
                    // Read before the write (result location: the tag is written first).
                    const x = v.asFloat().?;
                    v.* = .{ .float = x };
                }
            }
        }
        if (out_type == .float32) roundCells(out);
        if (spec.mapping != .group_to_rows) return mapped(a, f, spec, fac, mem, oidx, out_type, Column.zoneFor(f.columns[vi], out_type), out);
    }
    if (out_type == .float32) roundCells(out);

    return withColumn(a, f, .{ .name = spec.out, .type = out_type, .time_zone = Column.zoneFor(f.columns[vi], out_type) }, try fm.conform(a, try fm.columnFromCells(a, out), out_type, f.len));
}

/// The sort of `order_by`: a missing cell first (polars), then `Value.order`; descending
/// reverses the order of the present cells only.
const OrderCtx = struct {
    f: Frame,
    cols: []const usize,
    desc: bool,

    fn lt(s: OrderCtx, l: u32, m: u32) bool {
        for (s.cols) |ci| {
            const col = s.f.columnAt(ci);
            const x = col.get(l);
            const y = col.get(m);
            const xm = missing(x);
            const ym = missing(y);
            if (xm or ym) {
                if (xm and ym) continue;
                return xm;
            }
            const o = x.order(y);
            if (o == .eq) continue;
            return if (s.desc) o == .gt else o == .lt;
        }
        return false;
    }
};

/// The columns `spec.mapping` is not `group_to_rows`: `join` puts each partition's results
/// in a list on every row of it, `explode` reorders the rows partition by partition.
fn mapped(a: std.mem.Allocator, f: Frame, spec: WindowSpec, fac: keys.Factors, mem: keys.Members, oidx: []const usize, out_type: ColumnType, zone: ?[]const u8, out: []const Value) Error!Frame {
    // The rows in the order the partitions were computed in (first-seen partition, then
    // its sorted order); `reverse` is not applied: the list / the rows read in the
    // `order_by` order.
    const perm = try a.alloc(u32, f.len);
    defer a.free(perm);
    var k: usize = 0;
    for (0..fac.groups()) |g| {
        const idx = mem.of(g);
        const part = perm[k .. k + idx.len];
        @memcpy(part, idx);
        if (oidx.len > 0) {
            const ctx: OrderCtx = .{ .f = f, .cols = oidx, .desc = spec.order_descending };
            std.mem.sort(u32, part, ctx, OrderCtx.lt);
        }
        k += idx.len;
    }
    const data = try fm.conform(a, try fm.columnFromCells(a, out), out_type, f.len);
    const col: Column = .{ .name = spec.out, .type = out_type, .time_zone = zone };
    if (spec.mapping == .explode) {
        const whole = try withColumn(a, f, col, data);
        return verbs.takeRows(a, whole, perm);
    }
    // join: the sorted results imploded per partition, put back on every row of it.
    const sorted_cells = try a.alloc(Value, f.len);
    defer a.free(sorted_cells);
    const sorted_ids = try a.alloc(u32, f.len);
    defer a.free(sorted_ids);
    for (perm, sorted_cells, sorted_ids) |ri, *c, *id| {
        c.* = out[ri];
        id.* = fac.ids[ri];
    }
    const vals = try fm.columnFromCells(a, sorted_cells);
    const one: Frame = .{ .columns = &.{.{ .name = "v", .type = out_type, .time_zone = zone }}, .data = &.{vals}, .len = f.len };
    const cells = try a.alloc(Value, f.len);
    defer a.free(cells);
    try transform(a, one, 0, sorted_ids, fac.groups(), .implode, 0.5, cells);
    // `cells` is indexed by sorted position; put each partition's list on its rows.
    const res = try a.alloc(Value, f.len);
    defer a.free(res);
    for (perm, cells) |ri, c| res[ri] = c;
    return withColumn(a, f, .{ .name = spec.out, .type = .list }, try fm.columnFromCells(a, res));
}

fn timeColName(op: WindowOp) ?[]const u8 {
    return switch (op) {
        .rolling_time => |rt| rt.time_col,
        .rolling_rank => |rr| rr.time_col,
        .rolling_corr, .rolling_cov => |rp| rp.time_col,
        .ewm => |e| e.times_col,
        .ewm_by => |e| e.time_col,
        else => null,
    };
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

/// Row counts of the partitions of a call: `mem` when there are some, else one of `n` rows.
const GroupSizes = struct {
    mem: ?keys.Members,
    n: usize,

    fn sizeOf(gs: GroupSizes, g: usize) usize {
        return if (gs.mem) |m| m.of(g).len else gs.n;
    }
};

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
        .cum_sum, .cum_prod, .cum_min, .cum_max => {},
        .rolling => |r| if (!rollingPlain(r)) return null,
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
            try checkTotalWork(op, GroupSizes{ .mem = mem, .n = n }, ng);
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

/// Element visits `op` makes over a partition of `m` rows, for the functions that revisit
/// cells (a window per row, a prefix per row); the rest are linear.
fn groupWork(op: WindowOp, m: usize) usize {
    return switch (op) {
        .rolling => |r| m *| @min(r.window +| 1, m),
        .expanding => |e| if (e.func == .median or expandingLate(e.func, e.ddof)) m *| m else 0,
        // A window per row; expanding is the prefix, counted as `m * m` like `expanding`'s.
        .rolling_rank => |r| m *| @min(if (r.time_col != null) m else (r.window orelse m), m),
        // Two cells per row of a window.
        .rolling_corr, .rolling_cov => |r| 2 *| m *| @min(if (r.time_col != null) m else (r.window orelse m), m),
        else => 0,
    };
}

/// `max_window_work` is for the whole call, not per partition (sweep S2-2): the sum of
/// every partition's work, refused before any of it is done.
fn checkTotalWork(op: WindowOp, sizes: anytype, n_groups: usize) Error!void {
    var total: usize = 0;
    for (0..n_groups) |g| {
        total +|= groupWork(op, sizes.sizeOf(g));
        if (total > max_window_work) return error.TooLarge;
    }
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

/// Most elements `transform` with `implode` may build: every row gets its partition's
/// whole list, so a partition of `m` rows is `m * m` elements (review R2 H1: 200k rows in
/// one partition were 4e10). Summed over partitions, refused before anything is built.
/// 2^26 elements; past it `error.TooLarge`.
pub const max_implode_window_cells: usize = 1 << 26;

fn transform(a: std.mem.Allocator, f: Frame, vi: usize, ids: []const u32, ng: usize, func: t0.AggFn, q: f64, out: []Value) Error!void {
    if (func == .implode) {
        const sizes = try a.alloc(usize, ng);
        defer a.free(sizes);
        @memset(sizes, 0);
        for (ids) |g| sizes[g] += 1;
        var cells: usize = 0;
        for (sizes) |m| {
            cells +|= m *| m;
            if (cells > max_implode_window_cells) return error.TooLarge;
        }
    }
    // The partition keys are already ids: aggregate over a two-column frame of them and
    // the value column, which is shared, not copied.
    const cols = [_]Column{ .{ .name = "g", .type = .int }, .{ .name = "v", .type = f.columns[vi].type, .time_zone = f.columns[vi].time_zone } };
    const gs = try a.alloc(i64, f.len);
    defer a.free(gs);
    for (gs, ids) |*x, g| x.* = g;
    const data = [_]ColumnData{ .{ .int = .{ .values = gs } }, f.columnAt(vi) };
    const res = try verbs.aggregate(a, .{ .columns = &cols, .data = &data, .len = f.len }, .{
        .group_by = &.{"g"},
        .aggs = &.{.{ .src = "v", .out = "r", .func = func, .q = q }},
        .skip_na = true,
    });
    // Ids are first-seen, and so are the aggregate's rows.
    const r = res.columnAt(1);
    for (ids, out) |g, *o| o.* = r.get(g);
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

/// Float32 results (W11): each float cell rounded to the nearest f32, the f64 that holds it.
fn roundCells(cells: []Value) void {
    for (cells) |*c| if (c.* == .float) {
        c.* = .{ .float = dtype.roundF32(c.float) };
    };
}

/// `cum_*` over an all-int partition of the type `ty` (Int64, or an integer width whose
/// result type is `ty`). An overflow of `ty` nulls that row and all after it: no later total
/// can be right (both engines wrap). Missing rows are null and do not move the total.
fn cumInt(cells: []const Value, op: WindowOp, ty: ColumnType, out: []Value) void {
    var acc: ?i128 = null;
    var dead = false;
    for (cells, out) |c, *o| {
        const x: i128 = switch (c) {
            .int => |i| i,
            .uint => |u| u,
            else => {
                o.* = .null;
                continue;
            },
        };
        if (dead) {
            o.* = .null;
            continue;
        }
        const next: ?i128 = if (acc) |v| switch (op) {
            .cum_sum => std.math.add(i128, v, x) catch null,
            .cum_prod => std.math.mul(i128, v, x) catch null,
            .cum_min => @min(v, x),
            else => @max(v, x),
        } else x;
        const cell = if (next) |nx| dtype.fitInt(nx, ty) else null;
        if (cell == null) {
            dead = true;
            o.* = .null;
            continue;
        }
        acc = next;
        o.* = cell.?;
    }
}

/// Per-partition inputs besides the value cells: the time column's instants
/// (`rolling_time`) and the second column's cells (`rolling_corr`, `rolling_cov`).
const Extra = struct { times: []const ?i64 = &.{}, others: []const Value = &.{}, weights: ?[]const f64 = null, out_ty: ColumnType = .int };

fn computeOne(a: std.mem.Allocator, cells: []const Value, extra: Extra, op: WindowOp, int_col: bool, time_work: *usize, out: []Value) Error!void {
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
                    const x = dtype.exactI128(cells[i]) orelse continue;
                    const y = dtype.exactI128(cells[k]) orelse continue;
                    // i128 holds the difference of any two cells; the type's range decides.
                    o.* = dtype.fitInt(x - y, extra.out_ty) orelse .null;
                    continue;
                }
                const x = numOrNull(cells[i]) orelse continue;
                const y = numOrNull(cells[k]) orelse continue;
                o.* = .{ .float = if (op == .diff) x - y else x / y - 1 };
            }
        },
        .cum_sum, .cum_prod, .cum_min, .cum_max => {
            if (int_col) return cumInt(cells, op, extra.out_ty, out);
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
        .rolling => |r| try rolling(a, cells, r, extra.weights, out),
        .rolling_time => |r| try rollingTime(a, cells, extra.times, r, time_work, out),
        .rolling_rank => |r| try rollingRank(a, cells, extra.times, r, out),
        .rolling_corr => |r| try rollingPair(a, cells, extra.others, extra.times, r, .corr, out),
        .rolling_cov => |r| try rollingPair(a, cells, extra.others, extra.times, r, .cov, out),
        .expanding => |e| try expanding(a, cells, e.func, @max(e.min_periods, 1), .{ .q = e.q, .ddof = e.ddof }, out),
        .ewm => |e| try ewm(cells, extra.times, e, out),
        .ewm_by => |e| try ewmBy(cells, extra.times, e, out),
        .ewm_cov => |p| try ewmPair(a, cells, extra.others, p, .cov, out),
        .ewm_corr => |p| try ewmPair(a, cells, extra.others, p, .corr, out),
        .rank => |r| try rank(a, cells, r.method, r.descending, r.pct, r.na_option, out),
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

/// The window of plain rows ending at the row: what the typed kernels compute.
fn rollingPlain(r: Rolling) bool {
    return r.closed == .right and r.step <= 1 and !r.forward and r.weights == null and r.win_type == null;
}

fn rolling(a: std.mem.Allocator, cells: []const Value, r: Rolling, win_weights: ?[]const f64, out: []Value) Error!void {
    if (!rollingPlain(r)) return rollingGeneral(a, cells, r, win_weights, out);
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

/// Where a time window's search for its first row stands, and the last time seen.
/// `run` is the index where the current run of rows at time `prev` began.
const TimeWin = struct { start: usize = 0, prev: ?i64 = null, run: usize = 0 };

/// Rows `[start, end)` of row `i`'s time window over `times` (ascending): `(t - period, t]`
/// with the ends `closed` says. Null for a row with no time, a non-positive period, or a
/// time earlier than the last one seen (the order is broken).
fn timeWindow(st: *TimeWin, times: []const ?i64, i: usize, period: i64, closed: Closed) ?[2]usize {
    const t = times[i] orelse return null;
    if (period <= 0) return null;
    if (st.prev != null and t < st.prev.?) return null;
    if (st.prev == null or t > st.prev.?) st.run = i;
    st.prev = t;
    // A time so early that subtracting overflows has no row before its window.
    const lo = std.math.sub(i64, t, period) catch std.math.minInt(i64);
    const lower_incl = closed == .left or closed == .both;
    while (st.start < i and (times[st.start] == null or (if (lower_incl) times[st.start].? < lo else times[st.start].? <= lo))) st.start += 1;
    var end = i + 1;
    if (closed == .left or closed == .neither) {
        // The rows at time `t` itself (this one and earlier ties) are outside: the times seen
        // are ascending, so those ties are the run that began at `st.run` (O(1), no walk).
        end = @max(st.start, st.run);
    }
    return .{ st.start, end };
}

/// `work` counts the element visits of every partition of the call, so the cap holds for
/// the whole call (sweep S2-2).
fn rollingTime(a: std.mem.Allocator, cells: []const Value, times: []const ?i64, r: RollingTime, work: *usize, out: []Value) Error!void {
    const n = cells.len;
    const buf = try a.alloc(f64, n);
    defer a.free(buf);
    var tw: TimeWin = .{};
    for (out, 0..) |*o, i| {
        o.* = .null;
        const b = timeWindow(&tw, times, i, r.period, r.closed) orelse continue;
        var k: usize = 0;
        for (cells[b[0]..b[1]]) |c| {
            if (numOrNull(c)) |x| {
                buf[k] = x;
                k += 1;
            }
        }
        work.* += b[1] - b[0] + @intFromBool(b[1] == b[0]);
        if (work.* > max_window_work) return error.TooLarge;
        if (k >= @max(r.min_periods, needed(r.func))) o.* = winStat(buf[0..k], r.func, .{ .q = r.q, .ddof = r.ddof });
    }
}

/// The `expanding` functions added after the move, recomputed per prefix (quadratic).
fn expandingLate(func: WinFn, ddof: u32) bool {
    return switch (func) {
        .mean, .sum, .min, .max, .count, .median => false,
        .std, .@"var" => ddof != 1,
        else => true,
    };
}

fn expanding(a: std.mem.Allocator, cells: []const Value, func: WinFn, min_p: usize, so: StatOpts, out: []Value) Error!void {
    const late = expandingLate(func, so.ddof);
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
fn ewm(cells: []const Value, times: []const ?i64, e: Ewm, out: []Value) Error!void {
    if (e.times_col != null) return ewmTimes(cells, times, e, out);
    const alpha = try ewmAlpha(e);
    if (e.func == .sum) {
        // pandas' `normalize=False` recursion: the history decays, the value is added.
        var weighted: ?f64 = null;
        var nobs: usize = 0;
        for (cells, out) |c, *o| {
            const x = numOrNull(c);
            if (x != null) nobs += 1;
            if (weighted) |wv| {
                if (x != null or !e.ignore_na) {
                    weighted = wv * (1 - alpha);
                    if (x) |v| weighted = weighted.? + v;
                }
            } else if (x) |v| weighted = v;
            o.* = if (weighted != null and nobs >= @max(e.min_periods, 1)) .{ .float = weighted.? } else .null;
        }
        return;
    }
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
            .sum => unreachable, // returned above
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

fn rank(a: std.mem.Allocator, cells: []const Value, method: RankMethod, desc: bool, pct: bool, na: RankNa, out: []Value) Error!void {
    var order: std.ArrayList(u32) = .empty;
    defer order.deinit(a);
    for (cells, 0..) |c, i| {
        if (na != .keep or !missing(c)) try order.append(a, @intCast(i));
    }
    const Ctx = struct {
        cells: []const Value,
        desc: bool,
        na: RankNa,
        fn lt(s: @This(), l: u32, m: u32) bool {
            const lm = missing(s.cells[l]);
            const mm = missing(s.cells[m]);
            // The missing cells tie with each other, below or above every number.
            if (lm or mm) {
                if (lm and mm) return false;
                return if (s.na == .top) lm else mm;
            }
            const o = s.cells[l].order(s.cells[m]);
            return if (s.desc) o == .gt else o == .lt;
        }
    };
    const ctx: Ctx = .{ .cells = cells, .desc = desc, .na = na };
    std.mem.sort(u32, order.items, ctx, Ctx.lt); // stable: `first` keeps row order
    @memset(out, .null);
    const xs = order.items;
    var i: usize = 0;
    var dense: i64 = 0;
    var denom: f64 = @floatFromInt(xs.len);
    while (i < xs.len) {
        var j = i + 1;
        while (j < xs.len and !ctx.lt(xs[i], xs[j])) j += 1;
        dense += 1;
        for (xs[i..j], i..) |ri, k| {
            const r: f64 = switch (method) {
                .first => @floatFromInt(k + 1),
                .min => @floatFromInt(i + 1),
                .max => @floatFromInt(j),
                .dense => @floatFromInt(dense),
                .average => @as(f64, @floatFromInt(i + 1 + j)) / 2,
            };
            out[ri] = if (pct or method == .average) .{ .float = r } else .{ .int = @intFromFloat(r) };
        }
        i = j;
    }
    if (pct) {
        if (method == .dense) denom = @floatFromInt(dense);
        for (out) |*o| {
            if (o.* == .float) o.* = .{ .float = o.float / denom };
        }
    }
}

/// Rows `[start, end)` of row `i`'s window in a partition of `n` rows: `window` rows
/// ending at `i` (around it with `center`, as `rolling` places them), or the prefix
/// when `rows` is null. `i` is always inside.
fn windowBounds(i: usize, n: usize, rows: ?usize, center: bool) [2]usize {
    const w = rows orelse return .{ 0, i + 1 };
    const lead = if (center) (w -| 1) / 2 else 0;
    const end = @min(n, i +| lead +| 1);
    const start = (i +| lead +| 1) -| w;
    return .{ @min(start, end), end };
}

/// `rolling_rank`: each row's value ranked among its window's present values.
fn rollingRank(a: std.mem.Allocator, cells: []const Value, times: []const ?i64, r: RollingRank, out: []Value) Error!void {
    const n = cells.len;
    @memset(out, .null);
    const timed = r.time_col != null;
    if (timed and r.closed != .right and r.closed != .both) return error.BadOption;
    if (!timed) if (r.window) |w| if (w == 0) return;
    if (groupWork(.{ .rolling_rank = r }, n) > max_window_work) return error.TooLarge;
    const min_p = r.min_periods orelse (if (timed) 1 else (r.window orelse 1));
    var tw: TimeWin = .{};
    const vals = try a.alloc(?f64, n);
    defer a.free(vals);
    for (cells, vals) |c, *v| v.* = numOrNull(c);
    const buf = try a.alloc(f64, if (r.method == .dense) (if (timed) n else @min(r.window orelse n, n)) else 0);
    defer a.free(buf);
    for (out, 0..) |*o, i| {
        const x = vals[i] orelse continue;
        const b = if (timed) (timeWindow(&tw, times, i, r.period, r.closed) orelse continue) else windowBounds(i, n, r.window, r.center);
        var nobs: usize = 0;
        var before: usize = 0; // values ranked ahead of x
        var ties: usize = 0; // values equal to x, x included
        var ties_earlier: usize = 0; // of those, rows before i
        for (vals[b[0]..b[1]], b[0]..) |vy, j| {
            const y = vy orelse continue;
            if (r.method == .dense) buf[nobs] = y;
            nobs += 1;
            if (if (r.descending) y > x else y < x) {
                before += 1;
            } else if (y == x) {
                ties += 1;
                ties_earlier += @intFromBool(j < i);
            }
        }
        if (nobs < min_p) continue;
        var denom: f64 = @floatFromInt(nobs);
        const rk: f64 = switch (r.method) {
            .average => @as(f64, @floatFromInt(before)) + @as(f64, @floatFromInt(ties + 1)) / 2,
            .min => @floatFromInt(before + 1),
            .max => @floatFromInt(before + ties),
            .first => @floatFromInt(before + ties_earlier + 1),
            .dense => blk: {
                // Distinct values ahead of x, and in all; the window sorted (the log
                // factor `max_window_work` leaves out, as for `quantile`).
                const vs = buf[0..nobs];
                std.mem.sort(f64, vs, {}, std.sort.asc(f64));
                var distinct: usize = 0;
                var ahead: usize = 0;
                for (vs, 0..) |y, k| {
                    if (k > 0 and y == vs[k - 1]) continue;
                    distinct += 1;
                    if (if (r.descending) y > x else y < x) ahead += 1;
                }
                denom = @floatFromInt(distinct);
                break :blk @floatFromInt(ahead + 1);
            },
        };
        o.* = .{ .float = if (r.pct) rk / denom else rk };
    }
}

const PairStat = enum { corr, cov };

/// `rolling_corr`/`rolling_cov`: the pairwise-complete rows of each window, then the
/// `corr` verb's two-pass numerics.
fn rollingPair(a: std.mem.Allocator, xcells: []const Value, ycells: []const Value, times: []const ?i64, r: RollingPair, stat: PairStat, out: []Value) Error!void {
    const n = xcells.len;
    @memset(out, .null);
    const timed = r.time_col != null;
    if (!timed) if (r.window) |w| if (w == 0) return;
    if (groupWork(.{ .rolling_corr = r }, n) > max_window_work) return error.TooLarge;
    const min_p = @max(r.min_periods orelse (if (timed) 1 else (r.window orelse 1)), 1);
    var tw: TimeWin = .{};
    const xs = try a.alloc(?f64, n);
    defer a.free(xs);
    const ys = try a.alloc(?f64, n);
    defer a.free(ys);
    for (xs, ys, 0..) |*x, *y, i| {
        x.* = numOrNull(xcells[i]);
        y.* = if (i < ycells.len) numOrNull(ycells[i]) else null;
    }
    const w = if (timed) n else @min(r.window orelse n, n);
    const xb = try a.alloc(f64, w);
    defer a.free(xb);
    const yb = try a.alloc(f64, w);
    defer a.free(yb);
    for (out, 0..) |*o, i| {
        const b = if (timed) (timeWindow(&tw, times, i, r.period, r.closed) orelse continue) else windowBounds(i, n, r.window, r.center);
        var k: usize = 0;
        for (b[0]..b[1]) |j| {
            const x = xs[j] orelse continue;
            const y = ys[j] orelse continue;
            xb[k] = x;
            yb[k] = y;
            k += 1;
        }
        if (k < min_p) continue;
        o.* = switch (stat) {
            .corr => .{ .float = corr.pearson(xb[0..k], yb[0..k]) },
            .cov => if (k <= r.ddof) .null else .{ .float = corr.comoment(xb[0..k], yb[0..k]) / @as(f64, @floatFromInt(k - r.ddof)) },
        };
    }
}

/// pandas `ewm(halflife=, times=)` mean: the history is multiplied by `0.5^(dt / halflife)`
/// per step (`pandas` sets `alpha = 0.5` with `halflife` alone), `dt` the time since the
/// previous row with a time.
fn ewmTimes(cells: []const Value, times: []const ?i64, e: Ewm, out: []Value) Error!void {
    if (e.func != .mean) return error.BadOption;
    if (e.alpha != null or e.span != null or e.com != null) return error.BadOption;
    const hl = e.halflife orelse return error.InvalidDecay;
    if (!(hl > 0) or !std.math.isFinite(hl)) return error.InvalidDecay;
    var weighted: ?f64 = null;
    var old_w: f64 = 1;
    var nobs: usize = 0;
    var prev_t: ?i64 = null;
    for (cells, out, 0..) |c, *o, i| {
        o.* = .null;
        const t = times[i] orelse continue;
        if (prev_t != null and t < prev_t.?) continue;
        const x = numOrNull(c);
        if (x != null) nobs += 1;
        if (weighted) |wv| {
            if (x != null or !e.ignore_na) {
                const dt: f64 = @floatFromInt(@as(i128, t) - prev_t.?);
                old_w *= std.math.pow(f64, 0.5, dt / hl);
                if (x) |v| {
                    // pandas leaves a value equal to the average alone (constant series).
                    // adjust=False: the new value weighs what the history lost, so
                    // the update is `decay * y + (1 - decay) * x` (polars' `ewm_mean_by`).
                    const new_w: f64 = if (e.adjust) 1 else 1 - old_w;
                    if (wv != v) weighted = (old_w * wv + new_w * v) / (old_w + new_w);
                    if (e.adjust) old_w += new_w else old_w = 1;
                }
            }
        } else if (x) |v| weighted = v;
        prev_t = t;
        if (weighted != null and nobs >= @max(e.min_periods, 1)) o.* = .{ .float = weighted.? };
    }
}

/// polars `ewm_mean_by` / `ewm_sum_by` (`EwmBy`).
fn ewmBy(cells: []const Value, times: []const ?i64, e: EwmBy, out: []Value) Error!void {
    if (e.half_life <= 0) return error.InvalidDecay;
    const hl: f64 = @floatFromInt(e.half_life);
    var y: ?f64 = null;
    var prev_t: i64 = 0;
    for (cells, out, 0..) |c, *o, i| {
        o.* = .null;
        const t = times[i] orelse continue;
        const x = numOrNull(c) orelse continue;
        if (y) |yv| {
            if (t < prev_t) continue;
            const dt: f64 = @floatFromInt(@as(i128, t) - prev_t);
            const decay = std.math.pow(f64, 0.5, dt / hl);
            y = switch (e.func) {
                .mean => decay * yv + (1 - decay) * x,
                .sum => decay * yv + x,
            };
        } else y = x;
        prev_t = t;
        o.* = .{ .float = y.? };
    }
}

/// pandas' `ewmcov` over the rows where both cells are present: an online update of the
/// exponentially weighted covariance; `bias` skips the reliability-weights correction.
fn ewmCovSeries(xs: []const ?f64, ys: []const ?f64, alpha: f64, e: Ewm, bias: bool, res: []?f64) void {
    const n = xs.len;
    @memset(res, null);
    if (n == 0) return;
    const minp = @max(e.min_periods, 1);
    const old_wt_factor = 1 - alpha;
    const new_wt: f64 = if (e.adjust) 1 else alpha;
    var have = xs[0] != null and ys[0] != null;
    var mean_x: f64 = if (have) xs[0].? else 0;
    var mean_y: f64 = if (have) ys[0].? else 0;
    var nobs: usize = @intFromBool(have);
    if (have and nobs >= minp) res[0] = if (bias) 0 else null;
    var cov: f64 = 0;
    var sum_wt: f64 = 1;
    var sum_wt2: f64 = 1;
    var old_wt: f64 = 1;
    for (1..n) |i| {
        const is_obs = xs[i] != null and ys[i] != null;
        if (is_obs) nobs += 1;
        if (have) {
            if (is_obs or !e.ignore_na) {
                sum_wt *= old_wt_factor;
                sum_wt2 *= old_wt_factor * old_wt_factor;
                old_wt *= old_wt_factor;
                if (is_obs) {
                    const cur_x = xs[i].?;
                    const cur_y = ys[i].?;
                    const old_mean_x = mean_x;
                    const old_mean_y = mean_y;
                    // pandas skips the update when the new value equals the mean.
                    if (mean_x != cur_x) mean_x = (old_wt * old_mean_x + new_wt * cur_x) / (old_wt + new_wt);
                    if (mean_y != cur_y) mean_y = (old_wt * old_mean_y + new_wt * cur_y) / (old_wt + new_wt);
                    cov = (old_wt * (cov + (old_mean_x - mean_x) * (old_mean_y - mean_y)) + new_wt * ((cur_x - mean_x) * (cur_y - mean_y))) / (old_wt + new_wt);
                    sum_wt += new_wt;
                    sum_wt2 += new_wt * new_wt;
                    old_wt += new_wt;
                    if (!e.adjust) {
                        sum_wt /= old_wt;
                        sum_wt2 /= old_wt * old_wt;
                        old_wt = 1;
                    }
                }
            }
        } else if (is_obs) {
            have = true;
            mean_x = xs[i].?;
            mean_y = ys[i].?;
        }
        if (nobs >= minp and have) {
            if (!bias) {
                const num = sum_wt * sum_wt;
                const den = num - sum_wt2;
                if (den > 0) res[i] = num / den * cov;
            } else res[i] = cov;
        }
    }
}

/// `ewm_cov` / `ewm_corr`; corr is `cov / sqrt(var_x var_y)`, each biased, as pandas.
fn ewmPair(a: std.mem.Allocator, xcells: []const Value, ycells: []const Value, p: EwmPair, stat: PairStat, out: []Value) Error!void {
    const n = xcells.len;
    const alpha = try ewmAlpha(p.ewm);
    const buf = try a.alloc(?f64, 7 * n);
    defer a.free(buf);
    const xs = buf[0..n];
    const ys = buf[n .. 2 * n];
    for (xs, ys, 0..) |*x, *y, i| {
        x.* = numOrNull(xcells[i]);
        y.* = if (i < ycells.len) numOrNull(ycells[i]) else null;
    }
    const c = buf[2 * n .. 3 * n];
    switch (stat) {
        .cov => {
            ewmCovSeries(xs, ys, alpha, p.ewm, p.bias, c);
            for (out, c) |*o, v| o.* = if (v) |x| .{ .float = x } else .null;
        },
        .corr => {
            const xv = buf[3 * n .. 4 * n];
            const yv = buf[4 * n .. 5 * n];
            // pandas masks the pair first: a row where either is missing is missing in
            // all three of cov, var x and var y.
            const xj = buf[5 * n .. 6 * n];
            const yj = buf[6 * n .. 7 * n];
            for (xj, yj, xs, ys) |*u, *v, x, y| {
                const both = x != null and y != null;
                u.* = if (both) x else null;
                v.* = if (both) y else null;
            }
            ewmCovSeries(xj, yj, alpha, p.ewm, true, c);
            ewmCovSeries(xj, xj, alpha, p.ewm, true, xv);
            ewmCovSeries(yj, yj, alpha, p.ewm, true, yv);
            for (out, c, xv, yv) |*o, cv, xx, yy| {
                o.* = .null;
                if (cv == null or xx == null or yy == null) continue;
                const prod = xx.? * yy.?;
                const den = if (prod < 0) 0 else @sqrt(prod);
                const r = cv.? / den;
                if (std.math.isFinite(r)) o.* = .{ .float = r };
            }
        },
    }
}

// ── weighted and named windows ──────────────────────────────────────────────

/// Most points a `win_type` window may have.
pub const max_window_points: usize = 1 << 22;

fn besselI0(x: f64) f64 {
    // Modified Bessel function of the first kind, order 0: the power series, whose
    // terms shrink fast once k > x / 2.
    const q = x * x / 4;
    var term: f64 = 1;
    var sum: f64 = 1;
    var k: f64 = 1;
    while (k < 1000) : (k += 1) {
        term *= q / (k * k);
        sum += term;
        if (term < sum * 1e-17) break;
    }
    return sum;
}

fn genCos(coefs: []const f64, fac: f64) f64 {
    var w: f64 = 0;
    for (coefs, 0..) |c, k| w += c * @cos(@as(f64, @floatFromInt(k)) * fac);
    return w;
}

/// The `m` points of the symmetric window `wt` (scipy.signal.windows with `sym=True`, which
/// is what pandas' `rolling(win_type=)` calls). Formulas from the scipy documentation;
/// `m == 1` is `[1]` for every shape.
pub fn windowWeights(a: std.mem.Allocator, wt: WinType, m: usize) Error![]f64 {
    if (m > max_window_points) return error.TooLarge;
    switch (wt) {
        .exponential => |p| if (!(p.tau > 0) or !std.math.isFinite(p.tau)) return error.BadOption,
        .gaussian => |p| if (!(p.std > 0) or !std.math.isFinite(p.std)) return error.BadOption,
        .general_gaussian => |p| if (!(p.sig > 0) or !std.math.isFinite(p.sig) or !std.math.isFinite(p.p)) return error.BadOption,
        .kaiser => |p| if (!(p.beta >= 0) or p.beta > 700) return error.BadOption,
        else => {},
    }
    const w = try a.alloc(f64, m);
    errdefer a.free(w);
    if (m == 1) {
        w[0] = 1;
        return w;
    }
    const mf: f64 = @floatFromInt(m);
    const den = mf - 1;
    const centre = den / 2;
    const pi = std.math.pi;
    const hamming = [_]f64{ 0.54, 0.46 };
    const hann = [_]f64{ 0.5, 0.5 };
    const blackman = [_]f64{ 0.42, 0.50, 0.08 };
    const bh = [_]f64{ 0.35875, 0.48829, 0.14128, 0.01168 };
    const nuttall = [_]f64{ 0.3635819, 0.4891775, 0.1365995, 0.0106411 };
    const flattop = [_]f64{ 0.21557895, 0.41663158, 0.277263158, 0.083578947, 0.006947368 };
    for (w, 0..) |*x, i| {
        const n: f64 = @floatFromInt(i);
        const fac = -pi + 2 * pi * n / den;
        x.* = switch (wt) {
            .boxcar => 1,
            .triang => blk: {
                const j: f64 = @floatFromInt(@min(i, m - 1 - i) + 1);
                break :blk if (m % 2 == 0) (2 * j - 1) / mf else 2 * j / (mf + 1);
            },
            .hamming => genCos(&hamming, fac),
            .hann => genCos(&hann, fac),
            .bartlett => if (n <= centre) 2 * n / den else 2 - 2 * n / den,
            .barthann => blk: {
                const f = @abs(n / den - 0.5);
                break :blk 0.62 - 0.48 * f + 0.38 * @cos(2 * pi * f);
            },
            .blackman => genCos(&blackman, fac),
            .blackmanharris => genCos(&bh, fac),
            .nuttall => genCos(&nuttall, fac),
            .flattop => genCos(&flattop, fac),
            .parzen => blk: {
                const an = @abs(n - centre);
                const r = an / (mf / 2);
                break :blk if (an > den / 4) 2 * std.math.pow(f64, 1 - r, 3) else 1 - 6 * r * r + 6 * r * r * r;
            },
            .bohman => blk: {
                if (i == 0 or i == m - 1) break :blk 0;
                const f = @abs(-1 + 2 * n / den);
                break :blk (1 - f) * @cos(pi * f) + @sin(pi * f) / pi;
            },
            .cosine => @sin(pi * (n + 0.5) / mf),
            .exponential => |p| @exp(-@abs(n - centre) / p.tau),
            .gaussian => |p| @exp(-((n - centre) * (n - centre)) / (2 * p.std * p.std)),
            .general_gaussian => |p| @exp(-0.5 * std.math.pow(f64, @abs((n - centre) / p.sig), 2 * p.p)),
            .kaiser => |p| blk: {
                const r = (n - centre) / centre;
                break :blk besselI0(p.beta * @sqrt(@max(0, 1 - r * r))) / besselI0(p.beta);
            },
        };
    }
    return w;
}

/// `func` over the present values `xs` with their window weights `ws` (`Rolling.weights`).
fn weightedStat(xs: []const f64, ws: []const f64, func: WinFn) Value {
    var sw: f64 = 0;
    var swx: f64 = 0;
    for (xs, ws) |x, w| {
        sw += w;
        swx += w * x;
    }
    switch (func) {
        .sum => return .{ .float = swx },
        .mean => return if (sw == 0) .null else .{ .float = swx / sw },
        .min, .max => {
            var m = ws[0] * xs[0];
            for (xs[1..], ws[1..]) |x, w| m = if (func == .min) @min(m, w * x) else @max(m, w * x);
            return .{ .float = m };
        },
        .@"var", .std => {
            if (sw == 0) return .null;
            const mean = swx / sw;
            var s: f64 = 0;
            for (xs, ws) |x, w| s += w * (x - mean) * (x - mean);
            const v = s / sw;
            return .{ .float = if (func == .std) @sqrt(v) else v };
        },
        else => unreachable, // `rollingGeneral` refused the rest
    }
}

/// `rolling` with any of `closed`, `step`, `forward`, `weights`, `win_type` set: the
/// cell-by-cell window, row by row.
/// `win_weights` are the `win_type` weights the caller generated once for the whole call.
fn rollingGeneral(a: std.mem.Allocator, cells: []const Value, r: Rolling, win_weights: ?[]const f64, out: []Value) Error!void {
    const n = cells.len;
    @memset(out, .null);
    if (r.forward and (r.center or r.closed != .right)) return error.BadOption;
    if (r.win_type != null and r.weights != null) return error.BadOption;
    if ((r.win_type != null or r.weights != null) and r.closed != .right) return error.BadOption;
    var generated: ?[]f64 = null;
    defer if (generated) |g| a.free(g);
    if (r.win_type) |wt| {
        if (r.func != .mean and r.func != .sum) return error.BadOption;
        if (win_weights == null) generated = try windowWeights(a, wt, r.window);
    } else if (r.weights) |w| {
        if (w.len != r.window) return error.BadOption;
        switch (r.func) {
            .mean, .sum, .min, .max, .@"var", .std => {},
            else => return error.BadOption,
        }
    }
    const wv: ?[]const f64 = generated orelse win_weights orelse r.weights;
    if (r.window == 0) return;
    const cap = @min(r.window +| 1, n);
    const work = std.math.mul(usize, n, cap) catch return error.TooLarge;
    if (work > max_window_work) return error.TooLarge;
    const buf = try a.alloc(f64, cap);
    defer a.free(buf);
    const wbuf = try a.alloc(f64, if (wv != null) cap else 0);
    defer a.free(wbuf);
    const min_p = r.min_periods orelse (if (r.func == .count) 0 else r.window);
    const need = @max(min_p, needed(r.func));
    const step = @max(r.step, 1);
    const wi: i128 = @intCast(r.window);
    const lead: i128 = if (r.center) @intCast((r.window - 1) / 2) else 0;
    for (out, 0..) |*o, i| {
        if (i % step != 0) continue;
        const ii: i128 = @intCast(i);
        var s: i128 = undefined;
        var e: i128 = undefined;
        if (r.forward) {
            s = ii;
            e = ii + wi;
        } else {
            e = ii + 1 + lead;
            s = e - wi;
            if (r.closed == .left or r.closed == .both) s -= 1;
            if (r.closed == .left or r.closed == .neither) e -= 1;
        }
        const lo: usize = @intCast(@max(s, 0));
        const hi: usize = @intCast(@min(e, @as(i128, @intCast(n))));
        var k: usize = 0;
        if (lo < hi) {
            for (lo..hi) |j| {
                const x = numOrNull(cells[j]) orelse continue;
                buf[k] = x;
                if (wv) |ww| wbuf[k] = ww[@intCast(@as(i128, @intCast(j)) - s)];
                k += 1;
            }
        }
        if (k < need) continue;
        o.* = if (wv != null) weightedStat(buf[0..k], wbuf[0..k], r.func) else winStat(buf[0..k], r.func, .{ .q = r.q, .ddof = r.ddof });
    }
}

// ── tests ───────────────────────────────────────────────────────────────────
