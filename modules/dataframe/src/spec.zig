// SPDX-License-Identifier: MIT
//! The verbs' spec types and limits. Each has the same fields, defaults and meaning as
//! the spec of the same name in `tabular` (the same authors, MIT), whose row verbs are
//! this module's differential oracle until they retire.

const std = @import("std");
const vm = @import("value.zig");
const Value = vm.Value;
const ColumnType = vm.ColumnType;

/// `TooLarge`: a verb would build more than one of the limits below allows. The limits
/// are constants, not spec fields: specs come from user files.
pub const Error = error{ NoSuchColumn, OutOfMemory, TooLarge };

/// Most cells (`groups x aggs.len`) one `aggregate` may build accumulators for.
/// Each cell is a ~280-byte accumulator plus an output `Value`; `aggs` is spec
/// data and the group count is data cardinality, so the product is checked
/// as groups appear (before their accumulators are allocated). 2^24 cells.
pub const max_aggregate_cells: usize = 1 << 24;

/// Most output cells (`rows x melted columns`) one `unpivot` may produce. The
/// melted-column list is spec data and may repeat a column. 2^22 cells.
pub const max_unpivot_cells: usize = 1 << 22;

/// Most cells (`distinct row keys x distinct col keys`) one `pivot` may produce.
/// The matrix is dense and BOTH key counts come from the data, so a few
/// thousand rows with all-distinct keys are millions of cells (and `a.print`
/// calls); one more than this is `error.TooLarge`. 2^22 cells.
pub const max_pivot_cells: usize = 1 << 22;

/// Most CELLS (output rows x output columns) one `join` may emit
/// (inner/left/right/full). Rows sharing a key fan out into left x right
/// pairs, so two inputs of a few thousand rows on a low-cardinality key are
/// millions of output rows, and each is a `Value` per column; the count is
/// taken BEFORE anything is emitted and above this it is `error.TooLarge`.
/// 2^24 cells (512 MiB of `Value`s).
pub const max_join_cells: usize = 1 << 24;

/// Most element visits (`(rows - window + 1) * window`) one `rolling` call may
/// do: 2^30, a few seconds. A window of about half the series is quadratic.
/// Above it `error.TooLarge`.
pub const max_rolling_work: usize = 1 << 30;

// ── map ─────────────────────────────────────────────────────────────────────

pub const Operand = union(enum) {
    col: []const u8,
    num: f64,
};

/// `abs` and `sqrt` are unary: they read `lhs` and ignore `rhs`.
pub const BinOp = enum { add, sub, mul, div, min, max, abs, sqrt };

/// What `map` writes when an operand is missing (null or non-numeric) or the
/// result is undefined (`div` by zero, `sqrt` of a negative number).
pub const OnMissing = enum {
    /// A missing operand reads as 0 and an undefined result is 0 — the
    /// historical behaviour, kept as the default.
    zero,
    /// Null in, null out; an undefined result is null (SQL's rule, and
    /// pandas' NaN propagation).
    null,
};

/// `out = lhs op rhs`, appended as a float column. `min`/`max` follow IEEE `@min`/`@max`
/// (a NaN operand loses to a number).
pub const MapSpec = struct {
    /// Name of the appended column.
    out: []const u8,
    out_type: ColumnType = .float,
    lhs: Operand,
    op: BinOp,
    /// Ignored by the unary ops (`abs`, `sqrt`).
    rhs: Operand = .{ .num = 0 },
    on_missing: OnMissing = .zero,
};

// ── aggregate ───────────────────────────────────────────────────────────────

/// `sum`/`mean`/`count` count every row of the group (a null or non-numeric
/// cell adds 0 to `sum` and 1 to `count` — historical behaviour, unlike
/// pandas' skip-NA). The statistics added 2026-10-04 skip MISSING values
/// (null, non-numeric, NaN), as pandas does by default. Everything numeric here goes
/// through f64 except `sum_exact`: an int `sum` is a float and loses past 2^53, where
/// pandas and polars keep int64:
///   `std`/`var` — sample (n−1, pandas' default `ddof=1`), null below 2 values;
///   `median`, `quantile` (`AggCol.q`) — linear interpolation between order
///     statistics (numpy/pandas default, Hyndman–Fan type 7), null when empty;
///   `nunique` — distinct non-missing values of any kind, text included
///     (pandas `nunique()`, `dropna=True`); int 1 and float 1.0 are one value, text
///     "1" another, and a `.decimal` equal to them is the same value too;
///   `sum_exact` — i128 sum at `decimal_scale`, output `.decimal`:
///     `.decimal` cells exactly, `.int` cells exactly (× scale), `.float` cells
///     through `Value.cast(.decimal)`; null if the total overflows i128.
/// Added 2026-11-02, all skipping missing values whatever `skip_na` says (except
/// `size`, which is the row count):
///   `size` rows of the group; `prod` product (1 when empty); `any`/`all` truth of
///   non-missing cells (a number is true when non-zero, text when non-empty);
///   `sem` standard error (`std`/sqrt(n)); `skew`/`kurt` pandas' bias-corrected
///   sample skewness (null below 3 values) and excess kurtosis (below 4);
///   `mode` the most frequent value, a tie going to the smallest; `arg_min`/`arg_max`
///   the row position (in the input) of the first smallest/largest value.
pub const AggFn = enum { sum, mean, count, min, max, first, last, std, @"var", median, quantile, nunique, sum_exact, size, prod, any, all, sem, skew, kurt, mode, arg_min, arg_max };

pub const AggCol = struct {
    src: []const u8,
    out: []const u8,
    func: AggFn,
    /// Probability for `func = .quantile`, in [0, 1]; anything else (or NaN)
    /// gives null. Ignored by the other functions.
    q: f64 = 0.5,
    /// `quantile`'s method between two order statistics (pandas and polars
    /// `interpolation`).
    interpolation: Interpolation = .linear,
    /// Delta degrees of freedom of `std`, `var`, `sem`: the divisor is `n - ddof`
    /// (pandas' and polars' `ddof`, default 1); null once it is not positive.
    ddof: u32 = 1,
    /// `sum` and `prod` of fewer than this many non-missing values are null (pandas'
    /// `min_count`; 0 = never).
    min_count: usize = 0,
};

/// numpy's, pandas' and polars' quantile interpolation between the order statistics
/// around `h = (n - 1) q`.
pub const Interpolation = enum { linear, lower, higher, midpoint, nearest };

pub const FxConvert = struct {
    /// Column holding the per-row conversion rate (null/absent → 1.0). The
    /// numeric aggregate value is multiplied by this before accumulation.
    rate_col: []const u8,
};

pub const AggregateSpec = struct {
    group_by: []const []const u8,
    aggs: []const AggCol,
    fx: ?FxConvert = null,
    /// pandas' `skipna=True` for the functions that historically count every
    /// row: `sum`/`mean` over non-missing numbers (`mean` null when none),
    /// `count` of non-missing cells, `min`/`max`/`first`/`last` of non-missing
    /// cells. false keeps the historical behaviour documented on `AggFn`.
    skip_na: bool = false,
    /// Sort the output by the group columns ascending, missing last (pandas'
    /// `groupby(sort=True)`). false keeps first-seen order.
    sort_groups: bool = false,
    /// Drop groups with a missing key (pandas' `dropna=True`). false keeps them
    /// as a group of their own; null and NaN are one key either way.
    drop_missing_keys: bool = false,
};

// ── sort ────────────────────────────────────────────────────────────────────

pub const SortDir = enum { asc, desc };
pub const SortKey = struct { key: []const u8, dir: SortDir = .asc };
pub const SortSpec = struct {
    key: []const u8,
    dir: SortDir = .asc,
    /// Additional tie-break keys, applied in order after `key`/`dir`.
    then_by: []const SortKey = &.{},
    /// `.auto`: `Value.order` (null lowest, NaN the highest number), reversed by
    /// `.desc` (historical). `.first`/`.last`: every missing cell (null, NaN) goes
    /// there whatever the direction (pandas' `na_position`).
    missing: enum { auto, first, last } = .auto,
};

// ── pivot / unpivot ─────────────────────────────────────────────────────────

pub const PivotSpec = struct {
    row_key: []const u8,
    col_key: []const u8,
    value_col: []const u8,
    agg: AggFn = .sum,
    /// Probability when `agg = .quantile`.
    q: f64 = 0.5,
    /// `AggregateSpec.skip_na` for the cells (pandas' `pivot_table` skips).
    skip_na: bool = false,
    /// Written into a cell no row fell into; null leaves it null.
    fill_value: ?f64 = null,
};

pub const UnpivotSpec = struct {
    /// Columns copied as-is (row identity) to every output row.
    id_cols: []const []const u8,
    /// Wide columns to melt into (key,value) row pairs. Empty (default) melts
    /// every column NOT in `id_cols`.
    value_cols: []const []const u8 = &.{},
    out_key: []const u8 = "variable",
    out_value: []const u8 = "value",
};

// ── filter / dropna ─────────────────────────────────────────────────────────

pub const CmpOp = enum { eq, ne, lt, le, gt, ge, is_null, not_null };

/// `col op value`. A MISSING cell (null, or a NaN float) satisfies only
/// `is_null` — every comparison against it is false, `ne` included (SQL's
/// three-valued rule: an absent value is not "different", it is unknown).
/// A comparison needs comparable kinds: number with number (int/float/decimal
/// by value, two decimals exactly), text with text (bytewise, so ISO dates
/// order correctly), bool with bool. A cell of another kind than `value`
/// matches nothing — a numeric cell never equals a text literal.
pub const Predicate = struct {
    col: []const u8,
    op: CmpOp,
    /// Ignored by `is_null` / `not_null`.
    value: Value = .null,
};

pub const FilterSpec = struct {
    where: []const Predicate,
    /// `.all`: a row is kept when every predicate holds (AND; an empty
    /// `where` keeps every row). `.any`: when at least one holds (OR; an
    /// empty `where` keeps none).
    mode: enum { all, any } = .all,
};

/// Missing = null, or a NaN float (pandas' `isna`).
pub const DropNaSpec = struct {
    /// Columns to inspect; empty = every column.
    subset: []const []const u8 = &.{},
    /// `.any`: drop a row with any missing cell in `subset`; `.all`: only a
    /// row whose `subset` cells are all missing.
    how: enum { any, all } = .any,
    /// Keep a row with at least this many non-missing cells in `subset`, whatever
    /// `how` says (pandas' `thresh`). null: `how` decides.
    thresh: ?usize = null,
};

// ── cumsum / rolling ────────────────────────────────────────────────────────

pub const ColSpec = struct { value_col: []const u8, out: []const u8 };
pub const RollFn = enum { mean, sum, std_sample, min, max };
pub const RollSpec = struct {
    value_col: []const u8,
    out: []const u8,
    window: usize,
    func: RollFn = .mean,
};

// ── join / distinct ─────────────────────────────────────────────────────────

pub const JoinHow = enum { inner, left, right, full, semi, anti, cross };
pub const JoinSpec = struct {
    /// Single-column join key. Ignored when `keys` is non-empty (kept optional,
    /// rather than required, purely so `keys`-only callers don't need to set it).
    on: []const u8 = "",
    /// Composite join key (same column names assumed on both sides). When
    /// non-empty, overrides `on`.
    keys: []const []const u8 = &.{},
    how: JoinHow = .inner,
    /// The right side's key column names, when they differ from the left's
    /// (pandas' `left_on`/`right_on`): same count as the left's. Like `on`, they
    /// are dropped from the output.
    right_on: []const []const u8 = &.{},
    /// Appended to a right column whose name the left side also has. null keeps
    /// both under the one name (historical; `columnIndex` finds only the left).
    suffix: ?[]const u8 = null,
    /// `.match`: a missing key (null, NaN) equals a missing key (historical, and
    /// pandas). `.no_match`: it equals nothing (SQL, and polars' default).
    null_keys: enum { match, no_match } = .match,
    /// Fill the key columns of a right-only row from the right side (`right`,
    /// `full`), as pandas does. false leaves them null (historical).
    coalesce_keys: bool = false,
};

pub const DistinctSpec = struct {
    /// Columns forming the row-identity composite key; empty = every column.
    keys: []const []const u8,
    /// Which occurrence's *values* win on a duplicate key. Either way the
    /// output keeps one row per key, in first-seen key order. `.none` keeps
    /// only the keys that occur once (pandas' `keep=False`).
    keep: enum { first, last, none } = .first,
};

// ── columns ─────────────────────────────────────────────────────────────────

/// `select`/`rename`'s error set: a result with two columns of the same name is
/// refused, since `Frame.columnIndex` would only ever find the first.
pub const ColumnsError = Error || error{DuplicateColumn};

pub const Rename = struct { from: []const u8, to: []const u8 };

pub const FillNaSpec = struct {
    /// Columns to fill; empty = every column.
    subset: []const []const u8 = &.{},
    /// Written into every missing cell as is — the column's declared type is
    /// not changed, so fill a `.float` column with a `.float`.
    value: Value,
};
