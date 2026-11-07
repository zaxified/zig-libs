// SPDX-License-Identifier: MIT
//! dataframe — a columnar table (`Frame`) and the verbs of a dataframe library over it,
//! graded against pandas (the reference) and polars (the fastest).
//!
//! A `Frame` holds one typed array per column (`ColumnData`: int, float, bool, decimal,
//! text, or `boxed` cells of mixed kinds) and a validity bitmap where a column has
//! nulls. Rows have no labels: polars' model, not pandas' index. Every verb is
//! `verb(allocator, Frame, Spec) -> Frame`: nothing is mutated, untouched columns are
//! shared with the input, and the allocator is an arena the caller frees at once.
//!
//! Memory: a result borrows from its input and from the spec's names, so both must stay
//! alive as long as the result. A frame's arrays may be longer than its `len` behind
//! the slices' capacity, so a general-purpose allocator would leak them: pass an arena,
//! over `big_block_allocator` for big tables.
//!
//! Provenance: original work of the zig-libs authors (MIT). The storage comes from
//! `dataset`'s `Frame` and the verbs from `tabular`'s `frame` namespace, same authors;
//! their semantics follow pandas and polars, read as documentation only.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Columnar dataframe (`Frame`): typed columns, validity bitmaps and pandas/polars verbs — aggregate, join, pivot, sort, melt, filter.",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "pandas 3.1 (reference) and polars 2.1 (fastest) eager DataFrame API",
    .deps = .{},
};

// ── the cell model ──────────────────────────────────────────────────────────

const value = @import("value.zig");
pub const ColumnType = value.ColumnType;
pub const Column = value.Column;
pub const Value = value.Value;
pub const decimal_scale = value.decimal_scale;
pub const timestamp_units_per_second = value.timestamp_units_per_second;
pub const Date = value.Date;
pub const parseIsoDate = value.parseIsoDate;
pub const parseIsoTimestamp = value.parseIsoTimestamp;
pub const formatIsoTimestamp = value.formatIsoTimestamp;
pub const max_iso_timestamp_len = value.max_iso_timestamp_len;

// ── storage ─────────────────────────────────────────────────────────────────

const frame = @import("frame.zig");
pub const Frame = frame.Frame;
pub const FrameBuilder = frame.FrameBuilder;
pub const FrameBuilderError = frame.FrameBuilderError;
pub const ColumnData = frame.ColumnData;
pub const TypedColumn = frame.TypedColumn;
pub const TextColumn = frame.TextColumn;
pub const Series = frame.Series;
pub const columnFromCells = frame.columnFromCells;
pub const big_block_allocator = frame.big_block_allocator;
pub const max_row_hint = frame.max_row_hint;

// ── verbs and their specs ───────────────────────────────────────────────────

const spec = @import("spec.zig");
pub const Error = spec.Error;
pub const ColumnsError = spec.ColumnsError;
pub const max_aggregate_cells = spec.max_aggregate_cells;
pub const max_unpivot_cells = spec.max_unpivot_cells;
pub const max_pivot_cells = spec.max_pivot_cells;
pub const max_join_cells = spec.max_join_cells;
pub const max_rolling_work = spec.max_rolling_work;
pub const Operand = spec.Operand;
pub const BinOp = spec.BinOp;
pub const OnMissing = spec.OnMissing;
pub const MapSpec = spec.MapSpec;
pub const AggFn = spec.AggFn;
pub const AggCol = spec.AggCol;
pub const FxConvert = spec.FxConvert;
pub const AggregateSpec = spec.AggregateSpec;
pub const SortDir = spec.SortDir;
pub const SortKey = spec.SortKey;
pub const SortSpec = spec.SortSpec;
pub const PivotSpec = spec.PivotSpec;
pub const UnpivotSpec = spec.UnpivotSpec;
pub const CmpOp = spec.CmpOp;
pub const Predicate = spec.Predicate;
pub const FilterSpec = spec.FilterSpec;
pub const DropNaSpec = spec.DropNaSpec;
pub const FillNaSpec = spec.FillNaSpec;
pub const Rename = spec.Rename;
pub const ColSpec = spec.ColSpec;
pub const RollFn = spec.RollFn;
pub const RollSpec = spec.RollSpec;
pub const JoinHow = spec.JoinHow;
pub const JoinSpec = spec.JoinSpec;
pub const DistinctSpec = spec.DistinctSpec;

const verbs = @import("verbs.zig");
pub const map = verbs.map;
pub const cumsum = verbs.cumsum;
pub const rolling = verbs.rolling;
pub const filter = verbs.filter;
pub const distinct = verbs.distinct;
pub const aggregate = verbs.aggregate;
pub const unpivot = verbs.unpivot;
pub const join = verbs.join;
pub const sort = verbs.sort;
pub const dropna = verbs.dropna;
pub const fillna = verbs.fillna;
pub const pivot = verbs.pivot;
pub const select = verbs.select;
pub const drop = verbs.drop;
pub const rename = verbs.rename;

const expr = @import("expr.zig");
pub const Expr = expr.Expr;
pub const Unary = expr.Unary;
pub const Binary = expr.Binary;
pub const Assign = expr.Assign;
pub const CastSpec = expr.CastSpec;
pub const ExprError = expr.ExprError;
pub const CastError = expr.CastError;
pub const max_expr_depth = expr.max_depth;
pub const max_expr_nodes = expr.max_nodes;
pub const castValue = expr.castValue;
pub const mutate = expr.mutate;
pub const where = expr.where;
pub const cast = expr.cast;

const win = @import("window.zig");
pub const WindowSpec = win.WindowSpec;
pub const WindowOp = win.WindowOp;
pub const WindowError = win.WindowError;
pub const WinFn = win.WinFn;
pub const Rolling = win.Rolling;
pub const RollingTime = win.RollingTime;
pub const Ewm = win.Ewm;
pub const RankMethod = win.RankMethod;
pub const max_window_work = win.max_window_work;
pub const window = win.window;

const more = @import("more.zig");
pub const PageSpec = more.PageSpec;
pub const TopNSpec = more.TopNSpec;
pub const TopSpec = more.TopSpec;
pub const SampleSpec = more.SampleSpec;
pub const Partition = more.Partition;
pub const ValueCountsSpec = more.ValueCountsSpec;
pub const ClipSpec = more.ClipSpec;
pub const ReplacePair = more.ReplacePair;
pub const ReplaceSpec = more.ReplaceSpec;
pub const CutSpec = more.CutSpec;
pub const CutError = more.CutError;
pub const AsofSpec = more.AsofSpec;
pub const AsofError = more.AsofError;
pub const page = more.page;
pub const tail = more.tail;
pub const topN = more.topN;
pub const nlargest = more.nlargest;
pub const sample = more.sample;
pub const concatByName = more.concatByName;
pub const partitionBy = more.partitionBy;
pub const valueCounts = more.valueCounts;
pub const describe = more.describe;
pub const clip = more.clip;
pub const replace = more.replace;
pub const cut = more.cut;
pub const joinAsof = more.joinAsof;
pub const Freq = more.Freq;
pub const ResampleAgg = more.ResampleAgg;
pub const ResampleSpec = more.ResampleSpec;
pub const resample = more.resample;
pub const reduce = more.reduce;

// Dark-tests aggregator: a bare `pub const` re-export does NOT pull a
// submodule's tests into the test binary — this reference does.
test {
    _ = value;
    _ = frame;
    _ = spec;
    _ = verbs;
    _ = expr;
    _ = win;
    _ = more;
    _ = @import("keys.zig");
    _ = @import("core.zig");
    _ = @import("value_test.zig");
    _ = @import("storage_test.zig");
    _ = @import("verbs_test.zig");
    _ = @import("oracle_test.zig");
    _ = @import("expr_window_test.zig");
    _ = @import("more_test.zig");
    _ = @import("review_test.zig");
}
