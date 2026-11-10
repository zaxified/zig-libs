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
    .deps = .{ "datefmt", "csvstream", "regex", "tz", "unitext" },
};

// ── the cell model ──────────────────────────────────────────────────────────

const value = @import("value.zig");
pub const ColumnType = value.ColumnType;
pub const Column = value.Column;
pub const Value = value.Value;
pub const ListView = value.ListView;
pub const RecordView = value.RecordView;
pub const max_nesting_depth = value.max_nesting_depth;
pub const decimal_scale = value.decimal_scale;
pub const timestamp_units_per_second = value.timestamp_units_per_second;
pub const Date = value.Date;
pub const parseIsoDate = value.parseIsoDate;
pub const parseIsoTimestamp = value.parseIsoTimestamp;
pub const formatIsoTimestamp = value.formatIsoTimestamp;
pub const max_iso_timestamp_len = value.max_iso_timestamp_len;
pub const parseDurationCell = value.parseDurationCell;
pub const formatIsoDuration = value.formatIsoDuration;
pub const formatDuration = value.formatDuration;
pub const max_duration_len = value.max_duration_len;

// ── storage ─────────────────────────────────────────────────────────────────

const frame = @import("frame.zig");
pub const Frame = frame.Frame;
pub const FrameBuilder = frame.FrameBuilder;
pub const FrameBuilderError = frame.FrameBuilderError;
pub const ColumnData = frame.ColumnData;
pub const TypedColumn = frame.TypedColumn;
pub const TextColumn = frame.TextColumn;
pub const CatColumn = frame.CatColumn;
pub const ListColumn = frame.ListColumn;
pub const StructColumn = frame.StructColumn;
pub const Series = frame.Series;
pub const columnFromCells = frame.columnFromCells;
pub const big_block_allocator = frame.big_block_allocator;
pub const huge_page_allocator = frame.huge_page_allocator;
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
pub const MissingPlace = spec.MissingPlace;
pub const PivotSpec = spec.PivotSpec;
pub const UnpivotSpec = spec.UnpivotSpec;
pub const CmpOp = spec.CmpOp;
pub const Predicate = spec.Predicate;
pub const FilterSpec = spec.FilterSpec;
pub const DropNaSpec = spec.DropNaSpec;
pub const FillNaSpec = spec.FillNaSpec;
pub const ColumnFill = spec.ColumnFill;
pub const Rename = spec.Rename;
pub const ColSpec = spec.ColSpec;
pub const RollFn = spec.RollFn;
pub const RollSpec = spec.RollSpec;
pub const JoinHow = spec.JoinHow;
pub const JoinSpec = spec.JoinSpec;
pub const JoinValidate = spec.JoinValidate;
pub const JoinError = spec.JoinError;
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
pub const RoundMode = expr.RoundMode;
pub const PadSide = expr.PadSide;
pub const StripSide = expr.StripSide;
/// Unicode normalization form of `Expr.normalize`: `.nfc`, `.nfd`, `.nfkc`, `.nfkd`.
pub const NormalForm = expr.NormalForm;
pub const DtPart = expr.DtPart;
pub const ParseTo = expr.ParseTo;
pub const Duration = @import("dtfn.zig").Duration;
pub const parseDuration = @import("dtfn.zig").parseDuration;
pub const translateFormat = @import("dtfn.zig").translateFormat;
pub const RoundTo = @import("dtfn.zig").RoundTo;
const corr_mod = @import("corr.zig");
pub const CorrError = corr_mod.CorrError;
pub const CorrMethod = corr_mod.CorrMethod;
pub const CorrSpec = corr_mod.CorrSpec;
pub const CovSpec = corr_mod.CovSpec;
pub const max_corr_work = corr_mod.max_corr_work;
pub const corr = corr_mod.corr;
pub const CorrWithError = corr_mod.CorrWithError;
pub const CorrWithSpec = corr_mod.CorrWithSpec;
pub const corrWith = corr_mod.corrWith;
pub const cov = corr_mod.cov;
pub const TzPolicy = @import("dtfn.zig").TzPolicy;
pub const max_text_result = @import("exprfn.zig").max_text_result;
pub const max_eval_bytes = expr.max_eval_bytes;
pub const max_eval_work = expr.max_eval_work;
pub const max_expr_depth = expr.max_depth;
pub const max_expr_nodes = expr.max_nodes;
pub const castValue = expr.castValue;
pub const mutate = expr.mutate;
pub const where = expr.where;
pub const cast = expr.cast;
pub const ListOp = expr.ListOp;
pub const SetOp = expr.SetOp;
pub const StructOp = expr.StructOp;
pub const NameMap = expr.NameMap;
pub const max_list_result = @import("listfn.zig").max_list_result;
pub const NamedExpr = expr.NamedExpr;

const nestverbs = @import("nestverbs.zig");
pub const NestError = nestverbs.NestError;
pub const UnnestSpec = nestverbs.UnnestSpec;
pub const max_explode_cells = nestverbs.max_explode_cells;
pub const max_explode_bytes = nestverbs.max_explode_bytes;
pub const max_unnest_fields = nestverbs.max_unnest_fields;
pub const explode = nestverbs.explode;
const catfn = @import("catfn.zig");
pub const CatError = catfn.CatError;
pub const CatRename = catfn.CatRename;
pub const EnumDecl = catfn.EnumDecl;
pub const catCategories = catfn.categories;
pub const catIsOrdered = catfn.isOrdered;
pub const catCodes = catfn.codes;
/// polars `to_physical()` of a categorical: the same as `catCodes`.
pub const catToPhysical = catfn.codes;
pub const catSetOrdered = catfn.setOrdered;
pub const catAddCategories = catfn.addCategories;
pub const catRemoveCategories = catfn.removeCategories;
pub const catRemoveUnusedCategories = catfn.removeUnusedCategories;
pub const catSetCategories = catfn.setCategories;
pub const catReorderCategories = catfn.reorderCategories;
pub const catRenameCategories = catfn.renameCategories;
pub const explodeAll = nestverbs.explodeAll;
pub const flattenList = nestverbs.flattenList;
pub const structDtypes = nestverbs.structDtypes;
pub const unnest = nestverbs.unnest;

const win = @import("window.zig");
pub const WindowSpec = win.WindowSpec;
pub const WindowOp = win.WindowOp;
pub const WindowError = win.WindowError;
pub const WinFn = win.WinFn;
pub const Rolling = win.Rolling;
pub const RollingTime = win.RollingTime;
pub const Ewm = win.Ewm;
pub const EwmBy = win.EwmBy;
pub const EwmPair = win.EwmPair;
pub const WindowClosed = win.Closed;
pub const WinType = win.WinType;
pub const windowWeights = win.windowWeights;
pub const Mapping = win.Mapping;
pub const RankMethod = win.RankMethod;
pub const RankNa = win.RankNa;
pub const max_implode_window_cells = win.max_implode_window_cells;
pub const RollingRank = win.RollingRank;
pub const RollingPair = win.RollingPair;
pub const max_window_work = win.max_window_work;
pub const window = win.window;

// ── callback verbs (survey rows 21, 25) ─────────────────────────────────────

const callback = @import("callback.zig");
/// The errors of every callback verb besides the callback's own.
pub const CallbackError = callback.CallbackError;
/// `CallbackError` merged with the error set `func` returns.
pub const CallbackErrorOf = callback.ErrorOf;
pub const OutColumn = callback.OutColumn;
pub const MapElementsSpec = callback.MapElementsSpec;
pub const MapRowsSpec = callback.MapRowsSpec;
pub const sortByKey = callback.sortByKey;
pub const Row = callback.Row;
pub const RollingMapSpec = callback.RollingMapSpec;
pub const GroupsSpec = callback.GroupsSpec;
pub const max_rolling_map_work = callback.max_rolling_map_work;
/// pandas `Series.map`, polars `map_elements`.
pub const mapElements = callback.mapElements;
/// pandas `apply(axis=1)`, polars `map_rows`.
pub const mapRows = callback.mapRows;
/// pandas `rolling().apply`, polars `rolling_map`.
pub const rollingMap = callback.rollingMap;
/// pandas `groupby().apply`, polars `map_groups`.
pub const mapGroups = callback.mapGroups;
/// pandas `groupby().filter(f)`.
pub const filterGroups = callback.filterGroups;

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
pub const DescribeSpec = more.DescribeSpec;
pub const DescribeError = more.DescribeError;
pub const describeWith = more.describeWith;
pub const binEdges = more.binEdges;
pub const QuantilesSpec = more.QuantilesSpec;
pub const QuantilesError = more.QuantilesError;
pub const quantiles = more.quantiles;
pub const OhlcSpec = more.OhlcSpec;
pub const ohlc = more.ohlc;
pub const ohlcAggs = more.ohlcAggs;
pub const clip = more.clip;
pub const replace = more.replace;
pub const cut = more.cut;
pub const BinError = more.BinError;
pub const BinPoints = more.BinPoints;
pub const BinFractions = more.BinFractions;
pub const BinIntervalsSpec = more.BinIntervalsSpec;
pub const BinQuantilesSpec = more.BinQuantilesSpec;
pub const BinRanksSpec = more.BinRanksSpec;
pub const max_bins = more.max_bins;
pub const binIntervals = more.binIntervals;
pub const binQuantiles = more.binQuantiles;
pub const binRanks = more.binRanks;
pub const joinAsof = more.joinAsof;
pub const Freq = more.Freq;
pub const ResampleAgg = more.ResampleAgg;
pub const ResampleSpec = more.ResampleSpec;
pub const resample = more.resample;
pub const reduce = more.reduce;

// ── structure (survey rows 2, 4, 10, 12, 13, 20, 43, 58, 68, 82) ────────────

const structure = @import("structure.zig");
pub const StructureError = structure.StructureError;
pub const Popped = structure.Popped;
pub const AffixSpec = structure.AffixSpec;
pub const Selector = structure.Selector;
pub const max_selector_depth = structure.max_selector_depth;
pub const max_selector_visits = structure.max_selector_visits;
pub const TransposeSpec = structure.TransposeSpec;
pub const ConcatHow = structure.ConcatHow;
pub const clone = structure.clone;
pub const clear = structure.clear;
pub const take = structure.take;
pub const gatherEvery = structure.gatherEvery;
pub const reverse = structure.reverse;
pub const insertColumn = structure.insertColumn;
pub const hstack = structure.hstack;
pub const replaceColumn = structure.replaceColumn;
pub const popColumn = structure.popColumn;
pub const addAffix = structure.addAffix;
pub const selectColumns = structure.selectColumns;
pub const selectBy = structure.selectBy;
pub const nullCount = structure.nullCount;
pub const hasNulls = structure.hasNulls;
pub const columnBytes = structure.columnBytes;
pub const estimatedSize = structure.estimatedSize;
pub const info = structure.info;
pub const equals = structure.equals;
pub const transpose = structure.transpose;
pub const max_transpose_width = structure.max_transpose_width;
pub const concat = structure.concat;

// ── analysis (survey rows 31, 45, 50, 61, 62, 85) ───────────────────────────

const analysis = @import("analysis.zig");
pub const AnalysisError = analysis.AnalysisError;
pub const Interpolation = spec.Interpolation;
pub const DupMask = analysis.DupMask;
pub const DupMaskSpec = analysis.DupMaskSpec;
pub const HorizontalFn = analysis.HorizontalFn;
pub const HorizontalSpec = analysis.HorizontalSpec;
pub const FillStrategy = analysis.FillStrategy;
pub const FillNullSpec = analysis.FillNullSpec;
pub const ReplaceStrictSpec = analysis.ReplaceStrictSpec;
pub const SearchSide = analysis.SearchSide;
pub const FactorizeSpec = analysis.FactorizeSpec;
pub const Factorized = analysis.Factorized;
pub const TopKSpec = analysis.TopKSpec;
pub const QcutSpec = analysis.QcutSpec;
pub const duplicateMask = analysis.duplicateMask;
pub const horizontal = analysis.horizontal;
pub const fillNull = analysis.fillNull;
pub const replaceStrict = analysis.replaceStrict;
pub const argSort = analysis.argSort;
pub const isSorted = analysis.isSorted;
pub const searchSorted = analysis.searchSorted;
pub const indexOf = analysis.indexOf;
pub const factorize = analysis.factorize;
pub const topK = analysis.topK;
pub const qcut = analysis.qcut;
pub const qcutEdges = analysis.qcutEdges;

// ── wave 4 (survey rows 5, 8, 20, 25, 38, 53, 55, 62, 66, 69, 80, 87-89) ─────

const reshape = @import("reshape.zig");
pub const ReshapeError = reshape.ReshapeError;
pub const GroupFilterSpec = reshape.GroupFilterSpec;
pub const NgroupSpec = reshape.NgroupSpec;
pub const JoinPredicate = reshape.JoinPredicate;
pub const max_join_where_pairs = reshape.max_join_where_pairs;
pub const MergeOrderedSpec = reshape.MergeOrderedSpec;
pub const PivotManySpec = reshape.PivotManySpec;
pub const DummiesSpec = reshape.DummiesSpec;
pub const Repeat = reshape.Repeat;
pub const ScatterSpec = reshape.ScatterSpec;
pub const MatchSchemaSpec = reshape.MatchSchemaSpec;
pub const Matrix = reshape.Matrix;
pub const BetweenTimeSpec = reshape.BetweenTimeSpec;
pub const groupFilter = reshape.groupFilter;
pub const ngroup = reshape.ngroup;
pub const joinWhere = reshape.joinWhere;
pub const mergeOrdered = reshape.mergeOrdered;
pub const mergeSorted = reshape.mergeSorted;
pub const pivotMany = reshape.pivotMany;
pub const PivotKeysSpec = reshape.PivotKeysSpec;
pub const pivotKeys = reshape.pivotKeys;
pub const dummies = reshape.dummies;
pub const combineFirst = reshape.combineFirst;
pub const update = reshape.update;
pub const repeatRows = reshape.repeatRows;
pub const scatter = reshape.scatter;
pub const dropNans = reshape.dropNans;
pub const matchToSchema = reshape.matchToSchema;
pub const toFloatMatrix = reshape.toFloatMatrix;
pub const hashRows = reshape.hashRows;
pub const betweenTime = reshape.betweenTime;
pub const UnstackHow = reshape.UnstackHow;
pub const UnstackSpec = reshape.UnstackSpec;
pub const unstack = reshape.unstack;
pub const WideToLongSpec = reshape.WideToLongSpec;
pub const WideToLongError = reshape.WideToLongError;
pub const wideToLong = reshape.wideToLong;

const seriesfn = @import("seriesfn.zig");
pub const Peak = seriesfn.Peak;
pub const rle = seriesfn.rle;
pub const rleId = seriesfn.rleId;
pub const peaks = seriesfn.peaks;
pub const autocorr = seriesfn.autocorr;
pub const entropy = seriesfn.entropy;
pub const nanExtreme = seriesfn.nanExtreme;
pub const extremeBy = seriesfn.extremeBy;
pub const nUnique = seriesfn.nUnique;
pub const firstValid = seriesfn.firstValid;
pub const lastValid = seriesfn.lastValid;
pub const argTrue = seriesfn.argTrue;
pub const argUnique = seriesfn.argUnique;
pub const asofIndex = seriesfn.asofIndex;
pub const extendConstant = seriesfn.extendConstant;

const frameops = @import("frameops.zig");
pub const FrameOpsError = frameops.FrameOpsError;
pub const ArithSpec = frameops.ArithSpec;
pub const ArithScalarSpec = frameops.ArithScalarSpec;
pub const InterpolateSpec = frameops.InterpolateSpec;
pub const DynamicSpec = frameops.DynamicSpec;
pub const DynamicClosed = frameops.DynamicClosed;
pub const DynamicLabel = frameops.DynamicLabel;
pub const StartBy = frameops.StartBy;
pub const Origin = frameops.Origin;
pub const UpsampleSpec = frameops.UpsampleSpec;
pub const max_upsample_rows = frameops.max_upsample_rows;
pub const arith = frameops.arith;
pub const arithScalar = frameops.arithScalar;
pub const compare = frameops.compare;
pub const dot = frameops.dot;
pub const interpolate = frameops.interpolate;
pub const groupByDynamic = frameops.groupByDynamic;
pub const upsample = frameops.upsample;

// ── input and output (survey rows 73, 74, 77) ────────────────────────────────

const csvio = @import("csvio.zig");
pub const CsvReadError = csvio.CsvReadError;
pub const CsvReadOptions = csvio.CsvReadOptions;
pub const CsvWriteOptions = csvio.CsvWriteOptions;
pub const CsvWriteError = csvio.CsvWriteError;
pub const CsvQuote = csvio.CsvQuote;
pub const ColumnNulls = csvio.ColumnNulls;
pub const BadLines = csvio.BadLines;
pub const TypeOverride = csvio.TypeOverride;
pub const pandas_na_values = csvio.pandas_na_values;
pub const polars_na_values = csvio.polars_na_values;
pub const readCsv = csvio.readCsv;
pub const readCsvReader = csvio.readCsvReader;
pub const writeCsv = csvio.writeCsv;

const csvchunk = @import("csvchunk.zig");
pub const CsvChunkReader = csvchunk.CsvChunkReader;
pub const ChunkOptions = csvchunk.ChunkOptions;
pub const ChunkSchema = csvchunk.ChunkSchema;
pub const ChunkError = csvchunk.ChunkError;
const ndjsonchunk = @import("ndjsonchunk.zig");
pub const NdjsonChunkReader = ndjsonchunk.NdjsonChunkReader;
pub const NdjsonChunkError = ndjsonchunk.NdjsonChunkError;

const jsonio = @import("jsonio.zig");
pub const JsonOrient = jsonio.JsonOrient;
pub const writeJson = jsonio.writeJson;
pub const writeJsonOpts = jsonio.writeJsonOpts;
pub const JsonWriteOptions = jsonio.JsonWriteOptions;
pub const JsonWriteError = jsonio.JsonWriteError;
pub const JsonDateFormat = jsonio.JsonDateFormat;
pub const JsonDateUnit = jsonio.JsonDateUnit;
pub const writeNdjson = jsonio.writeNdjson;

const jsonread = @import("jsonread.zig");
pub const JsonReadOrient = jsonread.JsonReadOrient;
pub const JsonReadOptions = jsonread.JsonReadOptions;
pub const JsonReadError = jsonread.JsonReadError;
pub const JsonDuplicateKeys = jsonread.DuplicateKeys;
pub const readJson = jsonread.readJson;
pub const readNdjson = jsonread.readNdjson;
pub const JsonDecodeSpec = jsonread.JsonDecodeSpec;
pub const jsonDecode = jsonread.jsonDecode;

const render = @import("render.zig");
pub const FormatOptions = render.FormatOptions;
pub const MarkdownOptions = render.MarkdownOptions;
pub const RenderError = render.RenderError;
pub const format = render.format;
pub const formatTo = render.formatTo;
pub const toMarkdown = render.toMarkdown;
pub const HtmlOptions = render.HtmlOptions;
pub const toHtml = render.toHtml;
pub const htmlTo = render.htmlTo;
pub const GlimpseOptions = render.GlimpseOptions;
pub const glimpse = render.glimpse;
pub const glimpseTo = render.glimpseTo;
pub const markdownTo = render.markdownTo;

// ── constructors, names, column functions (dataframe S2 wave W3) ──────────────

const ranges = @import("ranges.zig");
pub const RangeError = ranges.RangeError;
pub const max_range_rows = ranges.max_range_rows;
pub const Closed = ranges.Closed;
pub const CalendarSpec = ranges.CalendarSpec;
pub const intRange = ranges.intRange;
pub const intRanges = ranges.intRanges;
pub const linearSpace = ranges.linearSpace;
pub const repeatValue = ranges.repeatValue;
pub const ones = ranges.ones;
pub const zeros = ranges.zeros;
pub const dateRange = ranges.dateRange;
pub const dateRangePeriods = ranges.dateRangePeriods;
pub const datetimeRange = ranges.datetimeRange;
pub const datetimeRangePeriods = ranges.datetimeRangePeriods;
pub const datetimeSpace = ranges.datetimeSpace;
pub const EpochUnit = expr.EpochUnit;

const names = @import("names.zig");
pub const NamesError = names.NamesError;
pub const ReplaceNamesSpec = names.ReplaceNamesSpec;
pub const renameWith = names.renameWith;
pub const renameLower = names.renameLower;
pub const renameUpper = names.renameUpper;
pub const renameReplace = names.renameReplace;

const colfn = @import("colfn.zig");
pub const ColfnError = colfn.ColfnError;
pub const HistSpec = colfn.HistSpec;
pub const max_hist_bins = colfn.max_hist_bins;
pub const FoldSpec = colfn.FoldSpec;
pub const CumFoldSpec = colfn.CumFoldSpec;
pub const AlignSpec = colfn.AlignSpec;
pub const item = colfn.item;
pub const uniqueCounts = colfn.uniqueCounts;
pub const hist = colfn.hist;
pub const foldColumns = colfn.foldColumns;
pub const cumFoldColumns = colfn.cumFoldColumns;
pub const cumSumHorizontal = colfn.cumSumHorizontal;
pub const alignFrames = colfn.alignFrames;

// ── str and dt gaps, durations (dataframe S2 wave W4) ─────────────────────────
const strfn = @import("strfn.zig");
pub const StrError = strfn.StrError;
pub const SplitSpec = strfn.SplitSpec;
pub const StrDummiesSpec = strfn.DummiesSpec;
pub const max_str_columns = strfn.max_str_columns;
pub const splitColumns = strfn.splitColumns;
pub const strGetDummies = strfn.getDummies;
pub const Encoding = expr.Encoding;
pub const DateMode = expr.DateMode;
pub const OffsetKind = @import("dtfn.zig").OffsetKind;
pub const BusinessRoll = @import("dtfn.zig").Roll;

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
    _ = callback;
    _ = @import("step4_test.zig");
    _ = @import("more_test.zig");
    _ = @import("review_test.zig");
    _ = structure;
    _ = analysis;
    _ = @import("exprfn.zig");
    _ = @import("structure_test.zig");
    _ = @import("analysis_test.zig");
    _ = @import("exprfn_test.zig");
    _ = @import("dtfn.zig");
    _ = @import("dtfn_test.zig");
    _ = reshape;
    _ = seriesfn;
    _ = @import("wave4_test.zig");
    _ = frameops;
    _ = @import("frameops_test.zig");
    _ = @import("oracle2_test.zig");
    _ = @import("review2_test.zig");
    _ = @import("textio.zig");
    _ = csvio;
    _ = csvchunk;
    _ = ndjsonchunk;
    _ = @import("s2w9_test.zig");
    _ = @import("s2w9_oracle_test.zig");
    _ = @import("s2w10_test.zig");
    _ = @import("s2w10_oracle_test.zig");
    _ = @import("s2w11_oracle_test.zig");
    _ = @import("s2w11_test.zig");
    _ = @import("s2w11a_oracle_test.zig");
    _ = @import("s2w11a_test.zig");
    _ = @import("s2w11b_test.zig");
    _ = @import("s2w11b_oracle_test.zig");
    _ = @import("dtype.zig");
    _ = jsonio;
    _ = jsonread;
    _ = render;
    _ = @import("io_test.zig");
    _ = @import("io_s2_test.zig");
    _ = @import("d4b_test.zig");
    _ = @import("oracle3_io_test.zig");
    _ = @import("d4a_test.zig");
    _ = @import("d4c_test.zig");
    _ = @import("d4d_test.zig");
    _ = @import("sweep_s1_test.zig");
    _ = @import("sweep_s2b_test.zig");
    _ = @import("sweep_s2_test.zig");
    _ = @import("sweep_w11_test.zig");
    _ = @import("sweep_s2a_test.zig");
    _ = @import("fuzz.zig");
    _ = @import("fuzz_s2_test.zig");
    _ = @import("jsonread_test.zig");
    _ = @import("parity_test.zig");
    _ = @import("nested_test.zig");
    _ = @import("regex_test.zig");
    _ = @import("tz_test.zig");
    _ = @import("corr_test.zig");
    _ = @import("mut_ma_test.zig");
    _ = @import("mut_mb_test.zig");
    _ = @import("mut_m3_test.zig");
    _ = @import("catdur_test.zig");
    _ = @import("listfn.zig");
    _ = nestverbs;
    _ = @import("list_test.zig");
    _ = @import("s2w2_test.zig");
    _ = ranges;
    _ = names;
    _ = colfn;
    _ = @import("s2w3_test.zig");
    _ = @import("s2w3_oracle_test.zig");
    _ = strfn;
    _ = @import("s2w4_test.zig");
    _ = @import("s2w4_oracle_test.zig");
    _ = @import("s2w5_test.zig");
    _ = @import("s2w5_oracle_test.zig");
    _ = @import("s2w8_test.zig");
    _ = @import("s2w8_oracle_test.zig");
    // ── dataframe S2 wave W6 ──
    _ = @import("s2w6_test.zig");
    _ = @import("s2w6_oracle_test.zig");
    _ = catfn;
    // ── dataframe S2 wave W7 ──
    _ = @import("s2w7_carry_test.zig");
    _ = @import("s2w7_test.zig");
    _ = @import("s2w7_oracle_test.zig");
    _ = @import("backlog_low_test.zig");
}
