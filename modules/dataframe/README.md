# dataframe

A columnar table, `Frame`, and the verbs of a dataframe library over it, modeled on the
eager API of pandas (the reference) and polars (the fastest). Each column is one typed
array (`int`, `float`, `bool`, `decimal`, `text`, or `boxed` cells of mixed kinds) with a
validity bitmap where it has nulls. Rows have no labels, as in polars: a row is its
position.

- **Verbs:** `aggregate` (24 functions, fx conversion, exact `sum_exact`), `join` (inner,
  left, right, full, semi, anti, cross), `pivot`, `unpivot` (melt), `sort` (multi-key,
  stable, null placement), `filter`, `distinct`, `dropna`, `fillna`, `select`, `drop`,
  `rename`, `map` (column arithmetic), `cumsum`, `rolling`; expressions (`mutate`,
  `where`, `cast` over an `Expr` tree: arithmetic, comparison, three-valued logic,
  `is_in`, `if_else`, `coalesce`, text ops); `window` per group (shift, diff, pct_change,
  cumulative, rolling by count or time, expanding, ewm, rank, ffill/bfill, interpolate,
  transform); `joinAsof`, `concatByName`, `partitionBy`, `valueCounts`, `describe`,
  `cut`, `binIntervals`/`binQuantiles`/`binRanks`, `unstack`, `wideToLong`, `corrWith`, `clip`, `replace`, `page`/`tail`/`topN`/`nlargest`/`sample`, `resample` (day to
  year), `reduce`.
- **Frame structure:** `clone`, `clear`, `take` (gather, negative from the end),
  `gatherEvery`, `reverse`, `insertColumn`, `hstack`, `replaceColumn`, `popColumn`,
  `addAffix` (prefix/suffix), selectors (`selectBy`/`selectColumns`: by type, name,
  position, prefix, `not`/`any_of`/`all_of`; pandas `select_dtypes`), `nullCount`,
  `hasNulls`, `info`, `estimatedSize`, `equals`, `transpose`, `concat` (vertical,
  vertical_relaxed, diagonal, horizontal).
- **Analysis:** `duplicateMask` (pandas `duplicated`, polars `is_duplicated`/`is_unique`/
  `is_first_distinct`/`is_last_distinct`), `horizontal` (row-wise sum/min/max/mean/all/
  any/count), `fillNull` strategies (forward/backward with `limit`, mean, min, max,
  zero, one), `replaceStrict`, `argSort`, `isSorted`, `searchSorted`, `indexOf`,
  `factorize`, `topK` over several columns (`keep` first/last/all), `qcut`; `aggregate`
  takes `ddof`, quantile `interpolation` and `min_count`, `dropna` takes `thresh`.
- **Element functions in `Expr`:** `round` to decimals (half-even or half-away; exact for
  ints and decimals), `round_sig_figs`, trigonometry and hyperbolics, `cbrt`, `log1p`,
  `expm1`, `log2`, `log_base`, `atan2`, `erf`, `degrees`/`radians`; `is_nan`,
  `is_finite`, `is_infinite`, `fill_nan`, `eq_missing`, `is_close`; bitwise `and`/`or`/
  `xor`/`not` and bit counts; the plain string methods (`capitalize`, `title`,
  `swapcase`, `reverse`, `len_bytes`, `is_alpha` family, `lstrip`/`rstrip`,
  `strip_chars`, `strip_prefix`/`suffix`, `find`/`rfind`, `count_matches`, `repeat`,
  `head`/`tail`, `slice`, `char_at`, `pad` (ljust/rjust/center), `zfill`, `translate`,
  `to_integer(base)`), `contains_any` and `replace_many`.
- **More verbs:** `groupFilter` (pandas `groupby.filter`, polars `having`), `ngroup`,
  `joinWhere` (inequality join), `mergeOrdered`, `mergeSorted`, `pivotMany` (several
  values), `dummies` (`get_dummies`), `combineFirst`, `update`, `repeatRows`,
  `scatter`, `dropNans`, `matchToSchema`, `toFloatMatrix` (`to_numpy`), `hashRows`,
  `betweenTime`; over one column `rle`, `rleId`, `peaks`, `autocorr`, `entropy`,
  `nanExtreme`, `extremeBy` (`max_by`/`min_by`), `nUnique`, `firstValid`/`lastValid`,
  `argTrue`, `argUnique`, `asofIndex`, `extendConstant`; `window`'s rolling and
  expanding functions add `prod`, `sem`, `skew`, `kurt`, `first`, `last`, `nunique`,
  `quantile` and `ddof`.
- **Frame-wide and time windows:** `arith` (frame op frame, `fill_value`),
  `arithScalar`, `compare`, `dot`, `interpolate` (linear or nearest, by position or by
  a column), `groupByDynamic` (polars `group_by_dynamic`, pandas `resample("15min")`),
  `upsample` (`asfreq`), `pivotKeys` (several row and column keys).
- **Dates and times in `Expr`:** `dt` (year … nanosecond, ISO weekday/week/year,
  quarter, day of year, days in month, `is_month_start` … `is_year_end`, leap year,
  business day, month/day names, epoch in days/s/ms/us, date, time, month start/end),
  `strptime` and `strftime` with pandas'/polars' `%` directives, `offset_by` and
  `truncate` with polars' duration strings (`"1mo2d"`, `"15m"`), `add_business_days`.
  A temporal cell is an int (microseconds since the epoch, UTC) or ISO text; the
  calendar is the sibling module `datefmt`'s.

- **Input and output:** `readCsv`/`readCsvReader` and `CsvChunkReader`/`NdjsonChunkReader` (a stream `n` rows at a time, in memory bounded by the chunk; through the sibling `csvstream`;
  delimiter, quote, header or given names, null markers, per-column types, column subset,
  `skip_rows`, `n_rows`, comments, BOM, ragged rows; types inferred from all cells, int,
  float, bool, optionally date and timestamp; every limit has its own error), `writeCsv`
  (pandas' spelling; quoting styles, null text, float precision, date/datetime layouts,
  scientific floats, column subset, decimal comma, BOM), `readJson` (`records`, `columns`,
  `split`, `index`, `values`, `table`) and `readNdjson` (nested values become list and struct
  columns; a repeated key is refused unless `duplicate_keys = .last`), `writeJson`/`writeJsonOpts`
  (the same six orients; `force_ascii`, `double_precision`, `indent`, epoch dates) and
  `writeNdjson`, `format` (`to_string`-like, rows and columns cut around a `…` as polars does),
  `toMarkdown`, `toHtml` (pandas `to_html`) and `glimpse` (polars). `readCsv` also takes
  `thousands`, `decimal`, `true_values`/`false_values`, per-column null markers, `na_filter`,
  `skipinitialspace`, `skipfooter`, `skip_rows_after_header`, a row index column, `on_bad_lines`,
  `date_format`, `escape_char`. `SPEC.md` § Input and output.
- **Column types:** int, float, bool, text, decimal, date, timestamp (optionally carrying an
  IANA zone, `Column.time_zone`; `convert_time_zone`/`replace_time_zone` in `Expr`), duration,
  time of day, categorical (dictionary-encoded, optionally ordered), binary, list, struct and
  fixed-size array (Arrow's layouts; every structural verb and key carries them, a cell is a
  borrowed `ListView`/`RecordView`), and the width types `int8`, `int16`, `int32`, `uint8`,
  `uint16`, `uint32`, `uint64`, `float32` beside `int` (Int64) and `float` (Float64)
  (`ColumnType`, `src/value.zig`; `SPEC.md` § Design notes by feature).
- **Model after:** pandas 3.1 and polars 2.1, eager DataFrame API.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant (no shared state).
  **Deps:** `datefmt` (the calendar of the `dt` functions), `csvstream` (records, fields and quoting of the CSV reader and writer), `regex` (the regular-expression `Expr` functions), `tz` (time zones), `unitext` (Unicode case mapping and character classes).

Provenance: original work of the zig-libs authors (MIT); the storage came from
`dataset`'s `Frame` and the verbs from `tabular`, same authors (both modules are retired). Modeled after pandas
(BSD-3-Clause) and polars (MIT): verb names and behaviour from their documentation, no
source copied. Design references (consulted for edge rules, nothing copied): pandas'
`core/missing.py` and SciPy's `interpolate` package (both BSD-3-Clause) for the
`quadratic`/`cubic`/`pchip`/`akima` interpolation in `src/interpfn.zig`, and pandas'
`read_fwf` column detection (`python_parser.py`, BSD-3-Clause) for `readFwf`'s `.infer`. `src/oracle_vectors.json` holds generated tables and what
pandas 3.1.0 and polars 2.1.0 answered over them, `src/oracle2_vectors.json` the same for the D2 verbs and `src/oracle3_io_vectors.json` for CSV and JSON
input and output (`tools/README.md`); no outside data.

## Use

```zig
const df = @import("dataframe");

var arena = std.heap.ArenaAllocator.init(df.big_block_allocator);
defer arena.deinit();
const a = arena.allocator();

const cols = [_]df.Column{ .{ .name = "k", .type = .text }, .{ .name = "v", .type = .float } };
var b = try df.FrameBuilder.init(a, &cols, 3);
try b.appendRow(&.{ .{ .text = "x" }, .{ .float = 1 } });
try b.appendRow(&.{ .{ .text = "y" }, .null });
try b.appendRow(&.{ .{ .text = "x" }, .{ .float = 2 } });
const f = try b.toOwned();

const g = try df.aggregate(a, f, .{
    .group_by = &.{"k"},
    .aggs = &.{.{ .src = "v", .out = "total", .func = .sum }},
    .skip_na = true,
});
const s = try df.sort(a, g, .{ .key = "total", .dir = .desc });
_ = s.cell(0, "k"); // .{ .text = "x" }
```

Structure, analysis and element functions follow the same shape:

```zig
// pandas df.duplicated(subset=["k"]) as a bool column, then drop the repeats.
const m = try df.duplicateMask(a, f, .{ .keys = &.{"k"}, .out = "dup" });
// Row-wise: pandas df[["x", "y"]].sum(axis=1), polars sum_horizontal.
const h = try df.horizontal(a, m, .{ .cols = &.{"v"}, .func = .sum, .out = "row_sum" });
// Numeric columns only (pandas select_dtypes(include="number")).
const nums = try df.selectBy(a, h, .numeric);
// Element functions: round to 2 decimals, a zero-padded code.
const X: df.Expr = .{ .col = "v" };
const r = try df.mutate(a, nums, &.{.{ .out = "v2", .expr = .{ .round = .{ .x = &X, .decimals = 2 } } }});
_ = r;

// Dates: `events` has a text column `when` like "03/15/2024". Parse it, take the
// ISO week, step a month (polars offset_by).
const D: df.Expr = .{ .col = "when" };
const P: df.Expr = .{ .strptime = .{ .x = &D, .format = "%m/%d/%Y" } };
const dates = try df.mutate(a, events, &.{
    .{ .out = "day", .expr = P, .type = .date },
    .{ .out = "week", .expr = .{ .dt = .{ .x = &P, .part = .iso_week } } },
    .{ .out = "next", .expr = .{ .offset_by = .{ .x = &P, .by = "1mo" } } },
});
_ = dates;
```

Reading other encodings and compressed files. `readCsv` takes UTF-8 bytes and
`readCsvReader` any `std.Io.Reader`, so a file in another encoding or compression goes
through the sibling modules first (this example is the test
`README: a bzip2-compressed windows-1250 file` in `src/io_s2_test.zig`, which `zig build
test-dataframe` compiles and runs; `encoding` and `bzip2` are test-only dependencies):

```zig
// `file` is a `std.Io.Reader` over the .bz2 bytes (a file reader, a socket, ...).
var buf: [4096]u8 = undefined;
var dec = try bzip2.DecompressReader.init(a, file, &buf, .{});
defer dec.deinit();
const raw = try dec.reader.allocRemaining(a, .limited(64 << 20)); // the decompressed bytes
const utf8 = try encoding.decodeToUtf8(a, raw, .windows_1250);   // WHATWG decoding, U+FFFD for bad bytes
const f = try df.readCsv(a, utf8, .{ .delimiter = ';', .decimal = ',' }); // "8,25" is the float 8.25
// A UTF-8 file needs no decoding: df.readCsvReader(a, &dec.reader, .{}).
```

`example/main.zig` runs a longer pipeline (`zig build run-example-dataframe`).

## What results share, and which allocator

Every verb is `verb(allocator, Frame, Spec) -> Frame` and mutates nothing. **A result
borrows:** columns a verb did not touch are shared with its input, a selection of every
row in order shares them all, and the spec's names become column names. Keep the input
and the spec alive as long as the result. Pass an arena: a result has no `deinit`, and a
frame's arrays may be longer than its `len`, so a general-purpose allocator would leak.
For big tables put the arena over `df.big_block_allocator` (2 MiB aligned blocks, advised for
transparent huge pages only where the kernel's `defrag` setting allows it; `huge_page_allocator` always advises). **In a pipeline, keep one arena and `reset(.retain_capacity)` it
between batches** rather than a fresh arena per call: a fresh one pays the kernel for
zeroing every output page, which on 1 M rows is most of a columnar verb's cost
(pandas' malloc keeps its pages between calls the same way). The card's speed is measured
that way (`BENCH_RETAIN=1`); its `**Performance:**` line in `SPEC.md` has the figures.

Missing is null or a NaN float in every verb, as pandas' `isna`. A frame of 2^32 - 1 rows
or more, and work past the caps in `SPEC.md` § Limits and refusals, is `error.TooLarge`.

## Building a frame

`FrameBuilder` copies each row's cells (text included) into per-column arrays; the
storage follows the cells, not the declared `ColumnType`, so a column declared `.float`
that receives ints is an int array, and a mix is `boxed`. A list or record cell taken from
another frame is copied into the column's own storage. A hand-built `Frame`
(`.{ .columns, .data, .len }`) is fine too: arrays shorter than `len` read as null past
their end. `Frame.series(name)` gives one column as a `Series` view.

## Not provided

No row index or MultiIndex, no lazy engine or SQL, no Python-object conversions, no
Arrow/Parquet or other columnar file formats (Arrow IPC over a `Frame` is the sibling `arrow`
module), no XML, no Int128. The reasons are in `SPEC.md` § What this module is, and what it is not
and § What is deliberately not done; the open items are in § Backlog / deferred.

## Verify

`scripts/modtest dataframe` (`zig build test-dataframe`). The verbs are checked against pandas'
and polars' frozen answers, their cell-by-cell reference paths and a deterministic fuzz driver
(`DATAFRAME_FUZZ`); see `SPEC.md` § Verification.
