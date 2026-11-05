# tabular

Dataset algebra over [`dataset`](../dataset): pure `dataset → dataset` verbs.
Nothing mutates in place — every transform takes an allocator (normally a
caller-owned pipeline arena) and returns a new `Dataset`.

- Dataset-algebra verbs over the `dataset` module, at the size a user of pandas or
  polars reaches for (`SPEC.md` § Compared with lists each verdict).
- **Model after:** pandas / polars / dplyr verb algebra + technical-analysis
  rolling-window idioms.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant (no shared
  state). **Deps:** `dataset`.

Provenance: original work of the zig-libs authors (MIT); modeled after
pandas (BSD-3-Clause), polars (MIT) and dplyr (MIT) — verb-algebra naming/behavior
only, no source consulted or copied. `src/oracle_vectors.json` holds generated tables
and what pandas 3.1.0 and polars 2.1.0 answered over them, written by
`tools/oracle.py` from a fixed seed; no outside data.

## What results share, and which allocator

Results borrow. `filter`, `where`, `sort`, `page`, `topN`, `tail`, `nlargest`, `sample`, `distinct`, `dropna`, `clampRange` and semi/anti joins
return the input's row slices; `rename` the input's rows; `fillna` the rows it did not change; every verb that copies cells still points
at the input's text bytes and column names, and spec strings end up as column names. So the input and the spec must outlive
the result. Pass an arena: a verb frees its temporaries but a result has no `deinit`, and with a general allocator it would leak. A row not
as wide as the schema is `error.NoSuchColumn`; constructed keys end in `error.TooLarge`, not a hang (`SPEC.md`).

## Layout

Named namespaces from `root.zig` (their spec type names collide, so they are
deliberately not flattened): `transforms`, `series`, `expr`, `window`.

```zig
const tabular = @import("tabular");

const g = try tabular.transforms.aggregate(a, ds, .{
    .group_by = &.{"ccy"},
    .aggs = &.{.{ .src = "amt", .out = "base", .func = .sum }},
    .fx = .{ .rate_col = "fx" }, // fx-convert-before-sum; null rate = 1.0
});

const r = try tabular.series.rolling(a, ds, .{
    .value_col = "px", .out = "ma20", .window = 20, .func = .mean,
});
```

### `transforms` (Tier 0)

`map` (add/sub/mul/div/min/max, unary abs/sqrt; `on_missing = .zero` —
the historical default — or `.null` for null-in-null-out) · `aggregate` (+fx;
sum/mean/count/min/max/first/last, and the missing-skipping statistics
std/var/median/quantile/nunique plus exact i128 `sum_exact` over `.decimal`) ·
`filter` (column-vs-literal predicates, AND/OR; a null or NaN cell matches only
`is_null`) · `filterBy` (any predicate fn) · `select` / `drop` / `rename` ·
`dropna` / `fillna` (null and NaN are missing) · `weightedGroupSum` (+fx) · `percentOfTotal` ·
`sort` (multi-key tie-break via `SortSpec.then_by`) · `topN` (+ tail fold) ·
`page` (limit/offset windowed slice) · `pivot` (numeric-aware column-key
ordering when every key parses as a number, else lexicographic) ·
`unpivot`/melt · `resample` (day/month/year; sum/mean/first/last/compound) ·
`reduce` · `clampRange` · `format`/`formatColumn` · `tail` · `nlargest` (`.asc` is
nsmallest) · `sample` · `partitionBy` (one table per group, for logic no verb says) ·
`concatByName` · `valueCounts` · `describe` · `clip` · `replace` · `cut`. `resample` and
`clampRange` also read a `dataset` `.timestamp` column (UTC calendar day of the instant).
`AggregateSpec` has `skip_na`, `sort_groups`, `drop_missing_keys`; `AggFn` also size, prod,
any, all, sem, skew, kurt, mode, arg_min, arg_max; `SortSpec.missing` places nulls.

```zig
const t0 = tabular.transforms;
const big = try t0.filter(a, ds, .{ .where = &.{
    .{ .col = "amount", .op = .gt, .value = .{ .float = 1000 } },
    .{ .col = "kind", .op = .eq, .value = .{ .text = "buy" } },
} });
const stats = try t0.aggregate(a, big, .{ .group_by = &.{"asset"}, .aggs = &.{
    .{ .src = "amount", .out = "p90", .func = .quantile, .q = 0.9 },
    .{ .src = "amount", .out = "total", .func = .sum_exact }, // .decimal, exact
} });
```

⚠ Without `skip_na`, `sum`/`mean`/`count`/`min`/`max`/`first`/`last` count a null cell
(historical; `sum` as a zero); the statistics added since skip missing values the way
pandas does.

Group, join and distinct keys compare by value (`Value.order`): int 1, float 1.0 and decimal 1 are one
key, NaN and null one missing key, text is never equal to a number. `aggregate`, `pivot`, `unpivot` number
a colliding output name (`name_2`).

**fx-convert-before-sum** is first-class on `aggregate` and `weightedGroupSum`:
each row's numeric value is multiplied by its per-row fx rate *before*
accumulation, and a null/absent rate means `1.0`. This is a real multi-currency
correctness fix (income rows store a null rate) and is preserved exactly.

### `series` (Tier 1)

Series math over an already date-ordered dataset (sort by date first where order
matters): `cumsum` · `cumreturn` · `drawdown` · `rolling`
(mean/sum/std_sample/min/max) · `pctChange` · `rebase` · `forwardFill` ·
`expanding` (cumulative window, same functions) · `ewm` (exponentially weighted
mean — `alpha`/`span`/`com`/`halflife`, `adjust`, pandas' `ignore_na=False`
weighting; checked against the pandas documentation's own example) ·
`outlierFlag` (with optional guard) · `mergeByKey` · `distinct` (dedup by key
set, keeps first/last row verbatim — no summing) · `datePart` · `join`
(inner/left/right/full/semi/anti; single-column `on` or composite `keys`;
duplicate-key rows fan out rather than last-wins) · `stdSample`.

A `full` join gives the left rows in order, each with its matches, then the unmatched right rows at the
end. `join` also has `right_on`, `suffix`, `null_keys`, `coalesce_keys` and `how = .cross`;
`joinAsof` is `merge_asof`/`join_asof`. `distinct`: empty `keys` is the whole row, `keep =
.none` drops every repeated key.

### `expr`

```zig
const ex = tabular.expr;
const net = ex.Expr{ .col = "net" };
const gross: ex.Expr = .{ .binary = .{ .op = .mul, .l = &net, .r = &.{ .lit = .{ .float = 1.21 } } } };
const out = try ex.mutate(a, ds, &.{.{ .out = "gross", .expr = gross }});

const g = ex.Expr{ .col = "gross" };
const big: ex.Expr = .{ .binary = .{ .op = .gt, .l = &g, .r = &net } }; // column vs column
const kept = try ex.where(a, out, &big);
```

Arithmetic (int stays int, overflow is null), comparison, `and`/`or`/`not` with null
meaning unknown, `is_in`, `if_else`, `coalesce`, `cast`, math, ASCII text verbs. `cast`
is also a verb, coercing or strict. A result with text or bool among other kinds is
`error.BadExpr`: no type holds it.

### `window`

```zig
const r = try tabular.window.window(a, ds, .{
    .value_col = "px", .out = "ma5", .partition_by = &.{"asset"},
    .op = .{ .rolling = .{ .window = 5, .min_periods = 1 } },
});
```

`shift` · `diff` · `pct_change` · `cum_sum/prod/min/max/count` · `row_number` · `rolling` ·
`rolling_time` · `expanding` · `ewm` (mean, var, std) · `rank` · `ffill` · `bfill` ·
`interpolate` · `transform` (any `AggFn` on every row of its group). Skip-NA like pandas,
unlike the older `series` verbs, which read a missing cell as 0. Not every number matches pandas: an int
column stays int here and in polars, where pandas' `diff` and `shift` turn float.

### `frame`

`map`, `cumsum`, `rolling` and `join` on `dataset.Frame`, the columnar table. The specs are those of `transforms` and `series`, and so are
the answers, cell for cell and error for error, boxed columns included. **A result shares the columns it did not touch with its input**, so
the input must outlive it. The rest of the verbs are not on `Frame` yet.

```zig
const f = try dataset.Frame.fromDataset(a, ds);
const m = try tabular.frame.map(a, f, .{ .out = "p", .lhs = .{ .col = "v" }, .op = .mul, .rhs = .{ .col = "w" } });
```

## Tests

`zig build test-tabular` (headless). `frame`'s verbs are checked against the row verbs over generated tables. The verbs are checked against pandas and polars
over generated tables (`tools/README.md`), frozen; no Python is needed to replay them.
`root.zig` carries a dark-tests aggregator so all submodules' tests run — a bare
re-export would not pull them in.

## Speed

`zig build bench-tabular` against pandas 3.1.0 and polars 2.1.0; the table with causes is in `SPEC.md` § Backlog. Sort is 2-4x
faster than pandas. Group-by over clean keys is about level, a key column with nulls takes 3x. A filter takes 2x. Verbs that build
rows pay for `dataset`'s row store: joins 1.5-8x, `melt` 4x, an appended column up to 106x, because pandas shares the other
columns. Reuse a pipeline arena: about half of those costs is page faults. `frame`'s verbs take those rows to at or under pandas with a
reused arena; on a fresh arena 0.2-2.5x.

## What loses precision

`aggregate` `sum`/`mean`/`prod`, `pivot`, `map` and the `series` verbs add through f64: an int column's `sum` is a float, and 2^53 + 1 is
lost, where pandas and polars keep int64. For an exact total use `sum_exact`. `window` (`cum_*`, `diff`, `transform` `sum`) and `expr`
keep an int column int, with null on overflow where the engines wrap.

## Deferred (not implemented)

- Optional strict-ordering guard for `rolling`/`outlierFlag` (they still assume
  the caller pre-sorted by date) — a v-next hardening pass.
- Unicode case mapping in `expr`; ASCII only.
