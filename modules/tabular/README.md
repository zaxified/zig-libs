# tabular

Dataset algebra over [`dataset`](../dataset): pure `dataset → dataset` verbs.
Nothing mutates in place — every transform takes an allocator (normally a
caller-owned pipeline arena) and returns a new `Dataset`.

- Dataset-algebra verbs over the `dataset` module.
- **Model after:** pandas / dplyr verb algebra + technical-analysis
  rolling-window idioms.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant (no shared
  state). **Deps:** `dataset`.

Provenance: original work of the zig-libs authors (MIT); modeled after
pandas (BSD-3-Clause) and dplyr (MIT) — verb-algebra naming/behavior only, no
source consulted or copied.

## Layout

Two tiers in two files, exposed as named namespaces from `root.zig` (their spec
type names collide, so they are deliberately not flattened):

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
`reduce` · `clampRange` · `format`/`formatColumn`. `resample` and `clampRange`
also read a `dataset` `.timestamp` column (UTC calendar day of the instant).

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

⚠ `sum`/`mean`/`count` still count a null cell as a zero-valued row (historical);
the statistics added 2026-10-04 skip missing values the way pandas does.

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

## Tests

`zig build test-tabular` (headless; green in Debug and `-Doptimize=ReleaseFast`).
`root.zig` carries a dark-tests aggregator (`test { _ = transforms; _ = series; }`)
so both submodules' tests run — a bare re-export would not pull them in.

## Deferred (not implemented)

- Grouped-series TA nodes (per-asset-group EMA/MACD/RSI) — a materially bigger
  feature (per-group windowed state), scoped as its own future arc.
- Optional strict-ordering guard for `rolling`/`outlierFlag` (they still assume
  the caller pre-sorted by date) — a v-next hardening pass.
- `ewm` variance/std and `min_periods`, time-based (`"7D"`) windows — no
  consumer needs them yet; `ewm` mean is what TA indicators use.
- A predicate expression language (nested AND/OR, column-vs-column) — `filter`
  covers one AND/OR level; `filterBy` takes any Zig predicate.
