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
pandas (BSD-3-Clause) and dplyr (MIT) verb-algebra naming/behavior — see
NOTICE.

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

`map` · `aggregate` (+fx) · `weightedGroupSum` (+fx) · `percentOfTotal` ·
`sort` · `topN` (+ tail fold) · `pivot` · `resample` (day/month/year;
sum/mean/first/last/compound) · `reduce` · `clampRange` ·
`format`/`formatColumn`.

**fx-convert-before-sum** is first-class on `aggregate` and `weightedGroupSum`:
each row's numeric value is multiplied by its per-row fx rate *before*
accumulation, and a null/absent rate means `1.0`. This is a real multi-currency
correctness fix (income rows store a null rate) and is preserved exactly.

### `series` (Tier 1)

Series math over an already date-ordered dataset (sort by date first where order
matters): `cumsum` · `cumreturn` · `drawdown` · `rolling`
(mean/sum/std_sample/min/max) · `pctChange` · `rebase` · `forwardFill` ·
`outlierFlag` (with optional guard) · `mergeByKey` · `datePart` ·
`join` (inner/left) · `stdSample`.

## Tests

`zig build test-tabular` (headless; green in Debug and `-Doptimize=ReleaseFast`).
`root.zig` carries a dark-tests aggregator (`test { _ = transforms; _ = series; }`)
so both submodules' tests run — a bare re-export would not pull them in.

## Deferred (not implemented in v1)

- Multi-column sort (`SortSpec.key` is single-column, no tie-break) and
  numeric-aware pivot column-key ordering (currently lexicographic — mis-sorts
  unpadded numeric keys like `2` vs `10`).
- Grouped-series TA nodes (per-asset-group EMA/MACD/RSI).
- `unpivot`/`melt`; right/full-outer joins, multi-column join keys,
  anti/semi-join.
- Dataset-level `distinct`/dedup without summing (`mergeByKey` sums numerics).
- `limit`/`offset` pagination beyond `topN`; optional strict-ordering guard for
  `rolling`/`outlierFlag` (they assume the caller pre-sorted).
