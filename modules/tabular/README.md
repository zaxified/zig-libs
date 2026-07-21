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
`sort` (multi-key tie-break via `SortSpec.then_by`) · `topN` (+ tail fold) ·
`page` (limit/offset windowed slice) · `pivot` (numeric-aware column-key
ordering when every key parses as a number, else lexicographic) ·
`unpivot`/melt · `resample` (day/month/year; sum/mean/first/last/compound) ·
`reduce` · `clampRange` · `format`/`formatColumn`.

**fx-convert-before-sum** is first-class on `aggregate` and `weightedGroupSum`:
each row's numeric value is multiplied by its per-row fx rate *before*
accumulation, and a null/absent rate means `1.0`. This is a real multi-currency
correctness fix (income rows store a null rate) and is preserved exactly.

### `series` (Tier 1)

Series math over an already date-ordered dataset (sort by date first where order
matters): `cumsum` · `cumreturn` · `drawdown` · `rolling`
(mean/sum/std_sample/min/max) · `pctChange` · `rebase` · `forwardFill` ·
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
