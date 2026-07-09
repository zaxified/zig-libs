# tabular — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Dataset algebra over `dataset`: pure `dataset → dataset` verbs. Nothing mutates in place — every
transform takes an allocator (normally a caller-owned pipeline arena) and returns a new `Dataset`.
Two tiers in two files, exposed as named namespaces (`tabular.transforms`, `tabular.series` — not
flattened, since their spec type names collide): **Tier 0** (`transforms`) — `map` · `aggregate`(+fx)
· `weightedGroupSum`(+fx) · `percentOfTotal` · `sort` · `topN`(+ tail fold) · `pivot` · `resample`
(day/month/year; sum/mean/first/last/compound) · `reduce` · `clampRange` · `format`/`formatColumn`.
**Tier 1** (`series`) — math over an already date-ordered dataset: `cumsum` · `cumreturn` ·
`drawdown` · `rolling` (mean/sum/std_sample/min/max) · `pctChange` · `rebase` · `forwardFill` ·
`outlierFlag` (optional guard) · `mergeByKey` · `datePart` · `join` (inner/left) · `stdSample`.
fx-convert-before-sum is first-class on `aggregate`/`weightedGroupSum`: each row's numeric value is
multiplied by its per-row fx rate *before* accumulation, and a null/absent rate means `1.0` — a real
multi-currency correctness fix (income rows store a null rate).
`root.zig` carries a dark-tests aggregator (`test { _ = transforms; _ = series; }`) so both
submodules' tests run — a bare re-export would not pull them in (repo-wide dark-tests gotcha).
Reentrant — no shared state. Original work of the zig-libs authors (MIT); modeled after pandas/dplyr
verb algebra + TA rolling-window idioms — see NOTICE.

## Threat model / out of scope
Not a security boundary — a pure computational library over caller-provided in-memory datasets;
callers are trusted to construct valid `Dataset`s (`dataset` module owns that codec/validation
boundary). Failure mode / resource bound: `rolling`/`outlierFlag` assume the caller pre-sorted by
date — an unsorted input silently produces wrong (not crashing) rolling stats, since there is no
strict-ordering guard in v1. `join`/`mergeByKey` allocate proportional to input size; no built-in cap
on join fan-out (a caller joining two large unfiltered datasets can produce a large result — the
caller's arena/allocator is the only bound).

## Verification
`zig build test-tabular` (headless; green in Debug and `-Doptimize=ReleaseFast`), 21 tests across
`transforms`+`series`, using hand-computed golden values as the correctness oracle for the lift plus
new cases for the fx-convert-before-sum path. Run: `zig build test-tabular`.

## Backlog / deferred
Multi-column sort (`SortSpec.key` is single-column, no tie-break) and numeric-aware pivot column-key
ordering (currently lexicographic — mis-sorts unpadded numeric keys like `2` vs `10`); grouped-series
TA nodes (per-asset-group EMA/MACD/RSI); `unpivot`/`melt`; right/full-outer
joins, multi-column join keys, anti/semi-join; dataset-level `distinct`/dedup without summing
(`mergeByKey` sums numerics); `limit`/`offset` pagination beyond `topN`; optional strict-ordering
guard for `rolling`/`outlierFlag` (from the module README, folded here).

## Status
`extract · any · util · reentrant` + deps: `dataset` — canonical source is `pub const meta` in
src/root.zig.
