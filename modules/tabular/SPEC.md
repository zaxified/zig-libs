# tabular — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Dataset algebra over `dataset`: pure `dataset → dataset` verbs. Nothing mutates in place — every
transform takes an allocator (normally a caller-owned pipeline arena) and returns a new `Dataset`.
Two tiers in two files, exposed as named namespaces (`tabular.transforms`, `tabular.series` — not
flattened, since their spec type names collide): **Tier 0** (`transforms`) — `map` · `aggregate`(+fx)
· `weightedGroupSum`(+fx) · `percentOfTotal` · `sort` (multi-key tie-break via `SortSpec.then_by`) ·
`topN`(+ tail fold) · `page` (limit/offset windowed slice) · `pivot` (numeric-aware column-key
ordering — falls back to lexicographic unless every key parses as a number) · `unpivot`/melt ·
`resample` (day/month/year; sum/mean/first/last/compound) · `reduce` · `clampRange` ·
`format`/`formatColumn`.
**Tier 1** (`series`) — math over an already date-ordered dataset: `cumsum` · `cumreturn` ·
`drawdown` · `rolling` (mean/sum/std_sample/min/max) · `pctChange` · `rebase` · `forwardFill` ·
`outlierFlag` (optional guard) · `mergeByKey` · `distinct` (dedup by key set, no summing — keep
first or last) · `datePart` · `join` (inner/left/right/full/semi/anti; single-column `on` or
composite `keys`, fan-out on duplicate keys rather than last-wins) · `stdSample`.
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
`zig build test-tabular` (headless; green in Debug and `-Doptimize=ReleaseFast`), 31 tests across
`transforms`+`series`, using hand-computed golden values as the correctness oracle for the lift plus
new cases for the fx-convert-before-sum path, join fan-out/outer/anti-semi variants (incl. a
composite-key positive control that fails under naive single-key matching), `distinct` vs.
`mergeByKey` summing, multi-key sort tie-breaks, `page` windowing, numeric-aware pivot ordering, and
an `unpivot`→`pivot` round-trip. Run: `zig build test-tabular`.

## Backlog / deferred
Grouped-series TA nodes (per-asset-group EMA/MACD/RSI) — a materially bigger feature (per-group
windowed state machines), scoped as its own future arc rather than folded into this pass. Optional
strict-ordering guard for `rolling`/`outlierFlag` (they still assume the caller pre-sorted by date —
unchanged from the module README's threat-model note) — deferred as a v-next hardening pass, not
required for the join/reshape/pagination gaps closed here.

## Status
`extract · any · util · reentrant` + deps: `dataset` — canonical source is `pub const meta` in
src/root.zig.
