# tabular — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — ADDED (survey 2026-09-30 gaps + two wgs consumer gaps), no breaking change:
  - `transforms.filter` (column-vs-literal predicates, `.all`/`.any`; SQL's rule — a null or
    NaN cell matches only `is_null`, never `ne`; kinds must match: a number never equals text)
    and `filterBy` (any predicate fn).
  - `select` / `drop` / `rename` (simultaneous renames; `error.DuplicateColumn` on a result with
    two columns of one name — new error set `ColumnsError`, existing verbs keep `Error`).
  - `dropna` (`subset`, `how = any|all`) / `fillna` (null and NaN are missing).
  - `AggFn`: `std`, `var` (sample, n−1), `median`, `quantile` (type 7, `AggCol.q` /
    `PivotSpec.q`), `nunique`, `sum_exact` (i128 at the decimal scale → `.decimal`, null on
    overflow; wgs's `aggregate_exact` can go). They skip missing values; `sum`/`mean`/`count`
    keep their historical null-as-zero rule.
  - `BinOp`: `min`, `max`, unary `abs`, `sqrt`; `MapSpec.rhs` defaults to `.num = 0`;
    `MapSpec.on_missing = .zero` (default, unchanged) | `.null` (null in, null out; div-by-0 and
    sqrt of a negative → null) — wgs's `applyMapExt` can go.
  - `series.expanding`, `series.ewm` (mean; alpha/span/com/halflife, adjust; `EwmError`).
  - `resample` / `clampRange` read a `dataset` `.timestamp` column.
  - Mutation 2026-10-04: 47 mutants, 47 killed (10 survivors of the first run killed by 2 new
    tests with stated reasons).

- **2026-07-18** — Security audit: zero findings fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on pandas / dplyr (design
  reference, not a test anchor).
- **2026-07-09** — New module: Dataset algebra (pandas/dplyr-style verbs) over `dataset`
  — aggregate/pivot/resample/rolling/join, fx-aware.
