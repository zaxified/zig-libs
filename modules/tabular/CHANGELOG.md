# tabular — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-05** — ADDED `tabular.frame`: `map`, `cumsum`, `rolling`, `join` on `dataset.Frame`, with the row verbs' specs and answers, cell for cell and error for error (`src/frame_test.zig`, generated tables of every column shape). **A result borrows the columns it did not touch from its input.** Row verbs unchanged. `series.windowAgg` is public now, `keys.probeInts` added. Bench `f_` rows against pandas, SPEC § Backlog.

- **2026-11-02** — `window` keeps an all-int column exact: `cum_sum/prod/min/max`, `diff`, `transform` `sum` are int, null on overflow. The oracle compares integers exactly and output types, over a corpus extended past 2^53, with mixed int/float keys and tables that grow the hash table: 1353 cases. `aggregate` `sum`'s f64 loss stated in SPEC and README. Card: `Performance: not measured`, every ratio with its cause in SPEC Backlog; bench row `group_null`. README states what results borrow, the allocator assumed and where a full join puts unmatched right rows.

- **2026-11-02** — FIXED, independent review, **BEHAVIOURAL, not breaking**: int `mod` no longer overflows on extreme operands (a panic); a decimal and a float equal under `Value.order` are one key (the float test used a rounded `asFloat`); `quantile`/`median` under fx no longer read uninitialised memory when a product is NaN; `valueCounts` sorts by position; `aggregate`, `pivot`, `unpivot` number a colliding output name (`name_2`) instead of leaving it unreachable. Hash tables are seeded per call and refuse with `TooLarge` past a work cap: constructed keys took 5854 ms, now 35 ms. A row not as wide as the schema is `NoSuchColumn` from every verb, not a panic. `join` caps a cross join of column-less tables by rows. `mutate` infers its type from all results (`error.BadExpr` when no type holds them) and applies a declared one; `window` `shift` with a fill of another kind promotes or is `error.BadFill`; `clip` keeps its column's type; `pivot` columns are typed by the function (`count` is int, was declared float). `rolling` `min_periods = 0`: `sum` of no values is 0, as pandas and polars. Text to number refuses hex and underscores and "12.9" to int is null, was 12.

- **2026-11-02** — ADDED `transforms.partitionBy`, the per-group escape hatch. Card: Scope parity with the pandas/polars verb set, oracle evidence, measured Performance (`tools/bench.zig`); stale claims corrected (join "no cap", two tiers, "not measured"). P stays 3: filter and distinct are over 1.1× pandas, a row-store cost stated on the card.

- **2026-11-02** — pandas 3.1.0 and polars 2.1.0 as black-box oracles: `tools/oracle.py`, 1191 frozen cases replayed by `src/oracle_test.zig`, every engine disagreement labelled; the new verbs swept in `src/sweep_test.zig`. `Expr` integer `mod` no longer needs a positive divisor (`@mod` would have panicked).

- **2026-11-02** — ADDED + **CONSUMER-VISIBLE (keys)**: survey gaps of the pandas/polars verb set.
  `keys.zig`: canonical, length-prefixed key encoding, factorizer, stable radix sort. Group, join, distinct and pivot keys
  no longer collide on a 0x1f in the data or on int 5 vs text "i5", and are equal by value (int 1 = float 1.0 = decimal 1,
  -0.0 = 0.0, NaN = null as a key, so int and float now join). `aggregate`, `pivot`, `sort`, `join`, `distinct`,
  `mergeByKey` rebuilt on it (2-7x faster, see `tools/bench.zig`). New: `expr.mutate` / `where` / `cast`
  (`Expr` tree, Kleene logic, int stays int, overflow null), `window.window` (shift, diff, pct_change, cumulative, rolling
  by count or time, expanding, ewm with var/std, rank, ffill/bfill, interpolate, transform, each per group),
  `series.joinAsof`, `JoinSpec.right_on/suffix/null_keys/coalesce_keys`, `JoinHow.cross`, `AggFn` size/prod/any/all/sem/skew/
  kurt/mode/arg_min/arg_max, `AggregateSpec.skip_na/sort_groups/drop_missing_keys`, `SortSpec.missing`,
  `PivotSpec.skip_na/fill_value`, `DistinctSpec.keep = .none` and empty `keys` = whole row, `Freq` week/quarter, `ResampleAgg`
  min/max/count, `tail`, `nlargest`, `sample`, `concatByName`, `valueCounts`, `describe`, `clip`, `replace`, `cut`.
  Every default keeps its old behaviour except the key equality above.

- **2026-10-31** — **CONSUMER-VISIBLE (error set widened):** no-panic sweep + blind review (§ GW). `transforms.Error` and `series.Error` gain `TooLarge`; new caps: `max_pivot_cells` 2^22, `max_aggregate_cells` 2^24 (groups × aggs), `max_unpivot_cells` 2^22, `series.max_join_cells` 2^24 (counted before emitting), `max_rolling_work` 2^30. Fixed: `join` with a repeated key column wrote past the end of its column array; `pivot` column order was not total for a "nan" key. `select`'s duplicate check and `join`'s key mask are O(columns).

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
