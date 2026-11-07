# `dataframe` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-07** — **BEHAVIOURAL, not breaking:** fixes from the independent review.
  `cumsum` and `rolling` follow pandas and polars (a missing cell is skipped and its row
  is null, a short window is null, an int `cumsum` stays int; both are `window` now and
  return `WindowError`); `distinct(.keep = .last)` keeps rows in input order; a suffixed
  join column that collides with a left name is numbered; a decimal casts to text
  exactly; pivot column keys read numbers as `cast` does; `aggregate` with
  `drop_missing_keys` and no group columns keeps its row; a huge `FrameBuilder` hint is
  clamped to `max_row_hint` instead of overflowing; `big_block_allocator` frees with the
  alignment it allocated with.

- **2026-11-07** — ADDED `resample` (day, week, month, quarter, year) and `reduce` on
  `Frame`, as `tabular`'s row verbs: every verb `tabular` has as a row verb is now here,
  except the compositions listed in SPEC § Backlog.

- **2026-11-07** — ADDED the rest of `tabular`'s verbs on `Frame`: `page`, `tail`, `topN`,
  `nlargest`, `sample`, `concatByName`, `partitionBy`, `valueCounts`, `describe`, `clip`,
  `replace`, `cut`, `joinAsof`. The oracle replays all 1353 pandas/polars cases.

- **2026-11-07** — ADDED `mutate`, `where`, `cast` (the `Expr` tree of `tabular.expr`,
  evaluated over the columns it names) and `window` (every operation of
  `tabular.window`, per group or not) on `Frame`. The oracle replays 1281 pandas/polars
  cases, every one run.

- **2026-11-07** — New module: a columnar dataframe, `Frame`, with `dataset`'s storage
  and `tabular`'s `frame` verbs (`map`, `cumsum`, `rolling`, `filter`, `distinct`,
  `aggregate`, `unpivot`, `join`), plus `sort`, `dropna`, `fillna`, `pivot`, `select`,
  `drop`, `rename` on `Frame`. Verified against `tabular`'s row verbs over generated
  tables and against 570 frozen pandas 3.1.0 / polars 2.1.0 answers.
