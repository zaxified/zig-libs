# `dataframe` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-07** — New module: a columnar dataframe, `Frame`, with `dataset`'s storage
  and `tabular`'s `frame` verbs (`map`, `cumsum`, `rolling`, `filter`, `distinct`,
  `aggregate`, `unpivot`, `join`), plus `sort`, `dropna`, `fillna`, `pivot`, `select`,
  `drop`, `rename` on `Frame`. Verified against `tabular`'s row verbs over generated
  tables and against 570 frozen pandas 3.1.0 / polars 2.1.0 answers.
