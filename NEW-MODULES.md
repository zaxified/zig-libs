# Accepted new-module ideas

Ideas for modules that do not exist yet, accepted as belonging in the collection but not
started. An existing module's own gaps go into its `SPEC.md` § "Backlog / deferred"; this file
is only for work that has no module to park it in. Parking such an item in an unrelated
module's Backlog hides it: nobody reading that module is looking for it.

When work starts, the module is created from `modules/_template/` (CONVENTIONS.md §6) and its
entry here is deleted in the same change. An idea that is rejected later is deleted with a
one-line reason in the root `CHANGELOG.md`.

Entry format: `### <name> — <one line>`, then **Origin** (date, who asked, why),
**Scope** (the API or format, and what stays out), **Expected** (equivalents elsewhere that
set the parity bar), **Notes** (dependencies, open decisions, effort).

## Open

### parquet — Apache Parquet over `dataframe.Frame`
- **Origin:** named as planned in `dataframe`'s SPEC; the same consumer request asks for it
  "later".
- **Scope:** read and write, plain + dictionary + RLE/bit-packed encodings, Snappy/ZSTD/GZIP
  pages, nested schemas through repetition/definition levels, statistics in the footer.
- **Expected:** pyarrow `parquet`, polars `read_parquet`/`write_parquet`, parquet-rs.
- **Notes:** after `arrow` (shares the type mapping). Effort XL.
