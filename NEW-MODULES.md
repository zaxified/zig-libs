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

### lz4 — LZ4 block and frame format codec
- **Origin:** 2026-11-17, the `arrow` module: Arrow IPC body compression is LZ4_FRAME or ZSTD;
  without an LZ4 codec `arrow` reads LZ4-compressed files with `error.Unsupported`. `parquet`
  (LZ4_RAW pages) would be the second consumer.
- **Scope:** LZ4 block format and the LZ4 frame format (magic, frame descriptor, block
  checksums, content checksum via xxHash32), compress and decompress, bounded output size.
  Out: LZ4 HC levels at first, dictionary compression.
- **Expected:** the reference `lz4` C library and its CLI (frame format), lz4_flex (Rust),
  python-lz4.
- **Notes:** an xxHash32 is needed for the frame checksums (check sibling modules first).
  Interop oracle: the `lz4` CLI round trip. Effort M.

### parquet — Apache Parquet over `dataframe.Frame`
- **Origin:** named as planned in `dataframe`'s SPEC; the same consumer request asks for it
  "later".
- **Scope:** read and write, plain + dictionary + RLE/bit-packed encodings, Snappy/ZSTD/GZIP
  pages, nested schemas through repetition/definition levels, statistics in the footer.
- **Expected:** pyarrow `parquet`, polars `read_parquet`/`write_parquet`, parquet-rs.
- **Notes:** after `arrow` (shares the type mapping). Effort XL.
