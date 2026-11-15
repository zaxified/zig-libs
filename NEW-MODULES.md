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

### arrow — Apache Arrow IPC over `dataframe.Frame`
- **Origin:** 2026-11-15, consumer request: a frame cache written with a hand-made scalar-only
  codec (nested and zoned-timestamp columns refused). `dataframe`'s SPEC already names `arrow`
  and `parquet` as the planned home of columnar formats.
- **Scope:** the Arrow IPC stream and file formats (schema + record batch + dictionary
  messages, flatbuffers metadata, 8/64-byte alignment, optional LZ4/ZSTD body compression),
  read and write of a `dataframe.Frame` with every column type it has, including list, struct,
  fixed-size array and timestamps with a time zone. Out: the C data interface, Flight,
  compute kernels.
- **Expected:** pyarrow `ipc.new_file`/`open_file`, polars `write_ipc`/`read_ipc`, pandas
  `to_feather`/`read_feather` (Feather v2 = the Arrow IPC file format); arrow-rs `arrow-ipc`
  is the reference implementation to test against.
- **Notes:** depends on `dataframe` (and `zstd`, an LZ4 codec if one exists); keep
  `dataframe`'s own closure free of it — the adapter depends on the frame, not the other way.
  Effort L. Interop oracle: files written by pyarrow, read back by pyarrow.

### parquet — Apache Parquet over `dataframe.Frame`
- **Origin:** named as planned in `dataframe`'s SPEC; the same consumer request asks for it
  "later".
- **Scope:** read and write, plain + dictionary + RLE/bit-packed encodings, Snappy/ZSTD/GZIP
  pages, nested schemas through repetition/definition levels, statistics in the footer.
- **Expected:** pyarrow `parquet`, polars `read_parquet`/`write_parquet`, parquet-rs.
- **Notes:** after `arrow` (shares the type mapping). Effort XL.

### proxyproto — PROXY protocol v1/v2 parser (HAProxy)
- **Origin:** 2026-09-24, found while planning a server behind a load balancer, written up in
  `http`'s Backlog; 2026-11-15 consumer request asks for a standalone module, since a plain
  TCP proxy or any non-HTTP server needs it too and `http` should not grow a dependency for it.
  Decision 2026-11-15: own module, `http` takes it as an optional dependency of its accept path.
- **Scope:** parse on accept over a `std.Io.Reader` (peek + toss, so a missing optional
  header leaves the bytes for the protocol codec), v1 text and v2 binary forms, TCP4/TCP6/
  UNIX/LOCAL, TLV access (ALPN, authority, CRC32C, SSL sub-TLVs, AWS/GCP/Azure ids), a header
  size cap, and the "accept the header only from listed peers" rule (`netaddr.Prefix` list) as
  the API's default rather than the caller's discipline. A writer for the client side (a
  proxy that prepends the header).
- **Expected:** Go `pires/go-proxyproto`, nginx `proxy_protocol`, HAProxy's own spec
  (`doc/proxy-protocol.txt`).
- **Notes:** deps `netaddr`, `crc32c`. Effort M. Interop oracle: HAProxy `send-proxy-v2`.
