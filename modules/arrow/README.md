# arrow

Apache Arrow IPC — the stream and file (Feather v2) formats — for `dataframe.Frame`.

**Status:** stream and file format for every `dataframe` column type except `boxed` storage, ZSTD and LZ4_FRAME body
compression both ways (`WriteOptions.compression = .zstd` / `.lz4`), schema / field / footer key/value metadata both
ways (`ReadOptions.metadata`, `WriteOptions.*_metadata`), column projection on read (`ReadOptions.columns`),
`ReadOptions.lossy` for values `dataframe` cannot hold; anchored on the apache/arrow-testing golden files; fuzz driver
(`ARROW_FUZZ`). The no-panic sweep is not recorded yet and no speed has been measured.

## Not provided

No zero-copy or memory-mapped read (the reader copies every buffer into `dataframe`'s storage), no incremental reader
or writer (the input and the output are whole byte slices), no big-endian byte swap, no C data interface, Flight,
tensors or compute kernels. Interval and Union are refused (`Unsupported`); RunEndEncoded, the view types and Map are
read as the plain columns they encode (Map as a list of its entries struct) and never written; LZ4 is written at its
fast levels only. See SPEC.md *What is deliberately not done* and *Backlog / deferred*.

Provenance: written from the Arrow columnar format specification (arrow.apache.org/docs/format) and the
FlatBuffers binary format description; no Arrow or FlatBuffers source was ported (Arrow C++ and arrow-rs were
read for behaviour choices only, each cited in SPEC.md). `src/testdata/` reproduces apache/arrow-testing golden
files (Apache-2.0 data) — see `NOTICE`.
