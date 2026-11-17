# arrow

Apache Arrow IPC — the stream and file (Feather v2) formats — for `dataframe.Frame`.

**Status:** stream and file format for every `dataframe` column type, ZSTD and LZ4_FRAME body compression both
ways (`WriteOptions.compression = .zstd` / `.lz4`),
`ReadOptions.lossy` for values `dataframe` cannot hold; anchored on the apache/arrow-testing golden files;
fuzz driver (`ARROW_FUZZ`). Still open (SPEC.md § Plan, A6): no-panic sweep, mutation, survey.

Provenance: written from the Arrow columnar format specification (arrow.apache.org/docs/format) and the
FlatBuffers binary format description; no Arrow or FlatBuffers source was ported (Arrow C++ and arrow-rs were
read for behaviour choices only, each cited in SPEC.md). `src/testdata/` reproduces apache/arrow-testing golden
files (Apache-2.0 data) — see `NOTICE`.
