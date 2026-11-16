# arrow

Apache Arrow IPC — the stream and file (Feather v2) formats — for `dataframe.Frame`.

**Status:** work in progress. Done: the FlatBuffers layer (`arrow.fb`). Planned (SPEC.md § Plan): the
schema mapping to every `dataframe` column type, the IPC stream and file formats, ZSTD body compression,
a fuzz driver and an interop oracle over the apache/arrow-testing golden files.

Provenance: written from the Arrow columnar format specification (arrow.apache.org/docs/format) and the
FlatBuffers binary format description; no Arrow or FlatBuffers source was read or ported.
