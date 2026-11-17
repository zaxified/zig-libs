# `arrow` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-17** — Scope survey against Apache Arrow C++ / pyarrow, arrow-rs, polars, arrow-go, arrow-nanoarrow and the Zig attempts: `**Scope:** core`, `## Compared with` table, gap list under `## Backlog / deferred` (8 proposed, 10 deferred). Documentation only; NO CODE CHANGE.
- **2026-11-17** — Mutation audit: tests for the guards no earlier test pinned (hand-built vtables, field offsets, strings without NUL and short vectors; builder alignment and `tbl_len`; the exact `max_depth` and decode-budget boundaries; big-endian schemas, bad type parameters, absent type tables and versions; streams without the end marker; metadata and body padding; null slots, short buffers, negative offsets and indices; shared dictionaries that differ; the date range; `max_rows` / `max_cells` sums; leading mark, footer length and block kinds) in `src/guards_test.zig` and beside each layer. NO CONSUMER-VISIBLE CHANGE.
- **2026-11-17** — Module lands in the collection: catalog, Libraries and Portability tables regenerated; its NEW-MODULES entry is replaced by an `lz4` idea (LZ4_FRAME bodies read as `error.Unsupported` until then). NO CONSUMER-VISIBLE CHANGE beyond that.
- **2026-11-17** — `lossy`: a Date64 off a day boundary is now floored to the calendar day that contains the instant (-1 ms reads as 1969-12-31), not truncated toward zero; nanosecond times still truncate toward zero.
- **2026-11-17** — Review fixes (1 HIGH, 4 MED, 8 LOW). **Breaking:** `Error` gains `InvalidUtf8`;
  `File.batchRows` returns `Error!usize`; with `lossy = false` a nanosecond value with digits past the microsecond
  and a Date64 off a day boundary are `error.Unsupported` (under `lossy` truncated toward zero, no longer floored).
  The schema decoder charges every field, metadata entry and name byte against a budget from the metadata's
  length, so tables shared through FlatBuffers offsets (2.5 KB naming 2^64 fields) are `Malformed` instead of
  an unbounded allocation; `ReadOptions.max_body_bytes` caps the whole read, not each message;
  `ReadOptions.max_cells` (new, 2^28) bounds the array slots a read decodes, dictionary copies included;
  `ReadOptions.validate_utf8` (new, on) checks Utf8 values, and the writer refuses a `.text` cell that is not
  UTF-8; the metadata version must be V4 or V5; Decimal128 is written with the column's real precision and a
  value wider than its declared precision (or than 38 digits) is read like an inexact scale; two fields may share
  a dictionary id when their value types agree; file footer blocks must match their message's lengths and may
  not overlap. New `src/hostile_test.zig` builds each hostile shape with `fb.Builder` and reads it under a
  byte-capped allocator. The example prints the batch as a table and writes under `.zig-cache/tmp/`.
- **2026-11-17** — Wave A5 and A6 part 1: ZSTD body compression read and write (`WriteOptions.compression = .zstd`,
  `compression_level`; a buffer that does not shrink is stored raw; `ReadOptions.max_body_bytes` caps what a
  compressed body may expand to; LZ4_FRAME stays `error.Unsupported`); `ReadOptions.lossy` reads a value
  `dataframe` cannot hold (Decimal128 out of range, a time of 24:00:00, a date outside 0000-9999, an overflowing
  s/ms timestamp) as null and an unknown time zone as a naive column — the default is still `error.Unsupported`;
  the apache/arrow-testing integration golden files (Apache-2.0 data, `NOTICE`) committed and compared field by
  field with their JSON; a deterministic fuzz driver for the readers (`ARROW_FUZZ`); `example/main.zig`. Depends
  on `zstd` too.
- **2026-11-16** — Wave A4: the Arrow IPC file format — `arrow.writeFile`, `arrow.readFile`, and `arrow.openFile`
  with `File.readBatch(i)` for random access to one record batch (footer with dictionary and record batch blocks);
  a Time32/Time64 value outside the day now reads as `error.Unsupported` (a value `dataframe` cannot hold) rather
  than `Malformed`.
- **2026-11-16** — Waves A2 + A3: `arrow.writeStream` / `arrow.readStream` turn a whole `dataframe.Frame` into an
  Arrow IPC stream and back — every column type (widths, decimal, text/binary with Large offsets, date, timestamp
  with zone, duration, time, categorical as a dictionary, list, fixed-size array, struct), nulls, rows per batch,
  dictionary deltas; the reader also takes other units, decimal scales, Float16, any dictionary index type and
  offsets not starting at 0, and refuses every malformed stream with an error. Depends on `dataframe`.
- **2026-11-16** — Wave A3 part 1: IPC framing (`arrow.ipc`): encapsulated messages (continuation marker, legacy framing
  read, 8-byte padding), end of stream, `RecordBatch` / `DictionaryBatch` metadata both ways with every node and buffer
  checked against the body, a body builder with 64-byte buffer alignment.
- **2026-11-16** — Wave A1 part 2: Arrow schema metadata (`arrow.schema`): `Schema` / `Field` / type / `DictionaryEncoding` /
  `KeyValue` tables of `Schema.fbs` and the `Message` envelope, decoded and encoded (Null, Int 8-64, Float 16/32/64, Binary,
  Utf8, Bool, Decimal 32-256, Date, Time, Timestamp with zone, List, Struct, FixedSizeBinary, FixedSizeList, Duration, the
  Large variants; other types are reported as `unsupported` with their id); nesting capped at 64, big-endian refused.
- **2026-11-16** — New module (work in progress, wave A1): the FlatBuffers layer Arrow's metadata is written in — a
  bounds-checked reader (every offset, vtable, vector and string checked; a hostile buffer is `error.Malformed`) and a
  back-to-front builder.
