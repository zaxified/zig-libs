# `arrow` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
