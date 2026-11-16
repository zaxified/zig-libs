# `arrow` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
