# `arrow` — specification

## Maturity

**Grade:** *(written by `zig build gen-catalog` — never by hand)*

**Scope:** unsurveyed

**Audit:** review none · mutation none · src ?

**Hardening:** fuzz 2026-11-17 (ARROW_FUZZ, harness `read`: 350k seeds, clean; reach: frames, files, batches, every error kind, frames from compressed inputs) · ct n/a — parses and writes data files, holds no secret

**Performance:** not measured

**Known defects:** none recorded

**Downstream consumer:** no

<!-- The card a consumer reads first, and the one the README catalog's Grade
     column is computed from. Everything but the Grade line is yours; the Grade
     line is generated from them plus the anchor grade below (CONVENTIONS.md §8,
     "Maturity"). The grade is the WORST axis; the profile beside it (S E A H P)
     shows every axis, so a 3 says what would make it a 2.

     Scope (S) — how much of what a user expects this module covers, against the
                 reference implementation and the notable Rust/Go/C ones. Set only
                 by a survey (SURVEY-PLAYBOOK.md), never by feel:
                 `ahead — <reference, version> (surveyed YYYY-MM-DD)` parity AND a
                   measured lead, stated on an `**Ahead:**` line (below) → 1;
                 `parity — …` nothing a user would notice is missing → 2;
                 `core — …` the main use cases, gaps listed under Backlog → 3;
                 `mvp — …` the happy path, gaps a user will hit → 4;
                 `poc — …` a demonstration, finish it before anyone consumes it → 5.
                 `unsurveyed` until then — the grade then carries a `?`, and so
                 does a survey older than a year.
     Ahead     — only with scope `ahead`, refused without it. One or more claims,
                 separated by ` · `, each `<kind> — <claim> (measured YYYY-MM-DD)`:
                 `speed` — faster than the FASTEST implementation in the field (not
                   merely the reference); `**Performance:**` must show `fastest <y>×`
                   with y < 1, from a bench kept in `tools/` (CONVENTIONS.md §9);
                 `correctness` — a defect in the reference found by our oracle, with
                   the case that reproduces it;
                 `feature` — something a user notices that the reference lacks.
                 A lead older than 180 days counts as parity until re-measured.
     Audit (A) — the latest `review` (a security/adversarial audit of THIS module
                 whose findings or verdict are recorded) and the latest `mutation`
                 run over its tests: YYYY-MM-DD, `?` when it happened but the date
                 is lost, `none`. After the mutation date, its score:
                 `(<killed>/<total>, <n> eq)` — survivors not shown equivalent keep
                 the audit at 2. `src` is the hash of the Zig sources the audit
                 read (`zig build maturity-report`, column `src now`); once the code
                 changes the audit is STALE and counts 2. Carrying a hash over a
                 purely mechanical change (a Zig migration, `zig fmt`) is allowed;
                 the commit that does it says so.
                 Which run restores it (2026-11-12): a WHOLE-MODULE run — every
                 guard of the production code — when the module has none yet, when
                 the code changed since the last one exceeds ~20 % of the
                 production lines, or when that run is over 12 months old.
                 Otherwise a DELTA run restores it: mutants over every function
                 the change touched (the whole function, not only its changed
                 lines) and over the guards elsewhere that read state the change
                 writes; same strict verdict, 0 undecided; its score goes on the
                 Audit line and the Mutation paragraph names the base commit. A
                 delta REVIEW without mutants never refreshes `src`.
                 Mutant set: one mutant per guard and operator class (flip, drop,
                 off-by-one, swap arm, skip assignment, error remap) — not every
                 literal ±1; none on arid code (logging, declarations, comptime
                 constants and field defaults, asserts, test helpers). A mutant
                 that changes only cost (a fast path, a cache, a sort choice) is
                 equivalent, noted "cost-only".
                 1 = both dated, scored clean, over the current src · 2 = both, but
                 stale/unscored · 3 = one of them, or a `?` · 4 = neither.
     Hardening (H) — `fuzz`: when the deterministic fuzz driver last ran this
                 module's harnesses (`YYYY-MM-DD (<seeds>, reach <r>%)`); `ct`: when
                 ctgrind last checked its secret-dependent code. Each is a date,
                 `?` (done, not recorded), `none`, or `n/a — <why>` (refused for
                 fuzz when the module has a harness). 1 = every applicable item
                 dated · 3 = some · 4 = none · all n/a = no cap.
                 Optional third item `panic <YYYY-MM-DD [(…)]|n/a — <why>>`: the
                 no-panic sweep (CONVENTIONS.md §8) — data and limits are errors
                 at the API boundary, a caller-contract check is never an
                 `assert`/`unreachable`. Required for grade 1–2: without it
                 the H axis is 3 at best, and `maturity-report` lists the
                 module as `not swept`.
     Performance (P) — worst-workload time ratios, ours/theirs, lower is better:
                 `ref <x>× <impl> · fastest <y>× <impl> (measured YYYY-MM-DD)`;
                 `fastest ?` when the fastest in the field is not measured,
                 `fastest ref` when the reference IS the fastest. A range `a–b` is
                 read as b. `not measured`, or `n/a — <why>` where speed is not
                 what a user picks this module for.
                 1 = x ≤ 1 and y ≤ 1.25 · 2 = x ≤ 1.1 · 3 = x ≤ 2, or not
                 measured · 4 = x > 2. (P2's 10 % is the noise of a worst-of-N
                 ratio at parity; it holds only for a bench that alternates
                 the sides and keeps each one's best of several rounds —
                 CONVENTIONS.md §9, kind 3.)
     Evidence (E) — class C/D only (no outside truth; class A/B take E from the
                 anchor grade below — EXTERNAL with a live `tools/interop.zig`
                 oracle 1, frozen EXTERNAL 2, MIXED 3, REDERIVED 4, SELF 5):
                 `model-fuzz — <model>` an independent reference model the fuzz
                   driver compares against → 1;
                 `model — <model>` a reference model or a checked invariant → 2;
                 `kat — <what>` hand-computed values only → 3; `unclassified` → 3.
                 Delete the line for a class A/B module.
     Known defects (D) — an open defect that makes the module unsafe to rely on.
                 Any text other than `none recorded` sets the grade to 5.
     Downstream consumer — `yes` if a project outside this repo depends on it.
                 A consumed module must grade 3 or better; check-catalog-table
                 fails otherwise. -->

## Compared with

<!-- Required once Scope is surveyed (check-catalog-table enforces it): who
     "the competition" is, so the Scope verdict can be checked and re-run.
     Written by the survey (SURVEY-PLAYBOOK.md). Stars and activity go stale,
     hence the date. Delete this section while Scope is `unsurveyed`. -->

Surveyed YYYY-MM-DD per `SURVEY-PLAYBOOK.md`; stars and activity as of that date.

| Project | Language | Licence | Stars | Last release / push | What a user notices against this module |
|---|---|---|--:|---|---|
| [owner/repo](https://github.com/owner/repo) — **reference** | Rust | MIT | 12.3k | v1.2.3 (2026-08) | … |

**Where we are ahead:** … · **Where we are behind:** … (→ Backlog items)

## What this module is, and what it is not

One paragraph. Then the scope line that matters most: **what a reader might
reasonably expect here and will not find.** Name it, and say whether that is
deferred or refused. A capability silently absent is the thing that wastes
someone's afternoon.

## Wire format / algorithm

Apache Arrow columnar format 1.x, metadata version V5: `Schema.fbs`, `Message.fbs` (FlatBuffers, `src/fb.zig`,
`src/schema.zig`), the encapsulated message framing (continuation marker `0xFFFFFFFF`, metadata length, metadata
padded to 8, body; `src/ipc.zig`) and the stream format: `Schema`, then the `DictionaryBatch`es, then the
`RecordBatch`es, then the end-of-stream marker (`src/stream.zig`). The file format (wave A4) is `ARROW1` and two
zero bytes, the same stream, then a `Footer` table (`File.fbs`: version, schema, a `Block` per dictionary and per
record batch — offset of the message's framing, framing + padded metadata length, body length; 24-byte structs),
its `int32` length and `ARROW1`; `openFile` reads the footer's schema, decodes the dictionaries and checks every
batch's metadata, and `File.readBatch(i)` decodes one batch on demand. Buffers are written 64-byte aligned and padded;
any 8-byte layout is read. Validity bitmaps are LSB-first, a buffer of length 0 when the array has no null.

**Body compression (wave A5).** `Message.fbs` `BodyCompression`, method BUFFER: each buffer of a record or
dictionary batch is compressed on its own and starts with its uncompressed length as a little-endian `int64`; -1
means the bytes after it are stored raw; a buffer of length 0 stays empty. `WriteOptions.compression = .zstd`
(level `compression_level`, 0 = zstd's 3) compresses every non-empty buffer with the collection's `zstd` module and
stores raw the ones that do not shrink, as Arrow C++ and arrow-rs do. The reader decompresses ZSTD (one zstd context
per read) after checking each declared length against `zstd.decompressBound` and the message's total against
`ReadOptions.max_body_bytes`; LZ4_FRAME is `error.Unsupported` (the collection has no LZ4 codec).

**Type mapping (wave A2).** The writer maps the column's DECLARED `ColumnType` and reads the cells through
`ColumnData.get`, so storage of another kind that holds values of the declared type is written too:

| `dataframe` | Arrow written | Arrow also read |
|---|---|---|
| `int` / `int8`..`int32` / `uint8`..`uint64` | Int64 / Int8..Int32 / UInt8..UInt64 | — |
| `float` / `float32` | Float64 / Float32 | Float16 → `float32` |
| `bool` | Bool (bit-packed) | — |
| `decimal` (i128, 12 digits) | Decimal128(38, 12) | Decimal128(p, s) rescaled to 12 digits; inexact or out of range → `Unsupported`, or null under `lossy` |
| `text` / `binary` | Utf8 / Binary; Large* from `WriteOptions.large_from` bytes (default 2^31) | LargeUtf8 / LargeBinary; FixedSizeBinary → `binary` |
| `date` (ISO text) | Date32 (days) | Date64 (ms, floored to the day); years outside 0000–9999 → `Unsupported` |
| `timestamp` (+ `time_zone`) | Timestamp(us, zone) | s / ms / ns (ns floored to us); a zone `tz` does not know → `Unsupported`, or under `lossy` a naive column (the cells are UTC instants either way) |
| `duration` | Duration(us) | s / ms / ns |
| `time` | Time64(us) | Time32(s, ms), Time64(ns); a value outside `[0, 24h)` (Arrow allows 24:00:00) → `Unsupported`, or null under `lossy` |
| `categorical` | Utf8, dictionary-encoded, Int32 indices, `ordered` kept | any integer index type; an unordered dictionary is deduplicated and sorted lexically (the `CatColumn` invariant), an ordered one deduplicated in its order; null dictionary entries read as null rows |
| `list` (`inner[0]`) | List (Int32 offsets) | LargeList; null rows with elements and offsets not starting at 0 are compacted |
| `array` (`array_width`) | FixedSizeList(width) | — |
| `struct` (`inner`) | Struct | — |
| `.nulls` storage with no declaration (a list's elements) | Null | Null → `text` with no storage (what `readJson` gives an all-null column) |
| `boxed` storage | `Unsupported` (no Arrow type short of a dense union) | — |

A dictionary over a non-text type (Int64 values, say) is read as a plain column of that type. Each dictionary-encoded
column gets its own id, its whole dictionary written once before the first record batch.

## Constant-time contract

⚠ Only if this module touches secrets. State **which values are secret**, which
operations are claimed constant-time w.r.t. them, and — the part usually
missing — **what is deliberately not**. A blanket claim is worse than none: it
is what a reader relies on when they should be careful.

If a claim is machine-checked, say by what (`scripts/checks/ctgrind.sh <name>`, a row
in `scripts/checks/ctgrind-expected.tsv`). If it rests on reading the code, say that
instead. Those are different grades of evidence and must not be written alike.

## Limits and refusals

- `ReadOptions.max_rows` (default 2^27, ours): the most rows any one array may claim — the frame's rows summed over
  the batches, a list's elements, a dictionary's entries. It bounds what a few bytes of hostile stream can make the
  reader allocate where a length is not backed by bytes (a Null column, a list of nulls, a struct without fields):
  roughly 16 bytes per claimed row at worst. `error.LimitExceeded`.
- Nesting deeper than `schema.max_depth` (64) is refused on both sides.
- `dataframe` keeps list offsets in `u32`: more than 2^32 − 1 elements in one list column → `Unsupported`; the
  writer's Int32 list offsets refuse more than 2^31 − 1 elements in one batch.
- `ReadOptions.max_body_bytes` (default 2^31, ours): the most bytes one compressed message body may expand to;
  `error.LimitExceeded`. A declared length above what the zstd frames can hold (`zstd.decompressBound`), a frame
  that decodes to another length, or a broken frame is `error.Malformed`.
- Values `dataframe` cannot hold — a Decimal128 that does not fit 12 fractional digits in an i128, a time of day
  outside `[0, 24h)`, a date outside the years 0000–9999, s/ms timestamps or durations whose microseconds overflow
  i64 — fail the whole read with `error.Unsupported` by default. `ReadOptions.lossy = true` reads each as a null
  cell, and a timestamp zone `tz` does not know as a naive column; nothing else changes (a malformed stream is
  still an error). Tests: `src/stream_test.zig` "lossy: …", and the `datetime` and `decimal` golden sets.
- Refused on read (`Unsupported`): LZ4_FRAME body compression, a dictionary replaced mid-stream (deltas are
  appended), a dictionary nested in a dictionary's values, Decimal32/64/256, Interval, Union, Map, the view types,
  tensors. Every structural defect — a buffer shorter than its node, offsets running backwards or past the data, an
  index outside its dictionary, node or buffer counts not matching the schema, a column length not the batch's —
  is `error.Malformed`. Tests: `src/stream_test.zig` "targeted corruptions", "every truncation and byte flip".

## Anchoring

**External anchor (2026-11-17):** the apache/arrow-testing integration golden files written by Arrow C++,
committed under `src/testdata/` (Apache-2.0 data, see `NOTICE`; commit `5a26d357`), read by
`src/golden_test.zig`. Each set's `.stream` and `.arrow_file` is compared field by field and cell by cell with
its Arrow integration JSON (`.json.gz`), through an oracle written from the JSON's own encoding (units, decimal
scales, hex binary, dictionary indices, offsets; dates by Hinnant's `civil_from_days`), not through the reader.
Sets: `custom_metadata`, `dictionary`, `dictionary_unsigned`, `duplicate_fieldnames`, `extension`, `nested`,
`nested_large_offsets`, `null`, `null_trivial`, `primitive`, `primitive_large_offsets`, `primitive_no_batches`,
`primitive_zerolength`, `recursive_nested`, and from `2.0.0-compression` `zstd` and `uncompressible_zstd`
(ZSTD body compression); `datetime` and `decimal` are `Unsupported` by default and compared under `lossy`.
Stream and file read equal, each file batch has its JSON batch's length, and the frame this module writes back
(plain and zstd, stream and file) reads equal. `decimal256`, `interval`, `map`, `map_non_canonical`,
`nested_dictionary`, `union` and `lz4` are asserted `Unsupported`, lossy or not. The writer's bytes are anchored
only through the reader (no foreign reader runs here).

**Anchor grade:** class A · oracle EXTERNAL

## What is deliberately not done

Decisions to refuse work, with the reason. This is the section that stops the
same proposal arriving every few months — and the one whose absence made a
separate archive necessary until 2026-08-13. Distinguish **not now** from
**never** from **superseded by something external**; they are not the same and
get confused constantly.

## Open

- The writer is anchored only through our own reader: no foreign implementation reads our bytes (a live pyarrow
  round trip needs a venv + wheel — owner decision).
- LZ4_FRAME body compression: `Unsupported` until the collection has an LZ4 codec (a new-module idea; not filed
  from this wave).
- The reader copies every buffer (no zero-copy views over the input) and text is not checked for UTF-8.
- Performance not measured.

## Plan

Oracle: the apache/arrow-testing integration golden files with their JSON descriptions (data only, Apache-2.0); a live
pyarrow round trip is an owner decision. Out: the C data interface, Flight, compute kernels.

| Wave | Content | Status |
|---|---|---|
| A1 | FlatBuffers layer; Schema / Field / type tables, the Message envelope | done 2026-11-16 |
| A2 | Type mapping `dataframe` ↔ Arrow (table above); `boxed` refused | done 2026-11-16 |
| A3 | IPC stream: framing, Schema / DictionaryBatch / RecordBatch, end of stream, `rows_per_batch`; `writeStream` / `readStream` | done 2026-11-16 |
| A4 | IPC file: `ARROW1`, footer with blocks, random access to a batch; `writeFile` / `readFile` / `openFile` | done 2026-11-16 |
| A5 | ZSTD body compression read and write (`WriteOptions.compression`); LZ4_FRAME `Unsupported` until an `lz4` module exists | done 2026-11-17 |
| A6 | Golden oracle (done 2026-11-17), `ReadOptions.lossy` (done), fuzz driver (done 2026-11-17), example (done); no-panic sweep, mutation, survey | part 1 done 2026-11-17 |
