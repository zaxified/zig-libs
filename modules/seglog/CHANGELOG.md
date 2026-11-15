# `seglog` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-15** — New module: moved here from energomonitor's `egw-hub/seglog/`
  (segmented, crash-consistent, append-only log; format v2). `meta.deps` now lists
  all three imports (`kv`, `crc32c`, `zstd`). Other changes the repo gates required: `zig fmt` (whitespace) on `root.zig`,
  `fault_test.zig`, `example/bench.zig`; `fuzz_test.zig`'s first draw is now
  `value(u64) % 4` instead of a ranged draw (check-fuzz-reach R1: a ranged `Smith`
  draw returns its minimum for almost every seed); new `example/main.zig` (64 `pub fn`
  owe a consumer example). History below is the energomonitor one.
- **2026-09-28** — A compressed segment reuses the decoder the last one closed
  (`zstd.seekable.Seekable.reset`, zig-libs Z28 `bf865f4c`) instead of allocating
  2 × 128 KiB of buffers and a decoder per open (audit L6).
- **2026-09-28** — `rotate` creates a new segment file with kv's `.create_new`
  (`O_CREAT|O_EXCL`, zig-libs `a27c247c`) instead of `.create_truncate`: an existing
  file under the name is never emptied, atomically. The read-only probe before the
  manifest commit stays (audit L1): it refuses a non-empty orphan with
  `error.OrphanSegment` before the manifest names the segment. A name taken by an
  empty file is adopted as before.
- **2026-09-27** — `Log.rebuildManifest(gpa, store, ids)`: a lost or torn `MANIFEST` now
  has a recovery path (audit finding L4, egw-audit-2026-09-27) — every other kind of
  damage already did. Given the segments' ids (ascending; `kv.Storage` still has no
  directory listing, so the caller supplies them — `egw-hub`'s `seglog_cli.manifestRebuild`
  lists the directory itself), it reads each segment's own header and seal, cross-checks
  consecutive LSN ranges, and writes a fresh manifest naming each segment's form. Refuses
  over a manifest that still opens, or over segments that disagree with each other
  (`error.Corrupt`) rather than guess. Checks headers and seals only — run `Log.verify`
  after a rebuild for the data records themselves.
- **2026-09-27** — Lowering `Options.max_record_len` below records already written no
  longer risks silent, irreversible loss (audit finding L5, egw-audit-2026-09-27): a
  writer's `open` now refuses with `error.RecordTooLongForOptions` instead of treating
  such a record in the *active* segment as a torn tail and truncating it. Reading one
  in a closed segment still `error.Corrupt` (no on-disk field records what limit was in
  force when a segment was written), but with its own `Damage.Reason.record_too_long`,
  distinct from `bad_record`.
- **2026-09-27** — `Options.timestamps` bounds `append`/`appendAt`/`appendMany`/
  `appendEntries`: `.refuse` rejects an out-of-range `ts` before anything is written
  (`error.TimestampOutOfRange`); `.clamp` pulls it into range first. Default
  `.unbounded`, unchanged from before (audit finding L3, egw-audit-2026-09-27) — one
  out-of-range `ts` otherwise becomes a segment's seal `max_ts`/`min_ts` for good,
  which makes `seekTime` match that record for every later query and can wedge
  `enforceRetention`'s age policy on that segment (and every older one behind it)
  forever.
- **2026-09-27** — `Log.compress` decodes the `.zst` it just wrote back and compares it
  byte for byte against the raw segment before renaming over it or deleting the raw
  file (audit finding L2/E13, egw-audit-2026-09-27) — the read-back-and-compare
  `migrate` already ran on its own conversion, now on this one too. A mismatch is
  `error.CompressVerifyFailed` (counted, `Stats.compress_verify_failed`); the raw
  segment and the manifest are untouched, only `COMPRESS.tmp` is deleted.
- **2026-09-27** — **Automatic migration** from format 1: a writer's `open` checks the
  whole old log first (damage refuses it, `error.MigrationFailed`, nothing written),
  then converts it segment by segment in place — each read back and compared before
  it replaces the old file — and reports (`Log.migration()`, `MigrationReport`,
  `Options.migration_report`/`on_migration_progress`). `Options.migration = .refuse`
  gives `error.NeedsMigration`; readers get `error.MigrationInProgress` until it is done;
  a crash anywhere is resumed by the next `open`. `Options.legacy_ts` gives migrated
  records their time; `Log.translatePosition` moves a version-1 position. `appendEntries`:
  a batch with a timestamp per record.
- **2026-09-27** — `resync` over a damaged segment is linear again: the read window
  extends instead of reloading a block per byte tried, remembers where the data ends,
  and `resync` stops there (a damaged seek table can claim gigabytes). A compressed
  segment reads frame by frame and a frame that does not decode reads as nothing at
  once. Found by a deterministic fuzz driver (`SEGLOG_FUZZ`, in `fuzz_test.zig`):
  seeds, a watchdog per input, one job per core — 160 000 runs in about 10 s; it also
  found a hang in zig-libs `zstd.seekable` on a forged table (fixed there,
  `5f5aa411`).
- **2026-09-27** — Compression: `Log.compress(id)` / `Concurrent.compress` turns a closed
  segment into the zstd seekable format (`seg-<id>.zst`, `Options.compression` = level
  and frame size), the manifest recording each segment's form. The same bytes, so
  positions, LSNs and the index are unchanged and `zstd -d` gives the segment back.
  Reads go through a `Storage` wrapper that opens a missing `.log` as `.zst` and
  decodes only the frames a read touches; undecodable bytes read as missing, i.e.
  `Corrupt`. Compaction keeps a compressed segment compressed; retention weighs the
  compressed file. `open` removes what a crash left of a compression. Crash sweep and
  fuzz harness cover it. Needs zig-libs `zstd` (Z23).
- **2026-09-27** — `Options.preallocate`: the active segment's space reserved in steps
  (`kv.Storage.allocate`), data synced with `Storage.syncData`; the reservation is cut
  at the seal, and zeros past the data are the end of it on `open`, after a seal, and
  for a read-only reader (which now re-reads once at the live end before answering
  "nothing yet"). A full disk refuses an append without poisoning the log.
  `bytesCutOnOpen` counts to the last nonzero byte. 155-byte `.always` appends 295 →
  887/s. The CRC is zig-libs `crc32c` (hardware): reading 1 M × 155 B 0.47 → 0.066 s,
  `open` of the same 2.18 → 0.068 s. Needs zig-libs `c5a90ae9`.
- **2026-09-27** — `Log.stats()` (counters and gauges; with `Options.monotonic_ns` a
  power-of-two histogram of data-fsync latency, `SyncLatency`), `Concurrent.stats`. A
  fuzz harness builds a log, damages its segments, manifest and index files, and runs
  every read path over them (205 505 runs clean, ReleaseSafe). Mutations of F1–F6 and
  stats re-run in ReleaseSafe as one schemata build: 12 of 12 killed, each by its test.
- **2026-09-27** — Compaction: `Log.compact(id, ctx, keep)` and `Log.compactByKey`
  (newest record per key over the whole log), a closed segment rewritten to
  `COMPACT.tmp` and renamed over the old one; header flag *compacted* (LSNs only
  rise); `open` removes a leftover temp file. `Position` carries its record's LSN, and
  an iterator started from one re-finds the record by `seek` when it moved; `seek`
  returns the first record at or after an LSN. The `.idx` file records its segment's
  size. `Concurrent.compact`. The crash sweep runs a compacting script.
- **2026-09-27** — `Log.seek(lsn)` and `Log.seekTime(t)` (Kafka's time-index meaning:
  the first record where the newest timestamp so far reaches `t`), on a sparse index
  per segment (`Options.index_interval`, 4096 bytes): in memory for the active segment,
  `seg-<id>.idx` when sealed — derived, unsynced, CRC- and fit-checked on load, rebuilt
  when missing or wrong, deleted with its segment. `Concurrent` has both.
- **2026-09-27** — `Concurrent`: a `Log` for many threads behind a `std.Io.Mutex`, with
  group commit under `.always` — appends share an fsync run outside the lock, each
  returning once durable (1 thread ~280/s → 32 threads ~4 560/s, NVMe). A handle
  rotated away during a running fsync is retired, not closed, until it finishes. The
  crash sweeps also run through `Concurrent`; bench scenario `group`.
- **2026-09-27** — `Options.auto_rotate = .{ .max_bytes, .max_age }`: the log rotates to
  the newest id + 1 before an append that would overflow the segment, or once the
  segment is old (its creation stamp, from the header, survives a reopen); an append
  to an empty log creates segment 1. Manual `rotate(id)` is unchanged.
- **2026-09-27** — Sync policy: `Options.sync` = `.always` (default) / `.every_bytes` /
  `.manual`, `Log.sync()`, `Log.durableLsn()`. The writer's iterators read only the
  durable prefix; `rotate`'s seal syncs what was waiting; `open` syncs the tail it
  adopts. The crash sweep is generic over script and policy and runs the deferred
  policies too (a crash may take any whole-record suffix no sync covered).
- **2026-09-27** — Damage and recovery: `Iterator.damage()` (segment, offset, one of
  seven reasons), `Iterator.skipSegment()` and `Iterator.resync()` (the next intact
  record in the segment that fits the LSN sequence), each returning the `Gap` of LSNs
  stepped over; `Log.verify` walks the whole log that way. `Log.enforceRetention`
  drops the oldest segments by total size and by the newest timestamp in each seal.
- **2026-09-27** — **Format version 2** (version 1 is not read): every record
  carries an LSN — consecutive from 1 across the whole log, never reused — and
  a timestamp (`appendAt`, `appendManyAt`, or `Options.now`); the segment header
  (40 bytes, CRC-checked) holds the base LSN and must match the manifest, which
  now names each segment with its first LSN; the seal holds the LSN and time
  range. `append`/`appendMany` return `Appended { pos, lsn }`; `Record` has
  `lsn` and `ts`; new `nextLsn`, `segmentFirstLsn`, `error.UnsupportedVersion`.
  Reads go a block at a time (`read_block`, 64 KiB) instead of two `pread`s
  per record. A CRC-valid record with the wrong LSN is `Corrupt`, never cut.
- **2026-09-22** — `Log.openReadOnly`: a reader beside a live writer in another
  process — no lock, nothing written, created or repaired; follows appends,
  rotations and drops, and reads an unfinished newest-segment tail as "not yet".
  Mutations on it return `error.ReadOnly` (new in `AppendError`, `RotateError`,
  `DropError`); `refresh()` re-reads the manifest. Also: the writer's iterator no
  longer recreates a segment deleted from outside, and `open` without `create`
  no longer leaves an empty `MANIFEST`. Needs zig-libs `kv` with
  `OpenMode.read_only`.
- **2026-09-21** — New module: a segmented, crash-consistent append-only log —
  CRC32C records, sealed closed segments, a manifest as the only record of
  which segments exist, retention by whole segment. Built in egw-hub, to move
  into zig-libs once the hub has used it. Verified by `kv`'s `SimStorage`
  swept over every side effect in four crash models, plus a second sweep that
  crashes inside the recovering `open`; 16 guards mutation-checked.
