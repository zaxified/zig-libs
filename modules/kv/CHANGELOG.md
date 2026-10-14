# kv — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-14** — `Db.iterator(gpa, prefix)` (S2 survey R6, Bitcask fold): a consistent snapshot of the live keys and their values in key order; the data files it points into are pinned, so merges and compactions meanwhile delete their names but keep them readable until `Iterator.deinit`. The single-file `compact` no longer rewrites its `DataFile` in place. **Fix:** `FsStorage` claims and releases handle-table slots under a lock — two threads opening at once could get the same slot (several `Db`s on one backend, or since this release one `Db`'s merge and its writer; caught by ThreadSanitizer).

- **2026-10-14** — Hint files (S2 survey R2, Bitcask): every merge output gets `<path>.<id>.hint` (keys, lengths, offsets, expiry — no values — plus the data length covered and a CRC-32); `open` applies a valid hint instead of reading the file's records and replays only what lies past it. Missing, torn or inconsistent hints are ignored (replay); `read_verify` still checks values at `get`. VOPR harness: a crash swallowed by the post-commit deletion of retired files now counts as the epoch's fault instead of failing the next read.

- **2026-10-14** — Partial, concurrent merge (S2 survey R3/R4): `Db.fileStats` (Bitcask `status`), `Db.mergePlan(gpa, MergeThresholds)` (Bitcask merge triggers/thresholds and defaults; `needs_merge`) and `Db.merge(ids)`, which rewrites only the given sealed files while writers and readers go on (only the final swap excludes them); deletion markers kept while an older unmerged file may hold the value, expired records turned into markers, outputs placed at the newest merged file's position. `compact` now also takes the merge lock. Crash sweep over partial merges, VOPR with random partial merges, a merger thread in the ThreadSanitizer stress test (which found and fixed an unlocked read of the active file's size by `fileStats`).

- **2026-10-14** — Multi-file log (S2 survey R3, Bitcask `max_file_size`): `Options.max_file_size` (default `default_max_file_size` = 2 GiB) seals the active data file and starts `<path>.<id>.data` before an append would cross it; a store that never reaches it is unchanged. The first rotation migrates the store: `<path>` becomes a manifest (format version 3) and the old file `<path>.0.data`. ⚠ An older build refuses a migrated store (`error.UnsupportedVersion`) — do not downgrade one. `compact` on a multi-file store merges every live record into new files and deletes the old ones. A bad record in a sealed file is refused (`error.Corrupt`); only the active file's torn tail is cut. Per-file live/dead accounting in `Db.DataFile`. Crash sweeps over rotation, migration and merge in all four modes, the no-sync sweep over rotations, a multi-file VOPR run (which found and fixed a merge cleanup that deleted files the new manifest already named).

- **2026-10-14** — Readers no longer wait for a writer's fsync (S2 survey R5, in-process half): `Db` now serializes writers with `lock` and guards the keydir with a new read-write lock taken exclusive only for the in-memory update, never across a write or fsync. Readers run in parallel and still never see a value before it is durable under the sync policy. Tests: a reader answered while a writer is parked in fsync; concurrent readers alongside puts/deletes/compactions on the real filesystem, clean under ThreadSanitizer. No API change.

- **2026-10-14** — Sync policy (S2 survey R1, Bitcask `sync_strategy`): `Options.sync: SyncPolicy` = `.always` (default, unchanged behaviour), `.none`, `.interval_ms`; `Options.sync_clock` (default new `Clock.monotonic`); `Db.sync()`. Under `.none`/`.interval_ms` a crash loses acknowledged writes back to the last barrier (`sync`, `compact`, `open`, interval sync) and recovers the state after a prefix of the writes; `close` syncs best-effort. Additive. New crash sweep over a `.none` workload in all four crash modes + unit tests; two mutants killed.

- **2026-10-11** — `Storage.tryLockShared` (`flock` `LOCK_SH`, non-blocking) behind a new optional vtable slot `tryLockShared` (default null → `error.LockUnsupported`), so no implementer has to change. `FsStorage` and `SimStorage` implement it (the sim models shared holders per handle, conversion both ways as `flock` does, release on close and on crash); the VOPR `FaultStorage` forwards it. For kvtree's read-only openers. Test: `sim: shared locks coexist and exclude an exclusive holder both ways`.

- **2026-10-11** — **FIX (test infrastructure):** `SimStorage.truncate` through an un-synced overwrite (with `allow_overwrite`) re-sliced the range's undo buffer to the cut, and the next `sync` or crash freed the shorter slice — an invalid free (`testing.allocator` panics; another allocator could be corrupted). The range is now clamped by its length only and undo restores `old[0..min(old.len, len)]`. Found by pagecache's model test; new test `sim: a truncate through an un-synced overwrite frees its undo buffer whole` (sync and crash paths), red with the old re-slice. Only `allow_overwrite` records undo buffers, so kv's own append-only tests never reached it; overwriting consumers' tests over `SimStorage` (pagecache) did.

- **2026-10-01** — `kv.Lock` (the `Db`'s lock: `std.Io.Mutex` when the storage has an `Io`,
  else a spinlock) is public, for wrappers that hold their own lock across `Db` calls
  (`sessions.KvStore`): `.{ .io = db.store.io }`.
- **2026-10-01** — **Fix: `Db` no longer spins on its lock under a fiber/evented `Io`.**
  A task suspended in `sync` while holding the spinlock was starved forever by a second task
  of the same thread spinning on it (found by the simio kv pilot). `Storage` gained
  `io: ?std.Io = null`, set by `FsStorage.storage()`; `Db` then locks with `std.Io.Mutex`.
  Io-less storages keep the spinlock. Additive: existing `Storage` literals still compile.
- **2026-09-30** — Key listing and per-key expiry (maturity task C9). `Db.keys(gpa, prefix)`:
  sorted copies of the live keys under a prefix (new `KeyList`). `Db.putExpiring(key, value,
  expires_at_ms)` / `Db.putTtl(key, value, ttl_ms)` / `Db.expiresAt(key) ?Expiry`: an expired key
  is absent to every read at once and dropped from memory and file by `open` and `compact`.
  Wall clock (`Options.clock`, default `CLOCK_REALTIME`, new `Clock`), read only while the store
  holds expiring keys. On-disk format **v2** (new op 2 with an `expires_at` field); a v1 store
  is upgraded by one compaction at its first expiring put, and stays v1 otherwise. ⚠ A build
  of `kv` older than this refuses a v2 file (`error.UnsupportedVersion`) — do not downgrade a
  store that has used expiry. A deleted key whose expiry had already passed still gets its
  tombstone, so a wall clock stepped back cannot revive it. Crash sweep over the upgrade and
  expiry workload in all four crash modes; mutation-checked (22 of 23 killed, the survivor
  equivalent to the CRC check).

- **2026-09-29** — `Storage.list(gpa, prefix)`: the backend's files under a prefix, sorted, as an
  owned `Storage.Listing`; `null` from a backend that cannot list (new optional
  `VTable.list`, default `null`). `FsStorage` and `SimStorage` implement it (the simulator lists
  its volatile namespace, a pure read). For recovery and tooling — `Db` never lists
  (requested by egw-hub's `seglog` manifest rebuild).

- **2026-09-28** — `Storage.OpenMode.create_new`: create the file or fail with the new
  `error.PathAlreadyExists` (`O_CREAT|O_EXCL`), atomically, never emptying an existing
  file. `SimStorage` models it (an un-synced name is taken until a crash loses it).
  ⚠ Implementers of `Storage` that switch on `OpenMode` must handle the new mode; the
  added error widens `Storage.Error`.
- **2026-09-27** — `Storage.allocate` (`fallocate`, returns `false` when the backend or
  filesystem cannot) and `Storage.syncData` (`fdatasync`, `sync` where absent): optional
  vtable slots defaulting to `null`, so no implementer has to change. `FsStorage` has
  both on Linux. `SimStorage` models reserved zeros: a write into them is not an
  overwrite for the tripwire, and is lost, torn or reordered by a crash like any
  un-synced write although it did not grow the file. Measured: appends into reserved
  space + `fdatasync` 2.7× the rate of growing the file (ext4, NVMe).
- **2026-09-22** — `Storage.OpenMode.read_only`: open an existing file for reading
  only — never created (`error.FileNotFound`), emptied or written (`writeAll`/`truncate`
  → `error.AccessDenied`, refused by the backend). ⚠ Implementers of `Storage` must
  switch on `OpenMode` exhaustively; `mode == .create_truncate` would treat the new
  mode as `open_or_create` and create the file a reader expected to find.
- **2026-08-11** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Bitcask
  (Go) (design reference, not a test anchor).
- **2026-07-04** — New module: Crash-consistent embedded KV store (Bitcask-style log +
  randomized seeded VOPR: model-checked crash recovery across fuzzed fault schedules).
