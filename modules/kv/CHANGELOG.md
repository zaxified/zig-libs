# kv — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
