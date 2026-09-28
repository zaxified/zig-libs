# kv — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
