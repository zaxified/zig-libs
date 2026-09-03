# filestore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit. **Writes are now `fsync`ed: the temp before
  the rename, the directory after it.** The module described itself as a
  "DB-less **durable** keyed document store" with "crash safety by
  construction" and issued **no `fsync` at all** — measured on its own example
  with `strace`: 5 renames, 0 fsyncs. Temp-then-rename without those two syncs
  buys tear avoidance and nothing else: a reader never sees a half-written
  record, but after a power loss a `putBytes` that RETURNED can be missing
  entirely (the rename was never durable) or present over blocks that were
  never written. The word `fsync` appeared nowhere in the module, its SPEC or
  its README. The sibling `blobstore` — same shape, same store-a-file-then-
  rename — has fsynced its temp since its own audit ("durability: fsync before
  it becomes visible"); this module never followed. Re-measured after the fix:
  5 renames, **10 fsyncs**. ⚠ The directory `fsync` needs the directory
  re-opened with `.iterate = true`: std's default handle is `O_PATH`, which
  cannot be fsynced at all. That workaround is `kv`'s `FsStorage.vSyncDir`,
  reused rather than re-derived, and the existing suite pins it — dropping
  `.iterate` turns `zig build test-filestore` red.
- **2026-08-18** — New `Store.ttl: bool = true` option: set it `false` on a store that
  never calls `putWithTTL` to skip the `.expiry` sidecar probe on every `getBytes`
  (was unconditional — an extra syscall per get, doubling the cost of a
  `list`-then-`get` sweep for a store with no TTLs). `putWithTTL` now refuses with
  `error.TtlDisabled` on a `ttl = false` store instead of creating a sidecar that
  store's own `getBytes` would then never check — matches the shape of `blobstore`'s
  `refcount = false` -> `casDelete` -> `error.RefcountDisabled`. `sweep` is still
  unaffected by the flag either way. Remaining hazard, still reachable: `ttl = false`
  does not delete or ignore a *pre-existing* `.expiry` sidecar (one written while the
  store had `ttl = true`, or by a differently configured writer sharing the same
  `base`) — such a record keeps being served past its deadline instead of reported
  absent. Only opt out on a store certain to have no pre-existing TTL'd records.
- **2026-08-18** — `readExpiry` no longer reaches for `std.heap.page_allocator`: the
  `.expiry` sidecar read (capped at 32 bytes) now goes into a fixed stack buffer via a
  direct positional read, so the module never touches a hidden global allocator
  (CONVENTIONS.md §1.2).
- **2026-07-18** — Security audit: no findings.
- **2026-07-09** — New module: DB-less durable keyed document store — one
  atomically-written file per record + a typed-JSON convenience layer.
