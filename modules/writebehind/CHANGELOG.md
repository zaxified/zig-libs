# writebehind — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-01** — **Fix: `KvtreeSink` no longer spins on its lock under a fiber/evented `Io`.**
  It held a spinlock across `kvtree` writes (an fsync each); concurrent flush tasks on one
  thread spun on it forever while the holder was suspended. It now uses `kvtree.Lock`
  (`std.Io.Mutex` when the `Db`'s storage has an `Io`). Found by the spinlock audit that
  followed the simio kv pilot.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Caffeine
  `writeBehind` / a DB buffer pool (design reference, not a test anchor).
- **2026-07-22** — New module: crash-safe write-behind cache coordinator.
