# writebehind — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-05** — **Fix: `flushAll` could stop with a record still pending.** On its synchronous
  backstop path (a reopened WAL nobody `recover()`ed) `flushOneSync` read the key through a lease
  `ack` had already freed, then leased that key's next record and dropped the lease, hiding it
  for the 60 s visibility timeout. It now copies the key first and hands the next record to the
  pool. Mutation run: 26 of 32 killed, 4 equivalent, 1 exposed this bug, 1 not killable by a
  value test (the use-after-free itself); 6 tests added (the regression, `put` after `del`, read-through failure,
  `recover` of a delete, `drain()` over two records of one key, one sink call in flight per key).
- **2026-10-01** — **Fix: `KvtreeSink` no longer spins on its lock under a fiber/evented `Io`.**
  It held a spinlock across `kvtree` writes (an fsync each); concurrent flush tasks on one
  thread spun on it forever while the holder was suspended. It now uses `kvtree.Lock`
  (`std.Io.Mutex` when the `Db`'s storage has an `Io`). Found by the spinlock audit that
  followed the simio kv pilot.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Caffeine
  `writeBehind` / a DB buffer pool (design reference, not a test anchor).
- **2026-07-22** — New module: crash-safe write-behind cache coordinator.
