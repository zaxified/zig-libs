# writebehind — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-18** — **NO CONSUMER-VISIBLE CHANGE (tests and docs):** whole-module mutation audit of `src/root.zig`, 280 mutants, 250 killed, 24 equivalent or unobservable and 6 open (card replaced: it was a cumulative 45/52 over a 32-mutant run of unknown base). 29 tests added (WAL refusal errors, every flush path acking its record, lease lifetime, injected clocks, allocation failures in `startFlush`, a refused pool submit, `flushOneSync` and `deinitNoFlush` behaviour) and the test `FailingSink` no longer leaves a freed key in its map on an overwrite. Two defects recorded, not fixed: `flushAll` returns with records pending when `retry_backoff_ns > 0` or a synchronous flush is rejected, and `deinitNoFlush` leaks the tasks of queued jobs it drops (SPEC "Findings of the audit").
- **2026-11-18** — **API addition:** back-pressure for `put`/`del`. `Options.max_unflushed` (entries, default 0 = unbounded, so existing users see no change) is a high-water mark on `pendingCount()`; at the mark the writer drives the flush and waits up to `Options.put_block_ns` (default 60 s, Kafka's `max.block.ms`; 0 = no wait), then fails with the new `PutError.Backpressure`, having written nothing. A caller that switches on `PutError` exhaustively must handle the new member. Ehcache `queueSize` / Kafka `buffer.memory`+`max.block.ms` semantics, see SPEC "Back-pressure".
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

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
