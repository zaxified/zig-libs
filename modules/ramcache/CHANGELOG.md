# ramcache — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-21** — **A cache under miss pressure no longer degrades to a
  whole-table probe per lookup.** std's open-addressing map leaves a tombstone
  per removal and hands the slot back to `available`, so a remove-then-insert
  workload -- every miss on a full cache -- never triggered the rebuild that
  clears them; the table filled with tombstones until no free slot was left,
  and each lookup of an absent key (the `pin` before every `reserve`) walked
  all of it. Measured through pagecache over a flat backend (4 KiB pages,
  93 % misses, ReleaseFast): 74 000 / 212 000 / **697 000** user instructions
  per access at 64 / 256 / 1 024 entries -- 92 % in the probe loop -- against
  **30 000 at every size** once `maintain` rebuilds the index after removals
  reach a quarter of its capacity (`Stats.rehashes` counts them). Found by a
  qap perf audit: a kv-store GET whose store outgrew its page cache cost
  8x a hit. Test: 4 096 puts through a 64-entry cache rebuild at least once
  and the live keys still answer.

- **2026-09-03** — **`put` over a resident key no longer leaves the OLD value
  behind when its value dupe fails.** `put` cannot report failure, and
  `pagecache`'s write-through refresh calls it *after* the durable write has
  landed — so the cache went on serving pre-write bytes as a hit,
  indefinitely, over correct media. The `max_bytes` branch three lines up
  already reasons this out by name ("keeping the old bytes would serve
  pre-write data indefinitely") and calls `dropKey`; the allocator path did
  not. Absent is a miss, stale is corruption.
- **2026-09-03** — New: `removeMatching(prefix)`, removing every resident entry
  whose key starts with `prefix` and returning the count. For callers whose
  invalidation scope is a key prefix rather than one key or the whole cache —
  `pagecache` forgetting one file handle's pages on close, where the
  alternatives were a full `clear()` or a side table that grew with the store
  instead of the cache. Allocation-free and therefore infallible.
- **2026-08-11** — Security audit: fifteen findings fixed, one documented as accepted
  (not defects) — part of the collection-wide audit. Modeled on Caffeine (Java,
  conceptual) (design reference, not a test anchor).
- **2026-07-29** — A thread-safe option, `Sharded` — N independent `Cache` instances, one
  lock each, picked by a hash of the key. `Cache` is unchanged and stays
  `single_owner`/lock-free; the five modules that own one from a single
  thread pay nothing. `Sharded` cannot mirror `Cache.get`, whose returned
  slice borrows cache storage and would dangle the moment the lock drops,
  so reads copy under the lock: `getBuf(key, …, buf)` into a
  caller-supplied buffer (with a distinct `buffer_too_small` result, not a
  fake miss) or `get` returning an allocator-owned copy freed with `free`.
  The costs are stated rather than glossed: every piece of W-TinyLFU state
  is per shard (each sketch sees ~1/N of the traffic), `max_bytes`/
  `max_entries` are floor-divided so a hot shard evicts while a cold one
  has room and a single value must fit `max_bytes / N`, and
  `stats`/`clear`/`drainDirty` walk the shards one lock at a time and are
  therefore not atomic across them. On a `Sharded`, `on_evict` fires from
  whichever thread triggered the removal with a shard lock held, so it
  must be thread-safe and must not re-enter that `Sharded`; its
  `drainDirty` callback carries the same restriction, so
  `Cache.drainDirty`'s allowance to call `markClean` from inside the
  callback does **not** carry over to `Sharded`, whose async-flusher ack
  is `markCleanIf(key, flushed)` — a compare-and-clear that will not ack a
  value another thread has overwritten. All of that is `Sharded`'s
  contract only: `Cache` keeps its callback rules, its single-owner
  `on_evict`, and has no `markCleanIf`.
