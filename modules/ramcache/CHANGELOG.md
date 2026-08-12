# ramcache — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- A thread-safe option, `Sharded` — N independent `Cache` instances, one
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
  therefore not atomic across them. `on_evict` now fires from any thread
  with a shard lock held, so it must be thread-safe and must not re-enter
  the cache; the same restriction on `drainDirty`'s callback withdraws
  `Cache.drainDirty`'s allowance to call `markClean` from inside it, and
  the async flusher's ack becomes `markCleanIf(key, flushed)` — a
  compare-and-clear that will not ack a value another thread has
  overwritten.
