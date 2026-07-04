# ramcache

Bounded in-memory cache with **two independent freshness axes**: TTL (wall-time)
and **generation** (logical invalidation — bump one counter to invalidate every
generation-tied entry at once; stale entries drop **lazily on the next `get`**,
no sweep). Byte-cap + entry-cap, **expired-then-LRU** eviction (an already-expired
entry is always the first victim, else the least-recently-used).

Provenance: extracted from poc-wf-analytic `src/cache.zig` (same authors,
relicensed MIT).

- **Model after:** Go `groupcache` / `ristretto`; the generation-tie is the novel bit.
- **Platform:** any (pure `std`, dependency-free). **Role:** util.
- **Concurrency:** `single_owner` — NOT internally synchronized, no lock by
  design. One thread/event loop owns the instance; wrap it in your own lock if
  you must share it.
- **Determinism:** the caller supplies the clock (`now_ns`) and the generation
  counter on every call — zero global/time dependency, fully deterministic tests.

## API

```zig
const ramcache = @import("ramcache");

var c = ramcache.Cache.init(gpa, .{
    .max_bytes = 32 << 20, // cap on stored value bytes
    .max_entries = 4096,   // cap on entry count
    .default_ttl_ns = 0,   // TTL used by putDefault; <= 0 = no time expiry
});
defer c.deinit();

// ttl_ns <= 0 = never expire by time; gen == 0 = TTL-only (gen-bump immune).
c.put(key, value, now_ns, ttl_ns, gen);   // dupes key+value; no-ops on OOM
c.putDefault(key, value, now_ns, gen);    // put with options.default_ttl_ns

// null = miss (expired / stale-gen entries are dropped in passing).
if (c.get(key, now_ns, cur_gen)) |bytes| { ... }

c.clear();     // drop everything; lifetime counters survive
_ = c.stats;   // hits/misses/evictions/expired (lifetime) + entries/bytes (current)
```

**Ownership:** keys and values are copied into the cache's allocator on `put`.
A slice returned by `get` borrows the cache's storage — valid only until that
key is replaced, evicted, or cleared; copy it if you need it longer.

**Semantics:** an entry stamped with generation `G != 0` is stale as soon as the
caller's `cur_gen != G` — the idiom is "DB-derived entries die the instant a data
refresh bumps the generation", with external TTL-only entries (`gen == 0`)
unaffected. An item larger than `max_bytes` is never stored.

Tests: `zig build test-ramcache` (deterministic — injected `now_ns`/generation,
no real clock).
