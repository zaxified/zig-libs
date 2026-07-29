# ramcache

Bounded in-memory cache with **two independent freshness axes**: TTL (wall-time)
and **generation** (logical invalidation — bump one counter to invalidate every
generation-tied entry at once; stale entries drop **lazily on the next `get`**,
no sweep). Byte-cap + entry-cap, **expired-then-LRU** eviction (an already-expired
entry is always the first victim, else the least-recently-used).

Provenance: original work of the zig-libs authors (MIT); the W-TinyLFU
admission/eviction upgrade is clean-room from the TinyLFU paper (Einziger &
Friedman) with design refs Caffeine and ristretto — see NOTICE.

- **Model after:** Go `groupcache` / `ristretto`; the generation-tie is the novel bit.
- **Platform:** any (pure `std`, dependency-free). **Role:** util.
- **Concurrency:** `Cache` is `single_owner` — NOT internally synchronized, no
  lock by design. One thread/event loop owns the instance. To share a cache
  across threads use **`Sharded`** (below), a wrapper *alongside* `Cache`, so
  the single-owner hit path stays lock-free.
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

**Write-behind seam (opt-in):** every entry has a dirty bit (`put` sets it;
`markClean(key)` clears it; `isDirty(key)` reads it), and `Options.on_evict` fires
just before a value is freed on eviction, replacement, or clear — see SPEC.md for
the full contract. A periodic flusher drains proactively; `on_evict` is the safety
net so an unpersisted write is never silently dropped:

```zig
fn onEvict(ctx: ?*anyopaque, key: []const u8, value: []const u8, dirty: bool, reason: ramcache.EvictReason) void {
    if (dirty) persistNow(key, value); // last-chance flush before the memory goes away
}

var c = ramcache.Cache.init(gpa, .{
    .max_bytes = 32 << 20,
    .max_entries = 4096,
    .on_evict = onEvict,
});

const Flusher = struct {
    fn drain(ctx: ?*anyopaque, key: []const u8, value: []const u8) void {
        persist(key, value); // caller calls c.markClean(key) once durable
    }
};
c.drainDirty(Flusher.drain, null); // call periodically
```

## `Sharded` — the thread-safe option

`ramcache.Sharded` holds **N independent `Cache` instances**, each behind its own
spinlock, selected by a hash of the key. `Cache` itself is untouched: a
single-owner consumer keeps its lock-free hit path.

```zig
var sc = try ramcache.Sharded.init(gpa, .{
    .max_bytes = 32 << 20,  // AGGREGATE budget — divided by the shard count
    .max_entries = 4096,    // ditto
    .shards = 16,           // rounded up to a power of two, clamped (see below)
});
defer sc.deinit();

sc.put(key, value, now_ns, ttl_ns, gen);   // same contract as Cache.put

// Zero-allocation read: the value is copied into YOUR buffer under the lock.
var buf: [4096]u8 = undefined;
switch (sc.getBuf(key, now_ns, cur_gen, &buf)) {
    .ok => |v| use(v),                       // v aliases `buf`, not the cache
    .miss => fetchFromOrigin(),
    .buffer_too_small => |need| retryWith(need),
}

// Or an allocator-owned copy when you have no size bound:
if (try sc.get(key, now_ns, cur_gen)) |owned| {
    defer sc.free(owned);
    use(owned);
}
```

**There is no borrowed-slice `get`, deliberately.** `Cache.get` hands back a
slice into cache storage; another thread can evict that entry the instant the
lock is released, so that contract cannot be honoured concurrently. Both reads
above finish copying before the lock drops. The signatures differ from
`Cache`'s on purpose — single-owner code pasted across fails to *compile*
instead of corrupting memory under load.

**What sharding costs** (`Sharded`'s doc comment has the full statement):

- **Eviction is per shard.** The admission gate, the frequency sketch, the
  doorkeeper, the aging counter and the recency order are all per shard, so each
  sketch sees ~1/N of the traffic and admission quality drops. `max_bytes` /
  `max_entries` are floor-divided per shard, so a hot shard evicts while a cold
  one has room, and a single value must fit `max_bytes / N`.
- **Aggregate operations are not atomic across shards.** `stats()` is an
  approximate, per-shard-consistent snapshot; `clear()` guarantees only that each
  entry present when its shard was locked is gone; `drainDirty` visits each entry
  dirty at the time its shard was locked.
- **`on_evict` now fires from any thread, with a shard lock held.** It must be
  thread-safe, cheap, and must **not** call back into the same `Sharded` (a
  deadlock, not a detected error). Same for `drainDirty`'s callback — which is
  why the async flusher's ack is `markCleanIf(key, flushed_value)`, a
  compare-and-clear that refuses to ack a value another thread has overwritten.

Tests: `zig build test-ramcache` (deterministic — injected `now_ns`/generation,
no real clock; the `Sharded` concurrency tests use real threads).
