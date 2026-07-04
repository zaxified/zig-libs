# SPEC — `ramcache`

Bounded in-memory cache with **two independent freshness axes**: TTL (wall-time) + **generation**
(logical invalidation — bump a counter to invalidate everything, stale entries drop lazily on next
read, no sweep). Wave P1 (cleanest lift-out). `extract · any · util · single_owner`. **Seed: extract
from `~/CML/poc-wf-analytic/src/cache.zig`** (same authors' code, relicense MIT). Deps: **none**.
**This REPLACES the existing `modules/ramcache/` stub** (currently `isFresh` placeholder).

## Why

A reusable bounded cache that expires by TTL *and* by a generation counter (invalidate-all on a data
change, lazy drop). The poc-wf version is complete, pure-`std`, headless-tested (`zig build
test-cache`, 8 tests) — lift it out as a standalone module. Consumers: any hot-path cache; `metrics`/
`ratelimit`-style modules could use it later.

## Scope

1. **Extract + generalize:** read the seed, lift the cache out, drop poc-wf coupling. Keep the exact
   semantics: TTL freshness + **generation-tie** (an entry stamped at generation G is stale once the
   caller's current generation > G; dropped lazily on the next `get`, no sweep). Byte-cap + entry-cap
   with **expired-then-LRU** eviction.
2. **Clock + generation are caller-supplied** (as in the seed) → zero global/time dependency, fully
   deterministic tests. `get`/`put` take `now_ns` (and the current generation) as parameters, or the
   cache holds an injected clock — match the seed's shape.
3. **Concurrency = single-owner (documented):** the seed is poll-loop-owned, no internal lock. Keep
   that — the cache is NOT internally synchronized; the caller owns it from one thread (or guards it).
   Document this clearly (it's the `single_owner` concurrency tag). Do not add a lock (a caller who
   needs one wraps it).
4. **Ops:** `put(key, value, ttl_ns, generation)`, `get(key, now_ns, generation) ?[]const u8`
   (drops + returns null if expired or stale-gen), `clear`, `stats` (hits/misses/entries/bytes),
   `config`/tunables (max_bytes, max_entries, default_ttl). Match the seed's surface. Keys/values are
   byte slices; document ownership (the cache copies values into its own arena/buffer, or borrows —
   match the seed).

## Public API sketch (final = the seed's shape)

```zig
pub const Cache = struct {
    pub fn init(gpa, Options) Cache;   // max_bytes, max_entries, default_ttl_ns
    pub fn deinit(*Cache) void;
    pub fn put(self, key: []const u8, value: []const u8, ttl_ns: i128, generation: u64) !void;
    pub fn get(self, key: []const u8, now_ns: i128, generation: u64) ?[]const u8;  // lazy-drops stale
    pub fn clear(self) void;
    pub fn stats(self) Stats;   // { hits, misses, entries, bytes, evictions }
};
```

## Acceptance / verification

- **Offline unit tests (port the seed's 8 + add; deterministic via injected now/generation):** hit
  within TTL, miss after TTL (advance `now`), **generation bump invalidates lazily** (old entry
  returns null after gen increment, without a sweep), LRU eviction at `max_entries`, byte-cap
  eviction at `max_bytes` (expired-then-LRU order), `clear`, `stats` counts (hits/misses/evictions),
  value-ownership correctness (returned bytes valid until overwritten/evicted — match seed). No real
  clock in tests.
- `zig build test-ramcache` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. (The build already registers `ramcache`; just replace the stub's `src/root.zig` + README.)

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 (HashMap unmanaged, intrusive LRU list, arena/allocator for
  value storage). This is an **EXTRACTION** — preserve the seed's proven eviction + generation logic
  and port its tests; don't redesign.
- Keep it dependency-free, portable, single-owner (no internal lock — documented).
- Provenance: README `Provenance:` line = "extracted from poc-wf-analytic `src/cache.zig` (same
  authors, relicensed MIT)". `model_after` = "groupcache / ristretto; generation-tie is the novel
  bit". SPDX MIT header. No NOTICE entry (own code).
