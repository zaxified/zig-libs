# ramcache

Bounded in-memory cache with **two independent freshness axes**: TTL (wall-time)
and **generation** (logical invalidation — stale entries drop lazily on next read,
no sweep). Byte-cap + entry-cap, expired-then-LRU eviction.

- **Status:** `extract` — seeded in `~/CML/poc-wf-analytic/src/cache.zig` (complete,
  pure-std, headless-tested `zig build test-cache`). Cleanest immediate lift-out.
- **Model after:** Go `groupcache` / `ristretto`; the generation-tie is its novel bit.
- **Platform:** any. **Role:** util. **Concurrency:** single-owner (one loop owns it,
  lock-free — caller supplies clock + generation counter, so no global/time dependency).

Current file is a stub (`isFresh`) to establish the module shape.
