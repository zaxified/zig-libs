# readthrough

A backend-agnostic **read-through cache coordinator** — the read-path
counterpart to `writebehind`. `get(key)` serves a fresh cached value; on a miss
it calls the caller-supplied **loader** (fetch from Postgres, an upstream API, a
compute), stores the result with a TTL, and returns it. Concurrent misses for
the same key **coalesce into a single loader call** (single-flight / cache-
stampede guard) — the headline value of the module.

It is NOT a storage engine: it composes `ramcache` (W-TinyLFU + TTL +
generation invalidation) for storage and adds the orchestration `ramcache`
lacks — single-flight, read-through fetch, negative caching, and explicit
invalidation.

- **Model after:** Go `singleflight` + Caffeine `LoadingCache`, over a W-TinyLFU
  store.
- **Platform:** any (the `std.Io` futex, `std.Thread`, and `std.atomic` are all
  cross-OS). **Role:** util. **Concurrency:** `threadsafe` — `get` /
  `invalidate` / `invalidateAll` are safe to call from any number of OS threads
  at once.
- **Deps:** `ramcache` (storage) + `std`.

Provenance: original work of the zig-libs authors (MIT). The single-flight
coalescing shape follows Go's `singleflight` and the loader shape follows
Caffeine's `LoadingCache` — both **design references** (behavior and API shape
only, no source consulted or copied), recorded in the root
[`NOTICE`](../../NOTICE). The W-TinyLFU store underneath is
[`ramcache`](../ramcache), which carries its own entry.

## Contracts

- **Read-through:** a miss runs the loader exactly once (per coalesced set), the
  result is stored, and subsequent fresh reads are served from `ramcache`
  without touching the backend.
- **Single-flight:** while one caller ("the leader") is loading a key, every
  other caller for that key ("followers") blocks on an `std.Io` futex and shares
  the leader's one result — no thundering herd. Proven under real threads
  (`loads == 1`, `coalesced == N-1`).
- **TTL:** each positive entry carries `ttl_ns` (`<= 0` = never expire by time);
  a fresh get past the TTL reloads. Time is injectable (`Options.clock`) so TTL
  is testable without sleeping; production reads the monotonic `std.Io` clock.
- **Invalidation:** `invalidate(key)` forces the next `get(key)` to reload;
  `invalidateAll()` invalidates every entry at once via a `ramcache` generation
  bump (O(1), no sweep — stale entries drop lazily). An invalidation *during* an
  in-flight load still delivers the loaded value to that load's coalesced
  callers, but does NOT write it to the cache, so the next get reloads (the
  invalidation is never lost).
- **Negative caching (opt-in):** with `negative_ttl_ns > 0`, a loader "not
  found" is cached for that short TTL so a missing key stops hammering the
  backend, then is retried after it expires. With `cache_loader_errors = true`,
  a loader *error* is negatively cached too (off by default — backend errors are
  usually transient); a cached-error hit returns `error.CachedLoaderError`.

See `SPEC.md` for the concurrency model + rationale, the single-flight
mechanism, the exact invalidate-during-load / TTL=0 / loader-panic edge
semantics, and the deliberately-deferred list (including stale-while-revalidate).

## Ownership / return contract

Because this cache is thread-safe, `get` returns an **owned copy** of the value
(free it with `Cache.free`) — returning a slice into cache storage would be
unsafe when another thread can evict it concurrently. For an allocation-free hit
path, `ifCached(key, ctx, f)` hands the borrowed value to a callback while the
lock is held.

## Memory profile (qualitative)

- A **hit** allocates one owned copy of the value (the return) and nothing else;
  `ifCached` is the zero-allocation hit path.
- A **miss** allocates one small single-flight `Call` + one owned in-flight key,
  both freed the instant the load completes. The in-flight map is bounded by the
  number of *concurrently loading distinct keys*, not the key population — **no
  per-entry heap churn at scale**.
- Stored values live in `ramcache`, bounded by `max_bytes` / `max_entries`
  (W-TinyLFU eviction), plus one tag byte per stored value.

## API

```zig
const readthrough = @import("readthrough");

// The backend fetch — generic (ctx + fn), so it fits Postgres/HTTP/compute.
fn load(ctx: ?*anyopaque, key: []const u8) anyerror!readthrough.LoadOutcome {
    _ = ctx;
    const row = queryBackend(key) catch |e| return e; // transient error → propagates
    return if (row) |v| .{ .value = v } else .missing; // "not found" → negative
}

var c = readthrough.Cache.init(gpa, .{
    .io = io,                       // futex for coalesced-follower waits
    .loader = .{ .load = load },
    .ttl_ns = 5 * std.time.ns_per_s,       // positive-entry TTL (0 = no time expiry)
    .negative_ttl_ns = 500 * std.time.ns_per_ms, // 0 disables negative caching
    .cache_loader_errors = false,          // opt-in error caching
    .max_bytes = 64 << 20,
    .max_entries = 100_000,
    // .clock = myClock,             // optional; deterministic tests inject here
});
defer c.deinit();                   // requires all get()s to have returned (quiescence)

const r = try c.get("user:42");     // hit, or single-flight load → store → return
switch (r) {
    .value => |v| { defer c.free(r); use(v); },
    .missing => {},                 // absent at the backend
}

c.invalidate("user:42");            // next get(key) reloads
c.invalidateAll();                  // generation bump — everything reloads
const s = c.getStats();             // hits / misses / loads / coalesced / ...
```

## Tests

`zig build test-readthrough` (and `-Doptimize=ReleaseFast`) is green and
`DebugAllocator`-clean (no leaked `Call` / in-flight key / value). Deterministic
unit tests (injected manual clock, a counting loader) cover read-through basics,
distinct-key independence, TTL expiry, `invalidate`/`invalidateAll`, negative
caching (miss + opt-in error, with retry after the negative TTL), and the
`ifCached` zero-alloc path. Real-thread tests (`src/tests.zig`) prove
single-flight deterministically — a **gated loader** makes the leader block
inside the load until the test observes every follower has coalesced, so "the
loader ran exactly once" is a hard guarantee (also the permanent positive
control), plus independently-owned follower copies, invalidate-during-load, and
a mixed-key soak under contention.
