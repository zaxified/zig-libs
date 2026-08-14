# readthrough — design & threat notes

Purpose and API: see [README.md](README.md). This document is the auditor-facing
"how/why it was built, and what could go wrong" reference; it does not restate
the API or the meta tags (those live in `README.md` and `src/root.zig`).

## 1. Concurrency model — why `.threadsafe`

A read-through cache's whole value proposition is protecting an expensive
backend from concurrent misses (the cache stampede). That protection is only
real if the coalescing works **across OS threads** — a single-owner design would
push the locking onto every consumer and could not coalesce two threads' misses
at all. So `readthrough` is `.threadsafe`: it owns its synchronization.

**Primitive.** Zig 0.16 removed `std.Thread.Mutex` / `Condition` / `Futex`
(futexes moved onto the `std.Io` vtable). Following the repo's established
pattern (`writebehind`, `lockfree`, `workerpool`), shared state is guarded by a
tiny `std.atomic` **SpinLock** for the short critical sections (map lookup,
`ramcache` access, generation read, stats), and coalesced followers **block on
an `std.Io` futex** (`futexWaitTimeout` in a re-check loop, woken by
`futexWake`) rather than busy-spinning — the loader can be slow (a DB round
trip), so spinning followers would waste cores. This is exactly the
`workerpool` idle-wait pattern. `ramcache` is itself `single_owner` and
lock-free by design; serializing **every** access to it under our one SpinLock
is what makes the composite thread-safe.

**The loader runs outside the lock.** The single expensive step (the backend
fetch) must not hold the lock, or all other keys' `get`s would stall behind one
slow load. So the leader registers an in-flight `Call` under the lock, releases
it, runs the loader, then re-acquires the lock to store the result and publish
it. Consequence (documented): a loader must not re-enter `get` for the *same*
key (it would become a follower of itself and deadlock), and must not panic
(Zig does not unwind — a panic aborts and strands the in-flight `Call`; the
process is dead anyway, so this is a "don't" not a recovery path).

## 2. Single-flight mechanism

State: `in_flight: StringHashMap(*Call)`. A `Call` is a reference-counted
rendezvous with an atomic `done` word (the futex), an owned result buffer, and a
`poisoned` flag; every field except `done` is under the SpinLock.

`get(key)` under the lock:

1. **Fresh hit** → copy the value out (under the lock, since another thread may
   evict it the instant we unlock) and return an owned copy.
2. **Miss, key already in flight** → become a *follower*: bump the `Call`
   refcount, unlock, park on `done`, then read the shared result into an
   owned copy and drop the ref.
3. **Miss, no in-flight** → become the *leader*: create a `Call`, insert it
   (owning a duped key), unlock, run the loader, re-lock, remove the in-flight
   entry, store the result in `ramcache` (unless poisoned), publish
   (`done = 1` + `futexWake`), and return.

Exactly one leader is guaranteed because the check-and-insert happens under a
single lock acquisition: whoever first reaches "miss + not in-flight" inserts;
every later lock holder sees the entry and coalesces. No lost wakeup: followers
`futexWaitTimeout` with `expected = 0` and re-check `done` on each wake, so a
completion that races the park returns immediately.

**Refcounting / lifetime.** Leader starts the `Call` at `refs = 1`; each
follower increments under the lock while the `Call` is still reachable in the
map. The last participant to leave frees the `Call` and its buffer. The leader
issues the `futexWake` *before* dropping its own ref, and only frees if it is
the last out (i.e. there were no followers) — so a follower is never woken on
freed memory.

**Determinism of the test.** `loads == 1` is proven, not observed by luck: the
test's loader blocks inside `load` on a gate the test opens only after
`getStats().coalesced == N-1`, i.e. after every follower has provably joined the
one in-flight `Call`. Deleting the `in_flight.get` dedup turns the same test RED
(`loads == N`, `coalesced == 0`) — the permanent positive control.

## 3. Storage, TTL, and the tag byte

Stored bytes are `[tag][payload]`: `V` = positive (payload = value), `N` =
negative "not found" (no payload), `E` = negative cached-error. On a hit the tag
byte selects the return shape. This keeps positive and negative entries in the
one `ramcache` instance under one set of caps, at one byte overhead per value.

TTL and the clock come straight from `ramcache`'s injected-clock design: `get`
passes `now` (from `Options.clock`, or the monotonic `std.Io` "awake" clock) and
the current generation to `ramcache`, which does the freshness check and lazily
drops a stale entry. **`ttl_ns <= 0` = never expire by time** (an entry lives
until evicted or invalidated). **`negative_ttl_ns <= 0` disables negative
caching** entirely (every miss re-hits the loader).

## 4. Invalidation semantics

- **`invalidateAll()`** bumps a generation counter (starts at 1, always
  nonzero, so entries are generation-tied). Entries stored under the old
  generation are seen stale by the next `get` and dropped lazily by `ramcache` —
  O(1), no sweep. This is precisely `ramcache`'s generation axis, used as
  intended.

- **`invalidate(key)`** is the one thing `ramcache` does *not* offer directly:
  it has `get` / `put` / `clear` / generation, but **no per-key remove** (see
  §7). So a single-key invalidation shadows the entry by overwriting it with a
  reserved **poison generation** (`maxInt(u64)`, which the live generation never
  reaches), making the next `get` see it stale and drop it. To avoid inserting a
  junk entry for a key that was never cached, presence is first probed with
  `ramcache.isDirty` — a side-effect-free test that is exact here because every
  entry `readthrough` stores is dirty (it never calls `markClean`).

- **Invalidate during an in-flight load.** Both `invalidate(key)` and
  `invalidateAll()` set the `poisoned` flag on any matching in-flight `Call`.
  The leader, on completion, checks `poisoned` under the lock: if set, it still
  delivers the loaded value to that load's coalesced callers (they asked; they
  get a coherent answer) but does **not** write it to the cache. Net contract:
  **an invalidation is never lost** — the value a caller receives may be the one
  that was just invalidated, but the *cache* does not durably serve it; the next
  `get` reloads. This is uniform for single-key and all-key invalidation and is
  tested under real threads.

## 5. Ownership / return contract

`get` returns an **owned** value (freed via `Cache.free`), not a borrowed slice
into cache storage. Under `.threadsafe`, a borrowed pointer would be a
use-after-free waiting to happen (another thread evicts/replaces the entry after
the lock is released). This deliberately diverges from the `single_owner`
`ramcache`/`writebehind` borrow-until-next-mutation contract — it is the price
of thread safety. `ifCached(key, ctx, f)` is the escape hatch for a zero-copy,
zero-allocation hit: it invokes `f` with the borrowed value **while holding the
lock**, so `f` must be cheap and non-reentrant.

## 6. Failure / edge semantics

- **Loader transient error** → propagated from `get` as a Zig error; by default
  *not* cached (a "DB down" error is usually transient — caching it would extend
  the outage). Opt in with `cache_loader_errors` (bounded by `negative_ttl_ns`);
  a later hit on a cached error returns `error.CachedLoaderError` (the original
  error value is not preserved across the cache boundary — only the fact of
  failure; in-flight followers of the same load do get the exact error).
- **OOM** anywhere in the store/return path is non-fatal to correctness: a
  failed `ramcache` store just means the next get reloads (a cache miss is never
  fatal); a failed return copy surfaces as `error.OutOfMemory`. The single
  in-flight `Call` is always cleaned up.
- **TTL = 0 / negative_ttl = 0** — see §3 (never-expire / negative-caching-off).
- **`deinit` quiescence** — `deinit` requires that every `get` has returned
  (no load in flight). Leaders remove their own in-flight entry on completion,
  so a quiesced cache's in-flight map is empty; a leftover would carry an
  undefined result and cannot be safely reclaimed. This mirrors `writebehind`'s
  single-owner-teardown requirement.

## 7. Where the coordinator brief was imprecise (recorded for the auditor)

The task brief said "`ramcache` already supports generation invalidation — reuse
it" for **both** `invalidate(key)` and `invalidateAll()`. That is accurate for
`invalidateAll` (the generation axis is exactly right) but **not** for
`invalidate(key)`: `ramcache` exposes no per-key remove, and its generation axis
is a single global counter, not per-key. The per-key path is therefore
implemented in this module via the poison-generation shadow described in §4,
using only `ramcache`'s public `get`/`put`/`isDirty`. No change to `ramcache`
was needed or made.

## 8. Deliberately deferred

- **Stale-while-revalidate (SWR).** Serving a stale entry immediately while a
  single background refresh runs is valuable but needs either a background
  executor (a `workerpool` dep this module intentionally does not take — it
  keeps a leader on the *caller's* thread) or an async runtime, plus a precise
  staleness-window contract. Deferred rather than half-built. The single-flight
  machinery is the right foundation to add it on later (the refresh would be a
  leader whose result replaces the stale entry while `get`s keep serving stale).
- **Per-key TTL / per-call loader.** TTLs are per-cache (positive + negative),
  and the loader is fixed at construction (one backend per cache). Per-key TTL
  or a per-`get` loader override are easy extensions but unneeded so far.
- **Refresh-ahead / probabilistic early expiration** (recompute a hot key just
  before its TTL to avoid a synchronous miss) — a natural follow-on to SWR;
  deferred with it.
- **Sharded lock.** One SpinLock serializes all access. At extreme core counts
  the lock (not the loader, which is off-lock) could contend; a striped-lock or
  sharded-map refinement is possible but unmeasured and unwarranted until a real
  workload shows it.
- **Metrics beyond the counters** (latency histograms, per-key load timing) —
  left to the consumer's observability layer.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** singleflight+cache loader, in-process, no wire
