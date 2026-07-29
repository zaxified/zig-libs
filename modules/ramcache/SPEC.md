# ramcache — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Bounded in-memory cache, two independent freshness axes.** Wall-time TTL (`ttl_ns <= 0` = never
  expires by time) and a logical *generation* counter (`gen == 0` = TTL-only; bumping the caller's
  `cur_gen` instantly stales every entry tied to the old generation). Stale entries drop **lazily on
  the next `get`** — no sweep thread, no timer. Algorithm modeled after W-TinyLFU (Einziger &
  Friedman) with a Caffeine-shaped window/SLRU and a ristretto-shaped anti-starvation tie-break —
  see NOTICE for the paper/prior-art citations; the generation-tie axis and the TTL+cap base are
  this module's own.
- **Eviction order:** any TTL-expired entry first (a free win), then the W-TinyLFU contest — a
  warm admission-window candidate takes the main-region LRU victim's slot only if its estimated
  recent frequency wins (deterministic ~1/128 coin breaks ties so a rotating population can't
  stall). Frequency lives in a fixed 4-bit Count-Min Sketch + doorkeeper with periodic halving.
- **Clock + generation are injected on every call** (`now_ns`, `cur_gen`) — zero global/time
  dependency, every test deterministic.
- **Ownership:** keys/values are duped into the cache's allocator on `put`, freed on
  evict/replace/clear; a `get` slice borrows cache storage, valid only until that key is next
  replaced/evicted/cleared. `bytes` accounts value payloads only.
- **Never-fatal degradation:** `put` silently no-ops on OOM (a miss is never fatal); if the
  frequency sketch itself can't allocate, the cache degrades to plain LRU (gate always admits).
- **Write-behind seam (opt-in), for a caller-driven persistence layer built on top:** every entry
  carries a *dirty* bit — `put` always sets it (a write not yet known to be durable); `markClean(key)`
  clears it; `isDirty(key)` reads it — none of the three touch stats, SLRU promotion, or the
  frequency sketch. `drainDirty(cb, ctx)` sweeps every currently-dirty entry once
  (`*const fn(ctx, key, value) void`, no removal, no allocation) for a periodic flusher.
  `Options.on_evict` (`*const fn(ctx, key, value, dirty, EvictReason) void` + `on_evict_ctx`, the
  same fn-pointer + `*anyopaque` pattern as `aaa-gate.AuditFn`/`coap.observe.AdmitFn`) fires
  synchronously just *before* an entry's value memory is freed, on every path an entry can leave the
  cache: `.evicted` (W-TinyLFU victim, a degenerate LRU fallback, **or** a lazy TTL/generation-stale
  drop from `get` — all three route through the same internal removal, so a dirty-but-stale entry is
  reported too), `.replaced` (`put` over an existing key — the outgoing old value/dirty bit),
  `.cleared` (`clear()`, fired once per entry). Never fires on a plain `get` hit or miss. This is the
  safety net against the eviction/flush race: `drainDirty` persists proactively and calls
  `markClean`; `on_evict`'s `dirty` flag catches whatever a periodic sweep didn't get to before
  capacity pressure or `clear()` removed it. **Opt-in and free when unused:** `on_evict` defaults to
  `null` (no-op), and the dirty bit costs one `bool` per entry but is never consulted internally — no
  callback set + dirty API unused ⇒ behavior and performance are byte-identical to before this
  existed.

## `Sharded` — the internally-synchronized wrapper

`Cache` stays lock-free; `Sharded` is a second type in the same module holding N `Cache` instances,
one spinlock each, keyed by `Wyhash(shard_seed, key) & (N-1)`. Full contract in its doc comment;
the design commitments an auditor needs:

- **Safety is structural, not empirical.** (1) Every field of a shard's `Cache` is touched only
  between `lockSpin` and `unlock` — `shards` is private and no `*Cache` escapes. (2) Nothing derived
  from a `Cache` outlives its critical section (no method returns a slice into cache storage).
  (3) A key maps to exactly one shard by a pure function of the key bytes, and entries never move,
  so no two shards share a byte. (4) No operation holds two shard locks at once — the aggregate
  operations walk shards sequentially. (1)+(2) reduce each shard to the serialized single owner
  `Cache` was written against; (3) makes correctness compose; (4) removes any lock order, hence any
  inter-shard deadlock.
- **Value handoff.** `getBuf(key, …, buf) GetResult` copies into the caller's buffer under the lock
  (`ok` aliases *that* buffer, `buffer_too_small` carries the needed length so a sizing bug cannot
  masquerade as a miss); `get` returns an allocator-owned copy released with `free`. Mirroring
  `Cache.get`'s borrowed slice is impossible to honour concurrently and is deliberately not offered;
  a `withValue`-style callback under the lock was rejected because `getBuf` already gives the
  zero-allocation path without running caller code inside a non-reentrant spinlock.
- **Eviction quality degrades by design.** Admission gate, CMS sketch, doorkeeper, aging counter and
  recency order are per shard — each sketch sees ~1/N of the traffic. `max_bytes`/`max_entries` are
  floor-divided, so the effective aggregate cap is `N × (cap/N)` (never above the request), a hot
  shard evicts while a cold one has room, and the single-item ceiling tightens to `max_bytes / N`.
  The shard count is rounded up to a power of two, then clamped down so no shard gets a zero cap.
  The shard hash uses a seed distinct from the sketch's: sharing it would confine each shard's keys
  to 1/N of the doorkeeper index space.
- **Aggregates are not atomic.** `stats` is per-shard-consistent and globally approximate — because
  the lifetime counters are monotonic, the returned sum lies between the true aggregate at the first
  shard read and the true aggregate at the last; `entries`/`bytes` are non-monotonic and get no such
  bound. `clear` guarantees only that every entry present in shard *i* when shard *i* was locked is
  gone (a writer may repopulate an already-cleared shard). `drainDirty` visits every entry dirty in
  shard *i* when shard *i* was locked, once.
- **`on_evict` contract change.** It now fires from whichever thread triggered the removal, with a
  shard lock held: it must be thread-safe, cheap, and must not call into the same `Sharded` — where
  `Cache` calls reentrancy "unsupported", here it is a hard deadlock. `drainDirty`'s callback has
  the same restriction, which is why `Cache.drainDirty`'s allowance to call `markClean` from the
  callback does **not** carry over. The async-flusher ack is therefore `markCleanIf(key, flushed)`,
  a compare-and-clear that refuses to ack a value another thread has since overwritten; plain
  `markClean` is kept, documented as racy under concurrent writes.

## Threat model / out of scope

`Cache` is not a security primitive and is **not thread-safe** (`concurrency = single_owner` — one
thread/loop owns the instance; a caller sharing it either supplies its own lock — `sessions`'
`RamcacheStore` and `readthrough` are the reference for that pattern — or uses `Sharded`). The
`meta.concurrency` tag names the primary type; `Sharded` is internally synchronized. Key hashing is
Wyhash, not keyed/DoS-resistant —
not hardened against adversarial hash-collision flooding; intended for trusted internal keys (query
strings, URLs), not attacker-chosen keys. No persistence — `on_evict`/dirty-set (see above) is a
*seam* for a caller-built write-behind layer, not persistence itself; the cache does no I/O and
`on_evict` must not call back into the `Cache` (reentrancy mid-removal, e.g. during `clear`'s
iteration, is unsupported). An item larger than `max_bytes` is never stored. Region scans are
linear — fine for a hot query/fetch cache's modest entry counts, not a million-entry store.

## Verification

Deterministic unit tests (injected `now_ns`/generation, no real clock): hit/miss, TTL expiry, lazy
generation invalidation + `gen==0` immunity, replace/byte-accounting, entry-cap + byte-cap LRU
eviction, expired-before-LRU, clear-keeps-counters, value-copy-on-put, borrowed-slice lifetime,
stats. Sketch tests: exact estimate for a lone key, CMS never underestimates under collision load,
saturation at 15(+1 doorkeeper), aging halves + clears the doorkeeper. W-TinyLFU behavior: admission
gate, scan resistance (a 150-key one-hit burst doesn't evict a 20-key hot set), and a 60k-op
Zipf-skewed hit-ratio benchmark asserting W-TinyLFU beats an inline plain-LRU baseline by ≥10%.
Write-behind seam: `on_evict` fires on W-TinyLFU eviction / replacement / clear with the correct
key+value+dirty+reason and does *not* fire on a plain hit or miss (positive control); dirty set on
`put`, cleared by `markClean`, `markClean` on an absent key is a no-op; `drainDirty` visits exactly
the dirty entries (a cleaned one is excluded, positive control); an evicted dirty entry is reported
dirty to `on_evict` (the safety-net case) vs. an evicted clean entry reported non-dirty on the same
path; unset `on_evict` leaves eviction/replace/clear behavior unchanged. Run: `zig build
test-ramcache`.

**`Sharded`.** There is no external anchor for this design, so the tests carry the argument
themselves. Structural unit tests: `getBuf`'s `ok` slice aliases the caller's buffer (asserted by
pointer identity); `buffer_too_small` is distinct from `miss` and reports the needed length; an
owned copy from `get` survives a `clear()` of the entry it came from (the assertion that would read
freed memory if a borrowed slice were returned); keys reach *every* shard and aggregate occupancy
reaches the requested cap (a degenerate `shardIndex` stays consistent between put and get, so only
distribution and capacity see it); shard-count rounding + both clamps; per-shard byte ceiling;
`clear` and `stats` checked both aggregate *and* per-shard so a skipped shard cannot cancel out;
TTL/generation axes; `markCleanIf` refusing a stale ack. Concurrency (real threads, leak-checking
allocator): a mixed get/put/evict/clear stress where every stored value is a self-describing record
(key id + round + derived pattern) verified on both read paths *and* inside `on_evict`, with
`expectInvariants` re-deriving byte totals, region counters and the key→shard mapping from the raw
maps after the join; a parallel-`clear` race; and a dedicated test that a value is never freed while
being copied out — large values plus a `clear`-spinning thread, so an early lock release is caught
by construction rather than by luck.

**Mutation-tested.** Each central invariant was checked by mutating the implementation and
confirming a test goes red: shard lock released before `getBuf`'s copy (8/8 red — and 0/5 before the
dedicated copy-window test existed, which is why it exists); the same for `get`'s owned copy (3/3);
`put` without its lock (5/5); `shardIndex` collapsed to a constant; `clear`, `stats` and
`drainDirty` each skipping a shard; `markCleanIf` acking unconditionally; `buffer_too_small`
reported as a miss; per-shard caps not divided.

## Backlog / deferred

None beyond what's already covered above. Persistence itself and keyed-hash hardening remain
out of scope (unchanged); eviction callbacks + a dirty-set are now in (write-behind seam, see
above) — no longer listed as a gap.

## Status

`extract · any · util · single_owner` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
