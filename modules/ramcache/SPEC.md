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

## Borrow seam — `pin` / `reserve` / `release`

`get` returns a slice into cache storage whose validity rule is "until this key
is replaced, evicted, or the cache is cleared" — a rule a caller can only obey
by copying immediately. The borrow seam removes the rule instead of restating
it, for callers whose values are big enough that the copy matters (`pagecache`
pays a whole 4 KiB page per hit; see its SPEC's F3 note).

- `pin(key, now, gen) ?Borrow` — like `get`, but the entry becomes
  **unevictable** for the borrow's lifetime.
- `reserve(key, len, now, ttl, gen) ?Fill` — insert `len` bytes of
  *uninitialized* storage and lend them **writable**, so a caller that would
  otherwise fill a scratch buffer and then `put` (two copies) produces the value
  straight into its final home (one). Finish with `commit` (keep, downgrade to a
  read borrow) or `discard` (the fill failed; the entry never becomes visible,
  and `on_evict` is not fired over uninitialized bytes).
- `release(borrow)` — end it. Nested borrows of one entry are counted; the last
  release re-files the entry.

Two invariants make this safe without asking the caller to be careful:

1. **A pinned node is out of the index.** `pin` removes it from its region-LRU
   heap and the expiry heap; victim selection only ever reads heap roots, so a
   borrowed entry is not reachable from the structures eviction chooses from.
   This is why "borrowed entries are unevictable" costs nothing per eviction and
   cannot be forgotten at a call site. `release` pushes it back with the tick of
   its last access; if that push OOMs the entry is dropped instead (a live entry
   outside the index would be un-evictable forever). While pins are held the
   cache may exceed `max_entries`/`max_bytes` — a borrowed entry is resident by
   definition — and `Stats.pinned` reports how many.
2. **Anything that would destroy a borrowed entry parks it instead.** `put` over
   the key, `remove`, `clear`, and lazy TTL/generation expiry all unlink the
   entry from the map immediately (no stale hit is possible, and `clear()` still
   leaves nothing findable) while moving the value bytes onto the node, which
   owns them until the last `release`. Freeing them instead is a use-after-free;
   *refusing* the write instead is a stale hit. The parking list's capacity is
   reserved at pin time, one slot per borrowed entry, so parking is infallible —
   it must never be forced to free memory a caller is reading.

`deinit` frees any still-parked values: tearing the cache down with borrows
outstanding is a caller bug, but leaking is not an improvement on it.

## `Sharded` — the internally-synchronized wrapper

`Cache` stays lock-free; `Sharded` is a second type in the same module holding N `Cache` instances,
one lock each, keyed by `Wyhash(seed, key) & (N-1)` with a **per-instance** seed. Full contract in its doc comment;
the design commitments an auditor needs:

- **Safety is structural, not empirical.** (1) Every field of a shard's `Cache` is touched only
  between `lockAcquire` and `unlock` — `shards` is private and no `*Cache` escapes. (2) Nothing derived
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
  to 1/N of the doorkeeper index space. The ceiling holds on the **replace** path too — overwriting
  a resident key with a value over the bar drops the entry rather than storing it or leaving the
  pre-write bytes to be served forever (an update-only workload otherwise never reaches eviction at
  all, and `max_bytes` stops being a bound; see the threat-model section).
- **Adversarial key distribution is a liveness problem here, not a hashing one.** `Cache`'s threat
  model — unkeyed Wyhash, collisions cost lookup time and nothing else — does **not** carry over,
  because on this type the key picks a *lock*. Keys ground onto one shard cost `(N−1)/N` of the
  usable capacity and queue every writer on one lock. Two answers, of which the second is the
  load-bearing one: (1) the shard seed is derived per instance (`deriveSeed`: base constant mixed
  with the shards allocation's address and a process-wide counter) instead of being a public
  compile-time constant, so a shard's preimage cannot be ground out offline from the source —
  `Options.shard_seed` overrides it for callers needing reproducible placement. This is ASLR plus a
  counter, **not** a keyed MAC: `ramcache` is `platform = .any` and takes no `Io`, and Zig has no
  field privacy, so it raises the cost of the attack rather than closing it. (2) `lockAcquire` spins
  `spin_budget = 64` times and then yields, so the funnelled case degrades to ordinary queueing
  instead of N cores spinning at 100 % across an eviction loop, an allocation under the lock, or a
  caller callback — which is what would make `Sharded` strictly *worse* than one global mutex. This
  holds whether or not the seed is known.
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
iteration, is unsupported). An item larger than `max_bytes` is never stored — on a fresh insert or
on an overwrite of a resident key, where the entry is dropped rather than kept at its pre-write
value. `Sharded` does **not** inherit the "trusted keys only" posture above unchanged: there the key
selects a lock, so it gets a per-instance shard seed and a yielding waiter (see its section). Victim
selection is **O(1)**: a binary min-heap per region ordered by the logical access tick, plus one
over TTL deadlines, so `regionLruKey` and `findExpiredKey` read a heap root instead of walking the
map. Each entry carries a small stable index node (a separate allocation, because a hash map moves
its values on rehash) and heap maintenance is O(log n) with no hashing. Until 2026-08-07 those two
functions were full-map scans and `maintain` ran up to three of them on **every** insert, making one
insert O(`max_entries`) — measured on `pagecache` at 1.98 → 93.5 us per 4 KiB page fill from 64 to
4096 pages, against 1.33 → 0.80 us now, with the per-insert entry-visit count flat at ~2 instead of
rising to ~10 200. The heaps are ordered by the same global tick the scans compared, and ticks are
unique per live entry, so the entry chosen is *identical* to the one the scan chose: this is a
complexity change, not a policy change.

## Verification

Deterministic unit tests (injected `now_ns`/generation, no real clock): hit/miss, TTL expiry, lazy
generation invalidation + `gen==0` immunity, replace/byte-accounting, entry-cap + byte-cap LRU
eviction, expired-before-LRU, clear-keeps-counters, value-copy-on-put, borrowed-slice lifetime,
stats. Sketch tests: exact estimate for a lone key, CMS never underestimates under collision load,
saturation at 15(+1 doorkeeper), aging halves + clears the doorkeeper. W-TinyLFU behavior: admission
gate, scan resistance (a 150-key one-hit burst doesn't evict a 20-key hot set), and a 60k-op
Zipf-skewed hit-ratio benchmark asserting W-TinyLFU beats an inline plain-LRU baseline by ≥10%.
Complexity: a counter-based (not clock-based) regression test asserts the per-insert entry-visit
count of the eviction path does not grow when capacity goes from 64 to 4096, plus an expired-first
test with one TTL entry buried among seven that never expire.
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
being copied out.

That copy-window test used to rest on a *memory-shaped* oracle alone — large values plus a
`clear`-spinning thread, on the theory that an early lock release would then be caught by
construction. Measured against the real mutation (`getBuf` unlocking right after the lookup) it was
**5 red / 4 green over nine fresh compiles**: a coin flip, which in a gate reads as harness flake and
gets re-run until green. Its primary oracle is now exact instead: a test-only probe (`copy_probe`,
compiled out of non-test builds) fires from *inside* `getBuf`'s critical section and tries to take
the very lock the copy is supposed to run under. `std.atomic.Mutex` is non-reentrant, so while the
lock is genuinely held that `tryLock` fails on every schedule and every run — mutual exclusion, no
window to miss. The mutation is now caught 9/9; isolated (a momentary unlock with nothing left
dangling) the probe alone reports 6032 violations where the memory oracle sees none.

Also covered since the 2026-08-11 re-audit: the **delivered** defaults (`.shards` omitted ⇒ 16
shards and the caps divided by 16 — every other test passes `.shards` explicitly, so `1` used to
leave the suite green); the shard seed (base constant pinned as a literal and against both sketch
seeds; two instances from identical options disagree on where >128 of 256 keys live; an explicit
`shard_seed` is honoured verbatim); a waiter yielding rather than spinning, proven by holding a shard
lock by hand while a second thread blocks on it; `drainDirty`'s lock under two writer threads and a
sweeping thread, where the callback `tryLock`s its own shard (deleting the lock previously left the
suite green); `stats()` compared to a per-shard sum **reflectively over every `Stats` field**, with a
real borrow taken through a shard's `Cache` so `pinned` is non-zero and the comparison is not
vacuous; and the aggregate/per-shard byte cap under an update-only workload.

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

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** pure in-process W-TinyLFU cache, no wire
