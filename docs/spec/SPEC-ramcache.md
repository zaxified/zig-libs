# SPEC — `ramcache`

**Purpose** — Serve a repeated lookup (same DB query, same fetched URL, same computed blob) from
RAM in ~ns instead of re-executing it in ~ms. A bounded in-memory cache with **two independent
freshness axes** — wall-time TTL and a logical *generation* counter (bump one counter to invalidate
every derived entry at once) — under a W-TinyLFU admission/eviction policy that makes it
scan-resistant. The hot cache in front of a query/fetch layer.

**Model after / Seed** — W-TinyLFU per Einziger & Friedman, *"TinyLFU: A Highly Efficient Cache
Admission Policy"*; the window + SLRU probation/protected structure follows Caffeine (Apache-2.0)
and the anti-starvation admission tie-break follows ristretto (Go, MIT) — algorithm/behavior only,
clean-room, no source copied. The base (TTL + generation invalidation + byte/entry caps) was
extracted from the authors' poc-wf-analytic `src/cache.zig`; the W-TinyLFU upgrade is new and the
generation-tie freshness axis is novel. See `NOTICE`.

**Design & invariants**
- **Two freshness axes, both lazy.** `ttl_ns <= 0` = never expire by time; `gen == 0` = not tied to
  a generation (TTL-only). A generation-tied entry is stale the instant the caller's `cur_gen`
  differs. Stale entries are dropped **lazily on the next `get`** — there is no sweep, no timer.
- **Bounded by count and by value bytes.** Eviction order: any TTL-expired entry first (a free win),
  then the W-TinyLFU contest — the admission window's LRU *candidate* takes the main region's LRU
  *victim*'s slot only if its estimated recent frequency is higher (a warm candidate can win a tie
  via a deterministic ~1/128 coin so a rotating population cannot stall). One-hit wonders cannot
  flush the proven-hot set. Frequency lives in a fixed 4-bit Count-Min Sketch + doorkeeper with
  periodic halving ("aging"), sized to capacity.
- **Clock + generation are injected on every call** (`now_ns`, `cur_gen`): zero global/time
  dependency, every test deterministic.
- **Ownership:** keys and values are duped into the cache's allocator on `put`, freed on
  evict/replace/clear. A slice from `get` borrows cache storage — valid only until that key is next
  replaced/evicted/cleared. `bytes` accounts value payloads only (the tunable cap).
- **Never-fatal degradation:** `put` silently no-ops on OOM (a cache miss is never fatal); if the
  frequency sketch itself cannot allocate, the cache degrades to plain LRU (gate always admits).

**Threat model / out of scope** — Not a security primitive and **not thread-safe**:
`concurrency = single_owner`, no internal lock by design — one thread/loop owns the instance; a
caller sharing it across threads supplies its own lock. Key hashing is Wyhash (not a keyed/DoS-
resistant hash), so it is not hardened against adversarial hash-collision flooding — intended for
trusted internal keys (query strings, URLs), not attacker-chosen keys. No persistence, no eviction
callbacks. An item larger than `max_bytes` is never stored. Region scans are linear (fine for the
modest entry counts a hot query/fetch cache holds — not a million-entry store).

**Verification** — Deterministic unit tests (injected `now_ns`/generation, no real clock):
hit/miss, TTL expiry, lazy generation invalidation + `gen==0` immunity, replace/byte-accounting,
entry-cap + byte-cap LRU eviction, expired-before-LRU, clear-keeps-counters, value-copy-on-put,
borrowed-slice lifetime, stats. Sketch tests: exact estimate for a lone key, CMS never
underestimates under collision load, saturation at 15(+1 doorkeeper), aging halves + clears the
doorkeeper. W-TinyLFU behavior: admission gate (frequent candidate evicts cold victim, cold
rejected), scan resistance (a 150-key one-hit burst does not evict a 20-key hot set), and a 60k-op
Zipf-skewed hit-ratio benchmark asserting W-TinyLFU strictly beats an inline plain-LRU baseline by
≥10%.

**Status** — `extract · any · util · single_owner` · deps: none (std only).
