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

## Threat model / out of scope

Not a security primitive and **not thread-safe** (`concurrency = single_owner` — one thread/loop
owns the instance; a caller sharing it across threads supplies its own lock — `sessions`'
`RamcacheStore` is the reference for that pattern). Key hashing is Wyhash, not keyed/DoS-resistant —
not hardened against adversarial hash-collision flooding; intended for trusted internal keys (query
strings, URLs), not attacker-chosen keys. No persistence, no eviction callbacks. An item larger than
`max_bytes` is never stored. Region scans are linear — fine for a hot query/fetch cache's modest
entry counts, not a million-entry store.

## Verification

Deterministic unit tests (injected `now_ns`/generation, no real clock): hit/miss, TTL expiry, lazy
generation invalidation + `gen==0` immunity, replace/byte-accounting, entry-cap + byte-cap LRU
eviction, expired-before-LRU, clear-keeps-counters, value-copy-on-put, borrowed-slice lifetime,
stats. Sketch tests: exact estimate for a lone key, CMS never underestimates under collision load,
saturation at 15(+1 doorkeeper), aging halves + clears the doorkeeper. W-TinyLFU behavior: admission
gate, scan resistance (a 150-key one-hit burst doesn't evict a 20-key hot set), and a 60k-op
Zipf-skewed hit-ratio benchmark asserting W-TinyLFU beats an inline plain-LRU baseline by ≥10%. Run:
`zig build test-ramcache`.

## Backlog / deferred

None found in PLAN.md or the module README beyond what's already covered above (no eviction
callbacks/persistence/keyed-hash hardening — documented as out of scope, not a v1 gap).

## Status

`extract · any · util · single_owner` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
