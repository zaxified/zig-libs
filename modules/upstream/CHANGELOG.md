# upstream — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — **mvp → core.** Membership changes while serving: `remove(id)`
  (drains, leaves the list and the ring, stays valid for calls in flight),
  `reap()`, `retiredCount()`, `drain`/`undrain`; `add` takes the lock and may run
  at any time. `Strategy.ring_hash` (consistent hashing, `pickByKey`,
  `ringOwner`, `ring_points_per_weight`, `max_ring_points`) and
  `Strategy.least_request` (power of two choices). `healthTick` checks a pinned
  snapshot (one tick at a time). Ring owners checked against Python's `xxhash`
  building the same ring; seeded churn sweep against a model under every
  strategy; a 3-worker + churn-thread test. Mutation 25 mutants, 0 surviving
  (1 equivalent). **Fixed:** `report` touched the member's latency fields after
  releasing its in-flight hold — harmless while members could not be freed, a
  use-after-free once `reap` exists; the decrement is now last.
  **Behaviour change:** `add` parses the address before checking the fleet
  bound (a malformed address on a full pool is `InvalidHostPort`, was
  `TooManyUpstreams`); `getById`/`count`/`stats` take the pool lock;
  `UpstreamStats.draining` and `PoolStats.retired` are new fields (defaults).
- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/root.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../../../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Envoy / HAProxy
  upstream cluster, resilience4j Bulkhead (design reference, not a test anchor).
- **2026-07-08** — New module: Load-balanced upstream pool + failover —
  round-robin/weighted/least-conn/EWMA strategies, per-upstream breaker+bulkhead,
  active+passive health.
