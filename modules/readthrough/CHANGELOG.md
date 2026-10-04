# readthrough — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — Tests: first mutation run (36 mutants, 35 killed, 1 equivalent); added tests for the TTL boundary, uncached error with `negative_ttl_ns = 0`, invalidation during a load, invalidation/negative-hit stats, absent-key invalidate in a full cache, and the `max_entries` bound.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Go
  `singleflight` + Caffeine `LoadingCache` (design reference, not a test anchor).
- **2026-07-24** — New module: Backend-agnostic read-through cache coordinator.
