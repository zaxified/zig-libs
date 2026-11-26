# readthrough — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-26** — **NO CONSUMER-VISIBLE CHANGE:** killing tests from the 2026-11-25 whole-module mutation run (`ttl_fn`, `getAll`, refresh-after-write).
- **2026-11-21** — **Additive:** `Options.refresh_after_ns` (Caffeine `refreshAfterWrite`): a positive entry past that age but not expired is served while one caller reloads it on its own thread; `Cache.refresh(key)` reloads a key unconditionally; `Stats.refreshes` (new field). Default off, stored layout and behaviour unchanged when off. `invalidate(key)` now uses `ramcache.Cache.remove` instead of the poison-generation shadow (same observable behaviour).

- **2026-11-16** — New: bulk loading. `Options.bulk_loader` (`BulkLoader`) + `Cache.getAll(keys)` / `freeAll`: hits served from the cache, keys already in flight awaited (coalesced), the remaining distinct keys fetched in ONE bulk loader call, stored under the usual TTL/negative rules (`ttl_fn` included); keys the loader omits become negative entries; without a bulk loader each missing key uses the single loader. Default behaviour unchanged.

- **2026-11-16** — New: per-key TTL. `Options.ttl_fn` (`TtlFn`) + `ttl_ctx` choose the TTL of each positively loaded entry (null = `ttl_ns`, `<= 0` = never expire); default behaviour unchanged.

- **2026-10-18** — Ported to Zig 0.17.0. comptime `strRepeat` helper: larger `@setEvalBranchQuota` (0.17 counts more branches per iteration).
- **2026-10-04** — Tests: first mutation run (36 mutants, 35 killed, 1 equivalent); added tests for the TTL boundary, uncached error with `negative_ttl_ns = 0`, invalidation during a load, invalidation/negative-hit stats, absent-key invalidate in a full cache, and the `max_entries` bound.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Go
  `singleflight` + Caffeine `LoadingCache` (design reference, not a test anchor).
- **2026-07-24** — New module: Backend-agnostic read-through cache coordinator.
