# readthrough — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC statements that Zig has no io-less blocking mutex / `std.Thread` primitives re-checked against the 0.17.0 std (still true).
- **2026-10-18** — Ported to Zig 0.17.0. comptime `strRepeat` helper: larger `@setEvalBranchQuota` (0.17 counts more branches per iteration).
- **2026-10-04** — Tests: first mutation run (36 mutants, 35 killed, 1 equivalent); added tests for the TTL boundary, uncached error with `negative_ttl_ns = 0`, invalidation during a load, invalidation/negative-hit stats, absent-key invalidate in a full cache, and the `max_entries` bound.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Go
  `singleflight` + Caffeine `LoadingCache` (design reference, not a test anchor).
- **2026-07-24** — New module: Backend-agnostic read-through cache coordinator.
