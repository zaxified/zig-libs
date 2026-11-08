# clock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-08** — **NEW MODULE:** `monotonicNs`, `monotonicCoarseNs`, `realtimeNs`/`Ms`/`S`, `elapsedNs`,
  injectable `Clock`/`WallClock`, `ManualClock`/`ManualWallClock`. Extracted from the 18 private copies of
  the same clock struct and OS reads across the collection (duplicate-code pass).
