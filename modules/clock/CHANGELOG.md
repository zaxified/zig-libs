# clock — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-08** — **Audit:** adversarial review of every entry point, 47-mutant schemata run (42 killed, 1
  equivalent, 4 surviving only on an x86-64 host — see SPEC), no-panic sweep. No behaviour change. The saturating `timespec` and Windows FILETIME conversions
  and the ms/s floor divisions are now pure helpers (`unixNsFromTimespec`, `unixNsFromFiletime`, `nsToMs`,
  `nsToS`) tested at their edges on any target; the `@intCast`s on the `timespec` fields became implicit
  widening. New tests: coarse vs precise granularity, negative second with nanoseconds, helper edges, a
  `ManualWallClock` concurrent-advance test, and a start barrier on both race tests.
- **2026-11-08** — **NEW MODULE:** `monotonicNs`, `monotonicCoarseNs`, `realtimeNs`/`Ms`/`S`, `elapsedNs`,
  injectable `Clock`/`WallClock`, `ManualClock`/`ManualWallClock`. Extracted from the 18 private copies of
  the same clock struct and OS reads across the collection (duplicate-code pass).
