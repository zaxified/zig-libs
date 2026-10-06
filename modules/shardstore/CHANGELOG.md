# shardstore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-06** — ADDED: merge-sorted scan across all shards — `Store.scan(ScanOptions)` →
  `Scan` (`next`/`deinit`), with `Bound` (unbounded / inclusive / exclusive) start and end,
  `limit` and `ScanDirection` (forward / reverse); new public `KV`, `Bound`, `ScanOptions`,
  `ScanDirection`, `ScanError`. Each shard is read at the version pinned when `scan` runs;
  each key is yielded once, from its owning shard (agrees with `get`). Scope mvp -> core;
  `## Compared with` re-assessed.
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: the store-wide
  exclusive lock (`"<name_prefix>.lock"` sidecar taken by `Store.init`, a second live `Store`
  over the same paths gets `error.Locked`) is now described in SPEC/README, which still said
  there was no cross-process exclusion. Recorded late: the lock itself (wave-2 F2 fix) never
  had a changelog entry.
- **2026-10-05** — Mutation run: 25 of 27 killed, 2 equivalent; 4 tests added (store-wide
  lock refusal, pinned routing, lock and shard release after a failed shard open, name
  validation at the highest index).
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Redis
  Cluster / Dynamo partitioning (design ref), over N `kvtree`s (design reference, not a
  test anchor).
- **2026-07-22** — New module: key-sharding router over N independent `kvtree` stores —
  multi-core write parallelism (per-shard single-writer, cross-shard parallel; caller
  partitions same-shard writes).
