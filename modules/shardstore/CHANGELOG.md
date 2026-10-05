# shardstore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
