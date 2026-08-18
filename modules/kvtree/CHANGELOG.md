# kvtree — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`): a crash-injection test's reorder
  seed mixed `round`/`crash_at` (both `usize`) directly with a splitmix64-style 64-bit
  golden-ratio constant (`0x9e3779b97f4a7c15`), which doesn't fit `usize` on a 32-bit
  target. The constant is genuinely a fixed 64-bit hash-mixing magic number, not a
  memory-sized quantity, so widened `round`/`crash_at` to `u64` for this expression only
  (the field it feeds, `SimStorage.reorder_seed`, was already `u64`) rather than
  truncating the constant — truncating a hash multiplier is exactly the kind of silent
  wrong-on-32-bit outcome this class of fix must avoid. Compile-only: the assignment
  target is `u64` either way, so the produced seed is unchanged on every target that
  already built. Verified: `zig build portable-kvtree` and
  `zig build test-kvtree --summary all` (35/35) both green.
- **2026-07-18** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on LMDB /
  BoltDB (design reference, not a test anchor).
- **2026-07-16** — New module: Ordered transactional KV store — copy-on-write B-tree
  (LMDB/BoltDB lineage): MVCC snapshot isolation, multi-key ACID txns, ordered range
  scans, VOPR-checked crash-safety. Crash-atomicity core.
