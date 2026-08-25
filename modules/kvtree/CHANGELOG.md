# kvtree — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-25** — **Fixed: the store grew for ever under a steady write load.** Chain
  storage for the freelist was allocated from `Pager.growOne` only, never from the
  freelist itself — a simplification taken to dodge the chicken-and-egg of a freelist
  write describing the page it is being written to. It was not orthogonal to anything:
  every commit rewrites the chain, so every commit permanently added `pagesNeeded()`
  entries to the list, which lengthened the chain, which added more entries. Measured
  downstream on a modest append workload: **over a gigabyte an hour**, and a 13 GB file
  before anyone noticed. Exactly one page leaked per commit even on a workload whose
  data set never grew.

  The chicken-and-egg dissolves by ORDERING, not by giving up reuse: take the storage
  pages out of the list first, then encode what remains, so nothing describes itself.
  New `Freelist.reserveChain` does that and `writeChainOn` writes onto whatever pages it
  chose (the chain was always linked by `next`, so non-adjacent pages need no format
  change). `core.commit` calls it BEFORE parking its own freed pages, which is the
  crash-safety half: at that moment every entry was freed by an earlier txn, so
  copy-on-write guarantees none is reachable from the still-durable base meta. The page
  count is a fixed point rather than a division — taking a page shortens the list, which
  can shorten the chain — so a page is recycled only when that leaves the arithmetic
  consistent, and grown otherwise (the single-entry case: one page parked, one page
  needed to say so).

  Guarded by a new steady-state test: 200 commits overwriting a fixed key set must not
  move `high_water` by a single page. It fails at +200 on the old code. `reserveChain`
  also has unit tests for the recycle path, the grow-instead cases and a multi-page
  chain. Both gated VOPR property tests (snapshot isolation/serializability, and the
  crash sweep across every storage side effect × 4 crash modes) still pass — which is
  the acceptance gate that matters here, since the fix makes commits write to recycled
  pages.

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
