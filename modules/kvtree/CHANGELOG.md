# kvtree — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-08** — **NO CONSUMER-VISIBLE CHANGE:** `fuzzRecover` had **no seed
  corpus at all**, so outside `--fuzz` it ran exactly one input — the empty one
  — and every one of its fifteen knobs was its own range minimum. Traced
  through: both meta slots were stamped `{txn_id 0, root 0, free_root 0,
  free_count 0, high_water 0}` and `candidateValid` rejected each at
  `pageIdOk(0, 0)`, its FIRST bounds check. The tree walk never took a step,
  `leafViewSafe`/`branchViewSafe` were never called, the freelist chain walk and
  both cycle guards never ran, and `recover` returned `error.Unrecoverable` on
  the only input the ordinary lane has ever given it. A short seed could not
  have fixed it either: the harness opens with `smith.bytes` over a 24 576-octet
  page image, and `Smith.bytes` consumes `@min(out.len, in.len)`, so anything
  shorter is swallowed whole and leaves the knobs nothing.

  Ten corpus entries are now built at run time — a full page image plus the knob
  words — and a corpus-guard test pins what they reach: 12 meta slots stamped,
  data pages stamped 25 random / 10 leaf / 1 branch / 4 freelist, **3 of 10
  seeds recovered** (txn_ids 5, 9 and 7, pinned by their sum so one seed cannot
  mask another), 1 of them adopted through a branch root and 1 with a walked and
  totalled freelist chain. The seven refusals are the ones the walk exists for:
  a chain count one over `Freelist.capacity`, a `next` pointing at its own page,
  a `high_water` past the end of the file, a root below `first_data_page`, a
  `free_count` of 2^64-1 against an empty freelist, both meta slots left as raw
  fill, and a leaf page over `0xff` fill whose `count` reads 65 535 — the exact
  shape `leafViewSafe` was added to reject, asserted directly in the guard.

- **2026-08-25** — **Fixed: the store grew for ever under a steady write load.** Chain
  storage for the freelist was allocated from `Pager.growOne` only, never from the
  freelist itself — a simplification taken to dodge the chicken-and-egg of a freelist
  write describing the page it is being written to. It was not orthogonal to anything:
  every commit rewrites the chain, so every commit permanently added `pagesNeeded()`
  entries to the list, which lengthened the chain, which added more entries.

  **Net file growth per commit equalled `pagesNeeded()` — the current chain length —
  exactly**, which is both the mechanism and the amplification: the leak per commit is
  the chain length, and the chain lengthens because of the leak. It is why the same
  defect shows as one page per commit here (a short list that fits a single chain page)
  and as two downstream (a longer list needing two).

  **The cost is per COMMIT and independent of what the commit carries**, so it scales
  with commit rate, not with data rate. Measured downstream on a tsdb-shaped append
  workload — 23 series, 17-byte keys, 8-byte values, every key new — a commit of three
  points and a commit of sixteen both cost exactly 8 KiB. Straight-line fits over
  60-second windows on that store: **327 KB/s at one commit per value**, 16.4 KB/s at
  one commit per source-resolve, 8.1 KB/s with the retention sweep rate-limited, and
  3.3 KB/s after widening the sampling interval. A 13 GB store accumulated over an
  afternoon of intermittent runs.

  **What it looks like from outside**, for anyone recognising their own case: a store
  growing megabytes per minute while holding kilobytes of data, and a batch-your-writes
  change paying off enormously for reasons that have nothing to do with I/O. That last
  one is the trap — downstream, batching cut the rate twentyfold and read as a win
  rather than as a symptom, which is part of why the real defect survived another pass.

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
