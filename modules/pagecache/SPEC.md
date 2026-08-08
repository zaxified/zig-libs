# pagecache — SPEC

A bounded, transparent **page cache** that sits between `kvtree`'s pager and
its underlying `Storage`, keeping a fixed RAM budget of hot pages resident and
refetching cold pages from the backing store on demand (hot-cold tiering).

## Problem

`kvtree` is a copy-on-write B-tree over a pluggable `Storage` seam (a page
read/write/append interface over a file, `FsStorage`, or in-memory
`SimStorage`). Every tree descent reads pages from that seam. For a store
larger than you want fully resident, you want only the *hot* pages in RAM and
cold pages fetched on demand, with a hard cap on resident memory — without
changing kvtree or its durability guarantees.

## The seam (drop-in `Storage`)

`PageCache` **wraps one inner `Storage` and itself implements the exact same
`Storage` vtable** kvtree drives (`open`, `size`, `pread`, `writeAll`, `sync`,
`truncate`, `close`, `rename`, `delete`, `syncDir`, `tryLockExclusive`). So it
composes by substitution:

```zig
var fs = kvtree.FsStorage.init(io, dir);
var pc = pagecache.PageCache.init(gpa, fs.storage(), .{ .max_pages = 1024 });
defer pc.deinit();
var db = try kvtree.Db.open(gpa, pc.storage(), "store.kvt", .{});
```

`pc.storage()` is a `kvtree.Storage` (== `kv.Storage`), indistinguishable to
`Db.open` from the raw backend's `storage()`. Handles pass straight through to
the inner backend.

## Cache structure & budget: **ramcache, not a custom map**

The bounded set is a **`ramcache.Cache`** (W-TinyLFU admission + segmented
LRU), not a purpose-built page map. Rationale:

- **It honors the dependency and the reuse philosophy** — `ramcache` already
  gives a proven, bounded, scan-resistant cache; reimplementing CLOCK/LRU here
  would duplicate it.
- **W-TinyLFU is a genuinely good fit for a page cache.** kvtree re-reads its
  two **meta pages on every commit**, so they build access frequency and stay
  pinned as "hot", while churning leaf pages are admitted/evicted by *recent*
  frequency. A one-shot scan of many cold pages **cannot flush the hot set**
  (scan resistance) — precisely the hot-cold tiering this module exists for.
- The only cost of the byte-slice API is one 12-byte key encode plus a
  `page_size` value copy per fill — negligible against an inner `Storage` read.

**Keying.** Each page is keyed by `handle (u32 LE) ++ page_index (u64 LE)`.
Including the handle means two files opened through the same cache never alias.

**Budget.** `Options.max_pages` is the maximum number of resident pages;
`ramcache` is configured with `max_entries = max_pages` and `max_bytes =
max_pages * page_size`. `ramcache` enforces the cap on every `put` (evicting
before returning), so **`resident_pages <= max_pages` holds at every observable
moment**. Only page-aligned, exactly-`page_size` accesses are cached (kvtree
always issues those); any other-shaped access bypasses the cache entirely.

### ramcache seam friction (and why it's fine)

`ramcache` exposes no **single-key removal** (only `clear()`). This matters
only for *invalidation* — a case that cannot produce a stale hit under
write-through, because:

- A resident page is **updated in place** by `put` on write-through (an
  existing key is replaced, never mis-admitted), so it never goes stale.
- A page leaves the cache only by **eviction** (fully removed) → the next read
  is a miss served from the inner Storage.

The residual cases where bytes could be dropped underneath us —
`create_truncate` open, `truncate`, `close` (handle-number recycling),
`rename`/`delete`, and non-page-aligned writes — are handled by a whole-cache
`clear()`. All are **rare or never issued by kvtree** (kvtree opens
`open_or_create`, never truncates in normal operation, never renames/deletes,
and only ever writes full pages), so the coarse invalidation costs nothing in
practice while keeping correctness unconditional.

## Write policy: **write-through only** (durability preserved)

kvtree's crash-safety is an *ordering* property: it writes tree pages, `sync`s,
overwrites a **meta page in place**, `sync`s again — a torn commit leaves the
previous meta as the newest valid one (double-buffered meta pages). A
**write-back** cache that buffered dirty pages and flushed them later would
reorder or delay those writes and silently break that invariant.

Therefore `PageCache` is strictly **write-through**:

- `writeAll` forwards to the inner `Storage` **first and unconditionally**; the
  durable write completes before the call returns, byte-for-byte as if the
  cache were absent. The resident copy is refreshed only as a side effect,
  **after** the inner write succeeds (on inner failure the error propagates and
  the cache keeps its last correct copy).
- `sync`, `syncDir`, and `truncate` forward verbatim — kvtree's commit
  barriers keep their exact meaning and timing.
- No dirty buffering, no deferred flush, no reordering. The cache **only**
  bounds RAM and elides redundant inner reads.

This is the safe default the task calls for; write-back is explicitly rejected
because it cannot preserve kvtree's ordered-commit durability.

## Transparency invariant

> A `kvtree.Db` opened over `PageCache(inner)` behaves **identically** to one
> opened directly over `inner`: same data, same ordered scans, same
> durability.

The cache is invisible to correctness — it can only make reads faster or bound
RSS. It never changes what is durable and never changes an observable result.
A resident page is always the latest written bytes (write-through updates it in
place); an absent page is always refetched from the authoritative inner store.

## Validation (tests, Debug + ReleaseFast, all green)

1. **Transparency** — an identical 1500-op put/get/delete/commit workload runs
   through `kvtree.Db` over `PageCache(Sim)` and over raw `Sim`; the two stores
   are asserted **byte-identical** on a full ordered cursor scan and on
   point-reads across the whole key space. The cache registers real hits and
   never exceeds its budget.
2. **Bounding** — a 4-page budget against a working set far larger than 4
   pages: `resident_pages <= budget` and `resident_bytes <= budget*page_size`
   are asserted throughout, eviction is confirmed (`evictions > 0`,
   `misses > budget`), meta pages are served from RAM (`hits > 0`), and every
   key still reads back the exact expected value (cold pages refetched).
3. **Durability** — write + commit through `PageCache(FsStorage)`
   (`std.testing.tmpDir`), tear the whole cache down, then reopen with a
   **fresh empty cache** and a fresh `FsStorage`: all committed data
   (including an overwrite and a delete) survives, proving the write-through
   writes reached disk and the cache masked nothing. Cleaned up via
   `tmp.cleanup()`.
4. **In-place meta overwrite** — with `SimStorage.allow_overwrite = true` (as
   kvtree's own harness runs), 50 commits repeatedly overwrite the meta pages
   at the same offset through the cache; every latest-committed key reads back
   correctly (a stale cached meta page would point at an old root and lose
   keys).
5. **Pass-through** — sub-page / unaligned reads bypass the cache and return
   exact inner bytes without registering as page hits/misses.

## Copy cost vs. a borrowing seam (design note, wave-2 audit F3)

A hit today copies a whole page once (`@memcpy(buf, cached)` into the caller's
buffer); a miss copies it **twice** (`inner.pread` into `buf`, then
`ramcache.put` dupes `buf` into cache storage, which itself allocates and
frees a `page_size` buffer per fill). LMDB's mmap'd pages are the zero-copy
alternative: the caller gets a pointer straight into the resident page, 0
copies, 0 allocations.

That is inherent to the current `pread(buf)` shape of the `Storage` seam, not
a local inefficiency — `Storage.pread(h, buf, off) !usize` hands the *caller*
an already-allocated destination, so `PageCache` cannot answer with "here is
my copy" instead. Removing the copy needs a **different seam**, not a local
optimisation:

- Add a borrowing pair to `Storage` — e.g. `preadRef(h, off) !PinnedPage` /
  `unpin(PinnedPage)` — that a cache-aware backend can implement by handing
  back a pointer into resident storage (mmap for a real file, the cache slot
  itself for `PageCache`), falling back to `pread`-into-an-owned-buffer for
  backends with nothing to borrow from (e.g. plain `FsStorage` without mmap).
  The pin must have a bounded lifetime the caller signals explicitly
  (`unpin`), since the byte range it points at is not caller-owned the way a
  `pread` buffer is.
  - Any pin held across a `writeAll`/`truncate`/`close` on the same page turns
    write-through's in-place `ramcache.put` (`vWriteAll`) or the coarse
    `clear()` guards (F2) into a use-after-free/UAF-into-stale-bytes hazard —
    the pin holder would need to either block the mutation or be invalidated
    itself, and "invalidated while pinned" has no answer in the current
    write-through model.
  - `kvtree`'s own pager would need a second, borrowing call path alongside
    its current `pread`-into-scratch one — a page-cache B-tree normally reads
    a page once per descent and holds it only for the duration of that visit,
    so the pin lifetime maps naturally to "duration of one page visit", but
    that is a `kvtree` change, not a `pagecache` one.
  - Every other `Storage` implementor (`FsStorage`, `SimStorage`, and any
    future backend) would need to grow the new vtable method (even if only as
    a `pread`-and-copy fallback), which is the "changes the seam every
    backend implements" cost the module's own to-do #3 flags as needing a
    design decision before it is actionable.

**Verdict of this note:** real, not urgent — no measured consumer is
bottlenecked on the extra copy today (the O(1)-victim-selection fix, F1/
`a1d7229`, was the one that mattered at the measured page counts). Scope a
`preadRef`/`pin`/`unpin` addition to `Storage` as its own cross-module task
(touches `kv`, `kvtree`, and every backend, not `pagecache` alone) if a real
caller's profile ever shows the double copy as the bottleneck rather than a
constant-factor cost against an O(1) fill.

## Backlog / non-goals

- **Per-key invalidation.** If `ramcache` gains a `remove(key)`, the
  coarse-grained `clear()` on truncate/close/rename/delete could be narrowed to
  the affected pages. Not needed for kvtree's access pattern.
- **Write-back / dirty buffering.** Deliberately excluded — incompatible with
  kvtree's ordered-commit durability model.
- **Prefetch / read-ahead.** A sequential-scan read-ahead could reduce misses
  during range scans; out of scope for v0 (transparency + bounding first).
- **Cross-thread sharing.** Inherits `single_owner` from both `ramcache` and
  `kvtree`; a shared deployment must wrap the owner in its own lock.
