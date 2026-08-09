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
`truncate`, `close`, `rename`, `delete`, `syncDir`, `tryLockExclusive`), plus
the seam's two **optional** borrow methods (`preadRef`, `releaseRef`) — which
`PageCache` is currently the only implementor of, because it is the only
`Storage` that holds page bytes in its own memory. So it composes by
substitution:

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

## Zero-copy reads: the borrow seam (wave-2 audit F3, implemented)

The copying `pread` seam costs a whole-page `@memcpy` on a **hit**
(`@memcpy(buf, cached)` into the caller's buffer) and **two** page copies on a
**miss** (`inner.pread` into `buf`, then `ramcache.put` duping `buf` into cache
storage). LMDB, the named C reference, hands the caller a pointer straight into
the mapped page: 0 copies. That gap is inherent to `Storage.pread(h, buf, off)`,
which hands the *caller* the destination — so `PageCache` has no way to answer
"here is my copy" instead. The fix is therefore a seam addition, not a local
optimisation, and it is now in place:

```zig
// kv.Storage, optional vtable slots (default null = "cannot lend")
preadRef:   ?*const fn (ctx, h, len: usize, off: u64) Error!?Ref
releaseRef: ?*const fn (ctx, ref: Ref) void
pub const Ref = struct { bytes: []const u8, token: *anyopaque };
```

* **Hit — 0 copies.** `PageCache.preadRef` pins the resident entry and returns
  a slice of cache storage.
* **Miss — 1 copy.** `ramcache.Cache.reserve` allocates the entry's value
  uninitialized and lends it *writable*, so the inner `pread` lands directly in
  the slot that will hold the page. There is no second dupe.
* **Cannot lend — `null`, explicitly.** `FsStorage`/`SimStorage` leave the two
  slots at their `null` default: `Storage.canLend()` answers `false` and
  `preadRef` returns `null`. There is deliberately **no** internal fall-back to
  a copying read, because a fall-back that looks like a success makes "did the
  fast path engage?" unanswerable at the call site. `null` is also the answer
  for an access that is not exactly one aligned page, and for a page that is
  not fully present on media.

### How the pin lifetime is enforced

The earlier version of this note flagged the hard part correctly: *"any pin held
across a `writeAll`/`truncate`/`close` on the same page turns write-through's
in-place `ramcache.put` or the coarse `clear()` guards into a use-after-free —
and 'invalidated while pinned' has no answer in the current write-through
model."* It has one now, and it is structural rather than documentary:

1. **A borrowed entry is not an eviction candidate.** `pin` removes the entry's
   index node from `ramcache`'s region-LRU and expiry heaps. Victim selection
   reads heap *roots* and nothing else, so there is no eviction path that has to
   remember to check a flag — a pinned entry is simply not reachable from the
   structures eviction chooses from, at zero cost per eviction. `release` files
   it back. While pins are held the cache may sit over `max_entries`/`max_bytes`
   (a borrowed page is resident by definition); `Stats.pinned` reports it.
2. **A write or invalidation over a borrowed page *parks* it.** `put`, `remove`,
   `clear` and lazy TTL expiry on a pinned entry unlink it from the map — so it
   can never be served again, and `clear()`'s contract ("resident pages drop to
   0", which the six invalidation guards of F2 rest on) stays literally true —
   while the value bytes move to the node, which owns them until the last
   `release`. The borrower keeps reading the snapshot it was handed; the next
   reader sees the new bytes. Doing only one of those two is the bug: freeing
   the bytes is `ocspcache` F4's use-after-free, and refusing the write is a
   stale hit, which is precisely what a write-through cache exists to prevent.
   The parking slot's capacity is reserved *at pin time*, so parking can never
   fail partway and be forced to free memory somebody is still reading.

### Who uses it

`kvtree`'s read descent (`lookup`, behind `Db.get`/`Txn.get`/`Snapshot.get`)
takes the borrow when the store can lend: it is the one tree path that only
*reads* its pages and holds exactly one at a time. The copy-on-write write path
and the `Cursor`'s root-to-leaf frame stack keep their own page copies on
purpose — they mutate or outlive their pages, and a borrow is read-only.

### Measured (see `src/bench.zig`, `PAGECACHE_BENCH=1`, ReleaseFast, 4 KiB pages)

| access | copies | allocs | ns/access |
|--------|--------|--------|-----------|
| hit, `pread` | 1 | 0 | 116–171 |
| hit, `preadRef` | **0** | 0 | **93–102** |
| miss, `pread` | 2 | 3 | 1612–1727 |
| miss, `preadRef` | **1** | 3 | 1585–1951 |

Read the two shapes differently. The **hit** is a real, repeatable win — one
whole-page `memcpy` removed, ~20–45 % off the access. The **miss** is a wash:
allocations are the same three either way (key dup, page buffer, index node —
the copying path's second buffer is the *caller's*, not the cache's), and the
~40 ns the removed copy saves is about what `pin`+`reserve`+`release` costs in
extra index work over `get`+`put`. Its claim is one fewer copy, not fewer
nanoseconds; against a real `read(2)` both are noise.

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
