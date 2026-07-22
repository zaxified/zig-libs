# pagecache

A bounded, transparent **page cache** between `kvtree`'s pager and its
underlying `Storage`. It keeps a fixed RAM budget of hot pages resident and
refetches cold pages from the backing store on demand (hot-cold tiering), so a
kvtree store larger than you want fully in memory runs with a hard cap on
resident pages — without any change to kvtree or its durability guarantees.

`PageCache` **implements the same `Storage` seam kvtree drives** and wraps a
real backend, so it is a drop-in: hand `pc.storage()` to `kvtree.Db.open`
instead of the raw `FsStorage`.

## Usage

```zig
const kvtree = @import("kvtree");
const pagecache = @import("pagecache");

var fs = kvtree.FsStorage.init(io, dir);
var pc = pagecache.PageCache.init(gpa, fs.storage(), .{
    .max_pages = 1024, // resident-page budget → 1024 * page_size bytes
});
defer pc.deinit();

var db = try kvtree.Db.open(gpa, pc.storage(), "store.kvt", .{});
defer db.close();

// ...use db exactly as if it were opened over fs.storage() directly...

const s = pc.stats(); // { hits, misses, resident_pages, resident_bytes, evictions }
```

Works over `SimStorage` too (set `sim.allow_overwrite = true`, since kvtree
overwrites its meta pages in place).

## Design in one paragraph

- **Write-through only.** Every write reaches the inner `Storage` before the
  call returns; `sync`/`syncDir`/`truncate` forward verbatim. kvtree's ordered
  meta-page commit — its crash-safety — is preserved exactly. Write-back is
  deliberately rejected (it would reorder/delay durable writes).
- **Bounded by `ramcache` (W-TinyLFU).** Pages are keyed by
  `(handle, page-index)`; the budget is a fixed page count. Constantly re-read
  meta pages stay hot and pinned; churning leaf pages are evicted by recent
  frequency; a cold scan can't flush the hot set.
- **Transparent.** A `Db` over `PageCache(inner)` is byte-for-byte equivalent
  to one over `inner` — same data, same scans, same durability. The cache only
  bounds RAM and cuts inner reads.

See [SPEC.md](SPEC.md) for the full write-through argument, the ramcache-vs-
custom decision, the keying/invalidation details, and the validation matrix.

## Tests

`zig build test-pagecache` (and `-Doptimize=ReleaseFast`) — transparency
(identical scans vs raw backend), bounding (budget never exceeded, eviction +
cold refetch), durability (fresh-cache reopen over `FsStorage` recovers
committed data), in-place meta overwrite, and pass-through of non-page I/O.

Catalog line:

`pagecache | Bounded write-through page cache between kvtree's pager and its Storage (hot-cold tiering via ramcache)`
