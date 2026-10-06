# shardstore

A **key-sharding router** over N independent `kvtree` stores — the multi-core
**write-parallelism** layer for the data family. A single `kvtree` has one
durable writer at a time (its copy-on-write commit core is single-writer by
design); `shardstore` shards the keyspace across N independent `kvtree`
instances, each its own single-writer domain backed by its own file, so writes
to keys in *different* shards proceed fully in parallel with no lock between
them.

- **Model after:** consistent key-sharding over N single-writer stores (the
  Redis Cluster / Dynamo partitioning idea).
- **Platform:** any — all I/O goes through `kvtree` → `kv`'s `Storage` seam.
  **Role:** both. **Concurrency:** `single_owner` — per-shard single-owner
  (kvtree's contract), cross-shard parallel; the router itself holds only
  immutable-after-`init` state and adds no locking.
- **Deps:** `kvtree` (which re-exports `kv`'s `Storage`/`FsStorage`/`SimStorage`
  seam — `shardstore` re-exports them too, so a consumer needs no direct `kv`
  import).

## API

```zig
const shardstore = @import("shardstore");

// Open (or create) 8 independent kvtree shards over a filesystem dir.
// `FsStorage` is per-handle concurrent, so declare it and get real cross-shard
// parallelism; the default is the conservative `.single_thread`.
var fs = shardstore.FsStorage.init(io, dir);
var store = try shardstore.Store.init(gpa, fs.storage(), .{
    .n_shards = 8,
    .storage_concurrency = .parallel_per_handle,
});
defer store.deinit();

try store.put("user:42", "alice");           // routed to shardFor("user:42")
const v = try store.get(gpa, "user:42");     // caller frees v
defer if (v) |b| gpa.free(b);
try store.delete("user:42");

const idx = store.shardFor("user:42");        // stable owning-shard index

// Merge-sorted scan across ALL shards: global key order, range bounds, limit.
var it = try store.scan(.{
    .start = .{ .inclusive = "user:" },        // or .exclusive / .unbounded
    .end = .{ .exclusive = "user;" },
    .limit = 100,                              // null = no limit
    .direction = .forward,                     // or .reverse
});
defer it.deinit();                             // releases every shard's pin
while (try it.next()) |e| {                    // e.key / e.val valid until next()
    _ = e;
}

// Advanced: per-shard kvtree API (transactions / snapshots / ordered cursors
// are per-shard — see the threading note below).
var txn = try store.shard("user:42").begin();
// … or drive one dedicated writer thread per shard:
var db = store.shardAt(0);
```

`Options`:

- `n_shards` (required) — number of independent shards; a power of two enables
  cheap mask routing, but any `n_shards >= 1` works.
- `name_prefix` = `"shard"`, `name_suffix` = `".kvt"` — shard `i`'s file is
  `"<prefix>-<i:0>5><suffix>"` (e.g. `shard-00000.kvt`), resolved by the injected
  `Storage`. A sixteen-byte `"<prefix>.manifest"` sits beside them.
- `storage_concurrency` = `.single_thread` — what the injected `Storage`
  guarantees about concurrent use. See the threading contract below; this is a
  precondition, not a tuning knob.

**`n_shards` is immutable for the life of the data.** Routing is
`hash % n_shards`, so a different count re-routes every key. The manifest records
the count at creation and a mismatched reopen fails with
`error.ShardCountMismatch` — previously it succeeded and silently read *absent*
for most keys (measured: a 200-key 4-shard store reopened with 8 found 98/200).
Changing the count means migrating the data; there is no incremental resharding.

## Merge-sorted scan

`store.scan(options)` is a k-way merge over one `kvtree` cursor per shard,
yielding entries in global (bytewise) key order — the same order a single
`kvtree` scan would give. `ScanOptions`:

- `start`, `end` — `Bound`s on the low and high end of the range, whichever the
  direction: `.unbounded`, `.inclusive = key` or `.exclusive = key` (an
  inclusive start is `kvtree.Cursor.seek`, an exclusive one `seekAfter`). A
  start above the end is an empty range, not an error.
- `limit: ?usize = null` — at most this many entries (in `.reverse`, the
  largest ones).
- `direction: ScanDirection = .forward` — or `.reverse` (descending).

`Scan.next()` returns `?KV` (slices valid until the next call — copy to keep);
`Scan.deinit()` always. Errors (`ScanError`: backend I/O, `Corrupt`,
`OutOfMemory`, `NotOwningThread`) are sticky except `NotOwningThread`.

**What a scan sees.** Every shard at the version that was newest when `scan`
was called — commits made while the scan is open (including the owner's own,
between `next` calls) never show up in it; open a new scan to see them. Because
all shard cursors are opened inside that one call and a `.single_thread` store
has one owner, the scan is a consistent point-in-time view of the whole store.
On a `.parallel_per_handle` store the scan touches every shard, so `scan`,
`next` and `deinit` must be serialized with all per-shard writer threads
(pause them); the module cannot check that in this mode. An open scan pins
pages in every shard — `deinit` it promptly.

Each key is yielded once, from its owning shard: the scan returns exactly the
pairs `get` would (a key written into a non-owning shard via `shardAt` is
invisible to both). Cost: O(log n_shards) per entry plus one key hash; a
bounded scan stops reading each shard at the far bound.

## Routing

`shardFor(key)` = `std.hash.Wyhash(seed=0)` of the key, reduced to
`[0, n_shards)` — `hash & (n_shards-1)` for a power-of-two count, else
`hash % n_shards`. Deterministic: the **same key always routes to the same
shard**, within a run and across reopens with the same `n_shards`. Dep-free,
good spread, not a security boundary.

## Threading contract

Per-shard single-owner, cross-shard parallel — exactly `kvtree`'s guarantee, no
more:

- Operations on **distinct** shards are independent and never contend (separate
  `Db` state and files; the router adds no shared mutable state). Partition work
  by shard — e.g. one writer thread per shard via `shardAt` — for true
  multi-core write throughput.
- Operations on the **same** shard are bounded by `kvtree`'s single-writer rule:
  **the caller must serialize concurrent same-shard writers.** This router adds
  no latch; `shardFor` is exposed so callers can partition up front.
- **All of which depends on the backend.** Every operation ends in the injected
  `Storage`, and that is where two shards meet. Cross-shard parallelism is real
  only over a backend safe for concurrent ops on distinct handles — `FsStorage`
  is (positional per-handle I/O), `SimStorage` is not (unmanaged containers, a
  non-atomic `ops_seen`). Declare it with `storage_concurrency`:
  - `.single_thread` (default) — the `Store` belongs to the thread that called
    `init`; any other thread gets `error.NotOwningThread` from `put`/`get`/
    `delete` instead of corrupting the backend. `adoptOwner()` hands it over.
  - `.parallel_per_handle` — no latch, no owner check, genuine cross-shard
    parallelism. You are asserting the backend can take it.

Not provided: cross-shard atomicity (a write group spanning shards is not one
transaction — transactions/snapshots/cursors stay per-shard; the scan's
consistent cut comes from the single-owner rule, not a cross-shard snapshot),
a same-shard write latch, exclusion beyond one advisory
store-wide lock (`"<name_prefix>.lock"`, `error.Locked`), or resharding. See `SPEC.md` for the full contract, the path/naming scheme, and
the verification argument.

Provenance: original composition (plain key-sharding over single-writer stores);
no third-party source consulted or copied. See `NOTICE`.
