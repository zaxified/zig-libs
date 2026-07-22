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
var fs = shardstore.FsStorage.init(io, dir);
var store = try shardstore.Store.init(gpa, fs.storage(), .{ .n_shards = 8 });
defer store.deinit();

try store.put("user:42", "alice");           // routed to shardFor("user:42")
const v = try store.get(gpa, "user:42");     // caller frees v
defer if (v) |b| gpa.free(b);
try store.delete("user:42");

const idx = store.shardFor("user:42");        // stable owning-shard index

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
  `Storage`.

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

Not provided: cross-shard atomicity (a write group spanning shards is not one
transaction — transactions/snapshots/cursors stay per-shard), a global ordered
scan across shards, a same-shard write latch, cross-process exclusion, or
resharding. See `SPEC.md` for the full contract, the path/naming scheme, and
the verification argument.

Provenance: original composition (plain key-sharding over single-writer stores);
no third-party source consulted or copied. See `NOTICE`.
