# shardstore — spec

A key-sharding router over N independent `kvtree` stores: the multi-core
**write-parallelism** layer for the data family. Usage: see ./README.md.
Provenance: original composition — plain consistent-by-key sharding over N
single-writer stores (the Redis Cluster / Dynamo partitioning idea); no source
ported. See /NOTICE.

## Problem

A single `kvtree` is a copy-on-write B-tree with a single durable writer at a
time (its correctness core is exactly the crash-atomic single-meta swap). That
is the right trade for embedded ordered/transactional storage, but it means one
`kvtree` cannot absorb multi-core write throughput: concurrent writers to one
`Db` must serialize.

The standard scale-out is to **shard by key**: split the keyspace across N
independent stores, each its own single-writer domain backed by its own file.
Writes to keys in *different* shards then proceed fully in parallel, because
they touch entirely separate `kvtree.Db` state and separate files with no lock
between them. `shardstore` is that router — nothing more.

## Routing

`shardFor(key)` hashes the key with `std.hash.Wyhash` (seed 0) and reduces it to
`[0, n_shards)`:

- **power-of-two `n_shards`**: `hash & (n_shards - 1)` (mask);
- **otherwise**: `hash % n_shards` (modulo).

Both are deterministic: the **same key always routes to the same shard**, within
a run and across `init`s with the same `n_shards`. Wyhash is a stable,
dep-free, non-cryptographic hash — good spread for uniform shard occupancy, and
not a security boundary (the router never defends against adversarial key
choice). `n_shards` a power of two is convenient (cheap mask) but not required.

## Path / naming scheme

Each shard is one `kvtree` file. Shard `i` is named:

```
<name_prefix>-<i:0>5><name_suffix>
```

with defaults `name_prefix = "shard"`, `name_suffix = ".kvt"` → `shard-00000.kvt`,
`shard-00001.kvt`, … Names are resolved by the injected `Storage` (for
`FsStorage`, relative to its `dir`), exactly as `kvtree`/`kv` resolve any path.
Reopening a `Store` over the same `Storage`/dir with the same `n_shards` and
naming re-attaches to the same files, so a key lands back on the shard that
holds it — persistence is entirely delegated to `kvtree`'s durability.

Zero-padding to five digits keeps names sorted and fixed-width for up to 99999
shards; a prefix/suffix that overflows the format buffer is rejected at `init`
with `error.ShardNameTooLong` (never a panic).

## Threading contract (precise)

The router holds only **immutable-after-`init`** state — the shard slice is
allocated once and never resized — so it introduces **no** synchronization and
**no** cross-shard coordination. Each shard's guarantee is `kvtree`'s, verbatim:

- **Distinct shards are independent.** Two threads operating on keys that hash
  to different shards never contend: separate `Db` state, separate files, no
  shared mutable router state. Concurrent access to distinct slice elements is
  data-race-free. This is the whole point, and the design encourages
  partitioning work by shard (drive one dedicated writer thread per shard via
  `shardAt`).
- **Same shard is bounded by kvtree's single-writer rule.** Two writers that
  hash to the *same* shard serialize per `kvtree`'s `single_owner` contract —
  and this router does **not** add a latch to make concurrent same-shard writers
  safe. The caller MUST serialize same-shard writers (or a future latch layer
  will). `shardFor` is public precisely so a caller can partition work up front
  and guarantee one writer per shard.

This module claims **no more** safety than `kvtree` provides. `kvtree` is
`single_owner` (one thread/loop owns a `Db`'s mutation state, lock-free); a
stateless key-router over N of them is per-shard single-owner and cross-shard
parallel — no more, no less.

## What it does NOT guarantee

- **No cross-shard atomicity.** A group of writes that spans shards is not a
  single transaction — each shard commits independently. Multi-key ACID
  transactions, MVCC snapshots and ordered range cursors remain **per-shard**
  (`kvtree`'s `begin`/`snapshot`/`cursor`), reachable via `shard(key)` /
  `shardAt(index)`. To keep a group atomic, choose keys that route to one shard,
  or use `n_shards = 1`.
- **No global ordered scan.** Keys are ordered *within* a shard only; there is
  no merge-sorted scan across shards (a k-way merge over per-shard cursors is a
  mechanical future addition, not provided here).
- **No same-shard write latch.** See the contract above — the caller partitions.
- **No cross-process exclusion** and **no rebalancing / resharding.** `n_shards`
  is fixed for the lifetime of the on-disk set; changing it re-routes keys and
  is out of scope (as with any modulo/mask sharding). One `Store` per on-disk
  shard set, mirroring `kvtree`'s one-`Db`-per-store rule.
- Durability, crash-safety and ordered semantics **within** a shard are
  inherited from `kvtree` under the same `fsync`-honesty caveat `kv`/`kvtree`
  document — this router neither strengthens nor weakens them.

## Verification

Tests (Debug + ReleaseFast, both green, 9/9; `zig fmt` clean, no leaks):

- **deterministic routing** — same key → same shard repeatedly, and identical
  routing across two `Store` instances with the same `n_shards`;
- **distribution** — a 2000-key histogram over 8 shards hits every shard well
  above the mean's lower bound (no stuck router);
- **round-trip** — put→get across all shards, then delete half and confirm the
  survivors (on other shards) are untouched;
- **multi-core write parallelism (headline)** — keys are bucketed by owning
  shard, then one writer thread per shard writes its disjoint, single-shard key
  range concurrently (`std.Thread`); after join, every write is present and
  reads back byte-exact — independent shards demonstrably do not contend, and
  same-shard access stays single-threaded per the contract;
- **persistence** — write over `FsStorage` in a `std.testing.tmpDir`, drop the
  `Store`, reopen a fresh one over the same dir/paths, and read everything back
  (durability delegated to `kvtree`);
- **non-power-of-two** — `n_shards = 5` exercises the modulo routing path and
  round-trips.

## Status line

`any · both · single_owner` + dep `kvtree`, model_after "consistent
key-sharding over N single-writer stores (Redis Cluster / Dynamo partitioning
idea)" — canonical source is `pub const meta` in src/root.zig.
