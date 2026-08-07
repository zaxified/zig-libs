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

One more file sits beside the shards: `<name_prefix>.manifest`, sixteen bytes of
magic + `n_shards` as u64 LE. It is written once when the store is created and
verified (then closed again, before any shard is opened) on every later `init`.

**Why it exists — `n_shards` is part of the data's identity.** Routing is
`hash % n_shards`, so a different shard count re-routes essentially every key.
The old behaviour was the bad kind of wrong: `init` succeeded, and the router
then looked for existing keys in the wrong files. Measured on a 200-key store
created with 4 shards, reopening it with 8 found 98/200 and with 2 found 88/200
— the rest read as *absent*, indistinguishable from never having been written,
after nothing worse than an operator editing a config value. That is silent
partial data loss, so it now fails closed with `error.ShardCountMismatch`.
A file under the manifest name that is not ours (bad magic, or shorter than one
record) is refused with `error.CorruptManifest` rather than overwritten.

Two limits, stated rather than papered over: a store created before manifests
existed has none, so the first `init` that touches it adopts whatever count it
is given; and the manifest is a *consistency* check, not a lock — see the
missing cross-process exclusion below.

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
- **…and every word above is conditional on the backend.** This is the part that
  used to be missing. The router and the `Db`s hold no shared mutable state, but
  each operation ends in the injected `Storage`, and that is where two shards'
  operations meet. Cross-shard parallelism is therefore real only over a backend
  that is itself safe for concurrent operations on **distinct handles**.
  `FsStorage` is: every operation is a positional `pread`/`pwrite` on its own
  `std.Io.File`, and the only shared field — the handle table — is written solely
  by `open`/`close`, which happen single-threaded in `init`/`deinit`.
  `SimStorage` is **not**: plain `StringHashMapUnmanaged`/`ArrayListUnmanaged`
  state and a non-atomic `ops_seen`.

  `Options.storage_concurrency` makes that precondition part of the API, and it
  is **enforced**, not merely documented:

  - `.single_thread` (**the default**, because guessing wrong the other way is
    silent UB while guessing wrong this way costs only throughput) — the `Store`
    is a single-thread object. `init` records the calling thread; `put`/`get`/
    `delete` from any other thread return `error.NotOwningThread` instead of
    reaching the backend. `adoptOwner()` hands the store over explicitly, which
    is what an init-on-main / run-on-worker consumer wants. The check is two
    loads and a compare against the address of a `threadlocal` — no syscall, no
    atomics — and it is deterministic: a foreign thread is refused whether or not
    it happens to overlap with the owner.
  - `.parallel_per_handle` — the caller asserts the backend is per-handle
    concurrent. Routed operations then take no latch and no owner check, and
    threads on distinct shards genuinely run in parallel. The same-shard rule
    above still applies.

  **This is what the wave-2 F1 finding was about.** The module's headline test
  drove four threads through one `SimStorage`; the audit measured a lost
  increment (serial `ops_seen` 33006 vs parallel 33005), so the test certifying
  "no contention" was itself a data race, and the claim had never run on a
  backend that could carry it. The claim was not wrong — the composition it was
  demonstrated over was.

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
- **No cross-process exclusion.** `kvtree.Db.open` discards its options and
  never takes the advisory lock the `Storage` seam offers, so two `Store`s over
  the same paths do not exclude each other — and this module multiplies that
  exposure by `n_shards`. Tracked as wave-2 F2, whose fix belongs in `kvtree`.
  The manifest does not help here: it detects a *different* shard count, not a
  second concurrent opener with the same one.
- **No rebalancing / resharding.** `n_shards` is fixed for the lifetime of the
  on-disk set — now enforced by the manifest rather than merely assumed. Growing
  it means migrating the data (read every key through a `Store` opened with the
  old count, write it through one opened with the new). Incremental resharding —
  Redis Cluster's 16 384 fixed hash slots mapped to shards, or a consistent-
  hashing ring with virtual nodes, which is what `model_after` alludes to — would
  move slots instead of rehashing every key; it is deliberately **not**
  implemented here. One `Store` per on-disk shard set, mirroring `kvtree`'s
  one-`Db`-per-store rule.
- Durability, crash-safety and ordered semantics **within** a shard are
  inherited from `kvtree` under the same `fsync`-honesty caveat `kv`/`kvtree`
  document — this router neither strengthens nor weakens them.

## Verification

Tests (Debug + ReleaseFast, both green, 13/13; `zig fmt` clean, no leaks):

- **deterministic routing** — same key → same shard repeatedly, and identical
  routing across two `Store` instances with the same `n_shards`;
- **distribution** — a 2000-key histogram over 8 shards hits every shard well
  above the mean's lower bound (no stuck router);
- **round-trip** — put→get across all shards, then delete half and confirm the
  survivors (on other shards) are untouched;
- **multi-core write parallelism (headline)** — over `FsStorage` in a
  `std.testing.tmpDir`, declared `.parallel_per_handle`. Keys are bucketed by
  owning shard and one writer thread per shard writes its disjoint, single-shard
  range concurrently; after join, every write is present and reads back
  byte-exact, over three rounds.

  Crucially it does not stop there, because *correct data is exactly what a
  fully serialized run would also produce* — which is how the original claim
  went unexamined for so long. A pass-through `Storage` shim rendezvouses the
  first backend write of each thread: the barrier opens only once all four
  threads are inside the backend simultaneously, on four distinct shards, and
  each arriving thread blocks until then. Serialize the routed path and the
  barrier is never met, the shim reports `timed_out`, and the test fails — a
  deterministic consequence of serialization rather than a race one hopes to
  observe. (Verified: adding a global latch to `put` turns this red at exactly
  the `!timed_out` assertion.)
- **the unsafe shape is refused** — several threads over a `.single_thread`
  (`SimStorage`) store get `error.NotOwningThread` from `put`/`get`/`delete`,
  and nothing they attempted reaches the backend; a companion test covers the
  explicit `adoptOwner()` hand-off. Deterministic, so unlike a concurrency test
  it cannot pass by luck.
- **shard-count manifest** — a store created with 4 shards refuses to reopen
  with 8 or with 2 (`error.ShardCountMismatch`) while reopening with 4 finds all
  200 keys; a foreign or truncated file under the manifest name is refused with
  `error.CorruptManifest` instead of being overwritten;
- **persistence** — write over `FsStorage` in a `std.testing.tmpDir`, drop the
  `Store`, reopen a fresh one over the same dir/paths, and read everything back
  (durability delegated to `kvtree`);
- **non-power-of-two** — `n_shards = 5` exercises the modulo routing path and
  round-trips.

## Status line

`any · both · single_owner` + dep `kvtree`, model_after "consistent
key-sharding over N single-writer stores (Redis Cluster / Dynamo partitioning
idea)" — canonical source is `pub const meta` in src/root.zig.
