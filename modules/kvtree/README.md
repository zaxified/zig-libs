# kvtree

Embedded **ordered transactional key-value store** — a copy-on-write B-tree
(LMDB/BoltDB lineage) with MVCC snapshot isolation, multi-key ACID
transactions, ordered range scans, and crash-safety proven the same VOPR way
`kv` v0 is. The ordered/transactional sibling of the `kv` Bitcask point store:
use `kv` for get/put-only workloads (e.g. `jobqueue`); reach for `kvtree` when
you need `scan(a..b)` in key order, atomic multi-key commit/rollback, or readers
that see a consistent snapshot without blocking the writer.

- **Model after:** LMDB / BoltDB (COW B-tree, double-buffered meta pages);
  reliability via **TigerBeetle**'s VOPR (deterministic fault simulation).
- **Platform:** any — all I/O goes through `kv`'s `Storage` seam. **Role:**
  both. **Concurrency:** `single_owner` — one writer; MVCC readers take lockless
  immutable snapshots.
- **Deps:** `kv`, `crc32` (reuses its `Storage` seam and its deterministic crash/fault
  `SimStorage`).

> **Status: core implemented.** The irreducible core — `commit`'s
> durability-ordered COW meta swap, `recover`'s crash meta-selection, and the
> MVCC page-reuse gate — is implemented in `core.zig` and
> `gate.fable_core_implemented` is `true`: the property tests drive the real
> `Db` through commit/snapshot schedules (including a multi-level-tree phase)
> and a crash-point sweep over every storage side effect of a commit, across
> all four `kv.SimStorage` crash modes. Values larger than a page live in
> overflow chains; underfull nodes are merged; the free end of the file is
> given back. Buckets (named nested key spaces, bbolt's unit) and read-only
> openers in other processes (a shared lock, as bbolt's `ReadOnly`) are in since
> 2026-10-11. Not built (`SPEC.md` says why): in-place compaction (`copyTo`
> compacts into a new file, as bbolt's `Compact` does), batching of writers
> from several threads (a `Db` has one owner).
> The on-disk freelist is a page CHAIN (not a single bounded page) — freeing
> more pages than one page holds chains another, so nothing is silently
> leaked. Chain-storage pages are recycled from the freelist like tree pages;
> the commit reserves them *before* parking its own freed pages, which is what
> makes that safe (see `SPEC.md`). They were grown-only until 2026-08-25, and
> since every commit rewrites the chain, that made the file grow without bound
> — a page per commit even when the data set did not change. See `SPEC.md` for
> the A-vs-B design decision and the verification argument.

Provenance: clean-room. Design references only — LMDB (OpenLDAP Public
License) and BoltDB (MIT) for the copy-on-write B-tree with double-buffered
meta pages (MVCC + atomic commit + crash-safety emergent from COW, no separate
WAL), and TigerBeetle (Apache-2.0) for the VOPR deterministic fault-injection
*approach*. Behavior/approach only; no third-party source consulted or
copied. The comparative benchmark under `tools/` (`bench.zig` and its `go_bench/` reference side against go.etcd.io/bbolt v1.5.0, 2026-10-11) is our own tooling; it drives the reference only through its public API.

## API

```zig
const kvtree = @import("kvtree");

var db = try kvtree.Db.open(gpa, store, "app.kvt", .{}); // store: kvtree.Storage
defer db.close();

// Point ops (autocommit == a one-op transaction).
try db.put("key", "value");
const v = try db.get(gpa, "key");   // ?[]u8, caller frees
try db.del("key");

// Multi-key ACID transaction. NOTE: commit() CONSUMES the txn on both
// outcomes — after a failed commit do NOT rollback (the store is already on
// the last committed version); rollback only a txn you never commit.
var txn = try db.begin();
try txn.put("a", "1");
try txn.put("b", "2");
try txn.commit();                   // atomic: both or neither

// MVCC snapshot — a stable view that ignores later commits.
var snap = try db.snapshot();
defer snap.release();
var cur = try snap.cursor();
defer cur.deinit();
try cur.seek("m");                  // first key >= "m"
while (try cur.next()) |e| {        // ordered iteration; e.key/e.val borrow
    if (!std.mem.lessThan(u8, e.key, "t")) break; // scan [m, t)
    // use e.key, e.val (valid until the cursor's next call)
}

// Both directions: the cursor sits BETWEEN keys; next() yields the one after,
// prev() the one before. Newest first, from a key down (the key included):
try cur.seekAfter("t");             // or cur.last() for the very end
while (try cur.prev()) |e| { _ = e; }

// Buckets: named, nested key spaces (bbolt's `Bucket`), each a B-tree of its
// own, written in the same atomic commit as everything else in the txn.
var t2 = try db.begin();
const users = try t2.createBucketIfNotExists("users");
try users.put("alice", "...");
const id = try users.nextSequence();          // a per-bucket counter, committed with it
const sessions = try users.createBucket("sessions");
try sessions.put("s1", "...");
try t2.deleteBucket("old");                  // with everything in it
try t2.commit();
var s2 = try db.snapshot();
defer s2.release();
if (try s2.bucket("users")) |u| {
    const alice = try u.get(gpa, "alice");    // ?[]u8, caller frees; a bucket's name reads as null
    defer if (alice) |a| gpa.free(a);
    var uc = try u.cursor();                  // nested buckets yield KV.bucket = true
    defer uc.deinit();
}
_ = id;

// Read-only openers share the store across processes; a writer waits for them
// (and they for it): error.Locked, never a race.
var ro = try kvtree.Db.open(gpa, store, "app.kvt", .{ .read_only = true });
defer ro.close();                            // ro.begin() -> error.ReadOnly

// Backup and compaction in one: a full, compact copy of the newest version,
// written to "<path>.copy", synced, then renamed into place.
try db.copyTo(store, "app.kvt.bak");
```

Production wires `kvtree.FsStorage` over a real directory; tests use
`kvtree.SimStorage` (re-exported from `kv`) for deterministic crash simulation.

**For read speed, open the store on `kvtree.FsStorage.initMmap`** (Linux;
`Db.open(gpa, fs.storage(), ...)`): pages are then lent out of a read-only
mapping of the file with no syscall and no copy, the way bbolt and LMDB read
theirs -- gets about 0.85x LMDB, scans faster than bbolt and LMDB (SPEC.md,
Performance). Writes stay pwrites with the same fsyncs. Bare `FsStorage.init`
`pread`s every page of every descent (about 4x slower gets). The caveat of
every mmap store applies: a file truncated by someone else below a page in use
is a SIGBUS -- the store's lock keeps other writers out. A
`pagecache.PageCache` in front of plain `FsStorage` is the shape for a bounded
RAM budget (it lends resident pages too, at a cache lookup per page).

## Verify

```
zig build test-kvtree                          # Debug
zig build test-kvtree -Doptimize=ReleaseFast   # ReleaseFast
```

All tests run for real (no skips): the mechanical codecs, B-tree node ops,
read path, the property harness (correct oracle + broken positive control
that MUST trip the checkers), and the two core property tests — the
snapshot-isolation/serializability schedule and the crash-point sweep. See
`SPEC.md` for the verification argument.
