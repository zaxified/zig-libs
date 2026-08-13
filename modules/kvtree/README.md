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
- **Deps:** `kv` (reuses its `Storage` seam and its deterministic crash/fault
  `SimStorage`).

> **Status: core implemented.** The irreducible core — `commit`'s
> durability-ordered COW meta swap, `recover`'s crash meta-selection, and the
> MVCC page-reuse gate — is implemented in `core.zig` and
> `gate.fable_core_implemented` is `true`: the property tests drive the real
> `Db` through commit/snapshot schedules (including a multi-level-tree phase)
> and a crash-point sweep over every storage side effect of a commit, across
> all four `kv.SimStorage` crash modes. Remaining scaffold simplifications
> (documented in `SPEC.md`'s backlog): no overflow pages for entries larger
> than a page, merge-less deletes (empty leaves persist until overwritten).
> The on-disk freelist is a page CHAIN (not a single bounded page) — freeing
> more pages than one page holds chains another, so nothing is silently
> leaked; chain-storage pages are drawn only from fresh growth, never the
> reuse pool. See `SPEC.md` for the A-vs-B design decision and the
> verification argument.

Provenance: clean-room. Design references only — LMDB (OpenLDAP Public
License) and BoltDB (MIT) for the copy-on-write B-tree with double-buffered
meta pages (MVCC + atomic commit + crash-safety emergent from COW, no separate
WAL), and TigerBeetle (Apache-2.0) for the VOPR deterministic fault-injection
*approach*. Behavior/approach only; no third-party source consulted or
copied.

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
    // use e.key, e.val (valid until the next next()/seek())
}
```

Production wires `kvtree.FsStorage` over a real directory; tests use
`kvtree.SimStorage` (re-exported from `kv`) for deterministic crash simulation.

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
