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

> **Status: SCAFFOLD — the transactional core is a Fable stub.** The page/node
> codecs and B-tree split/merge, the pager + freelist, the read/descend/cursor
> path, fresh-store init, and the whole property harness (with an in-memory
> oracle and a deliberately-broken positive control) are real and green today.
> The irreducible core — `commit`'s durability-ordered COW meta swap,
> `recover`'s crash meta-selection, and the MVCC page-reuse gate — is a `@panic`
> stub in `core.zig`; the property tests that drive it are gated behind
> `gate.fable_core_implemented` and report SKIP until it flips. Do not deploy
> until the gate is `true`. See `SPEC.md` for the A-vs-B design decision and
> exactly what the Fable core is.

Provenance: clean-room. Design references only — LMDB/BoltDB (COW B-tree +
meta-page double-buffer) and TigerBeetle's VOPR (deterministic fault-injection
*approach*). Behavior/approach only; no third-party source consulted or copied.
See `NOTICE`.

## API (intended shape — read path works today; write path is gated)

```zig
const kvtree = @import("kvtree");

var db = try kvtree.Db.open(gpa, store, "app.kvt", .{}); // store: kvtree.Storage
defer db.close();

// Point ops (autocommit == a one-op transaction) — gated on the core.
try db.put("key", "value");
const v = try db.get(gpa, "key");   // ?[]u8, caller frees
try db.del("key");

// Multi-key ACID transaction.
var txn = try db.begin();
errdefer txn.rollback();
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
zig build test-kvtree                          # Debug (2 core tests SKIP)
zig build test-kvtree -Doptimize=ReleaseFast   # ReleaseFast
```

Green today with the two core-dependent property tests skipped; the mechanical
codecs, B-tree node ops, read path, and the property harness (correct oracle +
broken positive control that MUST trip the checkers) all run for real. See
`SPEC.md` for the verification argument and the Fable-core boundary.
