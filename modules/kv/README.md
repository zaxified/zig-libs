# kv

Embedded, crash-consistent **key-value store** — a Bitcask-style append-only
log + in-memory keydir, with the module's whole value concentrated in one
place: an **injectable `Storage` seam** and a **deterministic fault-injection
sweep** (bounded mini-VOPR) that crashes the simulated machine at *every*
storage side effect and proves recovery each time.

- **Status:** `gap` — Zig has no production embedded DB.
- **Model after:** **Bitcask** (log-structured shape: append-only data file,
  in-memory keydir, compaction), **LMDB** / **xitdb** (single-writer embedded
  semantics), **TigerBeetle VOPR** (reliability via deterministic fault
  simulation instead of a giant test corpus).
- **Platform:** any — all I/O goes through `std.Io` behind the `Storage`
  seam (directory-fsync durability verified on Linux). **Role:** both.
- **Concurrency:** `threadsafe` — one coarse spinlock over every operation
  (see the honest caveats below).
- **Deps:** none (std only).

Provenance: clean-room. Design references only — Bitcask (the Basho paper's
log+keydir+merge model), LMDB and xitdb (embedded single-writer semantics),
TigerBeetle's VOPR (the deterministic fault-injection *approach*). Behavior
and approach only; no third-party source was consulted or copied. See
`NOTICE`.

## API

```zig
const kv = @import("kv");

// Production: FsStorage over a real directory (std.Io).
var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
var fs_store = kv.FsStorage.init(threaded.io(), dir); // dir: std.Io.Dir
var db = try kv.Db.open(gpa, fs_store.storage(), "app.kv", .{});
defer db.close();

try db.put("key", "value");        // durable (fsync'd) when this returns
const v = try db.get(gpa, "key");  // ?[]u8, caller frees; error.Corrupt never serves bad bytes
try db.delete("key");              // durable tombstone; absent key = no-op
_ = db.exists("key");              // in-memory
_ = db.count();                    // in-memory
if (db.deadBytes() > 1 << 20)      // caller-driven compaction (v0)
    try db.compact();              // temp + fsync + rename + dir-fsync swap
```

Options: `read_verify` (default true) re-checks the whole record CRC on every
`get`, so even post-`open` file rot is caught — corrupt data is **never**
served.

## On-disk format (v1, little-endian)

```
header:  "ZKVL" | version:u32            (8 bytes)
record:  crc32:u32 | op:u8 (0=put 1=del) | key_len:u32 | val_len:u32 | key | value
```

CRC-32 (IEEE) covers everything after the crc field. `open` replays the log
to rebuild the keydir; replay stops at the first torn/corrupt record and
**truncates** the file back to the last good one.

## Durability — the honest version

- `put`/`delete` return only after write + `fsync`. An acknowledged write
  survives OS crash / power loss **to the extent the platform's `fsync`
  reaches stable media** (drives with volatile write caches and lying
  hypervisors sit below this library).
- A torn trailing record (partial write at crash) is detected by
  length/CRC on `open` and discarded; committed records survive.
- Corruption policy: replay truncates at the *first* bad record — for
  mid-file media rot this also discards later records. v0 trades that rare
  case for a provable invariant: everything reachable after `open` is
  CRC-valid.
- After any storage-write error the store **poisons** itself (fail-stop —
  the fsyncgate lesson: a failed fsync leaves the page cache undefined).
  Mutations are refused; reads still serve the last consistent state;
  reopen to recover.
- Compaction swaps atomically (temp + fsync + rename + dir-fsync). A crash
  anywhere mid-compaction leaves the old file as the store; a stale
  `<path>.compact` temp is removed on the next `open`.

## Concurrency — v0 model

Internally synchronized with **one coarse spinlock** (`std.atomic.Mutex` +
`spinLoopHint`, the repo-standard io-less lock): single writer, and readers
see a consistent keydir because they take the same lock. Caveats, honestly:
a writer holds the lock **across fsync**, so a concurrent thread spin-waits
(burning CPU) for the duration of a disk flush — fine for embedded,
low-contention use; wrong for a hot multi-threaded server. Lockless MVCC
readers are a noted phase. **No cross-process locking** (no lock file): one
`Db` instance per store is the caller's responsibility.

## The Storage seam + mini-VOPR (the differentiator)

Every storage side effect — `open`, `writeAll`, `sync`, `truncate`,
`rename`, `delete`, `syncDir` — goes through the injectable `Storage`
vtable. Production uses `FsStorage`; tests use `SimStorage` (`sim.zig`), a
deterministic in-memory model of what an OS actually guarantees: file
content is volatile until `sync`, the *namespace* (create/rename/delete) is
volatile until `syncDir`, and a crash collapses the world under one of three
models (`lose_unsynced` / `keep_unsynced` / `torn_tail`).

The sweep (`fault_test.zig`) drives a scripted workload (puts, overwrites,
deletes, two compactions, edge keys) once per **(injection point × crash
mode)** — 55 injection points × 3 modes = 165 deterministic crash scenarios
— and asserts after each reboot+reopen: no acknowledged write lost, the
recovered state exactly equals the model with the in-flight op either
atomically applied or absent (never a mix, never torn data), compaction
crashes preserve the logical state, and the recovered store accepts new
durable writes. In-process, no randomness, no real process kill.

`SimStorage` is exported (`kv.SimStorage`) so consumers can crash-test their
own recovery logic.

## Noted phases (deliberately not in v0)

Full randomized VOPR at scale; immutable/MVCC on-disk structure
(HAMT/B-tree) with lockless readers; ordered/ranged scans; transactions and
batches; secondary indexes; automatic compaction thresholds; in-memory value
cache (compose with `ramcache`); cross-process lock file. The v0 keydir is
an unordered hash map.

Tests: `zig build test-kv` (29 tests — unit + sim-semantics + the sweep;
deterministic, tmp-dir round-trips on the real filesystem included).
