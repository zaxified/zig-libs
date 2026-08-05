# kv

Embedded, crash-consistent **key-value store** — a Bitcask-style append-only
log + in-memory keydir, with the module's whole value concentrated in one
place: an **injectable `Storage` seam** and a **deterministic fault-injection
sweep** (bounded mini-VOPR) that crashes the simulated machine at *every*
storage side effect and proves recovery each time.

- Zig has no production embedded DB.
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

// Allocation-free read into a reused buffer (same locking + CRC check):
var buf: [4096]u8 = undefined;
const v2 = try db.getBuf(&buf, "key");        // error.BufferTooSmall, never truncated
const n = db.valueLen("key");                 // ?u32, for sizing the buffer
try db.delete("key");              // durable tombstone; absent key = no-op
_ = db.exists("key");              // in-memory
_ = db.count();                    // in-memory
if (db.deadBytes() > 1 << 20)      // caller-driven compaction (v0)
    try db.compact();              // temp + fsync + rename + dir-fsync swap
```

Options: `read_verify` (default true) re-checks the whole record CRC on every
`get`, so even post-`open` file rot is caught — corrupt data is **never**
served. `lock` (default `.exclusive`) takes the cross-process lock described
below; `.none` opts out.

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
readers are a noted phase.

## Cross-process exclusion — what it does and does not buy

`open` takes an exclusive **advisory** lock (`flock(2)`, non-blocking) on a
sidecar `<path>.lock` and holds it until `close`. A second opener — another
process, or a second `Db` in this one — gets `error.Locked`. Opt out with
`Options.lock = .none`.

- **`flock`, not `fcntl(F_SETLK)`.** A POSIX record lock is released as soon
  as the process closes *any* fd for that file, including one opened by
  unrelated code elsewhere in the program — a library cannot defend against
  that. `flock` is scoped to the open file *description*, so only closing
  that handle (or dying) releases it.
- **`fork`.** The child inherits a *share* of the same lock, not a second
  one; both halves are one holder, so do not write from both. A child that
  calls `Db.open` itself is correctly refused while the parent holds the
  store.
- **Crash cleanup is free.** The kernel drops the lock when the holder dies,
  so there are no stale locks, no PID files and no timeout heuristics. A
  `SIGKILL`ed writer's store is immediately openable — there is a test that
  kills a real forked child to prove it.
- **Non-blocking on purpose.** `open` returns `error.Locked` rather than
  parking your thread inside a library call for an unbounded time; waiting
  or retrying is the caller's policy.
- **A sidecar, not the data file.** `compact()` swaps the data file by
  `rename(2)`; a lock on that file would end up stranded on an unlinked
  inode while the store's *name* pointed at a fresh, unlocked one. The
  sidecar's inode is stable, and it is never deleted (unlink+recreate would
  hand two processes locks on two different inodes of one name).
- **Not promised:** anything on NFS/SMB/9p/FUSE. Linux emulates `flock` over
  POSIX locks on NFS (re-introducing the close footgun), and several mount
  configurations make it node-local, i.e. silently no protection against a
  writer on another host. This module promises cross-process exclusion on
  **local POSIX filesystems**; nothing at this layer can detect the
  degradation. Advisory also means a process that never calls `Db.open` is
  not stopped by any of it. A backend that cannot lock at all reports
  `error.LockUnsupported` — it is never downgraded to "no lock" silently.

## The Storage seam + mini-VOPR (the differentiator)

Every storage side effect — `open`, `writeAll`, `sync`, `truncate`,
`rename`, `delete`, `syncDir`, `tryLockExclusive` — goes through the
injectable `Storage` vtable. Production uses `FsStorage`; tests use
`SimStorage` (`sim.zig`), a deterministic in-memory model of what an OS
actually guarantees: file content is volatile until `sync`, the *namespace*
(create/rename/delete) is volatile until `syncDir`, a lock belongs to an
open file description and dies with it, and a crash collapses the world
under one of three models (`lose_unsynced` / `keep_unsynced` / `torn_tail`).

Locking is modeled, not just implemented: `SimStorage` reproduces the three
states that matter — acquired, contended (`holdForeignLock` stands in for
another *process*, so it survives our crash while our own locks do not) and
unavailable (`lock_unsupported`) — and the acquisition is itself an
injection point, so the sweep crashes on it like any other side effect.

The sweep (`fault_test.zig`) drives a scripted workload (puts, overwrites,
deletes, two compactions, edge keys) once per **(injection point × crash
mode)** — 57 injection points × 3 modes = 171 deterministic crash scenarios
— and asserts after each reboot+reopen: no acknowledged write lost, the
recovered state exactly equals the model with the in-flight op either
atomically applied or absent (never a mix, never torn data), compaction
crashes preserve the logical state, and the recovered store accepts new
durable writes. In-process, no randomness, no real process kill.

`SimStorage` is exported (`kv.SimStorage`) so consumers can crash-test their
own recovery logic.

## VOPR extras: pluggable fault scheduling + failing-seed search

Beyond the fixed sweep, `vopr.zig` runs thousands of *randomized* fault
schedules per `zig build test-kv` (see its module doc). Two auditor-facing
extras sit on top of it:

- **`FaultScheduler`** (`scheduler.zig`) — the epoch-planning decision (which
  fault, how soon) is a pluggable seam (`vopr.Config.scheduler`), not inline
  logic. `uniformScheduler()` (the default) reproduces the harness's original
  flat-random distribution exactly; `coverageGuidedScheduler(&state)` biases
  the (fault-class × timing) draw toward the least-exercised cells (bandit-style
  epsilon-greedy over a cross-seed `Coverage` tally), covering all reachable
  cells measurably faster than uniform sampling on the same budget.
- **`shrink.zig`** — `findFailingSeed(gpa, start, end, cfg)` sweeps a seed
  range and returns the first captured failure (seed + full op/fault trace);
  `run(gpa, args, writer)` is a CLI-style driver (`--seed N`,
  `--search START END`, `--shrink`, `--sabotage`, `--quiet`) for ad-hoc
  exploration. `shrink(gpa, failing)` delta-debugs (ddmin) a failing run to a
  strictly smaller reproducer, using `vopr.zig`'s trace-replay mode
  (`generateTrace` captures a seed as a concrete, replayable `RecordedTrace`;
  `replayTrace` re-runs any subset deterministically without a live `Prng`).

## Noted phases (deliberately not in v0)

Full randomized VOPR at scale; immutable/MVCC on-disk structure
(HAMT/B-tree) with lockless readers; ordered/ranged scans; transactions and
batches; secondary indexes; automatic compaction thresholds; in-memory value
cache (compose with `ramcache`); shared/reader locks (the store is
single-writer, so the cross-process lock is exclusive-only). The v0 keydir
is an unordered hash map.

Tests: `zig build test-kv` (unit + sim-semantics + the fixed
sweep + the randomized VOPR + the scheduler/shrink extras above;
deterministic, tmp-dir round-trips on the real filesystem included).
