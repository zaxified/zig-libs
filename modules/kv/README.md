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

Provenance: clean-room. Design references only — Bitcask (Basho, Apache-2.0;
the published log-structured model: append-only CRC'd record file + in-memory
keydir + merge/compaction; paper/design only), LMDB (OpenLDAP Public License)
and xitdb (MIT) for embedded single-writer semantics, and TigerBeetle
(Apache-2.0) for the VOPR deterministic fault-injection *approach* (simulate
storage faults at every I/O step, assert recovery), not its implementation.
Behavior and approach only; no third-party source was consulted or copied
for the module. The comparative benchmark under `tools/` (`bench.zig` and its
`go_bench/` reference side against github.com/rosedblabs/rosedb/v2 v2.4.0,
2026-10-14, with its `go.mod`/`go.sum` pinning the reference) is our own
tooling; it drives the reference only through its public API. rosedb's source
was read only to review it before running it and to explain its sync
behaviour (see SPEC § Compared with); none of it shaped or entered this module.

## API

```zig
const kv = @import("kv");

// Production: FsStorage over a real directory (std.Io).
var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
var fs_store = kv.FsStorage.init(threaded.io(), dir); // dir: std.Io.Dir
var db = try kv.Db.open(gpa, fs_store.storage(), "app.kv", .{});
defer db.close();

try db.put("key", "value");        // durable (fsync'd) when this returns (default policy)
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

// Snapshot iteration (Bitcask fold): key order, values as of the call, while writes go on.
var it = try db.iterator(gpa, "user:");
defer it.deinit();
while (try it.next()) |p| _ = .{ p.key, p.value };   // slices valid until the next call

// Listing: sorted copies of the live keys under a prefix ("" = all).
const ks = try db.keys(gpa, "user:");
defer ks.deinit(gpa);
for (ks.keys) |k| _ = k;

// Expiry (wall clock, ms since the Unix epoch — survives a restart):
try db.putTtl("sess:ab12", "…", 30 * 60 * 1000);      // absent 30 min from now
try db.putExpiring("otp:42", "…", deadline_ms);        // absent from deadline_ms on
_ = db.expiresAt("sess:ab12");                         // ?Expiry: .never / .at_ms

// Bitcask-style merging of sealed files (multi-file stores; writes go on meanwhile):
if (try db.mergePlan(gpa, .{})) |ids| {          // null: no trigger fired
    defer gpa.free(ids);
    try db.merge(ids);
}
const stats = try db.fileStats(gpa);            // per-file size, live/dead, fragmentation()
defer gpa.free(stats);

// A reader beside a live writer (any process): no lock, changes nothing, view as of open.
var r = try kv.Db.open(gpa, fs_store.storage(), "app.kv", .{ .read_only = true });
defer r.close();
try r.refresh();                                // see the writer's newer state

// Bitcask-style sync policies (default .always = fsync per write):
var fast = try kv.Db.open(gpa, fs_store.storage(), "cache.kv", .{ .sync = .none });
try fast.put("k", "v");            // acknowledged, durable at the next barrier
try fast.sync();                   // the barrier (also: compact, close best-effort)
// .{ .sync = .{ .interval_ms = 1000 } }: fsync inside the first write ≥ 1 s after the last
```

Expired keys are absent to `get`, `exists`, `count` and `keys` at once; `open`
and `compact` drop them from memory and from the file, and `deadBytes` counts
them as waste. Nothing expires in the background: memory and disk are freed by
the next `compact` (or restart). A store that never writes an expiring key never
reads the clock and keeps `count` O(1).

Options: `read_verify` (default true) re-checks the whole record CRC on every
`get`, so even post-`open` file rot is caught — corrupt data is **never**
served. `lock` (default `.exclusive`) takes the cross-process lock described
below; `.none` opts out. `clock` (default `CLOCK_REALTIME`) decides expiry;
tests inject their own. `sync` (default `.always`) picks when writes reach the
disk — `.always`, `.none` or `.interval_ms` (Bitcask's `o_sync`, `none`,
`{seconds, N}`); `sync_clock` (default `CLOCK_MONOTONIC`) times the interval.
`max_file_size` (default 2 GiB, Bitcask's) seals the active data file and
starts a new one before an append would cross it; the first rotation turns the
single file into a manifest + data files, and `compact` then merges files.

## On-disk format (little-endian)

```
header:  "ZKVL" | version:u32            (8 bytes; 1, or 2 once a key has expired-capable records)
record:  crc32:u32 | op:u8 (0=put 1=del 2=put-with-expiry) | key_len:u32 | val_len:u32
         | [expires_at:i64, op 2 only] | key | value
```

A multi-file store (after its first rotation, see `max_file_size`) keeps a
**manifest** at `<path>` instead — same magic, version 3: the data-file ids in
replay order and a CRC — and its data files at `<path>.<id>.data`, each in the
format above. ⚠ A build of `kv` that knows only versions 1–2 refuses such a
store (`error.UnsupportedVersion`); do not downgrade one.

A store stays at version 1 until its first expiring put, which upgrades it by
one compaction (atomic rewrite, never an in-place header edit). An older build
of this module refuses a version-2 file with `error.UnsupportedVersion` rather
than taking op 2 for a torn record and truncating the log there.

CRC-32 (IEEE) covers everything after the crc field. `open` replays the log
to rebuild the keydir; replay stops at the first torn/corrupt record and
**truncates** the file back to the last good one.

## Durability — the honest version

- With the default `SyncPolicy.always`, `put`/`delete` return only after
  write + `fsync`. An acknowledged write survives OS crash / power loss **to
  the extent the platform's `fsync` reaches stable media** (drives with
  volatile write caches and lying hypervisors sit below this library).
- With `.none` / `.interval_ms` a crash may lose acknowledged writes made
  since the last barrier (`sync`, `compact`, `open`, an interval sync), but
  recovery still yields the state after *some prefix* of the writes, never a
  mix — the log is append-only and replay stops at the first gap. `close`
  syncs best-effort and cannot report the error; call `sync` first.
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

## Concurrency

Internally synchronized with two locks. Writers (`put`, `delete`, `compact`,
`sync`) are serialized by one mutex held for their whole duration, fsync
included. Readers (`get`, `getBuf`, `exists`, `count`, `keys`, …) take a
read-write lock **shared**; a writer takes it exclusive only for its in-memory
keydir update, never across a write or an fsync. So any number of readers run
in parallel, a reader is never held up by a writer's disk flush, and it never
sees a value before the sync policy has made it durable. Over `FsStorage` both
are `std.Io` locks (they yield to the `Io`); over an io-less storage they spin
(the read-write spin lock is writer-preferring).

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
under one of four models (`lose_unsynced` / `keep_unsynced` / `torn_tail` /
`reorder_unsynced`).

Locking is modeled, not just implemented: `SimStorage` reproduces the three
states that matter — acquired, contended (`holdForeignLock` stands in for
another *process*, so it survives our crash while our own locks do not) and
unavailable (`lock_unsupported`) — and the acquisition is itself an
injection point, so the sweep crashes on it like any other side effect.

The sweep (`fault_test.zig`) drives a scripted workload (puts, overwrites,
deletes, two compactions, edge keys) once per **(injection point × crash
mode)** (the three simple modes; `reorder_unsynced` has its own exhaustive
sweep) — and asserts after each reboot+reopen: no acknowledged write lost, the
recovered state exactly equals the model with the in-flight op either
atomically applied or absent (never a mix, never torn data), compaction
crashes preserve the logical state, and the recovered store accepts new
durable writes. In-process, no randomness, no real process kill.

`SimStorage` is exported (`kv.SimStorage`) so consumers can crash-test their
own recovery logic.

The vtable also carries two **optional** read slots, `preadRef`/`releaseRef`,
defaulting to `null` — a backend that really holds the bytes in its own memory
can lend them instead of copying. `null` is the truthful answer for anything
descriptor-backed, so `FsStorage`, `SimStorage` and the VOPR backend all leave
them alone and `Storage.canLend()` reports `false` for them; there is
deliberately no internal fall-back to a copying read, because a fall-back that
looks like a success makes "did the fast path engage?" unanswerable at the call
site. A non-null `Ref` must go back to `releaseRef` exactly once, and until it
does the backend guarantees the bytes neither move nor change nor are freed.
`pagecache` is the implementor today and `kvtree`'s read descent the caller; see
`SPEC.md`.

Two more optional slots: `allocate` (`fallocate`: reserve space; the file reads
as zeros past its data) and `syncData` (`fdatasync`; `sync` where absent). With
both, an append-and-sync loop into reserved space ran 2.7× faster on ext4 than
growing the file. `FsStorage` has them on Linux; `SimStorage` models reserved
zeros faithfully across all four crash modes. See `SPEC.md`.

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
