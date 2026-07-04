# SPEC — `kv`

Embedded, crash-consistent **key-value store** (no SQL) — the pure-Zig local DB. Wave P0 (flagship
complex). `gap · any · both · tsafe`. Model after: **Bitcask** (log-structured: append-only data
file + in-memory keydir + compaction) for the v0 shape, **LMDB**/**xitdb** for semantics, and the
**TigerBeetle VOPR** deterministic-fault-injection approach for reliability. Deps: **none (std
only)**. Greenfield (no seed — see the CML `zig_native_storage_landscape` decision: SQL rejected,
native KV = viable in months). New `build.zig` entry `.{ .name = "kv" }`.

## Why

Zig has no production embedded DB. A crash-consistent KV store is buildable and broadly useful.
The point of difference is **reliability via deterministic simulation** (fault-inject at every I/O
step, assert recovery) rather than a giant test corpus — the TigerBeetle model.

## Scope — v0 (this task; keep it bounded and BULLETPROOF, not big)

1. **Log-structured store (Bitcask-style):** a single append-only **data file** of length-prefixed,
   **CRC-checked** records `{ op: put|del, key, value }`, plus an in-memory **keydir**
   (`key → {file_offset, len}` or a tombstone). `open(path)` replays the log to rebuild the keydir;
   `put`/`get`/`delete`/`exists`; `get` reads the value from the file at the recorded offset (or an
   in-memory value cache — your call, document).
2. **Durability + crash consistency (the heart of it):** each committed write is `fsync`'d; a
   **torn trailing record** (partial write / bad CRC at the tail) is detected on `open` and the file
   **truncated to the last good record** — committed data survives, a half-written tail is discarded.
   Never return corrupt data; never lose an fsync'd commit.
3. **Compaction:** rewrite live entries into a fresh file (drop overwritten/deleted), swap in
   **atomically** (temp file + `fsync` + `rename` + dir `fsync`); a crash mid-compaction leaves the
   old file intact (recover to pre-compaction state). Bound log growth.
4. **Concurrency:** single-writer; reads can be concurrent with the writer (MVCC-ish — reads see a
   consistent keydir snapshot). v0 may be single-owner with a documented lock; full lockless-MVCC is
   a noted PHASE. State the model clearly.
5. **Deterministic fault-injection harness (the mini-VOPR — REQUIRED, this is the differentiator):**
   put ALL storage side effects (`write`, `fsync`, `rename`, `truncate`, dir-`fsync`) behind an
   **injectable storage interface**. A test harness runs an operation sequence and, at **every
   injection point**, simulates a crash (subsequent effects don't happen / a write is torn) then
   re-`open`s and asserts an invariant: **every acknowledged (fsync-returned) put is present and
   readable, no torn record is served, the store always opens to a consistent state.** Sweep every
   crash point across a scripted workload. (This is a *bounded* deterministic sim — NOT the full
   1000×-random VOPR, which is a noted PHASE.)

## PHASES (note as future, do NOT build now)
- Full VOPR: randomized long-running fault-injection at scale (the TigerBeetle 24/7 model).
- Immutable/MVCC on-disk structure (xitdb-style HAMT, lockless readers), ranged/ordered scans
  (B-tree), transactions/batches, secondary indexes. v0 keydir is an unordered hash map.

## Public API sketch (final = your call; allocator-explicit)

```zig
pub const Db = struct {
    pub fn open(gpa, path: []const u8, Options) !Db;   // Options: value_cache, compaction thresholds, Storage
    pub fn close(*Db) void;
    pub fn put(self, key: []const u8, value: []const u8) !void;   // durable on return (fsync)
    pub fn get(self, key: []const u8, buf_or_alloc) !?[]const u8;
    pub fn delete(self, key: []const u8) !void;
    pub fn exists(self, key: []const u8) bool;
    pub fn compact(self) !void;
    pub fn count(self) usize;
};
pub const Storage = struct { /* injectable write/fsync/rename/truncate — real fs default, fault-sim in tests */ };
```

## Acceptance / verification

- **Offline unit tests:** put/get/delete/overwrite/exists/count; **persistence** (put, close, reopen
  → values recovered); tombstone semantics (deleted key stays deleted across reopen); **compaction**
  (log shrinks, all live data intact, dead entries gone); record CRC rejects a corrupted byte;
  large-ish values; empty/one-byte keys+values; reopening an empty/nonexistent file.
- **Fault-injection sweep (the headline test):** a scripted workload driven through the injectable
  `Storage`; at **every** injection point simulate a crash and assert on reopen: no acknowledged put
  lost, no torn/corrupt record served, keydir consistent, compaction crash → old state intact. This
  must be deterministic and run in-process (no real process kill).
- `zig build test-kv` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check` clean.
  Registered with no deps.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 (std.fs File, pread/pwrite, fsync, atomic rename, std.hash.Crc,
  HashMap). NO libc. Keep the on-disk record format simple + versioned (a magic + version header) so
  future phases can evolve it.
- The **injectable Storage** is the key design: real filesystem by default, a fault-simulating
  implementation in tests. Everything durability-related MUST go through it so the sweep can crash
  anywhere. This is the module's whole value — do it first, build the store on top.
- Be honest in docs about the durability guarantee (what `fsync` does/doesn't promise) and the v0
  concurrency model. SPDX MIT + a `Provenance:` line (clean-room; design refs Bitcask / LMDB / xitdb
  / TigerBeetle VOPR — behavior/approach only, no source copied). Add the NOTICE design-ref entry.
