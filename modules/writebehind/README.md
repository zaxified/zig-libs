# writebehind

A crash-safe **write-behind (write-back) cache coordinator**. Application writes
hit a fast in-memory cache and return immediately; dirty entries are flushed to
a durable sink **asynchronously** by a worker pool, with a durable write-ahead
log guaranteeing that an **acknowledged write is never lost** even if the
process crashes before the async flush lands.

This is the P2 data-layer feature (DL5) — the way the server acks writes at cache
speed while keeping durability. It is a pure **composition** of four modules:
`ramcache` (write buffer + read cache), `jobqueue` (durable WAL), `workerpool`
(flush concurrency), and `kvtree` (the reference durable sink).

- **Model after:** a write-back cache (Caffeine `writeBehind`, a DB buffer pool)
  over a durable WAL.
- **Platform:** posix (the WAL's default clocks use `clock_gettime`; injectable).
  **Role:** both. **Concurrency:** `single_owner` — the write-side API is
  single-owner (one coordinator thread); flush concurrency is internal (the
  worker pool).
- **Deps:** `ramcache`, `workerpool`, `jobqueue`, `kvtree` (which re-exports
  `kv`'s `Storage`/`FsStorage`/`SimStorage` seam — `writebehind` re-exports them
  too, so a consumer needs no direct `kv` import for the WAL backend).

## Guarantee

- **Durability:** when `put(k, v)` returns, `v`'s WAL record has been fsync'd — a
  crash loses nothing; `recover()` re-applies it to the sink.
- **Consistency:** eventual, **last-writer-wins per key**. After `flushAll()` /
  `recover()` the sink holds each key's last acknowledged value (or absence,
  after the last `del`). Different keys flush concurrently; the same key flushes
  in enqueue order (never regresses).

See `SPEC.md` for the exact ordering argument, the threading contract, and how
the `workerpool` producer-quiescence + thread-safe-allocator contract is honored.

## API

```zig
const writebehind = @import("writebehind");
const kvtree = @import("kvtree");

// A durable sink (any Sink works; kvtree is the reference adapter).
var sink_fs = writebehind.FsStorage.init(io, dir);
var sink_db = try kvtree.Db.open(gpa, sink_fs.storage(), "sink.kvt", .{});
defer sink_db.close();
var ksink = writebehind.KvtreeSink.init(gpa, &sink_db);

// The coordinator: cache + durable WAL + flush pool.
var c = try writebehind.Coordinator.init(gpa, .{
    .io = io,                         // for the pool + flushAll wait
    .sink = ksink.sink(),
    .wal_store = wal_fs.storage(),    // durable WAL backend
    .wal_path = "wal.jq",
    .max_cache_bytes = 64 << 20,
    .max_cache_entries = 100_000,
    .n_workers = 4,
});
defer c.deinit();                     // flushes everything, then quiesces the pool

// Reopening over a non-empty WAL? Replay pending writes before serving:
try c.recover();

// Write path — fast ack, durable-on-return.
try c.put("user:42", "alice");
const v = try c.get("user:42");       // cache hit (or sink read-through); borrowed slice
try c.del("user:42");

// Flush control.
c.drain();        // one non-blocking flush pass (tick / threshold trigger)
c.flushAll();     // block until the cache is clean (graceful barrier); alias: sync()
```

- `Sink` is a small vtable (`write` / `delete` / optional `read`); implement it
  to target any durable store. `KvtreeSink` (durable) and `MapSink` (in-memory)
  are provided. A SQL sink (DL6) slots in without touching this module.
- **A sink that rejects writes costs liveness, not data.** Failed sink writes go
  back to the WAL and are retried indefinitely, so `flushAll` against a
  permanently-failing sink keeps retrying rather than returning. Set
  `max_flush_attempts` to a finite value to drop poison records instead; those
  are then counted by `poisonedCount()` and listed by `poisoned()` — never
  dropped silently.
- `deinitNoFlush()` is an abrupt teardown that keeps the WAL durable and
  delegates durability to the next process's `recover()` (also the crash
  simulation used in tests).

## Tests

`zig build test-writebehind` (and `-Doptimize=ReleaseFast`) — real
threads via the pool, `DebugAllocator`-clean. Covers: immediate cache
readability + post-flush sink consistency; last-writer-wins; delete +
read-shadow; sink read-through; **crash recovery** (drop the coordinator+cache
without flushing, then `recover()` from the durable WAL → every acked write
present, idempotent under double-recovery); the `on_evict` safety net (a dirty
entry evicted before flush is still persisted); pool concurrency over 1000 keys;
the real on-disk `kvtree` sink over `tmpDir`; size-cap rejection; and a
deliberately **failing** sink — that an acked write survives far more rejections
than the WAL's old attempt cap, that an explicit cap drops the record visibly
and without stranding the queue, and that a newer record for a poisoned key is
still flushed.
