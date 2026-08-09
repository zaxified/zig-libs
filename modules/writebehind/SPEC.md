# writebehind — spec

Design + durability notes for auditors. Usage: see ./README.md. Attribution/provenance: original
work of the zig-libs authors (MIT); a pure composition of `ramcache` + `jobqueue` + `workerpool` +
`kvtree` — no new crypto, no new storage engine.

## What it is

A crash-safe **write-behind (write-back) cache coordinator** — the P2 data-layer feature (DL5).
Application writes hit an in-memory cache and return at cache speed; dirty entries are flushed to a
durable sink **asynchronously** by a worker pool. A durable write-ahead log makes it crash-safe: an
acknowledged `put` is never lost, even if the process dies before the async flush lands.

## Composition — each dependency used for its strength

- **`ramcache`** — the write buffer + read cache. `put` stages here (dirty); `get` serves here. Its
  write-behind seam is the coordination surface: the per-entry **dirty bit** + `drainDirty` tell the
  coordinator *which* keys still need flushing; `markClean` acks a persisted key; the **`on_evict`
  hook** fires (with the dirty flag) when a dirty entry is evicted before the flusher reaches it.
- **`jobqueue`** — the **durable WAL** and the crash-safety anchor. Every `put`/`del` appends a
  durable record (`enqueue`, fsync'd by `kv`) *before* the caller's ack. The flusher `dequeue`s
  (leases) a record, writes it to the sink, then `ack`s (a durable delete). **Partition = the cache
  key**, so a key's records dequeue oldest-first (FIFO) — the ordering that makes last-writer-wins
  hold. A crash leaves every un-acked record durable; `recover()` replays them.
- **`workerpool`** — flush concurrency. Each "write this record to the sink" job runs off the
  request path on a pool worker.
- **`kvtree`** — the reference durable **sink** (`KvtreeSink`). The `Sink` vtable is sink-agnostic;
  a SQL adapter (DL6) slots in without touching this module. `MapSink` is an in-memory sink.

## The exact durability & consistency guarantee

- **Durability (the headline).** When `put(k, v)` returns, `v` is durable. Ordering inside `put` is:
  (1) `jobqueue.enqueue` — the WAL record + its durable id counter are fsync'd; only *then* (2)
  `cache.put` stages it, and (3) return. A crash at any point after the ack loses nothing: the WAL
  record survives and `recover()` (or the next flush) re-applies it to the sink. This holds even
  though the sink write itself is asynchronous and may not have happened yet.
- **Consistency = eventual, last-writer-wins per key.** After a quiescent `flushAll()` (or a
  `recover()`), the sink reflects, for every key, the value of the **last** acknowledged `put` (or
  absence, after the last `del`).
- **Ordering.** Flushes for *different* keys may be reordered and run concurrently (the pool's
  value). Flushes for the *same* key are **serialized in enqueue order**: at most one flush per key
  is in flight (`in_flight` set), and its next record is only dequeued (FIFO WAL partition) after
  the previous one acks (`finishTask` → `dequeueFor(key)`). So a key never regresses to an older
  value, even under a wide pool.
- **At-least-once to the sink.** A recovered/retried record may be written more than once; because
  the sink is a keyed store, a duplicate write of the same `(k, v)` is idempotent. `recover()` is
  itself idempotent — a second call finds the WAL already drained and does nothing.

### Why LWW holds without value-coalescing

Each `put(k)` appends its own WAL record carrying that write's value. N writes to `k` → N records,
ids increasing. The flusher writes **the WAL record's value** (not a mutable cache snapshot), FIFO,
single-flight-per-key → the sink sees `v1, v2, …, vN` in order → `vN` wins. Recovery replays the
surviving records in global id order → same result. No coalescing pass, no per-key version tracking
is needed; the WAL id order *is* the version order.

## The workerpool producer-quiescence contract, honored

`workerpool` requires that its lifecycle (`drain`/`shutdownNow`/`deinit`) never runs concurrently
with `submit`, and that `max_submitters ≥ concurrent Submitter holders`, over a thread-safe,
not-near-exhaustion domain allocator (its `lockfree.dequeue` @panics on limbo-bag alloc failure).
How this module satisfies each:

- **Single submitter, single thread.** The coordinator is the *only* thing that submits, and only
  from the coordinator thread, via the shared spinlock-serialized `pool.submit` — never a
  `Submitter` handle. So `max_submitters = 0` is correct and sufficient.
- **Quiesce-before-lifecycle.** `deinit` runs `flushAll()` first. `flushAll` returns only when
  `unflushed == 0` **and** `in_flight == 0` — i.e. every submitted flush has completed and been
  harvested, and (because `deinit` is on the coordinator thread) no new `put`/`submit` can be racing
  it. Only then does `deinit` call `pool.drain()`. Producers are provably quiesced.
- **Thread-safe allocator.** `Options` documents (and the tests use) a thread-safe allocator; the
  pool allocates queue nodes/job boxes from worker threads, per its contract.

## Threading contract

- **Write side = single-owner.** One thread ("the coordinator thread") calls `put` / `get` / `del` /
  `drain` / `flushAll` / `sync` / `recover` / `deinit`. Not internally synchronized against each
  other — exactly like the `ramcache` / `jobqueue` / `kvtree` it wraps (all `single_owner`).
- **Flush concurrency is internal.** Pool workers run sink writes. A flush job (`flushEntry`)
  touches ONLY the `Sink` and the internal completion channel — never the cache or the WAL. It
  carries an **owned snapshot** (key + value copied out of the lease before it could ever expire)
  and the lease; on finish it links the task onto a spinlock-guarded completion list and bumps a
  futex generation. The coordinator harvests (`pump`) and does all cache/WAL bookkeeping
  single-owner.
- **The `Sink` must tolerate concurrent calls** (multiple workers, plus the coordinator during
  `get` read-through and `recover`). The reference `KvtreeSink`/`MapSink` serialize with a spinlock,
  since `kvtree` is single-writer.

## The Sink vtable (extension point for DL6)

```zig
pub const Sink = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        write:  *const fn (ptr, key, value) anyerror!void,
        delete: *const fn (ptr, key) anyerror!void,
        read:   ?*const fn (ptr, gpa, key) anyerror!?[]u8 = null, // optional read-through
    };
};
```

A DL6 SQL sink implements `write`/`delete` against a table (upsert / delete-by-key) and, if it
supports point reads, `read` for read-through — no coordinator change. `write`/`delete`/`read` may
run concurrently, so the adapter must be internally thread-safe (a connection pool, or a lock).

## Recovery & liveness details

- **`recover()`** dequeues the WAL globally (FIFO by id), applies each record to the sink, and acks
  it — synchronous, no pool. Call once after `init` over a non-empty WAL, before serving.
- **on_evict safety net.** A dirty entry evicted before flush fires `on_evict(dirty=true)`; the
  coordinator records the key as an **orphan** so the flusher revisits it even though the cache no
  longer lists it dirty. Its WAL record was already durable, so the write is never lost — the orphan
  set only closes a *liveness* gap (which key to flush), not a durability one.
- **Non-admission safety net (the same gap, a different door).** Eviction is not the only way a key
  can leave the cache's dirty list: `ramcache.put` **refuses admission outright** to any value
  larger than the whole cache budget (`value.len > max_bytes`) and fires **no** `on_evict`. Such a
  key was therefore neither cache-dirty nor an orphan, and `kick()`'s only two sources are
  `drainDirty` and `orphans` — so a server whose flush loop is the documented periodic `drain()`
  tick left an **acked, durable** record pending forever while the WAL grew without bound.
  `put` now checks `cache.isDirty(key)` after staging and registers a non-admitted key as an
  orphan. `startKey` takes the value from the WAL lease rather than from the cache, so an
  over-budget value flushes normally once selected.

  **Why the fix lives here and not in `ramcache`.** Refusing an item bigger than the entire cache is
  correct, deliberate cache policy — admitting it would evict everything else to hold one entry, and
  every other `ramcache` consumer relies on the bound. Nor is a synthetic `on_evict` for a value
  that was never resident honest. The defect was this module's: it treated "handed to the cache" as
  "registered for flush", when the cache is only a *hint* about which keys are pending and the WAL
  is the authority. Regression test: *"over-budget value: acked write is reachable by drain() ALONE"*,
  which deliberately avoids `flushAll` because its `flushOneSync` backstop masks the hole.
- **`flushAll` backstop.** If records remain but none are cache-dirty/orphan (e.g. a reopened WAL
  the operator never `recover()`ed), `flushOneSync` drains them synchronously so `flushAll` always
  terminates in a clean state. `deinit` calls `flushAll`, so even a forgotten `recover()` loses
  nothing.
- **Sink write failure** → the record is `nack`'d back to the WAL (with `retry_backoff_ns`) and the
  key stays dirty/orphan; a later `drain` retries. Retries are **unbounded by default**
  (`max_flush_attempts = 0`), so `flushAll` against a permanently-failing sink retries at ~20 Hz and
  does not return — an operational fault, not a data-loss one, exactly as this line has always
  claimed.

  It was not true until 2026-07-31. The WAL was enqueued at `jobqueue`'s default `max_attempts` of
  5, so the sixth rejection **dead-lettered an acknowledged write**: gone from the sink, gone from
  the retry path, with no error to the caller and `unflushed` still counting it (so `flushAll` could
  never reach a quiescent state again). The two reference sinks accept essentially every write, so
  no test drove a record to that cliff — the gap was in the *failure contract*, not in the vtable's
  shape, which is what a review looking only at the `Sink` signature would have missed.

- **Giving up is opt-in and never silent.** Set `max_flush_attempts` to a finite value to drop a
  poison record rather than block its key behind it. A dropped record increments `poisonedCount`
  and is retrievable via `poisoned` (key = `partition`, value = `payload`, plus the attempt count);
  the coordinator also stops counting it as pending and advances the key's queue, so one poison
  record does not strand the newer records behind it. **A non-zero `poisonedCount` is data loss
  that has already happened** — it is reported, not prevented.

## Threat model / out of scope

- **Not** a distributed/replicated store: one process owns the cache + WAL + sink. Multi-writer,
  cross-process coordination, and sink transactions spanning multiple keys are out of scope.
- **`del` read-shadowing** uses an in-memory `tombstones` set so a `get` after `del` misses
  immediately. A tombstone is reclaimed as soon as either happens: a later `put` supersedes it
  (immediate, synchronous), or its delete's own flush is durably confirmed (in `finishTask`, once
  the sink no longer holds the pre-delete value, a `get` read-through would correctly miss on its
  own — F2, wave-2 audit). The one case a tombstone still outlives its delete forever is a
  **poisoned** (dead-lettered) delete: it never reached the sink, so dropping its tombstone would
  let a later `get` read-through resurrect the stale value — deliberately conservative, and only
  reachable with a finite `Options.max_flush_attempts` (the default never dead-letters). For that
  edge case, prefer periodic `flushAll` + a fresh coordinator, or a sink whose read-through returns
  the (now absent) key.
- **Key size** is capped at `jobqueue.max_field_len` (4096) — it is the WAL partition; value size at
  the WAL payload cap (default 1 MiB). Both surface as typed `PutError`s before any durable write.
- Correctness of the async wake/park, the lock-free queue, and the durable log lives in
  `workerpool` / `lockfree` / `jobqueue` / `kv` SPECs respectively; this module composes them and
  adds the flush-orchestration + recovery logic on top.

## Backlog / future work

- DL6 SQL sink adapter (the primary reason the `Sink` vtable exists).
- Bounded/back-pressured `put` (block or reject when `unflushed` exceeds a high-water mark) — today
  `put` is always non-blocking and the WAL is unbounded.
- Coalescing superseded WAL records for a hot key (bounded WAL growth under repeated overwrites);
  correctness already holds without it, this is a space optimization.
- ~~A tombstone GC / compaction pass for delete-heavy workloads.~~ Done (F2, wave-2 audit) for the
  case that matters — GC on durable delete-flush confirmation, in `finishTask`. What is still
  backlog: a tombstone behind a **poisoned** delete is retained forever by design (see "Threat
  model" above) — there is no compaction pass for that residue today, only the existing
  `flushAll`-and-restart workaround.
