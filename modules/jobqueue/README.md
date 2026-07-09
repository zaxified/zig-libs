# jobqueue

Durable **background-job queue** over the pure-Zig [`kv`](../kv) log:
`enqueue` → `dequeue` (lease) → `ack` / `nack`, with retry+backoff, a
dead-letter queue, per-partition FIFO ordering under a priority override, and
scheduled visibility (`delay_ns` / `run_at`).

- **Status:** `gap` — no production pure-Zig background-job queue exists.
- **Model after:** Faktory / Sidekiq (lease + retry + DLQ) over a Bitcask-style
  log; the injected-`Clock` pattern from the `resilience` / `jwt` siblings.
- **Platform:** `posix` — the OS-default wall/monotonic clocks use
  `clock_gettime` (both injectable; everything else is pure logic + `kv`).
- **Role:** both. **Concurrency:** `single_owner` — one owner drives the queue
  and the caller-driven maintenance sweep; the in-memory index is not locked.
- **Deps:** `kv` (its `Storage` seam is passed straight through, so production
  uses `kv.FsStorage` and tests use `kv.SimStorage`).

Provenance: original work of the zig-libs authors (MIT), greenfield over `kv`
— no third-party source consulted line-level or copied. The
**partition-FIFO dispatch shape** is original design work. Behavioral
references (design only): Faktory and Sidekiq (lease/reserve,
retry-with-backoff, dead-letter). The clock-injection and
exponential-jitter-backoff shapes follow the `resilience` sibling.

## Why an in-memory index over `kv`

`kv` is a point store — `put` / `get` / `delete` by key and **nothing else**
(no scan, private keydir). A queue must *enumerate* ready work, so jobqueue
keeps its own index (a `jobs` map, a `ready` set, a `leased` table, a `dlq`
set) and uses `kv` purely as the durable record of truth, rebuilt on `open`.

**Enumeration without scan — the durable id counter.** Each job is keyed
`j/<id>` from a durable monotonic counter at `m/next_id`. `enqueue` writes the
job record (fsync'd by `kv`) **then** bumps the counter (also fsync'd): a
returned `enqueue` is fully durable, and a crash between the two writes leaves
an orphan record the counter never references. Recovery is a bounded replay —
for `id in 1..next_id`, `kv.get(j/<id>)`: a `null` (acked ⇒ `kv.delete`d) is
skipped, a present record is decoded and re-indexed.

## Two clocks (both injected)

- **wall** (`i64` ns, Unix epoch) drives the *schedule*: `run_at` (absolute),
  `delay_ns` (relative), and the `nack` backoff visibility.
- **monotonic** (`u64` ns) drives *lease expiry*: a leased job is invisible
  until acked or its visibility timeout lapses.

## API

```zig
const jobqueue = @import("jobqueue");
const kv = @import("kv");

var fs = kv.FsStorage.init(io, dir);
var q = try jobqueue.Queue.open(gpa, fs.storage(), "jobs.kv", .{});
defer q.close();

const id = try q.enqueue("send_email", payload, .{
    .partition = "tenant-42",   // FIFO within a partition
    .priority = .high,          // .low/.normal/.high/.critical; ties are FIFO
    .delay_ns = 0,              // or .run_at = absolute wall ns
    .max_attempts = 5,
});

// A worker loop:
if (try q.dequeue(.{ .visibility_timeout_ns = 30 * std.time.ns_per_s })) |lease| {
    if (doWork(lease.payload)) try q.ack(lease)     // durable delete, never returns
    else try q.nack(lease, .{});                    // requeue w/ exp backoff, or DLQ
}

// Reclaim leases from crashed workers — caller-driven, no background thread
// (like kv's caller-driven compact):
_ = try q.reapExpiredLeases();

// Inspect the dead-letter queue:
const dead = try q.deadLetterList(gpa);
defer jobqueue.Queue.freeDeadLetterList(gpa, dead);
```

`Options` carries the injectable `wall_clock` / `mono_clock`, the `max_payload`
cap (default 1 MiB — reference large blobs out of band, e.g. via `blobstore`),
and the exponential-backoff policy (`backoff_base_ns` / `factor` / `max`, with
optional full jitter from an injected `random`).

## Delivery semantics (honesty note)

**At-least-once.** A lease is an *in-memory, single-process* reservation
(`kv` has no cross-process lock); a crash re-exposes every un-acked job as
ready on the next `open`. A stale lease (its timeout lapsed and the job was
reaped/re-leased) cannot `ack`/`nack` — it gets `error.StaleLease`. Make your
consumer **idempotent**.

## Deferred (v1 non-goals)

- **Durable / cross-process leases** — v1 leases live in memory (single-process
  worker model); no cross-process lock exists in `kv`.
- **Exactly-once** — this is at-least-once; the idempotent consumer is the
  app's job.
- **Rate-limited dispatch** — compose the `ratelimit` module later.
- **Cron-expression schedules** — v1 has only `delay_ns` + `run_at`; no
  `* * * * *` parsing.
- **A background maintenance thread & compaction-trigger policy** — the
  visibility sweep (`reapExpiredLeases`) is caller-driven; `kv.compact` is the
  caller's to schedule.
- **A per-partition priority heap** — v1 `dequeue` is a linear scan of the
  in-memory ready set (correct, and simplest given the `run_at` visibility
  gate); a heap is the noted optimization.
