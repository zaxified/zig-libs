# jobqueue

Durable **background-job queue** over the pure-Zig [`kv`](../kv) log:
`enqueue` → `dequeue` (lease) → `ack` / `nack`, with retry+backoff, a
dead-letter queue, per-partition FIFO ordering under a priority override, and
scheduled visibility (`delay_ns` / `run_at`).

- No production pure-Zig background-job queue exists.
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
references (design only): Faktory (AGPL or commercial) and Sidekiq
(LGPL-3.0 or commercial) — lease/reserve, retry-with-backoff, dead-letter.
Both are dual-licensed, so the open-source term is the one named; either way
a design reference carries no condition. The clock-injection and
exponential-jitter-backoff shapes follow the `resilience` sibling.

## Why an in-memory index over `kv`

`kv` is a point store — `put` / `get` / `delete` by key and **nothing else**
(no scan, private keydir). A queue must *enumerate* ready work, so jobqueue
keeps its own index (a `jobs` map, the ready pair described below, a `leased`
table, a `dlq` set) and uses `kv` purely as the durable record of truth,
rebuilt on `open`.

**Enumeration without scan — the durable id counter.** Each job is keyed
`j/<id>` from a durable monotonic counter at `m/next_id`. `enqueue` writes the
job record (fsync'd by `kv`) **then** bumps the counter (also fsync'd): a
returned `enqueue` is fully durable, and a crash between the two writes leaves
an orphan record the counter never references. Recovery is a bounded replay —
for `id in 1..next_id`, `kv.get(j/<id>)`: a `null` (acked ⇒ `kv.delete`d) is
skipped, a present record is decoded and re-indexed.

## Dispatch: a schedule heap feeding per-partition priority heaps

A ready job is not necessarily *visible*: a `delay_ns` / `run_at` job, or one
serving a `nack` backoff, is in the ready set but scheduled for later. A single
heap keyed by `(priority, id)` cannot express that — its top may be exactly
that invisible job, and popping past it to find a visible one destroys the
ordering. So the ready set is two structures:

- **`pending`** — one min-heap on `(run_at_ns, id)`: every ready job whose
  schedule has not been observed to arrive. Every job enters here, fresh,
  recovered or requeued after a `nack`.
- **`parts[partition]`** — one max-heap per partition on
  `(priority desc, id asc)`: the jobs visible *now*.

`dequeue` drains the due prefix of `pending` into the partition heaps, then
takes the best partition-heap top. With `.partition` set that is an O(1)
lookup; without, it is O(partitions) — either way plus O(log n) for the pop,
where the previous version scanned the whole ready set. Visibility is still
decided on every call rather than cached, so a wall clock that steps backwards
(NTP) simply demotes the affected job back to `pending`. A partition heap is
dropped once it empties, so churning through unbounded distinct partitions does
not accumulate them.

**Ordering is strict priority, ties FIFO by enqueue id — including across
partitions**, so an unfiltered `dequeue` returns the globally best job and a
steady stream of `.critical` work **will** starve `.low` work indefinitely.
That is deliberate: it is what a priority override means. If you need
isolation, pin a worker to a partition — `dequeue(.{ .partition = … })` is
unaffected by any other partition's priorities or load.

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
- **Fair-share / weighted dispatch across partitions** — dispatch is strict
  priority; there is no round-robin or weighting over partitions (see above).
