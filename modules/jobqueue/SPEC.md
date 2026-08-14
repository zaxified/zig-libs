# jobqueue — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants

- **Durable background-job queue over `kv`:** `enqueue` → `dequeue` (lease) → `ack`/`nack`, with
  retry+backoff, a dead-letter queue, per-partition FIFO ordering under a priority override, and
  scheduled visibility (`delay_ns`/`run_at`). Greenfield over `kv`; the partition-FIFO dispatch
  shape is original design work; Faktory/Sidekiq (lease/reserve, retry-with-backoff, dead-letter)
  and the `resilience`/`jwt` sibling clock-injection pattern are behavioral/design references only.
- **In-memory index over a point store.** `kv` is `put`/`get`/`delete` by key only (no scan); a
  queue must *enumerate* ready work, so jobqueue keeps its own index (`jobs`, the ready pair
  `pending`/`parts`, `leased`, `dlq`) and uses `kv` purely as the durable record of truth,
  rebuilt on `open`.
- **Dispatch = two ordered structures, not one heap.** A ready job is not necessarily *visible*:
  a `delay_ns`/`run_at` job, or one serving a `nack` backoff, is ready but scheduled. A single
  heap keyed by (priority, id) cannot express that — its top may be the invisible job, and
  popping past it to find a visible one destroys the ordering. So the ready set is split:
  `pending`, one min-heap on (`run_at_ns`, id) holding every job whose schedule has not been
  observed to arrive, and `parts`, one max-heap per partition on (priority desc, id asc) holding
  the jobs visible now. `dequeue` drains the due prefix of `pending` into the partition heaps,
  then takes the best partition-heap top — O(1) partition lookup under a `.partition` filter,
  O(partitions) without, plus O(log n) for the pop. Every job (fresh, recovered or requeued)
  enters through `pending`, so exactly one structure needs capacity reserved before the durable
  write. Visibility is still decided per `dequeue` call, never cached: the wall clock may step
  backwards, and a job that migrated but is no longer due is demoted back to `pending`.
- **Ordering: strict priority, ties FIFO by id — deliberately starvable.** A partition is a FIFO
  grouping key and a dispatch filter, not a fair-share class; an unfiltered `dequeue` returns the
  globally best job, so unbounded high-priority work starves low-priority work. That is what a
  priority override means, and it is not a regression (v1's linear scan chose identically). The
  mitigation available to callers is a per-partition worker (`dequeue(.{ .partition = … })`),
  which is fully isolated from other partitions' load.
- **Durable monotonic id counter, no scan needed for enumeration.** Each job is keyed `j/<id>` from
  a durable counter at `m/next_id`. `enqueue` writes the job record (fsync'd by `kv`) **then** bumps
  the counter (also fsync'd): a returned `enqueue` is fully durable, and a crash between the two
  writes leaves an orphan record the counter never references (safe, not double-counted).
  Recovery is a bounded replay — for `id in 1..next_id`, `kv.get(j/<id>)`: null (acked ⇒
  `kv.delete`d) is skipped, present is decoded and re-indexed.
- **Two injected clocks:** wall (`i64` ns, Unix epoch) drives the schedule (`run_at`, `delay_ns`,
  `nack` backoff visibility); monotonic (`u64` ns) drives lease expiry (a leased job is invisible
  until acked or its visibility timeout lapses). Both injectable for deterministic tests.
  `kv`'s `Storage` seam passes straight through (production: `kv.FsStorage`; tests: `kv.SimStorage`).
- **Concurrency:** single_owner — one owner drives the queue and the caller-driven maintenance
  sweep (`reapExpiredLeases`, like `kv`'s caller-driven `compact`); the in-memory index is not
  internally locked.

## Threat model / out of scope

Not a security boundary — durability/correctness, not adversarial hardening:
- **At-least-once delivery, explicitly not exactly-once.** A lease is an in-memory, single-process
  reservation (`kv` has no cross-process lock); a crash re-exposes every un-acked job as ready on
  the next `open`. A stale lease (timeout lapsed, job reaped/re-leased) cannot `ack`/`nack` — it
  gets `error.StaleLease`. The consumer must be idempotent; this module does not enforce that.
- **`max_payload` cap** (default 1 MiB) bounds per-job memory; large blobs should be referenced out
  of band (e.g. via `blobstore`), not inlined.
- **Out of scope:** cross-process/durable leases (v1 is single-process, in-memory), rate-limited
  dispatch (compose `ratelimit` separately), cron-expression schedules (only `delay_ns`/`run_at`).

## Verification

Tests run over the `kv.SimStorage` fault-injecting fake covering enqueue/dequeue/ack/nack lifecycle,
lease expiry + `reapExpiredLeases`, retry backoff + DLQ transition, partition-FIFO ordering under
priority, `run_at`/`delay_ns` visibility gating, `StaleLease` rejection, and crash-recovery replay
of the durable id-counter/orphan-record invariant. The dispatch order is pinned specifically by:
priority within one partition; cross-partition independence (an all-`critical` partition must not
reorder another partition's FIFO); a `critical` job that is *not* returned before its schedule even
though it outranks everything visible; that same job winning once it is due; deterministic FIFO
among equal priorities across partitions; and a wall-clock step backwards re-hiding an
already-eligible job. The `run_at` boundary is pinned **from both sides at nanosecond
granularity** — invisible at `run_at - 1`, dispatched at exactly `run_at`, and re-hidden by a
clock step back of a single nanosecond — because both the migration gate and the pop-time
re-check compare at ns granularity, and a millisecond-scale test cannot tell an off-by-one
there. Run: `zig build test-jobqueue`.

## Backlog / deferred

- **Durable/cross-process leases** — v1 leases live in memory (single-process worker model); no
  cross-process lock exists in `kv`.
- **Exactly-once** — this is at-least-once; the idempotent consumer is the app's job.
- **Rate-limited dispatch** — compose the `ratelimit` module later.
- **Cron-expression schedules** — v1 has only `delay_ns`/`run_at`; no `* * * * *` parsing.
- **A background maintenance thread & compaction-trigger policy** — the visibility sweep
  (`reapExpiredLeases`) is caller-driven; `kv.compact` is the caller's to schedule.
- **Fair-share / weighted dispatch across partitions** — dispatch is strict priority; there is no
  round-robin or weighting over partitions. Pin a worker to a partition if you need isolation.
- An early id-arithmetic priority hack (from an earlier design iteration) silently clobbered
  records — jobqueue's real `priority` field replaces it (already fixed, not an open gap).

## Status

`gap · posix · both · single_owner` + deps: `kv` — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** internal partition-FIFO dispatch queue; original design, no wire format
