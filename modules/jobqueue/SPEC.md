# jobqueue — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Durable background-job queue over `kv`:** `enqueue` → `dequeue` (lease) → `ack`/`nack`, with
  retry+backoff, a dead-letter queue, per-partition FIFO ordering under a priority override, and
  scheduled visibility (`delay_ns`/`run_at`). Greenfield over `kv`; the partition-FIFO dispatch
  shape folds axp's ex-`taskqueue` `nextPendingTask`/`nextFor` semantics (behavior only); Faktory/
  Sidekiq (lease/reserve, retry-with-backoff, dead-letter) and the `resilience`/`jwt` sibling
  clock-injection pattern are behavioral/design references only — see NOTICE.
- **In-memory index over a point store.** `kv` is `put`/`get`/`delete` by key only (no scan); a
  queue must *enumerate* ready work, so jobqueue keeps its own index (`jobs`, `ready`, `leased`,
  `dlq`) and uses `kv` purely as the durable record of truth, rebuilt on `open`.
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

12 tests over the `kv.SimStorage` fault-injecting fake covering enqueue/dequeue/ack/nack lifecycle,
lease expiry + `reapExpiredLeases`, retry backoff + DLQ transition, partition-FIFO ordering under
priority, `run_at`/`delay_ns` visibility gating, `StaleLease` rejection, and crash-recovery replay
of the durable id-counter/orphan-record invariant. Run: `zig build test-jobqueue`.

## Backlog / deferred

- **Durable/cross-process leases** — v1 leases live in memory (single-process worker model); no
  cross-process lock exists in `kv`.
- **Exactly-once** — this is at-least-once; the idempotent consumer is the app's job.
- **Rate-limited dispatch** — compose the `ratelimit` module later.
- **Cron-expression schedules** — v1 has only `delay_ns`/`run_at`; no `* * * * *` parsing.
- **A background maintenance thread & compaction-trigger policy** — the visibility sweep
  (`reapExpiredLeases`) is caller-driven; `kv.compact` is the caller's to schedule.
- **A per-partition priority heap** — v1 `dequeue` is a linear scan of the in-memory ready set
  (correct, simplest given the `run_at` visibility gate); a heap is the noted optimization.
- Ex-`taskqueue` fold: PLAN.md notes the seed's id-arithmetic priority hack silently clobbered
  records — jobqueue's real `priority` field replaces it (already fixed, not an open gap).

## Status

`gap · posix · both · single_owner` + deps: `kv` — canonical source is `pub const meta` in
src/root.zig.
