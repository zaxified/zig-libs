# jobqueue — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — **mvp → core.** `cancel(id)` (ready, scheduled or dead job:
  durable delete; a leased one is `error.JobLeased`, in the new `CancelError`),
  `requeueDead(id, .{ .run_at, .reset_attempts })`, `extendLease(lease, timeout)`
  (heartbeat), unique jobs (`EnqueueOptions.unique_key` → `error.DuplicateJob`
  in the new `UniqueError`, `findUnique`), `status(id)` (`Status`). A job with a
  unique key is stored as a version-2 record; every other job is still version 1,
  so a store that uses no unique keys stays readable by older builds. Seeded
  corrupt-record sweep over `decodeJob` and a model sweep over every operation
  with crashes; mutation 23 mutants, 0 surviving. **Fixed:** `open` freed a job
  twice when an allocation failed after the job had been indexed during recovery;
  every slot is now reserved first. **Behaviour change:** `decodeJob` refuses a
  record with `max_attempts` 0, `attempts > max_attempts`, or a ready job at its
  limit (none of which this module writes; the first would underflow in
  `requeueDead`). `Error` is unchanged.
- **2026-08-14** — Provenance record completed: Faktory and Sidekiq were already
  named as behavioural design references, without their licences, which
  `/NOTICE` §0 requires the record to carry. Both are dual-licensed (Faktory
  AGPL or commercial, Sidekiq LGPL-3.0 or commercial); the open-source term is
  the one recorded. Nothing is owed either way — a design reference imposes no
  condition. Documentation only.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Faktory / Sidekiq
  (design reference, not a test anchor).
- **2026-07-09** — New module: Durable background-job queue over `kv` — lease/retry/DLQ,
  per-partition FIFO under priority, scheduled visibility.
