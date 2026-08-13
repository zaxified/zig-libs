# jobqueue — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
