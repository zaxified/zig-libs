# lockfree — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on crossbeam-epoch (Rust),
  Fraser epoch reclamation (2004), Michael&Scott PODC'96 (design reference, not a test
  anchor).
- **2026-07-17** — New module: Lock-free concurrency primitives for shared-memory worker
  pools (Michael & Scott MPMC queue, PODC 1996 + Fraser/crossbeam epoch reclamation).
