# filestore — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — `readExpiry` no longer reaches for `std.heap.page_allocator`: the
  `.expiry` sidecar read (capped at 32 bytes) now goes into a fixed stack buffer via a
  direct positional read, so the module never touches a hidden global allocator
  (CONVENTIONS.md §1.2).
- **2026-07-18** — Security audit: no findings.
- **2026-07-09** — New module: DB-less durable keyed document store — one
  atomically-written file per record + a typed-JSON convenience layer.
