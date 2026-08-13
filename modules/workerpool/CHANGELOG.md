# workerpool — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  `std.Thread.Pool` / crossbeam worker pool (design ref), over `lockfree` (design
  reference, not a test anchor).
- **2026-07-22** — New module: in-process fixed-width worker pool over
  `lockfree.MpmcQueue`.
