# loopfree-reconv — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-15** — New module: Loop-free reconvergence transitions — two-class
  ordered-FIB schedule (provably no transient forwarding loop, TTL backstop),
  netsim-verified across fuzzed reconvergence schedules incl. overlapping.
