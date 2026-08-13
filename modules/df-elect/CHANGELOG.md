# df-elect — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-15** — New module: Partition-correct Designated-Forwarder election (static
  link-state total order, forced by a duplicate-freedom argument — RFC 7432 §8.5 analog)
  + split-horizon; bounded-badness model-checked in netsim.
