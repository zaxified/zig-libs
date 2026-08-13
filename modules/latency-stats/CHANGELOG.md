# latency-stats — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: no findings. Verified against RFC 3550 §6.4.1.
- **2026-07-06** — New module: Online RTT stats — min/max/mean/stddev + RFC 3550 jitter
  + loss % (O(1)/sample, no alloc) + an HdrHistogram for bounded-error percentiles
  (p50–p99.9).
