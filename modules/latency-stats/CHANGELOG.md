# latency-stats — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: no findings. Verified against RFC 3550 §6.4.1.
- **2026-07-07** — New `Histogram`: a high-dynamic-range histogram (HdrHistogram design,
  clean-room) for bounded-error percentiles — logarithmic bucketing with linear
  sub-buckets at a configurable significant-figures setting, a fixed counts array sized at
  `init`, allocation-free `record`. Gives p50/p90/p95/p99/p99.9/max with a guaranteed
  relative error; `valueAtPercentile` returns the bucket's highest-equivalent value, so it
  never under-reports, and `add` merges compatible histograms. The `Accumulator` API is
  unchanged.
- **2026-07-06** — New module: online RTT stats — streaming min/max/mean/population-stddev
  (Welford), RFC 3550 jitter and packet-loss %, O(1) per sample, zero allocation and no
  syscalls, plus a one-shot `compute()` over a slice of optional RTTs. Percentiles were not
  part of this — see the entry above.
