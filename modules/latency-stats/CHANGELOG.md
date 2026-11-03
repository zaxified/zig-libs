# latency-stats — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-02** — **Fixes (independent review):** `recordCorrectedCount` took the run's first value as the minimum, wrong when `lowest` is not a power of two (the lowest slot reaches below it) or the total ran out mid-run; now the last value actually recorded, clamped. A saturated `add` raised `max()` (and lowered `min()`) for slots it dropped; now only taken slots count. `valueAtPercentile(100)` is the last sample for totals past 2^53 (the f64 rank lost it). `wire.decode` refuses a compressed stream whose declared payload exceeds deflate's 1032:1 bound before allocating it; encode of a compressed stream over i32 is `OutputTooLarge`. Docs: `min`/`max` after `decode` are slot bounds. Tests: parity widened, fuzz harnesses for `recordCorrectedCount` and `add`, and 32-bit portability fixed in a test (`1 << 40` as usize).

- **2026-11-02** — **Performance + tools:** `tools/bench.zig` (HdrHistogram_c 0.11.10, Rust `hdrhistogram` 7.6.0, Go `hdrhistogram-go` v1.4.0; wire interop gate against C and Go). `recordCorrectedCount` records per slot with the minimum worked out once per run (was 2.7x the C time, now 1.06x); `valueAtPercentile` skips 8-slot blocks with a vector add (1.2x -> 0.67x of C); `add` merges into an empty histogram by copying and otherwise with a plain vector add when no slot can saturate; `countsIndexOf` shifts instead of multiplying. No behaviour change.

- **2026-11-02** — **Additive (grade 2 wave):** coordinated-omission correction `Histogram.recordCorrected` / `recordCorrectedCount` (one step per counts slot, so a tiny interval with a huge value cannot stall); distribution iterators `recorded`, `linear`, `logarithmic`, `percentiles` (`iter.zig`); `Accumulator.merge` (exact Welford/Chan combine, jitter blended); HdrHistogram V2 interchange `wire.encode` / `encodeCompressed` / `decode` (plain and zlib-compressed, hostile-input bounded by `DecodeOptions.max_counts`); `Histogram.countsLen`, `rankAtPercentile`, `slotLowest`, `slotHighest`. New sweep tests and a `decode` fuzz harness (`LATENCY_STATS_FUZZ`).

- **2026-10-31** — **BEHAVIOURAL, not breaking:** no-panic sweep + blind review (§ GX). `Histogram` counts and the total saturate at maxInt(u64) instead of overflowing (the doc no longer says it never drops a sample); `valueAtPercentile` stays in range for totals near 2^64 and treats a NaN percentile as 0; `add()` folds the other histogram's min/max only when it merged at least one count.

- **2026-10-04** — **Tests:** mutation run (21 schemata mutants, 19 killed, 2 equivalent; one
  new test: `recordCount(v, 0)` moves neither the count nor `max()`). No code change.

- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/root.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../../../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-08-18** — Documentation only, no behavior change: moved the RFC 3550 smoothed-jitter
  formula (`J += (|D| - J)/16`) and the "`mean_ns` is an f64 Welford running mean, not a
  truncating integer divide" caveat from a SPEC.md/API-section detail to a callout at the top
  of README.md, next to the module's one-line purpose. A consumer evaluating whether to adopt
  this module — in particular one replacing a mean-absolute-delta jitter implementation — was
  meeting these facts only after already reading past the API example; that consumer declined
  to adopt the module for exactly the numbers-move reason this callout now states up front.
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
