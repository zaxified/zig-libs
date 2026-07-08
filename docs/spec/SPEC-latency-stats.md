# SPEC — `latency-stats`

**Purpose** — Online round-trip-time statistics for probe/ping engines. Feed one RTT sample per reply
(and one "loss" per unanswered probe); it keeps running min / max / mean / population stddev, RFC 3550
interarrival jitter, and packet-loss %, all O(1) per sample with zero allocation and no syscalls. An
opt-in HdrHistogram-style `Histogram` adds percentiles (p50/p90/p95/p99/p99.9/…). It is the shared
stats backend for the `icmp`, `traceroute` and `probe` engines.

**Model after / Seed** — the streaming moment stats (min/max/mean/stddev + RFC 3550 §6.4.1 jitter) are
extracted from the authors' axp probe-path latency accounting (Apache-2.0, relicensed MIT by the
copyright holder), modelling fping / iputils-ping summary output; variance uses Welford's online
algorithm (Knuth TAOCP vol 2 §4.2.2). The `Histogram` is clean-room from Gil Tene's HdrHistogram
design (logarithmic bucketing with linear sub-buckets, bounded relative error) — design refs only
(HdrHistogram_c / Java / Rust), no source consulted or copied. See `NOTICE`.

**Design & invariants**
- **Two types, split on purpose:** the `Accumulator` path is **zero-allocation** and syscall-free;
  the `Histogram` is a separate opt-in type (counts array fixed at `init`) so percentiles never
  compromise the allocation-free moment path. Feed both the same samples.
- **Numerically stable:** mean + variance via Welford (no sum-of-squares overflow); `stddev_ns` is the
  *population* stddev (divide-by-n), matching what fping / iputils ping print; `jitter_ns` follows the
  RFC 3550 recurrence `J += (|D| - J)/16` over successive RTT differences (RTT as the single-clock
  transit proxy, as mtr/iputils do). Loss (`addLoss`) counts toward `sent`/loss% without disturbing
  timing state.
- **Histogram guarantees:** any value in `[lowest, highest]` is resolved with bounded relative error
  `1 / 2^significant_bits` (≈ one part in 10^sigfigs); `record`/`recordCount` are O(1), never fail and
  never drop a sample (out-of-range values clamp, saturating). `valueAtPercentile` returns the
  *highest-equivalent* bucket value, so it never under-reports; `add` merges two same-config histograms.
- **Platform:** any (pure arithmetic; no I/O, no clock). **Concurrency:** single_owner — one
  `Accumulator`/`Histogram` per probe stream; not thread-safe. `compute()` folds a slice of `?u64`
  (null = loss) as a one-shot equivalent of the streaming path.

**Threat model / out of scope** — Not security-sensitive. It performs no timing measurement itself
(the caller supplies the clock and the RTT samples) and holds no secrets. What it explicitly does not
do: no thread safety (wrap it if shared), no allocation in the `Accumulator` path (the `Histogram` is
the only allocator, once at `init`), no exact percentiles (bounded-error by design), and no exponential
histograms / summary-serialization / windowing / decay.

**Verification** — Unit tests with hand-computed known-answer sets: empty/single-sample snapshots, the
`{10,12,14,16}` mean + population-stddev vector, loss accounting + `lossPct`, the RFC 3550 jitter
recurrence, and `compute` ≡ streaming. Histogram: empty/invalid-config, single-value exactness,
uniform collapse, an exact 1..1000 ramp (percentiles + mean + population-variance verbatim), an 8192
LCG distribution cross-checked against a sorted oracle at sigfigs 1–4 within the guaranteed relative
error, representation-error sweep, `recordCount` ≡ repeated `record`, clamp policy, `add` merge, reset,
and the documented Accumulator+Histogram wiring pattern.

**Status** — `extract · any · util · single_owner` · deps: none (std only).
