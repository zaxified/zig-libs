# latency-stats — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Two types, split on purpose:** the `Accumulator` path is zero-allocation and syscall-free; the
  `Histogram` is a separate opt-in type (counts array fixed at `init`) so percentiles never
  compromise the allocation-free moment path. Feed both the same samples. Moment stats extracted
  from the authors' axp probe-path latency accounting; `Histogram` is clean-room from Gil Tene's
  HdrHistogram design (logarithmic bucketing with linear sub-buckets) — see NOTICE.
- **Numerically stable:** mean + variance via Welford's online algorithm (no sum-of-squares
  overflow); `stddev_ns` is the *population* stddev (divide-by-n), matching fping/iputils-ping
  output; `jitter_ns` follows the RFC 3550 §6.4.1 recurrence `J += (|D| - J)/16` over successive RTT
  differences. `addLoss` counts toward `sent`/loss% without disturbing timing state.
- **Histogram guarantees:** any value in `[lowest, highest]` is resolved with bounded relative
  error `1 / 2^significant_bits`; `record`/`recordCount` are O(1), never fail and never drop a
  sample (out-of-range values clamp, saturating). `valueAtPercentile` returns the
  *highest-equivalent* bucket value (never under-reports); `add` merges two same-config histograms.
- **Platform:** any (pure arithmetic; no I/O, no clock). **Concurrency:** single_owner — one
  `Accumulator`/`Histogram` per probe stream; not thread-safe. `compute()` folds a slice of `?u64`
  (null = loss) as a one-shot equivalent of the streaming path.

## Threat model / out of scope

Not security-sensitive. It performs no timing measurement itself (the caller supplies the clock and
the RTT samples) and holds no secrets. What it explicitly does not do: no thread safety (wrap it if
shared), no allocation in the `Accumulator` path (the `Histogram` is the only allocator, once at
`init`), no exact percentiles (bounded-error by design), and no exponential histograms /
summary-serialization / windowing / decay.

## Verification

Hand-computed known-answer sets: empty/single-sample snapshots, the `{10,12,14,16}` mean +
population-stddev vector, loss accounting + `lossPct`, the RFC 3550 jitter recurrence, and
`compute` ≡ streaming. Histogram: empty/invalid-config, single-value exactness, uniform collapse,
an exact 1..1000 ramp (percentiles + mean + population-variance verbatim), an 8192 LCG distribution
cross-checked against a sorted oracle at sigfigs 1–4 within the guaranteed relative error,
representation-error sweep, `recordCount` ≡ repeated `record`, clamp policy, `add` merge, reset.
Run: `zig build test-latency-stats`.

## Backlog / deferred

- **NOTICE citation nit** (PLAN.md pre-public checklist): the latency-stats/dns citation
  consistency issue is folded into the pending repo-wide security/similarity review pass, not yet
  resolved standalone.
- No functional/API backlog recorded (module README has no Deferred section).

## Status

`extract · any · util · single_owner` + deps: none (std only) — canonical source is `pub const
meta` in src/root.zig.
