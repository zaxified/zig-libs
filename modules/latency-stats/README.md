# latency-stats

Online round-trip-time statistics for probe/ping engines — running
min / max / mean / population-stddev / **RFC 3550 jitter** / packet-loss %,
O(1) per sample, zero allocation, no syscalls.

> **Before you adopt this — two numbers will not match a naive implementation, on purpose:**
> - `jitter_ns` is **RFC 3550 §6.4.1's smoothed interarrival jitter**, `J += (|D| - J)/16` applied
>   to successive RTT differences — not a mean absolute delta. If you are replacing a
>   mean-absolute-delta jitter calculation, the published numbers **will move**. That is this
>   module computing a different, spec-defined quantity, not a bug in either implementation.
> - `mean_ns` is an **f64 Welford running mean**, computed incrementally in floating point. It
>   differs from an exact integer divide (`sum / n` truncated to an integer) by up to one
>   nanosecond, in the direction of keeping the fractional part a truncating integer divide throws
>   away.

- Probe-path latency accounting, generalized as a
  standalone module.
- **Model after:** fping / iputils-ping summary stats + RFC 3550 §6.4.1
  interarrival jitter + Welford's online mean/variance.
- **Platform:** any (pure arithmetic). **Role:** util.
  **Concurrency:** single-owner (one `Accumulator` per probe stream).
  **Allocation:** none.

Provenance: original work of the zig-libs authors (MIT) — the streaming moment
stats (min/max/mean/stddev + RFC 3550 jitter), variance per Welford (Knuth
TAOCP vol 2 §4.2.2), their merge per Chan et al.'s parallel update. The
`Histogram` percentile support is clean-room from Gil Tene's HdrHistogram
design (logarithmic bucketing with linear sub-buckets, bounded relative
error); design references HdrHistogram_c (BSD-2-Clause/CC0), HdrHistogram Java
(CC0-1.0/BSD-2) and the Rust `hdrhistogram` crate (MIT OR Apache-2.0). Source
read, 2026-11-02, permissive licences, nothing copied: HdrHistogram_c
`hdr_histogram_log.c` (the V2 byte layout of `wire.zig`) and the Rust crate's
`add` (the merge-into-empty copy). `tools/` carries the bench harnesses: its
`go_bench/go.mod`, `go.sum` and `rust_bench/Cargo.lock` were generated on
2026-11-02 by `go mod tidy` / `cargo generate-lockfile` against
`hdrhistogram-go` v1.4.0 and `hdrhistogram` 7.6.0 (no data files are committed).

## API

```zig
const ls = @import("latency-stats");

var acc = ls.Accumulator.init();
acc.addSample(rtt_ns);   // a reply arrived
acc.addLoss();           // a probe went unanswered

const s = acc.snapshot(); // Stats: sent/received/min/max/mean/stddev/jitter (ns)
_ = s.lossPct();          // f64 in [0,100]

// one-shot over a slice (null = lost probe)
const s2 = ls.compute(&[_]?u64{ 10, null, 14, 16 });
```

`stddev_ns` is the population stddev (divide-by-n), matching fping / ping
summary output; `jitter_ns` follows the RFC 3550 recurrence `J += (|D|-J)/16`
over successive RTT differences.

Percentiles are the separate, allocating `Histogram` type (counts array sized once
at `init`): `Histogram.init(gpa, .{ .highest = ..., .sigfigs = 3 })`, then
`record` / `recordCount` / `valueAtPercentile` / `percentileSnapshot` / `add` (merge).

Beyond that (2026-11-02):

```zig
h.recordCorrected(rtt_ns, expected_interval_ns); // coordinated-omission correction
var it = h.percentiles(5);                       // also recorded() / linear(step) / logarithmic(first, base)
while (it.next()) |t| print("{d} {d}\n", .{ t.percentile, t.value });

var total = ls.Accumulator.init();
total.merge(per_target_acc);                     // exact mean/stddev, jitter blended

// HdrHistogram V2 interchange (C, Go, Java read it):
try ls.wire.encodeCompressed(&h, gpa, writer);
var back = try ls.wire.decode(gpa, bytes, .{ .max_counts = 1 << 20 }); // hostile-input safe
```

`Histogram.countsLen(opts)` says what a configuration costs (8 bytes a slot) before `init` allocates it.
