# latency-stats

Online round-trip-time statistics for probe/ping engines — running
min / max / mean / population-stddev / **RFC 3550 jitter** / packet-loss %,
O(1) per sample, zero allocation, no syscalls.

- Probe-path latency accounting, generalized as a
  standalone module.
- **Model after:** fping / iputils-ping summary stats + RFC 3550 §6.4.1
  interarrival jitter + Welford's online mean/variance.
- **Platform:** any (pure arithmetic). **Role:** util.
  **Concurrency:** single-owner (one `Accumulator` per probe stream).
  **Allocation:** none.

Provenance: original work of the zig-libs authors (MIT) — the streaming moment
stats (min/max/mean/stddev + RFC 3550 jitter), variance per Welford (Knuth
TAOCP vol 2 §4.2.2). The `Histogram` percentile support is clean-room from Gil
Tene's HdrHistogram design (logarithmic bucketing with linear sub-buckets,
bounded relative error); design references HdrHistogram_c (BSD-2-Clause/CC0),
HdrHistogram Java (CC0-1.0/BSD-2) and the Rust `hdrhistogram` crate (MIT OR
Apache-2.0) — behavior/format only, no source consulted or copied.

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
