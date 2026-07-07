// SPDX-License-Identifier: MIT
//! latency-stats — online round-trip-time statistics for probe/ping engines.
//!
//! Feed it one RTT sample per reply (and one "loss" per unanswered probe); it
//! keeps running min / max / mean / population stddev, RFC 3550 interarrival
//! jitter, and packet-loss %, all in O(1) per sample with **zero allocation**
//! and no syscalls. A one-shot `compute()` over a slice is provided too.
//!
//! For percentiles (p50/p90/p95/p99/p99.9/…) there is an opt-in `Histogram` —
//! an HdrHistogram-style high-dynamic-range histogram with bounded memory
//! (counts array fixed at init), O(1) record, and a guaranteed maximum
//! relative error. It is a separate type so the `Accumulator` path stays
//! allocation-free; feed both the same samples (see `Histogram` docs).
//!
//! Design notes:
//!   • mean + variance use Welford's online algorithm (numerically stable, no
//!     sum-of-squares overflow) — see Knuth TAOCP vol 2, §4.2.2.
//!   • `jitter_ns` is the smoothed mean deviation of consecutive transit-time
//!     differences from RFC 3550 §6.4.1: J += (|D| - J) / 16, where D is the
//!     difference of successive RTT samples (we use RTT as the transit proxy,
//!     as mtr/iputils ping do for a single-clock round trip).
//!   • stddev is the *population* stddev (divide by n), matching what fping and
//!     iputils `ping` print in their summary line.
//!
//! Provenance: extracted from the authors' axp project (latency accounting in
//! the probe path; Apache-2.0, relicensed MIT by the copyright holder). Models
//! fping / iputils-ping summary stats + RFC 3550 §6.4.1 jitter + Welford's
//! online variance. `Histogram` implements HdrHistogram percentiles per Gil
//! Tene's HdrHistogram design (logarithmic bucketing with linear sub-buckets,
//! bounded relative error); clean-room from the published design — no
//! HdrHistogram source (C/Java/Rust) consulted or copied. No third-party
//! source copied — see ../../NOTICE.

const std = @import("std");

pub const meta = .{
    .status = .extract,
    .platform = .any, // pure arithmetic; no I/O, no clock
    .role = .util,
    .concurrency = .single_owner, // one Accumulator per probe stream; not shared
    .model_after = "fping/iputils-ping summary stats + RFC 3550 §6.4.1 jitter + Welford online variance + HdrHistogram (Gil Tene's design, clean-room) for percentiles",
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

/// An immutable snapshot of the statistics at a point in time.
/// All times are nanoseconds. When `received == 0`, the timing fields
/// (`min_ns`, `max_ns`, `mean_ns`, `stddev_ns`, `jitter_ns`) are 0.
pub const Stats = struct {
    /// Probes sent (samples + losses).
    sent: u64,
    /// Replies received (samples fed to `addSample`).
    received: u64,
    min_ns: u64,
    max_ns: u64,
    mean_ns: f64,
    /// Population standard deviation (divide-by-n), like iputils ping's `mdev`
    /// sibling — here a true stddev, not mean deviation.
    stddev_ns: f64,
    /// RFC 3550 §6.4.1 smoothed interarrival jitter.
    jitter_ns: f64,

    /// Packet loss as a percentage in [0, 100]. Returns 0 when nothing sent.
    pub fn lossPct(self: Stats) f64 {
        if (self.sent == 0) return 0;
        const sent: f64 = @floatFromInt(self.sent);
        const received: f64 = @floatFromInt(self.received);
        return (sent - received) / sent * 100.0;
    }
};

/// Streaming O(1) accumulator. Default-initialize with `.{}` (or `Accumulator.init`).
pub const Accumulator = struct {
    sent: u64 = 0,
    received: u64 = 0,
    min_ns: u64 = std.math.maxInt(u64),
    max_ns: u64 = 0,

    // Welford online mean/variance over received RTTs.
    mean: f64 = 0,
    m2: f64 = 0,

    // RFC 3550 jitter state.
    jitter: f64 = 0,
    prev_ns: u64 = 0,
    have_prev: bool = false,

    pub fn init() Accumulator {
        return .{};
    }

    /// Record one reply with round-trip time `rtt_ns`. Updates count, min/max,
    /// Welford mean/variance, and RFC 3550 jitter. O(1), no allocation.
    pub fn addSample(self: *Accumulator, rtt_ns: u64) void {
        self.sent += 1;
        self.received += 1;

        if (rtt_ns < self.min_ns) self.min_ns = rtt_ns;
        if (rtt_ns > self.max_ns) self.max_ns = rtt_ns;

        const x: f64 = @floatFromInt(rtt_ns);

        // Welford online mean/variance.
        const n: f64 = @floatFromInt(self.received);
        const delta = x - self.mean;
        self.mean += delta / n;
        self.m2 += delta * (x - self.mean);

        // RFC 3550 §6.4.1 smoothed jitter.
        if (self.have_prev) {
            const prev: f64 = @floatFromInt(self.prev_ns);
            const d = @abs(x - prev);
            self.jitter += (d - self.jitter) / 16.0;
        }
        self.prev_ns = rtt_ns;
        self.have_prev = true;
    }

    /// Record one probe that got no reply (counts toward loss only).
    pub fn addLoss(self: *Accumulator) void {
        self.sent += 1;
    }

    /// Immutable snapshot of the current statistics.
    pub fn snapshot(self: Accumulator) Stats {
        if (self.received == 0) {
            return .{
                .sent = self.sent,
                .received = 0,
                .min_ns = 0,
                .max_ns = 0,
                .mean_ns = 0,
                .stddev_ns = 0,
                .jitter_ns = 0,
            };
        }
        const n: f64 = @floatFromInt(self.received);
        return .{
            .sent = self.sent,
            .received = self.received,
            .min_ns = self.min_ns,
            .max_ns = self.max_ns,
            .mean_ns = self.mean,
            .stddev_ns = @sqrt(self.m2 / n),
            .jitter_ns = self.jitter,
        };
    }

    /// Reset to the initial empty state.
    pub fn reset(self: *Accumulator) void {
        self.* = .{};
    }
};

/// One-shot convenience: fold a slice of optional RTTs (`null` = a lost probe)
/// into a single `Stats`. Equivalent to feeding each entry to an `Accumulator`.
pub fn compute(samples: []const ?u64) Stats {
    var acc = Accumulator.init();
    for (samples) |sample| {
        if (sample) |rtt_ns| acc.addSample(rtt_ns) else acc.addLoss();
    }
    return acc.snapshot();
}

// ── HdrHistogram-style percentile histogram ──────────────────────────────────

/// Configuration for `Histogram.init`.
pub const HistogramOptions = struct {
    /// Lowest discernible value, >= 1. Recorded values below it are clamped
    /// up to it (see `record`). Raise it (e.g. to 1000 for ns values where
    /// only µs matter) to shrink the counts array.
    lowest: u64 = 1,
    /// Highest trackable value; must be >= 2 * `lowest`. Recorded values
    /// above it are clamped down to it.
    highest: u64,
    /// Significant *decimal* figures of precision, 1–5. Determines the number
    /// of linear sub-buckets per logarithmic bucket and thereby the guaranteed
    /// maximum relative error (`maxRelativeError`) and the memory footprint.
    sigfigs: u8 = 3,
};

/// Snapshot of the common latency percentiles (`Histogram.percentileSnapshot`).
/// All values are highest-equivalent bucket values (never under-reported),
/// except `min`, which is the exact smallest recorded (clamped) value.
pub const PercentileSnapshot = struct {
    total_count: u64,
    min: u64,
    p50: u64,
    p90: u64,
    p95: u64,
    p99: u64,
    p999: u64,
    max: u64,
};

/// High-dynamic-range histogram of u64 values (nanoseconds), after Gil Tene's
/// HdrHistogram design: logarithmic buckets, each split into a power-of-two
/// number of linear sub-buckets, so any value in `[lowest, highest]` is
/// resolved with a bounded relative error of `1 / 2^significant_bits`
/// (≈ one part in 10^sigfigs; see `maxRelativeError`). Memory is fixed at
/// `init` — one u64 counter per sub-bucket slot — and `record` is O(1) with
/// no allocation.
///
/// Clamp policy: `record`/`recordCount` never fail and never drop a sample —
/// a value below `lowest` is counted as `lowest`, a value above `highest` is
/// counted as `highest` (saturating). `min()`/`max()` report the clamped
/// values.
///
/// Percentile semantics: `valueAtPercentile` returns the *highest equivalent
/// value* of the bucket containing the requested rank, so it never
/// under-reports the true percentile.
///
/// Pattern — percentiles alongside the zero-alloc `Accumulator` (the
/// histogram is opt-in and does not change the existing path):
///
///     var acc = Accumulator.init();
///     var hist = try Histogram.init(gpa, .{ .highest = 10 * std.time.ns_per_s });
///     defer hist.deinit();
///     // per probe:
///     acc.addSample(rtt_ns); // min/max/mean/stddev/jitter/loss
///     hist.record(rtt_ns); //   p50/p90/p95/p99/p99.9
///     // report:
///     const stats = acc.snapshot();
///     const pct = hist.percentileSnapshot();
///
/// Single-owner, like `Accumulator` — not thread-safe.
pub const Histogram = struct {
    gpa: std.mem.Allocator,
    /// One counter per sub-bucket slot; length fixed at init.
    counts: []u64,
    total_count: u64,
    /// Exact smallest / largest recorded (clamped) values; sentinel when empty.
    min_value: u64,
    max_value: u64,

    // Configuration (kept for `add` compatibility checks).
    lowest: u64,
    highest: u64,
    sigfigs: u8,

    // Derived bucket geometry. Each logarithmic bucket b covers values whose
    // magnitude doubles with b; within a bucket, `sub_bucket_count` linear
    // sub-buckets give the precision. Bucket 0 holds sub-buckets
    // [0, sub_bucket_count); every later bucket only uses the upper half
    // [sub_bucket_half_count, sub_bucket_count) — the lower half would alias
    // the previous bucket — hence `(bucket_count + 1) * sub_bucket_half_count`
    // counter slots in total.
    unit_magnitude: u6, // log2(lowest): values below 2^unit share sub-bucket 0
    sub_bucket_count_magnitude: u6, // log2(sub_bucket_count)
    sub_bucket_count: u64,
    sub_bucket_half_count: usize,
    sub_bucket_mask: u64, // (sub_bucket_count - 1) << unit_magnitude
    bucket_count: usize,

    pub const InitError = error{ InvalidConfig, OutOfMemory };
    pub const MergeError = error{IncompatibleConfig};

    /// Allocate a histogram for `[opts.lowest, opts.highest]` at
    /// `opts.sigfigs` decimal digits of precision. The counts array size is
    /// decided here and never changes. `error.InvalidConfig` when
    /// `lowest < 1`, `sigfigs` outside 1–5, or `highest < 2 * lowest`.
    pub fn init(gpa: std.mem.Allocator, opts: HistogramOptions) InitError!Histogram {
        if (opts.lowest < 1 or opts.sigfigs < 1 or opts.sigfigs > 5)
            return error.InvalidConfig;
        if (opts.highest < opts.lowest *| 2) return error.InvalidConfig;

        // Enough linear sub-buckets that a single sub-bucket step is a
        // relative step of at most 10^-sigfigs anywhere in a bucket: the
        // smallest power of two >= 2 * 10^sigfigs.
        const pow10 = [_]u64{ 10, 100, 1_000, 10_000, 100_000 };
        const largest_single_unit: u64 = 2 * pow10[opts.sigfigs - 1];
        const scm: u6 = @intCast(std.math.log2_int_ceil(u64, largest_single_unit));
        const unit_mag: u6 = @intCast(std.math.log2_int(u64, opts.lowest));
        if (@as(u32, unit_mag) + @as(u32, scm) > 63) return error.InvalidConfig;

        const sub_count = @as(u64, 1) << scm;
        const half: usize = @intCast(sub_count / 2);
        const mask = (sub_count - 1) << unit_mag;

        // Smallest number of doubling buckets whose top covers `highest`.
        var bucket_count: usize = 1;
        var max_cov: u64 = (sub_count << unit_mag) - 1;
        while (max_cov < opts.highest) {
            bucket_count += 1;
            max_cov = if (max_cov > std.math.maxInt(u64) / 2)
                std.math.maxInt(u64)
            else
                max_cov * 2 + 1;
        }

        const counts = try gpa.alloc(u64, (bucket_count + 1) * half);
        @memset(counts, 0);

        return .{
            .gpa = gpa,
            .counts = counts,
            .total_count = 0,
            .min_value = std.math.maxInt(u64),
            .max_value = 0,
            .lowest = opts.lowest,
            .highest = opts.highest,
            .sigfigs = opts.sigfigs,
            .unit_magnitude = unit_mag,
            .sub_bucket_count_magnitude = scm,
            .sub_bucket_count = sub_count,
            .sub_bucket_half_count = half,
            .sub_bucket_mask = mask,
            .bucket_count = bucket_count,
        };
    }

    pub fn deinit(self: *Histogram) void {
        self.gpa.free(self.counts);
        self.* = undefined;
    }

    /// Record one value. O(1), no allocation, never fails: out-of-range
    /// values are clamped to `[lowest, highest]` (see the clamp policy above).
    pub fn record(self: *Histogram, value: u64) void {
        self.recordCount(value, 1);
    }

    /// Record `n` occurrences of `value` at once (same clamp policy).
    pub fn recordCount(self: *Histogram, value: u64, n: u64) void {
        if (n == 0) return;
        const v = std.math.clamp(value, self.lowest, self.highest);
        self.counts[self.countsIndexOf(v)] += n;
        self.total_count += n;
        if (v < self.min_value) self.min_value = v;
        if (v > self.max_value) self.max_value = v;
    }

    /// Merge `other` into `self`. Equivalent to having recorded every sample
    /// of both into one histogram. `error.IncompatibleConfig` unless both
    /// were created with the same (lowest, highest, sigfigs).
    pub fn add(self: *Histogram, other: *const Histogram) MergeError!void {
        if (self.lowest != other.lowest or
            self.highest != other.highest or
            self.sigfigs != other.sigfigs)
            return error.IncompatibleConfig;
        for (self.counts, other.counts) |*dst, src| dst.* += src;
        self.total_count += other.total_count;
        if (other.total_count != 0) {
            if (other.min_value < self.min_value) self.min_value = other.min_value;
            if (other.max_value > self.max_value) self.max_value = other.max_value;
        }
    }

    /// Empty the histogram; the configuration and counts array are kept.
    pub fn reset(self: *Histogram) void {
        @memset(self.counts, 0);
        self.total_count = 0;
        self.min_value = std.math.maxInt(u64);
        self.max_value = 0;
    }

    // ── queries ──

    pub fn totalCount(self: *const Histogram) u64 {
        return self.total_count;
    }

    /// Exact smallest recorded (clamped) value; 0 when empty.
    pub fn min(self: *const Histogram) u64 {
        return if (self.total_count == 0) 0 else self.min_value;
    }

    /// Exact largest recorded (clamped) value; 0 when empty.
    pub fn max(self: *const Histogram) u64 {
        return self.max_value;
    }

    /// Mean of the recorded distribution, computed from the buckets using
    /// each slot's median-equivalent value (exact where the resolution is one
    /// unit). 0 when empty.
    pub fn mean(self: *const Histogram) f64 {
        if (self.total_count == 0) return 0;
        var sum: f64 = 0;
        for (self.counts, 0..) |c, i| {
            if (c == 0) continue;
            const mid: f64 = @floatFromInt(self.medianEquivalentAtIndex(i));
            sum += mid * @as(f64, @floatFromInt(c));
        }
        return sum / @as(f64, @floatFromInt(self.total_count));
    }

    /// Population standard deviation (divide-by-n, like `Stats.stddev_ns`),
    /// from the bucket median-equivalent values. 0 when empty.
    pub fn stdDev(self: *const Histogram) f64 {
        if (self.total_count == 0) return 0;
        const m = self.mean();
        var geometric_dev_total: f64 = 0;
        for (self.counts, 0..) |c, i| {
            if (c == 0) continue;
            const dev = @as(f64, @floatFromInt(self.medianEquivalentAtIndex(i))) - m;
            geometric_dev_total += dev * dev * @as(f64, @floatFromInt(c));
        }
        return @sqrt(geometric_dev_total / @as(f64, @floatFromInt(self.total_count)));
    }

    /// The value at percentile `p` (0–100, clamped): the highest-equivalent
    /// value of the bucket containing the `max(1, round(p/100 * total))`-th
    /// smallest recorded value (round-half-up rank, immune to float noise
    /// like 99.9/100*1000 -> 999.0000000000001) — never below the true
    /// percentile, and above it by at most `maxRelativeError`. 0 when empty.
    pub fn valueAtPercentile(self: *const Histogram, p: f64) u64 {
        if (self.total_count == 0) return 0;
        const pct = std.math.clamp(p, 0.0, 100.0);
        var target: u64 = @intFromFloat(pct / 100.0 * @as(f64, @floatFromInt(self.total_count)) + 0.5);
        if (target == 0) target = 1;
        if (target > self.total_count) target = self.total_count;

        var cumulative: u64 = 0;
        for (self.counts, 0..) |c, i| {
            cumulative += c;
            if (cumulative >= target) return self.highestEquivalentAtIndex(i);
        }
        unreachable; // target <= total_count, so the loop always hits it
    }

    /// One-call snapshot of the common latency percentiles.
    pub fn percentileSnapshot(self: *const Histogram) PercentileSnapshot {
        return .{
            .total_count = self.total_count,
            .min = self.min(),
            .p50 = self.valueAtPercentile(50),
            .p90 = self.valueAtPercentile(90),
            .p95 = self.valueAtPercentile(95),
            .p99 = self.valueAtPercentile(99),
            .p999 = self.valueAtPercentile(99.9),
            .max = self.max(),
        };
    }

    /// Count recorded at values equivalent to `v` (same bucket slot;
    /// `v` is clamped like `record`).
    pub fn countAtValue(self: *const Histogram, v: u64) u64 {
        const clamped = std.math.clamp(v, self.lowest, self.highest);
        return self.counts[self.countsIndexOf(clamped)];
    }

    /// Total count recorded in `[lo, hi]` (inclusive, by equivalent range;
    /// both bounds clamped). 0 when `lo > hi`.
    pub fn countBetween(self: *const Histogram, lo: u64, hi: u64) u64 {
        if (lo > hi) return 0;
        const first = self.countsIndexOf(std.math.clamp(lo, self.lowest, self.highest));
        const last = self.countsIndexOf(std.math.clamp(hi, self.lowest, self.highest));
        var sum: u64 = 0;
        for (self.counts[first .. last + 1]) |c| sum += c;
        return sum;
    }

    /// The guaranteed maximum relative error of any reported value:
    /// `1 / sub_bucket_half_count` = `1 / 2^significant_bits`
    /// (0.098 % for sigfigs=3).
    pub fn maxRelativeError(self: *const Histogram) f64 {
        return 1.0 / @as(f64, @floatFromInt(self.sub_bucket_half_count));
    }

    /// Smallest value that shares `v`'s bucket slot.
    pub fn lowestEquivalent(self: *const Histogram, v: u64) u64 {
        const b = self.bucketIndexOf(v);
        return self.subBucketIndexOf(v, b) << (self.unit_magnitude + b);
    }

    /// Largest value that shares `v`'s bucket slot (what percentiles report).
    pub fn highestEquivalent(self: *const Histogram, v: u64) u64 {
        const b = self.bucketIndexOf(v);
        const low = self.subBucketIndexOf(v, b) << (self.unit_magnitude + b);
        return low + (self.sizeOfRangeAtBucket(b) - 1);
    }

    // ── bucket geometry (internal) ──

    /// Logarithmic bucket of `v`: 0 while v fits bucket 0's full sub-bucket
    /// span, then +1 per doubling. OR-ing the mask floors the @clz result so
    /// small values land in bucket 0 without a branch.
    fn bucketIndexOf(self: *const Histogram, v: u64) u6 {
        const msb: u32 = 63 - @as(u32, @clz(v | self.sub_bucket_mask));
        const base: u32 = @as(u32, self.unit_magnitude) + @as(u32, self.sub_bucket_count_magnitude) - 1;
        return @intCast(msb - base);
    }

    /// Linear sub-bucket of `v` within bucket `b`: in [0, sub_bucket_count)
    /// for b == 0, in [half, sub_bucket_count) for b > 0.
    fn subBucketIndexOf(self: *const Histogram, v: u64, b: u6) u64 {
        return v >> (self.unit_magnitude + b);
    }

    /// Flat counts index: bucket 0 owns [0, 2*half); each later bucket adds
    /// `half` slots (its lower half aliases the previous bucket).
    fn countsIndexOf(self: *const Histogram, v: u64) usize {
        const b = self.bucketIndexOf(v);
        const sub = self.subBucketIndexOf(v, b);
        return @as(usize, b) * self.sub_bucket_half_count + @as(usize, @intCast(sub));
    }

    /// Width of one sub-bucket slot in bucket `b` (the equivalent range).
    fn sizeOfRangeAtBucket(self: *const Histogram, b: u6) u64 {
        return @as(u64, 1) << (self.unit_magnitude + b);
    }

    /// Inverse of `countsIndexOf`: (bucket, sub-bucket) for a flat index.
    fn bucketSubAtIndex(self: *const Histogram, idx: usize) struct { b: u6, sub: u64 } {
        const half = self.sub_bucket_half_count;
        const b_raw = idx / half;
        if (b_raw < 2) return .{ .b = 0, .sub = @intCast(idx) };
        return .{ .b = @intCast(b_raw - 1), .sub = @intCast(idx % half + half) };
    }

    fn highestEquivalentAtIndex(self: *const Histogram, idx: usize) u64 {
        const bs = self.bucketSubAtIndex(idx);
        const low = bs.sub << (self.unit_magnitude + bs.b);
        return low + (self.sizeOfRangeAtBucket(bs.b) - 1);
    }

    fn medianEquivalentAtIndex(self: *const Histogram, idx: usize) u64 {
        const bs = self.bucketSubAtIndex(idx);
        const low = bs.sub << (self.unit_magnitude + bs.b);
        return low + self.sizeOfRangeAtBucket(bs.b) / 2;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const eps = 1e-6;

test "empty accumulator snapshot is all zero" {
    const a = Accumulator.init();
    const s = a.snapshot();
    try testing.expectEqual(@as(u64, 0), s.sent);
    try testing.expectEqual(@as(u64, 0), s.received);
    try testing.expectEqual(@as(u64, 0), s.min_ns);
    try testing.expectEqual(@as(u64, 0), s.max_ns);
    try testing.expectApproxEqAbs(@as(f64, 0), s.mean_ns, eps);
    try testing.expectApproxEqAbs(@as(f64, 0), s.stddev_ns, eps);
    try testing.expectApproxEqAbs(@as(f64, 0), s.jitter_ns, eps);
    try testing.expectApproxEqAbs(@as(f64, 0), s.lossPct(), eps);
}

test "single sample" {
    var a = Accumulator.init();
    a.addSample(10);
    const s = a.snapshot();
    try testing.expectEqual(@as(u64, 1), s.sent);
    try testing.expectEqual(@as(u64, 1), s.received);
    try testing.expectEqual(@as(u64, 10), s.min_ns);
    try testing.expectEqual(@as(u64, 10), s.max_ns);
    try testing.expectApproxEqAbs(@as(f64, 10), s.mean_ns, eps);
    try testing.expectApproxEqAbs(@as(f64, 0), s.stddev_ns, eps);
    try testing.expectApproxEqAbs(@as(f64, 0), s.jitter_ns, eps);
    try testing.expectApproxEqAbs(@as(f64, 0), s.lossPct(), eps);
}

test "known set {10,12,14,16}: mean and population stddev" {
    var a = Accumulator.init();
    a.addSample(10);
    a.addSample(12);
    a.addSample(14);
    a.addSample(16);
    const s = a.snapshot();
    try testing.expectEqual(@as(u64, 4), s.sent);
    try testing.expectEqual(@as(u64, 4), s.received);
    try testing.expectEqual(@as(u64, 10), s.min_ns);
    try testing.expectEqual(@as(u64, 16), s.max_ns);
    try testing.expectApproxEqAbs(@as(f64, 13), s.mean_ns, eps);
    // population variance = (9 + 1 + 1 + 9) / 4 = 5
    try testing.expectApproxEqAbs(@sqrt(5.0), s.stddev_ns, eps);
}

test "loss accounting and lossPct" {
    var a = Accumulator.init();
    a.addSample(10);
    a.addLoss();
    a.addSample(20);
    const s = a.snapshot();
    try testing.expectEqual(@as(u64, 3), s.sent);
    try testing.expectEqual(@as(u64, 2), s.received);
    try testing.expectApproxEqAbs(100.0 / 3.0, s.lossPct(), 1e-4);
    // loss must not disturb timing state
    try testing.expectEqual(@as(u64, 10), s.min_ns);
    try testing.expectEqual(@as(u64, 20), s.max_ns);
    try testing.expectApproxEqAbs(@as(f64, 15), s.mean_ns, eps);
}

test "RFC 3550 jitter recurrence" {
    var a = Accumulator.init();
    a.addSample(10);
    a.addSample(20);
    // J = 0 + (|20 - 10| - 0) / 16 = 0.625
    try testing.expectApproxEqAbs(@as(f64, 0.625), a.snapshot().jitter_ns, eps);
    a.addSample(12);
    // J = 0.625 + (|12 - 20| - 0.625) / 16 = 1.0859375
    try testing.expectApproxEqAbs(@as(f64, 1.0859375), a.snapshot().jitter_ns, eps);
}

test "compute equals the streaming path" {
    const samples = [_]?u64{ 10, null, 14, 16 };
    const c = compute(&samples);

    var a = Accumulator.init();
    a.addSample(10);
    a.addLoss();
    a.addSample(14);
    a.addSample(16);
    const s = a.snapshot();

    try testing.expectEqual(@as(u64, 4), c.sent);
    try testing.expectEqual(@as(u64, 3), c.received);
    try testing.expectApproxEqAbs(40.0 / 3.0, c.mean_ns, eps);

    try testing.expectEqual(s.sent, c.sent);
    try testing.expectEqual(s.received, c.received);
    try testing.expectEqual(s.min_ns, c.min_ns);
    try testing.expectEqual(s.max_ns, c.max_ns);
    try testing.expectApproxEqAbs(s.mean_ns, c.mean_ns, eps);
    try testing.expectApproxEqAbs(s.stddev_ns, c.stddev_ns, eps);
    try testing.expectApproxEqAbs(s.jitter_ns, c.jitter_ns, eps);
    try testing.expectApproxEqAbs(s.lossPct(), c.lossPct(), eps);
}

test "reset returns to the empty snapshot" {
    var a = Accumulator.init();
    a.addSample(10);
    a.addLoss();
    a.addSample(20);
    a.reset();
    const s = a.snapshot();
    try testing.expectEqual(@as(u64, 0), s.sent);
    try testing.expectEqual(@as(u64, 0), s.received);
    try testing.expectEqual(@as(u64, 0), s.min_ns);
    try testing.expectEqual(@as(u64, 0), s.max_ns);
    try testing.expectApproxEqAbs(@as(f64, 0), s.mean_ns, eps);
    try testing.expectApproxEqAbs(@as(f64, 0), s.stddev_ns, eps);
    try testing.expectApproxEqAbs(@as(f64, 0), s.jitter_ns, eps);
    try testing.expectApproxEqAbs(@as(f64, 0), s.lossPct(), eps);
}

// ── Histogram tests ──────────────────────────────────────────────────────────

/// Deterministic 64-bit LCG (Knuth MMIX constants) for reproducible test data.
fn testLcg(state: *u64) u64 {
    state.* = state.* *% 6364136223846793005 +% 1442695040888963407;
    return state.* >> 11;
}

/// Oracle: true percentile of a sorted slice under the same rank rule the
/// histogram uses (the max(1, round(p/100 * n))-th smallest value).
fn sortedPercentile(sorted: []const u64, p: f64) u64 {
    var rank: u64 = @intFromFloat(p / 100.0 * @as(f64, @floatFromInt(sorted.len)) + 0.5);
    if (rank == 0) rank = 1;
    if (rank > sorted.len) rank = sorted.len;
    return sorted[@intCast(rank - 1)];
}

test "Histogram: empty behavior" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer h.deinit();
    try testing.expectEqual(@as(u64, 0), h.totalCount());
    try testing.expectEqual(@as(u64, 0), h.min());
    try testing.expectEqual(@as(u64, 0), h.max());
    try testing.expectApproxEqAbs(@as(f64, 0), h.mean(), eps);
    try testing.expectApproxEqAbs(@as(f64, 0), h.stdDev(), eps);
    try testing.expectEqual(@as(u64, 0), h.valueAtPercentile(50));
    try testing.expectEqual(@as(u64, 0), h.countAtValue(42));
    const p = h.percentileSnapshot();
    try testing.expectEqual(@as(u64, 0), p.total_count);
    try testing.expectEqual(@as(u64, 0), p.p50);
    try testing.expectEqual(@as(u64, 0), p.p999);
    try testing.expectEqual(@as(u64, 0), p.max);
}

test "Histogram: invalid configs are rejected" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidConfig, Histogram.init(gpa, .{ .lowest = 0, .highest = 100 }));
    try testing.expectError(error.InvalidConfig, Histogram.init(gpa, .{ .highest = 100, .sigfigs = 0 }));
    try testing.expectError(error.InvalidConfig, Histogram.init(gpa, .{ .highest = 100, .sigfigs = 6 }));
    try testing.expectError(error.InvalidConfig, Histogram.init(gpa, .{ .lowest = 100, .highest = 199 }));
}

test "Histogram: single value is exact" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1_000_000, .sigfigs = 3 });
    defer h.deinit();
    h.record(42); // 42 < 2048 sub-buckets => unit resolution, exact
    try testing.expectEqual(@as(u64, 1), h.totalCount());
    try testing.expectEqual(@as(u64, 42), h.min());
    try testing.expectEqual(@as(u64, 42), h.max());
    try testing.expectEqual(@as(u64, 42), h.valueAtPercentile(0));
    try testing.expectEqual(@as(u64, 42), h.valueAtPercentile(50));
    try testing.expectEqual(@as(u64, 42), h.valueAtPercentile(100));
    try testing.expectApproxEqAbs(@as(f64, 42), h.mean(), eps);
    try testing.expectApproxEqAbs(@as(f64, 0), h.stdDev(), eps);
    try testing.expectEqual(@as(u64, 1), h.countAtValue(42));
    try testing.expectEqual(@as(u64, 0), h.countAtValue(41));
}

test "Histogram: uniform values collapse to one bucket" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1_000_000, .sigfigs = 3 });
    defer h.deinit();
    var i: usize = 0;
    while (i < 100) : (i += 1) h.record(1234);
    try testing.expectEqual(@as(u64, 100), h.totalCount());
    try testing.expectEqual(@as(u64, 100), h.countAtValue(1234));
    try testing.expectEqual(@as(u64, 1234), h.valueAtPercentile(0));
    try testing.expectEqual(@as(u64, 1234), h.valueAtPercentile(50));
    try testing.expectEqual(@as(u64, 1234), h.valueAtPercentile(99.9));
    try testing.expectEqual(@as(u64, 1234), h.valueAtPercentile(100));
    try testing.expectApproxEqAbs(@as(f64, 1234), h.mean(), eps);
    try testing.expectApproxEqAbs(@as(f64, 0), h.stdDev(), eps);
}

test "Histogram: ramp 1..1000 has exact percentiles, p0=min, p100=max" {
    // With sigfigs=3 every value <= 2047 is resolved exactly (unit buckets),
    // so the histogram must reproduce the sorted-array percentiles verbatim.
    var h = try Histogram.init(testing.allocator, .{ .highest = 3_600_000_000_000, .sigfigs = 3 });
    defer h.deinit();
    var v: u64 = 1;
    while (v <= 1000) : (v += 1) h.record(v);

    try testing.expectEqual(@as(u64, 1000), h.totalCount());
    try testing.expectEqual(h.min(), h.valueAtPercentile(0)); // p0 = min
    try testing.expectEqual(@as(u64, 1), h.min());
    try testing.expectEqual(h.max(), h.valueAtPercentile(100)); // p100 = max
    try testing.expectEqual(@as(u64, 1000), h.max());
    try testing.expectEqual(@as(u64, 500), h.valueAtPercentile(50));
    try testing.expectEqual(@as(u64, 900), h.valueAtPercentile(90));
    try testing.expectEqual(@as(u64, 950), h.valueAtPercentile(95));
    try testing.expectEqual(@as(u64, 990), h.valueAtPercentile(99));
    try testing.expectEqual(@as(u64, 999), h.valueAtPercentile(99.9));

    const p = h.percentileSnapshot();
    try testing.expectEqual(@as(u64, 500), p.p50);
    try testing.expectEqual(@as(u64, 999), p.p999);
    try testing.expectEqual(@as(u64, 1000), p.max);

    // mean of 1..n = (n+1)/2; population variance = (n^2 - 1) / 12.
    try testing.expectApproxEqAbs(@as(f64, 500.5), h.mean(), eps);
    try testing.expectApproxEqRel(@sqrt(999_999.0 / 12.0), h.stdDev(), 1e-9);

    try testing.expectEqual(@as(u64, 11), h.countBetween(10, 20));
    try testing.expectEqual(@as(u64, 1), h.countBetween(50, 50));
    try testing.expectEqual(@as(u64, 0), h.countBetween(60, 10));
    try testing.expectEqual(@as(u64, 1000), h.countBetween(1, 1000));
}

test "Histogram: LCG distribution vs sorted oracle within guaranteed error" {
    const n = 8192;
    var values: [n]u64 = undefined;
    var state: u64 = 0x9e3779b97f4a7c15;
    for (&values) |*v| v.* = testLcg(&state) % 1_000_000_000 + 1; // [1, 1e9]

    var sorted = values;
    std.sort.pdq(u64, &sorted, {}, std.sort.asc(u64));

    const percentiles = [_]f64{ 0, 10, 25, 50, 75, 90, 95, 99, 99.9, 100 };
    for ([_]u8{ 1, 2, 3, 4 }) |sf| {
        var h = try Histogram.init(testing.allocator, .{ .highest = 1_000_000_000, .sigfigs = sf });
        defer h.deinit();
        for (values) |v| h.record(v);
        try testing.expectEqual(@as(u64, n), h.totalCount());
        try testing.expectEqual(sorted[0], h.min());
        try testing.expectEqual(sorted[n - 1], h.max());

        const bound = h.maxRelativeError();
        for (percentiles) |p| {
            const truth = sortedPercentile(&sorted, p);
            const got = h.valueAtPercentile(p);
            try testing.expect(got >= truth); // never under-reports
            const rel = @as(f64, @floatFromInt(got - truth)) / @as(f64, @floatFromInt(truth));
            try testing.expect(rel <= bound);
        }
    }
}

test "Histogram: max relative representation error <= 1/2^significant_bits" {
    for ([_]u8{ 2, 3 }) |sf| {
        var h = try Histogram.init(testing.allocator, .{ .highest = 3_600_000_000_000, .sigfigs = sf });
        defer h.deinit();
        const bound = h.maxRelativeError();
        // sigfigs=2 -> half count 128 -> 1/128; sigfigs=3 -> 1024 -> 1/1024.
        const expected_bound: f64 = if (sf == 2) 1.0 / 128.0 else 1.0 / 1024.0;
        try testing.expectApproxEqAbs(expected_bound, bound, 1e-12);

        var worst: f64 = 0;
        var v: u64 = 1;
        while (v <= 3_600_000_000_000) : (v = v * 3 / 2 + 1) { // geometric sweep
            const hi = h.highestEquivalent(v);
            const lo = h.lowestEquivalent(v);
            try testing.expect(lo <= v and v <= hi); // v inside its own slot
            const rel = @as(f64, @floatFromInt(hi - v)) / @as(f64, @floatFromInt(v));
            if (rel > worst) worst = rel;
        }
        try testing.expect(worst <= bound);
    }
}

test "Histogram: recordCount equals repeated record" {
    var a = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer a.deinit();
    var b = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer b.deinit();
    a.recordCount(777, 5);
    a.recordCount(777, 0); // no-op
    var i: usize = 0;
    while (i < 5) : (i += 1) b.record(777);
    try testing.expectEqualSlices(u64, b.counts, a.counts);
    try testing.expectEqual(b.totalCount(), a.totalCount());
    try testing.expectEqual(b.min(), a.min());
    try testing.expectEqual(b.max(), a.max());
}

test "Histogram: out-of-range records clamp without corrupting counts" {
    var h = try Histogram.init(testing.allocator, .{ .lowest = 1, .highest = 1000 });
    defer h.deinit();
    h.record(0); // below lowest -> counted as 1
    h.record(std.math.maxInt(u64)); // above highest -> counted as 1000
    h.record(5_000); // above highest -> counted as 1000
    try testing.expectEqual(@as(u64, 3), h.totalCount());
    try testing.expectEqual(@as(u64, 1), h.min());
    try testing.expectEqual(@as(u64, 1000), h.max());
    try testing.expectEqual(@as(u64, 1), h.countAtValue(1));
    try testing.expectEqual(@as(u64, 2), h.countAtValue(1000));
    try testing.expectEqual(@as(u64, 3), h.countBetween(1, 1000));
    try testing.expectEqual(@as(u64, 1000), h.valueAtPercentile(100));
}

test "Histogram: add merge equals recording both sets into one" {
    const gpa = testing.allocator;
    var h1 = try Histogram.init(gpa, .{ .highest = 1_000_000_000 });
    defer h1.deinit();
    var h2 = try Histogram.init(gpa, .{ .highest = 1_000_000_000 });
    defer h2.deinit();
    var all = try Histogram.init(gpa, .{ .highest = 1_000_000_000 });
    defer all.deinit();

    var state: u64 = 12345;
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        const v = testLcg(&state) % 1_000_000_000 + 1;
        if (i % 2 == 0) h1.record(v) else h2.record(v);
        all.record(v);
    }

    try h1.add(&h2);
    try testing.expectEqualSlices(u64, all.counts, h1.counts);
    try testing.expectEqual(all.totalCount(), h1.totalCount());
    try testing.expectEqual(all.min(), h1.min());
    try testing.expectEqual(all.max(), h1.max());
    for ([_]f64{ 0, 50, 99, 99.9, 100 }) |p| {
        try testing.expectEqual(all.valueAtPercentile(p), h1.valueAtPercentile(p));
    }

    // Merging an empty histogram must not disturb min/max.
    var empty = try Histogram.init(gpa, .{ .highest = 1_000_000_000 });
    defer empty.deinit();
    const min_before = h1.min();
    try h1.add(&empty);
    try testing.expectEqual(min_before, h1.min());

    // Different config -> rejected.
    var other = try Histogram.init(gpa, .{ .highest = 1_000_000_000, .sigfigs = 2 });
    defer other.deinit();
    try testing.expectError(error.IncompatibleConfig, h1.add(&other));
}

test "Histogram: reset empties and the histogram stays usable" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer h.deinit();
    h.record(100);
    h.record(200_000);
    h.reset();
    try testing.expectEqual(@as(u64, 0), h.totalCount());
    try testing.expectEqual(@as(u64, 0), h.min());
    try testing.expectEqual(@as(u64, 0), h.max());
    try testing.expectEqual(@as(u64, 0), h.valueAtPercentile(50));
    h.record(500);
    try testing.expectEqual(@as(u64, 1), h.totalCount());
    try testing.expectEqual(@as(u64, 500), h.valueAtPercentile(50));
}

test "Histogram: wiring pattern alongside Accumulator" {
    // The documented pattern: one probe stream feeds both the zero-alloc
    // Accumulator (moments, jitter, loss) and the opt-in Histogram
    // (percentiles). Their overlapping views must agree.
    var acc = Accumulator.init();
    var hist = try Histogram.init(testing.allocator, .{ .highest = 10_000_000_000, .sigfigs = 3 });
    defer hist.deinit();

    const rtts = [_]u64{ 900, 1000, 1000, 1100, 1200, 1500, 2000 };
    for (rtts) |rtt| {
        acc.addSample(rtt);
        hist.record(rtt);
    }
    acc.addLoss(); // losses go only to the Accumulator

    const s = acc.snapshot();
    const p = hist.percentileSnapshot();
    try testing.expectEqual(s.received, p.total_count);
    try testing.expectEqual(s.min_ns, p.min);
    try testing.expectEqual(s.max_ns, p.max);
    try testing.expectEqual(@as(u64, 1100), p.p50); // 4th of 7, exact range
    try testing.expectEqual(@as(u64, 2000), p.p99);
    try testing.expectApproxEqAbs(s.mean_ns, hist.mean(), eps); // exact buckets here
}
