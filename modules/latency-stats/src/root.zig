// SPDX-License-Identifier: MIT
//! latency-stats — online round-trip-time statistics for probe/ping engines.
//!
//! Feed it one RTT sample per reply (and one "loss" per unanswered probe); it
//! keeps running min / max / mean / population stddev, RFC 3550 interarrival
//! jitter, and packet-loss %, all in O(1) per sample with **zero allocation**
//! and no syscalls. A one-shot `compute()` over a slice is provided too.
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
//! online variance. No third-party source copied — see ../../NOTICE.

const std = @import("std");

pub const meta = .{
    .status = .extract,
    .platform = .any, // pure arithmetic; no I/O, no clock
    .role = .util,
    .concurrency = .single_owner, // one Accumulator per probe stream; not shared
    .model_after = "fping/iputils-ping summary stats + RFC 3550 §6.4.1 jitter + Welford online variance",
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
