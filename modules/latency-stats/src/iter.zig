// SPDX-License-Identifier: MIT
//! Distribution iterators over a `Histogram`: the recorded slots, fixed-width
//! (linear) and geometric (logarithmic) intervals, and percentile ticks. Each
//! is a plain value with `next()`; none allocates, none can fail, and every
//! argument is total (a nonsense step or base falls back to a default, see
//! each `init`). They borrow the histogram: do not record while iterating.
//!
//! The four are what HdrHistogram's iterators give a user who prints or plots
//! a latency distribution. Interval iterators attribute a counts slot to the
//! interval that contains the slot's smallest value, and stop at the interval
//! holding the largest recorded value, so the counts of all bins add up to
//! `total_count` and the last bin's `cumulative` equals it.

const std = @import("std");
const testing = std.testing;
const Histogram = @import("root.zig").Histogram;

const maxU = std.math.maxInt(u64);

/// One bin of a value iterator. For `Recorded` it is one counts slot
/// (`lowest`..`highest` are the slot's equivalent range); for `Linear` and
/// `Logarithmic` it is the interval `lowest..highest` (inclusive).
pub const Bin = struct {
    lowest: u64,
    highest: u64,
    /// Samples in this bin.
    count: u64,
    /// Samples in this bin and every bin before it.
    cumulative: u64,
};

/// Every non-empty counts slot, smallest value first.
pub const Recorded = struct {
    h: *const Histogram,
    idx: usize = 0,
    cum: u64 = 0,

    pub fn init(h: *const Histogram) Recorded {
        return .{ .h = h };
    }

    pub fn next(self: *Recorded) ?Bin {
        while (self.idx < self.h.counts.len) {
            const i = self.idx;
            self.idx += 1;
            const c = self.h.counts[i];
            if (c == 0) continue;
            self.cum +|= c;
            return .{ .lowest = self.h.slotLowest(i), .highest = self.h.slotHighest(i), .count = c, .cumulative = self.cum };
        }
        return null;
    }
};

/// Shared walk of the interval iterators: consume the slots whose smallest
/// value is `<= hi`.
fn take(h: *const Histogram, idx: *usize, hi: u64) u64 {
    var count: u64 = 0;
    while (idx.* < h.counts.len and h.slotLowest(idx.*) <= hi) : (idx.* += 1) count +|= h.counts[idx.*];
    return count;
}

/// Intervals `[0, step-1]`, `[step, 2*step-1]`, ... up to the one holding the
/// largest recorded value. Empty intervals are yielded (count 0). `step == 0`
/// is treated as 1.
pub const Linear = struct {
    h: *const Histogram,
    step: u64,
    lo: u64 = 0,
    idx: usize = 0,
    cum: u64 = 0,
    done: bool,

    pub fn init(h: *const Histogram, step: u64) Linear {
        return .{ .h = h, .step = @max(step, 1), .done = h.total_count == 0 };
    }

    pub fn next(self: *Linear) ?Bin {
        if (self.done) return null;
        const hi = if (self.lo > maxU - (self.step - 1)) maxU else self.lo + (self.step - 1);
        const c = take(self.h, &self.idx, hi);
        self.cum +|= c;
        const bin: Bin = .{ .lowest = self.lo, .highest = hi, .count = c, .cumulative = self.cum };
        if (hi == maxU or hi >= self.h.max_value) self.done = true else self.lo = hi + 1;
        return bin;
    }
};

/// Intervals `[0, first-1]`, then each one's upper bound `base` times the
/// previous one's, up to the one holding the largest recorded value.
/// `first == 0` is treated as 1; a `base` that is NaN or below 1.01 as 2.
pub const Logarithmic = struct {
    h: *const Histogram,
    base: f64,
    /// Exclusive upper bound of the next interval.
    upper: f64,
    lo: u64 = 0,
    idx: usize = 0,
    cum: u64 = 0,
    done: bool,

    pub fn init(h: *const Histogram, first: u64, base: f64) Logarithmic {
        return .{
            .h = h,
            .base = if (base >= 1.01) base else 2.0,
            .upper = @floatFromInt(@max(first, 1)),
            .done = h.total_count == 0,
        };
    }

    pub fn next(self: *Logarithmic) ?Bin {
        if (self.done) return null;
        var hi: u64 = if (self.upper >= 18446744073709551616.0) maxU else @as(u64, @intFromFloat(self.upper)) -| 1;
        if (hi < self.lo) hi = self.lo; // a base too close to 1 for the float to grow
        const c = take(self.h, &self.idx, hi);
        self.cum +|= c;
        const bin: Bin = .{ .lowest = self.lo, .highest = hi, .count = c, .cumulative = self.cum };
        if (hi == maxU or hi >= self.h.max_value) self.done = true else {
            self.lo = hi + 1;
            self.upper *= self.base;
        }
        return bin;
    }
};

/// One tick of `Percentiles`.
pub const Tick = struct {
    /// The percentile asked for (the last tick says exactly 100).
    percentile: f64,
    /// `valueAtPercentile(percentile)`: the highest equivalent value.
    value: u64,
    /// Samples at or below `value`'s slot.
    cumulative: u64,
};

/// Percentile ticks `0, s, 2s, ...` with the step halving at each halving of
/// the distance to 100 (`ticks_per_half_distance` ticks between 0 and 50,
/// between 50 and 75, ...), ending with a tick at 100. Walks the counts once.
/// `ticks_per_half_distance == 0` is treated as 1.
pub const Percentiles = struct {
    h: *const Histogram,
    ticks: f64,
    p: f64 = 0,
    idx: usize = 0,
    cum: u64 = 0,
    done: bool,

    pub fn init(h: *const Histogram, ticks_per_half_distance: u32) Percentiles {
        return .{ .h = h, .ticks = @floatFromInt(@max(ticks_per_half_distance, 1)), .done = h.total_count == 0 };
    }

    pub fn next(self: *Percentiles) ?Tick {
        if (self.done) return null;
        const target = self.h.rankAtPercentile(self.p);
        while (self.cum < target and self.idx < self.h.counts.len) {
            self.cum +|= self.h.counts[self.idx];
            self.idx += 1;
        }
        const last = self.cum >= self.h.total_count;
        const tick: Tick = .{
            .percentile = if (last) 100 else self.p,
            .value = self.h.slotHighest(self.idx -| 1),
            .cumulative = self.cum,
        };
        if (last) {
            self.done = true;
        } else {
            const to_go = 100.0 - self.p;
            const half_dist = std.math.pow(f64, 2, @floor(std.math.log2(100.0 / to_go)) + 1);
            const np = self.p + 100.0 / (self.ticks * half_dist);
            // A step below the float's resolution near 100 (huge totals) would
            // repeat this tick for ever: jump to the end instead.
            self.p = if (np > self.p and np < 100) np else 100;
        }
        return tick;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

fn ramp(gpa: std.mem.Allocator) !Histogram {
    var h = try Histogram.init(gpa, .{ .highest = 1_000_000, .sigfigs = 3 });
    for (1..1001) |v| h.record(v);
    return h;
}

test "recorded: every non-empty slot once, counts add up" {
    var h = try ramp(testing.allocator);
    defer h.deinit();
    var it = h.recorded();
    var n: u64 = 0;
    var prev_hi: u64 = 0;
    var last: Bin = undefined;
    while (it.next()) |b| {
        try testing.expect(b.lowest > prev_hi or n == 0);
        prev_hi = b.highest;
        n += b.count;
        try testing.expectEqual(n, b.cumulative);
        last = b;
    }
    try testing.expectEqual(@as(u64, 1000), n);
    try testing.expectEqual(@as(u64, 1000), last.cumulative);
    try testing.expectEqual(@as(u64, 1000), last.highest);
}

test "linear: exact ramp splits into equal tenths, last bin ends the walk" {
    var h = try ramp(testing.allocator);
    defer h.deinit();
    var it = h.linear(100);
    var bins: usize = 0;
    while (it.next()) |b| : (bins += 1) {
        // [0,99] holds 1..99, then 100 each, [1000,1099] holds the 1000.
        const want: u64 = if (bins == 0) 99 else if (bins == 10) 1 else 100;
        try testing.expectEqual(want, b.count);
        try testing.expectEqual(@as(u64, bins) * 100, b.lowest);
    }
    try testing.expectEqual(@as(usize, 11), bins);
    try testing.expect(it.next() == null);
}

test "linear step 0 behaves as 1; empty histogram yields nothing" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1000 });
    defer h.deinit();
    var e = h.linear(5);
    try testing.expect(e.next() == null);
    h.record(3);
    var it = h.linear(0);
    var total: u64 = 0;
    var bins: usize = 0;
    while (it.next()) |b| : (bins += 1) total += b.count;
    try testing.expectEqual(@as(u64, 1), total);
    try testing.expectEqual(@as(usize, 4), bins); // [0],[1],[2],[3]
}

test "logarithmic: doubling intervals, all samples, total ends at the last bin" {
    var h = try ramp(testing.allocator);
    defer h.deinit();
    var it = h.logarithmic(10, 2.0);
    var total: u64 = 0;
    var want_hi: u64 = 9;
    var last_cum: u64 = 0;
    while (it.next()) |b| {
        total += b.count;
        last_cum = b.cumulative;
        if (b.highest < 1000) {
            try testing.expectEqual(want_hi, b.highest);
            want_hi = (want_hi + 1) * 2 - 1;
        }
    }
    try testing.expectEqual(@as(u64, 1000), total);
    try testing.expectEqual(@as(u64, 1000), last_cum);
    // Nonsense base / first fall back; huge ranges still terminate by max.
    var odd = h.logarithmic(0, std.math.nan(f64));
    var n: usize = 0;
    while (odd.next()) |_| n += 1;
    try testing.expect(n > 1 and n < 64);
}

test "percentiles: ticks are monotone, end at 100, value matches valueAtPercentile" {
    var h = try ramp(testing.allocator);
    defer h.deinit();
    var it = h.percentiles(5);
    var prev: f64 = -1;
    var prev_v: u64 = 0;
    var n: usize = 0;
    var last: Tick = undefined;
    while (it.next()) |t| : (n += 1) {
        try testing.expect(t.percentile > prev);
        try testing.expect(t.value >= prev_v);
        if (t.percentile < 100) try testing.expectEqual(h.valueAtPercentile(t.percentile), t.value);
        prev = t.percentile;
        prev_v = t.value;
        last = t;
    }
    try testing.expectEqual(@as(f64, 100), last.percentile);
    try testing.expectEqual(@as(u64, 1000), last.cumulative);
    try testing.expectEqual(h.valueAtPercentile(100), last.value);
    try testing.expect(n > 10 and n < 200);
}

test "percentiles: huge totals terminate (float step below resolution)" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer h.deinit();
    h.recordCount(5, maxU / 2);
    h.recordCount(900, maxU / 4);
    var it = h.percentiles(1000);
    var n: usize = 0;
    while (it.next()) |_| {
        n += 1;
        try testing.expect(n < 100_000);
    }
    try testing.expect(n > 10);
}
