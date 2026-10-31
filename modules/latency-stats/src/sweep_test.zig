// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GX). Each test names the finding it kills.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const Histogram = root.Histogram;
const Accumulator = root.Accumulator;
const maxU = std.math.maxInt(u64);

test "recordCount saturates the total instead of overflowing (sweep LS1)" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer h.deinit();
    h.recordCount(5, maxU - 1);
    h.recordCount(900, 10); // only 1 still fits
    try testing.expectEqual(@as(u64, maxU), h.totalCount());
    h.record(5); // full: dropped, no overflow
    h.recordCount(7, maxU);
    try testing.expectEqual(@as(u64, maxU), h.totalCount());
    var sum: u64 = 0;
    for (h.counts) |c| sum += c; // would itself overflow if the invariant broke
    try testing.expectEqual(@as(u64, maxU), sum);
    try testing.expectEqual(@as(u64, maxU - 1), h.countAtValue(5));
    try testing.expectEqual(@as(u64, 1), h.countAtValue(900));
}

test "add saturates the total instead of overflowing (sweep LS1)" {
    var a = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer a.deinit();
    var b = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer b.deinit();
    a.recordCount(5, maxU - 3);
    b.recordCount(5, 2);
    b.recordCount(900, 100);
    try a.add(&b);
    try testing.expectEqual(@as(u64, maxU), a.totalCount());
    var sum: u64 = 0;
    for (a.counts) |c| sum += c;
    try testing.expectEqual(@as(u64, maxU), sum);
    try a.add(&a); // self-merge when already full
    try testing.expectEqual(@as(u64, maxU), a.totalCount());
}

test "percentile with a total near 2^64 does not trap in @intFromFloat (sweep LS2)" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer h.deinit();
    h.recordCount(5, maxU);
    const want = h.highestEquivalent(5);
    try testing.expectEqual(want, h.valueAtPercentile(100));
    try testing.expectEqual(want, h.valueAtPercentile(99.9));
    try testing.expectEqual(want, h.percentileSnapshot().p999);
}

test "percentile with NaN / infinite p is total (sweep LS3)" {
    var h = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer h.deinit();
    h.record(10);
    h.record(20);
    h.record(30);
    const nan = std.math.nan(f64);
    try testing.expectEqual(h.valueAtPercentile(0), h.valueAtPercentile(nan));
    try testing.expectEqual(h.valueAtPercentile(0), h.valueAtPercentile(-std.math.inf(f64)));
    try testing.expectEqual(h.valueAtPercentile(100), h.valueAtPercentile(std.math.inf(f64)));
}

test "Accumulator at the extremes stays finite (sweep LS4)" {
    var acc = Accumulator.init();
    acc.addSample(maxU);
    acc.addSample(0);
    acc.addSample(maxU);
    const s = acc.snapshot();
    try testing.expect(std.math.isFinite(s.mean_ns));
    try testing.expect(std.math.isFinite(s.stddev_ns));
    try testing.expect(std.math.isFinite(s.jitter_ns));
    try testing.expectEqual(@as(u64, maxU), s.max_ns);
    try testing.expectEqual(@as(f64, 0), (root.Stats{ .sent = 0, .received = 0, .min_ns = 0, .max_ns = 0, .mean_ns = 0, .stddev_ns = 0, .jitter_ns = 0 }).lossPct());
}

test "Histogram.init extremes are bounded or rejected (sweep LS5)" {
    // Largest legal config: lowest 1, highest maxInt, 5 sigfigs -> ~50 MB, no shift overflow.
    var h = try Histogram.init(testing.allocator, .{ .highest = maxU, .sigfigs = 5 });
    defer h.deinit();
    h.record(maxU);
    h.record(0);
    try testing.expectEqual(@as(u64, maxU), h.max());
    try testing.expectEqual(@as(u64, maxU), h.valueAtPercentile(100));
    try testing.expectError(error.InvalidConfig, Histogram.init(testing.allocator, .{ .lowest = maxU, .highest = maxU }));
    try testing.expectError(error.InvalidConfig, Histogram.init(testing.allocator, .{ .lowest = 1 << 63, .highest = maxU }));
    try testing.expectError(error.InvalidConfig, Histogram.init(testing.allocator, .{ .highest = 100, .sigfigs = 0 }));
    try testing.expectError(error.InvalidConfig, Histogram.init(testing.allocator, .{ .highest = 100, .sigfigs = 255 }));
}

test "add of a fully dropped histogram does not fold its min/max (sweep REV-LS1)" {
    var a = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer a.deinit();
    var b = try Histogram.init(testing.allocator, .{ .highest = 1_000_000 });
    defer b.deinit();
    a.recordCount(5, maxU); // full
    b.record(900_000);
    try a.add(&b);
    try testing.expectEqual(@as(u64, 5), a.max());
    try testing.expectEqual(@as(u64, 5), a.min());
    try testing.expectEqual(a.highestEquivalent(5), a.valueAtPercentile(100));
}
