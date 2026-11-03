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

// ── wave 2026-11-02 (grade 2): coordinated omission, merge, iterators, wire ──

const wire = root.wire;

test "recordCorrected equals the one-by-one loop (parity)" {
    const cfgs = [_]root.HistogramOptions{
        .{ .highest = 100_000, .sigfigs = 3 },
        .{ .lowest = 50, .highest = 10_000_000, .sigfigs = 2 },
        .{ .highest = 5_000, .sigfigs = 1 },
    };
    for (cfgs) |cfg| {
        for ([_]u64{ 1, 7, 100, 999, 1000, 4096 }) |iv| {
            for ([_]u64{ 0, 1, 50, iv, iv + 1, 3 * iv + 5, 90_000, 4_000_000 }) |v| {
                var a = try Histogram.init(testing.allocator, cfg);
                defer a.deinit();
                var b = try Histogram.init(testing.allocator, cfg);
                defer b.deinit();
                a.recordCorrectedCount(v, 3, iv);
                // reference: the plain definition, on the clamped value
                b.recordCount(v, 3);
                const c = std.math.clamp(v, cfg.lowest, cfg.highest);
                if (c > iv) {
                    var m = c - iv;
                    while (m >= iv) : (m -= iv) b.recordCount(m, 3);
                }
                try testing.expectEqualSlices(u64, b.counts, a.counts);
                try testing.expectEqual(b.total_count, a.total_count);
                try testing.expectEqual(b.min(), a.min());
                try testing.expectEqual(b.max(), a.max());
            }
        }
    }
}

test "recordCorrected with a tiny interval and a huge value returns (sweep LS6)" {
    var h = try Histogram.init(testing.allocator, .{ .highest = maxU, .sigfigs = 3 });
    defer h.deinit();
    h.recordCorrected(maxU, 1); // 2^64 synthetic samples if done one by one
    try testing.expectEqual(@as(u64, maxU), h.totalCount());
    h.recordCorrectedCount(maxU, maxU, 1);
    h.recordCorrected(5, 0);
    h.recordCorrected(0, maxU);
    var sum: u64 = 0;
    for (h.counts) |c| sum += c; // overflows (trap) if the total ever lied
    try testing.expectEqual(@as(u64, maxU), sum);
    var lo = try Histogram.init(testing.allocator, .{ .lowest = 1_000_000_000, .highest = maxU });
    defer lo.deinit();
    lo.recordCorrected(1_900_000_000, 1);
    lo.recordCorrected(900_000_000, 1); // below `lowest`: all of it clamps into one slot
    try testing.expect(lo.totalCount() > 1);
}

test "Accumulator.merge equals feeding one stream; extremes stay finite (sweep LS7)" {
    var whole = Accumulator.init();
    var a = Accumulator.init();
    var b = Accumulator.init();
    for ([_]u64{ 10, 12, 14, 16, 90, 11, 13 }, 0..) |v, i| {
        whole.addSample(v);
        if (i < 4) a.addSample(v) else b.addSample(v);
    }
    whole.addLoss();
    b.addLoss();
    a.merge(b);
    const w = whole.snapshot();
    const m = a.snapshot();
    try testing.expectEqual(w.sent, m.sent);
    try testing.expectEqual(w.received, m.received);
    try testing.expectEqual(w.min_ns, m.min_ns);
    try testing.expectEqual(w.max_ns, m.max_ns);
    try testing.expectApproxEqAbs(w.mean_ns, m.mean_ns, 1e-9);
    try testing.expectApproxEqAbs(w.stddev_ns, m.stddev_ns, 1e-9);
    // empty sides
    var e = Accumulator.init();
    e.merge(a);
    try testing.expectEqual(a.snapshot().received, e.snapshot().received);
    a.merge(Accumulator.init());
    try testing.expectEqual(a.snapshot().received, e.snapshot().received);
    // extremes
    var x = Accumulator.init();
    x.addSample(maxU);
    x.sent = maxU;
    var y = Accumulator.init();
    y.addSample(0);
    y.received = maxU;
    y.sent = maxU;
    x.merge(y);
    const s = x.snapshot();
    try testing.expectEqual(@as(u64, maxU), s.sent);
    try testing.expectEqual(@as(u64, maxU), s.received);
    try testing.expect(std.math.isFinite(s.mean_ns) and std.math.isFinite(s.stddev_ns) and std.math.isFinite(s.jitter_ns));
}

test "iterators take any argument and stop (sweep LS8)" {
    var h = try Histogram.init(testing.allocator, .{ .highest = maxU, .sigfigs = 2 });
    defer h.deinit();
    h.record(1);
    h.record(maxU);
    var lin = h.linear(0);
    try testing.expect(lin.next() != null);
    var lin2 = h.linear(maxU); // step wider than the range
    var n: usize = 0;
    while (lin2.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 2), n);
    for ([_]f64{ std.math.nan(f64), -1, 0, 1, 1.0000001, std.math.inf(f64), 1e300 }) |base| {
        var lg = h.logarithmic(maxU, base);
        var k: usize = 0;
        while (lg.next()) |_| : (k += 1) try testing.expect(k < 100_000);
        var lg0 = h.logarithmic(0, base);
        k = 0;
        while (lg0.next()) |_| : (k += 1) if (k > 200) break; // lazily bounded by the caller
    }
    var pt = h.percentiles(std.math.maxInt(u32));
    try testing.expect(pt.next() != null);
    var pz = h.percentiles(0);
    while (pz.next()) |_| {}
    var empty = try Histogram.init(testing.allocator, .{ .highest = 100 });
    defer empty.deinit();
    var r = empty.recorded();
    try testing.expect(r.next() == null);
    var pe = empty.percentiles(5);
    try testing.expect(pe.next() == null);
    try testing.expectEqual(@as(u64, 0), empty.slotLowest(1 << 40));
    try testing.expectEqual(@as(u64, 0), empty.slotHighest(1 << 40));
    try testing.expectEqual(@as(u64, 0), empty.rankAtPercentile(50));
}

test "wire.decode is total over short and forged input (sweep LS9; fuzz_test.zig holds the rest)" {
    var buf: [48]u8 = @splat(0);
    for (0..buf.len) |n| {
        if (wire.decode(testing.allocator, buf[0..n], .{})) |*d| {
            var dd = d.*;
            dd.deinit();
            return error.AcceptedZeros;
        } else |_| {}
    }
    var h = try Histogram.init(testing.allocator, .{ .highest = 1000 });
    defer h.deinit();
    h.record(5);
    var aw = std.Io.Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    try wire.encodeCompressed(&h, testing.allocator, &aw.writer);
    const z = try testing.allocator.dupe(u8, aw.written());
    defer testing.allocator.free(z);
    for (0..z.len) |n| try testing.expectError(error.BadFormat, wire.decode(testing.allocator, z[0..n], .{}));
    var i: usize = 0;
    while (i < z.len) : (i += 1) { // every single-byte corruption: some error or a valid histogram
        z[i] ^= 0xa5;
        if (wire.decode(testing.allocator, z, .{})) |*d| {
            var dd = d.*;
            dd.deinit();
        } else |_| {}
        z[i] ^= 0xa5;
    }
}
