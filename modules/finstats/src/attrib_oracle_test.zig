// SPDX-License-Identifier: MIT
//! Published and foreign anchors for `brinsonAttribution`, `twrDaily` and the calmar of
//! `riskMetrics` (see the SPEC's Anchoring section).
//!
//! - Brinson-Fachler: the worked table in FinanceToolkit's documentation, numbers to four
//!   decimals, which includes segments the portfolio does not hold, shown with no return.
//! - Modified Dietz: published worked examples (Wikipedia "Modified Dietz method", FinFacts
//!   "Modified Dietz"). `twrDaily` takes the average capital from the caller, so the
//!   examples pin the numerator, the division and the skip of a non-positive base.
//! - Brinson-Fachler at full precision: FinanceToolkit `get_brinson_fachler_attribution` run
//!   as a black box over our seeded inputs, edge rules included (`tools/attrib_oracle.py`).
//! - calmar: ffn `PerformanceStats.calmar` (`tools/calmar_oracle.py`).

const std = @import("std");
const testing = std.testing;
const fs = @import("root.zig");

const calmar_ref = @import("testdata/calmar_vectors.zig");
const ft_ref = @import("testdata/attrib_oracle_vectors.zig");
const nan = std.math.nan(f64);

/// One segment; a return that is not there is NaN.
const Seg = struct { name: []const u8, wp: f64, wb: f64, rp: f64, rb: f64 };

fn brinsonOf(a: std.mem.Allocator, segs: []const Seg) !fs.BrinsonResult {
    const cols = try a.alloc(f64, 4 * segs.len);
    const wp = cols[0..segs.len];
    const wb = cols[segs.len..][0..segs.len];
    const rp = cols[2 * segs.len ..][0..segs.len];
    const rb = cols[3 * segs.len ..][0..segs.len];
    for (segs, 0..) |s, i| {
        wp[i] = s.wp;
        wb[i] = s.wb;
        rp[i] = s.rp;
        rb[i] = s.rb;
    }
    return fs.brinsonAttribution(a, wp, wb, rp, rb);
}

test "published: FinanceToolkit's Brinson-Fachler table, unheld segments shown without a return" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const T = struct { seg: Seg, alloc: f64, sel: f64, inter: f64, total: f64 };
    const table = [_]T{
        .{ .seg = .{ .name = "Basic Materials", .wp = 0, .wb = 0.017, .rp = nan, .rb = 0.1115 }, .alloc = 0.0012, .sel = 0, .inter = 0, .total = 0.0012 },
        .{ .seg = .{ .name = "Communication Services", .wp = 0, .wb = 0.0923, .rp = nan, .rb = 0.2249 }, .alloc = -0.0042, .sel = 0, .inter = 0, .total = -0.0042 },
        .{ .seg = .{ .name = "Consumer Cyclical", .wp = 0, .wb = 0.0896, .rp = nan, .rb = 0.0881 }, .alloc = 0.0082, .sel = 0, .inter = 0, .total = 0.0082 },
        .{ .seg = .{ .name = "Consumer Defensive", .wp = 0, .wb = 0.0495, .rp = nan, .rb = 0.0183 }, .alloc = 0.008, .sel = 0, .inter = 0, .total = 0.008 },
        .{ .seg = .{ .name = "Energy", .wp = 0.2, .wb = 0.0373, .rp = 0.1625, .rb = 0.0661 }, .alloc = -0.0185, .sel = 0.0036, .inter = 0.0157, .total = 0.0008 },
        .{ .seg = .{ .name = "Financial Services", .wp = 0.2, .wb = 0.1208, .rp = 0.371, .rb = 0.152 }, .alloc = -0.0022, .sel = 0.0265, .inter = 0.0173, .total = 0.0416 },
        .{ .seg = .{ .name = "Healthcare", .wp = 0.2, .wb = 0.0994, .rp = 0.4809, .rb = 0.1447 }, .alloc = -0.0035, .sel = 0.0334, .inter = 0.0338, .total = 0.0637 },
        .{ .seg = .{ .name = "Industrials", .wp = 0, .wb = 0.0803, .rp = nan, .rb = 0.1976 }, .alloc = -0.0014, .sel = 0, .inter = 0, .total = -0.0014 },
        .{ .seg = .{ .name = "Real Estate", .wp = 0, .wb = 0.0175, .rp = nan, .rb = 0.036 }, .alloc = 0.0025, .sel = 0, .inter = 0, .total = 0.0025 },
        .{ .seg = .{ .name = "Technology", .wp = 0.4, .wb = 0.3758, .rp = 0.1419, .rb = 0.2489 }, .alloc = 0.0017, .sel = -0.0402, .inter = -0.0026, .total = -0.0411 },
        .{ .seg = .{ .name = "Utilities", .wp = 0, .wb = 0.0204, .rp = nan, .rb = 0.1511 }, .alloc = 0.0006, .sel = 0, .inter = 0, .total = 0.0006 },
    };
    var segs: [table.len]Seg = undefined;
    for (&segs, table) |*s, t| s.* = t.seg;
    const b = try brinsonOf(a, &segs);

    // Inputs and answers are both rounded to four decimals, and a weight error of 5e-5
    // meets a return difference of up to about 0.5.
    const tol = 1.5e-4;
    var bhb_differs: usize = 0;
    for (table, 0..) |t, i| {
        errdefer std.debug.print("segment {s}\n", .{t.seg.name});
        try testing.expectApproxEqAbs(t.alloc, b.rows[i].allocation, tol);
        try testing.expectApproxEqAbs(t.sel, b.rows[i].selection, tol);
        try testing.expectApproxEqAbs(t.inter, b.rows[i].interaction, tol);
        try testing.expectApproxEqAbs(t.total, b.rows[i].total, tol);
        // Negative control: BHB's allocation (wp - wb) * rb must not fit this table.
        if (@abs((t.seg.wp - t.seg.wb) * t.seg.rb - t.alloc) > 10 * tol) bhb_differs += 1;
    }
    try testing.expect(bhb_differs >= 5);
    const totals = b.total;
    try testing.expectApproxEqAbs(-0.0077, totals.allocation, 3 * tol);
    try testing.expectApproxEqAbs(0.0233, totals.selection, 3 * tol);
    try testing.expectApproxEqAbs(0.0642, totals.interaction, 3 * tol);
    try testing.expectApproxEqAbs(0.0798, totals.total, 3 * tol);
}

test "oracle: brinsonAttribution against FinanceToolkit, edge rules included" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (ft_ref.bf_cases) |c| {
        errdefer std.debug.print("FinanceToolkit case: {s}\n", .{c.label});
        {
            const m = c.wp.len;
            const b = try fs.brinsonAttribution(a, c.wp, c.wb, c.rp, c.rb);
            var bhb_differs = false;
            for (0..m) |i| {
                try testing.expectApproxEqAbs(c.alloc[i], b.rows[i].allocation, 1e-14);
                try testing.expectApproxEqAbs(c.sel[i], b.rows[i].selection, 1e-14);
                try testing.expectApproxEqAbs(c.inter[i], b.rows[i].interaction, 1e-14);
                // Negative control: these vectors must be able to tell BF from BHB.
                if (@abs(c.bhb_alloc[i] - c.alloc[i]) > 1e-6) bhb_differs = true;
            }
            try testing.expect(bhb_differs);
            try testing.expectApproxEqAbs(c.total_active, b.total.total, 1e-13);
        }
    }
}

test "brinsonAttribution: a segment not held is pure allocation, whatever its stated return" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Rb = 0.5*0.10 + 0.5*0.02 = 0.06. A is not held, B is 100 %.
    // A: allocation -0.5*(0.10-0.06) = -0.02, nothing else. B: allocation 0.5*(0.02-0.06) = -0.02,
    // selection 0.5*(0.05-0.02) = 0.015, interaction 0.5*(0.05-0.02) = 0.015. Active 0.05-0.06.
    for ([_]f64{ 0.33, nan }) |stated| {
        const b = try brinsonOf(a, &.{
            .{ .name = "A", .wp = 0, .wb = 0.5, .rp = stated, .rb = 0.10 },
            .{ .name = "B", .wp = 1, .wb = 0.5, .rp = 0.05, .rb = 0.02 },
        });
        try testing.expectApproxEqAbs(@as(f64, -0.02), b.rows[0].allocation, 1e-15);
        try testing.expectEqual(@as(f64, 0), b.rows[0].selection);
        try testing.expectEqual(@as(f64, 0), b.rows[0].interaction);
        try testing.expectApproxEqAbs(@as(f64, -0.02), b.rows[0].total, 1e-15);
        try testing.expectApproxEqAbs(@as(f64, -0.01), b.total.total, 1e-15);
    }
}

test "brinsonAttribution: a segment outside the benchmark with no return is measured against Rb" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Rb = 1.0*0.04. X is outside the benchmark: rb becomes Rb, so allocation 0.5*0 = 0,
    // selection 0, interaction 0.5*(0.10-0.04) = 0.03. Y: allocation -0.5*0 = 0,
    // selection 1.0*(0.02-0.04) = -0.02, interaction -0.5*(0.02-0.04) = 0.01.
    // Rp = 0.06, active 0.02, and the effects add up to it.
    for ([_]f64{nan}) |missing| {
        const b = try brinsonOf(a, &.{
            .{ .name = "X", .wp = 0.5, .wb = 0, .rp = 0.10, .rb = missing },
            .{ .name = "Y", .wp = 0.5, .wb = 1, .rp = 0.02, .rb = 0.04 },
        });
        try testing.expectEqual(@as(f64, 0), b.rows[0].allocation);
        try testing.expectEqual(@as(f64, 0), b.rows[0].selection);
        try testing.expectApproxEqAbs(@as(f64, 0.03), b.rows[0].interaction, 1e-15);
        try testing.expectApproxEqAbs(@as(f64, -0.02), b.rows[1].selection, 1e-15);
        try testing.expectApproxEqAbs(@as(f64, 0.01), b.rows[1].interaction, 1e-15);
        try testing.expectApproxEqAbs(@as(f64, 0.02), b.total.total, 1e-15);
    }
    // A stated return outside the benchmark is kept: allocation 0.5*(0.08-0.04) = 0.02.
    const c = try brinsonOf(a, &.{
        .{ .name = "X", .wp = 0.5, .wb = 0, .rp = 0.10, .rb = 0.08 },
        .{ .name = "Y", .wp = 0.5, .wb = 1, .rp = 0.02, .rb = 0.04 },
    });
    try testing.expectApproxEqAbs(@as(f64, 0.02), c.rows[0].allocation, 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 0.01), c.rows[0].interaction, 1e-15);
}

test "brinsonAttribution: a position that has no return is NaN, not a number built on zero" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // A held segment with no portfolio return: its own row and the totals are undefined,
    // the other segment's selection is not.
    for ([_]f64{nan}) |missing| {
        const b = try brinsonOf(a, &.{
            .{ .name = "A", .wp = 0.5, .wb = 0.5, .rp = missing, .rb = 0.10 },
            .{ .name = "B", .wp = 0.5, .wb = 0.5, .rp = 0.05, .rb = 0.02 },
        });
        try testing.expect(std.math.isNan(b.rows[0].selection));
        try testing.expect(std.math.isNan(b.total.selection));
        try testing.expectApproxEqAbs(@as(f64, 0.015), b.rows[1].selection, 1e-15);
        // A benchmark segment with no return: Rb itself is undefined.
        const c = try brinsonOf(a, &.{
            .{ .name = "A", .wp = 0.7, .wb = 0.5, .rp = 0.10, .rb = missing },
            .{ .name = "B", .wp = 0.3, .wb = 0.5, .rp = 0.05, .rb = 0.02 },
        });
        try testing.expect(std.math.isNan(c.rows[1].allocation));
        try testing.expect(std.math.isNan(c.total.total));
    }
}

/// `twrDaily` over one period: a seed row, then the period's end value, its net flow and
/// the Modified Dietz average capital. Null when the module emits no return for it.
fn dietz(a: std.mem.Allocator, start: f64, end: f64, flow: f64, base: f64) !?f64 {
    const t = try fs.twrDaily(a, &.{ start, end }, &.{ 0, flow }, &.{ start, base }, 0);
    return if (t.len == 0) null else t[0].r;
}

test "published: Modified Dietz worked examples" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Wikipedia: 100 to 300, +50 half way. Average capital 100 + 0.5*50 = 125, return 120 %.
    try testing.expectApproxEqAbs(@as(f64, 1.2), (try dietz(a, 100, 300, 50, 100 + 0.5 * 50)).?, 1e-15);

    // Wikipedia: bought for 1 128 728, sold for 1 125 990, no flows. About -0.24 %.
    try testing.expectApproxEqAbs(@as(f64, -0.0024), (try dietz(a, 1128728, 1125990, 0, 1128728)).?, 5e-5);

    // FinFacts: 1 000 000 to 1 080 000 over 30 days, flows +50 000 on day 4, -20 000 on day 14,
    // +10 000 on day 24, each weighted (30 - day) / 30. Published as 0.03866.
    const base = 1_000_000.0 + 50_000.0 * 26.0 / 30.0 - 20_000.0 * 16.0 / 30.0 + 10_000.0 * 6.0 / 30.0;
    try testing.expectApproxEqAbs(@as(f64, 0.03866), (try dietz(a, 1_000_000, 1_080_000, 40_000, base)).?, 5e-6);

    // Wikipedia: average capital 1000 - 7/8*1200 = -50, for which the naive answer is
    // -900 %, a number the same article rejects. The module emits no return for it.
    try testing.expectEqual(@as(?f64, null), try dietz(a, 1000, 250, -1200, 1000 - 7.0 / 8.0 * 1200));
}

test "oracle: riskMetrics calmar against ffn PerformanceStats" {
    for (calmar_ref.cases, 0..) |c, k| {
        errdefer std.debug.print("calmar case {d}\n", .{k});
        const dates = calmar_ref.dates[0..c.returns.len];
        const m = try fs.riskMetrics(testing.allocator, c.returns, .{ .span_days = try fs.daySpan(dates[0], dates[dates.len - 1]) });
        try testing.expectApproxEqRel(c.calmar, m.calmar, 1e-11);
    }
}
