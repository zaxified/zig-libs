// SPDX-License-Identifier: MIT
//! Published and foreign anchors for `brinsonAttribution`, `twrDaily` and the calmar of
//! `riskMetrics` (see the SPEC's Anchoring section).
//!
//! - Brinson-Fachler: the worked table in FinanceToolkit's documentation, numbers to four
//!   decimals, which includes segments the portfolio does not hold, shown with no return.
//! - Modified Dietz: published worked examples (Wikipedia "Modified Dietz method", FinFacts
//!   "Modified Dietz"). `twrDaily` takes the average capital from the caller, so the
//!   examples pin the numerator, the division and the skip of a non-positive base.
//! - calmar: ffn `PerformanceStats.calmar` (`tools/calmar_oracle.py`).

const std = @import("std");
const testing = std.testing;
const fs = @import("root.zig");
const dataset = @import("dataset");
const Column = dataset.Column;
const Value = dataset.Value;
const Dataset = dataset.Dataset;

const calmar_ref = @import("testdata/calmar_vectors.zig");
const nan = std.math.nan(f64);

const brinson_spec: fs.BrinsonSpec = .{
    .segment_col = "s",
    .port_weight_col = "wp",
    .bench_weight_col = "wb",
    .port_return_col = "rp",
    .bench_return_col = "rb",
};

const brinson_cols = [_]Column{
    .{ .name = "s", .type = .text },   .{ .name = "wp", .type = .float },
    .{ .name = "wb", .type = .float }, .{ .name = "rp", .type = .float },
    .{ .name = "rb", .type = .float },
};

/// One segment: a null return means the column holds `.null`, NaN a float NaN.
const Seg = struct { name: []const u8, wp: f64, wb: f64, rp: ?f64, rb: ?f64 };

fn optValue(x: ?f64) Value {
    return if (x) |v| .{ .float = v } else .null;
}

fn brinsonOf(a: std.mem.Allocator, segs: []const Seg) !Dataset {
    const rows = try a.alloc([]const Value, segs.len);
    for (rows, segs) |*r, s| r.* = try a.dupe(Value, &.{
        .{ .text = s.name },
        .{ .float = s.wp },
        .{ .float = s.wb },
        optValue(s.rp),
        optValue(s.rb),
    });
    return fs.brinsonAttribution(a, .{ .columns = &brinson_cols, .rows = rows }, brinson_spec);
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
        try testing.expectApproxEqAbs(t.alloc, b.rows[i][1].float, tol);
        try testing.expectApproxEqAbs(t.sel, b.rows[i][2].float, tol);
        try testing.expectApproxEqAbs(t.inter, b.rows[i][3].float, tol);
        try testing.expectApproxEqAbs(t.total, b.rows[i][4].float, tol);
        // Negative control: BHB's allocation (wp - wb) * rb must not fit this table.
        if (@abs((t.seg.wp - t.seg.wb) * t.seg.rb.? - t.alloc) > 10 * tol) bhb_differs += 1;
    }
    try testing.expect(bhb_differs >= 5);
    const totals = b.rows[table.len];
    try testing.expectApproxEqAbs(-0.0077, totals[1].float, 3 * tol);
    try testing.expectApproxEqAbs(0.0233, totals[2].float, 3 * tol);
    try testing.expectApproxEqAbs(0.0642, totals[3].float, 3 * tol);
    try testing.expectApproxEqAbs(0.0798, totals[4].float, 3 * tol);
}

test "brinsonAttribution: a segment not held is pure allocation, whatever its stated return" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Rb = 0.5*0.10 + 0.5*0.02 = 0.06. A is not held, B is 100 %.
    // A: allocation -0.5*(0.10-0.06) = -0.02, nothing else. B: allocation 0.5*(0.02-0.06) = -0.02,
    // selection 0.5*(0.05-0.02) = 0.015, interaction 0.5*(0.05-0.02) = 0.015. Active 0.05-0.06.
    for ([_]?f64{ 0.33, nan, null }) |stated| {
        const b = try brinsonOf(a, &.{
            .{ .name = "A", .wp = 0, .wb = 0.5, .rp = stated, .rb = 0.10 },
            .{ .name = "B", .wp = 1, .wb = 0.5, .rp = 0.05, .rb = 0.02 },
        });
        try testing.expectApproxEqAbs(@as(f64, -0.02), b.rows[0][1].float, 1e-15);
        try testing.expectEqual(@as(f64, 0), b.rows[0][2].float);
        try testing.expectEqual(@as(f64, 0), b.rows[0][3].float);
        try testing.expectApproxEqAbs(@as(f64, -0.02), b.rows[0][4].float, 1e-15);
        try testing.expectApproxEqAbs(@as(f64, -0.01), b.rows[2][4].float, 1e-15);
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
    for ([_]?f64{ nan, null }) |missing| {
        const b = try brinsonOf(a, &.{
            .{ .name = "X", .wp = 0.5, .wb = 0, .rp = 0.10, .rb = missing },
            .{ .name = "Y", .wp = 0.5, .wb = 1, .rp = 0.02, .rb = 0.04 },
        });
        try testing.expectEqual(@as(f64, 0), b.rows[0][1].float);
        try testing.expectEqual(@as(f64, 0), b.rows[0][2].float);
        try testing.expectApproxEqAbs(@as(f64, 0.03), b.rows[0][3].float, 1e-15);
        try testing.expectApproxEqAbs(@as(f64, -0.02), b.rows[1][2].float, 1e-15);
        try testing.expectApproxEqAbs(@as(f64, 0.01), b.rows[1][3].float, 1e-15);
        try testing.expectApproxEqAbs(@as(f64, 0.02), b.rows[2][4].float, 1e-15);
    }
    // A stated return outside the benchmark is kept: allocation 0.5*(0.08-0.04) = 0.02.
    const c = try brinsonOf(a, &.{
        .{ .name = "X", .wp = 0.5, .wb = 0, .rp = 0.10, .rb = 0.08 },
        .{ .name = "Y", .wp = 0.5, .wb = 1, .rp = 0.02, .rb = 0.04 },
    });
    try testing.expectApproxEqAbs(@as(f64, 0.02), c.rows[0][1].float, 1e-15);
    try testing.expectApproxEqAbs(@as(f64, 0.01), c.rows[0][3].float, 1e-15);
}

test "brinsonAttribution: a position that has no return is NaN, not a number built on zero" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // A held segment with no portfolio return: its own row and the totals are undefined,
    // the other segment's selection is not.
    for ([_]?f64{ nan, null }) |missing| {
        const b = try brinsonOf(a, &.{
            .{ .name = "A", .wp = 0.5, .wb = 0.5, .rp = missing, .rb = 0.10 },
            .{ .name = "B", .wp = 0.5, .wb = 0.5, .rp = 0.05, .rb = 0.02 },
        });
        try testing.expect(std.math.isNan(b.rows[0][2].float));
        try testing.expect(std.math.isNan(b.rows[2][2].float));
        try testing.expectApproxEqAbs(@as(f64, 0.015), b.rows[1][2].float, 1e-15);
        // A benchmark segment with no return: Rb itself is undefined.
        const c = try brinsonOf(a, &.{
            .{ .name = "A", .wp = 0.7, .wb = 0.5, .rp = 0.10, .rb = missing },
            .{ .name = "B", .wp = 0.3, .wb = 0.5, .rp = 0.05, .rb = 0.02 },
        });
        try testing.expect(std.math.isNan(c.rows[1][1].float));
        try testing.expect(std.math.isNan(c.rows[2][4].float));
    }
}

const twr_cols = [_]Column{
    .{ .name = "d", .type = .date },  .{ .name = "v", .type = .float },
    .{ .name = "f", .type = .float }, .{ .name = "pe", .type = .float },
};

/// `twrDaily` over one period: a seed row, then the period's end value, its net flow and
/// the Modified Dietz average capital.
fn dietz(a: std.mem.Allocator, start: f64, end: f64, flow: f64, base: f64) !Dataset {
    const rows = try a.dupe([]const Value, &.{
        try a.dupe(Value, &.{ .{ .text = "2024-01-01" }, .{ .float = start }, .{ .float = 0 }, .{ .float = start } }),
        try a.dupe(Value, &.{ .{ .text = "2024-01-31" }, .{ .float = end }, .{ .float = flow }, .{ .float = base } }),
    });
    return fs.twrDaily(a, .{ .columns = &twr_cols, .rows = rows }, .{
        .date_col = "d",
        .value_col = "v",
        .flow_col = "f",
        .pe_col = "pe",
    });
}

test "published: Modified Dietz worked examples" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Wikipedia: 100 to 300, +50 half way. Average capital 100 + 0.5*50 = 125, return 120 %.
    try testing.expectApproxEqAbs(@as(f64, 1.2), (try dietz(a, 100, 300, 50, 100 + 0.5 * 50)).rows[0][1].float, 1e-15);

    // Wikipedia: bought for 1 128 728, sold for 1 125 990, no flows. About -0.24 %.
    try testing.expectApproxEqAbs(@as(f64, -0.0024), (try dietz(a, 1128728, 1125990, 0, 1128728)).rows[0][1].float, 5e-5);

    // FinFacts: 1 000 000 to 1 080 000 over 30 days, flows +50 000 on day 4, -20 000 on day 14,
    // +10 000 on day 24, each weighted (30 - day) / 30. Published as 0.03866.
    const base = 1_000_000.0 + 50_000.0 * 26.0 / 30.0 - 20_000.0 * 16.0 / 30.0 + 10_000.0 * 6.0 / 30.0;
    try testing.expectApproxEqAbs(@as(f64, 0.03866), (try dietz(a, 1_000_000, 1_080_000, 40_000, base)).rows[0][1].float, 5e-6);

    // Wikipedia: average capital 1000 - 7/8*1200 = -50, for which the naive answer is
    // -900 %, a number the same article rejects. The module emits no return for it.
    try testing.expectEqual(@as(usize, 0), (try dietz(a, 1000, 250, -1200, 1000 - 7.0 / 8.0 * 1200)).rows.len);
}

test "oracle: riskMetrics calmar against ffn PerformanceStats" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cols = [_]Column{ .{ .name = "d", .type = .date }, .{ .name = "r", .type = .float } };
    for (calmar_ref.cases, 0..) |c, k| {
        errdefer std.debug.print("calmar case {d}\n", .{k});
        const rows = try a.alloc([]const Value, c.returns.len);
        for (rows, c.returns, calmar_ref.dates) |*r, v, d|
            r.* = try a.dupe(Value, &.{ .{ .text = d }, .{ .float = v } });
        const m = try fs.riskMetrics(a, .{ .columns = &cols, .rows = rows }, .{ .ret_col = "r", .date_col = "d" });
        var found = false;
        for (m.columns, 0..) |col, i| if (std.mem.eql(u8, col.name, "calmar")) {
            try testing.expectApproxEqRel(c.calmar, m.rows[0][i].float, 1e-11);
            found = true;
        };
        try testing.expect(found);
    }
}
