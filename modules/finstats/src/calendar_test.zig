// SPDX-License-Identifier: MIT

//! Tests for `calendar.zig`: calendar aggregation, converters, named rolling
//! functions, resampling Monte Carlo, empyrical extras and tail measures.
//!
//! External anchor: `testdata/calendar_vectors.zig`, made by
//! `tools/calendar_oracle.py` from empyrical-reloaded, ffn, quantstats, scipy
//! and pandas over three seeded calendar-day series (a leap February, two year
//! ends), replayed at 1e-11 relative unless a comment gives a measured reason.
//! The Monte Carlo functions cannot be replayed (our PRNG is not numpy's), so
//! their tests pin distribution facts. Hand values pin what no library
//! answers: ISO weeks over a year end, tie rules, the empty and degenerate
//! answers, the tail measures defined by formula.

const std = @import("std");
const testing = std.testing;
const cal = @import("calendar.zig");
const slice = @import("slice.zig");
const v = @import("testdata/calendar_vectors.zig");

const nan = std.math.nan(f64);

fn near(want: f64, got: f64, rel: f64) !void {
    if (@abs(want - got) <= 1e-14 + rel * @abs(want)) return;
    std.debug.print("want {d}, got {d} (diff {e})\n", .{ want, got, want - got });
    return error.TestUnexpectedResult;
}

fn nearAll(want: []const f64, got: []const f64, rel: f64) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got, 0..) |w, g, i| {
        if (@abs(w - g) <= 1e-14 + rel * @abs(w)) continue;
        std.debug.print("index {d}: want {d}, got {d}\n", .{ i, w, g });
        return error.TestUnexpectedResult;
    }
}

fn expectPeriods(want: []const v.Per, got: []const cal.PeriodReturn) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| {
        try testing.expectEqual(w.year, g.year);
        try testing.expectEqual(w.period, g.period);
        try near(w.value, g.value, 1e-11);
    }
}

const dates: []const []const u8 = &v.dates;

// ── calendar aggregation ────────────────────────────────────────────────────

test "aggregation matches empyrical, quantstats (monthly, quarterly, yearly, weekly)" {
    const a = testing.allocator;
    for (v.cals) |c| {
        inline for (.{ .{ cal.Period.monthly, "monthly" }, .{ cal.Period.quarterly, "quarterly" }, .{ cal.Period.yearly, "yearly" } }) |pc| {
            const got = try cal.aggregateReturns(a, dates, c.rets, pc[0]);
            defer a.free(got);
            try expectPeriods(@field(c, pc[1]), got);
        }
        // empyrical's weekly keys are wrong over a year end, so compare on a span without one
        const w = try cal.aggregateReturns(a, dates[c.weekly_lo..c.weekly_hi], c.rets[c.weekly_lo..c.weekly_hi], .weekly);
        defer a.free(w);
        try expectPeriods(c.weekly, w);

        const m = try cal.monthlyReturns(a, dates, c.rets);
        defer a.free(m);
        try expectPeriods(c.monthly, m);
        const y = try cal.yearlyReturns(a, dates, c.rets);
        defer a.free(y);
        try expectPeriods(c.yearly, y);

        try near(c.best_m, cal.bestPeriod(dates, c.rets, .monthly), 1e-11);
        try near(c.worst_m, cal.worstPeriod(dates, c.rets, .monthly), 1e-11);
        try near(c.best_y, cal.bestPeriod(dates, c.rets, .yearly), 1e-11);
        try near(c.avg_up_m, cal.avgUpMonth(dates, c.rets), 1e-11);
        try near(c.avg_down_m, cal.avgDownMonth(dates, c.rets), 1e-11);
        try near(c.exp_m, cal.expectedMonthlyReturn(dates, c.rets), 1e-11);
        try near(c.exp_y, cal.expectedYearlyReturn(dates, c.rets), 1e-11);
        try near(c.gtp_m, cal.gainToPainMonthly(dates, c.rets), 1e-11);
        try near(c.win_q, cal.winQuarter(dates, c.rets), 1e-11);
        try near(c.mtd, cal.mtdReturn(dates, c.rets), 1e-11);
        try near(c.ytd, cal.ytdReturn(dates, c.rets), 1e-11);
    }
}

test "ISO weeks over a year end, leap day, hand values" {
    const a = testing.allocator;
    // 2019-12-30 Mon and 2020-01-02 Thu are ISO 2020-W01; 2020-12-31 Thu and
    // 2021-01-01 Fri are 2020-W53; 2021-01-04 Mon is 2021-W01.
    const d = [_][]const u8{ "2019-12-30", "2020-01-02", "2020-12-31", "2021-01-01", "2021-01-04" };
    const r = [_]f64{ 0.01, 0.02, 0.03, 0.04, 0.05 };
    const w = try cal.aggregateReturns(a, &d, &r, .weekly);
    defer a.free(w);
    try testing.expectEqual(@as(usize, 3), w.len);
    try testing.expectEqual(@as(i32, 2020), w[0].year);
    try testing.expectEqual(@as(u8, 1), w[0].period);
    try near(1.01 * 1.02 - 1, w[0].value, 1e-14);
    try testing.expectEqual(@as(i32, 2020), w[1].year);
    try testing.expectEqual(@as(u8, 53), w[1].period);
    try near(1.03 * 1.04 - 1, w[1].value, 1e-14);
    try testing.expectEqual(@as(i32, 2021), w[2].year);
    try testing.expectEqual(@as(u8, 1), w[2].period);

    // the leap day belongs to February; a time part after the date is ignored
    const d2 = [_][]const u8{ "2020-02-28", "2020-02-29T10:00:00", "2020-03-01" };
    const m = try cal.monthlyReturns(a, &d2, &.{ 0.1, 0.1, 0.5 });
    defer a.free(m);
    try testing.expectEqual(@as(usize, 2), m.len);
    try near(1.21 - 1, m[0].value, 1e-14);
    try testing.expectEqual(@as(u8, 2), m[0].period);
    try testing.expectEqual(@as(u8, 3), m[1].period);

    const q = try cal.aggregateReturns(a, &d2, &.{ 0.1, 0.1, 0.5 }, .quarterly);
    defer a.free(q);
    try testing.expectEqual(@as(usize, 1), q.len);
    try testing.expectEqual(@as(u8, 1), q[0].period);

    // mtd / ytd / quarters / months by hand
    const d3 = [_][]const u8{ "2020-01-31", "2020-02-03", "2020-02-04" };
    const r3 = [_]f64{ 0.1, 0.01, 0.02 };
    try near(1.01 * 1.02 - 1, cal.mtdReturn(&d3, &r3), 1e-14);
    try near(1.1 * 1.01 * 1.02 - 1, cal.ytdReturn(&d3, &r3), 1e-14);
    const d4 = [_][]const u8{ "2020-02-01", "2020-05-01", "2020-08-01", "2020-08-02" };
    try near(2.0 / 3.0, cal.winQuarter(&d4, &.{ 0.1, -0.1, 0.1, 0.0 }), 1e-14);
    const d5 = [_][]const u8{ "2020-01-10", "2020-01-20", "2020-02-10", "2020-03-10" };
    const r5 = [_]f64{ 0.01, 0.02, -0.01, 0.03 };
    try near(1.01 * 1.02 - 1, cal.bestPeriod(&d5, &r5, .monthly), 1e-14);
    try near(-0.01, cal.worstPeriod(&d5, &r5, .monthly), 1e-14);
    try near((0.0302 + 0.03) / 2.0, cal.avgUpMonth(&d5, &r5), 1e-14);
    try near(-0.01, cal.avgDownMonth(&d5, &r5), 1e-14);
    // sum-resolution gain to pain: months 0.03, -0.01, 0.03 -> 0.05 / 0.01
    try near(5.0, cal.gainToPainMonthly(&d5, &r5), 1e-12);
    try near(@exp((@log(1.0302) + @log(0.99) + @log(1.03)) / 3.0) - 1, cal.expectedMonthlyReturn(&d5, &r5), 1e-12);
}

test "aggregation errors, empty, non-finite" {
    const a = testing.allocator;
    try testing.expectError(error.LengthMismatch, cal.aggregateReturns(a, &.{"2020-01-01"}, &.{ 0.1, 0.2 }, .monthly));
    try testing.expectError(error.BadDate, cal.aggregateReturns(a, &.{ "2020-01-01", "2021-02-29" }, &.{ 0.1, 0.2 }, .monthly));
    try testing.expectError(error.BadDate, cal.aggregateReturns(a, &.{"20200101"}, &.{0.1}, .yearly));
    try testing.expectError(error.DatesNotSorted, cal.aggregateReturns(a, &.{ "2020-01-02", "2020-01-01" }, &.{ 0.1, 0.2 }, .weekly));
    // equal dates are allowed (several rows a day)
    const same = try cal.aggregateReturns(a, &.{ "2020-01-02", "2020-01-02" }, &.{ 0.1, 0.2 }, .yearly);
    defer a.free(same);
    try near(1.1 * 1.2 - 1, same[0].value, 1e-14);

    const none = try cal.aggregateReturns(a, &.{}, &.{}, .monthly);
    defer a.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
    const e: []const []const u8 = &.{};
    inline for (.{ cal.mtdReturn(e, &.{}), cal.ytdReturn(e, &.{}), cal.winQuarter(e, &.{}), cal.bestPeriod(e, &.{}, .weekly), cal.worstPeriod(e, &.{}, .yearly), cal.avgUpMonth(e, &.{}), cal.avgDownMonth(e, &.{}), cal.expectedMonthlyReturn(e, &.{}), cal.expectedYearlyReturn(e, &.{}), cal.gainToPainMonthly(e, &.{}) }) |x| try testing.expectEqual(@as(f64, 0), x);

    // bare numbers: NaN for bad input
    const d = [_][]const u8{ "2020-01-01", "2020-02-01" };
    try testing.expect(std.math.isNan(cal.mtdReturn(&d, &.{0.1})));
    try testing.expect(std.math.isNan(cal.ytdReturn(&.{ "2020-02-01", "2020-01-01" }, &.{ 0.1, 0.1 })));
    try testing.expect(std.math.isNan(cal.winQuarter(&.{"nope"}, &.{0.1})));
    try testing.expect(std.math.isNan(cal.bestPeriod(&d, &.{ 0.1, nan }, .monthly)));
    try testing.expect(std.math.isNan(cal.avgUpMonth(&d, &.{ 0.1, std.math.inf(f64) })));
    try testing.expect(std.math.isNan(cal.expectedYearlyReturn(&d, &.{ 0.1, -1.5 })));
    try testing.expect(std.math.isNan(cal.gainToPainMonthly(&d, &.{ nan, 0.1 })));
    // no losing month: +inf; nothing at all positive: 0; a wiped-out month: -1
    try testing.expect(std.math.isInf(cal.gainToPainMonthly(&d, &.{ 0.1, 0.1 })));
    try testing.expectEqual(@as(f64, 0), cal.gainToPainMonthly(&d, &.{ 0.0, 0.0 }));
    try testing.expectEqual(@as(f64, -1), cal.expectedMonthlyReturn(&d, &.{ -1.0, 0.1 }));
    try testing.expectEqual(@as(f64, 0), cal.avgDownMonth(&d, &.{ 0.1, 0.2 }));
}

// ── converters ──────────────────────────────────────────────────────────────

test "converters match empyrical, ffn, scipy" {
    const a = testing.allocator;
    for (v.cals) |c| {
        const simple = try cal.toReturns(a, c.prices);
        defer a.free(simple);
        try testing.expectEqual(c.prices.len - 1, simple.len);
        try nearAll(c.simple, simple, 1e-11);
        const lg = try cal.toLogReturns(a, c.prices);
        defer a.free(lg);
        try nearAll(c.log, lg, 1e-11);
        const idx = try cal.toPriceIndex(a, c.rets, 100);
        defer a.free(idx);
        try testing.expectEqual(c.rets.len + 1, idx.len);
        try nearAll(c.index100, idx, 1e-11);
        const rb = try cal.rebase(a, c.prices, 50);
        defer a.free(rb);
        try nearAll(c.rebase50, rb, 1e-11);
        const geo = try cal.toExcessReturns(a, c.rets, v.rf, v.ppy);
        defer a.free(geo);
        try nearAll(c.excess_geo, geo, 1e-11);
        const ari = try cal.toExcessReturns(a, c.rets, 0.0001, null);
        defer a.free(ari);
        try nearAll(c.excess_arith, ari, 1e-11);
        const w = try cal.winsorize(a, c.rets, 0.05, 0.05);
        defer a.free(w);
        try nearAll(c.wins, w, 1e-11);
        const wa = try cal.winsorize(a, c.rets, 0.1, 0.02);
        defer a.free(wa);
        try nearAll(c.wins_asym, wa, 1e-11);
        const rs = try cal.rescale(a, c.rets, -1, 3);
        defer a.free(rs);
        try nearAll(c.rescaled, rs, 1e-11);
        // the Into forms agree and check their length
        const buf = try a.alloc(f64, c.prices.len - 1);
        defer a.free(buf);
        try cal.toReturnsInto(buf, c.prices);
        try nearAll(c.simple, buf, 1e-11);
        try testing.expectError(error.LengthMismatch, cal.toReturnsInto(buf[1..], c.prices));
    }
    try near(0.00019363050654397362, cal.deannualize(0.05, 252), 1e-12); // ffn deannualize
}

test "converter edges: lengths, bad prices, constant series" {
    const a = testing.allocator;
    const none = try cal.toReturns(a, &.{});
    defer a.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
    const one = try cal.toLogReturns(a, &.{5.0});
    defer a.free(one);
    try testing.expectEqual(@as(usize, 0), one.len);
    // a price at or below 0, on either side of a return, gives NaN there only
    const r = try cal.toReturns(a, &.{ 100, 101, 0, 50, -2, 110 });
    defer a.free(r);
    try near(0.01, r[0], 1e-14);
    for (r[1..]) |x| try testing.expect(std.math.isNan(x));
    const l = try cal.toLogReturns(a, &.{ 100, 101, 0, 50 });
    defer a.free(l);
    try near(@log(1.01), l[0], 1e-14);
    try testing.expect(std.math.isNan(l[1]) and std.math.isNan(l[2]));
    const nf = try cal.toReturns(a, &.{ 1, nan, 2 });
    defer a.free(nf);
    try testing.expect(std.math.isNan(nf[0]) and std.math.isNan(nf[1]));
    // ffn: price index of [0.01, -0.02, 0.03] from 100
    const pi = try cal.toPriceIndex(a, &.{ 0.01, -0.02, 0.03 }, 100);
    defer a.free(pi);
    try nearAll(&.{ 100, 101, 98.98, 101.9494 }, pi, 1e-12);
    const pe = try cal.toPriceIndex(a, &.{}, 7);
    defer a.free(pe);
    try nearAll(&.{7}, pe, 0);
    const pn = try cal.toPriceIndex(a, &.{ 0.1, nan, 0.1 }, 1);
    defer a.free(pn);
    try testing.expect(std.math.isNan(pn[2]) and std.math.isNan(pn[3]) and !std.math.isNan(pn[1]));
    // rebase: first price at or below 0 poisons all
    const rb = try cal.rebase(a, &.{ 50, 60, 45 }, 100);
    defer a.free(rb);
    try nearAll(&.{ 100, 120, 90 }, rb, 1e-14);
    const rb0 = try cal.rebase(a, &.{ 0, 60 }, 100);
    defer a.free(rb0);
    for (rb0) |x| try testing.expect(std.math.isNan(x));
    // rescale: constant -> hi (ffn); winsorize: bad limits -> NaN
    const rc = try cal.rescale(a, &.{ 2, 2, 2 }, -1, 3);
    defer a.free(rc);
    try nearAll(&.{ 3, 3, 3 }, rc, 0);
    const rn = try cal.rescale(a, &.{ 1, nan }, 0, 1);
    defer a.free(rn);
    try testing.expect(std.math.isNan(rn[0]) and std.math.isNan(rn[1]));
    const wb = try cal.winsorize(a, &.{ 1, 2, 3 }, -0.1, 0.1);
    defer a.free(wb);
    try testing.expect(std.math.isNan(wb[0]));
    const wf = try cal.winsorize(a, &.{ 1, 2, 3 }, 1.0, 0.0);
    defer a.free(wf);
    try testing.expect(std.math.isNan(wf[1]));
    const ws = try cal.winsorize(a, &.{ 3, 1, 2, 9, 8, 7, 5, 4, 6, 100, -50, 0.5 }, 0.1, 0.1);
    defer a.free(ws);
    try nearAll(&.{ 3, 1, 2, 9, 8, 7, 5, 4, 6, 9, 0.5, 0.5 }, ws, 0); // scipy / ffn on the same input
    const we = try cal.winsorize(a, &.{}, 0.1, 0.1);
    defer a.free(we);
    try testing.expectEqual(@as(usize, 0), we.len);
    // deannualize / excess edges
    try testing.expectEqual(@as(f64, 0), cal.deannualize(0, 12));
    try testing.expectEqual(@as(f64, -1), cal.deannualize(-1, 12));
    try testing.expect(std.math.isNan(cal.deannualize(-1.5, 12)));
    try testing.expect(std.math.isNan(cal.deannualize(0.05, 0)));
    try testing.expect(std.math.isNan(cal.deannualize(nan, 12)));
    const ex = try cal.toExcessReturns(a, &.{ 0.01, 0.02 }, 0.05, 12);
    defer a.free(ex);
    try nearAll(&.{ 0.00592588, 0.01592588 }, ex, 1e-5); // ffn, 8 digits printed: 0.01 - (1.05^(1/12) - 1)
    const exn = try cal.toExcessReturns(a, &.{0.01}, 0.05, 0);
    defer a.free(exn);
    try testing.expect(std.math.isNan(exn[0]));
}

// ── rolling ─────────────────────────────────────────────────────────────────

test "named rolling functions match quantstats, empyrical" {
    const a = testing.allocator;
    for (v.cals) |c| {
        const n = c.rets.len - v.window + 1;
        const s = try cal.rollingSortino(a, c.rets, v.window, v.rf, v.ppy);
        defer a.free(s);
        try testing.expectEqual(n, s.len);
        try nearAll(c.r_sortino, s, 1e-11);
        const sh = try cal.rollingSharpeRf(a, c.rets, v.window, v.rf, v.ppy);
        defer a.free(sh);
        try nearAll(c.r_sharpe, sh, 1e-11);
        const cg = try cal.rollingCagr(a, c.rets, v.window, v.ppy);
        defer a.free(cg);
        try nearAll(c.r_cagr, cg, 1e-11);
        const dd = try cal.rollingMaxDrawdown(a, c.rets, v.window);
        defer a.free(dd);
        try nearAll(c.r_mdd, dd, 1e-11);
        const wr = try cal.rollingWinRate(a, c.rets, v.window);
        defer a.free(wr);
        try nearAll(c.r_win, wr, 1e-11);
        // empyrical's capture functions annualise with its daily default, 252
        const up = try cal.rollUpCapture(a, c.rets, c.bench, v.window, 252);
        defer a.free(up);
        try nearAll(c.r_up, up, 1e-11);
        const dn = try cal.rollDownCapture(a, c.rets, c.bench, v.window, 252);
        defer a.free(dn);
        try nearAll(c.r_down, dn, 1e-11);
    }
}

test "rolling edges" {
    const a = testing.allocator;
    const xs = [_]f64{ 0.01, -0.02, 0.03, 0.0 };
    inline for (.{ 0, 5 }) |w| {
        const s = try cal.rollingSortino(a, &xs, w, 0, 252);
        defer a.free(s);
        try testing.expectEqual(@as(usize, 0), s.len);
        const m = try cal.rollingMaxDrawdown(a, &xs, w);
        defer a.free(m);
        try testing.expectEqual(@as(usize, 0), m.len);
    }
    const wr = try cal.rollingWinRate(a, &xs, 2);
    defer a.free(wr);
    try nearAll(&.{ 0.5, 0.5, 1.0 }, wr, 0);
    const wz = try cal.rollingWinRate(a, &.{ 0.0, 0.0 }, 2);
    defer a.free(wz);
    try nearAll(&.{0}, wz, 0);
    // bad ppy / non-finite: NaN windows, same length
    const bad = try cal.rollingCagr(a, &xs, 2, 0);
    defer a.free(bad);
    try testing.expectEqual(@as(usize, 3), bad.len);
    for (bad) |x| try testing.expect(std.math.isNan(x));
    const cn = try cal.rollUpCapture(a, &.{ 0.1, nan }, &.{ 0.1, 0.1 }, 2, 252);
    defer a.free(cn);
    try testing.expect(std.math.isNan(cn[0]));
    try testing.expectError(error.LengthMismatch, cal.rollDownCapture(a, &xs, xs[1..], 2, 252));
    // cap: a window of half a long series is O(n^2)
    const big = try a.alloc(f64, 80_000);
    defer a.free(big);
    @memset(big, 0.001);
    try testing.expectError(error.TooLarge, cal.rollingSortino(a, big, 40_000, 0, 252));
    try testing.expectError(error.TooLarge, cal.rollUpCapture(a, big, big, 40_000, 252));
}

// ── resampling Monte Carlo ──────────────────────────────────────────────────

fn sampleReturns(a: std.mem.Allocator, n: usize, seed: u64) ![]f64 {
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    const xs = try a.alloc(f64, n);
    for (xs) |*x| x.* = 0.001 + (rnd.float(f64) - 0.5) * 0.04;
    return xs;
}

test "montecarlo: the total return is invariant, probabilities, seeded determinism" {
    const a = testing.allocator;
    const xs = try sampleReturns(a, 120, 7);
    defer a.free(xs);
    const total = slice.totalReturn(xs);
    const r = try cal.montecarlo(a, xs, 2000, 1, -0.1, total - 1e-9);
    // a permutation does not change a product: a point distribution
    try near(total, r.total.min, 1e-12);
    try near(total, r.total.max, 1e-12);
    try near(total, r.total.mean, 1e-12);
    try near(total, r.total.median, 1e-12);
    try testing.expect(r.total.std < 1e-12);
    try testing.expectEqual(@as(f64, 1), r.goal_probability.?);
    const r2 = try cal.montecarlo(a, xs, 500, 1, 0.0, total + 1e-6);
    try testing.expectEqual(@as(f64, 1), r2.bust_probability.?); // every drawdown is <= 0
    try testing.expectEqual(@as(f64, 0), r2.goal_probability.?);
    const r3 = try cal.montecarlo(a, xs, 500, 1, -1.0, null);
    try testing.expectEqual(@as(f64, 0), r3.bust_probability.?); // no path loses everything
    try testing.expect(r3.goal_probability == null);
    // a moderate bust level is reached by some paths and not by all
    const dd = try cal.montecarloDrawdown(a, xs, 2000, 3);
    const mid = try cal.montecarlo(a, xs, 2000, 3, dd.median, null);
    try testing.expect(mid.bust_probability.? > 0.3 and mid.bust_probability.? < 0.7);
    // same seed, same answer; another seed, another sample
    const again = try cal.montecarloDrawdown(a, xs, 2000, 3);
    try testing.expectEqual(dd, again);
    const other = try cal.montecarloDrawdown(a, xs, 2000, 4);
    try testing.expect(other.mean != dd.mean);
    // cagr is a point too, and equals slice.cagrPeriods
    const cg = try cal.montecarloCagr(a, xs, 300, 5, 252);
    try near(slice.cagrPeriods(xs, 252), cg.min, 1e-11);
    try near(slice.cagrPeriods(xs, 252), cg.max, 1e-11);
}

test "montecarloDrawdown: every path is a permutation of the input" {
    const a = testing.allocator;
    // [-0.1, -0.1, 0.5] has three orders; the drawdown is -0.19 for two of them
    // and -0.1 for [-0.1, 0.5, -0.1]. Only the input's own values can do that.
    const d = try cal.montecarloDrawdown(a, &.{ -0.1, -0.1, 0.5 }, 3000, 11);
    try near(-0.19, d.min, 1e-12);
    try near(-0.1, d.max, 1e-12);
    // the order of the elements is uniform: -0.19 two thirds of the time (1/3 -> mean -0.16)
    try testing.expect(@abs(d.mean - (-0.16)) < 0.01);
    // the two orders of a pair give the same drawdown, whatever the draw
    const p = try cal.montecarloDrawdown(a, &.{ 0.1, -0.2 }, 200, 2);
    try near(-0.2, p.min, 1e-12);
    try near(-0.2, p.max, 1e-12);
    // ordering of the summary
    const xs = try sampleReturns(a, 100, 21);
    defer a.free(xs);
    const s = try cal.montecarloDrawdown(a, xs, 3000, 9);
    try testing.expect(s.max <= 0 and s.min <= s.p5 and s.p5 <= s.p25 and s.p25 <= s.median and s.median <= s.p75 and s.p75 <= s.p95 and s.p95 <= s.max);
    try testing.expect(s.std > 0);
}

test "montecarlo percentiles agree between two large seeded runs" {
    const a = testing.allocator;
    const xs = try sampleReturns(a, 100, 33);
    defer a.free(xs);
    const x = try cal.montecarloDrawdown(a, xs, 8000, 101);
    const y = try cal.montecarloDrawdown(a, xs, 8000, 202);
    // standard error of a median or mean at this size is about 3e-4 for sd ~ 0.02
    try testing.expect(@abs(x.median - y.median) < 3e-3);
    try testing.expect(@abs(x.mean - y.mean) < 3e-3);
    try testing.expect(@abs(x.p5 - y.p5) < 6e-3);
    try testing.expect(@abs(x.p95 - y.p95) < 6e-3);
    try testing.expect(@abs(x.std - y.std) < 3e-3);
}

test "montecarloSharpe: bootstrap, centred on the sample Sharpe" {
    const a = testing.allocator;
    const xs = try sampleReturns(a, 120, 44);
    defer a.free(xs);
    const sample = slice.sharpeRatio(xs, 0, 252);
    const d = try cal.montecarloSharpe(a, xs, 4000, 8, 0, 252);
    // the bootstrap sd of an annualised Sharpe on 120 days is about 1.5
    try testing.expect(@abs(d.mean - sample) < 0.25);
    try testing.expect(d.std > 0.5 and d.std < 3.0);
    try testing.expect(d.min < sample and d.max > sample);
    const rf = try cal.montecarloSharpe(a, xs, 4000, 8, 0.05, 252);
    try testing.expect(rf.mean < d.mean); // same draws, a higher hurdle
    // a constant series has no spread: Sharpe 0 for every path
    const c = try cal.montecarloSharpe(a, &.{ 0.01, 0.01, 0.01 }, 50, 1, 0, 252);
    try testing.expectEqual(@as(f64, 0), c.max);
    try testing.expectEqual(@as(f64, 0), c.min);
}

test "montecarlo caps, empty and non-finite inputs" {
    const a = testing.allocator;
    const xs = try sampleReturns(a, 100, 1);
    defer a.free(xs);
    try testing.expectError(error.TooLarge, cal.montecarlo(a, xs, cal.max_resample_sims + 1, 1, null, null));
    try testing.expectError(error.TooLarge, cal.montecarloDrawdown(a, xs, cal.max_resample_sims, 1));
    try testing.expectError(error.TooLarge, cal.montecarloCagr(a, xs, cal.max_resample_sims, 1, 252));
    try testing.expectError(error.TooLarge, cal.montecarloSharpe(a, xs, cal.max_resample_sims, 1, 0, 252));
    try testing.expectError(error.TooLarge, cal.montecarlo(a, xs, std.math.maxInt(usize), 1, null, null));
    const e = try cal.montecarlo(a, &.{}, 100, 1, 0.1, null);
    try testing.expectEqual(@as(f64, 0), e.total.mean);
    try testing.expect(e.bust_probability == null);
    const z = try cal.montecarloDrawdown(a, xs, 0, 1);
    try testing.expectEqual(@as(f64, 0), z.max);
    const bad = try cal.montecarlo(a, &.{ 0.1, nan }, 10, 1, 0.1, 0.1);
    try testing.expect(std.math.isNan(bad.total.mean) and std.math.isNan(bad.bust_probability.?));
    const bp = try cal.montecarloCagr(a, xs, 10, 1, 0);
    try testing.expect(std.math.isNan(bp.mean));
    const bs = try cal.montecarloSharpe(a, xs, 10, 1, nan, 252);
    try testing.expect(std.math.isNan(bs.mean));
    const one = try cal.montecarloDrawdown(a, &.{-0.5}, 5, 1);
    try near(-0.5, one.mean, 1e-14);
    try testing.expectEqual(@as(f64, 0), one.std);
}

// ── empyrical extras ────────────────────────────────────────────────────────

test "alpha, up / down alpha and beta, excess Sharpe, batting average match empyrical" {
    for (v.cals) |c| {
        const ab = cal.alphaBeta(c.rets, c.bench, v.rf, v.ppy);
        try near(c.alpha, ab.alpha, 1e-11);
        try near(c.beta, ab.beta, 1e-11);
        try near(c.alpha, cal.jensenAlpha(c.rets, c.bench, v.rf, v.ppy), 1e-11);
        const up = cal.upAlphaBeta(c.rets, c.bench, v.rf, v.ppy);
        try near(c.up_alpha, up.alpha, 1e-11);
        try near(c.up_beta, up.beta, 1e-11);
        const dn = cal.downAlphaBeta(c.rets, c.bench, v.rf, v.ppy);
        try near(c.down_alpha, dn.alpha, 1e-11);
        try near(c.down_beta, dn.beta, 1e-11);
        try near(c.excess_sharpe, cal.excessSharpe(c.rets, c.bench), 1e-11);
        const b = cal.battingAverage(c.rets, c.bench);
        try near(c.bat_all, b.all, 1e-11);
        try near(c.bat_up, b.up, 1e-11);
        try near(c.bat_down, b.down, 1e-11);
    }
}

test "alpha edges" {
    const p = [_]f64{ 0.01, -0.02, 0.03, 0.005 };
    // a series against itself: beta 1, alpha 0, at any rf
    const s = cal.alphaBeta(&p, &p, 0.04, 252);
    try near(1.0, s.beta, 1e-12);
    try testing.expect(@abs(s.alpha) < 1e-12);
    // a flat benchmark: beta 0, alpha is the compounded mean excess
    const f = cal.alphaBeta(&p, &.{ 0.0, 0.0, 0.0, 0.0 }, 0, 4);
    try testing.expectEqual(@as(f64, 0), f.beta);
    try near(std.math.pow(f64, 1 + 0.00625, 4) - 1, f.alpha, 1e-12);
    // up side with no up period, mismatch, non-finite, bad ppy, bad rf: NaN
    try testing.expect(std.math.isNan(cal.upAlphaBeta(&p, &.{ -0.1, -0.1, 0, 0 }, 0, 252).alpha));
    try testing.expect(std.math.isNan(cal.jensenAlpha(&p, p[1..], 0, 252)));
    try testing.expect(std.math.isNan(cal.jensenAlpha(&.{ 0.1, nan }, &.{ 0.1, 0.1 }, 0, 252)));
    try testing.expect(std.math.isNan(cal.jensenAlpha(&p, &p, 0, 0)));
    try testing.expect(std.math.isNan(cal.jensenAlpha(&p, &p, -1, 252)));
    try testing.expect(std.math.isNan(cal.downAlphaBeta(&.{0.1}, &.{-0.1}, 0, 252).beta)); // one period
    // excess Sharpe and batting
    try testing.expectEqual(@as(f64, 0), cal.excessSharpe(&.{ 0.1, 0.1 }, &.{ 0.0, 0.0 }));
    try testing.expectEqual(@as(f64, 0), cal.excessSharpe(&.{0.1}, &.{0.0}));
    try testing.expect(std.math.isNan(cal.excessSharpe(&.{ 0.1, 0.2 }, &.{0.1})));
    const bt = cal.battingAverage(&.{ 0.1, 0.0, -0.1, 0.2 }, &.{ 0.0, 0.0, -0.2, 0.3 });
    // up market (b >= 0): rows 0, 1, 3 -> wins at row 0 only; down market: row 2 wins
    try near(0.5, bt.all, 1e-14);
    try near(1.0 / 3.0, bt.up, 1e-14);
    try near(1.0, bt.down, 1e-14);
    const bz = cal.battingAverage(&.{}, &.{});
    try testing.expectEqual(@as(f64, 0), bz.all);
    try testing.expect(std.math.isNan(cal.battingAverage(&.{nan}, &.{0.0}).up));
}

test "beta fragility heuristic matches empyrical (the middle index rounds half to even)" {
    const a = testing.allocator;
    for (v.frags) |fr| {
        const h = try cal.betaFragilityHeuristic(a, fr.p, fr.b);
        try near(fr.h, h, 1e-11);
    }
    try testing.expectEqual(@as(f64, 0), try cal.betaFragilityHeuristic(a, &.{ 1, 2 }, &.{ 1, 2 }));
    try testing.expectEqual(@as(f64, 0), try cal.betaFragilityHeuristic(a, &.{ 1, 2, 3 }, &.{ 1, 1, 1 }));
    try testing.expect(std.math.isNan(try cal.betaFragilityHeuristic(a, &.{ 1, 2, 3 }, &.{ 1, nan, 1 })));
    try testing.expect(std.math.isNan(try cal.betaFragilityHeuristic(a, &.{ 1, 2, 3 }, &.{ 1, 2 })));
    // a straight line has no convexity
    try near(0, try cal.betaFragilityHeuristic(a, &.{ 0.0, 0.1, 0.2, 0.3, 0.4 }, &.{ 0.0, 0.1, 0.2, 0.3, 0.4 }), 0);
    // five points, middle (f, r) = (2, 1), ends (0, 0) and (8, 0): 0 - 1 = -1
    try near(-1.0, try cal.betaFragilityHeuristic(a, &.{ 0, 5, 1, 0, 0 }, &.{ 0, 1, 2, 3, 8 }), 1e-14);
    // three points: the middle index rounds 1.5 to 2, the highest, so the heuristic is 0
    try near(0.0, try cal.betaFragilityHeuristic(a, &.{ 0, 1, 0 }, &.{ 0, 1, 4 }), 1e-14);
}

test "GPD estimates: formulas exact, fit within the measured gap of empyrical's fmin" {
    const a = testing.allocator;
    var worst_scale: f64 = 0;
    var worst_shape: f64 = 0;
    var worst_var: f64 = 0;
    for (v.gpds) |g| {
        // VaR and ES from empyrical's own parameters: the formulas, exactly
        const ve = cal.gpdVarEs(g.threshold, g.scale, g.shape, g.n_losses, g.n_exceed, g.p);
        try near(g.var_, ve.var_estimate, 1e-8);
        try near(g.es, ve.es_estimate, 1e-8);
        const r = try cal.gpdRiskEstimates(a, g.xs, g.p);
        try testing.expectEqual(g.threshold, r.threshold);
        worst_scale = @max(worst_scale, @abs(r.scale - g.scale) / g.scale);
        worst_shape = @max(worst_shape, @abs(r.shape - g.shape));
        worst_var = @max(worst_var, @abs(r.var_estimate - g.var_) / g.var_);
        // Measured gap to empyrical's fmin (default tolerances) on these eight fits: scale 4.8e-3
        // relative, shape 2.3e-5 absolute (ours is the exact optimum, 0 on the shape >= 0 boundary),
        // VaR 6.7e-3, ES 2.6e-3 relative; the worst fits have one to seven exceedances.
        try near(g.scale, r.scale, 1e-2);
        try testing.expect(@abs(r.shape - g.shape) < 1e-4);
        try near(g.var_, r.var_estimate, 2e-2);
        try near(g.es, r.es_estimate, 2e-2);
    }
    try testing.expect(worst_scale < 1e-2 and worst_shape < 1e-4 and worst_var < 2e-2);
}

test "GPD edges: no loss, bad probability, non-finite, tiny losses, one loss" {
    const a = testing.allocator;
    const z = try cal.gpdRiskEstimates(a, &.{ 0.01, 0.02 }, 0.01);
    try testing.expectEqual(@as(f64, 0), z.var_estimate);
    try testing.expectEqual(@as(f64, 0), z.threshold);
    const e = try cal.gpdRiskEstimates(a, &.{}, 0.01);
    try testing.expectEqual(@as(f64, 0), e.es_estimate);
    for ([_]f64{ 0, 1, -0.1, 1.5, nan }) |p| {
        const r = try cal.gpdRiskEstimates(a, &.{ -0.01, 0.02 }, p);
        try testing.expect(std.math.isNan(r.var_estimate) and std.math.isNan(r.threshold));
    }
    const nf = try cal.gpdRiskEstimates(a, &.{ -0.01, nan }, 0.01);
    try testing.expect(std.math.isNan(nf.scale));
    // losses far below the smallest threshold: nothing to fit, zeros, and it returns
    const tiny = try cal.gpdRiskEstimates(a, &.{ -1e-12, -1e-13, 0.5 }, 0.01);
    try testing.expectEqual(@as(f64, 0), tiny.var_estimate);
    // one loss: the exponential fit through it (scale = the loss), no hang
    const one = try cal.gpdRiskEstimates(a, &.{ -0.1, 0.0, 0.0 }, 0.01);
    try testing.expectEqual(@as(f64, 0.1), one.threshold);
    try near(0.1, one.scale, 1e-12);
    try testing.expectEqual(@as(f64, 0), one.shape);
    // identical losses and a heavy tail both finish with finite numbers
    var big: [2000]f64 = undefined;
    for (&big, 0..) |*x, i| x.* = -0.05 * (1.0 + @as(f64, @floatFromInt(i % 7)) * 40.0 / @as(f64, @floatFromInt(1 + i % 3)));
    const hv = try cal.gpdRiskEstimates(a, &big, 0.01);
    try testing.expect(std.math.isFinite(hv.scale) and std.math.isFinite(hv.shape) and hv.shape >= 0);
    @memset(&big, -0.03);
    const same = try cal.gpdRiskEstimates(a, &big, 0.05);
    try near(0.03, same.scale, 1e-12);
    try testing.expectEqual(@as(f64, 0), same.shape);
}

// ── tail measures ───────────────────────────────────────────────────────────

test "conditional drawdown at risk by hand" {
    const a = testing.allocator;
    // levels .9, 1.08, .864, .864, .864 -> drawdowns -0.1, 0, -0.2, -0.2, -0.2
    const r = [_]f64{ -0.1, 0.2, -0.2, 0, 0 };
    try near(0.2, try cal.conditionalDrawdownAtRisk(a, &r, 0.5), 1e-12);
    // confidence 0.2: threshold = 0.8 quantile of the drawdowns = -0.08; tail = {-0.1, -0.2, -0.2, -0.2}
    try near(0.175, try cal.conditionalDrawdownAtRisk(a, &r, 0.2), 1e-12);
    // at confidence 0 the tail is everything: mean of all five
    try near((0.1 + 0.6) / 5.0, try cal.conditionalDrawdownAtRisk(a, &r, 0.0), 1e-12);
    try testing.expectEqual(@as(f64, 0), try cal.conditionalDrawdownAtRisk(a, &.{}, 0.95));
    try testing.expectEqual(@as(f64, 0), try cal.conditionalDrawdownAtRisk(a, &.{ 0.1, 0.2 }, 0.95)); // never underwater
    try testing.expect(std.math.isNan(try cal.conditionalDrawdownAtRisk(a, &r, 1.5)));
    try testing.expect(std.math.isNan(try cal.conditionalDrawdownAtRisk(a, &.{ 0.1, -2.0 }, 0.9)));
    try testing.expect(std.math.isNan(try cal.conditionalDrawdownAtRisk(a, &.{ 0.1, nan }, 0.9)));
    // the 95 % CDaR is at least the maximum drawdown's share of the tail: bounded by it
    for (v.cals) |c| {
        const cd = try cal.conditionalDrawdownAtRisk(a, c.rets, 0.95);
        try testing.expect(cd >= 0 and cd <= -slice.maxDrawdown(c.rets) + 1e-12);
        try near(-slice.maxDrawdown(c.rets), try cal.conditionalDrawdownAtRisk(a, c.rets, 1.0), 1e-12);
    }
}

test "EWMA volatility matches pandas, spans, hand values" {
    const a = testing.allocator;
    for (v.cals) |c| {
        const e = try cal.ewmaVolatility(a, c.rets, 0.94, 252);
        defer a.free(e);
        try nearAll(c.ewma, e, 1e-11);
    }
    const h = try cal.ewmaVolatility(a, &.{ 0.1, 0.0 }, 0.5, 1);
    defer a.free(h);
    try near(0.1, h[0], 1e-14);
    try near(@sqrt(0.005), h[1], 1e-14);
    try near(0.9, cal.lambdaFromSpan(19), 1e-15); // pandas ewm(span=19): alpha = 0.1
    try testing.expect(std.math.isNan(cal.lambdaFromSpan(0.5)));
    const bad = try cal.ewmaVolatility(a, &.{ 0.1, 0.2 }, 1.5, 252);
    defer a.free(bad);
    try testing.expect(std.math.isNan(bad[0]) and std.math.isNan(bad[1]));
    const bp = try cal.ewmaVolatility(a, &.{0.1}, 0.9, 0);
    defer a.free(bp);
    try testing.expect(std.math.isNan(bp[0]));
    const nf = try cal.ewmaVolatility(a, &.{ 0.1, nan }, 0.9, 252);
    defer a.free(nf);
    try testing.expect(std.math.isNan(nf[0]));
    const em = try cal.ewmaVolatility(a, &.{}, 0.9, 252);
    defer a.free(em);
    try testing.expectEqual(@as(usize, 0), em.len);
    // lambda 1 freezes the first value; lambda 0 follows each return
    const l1 = try cal.ewmaVolatility(a, &.{ 0.1, 0.3 }, 1, 1);
    defer a.free(l1);
    try near(0.1, l1[1], 1e-14);
    const l0 = try cal.ewmaVolatility(a, &.{ 0.1, -0.3 }, 0, 1);
    defer a.free(l0);
    try near(0.3, l0[1], 1e-14);
}

test "Hurst exponent: definition, hand values, vector" {
    for (v.cals) |c| try near(c.hurst, cal.hurstExponent(c.rets), 1e-9);
    // an alternating series: the running sum of the mean-adjusted values is 1, 0, 1, 0, ...
    // so R/S = 1 at every block size and the slope is 0
    var alt: [64]f64 = undefined;
    for (&alt, 0..) |*x, i| x.* = if (i % 2 == 0) 1 else -1;
    try near(0, cal.hurstExponent(&alt), 1e-12);
    // a steady trend has R/S growing like s (R about s^2/8, S about s/sqrt(12)): exponent near 1
    var ramp: [256]f64 = undefined;
    for (&ramp, 0..) |*x, i| x.* = @floatFromInt(i);
    const hr = cal.hurstExponent(&ramp);
    try testing.expect(hr > 0.9 and hr < 1.2);
    // under 16 values only one block size exists; a constant has no spread
    try testing.expectEqual(@as(f64, 0), cal.hurstExponent(alt[0..15]));
    try testing.expectEqual(@as(f64, 0), cal.hurstExponent(&.{}));
    var flat: [64]f64 = undefined;
    @memset(&flat, 0.01);
    try testing.expectEqual(@as(f64, 0), cal.hurstExponent(&flat));
    alt[5] = nan;
    try testing.expect(std.math.isNan(cal.hurstExponent(&alt)));
}

test "Gaussian EVaR: closed form, independent optimiser, bounds" {
    try near(2.4477468306808161, cal.evarGaussian(0, 1, 0.95), 1e-12);
    // scipy minimises the defining infimum for mean 0.0004, std 0.01, 95 %: optimiser tolerance
    try near(v.cals[0].evar, cal.evarGaussian(0.0004, 0.01, 0.95), 1e-8);
    try near(-0.0004 + 0.01 * 2.4477468306808161, cal.evarGaussian(0.0004, 0.01, 0.95), 1e-12);
    // at least the Gaussian VaR and CVaR of the same level
    try testing.expect(cal.evarGaussian(0.0004, 0.01, 0.99) >= slice.gaussianCVaR(0.0004, 0.01, 0.99));
    try testing.expect(cal.evarGaussian(0.0004, 0.01, 0.99) >= slice.gaussianVaR(0.0004, 0.01, 0.99));
    try testing.expectEqual(@as(f64, -0.5), cal.evarGaussian(0.5, 0, 0.9));
    try testing.expect(std.math.isNan(cal.evarGaussian(0, -1, 0.9)));
    try testing.expect(std.math.isNan(cal.evarGaussian(0, 1, 1)));
    try testing.expect(std.math.isNan(cal.evarGaussian(0, 1, 0)));
    try testing.expect(std.math.isNan(cal.evarGaussian(nan, 1, 0.9)));
}

// ── allocation failure ──────────────────────────────────────────────────────

fn aggregateCase(a: std.mem.Allocator) !void {
    const g = try cal.aggregateReturns(a, v.dates[0..120], v.cals[0].rets[0..120], .monthly);
    a.free(g);
}
fn convertCase(a: std.mem.Allocator) !void {
    const xs = v.cals[0].rets[0..50];
    const r = try cal.toReturns(a, v.cals[0].prices[0..50]);
    a.free(r);
    const l = try cal.toLogReturns(a, v.cals[0].prices[0..50]);
    a.free(l);
    const p = try cal.toPriceIndex(a, xs, 100);
    a.free(p);
    const b = try cal.rebase(a, xs, 100);
    a.free(b);
    const e = try cal.toExcessReturns(a, xs, 0.02, 252);
    a.free(e);
    const w = try cal.winsorize(a, xs, 0.1, 0.1);
    a.free(w);
    const s = try cal.rescale(a, xs, 0, 1);
    a.free(s);
    const ew = try cal.ewmaVolatility(a, xs, 0.94, 252);
    a.free(ew);
}
fn rollingCase(a: std.mem.Allocator) !void {
    const c = v.cals[0];
    const s = try cal.rollingSortino(a, c.rets[0..60], 20, 0.02, 252);
    a.free(s);
    const u = try cal.rollUpCapture(a, c.rets[0..60], c.bench[0..60], 20, 252);
    a.free(u);
    const w = try cal.rollingWinRate(a, c.rets[0..60], 20);
    a.free(w);
}
fn monteCarloCase(a: std.mem.Allocator) !void {
    const xs = v.cals[0].rets[0..30];
    _ = try cal.montecarlo(a, xs, 20, 1, -0.05, 0.0);
    _ = try cal.montecarloDrawdown(a, xs, 20, 1);
    _ = try cal.montecarloSharpe(a, xs, 20, 1, 0.01, 252);
}
fn tailCase(a: std.mem.Allocator) !void {
    const c = v.cals[0];
    _ = try cal.betaFragilityHeuristic(a, c.rets[0..40], c.bench[0..40]);
    _ = try cal.gpdRiskEstimates(a, v.gpds[0].xs[0..100], 0.05);
    _ = try cal.conditionalDrawdownAtRisk(a, c.rets[0..40], 0.9);
}

test "allocation failure is reported and nothing leaks" {
    try testing.checkAllAllocationFailures(testing.allocator, aggregateCase, .{});
    try testing.checkAllAllocationFailures(testing.allocator, convertCase, .{});
    try testing.checkAllAllocationFailures(testing.allocator, rollingCase, .{});
    try testing.checkAllAllocationFailures(testing.allocator, monteCarloCase, .{});
    try testing.checkAllAllocationFailures(testing.allocator, tailCase, .{});
}

test "gpdRiskEstimates refuses more fitting work than the stated cap" {
    // The cap is checked before any fit runs, so a series past it answers at once.
    const a = std.testing.allocator;
    const n = cal.max_gpd_work / 700 + 1;
    const xs = try a.alloc(f64, n); // about 24 MiB
    defer a.free(xs);
    @memset(xs, -0.5);
    try std.testing.expectError(error.TooLarge, cal.gpdRiskEstimates(a, xs, 0.01));
}
