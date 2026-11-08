// SPDX-License-Identifier: MIT
//! The whole `finstats.slice` surface under hostile numbers and date text: nothing
//! may panic, hang or leak, and the facts that hold between functions must hold on
//! any finite series. `dayNumber` is compared with `civilOracle`, a days-from-civil
//! written independently below.
//!
//! `FINSTATS_FUZZ=<runs>[,<seed>]` runs the deterministic driver; 400 seeds run in
//! every test run, and they must get everywhere.

const std = @import("std");
const testing = std.testing;
const fs = @import("root.zig");
const sl = fs;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;

const nan = std.math.nan(f64);
const inf = std.math.inf(f64);

const Label = enum { finite_series, hostile_series, wipe_out, mismatch, sorted_dates, unsorted_dates, bad_date, real_date, episodes, calendar_total, pbo_ran };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

fn drawValue(comptime S: type, src: *S, hostile: bool) f64 {
    if (hostile) {
        return switch (src.valueRangeAtMost(u8, 0, 11)) {
            0 => nan,
            1 => inf,
            2 => -inf,
            3 => -1,
            4 => -1.5,
            5 => 0,
            6 => 1e308,
            7 => -1e308,
            8 => 5e-324,
            9 => 1e150,
            else => @as(f64, @floatFromInt(src.valueRangeAtMost(i32, -1000, 1000))) / 1000,
        };
    }
    return switch (src.valueRangeAtMost(u8, 0, 9)) {
        0 => 0, // exact zeros matter: exposure, win rate
        else => @as(f64, @floatFromInt(src.valueRangeAtMost(i32, -300, 300))) / 1000,
    };
}

fn near(a: f64, b: f64, tol: f64) !void {
    if (std.math.isNan(a) or std.math.isNan(b)) return error.UnexpectedNaN;
    if (@abs(a - b) > tol * @max(1.0, @max(@abs(a), @abs(b)))) return error.FactsDisagree;
}

fn inUnit(x: f64) !void {
    if (!(x >= 0 and x <= 1)) return error.NotAProbability;
}

/// Calls every number-returning function: the answer may be anything, but must come.
fn numbersOnly(xs: []const f64, b: []const f64, rf: f64, ppy: f64) void {
    const f = [_]f64{
        sl.sharpeRatio(xs, rf, ppy),                       sl.sortinoRatio(xs, rf, ppy),             sl.calmarRatio(xs, ppy),
        sl.totalReturn(xs),                                sl.cagrPeriods(xs, ppy),                  sl.geometricMean(xs),
        sl.maxDrawdown(xs),                                sl.gainToPain(xs),                        sl.recoveryFactor(xs),
        sl.stability(xs),                                  sl.bestReturn(xs),                        sl.worstReturn(xs),
        sl.avgWin(xs),                                     sl.avgLoss(xs),                           sl.volatility(xs, ppy),
        sl.downsideDeviation(xs, rf, ppy),                 sl.ulcerIndex(xs),                        sl.skewness(xs),
        sl.excessKurtosis(xs),                             sl.winRate(xs),                           sl.payoffRatio(xs),
        sl.profitFactor(xs),                               sl.kellyCriterion(xs),                    sl.omegaRatio(xs, rf),
        sl.avgReturn(xs),                                  sl.riskReturnRatio(xs),                   sl.ulcerPerformanceIndex(xs, rf),
        sl.cpcIndex(xs),                                   sl.profitRatio(xs),                       sl.winLossRatio(xs),
        sl.exposure(xs),                                   sl.rar(xs, rf, ppy),                      sl.autocorrPenalty(xs),
        sl.smartSharpe(xs, rf, ppy),                       sl.smartSortino(xs, rf, ppy),             sl.sortinoSqrt2(xs, rf, ppy),
        sl.smartSortinoSqrt2(xs, rf, ppy),                 sl.adjustedSortino(xs, rf, ppy),          sl.skewSample(xs),
        sl.kurtosisSample(xs),                             sl.probabilisticSharpeRatio(xs, rf, ppy), sl.probabilisticSortinoRatio(xs, rf, ppy),
        sl.probabilisticAdjustedSortinoRatio(xs, rf, ppy), sl.deflatedSharpeRatio(xs, b, rf, ppy),   sl.probMom(xs, b),
        sl.beta(xs, b),                                    sl.rSquared(xs, b),                       sl.pearson(xs, b),
        sl.informationRatio(xs, b),                        sl.treynorRatio(xs, b, rf),               sl.capture(xs, b, ppy),
        sl.jensenAlpha(xs, b, rf, ppy),                    sl.excessSharpe(xs, b),                   sl.hurstExponent(xs),
        sl.normalCdf(rf),                                  sl.riskOfRuin(rf, ppy),                   sl.expectedMaxSharpe(xs.len, rf),
        sl.deannualize(rf, ppy),                           sl.lambdaFromSpan(ppy),                   sl.evarGaussian(rf, ppy, 0.95),
    };
    std.mem.doNotOptimizeAway(f);
    std.mem.doNotOptimizeAway(sl.periodStats(xs, ppy, rf));
    std.mem.doNotOptimizeAway(sl.parametricRisk(xs, 0.95));
    std.mem.doNotOptimizeAway(sl.betaAlpha(xs, b, rf, ppy));
    std.mem.doNotOptimizeAway(sl.trackingRisk(xs, b, ppy));
    std.mem.doNotOptimizeAway(sl.greeks(xs, b, ppy));
    std.mem.doNotOptimizeAway(sl.alphaBeta(xs, b, rf, ppy));
    std.mem.doNotOptimizeAway(sl.upAlphaBeta(xs, b, rf, ppy));
    std.mem.doNotOptimizeAway(sl.downAlphaBeta(xs, b, rf, ppy));
    std.mem.doNotOptimizeAway(sl.battingAverage(xs, b));
}

fn meanFn(w: []const f64) f64 {
    return sl.avgReturn(w);
}

/// Calls every allocating function, and frees what it returns. A wrong length or a
/// cap may answer with an error; only an out-of-memory would be a surprise here.
fn allocating(gpa: std.mem.Allocator, xs: []const f64, b: []const f64, rf: f64, ppy: f64, window: usize, seed: u64) !void {
    const T = struct {
        fn free(g: std.mem.Allocator, r: anytype) void {
            if (r) |v| g.free(v) else |_| {}
        }
    };
    T.free(gpa, sl.histogram(gpa, xs, window));
    T.free(gpa, sl.cumulativeReturns(gpa, xs));
    T.free(gpa, sl.drawdownSeries(gpa, xs));
    T.free(gpa, sl.rollingMean(gpa, xs, window));
    T.free(gpa, sl.rollingVolatility(gpa, xs, window));
    T.free(gpa, sl.rollingSharpe(gpa, xs, window));
    T.free(gpa, sl.rollingSortino(gpa, xs, window, rf, ppy));
    T.free(gpa, sl.rollingSharpeRf(gpa, xs, window, rf, ppy));
    T.free(gpa, sl.rollingCagr(gpa, xs, window, ppy));
    T.free(gpa, sl.rollingMaxDrawdown(gpa, xs, window));
    T.free(gpa, sl.rollingWinRate(gpa, xs, window));
    T.free(gpa, sl.rollingBetaAlpha(gpa, xs, b, window, ppy));
    T.free(gpa, sl.rollingGreeks(gpa, xs, b, window));
    T.free(gpa, sl.rollAlphaBeta(gpa, xs, b, window, rf, ppy));
    T.free(gpa, sl.rollUpCapture(gpa, xs, b, window, ppy));
    T.free(gpa, sl.rollDownCapture(gpa, xs, b, window, ppy));
    T.free(gpa, sl.rollUpDownCapture(gpa, xs, b, window, ppy));
    T.free(gpa, sl.pctRank(gpa, xs, window));
    T.free(gpa, sl.outliers(gpa, xs, rf));
    T.free(gpa, sl.removeOutliers(gpa, xs, rf));
    T.free(gpa, sl.toReturns(gpa, xs));
    T.free(gpa, sl.toLogReturns(gpa, xs));
    T.free(gpa, sl.toPriceIndex(gpa, xs, rf));
    T.free(gpa, sl.rebase(gpa, xs, rf));
    T.free(gpa, sl.toExcessReturns(gpa, xs, rf, ppy));
    T.free(gpa, sl.winsorize(gpa, xs, rf, ppy));
    T.free(gpa, sl.rescale(gpa, xs, rf, ppy));
    T.free(gpa, sl.ewmaVolatility(gpa, xs, rf, ppy));
    T.free(gpa, sl.correlationMatrix(gpa, &.{ xs, b }, window));
    T.free(gpa, sl.resampleReturns(gpa, xs, meanFn, seed, window));
    _ = sl.quantile(gpa, xs, rf) catch {};
    _ = sl.tailRatio(gpa, xs) catch {};
    _ = sl.varHistoric(gpa, xs, rf) catch {};
    _ = sl.cvarHistoric(gpa, xs, rf) catch {};
    _ = sl.riskMetrics(gpa, xs, .{ .periods_per_year = ppy, .rf = rf, .span_days = ppy }) catch {};
    _ = sl.tradeStats(gpa, xs) catch {};
    _ = sl.benchmarkStats(gpa, xs, b, rf, rf, ppy) catch {};
    _ = sl.serenityIndex(gpa, xs, rf) catch {};
    _ = sl.commonSenseRatio(gpa, xs) catch {};
    _ = sl.outlierWinRatio(gpa, xs, rf) catch {};
    _ = sl.outlierLossRatio(gpa, xs, rf) catch {};
    _ = sl.upCapture(gpa, xs, b, ppy) catch {};
    _ = sl.downCapture(gpa, xs, b, ppy) catch {};
    _ = sl.upDownCapture(gpa, xs, b, ppy) catch {};
    _ = sl.betaFragilityHeuristic(gpa, xs, b) catch {};
    _ = sl.gpdRiskEstimates(gpa, xs, rf) catch {};
    _ = sl.conditionalDrawdownAtRisk(gpa, xs, rf) catch {};
    _ = sl.montecarlo(gpa, xs, window, seed, rf, ppy) catch {};
    _ = sl.montecarloCagr(gpa, xs, window, seed, ppy) catch {};
    _ = sl.montecarloDrawdown(gpa, xs, window, seed) catch {};
    _ = sl.montecarloSharpe(gpa, xs, window, seed, rf, ppy) catch {};
    if (sl.brinsonAttribution(gpa, xs, b, xs, b)) |r| gpa.free(r.rows) else |_| {}
    if (sl.monteCarlo(gpa, .{ .start = rf, .mu_ann = rf, .vol_ann = ppy, .monthly = rf, .years = ppy, .paths = @min(window, 4) })) |r| gpa.free(r) else |_| {}
    const shape: sl.Shape = .{ .periods = xs.len, .assets = 1, .factors = 1 };
    if (sl.perfAttrib(gpa, shape, xs, xs, xs, xs)) |r0| {
        var r = r0;
        r.deinit(gpa);
    } else |_| {}
    T.free(gpa, sl.computeExposures(gpa, shape, xs, b));
}

/// A date: mostly real, sometimes damaged at a place that matters.
fn drawDate(comptime S: type, src: *S, buf: *[16]u8) []const u8 {
    const y = src.valueRangeAtMost(u16, 1998, 2004);
    const m = src.valueRangeAtMost(u8, 1, 12);
    const d = src.valueRangeAtMost(u8, 1, 28);
    const s = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ y, m, d }) catch unreachable; // fits 16
    if (src.valueRangeAtMost(u8, 0, 40) == 0) {
        buf[src.valueRangeAtMost(u8, 0, 9)] = src.value(u8);
    }
    return s;
}

/// Days since 1970-01-01 of exactly `YYYY-MM-DD` (ten bytes, digits and two dashes, a
/// real calendar day, year 0000 to 9999), or null. Howard Hinnant's days-from-civil.
fn civilOracle(text: []const u8) ?i64 {
    if (text.len != 10 or text[4] != '-' or text[7] != '-') return null;
    var f: [3]i64 = undefined;
    const spans = [_][2]usize{ .{ 0, 4 }, .{ 5, 7 }, .{ 8, 10 } };
    for (spans, &f) |sp, *out| {
        var v: i64 = 0;
        for (text[sp[0]..sp[1]]) |c| {
            if (c < '0' or c > '9') return null;
            v = v * 10 + (c - '0');
        }
        out.* = v;
    }
    const y = f[0];
    const m = f[1];
    const d = f[2];
    if (m < 1 or m > 12 or d < 1) return null;
    const leap = (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
    const dim = [_]i64{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (d > dim[@intCast(m - 1)]) return null;
    const yy = if (m <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp = @mod(m + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) !void {
    // Date text first, byte-first for the Smith source: see check-fuzz-reach.
    var raw: [24]u8 = undefined;
    src.bytes(&raw);
    var text: []const u8 = raw[0 .. @as(usize, raw[23]) % 24];
    // Random bytes are almost never a date: most inputs are date-shaped, with a month
    // and day that may not exist and a year that may be anything.
    if (raw[22] % 4 != 0) {
        const y = src.valueRangeAtMost(u16, 0, 9999);
        const m = src.valueRangeAtMost(u8, 0, 13);
        const d = src.valueRangeAtMost(u8, 0, 32);
        text = std.fmt.bufPrint(&raw, "{d:0>4}-{d:0>2}-{d:0>2}", .{ y, m, d }) catch unreachable; // fits 24
    }
    const ours = sl.dayNumber(text) catch null;
    if (text.len == 10) {
        const theirs = civilOracle(text);
        if ((ours == null) != (theirs == null)) return error.DateVerdictDiffers;
        if (ours) |o| {
            if (o != theirs.?) return error.DayNumberDiffers;
            mark(.real_date);
        } else mark(.bad_date);
    }

    const hostile = src.valueRangeAtMost(u8, 0, 2) == 0;
    const n = @as(usize, src.valueRangeAtMost(u32, 0, 48));
    const xs = try gpa.alloc(f64, n);
    defer gpa.free(xs);
    const b = try gpa.alloc(f64, n);
    defer gpa.free(b);
    var wipe = false;
    for (xs, b) |*x, *y| {
        x.* = drawValue(S, src, hostile);
        y.* = drawValue(S, src, hostile);
        wipe = wipe or x.* <= -1;
    }
    if (hostile) mark(.hostile_series) else mark(.finite_series);
    if (wipe) mark(.wipe_out);
    const rf: f64 = switch (src.valueRangeAtMost(u8, 0, 6)) {
        0 => nan,
        1 => -2,
        2 => 2,
        else => @as(f64, @floatFromInt(src.valueRangeAtMost(i32, 0, 100))) / 1000,
    };
    const ppy: f64 = switch (src.valueRangeAtMost(u8, 0, 6)) {
        0 => nan,
        1 => 0,
        2 => -1,
        else => 252,
    };
    const window = @as(usize, src.valueRangeAtMost(u32, 0, 52));
    const seed = src.value(u64);

    numbersOnly(xs, b, rf, ppy);
    try allocating(gpa, xs, b, rf, ppy, window, seed);
    if (n > 0 and src.valueRangeAtMost(u8, 0, 3) == 0) {
        mark(.mismatch);
        numbersOnly(xs, b[0 .. n - 1], rf, ppy);
        try allocating(gpa, xs, b[0 .. n - 1], rf, ppy, window, seed);
    }

    // Dates: mostly in order, and the calendar must add up.
    const buffers = try gpa.alloc([16]u8, n);
    defer gpa.free(buffers);
    const dates = try gpa.alloc([]const u8, n);
    defer gpa.free(dates);
    for (dates, buffers) |*d, *bf| d.* = drawDate(S, src, bf);
    const keep_sorted = src.valueRangeAtMost(u8, 0, 3) != 0;
    if (keep_sorted) std.mem.sort([]const u8, dates, {}, struct {
        fn lt(_: void, l: []const u8, r: []const u8) bool {
            return std.mem.order(u8, l, r) == .lt;
        }
    }.lt);
    var all_real = true;
    var in_order = true;
    var prev: i64 = std.math.minInt(i64);
    for (dates) |d| {
        const dn = sl.dayNumber(d) catch {
            all_real = false;
            continue;
        };
        if (dn < prev) in_order = false;
        prev = dn;
    }
    if (!all_real) {
        mark(.bad_date);
        if (sl.monthlyReturns(gpa, dates, xs)) |m| {
            gpa.free(m);
            return error.BadDateAccepted;
        } else |e| {
            // Dates are checked in order: going backwards may be seen before the bad one.
            if (e != error.BadDate and e != error.DatesNotSorted) return error.WrongDateError;
        }
    } else if (!in_order) {
        mark(.unsorted_dates);
        try testing.expectError(error.DatesNotSorted, sl.monthlyReturns(gpa, dates, xs));
    } else mark(.sorted_dates);
    for ([_]sl.Period{ .weekly, .monthly, .quarterly, .yearly }) |p| {
        if (sl.aggregateReturns(gpa, dates, xs, p)) |r| gpa.free(r) else |_| {}
        std.mem.doNotOptimizeAway(sl.bestPeriod(dates, xs, p));
    }
    std.mem.doNotOptimizeAway(sl.mtdReturn(dates, xs));
    std.mem.doNotOptimizeAway(sl.ytdReturn(dates, xs));
    std.mem.doNotOptimizeAway(sl.winQuarter(dates, xs));
    std.mem.doNotOptimizeAway(sl.gainToPainMonthly(dates, xs));
    std.mem.doNotOptimizeAway(sl.expectedYearlyReturn(dates, xs));
    if (sl.drawdownEpisodes(gpa, dates, xs, window)) |e| gpa.free(e) else |_| {}
    if (sl.xirr(gpa, dates, xs, b, .value_includes_flow, null)) |_| {} else |_| {}
    if (sl.xirrPrecise(gpa, dates, xs, b, .value_excludes_flow, .{})) |_| {} else |_| {}
    if (n >= 2) std.mem.doNotOptimizeAway(sl.yearFrac(dates[0], dates[n - 1]) catch 0);

    // PBO over a little search; its caps must hold whatever the blocks.
    const blocks = @as(usize, src.valueRangeAtMost(u32, 0, 12));
    if (sl.probBacktestOverfittingDetail(gpa, &.{ xs, b, xs }, blocks, sl.sharpePerPeriod)) |d| {
        defer d.deinit(gpa);
        if (d.logits.len > 0) mark(.pbo_ran);
        if (!std.math.isNan(d.pbo)) try inUnit(d.pbo);
    } else |_| {}

    if (hostile) return;

    // Facts between functions, on a series where every one is defined.
    try inUnit(sl.winRate(xs));
    try inUnit(sl.exposure(xs));
    try inUnit(sl.normalCdf(sl.sharpeRatio(xs, 0.01, 252)));
    if (n >= 2) {
        // NaN is the documented answer when the variance term goes negative (a short,
        // very skewed series).
        const psr = sl.probabilisticSharpeRatio(xs, 0.01, 252);
        if (!std.math.isNan(psr)) try inUnit(psr);
    }
    if (n >= 1) {
        const dd = try sl.drawdownSeries(gpa, xs);
        defer gpa.free(dd);
        try near(sl.maxDrawdown(xs), std.mem.min(f64, dd), 1e-12);
        const cum = try sl.cumulativeReturns(gpa, xs);
        defer gpa.free(cum);
        try near(sl.totalReturn(xs), cum[n - 1], 1e-12);
        // the price round trip
        const px = try sl.toPriceIndex(gpa, xs, 100);
        defer gpa.free(px);
        const back = try sl.toReturns(gpa, px);
        defer gpa.free(back);
        for (back, xs) |g, e| try near(e, g, 1e-9);
        const u = sl.ulcerIndex(xs);
        if (!(u >= 0 and u <= 1)) return error.UlcerOutOfRange;
        try near(u * 100, (try sl.riskMetrics(gpa, xs, .{})).ulcer, 1e-12);
    }
    if (all_real and in_order and n >= 1) {
        // compounding by period is compounding: every grouping keeps the total
        mark(.calendar_total);
        for ([_]sl.Period{ .weekly, .monthly, .quarterly, .yearly }) |p| {
            const per = try sl.aggregateReturns(gpa, dates, xs, p);
            defer gpa.free(per);
            var level: f64 = 1;
            for (per) |q| level *= 1 + q.value;
            try near(sl.totalReturn(xs), level - 1, 1e-10);
        }
        // the deepest episode of a price path is its maximum drawdown
        const px = try sl.toPriceIndex(gpa, xs, 100);
        defer gpa.free(px);
        const ep_dates = try gpa.alloc([]const u8, n + 1);
        defer gpa.free(ep_dates);
        ep_dates[0] = dates[0];
        @memcpy(ep_dates[1..], dates);
        const eps = try sl.drawdownEpisodes(gpa, ep_dates, px, 1);
        defer gpa.free(eps);
        if (eps.len > 0) {
            mark(.episodes);
            try near(sl.maxDrawdown(xs), eps[0].depth, 1e-10);
        } else if (sl.maxDrawdown(xs) != 0) return error.EpisodeMissing;
    }
    // Brinson's identity with weights that sum to one
    if (n >= 1) {
        const w = 1.0 / @as(f64, @floatFromInt(n));
        const wp = try gpa.alloc(f64, n);
        defer gpa.free(wp);
        @memset(wp, w);
        const rr = try sl.brinsonAttribution(gpa, wp, wp, xs, b);
        defer gpa.free(rr.rows);
        var active: f64 = 0;
        for (xs, b) |x, y| active += w * (x - y);
        try near(active, rr.total.total, 1e-12);
    }
    // Attribution adds up, and tilt plus timing is common
    if (n >= 1) {
        const shape: sl.Shape = .{ .periods = n, .assets = 1, .factors = 1 };
        var at = try sl.perfAttrib(gpa, shape, xs, b, xs, b);
        defer at.deinit(gpa);
        for (at.common, at.specific, at.total, at.tilt, at.timing) |c, s, t, tl, tm| {
            try near(t, c + s, 1e-12);
            try near(c, tl + tm, 1e-12);
        }
    }
}

test "fuzz driver: FINSTATS_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "FINSTATS_FUZZ", .name = "finstats-slice" });
}

test "fuzz: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("finstats seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

fn fuzzOne(_: void, smith: *testing.Smith) !void {
    // Byte-first: the seed's bytes are the input, see check-fuzz-reach.
    var buf: [4096]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var src: testkit.fuzz.ScriptSource = .init(buf[0..len]);
    try harness(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: the slice surface never panics" {
    try testing.fuzz({}, fuzzOne, .{});
}
