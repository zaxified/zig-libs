// SPDX-License-Identifier: MIT
//! Calendar aggregation, series converters, named rolling functions, resampling
//! Monte Carlo, empyrical extras and tail-risk estimators: what a quantstats,
//! empyrical, ffn or FinanceToolkit user expects next to `finstats.slice`.
//!
//! Same rules as `slice.zig`. Dates are ISO text checked by `slice.dayNumber`
//! and must not go backwards (`error.DatesNotSorted`); a function that returns
//! an error set reports bad input through `slice.Error`, a bare-number
//! function answers NaN for it (NaN or infinity in a series, a `ppy` that is
//! not positive finite, series of different lengths). An empty series gives 0,
//! a zero denominator the answer `slice.zig`'s "period statistics" comment
//! gives. Nothing panics.
//!
//! Every convention below was measured by running the library it is named
//! after as a black box (`tools/calendar_oracle.py`); where two libraries
//! disagree, or one is plainly wrong, the function's comment says which was
//! followed.

const std = @import("std");
const datefmt = @import("datefmt");
const core = @import("core.zig");
const slice = @import("slice.zig");

pub const Error = slice.Error;

const nan = std.math.nan(f64);
const finiteAll = core.finiteAll;
const f64lt = core.f64lt;

/// Most simulated values (`sims` x series length) a resampling Monte Carlo
/// function will draw in one call: 2^25, about a second. Above it
/// `error.TooLarge`.
pub const max_resample_cells: usize = 1 << 25;

/// Most simulations one resampling call will hold: 2^20 (8 MiB of results).
/// Above it `error.TooLarge`.
pub const max_resample_sims: usize = 1 << 20;

/// Most elements `hurstExponent` will accept: its work is O(n log n) with no
/// allocation, so this only keeps a hostile length from running for minutes.
pub const max_hurst_len: usize = 1 << 26;

/// Most values `gpdRiskEstimates` will pass through its fits in one call, each fit
/// being `gpd_fit_passes` passes over the exceedances: 2^31, tens of seconds at
/// worst. A daily series of decades costs a few million. Above it `error.TooLarge`.
pub const max_gpd_work: usize = 1 << 31;

const gpd_fit_passes = 700;

fn badPpy(ppy: f64) bool {
    return !(ppy > 0) or !std.math.isFinite(ppy);
}

// ── civil calendar ──────────────────────────────────────────────────────────

const Civil = struct { y: i32, m: u8, d: u8 };

/// Year, month, day of a day number (days since 1970-01-01; Hinnant). Only
/// ever called with the number of a validated ISO date, years 0000 to 9999.
fn civilOf(dn: i64) Civil {
    const c = datefmt.epochDayToYmd(dn);
    return .{ .y = c.year, .m = @intCast(c.month), .d = @intCast(c.day) };
}

fn daysFromCivil(y: i32, m: u32, d: u32) i64 {
    return datefmt.ymdToEpochDay(y, m, d);
}

/// Which grouping `aggregateReturns` uses.
pub const Period = enum { weekly, monthly, quarterly, yearly };

/// One period of `aggregateReturns`: `year` and `period` are its key (the
/// calendar year and month 1..12 / quarter 1..4; the ISO year and ISO week
/// 1..53 for `.weekly`; `period` is 0 for `.yearly`), `value` the return.
pub const PeriodReturn = struct { year: i32, period: u8, value: f64 };

fn keyOf(dn: i64, p: Period) PeriodReturn {
    const c = civilOf(dn);
    switch (p) {
        .yearly => return .{ .year = c.y, .period = 0, .value = 0 },
        .quarterly => return .{ .year = c.y, .period = (c.m - 1) / 3 + 1, .value = 0 },
        .monthly => return .{ .year = c.y, .period = c.m, .value = 0 },
        .weekly => {
            // ISO 8601: weeks start on Monday; the week belongs to the year
            // that holds its Thursday. 1970-01-01 was a Thursday.
            const wd = @mod(dn + 3, 7); // Monday = 0
            const thursday = dn - wd + 3;
            const ty = civilOf(thursday).y;
            const week = @divFloor(thursday - daysFromCivil(ty, 1, 1), 7) + 1;
            return .{ .year = ty, .period = std.math.cast(u8, week) orelse 1, .value = 0 };
        },
    }
}

/// Walks the periods of a validated, sorted date series in order.
const PeriodIter = struct {
    dates: []const []const u8,
    rets: []const f64,
    period: Period,
    compounded: bool,
    i: usize = 0,

    fn init(dates: []const []const u8, rets: []const f64, period: Period, compounded: bool) Error!PeriodIter {
        if (dates.len != rets.len) return error.LengthMismatch;
        var prev: i64 = 0;
        for (dates, 0..) |d, k| {
            const dn = try slice.dayNumber(d);
            if (k > 0 and dn < prev) return error.DatesNotSorted;
            prev = dn;
        }
        return .{ .dates = dates, .rets = rets, .period = period, .compounded = compounded };
    }

    fn next(self: *PeriodIter) ?PeriodReturn {
        if (self.i >= self.dates.len) return null;
        const start = self.i;
        const k0 = keyOf(slice.dayNumber(self.dates[start]) catch return null, self.period);
        var j = start + 1;
        while (j < self.dates.len) : (j += 1) {
            const kj = keyOf(slice.dayNumber(self.dates[j]) catch return null, self.period);
            if (kj.year != k0.year or kj.period != k0.period) break;
        }
        self.i = j;
        const rs = self.rets[start..j];
        var out = k0;
        if (self.compounded) {
            out.value = slice.totalReturn(rs);
        } else if (finiteAll(rs)) {
            var s: f64 = 0;
            for (rs) |x| s += x;
            out.value = s;
        } else out.value = nan;
        return out;
    }
};

// ── calendar aggregation ────────────────────────────────────────────────────

/// Compounded return of each period that has at least one row, in date order:
/// Π(1 + r) - 1 over the rows of the period (empyrical `aggregate_returns`,
/// which it equals to 1e-15; quantstats `monthly_returns` and
/// `utils.aggregate_returns(.., "ME")` agree). A period with a return below -1 or
/// a non-finite one is NaN; one of exactly -1 wipes the period out, -1. Empty input:
/// no periods.
///
/// Weeks. This follows ISO 8601: key (ISO year, ISO week), Monday to Sunday.
/// empyrical keys a week by (CALENDAR year, ISO week) instead, which splits
/// the week that straddles New Year in two and, in a series longer than a year,
/// merges the early-January week 1 with the late-December week 1 of the next
/// ISO year. That is a library defect, not a convention, so it is not
/// reproduced; away from year ends the two give the same numbers (pinned on a
/// span without one).
pub fn aggregateReturns(a: std.mem.Allocator, dates: []const []const u8, rets: []const f64, period: Period) Error![]PeriodReturn {
    var it = try PeriodIter.init(dates, rets, period, true);
    return collect(a, &it);
}

fn collect(a: std.mem.Allocator, it: *PeriodIter) Error![]PeriodReturn {
    var out: std.ArrayList(PeriodReturn) = .empty;
    errdefer out.deinit(a);
    while (it.next()) |p| try out.append(a, p);
    return out.toOwnedSlice(a);
}

/// `aggregateReturns` by calendar month.
pub fn monthlyReturns(a: std.mem.Allocator, dates: []const []const u8, rets: []const f64) Error![]PeriodReturn {
    return aggregateReturns(a, dates, rets, .monthly);
}

/// `aggregateReturns` by calendar year.
pub fn yearlyReturns(a: std.mem.Allocator, dates: []const []const u8, rets: []const f64) Error![]PeriodReturn {
    return aggregateReturns(a, dates, rets, .yearly);
}

/// Compounded return of the rows in the calendar month of the LAST date, from
/// the month's first row to the last (month to date). Empty: 0. NaN on bad
/// dates, unsorted dates, different lengths or a non-compoundable return.
pub fn mtdReturn(dates: []const []const u8, rets: []const f64) f64 {
    return toDate(dates, rets, .monthly);
}

/// Compounded return of the rows in the calendar year of the LAST date (year to
/// date). Same conventions as `mtdReturn`.
pub fn ytdReturn(dates: []const []const u8, rets: []const f64) f64 {
    return toDate(dates, rets, .yearly);
}

fn toDate(dates: []const []const u8, rets: []const f64, period: Period) f64 {
    var it = PeriodIter.init(dates, rets, period, true) catch return nan;
    var last: ?PeriodReturn = null;
    while (it.next()) |p| last = p;
    return if (last) |p| p.value else 0;
}

const PeriodStat = enum { best, worst, avg_up, avg_down, geometric, win_rate };

fn periodStat(dates: []const []const u8, rets: []const f64, period: Period, comptime which: PeriodStat) f64 {
    var it = PeriodIter.init(dates, rets, period, true) catch return nan;
    var count: usize = 0;
    var wins: usize = 0;
    var losses: usize = 0;
    var best: f64 = -std.math.inf(f64);
    var worst: f64 = std.math.inf(f64);
    var up_sum: f64 = 0;
    var down_sum: f64 = 0;
    var log_sum: f64 = 0;
    var wiped = false;
    while (it.next()) |p| {
        const v = p.value;
        if (std.math.isNan(v)) return nan;
        count += 1;
        best = @max(best, v);
        worst = @min(worst, v);
        if (v > 0) {
            wins += 1;
            up_sum += v;
        } else if (v < 0) {
            losses += 1;
            down_sum += v;
        }
        if (v <= -1) wiped = true else log_sum += std.math.log1p(v);
    }
    if (count == 0) return 0;
    const nf: f64 = @floatFromInt(count);
    return switch (which) {
        .best => best,
        .worst => worst,
        .avg_up => if (wins == 0) 0 else up_sum / @as(f64, @floatFromInt(wins)),
        .avg_down => if (losses == 0) 0 else down_sum / @as(f64, @floatFromInt(losses)),
        .geometric => if (wiped) -1 else std.math.expm1(log_sum / nf),
        .win_rate => if (wins + losses == 0) 0 else @as(f64, @floatFromInt(wins)) / @as(f64, @floatFromInt(wins + losses)),
    };
}

/// Share of calendar quarters with a positive compounded return among the
/// quarters that are not exactly flat (quantstats `win_rate` of the quarterly
/// returns; a flat quarter is neither win nor loss). No such quarter: 0.
pub fn winQuarter(dates: []const []const u8, rets: []const f64) f64 {
    return periodStat(dates, rets, .quarterly, .win_rate);
}

/// Largest compounded return of any `period` (quantstats `best(aggregate=..)`).
/// Empty: 0.
pub fn bestPeriod(dates: []const []const u8, rets: []const f64, period: Period) f64 {
    return periodStat(dates, rets, period, .best);
}

/// Smallest compounded return of any `period` (quantstats `worst(aggregate=..)`).
/// Empty: 0.
pub fn worstPeriod(dates: []const []const u8, rets: []const f64, period: Period) f64 {
    return periodStat(dates, rets, period, .worst);
}

/// Mean of the strictly positive monthly compounded returns (quantstats
/// `avg_win(aggregate="ME")`); 0 if there are none.
pub fn avgUpMonth(dates: []const []const u8, rets: []const f64) f64 {
    return periodStat(dates, rets, .monthly, .avg_up);
}

/// Mean of the strictly negative monthly compounded returns, a value <= 0
/// (quantstats `avg_loss(aggregate="ME")`); 0 if there are none.
pub fn avgDownMonth(dates: []const []const u8, rets: []const f64) f64 {
    return periodStat(dates, rets, .monthly, .avg_down);
}

/// Geometric mean monthly return, (Π(1 + m))^(1/months) - 1 over the monthly
/// compounded returns (quantstats `expected_return(aggregate="ME")`). A month
/// of -100 % or worse gives -1. Empty: 0.
pub fn expectedMonthlyReturn(dates: []const []const u8, rets: []const f64) f64 {
    return periodStat(dates, rets, .monthly, .geometric);
}

/// Geometric mean yearly return over the calendar years that have rows
/// (quantstats `expected_return(aggregate="YE")`). A partial year counts as one.
pub fn expectedYearlyReturn(dates: []const []const u8, rets: []const f64) f64 {
    return periodStat(dates, rets, .yearly, .geometric);
}

/// Gain to pain at monthly resolution: Σ monthly / |Σ negative monthly|, where
/// a month is the SUM of its returns (quantstats `gain_to_pain_ratio(resolution=
/// "M")`, which resamples by sum, not by compounding; `monthlyReturns` and
/// `slice.gainToPain` give the compounded variant). No losing month: +inf when
/// the sum is positive, else 0. Empty: 0.
pub fn gainToPainMonthly(dates: []const []const u8, rets: []const f64) f64 {
    var it = PeriodIter.init(dates, rets, .monthly, false) catch return nan;
    var sum: f64 = 0;
    var loss: f64 = 0;
    while (it.next()) |p| {
        if (std.math.isNan(p.value)) return nan;
        sum += p.value;
        if (p.value < 0) loss += p.value;
    }
    if (loss == 0) return if (sum > 0) std.math.inf(f64) else 0;
    return sum / @abs(loss);
}

// ── converters ──────────────────────────────────────────────────────────────

fn pricePair(p0: f64, p1: f64) bool {
    return std.math.isFinite(p0) and std.math.isFinite(p1) and p0 > 0 and p1 > 0;
}

/// Simple returns p[i+1] / p[i] - 1: ONE FEWER than there are prices (empyrical
/// `simple_returns` drops the first row; ffn `to_returns` keeps it as NaN, which
/// is dropped here). Fewer than two prices: no returns. A return whose price,
/// or previous price, is at or below 0 or not finite is NaN (empyrical gives
/// -1 or inf there).
pub fn toReturns(a: std.mem.Allocator, prices: []const f64) std.mem.Allocator.Error![]f64 {
    const out = try a.alloc(f64, if (prices.len == 0) 0 else prices.len - 1);
    fillReturns(out, prices);
    return out;
}

/// `toReturns` into a caller buffer, `error.LengthMismatch` unless `out.len` is
/// one less than `prices.len` (0 for no prices).
pub fn toReturnsInto(out: []f64, prices: []const f64) error{LengthMismatch}!void {
    if (out.len != (if (prices.len == 0) 0 else prices.len - 1)) return error.LengthMismatch;
    fillReturns(out, prices);
}

fn fillReturns(out: []f64, prices: []const f64) void {
    for (out, 0..) |*o, i| {
        o.* = if (pricePair(prices[i], prices[i + 1])) prices[i + 1] / prices[i] - 1 else nan;
    }
}

/// Log returns ln(p[i+1] / p[i]), one fewer than the prices (ffn
/// `to_log_returns` with its leading NaN row dropped). Same bad-price rule as
/// `toReturns`.
pub fn toLogReturns(a: std.mem.Allocator, prices: []const f64) std.mem.Allocator.Error![]f64 {
    const out = try a.alloc(f64, if (prices.len == 0) 0 else prices.len - 1);
    fillLogReturns(out, prices);
    return out;
}

/// `toLogReturns` into a caller buffer; the length rule of `toReturnsInto`.
pub fn toLogReturnsInto(out: []f64, prices: []const f64) error{LengthMismatch}!void {
    if (out.len != (if (prices.len == 0) 0 else prices.len - 1)) return error.LengthMismatch;
    fillLogReturns(out, prices);
}

fn fillLogReturns(out: []f64, prices: []const f64) void {
    for (out, 0..) |*o, i| {
        o.* = if (pricePair(prices[i], prices[i + 1])) @log(prices[i + 1] / prices[i]) else nan;
    }
}

/// Price index from returns: `start`, then start * Π(1 + r) after each return;
/// ONE MORE value than there are returns (ffn `to_price_index(returns, start)`;
/// empyrical `cum_returns(.., starting_value)` is the same without the leading
/// `start`). A NaN return makes every later value NaN. A `start` that is not
/// finite gives all NaN.
pub fn toPriceIndex(a: std.mem.Allocator, rets: []const f64, start: f64) std.mem.Allocator.Error![]f64 {
    const out = try a.alloc(f64, rets.len + 1);
    fillPriceIndex(out, rets, start);
    return out;
}

/// `toPriceIndex` into a caller buffer of `rets.len + 1`.
pub fn toPriceIndexInto(out: []f64, rets: []const f64, start: f64) error{LengthMismatch}!void {
    if (out.len != rets.len + 1) return error.LengthMismatch;
    fillPriceIndex(out, rets, start);
}

fn fillPriceIndex(out: []f64, rets: []const f64, start: f64) void {
    out[0] = if (std.math.isFinite(start)) start else nan;
    for (rets, 0..) |r, i| out[i + 1] = out[i] * (1 + r);
}

/// Prices scaled to start at `value`: p[i] / p[0] * value (ffn `rebase`;
/// quantstats `utils.rebase` agrees). A first price at or below 0 or not
/// finite, or a `value` not finite, gives all NaN; any other bad price gives NaN
/// at its place.
pub fn rebase(a: std.mem.Allocator, prices: []const f64, value: f64) std.mem.Allocator.Error![]f64 {
    const out = try a.alloc(f64, prices.len);
    fillRebase(out, prices, value);
    return out;
}

/// `rebase` into a caller buffer of the same length as `prices`.
pub fn rebaseInto(out: []f64, prices: []const f64, value: f64) error{LengthMismatch}!void {
    if (out.len != prices.len) return error.LengthMismatch;
    fillRebase(out, prices, value);
}

fn fillRebase(out: []f64, prices: []const f64, value: f64) void {
    if (prices.len == 0) return;
    const p0 = prices[0];
    const bad = !std.math.isFinite(p0) or p0 <= 0 or !std.math.isFinite(value);
    for (out, prices) |*o, p| o.* = if (bad or !std.math.isFinite(p)) nan else p / p0 * value;
}

/// The per-period rate of an annual one, (1 + rate)^(1/nperiods) - 1 (ffn
/// `deannualize`). NaN for `nperiods` not positive finite, a rate not finite or
/// below -1.
pub fn deannualize(rate: f64, nperiods: f64) f64 {
    if (badPpy(nperiods) or !std.math.isFinite(rate) or rate < -1) return nan;
    if (rate == 0) return 0;
    const p = std.math.pow(f64, 1 + rate, 1 / nperiods);
    return if (std.math.isFinite(p)) p - 1 else nan;
}

/// Excess returns over a risk-free rate `rf`, ARITHMETIC: r - rf_p. With
/// `nperiods` the annual rate `rf` is compounded down to a period first,
/// rf_p = (1 + rf)^(1/nperiods) - 1 (`deannualize`); without it `rf` is already
/// per period (ffn `to_excess_returns(returns, rf, nperiods)`, measured equal to
/// 1e-15; its docstring speaks of a geometric excess, which version 1.3.0 does not
/// compute; with `nperiods` omitted and a date-indexed series ffn silently infers
/// the annualisation from the index, which is not offered here). Bad `nperiods` or
/// `rf`: all NaN.
pub fn toExcessReturns(a: std.mem.Allocator, rets: []const f64, rf: f64, nperiods: ?f64) std.mem.Allocator.Error![]f64 {
    const out = try a.alloc(f64, rets.len);
    fillExcess(out, rets, rf, nperiods);
    return out;
}

/// `toExcessReturns` into a caller buffer of the same length as `rets`.
pub fn toExcessReturnsInto(out: []f64, rets: []const f64, rf: f64, nperiods: ?f64) error{LengthMismatch}!void {
    if (out.len != rets.len) return error.LengthMismatch;
    fillExcess(out, rets, rf, nperiods);
}

fn fillExcess(out: []f64, rets: []const f64, rf: f64, nperiods: ?f64) void {
    if (nperiods) |n| {
        const rfp = deannualize(rf, n);
        for (out, rets) |*o, r| o.* = if (std.math.isNan(rfp)) nan else r - rfp;
    } else {
        for (out, rets) |*o, r| o.* = if (std.math.isFinite(rf)) r - rf else nan;
    }
}

/// Clip the `lo` and `hi` tails to the next value inside, scipy
/// `mstats.winsorize(xs, limits=(lo, hi))` (ffn `winsorize(x, limits=l)` is
/// `lo = hi = l`): with n values, the k_lo = floor(lo * n) smallest become the
/// (k_lo+1)-th smallest and the k_hi = floor(hi * n) largest the (k_hi+1)-th
/// largest. All NaN for a non-finite value, a limit outside [0, 1], or a limit
/// pair that leaves no value (k_lo + k_hi at least n, ties aside).
pub fn winsorize(a: std.mem.Allocator, xs: []const f64, lo: f64, hi: f64) std.mem.Allocator.Error![]f64 {
    const out = try a.alloc(f64, xs.len);
    errdefer a.free(out);
    const n = xs.len;
    const bad = !finiteAll(xs) or !(lo >= 0 and lo <= 1) or !(hi >= 0 and hi <= 1);
    const nf: f64 = @floatFromInt(n);
    const k_lo = if (bad) 0 else std.math.lossyCast(usize, @floor(lo * nf));
    const k_hi = if (bad) 0 else std.math.lossyCast(usize, @floor(hi * nf));
    if (bad or n == 0 or k_lo >= n or k_hi >= n) {
        @memset(out, nan);
        return out;
    }
    const sorted = try a.dupe(f64, xs);
    defer a.free(sorted);
    std.mem.sort(f64, sorted, {}, f64lt);
    const low = sorted[k_lo];
    const high = sorted[n - 1 - k_hi];
    for (out, xs) |*o, x| o.* = if (low > high) nan else @min(@max(x, low), high);
    return out;
}

/// Linear map of the series onto `[lo, hi]`: (x - min) / (max - min) * (hi - lo)
/// + lo (ffn `rescale`). A constant series maps every value to `hi`, as ffn
/// does. All NaN for a non-finite value or bound.
pub fn rescale(a: std.mem.Allocator, xs: []const f64, lo: f64, hi: f64) std.mem.Allocator.Error![]f64 {
    const out = try a.alloc(f64, xs.len);
    if (xs.len == 0) return out;
    if (!finiteAll(xs) or !std.math.isFinite(lo) or !std.math.isFinite(hi)) {
        @memset(out, nan);
        return out;
    }
    const mn = std.mem.min(f64, xs);
    const mx = std.mem.max(f64, xs);
    const span = mx - mn;
    for (out, xs) |*o, x| {
        o.* = if (span == 0) hi else if (std.math.isFinite(span)) (x - mn) / span * (hi - lo) + lo else (x / 2 - mn / 2) / (mx / 2 - mn / 2) * (hi - lo) + lo;
    }
    return out;
}

// ── rolling ─────────────────────────────────────────────────────────────────

fn windowCount(n: usize, window: usize) error{TooLarge}!usize {
    if (window == 0 or n < window) return 0;
    const count = n - window + 1;
    const work = std.math.mul(usize, count, window) catch return error.TooLarge;
    if (work > slice.max_rolling_work) return error.TooLarge;
    return count;
}

const RfCtx = struct { rf: f64, ppy: f64 };

fn sortinoReducer(c: RfCtx, w: []const f64) f64 {
    return slice.sortinoRatio(w, c.rf, c.ppy);
}

fn sharpeReducer(c: RfCtx, w: []const f64) f64 {
    return slice.sharpeRatio(w, c.rf, c.ppy);
}

fn cagrReducer(ppy: f64, w: []const f64) f64 {
    return slice.cagrPeriods(w, ppy);
}

/// `slice.sortinoRatio` over each full trailing window (n - window + 1 values;
/// none if the series is shorter or `window` is 0), `rf` ANNUAL (quantstats
/// `rolling_sortino(rf, rolling_period, periods_per_year)`, equal to 1e-12).
/// O(n x window), capped by `slice.max_rolling_work`.
pub fn rollingSortino(a: std.mem.Allocator, xs: []const f64, window: usize, rf: f64, ppy: f64) Error![]f64 {
    return slice.rollingApplyCtx(a, xs, window, RfCtx{ .rf = rf, .ppy = ppy }, sortinoReducer);
}

/// Annualised Sharpe over each full trailing window,
/// `slice.sharpeRatio(window, rf, ppy)`: mean(r - rf_p) / std(r) * sqrt(ppy),
/// `rf` annual (quantstats `rolling_sharpe`, equal to 1e-12; note that
/// `slice.rollingSharpe` is the unannualised rf-0 older form). A window with
/// zero spread gives 0, where quantstats gives inf or NaN.
pub fn rollingSharpeRf(a: std.mem.Allocator, xs: []const f64, window: usize, rf: f64, ppy: f64) Error![]f64 {
    return slice.rollingApplyCtx(a, xs, window, RfCtx{ .rf = rf, .ppy = ppy }, sharpeReducer);
}

/// `slice.cagrPeriods(window, ppy)` over each full trailing window (empyrical
/// `annual_return` per window).
pub fn rollingCagr(a: std.mem.Allocator, xs: []const f64, window: usize, ppy: f64) Error![]f64 {
    return slice.rollingApplyCtx(a, xs, window, ppy, cagrReducer);
}

/// `slice.maxDrawdown` over each full trailing window (empyrical
/// `roll_max_drawdown`, equal exactly).
pub fn rollingMaxDrawdown(a: std.mem.Allocator, xs: []const f64, window: usize) Error![]f64 {
    return slice.rollingApply(a, xs, window, slice.maxDrawdown);
}

/// `slice.winRate` over each full trailing window: positive periods over
/// non-zero periods, a window of only zeros 0.
pub fn rollingWinRate(a: std.mem.Allocator, xs: []const f64, window: usize) Error![]f64 {
    return slice.rollingApply(a, xs, window, slice.winRate);
}

fn rollCapture(a: std.mem.Allocator, p: []const f64, b: []const f64, window: usize, ppy: f64, up: bool) Error![]f64 {
    if (p.len != b.len) return error.LengthMismatch;
    const out = try a.alloc(f64, try windowCount(p.len, window));
    errdefer a.free(out);
    if (captureBad(p, b, ppy)) {
        @memset(out, nan);
        return out;
    }
    for (out, 0..) |*o, k| o.* = try core.capture(a, p[k .. k + window], b[k .. k + window], ppy, up);
    return out;
}

/// `up_capture` of each full trailing window (empyrical `roll_up_capture`):
/// the CAGR of `p` over the periods where `b` rose, over the CAGR of `b` over
/// the same periods; 0 for a window with no such period.
pub fn rollUpCapture(a: std.mem.Allocator, p: []const f64, b: []const f64, window: usize, ppy: f64) Error![]f64 {
    return rollCapture(a, p, b, window, ppy, true);
}

/// `down_capture` of each full trailing window (empyrical `roll_down_capture`).
pub fn rollDownCapture(a: std.mem.Allocator, p: []const f64, b: []const f64, window: usize, ppy: f64) Error![]f64 {
    return rollCapture(a, p, b, window, ppy, false);
}

// ── resampling Monte Carlo (quantstats montecarlo*) ─────────────────────────

/// Distribution of one statistic over the simulated paths. `std` is the sample
/// standard deviation (ddof 1), the percentiles are linear-interpolated
/// (numpy's default), as quantstats reports them.
pub const Dist = struct { min: f64, max: f64, mean: f64, median: f64, std: f64, p5: f64, p25: f64, p75: f64, p95: f64 };

/// `montecarlo`: the distribution of the final total return, and the shares of
/// paths that went bust or reached the goal (null if not asked for).
pub const McResult = struct { total: Dist, bust_probability: ?f64, goal_probability: ?f64 };

fn filled(v: f64) Dist {
    return .{ .min = v, .max = v, .mean = v, .median = v, .std = v, .p5 = v, .p25 = v, .p75 = v, .p95 = v };
}

fn distOf(a: std.mem.Allocator, vals: []const f64) std.mem.Allocator.Error!Dist {
    if (vals.len == 0) return filled(0);
    for (vals) |v| if (std.math.isNan(v)) return filled(nan);
    const s = try a.dupe(f64, vals);
    defer a.free(s);
    std.mem.sort(f64, s, {}, f64lt);
    return .{
        .min = s[0],
        .max = s[s.len - 1],
        .mean = core.mean(s),
        .median = slice.quantileSorted(s, 0.5),
        .std = core.stdSample(s),
        .p5 = slice.quantileSorted(s, 0.05),
        .p25 = slice.quantileSorted(s, 0.25),
        .p75 = slice.quantileSorted(s, 0.75),
        .p95 = slice.quantileSorted(s, 0.95),
    };
}

fn checkResample(n: usize, sims: usize) error{TooLarge}!void {
    if (sims > max_resample_sims) return error.TooLarge;
    const cells = std.math.mul(usize, n, sims) catch return error.TooLarge;
    if (cells > max_resample_cells) return error.TooLarge;
}

const Mode = enum { permute, bootstrap };

/// Draws the next path into `buf` (a permutation of `xs` or a with-replacement
/// sample of it); `buf` holds the previous permutation, which stays a uniform
/// one under a further Fisher-Yates pass.
fn drawPath(rnd: std.Random, xs: []const f64, buf: []f64, mode: Mode) void {
    switch (mode) {
        .permute => {
            var i = buf.len;
            while (i > 1) {
                i -= 1;
                const j = rnd.uintLessThan(usize, i + 1);
                std.mem.swap(f64, &buf[i], &buf[j]);
            }
        },
        .bootstrap => for (buf) |*b| {
            b.* = xs[rnd.uintLessThan(usize, xs.len)];
        },
    }
}

fn resampleStat(
    a: std.mem.Allocator,
    xs: []const f64,
    sims: usize,
    seed: u64,
    comptime mode: Mode,
    ctx: anytype,
    comptime eval: fn (@TypeOf(ctx), []const f64) f64,
) Error!Dist {
    try checkResample(xs.len, sims);
    if (xs.len == 0 or sims == 0) return filled(0);
    if (!finiteAll(xs)) return filled(nan);
    const vals = try a.alloc(f64, sims);
    defer a.free(vals);
    const buf = try a.dupe(f64, xs);
    defer a.free(buf);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    for (vals) |*v| {
        drawPath(rnd, xs, buf, mode);
        v.* = eval(ctx, buf);
    }
    return distOf(a, vals);
}

fn totalEval(_: void, w: []const f64) f64 {
    return slice.totalReturn(w);
}
fn cagrEval(ppy: f64, w: []const f64) f64 {
    return slice.cagrPeriods(w, ppy);
}
fn ddEval(_: void, w: []const f64) f64 {
    return slice.maxDrawdown(w);
}
fn sharpeEval(c: RfCtx, w: []const f64) f64 {
    return slice.sharpeRatio(w, c.rf, c.ppy);
}

/// Resampling Monte Carlo of the ORDER of the returns (quantstats
/// `montecarlo`): `sims` random permutations of `xs` (every path uses exactly
/// the input's returns, once each; measured on quantstats), seeded by `seed`.
/// Because a permutation does not change a product, the distribution of the
/// final total return is a point (min = max = `slice.totalReturn(xs)` to
/// rounding), as in quantstats; what varies is the path. `bust`: the share of
/// paths whose maximum drawdown (`slice.maxDrawdown`, a value <= 0) reached
/// `bust` or worse, e.g. -0.2 (quantstats measures the bust threshold against
/// the drawdown, not the level; its drawdown starts the peak at the first
/// return where this one starts it at 1, so a first-period loss counts here).
/// `goal`: the share of paths whose final total return is at least `goal`.
/// Our PRNG is xoshiro256, not numpy's, so only the distribution, not the
/// numbers, matches. Empty series or no sims: all 0. Non-finite series, or a NaN
/// `bust` or `goal`: NaN for what depends on it.
/// `error.TooLarge` above `max_resample_sims` or `max_resample_cells`.
pub fn montecarlo(a: std.mem.Allocator, xs: []const f64, sims: usize, seed: u64, bust: ?f64, goal: ?f64) Error!McResult {
    try checkResample(xs.len, sims);
    const none: McResult = .{ .total = filled(0), .bust_probability = null, .goal_probability = null };
    if (xs.len == 0 or sims == 0) return none;
    if (!finiteAll(xs)) return .{ .total = filled(nan), .bust_probability = if (bust != null) nan else null, .goal_probability = if (goal != null) nan else null };
    const vals = try a.alloc(f64, sims);
    defer a.free(vals);
    const buf = try a.dupe(f64, xs);
    defer a.free(buf);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    var busts: usize = 0;
    var goals: usize = 0;
    for (vals) |*v| {
        drawPath(rnd, xs, buf, .permute);
        v.* = slice.totalReturn(buf);
        if (bust) |b| {
            if (slice.maxDrawdown(buf) <= b) busts += 1;
        }
        if (goal) |g| {
            if (v.* >= g) goals += 1;
        }
    }
    const sf: f64 = @floatFromInt(sims);
    return .{
        .total = try distOf(a, vals),
        .bust_probability = if (bust) |b| (if (std.math.isNan(b)) nan else @as(f64, @floatFromInt(busts)) / sf) else null,
        .goal_probability = if (goal) |g| (if (std.math.isNan(g)) nan else @as(f64, @floatFromInt(goals)) / sf) else null,
    };
}

/// Distribution of the CAGR (`slice.cagrPeriods(path, ppy)`) over `sims`
/// permutations of `xs` (quantstats `montecarlo_cagr`). A permutation keeps the
/// product, so this too is a point; same conventions as `montecarlo`.
pub fn montecarloCagr(a: std.mem.Allocator, xs: []const f64, sims: usize, seed: u64, ppy: f64) Error!Dist {
    if (badPpy(ppy)) return filled(nan);
    return resampleStat(a, xs, sims, seed, .permute, ppy, cagrEval);
}

/// Distribution of the maximum drawdown (`slice.maxDrawdown`, <= 0) over `sims`
/// permutations of `xs` (quantstats `montecarlo_drawdown`: mean, std with ddof 1
/// and the percentiles agree with its definition; its drawdown starts the peak
/// at the first return, this one at 1). The one Monte Carlo statistic where the
/// order matters.
pub fn montecarloDrawdown(a: std.mem.Allocator, xs: []const f64, sims: usize, seed: u64) Error!Dist {
    return resampleStat(a, xs, sims, seed, .permute, {}, ddEval);
}

/// Distribution of the annualised Sharpe ratio (`slice.sharpeRatio(path, rf,
/// ppy)`) over `sims` BOOTSTRAP paths: `xs.len` returns drawn WITH replacement,
/// since a permutation cannot change a Sharpe ratio (mean and std are order
/// free). quantstats `montecarlo_sharpe` centres on the same value but reports
/// a spread about 11 times narrower than a bootstrap of this size has; how it
/// resamples could not be established as a black box, so its spread is NOT
/// reproduced (the mean is, up to sampling error).
pub fn montecarloSharpe(a: std.mem.Allocator, xs: []const f64, sims: usize, seed: u64, rf: f64, ppy: f64) Error!Dist {
    if (badPpy(ppy) or !std.math.isFinite(rf)) return filled(nan);
    return resampleStat(a, xs, sims, seed, .bootstrap, RfCtx{ .rf = rf, .ppy = ppy }, sharpeEval);
}

// ── empyrical extras ────────────────────────────────────────────────────────

/// Annualised alpha and beta of a series against a benchmark.
pub const AlphaBeta = struct { alpha: f64, beta: f64 };

const nan_ab: AlphaBeta = .{ .alpha = nan, .beta = nan };

/// Which periods `alphaBetaOf` keeps, by the benchmark's direction.
const Side = enum { all, up, down };

fn alphaBetaOf(p: []const f64, b: []const f64, rf: f64, ppy: f64, comptime filter: Side) AlphaBeta {
    if (p.len != b.len or badPpy(ppy) or !finiteAll(p) or !finiteAll(b)) return nan_ab;
    const rfp = core.rfPerPeriod(rf, ppy);
    if (std.math.isNan(rfp)) return nan_ab;
    var n: usize = 0;
    var sp: f64 = 0;
    var sb: f64 = 0;
    for (p, b) |x, y| {
        if (!keep(y, filter)) continue;
        n += 1;
        sp += x;
        sb += y;
    }
    if (n < 2) return nan_ab;
    const nf: f64 = @floatFromInt(n);
    const mp = sp / nf;
    const mb = sb / nf;
    var cov: f64 = 0;
    var varb: f64 = 0;
    for (p, b) |x, y| {
        if (!keep(y, filter)) continue;
        cov += (x - mp) * (y - mb);
        varb += (y - mb) * (y - mb);
    }
    const beta: f64 = if (varb > 0) cov / varb else 0;
    const per_period = (mp - rfp) - beta * (mb - rfp);
    const alpha = std.math.pow(f64, 1 + per_period, ppy) - 1;
    return .{ .alpha = if (std.math.isFinite(alpha)) alpha else nan, .beta = beta };
}

fn keep(y: f64, comptime filter: Side) bool {
    return switch (filter) {
        .all => true,
        .up => y > 0,
        .down => y < 0,
    };
}

/// Annualised alpha and beta, empyrical `alpha_beta(returns, factor_returns,
/// risk_free, annualization)`: beta = cov(p - rf_p, b - rf_p) / var(b - rf_p)
/// (the shift changes neither), alpha = (1 + mean(p - rf_p) - beta * mean(b -
/// rf_p))^ppy - 1, GEOMETRICALLY annualised (`slice.rollingBetaAlpha` and
/// `slice.betaAlpha` annualise arithmetically). `rf` is ANNUAL and compounded
/// down to a period like everywhere in this module; empyrical takes the
/// per-period rate (the same number once converted). Zero variance of `b`:
/// beta 0 (empyrical divides by zero). NaN on different lengths, fewer than two
/// periods, non-finite input or a bad `rf` or `ppy`.
pub fn alphaBeta(p: []const f64, b: []const f64, rf: f64, ppy: f64) AlphaBeta {
    return alphaBetaOf(p, b, rf, ppy, .all);
}

/// Jensen's alpha with a risk-free rate: the `alpha` of `alphaBeta`, which is
/// empyrical `alpha(returns, factor_returns, risk_free, annualization)`.
pub fn jensenAlpha(p: []const f64, b: []const f64, rf: f64, ppy: f64) f64 {
    return alphaBetaOf(p, b, rf, ppy, .all).alpha;
}

/// `alphaBeta` over the periods where the benchmark rose (b > 0; empyrical
/// `up_alpha_beta`, equal to 1e-12; an exactly flat benchmark period is in
/// neither side).
pub fn upAlphaBeta(p: []const f64, b: []const f64, rf: f64, ppy: f64) AlphaBeta {
    return alphaBetaOf(p, b, rf, ppy, .up);
}

/// `alphaBeta` over the periods where the benchmark fell (b < 0; empyrical
/// `down_alpha_beta`).
pub fn downAlphaBeta(p: []const f64, b: []const f64, rf: f64, ppy: f64) AlphaBeta {
    return alphaBetaOf(p, b, rf, ppy, .down);
}

/// Mean of the active return p - b over its sample standard deviation, NOT
/// annualised (empyrical `excess_sharpe`, equal to 1e-14). Fewer than two
/// periods or zero spread: 0. NaN on different lengths or non-finite input.
pub fn excessSharpe(p: []const f64, b: []const f64) f64 {
    if (p.len != b.len or !finiteAll(p) or !finiteAll(b)) return nan;
    if (p.len < 2) return 0;
    var m: f64 = 0;
    for (p, b) |x, y| m += x - y;
    m /= @as(f64, @floatFromInt(p.len));
    var ss: f64 = 0;
    for (p, b) |x, y| ss += (x - y - m) * (x - y - m);
    const sd = @sqrt(ss / @as(f64, @floatFromInt(p.len - 1)));
    var scale: f64 = 0;
    for (p, b) |x, y| scale = @max(scale, @abs(x - y));
    if (sd <= 8 * std.math.floatEps(f64) * scale) return 0;
    return m / sd;
}

/// Share of periods in which the series beat the benchmark.
pub const Batting = struct { all: f64, up: f64, down: f64 };

/// Share of periods with p > b over all periods, over those where the
/// benchmark did not fall (b >= 0, "up market") and over those where it fell
/// (b < 0, "down market") (empyrical `batting_average`; its up market includes
/// a flat benchmark period, measured). A side with no period: 0. NaN fields on
/// different lengths or non-finite input.
pub fn battingAverage(p: []const f64, b: []const f64) Batting {
    if (p.len != b.len or !finiteAll(p) or !finiteAll(b)) return .{ .all = nan, .up = nan, .down = nan };
    var wins: [3]usize = .{ 0, 0, 0 };
    var cnt: [3]usize = .{ 0, 0, 0 };
    for (p, b) |x, y| {
        const side: usize = if (y >= 0) 1 else 2;
        cnt[0] += 1;
        cnt[side] += 1;
        if (x > y) {
            wins[0] += 1;
            wins[side] += 1;
        }
    }
    var out: [3]f64 = undefined;
    for (&out, wins, cnt) |*o, w, c| o.* = if (c == 0) 0 else @as(f64, @floatFromInt(w)) / @as(f64, @floatFromInt(c));
    return .{ .all = out[0], .up = out[1], .down = out[2] };
}

const PairIdx = struct {
    f: []const f64,
    fn lt(self: PairIdx, i: usize, j: usize) bool {
        return self.f[i] < self.f[j];
    }
};

/// Beta fragility heuristic (empyrical `beta_fragility_heuristic`; Taleb et al.,
/// IMF WP/12/216): sort the periods by benchmark return, take the lowest, the
/// middle and the highest; the heuristic is the convexity of the series along
/// the benchmark at the middle point, `(r_lo (f_mid - f_lo) + r_hi (f_hi - f_mid))
/// / (f_hi - f_lo) - r_mid`. A negative value says losses follow when beta
/// moves; its size is the loss. The middle is index n/2 rounded half to even
/// (empyrical rounds with numpy's `around`; measured). Fewer than three periods
/// or a benchmark with no spread: 0 (empyrical gives NaN for fewer than three
/// and rounding noise for no spread). NaN on different lengths or non-finite
/// input.
pub fn betaFragilityHeuristic(a: std.mem.Allocator, p: []const f64, b: []const f64) Error!f64 {
    if (p.len != b.len or !finiteAll(p) or !finiteAll(b)) return nan;
    const n = p.len;
    if (n < 3) return 0;
    const idx = try a.alloc(usize, n);
    defer a.free(idx);
    for (idx, 0..) |*v, i| v.* = i;
    std.sort.block(usize, idx, PairIdx{ .f = b }, PairIdx.lt);
    const half = n / 2;
    const mid = if (n % 2 == 0 or half % 2 == 0) half else half + 1;
    const lo = idx[0];
    const md = idx[mid];
    const hi = idx[n - 1];
    const dx = b[hi] - b[lo];
    if (!(dx > 0)) return 0;
    return (p[lo] * (b[md] - b[lo]) + p[hi] * (b[hi] - b[md])) / dx - p[md];
}

// ── GPD tail estimates (empyrical gpd_risk_estimates) ───────────────────────

/// `gpdRiskEstimates` result, in empyrical's order: the threshold the fit
/// settled on, the GPD scale and shape, and VaR and expected shortfall (both
/// positive losses).
pub const GpdRisk = struct { threshold: f64, scale: f64, shape: f64, var_estimate: f64, es_estimate: f64 };

/// Peaks-over-threshold VaR and expected shortfall from the GPD parameters, as
/// empyrical computes them from its own fit: with `n_losses` the number of
/// negative returns (NOT the sample size) and `n_exceed` those of at least
/// `u`, VaR = u + scale/shape * ((n_losses * p / n_exceed)^(-shape) - 1) (the
/// logarithmic limit for shape 0) and ES = (VaR + scale - shape * u) / (1 -
/// shape) (infinite for shape >= 1).
pub fn gpdVarEs(u: f64, scale: f64, shape: f64, n_losses: usize, n_exceed: usize, p: f64) struct { var_estimate: f64, es_estimate: f64 } {
    if (n_exceed == 0 or n_losses == 0) return .{ .var_estimate = nan, .es_estimate = nan };
    const ratio = @as(f64, @floatFromInt(n_losses)) * p / @as(f64, @floatFromInt(n_exceed));
    const v = if (@abs(shape) < 1e-9) u - scale * @log(ratio) else u + scale / shape * (std.math.pow(f64, ratio, -shape) - 1);
    const es = if (shape >= 1) std.math.inf(f64) else (v + scale - shape * u) / (1 - shape);
    return .{ .var_estimate = v, .es_estimate = es };
}

const GpdFit = struct { scale: f64, shape: f64 };

/// Per-observation negative profile log-likelihood of the GPD in theta =
/// shape / scale (Grimshaw's reparametrisation): shape(theta) = mean(log1p(theta
/// y)), scale = shape / theta.
fn gpdProfile(ys: []const f64, theta: f64) f64 {
    var s: f64 = 0;
    for (ys) |y| s += std.math.log1p(theta * y);
    const xi = s / @as(f64, @floatFromInt(ys.len));
    if (!(xi > 0) or !std.math.isFinite(xi)) return std.math.inf(f64);
    return @log(xi / theta) + xi + 1;
}

/// Maximum-likelihood GPD with scale > 0 and shape >= 0 for the positive values
/// `ys`: the exponential limit (shape 0, scale = mean) against the best interior
/// shape, found by a fixed 512-point scan of theta on a log grid and a 120-step
/// golden section inside the best cell. Bounded work: at most `gpd_fit_passes` passes over `ys`.
fn gpdFit(ys: []const f64) ?GpdFit {
    if (ys.len == 0) return null;
    var ymax: f64 = 0;
    var ymin = std.math.inf(f64);
    for (ys) |y| {
        ymax = @max(ymax, y);
        ymin = @min(ymin, y);
    }
    const m = core.mean(ys);
    const nll0 = @log(m) + 1;
    var best_nll = std.math.inf(f64);
    var best_k: usize = 0;
    const grid = 512;
    const lo = @log(1e-6 / ymax);
    const hi = @log(1e8 / ymin);
    const step = (hi - lo) / grid;
    for (0..grid + 1) |k| {
        const v = gpdProfile(ys, @exp(lo + step * @as(f64, @floatFromInt(k))));
        if (v < best_nll) {
            best_nll = v;
            best_k = k;
        }
    }
    var out: GpdFit = .{ .scale = m, .shape = 0 };
    if (best_nll < nll0 - 1e-12 * @abs(nll0)) {
        var l = lo + step * @as(f64, @floatFromInt(if (best_k == 0) 0 else best_k - 1));
        var r = lo + step * @as(f64, @floatFromInt(@min(best_k + 1, grid)));
        const gr = 0.6180339887498949;
        var c = r - gr * (r - l);
        var d = l + gr * (r - l);
        var fc = gpdProfile(ys, @exp(c));
        var fd = gpdProfile(ys, @exp(d));
        for (0..120) |_| {
            if (fc < fd) {
                r = d;
                d = c;
                fd = fc;
                c = r - gr * (r - l);
                fc = gpdProfile(ys, @exp(c));
            } else {
                l = c;
                c = d;
                fc = fd;
                d = l + gr * (r - l);
                fd = gpdProfile(ys, @exp(d));
            }
        }
        const theta = @exp((l + r) / 2);
        var s: f64 = 0;
        for (ys) |y| s += std.math.log1p(theta * y);
        const xi = s / @as(f64, @floatFromInt(ys.len));
        if (xi > 0 and gpdProfile(ys, theta) < nll0) out = .{ .scale = xi / theta, .shape = xi };
    }
    return out;
}

/// GPD tail-risk estimates, empyrical `gpd_risk_estimates(returns, var_p)`.
/// The losses are the negated negative returns; the threshold starts at 0.2 and
/// is halved (at most 28 times, down to 1e-9) until some loss reaches it AND the
/// resulting VaR is positive. The second test is what empyrical does, measured:
/// the smallest exceedance count it accepts equals the count at which its VaR
/// turns positive, to the last integer, across `var_p` and sample sizes. A GPD with shape >= 0 is fitted by
/// maximum likelihood to those losses THEMSELVES, not to their excess over the
/// threshold (empyrical's convention, reproduced), and `gpdVarEs` turns it into
/// VaR and ES at the tail probability `var_p`.
///
/// Fit accuracy (measured, NOT 1e-6). empyrical minimises with scipy's `fmin` at
/// its default tolerances and its answer is not the optimum: on the eight seeded
/// fits in `calendar_test.zig` its scale differs from the exact optimum this
/// function finds (to about 1e-10) by up to 4.8e-3 relative, its shape (which is
/// exactly 0 at the optimum for these thin tails) by up to 2.3e-5, and VaR / ES
/// follow by up to 6.7e-3 / 2.6e-3 relative; the worst fits have one to seven
/// exceedances. Against empyrical the threshold is identical, and given the
/// same parameters `gpdVarEs` agrees with it to 1e-8. The fit is
/// bounded and cannot hang: past `max_gpd_work` it is `error.TooLarge`. No loss at all, or a `var_p` outside (0, 1): all
/// zeros / all NaN respectively; non-finite input: all NaN.
pub fn gpdRiskEstimates(a: std.mem.Allocator, xs: []const f64, var_p: f64) Error!GpdRisk {
    const bad: GpdRisk = .{ .threshold = nan, .scale = nan, .shape = nan, .var_estimate = nan, .es_estimate = nan };
    if (!finiteAll(xs) or !(var_p > 0 and var_p < 1)) return bad;
    const zero: GpdRisk = .{ .threshold = 0, .scale = 0, .shape = 0, .var_estimate = 0, .es_estimate = 0 };
    var losses: std.ArrayList(f64) = .empty;
    defer losses.deinit(a);
    for (xs) |x| if (x < 0) try losses.append(a, -x);
    if (losses.items.len == 0) return zero;
    const ys = try a.alloc(f64, losses.items.len);
    defer a.free(ys);
    var work: usize = 0;
    var u: f64 = 0.2;
    while (u > 1e-9) : (u /= 2) {
        var k: usize = 0;
        for (losses.items) |l| if (l >= u) {
            ys[k] = l;
            k += 1;
        };
        if (k == 0) continue;
        // k <= xs.len, far below usize's limit once multiplied by a few hundred
        // on a 64-bit target; checked anyway for a 32-bit one.
        const fit_work = std.math.mul(usize, k, gpd_fit_passes) catch return error.TooLarge;
        work = std.math.add(usize, work, fit_work) catch return error.TooLarge;
        if (work > max_gpd_work) return error.TooLarge;
        const fit = gpdFit(ys[0..k]) orelse continue;
        const ve = gpdVarEs(u, fit.scale, fit.shape, losses.items.len, k, var_p);
        if (!(ve.var_estimate > 0)) continue; // empyrical lowers the threshold until VaR is positive
        return .{ .threshold = u, .scale = fit.scale, .shape = fit.shape, .var_estimate = ve.var_estimate, .es_estimate = ve.es_estimate };
    }
    return zero;
}

// ── tail measures (FinanceToolkit style; pinned by definition) ──────────────

/// Conditional drawdown at risk: the mean of the worst `1 - confidence` share of
/// the drawdowns, as a positive number (`cvarHistoric` of the drawdown series).
/// The drawdown series is the compounded level's fall from its running peak
/// after each return, the peak starting at 1 (so `slice.maxDrawdown` is its
/// minimum); the quantile is linear. Empty: 0. NaN on a non-compoundable
/// series or a confidence outside [0, 1].
pub fn conditionalDrawdownAtRisk(a: std.mem.Allocator, xs: []const f64, confidence: f64) Error!f64 {
    if (!core.compoundable(xs) or !(confidence >= 0 and confidence <= 1)) return nan;
    if (xs.len == 0) return 0;
    const dd = try a.alloc(f64, xs.len);
    defer a.free(dd);
    var level: f64 = 1;
    var peak: f64 = 1;
    for (xs, dd) |x, *o| {
        level *= 1 + x;
        peak = @max(peak, level);
        o.* = (level - peak) / peak;
        if (peak > 0x1p500) {
            level *= 0x1p-500;
            peak *= 0x1p-500;
        }
    }
    return slice.cvarHistoric(a, dd, confidence);
}

/// The RiskMetrics decay `lambda` of a pandas-style `span`: 1 - 2 / (span + 1)
/// (`ewm(span=..)` has alpha = 2 / (span + 1) = 1 - lambda). NaN for span < 1.
pub fn lambdaFromSpan(span: f64) f64 {
    if (!(span >= 1) or !std.math.isFinite(span)) return nan;
    return 1 - 2 / (span + 1);
}

/// Exponentially weighted volatility, zero-mean (RiskMetrics): var_0 = r_0^2 and
/// var_t = lambda var_(t-1) + (1 - lambda) r_t^2, reported as sqrt(var_t * ppy);
/// one value per return. This is pandas `(r**2).ewm(alpha=1-lambda,
/// adjust=False).mean()`; with `lambdaFromSpan` it is `ewm(span=..)`. `lambda`
/// in [0, 1] (0.94 is RiskMetrics' daily value). All NaN for a lambda outside
/// that, a bad `ppy` or non-finite input; empty input: no values.
pub fn ewmaVolatility(a: std.mem.Allocator, xs: []const f64, lambda: f64, ppy: f64) std.mem.Allocator.Error![]f64 {
    const out = try a.alloc(f64, xs.len);
    if (!(lambda >= 0 and lambda <= 1) or badPpy(ppy) or !finiteAll(xs)) {
        @memset(out, nan);
        return out;
    }
    var v: f64 = 0;
    for (out, xs, 0..) |*o, x, i| {
        v = if (i == 0) x * x else lambda * v + (1 - lambda) * x * x;
        o.* = @sqrt(v * ppy);
    }
    return out;
}

/// Hurst exponent by rescaled-range (R/S) analysis of the series as given
/// (returns, not a level). Block sizes s = 8, 16, 32, ... up to the length; for
/// each, the series is cut into floor(n / s) disjoint blocks and the R/S of
/// each is the range of the running sum of its mean-adjusted values over its
/// population standard deviation (blocks with no spread are skipped); the
/// exponent is the least-squares slope of ln(mean R/S) on ln(s) over the sizes
/// that had any block. About 0.5 for independent returns, below for mean
/// reverting ones (an alternating series gives exactly 0), above for trending.
/// Fewer than two usable sizes (under 16 values, or no spread): 0. NaN on
/// non-finite input; above `max_hurst_len` values also NaN (it has no error set).
pub fn hurstExponent(xs: []const f64) f64 {
    if (!finiteAll(xs) or xs.len > max_hurst_len) return nan;
    var cnt: f64 = 0;
    var sx: f64 = 0;
    var sy: f64 = 0;
    var sxx: f64 = 0;
    var sxy: f64 = 0;
    var s: usize = 8;
    while (s <= xs.len) : (s *= 2) {
        const blocks = xs.len / s;
        var rs_sum: f64 = 0;
        var used: usize = 0;
        for (0..blocks) |bi| {
            const w = xs[bi * s ..][0..s];
            const m = core.mean(w);
            var run: f64 = 0;
            var mx: f64 = 0;
            var mn: f64 = 0;
            var ss: f64 = 0;
            var scale: f64 = 0;
            for (w) |x| {
                scale = @max(scale, @abs(x));
                run += x - m;
                mx = @max(mx, run);
                mn = @min(mn, run);
                ss += (x - m) * (x - m);
            }
            const sd = @sqrt(ss / @as(f64, @floatFromInt(s)));
            if (sd > 8 * std.math.floatEps(f64) * scale and (mx - mn) > 0) {
                rs_sum += (mx - mn) / sd;
                used += 1;
            }
        }
        if (used == 0) continue;
        const x = @log(@as(f64, @floatFromInt(s)));
        const y = @log(rs_sum / @as(f64, @floatFromInt(used)));
        cnt += 1;
        sx += x;
        sy += y;
        sxx += x * x;
        sxy += x * y;
    }
    if (cnt < 2) return 0;
    const den = cnt * sxx - sx * sx;
    if (!(den > 0)) return 0;
    return (cnt * sxy - sx * sy) / den;
}

/// Entropic value at risk of a Gaussian return, as a positive loss:
/// EVaR = -mean + std * sqrt(-2 ln(1 - confidence)), the closed form of
/// inf over z > 0 of (1/z) ln(E[exp(z L)] / (1 - confidence)) for the normal
/// loss L = -return. It is at least the Gaussian VaR and CVaR at the same
/// level. Zero `std`: -mean. NaN for a negative or non-finite `std`, a non-finite
/// mean or a confidence outside (0, 1).
pub fn evarGaussian(mean_: f64, std_: f64, confidence: f64) f64 {
    if (!std.math.isFinite(mean_) or !std.math.isFinite(std_) or std_ < 0) return nan;
    if (!(confidence > 0 and confidence < 1)) return nan;
    return -mean_ + std_ * @sqrt(-2 * @log(1 - confidence));
}

// ── capture, rolling alpha and beta, small converters ───────────────────────

fn captureBad(p: []const f64, b: []const f64, ppy: f64) bool {
    return badPpy(ppy) or !core.compoundable(p) or !core.compoundable(b);
}

/// CAGR of `p` over the CAGR of `b` (empyrical `capture`). A benchmark CAGR of 0: 0.
/// NaN on different lengths, a non-compoundable series or a bad `ppy`.
pub fn capture(p: []const f64, b: []const f64, ppy: f64) f64 {
    if (p.len != b.len or captureBad(p, b, ppy)) return nan;
    const bench = core.cagrOf(b, ppy);
    return if (bench == 0) 0 else core.cagrOf(p, ppy) / bench;
}

/// `capture` over the periods where the benchmark rose (empyrical `up_capture`). No
/// such period: 0. `error.LengthMismatch` on different lengths; NaN on a
/// non-compoundable series or a bad `ppy`.
pub fn upCapture(a: std.mem.Allocator, p: []const f64, b: []const f64, ppy: f64) Error!f64 {
    if (p.len != b.len) return error.LengthMismatch;
    if (captureBad(p, b, ppy)) return nan;
    return core.capture(a, p, b, ppy, true);
}

/// `capture` over the periods where the benchmark fell (empyrical `down_capture`).
/// Conventions of `upCapture`.
pub fn downCapture(a: std.mem.Allocator, p: []const f64, b: []const f64, ppy: f64) Error!f64 {
    if (p.len != b.len) return error.LengthMismatch;
    if (captureBad(p, b, ppy)) return nan;
    return core.capture(a, p, b, ppy, false);
}

fn upDownOf(a: std.mem.Allocator, p: []const f64, b: []const f64, ppy: f64) std.mem.Allocator.Error!f64 {
    const up = try core.capture(a, p, b, ppy, true);
    const down = try core.capture(a, p, b, ppy, false);
    if (down == 0) return if (up > 0) std.math.inf(f64) else 0;
    return up / down;
}

/// `upCapture / downCapture` (empyrical `up_down_capture`). No down capture: +inf for
/// a positive up capture, else 0. Conventions of `upCapture`.
pub fn upDownCapture(a: std.mem.Allocator, p: []const f64, b: []const f64, ppy: f64) Error!f64 {
    if (p.len != b.len) return error.LengthMismatch;
    if (captureBad(p, b, ppy)) return nan;
    return upDownOf(a, p, b, ppy);
}

/// `upDownCapture` of each full trailing window (empyrical `roll_up_down_capture`).
pub fn rollUpDownCapture(a: std.mem.Allocator, p: []const f64, b: []const f64, window: usize, ppy: f64) Error![]f64 {
    if (p.len != b.len) return error.LengthMismatch;
    const out = try a.alloc(f64, try windowCount(p.len, window));
    errdefer a.free(out);
    if (captureBad(p, b, ppy)) {
        @memset(out, nan);
        return out;
    }
    for (out, 0..) |*o, k| o.* = try upDownOf(a, p[k .. k + window], b[k .. k + window], ppy);
    return out;
}

/// `alphaBeta` of each full trailing window (empyrical `roll_alpha_beta`), alpha
/// annualised geometrically. `slice.rollingBetaAlpha` annualises arithmetically.
pub fn rollAlphaBeta(a: std.mem.Allocator, p: []const f64, b: []const f64, window: usize, rf: f64, ppy: f64) Error![]AlphaBeta {
    if (p.len != b.len) return error.LengthMismatch;
    const out = try a.alloc(AlphaBeta, try windowCount(p.len, window));
    for (out, 0..) |*o, k| o.* = alphaBeta(p[k .. k + window], b[k .. k + window], rf, ppy);
    return out;
}

/// {beta, alpha} of each full trailing window with alpha PER PERIOD, mean(p) - beta *
/// mean(b) (quantstats `rolling_greeks`, which pads the first `window - 1` rows with
/// NaN where this has no row; its static `greeks` does annualise, as `slice.greeks`).
pub fn rollingGreeks(a: std.mem.Allocator, p: []const f64, b: []const f64, window: usize) Error![]slice.BetaAlphaPoint {
    return slice.rollingBetaAlpha(a, p, b, window, 1);
}

/// Years from `start` to `end` on a 365.25-day year (ffn `year_frac`). `end` before
/// `start` gives a negative number, where ffn raises. Not a real date: `error.BadDate`.
pub fn yearFrac(start: []const u8, end: []const u8) error{BadDate}!f64 {
    return try slice.daySpan(start, end) / 365.25;
}

/// `func` over `trials` bootstrap samples of `xs`, each `xs.len` values drawn with
/// replacement, seeded by `seed`: one value per trial (ffn `resample_returns`; our
/// PRNG differs from numpy's, so the distribution matches and the numbers do not).
/// Empty series or no trials: no values. Non-finite input: all NaN. Above
/// `max_resample_sims` or `max_resample_cells`: `error.TooLarge`.
pub fn resampleReturns(a: std.mem.Allocator, xs: []const f64, comptime func: fn ([]const f64) f64, seed: u64, trials: usize) Error![]f64 {
    try checkResample(xs.len, trials);
    const out = try a.alloc(f64, if (xs.len == 0) 0 else trials);
    errdefer a.free(out);
    if (!finiteAll(xs)) {
        @memset(out, nan);
        return out;
    }
    const buf = try a.dupe(f64, xs);
    defer a.free(buf);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    for (out) |*o| {
        drawPath(rnd, xs, buf, .bootstrap);
        o.* = func(buf);
    }
    return out;
}
