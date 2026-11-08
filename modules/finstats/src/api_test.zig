// SPDX-License-Identifier: MIT
//! The public functions of `finstats`, each on a small series whose answer is worked
//! out by hand or taken from a published source: xirr and its `Opening` conventions,
//! histogram, risk, benchmark and trade rows, rolling windows, Brinson attribution,
//! the allocation-failure and cap behaviour. The foreign-library vectors are in
//! oracle_test, period_test and attrib_oracle_test.
//!
//! Until 2026-11-08 these ran on `Dataset` columns through functions of `root.zig`;
//! they are the same series and expected values on the slice API.

const std = @import("std");
const testing = std.testing;
const fs = @import("root.zig");

const annualize = fs.annualize;
const quantile = fs.quantile;
const quantileSorted = fs.quantileSorted;
const gaussianVaR = fs.gaussianVaR;
const gaussianCVaR = fs.gaussianCVaR;
const cornishFisherZ = fs.cornishFisherZ;
const cornishFisherVaR = fs.cornishFisherVaR;
const cornishFisherCVaR = fs.cornishFisherCVaR;
const invNormCdf = fs.invNormCdf;
const skewness = fs.skewness;
const excessKurtosis = fs.excessKurtosis;
const omegaRatio = fs.omegaRatio;
const winRate = fs.winRate;
const payoffRatio = fs.payoffRatio;
const profitFactor = fs.profitFactor;
const kellyCriterion = fs.kellyCriterion;
const tailRatio = fs.tailRatio;

const Fix = struct {
    arena: std.heap.ArenaAllocator,
    fn init() Fix {
        return .{ .arena = std.heap.ArenaAllocator.init(testing.allocator) };
    }
    fn deinit(self: *Fix) void {
        self.arena.deinit();
    }
    fn a(self: *Fix) std.mem.Allocator {
        return self.arena.allocator();
    }
};

/// `xirr` at the default `rate_tol`, with the `Opening` the test names.
fn xi(a: std.mem.Allocator, dates: []const []const u8, flows: []const f64, values: []const f64, opening: fs.Opening) fs.XirrError!f64 {
    return fs.xirr(a, dates, flows, values, opening, fs.default_rate_tol);
}

/// `xirrPrecise` with default options.
fn xp(a: std.mem.Allocator, dates: []const []const u8, flows: []const f64, values: []const f64, opening: fs.Opening) fs.XirrError!f64 {
    return fs.xirrPrecise(a, dates, flows, values, opening, .{});
}

test "scratch allocations are released: EVERY allocating public fn, on std.testing.allocator" {
    // Every other test here runs on an arena, which bulk-frees, so a function that
    // never released its scratch looked identical to one that did. The list is every
    // public fn of the plain-series surface that takes an allocator, so a new one
    // cannot be added without either appearing here or leaving this test to be edited
    // deliberately. The dip in `lv` is load-bearing: with a monotonically rising level
    // `drawdownEpisodes` never appends, its scratch list never allocates and removing
    // its `deinit` left the test green. A call is not coverage until it makes the
    // function allocate.
    const a = testing.allocator;
    const dates = [_][]const u8{ "2023-01-01", "2023-07-01", "2024-01-01" };
    const flow = [_]f64{ 100, 0, 0 };
    const v = [_]f64{ 100, 90, 200 };
    const ret = [_]f64{ 0.01, -0.02, 0.03 };
    const bench = [_]f64{ 0.008, -0.015, 0.025 };
    const pe = [_]f64{ 100, 100, 150 };

    _ = try xi(a, &dates, &flow, &v, .none);
    _ = try xp(a, &dates, &flow, &v, .none);
    _ = try quantile(a, &[_]f64{ 0.3, 0.1, 0.2 }, 0.5);
    _ = try tailRatio(a, &[_]f64{ 0.3, -0.1, 0.2 });
    a.free(try fs.twrDaily(a, &v, &flow, &pe, 0));
    a.free(try fs.histogram(a, &v, 4));
    _ = try fs.riskMetrics(a, &ret, .{});
    _ = try fs.benchmarkStats(a, &ret, &bench, 0.1, 0, 252);
    a.free(try fs.monteCarlo(a, .{ .start = 1000, .mu_ann = 0.07, .vol_ann = 0.15, .monthly = 100, .years = 1, .paths = 32 }));
    a.free(try fs.drawdownEpisodes(a, &dates, &v, 5));
    a.free(try fs.rollingApply(a, &v, 2, fs.rollingMeanReducer));
    a.free(try fs.rollingMean(a, &v, 2));
    a.free(try fs.rollingVolatility(a, &v, 2));
    a.free(try fs.rollingSharpe(a, &v, 2));
    a.free(try fs.rollingBetaAlpha(a, &ret, &bench, 2, 252));
    _ = try fs.tradeStats(a, &ret);
    _ = try fs.varHistoric(a, &ret, 0.95);
    _ = try fs.cvarHistoric(a, &ret, 0.95);
    a.free(try fs.cumulativeReturns(a, &ret));
    a.free(try fs.drawdownSeries(a, &ret));

    // `correlationMatrix` and `brinsonAttribution` return their own storage.
    const cx = [_]f64{ 1.0, 2.0, 1.5 };
    const cy = [_]f64{ 2.0, 3.0, 2.5 };
    a.free(try fs.correlationMatrix(a, &.{ &cx, &cy }, 2));
    const br = try fs.brinsonAttribution(a, &.{ 0.6, 0.4 }, &.{ 0.5, 0.5 }, &.{ 0.10, 0.03 }, &.{ 0.08, 0.04 });
    a.free(br.rows);
}

test "xirr: a mid-life window needs `opening`; without it there is no root, and no root is an ERROR" {
    var f = Fix.init();
    defer f.deinit();
    // A series that starts mid-life: 1000 already in the position on day one,
    // no flows at all, 1100 a year later. The money-weighted return is +10 %/y.
    const dates = [_][]const u8{ "2024-01-01", "2025-01-01" };
    const flow = [_]f64{ 0, 0 };
    const v = [_]f64{ 1000, 1100 };

    // Seeded: the opening 1000 is a cashflow, so NPV crosses zero at ~+10 %.
    // (366 calendar days over a 365.25 year -> 0.0998, not exactly 0.10.)
    const r = try xi(f.a(), &dates, &flow, &v, .value_includes_flow);
    try testing.expectApproxEqAbs(@as(f64, 0.0998), r, 0.002);

    // Unseeded: the only cashflow is the terminal +1100, so NPV is positive at
    // every rate in the bracket. This used to bisect its way to `hi` and hand
    // back 10.0 -- a confident +1000 % -- which is what reached a KPI card.
    try testing.expectError(error.XirrNoRoot, xi(f.a(), &dates, &flow, &v, .none));
    try testing.expectError(error.XirrNoRoot, xp(f.a(), &dates, &flow, &v, .none));
}

test "xirr: a one-row window has NO unique rate: every rate is a root, so none of them is the answer" {
    var f = Fix.init();
    defer f.deinit();
    // One row, which is what a window narrow enough to hold a single
    // observation collapses to. Reported from a consumer against a real
    // database (a one-day date range), where it came back as +999.9999 % and
    // was indistinguishable at the call site from a real answer.
    const dates = [_][]const u8{"2026-08-24"};
    const flow = [_]f64{0};
    const v = [_]f64{1000};

    // WHY THE SIGN-CHANGE CHECK CANNOT SEE THIS. Every cashflow lands on the
    // same date, so every discount exponent is 0 and NPV is the CONSTANT sum of
    // cf at every rate in the bracket. Under `.value_includes_flow` the seed is
    // -value[0] and the terminal is +value[0], so that constant is exactly 0 --
    // and a bound that IS zero used to read as "a root exists", which is true
    // and useless: every rate is a root, so no rate is the answer. Bisection
    // then walked its 200 halvings to `hi`.
    try testing.expectError(error.XirrNoRoot, xi(f.a(), &dates, &flow, &v, .value_includes_flow));
    try testing.expectError(error.XirrNoRoot, xp(f.a(), &dates, &flow, &v, .value_includes_flow));

    // The other half of the same shape, and the reason the fix is stated as
    // "NPV is constant" rather than as a row count: unseeded, the one cashflow
    // is the terminal +1000, so NPV is the constant 1000 -- no root at all, and
    // the sign-change check already rejected that one on its own.
    try testing.expectError(error.XirrNoRoot, xi(f.a(), &dates, &flow, &v, .none));
}

test "xirr: an empty window is a detectable EmptyWindow, not a confident 0.0" {
    // A1 finding (MEDIUM): an empty series returned success with `0.0`, the same
    // "non-answer that looks like an answer" shape the XirrNoRoot fix closed. An
    // empty date-range window (a day with zero rows) is more common than one that
    // selects exactly one row, and a caller reading `0.0` as "no return" cannot tell
    // it apart from a genuine 0% IRR.
    var f = Fix.init();
    defer f.deinit();
    const dates: []const []const u8 = &.{};
    const none: []const f64 = &.{};
    try testing.expectError(error.EmptyWindow, xi(f.a(), dates, none, none, .none));
    try testing.expectError(error.EmptyWindow, xp(f.a(), dates, none, none, .none));
}

test "xirr: the two `opening` conventions differ when row 0 carries a flow (pins which one skips it)" {
    var f = Fix.init();
    defer f.deinit();
    // Row 0 has BOTH a 1000 value and a 1000 flow. Whether those are the same
    // 1000 is invisible in the data, which is the whole reason `Opening` is an
    // enum rather than a bool: the two readings give wildly different answers.
    const dates = [_][]const u8{ "2024-01-01", "2025-01-01" };
    const flow = [_]f64{ 1000, 0 };
    const v = [_]f64{ 1000, 1100 };

    // `value[0]` is end-of-day and already contains the flow -> count it once.
    // 1000 in, 1100 out -> the same ~+10 % as the flow-free fixture above.
    const inc = try xi(f.a(), &dates, &flow, &v, .value_includes_flow);
    try testing.expectApproxEqAbs(@as(f64, 0.0998), inc, 0.002);

    // `value[0]` is the opening figure taken BEFORE the flow -> 2000 went in for
    // an 1100 exit. Sign-flipped and nowhere near the other reading.
    const exc = try xi(f.a(), &dates, &flow, &v, .value_excludes_flow);
    try testing.expectApproxEqAbs(@as(f64, -0.449), exc, 0.003);
    try testing.expect(inc > 0 and exc < 0);
}

// Inception-to-date: 1000 in at the start, 500 more a year later, worth 2100 after
// two years. `v` is end-of-day, so the 1700 on 2023-01-01 already contains that
// day's 500 contribution.
const life_dates = [_][]const u8{ "2022-01-01", "2022-07-01", "2023-01-01", "2023-07-01", "2024-01-01" };
const life_flow = [_]f64{ 1000, 0, 500, 0, 0 };
const life_v = [_]f64{ 1000, 1100, 1700, 1900, 2100 };

test "xirr: lifetime is untouched, and the same fixture windowed lands on the window's time-weighted return" {
    var f = Fix.init();
    defer f.deinit();
    // Lifetime, `.none` -- the whole history, which starts from nothing.
    const lifetime = try xi(f.a(), &life_dates, &life_flow, &life_v, .none);
    try testing.expect(lifetime > 0.15 and lifetime < 0.30);

    // The last three rows are the "1 year" window. No flows occur inside it
    // after the seed, so its time-weighted return is exactly 2100/1700 - 1 and
    // the money-weighted return must agree with it -- an oracle, not a range.
    const windowed = try xi(f.a(), life_dates[2..], life_flow[2..], life_v[2..], .value_includes_flow);
    const twr = 2100.0 / 1700.0 - 1.0; // +23.53 % over 365 days
    try testing.expectApproxEqAbs(twr, windowed, 0.002);

    // ...and the same window WITHOUT the seed shows why `opening` is the fix and
    // `XirrNoRoot` is only a backstop. Here the window's first row happens to
    // carry a 500 flow, so the un-seeded cashflows are [-500, +2100] -- that DOES
    // bracket a root, and bisection converges on it happily. The answer is the
    // IRR of a different question (500 in, 2100 out) and comes back finite,
    // plausibly shaped and more than an order of magnitude wrong. No guard
    // catches this one: only seeding the opening balance does.
    const unseeded = try xi(f.a(), life_dates[2..], life_flow[2..], life_v[2..], .none);
    try testing.expectApproxEqAbs(@as(f64, 3.204), unseeded, 0.01); // +320 % vs the true +23.5 %
    try testing.expect(unseeded > 10 * windowed);
}

test "xirrPrecise: the same window, against an independent oracle: the Newton path's missing half" {
    // The sibling of the `xirr` test above. It matters most on THIS path: the case
    // the whole `opening` change exists for -- a window whose first row carries a
    // flow -- is the one no runtime guard can catch, because it genuinely brackets a
    // root. The sign-change check passes, Newton converges quickly and confidently,
    // and the answer belongs to a different question.
    var f = Fix.init();
    defer f.deinit();
    // Lifetime, `.none`, and it must agree with the bisection sibling, which is
    // what makes them two implementations of one definition.
    const lifetime = try xp(f.a(), &life_dates, &life_flow, &life_v, .none);
    try testing.expect(lifetime > 0.15 and lifetime < 0.30);
    const lifetime_bisected = try xi(f.a(), &life_dates, &life_flow, &life_v, .none);
    try testing.expectApproxEqAbs(lifetime_bisected, lifetime, 1e-6);

    // The last three rows are the "1 year" window, seeded. No flow occurs
    // inside it after the seed, so the money-weighted answer must equal the
    // time-weighted one -- an oracle computed from the data, not from another
    // root-finder.
    const windowed = try xp(f.a(), life_dates[2..], life_flow[2..], life_v[2..], .value_includes_flow);
    const twr = 2100.0 / 1700.0 - 1.0; // +23.53 % over 365 days
    try testing.expectApproxEqAbs(twr, windowed, 0.002);

    // And a second, sharper oracle that only the Newton path can be held to: two
    // cashflows have a CLOSED FORM for the IRR, so this is arithmetic rather than a
    // second search. Bisection's `1e-2` on NPV could not be asked this question;
    // Newton's `1e-8` can, which is the point of having the precise sibling at all.
    const exact = std.math.pow(f64, 2100.0 / 1700.0, 365.25 / 365.0) - 1.0;
    try testing.expectApproxEqAbs(exact, windowed, 1e-9);

    // ...and the same window WITHOUT the seed. The un-seeded cashflows are
    // [-500, +2100]: that DOES bracket a root, so `bracketHasRoot` passes and
    // Newton converges -- on the IRR of "500 in, 2100 out", which is finite,
    // plausibly shaped and more than an order of magnitude wrong. Nothing at
    // runtime catches this; only seeding the opening balance does, which is
    // why `opening` has no default.
    const unseeded = try xp(f.a(), life_dates[2..], life_flow[2..], life_v[2..], .none);
    const exact_wrong = std.math.pow(f64, 2100.0 / 500.0, 365.25 / 365.0) - 1.0;
    try testing.expectApproxEqAbs(exact_wrong, unseeded, 1e-9); // +320 % vs the true +23.5 %
    try testing.expect(unseeded > 10 * windowed);
}

test "xirr: convergence is measured in the ANSWER's units: an absolute NPV threshold is scale-dependent" {
    var f = Fix.init();
    defer f.deinit();
    // The SAME +10 %/year question, asked at two magnitudes. Nothing about the
    // answer depends on the units the cashflows are denominated in.
    const dates = [_][]const u8{ "2024-01-01", "2025-01-01" };
    const small_flow = [_]f64{ 0.01, 0 };
    const small_v = [_]f64{ 0.01, 0.011 };
    const large_flow = [_]f64{ 1_000_000, 0 };
    const large_v = [_]f64{ 1_000_000, 1_100_000 };

    const r_small = try xi(f.a(), &dates, &small_flow, &small_v, .none);
    const r_large = try xi(f.a(), &dates, &large_flow, &large_v, .none);
    try testing.expectApproxEqAbs(@as(f64, 0.0998), r_small, 0.001);
    try testing.expectApproxEqAbs(@as(f64, 0.0998), r_large, 0.001);
    try testing.expectApproxEqAbs(r_small, r_large, 1e-6); // scale-free

    // `rate_tol = null` restores the pre-2026-08-23 test, which was |NPV| <
    // 1e-2 and nothing else. On the small series that threshold is met at the
    // very FIRST midpoint of [-0.99, 10] -- so it returned 4.505, i.e. +450 %,
    // for a series returning 10 %. Same silently-plausible shape as the bracket
    // bound; the sign-change check cannot see it, because there IS a root here.
    const r_legacy = try fs.xirr(f.a(), &dates, &small_flow, &small_v, .none, null);
    try testing.expectApproxEqAbs(@as(f64, 4.505), r_legacy, 1e-9);
    try testing.expect(r_legacy > 40 * r_small);
}

test "xirr: the cost of `rate_tol = null` is measured here, not quoted" {
    // `default_rate_tol`'s doc comment publishes a MEASURED table, and this test IS
    // its construction: the rows, dates and magnitudes are exactly these, and every
    // published cell is asserted below. Change the algorithm and this goes red
    // rather than the comment going quietly stale. Synthetic throughout.
    var f = Fix.init();
    defer f.deinit();
    const dates = [_][]const u8{ "2024-01-01", "2025-01-01" };

    // Magnitude, and the published error in percentage points of the annual
    // rate. Quoted to four significant figures, which is what the table shows.
    const table = [_]struct { m: f64, err_pp: f64 }{
        .{ .m = 0.01, .err_pp = 440.5 },
        .{ .m = 0.1, .err_pp = 5.947 },
        .{ .m = 1, .err_pp = 0.4922 },
        .{ .m = 10, .err_pp = 0.04444 },
        .{ .m = 100, .err_pp = 0.01090 },
        .{ .m = 1e3, .err_pp = 4.165e-4 },
        .{ .m = 1e6, .err_pp = 1.056e-6 },
    };

    for (table) |row| {
        // 366 calendar days over a 365.25-day year -- hence 0.0997852, not 0.10.
        const flow = [_]f64{ row.m, 0 };
        const v = [_]f64{ row.m, 1.1 * row.m };
        const with_tol = try xi(f.a(), &dates, &flow, &v, .none);
        const without = try fs.xirr(f.a(), &dates, &flow, &v, .none, null);
        // The reference leg is scale-free at every magnitude: that is what
        // makes the other leg's spread an ERROR and not a property of the
        // question being asked.
        try testing.expectApproxEqAbs(@as(f64, 0.0997852), with_tol, 1e-6);
        try testing.expectApproxEqRel(row.err_pp, @abs(without - with_tol) * 100.0, 1e-3);
    }

    // The two claims the prose makes on top of the table.
    const bisect_stop = struct {
        fn stop(fx: *Fix, d: []const []const u8, m: f64) !f64 {
            return fs.xirr(fx.a(), d, &.{ m, 0 }, &.{ m, 1.1 * m }, .none, null);
        }
    }.stop;
    // "crosses a basis point between M = 100 and M = 300".
    const ref = 0.0997851787;
    try testing.expect(@abs(try bisect_stop(&f, &dates, 100) - ref) * 100.0 > 0.01);
    try testing.expect(@abs(try bisect_stop(&f, &dates, 300) - ref) * 100.0 < 0.01);
    // "not a curve": two different magnitudes stop on the identical midpoint,
    // and it is the one the doc quotes.
    const stop_3 = try bisect_stop(&f, &dates, 3);
    try testing.expectEqual(stop_3, try bisect_stop(&f, &dates, 10));
    try testing.expectApproxEqAbs(@as(f64, 0.09934082), stop_3, 5e-9);
}

test "xirrPrecise: a Newton budget too small to meet `tol` still lands on the same answer" {
    var f = Fix.init();
    defer f.deinit();
    // |NPV| < 1e-8 is unreachable at this magnitude in f64, so with only the
    // absolute test Newton exhausted its budget however exactly it had landed
    // and every call paid for the bisection fallback as well. The rate-space
    // return added for that is a WORK saving, not an answer change, and this
    // test says so rather than pretending otherwise: deleting it leaves the
    // suite green, because the fallback lands in the same place. What is pinned
    // here is that the two paths agree.
    const dates = [_][]const u8{ "2024-01-01", "2025-01-01" };
    const flow = [_]f64{ 1e9, 0 };
    const v = [_]f64{ 1e9, 1.1e9 };
    const r = try xp(f.a(), &dates, &flow, &v, .none);
    try testing.expectApproxEqAbs(@as(f64, 0.0998), r, 0.001);

    // Two Newton steps from the 0.1 guess, versus the full 50: same answer to
    // 1e-12 whichever phase produced it.
    const r2 = try fs.xirrPrecise(f.a(), &dates, &flow, &v, .none, .{ .max_newton_iter = 2 });
    try testing.expectApproxEqAbs(r, r2, 1e-12);

    // And the legacy absolute-only mode agrees too -- at THIS magnitude. The
    // scale-dependence that makes `rate_tol` worth having bites small
    // cashflows, not large ones; see the `xirr` test above for where it does.
    const r3 = try fs.xirrPrecise(f.a(), &dates, &flow, &v, .none, .{ .rate_tol = null });
    try testing.expectApproxEqAbs(r, r3, 1e-12);
}

test "xirrPrecise: a doubling in a year is 2^(365.25/365) - 1, and a mid-life window declared `.none` has no root" {
    // Newton lands far tighter than bisection would: tight enough to show that the
    // answer is NOT 100 %: 365 days over a 365.25-day year is 2^(365.25/365) - 1 =
    // 100.095 % (the old `xirrPreciseNode` test asserted 100.0949 after its x100).
    var f = Fix.init();
    defer f.deinit();
    const dates = [_][]const u8{ "2023-01-01", "2024-01-01" };
    const flow = [_]f64{ 100, 0 };
    const v = [_]f64{ 100, 200 }; // IRR ~ 100 %
    const r = try xp(f.a(), &dates, &flow, &v, .none);
    try testing.expectApproxEqAbs(@as(f64, 1.000949), r, 1e-5);
    // bisection, to the ~1 % its |NPV| threshold allows (the old `xirrNode` test)
    try testing.expectApproxEqAbs(@as(f64, 1), try fs.xirr(f.a(), &dates, &flow, &v, .none, null), 0.02);

    // A mid-life window declared `.none` has no root, and the answer says so.
    try testing.expectError(error.XirrNoRoot, xp(f.a(), dates[1..], flow[1..], v[1..], .none));
}

test "annualize: CAGR of a cumulative return over the day span" {
    // The old `annualizeNode` test: +100 % between 2023-01-01 and 2024-01-01.
    try testing.expectApproxEqAbs(@as(f64, 1.0), annualize(1.0, try fs.daySpan("2023-01-01", "2024-01-01")), 0.01);
}

test "twrDaily: Modified-Dietz" {
    var f = Fix.init();
    defer f.deinit();
    const t = try fs.twrDaily(f.a(), &.{ 100, 110, 121 }, &.{ 0, 0, 0 }, &.{ 100, 100, 110 }, 0);
    try testing.expectEqual(@as(usize, 2), t.len);
    try testing.expectEqual(@as(usize, 1), t[0].row);
    try testing.expectEqual(@as(usize, 2), t[1].row);
    try testing.expectApproxEqAbs(@as(f64, 0.1), t[0].r, 1e-9); // r = 0.1
    try testing.expectApproxEqAbs(@as(f64, 0.1), t[1].r, 1e-9); // r = 0.1
}

test "quantile linear interp + histogram" {
    var f = Fix.init();
    defer f.deinit();
    const s = [_]f64{ 1, 2, 3, 4 };
    try testing.expectApproxEqAbs(@as(f64, 2.5), quantileSorted(&s, 0.5), 1e-9);

    const h = try fs.histogram(f.a(), &.{ 0, 1, 2, 10 }, 5);
    try testing.expectEqual(@as(usize, 5), h.len);
    // total count == number of values
    var total: u64 = 0;
    for (h) |b| total += b.count;
    try testing.expectEqual(@as(u64, 4), total);
    try testing.expectEqual(@as(u64, 1), h[4].count); // the 10 lands in last bin
}

test "histogram excludes NaN rows instead of silently binning them at 0" {
    // A1 finding (LOW): a NaN `@intFromFloat(@floor(NaN))` -- measured NOT to
    // panic here even in Debug -- lands in the `b < 0` clamp and was silently
    // counted in bucket 0, indistinguishable from a genuine minimum-value row.
    // Reachable from this module's own `annualize`, which is NaN for a position down
    // more than 100%.
    var f = Fix.init();
    defer f.deinit();
    const h = try fs.histogram(f.a(), &.{ 0, std.math.nan(f64), 1, 10 }, 5);
    var total: u64 = 0;
    for (h) |b| total += b.count;
    // Only the three finite rows land in a bucket -- the NaN row is
    // excluded entirely, not silently folded into bucket 0.
    try testing.expectEqual(@as(u64, 3), total);
}

test "histogram: an infinite value is excluded, not NaN-ing every edge and every index" {
    // Same shape as the NaN finding above, reached through the OTHER non-finite
    // value. A single -inf row made `span` infinite, so `(v - lo) / span` was NaN
    // for EVERY row -- finite ones included -- and all of them fell through the
    // `b < 0` clamp into bucket 0 while every emitted edge printed `-nan`. Measured
    // identical in Debug, ReleaseSafe and ReleaseFast: no mode panicked, so
    // nothing but a test stood between this and a wrong chart.
    var f = Fix.init();
    defer f.deinit();
    const h = try fs.histogram(f.a(), &.{ -std.math.inf(f64), 5, 1 }, 5);
    try testing.expectEqual(@as(usize, 5), h.len);
    // Every edge is a real number -- the range is [1, 5], set by the finite
    // rows alone.
    try testing.expectEqual(@as(f64, 1), h[0].lo);
    try testing.expectEqual(@as(f64, 5), h[4].hi);
    for (h) |b| {
        try testing.expect(std.math.isFinite(b.lo));
        try testing.expect(std.math.isFinite(b.hi));
    }
    // The seam: the two finite rows land in DIFFERENT buckets. A regression
    // that lets the infinity back in puts all three in bucket 0, and a total
    // of 2 alone would not catch that.
    try testing.expectEqual(@as(u64, 1), h[0].count);
    try testing.expectEqual(@as(u64, 1), h[4].count);
    var total: u64 = 0;
    for (h) |b| total += b.count;
    try testing.expectEqual(@as(u64, 2), total);
}

test "histogram: no finite row is ZERO bins, not `bins` rows of inf-to-inf" {
    // Reported by a downstream consumer, 2026-09-17. `lo`/`hi` kept their
    // +inf/-inf seeds when every row was skipped, and each edge came out +inf: a
    // SUCCESSFUL result describing twelve bins from inf to inf -- the "non-answer
    // that looks like an answer" shape `xirr` raises `error.EmptyWindow` for.
    var f = Fix.init();
    defer f.deinit();
    const nan = std.math.nan(f64);
    const inf = std.math.inf(f64);

    try testing.expectEqual(@as(usize, 0), (try fs.histogram(f.a(), &.{}, 3)).len);
    // The all-NaN case is the reachable one: `annualize` is NaN for a position down
    // more than 100%, so a portfolio of those alone lands here.
    try testing.expectEqual(@as(usize, 0), (try fs.histogram(f.a(), &.{ nan, nan }, 3)).len);
    // An all-infinity column is the same non-answer for the same reason.
    try testing.expectEqual(@as(usize, 0), (try fs.histogram(f.a(), &.{ inf, -inf }, 3)).len);

    // One finite row is NOT the empty case -- it has a range (a degenerate one,
    // span falls back to 1) and must still produce its bins. Without this,
    // "return zero rows whenever the data look thin" would pass.
    const h3 = try fs.histogram(f.a(), &.{7}, 3);
    try testing.expectEqual(@as(usize, 3), h3.len);
    try testing.expectEqual(@as(f64, 7), h3[0].lo);
    try testing.expectEqual(@as(u64, 1), h3[0].count);
}

test "annualize CAGR" {
    try testing.expectApproxEqAbs(@as(f64, 1.0), annualize(1.0, 365.25), 1e-9); // double in 1y → 100%
    try testing.expectApproxEqAbs(@as(f64, 0.0), annualize(0.0, 100), 1e-12);
}

test "quantileSorted: out-of-range q is clamped instead of panicking (audit F1)" {
    // Batch: q was fed straight into @intFromFloat(@floor(q*(n-1))); a q < 0
    // (e.g. a 0-100 vs 0-1 convention mixup) panicked in ReleaseSafe / OOB-read
    // in ReleaseFast. It is now clamped into [0,1] (NaN -> 0).
    const s = [_]f64{ 1, 2, 3, 4 };
    try testing.expectEqual(@as(f64, 1), quantileSorted(&s, -0.5)); // was a panic
    try testing.expectEqual(@as(f64, 4), quantileSorted(&s, 2.0));
    try testing.expectEqual(@as(f64, 1), quantileSorted(&s, std.math.nan(f64)));
}

test "gaussianVaR/CVaR: standard-normal known values at 95%" {
    // textbook standard-normal 95% VaR/CVaR: z_0.05 ≈ -1.6449, ES ≈ 2.0627
    const v = gaussianVaR(0, 1, 0.95);
    const cv = gaussianCVaR(0, 1, 0.95);
    try testing.expectApproxEqAbs(@as(f64, 1.6449), v, 1e-3);
    try testing.expectApproxEqAbs(@as(f64, 2.0627), cv, 1e-3);
    try testing.expect(cv >= v); // CVaR >= VaR invariant (positive control)
}

test "cornishFisherZ collapses to the raw z-score when skew=kurt=0" {
    const z = invNormCdf(0.05);
    try testing.expectApproxEqAbs(z, cornishFisherZ(z, 0, 0), 1e-12);
}

test "skewness/excessKurtosis: symmetric fixture has known moments" {
    const xs = [_]f64{ -2, -1, 0, 1, 2 };
    try testing.expectApproxEqAbs(@as(f64, 0), skewness(&xs), 1e-9); // symmetric -> 0
    try testing.expectApproxEqAbs(@as(f64, -1.3), excessKurtosis(&xs), 1e-9); // platykurtic, hand-computed
}

test "cornishFisherVaR/CVaR: negative skew + fat tail widens the tail vs Gaussian" {
    // hand-computed via the same Acklam approximation + CF expansion (see tool notes)
    const mean_ = 0.001;
    const std_dev = 0.02;
    const skew = -1.0;
    const kurt = 2.0;
    const conf = 0.95;
    const var_g = gaussianVaR(mean_, std_dev, conf);
    const cvar_g = gaussianCVaR(mean_, std_dev, conf);
    const var_cf = cornishFisherVaR(mean_, std_dev, skew, kurt, conf);
    const cvar_cf = cornishFisherCVaR(mean_, std_dev, skew, kurt, conf);

    try testing.expectApproxEqAbs(@as(f64, 0.036399), var_cf, 1e-3);
    try testing.expectApproxEqAbs(@as(f64, 0.052410), cvar_cf, 2e-3); // quadrature, looser tol

    // positive controls: negative skew + excess kurtosis must widen (not
    // shrink) the tail relative to the Gaussian fit, and CVaR >= VaR must
    // still hold for the CF variant (the naive phi(z_cf)/alpha shortcut
    // FAILS this for these exact inputs -- see cornishFisherCVaR's doc comment).
    try testing.expect(var_cf > var_g);
    try testing.expect(cvar_cf >= var_cf);
    try testing.expect(cvar_g >= var_g); // Gaussian side of the same invariant
}

test "omegaRatio: hand-computed threshold-0 ratio + infinite-when-no-losses control" {
    const xs = [_]f64{ 0.01, -0.02, 0.03, -0.01, 0.02 };
    // gains = 0.01+0.03+0.02 = 0.06; losses = 0.02+0.01 = 0.03 -> omega = 2.0
    try testing.expectApproxEqAbs(@as(f64, 2.0), omegaRatio(&xs, 0), 1e-9);

    const all_gains = [_]f64{ 0.01, 0.02, 0.03 };
    try testing.expect(std.math.isPositiveInf(omegaRatio(&all_gains, 0))); // no losses -> +inf

    const flat = [_]f64{ 0, 0, 0 };
    try testing.expectApproxEqAbs(@as(f64, 1.0), omegaRatio(&flat, 0), 1e-9); // flat at threshold -> 1.0
}

test "quantile: unsorted-slice wrapper sorts a COPY and matches quantileSorted (mutation guard)" {
    // `quantile` had no test call site at all -- only `quantileSorted` (the
    // pre-sorted primitive) was ever exercised directly. Feed it genuinely
    // unsorted input so the sort step is load-bearing, and confirm the
    // original slice is left untouched (it dupes before sorting).
    var f = Fix.init();
    defer f.deinit();
    // q = 0.25, deliberately NOT 0.5 -- a 0.5 probe is symmetric under a
    // q -> 1-q mutation (the wrong answer would equal the right one).
    const xs = [_]f64{ 3, 1, 4, 1, 5, 9, 2, 6 };
    const got = try quantile(f.a(), &xs, 0.25);
    var sorted_copy = xs;
    std.mem.sort(f64, &sorted_copy, {}, std.sort.asc(f64));
    try testing.expectApproxEqAbs(quantileSorted(&sorted_copy, 0.25), got, 1e-9);
    // The caller's original slice must be untouched (unsorted-order proof).
    try testing.expectEqual(@as(f64, 3), xs[0]);
    try testing.expectEqual(@as(f64, 6), xs[7]);
}

test "riskMetrics: basic invariants" {
    var f = Fix.init();
    defer f.deinit();
    const rm = try fs.riskMetrics(f.a(), &.{ 0.01, -0.02, 0.015, -0.005, 0.02 }, .{ .ann_return = 0.1 });
    try testing.expect(rm.ann_vol > 0);
    try testing.expect(rm.mdd <= 0);
    try testing.expect(rm.var95 >= 0); // -q05, q05 negative
}

test "betaAlpha: identical series -> beta 1, r2 1, alpha 0" {
    const x = [_]f64{ 0.01, -0.02, 0.03 };
    const ba = fs.betaAlpha(&x, &x, 0.1, 0.1);
    try testing.expectApproxEqAbs(@as(f64, 1), ba.beta, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 1), ba.r2, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 0), ba.alpha, 1e-9);
}

test "monteCarlo: deterministic percentile ordering" {
    var f = Fix.init();
    defer f.deinit();
    const mc = try fs.monteCarlo(f.a(), .{ .start = 10000, .mu_ann = 0.07, .vol_ann = 0.15, .monthly = 100, .years = 5, .paths = 500 });
    try testing.expectEqual(@as(usize, 61), mc.len); // 5*12 + 1
    // percentiles must be ordered and grow beyond the start at the horizon
    const last = mc.len - 1;
    try testing.expect(mc[last].p10 <= mc[last].p50);
    try testing.expect(mc[last].p50 <= mc[last].p90);
    try testing.expectEqual(@as(f64, 10000), mc[0].p50); // t=0 all == start
}

test "correlationMatrix: min-overlap gating" {
    var f = Fix.init();
    defer f.deinit();
    // two series perfectly correlated over 3 shared positions (< min_overlap 30)
    const x = [_]f64{ 0.01, 0.02, 0.03 };
    const y = [_]f64{ 0.02, 0.04, 0.06 };
    const m = try fs.correlationMatrix(f.a(), &.{ &x, &y }, 30);
    try testing.expectApproxEqAbs(@as(f64, 1), m[0], 1e-12); // diagonal
    try testing.expect(std.math.isNan(m[1])); // only 3 overlap < 30 -> NaN

    // with min_overlap = 3 the off-diagonal becomes a real correlation (== 1 here)
    const m2 = try fs.correlationMatrix(f.a(), &.{ &x, &y }, 3);
    try testing.expectApproxEqAbs(@as(f64, 1), m2[1], 1e-9);
}

test "drawdownEpisodes: state machine" {
    var f = Fix.init();
    defer f.deinit();
    const dates = [_][]const u8{ "2024-01-01", "2024-01-02", "2024-01-03", "2024-01-04", "2024-01-05" };
    // 80 is the trough, 100 recovers, 120 is a new peak, 90 is under water with no recovery
    const e = try fs.drawdownEpisodes(f.a(), &dates, &.{ 100, 80, 100, 120, 90 }, 5);
    try testing.expectEqual(@as(usize, 2), e.len);
    // worst first: -25% (120->90) then -20% (100->80)
    try testing.expectApproxEqAbs(@as(f64, -25), e[0].depth * 100, 1e-9);
    try testing.expect(e[0].recovery_i == null); // still underwater
    try testing.expectApproxEqAbs(@as(f64, -20), e[1].depth * 100, 1e-9);
    try testing.expectEqualStrings("2024-01-03", dates[e[1].recovery_i.?]);
}

test "xirrPrecise: known-IRR fixture (100 -> 121 over ~2y = ~10% IRR)" {
    var f = Fix.init();
    defer f.deinit();
    // hand-computed: 731 calendar days / 365.25 = 2.001369y; (121/100)^(1/y)-1 = 0.0999283
    const dates = [_][]const u8{ "2020-01-01", "2022-01-01" };
    const flow = [_]f64{ 100, 0 };
    const v = [_]f64{ 100, 121 };
    const r = try xp(f.a(), &dates, &flow, &v, .none);
    try testing.expectApproxEqAbs(@as(f64, 0.0999283), r, 1e-3);

    // fallback: max_newton_iter=1 forces Newton to bail before converging;
    // the bisection fallback must still land on the same answer.
    const r2 = try fs.xirrPrecise(f.a(), &dates, &flow, &v, .none, .{ .max_newton_iter = 1, .tol = 1e-6 });
    try testing.expectApproxEqAbs(@as(f64, 0.0999283), r2, 1e-3);
}

test "parametricRisk: every field is the scalar function's answer" {
    const xs = [_]f64{ -2, -1, 0, 1, 2 };
    const pr = fs.parametricRisk(&xs, 0.95);
    try testing.expectApproxEqAbs(@as(f64, 0), pr.mean, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0), pr.skew, 1e-9);
    try testing.expectApproxEqAbs(gaussianVaR(pr.mean, pr.std, 0.95), pr.var_gaussian, 1e-12);
    try testing.expectApproxEqAbs(gaussianCVaR(pr.mean, pr.std, 0.95), pr.cvar_gaussian, 1e-12);
    try testing.expectApproxEqAbs(cornishFisherVaR(pr.mean, pr.std, pr.skew, pr.kurt, 0.95), pr.var_cf, 1e-12);
    try testing.expectApproxEqAbs(cornishFisherCVaR(pr.mean, pr.std, pr.skew, pr.kurt, 0.95), pr.cvar_cf, 1e-12);
    try testing.expect(pr.cvar_gaussian >= pr.var_gaussian);
}

test "trackingRisk: tracking error + information ratio, hand-computed" {
    // active = p - b = [0.01, -0.02, 0.03, 0.0, 0.02]; mean=0.008, sample-std=0.0192354
    const p = [_]f64{ 0.02, -0.01, 0.04, 0.01, 0.03 };
    const b = [_]f64{ 0.01, 0.01, 0.01, 0.01, 0.01 };
    const tr = fs.trackingRisk(&p, &b, 1);
    try testing.expectApproxEqAbs(@as(f64, 0.0192354), tr.tracking_error, 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 0.4159), tr.information_ratio, 1e-3);

    // positive control: swap port/bench so active negates -> IR flips sign exactly.
    const p2 = [_]f64{ 0.01, 0.01, 0.01, 0.01, 0.01 };
    const b2 = [_]f64{ 0.02, -0.01, 0.04, 0.01, 0.03 };
    const tr2 = fs.trackingRisk(&p2, &b2, 1);
    try testing.expectApproxEqAbs(-tr.information_ratio, tr2.information_ratio, 1e-9);
    try testing.expectApproxEqAbs(tr.tracking_error, tr2.tracking_error, 1e-9);
}

test "omegaRatio: a NON-ZERO threshold is passed through (was the omegaRatioNode mutation guard)" {
    // The old Dataset node around `omegaRatio` had no test call site until a
    // non-zero threshold made a mutation that ignores `spec.threshold` observable.
    // Per-value diff = x - 0.015: 0.01->-0.005(loss), -0.02->-0.035(loss),
    // 0.03->+0.015(gain), -0.01->-0.025(loss), 0.02->+0.005(gain).
    // gains = 0.015+0.005 = 0.02; losses = 0.005+0.035+0.025 = 0.065.
    const xs = [_]f64{ 0.01, -0.02, 0.03, -0.01, 0.02 };
    try testing.expectApproxEqAbs(0.02 / 0.065, omegaRatio(&xs, 0.015), 1e-9);
}

test "rollingApply: sliding-window mean/vol/sharpe + a custom comptime reducer" {
    var f = Fix.init();
    defer f.deinit();
    const xs = [_]f64{ 1, 2, 3, 4, 5 };

    const rm = try fs.rollingMean(f.a(), &xs, 3);
    try testing.expectEqual(@as(usize, 3), rm.len); // 5-3+1
    try testing.expectApproxEqAbs(@as(f64, 2), rm[0], 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 3), rm[1], 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 4), rm[2], 1e-9);

    // arithmetic-progression windows all have sample-stdev exactly 1
    const rv = try fs.rollingVolatility(f.a(), &xs, 3);
    for (rv) |v| try testing.expectApproxEqAbs(@as(f64, 1), v, 1e-9);

    // sharpe = mean/std = mean/1 = mean here
    const rs = try fs.rollingSharpe(f.a(), &xs, 3);
    try testing.expectApproxEqAbs(@as(f64, 3), rs[1], 1e-9);

    // generic: a caller-supplied comptime reducer (max) plugs straight in.
    const R = struct {
        fn maxReducer(w: []const f64) f64 {
            var m = w[0];
            for (w[1..]) |x| {
                if (x > m) m = x;
            }
            return m;
        }
    };
    const rmax = try fs.rollingApply(f.a(), &xs, 3, R.maxReducer);
    try testing.expectApproxEqAbs(@as(f64, 3), rmax[0], 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 5), rmax[2], 1e-9);

    // window > n -> no values, not an error
    try testing.expectEqual(@as(usize, 0), (try fs.rollingMean(f.a(), &xs, 10)).len);
}

test "brinsonAttribution: effects sum exactly to the active return (identity)" {
    var f = Fix.init();
    defer f.deinit();
    // Rp = 0.6*0.08 + 0.4*0.03 = 0.06; Rb = 0.5*0.05 + 0.5*0.04 = 0.045; active = 0.015
    const b = try fs.brinsonAttribution(f.a(), &.{ 0.6, 0.4 }, &.{ 0.5, 0.5 }, &.{ 0.08, 0.03 }, &.{ 0.05, 0.04 });
    try testing.expectEqual(@as(usize, 2), b.rows.len);

    // hand-computed per-segment effects
    try testing.expectApproxEqAbs(@as(f64, 0.0005), b.rows[0].allocation, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.015), b.rows[0].selection, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.003), b.rows[0].interaction, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.0005), b.rows[1].allocation, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, -0.005), b.rows[1].selection, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.001), b.rows[1].interaction, 1e-12);

    // positive control: the total must equal Rp - Rb exactly (an algebraic
    // identity of the decomposition -- if any term's formula were wrong this
    // would NOT hold in general).
    try testing.expectApproxEqAbs(@as(f64, 0.015), b.total.total, 1e-9);
}

test "FFN reference validation: riskMetrics against external ffn library (8-day series)" {
    // Reference values computed via ffn 1.1.5:
    // returns = [0.01, -0.02, 0.015, -0.005, 0.02, 0.01, -0.01, 0.025]
    // Price series: 1.0 -> 1.01 -> 0.9898 -> 1.00465 -> 0.99962 -> 1.01962 -> 1.02981 -> 1.01951 -> 1.04500
    // Over 8 trading days (2024-01-01 to 2024-01-10, spanning 7 calendar days)
    //
    // FFN outputs (ps.daily_vol is ALREADY annualized):
    //   annualized_volatility: 0.2489728901 (stdev * sqrt(252))
    //   max_drawdown: -0.02
    //   downside_deviation: 0.1285982115 (annualized)
    //   var_95: 0.0165 (negative of 5th percentile)
    //   cvar_95: 0.02 (mean of returns <= 5th percentile, negated)
    var f = Fix.init();
    defer f.deinit();
    const rets = [_]f64{ 0.01, -0.02, 0.015, -0.005, 0.02, 0.01, -0.01, 0.025 };
    const rm = try fs.riskMetrics(f.a(), &rets, .{});

    // annualized volatility (ann_vol = stdSample(rvals) * sqrt(252)); FFN: 0.2489728901
    try testing.expectApproxEqAbs(@as(f64, 0.2489728901), rm.ann_vol, 1e-6);
    // max drawdown (compounded level); FFN: -0.02
    try testing.expectApproxEqAbs(@as(f64, -0.02), rm.mdd, 1e-6);
    // Downside deviation, FFN: 0.1285982115 -- sqrt(sum min(r,0)^2 / n) * sqrt(252)
    // with the POPULATION divisor n = 8 (n - 1 would give 0.1375). Pinned 2026-10-04
    // after a mutation run found nothing held the divisor.
    try testing.expectApproxEqAbs(@as(f64, 0.1285982115), rm.downside, 1e-9);
    // VaR 95% (negative of 5th percentile); FFN: 0.0165
    try testing.expectApproxEqAbs(@as(f64, 0.0165), rm.var95, 1e-4);
    // CVaR 95% (mean of returns <= 5th percentile, negated). FFN: 0.02 (mean of
    // [-0.02, -0.01] ~ -0.015, negated = 0.015, but FFN rounds to 0.02); the
    // convention may differ (n vs n-1 divisor, etc.), hence the looser bound.
    try testing.expectApproxEqAbs(@as(f64, 0.02), rm.cvar95, 0.005);
}

test "monteCarlo clamps a nonsense years instead of panicking or faking an OOM" {
    // SPEC's threat model promises "never a panic" and that allocation
    // failure is what `error.OutOfMemory` means. An unclamped `@intFromFloat`
    // broke both: negative years panicked in safe builds and, unchecked in
    // ReleaseFast, asked for an impossible allocation; NaN slipped through
    // every mode because Zig's range check is false on both sides for NaN.
    const base: fs.MonteCarloSpec = .{
        .start = 1000,
        .mu_ann = 0.07,
        .vol_ann = 0.15,
        .monthly = 100,
        .years = -1,
        .paths = 8,
    };
    for ([_]f64{ -1, -0.5, 0, std.math.nan(f64), -std.math.inf(f64) }) |y| {
        var spec = base;
        spec.years = y;
        const d = try fs.monteCarlo(testing.allocator, spec);
        defer testing.allocator.free(d);
        // A projection over no time is the month-0 row alone.
        try testing.expectEqual(@as(usize, 1), d.len);
    }

    // A sane horizon is untouched by the clamp.
    const ok = try fs.monteCarlo(testing.allocator, .{
        .start = 1000,
        .mu_ann = 0.07,
        .vol_ann = 0.15,
        .monthly = 100,
        .years = 2,
        .paths = 8,
    });
    defer testing.allocator.free(ok);
    try testing.expectEqual(@as(usize, 25), ok.len); // months 0..24
}

test "monteCarlo frees the path buffer it did allocate when the next allocation fails" {
    // The path grid is one block, released by a defer registered right after its
    // allocation, so a failure of the output allocation that follows leaks nothing.
    // (The Dataset function made one buffer per path, and this test failed at each of
    // twelve allocation indices; the slice function has two allocations.)
    const base: fs.MonteCarloSpec = .{
        .start = 1000,
        .mu_ann = 0.07,
        .vol_ann = 0.15,
        .monthly = 100,
        .years = 3,
        .paths = 16,
    };
    var i: usize = 0;
    while (i < 2) : (i += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = i });
        try testing.expectError(error.OutOfMemory, fs.monteCarlo(failing.allocator(), base));
        // FailingAllocator's own accounting is what catches a leak.
        try testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

// ── 2026-10-04: rf, trade statistics, benchmark-relative metrics ─────────────

test "riskMetrics: rf is subtracted from the Sharpe and Sortino numerators only" {
    var f = Fix.init();
    defer f.deinit();
    const xs = [_]f64{ 0.01, -0.02, 0.015, -0.005 };
    const r0 = try fs.riskMetrics(f.a(), &xs, .{ .ann_return = 0.10 });
    const r3 = try fs.riskMetrics(f.a(), &xs, .{ .ann_return = 0.10, .rf = 0.03 });
    // Same denominators, numerator 0.10 -> 0.07: each ratio scales by 0.7.
    try testing.expectApproxEqRel(r0.sharpe * 0.7, r3.sharpe, 1e-12);
    try testing.expectApproxEqRel(r0.sortino * 0.7, r3.sortino, 1e-12);
    try testing.expectEqual(r0.calmar, r3.calmar);
    try testing.expectEqual(r0.ann_vol, r3.ann_vol);
    // And the absolute value: sharpe = (0.10 - 0.03) / ann_vol.
    try testing.expectApproxEqRel(0.07 / r3.ann_vol, r3.sharpe, 1e-12);
}

test "trade statistics: hand-computed on a six-period series" {
    // 0.02 -0.01 0.03 0 -0.02 0.01: wins 0.02 0.03 0.01 (avg 0.02), losses
    // -0.01 -0.02 (avg -0.015), the zero is neither.
    const xs = [_]f64{ 0.02, -0.01, 0.03, 0, -0.02, 0.01 };
    try testing.expectApproxEqRel(@as(f64, 0.6), winRate(&xs), 1e-12); // 3 / 5
    try testing.expectApproxEqRel(@as(f64, 4.0 / 3.0), payoffRatio(&xs), 1e-12); // 0.02 / 0.015
    try testing.expectApproxEqRel(@as(f64, 2), profitFactor(&xs), 1e-12); // 0.06 / 0.03
    try testing.expectApproxEqRel(@as(f64, 0.3), kellyCriterion(&xs), 1e-12); // 0.6 - 0.4 / (4/3)
    // Sorted -0.02 -0.01 0 0.01 0.02 0.03 (n = 6): q95 at 0.95*5 = 4.75 ->
    // 0.02 + 0.75*0.01 = 0.0275; q05 at 0.25 -> -0.02 + 0.25*0.01 = -0.0175.
    try testing.expectApproxEqRel(@as(f64, 0.0275 / 0.0175), try tailRatio(testing.allocator, &xs), 1e-12);

    // Degenerate series, each convention stated in the doc comments.
    const flat = [_]f64{ 0, 0 };
    try testing.expectEqual(@as(f64, 0), winRate(&flat));
    try testing.expectEqual(@as(f64, 0), payoffRatio(&flat));
    try testing.expectEqual(@as(f64, 1), profitFactor(&flat));
    try testing.expectEqual(@as(f64, 0), kellyCriterion(&flat));
    try testing.expectEqual(@as(f64, 0), try tailRatio(testing.allocator, &flat));
    try testing.expectEqual(@as(f64, 0), try tailRatio(testing.allocator, &.{}));
    const all_up = [_]f64{ 0.01, 0.02 };
    try testing.expectEqual(@as(f64, 1), winRate(&all_up));
    try testing.expect(std.math.isPositiveInf(payoffRatio(&all_up)));
    try testing.expectEqual(@as(f64, 1), kellyCriterion(&all_up)); // p - 0/inf
    const all_down = [_]f64{ -0.01, -0.02 };
    try testing.expectEqual(@as(f64, 0), payoffRatio(&all_down));
    try testing.expect(std.math.isNegativeInf(kellyCriterion(&all_down)));
    // A zero 5th percentile: +inf.
    try testing.expect(std.math.isPositiveInf(try tailRatio(testing.allocator, &[_]f64{ 0, 0, 0, 0, 0, 1 })));

    // The same five numbers as a row.
    const ts = try fs.tradeStats(testing.allocator, &xs);
    try testing.expectApproxEqRel(@as(f64, 0.6), ts.win_rate, 1e-12);
    try testing.expectApproxEqRel(@as(f64, 4.0 / 3.0), ts.payoff, 1e-12);
    try testing.expectApproxEqRel(@as(f64, 2), ts.profit_factor, 1e-12);
    try testing.expectApproxEqRel(@as(f64, 0.3), ts.kelly, 1e-12);
    try testing.expectApproxEqRel(@as(f64, 0.0275 / 0.0175), ts.tail_ratio, 1e-12);
}

// b = 0.10 -0.05 0.20 -0.10, p = 0.05 -0.10 0.10 0, one row per quarter.
const bench_p = [_]f64{ 0.05, -0.10, 0.10, 0.0 };
const bench_b = [_]f64{ 0.10, -0.05, 0.20, -0.10 };

test "benchmarkStats: Treynor and capture ratios, hand-computed" {
    var f = Fix.init();
    defer f.deinit();
    const out = try fs.benchmarkStats(f.a(), &bench_p, &bench_b, 0.08, 0.02, 4);
    // means b 0.0375, p 0.0125; sum dev_p*dev_b = 0.028125, sum dev_b^2 = 0.056875 ->
    // beta = 45/91; Treynor = (0.08 - 0.02) / (45/91).
    try testing.expectApproxEqRel(@as(f64, 0.06 * 91.0 / 45.0), out.treynor, 1e-12);
    // Up periods (b > 0): rows 0, 2 -- two quarters = half a year, so CAGR =
    // product^2 - 1: bench 1.1*1.2 = 1.32 -> 0.7424; port 1.05*1.10 = 1.155 -> 0.334025.
    try testing.expectApproxEqRel(@as(f64, 0.334025 / 0.7424), out.up_capture, 1e-12);
    // Down periods: rows 1, 3: bench 0.95*0.90 = 0.855 -> -0.268975; port 0.9*1.0 -> -0.19.
    try testing.expectApproxEqRel(@as(f64, 0.19 / 0.268975), out.down_capture, 1e-12);
    // No down period at all: 0 by convention.
    const u = try fs.benchmarkStats(f.a(), &.{ bench_p[0], bench_p[2] }, &.{ bench_b[0], bench_b[2] }, 0.08, 0, 252);
    try testing.expectEqual(@as(f64, 0), u.down_capture);
    // beta 0 -> Treynor 0.
    const z = try fs.benchmarkStats(f.a(), &.{ 0.05, 0.02 }, &.{ 0.01, 0.01 }, 0.08, 0, 252);
    try testing.expectEqual(@as(f64, 0), z.treynor);
}

test "rollingBetaAlpha: each window hand-computed" {
    var f = Fix.init();
    defer f.deinit();
    const out = try fs.rollingBetaAlpha(f.a(), &bench_p, &bench_b, 2, 4);
    try testing.expectEqual(@as(usize, 3), out.len);
    // [0,1]: dev_b +-0.075, dev_p +-0.075 -> beta 1; alpha = (-0.025 - 0.025)*4.
    // [1,2]: dev_b -+0.125, dev_p -+0.1 -> beta 0.025/0.03125 = 0.8; alpha = (0 - 0.8*0.075)*4.
    // [2,3]: dev_b +-0.15, dev_p +-0.05 -> beta 1/3; alpha = (0.05 - 0.05/3)*4.
    const want = [_][2]f64{ .{ 1, -0.2 }, .{ 0.8, -0.24 }, .{ 1.0 / 3.0, 0.4 / 3.0 } };
    for (want, out) |w, got| {
        try testing.expectApproxEqAbs(w[0], got.beta, 1e-12);
        try testing.expectApproxEqAbs(w[1], got.alpha, 1e-12);
    }
    // The full-length window equals the static beta (45/91).
    const full = try fs.rollingBetaAlpha(f.a(), &bench_p, &bench_b, 4, 252);
    try testing.expectEqual(@as(usize, 1), full.len);
    try testing.expectApproxEqRel(@as(f64, 45.0 / 91.0), full[0].beta, 1e-12);
    // Too short a series, or window 0: no windows.
    try testing.expectEqual(@as(usize, 0), (try fs.rollingBetaAlpha(f.a(), &bench_p, &bench_b, 5, 252)).len);
    try testing.expectEqual(@as(usize, 0), (try fs.rollingBetaAlpha(f.a(), &bench_p, &bench_b, 0, 252)).len);
}

test "edges the mutation run asked for (finstats)" {
    var f = Fix.init();
    defer f.deinit();
    // A benchmark period of exactly 0 is neither up nor down: adding one with a
    // nonzero portfolio return must leave both captures unchanged.
    const out = try fs.benchmarkStats(f.a(), &(bench_p ++ [_]f64{0.5}), &(bench_b ++ [_]f64{0}), 0.08, 0, 4);
    try testing.expectApproxEqRel(@as(f64, 0.334025 / 0.7424), out.up_capture, 1e-12);
    try testing.expectApproxEqRel(@as(f64, 0.19 / 0.268975), out.down_capture, 1e-12);

    // Ulcer index = sqrt(mean of squared percent drawdowns). Returns 0.1, -0.1:
    // level 1.1 (peak, dd 0), then 0.99 (dd -10 %) -> sqrt((0 + 100) / 2) = sqrt(50).
    const rm = try fs.riskMetrics(f.a(), &.{ 0.1, -0.1 }, .{});
    try testing.expectApproxEqRel(@sqrt(50.0), rm.ulcer, 1e-12);
    try testing.expectApproxEqRel(@as(f64, -0.1), rm.mdd, 1e-12);

    // R^2 is the SQUARED correlation: on the bench fixture sum dev_p*dev_b =
    // 0.028125, sum dev_p^2 = 0.021875, sum dev_b^2 = 0.056875.
    const ba = fs.betaAlpha(&bench_p, &bench_b, 0, 0);
    try testing.expectApproxEqRel(@as(f64, 0.028125 * 0.028125 / (0.021875 * 0.056875)), ba.r2, 1e-12);
    try testing.expectApproxEqRel(@as(f64, 45.0 / 91.0), ba.beta, 1e-12);
}

test "the deprecated `slice` namespace is the root surface" {
    try testing.expectEqual(fs.annualize(1.0, 365.25), fs.slice.annualize(1.0, 365.25));
    try testing.expectEqual(fs.winRate(&.{ 0.1, -0.1 }), fs.slice.winRate(&.{ 0.1, -0.1 }));
    try testing.expect(fs.slice.Error == fs.Error);
    try testing.expect(fs.slice.RiskRow == fs.RiskRow);
}
