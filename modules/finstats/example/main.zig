// SPDX-License-Identifier: MIT

//! What a portfolio-reporting consumer does with `finstats`: given a
//! dated series of external cash flows and portfolio values (the shape a
//! brokerage export or a ledger reducer would hand over, as parallel slices),
//! compute the money-weighted return (`xirr`), a daily return series' risk
//! metrics (vol/VaR/Sharpe/...), and the worst drawdown episodes: the numbers
//! a portfolio summary page actually shows a user.
//!
//! Built against the PUBLISHED module (`@import("finstats")`); it has no
//! dependency, every entry point takes plain slices.

const std = @import("std");
const finstats = @import("finstats");

// A small deposit-then-grow account: contribute 1000 on day 1, no further
// flows, worth 1300 a year later. `flows` is "positive = contribution" (money
// going INTO the account, not the investor's own signed cash-flow convention;
// `xirr` negates it internally to get there). The mid-series dip gives
// `drawdownEpisodes` below something to find.
const dates = [_][]const u8{ "2024-01-01", "2024-04-01", "2024-08-01", "2024-12-31" };
const flows = [_]f64{ 1000, 0, 0, 0 };
const values = [_]f64{ 1000, 1150, 900, 1300 };

// A short daily-return series for the risk metrics: the shape a return
// series reducer upstream of this module would already have produced.
const returns = [_]f64{ 0.010, -0.020, 0.015, -0.005, 0.020 };

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── xirr: the money-weighted return a "your account" page shows ────
    // Left on a plain `DebugAllocator` on purpose: the module's own tests run
    // many functions on an arena, which bulk-frees regardless, so only a
    // consumer like this one can see a scratch buffer that is never released.
    const rate = try finstats.xirr(
        gpa,
        &dates,
        &flows,
        &values,
        // No default on purpose: this series IS the whole history, and saying
        // so is the one thing that cannot be got wrong by not thinking about
        // it. See the window below for what the other answer buys.
        .none,
        finstats.default_rate_tol,
    );
    std.debug.print("xirr: {d:.4}\n", .{rate});

    // ── the same account, but only the last 9 months of it ─────────────
    // A date-range selector ("1Y / YTD / All") hands over a SLICE, and a slice
    // that starts mid-life opens with a position rather than with nothing. Say
    // so, or the opening 1150 is money that appeared from nowhere.
    // `.value_includes_flow` is the right reading here because `value` is an
    // end-of-day figure: whatever flowed in on the window's first day is
    // already inside it.
    const windowed = try finstats.xirr(gpa, dates[1..], flows[1..], values[1..], .value_includes_flow, finstats.default_rate_tol);
    std.debug.print("xirr (last 9 months): {d:.4}\n", .{windowed});

    // Forget the seed and there is no rate of return to find: the only
    // cashflow left is the terminal +1300, and NPV is positive at every
    // rate in the [-0.99, 10] bracket. That is an error, not a number:
    // before 2026-08-23 it bisected its way to the bound and returned
    // 10.0, which renders as a perfectly confident +1000 %.
    if (finstats.xirr(gpa, dates[1..], flows[1..], values[1..], .none, finstats.default_rate_tol)) |wrong| {
        std.debug.print("unreachable: {d}\n", .{wrong});
    } else |err| {
        std.debug.print("xirr (window, unseeded): {t}\n", .{err});
    }

    // ── risk metrics: one row {ann_vol, downside, var95, cvar95, mdd,
    // ulcer, sharpe, sortino, calmar} ready to bind straight into a KPI
    // widget row. `span_days` makes the ratios use the compounded return over
    // the calendar span of the series.
    const risk = try finstats.riskMetrics(gpa, &returns, .{
        .periods_per_year = 252,
        .span_days = try finstats.daySpan("2024-01-02", "2024-01-08"),
    });
    std.debug.print("ann_vol: {d:.4}  sharpe: {d:.4}\n", .{ risk.ann_vol, risk.sharpe });

    // ── quantile: the same 5% tail figure riskMetrics computes
    // internally for VaR, available standalone for a caller building its
    // own metric.
    const p05 = try finstats.quantile(gpa, &returns, 0.05);
    std.debug.print("5th percentile return: {d:.4}\n", .{p05});

    // ── drawdown episodes: peak/trough/recovery for a "worst drawdowns"
    // table, derived straight from the account-value series above. Each
    // episode names its rows by index into the input.
    const episodes = try finstats.drawdownEpisodes(gpa, &dates, &values, 3);
    defer gpa.free(episodes);
    std.debug.print("drawdown episodes found: {d}\n", .{episodes.len});

    // ── fail-closed: two series that do not line up are an error, not a
    // silent truncation.
    if (finstats.xirr(gpa, &dates, flows[1..], &values, .none, finstats.default_rate_tol)) |_| {
        return error.MisalignmentNotDetected;
    } else |err| switch (err) {
        error.LengthMismatch => std.debug.print("misaligned series rejected: LengthMismatch\n", .{}),
        else => return err,
    }
}
