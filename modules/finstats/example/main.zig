// SPDX-License-Identifier: MIT

//! What a portfolio-reporting consumer does with `finstats`: given a
//! dated series of external cash flows and portfolio values (the shape a
//! brokerage export or a ledger reducer would hand over as a `dataset.
//! Dataset`), compute the money-weighted return (`xirr`), a daily
//! return series' risk metrics (vol/VaR/Sharpe/...), and the worst
//! drawdown episodes — the numbers a portfolio summary page actually
//! shows a user.
//!
//! Built against the PUBLISHED module (`@import("finstats")`) plus its
//! declared dep `dataset` (needed for `Dataset`/`Column`/`Value`, the
//! only shape every entry point here takes input as).

const std = @import("std");
const finstats = @import("finstats");
const dataset = @import("dataset");

const Value = dataset.Value;
const Column = dataset.Column;
const Dataset = dataset.Dataset;

// A small deposit-then-grow account: contribute 1000 on day 1, no further
// flows, worth 1300 a year later. The three tagged fields `xirr` needs are
// date/flow/value — everything else in a real export is irrelevant to it.
const flow_columns = [_]Column{
    .{ .name = "date", .type = .date },
    .{ .name = "flow", .type = .float },
    .{ .name = "value", .type = .float },
};
// `flow` is "positive = contribution" (`XirrSpec.flow_col`'s doc comment) —
// money going INTO the account, not the investor's own signed cash-flow
// convention (`xirr` negates it internally to get there). The mid-series
// dip gives `drawdownEpisodes` below something to find.
const flow_rows = [_][]const Value{
    &.{ .{ .text = "2024-01-01" }, .{ .float = 1000 }, .{ .float = 1000 } },
    &.{ .{ .text = "2024-04-01" }, .{ .float = 0 }, .{ .float = 1150 } },
    &.{ .{ .text = "2024-08-01" }, .{ .float = 0 }, .{ .float = 900 } },
    &.{ .{ .text = "2024-12-31" }, .{ .float = 0 }, .{ .float = 1300 } },
};
const flow_dataset: Dataset = .{ .columns = &flow_columns, .rows = &flow_rows };

// A short daily-return series for the risk metrics — the shape a return
// series reducer upstream of this module would already have produced.
const ret_columns = [_]Column{
    .{ .name = "date", .type = .date },
    .{ .name = "ret", .type = .float },
};
const ret_rows = [_][]const Value{
    &.{ .{ .text = "2024-01-02" }, .{ .float = 0.010 } },
    &.{ .{ .text = "2024-01-03" }, .{ .float = -0.020 } },
    &.{ .{ .text = "2024-01-04" }, .{ .float = 0.015 } },
    &.{ .{ .text = "2024-01-05" }, .{ .float = -0.005 } },
    &.{ .{ .text = "2024-01-08" }, .{ .float = 0.020 } },
};
const ret_dataset: Dataset = .{ .columns = &ret_columns, .rows = &ret_rows };

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── xirr: the money-weighted return a "your account" page shows ────
    // This example is what caught the scratch-buffer leak `xirr`,
    // `xirrPrecise`, `quantile`, `riskMetrics` and `parametricRisk` all
    // carried (fixed 2026-08-22): the module's own tests run on an arena,
    // which bulk-frees regardless, so only a consumer on a plain
    // `DebugAllocator` — this file — could see it. Left on `gpa` on
    // purpose so it stays visible if it ever comes back.
    const rate = try finstats.xirr(gpa, flow_dataset, .{
        .date_col = "date",
        .flow_col = "flow",
        .value_col = "value",
        // No default on purpose: this series IS the whole history, and saying
        // so is the one thing that cannot be got wrong by not thinking about
        // it. See the window below for what the other answer buys.
        .opening = .none,
    });
    std.debug.print("xirr: {d:.4}\n", .{rate});

    // ── the same account, but only the last 9 months of it ─────────────
    // A date-range selector ("1Y / YTD / All") hands the reducer a SLICE,
    // and a slice that starts mid-life opens with a position rather than
    // with nothing. Say so, or the opening 1150 is money that appeared
    // from nowhere. `.value_includes_flow` is the right reading here
    // because `value` is an end-of-day figure: whatever flowed in on the
    // window's first day is already inside it.
    const window = Dataset{ .columns = &flow_columns, .rows = flow_rows[1..] };
    const windowed = try finstats.xirr(gpa, window, .{
        .date_col = "date",
        .flow_col = "flow",
        .value_col = "value",
        .opening = .value_includes_flow,
    });
    std.debug.print("xirr (last 9 months): {d:.4}\n", .{windowed});

    // Forget the seed and there is no rate of return to find: the only
    // cashflow left is the terminal +1300, and NPV is positive at every
    // rate in the [-0.99, 10] bracket. That is an error, not a number —
    // before 2026-08-23 it bisected its way to the bound and returned
    // 10.0, which renders as a perfectly confident +1000 %.
    if (finstats.xirr(gpa, window, .{
        .date_col = "date",
        .flow_col = "flow",
        .value_col = "value",
        .opening = .none,
    })) |wrong| {
        std.debug.print("unreachable: {d}\n", .{wrong});
    } else |err| {
        std.debug.print("xirr (window, unseeded): {t}\n", .{err});
    }

    // ── risk metrics: a single row {ann_vol, downside, var95, cvar95,
    // mdd, ulcer, sharpe, sortino, calmar} ready to bind straight into a
    // KPI widget row.
    var risk = try finstats.riskMetrics(gpa, ret_dataset, .{
        .ret_col = "ret",
        .date_col = "date",
        .periods_per_year = 252,
    });
    defer freeDataset(gpa, &risk);
    const vi = risk.columnIndex("ann_vol").?;
    const si = risk.columnIndex("sharpe").?;
    std.debug.print("ann_vol: {d:.4}  sharpe: {d:.4}\n", .{
        risk.rows[0][vi].asFloat().?, risk.rows[0][si].asFloat().?,
    });

    // ── quantile: the same 5% tail figure riskMetrics computes
    // internally for VaR, available standalone for a caller building its
    // own metric.
    const returns = [_]f64{ 0.010, -0.020, 0.015, -0.005, 0.020 };
    const p05 = try finstats.quantile(gpa, &returns, 0.05);
    std.debug.print("5th percentile return: {d:.4}\n", .{p05});

    // ── drawdown episodes: peak/trough/recovery for a "worst drawdowns"
    // table, derived straight from the account-value series above.
    var episodes = try finstats.drawdownEpisodes(gpa, flow_dataset, .{
        .date_col = "date",
        .value_col = "value",
        .top_n = 3,
    });
    defer freeDataset(gpa, &episodes);
    std.debug.print("drawdown episodes found: {d}\n", .{episodes.rows.len});

    // ── fail-closed: a KPI node bound to a column name that doesn't
    // exist in this dataset is a config error, not a silent zero.
    _ = finstats.xirrNode(gpa, flow_dataset, .{
        .date_col = "date",
        .flow_col = "flow",
        .value_col = "no_such_column",
        .opening = .none,
    }) catch |err| switch (err) {
        error.NoSuchColumn => {
            std.debug.print("misconfigured KPI node rejected: NoSuchColumn\n", .{});
            return;
        },
        else => return err,
    };
    return error.MisconfigurationNotDetected;
}

/// `finstats`' `Dataset`-returning functions allocate `columns`/`rows`/each
/// row's cells from the given allocator; free them the same way a caller
/// discarding a transform result would.
fn freeDataset(a: std.mem.Allocator, d: *Dataset) void {
    for (d.rows) |row| a.free(row);
    a.free(d.rows);
    a.free(d.columns);
}
