// SPDX-License-Identifier: MIT

//! What a charting or screening consumer does with `indicators`: take a
//! close-price history (plain slices, as a dataframe column or a broker
//! export would hand it over), compute the usual overlays and oscillators in
//! batch into caller-owned buffers, then keep RSI live with the streaming type
//! as new bars arrive -- and check that the live value is the batch value.
//!
//! Built against the PUBLISHED module (`@import("indicators")`). Every output
//! is as long as its input; the first `lookback` slots are NaN, and every
//! batch call returns that lookback, so the consumer never guesses the warm-up.

const std = @import("std");
const ind = @import("indicators");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // A deterministic random walk stands in for 120 daily closes.
    const n = 120;
    const close = try gpa.alloc(f64, n);
    defer gpa.free(close);
    var prng: std.Random.DefaultPrng = .init(42);
    var px: f64 = 100;
    for (close) |*c| {
        px += (prng.random().float(f64) - 0.5) * 2.0;
        c.* = px;
    }

    // ── overlays: SMA(20) and Bollinger bands(20, 2σ) ─────────────────
    const sma20 = try gpa.alloc(f64, n);
    defer gpa.free(sma20);
    const sma_lb = try ind.sma(f64, close, sma20, .{ .period = 20 });

    const upper = try gpa.alloc(f64, n);
    defer gpa.free(upper);
    const middle = try gpa.alloc(f64, n);
    defer gpa.free(middle);
    const lower = try gpa.alloc(f64, n);
    defer gpa.free(lower);
    _ = try ind.bbands(f64, close, upper, middle, lower, .{ .period = 20 });

    // ── oscillators: RSI(14) and MACD(12, 26, 9), TA-Lib's defaults ───
    const rsi14 = try gpa.alloc(f64, n);
    defer gpa.free(rsi14);
    const rsi_lb = try ind.rsi(f64, close, rsi14, .{});

    const line = try gpa.alloc(f64, n);
    defer gpa.free(line);
    const signal = try gpa.alloc(f64, n);
    defer gpa.free(signal);
    const hist = try gpa.alloc(f64, n);
    defer gpa.free(hist);
    const macd_lb = try ind.macd(f64, close, line, signal, hist, .{});

    const last = n - 1;
    std.debug.print("bars={d}  close={d:.2}\n", .{ n, close[last] });
    std.debug.print("SMA20 (lookback {d}) = {d:.4}\n", .{ sma_lb, sma20[last] });
    std.debug.print("BB20  = {d:.4} / {d:.4} / {d:.4}\n", .{ upper[last], middle[last], lower[last] });
    std.debug.print("RSI14 (lookback {d}) = {d:.4}\n", .{ rsi_lb, rsi14[last] });
    std.debug.print("MACD  (lookback {d}) = {d:.4}  signal {d:.4}  hist {d:.4}\n", .{ macd_lb, line[last], signal[last], hist[last] });

    // ── live: the same RSI, one bar at a time ─────────────────────────
    // `update` returns null until the warm-up is over, then the value the
    // batch call wrote for that bar. `peek` answers "what would RSI be if
    // the next close were x" without moving the state.
    var live = try ind.RsiStream(f64).init(.{});
    for (close, 0..) |c, i| {
        const v = live.update(c);
        if (i < rsi_lb) {
            if (v != null) return error.StreamWarmUpMismatch;
        } else if (v.? != rsi14[i]) {
            return error.StreamBatchMismatch;
        }
    }
    const what_if = live.peek(close[last] + 1.0).?;
    std.debug.print("RSI14 live = batch at every bar; if the next close were +1: {d:.4}\n", .{what_if});
}
