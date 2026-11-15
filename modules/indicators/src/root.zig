// SPDX-License-Identifier: MIT
//! indicators: technical-analysis indicators over plain slices, with TA-Lib
//! 0.8.3 as the reference (formulas ported from its BSD-3 C source, see NOTICE).
//!
//! Seed set (wave I2): SMA, EMA, WMA, MA, MACD, MACDEXT, MACDFIX, RSI, BBANDS,
//! TRANGE, ATR, NATR, STOCH, STOCHF, MAX, MIN, SUM.
//!
//! ```zig
//! const ind = @import("indicators");
//! const lb = try ind.ema(f64, closes, out, .{ .period = 12 }); // out.len == closes.len
//! // out[0..lb] is NaN; lb == try ind.emaLookback(.{ .period = 12 })
//! var s = try ind.EmaStream(f64).init(.{ .period = 12 }); // streaming: same numbers, bit for bit
//! if (s.update(price)) |v| use(v);
//! ```
//!
//! Every batch function is generic over `T` (f32 or f64, the math is f64), takes
//! one output slice per output with `out.len == in.len`, fills the lead with
//! NaN and returns the lookback. Every function has a `<name>Lookback(params)`
//! and a streaming type `<Name>Stream(T)` (`init`, `update`, `peek`, `value`).
//! Streaming types that need history take a caller buffer (`bufLen`); the
//! recursive ones are plain values and copy by value. Parameters outside
//! TA-Lib's ranges are `error.BadParam`; a moving-average type that is not
//! built yet is `error.Unsupported`. Nothing panics.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const window = @import("window.zig");
const rsi_ = @import("rsi.zig");
const range = @import("range.zig");
const macd_ = @import("macd.zig");
const bands = @import("bands.zig");
const stoch_ = @import("stoch.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Technical-analysis indicators (TA-Lib parity): moving averages, MACD, RSI, Bollinger bands, ATR, stochastic, rolling max/min/sum.",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "TA-Lib C 0.8.3",
    .deps = .{},
};

// shared types
pub const Error = core.Error;
pub const Nan = core.Nan;
pub const Seed = core.Seed;
pub const Unstable = core.Unstable;
pub const MaType = core.MaType;
pub const Bar = core.Bar;

// moving averages
pub const SmaParams = smooth.SmaParams;
pub const sma = smooth.sma;
pub const smaLookback = smooth.smaLookback;
pub const SmaStream = smooth.SmaStream;
pub const EmaParams = smooth.EmaParams;
pub const ema = smooth.ema;
pub const emaLookback = smooth.emaLookback;
pub const EmaStream = smooth.EmaStream;
pub const WmaParams = smooth.WmaParams;
pub const wma = smooth.wma;
pub const wmaLookback = smooth.wmaLookback;
pub const WmaStream = smooth.WmaStream;
pub const MaParams = smooth.MaParams;
pub const ma = smooth.ma;
pub const maLookback = smooth.maLookback;
pub const MaStream = smooth.MaStream;

// rolling window
pub const WindowParams = window.WindowParams;
pub const sum = window.sum;
pub const sumLookback = window.sumLookback;
pub const SumStream = window.SumStream;
pub const max = window.max;
pub const maxLookback = window.maxLookback;
pub const MaxStream = window.MaxStream;
pub const min = window.min;
pub const minLookback = window.minLookback;
pub const MinStream = window.MinStream;

// momentum
pub const RsiParams = rsi_.RsiParams;
pub const rsi = rsi_.rsi;
pub const rsiLookback = rsi_.rsiLookback;
pub const RsiStream = rsi_.RsiStream;

pub const MacdOut = macd_.MacdOut;
pub const MacdParams = macd_.MacdParams;
pub const macd = macd_.macd;
pub const macdLookback = macd_.macdLookback;
pub const MacdStream = macd_.MacdStream;
pub const MacdextParams = macd_.MacdextParams;
pub const macdext = macd_.macdext;
pub const macdextLookback = macd_.macdextLookback;
pub const MacdextStream = macd_.MacdextStream;
pub const MacdfixParams = macd_.MacdfixParams;
pub const macdfix = macd_.macdfix;
pub const macdfixLookback = macd_.macdfixLookback;
pub const MacdfixStream = macd_.MacdfixStream;

pub const StochOut = stoch_.StochOut;
pub const StochParams = stoch_.StochParams;
pub const stoch = stoch_.stoch;
pub const stochLookback = stoch_.stochLookback;
pub const StochStream = stoch_.StochStream;
pub const StochfParams = stoch_.StochfParams;
pub const stochf = stoch_.stochf;
pub const stochfLookback = stoch_.stochfLookback;
pub const StochfStream = stoch_.StochfStream;

// volatility and bands
pub const trange = range.trange;
pub const trangeLookback = range.trangeLookback;
pub const TrangeStream = range.TrangeStream;
pub const AtrParams = range.AtrParams;
pub const atr = range.atr;
pub const atrLookback = range.atrLookback;
pub const AtrStream = range.AtrStream;
pub const NatrParams = range.NatrParams;
pub const natr = range.natr;
pub const natrLookback = range.natrLookback;
pub const NatrStream = range.NatrStream;
pub const BbandsOut = bands.BbandsOut;
pub const BbandsParams = bands.BbandsParams;
pub const bbands = bands.bbands;
pub const bbandsLookback = bands.bbandsLookback;
pub const BbandsStream = bands.BbandsStream;

test {
    _ = core;
    _ = smooth;
    _ = window;
    _ = rsi_;
    _ = range;
    _ = macd_;
    _ = bands;
    _ = stoch_;
    _ = @import("testhelp.zig");
    _ = @import("oracle_test.zig");
}

test "root: the module doc example runs" {
    var closes: [20]f64 = undefined;
    for (&closes, 0..) |*c, i| c.* = @floatFromInt(i);
    var out: [20]f64 = undefined;
    const lb = try ema(f64, &closes, &out, .{ .period = 12 });
    try std.testing.expectEqual(@as(usize, 11), lb);
    try std.testing.expectEqual(lb, try emaLookback(.{ .period = 12 }));
    var s = try EmaStream(f64).init(.{ .period = 12 });
    var last: ?f64 = null;
    for (closes) |c| last = s.update(c) orelse last;
    try std.testing.expectEqual(out[19], last.?);
}
