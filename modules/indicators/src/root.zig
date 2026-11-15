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
const mom_wilder = @import("mom_wilder.zig");
const mom_simple = @import("mom_simple.zig");

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

// BEGIN momentum exports (generated from the mom_*.zig files)
pub const WilderParams = mom_wilder.WilderParams;
pub const adxLookback = mom_wilder.adxLookback;
pub const AdxStream = mom_wilder.AdxStream;
pub const dxLookback = mom_wilder.dxLookback;
pub const DxStream = mom_wilder.DxStream;
pub const adxrLookback = mom_wilder.adxrLookback;
pub const AdxrStream = mom_wilder.AdxrStream;
pub const minusDmLookback = mom_wilder.minusDmLookback;
pub const MinusDmStream = mom_wilder.MinusDmStream;
pub const plusDmLookback = mom_wilder.plusDmLookback;
pub const PlusDmStream = mom_wilder.PlusDmStream;
pub const minusDiLookback = mom_wilder.minusDiLookback;
pub const MinusDiStream = mom_wilder.MinusDiStream;
pub const plusDiLookback = mom_wilder.plusDiLookback;
pub const PlusDiStream = mom_wilder.PlusDiStream;
pub const AroonParams = mom_wilder.AroonParams;
pub const aroonLookback = mom_wilder.aroonLookback;
pub const AroonStream = mom_wilder.AroonStream;
pub const aroonoscLookback = mom_wilder.aroonoscLookback;
pub const AroonoscStream = mom_wilder.AroonoscStream;
pub const adx = mom_wilder.adx;
pub const dx = mom_wilder.dx;
pub const adxr = mom_wilder.adxr;
pub const minusDm = mom_wilder.minusDm;
pub const plusDm = mom_wilder.plusDm;
pub const minusDi = mom_wilder.minusDi;
pub const plusDi = mom_wilder.plusDi;
pub const aroon = mom_wilder.aroon;
pub const aroonosc = mom_wilder.aroonosc;
pub const MomParams = mom_simple.MomParams;
pub const momLookback = mom_simple.momLookback;
pub const MomStream = mom_simple.MomStream;
pub const rocLookback = mom_simple.rocLookback;
pub const RocStream = mom_simple.RocStream;
pub const rocpLookback = mom_simple.rocpLookback;
pub const RocpStream = mom_simple.RocpStream;
pub const rocrLookback = mom_simple.rocrLookback;
pub const RocrStream = mom_simple.RocrStream;
pub const rocr100Lookback = mom_simple.rocr100Lookback;
pub const Rocr100Stream = mom_simple.Rocr100Stream;
pub const bopLookback = mom_simple.bopLookback;
pub const BopStream = mom_simple.BopStream;
pub const ibsLookback = mom_simple.ibsLookback;
pub const IbsStream = mom_simple.IbsStream;
pub const wadLookback = mom_simple.wadLookback;
pub const WadStream = mom_simple.WadStream;
pub const SwingParams = mom_simple.SwingParams;
pub const asiLookback = mom_simple.asiLookback;
pub const AsiStream = mom_simple.AsiStream;
pub const siLookback = mom_simple.siLookback;
pub const SiStream = mom_simple.SiStream;
pub const QstickParams = mom_simple.QstickParams;
pub const qstickLookback = mom_simple.qstickLookback;
pub const QstickStream = mom_simple.QstickStream;
pub const ImiParams = mom_simple.ImiParams;
pub const imiLookback = mom_simple.imiLookback;
pub const ImiStream = mom_simple.ImiStream;
pub const AoParams = mom_simple.AoParams;
pub const aoLookback = mom_simple.aoLookback;
pub const AoStream = mom_simple.AoStream;
pub const AcParams = mom_simple.AcParams;
pub const acLookback = mom_simple.acLookback;
pub const AcStream = mom_simple.AcStream;
pub const DpoParams = mom_simple.DpoParams;
pub const dpoLookback = mom_simple.dpoLookback;
pub const DpoStream = mom_simple.DpoStream;
pub const ErParams = mom_simple.ErParams;
pub const erLookback = mom_simple.erLookback;
pub const ErStream = mom_simple.ErStream;
pub const FoscParams = mom_simple.FoscParams;
pub const foscLookback = mom_simple.foscLookback;
pub const FoscStream = mom_simple.FoscStream;
pub const CtiParams = mom_simple.CtiParams;
pub const ctiLookback = mom_simple.ctiLookback;
pub const CtiStream = mom_simple.CtiStream;
pub const VhfParams = mom_simple.VhfParams;
pub const vhfLookback = mom_simple.vhfLookback;
pub const VhfStream = mom_simple.VhfStream;
pub const WillrParams = mom_simple.WillrParams;
pub const willrLookback = mom_simple.willrLookback;
pub const WillrStream = mom_simple.WillrStream;
pub const FractalParams = mom_simple.FractalParams;
pub const fractalLookback = mom_simple.fractalLookback;
pub const FractalStream = mom_simple.FractalStream;
pub const CciParams = mom_simple.CciParams;
pub const cciLookback = mom_simple.cciLookback;
pub const CciStream = mom_simple.CciStream;
pub const ChopParams = mom_simple.ChopParams;
pub const chopLookback = mom_simple.chopLookback;
pub const ChopStream = mom_simple.ChopStream;
pub const choptrLookback = mom_simple.choptrLookback;
pub const ChoptrStream = mom_simple.ChoptrStream;
pub const VortexParams = mom_simple.VortexParams;
pub const vortexLookback = mom_simple.vortexLookback;
pub const VortexStream = mom_simple.VortexStream;
pub const MfiParams = mom_simple.MfiParams;
pub const mfiLookback = mom_simple.mfiLookback;
pub const MfiStream = mom_simple.MfiStream;
pub const UltoscParams = mom_simple.UltoscParams;
pub const ultoscLookback = mom_simple.ultoscLookback;
pub const UltoscStream = mom_simple.UltoscStream;
pub const CmoParams = mom_simple.CmoParams;
pub const cmoLookback = mom_simple.cmoLookback;
pub const CmoStream = mom_simple.CmoStream;
pub const CmouParams = mom_simple.CmouParams;
pub const cmouLookback = mom_simple.cmouLookback;
pub const CmouStream = mom_simple.CmouStream;
pub const mom = mom_simple.mom;
pub const roc = mom_simple.roc;
pub const rocp = mom_simple.rocp;
pub const rocr = mom_simple.rocr;
pub const rocr100 = mom_simple.rocr100;
pub const bop = mom_simple.bop;
pub const ibs = mom_simple.ibs;
pub const wad = mom_simple.wad;
pub const asi = mom_simple.asi;
pub const si = mom_simple.si;
pub const qstick = mom_simple.qstick;
pub const imi = mom_simple.imi;
pub const ao = mom_simple.ao;
pub const ac = mom_simple.ac;
pub const dpo = mom_simple.dpo;
pub const er = mom_simple.er;
pub const fosc = mom_simple.fosc;
pub const cti = mom_simple.cti;
pub const vhf = mom_simple.vhf;
pub const willr = mom_simple.willr;
pub const fractal = mom_simple.fractal;
pub const cci = mom_simple.cci;
pub const chop = mom_simple.chop;
pub const choptr = mom_simple.choptr;
pub const vortex = mom_simple.vortex;
pub const mfi = mom_simple.mfi;
pub const ultosc = mom_simple.ultosc;
pub const cmo = mom_simple.cmo;
pub const cmou = mom_simple.cmou;
// END momentum exports

test {
    _ = core;
    _ = smooth;
    _ = window;
    _ = rsi_;
    _ = range;
    _ = macd_;
    _ = bands;
    _ = stoch_;
    _ = mom_wilder;
    _ = mom_simple;
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
