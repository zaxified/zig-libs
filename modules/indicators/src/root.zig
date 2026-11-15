// SPDX-License-Identifier: MIT
//! indicators: technical-analysis indicators over plain slices, with TA-Lib
//! 0.8.3 as the reference (formulas ported from its BSD-3 C source, see NOTICE).
//!
//! Seed set (wave I2): SMA, EMA, WMA, MA, MACD, MACDEXT, MACDFIX, RSI, BBANDS,
//! TRANGE, ATR, NATR, STOCH, STOCHF, MAX, MIN, SUM. Wave I3 (overlap studies):
//! DEMA, TEMA, T3, TRIMA, KAMA, MIDPOINT, MIDPRICE, SAR, SAREXT, MAVP, ACCBANDS,
//! ALMA, CKSP, DONCHIAN, FRAMA, HMA, ICHIMOKU, KC, MCGD, RMA, SUPERTREND,
//! SWAK_BUTTER, SWAK_GAUSS, VIDYA, VWMA, ZIGZAG, ZLEMA; every `MaType` but MAMA
//! now works in MA, MACDEXT, BBANDS, STOCH and STOCHF. Wave I3 (volume, volatility,
//! price transform, statistic, math operators): 50 more functions, see SPEC.md. 94 of
//! TA-Lib's 237 functions in all.
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
//! built yet (MAMA) is `error.Unsupported`. Nothing panics.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const window = @import("window.zig");
const rsi_ = @import("rsi.zig");
const range = @import("range.zig");
const macd_ = @import("macd.zig");
const bands = @import("bands.zig");
const stoch_ = @import("stoch.zig");
const mavg = @import("mavg.zig");
const overlap = @import("overlap.zig");
const trend_ = @import("trend.zig");
const channels = @import("channels.zig");
const hist = @import("hist.zig");
// BEGIN vs imports
const volume_ = @import("volume.zig");
const volatility_ = @import("volatility.zig");
const pricetx_ = @import("pricetx.zig");
const statistic_ = @import("statistic.zig");
const mathops_ = @import("mathops.zig");
// END vs imports

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Technical-analysis indicators (TA-Lib parity): moving averages (SMA to T3, KAMA, HMA, ALMA), MACD, RSI, Bollinger / Keltner / Donchian bands, ATR, stochastic, SAR, Supertrend, Ichimoku, rolling max/min/sum, plus 50 volume, volatility, price-transform, statistic and math-operator functions (OBV, VWAP, CMF, KVO, BBW, LINEARREG, MEDIAN, ...); 94 of TA-Lib's 237.",
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

// moving averages, wave I3 (also dispatched by `ma` / every `MaType` slot)
pub const DemaParams = mavg.DemaParams;
pub const dema = mavg.dema;
pub const demaLookback = mavg.demaLookback;
pub const DemaStream = mavg.DemaStream;
pub const TemaParams = mavg.TemaParams;
pub const tema = mavg.tema;
pub const temaLookback = mavg.temaLookback;
pub const TemaStream = mavg.TemaStream;
pub const T3Params = mavg.T3Params;
pub const t3 = mavg.t3;
pub const t3Lookback = mavg.t3Lookback;
pub const T3Stream = mavg.T3Stream;
pub const TrimaParams = mavg.TrimaParams;
pub const trima = mavg.trima;
pub const trimaLookback = mavg.trimaLookback;
pub const TrimaStream = mavg.TrimaStream;
pub const KamaParams = mavg.KamaParams;
pub const kama = mavg.kama;
pub const kamaLookback = mavg.kamaLookback;
pub const KamaStream = mavg.KamaStream;
pub const ZlemaParams = mavg.ZlemaParams;
pub const zlema = mavg.zlema;
pub const zlemaLookback = mavg.zlemaLookback;
pub const ZlemaStream = mavg.ZlemaStream;
pub const RmaParams = mavg.RmaParams;
pub const rma = mavg.rma;
pub const rmaLookback = mavg.rmaLookback;
pub const RmaStream = mavg.RmaStream;
pub const VidyaParams = mavg.VidyaParams;
pub const vidya = mavg.vidya;
pub const vidyaLookback = mavg.vidyaLookback;
pub const VidyaStream = mavg.VidyaStream;
pub const HmaParams = mavg.HmaParams;
pub const hma = mavg.hma;
pub const hmaLookback = mavg.hmaLookback;
pub const HmaStream = mavg.HmaStream;
pub const AlmaParams = mavg.AlmaParams;
pub const alma = mavg.alma;
pub const almaLookback = mavg.almaLookback;
pub const AlmaStream = mavg.AlmaStream;
pub const McgdParams = mavg.McgdParams;
pub const mcgd = mavg.mcgd;
pub const mcgdLookback = mavg.mcgdLookback;
pub const McgdStream = mavg.McgdStream;
pub const SwakParams = mavg.SwakParams;
pub const swakButter = mavg.swakButter;
pub const swakButterLookback = mavg.swakButterLookback;
pub const SwakButterStream = mavg.SwakButterStream;
pub const swakGauss = mavg.swakGauss;
pub const swakGaussLookback = mavg.swakGaussLookback;
pub const SwakGaussStream = mavg.SwakGaussStream;

// overlap studies, wave I3
pub const MidParams = overlap.MidParams;
pub const midpoint = overlap.midpoint;
pub const midpointLookback = overlap.midpointLookback;
pub const MidpointStream = overlap.MidpointStream;
pub const midprice = overlap.midprice;
pub const midpriceLookback = overlap.midpriceLookback;
pub const MidpriceStream = overlap.MidpriceStream;
pub const FramaParams = overlap.FramaParams;
pub const frama = overlap.frama;
pub const framaLookback = overlap.framaLookback;
pub const FramaStream = overlap.FramaStream;
pub const VwmaParams = overlap.VwmaParams;
pub const vwma = overlap.vwma;
pub const vwmaLookback = overlap.vwmaLookback;
pub const VwmaStream = overlap.VwmaStream;
pub const MavpParams = overlap.MavpParams;
pub const mavp = overlap.mavp;
pub const mavpLookback = overlap.mavpLookback;

pub const SarParams = trend_.SarParams;
pub const sar = trend_.sar;
pub const sarLookback = trend_.sarLookback;
pub const SarStream = trend_.SarStream;
pub const SarextParams = trend_.SarextParams;
pub const sarext = trend_.sarext;
pub const sarextLookback = trend_.sarextLookback;
pub const SarextStream = trend_.SarextStream;
pub const SupertrendParams = trend_.SupertrendParams;
pub const SupertrendOut = trend_.SupertrendOut;
pub const supertrend = trend_.supertrend;
pub const supertrendLookback = trend_.supertrendLookback;
pub const SupertrendStream = trend_.SupertrendStream;
pub const CkspParams = trend_.CkspParams;
pub const CkspOut = trend_.CkspOut;
pub const cksp = trend_.cksp;
pub const ckspLookback = trend_.ckspLookback;
pub const CkspStream = trend_.CkspStream;
pub const ZigzagParams = trend_.ZigzagParams;
pub const ZigzagOut = trend_.ZigzagOut;
pub const zigzag = trend_.zigzag;
pub const zigzagLookback = trend_.zigzagLookback;
pub const ZigzagStream = trend_.ZigzagStream;

pub const AccbandsParams = channels.AccbandsParams;
pub const accbands = channels.accbands;
pub const accbandsLookback = channels.accbandsLookback;
pub const AccbandsStream = channels.AccbandsStream;
pub const DonchianParams = channels.DonchianParams;
pub const donchian = channels.donchian;
pub const donchianLookback = channels.donchianLookback;
pub const DonchianStream = channels.DonchianStream;
pub const KcParams = channels.KcParams;
pub const kc = channels.kc;
pub const kcLookback = channels.kcLookback;
pub const KcStream = channels.KcStream;
pub const IchimokuParams = channels.IchimokuParams;
pub const IchimokuOut = channels.IchimokuOut;
pub const ichimoku = channels.ichimoku;
pub const ichimokuLookback = channels.ichimokuLookback;
pub const IchimokuStream = channels.IchimokuStream;
// BEGIN vs exports

// volume (volume / volatility / price transform / statistic / math operator waves)
pub const adLookback = volume_.adLookback;
pub const ad = volume_.ad;
pub const AdStream = volume_.AdStream;
pub const AdoscParams = volume_.AdoscParams;
pub const adoscLookback = volume_.adoscLookback;
pub const adosc = volume_.adosc;
pub const AdoscStream = volume_.AdoscStream;
pub const CmfParams = volume_.CmfParams;
pub const cmfLookback = volume_.cmfLookback;
pub const cmf = volume_.cmf;
pub const CmfStream = volume_.CmfStream;
pub const EfiParams = volume_.EfiParams;
pub const efiLookback = volume_.efiLookback;
pub const efi = volume_.efi;
pub const EfiStream = volume_.EfiStream;
pub const EmvParams = volume_.EmvParams;
pub const emvLookback = volume_.emvLookback;
pub const emv = volume_.emv;
pub const EmvStream = volume_.EmvStream;
pub const KvoParams = volume_.KvoParams;
pub const KvoOut = volume_.KvoOut;
pub const kvoLookback = volume_.kvoLookback;
pub const kvo = volume_.kvo;
pub const KvoStream = volume_.KvoStream;
pub const marketfiLookback = volume_.marketfiLookback;
pub const marketfi = volume_.marketfi;
pub const MarketfiStream = volume_.MarketfiStream;
pub const nviLookback = volume_.nviLookback;
pub const nvi = volume_.nvi;
pub const NviStream = volume_.NviStream;
pub const pviLookback = volume_.pviLookback;
pub const pvi = volume_.pvi;
pub const PviStream = volume_.PviStream;
pub const obvLookback = volume_.obvLookback;
pub const obv = volume_.obv;
pub const ObvStream = volume_.ObvStream;
pub const pvtLookback = volume_.pvtLookback;
pub const pvt = volume_.pvt;
pub const PvtStream = volume_.PvtStream;
pub const vwapLookback = volume_.vwapLookback;
pub const vwap = volume_.vwap;
pub const VwapStream = volume_.VwapStream;
pub const RvolParams = volume_.RvolParams;
pub const rvolLookback = volume_.rvolLookback;
pub const rvol = volume_.rvol;
pub const RvolStream = volume_.RvolStream;
pub const PvoParams = volume_.PvoParams;
pub const pvoLookback = volume_.pvoLookback;
pub const pvo = volume_.pvo;
pub const PvoStream = volume_.PvoStream;

// volatility (volume / volatility / price transform / statistic / math operator waves)
pub const AdrParams = volatility_.AdrParams;
pub const adrLookback = volatility_.adrLookback;
pub const adr = volatility_.adr;
pub const AdrStream = volatility_.AdrStream;
pub const BbwParams = volatility_.BbwParams;
pub const PercentbParams = volatility_.PercentbParams;
pub const bbwLookback = volatility_.bbwLookback;
pub const bbw = volatility_.bbw;
pub const BbwStream = volatility_.BbwStream;
pub const percentbLookback = volatility_.percentbLookback;
pub const percentb = volatility_.percentb;
pub const PercentbStream = volatility_.PercentbStream;
pub const CviParams = volatility_.CviParams;
pub const cviLookback = volatility_.cviLookback;
pub const cvi = volatility_.cvi;
pub const CviStream = volatility_.CviStream;
pub const MassiParams = volatility_.MassiParams;
pub const massiLookback = volatility_.massiLookback;
pub const massi = volatility_.massi;
pub const MassiStream = volatility_.MassiStream;
pub const RogersSatchellParams = volatility_.RogersSatchellParams;
pub const rogerssatchellLookback = volatility_.rogerssatchellLookback;
pub const rogerssatchell = volatility_.rogerssatchell;
pub const RogersSatchellStream = volatility_.RogersSatchellStream;
pub const RviParams = volatility_.RviParams;
pub const rviLookback = volatility_.rviLookback;
pub const rvi = volatility_.rvi;
pub const RviStream = volatility_.RviStream;
pub const rvirLookback = volatility_.rvirLookback;
pub const rvir = volatility_.rvir;
pub const RvirStream = volatility_.RvirStream;

// pricetx (volume / volatility / price transform / statistic / math operator waves)
pub const AvgdevParams = pricetx_.AvgdevParams;
pub const avgdevLookback = pricetx_.avgdevLookback;
pub const avgdev = pricetx_.avgdev;
pub const AvgdevStream = pricetx_.AvgdevStream;
pub const avgpriceLookback = pricetx_.avgpriceLookback;
pub const avgprice = pricetx_.avgprice;
pub const AvgpriceStream = pricetx_.AvgpriceStream;
pub const medpriceLookback = pricetx_.medpriceLookback;
pub const medprice = pricetx_.medprice;
pub const MedpriceStream = pricetx_.MedpriceStream;
pub const typpriceLookback = pricetx_.typpriceLookback;
pub const typprice = pricetx_.typprice;
pub const TyppriceStream = pricetx_.TyppriceStream;
pub const wclpriceLookback = pricetx_.wclpriceLookback;
pub const wclprice = pricetx_.wclprice;
pub const WclpriceStream = pricetx_.WclpriceStream;
pub const HaParams = pricetx_.HaParams;
pub const HaOut = pricetx_.HaOut;
pub const haLookback = pricetx_.haLookback;
pub const ha = pricetx_.ha;
pub const HaStream = pricetx_.HaStream;

// statistic (volume / volatility / price transform / statistic / math operator waves)
pub const VarianceParams = statistic_.VarianceParams;
pub const StddevParams = statistic_.StddevParams;
pub const varianceLookback = statistic_.varianceLookback;
pub const variance = statistic_.variance;
pub const VarianceStream = statistic_.VarianceStream;
pub const stddevLookback = statistic_.stddevLookback;
pub const stddev = statistic_.stddev;
pub const StddevStream = statistic_.StddevStream;
pub const LinearregParams = statistic_.LinearregParams;
pub const LrMode = statistic_.LrMode;
pub const linearregLookback = statistic_.linearregLookback;
pub const linearreg = statistic_.linearreg;
pub const LinearregStream = statistic_.LinearregStream;
pub const linearregSlopeLookback = statistic_.linearregSlopeLookback;
pub const linearregSlope = statistic_.linearregSlope;
pub const LinearregSlopeStream = statistic_.LinearregSlopeStream;
pub const linearregAngleLookback = statistic_.linearregAngleLookback;
pub const linearregAngle = statistic_.linearregAngle;
pub const LinearregAngleStream = statistic_.LinearregAngleStream;
pub const linearregInterceptLookback = statistic_.linearregInterceptLookback;
pub const linearregIntercept = statistic_.linearregIntercept;
pub const LinearregInterceptStream = statistic_.LinearregInterceptStream;
pub const tsfLookback = statistic_.tsfLookback;
pub const tsf = statistic_.tsf;
pub const TsfStream = statistic_.TsfStream;
pub const PercentrankParams = statistic_.PercentrankParams;
pub const percentrankLookback = statistic_.percentrankLookback;
pub const percentrank = statistic_.percentrank;
pub const PercentrankStream = statistic_.PercentrankStream;
pub const KurtosisParams = statistic_.KurtosisParams;
pub const kurtosisLookback = statistic_.kurtosisLookback;
pub const kurtosis = statistic_.kurtosis;
pub const KurtosisStream = statistic_.KurtosisStream;
pub const CorrelParams = statistic_.CorrelParams;
pub const correlLookback = statistic_.correlLookback;
pub const correl = statistic_.correl;
pub const CorrelStream = statistic_.CorrelStream;
pub const BetaParams = statistic_.BetaParams;
pub const betaLookback = statistic_.betaLookback;
pub const beta = statistic_.beta;
pub const BetaStream = statistic_.BetaStream;
pub const MedianParams = statistic_.MedianParams;
pub const medianLookback = statistic_.medianLookback;
pub const median = statistic_.median;
pub const MedianStream = statistic_.MedianStream;
pub const PercentileParams = statistic_.PercentileParams;
pub const percentileLookback = statistic_.percentileLookback;
pub const percentile = statistic_.percentile;
pub const PercentileStream = statistic_.PercentileStream;

// mathops (volume / volatility / price transform / statistic / math operator waves)
pub const no_index = mathops_.no_index;
pub const addLookback = mathops_.addLookback;
pub const add = mathops_.add;
pub const AddStream = mathops_.AddStream;
pub const subLookback = mathops_.subLookback;
pub const sub = mathops_.sub;
pub const SubStream = mathops_.SubStream;
pub const multLookback = mathops_.multLookback;
pub const mult = mathops_.mult;
pub const MultStream = mathops_.MultStream;
pub const divLookback = mathops_.divLookback;
pub const div = mathops_.div;
pub const DivStream = mathops_.DivStream;
pub const cumsumLookback = mathops_.cumsumLookback;
pub const cumsum = mathops_.cumsum;
pub const CumsumStream = mathops_.CumsumStream;
pub const MinmaxParams = mathops_.MinmaxParams;
pub const MaxindexParams = mathops_.MaxindexParams;
pub const MinindexParams = mathops_.MinindexParams;
pub const MinmaxindexParams = mathops_.MinmaxindexParams;
pub const MinmaxOut = mathops_.MinmaxOut;
pub const minmaxLookback = mathops_.minmaxLookback;
pub const minmax = mathops_.minmax;
pub const MinmaxStream = mathops_.MinmaxStream;
pub const maxindexLookback = mathops_.maxindexLookback;
pub const maxindex = mathops_.maxindex;
pub const MaxindexStream = mathops_.MaxindexStream;
pub const minindexLookback = mathops_.minindexLookback;
pub const minindex = mathops_.minindex;
pub const MinindexStream = mathops_.MinindexStream;
pub const MinmaxindexOut = mathops_.MinmaxindexOut;
pub const minmaxindexLookback = mathops_.minmaxindexLookback;
pub const minmaxindex = mathops_.minmaxindex;
pub const MinmaxindexStream = mathops_.MinmaxindexStream;
// END vs exports

test {
    _ = core;
    _ = smooth;
    _ = window;
    _ = rsi_;
    _ = range;
    _ = macd_;
    _ = bands;
    _ = stoch_;
    _ = mavg;
    _ = overlap;
    _ = trend_;
    _ = channels;
    _ = hist;
    _ = @import("overlap_test.zig");
    // BEGIN vs tests
    _ = volume_;
    _ = volatility_;
    _ = pricetx_;
    _ = statistic_;
    _ = mathops_;
    // END vs tests
    _ = @import("testhelp.zig");
    _ = @import("vs_kit.zig");
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
