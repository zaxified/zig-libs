// SPDX-License-Identifier: MIT
//! The whole public surface of `indicators` (every batch function, every
//! `Lookback`, every streaming type, 237 functions) under hostile inputs: NaN,
//! +-inf, huge, denormal and -0 values, lengths 0 .. 600, every parameter at and
//! beyond its range (0, 1, 100000, 100001, 2^30, usize max, signed -1, NaN
//! floats), slice lengths that disagree, output slices too short or too long,
//! stream buffers too short, and a failing allocator for the functions that take
//! one. Nothing may panic, hang, leak or allocate without bound, and the facts
//! that hold between the functions must hold on any input:
//!
//!   - a length mismatch is `error.BadParam`, never a success;
//!   - a batch call that succeeds returns exactly what `Lookback` says, writes
//!     every output slot (a signalling-NaN sentinel survives nowhere) and leaves
//!     the first `lookback` slots NaN;
//!   - the same call over differently pre-filled output buffers answers the same
//!     bits (no read of an output slot that was never written);
//!   - the stream agrees with the batch call (bit for bit, `-0.0 == 0.0` and any
//!     NaN == any NaN), `peek` equals `update`, a stream rebuilt over a
//!     differently filled buffer answers the same, a clone continues like its
//!     original, a buffer one slot short is `error.BadParam`;
//!   - `Lookback`, the batch call and the stream agree on which parameters are
//!     out of range.
//!
//! One harness run draws up to four (function, element type, seed) triples; the
//! seed then drives a local PRNG that builds the data, the lengths and the
//! parameters, so the harness body is not generic over the choice source.
//!
//! `INDICATORS_FUZZ=<runs>[,<seed>]` runs the deterministic driver (and prints
//! `RF` lines: per function runs / batch ok / f32 ok / stream passes); 237 x 6
//! forced runs, one at least with default parameters, are part of every test run,
//! and they must get everywhere.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ind = @import("root.zig");
const cc = @import("candles_core.zig");
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;

const max_n: usize = 600;
/// Backing length of every input: lengths up to `n + 8` are drawn for the mismatch cases.
const cap: usize = max_n + 8;
/// One batch call must not allocate more than this (bytes, cumulative): the scratch of the
/// largest legal period (100000 f64) times a few, not a function of anything else.
const alloc_cap: usize = 16 << 20;
/// One stream may ask for at most this many buffer elements.
const stream_buf_cap: usize = 4 << 20;

// ── the table ───────────────────────────────────────────────────────────────

/// `{ name, argument spec, batch function, lookback function, stream constructor or void }`.
/// Spec letters, after the leading `comptime T`: `g` allocator, `i` input `[]const T`, `o` output
/// `[]T`, `8` `[]i8`, `3` `[]i32`, `u` `[]usize` outputs, `p` the params struct (the type is read
/// from the lookback function). The 61 candlestick patterns are not in the table: they are
/// generated from `candles.all`.
const rows = .{
    .{ "sma", "iop", ind.sma, ind.smaLookback, ind.SmaStream },
    .{ "ema", "iop", ind.ema, ind.emaLookback, ind.EmaStream },
    .{ "wma", "iop", ind.wma, ind.wmaLookback, ind.WmaStream },
    .{ "ma", "iop", ind.ma, ind.maLookback, ind.MaStream },
    .{ "sum", "iop", ind.sum, ind.sumLookback, ind.SumStream },
    .{ "max", "iop", ind.max, ind.maxLookback, ind.MaxStream },
    .{ "min", "iop", ind.min, ind.minLookback, ind.MinStream },
    .{ "rsi", "iop", ind.rsi, ind.rsiLookback, ind.RsiStream },
    .{ "macd", "iooop", ind.macd, ind.macdLookback, ind.MacdStream },
    .{ "macdext", "giooop", ind.macdext, ind.macdextLookback, ind.MacdextStream },
    .{ "macdfix", "iooop", ind.macdfix, ind.macdfixLookback, ind.MacdfixStream },
    .{ "stoch", "giiioop", ind.stoch, ind.stochLookback, ind.StochStream },
    .{ "stochf", "giiioop", ind.stochf, ind.stochfLookback, ind.StochfStream },
    .{ "trange", "iiio", ind.trange, ind.trangeLookback, ind.TrangeStream },
    .{ "atr", "iiiop", ind.atr, ind.atrLookback, ind.AtrStream },
    .{ "natr", "iiiop", ind.natr, ind.natrLookback, ind.NatrStream },
    .{ "bbands", "iooop", ind.bbands, ind.bbandsLookback, ind.BbandsStream },
    .{ "dema", "iop", ind.dema, ind.demaLookback, ind.DemaStream },
    .{ "tema", "iop", ind.tema, ind.temaLookback, ind.TemaStream },
    .{ "t3", "iop", ind.t3, ind.t3Lookback, ind.T3Stream },
    .{ "trima", "iop", ind.trima, ind.trimaLookback, ind.TrimaStream },
    .{ "kama", "iop", ind.kama, ind.kamaLookback, ind.KamaStream },
    .{ "zlema", "iop", ind.zlema, ind.zlemaLookback, ind.ZlemaStream },
    .{ "rma", "iop", ind.rma, ind.rmaLookback, ind.RmaStream },
    .{ "vidya", "iop", ind.vidya, ind.vidyaLookback, ind.VidyaStream },
    .{ "hma", "iop", ind.hma, ind.hmaLookback, ind.HmaStream },
    .{ "alma", "giop", ind.alma, ind.almaLookback, ind.AlmaStream },
    .{ "mcgd", "iop", ind.mcgd, ind.mcgdLookback, ind.McgdStream },
    .{ "swakButter", "iop", ind.swakButter, ind.swakButterLookback, ind.SwakButterStream },
    .{ "swakGauss", "iop", ind.swakGauss, ind.swakGaussLookback, ind.SwakGaussStream },
    .{ "midpoint", "iop", ind.midpoint, ind.midpointLookback, ind.MidpointStream },
    .{ "midprice", "iiop", ind.midprice, ind.midpriceLookback, ind.MidpriceStream },
    .{ "frama", "iiop", ind.frama, ind.framaLookback, ind.FramaStream },
    .{ "vwma", "iiop", ind.vwma, ind.vwmaLookback, ind.VwmaStream },
    .{ "mavp", "iiop", ind.mavp, ind.mavpLookback, void },
    .{ "sar", "iiop", ind.sar, ind.sarLookback, ind.SarStream },
    .{ "sarext", "iiop", ind.sarext, ind.sarextLookback, ind.SarextStream },
    .{ "supertrend", "iiio8p", ind.supertrend, ind.supertrendLookback, ind.SupertrendStream },
    .{ "cksp", "giiioop", ind.cksp, ind.ckspLookback, ind.CkspStream },
    .{ "zigzag", "iio83p", ind.zigzag, ind.zigzagLookback, ind.ZigzagStream },
    .{ "accbands", "iiiooop", ind.accbands, ind.accbandsLookback, ind.AccbandsStream },
    .{ "donchian", "iiooop", ind.donchian, ind.donchianLookback, ind.DonchianStream },
    .{ "kc", "iiiooop", ind.kc, ind.kcLookback, ind.KcStream },
    .{ "ichimoku", "iioooop", ind.ichimoku, ind.ichimokuLookback, ind.IchimokuStream },
    .{ "htDcperiod", "iop", ind.htDcperiod, ind.htDcperiodLookback, ind.HtDcperiodStream },
    .{ "htDcphase", "iop", ind.htDcphase, ind.htDcphaseLookback, ind.HtDcphaseStream },
    .{ "htPhasor", "ioop", ind.htPhasor, ind.htPhasorLookback, ind.HtPhasorStream },
    .{ "htSine", "ioop", ind.htSine, ind.htSineLookback, ind.HtSineStream },
    .{ "htTrendline", "iop", ind.htTrendline, ind.htTrendlineLookback, ind.HtTrendlineStream },
    .{ "htTrendmode", "i8p", ind.htTrendmode, ind.htTrendmodeLookback, ind.HtTrendmodeStream },
    .{ "mama", "ioop", ind.mama, ind.mamaLookback, ind.MamaStream },
    .{ "swakBp", "iop", ind.swakBp, ind.swakBpLookback, ind.SwakBpStream },
    .{ "swakHp", "iop", ind.swakHp, ind.swakHpLookback, ind.SwakHpStream },
    .{ "swak2php", "iop", ind.swak2php, ind.swak2phpLookback, ind.Swak2phpStream },
    .{ "ad", "iiiio", ind.ad, ind.adLookback, ind.AdStream },
    .{ "adosc", "iiiiop", ind.adosc, ind.adoscLookback, ind.AdoscStream },
    .{ "cmf", "iiiiop", ind.cmf, ind.cmfLookback, ind.CmfStream },
    .{ "efi", "iiop", ind.efi, ind.efiLookback, ind.EfiStream },
    .{ "emv", "iiiop", ind.emv, ind.emvLookback, ind.EmvStream },
    .{ "kvo", "iiiioop", ind.kvo, ind.kvoLookback, ind.KvoStream },
    .{ "marketfi", "iiio", ind.marketfi, ind.marketfiLookback, ind.MarketfiStream },
    .{ "nvi", "iio", ind.nvi, ind.nviLookback, ind.NviStream },
    .{ "pvi", "iio", ind.pvi, ind.pviLookback, ind.PviStream },
    .{ "obv", "iio", ind.obv, ind.obvLookback, ind.ObvStream },
    .{ "pvt", "iio", ind.pvt, ind.pvtLookback, ind.PvtStream },
    .{ "vwap", "iiiio", ind.vwap, ind.vwapLookback, ind.VwapStream },
    .{ "rvol", "iop", ind.rvol, ind.rvolLookback, ind.RvolStream },
    .{ "pvo", "iop", ind.pvo, ind.pvoLookback, ind.PvoStream },
    .{ "adr", "iiop", ind.adr, ind.adrLookback, ind.AdrStream },
    .{ "bbw", "iop", ind.bbw, ind.bbwLookback, ind.BbwStream },
    .{ "percentb", "iop", ind.percentb, ind.percentbLookback, ind.PercentbStream },
    .{ "cvi", "iiop", ind.cvi, ind.cviLookback, ind.CviStream },
    .{ "massi", "iiop", ind.massi, ind.massiLookback, ind.MassiStream },
    .{ "rogerssatchell", "iiiiop", ind.rogerssatchell, ind.rogerssatchellLookback, ind.RogersSatchellStream },
    .{ "rvi", "iop", ind.rvi, ind.rviLookback, ind.RviStream },
    .{ "rvir", "iiop", ind.rvir, ind.rvirLookback, ind.RvirStream },
    .{ "avgdev", "iop", ind.avgdev, ind.avgdevLookback, ind.AvgdevStream },
    .{ "avgprice", "iiiio", ind.avgprice, ind.avgpriceLookback, ind.AvgpriceStream },
    .{ "medprice", "iio", ind.medprice, ind.medpriceLookback, ind.MedpriceStream },
    .{ "typprice", "iiio", ind.typprice, ind.typpriceLookback, ind.TyppriceStream },
    .{ "wclprice", "iiio", ind.wclprice, ind.wclpriceLookback, ind.WclpriceStream },
    .{ "ha", "iiiioooop", ind.ha, ind.haLookback, ind.HaStream },
    .{ "variance", "iop", ind.variance, ind.varianceLookback, ind.VarianceStream },
    .{ "stddev", "iop", ind.stddev, ind.stddevLookback, ind.StddevStream },
    .{ "linearreg", "iop", ind.linearreg, ind.linearregLookback, ind.LinearregStream },
    .{ "linearregSlope", "iop", ind.linearregSlope, ind.linearregSlopeLookback, ind.LinearregSlopeStream },
    .{ "linearregAngle", "iop", ind.linearregAngle, ind.linearregAngleLookback, ind.LinearregAngleStream },
    .{ "linearregIntercept", "iop", ind.linearregIntercept, ind.linearregInterceptLookback, ind.LinearregInterceptStream },
    .{ "tsf", "iop", ind.tsf, ind.tsfLookback, ind.TsfStream },
    .{ "percentrank", "iop", ind.percentrank, ind.percentrankLookback, ind.PercentrankStream },
    .{ "kurtosis", "iop", ind.kurtosis, ind.kurtosisLookback, ind.KurtosisStream },
    .{ "correl", "iiop", ind.correl, ind.correlLookback, ind.CorrelStream },
    .{ "beta", "iiop", ind.beta, ind.betaLookback, ind.BetaStream },
    .{ "median", "giop", ind.median, ind.medianLookback, ind.MedianStream },
    .{ "percentile", "giop", ind.percentile, ind.percentileLookback, ind.PercentileStream },
    .{ "add", "iio", ind.add, ind.addLookback, ind.AddStream },
    .{ "sub", "iio", ind.sub, ind.subLookback, ind.SubStream },
    .{ "mult", "iio", ind.mult, ind.multLookback, ind.MultStream },
    .{ "div", "iio", ind.div, ind.divLookback, ind.DivStream },
    .{ "cumsum", "io", ind.cumsum, ind.cumsumLookback, ind.CumsumStream },
    .{ "minmax", "ioop", ind.minmax, ind.minmaxLookback, ind.MinmaxStream },
    .{ "maxindex", "iup", ind.maxindex, ind.maxindexLookback, ind.MaxindexStream },
    .{ "minindex", "iup", ind.minindex, ind.minindexLookback, ind.MinindexStream },
    .{ "minmaxindex", "iuup", ind.minmaxindex, ind.minmaxindexLookback, ind.MinmaxindexStream },
    .{ "adx", "iiiop", ind.adx, ind.adxLookback, ind.AdxStream },
    .{ "dx", "iiiop", ind.dx, ind.dxLookback, ind.DxStream },
    .{ "adxr", "giiiop", ind.adxr, ind.adxrLookback, ind.AdxrStream },
    .{ "minusDm", "iiop", ind.minusDm, ind.minusDmLookback, ind.MinusDmStream },
    .{ "plusDm", "iiop", ind.plusDm, ind.plusDmLookback, ind.PlusDmStream },
    .{ "minusDi", "iiiop", ind.minusDi, ind.minusDiLookback, ind.MinusDiStream },
    .{ "plusDi", "iiiop", ind.plusDi, ind.plusDiLookback, ind.PlusDiStream },
    .{ "aroon", "iioop", ind.aroon, ind.aroonLookback, ind.AroonStream },
    .{ "aroonosc", "iiop", ind.aroonosc, ind.aroonoscLookback, ind.AroonoscStream },
    .{ "mom", "iop", ind.mom, ind.momLookback, ind.MomStream },
    .{ "roc", "iop", ind.roc, ind.rocLookback, ind.RocStream },
    .{ "rocp", "iop", ind.rocp, ind.rocpLookback, ind.RocpStream },
    .{ "rocr", "iop", ind.rocr, ind.rocrLookback, ind.RocrStream },
    .{ "rocr100", "iop", ind.rocr100, ind.rocr100Lookback, ind.Rocr100Stream },
    .{ "bop", "iiiio", ind.bop, ind.bopLookback, ind.BopStream },
    .{ "ibs", "iiio", ind.ibs, ind.ibsLookback, ind.IbsStream },
    .{ "wad", "iiio", ind.wad, ind.wadLookback, ind.WadStream },
    .{ "asi", "iiiiop", ind.asi, ind.asiLookback, ind.AsiStream },
    .{ "si", "iiiiop", ind.si, ind.siLookback, ind.SiStream },
    .{ "qstick", "iiop", ind.qstick, ind.qstickLookback, ind.QstickStream },
    .{ "imi", "iiop", ind.imi, ind.imiLookback, ind.ImiStream },
    .{ "ao", "iiop", ind.ao, ind.aoLookback, ind.AoStream },
    .{ "ac", "giiop", ind.ac, ind.acLookback, ind.AcStream },
    .{ "dpo", "iop", ind.dpo, ind.dpoLookback, ind.DpoStream },
    .{ "er", "iop", ind.er, ind.erLookback, ind.ErStream },
    .{ "fosc", "iop", ind.fosc, ind.foscLookback, ind.FoscStream },
    .{ "cti", "iop", ind.cti, ind.ctiLookback, ind.CtiStream },
    .{ "vhf", "iop", ind.vhf, ind.vhfLookback, ind.VhfStream },
    .{ "willr", "iiiop", ind.willr, ind.willrLookback, ind.WillrStream },
    .{ "fractal", "gii88p", ind.fractal, ind.fractalLookback, ind.FractalStream },
    .{ "cci", "iiiop", ind.cci, ind.cciLookback, ind.CciStream },
    .{ "chop", "iiiop", ind.chop, ind.chopLookback, ind.ChopStream },
    .{ "choptr", "iiiop", ind.choptr, ind.choptrLookback, ind.ChoptrStream },
    .{ "vortex", "iiioop", ind.vortex, ind.vortexLookback, ind.VortexStream },
    .{ "mfi", "iiiiop", ind.mfi, ind.mfiLookback, ind.MfiStream },
    .{ "ultosc", "iiiop", ind.ultosc, ind.ultoscLookback, ind.UltoscStream },
    .{ "cmo", "iop", ind.cmo, ind.cmoLookback, ind.CmoStream },
    .{ "cmou", "iop", ind.cmou, ind.cmouLookback, ind.CmouStream },
    .{ "cg", "iop", ind.cg, ind.cgLookback, ind.CgStream },
    .{ "trix", "iop", ind.trix, ind.trixLookback, ind.TrixStream },
    .{ "apo", "iop", ind.apo, ind.apoLookback, ind.ApoStream },
    .{ "ppo", "iop", ind.ppo, ind.ppoLookback, ind.PpoStream },
    .{ "coppock", "iop", ind.coppock, ind.coppockLookback, ind.CoppockStream },
    .{ "eri", "iiioop", ind.eri, ind.eriLookback, ind.EriStream },
    .{ "dosc", "giop", ind.dosc, ind.doscLookback, ind.DoscStream },
    .{ "fisher", "iioop", ind.fisher, ind.fisherLookback, ind.FisherStream },
    .{ "pso", "iiiop", ind.pso, ind.psoLookback, ind.PsoStream },
    .{ "smi", "iiioop", ind.smi, ind.smiLookback, ind.SmiStream },
    .{ "tsi", "iop", ind.tsi, ind.tsiLookback, ind.TsiStream },
    .{ "wavetrend", "giiioop", ind.wavetrend, ind.wavetrendLookback, ind.WavetrendStream },
    .{ "kst", "gioop", ind.kst, ind.kstLookback, ind.KstStream },
    .{ "kstext", "gioop", ind.kstext, ind.kstextLookback, ind.KstextStream },
    .{ "kdj", "giiiooop", ind.kdj, ind.kdjLookback, ind.KdjStream },
    .{ "stochrsi", "gioop", ind.stochrsi, ind.stochrsiLookback, ind.StochrsiStream },
    .{ "crsi", "giop", ind.crsi, ind.crsiLookback, ind.CrsiStream },
    .{ "stc", "giop", ind.stc, ind.stcLookback, ind.StcStream },
    .{ "sqzmom", "giiio8p", ind.sqzmom, ind.sqzmomLookback, ind.SqzmomStream },
    .{ "acos", "io", ind.acos, ind.acosLookback, ind.AcosStream },
    .{ "asin", "io", ind.asin, ind.asinLookback, ind.AsinStream },
    .{ "atan", "io", ind.atan, ind.atanLookback, ind.AtanStream },
    .{ "ceil", "io", ind.ceil, ind.ceilLookback, ind.CeilStream },
    .{ "cos", "io", ind.cos, ind.cosLookback, ind.CosStream },
    .{ "cosh", "io", ind.cosh, ind.coshLookback, ind.CoshStream },
    .{ "exp", "io", ind.exp, ind.expLookback, ind.ExpStream },
    .{ "floor", "io", ind.floor, ind.floorLookback, ind.FloorStream },
    .{ "ln", "io", ind.ln, ind.lnLookback, ind.LnStream },
    .{ "log10", "io", ind.log10, ind.log10Lookback, ind.Log10Stream },
    .{ "sin", "io", ind.sin, ind.sinLookback, ind.SinStream },
    .{ "sinh", "io", ind.sinh, ind.sinhLookback, ind.SinhStream },
    .{ "sqrt", "io", ind.sqrt, ind.sqrtLookback, ind.SqrtStream },
    .{ "tan", "io", ind.tan, ind.tanLookback, ind.TanStream },
    .{ "tanh", "io", ind.tanh, ind.tanhLookback, ind.TanhStream },
};

const n_rows = rows.len;
const n_entries = n_rows + ind.candles.all.len;

// ── per-function reach ──────────────────────────────────────────────────────

const Counts = struct { runs: u64 = 0, ok: u64 = 0, ok32: u64 = 0, bad: u64 = 0, oom: u64 = 0, mismatch: u64 = 0, stream: u64 = 0, clone: u64 = 0 };
var reach_table: [n_entries]Counts = @splat(.{});
var entry_names: [n_entries][]const u8 = undefined;
var cur_name: []const u8 = "";
var cur_seed: u64 = 0;
var cur_t: []const u8 = "";
var cur_idx: usize = 0;
var cur_bar: usize = 0;
var findings: u64 = 0;
var fcount: [n_entries]u8 = @splat(0);
var cur_info: [768]u8 = undefined;
var cur_info_len: usize = 0;

fn fail(msg: []const u8) error{FuzzFinding} {
    findings += 1;
    if (fcount[cur_idx] >= 2) return error.FuzzFinding;
    fcount[cur_idx] += 1;
    std.debug.print("indicators fuzz FINDING: {s} [{s}, T={s}, entry seed={d}, bar {d}] {s}\n", .{ msg, cur_name, cur_t, cur_seed, cur_bar, cur_info[0..cur_info_len] });
    return error.FuzzFinding;
}

// ── a local PRNG ────────────────────────────────────────────────────────────

const R = struct {
    p: std.Random.DefaultPrng,
    fn init(seed: u64) R {
        return .{ .p = .init(seed) };
    }
    fn range(self: *R, comptime T: type, lo: T, hi: T) T {
        return self.p.random().intRangeAtMost(T, lo, hi);
    }
    fn bits(self: *R) u64 {
        return self.p.random().int(u64);
    }
    fn chance(self: *R, pct: u8) bool {
        return self.range(u8, 0, 99) < pct;
    }
};

fn trunc(comptime F: type, v: u64) F {
    const U = @Int(.unsigned, @bitSizeOf(F));
    return @bitCast(@as(U, @truncate(v)));
}

fn special(r: *R) f64 {
    return switch (r.range(u8, 0, 15)) {
        0 => std.math.nan(f64),
        1 => std.math.inf(f64),
        2 => -std.math.inf(f64),
        3 => 0,
        4 => -0.0,
        5 => 1e308,
        6 => -1e308,
        7 => 5e-324,
        8 => -5e-324,
        9 => 1e-300,
        10 => 1e150,
        11 => std.math.floatMax(f64),
        12 => -1,
        13 => 1,
        14 => @bitCast(r.bits()),
        else => std.math.floatMin(f64),
    };
}

fn drawInt(comptime F: type, r: *R) F {
    const info = @typeInfo(F).int;
    return switch (r.range(u8, 0, 16)) {
        0 => 0,
        1 => 1,
        2 => 2,
        3...9 => trunc(F, r.range(u8, 2, 30)),
        10 => trunc(F, r.range(u16, 31, 700)),
        11 => trunc(F, 99_999 + @as(u64, r.range(u8, 0, 2))),
        12 => std.math.maxInt(F),
        13 => std.math.maxInt(F) - trunc(F, r.range(u8, 0, 3)),
        14 => trunc(F, (@as(u64, 1) << 30) - 1 + r.range(u8, 0, 2)),
        15 => if (info.signedness == .signed) trunc(F, @bitCast(@as(i64, -1))) else trunc(F, 3),
        else => trunc(F, r.bits()),
    };
}

fn drawFloat(r: *R) f64 {
    return switch (r.range(u8, 0, 13)) {
        0 => std.math.nan(f64),
        1 => std.math.inf(f64),
        2 => -std.math.inf(f64),
        3 => 0,
        4 => -0.0,
        5 => 1,
        6 => -1,
        7 => 0.5,
        8 => 2,
        9, 10 => @as(f64, @floatFromInt(r.range(i32, -3000, 3000))) / 1000.0,
        11 => 1e-300,
        12 => 1e300,
        else => @bitCast(r.bits()),
    };
}

/// A value of any type a parameter struct is made of. A field with a default keeps it
/// `default_pct` times in 100.
fn drawValue(comptime F: type, dv: ?F, r: *R, default_pct: u8) F {
    if (dv) |d| if (r.chance(default_pct)) return d;
    switch (@typeInfo(F)) {
        .int => return drawInt(F, r),
        .float => return @floatCast(drawFloat(r)),
        .bool => return r.chance(50),
        .@"enum" => {
            const vs = comptime std.enums.values(F);
            return vs[r.range(usize, 0, vs.len - 1)];
        },
        .optional => |o| return if (r.chance(50)) null else drawValue(o.child, null, r, 0),
        .@"union" => {
            if (F != ind.Unstable) @compileError("fuzz: unknown union parameter " ++ @typeName(F));
            return switch (r.range(u8, 0, 3)) {
                0 => .auto4,
                1 => .auto8,
                else => .{ .bars = drawInt(usize, r) },
            };
        },
        .@"struct" => |s| {
            var v: F = undefined;
            inline for (s.field_names, s.field_types, s.field_attrs) |nm, ft, at| {
                @field(v, nm) = drawValue(ft, at.defaultValue(ft), r, default_pct);
            }
            return v;
        },
        else => @compileError("fuzz: unknown parameter type " ++ @typeName(F)),
    }
}

/// Every field at its default and one of them hostile: what a range check that forgot a field lets through.
fn drawOne(comptime P: type, r: *R) P {
    var p = drawValue(P, null, r, 100);
    const s = @typeInfo(P).@"struct";
    if (s.field_names.len == 0) return p;
    const k = r.range(usize, 0, s.field_names.len - 1);
    inline for (s.field_names, s.field_types, s.field_attrs, 0..) |nm, ft, at, i| {
        if (i == k) @field(p, nm) = drawValue(ft, at.defaultValue(ft), r, 0);
    }
    return p;
}

// ── data ────────────────────────────────────────────────────────────────────

fn drawLen(r: *R) usize {
    return switch (r.range(u8, 0, 99)) {
        0...3 => 0,
        4...7 => 1,
        8...27 => r.range(usize, 2, 10),
        28...58 => r.range(usize, 11, 64),
        else => r.range(usize, 65, max_n),
    };
}

/// Open, high, low, close, volume over `len` bars, in one of several shapes.
fn genBars(r: *R, bars: *[5][cap]f64, len: usize) void {
    const scale: f64 = switch (r.range(u8, 0, 11)) {
        0 => 1e-9,
        1 => 1e12,
        2 => 1e-3,
        3 => 1e6,
        4 => 1e150,
        else => 1,
    };
    var px: f64 = scale * @as(f64, switch (r.range(u8, 0, 9)) {
        0 => 0,
        1 => -50,
        2 => 1,
        3 => 0.001,
        else => 100,
    });
    const step: f64 = scale * @as(f64, switch (r.range(u8, 0, 5)) {
        0 => 0,
        1 => 0.01,
        else => 1,
    });
    for (0..len) |i| {
        const d = @as(f64, @floatFromInt(r.range(i32, -1000, 1000))) / 1000.0 * step;
        const o = px;
        const c = o + d;
        const up = @as(f64, @floatFromInt(r.range(u16, 0, 1000))) / 1000.0 * step;
        const dn = @as(f64, @floatFromInt(r.range(u16, 0, 1000))) / 1000.0 * step;
        bars[0][i] = o;
        bars[1][i] = @max(o, c) + up;
        bars[2][i] = @min(o, c) - dn;
        bars[3][i] = c;
        bars[4][i] = @floatFromInt(r.range(u32, 0, 1_000_000));
        px = c;
    }
    switch (r.range(u8, 0, 19)) {
        8...12 => for (0..@as(usize, r.range(u8, 1, 4))) |_| {
            bars[r.range(u8, 0, 4)][r.range(usize, 0, len - 1)] = special(r);
        },
        13, 14 => for (bars) |*s| for (s[0..len]) |*v| {
            if (r.chance(35)) v.* = special(r);
        },
        15, 16 => {
            const k = if (r.chance(50)) @as(f64, @floatFromInt(r.range(i8, -3, 3))) else special(r);
            for (bars) |*s| @memset(s[0..len], k);
        },
        17, 18 => for (bars) |*s| for (s[0..len]) |*v| {
            v.* = @floatFromInt(r.range(u8, 0, 4));
        },
        else => {},
    }
}

/// Which of the five series feeds input `k`: mostly the natural reading (close;
/// high, low; high, low, close; open, high, low, close), sometimes with the volume
/// in place of the bar, sometimes anything.
fn assign(r: *R, out: []u8) void {
    const wild = r.chance(15);
    const vol = r.chance(35);
    for (out, 0..) |*o, k| {
        if (wild) {
            o.* = r.range(u8, 0, 4);
            continue;
        }
        o.* = switch (out.len) {
            1 => 3,
            2 => if (vol) @as(u8, if (k == 0) 3 else 4) else @as(u8, @intCast(1 + k)),
            3 => if (vol) @as(u8, if (k == 2) 4 else @intCast(1 + k)) else @as(u8, @intCast(1 + k)),
            else => if (vol) @as(u8, @intCast(1 + k)) else @as(u8, @intCast(k)),
        };
    }
}

// ── the generic call ────────────────────────────────────────────────────────

fn has(comptime spec: []const u8, comptime c: u8) bool {
    return std.mem.findScalar(u8, spec, c) != null;
}
fn countIn(comptime spec: []const u8) usize {
    var k: usize = 0;
    for (spec) |c| {
        if (c == 'i') k += 1;
    }
    return k;
}
fn isOut(comptime c: u8) bool {
    return c == 'o' or c == '8' or c == '3' or c == 'u';
}
fn countOut(comptime spec: []const u8) usize {
    var k: usize = 0;
    for (spec) |c| {
        if (isOut(c)) k += 1;
    }
    return k;
}
fn outPos(comptime spec: []const u8, comptime k: usize) usize {
    var seen: usize = 0;
    for (spec, 0..) |c, pos| {
        if (isOut(c)) {
            if (seen == k) return pos;
            seen += 1;
        }
    }
    @compileError("fuzz: no such output");
}
fn ArgT(comptime T: type, comptime P: type, comptime c: u8) type {
    return switch (c) {
        'g' => Allocator,
        'i' => []const T,
        'o' => []T,
        '8' => []i8,
        '3' => []i32,
        'u' => []usize,
        'p' => P,
        else => @compileError("fuzz: bad spec letter"),
    };
}
fn Args(comptime T: type, comptime spec: []const u8, comptime P: type) type {
    var ts: [spec.len]type = undefined;
    for (spec, 0..) |c, i| ts[i] = ArgT(T, P, c);
    return @Tuple(&ts);
}

fn mkOut(comptime E: type, arena: Allocator, len: usize, fill: u8) ![]E {
    const s = try arena.alloc(E, len);
    @memset(s, sentinelOf(E, fill));
    return s;
}

fn sentinelOf(comptime E: type, fill: u8) E {
    return switch (@typeInfo(E)) {
        .float => if (E == f64)
            @bitCast(@as(u64, if (fill == 0) 0x7ff4_dead_beef_0001 else 0x7ff4_dead_beef_0002))
        else
            @bitCast(@as(u32, if (fill == 0) 0x7fa0_dead else 0x7fa0_beef)),
        .int => trunc(E, if (fill == 0) 0x5a5a_5a5a_5a5a_5a5a else 0x3c3c_3c3c_3c3c_3c3c),
        else => @compileError("fuzz: sentinel type"),
    };
}

/// The bits of a slot, widened: for comparing "the same answer" and "never written".
fn bitsOf(x: anytype) u64 {
    return switch (@typeInfo(@TypeOf(x))) {
        .float => if (@TypeOf(x) == f64) @as(u64, @bitCast(x)) else @as(u64, @as(u32, @bitCast(x))),
        .int => |i| if (i.signedness == .signed) @as(u64, @bitCast(@as(i64, x))) else @as(u64, x),
        else => @compileError("fuzz: bitsOf type"),
    };
}
fn isNanV(x: anytype) bool {
    return switch (@typeInfo(@TypeOf(x))) {
        .float => std.math.isNan(x),
        else => false,
    };
}
/// Same answer: equal bits, any NaN equal to any NaN.
fn sameV(a: anytype, b: @TypeOf(a)) bool {
    if (isNanV(a) and isNanV(b)) return true;
    return bitsOf(a) == bitsOf(b);
}
/// Same value (the stream and the batch form of MAX / MIN differ in the sign of a zero tie).
fn eqV(a: anytype, b: anytype) bool {
    if (isNanV(a) and isNanV(b)) return true;
    return switch (@typeInfo(@TypeOf(a))) {
        .float => a == b,
        else => @as(i128, a) == @as(i128, b),
    };
}

fn callLb(comptime lb: anytype, p: anytype, comptime hasP: bool) ind.Error!usize {
    return if (hasP) lb(p) else lb();
}

fn Result(comptime T: type, comptime spec: []const u8, comptime P: type) type {
    return struct { r: (ind.Error || Allocator.Error)!usize, a: Args(T, spec, P), bytes: usize };
}

fn callBatch(
    comptime T: type,
    comptime spec: []const u8,
    comptime P: type,
    comptime f: anytype,
    arena: Allocator,
    gpa: Allocator,
    ins: *const [countIn(spec)][]T,
    lens: *const [countIn(spec) + countOut(spec)]usize,
    p: P,
    fill: u8,
    fail_at: usize,
    alias: bool,
) !Result(T, spec, P) {
    const n_in = comptime countIn(spec);
    var a: Args(T, spec, P) = undefined;
    var fa = std.testing.FailingAllocator.init(gpa, .{ .fail_index = fail_at });
    comptime var ii: usize = 0;
    comptime var oi: usize = 0;
    inline for (spec, 0..) |ch, pos| {
        switch (ch) {
            'g' => a[pos] = fa.allocator(),
            'i' => {
                a[pos] = ins[ii][0..lens[ii]];
                ii += 1;
            },
            'o', '8', '3', 'u' => {
                const E = @typeInfo(ArgT(T, P, ch)).pointer.child;
                const s = if (comptime (E == T and oi == 0))
                    // in-place call: out is in (the contract says it must not be; it must still not crash)
                    (if (alias) ins[0][0..lens[n_in]] else try mkOut(E, arena, lens[n_in + oi], fill))
                else
                    try mkOut(E, arena, lens[n_in + oi], fill);
                a[pos] = s;
                oi += 1;
            },
            'p' => a[pos] = p,
            else => @compileError("fuzz: bad spec letter"),
        }
    }
    const r = @call(.auto, f, .{T} ++ a);
    return .{ .r = r, .a = a, .bytes = fa.allocated_bytes };
}

fn callIn(comptime St: type, comptime method: []const u8, s: anytype, vals: anytype) @typeInfo(@TypeOf(@field(St, method))).@"fn".return_type.? {
    const F = @field(St, method);
    const ps = @typeInfo(@TypeOf(F)).@"fn".param_types;
    if (comptime ps.len == 2 and @typeInfo(ps[1].?) == .@"struct") {
        var b: ps[1].? = undefined;
        inline for (@typeInfo(ps[1].?).@"struct".field_names, 0..) |fname, k| @field(b, fname) = vals[k];
        return F(s, b);
    }
    return switch (comptime ps.len - 1) {
        1 => F(s, vals[0]),
        2 => F(s, vals[0], vals[1]),
        3 => F(s, vals[0], vals[1], vals[2]),
        4 => F(s, vals[0], vals[1], vals[2], vals[3]),
        else => @compileError("fuzz: stream update arity"),
    };
}

/// A buffer element is an f64 or a struct of f64 (the candle ring keeps whole bars).
fn fillAny(comptime E: type, buf: []E, v: f64) void {
    if (E == f64) return @memset(buf, v);
    for (buf) |*e| {
        inline for (@typeInfo(E).@"struct".field_names) |nm| @field(e, nm) = v;
    }
}

fn isBad(e: anyerror) bool {
    return std.mem.eql(u8, @errorName(e), "BadParam");
}

/// A stream over `buf` (prefilled by the caller) fed `n` bars; the answers go to `outs`.
/// Checks `peek == update` and `value` on the way; at `n / 2` it clones when the type can.
fn feed(
    comptime St: type,
    comptime T: type,
    comptime n_in: usize,
    comptime X: type,
    comptime B: type,
    s: *St,
    ins: *const [n_in][]T,
    n: usize,
    outs: []?X,
    clone_dst: ?[]B,
    cloned: *bool,
) !void {
    var s2: St = undefined;
    var have2 = false;
    if (s.value() != null) return fail("value() is not null before the first update");
    for (0..n) |i| {
        cur_bar = i;
        var vals: [n_in]T = undefined;
        for (0..n_in) |k| vals[k] = ins[k][i];
        if (comptime @hasDecl(St, "clone")) {
            if (i == n / 2 and clone_dst != null and !have2) {
                if (s.clone(clone_dst.?)) |c| {
                    s2 = c;
                    have2 = true;
                    cloned.* = true;
                } else |_| return fail("clone into a buffer of the right size failed");
            }
        }
        const pk = callIn(St, "peek", s, vals);
        const u = callIn(St, "update", s, vals);
        outs[i] = u;
        if ((pk == null) != (u == null)) return fail("peek and update disagree on null");
        if (pk) |pv| if (!sameX(X, pv, u.?)) {
            std.debug.print("  peek {any} update {any}\n", .{ pv, u.? });
            return fail("peek differs from update");
        };
        if (u) |uv| {
            const v = s.value() orelse return fail("value() null after a non-null update");
            if (!sameX(X, v, uv)) {
                std.debug.print("  value {any} update {any}\n", .{ v, uv });
                return fail("value() differs from the last update");
            }
        }
        if (have2) {
            const uc = callIn(St, "update", &s2, vals);
            if ((uc == null) != (u == null)) return fail("clone differs from its original (null)");
            if (u) |uv| if (!sameX(X, uc.?, uv)) return fail("clone differs from its original");
        }
    }
}

fn sameX(comptime X: type, a: X, b: X) bool {
    switch (@typeInfo(X)) {
        .@"struct" => |s| {
            inline for (s.field_names) |nm| {
                if (!sameV(@field(a, nm), @field(b, nm))) return false;
            }
            return true;
        },
        else => return sameV(a, b),
    }
}

// ── one entry, one run ──────────────────────────────────────────────────────

fn runEntry(
    comptime T: type,
    comptime idx: usize,
    comptime name: []const u8,
    comptime spec: []const u8,
    comptime f: anytype,
    comptime lb: anytype,
    comptime S: anytype,
    gpa: Allocator,
    seed: u64,
    force_default: bool,
) !void {
    const n_in = comptime countIn(spec);
    const n_out = comptime countOut(spec);
    const hasG = comptime has(spec, 'g');
    const hasP = comptime has(spec, 'p');
    const P = comptime if (hasP) @typeInfo(@TypeOf(lb)).@"fn".param_types[0].? else void;
    const tname = comptime if (T == f64) "f64" else "f32";
    entry_names[idx] = name;
    cur_name = name;
    cur_idx = idx;
    cur_seed = seed;
    cur_t = tname;
    const cnt = &reach_table[idx];
    cnt.runs += 1;

    var r = R.init(seed);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const n = if (force_default) 90 + r.range(usize, 0, 300) else drawLen(&r);
    const all_default = force_default or r.chance(25);
    const p: P = if (hasP) (if (!all_default and r.chance(30)) drawOne(P, &r) else drawValue(P, null, &r, if (all_default) 100 else 40)) else {};
    const skip_mode = comptime hasP and @hasField(P, "nan");

    // inputs
    var bars: [5][cap]f64 = undefined;
    genBars(&r, &bars, n + 8);
    var asg: [n_in]u8 = undefined;
    assign(&r, &asg);
    var ins: [n_in][]T = undefined;
    var has_nan = false;
    for (0..n_in) |k| {
        ins[k] = try arena.alloc(T, n + 8);
        for (ins[k], bars[asg[k]][0 .. n + 8]) |*d, s| d.* = @floatCast(s);
        for (ins[k][0..n]) |v| {
            if (std.math.isNan(v)) has_nan = true;
        }
    }
    // `nan = .skip` answers differently in batch and stream by design (see SPEC); so do the batch MAX / MIN / MINMAX
    // (block scan) and their stream (automaton) where a NaN is in the data (SPEC, MAX / MIN / MINMAX).
    const block_scan = comptime std.mem.eql(u8, name, "max") or std.mem.eql(u8, name, "min") or std.mem.eql(u8, name, "minmax");
    const skipcase = (skip_mode and has_nan and p.nan == .skip) or (block_scan and has_nan);
    cur_info_len = if (std.fmt.bufPrint(&cur_info, "n={d} p={any}", .{ n, p })) |s| s.len else |_| 0;

    // lengths: all n, or one slice (input or output) differs
    var lens: [n_in + n_out]usize = @splat(n);
    var mismatch = false;
    if (!force_default and r.chance(25)) {
        const w = r.range(usize, 0, n_in + n_out - 1);
        lens[w] = switch (r.range(u8, 0, 4)) {
            0 => 0,
            1 => n + 1,
            2 => n + 7,
            3 => if (n > 0) n - 1 else n + 2,
            else => n / 2,
        };
        if (lens[w] == n) lens[w] = n + 1;
        mismatch = true;
    }
    const fail_at: usize = if (hasG and !force_default and r.chance(35)) r.range(usize, 0, 6) else std.math.maxInt(usize);

    const lbr = callLb(lb, p, hasP);

    const r0 = try callBatch(T, spec, P, f, arena, gpa, &ins, &lens, p, 0, fail_at, false);
    const r1 = try callBatch(T, spec, P, f, arena, gpa, &ins, &lens, p, 1, fail_at, false);
    if (r0.bytes > alloc_cap or r1.bytes > alloc_cap) return fail("a batch call allocated more than the cap");

    // the same call twice, over differently prefilled outputs
    if (r0.r) |v0| {
        const v1 = r1.r catch return fail("second run failed where the first succeeded");
        if (v0 != v1) return fail("lookback differs between two runs");
        inline for (spec, 0..) |ch, pos| {
            if (comptime isOut(ch)) {
                for (r0.a[pos], r1.a[pos]) |x, y| {
                    if (!sameV(x, y)) return fail("output differs between two runs (a slot was read before it was written)");
                }
            }
        }
    } else |e0| {
        if (r1.r) |_| return fail("first run failed where the second succeeded") else |e1| {
            if (!std.mem.eql(u8, @errorName(e0), @errorName(e1))) return fail("error differs between two runs");
        }
    }

    // an in-place call over a copy of the input: no answer is pinned, but no crash either
    if (r.chance(8)) {
        var ins2: [n_in][]T = undefined;
        for (0..n_in) |k| ins2[k] = try arena.dupe(T, ins[k]);
        const ra = try callBatch(T, spec, P, f, arena, gpa, &ins2, &lens, p, 0, fail_at, true);
        if (ra.bytes > alloc_cap) return fail("an in-place call allocated more than the cap");
        if (ra.r) |_| {} else |e| {
            if (!isBad(e) and e != error.OutOfMemory) return fail("unexpected error from an in-place call");
        }
        fuzz_driver.hit("in_place");
    }

    var batch_lb: ?usize = null;
    if (r0.r) |lbv| {
        if (mismatch) return fail("a length mismatch was accepted");
        const want = lbr catch return fail("lookback rejects parameters the batch call accepted");
        if (want != lbv) return fail("returned lookback differs from Lookback()");
        batch_lb = lbv;
        cnt.ok += 1;
        if (T == f32) cnt.ok32 += 1;
        fuzz_driver.hit("batch_ok");
        inline for (spec, 0..) |ch, pos| {
            if (comptime isOut(ch)) {
                const o = r0.a[pos];
                const E = @typeInfo(@TypeOf(o)).pointer.child;
                for (o) |x| {
                    if (bitsOf(x) == bitsOf(sentinelOf(E, 0))) return fail("an output slot was never written");
                }
                if (comptime ch == 'o') {
                    for (o[0..@min(lbv, o.len)]) |x| {
                        if (!std.math.isNan(x)) return fail("a slot inside the lookback is not NaN");
                    }
                }
            }
        }
    } else |e| {
        if (isBad(e)) {
            cnt.bad += 1;
            fuzz_driver.hit("bad_param");
            if (mismatch) {
                cnt.mismatch += 1;
                fuzz_driver.hit("mismatch");
            } else if (lbr) |_| {
                return fail("batch call says BadParam but Lookback accepts the parameters");
            } else |_| {}
        } else if (e == error.OutOfMemory) {
            if (fail_at == std.math.maxInt(usize)) return fail("OutOfMemory without a failing allocator");
            cnt.oom += 1;
            fuzz_driver.hit("oom");
        } else return fail("unexpected error from the batch call");
    }

    // the stream
    if (comptime @TypeOf(S) != type) {
        const St = S(T);
        const init_ps = @typeInfo(@TypeOf(St.init)).@"fn".param_types;
        const X = @typeInfo(@typeInfo(@TypeOf(St.update)).@"fn".return_type.?).optional.child;
        const sp = if (hasP) p else @as(init_ps[0].?, .{});
        var need: usize = 0;
        var need_err = false;
        const BufT = if (init_ps.len == 2) @typeInfo(init_ps[1].?).pointer.child else f64;
        if (comptime init_ps.len == 2) {
            if (St.bufLen(sp)) |nd| {
                if (nd > stream_buf_cap) return fail("a stream asks for an unbounded buffer");
                need = nd;
            } else |e| {
                if (!isBad(e)) return fail("bufLen: unexpected error");
                need_err = true;
            }
            if (!need_err and need > 0) {
                const sb = try arena.alloc(BufT, need - 1);
                fillAny(BufT, sb, 0);
                if (St.init(sp, sb)) |_| return fail("init accepted a buffer one slot short") else |e| {
                    if (!isBad(e)) return fail("init with a short buffer: not BadParam");
                }
            }
        }
        const buf_len = need + r.range(usize, 0, 3);
        var outs: [2][]?X = undefined;
        var inited = false;
        for (0..2) |pass| {
            const buf = try arena.alloc(BufT, buf_len);
            fillAny(BufT, buf, if (pass == 0) -1.25e-5 else 7.5e9);
            var s_or: St = undefined;
            const init_r = if (comptime init_ps.len == 2) St.init(sp, buf) else if (comptime init_ps.len == 1) St.init(sp) else St.init();
            if (init_r) |sv| {
                if (lbr) |_| {} else |_| return fail("stream init accepts parameters Lookback rejects");
                s_or = sv;
            } else |e| {
                if (!isBad(e)) return fail("stream init: unexpected error");
                if (lbr) |_| return fail("stream init rejects parameters Lookback accepts") else |_| {}
                break;
            }
            outs[pass] = try arena.alloc(?X, n);
            var cloned = false;
            var clone_dst: ?[]BufT = null;
            if (comptime @hasDecl(St, "clone")) {
                const cd = try arena.alloc(BufT, buf_len);
                if (pass == 0 and need > 0) {
                    const short = try arena.alloc(BufT, need - 1);
                    if (s_or.clone(short)) |_| return fail("clone accepted a buffer one slot short") else |e| {
                        if (!isBad(e)) return fail("clone with a short buffer: not BadParam");
                    }
                }
                clone_dst = cd;
            }
            try feed(St, T, n_in, X, BufT, &s_or, &ins, n, outs[pass], clone_dst, &cloned);
            if (cloned) cnt.clone += 1;
            cnt.stream += 1;
            fuzz_driver.hit("stream_pass");
            if (pass == 1) inited = true;
        }
        if (inited) {
            for (outs[0], outs[1]) |a0, a1| {
                if ((a0 == null) != (a1 == null)) return fail("stream answers differ over a differently filled buffer (null)");
                if (a0) |v| if (!sameX(X, v, a1.?)) return fail("stream answers differ over a differently filled buffer");
            }
            // against the batch call
            if (batch_lb) |lbv| {
                if (!skipcase) {
                    for (outs[0], 0..) |u, i| {
                        if ((u == null) != (i < lbv)) return fail("stream null/non-null does not follow the lookback");
                        if (u) |x| {
                            if (comptime @typeInfo(X) == .@"struct") {
                                inline for (@typeInfo(X).@"struct".field_names, 0..) |fname, k| {
                                    if (!eqV(@field(x, fname), r0.a[comptime outPos(spec, k)][i])) {
                                        std.debug.print("  bar {d} field {s}: stream {any} batch {any} lookback {d}\n", .{ i, fname, @field(x, fname), r0.a[comptime outPos(spec, k)][i], lbv });
                                        return fail("stream differs from the batch call");
                                    }
                                }
                            } else {
                                if (!eqV(x, r0.a[comptime outPos(spec, 0)][i])) {
                                    std.debug.print("  bar {d}: stream {any} batch {any} lookback {d}\n", .{ i, x, r0.a[comptime outPos(spec, 0)][i], lbv });
                                    return fail("stream differs from the batch call");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn runIdx(idx: usize, use32: bool, gpa: Allocator, seed: u64, force_default: bool) !void {
    inline for (rows, 0..) |row, i| {
        if (idx == i) {
            if (use32) return runEntry(f32, i, row[0], row[1], row[2], row[3], row[4], gpa, seed, force_default);
            return runEntry(f64, i, row[0], row[1], row[2], row[3], row[4], gpa, seed, force_default);
        }
    }
    inline for (ind.candles.all, 0..) |Pat, j| {
        if (idx == n_rows + j) {
            const O = cc.Op(Pat);
            const nm = "cdl" ++ ind.candles.names[j];
            if (use32) return runEntry(f32, n_rows + j, nm, "iiii3p", O.run, O.lookback, O.Stream, gpa, seed, force_default);
            return runEntry(f64, n_rows + j, nm, "iiii3p", O.run, O.lookback, O.Stream, gpa, seed, force_default);
        }
    }
    unreachable; // idx < n_entries by construction of every caller
}

// ── the harness ─────────────────────────────────────────────────────────────

fn harness(comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    const k = 1 + src.index(4);
    for (0..k) |_| {
        const idx = src.index(n_entries);
        const use32 = src.valueRangeAtMost(u8, 0, 3) == 0;
        const seed = src.value(u64);
        if (use32) fuzz_driver.hit("f32");
        runIdx(idx, use32, gpa, seed, false) catch |e| {
            if (e != error.FuzzFinding) return e;
        };
    }
}

fn reportReach() void {
    var tot: Counts = .{};
    for (reach_table, 0..) |c, i| {
        if (c.runs == 0) continue;
        std.debug.print("RF {s} runs={d} ok={d} ok32={d} bad={d} oom={d} mismatch={d} stream={d} clone={d}\n", .{ entry_names[i], c.runs, c.ok, c.ok32, c.bad, c.oom, c.mismatch, c.stream, c.clone });
        tot.runs += c.runs;
        tot.ok += c.ok;
        tot.bad += c.bad;
        tot.oom += c.oom;
        tot.mismatch += c.mismatch;
        tot.stream += c.stream;
    }
    if (tot.runs != 0) std.debug.print("RF-TOTAL entries={d} runs={d} ok={d} bad={d} oom={d} mismatch={d} stream={d}\n", .{ n_entries, tot.runs, tot.ok, tot.bad, tot.oom, tot.mismatch, tot.stream });
}

test "fuzz driver: INDICATORS_FUZZ" {
    reach_table = @splat(.{});
    findings = 0;
    fuzz_driver.run(harness, .{ .prefix = "INDICATORS_FUZZ", .name = "indicators" }) catch |err| {
        if (err == error.SkipZigTest) return err;
        reportReach();
        return err;
    };
    reportReach();
    if (findings != 0) {
        std.debug.print("indicators fuzz: {d} findings\n", .{findings});
        return error.FuzzFinding;
    }
}

test "fuzz: the table covers the public surface" {
    @setEvalBranchQuota(200_000);
    comptime var lookbacks = 0;
    comptime var streams = 0;
    inline for (@typeInfo(ind).@"struct".decl_names) |d| {
        if (comptime std.mem.endsWith(u8, d, "Lookback")) lookbacks += 1;
        if (comptime std.mem.endsWith(u8, d, "Stream")) streams += 1;
    }
    comptime var table_streams = 0;
    inline for (rows) |row| {
        if (@TypeOf(row[4]) != type) table_streams += 1;
    }
    const lb_count: usize = lookbacks;
    const st_count: usize = streams;
    const ts_count: usize = table_streams;
    try testing.expectEqual(@as(usize, n_rows), lb_count);
    try testing.expectEqual(@as(usize, n_rows - 1), st_count); // MAVP has no stream
    try testing.expectEqual(st_count, ts_count);
    try testing.expectEqual(@as(usize, 237), n_entries);
}

test "fuzz: every function, six forced runs each, and they get everywhere" {
    reach_table = @splat(.{});
    for (0..n_entries) |idx| {
        for (0..6) |s| {
            runIdx(idx, s % 2 == 1, testing.allocator, @as(u64, idx) * 1000 + s, s < 4) catch |err| {
                std.debug.print("function {s}: {t}\n", .{ entry_names[idx], err });
                return err;
            };
        }
    }
    if (findings != 0) return error.FuzzFinding;
    var missing: usize = 0;
    for (reach_table, 0..) |c, i| {
        if (c.ok == 0 or c.ok32 == 0 or (c.stream == 0 and !std.mem.eql(u8, entry_names[i], "mavp"))) {
            std.debug.print("reach: {s} ok={d} ok32={d} stream={d}\n", .{ entry_names[i], c.ok, c.ok32, c.stream });
            missing += 1;
        }
    }
    if (missing != 0) return error.HarnessDoesNotReach;
    fuzz_driver.resetReach();
}

test "fuzz driver: replay one entry (INDICATORS_FUZZ_ENTRY=<name>,<f32|f64>,<seed>)" {
    const txt = std.testing.environ.getPosix("INDICATORS_FUZZ_ENTRY") orelse return error.SkipZigTest;
    var it = std.mem.splitScalar(u8, txt, ',');
    const want = it.next() orelse return error.BadEntry;
    const ty = it.next() orelse return error.BadEntry;
    const seed = try std.fmt.parseInt(u64, it.next() orelse return error.BadEntry, 10);
    findings = 0;
    for (0..n_entries) |idx| {
        // every function, so the name is looked up by running nothing but the match
        var found = false;
        inline for (rows, 0..) |row, i| {
            if (idx == i and std.mem.eql(u8, row[0], want)) found = true;
        }
        inline for (ind.candles.names, 0..) |nm, j| {
            if (idx == n_rows + j and std.mem.eql(u8, "cdl" ++ nm, want)) found = true;
        }
        if (!found) continue;
        try runIdx(idx, std.mem.eql(u8, ty, "f32"), testing.allocator, seed, false);
        std.debug.print("replay clean\n", .{});
        return;
    }
    return error.NoSuchEntry;
}

test "fuzz: 300 random harness runs" {
    findings = 0;
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("indicators seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    if (findings != 0) return error.FuzzFinding;
    fuzz_driver.resetReach();
}

fn fuzzOne(_: void, smith: *testing.Smith) !void {
    // Byte-first: the seed's bytes are the input, see check-fuzz-reach.
    var buf: [4096]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var src: testkit.fuzz.ScriptSource = .init(buf[0..len]);
    try harness(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: the indicator surface never panics" {
    try testing.fuzz({}, fuzzOne, .{});
}
