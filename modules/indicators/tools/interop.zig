// SPDX-License-Identifier: MIT

//! Live differential oracle: `indicators` against TA-Lib C 0.8.3 -- every seed
//! function, batch API, f64 input (`TA_<F>`) and f32 input (`TA_S_<F>`), over
//! seeded random-walk OHLC inputs, a parameter grid (defaults, edges, swapped
//! fast/slow, every supported MA type, out-of-range values), the unstable period
//! at 0, 3 and both AUTO levels (`TA_SetUnstablePeriod`), and lengths 1, 2,
//! period-1, period, period+1, lookback..lookback+2, 300 and 5000.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-indicators` runs it and
//! `zig build check-interop` compiles it. Needs `zig` on PATH (it builds
//! `tools/talib_oracle.c` with `zig cc`) and TA-Lib built as a static archive:
//!   TALIB_A    path of `libta-lib.a`        (default `~/.local/share/zig-libs/oracle-bin/ta-lib-0.8.3/libta-lib.a`)
//!   TALIB_INC  directory with `ta_libc.h`   (default `~/.local/share/zig-libs/oracles/ta-lib-0.8.3/src/ta-lib-0.8.3/include`)
//! A leading `~` is expanded from `$HOME`. The archive is OUR compile of the audited
//! TA-Lib sources with our own command line (recipe: `tools/README.md`), never TA-Lib's
//! build system. No network. Run from the repository root.
//! Exit 0 = every case agrees within the stated per-function bound; 1 = a disagreement
//! (the first few per function are printed in full) or an oracle failure; 2 = archive or
//! headers not found.
//!
//!   zig build interop-indicators -- --emit-vectors modules/indicators/src/testdata/talib_vectors.zig
//!
//! additionally writes the frozen vectors `src/oracle_test.zig` replays in CI (run `zig fmt` on
//! the file afterwards: the repository's format gate checks it).
//!
//! What is compared, per record: the return code (BadParam <-> TA_BAD_PARAM), the
//! lookback against `TA_<F>_Lookback`, `outBegIdx == lookback` and
//! `outNBElement == n - lookback` when anything is produced, the NaN lead of ours,
//! and every value: bitwise equal, else the distance in ULPs of the output type.
//! `ulp_bound` is the allowed distance per function; 0 means bitwise, anything else
//! is explained next to the table.

const std = @import("std");
const ind = @import("indicators");

const work_dir = ".zig-cache/interop-indicators";
const c_source = "modules/indicators/tools/talib_oracle.c";
const default_a = "~/.local/share/zig-libs/oracle-bin/ta-lib-0.8.3/libta-lib.a";
const default_inc = "~/.local/share/zig-libs/oracles/ta-lib-0.8.3/src/ta-lib-0.8.3/include";
const ta_bad_param: i32 = 2;
const vec_n = 40;

/// Same order as the C `F_*` enum.
const Func = enum(u8) {
    sma,
    ema,
    wma,
    ma,
    macd,
    macdext,
    macdfix,
    rsi,
    bbands,
    trange,
    atr,
    natr,
    stoch,
    stochf,
    max,
    min,
    sum,
    // wave I3
    dema,
    tema,
    t3,
    trima,
    kama,
    midpoint,
    midprice,
    sar,
    sarext,
    mavp,
    accbands,
    alma,
    cksp,
    donchian,
    frama,
    hma,
    ichimoku,
    kc,
    mcgd,
    rma,
    supertrend,
    swak_butter,
    swak_gauss,
    vidya,
    vwma,
    zigzag,
    zlema,
    // volume / volatility / price transform / statistic / math operator wave
    ad,
    adosc,
    cmf,
    efi,
    emv,
    kvo,
    marketfi,
    nvi,
    obv,
    pvi,
    pvo,
    pvt,
    rvol,
    vwap,
    adr,
    bbw,
    cvi,
    massi,
    percentb,
    rogerssatchell,
    rvi,
    rvir,
    avgdev,
    avgprice,
    ha,
    medprice,
    typprice,
    wclprice,
    beta,
    correl,
    kurtosis,
    linearreg,
    linearreg_angle,
    linearreg_intercept,
    linearreg_slope,
    median,
    percentile,
    percentrank,
    stddev,
    tsf,
    @"var",
    add,
    cumsum,
    div,
    maxindex,
    minindex,
    minmax,
    minmaxindex,
    mult,
    sub,
    // cycle wave
    ht_dcperiod,
    ht_dcphase,
    ht_phasor,
    ht_sine,
    ht_trendline,
    ht_trendmode,
    mama,
    swak_bp,
    swak_hp,
    swak_2php,
    acos,
    asin,
    atan,
    ceil,
    cos,
    cosh,
    exp,
    floor,
    ln,
    log10,
    sin,
    sinh,
    sqrt,
    tan,
    tanh,
    // momentum wave
    adx,
    adxr,
    dx,
    minus_di,
    plus_di,
    minus_dm,
    plus_dm,
    aroon,
    aroonosc,
    mom,
    roc,
    rocp,
    rocr,
    rocr100,
    bop,
    ibs,
    qstick,
    wad,
    asi,
    si,
    imi,
    ao,
    ac,
    dpo,
    er,
    fosc,
    cti,
    vhf,
    willr,
    fractal,
    cci,
    chop,
    choptr,
    vortex,
    mfi,
    ultosc,
    cmo,
    cmou,
    cg,
    apo,
    ppo,
    trix,
    coppock,
    eri,
    dosc,
    fisher,
    pso,
    smi,
    tsi,
    wavetrend,
    kst,
    kstext,
    kdj,
    stochrsi,
    crsi,
    stc,
    sqzmom,
};
const func_names = [_][]const u8{
    "SMA",                 "EMA",             "WMA",     "MA",          "MACD",        "MACDEXT",     "MACDFIX",     "RSI",        "BBANDS",         "TRANGE",    "ATR",
    "NATR",                "STOCH",           "STOCHF",  "MAX",         "MIN",         "SUM",         "DEMA",        "TEMA",       "T3",             "TRIMA",     "KAMA",
    "MIDPOINT",            "MIDPRICE",        "SAR",     "SAREXT",      "MAVP",        "ACCBANDS",    "ALMA",        "CKSP",       "DONCHIAN",       "FRAMA",     "HMA",
    "ICHIMOKU",            "KC",              "MCGD",    "RMA",         "SUPERTREND",  "SWAK_BUTTER", "SWAK_GAUSS",  "VIDYA",      "VWMA",           "ZIGZAG",    "ZLEMA",
    "AD",                  "ADOSC",           "CMF",     "EFI",         "EMV",         "KVO",         "MARKETFI",    "NVI",        "OBV",            "PVI",       "PVO",
    "PVT",                 "RVOL",            "VWAP",    "ADR",         "BBW",         "CVI",         "MASSI",       "PERCENTB",   "ROGERSSATCHELL", "RVI",       "RVIR",
    "AVGDEV",              "AVGPRICE",        "HA",      "MEDPRICE",    "TYPPRICE",    "WCLPRICE",    "BETA",        "CORREL",     "KURTOSIS",       "LINEARREG", "LINEARREG_ANGLE",
    "LINEARREG_INTERCEPT", "LINEARREG_SLOPE", "MEDIAN",  "PERCENTILE",  "PERCENTRANK", "STDDEV",      "TSF",         "VAR",        "ADD",            "CUMSUM",    "DIV",
    "MAXINDEX",            "MININDEX",        "MINMAX",  "MINMAXINDEX", "MULT",        "SUB",         "HT_DCPERIOD", "HT_DCPHASE", "HT_PHASOR",      "HT_SINE",   "HT_TRENDLINE",
    "HT_TRENDMODE",        "MAMA",            "SWAK_BP", "SWAK_HP",     "SWAK_2PHP",   "ACOS",        "ASIN",        "ATAN",       "CEIL",           "COS",       "COSH",
    "EXP",                 "FLOOR",           "LN",      "LOG10",       "SIN",         "SINH",        "SQRT",        "TAN",        "TANH",           "ADX",       "ADXR",
    "DX",                  "MINUS_DI",        "PLUS_DI", "MINUS_DM",    "PLUS_DM",     "AROON",       "AROONOSC",    "MOM",        "ROC",            "ROCP",      "ROCR",
    "ROCR100",             "BOP",             "IBS",     "QSTICK",      "WAD",         "ASI",         "SI",          "IMI",        "AO",             "AC",        "DPO",
    "ER",                  "FOSC",            "CTI",     "VHF",         "WILLR",       "FRACTAL",     "CCI",         "CHOP",       "CHOPTR",         "VORTEX",    "MFI",
    "ULTOSC",              "CMO",             "CMOU",    "CG",          "APO",         "PPO",         "TRIX",        "COPPOCK",    "ERI",            "DOSC",      "FISHER",
    "PSO",                 "SMI",             "TSI",     "WAVETREND",   "KST",         "KSTEXT",      "KDJ",         "STOCHRSI",   "CRSI",           "STC",       "SQZMOM",
};
const n_func = func_names.len;

/// Allowed distance in ULPs, per function. Everything is expected to be bitwise:
/// both sides do the same operations in the same order and neither contracts
/// `a*b + c` outside the explicit `fma` calls. A nonzero entry must say why.
const ulp_bound = blk: {
    var b: [n_func]u64 = @splat(0);
    // LINEARREG_ANGLE is the one function that calls a libm routine we do not
    // control: `atan` (TA-Lib's, i.e. the C library the archive links, glibc's) against
    // Zig's `std.math.atan` (a port of musl's). Both are within an ULP or so of the exact
    // arctangent but are different roundings; the scaling by 180/pi can stretch the
    // distance to 2 ULP of the result (measured: 14 of 15066 values, max 2). Every other
    // function, `log` of ROGERSSATCHELL and `sqrt` included, agrees bitwise.
    b[@backingInt(Func.linearreg_angle)] = 2;
    // ACOS, ASIN, ATAN, SINH, COSH, TANH: Zig has no builtin for them, `xmath.zig` writes them (double-double
    // inverse trigonometric functions, fdlibm hyperbolics with a double-double exponential from 22 up). Against
    // the C library of the oracle (glibc) 0.01% to 1% of the results differ in the last bit (measured max 1 ULP,
    // 2 for SINH and TANH): the C library is not correctly rounded, ours is except for the hyperbolics.
    for ([_]Func{ .acos, .asin, .atan, .cosh, .sinh, .tanh }) |f| b[@backingInt(f)] = 2;
    // PSO: tanh(expm1). TA-Lib's glibc and our `tanh` round a few results differently (measured on the momentum branch:
    // 16 of 20930 values differ, by at most 2 ULP).
    b[@backingInt(Func.pso)] = 2;
    break :blk b;
};

/// Allowed distance as a fraction of the largest |value| of the same output column of the same record, besides
/// the ULP bound (either one passes). The Hilbert-transform family and MAMA run a recursion that feeds an
/// `atan` of the C library back into itself: where glibc's `atan` rounds differently from ours (about one in
/// 4000 arguments, measured on ATAN alone: 8 of 31883) the two runs differ by a last bit, which the filter
/// carries along, a few ULP of the column maximum at the end (measured max 1e-15). In ULPs of an output that is
/// near zero it reads like thousands, hence the column-relative form.
const scaled_bound = blk: {
    var b: [n_func]f64 = @splat(0.0);
    for ([_]Func{ .ht_dcperiod, .ht_dcphase, .ht_phasor, .ht_sine, .mama }) |f| b[@backingInt(f)] = 1e-13;
    break :blk b;
};
/// The same allowance for every function that takes a moving-average type, when that type is MAMA.
const mama_slot_scaled: f64 = 1e-12;

fn usesMama(cs: Case) bool {
    const m: i32 = 7;
    return switch (cs.func) {
        .ma, .bbands, .bbw, .percentb => cs.ip[1] == m,
        .macdext => cs.ip[1] == m or cs.ip[3] == m or cs.ip[5] == m,
        .stoch => cs.ip[2] == m or cs.ip[4] == m,
        .stochf, .mavp, .pvo => cs.ip[2] == m,
        else => false,
    };
}

/// What the inputs are: close; high+low; high+low+close; close+volume; close+per-bar periods.
const InKind = enum { c, hl, hlc, cv, cp };
fn inKind(f: Func) InKind {
    return switch (f) {
        .trange, .atr, .natr, .stoch, .stochf, .accbands, .cksp, .kc, .supertrend => .hlc,
        .midprice, .sar, .sarext, .donchian, .frama, .ichimoku, .zigzag => .hl,
        .vwma => .cv,
        .mavp => .cp,
        else => .c,
    };
}
/// The input series of a function, in the order of its TA-Lib prototype:
/// o(pen) h(igh) l(ow) c(lose) v(olume); x = the generated second series of
/// VWMA (volume) and MAVP (periods). Two-series functions read close and open.
fn seriesOf(f: Func) []const u8 {
    return switch (f) {
        .ad, .adosc, .cmf, .kvo, .vwap => "hlcv",
        .emv, .marketfi => "hlv",
        .efi, .nvi, .obv, .pvi, .pvt => "cv",
        .pvo, .rvol => "v",
        .adr, .cvi, .massi, .rvir, .medprice => "hl",
        .rogerssatchell, .avgprice, .ha => "ohlc",
        .typprice, .wclprice => "hlc",
        .beta, .correl, .add, .sub, .mult, .div => "co",
        .adx, .adxr, .dx, .minus_di, .plus_di => "hlc",
        .minus_dm, .plus_dm, .aroon, .aroonosc, .ao, .ac, .fractal => "hl",
        .bop, .asi, .si => "ohlc",
        .qstick, .imi => "oc",
        .ibs, .wad, .willr, .cci, .chop, .choptr, .vortex, .ultosc => "hlc",
        .mfi => "hlcv",
        .eri, .pso, .smi, .wavetrend => "hlc",
        .fisher => "hl",
        .kdj, .sqzmom => "hlc",
        else => switch (inKind(f)) {
            .c => "c",
            .hl => "hl",
            .hlc => "hlc",
            .cv, .cp => "cx",
        },
    };
}
fn nIn(f: Func) usize {
    return seriesOf(f).len;
}
fn isIndex(f: Func) bool {
    return f == .maxindex or f == .minindex or f == .minmaxindex;
}
fn nOut(f: Func) usize {
    return switch (f) {
        .macd, .macdext, .macdfix, .bbands, .accbands, .donchian, .kc, .zigzag => 3,
        .ichimoku => 4,
        .stoch, .stochf, .cksp, .supertrend, .kvo, .minmax, .minmaxindex, .ht_phasor, .ht_sine, .mama => 2,
        .aroon, .vortex, .fractal, .eri, .fisher, .smi, .wavetrend, .kst, .kstext, .stochrsi, .sqzmom => 2,
        .kdj => 3,
        .ha => 4,
        else => 1,
    };
}

const Case = struct {
    func: Func,
    is32: bool = false,
    ukind: u8 = 0, // 0 bars, 1 auto4, 2 auto8
    ubars: u32 = 0,
    n: u32,
    ip: [6]i32 = @splat(0),
    dp: [8]f64 = @splat(0),
    xp: [6]i32 = @splat(0), // ints 6..11 of the prototype (KST, KSTEXT)
    kind: u8 = 0, // input kind: 0 walk, 1 walk with flat runs, 2 walk scaled by 1e-9, 3 signed-zero ties
    seed: u64 = 0,
    bad: bool = false,
    emit: bool = false,

    fn unstable(self: Case) ind.Unstable {
        return switch (self.ukind) {
            0 => .{ .bars = self.ubars },
            1 => .auto4,
            else => .auto8,
        };
    }
};

// ── inputs ──────────────────────────────────────────────────────────────────

/// Seeded OHLC series: close walks, high/low bracket it. Kind 1 holds the price
/// for random runs (flat windows, where RSI/STOCH/BBANDS have special cases);
/// kind 2 is scaled to ~1e-7 (relative thresholds must not depend on the unit).
fn genInput(seed: u64, kind: u8, h: []f64, l: []f64, c: []f64) void {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    if (kind == 3) {
        // Signed-zero ties: blocks of 8 bars drawing from {+0, -0, 3}, {+0, -0, -3} and {+0, -0}, so a
        // window's minimum, maximum or both are a tie between 0.0 and -0.0 (MAX / MIN / MINMAX).
        for (h, l, c, 0..) |*hh, *ll, *cc, i| {
            const pick = r.uintLessThan(u8, 3);
            cc.* = switch ((i / 8) % 3) {
                0 => switch (pick) {
                    0 => 0.0,
                    1 => -0.0,
                    else => 3.0,
                },
                1 => switch (pick) {
                    0 => 0.0,
                    1 => -0.0,
                    else => -3.0,
                },
                else => if (pick == 0) 0.0 else -0.0,
            };
            hh.* = cc.*;
            ll.* = cc.*;
        }
        return;
    }
    if (kind == 4 or kind == 5) {
        // Math transforms: kind 4 stays inside [-1.2, 1.2] (ACOS / ASIN domain, small arguments) behind a head of
        // edge values; kind 5 spans many decades of both signs (overflow and underflow of EXP / COSH / SINH, big
        // trigonometric arguments).
        const head = [_]f64{ 0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 1.0000000000000002, -1.0000000000000002, std.math.inf(f64), -std.math.inf(f64), std.math.nan(f64), 710.0, -745.0, 1e22, 1e-310 };
        for (h, l, c, 0..) |*hh, *ll, *cc, i| {
            if (i < head.len and kind == 4) {
                cc.* = head[i];
            } else if (kind == 4) {
                cc.* = (r.float(f64) - 0.5) * 2.4;
            } else {
                const mag = std.math.pow(f64, 10.0, (r.float(f64) - 0.3) * 8.0);
                cc.* = if (r.boolean()) mag else -mag;
            }
            hh.* = cc.*;
            ll.* = cc.*;
        }
        return;
    }
    var v: f64 = 100.0;
    var hold: usize = 0;
    for (h, l, c) |*hh, *ll, *cc| {
        if (kind == 1) {
            if (hold > 0) {
                hold -= 1;
            } else {
                v += (r.float(f64) - 0.5) * 2.0;
                if (r.boolean()) hold = r.uintLessThan(usize, 20);
            }
        } else {
            v += (r.float(f64) - 0.5) * 2.0;
        }
        const scale: f64 = if (kind == 2) 1e-9 else 1.0;
        const flat = kind == 1 and hold > 0;
        cc.* = v * scale;
        hh.* = if (flat) cc.* else (v + r.float(f64) * 1.5) * scale;
        ll.* = if (flat) cc.* else (v - r.float(f64) * 1.5) * scale;
    }
}

/// The second series of VWMA (volume, with zero stretches) and MAVP (per-bar
/// periods, -1..15 with an occasional NaN, so both clamps are exercised).
fn genAux(f: Func, seed: u64, kind: u8, a: []f64) void {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5bd1_e995);
    const r = prng.random();
    var zero_run: usize = 0;
    for (a) |*x| {
        if (inKind(f) == .cp) {
            x.* = if (kind == 1 and r.uintLessThan(u8, 40) == 0) std.math.nan(f64) else -1.0 + r.float(f64) * 16.0;
        } else if (zero_run > 0) {
            zero_run -= 1;
            x.* = 0.0;
        } else {
            x.* = 100.0 + r.float(f64) * 900.0;
            if (r.uintLessThan(u8, 25) == 0) x.* = 0.0;
            if (kind == 1 and r.uintLessThan(u8, 6) == 0) zero_run = r.uintLessThan(usize, 12);
        }
    }
}

fn needsAux(f: Func) bool {
    return switch (inKind(f)) {
        .cv, .cp => true,
        else => false,
    };
}

const Series = struct { o: []f64, h: []f64, l: []f64, c: []f64, v: []f64, x: []f64 };

/// OHLCV + the aux series of one case. High, low and close come from `genInput`
/// unchanged; the open (inside the bar) and the volume (0..2000, with runs of
/// zeros, and zero on every flat bar of kind 1) come from a generator of their
/// own, and the aux series (VWMA volume / MAVP periods) from `genAux`, so the
/// records of the earlier functions do not move.
fn genSeries(arena: std.mem.Allocator, f: Func, seed: u64, kind: u8, n: usize) !Series {
    const s: Series = .{
        .o = try arena.alloc(f64, n),
        .h = try arena.alloc(f64, n),
        .l = try arena.alloc(f64, n),
        .c = try arena.alloc(f64, n),
        .v = try arena.alloc(f64, n),
        .x = try arena.alloc(f64, n),
    };
    genInput(seed, kind, s.h, s.l, s.c);
    if (needsAux(f)) genAux(f, seed, kind, s.x) else @memset(s.x, 0);
    var prng = std.Random.DefaultPrng.init(seed ^ 0x6f76_6f6c_756d);
    const r = prng.random();
    var zero_run: usize = 0;
    for (s.o, s.h, s.l, s.v) |*oo, hh, ll, *vv| {
        oo.* = ll + (hh - ll) * r.float(f64);
        if (zero_run > 0) {
            zero_run -= 1;
            vv.* = 0.0;
        } else {
            vv.* = @floor(r.float(f64) * 2000.0);
            if (r.uintLessThan(usize, 25) == 0) zero_run = r.uintLessThan(usize, 12);
        }
        if (kind == 1 and hh == ll) vv.* = 0.0;
    }
    return s;
}

fn seriesSlice(s: anytype, letter: u8) @TypeOf(s.o) {
    return switch (letter) {
        'o' => s.o,
        'h' => s.h,
        'l' => s.l,
        'c' => s.c,
        'x' => s.x,
        else => s.v,
    };
}

// ── ours ────────────────────────────────────────────────────────────────────

const OursError = ind.Error || std.mem.Allocator.Error;

fn mt(x: i32) ind.MaType {
    return @fromBackingInt(@intCast(@as(u8, @intCast(x))));
}
fn us(x: i32) usize {
    return @intCast(x);
}

fn Ser(comptime T: type) type {
    return struct { o: []const T, h: []const T, l: []const T, c: []const T, v: []const T, x: []const T };
}

fn runOurs(comptime T: type, gpa: std.mem.Allocator, cs: Case, s: Ser(T), o: *[4][]T, io: *[2][]usize) OursError!usize {
    const h = s.h;
    const l = s.l;
    const c = s.c;
    const au = s.x;
    const ip = cs.ip;
    const dp = cs.dp;
    const un = cs.unstable();
    return switch (cs.func) {
        .sma => ind.sma(T, c, o[0], .{ .period = us(ip[0]) }),
        .ema => ind.ema(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .wma => ind.wma(T, c, o[0], .{ .period = us(ip[0]) }),
        .ma => ind.ma(T, c, o[0], .{ .period = us(ip[0]), .kind = mt(ip[1]), .unstable = un }),
        .macd => ind.macd(T, c, o[0], o[1], o[2], .{ .fast = us(ip[0]), .slow = us(ip[1]), .signal = us(ip[2]), .unstable = un }),
        .macdext => ind.macdext(T, gpa, c, o[0], o[1], o[2], .{ .fast = us(ip[0]), .fast_ma = mt(ip[1]), .slow = us(ip[2]), .slow_ma = mt(ip[3]), .signal = us(ip[4]), .signal_ma = mt(ip[5]), .unstable = un }),
        .macdfix => ind.macdfix(T, c, o[0], o[1], o[2], .{ .signal = us(ip[0]), .unstable = un }),
        .rsi => ind.rsi(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .bbands => ind.bbands(T, c, o[0], o[1], o[2], .{ .period = us(ip[0]), .dev_up = dp[0], .dev_dn = dp[1], .ma = mt(ip[1]), .unstable = un }),
        .trange => ind.trange(T, h, l, c, o[0]),
        .atr => ind.atr(T, h, l, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .natr => ind.natr(T, h, l, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .stoch => ind.stoch(T, gpa, h, l, c, o[0], o[1], .{ .fastk = us(ip[0]), .slowk = us(ip[1]), .slowk_ma = mt(ip[2]), .slowd = us(ip[3]), .slowd_ma = mt(ip[4]), .unstable = un }),
        .stochf => ind.stochf(T, gpa, h, l, c, o[0], o[1], .{ .fastk = us(ip[0]), .fastd = us(ip[1]), .fastd_ma = mt(ip[2]), .unstable = un }),
        .max => ind.max(T, c, o[0], .{ .period = us(ip[0]) }),
        .min => ind.min(T, c, o[0], .{ .period = us(ip[0]) }),
        .sum => ind.sum(T, c, o[0], .{ .period = us(ip[0]) }),
        .dema => ind.dema(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .tema => ind.tema(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .t3 => ind.t3(T, c, o[0], .{ .period = us(ip[0]), .vfactor = dp[0], .unstable = un }),
        .trima => ind.trima(T, c, o[0], .{ .period = us(ip[0]) }),
        .kama => ind.kama(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .midpoint => ind.midpoint(T, c, o[0], .{ .period = us(ip[0]) }),
        .midprice => ind.midprice(T, h, l, o[0], .{ .period = us(ip[0]) }),
        .sar => ind.sar(T, h, l, o[0], .{ .acceleration = dp[0], .maximum = dp[1] }),
        .sarext => ind.sarext(T, h, l, o[0], .{ .start_value = dp[0], .offset_on_reverse = dp[1], .af_init_long = dp[2], .af_long = dp[3], .af_max_long = dp[4], .af_init_short = dp[5], .af_short = dp[6], .af_max_short = dp[7] }),
        .mavp => ind.mavp(T, c, au, o[0], .{ .min_period = us(ip[0]), .max_period = us(ip[1]), .kind = mt(ip[2]), .unstable = un }),
        .accbands => ind.accbands(T, h, l, c, o[0], o[1], o[2], .{ .period = us(ip[0]) }),
        .alma => ind.alma(T, gpa, c, o[0], .{ .period = us(ip[0]), .sigma = dp[0], .offset = dp[1] }),
        .cksp => ind.cksp(T, gpa, h, l, c, o[0], o[1], .{ .period = us(ip[0]), .stop_period = us(ip[1]), .multiplier = dp[0], .unstable = un }),
        .donchian => ind.donchian(T, h, l, o[0], o[1], o[2], .{ .period = us(ip[0]) }),
        .frama => ind.frama(T, h, l, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .hma => ind.hma(T, c, o[0], .{ .period = us(ip[0]) }),
        .ichimoku => ind.ichimoku(T, h, l, o[0], o[1], o[2], o[3], .{ .tenkan = us(ip[0]), .kijun = us(ip[1]), .senkou_b = us(ip[2]) }),
        .kc => ind.kc(T, h, l, c, o[0], o[1], o[2], .{ .period = us(ip[0]), .atr_period = us(ip[1]), .nb_dev = dp[0], .unstable = un }),
        .mcgd => ind.mcgd(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .rma => ind.rma(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .supertrend => blk: {
            const tr = try gpa.alloc(i8, c.len);
            const lb = try ind.supertrend(T, h, l, c, o[0], tr, .{ .period = us(ip[0]), .multiplier = dp[0], .unstable = un });
            for (o[1][0..c.len], tr, 0..) |*d, t, i| d.* = if (i < lb) std.math.nan(T) else @floatFromInt(t);
            break :blk lb;
        },
        .swak_butter => ind.swakButter(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .swak_gauss => ind.swakGauss(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .vidya => ind.vidya(T, c, o[0], .{ .period = us(ip[0]), .cmo_period = us(ip[1]), .unstable = un }),
        .vwma => ind.vwma(T, c, au, o[0], .{ .period = us(ip[0]) }),
        .zigzag => blk: {
            const tr = try gpa.alloc(i8, c.len);
            const pv = try gpa.alloc(i32, c.len);
            const lb = try ind.zigzag(T, h, l, o[0], tr, pv, .{ .sensitivity = dp[0], .min_trend_length = us(ip[0]) });
            for (o[1][0..c.len], o[2][0..c.len], tr, pv, 0..) |*d, *e, t, v, i| {
                d.* = if (i < lb) std.math.nan(T) else @floatFromInt(t);
                e.* = if (i < lb) std.math.nan(T) else @floatFromInt(v);
            }
            break :blk lb;
        },
        .zlema => ind.zlema(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        // volume
        .ad => ind.ad(T, h, l, c, s.v, o[0]),
        .adosc => ind.adosc(T, h, l, c, s.v, o[0], .{ .fast = us(ip[0]), .slow = us(ip[1]), .unstable = un }),
        .cmf => ind.cmf(T, h, l, c, s.v, o[0], .{ .period = us(ip[0]) }),
        .efi => ind.efi(T, c, s.v, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .emv => ind.emv(T, h, l, s.v, o[0], .{ .period = us(ip[0]), .divisor = dp[0] }),
        .kvo => ind.kvo(T, h, l, c, s.v, o[0], o[1], .{ .fast = us(ip[0]), .slow = us(ip[1]), .signal = us(ip[2]), .unstable = un }),
        .marketfi => ind.marketfi(T, h, l, s.v, o[0]),
        .nvi => ind.nvi(T, c, s.v, o[0]),
        .obv => ind.obv(T, c, s.v, o[0]),
        .pvi => ind.pvi(T, c, s.v, o[0]),
        .pvo => ind.pvo(T, s.v, o[0], .{ .fast = us(ip[0]), .slow = us(ip[1]), .ma = mt(ip[2]), .unstable = un }),
        .pvt => ind.pvt(T, c, s.v, o[0]),
        .rvol => ind.rvol(T, s.v, o[0], .{ .period = us(ip[0]) }),
        .vwap => ind.vwap(T, h, l, c, s.v, o[0]),
        // volatility
        .adr => ind.adr(T, h, l, o[0], .{ .period = us(ip[0]) }),
        .bbw => ind.bbw(T, c, o[0], .{ .period = us(ip[0]), .dev_up = dp[0], .dev_dn = dp[1], .ma = mt(ip[1]), .unstable = un }),
        .cvi => ind.cvi(T, h, l, o[0], .{ .period = us(ip[0]), .roc = us(ip[1]), .unstable = un }),
        .massi => ind.massi(T, h, l, o[0], .{ .fast = us(ip[0]), .slow = us(ip[1]), .unstable = un }),
        .percentb => ind.percentb(T, c, o[0], .{ .period = us(ip[0]), .dev_up = dp[0], .dev_dn = dp[1], .ma = mt(ip[1]), .unstable = un }),
        .rogerssatchell => ind.rogerssatchell(T, s.o, h, l, c, o[0], .{ .period = us(ip[0]), .annualization = dp[0] }),
        .rvi => ind.rvi(T, c, o[0], .{ .period = us(ip[0]), .stddev = us(ip[1]), .unstable = un }),
        .rvir => ind.rvir(T, h, l, o[0], .{ .period = us(ip[0]), .stddev = us(ip[1]), .unstable = un }),
        // price transform
        .avgdev => ind.avgdev(T, c, o[0], .{ .period = us(ip[0]) }),
        .avgprice => ind.avgprice(T, s.o, h, l, c, o[0]),
        .ha => ind.ha(T, s.o, h, l, c, o[0], o[1], o[2], o[3], .{ .unstable = un }),
        .medprice => ind.medprice(T, h, l, o[0]),
        .typprice => ind.typprice(T, h, l, c, o[0]),
        .wclprice => ind.wclprice(T, h, l, c, o[0]),
        // statistic
        .beta => ind.beta(T, c, s.o, o[0], .{ .period = us(ip[0]) }),
        .correl => ind.correl(T, c, s.o, o[0], .{ .period = us(ip[0]) }),
        .kurtosis => ind.kurtosis(T, c, o[0], .{ .period = us(ip[0]) }),
        .linearreg => ind.linearreg(T, c, o[0], .{ .period = us(ip[0]) }),
        .linearreg_angle => ind.linearregAngle(T, c, o[0], .{ .period = us(ip[0]) }),
        .linearreg_intercept => ind.linearregIntercept(T, c, o[0], .{ .period = us(ip[0]) }),
        .linearreg_slope => ind.linearregSlope(T, c, o[0], .{ .period = us(ip[0]) }),
        .median => ind.median(T, gpa, c, o[0], .{ .period = us(ip[0]) }),
        .percentile => ind.percentile(T, gpa, c, o[0], .{ .period = us(ip[0]), .percentile = dp[0] }),
        .percentrank => ind.percentrank(T, c, o[0], .{ .period = us(ip[0]) }),
        .stddev => ind.stddev(T, c, o[0], .{ .period = us(ip[0]), .nbdev = dp[0] }),
        .tsf => ind.tsf(T, c, o[0], .{ .period = us(ip[0]) }),
        .@"var" => ind.variance(T, c, o[0], .{ .period = us(ip[0]), .nbdev = dp[0] }),
        // math operators
        .add => ind.add(T, c, s.o, o[0]),
        .sub => ind.sub(T, c, s.o, o[0]),
        .mult => ind.mult(T, c, s.o, o[0]),
        .div => ind.div(T, c, s.o, o[0]),
        .cumsum => ind.cumsum(T, c, o[0]),
        .maxindex => ind.maxindex(T, c, io[0], .{ .period = us(ip[0]) }),
        .minindex => ind.minindex(T, c, io[0], .{ .period = us(ip[0]) }),
        .minmax => ind.minmax(T, c, o[0], o[1], .{ .period = us(ip[0]) }),
        .minmaxindex => ind.minmaxindex(T, c, io[0], io[1], .{ .period = us(ip[0]) }),
        // cycle
        .ht_dcperiod => ind.htDcperiod(T, c, o[0], .{ .unstable = un }),
        .ht_dcphase => ind.htDcphase(T, c, o[0], .{ .unstable = un }),
        .ht_phasor => ind.htPhasor(T, c, o[0], o[1], .{ .unstable = un }),
        .ht_sine => ind.htSine(T, c, o[0], o[1], .{ .unstable = un }),
        .ht_trendline => ind.htTrendline(T, c, o[0], .{ .unstable = un }),
        .ht_trendmode => blk: {
            const tr = try gpa.alloc(i8, c.len);
            const lb = try ind.htTrendmode(T, c, tr, .{ .unstable = un });
            for (o[0][0..c.len], tr, 0..) |*d, t, i| d.* = if (i < lb) std.math.nan(T) else @floatFromInt(t);
            break :blk lb;
        },
        .mama => ind.mama(T, c, o[0], o[1], .{ .fast_limit = dp[0], .slow_limit = dp[1], .unstable = un }),
        .swak_bp => ind.swakBp(T, c, o[0], .{ .period = us(ip[0]), .delta = dp[0], .unstable = un }),
        .swak_hp => ind.swakHp(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .swak_2php => ind.swak2php(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .acos => ind.acos(T, c, o[0]),
        .asin => ind.asin(T, c, o[0]),
        .atan => ind.atan(T, c, o[0]),
        .ceil => ind.ceil(T, c, o[0]),
        .cos => ind.cos(T, c, o[0]),
        .cosh => ind.cosh(T, c, o[0]),
        .exp => ind.exp(T, c, o[0]),
        .floor => ind.floor(T, c, o[0]),
        .ln => ind.ln(T, c, o[0]),
        .log10 => ind.log10(T, c, o[0]),
        .sin => ind.sin(T, c, o[0]),
        .sinh => ind.sinh(T, c, o[0]),
        .sqrt => ind.sqrt(T, c, o[0]),
        .tan => ind.tan(T, c, o[0]),
        .tanh => ind.tanh(T, c, o[0]),
        // momentum
        .adx => ind.adx(T, h, l, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .adxr => ind.adxr(T, gpa, h, l, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .dx => ind.dx(T, h, l, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .minus_di => ind.minusDi(T, h, l, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .plus_di => ind.plusDi(T, h, l, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .minus_dm => ind.minusDm(T, h, l, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .plus_dm => ind.plusDm(T, h, l, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .aroon => ind.aroon(T, h, l, o[0], o[1], .{ .period = us(ip[0]) }),
        .aroonosc => ind.aroonosc(T, h, l, o[0], .{ .period = us(ip[0]) }),
        .mom => ind.mom(T, c, o[0], .{ .period = us(ip[0]) }),
        .roc => ind.roc(T, c, o[0], .{ .period = us(ip[0]) }),
        .rocp => ind.rocp(T, c, o[0], .{ .period = us(ip[0]) }),
        .rocr => ind.rocr(T, c, o[0], .{ .period = us(ip[0]) }),
        .rocr100 => ind.rocr100(T, c, o[0], .{ .period = us(ip[0]) }),
        .bop => ind.bop(T, s.o, h, l, c, o[0]),
        .ibs => ind.ibs(T, h, l, c, o[0]),
        .qstick => ind.qstick(T, s.o, c, o[0], .{ .period = us(ip[0]) }),
        .wad => ind.wad(T, h, l, c, o[0]),
        .asi => ind.asi(T, s.o, h, l, c, o[0], .{ .limit_move = dp[0] }),
        .si => ind.si(T, s.o, h, l, c, o[0], .{ .limit_move = dp[0] }),
        .imi => ind.imi(T, s.o, c, o[0], .{ .period = us(ip[0]) }),
        .ao => ind.ao(T, h, l, o[0], .{ .fast = us(ip[0]), .slow = us(ip[1]) }),
        .ac => ind.ac(T, gpa, h, l, o[0], .{ .fast = us(ip[0]), .slow = us(ip[1]), .signal = us(ip[2]) }),
        .dpo => ind.dpo(T, c, o[0], .{ .period = us(ip[0]) }),
        .er => ind.er(T, c, o[0], .{ .period = us(ip[0]) }),
        .fosc => ind.fosc(T, c, o[0], .{ .period = us(ip[0]) }),
        .cti => ind.cti(T, c, o[0], .{ .period = us(ip[0]) }),
        .vhf => ind.vhf(T, c, o[0], .{ .period = us(ip[0]) }),
        .willr => ind.willr(T, h, l, c, o[0], .{ .period = us(ip[0]) }),
        .fractal => blk: {
            const a = try gpa.alloc(i8, h.len);
            defer gpa.free(a);
            const b = try gpa.alloc(i8, h.len);
            defer gpa.free(b);
            const lb = try ind.fractal(T, gpa, h, l, a, b, .{ .left = us(ip[0]), .right = us(ip[1]) });
            for (0..h.len) |i| {
                o[0][i] = if (i < lb) std.math.nan(T) else @floatFromInt(a[i]);
                o[1][i] = if (i < lb) std.math.nan(T) else @floatFromInt(b[i]);
            }
            break :blk lb;
        },
        .cci => ind.cci(T, h, l, c, o[0], .{ .period = us(ip[0]) }),
        .chop => ind.chop(T, h, l, c, o[0], .{ .period = us(ip[0]) }),
        .choptr => ind.choptr(T, h, l, c, o[0], .{ .period = us(ip[0]) }),
        .vortex => ind.vortex(T, h, l, c, o[0], o[1], .{ .period = us(ip[0]) }),
        .mfi => ind.mfi(T, h, l, c, s.v, o[0], .{ .period = us(ip[0]) }),
        .ultosc => ind.ultosc(T, h, l, c, o[0], .{ .period1 = us(ip[0]), .period2 = us(ip[1]), .period3 = us(ip[2]) }),
        .cmo => ind.cmo(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .cmou => ind.cmou(T, c, o[0], .{ .period = us(ip[0]) }),
        .cg => ind.cg(T, c, o[0], .{ .period = us(ip[0]) }),
        .apo => ind.apo(T, c, o[0], .{ .fast = us(ip[0]), .slow = us(ip[1]), .kind = mt(ip[2]), .unstable = un }),
        .ppo => ind.ppo(T, c, o[0], .{ .fast = us(ip[0]), .slow = us(ip[1]), .kind = mt(ip[2]), .unstable = un }),
        .trix => ind.trix(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .coppock => ind.coppock(T, c, o[0], .{ .wma = us(ip[0]), .roc1 = us(ip[1]), .roc2 = us(ip[2]) }),
        .eri => ind.eri(T, h, l, c, o[0], o[1], .{ .period = us(ip[0]), .unstable = un }),
        .dosc => ind.dosc(T, gpa, c, o[0], .{ .period = us(ip[0]), .first = us(ip[1]), .second = us(ip[2]), .signal = us(ip[3]), .unstable = un }),
        .fisher => ind.fisher(T, h, l, o[0], o[1], .{ .period = us(ip[0]), .unstable = un }),
        .pso => ind.pso(T, h, l, c, o[0], .{ .fastk = us(ip[0]), .ema = us(ip[1]), .unstable = un }),
        .smi => ind.smi(T, h, l, c, o[0], o[1], .{ .period = us(ip[0]), .fast = us(ip[1]), .slow = us(ip[2]), .signal = us(ip[3]), .unstable = un }),
        .tsi => ind.tsi(T, c, o[0], .{ .first = us(ip[0]), .second = us(ip[1]), .unstable = un }),
        .kst => ind.kst(T, gpa, c, o[0], o[1], .{ .roc1 = us(ip[0]), .roc2 = us(ip[1]), .roc3 = us(ip[2]), .roc4 = us(ip[3]), .sma1 = us(ip[4]), .sma2 = us(ip[5]), .sma3 = us(cs.xp[0]), .sma4 = us(cs.xp[1]), .signal = us(cs.xp[2]) }),
        .kstext => ind.kstext(T, gpa, c, o[0], o[1], .{ .roc1 = us(ip[0]), .roc2 = us(ip[1]), .roc3 = us(ip[2]), .roc4 = us(ip[3]), .ma1 = us(ip[4]), .ma2 = us(ip[5]), .ma3 = us(cs.xp[0]), .ma4 = us(cs.xp[1]), .signal = us(cs.xp[2]), .roc_ma = mt(cs.xp[3]), .signal_ma = mt(cs.xp[4]) }),
        .kdj => ind.kdj(T, gpa, h, l, c, o[0], o[1], o[2], .{ .fastk = us(ip[0]), .slowk = us(ip[1]), .slowk_ma = mt(ip[2]), .slowd = us(ip[3]), .slowd_ma = mt(ip[4]), .unstable = un }),
        .stochrsi => ind.stochrsi(T, gpa, c, o[0], o[1], .{ .period = us(ip[0]), .fastk = us(ip[1]), .fastd = us(ip[2]), .fastd_ma = mt(ip[3]), .unstable = un }),
        .crsi => ind.crsi(T, gpa, c, o[0], .{ .period = us(ip[0]), .streak = us(ip[1]), .rank = us(ip[2]), .unstable = un }),
        .stc => ind.stc(T, gpa, c, o[0], .{ .fast = us(ip[0]), .slow = us(ip[1]), .cycle = us(ip[2]), .unstable = un }),
        .sqzmom => blk: {
            const q = try gpa.alloc(i8, h.len);
            defer gpa.free(q);
            const lb = try ind.sqzmom(T, gpa, h, l, c, o[0], q, .{ .bb_period = us(ip[0]), .kc_period = us(ip[1]), .nb_dev = dp[0], .factor_wide = dp[1], .factor_normal = dp[2], .factor_narrow = dp[3] });
            for (0..h.len) |i| o[1][i] = if (i < lb) std.math.nan(T) else @floatFromInt(q[i]);
            break :blk lb;
        },
        .wavetrend => ind.wavetrend(T, gpa, h, l, c, o[0], o[1], .{ .channel = us(ip[0]), .average = us(ip[1]), .signal = us(ip[2]), .unstable = un }),
    };
}

// ── the case grid ───────────────────────────────────────────────────────────

const P = struct { ip: [6]i32 = @splat(0), dp: [8]f64 = @splat(0), xp: [6]i32 = @splat(0) };
fn d2(a: f64, b: f64) [8]f64 {
    return .{ a, b, 0, 0, 0, 0, 0, 0 };
}
fn p1(a: i32) P {
    return .{ .ip = .{ a, 0, 0, 0, 0, 0 } };
}
/// Up to 12 ints: the first six into `ip`, the rest into `xp`.
fn pn(a: anytype) P {
    var r = P{};
    inline for (a, 0..) |x, i| {
        if (i < 6) r.ip[i] = x else r.xp[i - 6] = x;
    }
    return r;
}

fn periods(comptime ps: []const i32) [ps.len]P {
    var r: [ps.len]P = undefined;
    for (ps, &r) |a, *o| o.* = p1(a);
    return r;
}

/// MA types in the grid: every type.
const grid_ma = [_]i32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15 };

fn paramsOf(f: Func, gpa: std.mem.Allocator) ![]const P {
    var l: std.ArrayList(P) = .empty;
    switch (f) {
        .sma, .wma => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 14, 50, 100, 0, 100001 })),
        .ema => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 12, 26, 50, 100, 0, 100001 })),
        .max, .min, .sum => try l.appendSlice(gpa, &periods(&.{ 30, 2, 3, 5, 14, 100, 1, 0, 100001 })),
        .rsi => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 30, 1, 0, 100001 })),
        .atr, .natr => try l.appendSlice(gpa, &periods(&.{ 14, 1, 2, 3, 5, 30, 0, 100001 })),
        .trange => try l.append(gpa, .{}),
        .ma => {
            for ([_]i32{ 30, 1, 2, 5, 14 }) |per| for (grid_ma) |t| try l.append(gpa, pn(.{ per, t, 0, 0, 0, 0 }));
            try l.append(gpa, pn(.{ 0, 0, 0, 0, 0, 0 }));
            try l.append(gpa, pn(.{ 100001, 1, 0, 0, 0, 0 }));
        },
        .macd => for ([_][3]i32{ .{ 12, 26, 9 }, .{ 2, 3, 2 }, .{ 5, 8, 1 }, .{ 26, 12, 9 }, .{ 3, 3, 3 }, .{ 10, 20, 5 }, .{ 2, 2, 1 }, .{ 1, 26, 9 }, .{ 12, 100001, 9 }, .{ 12, 26, 0 } }) |t|
            try l.append(gpa, pn(.{ t[0], t[1], t[2], 0, 0, 0 })),
        .macdfix => try l.appendSlice(gpa, &periods(&.{ 9, 1, 2, 3, 5, 20, 0, 100001 })),
        .macdext => {
            const per = [_][3]i32{ .{ 12, 26, 9 }, .{ 5, 8, 3 }, .{ 9, 4, 1 }, .{ 3, 3, 2 } };
            const ty = [_][3]i32{ .{ 0, 0, 0 }, .{ 1, 1, 1 }, .{ 2, 2, 2 }, .{ 2, 1, 0 }, .{ 0, 1, 2 }, .{ 10, 0, 1 }, .{ 3, 4, 5 }, .{ 6, 8, 9 }, .{ 12, 13, 14 }, .{ 15, 3, 6 }, .{ 4, 4, 4 }, .{ 8, 8, 8 }, .{ 7, 7, 7 }, .{ 0, 7, 1 }, .{ 7, 0, 7 } };
            for (per) |a| for (ty) |t| try l.append(gpa, pn(.{ a[0], t[0], a[1], t[1], a[2], t[2] }));
            try l.append(gpa, pn(.{ 1, 0, 26, 0, 9, 0 }));
            try l.append(gpa, pn(.{ 12, 0, 26, 0, 100001, 0 }));
        },
        .bbands => {
            for ([_]i32{ 20, 5, 2, 10, 3, 34, 50 }) |per| for (grid_ma) |t| try l.append(gpa, .{ .ip = .{ per, t, 0, 0, 0, 0 }, .dp = d2(2, 2) });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = d2(1.5, 2.5) });
            try l.append(gpa, .{ .ip = .{ 9, 1, 0, 0, 0, 0 }, .dp = d2(2.5, 0.5) });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = d2(-1, -1) });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = d2(0, 0) });
            try l.append(gpa, .{ .ip = .{ 1, 0, 0, 0, 0, 0 }, .dp = d2(2, 2) });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = d2(4e37, 2) });
        },
        .stoch => {
            for ([_][5]i32{ .{ 5, 3, 0, 3, 0 }, .{ 1, 1, 0, 1, 0 }, .{ 14, 3, 1, 3, 2 }, .{ 3, 2, 0, 5, 2 }, .{ 10, 5, 2, 1, 0 }, .{ 9, 1, 1, 4, 1 }, .{ 5, 3, 10, 3, 0 }, .{ 0, 3, 0, 3, 0 }, .{ 5, 0, 0, 3, 0 }, .{ 5, 3, 0, 100001, 0 }, .{ 8, 4, 3, 3, 4 }, .{ 8, 4, 5, 5, 6 }, .{ 8, 4, 8, 3, 9 }, .{ 8, 4, 12, 3, 13 }, .{ 8, 4, 14, 3, 15 }, .{ 8, 4, 7, 3, 7 }, .{ 14, 6, 6, 4, 8 } }) |t|
                try l.append(gpa, pn(.{ t[0], t[1], t[2], t[3], t[4], 0 }));
        },
        .stochf => {
            for ([_][3]i32{ .{ 5, 3, 0 }, .{ 1, 1, 0 }, .{ 9, 4, 1 }, .{ 14, 3, 2 }, .{ 3, 5, 2 }, .{ 4, 1, 1 }, .{ 5, 3, 10 }, .{ 0, 3, 0 }, .{ 5, 0, 0 }, .{ 6, 4, 3 }, .{ 6, 4, 4 }, .{ 6, 5, 5 }, .{ 6, 4, 6 }, .{ 6, 4, 8 }, .{ 6, 5, 9 }, .{ 6, 4, 12 }, .{ 6, 4, 13 }, .{ 6, 4, 7 }, .{ 10, 6, 14 }, .{ 6, 4, 15 } }) |t|
                try l.append(gpa, pn(.{ t[0], t[1], t[2], 0, 0, 0 }));
        },
        .dema, .tema, .rma => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 12, 26, 50, 100, 0, 100001 })),
        .zlema => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 14, 50, 0, 100001 })),
        // ── volume / volatility / price transform / statistic / math operator waves ──
        .ad, .marketfi, .nvi, .obv, .pvi, .pvt, .vwap, .avgprice, .ha, .medprice, .typprice, .wclprice, .add, .sub, .mult, .div, .cumsum => try l.append(gpa, .{}),
        .adosc => for ([_][2]i32{ .{ 3, 10 }, .{ 2, 2 }, .{ 5, 3 }, .{ 12, 26 }, .{ 2, 60 }, .{ 40, 2 }, .{ 1, 10 }, .{ 3, 100001 } }) |t|
            try l.append(gpa, pn(.{ t[0], t[1], 0, 0, 0, 0 })),
        .cmf => try l.appendSlice(gpa, &periods(&.{ 20, 2, 3, 5, 50, 1, 0, 100001 })),
        .efi => try l.appendSlice(gpa, &periods(&.{ 13, 1, 2, 3, 5, 30, 0, 100001 })),
        .emv => for ([_]struct { p: i32, d: f64 }{ .{ .p = 14, .d = 10000 }, .{ .p = 1, .d = 1 }, .{ .p = 2, .d = 10000 }, .{ .p = 5, .d = 1 }, .{ .p = 10, .d = 1e6 }, .{ .p = 14, .d = 0.5 }, .{ .p = 14, .d = 4e37 }, .{ .p = 0, .d = 10000 } }) |t|
            try l.append(gpa, .{ .ip = .{ t.p, 0, 0, 0, 0, 0 }, .dp = d2(t.d, 0) }),
        .kvo => for ([_][3]i32{ .{ 34, 55, 13 }, .{ 2, 2, 2 }, .{ 5, 9, 3 }, .{ 10, 5, 2 }, .{ 3, 3, 3 }, .{ 20, 12, 7 }, .{ 1, 55, 13 }, .{ 34, 55, 1 } }) |t|
            try l.append(gpa, pn(.{ t[0], t[1], t[2], 0, 0, 0 })),
        .pvo => {
            for ([_][3]i32{ .{ 12, 26, 1 }, .{ 2, 3, 0 }, .{ 5, 3, 2 }, .{ 10, 20, 10 }, .{ 26, 12, 1 }, .{ 4, 9, 0 }, .{ 3, 3, 1 }, .{ 2, 5, 2 }, .{ 6, 12, 0 }, .{ 1, 26, 1 } }) |t|
                try l.append(gpa, pn(.{ t[0], t[1], t[2], 0, 0, 0 }));
            // every MaType in the smoothing slot
            for ([_][2]i32{ .{ 12, 26 }, .{ 3, 5 } }) |fs| for (grid_ma) |t| try l.append(gpa, pn(.{ fs[0], fs[1], t, 0, 0, 0 }));
        },
        .rvol => try l.appendSlice(gpa, &periods(&.{ 20, 1, 2, 3, 5, 10, 0, 100001 })),
        // cycle wave
        .ht_dcperiod, .ht_dcphase, .ht_phasor, .ht_sine, .ht_trendline, .ht_trendmode => try l.append(gpa, .{}),
        .mama => for ([_][2]f64{ .{ 0.5, 0.05 }, .{ 0.25, 0.04 }, .{ 0.99, 0.01 }, .{ 0.01, 0.01 }, .{ 0.3, 0.6 }, .{ 0.7, 0.99 }, .{ 0.009, 0.05 }, .{ 0.5, 0.995 }, .{ 0.5, std.math.nan(f64) } }) |t|
            try l.append(gpa, .{ .dp = d2(t[0], t[1]) }),
        .swak_bp => for ([_][2]f64{ .{ 20, 0.1 }, .{ 5, 0.05 }, .{ 7, 0.5 }, .{ 2000, 0.3 }, .{ 50, 0.2 }, .{ 12, 0.4 }, .{ 4, 0.1 }, .{ 2001, 0.1 }, .{ 20, 0.04 }, .{ 20, 0.51 }, .{ 20, std.math.nan(f64) } }) |t|
            try l.append(gpa, .{ .ip = .{ @intFromFloat(t[0]), 0, 0, 0, 0, 0 }, .dp = d2(t[1], 0) }),
        .swak_hp => try l.appendSlice(gpa, &periods(&.{ 20, 5, 6, 7, 10, 50, 100, 1000, 4, 0, 100001 })),
        .swak_2php => try l.appendSlice(gpa, &periods(&.{ 20, 2, 3, 5, 10, 50, 100, 1, 0, 10001 })),
        .acos, .asin, .atan, .ceil, .cos, .cosh, .exp, .floor, .ln, .log10, .sin, .sinh, .sqrt, .tan, .tanh => try l.append(gpa, .{}),
        // momentum wave
        .adx, .adxr, .dx => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 10, 30, 1, 0, 100001 })),
        .minus_di, .plus_di, .minus_dm, .plus_dm => try l.appendSlice(gpa, &periods(&.{ 14, 1, 2, 3, 5, 10, 30, 0, 100001 })),
        .aroon, .aroonosc => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 25, 1, 0, 100001 })),
        .mom, .roc, .rocp, .rocr, .rocr100 => try l.appendSlice(gpa, &periods(&.{ 10, 1, 2, 3, 5, 30, 0, 100001 })),
        .qstick => try l.appendSlice(gpa, &periods(&.{ 10, 1, 2, 3, 5, 30, 0, 100001 })),
        .imi => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 20, 0, 1, 100001 })),
        .dpo => try l.appendSlice(gpa, &periods(&.{ 20, 2, 3, 4, 5, 10, 30, 0, 1, 100001 })),
        .er => try l.appendSlice(gpa, &periods(&.{ 10, 2, 3, 5, 20, 0, 1, 100001 })),
        .fosc => try l.appendSlice(gpa, &periods(&.{ 5, 2, 3, 10, 40, 1, 0, 100001 })),
        .cti => try l.appendSlice(gpa, &periods(&.{ 20, 2, 3, 5, 40, 1, 0, 100001 })),
        .vhf => try l.appendSlice(gpa, &periods(&.{ 28, 2, 3, 5, 0, 1, 100001 })),
        .willr, .cci, .chop, .choptr => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 30, 1, 0, 100001 })),
        .vortex => try l.appendSlice(gpa, &periods(&.{ 14, 1, 2, 3, 5, 30, 0, 100001 })),
        .mfi => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 30, 1, 0, 100001 })),
        .cmo, .cmou => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 30, 1, 0, 100001 })),
        .bop, .ibs, .wad => try l.append(gpa, .{}),
        .asi, .si => for ([_]f64{ 3, 0.5, 1e-8, 100, 7.25, 0, -1, 1e-9 }) |d| try l.append(gpa, .{ .dp = d2(d, 0) }),
        .ao => for ([_][2]i32{ .{ 5, 34 }, .{ 2, 3 }, .{ 34, 5 }, .{ 10, 10 }, .{ 2, 100 }, .{ 1, 34 }, .{ 5, 0 }, .{ 5, 100001 } }) |t| try l.append(gpa, pn(.{ t[0], t[1] })),
        .ac => for ([_][3]i32{ .{ 5, 34, 5 }, .{ 2, 3, 2 }, .{ 10, 20, 5 }, .{ 34, 5, 3 }, .{ 3, 3, 2 }, .{ 5, 34, 1 }, .{ 5, 34, 100001 } }) |t| try l.append(gpa, pn(.{ t[0], t[1], t[2] })),
        .ultosc => for ([_][3]i32{ .{ 7, 14, 28 }, .{ 1, 1, 1 }, .{ 3, 5, 10 }, .{ 10, 5, 3 }, .{ 5, 5, 5 }, .{ 1, 2, 3 }, .{ 14, 14, 28 }, .{ 0, 14, 28 }, .{ 7, 100001, 28 } }) |t| try l.append(gpa, pn(.{ t[0], t[1], t[2] })),
        .cg => try l.appendSlice(gpa, &periods(&.{ 10, 2, 3, 5, 20, 40, 1, 0, 100001 })),
        .apo, .ppo => {
            for ([_][2]i32{ .{ 12, 26 }, .{ 2, 3 }, .{ 5, 14 }, .{ 26, 12 }, .{ 3, 3 }, .{ 10, 50 } }) |t| for (grid_ma) |k| try l.append(gpa, pn(.{ t[0], t[1], k }));
            try l.append(gpa, pn(.{ 1, 26, 1 }));
            try l.append(gpa, pn(.{ 12, 100001, 0 }));
        },
        .trix => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 14, 0, 100001 })),
        .coppock => for ([_][3]i32{ .{ 10, 11, 14 }, .{ 1, 2, 3 }, .{ 3, 5, 2 }, .{ 5, 1, 1 }, .{ 2, 14, 11 }, .{ 0, 11, 14 }, .{ 10, 0, 14 } }) |t| try l.append(gpa, pn(.{ t[0], t[1], t[2] })),
        .eri => try l.appendSlice(gpa, &periods(&.{ 13, 1, 2, 3, 5, 30, 0, 100001 })),
        .dosc => for ([_][4]i32{ .{ 14, 5, 3, 9 }, .{ 2, 2, 2, 2 }, .{ 3, 4, 5, 6 }, .{ 10, 3, 2, 12 }, .{ 14, 1, 3, 9 }, .{ 14, 5, 3, 1 } }) |t| try l.append(gpa, pn(.{ t[0], t[1], t[2], t[3] })),
        .fisher => try l.appendSlice(gpa, &periods(&.{ 10, 2, 3, 5, 20, 1, 0, 100001 })),
        .pso => for ([_][2]i32{ .{ 8, 5 }, .{ 1, 1 }, .{ 2, 2 }, .{ 3, 8 }, .{ 20, 3 }, .{ 5, 1 }, .{ 0, 5 }, .{ 8, 0 } }) |t| try l.append(gpa, pn(.{ t[0], t[1] })),
        .smi => for ([_][4]i32{ .{ 13, 2, 25, 9 }, .{ 2, 2, 2, 2 }, .{ 5, 3, 7, 4 }, .{ 10, 4, 3, 2 }, .{ 20, 2, 10, 5 }, .{ 1, 2, 25, 9 }, .{ 13, 1, 25, 9 } }) |t| try l.append(gpa, pn(.{ t[0], t[1], t[2], t[3] })),
        .tsi => for ([_][2]i32{ .{ 25, 13 }, .{ 2, 2 }, .{ 3, 5 }, .{ 10, 3 }, .{ 1, 13 }, .{ 25, 1 } }) |t| try l.append(gpa, pn(.{ t[0], t[1] })),
        .wavetrend => for ([_][3]i32{ .{ 10, 21, 4 }, .{ 2, 1, 1 }, .{ 3, 2, 2 }, .{ 5, 8, 3 }, .{ 20, 5, 1 }, .{ 1, 21, 4 }, .{ 10, 0, 4 }, .{ 10, 21, 0 } }) |t| try l.append(gpa, pn(.{ t[0], t[1], t[2] })),
        .kst => for ([_][9]i32{ .{ 10, 15, 20, 30, 10, 10, 10, 15, 9 }, .{ 1, 2, 3, 4, 1, 2, 3, 1, 1 }, .{ 2, 3, 4, 5, 2, 2, 3, 3, 2 }, .{ 5, 10, 15, 20, 5, 5, 5, 5, 3 }, .{ 30, 20, 15, 10, 15, 10, 10, 10, 9 }, .{ 0, 15, 20, 30, 10, 10, 10, 15, 9 }, .{ 10, 15, 20, 30, 10, 10, 10, 15, 0 } }) |t| try l.append(gpa, pn(t)),
        .kstext => {
            for ([_][2]i32{ .{ 0, 0 }, .{ 1, 1 }, .{ 2, 2 }, .{ 1, 0 }, .{ 0, 2 }, .{ 2, 1 }, .{ 10, 0 } }) |ty| for ([_][9]i32{ .{ 10, 15, 20, 30, 10, 10, 10, 15, 9 }, .{ 2, 3, 4, 5, 2, 2, 3, 3, 2 }, .{ 1, 2, 3, 4, 1, 2, 3, 1, 1 } }) |t|
                try l.append(gpa, pn(t ++ ty));
            try l.append(gpa, pn([_]i32{ 0, 15, 20, 30, 10, 10, 10, 15, 9, 0, 0 }));
            // every MaType in both slots (the first period set), alone and paired with a different type
            for (grid_ma) |t| {
                try l.append(gpa, pn([_]i32{ 10, 15, 20, 30, 10, 10, 10, 15, 9, t, t }));
                try l.append(gpa, pn([_]i32{ 2, 3, 4, 5, 2, 2, 3, 3, 2, t, 1 }));
                try l.append(gpa, pn([_]i32{ 2, 3, 4, 5, 2, 2, 3, 3, 2, 0, t }));
            }
        },
        .kdj => {
            for ([_][5]i32{ .{ 9, 3, 0, 3, 0 }, .{ 5, 2, 1, 2, 2 }, .{ 3, 1, 2, 1, 0 }, .{ 14, 3, 10, 3, 0 }, .{ 1, 1, 0, 1, 0 }, .{ 9, 3, 1, 3, 1 }, .{ 0, 3, 0, 3, 0 } }) |t| try l.append(gpa, pn(t));
            // every MaType in both slots (TA-Lib's default is RMA)
            for (grid_ma) |t| {
                try l.append(gpa, pn(.{ 9, 3, t, 3, t }));
                try l.append(gpa, pn(.{ 5, 2, 0, 3, t }));
                try l.append(gpa, pn(.{ 5, 3, t, 2, 1 }));
            }
        },
        .stochrsi => {
            for ([_][4]i32{ .{ 14, 5, 3, 0 }, .{ 2, 1, 1, 0 }, .{ 5, 3, 2, 1 }, .{ 10, 4, 3, 2 }, .{ 3, 5, 2, 10 }, .{ 1, 5, 3, 0 }, .{ 14, 0, 3, 0 }, .{ 14, 5, 0, 0 } }) |t| try l.append(gpa, pn(t));
            for (grid_ma) |t| {
                try l.append(gpa, pn(.{ 14, 5, 3, t }));
                try l.append(gpa, pn(.{ 5, 3, 2, t }));
            }
        },
        .crsi => for ([_][3]i32{ .{ 3, 2, 100 }, .{ 2, 2, 2 }, .{ 5, 3, 10 }, .{ 14, 14, 20 }, .{ 2, 5, 3 }, .{ 2, 2, 10001 }, .{ 1, 2, 100 }, .{ 3, 1, 100 } }) |t| try l.append(gpa, pn(t)),
        .stc => for ([_][3]i32{ .{ 23, 50, 10 }, .{ 2, 3, 2 }, .{ 5, 3, 2 }, .{ 10, 20, 5 }, .{ 12, 26, 4 }, .{ 1, 50, 10 }, .{ 23, 50, 1 } }) |t| try l.append(gpa, pn(t)),
        .sqzmom => for ([_]P{
            .{ .ip = .{ 20, 20, 0, 0, 0, 0 }, .dp = .{ 2, 2, 1.5, 1, 0, 0, 0, 0 } },
            .{ .ip = .{ 5, 5, 0, 0, 0, 0 }, .dp = .{ 2, 2, 1.5, 1, 0, 0, 0, 0 } },
            .{ .ip = .{ 2, 2, 0, 0, 0, 0 }, .dp = .{ 2, 2, 1.5, 1, 0, 0, 0, 0 } },
            .{ .ip = .{ 10, 4, 0, 0, 0, 0 }, .dp = .{ 1.5, 2.5, 1.5, 0.5, 0, 0, 0, 0 } },
            .{ .ip = .{ 20, 10, 0, 0, 0, 0 }, .dp = .{ 2, 3, 2, 1, 0, 0, 0, 0 } },
            .{ .ip = .{ 4, 10, 0, 0, 0, 0 }, .dp = .{ 0, 0, 0, 0, 0, 0, 0, 0 } },
            .{ .ip = .{ 20, 20, 0, 0, 0, 0 }, .dp = .{ 2, 1, 1.5, 1, 0, 0, 0, 0 } },
            .{ .ip = .{ 20, 20, 0, 0, 0, 0 }, .dp = .{ -1, 2, 1.5, 1, 0, 0, 0, 0 } },
            .{ .ip = .{ 1, 20, 0, 0, 0, 0 }, .dp = .{ 2, 2, 1.5, 1, 0, 0, 0, 0 } },
        }) |pp| try l.append(gpa, pp),
        .fractal => for ([_][2]i32{ .{ 2, 2 }, .{ 1, 1 }, .{ 3, 2 }, .{ 2, 5 }, .{ 1, 3 }, .{ 0, 2 }, .{ 2, 0 } }) |t| try l.append(gpa, pn(.{ t[0], t[1] })),
        .adr => try l.appendSlice(gpa, &periods(&.{ 14, 1, 2, 3, 5, 30, 0, 100001 })),
        .bbw, .percentb => {
            for ([_]i32{ 20, 5, 2, 10, 3, 34, 50 }) |per| for (grid_ma) |t| try l.append(gpa, .{ .ip = .{ per, t, 0, 0, 0, 0 }, .dp = d2(2, 2) });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = d2(1.5, 2.5) });
            try l.append(gpa, .{ .ip = .{ 9, 1, 0, 0, 0, 0 }, .dp = d2(2.5, 0.5) });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = d2(-1, -1) });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = d2(0, 0) });
            try l.append(gpa, .{ .ip = .{ 1, 0, 0, 0, 0, 0 }, .dp = d2(2, 2) });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = d2(4e37, 2) });
        },
        .cvi => for ([_][2]i32{ .{ 10, 10 }, .{ 2, 1 }, .{ 3, 5 }, .{ 20, 3 }, .{ 5, 1 }, .{ 10, 50 }, .{ 1, 10 }, .{ 10, 0 } }) |t|
            try l.append(gpa, pn(.{ t[0], t[1], 0, 0, 0, 0 })),
        .massi => for ([_][2]i32{ .{ 9, 25 }, .{ 2, 2 }, .{ 3, 10 }, .{ 5, 2 }, .{ 20, 40 }, .{ 2, 50 }, .{ 1, 25 }, .{ 9, 1 } }) |t|
            try l.append(gpa, pn(.{ t[0], t[1], 0, 0, 0, 0 })),
        .rogerssatchell => for ([_]struct { p: i32, a: f64 }{ .{ .p = 10, .a = 252 }, .{ .p = 1, .a = 252 }, .{ .p = 2, .a = 1 }, .{ .p = 5, .a = 0 }, .{ .p = 20, .a = 365 }, .{ .p = 10, .a = -1 }, .{ .p = 0, .a = 252 }, .{ .p = 10, .a = 4e37 } }) |t|
            try l.append(gpa, .{ .ip = .{ t.p, 0, 0, 0, 0, 0 }, .dp = d2(t.a, 0) }),
        .rvi, .rvir => for ([_][2]i32{ .{ 14, 10 }, .{ 1, 2 }, .{ 2, 2 }, .{ 3, 5 }, .{ 5, 3 }, .{ 10, 10 }, .{ 1, 10 }, .{ 14, 1 }, .{ 0, 10 } }) |t|
            try l.append(gpa, pn(.{ t[0], t[1], 0, 0, 0, 0 })),
        .avgdev => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 30, 50, 1, 0, 100001 })),
        .beta => try l.appendSlice(gpa, &periods(&.{ 5, 1, 2, 3, 10, 30, 0, 100001 })),
        .correl => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 10, 0, 100001 })),
        .kurtosis => try l.appendSlice(gpa, &periods(&.{ 30, 4, 5, 6, 10, 100, 3, 10001 })),
        .linearreg, .linearreg_angle, .linearreg_intercept, .linearreg_slope, .tsf => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 30, 100, 1, 100001 })),
        .median => try l.appendSlice(gpa, &periods(&.{ 30, 2, 3, 4, 5, 10, 127, 128, 200, 1, 10001 })),
        .percentile => for ([_]struct { p: i32, q: f64 }{ .{ .p = 100, .q = 50 }, .{ .p = 2, .q = 50 }, .{ .p = 5, .q = 0 }, .{ .p = 5, .q = 100 }, .{ .p = 10, .q = 25 }, .{ .p = 10, .q = 75 }, .{ .p = 20, .q = 99.9 }, .{ .p = 30, .q = 0.001 }, .{ .p = 129, .q = 90 }, .{ .p = 1, .q = 50 }, .{ .p = 10, .q = 101 }, .{ .p = 10, .q = -1 } }) |t|
            try l.append(gpa, .{ .ip = .{ t.p, 0, 0, 0, 0, 0 }, .dp = d2(t.q, 0) }),
        .percentrank => try l.appendSlice(gpa, &periods(&.{ 100, 2, 3, 5, 20, 1, 10001 })),
        .stddev, .@"var" => for ([_]struct { p: i32, d: f64 }{ .{ .p = 5, .d = 1 }, .{ .p = 2, .d = 1 }, .{ .p = 3, .d = 2 }, .{ .p = 10, .d = 0.5 }, .{ .p = 30, .d = 1 }, .{ .p = 1, .d = 1 }, .{ .p = 5, .d = 4e37 }, .{ .p = 0, .d = 1 } }) |t|
            try l.append(gpa, .{ .ip = .{ t.p, 0, 0, 0, 0, 0 }, .dp = d2(t.d, 0) }),
        .maxindex, .minindex, .minmax, .minmaxindex => try l.appendSlice(gpa, &periods(&.{ 30, 2, 3, 5, 14, 100, 1, 0, 100001 })),
        .trima => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 4, 5, 14, 50, 100, 0, 100001 })),
        .kama => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 10, 50, 0, 100001 })),
        .midpoint, .midprice, .donchian, .accbands => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 20, 30, 100, 1, 0, 100001 })),
        .mcgd => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 30, 100, 1, 0, 100001 })),
        .hma => try l.appendSlice(gpa, &periods(&.{ 20, 1, 2, 3, 4, 5, 9, 16, 25, 36, 50, 100, 0, 100001 })),
        .vwma => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 14, 50, 0, 100001 })),
        .frama => try l.appendSlice(gpa, &periods(&.{ 16, 2, 4, 10, 20, 6, 3, 0, 100001 })),
        .swak_butter, .swak_gauss => try l.appendSlice(gpa, &periods(&.{ 20, 2, 3, 5, 10, 50, 100, 1, 0, 10001 })),
        .t3 => for ([_][2]f64{ .{ 5, 0.7 }, .{ 1, 0.7 }, .{ 2, 0.7 }, .{ 3, 0 }, .{ 4, 1 }, .{ 10, 0.5 }, .{ 30, 0.7 }, .{ 5, 1.1 }, .{ 5, -0.1 }, .{ 0, 0.7 }, .{ 100001, 0.7 } }) |t|
            try l.append(gpa, .{ .ip = .{ @intFromFloat(t[0]), 0, 0, 0, 0, 0 }, .dp = d2(t[1], 0) }),
        .sar => for ([_][2]f64{ .{ 0.02, 0.2 }, .{ 0.01, 0.1 }, .{ 0.3, 0.2 }, .{ 0, 0 }, .{ 0.5, 0.5 }, .{ -1, 0.2 }, .{ 0.02, -1 } }) |t|
            try l.append(gpa, .{ .dp = d2(t[0], t[1]) }),
        .sarext => for ([_][8]f64{
            .{ 0, 0, 0.02, 0.02, 0.2, 0.02, 0.02, 0.2 },
            .{ 100, 0, 0.02, 0.02, 0.2, 0.02, 0.02, 0.2 },
            .{ -100, 0.01, 0.02, 0.02, 0.2, 0.02, 0.02, 0.2 },
            .{ 0, 0.02, 0.03, 0.04, 0.3, 0.05, 0.06, 0.1 },
            .{ 0, 0, 0.5, 0.4, 0.2, 0.6, 0.5, 0.3 },
            .{ 95, 0.005, 0.01, 0.01, 0.1, 0.01, 0.01, 0.1 },
            .{ 0, 0, 0, 0, 0, 0, 0, 0 },
            .{ 0, -1, 0.02, 0.02, 0.2, 0.02, 0.02, 0.2 },
            .{ 4e37, 0, 0.02, 0.02, 0.2, 0.02, 0.02, 0.2 },
            .{ 0, 0, -0.1, 0.02, 0.2, 0.02, 0.02, 0.2 },
        }) |t|
            try l.append(gpa, .{ .dp = t }),
        .mavp => {
            for ([_]i32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15 }) |t| try l.append(gpa, pn(.{ 2, 30, t, 0, 0, 0 }));
            for ([_][3]i32{ .{ 2, 10, 0 }, .{ 5, 5, 1 }, .{ 1, 10, 0 }, .{ 3, 12, 4 }, .{ 2, 14, 6 }, .{ 2, 10, 8 }, .{ 2, 12, 9 }, .{ 1, 1, 0 }, .{ 5, 2, 0 }, .{ 0, 10, 0 }, .{ 2, 10001, 0 } }) |t|
                try l.append(gpa, pn(.{ t[0], t[1], t[2], 0, 0, 0 }));
        },
        .alma => for ([_][3]f64{ .{ 9, 6, 0.85 }, .{ 1, 6, 0.85 }, .{ 2, 6, 0.85 }, .{ 5, 3, 0.5 }, .{ 30, 6, 0.85 }, .{ 10, 0.01, 0 }, .{ 10, 2, 1 }, .{ 50, 6, 0.85 }, .{ 9, 0.001, 0.5 }, .{ 9, 6, 1.5 }, .{ 0, 6, 0.85 }, .{ 100, 6, 0.85 } }) |t|
            try l.append(gpa, .{ .ip = .{ @intFromFloat(t[0]), 0, 0, 0, 0, 0 }, .dp = d2(t[1], t[2]) }),
        .cksp => for ([_][3]f64{ .{ 10, 9, 1 }, .{ 2, 1, 0 }, .{ 3, 2, 2 }, .{ 5, 7, 1.5 }, .{ 10, 1, 1 }, .{ 14, 5, 3 }, .{ 1, 9, 1 }, .{ 10, 0, 1 }, .{ 10, 9, -1 } }) |t|
            try l.append(gpa, .{ .ip = .{ @intFromFloat(t[0]), @intFromFloat(t[1]), 0, 0, 0, 0 }, .dp = d2(t[2], 0) }),
        .ichimoku => for ([_][3]i32{ .{ 3, 5, 8 }, .{ 2, 2, 2 }, .{ 5, 3, 8 }, .{ 9, 26, 52 }, .{ 9, 26, 4 }, .{ 1, 26, 52 }, .{ 9, 1, 52 }, .{ 9, 26, 1 } }) |t|
            try l.append(gpa, pn(.{ t[0], t[1], t[2], 0, 0, 0 })),
        .kc => for ([_][3]f64{ .{ 20, 10, 2 }, .{ 2, 1, 1 }, .{ 3, 12, 1.5 }, .{ 14, 14, 2 }, .{ 5, 3, -1 }, .{ 10, 20, 0.5 }, .{ 1, 10, 2 }, .{ 20, 0, 2 } }) |t|
            try l.append(gpa, .{ .ip = .{ @intFromFloat(t[0]), @intFromFloat(t[1]), 0, 0, 0, 0 }, .dp = d2(t[2], 0) }),
        .supertrend => for ([_][2]f64{ .{ 10, 3 }, .{ 2, 1 }, .{ 3, 0 }, .{ 5, 2.5 }, .{ 14, 3 }, .{ 1, 3 }, .{ 10, -1 } }) |t|
            try l.append(gpa, .{ .ip = .{ @intFromFloat(t[0]), 0, 0, 0, 0, 0 }, .dp = d2(t[1], 0) }),
        .vidya => for ([_][2]i32{ .{ 12, 9 }, .{ 1, 9 }, .{ 2, 2 }, .{ 5, 4 }, .{ 10, 9 }, .{ 30, 20 }, .{ 12, 1 }, .{ 0, 9 }, .{ 12, 100001 } }) |t|
            try l.append(gpa, pn(.{ t[0], t[1], 0, 0, 0, 0 })),
        .zigzag => for ([_][2]f64{ .{ 5, 1 }, .{ 1, 1 }, .{ 0.5, 3 }, .{ 10, 2 }, .{ 20, 5 }, .{ 0, 1 }, .{ 100, 1 }, .{ -1, 1 }, .{ 101, 1 }, .{ 5, 0 } }) |t|
            try l.append(gpa, .{ .ip = .{ @intFromFloat(t[1]), 0, 0, 0, 0, 0 }, .dp = d2(t[0], 0) }),
    }
    return l.items;
}

/// Functions on which the unstable period does anything.
fn unstableMatters(f: Func) bool {
    return switch (f) {
        .sma, .wma, .trange, .max, .min, .sum => false,
        .trima, .midpoint, .midprice, .sar, .sarext, .accbands, .alma, .donchian, .hma, .ichimoku, .vwma, .zigzag => false,
        .ad, .cmf, .emv, .marketfi, .nvi, .obv, .pvi, .pvt, .rvol, .vwap, .adr, .rogerssatchell => false,
        .avgdev, .avgprice, .medprice, .typprice, .wclprice, .beta, .correl, .kurtosis => false,
        .linearreg, .linearreg_angle, .linearreg_intercept, .linearreg_slope, .median, .percentile, .percentrank => false,
        .stddev, .tsf, .@"var", .add, .sub, .mult, .div, .cumsum, .maxindex, .minindex, .minmax, .minmaxindex => false,
        .acos, .asin, .atan, .ceil, .cos, .cosh, .exp, .floor, .ln, .log10, .sin, .sinh, .sqrt, .tan, .tanh => false,
        .cg, .coppock, .kst, .kstext, .sqzmom, .aroon, .aroonosc, .mom, .roc, .rocp, .rocr, .rocr100, .bop, .ibs, .qstick, .wad, .asi, .si, .imi, .ao, .ac, .dpo, .er, .fosc, .cti, .vhf, .willr, .fractal, .cci, .chop, .choptr, .vortex, .mfi, .ultosc, .cmou => false,
        else => true,
    };
}

fn probeLookback(gpa: std.mem.Allocator, cs_in: Case) ?usize {
    var cs = cs_in;
    cs.n = 1;
    var hh: [1]f64 = .{100};
    var o0: [1]f64 = undefined;
    var o1: [1]f64 = undefined;
    var o2: [1]f64 = undefined;
    var o3: [1]f64 = undefined;
    var ix0: [1]usize = undefined;
    var ix1: [1]usize = undefined;
    var o: [4][]f64 = .{ &o0, &o1, &o2, &o3 };
    var io: [2][]usize = .{ &ix0, &ix1 };
    const sr = Ser(f64){ .o = &hh, .h = &hh, .l = &hh, .c = &hh, .v = &hh, .x = &hh };
    return runOurs(f64, gpa, cs, sr, &o, &io) catch null;
}

/// How many parameter sets of a function get frozen vectors (the seed and
/// overlap functions keep 3; the later waves 2, to keep the frozen file near 1.5 MB).
fn emitSets(f: Func) usize {
    if (isMathTx(f)) return 1;
    return if (@backingInt(f) < @backingInt(Func.ad)) 3 else 2;
}

/// How many parameter sets of a function get frozen vectors at a non-default unstable period (the file stays near 1.5 MB).
fn emitUnstableSets(f: Func) usize {
    _ = f;
    return 1;
}

/// Frozen-vector length: the Hilbert family and MAMA only start answering at bar 32 / 63, so their vectors are longer.
fn vecLen(f: Func) u32 {
    return if (isHt(f)) 100 else vec_n;
}

/// The Hilbert-transform family and MAMA: a long warm-up (lookback 32 / 63 plus an unstable period of up to 556).
fn isHt(f: Func) bool {
    return switch (f) {
        .ht_dcperiod, .ht_dcphase, .ht_phasor, .ht_sine, .ht_trendline, .ht_trendmode, .mama => true,
        else => false,
    };
}

/// The element-wise math transforms; they also get inputs inside their domains (kinds 4, 5).
fn isMathTx(f: Func) bool {
    return switch (f) {
        .acos, .asin, .atan, .ceil, .cos, .cosh, .exp, .floor, .ln, .log10, .sin, .sinh, .sqrt, .tan, .tanh => true,
        else => false,
    };
}

/// Functions whose output is an input value (or its index) picked out of a window: a tie between
/// equal values, 0.0 and -0.0 included, is decided by the scan order, so the sign / index can differ.
fn hasZeroTies(f: Func) bool {
    return f == .max or f == .min or f == .minmax or f == .maxindex or f == .minindex or f == .minmaxindex;
}

/// Input kinds of the long case besides the plain walk: flat runs and tiny values, and for the math transforms
/// values inside their domains (kind 4) and a wide magnitude range (kind 5).
fn kindsOf(f: Func) []const u8 {
    return if (isMathTx(f)) &.{ 1, 2, 4, 5 } else &.{ 1, 2 };
}

fn addLen(gpa: std.mem.Allocator, ns: *std.ArrayList(u32), n: usize) !void {
    if (n < 1) return;
    for (ns.items) |x| if (x == n) return;
    try ns.append(gpa, @intCast(n));
}

fn buildCases(gpa: std.mem.Allocator, cases: *std.ArrayList(Case)) !void {
    var seed: u64 = 0x7461_6c69_6221;
    for (std.enums.values(Func)) |f| {
        const plist = try paramsOf(f, gpa);
        for (plist, 0..) |pp, pi| {
            const base = Case{ .func = f, .n = 0, .ip = pp.ip, .dp = pp.dp, .xp = pp.xp };
            const lbo = probeLookback(gpa, base);
            if (lbo == null) {
                var c = base;
                c.n = 300;
                c.bad = true;
                seed += 1;
                c.seed = seed;
                try cases.append(gpa, c);
                continue;
            }
            const lb = lbo.?;
            const per: usize = @intCast(@max(pp.ip[0], 1));
            var ns: std.ArrayList(u32) = .empty;
            for ([_]usize{ 1, 2, per -| 1, per, per + 1, lb, lb + 1, lb + 2, vecLen(f), 300 }) |n| try addLen(gpa, &ns, n);
            if (pi == 0) try addLen(gpa, &ns, 5000);
            for (ns.items) |n| {
                var c = base;
                c.n = n;
                seed += 1;
                c.seed = seed;
                c.emit = n == vecLen(f) and pi < emitSets(f);
                try cases.append(gpa, c);
                if ((n == 300 or (n == 5000 and isMathTx(f))) and pi < 4) for (kindsOf(f)) |k| {
                    var ck = c;
                    ck.kind = k;
                    seed += 1;
                    ck.seed = seed;
                    try cases.append(gpa, ck);
                };
                if (pi < 3 and n >= 300) {
                    var c32 = c;
                    c32.is32 = true;
                    c32.emit = false;
                    try cases.append(gpa, c32);
                }
            }
            if (hasZeroTies(f) and pi < 3) for ([_]usize{ vec_n, 300 }) |n| {
                // kind 3: windows tied between 0.0 and -0.0; the zero's sign is compared
                var ck = base;
                ck.kind = 3;
                ck.n = @intCast(n);
                seed += 1;
                ck.seed = seed;
                ck.emit = n == vec_n and pi == 0;
                try cases.append(gpa, ck);
            };
            if (pi == 0 and f != .trange) {
                var c32 = base;
                c32.is32 = true;
                c32.n = vecLen(f);
                seed += 1;
                c32.seed = seed;
                c32.emit = true;
                try cases.append(gpa, c32);
            }
            if (unstableMatters(f) and pi < 6) {
                for ([_][2]u32{ .{ 0, 3 }, .{ 1, 0 }, .{ 2, 0 } }) |u| {
                    for ([_]usize{ lb + 1, vecLen(f), 300, 700 }, 0..) |n, qi| {
                        if (qi == 3 and !isHt(f)) continue; // the long run is for the Hilbert family's AUTO warm-up
                        var c = base;
                        c.ukind = @intCast(u[0]);
                        c.ubars = u[1];
                        c.n = @intCast(n);
                        seed += 1;
                        c.seed = seed;
                        c.emit = n == vecLen(f) and pi < emitUnstableSets(f) and !(u[0] == 2) and !(u[0] == 0 and pi == 1);
                        try cases.append(gpa, c);
                        if (n == 300 and u[0] == 1 and pi < 3) {
                            var c32 = c;
                            c32.is32 = true;
                            c32.emit = false;
                            try cases.append(gpa, c32);
                        }
                    }
                }
            }
        }
    }
}

// ── comparison ──────────────────────────────────────────────────────────────

fn ordered(comptime T: type, x: T) i64 {
    const U = if (T == f32) u32 else u64;
    const I = if (T == f32) i32 else i64;
    const bits: U = @bitCast(x);
    const sign = @as(U, 1) << (@bitSizeOf(U) - 1);
    if (bits & sign != 0) return -@as(i64, @as(I, @intCast(bits & ~sign)));
    return @as(i64, @as(I, @intCast(bits)));
}

fn ulpDist(comptime T: type, a: T, b: T) u64 {
    if (std.math.isNan(a) and std.math.isNan(b)) return 0;
    if (std.math.isNan(a) or std.math.isNan(b)) return std.math.maxInt(u64);
    return @abs(ordered(T, a) - ordered(T, b));
}

const Stat = struct {
    records: usize = 0,
    values: usize = 0,
    bitwise: usize = 0,
    max_ulp: u64 = 0,
    /// Largest |ours - TA-Lib| over the largest |TA-Lib| value of the same output of the same record.
    max_scaled: f64 = 0.0,
    bad: usize = 0,
    reported: usize = 0,
};

const Ctx = struct {
    io: std.Io,
    cwd: std.Io.Dir,
    abs: []const u8,
    exe: []const u8,
    gpa: std.mem.Allocator,
    stats: [n_func]Stat = @splat(.{}),
    vec_out: ?*std.Io.Writer = null,
    vec_count: usize = 0,
};

fn report(c: *Ctx, cs: Case, comptime fmt: []const u8, args: anytype) void {
    const st = &c.stats[@backingInt(cs.func)];
    st.bad += 1;
    if (st.reported >= 3) return;
    st.reported += 1;
    std.debug.print("MISMATCH {s} n={d} f32={} unstable={d}/{d} kind={d} ip={any} dp={any}: ", .{ func_names[@backingInt(cs.func)], cs.n, cs.is32, cs.ukind, cs.ubars, cs.kind, cs.ip, cs.dp });
    std.debug.print(fmt ++ "\n", args);
}

const Head = struct { ret: i32, lb: i32, beg: i32, nb: i32 };

fn conv(arena: std.mem.Allocator, comptime T: type, xs: []const f64) ![]T {
    const r = try arena.alloc(T, xs.len);
    for (r, xs) |*d, x| d.* = @floatCast(x);
    return r;
}

/// Runs ours for one case against what TA-Lib answered; returns the number of
/// bytes of `theirs` consumed.
fn checkCase(comptime T: type, c: *Ctx, arena: std.mem.Allocator, cs: Case, head: Head, theirs: []const u8) !usize {
    const st = &c.stats[@backingInt(cs.func)];
    st.records += 1;
    const n: usize = cs.n;
    const sr = try genSeries(arena, cs.func, cs.seed, cs.kind, n);
    const sT = Ser(T){
        .o = try conv(arena, T, sr.o),
        .h = try conv(arena, T, sr.h),
        .l = try conv(arena, T, sr.l),
        .c = try conv(arena, T, sr.c),
        .v = try conv(arena, T, sr.v),
        .x = try conv(arena, T, sr.x),
    };
    const no = nOut(cs.func);
    const idx_out = isIndex(cs.func);
    var o: [4][]T = undefined;
    for (&o) |*sl| sl.* = try arena.alloc(T, n);
    var io: [2][]usize = undefined;
    for (&io) |*sl| sl.* = try arena.alloc(usize, n);
    const res = runOurs(T, c.gpa, cs, sT, &o, &io);
    if (res) |lb| {
        if (head.ret != 0) {
            report(c, cs, "ours succeeded (lookback {d}), TA-Lib returned {d}", .{ lb, head.ret });
            return 0;
        }
        if (@as(i64, head.lb) != @as(i64, @intCast(lb))) {
            report(c, cs, "lookback ours {d} TA-Lib {d}", .{ lb, head.lb });
            return @as(usize, @intCast(head.nb)) * 8 * no;
        }
        const nb: usize = @intCast(head.nb);
        const expect_nb = if (n > lb) n - lb else 0;
        if (nb != expect_nb or (nb > 0 and head.beg != head.lb)) {
            report(c, cs, "outBegIdx {d} outNBElement {d} for lookback {d}, n {d}", .{ head.beg, head.nb, lb, n });
            return nb * 8 * no;
        }
        var bad_here = false;
        for (0..no) |q| {
            var col_max: f64 = 0.0;
            if (!idx_out) for (0..nb) |i| {
                const w64: f64 = @bitCast(std.mem.readInt(u64, theirs[(q * nb + i) * 8 ..][0..8], .little));
                if (std.math.isFinite(w64)) col_max = @max(col_max, @abs(w64));
            };
            const lead = @min(lb, n);
            if (idx_out) {
                for (io[q][0..lead]) |v| if (v != ind.no_index) {
                    report(c, cs, "ours has an index in the lead of output {d}", .{q});
                    bad_here = true;
                    break;
                };
            } else {
                for (o[q][0..lead]) |v| if (!std.math.isNan(v)) {
                    report(c, cs, "ours has a non-NaN value in the lead of output {d}", .{q});
                    bad_here = true;
                    break;
                };
            }
            for (0..nb) |i| {
                const want64: f64 = @bitCast(std.mem.readInt(u64, theirs[(q * nb + i) * 8 ..][0..8], .little));
                var d: u64 = undefined;
                var got_f: f64 = undefined;
                var want_f: f64 = want64;
                if (idx_out) {
                    got_f = @floatFromInt(io[q][lb + i]);
                    d = if (got_f == want64) 0 else std.math.maxInt(u64);
                } else {
                    const want: T = @floatCast(want64);
                    const got = o[q][lb + i];
                    d = ulpDist(T, got, want);
                    // ulpDist reads +0.0 and -0.0 as equal; on the tie inputs (kind 3) their sign is part of the answer
                    if (cs.kind == 3 and d == 0 and got == 0 and std.math.signbit(got) != std.math.signbit(want)) d = 1;
                    got_f = got;
                    want_f = want;
                }
                st.values += 1;
                if (d == 0) st.bitwise += 1;
                if (!idx_out and col_max > 0.0 and d != std.math.maxInt(u64)) st.max_scaled = @max(st.max_scaled, @abs(got_f - want_f) / col_max);
                st.max_ulp = @max(st.max_ulp, d);
                const sb: f64 = if (usesMama(cs)) mama_slot_scaled else scaled_bound[@backingInt(cs.func)];
                const within_scaled = sb > 0.0 and @abs(got_f - want_f) <= sb * col_max;
                if (d > ulp_bound[@backingInt(cs.func)] and !within_scaled and !bad_here) {
                    report(c, cs, "output {d} at {d}: ours {e} TA-Lib {e} ({d} ulp)", .{ q, lb + i, got_f, want_f, d });
                    bad_here = true;
                }
            }
        }
        if (cs.emit and !bad_here) try emitVector(c, cs, lb, nb, sT, theirs);
        return nb * 8 * no;
    } else |err| switch (err) {
        error.BadParam => {
            if (head.ret != ta_bad_param) report(c, cs, "ours BadParam, TA-Lib returned {d}", .{head.ret});
            return if (head.ret == 0) @as(usize, @intCast(head.nb)) * 8 * no else 0;
        },
        else => {
            report(c, cs, "ours failed: {s}", .{@errorName(err)});
            return if (head.ret == 0) @as(usize, @intCast(head.nb)) * 8 * no else 0;
        },
    }
}

fn hexBits(w: *std.Io.Writer, v: f64) !void {
    try w.print("0x{x}", .{@as(u64, @bitCast(v))});
}

fn emitVector(c: *Ctx, cs: Case, lb: usize, nb: usize, sT: anytype, theirs: []const u8) !void {
    const w = c.vec_out orelse return;
    c.vec_count += 1;
    try w.print("    .{{ .func = {d}, .f32 = {}, .ukind = {d}, .ubars = {d}, .n = {d}, .lb = {d}, .ip = .{{", .{ @backingInt(cs.func), cs.is32, cs.ukind, cs.ubars, cs.n, lb });
    for (cs.ip, 0..) |x, i| try w.print("{s}{d}", .{ if (i > 0) ", " else " ", x });
    try w.writeAll(" }, .xp = .{");
    for (cs.xp, 0..) |x, i| try w.print("{s}{d}", .{ if (i > 0) ", " else " ", x });
    try w.writeAll(" }, .dp = .{ ");
    for (cs.dp, 0..) |d, i| {
        if (i > 0) try w.writeAll(", ");
        try hexBits(w, d);
    }
    try w.writeAll(" },\n      .ins = &.{");
    for (seriesOf(cs.func)) |letter| {
        const src = seriesSlice(sT, letter);
        try w.writeAll(" &.{");
        for (src, 0..) |v, i| {
            try w.writeAll(if (i > 0) ", " else " ");
            try hexBits(w, @floatCast(v));
        }
        try w.writeAll(" },");
    }
    try w.writeAll(" },\n      .outs = &.{");
    for (0..nOut(cs.func)) |q| {
        try w.writeAll(" &.{");
        for (0..nb) |i| {
            try w.writeAll(if (i > 0) ", " else " ");
            const x = std.mem.readInt(u64, theirs[(q * nb + i) * 8 ..][0..8], .little);
            try w.print("0x{x}", .{x});
        }
        try w.writeAll(" },");
    }
    try w.writeAll(" } },\n");
}

fn runAll(c: *Ctx, arena: std.mem.Allocator, cases: []const Case) !void {
    var buf: std.Io.Writer.Allocating = .init(arena);
    const w = &buf.writer;
    try w.writeInt(u32, @intCast(cases.len), .little);
    for (cases) |cs| {
        try w.writeAll(&.{ @backingInt(cs.func), @intFromBool(cs.is32), cs.ukind, 0 });
        try w.writeInt(u32, cs.ubars, .little);
        try w.writeInt(u32, cs.n, .little);
        for (cs.ip) |x| try w.writeInt(i32, x, .little);
        for (cs.dp) |x| try w.writeInt(u64, @bitCast(x), .little);
        for (cs.xp) |x| try w.writeInt(i32, x, .little);
        const n: usize = cs.n;
        const sr = try genSeries(arena, cs.func, cs.seed, cs.kind, n);
        for (seriesOf(cs.func)) |letter| {
            for (seriesSlice(sr, letter)) |v| {
                if (cs.is32) {
                    const f: f32 = @floatCast(v);
                    try w.writeInt(u32, @bitCast(f), .little);
                } else try w.writeInt(u64, @bitCast(v), .little);
            }
        }
    }
    const cases_path = try arena.print("{s}/cases.bin", .{c.abs});
    const results_path = try arena.print("{s}/results.bin", .{c.abs});
    try c.cwd.writeFile(c.io, .{ .sub_path = cases_path, .data = buf.written() });
    const res = try std.process.run(arena, c.io, .{ .argv = &.{ c.exe, cases_path, results_path } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("interop-indicators: TA-Lib side failed:\n{s}\n", .{res.stderr});
        return error.OracleFailed;
    }
    const theirs = try c.cwd.readFileAlloc(c.io, results_path, arena, .limited(1 << 31));
    var off: usize = 0;
    for (cases) |cs| {
        if (off + 16 > theirs.len) return error.ShortResults;
        var head: Head = undefined;
        head = .{
            .ret = std.mem.readInt(i32, theirs[off..][0..4], .little),
            .lb = std.mem.readInt(i32, theirs[off + 4 ..][0..4], .little),
            .beg = std.mem.readInt(i32, theirs[off + 8 ..][0..4], .little),
            .nb = std.mem.readInt(i32, theirs[off + 12 ..][0..4], .little),
        };
        off += 16;
        const used = if (cs.is32)
            try checkCase(f32, c, arena, cs, head, theirs[off..])
        else
            try checkCase(f64, c, arena, cs, head, theirs[off..]);
        off += used;
    }
    if (off != theirs.len) return error.TrailingResults;
}

fn expandHome(arena: std.mem.Allocator, home: ?[]const u8, path: []const u8) ![]const u8 {
    if (path.len > 0 and path[0] == '~') return try arena.print("{s}{s}", .{ home orelse "", path[1..] });
    return path;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const home = init.environ_map.get("HOME");
    const args = try init.minimal.args.toSlice(arena);
    var emit_path: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--emit-vectors") and i + 1 < args.len) {
            i += 1;
            emit_path = args[i];
        }
    }

    const archive = try expandHome(arena, home, init.environ_map.get("TALIB_A") orelse default_a);
    const inc = try expandHome(arena, home, init.environ_map.get("TALIB_INC") orelse default_inc);
    cwd.access(io, archive, .{}) catch {
        std.debug.print("interop-indicators: TA-Lib archive not found at {s} (set TALIB_A to libta-lib.a, see tools/README.md)\n", .{archive});
        return 2;
    };
    cwd.access(io, try arena.print("{s}/ta_libc.h", .{inc}), .{}) catch {
        std.debug.print("interop-indicators: ta_libc.h not found in {s} (set TALIB_INC)\n", .{inc});
        return 2;
    };
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const exe = try arena.print("{s}/talib_oracle", .{abs});
    const cc = try std.process.run(arena, io, .{ .argv = &.{ "zig", "cc", "-O1", "-I", inc, c_source, archive, "-lm", "-o", exe } });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("interop-indicators: zig cc failed:\n{s}\n", .{cc.stderr});
        return 1;
    }
    const ver_run = try std.process.run(arena, io, .{ .argv = &.{ exe, "--version" } });
    const version = std.mem.trimEnd(u8, ver_run.stdout, "\n");

    var cases: std.ArrayList(Case) = .empty;
    try buildCases(arena, &cases);

    var vec: std.Io.Writer.Allocating = .init(arena);
    var ctx: Ctx = .{ .io = io, .cwd = cwd, .abs = abs, .exe = exe, .gpa = arena };
    if (emit_path != null) {
        ctx.vec_out = &vec.writer;
        try vec.writer.writeAll(
            \\// SPDX-License-Identifier: MIT
            \\//! GENERATED by `zig build interop-indicators -- --emit-vectors <this file>`
            \\//! (modules/indicators/tools/interop.zig): TA-Lib answers frozen as bit patterns.
            \\//! Inputs and outputs are f64 bits (for `f32` records the inputs are the f32
            \\//! values widened, the outputs TA_S_*'s doubles). Replayed by src/oracle_test.zig.
            \\
            \\pub const Vec = struct {
            \\    func: u8,
            \\    f32: bool,
            \\    ukind: u8,
            \\    ubars: u32,
            \\    n: u32,
            \\    lb: u32,
            \\    ip: [6]i32,
            \\    xp: [6]i32,
            \\    dp: [8]u64,
            \\    ins: []const []const u64,
            \\    outs: []const []const u64,
            \\};
            \\
            \\
        );
        try vec.writer.print("pub const source = \"{s}\";\n\n", .{version});
        try vec.writer.writeAll("pub const vectors = [_]Vec{\n");
    }
    try runAll(&ctx, arena, cases.items);

    var failed = false;
    std.debug.print("interop-indicators: {s}, {d} records\n", .{ version, cases.items.len });
    std.debug.print("  {s:<8} {s:>8} {s:>10} {s:>10} {s:>8} {s:>5} {s:>10}\n", .{ "func", "records", "values", "bitwise", "max ulp", "bad", "max/colmax" });
    for (func_names, ctx.stats) |name, st| {
        std.debug.print("  {s:<8} {d:>8} {d:>10} {d:>10} {d:>8} {d:>5} {e:>10.1}\n", .{ name, st.records, st.values, st.bitwise, st.max_ulp, st.bad, st.max_scaled });
        if (st.bad != 0) failed = true;
    }
    if (failed) {
        std.debug.print("interop-indicators: DISAGREEMENT with {s}\n", .{version});
        return 1;
    }
    if (emit_path) |pth| {
        try vec.writer.writeAll("};\n\npub const ulp_bound = [_]u64{");
        for (ulp_bound, 0..) |b, k| try vec.writer.print("{s}{d}", .{ if (k > 0) ", " else " ", b });
        try vec.writer.writeAll(" };\n\npub const scaled_bound = [_]f64{");
        for (scaled_bound, 0..) |b, k| try vec.writer.print("{s}{e}", .{ if (k > 0) ", " else " ", b });
        try vec.writer.writeAll(" };\n");
        if (std.fs.path.dirname(pth)) |d| try cwd.createDirPath(io, d);
        try cwd.writeFile(io, .{ .sub_path = pth, .data = vec.written() });
        std.debug.print("interop-indicators: wrote {d} vectors to {s}\n", .{ ctx.vec_count, pth });
    }
    std.debug.print("interop-indicators: all cases agree with {s}\n", .{version});
    return 0;
}
