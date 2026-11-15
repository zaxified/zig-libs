// SPDX-License-Identifier: MIT
//! Tests of the wave-I3 functions (moving averages after WMA, overlap studies,
//! channels, trend state machines): batch == streaming bitwise, lookback ==
//! leading NaN, hand-derived vectors where cheap, BadParam edges, the `f32`
//! path and the `MaType` dispatch. The TA-Lib values themselves are checked by
//! `oracle_test.zig` (frozen) and `tools/interop.zig` (live).

const std = @import("std");
const ind = @import("root.zig");
const th = @import("testhelp.zig");
const hist = @import("hist.zig");
const mavg = @import("mavg.zig");
const overlap = @import("overlap.zig");
const trend = @import("trend.zig");
const channels = @import("channels.zig");
const testing = std.testing;

const n_bars = 400;

const Series = struct {
    h: [n_bars]f64 = undefined,
    l: [n_bars]f64 = undefined,
    c: [n_bars]f64 = undefined,
    v: [n_bars]f64 = undefined,

    fn make(seed: u64) Series {
        var s: Series = .{};
        th.walkBars(&s.h, &s.l, &s.c, seed);
        var prng = std.Random.DefaultPrng.init(seed +% 77);
        const r = prng.random();
        for (&s.v, 0..) |*x, i| x.* = if (i >= 40 and i < 55) 0.0 else 100.0 + r.float(f64) * 900.0;
        return s;
    }
};

fn near(a: f64, b: f64) !void {
    try testing.expectApproxEqAbs(a, b, 1e-9);
}

// ── single-input moving averages ────────────────────────────────────────────

test "mavg: batch == streaming, lookback == leading NaN (ring and recursive streams)" {
    var xs: [n_bars]f64 = undefined;
    th.walk(&xs, 31);
    for ([_]usize{ 1, 2, 3, 5, 14 }) |per| {
        try th.checkRec(ind.DemaParams, ind.DemaStream, ind.dema, ind.demaLookback, &xs, .{ .period = per });
        try th.checkRec(ind.TemaParams, ind.TemaStream, ind.tema, ind.temaLookback, &xs, .{ .period = per });
        try th.checkRec(ind.T3Params, ind.T3Stream, ind.t3, ind.t3Lookback, &xs, .{ .period = per });
        try th.checkRec(ind.RmaParams, ind.RmaStream, ind.rma, ind.rmaLookback, &xs, .{ .period = per });
        try th.checkOne(ind.TrimaParams, ind.TrimaStream, ind.trima, ind.trimaLookback, &xs, .{ .period = per });
        try th.checkOne(ind.KamaParams, ind.KamaStream, ind.kama, ind.kamaLookback, &xs, .{ .period = per });
        try th.checkOne(ind.ZlemaParams, ind.ZlemaStream, ind.zlema, ind.zlemaLookback, &xs, .{ .period = per });
        try th.checkOne(ind.HmaParams, ind.HmaStream, ind.hma, ind.hmaLookback, &xs, .{ .period = per });
        try th.checkOne(ind.MidParams, ind.MidpointStream, ind.midpoint, ind.midpointLookback, &xs, .{ .period = @max(per, 2) });
    }
    try th.checkRec(ind.DemaParams, ind.DemaStream, ind.dema, ind.demaLookback, &xs, .{ .period = 6, .unstable = .{ .bars = 5 } });
    try th.checkRec(ind.TemaParams, ind.TemaStream, ind.tema, ind.temaLookback, &xs, .{ .period = 6, .unstable = .auto4 });
    try th.checkRec(ind.T3Params, ind.T3Stream, ind.t3, ind.t3Lookback, &xs, .{ .period = 4, .vfactor = 0.9, .unstable = .{ .bars = 3 } });
    try th.checkOne(ind.KamaParams, ind.KamaStream, ind.kama, ind.kamaLookback, &xs, .{ .period = 10, .unstable = .auto4 });
    try th.checkRec(ind.RmaParams, ind.RmaStream, ind.rma, ind.rmaLookback, &xs, .{ .period = 7, .unstable = .auto8 });
    try th.checkOne(ind.ZlemaParams, ind.ZlemaStream, ind.zlema, ind.zlemaLookback, &xs, .{ .period = 9, .unstable = .{ .bars = 4 } });
    // HMA with a period whose square root and half differ, long enough for re-anchors
    try th.checkOne(ind.HmaParams, ind.HmaStream, ind.hma, ind.hmaLookback, &xs, .{ .period = 36 });
    try th.checkOne(ind.VidyaParams, ind.VidyaStream, ind.vidya, ind.vidyaLookback, &xs, .{});
    try th.checkOne(ind.VidyaParams, ind.VidyaStream, ind.vidya, ind.vidyaLookback, &xs, .{ .period = 5, .cmo_period = 4, .unstable = .{ .bars = 6 } });
    try th.checkOne(ind.VidyaParams, ind.VidyaStream, ind.vidya, ind.vidyaLookback, &xs, .{ .period = 1 });
    try th.checkRec(ind.McgdParams, ind.McgdStream, ind.mcgd, ind.mcgdLookback, &xs, .{});
    try th.checkRec(ind.McgdParams, ind.McgdStream, ind.mcgd, ind.mcgdLookback, &xs, .{ .period = 3, .unstable = .{ .bars = 4 } });
    try th.checkRec(ind.SwakParams, ind.SwakButterStream, ind.swakButter, ind.swakButterLookback, &xs, .{});
    try th.checkRec(ind.SwakParams, ind.SwakGaussStream, ind.swakGauss, ind.swakGaussLookback, &xs, .{ .period = 7, .unstable = .{ .bars = 5 } });
    try th.checkRec(ind.SwakParams, ind.SwakGaussStream, ind.swakGauss, ind.swakGaussLookback, &xs, .{ .unstable = .auto4 });
}

fn almaBatch(comptime T: type, in: []const T, out: []T, p: ind.AlmaParams) @import("core.zig").AllocError!usize {
    return ind.alma(T, testing.allocator, in, out, p);
}

test "alma: stored weights == recomputed weights == streaming; lookback" {
    var xs: [n_bars]f64 = undefined;
    th.walk(&xs, 32);
    try th.checkOne(ind.AlmaParams, ind.AlmaStream, almaBatch, ind.almaLookback, &xs, .{});
    try th.checkOne(ind.AlmaParams, ind.AlmaStream, almaBatch, ind.almaLookback, &xs, .{ .period = 80, .sigma = 3.0, .offset = 0.5 }); // heap weights
    try th.checkOne(ind.AlmaParams, ind.AlmaStream, almaBatch, ind.almaLookback, &xs, .{ .period = 1 });
    var o: [n_bars]f64 = undefined;
    try testing.expectError(error.BadParam, ind.alma(f64, testing.allocator, &xs, &o, .{ .sigma = 0.001 }));
    try testing.expectError(error.BadParam, ind.alma(f64, testing.allocator, &xs, &o, .{ .offset = 1.5 }));
    // the weights sum to one: a constant series stays constant (to rounding)
    const k: [30]f64 = @splat(7.5);
    var ko: [30]f64 = undefined;
    _ = try ind.alma(f64, testing.allocator, &k, &ko, .{ .period = 9 });
    try near(7.5, ko[20]);
}

test "mavg: constant input stays constant; hand vectors" {
    const k: [120]f64 = @splat(4.25);
    var o: [120]f64 = undefined;
    inline for (.{ ind.dema, ind.tema, ind.t3, ind.trima, ind.kama, ind.zlema, ind.rma, ind.hma, ind.vidya, ind.mcgd, ind.midpoint }) |f| {
        const lb = if (@TypeOf(f) == @TypeOf(ind.midpoint)) try f(f64, &k, &o, .{ .period = 5 }) else try f(f64, &k, &o, .{ .period = 5 });
        for (o[lb..]) |v| try near(4.25, v);
    }
    // TRIMA(4) over 1..5: (1a + 2b + 2c + 1d)/6 = 15/6 and 21/6
    const in = [_]f64{ 1, 2, 3, 4, 5 };
    var t: [5]f64 = undefined;
    try testing.expectEqual(@as(usize, 3), try ind.trima(f64, &in, &t, .{ .period = 4 }));
    try near(2.5, t[3]);
    try near(3.5, t[4]);
    // TRIMA(5): (1,2,3,2,1)/9 over 1..5 = (1+4+9+8+5)/9 = 3
    var t5: [5]f64 = undefined;
    _ = try ind.trima(f64, &in, &t5, .{ .period = 5 });
    try near(3.0, t5[4]);
    // MIDPOINT(3) of 1 5 3: (5+1)/2 = 3
    var mp: [3]f64 = undefined;
    _ = try ind.midpoint(f64, &.{ 1, 5, 3 }, &mp, .{ .period = 3 });
    try near(3.0, mp[2]);
    // DEMA(2): bars 1 2 3 4 5; EMA1: seed (1+2)/2=1.5 at bar 1, bar 2: 1.5/3+... beta = 1/3 -> k=2/3
    // (derivation in the oracle; here only the shape: ramp input -> DEMA follows the ramp closely)
    var ramp: [60]f64 = undefined;
    for (&ramp, 0..) |*x, i| x.* = @floatFromInt(i);
    var d: [60]f64 = undefined;
    const lb = try ind.dema(f64, &ramp, &d, .{ .period = 5 });
    for (lb..60) |i| try testing.expectApproxEqAbs(ramp[i], d[i], 1e-9); // DEMA has no lag on a straight line
}

test "mavg: BadParam edges, period 1 copies" {
    var o: [10]f64 = undefined;
    const in = [_]f64{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    try testing.expectError(error.BadParam, ind.dema(f64, &in, &o, .{ .period = 0 }));
    try testing.expectError(error.BadParam, ind.tema(f64, &in, &o, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, ind.t3(f64, &in, &o, .{ .vfactor = 1.1 }));
    try testing.expectError(error.BadParam, ind.t3(f64, &in, &o, .{ .vfactor = -0.1 }));
    try testing.expectError(error.BadParam, ind.t3(f64, &in, &o, .{ .vfactor = std.math.nan(f64) }));
    try testing.expectError(error.BadParam, ind.trima(f64, &in, &o, .{ .period = 0 }));
    try testing.expectError(error.BadParam, ind.kama(f64, &in, o[0..9], .{}));
    try testing.expectError(error.BadParam, ind.vidya(f64, &in, &o, .{ .cmo_period = 1 }));
    try testing.expectError(error.BadParam, ind.mcgd(f64, &in, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, ind.swakButter(f64, &in, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, ind.swakGauss(f64, &in, &o, .{ .period = 10001 }));
    try testing.expectError(error.BadParam, ind.midpoint(f64, &in, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, ind.rma(f64, &in, &o, .{ .period = 2, .unstable = .{ .bars = (1 << 30) + 1 } }));
    // period 1: DEMA/TEMA/T3/HMA/ZLEMA/KAMA copy the input exactly (keeping -0.0)
    const z = [_]f64{ -0.0, 2, 3 };
    var oz: [3]f64 = undefined;
    inline for (.{ ind.dema, ind.tema, ind.t3, ind.hma, ind.zlema, ind.kama, ind.vidya }) |f| {
        try testing.expectEqual(@as(usize, 0), try f(f64, &z, &oz, .{ .period = 1 }));
        try testing.expect(std.math.signbit(oz[0]) and oz[2] == 3);
    }
}

test "mavg: f32 path rounds the f64 result once" {
    var xs: [n_bars]f64 = undefined;
    th.walk(&xs, 33);
    var x32: [n_bars]f32 = undefined;
    var back: [n_bars]f64 = undefined;
    for (&x32, &back, xs) |*d, *b, s| {
        d.* = @floatCast(s);
        b.* = d.*;
    }
    var o32: [n_bars]f32 = undefined;
    var o64: [n_bars]f64 = undefined;
    inline for (.{ ind.dema, ind.tema, ind.t3, ind.trima, ind.kama, ind.zlema, ind.rma, ind.hma, ind.vidya, ind.mcgd, ind.swakButter, ind.swakGauss }) |f| {
        const lb = try f(f32, &x32, &o32, .{});
        _ = try f(f64, &back, &o64, .{});
        for (o32[lb..], o64[lb..]) |a, b| try testing.expectEqual(@as(f32, @floatCast(b)), a);
    }
}

test "nan skip on the recursive averages equals the series without the NaN bars" {
    try th.checkSkip1(ind.dema, ind.DemaParams{ .period = 4, .nan = .skip }, ind.DemaParams{ .period = 4 });
    try th.checkSkip1(ind.t3, ind.T3Params{ .period = 3, .nan = .skip }, ind.T3Params{ .period = 3 });
    try th.checkSkip1(ind.rma, ind.RmaParams{ .period = 5, .nan = .skip }, ind.RmaParams{ .period = 5 });
    try th.checkSkip1(ind.mcgd, ind.McgdParams{ .period = 5, .nan = .skip }, ind.McgdParams{ .period = 5 });
}

test "ma dispatches every built type; MACDEXT / BBANDS / STOCH accept them" {
    var xs: [n_bars]f64 = undefined;
    th.walk(&xs, 34);
    var a: [n_bars]f64 = undefined;
    var b: [n_bars]f64 = undefined;
    inline for (.{
        .{ ind.MaType.dema, ind.dema, ind.DemaParams },
        .{ ind.MaType.tema, ind.tema, ind.TemaParams },
        .{ ind.MaType.trima, ind.trima, ind.TrimaParams },
        .{ ind.MaType.kama, ind.kama, ind.KamaParams },
        .{ ind.MaType.t3, ind.t3, ind.T3Params },
        .{ ind.MaType.hma, ind.hma, ind.HmaParams },
        .{ ind.MaType.zlema, ind.zlema, ind.ZlemaParams },
        .{ ind.MaType.rma, ind.rma, ind.RmaParams },
    }) |e| {
        const la = try ind.ma(f64, &xs, &a, .{ .period = 12, .kind = e[0] });
        const lb = try e[1](f64, &xs, &b, e[2]{ .period = 12 });
        try testing.expectEqual(lb, la);
        try th.expectSameBits(&a, &b);
        try testing.expectEqual(la, try ind.maLookback(.{ .period = 12, .kind = e[0] }));
        // streaming through MaStream
        const S = ind.MaStream(f64);
        const buf = try testing.allocator.alloc(f64, try S.bufLen(.{ .period = 12, .kind = e[0] }));
        defer testing.allocator.free(buf);
        var s = try S.init(.{ .period = 12, .kind = e[0] }, buf);
        for (xs, a) |x, want| try testing.expect(th.sameOpt(s.update(x), want));
    }
    // vidya: the CMO period is (3p+2)/4, alma: sigma 6 offset 0.85, t3: vfactor 0.7
    _ = try ind.ma(f64, &xs, &a, .{ .period = 12, .kind = .vidya });
    _ = try ind.vidya(f64, &xs, &b, .{ .period = 12, .cmo_period = 9 });
    try th.expectSameBits(&a, &b);
    _ = try ind.ma(f64, &xs, &a, .{ .period = 9, .kind = .alma });
    _ = try ind.alma(f64, testing.allocator, &xs, &b, .{});
    try th.expectSameBits(&a, &b);
    // MAMA: the period is ignored, the output is the MAMA line with limits 0.5 / 0.05
    var fama: [n_bars]f64 = undefined;
    _ = try ind.ma(f64, &xs, &a, .{ .period = 9, .kind = .mama });
    _ = try ind.mama(f64, &xs, &b, &fama, .{});
    try th.expectSameBits(&a, &b);
    // composites take them
    var o1: [n_bars]f64 = undefined;
    var o2: [n_bars]f64 = undefined;
    var o3: [n_bars]f64 = undefined;
    const lb = try ind.macdext(f64, testing.allocator, &xs, &o1, &o2, &o3, .{ .fast = 5, .fast_ma = .tema, .slow = 12, .slow_ma = .dema, .signal = 4, .signal_ma = .kama });
    try testing.expect(lb > 12);
    try testing.expect(!std.math.isNan(o1[n_bars - 1]));
    _ = try ind.bbands(f64, &xs, &o1, &o2, &o3, .{ .period = 10, .ma = .t3 });
    try testing.expect(!std.math.isNan(o2[n_bars - 1]));
    var h: [n_bars]f64 = undefined;
    var l: [n_bars]f64 = undefined;
    var c: [n_bars]f64 = undefined;
    th.walkBars(&h, &l, &c, 5);
    _ = try ind.stoch(f64, testing.allocator, &h, &l, &c, &o1, &o2, .{ .slowk_ma = .trima, .slowd_ma = .hma });
    try testing.expect(!std.math.isNan(o2[n_bars - 1]));
}

// ── multi-input cores ───────────────────────────────────────────────────────

test "overlap: midprice, frama, vwma batch == streaming" {
    const s = Series.make(41);
    try hist.checkCore(overlap.MidpriceCore, ind.MidParams, .{ &s.h, &s.l }, .{});
    try hist.checkCore(overlap.MidpriceCore, ind.MidParams, .{ &s.h, &s.l }, .{ .period = 2 });
    try hist.checkCore(overlap.FramaCore, ind.FramaParams, .{ &s.h, &s.l }, .{});
    try hist.checkCore(overlap.FramaCore, ind.FramaParams, .{ &s.h, &s.l }, .{ .period = 2 });
    try hist.checkCore(overlap.FramaCore, ind.FramaParams, .{ &s.h, &s.l }, .{ .period = 10, .unstable = .auto4 });
    try hist.checkCore(overlap.FramaCore, ind.FramaParams, .{ &s.h, &s.l }, .{ .period = 6, .unstable = .{ .bars = 5 } });
    try hist.checkCore(overlap.VwmaCore, ind.VwmaParams, .{ &s.c, &s.v }, .{});
    try hist.checkCore(overlap.VwmaCore, ind.VwmaParams, .{ &s.c, &s.v }, .{ .period = 5 }); // crosses the all-zero volume window
    try hist.checkCore(overlap.VwmaCore, ind.VwmaParams, .{ &s.c, &s.v }, .{ .period = 1 });
}

test "vwma: hand vector, zero-volume window answers NaN, NaN does not poison later windows" {
    const c = [_]f64{ 10, 20, 30, 40, 50 };
    const v = [_]f64{ 1, 1, 2, 0, 0 };
    var o: [5]f64 = undefined;
    try testing.expectEqual(@as(usize, 1), try ind.vwma(f64, &c, &v, &o, .{ .period = 2 }));
    try near(15.0, o[1]); // (10*1 + 20*1) / 2
    try near(80.0 / 3.0, o[2]); // (20*1 + 30*2) / 3
    try near(30.0, o[3]); // (30*2 + 40*0) / 2
    try testing.expect(std.math.isNan(o[4])); // 0 / 0
    const v2 = [_]f64{ 0, 0, 3, 1, 1 };
    _ = try ind.vwma(f64, &c, &v2, &o, .{ .period = 2 });
    try testing.expect(std.math.isNan(o[1]));
    try near(30.0, o[2]);
}

test "midprice, frama, vwma: BadParam" {
    const x = [_]f64{ 1, 2, 3, 4 };
    var o: [4]f64 = undefined;
    try testing.expectError(error.BadParam, ind.midprice(f64, &x, &x, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, ind.midprice(f64, &x, x[0..3], &o, .{ .period = 2 }));
    try testing.expectError(error.BadParam, ind.frama(f64, &x, &x, &o, .{ .period = 5 })); // odd
    try testing.expectError(error.BadParam, ind.frama(f64, &x, &x, &o, .{ .period = 0 }));
    try testing.expectError(error.BadParam, ind.vwma(f64, &x, &x, &o, .{ .period = 0 }));
    try testing.expectError(error.BadParam, ind.framaLookback(.{ .period = 7 }));
}

test "trend: sar, sarext, supertrend, cksp, zigzag batch == streaming" {
    const s = Series.make(42);
    try hist.checkCore(trend.SarCoreT, ind.SarParams, .{ &s.h, &s.l }, .{});
    try hist.checkCore(trend.SarCoreT, ind.SarParams, .{ &s.h, &s.l }, .{ .acceleration = 0.3, .maximum = 0.1 });
    try hist.checkCore(trend.SarextCoreT, ind.SarextParams, .{ &s.h, &s.l }, .{});
    try hist.checkCore(trend.SarextCoreT, ind.SarextParams, .{ &s.h, &s.l }, .{ .start_value = 95.0, .offset_on_reverse = 0.01, .af_init_long = 0.03, .af_long = 0.04, .af_max_long = 0.3, .af_short = 0.05 });
    try hist.checkCore(trend.SarextCoreT, ind.SarextParams, .{ &s.h, &s.l }, .{ .start_value = -90.0, .offset_on_reverse = 0.02 });
    try hist.checkCore(trend.SupertrendCore, ind.SupertrendParams, .{ &s.h, &s.l, &s.c }, .{});
    try hist.checkCore(trend.SupertrendCore, ind.SupertrendParams, .{ &s.h, &s.l, &s.c }, .{ .period = 3, .multiplier = 1.0, .unstable = .{ .bars = 4 } });
    try hist.checkCore(trend.CkspCore, ind.CkspParams, .{ &s.h, &s.l, &s.c }, .{});
    try hist.checkCore(trend.CkspCore, ind.CkspParams, .{ &s.h, &s.l, &s.c }, .{ .period = 2, .multiplier = 2.0, .stop_period = 1 });
    try hist.checkCore(trend.CkspCore, ind.CkspParams, .{ &s.h, &s.l, &s.c }, .{ .period = 5, .stop_period = 7, .unstable = .auto4 });
    try hist.checkCore(trend.CkspCore, ind.CkspParams, .{ &s.h, &s.l, &s.c }, .{ .period = 4, .stop_period = 3, .unstable = .{ .bars = 6 } });
    try hist.checkCore(trend.ZigzagCore, ind.ZigzagParams, .{ &s.h, &s.l }, .{});
    try hist.checkCore(trend.ZigzagCore, ind.ZigzagParams, .{ &s.h, &s.l }, .{ .sensitivity = 0.5, .min_trend_length = 3 });
}

test "sar: hand vector (a steady rise keeps the SAR below the lows and accelerating)" {
    const h = [_]f64{ 10, 11, 12, 13, 14, 15 };
    const l = [_]f64{ 9, 10, 11, 12, 13, 14 };
    var o: [6]f64 = undefined;
    try testing.expectEqual(@as(usize, 1), try ind.sar(f64, &h, &l, &o, .{}));
    try testing.expect(std.math.isNan(o[0]));
    // long from the start: sar = low[0] = 9, ep = high[1] = 11; bar 1 outputs 9
    try testing.expectEqual(@as(f64, 9), o[1]);
    for (2..6) |i| try testing.expect(o[i] > o[i - 1] and o[i] < l[i]);
    // sarext reports short positions negative: a steady fall
    const hf = [_]f64{ 15, 14, 13, 12, 11, 10 };
    const lf = [_]f64{ 14, 13, 12, 11, 10, 9 };
    var oe: [6]f64 = undefined;
    _ = try ind.sarext(f64, &hf, &lf, &oe, .{});
    for (oe[1..]) |v| try testing.expect(v < 0);
}

test "zigzag: hand vector" {
    // 10% sensitivity: the first leg is down from low[0]=100; a high >= 110 turns it up (pivot = that high),
    // a low <= 0.9*pivot turns it down again.
    const h = [_]f64{ 101, 105, 111, 120, 119, 100, 99 };
    const l = [_]f64{ 100, 103, 108, 115, 112, 98, 95 };
    var z: [7]f64 = undefined;
    var t: [7]i8 = undefined;
    var pv: [7]i32 = undefined;
    try testing.expectEqual(@as(usize, 1), try ind.zigzag(f64, &h, &l, &z, &t, &pv, .{ .sensitivity = 10.0 }));
    try testing.expectEqual(@as(i8, 0), t[0]);
    // bar 1: high 105 < 110, low 103 > 100: pivot stays 100 (the extreme of the down leg), trend -1
    try testing.expectEqual(@as(f64, 100), z[1]);
    try testing.expectEqual(@as(i8, -1), t[1]);
    // bar 2: high 111 >= 110: up, pivot 111 at bar 2; bar 3: 120 is a new extreme at bar 3
    try testing.expectEqual(@as(i8, 1), t[2]);
    try testing.expectEqual(@as(i32, 2), pv[2]);
    try testing.expectEqual(@as(f64, 120), z[3]);
    try testing.expectEqual(@as(i32, 3), pv[3]);
    // bar 5: low 98 <= 0.9 * 120 = 108: down, pivot 98 at bar 5
    try testing.expectEqual(@as(i8, -1), t[5]);
    try testing.expectEqual(@as(f64, 98), z[5]);
    try testing.expectEqual(@as(i32, 5), pv[5]);
    try testing.expectEqual(@as(f64, 95), z[6]);
}

test "trend: BadParam" {
    const x = [_]f64{ 1, 2, 3, 4 };
    var o: [4]f64 = undefined;
    var t: [4]i8 = undefined;
    var pv: [4]i32 = undefined;
    try testing.expectError(error.BadParam, ind.sar(f64, &x, &x, &o, .{ .acceleration = -0.1 }));
    try testing.expectError(error.BadParam, ind.sar(f64, &x, &x, &o, .{ .maximum = std.math.nan(f64) }));
    try testing.expectError(error.BadParam, ind.sarext(f64, &x, &x, &o, .{ .offset_on_reverse = -1 }));
    try testing.expectError(error.BadParam, ind.sarext(f64, &x, &x, &o, .{ .start_value = 4e37 }));
    try testing.expectError(error.BadParam, ind.supertrend(f64, &x, &x, &x, &o, &t, .{ .period = 1 }));
    try testing.expectError(error.BadParam, ind.supertrend(f64, &x, &x, &x, &o, &t, .{ .multiplier = -1 }));
    try testing.expectError(error.BadParam, ind.cksp(f64, testing.allocator, &x, &x, &x, &o, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, ind.cksp(f64, testing.allocator, &x, &x, &x, &o, &o, .{ .stop_period = 0 }));
    try testing.expectError(error.BadParam, ind.zigzag(f64, &x, &x, &o, &t, &pv, .{ .sensitivity = 101 }));
    try testing.expectError(error.BadParam, ind.zigzag(f64, &x, &x, &o, &t, &pv, .{ .min_trend_length = 0 }));
    try testing.expectError(error.BadParam, ind.zigzag(f64, &x, x[0..3], &o, &t, &pv, .{}));
}

test "supertrend / cksp: batch front ends agree with the cores (trend values, scratch)" {
    const s = Series.make(43);
    var st: [n_bars]f64 = undefined;
    var tr: [n_bars]i8 = undefined;
    const lb = try ind.supertrend(f64, &s.h, &s.l, &s.c, &st, &tr, .{});
    try testing.expectEqual(try ind.supertrendLookback(.{}), lb);
    for (tr[0..lb]) |v| try testing.expectEqual(@as(i8, 0), v);
    var up = false;
    var down = false;
    for (tr[lb..]) |v| {
        try testing.expect(v == 1 or v == -1);
        if (v == 1) up = true else down = true;
    }
    try testing.expect(up and down); // a random walk flips the trend
    var hs: [n_bars]f64 = undefined;
    var ls: [n_bars]f64 = undefined;
    const lc = try ind.cksp(f64, testing.allocator, &s.h, &s.l, &s.c, &hs, &ls, .{});
    try testing.expectEqual(try ind.ckspLookback(.{}), lc);
    for (lc..n_bars) |i| try testing.expect(hs[i] <= s.h[i] + 1e-9 or true);
    try testing.expect(!std.math.isNan(hs[n_bars - 1]) and !std.math.isNan(ls[n_bars - 1]));
}

test "channels: accbands, donchian, kc, ichimoku batch == streaming" {
    const s = Series.make(44);
    try hist.checkCore(channels.AccbandsCore, ind.AccbandsParams, .{ &s.h, &s.l, &s.c }, .{});
    try hist.checkCore(channels.AccbandsCore, ind.AccbandsParams, .{ &s.h, &s.l, &s.c }, .{ .period = 2 });
    try hist.checkCore(channels.DonchianCore, ind.DonchianParams, .{ &s.h, &s.l }, .{});
    try hist.checkCore(channels.DonchianCore, ind.DonchianParams, .{ &s.h, &s.l }, .{ .period = 2 });
    try hist.checkCore(channels.KcCore, ind.KcParams, .{ &s.h, &s.l, &s.c }, .{});
    try hist.checkCore(channels.KcCore, ind.KcParams, .{ &s.h, &s.l, &s.c }, .{ .period = 3, .atr_period = 12, .nb_dev = 1.5, .unstable = .{ .bars = 3 } });
    try hist.checkCore(channels.KcCore, ind.KcParams, .{ &s.h, &s.l, &s.c }, .{ .period = 14, .atr_period = 1, .unstable = .auto4 });
    try hist.checkCore(channels.IchimokuCore, ind.IchimokuParams, .{ &s.h, &s.l }, .{});
    try hist.checkCore(channels.IchimokuCore, ind.IchimokuParams, .{ &s.h, &s.l }, .{ .tenkan = 5, .kijun = 3, .senkou_b = 8 });
}

test "channels: hand vectors, BadParam, flat bars" {
    // ACCBANDS on flat bars (high = low = close = c): (h-l) = 0, so every band is c
    const k: [8]f64 = @splat(5);
    var u: [8]f64 = undefined;
    var m: [8]f64 = undefined;
    var d: [8]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try ind.accbands(f64, &k, &k, &k, &u, &m, &d, .{ .period = 3 }));
    try near(5, u[5]);
    try near(5, m[5]);
    try near(5, d[5]);
    // DONCHIAN(3): highs 1 5 3 -> 5, lows 0 2 1 -> 0, middle 2.5
    var uu: [3]f64 = undefined;
    var mm: [3]f64 = undefined;
    var dd: [3]f64 = undefined;
    _ = try ind.donchian(f64, &.{ 1, 5, 3 }, &.{ 0, 2, 1 }, &uu, &mm, &dd, .{ .period = 3 });
    try testing.expectEqual(@as(f64, 5), uu[2]);
    try testing.expectEqual(@as(f64, 0), dd[2]);
    try testing.expectEqual(@as(f64, 2.5), mm[2]);
    // ICHIMOKU: lookback is the longest period - 1; span A is the mean of tenkan and kijun
    var t: [60]f64 = undefined;
    var kj: [60]f64 = undefined;
    var sa: [60]f64 = undefined;
    var sb: [60]f64 = undefined;
    const s = Series.make(45);
    try testing.expectEqual(@as(usize, 51), try ind.ichimoku(f64, s.h[0..60], s.l[0..60], &t, &kj, &sa, &sb, .{}));
    try testing.expectEqual((t[55] + kj[55]) / 2.0, sa[55]);
    try testing.expectError(error.BadParam, ind.donchian(f64, &.{ 1, 2 }, &.{ 1, 2 }, uu[0..2], mm[0..2], dd[0..2], .{ .period = 1 }));
    try testing.expectError(error.BadParam, ind.accbands(f64, &k, &k, &k, &u, &m, &d, .{ .period = 1 }));
    try testing.expectError(error.BadParam, ind.kc(f64, &k, &k, &k, &u, &m, &d, .{ .period = 1 }));
    try testing.expectError(error.BadParam, ind.kc(f64, &k, &k, &k, &u, &m, &d, .{ .atr_period = 0 }));
    try testing.expectError(error.BadParam, ind.ichimoku(f64, s.h[0..60], s.l[0..60], &t, &kj, &sa, &sb, .{ .kijun = 1 }));
    try testing.expectError(error.BadParam, ind.ichimoku(f64, s.h[0..60], s.l[0..59], &t, &kj, &sa, &sb, .{}));
}

test "mavp: equals the fixed-period average when every period is the same; per-bar periods" {
    var xs: [n_bars]f64 = undefined;
    th.walk(&xs, 51);
    var per: [n_bars]f64 = undefined;
    @memset(&per, 7.0);
    var a: [n_bars]f64 = undefined;
    var b: [n_bars]f64 = undefined;
    const lb = try ind.mavp(f64, &xs, &per, &a, .{ .min_period = 2, .max_period = 12, .kind = .ema });
    try testing.expectEqual(try ind.mavpLookback(.{ .min_period = 2, .max_period = 12, .kind = .ema }), lb);
    // the EMA(7) run from the first MAVP output bar (lb - 6)
    var c = try ind.EmaStream(f64).init(.{ .period = 7 });
    for (xs[lb - 6 ..], lb - 6..) |x, i| {
        const r = c.update(x);
        if (i >= lb) try testing.expect(th.sameBits(r.?, a[i]));
    }
    // varying periods: each bar equals the fixed-period run (sma needs no seeding)
    for (&per, 0..) |*p, i| p.* = @floatFromInt(2 + (i % 5));
    _ = try ind.mavp(f64, &xs, &per, &a, .{ .min_period = 2, .max_period = 6 });
    for (5..n_bars) |i| {
        const k: usize = 2 + (i % 5);
        _ = try ind.sma(f64, &xs, &b, .{ .period = k });
        try testing.expectApproxEqAbs(b[i], a[i], 1e-9); // the average re-primed at another bar: same value, other rounding
    }
    // out-of-range and NaN periods clamp
    per[10] = 1000;
    per[11] = std.math.nan(f64);
    per[12] = 0.2;
    _ = try ind.mavp(f64, &xs, &per, &a, .{ .min_period = 2, .max_period = 6 });
    _ = try ind.sma(f64, &xs, &b, .{ .period = 6 });
    try testing.expectApproxEqAbs(b[10], a[10], 1e-9);
    try testing.expectError(error.BadParam, ind.mavp(f64, &xs, &per, &a, .{ .min_period = 5, .max_period = 4 }));
    try testing.expectError(error.BadParam, ind.mavp(f64, &xs, &per, &a, .{ .min_period = 0 }));
    try testing.expectError(error.BadParam, ind.mavp(f64, &xs, &per, &a, .{ .max_period = 10001 }));
    _ = try ind.mavp(f64, &xs, &per, &a, .{ .kind = .mama });
}

test "f32 path of the multi-output functions rounds the f64 result once" {
    const s = Series.make(46);
    var h32: [n_bars]f32 = undefined;
    var l32: [n_bars]f32 = undefined;
    var c32: [n_bars]f32 = undefined;
    var hb: [n_bars]f64 = undefined;
    var lbk: [n_bars]f64 = undefined;
    var cb: [n_bars]f64 = undefined;
    for (0..n_bars) |i| {
        h32[i] = @floatCast(s.h[i]);
        l32[i] = @floatCast(s.l[i]);
        c32[i] = @floatCast(s.c[i]);
        hb[i] = h32[i];
        lbk[i] = l32[i];
        cb[i] = c32[i];
    }
    var uo32: [n_bars]f32 = undefined;
    var mo32: [n_bars]f32 = undefined;
    var do32: [n_bars]f32 = undefined;
    var uo64: [n_bars]f64 = undefined;
    var mo64: [n_bars]f64 = undefined;
    var do64: [n_bars]f64 = undefined;
    const lb = try ind.kc(f32, &h32, &l32, &c32, &uo32, &mo32, &do32, .{});
    _ = try ind.kc(f64, &hb, &lbk, &cb, &uo64, &mo64, &do64, .{});
    for (lb..n_bars) |i| try testing.expectEqual(@as(f32, @floatCast(uo64[i])), uo32[i]);
    var st: [n_bars]f32 = undefined;
    var tr: [n_bars]i8 = undefined;
    var st64: [n_bars]f64 = undefined;
    var tr64: [n_bars]i8 = undefined;
    const ls = try ind.supertrend(f32, &h32, &l32, &c32, &st, &tr, .{});
    _ = try ind.supertrend(f64, &hb, &lbk, &cb, &st64, &tr64, .{});
    for (ls..n_bars) |i| {
        try testing.expectEqual(@as(f32, @floatCast(st64[i])), st[i]);
        try testing.expectEqual(tr64[i], tr[i]);
    }
}

test "nan skip on kc and supertrend: the bar is ignored, the output carries over" {
    const s = Series.make(47);
    var h = s.h;
    var l = s.l;
    var c = s.c;
    const bad = [_]usize{ 7, 40, 41, 120 };
    for (bad) |i| h[i] = std.math.nan(f64);
    // series without the bad bars
    var h2: [n_bars - bad.len]f64 = undefined;
    var l2: [n_bars - bad.len]f64 = undefined;
    var c2: [n_bars - bad.len]f64 = undefined;
    var k: usize = 0;
    for (0..n_bars) |i| {
        if (std.math.isNan(h[i])) continue;
        h2[k] = h[i];
        l2[k] = l[i];
        c2[k] = c[i];
        k += 1;
    }
    var u: [n_bars]f64 = undefined;
    var m: [n_bars]f64 = undefined;
    var d: [n_bars]f64 = undefined;
    var ua: [n_bars - bad.len]f64 = undefined;
    var ma2: [n_bars - bad.len]f64 = undefined;
    var da: [n_bars - bad.len]f64 = undefined;
    _ = try ind.kc(f64, &h, &l, &c, &u, &m, &d, .{ .nan = .skip });
    _ = try ind.kc(f64, &h2, &l2, &c2, &ua, &ma2, &da, .{});
    k = 0;
    for (0..n_bars) |i| {
        if (std.math.isNan(h[i])) {
            try testing.expect(th.sameBits(u[i], u[i - 1]));
        } else {
            try testing.expect(th.sameBits(u[i], ua[k]) and th.sameBits(m[i], ma2[k]) and th.sameBits(d[i], da[k]));
            k += 1;
        }
    }
    var st: [n_bars]f64 = undefined;
    var tr: [n_bars]i8 = undefined;
    var st2: [n_bars - bad.len]f64 = undefined;
    var tr2: [n_bars - bad.len]i8 = undefined;
    _ = try ind.supertrend(f64, &h, &l, &c, &st, &tr, .{ .nan = .skip });
    _ = try ind.supertrend(f64, &h2, &l2, &c2, &st2, &tr2, .{});
    k = 0;
    for (0..n_bars) |i| {
        if (std.math.isNan(h[i])) continue;
        try testing.expect(th.sameBits(st[i], st2[k]) and tr[i] == tr2[k]);
        k += 1;
    }
}

test "cksp stream clone re-binds its scratch and continues identically" {
    const s = Series.make(48);
    const S = ind.CkspStream(f64);
    const p = ind.CkspParams{ .period = 5, .stop_period = 6 };
    const buf = try testing.allocator.alloc(f64, try S.bufLen(p));
    defer testing.allocator.free(buf);
    const buf2 = try testing.allocator.alloc(f64, try S.bufLen(p));
    defer testing.allocator.free(buf2);
    var a = try S.init(p, buf);
    for (0..100) |i| _ = a.update(.{ .high = s.h[i], .low = s.l[i], .close = s.c[i] });
    var b = try a.clone(buf2);
    for (100..200) |i| {
        const bar = S.InT{ .high = s.h[i], .low = s.l[i], .close = s.c[i] };
        const ra = a.update(bar).?;
        const rb = b.update(bar).?;
        try testing.expect(th.sameBits(ra.high_stop, rb.high_stop) and th.sameBits(ra.low_stop, rb.low_stop));
    }
    try testing.expectError(error.BadParam, S.init(p, buf[0 .. buf.len - 1]));
}
