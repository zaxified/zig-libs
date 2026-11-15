// SPDX-License-Identifier: MIT
//! Regression tests from the 2026-11-15 mutation audit: each pins a rule that a
//! surviving mutant showed no other test (nor the frozen TA-Lib vectors) observed.
//! The TA-Lib rule behind each is named in its test; the live oracle
//! (`zig build interop-indicators`) agrees with every one of them.

const std = @import("std");
const ind = @import("root.zig");
const th = @import("testhelp.zig");
const testing = std.testing;

const nan = std.math.nan(f64);
const inf = std.math.inf(f64);

/// Batch against a fresh stream, bit for bit (null == NaN).
fn expectStreamEqualsBatch(comptime S: type, s: *S, xs: []const f64, want: []const f64) !void {
    for (xs, want) |x, w| try testing.expect(th.sameOpt(s.update(x), w));
}

test "max / min: signed-zero ties, the streaming rescan keeps the oldest, the batch block scan the later suffix value" {
    // stream, period 3 over +0 -0 -5: the rescan of (+0, -0, -5) keeps the oldest of the equal pair: +0
    var buf: [3]f64 = undefined;
    var s = try ind.MaxStream(f64).init(.{ .period = 3 }, &buf);
    _ = s.update(0.0);
    _ = s.update(-0.0);
    const r = s.update(-5).?;
    try testing.expect(r == 0 and !std.math.signbit(r));
    // batch, period 3 over -0 +0 -1: the block's suffix scan runs backward and only a strictly greater value
    // replaces, so the later +0 stays
    const in = [_]f64{ -0.0, 0.0, -1 };
    var out: [3]f64 = undefined;
    _ = try ind.max(f64, &in, &out, .{ .period = 3 });
    try testing.expect(out[2] == 0 and !std.math.signbit(out[2]));
}

test "kama: exactly flat windows (efficiency ratio 1) agree between batch and stream on fractional prices" {
    // TA-Lib 0.8.x counts zero one-bar changes; `period` of them in a row reset the change sum. With
    // fractional prices the running sum keeps a rounding residue, so the reset is visible in the bits.
    // A one-bar spike of 1e9 before each flat stretch leaves a rounding residue of either sign in the change sum.
    var xs: [400]f64 = undefined;
    th.walk(&xs, 91);
    var i: usize = 20;
    while (i + 17 < xs.len) : (i += 41) {
        xs[i - 3] += 1e9;
        for (xs[i + 1 .. i + 17]) |*v| v.* = xs[i];
    }
    inline for (.{ 3, 5, 10 }) |p| {
        try th.checkOne(ind.KamaParams, ind.KamaStream, ind.kama, ind.kamaLookback, &xs, .{ .period = p });
    }
}

test "hma: WMA(2 WMA(x, p/2) - WMA(x, p), sqrt p), bit for bit, at odd periods (p/2 rounds down)" {
    var xs: [200]f64 = undefined;
    th.walk(&xs, 92);
    inline for (.{ 9, 15 }) |p| {
        const half = p / 2;
        const shift = p - half; // the half-period WMA is fed from here, so its first output lands on bar p - 1
        const s: usize = @intFromFloat(@floor(@sqrt(@as(f64, p))));
        var a: [200]f64 = undefined;
        var b: [200]f64 = undefined;
        var d: [200]f64 = undefined;
        var w: [200]f64 = undefined;
        var got: [200]f64 = undefined;
        _ = try ind.wma(f64, xs[shift..], a[0 .. xs.len - shift], .{ .period = half });
        _ = try ind.wma(f64, &xs, &b, .{ .period = p });
        const first = p - 1;
        for (first..xs.len) |k| d[k] = 2.0 * a[k - shift] - b[k];
        _ = try ind.wma(f64, d[first..], w[first..], .{ .period = s });
        const lb = try ind.hma(f64, &xs, &got, .{ .period = p });
        try testing.expectEqual(first + s - 1, lb);
        try th.expectSameBits(w[lb..], got[lb..]);
    }
}

test "mcgd: an update that would leave the finite numbers is dropped (a zero bar keeps the line)" {
    const in = [_]f64{ 10, 11, 12, 0, 13, 0, 14 };
    var out: [in.len]f64 = undefined;
    _ = try ind.mcgd(f64, &in, &out, .{ .period = 2 });
    for (out[1..]) |v| try testing.expect(std.math.isFinite(v));
    try testing.expect(th.sameBits(out[2], out[3]));
    try testing.expect(th.sameBits(out[4], out[5]));
}

test "macdext: slow < fast swaps the periods AND the MA types" {
    var xs: [120]f64 = undefined;
    th.walk(&xs, 93);
    var a1: [120]f64 = undefined;
    var s1: [120]f64 = undefined;
    var h1: [120]f64 = undefined;
    var a2: [120]f64 = undefined;
    var s2: [120]f64 = undefined;
    var h2: [120]f64 = undefined;
    const l1 = try ind.macdext(f64, testing.allocator, &xs, &a1, &s1, &h1, .{ .fast = 26, .fast_ma = .sma, .slow = 12, .slow_ma = .ema, .signal = 9, .signal_ma = .wma });
    const l2 = try ind.macdext(f64, testing.allocator, &xs, &a2, &s2, &h2, .{ .fast = 12, .fast_ma = .ema, .slow = 26, .slow_ma = .sma, .signal = 9, .signal_ma = .wma });
    try testing.expectEqual(l2, l1);
    try th.expectSameBits(&a2, &a1);
    try th.expectSameBits(&s2, &s1);
}

test "atr nan = skip: a NaN in the close alone also skips the bar" {
    var h: [80]f64 = undefined;
    var l: [80]f64 = undefined;
    var c: [80]f64 = undefined;
    th.walkBars(&h, &l, &c, 94);
    c[30] = nan;
    var out: [80]f64 = undefined;
    _ = try ind.atr(f64, &h, &l, &c, &out, .{ .period = 5, .nan = .skip });
    try testing.expect(th.sameBits(out[29], out[30]));
    for (out[31..]) |v| try testing.expect(!std.math.isNan(v));
    var st = try ind.AtrStream(f64).init(.{ .period = 5, .nan = .skip });
    for (h, l, c, out) |hh, ll, cc, w| try testing.expect(th.sameOpt(st.update(.{ .high = hh, .low = ll, .close = cc }), w));
}

test "apo, ao: swapped fast / slow periods" {
    var xs: [120]f64 = undefined;
    th.walk(&xs, 95);
    var o1: [120]f64 = undefined;
    var o2: [120]f64 = undefined;
    // APO: TA-Lib swaps the periods so the fast one is the shorter: the same output
    _ = try ind.apo(f64, &xs, &o1, .{ .fast = 26, .slow = 12 });
    _ = try ind.apo(f64, &xs, &o2, .{ .fast = 12, .slow = 26 });
    try th.expectSameBits(&o2, &o1);
    // AO is SMA(fast) - SMA(slow) of the median price as given: swapping negates it exactly
    var h: [120]f64 = undefined;
    var l: [120]f64 = undefined;
    var c: [120]f64 = undefined;
    th.walkBars(&h, &l, &c, 96);
    const lb = try ind.ao(f64, &h, &l, &o1, .{ .fast = 34, .slow = 5 });
    _ = try ind.ao(f64, &h, &l, &o2, .{ .fast = 5, .slow = 34 });
    for (o1[lb..], o2[lb..]) |a, b| try testing.expect(th.sameBits(a, -b));
}

test "ppo: a zero tail answers exactly 0 (windowed: the whole slow window is zero; EMA: the slow MA is ~0)" {
    var xs: [700]f64 = undefined;
    th.walk(&xs, 97);
    for (xs[60..]) |*v| v.* = 0.0;
    inline for (.{ ind.MaType.sma, ind.MaType.ema }) |k| {
        const p: ind.PpoParams = .{ .fast = 3, .slow = 7, .kind = k };
        var out: [700]f64 = undefined;
        _ = try ind.ppo(f64, &xs, &out, p);
        try testing.expectEqual(@as(f64, 0.0), out[699]);
        if (k == .sma) for (out[67..]) |v| try testing.expectEqual(@as(f64, 0.0), v);
        const buf = try testing.allocator.alloc(f64, try ind.PpoStream(f64).bufLen(p));
        defer testing.allocator.free(buf);
        var s = try ind.PpoStream(f64).init(p, buf);
        try expectStreamEqualsBatch(@TypeOf(s), &s, &xs, &out);
    }
}

test "tsi: a constant series has no momentum and answers 0, batch and stream" {
    const xs: [80]f64 = @splat(100.0);
    var out: [80]f64 = undefined;
    const lb = try ind.tsi(f64, &xs, &out, .{ .first = 5, .second = 3 });
    for (out[lb..]) |v| try testing.expectEqual(@as(f64, 0.0), v);
    var s = try ind.TsiStream(f64).init(.{ .first = 5, .second = 3 });
    try expectStreamEqualsBatch(@TypeOf(s), &s, &xs, &out);
}

test "zero prices: COPPOCK and ROCR100 answer 0 for a zero base, never NaN" {
    var xs: [60]f64 = undefined;
    th.walk(&xs, 98);
    xs[10] = 0.0;
    xs[30] = 0.0;
    var out: [60]f64 = undefined;
    const lb = try ind.coppock(f64, &xs, &out, .{ .wma = 2, .roc1 = 3, .roc2 = 4 });
    for (out[lb..]) |v| try testing.expect(std.math.isFinite(v));
    _ = try ind.rocr100(f64, &xs, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 0.0), out[12]);
    try testing.expectEqual(@as(f64, 0.0), out[32]);
}

test "willr: a close above the window's high is clamped to 0, a flat window answers 0" {
    const h = [_]f64{ 10, 10, 10, 11, 11 };
    const l = [_]f64{ 9, 9, 9, 10, 11 };
    const c = [_]f64{ 9.5, 9.5, 12, 10.5, 11 };
    var out: [5]f64 = undefined;
    _ = try ind.willr(f64, &h, &l, &c, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 0.0), out[2]); // close 12 above the highest high 10
    const fh = [_]f64{ 5, 5, 5 };
    var o2: [3]f64 = undefined;
    _ = try ind.willr(f64, &fh, &fh, &fh, &o2, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 0.0), o2[2]);
}

test "vwma: a zero-volume window answers NaN after fractional volumes (no rounding residue leaks)" {
    const xs = [_]f64{ 10.1, 10.3, 10.7, 11.9, 12.3, 12.1, 12.2, 13 };
    const v = [_]f64{ 0.1, 0.7, 0.3, 0, 0, 0, 1.3, 2 };
    var out: [8]f64 = undefined;
    _ = try ind.vwma(f64, &xs, &v, &out, .{ .period = 3 });
    try testing.expect(std.math.isNan(out[5]));
    try testing.expect(!std.math.isNan(out[6]));
}

test "kc nan = skip: the stream answers the last output on a skipped bar" {
    var h: [60]f64 = undefined;
    var l: [60]f64 = undefined;
    var c: [60]f64 = undefined;
    th.walkBars(&h, &l, &c, 99);
    const p: ind.KcParams = .{ .period = 5, .atr_period = 3, .nan = .skip };
    const buf = try testing.allocator.alloc(f64, try ind.KcStream(f64).bufLen(p));
    defer testing.allocator.free(buf);
    var s = try ind.KcStream(f64).init(p, buf);
    var last: ?f64 = null;
    for (h, l, c) |hh, ll, cc| last = (s.update(.{ .high = hh, .low = ll, .close = cc }) orelse continue).upper;
    const pk = s.peek(.{ .high = nan, .low = 1, .close = 1 }).?;
    try testing.expect(th.sameBits(last.?, pk.upper));
    const r = s.update(.{ .high = nan, .low = 1, .close = 1 }).?;
    try testing.expect(th.sameBits(last.?, r.upper));
}

test "accbands: a bar with high = -low (sum ~0) contributes high and low unscaled" {
    const h = [_]f64{ 1, 2, 3, 4 };
    const l = [_]f64{ -1, -2, -3, -4 };
    const c = [_]f64{ 0, 0, 0, 0 };
    var u: [4]f64 = undefined;
    var m: [4]f64 = undefined;
    var d: [4]f64 = undefined;
    _ = try ind.accbands(f64, &h, &l, &c, &u, &m, &d, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 3.5), u[3]);
    try testing.expectEqual(@as(f64, -3.5), d[3]);
}

test "plus_dm: an up-move equal to the down-move counts as no directional move" {
    // every bar widens by 1 on both sides: diff+ == diff- == 1, so +DM is 0 throughout
    var h: [30]f64 = undefined;
    var l: [30]f64 = undefined;
    for (&h, &l, 0..) |*a, *b, i| {
        a.* = 100.0 + @as(f64, @floatFromInt(i));
        b.* = 50.0 - @as(f64, @floatFromInt(i));
    }
    var out: [30]f64 = undefined;
    const lb = try ind.plusDm(f64, &h, &l, &out, .{ .period = 4 });
    for (out[lb..]) |v| try testing.expectEqual(@as(f64, 0.0), v);
}

test "bbw / percentb are the bands BBANDS answers, bit for bit (equal and unequal deviations)" {
    // With equal deviations both compute `mid +- dev*sd` unfused, with unequal ones the upper band is
    // `fma(sd, dev, mid)`; the two forms differ in the last bit on many bars, so each side pins the other.
    var xs: [200]f64 = undefined;
    th.walk(&xs, 100);
    var u: [200]f64 = undefined;
    var m: [200]f64 = undefined;
    var l: [200]f64 = undefined;
    var w: [200]f64 = undefined;
    var pb: [200]f64 = undefined;
    inline for (.{ [2]f64{ 1.7, 1.7 }, [2]f64{ 1.7, 2.3 } }) |dv| {
        const p: ind.BbandsParams = .{ .period = 7, .dev_up = dv[0], .dev_dn = dv[1] };
        const lb = try ind.bbands(f64, &xs, &u, &m, &l, p);
        _ = try ind.bbw(f64, &xs, &w, p);
        _ = try ind.percentb(f64, &xs, &pb, p);
        for (lb..xs.len) |k| {
            try testing.expect(th.sameBits(w[k], (u[k] - l[k]) / m[k] * 100.0));
            try testing.expect(th.sameBits(pb[k], (xs[k] - l[k]) / (u[k] - l[k])));
        }
    }
}

test "cdlhikkake: the confirmation window is the three bars after the pattern, and the pre-warm keeps its state" {
    const B = struct { o: f64, h: f64, l: f64, c: f64 };
    const flat: B = .{ .o = 9.5, .h = 10, .l = 9, .c = 9.5 };
    const mother: B = .{ .o = 10, .h = 12, .l = 8, .c = 10 };
    const inside: B = .{ .o = 10, .h = 11, .l = 9, .c = 10 };
    const down: B = .{ .o = 10, .h = 10.5, .l = 8.5, .c = 10 }; // lower high and lower low: bullish hikkake
    const n1: B = .{ .o = 10, .h = 10.4, .l = 8.6, .c = 10 };
    const n2: B = .{ .o = 10, .h = 10.45, .l = 8.55, .c = 10 };
    const n3: B = .{ .o = 10, .h = 10.5, .l = 8.5, .c = 10 };
    const up: B = .{ .o = 10, .h = 11.6, .l = 10, .c = 11.5 }; // closes above the inside bar's high
    const cases = [_]struct { bars: []const B, at: usize, want: i32 }{
        // pattern at bar 8, confirmed on the third bar after it
        .{ .bars = &.{ flat, flat, flat, flat, flat, flat, mother, inside, down, n1, n2, up }, .at = 11, .want = 200 },
        // ... but not on the fourth
        .{ .bars = &.{ flat, flat, flat, flat, flat, flat, mother, inside, down, n1, n2, n3, up }, .at = 12, .want = 0 },
        // pattern at bar 4, inside the pre-warm (lookback 5): its confirmation at bar 5 still counts
        .{ .bars = &.{ flat, flat, mother, inside, down, up }, .at = 5, .want = 200 },
    };
    for (cases) |cs| {
        var o: [16]f64 = undefined;
        var h: [16]f64 = undefined;
        var l: [16]f64 = undefined;
        var c: [16]f64 = undefined;
        var out: [16]i32 = undefined;
        const n = cs.bars.len;
        for (cs.bars, 0..) |b, i| {
            o[i] = b.o;
            h[i] = b.h;
            l[i] = b.l;
            c[i] = b.c;
        }
        try testing.expectEqual(@as(usize, 5), try ind.candles.cdlhikkake(f64, o[0..n], h[0..n], l[0..n], c[0..n], out[0..n], .{}));
        try testing.expectEqual(cs.want, out[cs.at]);
    }
}

test "auto unstable levels: the lookbacks TA-Lib answers (KAMA, RMA, VIDYA, PLUS_DI)" {
    // KAMA: 25 * {4, 8} * isqrt(period); RMA: (k (2p - 1) + 1) / 2, k = 10, 19; VIDYA: 2 * {4, 8} * (p + 1) * isqrt(cmo);
    // PLUS_DI: {10, 19} * p. Checked live against TA_*_Lookback by `interop-indicators`.
    try testing.expectEqual(@as(usize, 30 + 500), try ind.kamaLookback(.{ .period = 30, .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 30 + 1000), try ind.kamaLookback(.{ .period = 30, .unstable = .auto8 }));
    try testing.expectEqual(@as(usize, 13 + 135), try ind.rmaLookback(.{ .period = 14, .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 13 + 257), try ind.rmaLookback(.{ .period = 14, .unstable = .auto8 }));
    try testing.expectEqual(@as(usize, 9 + 312), try ind.vidyaLookback(.{ .period = 12, .cmo_period = 9, .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 9 + 624), try ind.vidyaLookback(.{ .period = 12, .cmo_period = 9, .unstable = .auto8 }));
    try testing.expectEqual(@as(usize, 14 + 140), try ind.plusDiLookback(.{ .period = 14, .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 14 + 266), try ind.plusDiLookback(.{ .period = 14, .unstable = .auto8 }));
}

/// A fractional walk whose tail from `flat_from` holds its value; bar `spike` (when below `flat_from - 1`)
/// jumps by 1e9 for one bar, so the running change sums keep a rounding residue of either sign.
fn walkThenFlat(xs: []f64, seed: u64, flat_from: usize, spike: usize) void {
    th.walk(xs, seed);
    if (spike + 1 < flat_from) xs[spike] += 1e9;
    for (xs[flat_from..]) |*v| v.* = xs[flat_from - 1];
}

test "kama: `period` exactly-zero changes in a row make the efficiency ratio 1, from the first window on" {
    // TA-Lib 0.8.x counts the zero changes from the first window: with k of them at its end, the ratio is 1 from
    // bar period + (period - k) on, whatever rounding residue the change sum keeps.
    const kmax: f64 = 2.0 / 31.0;
    const two_thirds: f64 = 2.0 / 3.0;
    const sc1 = @mulAdd(f64, 1.0, two_thirds - kmax, kmax);
    var xs: [80]f64 = undefined;
    var out: [80]f64 = undefined;
    inline for (.{ 4, 7 }) |p| {
        for (1..p) |k| {
            for (0..12) |seed| {
                walkThenFlat(&xs, 300 + seed, p + 1 - k, 1);
                _ = try ind.kama(f64, &xs, &out, .{ .period = p });
                for (2 * p - k..xs.len) |n| {
                    const want = @mulAdd(f64, xs[n] - out[n - 1], sc1 * sc1, out[n - 1]);
                    try testing.expect(th.sameBits(want, out[n]));
                }
            }
        }
    }
}

test "vidya: `cmo_period` exactly-zero changes in a row stop the line (k = 0), residue or not" {
    var xs: [120]f64 = undefined;
    var out: [120]f64 = undefined;
    for (0..24) |seed| {
        walkThenFlat(&xs, 400 + seed, 40, 30);
        _ = try ind.vidya(f64, &xs, &out, .{ .period = 6, .cmo_period = 5 });
        // the 5th zero change is the one of bar 44: from there the output repeats
        for (44..xs.len) |n| try testing.expect(th.sameBits(out[n - 1], out[n]));
    }
}

test "mcgd: the update divides by period * (r^2 * r^2), r = x / md, in this order (TA-Lib's bits)" {
    // prices swinging by up to +-70%: x / md far from 1, where the product order shows in the last bit
    var xs: [300]f64 = undefined;
    for (&xs, 0..) |*x, i| x.* = 100.0 * (1.0 + 0.7 * @sin(@as(f64, @floatFromInt(i)) * 1.3));
    var out: [300]f64 = undefined;
    _ = try ind.mcgd(f64, &xs, &out, .{ .period = 10 });
    var md = xs[0];
    for (xs[1..], out[1..], 1..) |x, got, i| {
        const r = x / md;
        md = md + (x - md) / (10.0 * (r * r * (r * r)));
        if (i >= 9) try testing.expect(th.sameBits(md, got));
    }
}

test "flat and zero-volume windows answer TA-Lib's neutral values, never NaN (MFI, CMOU, VORTEX, VHF, CHOP, CMF, DX)" {
    const n = 60;
    var h: [n]f64 = undefined;
    var l: [n]f64 = undefined;
    var c: [n]f64 = undefined;
    var v: [n]f64 = undefined;
    var o: [n]f64 = undefined;
    var o2: [n]f64 = undefined;
    // MFI: zero-volume bars `period` in a row reset the money-flow sums: 0 from there on
    th.walkBars(&h, &l, &c, 102);
    for (&v, 0..) |*x, i| x.* = if (i < 30) 0.37 + 0.11 * @as(f64, @floatFromInt(i % 5)) else 0.0;
    _ = try ind.mfi(f64, &h, &l, &c, &v, &o, .{ .period = 5 });
    for (o[35..]) |x| try testing.expectEqual(@as(f64, 0.0), x);
    // CMOU: `period` zero changes in a row answer 0
    var xs: [n]f64 = undefined;
    walkThenFlat(&xs, 103, 30, 20);
    _ = try ind.cmou(f64, &xs, &o, .{ .period = 5 });
    for (o[36..]) |x| try testing.expectEqual(@as(f64, 0.0), x);
    // VHF on a constant series, VORTEX and DX on constant bars: no change, no range
    const k: [n]f64 = @splat(10.0);
    _ = try ind.vhf(f64, &k, &o, .{ .period = 5 });
    for (o[5..]) |x| try testing.expectEqual(@as(f64, 0.0), x);
    _ = try ind.vortex(f64, &k, &k, &k, &o, &o2, .{ .period = 5 });
    for (o[5..], o2[5..]) |a, b| try testing.expect(a == 0.0 and b == 0.0);
    const hi: [n]f64 = @splat(11.0);
    const lo: [n]f64 = @splat(9.0);
    const dlb = try ind.dx(f64, &hi, &lo, &k, &o, .{ .period = 5 });
    for (o[dlb..]) |x| try testing.expectEqual(@as(f64, 0.0), x);
    // CHOP: a window without a high-low range answers 100 even when the closes give it a true range
    const cl: [n]f64 = @splat(11.0);
    const clb = try ind.chop(f64, &k, &k, &cl, &o, .{ .period = 5 });
    for (o[clb..]) |x| try testing.expectEqual(@as(f64, 100.0), x);
    // CMF over zero volumes from the first bar: 0
    const zv: [n]f64 = @splat(0.0);
    const flb = try ind.cmf(f64, &hi, &lo, &k, &zv, &o, .{ .period = 3 });
    for (o[flb..]) |x| try testing.expectEqual(@as(f64, 0.0), x);
}

test "er: a monotone fall has efficiency ratio 1 at most (clamped against the rounding of the change sum)" {
    var xs: [300]f64 = undefined;
    var o: [300]f64 = undefined;
    var prng = std.Random.DefaultPrng.init(104);
    const r = prng.random();
    for (0..40) |_| {
        // steps of mixed magnitude (1e-3 .. 1e5): the change sum rounds differently from the net change
        var x: f64 = 1e7;
        for (&xs) |*d| {
            x -= std.math.pow(f64, 10.0, r.float(f64) * 8.0 - 3.0);
            d.* = x;
        }
        const lb = try ind.er(f64, &xs, &o, .{ .period = 7 });
        for (o[lb..]) |e| try testing.expect(@abs(e) <= 1.0);
    }
}

test "fisher: the smoothed value is clamped to 0.999 past 0.99, so a steady rise settles at ln(1999)" {
    var hs: [300]f64 = undefined;
    for (&hs, 0..) |*d, i| d.* = 100.0 + @as(f64, @floatFromInt(i));
    var f: [300]f64 = undefined;
    var t: [300]f64 = undefined;
    _ = try ind.fisher(f64, &hs, &hs, &f, &t, .{ .period = 10 });
    try testing.expectApproxEqAbs(@log(@as(f64, 1999.0)), f[299], 1e-9);
}

test "wavetrend: a flat tail whose EMA has settled contributes no momentum (wt1 decays to 0)" {
    var h: [700]f64 = undefined;
    var l: [700]f64 = undefined;
    var c: [700]f64 = undefined;
    th.walkBars(&h, &l, &c, 105);
    for (100..700) |i| {
        h[i] = 100.37;
        l[i] = 100.37;
        c[i] = 100.37;
    }
    var w1: [700]f64 = undefined;
    var w2: [700]f64 = undefined;
    _ = try ind.wavetrend(f64, testing.allocator, &h, &l, &c, &w1, &w2, .{});
    try testing.expect(@abs(w1[699]) < 1e-3);
}

test "kurtosis: the running sums are rebuilt every 32 * period bars (a long run at the shortest period)" {
    // a steady alternation: the moments never drop below their peaks, only the bar counter re-anchors
    var xs: [400]f64 = undefined;
    for (&xs, 0..) |*x, i| x.* = 100.0 + @as(f64, @floatFromInt(i % 2)) * 1.37 + @as(f64, @floatFromInt(i % 3)) * 0.11;
    var o: [400]f64 = undefined;
    const lb = try ind.kurtosis(f64, &xs, &o, .{ .period = 4 });
    for (o[lb..]) |x| try testing.expect(std.math.isFinite(x));
}

test "tanh is the module's fdlibm-formula tanh (what TA-Lib's libm answers), not std.math.tanh" {
    const xmath = @import("xmath.zig");
    var xs: [4000]f64 = undefined;
    var prng = std.Random.DefaultPrng.init(107);
    for (&xs) |*x| x.* = (prng.random().float(f64) - 0.5) * 6.0;
    var o: [4000]f64 = undefined;
    _ = try ind.tanh(f64, &xs, &o);
    for (xs, o) |x, y| try testing.expect(th.sameBits(xmath.tanh(x), y));
}

const Cdl = struct { o: f64, h: f64, l: f64, c: f64 };

fn cdlRun(comptime f: anytype, bars: []const Cdl, settings: ind.candles.CandleSettings) !i32 {
    var o: [8]f64 = undefined;
    var h: [8]f64 = undefined;
    var l: [8]f64 = undefined;
    var c: [8]f64 = undefined;
    var out: [8]i32 = undefined;
    const n = bars.len;
    for (bars, 0..) |b, i| {
        o[i] = b.o;
        h[i] = b.h;
        l[i] = b.l;
        c[i] = b.c;
    }
    _ = try f(f64, o[0..n], h[0..n], l[0..n], c[0..n], out[0..n], .{ .settings = settings });
    return out[n - 1];
}

fn bar(o: f64, c: f64) Cdl {
    return .{ .o = o, .h = @max(o, c) + 0.1, .l = @min(o, c) - 0.1, .c = c };
}

test "candle patterns: each condition of 2CROWS, 3INSIDE, MORNINGSTAR, PIERCING and MATHOLD is load-bearing" {
    // Averages over 0 bars are the bar's own range times the factor: the body tests become plain ratios.
    var s: ind.candles.CandleSettings = .default;
    s.body_long = .{ .range = .real_body, .avg_period = 0, .factor = 0.5 };
    s.body_short = .{ .range = .real_body, .avg_period = 0, .factor = 2.0 };
    const C = ind.candles;
    // 2CROWS: the third black candle must open below the second's open
    try testing.expectEqual(@as(i32, -100), try cdlRun(C.cdl2crows, &.{ bar(10, 12), bar(14, 13), bar(13.5, 11) }, s));
    try testing.expectEqual(@as(i32, 0), try cdlRun(C.cdl2crows, &.{ bar(10, 12), bar(14, 13), bar(14.5, 11) }, s));
    // 3INSIDE: the inside body must be short (here: not above half its own size)
    var s3 = s;
    s3.body_short.factor = 0.5;
    try testing.expectEqual(@as(i32, -100), try cdlRun(C.cdl3inside, &.{ bar(10, 14), bar(12.5, 11.5), bar(12, 9) }, s));
    try testing.expectEqual(@as(i32, 0), try cdlRun(C.cdl3inside, &.{ bar(10, 14), bar(12.5, 11.5), bar(12, 9) }, s3));
    // MORNINGSTAR: the white candle must close above c2 + body2 * penetration; short bodies against the
    // previous bar's body (period 1)
    var sm = s;
    sm.body_short = .{ .range = .real_body, .avg_period = 1, .factor = 1.0 };
    const star = [_]Cdl{ bar(5, 5.5), bar(20, 10), bar(8, 8.5) };
    try testing.expectEqual(@as(i32, 100), try cdlRun(C.cdlmorningstar, &(star ++ [_]Cdl{bar(9, 14)}), sm));
    try testing.expectEqual(@as(i32, 0), try cdlRun(C.cdlmorningstar, &(star ++ [_]Cdl{bar(9, 12)}), sm));
    // PIERCING: the white candle must close above the black body's midpoint
    try testing.expectEqual(@as(i32, 100), try cdlRun(C.cdlpiercing, &.{ bar(20, 10), bar(9, 16) }, s));
    try testing.expectEqual(@as(i32, 0), try cdlRun(C.cdlpiercing, &.{ bar(20, 10), bar(9, 14) }, s));
    // MATHOLD: the reaction candles must stay above c4 - body4 * penetration
    const m4 = bar(10, 20);
    const m3 = bar(23, 22);
    const m1 = bar(19, 18.5);
    const m0 = Cdl{ .o = 18.6, .h = 24.1, .l = 18.5, .c = 24 };
    try testing.expectEqual(@as(i32, 100), try cdlRun(C.cdlmathold, &.{ m4, m3, bar(19.5, 19), m1, m0 }, s));
    try testing.expectEqual(@as(i32, 0), try cdlRun(C.cdlmathold, &.{ m4, m3, bar(19.5, 14), m1, m0 }, s));
}

test "trix period 1: the steady batch path copies like the stream (an inf input does not turn into NaN)" {
    const xs = [_]f64{ 1, 2, inf, 3, 4, 5, -0.0, 6 };
    var out: [xs.len]f64 = undefined;
    _ = try ind.trix(f64, &xs, &out, .{ .period = 1 });
    var s = try ind.TrixStream(f64).init(.{ .period = 1 });
    try expectStreamEqualsBatch(@TypeOf(s), &s, &xs, &out);
}
