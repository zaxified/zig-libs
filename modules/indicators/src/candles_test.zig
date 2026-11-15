// SPDX-License-Identifier: MIT
//! Tests of the candlestick patterns: batch == streaming for all 61 (default
//! and tweaked settings, f64 and f32), lookbacks, BadParam, hand-built bars for
//! the stateful HIKKAKE and the +-80 forms, and a check that the settings are
//! honoured. The numbers themselves are checked against TA-Lib by the oracle.

const std = @import("std");
const testing = std.testing;
const th = @import("testhelp.zig");
const candles = @import("candles.zig");
const cc = @import("candles_core.zig");

const n_bars = 600;

fn tweaked() cc.CandleSettings {
    var s = cc.CandleSettings.default;
    s.body_long = .{ .range = .high_low, .avg_period = 4, .factor = 0.9 };
    s.body_short = .{ .range = .real_body, .avg_period = 3, .factor = 1.3 };
    s.body_doji = .{ .range = .real_body, .avg_period = 2, .factor = 0.2 };
    s.shadow_long = .{ .range = .shadows, .avg_period = 3, .factor = 0.7 };
    s.shadow_very_short = .{ .range = .real_body, .avg_period = 6, .factor = 0.3 };
    s.near = .{ .range = .shadows, .avg_period = 2, .factor = 0.5 };
    s.equal = .{ .range = .high_low, .avg_period = 0, .factor = 0.1 };
    s.far = .{ .range = .real_body, .avg_period = 7, .factor = 0.8 };
    return s;
}

fn checkPattern(comptime P: type, comptime T: type, s: cc.CandleSettings, seed: u64) !void {
    const O = cc.Op(P);
    const a = testing.allocator;
    const os = try a.alloc(f64, n_bars);
    defer a.free(os);
    const hs = try a.alloc(f64, n_bars);
    defer a.free(hs);
    const ls = try a.alloc(f64, n_bars);
    defer a.free(ls);
    const cs = try a.alloc(f64, n_bars);
    defer a.free(cs);
    th.candleBars(os, hs, ls, cs, seed);
    const ot = try a.alloc(T, n_bars);
    defer a.free(ot);
    const ht = try a.alloc(T, n_bars);
    defer a.free(ht);
    const lt = try a.alloc(T, n_bars);
    defer a.free(lt);
    const ct = try a.alloc(T, n_bars);
    defer a.free(ct);
    for (0..n_bars) |i| {
        ot[i] = @floatCast(os[i]);
        ht[i] = @floatCast(hs[i]);
        lt[i] = @floatCast(ls[i]);
        ct[i] = @floatCast(cs[i]);
    }
    const out = try a.alloc(i32, n_bars);
    defer a.free(out);
    const p: O.Params = .{ .settings = s };
    const lb = try O.run(T, ot, ht, lt, ct, out, p);
    try testing.expectEqual(try O.lookback(p), lb);
    for (out[0..lb]) |v| try testing.expectEqual(@as(i32, 0), v);
    const S = O.Stream(T);
    const buf = try a.alloc(cc.Bar, try S.bufLen(p));
    defer a.free(buf);
    var st = try S.init(p, buf);
    const buf2 = try a.alloc(cc.Bar, buf.len);
    defer a.free(buf2);
    var cl: ?S = null;
    for (0..n_bars) |i| {
        const pk = st.peek(ot[i], ht[i], lt[i], ct[i]);
        const got = st.update(ot[i], ht[i], lt[i], ct[i]);
        try testing.expectEqual(pk, got);
        if (i < lb) {
            try testing.expect(got == null);
        } else {
            try testing.expectEqual(out[i], got.?);
            try testing.expectEqual(out[i], st.value().?);
        }
        if (i == n_bars / 2) cl = try st.clone(buf2);
    }
    // a clone taken mid-stream continues identically
    var c2 = cl.?;
    for (n_bars / 2 + 1..n_bars) |i| {
        try testing.expectEqual(@as(?i32, out[i]), c2.update(ot[i], ht[i], lt[i], ct[i]));
    }
}

test "all patterns: batch == streaming == peek, lead zero (default settings, f64)" {
    @setEvalBranchQuota(2_000_000);
    inline for (candles.all, 0..) |P, k| try checkPattern(P, f64, .default, 100 + k);
}

test "all patterns: batch == streaming (tweaked settings, f64 and f32)" {
    @setEvalBranchQuota(2_000_000);
    inline for (candles.all, 0..) |P, k| {
        try checkPattern(P, f64, tweaked(), 200 + k);
        try checkPattern(P, f32, tweaked(), 300 + k);
    }
}

test "lookbacks follow TA-Lib" {
    const d: cc.CandleSettings = .default;
    try testing.expectEqual(@as(usize, 12), try candles.cdl2crowsLookback(.{ .settings = d }));
    try testing.expectEqual(@as(usize, 10), try candles.cdldojiLookback(.{}));
    try testing.expectEqual(@as(usize, 2), try candles.cdlengulfingLookback(.{}));
    try testing.expectEqual(@as(usize, 3), try candles.cdl3outsideLookback(.{}));
    try testing.expectEqual(@as(usize, 5), try candles.cdlhikkakeLookback(.{}));
    try testing.expectEqual(@as(usize, 10), try candles.cdlhikkakemodLookback(.{}));
    try testing.expectEqual(@as(usize, 14), try candles.cdlmatholdLookback(.{}));
    try testing.expectEqual(@as(usize, 12), try candles.cdlabandonedbabyLookback(.{}));
    try testing.expectEqual(@as(usize, 15), try candles.cdlhikkakemodLookback(.{ .settings = .{ .near = .{ .range = .high_low, .avg_period = 10, .factor = 0.2 } } }));
    try testing.expectEqual(@as(usize, 6), try candles.cdlhikkakemodLookback(.{ .settings = .{ .near = .{ .range = .high_low, .avg_period = 0, .factor = 0.2 } } }));
}

test "BadParam: settings and penetration out of range, length mismatch" {
    var s = cc.CandleSettings.default;
    s.near.factor = -1.0;
    try testing.expectError(error.BadParam, candles.cdl2crowsLookback(.{ .settings = s }));
    s = .default;
    s.body_long.factor = std.math.nan(f64);
    try testing.expectError(error.BadParam, candles.cdldojiLookback(.{ .settings = s }));
    s = .default;
    s.body_doji.avg_period = 100001;
    try testing.expectError(error.BadParam, candles.cdldojiLookback(.{ .settings = s }));
    try testing.expectError(error.BadParam, candles.cdleveningstarLookback(.{ .penetration = -0.1 }));
    try testing.expectError(error.BadParam, candles.cdleveningstarLookback(.{ .penetration = 3.1e37 }));
    _ = try candles.cdleveningstarLookback(.{ .penetration = 0.0 });
    var out: [4]i32 = undefined;
    const x = [_]f64{ 1, 2, 3, 4 };
    try testing.expectError(error.BadParam, candles.cdldoji(f64, &x, &x, &x, x[0..3], &out, .{}));
    try testing.expectError(error.BadParam, candles.cdldoji(f64, &x, &x, &x, &x, out[0..3], .{}));
}

test "DOJI: a flat-bodied bar among normal ones" {
    var o: [14]f64 = undefined;
    var h: [14]f64 = undefined;
    var l: [14]f64 = undefined;
    var c: [14]f64 = undefined;
    for (0..14) |i| {
        o[i] = 10.0;
        c[i] = 11.0;
        h[i] = 12.0;
        l[i] = 9.0;
    }
    c[12] = 10.0; // open == close
    var out: [14]i32 = undefined;
    const lb = try candles.cdldoji(f64, &o, &h, &l, &c, &out, .{});
    try testing.expectEqual(@as(usize, 10), lb);
    for (out, 0..) |v, i| try testing.expectEqual(@as(i32, if (i == 12) 100 else 0), v);
}

test "ENGULFING: 100 when both ends engulf, 80 when an end touches" {
    // black (open 10, close 9), then white (open 8.5, close 10.5): engulfs on both sides
    const o = [_]f64{ 10.0, 8.5, 10.0, 9.0 };
    const c = [_]f64{ 9.0, 10.5, 9.0, 10.5 };
    const h = [_]f64{ 10.5, 11.0, 10.5, 11.0 };
    const l = [_]f64{ 8.5, 8.0, 8.5, 8.5 };
    var out: [4]i32 = undefined;
    _ = try candles.cdlengulfing(f64, &o, &h, &l, &c, &out, .{});
    // lookback is 2: bar 2 is the black (10 -> 9) after a white: bearish engulfing needs open >= prev close and close < prev open
    try testing.expectEqual(@as(i32, 0), out[1]);
    // bar 2 (black 10 -> 9) vs bar 1 (white 8.5 -> 10.5): open 10 < 10.5 -> no
    try testing.expectEqual(@as(i32, 0), out[2]);
    // bar 3 (white 9 -> 10.5) vs bar 2 (black 10 -> 9): close 10.5 > open 10 and open 9 <= close 9: touches -> 80
    try testing.expectEqual(@as(i32, 80), out[3]);
}

test "HIKKAKE: signal, then +-200 on confirmation within three bars" {
    var o: [8]f64 = undefined;
    var h: [8]f64 = undefined;
    var l: [8]f64 = undefined;
    var c: [8]f64 = undefined;
    for (0..8) |i| {
        o[i] = 7.0;
        c[i] = 7.0;
        h[i] = 20.0;
        l[i] = 0.0;
    }
    h[3] = 10.0;
    l[3] = 5.0;
    h[4] = 9.0; // inside bar
    l[4] = 6.0;
    h[5] = 8.5; // lower high and lower low: bullish hikkake
    l[5] = 5.5;
    c[6] = 9.5; // closes above the inside bar's high
    h[6] = 10.0;
    l[6] = 6.0;
    var out: [8]i32 = undefined;
    const lb = try candles.cdlhikkake(f64, &o, &h, &l, &c, &out, .{});
    try testing.expectEqual(@as(usize, 5), lb);
    try testing.expectEqual(@as(i32, 100), out[5]);
    try testing.expectEqual(@as(i32, 200), out[6]);
    try testing.expectEqual(@as(i32, 0), out[7]);
}

test "settings are honoured: a stricter doji threshold removes the doji" {
    var o: [14]f64 = undefined;
    var h: [14]f64 = undefined;
    var l: [14]f64 = undefined;
    var c: [14]f64 = undefined;
    for (0..14) |i| {
        o[i] = 10.0;
        c[i] = 11.0;
        h[i] = 12.0;
        l[i] = 9.0;
    }
    c[12] = 10.1; // body 0.1 of range 3: doji at factor 0.1 (0.3), not at 0.02 (0.06)
    var out: [14]i32 = undefined;
    _ = try candles.cdldoji(f64, &o, &h, &l, &c, &out, .{});
    try testing.expectEqual(@as(i32, 100), out[12]);
    var s = cc.CandleSettings.default;
    s.body_doji.factor = 0.02;
    _ = try candles.cdldoji(f64, &o, &h, &l, &c, &out, .{ .settings = s });
    try testing.expectEqual(@as(i32, 0), out[12]);
    // a shorter averaging period moves the lookback
    s = .default;
    s.body_doji.avg_period = 3;
    const lb = try candles.cdldoji(f64, &o, &h, &l, &c, &out, .{ .settings = s });
    try testing.expectEqual(@as(usize, 3), lb);
}
