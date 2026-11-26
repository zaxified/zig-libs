// SPDX-License-Identifier: MIT

//! Killing tests of the 2026-11-25 delta mutation run over the w17-a batch work
//! (vmath, cksp, fisher / pso, chop, ultosc, the cci two-bar pass, wavetrend /
//! stc / rvi steady paths): each pins a boundary, a guard or a rule the existing
//! bit-for-bit tests left to luck. The threshold sweep compares every four-lane
//! function with its scalar twin on values right at (and on both sides of) every
//! constant that decides fast path against scalar fallback.

const std = @import("std");
const testing = std.testing;
const ind = @import("root.zig");
const th = @import("testhelp.zig");
const vmath = @import("vmath.zig");
const xmath = @import("xmath.zig");
const trend = @import("trend.zig");
const hist = @import("hist.zig");
const smooth = @import("smooth.zig");
const overlap = @import("overlap.zig");
const core = @import("core.zig");

const nan = std.math.nan(f64);
const inf = std.math.inf(f64);

fn logS(x: f64) f64 {
    return @log(x);
}
fn expS(x: f64) f64 {
    return @exp(x);
}
fn log10S(x: f64) f64 {
    return @log10(x);
}

fn fromHi(h: u32, lo: u32, neg: bool) f64 {
    var b: u64 = (@as(u64, h) << 32) | lo;
    if (neg) b |= @as(u64, 1) << 63;
    return @bitCast(b);
}

fn sweepFn(comptime f: anytype, comptime scalar: anytype, xs: []const f64) !void {
    var i: usize = 0;
    while (i < xs.len) : (i += 4) {
        var lane: [4]f64 = undefined;
        for (0..4) |l| lane[l] = xs[@min(i + l, xs.len - 1)];
        const got: [4]f64 = f(@as(vmath.V, lane));
        for (0..4) |l| {
            if (!th.sameBits(got[l], scalar(lane[l]))) {
                std.debug.print("lane {d} x={x} got={x} want={x}\n", .{ l, @as(u64, @bitCast(lane[l])), @as(u64, @bitCast(got[l])), @as(u64, @bitCast(scalar(lane[l]))) });
                return error.TestUnexpectedResult;
            }
        }
    }
}

test "mutation 2026-11-25: vmath four-lane functions equal their scalar twins right at every fast / fallback threshold" {
    var xs: std.ArrayList(f64) = .empty;
    defer xs.deinit(testing.allocator);
    var prng = std.Random.DefaultPrng.init(0xb0da);
    const rnd = prng.random();
    var lows: [307]u32 = undefined;
    lows[0..7].* = .{ 0, 1, 2, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff };
    for (lows[7..]) |*w| w.* = rnd.int(u32);
    // high words that gate exp4 / log10_4 / tanh4 and (halved) tanh4's expm1 argument
    const his = [_]u32{
        0x3E300000, 0x40590000, 0x3FD62E42, 0x3FF0A2B2, // exp4
        0x00100000, 0x7FF00000, // log10_4
        0x3c800000, 0x40360000, 0x3ff00000, // tanh4
        0x3C900000, 0x4043687A, // expm1x range (argument = 2|x|)
        // log4's top 16 bits 0x0010 / 0x7ff0 (min normal, infinity)
        0x000f0000, 0x000fffff,
        0x00100000, 0x0010ffff,
        0x00110000, 0x7fef0000,
        0x7feffff0, 0x7ff00000,
        0x7ff0ffff, 0x7ff10000,
    };
    for (his) |h| {
        for ([_]i32{ -1, 0, 1 }) |dh| {
            const hh: u32 = @intCast(@as(i64, h) + dh);
            for (lows) |lo| for ([_]bool{ false, true }) |neg| {
                const x = fromHi(hh, lo, neg);
                try xs.append(testing.allocator, x);
                try xs.append(testing.allocator, x * 0.5); // tanh4: expm1x sees 2|x|
            };
        }
    }
    // log4's near-one window [1 - 2^-4, 1 + 0x1.09p-4) and its neighbours, exactly
    const lo_b: u64 = @bitCast(@as(f64, 1.0 - 0x1p-4));
    const hi_b: u64 = @bitCast(@as(f64, 1.0 + 0x1.09p-4));
    for ([_]u64{ lo_b, hi_b }) |b| {
        for ([_]i64{ -2, -1, 0, 1, 2 }) |d| try xs.append(testing.allocator, @bitCast(@as(u64, @intCast(@as(i64, @intCast(b)) + d))));
    }
    try xs.appendSlice(testing.allocator, &.{ 1.0, 0.5, 2.0, 22.0, 38.0 / 2.0, 19.4, 0.0, -0.0, inf, -inf, nan });
    try sweepFn(vmath.log4, logS, xs.items);
    try sweepFn(vmath.exp4, expS, xs.items);
    try sweepFn(vmath.log10_4, log10S, xs.items);
    try sweepFn(vmath.tanh4, xmath.tanh, xs.items);
}

fn Bars(comptime n: usize) type {
    return struct { h: [n]f64, l: [n]f64, c: [n]f64 };
}

fn bars(comptime n: usize, seed: u64) Bars(n) {
    var r: Bars(n) = undefined;
    th.walkBars(&r.h, &r.l, &r.c, seed);
    return r;
}

fn expectCkspLikeGeneric(h: []const f64, l: []const f64, c: []const f64, p: ind.CkspParams) !void {
    const gpa = testing.allocator;
    const n = h.len;
    const got = try gpa.alloc(f64, 2 * n);
    defer gpa.free(got);
    const want = try gpa.alloc(f64, 2 * n);
    defer gpa.free(want);
    const lb = try ind.cksp(f64, gpa, h, l, c, got[0..n], got[n..], p);
    const lb2 = try hist.batchAlloc(f64, trend.CkspCore, gpa, .{ h, l, c }, .{ want[0..n], want[n..] }, p);
    try testing.expectEqual(lb2, lb);
    try th.expectSameBits(want, got);
}

test "mutation 2026-11-25: cksp answers the generic core's bits for a NaN / infinite high or low, a zero low, and an extremum on the window's first bar" {
    const n = 220;
    const b = bars(n, 5);
    const p: ind.CkspParams = .{};
    var h = b.h;
    var l = b.l;
    var c = b.c;
    try expectCkspLikeGeneric(&h, &l, &c, p);
    // a non-finite or zero price on one bar, each of the six places the fast pass refuses
    const spots = [_]struct { which: u8, v: f64 }{
        .{ .which = 0, .v = nan }, .{ .which = 0, .v = inf },
        .{ .which = 1, .v = nan }, .{ .which = 1, .v = -inf },
        .{ .which = 1, .v = 0.0 }, .{ .which = 2, .v = inf },
        .{ .which = 0, .v = 0.0 }, .{ .which = 2, .v = nan },
    };
    for (spots) |s| {
        h = b.h;
        l = b.l;
        c = b.c;
        switch (s.which) {
            0 => h[100] = s.v,
            1 => l[100] = s.v,
            else => c[100] = s.v,
        }
        try expectCkspLikeGeneric(&h, &l, &c, p);
    }
    // an extremum on the first bar the block-wise pass pushes (the window start of the first stop)
    const params = [_]ind.CkspParams{
        .{},
        .{ .period = 3, .stop_period = 40 },
        .{ .period = 50, .stop_period = 3 },
        .{ .period = 10, .stop_period = 1 },
        // an AUTO unstable level delays the first stops by stop_period - 1: with stop_period > period + 1 the
        // extrema start after the ATR is a bare recurrence (phase 0 of the steady loop)
        .{ .period = 3, .stop_period = 40, .unstable = .auto4 },
        .{ .period = 5, .stop_period = 12, .unstable = .auto8 },
        .{ .period = 10, .stop_period = 9, .unstable = .{ .bars = 25 } },
    };
    for (params) |q| {
        const lb = try ind.ckspLookback(q);
        const ws = lb + 2 - q.stop_period - q.period; // first_stop + 1 - period
        for ([_]u8{ 0, 1 }) |side| {
            h = b.h;
            l = b.l;
            c = b.c;
            if (side == 0) h[ws] += 1000.0 else l[ws] -= 90.0;
            try expectCkspLikeGeneric(&h, &l, &c, q);
        }
    }
}

test "mutation 2026-11-25: cksp, fisher and pso refuse slices of different lengths with BadParam" {
    const n = 120;
    const b = bars(n, 8);
    var o1: [n]f64 = undefined;
    var o2: [n]f64 = undefined;
    try testing.expectError(error.BadParam, ind.cksp(f64, testing.allocator, &b.h, b.l[0 .. n - 1], &b.c, &o1, &o2, .{}));
    try testing.expectError(error.BadParam, ind.cksp(f64, testing.allocator, &b.h, &b.l, &b.c, o1[0 .. n - 1], &o2, .{}));
    try testing.expectError(error.BadParam, ind.fisher(f64, &b.h, b.l[0 .. n - 1], &o1, &o2, .{}));
    try testing.expectError(error.BadParam, ind.fisher(f64, &b.h, &b.l, &o1, o2[0 .. n - 1], .{}));
    try testing.expectError(error.BadParam, ind.pso(f64, &b.h, &b.l, b.c[0 .. n - 1], &o1, .{}));
    try testing.expectError(error.BadParam, ind.pso(f64, &b.h, &b.l, &b.c, o1[0 .. n - 1], .{}));
}

test "mutation 2026-11-25: wavetrend batch equals the stream once the deviation average has decayed to exactly zero" {
    // A long flat stretch with the shortest averages: |num| is forced to 0, the deviation EMA decays to 0.0 (denormal
    // then zero), so `0.015 * dv > 0.0` is false and the channel index is 0, not 0 / 0.
    const gpa = testing.allocator;
    const n = 3300;
    const h = try gpa.alloc(f64, n);
    defer gpa.free(h);
    const l = try gpa.alloc(f64, n);
    defer gpa.free(l);
    const c = try gpa.alloc(f64, n);
    defer gpa.free(c);
    const w1 = try gpa.alloc(f64, n);
    defer gpa.free(w1);
    const w2 = try gpa.alloc(f64, n);
    defer gpa.free(w2);
    th.walkBars(h[0..200], l[0..200], c[0..200], 21);
    @memset(h[200..], 100.0);
    @memset(l[200..], 100.0);
    @memset(c[200..], 100.0);
    const p: ind.WavetrendParams = .{ .channel = 2, .average = 1, .signal = 1 };
    _ = try ind.wavetrend(f64, gpa, h, l, c, w1, w2, p);
    const S = ind.WavetrendStream(f64);
    const buf = try gpa.alloc(f64, try S.bufLen(p));
    defer gpa.free(buf);
    var st = try S.init(p, buf);
    for (0..n) |i| {
        const r = st.update(.{ .high = h[i], .low = l[i], .close = c[i] });
        try testing.expect(th.sameOpt(if (r) |v| v.wt1 else null, w1[i]));
        try testing.expect(th.sameOpt(if (r) |v| v.wt2 else null, w2[i]));
    }
}

fn expectCciLikeStream(h: []const f64, l: []const f64, c: []const f64, per: usize) !void {
    const gpa = testing.allocator;
    const out = try gpa.alloc(f64, h.len);
    defer gpa.free(out);
    _ = try ind.cci(f64, h, l, c, out, .{ .period = per });
    const S = ind.CciStream(f64);
    const buf = try gpa.alloc(f64, try S.bufLen(.{ .period = per }));
    defer gpa.free(buf);
    var st = try S.init(.{ .period = per }, buf);
    for (h, l, c, out) |hh, ll, cc, w| try testing.expect(th.sameOpt(st.update(.{ .high = hh, .low = ll, .close = cc }), w));
}

test "mutation 2026-11-25: cci's zero-scaled deviation and underflowing divisor answer 0.0 like the stream" {
    // a spike far below the scaled epsilon of the mean deviation (period 500), not of the deviation from the mean
    var h: [520]f64 = undefined;
    @memset(&h, 1000.0);
    h[519] = 1000.0 + 1e-11;
    try expectCciLikeStream(&h, &h, &h, 500);
    // subnormal prices: eps * scale underflows to zero while 0.015 * deviation is zero too
    var prng = std.Random.DefaultPrng.init(0xcc1);
    const r = prng.random();
    const tiny = std.math.floatTrueMin(f64);
    var hh: [48]f64 = undefined;
    var ll: [48]f64 = undefined;
    var cc: [48]f64 = undefined;
    for (0..60) |seed| {
        _ = seed;
        for (0..48) |i| {
            const lo: f64 = @floatFromInt(r.uintLessThan(u32, 6));
            const up: f64 = @floatFromInt(r.uintLessThan(u32, 4));
            ll[i] = lo * tiny;
            hh[i] = (lo + up) * tiny;
            cc[i] = (lo + @as(f64, @floatFromInt(r.uintLessThan(u32, 3)))) * tiny;
            if (cc[i] > hh[i]) cc[i] = hh[i];
        }
        for ([_]usize{ 2, 3, 5, 8 }) |per| try expectCciLikeStream(&hh, &ll, &cc, per);
    }
}

test "mutation 2026-11-25: ultosc batch equals the stream through long runs of exactly-zero terms (sums reset, counter clamped)" {
    const gpa = testing.allocator;
    const n = 520;
    var h: [n]f64 = undefined;
    var l: [n]f64 = undefined;
    var c: [n]f64 = undefined;
    const trip = [_][3]usize{ .{ 7, 14, 28 }, .{ 3, 5, 9 }, .{ 20, 3, 9 }, .{ 1, 1, 1 }, .{ 2, 3, 4 }, .{ 5, 50, 120 }, .{ 4, 4, 4 }, .{ 20, 40, 60 }, .{ 30, 31, 32 }, .{ 10, 100, 200 }, .{ 50, 60, 70 }, .{ 9, 9, 17 } };
    for (0..40) |seed| {
        // a geometric walk (prices change binade, so the window sums round), then a flat stretch: every term
        // in it is exactly zero and the three sums are left with their rounding residue
        var prng = std.Random.DefaultPrng.init(700 + seed);
        const r = prng.random();
        var v: f64 = 100.0;
        for (0..n) |i| {
            v *= 1.0 + (r.float(f64) - 0.5) * 0.9;
            c[i] = v;
            h[i] = v * (1.0 + r.float(f64) * 0.3);
            l[i] = v * (1.0 - r.float(f64) * 0.3);
        }
        const start = 150 + seed * 3;
        const len = 70 + seed * 3;
        for (start..start + len) |i| {
            h[i] = c[start - 1];
            l[i] = c[start - 1];
            c[i] = c[start - 1];
        }
        for (trip) |t| {
            const p: ind.UltoscParams = .{ .period1 = t[0], .period2 = t[1], .period3 = t[2] };
            var out: [n]f64 = undefined;
            _ = try ind.ultosc(f64, &h, &l, &c, &out, p);
            const S = ind.UltoscStream(f64);
            const buf = try gpa.alloc(f64, try S.bufLen(p));
            defer gpa.free(buf);
            var st = try S.init(p, buf);
            for (0..n) |i| try testing.expect(th.sameOpt(st.update(.{ .high = h[i], .low = l[i], .close = c[i] }), out[i]));
        }
    }
}

test "mutation 2026-11-25: mavp's period-range check never fires for a valid average (lookback and ring length are non-decreasing in the period)" {
    const MaT = core.MaType;
    const unst = [_]core.Unstable{ core.no_unstable, .{ .bars = 5 }, .auto4, .auto8 };
    const seeds = [_]core.Seed{ .sma, .first };
    var accepted: usize = 0;
    for (std.meta.tags(MaT)) |kind| {
        for (unst) |u| for (seeds) |sd| for ([_]usize{ 1, 2, 3, 7, 25 }) |mx| {
            const p: ind.MavpParams = .{ .min_period = 1, .max_period = mx, .kind = kind, .unstable = u, .seed = sd };
            _ = ind.mavpLookback(p) catch continue;
            try overlap.MavpCore.validate(p);
            accepted += 1;
            var prev_lb: usize = 0;
            var prev_ring: usize = 0;
            for (1..mx + 1) |k| {
                const mp: smooth.MaParams = .{ .period = k, .kind = kind, .unstable = u, .seed = sd };
                try testing.expect(smooth.MaCore.lookback(mp) >= prev_lb);
                try testing.expect(smooth.MaCore.ringLen(mp) >= prev_ring);
                prev_lb = smooth.MaCore.lookback(mp);
                prev_ring = smooth.MaCore.ringLen(mp);
            }
        };
    }
    try testing.expect(accepted > 100);
}
