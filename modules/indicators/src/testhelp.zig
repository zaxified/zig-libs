// SPDX-License-Identifier: MIT
//! Test helpers shared by the indicator files: seeded random walks and the
//! batch-versus-streaming comparison.

const std = @import("std");
const testing = std.testing;

/// Seeded random-walk close prices around 100.
pub fn walk(xs: []f64, seed: u64) void {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var v: f64 = 100.0;
    for (xs) |*x| {
        v += (r.float(f64) - 0.5) * 2.0;
        x.* = v;
    }
}

/// Seeded OHLC walk: low <= close <= high.
pub fn walkBars(hs: []f64, ls: []f64, cs: []f64, seed: u64) void {
    walk(cs, seed);
    var prng = std.Random.DefaultPrng.init(seed +% 1000);
    const r = prng.random();
    for (hs, ls, cs) |*h, *l, c| {
        h.* = c + r.float(f64) * 1.5;
        l.* = c - r.float(f64) * 1.5;
    }
}

pub fn sameBits(a: f64, b: f64) bool {
    if (std.math.isNan(a) and std.math.isNan(b)) return true;
    return @as(u64, @bitCast(a)) == @as(u64, @bitCast(b));
}

pub fn expectSameBits(a: []const f64, b: []const f64) !void {
    try testing.expectEqual(a.len, b.len);
    for (a, b, 0..) |x, y, i| {
        if (!sameBits(x, y)) {
            std.debug.print("bit mismatch at {d}: {e} vs {e}\n", .{ i, x, y });
            return error.TestExpectedEqual;
        }
    }
}

/// An optional stream output against a batch slot (null == NaN).
pub fn sameOpt(got: ?f64, want: f64) bool {
    if (got) |g| return sameBits(g, want);
    return std.math.isNan(want);
}

pub fn leadingNan(xs: []const f64) usize {
    var n: usize = 0;
    while (n < xs.len and std.math.isNan(xs[n])) n += 1;
    return n;
}

/// Batch against streaming for a single-input indicator with a ring buffer:
/// bitwise equal, `peek` equals `update`, lookback equals the leading NaN count.
pub fn checkOne(
    comptime Params: type,
    comptime StreamFn: anytype,
    comptime batchFn: anytype,
    comptime lbFn: anytype,
    xs: []const f64,
    p: Params,
) !void {
    const S = StreamFn(f64);
    const out = try testing.allocator.alloc(f64, xs.len);
    defer testing.allocator.free(out);
    const lb = try batchFn(f64, xs, out, p);
    try testing.expectEqual(try lbFn(p), lb);
    try testing.expectEqual(lb, leadingNan(out));
    const buf = try testing.allocator.alloc(f64, try S.bufLen(p));
    defer testing.allocator.free(buf);
    var s = try S.init(p, buf);
    for (xs, out) |x, want| {
        const pk = s.peek(x);
        const got = s.update(x);
        try testing.expect(sameOpt(got, want));
        try testing.expect(pk == null and got == null or pk != null and got != null and sameBits(pk.?, got.?));
    }
}

/// Same for a stream without a buffer (`init(p)`).
pub fn checkRec(
    comptime Params: type,
    comptime StreamFn: anytype,
    comptime batchFn: anytype,
    comptime lbFn: anytype,
    xs: []const f64,
    p: Params,
) !void {
    const S = StreamFn(f64);
    const out = try testing.allocator.alloc(f64, xs.len);
    defer testing.allocator.free(out);
    const lb = try batchFn(f64, xs, out, p);
    try testing.expectEqual(try lbFn(p), lb);
    try testing.expectEqual(lb, leadingNan(out));
    var s = try S.init(p);
    for (xs, out) |x, want| {
        const pk = s.peek(x);
        const got = s.update(x);
        try testing.expect(sameOpt(got, want));
        try testing.expect(pk == null and got == null or pk != null and got != null and sameBits(pk.?, got.?));
    }
}

/// `nan = .skip`: the output at a NaN bar is the previous output (NaN before the
/// first one), every other bar equals the run over the series with the NaN bars
/// removed. `batchFn(f64, in, out, p)`; `p_skip` has `.nan = .skip`.
pub fn checkSkip1(comptime batchFn: anytype, p_skip: anytype, p_prop: anytype) !void {
    var xs: [80]f64 = undefined;
    walk(&xs, 1234);
    var ys = xs;
    const nan_at = [_]usize{ 2, 30, 31, 55 };
    for (nan_at) |i| ys[i] = std.math.nan(f64);
    var clean: [80 - nan_at.len]f64 = undefined;
    var j: usize = 0;
    for (ys) |v| {
        if (std.math.isNan(v)) continue;
        clean[j] = v;
        j += 1;
    }
    var out: [80]f64 = undefined;
    var want: [80 - nan_at.len]f64 = undefined;
    _ = try batchFn(f64, &ys, &out, p_skip);
    _ = try batchFn(f64, &clean, &want, p_prop);
    var k: usize = 0;
    var last = std.math.nan(f64);
    for (ys, out) |y, o| {
        if (std.math.isNan(y)) {
            try testing.expect(sameBits(o, last));
        } else {
            try testing.expect(sameBits(o, want[k]));
            k += 1;
        }
        last = o;
    }
}

test "walk is deterministic and bars are ordered" {
    var a: [20]f64 = undefined;
    var b: [20]f64 = undefined;
    walk(&a, 5);
    walk(&b, 5);
    try expectSameBits(&a, &b);
    var h: [20]f64 = undefined;
    var l: [20]f64 = undefined;
    var c: [20]f64 = undefined;
    walkBars(&h, &l, &c, 9);
    for (h, l, c) |hh, ll, cc| try testing.expect(ll <= cc and cc <= hh);
}

/// Seeded OHLC bars with candlestick structure: a mix of ordinary, doji,
/// long-body, marubozu and gapping bars (a plain random walk forms almost no
/// patterns). Always low <= min(open, close) and high >= max(open, close).
pub fn candleBars(os: []f64, hs: []f64, ls: []f64, cs: []f64, seed: u64) void {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var p: f64 = 100.0;
    for (os, hs, ls, cs) |*o, *h, *l, *c| {
        const kind = r.uintLessThan(u32, 12);
        const dir: f64 = if (r.boolean()) 1.0 else -1.0;
        var op = p;
        var cl: f64 = undefined;
        var up: f64 = r.float(f64) * 0.8;
        var dn: f64 = r.float(f64) * 0.8;
        switch (kind) {
            0, 1 => { // doji: open == close (or nearly), long shadows
                cl = op + (r.float(f64) - 0.5) * 0.02;
                up = 0.5 + r.float(f64) * 2.0;
                dn = 0.5 + r.float(f64) * 2.0;
            },
            2, 3 => { // long body
                cl = op + dir * (3.0 + r.float(f64) * 3.0);
            },
            4 => { // marubozu
                cl = op + dir * (3.0 + r.float(f64) * 3.0);
                up = 0.0;
                dn = 0.0;
            },
            5, 6 => { // gap, then a body
                op = p + dir * (1.5 + r.float(f64) * 2.0);
                cl = op + (r.float(f64) - 0.5) * 3.0;
            },
            7 => { // hammer / shooting-star shapes
                cl = op + (r.float(f64) - 0.5) * 0.6;
                if (r.boolean()) up = 0.0 else dn = 0.0;
                if (up == 0.0) dn = 1.5 + r.float(f64) * 2.0 else up = 1.5 + r.float(f64) * 2.0;
            },
            else => cl = op + (r.float(f64) - 0.5) * 2.5,
        }
        o.* = op;
        c.* = cl;
        h.* = @max(op, cl) + up;
        l.* = @min(op, cl) - dn;
        p = cl;
    }
}
