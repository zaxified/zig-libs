// SPDX-License-Identifier: MIT
//! TRANGE, ATR and NATR, ported from TA-Lib 0.8.3 (`ta_TRANGE.c`, `ta_ATR.c`,
//! `ta_NATR.c`; BSD-3, see NOTICE). The inputs are parallel high / low / close
//! slices of one length.

const std = @import("std");
const core = @import("core.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Nan = core.Nan;
const Unstable = core.Unstable;
const Bar = core.Bar;
const pf = core.pf;

fn nanSkip(p: anytype) bool {
    if (@hasField(@TypeOf(p), "nan")) return p.nan == .skip;
    return false;
}

fn barHasNan(b: Bar(f64)) bool {
    return core.isNan(b.high) or core.isNan(b.low) or core.isNan(b.close);
}

/// Batch driver for a bar-input, single-output core.
pub fn batchBars(comptime T: type, comptime Core: type, hs: []const T, ls: []const T, cs: []const T, out: []T, p: anytype) Error!usize {
    core.checkFloat(T);
    try core.checkLen(hs.len, &.{ ls.len, cs.len, out.len });
    var c = try Core.init(p);
    const skip = nanSkip(p);
    for (hs, ls, cs, out) |h, l, cl, *o| {
        const b = Bar(f64){ .high = h, .low = l, .close = cl };
        if (skip and barHasNan(b)) {
            o.* = std.math.nan(T);
            continue;
        }
        o.* = if (c.step(b)) |r| core.to(T, r) else std.math.nan(T);
    }
    return Core.lookback(p);
}

/// Streaming wrapper for a bar-input core (no history: copyable by value).
pub fn BarStream(comptime T: type, comptime Params: type, comptime Core: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        c: Core,
        skip: bool,
        last: ?T = null,

        pub fn init(p: Params) Error!Self {
            return .{ .c = try Core.init(p), .skip = nanSkip(p) };
        }
        pub fn update(self: *Self, bar: Bar(T)) ?T {
            const b = core.to(Bar(f64), bar);
            if (self.skip and barHasNan(b)) return null;
            const r = self.c.step(b) orelse return null;
            self.last = core.to(T, r);
            return self.last;
        }
        pub fn peek(self: *const Self, bar: Bar(T)) ?T {
            const b = core.to(Bar(f64), bar);
            if (self.skip and barHasNan(b)) return null;
            var cc = self.c;
            const r = cc.step(b) orelse return null;
            return core.to(T, r);
        }
        pub fn value(self: *const Self) ?T {
            return self.last;
        }
    };
}

// ── TRANGE ──────────────────────────────────────────────────────────────────

pub const TrangeParams = struct {};

/// True range: the greatest of high-low, |prevClose-high|, |prevClose-low|.
/// Bar 0 only provides the previous close.
pub const TrCore = struct {
    prev_close: f64 = 0.0,
    has: bool = false,

    pub fn validate(_: TrangeParams) Error!void {}
    pub fn lookback(_: TrangeParams) usize {
        return 1;
    }
    pub fn init(_: TrangeParams) Error!TrCore {
        return .{};
    }
    pub fn step(self: *TrCore, b: Bar(f64)) ?f64 {
        const cy = self.prev_close;
        self.prev_close = b.close;
        if (!self.has) {
            self.has = true;
            return null;
        }
        var greatest = b.high - b.low;
        const v2 = @abs(cy - b.high);
        if (v2 > greatest) greatest = v2;
        const v3 = @abs(cy - b.low);
        if (v3 > greatest) greatest = v3;
        return greatest;
    }
};

pub fn trangeLookback() usize {
    return 1;
}
pub fn trange(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T) Error!usize {
    return batchBars(T, TrCore, high, low, close, out, TrangeParams{});
}
pub fn TrangeStream(comptime T: type) type {
    return BarStream(T, TrangeParams, TrCore);
}

// ── ATR / NATR ──────────────────────────────────────────────────────────────

pub const AtrParams = struct {
    period: usize = 14,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
};
pub const NatrParams = AtrParams;

/// Wilder's average true range: the first `period` true ranges are averaged
/// (the seed), then `atr = fma(beta, atr, alpha * tr)` with beta = (p-1)/p and
/// alpha = 1 - beta (derived from beta so that alpha + beta is exactly 1).
/// `natr` true: normalise by the bar's own close, percent; period 1 stays the
/// raw true range; a zero close answers 0.0.
pub fn AtrCore(comptime normalize: bool) type {
    return struct {
        const Self = @This();
        p: usize,
        u: usize,
        beta: f64,
        alpha: f64,
        tr: TrCore = .{},
        k: usize = 0,
        total: f64 = 0.0,
        prev: f64 = 0.0,

        pub fn validate(p: AtrParams) Error!void {
            try core.checkPeriod(p.period, 1);
            try p.unstable.check();
        }
        pub fn unstableOf(p: AtrParams) usize {
            if (normalize) {
                const c4: usize = if (p.period > 1) 10 * p.period else 0;
                const c8: usize = if (p.period > 1) 19 * p.period else 0;
                return p.unstable.get(c4, c8);
            }
            const c4: usize = if (p.period > 1) (10 * (2 * p.period - 1) + 1) / 2 else 0;
            const c8: usize = if (p.period > 1) (19 * (2 * p.period - 1) + 1) / 2 else 0;
            return p.unstable.get(c4, c8);
        }
        pub fn lookback(p: AtrParams) usize {
            return p.period + unstableOf(p);
        }
        pub fn init(p: AtrParams) Error!Self {
            try validate(p);
            const beta = pf(p.period - 1) / pf(p.period);
            return .{ .p = p.period, .u = unstableOf(p), .beta = beta, .alpha = 1.0 - beta };
        }
        pub fn step(self: *Self, b: Bar(f64)) ?f64 {
            const t = self.tr.step(b) orelse return null;
            self.k += 1;
            if (self.k < self.p) {
                self.total += t;
                return null;
            }
            if (self.k == self.p) {
                self.total += t;
                self.prev = self.total / pf(self.p);
            } else {
                self.prev = @mulAdd(f64, self.beta, self.prev, self.alpha * t);
            }
            if (self.k < self.p + self.u) return null;
            if (!normalize or self.p <= 1) return self.prev;
            return if (b.close != 0.0) self.prev / b.close * 100.0 else 0.0;
        }
    };
}

pub const AtrCoreT = AtrCore(false);
pub const NatrCoreT = AtrCore(true);

pub fn atrLookback(p: AtrParams) Error!usize {
    try AtrCoreT.validate(p);
    return AtrCoreT.lookback(p);
}
pub fn atr(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: AtrParams) Error!usize {
    return batchBars(T, AtrCoreT, high, low, close, out, p);
}
pub fn AtrStream(comptime T: type) type {
    return BarStream(T, AtrParams, AtrCoreT);
}
pub fn natrLookback(p: NatrParams) Error!usize {
    try NatrCoreT.validate(p);
    return NatrCoreT.lookback(p);
}
pub fn natr(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: NatrParams) Error!usize {
    return batchBars(T, NatrCoreT, high, low, close, out, p);
}
pub fn NatrStream(comptime T: type) type {
    return BarStream(T, NatrParams, NatrCoreT);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// Bars used by the hand-checked vectors (high, low, close):
//   b0 (10, 8, 9)   b1 (11, 9, 10)   b2 (15, 11, 14)   b3 (13, 12, 12.5)
// True range from bar 1 on, greatest of H-L, |Cy-H|, |Cy-L|:
//   b1: 2, |9-11| = 2, |9-9| = 0                 -> 2
//   b2: 4, |10-15| = 5, |10-11| = 1              -> 5
//   b3: 1, |14-13| = 1, |14-12| = 2              -> 2
const t_h = [_]f64{ 10, 11, 15, 13 };
const t_l = [_]f64{ 8, 9, 11, 12 };
const t_c = [_]f64{ 9, 10, 14, 12.5 };

test "trange hand-checked vector" {
    var out: [4]f64 = undefined;
    try testing.expectEqual(@as(usize, 1), try trange(f64, &t_h, &t_l, &t_c, &out));
    try testing.expect(std.math.isNan(out[0]));
    try testing.expectEqual(@as(f64, 2), out[1]);
    try testing.expectEqual(@as(f64, 5), out[2]);
    try testing.expectEqual(@as(f64, 2), out[3]);
}

test "atr and natr hand-checked vector" {
    // period 2: seed = (2 + 5) / 2 = 3.5 at bar 2; beta = alpha = 0.5;
    // bar 3: fma(0.5, 3.5, 0.5 * 2) = 1.75 + 1 = 2.75.
    var out: [4]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try atr(f64, &t_h, &t_l, &t_c, &out, .{ .period = 2 }));
    try testing.expect(std.math.isNan(out[1]));
    try testing.expectEqual(@as(f64, 3.5), out[2]);
    try testing.expectEqual(@as(f64, 2.75), out[3]);
    // natr = atr / close * 100: 3.5 / 14 * 100 = 25, 2.75 / 12.5 * 100 = 22.
    try testing.expectEqual(@as(usize, 2), try natr(f64, &t_h, &t_l, &t_c, &out, .{ .period = 2 }));
    try testing.expectEqual(@as(f64, 25), out[2]);
    try testing.expectEqual(@as(f64, 22), out[3]);
}

test "atr period 1 is the true range; natr period 1 stays unnormalised" {
    var out: [4]f64 = undefined;
    try testing.expectEqual(@as(usize, 1), try atr(f64, &t_h, &t_l, &t_c, &out, .{ .period = 1 }));
    try testing.expectEqual(@as(f64, 5), out[2]);
    try testing.expectEqual(@as(usize, 1), try natr(f64, &t_h, &t_l, &t_c, &out, .{ .period = 1 }));
    try testing.expectEqual(@as(f64, 5), out[2]);
}

test "natr: a zero close answers 0" {
    const h = [_]f64{ 1, 2, 3 };
    const l = [_]f64{ 0, 1, 2 };
    const c = [_]f64{ 0.5, 1.5, 0 };
    var out: [3]f64 = undefined;
    _ = try natr(f64, &h, &l, &c, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 0), out[2]);
}

test "atr/natr unstable: lookback and AUTO constants" {
    try testing.expectEqual(@as(usize, 14), try atrLookback(.{}));
    try testing.expectEqual(@as(usize, 14 + 3), try atrLookback(.{ .unstable = .{ .bars = 3 } }));
    // auto4 = (10 * (2p-1) + 1) / 2 = (10*27+1)/2 = 135 ; auto8 = (19*27+1)/2 = 257 (p = 14)
    try testing.expectEqual(@as(usize, 14 + 135), try atrLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 14 + 257), try atrLookback(.{ .unstable = .auto8 }));
    // natr uses 10p / 19p
    try testing.expectEqual(@as(usize, 14 + 140), try natrLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 14 + 266), try natrLookback(.{ .unstable = .auto8 }));
    try testing.expectEqual(@as(usize, 1), try atrLookback(.{ .period = 1, .unstable = .auto8 }));
}

test "range: BadParam" {
    var out: [4]f64 = undefined;
    try testing.expectError(error.BadParam, atr(f64, &t_h, &t_l, &t_c, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, atr(f64, &t_h, &t_l, &t_c, &out, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, natr(f64, &t_h, &t_l, &t_c, &out, .{ .period = 0 }));
    try testing.expectError(error.BadParam, atr(f64, &t_h, t_l[0..3], &t_c, &out, .{ .period = 2 }));
    try testing.expectError(error.BadParam, trange(f64, &t_h, &t_l, &t_c, out[0..3]));
}

fn checkBars(comptime Stream: anytype, comptime batch: anytype, comptime lbFn: anytype, p: anytype, hh: []const f64, ll: []const f64, cc: []const f64) !void {
    const S = Stream(f64);
    const out = try testing.allocator.alloc(f64, hh.len);
    defer testing.allocator.free(out);
    const lb = try batch(f64, hh, ll, cc, out, p);
    try testing.expectEqual(try lbFn(p), lb);
    try testing.expectEqual(lb, th.leadingNan(out));
    var s = try S.init(p);
    for (hh, ll, cc, out) |h, l, c, want| {
        const b = Bar(f64){ .high = h, .low = l, .close = c };
        const pk = s.peek(b);
        const got = s.update(b);
        try testing.expect(th.sameOpt(got, want));
        try testing.expect(th.sameOpt(pk, want));
    }
}

fn trWrap(comptime T: type, h: []const T, l: []const T, c: []const T, out: []T, _: TrangeParams) Error!usize {
    return trange(T, h, l, c, out);
}
fn trLb(_: TrangeParams) Error!usize {
    return trangeLookback();
}

test "range: batch == streaming, lookback == leading NaN, f32" {
    var h: [300]f64 = undefined;
    var l: [300]f64 = undefined;
    var c: [300]f64 = undefined;
    th.walkBars(&h, &l, &c, 41);
    try checkBars(TrangeStream, trWrap, trLb, TrangeParams{}, &h, &l, &c);
    try checkBars(AtrStream, atr, atrLookback, AtrParams{}, &h, &l, &c);
    try checkBars(AtrStream, atr, atrLookback, AtrParams{ .period = 1 }, &h, &l, &c);
    try checkBars(AtrStream, atr, atrLookback, AtrParams{ .period = 5, .unstable = .{ .bars = 4 } }, &h, &l, &c);
    try checkBars(NatrStream, natr, natrLookback, NatrParams{}, &h, &l, &c);
    try checkBars(NatrStream, natr, natrLookback, NatrParams{ .period = 3, .unstable = .auto4 }, &h, &l, &c);
    var h32: [50]f32 = undefined;
    var l32: [50]f32 = undefined;
    var c32: [50]f32 = undefined;
    for (0..50) |i| {
        h32[i] = @floatCast(h[i]);
        l32[i] = @floatCast(l[i]);
        c32[i] = @floatCast(c[i]);
    }
    var o32: [50]f32 = undefined;
    try testing.expectEqual(@as(usize, 14), try atr(f32, &h32, &l32, &c32, &o32, .{}));
    try testing.expect(o32[14] > 0);
    try testing.expectEqual(@as(usize, 1), try trange(f32, &h32, &l32, &c32, &o32));
}

test "atr nan skip ignores the bad bar" {
    const nan = std.math.nan(f64);
    const h = [_]f64{ 10, 11, nan, 15, 13 };
    const l = [_]f64{ 8, 9, 1, 11, 12 };
    const c = [_]f64{ 9, 10, 1, 14, 12.5 };
    var out: [5]f64 = undefined;
    _ = try atr(f64, &h, &l, &c, &out, .{ .period = 2, .nan = .skip });
    try testing.expect(std.math.isNan(out[2]));
    try testing.expectEqual(@as(f64, 3.5), out[3]);
    try testing.expectEqual(@as(f64, 2.75), out[4]);
}
