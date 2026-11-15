// SPDX-License-Identifier: MIT
//! The Wilder-smoothed directional-movement family and AROON, ported from
//! TA-Lib 0.8.3 (`ta_ADX.c`, `ta_ADXR.c`, `ta_DX.c`, `ta_PLUS_DI.c`,
//! `ta_MINUS_DI.c`, `ta_PLUS_DM.c`, `ta_MINUS_DM.c`, `ta_AROON.c`,
//! `ta_AROONOSC.c`; BSD-3, see NOTICE).
//!
//! Two arithmetic families, as in the C: ADX / ADXR / DX select the directional
//! movement with the two-stage `KEEP_IF_GT` pair and decay it as
//! `dm -= dm * (1/p); dm += dm1`; the DI / DM functions use the
//! `max(decayed, decayed + dm1)` form (which also drops a negative dm1). Both
//! start from the sum of the first `p - 1` bars. The unstable period delays the
//! first output (`Unstable`), the AUTO constants are those of each function's id.

const std = @import("std");
const core = @import("core.zig");
const vs = @import("vs_kit.zig");
const mu = @import("mom_util.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Unstable = core.Unstable;
const pf = core.pf;

pub const WilderParams = struct {
    period: usize = 14,
    unstable: Unstable = core.no_unstable,
};

const eps: f64 = 0.00000000000001; // TA_EPSILON
fn isZero(v: f64) bool {
    return (-eps < v) and (v < eps);
}

fn trueRange(high: f64, low: f64, prev_close: f64) f64 {
    var range = high - low;
    const t1 = @abs(high - prev_close);
    if (t1 > range) range = t1;
    const t2 = @abs(low - prev_close);
    if (t2 > range) range = t2;
    return range;
}

fn keepGt(a: f64, b: f64, x: f64) f64 {
    return if (a > b) x else 0.0;
}

// ── ADX / DX ────────────────────────────────────────────────────────────────

pub fn AdxCore(comptime dx_only: bool) type {
    return struct {
        const Self = @This();
        pub const In = vs.Hlc(f64);
        pub const Out = f64;
        pub const Params = WilderParams;
        pub const windowed = false;
        pub fn Inputs(comptime T: type) type {
            return vs.Hlc(T);
        }
        pub fn Outputs(comptime T: type) type {
            return T;
        }

        p: usize,
        u: usize,
        inv: f64,
        n: usize = 0,
        ph: f64 = 0.0,
        pl: f64 = 0.0,
        pc: f64 = 0.0,
        minus_dm: f64 = 0.0,
        plus_dm: f64 = 0.0,
        tr: f64 = 0.0,
        sum_dx: f64 = 0.0,
        adx: f64 = 0.0,
        last: f64 = 0.0,

        pub fn validate(p: Params) Error!void {
            try core.checkPeriod(p.period, 2);
            try p.unstable.check();
        }
        pub fn unstableOf(p: Params) usize {
            if (dx_only) return p.unstable.get(10 * p.period, 19 * p.period);
            return p.unstable.get(16 * p.period, 25 * p.period);
        }
        pub fn lookback(p: Params) usize {
            if (dx_only) return p.period + unstableOf(p);
            return 2 * p.period + unstableOf(p) - 1;
        }
        pub fn ringLen(_: Params) usize {
            return 0;
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            return .{ .p = p.period, .u = unstableOf(p), .inv = 1.0 / pf(p.period) };
        }

        /// 100 * |-DI - +DI| / (-DI + +DI) of the current smoothed sums, null when
        /// the true range is not positive or the DIs sum to ~0.
        fn dxValue(self: *const Self) ?f64 {
            if (self.tr > 0.0) {
                const minus_di = 100.0 * (self.minus_dm / self.tr);
                const plus_di = 100.0 * (self.plus_dm / self.tr);
                const t = minus_di + plus_di;
                if (!isZero(t)) return 100.0 * (@abs(minus_di - plus_di) / t);
            }
            return null;
        }

        pub fn step(self: *Self, _: anytype, b: In) ?f64 {
            const k = self.n;
            self.n += 1;
            if (k == 0) {
                self.ph = b.high;
                self.pl = b.low;
                self.pc = b.close;
                return null;
            }
            const diff_p = b.high - self.ph;
            self.ph = b.high;
            const diff_m = self.pl - b.low;
            self.pl = b.low;
            const minus_sel = keepGt(diff_m - diff_p, 0.0, diff_m);
            const plus_sel = keepGt(diff_p - diff_m, 0.0, diff_p);
            const minus1 = keepGt(diff_m, 0.0, minus_sel);
            const plus1 = keepGt(diff_p, 0.0, plus_sel);
            const t = trueRange(self.ph, self.pl, self.pc);
            self.pc = b.close;
            if (k < self.p) {
                self.minus_dm += minus1;
                self.plus_dm += plus1;
                self.tr += t;
                return null;
            }
            self.minus_dm -= self.minus_dm * self.inv;
            self.plus_dm -= self.plus_dm * self.inv;
            self.minus_dm += minus1;
            self.plus_dm += plus1;
            self.tr = self.tr - self.tr * self.inv + t;
            if (dx_only) {
                if (k < self.p + self.u) return null;
                // the first output answers 0.0 where nothing is computable; later
                // ones repeat the previous output
                self.last = self.dxValue() orelse self.last;
                return self.last;
            }
            if (k < 2 * self.p) {
                if (self.dxValue()) |v| self.sum_dx += v;
                if (k == 2 * self.p - 1) self.adx = self.sum_dx / pf(self.p);
            } else if (self.dxValue()) |v| {
                self.adx = self.adx - (self.adx - v) * self.inv;
            }
            if (k < 2 * self.p - 1 + self.u) return null;
            return self.adx;
        }
    };
}

pub const ADX = AdxCore(false);
pub const DX = AdxCore(true);

pub fn adxLookback(p: WilderParams) Error!usize {
    try ADX.validate(p);
    return ADX.lookback(p);
}
pub fn adx(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: WilderParams) Error!usize {
    return vs.batch(T, ADX, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn AdxStream(comptime T: type) type {
    return vs.Stream(T, ADX);
}
pub fn dxLookback(p: WilderParams) Error!usize {
    try DX.validate(p);
    return DX.lookback(p);
}
pub fn dx(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: WilderParams) Error!usize {
    return vs.batch(T, DX, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn DxStream(comptime T: type) type {
    return vs.Stream(T, DX);
}

// ── ADXR ────────────────────────────────────────────────────────────────────

/// ADXR = (ADX now + ADX `period - 1` outputs ago) / 2. Keeps the last `period`
/// ADX values in its scratch.
pub const ADXR = struct {
    const Self = @This();
    pub const In = vs.Hlc(f64);
    pub const Out = f64;
    pub const Params = WilderParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.Hlc(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }

    a: ADX,
    ring: mu.Ring,
    p: usize,
    n: usize = 0,

    pub fn validate(p: Params) Error!void {
        return ADX.validate(p);
    }
    pub fn lookback(p: Params) usize {
        return p.period + ADX.lookback(p) - 1;
    }
    pub fn ringLen(_: Params) usize {
        return 0;
    }
    pub fn scratchLen(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params, scratch: []f64) Error!Self {
        try validate(p);
        if (scratch.len < p.period) return error.BadParam;
        return .{ .a = try ADX.init(p), .ring = mu.Ring.init(scratch[0..p.period]), .p = p.period };
    }
    pub fn step(self: *Self, src: anytype, b: In) ?f64 {
        self.n += 1;
        const v = self.a.step(src, b) orelse return null;
        self.ring.push(v);
        if (self.ring.n < self.p) return null;
        return (v + self.ring.at(self.ring.n - self.p)) / 2.0;
    }
    pub fn peekStep(self: *const Self, src: anytype, b: In) ?f64 {
        return mu.peekRings(Self, self, src, b);
    }
};

pub fn adxrLookback(p: WilderParams) Error!usize {
    try ADXR.validate(p);
    return ADXR.lookback(p);
}
pub fn adxr(comptime T: type, gpa: std.mem.Allocator, high: []const T, low: []const T, close: []const T, out: []T, p: WilderParams) core.AllocError!usize {
    return vs.batchScratch(T, ADXR, gpa, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn AdxrStream(comptime T: type) type {
    return vs.Stream(T, ADXR);
}

// ── ±DM / ±DI ───────────────────────────────────────────────────────────────

pub const DmKind = enum { minus_dm, plus_dm, minus_di, plus_di };

pub fn DmCore(comptime kind: DmKind) type {
    const is_di = kind == .minus_di or kind == .plus_di;
    const is_minus = kind == .minus_dm or kind == .minus_di;
    return struct {
        const Self = @This();
        pub const In = if (is_di) vs.Hlc(f64) else vs.Hl(f64);
        pub const Out = f64;
        pub const Params = WilderParams;
        pub const windowed = false;
        pub fn Inputs(comptime T: type) type {
            return if (is_di) vs.Hlc(T) else vs.Hl(T);
        }
        pub fn Outputs(comptime T: type) type {
            return T;
        }

        p: usize,
        l: usize,
        inv: f64,
        n: usize = 0,
        ph: f64 = 0.0,
        pl: f64 = 0.0,
        pc: f64 = 0.0,
        dm: f64 = 0.0,
        tr: f64 = 0.0,

        pub fn validate(p: Params) Error!void {
            try core.checkPeriod(p.period, 1);
            try p.unstable.check();
        }
        pub fn lookback(p: Params) usize {
            if (p.period == 1) return 1;
            if (is_di) return p.period + p.unstable.get(10 * p.period, 19 * p.period);
            const c4 = (10 * (2 * p.period - 1) + 1) / 2;
            const c8 = (19 * (2 * p.period - 1) + 1) / 2;
            return p.period + p.unstable.get(c4, c8) - 1;
        }
        pub fn ringLen(_: Params) usize {
            return 0;
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            return .{ .p = p.period, .l = lookback(p), .inv = 1.0 / pf(p.period) };
        }

        fn close(b: In) f64 {
            return if (is_di) b.close else 0.0;
        }

        pub fn step(self: *Self, _: anytype, b: In) ?f64 {
            const k = self.n;
            self.n += 1;
            if (k == 0) {
                self.ph = b.high;
                self.pl = b.low;
                self.pc = close(b);
                return null;
            }
            const diff_p = b.high - self.ph;
            self.ph = b.high;
            const diff_m = self.pl - b.low;
            self.pl = b.low;
            const t_range = if (is_di) trueRange(self.ph, self.pl, self.pc) else 0.0;
            self.pc = close(b);
            if (self.p == 1) {
                if (is_di) {
                    const hit = if (is_minus) (diff_m > 0 and diff_p < diff_m) else (diff_p > 0 and diff_p > diff_m);
                    if (!hit) return 0.0;
                    if (t_range <= 0.0) return 0.0;
                    return (if (is_minus) diff_m else diff_p) / t_range;
                }
                if (is_minus) {
                    const d1 = if (diff_m > 0.0) diff_m else 0.0;
                    return if (diff_p < diff_m) d1 else 0.0;
                }
                const d1 = if (diff_p > 0.0) diff_p else 0.0;
                return if (diff_p > diff_m) d1 else 0.0;
            }
            const sel = if (is_minus) diff_m - diff_p else diff_p - diff_m;
            const d1 = keepGt(sel, 0.0, if (is_minus) diff_m else diff_p);
            if (k < self.p) {
                const t = self.dm + d1;
                self.dm = if (self.dm > t) self.dm else t;
                if (is_di) self.tr += t_range;
            } else {
                const t = self.dm - self.dm * self.inv;
                self.dm = t + d1;
                self.dm = if (t > self.dm) t else self.dm;
                if (is_di) self.tr = self.tr - self.tr * self.inv + t_range;
            }
            if (k < self.l) return null;
            if (!is_di) return self.dm;
            return if (self.tr > 0.0) 100.0 * (self.dm / self.tr) else 0.0;
        }
    };
}

pub const MINUS_DM = DmCore(.minus_dm);
pub const PLUS_DM = DmCore(.plus_dm);
pub const MINUS_DI = DmCore(.minus_di);
pub const PLUS_DI = DmCore(.plus_di);

pub fn minusDmLookback(p: WilderParams) Error!usize {
    try MINUS_DM.validate(p);
    return MINUS_DM.lookback(p);
}
pub fn minusDm(comptime T: type, high: []const T, low: []const T, out: []T, p: WilderParams) Error!usize {
    return vs.batch(T, MINUS_DM, p, .{ .high = high, .low = low }, .{out});
}
pub fn MinusDmStream(comptime T: type) type {
    return vs.Stream(T, MINUS_DM);
}
pub fn plusDmLookback(p: WilderParams) Error!usize {
    try PLUS_DM.validate(p);
    return PLUS_DM.lookback(p);
}
pub fn plusDm(comptime T: type, high: []const T, low: []const T, out: []T, p: WilderParams) Error!usize {
    return vs.batch(T, PLUS_DM, p, .{ .high = high, .low = low }, .{out});
}
pub fn PlusDmStream(comptime T: type) type {
    return vs.Stream(T, PLUS_DM);
}
pub fn minusDiLookback(p: WilderParams) Error!usize {
    try MINUS_DI.validate(p);
    return MINUS_DI.lookback(p);
}
pub fn minusDi(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: WilderParams) Error!usize {
    return vs.batch(T, MINUS_DI, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn MinusDiStream(comptime T: type) type {
    return vs.Stream(T, MINUS_DI);
}
pub fn plusDiLookback(p: WilderParams) Error!usize {
    try PLUS_DI.validate(p);
    return PLUS_DI.lookback(p);
}
pub fn plusDi(comptime T: type, high: []const T, low: []const T, close: []const T, out: []T, p: WilderParams) Error!usize {
    return vs.batch(T, PLUS_DI, p, .{ .high = high, .low = low, .close = close }, .{out});
}
pub fn PlusDiStream(comptime T: type) type {
    return vs.Stream(T, PLUS_DI);
}

// ── AROON / AROONOSC ────────────────────────────────────────────────────────

pub const AroonParams = struct { period: usize = 14 };

/// Index of the latest lowest low / highest high of the last `period + 1` bars,
/// tracked incrementally as in TA_AROON (rescan only when the extreme left the
/// window; ties go to the newest bar).
const AroonState = struct {
    lo_idx: isize = -1,
    hi_idx: isize = -1,
    lowest: f64 = 0.0,
    highest: f64 = 0.0,

    fn update(self: *AroonState, src: anytype, b: vs.Hl(f64), today: usize, p: usize) void {
        const trailing: isize = @intCast(today - p);
        const t: isize = @intCast(today);
        if (self.lo_idx < trailing) {
            self.lo_idx = trailing;
            self.lowest = src.at(@intCast(trailing)).low;
            var i = trailing;
            while (i < t) {
                i += 1;
                const v = src.at(@intCast(i)).low;
                if (v <= self.lowest) {
                    self.lo_idx = i;
                    self.lowest = v;
                }
            }
        } else if (b.low <= self.lowest) {
            self.lo_idx = t;
            self.lowest = b.low;
        }
        if (self.hi_idx < trailing) {
            self.hi_idx = trailing;
            self.highest = src.at(@intCast(trailing)).high;
            var i = trailing;
            while (i < t) {
                i += 1;
                const v = src.at(@intCast(i)).high;
                if (v >= self.highest) {
                    self.hi_idx = i;
                    self.highest = v;
                }
            }
        } else if (b.high >= self.highest) {
            self.hi_idx = t;
            self.highest = b.high;
        }
    }
};

pub fn AroonCore(comptime osc: bool) type {
    return struct {
        const Self = @This();
        pub const In = vs.Hl(f64);
        pub const Out = if (osc) f64 else struct { down: f64, up: f64 };
        pub const Params = AroonParams;
        pub const windowed = true;
        pub fn Inputs(comptime T: type) type {
            return vs.Hl(T);
        }
        pub fn Outputs(comptime T: type) type {
            return if (osc) T else struct { down: T, up: T };
        }

        p: usize,
        factor: f64,
        n: usize = 0,
        st: AroonState = .{},

        pub fn validate(p: Params) Error!void {
            try core.checkPeriod(p.period, 2);
        }
        pub fn lookback(p: Params) usize {
            return p.period;
        }
        pub fn ringLen(p: Params) usize {
            return p.period + 1;
        }
        pub fn init(p: Params) Error!Self {
            try validate(p);
            return .{ .p = p.period, .factor = @as(f64, 100.0) / pf(p.period) };
        }
        pub fn step(self: *Self, src: anytype, b: In) ?Out {
            const today = self.n;
            self.n += 1;
            if (today < self.p) return null;
            self.st.update(src, b, today, self.p);
            if (osc) {
                const d: isize = self.st.hi_idx - self.st.lo_idx;
                return self.factor * @as(f64, @floatFromInt(d));
            }
            const t: isize = @intCast(today);
            const up: isize = @as(isize, @intCast(self.p)) - (t - self.st.hi_idx);
            const dn: isize = @as(isize, @intCast(self.p)) - (t - self.st.lo_idx);
            return .{ .up = self.factor * @as(f64, @floatFromInt(up)), .down = self.factor * @as(f64, @floatFromInt(dn)) };
        }
    };
}

pub const AROON = AroonCore(false);
pub const AROONOSC = AroonCore(true);

pub fn aroonLookback(p: AroonParams) Error!usize {
    try AROON.validate(p);
    return AROON.lookback(p);
}
/// Outputs `down` and `up` (TA-Lib's order).
pub fn aroon(comptime T: type, high: []const T, low: []const T, down: []T, up: []T, p: AroonParams) Error!usize {
    return vs.batch(T, AROON, p, .{ .high = high, .low = low }, .{ down, up });
}
pub fn AroonStream(comptime T: type) type {
    return vs.Stream(T, AROON);
}
pub fn aroonoscLookback(p: AroonParams) Error!usize {
    try AROONOSC.validate(p);
    return AROONOSC.lookback(p);
}
pub fn aroonosc(comptime T: type, high: []const T, low: []const T, out: []T, p: AroonParams) Error!usize {
    return vs.batch(T, AROONOSC, p, .{ .high = high, .low = low }, .{out});
}
pub fn AroonoscStream(comptime T: type) type {
    return vs.Stream(T, AROONOSC);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "wilder family: batch == streaming, lookback == NaN lead" {
    const ps = [_]WilderParams{ .{}, .{ .period = 2 }, .{ .period = 5, .unstable = .{ .bars = 4 } }, .{ .period = 3, .unstable = .auto4 }, .{ .period = 7, .unstable = .auto8 } };
    for (ps) |p| {
        try mu.checkCore(ADX, p, 300, 11);
        try mu.checkCore(ADXR, p, 300, 12);
        try mu.checkCore(DX, p, 300, 13);
        try mu.checkCore(MINUS_DI, p, 300, 14);
        try mu.checkCore(PLUS_DI, p, 300, 15);
        try mu.checkCore(MINUS_DM, p, 300, 16);
        try mu.checkCore(PLUS_DM, p, 300, 17);
    }
    // period 1 exists for the DI / DM functions
    const p1 = WilderParams{ .period = 1 };
    try mu.checkCore(MINUS_DI, p1, 80, 18);
    try mu.checkCore(PLUS_DI, p1, 80, 19);
    try mu.checkCore(MINUS_DM, p1, 80, 20);
    try mu.checkCore(PLUS_DM, p1, 80, 21);
}

test "wilder family: lookbacks" {
    try testing.expectEqual(@as(usize, 27), try adxLookback(.{}));
    try testing.expectEqual(@as(usize, 14), try dxLookback(.{}));
    try testing.expectEqual(@as(usize, 40), try adxrLookback(.{}));
    try testing.expectEqual(@as(usize, 14), try minusDiLookback(.{}));
    try testing.expectEqual(@as(usize, 13), try minusDmLookback(.{}));
    try testing.expectEqual(@as(usize, 1), try plusDmLookback(.{ .period = 1, .unstable = .auto8 }));
    // auto constants: ADX (10+6)p / (19+6)p, DX 10p / 19p, DM (10(2p-1)+1)/2 ...
    try testing.expectEqual(@as(usize, 27 + 16 * 14 - 0), try adxLookback(.{ .unstable = .auto4 }) + 0);
    try testing.expectEqual(@as(usize, 14 + 140), try dxLookback(.{ .unstable = .auto4 }));
    try testing.expectEqual(@as(usize, 14 + 135 - 1), try plusDmLookback(.{ .unstable = .auto4 }));
}

test "wilder family: BadParam" {
    var o: [4]f64 = undefined;
    const x = [_]f64{ 1, 2, 3, 4 };
    try testing.expectError(error.BadParam, adx(f64, &x, &x, &x, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, dx(f64, &x, &x, &x, &o, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, plusDi(f64, &x, &x, &x, &o, .{ .period = 0 }));
    try testing.expectError(error.BadParam, minusDm(f64, &x, x[0..3], &o, .{}));
    try testing.expectError(error.BadParam, adxr(f64, testing.allocator, &x, &x, &x, &o, .{ .period = 1 }));
    try testing.expectError(error.BadParam, aroon(f64, &x, &x, &o, &o, .{ .period = 1 }));
}

test "plus/minus DM hand vector" {
    // period 1: +DM = rise when it beats the fall, -DM = fall when it beats the rise.
    // highs 10 12 11 13, lows 8 9 7 8:  rises +2 -1 +2, falls -1 +2 -1
    const h = [_]f64{ 10, 12, 11, 13 };
    const l = [_]f64{ 8, 9, 7, 8 };
    var o: [4]f64 = undefined;
    _ = try plusDm(f64, &h, &l, &o, .{ .period = 1 });
    try testing.expect(std.math.isNan(o[0]));
    try testing.expectEqual(@as(f64, 2), o[1]);
    try testing.expectEqual(@as(f64, 0), o[2]);
    try testing.expectEqual(@as(f64, 2), o[3]);
    _ = try minusDm(f64, &h, &l, &o, .{ .period = 1 });
    try testing.expectEqual(@as(f64, 0), o[1]);
    try testing.expectEqual(@as(f64, 2), o[2]);
    try testing.expectEqual(@as(f64, 0), o[3]);
    // period 2: seed = +DM of bar 1 (2); bar 2: 2 - 2/2 + 0 = 1; bar 3: 1 - 0.5 + 2 = 2.5
    _ = try plusDm(f64, &h, &l, &o, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 2), o[1]);
    try testing.expectEqual(@as(f64, 1), o[2]);
    try testing.expectEqual(@as(f64, 2.5), o[3]);
}

test "aroon hand vector" {
    // period 2, highs 1 3 2 1 0.5 / lows 0 2 1 0 -1
    const h = [_]f64{ 1, 3, 2, 1, 0.5 };
    const l = [_]f64{ 0, 2, 1, 0, -1 };
    var dn: [5]f64 = undefined;
    var up: [5]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try aroon(f64, &h, &l, &dn, &up, .{ .period = 2 }));
    // bar 2: window bars 0..2: highest at 1 (1 bar ago) -> 50, lowest at 0 (2 ago) -> 0
    try testing.expectEqual(@as(f64, 50), up[2]);
    try testing.expectEqual(@as(f64, 0), dn[2]);
    // bar 4: window bars 2..4: highest at 2 (2 ago) -> 0, lowest at 4 -> 100
    try testing.expectEqual(@as(f64, 0), up[4]);
    try testing.expectEqual(@as(f64, 100), dn[4]);
    var osc: [5]f64 = undefined;
    _ = try aroonosc(f64, &h, &l, &osc, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 50), osc[2]);
    try testing.expectEqual(@as(f64, -100), osc[4]);
}

test "aroon and aroonosc: batch == streaming, f32" {
    try mu.checkCore(AROON, .{}, 300, 22);
    try mu.checkCore(AROON, .{ .period = 2 }, 120, 23);
    try mu.checkCore(AROONOSC, .{ .period = 9 }, 300, 24);
    try mu.checkF32(AROON, .{}, 100, 25);
    try mu.checkF32(ADX, .{}, 100, 26);
    try mu.checkF32(ADXR, .{ .period = 5 }, 100, 27);
    try mu.checkF32(MINUS_DI, .{}, 100, 28);
}
