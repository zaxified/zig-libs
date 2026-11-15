// SPDX-License-Identifier: MIT
//! CG (Ehlers' center of gravity), ported from TA-Lib 0.8.3 (`ta_CG.c`; BSD-3,
//! see NOTICE).
//!
//! TA-Lib evaluates `-sum(w_i x_i) / sum(x_i)` with an exact-arithmetic
//! scheme: the window sums are kept as two or three integer-valued "limbs" of
//! the scaled prices (rounded with the 1.5 * 2^52 trick) so that adding and
//! removing a bar is exact, and the scale is re-derived when a value no longer
//! fits. This port follows the C statement by statement; the state that the C
//! keeps in locals across bars (`limbs`, `scale`, `half`, the six sums,
//! `stickyBars`) lives in the core.

const std = @import("std");
const core = @import("core.zig");
const vs = @import("vs_kit.zig");
const mu = @import("mom_util.zig");
const Error = core.Error;
const pf = core.pf;

pub const CgParams = struct { period: usize = 10 };

const R: f64 = 6.755399441055744e15; // 1.5 * 2^52: (t + R) - R rounds t to an integer
const TWO52: f64 = 4.503599627370496e15;
const TWO53: f64 = 9.007199254740992e15;
const DBL_MAX: f64 = 1.7976931348623157e308;
const SCALE_CAP: f64 = 4.49423283715579e307;

fn roundInt(t: f64) f64 {
    return t + R - R;
}

/// The "does not fit" test of the scaling search.
fn misfit(y: f64, ylim: f64, x: f64) bool {
    return !(y < ylim) or (y < TWO52 and y + TWO52 - TWO52 != y) or (y == 0.0 and x != 0.0);
}

pub const CG = struct {
    const Self = @This();
    pub const In = vs.X(f64);
    pub const Out = f64;
    pub const Params = CgParams;
    pub const windowed = true;
    pub fn Inputs(comptime T: type) type {
        return vs.X(T);
    }
    pub fn Outputs(comptime T: type) type {
        return T;
    }

    l: usize,
    pd: f64,
    flat: f64,
    width2: f64,
    ylim2: f64,
    width3: f64,
    ylim3: f64,
    head2: f64,
    head3: f64,
    n: usize = 0,
    limbs: u8 = 0,
    sticky: usize = 0,
    scale: f64 = 1.0,
    width: f64 = 1.0,
    inv_width: f64 = 1.0,
    width_sq: f64 = 1.0,
    inv_width_sq: f64 = 1.0,
    ylim: f64 = 0.0,
    half: f64 = 1.0,
    den_a: f64 = 0.0,
    den_b: f64 = 0.0,
    den_c: f64 = 0.0,
    num_a: f64 = 0.0,
    num_b: f64 = 0.0,
    num_c: f64 = 0.0,
    num: f64 = 0.0,
    den: f64 = 0.0,

    pub fn validate(p: Params) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn lookback(p: Params) usize {
        return p.period - 1;
    }
    pub fn ringLen(p: Params) usize {
        return p.period;
    }
    pub fn init(p: Params) Error!Self {
        try validate(p);
        const pd = pf(p.period);
        var weight_total: f64 = 1.0;
        while (weight_total < pd * (pd + 1.0) * 0.5) weight_total *= 2.0;
        const width2 = TWO53 / weight_total;
        const ylim2 = 0.25 * width2 * width2;
        var width3 = width2;
        if (width3 > 67108864.0) width3 = 67108864.0;
        const ylim3 = 0.25 * width2 * width3 * width3;
        var head2: f64 = 1.0;
        while (head2 * head2 * TWO53 < ylim2) head2 *= 2.0;
        var head3: f64 = 1.0;
        while (head3 * head3 * TWO53 < ylim3) head3 *= 2.0;
        return .{
            .l = p.period - 1,
            .pd = pd,
            .flat = -(pd + 1.0) * 0.5,
            .width2 = width2,
            .ylim2 = ylim2,
            .width3 = width3,
            .ylim3 = ylim3,
            .head2 = head2,
            .head3 = head3,
        };
    }

    /// Add the limbs of one scaled value to the running sums (limbs == 2).
    fn limb2(self: *const Self, y: f64) struct { a: f64, c: f64 } {
        var t = y * self.inv_width;
        const a = roundInt(t);
        t = a * self.width;
        return .{ .a = a, .c = y - t };
    }
    const Limbs3 = struct { a: f64, b: f64, c: f64 };
    fn limb3(self: *const Self, y: f64) Limbs3 {
        var t = y * self.inv_width_sq;
        const a = roundInt(t);
        t = a * self.width_sq;
        const q = y - t;
        t = q * self.inv_width;
        const b = roundInt(t);
        t = b * self.width;
        return .{ .a = a, .b = b, .c = q - t };
    }

    pub fn step(self: *Self, src: anytype, in: In) ?f64 {
        const today = self.n;
        self.n += 1;
        if (today < self.l) return null;
        const first = today - self.l; // the bar leaving the window after this output
        var fits = false;
        const x0 = in.x;
        const y0 = x0 * self.scale;
        if (self.limbs == 2) {
            if (@abs(y0) < self.ylim and (y0 != 0.0 or x0 == 0.0)) {
                const v = self.limb2(y0);
                if (roundInt(v.c) == v.c) {
                    self.den_a += v.a;
                    self.den_c += v.c;
                    self.num_a += self.den_a;
                    self.num_c += self.den_c;
                    fits = true;
                }
            }
        } else if (self.limbs == 3) {
            if (@abs(y0) < self.ylim and (y0 != 0.0 or x0 == 0.0)) {
                const v = self.limb3(y0);
                if (roundInt(v.c) == v.c) {
                    self.den_a += v.a;
                    self.den_b += v.b;
                    self.den_c += v.c;
                    self.num_a += self.den_a;
                    self.num_b += self.den_b;
                    self.num_c += self.den_c;
                    fits = true;
                }
            }
        }
        if (!fits and self.limbs == 0 and self.sticky > 0) {
            self.sticky -= 1;
            self.num = 0.0;
            self.den = 0.0;
            var j = first;
            while (j <= today) : (j += 1) {
                self.den += src.at(j).x;
                self.num += self.den;
            }
        } else if (!fits) {
            self.rescale(src, first, today);
        }
        if (self.limbs == 2) {
            var t = self.den_a * self.width;
            self.den = t + self.den_c;
            t = self.num_a * self.width;
            self.num = t + self.num_c;
        } else if (self.limbs == 3) {
            self.den = self.fold3(self.den_a, self.den_b, self.den_c);
            self.num = self.fold3(self.num_a, self.num_b, self.num_c);
        }
        const value = if (self.den != 0.0) -self.num / self.den else self.flat;
        // retire the oldest bar
        if (self.limbs == 2) {
            const v = self.limb2(src.at(first).x * self.scale);
            self.den_a -= v.a;
            self.den_c -= v.c;
            self.num_a -= self.pd * v.a;
            self.num_c -= self.pd * v.c;
        } else if (self.limbs == 3) {
            const v = self.limb3(src.at(first).x * self.scale);
            self.den_a -= v.a;
            self.den_b -= v.b;
            self.den_c -= v.c;
            self.num_a -= self.pd * v.a;
            self.num_b -= self.pd * v.b;
            self.num_c -= self.pd * v.c;
        }
        return value;
    }

    /// Fold three limbs back into one double, as the C does.
    fn fold3(self: *const Self, a_in: f64, b_in: f64, c_in: f64) f64 {
        var t = c_in * self.inv_width;
        var q = roundInt(t);
        var b = b_in + q;
        t = q * self.width;
        var c = c_in - t;
        t = b * self.inv_width;
        q = roundInt(t);
        t = q * self.width;
        b = b - t;
        t = b * self.width;
        c = t + c;
        t = a_in + q;
        t = t * self.width_sq;
        return t + c;
    }

    /// The value no longer fits the current scale (or there is none yet): look
    /// for a new scale from the window, or fall back to plain sums for a while.
    fn rescale(self: *Self, src: anytype, first: usize, today: usize) void {
        var max_abs: f64 = 0.0;
        var max_at: usize = 0;
        var k: usize = 0;
        var j = first;
        while (j <= today) : (j += 1) {
            const x = @abs(src.at(j).x);
            if (x >= max_abs) {
                max_abs = x;
                max_at = k;
            }
            k += 1;
        }
        if (max_abs > 0.0 and max_abs <= DBL_MAX) {
            while (self.half * 65536.0 <= max_abs) self.half *= 65536.0;
            while (self.half * 2.0 <= max_abs) self.half *= 2.0;
            while (self.half > max_abs * 65536.0) self.half *= 0.0000152587890625;
            while (self.half > max_abs) self.half *= 0.5;
        }
        var scale2_lo = self.ylim2 * 0.5 / self.half;
        if (scale2_lo > SCALE_CAP) scale2_lo = SCALE_CAP;
        const scale2_mid = scale2_lo / self.head2;
        var scale3_lo = self.ylim3 * 0.5 / self.half;
        if (scale3_lo > SCALE_CAP) scale3_lo = SCALE_CAP;
        const scale3_mid = scale3_lo / self.head3;
        var fit2_mid = true;
        var fit2_lo = true;
        var fit3_mid = true;
        var fail_at: isize = -1;
        self.num = 0.0;
        self.den = 0.0;
        k = 0;
        j = first;
        while (j <= today) : (j += 1) {
            const x = src.at(j).x;
            self.den += x;
            self.num += self.den;
            if (misfit(@abs(x * scale2_mid), self.ylim2, x)) fit2_mid = false;
            if (misfit(@abs(x * scale2_lo), self.ylim2, x)) fit2_lo = false;
            if (misfit(@abs(x * scale3_mid), self.ylim3, x)) fit3_mid = false;
            if (misfit(@abs(x * scale3_lo), self.ylim3, x)) fail_at = @intCast(k);
            k += 1;
        }
        self.limbs = 0;
        if (fail_at >= 0) {
            const fa: usize = @intCast(fail_at);
            self.sticky = if (fa < max_at) fa else max_at;
            return;
        }
        if (fit2_mid or fit2_lo) {
            self.limbs = 2;
            self.width = self.width2;
            self.ylim = self.ylim2;
            self.scale = if (fit2_mid) scale2_mid else scale2_lo;
        } else {
            self.limbs = 3;
            self.width = self.width3;
            self.ylim = self.ylim3;
            self.scale = if (fit3_mid) scale3_mid else scale3_lo;
        }
        self.inv_width = 1.0 / self.width;
        self.width_sq = self.width * self.width;
        self.inv_width_sq = self.inv_width * self.inv_width;
        self.den_a = 0.0;
        self.den_b = 0.0;
        self.den_c = 0.0;
        self.num_a = 0.0;
        self.num_b = 0.0;
        self.num_c = 0.0;
        j = first;
        while (j <= today) : (j += 1) {
            const y = src.at(j).x * self.scale;
            if (self.limbs == 2) {
                const v = self.limb2(y);
                self.den_a += v.a;
                self.den_c += v.c;
                self.num_a += self.den_a;
                self.num_c += self.den_c;
            } else {
                const v = self.limb3(y);
                self.den_a += v.a;
                self.den_b += v.b;
                self.den_c += v.c;
                self.num_a += self.den_a;
                self.num_b += self.den_b;
                self.num_c += self.den_c;
            }
        }
    }
};

pub fn cgLookback(p: CgParams) Error!usize {
    try CG.validate(p);
    return CG.lookback(p);
}
pub fn cg(comptime T: type, in: []const T, out: []T, p: CgParams) Error!usize {
    return vs.batch(T, CG, p, .{ .x = in }, .{out});
}
pub fn CgStream(comptime T: type) type {
    return vs.SingleStream(T, CG);
}

const testing = std.testing;

test "cg: batch == streaming, lookback == NaN lead, f32" {
    try mu.checkCore(CG, .{}, 300, 1);
    try mu.checkCore(CG, .{ .period = 2 }, 100, 2);
    try mu.checkCore(CG, .{ .period = 40 }, 300, 3);
    try mu.checkF32(CG, .{}, 80, 4);
}

test "cg: hand vector and degenerate windows" {
    // window 1 2 3 (period 3): -sum((i+1) x_i)... TA-Lib: num = sum_{k} cumulative den,
    // value = -num / den with den = 1+2+3 = 6 and num = 1 + 3 + 6 = 10 -> -10/6
    const x = [_]f64{ 1, 2, 3 };
    var o: [3]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try cg(f64, &x, &o, .{ .period = 3 }));
    try testing.expectApproxEqAbs(@as(f64, -10.0 / 6.0), o[2], 1e-15);
    // a window summing to zero answers the flat value -(p + 1) / 2
    const z = [_]f64{ 1, -1, 1, -1 };
    var o4: [4]f64 = undefined;
    _ = try cg(f64, &z, &o4, .{ .period = 2 });
    try testing.expectEqual(@as(f64, -1.5), o4[1]);
    try testing.expectError(error.BadParam, cg(f64, &x, &o, .{ .period = 1 }));
}

test "cg: wide magnitude swings (rescale and sticky paths) stay finite" {
    var xs: [200]f64 = undefined;
    var prng = std.Random.DefaultPrng.init(9);
    const r = prng.random();
    for (&xs, 0..) |*v, i| {
        const mag: f64 = if (i % 37 < 5) 1e-300 else if (i % 41 < 4) 1e150 else 100.0;
        v.* = (r.float(f64) - 0.3) * mag;
    }
    var o: [200]f64 = undefined;
    _ = try cg(f64, &xs, &o, .{ .period = 7 });
    for (o[6..]) |v| try testing.expect(!std.math.isNan(v));
    try mu.checkCore(CG, .{ .period = 7 }, 50, 5);
}
