// SPDX-License-Identifier: MIT
//! MACD, MACDEXT and MACDFIX, ported from TA-Lib 0.8.3 (`ta_MACD.c`,
//! `ta_MACDEXT.c`, `ta_MACDFIX.c`; BSD-3, see NOTICE).
//!
//! The line is `fast - slow`, the signal is a moving average of the line and
//! the histogram is `line - signal`. TA-Lib places every component so that its
//! first output falls on the bar where the slowest one has its first output
//! (a component with a smaller lookback is simply fed from a later bar, which
//! changes the seeding window of an SMA/WMA/EMA and so the last bits of the
//! result): `skip = largest lookback - own lookback`.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const th = @import("testhelp.zig");
const Error = core.Error;
const Nan = core.Nan;
const Seed = core.Seed;
const Unstable = core.Unstable;
const MaType = core.MaType;
const EmaCore = smooth.EmaCore;
const MaCore = smooth.MaCore;
const MaParams = smooth.MaParams;
const Stage = smooth.Stage;
const NoSrc = smooth.NoSrc;
const SliceSrc = core.SliceSrc;

pub fn MacdOut(comptime T: type) type {
    return struct { macd: T, signal: T, hist: T };
}
const Out64 = MacdOut(f64);

// ── MACD / MACDFIX (EMA based) ──────────────────────────────────────────────

pub const MacdParams = struct {
    fast: usize = 12,
    slow: usize = 26,
    signal: usize = 9,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
    seed: Seed = .sma,
};

pub const MacdfixParams = struct {
    signal: usize = 9,
    unstable: Unstable = core.no_unstable,
    nan: Nan = .propagate,
    seed: Seed = .sma,
};

/// Three EMAs in lockstep: slow from bar 0, fast from `skip_fast`, the signal
/// from the first line bar.
pub const MacdCore = struct {
    slow: EmaCore,
    fast: EmaCore,
    sig: EmaCore,
    skip_fast: usize,
    /// signal period 1 with no unstable bars: TA-Lib's first signal value is
    /// `0.0 + line` (it seeds an SMA of one value), later ones copy the line.
    seed_quirk: bool,
    lb: usize,
    n: usize = 0,
    sig_first: bool = true,

    pub fn validate(p: MacdParams) Error!void {
        try core.checkPeriod(p.fast, 2);
        try core.checkPeriod(p.slow, 2);
        try core.checkPeriod(p.signal, 1);
        try p.unstable.check();
    }
    fn ordered(p: MacdParams) [2]usize {
        return if (p.slow < p.fast) .{ p.slow, p.fast } else .{ p.fast, p.slow };
    }
    pub fn lookback(p: MacdParams) usize {
        const fs = ordered(p);
        return EmaCore.lookbackOf(fs[1], p.unstable, p.seed) + EmaCore.lookbackOf(p.signal, p.unstable, p.seed);
    }
    pub fn init(p: MacdParams) Error!MacdCore {
        try validate(p);
        const fs = ordered(p);
        const first = p.seed == .first;
        const ls = EmaCore.lookbackOf(fs[1], p.unstable, p.seed);
        const lf = EmaCore.lookbackOf(fs[0], p.unstable, p.seed);
        const bs = EmaCore.betaK(fs[1]);
        const bf = EmaCore.betaK(fs[0]);
        const bg = EmaCore.betaK(p.signal);
        const ug = EmaCore.unstableOf(p.signal, p.unstable);
        return .{
            .slow = EmaCore.initRaw(fs[1], bs[0], bs[1], EmaCore.unstableOf(fs[1], p.unstable), first),
            .fast = EmaCore.initRaw(fs[0], bf[0], bf[1], EmaCore.unstableOf(fs[0], p.unstable), first),
            .sig = EmaCore.initRaw(p.signal, bg[0], bg[1], ug, first),
            .skip_fast = if (first) 0 else ls - lf,
            .seed_quirk = p.signal == 1 and ug == 0 and !first,
            .lb = lookback(p),
        };
    }
    /// MACDFIX: 12/26 with the fixed smoothing factors 0.15 and 0.075 (not
    /// 2/(p+1)); beta is 1 - k and k is re-derived from it, no `beta < 0.5` swap.
    pub fn initFix(p: MacdfixParams) Error!MacdCore {
        try core.checkPeriod(p.signal, 1);
        try p.unstable.check();
        const first = p.seed == .first;
        // Typed f64 on purpose: untyped float literals are folded at comptime with
        // more than double precision and `1 - (1 - k)` would not be TA-Lib's value.
        const k12: f64 = 0.15;
        const k26: f64 = 0.075;
        const fast_beta: f64 = 1.0 - k12;
        const fast_k: f64 = 1.0 - fast_beta;
        const slow_beta: f64 = 1.0 - k26;
        const slow_k: f64 = 1.0 - slow_beta;
        const bg = EmaCore.betaK(p.signal);
        const us = EmaCore.unstableOf(26, p.unstable);
        const ug = EmaCore.unstableOf(p.signal, p.unstable);
        return .{
            .slow = EmaCore.initRaw(26, slow_beta, slow_k, us, first),
            // The fast window is the tail of the slow window and runs as many
            // unstable bars as the slow EMA does.
            .fast = EmaCore.initRaw(12, fast_beta, fast_k, us, first),
            .sig = EmaCore.initRaw(p.signal, bg[0], bg[1], ug, first),
            .skip_fast = if (first) 0 else 26 - 12,
            .seed_quirk = p.signal == 1 and ug == 0 and !first,
            .lb = EmaCore.lookbackOf(26, p.unstable, p.seed) + EmaCore.lookbackOf(p.signal, p.unstable, p.seed),
        };
    }
    pub fn lookbackFix(p: MacdfixParams) usize {
        return EmaCore.lookbackOf(26, p.unstable, p.seed) + EmaCore.lookbackOf(p.signal, p.unstable, p.seed);
    }
    pub fn step(self: *MacdCore, src: anytype, x: f64) ?Out64 {
        _ = src;
        const n = self.n;
        self.n += 1;
        const s = self.slow.step(NoSrc{}, x);
        const f = if (n >= self.skip_fast) self.fast.step(NoSrc{}, x) else null;
        if (s == null or f == null) return null;
        const line = f.? - s.?;
        var sg = self.sig.step(NoSrc{}, line) orelse return null;
        if (self.sig_first) {
            self.sig_first = false;
            if (self.seed_quirk) sg = 0.0 + line;
        }
        return .{ .macd = line, .signal = sg, .hist = line - sg };
    }
};

/// Adapter so MACDFIX has the same `init(p)` / `lookback(p)` shape.
pub const MacdfixCore = struct {
    pub fn validate(p: MacdfixParams) Error!void {
        try core.checkPeriod(p.signal, 1);
        try p.unstable.check();
    }
    pub fn lookback(p: MacdfixParams) usize {
        return MacdCore.lookbackFix(p);
    }
    pub fn init(p: MacdfixParams) Error!MacdCore {
        return MacdCore.initFix(p);
    }
};

fn nanSkip(p: anytype) bool {
    if (@hasField(@TypeOf(p), "nan")) return p.nan == .skip;
    return false;
}

fn batch3(comptime T: type, comptime Core: type, in: []const T, o_macd: []T, o_sig: []T, o_hist: []T, p: anytype) Error!usize {
    core.checkFloat(T);
    try core.checkLen(in.len, &.{ o_macd.len, o_sig.len, o_hist.len });
    var c = try Core.init(p);
    const skip = nanSkip(p);
    const nan = std.math.nan(T);
    var last = MacdOut(T){ .macd = nan, .signal = nan, .hist = nan };
    for (in, o_macd, o_sig, o_hist) |x, *a, *b, *h| {
        const xv: f64 = x;
        if (skip and core.isNan(xv)) {
            a.* = last.macd; // carry the previous output over the skipped bar
            b.* = last.signal;
            h.* = last.hist;
            continue;
        }
        if (c.step(NoSrc{}, xv)) |r| {
            const o = core.to(MacdOut(T), r);
            a.* = o.macd;
            b.* = o.signal;
            h.* = o.hist;
            last = o;
        } else {
            a.* = nan;
            b.* = nan;
            h.* = nan;
        }
    }
    return Core.lookback(p);
}

fn Rec3(comptime T: type, comptime Params: type, comptime Core: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        c: MacdCore,
        skip: bool,
        last: ?MacdOut(T) = null,

        pub fn init(p: Params) Error!Self {
            return .{ .c = try Core.init(p), .skip = nanSkip(p) };
        }
        pub fn update(self: *Self, x: T) ?MacdOut(T) {
            const xv: f64 = x;
            if (self.skip and core.isNan(xv)) return self.last;
            const r = self.c.step(NoSrc{}, xv) orelse return null;
            self.last = core.to(MacdOut(T), r);
            return self.last;
        }
        pub fn peek(self: *const Self, x: T) ?MacdOut(T) {
            const xv: f64 = x;
            if (self.skip and core.isNan(xv)) return self.last;
            var cc = self.c;
            const r = cc.step(NoSrc{}, xv) orelse return null;
            return core.to(MacdOut(T), r);
        }
        pub fn value(self: *const Self) ?MacdOut(T) {
            return self.last;
        }
    };
}

pub fn macdLookback(p: MacdParams) Error!usize {
    try MacdCore.validate(p);
    return MacdCore.lookback(p);
}
pub fn macd(comptime T: type, in: []const T, out_macd: []T, out_signal: []T, out_hist: []T, p: MacdParams) Error!usize {
    return batch3(T, MacdCore, in, out_macd, out_signal, out_hist, p);
}
pub fn MacdStream(comptime T: type) type {
    return Rec3(T, MacdParams, MacdCore);
}

pub fn macdfixLookback(p: MacdfixParams) Error!usize {
    try MacdfixCore.validate(p);
    return MacdfixCore.lookback(p);
}
pub fn macdfix(comptime T: type, in: []const T, out_macd: []T, out_signal: []T, out_hist: []T, p: MacdfixParams) Error!usize {
    return batch3(T, MacdfixCore, in, out_macd, out_signal, out_hist, p);
}
pub fn MacdfixStream(comptime T: type) type {
    return Rec3(T, MacdfixParams, MacdfixCore);
}

// ── MACDEXT (any MA type per line) ──────────────────────────────────────────

pub const MacdextParams = struct {
    fast: usize = 12,
    fast_ma: MaType = .sma,
    slow: usize = 26,
    slow_ma: MaType = .sma,
    signal: usize = 9,
    signal_ma: MaType = .sma,
    unstable: Unstable = core.no_unstable,
    seed: Seed = .sma,
};

const ExtPlan = struct {
    fast: MaParams,
    slow: MaParams,
    sig: MaParams,
    lb_fast: usize,
    lb_slow: usize,
    lb_sig: usize,
    lmax: usize,

    fn make(p: MacdextParams) Error!ExtPlan {
        try core.checkPeriod(p.fast, 2);
        try core.checkPeriod(p.slow, 2);
        try core.checkPeriod(p.signal, 1);
        // TA-Lib swaps the periods AND the types when slow < fast.
        const swap = p.slow < p.fast;
        const fast = MaParams{
            .period = if (swap) p.slow else p.fast,
            .kind = if (swap) p.slow_ma else p.fast_ma,
            .unstable = p.unstable,
            .seed = p.seed,
        };
        const slow = MaParams{
            .period = if (swap) p.fast else p.slow,
            .kind = if (swap) p.fast_ma else p.slow_ma,
            .unstable = p.unstable,
            .seed = p.seed,
        };
        const sig = MaParams{ .period = p.signal, .kind = p.signal_ma, .unstable = p.unstable, .seed = p.seed };
        try MaCore.validate(fast);
        try MaCore.validate(slow);
        try MaCore.validate(sig);
        const lf = MaCore.lookback(fast);
        const ls = MaCore.lookback(slow);
        return .{
            .fast = fast,
            .slow = slow,
            .sig = sig,
            .lb_fast = lf,
            .lb_slow = ls,
            .lb_sig = MaCore.lookback(sig),
            .lmax = @max(lf, ls),
        };
    }
    fn total(self: ExtPlan) usize {
        return self.lmax + self.lb_sig;
    }
};

pub fn macdextLookback(p: MacdextParams) Error!usize {
    return (try ExtPlan.make(p)).total();
}

/// MACDEXT. All intermediate series are f64 whatever `T` is: with `f64` the
/// line is built in `out_macd` itself, with `f32` a scratch of `in.len` f64 is
/// allocated from `gpa` and freed before returning.
pub fn macdext(comptime T: type, gpa: std.mem.Allocator, in: []const T, out_macd: []T, out_signal: []T, out_hist: []T, p: MacdextParams) core.AllocError!usize {
    core.checkFloat(T);
    try core.checkLen(in.len, &.{ out_macd.len, out_signal.len, out_hist.len });
    const plan = try ExtPlan.make(p);
    var cf = try MaCore.init(plan.fast);
    var cs = try MaCore.init(plan.slow);
    var cg = try MaCore.init(plan.sig);
    const skip_f = plan.lmax - plan.lb_fast;
    const skip_s = plan.lmax - plan.lb_slow;
    const nan = std.math.nan(T);
    var owned: []f64 = &.{};
    defer if (T != f64) gpa.free(owned);
    const line: []f64 = if (T == f64) out_macd else blk: {
        owned = try gpa.alloc(f64, in.len);
        break :blk owned;
    };
    @memset(out_macd, nan);
    @memset(out_signal, nan);
    @memset(out_hist, nan);
    const sf = SliceSrc(T){ .xs = in, .off = skip_f };
    const ss = SliceSrc(T){ .xs = in, .off = skip_s };
    const sg = SliceSrc(f64){ .xs = line, .off = plan.lmax };
    for (in, 0..) |x, i| {
        const xv: f64 = x;
        const f = if (i >= skip_f) cf.step(sf, xv) else null;
        const s = if (i >= skip_s) cs.step(ss, xv) else null;
        if (f == null or s == null) continue;
        line[i] = f.? - s.?;
        const g = cg.step(sg, line[i]) orelse continue;
        out_macd[i] = core.to(T, line[i]);
        out_signal[i] = core.to(T, g);
        out_hist[i] = core.to(T, line[i] - g);
    }
    // The line is defined from `lmax`, but TA-Lib outputs all three from the
    // signal's first bar: blank the earlier line values (the signal read them above).
    @memset(out_macd[@min(plan.lmax, in.len)..@min(plan.total(), in.len)], nan);
    return plan.total();
}

/// Streaming MACDEXT. The three stages keep rings of their own in the
/// caller's buffer (`bufLen`); copies share it, `clone` copies it.
pub fn MacdextStream(comptime T: type) type {
    core.checkFloat(T);
    return struct {
        const Self = @This();
        fast: Stage,
        slow: Stage,
        sig: Stage,
        skip_f: usize,
        skip_s: usize,
        lmax: usize,
        n: usize = 0,
        last: ?MacdOut(T) = null,

        pub fn bufLen(p: MacdextParams) Error!usize {
            const plan = try ExtPlan.make(p);
            return MaCore.ringLen(plan.fast) + MaCore.ringLen(plan.slow) + MaCore.ringLen(plan.sig);
        }
        pub fn init(p: MacdextParams, buf: []f64) Error!Self {
            const plan = try ExtPlan.make(p);
            var rest = buf;
            return .{
                .fast = try Stage.init(plan.fast, &rest),
                .slow = try Stage.init(plan.slow, &rest),
                .sig = try Stage.init(plan.sig, &rest),
                .skip_f = plan.lmax - plan.lb_fast,
                .skip_s = plan.lmax - plan.lb_slow,
                .lmax = plan.lmax,
            };
        }
        fn run(self: *Self, x: T, comptime dry: bool) ?MacdOut(T) {
            const xv: f64 = x;
            const n = self.n;
            if (!dry) self.n += 1;
            const f = if (n >= self.skip_f) self.fast.feed(xv, dry) else null;
            const s = if (n >= self.skip_s) self.slow.feed(xv, dry) else null;
            if (f == null or s == null) return null;
            const line = f.? - s.?;
            const g = self.sig.feed(line, dry) orelse return null;
            return core.to(MacdOut(T), Out64{ .macd = line, .signal = g, .hist = line - g });
        }
        pub fn update(self: *Self, x: T) ?MacdOut(T) {
            const r = self.run(x, false) orelse return null;
            self.last = r;
            return r;
        }
        pub fn peek(self: *const Self, x: T) ?MacdOut(T) {
            var cp = self.*;
            return cp.run(x, true);
        }
        pub fn value(self: *const Self) ?MacdOut(T) {
            return self.last;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn macdextT(comptime T: type, in: []const T, a: []T, b: []T, h: []T, p: MacdextParams) core.AllocError!usize {
    return macdext(T, testing.allocator, in, a, b, h, p);
}

fn check3(comptime Stream: anytype, comptime batch: anytype, comptime lbFn: anytype, xs: []const f64, p: anytype, comptime buffered: bool) !void {
    const S = Stream(f64);
    const n = xs.len;
    const a = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(a);
    const b = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(b);
    const h = try testing.allocator.alloc(f64, n);
    defer testing.allocator.free(h);
    const lb = try batch(f64, xs, a, b, h, p);
    try testing.expectEqual(try lbFn(p), lb);
    try testing.expectEqual(lb, th.leadingNan(a));
    try testing.expectEqual(lb, th.leadingNan(b));
    try testing.expectEqual(lb, th.leadingNan(h));
    const buf: []f64 = if (buffered) try testing.allocator.alloc(f64, try S.bufLen(p)) else &.{};
    defer if (buffered) testing.allocator.free(buf);
    var s = if (buffered) try S.init(p, buf) else try S.init(p);
    for (xs, a, b, h) |x, wa, wb, wh| {
        const pk = s.peek(x);
        const got = s.update(x);
        if (got) |g| {
            try testing.expect(th.sameBits(g.macd, wa) and th.sameBits(g.signal, wb) and th.sameBits(g.hist, wh));
            try testing.expect(pk != null and th.sameBits(pk.?.signal, g.signal) and th.sameBits(pk.?.macd, g.macd));
        } else {
            try testing.expect(std.math.isNan(wa) and std.math.isNan(wb) and std.math.isNan(wh) and pk == null);
        }
    }
}

test "macd hand-checked vector (period 2/3/2 on a 6 bar series)" {
    // fast 2 (beta = 1/3 -> k = 2/3, re-derived beta = 1 - k), slow 3 (beta = k = 0.5), signal 2.
    // input 1 2 3 4 6 5. Slow seed at bar 2 = (1+2+3)/3 = 2; fast window = bars 1..2 -> (2+3)/2 = 2.5.
    //   line[2] = 2.5 - 2 = 0.5
    //   bar 3: slow = 0.5*2 + 0.5*4 = 3; fast = beta*2.5 + k*4 with beta = 1/3, k = 2/3 -> 0.8333+2.6667 = 3.5; line = 0.5
    //   signal seed = (line[2] + line[3]) / 2 = 0.5 at bar 3 (the first output).
    //   bar 4: slow = 0.5*3 + 0.5*6 = 4.5; fast = 3.5/3 + 2/3*6 = 5.1667; line = 0.6667
    //     signal = beta(1/3)*0.5 + k(2/3)*0.6667 = 0.1667 + 0.4444 = 0.6111; hist = 0.0556
    const in = [_]f64{ 1, 2, 3, 4, 6, 5 };
    var a: [6]f64 = undefined;
    var b: [6]f64 = undefined;
    var h: [6]f64 = undefined;
    try testing.expectEqual(@as(usize, 3), try macd(f64, &in, &a, &b, &h, .{ .fast = 2, .slow = 3, .signal = 2 }));
    try testing.expect(std.math.isNan(a[2]) and std.math.isNan(b[2]));
    try testing.expectApproxEqAbs(@as(f64, 0.5), a[3], 1e-14);
    try testing.expectApproxEqAbs(@as(f64, 0.5), b[3], 1e-14);
    try testing.expectApproxEqAbs(@as(f64, 0.0), h[3], 1e-14);
    try testing.expectApproxEqAbs(@as(f64, 2.0 / 3.0), a[4], 1e-14);
    try testing.expectApproxEqAbs(@as(f64, 0.61111111111111), b[4], 1e-13);
    try testing.expectApproxEqAbs(@as(f64, 0.05555555555556), h[4], 1e-13);
    // slow < fast swaps them
    var a2: [6]f64 = undefined;
    var b2: [6]f64 = undefined;
    var h2: [6]f64 = undefined;
    _ = try macd(f64, &in, &a2, &b2, &h2, .{ .fast = 3, .slow = 2, .signal = 2 });
    try th.expectSameBits(&a, &a2);
}

test "macd signal period 1: the signal is the line, the histogram zero" {
    var xs: [60]f64 = undefined;
    th.walk(&xs, 51);
    var a: [60]f64 = undefined;
    var b: [60]f64 = undefined;
    var h: [60]f64 = undefined;
    try testing.expectEqual(@as(usize, 25), try macd(f64, &xs, &a, &b, &h, .{ .signal = 1 }));
    for (25..60) |i| {
        try testing.expectEqual(a[i], b[i]);
        try testing.expectEqual(@as(f64, 0), h[i]);
    }
}

test "macd lookback with unstable and AUTO" {
    try testing.expectEqual(@as(usize, 25 + 8), try macdLookback(.{}));
    try testing.expectEqual(@as(usize, 33 + 10), try macdLookback(.{ .unstable = .{ .bars = 5 } }));
    // auto4: slow 26 -> (261)/2 = 130, signal 9 -> 91/2 = 45
    try testing.expectEqual(@as(usize, 25 + 130 + 8 + 45), try macdLookback(.{ .unstable = .auto4 }));
}

test "macdfix uses 0.15 / 0.075, not 2/(p+1)" {
    // MACDFIX(signal) differs from MACD(12, 26, signal) because k(12) = 0.15 vs 2/13.
    var xs: [80]f64 = undefined;
    th.walk(&xs, 61);
    var a: [80]f64 = undefined;
    var b: [80]f64 = undefined;
    var h: [80]f64 = undefined;
    var a2: [80]f64 = undefined;
    var b2: [80]f64 = undefined;
    var h2: [80]f64 = undefined;
    try testing.expectEqual(@as(usize, 33), try macdfix(f64, &xs, &a, &b, &h, .{}));
    _ = try macd(f64, &xs, &a2, &b2, &h2, .{});
    try testing.expect(a[40] != a2[40]);
    // The line is bounded by the fixed-k EMA difference: compare with an explicit recursion.
    var fast: f64 = 0;
    var slow: f64 = 0;
    for (xs[0..26]) |v| slow += v;
    slow /= 26.0;
    for (xs[14..26]) |v| fast += v;
    fast /= 12.0;
    const k12: f64 = 0.15;
    const k26: f64 = 0.075;
    const fb: f64 = 1.0 - k12;
    const fk: f64 = 1.0 - fb;
    const sb: f64 = 1.0 - k26;
    const sk: f64 = 1.0 - sb;
    var line_at: [80]f64 = undefined;
    line_at[25] = fast - slow;
    for (26..80) |i| {
        fast = @mulAdd(f64, fb, fast, fk * xs[i]);
        slow = @mulAdd(f64, sb, slow, sk * xs[i]);
        line_at[i] = fast - slow;
    }
    for (33..80) |i| try testing.expectEqual(line_at[i], a[i]);
}

test "macdext: SMA lines hand-check, swap, all-EMA equals macd, unsupported" {
    // fast SMA 2, slow SMA 3, signal SMA 2 on 1 2 3 4 6 5:
    //   fast: 1.5 2.5 3.5 5 5.5 ; slow: 2 3 4.33.. 5 (bars 2..5) ; both from bar 2:
    //   line[2] = 2.5-2 = 0.5, line[3] = 3.5-3 = 0.5, line[4] = 5 - 13/3 = 2/3, line[5] = 5.5 - 5 = 0.5
    //   signal (SMA 2 of the line) at bar 3 = 0.5, bar 4 = (0.5+2/3)/2, bar 5 = (2/3+0.5)/2
    const in = [_]f64{ 1, 2, 3, 4, 6, 5 };
    var a: [6]f64 = undefined;
    var b: [6]f64 = undefined;
    var h: [6]f64 = undefined;
    try testing.expectEqual(@as(usize, 3), try macdext(f64, testing.allocator, &in, &a, &b, &h, .{ .fast = 2, .slow = 3, .signal = 2 }));
    try testing.expect(std.math.isNan(a[2]));
    try testing.expectApproxEqAbs(@as(f64, 0.5), a[3], 1e-14);
    try testing.expectApproxEqAbs(@as(f64, 0.5), b[3], 1e-14);
    try testing.expectApproxEqAbs(@as(f64, 2.0 / 3.0), a[4], 1e-14);
    try testing.expectApproxEqAbs(@as(f64, (0.5 + 2.0 / 3.0) / 2.0), b[4], 1e-14);
    try testing.expectApproxEqAbs(@as(f64, 0.5), a[5], 1e-14);
    try testing.expectApproxEqAbs(@as(f64, (2.0 / 3.0 + 0.5) / 2.0), b[5], 1e-14);
    // swapped periods swap the types too
    var a2: [6]f64 = undefined;
    var b2: [6]f64 = undefined;
    var h2: [6]f64 = undefined;
    _ = try macdext(f64, testing.allocator, &in, &a2, &b2, &h2, .{ .fast = 3, .slow = 2, .signal = 2 });
    try th.expectSameBits(&a, &a2);
    // all-EMA agrees with macd (TA-Lib delegates that case to MACD)
    var xs: [120]f64 = undefined;
    th.walk(&xs, 71);
    var m1: [120]f64 = undefined;
    var m2: [120]f64 = undefined;
    var m3: [120]f64 = undefined;
    var e1: [120]f64 = undefined;
    var e2: [120]f64 = undefined;
    var e3: [120]f64 = undefined;
    _ = try macd(f64, &xs, &m1, &m2, &m3, .{ .unstable = .{ .bars = 6 } });
    _ = try macdext(f64, testing.allocator, &xs, &e1, &e2, &e3, .{ .fast_ma = .ema, .slow_ma = .ema, .signal_ma = .ema, .unstable = .{ .bars = 6 } });
    try th.expectSameBits(&m1, &e1);
    try th.expectSameBits(&m2, &e2);
    try th.expectSameBits(&m3, &e3);
    try testing.expectError(error.Unsupported, macdext(f64, testing.allocator, &in, &a, &b, &h, .{ .fast = 2, .slow = 3, .fast_ma = .dema }));
}

test "macd family: BadParam" {
    const in = [_]f64{ 1, 2, 3, 4, 5, 6 };
    var a: [6]f64 = undefined;
    var b: [6]f64 = undefined;
    var h: [6]f64 = undefined;
    try testing.expectError(error.BadParam, macd(f64, &in, &a, &b, &h, .{ .fast = 1 }));
    try testing.expectError(error.BadParam, macd(f64, &in, &a, &b, &h, .{ .slow = 100001 }));
    try testing.expectError(error.BadParam, macd(f64, &in, &a, &b, &h, .{ .signal = 0 }));
    try testing.expectError(error.BadParam, macd(f64, &in, &a, &b, h[0..5], .{}));
    try testing.expectError(error.BadParam, macdfix(f64, &in, &a, &b, &h, .{ .signal = 0 }));
    try testing.expectError(error.BadParam, macdext(f64, testing.allocator, &in, &a, &b, &h, .{ .fast = 1 }));
    try testing.expectError(error.BadParam, macdext(f64, testing.allocator, &in, &a, &b, &h, .{ .signal = 100001 }));
    try testing.expectError(error.BadParam, macdextLookback(.{ .slow = 0 }));
}

test "macd family: batch == streaming, lookback == leading NaN, f32" {
    var xs: [250]f64 = undefined;
    th.walk(&xs, 81);
    try check3(MacdStream, macd, macdLookback, &xs, MacdParams{}, false);
    try check3(MacdStream, macd, macdLookback, &xs, MacdParams{ .fast = 5, .slow = 8, .signal = 3, .unstable = .{ .bars = 4 } }, false);
    try check3(MacdStream, macd, macdLookback, &xs, MacdParams{ .signal = 1 }, false);
    try check3(MacdStream, macd, macdLookback, &xs, MacdParams{ .seed = .first, .unstable = .auto4 }, false);
    try check3(MacdfixStream, macdfix, macdfixLookback, &xs, MacdfixParams{}, false);
    try check3(MacdfixStream, macdfix, macdfixLookback, &xs, MacdfixParams{ .signal = 1, .unstable = .auto4 }, false);
    try check3(MacdextStream, macdextT, macdextLookback, &xs, MacdextParams{}, true);
    try check3(MacdextStream, macdextT, macdextLookback, &xs, MacdextParams{ .fast_ma = .wma, .slow_ma = .ema, .signal_ma = .sma, .fast = 5, .slow = 9, .signal = 4 }, true);
    try check3(MacdextStream, macdextT, macdextLookback, &xs, MacdextParams{ .fast = 9, .fast_ma = .ema, .slow = 5, .slow_ma = .wma, .signal = 1 }, true);
    var f32s: [100]f32 = undefined;
    for (&f32s, xs[0..100]) |*d, s| d.* = @floatCast(s);
    var a: [100]f32 = undefined;
    var b: [100]f32 = undefined;
    var h: [100]f32 = undefined;
    try testing.expectEqual(@as(usize, 33), try macd(f32, &f32s, &a, &b, &h, .{}));
    try testing.expectEqual(@as(usize, 33), try macdfix(f32, &f32s, &a, &b, &h, .{}));
    try testing.expectEqual(@as(usize, 33), try macdext(f32, testing.allocator, &f32s, &a, &b, &h, .{ .fast_ma = .ema, .slow_ma = .ema, .signal_ma = .ema }));
    try testing.expect(!std.math.isNan(h[40]));
}

fn checkSkip3(comptime batch: anytype, p_skip: anytype, p_prop: anytype) !void {
    var xs: [100]f64 = undefined;
    th.walk(&xs, 4321);
    var ys = xs;
    const nan_at = [_]usize{ 3, 50, 51, 80 };
    for (nan_at) |i| ys[i] = std.math.nan(f64);
    var clean: [100 - nan_at.len]f64 = undefined;
    var j: usize = 0;
    for (ys) |v| {
        if (std.math.isNan(v)) continue;
        clean[j] = v;
        j += 1;
    }
    var o: [3][100]f64 = undefined;
    var w: [3][100 - nan_at.len]f64 = undefined;
    _ = try batch(f64, &ys, &o[0], &o[1], &o[2], p_skip);
    _ = try batch(f64, &clean, &w[0], &w[1], &w[2], p_prop);
    for (0..3) |q| {
        var k: usize = 0;
        var last = std.math.nan(f64);
        for (ys, o[q]) |y, v| {
            if (std.math.isNan(y)) {
                try testing.expect(th.sameBits(v, last));
            } else {
                try testing.expect(th.sameBits(v, w[q][k]));
                k += 1;
            }
            last = v;
        }
    }
}

test "macd/macdfix: nan skip equals the series without the NaN bars, outputs carry over" {
    try checkSkip3(macd, MacdParams{ .fast = 4, .slow = 9, .signal = 3, .nan = .skip }, MacdParams{ .fast = 4, .slow = 9, .signal = 3 });
    try checkSkip3(macdfix, MacdfixParams{ .signal = 3, .nan = .skip }, MacdfixParams{ .signal = 3 });
    var s = try MacdStream(f64).init(.{ .fast = 2, .slow = 3, .signal = 2, .nan = .skip });
    const nan = std.math.nan(f64);
    try testing.expect(s.update(nan) == null);
    for ([_]f64{ 1, 2, 3, 4, 6 }) |x| _ = s.update(x);
    const v = s.value().?;
    try testing.expectEqual(@as(?MacdOut(f64), v), s.update(nan));
}

test "macdext: f32 output is the f64 result of the f32-rounded input, rounded once" {
    var xs: [150]f64 = undefined;
    th.walk(&xs, 909);
    var x32: [150]f32 = undefined;
    var x6: [150]f64 = undefined;
    for (&x32, &x6, xs) |*a, *b, s| {
        a.* = @floatCast(s);
        b.* = a.*;
    }
    var o32: [3][150]f32 = undefined;
    var o64: [3][150]f64 = undefined;
    const ps = [_]MacdextParams{ .{}, .{ .fast_ma = .wma, .slow_ma = .ema, .fast = 5, .slow = 9, .signal = 4 } };
    for (ps) |p| {
        const lb = try macdext(f32, testing.allocator, &x32, &o32[0], &o32[1], &o32[2], p);
        _ = try macdext(f64, testing.allocator, &x6, &o64[0], &o64[1], &o64[2], p);
        for (0..3) |q| for (0..150) |i| {
            const want = if (i < lb) std.math.nan(f64) else @as(f64, @as(f32, @floatCast(o64[q][i])));
            try testing.expect(th.sameBits(@as(f64, o32[q][i]), want));
        };
    }
}
