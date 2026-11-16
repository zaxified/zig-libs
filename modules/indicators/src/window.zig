// SPDX-License-Identifier: MIT
//! Rolling SUM, MAX and MIN over a window, ported from TA-Lib 0.8.3
//! (`ta_SUM.c`, `ta_MAX.c`, `ta_MIN.c`; BSD-3, see NOTICE). The window extreme
//! core is also what STOCH reads its highest high and lowest low from.

const std = @import("std");
const core = @import("core.zig");
const smooth = @import("smooth.zig");
const Error = core.Error;
const pf = core.pf;
const th = @import("testhelp.zig");

pub const WindowParams = struct { period: usize = 30 };
pub const SumParams = WindowParams;
pub const MaxParams = WindowParams;
pub const MinParams = WindowParams;

// ── SUM ─────────────────────────────────────────────────────────────────────

pub const SumCore = struct {
    p: usize,
    n: usize = 0,
    sum: f64 = 0.0,

    pub fn validate(p: WindowParams) Error!void {
        try core.checkPeriod(p.period, 2);
    }
    pub fn ringLen(p: WindowParams) usize {
        return p.period;
    }
    pub fn lookback(p: WindowParams) usize {
        return p.period - 1;
    }
    pub fn init(p: WindowParams) Error!SumCore {
        try validate(p);
        return .{ .p = p.period };
    }
    pub fn step(self: *SumCore, src: anytype, x: f64) ?f64 {
        const n = self.n;
        self.n += 1;
        self.sum += x;
        if (n + 1 < self.p) return null;
        const t = self.sum;
        self.sum -= src.at(n + 1 - self.p);
        return t;
    }
};

pub fn sumLookback(p: SumParams) Error!usize {
    try SumCore.validate(p);
    return SumCore.lookback(p);
}
pub fn sum(comptime T: type, in: []const T, out: []T, p: SumParams) Error!usize {
    return smooth.batch1(T, SumCore, in, out, p);
}
pub fn SumStream(comptime T: type) type {
    return smooth.Stream1(T, SumParams, SumCore);
}

// ── MAX / MIN ───────────────────────────────────────────────────────────────

/// The extreme of the last `period` bars. Tracks the index of the current
/// extreme and rescans the window only when it leaves it (TA_MAX / TA_MIN's
/// classic algorithm; ties keep the newest bar).
pub fn ExtCore(comptime is_max: bool) type {
    return struct {
        const Self = @This();
        p: usize,
        n: usize = 0,
        idx: ?usize = null,
        val: f64 = 0.0,

        pub fn validate(p: WindowParams) Error!void {
            try core.checkPeriod(p.period, 2);
        }
        pub fn ringLen(p: WindowParams) usize {
            return p.period;
        }
        pub fn lookback(p: WindowParams) usize {
            return p.period - 1;
        }
        pub fn init(p: WindowParams) Error!Self {
            try validate(p);
            return .{ .p = p.period };
        }
        /// The window-extreme update shared with STOCH; `period >= 1`.
        pub fn initAny(period: usize) Self {
            return .{ .p = period };
        }
        inline fn better(a: f64, b: f64) bool {
            return if (is_max) a > b else a < b;
        }
        inline fn betterEq(a: f64, b: f64) bool {
            return if (is_max) a >= b else a <= b;
        }
        pub fn step(self: *Self, src: anytype, x: f64) ?f64 {
            const n = self.n;
            self.n += 1;
            if (n + 1 < self.p) return null;
            const trailing = n + 1 - self.p;
            if (self.idx == null or self.idx.? < trailing) {
                var idx = trailing;
                var val = src.at(trailing);
                var i = trailing;
                while (i < n) {
                    i += 1;
                    const t = src.at(i);
                    if (better(t, val)) {
                        idx = i;
                        val = t;
                    }
                }
                self.idx = idx;
                self.val = val;
            } else if (betterEq(x, self.val)) {
                self.idx = n;
                self.val = x;
            }
            return self.val;
        }
        /// `step` over the bars `n..` of a slice once the output has started
        /// (`n + 1 >= p`), as one inlined update per bar: the same rescan and the
        /// same tie rule, the index kept as `idx + 1` (0 = none) in a register.
        pub const Run = struct {
            p: usize,
            idx1: usize,
            val: f64,
            pub fn of(c: *const Self) Run {
                return .{ .p = c.p, .idx1 = if (c.idx) |v| v + 1 else 0, .val = c.val };
            }
            pub fn store(r: Run, c: *Self, n: usize) void {
                c.n = n;
                c.idx = if (r.idx1 == 0) null else r.idx1 - 1;
                c.val = r.val;
            }
            pub inline fn bar(r: *Run, comptime T: type, xs: []const T, n: usize) f64 {
                const trailing = n + 1 - r.p;
                const x: f64 = xs[n];
                if (r.idx1 <= trailing) {
                    var idx = trailing;
                    var val: f64 = xs[trailing];
                    var i = trailing;
                    while (i < n) {
                        i += 1;
                        const t: f64 = xs[i];
                        if (better(t, val)) {
                            idx = i;
                            val = t;
                        }
                    }
                    r.idx1 = idx + 1;
                    r.val = val;
                } else if (betterEq(x, r.val)) {
                    r.idx1 = n + 1;
                    r.val = x;
                }
                return r.val;
            }
        };
    };
}

pub const MaxCore = ExtCore(true);
pub const MinCore = ExtCore(false);

/// TA-Lib 0.8.3's batch MAX / MIN: a Van Herk / Gil-Werman block scan (ta_MAX.c), reproduced
/// operation for operation, because it decides ties differently from the streaming automaton
/// of `ExtCore`: only the sign of an equal pair 0.0 / -0.0 (and where a NaN shows) can tell them apart.
/// Blocks are `period` bars; the output at a block's last bar is the block's suffix extremum
/// (scanned backward, a strict comparison, so the LATER of equal values stays); the other outputs
/// combine the suffix extremum of the older block's remainder with the running prefix extremum of the
/// newer block (scanned forward, strict, the EARLIEST stays), the suffix side winning a tie. TA-Lib keeps
/// two scratch arrays; here the suffix extrema of a block are parked in the output slots that block is
/// about to fill (`out[b + period - 1 + m]`), each read once before it is overwritten, so nothing is allocated.
/// `out` must not alias `in`. The streaming types still run `ExtCore` (TA-Lib's streaming tier does too).
pub fn extBatch(comptime T: type, comptime is_max: bool, in: []const T, out: []T, p: WindowParams) Error!usize {
    core.checkFloat(T);
    try core.checkPeriod(p.period, 2);
    try core.checkLen(in.len, &.{out.len});
    const per = p.period;
    const n = in.len;
    const lb = per - 1;
    const nan = std.math.nan(T);
    for (out[0..@min(lb, n)]) |*o| o.* = nan;
    var b: usize = 0; // block start; the block is [b, b + per - 1]
    while (b + per <= n) : (b += per) {
        const first = b + per - 1; // output slot of suf[0]
        var ext = in[first];
        if (first + per - 1 < n) out[first + per - 1] = ext;
        var m = per - 1;
        while (m > 0) {
            m -= 1;
            const t = in[b + m];
            if (if (is_max) t > ext else t < ext) ext = t;
            if (first + m < n) out[first + m] = ext;
        }
        // out[first] now holds suf[0]: the block's own output. The rest combine with the next block's prefix.
        const next = b + per;
        if (next >= n) break;
        const avail = @min(per - 1, n - next);
        var pre = in[next];
        var j: usize = 1;
        while (j <= avail) : (j += 1) {
            if (j > 1) {
                const t = in[next + j - 1];
                if (if (is_max) t > pre else t < pre) pre = t;
            }
            const slot = &out[first + j];
            if (if (is_max) pre > slot.* else pre < slot.*) slot.* = pre;
        }
    }
    return lb;
}

/// The longest period `hiLoBlocks` serves; its two suffix arrays live on the stack (4 KiB). TA-Lib keeps 30 on
/// its stack and allocates past that; the batch functions that use the kernel take no allocator, so a longer
/// period runs the caller's automaton instead (same values except where a NaN or a 0.0 / -0.0 tie shows).
pub const block_cap: usize = 256;

/// TA-Lib 0.8.3's batch window extrema over a highs and a lows series at once — the block scan of `ta_MIDPOINT.c`,
/// `ta_MIDPRICE.c` and `ta_WILLR.c`, the two-series form of `extBatch` with the same tie rule (the block suffix,
/// scanned backward with a strict comparison, wins a tie against the next block's prefix). Calls
/// `sink.put(k, highest, lowest)` for every bar `k >= per - 1` in increasing order, the highest of `hs[k + 1 - per
/// .. k]` and the lowest of `ls[...]` (pass one series twice for MIDPOINT). Returns false and calls nothing when
/// `per > block_cap`. Amortized two comparisons per bar and series, no rescans, no allocation.
pub fn hiLoBlocks(comptime T: type, hs: []const T, ls: []const T, per: usize, sink: anytype) bool {
    if (per == 0) return false;
    return hiLoBlocksFrom(T, hs, ls, per, per - 1, sink);
}

/// `hiLoBlocks` with the first output at bar `from >= per - 1` and the blocks aligned on `from + 1 - per`, as
/// TA-Lib aligns them when a caller asks for a later start (ICHIMOKU's three MIDPRICE calls start at the longest
/// lookback): bars before `from` are not reported.
pub fn hiLoBlocksFrom(comptime T: type, hs: []const T, ls: []const T, per: usize, from: usize, sink: anytype) bool {
    if (per > block_cap or per == 0 or from + 1 < per) return false;
    var suf_h: [block_cap]f64 = undefined;
    var suf_l: [block_cap]f64 = undefined;
    const n = @min(hs.len, ls.len);
    var b: usize = from + 1 - per; // block start; the block is [b, b + per - 1]
    while (b + per <= n) : (b += per) {
        const first = b + per - 1;
        var h: f64 = hs[first];
        var l: f64 = ls[first];
        suf_h[per - 1] = h;
        suf_l[per - 1] = l;
        var i = per - 1;
        while (i > 0) {
            i -= 1;
            const xh: f64 = hs[b + i];
            const xl: f64 = ls[b + i];
            if (xh > h) h = xh;
            if (xl < l) l = xl;
            suf_h[i] = h;
            suf_l[i] = l;
        }
        sink.put(first, h, l);
        // The windows ending in the next block: this block's suffix from `m` on, that block's prefix up to `m - 1`.
        const next = b + per;
        if (next >= n) break;
        const avail = @min(per - 1, n - next);
        var ph: f64 = hs[next];
        var pl: f64 = ls[next];
        var m: usize = 1;
        while (m <= avail) : (m += 1) {
            if (m > 1) {
                const xh: f64 = hs[next + m - 1];
                const xl: f64 = ls[next + m - 1];
                if (xh > ph) ph = xh;
                if (xl < pl) pl = xl;
            }
            var hh = suf_h[m];
            if (ph > hh) hh = ph;
            var ll = suf_l[m];
            if (pl < ll) ll = pl;
            sink.put(first + m, hh, ll);
        }
    }
    return true;
}

pub fn maxLookback(p: MaxParams) Error!usize {
    try MaxCore.validate(p);
    return MaxCore.lookback(p);
}
pub fn max(comptime T: type, in: []const T, out: []T, p: MaxParams) Error!usize {
    return extBatch(T, true, in, out, p);
}
pub fn MaxStream(comptime T: type) type {
    return smooth.Stream1(T, MaxParams, MaxCore);
}
pub fn minLookback(p: MinParams) Error!usize {
    try MinCore.validate(p);
    return MinCore.lookback(p);
}
pub fn min(comptime T: type, in: []const T, out: []T, p: MinParams) Error!usize {
    return extBatch(T, false, in, out, p);
}
pub fn MinStream(comptime T: type) type {
    return smooth.Stream1(T, MinParams, MinCore);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "sum hand-checked vector" {
    // period 3 over 1 2 3 4 5: 6, 9, 12 (running sum 1,3,6 -> 6; 6-1+4 = 9; 9-2+5 = 12).
    const in = [_]f64{ 1, 2, 3, 4, 5 };
    var out: [5]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try sum(f64, &in, &out, .{ .period = 3 }));
    try testing.expect(std.math.isNan(out[1]));
    try testing.expectEqual(@as(f64, 6), out[2]);
    try testing.expectEqual(@as(f64, 9), out[3]);
    try testing.expectEqual(@as(f64, 12), out[4]);
}

test "max and min hand-checked vector" {
    // period 3 over 5 1 4 2 8 3: windows (5,1,4) (1,4,2) (4,2,8) (2,8,3).
    // The max of the first window is 5 at bar 0; at bar 3 it has left, so the
    // window is rescanned: (1,4,2) -> 4; bar 4: 8 >= 4 -> 8; bar 5: 8 is still inside -> 8.
    const in = [_]f64{ 5, 1, 4, 2, 8, 3 };
    var hi: [6]f64 = undefined;
    var lo: [6]f64 = undefined;
    try testing.expectEqual(@as(usize, 2), try max(f64, &in, &hi, .{ .period = 3 }));
    try testing.expectEqual(@as(usize, 2), try min(f64, &in, &lo, .{ .period = 3 }));
    try testing.expectEqualSlices(f64, &.{ 5, 4, 8, 8 }, hi[2..]);
    try testing.expectEqualSlices(f64, &.{ 1, 1, 2, 2 }, lo[2..]);
}

test "window: BadParam, period 2 minimum" {
    const in = [_]f64{ 1, 2, 3 };
    var out: [3]f64 = undefined;
    try testing.expectError(error.BadParam, sum(f64, &in, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, max(f64, &in, &out, .{ .period = 1 }));
    try testing.expectError(error.BadParam, min(f64, &in, &out, .{ .period = 100001 }));
    try testing.expectError(error.BadParam, sumLookback(.{ .period = 0 }));
    try testing.expectError(error.BadParam, max(f64, &in, out[0..2], .{ .period = 2 }));
    try testing.expectEqual(@as(usize, 1), try maxLookback(.{ .period = 2 }));
}

test "window: batch == streaming, lookback == leading NaN, matches naive scan, f32" {
    var xs: [400]f64 = undefined;
    th.walk(&xs, 21);
    try th.checkOne(SumParams, SumStream, sum, sumLookback, &xs, .{ .period = 10 });
    try th.checkOne(MaxParams, MaxStream, max, maxLookback, &xs, .{ .period = 10 });
    try th.checkOne(MinParams, MinStream, min, minLookback, &xs, .{ .period = 10 });
    try th.checkOne(MaxParams, MaxStream, max, maxLookback, &xs, .{ .period = 2 });
    var hi: [400]f64 = undefined;
    var lo: [400]f64 = undefined;
    _ = try max(f64, &xs, &hi, .{ .period = 7 });
    _ = try min(f64, &xs, &lo, .{ .period = 7 });
    for (6..400) |i| {
        var h = xs[i];
        var l = xs[i];
        for (xs[i - 6 .. i + 1]) |v| {
            h = @max(h, v);
            l = @min(l, v);
        }
        try testing.expectEqual(h, hi[i]);
        try testing.expectEqual(l, lo[i]);
    }
    var f32s: [50]f32 = undefined;
    for (&f32s, xs[0..50]) |*d, s| d.* = @floatCast(s);
    var o32: [50]f32 = undefined;
    try testing.expectEqual(@as(usize, 4), try sum(f32, &f32s, &o32, .{ .period = 5 }));
    try testing.expectEqual(@as(usize, 4), try max(f32, &f32s, &o32, .{ .period = 5 }));
    try testing.expectEqual(@as(usize, 4), try min(f32, &f32s, &o32, .{ .period = 5 }));
}

test "sum: a NaN poisons the running sum" {
    const nan = std.math.nan(f64);
    const in = [_]f64{ 1, 2, nan, 4, 5, 6 };
    var out: [6]f64 = undefined;
    _ = try sum(f64, &in, &out, .{ .period = 2 });
    try testing.expectEqual(@as(f64, 3), out[1]);
    for (out[2..]) |v| try testing.expect(std.math.isNan(v));
}

test "max/min with NaN: a NaN never wins a comparison; the batch block scan and the streaming automaton show it at different bars" {
    const nan = std.math.nan(f64);
    // max, period 3 over 1 2 NaN 0 0 0, BATCH (TA-Lib's block scan, by reading of ta_MAX.c; the oracle has no NaN inputs):
    //  block [1 2 NaN] scanned backward starts at NaN and nothing beats it: out[2] NaN, and the
    //  suffix NaN stays in the combined outputs 3 and 4; block [0 0 0] gives out[5] = 0.
    const a = [_]f64{ 1, 2, nan, 0, 0, 0 };
    var out: [6]f64 = undefined;
    _ = try max(f64, &a, &out, .{ .period = 3 });
    try testing.expect(std.math.isNan(out[2]));
    try testing.expect(std.math.isNan(out[3]));
    try testing.expect(std.math.isNan(out[4]));
    try testing.expectEqual(@as(f64, 0), out[5]);
    // min, period 3 over 5 4 NaN 9 9 9: NaN, NaN, NaN, 9
    const b = [_]f64{ 5, 4, nan, 9, 9, 9 };
    _ = try min(f64, &b, &out, .{ .period = 3 });
    try testing.expect(std.math.isNan(out[2]));
    try testing.expect(std.math.isNan(out[3]));
    try testing.expect(std.math.isNan(out[4]));
    try testing.expectEqual(@as(f64, 9), out[5]);
    // STREAMING (the automaton): max over 1 2 NaN 0 0 0:
    //  bar 2 rescan (1,2,NaN): 1 -> 2, NaN > 2 false -> 2; bar 3: 0 >= 2 false -> 2;
    //  bar 4: the max (bar 1) left, rescan (NaN,0,0): starts at NaN, 0 > NaN false -> NaN;
    //  bar 5: NaN's index left, rescan (0,0,0) -> 0.
    var sbuf: [3]f64 = undefined;
    var s = try MaxStream(f64).init(.{ .period = 3 }, &sbuf);
    var got: [6]?f64 = undefined;
    for (a, &got) |x, *g| g.* = s.update(x);
    try testing.expectEqual(@as(f64, 2), got[2].?);
    try testing.expectEqual(@as(f64, 2), got[3].?);
    try testing.expect(std.math.isNan(got[4].?));
    try testing.expectEqual(@as(f64, 0), got[5].?);
}

test "max/min batch is TA-Lib's block scan; the streaming automaton decides ties differently (0.0 vs -0.0)" {
    const nz = -0.0;
    // Batch, max, period 3 over -2 -0 -1 +0 -0 (block [0..2], then the next block's prefix):
    //  out[2] = suffix max of the block, the later of equals stays: -0 (from -2, -0, -1)
    //  out[3] = combine(suf[1] = -0, pre = +0): the prefix must be strictly greater to win: -0
    //  out[4] = combine(suf[2] = -1, pre = max(+0, -0) with the earlier staying = +0): +0
    const a = [_]f64{ -2, nz, -1, 0.0, nz };
    var out: [5]f64 = undefined;
    _ = try max(f64, &a, &out, .{ .period = 3 });
    try testing.expect(std.math.signbit(out[2]) and out[2] == 0);
    try testing.expect(std.math.signbit(out[3]) and out[3] == 0);
    try testing.expect(!std.math.signbit(out[4]) and out[4] == 0);
    // Batch, min, period 3 over 2 +0 1 -0 +0: out[2] = suf[0] = min(2, +0, 1) = +0;
    //  out[3] = combine(suf[1] = +0 (min of +0, 1), pre = -0): -0 < +0 is false: +0; out[4] = combine(suf[2] = 1, pre = -0 (the earlier of -0, +0)): -0.
    const b = [_]f64{ 2, 0.0, 1, nz, 0.0 };
    _ = try min(f64, &b, &out, .{ .period = 3 });
    try testing.expect(!std.math.signbit(out[2]) and out[2] == 0);
    try testing.expect(!std.math.signbit(out[3]) and out[3] == 0);
    try testing.expect(std.math.signbit(out[4]) and out[4] == 0);
    // Streaming: a rescan keeps the OLDEST of equal values, an incremental update the NEWEST.
    //  max, period 3 over -2 -0 -1 +0 -0: bar 2 rescan -> -0; bar 3: +0 >= -0 -> +0; bar 4: -0 >= +0 -> -0.
    var sbuf: [3]f64 = undefined;
    var s = try MaxStream(f64).init(.{ .period = 3 }, &sbuf);
    var got: [5]?f64 = undefined;
    for (a, &got) |x, *g| g.* = s.update(x);
    try testing.expect(std.math.signbit(got[2].?));
    try testing.expect(!std.math.signbit(got[3].?));
    try testing.expect(std.math.signbit(got[4].?));
}

test "hiLoBlocks: every window's highest and lowest, across block edges and short tails, against a naive scan" {
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    const rnd = prng.random();
    var hs: [300]f64 = undefined;
    var ls: [300]f64 = undefined;
    const Sink = struct {
        hi: []f64,
        lo: []f64,
        seen: []bool,
        last: *usize,
        pub fn put(s: @This(), k: usize, h: f64, l: f64) void {
            // Strictly increasing, each bar once.
            std.debug.assert(s.last.* == std.math.maxInt(usize) or k == s.last.* + 1);
            s.last.* = k;
            s.hi[k] = h;
            s.lo[k] = l;
            s.seen[k] = true;
        }
    };
    var hi: [300]f64 = undefined;
    var lo: [300]f64 = undefined;
    var seen: [300]bool = undefined;
    for (0..400) |_| {
        const n = rnd.intRangeAtMost(usize, 0, 300);
        const per = rnd.intRangeAtMost(usize, 1, 40);
        // Few distinct values, so ties are common.
        for (hs[0..n], ls[0..n]) |*h, *l| {
            h.* = @floatFromInt(rnd.intRangeAtMost(i32, -4, 4));
            l.* = @floatFromInt(rnd.intRangeAtMost(i32, -4, 4));
        }
        @memset(&seen, false);
        var last: usize = std.math.maxInt(usize);
        try testing.expect(hiLoBlocks(f64, hs[0..n], ls[0..n], per, Sink{ .hi = &hi, .lo = &lo, .seen = &seen, .last = &last }));
        for (0..n) |k| {
            try testing.expectEqual(k + 1 >= per, seen[k]);
            if (k + 1 < per) continue;
            var eh = hs[k + 1 - per];
            var el = ls[k + 1 - per];
            for (k + 1 - per..k + 1) |j| {
                eh = @max(eh, hs[j]);
                el = @min(el, ls[j]);
            }
            try testing.expectEqual(eh, hi[k]);
            try testing.expectEqual(el, lo[k]);
        }
    }
    // Past the stack scratch it declines and calls nothing.
    const Never = struct {
        pub fn put(_: @This(), _: usize, _: f64, _: f64) void {
            unreachable;
        }
    };
    try testing.expect(!hiLoBlocks(f64, hs[0..0], ls[0..0], block_cap + 1, Never{}));
}

test "midpoint / midprice / willr / ichimoku batch (block scan) equal the stream on both sides of block_cap" {
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    const n = 700;
    var h: [n]f64 = undefined;
    var l: [n]f64 = undefined;
    var c: [n]f64 = undefined;
    var x: f64 = 100;
    for (&h, &l, &c) |*hh, *ll, *cc| {
        x += (rnd.float(f64) - 0.5);
        hh.* = x + rnd.float(f64);
        ll.* = x - rnd.float(f64);
        cc.* = x;
    }
    const ind = @import("root.zig");
    var out: [n]f64 = undefined;
    var buf: [4 * 302]f64 = undefined;
    for ([_]usize{ 2, 3, 14, 30, 255, 256, 257, 300 }) |per| {
        _ = try ind.midpoint(f64, &c, &out, .{ .period = per });
        var s1 = try ind.MidpointStream(f64).init(.{ .period = per }, &buf);
        for (c, out) |v, o| try expectSameOpt(o, s1.update(v));
        _ = try ind.midprice(f64, &h, &l, &out, .{ .period = per });
        var s2 = try ind.MidpriceStream(f64).init(.{ .period = per }, &buf);
        for (h, l, out) |hh, ll, o| try expectSameOpt(o, s2.update(.{ .high = hh, .low = ll }));
        _ = try ind.willr(f64, &h, &l, &c, &out, .{ .period = per });
        var s3 = try ind.WillrStream(f64).init(.{ .period = per }, &buf);
        for (h, l, c, out) |hh, ll, cc, o| try expectSameOpt(o, s3.update(.{ .high = hh, .low = ll, .close = cc }));
        // MFI: the batch's stack ring of flows (period <= 256) against the stream's recomputed flows.
        var v: [n]f64 = undefined;
        for (&v, 0..) |*vv, j| vv.* = 1000.0 + @as(f64, @floatFromInt(j % 17));
        _ = try ind.mfi(f64, &h, &l, &c, &v, &out, .{ .period = per });
        var s5 = try ind.MfiStream(f64).init(.{ .period = per }, &buf);
        for (h, l, c, v, out) |hh, ll, cc, vv, o| try expectSameOpt(o, s5.update(.{ .high = hh, .low = ll, .close = cc, .volume = vv }));
        // ICHIMOKU: the shorter periods' blocks are aligned on the longest lookback, not on bar 0.
        const ip = ind.IchimokuParams{ .tenkan = @max(2, per / 3), .kijun = @max(2, per / 2), .senkou_b = per };
        var t: [n]f64 = undefined;
        var k: [n]f64 = undefined;
        var a: [n]f64 = undefined;
        var sb: [n]f64 = undefined;
        _ = try ind.ichimoku(f64, &h, &l, &t, &k, &a, &sb, ip);
        var s4 = try ind.IchimokuStream(f64).init(ip, &buf);
        for (h, l, 0..) |hh, ll, j| {
            if (s4.update(.{ .high = hh, .low = ll })) |r| {
                try testing.expectEqual(@as(u64, @bitCast(r.tenkan)), @as(u64, @bitCast(t[j])));
                try testing.expectEqual(@as(u64, @bitCast(r.kijun)), @as(u64, @bitCast(k[j])));
                try testing.expectEqual(@as(u64, @bitCast(r.senkou_a)), @as(u64, @bitCast(a[j])));
                try testing.expectEqual(@as(u64, @bitCast(r.senkou_b)), @as(u64, @bitCast(sb[j])));
            } else try testing.expect(std.math.isNan(t[j]) and std.math.isNan(k[j]) and std.math.isNan(a[j]) and std.math.isNan(sb[j]));
        }
    }
}

fn expectSameOpt(batch: f64, stream: ?f64) !void {
    if (stream) |v| {
        try testing.expectEqual(@as(u64, @bitCast(v)), @as(u64, @bitCast(batch)));
    } else try testing.expect(std.math.isNan(batch));
}
