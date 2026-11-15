// SPDX-License-Identifier: MIT
//! Candlestick-pattern machinery ported from TA-Lib 0.8.3 (`ta_utility.h`
//! TA_CANDLERANGE / TA_CANDLEAVERAGE, the per-pattern period totals of
//! `ta_CDL*.c`; BSD-3, see NOTICE).
//!
//! TA-Lib keeps the candle settings (range type, average period, factor) in a
//! process-global table; here they are an explicit `CandleSettings` passed in
//! every call's params (`.default` = TA-Lib's defaults).
//!
//! Every pattern is a small comptime description (`P`) run by one `Engine`:
//!   - `tots`: the period totals the C keeps, as (setting, bar offset `b`)
//!     pairs. Total (s, b) at bar `i` is the sum of the range of setting `s`
//!     over the `avg_period` bars that precede bar `i - b`; it is initialised in
//!     ascending bar order and then updated `total += range(i-b) -
//!     range(i-b-avg_period)` after each bar is judged, exactly as the C does.
//!   - `lb_sets` / `lb_add`: lookback = max(avg_period of lb_sets) + lb_add.
//!   - `eval(w)`: the pattern test over the window `w` (bars addressed by how
//!     many bars back from the current one).
//! The same `Engine.step` runs the batch (a view over the caller's slices) and
//! the streaming type (a ring of the last `lookback + 1` bars), so both agree
//! to the bit.

const std = @import("std");
const core = @import("core.zig");
const Error = core.Error;

pub const RangeType = enum(u8) { real_body = 0, high_low = 1, shadows = 2 };

/// One TA-Lib candle setting: what is measured, over how many previous candles
/// it is averaged (0 = the candle itself) and the factor applied to the average.
pub const Setting = struct {
    range: RangeType,
    avg_period: usize,
    factor: f64,
};

pub const SetId = enum { body_long, body_very_long, body_short, body_doji, shadow_long, shadow_very_long, shadow_short, shadow_very_short, near, far, equal };

/// TA-Lib's candle settings (`TA_CandleSettingType`), defaults from
/// `TA_CANDLE_DEFAULT_SETTINGS`.
pub const CandleSettings = struct {
    /// Real body is long when longer than the average of the 10 previous real bodies.
    body_long: Setting = .{ .range = .real_body, .avg_period = 10, .factor = 1.0 },
    /// Very long: longer than 3 times that average.
    body_very_long: Setting = .{ .range = .real_body, .avg_period = 10, .factor = 3.0 },
    /// Short: shorter than the average of the 10 previous real bodies.
    body_short: Setting = .{ .range = .real_body, .avg_period = 10, .factor = 1.0 },
    /// Doji-like: shorter than 10% of the average of the 10 previous high-low ranges.
    body_doji: Setting = .{ .range = .high_low, .avg_period = 10, .factor = 0.1 },
    /// Long shadow: longer than the real body.
    shadow_long: Setting = .{ .range = .real_body, .avg_period = 0, .factor = 1.0 },
    /// Very long shadow: longer than 2 times the real body.
    shadow_very_long: Setting = .{ .range = .real_body, .avg_period = 0, .factor = 2.0 },
    /// Short shadow: shorter than half the average of the 10 previous sums of shadows.
    shadow_short: Setting = .{ .range = .shadows, .avg_period = 10, .factor = 1.0 },
    /// Very short shadow: shorter than 10% of the average of the 10 previous high-low ranges.
    shadow_very_short: Setting = .{ .range = .high_low, .avg_period = 10, .factor = 0.1 },
    /// "Near": at most 20% of the average of the 5 previous high-low ranges.
    near: Setting = .{ .range = .high_low, .avg_period = 5, .factor = 0.2 },
    /// "Far": at least 60% of that average.
    far: Setting = .{ .range = .high_low, .avg_period = 5, .factor = 0.6 },
    /// "Equal": at most 5% of that average.
    equal: Setting = .{ .range = .high_low, .avg_period = 5, .factor = 0.05 },

    pub const default: CandleSettings = .{};

    pub fn get(self: *const CandleSettings, comptime id: SetId) Setting {
        return @field(self, @tagName(id));
    }

    /// TA_SetCandleSettings' domain: averaging periods within TA-Lib's period
    /// limit, factors finite and not negative.
    pub fn validate(self: *const CandleSettings) Error!void {
        inline for (comptime std.enums.values(SetId)) |id| {
            const s = self.get(id);
            if (s.avg_period > core.max_period) return error.BadParam;
            if (!(s.factor >= 0.0 and s.factor <= std.math.floatMax(f64))) return error.BadParam;
        }
    }
};

/// One bar, the inputs of every pattern.
pub const Bar = struct { o: f64, h: f64, l: f64, c: f64 };

pub const Tot = struct { set: SetId, b: usize };
pub fn tot(set: SetId, b: usize) Tot {
    return .{ .set = set, .b = b };
}

/// Largest averaging period among `ids` (0 when empty).
pub fn maxPeriod(s: *const CandleSettings, comptime ids: []const SetId) usize {
    var m: usize = 0;
    inline for (ids) |id| m = @max(m, s.get(id).avg_period);
    return m;
}

fn rangeOf(st: Setting, b: Bar) f64 {
    return switch (st.range) {
        .real_body => @abs(b.c - b.o),
        .high_low => b.h - b.l,
        .shadows => (b.h - (if (b.c >= b.o) b.c else b.o)) + ((if (b.c >= b.o) b.o else b.c) - b.l),
    };
}

/// The window a pattern's `eval` sees: bar `b` bars back from the current one
/// (`b = 0` is the current bar), plus the candle averages.
pub fn Win(comptime P: type, comptime View: type, comptime State: type) type {
    return struct {
        const Self = @This();
        v: View,
        s: *const CandleSettings,
        tots: *const [P.tots.len]f64,
        pen: f64,
        st: *State,

        pub fn bar(self: *const Self, b: usize) Bar {
            return self.v.at(b);
        }
        pub fn o(self: *const Self, b: usize) f64 {
            return self.v.at(b).o;
        }
        pub fn h(self: *const Self, b: usize) f64 {
            return self.v.at(b).h;
        }
        pub fn l(self: *const Self, b: usize) f64 {
            return self.v.at(b).l;
        }
        pub fn c(self: *const Self, b: usize) f64 {
            return self.v.at(b).c;
        }
        /// TA_CANDLECOLOR: 1 white (close >= open), -1 black.
        pub fn color(self: *const Self, b: usize) i32 {
            const x = self.v.at(b);
            return if (x.c >= x.o) 1 else -1;
        }
        /// TA_REALBODY
        pub fn body(self: *const Self, b: usize) f64 {
            const x = self.v.at(b);
            return @abs(x.c - x.o);
        }
        /// TA_UPPERSHADOW
        pub fn upper(self: *const Self, b: usize) f64 {
            const x = self.v.at(b);
            return x.h - (if (x.c >= x.o) x.c else x.o);
        }
        /// TA_LOWERSHADOW
        pub fn lower(self: *const Self, b: usize) f64 {
            const x = self.v.at(b);
            return (if (x.c >= x.o) x.o else x.c) - x.l;
        }
        /// TA_HIGHLOWRANGE
        pub fn hl(self: *const Self, b: usize) f64 {
            const x = self.v.at(b);
            return x.h - x.l;
        }
        pub fn maxOc(self: *const Self, b: usize) f64 {
            const x = self.v.at(b);
            return @max(x.o, x.c);
        }
        pub fn minOc(self: *const Self, b: usize) f64 {
            const x = self.v.at(b);
            return @min(x.o, x.c);
        }
        /// TA_REALBODYGAPUP(b2, b1)
        pub fn bodyGapUp(self: *const Self, b2: usize, b1: usize) bool {
            return self.minOc(b2) > self.maxOc(b1);
        }
        pub fn bodyGapDown(self: *const Self, b2: usize, b1: usize) bool {
            return self.maxOc(b2) < self.minOc(b1);
        }
        pub fn gapUp(self: *const Self, b2: usize, b1: usize) bool {
            return self.l(b2) > self.h(b1);
        }
        pub fn gapDown(self: *const Self, b2: usize, b1: usize) bool {
            return self.h(b2) < self.l(b1);
        }

        /// TA_CANDLERANGE(set, bar b)
        pub fn rng(self: *const Self, comptime set: SetId, b: usize) f64 {
            return rangeOf(self.s.get(set), self.v.at(b));
        }

        /// TA_CANDLEAVERAGE(set, total (set, b), bar b): factor * (sum / period
        /// or, for period 0, the bar's own range) / (2 for shadows, else 1).
        pub fn avg(self: *const Self, comptime set: SetId, comptime b: usize) f64 {
            const st = self.s.get(set);
            const idx = comptime totIndex(set, b);
            const base: f64 = if (st.avg_period != 0)
                self.tots[idx] / @as(f64, @floatFromInt(st.avg_period))
            else
                rangeOf(st, self.v.at(b));
            return st.factor * base / (if (st.range == .shadows) @as(f64, 2.0) else @as(f64, 1.0));
        }

        fn totIndex(comptime set: SetId, comptime b: usize) usize {
            inline for (P.tots, 0..) |t, i| {
                if (t.set == set and t.b == b) return i;
            }
            @compileError("candles: total (" ++ @tagName(set) ++ ", " ++ std.fmt.comptimePrint("{d}", .{b}) ++ ") not declared in tots");
        }
    };
}

/// Runs one pattern. `P` provides `tots`, `lb_sets`, `lb_add`, `eval`, and
/// optionally `State` (cross-bar state, e.g. HIKKAKE) and `penetration`.
pub fn Engine(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const State = if (@hasDecl(P, "State")) P.State else struct {};
        pub const has_pen = @hasDecl(P, "pen_default");

        s: CandleSettings,
        pen: f64,
        lb: usize,
        n: usize = 0,
        totals: [P.tots.len]f64 = @splat(0.0),
        st: State = .{},

        pub fn lookbackOf(s: *const CandleSettings) usize {
            if (@hasDecl(P, "lookback")) return P.lookback(s);
            return maxPeriod(s, &P.lb_sets) + P.lb_add;
        }

        pub fn init(s: CandleSettings, pen: f64) Error!Self {
            try s.validate();
            if (has_pen and !(pen >= 0.0 and pen <= 3.0e37)) return error.BadParam;
            return .{ .s = s, .pen = pen, .lb = lookbackOf(&s) };
        }

        /// Feed the bar `v.at(0)`; null until the lookback is satisfied.
        pub fn step(self: *Self, v: anytype) ?i32 {
            const n = self.n;
            self.n += 1;
            const W = Win(P, @TypeOf(v), State);
            var w = W{ .v = v, .s = &self.s, .tots = &self.totals, .pen = self.pen, .st = &self.st };
            // Patterns with cross-bar state (HIKKAKE) run the C's pre-warm: the
            // C judges (and discards) the `warm_bars` bars before the first output
            // so that the state, and the totals, are already running at the lookback.
            const warm = if (@hasDecl(P, "warm_bars")) P.warm_bars else 0;
            const start = self.lb - warm;
            if (n < start) {
                inline for (P.tots, 0..) |t, ti| {
                    const per = self.s.get(t.set).avg_period;
                    if (n + t.b + per >= start and n + t.b < start) self.totals[ti] += w.rng(t.set, 0);
                }
                return null;
            }
            const r = P.eval(&w);
            inline for (P.tots, 0..) |t, ti| {
                const per = self.s.get(t.set).avg_period;
                self.totals[ti] += w.rng(t.set, t.b) - w.rng(t.set, t.b + per);
            }
            if (n < self.lb) return null;
            return r;
        }
    };
}

/// Batch view over the caller's slices; `i` is the current bar.
pub fn SliceView(comptime T: type) type {
    return struct {
        open: []const T,
        high: []const T,
        low: []const T,
        close: []const T,
        i: usize,
        pub fn at(self: @This(), b: usize) Bar {
            const k = self.i - b;
            return .{ .o = self.open[k], .h = self.high[k], .l = self.low[k], .c = self.close[k] };
        }
    };
}

/// Ring of the last `buf.len` bars; `head` is the slot of the current bar.
pub const RingView = struct {
    buf: []const Bar,
    head: usize,
    pub fn at(self: RingView, b: usize) Bar {
        const cap = self.buf.len;
        return self.buf[(self.head + cap - b % cap) % cap];
    }
};

/// Ring view for `peek`: the current bar is `x`, not stored; `head` is the
/// slot of the previous bar.
pub const PeekView = struct {
    buf: []const Bar,
    head: usize,
    x: Bar,
    pub fn at(self: PeekView, b: usize) Bar {
        if (b == 0) return self.x;
        const cap = self.buf.len;
        return self.buf[(self.head + cap - (b - 1) % cap) % cap];
    }
};

/// The public surface of one pattern: params, batch, lookback, stream.
pub fn Op(comptime P: type) type {
    const E = Engine(P);
    return struct {
        pub const Params = if (E.has_pen) struct {
            settings: CandleSettings = .default,
            /// Penetration into the first body (TA-Lib range 0 .. 3e37).
            penetration: f64 = P.pen_default,
        } else struct {
            settings: CandleSettings = .default,
        };

        fn mk(p: Params) Error!E {
            return E.init(p.settings, if (E.has_pen) p.penetration else 0.0);
        }

        pub fn lookback(p: Params) Error!usize {
            const e = try mk(p);
            return e.lb;
        }

        /// Writes 0 / ±80 / ±100 / ±200 per bar as TA-Lib does (0 in the lead);
        /// returns the lookback.
        pub fn run(comptime T: type, open: []const T, high: []const T, low: []const T, close: []const T, out: []i32, p: Params) Error!usize {
            core.checkFloat(T);
            const n = open.len;
            try core.checkLen(n, &.{ high.len, low.len, close.len, out.len });
            var e = try mk(p);
            var v = SliceView(T){ .open = open, .high = high, .low = low, .close = close, .i = 0 };
            for (0..n) |i| {
                v.i = i;
                out[i] = e.step(v) orelse 0;
            }
            return e.lb;
        }

        pub fn Stream(comptime T: type) type {
            core.checkFloat(T);
            return struct {
                const Self = @This();
                e: E,
                buf: []Bar,
                head: usize = 0,
                last: ?i32 = null,

                /// Number of `Bar` slots the caller must provide to `init`.
                pub fn bufLen(p: Params) Error!usize {
                    const e = try mk(p);
                    return e.lb + 1;
                }
                pub fn init(p: Params, buf: []Bar) Error!Self {
                    const need = try bufLen(p);
                    if (buf.len < need) return error.BadParam;
                    return .{ .e = try mk(p), .buf = buf[0..need] };
                }
                fn mkBar(o: T, h: T, l: T, c: T) Bar {
                    return .{ .o = o, .h = h, .l = l, .c = c };
                }
                /// Feed one bar; null until the lookback is satisfied.
                pub fn update(self: *Self, o: T, h: T, l: T, c: T) ?i32 {
                    const slot = if (self.e.n == 0) 0 else (self.head + 1) % self.buf.len;
                    self.buf[slot] = mkBar(o, h, l, c);
                    self.head = slot;
                    const r = self.e.step(RingView{ .buf = self.buf, .head = slot }) orelse return null;
                    self.last = r;
                    return r;
                }
                /// What `update` would answer, without changing the state.
                pub fn peek(self: *const Self, o: T, h: T, l: T, c: T) ?i32 {
                    var e = self.e;
                    return e.step(PeekView{ .buf = self.buf, .head = self.head, .x = mkBar(o, h, l, c) });
                }
                /// The last value `update` produced.
                pub fn value(self: *const Self) ?i32 {
                    return self.last;
                }
                /// A copy whose ring lives in `dst` (`dst.len >= bufLen`).
                pub fn clone(self: *const Self, dst: []Bar) Error!Self {
                    if (dst.len < self.buf.len) return error.BadParam;
                    var r = self.*;
                    r.buf = dst[0..self.buf.len];
                    @memcpy(r.buf, self.buf);
                    return r;
                }
            };
        }
    };
}
