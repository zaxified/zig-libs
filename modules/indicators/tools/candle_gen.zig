// SPDX-License-Identifier: MIT
//! Inputs and settings presets of the candlestick-pattern oracle (`interop.zig`).
//!
//! A random walk almost never forms a candlestick pattern, so the generator
//! writes bars from a mix of single-bar shapes (doji, long body, marubozu,
//! hammer-like, spinning top, gap) and multi-bar motifs (two-bar reversals,
//! stars, soldiers / crows, three methods, hikkake, ladder, ...) whose
//! proportions are drawn at random, so the "near / far / equal / short / long"
//! thresholds are crossed from both sides. Kind 1 snaps every price to a
//! 0.25 grid (exact ties between opens, closes, highs and lows: the `<` / `<=`
//! boundaries), kind 2 scales everything by 1e-9 (the thresholds are relative).

const std = @import("std");
const ind = @import("indicators");
const CandleSettings = ind.candles.CandleSettings;

pub const Gen = struct {
    r: std.Random,
    o: []f64,
    h: []f64,
    l: []f64,
    c: []f64,
    i: usize = 0,
    p: f64 = 100.0,

    fn u(g: *Gen, a: f64, b: f64) f64 {
        return a + (b - a) * g.r.float(f64);
    }
    fn dirSign(g: *Gen) f64 {
        return if (g.r.boolean()) 1.0 else -1.0;
    }
    fn put(g: *Gen, op: f64, cl: f64, up: f64, dn: f64) void {
        if (g.i >= g.o.len) return;
        g.o[g.i] = op;
        g.c[g.i] = cl;
        g.h[g.i] = @max(op, cl) + @max(up, 0.0);
        g.l[g.i] = @min(op, cl) - @max(dn, 0.0);
        g.i += 1;
        g.p = cl;
    }
    /// A bar from `op` to `cl` with shadows on the far sides `up` / `dn`.
    fn sh(g: *Gen) f64 {
        return g.u(0.0, 0.12);
    }
    fn body(g: *Gen, kind: u32) f64 {
        return switch (kind) {
            0 => g.u(0.0, 0.25), // doji-ish
            1 => g.u(0.1, 0.7), // short
            2 => g.u(0.8, 1.8), // medium
            else => g.u(2.2, 5.0), // long
        };
    }

    fn single(g: *Gen) void {
        const s = g.dirSign();
        const p = g.p;
        switch (g.r.uintLessThan(u32, 10)) {
            0 => g.put(p, p + s * g.u(0.0, 0.03), g.u(0.4, 2.5), g.u(0.4, 2.5)), // doji, long shadows
            1 => g.put(p, p + s * g.u(0.0, 0.03), g.u(0.0, 0.05), g.u(1.0, 3.0)), // dragonfly
            2 => g.put(p, p + s * g.u(0.0, 0.03), g.u(1.0, 3.0), g.u(0.0, 0.05)), // gravestone
            3 => g.put(p, p + s * g.body(3), g.sh(), g.sh()), // long body
            4 => g.put(p, p + s * g.body(3), 0.0, 0.0), // marubozu
            5 => g.put(p, p + s * g.body(3), 0.0, g.u(0.1, 0.6)), // opening / closing marubozu
            6 => g.put(p, p + s * g.body(1), g.u(1.0, 3.0), g.sh()), // inverted hammer / shooting star
            7 => g.put(p, p + s * g.body(1), g.sh(), g.u(1.0, 3.0)), // hammer / hanging man
            8 => g.put(p, p + s * g.body(1), g.u(0.3, 1.5), g.u(0.3, 1.5)), // spinning top / high wave
            else => g.put(p, p + s * g.body(2), g.u(0.0, 0.8), g.u(0.0, 0.8)),
        }
    }

    fn twoBar(g: *Gen) void {
        const s = g.dirSign();
        const p = g.p;
        const b1 = g.body(3 - g.r.uintLessThan(u32, 2));
        const c1 = p + s * b1;
        const long1 = g.r.boolean();
        g.put(p, c1, if (long1) 0.0 else g.sh(), if (long1) 0.0 else g.sh());
        switch (g.r.uintLessThan(u32, 8)) {
            0 => { // engulfing: opposite bar covers the first body, ends touching or beyond
                const o2 = c1 + s * g.u(-0.05, 0.4);
                const c2 = p - s * g.u(-0.05, 0.6);
                g.put(o2, c2, g.sh(), g.sh());
            },
            1 => { // harami / harami cross
                const o2 = c1 - s * g.u(0.1, 0.5) * b1;
                g.put(o2, o2 + g.dirSign() * g.body(r2(g)) * 0.3, g.sh(), g.sh());
            },
            2 => { // piercing / dark cloud / thrusting / in-neck / on-neck
                const gap = g.u(0.02, 1.0);
                const frac = switch (g.r.uintLessThan(u32, 4)) {
                    0 => g.u(-0.05, 0.05),
                    1 => g.u(0.1, 0.5),
                    2 => g.u(0.45, 0.6),
                    else => g.u(0.55, 1.0),
                };
                g.put(c1 + s * gap, c1 - s * frac * b1, g.sh(), g.sh());
            },
            3 => { // kicking: marubozu pair with a gap
                const b2 = g.body(3);
                const o2 = c1 + s * g.u(0.1, 1.5);
                g.put(o2, o2 - s * b2, 0.0, 0.0);
            },
            4 => { // separating lines: equal opens, opposite colours
                const b2 = g.body(3);
                const o2 = p + g.u(-0.05, 0.05);
                g.put(o2, o2 - s * b2, g.sh() * 0.1, g.sh() * 0.1);
            },
            5 => { // counterattack / matching low / sticks sandwich: equal closes
                const o2 = c1 + s * g.u(0.0, 1.0);
                g.put(o2, c1 + g.u(-0.06, 0.06), g.sh(), g.sh());
            },
            6 => { // homing pigeon style: second inside, same colour
                const o2 = p + s * g.u(0.1, 0.3) * b1;
                g.put(o2, o2 + s * g.u(0.0, 0.3), g.sh(), g.sh());
            },
            else => { // belt hold / continuation
                const o2 = c1 + g.u(-0.3, 0.3);
                g.put(o2, o2 + g.dirSign() * g.body(3), 0.0, g.sh());
            },
        }
    }
    fn r2(g: *Gen) u32 {
        return g.r.uintLessThan(u32, 3);
    }

    fn star(g: *Gen) void {
        // long body, gapped small body (doji or short), reversal bar
        const s = g.dirSign();
        const p = g.p;
        const b1 = g.body(3);
        const c1 = p + s * b1;
        g.put(p, c1, g.sh(), g.sh());
        const baby = g.r.uintLessThan(u32, 3) == 0;
        const gap = g.u(0.05, 1.0);
        const o2 = c1 + s * (if (baby) g.u(0.6, 1.4) else gap);
        const small: f64 = if (g.r.boolean()) g.u(0.0, 0.04) else g.u(0.05, 0.6);
        const sd = if (baby) 0.0 else g.sh();
        g.put(o2, o2 + g.dirSign() * small, sd, sd);
        const o3 = g.p - s * g.u(0.0, 0.5);
        const depth = g.u(0.2, 1.3);
        g.put(o3, c1 - s * depth * b1, g.sh(), g.sh());
        if (g.r.uintLessThan(u32, 4) == 0) { // tri-star style: three small bars
            g.put(g.p, g.p + g.u(-0.03, 0.03), g.u(0.2, 1.0), g.u(0.2, 1.0));
        }
    }

    fn trio(g: *Gen) void {
        // three steps in one direction: soldiers / crows / advance block / stalled / identical crows
        const s = g.dirSign();
        var cprev = g.p;
        var bprev = g.body(3);
        const mode = g.r.uintLessThan(u32, 4);
        for (0..3) |j| {
            const b = switch (mode) {
                0 => g.u(1.5, 3.5),
                1 => bprev * g.u(0.5, 1.1), // shrinking: advance block
                2 => if (j == 2) g.u(0.05, 0.6) else g.u(1.5, 3.5), // stalled
                else => g.u(1.5, 3.5),
            };
            const o = if (j == 0) cprev else if (mode == 3) cprev + g.u(-0.05, 0.05) else cprev - s * g.u(0.0, 0.7) * bprev;
            g.put(o, o + s * b, if (s > 0) g.u(0.0, 0.9) else g.sh(), if (s > 0) g.sh() else g.u(0.0, 0.9));
            cprev = g.p;
            bprev = b;
        }
        if (g.r.uintLessThan(u32, 3) == 0) { // fourth bar: three line strike / three inside / outside
            const o4 = g.p + s * g.u(0.0, 0.5);
            g.put(o4, o4 - s * g.u(1.0, 9.0), g.sh(), g.sh());
        }
    }

    fn five(g: *Gen) void {
        // mat hold / rising and falling three methods / breakaway
        const s = g.dirSign();
        const p = g.p;
        const b1 = g.body(3);
        const c1 = p + s * b1;
        g.put(p, c1, g.sh(), g.sh());
        if (g.r.boolean()) { // methods: three small counter bars inside the first range
            const gap = if (g.r.boolean()) g.u(0.05, 0.6) else 0.0;
            var o = c1 + s * gap - s * g.u(0.0, 0.2);
            for (0..3) |_| {
                const b = g.u(0.05, 0.5);
                g.put(o, o - s * b, g.sh(), g.sh());
                o = g.p + s * g.u(-0.1, 0.1);
            }
            const o5 = g.p + s * g.u(0.0, 0.4);
            g.put(o5, c1 + s * g.u(-0.3, 1.5), g.sh(), g.sh());
        } else { // breakaway: gap, two bars further in the same direction, then the reversal
            const o2 = c1 + s * g.u(0.1, 1.0);
            g.put(o2, o2 + s * g.u(0.05, 0.8), g.sh(), g.sh());
            for (0..2) |_| {
                const o = g.p - s * g.u(0.0, 0.3);
                g.put(o, o + s * g.u(0.1, 0.9), g.sh(), g.sh());
            }
            const o5 = g.p - s * g.u(0.0, 0.4);
            g.put(o5, o5 - s * g.u(1.0, 4.0), g.sh(), g.sh());
        }
    }

    fn special(g: *Gen) void {
        switch (g.r.uintLessThan(u32, 8)) {
            0 => { // hikkake: wide bar, inside bar, breakout bar, then confirmation or not
                const p = g.p;
                g.put(p, p + g.u(-0.5, 0.5), g.u(1.0, 3.0), g.u(1.0, 3.0));
                const h0 = g.h[g.i - 1];
                const l0 = g.l[g.i - 1];
                const hi = h0 - g.u(0.1, 0.5);
                const lo = l0 + g.u(0.1, 0.5);
                const mid = (hi + lo) / 2.0;
                if (g.i < g.o.len) {
                    g.o[g.i] = mid;
                    g.c[g.i] = mid + g.u(-0.1, 0.1);
                    g.h[g.i] = hi;
                    g.l[g.i] = lo;
                    g.i += 1;
                    g.p = g.c[g.i - 1];
                }
                const up = g.r.boolean();
                const d = g.u(0.1, 0.4);
                if (g.i < g.o.len) {
                    g.o[g.i] = mid;
                    g.c[g.i] = mid + (if (up) d else -d);
                    g.h[g.i] = if (up) hi + g.u(0.1, 0.5) else hi - d;
                    g.l[g.i] = if (up) lo + d else lo - g.u(0.1, 0.5);
                    g.h[g.i] = @max(g.h[g.i], @max(g.o[g.i], g.c[g.i]));
                    g.l[g.i] = @min(g.l[g.i], @min(g.o[g.i], g.c[g.i]));
                    g.i += 1;
                    g.p = g.c[g.i - 1];
                }
                const k = g.r.uintLessThan(u32, 3);
                for (0..k) |_| {
                    const o = g.p;
                    const cl = if (up) hi - g.u(0.0, 0.8) else lo + g.u(0.0, 0.8);
                    const cl2 = if (g.r.boolean()) (if (up) lo - g.u(0.1, 0.7) else hi + g.u(0.1, 0.7)) else cl;
                    g.put(o, cl2, g.sh(), g.sh());
                }
            },
            1 => { // ladder bottom
                const p = g.p;
                var o = p;
                for (0..3) |_| {
                    const b = g.u(1.0, 2.5);
                    g.put(o, o - b, g.sh(), g.sh());
                    o = g.p + g.u(0.2, 1.2);
                }
                const b4 = g.u(0.5, 1.5);
                g.put(g.o[g.i - 1] - g.u(0.0, 0.6), g.p - b4, g.u(0.3, 1.5), g.sh());
                const o5 = g.o[g.i - 1] + g.u(0.1, 0.8);
                g.put(o5, g.h[g.i - 1] + g.u(0.1, 1.5), g.sh(), g.sh());
            },
            2 => { // concealing baby swallow
                const p = g.p;
                g.put(p, p - g.u(2.0, 4.0), 0.0, 0.0);
                const o2 = g.p - g.u(0.1, 0.8);
                g.put(o2, o2 - g.u(2.0, 4.0), 0.0, 0.0);
                const o3 = g.p - g.u(0.1, 0.8);
                const c3 = o3 - g.u(0.1, 1.0);
                g.put(o3, c3, g.o[g.i - 1] - o3 + g.u(0.2, 1.5), 0.0);
                const h3 = g.h[g.i - 1];
                const l3 = g.l[g.i - 1];
                g.put(h3 + g.u(-0.3, 0.2), l3 - g.u(0.1, 1.0), 0.0, 0.0);
            },
            3 => { // unique three river
                const p = g.p;
                g.put(p, p - g.u(2.5, 4.0), g.sh(), g.sh());
                const o2 = g.o[g.i - 1] - g.u(0.0, 0.3);
                const c2 = g.p + g.u(0.1, 0.6);
                g.put(o2, c2, g.sh(), g.u(0.5, 1.5));
                const o3 = g.l[g.i - 1] + g.u(0.05, 0.3);
                g.put(o3, o3 + g.u(0.05, 0.5), g.sh(), g.sh());
            },
            4 => { // three stars in the south
                const p = g.p;
                g.put(p, p - g.u(2.5, 4.0), g.sh(), g.u(1.0, 3.0));
                const c1 = g.p;
                const o2 = c1 + g.u(0.2, 1.0);
                g.put(o2, o2 - g.u(1.0, 2.0), g.sh(), g.u(0.3, 1.0));
                const o3 = g.p + g.u(0.3, 0.8);
                const c3 = o3 - g.u(0.1, 0.4);
                g.put(o3, c3, 0.0, 0.0);
            },
            5, 6 => { // two crows / upside gap two crows (white long bar, gapped black small bar, black bar)
                const p = g.p;
                const b1 = g.u(2.5, 4.5);
                g.put(p, p + b1, g.sh(), g.sh());
                const c1 = g.p;
                const gap = g.u(0.1, 0.8);
                const o2 = c1 + gap;
                g.put(o2, o2 - gap * g.u(0.1, 0.9), g.sh(), g.sh());
                const c2 = g.p;
                if (g.r.boolean()) {
                    const o3 = c2 + g.u(0.05, 0.95) * (o2 - c2);
                    g.put(o3, c1 - g.u(0.1, 0.9) * b1, g.sh(), g.sh());
                } else {
                    const o3 = o2 + g.u(0.05, 0.5);
                    g.put(o3, c1 + g.u(0.05, 0.95) * (c2 - c1), g.sh(), g.sh());
                }
            },
            else => { // upside / downside gap tasuki, gap side-by-side white lines, gap three methods
                const s = g.dirSign();
                const p = g.p;
                const b1 = g.body(2);
                g.put(p, p + s * b1, g.sh(), g.sh());
                const c1 = g.p;
                const o2 = c1 + s * g.u(0.3, 1.2);
                const b2 = g.body(2);
                g.put(o2, o2 + s * b2, g.sh(), g.sh());
                const mode = g.r.uintLessThan(u32, 3);
                if (mode == 0) { // tasuki: third opens inside the second body, closes in the gap
                    const o3 = g.p - s * g.u(0.1, 0.5) * b2;
                    g.put(o3, c1 + s * g.u(0.0, 0.25), g.sh(), g.sh());
                } else if (mode == 1) { // side-by-side: third opens near the second open
                    g.put(o2 + g.u(-0.05, 0.05), o2 + s * g.u(0.8, 2.0), g.sh(), g.sh());
                } else { // gap three methods: third opposite, opens inside the second body, closes inside the first
                    const o3 = g.p - s * g.u(0.1, 0.8) * b2;
                    g.put(o3, p + s * g.u(0.1, 0.9) * b1, g.sh(), g.sh());
                }
            },
        }
    }
};

/// Fill the four series with `kind`-flavoured candle patterns. Always low <= min(open, close),
/// high >= max(open, close).
pub fn genCandles(seed: u64, kind: u8, o: []f64, h: []f64, l: []f64, c: []f64) void {
    var prng = std.Random.DefaultPrng.init(seed ^ 0x6361_6e64_6c65);
    var g: Gen = .{ .r = prng.random(), .o = o, .h = h, .l = l, .c = c };
    while (g.i < o.len) {
        switch (g.r.uintLessThan(u32, 100)) {
            0...29 => g.single(),
            30...49 => g.twoBar(),
            50...59 => g.star(),
            60...69 => g.trio(),
            70...77 => g.five(),
            78...91 => g.special(),
            else => {
                const d = (g.r.float(f64) - 0.5) * 2.5;
                g.put(g.p, g.p + d, g.r.float(f64) * 0.8, g.r.float(f64) * 0.8);
            },
        }
        // keep the walk near 100 so thresholds stay comparable
        if (g.p < 40.0 or g.p > 160.0) g.p = 100.0;
    }
    switch (kind) {
        1 => for (o, h, l, c) |*oo, *hh, *ll, *cc| {
            oo.* = @round(oo.* * 4.0) / 4.0;
            cc.* = @round(cc.* * 4.0) / 4.0;
            hh.* = @max(@round(hh.* * 4.0) / 4.0, @max(oo.*, cc.*));
            ll.* = @min(@round(ll.* * 4.0) / 4.0, @min(oo.*, cc.*));
        },
        2 => for (o, h, l, c) |*oo, *hh, *ll, *cc| {
            oo.* *= 1e-9;
            hh.* *= 1e-9;
            ll.* *= 1e-9;
            cc.* *= 1e-9;
        },
        else => {},
    }
}

/// Settings presets of the oracle: 0 is TA-Lib's default table, 1..4 move every setting
/// (range type, averaging period, factor) so the settings are shown to be honoured.
pub fn presetSettings(k: u8) CandleSettings {
    var s: CandleSettings = .default;
    switch (k) {
        1 => {
            s.body_long = .{ .range = .high_low, .avg_period = 4, .factor = 0.9 };
            s.body_short = .{ .range = .real_body, .avg_period = 3, .factor = 1.3 };
            s.body_doji = .{ .range = .real_body, .avg_period = 2, .factor = 0.2 };
            s.shadow_long = .{ .range = .shadows, .avg_period = 3, .factor = 0.7 };
            s.shadow_very_short = .{ .range = .real_body, .avg_period = 6, .factor = 0.3 };
            s.near = .{ .range = .shadows, .avg_period = 2, .factor = 0.5 };
            s.equal = .{ .range = .high_low, .avg_period = 0, .factor = 0.1 };
            s.far = .{ .range = .real_body, .avg_period = 7, .factor = 0.8 };
        },
        2 => { // every averaging period 0: the candle's own range is the average
            inline for (std.enums.values(ind.candles.SetId)) |id| @field(s, @tagName(id)).avg_period = 0;
        },
        3 => { // long averaging periods, doubled factors
            inline for (std.enums.values(ind.candles.SetId)) |id| {
                @field(s, @tagName(id)).avg_period = 20;
                @field(s, @tagName(id)).factor *= 2.0;
            }
        },
        4 => { // rotated range types, short periods
            s.body_long = .{ .range = .shadows, .avg_period = 1, .factor = 1.0 };
            s.body_very_long = .{ .range = .high_low, .avg_period = 2, .factor = 3.0 };
            s.body_short = .{ .range = .high_low, .avg_period = 1, .factor = 0.4 };
            s.body_doji = .{ .range = .shadows, .avg_period = 1, .factor = 0.3 };
            s.shadow_long = .{ .range = .high_low, .avg_period = 1, .factor = 0.5 };
            s.shadow_very_long = .{ .range = .shadows, .avg_period = 0, .factor = 1.0 };
            s.shadow_short = .{ .range = .real_body, .avg_period = 2, .factor = 1.5 };
            s.shadow_very_short = .{ .range = .shadows, .avg_period = 1, .factor = 0.2 };
            s.near = .{ .range = .real_body, .avg_period = 1, .factor = 0.7 };
            s.far = .{ .range = .shadows, .avg_period = 1, .factor = 1.2 };
            s.equal = .{ .range = .real_body, .avg_period = 2, .factor = 0.15 };
        },
        else => {},
    }
    return s;
}
