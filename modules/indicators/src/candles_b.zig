// SPDX-License-Identifier: MIT
//! Candlestick patterns, part B (TA-Lib `ta_CDLMARUBOZU.c` ... `ta_CDLXSIDEGAP3METHODS.c`;
//! BSD-3, see NOTICE). Same scheme as `candles_a.zig`.

const cc = @import("candles_core.zig");
const tot = cc.tot;
const Tot = cc.Tot;
const SetId = cc.SetId;

pub const Cdlmarubozu = struct {
    pub const tots = [_]Tot{ tot(.body_long, 0), tot(.shadow_very_short, 0) };
    pub const lb_sets = [_]SetId{ .body_long, .shadow_very_short };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) > w.avg(.body_long, 0) and
            w.upper(0) < w.avg(.shadow_very_short, 0) and
            w.lower(0) < w.avg(.shadow_very_short, 0)) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdlmatchinglow = struct {
    pub const tots = [_]Tot{tot(.equal, 1)};
    pub const lb_sets = [_]SetId{.equal};
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -1 and
            w.color(0) == -1 and
            w.c(0) <= w.c(1) + w.avg(.equal, 1) and
            w.c(0) >= w.c(1) - w.avg(.equal, 1)) return 100;
        return 0;
    }
};

pub const Cdlmorningdojistar = struct {
    pub const pen_default: f64 = 0.3;
    pub const tots = [_]Tot{ tot(.body_long, 2), tot(.body_doji, 1), tot(.body_short, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .body_long, .body_short };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == -1 and
            w.color(0) == 1 and
            w.bodyGapDown(1, 2) and
            w.c(0) > @mulAdd(f64, w.body(2), w.pen, w.c(2)) and
            w.body(2) > w.avg(.body_long, 2) and
            w.body(1) <= w.avg(.body_doji, 1) and
            w.body(0) > w.avg(.body_short, 0)) return 100;
        return 0;
    }
};

pub const Cdlmorningstar = struct {
    pub const pen_default: f64 = 0.3;
    pub const tots = [_]Tot{ tot(.body_long, 2), tot(.body_short, 1), tot(.body_short, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .body_long };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == -1 and
            w.color(0) == 1 and
            w.bodyGapDown(1, 2) and
            w.c(0) > @mulAdd(f64, w.body(2), w.pen, w.c(2)) and
            w.body(2) > w.avg(.body_long, 2) and
            w.body(1) <= w.avg(.body_short, 1) and
            w.body(0) > w.avg(.body_short, 0)) return 100;
        return 0;
    }
};

pub const Cdlonneck = struct {
    pub const tots = [_]Tot{ tot(.equal, 1), tot(.body_long, 1) };
    pub const lb_sets = [_]SetId{ .equal, .body_long };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -1 and
            w.body(1) > w.avg(.body_long, 1) and
            w.color(0) == 1 and
            w.o(0) < w.l(1) and
            w.c(0) <= w.l(1) + w.avg(.equal, 1) and
            w.c(0) >= w.l(1) - w.avg(.equal, 1)) return -100;
        return 0;
    }
};

pub const Cdlpiercing = struct {
    pub const tots = [_]Tot{ tot(.body_long, 1), tot(.body_long, 0) };
    pub const lb_sets = [_]SetId{.body_long};
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -1 and
            w.body(1) > w.avg(.body_long, 1) and
            w.color(0) == 1 and
            w.body(0) > w.avg(.body_long, 0) and
            w.o(0) < w.l(1) and
            w.c(0) < w.o(1) and
            w.c(0) > @mulAdd(f64, w.body(1), 0.5, w.c(1))) return 100;
        return 0;
    }
};

pub const Cdlrickshawman = struct {
    pub const tots = [_]Tot{ tot(.body_doji, 0), tot(.shadow_long, 0), tot(.near, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .shadow_long, .near };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) <= w.avg(.body_doji, 0) and
            w.lower(0) > w.avg(.shadow_long, 0) and
            w.upper(0) > w.avg(.shadow_long, 0) and
            (w.minOc(0) <= w.l(0) + (w.h(0) - w.l(0)) / 2.0 + w.avg(.near, 0) and
                w.maxOc(0) >= w.l(0) + (w.h(0) - w.l(0)) / 2.0 - w.avg(.near, 0))) return 100;
        return 0;
    }
};

pub const Cdlmathold = struct {
    pub const pen_default: f64 = 0.5;
    pub const tots = [_]Tot{ tot(.body_long, 4), tot(.body_short, 3), tot(.body_short, 2), tot(.body_short, 1) };
    pub const lb_sets = [_]SetId{ .body_short, .body_long };
    pub const lb_add = 4;
    pub fn eval(w: anytype) i32 {
        if (w.color(4) == 1 and
            w.color(3) == -1 and
            w.color(0) == 1 and
            w.bodyGapUp(3, 4) and
            w.minOc(2) < w.c(4) and
            w.minOc(1) < w.c(4) and
            w.minOc(2) > w.c(4) - w.body(4) * w.pen and
            w.minOc(1) > w.c(4) - w.body(4) * w.pen and
            w.maxOc(2) < w.o(3) and
            w.maxOc(1) < w.maxOc(2) and
            w.o(0) > w.c(1) and
            w.c(0) > @max(@max(w.h(3), w.h(2)), w.h(1)) and
            w.body(4) > w.avg(.body_long, 4) and
            w.body(3) < w.avg(.body_short, 3) and
            w.body(2) < w.avg(.body_short, 2) and
            w.body(1) < w.avg(.body_short, 1)) return 100;
        return 0;
    }
};

pub const Cdlrisefall3methods = struct {
    pub const tots = [_]Tot{ tot(.body_long, 4), tot(.body_short, 3), tot(.body_short, 2), tot(.body_short, 1), tot(.body_long, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .body_long };
    pub const lb_add = 4;
    pub fn eval(w: anytype) i32 {
        const k: f64 = @floatFromInt(w.color(4));
        if (w.color(4) == -w.color(3) and
            w.color(3) == w.color(2) and
            w.color(2) == w.color(1) and
            w.color(1) == -w.color(0) and
            w.minOc(3) < w.h(4) and
            w.maxOc(3) > w.l(4) and
            w.minOc(2) < w.h(4) and
            w.maxOc(2) > w.l(4) and
            w.minOc(1) < w.h(4) and
            w.maxOc(1) > w.l(4) and
            w.c(2) * k < w.c(3) * k and
            w.c(1) * k < w.c(2) * k and
            w.o(0) * k > w.c(1) * k and
            w.c(0) * k > w.c(4) * k and
            w.body(4) > w.avg(.body_long, 4) and
            w.body(3) < w.avg(.body_short, 3) and
            w.body(2) < w.avg(.body_short, 2) and
            w.body(1) < w.avg(.body_short, 1) and
            w.body(0) > w.avg(.body_long, 0)) return 100 * w.color(4);
        return 0;
    }
};

pub const Cdlseparatinglines = struct {
    pub const tots = [_]Tot{ tot(.shadow_very_short, 0), tot(.body_long, 0), tot(.equal, 1) };
    pub const lb_sets = [_]SetId{ .shadow_very_short, .body_long, .equal };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -w.color(0) and
            w.o(0) <= w.o(1) + w.avg(.equal, 1) and
            w.o(0) >= w.o(1) - w.avg(.equal, 1) and
            w.body(0) > w.avg(.body_long, 0) and
            ((w.color(0) == 1 and w.lower(0) < w.avg(.shadow_very_short, 0)) or
                (w.color(0) == -1 and w.upper(0) < w.avg(.shadow_very_short, 0)))) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdlshootingstar = struct {
    pub const tots = [_]Tot{ tot(.body_short, 0), tot(.shadow_long, 0), tot(.shadow_very_short, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .shadow_long, .shadow_very_short };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.bodyGapUp(0, 1) and
            w.body(0) < w.avg(.body_short, 0) and
            w.upper(0) > w.avg(.shadow_long, 0) and
            w.lower(0) < w.avg(.shadow_very_short, 0)) return -100;
        return 0;
    }
};

pub const Cdlshortline = struct {
    pub const tots = [_]Tot{ tot(.body_short, 0), tot(.shadow_short, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .shadow_short };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) < w.avg(.body_short, 0) and
            w.upper(0) < w.avg(.shadow_short, 0) and
            w.lower(0) < w.avg(.shadow_short, 0)) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdlspinningtop = struct {
    pub const tots = [_]Tot{tot(.body_short, 0)};
    pub const lb_sets = [_]SetId{.body_short};
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.upper(0) > w.body(0) and
            w.lower(0) > w.body(0) and
            w.body(0) < w.avg(.body_short, 0)) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdlstalledpattern = struct {
    pub const tots = [_]Tot{
        tot(.body_long, 2), tot(.body_long, 1),  tot(.near, 2),
        tot(.near, 1),      tot(.body_short, 0), tot(.shadow_very_short, 1),
    };
    pub const lb_sets = [_]SetId{ .body_long, .body_short, .shadow_very_short, .near };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == 1 and
            w.color(1) == 1 and
            w.color(0) == 1 and
            w.c(0) > w.c(1) and
            w.c(1) > w.c(2) and
            w.body(2) > w.avg(.body_long, 2) and
            w.body(1) > w.avg(.body_long, 1) and
            w.upper(1) < w.avg(.shadow_very_short, 1) and
            w.o(1) > w.o(2) and
            w.o(1) <= w.c(2) + w.avg(.near, 2) and
            w.body(0) < w.avg(.body_short, 0) and
            w.o(0) >= w.c(1) - w.body(0) - w.avg(.near, 1)) return -100;
        return 0;
    }
};

pub const Cdlsticksandwich = struct {
    pub const tots = [_]Tot{tot(.equal, 2)};
    pub const lb_sets = [_]SetId{.equal};
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == -1 and
            w.color(1) == 1 and
            w.color(0) == -1 and
            w.l(1) > w.c(2) and
            w.c(0) <= w.c(2) + w.avg(.equal, 2) and
            w.c(0) >= w.c(2) - w.avg(.equal, 2)) return 100;
        return 0;
    }
};

pub const Cdltakuri = struct {
    pub const tots = [_]Tot{ tot(.body_doji, 0), tot(.shadow_very_short, 0), tot(.shadow_very_long, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .shadow_very_short, .shadow_very_long };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) <= w.avg(.body_doji, 0) and
            w.upper(0) < w.avg(.shadow_very_short, 0) and
            w.lower(0) > w.avg(.shadow_very_long, 0)) return 100;
        return 0;
    }
};

pub const Cdltasukigap = struct {
    pub const tots = [_]Tot{tot(.near, 1)};
    pub const lb_sets = [_]SetId{.near};
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if ((w.bodyGapUp(1, 2) and
            w.color(1) == 1 and
            w.color(0) == -1 and
            w.o(0) < w.c(1) and
            w.o(0) > w.o(1) and
            w.c(0) < w.o(1) and
            w.c(0) > w.maxOc(2) and
            @abs(w.body(1) - w.body(0)) < w.avg(.near, 1)) or
            (w.bodyGapDown(1, 2) and
                w.color(1) == -1 and
                w.color(0) == 1 and
                w.o(0) < w.o(1) and
                w.o(0) > w.c(1) and
                w.c(0) > w.o(1) and
                w.c(0) < w.minOc(2) and
                @abs(w.body(1) - w.body(0)) < w.avg(.near, 1))) return w.color(1) * 100;
        return 0;
    }
};

pub const Cdlthrusting = struct {
    pub const tots = [_]Tot{ tot(.equal, 1), tot(.body_long, 1) };
    pub const lb_sets = [_]SetId{ .equal, .body_long };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -1 and
            w.body(1) > w.avg(.body_long, 1) and
            w.color(0) == 1 and
            w.o(0) < w.l(1) and
            w.c(0) > w.c(1) + w.avg(.equal, 1) and
            w.c(0) <= @mulAdd(f64, w.body(1), 0.5, w.c(1))) return -100;
        return 0;
    }
};

pub const Cdltristar = struct {
    pub const tots = [_]Tot{tot(.body_doji, 2)};
    pub const lb_sets = [_]SetId{.body_doji};
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.body(2) <= w.avg(.body_doji, 2) and
            w.body(1) <= w.avg(.body_doji, 2) and
            w.body(0) <= w.avg(.body_doji, 2))
        {
            var out: i32 = 0;
            if (w.bodyGapUp(1, 2) and w.maxOc(0) < w.maxOc(1)) out = -100;
            if (w.bodyGapDown(1, 2) and w.minOc(0) > w.minOc(1)) out = 100;
            return out;
        }
        return 0;
    }
};

pub const Cdlunique3river = struct {
    pub const tots = [_]Tot{ tot(.body_long, 2), tot(.body_short, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .body_long };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == -1 and
            w.color(1) == -1 and
            w.color(0) == 1 and
            w.c(1) > w.c(2) and
            w.o(1) <= w.o(2) and
            w.l(1) < w.l(2) and
            w.o(0) > w.l(1) and
            w.body(2) > w.avg(.body_long, 2) and
            w.body(0) < w.avg(.body_short, 0)) return 100;
        return 0;
    }
};

pub const Cdlupsidegap2crows = struct {
    pub const tots = [_]Tot{ tot(.body_long, 2), tot(.body_short, 1) };
    pub const lb_sets = [_]SetId{ .body_short, .body_long };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == 1 and
            w.body(2) > w.avg(.body_long, 2) and
            w.color(1) == -1 and
            w.body(1) <= w.avg(.body_short, 1) and
            w.bodyGapUp(1, 2) and
            w.color(0) == -1 and
            w.o(0) > w.o(1) and
            w.c(0) < w.c(1) and
            w.c(0) > w.c(2)) return -100;
        return 0;
    }
};

pub const Cdlxsidegap3methods = struct {
    pub const tots = [_]Tot{};
    pub const lb_sets = [_]SetId{};
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == w.color(1) and
            w.color(1) == -w.color(0) and
            w.o(0) < w.maxOc(1) and
            w.o(0) > w.minOc(1) and
            w.c(0) < w.maxOc(2) and
            w.c(0) > w.minOc(2) and
            ((w.color(2) == 1 and w.bodyGapUp(1, 2)) or
                (w.color(2) == -1 and w.bodyGapDown(1, 2)))) return w.color(2) * 100;
        return 0;
    }
};
