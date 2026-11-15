// SPDX-License-Identifier: MIT
//! Candlestick patterns, part A (TA-Lib `ta_CDL2CROWS.c` ... `ta_CDLEVENINGSTAR.c`;
//! BSD-3, see NOTICE). Each pattern is a comptime description run by
//! `candles_core.Engine`; the tests are the C's conditions, transcribed in the
//! C's order of operations.

const cc = @import("candles_core.zig");
const tot = cc.tot;
const Tot = cc.Tot;
const SetId = cc.SetId;

pub const Cdl2crows = struct {
    pub const tots = [_]Tot{tot(.body_long, 2)};
    pub const lb_sets = [_]SetId{.body_long};
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == 1 and
            w.body(2) > w.avg(.body_long, 2) and
            w.color(1) == -1 and
            w.minOc(1) > w.maxOc(2) and
            w.color(0) == -1 and
            w.o(0) < w.o(1) and
            w.o(0) > w.c(1) and
            w.c(0) > w.o(2) and
            w.c(0) < w.c(2)) return -100;
        return 0;
    }
};

pub const Cdl3blackcrows = struct {
    pub const tots = [_]Tot{ tot(.shadow_very_short, 2), tot(.shadow_very_short, 1), tot(.shadow_very_short, 0) };
    pub const lb_sets = [_]SetId{.shadow_very_short};
    pub const lb_add = 3;
    pub fn eval(w: anytype) i32 {
        if (w.color(3) == 1 and
            w.color(2) == -1 and
            w.color(1) == -1 and
            w.color(0) == -1 and
            w.o(1) < w.o(2) and
            w.o(1) > w.c(2) and
            w.o(0) < w.o(1) and
            w.o(0) > w.c(1) and
            w.h(3) > w.c(2) and
            w.c(2) > w.c(1) and
            w.c(1) > w.c(0) and
            w.lower(2) < w.avg(.shadow_very_short, 2) and
            w.lower(1) < w.avg(.shadow_very_short, 1) and
            w.lower(0) < w.avg(.shadow_very_short, 0)) return -100;
        return 0;
    }
};

pub const Cdl3inside = struct {
    pub const tots = [_]Tot{ tot(.body_long, 2), tot(.body_short, 1) };
    pub const lb_sets = [_]SetId{ .body_short, .body_long };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.maxOc(1) < w.maxOc(2) and
            w.minOc(1) > w.minOc(2) and
            ((w.color(2) == 1 and w.color(0) == -1 and w.c(0) < w.o(2)) or
                (w.color(2) == -1 and w.color(0) == 1 and w.c(0) > w.o(2))) and
            w.body(2) > w.avg(.body_long, 2) and
            w.body(1) <= w.avg(.body_short, 1)) return -w.color(2) * 100;
        return 0;
    }
};

pub const Cdl3linestrike = struct {
    pub const tots = [_]Tot{ tot(.near, 3), tot(.near, 2) };
    pub const lb_sets = [_]SetId{.near};
    pub const lb_add = 3;
    pub fn eval(w: anytype) i32 {
        if (w.color(3) == w.color(2) and
            w.color(2) == w.color(1) and
            w.color(0) == -w.color(1) and
            w.o(2) >= w.minOc(3) - w.avg(.near, 3) and
            w.o(2) <= w.maxOc(3) + w.avg(.near, 3) and
            w.o(1) >= w.minOc(2) - w.avg(.near, 2) and
            w.o(1) <= w.maxOc(2) + w.avg(.near, 2) and
            ((w.color(1) == 1 and
                w.c(1) > w.c(2) and
                w.c(2) > w.c(3) and
                w.o(0) > w.c(1) and
                w.c(0) < w.o(3)) or
                (w.color(1) == -1 and
                    w.c(1) < w.c(2) and
                    w.c(2) < w.c(3) and
                    w.o(0) < w.c(1) and
                    w.c(0) > w.o(3)))) return w.color(1) * 100;
        return 0;
    }
};

pub const Cdl3outside = struct {
    pub const tots = [_]Tot{};
    pub const lb_sets = [_]SetId{};
    pub const lb_add = 3;
    pub fn eval(w: anytype) i32 {
        if ((w.color(1) == 1 and
            w.color(2) == -1 and
            w.c(1) > w.o(2) and
            w.o(1) < w.c(2) and
            w.c(0) > w.c(1)) or
            (w.color(1) == -1 and
                w.color(2) == 1 and
                w.o(1) > w.c(2) and
                w.c(1) < w.o(2) and
                w.c(0) < w.c(1))) return w.color(1) * 100;
        return 0;
    }
};

pub const Cdl3starsinsouth = struct {
    pub const tots = [_]Tot{ tot(.body_long, 2), tot(.shadow_long, 2), tot(.shadow_very_short, 1), tot(.shadow_very_short, 0), tot(.body_short, 0) };
    pub const lb_sets = [_]SetId{ .shadow_very_short, .shadow_long, .body_long, .body_short };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == -1 and
            w.color(1) == -1 and
            w.color(0) == -1 and
            w.body(2) > w.avg(.body_long, 2) and
            w.lower(2) > w.avg(.shadow_long, 2) and
            w.body(1) < w.body(2) and
            w.o(1) > w.c(2) and
            w.o(1) <= w.h(2) and
            w.l(1) < w.c(2) and
            w.l(1) >= w.l(2) and
            w.lower(1) > w.avg(.shadow_very_short, 1) and
            w.body(0) < w.avg(.body_short, 0) and
            w.lower(0) < w.avg(.shadow_very_short, 0) and
            w.upper(0) < w.avg(.shadow_very_short, 0) and
            w.l(0) > w.l(1) and
            w.h(0) < w.h(1)) return 100;
        return 0;
    }
};

pub const Cdl3whitesoldiers = struct {
    pub const tots = [_]Tot{
        tot(.shadow_very_short, 2), tot(.shadow_very_short, 1), tot(.shadow_very_short, 0),
        tot(.near, 2),              tot(.near, 1),              tot(.far, 2),
        tot(.far, 1),               tot(.body_short, 0),
    };
    pub const lb_sets = [_]SetId{ .shadow_very_short, .body_short, .far, .near };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == 1 and
            w.upper(2) < w.avg(.shadow_very_short, 2) and
            w.color(1) == 1 and
            w.upper(1) < w.avg(.shadow_very_short, 1) and
            w.color(0) == 1 and
            w.upper(0) < w.avg(.shadow_very_short, 0) and
            w.c(0) > w.c(1) and
            w.c(1) > w.c(2) and
            w.o(1) > w.o(2) and
            w.o(1) <= w.c(2) + w.avg(.near, 2) and
            w.o(0) > w.o(1) and
            w.o(0) <= w.c(1) + w.avg(.near, 1) and
            w.body(1) > w.body(2) - w.avg(.far, 2) and
            w.body(0) > w.body(1) - w.avg(.far, 1) and
            w.body(0) > w.avg(.body_short, 0)) return 100;
        return 0;
    }
};

pub const Cdlabandonedbaby = struct {
    pub const pen_default: f64 = 0.3;
    pub const tots = [_]Tot{ tot(.body_long, 2), tot(.body_doji, 1), tot(.body_short, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .body_long, .body_short };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.body(2) > w.avg(.body_long, 2) and
            w.body(1) <= w.avg(.body_doji, 1) and
            w.body(0) > w.avg(.body_short, 0) and
            ((w.color(2) == 1 and
                w.color(0) == -1 and
                w.c(0) < w.c(2) - w.body(2) * w.pen and
                w.gapUp(1, 2) and
                w.gapDown(0, 1)) or
                (w.color(2) == -1 and
                    w.color(0) == 1 and
                    w.c(0) > @mulAdd(f64, w.body(2), w.pen, w.c(2)) and
                    w.gapDown(1, 2) and
                    w.gapUp(0, 1)))) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdladvanceblock = struct {
    pub const tots = [_]Tot{
        tot(.shadow_short, 2), tot(.shadow_short, 1), tot(.shadow_short, 0),
        tot(.shadow_long, 1),  tot(.shadow_long, 0),  tot(.far, 2),
        tot(.far, 1),          tot(.near, 2),         tot(.near, 1),
        tot(.body_long, 2),
    };
    pub const lb_sets = [_]SetId{ .shadow_long, .shadow_short, .far, .near, .body_long };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == 1 and
            w.color(1) == 1 and
            w.color(0) == 1 and
            w.c(0) > w.c(1) and
            w.c(1) > w.c(2) and
            w.o(1) > w.o(2) and
            w.o(1) <= w.c(2) + w.avg(.near, 2) and
            w.o(0) > w.o(1) and
            w.o(0) <= w.c(1) + w.avg(.near, 1) and
            w.body(2) > w.avg(.body_long, 2) and
            w.upper(2) < w.avg(.shadow_short, 2) and
            ((w.body(1) < w.body(2) - w.avg(.far, 2) and
                w.body(0) < w.body(1) + w.avg(.near, 1)) or
                w.body(0) < w.body(1) - w.avg(.far, 1) or
                (w.body(0) < w.body(1) and
                    w.body(1) < w.body(2) and
                    (w.upper(0) > w.avg(.shadow_short, 0) or
                        w.upper(1) > w.avg(.shadow_short, 1))) or
                (w.body(0) < w.body(1) and
                    w.upper(0) > w.avg(.shadow_long, 0)))) return -100;
        return 0;
    }
};

pub const Cdlbelthold = struct {
    pub const tots = [_]Tot{ tot(.body_long, 0), tot(.shadow_very_short, 0) };
    pub const lb_sets = [_]SetId{ .body_long, .shadow_very_short };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) > w.avg(.body_long, 0) and
            ((w.color(0) == 1 and w.lower(0) < w.avg(.shadow_very_short, 0)) or
                (w.color(0) == -1 and w.upper(0) < w.avg(.shadow_very_short, 0)))) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdlbreakaway = struct {
    pub const tots = [_]Tot{tot(.body_long, 4)};
    pub const lb_sets = [_]SetId{.body_long};
    pub const lb_add = 4;
    pub fn eval(w: anytype) i32 {
        if (w.color(4) == w.color(3) and
            w.color(3) == w.color(1) and
            w.color(1) == -w.color(0) and
            w.body(4) > w.avg(.body_long, 4) and
            ((w.color(4) == -1 and
                w.maxOc(3) < w.minOc(4) and
                w.h(2) < w.h(3) and
                w.l(2) < w.l(3) and
                w.h(1) < w.h(2) and
                w.l(1) < w.l(2) and
                w.c(0) > w.o(3) and
                w.c(0) < w.c(4)) or
                (w.color(4) == 1 and
                    w.minOc(3) > w.maxOc(4) and
                    w.h(2) > w.h(3) and
                    w.l(2) > w.l(3) and
                    w.h(1) > w.h(2) and
                    w.l(1) > w.l(2) and
                    w.c(0) < w.o(3) and
                    w.c(0) > w.c(4)))) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdlclosingmarubozu = struct {
    pub const tots = [_]Tot{ tot(.body_long, 0), tot(.shadow_very_short, 0) };
    pub const lb_sets = [_]SetId{ .body_long, .shadow_very_short };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) > w.avg(.body_long, 0) and
            ((w.color(0) == 1 and w.upper(0) < w.avg(.shadow_very_short, 0)) or
                (w.color(0) == -1 and w.lower(0) < w.avg(.shadow_very_short, 0)))) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdlconcealbabyswall = struct {
    pub const tots = [_]Tot{ tot(.shadow_very_short, 3), tot(.shadow_very_short, 2), tot(.shadow_very_short, 1) };
    pub const lb_sets = [_]SetId{.shadow_very_short};
    pub const lb_add = 3;
    pub fn eval(w: anytype) i32 {
        if (w.color(3) == -1 and
            w.color(2) == -1 and
            w.color(1) == -1 and
            w.color(0) == -1 and
            w.lower(3) < w.avg(.shadow_very_short, 3) and
            w.upper(3) < w.avg(.shadow_very_short, 3) and
            w.lower(2) < w.avg(.shadow_very_short, 2) and
            w.upper(2) < w.avg(.shadow_very_short, 2) and
            w.bodyGapDown(1, 2) and
            w.upper(1) > w.avg(.shadow_very_short, 1) and
            w.h(1) > w.c(2) and
            w.h(0) > w.h(1) and
            w.l(0) < w.l(1)) return 100;
        return 0;
    }
};

pub const Cdlcounterattack = struct {
    pub const tots = [_]Tot{ tot(.equal, 1), tot(.body_long, 1), tot(.body_long, 0) };
    pub const lb_sets = [_]SetId{ .equal, .body_long };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -w.color(0) and
            w.body(1) > w.avg(.body_long, 1) and
            w.body(0) > w.avg(.body_long, 0) and
            w.c(0) <= w.c(1) + w.avg(.equal, 1) and
            w.c(0) >= w.c(1) - w.avg(.equal, 1)) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdldarkcloudcover = struct {
    pub const pen_default: f64 = 0.5;
    pub const tots = [_]Tot{tot(.body_long, 1)};
    pub const lb_sets = [_]SetId{.body_long};
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == 1 and
            w.body(1) > w.avg(.body_long, 1) and
            w.color(0) == -1 and
            w.o(0) > w.h(1) and
            w.c(0) > w.o(1) and
            w.c(0) < w.c(1) - w.body(1) * w.pen) return -100;
        return 0;
    }
};

pub const Cdldoji = struct {
    pub const tots = [_]Tot{tot(.body_doji, 0)};
    pub const lb_sets = [_]SetId{.body_doji};
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) <= w.avg(.body_doji, 0)) return 100;
        return 0;
    }
};

pub const Cdldojistar = struct {
    pub const tots = [_]Tot{ tot(.body_long, 1), tot(.body_doji, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .body_long };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.body(1) > w.avg(.body_long, 1) and
            w.body(0) <= w.avg(.body_doji, 0) and
            ((w.color(1) == 1 and w.minOc(0) > w.maxOc(1)) or
                (w.color(1) == -1 and w.maxOc(0) < w.minOc(1)))) return -w.color(1) * 100;
        return 0;
    }
};

pub const Cdldragonflydoji = struct {
    pub const tots = [_]Tot{ tot(.body_doji, 0), tot(.shadow_very_short, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .shadow_very_short };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) <= w.avg(.body_doji, 0) and
            w.upper(0) < w.avg(.shadow_very_short, 0) and
            w.lower(0) > w.avg(.shadow_very_short, 0)) return 100;
        return 0;
    }
};

pub const Cdlengulfing = struct {
    pub const tots = [_]Tot{};
    pub const lb_sets = [_]SetId{};
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if ((w.color(0) == 1 and
            w.color(1) == -1 and
            ((w.c(0) >= w.o(1) and w.o(0) < w.c(1)) or
                (w.c(0) > w.o(1) and w.o(0) <= w.c(1)))) or
            (w.color(0) == -1 and
                w.color(1) == 1 and
                ((w.o(0) >= w.c(1) and w.c(0) < w.o(1)) or
                    (w.o(0) > w.c(1) and w.c(0) <= w.o(1)))))
        {
            if (w.o(0) != w.c(1) and w.c(0) != w.o(1)) return w.color(0) * 100;
            return w.color(0) * 80;
        }
        return 0;
    }
};

pub const Cdleveningdojistar = struct {
    pub const pen_default: f64 = 0.3;
    pub const tots = [_]Tot{ tot(.body_long, 2), tot(.body_doji, 1), tot(.body_short, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .body_long, .body_short };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == 1 and
            w.color(0) == -1 and
            w.bodyGapUp(1, 2) and
            w.c(0) < w.c(2) - w.body(2) * w.pen and
            w.body(2) > w.avg(.body_long, 2) and
            w.body(1) <= w.avg(.body_doji, 1) and
            w.body(0) > w.avg(.body_short, 0)) return -100;
        return 0;
    }
};

pub const Cdleveningstar = struct {
    pub const pen_default: f64 = 0.3;
    pub const tots = [_]Tot{ tot(.body_long, 2), tot(.body_short, 1), tot(.body_short, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .body_long };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == 1 and
            w.color(0) == -1 and
            w.bodyGapUp(1, 2) and
            w.c(0) < w.c(2) - w.body(2) * w.pen and
            w.body(2) > w.avg(.body_long, 2) and
            w.body(1) <= w.avg(.body_short, 1) and
            w.body(0) > w.avg(.body_short, 0)) return -100;
        return 0;
    }
};

pub const Cdlgapsidesidewhite = struct {
    pub const tots = [_]Tot{ tot(.near, 1), tot(.equal, 1) };
    pub const lb_sets = [_]SetId{ .near, .equal };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (((w.bodyGapUp(1, 2) and w.bodyGapUp(0, 2)) or
            (w.bodyGapDown(1, 2) and w.bodyGapDown(0, 2))) and
            w.color(1) == 1 and
            w.color(0) == 1 and
            w.body(0) >= w.body(1) - w.avg(.near, 1) and
            w.body(0) <= w.body(1) + w.avg(.near, 1) and
            w.o(0) >= w.o(1) - w.avg(.equal, 1) and
            w.o(0) <= w.o(1) + w.avg(.equal, 1)) return if (w.bodyGapUp(1, 2)) 100 else -100;
        return 0;
    }
};

pub const Cdlgravestonedoji = struct {
    pub const tots = [_]Tot{ tot(.body_doji, 0), tot(.shadow_very_short, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .shadow_very_short };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) <= w.avg(.body_doji, 0) and
            w.lower(0) < w.avg(.shadow_very_short, 0) and
            w.upper(0) > w.avg(.shadow_very_short, 0)) return 100;
        return 0;
    }
};

pub const Cdlhammer = struct {
    pub const tots = [_]Tot{ tot(.body_short, 0), tot(.shadow_long, 0), tot(.shadow_very_short, 0), tot(.near, 1) };
    pub const lb_sets = [_]SetId{ .body_short, .shadow_long, .shadow_very_short, .near };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) < w.avg(.body_short, 0) and
            w.lower(0) > w.avg(.shadow_long, 0) and
            w.upper(0) < w.avg(.shadow_very_short, 0) and
            w.minOc(0) <= w.l(1) + w.avg(.near, 1)) return 100;
        return 0;
    }
};

pub const Cdlhangingman = struct {
    pub const tots = [_]Tot{ tot(.body_short, 0), tot(.shadow_long, 0), tot(.shadow_very_short, 0), tot(.near, 1) };
    pub const lb_sets = [_]SetId{ .body_short, .shadow_long, .shadow_very_short, .near };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) < w.avg(.body_short, 0) and
            w.lower(0) > w.avg(.shadow_long, 0) and
            w.upper(0) < w.avg(.shadow_very_short, 0) and
            w.minOc(0) >= w.h(1) - w.avg(.near, 1)) return -100;
        return 0;
    }
};

fn haramiEval(w: anytype, comptime second: SetId) i32 {
    if (w.body(1) > w.avg(.body_long, 1)) {
        if (w.body(0) <= w.avg(second, 0)) {
            if (w.maxOc(0) < w.maxOc(1) and w.minOc(0) > w.minOc(1)) {
                return -w.color(1) * 100;
            } else if (w.maxOc(0) <= w.maxOc(1) and w.minOc(0) >= w.minOc(1)) {
                return -w.color(1) * 80;
            }
        }
    }
    return 0;
}

pub const Cdlharami = struct {
    pub const tots = [_]Tot{ tot(.body_long, 1), tot(.body_short, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .body_long };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        return haramiEval(w, .body_short);
    }
};

pub const Cdlharamicross = struct {
    pub const tots = [_]Tot{ tot(.body_long, 1), tot(.body_doji, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .body_long };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        return haramiEval(w, .body_doji);
    }
};

pub const Cdlhighwave = struct {
    pub const tots = [_]Tot{ tot(.body_short, 0), tot(.shadow_very_long, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .shadow_very_long };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) < w.avg(.body_short, 0) and
            w.upper(0) > w.avg(.shadow_very_long, 0) and
            w.lower(0) > w.avg(.shadow_very_long, 0)) return w.color(0) * 100;
        return 0;
    }
};

pub const Cdlhomingpigeon = struct {
    pub const tots = [_]Tot{ tot(.body_long, 1), tot(.body_short, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .body_long };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -1 and
            w.color(0) == -1 and
            w.body(1) > w.avg(.body_long, 1) and
            w.body(0) <= w.avg(.body_short, 0) and
            w.o(0) < w.o(1) and
            w.c(0) > w.c(1)) return 100;
        return 0;
    }
};

pub const Cdlidentical3crows = struct {
    pub const tots = [_]Tot{
        tot(.shadow_very_short, 2), tot(.shadow_very_short, 1), tot(.shadow_very_short, 0),
        tot(.equal, 2),             tot(.equal, 1),
    };
    pub const lb_sets = [_]SetId{ .shadow_very_short, .equal };
    pub const lb_add = 2;
    pub fn eval(w: anytype) i32 {
        if (w.color(2) == -1 and
            w.lower(2) < w.avg(.shadow_very_short, 2) and
            w.color(1) == -1 and
            w.lower(1) < w.avg(.shadow_very_short, 1) and
            w.color(0) == -1 and
            w.lower(0) < w.avg(.shadow_very_short, 0) and
            w.c(2) > w.c(1) and
            w.c(1) > w.c(0) and
            w.o(1) <= w.c(2) + w.avg(.equal, 2) and
            w.o(1) >= w.c(2) - w.avg(.equal, 2) and
            w.o(0) <= w.c(1) + w.avg(.equal, 1) and
            w.o(0) >= w.c(1) - w.avg(.equal, 1)) return -100;
        return 0;
    }
};

pub const Cdlinneck = struct {
    pub const tots = [_]Tot{ tot(.equal, 1), tot(.body_long, 1) };
    pub const lb_sets = [_]SetId{ .equal, .body_long };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -1 and
            w.body(1) > w.avg(.body_long, 1) and
            w.color(0) == 1 and
            w.o(0) < w.l(1) and
            w.c(0) <= w.c(1) + w.avg(.equal, 1) and
            w.c(0) >= w.c(1)) return -100;
        return 0;
    }
};

pub const Cdlinvertedhammer = struct {
    pub const tots = [_]Tot{ tot(.body_short, 0), tot(.shadow_long, 0), tot(.shadow_very_short, 0) };
    pub const lb_sets = [_]SetId{ .body_short, .shadow_long, .shadow_very_short };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.bodyGapDown(0, 1) and
            w.body(0) < w.avg(.body_short, 0) and
            w.upper(0) > w.avg(.shadow_long, 0) and
            w.lower(0) < w.avg(.shadow_very_short, 0)) return 100;
        return 0;
    }
};

pub const Cdlkickingbylength = struct {
    pub const tots = [_]Tot{ tot(.body_long, 1), tot(.body_long, 0), tot(.shadow_very_short, 1), tot(.shadow_very_short, 0) };
    pub const lb_sets = [_]SetId{ .shadow_very_short, .body_long };
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -w.color(0) and
            w.body(1) > w.avg(.body_long, 1) and
            w.upper(1) < w.avg(.shadow_very_short, 1) and
            w.lower(1) < w.avg(.shadow_very_short, 1) and
            w.body(0) > w.avg(.body_long, 0) and
            w.upper(0) < w.avg(.shadow_very_short, 0) and
            w.lower(0) < w.avg(.shadow_very_short, 0) and
            ((w.color(1) == -1 and w.gapUp(0, 1)) or
                (w.color(1) == 1 and w.gapDown(0, 1))))
        {
            const k: usize = if (w.body(0) > w.body(1)) 0 else 1;
            return w.color(k) * 100;
        }
        return 0;
    }
};

pub const Cdlladderbottom = struct {
    pub const tots = [_]Tot{tot(.shadow_very_short, 1)};
    pub const lb_sets = [_]SetId{.shadow_very_short};
    pub const lb_add = 4;
    pub fn eval(w: anytype) i32 {
        if (w.color(4) == -1 and
            w.color(3) == -1 and
            w.color(2) == -1 and
            w.o(4) > w.o(3) and
            w.o(3) > w.o(2) and
            w.c(4) > w.c(3) and
            w.c(3) > w.c(2) and
            w.color(1) == -1 and
            w.upper(1) > w.avg(.shadow_very_short, 1) and
            w.color(0) == 1 and
            w.o(0) > w.o(1) and
            w.c(0) > w.h(1)) return 100;
        return 0;
    }
};

pub const Cdllongleggeddoji = struct {
    pub const tots = [_]Tot{ tot(.body_doji, 0), tot(.shadow_long, 0) };
    pub const lb_sets = [_]SetId{ .body_doji, .shadow_long };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) <= w.avg(.body_doji, 0) and
            (w.lower(0) > w.avg(.shadow_long, 0) or w.upper(0) > w.avg(.shadow_long, 0))) return 100;
        return 0;
    }
};

pub const Cdllongline = struct {
    pub const tots = [_]Tot{ tot(.body_long, 0), tot(.shadow_short, 0) };
    pub const lb_sets = [_]SetId{ .body_long, .shadow_short };
    pub const lb_add = 0;
    pub fn eval(w: anytype) i32 {
        if (w.body(0) > w.avg(.body_long, 0) and
            w.upper(0) < w.avg(.shadow_short, 0) and
            w.lower(0) < w.avg(.shadow_short, 0)) return w.color(0) * 100;
        return 0;
    }
};

/// Same test as KICKINGBYLENGTH, but the sign is the second bar's colour.
pub const Cdlkicking = struct {
    pub const tots = Cdlkickingbylength.tots;
    pub const lb_sets = Cdlkickingbylength.lb_sets;
    pub const lb_add = 1;
    pub fn eval(w: anytype) i32 {
        if (w.color(1) == -w.color(0) and
            w.body(1) > w.avg(.body_long, 1) and
            w.upper(1) < w.avg(.shadow_very_short, 1) and
            w.lower(1) < w.avg(.shadow_very_short, 1) and
            w.body(0) > w.avg(.body_long, 0) and
            w.upper(0) < w.avg(.shadow_very_short, 0) and
            w.lower(0) < w.avg(.shadow_very_short, 0) and
            ((w.color(1) == -1 and w.gapUp(0, 1)) or
                (w.color(1) == 1 and w.gapDown(0, 1)))) return w.color(0) * 100;
        return 0;
    }
};

/// HIKKAKE state: the days left to confirm (`cd`), the last signal and the
/// high / low of the inside bar it confirms against.
pub const HikkakeState = struct { cd: i32 = 0, result: i32 = 0, high: f64 = 0.0, low: f64 = 0.0 };

fn hikkakeTail(st: *HikkakeState, w: anytype, hit: bool) i32 {
    var out: i32 = 0;
    if (hit) {
        st.result = 100 * @as(i32, if (w.h(0) < w.h(1)) 1 else -1);
        st.high = w.h(1);
        st.low = w.l(1);
        st.cd = 4;
        out = st.result;
    } else if (st.cd > 0 and
        ((st.result > 0 and w.c(0) > st.high) or
            (st.result < 0 and w.c(0) < st.low)))
    {
        out = st.result + 100 * @as(i32, if (st.result > 0) 1 else -1);
        st.cd = 0;
    }
    if (st.cd > 0) st.cd -= 1;
    return out;
}

pub const Cdlhikkake = struct {
    pub const State = HikkakeState;
    pub const warm_bars = 3;
    pub const tots = [_]Tot{};
    pub const lb_sets = [_]SetId{};
    pub const lb_add = 5;
    pub fn eval(w: anytype) i32 {
        const hit = w.h(1) < w.h(2) and
            w.l(1) > w.l(2) and
            ((w.h(0) < w.h(1) and w.l(0) < w.l(1)) or
                (w.h(0) > w.h(1) and w.l(0) > w.l(1)));
        return hikkakeTail(w.st, w, hit);
    }
};

pub const Cdlhikkakemod = struct {
    pub const State = HikkakeState;
    pub const warm_bars = 3;
    pub const tots = [_]Tot{tot(.near, 2)};
    pub fn lookback(s: *const cc.CandleSettings) usize {
        return @max(1, s.near.avg_period) + 5;
    }
    pub fn eval(w: anytype) i32 {
        const hit = w.h(2) < w.h(3) and
            w.l(2) > w.l(3) and
            w.h(1) < w.h(2) and
            w.l(1) > w.l(2) and
            ((w.h(0) < w.h(1) and
                w.l(0) < w.l(1) and
                w.c(2) <= w.l(2) + w.avg(.near, 2)) or
                (w.h(0) > w.h(1) and
                    w.l(0) > w.l(1) and
                    w.c(2) >= w.h(2) - w.avg(.near, 2)));
        return hikkakeTail(w.st, w, hit);
    }
};
