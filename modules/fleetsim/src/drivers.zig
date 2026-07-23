// SPDX-License-Identifier: MIT

//! Point behaviour: what makes a simulated device interesting rather than a
//! wall of constants.
//!
//! A `Driver` is a pure-ish function of simulated time (`random_walk` also
//! consumes the fleet's seeded `std.Random`, which is the only source of
//! randomness anywhere in this module — never `std.crypto.random`, which does
//! not exist in 0.16 anyway and would destroy replayability if it did).
//!
//! A `Sink` is where the number lands. Sinks are deliberately protocol-shaped
//! but driver-agnostic, so ONE driver instance can feed a Modbus holding
//! register, a DNP3 analog input and an OPC UA variable at the same time — a
//! `Signal` is exactly that pairing: one driver, many sinks, one period.

const std = @import("std");
const node_mod = @import("node.zig");
const Time = node_mod.Time;

// ── drivers ─────────────────────────────────────────────────────────────────

/// One scheduled level change for `step`.
pub const StepLevel = struct {
    /// Simulated time at which this level takes effect.
    at_ms: Time,
    value: f64,
};

/// One recorded sample for `replay`.
pub const Sample = struct {
    /// Offset from the start of the series (or of the current loop).
    at_ms: Time,
    value: f64,
};

pub const Driver = union(enum) {
    /// A value that never moves. The honest default.
    constant: struct { value: f64 },

    /// Linear in time, clamped or wrapped at the limits.
    ramp: struct {
        start: f64,
        /// Change per millisecond. Negative ramps down.
        per_ms: f64,
        min: f64 = -std.math.floatMax(f64),
        max: f64 = std.math.floatMax(f64),
        /// Wrap back to `min` instead of clamping at `max` (a totaliser).
        wrap: bool = false,
    },

    /// `mean + amplitude * sin(2π (t + phase) / period)`.
    sine: struct {
        mean: f64,
        amplitude: f64,
        period_ms: Time,
        phase_ms: Time = 0,
    },

    /// Brownian-ish: each *step* adds ±`step` drawn from the fleet's seeded
    /// PRNG. Stateful — the value depends on how many times it has been
    /// sampled, which is exactly why the fleet samples signals on a fixed
    /// schedule rather than on demand.
    random_walk: struct {
        value: f64,
        step: f64,
        min: f64 = -std.math.floatMax(f64),
        max: f64 = std.math.floatMax(f64),
    },

    /// Piecewise-constant schedule: the last level whose `at_ms` has passed.
    /// Levels must be sorted; before the first one the driver holds `initial`.
    step: struct {
        initial: f64 = 0,
        levels: []const StepLevel,
    },

    /// Plays back a recorded series, holding the last sample between points
    /// (zero-order hold — a resampled interpolation would invent data the
    /// recording does not contain).
    replay: struct {
        samples: []const Sample,
        loop: bool = false,
        /// Simulated time the series starts at.
        origin_ms: Time = 0,
    },

    /// The driver's value at `now_ms`. `rand` is consumed only by
    /// `random_walk`; passing the same `std.Random` sequence and the same call
    /// order reproduces the same series exactly.
    pub fn sample(self: *Driver, now_ms: Time, rand: std.Random) f64 {
        switch (self.*) {
            .constant => |c| return c.value,
            .ramp => |r| {
                const raw = r.start + r.per_ms * @as(f64, @floatFromInt(now_ms));
                if (raw <= r.max) return @max(raw, r.min);
                if (!r.wrap) return r.max;
                const span = r.max - r.min;
                if (!(span > 0)) return r.max;
                return r.min + @mod(raw - r.min, span);
            },
            .sine => |s| {
                if (s.period_ms == 0) return s.mean;
                const t: f64 = @floatFromInt((now_ms + s.phase_ms) % s.period_ms);
                const p: f64 = @floatFromInt(s.period_ms);
                return s.mean + s.amplitude * @sin(2.0 * std.math.pi * t / p);
            },
            .random_walk => |*w| {
                // Two draws, not one: a single float draw scaled to ±step
                // makes the sign correlate with the low bits. A separate
                // boolean sign draw keeps the walk symmetric.
                const magnitude = rand.float(f64) * w.step;
                const up = rand.boolean();
                w.value = std.math.clamp(
                    if (up) w.value + magnitude else w.value - magnitude,
                    w.min,
                    w.max,
                );
                return w.value;
            },
            .step => |s| {
                var v = s.initial;
                for (s.levels) |lvl| {
                    if (lvl.at_ms > now_ms) break;
                    v = lvl.value;
                }
                return v;
            },
            .replay => |r| {
                if (r.samples.len == 0) return 0;
                const span = r.samples[r.samples.len - 1].at_ms + 1;
                if (now_ms < r.origin_ms) return r.samples[0].value;
                var t = now_ms - r.origin_ms;
                if (r.loop and span > 0) t %= span;
                var v = r.samples[0].value;
                for (r.samples) |s| {
                    if (s.at_ms > t) break;
                    v = s.value;
                }
                return v;
            },
        }
    }
};

// ── sinks ───────────────────────────────────────────────────────────────────

/// Where a driver's value lands. One indirection so a driver never knows which
/// protocol it is feeding.
pub const Sink = struct {
    ctx: *anyopaque,
    applyFn: *const fn (ctx: *anyopaque, value: f64, now_ms: Time) void,

    pub fn apply(self: Sink, value: f64, now_ms: Time) void {
        self.applyFn(self.ctx, value, now_ms);
    }
};

/// One driver, many sinks, one sampling period. The fleet schedules these as
/// ordinary events, so they land in the trace in a defined order.
pub const Signal = struct {
    driver: Driver,
    sinks: []const Sink,
    /// How often the driver is sampled. Zero means "once, at `start_ms`".
    period_ms: Time = 1000,
    start_ms: Time = 0,
    /// Last value produced, for assertions and logging.
    last: f64 = 0,
    /// How many times this signal has fired.
    fires: u64 = 0,

    pub fn fire(self: *Signal, now_ms: Time, rand: std.Random) void {
        const v = self.driver.sample(now_ms, rand);
        self.last = v;
        self.fires += 1;
        for (self.sinks) |s| s.apply(v, now_ms);
    }
};

// ── ready-made sinks over caller-owned storage ──────────────────────────────

/// A `u16` register (Modbus holding/input, an S7 word, a raw scaled point).
/// `value * scale + offset`, saturated into `u16`.
pub const ScaledRegister = struct {
    cell: *u16,
    scale: f64 = 1,
    offset: f64 = 0,

    pub fn sink(self: *ScaledRegister) Sink {
        return .{ .ctx = self, .applyFn = applyFn };
    }

    fn applyFn(ctx: *anyopaque, value: f64, now_ms: Time) void {
        _ = now_ms;
        const self: *ScaledRegister = @ptrCast(@alignCast(ctx));
        self.cell.* = saturateU16(value * self.scale + self.offset);
    }
};

/// A boolean point (Modbus coil / discrete input, a BACnet binary value).
pub const Threshold = struct {
    cell: *bool,
    /// True when `value >= on_at`.
    on_at: f64 = 0.5,

    pub fn sink(self: *Threshold) Sink {
        return .{ .ctx = self, .applyFn = applyFn };
    }

    fn applyFn(ctx: *anyopaque, value: f64, now_ms: Time) void {
        _ = now_ms;
        const self: *Threshold = @ptrCast(@alignCast(ctx));
        self.cell.* = value >= self.on_at;
    }
};

/// A 32-bit float written into a caller-owned byte area (an S7 DB word, an
/// ENIP REAL tag, an IEC 104 short-float payload built by hand).
pub const FloatBytes = struct {
    bytes: []u8,
    offset: usize = 0,
    endian: std.builtin.Endian = .big,

    pub fn sink(self: *FloatBytes) Sink {
        return .{ .ctx = self, .applyFn = applyFn };
    }

    fn applyFn(ctx: *anyopaque, value: f64, now_ms: Time) void {
        _ = now_ms;
        const self: *FloatBytes = @ptrCast(@alignCast(ctx));
        if (self.offset + 4 > self.bytes.len) return;
        const bits: u32 = @bitCast(@as(f32, @floatCast(value)));
        std.mem.writeInt(u32, self.bytes[self.offset..][0..4], bits, self.endian);
    }
};

/// A plain `f64` cell — the seam a caller uses to feed anything this module
/// does not ship a sink for.
pub const Cell = struct {
    cell: *f64,

    pub fn sink(self: *Cell) Sink {
        return .{ .ctx = self, .applyFn = applyFn };
    }

    fn applyFn(ctx: *anyopaque, value: f64, now_ms: Time) void {
        _ = now_ms;
        const self: *Cell = @ptrCast(@alignCast(ctx));
        self.cell.* = value;
    }
};

pub fn saturateU16(v: f64) u16 {
    if (std.math.isNan(v)) return 0;
    if (v <= 0) return 0;
    if (v >= 65535) return 65535;
    return @intFromFloat(v);
}

pub fn saturateI16(v: f64) i16 {
    if (std.math.isNan(v)) return 0;
    if (v <= -32768) return -32768;
    if (v >= 32767) return 32767;
    return @intFromFloat(v);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn noRandom() std.Random {
    // A driver that does not draw must not need a generator; this stub proves
    // it by trapping if one ever calls it.
    return .{ .ptr = undefined, .fillFn = struct {
        fn f(_: *anyopaque, _: []u8) void {
            unreachable;
        }
    }.f };
}

test "constant / ramp / sine are pure functions of simulated time" {
    var c = Driver{ .constant = .{ .value = 7 } };
    try testing.expectEqual(@as(f64, 7), c.sample(0, noRandom()));
    try testing.expectEqual(@as(f64, 7), c.sample(1_000_000, noRandom()));

    var r = Driver{ .ramp = .{ .start = 0, .per_ms = 0.5, .max = 100 } };
    try testing.expectEqual(@as(f64, 0), r.sample(0, noRandom()));
    try testing.expectEqual(@as(f64, 50), r.sample(100, noRandom()));
    try testing.expectEqual(@as(f64, 100), r.sample(10_000, noRandom())); // clamped

    var w = Driver{ .ramp = .{ .start = 0, .per_ms = 1, .min = 0, .max = 10, .wrap = true } };
    try testing.expectEqual(@as(f64, 5), w.sample(5, noRandom()));
    try testing.expectEqual(@as(f64, 2), w.sample(12, noRandom())); // wrapped

    var s = Driver{ .sine = .{ .mean = 50, .amplitude = 10, .period_ms = 1000 } };
    try testing.expectApproxEqAbs(@as(f64, 50), s.sample(0, noRandom()), 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 60), s.sample(250, noRandom()), 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 40), s.sample(750, noRandom()), 1e-9);
    // Periodic: t and t+period agree exactly.
    try testing.expectEqual(s.sample(123, noRandom()), s.sample(1123, noRandom()));
}

test "random_walk is reproducible from its seed and honours its bounds" {
    var a = std.Random.DefaultPrng.init(0xFEED);
    var b = std.Random.DefaultPrng.init(0xFEED);
    var c = std.Random.DefaultPrng.init(0xBEEF);
    var da = Driver{ .random_walk = .{ .value = 50, .step = 5, .min = 0, .max = 100 } };
    var db = Driver{ .random_walk = .{ .value = 50, .step = 5, .min = 0, .max = 100 } };
    var dc = Driver{ .random_walk = .{ .value = 50, .step = 5, .min = 0, .max = 100 } };

    var moved = false;
    for (0..200) |i| {
        const t: Time = i * 10;
        const va = da.sample(t, a.random());
        const vb = db.sample(t, b.random());
        _ = dc.sample(t, c.random());
        try testing.expectEqual(va, vb);
        try testing.expect(va >= 0 and va <= 100);
        if (va != 50) moved = true;
    }
    try testing.expect(moved); // it is a walk, not a constant
    try testing.expect(da.random_walk.value != dc.random_walk.value); // seeds diverge
}

test "random_walk clamps hard against its bounds" {
    var p = std.Random.DefaultPrng.init(3);
    var d = Driver{ .random_walk = .{ .value = 0, .step = 1000, .min = -1, .max = 1 } };
    for (0..500) |i| {
        const v = d.sample(i, p.random());
        try testing.expect(v >= -1 and v <= 1);
    }
}

test "step holds the last level that has come due" {
    const levels = [_]StepLevel{
        .{ .at_ms = 1000, .value = 10 },
        .{ .at_ms = 2000, .value = 20 },
        .{ .at_ms = 5000, .value = 5 },
    };
    var d = Driver{ .step = .{ .initial = 1, .levels = &levels } };
    try testing.expectEqual(@as(f64, 1), d.sample(0, noRandom()));
    try testing.expectEqual(@as(f64, 1), d.sample(999, noRandom()));
    try testing.expectEqual(@as(f64, 10), d.sample(1000, noRandom()));
    try testing.expectEqual(@as(f64, 20), d.sample(4999, noRandom()));
    try testing.expectEqual(@as(f64, 5), d.sample(100_000, noRandom()));
}

test "replay holds each sample and can loop" {
    const samples = [_]Sample{
        .{ .at_ms = 0, .value = 1 },
        .{ .at_ms = 100, .value = 2 },
        .{ .at_ms = 200, .value = 3 },
    };
    var once = Driver{ .replay = .{ .samples = &samples } };
    try testing.expectEqual(@as(f64, 1), once.sample(0, noRandom()));
    try testing.expectEqual(@as(f64, 1), once.sample(99, noRandom()));
    try testing.expectEqual(@as(f64, 2), once.sample(100, noRandom()));
    try testing.expectEqual(@as(f64, 3), once.sample(9999, noRandom())); // held past the end

    var looped = Driver{ .replay = .{ .samples = &samples, .loop = true } };
    try testing.expectEqual(@as(f64, 1), looped.sample(201, noRandom()));
    try testing.expectEqual(@as(f64, 2), looped.sample(301, noRandom()));
}

test "one driver instance feeds several protocol-shaped sinks at once" {
    var reg: u16 = 0;
    var coil: bool = false;
    var db: [8]u8 = @splat(0);
    var raw: f64 = 0;

    var s_reg = ScaledRegister{ .cell = &reg, .scale = 10 };
    var s_coil = Threshold{ .cell = &coil, .on_at = 55 };
    var s_bytes = FloatBytes{ .bytes = &db, .offset = 2 };
    var s_cell = Cell{ .cell = &raw };

    const sinks = [_]Sink{ s_reg.sink(), s_coil.sink(), s_bytes.sink(), s_cell.sink() };
    var sig = Signal{
        .driver = .{ .sine = .{ .mean = 50, .amplitude = 10, .period_ms = 1000 } },
        .sinks = &sinks,
    };

    sig.fire(250, noRandom()); // peak: 60
    try testing.expectEqual(@as(u16, 600), reg);
    try testing.expect(coil);
    try testing.expectEqual(@as(f64, 60), raw);
    try testing.expectEqual(@as(u32, @bitCast(@as(f32, 60))), std.mem.readInt(u32, db[2..6], .big));

    sig.fire(750, noRandom()); // trough: 40
    try testing.expectEqual(@as(u16, 400), reg);
    try testing.expect(!coil);
    try testing.expectEqual(@as(u64, 2), sig.fires);
}

test "saturation never wraps" {
    try testing.expectEqual(@as(u16, 0), saturateU16(-1));
    try testing.expectEqual(@as(u16, 65535), saturateU16(1e30));
    try testing.expectEqual(@as(u16, 0), saturateU16(std.math.nan(f64)));
    try testing.expectEqual(@as(i16, -32768), saturateI16(-1e30));
    try testing.expectEqual(@as(i16, 32767), saturateI16(1e30));
}
