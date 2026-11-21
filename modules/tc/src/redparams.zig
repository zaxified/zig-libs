// SPDX-License-Identifier: MIT
//! Derived `red` / `sfq`-RED parameters: what `tc qdisc add ... red` computes
//! from `limit`, `min`, `max`, `avpkt`, `burst`, `probability` and `bandwidth`
//! before it sends the request. A caller can state the intent (the same words as
//! the man page) and get `wlog`, `plog`, `scell_log`, the 256-octet idle-damping
//! table `stab` and `max_p` that `tc` would have sent.
//!
//! Sources. The weight `wlog` is the inequality of Floyd and Jacobson, "Random
//! Early Detection gateways for Congestion Avoidance" (1993), section 6 (the
//! average queue after a burst of `burst` packets arrives at an empty queue must
//! stay under `min`); `plog`, the cell size `scell_log` and the table `stab` are
//! `tc`'s conventions. Those conventions were established as a black box: an
//! unmodified `tc` (iproute2 6.19) under `strace` in a network namespace, over
//! about 1 000 parameter sets, and the tables in this file's tests are such
//! captures. No iproute2 source was read. `tools/red_oracle.sh` re-runs the
//! comparison against a `tc` on the machine.
//!
//! What the derivation is, as measured (each point is in the tests below):
//!
//! * thresholds: `min` and `max` default as the man page says (`max` to `limit/4`,
//!   `min` to `max/3`); a given `min` with no `max` makes `max = 3 * min`
//!   (`red`) or `limit / 4` (`sfq`); 0 means "not given"; `burst` defaults to
//!   `(2 * min + max) / (3 * avpkt)`, rounded down.
//! * `wlog`: the smallest `w` in 1..31 with `a <= (1 - (1 - 2^-w)^burst) / 2^-w`,
//!   where `a = burst + 1 - min / avpkt`, in `f64`; `a < 1` (a burst smaller than
//!   `min / avpkt`) is refused. The power is taken in `f128` here so that it
//!   rounds as a correctly rounded libm `pow` does.
//! * `plog`: the smallest `p` in 0..31 with `(max - min) / probability < 2^p`.
//! * `max_p`: `probability * 2^32` truncated to 32 bits (so 1.0 gives 0, as `tc`
//!   sends it).
//! * `scell_log` (`red` only): the smallest `c` in 0..31 with
//!   `256 * K * 2^c / T >= 15.5`, 31 when there is none, where
//!   `K = -ln(1 - 2^-wlog)` and `T` is the transmit time of one `avpkt` at
//!   `bandwidth` in psched ticks, rounded up (`Psched.calcXmitTime`).
//! * `stab[i]` (`red` only), `i` in 0..254: `trunc(K * (i << scell_log) / T)`
//!   with `i << scell_log` taken as a signed 32-bit number (it wraps), a negative
//!   result and anything above 31 read as 31; `stab[255]` is 31. `sfq` sends
//!   `scell_log` 0 and no table.
//!
//! Where `tc` accepts a value this refuses it: a `probability` above 1 (`tc`
//! takes it and wraps `max_p`).

const std = @import("std");
const ratespec = @import("ratespec.zig");
const qdisc = @import("qdisc.zig");

pub const Psched = ratespec.Psched;

pub const Error = error{
    /// `limit` (`red`: also `avpkt`) is zero: `tc` refuses with "Required
    /// parameter is missing".
    MissingParameter,
    /// `min` above `max` (`red`), `min` not below `max` (`sfq`), or a
    /// threshold that does not fit 32 bits.
    BadThresholds,
    /// `burst` is smaller than `min / avpkt` packets (`tc`: "burst is too
    /// small"); `minBurst` gives the smallest that works.
    BurstTooSmall,
    /// No weight `2^-w`, `w` in 1..31, covers `burst` (`tc`: "failed to
    /// calculate EWMA constant").
    BurstTooLarge,
    /// `probability` is not in (0, 1], or `(max - min) / probability` is at
    /// least 2^31 (`tc`: "failed to calculate probability").
    ProbabilityOutOfRange,
};

/// `tc`'s default `bandwidth`, 10 Mbit/s in bytes per second.
pub const default_bandwidth: u32 = 1_250_000;
/// `sfq`'s default `avpkt`.
pub const sfq_default_avpkt: u32 = 1000;

/// The words of `tc qdisc add ... red`.
pub const RedParams = struct {
    /// `limit`, bytes. Required.
    limit: u32,
    /// `min`, bytes; null or 0 = default.
    min: ?u32 = null,
    /// `max`, bytes; null or 0 = default.
    max: ?u32 = null,
    /// `avpkt`, bytes. Required.
    avpkt: u32,
    /// `burst`, packets; null or 0 = default.
    burst: ?u32 = null,
    /// `probability`, in (0, 1].
    probability: f64 = 0.02,
    /// `bandwidth`, bytes per second; 0 = 10 Mbit/s.
    bandwidth: u32 = 0,
    /// `red_flag_*` bits.
    flags: u8 = 0,
};

/// What `tc` puts on the wire for a `red` qdisc.
pub const RedDerived = struct {
    qth_min: u32,
    qth_max: u32,
    wlog: u8,
    plog: u8,
    scell_log: u8,
    max_p: u32,
    stab: [qdisc.red_stab_len]u8,

    /// The qdisc spec. `stab` points into `self`: keep `self` alive while the
    /// spec is in use (building the request copies it).
    pub fn toRed(self: *const RedDerived, limit: u32, flags: u8) qdisc.Red {
        return .{
            .limit = limit,
            .qth_min = self.qth_min,
            .qth_max = self.qth_max,
            .wlog = self.wlog,
            .plog = self.plog,
            .scell_log = self.scell_log,
            .stab = &self.stab,
            .max_p = self.max_p,
            .flags = flags,
        };
    }
};

/// The RED words of `tc qdisc add ... sfq` (`redflowlimit`, `min`, `max`,
/// `avpkt`, `burst`, `probability`, `ecn`, `harddrop`).
pub const SfqRedParams = struct {
    /// `redflowlimit`, bytes. Required.
    flow_limit: u32,
    min: ?u32 = null,
    max: ?u32 = null,
    avpkt: u32 = sfq_default_avpkt,
    burst: ?u32 = null,
    probability: f64 = 0.02,
    /// `red_flag_ecn` and `red_flag_harddrop` bits.
    flags: u8 = 0,
};

fn nz(v: ?u32) u32 {
    return v orelse 0;
}

fn toU32(v: u64) Error!u32 {
    return std.math.cast(u32, v) orelse error.BadThresholds;
}

/// `(1 - 2^-w)^n`, correctly rounded to `f64` in all but astronomically rare
/// cases (repeated squaring in `f128`).
fn powOneMinus(w: u8, n: u32) f64 {
    var base: f128 = 1.0 - std.math.ldexp(@as(f128, 1.0), -@as(i32, w));
    var acc: f128 = 1.0;
    var e = n;
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) acc *= base;
        base *= base;
    }
    return @floatCast(acc);
}

/// The smallest burst (packets) `wlogFor` accepts for `min` and `avpkt`.
pub fn minBurst(min: u32, avpkt: u32) u32 {
    if (avpkt == 0) return 0;
    return @intCast((@as(u64, min) + avpkt - 1) / avpkt);
}

/// `wlog` for a burst of `burst` packets under threshold `min` at mean packet
/// size `avpkt`.
pub fn wlogFor(min: u32, avpkt: u32, burst: u32) Error!u8 {
    if (avpkt == 0) return error.MissingParameter;
    const a = @as(f64, @floatFromInt(burst)) + 1.0 -
        @as(f64, @floatFromInt(min)) / @as(f64, @floatFromInt(avpkt));
    if (a < 1.0) return error.BurstTooSmall;
    var w: u8 = 1;
    while (w < 32) : (w += 1) {
        const weight = std.math.ldexp(@as(f64, 1.0), -@as(i32, w));
        if (a <= (1.0 - powOneMinus(w, burst)) / weight) return w;
    }
    return error.BurstTooLarge;
}

/// `plog` for the span `max - min` at maximum marking probability `p`.
pub fn plogFor(min: u32, max: u32, p: f64) Error!u8 {
    if (max < min) return error.BadThresholds;
    if (!(p > 0.0 and p <= 1.0)) return error.ProbabilityOutOfRange;
    const x = @as(f64, @floatFromInt(max - min)) / p;
    var k: u8 = 0;
    while (k < 32) : (k += 1) {
        if (x < @as(f64, @floatFromInt(@as(u64, 1) << @intCast(k)))) return k;
    }
    return error.ProbabilityOutOfRange;
}

/// `max_p`: `probability * 2^32`, truncated to 32 bits.
pub fn maxPFor(p: f64) u32 {
    const v: u64 = @intFromFloat(p * 4294967296.0);
    return @truncate(v);
}

fn ewmaK(wlog: u8) f64 {
    return -@log(1.0 - std.math.ldexp(@as(f64, 1.0), -@as(i32, wlog)));
}

/// The cell size for the idle-damping table: `ticks` is the transmit time of
/// one mean packet.
pub fn scellLogFor(wlog: u8, ticks: u32) u8 {
    const k = ewmaK(wlog);
    const t: f64 = @floatFromInt(ticks);
    var c: u8 = 0;
    while (c < 31) : (c += 1) {
        if (256.0 * k * @as(f64, @floatFromInt(@as(u64, 1) << @intCast(c))) / t >= 15.5) return c;
    }
    return 31;
}

/// The 256-octet idle-damping table for `wlog`, `scell_log` and `ticks`.
pub fn stabFor(wlog: u8, scell_log: u8, ticks: u32) [qdisc.red_stab_len]u8 {
    const k = ewmaK(wlog);
    const t: f64 = @floatFromInt(ticks);
    var out: [qdisc.red_stab_len]u8 = undefined;
    for (out[0..255], 0..) |*b, i| {
        const x: i32 = @bitCast(@as(u32, @truncate(@as(u64, i) << @intCast(scell_log))));
        const n: i64 = @intFromFloat(k * @as(f64, @floatFromInt(x)) / t);
        b.* = if (n < 0) 31 else @intCast(@min(n, 31));
    }
    out[255] = 31;
    return out;
}

/// Derive everything `tc qdisc add ... red` sends. `ps` is the host's
/// `/proc/net/psched` calibration (`Psched.read`); `ratespec.golden_psched`
/// reproduces the captures in this module's tests.
pub fn deriveRed(p: RedParams, ps: Psched) Error!RedDerived {
    if (p.limit == 0 or p.avpkt == 0) return error.MissingParameter;
    var qmax: u64 = nz(p.max);
    var qmin: u64 = nz(p.min);
    if (qmax == 0) qmax = if (qmin != 0) 3 * qmin else p.limit / 4;
    if (qmin == 0) qmin = qmax / 3;
    const min = try toU32(qmin);
    const max = try toU32(qmax);
    var burst: u64 = nz(p.burst);
    if (burst == 0) burst = (2 * qmin + qmax) / (3 * @as(u64, p.avpkt));
    const wlog = try wlogFor(min, p.avpkt, try toU32(burst));
    const plog = try plogFor(min, max, p.probability);
    const bw = if (p.bandwidth == 0) default_bandwidth else p.bandwidth;
    const ticks = ps.calcXmitTime(bw, p.avpkt);
    const scell = scellLogFor(wlog, ticks);
    return .{
        .qth_min = min,
        .qth_max = max,
        .wlog = wlog,
        .plog = plog,
        .scell_log = scell,
        .max_p = maxPFor(p.probability),
        .stab = stabFor(wlog, scell, ticks),
    };
}

/// The RED words of an `sfq`: `qdisc.SfqRed` with `wlog`, `plog` and `max_p`
/// filled in as `tc` does (`scell_log` stays 0 there).
pub fn deriveSfqRed(p: SfqRedParams) Error!qdisc.SfqRed {
    if (p.flow_limit == 0 or p.avpkt == 0) return error.MissingParameter;
    var qmax: u64 = nz(p.max);
    var qmin: u64 = nz(p.min);
    if (qmax == 0) qmax = p.flow_limit / 4;
    if (qmin == 0) qmin = qmax / 3;
    if (qmin >= qmax) return error.BadThresholds;
    const min = try toU32(qmin);
    const max = try toU32(qmax);
    var burst: u64 = nz(p.burst);
    if (burst == 0) burst = (2 * qmin + qmax) / (3 * @as(u64, p.avpkt));
    return .{
        .flow_limit = p.flow_limit,
        .qth_min = min,
        .qth_max = max,
        .wlog = try wlogFor(min, p.avpkt, try toU32(burst)),
        .plog = try plogFor(min, max, p.probability),
        .scell_log = 0,
        .flags = p.flags,
        .max_p = maxPFor(p.probability),
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

// Each row is one parameter set given to an unmodified iproute2 6.19 `tc` (same
// recipe as `tools/capture.sh`) and the PARMS, MAX_P and STAB it sent; `crc` is
// the CRC-32 of the 256 octets of STAB.
const RedCase = struct {
    limit: u32,
    min: ?u32,
    max: ?u32,
    avpkt: u32,
    burst: ?u32,
    p: f64,
    bw: u32,
    qmin: u32,
    qmax: u32,
    wlog: u8,
    plog: u8,
    scell: u8,
    max_p: u32,
    crc: u32,
    flags: u8,
};

const red_cases = [_]RedCase{
    .{ .limit = 34771, .min = 8744, .max = 21563, .avpkt = 64, .burst = 236, .p = 0.05, .bw = 37500, .qmin = 8744, .qmax = 21563, .wlog = 7, .plog = 18, .scell = 18, .max_p = 214748364, .crc = 4030141700, .flags = 0 },
    .{ .limit = 401097, .min = 49730, .max = 77294, .avpkt = 500, .burst = 101, .p = 0.1, .bw = 1250000, .qmin = 49730, .qmax = 77294, .wlog = 2, .plog = 19, .scell = 11, .max_p = 429496729, .crc = 3841500262, .flags = 0 },
    .{ .limit = 369336, .min = 30659, .max = 129476, .avpkt = 1000, .burst = 60, .p = 0.01, .bw = 3125000, .qmin = 30659, .qmax = 129476, .wlog = 6, .plog = 24, .scell = 15, .max_p = 42949672, .crc = 2840502494, .flags = 0 },
    .{ .limit = 2574249, .min = 842642, .max = 1720266, .avpkt = 9000, .burst = 393, .p = 1.0, .bw = 37500, .qmin = 842642, .qmax = 1720266, .wlog = 10, .plog = 20, .scell = 28, .max_p = 0, .crc = 2157873325, .flags = 0 },
    .{ .limit = 9991996, .min = 383216, .max = 1740521, .avpkt = 3000, .burst = 227, .p = 1.0, .bw = 125000, .qmin = 383216, .qmax = 1740521, .wlog = 7, .plog = 21, .scell = 22, .max_p = 0, .crc = 2052072024, .flags = 0 },
    .{ .limit = 186034, .min = 52258, .max = 89025, .avpkt = 500, .burst = 114, .p = 0.001, .bw = 77750000, .qmin = 52258, .qmax = 89025, .wlog = 4, .plog = 26, .scell = 7, .max_p = 4294967, .crc = 440002395, .flags = 0 },
    .{ .limit = 1172679, .min = 55747, .max = 328394, .avpkt = 500, .burst = 211, .p = 0.9, .bw = 37500, .qmin = 55747, .qmax = 328394, .wlog = 7, .plog = 19, .scell = 21, .max_p = 3865470566, .crc = 1654273265, .flags = 0 },
    .{ .limit = 21125, .min = 2786, .max = 4826, .avpkt = 64, .burst = 45, .p = 0.1, .bw = 375000, .qmin = 2786, .qmax = 4826, .wlog = 2, .plog = 15, .scell = 10, .max_p = 429496729, .crc = 2869465596, .flags = 0 },
    .{ .limit = 401736, .min = 20727, .max = 80452, .avpkt = 200, .burst = 108, .p = 0.1, .bw = 37500, .qmin = 20727, .qmax = 80452, .wlog = 3, .plog = 20, .scell = 16, .max_p = 429496729, .crc = 3150985358, .flags = 0 },
    .{ .limit = 303694, .min = 36893, .max = 206482, .avpkt = 500, .burst = 75, .p = 0.001, .bw = 12500000, .qmin = 36893, .qmax = 206482, .wlog = 2, .plog = 28, .scell = 8, .max_p = 4294967, .crc = 3772482143, .flags = 0 },
    .{ .limit = 225480, .min = 38673, .max = 132242, .avpkt = 1500, .burst = 26, .p = 0.0001, .bw = 1250000, .qmin = 38673, .qmax = 132242, .wlog = 1, .plog = 30, .scell = 11, .max_p = 429496, .crc = 2350402013, .flags = 0 },
    .{ .limit = 104389, .min = 11978, .max = 53758, .avpkt = 100, .burst = 120, .p = 0.02, .bw = 1250000000, .qmin = 11978, .qmax = 53758, .wlog = 1, .plog = 21, .scell = 0, .max_p = 85899345, .crc = 3936997675, .flags = 0 },
    .{ .limit = 111803, .min = 5969, .max = 21194, .avpkt = 100, .burst = 69, .p = 0.5, .bw = 1250000000, .qmin = 5969, .qmax = 21194, .wlog = 4, .plog = 15, .scell = 1, .max_p = 2147483648, .crc = 4182194221, .flags = 0 },
    .{ .limit = 2264580, .min = 201781, .max = 455891, .avpkt = 1500, .burst = 135, .p = 0.001, .bw = 125000000, .qmin = 201781, .qmax = 455891, .wlog = 1, .plog = 28, .scell = 5, .max_p = 4294967, .crc = 3419640152, .flags = 0 },
    .{ .limit = 1116789, .min = 107329, .max = 289460, .avpkt = 1000, .burst = 207, .p = 1.0, .bw = 1250000000, .qmin = 107329, .qmax = 289460, .wlog = 7, .plog = 18, .scell = 7, .max_p = 0, .crc = 4030141700, .flags = 0 },
    .{ .limit = 2549087, .min = 173770, .max = 731404, .avpkt = 1500, .burst = 125, .p = 0.001, .bw = 312500000, .qmin = 173770, .qmax = 731404, .wlog = 4, .plog = 30, .scell = 7, .max_p = 4294967, .crc = 1078042343, .flags = 0 },
    .{ .limit = 1180906, .min = 146321, .max = 699311, .avpkt = 1000, .burst = 147, .p = 0.5, .bw = 375000, .qmin = 146321, .qmax = 699311, .wlog = 1, .plog = 21, .scell = 12, .max_p = 2147483648, .crc = 1249654127, .flags = 0 },
    .{ .limit = 12776476, .min = 738659, .max = 3492255, .avpkt = 9000, .burst = 112, .p = 0.3, .bw = 125000000, .qmin = 738659, .qmax = 3492255, .wlog = 5, .plog = 24, .scell = 12, .max_p = 1288490188, .crc = 1304705201, .flags = 0 },
    .{ .limit = 219717, .min = 27890, .max = 149072, .avpkt = 200, .burst = 169, .p = 1.0, .bw = 125000, .qmin = 27890, .qmax = 149072, .wlog = 5, .plog = 17, .scell = 16, .max_p = 0, .crc = 2757582710, .flags = 0 },
    .{ .limit = 5008796, .min = 663587, .max = 3675626, .avpkt = 9000, .burst = 173, .p = 0.02, .bw = 1250000000, .qmin = 663587, .qmax = 3675626, .wlog = 8, .plog = 28, .scell = 11, .max_p = 85899345, .crc = 1115767290, .flags = 0 },
    .{ .limit = 78941, .min = 6604, .max = 13521, .avpkt = 64, .burst = 104, .p = 0.01, .bw = 375000, .qmin = 6604, .qmax = 13521, .wlog = 1, .plog = 20, .scell = 8, .max_p = 42949672, .crc = 1910282329, .flags = 0 },
    .{ .limit = 3486347, .min = 480008, .max = 903752, .avpkt = 9000, .burst = 153, .p = 0.05, .bw = 375000, .qmin = 480008, .qmax = 903752, .wlog = 8, .plog = 24, .scell = 23, .max_p = 214748364, .crc = 2586082741, .flags = 0 },
    .{ .limit = 200016, .min = 14355, .max = 64794, .avpkt = 100, .burst = 443, .p = 0.3, .bw = 125000, .qmin = 14355, .qmax = 64794, .wlog = 10, .plog = 18, .scell = 20, .max_p = 1288490188, .crc = 2149629475, .flags = 0 },
    .{ .limit = 413133, .min = 51507, .max = 116152, .avpkt = 1000, .burst = 81, .p = 0.9, .bw = 77750000, .qmin = 51507, .qmax = 116152, .wlog = 6, .plog = 17, .scell = 10, .max_p = 3865470566, .crc = 292342195, .flags = 0 },
    .{ .limit = 2037737, .min = 130632, .max = 700361, .avpkt = 1500, .burst = 387, .p = 0.01, .bw = 125000000, .qmin = 130632, .qmax = 700361, .wlog = 10, .plog = 26, .scell = 14, .max_p = 42949672, .crc = 1988712287, .flags = 0 },
    .{ .limit = 4919, .min = 453, .max = 1987, .avpkt = 64, .burst = 17, .p = 1.0, .bw = 1250000000, .qmin = 453, .qmax = 1987, .wlog = 5, .plog = 11, .scell = 1, .max_p = 0, .crc = 2902322243, .flags = 0 },
    .{ .limit = 3097417, .min = 118171, .max = 554042, .avpkt = 1000, .burst = 120, .p = 0.01, .bw = 12500000, .qmin = 118171, .qmax = 554042, .wlog = 2, .plog = 26, .scell = 9, .max_p = 42949672, .crc = 3772482143, .flags = 0 },
    .{ .limit = 101354, .min = 6260, .max = 23500, .avpkt = 100, .burst = 64, .p = 0.5, .bw = 375000, .qmin = 6260, .qmax = 23500, .wlog = 2, .plog = 16, .scell = 10, .max_p = 2147483648, .crc = 3534364912, .flags = 0 },
    .{ .limit = 21519, .min = 5429, .max = 17402, .avpkt = 200, .burst = 37, .p = 1.0, .bw = 12500000, .qmin = 5429, .qmax = 17402, .wlog = 4, .plog = 14, .scell = 8, .max_p = 0, .crc = 2804540518, .flags = 0 },
    .{ .limit = 865445, .min = 78507, .max = 241472, .avpkt = 1500, .burst = 352, .p = 0.01, .bw = 37500, .qmin = 78507, .qmax = 241472, .wlog = 11, .plog = 24, .scell = 27, .max_p = 42949672, .crc = 762354467, .flags = 0 },
    .{ .limit = 1544867, .min = 179581, .max = 973580, .avpkt = 3000, .burst = 359, .p = 1.0, .bw = 12500000, .qmin = 179581, .qmax = 973580, .wlog = 10, .plog = 20, .scell = 18, .max_p = 0, .crc = 110515047, .flags = 0 },
    .{ .limit = 24287, .min = 1507, .max = 5885, .avpkt = 64, .burst = 53, .p = 1.0, .bw = 125000, .qmin = 1507, .qmax = 5885, .wlog = 6, .plog = 13, .scell = 15, .max_p = 0, .crc = 4293203794, .flags = 0 },
    .{ .limit = 611934, .min = 33491, .max = 125766, .avpkt = 1000, .burst = 63, .p = 1.0, .bw = 1250000, .qmin = 33491, .qmax = 125766, .wlog = 6, .plog = 17, .scell = 16, .max_p = 0, .crc = 3257550550, .flags = 0 },
    .{ .limit = 3719056, .min = 373250, .max = 2034869, .avpkt = 3000, .burst = 126, .p = 1.0, .bw = 125000000, .qmin = 373250, .qmax = 2034869, .wlog = 2, .plog = 21, .scell = 7, .max_p = 0, .crc = 581960148, .flags = 0 },
    .{ .limit = 46412, .min = 3859, .max = 10992, .avpkt = 64, .burst = 61, .p = 1.0, .bw = 312500000, .qmin = 3859, .qmax = 10992, .wlog = 1, .plog = 13, .scell = 0, .max_p = 0, .crc = 2621590702, .flags = 0 },
    .{ .limit = 19007987, .min = 1080533, .max = 5259163, .avpkt = 9000, .burst = 121, .p = 1.0, .bw = 1250000000, .qmin = 1080533, .qmax = 5259163, .wlog = 1, .plog = 22, .scell = 4, .max_p = 0, .crc = 3019778438, .flags = 0 },
    .{ .limit = 1076615, .min = 146762, .max = 838472, .avpkt = 1000, .burst = 446, .p = 1.0, .bw = 37500, .qmin = 146762, .qmax = 838472, .wlog = 10, .plog = 20, .scell = 25, .max_p = 0, .crc = 2136268126, .flags = 0 },
    .{ .limit = 51161, .min = 2297, .max = 8862, .avpkt = 100, .burst = 24, .p = 1.0, .bw = 312500000, .qmin = 2297, .qmax = 8862, .wlog = 2, .plog = 13, .scell = 1, .max_p = 0, .crc = 3147066105, .flags = 0 },
    .{ .limit = 1640385, .min = 232867, .max = 548243, .avpkt = 3000, .burst = 177, .p = 0.5, .bw = 12500, .qmin = 232867, .qmax = 548243, .wlog = 8, .plog = 20, .scell = 26, .max_p = 2147483648, .crc = 587493571, .flags = 0 },
    .{ .limit = 79514, .min = 13534, .max = 22217, .avpkt = 1000, .burst = 313, .p = 0.5, .bw = 37500, .qmin = 13534, .qmax = 22217, .wlog = 12, .plog = 15, .scell = 27, .max_p = 2147483648, .crc = 2833246398, .flags = 0 },
    .{ .limit = 187801, .min = 13847, .max = 40319, .avpkt = 100, .burst = 139, .p = 1.0, .bw = 12500, .qmin = 13847, .qmax = 40319, .wlog = 1, .plog = 15, .scell = 14, .max_p = 0, .crc = 2984771196, .flags = 0 },
    .{ .limit = 2849848, .min = 217486, .max = 769611, .avpkt = 1500, .burst = 145, .p = 1.0, .bw = 1250000, .qmin = 217486, .qmax = 769611, .wlog = 1, .plog = 20, .scell = 11, .max_p = 0, .crc = 2350402013, .flags = 0 },
    .{ .limit = 18769, .min = 659, .max = 3422, .avpkt = 64, .burst = 310, .p = 1.0, .bw = 312500000, .qmin = 659, .qmax = 3422, .wlog = 13, .plog = 12, .scell = 11, .max_p = 0, .crc = 1057605817, .flags = 0 },
    .{ .limit = 462493, .min = 66132, .max = 196973, .avpkt = 500, .burst = 432, .p = 1.0, .bw = 77750000, .qmin = 66132, .qmax = 196973, .wlog = 10, .plog = 17, .scell = 13, .max_p = 0, .crc = 2193764734, .flags = 0 },
    .{ .limit = 80451, .min = 11104, .max = 19942, .avpkt = 100, .burst = 141, .p = 1.0, .bw = 375000, .qmin = 11104, .qmax = 19942, .wlog = 5, .plog = 14, .scell = 13, .max_p = 0, .crc = 1459656463, .flags = 0 },
    .{ .limit = 7102655, .min = 335496, .max = 1193055, .avpkt = 3000, .burst = 113, .p = 1.0, .bw = 12500000, .qmin = 335496, .qmax = 1193055, .wlog = 2, .plog = 20, .scell = 10, .max_p = 0, .crc = 2636140883, .flags = 0 },
    .{ .limit = 114595, .min = 13175, .max = 74865, .avpkt = 500, .burst = 31, .p = 1.0, .bw = 77750000, .qmin = 13175, .qmax = 74865, .wlog = 3, .plog = 16, .scell = 6, .max_p = 0, .crc = 17706065, .flags = 0 },
    .{ .limit = 81945, .min = 6572, .max = 21761, .avpkt = 200, .burst = 33, .p = 1.0, .bw = 1250000000, .qmin = 6572, .qmax = 21761, .wlog = 1, .plog = 14, .scell = 0, .max_p = 0, .crc = 1053068499, .flags = 0 },
    .{ .limit = 4897665, .min = 640169, .max = 1376295, .avpkt = 9000, .burst = 371, .p = 1.0, .bw = 125000, .qmin = 640169, .qmax = 1376295, .wlog = 10, .plog = 20, .scell = 27, .max_p = 0, .crc = 1537293641, .flags = 0 },
    .{ .limit = 2599, .min = 322, .max = 549, .avpkt = 64, .burst = 35, .p = 1.0, .bw = 37500, .qmin = 322, .qmax = 549, .wlog = 8, .plog = 8, .scell = 19, .max_p = 0, .crc = 4030141700, .flags = 0 },
    .{ .limit = 24000, .min = 2000, .max = 6000, .avpkt = 200, .burst = 20, .p = 0.02, .bw = 12500, .qmin = 2000, .qmax = 6000, .wlog = 4, .plog = 18, .scell = 18, .max_p = 85899345, .crc = 4018932366, .flags = 0 },
    .{ .limit = 60000, .min = 5000, .max = 15000, .avpkt = 500, .burst = 20, .p = 0.02, .bw = 125000, .qmin = 5000, .qmax = 15000, .wlog = 4, .plog = 19, .scell = 16, .max_p = 85899345, .crc = 4018932366, .flags = 0 },
    .{ .limit = 120000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20, .p = 0.02, .bw = 1250000, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 20, .scell = 14, .max_p = 85899345, .crc = 17706065, .flags = 0 },
    .{ .limit = 180000, .min = 15000, .max = 45000, .avpkt = 1500, .burst = 20, .p = 0.02, .bw = 12500000, .qmin = 15000, .qmax = 45000, .wlog = 4, .plog = 21, .scell = 11, .max_p = 85899345, .crc = 2786247284, .flags = 0 },
    .{ .limit = 1080000, .min = 90000, .max = 270000, .avpkt = 9000, .burst = 20, .p = 0.02, .bw = 125000000, .qmin = 90000, .qmax = 270000, .wlog = 4, .plog = 24, .scell = 11, .max_p = 85899345, .crc = 1612759256, .flags = 0 },
    .{ .limit = 100000, .min = null, .max = null, .avpkt = 1000, .burst = 20, .p = 0.02, .bw = 0, .qmin = 8333, .qmax = 25000, .wlog = 5, .plog = 20, .scell = 15, .max_p = 85899345, .crc = 2757582710, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = null, .avpkt = 1000, .burst = null, .p = 0.02, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 3, .plog = 20, .scell = 13, .max_p = 85899345, .crc = 2586082741, .flags = 0 },
    .{ .limit = 100000, .min = null, .max = 9000, .avpkt = 1000, .burst = 20, .p = 0.02, .bw = 0, .qmin = 3000, .qmax = 9000, .wlog = 7, .plog = 19, .scell = 17, .max_p = 85899345, .crc = 2872037873, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = null, .p = 0.02, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 3, .plog = 20, .scell = 13, .max_p = 85899345, .crc = 2586082741, .flags = 0 },
    .{ .limit = 100000, .min = 12345, .max = 40000, .avpkt = 700, .burst = null, .p = 0.02, .bw = 0, .qmin = 12345, .qmax = 40000, .wlog = 4, .plog = 21, .scell = 14, .max_p = 85899345, .crc = 1064687937, .flags = 0 },
    .{ .limit = 100000, .min = 2000, .max = 9999, .avpkt = 700, .burst = null, .p = 0.02, .bw = 0, .qmin = 2000, .qmax = 9999, .wlog = 3, .plog = 19, .scell = 12, .max_p = 85899345, .crc = 1057605817, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20, .p = 0.02, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 20, .scell = 14, .max_p = 85899345, .crc = 17706065, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20, .p = 0.02, .bw = 1, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 20, .scell = 31, .max_p = 85899345, .crc = 2157873325, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20, .p = 0.02, .bw = 125, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 20, .scell = 27, .max_p = 85899345, .crc = 1222335882, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20, .p = 1.0, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 15, .scell = 14, .max_p = 0, .crc = 17706065, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20, .p = 0.00001, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 31, .scell = 14, .max_p = 42949, .crc = 17706065, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 10000, .avpkt = 1000, .burst = 20, .p = 0.02, .bw = 0, .qmin = 10000, .qmax = 10000, .wlog = 4, .plog = 0, .scell = 14, .max_p = 85899345, .crc = 17706065, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 14096, .avpkt = 1000, .burst = 10, .p = 0.5, .bw = 0, .qmin = 10000, .qmax = 14096, .wlog = 1, .plog = 14, .scell = 11, .max_p = 2147483648, .crc = 1975669165, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 14095, .avpkt = 1000, .burst = 10, .p = 0.5, .bw = 0, .qmin = 10000, .qmax = 14095, .wlog = 1, .plog = 13, .scell = 11, .max_p = 2147483648, .crc = 1975669165, .flags = 0 },
    .{ .limit = 100000, .min = 1000, .max = 3000, .avpkt = 1000, .burst = 1, .p = 0.5, .bw = 0, .qmin = 1000, .qmax = 3000, .wlog = 1, .plog = 12, .scell = 11, .max_p = 2147483648, .crc = 1975669165, .flags = 0 },
    .{ .limit = 100000, .min = 1000, .max = 3000, .avpkt = 1000, .burst = 2, .p = 0.5, .bw = 0, .qmin = 1000, .qmax = 3000, .wlog = 27, .plog = 12, .scell = 31, .max_p = 2147483648, .crc = 2157873325, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 100000, .p = 0.02, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 30, .plog = 20, .scell = 31, .max_p = 85899345, .crc = 2157873325, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20, .p = 0.3333, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 16, .scell = 14, .max_p = 1431512599, .crc = 17706065, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20, .p = 0.02, .bw = 500000000, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 20, .scell = 5, .max_p = 85899345, .crc = 4182194221, .flags = 0 },
};

const sfq_cases = [_]RedCase{
    .{ .limit = 100000, .min = 30000, .max = 90000, .avpkt = 1000, .burst = 55, .p = 0.4, .bw = 0, .qmin = 30000, .qmax = 90000, .wlog = 5, .plog = 18, .scell = 0, .max_p = 1717986918, .crc = 0, .flags = 3 },
    .{ .limit = 100000, .min = null, .max = null, .avpkt = 1000, .burst = 20, .p = 0.02, .bw = 0, .qmin = 8333, .qmax = 25000, .wlog = 5, .plog = 20, .scell = 0, .max_p = 85899345, .crc = 0, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = null, .avpkt = 1000, .burst = null, .p = 0.02, .bw = 0, .qmin = 10000, .qmax = 25000, .wlog = 3, .plog = 20, .scell = 0, .max_p = 85899345, .crc = 0, .flags = 0 },
    .{ .limit = 100000, .min = null, .max = 30000, .avpkt = 1000, .burst = null, .p = 0.02, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 3, .plog = 20, .scell = 0, .max_p = 85899345, .crc = 0, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20, .p = 1.0, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 15, .scell = 0, .max_p = 0, .crc = 0, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 0, .burst = 20, .p = 0.02, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 4, .plog = 20, .scell = 0, .max_p = 85899345, .crc = 0, .flags = 0 },
    .{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 700, .burst = 40, .p = 0.1, .bw = 0, .qmin = 10000, .qmax = 30000, .wlog = 6, .plog = 18, .scell = 0, .max_p = 429496729, .crc = 0, .flags = 1 },
    .{ .limit = 400000, .min = 30000, .max = 90000, .avpkt = 1500, .burst = 30, .p = 0.01, .bw = 0, .qmin = 30000, .qmax = 90000, .wlog = 4, .plog = 23, .scell = 0, .max_p = 42949672, .crc = 0, .flags = 2 },
};

// (min, avpkt, burst, wlog): `wlog` null where `tc` refuses ("burst is too
// small"). 96 rows over four thresholds (4, 10, 30 and 100 packets).
const wlog_cases = [_]struct { u32, u32, u32, ?u8 }{
    .{ 4000, 1000, 1, null },
    .{ 4000, 1000, 2, null },
    .{ 4000, 1000, 3, null },
    .{ 4000, 1000, 4, 1 },
    .{ 4000, 1000, 5, 2 },
    .{ 4000, 1000, 6, 2 },
    .{ 4000, 1000, 7, 3 },
    .{ 4000, 1000, 8, 3 },
    .{ 4000, 1000, 9, 4 },
    .{ 4000, 1000, 10, 4 },
    .{ 4000, 1000, 11, 4 },
    .{ 4000, 1000, 14, 5 },
    .{ 4000, 1000, 17, 6 },
    .{ 4000, 1000, 20, 6 },
    .{ 4000, 1000, 25, 7 },
    .{ 4000, 1000, 30, 8 },
    .{ 4000, 1000, 40, 8 },
    .{ 4000, 1000, 55, 9 },
    .{ 4000, 1000, 70, 10 },
    .{ 4000, 1000, 100, 11 },
    .{ 4000, 1000, 150, 12 },
    .{ 4000, 1000, 200, 13 },
    .{ 4000, 1000, 300, 14 },
    .{ 4000, 1000, 500, 16 },
    .{ 10000, 1000, 1, null },
    .{ 10000, 1000, 2, null },
    .{ 10000, 1000, 3, null },
    .{ 10000, 1000, 4, null },
    .{ 10000, 1000, 5, null },
    .{ 10000, 1000, 6, null },
    .{ 10000, 1000, 7, null },
    .{ 10000, 1000, 8, null },
    .{ 10000, 1000, 9, null },
    .{ 10000, 1000, 10, 1 },
    .{ 10000, 1000, 11, 2 },
    .{ 10000, 1000, 14, 3 },
    .{ 10000, 1000, 17, 4 },
    .{ 10000, 1000, 20, 4 },
    .{ 10000, 1000, 25, 5 },
    .{ 10000, 1000, 30, 6 },
    .{ 10000, 1000, 40, 7 },
    .{ 10000, 1000, 55, 8 },
    .{ 10000, 1000, 70, 8 },
    .{ 10000, 1000, 100, 10 },
    .{ 10000, 1000, 150, 11 },
    .{ 10000, 1000, 200, 12 },
    .{ 10000, 1000, 300, 13 },
    .{ 10000, 1000, 500, 14 },
    .{ 30000, 1000, 1, null },
    .{ 30000, 1000, 2, null },
    .{ 30000, 1000, 3, null },
    .{ 30000, 1000, 4, null },
    .{ 30000, 1000, 5, null },
    .{ 30000, 1000, 6, null },
    .{ 30000, 1000, 7, null },
    .{ 30000, 1000, 8, null },
    .{ 30000, 1000, 9, null },
    .{ 30000, 1000, 10, null },
    .{ 30000, 1000, 11, null },
    .{ 30000, 1000, 14, null },
    .{ 30000, 1000, 17, null },
    .{ 30000, 1000, 20, null },
    .{ 30000, 1000, 25, null },
    .{ 30000, 1000, 30, 1 },
    .{ 30000, 1000, 40, 4 },
    .{ 30000, 1000, 55, 5 },
    .{ 30000, 1000, 70, 6 },
    .{ 30000, 1000, 100, 8 },
    .{ 30000, 1000, 150, 9 },
    .{ 30000, 1000, 200, 10 },
    .{ 30000, 1000, 300, 11 },
    .{ 30000, 1000, 500, 13 },
    .{ 100000, 1000, 1, null },
    .{ 100000, 1000, 2, null },
    .{ 100000, 1000, 3, null },
    .{ 100000, 1000, 4, null },
    .{ 100000, 1000, 5, null },
    .{ 100000, 1000, 6, null },
    .{ 100000, 1000, 7, null },
    .{ 100000, 1000, 8, null },
    .{ 100000, 1000, 9, null },
    .{ 100000, 1000, 10, null },
    .{ 100000, 1000, 11, null },
    .{ 100000, 1000, 14, null },
    .{ 100000, 1000, 17, null },
    .{ 100000, 1000, 20, null },
    .{ 100000, 1000, 25, null },
    .{ 100000, 1000, 30, null },
    .{ 100000, 1000, 40, null },
    .{ 100000, 1000, 55, null },
    .{ 100000, 1000, 70, null },
    .{ 100000, 1000, 100, 1 },
    .{ 100000, 1000, 150, 6 },
    .{ 100000, 1000, 200, 7 },
    .{ 100000, 1000, 300, 9 },
    .{ 100000, 1000, 500, 11 },
};

test "red: thresholds, wlog, plog, max_p, scell_log and stab equal what tc sent (every captured row)" {
    for (red_cases) |c| {
        const d = try deriveRed(.{
            .limit = c.limit,
            .min = c.min,
            .max = c.max,
            .avpkt = c.avpkt,
            .burst = c.burst,
            .probability = c.p,
            .bandwidth = c.bw,
        }, ratespec.golden_psched);
        errdefer std.debug.print("row: limit {d} avpkt {d} burst {?d} p {d} bw {d}\n", .{ c.limit, c.avpkt, c.burst, c.p, c.bw });
        try testing.expectEqual(c.qmin, d.qth_min);
        try testing.expectEqual(c.qmax, d.qth_max);
        try testing.expectEqual(c.wlog, d.wlog);
        try testing.expectEqual(c.plog, d.plog);
        try testing.expectEqual(c.scell, d.scell_log);
        try testing.expectEqual(c.max_p, d.max_p);
        try testing.expectEqual(c.crc, std.hash.Crc32.hash(&d.stab));
    }
}

test "sfq red: thresholds, wlog, plog and max_p equal what tc sent" {
    for (sfq_cases) |c| {
        const d = try deriveSfqRed(.{
            .flow_limit = c.limit,
            .min = c.min,
            .max = c.max,
            .avpkt = if (c.avpkt == 0) sfq_default_avpkt else c.avpkt,
            .burst = c.burst,
            .probability = c.p,
            .flags = c.flags,
        });
        errdefer std.debug.print("row: limit {d} burst {?d} p {d}\n", .{ c.limit, c.burst, c.p });
        try testing.expectEqual(c.qmin, d.qth_min);
        try testing.expectEqual(c.qmax, d.qth_max);
        try testing.expectEqual(c.wlog, d.wlog);
        try testing.expectEqual(c.plog, d.plog);
        try testing.expectEqual(@as(u8, 0), d.scell_log);
        try testing.expectEqual(c.max_p, d.max_p);
        try testing.expectEqual(c.flags, d.flags);
    }
}

test "wlogFor: 96 (min, avpkt, burst) rows against tc, errors included" {
    for (wlog_cases) |c| {
        if (c[3]) |w| {
            try testing.expectEqual(w, try wlogFor(c[0], c[1], c[2]));
        } else {
            try testing.expectError(error.BurstTooSmall, wlogFor(c[0], c[1], c[2]));
        }
    }
}

test "wlogFor: the inequality is <=, and the weight search ends at 31" {
    // min = avpkt, burst 1: a == 1 == (1 - (1 - W)) / W for every W; `<=` accepts w = 1.
    try testing.expectEqual(@as(u8, 1), try wlogFor(1000, 1000, 1));
    // burst 2: (1 - (1 - W)^2) / W = 2 - W < 2 until the f64 rounding at W = 2^-27 makes it 2.
    try testing.expectEqual(@as(u8, 27), try wlogFor(1000, 1000, 2));
    try testing.expectError(error.BurstTooLarge, wlogFor(10000, 1000, 1_000_000));
    try testing.expectEqual(@as(u32, 24), minBurst(1507, 64));
}

test "plogFor: strict, from 0 up to 31" {
    try testing.expectEqual(@as(u8, 0), try plogFor(10000, 10000, 0.5));
    try testing.expectEqual(@as(u8, 14), try plogFor(10000, 14096, 0.5)); // 8192 is not below 2^13
    try testing.expectEqual(@as(u8, 13), try plogFor(10000, 14095, 0.5));
    try testing.expectEqual(@as(u8, 31), try plogFor(10000, 30000, 0.00001));
    try testing.expectError(error.ProbabilityOutOfRange, plogFor(10000, 30000, 0.000009));
    try testing.expectError(error.ProbabilityOutOfRange, plogFor(10000, 30000, 0.0));
    try testing.expectError(error.ProbabilityOutOfRange, plogFor(10000, 30000, 1.5));
    try testing.expectError(error.BadThresholds, plogFor(30000, 10000, 0.02));
}

test "maxPFor: truncated, and 1.0 wraps to 0 as tc sends it" {
    try testing.expectEqual(@as(u32, 85899345), maxPFor(0.02));
    try testing.expectEqual(@as(u32, 0), maxPFor(1.0));
    try testing.expectEqual(@as(u32, 2147483648), maxPFor(0.5));
}

test "red: the goldens' stab is the derived one" {
    // goldens.zig: red limit 100000 min 10000 max 30000 avpkt 1000 burst 20 probability 0.02
    const d = try deriveRed(.{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 20 }, ratespec.golden_psched);
    try testing.expectEqual(@as(u8, 4), d.wlog);
    try testing.expectEqual(@as(u8, 20), d.plog);
    try testing.expectEqual(@as(u8, 14), d.scell_log);
    try testing.expectEqual(@as(u32, 85899345), d.max_p);
    try testing.expectEqual(@as(u8, 31), d.stab[255]);
    try testing.expectEqual(@as(u8, 1), d.stab[12]);
    const spec = d.toRed(100000, 0);
    try testing.expectEqual(@as(u8, 4), spec.wlog);
}

test "refusals" {
    const ps = ratespec.golden_psched;
    try testing.expectError(error.MissingParameter, deriveRed(.{ .limit = 0, .avpkt = 1000 }, ps));
    try testing.expectError(error.MissingParameter, deriveRed(.{ .limit = 1000, .avpkt = 0 }, ps));
    // burst 5 is below min / avpkt = 10
    try testing.expectError(error.BurstTooSmall, deriveRed(.{ .limit = 100000, .min = 10000, .max = 30000, .avpkt = 1000, .burst = 5 }, ps));
    try testing.expectError(error.BadThresholds, deriveRed(.{ .limit = 100000, .min = 10000, .max = 9000, .avpkt = 1000, .burst = 20 }, ps));
    try testing.expectError(error.BadThresholds, deriveSfqRed(.{ .flow_limit = 100000, .min = 10000, .max = 5000 }));
    try testing.expectError(error.MissingParameter, deriveSfqRed(.{ .flow_limit = 0 }));
}
