// SPDX-License-Identifier: MIT

//! Live differential oracle: `indicators` against TA-Lib C 0.8.3 -- every seed
//! function, batch API, f64 input (`TA_<F>`) and f32 input (`TA_S_<F>`), over
//! seeded random-walk OHLC inputs, a parameter grid (defaults, edges, swapped
//! fast/slow, every supported MA type, out-of-range values), the unstable period
//! at 0, 3 and both AUTO levels (`TA_SetUnstablePeriod`), and lengths 1, 2,
//! period-1, period, period+1, lookback..lookback+2, 300 and 5000.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-indicators` runs it and
//! `zig build check-interop` compiles it. Needs `zig` on PATH (it builds
//! `tools/talib_oracle.c` with `zig cc`) and TA-Lib built as a static archive:
//!   TALIB_A    path of `libta-lib.a`        (default `~/.local/share/zig-libs/oracle-bin/ta-lib-0.8.3/libta-lib.a`)
//!   TALIB_INC  directory with `ta_libc.h`   (default `~/.local/share/zig-libs/oracles/ta-lib-0.8.3/src/ta-lib-0.8.3/include`)
//! A leading `~` is expanded from `$HOME`. The archive is OUR compile of the audited
//! TA-Lib sources with our own command line (recipe: `tools/README.md`), never TA-Lib's
//! build system. No network. Run from the repository root.
//! Exit 0 = every case agrees within the stated per-function bound; 1 = a disagreement
//! (the first few per function are printed in full) or an oracle failure; 2 = archive or
//! headers not found.
//!
//!   zig build interop-indicators -- --emit-vectors modules/indicators/src/testdata/talib_vectors.zig
//!
//! additionally writes the frozen vectors `src/oracle_test.zig` replays in CI (run `zig fmt` on
//! the file afterwards: the repository's format gate checks it).
//!
//! What is compared, per record: the return code (BadParam <-> TA_BAD_PARAM), the
//! lookback against `TA_<F>_Lookback`, `outBegIdx == lookback` and
//! `outNBElement == n - lookback` when anything is produced, the NaN lead of ours,
//! and every value: bitwise equal, else the distance in ULPs of the output type.
//! `ulp_bound` is the allowed distance per function; 0 means bitwise, anything else
//! is explained next to the table.

const std = @import("std");
const ind = @import("indicators");

const work_dir = ".zig-cache/interop-indicators";
const c_source = "modules/indicators/tools/talib_oracle.c";
const default_a = "~/.local/share/zig-libs/oracle-bin/ta-lib-0.8.3/libta-lib.a";
const default_inc = "~/.local/share/zig-libs/oracles/ta-lib-0.8.3/src/ta-lib-0.8.3/include";
const ta_bad_param: i32 = 2;
const vec_n = 40;

/// Same order as the C `F_*` enum.
const Func = enum(u8) { sma, ema, wma, ma, macd, macdext, macdfix, rsi, bbands, trange, atr, natr, stoch, stochf, max, min, sum };
const func_names = [_][]const u8{ "SMA", "EMA", "WMA", "MA", "MACD", "MACDEXT", "MACDFIX", "RSI", "BBANDS", "TRANGE", "ATR", "NATR", "STOCH", "STOCHF", "MAX", "MIN", "SUM" };
const n_func = func_names.len;

/// Allowed distance in ULPs, per function. Everything is expected to be bitwise:
/// both sides do the same operations in the same order and neither contracts
/// `a*b + c` outside the explicit `fma` calls. A nonzero entry must say why.
const ulp_bound = [n_func]u64{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

fn nIn(f: Func) usize {
    return switch (f) {
        .trange, .atr, .natr, .stoch, .stochf => 3,
        else => 1,
    };
}
fn nOut(f: Func) usize {
    return switch (f) {
        .macd, .macdext, .macdfix, .bbands => 3,
        .stoch, .stochf => 2,
        else => 1,
    };
}

const Case = struct {
    func: Func,
    is32: bool = false,
    ukind: u8 = 0, // 0 bars, 1 auto4, 2 auto8
    ubars: u32 = 0,
    n: u32,
    ip: [6]i32 = @splat(0),
    dp: [2]f64 = .{ 0, 0 },
    kind: u8 = 0, // input kind: 0 walk, 1 walk with flat runs, 2 walk scaled by 1e-9
    seed: u64 = 0,
    bad: bool = false,
    emit: bool = false,

    fn unstable(self: Case) ind.Unstable {
        return switch (self.ukind) {
            0 => .{ .bars = self.ubars },
            1 => .auto4,
            else => .auto8,
        };
    }
};

// ── inputs ──────────────────────────────────────────────────────────────────

/// Seeded OHLC series: close walks, high/low bracket it. Kind 1 holds the price
/// for random runs (flat windows, where RSI/STOCH/BBANDS have special cases);
/// kind 2 is scaled to ~1e-7 (relative thresholds must not depend on the unit).
fn genInput(seed: u64, kind: u8, h: []f64, l: []f64, c: []f64) void {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    var v: f64 = 100.0;
    var hold: usize = 0;
    for (h, l, c) |*hh, *ll, *cc| {
        if (kind == 1) {
            if (hold > 0) {
                hold -= 1;
            } else {
                v += (r.float(f64) - 0.5) * 2.0;
                if (r.boolean()) hold = r.uintLessThan(usize, 20);
            }
        } else {
            v += (r.float(f64) - 0.5) * 2.0;
        }
        const scale: f64 = if (kind == 2) 1e-9 else 1.0;
        const flat = kind == 1 and hold > 0;
        cc.* = v * scale;
        hh.* = if (flat) cc.* else (v + r.float(f64) * 1.5) * scale;
        ll.* = if (flat) cc.* else (v - r.float(f64) * 1.5) * scale;
    }
}

// ── ours ────────────────────────────────────────────────────────────────────

const OursError = ind.Error || std.mem.Allocator.Error;

fn mt(x: i32) ind.MaType {
    return @fromBackingInt(@intCast(@as(u8, @intCast(x))));
}
fn us(x: i32) usize {
    return @intCast(x);
}

fn runOurs(comptime T: type, gpa: std.mem.Allocator, cs: Case, h: []const T, l: []const T, c: []const T, o: *[3][]T) OursError!usize {
    const ip = cs.ip;
    const un = cs.unstable();
    return switch (cs.func) {
        .sma => ind.sma(T, c, o[0], .{ .period = us(ip[0]) }),
        .ema => ind.ema(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .wma => ind.wma(T, c, o[0], .{ .period = us(ip[0]) }),
        .ma => ind.ma(T, c, o[0], .{ .period = us(ip[0]), .kind = mt(ip[1]), .unstable = un }),
        .macd => ind.macd(T, c, o[0], o[1], o[2], .{ .fast = us(ip[0]), .slow = us(ip[1]), .signal = us(ip[2]), .unstable = un }),
        .macdext => ind.macdext(T, gpa, c, o[0], o[1], o[2], .{ .fast = us(ip[0]), .fast_ma = mt(ip[1]), .slow = us(ip[2]), .slow_ma = mt(ip[3]), .signal = us(ip[4]), .signal_ma = mt(ip[5]), .unstable = un }),
        .macdfix => ind.macdfix(T, c, o[0], o[1], o[2], .{ .signal = us(ip[0]), .unstable = un }),
        .rsi => ind.rsi(T, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .bbands => ind.bbands(T, c, o[0], o[1], o[2], .{ .period = us(ip[0]), .dev_up = cs.dp[0], .dev_dn = cs.dp[1], .ma = mt(ip[1]), .unstable = un }),
        .trange => ind.trange(T, h, l, c, o[0]),
        .atr => ind.atr(T, h, l, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .natr => ind.natr(T, h, l, c, o[0], .{ .period = us(ip[0]), .unstable = un }),
        .stoch => ind.stoch(T, gpa, h, l, c, o[0], o[1], .{ .fastk = us(ip[0]), .slowk = us(ip[1]), .slowk_ma = mt(ip[2]), .slowd = us(ip[3]), .slowd_ma = mt(ip[4]), .unstable = un }),
        .stochf => ind.stochf(T, gpa, h, l, c, o[0], o[1], .{ .fastk = us(ip[0]), .fastd = us(ip[1]), .fastd_ma = mt(ip[2]), .unstable = un }),
        .max => ind.max(T, c, o[0], .{ .period = us(ip[0]) }),
        .min => ind.min(T, c, o[0], .{ .period = us(ip[0]) }),
        .sum => ind.sum(T, c, o[0], .{ .period = us(ip[0]) }),
    };
}

// ── the case grid ───────────────────────────────────────────────────────────

const P = struct { ip: [6]i32 = @splat(0), dp: [2]f64 = .{ 0, 0 } };
fn p1(a: i32) P {
    return .{ .ip = .{ a, 0, 0, 0, 0, 0 } };
}
fn pn(a: [6]i32) P {
    return .{ .ip = a };
}

fn periods(comptime ps: []const i32) [ps.len]P {
    var r: [ps.len]P = undefined;
    for (ps, &r) |a, *o| o.* = p1(a);
    return r;
}

/// MA types in the grid: SMA 0, EMA 1, WMA 2, DISABLED 10.
const grid_ma = [_]i32{ 0, 1, 2, 10 };

fn paramsOf(f: Func, gpa: std.mem.Allocator) ![]const P {
    var l: std.ArrayList(P) = .empty;
    switch (f) {
        .sma, .wma => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 14, 50, 100, 0, 100001 })),
        .ema => try l.appendSlice(gpa, &periods(&.{ 30, 1, 2, 3, 5, 12, 26, 50, 100, 0, 100001 })),
        .max, .min, .sum => try l.appendSlice(gpa, &periods(&.{ 30, 2, 3, 5, 14, 100, 1, 0, 100001 })),
        .rsi => try l.appendSlice(gpa, &periods(&.{ 14, 2, 3, 5, 30, 1, 0, 100001 })),
        .atr, .natr => try l.appendSlice(gpa, &periods(&.{ 14, 1, 2, 3, 5, 30, 0, 100001 })),
        .trange => try l.append(gpa, .{}),
        .ma => {
            for ([_]i32{ 30, 1, 2, 5, 14 }) |per| for (grid_ma) |t| try l.append(gpa, pn(.{ per, t, 0, 0, 0, 0 }));
            try l.append(gpa, pn(.{ 0, 0, 0, 0, 0, 0 }));
            try l.append(gpa, pn(.{ 100001, 1, 0, 0, 0, 0 }));
        },
        .macd => for ([_][3]i32{ .{ 12, 26, 9 }, .{ 2, 3, 2 }, .{ 5, 8, 1 }, .{ 26, 12, 9 }, .{ 3, 3, 3 }, .{ 10, 20, 5 }, .{ 2, 2, 1 }, .{ 1, 26, 9 }, .{ 12, 100001, 9 }, .{ 12, 26, 0 } }) |t|
            try l.append(gpa, pn(.{ t[0], t[1], t[2], 0, 0, 0 })),
        .macdfix => try l.appendSlice(gpa, &periods(&.{ 9, 1, 2, 3, 5, 20, 0, 100001 })),
        .macdext => {
            const per = [_][3]i32{ .{ 12, 26, 9 }, .{ 5, 8, 3 }, .{ 9, 4, 1 }, .{ 3, 3, 2 } };
            const ty = [_][3]i32{ .{ 0, 0, 0 }, .{ 1, 1, 1 }, .{ 2, 2, 2 }, .{ 2, 1, 0 }, .{ 0, 1, 2 }, .{ 10, 0, 1 } };
            for (per) |a| for (ty) |t| try l.append(gpa, pn(.{ a[0], t[0], a[1], t[1], a[2], t[2] }));
            try l.append(gpa, pn(.{ 1, 0, 26, 0, 9, 0 }));
            try l.append(gpa, pn(.{ 12, 0, 26, 0, 100001, 0 }));
        },
        .bbands => {
            for ([_]i32{ 20, 5, 2, 10, 3 }) |per| for (grid_ma) |t| try l.append(gpa, .{ .ip = .{ per, t, 0, 0, 0, 0 }, .dp = .{ 2, 2 } });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = .{ 1.5, 2.5 } });
            try l.append(gpa, .{ .ip = .{ 9, 1, 0, 0, 0, 0 }, .dp = .{ 2.5, 0.5 } });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = .{ -1, -1 } });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = .{ 0, 0 } });
            try l.append(gpa, .{ .ip = .{ 1, 0, 0, 0, 0, 0 }, .dp = .{ 2, 2 } });
            try l.append(gpa, .{ .ip = .{ 5, 0, 0, 0, 0, 0 }, .dp = .{ 4e37, 2 } });
        },
        .stoch => {
            for ([_][5]i32{ .{ 5, 3, 0, 3, 0 }, .{ 1, 1, 0, 1, 0 }, .{ 14, 3, 1, 3, 2 }, .{ 3, 2, 0, 5, 2 }, .{ 10, 5, 2, 1, 0 }, .{ 9, 1, 1, 4, 1 }, .{ 5, 3, 10, 3, 0 }, .{ 0, 3, 0, 3, 0 }, .{ 5, 0, 0, 3, 0 }, .{ 5, 3, 0, 100001, 0 } }) |t|
                try l.append(gpa, pn(.{ t[0], t[1], t[2], t[3], t[4], 0 }));
        },
        .stochf => {
            for ([_][3]i32{ .{ 5, 3, 0 }, .{ 1, 1, 0 }, .{ 9, 4, 1 }, .{ 14, 3, 2 }, .{ 3, 5, 2 }, .{ 4, 1, 1 }, .{ 5, 3, 10 }, .{ 0, 3, 0 }, .{ 5, 0, 0 } }) |t|
                try l.append(gpa, pn(.{ t[0], t[1], t[2], 0, 0, 0 }));
        },
    }
    return l.items;
}

/// Functions on which the unstable period does anything.
fn unstableMatters(f: Func) bool {
    return switch (f) {
        .sma, .wma, .trange, .max, .min, .sum => false,
        else => true,
    };
}

fn probeLookback(gpa: std.mem.Allocator, cs_in: Case) ?usize {
    var cs = cs_in;
    cs.n = 1;
    var hh: [1]f64 = .{100};
    var o0: [1]f64 = undefined;
    var o1: [1]f64 = undefined;
    var o2: [1]f64 = undefined;
    var o: [3][]f64 = .{ &o0, &o1, &o2 };
    return runOurs(f64, gpa, cs, &hh, &hh, &hh, &o) catch null;
}

fn addLen(gpa: std.mem.Allocator, ns: *std.ArrayList(u32), n: usize) !void {
    if (n < 1) return;
    for (ns.items) |x| if (x == n) return;
    try ns.append(gpa, @intCast(n));
}

fn buildCases(gpa: std.mem.Allocator, cases: *std.ArrayList(Case)) !void {
    var seed: u64 = 0x7461_6c69_6221;
    for (std.enums.values(Func)) |f| {
        const plist = try paramsOf(f, gpa);
        for (plist, 0..) |pp, pi| {
            const base = Case{ .func = f, .n = 0, .ip = pp.ip, .dp = pp.dp };
            const lbo = probeLookback(gpa, base);
            if (lbo == null) {
                var c = base;
                c.n = 300;
                c.bad = true;
                seed += 1;
                c.seed = seed;
                try cases.append(gpa, c);
                continue;
            }
            const lb = lbo.?;
            const per: usize = @intCast(@max(pp.ip[0], 1));
            var ns: std.ArrayList(u32) = .empty;
            for ([_]usize{ 1, 2, per -| 1, per, per + 1, lb, lb + 1, lb + 2, vec_n, 300 }) |n| try addLen(gpa, &ns, n);
            if (pi == 0) try addLen(gpa, &ns, 5000);
            for (ns.items) |n| {
                var c = base;
                c.n = n;
                seed += 1;
                c.seed = seed;
                c.emit = n == vec_n and pi < 4;
                try cases.append(gpa, c);
                if (n == 300 and pi < 4) for ([_]u8{ 1, 2 }) |k| {
                    var ck = c;
                    ck.kind = k;
                    seed += 1;
                    ck.seed = seed;
                    try cases.append(gpa, ck);
                };
                if (pi < 3 and n >= 300) {
                    var c32 = c;
                    c32.is32 = true;
                    c32.emit = false;
                    try cases.append(gpa, c32);
                }
            }
            if (pi == 0 and f != .trange) {
                var c32 = base;
                c32.is32 = true;
                c32.n = vec_n;
                seed += 1;
                c32.seed = seed;
                c32.emit = true;
                try cases.append(gpa, c32);
            }
            if (unstableMatters(f) and pi < 6) {
                for ([_][2]u32{ .{ 0, 3 }, .{ 1, 0 }, .{ 2, 0 } }) |u| {
                    for ([_]usize{ lb + 1, vec_n, 300 }) |n| {
                        var c = base;
                        c.ukind = @intCast(u[0]);
                        c.ubars = u[1];
                        c.n = @intCast(n);
                        seed += 1;
                        c.seed = seed;
                        c.emit = n == vec_n and pi < 2 and !(u[0] == 2) and !(u[0] == 0 and pi == 1);
                        try cases.append(gpa, c);
                        if (n == 300 and u[0] == 1 and pi < 3) {
                            var c32 = c;
                            c32.is32 = true;
                            c32.emit = false;
                            try cases.append(gpa, c32);
                        }
                    }
                }
            }
        }
    }
}

// ── comparison ──────────────────────────────────────────────────────────────

fn ordered(comptime T: type, x: T) i64 {
    const U = if (T == f32) u32 else u64;
    const I = if (T == f32) i32 else i64;
    const bits: U = @bitCast(x);
    const sign = @as(U, 1) << (@bitSizeOf(U) - 1);
    if (bits & sign != 0) return -@as(i64, @as(I, @intCast(bits & ~sign)));
    return @as(i64, @as(I, @intCast(bits)));
}

fn ulpDist(comptime T: type, a: T, b: T) u64 {
    if (std.math.isNan(a) and std.math.isNan(b)) return 0;
    if (std.math.isNan(a) or std.math.isNan(b)) return std.math.maxInt(u64);
    return @abs(ordered(T, a) - ordered(T, b));
}

const Stat = struct {
    records: usize = 0,
    values: usize = 0,
    bitwise: usize = 0,
    max_ulp: u64 = 0,
    bad: usize = 0,
    reported: usize = 0,
};

const Ctx = struct {
    io: std.Io,
    cwd: std.Io.Dir,
    abs: []const u8,
    exe: []const u8,
    gpa: std.mem.Allocator,
    stats: [n_func]Stat = @splat(.{}),
    vec_out: ?*std.Io.Writer = null,
    vec_count: usize = 0,
};

fn report(c: *Ctx, cs: Case, comptime fmt: []const u8, args: anytype) void {
    const st = &c.stats[@backingInt(cs.func)];
    st.bad += 1;
    if (st.reported >= 3) return;
    st.reported += 1;
    std.debug.print("MISMATCH {s} n={d} f32={} unstable={d}/{d} kind={d} ip={any} dp={any}: ", .{ func_names[@backingInt(cs.func)], cs.n, cs.is32, cs.ukind, cs.ubars, cs.kind, cs.ip, cs.dp });
    std.debug.print(fmt ++ "\n", args);
}

const Head = struct { ret: i32, lb: i32, beg: i32, nb: i32 };

/// Runs ours for one case against what TA-Lib answered; returns the number of
/// bytes of `theirs` consumed.
fn checkCase(comptime T: type, c: *Ctx, arena: std.mem.Allocator, cs: Case, head: Head, theirs: []const u8) !usize {
    const st = &c.stats[@backingInt(cs.func)];
    st.records += 1;
    const n: usize = cs.n;
    const hs = try arena.alloc(f64, n);
    const ls = try arena.alloc(f64, n);
    const cl = try arena.alloc(f64, n);
    genInput(cs.seed, cs.kind, hs, ls, cl);
    const h = try arena.alloc(T, n);
    const l = try arena.alloc(T, n);
    const cc = try arena.alloc(T, n);
    for (0..n) |i| {
        h[i] = @floatCast(hs[i]);
        l[i] = @floatCast(ls[i]);
        cc[i] = @floatCast(cl[i]);
    }
    const no = nOut(cs.func);
    var o: [3][]T = undefined;
    for (&o) |*s| s.* = try arena.alloc(T, n);
    const res = runOurs(T, c.gpa, cs, h, l, cc, &o);
    if (res) |lb| {
        if (head.ret != 0) {
            report(c, cs, "ours succeeded (lookback {d}), TA-Lib returned {d}", .{ lb, head.ret });
            return 0;
        }
        if (@as(i64, head.lb) != @as(i64, @intCast(lb))) {
            report(c, cs, "lookback ours {d} TA-Lib {d}", .{ lb, head.lb });
            return @as(usize, @intCast(head.nb)) * 8 * no;
        }
        const nb: usize = @intCast(head.nb);
        const expect_nb = if (n > lb) n - lb else 0;
        if (nb != expect_nb or (nb > 0 and head.beg != head.lb)) {
            report(c, cs, "outBegIdx {d} outNBElement {d} for lookback {d}, n {d}", .{ head.beg, head.nb, lb, n });
            return nb * 8 * no;
        }
        var bad_here = false;
        for (0..no) |q| {
            const lead = @min(lb, n);
            for (o[q][0..lead]) |v| if (!std.math.isNan(v)) {
                report(c, cs, "ours has a non-NaN value in the lead of output {d}", .{q});
                bad_here = true;
                break;
            };
            for (0..nb) |i| {
                const want: T = @floatCast(@as(f64, @bitCast(std.mem.readInt(u64, theirs[(q * nb + i) * 8 ..][0..8], .little))));
                const got = o[q][lb + i];
                const d = ulpDist(T, got, want);
                st.values += 1;
                if (d == 0) st.bitwise += 1;
                st.max_ulp = @max(st.max_ulp, d);
                if (d > ulp_bound[@backingInt(cs.func)] and !bad_here) {
                    report(c, cs, "output {d} at {d}: ours {e} TA-Lib {e} ({d} ulp)", .{ q, lb + i, got, want, d });
                    bad_here = true;
                }
            }
        }
        if (cs.emit and !bad_here) try emitVector(c, cs, lb, nb, hs, ls, cl, h, l, cc, theirs, T);
        return nb * 8 * no;
    } else |err| switch (err) {
        error.BadParam => {
            if (head.ret != ta_bad_param) report(c, cs, "ours BadParam, TA-Lib returned {d}", .{head.ret});
            return if (head.ret == 0) @as(usize, @intCast(head.nb)) * 8 * no else 0;
        },
        else => {
            report(c, cs, "ours failed: {s}", .{@errorName(err)});
            return if (head.ret == 0) @as(usize, @intCast(head.nb)) * 8 * no else 0;
        },
    }
}

fn hexBits(w: *std.Io.Writer, v: f64) !void {
    try w.print("0x{x}", .{@as(u64, @bitCast(v))});
}

fn emitVector(c: *Ctx, cs: Case, lb: usize, nb: usize, hs: []const f64, ls: []const f64, cl: []const f64, h: anytype, l: anytype, cc: anytype, theirs: []const u8, comptime T: type) !void {
    _ = hs;
    _ = ls;
    _ = cl;
    const w = c.vec_out orelse return;
    c.vec_count += 1;
    try w.print("    .{{ .func = {d}, .f32 = {}, .ukind = {d}, .ubars = {d}, .n = {d}, .lb = {d}, .ip = .{{", .{ @backingInt(cs.func), cs.is32, cs.ukind, cs.ubars, cs.n, lb });
    for (cs.ip, 0..) |x, i| try w.print("{s}{d}", .{ if (i > 0) ", " else " ", x });
    try w.writeAll(" }, .dp = .{ ");
    try hexBits(w, cs.dp[0]);
    try w.writeAll(", ");
    try hexBits(w, cs.dp[1]);
    try w.writeAll(" },\n      .ins = &.{");
    const ni = nIn(cs.func);
    for (0..ni) |q| {
        const src = if (ni == 1) cc else switch (q) {
            0 => h,
            1 => l,
            else => cc,
        };
        try w.writeAll(" &.{");
        for (src, 0..) |v, i| {
            try w.writeAll(if (i > 0) ", " else " ");
            try hexBits(w, @floatCast(v));
        }
        try w.writeAll(" },");
    }
    try w.writeAll(" },\n      .outs = &.{");
    for (0..nOut(cs.func)) |q| {
        try w.writeAll(" &.{");
        for (0..nb) |i| {
            try w.writeAll(if (i > 0) ", " else " ");
            const x = std.mem.readInt(u64, theirs[(q * nb + i) * 8 ..][0..8], .little);
            try w.print("0x{x}", .{x});
        }
        try w.writeAll(" },");
    }
    try w.writeAll(" } },\n");
    _ = T;
}

fn runAll(c: *Ctx, arena: std.mem.Allocator, cases: []const Case) !void {
    var buf: std.Io.Writer.Allocating = .init(arena);
    const w = &buf.writer;
    try w.writeInt(u32, @intCast(cases.len), .little);
    for (cases) |cs| {
        try w.writeAll(&.{ @backingInt(cs.func), @intFromBool(cs.is32), cs.ukind, 0 });
        try w.writeInt(u32, cs.ubars, .little);
        try w.writeInt(u32, cs.n, .little);
        for (cs.ip) |x| try w.writeInt(i32, x, .little);
        for (cs.dp) |x| try w.writeInt(u64, @bitCast(x), .little);
        const n: usize = cs.n;
        const hs = try arena.alloc(f64, n);
        const ls = try arena.alloc(f64, n);
        const cl = try arena.alloc(f64, n);
        genInput(cs.seed, cs.kind, hs, ls, cl);
        const ni = nIn(cs.func);
        for (0..ni) |q| {
            const src = if (ni == 1) cl else switch (q) {
                0 => hs,
                1 => ls,
                else => cl,
            };
            for (src) |v| {
                if (cs.is32) {
                    const f: f32 = @floatCast(v);
                    try w.writeInt(u32, @bitCast(f), .little);
                } else try w.writeInt(u64, @bitCast(v), .little);
            }
        }
    }
    const cases_path = try arena.print("{s}/cases.bin", .{c.abs});
    const results_path = try arena.print("{s}/results.bin", .{c.abs});
    try c.cwd.writeFile(c.io, .{ .sub_path = cases_path, .data = buf.written() });
    const res = try std.process.run(arena, c.io, .{ .argv = &.{ c.exe, cases_path, results_path } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("interop-indicators: TA-Lib side failed:\n{s}\n", .{res.stderr});
        return error.OracleFailed;
    }
    const theirs = try c.cwd.readFileAlloc(c.io, results_path, arena, .limited(1 << 31));
    var off: usize = 0;
    for (cases) |cs| {
        if (off + 16 > theirs.len) return error.ShortResults;
        var head: Head = undefined;
        head = .{
            .ret = std.mem.readInt(i32, theirs[off..][0..4], .little),
            .lb = std.mem.readInt(i32, theirs[off + 4 ..][0..4], .little),
            .beg = std.mem.readInt(i32, theirs[off + 8 ..][0..4], .little),
            .nb = std.mem.readInt(i32, theirs[off + 12 ..][0..4], .little),
        };
        off += 16;
        const used = if (cs.is32)
            try checkCase(f32, c, arena, cs, head, theirs[off..])
        else
            try checkCase(f64, c, arena, cs, head, theirs[off..]);
        off += used;
    }
    if (off != theirs.len) return error.TrailingResults;
}

fn expandHome(arena: std.mem.Allocator, home: ?[]const u8, path: []const u8) ![]const u8 {
    if (path.len > 0 and path[0] == '~') return try arena.print("{s}{s}", .{ home orelse "", path[1..] });
    return path;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const home = init.environ_map.get("HOME");
    const args = try init.minimal.args.toSlice(arena);
    var emit_path: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--emit-vectors") and i + 1 < args.len) {
            i += 1;
            emit_path = args[i];
        }
    }

    const archive = try expandHome(arena, home, init.environ_map.get("TALIB_A") orelse default_a);
    const inc = try expandHome(arena, home, init.environ_map.get("TALIB_INC") orelse default_inc);
    cwd.access(io, archive, .{}) catch {
        std.debug.print("interop-indicators: TA-Lib archive not found at {s} (set TALIB_A to libta-lib.a, see tools/README.md)\n", .{archive});
        return 2;
    };
    cwd.access(io, try arena.print("{s}/ta_libc.h", .{inc}), .{}) catch {
        std.debug.print("interop-indicators: ta_libc.h not found in {s} (set TALIB_INC)\n", .{inc});
        return 2;
    };
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const exe = try arena.print("{s}/talib_oracle", .{abs});
    const cc = try std.process.run(arena, io, .{ .argv = &.{ "zig", "cc", "-O1", "-I", inc, c_source, archive, "-lm", "-o", exe } });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("interop-indicators: zig cc failed:\n{s}\n", .{cc.stderr});
        return 1;
    }
    const ver_run = try std.process.run(arena, io, .{ .argv = &.{ exe, "--version" } });
    const version = std.mem.trimEnd(u8, ver_run.stdout, "\n");

    var cases: std.ArrayList(Case) = .empty;
    try buildCases(arena, &cases);

    var vec: std.Io.Writer.Allocating = .init(arena);
    var ctx: Ctx = .{ .io = io, .cwd = cwd, .abs = abs, .exe = exe, .gpa = arena };
    if (emit_path != null) {
        ctx.vec_out = &vec.writer;
        try vec.writer.writeAll(
            \\// SPDX-License-Identifier: MIT
            \\//! GENERATED by `zig build interop-indicators -- --emit-vectors <this file>`
            \\//! (modules/indicators/tools/interop.zig): TA-Lib answers frozen as bit patterns.
            \\//! Inputs and outputs are f64 bits (for `f32` records the inputs are the f32
            \\//! values widened, the outputs TA_S_*'s doubles). Replayed by src/oracle_test.zig.
            \\
            \\pub const Vec = struct {
            \\    func: u8,
            \\    f32: bool,
            \\    ukind: u8,
            \\    ubars: u32,
            \\    n: u32,
            \\    lb: u32,
            \\    ip: [6]i32,
            \\    dp: [2]u64,
            \\    ins: []const []const u64,
            \\    outs: []const []const u64,
            \\};
            \\
            \\
        );
        try vec.writer.print("pub const source = \"{s}\";\n\n", .{version});
        try vec.writer.writeAll("pub const vectors = [_]Vec{\n");
    }
    try runAll(&ctx, arena, cases.items);

    var failed = false;
    std.debug.print("interop-indicators: {s}, {d} records\n", .{ version, cases.items.len });
    std.debug.print("  {s:<8} {s:>8} {s:>10} {s:>10} {s:>8} {s:>5}\n", .{ "func", "records", "values", "bitwise", "max ulp", "bad" });
    for (func_names, ctx.stats) |name, st| {
        std.debug.print("  {s:<8} {d:>8} {d:>10} {d:>10} {d:>8} {d:>5}\n", .{ name, st.records, st.values, st.bitwise, st.max_ulp, st.bad });
        if (st.bad != 0) failed = true;
    }
    if (failed) {
        std.debug.print("interop-indicators: DISAGREEMENT with {s}\n", .{version});
        return 1;
    }
    if (emit_path) |pth| {
        try vec.writer.writeAll("};\n\npub const ulp_bound = [_]u64{");
        for (ulp_bound, 0..) |b, k| try vec.writer.print("{s}{d}", .{ if (k > 0) ", " else " ", b });
        try vec.writer.writeAll(" };\n");
        if (std.fs.path.dirname(pth)) |d| try cwd.createDirPath(io, d);
        try cwd.writeFile(io, .{ .sub_path = pth, .data = vec.written() });
        std.debug.print("interop-indicators: wrote {d} vectors to {s}\n", .{ ctx.vec_count, pth });
    }
    std.debug.print("interop-indicators: all cases agree with {s}\n", .{version});
    return 0;
}
