// SPDX-License-Identifier: MIT

//! Comparative benchmark: `indicators` against TA-Lib C 0.8.3 (the reference; the module
//! is a port of it, so there is no other candidate) -- the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-indicators` runs it (always ReleaseFast);
//! `zig build check-interop` compiles it. Run from the repository root. It needs the same
//! TA-Lib archive and headers as `interop-indicators` (`TALIB_A`, `TALIB_INC`, defaults under
//! `~/.local/share/zig-libs/`, recipe in `tools/README.md`) and the system C compiler `cc` (env `CC`) for the C driver
//! `tools/bench_talib.c` (rows in `tools/bench_rows.h`), built here once into
//! `.zig-cache/bench-indicators/`.
//!
//! Both sides time the same thing: one BATCH call over the first n bars of the same seeded
//! random-walk OHLCV series (f64; the file `ohlcv.bin` this program writes), into
//! preallocated output buffers, one thread; ours `ind.<f>(f64, ...)` with `out.len == n`
//! (so it also writes the NaN lead), TA-Lib `TA_<F>(0, n - 1, ...)` into compact buffers.
//! Parameters are the same on both sides and runtime values on ours (an opaque copy), not
//! constants the optimizer could fold. Each side times itself as the benchkit does: double the
//! batch until it takes over 100 ms, best of five. Rows `<name>.<n>`; the `s_*` rows time n
//! streaming updates (`EmaStream.update` against `TA_EMA_Update`, ...), one op = n updates.
//!
//! Before anything is timed, every row is run once at n = 1000 on both sides and the sum of
//! all finite outputs must agree (relative 1e-9) and so must the output count; the timed
//! counts must agree too (benchkit fails a run otherwise). Ratios by user-mode cycles.
//!
//! Caveats, also in SPEC.md § Benchmark: the TA-Lib archive is OUR compile of its sources,
//! `-O2 -ffp-contract=off -fno-math-errno`, generic x86-64 with TA-Lib's own `target_clones`
//! fma variants (the official build's value flags), while this program is built for the
//! native CPU; a distribution's TA-Lib is the same C at `-O2`/`-O3`. `-Djcc-safe` does not
//! reach the C side. The C driver MUST be linked by the system `cc` (gcc, glibc): `zig cc` resolves
//! TA-Lib's `fma()` calls to compiler-rt's SOFTWARE fma, which made TA-Lib 5-20x slower on every
//! function that fuses (EMA, ATR, T3, ...; measured 2026-11-15) -- a ratio against that is
//! meaningless. Arguments filter workloads (substrings of `row.n`). `BENCH_ROUNDS`
//! (default 3) sets the alternating rounds; `BENCH_CHECK_ONLY=1` stops after the pre-check.

const std = @import("std");
const bench = @import("benchkit");
const ind = @import("indicators");

const bench_name = "bench-indicators";
const work_dir = ".zig-cache/bench-indicators";
const c_source = "modules/indicators/tools/bench_talib.c";
const default_a = "~/.local/share/zig-libs/oracle-bin/ta-lib-0.8.3/libta-lib.a";
const default_inc = "~/.local/share/zig-libs/oracles/ta-lib-0.8.3/src/ta-lib-0.8.3/include";
const gpa = std.heap.smp_allocator;

const max_n = 1_000_000;

// ── data ─────────────────────────────────────────────────────────────────────

const Data = struct {
    o: []f64,
    h: []f64,
    l: []f64,
    c: []f64,
    v: []f64,
    a: []f64,
    b: []f64,
    cc: []f64,
    d: []f64,
    oi: []i32,
};
var D: Data = undefined;

fn alloc(comptime T: type) []T {
    return gpa.alloc(T, max_n) catch @panic("oom");
}

/// A seeded random walk: close moves by up to +-1 %, open is the previous close, high / low
/// extend the body by up to 0.5 %, volume 1000..11000.
fn generate(r: std.Random) void {
    var c: f64 = 100;
    for (0..max_n) |i| {
        const o = c;
        c = o * (1 + (r.float(f64) - 0.5) * 0.02);
        D.o[i] = o;
        D.c[i] = c;
        D.h[i] = @max(o, c) * (1 + r.float(f64) * 0.005);
        D.l[i] = @min(o, c) * (1 - r.float(f64) * 0.005);
        D.v[i] = 1000 + r.float(f64) * 10000;
    }
}

// ── rows ─────────────────────────────────────────────────────────────────────

const Ins = enum { c, hl, hlc, hlcv, ohlc, cv, oc };
const Outs = enum { f1, f2, f3, f4, i1 };

const RowFn = *const fn (usize) usize;
const Row = struct { name: []const u8, f: RowFn, outs: Outs };

fn inputs(comptime k: Ins, n: usize) switch (k) {
    .c => struct { []const f64 },
    .hl, .cv, .oc => struct { []const f64, []const f64 },
    .hlc => struct { []const f64, []const f64, []const f64 },
    .hlcv, .ohlc => struct { []const f64, []const f64, []const f64, []const f64 },
} {
    return switch (k) {
        .c => .{D.c[0..n]},
        .hl => .{ D.h[0..n], D.l[0..n] },
        .cv => .{ D.c[0..n], D.v[0..n] },
        .oc => .{ D.o[0..n], D.c[0..n] },
        .hlc => .{ D.h[0..n], D.l[0..n], D.c[0..n] },
        .hlcv => .{ D.h[0..n], D.l[0..n], D.c[0..n], D.v[0..n] },
        .ohlc => .{ D.o[0..n], D.h[0..n], D.l[0..n], D.c[0..n] },
    };
}

fn outputs(comptime k: Outs, n: usize) switch (k) {
    .f1 => struct { []f64 },
    .f2 => struct { []f64, []f64 },
    .f3 => struct { []f64, []f64, []f64 },
    .f4 => struct { []f64, []f64, []f64, []f64 },
    .i1 => struct { []i32 },
} {
    return switch (k) {
        .f1 => .{D.a[0..n]},
        .f2 => .{ D.a[0..n], D.b[0..n] },
        .f3 => .{ D.a[0..n], D.b[0..n], D.cc[0..n] },
        .f4 => .{ D.a[0..n], D.b[0..n], D.cc[0..n], D.d[0..n] },
        .i1 => .{D.oi[0..n]},
    };
}

/// The type of the last parameter of `f` (the params struct: it does not depend on `T`).
fn lastParam(comptime f: anytype) type {
    const ps = @typeInfo(@TypeOf(f)).@"fn".param_types;
    return ps[ps.len - 1].?;
}

/// One batch row: `f(f64, [gpa,] inputs..., outputs..., params)`. The parameters are copied
/// through memory the optimizer cannot see through, so they are runtime values as in a caller.
fn W(comptime name: []const u8, comptime f: anytype, comptime ins: Ins, comptime outs: Outs, comptime needs_gpa: bool, comptime init: lastParam(f)) Row {
    const P = lastParam(f);
    const G = struct {
        fn run(n: usize) usize {
            var p: P = init;
            std.mem.doNotOptimizeAway(&p);
            const args = .{f64} ++ (if (needs_gpa) .{gpa} else .{}) ++ inputs(ins, n) ++ outputs(outs, n) ++ .{p};
            const lb = @call(.auto, f, args) catch @panic("indicators bench: a row failed");
            return n - lb;
        }
    };
    return .{ .name = name, .f = G.run, .outs = outs };
}

/// A row of a function with no parameters.
fn W0(comptime name: []const u8, comptime f: anytype, comptime ins: Ins, comptime outs: Outs) Row {
    const G = struct {
        fn run(n: usize) usize {
            const args = .{f64} ++ inputs(ins, n) ++ outputs(outs, n);
            const lb = @call(.auto, f, args) catch @panic("indicators bench: a row failed");
            return n - lb;
        }
    };
    return .{ .name = name, .f = G.run, .outs = outs };
}

const rows = [_]Row{
    // the headline set
    W("sma", ind.sma, .c, .f1, false, .{ .period = 30 }),
    W("ema", ind.ema, .c, .f1, false, .{ .period = 30 }),
    W("wma", ind.wma, .c, .f1, false, .{ .period = 30 }),
    W("rsi", ind.rsi, .c, .f1, false, .{ .period = 14 }),
    W("macd", ind.macd, .c, .f3, false, .{ .fast = 12, .slow = 26, .signal = 9 }),
    W("bbands", ind.bbands, .c, .f3, false, .{ .period = 20, .dev_up = 2.0, .dev_dn = 2.0, .ma = .sma }),
    W("atr", ind.atr, .hlc, .f1, false, .{ .period = 14 }),
    W("stoch", ind.stoch, .hlc, .f2, true, .{ .fastk = 5, .slowk = 3, .slowk_ma = .sma, .slowd = 3, .slowd_ma = .sma }),
    W("adx", ind.adx, .hlc, .f1, false, .{ .period = 14 }),
    W0("obv", ind.obv, .cv, .f1),
    W("max", ind.max, .c, .f1, false, .{ .period = 30 }),
    W("min", ind.min, .c, .f1, false, .{ .period = 30 }),
    W("cci", ind.cci, .hlc, .f1, false, .{ .period = 14 }),
    W("mfi", ind.mfi, .hlcv, .f1, false, .{ .period = 14 }),
    W("kama", ind.kama, .c, .f1, false, .{ .period = 30 }),
    W("t3", ind.t3, .c, .f1, false, .{ .period = 5, .vfactor = 0.7 }),
    W("ht_dcperiod", ind.htDcperiod, .c, .f1, false, .{}),
    W("linearreg", ind.linearreg, .c, .f1, false, .{ .period = 14 }),
    W("stddev", ind.stddev, .c, .f1, false, .{ .period = 20, .nbdev = 1.0 }),
    W("cdlengulfing", ind.candles.cdlengulfing, .ohlc, .i1, false, .{}),
    // the screening set
    W("dema", ind.dema, .c, .f1, false, .{ .period = 30 }),
    W("tema", ind.tema, .c, .f1, false, .{ .period = 30 }),
    W("trima", ind.trima, .c, .f1, false, .{ .period = 30 }),
    W("sar", ind.sar, .hl, .f1, false, .{ .acceleration = 0.02, .maximum = 0.2 }),
    W("mama", ind.mama, .c, .f2, false, .{ .fast_limit = 0.5, .slow_limit = 0.05 }),
    W("ht_trendline", ind.htTrendline, .c, .f1, false, .{}),
    W("ht_sine", ind.htSine, .c, .f2, false, .{}),
    W("ht_phasor", ind.htPhasor, .c, .f2, false, .{}),
    W("ht_dcphase", ind.htDcphase, .c, .f1, false, .{}),
    W("correl", ind.correl, .oc, .f1, false, .{ .period = 30 }),
    W("beta", ind.beta, .oc, .f1, false, .{ .period = 5 }),
    W("var", ind.variance, .c, .f1, false, .{ .period = 5, .nbdev = 1.0 }),
    W("aroon", ind.aroon, .hl, .f2, false, .{ .period = 14 }),
    W("willr", ind.willr, .hlc, .f1, false, .{ .period = 14 }),
    W("ultosc", ind.ultosc, .hlc, .f1, false, .{ .period1 = 7, .period2 = 14, .period3 = 28 }),
    W("trix", ind.trix, .c, .f1, false, .{ .period = 30 }),
    W("ppo", ind.ppo, .c, .f1, false, .{ .fast = 12, .slow = 26, .kind = .ema }),
    W("apo", ind.apo, .c, .f1, false, .{ .fast = 12, .slow = 26, .kind = .ema }),
    W("adosc", ind.adosc, .hlcv, .f1, false, .{ .fast = 3, .slow = 10 }),
    W("midpoint", ind.midpoint, .c, .f1, false, .{ .period = 14 }),
    W("plus_di", ind.plusDi, .hlc, .f1, false, .{ .period = 14 }),
    W("natr", ind.natr, .hlc, .f1, false, .{ .period = 14 }),
    W("stochrsi", ind.stochrsi, .c, .f2, true, .{ .period = 14, .fastk = 5, .fastd = 3, .fastd_ma = .sma }),
    W("cmo", ind.cmo, .c, .f1, false, .{ .period = 14 }),
    W("roc", ind.roc, .c, .f1, false, .{ .period = 10 }),
    W("mom", ind.mom, .c, .f1, false, .{ .period = 10 }),
    W("sum", ind.sum, .c, .f1, false, .{ .period = 30 }),
    W0("trange", ind.trange, .hlc, .f1),
    W("avgdev", ind.avgdev, .c, .f1, false, .{ .period = 14 }),
    W("tsf", ind.tsf, .c, .f1, false, .{ .period = 14 }),
    W("stochf", ind.stochf, .hlc, .f2, true, .{ .fastk = 5, .fastd = 3, .fastd_ma = .sma }),
    W("median", ind.median, .c, .f1, true, .{ .period = 30 }),
    W("percentile", ind.percentile, .c, .f1, true, .{ .period = 100, .percentile = 50.0 }),
    W("percentrank", ind.percentrank, .c, .f1, false, .{ .period = 100 }),
    W("kurtosis", ind.kurtosis, .c, .f1, false, .{ .period = 30 }),
    W("hma", ind.hma, .c, .f1, false, .{ .period = 20 }),
    W("alma", ind.alma, .c, .f1, true, .{ .period = 9, .sigma = 6.0, .offset = 0.85 }),
    W("vidya", ind.vidya, .c, .f1, false, .{ .period = 12, .cmo_period = 9 }),
    W("frama", ind.frama, .hl, .f1, false, .{ .period = 16 }),
    W0("vwap", ind.vwap, .hlcv, .f1),
    W("kdj", ind.kdj, .hlc, .f3, true, .{ .fastk = 9, .slowk = 3, .slowk_ma = .rma, .slowd = 3, .slowd_ma = .rma }),
    W("crsi", ind.crsi, .c, .f1, true, .{ .period = 3, .streak = 2, .rank = 100 }),
    W("stc", ind.stc, .c, .f1, true, .{ .fast = 23, .slow = 50, .cycle = 10 }),
    W("wavetrend", ind.wavetrend, .hlc, .f2, true, .{ .channel = 10, .average = 21, .signal = 4 }),
    W("chop", ind.chop, .hlc, .f1, false, .{ .period = 14 }),
    W("fisher", ind.fisher, .hl, .f2, false, .{ .period = 10 }),
    W("ichimoku", ind.ichimoku, .hl, .f4, false, .{ .tenkan = 9, .kijun = 26, .senkou_b = 52 }),
    W("macdext", ind.macdext, .c, .f3, true, .{ .fast = 12, .fast_ma = .sma, .slow = 26, .slow_ma = .sma, .signal = 9, .signal_ma = .sma }),
    W("ma_ema", ind.ma, .c, .f1, false, .{ .period = 30, .kind = .ema }),
    W("cmf", ind.cmf, .hlcv, .f1, false, .{ .period = 20 }),
    W("efi", ind.efi, .cv, .f1, false, .{ .period = 13 }),
    W("kvo", ind.kvo, .hlcv, .f2, false, .{ .fast = 34, .slow = 55, .signal = 13 }),
    W0("ad", ind.ad, .hlcv, .f1),
    W("minmax", ind.minmax, .c, .f2, false, .{ .period = 30 }),
    W("aroonosc", ind.aroonosc, .hl, .f1, false, .{ .period = 14 }),
    W0("bop", ind.bop, .ohlc, .f1),
    W("rvi", ind.rvi, .c, .f1, false, .{ .period = 14, .stddev = 10 }),
    W("tsi", ind.tsi, .c, .f1, false, .{ .first = 25, .second = 13 }),
    W("dx", ind.dx, .hlc, .f1, false, .{ .period = 14 }),
    W("kc", ind.kc, .hlc, .f3, false, .{ .period = 20, .atr_period = 10, .nb_dev = 2.0 }),
    W("donchian", ind.donchian, .hl, .f3, false, .{ .period = 20 }),
    W("accbands", ind.accbands, .hlc, .f3, false, .{ .period = 20 }),
    W("swak_butter", ind.swakButter, .c, .f1, false, .{ .period = 20 }),
    W("cdldoji", ind.candles.cdldoji, .ohlc, .i1, false, .{}),
    W("cdlhammer", ind.candles.cdlhammer, .ohlc, .i1, false, .{}),
    W("cdlmorningstar", ind.candles.cdlmorningstar, .ohlc, .i1, false, .{ .penetration = 0.3 }),
    W("cdlhikkake", ind.candles.cdlhikkake, .ohlc, .i1, false, .{}),
    W("cdl3whitesoldiers", ind.candles.cdl3whitesoldiers, .ohlc, .i1, false, .{}),
};

// ── streams: n updates ───────────────────────────────────────────────────────

/// The first bars are fed untimed-in-count: TA-Lib's `_Open` needs a history, the C side opens over
/// the same 100 bars and counts the updates after them.
const seed = 100;

fn sEma(n: usize) usize {
    var s = ind.EmaStream(f64).init(.{ .period = 30 }) catch @panic("ema stream");
    var c: usize = 0;
    var acc: f64 = 0;
    for (D.c[0..seed]) |x| _ = s.update(x);
    for (D.c[seed..n]) |x| {
        if (s.update(x)) |v| {
            c += 1;
            acc += v;
        }
    }
    // The values are consumed: without this the optimizer folds the counting loop away.
    std.mem.doNotOptimizeAway(acc);
    return c;
}

fn sRsi(n: usize) usize {
    var s = ind.RsiStream(f64).init(.{ .period = 14 }) catch @panic("rsi stream");
    var c: usize = 0;
    var acc: f64 = 0;
    for (D.c[0..seed]) |x| _ = s.update(x);
    for (D.c[seed..n]) |x| {
        if (s.update(x)) |v| {
            c += 1;
            acc += v;
        }
    }
    std.mem.doNotOptimizeAway(acc);
    return c;
}

fn sAtr(n: usize) usize {
    var s = ind.AtrStream(f64).init(.{ .period = 14 }) catch @panic("atr stream");
    var c: usize = 0;
    var acc: f64 = 0;
    for (0..seed) |i| _ = s.update(.{ .high = D.h[i], .low = D.l[i], .close = D.c[i] });
    for (seed..n) |i| {
        if (s.update(.{ .high = D.h[i], .low = D.l[i], .close = D.c[i] })) |v| {
            c += 1;
            acc += v;
        }
    }
    std.mem.doNotOptimizeAway(acc);
    return c;
}

const streams = [_]Row{
    .{ .name = "s_ema", .f = sEma, .outs = .f1 },
    .{ .name = "s_rsi", .f = sRsi, .outs = .f1 },
    .{ .name = "s_atr", .f = sAtr, .outs = .f1 },
};

// ── workloads ────────────────────────────────────────────────────────────────

const Op = struct { f: RowFn, n: usize };
const Ctx = struct { op: Op };
const Work = bench.Work(Op);

fn once(ctx: *Ctx) u64 {
    return ctx.op.f(ctx.op.n);
}

/// Rows timed at 1e3 and 1e5 (the headline set), and the few also at 1e6.
fn headline(name: []const u8) bool {
    for (rows[0..20]) |r| if (std.mem.eql(u8, r.name, name)) return true;
    return false;
}
const big_rows = [_][]const u8{ "sma", "ema", "rsi", "atr", "ht_dcperiod", "t3" };
fn isBig(name: []const u8) bool {
    for (big_rows) |b| if (std.mem.eql(u8, b, name)) return true;
    return false;
}

fn expandHome(arena: std.mem.Allocator, home: ?[]const u8, path: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, path, "~/")) return arena.print("{s}{s}", .{ home orelse return error.NoHome, path[1..] });
    return path;
}

fn sumOf(row: Row, n: usize) struct { sum: f64, count: usize } {
    const count = row.f(n);
    var s: f64 = 0;
    const lists = [_][]f64{ D.a[0..n], D.b[0..n], D.cc[0..n], D.d[0..n] };
    const nf: usize = switch (row.outs) {
        .f1 => 1,
        .f2 => 2,
        .f3 => 3,
        .f4 => 4,
        .i1 => 0,
    };
    for (lists[0..nf]) |l| for (l) |x| {
        if (std.math.isFinite(x)) s += x;
    };
    if (row.outs == .i1) for (D.oi[0..n]) |x| {
        s += @floatFromInt(x);
    };
    return .{ .sum = s, .count = count };
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;
    const home = init.environ_map.get("HOME");
    const archive = try expandHome(arena, home, init.environ_map.get("TALIB_A") orelse default_a);
    const inc = try expandHome(arena, home, init.environ_map.get("TALIB_INC") orelse default_inc);
    cwd.access(io, archive, .{}) catch {
        std.debug.print("{s}: TA-Lib archive not found at {s} (set TALIB_A, see tools/README.md)\n", .{ bench_name, archive });
        return 2;
    };

    D = .{ .o = alloc(f64), .h = alloc(f64), .l = alloc(f64), .c = alloc(f64), .v = alloc(f64), .a = alloc(f64), .b = alloc(f64), .cc = alloc(f64), .d = alloc(f64), .oi = alloc(i32) };
    var prng = std.Random.DefaultPrng.init(0x1d1_ca70);
    generate(prng.random());
    {
        const bytes = try arena.alloc(u8, 5 * max_n * 8);
        const lists = [_][]f64{ D.o, D.h, D.l, D.c, D.v };
        for (lists, 0..) |l, k| @memcpy(bytes[k * max_n * 8 ..][0 .. max_n * 8], std.mem.sliceAsBytes(l));
        try cwd.writeFile(io, .{ .sub_path = work_dir ++ "/ohlcv.bin", .data = bytes });
    }

    const exe = try arena.print("{s}/bench_talib", .{abs});
    const cc = init.environ_map.get("CC") orelse "cc";
    std.debug.print("{s}: building the C side ({s}, {s}) ...\n", .{ bench_name, cc, c_source });
    {
        const res = try std.process.run(arena, io, .{ .argv = &.{ cc, "-O2", "-I", inc, c_source, archive, "-lm", "-o", exe } });
        if (res.term != .exited or res.term.exited != 0) {
            std.debug.print("{s}: cc failed:\n{s}\n", .{ bench_name, res.stderr });
            return 1;
        }
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;

    // Pre-check: every row once at n = 1000 on both sides.
    var bad = false;
    for (rows) |r| {
        if (!bench.selected(try arena.print("{s}.1000", .{r.name}), filters) and !bench.selected(try arena.print("{s}.100000", .{r.name}), filters)) continue;
        const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, "--sum", try arena.print("{s}.1000", .{r.name}) } });
        if (res.term != .exited or res.term.exited != 0) {
            try w.print("pre-check: {s}: the C side failed:\n{s}\n", .{ r.name, res.stderr });
            bad = true;
            continue;
        }
        var f = std.mem.tokenizeAny(u8, std.mem.trimEnd(u8, res.stdout, "\n"), "\t");
        _ = f.next();
        const their_sum = try std.fmt.parseFloat(f64, f.next().?);
        const their_count = try std.fmt.parseInt(usize, f.next().?, 10);
        const mine = sumOf(r, 1000);
        const tol = 1e-9 * @max(1.0, @abs(their_sum));
        const ok = mine.count == their_count and @abs(mine.sum - their_sum) <= tol;
        if (!ok) {
            bad = true;
            try w.print("pre-check: {s:<18} DIFFER: count ours {d} theirs {d}; sum ours {e} theirs {e}\n", .{ r.name, mine.count, their_count, mine.sum, their_sum });
        }
    }
    try w.flush();
    if (bad) {
        try w.writeAll(bench_name ++ ": FAILED -- the sides disagree before timing; see above\n");
        try w.flush();
        return 1;
    }
    try w.writeAll("pre-check: every row agrees with TA-Lib (output count, sum of finite outputs within 1e-9) at n = 1000\n");

    if (init.environ_map.get("BENCH_CHECK_ONLY") != null) {
        try w.flush();
        return 0;
    }

    var ws: std.ArrayList(Work) = .empty;
    const sizes_all = [_]usize{ 1_000, 100_000 };
    for (rows) |r| {
        if (headline(r.name)) {
            for (sizes_all) |n| try ws.append(arena, .{ .name = try arena.print("{s}.{d}", .{ r.name, n }), .op = .{ .f = r.f, .n = n }, .ref = try arena.print("{s}.{d}", .{ r.name, n }) });
            if (isBig(r.name)) try ws.append(arena, .{ .name = try arena.print("{s}.1000000", .{r.name}), .op = .{ .f = r.f, .n = 1_000_000 }, .ref = try arena.print("{s}.1000000", .{r.name}) });
        } else {
            try ws.append(arena, .{ .name = try arena.print("{s}.100000", .{r.name}), .op = .{ .f = r.f, .n = 100_000 }, .ref = try arena.print("{s}.100000", .{r.name}) });
        }
    }
    for (streams) |r| try ws.append(arena, .{ .name = try arena.print("{s}.100000", .{r.name}), .op = .{ .f = r.f, .n = 100_000 }, .ref = try arena.print("{s}.100000", .{r.name}) });

    var ctx: Ctx = .{ .op = ws.items[0].op };
    const s = bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, &ctx, once, ws.items, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("reference: {s}\nworst ours/TA-Lib = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    try w.writeAll("streams: s_* rows are n = 100000 updates per op; ns per update = ns / 100000\n");
    try w.flush();
    return 0;
}
