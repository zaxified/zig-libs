// SPDX-License-Identifier: MIT
//! The comparison driver behind a maturity card's `**Performance:**` line.
//!
//! Eighteen `tools/bench.zig` programs carried the same ~200 lines by hand
//! (counted 2026-10-17: `Cycles`, `Row`, `Side`, `timeIt`, `foreign`, `Work`,
//! `Summary`, `drive`, `buildForeign`, `foreignOnce` byte-identical in 15 of
//! them, three with a one-feature fork each). This is that code once, with the
//! three forks as `Work` fields: `info` (brotli), `ours_foreign` (sandbox),
//! `wall_only` (resilience).
//!
//! ## The method
//!
//! Our side doubles its batch until one batch takes over 100 ms and keeps the
//! best of five; the foreign program does the same on its side and prints
//! `name \t ns/op \t cycles/op \t count` (its banner on stderr). Per workload
//! the sides **alternate** for `rounds` rounds, each keeping its best — timed
//! one after the other they would see different loads of a shared machine.
//! Ratios are ours/theirs by user-mode cycles when every side counted them,
//! else by wall time. A spread over 5 % is printed as a noisy run. An output
//! `count` that differs between the sides fails the run: the sides did not do
//! the same work, so their times compare nothing.
//!
//! The scoring (`score`, `Summary.add`) is a pure function of the rows and is
//! what the tests here exercise; `drive` only times and prints around it.
//!
//! A bench program is a program, not a test: it is built ReleaseFast by
//! `zig build bench-<m>` and never run by any lane (CONVENTIONS.md §9 kind 3).

const std = @import("std");
const builtin = @import("builtin");

/// One timed side: per-op wall time and user-mode cycles (0 = no counter).
pub const Row = struct { ns: f64, cycles: f64 = 0, count: u64 };

/// Best and worst of the rounds of one side.
pub const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    best_cyc: f64 = std.math.inf(f64),
    worst_cyc: f64 = 0,
    count: u64 = 0,

    pub fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.best_cyc = @min(s.best_cyc, r.cycles);
        s.worst_cyc = @max(s.worst_cyc, r.cycles);
        s.count = r.count;
    }
    pub fn best(s: Side, cyc: bool) f64 {
        return if (cyc) s.best_cyc else s.best_ns;
    }
    pub fn spread(s: Side, cyc: bool) f64 {
        return if (cyc) s.worst_cyc / s.best_cyc - 1 else s.worst_ns / s.best_ns - 1;
    }
};

/// This thread's user-mode cycle counter (`perf stat -e cycles:u`); a null
/// `fd` (no Linux, no permission) reads 0, which makes `drive` fall back to
/// wall time.
pub const Cycles = struct {
    fd: ?i32,

    pub fn open() Cycles {
        if (builtin.os.tag != .linux) return .{ .fd = null };
        const linux = std.os.linux;
        var attr: linux.perf_event_attr = .{
            .type = .HARDWARE,
            .config = @intFromEnum(linux.PERF.COUNT.HW.CPU_CYCLES),
            .flags = .{ .exclude_kernel = true, .exclude_hv = true },
        };
        const rc = linux.perf_event_open(&attr, 0, -1, -1, 0);
        if (linux.errno(rc) != .SUCCESS) return .{ .fd = null };
        return .{ .fd = @intCast(rc) };
    }

    pub fn read(c: Cycles) u64 {
        if (builtin.os.tag != .linux) return 0;
        const fd = c.fd orelse return 0;
        var v: u64 = 0;
        _ = std.os.linux.read(fd, @ptrCast(&v), @sizeOf(u64));
        return v;
    }
};

/// Time `@call(once, args)`: double the batch until it takes over 100 ms,
/// then the best of five batches, per op. `count` is what the last call
/// returned (an output size the sides must agree on). `wall_only` reports no
/// cycles: a threaded op's cycles are mostly other threads', so wall time
/// decides.
pub fn timeIt(io: std.Io, cyc: Cycles, comptime once: anytype, args: anytype, wall_only: bool) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(@call(.auto, once, args));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var best_cycles: u64 = std.math.maxInt(u64);
    var count: u64 = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        const c0 = cyc.read();
        for (0..n) |_| count = @call(.auto, once, args);
        best_cycles = @min(best_cycles, cyc.read() - c0);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    const nf: f64 = @floatFromInt(n);
    const cyc_per: f64 = if (wall_only) 0 else @as(f64, @floatFromInt(best_cycles)) / nf;
    return .{ .ns = @as(f64, @floatFromInt(best)) / nf, .cycles = cyc_per, .count = count };
}

/// Parse one line of a foreign program's output for workload `name`:
/// `name \t ns/op \t cycles/op \t count`, or `name \t ns/op \t count` from a
/// side that counts no cycles (the Go stdlib benches); a trailing newline is
/// allowed.
pub fn parseForeign(out: []const u8, name: []const u8) error{ BadForeignOutput, InvalidCharacter, Overflow }!Row {
    var fields: [5][]const u8 = undefined;
    var n: usize = 0;
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, out, "\n"), '\t');
    while (f.next()) |x| : (n += 1) {
        if (n == fields.len) return error.BadForeignOutput;
        fields[n] = x;
    }
    if (n != 3 and n != 4) return error.BadForeignOutput;
    if (!std.mem.eql(u8, fields[0], name)) return error.BadForeignOutput;
    return .{
        .ns = try std.fmt.parseFloat(f64, fields[1]),
        .cycles = if (n == 4) try std.fmt.parseFloat(f64, fields[2]) else 0,
        .count = try std.fmt.parseInt(u64, fields[n - 1], 10),
    };
}

/// Run the foreign program for one workload: `<exe> <work dir> <name>`.
/// Its stderr is the banner (which implementation, which version), kept in
/// `banner` when given.
pub fn foreign(arena: std.mem.Allocator, io: std.Io, bench_name: []const u8, exe: []const u8, abs: []const u8, name: []const u8, banner: ?*[]const u8) !Row {
    return foreignArgv(arena, io, bench_name, &.{ exe, abs, name }, name, banner);
}

/// `foreign` with the whole command line given (a side that takes no work
/// directory).
pub fn foreignArgv(arena: std.mem.Allocator, io: std.Io, bench_name: []const u8, argv: []const []const u8, name: []const u8, banner: ?*[]const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = argv });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    if (banner) |b| b.* = res.stderr;
    return parseForeign(res.stdout, name);
}

pub const GoBuild = struct {
    /// The `go` program. The caller (a `tools/` program) names it: a module's
    /// own source never names a foreign toolchain (`check-module-purity`).
    exe: []const u8,
    /// The Go package, relative to the repository root
    /// (`modules/<m>/tools/go_bench`).
    dir: []const u8,
    /// The work directory, absolute; the binary is `<abs>/go_bench`.
    abs: []const u8,
    /// `GOTOOLCHAIN`: `local`, or an exact `go1.N.M` that must then already
    /// be installed (the network is off).
    toolchain: []const u8 = "local",
};

/// Build the Go side once, offline (`GOPROXY=off`, `-mod=readonly`), so the
/// timed runs do not pay for it.
pub fn goBuild(arena: std.mem.Allocator, io: std.Io, bench_name: []const u8, environ: *const std.process.Environ.Map, opts: GoBuild) ![]const u8 {
    var env = try environ.clone(arena);
    try env.put("GOTOOLCHAIN", opts.toolchain);
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try std.fmt.allocPrint(arena, "{s}/go_bench", .{opts.abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ opts.exe, "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = opts.dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return error.GoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: go build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.GoBuildFailed;
    }
    return exe;
}

/// One workload: `op` for our side, the foreign program's workload `ref`
/// (the reference) and optionally `alt` (a second implementation in the
/// field, for the `fastest` ratio); `*_exe` index `Run.exes`.
pub fn Work(comptime Op: type) type {
    return struct {
        name: []const u8,
        op: Op,
        ref: []const u8,
        alt: ?[]const u8 = null,
        ref_exe: usize = 0,
        alt_exe: usize = 0,
        /// Printed, but kept out of the verdict (`Summary`): a row that shows
        /// a cost the card does not claim against (brotli's allocating path).
        info: bool = false,
        /// Our side is timed by the foreign program too, under this workload
        /// name (sandbox: the cost of a filter is measured from C on both
        /// sides, so the harness overhead is the same).
        ours_foreign: ?[]const u8 = null,
        /// Wall time only for our side (see `timeIt`).
        wall_only: bool = false,
    };
}

/// One workload's verdict, from the three sides' best-of-rounds.
pub const Line = struct {
    by_cycles: bool,
    /// ours / ref.
    ref: f64,
    /// ours / min(ref, alt); `ref` when there is no `alt`.
    fast: f64,
    has_alt: bool,
    spread: f64,
    same_count: bool,
    info: bool,
};

pub fn score(ours: Side, ref: Side, alt: ?Side, info: bool) Line {
    const by_cyc = ours.best_cyc > 0 and ref.best_cyc > 0 and (alt == null or alt.?.best_cyc > 0);
    const r_ref = ours.best(by_cyc) / ref.best(by_cyc);
    const r_fast = if (alt) |a| ours.best(by_cyc) / @min(ref.best(by_cyc), a.best(by_cyc)) else r_ref;
    const spr_alt = if (alt) |a| a.spread(by_cyc) else 0;
    return .{
        .by_cycles = by_cyc,
        .ref = r_ref,
        .fast = r_fast,
        .has_alt = alt != null,
        .spread = @max(ours.spread(by_cyc), @max(ref.spread(by_cyc), spr_alt)),
        .same_count = ours.count == ref.count and (alt == null or ours.count == alt.?.count),
        .info = info,
    };
}

pub const Summary = struct {
    best_ref: f64 = std.math.inf(f64),
    worst_ref: f64 = 0,
    /// Worst of ours / min(ref, alt) over the workloads that have an `alt`.
    worst_fast: ?f64 = null,
    max_spread: f64 = 0,
    /// Every workload was compared by cycles.
    by_cycles: bool = true,
    /// Some workload's output count differed between the sides.
    mismatch: bool = false,
    banner: []const u8 = "",
    alt_banner: []const u8 = "",

    /// Fold one workload in. An `info` line counts for the spread and the
    /// count check, never for the ratios the card quotes.
    pub fn add(s: *Summary, l: Line) void {
        s.by_cycles = s.by_cycles and l.by_cycles;
        if (!l.info) {
            s.worst_ref = @max(s.worst_ref, l.ref);
            s.best_ref = @min(s.best_ref, l.ref);
            if (l.has_alt) s.worst_fast = @max(s.worst_fast orelse 0, l.fast);
        }
        s.max_spread = @max(s.max_spread, l.spread);
        s.mismatch = s.mismatch or !l.same_count;
    }
};

/// Whether workload `name` runs under the command-line filters (substrings;
/// none = all).
pub fn selected(name: []const u8, filters: []const [:0]const u8) bool {
    if (filters.len == 0) return true;
    for (filters) |f| if (std.mem.indexOf(u8, name, f) != null) return true;
    return false;
}

pub const Run = struct {
    /// `bench-<module>`, the prefix of every diagnostic.
    name: []const u8,
    /// The foreign programs `Work.ref_exe`/`alt_exe` index.
    exes: []const []const u8,
    /// The work directory, absolute: the first argument of every foreign run.
    abs: []const u8,
    filters: []const [:0]const u8 = &.{},
    rounds: usize = 3,
};

/// Time every selected workload, print the table to `w`, return the verdict.
/// `ctx` is a pointer to a struct with an `op` field, which is set to each
/// workload's `op` before `once(ctx)` is timed.
pub fn drive(io: std.Io, arena: std.mem.Allocator, run: Run, ctx: anytype, comptime once: anytype, ws: anytype, w: *std.Io.Writer) !Summary {
    const cyc: Cycles = .open();
    var s: Summary = .{};
    try w.print("{s:<18} {s:>11} {s:>11} {s:>11} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "ref ns", "alt ns", "/ref", "/fast", "spr us", "spr rf", "spr al" });
    try w.flush();
    for (ws) |x| {
        if (!selected(x.name, run.filters)) continue;
        ctx.op = x.op;
        var ours: Side = .{};
        var ref: Side = .{};
        var alt: Side = .{};
        for (0..run.rounds) |_| {
            ref.add(try foreign(arena, io, run.name, run.exes[x.ref_exe], run.abs, x.ref, &s.banner));
            if (x.ours_foreign) |n| {
                var sink_banner: []const u8 = undefined;
                ours.add(try foreign(arena, io, run.name, run.exes[x.ref_exe], run.abs, n, &sink_banner));
            } else ours.add(timeIt(io, cyc, once, .{ctx}, x.wall_only));
            if (x.alt) |a| alt.add(try foreign(arena, io, run.name, run.exes[x.alt_exe], run.abs, a, &s.alt_banner));
        }
        const l = score(ours, ref, if (x.alt != null) alt else null, x.info);
        s.add(l);
        const by = l.by_cycles;
        try w.print("{s:<18} {d:>11.0} {d:>11.0} {d:>11.0} {d:>7.3} {d:>7.3} {d:>5.1}% {d:>5.1}% {d:>5.1}%  {d}{s}\n", .{
            x.name,                                ours.best_ns,         ref.best_ns,
            if (x.alt != null) alt.best_ns else 0, l.ref,                l.fast,
            100 * ours.spread(by),                 100 * ref.spread(by), if (x.alt != null) 100 * alt.spread(by) else 0,
            ours.count,
            if (!l.same_count) " ≠" else if (x.info) "  (info, not in the verdict)" else "",
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ run.rounds, if (s.by_cycles) "user-mode cycles" else "wall time", 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    try w.flush();
    if (s.mismatch) {
        std.debug.print("{s}: FAILED -- an output size differs between the sides\n", .{run.name});
        return error.CountMismatch;
    }
    return s;
}

/// The foreign program, built from `src` by the compiler command `cc`
/// (`&.{ "zig", "cc" }`; the caller, a `tools/` program, names it — a
/// module's own source never names a foreign toolchain) with `-O3
/// -march=native` against `libs` (shared objects named by path, so no
/// headers are needed), into `<abs>/foreign_bench`.
pub fn buildForeign(arena: std.mem.Allocator, io: std.Io, bench_name: []const u8, cc: []const []const u8, abs: []const u8, src: []const u8, libs: []const []const u8) ![]const u8 {
    const exe = try std.fmt.allocPrint(arena, "{s}/foreign_bench", .{abs});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, cc);
    try argv.appendSlice(arena, &.{ "-O3", "-march=native", src });
    try argv.appendSlice(arena, libs);
    try argv.appendSlice(arena, &.{ "-o", exe });
    std.debug.print("{s}: building the foreign side ({s}) ...\n", .{ bench_name, src });
    const res = try std.process.run(arena, io, .{ .argv = argv.items });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: the C compiler failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.ForeignBuildFailed;
    }
    return exe;
}

/// Run the foreign program once in a non-timing mode (`interop`, `keygen`).
pub fn foreignOnce(arena: std.mem.Allocator, io: std.Io, bench_name: []const u8, exe: []const u8, abs: []const u8, mode: []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, mode } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed in {s}:\n{s}\n", .{ bench_name, mode, res.stderr });
        return error.ForeignFailed;
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn side(rows: []const Row) Side {
    var s: Side = .{};
    for (rows) |r| s.add(r);
    return s;
}

test "Side: best and worst of the rounds, spread relative to the best" {
    const s = side(&.{ .{ .ns = 12, .cycles = 30, .count = 5 }, .{ .ns = 10, .cycles = 40, .count = 5 }, .{ .ns = 15, .cycles = 33, .count = 5 } });
    try testing.expectEqual(@as(f64, 10), s.best(false));
    try testing.expectEqual(@as(f64, 30), s.best(true));
    try testing.expectApproxEqAbs(@as(f64, 0.5), s.spread(false), 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 1.0 / 3.0), s.spread(true), 1e-12);
}

test "score: by cycles only when every side counted them" {
    const ours = side(&.{.{ .ns = 50, .cycles = 100, .count = 1 }});
    const ref = side(&.{.{ .ns = 100, .cycles = 400, .count = 1 }});
    const no_cyc = side(&.{.{ .ns = 25, .cycles = 0, .count = 1 }});
    const l = score(ours, ref, null, false);
    try testing.expect(l.by_cycles);
    try testing.expectEqual(@as(f64, 0.25), l.ref);
    try testing.expectEqual(l.ref, l.fast);
    // An alt without a counter turns the whole line to wall time.
    const m = score(ours, ref, no_cyc, false);
    try testing.expect(!m.by_cycles);
    try testing.expectEqual(@as(f64, 0.5), m.ref);
    try testing.expectEqual(@as(f64, 2.0), m.fast); // 50 / min(100, 25)
    // Our side without one (wall_only) does the same.
    try testing.expect(!score(no_cyc, ref, null, false).by_cycles);
}

test "score: a count that differs on any side is a mismatch" {
    const a = side(&.{.{ .ns = 1, .cycles = 1, .count = 7 }});
    const b = side(&.{.{ .ns = 1, .cycles = 1, .count = 8 }});
    try testing.expect(score(a, a, null, false).same_count);
    try testing.expect(!score(a, b, null, false).same_count);
    try testing.expect(!score(a, a, b, false).same_count);
}

test "score: the spread is the worst of the three sides" {
    const calm = side(&.{ .{ .ns = 10, .count = 1 }, .{ .ns = 10, .count = 1 } });
    const noisy = side(&.{ .{ .ns = 10, .count = 1 }, .{ .ns = 13, .count = 1 } });
    try testing.expectApproxEqAbs(@as(f64, 0.3), score(calm, calm, noisy, false).spread, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.3), score(calm, noisy, null, false).spread, 1e-12);
    try testing.expectApproxEqAbs(@as(f64, 0.3), score(noisy, calm, null, false).spread, 1e-12);
}

test "Summary: worst/best over the lines, info lines out of the ratios" {
    var s: Summary = .{};
    s.add(.{ .by_cycles = true, .ref = 0.8, .fast = 0.8, .has_alt = false, .spread = 0.01, .same_count = true, .info = false });
    s.add(.{ .by_cycles = true, .ref = 1.05, .fast = 1.3, .has_alt = true, .spread = 0.02, .same_count = true, .info = false });
    s.add(.{ .by_cycles = false, .ref = 9.0, .fast = 9.0, .has_alt = true, .spread = 0.07, .same_count = true, .info = true });
    try testing.expectEqual(@as(f64, 0.8), s.best_ref);
    try testing.expectEqual(@as(f64, 1.05), s.worst_ref);
    try testing.expectEqual(@as(?f64, 1.3), s.worst_fast);
    // The info line still counts for the noise and the metric.
    try testing.expectEqual(@as(f64, 0.07), s.max_spread);
    try testing.expect(!s.by_cycles);
    try testing.expect(!s.mismatch);
    s.add(.{ .by_cycles = true, .ref = 1, .fast = 1, .has_alt = false, .spread = 0, .same_count = false, .info = true });
    try testing.expect(s.mismatch);
}

test "Summary: no alt anywhere leaves fastest unmeasured, not zero" {
    var s: Summary = .{};
    s.add(.{ .by_cycles = true, .ref = 0.9, .fast = 0.9, .has_alt = false, .spread = 0, .same_count = true, .info = false });
    try testing.expectEqual(@as(?f64, null), s.worst_fast);
}

test "parseForeign: four (or three) tab-separated fields, name checked" {
    const r = try parseForeign("enc_64\t123.5\t410\t64\n", "enc_64");
    try testing.expectEqual(Row{ .ns = 123.5, .cycles = 410, .count = 64 }, r);
    try testing.expectError(error.BadForeignOutput, parseForeign("dec_64\t1\t2\t3\n", "enc_64"));
    // Three fields: a side without a cycle counter.
    try testing.expectEqual(Row{ .ns = 7, .cycles = 0, .count = 2 }, try parseForeign("enc_64\t7\t2", "enc_64"));
    try testing.expectError(error.BadForeignOutput, parseForeign("enc_64\t1\n", "enc_64"));
    try testing.expectError(error.BadForeignOutput, parseForeign("enc_64\t1\t2\t3\t4\n", "enc_64"));
    try testing.expectError(error.BadForeignOutput, parseForeign("enc_64\t1\t2\t3\t4\t5\t6\n", "enc_64"));
    try testing.expectError(error.InvalidCharacter, parseForeign("enc_64\t1\tx\t3", "enc_64"));
}

test "selected: no filters runs everything, else any substring" {
    try testing.expect(selected("enc_64", &.{}));
    try testing.expect(selected("enc_64", &.{ "dec", "64" }));
    try testing.expect(!selected("enc_64", &.{"dec"}));
}

test "timeIt: the count is the last op's result, the time per op" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const Ctx = struct {
        calls: usize = 0,
        fn once(c: *@This()) usize {
            c.calls += 1;
            return 42;
        }
    };
    var c: Ctx = .{};
    var threaded: std.Io.Threaded = .init_single_threaded;
    const r = timeIt(threaded.io(), .{ .fd = null }, Ctx.once, .{&c}, true);
    try testing.expectEqual(@as(u64, 42), r.count);
    try testing.expectEqual(@as(f64, 0), r.cycles);
    try testing.expect(r.ns > 0 and r.ns < 1e6);
    try testing.expect(c.calls > 5);
}
