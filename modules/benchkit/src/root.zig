// SPDX-License-Identifier: MIT
//! benchkit — the comparison driver behind a maturity card's `**Performance:**`
//! line. Bench-only: `build.zig` hands it to every `tools/bench.zig` program
//! and to nothing a downstream user imports.
//!
//! It was `testkit.bench` until 2026-11-14. It moved out because testkit is a
//! `test_dep` of 221 modules: every edit to this file re-keyed all their tests
//! in every CI lane (8 of testkit's 31 changes in the six weeks before), and no
//! test imports it. Here an edit re-keys the bench programs only.
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

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Bench-only comparison driver — alternating rounds of ours / reference / fastest alternative in one run, user-mode cycle ratios with a wall-time fallback, foreign programs built and run capped and timed out; wired into tools/bench.zig only, absent from consumer imports",
    .platform_note = "any (cycle counter: linux)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "criterion and Go's testing.B, reduced to the comparison a maturity card quotes",
    .deps = .{},
};

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
            .config = @backingInt(linux.PERF.COUNT.HW.CPU_CYCLES),
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

    /// Release the counter. One left open per `drive` call piled up on the
    /// thread: past the PMU's counters they are multiplexed and each reads
    /// only part of the cycles (tlsserver's bench, one `drive` per workload,
    /// 2026-10-21: workloads 4–6 read 0.35–0.54× while wall time said
    /// 0.46–0.90×).
    pub fn close(c: Cycles) void {
        if (builtin.os.tag != .linux) return;
        if (c.fd) |fd| _ = std.os.linux.close(fd);
    }
};

/// Counter delta; 0 when a read failed in between (`Cycles.read` answers 0
/// for an unreadable counter), never an underflow.
fn cyclesSince(now: u64, before: u64) u64 {
    return now -| before;
}

/// Captured foreign output is one result line and a banner, or a compiler's
/// diagnostics: this much is plenty, and a foreign program that writes past it
/// fails the run (`error.StreamTooLong`) instead of filling memory.
pub const capture_limit: std.Io.Limit = .limited(16 << 20);

/// Longest a foreign compiler / `go build` may run, and a timed foreign run:
/// a hung child fails the benchmark (`error.Timeout`, the child killed)
/// instead of blocking it for good.
pub const build_timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(600), .clock = .awake } };
pub const run_timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } };

/// Every foreign child goes through here: output capped at `capture_limit`
/// (`error.StreamTooLong`) and a `timeout` (`error.Timeout`).
fn runCapped(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8, environ_map: ?*const std.process.Environ.Map, cwd: std.process.Child.Cwd, timeout: std.Io.Timeout) !std.process.RunResult {
    return std.process.run(arena, io, .{
        .argv = argv,
        .environ_map = environ_map,
        .cwd = cwd,
        .stdout_limit = capture_limit,
        .stderr_limit = capture_limit,
        .timeout = timeout,
    });
}

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
        // Kept observable per call, as in the doubling loop: a pure `once`
        // whose result is only overwritten could be hoisted out of the loop.
        for (0..n) |_| {
            count = @call(.auto, once, args);
            std.mem.doNotOptimizeAway(count);
        }
        best_cycles = @min(best_cycles, cyclesSince(cyc.read(), c0));
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    const nf: f64 = @floatFromInt(n);
    const cyc_per: f64 = if (wall_only) 0 else @as(f64, @floatFromInt(best_cycles)) / nf;
    return .{ .ns = @as(f64, @floatFromInt(best)) / nf, .cycles = cyc_per, .count = count };
}

/// Parse one line of a foreign program's output for workload `name`:
/// `name \t ns/op \t cycles/op \t count`, or `name \t ns/op \t count` from a
/// side that counts no cycles (the Go stdlib benches); a trailing newline is
/// allowed. `ns` must be finite and positive, `cycles` finite and not
/// negative (0 = not counted), else `error.BadForeignOutput`.
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
    const ns = try std.fmt.parseFloat(f64, fields[1]);
    const cycles: f64 = if (n == 4) try std.fmt.parseFloat(f64, fields[2]) else 0;
    // `nan` / `inf` / a non-positive time would make every ratio NaN (which
    // compares as "not slower") or infinite; cycles may be 0 (not counted).
    if (!std.math.isFinite(ns) or ns <= 0) return error.BadForeignOutput;
    if (!std.math.isFinite(cycles) or cycles < 0) return error.BadForeignOutput;
    return .{
        .ns = ns,
        .cycles = cycles,
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
    const res = try runCapped(arena, io, argv, null, .inherit, run_timeout);
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
    /// The work directory, absolute; the binary is `<abs>/<out>`.
    abs: []const u8,
    /// The binary's name in `abs` (a second Go program beside the reference
    /// needs its own).
    out: []const u8 = "go_bench",
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
    const exe = try arena.print("{s}/{s}", .{ opts.abs, opts.out });
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const res = runCapped(arena, io, &.{ opts.exe, "build", "-o", exe, "." }, &env, .{ .path = opts.dir }, build_timeout) catch |e| {
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
        /// The card's reference has no such workload, so `ref` here names
        /// the fastest candidate instead (aescbc's CTS rows: Go has no CTS,
        /// OpenSSL does): the row counts for `Summary.worst_fast`, never for
        /// the reference ratio.
        fast_only: bool = false,
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
    /// See `Work.fast_only`: `ref` is the fastest candidate's ratio.
    fast_only: bool = false,
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
        if (l.fast_only) {
            if (!l.info) s.worst_fast = @max(s.worst_fast orelse 0, l.fast);
        } else if (!l.info) {
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
    for (filters) |f| if (std.mem.find(u8, name, f) != null) return true;
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

/// `Run.rounds`, at least 1.
fn roundsOf(run: Run) usize {
    return @max(1, run.rounds);
}

/// `Run.exes[i]`, with the index checked: `Work.ref_exe`/`alt_exe` are the
/// caller's, and this runs in a ReleaseFast bench program, where an
/// out-of-range index would be an unchecked read.
fn exeAt(run: Run, i: usize) []const u8 {
    if (i >= run.exes.len) @panic("benchkit: Work.ref_exe/alt_exe indexes past Run.exes");
    return run.exes[i];
}

/// Time every selected workload, print the table to `w`, return the verdict.
/// `ctx` is a pointer to a struct with an `op` field, which is set to each
/// workload's `op` before `once(ctx)` is timed.
pub fn drive(io: std.Io, arena: std.mem.Allocator, run: Run, ctx: anytype, comptime once: anytype, ws: anytype, w: *std.Io.Writer) !Summary {
    const cyc: Cycles = .open();
    defer cyc.close();
    var s: Summary = .{};
    // Zero rounds would leave every side at its +inf start and print NaN
    // ratios as a verdict; one round is the least that measures anything.
    const rounds = roundsOf(run);
    try w.print("{s:<18} {s:>11} {s:>11} {s:>11} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "ref ns", "alt ns", "/ref", "/fast", "spr us", "spr rf", "spr al" });
    try w.flush();
    for (ws) |x| {
        if (!selected(x.name, run.filters)) continue;
        ctx.op = x.op;
        var ours: Side = .{};
        var ref: Side = .{};
        var alt: Side = .{};
        for (0..rounds) |_| {
            ref.add(try foreign(arena, io, run.name, exeAt(run, x.ref_exe), run.abs, x.ref, &s.banner));
            if (x.ours_foreign) |n| {
                var sink_banner: []const u8 = undefined;
                ours.add(try foreign(arena, io, run.name, exeAt(run, x.ref_exe), run.abs, n, &sink_banner));
            } else ours.add(timeIt(io, cyc, once, .{ctx}, x.wall_only));
            if (x.alt) |a| alt.add(try foreign(arena, io, run.name, exeAt(run, x.alt_exe), run.abs, a, &s.alt_banner));
        }
        var l = score(ours, ref, if (x.alt != null) alt else null, x.info);
        l.fast_only = x.fast_only;
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
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (s.by_cycles) "user-mode cycles" else "wall time", 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
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
    const exe = try arena.print("{s}/foreign_bench", .{abs});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, cc);
    try argv.appendSlice(arena, &.{ "-O3", "-march=native", src });
    try argv.appendSlice(arena, libs);
    try argv.appendSlice(arena, &.{ "-o", exe });
    std.debug.print("{s}: building the foreign side ({s}) ...\n", .{ bench_name, src });
    const res = try runCapped(arena, io, argv.items, null, .inherit, build_timeout);
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: the C compiler failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.ForeignBuildFailed;
    }
    return exe;
}

/// Run the foreign program once in a non-timing mode (`interop`, `keygen`).
pub fn foreignOnce(arena: std.mem.Allocator, io: std.Io, bench_name: []const u8, exe: []const u8, abs: []const u8, mode: []const u8) !void {
    const res = try runCapped(arena, io, &.{ exe, abs, mode }, null, .inherit, run_timeout);
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
    // The count is the last row's (the sides agree on it, so any row would do).
    try testing.expectEqual(@as(u64, 5), s.count);
    try testing.expectEqual(@as(u64, 9), side(&.{ .{ .ns = 1, .count = 4 }, .{ .ns = 1, .count = 9 } }).count);
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

test "Summary: a fast_only line counts for fastest, never for the reference ratio" {
    var s: Summary = .{};
    s.add(.{ .by_cycles = true, .ref = 0.8, .fast = 0.8, .has_alt = false, .spread = 0, .same_count = true, .info = false });
    s.add(.{ .by_cycles = true, .ref = 1.21, .fast = 1.21, .has_alt = false, .spread = 0, .same_count = true, .info = false, .fast_only = true });
    try testing.expectEqual(@as(f64, 0.8), s.worst_ref);
    try testing.expectEqual(@as(f64, 0.8), s.best_ref);
    try testing.expectEqual(@as(?f64, 1.21), s.worst_fast);
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
    // The batch doubled until it took over 100 ms: a trivial op ran far more
    // often than the 6 calls of a batch that never doubled.
    try testing.expect(c.calls > 100_000);
}

// ── sweep GK (2026-10-29) ────────────────────────────────────────────────────

test "cyclesSince never underflows when the counter read failed (sweep TK-8)" {
    try testing.expectEqual(@as(u64, 7), cyclesSince(10, 3));
    try testing.expectEqual(@as(u64, 0), cyclesSince(0, 5));
}

test "roundsOf: zero rounds means one (sweep TK-8)" {
    try testing.expectEqual(@as(usize, 1), roundsOf(.{ .name = "b", .exes = &.{}, .abs = "/", .rounds = 0 }));
    try testing.expectEqual(@as(usize, 3), roundsOf(.{ .name = "b", .exes = &.{}, .abs = "/", .rounds = 3 }));
}

test "exeAt: an index past Run.exes is a checked panic (sweep TK-8)" {
    const child = @import("testkit").child;
    if (!child.supported) return error.SkipZigTest;
    const S = struct {
        fn over() u8 {
            const r: Run = .{ .name = "b", .exes = &.{"/bin/true"}, .abs = "/" };
            std.mem.doNotOptimizeAway(exeAt(r, 1).len);
            return 0;
        }
    };
    const out = try child.run(S.over, .{}, .{ .limit_ms = 5000 });
    try testing.expect(out.eql(.{ .signaled = @backingInt(std.os.linux.SIG.ABRT) }));
    const r: Run = .{ .name = "b", .exes = &.{"/bin/true"}, .abs = "/" };
    try testing.expectEqualStrings("/bin/true", exeAt(r, 0));
}

test "foreign output past capture_limit fails the run instead of filling memory (sweep TK-8)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // 17 MiB of zeros on stdout from `head`; no network, no temp files.
    const r = foreignArgv(arena_state.allocator(), testing.io, "bench-test", &.{ "/usr/bin/head", "-c", "17825792", "/dev/zero" }, "x", null);
    if (r) |_| return error.TestUnexpectedResult else |e| switch (e) {
        error.StreamTooLong => {},
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    }
}

test "parseForeign: nan, inf and non-positive times are BadForeignOutput (review R-TK-3)" {
    for ([_][]const u8{ "x\tnan\t5\t1", "x\tinf\t5\t1", "x\t-1\t5\t1", "x\t0\t5\t1", "x\t3\tnan\t1", "x\t3\t-2\t1", "x\t3\tinf\t1", "x\tnan\t1" }) |line| {
        try testing.expectError(error.BadForeignOutput, parseForeign(line, "x"));
    }
    try testing.expectEqual(Row{ .ns = 3, .cycles = 0, .count = 1 }, try parseForeign("x\t3\t0\t1", "x"));
}

test "runCapped: output past capture_limit and a child past the timeout both fail (review R-TK-2)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const quick: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(300), .clock = .awake } };
    // stderr past the limit (the stdout cap is the sweep TK-8 test above).
    const e1 = runCapped(a, testing.io, &.{ "/bin/sh", "-c", "head -c 17825792 /dev/zero >&2" }, null, .inherit, run_timeout);
    if (e1) |_| return error.TestUnexpectedResult else |e| switch (e) {
        error.StreamTooLong => {},
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    }
    const e2 = runCapped(a, testing.io, &.{ "/bin/sleep", "20" }, null, .inherit, quick);
    if (e2) |_| return error.TestUnexpectedResult else |e| switch (e) {
        error.Timeout => {},
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    }
}

// ── mutation run (2026-11-14, benchkit as a module of its own) ───────────────
//
// Foreign programs are small `/bin/sh` scripts written into a temp dir: they
// print the rows a real bench program would, and log each call, so the order
// and the routing of `drive`'s foreign runs can be asserted.

const Tmp = struct {
    t: testing.TmpDir,
    /// Absolute, symlink-free path of the directory.
    abs: []const u8,

    fn init(a: std.mem.Allocator) !Tmp {
        var t = testing.tmpDir(.{});
        errdefer t.cleanup();
        return .{ .t = t, .abs = try t.dir.realPathFileAlloc(testing.io, ".", a) };
    }
    fn script(x: Tmp, a: std.mem.Allocator, name: []const u8, body: []const u8) !void {
        const data = try a.print("#!/bin/sh\n{s}\n", .{body});
        try x.t.dir.writeFile(testing.io, .{ .sub_path = name, .data = data, .flags = .{ .permissions = .executable_file } });
    }
    fn path(x: Tmp, a: std.mem.Allocator, name: []const u8) ![]const u8 {
        return a.print("{s}/{s}", .{ x.abs, name });
    }
    fn read(x: Tmp, a: std.mem.Allocator, name: []const u8) ![]u8 {
        return x.t.dir.readFileAlloc(testing.io, name, a, .limited(1 << 20));
    }
};

fn noSuchFile(e: anyerror) !void {
    // A missing /bin/sh (no such system) is a skip, not a pass.
    if (e == error.FileNotFound) return error.SkipZigTest;
    return e;
}

fn contains(hay: []const u8, needle: []const u8) bool {
    return std.mem.find(u8, hay, needle) != null;
}

test "score: a reference side without a counter turns the line to wall time; has_alt and info are carried" {
    const ours = side(&.{.{ .ns = 50, .cycles = 100, .count = 1 }});
    const ref_no = side(&.{.{ .ns = 100, .cycles = 0, .count = 1 }});
    const ref = side(&.{.{ .ns = 100, .cycles = 400, .count = 1 }});
    const slow_alt = side(&.{.{ .ns = 400, .cycles = 900, .count = 1 }});
    try testing.expect(!score(ours, ref_no, null, false).by_cycles);
    try testing.expectEqual(@as(f64, 0.5), score(ours, ref_no, null, false).ref);
    // Fastest = the faster of ref and alt: an alt slower than the reference changes nothing.
    const l = score(ours, ref, slow_alt, false);
    try testing.expectEqual(@as(f64, 0.25), l.ref);
    try testing.expectEqual(@as(f64, 0.25), l.fast);
    try testing.expect(l.has_alt and !l.info);
    const m = score(ours, ref, null, true);
    try testing.expect(!m.has_alt and m.info);
    try testing.expect(!m.fast_only);
}

test "Summary: the worst, best and spread are maxima/minima, not the last line; a mismatch sticks" {
    var s: Summary = .{};
    s.add(.{ .by_cycles = true, .ref = 2.0, .fast = 3.0, .has_alt = true, .spread = 0.04, .same_count = false, .info = false });
    s.add(.{ .by_cycles = true, .ref = 1.5, .fast = 1.2, .has_alt = true, .spread = 0.01, .same_count = true, .info = false });
    s.add(.{ .by_cycles = true, .ref = 1.1, .fast = 4.0, .has_alt = false, .spread = 0, .same_count = true, .info = false, .fast_only = true });
    s.add(.{ .by_cycles = true, .ref = 7.0, .fast = 8.0, .has_alt = false, .spread = 0, .same_count = true, .info = true, .fast_only = true });
    s.add(.{ .by_cycles = true, .ref = 1.0, .fast = 1.0, .has_alt = true, .spread = 0, .same_count = true, .info = false, .fast_only = true });
    try testing.expectEqual(@as(f64, 2.0), s.worst_ref);
    try testing.expectEqual(@as(f64, 1.5), s.best_ref);
    try testing.expectEqual(@as(?f64, 4.0), s.worst_fast);
    try testing.expectEqual(@as(f64, 0.04), s.max_spread);
    try testing.expect(s.by_cycles);
    try testing.expect(s.mismatch);
}

test "timeIt: doubles until a batch takes over 100 ms, then the best of five, per op (scripted clock and counter)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const Clock = struct {
        script: []const i96,
        i: usize = 0,
        fn now(ud: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const c: *@This() = @ptrCast(@alignCast(ud.?));
            const v = c.script[c.i];
            c.i += 1;
            return .{ .nanoseconds = v };
        }
    };
    const vt: std.Io.VTable = comptime blk: {
        var v = std.Io.failing.vtable.*;
        v.now = Clock.now;
        break :blk v;
    };
    const ms = 1_000_000;
    // Doubling: a batch of exactly 100 ms is not over 100 ms (n 1 -> 2), then
    // 100 ms + 1 ns ends it at n = 2. Five batches of 40, 30, 50, 35, 45 ms.
    var clock: Clock = .{ .script = &.{
        0, 100 * ms, 0, 100 * ms + 1,
        0, 40 * ms,  0, 30 * ms,
        0, 50 * ms,  0, 35 * ms,
        0, 45 * ms,
    } };
    const io: std.Io = .{ .userdata = &clock, .vtable = &vt };
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    // Counter reads, two per batch: deltas 400, 300, 500, 350, 450.
    const reads = [_]u64{ 1000, 1400, 2000, 2300, 3000, 3500, 4000, 4350, 5000, 5450 };
    const Ctx = struct {
        calls: usize = 0,
        fn once(c: *@This()) u64 {
            c.calls += 1;
            return 42;
        }
    };
    var c: Ctx = .{};
    _ = linux.write(fds[1], @ptrCast(&reads), @sizeOf(@TypeOf(reads)));
    const r = timeIt(io, .{ .fd = fds[0] }, Ctx.once, .{&c}, false);
    try testing.expectEqual(@as(usize, 1 + 2 + 5 * 2), c.calls);
    try testing.expectEqual(@as(u64, 42), r.count);
    try testing.expectEqual(@as(f64, 15 * ms), r.ns); // 30 ms best batch / 2
    try testing.expectEqual(@as(f64, 150), r.cycles); // 300 best delta / 2
    // wall_only reports no cycles, and a null counter reads 0.
    clock.i = 0;
    c = .{};
    _ = linux.write(fds[1], @ptrCast(&reads), @sizeOf(@TypeOf(reads)));
    const w = timeIt(io, .{ .fd = fds[0] }, Ctx.once, .{&c}, true);
    try testing.expectEqual(@as(f64, 0), w.cycles);
    try testing.expectEqual(@as(f64, 15 * ms), w.ns);
    clock.i = 0;
    const z = timeIt(io, .{ .fd = null }, Ctx.once, .{&c}, false);
    try testing.expectEqual(@as(f64, 0), z.cycles);
}

test "Cycles: read returns what the counter holds, close releases the descriptor, a null one reads 0" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    try testing.expectEqual(@as(u64, 0), (Cycles{ .fd = null }).read());
    (Cycles{ .fd = null }).close(); // nothing to release
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    defer _ = linux.close(fds[1]);
    const v: u64 = 0x0123_4567_89ab_cdef;
    _ = linux.write(fds[1], @ptrCast(&v), @sizeOf(u64));
    const c: Cycles = .{ .fd = fds[0] };
    try testing.expectEqual(v, c.read());
    c.close();
    var b: [1]u8 = undefined;
    try testing.expectEqual(linux.E.BADF, linux.errno(linux.read(fds[0], &b, 1)));
}

test "Cycles.open: a usable user-mode cycle counter where perf is permitted" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const c: Cycles = .open();
    defer c.close();
    if (c.fd == null) return error.SkipZigTest; // no perf_event_open here
    const a = c.read();
    var x: u64 = 1;
    for (0..2_000_000) |i| {
        x = x *% 6364136223846793005 +% i;
        std.mem.doNotOptimizeAway(x);
    }
    try testing.expect(c.read() > a);
}

test "Cycles.open: the counter counts cycles (not instructions) in user mode only" {
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .linux) return error.SkipZigTest;
    const c: Cycles = .open();
    defer c.close();
    if (c.fd == null) return error.SkipZigTest;
    // `pause` is one instruction of at least ten cycles: a loop of them gets
    // several cycles per instruction (an instruction counter would get ~3).
    const n = 200_000;
    var a = c.read();
    for (0..n) |_| asm volatile ("pause");
    var d = c.read() - a;
    try testing.expect(d > 5 * n);
    // Kernel time is not counted: 64 MiB zeroed by the kernel is millions of
    // cycles in `read`, and almost none in this process.
    const zero = std.os.linux.open("/dev/zero", .{ .ACCMODE = .RDONLY }, 0);
    if (std.os.linux.errno(zero) != .SUCCESS) return error.SkipZigTest;
    defer _ = std.os.linux.close(@intCast(zero));
    var buf: [1 << 20]u8 = undefined;
    a = c.read();
    for (0..64) |_| _ = std.os.linux.read(@intCast(zero), &buf, buf.len);
    d = c.read() - a;
    try testing.expect(d < 2_000_000);
}

test "runCapped: argv, environment and working directory reach the child; the cap is exact" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    var env = std.process.Environ.Map.init(a);
    try env.put("BENCHKIT_T", "kept");
    const r = runCapped(a, testing.io, &.{ "/bin/sh", "-c", "printf '%s|%s' \"$BENCHKIT_T\" \"$(pwd -P)\"" }, &env, .{ .path = tmp.abs }, run_timeout) catch |e| return noSuchFile(e);
    try testing.expectEqualStrings(try a.print("kept|{s}", .{tmp.abs}), r.stdout);
    // Exactly `capture_limit` bytes pass on either stream, one more does not.
    const lim = @backingInt(capture_limit);
    const ok_out = try a.print("head -c {d} /dev/zero", .{lim});
    const ok = try runCapped(a, testing.io, &.{ "/bin/sh", "-c", ok_out }, null, .inherit, run_timeout);
    try testing.expectEqual(lim, ok.stdout.len);
    const ok_err = try a.print("head -c {d} /dev/zero >&2", .{lim});
    const ok2 = try runCapped(a, testing.io, &.{ "/bin/sh", "-c", ok_err }, null, .inherit, run_timeout);
    try testing.expectEqual(lim, ok2.stderr.len);
    const over = try a.print("head -c {d} /dev/zero", .{lim + 1});
    try testing.expectError(error.StreamTooLong, runCapped(a, testing.io, &.{ "/bin/sh", "-c", over }, null, .inherit, run_timeout));
}

test "foreign: <exe> <dir> <name>, the row from stdout, the banner from stderr; a bad exit fails" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    try tmp.script(a, "ok", "printf '%s\\t12.5\\t40\\t7\\n' \"$2\"; echo \"dir=$1\" >&2");
    try tmp.script(a, "bad", "printf '%s\\t1\\t2\\t3\\n' \"$2\"; exit 3");
    try tmp.script(a, "sig", "printf '%s\\t1\\t2\\t3\\n' \"$2\"; kill -KILL $$");
    try tmp.script(a, "wrong", "printf 'other\\t1\\t2\\t3\\n'");
    var banner: []const u8 = "";
    const r = foreign(a, testing.io, "bench-test", try tmp.path(a, "ok"), "/some/dir", "w", &banner) catch |e| return noSuchFile(e);
    try testing.expectEqual(Row{ .ns = 12.5, .cycles = 40, .count = 7 }, r);
    try testing.expectEqualStrings("dir=/some/dir\n", banner);
    // No banner wanted: still parses.
    try testing.expectEqual(r, try foreign(a, testing.io, "bench-test", try tmp.path(a, "ok"), "/d", "w", null));
    // A banner is kept only from a run that succeeded.
    banner = "unset";
    try testing.expectError(error.ForeignFailed, foreign(a, testing.io, "bench-test", try tmp.path(a, "bad"), "/d", "w", &banner));
    try testing.expectError(error.ForeignFailed, foreign(a, testing.io, "bench-test", try tmp.path(a, "sig"), "/d", "w", &banner));
    try testing.expectEqualStrings("unset", banner);
    try testing.expectError(error.BadForeignOutput, foreign(a, testing.io, "bench-test", try tmp.path(a, "wrong"), "/d", "w", null));
}

test "foreignOnce: <exe> <dir> <mode>; a bad exit or a signal fails" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    try tmp.script(a, "once", "case \"$2\" in ok) echo \"$1|$2\" > \"$1/ran.txt\";; sig) kill -KILL $$;; *) echo oops >&2; exit 3;; esac");
    const exe = try tmp.path(a, "once");
    foreignOnce(a, testing.io, "bench-test", exe, tmp.abs, "ok") catch |e| return noSuchFile(e);
    try testing.expectEqualStrings(try a.print("{s}|ok\n", .{tmp.abs}), try tmp.read(a, "ran.txt"));
    try testing.expectError(error.ForeignFailed, foreignOnce(a, testing.io, "bench-test", exe, "/d", "fail"));
    try testing.expectError(error.ForeignFailed, foreignOnce(a, testing.io, "bench-test", exe, "/d", "sig"));
}

test "buildForeign: the compiler command line is cc, -O3 -march=native, src, libs, -o exe" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    const cc_body = try a.print("echo \"$*\" > {s}/args.txt", .{tmp.abs});
    const exe = buildForeign(a, testing.io, "bench-test", &.{ "/bin/sh", "-c", cc_body, "cc" }, tmp.abs, "f.c", &.{ "liba.so", "libb.so" }) catch |e| return noSuchFile(e);
    try testing.expectEqualStrings(try a.print("{s}/foreign_bench", .{tmp.abs}), exe);
    try testing.expectEqualStrings(try a.print("-O3 -march=native f.c liba.so libb.so -o {s}/foreign_bench\n", .{tmp.abs}), try tmp.read(a, "args.txt"));
    // No libs: nothing between the source and -o.
    _ = try buildForeign(a, testing.io, "bench-test", &.{ "/bin/sh", "-c", cc_body, "cc" }, tmp.abs, "g.c", &.{});
    try testing.expectEqualStrings(try a.print("-O3 -march=native g.c -o {s}/foreign_bench\n", .{tmp.abs}), try tmp.read(a, "args.txt"));
    try testing.expectError(error.ForeignBuildFailed, buildForeign(a, testing.io, "bench-test", &.{ "/bin/sh", "-c", "exit 3", "cc" }, tmp.abs, "f.c", &.{}));
    try testing.expectError(error.ForeignBuildFailed, buildForeign(a, testing.io, "bench-test", &.{ "/bin/sh", "-c", "kill -KILL $$", "cc" }, tmp.abs, "f.c", &.{}));
    // A compiler that cannot be run at all is the spawn error, not a silent pass.
    try testing.expectError(error.FileNotFound, buildForeign(a, testing.io, "bench-test", &.{"/nonexistent/cc"}, tmp.abs, "f.c", &.{}));
}

test "goBuild: offline environment over the caller's, build arguments and working directory; failures are GoBuildFailed" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    // `/bin/sh build -o <exe> .` in `dir` runs the file `build` there.
    try tmp.script(a, "build", "echo \"$GOTOOLCHAIN|$GOPROXY|$GOFLAGS|$KEEP|$*|$(pwd -P)\" > got.txt");
    var env = std.process.Environ.Map.init(a);
    try env.put("KEEP", "1");
    try env.put("GOPROXY", "on");
    try env.put("GOFLAGS", "-x");
    try env.put("GOTOOLCHAIN", "auto");
    const exe = goBuild(a, testing.io, "bench-test", &env, .{ .exe = "/bin/sh", .dir = tmp.abs, .abs = "/work/abs" }) catch |e| return noSuchFile(e);
    try testing.expectEqualStrings("/work/abs/go_bench", exe);
    try testing.expectEqualStrings(try a.print("local|off|-mod=readonly|1|-o /work/abs/go_bench .|{s}\n", .{tmp.abs}), try tmp.read(a, "got.txt"));
    // The caller's map is left as it was.
    try testing.expectEqualStrings("on", env.get("GOPROXY").?);
    const exe2 = try goBuild(a, testing.io, "bench-test", &env, .{ .exe = "/bin/sh", .dir = tmp.abs, .abs = "/w2", .out = "second", .toolchain = "go1.99.0" });
    try testing.expectEqualStrings("/w2/second", exe2);
    try testing.expectEqualStrings(try a.print("go1.99.0|off|-mod=readonly|1|-o /w2/second .|{s}\n", .{tmp.abs}), try tmp.read(a, "got.txt"));
    try tmp.script(a, "build", "exit 3");
    const opts: GoBuild = .{ .exe = "/bin/sh", .dir = tmp.abs, .abs = "/w" };
    try testing.expectError(error.GoBuildFailed, goBuild(a, testing.io, "bench-test", &env, opts));
    try tmp.script(a, "build", "kill -KILL $$");
    try testing.expectError(error.GoBuildFailed, goBuild(a, testing.io, "bench-test", &env, opts));
    // `go` itself missing: also GoBuildFailed, with its own message.
    try testing.expectError(error.GoBuildFailed, goBuild(a, testing.io, "bench-test", &env, .{ .exe = "/nonexistent/go", .dir = tmp.abs, .abs = "/w" }));
}

test "exeAt: the panic is benchkit's own message, not a bounds check (the index == len edge)" {
    const child = @import("testkit").child;
    if (!child.supported) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    const err_path = try a.dupeSentinel(u8, try tmp.path(a, "err.txt"), 0);
    const S = struct {
        fn over(path: [:0]const u8, i: usize) u8 {
            const fd = std.os.linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
            if (std.os.linux.errno(fd) != .SUCCESS) return 2;
            _ = std.os.linux.dup2(@intCast(fd), 2);
            const r: Run = .{ .name = "b", .exes = &.{ "/bin/true", "/bin/false" }, .abs = "/" };
            std.mem.doNotOptimizeAway(exeAt(r, i).len);
            return 0;
        }
    };
    // i == len and i > len: both are benchkit's message; i < len is fine.
    for ([_]usize{ 2, 5 }) |i| {
        const out = try child.run(S.over, .{ err_path, i }, .{ .limit_ms = 5000, .show_stderr = true });
        try testing.expect(out.eql(.{ .signaled = @backingInt(std.os.linux.SIG.ABRT) }));
        const msg = try tmp.read(a, "err.txt");
        try testing.expect(contains(msg, "benchkit: Work.ref_exe/alt_exe indexes past Run.exes"));
    }
    const out = try child.run(S.over, .{ err_path, 1 }, .{ .limit_ms = 5000, .show_stderr = true });
    try testing.expect(out.eql(.{ .exited = 0 }));
}

/// The two foreign programs of the `drive` tests: A (index 0) and B (index 1).
/// Every call is logged to `log.txt` as `<exe> <workload>`.
fn driveScripts(a: std.mem.Allocator, tmp: Tmp) ![]const []const u8 {
    try tmp.script(a, "A",
        \\echo "A $2" >> "$1/log.txt"
        \\case "$2" in o*) echo banner-O >&2;; *) echo banner-A >&2;; esac
        \\case "$2" in
        \\  r1) printf 'r1\t200\t400\t5\n';;
        \\  o1) printf 'o1\t100\t100\t5\n';;
        \\  r2) printf 'r2\t50\t100\t5\n';;
        \\  o2) printf 'o2\t60\t200\t5\n';;
        \\  r3) printf 'r3\t50\t100\t5\n';;
        \\  o3) printf 'o3\t60\t900\t5\n';;
        \\  r4) printf 'r4\t50\t100\t5\n';;
        \\  o4) printf 'o4\t60\t150\t5\n';;
        \\esac
    );
    try tmp.script(a, "B",
        \\echo "B $2" >> "$1/log.txt"
        \\echo banner-B >&2
        \\printf 'a1\t150\t300\t5\n'
    );
    const exes = try a.alloc([]const u8, 2);
    exes[0] = try tmp.path(a, "A");
    exes[1] = try tmp.path(a, "B");
    return exes;
}

const DCtx = struct {
    op: u32 = 0,
    fn once(c: *DCtx) u64 {
        return c.op;
    }
};

test "drive: sides alternate per round, each workload goes to its own program, the verdict leaves info and fast_only lines out" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    const exes = try driveScripts(a, tmp);
    const W = Work(u32);
    const ws = [_]W{
        .{ .name = "w1", .op = 1, .ref = "r1", .alt = "a1", .ref_exe = 0, .alt_exe = 1, .ours_foreign = "o1" },
        .{ .name = "w2", .op = 2, .ref = "r2", .ours_foreign = "o2" },
        .{ .name = "w3", .op = 3, .ref = "r3", .ours_foreign = "o3", .info = true },
        .{ .name = "w4", .op = 4, .ref = "r4", .ours_foreign = "o4", .fast_only = true },
    };
    var ctx: DCtx = .{};
    var aw: std.Io.Writer.Allocating = .init(a);
    const s = drive(testing.io, a, .{ .name = "bench-test", .exes = exes, .abs = tmp.abs, .rounds = 2 }, &ctx, DCtx.once, &ws, &aw.writer) catch |e| return noSuchFile(e);
    try testing.expectEqualStrings(
        "A r1\nA o1\nB a1\nA r1\nA o1\nB a1\n" ++ "A r2\nA o2\nA r2\nA o2\n" ++ "A r3\nA o3\nA r3\nA o3\n" ++ "A r4\nA o4\nA r4\nA o4\n",
        try tmp.read(a, "log.txt"),
    );
    // w1: 100/400 and 100/min(400, 300); w2: 200/100; w3 is info; w4: 150/100 for fastest only.
    try testing.expectEqual(@as(f64, 0.25), s.best_ref);
    try testing.expectEqual(@as(f64, 2.0), s.worst_ref);
    try testing.expectEqual(@as(?f64, 1.5), s.worst_fast);
    try testing.expectEqual(@as(f64, 0), s.max_spread);
    try testing.expect(s.by_cycles and !s.mismatch);
    // The reference's banner, not the one from our side run through the same program.
    try testing.expectEqualStrings("banner-A\n", s.banner);
    try testing.expectEqualStrings("banner-B\n", s.alt_banner);
    const out = aw.written();
    try testing.expect(contains(out, "rounds: 2; ratios by user-mode cycles; largest spread 0.0%\n"));
    try testing.expect(!contains(out, "OVER 5 %"));
    for ([_][]const u8{ "w1", "w2", "w3", "w4" }) |n| try testing.expect(contains(out, n));
}

test "drive: filters pick workloads, zero rounds run once, the work-less side is not asked" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    const exes = try driveScripts(a, tmp);
    const W = Work(u32);
    const ws = [_]W{
        .{ .name = "w1", .op = 1, .ref = "r1", .alt = "a1", .ref_exe = 0, .alt_exe = 1, .ours_foreign = "o1" },
        .{ .name = "w2", .op = 2, .ref = "r2", .ours_foreign = "o2" },
    };
    var ctx: DCtx = .{};
    var aw: std.Io.Writer.Allocating = .init(a);
    const s = drive(testing.io, a, .{ .name = "bench-test", .exes = exes, .abs = tmp.abs, .filters = &.{"w2"}, .rounds = 0 }, &ctx, DCtx.once, &ws, &aw.writer) catch |e| return noSuchFile(e);
    try testing.expectEqualStrings("A r2\nA o2\n", try tmp.read(a, "log.txt"));
    try testing.expectEqual(@as(f64, 2.0), s.best_ref);
    try testing.expectEqual(@as(f64, 2.0), s.worst_ref);
    try testing.expectEqual(@as(?f64, null), s.worst_fast);
    try testing.expect(contains(aw.written(), "rounds: 1;"));
    try testing.expect(!contains(aw.written(), "w1"));
}

test "drive: a differing output count on either side fails the run" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    try tmp.script(a, "R", "case \"$2\" in r) printf 'r\\t10\\t10\\t5\\n';; o) printf 'o\\t10\\t10\\t5\\n';; a) printf 'a\\t10\\t10\\t5\\n';; esac");
    try tmp.script(a, "Rours6", "case \"$2\" in r) printf 'r\\t10\\t10\\t5\\n';; o) printf 'o\\t10\\t10\\t6\\n';; esac");
    try tmp.script(a, "Ralt6", "case \"$2\" in r) printf 'r\\t10\\t10\\t5\\n';; o) printf 'o\\t10\\t10\\t5\\n';; a) printf 'a\\t10\\t10\\t6\\n';; esac");
    const W = Work(u32);
    var ctx: DCtx = .{};
    var aw: std.Io.Writer.Allocating = .init(a);
    const none: Work(u32) = .{ .name = "w", .op = 1, .ref = "r", .ours_foreign = "o" };
    const with_alt: Work(u32) = .{ .name = "w", .op = 1, .ref = "r", .alt = "a", .ours_foreign = "o" };
    const run: Run = .{ .name = "bench-test", .exes = &.{ try tmp.path(a, "R"), try tmp.path(a, "Rours6"), try tmp.path(a, "Ralt6") }, .abs = tmp.abs, .rounds = 1 };
    _ = drive(testing.io, a, run, &ctx, DCtx.once, &[_]W{none}, &aw.writer) catch |e| return noSuchFile(e);
    var r1 = run;
    r1.exes = &.{run.exes[1]};
    try testing.expectError(error.CountMismatch, drive(testing.io, a, r1, &ctx, DCtx.once, &[_]W{none}, &aw.writer));
    var r2 = run;
    r2.exes = &.{run.exes[2]};
    try testing.expectError(error.CountMismatch, drive(testing.io, a, r2, &ctx, DCtx.once, &[_]W{with_alt}, &aw.writer));
    // The same count on every side passes with an alt, too.
    _ = try drive(testing.io, a, .{ .name = "bench-test", .exes = &.{run.exes[0]}, .abs = tmp.abs, .rounds = 1 }, &ctx, DCtx.once, &[_]W{with_alt}, &aw.writer);
}

test "drive: a noisy side is flagged, and a side without a counter turns the verdict to wall time" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    // Every call bumps a counter; the reference is slower each time it runs
    // (three fields: no cycle counter), ours is steady.
    try tmp.script(a, "N",
        \\n=0; [ -f "$1/n" ] && n=$(cat "$1/n"); n=$((n+1)); echo $n > "$1/n"
        \\case "$2" in
        \\  r) printf 'r\t%s\t5\n' $((100+n*20));;
        \\  o) printf 'o\t100\t100\t5\n';;
        \\esac
    );
    const W = Work(u32);
    const ws = [_]W{.{ .name = "w", .op = 1, .ref = "r", .ours_foreign = "o" }};
    var ctx: DCtx = .{};
    var aw: std.Io.Writer.Allocating = .init(a);
    const s = drive(testing.io, a, .{ .name = "bench-test", .exes = &.{try tmp.path(a, "N")}, .abs = tmp.abs, .rounds = 2 }, &ctx, DCtx.once, &ws, &aw.writer) catch |e| return noSuchFile(e);
    // Ref ran as calls 1 and 3: 120 and 160 ns.
    try testing.expectApproxEqAbs(@as(f64, 160.0 / 120.0 - 1), s.max_spread, 1e-12);
    try testing.expect(!s.by_cycles);
    try testing.expectApproxEqAbs(@as(f64, 100.0 / 120.0), s.best_ref, 1e-12);
    try testing.expect(contains(aw.written(), "ratios by wall time; largest spread 33.3% (OVER 5 %: noisy run, repeat)\n"));
}

test "drive: the in-process side sees each workload's op; wall_only drops its cycles; no descriptor is left open" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = try Tmp.init(a);
    defer tmp.t.cleanup();
    try tmp.script(a, "A", "printf '%s\\t100\\t100\\t7\\n' \"$2\"");
    const W = Work(u32);
    var ctx: DCtx = .{};
    var aw: std.Io.Writer.Allocating = .init(a);
    const run: Run = .{ .name = "bench-test", .exes = &.{try tmp.path(a, "A")}, .abs = tmp.abs, .rounds = 1 };
    // The first process run may open a descriptor of the Io's own; count after it.
    _ = drive(testing.io, a, run, &ctx, DCtx.once, &[_]W{.{ .name = "w", .op = 7, .ref = "r", .ours_foreign = "r" }}, &aw.writer) catch |e| return noSuchFile(e);
    const before = openFds();
    // The op (7) is the count `once` returns; the reference says 7.
    const s = try drive(testing.io, a, run, &ctx, DCtx.once, &[_]W{.{ .name = "w", .op = 7, .ref = "r" }}, &aw.writer);
    try testing.expectEqual(before, openFds());
    try testing.expect(!s.mismatch);
    // With a counter (and a reference that has one) the verdict is by cycles.
    const probe: Cycles = .open();
    defer probe.close();
    try testing.expectEqual(probe.fd != null, s.by_cycles);
    const w = try drive(testing.io, a, run, &ctx, DCtx.once, &[_]W{.{ .name = "w", .op = 7, .ref = "r", .wall_only = true }}, &aw.writer);
    try testing.expect(!w.by_cycles);
}

fn openFds() usize {
    var n: usize = 0;
    for (0..512) |fd| {
        if (std.os.linux.errno(std.os.linux.fcntl(@intCast(fd), std.os.linux.F.GETFD, 0)) == .SUCCESS) n += 1;
    }
    return n;
}
