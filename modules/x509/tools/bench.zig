// SPDX-License-Identifier: MIT

//! Comparative benchmark: `x509` against Go's `crypto/x509` (the reference;
//! Go 1.26 standard library only), the program behind the `**Performance:**`
//! line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-x509` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (`GOTOOLCHAIN=go1.26.0`, `GOPROXY=off`; stdlib only, `tools/go_bench`) and
//! no C compiler. Run from the repository root.
//!
//! The Go side generates three chains into `.zig-cache/bench-x509/` (fresh
//! keys each run; ten-year certificates, SAN `bench.example.test`, serverAuth):
//! `ecdsa256` (ECDSA P-256 root, intermediate and leaf), `rsa2048` (RSA-2048
//! PKCS#1 v1.5 throughout) and `mixed` (a P-256 leaf under RSA-2048 CAs, the
//! common public-web shape). This program reads them back.
//!
//! Workloads: `verify_<kind>` = what a TLS client does with the `[leaf,
//! intermediate]` list it received and its trust store: ours
//! `verifyChain(gpa, &.{leaf, inter}, &.{root}, .{ .now_sec, .expected_host,
//! .required_eku = .server_auth })` (parses all three certificates, builds
//! and checks the path, verifies both signatures, checks hostname and EKU);
//! Go's `ParseCertificate` of leaf and intermediate, a fresh intermediates
//! pool, and `Certificate.Verify` against a root pool built once with the same
//! hostname and EKU requirements. Ours re-parses the trust anchor on every
//! call (its API takes DER) where Go's pool holds a parsed root: that favours
//! Go by one certificate parse. The count is the verified path length from
//! leaf to root (3) on both sides.
//!
//! Method (shared driver at the bottom): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Go has
//! no cycle counter here, so ratios are by wall time. Before timing anything
//! each chain must verify with the right host and be refused for a wrong one.
//! Arguments filter workloads by substring (no card line then).

const std = @import("std");
const x509 = @import("x509");

const bench_name = "bench-x509";
const work_dir = ".zig-cache/bench-x509";
const go_dir = "modules/x509/tools/go_bench";
const host = "bench.example.test";
const kinds = [_][]const u8{ "ecdsa256", "rsa2048", "mixed" };

const Op = struct { kind: usize };

const Ctx = struct {
    gpa: std.mem.Allocator,
    certs: [kinds.len][3][]u8, // leaf, inter, root
    now: i64,
    op: Op = undefined,
};

fn once(x: *Ctx) usize {
    const c = &x.certs[x.op.kind];
    const chain = [_]x509.chain.CertDer{ c[0], c[1] };
    const anchors = [_]x509.chain.CertDer{c[2]};
    const v = x509.verifyChain(x.gpa, &chain, &anchors, .{
        .now_sec = x.now,
        .expected_host = host,
        .required_eku = .server_auth,
    }) catch unreachable;
    std.mem.doNotOptimizeAway(&v);
    return v.depth + 1; // certificates up to the anchor, which is not counted in depth
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    var env = try init.environ_map.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try std.fmt.allocPrint(arena, "{s}/go_bench", .{abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    try runOk(arena, io, &env, &.{ "go", "build", "-o", exe, "." }, go_dir);
    try runOk(arena, io, &env, &.{ exe, abs, "gen" }, null);

    const ctx = try arena.create(Ctx);
    ctx.gpa = std.heap.smp_allocator;
    const now_txt = try dir.readFileAlloc(io, "now.txt", arena, .limited(64));
    ctx.now = try std.fmt.parseInt(i64, std.mem.trim(u8, now_txt, " \n"), 10);
    for (kinds, 0..) |k, i| for ([_][]const u8{ "leaf", "inter", "root" }, 0..) |n, j| {
        ctx.certs[i][j] = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "{s}_{s}.der", .{ k, n }), arena, .limited(1 << 16));
    };

    // Sanity before timing: verifies with the right host, refuses a wrong one.
    for (kinds, 0..) |k, i| {
        const c = &ctx.certs[i];
        const chain = [_]x509.chain.CertDer{ c[0], c[1] };
        const anchors = [_]x509.chain.CertDer{c[2]};
        const ok = x509.verifyChain(arena, &chain, &anchors, .{ .now_sec = ctx.now, .expected_host = host, .required_eku = .server_auth }) catch |e| {
            std.debug.print("{s}: FAILED -- our verifyChain refuses Go's {s} chain: {t}\n", .{ bench_name, k, e });
            return 1;
        };
        if (ok.depth != 2) return error.UnexpectedDepth;
        if (x509.verifyChain(arena, &chain, &anchors, .{ .now_sec = ctx.now, .expected_host = "other.example.test" })) |_| {
            std.debug.print("{s}: FAILED -- a wrong host name was accepted ({s})\n", .{ bench_name, k });
            return 1;
        } else |_| {}
    }

    var ws: std.ArrayList(Work) = .empty;
    for (kinds, 0..) |k, i| {
        const name = try std.fmt.allocPrint(arena, "verify_{s}", .{k});
        try ws.append(arena, .{ .name = name, .op = .{ .kind = i }, .ref = name });
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try drive(io, arena, &.{exe}, abs, ctx, ws.items, filters, rounds, w);
    try w.print("reference: {s}\nworst ours/Go = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go <version> crypto/x509 (chain verify) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
}

fn runOk(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, argv: []const []const u8, cwd_path: ?[]const u8) !void {
    const res = std.process.run(arena, io, .{
        .argv = argv,
        .environ_map = env,
        .cwd = if (cwd_path) |p| .{ .path = p } else .inherit,
    }) catch |e| {
        std.debug.print("{s}: could not run {s} ({t}) -- the benchmark needs Go\n", .{ bench_name, argv[0], e });
        return error.GoFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed:\n{s}\n", .{ bench_name, argv[0], res.stderr });
        return error.GoFailed;
    }
}

// ---- comparison driver (the same in every crypto module's tools/bench.zig) ----

/// One timed side: per-op wall time and user-mode cycles (0 = no counter).
const Row = struct { ns: f64, cycles: f64 = 0, count: u64 };

/// Best and worst of the rounds of one side.
const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    best_cyc: f64 = std.math.inf(f64),
    worst_cyc: f64 = 0,
    count: u64 = 0,

    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.best_cyc = @min(s.best_cyc, r.cycles);
        s.worst_cyc = @max(s.worst_cyc, r.cycles);
        s.count = r.count;
    }
    fn best(s: Side, cyc: bool) f64 {
        return if (cyc) s.best_cyc else s.best_ns;
    }
    fn spread(s: Side, cyc: bool) f64 {
        return if (cyc) s.worst_cyc / s.best_cyc - 1 else s.worst_ns / s.best_ns - 1;
    }
};

/// This thread's user-mode cycle counter (`perf stat -e cycles:u`).
const Cycles = struct {
    fd: ?i32,

    fn open() Cycles {
        if (@import("builtin").os.tag != .linux) return .{ .fd = null };
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

    fn read(c: Cycles) u64 {
        const fd = c.fd orelse return 0;
        var v: u64 = 0;
        _ = std.os.linux.read(fd, @ptrCast(&v), @sizeOf(u64));
        return v;
    }
};

fn timeIt(io: std.Io, cyc: Cycles, x: *Ctx) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(x));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var best_cycles: u64 = std.math.maxInt(u64);
    var count: usize = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        const c0 = cyc.read();
        for (0..n) |_| count = once(x);
        best_cycles = @min(best_cycles, cyc.read() - c0);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    const nf: f64 = @floatFromInt(n);
    return .{ .ns = @as(f64, @floatFromInt(best)) / nf, .cycles = @as(f64, @floatFromInt(best_cycles)) / nf, .count = count };
}

/// Run the foreign program for one workload: `<exe> <work dir> <name>`, which
/// prints `name \t ns/op \t cycles/op \t count` and its banner on stderr.
fn foreign(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8, banner: *[]const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    banner.* = res.stderr;
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const cycles = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .cycles = cycles, .count = count };
}

/// One workload: `op` for our side, the foreign program's workload `ref`
/// (the reference) and optionally `alt` (a second implementation in the
/// field, for the `fastest` ratio); `*_exe` index the foreign programs.
const Work = struct { name: []const u8, op: Op, ref: []const u8, alt: ?[]const u8 = null, ref_exe: usize = 0, alt_exe: usize = 0 };

const Summary = struct {
    best_ref: f64 = std.math.inf(f64),
    worst_ref: f64 = 0,
    /// Worst of ours / min(ref, alt) over the workloads that have an `alt`.
    worst_fast: ?f64 = null,
    max_spread: f64 = 0,
    banner: []const u8 = "",
    alt_banner: []const u8 = "",
};

fn drive(io: std.Io, arena: std.mem.Allocator, exes: []const []const u8, abs: []const u8, ctx: *Ctx, ws: []const Work, filters: []const [:0]const u8, rounds: usize, w: *std.Io.Writer) !Summary {
    const cyc: Cycles = .open();
    var s: Summary = .{};
    var metric_cycles = true;
    var mismatch = false;
    try w.print("{s:<18} {s:>11} {s:>11} {s:>11} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}  count\n", .{ "workload", "ours ns", "ref ns", "alt ns", "/ref", "/fast", "spr us", "spr rf", "spr al" });
    try w.flush();
    for (ws) |x| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, x.name, f) != null;
            if (!hit) continue;
        }
        ctx.op = x.op;
        var ours: Side = .{};
        var ref: Side = .{};
        var alt: Side = .{};
        // The sides alternate, `rounds` times, each keeping its best: timed one
        // after the other they would see different loads of a shared machine.
        for (0..rounds) |_| {
            ref.add(try foreign(arena, io, exes[x.ref_exe], abs, x.ref, &s.banner));
            ours.add(timeIt(io, cyc, ctx));
            if (x.alt) |a| alt.add(try foreign(arena, io, exes[x.alt_exe], abs, a, &s.alt_banner));
        }
        const by_cyc = ours.best_cyc > 0 and ref.best_cyc > 0 and (x.alt == null or alt.best_cyc > 0);
        metric_cycles = metric_cycles and by_cyc;
        const r_ref = ours.best(by_cyc) / ref.best(by_cyc);
        s.worst_ref = @max(s.worst_ref, r_ref);
        s.best_ref = @min(s.best_ref, r_ref);
        var r_fast: f64 = r_ref;
        if (x.alt != null) {
            r_fast = ours.best(by_cyc) / @min(ref.best(by_cyc), alt.best(by_cyc));
            s.worst_fast = @max(s.worst_fast orelse 0, r_fast);
        }
        const spr_alt = if (x.alt != null) alt.spread(by_cyc) else 0;
        s.max_spread = @max(s.max_spread, @max(ours.spread(by_cyc), @max(ref.spread(by_cyc), spr_alt)));
        const same = ours.count == ref.count and (x.alt == null or ours.count == alt.count);
        mismatch = mismatch or !same;
        try w.print("{s:<18} {d:>11.0} {d:>11.0} {d:>11.0} {d:>7.3} {d:>7.3} {d:>5.1}% {d:>5.1}% {d:>5.1}%  {d}{s}\n", .{
            x.name,        ours.best_ns, ref.best_ns,               if (x.alt != null) alt.best_ns else 0,
            r_ref,         r_fast,       100 * ours.spread(by_cyc), 100 * ref.spread(by_cyc),
            100 * spr_alt, ours.count,
            if (same) "" else " ≠",
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by {s}; largest spread {d:.1}%{s}\n", .{ rounds, if (metric_cycles) "user-mode cycles" else "wall time", 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    try w.flush();
    if (mismatch) {
        std.debug.print("{s}: FAILED -- an output size differs between the sides\n", .{bench_name});
        return error.CountMismatch;
    }
    return s;
}

/// The foreign program, built from `src` with `zig cc -O3 -march=native`
/// against `libs` (shared objects named by path, so no headers are needed).
fn buildForeign(arena: std.mem.Allocator, io: std.Io, abs: []const u8, src: []const u8, libs: []const []const u8) ![]const u8 {
    const exe = try std.fmt.allocPrint(arena, "{s}/foreign_bench", .{abs});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ "zig", "cc", "-O3", "-march=native", src });
    try argv.appendSlice(arena, libs);
    try argv.appendSlice(arena, &.{ "-o", exe });
    std.debug.print("{s}: building the foreign side ({s}) ...\n", .{ bench_name, src });
    const cc = try std.process.run(arena, io, .{ .argv = argv.items });
    if (cc.term != .exited or cc.term.exited != 0) {
        std.debug.print("{s}: zig cc failed:\n{s}\n", .{ bench_name, cc.stderr });
        return error.ForeignBuildFailed;
    }
    return exe;
}

/// Run the foreign program once in a non-timing mode (`interop`, `keygen`).
fn foreignOnce(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, mode: []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, mode } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: foreign side failed in {s}:\n{s}\n", .{ bench_name, mode, res.stderr });
        return error.ForeignFailed;
    }
}
