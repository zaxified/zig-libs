// SPDX-License-Identifier: MIT

//! Comparative benchmark: `tlsclient` against Go's `crypto/tls` client (the
//! reference named by the maturity card; Go 1.26 standard library only), the
//! program behind the `**Performance:**` line of the card (CONVENTIONS.md §9,
//! kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-tlsclient` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (`GOTOOLCHAIN=go1.26.0`, `GOPROXY=off`; stdlib only, `tools/go_bench`) and
//! loopback networking. Run from the repository root.
//!
//! The API takes a `*Reader`/`*Writer` pair and the server's flight depends on
//! the client's random key share, so a handshake cannot be replayed from a
//! recording; both clients therefore talk to a real server: ONE Go
//! `crypto/tls` server process (default config, TLS 1.3, certificate chains
//! it generates at start: `ecdsa256` = ECDSA P-256 root/intermediate/leaf,
//! `rsa2048` = RSA-2048 throughout; SAN `bench.example.test`), which both
//! sides use alike over 127.0.0.1.
//!
//! Workload `handshake_<kind>` = one complete client handshake: TCP connect,
//! ClientHello (with the library's default key shares), server flight read,
//! chain verified against the root and the name `bench.example.test`, client
//! Finished written, close. Ours: `Client.init` over a std.Io.net stream with
//! the root in a `Certificate.Bundle`; theirs: `tls.Client(...).Handshake()`
//! with the root in a `CertPool`, TLS 1.3 asserted. No application data, no
//! resumption on either side.
//!
//! What is measured: the CLIENT thread's user-mode cycles per handshake (ours
//! `perf_event_open` on the calling thread, Go's the same on its pinned
//! (`LockOSThread`) goroutine thread) -- not wall time, which would be
//! dominated by the server's work and round trips that are identical for both
//! and dilute the ratio. Kernel time (socket syscalls) is excluded on both
//! sides. Go's GC and runtime threads are therefore not counted; ours
//! allocates nothing on the heap.
//!
//! ⚠ Caveats worth knowing when reading the ratio: the two clients may not
//! offer identical key-share groups (the Zig std-derived key share set versus
//! Go's default list including a hybrid ML-KEM group), and the negotiated
//! cipher suite is the server's choice (Go server prefers AES-GCM with
//! hardware support); the count is 1 per handshake.
//!
//! Method (shared driver at the bottom): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side.
//! Before timing anything a handshake with the right name must succeed and
//! one with a wrong name must fail on our side. Arguments filter workloads by
//! substring (no card line then).

const std = @import("std");
const tlsclient = @import("tlsclient");
const Client = tlsclient.Client;

const bench_name = "bench-tlsclient";
const work_dir = ".zig-cache/bench-tlsclient";
const go_dir = "modules/tlsclient/tools/go_bench";
const host = "bench.example.test";
const kinds = [_][]const u8{ "ecdsa256", "rsa2048" };

const Op = struct { kind: usize };

const Ctx = struct {
    io: std.Io,
    ports: [kinds.len]u16,
    bundles: [kinds.len]std.crypto.Certificate.Bundle,
    lock: std.Io.RwLock = .init,
    op: Op = undefined,
};

fn handshake(x: *Ctx, kind: usize, name: []const u8) !void {
    const io = x.io;
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", x.ports[kind]);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var net_in: [Client.min_buffer_len]u8 = undefined;
    var net_out: [Client.min_buffer_len]u8 = undefined;
    var tls_in: [Client.min_buffer_len]u8 = undefined;
    var tls_out: [Client.min_buffer_len]u8 = undefined;
    var sr = stream.reader(io, &net_in);
    var sw = stream.writer(io, &net_out);
    var entropy: [Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    _ = try Client.init(&sr.interface, &sw.interface, .{
        .host = .{ .explicit = name },
        .ca = .{ .bundle = .{ .gpa = std.heap.smp_allocator, .io = io, .lock = &x.lock, .bundle = &x.bundles[kind] } },
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
    });
}

fn once(x: *Ctx) usize {
    handshake(x, x.op.kind, host) catch |e| {
        std.debug.print("{s}: handshake failed: {t}\n", .{ bench_name, e });
        std.process.exit(1);
    };
    return 1;
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
    const build = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = go_dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- the benchmark needs it\n", .{ bench_name, e });
        return 1;
    };
    if (build.term != .exited or build.term.exited != 0) {
        std.debug.print("{s}: go build failed:\n{s}\n", .{ bench_name, build.stderr });
        return 1;
    }

    // The Go server, until we are done (killed on every exit path).
    var server = try std.process.spawn(io, .{
        .argv = &.{ exe, abs, "serve" },
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    defer server.kill(io);
    {
        var buf: [256]u8 = undefined;
        var r = server.stdout.?.reader(io, &buf);
        const line = (try r.interface.takeDelimiter('\n')) orelse {
            std.debug.print("{s}: the Go server exited before it was ready\n", .{bench_name});
            return 1;
        };
        if (!std.mem.eql(u8, std.mem.trim(u8, line, " \r"), "READY")) return error.BadServerBanner;
    }

    const ctx = try arena.create(Ctx);
    ctx.* = .{ .io = io, .ports = undefined, .bundles = undefined };
    const now = std.Io.Clock.real.now(io);
    for (kinds, 0..) |k, i| {
        const port_txt = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "port_{s}.txt", .{k}), arena, .limited(16));
        ctx.ports[i] = try std.fmt.parseInt(u16, std.mem.trim(u8, port_txt, " \n"), 10);
        ctx.bundles[i] = .empty;
        try ctx.bundles[i].addCertsFromFilePath(arena, io, now, dir, try std.fmt.allocPrint(arena, "root_{s}.pem", .{k}));
    }

    // Sanity before timing: the right name works, a wrong one is refused.
    for (kinds, 0..) |k, i| {
        handshake(ctx, i, host) catch |e| {
            std.debug.print("{s}: FAILED -- our client cannot handshake with the Go server ({s}): {t}\n", .{ bench_name, k, e });
            return 1;
        };
        if (handshake(ctx, i, "other.example.test")) |_| {
            std.debug.print("{s}: FAILED -- a wrong server name was accepted ({s})\n", .{ bench_name, k });
            return 1;
        } else |_| {}
    }

    var ws: std.ArrayList(Work) = .empty;
    for (kinds, 0..) |k, i| {
        const name = try std.fmt.allocPrint(arena, "handshake_{s}", .{k});
        try ws.append(arena, .{ .name = name, .op = .{ .kind = i }, .ref = name });
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try drive(io, arena, &.{exe}, abs, ctx, ws.items, filters, rounds, w);
    try w.print("reference: {s}\nworst ours/Go = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go <version> crypto/tls client (handshake, client CPU) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
    try w.flush();
    return 0;
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
