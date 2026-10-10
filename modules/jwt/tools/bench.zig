// SPDX-License-Identifier: MIT

//! Comparative benchmark: `jwt` against github.com/golang-jwt/jwt/v5 (the
//! reference: the most used JWT library of a compiled language, over Go's
//! standard-library crypto), the program behind the `**Performance:**` line
//! of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-jwt` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `go` on PATH and
//! golang-jwt v5.3.1 in the Go module cache (`go mod download
//! github.com/golang-jwt/jwt/v5@v5.3.1`; nothing is fetched by the bench:
//! GOPROXY=off, and `tools/go_bench/go.sum` pins the module). The Go side,
//! `tools/go_bench/main.go`, is copied into `.zig-cache/bench-jwt/go/` and
//! built there. Run from the repository root.
//!
//! Workloads, for HS256, ES256 and EdDSA, over the same keys on both sides
//! and a typical access token (iss, sub, aud, exp, nbf, iat, scope):
//!   <alg>_sign    `encodeJson(gpa, claims, key, .{})` (+ free) vs
//!                 `jwt.NewWithClaims(...).SignedString(key)`
//!   <alg>_verify  `parseAndVerify` with issuer, audience and expiry required
//!                 (+ deinit) vs `jwt.Parse` with the method pinned and
//!                 `WithIssuer`/`WithAudience`/`WithExpirationRequired`
//! Ours allocates from `std.heap.smp_allocator`; Go's side runs under its GC.
//! Keys and claims are written into `.zig-cache/bench-jwt/` from fixed seeds.
//!
//! Method (shared driver at the bottom): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. The Go
//! side has no cycle counter, so ratios are by wall time. Before timing
//! anything golang-jwt must accept our token for every algorithm and we must
//! accept its. Arguments filter workloads by substring.

const std = @import("std");
const jwt = @import("jwt");

const bench_name = "bench-jwt";
const work_dir = ".zig-cache/bench-jwt";
const issuer = "https://issuer.example.com";
const audience = "api.example.com";
const claims_json =
    \\{"aud":"api.example.com","exp":4102444800,"iat":1700000000,"iss":"https://issuer.example.com","nbf":1700000000,"scope":"read write","sub":"user-1234567890"}
;
const algs = [_][]const u8{ "hs256", "es256", "eddsa" };

const Op = struct { alg: usize, verify: bool };

const Ctx = struct {
    signing: [algs.len]jwt.SigningKey,
    tokens: [algs.len][]const u8,
    op: Op = undefined,
};

const opts: jwt.Options = .{ .now_s = 1_760_000_000, .issuer = .{ .required = issuer }, .audience = .{ .required = audience } };

fn once(x: *Ctx) usize {
    const gpa = std.heap.smp_allocator;
    const key = x.signing[x.op.alg];
    if (x.op.verify) {
        var parsed = jwt.parseAndVerify(gpa, x.tokens[x.op.alg], key.verificationKey(), opts) catch unreachable;
        parsed.deinit();
        return 1;
    }
    const tok = jwt.encodeJson(gpa, claims_json, key, .{}) catch unreachable;
    defer gpa.free(tok);
    return tok.len;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir ++ "/go");
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    // Keys, shared with the Go side.
    var prng = std.Random.DefaultPrng.init(0x1a7_be7c);
    const r = prng.random();
    var hmac_key: [32]u8 = undefined;
    r.bytes(&hmac_key);
    var ec_seed: [jwt.EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    r.bytes(&ec_seed);
    const ec_kp = try arena.create(jwt.EcdsaP256Sha256.KeyPair);
    ec_kp.* = try jwt.EcdsaP256Sha256.KeyPair.generateDeterministic(ec_seed);
    var ed_seed: [32]u8 = undefined;
    r.bytes(&ed_seed);
    const ed_kp = try arena.create(jwt.Ed25519.KeyPair);
    ed_kp.* = try jwt.Ed25519.KeyPair.generateDeterministic(ed_seed);
    try dir.writeFile(io, .{ .sub_path = "hs256.key", .data = &hmac_key });
    try dir.writeFile(io, .{ .sub_path = "es256.key", .data = &ec_kp.secret_key.toBytes() });
    try dir.writeFile(io, .{ .sub_path = "eddsa.seed", .data = &ed_seed });

    var ctx: Ctx = .{ .signing = .{ .{ .hs256 = &hmac_key }, .{ .es256 = ec_kp }, .{ .ed25519 = ed_kp } }, .tokens = undefined };
    for (algs, 0..) |a, i| {
        ctx.tokens[i] = try jwt.encodeJson(arena, claims_json, ctx.signing[i], .{});
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "zig_{s}.jwt", .{a}), .data = ctx.tokens[i] });
    }

    // Build the Go side in a copy of tools/go_bench.
    for ([_][]const u8{ "go.mod", "go.sum", "main.go" }) |f| {
        const src = try cwd.readFileAlloc(io, try std.fmt.allocPrint(arena, "modules/jwt/tools/go_bench/{s}", .{f}), arena, .limited(1 << 20));
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "go/{s}", .{f}), .data = src });
    }
    const exe = try std.fmt.allocPrint(arena, "{s}/foreign_bench", .{abs});
    const go_dir = try std.fmt.allocPrint(arena, "{s}/go", .{abs});
    std.debug.print("bench-jwt: building the Go side ...\n", .{});
    const gb = try std.process.run(arena, io, .{ .argv = &.{ "env", "GOPROXY=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local", "GOWORK=off", "go", "-C", go_dir, "build", "-o", exe, "." } });
    if (gb.term != .exited or gb.term.exited != 0) {
        std.debug.print("bench-jwt: go build failed (is golang-jwt v5.3.1 in the module cache?):\n{s}\n", .{gb.stderr});
        return 1;
    }

    // Interop before timing: Go accepted ours inside `interop`; now we accept Go's.
    try foreignOnce(arena, io, exe, abs, "interop");
    for (algs, 0..) |a, i| {
        const theirs = try dir.readFileAlloc(io, try std.fmt.allocPrint(arena, "go_{s}.jwt", .{a}), arena, .limited(1 << 16));
        var parsed = jwt.parseAndVerify(arena, theirs, ctx.signing[i].verificationKey(), opts) catch |e| {
            std.debug.print("bench-jwt: FAILED -- golang-jwt's {s} token is rejected here: {s}\n", .{ a, @errorName(e) });
            return 1;
        };
        parsed.deinit();
    }

    var ws: std.ArrayList(Work) = .empty;
    for (algs, 0..) |a, i| for ([_]bool{ false, true }) |verify| {
        const op = if (verify) "verify" else "sign";
        try ws.append(arena, .{
            .name = try std.fmt.allocPrint(arena, "{s}_{s}", .{ a, op }),
            .op = .{ .alg = i, .verify = verify },
            .ref = try std.fmt.allocPrint(arena, "go.{s}_{s}", .{ a, op }),
        });
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try drive(io, arena, &.{exe}, abs, &ctx, ws.items, filters, rounds, w);
    try w.print("reference: {s}\nworst ours/golang-jwt = {d:.3} (best {d:.3})\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), s.worst_ref, s.best_ref });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× golang-jwt v5.3.1 (Go <version>) · fastest ? (measured <today>)\n", .{ s.best_ref, s.worst_ref });
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
