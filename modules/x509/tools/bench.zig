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
//! Method (`testkit.bench`): each side doubles its batch until it
//! takes over 100 ms and keeps the best of five; per workload the sides
//! alternate for `BENCH_ROUNDS` (default 3) rounds, each keeping its best; the
//! spread printed is (worst round − best round) / best round per side. Go has
//! no cycle counter here, so ratios are by wall time. Before timing anything
//! each chain must verify with the right host and be refused for a wrong one.
//! Arguments filter workloads by substring (no card line then).

const std = @import("std");
const bench = @import("testkit").bench;
const Work = bench.Work(Op);
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
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{exe}, .abs = abs, .filters = filters, .rounds = rounds }, ctx, once, ws.items, w);
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
