// SPDX-License-Identifier: MIT

//! Comparative benchmark: `x509` against Go's `crypto/x509` (the reference;
//! Go 1.26 standard library only), the program behind the `**Performance:**`
//! line of the maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//! The fastest in the field: rustls-webpki 0.103.15 over ring 0.17
//! (`tools/rust_fast_bench`, the default `BENCH_ALT=webpki`). OpenSSL's
//! `X509_verify_cert` (`tools/c_bench/foreign_bench.c`, `BENCH_ALT=openssl`)
//! was measured too and is slower than Go here (2026-10-26: 1.3–1.4×), so it
//! is not the fastest; it stays selectable.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-x509` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0
//! (`GOTOOLCHAIN=local`, `GOPROXY=off`; stdlib only, `tools/go_bench`), and
//! for the alt side either `cargo` with rustls-webpki 0.103.15,
//! rustls-pki-types 1.15.1 and ring 0.17.14 in cargo's cache (built
//! `--offline`), or `zig` on PATH (it builds the C side with `zig cc -O3
//! -march=native`) and the system OpenSSL 3 (`libcrypto.so.3`, path below or
//! `LIBCRYPTO_SO`; no headers needed). Run from the repository root.
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
//! Go by one certificate parse. OpenSSL's side has the same shape:
//! `d2i_X509` of leaf and intermediate, a fresh untrusted stack and
//! `X509_STORE_CTX`, and `X509_verify_cert` against a store holding the root
//! parsed once, with the time, `X509_VERIFY_PARAM_set1_host` and the
//! sslserver purpose. webpki's: `EndEntityCert::try_from` of the leaf,
//! `verify_for_usage` (every algorithm webpki has over ring, the intermediate
//! as presented, the anchor extracted once from the root, serverAuth) and
//! `verify_is_valid_for_subject_name`. The count is the verified path length
//! from leaf to root (3) on every side.
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
const c_src = "modules/x509/tools/c_bench/foreign_bench.c";
const default_so = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const fast_rs_manifest = "modules/x509/tools/rust_fast_bench/Cargo.toml";
const fast_rs_exe = "modules/x509/tools/rust_fast_bench/target/release/x509_fast_bench";

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
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try arena.print("{s}/go_bench", .{abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    try runOk(arena, io, &env, &.{ "go", "build", "-o", exe, "." }, go_dir);
    try runOk(arena, io, &env, &.{ exe, abs, "gen" }, null);

    const ctx = try arena.create(Ctx);
    ctx.gpa = std.heap.smp_allocator;
    const now_txt = try dir.readFileAlloc(io, "now.txt", arena, .limited(64));
    ctx.now = try std.fmt.parseInt(i64, std.mem.trim(u8, now_txt, " \n"), 10);
    for (kinds, 0..) |k, i| for ([_][]const u8{ "leaf", "inter", "root" }, 0..) |n, j| {
        ctx.certs[i][j] = try dir.readFileAlloc(io, try arena.print("{s}_{s}.der", .{ k, n }), arena, .limited(1 << 16));
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

    const alt_name = init.environ_map.get("BENCH_ALT") orelse "webpki";
    const alt_exe = if (std.mem.eql(u8, alt_name, "webpki")) blk: {
        try runOk(arena, io, &env, &.{ "cargo", "build", "--release", "--offline", "--quiet", "--manifest-path", fast_rs_manifest }, null);
        break :blk try cwd.realPathFileAlloc(io, fast_rs_exe, arena);
    } else if (std.mem.eql(u8, alt_name, "openssl"))
        try bench.buildForeign(arena, io, bench_name, &.{ "zig", "cc" }, abs, c_src, &.{init.environ_map.get("LIBCRYPTO_SO") orelse default_so})
    else {
        std.debug.print("{s}: BENCH_ALT={s} -- webpki or openssl\n", .{ bench_name, alt_name });
        return 2;
    };
    // The same chains verify on the alt side, and a wrong host is refused there too.
    try bench.foreignOnce(arena, io, bench_name, alt_exe, abs, "check");

    var ws: std.ArrayList(Work) = .empty;
    for (kinds, 0..) |k, i| {
        const name = try arena.print("verify_{s}", .{k});
        try ws.append(arena, .{ .name = name, .op = .{ .kind = i }, .ref = name, .alt = name, .ref_exe = 0, .alt_exe = 1 });
    }

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = try bench.drive(io, arena, .{ .name = bench_name, .exes = &.{ exe, alt_exe }, .abs = abs, .filters = filters, .rounds = rounds }, ctx, once, ws.items, w);
    try w.print("reference: {s}\nalt: {s}\nworst ours/Go = {d:.3} (best {d:.3}); worst ours/fastest = {d:.3}\n", .{ std.mem.trimEnd(u8, s.banner, "\n"), std.mem.trimEnd(u8, s.alt_banner, "\n"), s.worst_ref, s.best_ref, s.worst_fast orelse 0 });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× Go <version> crypto/x509 (chain verify) · fastest {d:.2}× (the faster of Go and {s} per workload) (measured <today>)\n", .{ s.best_ref, s.worst_ref, s.worst_fast orelse 0, std.mem.trimEnd(u8, s.alt_banner, "\n") });
    try w.flush();
    return 0;
}

fn runOk(arena: std.mem.Allocator, io: std.Io, env: *const std.process.Environ.Map, argv: []const []const u8, cwd_path: ?[]const u8) !void {
    const res = std.process.run(arena, io, .{
        .argv = argv,
        .environ_map = env,
        .cwd = if (cwd_path) |p| .{ .path = p } else .inherit,
    }) catch |e| {
        std.debug.print("{s}: could not run {s} ({t}) -- the benchmark needs Go and cargo or zig cc\n", .{ bench_name, argv[0], e });
        return error.ForeignFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed:\n{s}\n", .{ bench_name, argv[0], res.stderr });
        return error.ForeignFailed;
    }
}
