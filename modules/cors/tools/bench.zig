// SPDX-License-Identifier: MIT

//! Comparative benchmark: `cors` against rs/cors v1.11.1 (the reference), the
//! program behind the `**Performance:**` line of the maturity card
//! (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-cors` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! github.com/rs/cors v1.11.1 in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`). Run from the repository
//! root.
//!
//! The middleware has no entry point outside a request, so every workload is
//! request bytes in, response bytes out (16 requests to one route "/"): ours
//! `http.Server.serveStream` over `Router` + `Cors.middleware`, rs/cors's
//! `http.ReadRequest` + `cors.Handler(mux)` into a buffer. The HTTP stacks are
//! in the number on both sides, so `plain` (no middleware, the `actual`
//! request bytes) is measured too, is EXCLUDED from the verdict, and the
//! verdict is the "net" ratio: (workload - plain) per side, the cost of the
//! middleware itself. The gross ratio (stacks included) is printed beside it.
//! Same policy on both sides: four listed origins plus the pattern
//! `https://*.tenant.example`, methods GET/POST/PUT, allowed headers
//! Content-Type/Authorization/X-Requested-With, max-age 600, no credentials.
//!   preflight   OPTIONS from a listed origin, ACRM PUT + ACRH (granted, 204)
//!   actual      GET from a listed origin (echo + Vary)
//!   disallowed  GET from an origin on no list (Vary only)
//!   wildcard    GET from a pattern-matched origin (echo + Vary)
//! rs/cors lowercases the origin and scans the plain list, then the wildcards;
//! ours compares bytes (the wildcard matcher also validates the labels).
//! (ACRH is sent sorted, as a browser does: rs/cors's header set requires it.)
//! Result count = sum of status codes + one per response carrying
//! `Access-Control-Allow-Origin`, so a policy that diverges shows up as a
//! count mismatch before any timing is read.
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best. Ratios are ours/rs-cors by wall time; the verdict is the
//! WORST net ratio over the four workloads. Arguments filter workloads.
//!
//! "Fastest in the field": two more foreign sides are timed the same way over
//! the same request bytes, `tools/go_fast_bench` (the CORS middleware of
//! labstack/echo v5.4.2) and `tools/rust_fast_bench` (tower-http 0.7.1
//! `CorsLayer`), each with its own `plain` baseline so the verdict stays NET of
//! the HTTP stack. Neither is like-for-like work; each source header says
//! where: both skip the checks of Access-Control-Request-Method/-Headers on a
//! preflight, tower-http answers 200 (the count is compared on `canon`, the
//! count with 200 read as 204), neither has origin patterns (the `wildcard`
//! row is dropped for both, exit 3), and the Rust request side is httparse +
//! `http::Request`. `BENCH_FAST=0` skips both (needs cargo and the pinned echo
//! tree in the Go module cache). The card's fastest figure is ours / the
//! cheapest net cost of {rs/cors, echo, tower-http} per row, worst over the
//! rows.

const std = @import("std");
const bench = @import("testkit").bench;
const http = @import("http");
const router = @import("router");
const cors = @import("cors");

const bench_name = "bench-cors";
const work_dir = ".zig-cache/bench-cors";
const go_dir = "modules/cors/tools/go_bench";
const ref_short = "rs/cors";
const ref_card = "rs/cors v1.11.1";

const fast_go_dir = "modules/cors/tools/go_fast_bench";
const fast_rs_manifest = "modules/cors/tools/rust_fast_bench/Cargo.toml";
const fast_rs_exe = "modules/cors/tools/rust_fast_bench/target/release/cors_fast_bench";

const Fast = struct { name: []const u8, rust: bool, card: []const u8 };
const fasts = [_]Fast{
    .{ .name = "echo", .rust = false, .card = "labstack/echo v5.4.2" },
    .{ .name = "tower-http", .rust = true, .card = "tower-http 0.7.1" },
};

const net_base: ?[]const u8 = "plain";
const info_only = [_][]const u8{"plain"};
const names = [_][]const u8{ "plain", "preflight", "actual", "disallowed", "wildcard" };
const n_req = 16;

const Data = struct {
    plain: *router.Router,
    mw: *router.Router,
    wires: [names.len][n_req][]const u8,
};

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

const listed = [_][]const u8{ "https://app.example", "https://admin.example", "http://localhost:5173", "https://portal.example" };

var policy: cors.Cors = undefined;

fn once(d: *const Data, w: usize) u64 {
    const r = if (w == 0) d.plain else d.mw;
    var sum: u64 = 0;
    var out_buf: [1024]u8 = undefined;
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [64]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    for (d.wires[w]) |wire| {
        var in: std.Io.Reader = .fixed(wire);
        var out: std.Io.Writer = .fixed(&out_buf);
        http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
            .head = &head_buf,
            .request_body = &request_body_buf,
            .response_body = &response_body_buf,
            .chunk = &chunk_buf,
        });
        const resp = out.buffered();
        sum += std.fmt.parseInt(u16, resp[9..12], 10) catch 0;
        if (std.ascii.findIgnoreCase(resp, "\r\naccess-control-allow-origin:") != null) sum += 1;
    }
    return sum;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var d: Data = undefined;
    d.plain = try arena.create(router.Router);
    d.plain.* = router.Router.init(std.heap.smp_allocator);
    try d.plain.get("/", hOk);
    policy = try cors.Cors.init(std.heap.smp_allocator, .{
        .allowed_origins = .{ .patterns = .{
            .exact = &listed,
            .subdomains = &.{"https://*.tenant.example"},
        } },
        .allowed_methods = &.{ .get, .post, .put },
        .allowed_headers = .{ .list = &.{ "Content-Type", "Authorization", "X-Requested-With" } },
        .max_age_s = 600,
    });
    d.mw = try arena.create(router.Router);
    d.mw.* = router.Router.init(std.heap.smp_allocator);
    try d.mw.use(policy.middleware());
    try d.mw.get("/", hOk);
    for (names, 0..) |name, wi| {
        var all: std.Io.Writer.Allocating = .init(arena);
        for (0..n_req) |i| {
            const o = listed[i % listed.len];
            const wire = if (std.mem.eql(u8, name, "preflight"))
                try arena.print("OPTIONS / HTTP/1.1\r\nHost: t\r\nOrigin: {s}\r\nAccess-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: authorization, content-type\r\nConnection: close\r\n\r\n", .{o})
            else if (std.mem.eql(u8, name, "disallowed"))
                try arena.print("GET / HTTP/1.1\r\nHost: t\r\nOrigin: https://evil{d}.example\r\nConnection: close\r\n\r\n", .{i})
            else if (std.mem.eql(u8, name, "wildcard"))
                try arena.print("GET / HTTP/1.1\r\nHost: t\r\nOrigin: https://t{d}.tenant.example\r\nConnection: close\r\n\r\n", .{i})
            else // plain and actual: the same bytes, a GET from a listed origin
                try arena.print("GET / HTTP/1.1\r\nHost: t\r\nOrigin: {s}\r\nConnection: close\r\n\r\n", .{o});
            d.wires[wi][i] = wire;
            if (i != 0) try all.writer.writeByte(0);
            try all.writer.writeAll(wire);
        }
        try dir.writeFile(io, .{ .sub_path = try arena.print("{s}.wire", .{name}), .data = all.written() });
    }
    return d;
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

    var d: Data = try setup(arena, io, dir);

    const exe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    const use_fast = if (init.environ_map.get("BENCH_FAST")) |v| !std.mem.eql(u8, v, "0") else true;
    var fast_exe: [fasts.len][]const u8 = undefined;
    if (use_fast) {
        fast_exe[0] = try fastGoBuild(arena, io, init.environ_map, abs);
        try rustBuild(arena, io);
        fast_exe[1] = fast_rs_exe;
    }
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    if (use_fast) try w.print("{s:<22} {s:>11} {s:>11} {s:>9}  net, vs cheapest (who)\n", .{ "", fasts[0].name ++ " ns", fasts[1].name ++ " ns", "ours/best" });
    try w.flush();
    var worst: f64 = 0;
    var worst_fast: f64 = 0;
    var worst_fast_row: []const u8 = "";
    var worst_fast_who: []const u8 = "";
    var base_fast: [fasts.len]f64 = @splat(0);
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.find(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        var fast: [fasts.len]bench.Side = @splat(.{});
        var fast_canon: [fasts.len]?u64 = @splat(null);
        // false once a contender answers "unsupported" for this workload
        var fast_ok: [fasts.len]bool = @splat(use_fast);
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
            if (use_fast) for (fasts, 0..) |c, ci| {
                if (!fast_ok[ci]) continue;
                if (try fastRun(arena, io, fast_exe[ci], abs, c.name, name)) |r| {
                    fast[ci].add(r.row);
                    fast_canon[ci] = r.canon;
                } else fast_ok[ci] = false;
            };
            ours.add(bench.timeIt(io, .{ .fd = null }, once, .{ &d, wi }, true));
        }
        const gross = ours.best_ns / go.best_ns;
        // `net_base` (a workload name): the cost of the HTTP stacks both sides
        // carry is that workload; the module's own ratio is what is left over.
        var net: f64 = std.math.nan(f64);
        if (net_base) |nb| {
            if (std.mem.eql(u8, nb, name)) {
                base_ours = ours.best_ns;
                base_ref = go.best_ns;
            } else if (base_ref != 0 and go.best_ns > base_ref) {
                net = (ours.best_ns - base_ours) / (go.best_ns - base_ref);
            }
        }
        const ratio = if (net_base != null and !std.math.isNan(net)) net else gross;
        const info = for (info_only) |n| {
            if (std.mem.eql(u8, n, name)) break true;
        } else false;
        if (!info) {
            worst = @max(worst, ratio);
            best = @min(best, ratio);
        }
        max_spread = @max(max_spread, @max(ours.spread(false), go.spread(false)));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(false), 100 * go.spread(false), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ " ++ ref_short });
        if (use_fast) {
            // net cost of each side = workload - its own `plain`; the
            // cheapest of the reference and the contenders is the yardstick
            const is_base = std.mem.eql(u8, net_base.?, name);
            const ours_cost = ours.best_ns - base_ours;
            var fastest_cost: f64 = if (go.best_ns > base_ref) go.best_ns - base_ref else std.math.inf(f64);
            var fastest_who: []const u8 = ref_short;
            try w.print("{s:<22}", .{""});
            for (fasts, 0..) |c, ci| {
                if (!fast_ok[ci]) {
                    try w.print(" {s:>11}", .{"-"});
                    continue;
                }
                try w.print(" {d:>11.0}", .{fast[ci].best_ns});
                max_spread = @max(max_spread, fast[ci].spread(false));
                // ours' checksum is already the 204 one, so `canon` is compared to it
                const agrees = fast[ci].count == ours.count or (fast_canon[ci] != null and fast_canon[ci].? == ours.count);
                if (!agrees) {
                    mismatch = true;
                    try w.print(" ({s}: {d} / canon {d} != ours {d})", .{ c.name, fast[ci].count, fast_canon[ci] orelse 0, ours.count });
                }
                if (is_base) {
                    base_fast[ci] = fast[ci].best_ns;
                } else if (fast[ci].best_ns > base_fast[ci] and fast[ci].best_ns - base_fast[ci] < fastest_cost) {
                    fastest_cost = fast[ci].best_ns - base_fast[ci];
                    fastest_who = c.card;
                }
            }
            if (!is_base and std.math.isFinite(fastest_cost)) {
                const ratio_fast = if (ours_cost > 0) ours_cost / fastest_cost else 0;
                if (!info and ratio_fast > worst_fast) {
                    worst_fast = ratio_fast;
                    worst_fast_row = name;
                    worst_fast_who = fastest_who;
                }
                try w.print(" {d:>9.3}  ({s})\n", .{ ratio_fast, fastest_who });
            } else try w.writeAll("\n");
        }
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (use_fast) try w.print("worst vs fastest = {d:.2} (row {s}, {s})\n", .{ worst_fast, worst_fast_row, worst_fast_who });
    if (filters.len == 0) {
        if (use_fast)
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× {s} (measured <today>)\n", .{ best, worst, ref_card, worst_fast, worst_fast_who })
        else
            try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    }
    try w.flush();
    return 0;
}

// ---- the "fastest in the field" sides ----

/// Build tools/go_fast_bench (same environment as `bench.goBuild`: local
/// toolchain, `GOPROXY=off`, read-only modules) into `<abs>/go_fast_bench`.
fn fastGoBuild(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, abs: []const u8) ![]const u8 {
    var env = try environ.clone(arena);
    try env.put("GOTOOLCHAIN", "local");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try arena.print("{s}/go_fast_bench", .{abs});
    std.debug.print("{s}: building the Go fastest-in-the-field side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = fast_go_dir },
    }) catch |e| {
        std.debug.print("{s}: could not run go ({t}) -- BENCH_FAST=0 skips this side\n", .{ bench_name, e });
        return error.GoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: go build (go_fast_bench) failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.GoBuildFailed;
    }
    return exe;
}

/// `cargo build --release --offline` of tools/rust_fast_bench.
fn rustBuild(arena: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--quiet", "--manifest-path", fast_rs_manifest },
    }) catch |e| {
        std.debug.print("{s}: could not run cargo ({t}) -- BENCH_FAST=0 skips this side\n", .{ bench_name, e });
        return error.CargoBuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.CargoBuildFailed;
    }
}

const FastRow = struct { row: bench.Row, canon: ?u64 };

/// `<exe> <work dir> <workload> <contender>` prints `name \t ns/op \t count`
/// and, for a workload with a case-folded checksum, `\t canon`. Null when the
/// contender cannot do the workload (exit 3).
fn fastRun(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, who: []const u8, name: []const u8) !?FastRow {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name, who } });
    if (res.term == .exited and res.term.exited == 3) return null;
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed on {s}:\n{s}\n", .{ bench_name, who, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    const canon: ?u64 = if (f.next()) |c| try std.fmt.parseInt(u64, c, 10) else null;
    return .{ .row = .{ .ns = ns, .count = count }, .canon = canon };
}
