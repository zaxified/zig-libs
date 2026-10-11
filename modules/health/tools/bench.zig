// SPDX-License-Identifier: MIT

//! Comparative benchmark: `health` against alexliesenfeld/health v0.8.1 (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-health` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! github.com/alexliesenfeld/health in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`; `GOPROXY=off`). Run from the repository
//! root.
//!
//! Every workload is request bytes in, response bytes out (16 requests): ours
//! `http.Server.serveStream` over `Router` + `Health.middleware`, the
//! reference's `http.ReadRequest` + the `health.NewHandler` handler into a
//! buffer (no sockets on either side). The HTTP stacks are in the number on
//! both sides, so `passthrough` (a non-probe path answered by a bare handler)
//! is measured too, is EXCLUDED from the verdict, and the verdict is the "net"
//! ratio: (workload - passthrough) per side, the cost of the probe itself. The
//! gross ratio is printed beside it.
//!   liveness              ours: /healthz; reference: a checker with no checks
//!   readiness_3_up        3 checks, all pass, detail on, JSON body
//!   readiness_3_down      3 checks, one fails
//!   readiness_3_nodetail  the same, detail off / WithDisabledDetails
//! The reference runs with its cache OFF (WithDisabledCache) and autostart off,
//! so BOTH sides run every check on every request; the checks are atomic-flag
//! loads on both sides. It also writes a timestamp per check, which `health`
//! deliberately does not, so the result count is the sum of status codes + one
//! per response whose body starts with `{"status":"` (body lengths differ by
//! design). Each side times the same way (double the batch until it takes over
//! 100 ms, best of five); the sides alternate for BENCH_ROUNDS (default 3)
//! rounds, each keeping its best. Ratios are ours/reference by wall time; the
//! verdict is the WORST net ratio. Arguments filter workloads.

const std = @import("std");
const http = @import("http");
const router = @import("router");
const health = @import("health");

const bench_name = "bench-health";
const work_dir = ".zig-cache/bench-health";
const go_dir = "modules/health/tools/go_bench";
const ref_short = "ref";
const ref_card = "alexliesenfeld/health v0.8.1";

const net_base: ?[]const u8 = "passthrough";
const info_only = [_][]const u8{"passthrough"};
const names = [_][]const u8{ "passthrough", "liveness", "readiness_3_up", "readiness_3_down", "readiness_3_nodetail" };
const n_req = 16;

const Data = struct {
    routers: [names.len]*router.Router,
    wires: [names.len][n_req][]const u8,
};

fn hApp(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("<none>");
}

var flag_up: std.atomic.Value(bool) = .init(true);
var flag_down: std.atomic.Value(bool) = .init(false);

fn flagCheck(ctx: ?*anyopaque) bool {
    const f: *std.atomic.Value(bool) = @ptrCast(@alignCast(ctx.?));
    return f.load(.acquire);
}

var checks_up = [_]health.Check{
    .{ .name = "database", .checkFn = flagCheck, .ctx = &flag_up },
    .{ .name = "cache", .checkFn = flagCheck, .ctx = &flag_up },
    .{ .name = "queue", .checkFn = flagCheck, .ctx = &flag_up },
};
var checks_down = [_]health.Check{
    .{ .name = "database", .checkFn = flagCheck, .ctx = &flag_up },
    .{ .name = "cache", .checkFn = flagCheck, .ctx = &flag_down },
    .{ .name = "queue", .checkFn = flagCheck, .ctx = &flag_up },
};
var h_live: health.Health = .{ .json = true };
var h_up: health.Health = .{ .checks = &checks_up, .json = true };
var h_down: health.Health = .{ .checks = &checks_down, .json = true };
var h_quiet: health.Health = .{ .checks = &checks_down, .json = true, .detail = false };

fn once(d: *const Data, w: usize) u64 {
    const r = d.routers[w];
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
        const body_at = std.mem.indexOf(u8, resp, "\r\n\r\n") orelse continue;
        if (std.mem.startsWith(u8, resp[body_at + 4 ..], "{\"status\":\"")) sum += 1;
    }
    return sum;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var d: Data = undefined;
    const hs = [names.len]?*health.Health{ null, &h_live, &h_up, &h_down, &h_quiet };
    const targets = [names.len][]const u8{ "/other", "/healthz", "/readyz", "/readyz", "/readyz" };
    for (names, 0..) |name, wi| {
        const r = try arena.create(router.Router);
        r.* = router.Router.init(std.heap.smp_allocator);
        if (hs[wi]) |h| try r.use(h.middleware());
        try r.get("/other", hApp);
        d.routers[wi] = r;
        var all: std.Io.Writer.Allocating = .init(arena);
        for (0..n_req) |i| {
            const wire = try std.fmt.allocPrint(arena, "GET {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{targets[wi]});
            d.wires[wi][i] = wire;
            if (i != 0) try all.writer.writeByte(0);
            try all.writer.writeAll(wire);
        }
        try dir.writeFile(io, .{ .sub_path = try std.fmt.allocPrint(arena, "{s}.wire", .{name}), .data = all.written() });
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

    const exe = try goBuild(arena, io, init.environ_map, abs);
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("{s:<22} {s:>11} {s:>11} {s:>8} {s:>8} {s:>7} {s:>7}  count\n", .{ "workload", "ours ns", ref_short ++ " ns", "gross", "net", "spr us", "spr ref" });
    try w.flush();
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    var max_spread: f64 = 0;
    var mismatch = false;
    var base_ours: f64 = 0;
    var base_ref: f64 = 0;
    for (names, 0..) |name, wi| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: Side = .{};
        var go: Side = .{};
        for (0..rounds) |_| {
            go.add(try goRun(arena, io, exe, abs, name));
            ours.add(timeIt(io, &d, wi));
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
        max_spread = @max(max_spread, @max(ours.spread(), go.spread()));
        const same = ours.count == go.count;
        mismatch = mismatch or !same;
        try w.print("{s:<22} {d:>11.0} {d:>11.0} {d:>8.3} {d:>8.3} {d:>6.1}% {d:>6.1}%  {d}{s}\n", .{ name, ours.best_ns, go.best_ns, gross, net, 100 * ours.spread(), 100 * go.spread(), ours.count, if (same and !info) "" else if (same) "  (info only, not in the verdict)" else " ≠ " ++ ref_short });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time{s}; largest spread {d:.1}%{s}\n", .{ rounds, if (net_base != null) " (verdict = net of the " ++ net_base.? ++ " workload)" else "", 100 * max_spread, if (max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (mismatch) {
        try w.writeAll(bench_name ++ ": FAILED -- a result count differs from the reference's; the timing means nothing until it agrees\n");
        try w.flush();
        return 1;
    }
    try w.print("\nworst ours/{s} = {d:.2} (best {d:.2})\n", .{ ref_short, worst, best });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest ? (measured <today>)\n", .{ best, worst, ref_card });
    try w.flush();
    return 0;
}

// ---- comparison driver (the same in every stdlib-Go-referenced bench) ----

const Row = struct { ns: f64, count: u64 };

const Side = struct {
    best_ns: f64 = std.math.inf(f64),
    worst_ns: f64 = 0,
    count: u64 = 0,
    fn add(s: *Side, r: Row) void {
        s.best_ns = @min(s.best_ns, r.ns);
        s.worst_ns = @max(s.worst_ns, r.ns);
        s.count = r.count;
    }
    fn spread(s: Side) f64 {
        return s.worst_ns / s.best_ns - 1;
    }
};

fn timeIt(io: std.Io, d: *const Data, w: usize) Row {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(once(d, w));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    var count: u64 = 0;
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| count = once(d, w);
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return .{ .ns = @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n)), .count = count };
}

/// Build the Go side once (`go build`), so the timed runs do not pay for it.
fn goBuild(arena: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, abs: []const u8) ![]const u8 {
    var env = try environ.clone(arena);
    try env.put("GOTOOLCHAIN", "go1.26.0");
    try env.put("GOPROXY", "off");
    try env.put("GOFLAGS", "-mod=readonly");
    const exe = try std.fmt.allocPrint(arena, "{s}/go_bench", .{abs});
    std.debug.print("{s}: building the Go side ...\n", .{bench_name});
    const res = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env,
        .cwd = .{ .path = go_dir },
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

/// Run the Go side for one workload: `<exe> <work dir> <name>` prints
/// `name \t ns/op \t count`.
fn goRun(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8) !Row {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: Go side failed on {s}:\n{s}\n", .{ bench_name, name, res.stderr });
        return error.ForeignFailed;
    }
    var f = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, res.stdout, "\n"), '\t');
    if (!std.mem.eql(u8, f.next() orelse return error.BadForeignOutput, name)) return error.BadForeignOutput;
    const ns = try std.fmt.parseFloat(f64, f.next() orelse return error.BadForeignOutput);
    const count = try std.fmt.parseInt(u64, f.next() orelse return error.BadForeignOutput, 10);
    return .{ .ns = ns, .count = count };
}
