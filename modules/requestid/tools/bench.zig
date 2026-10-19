// SPDX-License-Identifier: MIT

//! Comparative benchmark: `requestid` against go-chi/chi v5.3.2
//! `middleware.RequestID` (the reference), the program behind the
//! `**Performance:**` line of the maturity card (CONVENTIONS.md §9, kept
//! instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-requestid` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26.0 and
//! github.com/go-chi/chi/v5 in the module cache (pinned by
//! `tools/go_bench/go.mod`/`go.sum`, the same version the router bench pins;
//! `GOPROXY=off`). Run from the repository root.
//!
//! The middleware has no entry point outside a request, so every workload is
//! request bytes in, response bytes out (16 requests to one route "/"): ours
//! `http.Server.serveStream` over `Router` + `RequestId.middleware`, chi's
//! `http.ReadRequest` + `Mux.ServeHTTP` into a buffer. The HTTP stacks are in
//! the number on both sides (as in router's `serve`), so `plain` (no
//! middleware) is measured too, is EXCLUDED from the verdict, and the verdict
//! is the "net" ratio: (workload - plain) per side, the cost of the middleware
//! itself. The gross ratio (stacks included) is printed beside it.
//!   generate  requests without `X-Request-Id`: the middleware generates an id
//!   adopt     requests carrying a valid `X-Request-Id`: adopted
//! chi's RequestID only stores the id in the request context; to do the same
//! job as `requestid` (echo on the response, expose to the handler) chi's
//! handler sets the response header from `middleware.GetReqID` and writes it
//! as the body. The ids differ in shape (ours 32 hex, chi `host/rand-000001`).
//! Result count = sum of status codes + one per response carrying the header.
//! Each side times the same way (double the batch until it takes over 100 ms,
//! best of five); the sides alternate for BENCH_ROUNDS (default 3) rounds, each
//! keeping its best. Ratios are ours/chi by wall time; the verdict is the WORST
//! net ratio over generate and adopt. Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const http = @import("http");
const router = @import("router");
const requestid = @import("requestid");

const bench_name = "bench-requestid";
const work_dir = ".zig-cache/bench-requestid";
const go_dir = "modules/requestid/tools/go_bench";
const ref_short = "chi";
const ref_card = "go-chi/chi v5.3.2 RequestID";

const net_base: ?[]const u8 = "plain";
const info_only = [_][]const u8{"plain"};
const names = [_][]const u8{ "plain", "generate", "adopt" };
const n_req = 16;

const Data = struct {
    plain: *router.Router,
    mw: *router.Router,
    wires: [3][n_req][]const u8,
};

fn hPlain(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("<none>");
}

fn hId(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll(requestid.current() orelse "<none>");
}

var ri: requestid.RequestId = .{};

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
        if (std.ascii.findIgnoreCase(resp, "\r\nx-request-id:") != null) sum += 1;
    }
    return sum;
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    var d: Data = undefined;
    d.plain = try arena.create(router.Router);
    d.plain.* = router.Router.init(std.heap.smp_allocator);
    try d.plain.get("/", hPlain);
    d.mw = try arena.create(router.Router);
    d.mw.* = router.Router.init(std.heap.smp_allocator);
    try d.mw.use(ri.middleware());
    try d.mw.get("/", hId);
    for (names, 0..) |name, wi| {
        var all: std.Io.Writer.Allocating = .init(arena);
        for (0..n_req) |i| {
            const wire = if (wi == 2)
                try arena.print("GET / HTTP/1.1\r\nHost: t\r\nX-Request-Id: edge-4f9a8c1d2b7e-{d:0>4}\r\nConnection: close\r\n\r\n", .{i})
            else
                try arena.dupe(u8, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
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
            for (filters) |f| hit = hit or std.mem.find(u8, name, f) != null;
            if (!hit) continue;
        }
        var ours: bench.Side = .{};
        var go: bench.Side = .{};
        for (0..rounds) |_| {
            go.add(try bench.foreign(arena, io, bench_name, exe, abs, name, null));
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
