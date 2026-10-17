// SPDX-License-Identifier: MIT

//! Comparative benchmark: `metrics` against prometheus/client_golang v1.24.1
//! (the reference), the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-metrics` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs a local go ≥ 1.26.0 (`GOTOOLCHAIN=local`) and
//! client_golang v1.24.1 in the module cache (pinned by `tools/go_bench/go.mod`
//! / `go.sum`, the same set the metrics oracle pins; `GOPROXY=off`). Run from
//! the repository root.
//!
//! Workloads -- what an HTTP service does with a metrics library:
//!   counter_inc    4096 x increment of a held counter
//!   observe        4096 x histogram observation (default buckets, values
//!                  0..10.9 s) on a held histogram
//!   counter_vec    4096 x "find the series for (method, code) and increment
//!                  it": ours `CounterVec.with(.{m, c}).inc()`, Go
//!                  `CounterVec.WithLabelValues(m, c).Inc()` -- like for like
//!                  since 2026-10-17 (before: `Registry.counter(name, help,
//!                  labels)`, which validates the whole descriptor per call
//!                  and has no Go counterpart: 1.66x)
//!   scrape         one `GET /metrics`: ours `Registry.writeText`, Go
//!                  `promhttp.HandlerFor` into a `httptest.ResponseRecorder`;
//!                  5 families, 20 request counters, 1+6 gauges, 12 histograms
//!                  (11 buckets each, 100 observations apiece). Family and
//!                  series ORDER differs (Go sorts), the byte sum does not.
//!   serve_plain    16 requests (GET / x8, POST / x4, GET /missing x4) through
//!                  ours `http.Server.serveStream` + `Router`, Go
//!                  `http.ReadRequest` + a handler into a buffer: the baseline
//!   serve_metrics  the same with the request-metrics middleware: ours
//!                  `RequestMetrics` (in-flight gauge, count by method and
//!                  status class, duration histogram by method), Go
//!                  `promhttp.InstrumentHandlerInFlight` + `...Counter` +
//!                  `...Duration`. The verdict for the two serve_* workloads is
//!                  the "net" ratio, (serve_metrics - serve_plain) per side:
//!                  the HTTP stacks are in both numbers (gross is printed too)
//!                  and serve_plain itself is excluded.
//! Result count = items processed per op (the *_inc/observe/vec ones: 4096),
//! the byte sum of the exposition (scrape), the sum of the status codes
//! (serve_*). The micro workloads are single-threaded and uncontended on both
//! sides. Each side times the same way (double the batch until it takes over
//! 100 ms, best of five); the sides alternate for BENCH_ROUNDS (default 3)
//! rounds, each keeping its best. Ratios are ours/Go by wall time; the verdict
//! is the WORST ratio. Arguments filter workloads.

const std = @import("std");
const bench = @import("testkit").bench;
const http = @import("http");
const router = @import("router");
const metrics = @import("metrics");

const bench_name = "bench-metrics";
const work_dir = ".zig-cache/bench-metrics";
const go_dir = "modules/metrics/tools/go_bench";
const ref_short = "Go";
const ref_card = "prometheus/client_golang v1.24.1";

const net_base: ?[]const u8 = "serve_plain";
const net_prefix = "serve_";
const info_only = [_][]const u8{"serve_plain"};
const names = [_][]const u8{ "counter_inc", "observe", "counter_vec", "scrape", "serve_plain", "serve_metrics" };
const n_obs = 4096;
const n_req = 16;
const methods = [_][]const u8{ "GET", "POST", "PUT", "DELETE" };
const codes = [_][]const u8{ "200", "201", "400", "404", "500" };

fn obsValue(k: usize) f64 {
    return @as(f64, @floatFromInt((k * 37) % 700)) / 64.0;
}

const Data = struct {
    counter: *metrics.Counter,
    hist: *metrics.Histogram,
    vals: [n_obs]f64,
    vec_reg: *metrics.Registry,
    vec: metrics.CounterVec,
    scrape_reg: *metrics.Registry,
    scrape_buf: []u8,
    plain: *router.Router,
    mw: *router.Router,
    wires: [n_req][]const u8,
};

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

fn sumBytes(s: []const u8) u64 {
    var t: u64 = 0;
    for (s) |c| t += c;
    return t;
}

fn once(d_const: *const Data, w: usize) u64 {
    const d: *Data = @constCast(d_const);
    switch (w) {
        0 => {
            for (0..n_obs) |_| d.counter.inc();
            return n_obs;
        },
        1 => {
            for (d.vals) |v| d.hist.observe(v);
            return n_obs;
        },
        2 => {
            for (0..n_obs) |i| {
                const c = d.vec.with(&.{ methods[i & 3], codes[(i >> 2) % 5] }) catch unreachable;
                c.inc();
            }
            return n_obs;
        },
        3 => {
            var out: std.Io.Writer = .fixed(d.scrape_buf);
            d.scrape_reg.writeText(&out) catch unreachable;
            return sumBytes(out.buffered());
        },
        else => {
            const r = if (w == 4) d.plain else d.mw;
            var sum: u64 = 0;
            var out_buf: [1024]u8 = undefined;
            var head_buf: [2048]u8 = undefined;
            var request_body_buf: [64]u8 = undefined;
            var response_body_buf: [1024]u8 = undefined;
            var chunk_buf: [128]u8 = undefined;
            for (d.wires) |wire| {
                var in: std.Io.Reader = .fixed(wire);
                var out: std.Io.Writer = .fixed(&out_buf);
                http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
                    .head = &head_buf,
                    .request_body = &request_body_buf,
                    .response_body = &response_body_buf,
                    .chunk = &chunk_buf,
                });
                sum += std.fmt.parseInt(u16, out.buffered()[9..12], 10) catch 0;
            }
            return sum;
        },
    }
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !Data {
    const gpa = std.heap.smp_allocator;
    var d: Data = undefined;
    // counter_inc / observe: held instruments in their own registry.
    const held = try arena.create(metrics.Registry);
    held.* = metrics.Registry.init(gpa);
    d.counter = try held.counter("bench_total", "bench", &.{});
    d.hist = try held.histogram("bench_seconds", "bench", &.{}, &metrics.default_buckets);
    for (&d.vals, 0..) |*v, i| v.* = obsValue(i);
    d.vec_reg = try arena.create(metrics.Registry);
    d.vec_reg.* = metrics.Registry.init(gpa);
    d.vec = try d.vec_reg.counterVec("bench_total", "bench", &.{ "method", "code" });

    // scrape: the same registry the Go side builds.
    d.scrape_reg = try arena.create(metrics.Registry);
    d.scrape_reg.* = metrics.Registry.init(gpa);
    const sr = d.scrape_reg;
    for (methods, 0..) |m, mi| for (codes, 0..) |c, ci| {
        const ctr = try sr.counter("http_requests_total", "Total HTTP requests served.", &.{ .{ .name = "method", .value = m }, .{ .name = "code", .value = c } });
        ctr.add(1 + (mi * 5 + ci) * 37);
    };
    const gg = try sr.gauge("app_in_flight", "Requests in flight.", &.{});
    gg.set(3);
    for (0..6) |i| {
        const room = try std.fmt.allocPrint(arena, "room{d}", .{i});
        const t = try sr.gauge("app_temp_celsius", "Room temperature.", &.{.{ .name = "room", .value = room }});
        t.set(@as(f64, @floatFromInt(i)) * 0.5);
    }
    for (methods, 0..) |m, mi| {
        const h = try sr.histogram("http_request_duration_seconds", "Request latency.", &.{.{ .name = "method", .value = m }}, &metrics.default_buckets);
        for (0..100) |k| h.observe(obsValue(mi * 100 + k));
    }
    for (0..8) |oi| {
        const opn = try std.fmt.allocPrint(arena, "op{d}", .{oi});
        const h = try sr.histogram("app_op_seconds", "Operation latency.", &.{.{ .name = "op", .value = opn }}, &metrics.default_buckets);
        for (0..100) |k| h.observe(obsValue(oi * 100 + k + 7));
    }
    d.scrape_buf = try arena.alloc(u8, 256 * 1024);

    // serve_*: one route per method on "/", no route for "/missing".
    d.plain = try arena.create(router.Router);
    d.plain.* = router.Router.init(gpa);
    try d.plain.get("/", hOk);
    try d.plain.post("/", hOk);
    const mreg = try arena.create(metrics.Registry);
    mreg.* = metrics.Registry.init(gpa);
    const rm = try arena.create(metrics.RequestMetrics);
    rm.* = try metrics.RequestMetrics.init(mreg, .{});
    d.mw = try arena.create(router.Router);
    d.mw.* = router.Router.init(gpa);
    try d.mw.use(rm.middleware());
    try d.mw.get("/", hOk);
    try d.mw.post("/", hOk);
    var all: std.Io.Writer.Allocating = .init(arena);
    for (0..n_req) |i| {
        const wire = if (i < 8)
            "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
        else if (i < 12)
            "POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        else
            "GET /missing HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
        d.wires[i] = wire;
        if (i != 0) try all.writer.writeByte(0);
        try all.writer.writeAll(wire);
    }
    try dir.writeFile(io, .{ .sub_path = "serve.wire", .data = all.written() });
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
            for (filters) |f| hit = hit or std.mem.indexOf(u8, name, f) != null;
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
        const in_net = std.mem.startsWith(u8, name, if (@hasDecl(@This(), "net_prefix")) @field(@This(), "net_prefix") else "");
        if (net_base) |nb| {
            if (std.mem.eql(u8, nb, name)) {
                base_ours = ours.best_ns;
                base_ref = go.best_ns;
            } else if (in_net and base_ref != 0 and go.best_ns > base_ref) {
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
