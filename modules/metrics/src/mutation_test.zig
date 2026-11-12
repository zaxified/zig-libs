// SPDX-License-Identifier: MIT

//! Tests for the survivors of the 2026-11-11 whole-module mutation run
//! (`root.zig` + `summary.zig`). Each one fails when the guard it names is
//! removed or shifted.

const std = @import("std");
const testing = std.testing;
const router = @import("router");
const http = @import("http");
const metrics = @import("root.zig");

fn render(reg: *metrics.Registry, om: bool) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer aw.deinit();
    if (om) try reg.writeOpenMetrics(&aw.writer) else try reg.writeText(&aw.writer);
    return aw.toOwnedSlice();
}

fn zeroFn(_: ?*anyopaque) f64 {
    return 0;
}

test "exemplar: two labels are comma separated in the OpenMetrics sample" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    const c = try reg.counter("ex_total", "h", &.{});
    try c.incWithExemplar(&.{ .{ .name = "a", .value = "1" }, .{ .name = "b", .value = "2" } }, null);
    const out = try render(&reg, true);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "ex_total 1.0 # {a=\"1\",b=\"2\"} 1.0\n") != null);
}

test "gauge: setToCurrentTime keeps the fraction of the second" {
    var g: metrics.Gauge = .{};
    var seen = false;
    for (0..200) |_| {
        g.setToCurrentTime(testing.io);
        const v = g.value();
        if (v != @floor(v)) seen = true;
    }
    try testing.expect(seen);
}

test "fill*Buckets: a one-element slice is valid" {
    var b: [1]f64 = undefined;
    try metrics.fillLinearBuckets(&b, 5, 1);
    try testing.expectEqual(@as(f64, 5), b[0]);
    try metrics.fillExponentialBuckets(&b, 2, 3);
    try testing.expectEqual(@as(f64, 2), b[0]);
}

test "default limits: label value 4096 B and 10000 series per family are the edges" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    const ok_arr: [4096]u8 = @splat('a');
    const bad_arr: [4097]u8 = @splat('a');
    const ok_val: []const u8 = &ok_arr;
    const bad_val: []const u8 = &bad_arr;
    _ = try reg.counter("lim_a", "h", &.{.{ .name = "l", .value = ok_val }});
    try testing.expectError(error.LabelValueTooLong, reg.counter("lim_a", "h", &.{.{ .name = "l", .value = bad_val }}));
    try reg.counterFunc("lim_f", "h", &.{.{ .name = "l", .value = ok_val }}, null, zeroFn);
    try testing.expectError(error.LabelValueTooLong, reg.counterFunc("lim_f", "h", &.{.{ .name = "l", .value = bad_val }}, null, zeroFn));
    const vec = try reg.counterVec("lim_v", "h", &.{"l"});
    _ = try vec.with(&.{ok_val});
    try testing.expectError(error.LabelValueTooLong, vec.with(&.{bad_val}));

    const big = try reg.counterVec("lim_s", "h", &.{"i"});
    var buf: [16]u8 = undefined;
    for (0..10_000) |i| {
        const s = std.fmt.bufPrint(&buf, "{d}", .{i}) catch unreachable;
        _ = try big.with(&.{s});
    }
    try testing.expectError(error.TooManySeries, big.with(&.{"extra"}));
    try testing.expectEqual(@as(usize, 10_000), big.len());
}

test "validateDescriptor: more than max_labels label names is refused for a vec" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    const nine = [_][]const u8{ "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8" };
    try testing.expectError(error.TooManyLabels, reg.counterVec("many", "h", &nine));
    _ = try reg.counterVec("many", "h", nine[0..8]);
}

test "summary registration: 1 ns buckets accepted; NaN quantile/epsilon refused and leave no family" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.summary("sm_one", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.05 }}, .max_age_ns = 5, .age_buckets = 5 });
    const nan = std.math.nan(f64);
    try testing.expectError(error.InvalidObjectives, reg.summary("sm_nq", "h", &.{}, .{ .objectives = &.{.{ .quantile = nan, .epsilon = 0.05 }} }));
    _ = try reg.counter("sm_nq", "h", &.{}); // no summary family was left behind
    try testing.expectError(error.InvalidObjectives, reg.summary("sm_ne", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = nan }} }));
    _ = try reg.counter("sm_ne", "h", &.{});
}

const BadQ = struct {
    fn collect(ctx: ?*anyopaque, sink: *metrics.Sink) anyerror!void {
        const q: *const f64 = @ptrCast(@alignCast(ctx.?));
        try sink.summary(0, &.{}, &.{.{ .quantile = q.*, .epsilon = 0.01 }}, &.{1.0}, 1, 1);
    }
};

test "Sink.summary: a quantile outside [0, 1] or NaN is InvalidBuckets" {
    const cases = [_]f64{ 1.5, -0.5, std.math.nan(f64) };
    for (cases) |q0| {
        var reg = metrics.Registry.init(testing.allocator);
        defer reg.deinit();
        var q = q0;
        try reg.registerCollector(&.{.{ .name = "bq", .help = "h", .kind = .summary }}, .{ .ctx = &q, .collect = BadQ.collect });
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw.deinit();
        try testing.expectError(error.WriteFailed, reg.writeText(&aw.writer));
        try testing.expectEqual(error.InvalidBuckets, reg.lastCollectorError().?);
    }
}

fn noCollect(_: ?*anyopaque, _: *metrics.Sink) anyerror!void {}

test "registerCollector: a histogram desc collides with a sibling desc named <name>_bucket" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    try testing.expectError(error.NameCollision, reg.registerCollector(&.{
        .{ .name = "hh", .help = "h", .kind = .histogram },
        .{ .name = "hh_bucket", .help = "h", .kind = .counter },
    }, .{ .collect = noCollect }));
}

test "negotiate: wildcard type with a concrete subtype is not an exact format match" {
    try testing.expectEqual(metrics.Format.text, metrics.Format.negotiate("*/openmetrics-text"));
    try testing.expectEqual(metrics.Format.openmetrics, metrics.Format.negotiate("*/plain, application/openmetrics-text;q=0.5"));
}

test "OpenMetrics: negative zero is 0.0" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    const g = try reg.gauge("nz", "h", &.{});
    g.set(-0.0);
    const out = try render(&reg, true);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "\nnz 0.0\n") != null);
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [4096]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

test "Endpoint: a POST gets 405 with the Allow header and its body" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    var ep: metrics.Endpoint = .{ .registry = &reg };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ep.middleware());
    var buf: [4096]u8 = undefined;
    const got = runWire(&r, "POST /metrics HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 405"));
    try testing.expect(std.mem.endsWith(u8, got, "Method Not Allowed\n"));
}

test "RequestMetrics.init: size names are checked only with their buckets; the get series exist up front" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try metrics.RequestMetrics.init(&reg, .{ .request_size_name = "bad name", .response_size_name = "bad name" });

    var reg2 = metrics.Registry.init(testing.allocator);
    defer reg2.deinit();
    _ = try metrics.RequestMetrics.init(&reg2, .{ .request_size_buckets = &.{10}, .response_size_buckets = &.{10} });
    const out = try render(&reg2, false);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "http_request_duration_seconds_count{method=\"get\"} 0\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "http_request_size_bytes_count{method=\"get\"} 0\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "http_response_size_bytes_count{method=\"get\"} 0\n") != null);

    // A name taken by another kind surfaces at init, not mid-request.
    var reg3 = metrics.Registry.init(testing.allocator);
    defer reg3.deinit();
    _ = try reg3.gauge("http_request_size_bytes", "h", &.{});
    if (metrics.RequestMetrics.init(&reg3, .{ .request_size_buckets = &.{10} })) |_| return error.TestUnexpectedResult else |_| {}
    var reg4 = metrics.Registry.init(testing.allocator);
    defer reg4.deinit();
    _ = try reg4.gauge("http_response_size_bytes", "h", &.{});
    if (metrics.RequestMetrics.init(&reg4, .{ .response_size_buckets = &.{10} })) |_| return error.TestUnexpectedResult else |_| {}
}

test "ProcessCollector: process_virtual_memory_max_bytes is 2^64-1 when the address space is unlimited" {
    const lim = try std.posix.getrlimit(.AS);
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    var pc: metrics.ProcessCollector = .{ .gpa = testing.allocator, .io = testing.io };
    try pc.register(&reg, "");
    const out = try render(&reg, false);
    defer testing.allocator.free(out);
    var want_buf: [64]u8 = undefined;
    const want = if (lim.cur == std.math.maxInt(@TypeOf(lim.cur)))
        "process_virtual_memory_max_bytes 1.8446744073709552e+19\n"
    else
        std.fmt.bufPrint(&want_buf, "process_virtual_memory_max_bytes {d}\n", .{lim.cur}) catch unreachable;
    if (lim.cur != std.math.maxInt(@TypeOf(lim.cur)) and lim.cur >= 1_000_000) return; // %g renders large values in e-notation
    try testing.expect(std.mem.indexOf(u8, out, want) != null);
}

test "registerCollector: a desc with a bad name or label names is refused and leaves nothing behind" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    const cb: metrics.Collector = .{ .collect = noCollect };
    try testing.expectError(error.InvalidName, reg.registerCollector(&.{.{ .name = "bad name", .help = "h", .kind = .gauge }}, cb));
    try testing.expectError(error.InvalidName, reg.registerCollector(&.{
        .{ .name = "fine_one", .help = "h", .kind = .gauge },
        .{ .name = "1bad", .help = "h", .kind = .gauge },
    }, cb));
    try testing.expectError(error.InvalidLabelName, reg.registerCollector(&.{.{ .name = "cl_a", .help = "h", .kind = .gauge, .label_names = &.{"bad-label"} }}, cb));
    try testing.expectError(error.InvalidLabelName, reg.registerCollector(&.{.{ .name = "cl_b", .help = "h", .kind = .gauge, .label_names = &.{ "x", "x" } }}, cb));
    // None of the refused names was taken.
    try reg.registerCollector(&.{.{ .name = "fine_one", .help = "h", .kind = .gauge }}, cb);
}

test "name collisions: a summary derives only _sum/_count, so a sibling _bucket is free; a histogram's _sum is not" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.summary("sx_lat", "h", &.{}, .{});
    _ = try reg.counter("sx_lat_bucket", "h", &.{});
    try testing.expectError(error.NameCollision, reg.counter("sx_lat_sum", "h", &.{}));
    try testing.expectError(error.NameCollision, reg.counter("sx_lat_count", "h", &.{}));
    _ = try reg.histogram("hx_lat", "h", &.{}, &.{1});
    try testing.expectError(error.NameCollision, reg.counter("hx_lat_bucket", "h", &.{}));
    // The other direction: the derived name is registered first.
    _ = try reg.counter("sy_lat_bucket", "h", &.{});
    _ = try reg.summary("sy_lat", "h", &.{}, .{});
    _ = try reg.counter("hz_lat_bucket", "h", &.{});
    try testing.expectError(error.NameCollision, reg.histogram("hz_lat", "h", &.{}, &.{1}));
}

test "Summary: quantile 0 and 1 answer the minimum and the maximum of a small sample" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    const s = try reg.summary("q01", "h", &.{}, .{ .objectives = &.{
        .{ .quantile = 0, .epsilon = 0.01 },
        .{ .quantile = 1, .epsilon = 0.01 },
    } });
    s.observe(5);
    s.observe(1);
    s.observe(3);
    var q: [2]f64 = undefined;
    const snap = s.snapshot(&q);
    try testing.expectEqual(@as(u64, 3), snap.count);
    try testing.expectEqual(@as(f64, 1), q[0]);
    try testing.expectEqual(@as(f64, 5), q[1]);
}

test "Endpoint: with max_in_flight set a GET under the limit still serves the exposition; the 405 is text/plain" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    const c = try reg.counter("mif_total", "h", &.{});
    c.inc();
    var ep: metrics.Endpoint = .{ .registry = &reg, .max_in_flight = 4 };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(ep.middleware());
    var buf: [4096]u8 = undefined;
    const got = runWire(&r, "GET /metrics HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, got, "mif_total 1\n") != null);
    var buf2: [4096]u8 = undefined;
    const bad = runWire(&r, "POST /metrics HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", &buf2);
    try testing.expect(std.ascii.findIgnoreCase(bad, "content-type: text/plain\r\n") != null);
}

fn hBoomAfterHead(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(202);
    try ctx.res.writeAll("partial");
    try ctx.res.flush();
    return error.Boom;
}

fn hBoomBeforeHead(_: *router.Ctx) anyerror!void {
    return error.Boom;
}

test "RequestMetrics: a handler error counts the status already on the wire, or 500 when nothing was sent" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try metrics.RequestMetrics.init(&reg, .{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.get("/late", hBoomAfterHead);
    try r.get("/early", hBoomBeforeHead);
    var buf: [4096]u8 = undefined;
    _ = runWire(&r, "GET /late HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    _ = runWire(&r, "GET /early HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    const out = try render(&reg, false);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "http_requests_total{method=\"get\",code=\"2xx\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "http_requests_total{method=\"get\",code=\"5xx\"} 1\n") != null);
}
