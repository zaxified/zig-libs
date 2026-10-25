// SPDX-License-Identifier: MIT

//! Grade-1 audit tests (2026-10-25): one test per mutation survivor of the
//! `METRICS_MUT` schemata run, plus the probes of the review findings. Public
//! API and struct fields only. Findings whose fix is not in yet are pinned
//! behind the `*_fixed` switches below: flip a switch when the fix lands and the
//! test asserts the corrected behaviour instead of the known-defective one.

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");
const procnet = @import("procnet");
const metrics = @import("root.zig");
const summary_mod = @import("summary.zig");

const Registry = metrics.Registry;
const Counter = metrics.Counter;
const Histogram = metrics.Histogram;
const Format = metrics.Format;

/// Review finding M1 (summary `_sum`/`_count` names are not collision-checked).
const f1_fixed = true;

fn scrape(reg: *Registry, aw: *std.Io.Writer.Allocating) ![]const u8 {
    try reg.writeText(&aw.writer);
    return aw.written();
}

/// Value of the unlabeled sample `name` in `text`.
fn sampleValue(text: []const u8, name: []const u8) !f64 {
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len > name.len and std.mem.startsWith(u8, line, name) and line[name.len] == ' ')
            return try std.fmt.parseFloat(f64, line[name.len + 1 ..]);
    }
    std.debug.print("sample {s} missing in:\n{s}\n", .{ name, text });
    return error.TestUnexpectedResult;
}

// ── clock ───────────────────────────────────────────────────────────────────

test "Clock.monotonic: nanoseconds of the OS monotonic clock, sub-second resolution" {
    const c = metrics.Clock.monotonic;
    const awake: i96 = std.Io.Clock.awake.now(testing.io).nanoseconds;
    const mine: i96 = c.now();
    // Same origin as the awake clock (CLOCK_MONOTONIC): a seconds-only or
    // milliseconds-scaled value is orders of magnitude off.
    const diff = if (mine > awake) mine - awake else awake - mine;
    try testing.expect(diff < 1000 * std.time.ns_per_s);
    var last = c.now();
    var sub_second = false;
    for (0..256) |_| {
        const t = c.now();
        try testing.expect(t >= last);
        last = t;
        if (t % std.time.ns_per_s != 0) sub_second = true;
    }
    try testing.expect(sub_second);
}

// ── bucket helpers ──────────────────────────────────────────────────────────

test "fillExponentialBucketsRange: two buckets are min and max" {
    var out: [2]f64 = undefined;
    try metrics.fillExponentialBucketsRange(&out, 1, 10);
    try testing.expectEqual(@as(f64, 1), out[0]);
    try testing.expectApproxEqRel(@as(f64, 10), out[1], 1e-12);
    var three: [3]f64 = undefined;
    try metrics.fillExponentialBucketsRange(&three, 1, 100);
    try testing.expectApproxEqRel(@as(f64, 10), three[1], 1e-12);
    try testing.expectApproxEqRel(@as(f64, 100), three[2], 1e-12);
}

// ── registry rules ──────────────────────────────────────────────────────────

test "unregister empties the family for a Vec handle that outlives it" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const v = try reg.counterVec("jobs_total", "Jobs.", &.{"k"});
    _ = try v.with(&.{"a"});
    _ = try v.with(&.{"b"});
    try testing.expectEqual(@as(usize, 2), v.len());
    try testing.expect(reg.unregister("jobs_total"));
    try testing.expectEqual(@as(usize, 0), v.len());
    // The handle keeps working off-exposition and `deinit` frees what it adds.
    _ = try v.with(&.{"c"});
    try testing.expectEqual(@as(usize, 1), v.len());
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try testing.expectEqualStrings("", try scrape(&reg, &aw));
}

test "counterFunc: exactly max_labels labels, a bad name leaves nothing behind" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const f = struct {
        fn f(_: ?*anyopaque) f64 {
            return 1;
        }
    }.f;
    var labels: [metrics.max_labels + 1]metrics.Label = undefined;
    const names = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h", "i" };
    for (&labels, names) |*l, n| l.* = .{ .name = n, .value = "v" };
    try reg.counterFunc("eight_total", "h", labels[0..metrics.max_labels], null, f);
    try testing.expectError(error.TooManyLabels, reg.counterFunc("nine_total", "h", &labels, null, f));
    const before = reg.families.items.len;
    try testing.expectError(error.InvalidName, reg.counterFunc("bad name", "h", &.{}, null, f));
    try testing.expectError(error.InvalidLabelName, reg.gaugeFunc("ok_name", "h", &.{.{ .name = "__x", .value = "v" }}, null, f));
    try testing.expectError(error.InvalidUtf8, reg.gaugeFunc("ok_name", "h\xff", &.{}, null, f));
    try testing.expectEqual(before, reg.families.items.len);
}

test "summary registration: quantile 0 and epsilon 0 are legal, a different quantile set is a mismatch" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.summary("s0", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0, .epsilon = 0.01 }} });
    _ = try reg.summary("s1", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = 0 }} });
    _ = try reg.summary("s2", "h", &.{}, .{ .objectives = &.{.{ .quantile = 1, .epsilon = 0.01 }} });
    _ = try reg.summary("s3", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.05 }} });
    try testing.expectError(error.ObjectivesMismatch, reg.summary("s3", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.9, .epsilon = 0.05 }} }));
    try testing.expectError(error.ObjectivesMismatch, reg.summary("s3", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.01 }} }));
    // A refused objective list registers nothing.
    const n = reg.families.items.len;
    try testing.expectError(error.InvalidObjectives, reg.summary("s4", "h", &.{}, .{ .objectives = &.{.{ .quantile = 1.0001, .epsilon = 0.01 }} }));
    try testing.expectError(error.InvalidObjectives, reg.summary("s4", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = 1 }} }));
    try testing.expectEqual(n, reg.families.items.len);
}

// ── scrape bookkeeping ──────────────────────────────────────────────────────

const TicketProbe = struct {
    reg: *Registry,
    seen: [3]u64 = .{ 99, 99, 99 },
    n: usize = 0,

    fn collect(ctx: ?*anyopaque, _: *metrics.Sink) anyerror!void {
        const p: *TicketProbe = @ptrCast(@alignCast(ctx.?));
        p.seen[p.n] = p.reg.scrapes.items[0];
        p.n += 1;
    }
};

test "scrape tickets count up, one per scrape; the size hint is the last output length" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var probe: TicketProbe = .{ .reg = &reg };
    try reg.registerCollector(&.{.{ .name = "probe", .help = "h", .kind = .gauge }}, .{ .ctx = &probe, .collect = TicketProbe.collect });
    const g = try reg.gauge("plain", "Plain.", &.{});
    g.set(12.5);
    try testing.expectEqual(@as(u64, 0), reg.scrape_seq);
    var last_len: usize = 0;
    for (0..3) |_| {
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw.deinit();
        last_len = (try scrape(&reg, &aw)).len;
        try testing.expectEqual(@as(usize, 0), reg.scrapes.items.len);
    }
    try testing.expectEqual(@as(usize, 3), probe.n);
    try testing.expectEqualSlices(u64, &.{ 0, 1, 2 }, &probe.seen);
    try testing.expectEqual(@as(u64, 3), reg.scrape_seq);
    try testing.expect(last_len > 0);
    try testing.expectEqual(last_len, reg.exposition_size_hint.load(.monotonic));
}

// ── Sink validation boundaries ──────────────────────────────────────────────

const SinkEdges = struct {
    fn collect(_: ?*anyopaque, sink: *metrics.Sink) anyerror!void {
        // cumulative counts equal to each other and to `count` are legal.
        try sink.histogram(0, &.{}, &.{ 1, 2 }, &.{ 3, 3 }, 1.5, 3);
        // quantile 0 and 1 are legal.
        try sink.summary(1, &.{}, &.{ .{ .quantile = 0, .epsilon = 0.01 }, .{ .quantile = 1, .epsilon = 0.01 } }, &.{ 1.5, 2.5 }, 4.0, 2);
    }
};

test "Sink: equal cumulative counts, a bucket equal to count, quantiles 0 and 1 are accepted" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    try reg.registerCollector(&.{
        .{ .name = "edge_h", .help = "h", .kind = .histogram },
        .{ .name = "edge_s", .help = "s", .kind = .summary },
    }, .{ .collect = SinkEdges.collect });
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const out = try scrape(&reg, &aw);
    try testing.expect(std.mem.find(u8, out, "edge_h_bucket{le=\"2\"} 3\n") != null);
    try testing.expect(std.mem.find(u8, out, "edge_s{quantile=\"0\"} 1.5\n") != null);
    try testing.expect(std.mem.find(u8, out, "edge_s{quantile=\"1\"} 2.5\n") != null);
    try testing.expectEqual(@as(?anyerror, null), reg.lastCollectorError());
}

// ── process collector ───────────────────────────────────────────────────────

test "ProcessCollector: each family carries its own value" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var pc: metrics.ProcessCollector = .{ .gpa = testing.allocator, .io = testing.io };
    try pc.register(&reg, "");
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const out = try scrape(&reg, &aw);

    const cpu = try sampleValue(out, "process_cpu_seconds_total");
    try testing.expect(cpu >= 0 and cpu < 1e8); // not the ~1.7e9 start time
    const rss = try sampleValue(out, "process_resident_memory_bytes");
    const vsize = try sampleValue(out, "process_virtual_memory_bytes");
    try testing.expect(rss > 0);
    try testing.expect(rss < vsize);
    const start = try sampleValue(out, "process_start_time_seconds");
    try testing.expect(start > 1.0e9 and start < 1.0e11);

    const unlimited: f64 = @floatFromInt(std.math.maxInt(u64));
    const limits = procnet.readPidLimits(testing.io, .self).?;
    const want_as: f64 = if (limits.maxAddressSpace()) |v| @floatFromInt(v) else unlimited;
    try testing.expectEqual(want_as, try sampleValue(out, "process_virtual_memory_max_bytes"));
    const want_fds: f64 = if (limits.maxOpenFiles()) |v| @floatFromInt(v) else unlimited;
    try testing.expectEqual(want_fds, try sampleValue(out, "process_max_fds"));

    // The network pair: bracketed by two direct readings of the same counters
    // (they only grow), receive and transmit not swapped.
    const n0 = try procnet.readPidNetstat(testing.allocator, testing.io, .self);
    defer n0.deinit(testing.allocator);
    if (n0.ipExtOctets()) |o0| {
        var aw2: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw2.deinit();
        const out2 = try scrape(&reg, &aw2);
        const n1 = try procnet.readPidNetstat(testing.allocator, testing.io, .self);
        defer n1.deinit(testing.allocator);
        const o1 = n1.ipExtOctets().?;
        const rx = try sampleValue(out2, "process_network_receive_bytes_total");
        const tx = try sampleValue(out2, "process_network_transmit_bytes_total");
        try testing.expect(@as(f64, @floatFromInt(o0.in)) <= rx and rx <= @as(f64, @floatFromInt(o1.in)));
        try testing.expect(@as(f64, @floatFromInt(o0.out)) <= tx and tx <= @as(f64, @floatFromInt(o1.out)));
    }

    const open: f64 = @floatFromInt(procnet.countFds(testing.io, .self).?);
    try testing.expectEqual(open, try sampleValue(out, "process_open_fds"));
}

// ── OpenMetrics ─────────────────────────────────────────────────────────────

test "OpenMetrics: NaN and infinities are spelled, not formatted" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    (try reg.gauge("g_nan", "h", &.{})).set(std.math.nan(f64));
    (try reg.gauge("g_inf", "h", &.{})).set(std.math.inf(f64));
    (try reg.gauge("g_ninf", "h", &.{})).set(-std.math.inf(f64));
    (try reg.gauge("g_m1", "h", &.{})).set(-1);
    (try reg.gauge("g_m2", "h", &.{})).set(-2);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try reg.writeOpenMetrics(&aw.writer);
    const out = aw.written();
    try testing.expect(std.mem.find(u8, out, "g_nan NaN\n") != null);
    try testing.expect(std.mem.find(u8, out, "g_inf +Inf\n") != null);
    try testing.expect(std.mem.find(u8, out, "g_ninf -Inf\n") != null);
    try testing.expect(std.mem.find(u8, out, "g_m1 -1.0\n") != null);
    try testing.expect(std.mem.find(u8, out, "g_m2 -2.0\n") != null);
}

// ── Accept negotiation ──────────────────────────────────────────────────────

test "Format.negotiate: order among clauses of equal weight and of equal specificity" {
    // Equal weight, both concrete: the first listed wins.
    try testing.expectEqual(Format.text, Format.negotiate("text/plain;version=0.0.4, application/openmetrics-text;version=1.0.0"));
    try testing.expectEqual(Format.openmetrics, Format.negotiate("application/openmetrics-text;version=1.0.0, text/plain;version=0.0.4"));
    // A concrete type outranks a wildcard that happens to carry a matching version.
    try testing.expectEqual(Format.openmetrics, Format.negotiate("text/*;version=0.0.4, application/openmetrics-text;version=1.0.0"));
    try testing.expectEqual(Format.openmetrics, Format.negotiate("*/*;version=0.0.4, application/openmetrics-text;version=1.0.0"));
}

test "Format.negotiate: type names compare case-insensitively; a wildcard never counts as the exact type" {
    try testing.expectEqual(Format.openmetrics, Format.negotiate("Application/OpenMetrics-Text"));
    // `application/*` is not the OpenMetrics type: no default version, no match.
    try testing.expectEqual(Format.text, Format.negotiate("application/*;q=0.9, text/plain;q=0.8"));
    // `Text/Plain` IS the text type (default version 0.0.4) and comes first.
    try testing.expectEqual(Format.text, Format.negotiate("Text/Plain, application/openmetrics-text;version=1.0.0"));
    // `text/*` is not: it does not match, the lower-weight OpenMetrics clause does.
    try testing.expectEqual(Format.openmetrics, Format.negotiate("text/*;q=0.9, application/openmetrics-text;version=1.0.0;q=0.8"));
}

// ── RequestMetrics ──────────────────────────────────────────────────────────

test "RequestMetrics.init: every refusal leaves the registry untouched" {
    const nan = std.math.nan(f64);
    const Case = struct { opts: metrics.RequestMetrics.Options, err: anyerror };
    const bad_buckets = [_][]const f64{ &.{ 1, nan }, &.{ 2, 1 }, &.{ 1, 1 } };
    var cases: std.ArrayList(Case) = .empty;
    defer cases.deinit(testing.allocator);
    try cases.append(testing.allocator, .{ .opts = .{ .counter_name = "bad name" }, .err = error.InvalidName });
    try cases.append(testing.allocator, .{ .opts = .{ .histogram_name = "bad name" }, .err = error.InvalidName });
    for (bad_buckets) |b| {
        try cases.append(testing.allocator, .{ .opts = .{ .buckets = b }, .err = error.InvalidBuckets });
        try cases.append(testing.allocator, .{ .opts = .{ .request_size_buckets = b }, .err = error.InvalidBuckets });
        try cases.append(testing.allocator, .{ .opts = .{ .response_size_buckets = b }, .err = error.InvalidBuckets });
    }
    try cases.append(testing.allocator, .{ .opts = .{ .request_size_buckets = &.{1}, .request_size_name = "bad name" }, .err = error.InvalidName });
    try cases.append(testing.allocator, .{ .opts = .{ .response_size_buckets = &.{1}, .response_size_name = "bad name" }, .err = error.InvalidName });
    for (cases.items, 0..) |c, i| {
        var reg = Registry.init(testing.allocator);
        defer reg.deinit();
        testing.expectError(c.err, metrics.RequestMetrics.init(&reg, c.opts)) catch |e| {
            std.debug.print("case {d}\n", .{i});
            return e;
        };
        if (reg.families.items.len != 0) {
            std.debug.print("case {d} left {d} families behind\n", .{ i, reg.families.items.len });
            return error.TestUnexpectedResult;
        }
    }
}

test "RequestMetrics.init: the 2xx touch series exists at once; every family is pinned" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const rm = try metrics.RequestMetrics.init(&reg, .{ .request_size_buckets = &.{1}, .response_size_buckets = &.{1} });
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const out = try scrape(&reg, &aw);
    try testing.expect(std.mem.find(u8, out, "http_requests_total{method=\"get\",code=\"2xx\"} 0\n") != null);
    try testing.expect(std.mem.find(u8, out, "code=\"3xx\"") == null);
    try testing.expect(!reg.unregister(rm.options.in_flight_name));
    try testing.expect(!reg.unregister(rm.options.counter_name));
    try testing.expect(!reg.unregister(rm.options.histogram_name));
    try testing.expect(!reg.unregister(rm.options.request_size_name));
    try testing.expect(!reg.unregister(rm.options.response_size_name));
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

const get_wire = "GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";

fn statusHandler(comptime code: u16) *const fn (*router.Ctx) anyerror!void {
    return struct {
        fn f(ctx: *router.Ctx) anyerror!void {
            ctx.res.setStatus(code);
            try ctx.res.writeAll("x");
        }
    }.f;
}

fn counterAt(reg: *Registry, rm: *const metrics.RequestMetrics, code: []const u8) !*Counter {
    return reg.counter(rm.options.counter_name, rm.options.counter_help, &.{
        .{ .name = "method", .value = "get" }, .{ .name = "code", .value = code },
    });
}

test "middleware: status 100 is 1xx, 599 is 5xx, 600 is other" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try metrics.RequestMetrics.init(&reg, .{});
    var buf: [4096]u8 = undefined;
    inline for (.{ .{ 100, "1xx" }, .{ 599, "5xx" }, .{ 600, "other" } }) |c| {
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(rm.middleware());
        try r.get("/x", statusHandler(c[0]));
        _ = runWire(&r, get_wire, &buf);
        try testing.expectEqual(@as(u64, 1), (try counterAt(&reg, &rm, c[1])).value());
    }
}

test "middleware: .code granularity, a status wider than three digits is other" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try metrics.RequestMetrics.init(&reg, .{ .status = .code });
    var buf: [4096]u8 = undefined;
    inline for (.{ .{ 418, "418" }, .{ 1000, "other" } }) |c| {
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(rm.middleware());
        try r.get("/x", statusHandler(c[0]));
        _ = runWire(&r, get_wire, &buf);
        try testing.expectEqual(@as(u64, 1), (try counterAt(&reg, &rm, c[1])).value());
    }
}

fn okHandler(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

test "middleware: series are memoized in the pub caches, and the caches are what the hot path reads" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try metrics.RequestMetrics.init(&reg, .{ .request_size_buckets = &.{ 10, 1000 }, .response_size_buckets = &.{ 1, 10 } });
    const mi = @backingInt(http.Method.get);
    try testing.expect(rm.counters[mi][2].load(.acquire) == null);
    try testing.expect(rm.histograms[mi].load(.acquire) == null);
    try testing.expect(rm.request_size_histograms[mi].load(.acquire) == null);
    try testing.expect(rm.response_size_histograms[mi].load(.acquire) == null);

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.get("/x", okHandler);
    var buf: [4096]u8 = undefined;
    _ = runWire(&r, get_wire, &buf);

    // Populated by the first request, pointing at the registry's series.
    try testing.expect(rm.counters[mi][2].load(.acquire).? == try counterAt(&reg, &rm, "2xx"));
    try testing.expect(rm.histograms[mi].load(.acquire) != null);
    try testing.expect(rm.request_size_histograms[mi].load(.acquire) != null);
    try testing.expect(rm.response_size_histograms[mi].load(.acquire) != null);
    try testing.expect(rm.request_size_histograms[mi].load(.acquire).? != rm.response_size_histograms[mi].load(.acquire).?);

    // Replace the cached series by private ones: the next request must use them.
    var c: Counter = .{};
    var no_counts: [0]u64 = .{};
    var h: Histogram = .{ .upper_bounds = &.{}, .bucket_counts = &no_counts };
    var req_h: Histogram = .{ .upper_bounds = &.{}, .bucket_counts = &no_counts };
    var res_h: Histogram = .{ .upper_bounds = &.{}, .bucket_counts = &no_counts };
    rm.counters[mi][2].store(&c, .release);
    rm.histograms[mi].store(&h, .release);
    rm.request_size_histograms[mi].store(&req_h, .release);
    rm.response_size_histograms[mi].store(&res_h, .release);
    _ = runWire(&r, get_wire, &buf);
    try testing.expectEqual(@as(u64, 1), c.value());
    try testing.expectEqual(@as(u64, 1), h.count());
    try testing.expectEqual(@as(u64, 1), req_h.count());
    try testing.expectEqual(@as(u64, 1), res_h.count());
    try testing.expectEqual(@as(f64, 2), res_h.sum()); // "ok"
    try testing.expect(req_h.sum() >= "GET".len + get_wire.len - 20);
    // The registry's own series saw only the first request.
    try testing.expectEqual(@as(u64, 1), (try counterAt(&reg, &rm, "2xx")).value());
}

// ── summary engine ──────────────────────────────────────────────────────────

test "summary: a rotated-out stream with a merged list starts clean" {
    var s = try summary_mod.Summary.init(testing.allocator, .{
        .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.05 }},
        .max_age_ns = 100,
        .age_buckets = 2,
    });
    defer s.deinit();
    // 1000 values: every stream flushes at least once, so its list `l` is non-empty.
    for (1..1001) |i| s.observe(@floatFromInt(i), 1);
    // Everything expires; three new values.
    s.observe(5e6, 1000);
    s.observe(6e6, 1000);
    s.observe(7e6, 1000);
    var q: [1]f64 = undefined;
    const snap = s.snapshot(1000, &q);
    try testing.expectEqual(@as(u64, 1003), snap.count);
    try testing.expectEqual(@as(f64, 6e6), q[0]);
}

test "summary: no objectives allocates nothing" {
    var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var s = try summary_mod.Summary.init(fa.allocator(), .{});
    defer s.deinit();
    s.observe(1, 1);
    s.observe(2, 2);
    var q: [0]f64 = undefined;
    const snap = s.snapshot(3, &q);
    try testing.expectEqual(@as(u64, 2), snap.count);
    try testing.expectEqual(@as(f64, 3), snap.sum);
    try testing.expectEqual(@as(usize, 0), fa.allocated_bytes);
}

test "summary: buf_cap 1 flushes every observation" {
    var s = try summary_mod.Summary.init(testing.allocator, .{
        .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.05 }},
        .buf_cap = 1,
    });
    defer s.deinit();
    s.observe(3, 1);
    s.observe(1, 1);
    s.observe(2, 1);
    var q: [1]f64 = undefined;
    _ = s.snapshot(1, &q);
    try testing.expectEqual(@as(f64, 2), q[0]);
}

test "summary: an allocation failure while a stream flushes is counted once per failed flush" {
    var fa = testing.FailingAllocator.init(testing.allocator, .{});
    var s = try summary_mod.Summary.init(fa.allocator(), .{
        .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.05 }},
        .age_buckets = 1,
        .buf_cap = 500,
    });
    defer s.deinit();
    fa.fail_index = fa.alloc_index; // the next allocation (the list's first node) fails
    for (0..500) |i| s.observe(@floatFromInt(i), 1);
    // One failed flush of a 500-value stream buffer: `dropped` says 1 although
    // up to 500 observations left the quantile stream (review finding L3).
    try testing.expectEqual(@as(u64, 1), s.droppedInserts());
    var q: [1]f64 = undefined;
    const snap = s.snapshot(1, &q);
    try testing.expectEqual(@as(u64, 500), snap.count); // _count/_sum unaffected
}

// ── review-finding probes ───────────────────────────────────────────────────

test "finding M1: a summary's derived _sum/_count names are not collision-checked" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.summary("lat", "Latency.", &.{}, .{ .objectives = &.{.{ .quantile = 0.5, .epsilon = 0.05 }} });
    const second = reg.counter("lat_count", "Other.", &.{});
    if (f1_fixed) {
        try testing.expectError(error.NameCollision, second);
    } else {
        // Known defect: accepted; the exposition then has two `lat_count`
        // samples and two TYPE lines for it, which Prometheus rejects as a whole.
        _ = try second;
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw.deinit();
        const out = try scrape(&reg, &aw);
        try testing.expect(std.mem.find(u8, out, "# TYPE lat_count counter") != null);
        try testing.expect(std.mem.find(u8, out, "\nlat_count 0\n") != null);
    }
    // The other registration order is equally unchecked.
    var reg2 = Registry.init(testing.allocator);
    defer reg2.deinit();
    _ = try reg2.counter("rt_sum", "Other.", &.{});
    const s2 = reg2.summary("rt", "Latency.", &.{}, .{});
    if (f1_fixed) {
        try testing.expectError(error.NameCollision, s2);
    } else {
        _ = try s2;
    }
}

test "finding M2 (inferred, not reproduced): a registration that fails inside familyLocked leaves no half-registered family" {
    var duplicate_seen = false;
    var warm: usize = 0;
    while (warm < 40) : (warm += 3) {
        var k: usize = 0;
        while (k < 24) : (k += 1) {
            var fa = testing.FailingAllocator.init(testing.allocator, .{});
            var reg = Registry.init(fa.allocator());
            defer reg.deinit();
            var name_buf: [32]u8 = undefined;
            for (0..warm) |i| {
                const n = std.fmt.bufPrint(&name_buf, "warm_{d}", .{i}) catch unreachable;
                _ = try reg.counter(n, "h", &.{});
            }
            fa.fail_index = fa.alloc_index + k;
            _ = reg.counter("target_total", "h", &.{}) catch {};
            fa.fail_index = std.math.maxInt(usize);
            const c = try reg.counter("target_total", "h", &.{});
            c.inc();
            var aw: std.Io.Writer.Allocating = .init(testing.allocator);
            defer aw.deinit();
            try reg.writeText(&aw.writer);
            const out = aw.written();
            const first = std.mem.find(u8, out, "# TYPE target_total ");
            if (first) |i| {
                if (std.mem.findPos(u8, out, i + 1, "# TYPE target_total ") != null) duplicate_seen = true;
            }
            if (first == null) duplicate_seen = true; // the counter we incremented is not exposed
        }
    }
    // Not reproduced (review finding M2 is inferred from the source: the failing
    // allocation would have to be exactly the `family_index.put` growth); this
    // sweep stays as a regression guard.
    try testing.expect(!duplicate_seen);
}
