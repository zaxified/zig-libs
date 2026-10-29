// SPDX-License-Identifier: MIT

//! No-panic sweep tests (2026-10-29, wave GH): one test per finding, each
//! failing (panic or wrong result) when its fix is removed. Names end with
//! "(sweep ME-n)".

const std = @import("std");
const testing = std.testing;
const router = @import("router");
const http = @import("http");
const metrics = @import("root.zig");

fn okHandler(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
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

test "approxRequestSize: a peer-declared Content-Length of 2^64-1 saturates, never overflows (sweep ME-1)" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    var rm = try metrics.RequestMetrics.init(&reg, .{ .request_size_buckets = &.{1000} });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.get("/x", okHandler);
    var buf: [4096]u8 = undefined;
    // `serveStream` has no body cap by default (`max_body_bytes = null`), so
    // the declared length reaches the middleware.
    const wire = "GET /x HTTP/1.1\r\nHost: t\r\nContent-Length: 18446744073709551615\r\nConnection: close\r\n\r\n";
    const got = runWire(&r, wire, &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const h = rm.request_size_histograms[@backingInt(http.Method.get)].load(.acquire).?;
    try testing.expectEqual(@as(u64, 1), h.count());
    try testing.expect(h.sum() >= 1.8e19);
}

test "Histogram.cumulativeBucket: an index past the last bound is the +Inf bucket (sweep ME-2)" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    const h = try reg.histogram("sweep_h", "h", &.{}, &.{ 1, 2 });
    h.observe(0.5);
    h.observe(1.5);
    h.observe(10); // beyond every bound: only in +Inf
    try testing.expectEqual(@as(u64, 1), h.cumulativeBucket(0));
    try testing.expectEqual(@as(u64, 2), h.cumulativeBucket(1));
    try testing.expectEqual(@as(u64, 3), h.cumulativeBucket(2));
    try testing.expectEqual(@as(u64, 3), h.cumulativeBucket(std.math.maxInt(usize)));
    // A histogram with no finite bound has only +Inf.
    const e = try reg.histogram("sweep_e", "e", &.{}, &.{});
    e.observe(1);
    try testing.expectEqual(@as(u64, 1), e.cumulativeBucket(0));
}

test "exemplar: a huge label list is refused before the duplicate scan, not in O(n^2) (sweep R1-4)" {
    // 200k distinct same-length names: the pairwise duplicate scan alone
    // would be ~2e10 compares; the up-front count check refuses at once.
    const n = 200_000;
    const names = try testing.allocator.alloc(u8, n * 7);
    defer testing.allocator.free(names);
    const labels = try testing.allocator.alloc(metrics.Label, n);
    defer testing.allocator.free(labels);
    for (labels, 0..) |*l, i| {
        const name = names[i * 7 ..][0..7];
        _ = std.fmt.bufPrint(name, "a{d:0>6}", .{i}) catch unreachable;
        l.* = .{ .name = name, .value = "" };
    }
    var c: metrics.Counter = .{};
    try testing.expectError(error.InvalidExemplar, c.addWithExemplar(1, labels, null));
    try testing.expectEqual(@as(u64, 0), c.value());
}

test "Summary.snapshot: an output slice shorter than the objectives is filled as far as it goes (sweep ME-3)" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    const s = try reg.summary("sweep_s", "s", &.{}, .{ .objectives = &metrics.default_objectives });
    for (1..11) |i| s.observe(@floatFromInt(i));
    var two: [2]f64 = .{ -1, -1 };
    const snap = s.snapshot(&two);
    try testing.expectEqual(@as(u64, 10), snap.count);
    try testing.expect(two[0] >= 1 and two[0] <= 10);
    try testing.expect(two[1] >= 1 and two[1] <= 10);
    var none: [0]f64 = .{};
    try testing.expectEqual(@as(u64, 10), s.snapshot(&none).count);
}

test "registration: a name too long for the scratch buffer still collides with a derived name (sweep ME-5)" {
    const a = testing.allocator;
    var reg = metrics.Registry.init(a);
    defer reg.deinit();
    const base = try a.alloc(u8, 300);
    defer a.free(base);
    @memset(base, 'a');
    const taken = try std.mem.concat(a, u8, &.{ base, "_sum" });
    defer a.free(taken);
    _ = try reg.counter(taken, "c", &.{});
    // The histogram would emit `<base>_sum` as well: a duplicate sample.
    try testing.expectError(error.NameCollision, reg.histogram(base, "h", &.{}, &.{1}));
    try testing.expectError(error.NameCollision, reg.summary(base, "s", &.{}, .{}));
    // Same length as `<base>_bucket` but another suffix: no collision, the
    // scan matches the suffix itself, not only the prefix and the length.
    const other_base = try a.alloc(u8, 300);
    defer a.free(other_base);
    @memset(other_base, 'b');
    const near = try std.mem.concat(a, u8, &.{ other_base, "_xbucke" });
    defer a.free(near);
    _ = try reg.counter(near, "c", &.{});
    _ = try reg.histogram(other_base, "h", &.{}, &.{1});
}

test "a new series' label value past max_label_value_len is an error, existing series unaffected (sweep review R1-1)" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    reg.max_label_value_len = 8;
    const v = try reg.counterVec("req_total", "h", &.{"tenant"});
    (try v.with(&.{"12345678"})).inc();
    try testing.expectError(error.LabelValueTooLong, v.with(&.{"123456789"}));
    try testing.expectEqual(@as(usize, 1), v.family.children.items.len);
    // A lowered limit refuses only new series.
    reg.max_label_value_len = 4;
    try testing.expectEqual(@as(u64, 1), (try v.with(&.{"12345678"})).value());
    // The labelled getters refuse before touching the registry: no empty
    // family is left behind.
    const n = reg.families.items.len;
    try testing.expectError(error.LabelValueTooLong, reg.counter("other_total", "h", &.{.{ .name = "a", .value = "12345" }}));
    try testing.expectError(error.LabelValueTooLong, reg.gaugeFunc("g", "h", &.{.{ .name = "a", .value = "12345" }}, null, struct {
        fn f(_: ?*anyopaque) f64 {
            return 0;
        }
    }.f));
    try testing.expectEqual(n, reg.families.items.len);
}

test "a family stops at max_series_per_family; delete frees a slot (sweep review R1-1)" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    reg.max_series_per_family = 3;
    const v = try reg.counterVec("req_total", "h", &.{"tenant"});
    for ([_][]const u8{ "a", "b", "c" }) |t| (try v.with(&.{t})).inc();
    try testing.expectError(error.TooManySeries, v.with(&.{"d"}));
    try testing.expectError(error.TooManySeries, reg.counter("req_total", "h", &.{.{ .name = "tenant", .value = "d" }}));
    // Existing series keep working at the cap.
    (try v.with(&.{"a"})).inc();
    try testing.expectEqual(@as(u64, 2), (try v.with(&.{"a"})).value());
    try testing.expect(v.delete(&.{"b"}));
    (try v.with(&.{"d"})).inc();
    try testing.expectEqual(@as(usize, 3), v.family.children.items.len);

    const f = struct {
        fn f(_: ?*anyopaque) f64 {
            return 0;
        }
    }.f;
    for ([_][]const u8{ "x", "y", "z" }) |t| try reg.gaugeFunc("fn_g", "h", &.{.{ .name = "k", .value = t }}, null, f);
    try testing.expectError(error.TooManySeries, reg.gaugeFunc("fn_g", "h", &.{.{ .name = "k", .value = "w" }}, null, f));
}

test "a summary epsilon below min_epsilon is refused at registration (sweep review R1-2, ME-4)" {
    var reg = metrics.Registry.init(testing.allocator);
    defer reg.deinit();
    for ([_]f64{ 0, 1e-12, 0.99e-4 }) |eps| {
        try testing.expectError(error.InvalidObjectives, reg.summary("s", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.99, .epsilon = eps }} }));
    }
    try testing.expectEqual(@as(usize, 0), reg.families.items.len);
    const s = try reg.summary("s", "h", &.{}, .{ .objectives = &.{.{ .quantile = 0.99, .epsilon = metrics.min_epsilon }} });
    s.observe(1);
}
