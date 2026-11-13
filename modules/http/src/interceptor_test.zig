// SPDX-License-Identifier: MIT

//! `Client.Options.interceptors` (2026-11-13): order, header injection,
//! retry without a leak, short-circuit, redirects inside one call, the plain
//! path, streaming left alone, and the whole-chain deadline. A loopback
//! `Server` is the origin. The two interceptors here (a bearer-token header
//! and a call counter) are test-only examples, not part of the module.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");

const http = @import("root.zig");
const Client = @import("Client.zig");
const Server = @import("Server.zig");

var hits_flaky: std.atomic.Value(u32) = .init(0);
var hits_all: std.atomic.Value(u32) = .init(0);

fn handler(req: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
    _ = hits_all.fetchAdd(1, .monotonic);
    const p = req.path;
    if (std.mem.eql(u8, p, "/auth")) return rw.writeAll(req.header("authorization") orelse "none");
    if (std.mem.eql(u8, p, "/flaky")) {
        if (hits_flaky.fetchAdd(1, .monotonic) == 0) {
            rw.status = 503;
            return rw.writeAll("busy");
        }
        return rw.writeAll("ok");
    }
    if (std.mem.eql(u8, p, "/always503")) {
        rw.status = 503;
        return rw.writeAll("busy");
    }
    if (std.mem.startsWith(u8, p, "/r/")) {
        const n = std.fmt.parseInt(u32, p[3..], 10) catch 0;
        if (n == 0) return rw.writeAll(req.header("authorization") orelse "none");
        var buf: [32]u8 = undefined;
        rw.status = 302;
        try rw.setHeader("Location", try std.mem.print(&buf, "/r/{d}", .{n - 1}));
        return rw.writeAll("");
    }
    return rw.writeAll("hello");
}

fn serve(s: *Server) void {
    s.serve() catch {};
}

/// Origin on loopback for one test.
const Origin = struct {
    server: Server,
    thread: std.Thread,
    port: u16,

    fn start(o: *Origin, io: std.Io) !void {
        hits_flaky.store(0, .monotonic);
        hits_all.store(0, .monotonic);
        o.server = Server.init(io, testing.allocator, .{ .handler = handler });
        errdefer o.server.deinit();
        o.server.bind() catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        o.port = o.server.boundAddress().getPort();
        o.thread = try std.Thread.spawn(.{}, serve, .{&o.server});
    }

    fn stop(o: *Origin) void {
        o.server.shutdown();
        o.thread.join();
        o.server.deinit();
    }

    fn url(o: *const Origin, buf: []u8, path: []const u8) []const u8 {
        return std.mem.print(buf, "http://127.0.0.1:{d}{s}", .{ o.port, path }) catch unreachable;
    }
};

fn body(res: *Client.Response) ![]u8 {
    return res.readAllAlloc(testing.allocator, 64);
}

// ── test-only interceptors ──────────────────────────────────────────────────

/// Adds `Authorization: Bearer <token>`; the header array lives on this
/// frame, which outlives the `proceed` it is used by.
const Bearer = struct {
    token: []const u8,

    fn intercept(ctx: ?*anyopaque, chain: *Client.Chain) Client.Error!Client.Response {
        const self: *const Bearer = @ptrCast(@alignCast(ctx.?));
        var hdrs: [9]http.Header = undefined;
        const have = chain.options.headers;
        if (have.len > 8) return error.Intercepted;
        @memcpy(hdrs[0..have.len], have);
        var val_buf: [64]u8 = undefined;
        hdrs[have.len] = .{
            .name = "Authorization",
            .value = std.fmt.bufPrint(&val_buf, "Bearer {s}", .{self.token}) catch return error.Intercepted,
        };
        chain.options.headers = hdrs[0 .. have.len + 1];
        return chain.proceed();
    }

    fn interceptor(self: *Bearer) Client.Interceptor {
        return .{ .ctx = self, .intercept = intercept };
    }
};

/// Counts calls and records entry/exit into a shared log.
const Tracer = struct {
    name: u8,
    log: *Log,
    calls: u32 = 0,

    fn intercept(ctx: ?*anyopaque, chain: *Client.Chain) Client.Error!Client.Response {
        const self: *Tracer = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        self.log.add(self.name, '>');
        defer self.log.add(self.name, '<');
        return chain.proceed();
    }

    fn interceptor(self: *Tracer) Client.Interceptor {
        return .{ .ctx = self, .intercept = intercept };
    }
};

const Log = struct {
    buf: [32]u8 = undefined,
    len: usize = 0,
    fn add(l: *Log, a: u8, b: u8) void {
        l.buf[l.len] = a;
        l.buf[l.len + 1] = b;
        l.len += 2;
    }
    fn text(l: *const Log) []const u8 {
        return l.buf[0..l.len];
    }
};

/// Retries a 5xx up to `max` times, deinit-ing every answer it drops.
const Retry = struct {
    max: u32,
    io: std.Io,
    attempts: u32 = 0,

    fn intercept(ctx: ?*anyopaque, chain: *Client.Chain) Client.Error!Client.Response {
        const self: *Retry = @ptrCast(@alignCast(ctx.?));
        while (true) {
            self.attempts += 1;
            var res = try chain.proceed();
            if (res.status < 500 or self.attempts > self.max) return res;
            res.deinit();
            self.io.sleep(.fromMilliseconds(5), .awake) catch return error.Canceled;
        }
    }
};

const Refuse = struct {
    fn intercept(_: ?*anyopaque, _: *Client.Chain) Client.Error!Client.Response {
        return error.Intercepted;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

test "interceptors: the first in the list is the outermost; the order is A> B> exchange <B <A" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var origin: Origin = undefined;
    try origin.start(io);
    defer origin.stop();

    var log: Log = .{};
    var a: Tracer = .{ .name = 'A', .log = &log };
    var b: Tracer = .{ .name = 'B', .log = &log };
    const list = [_]Client.Interceptor{ a.interceptor(), b.interceptor() };
    var client = Client.init(io, testing.allocator, .{ .interceptors = &list });
    defer client.deinit();

    var ub: [64]u8 = undefined;
    var res = try client.request(.get, origin.url(&ub, "/"), .{});
    defer res.deinit();
    const text = try body(&res);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings("hello", text);
    try testing.expectEqualStrings("A>B>B<A<", log.text());
    try testing.expectEqual(@as(u32, 1), a.calls);
    try testing.expectEqual(@as(u32, 1), b.calls);
}

test "interceptors: a header added by an interceptor reaches the server, on request and requestPlain" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var origin: Origin = undefined;
    try origin.start(io);
    defer origin.stop();

    var bearer: Bearer = .{ .token = "s3cret" };
    const list = [_]Client.Interceptor{bearer.interceptor()};
    var client = Client.init(io, testing.allocator, .{ .interceptors = &list });
    defer client.deinit();

    var ub: [64]u8 = undefined;
    const extra = [_]http.Header{.{ .name = "X-Other", .value = "1" }};
    for ([_]bool{ false, true }) |plain| {
        var res = if (plain)
            try client.requestPlain(.get, origin.url(&ub, "/auth"), .{ .headers = &extra })
        else
            try client.request(.get, origin.url(&ub, "/auth"), .{ .headers = &extra });
        defer res.deinit();
        const text = try body(&res);
        defer testing.allocator.free(text);
        try testing.expectEqualStrings("Bearer s3cret", text);
    }
    // Too many caller headers: the interceptor refuses, nothing is sent.
    const before = hits_all.load(.monotonic);
    var many: [9]http.Header = @splat(.{ .name = "X-A", .value = "1" });
    try testing.expectError(error.Intercepted, client.request(.get, origin.url(&ub, "/auth"), .{ .headers = &many }));
    try testing.expectEqual(before, hits_all.load(.monotonic));
}

test "interceptors: a retrying interceptor returns the second Response and leaks nothing" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var origin: Origin = undefined;
    try origin.start(io);
    defer origin.stop();

    var retry: Retry = .{ .max = 3, .io = io };
    const list = [_]Client.Interceptor{.{ .ctx = &retry, .intercept = Retry.intercept }};
    var client = Client.init(io, testing.allocator, .{ .interceptors = &list });
    defer client.deinit();

    var ub: [64]u8 = undefined;
    for ([_]bool{ false, true }) |plain| {
        hits_flaky.store(0, .monotonic);
        retry.attempts = 0;
        var res = if (plain)
            try client.requestPlain(.get, origin.url(&ub, "/flaky"), .{})
        else
            try client.request(.get, origin.url(&ub, "/flaky"), .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const text = try body(&res);
        defer testing.allocator.free(text);
        try testing.expectEqualStrings("ok", text);
        try testing.expectEqual(@as(u32, 2), retry.attempts);
    }

    // A budget that runs out returns the last 503 itself, still leak-free.
    retry.attempts = 0;
    var res = try client.request(.get, origin.url(&ub, "/always503"), .{});
    defer res.deinit();
    try testing.expectEqual(@as(u16, 503), res.status);
    try testing.expectEqual(@as(u32, 4), retry.attempts);
}

test "interceptors: 0 proceeds short-circuits with error.Intercepted and nothing is dialed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var origin: Origin = undefined;
    try origin.start(io);
    defer origin.stop();

    const list = [_]Client.Interceptor{.{ .intercept = Refuse.intercept }};
    var client = Client.init(io, testing.allocator, .{ .interceptors = &list });
    defer client.deinit();
    var ub: [64]u8 = undefined;
    try testing.expectError(error.Intercepted, client.request(.get, origin.url(&ub, "/"), .{}));
    try testing.expectError(error.Intercepted, client.requestPlain(.get, origin.url(&ub, "/"), .{}));
    try testing.expectEqual(@as(u32, 0), hits_all.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), client.dialCount());
}

test "interceptors: a redirect chain runs inside one call; the interceptor sees one" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var origin: Origin = undefined;
    try origin.start(io);
    defer origin.stop();

    var log: Log = .{};
    var tracer: Tracer = .{ .name = 'T', .log = &log };
    var bearer: Bearer = .{ .token = "tok" };
    const list = [_]Client.Interceptor{ tracer.interceptor(), bearer.interceptor() };
    var client = Client.init(io, testing.allocator, .{ .interceptors = &list });
    defer client.deinit();

    var ub: [64]u8 = undefined;
    var res = try client.request(.get, origin.url(&ub, "/r/2"), .{});
    defer res.deinit();
    const text = try body(&res);
    defer testing.allocator.free(text);
    // Same-origin hops keep the injected credential.
    try testing.expectEqualStrings("Bearer tok", text);
    try testing.expectEqual(@as(u32, 1), tracer.calls);
    try testing.expectEqual(@as(u32, 3), hits_all.load(.monotonic));
}

test "interceptors: requestStreaming is not intercepted" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var origin: Origin = undefined;
    try origin.start(io);
    defer origin.stop();

    var log: Log = .{};
    var tracer: Tracer = .{ .name = 'T', .log = &log };
    const refuse: Client.Interceptor = .{ .intercept = Refuse.intercept };
    const list = [_]Client.Interceptor{ tracer.interceptor(), refuse };
    var client = Client.init(io, testing.allocator, .{ .interceptors = &list });
    defer client.deinit();

    var ub: [64]u8 = undefined;
    for ([_]bool{ false, true }) |plain| {
        var up = if (plain)
            try client.requestStreamingPlain(.post, origin.url(&ub, "/"), .{}, 3)
        else
            try client.requestStreaming(.post, origin.url(&ub, "/"), .{}, 3);
        try up.writer().writeAll("abc");
        var res = try up.finish();
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
    }
    try testing.expectEqual(@as(u32, 0), tracer.calls);
    // ... while the same list does intercept `request`.
    try testing.expectError(error.Intercepted, client.request(.get, origin.url(&ub, "/"), .{}));
    try testing.expectEqual(@as(u32, 1), tracer.calls);
}

test "interceptors: total_timeout_ms bounds the whole chain, retries included" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var origin: Origin = undefined;
    try origin.start(io);
    defer origin.stop();

    // Retries forever; only the deadline can end it.
    var retry: Retry = .{ .max = std.math.maxInt(u32) - 1, .io = io };
    const list = [_]Client.Interceptor{.{ .ctx = &retry, .intercept = Retry.intercept }};
    var client = Client.init(io, testing.allocator, .{ .interceptors = &list, .total_timeout_ms = 300 });
    defer client.deinit();

    var ub: [64]u8 = undefined;
    for ([_]bool{ false, true }) |plain| {
        retry.attempts = 0;
        const r = if (plain)
            client.requestPlain(.get, origin.url(&ub, "/always503"), .{})
        else
            client.request(.get, origin.url(&ub, "/always503"), .{});
        if (r) |ok| {
            var res = ok;
            res.deinit();
            return error.TestExpectedError;
        } else |err| try testing.expect(err == error.Timeout or err == error.Canceled);
        try testing.expect(retry.attempts >= 2);
    }
}

test "interceptors: none set — the call is the plain one (an empty list changes nothing)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var origin: Origin = undefined;
    try origin.start(io);
    defer origin.stop();
    var client = Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var ub: [64]u8 = undefined;
    var res = try client.request(.get, origin.url(&ub, "/auth"), .{});
    defer res.deinit();
    const text = try body(&res);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings("none", text);
}
