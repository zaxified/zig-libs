// SPDX-License-Identifier: MIT

//! middleware.zig -- `Logger`, a `router.Middleware` that writes one access-log
//! line per request to a `Sink`.
//!
//! ```zig
//! var logger = accesslog.Logger{ .sink = &sink, .clock = .{ .now_ns = myNowNs } };
//! try router.use(logger.middleware());
//! ```
//!
//! The line's format is the `Sink`'s (`Sink.Options.format`); the middleware
//! only builds the `Entry` (`entryFromRequest`) and hands it over, so the
//! Sink's thread-safety, escaping and "never fail the request" rules apply
//! unchanged.
//!
//! ## Clock
//!
//! The module never reads a clock (module doc, "Time contract"), so the caller
//! injects `Clock`: one function returning nanoseconds. It is called twice per
//! request -- before and after the rest of the chain -- the first value is
//! `Entry.timestamp_ns`, the difference `Entry.latency_ns` (null if the clock
//! went backwards). One clock means one source for both: pass a wall clock and
//! a step of the system time can skew a latency; the caller who needs better
//! injects a clock that is wall-anchored but monotonic.
//!
//! ## Ids, user, extra fields
//!
//! Optional functions of the request (`StrFn`) supply `request_id`, `trace_id`,
//! `span_id` and `user`; `extra_fn` fills `Entry.extra`. They run AFTER the
//! chain, so a value an inner middleware or the handler established (an
//! authenticated user, `requestid.current()`) is visible. This module does not
//! depend on `requestid` or `tracecontext`; wiring is one line each:
//!
//! ```zig
//! fn rid(_: *const router.Ctx) ?[]const u8 { return requestid.current(); }
//! logger.request_id = rid;
//! ```
//!
//! ## Errors
//!
//! A handler error is re-raised unchanged (`http.Server` answers it). The line
//! is written either way; on an error the status logged is 500, the status
//! `http.Server` sends when nothing was sent yet (if the handler had already
//! sent a different status, the log still says 500 -- the connection is
//! closing anyway).

const std = @import("std");
const router = @import("router");
const root = @import("root.zig");

pub const Logger = struct {
    /// Where lines go; also fixes the format (`sink.options.format`).
    sink: *root.Sink,
    clock: Clock,
    /// Fills `Entry.time_formatted` (Combined's `[%t]`); null leaves it null,
    /// so Combined prints the raw nanosecond timestamp.
    time_format: ?TimeFormatFn = null,
    request_id: ?StrFn = null,
    trace_id: ?StrFn = null,
    span_id: ?StrFn = null,
    user: ?StrFn = null,
    extra_fn: ?ExtraFn = null,
    /// Conditional logging (nginx `access_log ... if=`, Apache `CustomLog
    /// ... env=`): called after the chain; false = write no line for this
    /// request. Sampling is this too (log one request in N, every error).
    /// null = log every request.
    keep: ?KeepFn = null,

    /// Whether to log this request; `failed` = the chain returned an error.
    pub const KeepFn = *const fn (ctx: *const router.Ctx, failed: bool) bool;

    /// Nanoseconds since the Unix epoch.
    pub const Clock = struct {
        context: ?*anyopaque = null,
        now_ns: *const fn (context: ?*anyopaque) i64,
    };

    /// Render `ns` (a `Clock` reading) as the Combined time string into `buf`
    /// and return the used slice, or null to leave it unset. `buf` is 64 bytes.
    pub const TimeFormatFn = *const fn (ns: i64, buf: []u8) ?[]const u8;

    /// A string for this request, valid until the function is called again on
    /// this thread or the request ends. Null: not available.
    pub const StrFn = *const fn (ctx: *const router.Ctx) ?[]const u8;

    /// Fill `out` and return the used prefix; values and keys must stay valid
    /// until the line is written. See `Entry.extra` for the key rules.
    pub const ExtraFn = *const fn (ctx: *const router.Ctx, out: *[max_extra]root.Field) []const root.Field;

    /// Most extra fields `extra_fn` can return.
    pub const max_extra = 8;

    pub fn middleware(l: *const Logger) router.Middleware {
        return .{ .state = @constCast(l), .run = run };
    }

    fn run(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
        const l: *const Logger = @ptrCast(@alignCast(state.?));
        const start = l.clock.now_ns(l.clock.context);
        const result = next.run(ctx);
        const end = l.clock.now_ns(l.clock.context);
        if (l.keep) |keep| if (!keep(ctx, std.meta.isError(result))) return result;

        var time_buf: [64]u8 = undefined;
        var addr_buf: [64]u8 = undefined;
        var extra_buf: [max_extra]root.Field = undefined;
        var entry = root.entryFromRequest(ctx.req, ctx.res, &addr_buf, .{
            .timestamp_ns = start,
            .time_formatted = if (l.time_format) |f| f(start, &time_buf) else null,
            .latency_ns = if (end >= start) @intCast(end - start) else null,
            .request_id = if (l.request_id) |f| f(ctx) else null,
            .trace_id = if (l.trace_id) |f| f(ctx) else null,
            .span_id = if (l.span_id) |f| f(ctx) else null,
            .user = if (l.user) |f| f(ctx) else null,
            .extra = if (l.extra_fn) |f| f(ctx, &extra_buf) else &.{},
        });
        if (std.meta.isError(result)) entry.status = 500;
        l.sink.log(entry);
        return result;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const http = @import("http");

/// A clock that advances by `step` ns per reading.
const FakeClock = struct {
    t: i64,
    step: i64,
    fn now(c: ?*anyopaque) i64 {
        const self: *FakeClock = @ptrCast(@alignCast(c.?));
        const v = self.t;
        self.t += self.step;
        return v;
    }
};

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
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

fn hOk(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(202);
    try ctx.res.writeAll("hello");
}

fn hFail(_: *router.Ctx) anyerror!void {
    return error.Boom;
}

fn ridFromHeader(ctx: *const router.Ctx) ?[]const u8 {
    return ctx.req.header("X-Req");
}

fn tenantExtra(ctx: *const router.Ctx, out: *[Logger.max_extra]root.Field) []const root.Field {
    out[0] = .{ .key = "route", .value = ctx.matchedPattern() orelse "-" };
    out[1] = .{ .key = "status", .value = "forged" }; // collides with a fixed key: skipped
    return out[0..2];
}

fn fmtTime(ns: i64, buf: []u8) ?[]const u8 {
    return std.mem.print(buf, "T{d}", .{ns}) catch null;
}

const get_req = "GET /items/7?x=1 HTTP/1.1\r\nHost: t\r\nUser-Agent: probe\r\nX-Req: r-1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

test "Logger: one logfmt line with the injected clock's timestamp and latency, ids and extra" {
    var clock: FakeClock = .{ .t = 1000, .step = 2_500_000 };
    var sink_buf: [1024]u8 = undefined;
    var sw: std.Io.Writer = .fixed(&sink_buf);
    var sink = root.Sink.init(&sw, .{ .format = .logfmt });
    var logger: Logger = .{
        .sink = &sink,
        .clock = .{ .context = &clock, .now_ns = FakeClock.now },
        .request_id = ridFromHeader,
        .extra_fn = tenantExtra,
    };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(logger.middleware());
    try r.get("/items/:id", hOk);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, get_req, &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 202"));
    try testing.expectEqualStrings(
        "ts=1000 method=GET target=\"/items/7?x=1\" protocol=HTTP/1.1 status=202 " ++
            "request_bytes=0 response_bytes=5 latency_ns=2500000 user_agent=probe " ++
            "request_id=r-1 route=/items/:id\n",
        sw.buffered(),
    );
    try testing.expectEqual(@as(i64, 1000 + 2 * 2_500_000), clock.t);
}

test "Logger: Combined through the same middleware, time_format fills [%t]" {
    var clock: FakeClock = .{ .t = 42, .step = 1 };
    var sink_buf: [1024]u8 = undefined;
    var sw: std.Io.Writer = .fixed(&sink_buf);
    var sink = root.Sink.init(&sw, .{ .format = .combined });
    var logger: Logger = .{ .sink = &sink, .clock = .{ .context = &clock, .now_ns = FakeClock.now }, .time_format = fmtTime };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(logger.middleware());
    try r.get("/items/:id", hOk);

    var buf: [1024]u8 = undefined;
    _ = runWire(&r, get_req, &buf);
    try testing.expectEqualStrings("- - - [T42] \"GET /items/7?x=1 HTTP/1.1\" 202 5 \"-\" \"probe\"\n", sw.buffered());
}

test "Logger: a handler error is re-raised to the server (500) and logged as 500" {
    var clock: FakeClock = .{ .t = 0, .step = 10 };
    var sink_buf: [1024]u8 = undefined;
    var sw: std.Io.Writer = .fixed(&sink_buf);
    var sink = root.Sink.init(&sw, .{ .format = .logfmt });
    var logger: Logger = .{ .sink = &sink, .clock = .{ .context = &clock, .now_ns = FakeClock.now } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(logger.middleware());
    try r.get("/items/:id", hFail);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, get_req, &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 500"));
    try testing.expect(std.mem.find(u8, sw.buffered(), " status=500 ") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, sw.buffered(), "\n"));
}

test "Logger: a clock that runs backwards logs latency as absent, not a wrapped number" {
    var clock: FakeClock = .{ .t = 100, .step = -50 };
    var sink_buf: [1024]u8 = undefined;
    var sw: std.Io.Writer = .fixed(&sink_buf);
    var sink = root.Sink.init(&sw, .{ .format = .logfmt });
    var logger: Logger = .{ .sink = &sink, .clock = .{ .context = &clock, .now_ns = FakeClock.now } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(logger.middleware());
    try r.get("/items/:id", hOk);

    var buf: [1024]u8 = undefined;
    _ = runWire(&r, get_req, &buf);
    try testing.expect(std.mem.find(u8, sw.buffered(), "latency_ns") == null);
    try testing.expect(std.mem.startsWith(u8, sw.buffered(), "ts=100 "));
}

fn keepErrorsAnd5xx(ctx: *const router.Ctx, failed: bool) bool {
    return failed or ctx.res.status >= 500;
}

fn hDown(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(503);
    try ctx.res.writeAll("down");
}

test "Logger: keep decides per request after the chain -- a skipped request writes no line" {
    // Kills: `keep` ignored (three lines), called before the chain (the 503
    // would still read as the default status and be skipped), or `failed`
    // not passed (the handler error skipped).
    var clock: FakeClock = .{ .t = 1, .step = 1 };
    var sink_buf: [1024]u8 = undefined;
    var sw: std.Io.Writer = .fixed(&sink_buf);
    var sink = root.Sink.init(&sw, .{ .format = .combined });
    var logger: Logger = .{
        .sink = &sink,
        .clock = .{ .context = &clock, .now_ns = FakeClock.now },
        .keep = keepErrorsAnd5xx,
    };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(logger.middleware());
    try r.get("/ok", hOk);
    try r.get("/down", hDown);
    try r.get("/fail", hFail);
    var buf: [1024]u8 = undefined;
    _ = runWire(&r, "GET /ok HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    _ = runWire(&r, "GET /down HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    _ = runWire(&r, "GET /fail HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    const text = sw.buffered();
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, text, "\n"));
    try testing.expect(std.mem.find(u8, text, "\"GET /down HTTP/1.1\" 503") != null);
    try testing.expect(std.mem.find(u8, text, "\"GET /fail HTTP/1.1\" 500") != null);
    try testing.expect(std.mem.find(u8, text, "/ok") == null);
}
