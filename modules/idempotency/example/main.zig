// SPDX-License-Identifier: MIT

//! What a payments-style `router` app does with `idempotency`: wire the
//! middleware in front of a handler that records its response via
//! `Store.respond`, then drive a realistic retry lifecycle over real HTTP/1.1
//! wire bytes (`http.Server.serveStream`, offline, no sockets) — a fresh key
//! runs the handler once, a retry with the SAME key+body replays the cached
//! response without re-running the handler, a retry with the same key but a
//! DIFFERENT body is rejected (422) rather than silently replayed, a
//! concurrent in-flight duplicate is rejected (409), a body over the
//! fingerprint cap fails closed (413), and a cached entry evicted by TTL lets
//! the handler run again.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — `deps`
//! only (`router`, `http`, `ramcache`), no `test_deps`, no private
//! declarations.

const std = @import("std");
const idempotency = @import("idempotency");
const router = @import("router");
const http = @import("http");
const ramcache = @import("ramcache");

/// A fake, caller-controlled clock -- the module injects one so TTL
/// accounting is deterministic and offline. Same shape as
/// `idempotency.Clock`: `.ctx` + `.nowFn`.
const FakeClock = struct {
    now_ns: i64 = 1_000_000_000,

    fn clock(fc: *FakeClock) idempotency.Clock {
        return .{ .ctx = fc, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        const fc: *FakeClock = @ptrCast(@alignCast(ctx.?));
        return fc.now_ns;
    }
};

/// App state shared with the handler: the store plus a call counter, so the
/// example can assert "ran exactly once" the same way the module's own tests
/// do — the whole point of the middleware is that the counter must NOT
/// advance on a replay.
const App = struct {
    store: *idempotency.Store,
    calls: u32 = 0,
};

fn hOrder(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    var body_buf: [32]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "order-{d}", .{app.calls}) catch unreachable;
    try app.store.respond(ctx, 201, "application/json", body);
}

/// A second app used only for the concurrent-in-flight scenario: its handler
/// re-enters the SAME router with the SAME key while the reservation is still
/// held, standing in for a second connection thread racing the first.
const ReentrantApp = struct {
    store: *idempotency.Store,
    r: *router.Router,
    calls: u32 = 0,
    second_status: u16 = 0,
};

fn hReentrant(ctx: *router.Ctx) anyerror!void {
    const app: *ReentrantApp = @ptrCast(@alignCast(ctx.state.?));
    app.calls += 1;
    if (app.calls == 1) {
        var buf: [2048]u8 = undefined;
        const resp = runWire(app.r, reqKey("POST", "/orders", "racey"), &buf);
        app.second_status = statusOf(resp);
    }
    try app.store.respond(ctx, 201, "application/json", "ok");
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var response_body_buf: [4096]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
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

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

fn statusOf(got: []const u8) u16 {
    // "HTTP/1.1 NNN ..."
    const start = 9;
    return std.fmt.parseInt(u16, got[start .. start + 3], 10) catch 0;
}

fn reqKey(comptime method: []const u8, comptime path: []const u8, comptime key: []const u8) []const u8 {
    return method ++ " " ++ path ++ " HTTP/1.1\r\nHost: t\r\n" ++
        "Idempotency-Key: " ++ key ++ "\r\nConnection: close\r\n\r\n";
}

fn reqKeyBody(comptime method: []const u8, comptime path: []const u8, comptime key: []const u8, comptime body: []const u8) []const u8 {
    return method ++ " " ++ path ++ " HTTP/1.1\r\nHost: t\r\nIdempotency-Key: " ++ key ++
        "\r\nContent-Length: " ++ std.fmt.comptimePrint("{d}", .{body.len}) ++
        "\r\nConnection: close\r\n\r\n" ++ body;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var fake_clock: FakeClock = .{};
    var cache = ramcache.Cache.init(gpa, .{ .max_bytes = 1 << 16, .max_entries = 32 });
    defer cache.deinit();
    var store: idempotency.Store = .{ .cache = &cache, .clock = fake_clock.clock(), .ttl_ns = 1000 };
    defer store.deinit();
    var app = App{ .store = &store };
    var idem = idempotency.Idempotency{ .store = &store };

    var r = router.Router.init(gpa);
    defer r.deinit();
    r.state = &app;
    try r.use(idem.middleware());
    try r.post("/orders", hOrder);
    try r.post("/refunds", hOrder);

    // 0. Error handled by name: registering the same route twice is rejected
    // rather than silently overwriting the first handler.
    if (r.post("/orders", hOrder)) |_| {
        unreachable;
    } else |err| switch (err) {
        error.DuplicateRoute => std.debug.print("duplicate route registration correctly rejected: DuplicateRoute\n", .{}),
        else => return err,
    }

    // 1. Fresh key: the handler runs and records its response.
    {
        var buf: [2048]u8 = undefined;
        const first = runWire(&r, reqKeyBody("POST", "/orders", "abc-123", "{\"amt\":10}"), &buf);
        std.debug.assert(std.mem.startsWith(u8, first, "HTTP/1.1 201"));
        std.debug.assert(std.mem.eql(u8, bodyOf(first), "order-1"));
        std.debug.assert(app.calls == 1);
        std.debug.assert(headerValue(first, "Idempotent-Replayed") == null);
    }

    // 2. Retry -- deliberate duplicate operation: same key, same body. Must
    // replay the cached response and NOT re-run the handler.
    {
        var buf: [2048]u8 = undefined;
        const replay = runWire(&r, reqKeyBody("POST", "/orders", "abc-123", "{\"amt\":10}"), &buf);
        std.debug.assert(std.mem.eql(u8, bodyOf(replay), "order-1"));
        std.debug.assert(std.mem.eql(u8, headerValue(replay, "Idempotent-Replayed").?, "true"));
        std.debug.assert(app.calls == 1); // unchanged -- the whole point
        std.debug.print("replay of a duplicate request returned the cached response, handler not re-run\n", .{});
    }

    // 3. Same key, DIFFERENT body -- not a retry. Error path: must answer 422
    // and never run the handler, without leaking the buffered/fingerprinted
    // body.
    {
        var buf: [2048]u8 = undefined;
        const mismatch = runWire(&r, reqKeyBody("POST", "/orders", "abc-123", "{\"amt\":999}"), &buf);
        std.debug.assert(std.mem.startsWith(u8, mismatch, "HTTP/1.1 422"));
        std.debug.assert(app.calls == 1);
        std.debug.print("same key, different body correctly rejected: 422, no re-run\n", .{});
    }

    // 4. A body over the fingerprint cap: cannot be safely fingerprinted, so
    // it must fail closed (413) rather than silently skip the check -- an
    // error return partway through the buffered-read path.
    {
        var small_store: idempotency.Store = .{ .cache = &cache, .clock = fake_clock.clock(), .ttl_ns = 1000 };
        defer small_store.deinit();
        var small_app = App{ .store = &small_store };
        var small_idem = idempotency.Idempotency{ .store = &small_store, .options = .{ .max_body_bytes = 8 } };

        var r2 = router.Router.init(gpa);
        defer r2.deinit();
        r2.state = &small_app;
        try r2.use(small_idem.middleware());
        try r2.post("/orders", hOrder);

        var buf: [2048]u8 = undefined;
        const over = runWire(&r2, reqKeyBody("POST", "/orders", "over-cap", "AAAAAAAAA"), &buf); // 9 bytes > 8
        std.debug.assert(std.mem.startsWith(u8, over, "HTTP/1.1 413"));
        std.debug.assert(small_app.calls == 0);
        std.debug.print("oversized body correctly rejected: 413, no handler run\n", .{});
    }

    // 5. Target scoping: the same client key on a DIFFERENT endpoint is a
    // distinct cache entry -- runs its own handler, does not cross-replay.
    {
        var buf: [2048]u8 = undefined;
        const distinct = runWire(&r, reqKeyBody("POST", "/refunds", "abc-123", "{\"amt\":5}"), &buf);
        std.debug.assert(std.mem.eql(u8, bodyOf(distinct), "order-2"));
        std.debug.assert(app.calls == 2);
    }

    // 6. Concurrent first-flight of the same key: the in-flight reservation
    // must reject the second, still-racing request with 409 rather than
    // double-running the handler -- the retried/duplicate pressure path this
    // module's reservation set exists for.
    {
        var re_store: idempotency.Store = .{ .cache = &cache, .clock = fake_clock.clock(), .ttl_ns = 1000 };
        defer re_store.deinit();

        var r3 = router.Router.init(gpa);
        defer r3.deinit();
        var re_app = ReentrantApp{ .store = &re_store, .r = &r3 };
        r3.state = &re_app;
        var re_idem = idempotency.Idempotency{ .store = &re_store };
        try r3.use(re_idem.middleware());
        try r3.post("/orders", hReentrant);

        var buf: [2048]u8 = undefined;
        const outer = runWire(&r3, reqKey("POST", "/orders", "racey"), &buf);
        std.debug.assert(std.mem.startsWith(u8, outer, "HTTP/1.1 201"));
        std.debug.assert(re_app.calls == 1); // the nested duplicate did NOT re-enter the handler
        std.debug.assert(re_app.second_status == 409);
        std.debug.print("concurrent in-flight duplicate correctly rejected: 409, handler ran once\n", .{});
    }

    // 7. TTL expiry (capacity/eviction-adjacent pressure path): advance the
    // fake clock past `ttl_ns`. The entry is gone, so the SAME key runs the
    // handler again instead of replaying stale data.
    {
        fake_clock.now_ns += 2000; // > ttl_ns (1000)
        var buf: [2048]u8 = undefined;
        const stale = runWire(&r, reqKeyBody("POST", "/orders", "abc-123", "{\"amt\":10}"), &buf);
        std.debug.assert(std.mem.eql(u8, bodyOf(stale), "order-3"));
        std.debug.assert(headerValue(stale, "Idempotent-Replayed") == null);
        std.debug.assert(app.calls == 3);
        std.debug.print("TTL-expired entry re-ran the handler instead of replaying stale data\n", .{});
    }

    // 8. Capacity pressure: many distinct keys through the same bounded
    // (32-entry) cache, forcing real eviction while the store is still live.
    // Asserted, not just printed: every request still succeeds (201), the
    // live entry count never exceeds the configured cap, and eviction
    // actually happened (not just headroom).
    {
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            var buf: [2048]u8 = undefined;
            var key_buf: [16]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "bulk-{d}", .{i}) catch unreachable;
            const req = try std.fmt.allocPrint(gpa, "POST /orders HTTP/1.1\r\nHost: t\r\nIdempotency-Key: {s}\r\nConnection: close\r\n\r\n", .{key});
            defer gpa.free(req);
            const resp = runWire(&r, req, &buf);
            std.debug.assert(std.mem.startsWith(u8, resp, "HTTP/1.1 201"));
            std.debug.assert(cache.stats.entries <= 32);
        }
        std.debug.assert(cache.stats.evictions > 0);
        std.debug.print("capacity: 64 more distinct keys through a 32-entry store -> {d} evictions, {d} live entries\n", .{ cache.stats.evictions, cache.stats.entries });
    }
}
