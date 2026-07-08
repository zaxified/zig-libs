// SPDX-License-Identifier: MIT

//! mcp-http — the MCP **Streamable HTTP** transport (2025-06-18 revision) as a
//! `router` middleware, so a `mcp.Server` (JSON-RPC 2.0 tools / resources /
//! prompts) is reachable remotely over HTTP instead of only over stdio.
//!
//! This is the request/response half: a single endpoint (`/mcp` by default)
//! where the client **POST**s one JSON-RPC message and gets back either the
//! JSON-RPC response (`application/json`) or — for a notification / anything
//! with no reply — **202 Accepted** with no body. It wraps the transport-
//! agnostic `mcp.Server.handleMessage`, which already does all protocol work
//! (version negotiation, dispatch, error objects) and, per the MCP spec,
//! rejects JSON-RPC batches.
//!
//! Deliberately out of scope here (later parts): the server→client **SSE
//! stream** on `GET /mcp` (progress / server-initiated messages) and
//! **session management** (`Mcp-Session-Id`). This transport is **stateless** —
//! it assigns no session id, which the spec permits; every POST is handled
//! independently. `GET`/`DELETE` on the endpoint answer **405** for now.
//!
//! ## Security
//!
//! Bind the server to loopback for a local integration, or put auth in front:
//! register an `aaa-gate`/`jwt` middleware **before** this one to gate the
//! endpoint (MCP has no read/write method split, so gate every POST). The MCP
//! spec also requires validating the `Origin` header against DNS-rebinding for
//! locally-bound servers — do that with a dedicated middleware (a following
//! part) or a reverse proxy. This module itself does no authentication.
//!
//! ## Usage
//!
//! ```zig
//! var server = mcp.Server.init(gpa, .{ .name = "netops", .version = "1.0" });
//! defer server.deinit();
//! try server.addTool(.{ ... });
//! var transport = mcphttp.Transport{ .gpa = gpa, .server = &server };
//! try router.use(transport.middleware()); // after any auth/origin middleware
//! ```
//!
//! ## Concurrency
//!
//! `mcp.Server` holds mutable state (e.g. `client_initialized`) and is not
//! internally synchronized; `http.Server` serves from several connection
//! threads. Inject `Transport.lock` (see `Lock`) to serialize `handleMessage`
//! under a threaded server, or run the server single-threaded. Body reads and
//! response framing happen outside the lock.

const std = @import("std");
const router = @import("router");
const http = @import("http");
const mcp = @import("mcp");

pub const meta = .{
    .status = .gap,
    .platform = .any,
    .role = .server,
    // Reentrant except the shared mcp.Server — inject Lock under a threaded
    // http.Server (documented).
    .concurrency = .reentrant,
    .model_after = "MCP Streamable HTTP transport (2025-06-18); bxp-gui/mcp_dart behavioral reference",
    .deps = .{ "router", "http", "mcp" },
};

/// Serialization seam for the shared `mcp.Server` under a multi-threaded
/// `http.Server` (same shape as `jwt.Lock`). Default `.none` is a no-op —
/// correct for a single-threaded server or an externally-synchronized one.
/// Plug a real mutex (`std.Thread.Mutex`) in for the default threaded server.
pub const Lock = struct {
    ctx: ?*anyopaque = null,
    lockFn: *const fn (?*anyopaque) void = noop,
    unlockFn: *const fn (?*anyopaque) void = noop,

    pub const none: Lock = .{};

    fn noop(_: ?*anyopaque) void {}
    fn acquire(l: Lock) void {
        l.lockFn(l.ctx);
    }
    fn release(l: Lock) void {
        l.unlockFn(l.ctx);
    }
};

/// The Streamable HTTP transport over one `mcp.Server`. Immutable config; the
/// `server` and this `Transport` must outlive the Router.
pub const Transport = struct {
    /// Allocator for the per-request body read + response capture (short-lived;
    /// freed before the handler returns).
    gpa: std.mem.Allocator,
    /// The MCP server this endpoint fronts. Must outlive the Router.
    server: *mcp.Server,
    /// Endpoint path (exact match). Default `/mcp`.
    path: []const u8 = "/mcp",
    /// Largest POST body accepted before answering 413. Default 4 MiB.
    max_body: usize = 4 << 20,
    /// Serialize `handleMessage` (see `Lock`). Default `.none`.
    lock: Lock = .none,

    pub fn middleware(t: *const Transport) router.Middleware {
        return .{ .state = @constCast(t), .run = middlewareRun };
    }
};

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const t: *const Transport = @ptrCast(@alignCast(state.?));

    if (!std.mem.eql(u8, ctx.req.path, t.path)) return next.run(ctx);

    switch (ctx.req.method) {
        .post => return handlePost(t, ctx),
        // The SSE stream (GET) and session teardown (DELETE) are later parts;
        // until then the endpoint is POST-only.
        else => {
            ctx.res.setStatus(405);
            try ctx.res.setHeader("Allow", "POST");
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Method Not Allowed\n");
        },
    }
}

fn handlePost(t: *const Transport, ctx: *router.Ctx) anyerror!void {
    const body = ctx.req.reader().allocRemaining(t.gpa, .limited(t.max_body)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => {
            ctx.res.setStatus(413);
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Payload Too Large\n");
            return;
        },
        error.ReadFailed => {
            ctx.res.setStatus(400);
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Bad Request\n");
            return;
        },
    };
    defer t.gpa.free(body);

    // Capture the one JSON-RPC response line (if any) the server writes.
    var out: std.Io.Writer.Allocating = .init(t.gpa);
    defer out.deinit();

    t.lock.acquire();
    const rc = t.server.handleMessage(body, &out.writer);
    t.lock.release();
    // handleMessage only fails on OOM or a transport write failure; the
    // Allocating writer fails solely on OOM, so both surface as a 500.
    rc catch return error.OutOfMemory;

    // A notification (or any id-less message) produces no response line.
    const resp = std.mem.trimEnd(u8, out.written(), "\n");
    if (resp.len == 0) {
        ctx.res.setStatus(202); // Accepted, no body
        return;
    }
    ctx.res.setStatus(200);
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.writeAll(resp); // writeAll copies, so freeing `out` after is safe
}

// ── tests (offline — through http.Server.serveStream + a real router) ───────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

fn echoTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.write("{\"ok\":true}");
    return false;
}

fn buildServer(gpa: std.mem.Allocator) !mcp.Server {
    var server = mcp.Server.init(gpa, .{ .name = "test", .version = "1.0" });
    errdefer server.deinit();
    try server.addTool(.{
        .name = "echo",
        .description = "echo",
        .input_schema = "{\"type\":\"object\"}",
        .handler = echoTool,
    });
    return server;
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [4096]u8 = undefined;
    var response_body_buf: [8192]u8 = undefined;
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

fn post(comptime target: []const u8, comptime json: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "POST {s} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ target, json.len, json },
    );
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

fn hApp(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("app");
}

test "POST initialize → 200 application/json with a result" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    try r.get("/", hApp);

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, got, "Content-Type: application/json") != null);
    const b = bodyOf(got);
    try testing.expect(std.mem.indexOf(u8, b, "\"jsonrpc\":\"2.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, b, "\"id\":1") != null);
    try testing.expect(std.mem.indexOf(u8, b, "\"result\"") != null);
    try testing.expect(std.mem.indexOf(u8, b, "\"serverInfo\"") != null);
}

test "POST tools/list → the registered tool; tools/call → its result" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const list = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, list, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, bodyOf(list), "\"echo\"") != null);

    var buf2: [4096]u8 = undefined;
    const call = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}
    ), &buf2);
    try testing.expect(std.mem.startsWith(u8, call, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, bodyOf(call), "\\\"ok\\\":true") != null);
}

test "POST a notification → 202 Accepted, no body" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 202"));
    try testing.expectEqualStrings("", bodyOf(got));
}

test "non-/mcp path passes through; GET /mcp → 405" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    try r.get("/", hApp);

    var buf: [2048]u8 = undefined;
    const app = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings("app", bodyOf(app));

    var buf2: [2048]u8 = undefined;
    const get = runWire(&r, "GET /mcp HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf2);
    try testing.expect(std.mem.startsWith(u8, get, "HTTP/1.1 405"));
    try testing.expect(std.mem.indexOf(u8, get, "Allow: POST") != null);
}

test "oversized POST body → 413" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .max_body = 16 };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"padding":"xxxxxxxxxxxx"}}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 413"));
}
