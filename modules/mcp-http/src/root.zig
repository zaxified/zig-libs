// SPDX-License-Identifier: MIT

//! mcp-http — the MCP **Streamable HTTP** transport (2025-06-18 revision) as a
//! `router` middleware, so a `mcp.Server` (JSON-RPC 2.0 tools / resources /
//! prompts) is reachable remotely over HTTP instead of only over stdio.
//!
//! A single endpoint (`/mcp` by default) where the client **POST**s one
//! JSON-RPC message. The response is delivered one of two ways:
//!
//! - **`application/json`** — a single response object (the default; also the
//!   only mode a client that doesn't `Accept: text/event-stream` gets).
//! - **SSE** (`text/event-stream`) — when the client accepts it, the response
//!   is an event stream so a tool call's `notifications/progress` reach the
//!   client **live**; each JSON-RPC message the server emits becomes one SSE
//!   `data:` event, and the stream closes after the response.
//!
//! A notification (or anything with no reply) answers **202 Accepted**, no
//! body, in either mode. It wraps the transport-agnostic
//! `mcp.Server.handleMessage`, which does all protocol work (version
//! negotiation, dispatch, error objects) and, per the MCP spec, rejects
//! JSON-RPC batches.
//!
//! ## Server→client requests (sampling / elicitation)
//!
//! `mcp.Server` can issue `sampling/createMessage` and `elicitation/create`.
//! Over HTTP those are **not** request/response within one connection: the
//! client's answer arrives as a *later, separate POST*, so nothing can park
//! waiting for it (same constraint as the `GET` stream — see `Sessions`).
//! What this transport wires up:
//!
//! - **Peer scoping.** Each session gets a numeric handle (`Sessions.tagOf`)
//!   passed to `mcp.Server.handleMessageFrom` as the *peer*. A response POSTed
//!   on session B can never resolve a request issued to session A, so one
//!   user's sampling completion or elicitation answer cannot be delivered into
//!   another user's tool call.
//! - **Delivery.** A request issued from inside a `tools/call` rides that
//!   POST's own response — an SSE `data:` event in stream mode; in
//!   `application/json` mode the body must stay a single object, so it is
//!   queued for the session's `GET` stream instead. To issue one *outside* a
//!   call, write it to a `std.Io.Writer.Allocating` and `Sessions.push` the
//!   bytes:
//!
//!   ```zig
//!   var line: std.Io.Writer.Allocating = .init(gpa);
//!   defer line.deinit();
//!   _ = try server.sendSamplingRequest(&line.writer, req, .{
//!       .peer = sessions.tagOf(sid).?, .on_response = &onAnswer, .ctx = app,
//!   });
//!   _ = try sessions.push(sid, std.mem.trimEnd(u8, line.written(), "\n"));
//!   ```
//!
//! - **The answer.** The client POSTs its JSON-RPC response to `/mcp`; the
//!   server produces no reply for it, so the endpoint answers **202 Accepted**
//!   and the registered `mcp.ResponseHandler` runs during that POST.
//!
//! **Sessions** (optional — set `Transport.sessions` to a `*Sessions`): the
//! transport assigns an `Mcp-Session-Id` at `initialize`, validates it on later
//! requests (unknown ⇒ 404 so the client re-initializes), tears one down on
//! `DELETE /mcp`, and serves server→client messages on `GET /mcp` — a
//! drain-and-close SSE stream with resumable replay (`Last-Event-ID`); enqueue
//! with `Sessions.push`. Leave `sessions` null for a **stateless** server (no
//! session id; `GET`/`DELETE` → 405). See `Sessions` for the delivery model.
//!
//! ## Security
//!
//! **Origin validation** (the MCP-mandated DNS-rebinding defense) is built in:
//! set `Transport.allowed_origins` and a browser request forging another site's
//! `Origin` gets 403 (empty ⇒ accept all — the dev default). **Authentication**
//! is not: register an `aaa-gate`/`jwt` middleware **before** this one to gate
//! the endpoint (MCP has no read/write method split, so gate every POST). Bind
//! to loopback for a local integration, or terminate auth at a reverse proxy.
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
    .platform = .any,
    .role = .server,
    // Reentrant except the shared mcp.Server — inject Lock under a threaded
    // http.Server (documented).
    .concurrency = .reentrant,
    .model_after = "MCP Streamable HTTP transport (2025-06-18); mcp_dart behavioral reference",
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

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn monoNs() u64 {
    switch (@import("builtin").os.tag) {
        .windows => {
            var qpf: std.os.windows.LARGE_INTEGER = undefined;
            var qpc: std.os.windows.LARGE_INTEGER = undefined;
            if (!std.os.windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool()) return 0;
            if (!std.os.windows.ntdll.RtlQueryPerformanceCounter(&qpc).toBool()) return 0;
            return @intCast(@as(u128, @as(u64, @bitCast(qpc))) * std.time.ns_per_s / @as(u64, @bitCast(qpf)));
        },
        else => {
            var ts: std.posix.timespec = undefined;
            if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
        },
    }
}

/// Server-side session registry for the Streamable HTTP transport. Optional —
/// leave `Transport.sessions` null for a **stateless** server (no session id;
/// `GET`/`DELETE` → 405). When set, the transport assigns an `Mcp-Session-Id`
/// at `initialize`, validates it on later requests (unknown ⇒ 404, so the
/// client re-initializes), tears a session down on `DELETE`, and serves
/// server→client messages on `GET /mcp`.
///
/// **Delivery model — the `GET` stream is drain-and-close** (a long-poll over
/// SSE): a GET replays every event queued since the request's `Last-Event-ID`
/// and then closes; the client's `EventSource` auto-reconnects (with
/// `Last-Event-ID`) to receive later events. This fits the io-less handler
/// model — a handler cannot cleanly park a connection waiting for a future push
/// — and MCP's low-frequency server→client traffic. Nothing is lost within the
/// bounded replay buffer (`replay_depth`); a client gone longer than that many
/// events loses the overflow, so size it for your burst.
///
/// Thread-safe: all state sits behind one spinlock (short critical sections —
/// a map touch / an event copy, never socket I/O). `push` may be called from
/// any thread; `GET` handlers snapshot under the lock and write outside it, so
/// a concurrent `DELETE` can free a session without a use-after-free.
pub const Sessions = struct {
    gpa: std.mem.Allocator,
    lock: std.atomic.Mutex = .unlocked,
    map: std.StringHashMapUnmanaged(*Session) = .empty,
    seq: u64 = 0,
    /// Buffered events retained per session for resumable replay. Older events
    /// are evicted; a client reconnecting past this depth loses them.
    replay_depth: usize = 256,
    /// Hard cap on live sessions. `create` refuses a new session past this,
    /// so an unauthenticated peer spamming `initialize` cannot grow the
    /// registry (and its per-session replay buffers) without bound.
    max_sessions: usize = 10_000,

    const Session = struct {
        id: []const u8, // gpa-owned, stable for the session's life
        /// Stable numeric handle for this session, handed to
        /// `mcp.Server.handleMessageFrom` as the *peer*. It scopes the
        /// correlation of server→client requests: a sampling/elicitation answer
        /// POSTed on session B can never resolve a request issued to session A.
        tag: u64,
        events: std.ArrayList(StoredEvent) = .empty,
        next_event_id: u64 = 1,
        closing: bool = false,
    };
    const StoredEvent = struct { id: u64, data: []const u8 }; // data gpa-owned

    pub fn init(gpa: std.mem.Allocator) Sessions {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Sessions) void {
        lockSpin(&self.lock);
        var it = self.map.valueIterator();
        while (it.next()) |sp| self.freeSession(sp.*);
        self.map.deinit(self.gpa);
        self.lock.unlock();
        self.* = undefined;
    }

    fn freeSession(self: *Sessions, s: *Session) void {
        for (s.events.items) |e| self.gpa.free(e.data);
        s.events.deinit(self.gpa);
        self.gpa.free(s.id);
        self.gpa.destroy(s);
    }

    /// Create a session; returns its id (store-owned, stable). Caller echoes it
    /// in the response `Mcp-Session-Id` header.
    fn create(self: *Sessions) error{ OutOfMemory, TooManySessions }![]const u8 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.map.count() >= self.max_sessions) return error.TooManySessions;
        self.seq += 1;
        // Unique (seq, under lock) and hard to guess (monotonic clock + the
        // store address mixed in) — NOT a CSPRNG token, so it is a routing key,
        // not an auth secret; gate the endpoint with aaa-gate/jwt for auth.
        const mixed = monoNs() ^ (@as(u64, @intCast(@intFromPtr(self))) *% 0x9E3779B97F4A7C15);
        var idbuf: [32]u8 = undefined;
        const id_txt = std.fmt.bufPrint(&idbuf, "{x:0>16}{x:0>16}", .{ mixed, self.seq }) catch unreachable;
        const id = try self.gpa.dupe(u8, id_txt);
        errdefer self.gpa.free(id);
        const s = try self.gpa.create(Session);
        errdefer self.gpa.destroy(s);
        // seq is allocated under the lock and never reused, so it is a unique
        // peer handle for this session's lifetime.
        s.* = .{ .id = id, .tag = self.seq };
        try self.map.put(self.gpa, id, s);
        return id;
    }

    fn exists(self: *Sessions, id: []const u8) bool {
        return self.tagOf(id) != null;
    }

    /// The session's peer handle (see `Session.tag`), or null when unknown.
    /// Pass it as `mcp.RequestOptions.peer` when issuing a server→client
    /// request for this session, so only that session's answer resolves it.
    pub fn tagOf(self: *Sessions, id: []const u8) ?u64 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.map.get(id) orelse return null;
        return s.tag;
    }

    /// Tear a session down (on `DELETE`). Returns whether it existed.
    fn destroy(self: *Sessions, id: []const u8) bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const kv = self.map.fetchRemove(id) orelse return false;
        self.freeSession(kv.value);
        return true;
    }

    /// Enqueue a server→client message for a session's `GET` stream (deliver on
    /// the client's next connect/reconnect). Callable from any thread. Returns
    /// false if the session is unknown. `data` is copied.
    pub fn push(self: *Sessions, id: []const u8, data: []const u8) error{OutOfMemory}!bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.map.get(id) orelse return false;
        const copy = try self.gpa.dupe(u8, data);
        errdefer self.gpa.free(copy);
        if (s.events.items.len >= self.replay_depth) {
            self.gpa.free(s.events.items[0].data);
            _ = s.events.orderedRemove(0);
        }
        try s.events.append(self.gpa, .{ .id = s.next_event_id, .data = copy });
        s.next_event_id += 1;
        return true;
    }

    /// Mark a session closing — its next `GET` drains what is queued and ends.
    pub fn close(self: *Sessions, id: []const u8) void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.map.get(id)) |s| s.closing = true;
    }

    /// Snapshot (into `arena`) every event with id > `after`, returning them via
    /// `out`; the bool is the session's `closing` flag. Null ⇒ unknown session.
    /// Copies under the lock so the caller can write to the socket lock-free.
    fn drainAfter(
        self: *Sessions,
        id: []const u8,
        after: u64,
        arena: std.mem.Allocator,
        out: *std.ArrayList(StoredEvent),
    ) error{OutOfMemory}!?bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const s = self.map.get(id) orelse return null;
        for (s.events.items) |e| {
            if (e.id > after)
                try out.append(arena, .{ .id = e.id, .data = try arena.dupe(u8, e.data) });
        }
        return s.closing;
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
    /// Allowed `Origin` header values (exact match) — the MCP-mandated
    /// DNS-rebinding defense for a locally-bound server (browser JS on another
    /// site cannot forge `Origin`). **Empty ⇒ every origin is accepted** (the
    /// dev default; safe only when the port is not reachable by a browser, e.g.
    /// loopback with no local web content, or auth in front). When non-empty, a
    /// request whose `Origin` header is present but not listed gets **403**; a
    /// request with **no** `Origin` (a non-browser client) is allowed — the
    /// attack this blocks is browser-driven. List full origins,
    /// e.g. `"http://localhost:7717"`.
    allowed_origins: []const []const u8 = &.{},
    /// Response delivery policy. `.auto` (default): when the client's `Accept`
    /// header includes `text/event-stream`, the POST response is delivered as
    /// an **SSE stream** so a tool call's `notifications/progress` reach the
    /// client live (each JSON-RPC message becomes one SSE `data:` event; the
    /// stream closes after the response). Clients that don't accept SSE still
    /// get a single `application/json` response. `.off`: always
    /// `application/json` (no streaming).
    stream: StreamMode = .auto,
    /// Optional session registry. Null ⇒ **stateless** (no `Mcp-Session-Id`;
    /// `GET`/`DELETE` → 405). Set a `*Sessions` to enable session assignment /
    /// validation and the server→client `GET /mcp` stream. Must outlive the
    /// Router.
    sessions: ?*Sessions = null,

    pub const StreamMode = enum { auto, off };

    pub fn middleware(t: *const Transport) router.Middleware {
        return .{ .state = @constCast(t), .run = middlewareRun };
    }
};

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const t: *const Transport = @ptrCast(@alignCast(state.?));

    if (!std.mem.eql(u8, ctx.req.path, t.path)) return next.run(ctx);

    if (!originAllowed(t, ctx.req)) {
        ctx.res.setStatus(403);
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll("Forbidden\n");
        return;
    }

    switch (ctx.req.method) {
        .post => return handlePost(t, ctx),
        .get => if (t.sessions != null) return handleGet(t, ctx) else return methodNotAllowed(t, ctx),
        .delete => if (t.sessions != null) return handleDelete(t, ctx) else return methodNotAllowed(t, ctx),
        else => return methodNotAllowed(t, ctx),
    }
}

fn methodNotAllowed(t: *const Transport, ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(405);
    try ctx.res.setHeader("Allow", if (t.sessions != null) "POST, GET, DELETE" else "POST");
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Method Not Allowed\n");
}

fn notFound(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(404);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("Session Not Found\n");
}

/// DNS-rebinding guard (MCP transport security): with a non-empty allowlist, a
/// present `Origin` must match exactly; an absent `Origin` (non-browser client)
/// is allowed. An empty allowlist accepts everything.
fn originAllowed(t: *const Transport, req: *const http.Server.Request) bool {
    if (t.allowed_origins.len == 0) return true;
    const origin = req.header("origin") orelse return true;
    for (t.allowed_origins) |allowed| {
        if (std.mem.eql(u8, allowed, origin)) return true;
    }
    return false;
}

/// Whether the client's `Accept` header admits an SSE response.
fn acceptsSse(req: *const http.Server.Request) bool {
    const accept = req.header("accept") orelse return false;
    return std.ascii.indexOfIgnoreCase(accept, "text/event-stream") != null;
}

/// Best-effort check whether a POST body is an `initialize` request (so the
/// transport assigns a session). A throwaway parse; a malformed body is not an
/// initialize (`handleMessage` will surface the real error).
fn isInitialize(gpa: std.mem.Allocator, body: []const u8) bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(), body, .{}) catch return false;
    if (v != .object) return false;
    const m = v.object.get("method") orelse return false;
    return m == .string and std.mem.eql(u8, m.string, "initialize");
}

/// The `Last-Event-ID` request header as a u64 (0 when absent/invalid ⇒ replay
/// the whole buffer).
fn parseLastEventId(req: *const http.Server.Request) u64 {
    const h = req.header("last-event-id") orelse return 0;
    return std.fmt.parseInt(u64, std.mem.trim(u8, h, " \t"), 10) catch 0;
}

/// `GET /mcp`: the server→client stream. Drain-and-close — replay every event
/// queued since `Last-Event-ID`, then close (the client reconnects for more).
fn handleGet(t: *const Transport, ctx: *router.Ctx) anyerror!void {
    const sessions = t.sessions.?;
    const sid = ctx.req.header("mcp-session-id") orelse return notFound(ctx);
    const after = parseLastEventId(ctx.req);

    var arena_state = std.heap.ArenaAllocator.init(t.gpa);
    defer arena_state.deinit();

    var batch: std.ArrayList(Sessions.StoredEvent) = .empty;
    // Snapshot under the store lock (copies into the arena) so writing to the
    // socket below holds no lock and races no concurrent DELETE.
    _ = (try sessions.drainAfter(sid, after, arena_state.allocator(), &batch)) orelse return notFound(ctx);

    var es = try http.sse.EventStream.start(ctx.res);
    if (batch.items.len == 0) {
        // Nothing queued: a heartbeat keeps the response well-formed; the
        // client's EventSource reconnects (with Last-Event-ID) for later events.
        try es.comment("keep-alive");
        return;
    }
    for (batch.items) |e| {
        var idbuf: [24]u8 = undefined;
        const idstr = std.fmt.bufPrint(&idbuf, "{d}", .{e.id}) catch unreachable;
        try es.send(.{ .id = idstr, .data = e.data });
    }
}

/// `DELETE /mcp`: tear down the session named by `Mcp-Session-Id`.
fn handleDelete(t: *const Transport, ctx: *router.Ctx) anyerror!void {
    const sid = ctx.req.header("mcp-session-id") orelse return notFound(ctx);
    if (t.sessions.?.destroy(sid)) {
        ctx.res.setStatus(204);
    } else {
        return notFound(ctx);
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

    // Session handling (only when a registry is configured). The client gets a
    // session id at `initialize` and must present it on every later request.
    // `sid`/`peer` identify the session for the rest of the request: `peer` is
    // what scopes server→client request correlation (see `Session.tag`).
    var sid: ?[]const u8 = null;
    var peer: u64 = 0;
    if (t.sessions) |sessions| {
        if (isInitialize(t.gpa, body)) {
            const new_sid = sessions.create() catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.TooManySessions => {
                    ctx.res.setStatus(429);
                    try ctx.res.setHeader("Content-Type", "text/plain");
                    try ctx.res.writeAll("Too Many Sessions\n");
                    return;
                },
            };
            try ctx.res.setHeader("Mcp-Session-Id", new_sid);
            sid = new_sid;
            peer = sessions.tagOf(new_sid) orelse 0;
        } else {
            const have = ctx.req.header("mcp-session-id") orelse return notFound(ctx);
            peer = sessions.tagOf(have) orelse return notFound(ctx);
            sid = have;
        }
    }

    if (t.stream == .auto and acceptsSse(ctx.req)) return streamResponse(t, ctx, body, peer);
    return jsonResponse(t, ctx, body, sid, peer);
}

/// The single-JSON-response path (client did not ask for SSE): capture what the
/// server writes and return `application/json`, or 202 for a notification (and
/// for a JSON-RPC *response* — a client answering a server→client request also
/// produces no reply, which is exactly what the Streamable HTTP spec wants
/// answered with 202).
///
/// The server may write **several** lines for one message: a tool's
/// `notifications/progress` and any `sampling/createMessage` /
/// `elicitation/create` it issues precede the response line. An
/// `application/json` body must be a single JSON object, so only the last line
/// (the response) becomes the body; the earlier server→client lines are queued
/// on the session's `GET` stream when a registry is configured, and dropped
/// when it is not — a stateless endpoint has no channel to deliver them on.
fn jsonResponse(t: *const Transport, ctx: *router.Ctx, body: []const u8, sid: ?[]const u8, peer: u64) anyerror!void {
    var out: std.Io.Writer.Allocating = .init(t.gpa);
    defer out.deinit();

    t.lock.acquire();
    const rc = t.server.handleMessageFrom(body, &out.writer, peer);
    t.lock.release();
    // handleMessage only fails on OOM or a transport write failure; the
    // Allocating writer fails solely on OOM, so both surface as a 500.
    rc catch return error.OutOfMemory;

    // Split into lines; the last non-empty one is the response to this POST.
    var resp: []const u8 = "";
    var it = std.mem.splitScalar(u8, out.written(), '\n');
    var prior: std.ArrayList([]const u8) = .empty;
    defer prior.deinit(t.gpa);
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (resp.len != 0) try prior.append(t.gpa, resp);
        resp = line;
    }
    if (prior.items.len != 0) {
        if (t.sessions) |sessions| {
            if (sid) |session_id| {
                for (prior.items) |line| _ = try sessions.push(session_id, line);
            }
        }
    }

    // A notification, or the client's response to one of our requests: no reply.
    if (resp.len == 0) {
        ctx.res.setStatus(202); // Accepted, no body
        return;
    }
    ctx.res.setStatus(200);
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.writeAll(resp); // writeAll copies, so freeing `out` after is safe
}

/// The SSE-response path: run the server against an adapter that re-frames each
/// JSON-RPC line the server writes (progress notifications, then the response)
/// as an SSE `data:` event, flushed live. If the message was a notification
/// (the server wrote nothing), no stream is started and we answer 202.
fn streamResponse(t: *const Transport, ctx: *router.Ctx, body: []const u8, peer: u64) anyerror!void {
    var buf: [4096]u8 = undefined;
    var adapter = SseAdapter.init(t.gpa, ctx.res, &buf);
    defer adapter.deinit();

    t.lock.acquire();
    const rc = t.server.handleMessageFrom(body, &adapter.writer, peer);
    t.lock.release();
    adapter.writer.flush() catch {}; // drain any bytes still buffered
    adapter.finish(); // emit a trailing partial line (defensive; mcp ends with \n)
    rc catch |err| return err;

    if (!adapter.started) ctx.res.setStatus(202); // notification: no stream, no body
    // else: the SSE stream carried the response; returning ends it (end() writes
    // the terminating chunk), which is the server-closes-after-response contract.
}

/// A `std.Io.Writer` that turns the server's newline-delimited JSON-RPC output
/// into SSE `data:` events on `rw`. Each complete line (the server writes one
/// JSON object per line, flushing after each) is emitted as its own event and
/// flushed to the socket; the `text/event-stream` head is written lazily on the
/// first event, so a no-output notification leaves the response free for a 202.
const SseAdapter = struct {
    rw: *http.Server.ResponseWriter,
    gpa: std.mem.Allocator,
    pending: std.ArrayList(u8) = .empty,
    es: http.sse.EventStream = undefined,
    started: bool = false,
    writer: std.Io.Writer,

    fn init(gpa: std.mem.Allocator, rw: *http.Server.ResponseWriter, buffer: []u8) SseAdapter {
        return .{
            .rw = rw,
            .gpa = gpa,
            .writer = .{ .vtable = &.{ .drain = drainFn }, .buffer = buffer },
        };
    }

    fn deinit(self: *SseAdapter) void {
        self.pending.deinit(self.gpa);
    }

    fn drainFn(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *SseAdapter = @alignCast(@fieldParentPtr("writer", w));
        self.pending.appendSlice(self.gpa, w.buffered()) catch return error.WriteFailed;
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            self.pending.appendSlice(self.gpa, d) catch return error.WriteFailed;
            consumed += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| self.pending.appendSlice(self.gpa, last) catch return error.WriteFailed;
        consumed += last.len * splat;
        try self.emitComplete();
        return consumed;
    }

    /// Emit every complete (newline-terminated) line currently buffered.
    fn emitComplete(self: *SseAdapter) std.Io.Writer.Error!void {
        while (std.mem.indexOfScalar(u8, self.pending.items, '\n')) |nl| {
            try self.emitLine(self.pending.items[0..nl]);
            const rest = self.pending.items.len - (nl + 1);
            std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[nl + 1 ..]);
            self.pending.shrinkRetainingCapacity(rest);
        }
    }

    fn emitLine(self: *SseAdapter, line: []const u8) std.Io.Writer.Error!void {
        const trimmed = std.mem.trimEnd(u8, line, "\r"); // tolerate CRLF
        if (trimmed.len == 0) return; // never seen from mcp, but skip blanks
        if (!self.started) {
            self.es = http.sse.EventStream.start(self.rw) catch return error.WriteFailed;
            self.started = true;
        }
        self.es.send(.{ .data = trimmed }) catch return error.WriteFailed;
    }

    /// Flush a trailing line with no final newline (defensive — mcp always ends
    /// its messages with one). Best-effort.
    fn finish(self: *SseAdapter) void {
        const rest = std.mem.trimEnd(u8, self.pending.items, "\r\n");
        if (rest.len != 0) self.emitLine(rest) catch {};
    }
};

// ── tests (offline — through http.Server.serveStream + a real router) ───────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

fn echoTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.write("{\"ok\":true}");
    return false;
}

fn workTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.reportProgress(1, 2, "step one"); // no-op unless the client sent a token
    call.reportProgress(2, 2, "step two");
    call.write("{\"done\":true}");
    return false;
}

// ── tools mirroring the real python-mcp reference capture (oracle tests) ────

/// Echoes back the `text` argument wrapped as `{"result": <value>}`, matching
/// the wrapping convention the official python `mcp` SDK's FastMCP-style
/// server (`mcp.server.mcpserver.MCPServer`) uses for a scalar tool return —
/// see `oracle_vectors.zig`'s `echo_call_response_json`, captured from a real
/// run of that SDK.
fn oracleEchoTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    const text = call.strArg("text") orelse return call.fail("missing 'text'");
    call.print("{{\"result\":\"{s}\"}}", .{text});
    return false;
}

/// Reports the same two progress steps the real captured `work` tool did
/// (`oracle_vectors.zig`'s `progress_1_json`/`progress_2_json`), then returns
/// `{"result":"done"}` in the same wrapping convention as `oracleEchoTool`.
fn oracleWorkTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.reportProgress(1, 2, "step one");
    call.reportProgress(2, 2, "step two");
    call.write("{\"result\":\"done\"}");
    return false;
}

fn buildOracleServer(gpa: std.mem.Allocator) !mcp.Server {
    var server = mcp.Server.init(gpa, .{ .name = "test", .version = "1.0" });
    errdefer server.deinit();
    try server.addTool(.{
        .name = "echo",
        .description = "Echo the given text back.",
        .input_schema = "{\"type\":\"object\"}",
        .handler = oracleEchoTool,
    });
    try server.addTool(.{
        .name = "work",
        .description = "Do some work, reporting progress twice.",
        .input_schema = "{\"type\":\"object\"}",
        .handler = oracleWorkTool,
    });
    return server;
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
    try server.addTool(.{
        .name = "work",
        .description = "work with progress",
        .input_schema = "{\"type\":\"object\"}",
        .handler = workTool,
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

fn postOrigin(comptime origin: []const u8, comptime json: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "POST /mcp HTTP/1.1\r\nHost: t\r\nOrigin: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ origin, json.len, json },
    );
}

fn postAccept(comptime accept: []const u8, comptime json: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        "POST /mcp HTTP/1.1\r\nHost: t\r\nAccept: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ accept, json.len, json },
    );
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

/// Header value of `name` (case-insensitive) from a raw response, or null.
fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

const init_body =
    \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}
;
const list_body =
    \\{"jsonrpc":"2.0","id":2,"method":"tools/list"}
;

fn postWithSession(buf: []u8, sid: []const u8, json: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "POST /mcp HTTP/1.1\r\nHost: t\r\nMcp-Session-Id: {s}\r\n" ++
        "Content-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ sid, json.len, json }) catch unreachable;
}

fn getWithSession(buf: []u8, sid: []const u8, last_event_id: ?[]const u8) []const u8 {
    if (last_event_id) |lei| {
        return std.fmt.bufPrint(buf, "GET /mcp HTTP/1.1\r\nHost: t\r\nMcp-Session-Id: {s}\r\n" ++
            "Last-Event-ID: {s}\r\nConnection: close\r\n\r\n", .{ sid, lei }) catch unreachable;
    }
    return std.fmt.bufPrint(buf, "GET /mcp HTTP/1.1\r\nHost: t\r\nMcp-Session-Id: {s}\r\nConnection: close\r\n\r\n", .{sid}) catch unreachable;
}

fn deleteWithSession(buf: []u8, sid: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "DELETE /mcp HTTP/1.1\r\nHost: t\r\nMcp-Session-Id: {s}\r\nConnection: close\r\n\r\n", .{sid}) catch unreachable;
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

test "Origin allowlist: match → 200, mismatch → 403, absent → allowed" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    const origins = [_][]const u8{"http://localhost:7717"};
    var transport = Transport{ .gpa = gpa, .server = &server, .allowed_origins = &origins };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var b1: [4096]u8 = undefined;
    const ok = runWire(&r, postOrigin("http://localhost:7717",
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ), &b1);
    try testing.expect(std.mem.startsWith(u8, ok, "HTTP/1.1 200"));

    var b2: [4096]u8 = undefined;
    const bad = runWire(&r, postOrigin("http://evil.example",
        \\{"jsonrpc":"2.0","id":2,"method":"tools/list"}
    ), &b2);
    try testing.expect(std.mem.startsWith(u8, bad, "HTTP/1.1 403"));

    // A client that sends no Origin (non-browser) is allowed even with an
    // allowlist — the DNS-rebinding attack is browser-driven.
    var b3: [4096]u8 = undefined;
    const no_origin = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":3,"method":"tools/list"}
    ), &b3);
    try testing.expect(std.mem.startsWith(u8, no_origin, "HTTP/1.1 200"));
}

test "SSE-on-POST: Accept text/event-stream → response delivered as an SSE data event" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    const got = runWire(&r, postAccept("application/json, text/event-stream",
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, got, "Content-Type: text/event-stream") != null);
    try testing.expect(std.mem.indexOf(u8, got, "Transfer-Encoding: chunked") != null);
    // The JSON-RPC response is framed as one SSE data event (whole event in one
    // chunk, so the substrings are contiguous).
    try testing.expect(std.mem.indexOf(u8, got, "data: {\"jsonrpc\"") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\"echo\"") != null);
}

test "SSE-on-POST: tool progress notifications stream live, then the result" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    const got = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"work","arguments":{},"_meta":{"progressToken":"p1"}}}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    // Two progress notifications + the final result = 3 data events.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "notifications/progress"));
    try testing.expect(std.mem.count(u8, got, "data: ") >= 3);
    try testing.expect(std.mem.indexOf(u8, got, "\\\"done\\\":true") != null);
}

test "SSE-on-POST: a notification with SSE Accept → 202, no stream started" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 202"));
    try testing.expect(std.mem.indexOf(u8, got, "text/event-stream") == null);
}

test "stream=.off forces application/json even when the client accepts SSE" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .stream = .off };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, got, "Content-Type: application/json") != null);
    try testing.expect(std.mem.indexOf(u8, got, "text/event-stream") == null);
}

test "sessions: initialize assigns Mcp-Session-Id; missing/unknown → 404; DELETE tears down" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;

    // initialize → 200 + a session id.
    const init = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
    try testing.expect(std.mem.startsWith(u8, init, "HTTP/1.1 200"));
    const sid_hdr = headerValue(init, "Mcp-Session-Id") orelse return error.NoSession;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_hdr.len], sid_hdr);
    const sid = sidbuf[0..sid_hdr.len];

    // A follow-up with no session id → 404.
    const noid = runWire(&r, postWithSession(&rbuf, "", list_body), &out);
    try testing.expect(std.mem.startsWith(u8, noid, "HTTP/1.1 404"));

    // With a bogus session id → 404.
    const bogus = runWire(&r, postWithSession(&rbuf, "deadbeef", list_body), &out);
    try testing.expect(std.mem.startsWith(u8, bogus, "HTTP/1.1 404"));

    // With the real session id → 200.
    const okid = runWire(&r, postWithSession(&rbuf, sid, list_body), &out);
    try testing.expect(std.mem.startsWith(u8, okid, "HTTP/1.1 200"));

    // DELETE → 204; afterwards the id is gone → 404.
    const del = runWire(&r, deleteWithSession(&rbuf, sid), &out);
    try testing.expect(std.mem.startsWith(u8, del, "HTTP/1.1 204"));
    const gone = runWire(&r, postWithSession(&rbuf, sid, list_body), &out);
    try testing.expect(std.mem.startsWith(u8, gone, "HTTP/1.1 404"));
}

test "sessions: GET streams pushed events as SSE; Last-Event-ID replays only newer" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;

    const init = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
    const sid_hdr = headerValue(init, "Mcp-Session-Id").?;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_hdr.len], sid_hdr);
    const sid = sidbuf[0..sid_hdr.len];

    // Push to an unknown session is a no-op (false); to ours, true.
    try testing.expect((try sessions.push("nope", "x")) == false);
    try testing.expect((try sessions.push(sid, "{\"n\":1}")) == true);
    try testing.expect((try sessions.push(sid, "{\"n\":2}")) == true);

    // GET with no Last-Event-ID → both events, id-tagged, as SSE.
    const got = runWire(&r, getWithSession(&rbuf, sid, null), &out);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, got, "Content-Type: text/event-stream") != null);
    try testing.expect(std.mem.indexOf(u8, got, "id: 1") != null);
    try testing.expect(std.mem.indexOf(u8, got, "data: {\"n\":1}") != null);
    try testing.expect(std.mem.indexOf(u8, got, "id: 2") != null);
    try testing.expect(std.mem.indexOf(u8, got, "data: {\"n\":2}") != null);

    // GET with Last-Event-ID: 1 → only event 2 (resumable replay).
    const got2 = runWire(&r, getWithSession(&rbuf, sid, "1"), &out);
    try testing.expect(std.mem.indexOf(u8, got2, "id: 2") != null);
    try testing.expect(std.mem.indexOf(u8, got2, "data: {\"n\":1}") == null);

    // GET past the last id → nothing queued: a heartbeat comment, still 200.
    const got3 = runWire(&r, getWithSession(&rbuf, sid, "2"), &out);
    try testing.expect(std.mem.startsWith(u8, got3, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, got3, ": keep-alive") != null);
    try testing.expect(std.mem.indexOf(u8, got3, "data:") == null);
}

test "sessions: GET/DELETE with an unknown session → 404" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [512]u8 = undefined;
    var out: [2048]u8 = undefined;
    try testing.expect(std.mem.startsWith(u8, runWire(&r, getWithSession(&rbuf, "ghost", null), &out), "HTTP/1.1 404"));
    try testing.expect(std.mem.startsWith(u8, runWire(&r, deleteWithSession(&rbuf, "ghost"), &out), "HTTP/1.1 404"));
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

// ── server→client requests over HTTP ───────────────────────────────────────

const init_sampling_body =
    \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"sampling":{},"elicitation":{}},"clientInfo":{"name":"c","version":"1"}}}
;

/// Records the client's answer to a server→client request.
const Answers = struct {
    calls: u32 = 0,
    text: [64]u8 = @splat(0),
    len: usize = 0,

    fn on(ctx: ?*anyopaque, resp: *const mcp.ClientResponse) void {
        const self: *Answers = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        const r = resp.samplingResult() catch return;
        const n = @min(r.content.text.len, self.text.len);
        @memcpy(self.text[0..n], r.content.text[0..n]);
        self.len = n;
    }
};

/// A tool that fires an elicitation and returns immediately (the seam's shape).
fn askTool(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    _ = call.requestElicitation(.{ .form = .{
        .message = "Please provide your GitHub username",
        .requested_schema =
        \\{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}
        ,
    } }, .{}) catch return call.fail("refused");
    call.write("{\"asked\":true}");
    return false;
}

test "POST of a JSON-RPC response → 202 and the handler runs" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var out: [4096]u8 = undefined;
    _ = runWire(&r, post("/mcp", init_sampling_body), &out);

    // Issue a sampling request out of band (stateless endpoint: the bytes would
    // go wherever the app sends them; here we only need the pending entry).
    var answers = Answers{};
    var line: std.Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    const id = try server.sendSamplingRequest(&line.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 32,
    }, .{ .on_response = &Answers.on, .ctx = &answers });
    try testing.expectEqual(@as(u64, 1), id);
    try testing.expectEqual(@as(usize, 1), server.pendingCount());

    // The client answers with a POST. No reply body ⇒ 202 Accepted.
    const got = runWire(&r, post("/mcp",
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"Paris"},"model":"m","stopReason":"endTurn"}}
    ), &out);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 202"));
    try testing.expectEqualStrings("", bodyOf(got));
    try testing.expectEqual(@as(u32, 1), answers.calls);
    try testing.expectEqualStrings("Paris", answers.text[0..answers.len]);
    try testing.expectEqual(@as(usize, 0), server.pendingCount());
}

test "sessions: a response POSTed on another session cannot resolve the request" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;

    // Two independent sessions over the same mcp.Server.
    const a_init = runWire(&r, postWithSession(&rbuf, "", init_sampling_body), &out);
    var a_buf: [64]u8 = undefined;
    const a_hdr = headerValue(a_init, "Mcp-Session-Id").?;
    @memcpy(a_buf[0..a_hdr.len], a_hdr);
    const sid_a = a_buf[0..a_hdr.len];

    const b_init = runWire(&r, postWithSession(&rbuf, "", init_sampling_body), &out);
    var b_buf: [64]u8 = undefined;
    const b_hdr = headerValue(b_init, "Mcp-Session-Id").?;
    @memcpy(b_buf[0..b_hdr.len], b_hdr);
    const sid_b = b_buf[0..b_hdr.len];
    try testing.expect(!std.mem.eql(u8, sid_a, sid_b));
    try testing.expect(sessions.tagOf(sid_a).? != sessions.tagOf(sid_b).?);

    // A sampling request bound to session A.
    var answers = Answers{};
    var line: std.Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    _ = try server.sendSamplingRequest(&line.writer, .{
        .messages = &.{.{ .role = .user, .content = .{ .text = "hi" } }},
        .max_tokens = 32,
    }, .{ .peer = sessions.tagOf(sid_a).?, .on_response = &Answers.on, .ctx = &answers });
    _ = try sessions.push(sid_a, std.mem.trimEnd(u8, line.written(), "\n"));

    const answer =
        \\{"jsonrpc":"2.0","id":1,"result":{"role":"assistant","content":{"type":"text","text":"leaked"},"model":"m"}}
    ;
    // Session B answers with the right id: 202 (nothing to reply), but the
    // request must NOT resolve — otherwise B's user's data lands in A's flow.
    const from_b = runWire(&r, postWithSession(&rbuf, sid_b, answer), &out);
    try testing.expect(std.mem.startsWith(u8, from_b, "HTTP/1.1 202"));
    try testing.expectEqual(@as(u32, 0), answers.calls);
    try testing.expectEqual(@as(usize, 1), server.pendingCount());

    // Session A answers: delivered.
    const from_a = runWire(&r, postWithSession(&rbuf, sid_a, answer), &out);
    try testing.expect(std.mem.startsWith(u8, from_a, "HTTP/1.1 202"));
    try testing.expectEqual(@as(u32, 1), answers.calls);
    try testing.expectEqualStrings("leaked", answers.text[0..answers.len]);
    try testing.expectEqual(@as(usize, 0), server.pendingCount());

    // The request itself was delivered to A's GET stream, not B's.
    const a_stream = runWire(&r, getWithSession(&rbuf, sid_a, null), &out);
    try testing.expect(std.mem.indexOf(u8, a_stream, "sampling/createMessage") != null);
    const b_stream = runWire(&r, getWithSession(&rbuf, sid_b, null), &out);
    try testing.expect(std.mem.indexOf(u8, b_stream, "sampling/createMessage") == null);
}

test "application/json mode: a tool's outbound request never lands in the body" {
    // An `application/json` body must be exactly one JSON object. A tool that
    // issues elicitation writes two lines; the earlier one must be routed to
    // the session stream, not concatenated into the response.
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    try server.addTool(.{
        .name = "ask",
        .description = "asks the user",
        .input_schema = "{\"type\":\"object\"}",
        .handler = askTool,
    });
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const init = runWire(&r, postWithSession(&rbuf, "", init_sampling_body), &out);
    const sid_hdr = headerValue(init, "Mcp-Session-Id").?;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_hdr.len], sid_hdr);
    const sid = sidbuf[0..sid_hdr.len];

    const got = runWire(&r, postWithSession(&rbuf, sid,
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ask"}}
    ), &out);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const b = bodyOf(got);
    // Exactly the tool result, and nothing of the elicitation request.
    try testing.expect(std.mem.indexOf(u8, b, "elicitation/create") == null);
    try testing.expect(std.mem.indexOf(u8, b, "\"id\":5") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, b, "\"jsonrpc\""));

    // The elicitation request went to the session's GET stream instead.
    const stream = runWire(&r, getWithSession(&rbuf, sid, null), &out);
    try testing.expect(std.mem.indexOf(u8, stream, "elicitation/create") != null);
}

test "SSE mode: a tool's outbound request streams as its own event before the result" {
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    try server.addTool(.{
        .name = "ask",
        .description = "asks the user",
        .input_schema = "{\"type\":\"object\"}",
        .handler = askTool,
    });
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var out: [8192]u8 = undefined;
    _ = runWire(&r, post("/mcp", init_sampling_body), &out);

    var out2: [8192]u8 = undefined;
    const got = runWire(&r, postAccept("text/event-stream",
        \\{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"ask"}}
    ), &out2);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const req_at = std.mem.indexOf(u8, got, "elicitation/create") orelse return error.NoRequestEvent;
    const res_at = std.mem.indexOf(u8, got, "\"id\":6") orelse return error.NoResult;
    try testing.expect(req_at < res_at); // request precedes the tool result
    try testing.expect(std.mem.count(u8, got, "data: ") >= 2);
}

test "Sessions.push: past replay_depth, the OLDEST event is evicted (mutation guard)" {
    // No prior test ever set a small replay_depth, so the FIFO-eviction branch
    // in push() (`s.events.items.len >= self.replay_depth`) was reachable only
    // by inspection: a mutation loosening it to '>' (keeping one extra event)
    // built and passed the whole suite.
    var s = Sessions.init(testing.allocator);
    defer s.deinit();
    s.replay_depth = 2;
    const id = try s.create();

    _ = try s.push(id, "a");
    _ = try s.push(id, "b");
    _ = try s.push(id, "c"); // over the cap -> "a" (event id 1) evicted

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var batch: std.ArrayList(Sessions.StoredEvent) = .empty;
    _ = (try s.drainAfter(id, 0, arena_state.allocator(), &batch)).?;
    try testing.expectEqual(@as(usize, 2), batch.items.len);
    try testing.expectEqualStrings("b", batch.items[0].data);
    try testing.expectEqualStrings("c", batch.items[1].data);
}

test "GET: a malformed Last-Event-ID header replays the whole buffer, not nothing (mutation guard)" {
    // parseLastEventId's error fallback (catch 0) is documented as "replay the
    // whole buffer" but no test ever sent an actually malformed header value
    // -- every existing GET test either omits it or sends a valid number.
    const gpa = testing.allocator;
    var server = try buildServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var rbuf: [1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const init = runWire(&r, postWithSession(&rbuf, "", init_body), &out);
    const sid_hdr = headerValue(init, "Mcp-Session-Id").?;
    var sidbuf: [64]u8 = undefined;
    @memcpy(sidbuf[0..sid_hdr.len], sid_hdr);
    const sid = sidbuf[0..sid_hdr.len];

    _ = try sessions.push(sid, "{\"n\":1}");

    const got = runWire(&r, getWithSession(&rbuf, sid, "not-a-number"), &out);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, got, "data: {\"n\":1}") != null);
}

test "Sessions.create: refuses new sessions past max_sessions (audit MED)" {
    // Batch-10 audit MED: create() had no cap, so an unauthenticated peer
    // spamming `initialize` grew the registry (and per-session replay buffers)
    // without bound. Past max_sessions, create() must fail closed.
    var s = Sessions.init(testing.allocator);
    defer s.deinit();
    s.max_sessions = 2;
    _ = try s.create();
    _ = try s.create();
    try testing.expectError(error.TooManySessions, s.create());
}

// ── oracle: replay of a real python-mcp SDK session (see oracle_vectors.zig) ─
//
// The tests below feed the EXACT request bytes a real run of the official
// `mcp` Python SDK's client sent to a real run of its server (captured once,
// frozen in `oracle_vectors.zig`, no socket opened here) through this
// module's own `Transport`, via the same offline `runWire` harness every
// other test in this file uses. This closes the gap `NOTICE`/`README.md`
// used to describe ("cross-checked for parity against a reference Dart
// server") without any captured bytes or live check ever backing it: the
// reference is now the specification's own SDK, exercised as a black-box
// oracle, and the check is real and offline.

const oracle = @import("oracle_vectors.zig");

test "oracle: the real python-mcp client's initialize request negotiates the real protocolVersion" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var sessions = Sessions.init(gpa);
    defer sessions.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server, .sessions = &sessions };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    // The real client's own Accept header, byte-exact — see oracle_vectors.zig.
    const got = runWire(&r, postAccept("application/json, text/event-stream", oracle.init_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, got, "Content-Type: text/event-stream") != null);
    try testing.expect(headerValue(got, "Mcp-Session-Id") != null);
    const b = bodyOf(got);
    try testing.expect(std.mem.indexOf(u8, b, "\"jsonrpc\":\"2.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, b, "\"id\":1") != null);
    // The exact protocolVersion string the real reference SDK negotiated for
    // this exact request (both request and response frozen from the same
    // live capture, so this is not a value we invented).
    try testing.expect(std.mem.indexOf(u8, oracle.init_response_json, "\"protocolVersion\":\"2025-11-25\"") != null);
    try testing.expect(std.mem.indexOf(u8, b, "\"protocolVersion\":\"2025-11-25\"") != null);
}

test "oracle: notifications/initialized (real client bytes) -> 202, matching the real server" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, post("/mcp", oracle.notifications_initialized_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 202"));
    try testing.expectEqualStrings("", bodyOf(got));
    // The real reference server answered the identical bytes the same way.
    try testing.expect(std.mem.startsWith(u8, oracle.notifications_initialized_status, "HTTP/1.1 202"));
}

test "oracle: tools/list (real client bytes) lists this module's tools" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    const got = runWire(&r, postAccept("application/json, text/event-stream", oracle.tools_list_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const b = bodyOf(got);
    try testing.expect(std.mem.indexOf(u8, b, "\"echo\"") != null);
    try testing.expect(std.mem.indexOf(u8, b, "\"work\"") != null);
    // Same two tool names the real reference server reported for this
    // module's own tools/list request (frozen from the live capture).
    try testing.expect(std.mem.indexOf(u8, oracle.tools_list_response_json, "\"echo\"") != null);
    try testing.expect(std.mem.indexOf(u8, oracle.tools_list_response_json, "\"work\"") != null);
}

test "oracle: tools/call \"echo\" (real client bytes) reproduces the real argument" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [4096]u8 = undefined;
    // The real client's captured tools/call request, byte-exact, including
    // its real argument value "hello-mcp-http-oracle". Plain `post` (no SSE
    // Accept) so the response is a single `application/json` object,
    // directly parseable — the SSE-framing path is exercised separately by
    // the "work" oracle test below.
    const got = runWire(&r, post("/mcp", oracle.echo_call_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    const b = bodyOf(got);

    // structuredContent is byte-comparable field-by-field (this module's tool
    // deliberately wrote the same `{"result": <value>}` wrapping FastMCP used
    // for the real capture — see oracleEchoTool's doc comment).
    var ours = try std.json.parseFromSlice(std.json.Value, gpa, b, .{});
    defer ours.deinit();
    var real = try std.json.parseFromSlice(std.json.Value, gpa, oracle.echo_call_response_json, .{});
    defer real.deinit();
    const our_sc = ours.value.object.get("result").?.object.get("structuredContent").?.object.get("result").?.string;
    const real_sc = real.value.object.get("result").?.object.get("structuredContent").?.object.get("result").?.string;
    try testing.expectEqualStrings("hello-mcp-http-oracle", real_sc); // sanity: this IS the real captured value
    try testing.expectEqualStrings(real_sc, our_sc);

    // content[0].text is NOT byte-comparable: the real SDK's framework layer
    // (FastMCP) puts the bare scalar there for a plain-string tool return,
    // while this module's lower-level ToolCall.write is opaque raw text (the
    // caller supplied the whole `{"result":...}` object as the text) — a
    // real, benign convention difference between the two layers, not a bug.
    // The marker value is still present in both, which is what we assert.
    try testing.expect(std.mem.indexOf(u8, b, "hello-mcp-http-oracle") != null);
    try testing.expect(std.mem.indexOf(u8, oracle.echo_call_response_json, "hello-mcp-http-oracle") != null);
}

test "oracle: tools/call \"work\" (real client bytes) reproduces the real progress frames byte-exact" {
    const gpa = testing.allocator;
    var server = try buildOracleServer(gpa);
    defer server.deinit();
    var transport = Transport{ .gpa = gpa, .server = &server };

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var buf: [8192]u8 = undefined;
    // The real client's captured tools/call request (progressToken: 4, a
    // bare JSON number), byte-exact.
    const got = runWire(&r, postAccept("text/event-stream", oracle.work_call_request), &buf);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, got, "Content-Type: text/event-stream") != null);

    // Byte-exact: this module's own notifications/progress field order
    // matches the real reference server's, so the captured lines are
    // asserted as literal substrings of THIS module's own SSE output.
    try testing.expect(std.mem.indexOf(u8, got, oracle.progress_1_json) != null);
    try testing.expect(std.mem.indexOf(u8, got, oracle.progress_2_json) != null);
    try testing.expect(std.mem.count(u8, got, "data: ") >= 3); // 2 progress + 1 result

    // Final result: structural comparison, same convention note as the echo
    // test above (content.text differs by framework convention; compare
    // structuredContent, which was deliberately written to match).
    const last_data = std.mem.lastIndexOf(u8, got, "data: ") orelse return error.NoResultEvent;
    const after = got[last_data + "data: ".len ..];
    const line_end = std.mem.indexOfAny(u8, after, "\r\n") orelse after.len;
    const result_line = after[0..line_end];
    var ours = try std.json.parseFromSlice(std.json.Value, gpa, result_line, .{});
    defer ours.deinit();
    var real = try std.json.parseFromSlice(std.json.Value, gpa, oracle.work_call_response_json, .{});
    defer real.deinit();
    try testing.expectEqualStrings(
        real.value.object.get("result").?.object.get("structuredContent").?.object.get("result").?.string,
        ours.value.object.get("result").?.object.get("structuredContent").?.object.get("result").?.string,
    );
}
