// SPDX-License-Identifier: MIT

//! `http-service` — a small Task-tracking JSON API, the kind of thing a
//! customer would actually run in front of the internet, built on `http` +
//! `router` and wired with the middleware stack a public-facing service
//! needs.
//!
//! **Two client shapes, two auth models, one binary:**
//!   - Machine API clients hit `/api/tasks*` with an `X-Api-Key` header
//!     (`aaa-gate`), get idempotent retries on POST/PUT (`idempotency`).
//!   - An external system posts completion events to `/webhooks/tasks`,
//!     authenticated by an HMAC signature instead of a key (`webhooksig`) —
//!     the shape a payment processor or CI system uses, not a bearer token.
//!
//! **The full middleware chain, outermost first, and why that order:**
//!
//!   1. `tracecontext`  — outermost by the module's own doc: every response,
//!      including a 401/429/503 short-circuit, must carry the trace context.
//!   2. `requestid`     — same reason, and it deliberately avoids `Ctx.data`
//!      so it composes with the auth middleware below it in the chain.
//!   3. accesslog (this file's own glue, not a `.middleware()`) — wraps the
//!      rest of the chain so its `Entry.status`/`latency_ns` reflect the
//!      FINAL outcome, whichever layer decided it.
//!   4. `security-headers` — stamps headers before anything downstream can
//!      write a byte (verified in the module source: `apply` runs before
//!      `next.run`), so every response carries them, including error pages.
//!   5. `cors`          — must run before the auth gate: a preflight
//!      `OPTIONS` carries no `Authorization`/`X-Api-Key`, so aaa-gate would
//!      reject it if it ran first (this is the module's own usage example).
//!   6. `health`        — "register before auth/rate-limit" (module doc): an
//!      orchestrator probe cannot present a credential.
//!   7. `openapi`       — public API documentation belongs next to health:
//!      no client should need a key just to read the spec.
//!   8. `metrics`       — two pieces, in the module's own order: the
//!      `/metrics` endpoint FIRST (a Prometheus scrape is an orchestrator
//!      probe like `/healthz` — it cannot present a credential, must not
//!      burn rate-limit, and must not count as traffic), then the request
//!      middleware, which sits ABOVE the three shedding layers below so a
//!      short-circuited 429/503 is still measured. Consequence of the
//!      placement, on purpose: `/healthz`, the OpenAPI doc and the scrape
//!      itself do not pollute the request metrics.
//!   9. `abuseguard`    — "register FIRST" relative to `ratelimit` (module's
//!      own usage example) so its auto-strike sees the 429s below it, plus
//!      the 401s from aaa-gate and the 400/409/422/413s from idempotency
//!      once those groups are nested inside this chain.
//!  10. `ratelimit`     — per-client token bucket, cheap and specific.
//!  11. `throttle`      — the last-resort global concurrency shed; it
//!      protects the server even when every per-client check passed.
//!
//! Then two route groups, each adding only the middleware ITS clients need:
//!   `/api/*`      → `aaa-gate` (API-key auth) + `idempotency`
//!   `/webhooks/*` → `webhooksig` (HMAC verification)
//!
//! **Left out of the 14, and why:**
//!   - `sessions` (+ its `csrf` sibling) — this is a machine-to-machine JSON
//!     API with no browser-rendered login page; there is no form to protect
//!     and no session cookie to issue. A customer adding a browser admin
//!     panel on top would wire `sessions` the same way `aaa-gate` is wired
//!     here (`router.use` on its own group).
//!
//! **The three that do not compose as `router.Middleware` (per the brief) —
//! used in their own shape, or left out:**
//!   - `accesslog` IS used, but as a plain `Entry → Writer` formatter called
//!     from a hand-written wrapper around `next.run` (see `accessLogRun`
//!     below) — exactly the shape its own docs describe, not bent into a
//!     `.middleware()` that does not exist.
//!   - `staticfiles` — left out. This service has no static assets; a JSON
//!     API serves nothing `staticfiles.Handler.serve` would help with.
//!   - `websocket` — left out. Nothing here needs a long-lived bidirectional
//!     stream; a customer wanting live task-update push would upgrade a
//!     dedicated route with it, outside the router chain, same as the
//!     module's own shape requires.
//!
//! Built against the modules as they exist in THIS working tree (not the
//! last release tag — see `build.zig.zon` and README for what that means for
//! the customer download path).

const std = @import("std");
const http = @import("http");
const router = @import("router");
const cors = @import("cors");
const security_headers = @import("security-headers");
const ratelimit = @import("ratelimit");
const requestid = @import("requestid");
const health = @import("health");
const throttle = @import("throttle");
const abuseguard = @import("abuseguard");
const aaa_gate = @import("aaa-gate");
const idempotency = @import("idempotency");
const tracecontext = @import("tracecontext");
const webhooksig = @import("webhooksig");
const openapi = @import("openapi");
const ramcache = @import("ramcache");
const accesslog = @import("accesslog");
const metrics = @import("metrics");
const netaddr = @import("netaddr");

const Allocator = std.mem.Allocator;

// ─────────────────────────────────────────────────────────────────────────────
// small clock helpers — this repo's convention (see modules/filestore,
// modules/abuseguard): std.time's wall/monotonic timestamp functions are
// removed in 0.16, so every module reads `std.posix.system.clock_gettime`
// directly rather than the (also-removed) std.time.Instant.
// ─────────────────────────────────────────────────────────────────────────────

fn wallNowNs() i64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
}

fn monoNowNs() u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ─────────────────────────────────────────────────────────────────────────────
// the business: an in-memory Task store
// ─────────────────────────────────────────────────────────────────────────────

const max_request_body = 16 * 1024; // one JSON task body, generously capped
const max_title_len = 200;

const Task = struct {
    id: u64,
    title: []u8, // gpa-owned
    done: bool,
    created_ns: i64,
};

/// Everything the handlers share, reached through `router.Ctx.state`. One
/// value on `runServer`'s stack — no globals, so two `App`s (two tenants,
/// two ports) would just be two of these.
const App = struct {
    gpa: Allocator,
    lock: std.atomic.Mutex = .unlocked,
    tasks: std.ArrayList(Task) = .empty,
    next_id: u64 = 1,
    /// Not owned here — the idempotency Store outlives the App the same way
    /// it outlives the Router (both live on `runServer`'s stack).
    idem_store: *idempotency.Store,
    /// Business metric, beside the middleware's request signals: how many
    /// tasks this process has created. Registered in `runServer`; null only
    /// until the registry exists.
    tasks_created: ?*metrics.Counter = null,

    fn deinit(a: *App) void {
        for (a.tasks.items) |t| a.gpa.free(t.title);
        a.tasks.deinit(a.gpa);
    }
};

fn appLock(a: *App) void {
    while (!a.lock.tryLock()) std.atomic.spinLoopHint();
}

fn findTaskIndex(a: *App, id: u64) ?usize {
    for (a.tasks.items, 0..) |t, i| if (t.id == id) return i;
    return null;
}

/// Readiness check bound to the task store — always true in practice (there
/// is no real dependency to fail here), but it is a REAL predicate over
/// `App` state, not a stub, so it demonstrates the `health.Check` seam
/// honestly: a database-backed service would swap this for a connection
/// flag with the same shape.
const max_tasks_sane_cap = 1_000_000;
fn taskStoreHealthy(ctx: ?*anyopaque) bool {
    const app: *App = @ptrCast(@alignCast(ctx.?));
    appLock(app);
    defer app.lock.unlock();
    return app.tasks.items.len < max_tasks_sane_cap;
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON helpers
// ─────────────────────────────────────────────────────────────────────────────

fn writeTaskJson(jw: *std.json.Stringify, t: *const Task) !void {
    try jw.beginObject();
    try jw.objectField("id");
    try jw.write(t.id);
    try jw.objectField("title");
    try jw.write(t.title);
    try jw.objectField("done");
    try jw.write(t.done);
    try jw.objectField("created_ns");
    try jw.write(t.created_ns);
    try jw.endObject();
}

fn jsonError(ctx: *router.Ctx, status: u16, msg: []const u8) !void {
    ctx.res.setStatus(status);
    try ctx.res.setHeader("Content-Type", "application/json");
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    var jw: std.json.Stringify = .{ .writer = &w, .options = .{} };
    jw.beginObject() catch return ctx.res.writeAll("{\"error\":\"internal\"}\n");
    jw.objectField("error") catch {};
    jw.write(msg) catch {};
    jw.endObject() catch {};
    try ctx.res.writeAll(w.buffered());
}

fn parseId(ctx: *router.Ctx) ?u64 {
    const raw = ctx.params.get("id") orelse return null;
    return std.fmt.parseInt(u64, raw, 10) catch null;
}

// ─────────────────────────────────────────────────────────────────────────────
// route handlers
// ─────────────────────────────────────────────────────────────────────────────

fn indexHandler(ctx: *router.Ctx) anyerror!void {
    try ctx.res.setHeader("Content-Type", "text/plain; charset=utf-8");
    try ctx.res.writeAll(
        \\http-service -- a hardened Task API example built on `http` + `router`.
        \\
        \\  GET    /healthz             liveness              (no auth)
        \\  GET    /readyz              readiness             (no auth)
        \\  GET    /openapi.json        OpenAPI 3.1 document  (no auth)
        \\  GET    /api/tasks           list tasks             (X-Api-Key)
        \\  POST   /api/tasks           create a task          (X-Api-Key, Idempotency-Key optional)
        \\  GET    /api/tasks/:id       get one task           (X-Api-Key)
        \\  PUT    /api/tasks/:id       update a task          (X-Api-Key, Idempotency-Key optional)
        \\  DELETE /api/tasks/:id       delete a task          (X-Api-Key)
        \\  POST   /webhooks/tasks      completion event, HMAC-signed (X-Signature-256)
        \\
        \\See README.md for the api-key / webhook-secret this process started
        \\with and a full curl walkthrough.
        \\
    );
}

const CreateBody = struct { title: []const u8 };

fn createTask(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));

    const body_bytes = ctx.req.reader().allocRemaining(app.gpa, .limited(max_request_body)) catch |err| switch (err) {
        error.StreamTooLong => return jsonError(ctx, 413, "request body too large (cap 16 KiB)"),
        else => |e| return e,
    };
    defer app.gpa.free(body_bytes);

    var parsed = std.json.parseFromSlice(CreateBody, app.gpa, body_bytes, .{}) catch
        return jsonError(ctx, 400, "malformed JSON: expected {\"title\": \"...\"}");
    defer parsed.deinit();
    const title = std.mem.trim(u8, parsed.value.title, " \t\r\n");
    if (title.len == 0 or title.len > max_title_len)
        return jsonError(ctx, 400, "title must be 1..200 bytes");

    const owned_title = try app.gpa.dupe(u8, title);
    // NB: deliberately NO `errdefer free(owned_title)`. Ownership transfers to
    // the task list on a successful append; after that point freeing it would
    // double-free (deinit frees every list title) and dangle every reader. So
    // the two fallible steps BEFORE the transfer free it explicitly, and
    // nothing after the transfer frees it — a later respond() failure then
    // leaves the task legitimately stored rather than corrupting the store.

    var aw: std.Io.Writer.Allocating = .init(app.gpa);
    defer aw.deinit();

    appLock(app);
    const id = app.next_id;
    app.next_id += 1;
    const task: Task = .{ .id = id, .title = owned_title, .done = false, .created_ns = wallNowNs() };
    var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
    // Render BEFORE the append transfers ownership, and under the lock so the
    // bytes cannot depend on the title surviving a concurrent DELETE. On
    // failure we still solely own owned_title, so we free it.
    writeTaskJson(&jw, &task) catch |err| {
        app.gpa.free(owned_title);
        app.lock.unlock();
        return err;
    };
    app.tasks.append(app.gpa, task) catch |err| {
        app.gpa.free(owned_title);
        app.lock.unlock();
        return err;
    };
    app.lock.unlock();

    if (app.tasks_created) |c| c.inc();
    if (aaa_gate.identityOf(ctx)) |id_| id_.audit_detail = "created a task";
    try app.idem_store.respond(ctx, 201, "application/json", aw.written());
}

fn listTasks(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    // Render into a private buffer UNDER the lock, then write to the socket
    // AFTER releasing it. App.lock is a spinlock; holding it across a blocking
    // write to a slow client makes every other handler busy-spin a core. The
    // JSON array outgrows http.Server's 4 KiB response buffer at a few dozen
    // tasks, so the write genuinely blocks — this is not a theoretical window.
    var aw: std.Io.Writer.Allocating = .init(app.gpa);
    defer aw.deinit();
    {
        appLock(app);
        defer app.lock.unlock();
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        try jw.beginArray();
        for (app.tasks.items) |*t| try writeTaskJson(&jw, t);
        try jw.endArray();
    }
    ctx.res.setStatus(200);
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.writer().writeAll(aw.written());
}

fn getTask(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    const id = parseId(ctx) orelse return jsonError(ctx, 400, "bad task id");
    var aw: std.Io.Writer.Allocating = .init(app.gpa);
    defer aw.deinit();
    {
        appLock(app);
        defer app.lock.unlock();
        const idx = findTaskIndex(app, id) orelse return jsonError(ctx, 404, "no such task");
        // Render under the lock (a concurrent DELETE could free the title);
        // write to the socket after unlocking, same reason as listTasks.
        var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
        try writeTaskJson(&jw, &app.tasks.items[idx]);
    }
    ctx.res.setStatus(200);
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.writer().writeAll(aw.written());
}

const UpdateBody = struct { title: ?[]const u8 = null, done: ?bool = null };

fn updateTask(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    const id = parseId(ctx) orelse return jsonError(ctx, 400, "bad task id");

    const body_bytes = ctx.req.reader().allocRemaining(app.gpa, .limited(max_request_body)) catch |err| switch (err) {
        error.StreamTooLong => return jsonError(ctx, 413, "request body too large (cap 16 KiB)"),
        else => |e| return e,
    };
    defer app.gpa.free(body_bytes);
    var parsed = std.json.parseFromSlice(UpdateBody, app.gpa, body_bytes, .{}) catch
        return jsonError(ctx, 400, "malformed JSON body");
    defer parsed.deinit();
    if (parsed.value.title) |nt| {
        const trimmed = std.mem.trim(u8, nt, " \t\r\n");
        if (trimmed.len == 0 or trimmed.len > max_title_len)
            return jsonError(ctx, 400, "title must be 1..200 bytes");
    }

    var aw: std.Io.Writer.Allocating = .init(app.gpa);
    defer aw.deinit();

    appLock(app);
    const idx = findTaskIndex(app, id) orelse {
        app.lock.unlock();
        return jsonError(ctx, 404, "no such task");
    };
    if (parsed.value.title) |nt| {
        const trimmed = std.mem.trim(u8, nt, " \t\r\n");
        const owned = app.gpa.dupe(u8, trimmed) catch |err| {
            app.lock.unlock();
            return err;
        };
        app.gpa.free(app.tasks.items[idx].title);
        app.tasks.items[idx].title = owned;
    }
    if (parsed.value.done) |d| app.tasks.items[idx].done = d;
    var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
    writeTaskJson(&jw, &app.tasks.items[idx]) catch |err| {
        app.lock.unlock();
        return err;
    };
    app.lock.unlock();

    if (aaa_gate.identityOf(ctx)) |id_| id_.audit_detail = "updated a task";
    try app.idem_store.respond(ctx, 200, "application/json", aw.written());
}

fn deleteTask(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    const id = parseId(ctx) orelse return jsonError(ctx, 400, "bad task id");
    appLock(app);
    const idx = findTaskIndex(app, id) orelse {
        app.lock.unlock();
        return jsonError(ctx, 404, "no such task");
    };
    const removed = app.tasks.swapRemove(idx);
    app.lock.unlock();
    app.gpa.free(removed.title);
    if (aaa_gate.identityOf(ctx)) |id_| id_.audit_detail = "deleted a task";
    ctx.res.setStatus(204);
}

const WebhookBody = struct { id: u64, event: []const u8 = "completed" };

/// The external-system side: no `X-Api-Key`, no session — a signed body
/// instead (RFC 2104 HMAC-SHA256 over the exact bytes received). The raw
/// body was already drained and verified by `webhooksig.Verifier.middleware`
/// before this handler ever runs; `webhooksig.bodyOf` is how a handler below
/// it gets those exact bytes back (the middleware owns the one read).
fn webhookTaskEvent(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    const raw = webhooksig.bodyOf(ctx) orelse return jsonError(ctx, 400, "missing verified body");

    var parsed = std.json.parseFromSlice(WebhookBody, app.gpa, raw, .{}) catch
        return jsonError(ctx, 400, "malformed JSON: expected {\"id\": <task id>}");
    defer parsed.deinit();

    var aw: std.Io.Writer.Allocating = .init(app.gpa);
    defer aw.deinit();

    appLock(app);
    const idx = findTaskIndex(app, parsed.value.id) orelse {
        app.lock.unlock();
        return jsonError(ctx, 404, "no such task");
    };
    app.tasks.items[idx].done = true;
    var jw: std.json.Stringify = .{ .writer = &aw.writer, .options = .{} };
    writeTaskJson(&jw, &app.tasks.items[idx]) catch |err| {
        app.lock.unlock();
        return err;
    };
    app.lock.unlock();

    ctx.res.setStatus(200);
    try ctx.res.setHeader("Content-Type", "application/json");
    try ctx.res.writeAll(aw.written());
}

// ─────────────────────────────────────────────────────────────────────────────
// accesslog — used in its own shape (README "the three that do not compose")
//
// `accesslog` is a plain `Entry -> Writer` formatter, not a `router.Middleware`
// — there is no `.middleware()` to call. This wrapper IS a real
// `router.Middleware` (hand-written, `state = null`) whose whole job is to
// call `next.run`, then build an `Entry` from the finished exchange and hand
// it to `accesslog.writeJsonLines`. Registered early (position 3) so
// `res.status`/latency reflect whatever any inner layer decided.
// ─────────────────────────────────────────────────────────────────────────────

fn accessLogRun(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const t0 = monoNowNs();
    try next.run(ctx);
    const latency_ns = monoNowNs() -| t0;

    var addr_buf: [64]u8 = undefined;
    const entry = accesslog.entryFromRequest(ctx.req, ctx.res, &addr_buf, .{
        .timestamp_ns = wallNowNs(),
        .latency_ns = latency_ns,
        .request_id = requestid.current(),
    });
    var line_buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&line_buf);
    accesslog.writeJsonLines(entry, &w) catch {
        std.debug.print("accesslog: line exceeded scratch buffer, dropped\n", .{});
        return;
    };
    std.debug.print("{s}", .{w.buffered()});
}

// ─────────────────────────────────────────────────────────────────────────────
// direct-internet client keying — ratelimit's own README warning, heeded:
// KeySource.forwarded_ip trusts X-Forwarded-For/X-Real-IP, which a client
// talking to this server directly (no reverse proxy) can forge to rotate
// through fresh buckets. This app IS the edge, so the key is the socket
// peer only.
// ─────────────────────────────────────────────────────────────────────────────

threadlocal var ratelimit_key_buf: [netaddr.max_ip_text_len]u8 = undefined;

fn peerOnlyKey(_: ?*anyopaque, ctx: *router.Ctx) []const u8 {
    const peer = ctx.req.peerAddress() orelse return ratelimit.fallback_key;
    const ip: netaddr.Ip = switch (peer) {
        .ip4 => |a| .{ .v4 = a.bytes },
        .ip6 => |a| .{ .v6 = a.bytes },
    };
    return netaddr.formatIp(ip.unmap(), &ratelimit_key_buf);
}

fn auditLog(_: ?*anyopaque, entry: aaa_gate.AuditEntry) void {
    std.debug.print(
        "aaa-gate: {t} {s} authed={} status={d} detail=\"{s}\" suppressed={d}\n",
        .{ entry.method, entry.path, entry.authed, entry.status, entry.detail, entry.suppressed },
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// wiring
// ─────────────────────────────────────────────────────────────────────────────

const default_port: u16 = 8087;
const default_api_key = "demo-api-key-change-me";
const default_webhook_secret = "demo-webhook-secret-change-me";

const usage_text =
    \\http-service -- a hardened Task-tracking HTTP API example.
    \\
    \\usage: http-service [options]
    \\
    \\options:
    \\  --listen <addr>        address to bind               (default 127.0.0.1)
    \\  --port <port>          TCP port                      (default 8087)
    \\  --api-key <key>        required X-Api-Key for /api/*   (default a fixed demo key -- see README)
    \\  --webhook-secret <s>   HMAC secret for /webhooks/*     (default a fixed demo secret -- see README)
    \\  -h, --help             this text
    \\
    \\Both defaults are fixed, published strings meant ONLY for this loopback
    \\demo -- see the startup banner and README for real curl commands using
    \\them. Never pass a real secret on a command line (`ps` can read it);
    \\that is exactly the caveat this module's own `--password-is` flags
    \\carry elsewhere in this collection.
    \\
;

// ── graceful shutdown ────────────────────────────────────────────────────────
//
// A service that can only be killed is a service whose teardown never runs, and
// this one's teardown is load-bearing: `main` frees the task store, the
// idempotency cache and every middleware, under a `DebugAllocator` that panics
// on leak. Killed with SIGKILL — which is what a test harness reaches for when
// there is nothing else — that check can never fire, so it says nothing.
//
// SIGTERM and SIGINT therefore stop the accept loop instead. The handler only
// stores a flag (the one thing that is unambiguously safe to do in a signal
// handler); a watcher thread does the actual `shutdown()`, which goes through
// `std.Io` and must not run in handler context. 100 ms of latency on Ctrl-C is
// invisible and buys not having to write a self-pipe.
var stop_requested: std.atomic.Value(bool) = .init(false);
var serve_finished: std.atomic.Value(bool) = .init(false);

fn onStopSignal(_: std.posix.SIG) callconv(.c) void {
    stop_requested.store(true, .release);
}

fn shutdownWatcher(server: *http.Server, io: std.Io) void {
    while (!stop_requested.load(.acquire)) {
        if (serve_finished.load(.acquire)) return; // the loop ended on its own
        io.sleep(.fromMilliseconds(100), .awake) catch return;
    }
    std.debug.print("http-service: signal received, draining\n", .{});
    server.shutdown();
}

fn installStopHandlers() void {
    var act: std.posix.Sigaction = .{
        .handler = .{ .handler = onStopSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.TERM, &act, null);
    std.posix.sigaction(.INT, &act, null);
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listen_addr: []const u8 = "127.0.0.1";
    var port: u16 = default_port;
    var api_key: []const u8 = default_api_key;
    var webhook_secret: []const u8 = default_webhook_secret;

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--listen")) {
            listen_addr = args.next() orelse {
                std.debug.print("http-service: --listen needs a value\n", .{});
                return 1;
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            const v = args.next() orelse {
                std.debug.print("http-service: --port needs a value\n", .{});
                return 1;
            };
            port = std.fmt.parseInt(u16, v, 10) catch {
                std.debug.print("http-service: --port wants a number, got '{s}'\n", .{v});
                return 1;
            };
        } else if (std.mem.eql(u8, arg, "--api-key")) {
            api_key = args.next() orelse {
                std.debug.print("http-service: --api-key needs a value\n", .{});
                return 1;
            };
        } else if (std.mem.eql(u8, arg, "--webhook-secret")) {
            webhook_secret = args.next() orelse {
                std.debug.print("http-service: --webhook-secret needs a value\n", .{});
                return 1;
            };
        } else {
            std.debug.print("http-service: unknown option '{s}' (try --help)\n", .{arg});
            return 1;
        }
    }

    return runServer(gpa, io, listen_addr, port, api_key, webhook_secret);
}

fn runServer(
    gpa: Allocator,
    io: std.Io,
    listen_addr: []const u8,
    port: u16,
    api_key: []const u8,
    webhook_secret: []const u8,
) !u8 {
    // ── idempotency's cache-backed store ───────────────────────────────────
    var idem_cache = ramcache.Cache.init(gpa, .{ .max_bytes = 8 << 20, .max_entries = 4096 });
    defer idem_cache.deinit();
    var idem_store: idempotency.Store = .{ .cache = &idem_cache };
    defer idem_store.deinit();
    var idem: idempotency.Idempotency = .{ .store = &idem_store };

    var app: App = .{ .gpa = gpa, .idem_store = &idem_store };
    defer app.deinit();

    // ── the middleware instances (all stack-local, all outlive the Router
    //    the same way `ServerState` does in the sibling ssh-demo/http-demo
    //    examples: this function blocks in `server.serve()` for the whole
    //    process lifetime) ────────────────────────────────────────────────
    var tc: tracecontext.TraceContext = .{};
    var ri: requestid.RequestId = .{};

    var sh = security_headers.SecurityHeaders.init(.{
        // A pure JSON API renders nothing a browser executes: deny-everything
        // is strictly more correct than helmet's browser-app default.
        .content_security_policy = security_headers.csp_api,
    }) catch |err| {
        std.debug.print("http-service: SecurityHeaders.init: {t}\n", .{err});
        return 1;
    };

    var cors_mw = cors.Cors.init(gpa, .{
        .allowed_origins = .{ .list = &.{"http://localhost:5173"} }, // example SPA dev origin
        .allowed_methods = &.{ .get, .post, .put, .delete },
        .exposed_headers = &.{ "X-Request-Id", "Idempotent-Replayed" },
        .max_age_s = 600,
    }) catch |err| {
        std.debug.print("http-service: Cors.init: {t}\n", .{err});
        return 1;
    };
    defer cors_mw.deinit();

    var checks = [_]health.Check{.{ .name = "task-store", .checkFn = taskStoreHealthy, .ctx = &app }};
    var h: health.Health = .{ .checks = &checks };

    var r: router.Router = .init(gpa);
    defer r.deinit();
    r.state = &app;

    var docs: openapi.Endpoint = .{
        .gpa = gpa,
        .router = &r,
        .info = .{ .title = "http-service Task API", .version = "1.0.0" },
    };
    defer docs.deinit();

    var reg = metrics.Registry.init(gpa);
    defer reg.deinit();
    var rm = metrics.RequestMetrics.init(&reg, .{}) catch |err| {
        std.debug.print("http-service: RequestMetrics.init: {t}\n", .{err});
        return 1;
    };
    var ep = metrics.Endpoint{ .registry = &reg }; // GET /metrics
    app.tasks_created = reg.counter("tasks_created_total", "Tasks created over the API.", &.{}) catch |err| {
        std.debug.print("http-service: counter: {t}\n", .{err});
        return 1;
    };

    var guard = abuseguard.Guard.init(gpa, .{
        .max_conns_per_ip = 50,
        .ban_threshold = 8,
        .ban_after_offenses = 2,
    });
    defer guard.deinit();

    var limiter = ratelimit.Limiter.init(gpa, .{
        .rate_per_s = 5,
        .burst = 10,
        .max_keys = 4096,
        .key = .{ .custom = .{ .keyFor = peerOnlyKey } }, // never .forwarded_ip -- see peerOnlyKey's doc
    });
    defer limiter.deinit();

    var th = throttle.Throttle.init(.{
        .max_in_flight = 32,
        .retry_after_ms = 1_000,
    });
    defer th.deinit();

    var gate = aaa_gate.Gate.init(gpa, .{
        .auth_mode = .api_key,
        .api_key = api_key,
        .api_key_header = "X-Api-Key",
        .deny_body = "{\"error\":\"unauthorized\"}\n",
        .deny_content_type = "application/json",
        .on_audit = auditLog,
    }) catch |err| {
        std.debug.print("http-service: Gate.init: {t}\n", .{err});
        return 1;
    };
    defer gate.deinit();

    var verifier = webhooksig.Verifier.init(gpa, .{
        .secret = webhook_secret,
        .header = "X-Signature-256",
    }) catch |err| {
        std.debug.print("http-service: Verifier.init: {t}\n", .{err});
        return 1;
    };
    defer verifier.deinit();

    // ── global middleware (see the module doc comment above for the full
    //    rationale of this exact order) — ALL of it must be registered
    //    before ANY route (including group routes) is added: `Router.use`
    //    refuses once `routes_added` flips, and adding a route through a
    //    group flips it on the shared Router too. ─────────────────────────
    try r.use(tc.middleware());
    try r.use(ri.middleware());
    try r.use(.{ .state = null, .run = accessLogRun });
    try r.use(sh.middleware());
    try r.use(cors_mw.middleware());
    try r.use(h.middleware());
    try r.use(docs.middleware());
    try r.use(ep.middleware()); // scrape short-circuits here: never limited, never counted
    try r.use(rm.middleware()); // measures everything below, incl. 429/503 sheds
    try r.use(guard.middleware());
    try r.use(limiter.middleware());
    try r.use(th.middleware());

    const api = try r.group("/api");
    try api.use(gate.middleware());
    try api.use(idem.middleware());

    const webhooks = try r.group("/webhooks");
    try webhooks.use(verifier.middleware());

    // ── routes (now that every `use` above has run) ────────────────────────
    try r.get("/", indexHandler);

    try api.addDoc(.get, "/tasks", listTasks, .{
        .summary = "List all tasks",
        .tags = &.{"tasks"},
        .responses = &.{.{ .status = 200, .description = "The task list" }},
    });
    try api.addDoc(.post, "/tasks", createTask, .{
        .summary = "Create a task",
        .tags = &.{"tasks"},
        .request_schema = "{\"type\":\"object\",\"required\":[\"title\"],\"properties\":{\"title\":{\"type\":\"string\"}}}",
        .responses = &.{.{ .status = 201, .description = "Created" }},
    });
    try api.addDoc(.get, "/tasks/:id", getTask, .{
        .summary = "Get one task",
        .tags = &.{"tasks"},
        .responses = &.{
            .{ .status = 200, .description = "The task" },
            .{ .status = 404, .description = "No such task" },
        },
    });
    try api.addDoc(.put, "/tasks/:id", updateTask, .{
        .summary = "Update a task",
        .tags = &.{"tasks"},
        .request_schema = "{\"type\":\"object\",\"properties\":{\"title\":{\"type\":\"string\"},\"done\":{\"type\":\"boolean\"}}}",
        .responses = &.{
            .{ .status = 200, .description = "Updated" },
            .{ .status = 404, .description = "No such task" },
        },
    });
    try api.addDoc(.delete, "/tasks/:id", deleteTask, .{
        .summary = "Delete a task",
        .tags = &.{"tasks"},
        .responses = &.{.{ .status = 204, .description = "Deleted" }},
    });

    try webhooks.addDoc(.post, "/tasks", webhookTaskEvent, .{
        .summary = "External task-completion event (HMAC-signed)",
        .tags = &.{"webhooks"},
        .request_schema = "{\"type\":\"object\",\"required\":[\"id\"],\"properties\":{\"id\":{\"type\":\"integer\"}}}",
        .responses = &.{
            .{ .status = 200, .description = "Acknowledged" },
            .{ .status = 401, .description = "Bad or missing signature" },
            .{ .status = 404, .description = "No such task" },
        },
    });

    // ── the server ──────────────────────────────────────────────────────────
    var server: http.Server = .init(io, gpa, .{
        .handler = r.handler(),
        .context = &r,
        .addr = listen_addr,
        .port = port,
        // Connection-level admission (nginx `limit_conn` + fail2ban shape),
        // separate from `guard.middleware()`'s auto-strike above: this pair
        // rejects an abusive peer AT ACCEPT TIME, before a single byte of
        // request is read.
        .on_connect = guard.onConnect(),
        .on_connect_ctx = guard.onConnectCtx(),
        .on_conn_state = guard.onConnState(),
        .on_conn_state_ctx = guard.onConnStateCtx(),
        .max_body_bytes = 1 << 20,
        .server_name = null, // fingerprint reduction is security-headers' job
    });
    defer server.deinit();

    server.bind() catch |err| {
        std.debug.print("http-service: cannot bind {s}:{d}: {t} ({s})\n", .{
            listen_addr,
            port,
            err,
            server.bindErrorName() orelse "no detail",
        });
        return 1;
    };
    const bound = server.boundAddress();
    printBanner(listen_addr, bound.getPort(), api_key, webhook_secret);

    installStopHandlers();
    const watcher = std.Thread.spawn(.{}, shutdownWatcher, .{ &server, io }) catch |err| {
        std.debug.print("http-service: cannot start the shutdown watcher: {t}\n", .{err});
        return 1;
    };
    defer {
        // Whichever way `serve` ended, release the watcher so this process can
        // actually exit — and so the leak check at the top of `main` runs.
        serve_finished.store(true, .release);
        watcher.join();
    }

    server.serve() catch |err| {
        std.debug.print("http-service: accept loop ended: {t}\n", .{err});
        return 1;
    };
    std.debug.print("http-service: stopped cleanly\n", .{});
    return 0;
}

fn printBanner(addr: []const u8, port: u16, api_key: []const u8, webhook_secret: []const u8) void {
    std.debug.print(
        \\http-service: listening on http://{s}:{d}
        \\
        \\  X-Api-Key:        {s}
        \\  webhook secret:   {s}   (HMAC-SHA256, X-Signature-256: sha256=<hex>)
        \\
        \\Try it:
        \\  curl -sSD- http://{s}:{d}/healthz
        \\  curl -sSD- http://{s}:{d}/openapi.json
        \\  curl -sSD- -H "X-Api-Key: {s}" \
        \\       -H 'Content-Type: application/json' -d '{{"title":"write the report"}}' \
        \\       http://{s}:{d}/api/tasks
        \\
        \\See README.md for the full walkthrough (rate-limit rejection, the
        \\signed webhook, idempotent replay, security headers).
        \\
    , .{ addr, port, api_key, webhook_secret, addr, port, addr, port, api_key, addr, port });
}
