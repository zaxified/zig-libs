// SPDX-License-Identifier: MIT

//! health — liveness + readiness probe endpoints as a `router` middleware
//! (the Kubernetes / load-balancer health-check contract).
//!
//! Two orthogonal signals, following the k8s probe model:
//!
//! - **Liveness** (`/healthz` by default): "the process is up and not
//!   wedged." Always answers **200** — a bare "is the server answering HTTP
//!   at all" check. A liveness failure means "restart me"; this module never
//!   fails liveness (a process that can run this handler is alive), so wire a
//!   liveness probe to it and let the orchestrator restart on *no response*.
//! - **Readiness** (`/readyz` by default): "ready to receive traffic."
//!   Answers **200** when every registered `Check` passes, else **503** with
//!   the failing check names in the body. A readiness failure means "take me
//!   out of the load-balancer rotation but do not restart" — use it for
//!   dependencies that can recover (a database reconnecting, a cache warming,
//!   a shed-load flag).
//!
//! It is a middleware, not a set of handlers, because a `router.Handler`
//! carries no per-instance state: the middleware owns the `Health` config and
//! intercepts the two probe paths, passing everything else through. Register
//! it **before** auth / rate-limit middleware so probes are never gated
//! (an orchestrator cannot present a bearer token).
//!
//! ## Usage
//!
//! ```zig
//! fn dbReady(ctx: ?*anyopaque) bool {
//!     const app: *App = @ptrCast(@alignCast(ctx.?));
//!     return app.db_connected.load(.acquire);
//! }
//! var checks = [_]health.Check{ .{ .name = "database", .checkFn = dbReady, .ctx = &app } };
//! var h = health.Health{ .checks = &checks };
//! try my_router.use(h.middleware()); // before auth/ratelimit
//! ```
//!
//! Bodies are written through the response writer (which copies), so the
//! failing-check listing is assembled on the stack — no allocation, and the
//! only shared state read is whatever your `Check` callbacks touch (they run
//! on the connection thread; make them thread-safe).

const std = @import("std");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    // The middleware only reads its immutable config; readiness is as
    // thread-safe as the caller's Check callbacks (documented).
    .concurrency = .threadsafe,
    .model_after = "Kubernetes liveness/readiness probes; the /healthz-/readyz convention",
    .deps = .{ "router", "http" },
};

/// A readiness predicate: returns true when this dependency is ready. `ctx` is
/// the `Check.ctx` verbatim. Runs on the serving connection thread — make it
/// non-blocking and thread-safe (typically an atomic-flag load).
pub const CheckFn = *const fn (ctx: ?*anyopaque) bool;

/// One named readiness dependency.
pub const Check = struct {
    /// Short identifier surfaced in the 503 body (e.g. "database"). Keep it a
    /// header-token-ish word; it is written to the response body verbatim.
    name: []const u8,
    checkFn: CheckFn,
    ctx: ?*anyopaque = null,
};

/// Probe configuration + the middleware over it. Immutable after construction;
/// share one instance freely across the router's connection threads.
pub const Health = struct {
    /// Readiness checks — ALL must pass for a 200. Empty ⇒ readiness always
    /// 200 (a liveness-equivalent readiness, the default).
    checks: []const Check = &.{},
    /// Liveness path (exact match, GET/HEAD).
    live_path: []const u8 = "/healthz",
    /// Readiness path (exact match, GET/HEAD).
    ready_path: []const u8 = "/readyz",
    /// Whether a 503 body names the checks that failed.
    ///
    /// On by default because that is what makes the probe useful to an
    /// operator. Turn it off when the probe is reachable from outside the
    /// cluster: the names are internal topology ("database", "kafka",
    /// "billing-api"), and a 503 that enumerates them tells an attacker what
    /// you depend on and which dependency is currently down. The status code
    /// is unchanged either way — Kubernetes only reads that.
    detail: bool = true,

    pub fn middleware(h: *const Health) router.Middleware {
        return .{ .state = @constCast(h), .run = middlewareRun };
    }
};

fn isProbeMethod(m: http.Method) bool {
    return m == .get or m == .head;
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const h: *const Health = @ptrCast(@alignCast(state.?));
    const req = ctx.req;

    if (isProbeMethod(req.method)) {
        if (std.mem.eql(u8, req.path, h.live_path)) return respondLive(ctx.res);
        if (std.mem.eql(u8, req.path, h.ready_path)) return respondReady(h, ctx.res);
    }
    return next.run(ctx);
}

fn respondLive(res: *http.Server.ResponseWriter) anyerror!void {
    res.setStatus(200);
    try res.setHeader("Content-Type", "text/plain");
    try res.setHeader("Cache-Control", "no-store");
    try res.writeAll("OK\n");
}

/// Bytes of "not ready: <name>" lines a 503 body carries. Past this the body
/// is truncated with a marker rather than growing — a probe response is not a
/// place to let an unbounded number of names size a buffer.
const detail_buf_len = 512;

fn respondReady(h: *const Health, res: *http.Server.ResponseWriter) anyerror!void {
    // Every check runs EXACTLY ONCE. It used to run twice — once to decide the
    // status, once to write the body — so a flag that flipped in between could
    // produce a 503 whose body listed nothing (or listed a check that had
    // since recovered). The predicates are explicitly allowed to be plain
    // atomic loads, so that race is real, not theoretical.
    var all_ok = true;
    var detail_buf: [detail_buf_len]u8 = undefined;
    var detail_len: usize = 0;
    var truncated = false;

    for (h.checks) |c| {
        if (c.checkFn(c.ctx)) continue;
        all_ok = false;
        if (!h.detail) continue;
        const line_len = "not ready: ".len + c.name.len + 1;
        if (detail_len + line_len > detail_buf.len) {
            truncated = true;
            continue;
        }
        var w = detail_buf[detail_len..];
        @memcpy(w[0.."not ready: ".len], "not ready: ");
        @memcpy(w["not ready: ".len..][0..c.name.len], c.name);
        w[line_len - 1] = '\n';
        detail_len += line_len;
    }

    try res.setHeader("Content-Type", "text/plain");
    try res.setHeader("Cache-Control", "no-store");
    if (all_ok) {
        res.setStatus(200);
        try res.writeAll("OK\n");
        return;
    }
    res.setStatus(503);
    if (!h.detail) {
        try res.writeAll("not ready\n");
        return;
    }
    try res.writeAll(detail_buf[0..detail_len]);
    if (truncated) try res.writeAll("not ready: ...\n");
}

// ── tests (offline — through http.Server.serveStream) ───────────────────────

const testing = std.testing;

test "isProbeMethod: GET and HEAD are probe methods, everything else is not (audit F1)" {
    // Doc comment + module docs both say "GET/HEAD", but every wire-level test
    // below only ever issues GET — HEAD had zero coverage, so a regression
    // that dropped HEAD support (e.g. mismatched to .post) would go unnoticed.
    try testing.expect(isProbeMethod(.get));
    try testing.expect(isProbeMethod(.head));
    try testing.expect(!isProbeMethod(.post));
    try testing.expect(!isProbeMethod(.put));
    try testing.expect(!isProbeMethod(.delete));
    try testing.expect(!isProbeMethod(.patch));
    try testing.expect(!isProbeMethod(.options));
}
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
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

fn wire(comptime target: []const u8) []const u8 {
    return "GET " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

fn hApp(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("app");
}

var ready_flag: bool = true;
fn flagCheck(_: ?*anyopaque) bool {
    return ready_flag;
}

test "liveness: always 200, on the configured path only" {
    var h = Health{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    try r.get("/", hApp);

    var buf: [1024]u8 = undefined;
    const live = runWire(&r, wire("/healthz"), &buf);
    try testing.expect(std.mem.startsWith(u8, live, "HTTP/1.1 200"));
    try testing.expectEqualStrings("OK\n", bodyOf(live));
    try testing.expect(std.mem.indexOf(u8, live, "Cache-Control: no-store") != null);

    // A non-probe path flows through to the app handler.
    const app = runWire(&r, wire("/"), &buf);
    try testing.expectEqualStrings("app", bodyOf(app));
}

test "readiness: 200 when all checks pass, 503 listing the failures" {
    var checks = [_]Check{
        .{ .name = "database", .checkFn = flagCheck },
        .{ .name = "always-ok", .checkFn = struct {
            fn f(_: ?*anyopaque) bool {
                return true;
            }
        }.f },
    };
    var h = Health{ .checks = &checks };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    try r.get("/", hApp);

    var buf: [1024]u8 = undefined;

    ready_flag = true;
    const ok = runWire(&r, wire("/readyz"), &buf);
    try testing.expect(std.mem.startsWith(u8, ok, "HTTP/1.1 200"));
    try testing.expectEqualStrings("OK\n", bodyOf(ok));

    ready_flag = false;
    const down = runWire(&r, wire("/readyz"), &buf);
    try testing.expect(std.mem.startsWith(u8, down, "HTTP/1.1 503"));
    try testing.expectEqualStrings("not ready: database\n", bodyOf(down));
    ready_flag = true;
}

test "readiness with no checks defaults to 200" {
    var h = Health{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    try r.get("/", hApp);

    var buf: [1024]u8 = undefined;
    const ok = runWire(&r, wire("/readyz"), &buf);
    try testing.expect(std.mem.startsWith(u8, ok, "HTTP/1.1 200"));
}

test "custom probe paths" {
    var h = Health{ .live_path = "/alive", .ready_path = "/ready" };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    try r.get("/healthz", hApp); // default path now flows through to the app

    var buf: [1024]u8 = undefined;
    try testing.expect(std.mem.startsWith(u8, runWire(&r, wire("/alive"), &buf), "HTTP/1.1 200"));
    try testing.expectEqualStrings("app", bodyOf(runWire(&r, wire("/healthz"), &buf)));
}

/// Counts its calls so a test can prove the probe evaluates each check once.
var eval_count: usize = 0;
fn countingFailingCheck(_: ?*anyopaque) bool {
    eval_count += 1;
    return false;
}

test "readiness: each check is evaluated exactly once per probe" {
    // It used to run twice — once for the status, once for the body — so a
    // predicate that flipped in between could yield a 503 listing nothing.
    var checks = [_]Check{
        .{ .name = "a", .checkFn = countingFailingCheck },
        .{ .name = "b", .checkFn = countingFailingCheck },
    };
    var h = Health{ .checks = &checks };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    try r.get("/", hApp);

    var buf: [1024]u8 = undefined;
    eval_count = 0;
    const down = runWire(&r, wire("/readyz"), &buf);
    try testing.expect(std.mem.startsWith(u8, down, "HTTP/1.1 503"));
    try testing.expectEqualStrings("not ready: a\nnot ready: b\n", bodyOf(down));
    try testing.expectEqual(@as(usize, 2), eval_count);
}

test "readiness: detail=false keeps the status but not the dependency names" {
    // The probe may be reachable from outside the cluster, where "database"
    // and friends are internal topology worth not publishing.
    var checks = [_]Check{.{ .name = "database", .checkFn = flagCheck }};
    var h = Health{ .checks = &checks, .detail = false };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    try r.get("/", hApp);

    var buf: [1024]u8 = undefined;
    ready_flag = false;
    const down = runWire(&r, wire("/readyz"), &buf);
    try testing.expect(std.mem.startsWith(u8, down, "HTTP/1.1 503")); // unchanged
    try testing.expectEqualStrings("not ready\n", bodyOf(down));
    try testing.expect(std.mem.indexOf(u8, down, "database") == null);

    ready_flag = true;
    const ok = runWire(&r, wire("/readyz"), &buf);
    try testing.expect(std.mem.startsWith(u8, ok, "HTTP/1.1 200"));
}
