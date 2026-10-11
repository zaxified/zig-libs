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
//! - **Startup** (opt-in, `startup = .{ .started = &flag }`, path `/startupz`
//!   by default): "the application has finished starting." Answers **503**
//!   until the application sets its flag (`flag.store(true, .release)`), then
//!   **200**. Kubernetes holds liveness/readiness probing back until it passes.
//!
//! Bodies are plain text by default; `json = true` switches all three probes to
//! `{"status":"up"|"down","details":{"<check>":{"status":"up"|"down"}}}`
//! (`application/json; charset=utf-8`; `details` only on readiness, only with
//! `detail`, and only when there are checks), the shape of
//! alexliesenfeld/health.
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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Liveness (`/healthz`) + readiness (`/readyz`) probe middleware — 200/503 from registered dependency checks (k8s probe contract)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
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
/// The startup probe (`Health.startup`). The flag is the application's, not
/// `Health`'s, so the config stays immutable -- a `Health` may live in
/// read-only memory -- and one flag can feed several servers. Set it once,
/// when start-up is done; the probe answers 200 for as long as it is set.
pub const Startup = struct {
    /// Exact match, GET/HEAD.
    path: []const u8 = "/startupz",
    started: *const std.atomic.Value(bool),
};

pub const Health = struct {
    /// Readiness checks — ALL must pass for a 200. Empty ⇒ readiness always
    /// 200 (a liveness-equivalent readiness, the default).
    checks: []const Check = &.{},
    /// Liveness path (exact match, GET/HEAD).
    live_path: []const u8 = "/healthz",
    /// Readiness path (exact match, GET/HEAD).
    ready_path: []const u8 = "/readyz",
    /// The startup probe; `null` (the default) disables it, so its path flows
    /// through to the app.
    startup: ?Startup = null,
    /// Answer with a JSON body instead of plain text (see the module doc).
    /// `detail` still governs whether check names appear.
    json: bool = false,
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

    /// Which probe this request is, if any.
    ///
    /// For a server that routes itself. `middleware` is the answer when there
    /// is a `router` to hang it on; a server without one -- a single-purpose
    /// API daemon, say -- would otherwise have to build a `router.Ctx` it has
    /// no other use for, or reimplement the contract this module exists to
    /// state. `metrics.Registry.respond` is the same shape.
    pub fn probeFor(h: *const Health, method: http.Method, path: []const u8) ?Probe {
        if (!isProbeMethod(method)) return null;
        if (std.mem.eql(u8, path, h.live_path)) return .live;
        if (std.mem.eql(u8, path, h.ready_path)) return .ready;
        if (h.startup) |st| if (std.mem.eql(u8, path, st.path)) return .startup;
        return null;
    }

    /// Answer one probe. Byte for byte what `middleware` writes -- both go
    /// through the same two functions, so the two entry points cannot drift.
    pub fn respond(h: *const Health, probe: Probe, res: *http.Server.ResponseWriter) anyerror!void {
        return switch (probe) {
            .live => respondLive(h, res),
            .ready => respondReady(h, res),
            .startup => respondStartup(h, res),
        };
    }
};

/// Which of the probes a request is.
pub const Probe = enum { live, ready, startup };

fn isProbeMethod(m: http.Method) bool {
    return m == .get or m == .head;
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const h: *const Health = @ptrCast(@alignCast(state.?));
    const req = ctx.req;

    if (h.probeFor(req.method, req.path)) |probe| return h.respond(probe, ctx.res);
    return next.run(ctx);
}

fn respondLive(h: *const Health, res: *http.Server.ResponseWriter) anyerror!void {
    res.setStatus(200);
    try setProbeHeaders(h, res);
    try res.writeAll(if (h.json) "{\"status\":\"up\"}" else "OK\n");
}

fn setProbeHeaders(h: *const Health, res: *http.Server.ResponseWriter) anyerror!void {
    try res.setHeader("Content-Type", if (h.json) "application/json; charset=utf-8" else "text/plain");
    try res.setHeader("Cache-Control", "no-store");
}

fn respondStartup(h: *const Health, res: *http.Server.ResponseWriter) anyerror!void {
    const up = h.startup.?.started.load(.acquire);
    res.setStatus(if (up) 200 else 503);
    try setProbeHeaders(h, res);
    try res.writeAll(if (h.json)
        (if (up) "{\"status\":\"up\"}" else "{\"status\":\"down\"}")
    else
        (if (up) "OK\n" else "not started\n"));
}

/// The JSON `details` object lists at most this many checks (their pass bits
/// are kept on the stack; every check still runs once and still counts for the
/// status). Far past any real service's dependency count.
const json_max_checks = 256;

/// Write `s` as a JSON string literal. Quote, backslash and control bytes are
/// escaped; a name that is not valid UTF-8 has every byte >= 0x80 written as
/// `\u00XX` so the document stays valid JSON.
fn writeJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    const utf8 = std.unicode.utf8ValidateSlice(s);
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11, 12, 14...31, 127 => try w.print("\\u{x:0>4}", .{c}),
            128...255 => if (utf8) try w.writeByte(c) else try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

fn respondReadyJson(h: *const Health, res: *http.Server.ResponseWriter) anyerror!void {
    // Every check runs exactly once (see respondReady); the pass bits of the
    // first `json_max_checks` are kept so the status line can be decided
    // before any body byte leaves the buffer.
    var passed: [json_max_checks / 64]u64 = @splat(0);
    var all_ok = true;
    for (h.checks, 0..) |c, i| {
        const ok = c.checkFn(c.ctx);
        if (!ok) all_ok = false;
        if (ok and i < json_max_checks) passed[i / 64] |= @as(u64, 1) << @intCast(i % 64);
    }
    res.setStatus(if (all_ok) 200 else 503);
    try setProbeHeaders(h, res);
    const w = res.writer();
    try w.writeAll(if (all_ok) "{\"status\":\"up\"" else "{\"status\":\"down\"");
    if (h.detail and h.checks.len != 0) {
        try w.writeAll(",\"details\":{");
        for (h.checks[0..@min(h.checks.len, json_max_checks)], 0..) |c, i| {
            if (i != 0) try w.writeByte(',');
            try writeJsonString(w, c.name);
            const ok = (passed[i / 64] >> @intCast(i % 64)) & 1 != 0;
            try w.writeAll(if (ok) ":{\"status\":\"up\"}" else ":{\"status\":\"down\"}");
        }
        try w.writeByte('}');
    }
    try w.writeByte('}');
}

/// Bytes of "not ready: <name>" lines a 503 body carries. Past this the body
/// is truncated with a marker rather than growing — a probe response is not a
/// place to let an unbounded number of names size a buffer.
const detail_buf_len = 512;

fn respondReady(h: *const Health, res: *http.Server.ResponseWriter) anyerror!void {
    if (h.json) return respondReadyJson(h, res);
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

test "probeFor recognises exactly the two probe paths, and only probe methods" {
    const h: Health = .{ .live_path = "/healthz", .ready_path = "/readyz" };

    try testing.expectEqual(Probe.live, h.probeFor(.get, "/healthz").?);
    try testing.expectEqual(Probe.ready, h.probeFor(.get, "/readyz").?);
    try testing.expectEqual(Probe.live, h.probeFor(.head, "/healthz").?);
    // The startup probe is opt-in: by default its path is the app's.
    try testing.expect(h.probeFor(.get, "/startupz") == null);
    var started: std.atomic.Value(bool) = .init(false);
    const hs: Health = .{ .startup = .{ .started = &started } };
    try testing.expectEqual(Probe.startup, hs.probeFor(.get, "/startupz").?);

    // Anything else belongs to whatever the server serves.
    try testing.expect(h.probeFor(.get, "/healthz/") == null);
    try testing.expect(h.probeFor(.get, "/health") == null);
    try testing.expect(h.probeFor(.get, "/") == null);
    // A probe path under a method that is not a probe is not a probe. Without
    // this, a POST to /readyz would be answered by the health module in a
    // server that routes itself, which is not what the middleware does.
    try testing.expect(h.probeFor(.post, "/readyz") == null);
    try testing.expect(h.probeFor(.delete, "/healthz") == null);
}

var direct_health: ?*const Health = null;
var direct_probe: Probe = .live;

fn directHandler(_: *http.Server.Request, res: *http.Server.ResponseWriter) anyerror!void {
    return direct_health.?.respond(direct_probe, res);
}

fn runWireDirect(bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = directHandler,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

test "respond writes what the middleware writes" {
    // The claim that matters about the direct API: it is not a second
    // implementation. Both entry points go through the same two functions,
    // and this pins that they agree -- a copy that drifted would make the
    // probe contract depend on how the server happened to be wired.
    var checks = [_]Check{.{ .name = "database", .checkFn = flagCheck }};
    var h = Health{ .checks = &checks };
    ready_flag = false;
    defer ready_flag = true;

    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    try r.get("/", hApp);

    var a_buf: [1024]u8 = undefined;
    var b_buf: [1024]u8 = undefined;
    const through = runWire(&r, wire("/readyz"), &a_buf);

    direct_health = &h;
    direct_probe = .ready;
    const direct = runWireDirect(wire("/readyz"), &b_buf);

    try testing.expect(std.mem.startsWith(u8, through, "HTTP/1.1 503"));
    try testing.expectEqualStrings(bodyOf(through), bodyOf(direct));
    try testing.expectEqualStrings("not ready: database\n", bodyOf(direct));

    // And the liveness half, which has no state to get wrong and would
    // therefore be the easy one to leave unchecked.
    direct_probe = .live;
    const live_direct = runWireDirect(wire("/healthz"), &b_buf);
    const live_through = runWire(&r, wire("/healthz"), &a_buf);
    try testing.expectEqualStrings(bodyOf(live_through), bodyOf(live_direct));
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

fn alwaysDown(_: ?*anyopaque) bool {
    return false;
}

/// `runWire` with room for a body past 512 bytes, so a full detail body
/// arrives in one piece.
fn runWireWide(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [8192]u8 = undefined;
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

test "readiness detail: lines that exactly fill the budget are all kept; one more adds the marker" {
    // `detail_buf_len` (512) bounds the "not ready: <name>" lines; past it
    // the body is "truncated with a marker rather than growing". A line is
    // 11 + name + 1 bytes: names of 200 and 288 give 212 + 300 = 512, the
    // exact budget -- both listed, no marker. A third failing check does not
    // fit and is replaced by `not ready: ...`. And a 503 is `no-store` like
    // the 200 (a cached "not ready" would outlive the outage). Mutation
    // 2026-10-04: an off-by-one budget, a dropped marker and a dropped
    // Cache-Control on /readyz all survived.
    const n200 = "a" ** 200;
    const n288 = "b" ** 288;
    var exact = [_]Check{
        .{ .name = n200, .checkFn = alwaysDown },
        .{ .name = n288, .checkFn = alwaysDown },
    };
    var over = [_]Check{
        .{ .name = n200, .checkFn = alwaysDown },
        .{ .name = n288, .checkFn = alwaysDown },
        .{ .name = "c", .checkFn = alwaysDown },
    };
    var buf: [4096]u8 = undefined;
    {
        var h = Health{ .checks = &exact };
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(h.middleware());
        const got = runWireWide(&r, wire("/readyz"), &buf);
        try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 503"));
        try testing.expect(std.mem.indexOf(u8, got, "Cache-Control: no-store") != null);
        try testing.expectEqualStrings("not ready: " ++ n200 ++ "\nnot ready: " ++ n288 ++ "\n", bodyOf(got));
    }
    {
        var h = Health{ .checks = &over };
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(h.middleware());
        const got = runWireWide(&r, wire("/readyz"), &buf);
        try testing.expectEqualStrings("not ready: " ++ n200 ++ "\nnot ready: " ++ n288 ++ "\nnot ready: ...\n", bodyOf(got));
    }
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

test "startup probe: 503 until the app's flag is set, then 200; null disables it" {
    var started: std.atomic.Value(bool) = .init(false);
    // `const`: the config is never written, so it may live in read-only memory.
    const h = Health{ .startup = .{ .started = &started } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    try r.get("/startupz", hApp);

    var buf: [1024]u8 = undefined;
    const before = runWire(&r, wire("/startupz"), &buf);
    try testing.expect(std.mem.startsWith(u8, before, "HTTP/1.1 503"));
    try testing.expectEqualStrings("not started\n", bodyOf(before));
    try testing.expect(std.mem.indexOf(u8, before, "Cache-Control: no-store") != null);

    // Readiness and liveness are independent of the latch.
    try testing.expect(std.mem.startsWith(u8, runWire(&r, wire("/readyz"), &buf), "HTTP/1.1 200"));

    started.store(true, .release);
    for (0..3) |_| {
        const after = runWire(&r, wire("/startupz"), &buf);
        try testing.expect(std.mem.startsWith(u8, after, "HTTP/1.1 200"));
        try testing.expectEqualStrings("OK\n", bodyOf(after));
    }

    // Disabled (the default): the path belongs to the app.
    const off = Health{};
    var r2 = router.Router.init(testing.allocator);
    defer r2.deinit();
    try r2.use(off.middleware());
    try r2.get("/startupz", hApp);
    try testing.expectEqualStrings("app", bodyOf(runWire(&r2, wire("/startupz"), &buf)));
    try testing.expect(off.probeFor(.get, "/startupz") == null);

    // Custom path; POST is not a probe.
    const c = Health{ .startup = .{ .path = "/booted", .started = &started } };
    try testing.expectEqual(Probe.startup, c.probeFor(.get, "/booted").?);
    try testing.expect(c.probeFor(.post, "/booted") == null);
    try testing.expect(c.probeFor(.get, "/startupz") == null);
}

test "json body: byte goldens for up, down, detail off, liveness and startup" {
    var checks = [_]Check{
        .{ .name = "database", .checkFn = flagCheck },
        .{ .name = "cache", .checkFn = struct {
            fn f(_: ?*anyopaque) bool {
                return true;
            }
        }.f },
    };
    var started: std.atomic.Value(bool) = .init(false);
    var h = Health{ .checks = &checks, .json = true, .startup = .{ .started = &started } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    var buf: [1024]u8 = undefined;

    ready_flag = true;
    const up = runWire(&r, wire("/readyz"), &buf);
    try testing.expect(std.mem.startsWith(u8, up, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, up, "Content-Type: application/json; charset=utf-8\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, up, "Cache-Control: no-store") != null);
    try testing.expectEqualStrings("{\"status\":\"up\",\"details\":{\"database\":{\"status\":\"up\"},\"cache\":{\"status\":\"up\"}}}", bodyOf(up));

    ready_flag = false;
    defer ready_flag = true;
    const down = runWire(&r, wire("/readyz"), &buf);
    try testing.expect(std.mem.startsWith(u8, down, "HTTP/1.1 503"));
    try testing.expectEqualStrings("{\"status\":\"down\",\"details\":{\"database\":{\"status\":\"down\"},\"cache\":{\"status\":\"up\"}}}", bodyOf(down));

    h.detail = false;
    const quiet = runWire(&r, wire("/readyz"), &buf);
    try testing.expect(std.mem.startsWith(u8, quiet, "HTTP/1.1 503"));
    try testing.expectEqualStrings("{\"status\":\"down\"}", bodyOf(quiet));
    try testing.expect(std.mem.indexOf(u8, quiet, "database") == null);
    h.detail = true;

    const live = runWire(&r, wire("/healthz"), &buf);
    try testing.expect(std.mem.indexOf(u8, live, "application/json; charset=utf-8") != null);
    try testing.expectEqualStrings("{\"status\":\"up\"}", bodyOf(live));

    const s503 = runWire(&r, wire("/startupz"), &buf);
    try testing.expect(std.mem.startsWith(u8, s503, "HTTP/1.1 503"));
    try testing.expectEqualStrings("{\"status\":\"down\"}", bodyOf(s503));
    started.store(true, .release);
    try testing.expectEqualStrings("{\"status\":\"up\"}", bodyOf(runWire(&r, wire("/startupz"), &buf)));

    // No checks: no `details` key at all (as the Go library's omitempty).
    const empty = Health{ .json = true };
    var r2 = router.Router.init(testing.allocator);
    defer r2.deinit();
    try r2.use(empty.middleware());
    try testing.expectEqualStrings("{\"status\":\"up\"}", bodyOf(runWire(&r2, wire("/readyz"), &buf)));
}

test "json body: check names are escaped, invalid UTF-8 stays valid JSON, router-free respond agrees" {
    var checks = [_]Check{
        .{ .name = "a\"b\\c\n\x01\x7f", .checkFn = alwaysDown },
        .{ .name = "caf\xc3\xa9", .checkFn = alwaysDown }, // valid UTF-8 kept raw
        .{ .name = "bad\xff", .checkFn = alwaysDown }, // invalid: byte escaped
    };
    var h = Health{ .checks = &checks, .json = true };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(h.middleware());
    var buf: [1024]u8 = undefined;
    const want = "{\"status\":\"down\",\"details\":{\"a\\\"b\\\\c\\n\\u0001\\u007f\":{\"status\":\"down\"},\"caf\xc3\xa9\":{\"status\":\"down\"},\"bad\\u00ff\":{\"status\":\"down\"}}}";
    const through = runWire(&r, wire("/readyz"), &buf);
    try testing.expectEqualStrings(want, bodyOf(through));

    var b2: [1024]u8 = undefined;
    direct_health = &h;
    direct_probe = .ready;
    try testing.expectEqualStrings(want, bodyOf(runWireDirect(wire("/readyz"), &b2)));
}

// ── model-fuzz: seeded random configs/requests vs. a naive reference model ──
//
// The model restates the documented contract (module doc + SPEC "Design &
// invariants"): liveness is always 200; readiness is 200 iff every check
// passes, else 503 with one "not ready: <name>" line per failing check in
// registration order, capped at a 512-byte budget with a "not ready: ..."
// marker, or just "not ready" when `detail` is off; each check runs exactly
// once per readiness probe and never otherwise; only GET/HEAD on the two exact
// paths are probes, everything else passes through to the app.

const FuzzCheck = struct {
    ok: bool = true,
    calls: u32 = 0,
};

fn fuzzCheckFn(ctx: ?*anyopaque) bool {
    const st: *FuzzCheck = @ptrCast(@alignCast(ctx.?));
    st.calls += 1;
    return st.ok;
}

test "model-fuzz: probes, pass-through, detail budget and call counts vs. a naive model" {
    const seed: u64 = 0x6865616c74683031;
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    const path_pool = [_][]const u8{ "/healthz", "/readyz", "/alive", "/ready", "/healthz/", "/readyz2", "/", "/x", "/startupz" };
    const methods = [_][]const u8{ "GET", "HEAD", "POST" };
    // Includes bytes the JSON writer must escape; the text body is verbatim.
    const name_chars = "abcdefghijklmnopqrstuvwxyz0123456789-_\"\\\n\x01";

    var reach_live: usize = 0;
    var reach_ready_ok: usize = 0;
    var reach_ready_503_detail: usize = 0;
    var reach_ready_503_nodetail: usize = 0;
    var reach_marker: usize = 0;
    var reach_skip_then_fit: usize = 0;
    var reach_passthrough: usize = 0;
    var reach_non_probe_method: usize = 0;
    var reach_head: usize = 0;
    var reach_custom_paths: usize = 0;
    var reach_exact_fill: usize = 0;
    var reach_json_ready: usize = 0;
    var reach_json_escape: usize = 0;
    var reach_startup_up: usize = 0;
    var reach_startup_down: usize = 0;
    var reach_startup_off: usize = 0;

    var step: usize = 0;
    while (step < 1200) : (step += 1) {
        errdefer std.debug.print("health model-fuzz mismatch: seed=0x{x} step={d}\n", .{ seed, step });

        // Config.
        const custom = rnd.boolean();
        const live_path: []const u8 = if (custom) "/alive" else "/healthz";
        const ready_path: []const u8 = if (custom) "/ready" else "/readyz";
        const detail = rnd.uintLessThan(u8, 3) != 0;
        const json = rnd.boolean();
        const startup_on = rnd.uintLessThan(u8, 4) != 0;
        const started = rnd.boolean();
        var started_flag: std.atomic.Value(bool) = .init(false);

        var states: [8]FuzzCheck = @splat(.{});
        var checks: [8]Check = undefined;
        var name_store: [8][320]u8 = undefined;
        // A "heavy" step has long early names and short late ones, so the
        // 512-byte budget overflows and a later short name may still fit.
        const heavy = rnd.uintLessThan(u8, 3) == 0;
        const n_checks = if (heavy) 5 + rnd.uintLessThan(usize, 4) else rnd.uintLessThan(usize, 9);
        const fail_bias = if (heavy) 3 else rnd.uintLessThan(u8, 4);
        for (0..n_checks) |i| {
            // Name lengths: short mostly, sometimes budget-sized.
            const nlen: usize = if (heavy)
                (if (i < 3) 120 + rnd.uintLessThan(usize, 180) else 1 + rnd.uintLessThan(usize, 20))
            else switch (rnd.uintLessThan(u8, 6)) {
                0 => 150 + rnd.uintLessThan(usize, 170),
                1 => 1,
                else => 1 + rnd.uintLessThan(usize, 20),
            };
            for (name_store[i][0..nlen]) |*c| c.* = name_chars[rnd.uintLessThan(usize, name_chars.len)];
            states[i].ok = rnd.uintLessThan(u8, 4) >= fail_bias; // fail_bias 3 => nearly all fail
            checks[i] = .{ .name = name_store[i][0..nlen], .checkFn = fuzzCheckFn, .ctx = &states[i] };
        }
        // Sometimes two failing names that sum to the budget -1/0/+1 bytes, to
        // probe the exact edge (512 = 2 * 12 + len0 + len1).
        if (heavy and rnd.uintLessThan(u8, 4) != 0) {
            const l0 = 200 + rnd.uintLessThan(usize, 50);
            const l1 = 512 - 24 - l0 + rnd.uintLessThan(usize, 3) - 1;
            for (0..2) |i| {
                const l = if (i == 0) l0 else l1;
                for (name_store[i][0..l]) |*c| c.* = name_chars[rnd.uintLessThan(usize, name_chars.len)];
                checks[i].name = name_store[i][0..l];
                states[i].ok = false;
            }
        }
        var h = Health{ .checks = checks[0..n_checks], .live_path = live_path, .ready_path = ready_path, .detail = detail, .json = json, .startup = if (startup_on) .{ .started = &started_flag } else null };
        started_flag.store(started, .release);

        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(h.middleware());
        for (path_pool) |p| {
            try r.get(p, hApp);
            try r.post(p, hApp);
        }

        // Request.
        const path = path_pool[rnd.uintLessThan(usize, path_pool.len)];
        const method = methods[rnd.uintLessThan(usize, methods.len)];
        var req_buf: [256]u8 = undefined;
        const req = std.fmt.bufPrint(&req_buf, "{s} {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{ method, path }) catch unreachable;
        var out: [16384]u8 = undefined;
        const got = runWireWide(&r, req, &out);
        const body = bodyOf(got);

        // Model.
        const is_get_head = std.mem.eql(u8, method, "GET") or std.mem.eql(u8, method, "HEAD");
        const is_head = std.mem.eql(u8, method, "HEAD");
        const on_live = std.mem.eql(u8, path, live_path);
        const on_ready = std.mem.eql(u8, path, ready_path);
        const on_startup = startup_on and std.mem.eql(u8, path, "/startupz");

        if (is_get_head and on_live) {
            reach_live += 1;
            if (is_head) reach_head += 1;
            if (custom) reach_custom_paths += 1;
            try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
            try testing.expect(std.mem.indexOf(u8, got, "Cache-Control: no-store") != null);
            if (!is_head) try testing.expectEqualStrings(if (json) "{\"status\":\"up\"}" else "OK\n", body);
            if (json) try testing.expect(std.mem.indexOf(u8, got, "Content-Type: application/json; charset=utf-8") != null);
            for (states[0..n_checks]) |s| try testing.expectEqual(@as(u32, 0), s.calls);
        } else if (is_get_head and on_startup) {
            if (started) reach_startup_up += 1 else reach_startup_down += 1;
            try testing.expect(std.mem.startsWith(u8, got, if (started) "HTTP/1.1 200" else "HTTP/1.1 503"));
            try testing.expect(std.mem.indexOf(u8, got, "Cache-Control: no-store") != null);
            if (!is_head) {
                const want: []const u8 = if (json)
                    (if (started) "{\"status\":\"up\"}" else "{\"status\":\"down\"}")
                else
                    (if (started) "OK\n" else "not started\n");
                try testing.expectEqualStrings(want, body);
            }
            for (states[0..n_checks]) |s| try testing.expectEqual(@as(u32, 0), s.calls);
        } else if (is_get_head and on_ready) {
            if (custom) reach_custom_paths += 1;
            if (is_head) reach_head += 1;
            var want_body: [600]u8 = undefined;
            var wl: usize = 0;
            var any_fail = false;
            var used: usize = 0;
            var trunc = false;
            var skipped_earlier = false;
            for (states[0..n_checks], 0..) |s, i| {
                if (s.ok) continue;
                any_fail = true;
                const name = checks[i].name;
                const line = 11 + name.len + 1;
                if (used + line > 512) {
                    trunc = true;
                    skipped_earlier = true;
                } else {
                    if (skipped_earlier) reach_skip_then_fit += 1;
                    used += line;
                    wl += (std.fmt.bufPrint(want_body[wl..], "not ready: {s}\n", .{name}) catch unreachable).len;
                }
            }
            if (json) {
                reach_json_ready += 1;
                try testing.expect(std.mem.startsWith(u8, got, if (any_fail) "HTTP/1.1 503" else "HTTP/1.1 200"));
                try testing.expect(std.mem.indexOf(u8, got, "Content-Type: application/json; charset=utf-8") != null);
                if (!is_head) {
                    // Independent oracle: build the document with a plain
                    // byte switch (only the bytes the name alphabet holds).
                    var jb: [8192]u8 = undefined;
                    var jw: Writer = .fixed(&jb);
                    jw.writeAll(if (any_fail) "{\"status\":\"down\"" else "{\"status\":\"up\"") catch unreachable;
                    if (detail and n_checks != 0) {
                        jw.writeAll(",\"details\":{") catch unreachable;
                        for (states[0..n_checks], 0..) |st, i| {
                            if (i != 0) jw.writeByte(',') catch unreachable;
                            jw.writeByte('"') catch unreachable;
                            for (checks[i].name) |ch| {
                                switch (ch) {
                                    '"' => jw.writeAll("\\\"") catch unreachable,
                                    '\\' => jw.writeAll("\\\\") catch unreachable,
                                    '\n' => jw.writeAll("\\n") catch unreachable,
                                    1 => {
                                        reach_json_escape += 1;
                                        jw.writeAll("\\u0001") catch unreachable;
                                    },
                                    else => jw.writeByte(ch) catch unreachable,
                                }
                            }
                            jw.writeAll(if (st.ok) "\":{\"status\":\"up\"}" else "\":{\"status\":\"down\"}") catch unreachable;
                        }
                        jw.writeByte('}') catch unreachable;
                    }
                    jw.writeByte('}') catch unreachable;
                    try testing.expectEqualStrings(jw.buffered(), body);
                }
            } else if (!any_fail) {
                reach_ready_ok += 1;
                try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
                if (!is_head) try testing.expectEqualStrings("OK\n", body);
            } else {
                try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 503"));
                if (detail) {
                    reach_ready_503_detail += 1;
                    if (used == 512) reach_exact_fill += 1;
                    if (trunc) {
                        reach_marker += 1;
                        wl += (std.fmt.bufPrint(want_body[wl..], "not ready: ...\n", .{}) catch unreachable).len;
                    }
                    if (!is_head) try testing.expectEqualStrings(want_body[0..wl], body);
                } else {
                    reach_ready_503_nodetail += 1;
                    if (!is_head) try testing.expectEqualStrings("not ready\n", body);
                }
            }
            try testing.expect(std.mem.indexOf(u8, got, "Cache-Control: no-store") != null);
            for (states[0..n_checks]) |s| try testing.expectEqual(@as(u32, 1), s.calls);
        } else {
            reach_passthrough += 1;
            if (is_get_head and !startup_on and std.mem.eql(u8, path, "/startupz")) reach_startup_off += 1;
            if (!is_get_head and (on_live or on_ready)) reach_non_probe_method += 1;
            if (!is_head) {
                try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
                try testing.expectEqualStrings("app", body);
            }
            try testing.expect(std.mem.indexOf(u8, got, "Cache-Control: no-store") == null);
            for (states[0..n_checks]) |s| try testing.expectEqual(@as(u32, 0), s.calls);
        }

        // The router-free entry points agree with the wire for every request.
        const probe = h.probeFor(if (is_head) .head else if (is_get_head) .get else .post, path);
        const want_probe: ?Probe = if (is_get_head and on_live) .live else if (is_get_head and on_ready) .ready else if (is_get_head and on_startup) .startup else null;
        try testing.expectEqual(want_probe, probe);
    }
    try testing.expect(reach_live > 0 and reach_ready_ok > 0 and reach_ready_503_detail > 0);
    try testing.expect(reach_ready_503_nodetail > 0 and reach_marker > 0 and reach_skip_then_fit > 0);
    try testing.expect(reach_passthrough > 0 and reach_non_probe_method > 0 and reach_head > 0);
    try testing.expect(reach_custom_paths > 0 and reach_exact_fill > 0);
    try testing.expect(reach_json_ready > 0 and reach_json_escape > 0);
    try testing.expect(reach_startup_up > 0 and reach_startup_down > 0 and reach_startup_off > 0);
}
