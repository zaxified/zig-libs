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
        return null;
    }

    /// Answer one probe. Byte for byte what `middleware` writes -- both go
    /// through the same two functions, so the two entry points cannot drift.
    pub fn respond(h: *const Health, probe: Probe, res: *http.Server.ResponseWriter) anyerror!void {
        return switch (probe) {
            .live => respondLive(res),
            .ready => respondReady(h, res),
        };
    }
};

/// Which of the two probes a request is.
pub const Probe = enum { live, ready };

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

test "probeFor recognises exactly the two probe paths, and only probe methods" {
    const h: Health = .{ .live_path = "/healthz", .ready_path = "/readyz" };

    try testing.expectEqual(Probe.live, h.probeFor(.get, "/healthz").?);
    try testing.expectEqual(Probe.ready, h.probeFor(.get, "/readyz").?);
    try testing.expectEqual(Probe.live, h.probeFor(.head, "/healthz").?);

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
    var response_body_buf: [2048]u8 = undefined;
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

    const path_pool = [_][]const u8{ "/healthz", "/readyz", "/alive", "/ready", "/healthz/", "/readyz2", "/", "/x" };
    const methods = [_][]const u8{ "GET", "HEAD", "POST" };
    const name_chars = "abcdefghijklmnopqrstuvwxyz0123456789-_";

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

    var step: usize = 0;
    while (step < 1200) : (step += 1) {
        errdefer std.debug.print("health model-fuzz mismatch: seed=0x{x} step={d}\n", .{ seed, step });

        // Config.
        const custom = rnd.boolean();
        const live_path: []const u8 = if (custom) "/alive" else "/healthz";
        const ready_path: []const u8 = if (custom) "/ready" else "/readyz";
        const detail = rnd.uintLessThan(u8, 3) != 0;

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
        var h = Health{ .checks = checks[0..n_checks], .live_path = live_path, .ready_path = ready_path, .detail = detail };

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
        var out: [4096]u8 = undefined;
        const got = runWireWide(&r, req, &out);
        const body = bodyOf(got);

        // Model.
        const is_get_head = std.mem.eql(u8, method, "GET") or std.mem.eql(u8, method, "HEAD");
        const is_head = std.mem.eql(u8, method, "HEAD");
        const on_live = std.mem.eql(u8, path, live_path);
        const on_ready = std.mem.eql(u8, path, ready_path);

        if (is_get_head and on_live) {
            reach_live += 1;
            if (is_head) reach_head += 1;
            if (custom) reach_custom_paths += 1;
            try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200"));
            try testing.expect(std.mem.indexOf(u8, got, "Cache-Control: no-store") != null);
            if (!is_head) try testing.expectEqualStrings("OK\n", body);
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
            if (!any_fail) {
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
        const want_probe: ?Probe = if (is_get_head and on_live) .live else if (is_get_head and on_ready) .ready else null;
        try testing.expectEqual(want_probe, probe);
    }
    try testing.expect(reach_live > 0 and reach_ready_ok > 0 and reach_ready_503_detail > 0);
    try testing.expect(reach_ready_503_nodetail > 0 and reach_marker > 0 and reach_skip_then_fit > 0);
    try testing.expect(reach_passthrough > 0 and reach_non_probe_method > 0 and reach_head > 0);
    try testing.expect(reach_custom_paths > 0 and reach_exact_fill > 0);
}
