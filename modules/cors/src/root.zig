// SPDX-License-Identifier: MIT

//! cors — Cross-Origin Resource Sharing (preflight + response headers) as a
//! global `router` middleware.
//!
//! Browsers gate cross-origin JavaScript on CORS response headers: a
//! "preflight" `OPTIONS` request asks permission before non-simple requests,
//! and every actual response needs `Access-Control-Allow-Origin` for the
//! script to read it. `Cors.init` precomputes the header values once;
//! `middleware()` plugs into the router. Register it as a **global**
//! middleware (`router.use`), first or near-first: the global chain also
//! wraps the router's 404/405 fallbacks, so a preflight to a GET-only route
//! is intercepted here *before* it would 405 (the router does not
//! synthesize `OPTIONS` routes).
//!
//! Behavior (modeled after rs/cors, the Go reference implementation):
//!
//! - **Preflight** = `OPTIONS` + an `Access-Control-Request-Method` header.
//!   Always intercepted and answered **204, no body** — `next` is never
//!   called, no handler runs, regardless of whether the path/method has a
//!   route. The CORS headers (`Access-Control-Allow-Origin/-Methods/
//!   -Headers/-Max-Age`, `Allow-Credentials`) are added only when the
//!   request passes all three gates: Origin allowed, requested method
//!   allowed, requested headers allowed. A failing preflight is still a 204
//!   — just without the headers, which is how the browser learns "no"
//!   (rs/cors semantics). Every intercepted preflight carries
//!   `Vary: Origin, Access-Control-Request-Method,
//!   Access-Control-Request-Headers` so caches never reuse it across
//!   origins.
//! - **Actual requests**: when the `Origin` header is present, allowed, and
//!   the request method is in `allowed_methods` (rs/cors gate; `OPTIONS`
//!   always passes it), the middleware sets `Access-Control-Allow-Origin`
//!   (the literal `*` for `.any`, else the specific origin echoed back —
//!   then also `Vary: Origin`), `Access-Control-Allow-Credentials` when
//!   enabled and `Access-Control-Expose-Headers` when configured — then
//!   calls `next`. Origin absent (a same-origin/non-browser request) or not
//!   allowed → nothing is set, the chain just runs: CORS never blocks
//!   server-side handling, it only withholds the headers that would let a
//!   cross-origin script read the response.
//!
//! Secure defaults: `allowed_origins = .none` — the middleware emits
//! nothing until origins are explicitly configured (deviation from
//! rs/cors's permissive `*` default, deliberate). Combining the `*` origin
//! (`.any`) with `allow_credentials` is **rejected at `init`**
//! (`error.CredentialsWithWildcardOrigin`): the Fetch spec forbids
//! `Access-Control-Allow-Origin: *` on credentialed responses, and the
//! reflect-any-origin-with-credentials workaround grants every website
//! credentialed access — if you truly need it, write a `.predicate` that
//! opts in explicitly.
//!
//! Origin matching is an exact byte compare against the configured list (or
//! your predicate): configure the canonical serialization browsers send —
//! lowercase scheme + host, no trailing slash, port only when non-default
//! (e.g. "https://app.example", "http://localhost:5173").
//!
//! Hot path: no allocation, no locks, no clock — the `Allow-Methods`/
//! `Allow-Headers`/`Expose-Headers`/`Max-Age` values are joined once at
//! `init` (the only allocation; freed by `deinit`), and header reflection
//! (origin echo, `.reflect` mode) borrows the request's own slices, which
//! outlive the response head. An initialized `Cors` is immutable —
//! reentrant across all of `http.Server`'s connection threads. It must
//! outlive the router serving requests, at a stable address (the
//! middleware's `state` points at it).

const std = @import("std");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .platform = .any,
    .role = .util,
    // An initialized Cors is immutable; the middleware only reads it and
    // writes per-request response state owned by the connection task.
    .concurrency = .reentrant,
    .model_after = "rs/cors (Go) + expressjs/cors",
    .deps = .{ "router", "http" },
};

const Allocator = std.mem.Allocator;

// ── configuration ───────────────────────────────────────────────────────────

/// Caller-supplied origin check for anything a static list cannot express
/// (subdomain wildcards, port ranges, dynamic tenant lists). Runs on the
/// hot path from every connection thread — must be fast and thread-safe.
pub const OriginPredicate = struct {
    ctx: ?*anyopaque = null,
    /// `origin` is the raw `Origin` header value. Return true to allow (the
    /// specific origin is echoed back, never `*`).
    allow: *const fn (ctx: ?*anyopaque, origin: []const u8) bool,
};

/// Which `Origin` values are allowed.
pub const Origins = union(enum) {
    /// Nobody (the default): no CORS headers are ever emitted — explicit
    /// opt-in posture.
    none,
    /// Every origin: responses carry the literal `Access-Control-Allow-
    /// Origin: *`. Incompatible with `allow_credentials` (rejected at init).
    any,
    /// Exact allow-list, matched by byte compare (use the canonical
    /// lowercase serialization, e.g. "https://app.example").
    list: []const []const u8,
    /// Custom check; an allowed origin is echoed back specifically.
    predicate: OriginPredicate,
};

/// Which request headers a preflight may approve.
pub const AllowedHeaders = union(enum) {
    /// Echo the preflight's `Access-Control-Request-Headers` verbatim (the
    /// default; expressjs/cors behavior — rs/cors's `*` mode). Header
    /// *names* are not sensitive and the origin gate stays the security
    /// boundary, so reflecting maximizes compatibility (no "Authorization
    /// not allowed" surprises).
    reflect,
    /// Fixed allow-list: a preflight requesting anything outside it fails
    /// (no CORS headers on the 204); successful preflights advertise the
    /// joined list. Matching is case-insensitive. Include every header the
    /// client will send beyond the CORS-safelisted ones (`Content-Type`,
    /// `Authorization`, `X-Requested-With`, ...).
    list: []const []const u8,
};

/// All strings are borrowed and must outlive the `Cors`. Values go onto the
/// wire verbatim — they must not contain CR/LF/NUL (Debug-asserted at init).
pub const Options = struct {
    /// Default `.none`: explicit opt-in (deviation from rs/cors's `*`).
    allowed_origins: Origins = .none,
    /// Methods advertised by preflights (`Access-Control-Allow-Methods`)
    /// and required of actual cross-origin requests. Default = the
    /// CORS-safelisted set (rs/cors default). `OPTIONS` is always
    /// implicitly allowed.
    allowed_methods: []const http.Method = &.{ .get, .head, .post },
    /// Default `.reflect` — see `AllowedHeaders`.
    allowed_headers: AllowedHeaders = .reflect,
    /// Response headers cross-origin JS may read beyond the CORS-safelisted
    /// set (`Access-Control-Expose-Headers` on actual responses); empty =
    /// omit the header.
    exposed_headers: []const []const u8 = &.{},
    /// Emit `Access-Control-Allow-Credentials: true` (cookies/TLS client
    /// certs/Authorization travel cross-origin). Requires specific origins:
    /// combined with `.any` it is spec-forbidden and init fails with
    /// `error.CredentialsWithWildcardOrigin`.
    allow_credentials: bool = false,
    /// `Access-Control-Max-Age` — how long the browser may cache a
    /// preflight, in seconds. null (default) = omit the header (browsers
    /// then use their own default, typically 5 s); 0 = disable caching.
    max_age_s: ?u32 = null,
};

pub const InitError = error{
    OutOfMemory,
    /// `allowed_origins = .any` + `allow_credentials = true`: the Fetch
    /// spec forbids `Access-Control-Allow-Origin: *` with credentials.
    /// List the origins (or use a predicate) instead.
    CredentialsWithWildcardOrigin,
};

// Digits of maxInt(u32) — the precomputed Access-Control-Max-Age value.
const max_age_digits = std.fmt.count("{d}", .{std.math.maxInt(u32)});

/// Preflight responses vary by all three request inputs that shape them.
const preflight_vary = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers";

// ── the middleware ──────────────────────────────────────────────────────────

/// Immutable, precomputed CORS policy + the `router.Middleware` over it.
/// Init once (any thread), then share freely; see the module doc.
pub const Cors = struct {
    gpa: Allocator,
    options: Options,
    /// `allowed_methods` joined as "GET, HEAD, POST" (owned).
    allow_methods_value: []const u8,
    /// `.list` allowed headers joined (owned); "" in `.reflect` mode.
    allow_headers_value: []const u8,
    /// `exposed_headers` joined (owned); "" when none.
    expose_headers_value: []const u8,
    /// Preformatted `max_age_s` digits (embedded — `Cors` must not move
    /// while serving).
    max_age_buf: [max_age_digits]u8 = undefined,
    max_age_len: usize = 0,

    /// Validate the configuration and precompute the joined header values
    /// (the only allocations this module ever makes). Configured strings
    /// are borrowed — they must outlive the returned `Cors`.
    pub fn init(gpa: Allocator, options: Options) InitError!Cors {
        if (options.allowed_origins == .any and options.allow_credentials)
            return error.CredentialsWithWildcardOrigin;
        if (std.debug.runtime_safety) {
            switch (options.allowed_origins) {
                .list => |l| for (l) |o| assertValueClean(o),
                else => {},
            }
            switch (options.allowed_headers) {
                .list => |l| for (l) |h| assertValueClean(h),
                .reflect => {},
            }
            for (options.exposed_headers) |h| assertValueClean(h);
        }

        const methods = try joinMethods(gpa, options.allowed_methods);
        errdefer gpa.free(methods);
        const allow_headers: []const u8 = switch (options.allowed_headers) {
            .reflect => "",
            .list => |l| try std.mem.join(gpa, ", ", l),
        };
        errdefer gpa.free(allow_headers);
        const expose_headers: []const u8 = if (options.exposed_headers.len == 0)
            ""
        else
            try std.mem.join(gpa, ", ", options.exposed_headers);

        var c: Cors = .{
            .gpa = gpa,
            .options = options,
            .allow_methods_value = methods,
            .allow_headers_value = allow_headers,
            .expose_headers_value = expose_headers,
        };
        if (options.max_age_s) |s| {
            // The buffer is sized for the largest u32.
            c.max_age_len = (std.fmt.bufPrint(&c.max_age_buf, "{d}", .{s}) catch unreachable).len;
        }
        return c;
    }

    pub fn deinit(c: *Cors) void {
        c.gpa.free(c.allow_methods_value);
        c.gpa.free(c.allow_headers_value);
        c.gpa.free(c.expose_headers_value);
        c.* = undefined;
    }

    /// The `router.Middleware` (`state` = this immutable Cors — per
    /// instance, no globals; never mutated by `run`). Register it
    /// **globally** (`router.use`, before routes) so preflights are
    /// intercepted even where the route would 404/405.
    pub fn middleware(c: *const Cors) router.Middleware {
        // Middleware.state is a mutable pointer by type only — run() never
        // writes through it.
        return .{ .state = @constCast(c), .run = middlewareRun };
    }

    // ── the two request shapes ──────────────────────────────────────────

    /// Preflight: answer 204 (no body) and stop — the router never sees it.
    /// CORS headers only when origin + requested method + requested headers
    /// all pass; `Vary` always (rs/cors semantics).
    fn handlePreflight(c: *const Cors, ctx: *router.Ctx) anyerror!void {
        const req = ctx.req;
        const res = ctx.res;
        res.setStatus(204);
        try res.setHeader("Vary", preflight_vary);
        emit: {
            const origin = req.header("Origin") orelse break :emit;
            const acao = c.allowOriginValue(origin) orelse break :emit;
            // Present by the preflight definition in middlewareRun.
            const req_method = req.header("Access-Control-Request-Method").?;
            if (!c.methodTokenAllowed(req_method)) break :emit;
            const acrh = req.header("Access-Control-Request-Headers");
            if (c.options.allowed_headers == .list) {
                if (acrh) |h| if (!c.requestedHeadersAllowed(h)) break :emit;
            }

            try res.setHeader("Access-Control-Allow-Origin", acao);
            try res.setHeader("Access-Control-Allow-Methods", c.allow_methods_value);
            switch (c.options.allowed_headers) {
                // Echo the request's own slice — it outlives the response
                // head (written before the handler scope ends).
                .reflect => if (acrh) |h| {
                    if (h.len != 0) try res.setHeader("Access-Control-Allow-Headers", h);
                },
                .list => if (c.allow_headers_value.len != 0)
                    try res.setHeader("Access-Control-Allow-Headers", c.allow_headers_value),
            }
            if (c.options.allow_credentials)
                try res.setHeader("Access-Control-Allow-Credentials", "true");
            if (c.options.max_age_s != null)
                try res.setHeader("Access-Control-Max-Age", c.max_age_buf[0..c.max_age_len]);
        }
        // Short-circuit: 204, no body. end() is idempotent — the serving
        // loop's end() and flush still run.
        try res.end();
    }

    /// Actual request: set the response CORS headers when Origin + method
    /// pass; otherwise leave the response untouched. The chain runs either
    /// way (CORS withholds readability, it never blocks handling).
    fn applyActual(c: *const Cors, req: *const http.Server.Request, res: *http.Server.ResponseWriter) http.Server.ResponseWriter.SetHeaderError!void {
        const origin = req.header("Origin") orelse return;
        const acao = c.allowOriginValue(origin) orelse return;
        // rs/cors gate: an actual method outside allowed_methods gets no
        // CORS headers either (OPTIONS always passes, see methodTokenAllowed).
        if (!c.methodTokenAllowed(req.method.token())) return;

        try res.setHeader("Access-Control-Allow-Origin", acao);
        // Echoing a specific origin makes the response vary by it; the
        // literal `*` does not.
        if (c.options.allowed_origins != .any) try res.setHeader("Vary", "Origin");
        if (c.options.allow_credentials)
            try res.setHeader("Access-Control-Allow-Credentials", "true");
        if (c.expose_headers_value.len != 0)
            try res.setHeader("Access-Control-Expose-Headers", c.expose_headers_value);
    }

    // ── the gates ───────────────────────────────────────────────────────

    /// The `Access-Control-Allow-Origin` value for this request, or null
    /// when the origin is not allowed: `*` for `.any`, else the specific
    /// origin echoed back. Exact byte compare for `.list` (see module doc).
    fn allowOriginValue(c: *const Cors, origin: []const u8) ?[]const u8 {
        return switch (c.options.allowed_origins) {
            .none => null,
            .any => "*", // .any + credentials is rejected at init
            .list => |l| for (l) |o| {
                if (std.mem.eql(u8, o, origin)) break origin;
            } else null,
            .predicate => |p| if (p.allow(p.ctx, origin)) origin else null,
        };
    }

    /// Case-insensitive method-token check against `allowed_methods`.
    /// OPTIONS is always allowed (rs/cors: the preflight vehicle itself is
    /// never the thing being permitted).
    fn methodTokenAllowed(c: *const Cors, token: []const u8) bool {
        if (std.ascii.eqlIgnoreCase(token, "OPTIONS")) return true;
        for (c.options.allowed_methods) |m| {
            if (std.ascii.eqlIgnoreCase(token, m.token())) return true;
        }
        return false;
    }

    /// `.list` mode: every header named in the preflight's
    /// `Access-Control-Request-Headers` (comma-separated, OWS-tolerant)
    /// must be on the configured list (case-insensitive).
    fn requestedHeadersAllowed(c: *const Cors, acrh: []const u8) bool {
        const list = c.options.allowed_headers.list;
        var it = std.mem.splitScalar(u8, acrh, ',');
        while (it.next()) |raw| {
            const name = std.mem.trim(u8, raw, " \t");
            if (name.len == 0) continue;
            const ok = for (list) |h| {
                if (std.ascii.eqlIgnoreCase(h, name)) break true;
            } else false;
            if (!ok) return false;
        }
        return true;
    }
};

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const c: *const Cors = @ptrCast(@alignCast(state.?));
    // A preflight is OPTIONS *with* Access-Control-Request-Method — a plain
    // OPTIONS request (no ACRM) is an actual request and routes normally.
    if (ctx.req.method == .options and ctx.req.header("Access-Control-Request-Method") != null)
        return c.handlePreflight(ctx); // short-circuit: next is never called
    try c.applyActual(ctx.req, ctx.res);
    return next.run(ctx);
}

/// Join method tokens with ", " into one owned slice.
fn joinMethods(gpa: Allocator, methods: []const http.Method) Allocator.Error![]const u8 {
    var total: usize = 0;
    for (methods, 0..) |m, i| {
        if (i != 0) total += 2;
        total += m.token().len;
    }
    const buf = try gpa.alloc(u8, total);
    var w: std.Io.Writer = .fixed(buf);
    for (methods, 0..) |m, i| {
        if (i != 0) w.writeAll(", ") catch unreachable;
        w.writeAll(m.token()) catch unreachable;
    }
    return buf;
}

/// Header values go onto the wire verbatim — refuse response-splitting
/// characters in configuration (Debug builds only).
fn assertValueClean(v: []const u8) void {
    for (v) |ch| std.debug.assert(ch != '\r' and ch != '\n' and ch != 0);
}

// ── tests (offline — through http.Server.serveStream, no socket) ────────────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// (same harness as the router/security-headers tests).
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
        .server_name = null, // keep goldens free of Server/Date noise
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

/// "METHOD target" request with extra header lines ("" or "Name: v\r\n"...).
fn wire(comptime method: []const u8, comptime target: []const u8, comptime extra: []const u8) []const u8 {
    return method ++ " " ++ target ++ " HTTP/1.1\r\nHost: t\r\n" ++ extra ++ "Connection: close\r\n\r\n";
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn expectHeaderLine(got: []const u8, comptime line: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, got, "\r\n" ++ line ++ "\r\n") != null);
}

fn expectNoHeader(got: []const u8, comptime name: []const u8) !void {
    try testing.expect(std.ascii.indexOfIgnoreCase(got, "\r\n" ++ name ++ ":") == null);
}

fn expectNoCorsHeaders(got: []const u8) !void {
    try expectNoHeader(got, "Access-Control-Allow-Origin");
    try expectNoHeader(got, "Access-Control-Allow-Methods");
    try expectNoHeader(got, "Access-Control-Allow-Headers");
    try expectNoHeader(got, "Access-Control-Allow-Credentials");
    try expectNoHeader(got, "Access-Control-Expose-Headers");
    try expectNoHeader(got, "Access-Control-Max-Age");
}

/// Handler-invocation flag, carried via `Ctx.state` — no globals.
const Flag = struct {
    hit: bool = false,

    fn of(ctx: *router.Ctx) *Flag {
        return @ptrCast(@alignCast(ctx.state.?));
    }
};

fn hOk(ctx: *router.Ctx) anyerror!void {
    if (ctx.state != null) Flag.of(ctx).hit = true;
    try ctx.res.writeAll("ok");
}

/// A router with the given cors middleware installed globally + GET/POST /t.
fn testRouter(c: *const Cors, flag: ?*Flag) !router.Router {
    var r = router.Router.init(testing.allocator);
    errdefer r.deinit();
    if (flag) |f| r.state = f;
    try r.use(c.middleware());
    try r.get("/t", hOk);
    try r.post("/t", hOk);
    return r;
}

const preflight_wire = wire("OPTIONS", "/t", "Origin: https://app.example\r\n" ++
    "Access-Control-Request-Method: POST\r\n" ++
    "Access-Control-Request-Headers: content-type, authorization\r\n");

test "preflight: golden 204 with the full header set; handler not invoked" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
        .allowed_methods = &.{ .get, .post },
        .allowed_headers = .{ .list = &.{ "Content-Type", "Authorization" } },
        .max_age_s = 600,
    });
    defer c.deinit();
    var flag: Flag = .{};
    var r = try testRouter(&c, &flag);
    defer r.deinit();

    var buf: [2048]u8 = undefined;
    // Byte-exact: 204, no body, exactly these headers in this order. The
    // Allow line is the router's: /t has no OPTIONS route, so dispatch's
    // 405 path sets it before the global chain runs — the interception
    // keeps it (harmless and informative on a 204).
    try testing.expectEqualStrings("HTTP/1.1 204 No Content\r\n" ++
        "Allow: GET, HEAD, POST\r\n" ++
        "Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n" ++
        "Access-Control-Allow-Origin: https://app.example\r\n" ++
        "Access-Control-Allow-Methods: GET, POST\r\n" ++
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n" ++
        "Access-Control-Max-Age: 600\r\n" ++
        "Connection: close\r\n" ++
        "\r\n", runWire(&r, preflight_wire, &buf));
    try testing.expect(!flag.hit);
}

test "preflight: .reflect echoes Access-Control-Request-Headers verbatim; absent ACRH emits none" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
    });
    defer c.deinit();
    var r = try testRouter(&c, null);
    defer r.deinit();

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, preflight_wire, &buf);
    try expectStatus(got, "204");
    try expectHeaderLine(got, "Access-Control-Allow-Headers: content-type, authorization");
    // No max_age_s configured → no Max-Age header.
    try expectNoHeader(got, "Access-Control-Max-Age");

    const got2 = runWire(&r, wire("OPTIONS", "/t", "Origin: https://app.example\r\n" ++
        "Access-Control-Request-Method: GET\r\n"), &buf);
    try expectStatus(got2, "204");
    try expectHeaderLine(got2, "Access-Control-Allow-Origin: https://app.example");
    try expectNoHeader(got2, "Access-Control-Allow-Headers");
}

test "preflight: failing any gate → 204 with Vary but zero CORS headers" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
        .allowed_methods = &.{ .get, .post },
        .allowed_headers = .{ .list = &.{"Content-Type"} },
    });
    defer c.deinit();
    var flag: Flag = .{};
    var r = try testRouter(&c, &flag);
    defer r.deinit();
    var buf: [2048]u8 = undefined;

    { // disallowed origin (byte compare: case matters)
        const got = runWire(&r, wire("OPTIONS", "/t", "Origin: https://evil.example\r\n" ++
            "Access-Control-Request-Method: POST\r\n"), &buf);
        try expectStatus(got, "204");
        try expectHeaderLine(got, "Vary: " ++ preflight_vary);
        try expectNoCorsHeaders(got);
        const got_case = runWire(&r, wire("OPTIONS", "/t", "Origin: HTTPS://APP.EXAMPLE\r\n" ++
            "Access-Control-Request-Method: POST\r\n"), &buf);
        try expectNoCorsHeaders(got_case);
    }
    { // disallowed requested method
        const got = runWire(&r, wire("OPTIONS", "/t", "Origin: https://app.example\r\n" ++
            "Access-Control-Request-Method: DELETE\r\n"), &buf);
        try expectStatus(got, "204");
        try expectNoCorsHeaders(got);
    }
    { // disallowed requested header in .list mode
        const got = runWire(&r, wire("OPTIONS", "/t", "Origin: https://app.example\r\n" ++
            "Access-Control-Request-Method: POST\r\n" ++
            "Access-Control-Request-Headers: content-type, x-evil\r\n"), &buf);
        try expectStatus(got, "204");
        try expectNoCorsHeaders(got);
    }
    { // no Origin at all (not a real browser preflight)
        const got = runWire(&r, wire("OPTIONS", "/t", "Access-Control-Request-Method: POST\r\n"), &buf);
        try expectStatus(got, "204");
        try expectNoCorsHeaders(got);
    }
    try testing.expect(!flag.hit); // intercepted every time
}

test "preflight: intercepted before 405 and 404 (the global-middleware point)" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
        .allowed_methods = &.{ .get, .post },
    });
    defer c.deinit();
    var flag: Flag = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &flag;
    try r.use(c.middleware());
    try r.get("/get-only", hOk); // no OPTIONS route → would 405

    var buf: [2048]u8 = undefined;
    { // would-be 405: the preflight wins
        const got = runWire(&r, wire("OPTIONS", "/get-only", "Origin: https://app.example\r\n" ++
            "Access-Control-Request-Method: POST\r\n"), &buf);
        try expectStatus(got, "204");
        try expectHeaderLine(got, "Access-Control-Allow-Origin: https://app.example");
        try expectHeaderLine(got, "Access-Control-Allow-Methods: GET, POST");
    }
    { // would-be 404: still intercepted (the actual request will 404 with
        // CORS headers, readable by the calling script)
        const got = runWire(&r, wire("OPTIONS", "/nope", "Origin: https://app.example\r\n" ++
            "Access-Control-Request-Method: GET\r\n"), &buf);
        try expectStatus(got, "204");
        try expectHeaderLine(got, "Access-Control-Allow-Origin: https://app.example");
    }
    try testing.expect(!flag.hit);
}

test "plain OPTIONS without ACRM is NOT a preflight: routes normally (405 here) with actual-request CORS headers" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
    });
    defer c.deinit();
    var r = try testRouter(&c, null);
    defer r.deinit();

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("OPTIONS", "/t", "Origin: https://app.example\r\n"), &buf);
    try expectStatus(got, "405"); // no OPTIONS route; global chain ran anyway
    try expectHeaderLine(got, "Allow: GET, HEAD, POST");
    try expectHeaderLine(got, "Access-Control-Allow-Origin: https://app.example");
}

test "actual: allowed list origin → echo + Vary: Origin; credentials + exposed headers when configured" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{ "https://app.example", "http://localhost:5173" } },
        .allow_credentials = true,
        .exposed_headers = &.{ "X-Request-Id", "X-Total-Count" },
    });
    defer c.deinit();
    var flag: Flag = .{};
    var r = try testRouter(&c, &flag);
    defer r.deinit();

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("GET", "/t", "Origin: http://localhost:5173\r\n"), &buf);
    try expectStatus(got, "200");
    try expectHeaderLine(got, "Access-Control-Allow-Origin: http://localhost:5173");
    try expectHeaderLine(got, "Vary: Origin");
    try expectHeaderLine(got, "Access-Control-Allow-Credentials: true");
    try expectHeaderLine(got, "Access-Control-Expose-Headers: X-Request-Id, X-Total-Count");
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nok"));
    try testing.expect(flag.hit); // handler ran (next was called)
}

test "actual: .any emits literal * and no Vary; no credentials header unless enabled" {
    var c: Cors = try .init(testing.allocator, .{ .allowed_origins = .any });
    defer c.deinit();
    var r = try testRouter(&c, null);
    defer r.deinit();

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("GET", "/t", "Origin: https://anyone.example\r\n"), &buf);
    try expectStatus(got, "200");
    try expectHeaderLine(got, "Access-Control-Allow-Origin: *");
    try expectNoHeader(got, "Vary");
    try expectNoHeader(got, "Access-Control-Allow-Credentials");
}

test "actual: disallowed origin / absent Origin / default .none → no CORS headers, handler still runs" {
    var buf: [2048]u8 = undefined;
    { // disallowed origin
        var c: Cors = try .init(testing.allocator, .{
            .allowed_origins = .{ .list = &.{"https://app.example"} },
        });
        defer c.deinit();
        var flag: Flag = .{};
        var r = try testRouter(&c, &flag);
        defer r.deinit();
        const got = runWire(&r, wire("GET", "/t", "Origin: https://evil.example\r\n"), &buf);
        try expectStatus(got, "200");
        try expectNoCorsHeaders(got);
        try expectNoHeader(got, "Vary");
        try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\nok"));
        try testing.expect(flag.hit);
    }
    { // absent Origin: a same-origin / non-browser request passes through
        var c: Cors = try .init(testing.allocator, .{ .allowed_origins = .any });
        defer c.deinit();
        var r = try testRouter(&c, null);
        defer r.deinit();
        const got = runWire(&r, wire("GET", "/t", ""), &buf);
        try expectStatus(got, "200");
        try expectNoCorsHeaders(got);
    }
    { // secure default: .none never emits anything
        var c: Cors = try .init(testing.allocator, .{});
        defer c.deinit();
        var r = try testRouter(&c, null);
        defer r.deinit();
        const got = runWire(&r, wire("GET", "/t", "Origin: https://app.example\r\n"), &buf);
        try expectStatus(got, "200");
        try expectNoCorsHeaders(got);
    }
}

test "actual: method outside allowed_methods gets no CORS headers (rs/cors gate)" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
        .allowed_methods = &.{.get},
    });
    defer c.deinit();
    var r = try testRouter(&c, null);
    defer r.deinit();

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("POST", "/t", "Origin: https://app.example\r\n"), &buf);
    try expectStatus(got, "200"); // the handler still serves it
    try expectNoCorsHeaders(got);
    const got2 = runWire(&r, wire("GET", "/t", "Origin: https://app.example\r\n"), &buf);
    try expectHeaderLine(got2, "Access-Control-Allow-Origin: https://app.example");
}

fn allowDevOrigins(_: ?*anyopaque, origin: []const u8) bool {
    return std.mem.endsWith(u8, origin, ".dev.example");
}

test "predicate origins: allowed echoes the specific origin (both request shapes); denied gets nothing" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .predicate = .{ .allow = allowDevOrigins } },
        .allow_credentials = true, // fine with a predicate — never `*`
    });
    defer c.deinit();
    var r = try testRouter(&c, null);
    defer r.deinit();

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("GET", "/t", "Origin: https://alice.dev.example\r\n"), &buf);
    try expectHeaderLine(got, "Access-Control-Allow-Origin: https://alice.dev.example");
    try expectHeaderLine(got, "Access-Control-Allow-Credentials: true");
    try expectHeaderLine(got, "Vary: Origin");

    const pf = runWire(&r, wire("OPTIONS", "/t", "Origin: https://alice.dev.example\r\n" ++
        "Access-Control-Request-Method: POST\r\n"), &buf);
    try expectStatus(pf, "204");
    try expectHeaderLine(pf, "Access-Control-Allow-Origin: https://alice.dev.example");
    try expectHeaderLine(pf, "Access-Control-Allow-Credentials: true");

    const denied = runWire(&r, wire("GET", "/t", "Origin: https://prod.example\r\n"), &buf);
    try expectNoCorsHeaders(denied);
}

test "wildcard + credentials is rejected at init (spec-forbidden combination)" {
    try testing.expectError(error.CredentialsWithWildcardOrigin, Cors.init(testing.allocator, .{
        .allowed_origins = .any,
        .allow_credentials = true,
    }));
    // The safe variants of each half still initialize.
    var a: Cors = try .init(testing.allocator, .{ .allowed_origins = .any });
    a.deinit();
    var b: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
        .allow_credentials = true,
    });
    b.deinit();
}

test "preflight: credentials + max-age 0 emitted for a specific origin" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
        .allow_credentials = true,
        .max_age_s = 0, // "disable preflight caching" — 0 is a real value
    });
    defer c.deinit();
    var r = try testRouter(&c, null);
    defer r.deinit();

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("OPTIONS", "/t", "Origin: https://app.example\r\n" ++
        "Access-Control-Request-Method: POST\r\n"), &buf);
    try expectStatus(got, "204");
    try expectHeaderLine(got, "Access-Control-Allow-Credentials: true");
    try expectHeaderLine(got, "Access-Control-Max-Age: 0");
}

test "config joins: default methods, dedup-free caller order, requested-header OWS tolerance" {
    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .any,
        .allowed_headers = .{ .list = &.{ "Content-Type", "X-Api-Key" } },
    });
    defer c.deinit();
    try testing.expectEqualStrings("GET, HEAD, POST", c.allow_methods_value);
    try testing.expectEqualStrings("Content-Type, X-Api-Key", c.allow_headers_value);
    // Tokenizer: spaces + tabs around names, trailing comma, case folding.
    try testing.expect(c.requestedHeadersAllowed("content-type ,\tX-API-KEY,"));
    try testing.expect(!c.requestedHeadersAllowed("content-type, x-other"));

    var d: Cors = try .init(testing.allocator, .{
        .allowed_origins = .any,
        .allowed_methods = &.{ .delete, .put, .get },
        .max_age_s = std.math.maxInt(u32),
    });
    defer d.deinit();
    try testing.expectEqualStrings("DELETE, PUT, GET", d.allow_methods_value);
    // The largest value exactly fills the embedded buffer.
    try testing.expectEqualStrings("4294967295", d.max_age_buf[0..d.max_age_len]);
    try testing.expectEqual(max_age_digits, d.max_age_len);
}

// ── tests (in-process integration — http.Server + http.Client) ──────────────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

/// Handler-invocation counter for the loopback test, carried via
/// `Ctx.state` (atomic: handlers run on the server's connection threads).
fn hInteg(ctx: *router.Ctx) anyerror!void {
    const hits: *std.atomic.Value(u32) = @ptrCast(@alignCast(ctx.state.?));
    _ = hits.fetchAdd(1, .monotonic);
    try ctx.res.writeAll("hello");
}

test "integration: preflight 204 (handler not invoked), allowed GET gets Allow-Origin, disallowed gets none" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var c: Cors = try .init(testing.allocator, .{
        .allowed_origins = .{ .list = &.{"https://app.example"} },
        .allowed_methods = &.{ .get, .post },
        .max_age_s = 300,
    });
    defer c.deinit();
    var hits: std.atomic.Value(u32) = .init(0);
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &hits;
    try r.use(c.middleware());
    try r.get("/hello", hInteg);

    var server = http.Server.init(io, testing.allocator, .{
        .handler = r.handler(),
        .context = &r,
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const port = server.boundAddress().getPort();
    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello", .{port});

    { // preflight OPTIONS → 204 + the CORS headers, handler never invoked
        var res = try client.request(.options, url, .{ .headers = &.{
            .{ .name = "Origin", .value = "https://app.example" },
            .{ .name = "Access-Control-Request-Method", .value = "POST" },
            .{ .name = "Access-Control-Request-Headers", .value = "content-type" },
        } });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 204), res.status);
        try testing.expectEqualStrings("https://app.example", res.header("access-control-allow-origin").?);
        try testing.expectEqualStrings("GET, POST", res.header("access-control-allow-methods").?);
        try testing.expectEqualStrings("content-type", res.header("access-control-allow-headers").?);
        try testing.expectEqualStrings("300", res.header("access-control-max-age").?);
        try testing.expectEqual(@as(u32, 0), hits.load(.monotonic));
    }

    { // actual GET with the allowed Origin → Allow-Origin + Vary, body served
        var res = try client.request(.get, url, .{ .headers = &.{
            .{ .name = "Origin", .value = "https://app.example" },
        } });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("https://app.example", res.header("access-control-allow-origin").?);
        try testing.expectEqualStrings("Origin", res.header("vary").?);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello", body);
        try testing.expectEqual(@as(u32, 1), hits.load(.monotonic));
    }

    { // disallowed origin → served, but zero CORS headers
        var res = try client.request(.get, url, .{ .headers = &.{
            .{ .name = "Origin", .value = "https://evil.example" },
        } });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expect(res.header("access-control-allow-origin") == null);
        try testing.expect(res.header("vary") == null);
        try testing.expectEqual(@as(u32, 2), hits.load(.monotonic));
    }
}
