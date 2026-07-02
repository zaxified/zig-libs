// SPDX-License-Identifier: MIT

//! security-headers — secure-by-default HTTP security response headers as a
//! stateless `router` middleware.
//!
//! A directly-internet-facing API should ship the standard hardening headers
//! on every response. `SecurityHeaders.init(.{})` gives the secure default
//! set; every header is individually overridable or disable-able through
//! `Options`. The middleware sets the configured headers on the
//! `ResponseWriter` **before** calling `next`, so the handler's head is
//! written with them and a handler may still override any single header by
//! setting it again (`setHeader` replaces by case-insensitive name) —
//! middleware provides the default, the handler wins.
//!
//! Default header set (see `Options` for the knobs):
//!
//! - `Strict-Transport-Security: max-age=31536000; includeSubDomains` —
//!   helmet.js v7 default (365 days, no `preload`). **Only meaningful over
//!   HTTPS**: browsers ignore HSTS received over plain HTTP, so the header
//!   is harmless there, but only ever deploy it on a host actually served
//!   via TLS — once cached, browsers refuse plain-HTTP for `max-age`
//!   (and, with `include_subdomains`, for every subdomain). Opt into
//!   `preload` only after registering at <https://hstspreload.org>.
//! - `X-Content-Type-Options: nosniff`.
//! - `X-Frame-Options: DENY` (spec-mandated default; helmet defaults to
//!   SAMEORIGIN — deviation noted). This is the legacy anti-clickjacking
//!   header; the modern form is the CSP `frame-ancestors` directive, which
//!   overrides `X-Frame-Options` in supporting browsers — keep the two
//!   consistent when you configure a CSP.
//! - `Referrer-Policy: no-referrer` (helmet default).
//! - `Cross-Origin-Opener-Policy: same-origin`,
//!   `Cross-Origin-Resource-Policy: same-origin` (helmet defaults).
//!
//! Off by default (opt-in):
//!
//! - `Content-Security-Policy` — **no default policy is emitted**. There is
//!   no universally-safe value: a browser-app policy breaks JSON APIs'
//!   consumers no more than an API policy breaks HTML pages, but silently
//!   shipping either is worse than making the choice explicit. Deviation
//!   from helmet (which defaults CSP on) — deliberate, and required by this
//!   module's spec ("CSP present only when configured"). Ready-made
//!   postures: `csp_api` (deny-everything, for pure JSON/binary APIs) and
//!   `csp_helmet_default` (helmet's browser-app default). An optional
//!   `Content-Security-Policy-Report-Only` mirror is independent, for
//!   trialing a policy without enforcing it.
//! - `Permissions-Policy` — caller-supplied feature-policy string
//!   (e.g. `"camera=(), microphone=(), geolocation=()"`).
//! - `Cross-Origin-Embedder-Policy` — **off by default** (matches helmet):
//!   COEP (`require-corp`) breaks every embedded cross-origin resource that
//!   does not opt in via CORP/CORS; enable it only when you need
//!   cross-origin isolation (SharedArrayBuffer et al.).
//! - `Server` — optional fingerprint reduction: a configured value replaces
//!   `http.Server`'s automatic `Server:` header for these responses. To
//!   drop the header entirely, configure the server itself with
//!   `.server_name = null` (a header, once set, can only be replaced).
//!
//! Stateless and reentrant: the middleware `state` is a pointer to the
//! immutable `SecurityHeaders` (precomputed config) — no clock, no
//! allocation, no locks; the hot path is a fixed series of `setHeader`
//! calls with precomputed strings (the HSTS value is formatted once at
//! `init` into an embedded buffer). Safe to share across all of
//! `http.Server`'s connection threads.
//!
//! Placement: register it **first** (outermost, before other middleware and
//! all routes — chi's rule) so short-circuit responses from inner middleware
//! (ratelimit 429, throttle 503, auth 401) and the router's 404/405
//! fallbacks carry the headers too. Known limitation: when a handler
//! *errors*, `http.Server` resets the response to build its automatic 500,
//! which drops all previously set headers — the plain 500 carries no
//! security headers (same for the server's own 431/414/413 replies, which
//! bypass the router entirely).
//!
//! Header values are emitted verbatim onto the wire: caller-supplied
//! strings must outlive the middleware and must not contain CR/LF (checked
//! with a Debug assert at `init`).

const std = @import("std");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .status = .gap,
    .platform = .any,
    .role = .util,
    // An initialized SecurityHeaders is immutable; the middleware only reads
    // it and writes per-request state owned by the connection task.
    .concurrency = .reentrant,
    .model_after = "helmet.js defaults + OWASP Secure Headers Project",
    .deps = .{ "router", "http" },
};

// ── configuration ───────────────────────────────────────────────────────────

/// `Strict-Transport-Security` knobs. The value string is precomputed at
/// `SecurityHeaders.init`. HTTPS-only in effect (browsers ignore HSTS over
/// plain HTTP) — see the module doc before enabling `preload`.
pub const Hsts = struct {
    /// `max-age` in seconds. Default 31536000 (365 days — helmet v7 default).
    max_age_s: u64 = 31_536_000,
    /// Apply to all subdomains too (helmet default: on).
    include_subdomains: bool = true,
    /// Chrome preload-list marker — requires `max_age_s` ≥ 1 year,
    /// `include_subdomains`, and registration at hstspreload.org. Off by
    /// default (helmet default).
    preload: bool = false,
};

/// One optional per header: `null` (or `false`) disables the header, a
/// string replaces the default value. Defaults = the secure baseline
/// (helmet.js defaults, except `x_frame_options` = DENY per spec). All
/// strings are borrowed — they must outlive the `SecurityHeaders`.
pub const Options = struct {
    /// `Strict-Transport-Security`; null = omit. HTTPS-only in effect.
    hsts: ?Hsts = .{},
    /// `Content-Security-Policy`; **off by default** — no universally-safe
    /// policy exists. See `csp_api` / `csp_helmet_default` for postures.
    content_security_policy: ?[]const u8 = null,
    /// `Content-Security-Policy-Report-Only`; independent of the enforcing
    /// header (typically used to trial a stricter policy).
    content_security_policy_report_only: ?[]const u8 = null,
    /// `X-Content-Type-Options: nosniff` ("nosniff" is the only defined
    /// value, hence a bool). Default on.
    x_content_type_options: bool = true,
    /// `X-Frame-Options`; default DENY (helmet uses SAMEORIGIN). Legacy —
    /// prefer expressing this as CSP `frame-ancestors` when you set a CSP,
    /// and keep both consistent.
    x_frame_options: ?[]const u8 = "DENY",
    /// `Referrer-Policy`; default `no-referrer` (helmet default — the most
    /// private; use "strict-origin-when-cross-origin" for the common
    /// browser-app compromise).
    referrer_policy: ?[]const u8 = "no-referrer",
    /// `Permissions-Policy`; caller-supplied, off by default (helmet does
    /// not set it either).
    permissions_policy: ?[]const u8 = null,
    /// `Cross-Origin-Opener-Policy`; default `same-origin` (helmet default).
    cross_origin_opener_policy: ?[]const u8 = "same-origin",
    /// `Cross-Origin-Resource-Policy`; default `same-origin` (helmet
    /// default; use "cross-origin" for public CDN-style assets).
    cross_origin_resource_policy: ?[]const u8 = "same-origin",
    /// `Cross-Origin-Embedder-Policy`; **off by default** (matches helmet —
    /// it breaks cross-origin embeds). Opt in with "require-corp" (or
    /// "credentialless") only when you need cross-origin isolation.
    cross_origin_embedder_policy: ?[]const u8 = null,
    /// Replacement `Server` header value (fingerprint reduction); null =
    /// leave the server's own behavior. Removal is not possible from
    /// middleware — configure `http.Server` with `.server_name = null`.
    server: ?[]const u8 = null,
};

/// Deny-everything CSP for a pure JSON/binary API (no HTML is ever
/// rendered from these responses): nothing loads, nothing embeds it.
pub const csp_api: []const u8 =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// helmet.js v7's default browser-app policy, reproduced as configuration
/// data (helmet is MIT; see NOTICE). A reasonable starting point when the
/// server also serves HTML.
pub const csp_helmet_default: []const u8 =
    "default-src 'self';base-uri 'self';font-src 'self' https: data:;" ++
    "form-action 'self';frame-ancestors 'self';img-src 'self' data:;" ++
    "object-src 'none';script-src 'self';script-src-attr 'none';" ++
    "style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests";

// "max-age=" + digits of maxInt(u64) + the two flags — the longest possible
// HSTS value, so the init-time formatting below can never fail.
const hsts_buf_len = "max-age=".len +
    std.fmt.count("{d}", .{std.math.maxInt(u64)}) +
    "; includeSubDomains".len + "; preload".len;

// ── the middleware ──────────────────────────────────────────────────────────

/// Immutable, precomputed header set + the `router.Middleware` over it.
/// Reentrant: init once (any thread), then share freely.
pub const SecurityHeaders = struct {
    options: Options,
    /// Precomputed `Strict-Transport-Security` value (formatted at init so
    /// the per-request path allocates and formats nothing).
    hsts_buf: [hsts_buf_len]u8 = undefined,
    hsts_len: usize = 0,

    /// Precompute the header set. `SecurityHeaders.init(.{})` = the secure
    /// defaults. Caller-supplied strings are borrowed (must outlive the
    /// returned value) and must not contain CR/LF/NUL (Debug-asserted).
    pub fn init(options: Options) SecurityHeaders {
        if (std.debug.runtime_safety) {
            if (options.content_security_policy) |v| assertValueClean(v);
            if (options.content_security_policy_report_only) |v| assertValueClean(v);
            if (options.x_frame_options) |v| assertValueClean(v);
            if (options.referrer_policy) |v| assertValueClean(v);
            if (options.permissions_policy) |v| assertValueClean(v);
            if (options.cross_origin_opener_policy) |v| assertValueClean(v);
            if (options.cross_origin_resource_policy) |v| assertValueClean(v);
            if (options.cross_origin_embedder_policy) |v| assertValueClean(v);
            if (options.server) |v| assertValueClean(v);
        }
        var sh: SecurityHeaders = .{ .options = options };
        if (options.hsts) |h| {
            // The buffer is sized for the longest possible value.
            var w: std.Io.Writer = .fixed(&sh.hsts_buf);
            w.print("max-age={d}", .{h.max_age_s}) catch unreachable;
            if (h.include_subdomains) w.writeAll("; includeSubDomains") catch unreachable;
            if (h.preload) w.writeAll("; preload") catch unreachable;
            sh.hsts_len = w.buffered().len;
        }
        return sh;
    }

    /// The precomputed `Strict-Transport-Security` value ("" when disabled).
    pub fn hstsValue(sh: *const SecurityHeaders) []const u8 {
        return sh.hsts_buf[0..sh.hsts_len];
    }

    /// Set every configured header on `res` (emitted in the fixed order
    /// below). Usable directly on any `ResponseWriter` when not routing
    /// through the middleware. Values set here are defaults in effect: a
    /// later `setHeader` with the same name replaces them (handler wins).
    pub fn apply(sh: *const SecurityHeaders, res: *http.Server.ResponseWriter) http.Server.ResponseWriter.SetHeaderError!void {
        const o = &sh.options;
        if (o.hsts != null) try res.setHeader("Strict-Transport-Security", sh.hstsValue());
        if (o.content_security_policy) |v| try res.setHeader("Content-Security-Policy", v);
        if (o.content_security_policy_report_only) |v| try res.setHeader("Content-Security-Policy-Report-Only", v);
        if (o.x_content_type_options) try res.setHeader("X-Content-Type-Options", "nosniff");
        if (o.x_frame_options) |v| try res.setHeader("X-Frame-Options", v);
        if (o.referrer_policy) |v| try res.setHeader("Referrer-Policy", v);
        if (o.permissions_policy) |v| try res.setHeader("Permissions-Policy", v);
        if (o.cross_origin_opener_policy) |v| try res.setHeader("Cross-Origin-Opener-Policy", v);
        if (o.cross_origin_resource_policy) |v| try res.setHeader("Cross-Origin-Resource-Policy", v);
        if (o.cross_origin_embedder_policy) |v| try res.setHeader("Cross-Origin-Embedder-Policy", v);
        if (o.server) |v| try res.setHeader("Server", v);
    }

    /// The `router.Middleware` (`state` = this immutable SecurityHeaders —
    /// per-instance, no globals; never mutated by `run`). Sets the headers,
    /// then runs the rest of the chain. Register it first (outermost,
    /// before routes — chi's rule) so inner short-circuits and 404/405
    /// fallbacks carry the headers too.
    pub fn middleware(sh: *const SecurityHeaders) router.Middleware {
        // Middleware.state is a mutable pointer by type only — run() never
        // writes through it.
        return .{ .state = @constCast(sh), .run = middlewareRun };
    }
};

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const sh: *const SecurityHeaders = @ptrCast(@alignCast(state.?));
    try sh.apply(ctx.res);
    return next.run(ctx);
}

/// Header values go onto the wire verbatim — refuse response-splitting
/// characters in configuration (Debug builds only).
fn assertValueClean(v: []const u8) void {
    for (v) |c| std.debug.assert(c != '\r' and c != '\n' and c != 0);
}

// ── tests (offline — through http.Server.serveStream, no socket) ────────────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// (same harness as the router/ratelimit/throttle tests).
fn runWireNamed(r: *router.Router, bytes: []const u8, out_buf: []u8, server_name: ?[]const u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = server_name,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    return runWireNamed(r, bytes, out_buf, null); // keep goldens free of Server noise
}

fn wire(comptime target: []const u8) []const u8 {
    return "GET " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
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

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

fn hFramed(ctx: *router.Ctx) anyerror!void {
    // Handler overrides one middleware default; the rest stay.
    try ctx.res.setHeader("X-Frame-Options", "SAMEORIGIN");
    try ctx.res.writeAll("framed");
}

test "defaults: exactly the expected header set with expected values (golden wire)" {
    const sh: SecurityHeaders = .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    // Byte-exact: asserts each default header AND the absence of everything
    // else (no CSP, no Permissions-Policy, no COEP, no Server).
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" ++
        "X-Content-Type-Options: nosniff\r\n" ++
        "X-Frame-Options: DENY\r\n" ++
        "Referrer-Policy: no-referrer\r\n" ++
        "Cross-Origin-Opener-Policy: same-origin\r\n" ++
        "Cross-Origin-Resource-Policy: same-origin\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 2\r\n" ++
        "\r\n" ++
        "ok", runWire(&r, wire("/t"), &buf));
}

test "disabling: each header omittable; everything off = a bare response" {
    { // one header off, the rest of the set intact
        const sh: SecurityHeaders = .init(.{ .hsts = null });
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(sh.middleware());
        try r.get("/t", hOk);

        var buf: [2048]u8 = undefined;
        const got = runWire(&r, wire("/t"), &buf);
        try expectNoHeader(got, "Strict-Transport-Security");
        try expectHeaderLine(got, "X-Content-Type-Options: nosniff");
        try expectHeaderLine(got, "X-Frame-Options: DENY");
        try expectHeaderLine(got, "Referrer-Policy: no-referrer");
        try expectHeaderLine(got, "Cross-Origin-Opener-Policy: same-origin");
        try expectHeaderLine(got, "Cross-Origin-Resource-Policy: same-origin");
    }
    { // all off: golden proof that nothing is emitted
        const sh: SecurityHeaders = .init(.{
            .hsts = null,
            .x_content_type_options = false,
            .x_frame_options = null,
            .referrer_policy = null,
            .cross_origin_opener_policy = null,
            .cross_origin_resource_policy = null,
        });
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(sh.middleware());
        try r.get("/t", hOk);

        var buf: [2048]u8 = undefined;
        try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++
            "Connection: close\r\n" ++
            "Content-Length: 2\r\n" ++
            "\r\n" ++
            "ok", runWire(&r, wire("/t"), &buf));
    }
}

test "overriding: custom values replace the defaults" {
    const sh: SecurityHeaders = .init(.{
        .hsts = .{ .max_age_s = 63_072_000, .include_subdomains = false },
        .x_frame_options = "SAMEORIGIN",
        .referrer_policy = "strict-origin-when-cross-origin",
        .cross_origin_opener_policy = "same-origin-allow-popups",
        .cross_origin_resource_policy = "cross-origin",
        .permissions_policy = "camera=(), microphone=(), geolocation=()",
    });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try expectHeaderLine(got, "Strict-Transport-Security: max-age=63072000");
    try expectHeaderLine(got, "X-Frame-Options: SAMEORIGIN");
    try expectHeaderLine(got, "Referrer-Policy: strict-origin-when-cross-origin");
    try expectHeaderLine(got, "Cross-Origin-Opener-Policy: same-origin-allow-popups");
    try expectHeaderLine(got, "Cross-Origin-Resource-Policy: cross-origin");
    try expectHeaderLine(got, "Permissions-Policy: camera=(), microphone=(), geolocation=()");
}

test "CSP: absent by default, present exactly as configured; Report-Only independent" {
    // Absence with defaults is proven byte-exactly by the golden test above.
    const sh: SecurityHeaders = .init(.{
        .content_security_policy = csp_api,
        .content_security_policy_report_only = "default-src 'self'",
    });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("/t"), &buf);
    try expectHeaderLine(got, "Content-Security-Policy: default-src 'none'; " ++
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    try expectHeaderLine(got, "Content-Security-Policy-Report-Only: default-src 'self'");
}

test "COEP: off by default, opt-in emits it" {
    const sh: SecurityHeaders = .init(.{ .cross_origin_embedder_policy = "require-corp" });
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    try expectHeaderLine(runWire(&r, wire("/t"), &buf), "Cross-Origin-Embedder-Policy: require-corp");
}

test "HSTS: value format for every flag combination" {
    const a: SecurityHeaders = .init(.{});
    try testing.expectEqualStrings("max-age=31536000; includeSubDomains", a.hstsValue());

    const b: SecurityHeaders = .init(.{ .hsts = .{ .preload = true } });
    try testing.expectEqualStrings("max-age=31536000; includeSubDomains; preload", b.hstsValue());

    const c: SecurityHeaders = .init(.{ .hsts = .{ .max_age_s = 0, .include_subdomains = false } });
    try testing.expectEqualStrings("max-age=0", c.hstsValue());

    const d: SecurityHeaders = .init(.{ .hsts = .{ .include_subdomains = false, .preload = true } });
    try testing.expectEqualStrings("max-age=31536000; preload", d.hstsValue());

    // The longest possible value exactly fills the precomputed buffer.
    const e: SecurityHeaders = .init(.{ .hsts = .{ .max_age_s = std.math.maxInt(u64), .preload = true } });
    try testing.expectEqualStrings("max-age=18446744073709551615; includeSubDomains; preload", e.hstsValue());
    try testing.expectEqual(hsts_buf_len, e.hstsValue().len);

    const off: SecurityHeaders = .init(.{ .hsts = null });
    try testing.expectEqualStrings("", off.hstsValue());
}

test "precedence: a handler's own header replaces the middleware default" {
    const sh: SecurityHeaders = .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/framed", hFramed);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, wire("/framed"), &buf);
    try expectStatus(got, "200");
    try expectHeaderLine(got, "X-Frame-Options: SAMEORIGIN");
    // Replaced, not duplicated — and the untouched defaults are intact.
    try testing.expectEqual(1, std.mem.count(u8, got, "X-Frame-Options"));
    try expectHeaderLine(got, "X-Content-Type-Options: nosniff");
    try expectHeaderLine(got, "Strict-Transport-Security: max-age=31536000; includeSubDomains");
}

test "Server: configured value replaces the server's automatic header" {
    { // control: without the option the server's own name goes out
        const sh: SecurityHeaders = .init(.{});
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(sh.middleware());
        try r.get("/t", hOk);

        var buf: [2048]u8 = undefined;
        try expectHeaderLine(runWireNamed(&r, wire("/t"), &buf, "real-server/1.0"), "Server: real-server/1.0");
    }
    { // replacement: the middleware value wins, the auto value never appears
        const sh: SecurityHeaders = .init(.{ .server = "webserver" });
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(sh.middleware());
        try r.get("/t", hOk);

        var buf: [2048]u8 = undefined;
        const got = runWireNamed(&r, wire("/t"), &buf, "real-server/1.0");
        try expectHeaderLine(got, "Server: webserver");
        try testing.expect(std.mem.indexOf(u8, got, "real-server") == null);
    }
}

test "404/405 fallbacks carry the headers too (router-level chain)" {
    const sh: SecurityHeaders = .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/t", hOk);

    var buf: [2048]u8 = undefined;
    const nf = runWire(&r, wire("/nope"), &buf);
    try expectStatus(nf, "404");
    try expectHeaderLine(nf, "X-Frame-Options: DENY");
    try expectHeaderLine(nf, "X-Content-Type-Options: nosniff");

    var buf2: [2048]u8 = undefined;
    const mna = runWireNamed(&r, "POST /t HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf2, null);
    try expectStatus(mna, "405");
    try expectHeaderLine(mna, "X-Frame-Options: DENY");
}

test "apply: usable directly on a bare ResponseWriter (no router)" {
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    const sh: SecurityHeaders = .init(.{});
    try sh.apply(&rw);
    try rw.end();
    const got = out.buffered();
    try expectHeaderLine(got, "Strict-Transport-Security: max-age=31536000; includeSubDomains");
    try expectHeaderLine(got, "Cross-Origin-Opener-Policy: same-origin");
}

// ── tests (in-process integration — http.Server + http.Client) ──────────────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

test "integration: a 200 over loopback carries the headers; handler override wins" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const sh: SecurityHeaders = .init(.{});
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/hello", hOk);
    try r.get("/framed", hFramed);

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

    { // the full default set on a normal 200
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("max-age=31536000; includeSubDomains", res.header("strict-transport-security").?);
        try testing.expectEqualStrings("nosniff", res.header("x-content-type-options").?);
        try testing.expectEqualStrings("DENY", res.header("x-frame-options").?);
        try testing.expectEqualStrings("no-referrer", res.header("referrer-policy").?);
        try testing.expectEqualStrings("same-origin", res.header("cross-origin-opener-policy").?);
        try testing.expectEqualStrings("same-origin", res.header("cross-origin-resource-policy").?);
        try testing.expect(res.header("content-security-policy") == null);
        try testing.expect(res.header("cross-origin-embedder-policy") == null);
        const body = try res.readAllAlloc(testing.allocator, 1024);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("ok", body);
    }

    { // a handler that sets its own X-Frame-Options wins over the default
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/framed", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expectEqualStrings("SAMEORIGIN", res.header("x-frame-options").?);
        try testing.expectEqualStrings("nosniff", res.header("x-content-type-options").?);
    }
}
