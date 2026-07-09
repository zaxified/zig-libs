// SPDX-License-Identifier: MIT

//! csrf — signed double-submit CSRF protection (OWASP CSRF Prevention Cheat
//! Sheet, "Signed Double-Submit Cookie").
//!
//! The token is `HMAC-SHA256(key, session_id)`, hex-encoded. Because it is a
//! keyed MAC over the session id, it is:
//!   - **bound to the session** — a token minted for session A does not verify
//!     for session B (defeats token fixation / cross-session replay), and
//!   - **stateless** — the server never stores it; it recomputes the expected
//!     MAC from the session id and compares in **constant time**
//!     (`std.crypto.timing_safe.eql`, never `std.mem.eql`).
//!
//! `middleware` guards the unsafe methods (POST/PUT/PATCH/DELETE): a guarded
//! request must present the token (in the `X-CSRF-Token` header, or a
//! configurable query-parameter fallback) and it must verify against the
//! request's session id (read from the session cookie) — otherwise **403**.
//! Safe methods pass and receive a fresh, JS-readable token cookie to echo on
//! their next unsafe request.
//!
//! ## Why not read the token from the POST body form field
//!
//! In this stack the handler owns the request-body reader; a middleware that
//! drained the body to find a `csrf_token` form field would steal it from the
//! handler. So the middleware extracts from the header (AJAX) and an optional
//! query parameter only. An app that renders a classic hidden form field parses
//! its own body and calls `verify(session_id, field_value)` directly — the pure
//! function is the seam. (Body form-field auto-extraction is a documented
//! DEFER.)

const std = @import("std");
const router = @import("router");
const http = @import("http");
const cookies = @import("cookies");

/// The MAC primitive: HMAC-SHA256.
pub const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

/// Raw MAC length (32).
pub const mac_length = Hmac.mac_length;

/// Hex token length (64).
pub const token_hex_len = mac_length * 2;

pub const default_header_name = "X-CSRF-Token";
pub const default_cookie_name = "csrf_token";
pub const default_form_field = "csrf_token";
pub const default_session_cookie = "session";

/// A signed double-submit CSRF guard. Immutable once built; share one across
/// threads. `key` is the HMAC secret — provision it out of band (32 random
/// bytes, kept server-side); rotating it invalidates all outstanding tokens
/// (a documented DEFER: dual-key rotation).
pub const Csrf = struct {
    key: [32]u8,
    /// Cookie the fresh token is delivered in (JS-readable → not HttpOnly).
    cookie_name: []const u8 = default_cookie_name,
    /// Request header the token is read from first.
    header_name: []const u8 = default_header_name,
    /// Query-parameter fallback name (also the conventional hidden-form-field
    /// name apps use with `verify`). Taken verbatim (not percent-decoded).
    form_field: []const u8 = default_form_field,
    /// Session cookie whose value is the HMAC message.
    session_cookie: []const u8 = default_session_cookie,
    /// `SameSite` for the token cookie.
    same_site: cookies.SameSite = .lax,
    /// `Secure` for the token cookie.
    secure: bool = true,
    /// The methods that require a valid token (the unsafe ones).
    methods: []const http.Method = &.{ .post, .put, .patch, .delete },
    /// Issue a fresh token cookie on safe responses (so a client always has a
    /// token to submit). Off ⇒ the app delivers the token itself.
    issue_on_safe: bool = true,

    /// Write the hex token for `session_id` into `out`, returning the slice.
    pub fn token(c: *const Csrf, session_id: []const u8, out: *[token_hex_len]u8) []const u8 {
        var mac: [mac_length]u8 = undefined;
        Hmac.create(&mac, session_id, &c.key);
        out.* = std.fmt.bytesToHex(mac, .lower);
        return out;
    }

    /// Whether `presented` is a valid token for `session_id`. Decodes both to
    /// raw MACs and compares with `std.crypto.timing_safe.eql` — never
    /// `std.mem.eql`. A wrong length or non-hex token is rejected (false).
    pub fn verify(c: *const Csrf, session_id: []const u8, presented: []const u8) bool {
        if (presented.len != token_hex_len) return false;
        var got: [mac_length]u8 = undefined;
        _ = std.fmt.hexToBytes(&got, presented) catch return false;
        var want: [mac_length]u8 = undefined;
        Hmac.create(&want, session_id, &c.key);
        return std.crypto.timing_safe.eql([mac_length]u8, want, got);
    }

    /// A `router.Middleware` enforcing the guard. Place it after the sessions
    /// middleware (it reads the session cookie); the Csrf must outlive the
    /// Router, at a stable address.
    pub fn middleware(c: *const Csrf) router.Middleware {
        return .{ .state = @constCast(c), .run = middlewareRun };
    }

    /// Set a fresh token cookie on the response for `session_id` (JS-readable).
    /// Best-effort (skipped if the head is already on the wire). Exposed so an
    /// app can issue a token from a handler explicitly.
    pub fn issue(c: *const Csrf, res: *http.Server.ResponseWriter, session_id: []const u8) void {
        var hexbuf: [token_hex_len]u8 = undefined;
        const tok = c.token(session_id, &hexbuf);
        const sc: cookies.SetCookie = .{
            .name = c.cookie_name,
            .value = tok,
            .path = "/",
            .secure = c.secure,
            .http_only = false, // the client's JS must read it to echo it
            .same_site = c.same_site,
        };
        // Thread-local: the response writer keeps the header slice uncopied
        // until writeHead, after this returns — a stack buffer would dangle.
        const v = sc.bufPrint(&cookie_buf) catch return;
        res.addSetCookie(v) catch {};
    }
};

threadlocal var cookie_buf: [256]u8 = undefined;

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const c: *const Csrf = @ptrCast(@alignCast(state.?));
    const sid = cookies.get(ctx.req, c.session_cookie);

    if (guarded(c.methods, ctx.req.method)) {
        const session_id = sid orelse return forbidden(ctx);
        const presented = presentedToken(c, ctx.req) orelse return forbidden(ctx);
        if (!c.verify(session_id, presented)) return forbidden(ctx);
        return next.run(ctx);
    }

    // Safe method: run, then hand back a fresh token to echo next time.
    try next.run(ctx);
    if (c.issue_on_safe) if (sid) |session_id| c.issue(ctx.res, session_id);
}

fn guarded(methods: []const http.Method, m: http.Method) bool {
    for (methods) |g| {
        if (g == m) return true;
    }
    return false;
}

/// The token presented on the request: the header value first, then the
/// query-parameter fallback. Both trimmed; empty counts as absent.
fn presentedToken(c: *const Csrf, req: *const http.Server.Request) ?[]const u8 {
    if (req.header(c.header_name)) |v| {
        const t = std.mem.trim(u8, v, " \t");
        if (t.len != 0) return t;
    }
    if (queryValue(req.query, c.form_field)) |v| {
        if (v.len != 0) return v;
    }
    return null;
}

/// First value of query parameter `name` in a raw `k=v&k2=v2` string, verbatim.
fn queryValue(query: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], name)) return pair[eq + 1 ..];
    }
    return null;
}

fn forbidden(ctx: *router.Ctx) anyerror!void {
    ctx.res.setStatus(403);
    try ctx.res.setHeader("Content-Type", "text/plain");
    try ctx.res.writeAll("CSRF token missing or invalid\n");
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

test "token/verify round-trip; wrong session id and tamper fail" {
    const c = Csrf{ .key = @splat(0xA5) };
    var buf: [token_hex_len]u8 = undefined;
    const tok = c.token("session-A", &buf);
    try testing.expectEqual(@as(usize, 64), tok.len);
    try testing.expect(c.verify("session-A", tok));

    // Replay across sessions: a token for A must not verify for B.
    try testing.expect(!c.verify("session-B", tok));

    // Tamper: flip one hex nibble → reject.
    var tampered = buf;
    tampered[0] = if (tampered[0] == 'a') 'b' else 'a';
    try testing.expect(!c.verify("session-A", &tampered));

    // Wrong length / non-hex → reject (no crash).
    try testing.expect(!c.verify("session-A", "short"));
    try testing.expect(!c.verify("session-A", "zz" ++ ("0" ** 62)));
}

test "different keys produce different (non-cross-verifying) tokens" {
    const c1 = Csrf{ .key = @splat(1) };
    const c2 = Csrf{ .key = @splat(2) };
    var b1: [token_hex_len]u8 = undefined;
    var b2: [token_hex_len]u8 = undefined;
    const t1 = c1.token("s", &b1);
    const t2 = c2.token("s", &b2);
    try testing.expect(!std.mem.eql(u8, t1, t2));
    try testing.expect(!c1.verify("s", t2));
    try testing.expect(!c2.verify("s", t1));
}

// Middleware harness.
fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
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

fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn makeRouter(r: *router.Router, c: *const Csrf) !void {
    try r.use(c.middleware());
    try r.get("/", hOk);
    try r.post("/", hOk);
}

test "middleware: safe GET passes and issues a JS-readable token cookie" {
    const c = Csrf{ .key = @splat(0x11) };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try makeRouter(&r, &c);

    var out: [4096]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nCookie: session=abc123\r\nConnection: close\r\n\r\n", &out);
    try expectStatus(got, "200");
    const sc = headerValue(got, "Set-Cookie").?;
    try testing.expect(std.mem.startsWith(u8, sc, "csrf_token="));
    // JS must read it → NOT HttpOnly.
    try testing.expect(std.mem.indexOf(u8, sc, "HttpOnly") == null);
    // The issued token verifies for that session.
    var buf: [token_hex_len]u8 = undefined;
    try testing.expect(c.verify("abc123", c.token("abc123", &buf)));
}

test "middleware: unsafe POST is 403 without a token, passes with the right one" {
    const c = Csrf{ .key = @splat(0x22) };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try makeRouter(&r, &c);

    // No token → 403, handler never runs.
    var out: [4096]u8 = undefined;
    const denied = runWire(&r, "POST / HTTP/1.1\r\nHost: t\r\nCookie: session=sess1\r\nConnection: close\r\n\r\n", &out);
    try expectStatus(denied, "403");

    // Compute the valid token, present it in the header → 200.
    var buf: [token_hex_len]u8 = undefined;
    const tok = c.token("sess1", &buf);
    const req = std.fmt.allocPrint(testing.allocator, "POST / HTTP/1.1\r\nHost: t\r\nCookie: session=sess1\r\nX-CSRF-Token: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{tok}) catch unreachable;
    defer testing.allocator.free(req);
    var out2: [4096]u8 = undefined;
    const ok = runWire(&r, req, &out2);
    try expectStatus(ok, "200");
    try testing.expect(std.mem.endsWith(u8, ok, "ok"));
}

test "middleware: a token from another session is rejected on POST (403)" {
    const c = Csrf{ .key = @splat(0x33) };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try makeRouter(&r, &c);

    // Token minted for "other", presented on a request whose session is "mine".
    var buf: [token_hex_len]u8 = undefined;
    const tok_other = c.token("other", &buf);
    const req = std.fmt.allocPrint(testing.allocator, "POST / HTTP/1.1\r\nHost: t\r\nCookie: session=mine\r\nX-CSRF-Token: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{tok_other}) catch unreachable;
    defer testing.allocator.free(req);
    var out: [4096]u8 = undefined;
    try expectStatus(runWire(&r, req, &out), "403");
}

test "middleware: query-parameter fallback token is accepted" {
    const c = Csrf{ .key = @splat(0x44) };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(c.middleware());
    try r.post("/submit", hOk);

    var buf: [token_hex_len]u8 = undefined;
    const tok = c.token("qs", &buf);
    const req = std.fmt.allocPrint(testing.allocator, "POST /submit?csrf_token={s} HTTP/1.1\r\nHost: t\r\nCookie: session=qs\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{tok}) catch unreachable;
    defer testing.allocator.free(req);
    var out: [4096]u8 = undefined;
    try expectStatus(runWire(&r, req, &out), "200");
}
