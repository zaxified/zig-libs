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
const burn = @import("burn.zig");
const idhex = @import("idhex.zig");

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
        return burn.run(burn.csrf_burn, []const u8, tokenBody, .{ c, session_id, out });
    }

    fn tokenBody(c: *const Csrf, session_id: []const u8, out: *[token_hex_len]u8) []const u8 {
        var mac: [mac_length]u8 = undefined;
        Hmac.create(&mac, session_id, &c.key);
        // Not `std.fmt.bytesToHex`: it indexes a table by the secret nibble
        // (8 memcheck contexts here, ctgrind `sessions/csrf`, 2026-10-09).
        idhex.encode(out, &mac);
        return out;
    }

    /// Whether `presented_tok` is a valid token for `session_id`. Decodes both
    /// to raw MACs and compares with `std.crypto.timing_safe.eql` — never
    /// `std.mem.eql`. A wrong length or non-hex token is rejected (false).
    pub fn verify(c: *const Csrf, session_id: []const u8, presented_tok: []const u8) bool {
        return burn.run(burn.csrf_burn, bool, verifyBody, .{ c, session_id, presented_tok });
    }

    fn verifyBody(c: *const Csrf, session_id: []const u8, presented_tok: []const u8) bool {
        if (presented_tok.len != token_hex_len) return false; // length is public
        // Not `std.fmt.hexToBytes`: it branches on each character's class,
        // and a legitimate presented token IS the secret token (6 memcheck
        // contexts here, ctgrind `sessions/csrf`, 2026-10-09). The validity
        // bit is folded in after the compare, not branched on before it.
        var got: [mac_length]u8 = undefined;
        const hex_ok = idhex.decode(&got, presented_tok);
        var want: [mac_length]u8 = undefined;
        Hmac.create(&want, session_id, &c.key);
        const mac_ok = std.crypto.timing_safe.eql([mac_length]u8, want, got);
        return (@intFromBool(mac_ok) & hex_ok) == 1;
    }

    /// The token presented on `req`: the header value first, then the
    /// query-parameter fallback. Both trimmed; empty counts as absent. Public
    /// so a caller driving the core `Csrf`/`sessions` API directly — without
    /// `router`'s `middleware` — can extract the token the same way the
    /// middleware does instead of copying this logic (requested for qap
    /// M11.4, 2026-09-27: qap's own `src/sessions.zig` had a private
    /// `presentedToken` duplicate). `middlewareRun` and `check` both call this
    /// one implementation, so they cannot drift apart.
    pub fn presented(c: *const Csrf, req: *const http.Server.Request) ?[]const u8 {
        if (req.header(c.header_name)) |v| {
            const t = std.mem.trim(u8, v, " \t");
            if (t.len != 0) return t;
        }
        if (queryValue(req.query, c.form_field)) |v| {
            if (v.len != 0) return v;
        }
        return null;
    }

    /// The whole CSRF guard, minus the middleware's 403 response: true iff
    /// `req` carries a session cookie AND a presented token (`presented`,
    /// above) AND that token `verify`s against the session id — the exact
    /// three conditions `middlewareRun` requires before letting a guarded
    /// method through, evaluated here through the same `presented`/`verify`
    /// calls so the two can never disagree (`middlewareRun` calls `check`
    /// itself, see below).
    ///
    /// **Does not apply the middleware's safe-method exemption** — `check`
    /// never looks at `req.method`, so it does not treat GET/HEAD as
    /// automatically valid. That is the deliberate choice: a caller reaching
    /// for `check` directly (bypassing the middleware, e.g. from a
    /// hidden-form-field handler) is asking "is this a valid token for this
    /// session", full stop, for whatever method the request actually used —
    /// silently returning `true` for a method the caller never asked to
    /// exempt would be the surprising behaviour. The middleware supplies the
    /// method exemption itself, by only calling `check` for the methods in
    /// `c.methods` (see `middlewareRun`); safe methods take a separate path
    /// (no token required, a fresh one issued instead).
    pub fn check(c: *const Csrf, req: *const http.Server.Request) bool {
        const session_id = cookies.get(req, c.session_cookie) orelse return false;
        const presented_tok = c.presented(req) orelse return false;
        return c.verify(session_id, presented_tok);
    }

    /// A `router.Middleware` enforcing the guard. Place it after the sessions
    /// middleware (it reads the session cookie); the Csrf must outlive the
    /// Router, at a stable address. A token is issued only once the request
    /// carries a session cookie, and the sessions middleware issues one only
    /// for a session the handler marked — a pre-auth form page calls
    /// `Session.keep()` so its visitor gets a cookie, then a token.
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
        // addSetCookie copies the bytes into the writer's own header_buf
        // before returning, so this local only has to outlive the call.
        var cookie_buf: [256]u8 = undefined;
        const v = sc.bufPrint(&cookie_buf) catch return;
        // Best-effort across the whole of `SetHeaderError` (which now also
        // carries `HeaderBytesExhausted`), and it fails CLOSED: with no token
        // cookie the client cannot echo a token, so the guarded methods are
        // REJECTED rather than let through. A dropped token costs a retry,
        // never a bypass.
        res.addSetCookie(v) catch {};
    }
};

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const c: *const Csrf = @ptrCast(@alignCast(state.?));

    // Guarded method: the whole decision is `check` (session cookie +
    // presented token + verify) — this is the one call site, so the
    // middleware and `Csrf.check` can never drift apart.
    if (guarded(c.methods, ctx.req.method)) {
        if (!c.check(ctx.req)) return forbidden(ctx);
        return next.run(ctx);
    }

    // Safe method: run, then hand back a fresh token to echo next time.
    try next.run(ctx);
    if (c.issue_on_safe) {
        if (cookies.get(ctx.req, c.session_cookie)) |session_id| c.issue(ctx.res, session_id);
    }
}

fn guarded(methods: []const http.Method, m: http.Method) bool {
    for (methods) |g| {
        if (g == m) return true;
    }
    return false;
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

/// The handler/middleware half of the dead-frame test below: issue a token
/// cookie for a fixed session id and return. `Csrf.issue` formats the raw
/// HMAC into a stack `hexbuf`, builds the `Set-Cookie` value into a stack
/// `cookie_buf`, and hands the result to `addSetCookie` — both buffers live
/// only inside `issue`'s own frame, which mirrors how `middlewareRun` calls
/// `c.issue(ctx.res, session_id)` on the trailing side of `next.run`, i.e.
/// after the handler has already returned.
///
/// A separate `noinline` function, not a block inside the test: Zig gives
/// each local its own slot for the enclosing function's entire body in
/// Debug, so a block scope frees nothing and a borrowed-slice bug would stay
/// invisible. Only a returned frame is really reusable. Mirrors `http`'s
/// `setFromDeadFrame` and `cookies`'s.
noinline fn setFromDeadFrame(c: *const Csrf, res: *http.Server.ResponseWriter) void {
    c.issue(res, "sess-dead-frame");
}

/// Reuse the frame `setFromDeadFrame` just left, the way the next call down
/// the stack would have. Bigger than `setFromDeadFrame` PLUS `issue` nested
/// under it; `noinline` + `doNotOptimizeAway` so neither the call nor the
/// stores can be optimized out.
noinline fn clobberDeadFrame() void {
    var scratch: [4096]u8 = undefined;
    @memset(&scratch, '#');
    std.mem.doNotOptimizeAway(&scratch);
}

test "Csrf.issue: the token Set-Cookie survives issue's dead frame" {
    // What this pins: `addSetCookie` (like `setHeader`) copies its bytes into
    // the response writer's own `header_buf` at call time — see `http`'s
    // `ResponseWriter.dupe`. Without that copy, the token `issue` computes
    // and formats would be a borrowed slice into a frame that is gone by the
    // time `end()` runs: `writeHead` runs inside `end()`, and both servers
    // call `end()` AFTER `middlewareRun` (where `c.issue` is called from) has
    // already returned. Reproduced here with no server at all:
    // `setFromDeadFrame` IS `middlewareRun`'s trailing half, and the clobber
    // is what the next stack user would have written over it.
    var out_buf: [1024]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    const c = Csrf{ .key = @splat(0x99) };
    setFromDeadFrame(&c, &rw);
    clobberDeadFrame();

    try rw.writeAll("ok");
    try rw.end();
    const wire = out.buffered();

    // The exact expected token, computed independently (not read off the
    // dead frame), read back off the wire after every byte of its source was
    // overwritten.
    var want: [token_hex_len]u8 = undefined;
    const expect_tok = c.token("sess-dead-frame", &want);
    var expect_line_buf: [256]u8 = undefined;
    const expect_line = std.fmt.bufPrint(&expect_line_buf, "Set-Cookie: csrf_token={s}; Path=/; Secure; SameSite=Lax\r\n", .{expect_tok}) catch unreachable;
    try testing.expect(std.mem.indexOf(u8, wire, expect_line) != null);
    // …and not one byte of the clobber pattern anywhere on it.
    try testing.expect(std.mem.indexOf(u8, wire, "#") == null);
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

test "middleware: issue_on_safe = false suppresses the token cookie on safe GET" {
    // Regression: `issue_on_safe` was read but nothing exercised the false
    // branch -- a mutation that always issued the cookie regardless of the
    // flag stayed green.
    const c = Csrf{ .key = @splat(0x55), .issue_on_safe = false };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try makeRouter(&r, &c);

    var out: [4096]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nCookie: session=abc123\r\nConnection: close\r\n\r\n", &out);
    try expectStatus(got, "200");
    try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "Set-Cookie"));
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

// ── Csrf.presented / Csrf.check (public core API) ──────────────────────────
//
// These handlers reach the `Csrf` under test through `ctx.state` (the
// Router's application-state slot), the same way a real app's routes would,
// rather than through the middleware -- `presented`/`check` are meant to be
// usable by a caller who is NOT running `Csrf.middleware` at all.

fn hReportPresented(ctx: *router.Ctx) anyerror!void {
    const c: *const Csrf = @ptrCast(@alignCast(ctx.state.?));
    if (c.presented(ctx.req)) |p| {
        try ctx.res.writeAll(p);
    } else {
        try ctx.res.writeAll("<absent>");
    }
}

fn hReportCheck(ctx: *router.Ctx) anyerror!void {
    const c: *const Csrf = @ptrCast(@alignCast(ctx.state.?));
    try ctx.res.writeAll(if (c.check(ctx.req)) "true" else "false");
}

test "Csrf.presented: header, query fallback, header wins, absent" {
    const c = Csrf{ .key = @splat(0x66) };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = @constCast(&c);
    try r.get("/p", hReportPresented);

    var out1: [4096]u8 = undefined;
    const header_only = runWire(&r, "GET /p HTTP/1.1\r\nHost: t\r\nX-CSRF-Token: from-header\r\nConnection: close\r\n\r\n", &out1);
    try testing.expect(std.mem.endsWith(u8, header_only, "from-header"));

    var out2: [4096]u8 = undefined;
    const query_only = runWire(&r, "GET /p?csrf_token=from-query HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out2);
    try testing.expect(std.mem.endsWith(u8, query_only, "from-query"));

    // Both present -> header wins (matches presentedToken's original order).
    var out3: [4096]u8 = undefined;
    const both = runWire(&r, "GET /p?csrf_token=from-query HTTP/1.1\r\nHost: t\r\nX-CSRF-Token: from-header\r\nConnection: close\r\n\r\n", &out3);
    try testing.expect(std.mem.endsWith(u8, both, "from-header"));

    var out4: [4096]u8 = undefined;
    const absent = runWire(&r, "GET /p HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out4);
    try testing.expect(std.mem.endsWith(u8, absent, "<absent>"));
}

test "Csrf.check: false on missing cookie, false on wrong token, true on the right one" {
    const c = Csrf{ .key = @splat(0x77) };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = @constCast(&c);
    try r.get("/c", hReportCheck);

    var buf: [token_hex_len]u8 = undefined;
    const tok = c.token("sess1", &buf);

    // A valid-looking token but no session cookie at all -> false.
    const req1 = try std.fmt.allocPrint(testing.allocator, "GET /c HTTP/1.1\r\nHost: t\r\nX-CSRF-Token: {s}\r\nConnection: close\r\n\r\n", .{tok});
    defer testing.allocator.free(req1);
    var out1: [4096]u8 = undefined;
    try testing.expect(std.mem.endsWith(u8, runWire(&r, req1, &out1), "false"));

    // Session cookie present, but the token does not verify -> false.
    var out2: [4096]u8 = undefined;
    const wrong_token = runWire(&r, "GET /c HTTP/1.1\r\nHost: t\r\nCookie: session=sess1\r\nX-CSRF-Token: " ++ ("0" ** token_hex_len) ++ "\r\nConnection: close\r\n\r\n", &out2);
    try testing.expect(std.mem.endsWith(u8, wrong_token, "false"));

    // Session cookie + the matching token -> true.
    const req3 = try std.fmt.allocPrint(testing.allocator, "GET /c HTTP/1.1\r\nHost: t\r\nCookie: session=sess1\r\nX-CSRF-Token: {s}\r\nConnection: close\r\n\r\n", .{tok});
    defer testing.allocator.free(req3);
    var out3: [4096]u8 = undefined;
    try testing.expect(std.mem.endsWith(u8, runWire(&r, req3, &out3), "true"));
}

/// Runs only if `middlewareRun`'s guarded branch already decided `c.check`
/// was true for this exact `ctx.req` -- asserting it again here from inside
/// the handler pins that the two can never disagree, since `middlewareRun`
/// calls the very same `check` (see the middleware source) rather than a
/// second, independently-written copy of the guard logic.
fn hOkAndCheckAgrees(ctx: *router.Ctx) anyerror!void {
    const c: *const Csrf = @ptrCast(@alignCast(ctx.state.?));
    try testing.expect(c.check(ctx.req));
    try ctx.res.writeAll("ok");
}

test "middleware and Csrf.check agree: a request the middleware lets through also passes check" {
    const c = Csrf{ .key = @splat(0x88) };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = @constCast(&c);
    try r.use(c.middleware());
    try r.post("/", hOkAndCheckAgrees);

    var buf: [token_hex_len]u8 = undefined;
    const tok = c.token("sess-agree", &buf);
    const req = try std.fmt.allocPrint(testing.allocator, "POST / HTTP/1.1\r\nHost: t\r\nCookie: session=sess-agree\r\nX-CSRF-Token: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{tok});
    defer testing.allocator.free(req);
    var out: [4096]u8 = undefined;
    const got = runWire(&r, req, &out);
    try expectStatus(got, "200");
    try testing.expect(std.mem.endsWith(u8, got, "ok"));
}

test "middleware and Csrf.check agree: a request the middleware 403s also fails check" {
    const c = Csrf{ .key = @splat(0x99) };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = @constCast(&c);
    try r.use(c.middleware());
    try r.post("/", hOk);
    // Same Csrf/session shape, reached through a SAFE (unguarded) method so
    // the handler runs and can report `check` directly on an otherwise
    // identical request -- no token presented, same session cookie.
    try r.get("/check-mirror", hReportCheck);

    var out_post: [4096]u8 = undefined;
    const denied = runWire(&r, "POST / HTTP/1.1\r\nHost: t\r\nCookie: session=sess-deny\r\nConnection: close\r\n\r\n", &out_post);
    try expectStatus(denied, "403");

    var out_get: [4096]u8 = undefined;
    const mirrored = runWire(&r, "GET /check-mirror HTTP/1.1\r\nHost: t\r\nCookie: session=sess-deny\r\nConnection: close\r\n\r\n", &out_get);
    try testing.expect(std.mem.endsWith(u8, mirrored, "false"));
}

// ── audit 2026-10-04: tests asked for by mutation survivors ──────────────────

test "verify: a non-hex character that decodes to the right nibble is still rejected" {
    // `idhex.decode` maps an invalid character to 0 and reports it only in
    // its validity bit, so the MAC compare alone would accept a valid token
    // whose `0` digit is replaced by any non-hex byte. The bit must count.
    var key: [32]u8 = @splat(0x30);
    var buf: [token_hex_len]u8 = undefined;
    const at = while (true) : (key[0] +%= 1) {
        const tok = (Csrf{ .key = key }).token("sid", &buf);
        if (std.mem.indexOfScalar(u8, tok, '0')) |i| break i;
    };
    const c = Csrf{ .key = key };
    try testing.expect(c.verify("sid", &buf)); // control
    for ("gz G/:@`\x00\xff") |bad| {
        var forged = buf;
        forged[at] = bad;
        try testing.expect(!c.verify("sid", &forged));
    }
}

test "verify: a token must be exactly 64 hex digits — a prefix of the right one fails" {
    // `verify` doc: "A wrong length or non-hex token is rejected". The raw MAC
    // is 32 octets; a shorter hex string would leave the rest of the decode
    // buffer unset and compare whatever it held.
    const c = Csrf{ .key = @splat(0x21) };
    var buf: [token_hex_len]u8 = undefined;
    const tok = c.token("sid", &buf);
    try testing.expect(c.verify("sid", tok)); // control
    try testing.expect(!c.verify("sid", tok[0 .. tok.len - 2]));
    try testing.expect(!c.verify("sid", tok[0..2]));
}

test "Csrf.presented: an empty header falls back to the query; an empty or look-alike query is absent" {
    // `presented` doc: header first, then the query parameter; "both
    // trimmed; empty counts as absent". The parameter is matched by its
    // exact name, so `csrf_tokenx` is a different parameter.
    const c = Csrf{ .key = @splat(0x67) };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = @constCast(&c);
    try r.get("/p", hReportPresented);

    var out1: [4096]u8 = undefined;
    const blank_header = runWire(&r, "GET /p?csrf_token=from-query HTTP/1.1\r\nHost: t\r\nX-CSRF-Token:   \r\nConnection: close\r\n\r\n", &out1);
    try testing.expect(std.mem.endsWith(u8, blank_header, "from-query"));
    var out2: [4096]u8 = undefined;
    const empty_query = runWire(&r, "GET /p?csrf_token= HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out2);
    try testing.expect(std.mem.endsWith(u8, empty_query, "<absent>"));
    var out3: [4096]u8 = undefined;
    const look_alike = runWire(&r, "GET /p?csrf_tokenx=abc HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out3);
    try testing.expect(std.mem.endsWith(u8, look_alike, "<absent>"));
}

test "Csrf.check: no session cookie is false even with the token an empty session id would have" {
    // `check` doc: true iff the request carries a session cookie AND a token
    // that verifies against it. A missing cookie is not the empty id.
    const c = Csrf{ .key = @splat(0x78) };
    var buf: [token_hex_len]u8 = undefined;
    const tok_for_empty = c.token("", &buf);
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = @constCast(&c);
    try r.get("/c", hReportCheck);
    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET /c HTTP/1.1\r\nHost: t\r\nX-CSRF-Token: {s}\r\nConnection: close\r\n\r\n", .{tok_for_empty});
    var out: [4096]u8 = undefined;
    try testing.expect(std.mem.endsWith(u8, runWire(&r, req, &out), "false"));
}
