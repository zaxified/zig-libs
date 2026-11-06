// SPDX-License-Identifier: MIT

//! Tests of `CookieManager` (cookiestore.zig): stateless sessions in a sealed
//! or signed cookie, through the router middleware and directly.

const std = @import("std");
const router = @import("router");
const http = @import("http");
const cookies = @import("cookies");

const sessions = @import("root.zig");
const cookiestore = @import("cookiestore.zig");
const CookieManager = sessions.CookieManager;
const Session = sessions.Session;
const Clock = sessions.Clock;

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const ManualClock = struct {
    now_ns: i64 = 1_700_000_000 * std.time.ns_per_s,
    fn clock(mc: *ManualClock) Clock {
        return .{ .ctx = mc, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        const mc: *ManualClock = @ptrCast(@alignCast(ctx.?));
        return mc.now_ns;
    }
};

fn testKey(fill: u8) cookies.Key {
    var k: cookies.Key = undefined;
    const bytes: [64]u8 = @splat(fill);
    cookies.Key.fromBytesInto(&k, &bytes) catch unreachable;
    return k;
}

const Env = struct {
    clk: ManualClock = .{},
    keys: [2]cookies.Key = .{ testKey(0x11), testKey(0x22) },

    fn manager(e: *Env, o: struct {
        mode: sessions.CookieMode = .encrypted,
        idle: i64 = 0,
        absolute: i64 = 0,
        nkeys: usize = 1,
        key_from: usize = 0,
        name: []const u8 = "session",
        max_cookie_bytes: usize = cookiestore.default_max_cookie_bytes,
        id_bytes: usize = 16,
    }) !CookieManager {
        return CookieManager.init(.{
            .io = testing.io,
            .keys = e.keys[o.key_from..][0..o.nkeys],
            .mode = o.mode,
            .clock = e.clk.clock(),
            .idle_timeout_ns = o.idle,
            .absolute_timeout_ns = o.absolute,
            .cookie_name = o.name,
            .max_cookie_bytes = o.max_cookie_bytes,
            .id_bytes = o.id_bytes,
        });
    }
};

/// Seal `s` and return the cookie value (a copy into `buf`).
fn sealCopy(m: *const CookieManager, s: *Session, buf: *[cookiestore.max_cookie_line]u8) ![]const u8 {
    return m.seal(s, buf);
}

test "CookieManager: seal → open round-trips id, timestamps, remember and data in both modes" {
    var env: Env = .{};
    for ([_]sessions.CookieMode{ .encrypted, .signed }) |mode| {
        const m = try env.manager(.{ .mode = mode, .idle = 60 * std.time.ns_per_s, .absolute = 3600 * std.time.ns_per_s });
        var s: Session = undefined;
        m.create(&s);
        try s.putValue("uid", "42");
        s.rememberMe(true);
        var buf: [cookiestore.max_cookie_line]u8 = undefined;
        const v = try sealCopy(&m, &s, &buf);
        for (v) |c| try testing.expect(c > 0x20 and c < 0x7F and c != ';' and c != ',' and c != '"' and c != '\\');

        env.clk.now_ns += 5 * std.time.ns_per_s;
        var got: Session = undefined;
        try testing.expectEqual(.loaded, m.open(v, &got));
        try testing.expectEqualStrings(s.id(), got.id());
        try testing.expectEqual(s.created_ns, got.created_ns);
        try testing.expectEqual(env.clk.now_ns, got.last_seen_ns);
        try testing.expect(got.remember);
        try testing.expect(!got.is_new);
        try testing.expectEqualStrings("42", (try got.getValue("uid")).?);
        try testing.expectEqual(m.dataLimit(), got.data_limit);
    }
}

test "CookieManager: the encrypted value hides the data, the signed one shows it but refuses a change" {
    var env: Env = .{};
    const enc = try env.manager(.{});
    const sig = try env.manager(.{ .mode = .signed });
    var s: Session = undefined;
    enc.create(&s);
    try s.setData("visible-marker");

    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    const ev = try sealCopy(&enc, &s, &buf);
    var plain: [cookiestore.max_cookie_line]u8 = undefined;
    const n = std.base64.standard.Decoder.calcSizeForSlice(ev) catch unreachable;
    std.base64.standard.Decoder.decode(plain[0..n], ev) catch unreachable;
    try testing.expect(std.mem.find(u8, plain[0..n], "visible-marker") == null);

    var buf2: [cookiestore.max_cookie_line]u8 = undefined;
    const sv = try sealCopy(&sig, &s, &buf2);
    const text = sv[cookies.signed.tag_b64_len..];
    const dn = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(text) catch unreachable;
    std.base64.url_safe_no_pad.Decoder.decode(plain[0..dn], text) catch unreachable;
    try testing.expect(std.mem.find(u8, plain[0..dn], "visible-marker") != null);

    // Every single-character change of either value fails to open.
    var out: Session = undefined;
    for ([_]struct { m: *const CookieManager, v: []const u8 }{ .{ .m = &enc, .v = ev }, .{ .m = &sig, .v = sv } }) |c| {
        var t: [cookiestore.max_cookie_line]u8 = undefined;
        for (0..c.v.len) |i| {
            @memcpy(t[0..c.v.len], c.v);
            t[i] = if (t[i] == 'A') 'B' else 'A';
            try testing.expectEqual(.absent, c.m.open(t[0..c.v.len], &out));
        }
        try testing.expectEqual(.absent, c.m.open(c.v[0 .. c.v.len - 1], &out));
    }
}

test "CookieManager: a foreign key, another cookie name or the other mode does not open the value" {
    var env: Env = .{};
    const m = try env.manager(.{});
    const other_key = try env.manager(.{ .key_from = 1 });
    const other_name = try env.manager(.{ .name = "sid" });
    const signed_m = try env.manager(.{ .mode = .signed });
    var s: Session = undefined;
    m.create(&s);
    try s.setData("x");
    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    const v = try sealCopy(&m, &s, &buf);
    var out: Session = undefined;
    try testing.expectEqual(.loaded, m.open(v, &out));
    try testing.expectEqual(.absent, other_key.open(v, &out));
    try testing.expectEqual(.absent, other_name.open(v, &out));
    try testing.expectEqual(.absent, signed_m.open(v, &out));
    try testing.expectEqual(.absent, m.open("", &out));
    const long: [5000]u8 = @splat('A');
    try testing.expectEqual(.absent, m.open(&long, &out));
}

test "CookieManager: key rotation — old values open under [new, old], new values are sealed with the new key" {
    var env: Env = .{};
    const old_only = try env.manager(.{ .key_from = 1 });
    var s: Session = undefined;
    old_only.create(&s);
    try s.setData("carried");
    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    const v_old = try sealCopy(&old_only, &s, &buf);

    const rotated = try env.manager(.{ .nkeys = 2 }); // keys[0] new, keys[1] old
    const new_only = try env.manager(.{});
    var got: Session = undefined;
    try testing.expectEqual(.loaded, rotated.open(v_old, &got));
    try testing.expectEqualStrings("carried", got.data());
    var buf2: [cookiestore.max_cookie_line]u8 = undefined;
    const v_new = try sealCopy(&rotated, &got, &buf2);
    try testing.expectEqual(.loaded, new_only.open(v_new, &got));
    try testing.expectEqual(.absent, old_only.open(v_new, &got));
}

test "CookieManager: idle and absolute timeouts are inside the sealed value" {
    var env: Env = .{};
    const m = try env.manager(.{ .idle = 10 * std.time.ns_per_s, .absolute = 100 * std.time.ns_per_s });
    var s: Session = undefined;
    m.create(&s);
    try s.setData("x");
    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    var v = try sealCopy(&m, &s, &buf);
    var out: Session = undefined;

    // Exactly at the idle limit: still live. One ns past: expired.
    env.clk.now_ns += 10 * std.time.ns_per_s;
    try testing.expectEqual(.loaded, m.open(v, &out));
    env.clk.now_ns += 1;
    try testing.expectEqual(.expired, m.open(v, &out));

    // Rolling: re-sealed every 9 s, the session lives until the absolute cap.
    env.clk.now_ns = 1_700_000_000 * std.time.ns_per_s;
    m.create(&s);
    try s.setData("x");
    var t: i64 = 0;
    while (t + 9 <= 100) : (t += 9) {
        v = try sealCopy(&m, &s, &buf);
        env.clk.now_ns += 9 * std.time.ns_per_s;
        try testing.expectEqual(.loaded, m.open(v, &s));
    }
    v = try sealCopy(&m, &s, &buf);
    env.clk.now_ns += 9 * std.time.ns_per_s; // 108 s since created
    try testing.expectEqual(.expired, m.open(v, &out));
}

test "CookieManager: dataLimit is exact — the limit fits the cookie line, one byte more is refused in the handler" {
    var env: Env = .{};
    for ([_]sessions.CookieMode{ .encrypted, .signed }) |mode| {
        for ([_]usize{ 512, 1000, 3072, 4096 }) |max_line| {
            for ([_][]const u8{ "s", "session", "__Host-a-long-session-cookie-name" }) |name| {
                for ([_]usize{ 16, 32, 64 }) |id_bytes| {
                    const m = try env.manager(.{ .mode = mode, .max_cookie_bytes = max_line, .name = name, .id_bytes = id_bytes });
                    const lim = m.dataLimit();
                    try testing.expect(lim > 0 and lim <= sessions.max_session_bytes);
                    var s: Session = undefined;
                    m.create(&s);
                    var big: [sessions.max_session_bytes + 1]u8 = @splat('z');
                    try s.setData(big[0..lim]);
                    try testing.expectError(error.Overflow, s.setData(big[0 .. lim + 1]));
                    try testing.expectEqual(lim, s.data_len);

                    // The full Set-Cookie line, longest Max-Age, stays within the limit.
                    var buf: [cookiestore.max_cookie_line]u8 = undefined;
                    const v = try sealCopy(&m, &s, &buf);
                    const sc: cookies.SetCookie = .{ .name = name, .value = v, .path = "/", .max_age = std.math.minInt(i64), .secure = true, .http_only = true, .same_site = .lax };
                    var line: [8192]u8 = undefined;
                    try testing.expect((try sc.bufPrint(&line)).len <= max_line);

                    // One byte more would not have fit: the limit is tight.
                    // `seal` with the manager's own cap lifted still refuses it
                    // on the encoder's bound.
                    s.data_limit = lim + 1;
                    try s.setData(big[0 .. lim + 1]);
                    var lifted = m;
                    lifted.data_limit = sessions.max_session_bytes;
                    try testing.expectError(error.SessionTooLarge, lifted.seal(&s, &buf));
                }
            }
        }
    }
}

test "CookieManager: putValue respects the cookie's limit and leaves the session unchanged" {
    var env: Env = .{};
    const m = try env.manager(.{ .max_cookie_bytes = 512 });
    var s: Session = undefined;
    m.create(&s);
    try s.putValue("a", "1");
    const before = s.data_len;
    const huge: [600]u8 = @splat('v');
    try testing.expectError(error.Overflow, s.putValue("b", &huge));
    try testing.expectEqual(before, s.data_len);
    try testing.expectEqualStrings("1", (try s.getValue("a")).?);
}

test "CookieManager.init refuses what it cannot serve" {
    var env: Env = .{};
    try testing.expectError(error.NoKeys, CookieManager.init(.{ .io = testing.io, .keys = &.{}, .clock = env.clk.clock() }));
    try testing.expectError(error.MonotonicClock, CookieManager.init(.{ .io = testing.io, .keys = env.keys[0..1], .clock = .monotonic }));
    try testing.expectError(error.InvalidIdBytes, env.manager(.{ .id_bytes = 15 }));
    try testing.expectError(error.InvalidIdBytes, env.manager(.{ .id_bytes = 65 }));
    try testing.expectError(error.EmptyCookieName, env.manager(.{ .name = "" }));
    try testing.expectError(error.InvalidCookieOptions, env.manager(.{ .name = "a;b" }));
    try testing.expectError(error.InvalidCookieSize, env.manager(.{ .max_cookie_bytes = cookiestore.max_cookie_line + 1 }));
    try testing.expectError(error.InvalidCookieSize, env.manager(.{ .max_cookie_bytes = 100 }));
    // The default clock is wall time and is accepted.
    _ = try CookieManager.init(.{ .io = testing.io, .keys = env.keys[0..1] });
}

test "CookieManager.seal refuses a Session it did not fill" {
    var env: Env = .{};
    const m = try env.manager(.{});
    var s: Session = undefined;
    m.create(&s);
    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    s.id_len = 31;
    try testing.expectError(error.InvalidSessionId, m.seal(&s, &buf));
    s.id_len = 32;
    s.id_buf[0] = 'g';
    try testing.expectError(error.InvalidSessionId, m.seal(&s, &buf));
    m.create(&s);
    s.data_len = m.dataLimit() + 1;
    try testing.expectError(error.SessionTooLarge, m.seal(&s, &buf));
}

// ── middleware ──────────────────────────────────────────────────────────────

const App = struct {
    m: *CookieManager,
    action: enum { put_uid, read_uid, nothing, keep, revoke, regenerate, fill_headers_then_put, fill_headers_only, fill_headers_then_regenerate } = .put_uid,
};

fn handler(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    const s = sessions.sessionOf(ctx).?;
    switch (app.action) {
        .put_uid => try s.putValue("uid", "42"),
        .read_uid => {},
        .nothing => {},
        .keep => s.keep(),
        .revoke => s.revoke(),
        .regenerate => app.m.regenerate(s),
        .fill_headers_then_put, .fill_headers_only, .fill_headers_then_regenerate => {
            // Spend `http`'s 4 KiB header copy budget (Set-Cookie lines are copied).
            var filler: [4000]u8 = @splat('f');
            filler[1] = '=';
            try ctx.res.addSetCookie(&filler);
            switch (app.action) {
                .fill_headers_then_put => try s.putValue("uid", "42"),
                .fill_headers_then_regenerate => app.m.regenerate(s),
                else => {},
            }
        },
    }
    try ctx.res.writeAll(s.id());
    try ctx.res.writeAll("|");
    try ctx.res.writeAll((s.getValue("uid") catch null) orelse "-");
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [8192]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var resp_body_buf: [1024]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
    http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &resp_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn request(r: *router.Router, method: []const u8, cookie_hdr: ?[]const u8, extra: []const u8, out: []u8) []const u8 {
    var req_buf: [6000]u8 = undefined;
    const req = if (cookie_hdr) |c|
        std.mem.print(&req_buf, "{s} / HTTP/1.1\r\nHost: t\r\nCookie: {s}\r\n{s}Content-Length: 0\r\nConnection: close\r\n\r\n", .{ method, c, extra }) catch unreachable
    else
        std.mem.print(&req_buf, "{s} / HTTP/1.1\r\nHost: t\r\n{s}Content-Length: 0\r\nConnection: close\r\n\r\n", .{ method, extra }) catch unreachable;
    return runWire(r, req, out);
}

/// Every `Set-Cookie` value for `name` in the response, first one.
fn setCookie(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const prefix = "Set-Cookie: ";
        if (!std.ascii.startsWithIgnoreCase(line, prefix)) continue;
        const v = line[prefix.len..];
        if (v.len > name.len and std.mem.startsWith(u8, v, name) and v[name.len] == '=') return v;
    }
    return null;
}

fn cookieValue(sc: []const u8) []const u8 {
    const eq = std.mem.findScalar(u8, sc, '=').?;
    const rest = sc[eq + 1 ..];
    return rest[0 .. std.mem.findScalar(u8, rest, ';') orelse rest.len];
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.find(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

fn statusOf(got: []const u8) []const u8 {
    return if (got.len >= 12) got[9..12] else "";
}

test "middleware: the session travels in the cookie; same id, fresh value on every response" {
    var env: Env = .{};
    var m = try env.manager(.{ .idle = 60 * std.time.ns_per_s });
    var app: App = .{ .m = &m };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", handler);

    var o1: [8192]u8 = undefined;
    const first = request(&r, "GET", null, "", &o1);
    const sc1 = setCookie(first, "session").?;
    try testing.expect(std.mem.find(u8, sc1, "HttpOnly") != null);
    try testing.expect(std.mem.find(u8, sc1, "Secure") != null);
    try testing.expect(std.mem.find(u8, sc1, "Max-Age=60") != null);
    const body1 = bodyOf(first);
    try testing.expect(std.mem.endsWith(u8, body1, "|42"));
    const id = body1[0 .. body1.len - 3];

    app.action = .read_uid;
    var cbuf: [4200]u8 = undefined;
    const c1 = std.mem.print(&cbuf, "session={s}", .{cookieValue(sc1)}) catch unreachable;
    var o2: [8192]u8 = undefined;
    const second = request(&r, "GET", c1, "", &o2);
    const body2 = bodyOf(second);
    try testing.expectEqualStrings(id, body2[0 .. body2.len - 3]);
    try testing.expect(std.mem.endsWith(u8, body2, "|42"));
    // A loaded session is re-sealed to roll its idle window: a new value.
    const sc2 = setCookie(second, "session").?;
    try testing.expect(!std.mem.eql(u8, cookieValue(sc1), cookieValue(sc2)));
}

test "middleware: a new session nobody marked gets no cookie; keep() gets one" {
    var env: Env = .{};
    var m = try env.manager(.{});
    var app: App = .{ .m = &m, .action = .nothing };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", handler);
    var o: [8192]u8 = undefined;
    try testing.expect(setCookie(request(&r, "GET", null, "", &o), "session") == null);
    app.action = .keep;
    try testing.expect(setCookie(request(&r, "GET", null, "", &o), "session") != null);
}

test "middleware: revoke clears the cookie; the old value still opens until its timeout (documented limit)" {
    var env: Env = .{};
    var m = try env.manager(.{ .idle = 60 * std.time.ns_per_s });
    var app: App = .{ .m = &m };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", handler);
    var o1: [8192]u8 = undefined;
    const sc1 = setCookie(request(&r, "GET", null, "", &o1), "session").?;
    var cbuf: [4200]u8 = undefined;
    const c1 = std.mem.print(&cbuf, "session={s}", .{cookieValue(sc1)}) catch unreachable;

    app.action = .revoke;
    var o2: [8192]u8 = undefined;
    const sc2 = setCookie(request(&r, "GET", c1, "", &o2), "session").?;
    try testing.expect(std.mem.find(u8, sc2, "Max-Age=-1") != null);
    try testing.expectEqualStrings("", cookieValue(sc2));

    var s: Session = undefined;
    try testing.expectEqual(.loaded, m.open(cookieValue(sc1), &s));
    env.clk.now_ns += 61 * std.time.ns_per_s;
    try testing.expectEqual(.expired, m.open(cookieValue(sc1), &s));
}

test "middleware: regenerate gives a new id, keeps the data" {
    var env: Env = .{};
    var m = try env.manager(.{});
    var app: App = .{ .m = &m };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", handler);
    var o1: [8192]u8 = undefined;
    const first = request(&r, "GET", null, "", &o1);
    const id1 = bodyOf(first)[0..32];
    var cbuf: [4200]u8 = undefined;
    const c1 = std.mem.print(&cbuf, "session={s}", .{cookieValue(setCookie(first, "session").?)}) catch unreachable;
    app.action = .regenerate;
    var o2: [8192]u8 = undefined;
    const second = request(&r, "GET", c1, "", &o2);
    var s: Session = undefined;
    try testing.expectEqual(.loaded, m.open(cookieValue(setCookie(second, "session").?), &s));
    try testing.expect(!std.mem.eql(u8, id1, s.id()));
    try testing.expectEqualStrings("42", (try s.getValue("uid")).?);
}

test "middleware: a changed session whose cookie cannot be written fails the request instead of losing the write" {
    var env: Env = .{};
    var m = try env.manager(.{});
    var app: App = .{ .m = &m, .action = .fill_headers_then_put };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", handler);
    var o: [16384]u8 = undefined;
    const got = request(&r, "GET", null, "", &o);
    try testing.expect(setCookie(got, "session") == null);
    try testing.expect(!std.mem.eql(u8, statusOf(got), "200"));
}

test "Csrf.cookie_sessions: a token stays valid although the cookie value changes on every response" {
    var env: Env = .{};
    var m = try env.manager(.{ .idle = 60 * std.time.ns_per_s });
    var app: App = .{ .m = &m, .action = .keep };
    const csrf: sessions.Csrf = .{ .key = @splat(0x5A), .secure = true, .cookie_sessions = &m };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.use(csrf.middleware());
    try r.get("/", handler);
    try r.post("/", handler);

    // 1: a session cookie. 2: a GET with it gets a token (and a re-sealed cookie).
    var o1: [8192]u8 = undefined;
    const sc1 = setCookie(request(&r, "GET", null, "", &o1), "session").?;
    var cb1: [4200]u8 = undefined;
    const c1 = std.mem.print(&cb1, "session={s}", .{cookieValue(sc1)}) catch unreachable;
    app.action = .read_uid;
    var o2: [8192]u8 = undefined;
    const second = request(&r, "GET", c1, "", &o2);
    const tok = cookieValue(setCookie(second, "csrf_token").?);
    const sc2 = setCookie(second, "session").?;
    try testing.expect(!std.mem.eql(u8, cookieValue(sc1), cookieValue(sc2)));

    // 3: a POST with the NEW cookie value and the token from step 2 passes.
    var cb2: [4200]u8 = undefined;
    const c2 = std.mem.print(&cb2, "session={s}", .{cookieValue(sc2)}) catch unreachable;
    var hb: [128]u8 = undefined;
    const hdr = std.mem.print(&hb, "X-CSRF-Token: {s}\r\n", .{tok}) catch unreachable;
    var o3: [8192]u8 = undefined;
    try testing.expectEqualStrings("200", statusOf(request(&r, "POST", c2, hdr, &o3)));
    // Without the token, or with another session's cookie: 403.
    var o4: [8192]u8 = undefined;
    try testing.expectEqualStrings("403", statusOf(request(&r, "POST", c2, "", &o4)));
    var o5: [8192]u8 = undefined;
    app.action = .keep;
    const other = setCookie(request(&r, "GET", null, "", &o5), "session").?;
    var cb3: [4200]u8 = undefined;
    const c3 = std.mem.print(&cb3, "session={s}", .{cookieValue(other)}) catch unreachable;
    var o6: [8192]u8 = undefined;
    try testing.expectEqualStrings("403", statusOf(request(&r, "POST", c3, hdr, &o6)));
}

// ── delta audit 2026-11-06 (G): boundaries the tests above leave open ────────

/// Sealed value length of a session payload of `n` bytes, from `cookies`'
/// own length functions -- independent of the manager's `max_value`.
fn valueLenFor(mode: sessions.CookieMode, id_bytes: usize, n: usize) usize {
    const p = 1 + 8 + 8 + 1 + id_bytes + n;
    return switch (mode) {
        .encrypted => cookies.private.len(p),
        .signed => cookies.signed.len(std.base64.url_safe_no_pad.Encoder.calcSize(p)),
    };
}

test "CookieManager: dataLimit is not conservative -- one byte more would really overflow the cookie line" {
    var env: Env = .{};
    for ([_]sessions.CookieMode{ .encrypted, .signed }) |mode| {
        for ([_]usize{ 512, 1000, 1001, 1002, 1003, 3072, 4096 }) |max_line| {
            for ([_][]const u8{ "s", "session", "__Host-a-long-session-cookie-name" }) |name| {
                for ([_]usize{ 16, 32, 64 }) |id_bytes| {
                    const m = try env.manager(.{ .mode = mode, .max_cookie_bytes = max_line, .name = name, .id_bytes = id_bytes });
                    const sc: cookies.SetCookie = .{ .name = name, .value = "", .path = "/", .max_age = std.math.minInt(i64), .secure = true, .http_only = true, .same_site = .lax };
                    var line: [8192]u8 = undefined;
                    const bare = (try sc.bufPrint(&line)).len;
                    const lim = m.dataLimit();
                    try testing.expect(bare + valueLenFor(mode, id_bytes, lim) <= max_line);
                    try testing.expect(bare + valueLenFor(mode, id_bytes, lim + 1) > max_line);
                }
            }
        }
    }
}

test "CookieManager.init refuses a max_cookie_bytes below the bare attributes" {
    var env: Env = .{};
    for ([_]usize{ 0, 1, 20, 40 }) |n|
        try testing.expectError(error.InvalidCookieSize, env.manager(.{ .max_cookie_bytes = n }));
}

test "CookieManager: absolute timeout boundary, and a zero timeout disables each check" {
    var env: Env = .{};
    const t0 = env.clk.now_ns;
    const m = try env.manager(.{ .absolute = 100 * std.time.ns_per_s });
    var s: Session = undefined;
    m.create(&s);
    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    env.clk.now_ns = t0 + 99 * std.time.ns_per_s;
    const v = try sealCopy(&m, &s, &buf); // last_seen fresh, created t0
    var out: Session = undefined;
    env.clk.now_ns = t0 + 100 * std.time.ns_per_s;
    try testing.expectEqual(.loaded, m.open(v, &out));
    env.clk.now_ns += 1;
    try testing.expectEqual(.expired, m.open(v, &out));

    // idle = absolute = 0: neither check runs, ten years later still live.
    env.clk.now_ns = t0;
    const forever = try env.manager(.{});
    forever.create(&s);
    const v2 = try sealCopy(&forever, &s, &buf);
    env.clk.now_ns = t0 + 10 * 365 * 24 * 3600 * std.time.ns_per_s;
    try testing.expectEqual(.loaded, forever.open(v2, &out));
    // Only idle set: an old `created` does not expire it.
    env.clk.now_ns = t0;
    const idle_only = try env.manager(.{ .idle = 10 * std.time.ns_per_s });
    idle_only.create(&s);
    env.clk.now_ns = t0 + 1000 * std.time.ns_per_s;
    const v3 = try sealCopy(&idle_only, &s, &buf);
    env.clk.now_ns += 10 * std.time.ns_per_s;
    try testing.expectEqual(.loaded, idle_only.open(v3, &out));
}

test "CookieManager.seal stamps last_seen at seal time, not at load time" {
    var env: Env = .{};
    const m = try env.manager(.{ .idle = 10 * std.time.ns_per_s });
    var s: Session = undefined;
    m.create(&s);
    env.clk.now_ns += 5 * std.time.ns_per_s; // a slow handler
    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    const v = try sealCopy(&m, &s, &buf);
    env.clk.now_ns += 10 * std.time.ns_per_s; // idle measured from the seal
    var out: Session = undefined;
    try testing.expectEqual(.loaded, m.open(v, &out));
}

test "CookieManager: a payload over this manager's dataLimit does not open (a wider manager's cookie)" {
    var env: Env = .{};
    const narrow = try env.manager(.{ .max_cookie_bytes = 512 });
    const wide = try env.manager(.{ .max_cookie_bytes = 4096 });
    var s: Session = undefined;
    wide.create(&s);
    var big: [sessions.max_session_bytes]u8 = @splat('w');
    try s.setData(big[0..narrow.dataLimit()]);
    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    var out: Session = undefined;
    try testing.expectEqual(.loaded, narrow.open(try sealCopy(&wide, &s, &buf), &out));
    try s.setData(big[0 .. narrow.dataLimit() + 1]);
    try testing.expectEqual(.absent, narrow.open(try sealCopy(&wide, &s, &buf), &out));
}

test "CookieManager: a plaintext with another format version does not open" {
    var env: Env = .{};
    const m = try env.manager(.{});
    for ([_]u8{ 1, 0, 2, 0xFF }) |ver| {
        var p: [18 + 16]u8 = undefined;
        p[0] = ver;
        std.mem.writeInt(u64, p[1..9], @bitCast(env.clk.now_ns), .little);
        std.mem.writeInt(i64, p[9..17], env.clk.now_ns, .little);
        p[17] = 16;
        @memset(p[18..], 0xAB);
        var sealed: [128]u8 = undefined;
        const v = try cookies.private.seal(&env.keys[0], "session", &p, @splat(7), &sealed);
        var out: Session = undefined;
        try testing.expectEqual(@as(sessions.Manager.LoadResult, if (ver == 1) .loaded else .absent), m.open(v, &out));
    }
}

test "CookieManager.seal refuses an even id outside the hex-length bounds" {
    var env: Env = .{};
    const m = try env.manager(.{});
    var s: Session = undefined;
    m.create(&s);
    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    @memset(&s.id_buf, 'a');
    s.id_len = 30;
    try testing.expectError(error.InvalidSessionId, m.seal(&s, &buf));
    s.id_len = s.id_buf.len + 2;
    try testing.expectError(error.InvalidSessionId, m.seal(&s, &buf));
}

test "CookieManager: putValue fills the limit exactly; one byte more is Overflow" {
    var env: Env = .{};
    const m = try env.manager(.{ .max_cookie_bytes = 512 });
    var s: Session = undefined;
    m.create(&s);
    const lim = m.dataLimit();
    var v: [512]u8 = @splat('v');
    // A fresh blob: 1 format byte + [key_len][key][val_len u16][val].
    try testing.expectError(error.Overflow, s.putValue("k", v[0 .. lim - 4]));
    try s.putValue("k", v[0 .. lim - 5]);
    try testing.expectEqual(lim, s.data_len);
}

test "CookieManager.save: persist_cookie = false omits Max-Age unless rememberMe; insecure escape hatch; persisted" {
    var env: Env = .{};
    for ([_]bool{ false, true }) |remember| {
        const m = try CookieManager.init(.{ .io = testing.io, .keys = env.keys[0..1], .clock = env.clk.clock(), .persist_cookie = false, .allow_insecure_cookie = true });
        var s: Session = undefined;
        m.create(&s);
        if (remember) s.rememberMe(true);
        var out_buf: [8192]u8 = undefined;
        var out: Writer = .fixed(&out_buf);
        var body_buf: [64]u8 = undefined;
        var chunk_buf: [64]u8 = undefined;
        var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});
        try testing.expect(!s.persisted);
        try m.save(&rw, &s);
        try testing.expect(s.persisted);
        const line = rw.getHeader("Set-Cookie").?;
        try testing.expectEqual(remember, std.mem.find(u8, line, "Max-Age=") != null);
        try testing.expect(std.mem.find(u8, line, "Secure") == null);
        try testing.expect(std.mem.find(u8, line, "HttpOnly") != null);
    }
}

test "middleware: a new session that only regenerates gets a cookie; persist_untouched_sessions issues one for nothing" {
    var env: Env = .{};
    var m = try env.manager(.{});
    var app: App = .{ .m = &m, .action = .regenerate };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", handler);
    var o: [8192]u8 = undefined;
    try testing.expect(setCookie(request(&r, "GET", null, "", &o), "session") != null);

    var m2 = try CookieManager.init(.{ .io = testing.io, .keys = env.keys[0..1], .clock = env.clk.clock(), .persist_untouched_sessions = true });
    var app2: App = .{ .m = &m2, .action = .nothing };
    var r2 = router.Router.init(testing.allocator);
    defer r2.deinit();
    r2.state = &app2;
    try r2.use(m2.middleware());
    try r2.get("/", handler);
    try testing.expect(setCookie(request(&r2, "GET", null, "", &o), "session") != null);
}

test "middleware: an unchanged loaded session whose cookie does not fit is served (200); a regenerated one fails" {
    var env: Env = .{};
    var m = try env.manager(.{});
    var app: App = .{ .m = &m, .action = .keep };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.get("/", handler);
    var o1: [8192]u8 = undefined;
    const sc1 = setCookie(request(&r, "GET", null, "", &o1), "session").?;
    var cbuf: [4200]u8 = undefined;
    const c1 = std.mem.print(&cbuf, "session={s}", .{cookieValue(sc1)}) catch unreachable;

    app.action = .fill_headers_only;
    var o2: [16384]u8 = undefined;
    const kept = request(&r, "GET", c1, "", &o2);
    try testing.expectEqualStrings("200", statusOf(kept));
    try testing.expect(setCookie(kept, "session") == null);

    app.action = .fill_headers_then_regenerate;
    var o3: [16384]u8 = undefined;
    const regen = request(&r, "GET", c1, "", &o3);
    try testing.expect(setCookie(regen, "session") == null);
    try testing.expect(!std.mem.eql(u8, statusOf(regen), "200"));
}

const Outer = struct {
    marker: u8 = 0,
    seen_after: ?*anyopaque = null,
    fn run(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
        const o: *Outer = @ptrCast(@alignCast(state.?));
        ctx.data = &o.marker;
        try next.run(ctx);
        o.seen_after = ctx.data;
    }
};

test "middleware: ctx.data is restored for the outer middleware" {
    var env: Env = .{};
    var m = try env.manager(.{});
    var app: App = .{ .m = &m, .action = .keep };
    var outer: Outer = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(.{ .state = &outer, .run = Outer.run });
    try r.use(m.middleware());
    try r.get("/", handler);
    var o: [8192]u8 = undefined;
    _ = request(&r, "GET", null, "", &o);
    try testing.expectEqual(@as(?*anyopaque, &outer.marker), outer.seen_after);
}

test "Csrf.cookie_sessions: an expired session cookie gets no token on a safe request" {
    var env: Env = .{};
    var m = try env.manager(.{ .idle = 60 * std.time.ns_per_s });
    var app: App = .{ .m = &m, .action = .keep };
    const csrf: sessions.Csrf = .{ .key = @splat(0x5A), .secure = true, .cookie_sessions = &m };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &app;
    try r.use(m.middleware());
    try r.use(csrf.middleware());
    try r.get("/", handler);
    var o1: [8192]u8 = undefined;
    const sc1 = setCookie(request(&r, "GET", null, "", &o1), "session").?;
    var cb1: [4200]u8 = undefined;
    const c1 = std.mem.print(&cb1, "session={s}", .{cookieValue(sc1)}) catch unreachable;
    app.action = .read_uid;
    var o2: [8192]u8 = undefined;
    try testing.expect(setCookie(request(&r, "GET", c1, "", &o2), "csrf_token") != null); // live: a token
    env.clk.now_ns += 61 * std.time.ns_per_s;
    var o3: [8192]u8 = undefined;
    try testing.expect(setCookie(request(&r, "GET", c1, "", &o3), "csrf_token") == null); // expired: none
}

test "CookieManager.seal refuses an odd id length above the minimum" {
    var env: Env = .{};
    const m = try env.manager(.{});
    var s: Session = undefined;
    m.create(&s);
    var buf: [cookiestore.max_cookie_line]u8 = undefined;
    s.id_len = 33; // 16.5 bytes: the even-length check, not the minimum, refuses it
    try testing.expectError(error.InvalidSessionId, m.seal(&s, &buf));
}
