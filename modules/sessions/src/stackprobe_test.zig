// SPDX-License-Identifier: MIT

//! Dead-stack probe for `Csrf.token` / `Csrf.verify` (`testkit.stackprobe`):
//! residue below each burn, and the CSRF key as a needle in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode). The token itself is public (it goes to the
//! client), so only the key is a needle.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 32 * 1024 });

var guard: root.Csrf = undefined;
var tok: [root.csrf_token_hex_len]u8 = undefined;
const session_id: []const u8 = "sess-0123456789abcdef";

test "STACKPROBE: no CSRF key residue after Csrf.token / Csrf.verify" {
    try sp.skipUnlessOptimized();
    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("sessions csrf probe key", &key, .{});
    guard = .{ .key = key };
    std.crypto.secureZero(u8, &key);
    const secrets = [_][]const u8{&guard.key};

    _ = try P.run("Csrf.token", root.Csrf.token, .{ &guard, session_id, &tok }, &secrets, .{});
    var good: [root.csrf_token_hex_len]u8 = tok;
    _ = try P.run("Csrf.verify valid", root.Csrf.verify, .{ &guard, session_id, @as([]const u8, &good) }, &secrets, .{});
    good[0] = if (good[0] == '0') '1' else '0';
    _ = try P.run("Csrf.verify forged", root.Csrf.verify, .{ &guard, session_id, @as([]const u8, &good) }, &secrets, .{});
}

// ── whole-module mutation run 2026-11-06 ────────────────────────────────────
// `CookieManager.open`/`seal`/`sessionId`/the middleware and `Csrf.check` wipe
// the plaintext of a session (id and payload) with `secureZero` in a `defer`;
// nothing measured that, so a deleted wipe went unnoticed. One end-to-end probe:
// a GET and a guarded POST of a live cookie session through `serveStream`.

const router = @import("router");
const http = @import("http");
const cookies = @import("cookies");
const cookiestore = @import("cookiestore.zig");

const P1 = sp.Probe(.{ .window = 256 * 1024, .repeats = 1 });

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

test "STACKPROBE: no session id or payload residue after serving a cookie session (open, seal, sessionId, Csrf.check)" {
    try sp.skipUnlessOptimized();
    var key: cookies.Key = undefined;
    const kb: [64]u8 = @splat(0x42);
    try cookies.Key.fromBytesInto(&key, &kb);
    const keys = [_]cookies.Key{key};
    var m = try cookiestore.CookieManager.init(.{ .io = std.testing.io, .keys = &keys });
    const csrf: root.Csrf = .{ .key = @splat(0x5A), .cookie_sessions = &m };
    var r = router.Router.init(std.testing.allocator);
    defer r.deinit();
    try r.use(m.middleware());
    try r.use(csrf.middleware());
    try r.get("/", hOk);
    try r.post("/", hOk);

    // A live session, made outside the probe.
    var s: root.Session = undefined;
    m.create(&s);
    try s.setData("probe-session-data-0123456789");
    var vbuf: [cookiestore.max_cookie_line]u8 = undefined;
    const value = try m.seal(&s, &vbuf);
    var raw_id: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw_id, s.id());
    var tokbuf: [root.csrf_token_hex_len]u8 = undefined;
    const ctok = csrf.token(s.id(), &tokbuf);

    var req_buf: [3 * 4096]u8 = undefined;
    const reqs = std.mem.print(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\nCookie: session={s}\r\n\r\nPOST / HTTP/1.1\r\nHost: t\r\nCookie: session={s}\r\nX-CSRF-Token: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{ value, value, ctok }) catch unreachable;
    var in: std.Io.Reader = .fixed(reqs);
    var out_buf: [8192]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var head: [4096]u8 = undefined;
    var request_body: [1024]u8 = undefined;
    var response_body: [1024]u8 = undefined;
    var chunk: [256]u8 = undefined;
    const secrets = [_][]const u8{ &raw_id, s.id(), s.data() };
    _ = try P1.run("serveStream cookie session", http.Server.serveStream, .{
        .{ .handler = r.handler(), .context = &r, .server_name = null },
        &in,
        &out,
        .{ .head = &head, .request_body = &request_body, .response_body = &response_body, .chunk = &chunk },
    }, &secrets, .{ .burn = false, .residue = false });
    // The POST passed the guard: both requests were answered 200.
    try std.testing.expect(std.mem.count(u8, out.buffered(), "HTTP/1.1 200") == 2);
}
