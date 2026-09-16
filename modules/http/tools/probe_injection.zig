// SPDX-License-Identifier: MIT
//
// WHAT THIS ASKS. Can a caller-supplied byte become a *new line* on the wire?
// Three entry points, one question:
//
//   A. h1 client   — CR/LF in a header name, a header value, the URL path or
//                    the query, written by `Client` onto a plain socket.
//   B. h2c -> h1   — an h2c request whose field value carries CR/LF, handed by
//                    `Server` to `proxy.ProxyHandler` and forwarded to an
//                    HTTP/1.1 backend. HPACK frames by length, so a value may
//                    hold bytes h1 can only read as framing.
//   C. h2c pseudo  — the same, through `:path` and `:authority`, plus a SPACE
//                    in `:path` (request-line confusion).
//
// WHY THIS IS A PROBE AND NOT A UNIT TEST. The subject is the bytes that leave
// the process, so the observer has to be a real peer on a real socket, and the
// h2 cases need a second and third thread (a front server and a backend) alive
// at once. `CONVENTIONS.md` §9 puts an instrument that needs threads scheduled
// inside a gate's timeout in `tools/`, not in `src/` — the module's hermetic
// half stays behind as ordinary tests.
//
// WHAT IT PRODUCES. Per case: the bytes the peer actually received, whether the
// injected needle is among them, and what the client did. Exit non-zero if a
// POSITIVE CONTROL did not reach the peer (the recorder is broken, so no other
// row is evidence) or if any needle DID reach it (a regression of the finding
// below).
//
// HISTORY, because it is the point. On 2026-09-04 every case here succeeded:
// `GET /admin` reached the peer through an h1 header value AND through the URL
// path; `:path` smuggled a whole second request through the proxy, answered 200
// to an unauthenticated h2c client (A1 G1 CRITICAL, F1/F13 HIGH). Commit
// `a4c1ab95` closed it with three guards — `h1.isToken`, `h1.isValidFieldValue`
// and `h1.isValidRequestTarget`, none of which existed before it — so today
// every case is REFUSED before a byte is written.
//
// ⚠ THE REFUSAL IS WHY THIS FILE HAD TO BE REWRITTEN TO BE RUNNABLE AT ALL.
// The audit's originals joined a recorder thread that was parked in `accept()`.
// While the guards did not exist the client always dialed, so `accept()` always
// returned. Once the client started refusing, nothing dialed — and the probes
// hung forever on the *fix*. One of them additionally let the refusal escape
// `main` through `try`, which skipped its own teardown and left a worker
// spinning over a destroyed `Server` until `req_index: u32` wrapped at 2^32 and
// panicked. A probe must be able to observe "nothing was sent"; see `wake`.
const std = @import("std");
const http = @import("http");
const net = std.Io.net;

var failures: u32 = 0;

fn fail(comptime fmt: []const u8, args: anytype) void {
    failures += 1;
    std.debug.print("  ⛔ " ++ fmt ++ "\n", args);
}

/// Accept ONE connection and keep whatever head arrives.
const Recorder = struct {
    io: std.Io,
    listener: *net.Server,
    buf: [8192]u8 = undefined,
    len: usize = 0,
    /// Answer every request so the peer is never the reason a client blocks.
    reply: []const u8 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",

    fn run(r: *Recorder) void {
        const s = r.listener.accept(r.io) catch return;
        defer s.close(r.io);
        var rbuf: [8192]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = s.reader(r.io, &rbuf);
        var sw = s.writer(r.io, &wbuf);
        while (r.len < r.buf.len) {
            const avail = sr.interface.peekGreedy(1) catch break;
            const take = @min(avail.len, r.buf.len - r.len);
            @memcpy(r.buf[r.len..][0..take], avail[0..take]);
            r.len += take;
            sr.interface.toss(take);
            if (std.mem.indexOf(u8, r.buf[0..r.len], "\r\n\r\n") != null) break;
        }
        sw.interface.writeAll(r.reply) catch {};
        sw.interface.flush() catch {};
    }
};

/// Release a recorder that is still parked in `accept()` by dialing it once and
/// closing immediately. Always safe to call: if the real connection already
/// arrived the recorder has returned, and this dial simply sits in the backlog
/// until the listener is closed.
///
/// This is the whole difference between an instrument and a hang. A refusal
/// means nothing dials; without this the probe would join a thread that can
/// never return, and "the guard worked" would look exactly like "the tool is
/// broken".
fn wake(io: std.Io, addr: net.IpAddress) void {
    const s = addr.connect(io, .{ .mode = .stream }) catch return;
    s.close(io);
}

/// ⚠ THE CONTROLS ARE JUDGED THE OTHER WAY UP. A case fails when its needle
/// REACHES the peer; a control fails when its needle does NOT. Reading both the
/// same way (the first version of this file did) reports a working control as a
/// breach and exits non-zero on a completely healthy run.
fn report(label: []const u8, rec: *const Recorder, needle: []const u8, client_said: ?[]const u8, is_control: bool) void {
    const sent = rec.buf[0..rec.len];
    const hit = std.mem.indexOf(u8, sent, needle) != null;
    std.debug.print("== {s} ==\n", .{label});
    if (client_said) |e| std.debug.print("   client refused with: {s}\n", .{e});
    if (sent.len == 0) {
        // `wake` dials this listener itself to release the recorder, so having
        // ACCEPTED a connection proves nothing. Bytes are the evidence.
        std.debug.print("   no request bytes reached the peer\n", .{});
    } else {
        std.debug.print("   --- {d} bytes reached the peer ---\n{s}\n   --- end ---\n", .{ sent.len, sent });
    }
    std.debug.print("   needle \"{s}\" on the wire: {}\n\n", .{ needle, hit });
    if (is_control) {
        if (!hit) fail("{s}: the CONTROL never reached the peer — the probe is broken, not the module", .{label});
    } else if (hit) {
        fail("{s}: the needle REACHED the peer — the guard that refuses this is gone", .{label});
    }
}

// ── A. h1 client ────────────────────────────────────────────────────────────

fn h1Case(
    gpa: std.mem.Allocator,
    io: std.Io,
    label: []const u8,
    url_suffix: []const u8,
    headers: []const http.Header,
    needle: []const u8,
    is_control: bool,
) !void {
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{});
    defer listener.deinit(io);
    const bound = listener.socket.address;

    var rec: Recorder = .{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Recorder.run, .{&rec});

    var c = http.Client.init(io, gpa, .{ .pool = .{ .enabled = false }, .total_timeout_ms = 3000 });
    defer c.deinit();
    var url_buf: [1024]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}{s}", .{ bound.getPort(), url_suffix });

    var said: ?[]const u8 = null;
    if (c.requestPlain(.get, url, .{ .headers = headers, .follow_redirects = false })) |*r| {
        var rr = r.*;
        rr.deinit();
    } else |e| {
        said = @errorName(e);
    }

    wake(io, bound);
    thread.join();

    report(label, &rec, needle, said, is_control);
}

// ── B & C. h2c in front of an h1 backend ────────────────────────────────────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

fn h2Case(
    gpa: std.mem.Allocator,
    io: std.Io,
    label: []const u8,
    path: []const u8,
    authority: []const u8,
    headers: []const http.Header,
    needle: []const u8,
    is_control: bool,
) !void {
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{});
    defer listener.deinit(io);
    const be_addr = listener.socket.address;
    var be: Recorder = .{ .io = io, .listener = &listener };
    const be_thread = try std.Thread.spawn(.{}, Recorder.run, .{&be});

    var client = http.Client.init(io, gpa, .{ .pool = .{ .enabled = false }, .total_timeout_ms = 4000 });
    defer client.deinit();
    var ph = http.proxy.ProxyHandler.init(.{
        .client = &client,
        .backend = .{ .host = "127.0.0.1", .port = be_addr.getPort() },
    });
    var server = http.Server.init(io, gpa, .{
        .handler = http.proxy.ProxyHandler.handler,
        .context = &ph,
        .enable_h2c = true,
    });
    defer server.deinit();
    try server.bind();
    const fe_port = server.boundAddress().getPort();
    const srv_thread = try std.Thread.spawn(.{}, serveWrap, .{&server});

    // A SEPARATE client for the attacker: sharing the proxy's back-side client
    // put both sides on one budget and turned every run, control included, into
    // a 504 — a hazard reported as a result.
    var atk = http.Client.init(io, gpa, .{ .pool = .{ .enabled = false }, .total_timeout_ms = 4000 });
    defer atk.deinit();

    var said: ?[]const u8 = null;
    // No `try` may escape from here on: the teardown below is what keeps this
    // program from leaving a live server behind (see the header).
    if (atk.connectH2c("127.0.0.1", fe_port, .{})) |sess| {
        if (sess.request(.get, path, .{ .authority = authority, .headers = headers })) |sid| {
            if (sess.awaitResponse(sid)) |*r| {
                var rr = r.*;
                std.debug.print("   h2 status = {d}\n", .{rr.status});
                rr.deinit(gpa);
            } else |e| said = @errorName(e);
        } else |e| said = @errorName(e);
        sess.close();
    } else |e| said = @errorName(e);

    server.shutdown();
    srv_thread.join();
    wake(io, be_addr);
    be_thread.join();

    report(label, &be, needle, said, is_control);
}

pub fn main() !void {
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg.deinit();
    const gpa = dbg.allocator();
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    std.debug.print("optimize mode (from inside the binary) = {s}\n\n", .{@tagName(@import("builtin").mode)});

    std.debug.print("── A. h1 client: does a caller byte become a line? ──\n\n", .{});
    try h1Case(gpa, io, "A0 CONTROL: a benign header", "/x", &.{.{ .name = "X-Ok", .value = "plain" }}, "X-Ok: plain", true);
    try h1Case(gpa, io, "A1: CRLF in a header VALUE", "/x", &.{
        .{ .name = "X-A", .value = "v\r\nX-Injected: yes\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\nX-End: 1" },
    }, "GET /admin", false);
    try h1Case(gpa, io, "A2: CRLF in a header NAME", "/x", &.{
        .{ .name = "X-B\r\nX-Name-Injected: yes", .value = "v" },
    }, "X-Name-Injected", false);
    try h1Case(gpa, io, "A3: CRLF in the URL PATH", "/a\r\nX-Path-Injected: yes\r\n\r\nGET /admin HTTP/1.1\r\nHost: h\r\n\r\n", &.{}, "GET /admin", false);
    try h1Case(gpa, io, "A4: CRLF in the URL QUERY", "/a?q=1\r\nX-Query-Injected: yes", &.{}, "X-Query-Injected", false);
    try h1Case(gpa, io, "A5: bare LF in a header value", "/x", &.{
        .{ .name = "X-C", .value = "v\nX-LF-Injected: yes" },
    }, "X-LF-Injected", false);

    std.debug.print("── B/C. h2c -> proxy -> h1 backend ──\n\n", .{});
    try h2Case(gpa, io, "B0 CONTROL: a benign h2c request", "/front", "front.example", &.{}, "GET /front HTTP/1.1", true);
    try h2Case(gpa, io, "B1: CRLF in an h2 field VALUE", "/front", "front.example", &.{
        .{ .name = "x-a", .value = "v\r\nX-Injected: yes\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\nX-End: 1" },
    }, "X-Injected: yes", false);
    try h2Case(gpa, io, "C1: CRLF in :path (request smuggling)", "/a\r\nX-Path-Injected: yes\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n", "front.example", &.{}, "GET /admin", false);
    try h2Case(gpa, io, "C2: CRLF in :authority", "/front", "front.example\r\nX-Authority-Injected: yes", &.{}, "X-Authority-Injected", false);
    try h2Case(gpa, io, "C3: SPACE in :path (request-line confusion)", "/a HTTP/1.1", "front.example", &.{}, "/a HTTP/1.1", false);

    if (failures != 0) {
        std.debug.print("⛔ {d} case(s) failed — see the lines above.\n", .{failures});
        std.process.exit(1);
    }
    std.debug.print("✅ every injection was refused, and both controls reached their peer.\n", .{});
}
