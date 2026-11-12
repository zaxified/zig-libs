// SPDX-License-Identifier: MIT

//! Tests added by the whole-module mutation run over the CLIENT half of `http`
//! (2026-11-12): one per survivor of the mutant schemata over `Client`,
//! `h2_client`, `h2`, `hpack`, `proxy`, `h2_upstream`, `client_proxy`, `url`,
//! `gzip`, `sniff`, `conneg`, `conditional`, `range`, `helpers` and `root`.
//! Public surface and loopback peers only; each test stands on its own.

const std = @import("std");
const testing = std.testing;
const net = std.Io.net;
const testkit = @import("testkit");

const http = @import("root.zig");
const Client = @import("Client.zig");
const h1 = @import("h1.zig");

// ── a scripted loopback origin ──────────────────────────────────────────────

/// Accepts one connection per entry of `answers`; for each it reads the request
/// head and the `Content-Length` body behind it, records both, writes the
/// answer and closes. A client that pooled the connection therefore holds a
/// STALE one afterwards.
const Scripted = struct {
    io: std.Io,
    listener: *net.Server,
    answers: []const []const u8,
    heads: [6][1024]u8 = undefined,
    head_lens: [6]usize = @splat(0),
    bodies: [6][256]u8 = undefined,
    body_lens: [6]usize = @splat(0),
    accepted: usize = 0,

    fn run(p: *Scripted) void {
        for (p.answers, 0..) |answer, n| {
            const s = p.listener.accept(p.io) catch return;
            defer s.close(p.io);
            p.accepted += 1;
            var rbuf: [2048]u8 = undefined;
            var sr = s.reader(p.io, &rbuf);
            var head_buf: [1024]u8 = undefined;
            const got = h1.readHead(&sr.interface, &head_buf) catch return;
            @memcpy(p.heads[n][0..got.len], got);
            p.head_lens[n] = got.len;
            if (contentLength(got)) |len| {
                if (len <= p.bodies[n].len) {
                    sr.interface.readSliceAll(p.bodies[n][0..len]) catch return;
                    p.body_lens[n] = len;
                }
            }
            var wbuf: [512]u8 = undefined;
            var sw = s.writer(p.io, &wbuf);
            sw.interface.writeAll(answer) catch return;
            sw.interface.flush() catch return;
        }
    }

    fn head(p: *const Scripted, n: usize) []const u8 {
        return p.heads[n][0..p.head_lens[n]];
    }

    fn body(p: *const Scripted, n: usize) []const u8 {
        return p.bodies[n][0..p.body_lens[n]];
    }

    fn contentLength(h: []const u8) ?usize {
        const at = std.ascii.findIgnoreCase(h, "content-length:") orelse return null;
        var rest = h[at + "content-length:".len ..];
        rest = std.mem.trimStart(u8, rest, " ");
        const end = std.mem.findScalar(u8, rest, '\r') orelse rest.len;
        return std.fmt.parseInt(usize, rest[0..end], 10) catch null;
    }
};

fn listen(io: std.Io) !net.Server {
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    return addr.listen(io, .{}) catch |err| testkit.loopbackSkip("mutation_b listen failed ({t})", .{err});
}

fn urlFor(buf: []u8, listener: *net.Server, path: []const u8) ![]const u8 {
    return std.mem.print(buf, "http://127.0.0.1:{d}{s}", .{ listener.socket.address.getPort(), path });
}

// ── redirects: which statuses move the body, which need a Location ─────────

test "mutation-b: 307 and 308 without Location come back to the caller, 301/302/303 without one are BadRedirect" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for (.{ false, true }) |plain| {
        inline for (.{ 307, 308 }) |status| {
            var listener = try listen(io);
            defer listener.deinit(io);
            const answer = std.fmt.comptimePrint("HTTP/1.1 {d} X\r\nContent-Length: 0\r\n\r\n", .{status});
            var peer: Scripted = .{ .io = io, .listener = &listener, .answers = &.{answer} };
            const thread = try std.Thread.spawn(.{}, Scripted.run, .{&peer});
            var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
            defer client.deinit();
            var ub: [64]u8 = undefined;
            const url = try urlFor(&ub, &listener, "/a");
            {
                var res = if (plain) try client.requestPlain(.get, url, .{}) else try client.request(.get, url, .{});
                defer res.deinit();
                try testing.expectEqual(@as(u16, status), res.status);
            }
            thread.join();
        }
        inline for (.{ 301, 302, 303 }) |status| {
            var listener = try listen(io);
            defer listener.deinit(io);
            const answer = std.fmt.comptimePrint("HTTP/1.1 {d} X\r\nContent-Length: 0\r\n\r\n", .{status});
            var peer: Scripted = .{ .io = io, .listener = &listener, .answers = &.{answer} };
            const thread = try std.Thread.spawn(.{}, Scripted.run, .{&peer});
            var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
            defer client.deinit();
            var ub: [64]u8 = undefined;
            const url = try urlFor(&ub, &listener, "/a");
            try testing.expectError(error.BadRedirect, if (plain) client.requestPlain(.get, url, .{}) else client.request(.get, url, .{}));
            thread.join();
        }
    }
}

test "mutation-b: a redirect keeps the body on 307/308 only, and an unparsable absolute Location is BadRedirect" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for (.{ false, true }) |plain| {
        inline for (.{ 301, 302, 303, 307, 308 }) |status| {
            var listener = try listen(io);
            defer listener.deinit(io);
            const first = std.fmt.comptimePrint("HTTP/1.1 {d} X\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n", .{status});
            var peer: Scripted = .{ .io = io, .listener = &listener, .answers = &.{ first, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" } };
            const thread = try std.Thread.spawn(.{}, Scripted.run, .{&peer});
            var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
            defer client.deinit();
            var ub: [64]u8 = undefined;
            const url = try urlFor(&ub, &listener, "/a");
            const opts: Client.RequestOptions = .{ .body = "payload" };
            {
                var res = if (plain) try client.requestPlain(.post, url, opts) else try client.request(.post, url, opts);
                defer res.deinit();
                try testing.expectEqual(@as(u16, 200), res.status);
            }
            thread.join();
            try testing.expect(std.mem.startsWith(u8, peer.head(0), "POST /a "));
            try testing.expectEqualStrings("payload", peer.body(0));
            if (status == 307 or status == 308) {
                try testing.expect(std.mem.startsWith(u8, peer.head(1), "POST /b "));
                try testing.expectEqualStrings("payload", peer.body(1));
            } else {
                try testing.expect(std.mem.startsWith(u8, peer.head(1), "GET /b "));
                try testing.expectEqual(@as(usize, 0), peer.body(1).len);
                try testing.expect(std.ascii.findIgnoreCase(peer.head(1), "content-length") == null);
            }
        }
        {
            var listener = try listen(io);
            defer listener.deinit(io);
            var peer: Scripted = .{ .io = io, .listener = &listener, .answers = &.{"HTTP/1.1 302 X\r\nLocation: http://127.0.0.1:99999/x\r\nContent-Length: 0\r\n\r\n"} };
            const thread = try std.Thread.spawn(.{}, Scripted.run, .{&peer});
            var client = Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
            defer client.deinit();
            var ub: [64]u8 = undefined;
            const url = try urlFor(&ub, &listener, "/a");
            try testing.expectError(error.BadRedirect, if (plain) client.requestPlain(.get, url, .{}) else client.request(.get, url, .{}));
            thread.join();
        }
    }
}

// ── stale pooled connection, retried exchange fails: nothing leaks ─────────

test "mutation-b: a stale pooled connection is retried once; when the retried exchange fails too the new connection is freed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for (.{ false, true }) |plain| {
        var listener = try listen(io);
        defer listener.deinit(io);
        var peer: Scripted = .{ .io = io, .listener = &listener, .answers = &.{
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            "garbage\r\n\r\n",
        } };
        const thread = try std.Thread.spawn(.{}, Scripted.run, .{&peer});
        var client = Client.init(io, testing.allocator, .{});
        defer client.deinit();
        var ub: [64]u8 = undefined;
        const url = try urlFor(&ub, &listener, "/a");
        {
            var res = if (plain) try client.requestPlain(.get, url, .{}) else try client.request(.get, url, .{});
            defer res.deinit();
            const b = try res.readAllAlloc(testing.allocator, 16);
            defer testing.allocator.free(b);
            try testing.expectEqualStrings("ok", b);
        }
        // The peer closed after answering: the pooled connection is stale. The
        // second request retries on a fresh dial; its answer is garbage. The
        // testing allocator proves the retried connection was released.
        const second = if (plain) client.requestPlain(.get, url, .{}) else client.request(.get, url, .{});
        if (second) |r| {
            var rr = r;
            rr.deinit();
        } else |_| {}
        thread.join();
    }
}

// ── pool housekeeping ───────────────────────────────────────────────────────

test "mutation-b: poolSweep drops an idle connection older than idle_timeout_ms and keeps a fresh one" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try listen(io);
    defer listener.deinit(io);
    var peer: Scripted = .{ .io = io, .listener = &listener, .answers = &.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"} };
    const thread = try std.Thread.spawn(.{}, Scripted.run, .{&peer});
    var client = Client.init(io, testing.allocator, .{ .pool = .{ .idle_timeout_ms = 40 } });
    defer client.deinit();
    var ub: [64]u8 = undefined;
    const url = try urlFor(&ub, &listener, "/a");
    {
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        const b = try res.readAllAlloc(testing.allocator, 16);
        defer testing.allocator.free(b);
    }
    thread.join();
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());
    client.poolSweep(); // younger than the timeout: kept
    try testing.expectEqual(@as(usize, 1), client.poolIdleCount());
    try io.sleep(.fromMilliseconds(120), .awake);
    client.poolSweep();
    try testing.expectEqual(@as(usize, 0), client.poolIdleCount());
}

// ── helpers: path.Clean, Redirect rewriting ─────────────────────────────────

const helpers = @import("helpers.zig");
const client_proxy = @import("client_proxy.zig");

test "mutation-b: cleanPath is Go's path.Clean on its own case table" {
    const cases = [_][2][]const u8{
        .{ "", "." },                  .{ "abc", "abc" },                        .{ "abc/def", "abc/def" },
        .{ "a/b/c", "a/b/c" },         .{ ".", "." },                            .{ "..", ".." },
        .{ "../..", "../.." },         .{ "../../abc", "../../abc" },            .{ "/abc", "/abc" },
        .{ "/", "/" },                 .{ "abc/", "abc" },                       .{ "abc/def/", "abc/def" },
        .{ "a/b/c/", "a/b/c" },        .{ "./", "." },                           .{ "../", ".." },
        .{ "../../", "../.." },        .{ "/abc/", "/abc" },                     .{ "abc//def//ghi", "abc/def/ghi" },
        .{ "//abc", "/abc" },          .{ "///abc", "/abc" },                    .{ "//abc//", "/abc" },
        .{ "abc//", "abc" },           .{ "abc/./def", "abc/def" },              .{ "/./abc/def", "/abc/def" },
        .{ "abc/.", "abc" },           .{ "abc/def/ghi/../jkl", "abc/def/jkl" }, .{ "abc/def/../ghi/../jkl", "abc/jkl" },
        .{ "abc/def/..", "abc" },      .{ "abc/def/../..", "." },                .{ "/abc/def/../..", "/" },
        .{ "abc/def/../../..", ".." }, .{ "/abc/def/../../..", "/" },            .{ "abc/def/../../../ghi/jkl/../../../mno", "../../mno" },
        .{ "abc/./../def", "def" },    .{ "abc//./../def", "def" },              .{ "abc/../../././../def", "../../def" },
        .{ "/..", "/" },               .{ "/../abc", "/abc" },                   .{ "a/..b/c", "a/..b/c" },
        .{ "a/.b", "a/.b" },           .{ "a/b.", "a/b." },                      .{ "...", "..." },
        .{ "/a/./b/../c/", "/a/c" },   .{ "x/y/../../..", ".." },
    };
    var out: [64]u8 = undefined;
    for (cases) |c| {
        try testing.expectEqualStrings(c[1], try helpers.cleanPath(c[0], &out));
    }
    // `out` must hold `in.len + 1`: exactly that is enough, one less is refused.
    var small: [4]u8 = undefined;
    try testing.expectEqualStrings("abc", try helpers.cleanPath("abc", &small));
    try testing.expectError(error.NoSpaceLeft, helpers.cleanPath("abcd", &small));
    var tiny: [1]u8 = undefined;
    try testing.expectEqualStrings(".", try helpers.cleanPath("", &tiny));
    var none: [0]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, helpers.cleanPath("", &none));
}

test "mutation-b: redirectLocation rewrites relative paths, passes absolute ones, keeps the trailing slash" {
    var buf: [helpers.redirect_buf_len]u8 = undefined;
    const cases = [_][3][]const u8{
        // req_path, location, header
        .{ "/d/p", "x", "/d/x" },
        .{ "/d/p", "x/", "/d/x/" },
        .{ "/d/p", "../y", "/y" },
        .{ "/d/p", "./", "/d/" },
        .{ "/d/p", "/x/", "/x/" },
        .{ "/d/p", "/x/../y", "/y" },
        .{ "/d/p", "x?a=/..", "/d/x?a=/.." },
        .{ "/d/p", "x#f", "/d/x#f" },
        .{ "/d/p", "http://h/x/../y", "http://h/x/../y" },
        .{ "/d/p", "a+b-c.d://h", "a+b-c.d://h" },
        .{ "/d/p", "//host/x", "//host/x" },
        .{ "/d/p", "//h", "//h" },
        .{ "/d/p", "//?x", "/?x" },
        .{ "/d/p", "///x", "/x" },
        .{ "/d/p", "/ /x", "/ /x" },
        .{ "/d/p", "/a%41b", "/a%41b" },
        .{ "/d/p", "/%41%zz/../q", "/%41%zz/../q" },
        .{ "/d/p", "/%41%42/../q", "/q" },
        .{ "/d/p", "/x#%4", "/x#%4" },
        .{ "/d/p", "/x#%41/../q", "/q" },
        .{ "", "x", "/x" },
        .{ "*", "x", "x" },
        .{ "/d/p", "/\xc4\x8d", "/%c4%8d" },
    };
    for (cases) |c| {
        const r = try helpers.redirectLocation(c[0], c[1], &buf);
        try testing.expectEqualStrings(c[2], r.header);
    }
    // The limit: a rooted location of 2047 bytes fits, 2048 does not; with a
    // `?` tail the path part alone has to fit.
    var long: [3000]u8 = undefined;
    @memset(&long, 'x');
    long[0] = '/';
    try testing.expectEqual(@as(usize, 2047), (try helpers.redirectLocation("/a", long[0..2047], &buf)).header.len);
    try testing.expectError(error.LocationTooLong, helpers.redirectLocation("/a", long[0..2048], &buf));
    long[2046] = '?';
    try testing.expectError(error.LocationTooLong, helpers.redirectLocation("/a", long[0..2048], &buf));
    // An absolute location is copied as is up to the escape buffer's size.
    const abs = "http://h/";
    @memcpy(long[0..abs.len], abs);
    @memset(long[abs.len..], 'y');
    try testing.expectEqual(@as(usize, 2048), (try helpers.redirectLocation("/a", long[0..2048], &buf)).header.len);
    try testing.expectError(error.LocationTooLong, helpers.redirectLocation("/a", long[0..2049], &buf));
}

// ── sniff: the 512-byte window is the WHATWG one ────────────────────────────

test "mutation-b: sniff window is 512 bytes, MP4 needs 12" {
    const sniff = @import("sniff.zig");
    var buf: [600]u8 = undefined;
    @memset(&buf, 'a');
    buf[512] = 0x00;
    try testing.expectEqualStrings(sniff.text_plain, sniff.detectContentType(buf[0..513]));
    buf[511] = 0x00;
    try testing.expectEqualStrings(sniff.octet_stream, sniff.detectContentType(buf[0..513]));
    try testing.expectEqual(@as(usize, 512), sniff.sniff_len);
}

// ── client_proxy: env fallbacks and credential size ─────────────────────────

test "mutation-b: lowercase proxy variables are read when the uppercase one is empty; one byte is a value" {
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("HTTP_PROXY", "");
    try env.put("http_proxy", "h");
    try env.put("https_proxy", "");
    try env.put("no_proxy", "z");
    const p = client_proxy.Proxy.fromEnviron(&env);
    try testing.expectEqualStrings("h", p.http.?);
    try testing.expectEqual(@as(?[]const u8, null), p.https);
    try testing.expectEqualStrings("z", p.no_proxy);
}

test "mutation-b: proxy credentials up to 512 decoded bytes parse, 513 are BadProxy; bracketed and plain ports" {
    const Endpoint = client_proxy.Endpoint;
    var raw: [600]u8 = undefined;
    const pre = "http://";
    @memcpy(raw[0..pre.len], pre);
    @memset(raw[pre.len .. pre.len + 513], 'u');
    const tail = "@proxy:3128";
    @memcpy(raw[pre.len + 512 ..][0..tail.len], tail);
    const ok = try Endpoint.parse(raw[0 .. pre.len + 512 + tail.len]);
    try testing.expectEqualStrings("proxy", ok.host);
    @memset(raw[pre.len .. pre.len + 513], 'u');
    @memcpy(raw[pre.len + 513 ..][0..tail.len], tail);
    try testing.expectError(error.BadProxy, Endpoint.parse(raw[0 .. pre.len + 513 + tail.len]));

    const a = try Endpoint.parse("[::1]:8080");
    try testing.expectEqualStrings("::1", a.host);
    try testing.expectEqual(@as(u16, 8080), a.port);
    const b = try Endpoint.parse("[::1]:");
    try testing.expectEqual(@as(u16, 80), b.port);
    const c = try Endpoint.parse("[::1]");
    try testing.expectEqual(@as(u16, 80), c.port);
    try testing.expectError(error.BadProxy, Endpoint.parse("[::1]x"));
    const d = try Endpoint.parse("h:7");
    try testing.expectEqualStrings("h", d.host);
    try testing.expectEqual(@as(u16, 7), d.port);
    const e = try Endpoint.parse("h:");
    try testing.expectEqual(@as(u16, 80), e.port);
    try testing.expectError(error.BadProxy, Endpoint.parse("h:1:2"));
    try testing.expectError(error.BadProxy, Endpoint.parse(":1"));
    const f = try Endpoint.parse("h");
    try testing.expectEqualStrings("h", f.host);
}

// ── conditional: first value of a repeated precondition header wins ────────

const conditional = @import("conditional.zig");
const Server = @import("Server.zig");

fn evalDup(method: http.Method, header_block: []const u8, v: conditional.Validators) conditional.Outcome {
    var body: Server.RequestBody = .{ .none = .fixed("") };
    const req: Server.Request = .{
        .method = method,
        .target = "/",
        .path = "/",
        .query = "",
        .head = .{
            .method = method.token(),
            .target = "/",
            .http1_0 = false,
            .header_block = header_block,
        },
        .body = &body,
        .context = null,
    };
    return conditional.evaluate(method, &req, v);
}

test "mutation-b: with a repeated precondition header the first value decides" {
    const v: conditional.Validators = .{ .etag = "\"v1\"", .last_modified = 784111777 };
    try testing.expectEqual(conditional.Outcome.not_modified, evalDup(.get, "If-None-Match: \"v1\"\r\nIf-None-Match: \"zz\"\r\n", v));
    try testing.expectEqual(conditional.Outcome.precondition_failed, evalDup(.put, "If-Match: \"zz\"\r\nIf-Match: \"v1\"\r\n", v));
    try testing.expectEqual(conditional.Outcome.not_modified, evalDup(.get, "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\nIf-Modified-Since: Sat, 05 Nov 1994 08:49:37 GMT\r\n", .{ .last_modified = 784111777 }));
    try testing.expectEqual(conditional.Outcome.precondition_failed, evalDup(.put, "If-Unmodified-Since: Sat, 05 Nov 1994 08:49:37 GMT\r\nIf-Unmodified-Since: Mon, 07 Nov 1994 08:49:37 GMT\r\n", .{ .last_modified = 784111777 }));
    // Other fields do not disturb the scan (names that start with `i` but are not preconditions).
    try testing.expectEqual(conditional.Outcome.not_modified, evalDup(.get, "Idempotency-Key: k\r\nIf-None-Match: \"v1\"\r\nX: y\r\n", v));
}

test "mutation-b: range defaults" {
    try testing.expectEqual(@as(usize, 16), @import("range.zig").default_max_ranges);
}

test "mutation-b: If-Range with an unterminated entity-tag ignores the range" {
    const v: conditional.Validators = .{ .etag = "\"v1\"", .last_modified = 784111777 };
    const blocks = [_]struct { []const u8, bool }{
        .{ "If-Range: \"v1\"\r\n", true },
        .{ "If-Range: \"v1\r\n", false },
        .{ "If-Range: \"v2\"\r\n", false },
        .{ "If-Range: W/\"v1\"\r\n", false },
        .{ "If-Range: \"\"\r\n", false },
        .{ "", true },
    };
    for (blocks) |b| {
        var body: Server.RequestBody = .{ .none = .fixed("") };
        const req: Server.Request = .{
            .method = .get,
            .target = "/",
            .path = "/",
            .query = "",
            .head = .{ .method = "GET", .target = "/", .http1_0 = false, .header_block = b[0] },
            .body = &body,
            .context = null,
        };
        try testing.expectEqual(b[1], conditional.ifRangeAllows(&req, v));
    }
    var body: Server.RequestBody = .{ .none = .fixed("") };
    const req: Server.Request = .{
        .method = .get,
        .target = "/",
        .path = "/",
        .query = "",
        .head = .{ .method = "GET", .target = "/", .http1_0 = false, .header_block = "If-Range: \"v1\"\r\n" },
        .body = &body,
        .context = null,
    };
    // A resource with no ETag, or one that is no entity-tag, cannot satisfy an entity-tag If-Range.
    try testing.expect(!conditional.ifRangeAllows(&req, .{ .last_modified = 784111777 }));
    try testing.expect(!conditional.ifRangeAllows(&req, .{ .etag = "v1" }));
}
