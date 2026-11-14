// SPDX-License-Identifier: MIT

//! The publishers' wire: what each one sends (request line, headers, body,
//! RFC 2136 message, argv) and how each reads the answer, against a recording
//! HTTP peer, a UDP update server and small shell scripts on loopback.
//! Before 2026-11-14 only the live interop pinned any of it.

const std = @import("std");
const testkit = @import("testkit");
const dns = @import("dns");
const netaddr = @import("netaddr");
const root = @import("root.zig");
const publishers = @import("publishers.zig");

const testing = std.testing;
const net = std.Io.net;

const value = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";

const rec: root.Record = .{
    .domain = "a.test",
    .fqdn = "_acme-challenge.a.test.",
    .zone = "a.test",
    .value = value,
    .token = "tok",
    .key_authorization = "tok.thumb",
};

fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Clock.Timestamp.now(io, .awake);
    return @intCast(@divTrunc(ts.raw.nanoseconds, std.time.ns_per_ms));
}

// ── HTTP peer ───────────────────────────────────────────────────────────────

/// Serves `serve` connections, one request each: records the request (head and
/// body) lowercased, answers `status` with `body` (and `Location`), closes.
const Peer = struct {
    io: std.Io,
    listener: net.Server,
    thread: ?std.Thread = null,
    serve: u32 = 1,
    status: u16 = 200,
    body: []const u8 = "",
    location: []const u8 = "",
    /// Everything received, lowercased, requests back to back.
    log: [16384]u8 = undefined,
    log_len: usize = 0,
    requests: std.atomic.Value(u32) = .init(0),
    done: bool = false,
    stop: std.atomic.Value(u32) = .init(0),
    connected: std.atomic.Value(u32) = .init(0),

    fn start(p: *Peer, io: std.Io) !void {
        p.io = io;
        const addr = try net.IpAddress.parse("127.0.0.1", 0);
        p.listener = addr.listen(io, .{}) catch |err| return testkit.loopbackSkip("listen failed ({t})", .{err});
        errdefer p.listener.deinit(io);
        p.thread = try std.Thread.spawn(.{}, run, .{p});
    }

    fn port(p: *const Peer) u16 {
        return p.listener.socket.address.getPort();
    }

    fn url(p: *const Peer, buf: []u8, path: []const u8) ![]const u8 {
        return std.mem.print(buf, "http://127.0.0.1:{d}{s}", .{ p.port(), path });
    }

    fn run(p: *Peer) void {
        var n: u32 = 0;
        while (n < p.serve and p.stop.load(.acquire) == 0) : (n += 1) {
            const s = p.listener.accept(p.io) catch return;
            _ = p.connected.fetchAdd(1, .monotonic);
            defer s.close(p.io);
            p.handle(s) catch {};
        }
    }

    fn handle(p: *Peer, s: net.Stream) !void {
        var rbuf: [4096]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = s.reader(p.io, &rbuf);
        var sw = s.writer(p.io, &wbuf);
        var content_length: usize = 0;
        var head_lines: usize = 0;
        while (head_lines < 100) : (head_lines += 1) {
            const line = try sr.interface.takeDelimiterInclusive('\n');
            p.append(line);
            if (std.mem.eql(u8, line, "\r\n")) break;
            if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
                content_length = try std.fmt.parseInt(usize, std.mem.trim(u8, line["content-length:".len..], " \r\n"), 10);
            }
        }
        if (content_length != 0) {
            var body: [4096]u8 = undefined;
            try sr.interface.readSliceAll(body[0..content_length]);
            p.append(body[0..content_length]);
        }
        _ = p.requests.fetchAdd(1, .acq_rel);
        try sw.interface.print("HTTP/1.1 {d} X\r\nContent-Length: {d}\r\nConnection: close\r\n", .{ p.status, p.body.len });
        if (p.location.len != 0) try sw.interface.print("Location: {s}\r\n", .{p.location});
        try sw.interface.writeAll("\r\n");
        try sw.interface.writeAll(p.body);
        try sw.interface.flush();
    }

    fn append(p: *Peer, bytes: []const u8) void {
        const n = @min(bytes.len, p.log.len - p.log_len);
        for (bytes[0..n], p.log[p.log_len..][0..n]) |b, *o| o.* = std.ascii.toLower(b);
        p.log_len += n;
    }

    /// Stop the thread (poking `accept` when connections are still owed), join
    /// and release the listener. After this `log` is safe to read.
    fn finish(p: *Peer) void {
        if (p.done) return;
        p.done = true;
        p.stop.store(1, .release);
        if (p.thread) |t| {
            var pokes: u32 = 0;
            while (p.connected.load(.acquire) < p.serve and pokes < p.serve) : (pokes += 1) {
                const addr = net.IpAddress.parse("127.0.0.1", p.port()) catch break;
                const c = addr.connect(p.io, .{ .mode = .stream }) catch break;
                c.close(p.io);
                p.io.sleep(.fromMilliseconds(20), .awake) catch {};
            }
            t.join();
        }
        p.listener.deinit(p.io);
    }

    fn has(p: *const Peer, needle: []const u8) bool {
        return std.mem.find(u8, p.log[0..p.log_len], needle) != null;
    }
};

fn httpOpts() @import("http").Client.Options {
    return .{ .pool = .{ .enabled = false }, .total_timeout_ms = 5000 };
}

test "AcmeDns.present: the account by domain, the request it sends, 200 only" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var peer: Peer = undefined;
    peer = .{ .io = io, .listener = undefined, .serve = 4 };
    try peer.start(io);
    defer peer.finish();
    var ub: [64]u8 = undefined;
    const accounts = [_]publishers.AcmeDns.Account{
        .{ .domain = "other.test", .username = "u1", .password = "k1", .subdomain = "sub1" },
        .{ .domain = "a.test", .username = "u2", .password = "k2", .subdomain = "sub2", .fulldomain = "_ACME-challenge.a.test" },
    };
    var p = publishers.AcmeDns.init(io, testing.allocator, .{ .server_url = try peer.url(&ub, "/"), .accounts = &accounts, .http = httpOpts() });
    defer p.deinit();
    const pub_ = p.publisher();
    var r = rec;
    r.domain = "A.test";
    try pub_.present(pub_.ctx, &r);
    try testing.expectEqual(@as(u16, 200), p.last_status);
    // An account without a fulldomain is not checked against the CNAME.
    var r_other = rec;
    r_other.domain = "other.test";
    try pub_.present(pub_.ctx, &r_other);
    // acme-dns answers 200; any other status is a refusal.
    peer.status = 201;
    try testing.expectError(error.PublishFailed, pub_.present(pub_.ctx, &r));
    try testing.expectEqual(@as(u16, 201), p.last_status);
    try testing.expectEqualStrings("acme-dns refused the update (see last_status)", p.note);
    peer.status = 200;
    try pub_.present(pub_.ctx, &r);
    try testing.expectEqualStrings("", p.note);
    // cleanup does nothing, on the wire too.
    pub_.cleanup(pub_.ctx, &r);
    peer.finish();
    try testing.expect(peer.has("post /update http/1.1"));
    try testing.expect(peer.has("x-api-user: u2\r\n"));
    try testing.expect(peer.has("x-api-key: k2\r\n"));
    try testing.expect(peer.has("content-type: application/json\r\n"));
    try testing.expect(peer.has("{\"subdomain\":\"sub2\",\"txt\":\"" ++ "loqxcyv8q5onbjqxbmr7sctno3tiaxdfowyjxajeux0" ++ "\"}"));
    try testing.expect(peer.has("x-api-user: u1\r\n") and peer.has("{\"subdomain\":\"sub1\""));
    try testing.expectEqual(@as(u32, 4), peer.requests.load(.acquire));
}

test "AcmeDns.present: no account, or a CNAME elsewhere, is refused before anything is sent" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var peer: Peer = undefined;
    peer = .{ .io = io, .listener = undefined, .serve = 1 };
    try peer.start(io);
    defer peer.finish();
    var ub: [64]u8 = undefined;
    const accounts = [_]publishers.AcmeDns.Account{
        .{ .domain = "a.test", .username = "u", .password = "k", .subdomain = "s", .fulldomain = "elsewhere.auth.test" },
    };
    var p = publishers.AcmeDns.init(io, testing.allocator, .{ .server_url = try peer.url(&ub, ""), .accounts = &accounts, .http = httpOpts() });
    defer p.deinit();
    const pub_ = p.publisher();
    var r = rec;
    r.domain = "b.test";
    try testing.expectError(error.PublishFailed, pub_.present(pub_.ctx, &r));
    try testing.expectEqualStrings("no acme-dns account for this domain", p.note);
    try testing.expectError(error.PublishFailed, pub_.present(pub_.ctx, &rec));
    try testing.expectEqualStrings("_acme-challenge.<domain> is not a CNAME to the account's fulldomain", p.note);
    peer.finish();
    try testing.expectEqual(@as(u32, 0), peer.requests.load(.acquire));
}

test "HttpReq: default JSON with basic auth, RAW JSON without, cleanup, 2xx" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var peer: Peer = undefined;
    peer = .{ .io = io, .listener = undefined, .serve = 5, .status = 204 };
    try peer.start(io);
    defer peer.finish();
    var ub: [64]u8 = undefined;
    const ep = try peer.url(&ub, "/api/");
    var d = publishers.HttpReq.init(io, testing.allocator, .{ .endpoint = ep, .username = "bob", .password = "pw", .http = httpOpts() });
    defer d.deinit();
    const dp = d.publisher();
    try dp.present(dp.ctx, &rec);
    try testing.expectEqual(@as(u16, 204), d.last_status);
    dp.cleanup(dp.ctx, &rec);
    var raw = publishers.HttpReq.init(io, testing.allocator, .{ .endpoint = ep, .mode = .raw, .http = httpOpts() });
    defer raw.deinit();
    const rp = raw.publisher();
    try rp.present(rp.ctx, &rec);
    peer.status = 500;
    try testing.expectError(error.PublishFailed, rp.present(rp.ctx, &rec));
    try testing.expectEqual(@as(u16, 500), raw.last_status);
    try testing.expectEqualStrings("the endpoint refused /present (see last_status)", raw.note);
    peer.status = 204;
    try rp.present(rp.ctx, &rec);
    try testing.expectEqualStrings("", raw.note);
    peer.finish();
    try testing.expect(peer.has("post /api/present http/1.1"));
    try testing.expect(peer.has("post /api/cleanup http/1.1"));
    try testing.expect(peer.has("{\"fqdn\":\"_acme-challenge.a.test.\",\"value\":\"loqxcyv8q5onbjqxbmr7sctno3tiaxdfowyjxajeux0\"}"));
    try testing.expect(peer.has("authorization: basic ym9ionb3\r\n"));
    try testing.expect(peer.has("{\"domain\":\"a.test\",\"token\":\"tok\",\"keyauth\":\"tok.thumb\"}"));
    // Both calls of the first publisher carry it, the RAW publisher's none.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, peer.log[0..peer.log_len], "authorization:"));
}

test "HttpReq: credentials that cannot be encoded say so" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var d = publishers.HttpReq.init(io, testing.allocator, .{ .endpoint = "http://127.0.0.1:1", .username = "a:b", .password = "pw", .http = httpOpts() });
    defer d.deinit();
    const dp = d.publisher();
    try testing.expectError(error.PublishFailed, dp.present(dp.ctx, &rec));
    try testing.expectEqualStrings("basic-auth credentials too long, or the username contains ':' (RFC 7617)", d.note);
    // Unreachable endpoint: the other note.
    d.options.username = "";
    try testing.expectError(error.PublishFailed, dp.present(dp.ctx, &rec));
    try testing.expectEqualStrings("the endpoint could not be reached", d.note);
}

test "post: a redirect is not followed (credentials stay with the configured endpoint)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var target: Peer = undefined;
    target = .{ .io = io, .listener = undefined, .serve = 1 };
    try target.start(io);
    defer target.finish();
    var tb: [64]u8 = undefined;
    var peer: Peer = undefined;
    peer = .{ .io = io, .listener = undefined, .serve = 1, .status = 307, .location = try target.url(&tb, "/landed") };
    try peer.start(io);
    defer peer.finish();
    var ub: [64]u8 = undefined;
    var d = publishers.HttpReq.init(io, testing.allocator, .{ .endpoint = try peer.url(&ub, "/h"), .username = "bob", .password = "pw", .http = httpOpts() });
    defer d.deinit();
    const dp = d.publisher();
    try testing.expectError(error.PublishFailed, dp.present(dp.ctx, &rec));
    try testing.expectEqual(@as(u16, 307), d.last_status);
    peer.finish();
    target.finish();
    try testing.expectEqual(@as(u32, 0), target.requests.load(.acquire));
}

test "post: a reply body of 64 KiB is drained, one byte more is refused" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var peer: Peer = undefined;
    const big = try testing.allocator.alloc(u8, 64 * 1024 + 1);
    defer testing.allocator.free(big);
    @memset(big, 'x');
    peer = .{ .io = io, .listener = undefined, .serve = 2, .body = big[0 .. 64 * 1024] };
    try peer.start(io);
    defer peer.finish();
    var ub: [64]u8 = undefined;
    var d = publishers.HttpReq.init(io, testing.allocator, .{ .endpoint = try peer.url(&ub, "/h"), .http = httpOpts() });
    defer d.deinit();
    const dp = d.publisher();
    try dp.present(dp.ctx, &rec);
    peer.body = big;
    try testing.expectError(error.PublishFailed, dp.present(dp.ctx, &rec));
    try testing.expectEqualStrings("the endpoint could not be reached", d.note);
}

test "AcmeDns.register: the request, 200 and 201 accepted, anything else refused" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const reply =
        \\{"username":"u","password":"p","fulldomain":"f.auth.test","subdomain":"s","allowfrom":[]}
    ;
    var peer: Peer = undefined;
    peer = .{ .io = io, .listener = undefined, .serve = 6, .status = 201, .body = reply };
    const big = try testing.allocator.alloc(u8, 64 * 1024 + 1);
    defer testing.allocator.free(big);
    @memset(big, ' ');
    try peer.start(io);
    defer peer.finish();
    var ub: [64]u8 = undefined;
    const url = try peer.url(&ub, "/");
    {
        var got = try publishers.AcmeDns.register(io, testing.allocator, url, httpOpts(), &.{});
        defer got.deinit();
        try testing.expectEqualStrings("p", got.value.password);
        try testing.expectEqualStrings("f.auth.test", got.value.fulldomain);
    }
    peer.status = 200;
    {
        var got = try publishers.AcmeDns.register(io, testing.allocator, url, httpOpts(), &.{"192.0.2.0/24"});
        defer got.deinit();
        try testing.expectEqualStrings("u", got.value.username);
    }
    peer.status = 403;
    try testing.expectError(error.RegistrationRefused, publishers.AcmeDns.register(io, testing.allocator, url, httpOpts(), &.{}));
    peer.status = 202;
    try testing.expectError(error.RegistrationRefused, publishers.AcmeDns.register(io, testing.allocator, url, httpOpts(), &.{}));
    // The reply is read up to 64 KiB, no more.
    peer.status = 201;
    peer.body = big[0 .. 64 * 1024];
    if (publishers.AcmeDns.register(io, testing.allocator, url, httpOpts(), &.{})) |*got| {
        got.deinit();
        return error.ExpectedAnError;
    } else |err| try testing.expect(err != error.BodyTooLarge);
    peer.body = big;
    try testing.expectError(error.BodyTooLarge, publishers.AcmeDns.register(io, testing.allocator, url, httpOpts(), &.{}));
    peer.finish();
    try testing.expect(peer.has("post /register http/1.1"));
    try testing.expect(peer.has("content-type: application/json\r\n"));
    try testing.expect(peer.has("\r\n\r\n{}"));
    try testing.expect(peer.has("{\"allowfrom\":[\"192.0.2.0/24\"]}"));
}

// ── RFC 2136 ────────────────────────────────────────────────────────────────

/// Answers every UDP datagram as an UPDATE response with `rcode`, the zone
/// section echoed; keeps the last datagram.
const UpdateStub = struct {
    io: std.Io,
    sock: net.Socket,
    thread: ?std.Thread = null,
    rcode: u4 = 0,
    silent: bool = false,
    last: [1024]u8 = undefined,
    last_len: usize = 0,
    count: std.atomic.Value(u32) = .init(0),
    stop: std.atomic.Value(bool) = .init(false),

    fn start(u: *UpdateStub, io: std.Io) !void {
        u.io = io;
        const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
        u.sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("bind failed ({t})", .{err});
        u.thread = try std.Thread.spawn(.{}, run, .{u});
    }

    fn finish(u: *UpdateStub) void {
        u.stop.store(true, .release);
        if (u.thread) |t| t.join();
        u.sock.close(u.io);
    }

    fn run(u: *UpdateStub) void {
        while (!u.stop.load(.acquire)) u.serveOne() catch {};
    }

    fn serveOne(u: *UpdateStub) !void {
        var rbuf: [1500]u8 = undefined;
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } };
        const in = try u.sock.receiveTimeout(u.io, &rbuf, t.toDeadline(u.io));
        const q = in.data;
        if (q.len < 12) return;
        @memcpy(u.last[0..q.len], q);
        u.last_len = q.len;
        if (u.silent) return;
        var at: usize = 12;
        while (at < q.len and q[at] != 0) at += 1 + q[at];
        const zone_end = at + 1 + 4;
        var out: [512]u8 = undefined;
        @memcpy(out[0..zone_end], q[0..zone_end]);
        std.mem.writeInt(u16, out[2..4], 0xA800 | @as(u16, u.rcode), .big);
        @memset(out[6..12], 0);
        out[5] = 1; // ZOCOUNT
        try u.sock.send(u.io, &in.from, out[0..zone_end]);
        _ = u.count.fetchAdd(1, .release);
    }
};

test "Rfc2136: the update it sends (add / delete one value) and how the rcode is read" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub: UpdateStub = undefined;
    stub = .{ .io = io, .sock = undefined };
    try stub.start(io);
    defer stub.finish();
    var p = publishers.Rfc2136.init(io, testing.allocator, .{
        .server = .{ .v4 = .{ 127, 0, 0, 1 } },
        .port = stub.sock.address.getPort(),
        .ttl = 777,
        .timeout_ms = 1000,
    });
    const pub_ = p.publisher();
    try pub_.present(pub_.ctx, &rec);
    try testing.expectEqual(dns.Rcode.no_error, p.last_rcode.?);
    {
        var msg = try dns.decode(testing.allocator, stub.last[0..stub.last_len]);
        defer msg.deinit();
        try testing.expectEqual(dns.message.Opcode.update, msg.header.opcode);
        try testing.expectEqualStrings("a.test", msg.questions[0].name);
        try testing.expectEqual(@as(usize, 1), msg.authorities.len);
        const u = msg.authorities[0];
        try testing.expectEqualStrings("_acme-challenge.a.test", u.name);
        try testing.expectEqual(dns.message.Type.txt, u.ty);
        try testing.expectEqual(dns.message.Class.in, u.class);
        try testing.expectEqual(@as(u32, 777), u.ttl);
        try testing.expectEqual(@as(usize, 1), u.data.txt.len);
        try testing.expectEqualStrings(value, u.data.txt[0]);
    }
    pub_.cleanup(pub_.ctx, &rec);
    {
        var msg = try dns.decode(testing.allocator, stub.last[0..stub.last_len]);
        defer msg.deinit();
        const u = msg.authorities[0];
        try testing.expectEqual(dns.message.Class.none, u.class);
        try testing.expectEqual(@as(u32, 0), u.ttl);
        try testing.expectEqualStrings(value, u.data.txt[0]);
    }
    stub.rcode = 5; // REFUSED
    try testing.expectError(error.PublishFailed, pub_.present(pub_.ctx, &rec));
    try testing.expectEqual(dns.Rcode.refused, p.last_rcode.?);
    try testing.expectEqualStrings("the server refused the update (see last_rcode)", p.note);
    // A fresh present clears the note.
    stub.rcode = 0;
    try pub_.present(pub_.ctx, &rec);
    try testing.expectEqualStrings("", p.note);
    // Over-long input is an error, not a crash (the buffers are fixed).
    var long = rec;
    const big: [400]u8 = @splat('v');
    long.value = &big;
    try testing.expectError(error.PublishFailed, pub_.present(pub_.ctx, &long));
}

test "Rfc2136: timeout and attempts are the caller's; a TSIG key demands a signed reply" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub: UpdateStub = undefined;
    stub = .{ .io = io, .sock = undefined, .silent = true };
    try stub.start(io);
    defer stub.finish();
    const port = stub.sock.address.getPort();
    var p = publishers.Rfc2136.init(io, testing.allocator, .{ .server = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = port, .timeout_ms = 200, .attempts = 1 });
    var pub_ = p.publisher();
    const t0 = nowMs(io);
    try testing.expectError(error.PublishFailed, pub_.present(pub_.ctx, &rec));
    const one = nowMs(io) - t0;
    try testing.expect(one >= 150 and one < 1000);
    try testing.expectEqualStrings("the server did not answer", p.note);
    p.options.attempts = 3;
    const t1 = nowMs(io);
    try testing.expectError(error.PublishFailed, pub_.present(pub_.ctx, &rec));
    try testing.expect(nowMs(io) - t1 >= 450);

    // The stub answers, unsigned: with a key configured that reply is refused.
    stub.silent = false;
    const key: dns.tsig.Key = .{ .name = "k.", .secret = "secret" };
    p.options.key = &key;
    p.options.attempts = 1;
    p.options.timeout_ms = 1000;
    try testing.expectError(error.PublishFailed, pub_.present(pub_.ctx, &rec));
    try testing.expectEqualStrings("the server's reply failed TSIG verification", p.note);
    // The request did carry the signature (a TSIG record in the additional section).
    var msg = try dns.decode(testing.allocator, stub.last[0..stub.last_len]);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 1), msg.additionals.len);
    try testing.expectEqual(dns.message.Type.tsig, msg.additionals[0].ty);
}

/// `fail_index` sweep: an induced allocation failure must come out as
/// `OutOfMemory` (never as a publisher failure), and nothing may leak.
fn oomSweep(comptime Ctx: type, ctx: *Ctx, comptime attempt: fn (*Ctx, std.mem.Allocator) anyerror!void) !void {
    var saw_oom = false;
    for (0..40) |k| {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = k });
        attempt(ctx, failing.allocator()) catch |err| {
            if (failing.has_induced_failure) {
                try testing.expectEqual(error.OutOfMemory, err);
                saw_oom = true;
            }
            continue;
        };
    }
    try testing.expect(saw_oom);
}

test "publishers: an allocation failure is OutOfMemory, not PublishFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub: UpdateStub = undefined;
    stub = .{ .io = io, .sock = undefined };
    try stub.start(io);
    defer stub.finish();
    const Rf = struct {
        io: std.Io,
        port: u16,
        fn attempt(c: *@This(), gpa: std.mem.Allocator) anyerror!void {
            var p = publishers.Rfc2136.init(c.io, gpa, .{ .server = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = c.port, .timeout_ms = 300 });
            const pub_ = p.publisher();
            try pub_.present(pub_.ctx, &rec);
        }
    };
    var rf: Rf = .{ .io = io, .port = stub.sock.address.getPort() };
    try oomSweep(Rf, &rf, Rf.attempt);

    var peer: Peer = undefined;
    peer = .{ .io = io, .listener = undefined, .serve = 80 };
    try peer.start(io);
    defer peer.finish();
    var ub: [64]u8 = undefined;
    const ep = try peer.url(&ub, "/h");
    const Ht = struct {
        io: std.Io,
        ep: []const u8,
        fn attempt(c: *@This(), gpa: std.mem.Allocator) anyerror!void {
            var p = publishers.HttpReq.init(c.io, gpa, .{ .endpoint = c.ep, .username = "u", .password = "p", .http = httpOpts() });
            defer p.deinit();
            const pub_ = p.publisher();
            try pub_.present(pub_.ctx, &rec);
        }
        fn attemptAcme(c: *@This(), gpa: std.mem.Allocator) anyerror!void {
            const accounts = [_]publishers.AcmeDns.Account{.{ .domain = "a.test", .username = "u", .password = "p", .subdomain = "s" }};
            var p = publishers.AcmeDns.init(c.io, gpa, .{ .server_url = c.ep, .accounts = &accounts, .http = httpOpts() });
            defer p.deinit();
            const pub_ = p.publisher();
            try pub_.present(pub_.ctx, &rec);
        }
    };
    var ht: Ht = .{ .io = io, .ep = ep };
    try oomSweep(Ht, &ht, Ht.attempt);
    try oomSweep(Ht, &ht, Ht.attemptAcme);
}

// ── exec ────────────────────────────────────────────────────────────────────

fn writeScript(io: std.Io, dir: std.Io.Dir, name: []const u8, body: []const u8) !void {
    const f = try dir.createFile(io, name, .{});
    defer f.close(io);
    var wbuf: [256]u8 = undefined;
    var fw = f.writer(io, &wbuf);
    try fw.interface.writeAll("#!/bin/sh\n");
    try fw.interface.writeAll(body);
    try fw.interface.flush();
    try testing.expectEqual(@as(usize, 0), std.os.linux.fchmod(f.handle, 0o755));
}

fn readAll(io: std.Io, dir: std.Io.Dir, name: []const u8, buf: []u8) ![]const u8 {
    const f = try dir.openFile(io, name, .{});
    defer f.close(io);
    var rb: [64]u8 = undefined;
    var fr = f.reader(io, &rb);
    const n = try fr.interface.readSliceShort(buf);
    return buf[0..n];
}

test "Exec: argv of both modes, exit codes, stderr tail, timeout" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeScript(io, tmp.dir, "rec.sh", "d=$(dirname \"$0\")\nprintf '%s\\n' \"$@\" >> \"$d/argv\"\nexit 0\n");
    try writeScript(io, tmp.dir, "fail.sh", "echo boom >&2\nexit 3\n");
    try writeScript(io, tmp.dir, "spam.sh", "printf '%01000d' 0 >&2\nprintf END >&2\nexit 1\n");
    try writeScript(io, tmp.dir, "slow.sh", "exec sleep 30\n");
    try writeScript(io, tmp.dir, "nap.sh", "sleep 0.3\nexit 0\n");
    try writeScript(io, tmp.dir, "orphan.sh", "sleep 5 &\necho $! > \"$(dirname \"$0\")/pid\"\nwait\n");
    var pb: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = pb[0..try tmp.dir.realPath(io, &pb)];
    var path_buf: [std.Io.Dir.max_path_bytes + 16]u8 = undefined;
    const gpa = testing.allocator;

    // Default mode: <program> present|cleanup <fqdn.> <value>.
    var e = publishers.Exec.init(io, gpa, .{ .program = try std.mem.print(&path_buf, "{s}/rec.sh", .{dir}) });
    const ep = e.publisher();
    try ep.present(ep.ctx, &rec);
    try testing.expectEqual(@as(u8, 0), e.last_term.?.exited);
    ep.cleanup(ep.ctx, &rec);
    var ab: [1024]u8 = undefined;
    try testing.expectEqualStrings("present\n_acme-challenge.a.test.\n" ++ value ++ "\ncleanup\n_acme-challenge.a.test.\n" ++ value ++ "\n", try readAll(io, tmp.dir, "argv", &ab));
    // RAW: <program> present -- <domain> <token> <keyAuth>.
    try tmp.dir.deleteFile(io, "argv");
    e.options.mode = .raw;
    try ep.present(ep.ctx, &rec);
    try testing.expectEqualStrings("present\n--\na.test\ntok\ntok.thumb\n", try readAll(io, tmp.dir, "argv", &ab));

    // A note from a failed run is gone after the next call.
    var nf = publishers.Exec.init(io, gpa, .{ .program = "/nonexistent/acmedns-test" });
    const nfp = nf.publisher();
    try testing.expectError(error.PublishFailed, nfp.present(nfp.ctx, &rec));
    nf.options.program = e.options.program;
    try nfp.present(nfp.ctx, &rec);
    try testing.expectEqualStrings("", nf.note);

    // A non-zero exit is a failure, with what the program said.
    var f = publishers.Exec.init(io, gpa, .{ .program = try std.mem.print(&path_buf, "{s}/fail.sh", .{dir}) });
    const fp = f.publisher();
    try testing.expectError(error.PublishFailed, fp.present(fp.ctx, &rec));
    try testing.expectEqual(@as(u8, 3), f.last_term.?.exited);
    try testing.expectEqualStrings("boom\n", f.lastStderr());
    try testing.expectEqualStrings("the program did not exit 0 (see last_term)", f.note);

    // Only the last 512 bytes of stderr are kept.
    var sp = publishers.Exec.init(io, gpa, .{ .program = try std.mem.print(&path_buf, "{s}/spam.sh", .{dir}) });
    const spp = sp.publisher();
    try testing.expectError(error.PublishFailed, spp.present(spp.ctx, &rec));
    try testing.expectEqual(@as(usize, 512), sp.lastStderr().len);
    try testing.expect(std.mem.endsWith(u8, sp.lastStderr(), "0END"));

    // A program that outlives its timeout is killed.
    var sl = publishers.Exec.init(io, gpa, .{ .program = try std.mem.print(&path_buf, "{s}/slow.sh", .{dir}), .timeout_ms = 300 });
    const slp = sl.publisher();
    const t0 = nowMs(io);
    try testing.expectError(error.PublishFailed, slp.present(slp.ctx, &rec));
    try testing.expect(nowMs(io) - t0 < 10_000);
    try testing.expect(sl.last_term.? != .exited);

    // The timeout is milliseconds: a 0.3 s program fits in 3 s.
    var nap = publishers.Exec.init(io, gpa, .{ .program = try std.mem.print(&path_buf, "{s}/nap.sh", .{dir}), .timeout_ms = 3000 });
    const nappub = nap.publisher();
    try nappub.present(nappub.ctx, &rec);

    // The whole process group goes: a grandchild does not outlive the timeout.
    var orph = publishers.Exec.init(io, gpa, .{ .program = try std.mem.print(&path_buf, "{s}/orphan.sh", .{dir}), .timeout_ms = 300 });
    const orp = orph.publisher();
    try testing.expectError(error.PublishFailed, orp.present(orp.ctx, &rec));
    const pid_text = std.mem.trim(u8, try readAll(io, tmp.dir, "pid", &ab), " \n");
    const pid = try std.fmt.parseInt(i32, pid_text, 10);
    var gone = false;
    for (0..40) |_| {
        const rc = std.os.linux.kill(pid, @fromBackingInt(@intCast(0)));
        if (std.os.linux.errno(rc) == .SRCH) {
            gone = true;
            break;
        }
        io.sleep(.fromMilliseconds(50), .awake) catch {};
    }
    try testing.expect(gone);

    // Not startable.
    var m = publishers.Exec.init(io, gpa, .{ .program = "/nonexistent/acmedns-test" });
    const mp = m.publisher();
    try testing.expectError(error.PublishFailed, mp.present(mp.ctx, &rec));
    try testing.expectEqualStrings("the program could not be started", m.note);
}
