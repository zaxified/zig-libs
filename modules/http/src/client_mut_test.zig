// SPDX-License-Identifier: MIT

//! Tests added by the whole-module mutation run, wave 3 (Client side): one per
//! mutant the earlier waves let survive. They use only the public surface and
//! loopback peers, and each stands on its own.

const std = @import("std");
const testing = std.testing;
const net = std.Io.net;
const testkit = @import("testkit");
const tlsserver = @import("tlsserver");

const http = @import("root.zig");
const Client = @import("Client.zig");
const Server = @import("Server.zig");

// ── https -> http redirect gate, end to end ─────────────────────────────────
//
// `Client.request` refuses a redirect from `https://` to `http://` unless
// `RequestOptions.allow_https_to_http_redirect` is set, and refuses it BEFORE
// any dial ("a refused host receives nothing"). The helper's truth table was
// tested; the gate's call in `request` was not (dropping it survived). The
// origin here is a real `tlsserver` on loopback; the redirect target is a plain
// listener that records whether anything spoke to it.

/// One-connection TLS origin on a thread (`tlsserver`): handshake, record the
/// ALPN protocol it selected, then either answer 302 to `location` or serve
/// "hello tls" as h2 (ALPN `h2`) / h1.
const TlsOrigin = struct {
    io: std.Io,
    server: net.Server,
    ck: tlsserver.CertifiedKey,
    mode: enum { redirect, app } = .app,
    alpn: []const []const u8 = &.{},
    location: []const u8 = "",
    served: std.atomic.Value(u32) = .init(0),
    /// 0 = the handshake did not finish; else 1 + the selected protocol's
    /// length (1 = no ALPN protocol selected).
    chosen_len: std.atomic.Value(u32) = .init(0),
    chosen_buf: [16]u8 = undefined,

    fn run(o: *TlsOrigin) void {
        o.serve() catch {};
    }

    fn chosenAlpn(o: *const TlsOrigin) ?[]const u8 {
        const n = o.chosen_len.load(.acquire);
        return if (n <= 1) null else o.chosen_buf[0 .. n - 1];
    }

    fn hello(_: *Server.Request, rw: *Server.ResponseWriter) anyerror!void {
        try rw.writeAll("hello tls");
    }

    fn serve(o: *TlsOrigin) !void {
        const gpa = testing.allocator;
        const ck = o.ck;
        var prng = std.Random.DefaultPrng.init(0x302);
        const cfg: tlsserver.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random(), .alpn_protocols = o.alpn };

        const stream = try o.server.accept(o.io);
        defer stream.close(o.io);
        const in_buf = try gpa.alloc(u8, tlsserver.record.max_record_len);
        defer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, tlsserver.server.minOutputLen(&cfg, &ck));
        defer gpa.free(out_buf);
        const joiner = try gpa.alloc(u8, tlsserver.inbound.Joiner.bufferLen(tlsserver.inbound.default_max_message));
        defer gpa.free(joiner);
        var sr = stream.reader(o.io, in_buf);
        var sw = stream.writer(o.io, out_buf);
        var conn = tlsserver.Connection.init(&cfg, &sr.interface, &sw.interface, joiner);
        defer conn.deinit();

        try conn.handshake();
        if (conn.server.alpnProtocol()) |p| {
            @memcpy(o.chosen_buf[0..p.len], p);
            o.chosen_len.store(@intCast(p.len + 1), .release);
        } else o.chosen_len.store(1, .release);

        switch (o.mode) {
            .redirect => {
                const data = (try conn.read()) orelse return;
                if (!std.mem.startsWith(u8, data, "GET ")) return;
                var resp: [256]u8 = undefined;
                const text = try std.mem.print(&resp, "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{o.location});
                try conn.writeAll(text);
            },
            .app => {
                if (o.chosenAlpn()) |p| if (std.mem.eql(u8, p, http.alpn_h2)) {
                    http.h2_server.serveStream(gpa, conn.reader(), conn.writer(), null, .{ .handler = hello });
                    _ = o.served.fetchAdd(1, .release);
                    try conn.close();
                    return;
                };
                var head: [4096]u8 = undefined;
                var request_body: [1024]u8 = undefined;
                var response_body: [1024]u8 = undefined;
                var chunk: [256]u8 = undefined;
                Server.serveStream(.{ .handler = hello }, conn.reader(), conn.writer(), .{
                    .head = &head,
                    .request_body = &request_body,
                    .response_body = &response_body,
                    .chunk = &chunk,
                });
            },
        }
        _ = o.served.fetchAdd(1, .release);
        try conn.close();
    }
};

/// One-connection plain peer: counts a request line, answers 200 "ok".
const PlainTarget = struct {
    io: std.Io,
    server: net.Server,
    hit: std.atomic.Value(u32) = .init(0),

    fn run(p: *PlainTarget) void {
        const s = p.server.accept(p.io) catch return;
        defer s.close(p.io);
        var rbuf: [1024]u8 = undefined;
        var wbuf: [256]u8 = undefined;
        var sr = s.reader(p.io, &rbuf);
        var sw = s.writer(p.io, &wbuf);
        const first = sr.interface.takeDelimiterInclusive('\n') catch return;
        if (!std.mem.startsWith(u8, first, "GET ")) return;
        _ = p.hit.fetchAdd(1, .release);
        while (true) {
            const l = sr.interface.takeDelimiterInclusive('\n') catch return;
            if (l.len <= 2) break;
        }
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok") catch return;
        sw.interface.flush() catch return;
    }

    /// Unblock a still-waiting `accept` so the thread can be joined.
    fn release(p: *PlainTarget, port: u16) void {
        if (p.hit.load(.acquire) != 0) return;
        const addr = net.IpAddress.parse("127.0.0.1", port) catch return;
        const s = addr.connect(p.io, .{ .mode = .stream }) catch return;
        s.close(p.io);
    }
};

fn redirectRig(allow: bool) !void {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const kv = comptime tlsserver.testKeyVector("p256-pkcs8");
    var pair: tlsserver.keys.CertKeyPair = undefined;
    try tlsserver.keys.CertKeyPair.fromPem(&pair, gpa, kv.cert_pem, kv.key_pem);
    defer pair.deinit(gpa);

    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const plain_l = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err});
    var target: PlainTarget = .{ .io = io, .server = plain_l };
    defer target.server.socket.close(io);
    const plain_port = plain_l.socket.address.getPort();

    const tls_l = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err});
    var loc_buf: [64]u8 = undefined;
    var origin: TlsOrigin = .{
        .io = io,
        .server = tls_l,
        .ck = pair.certifiedKey(),
        .mode = .redirect,
        .location = try std.mem.print(&loc_buf, "http://127.0.0.1:{d}/secret", .{plain_port}),
    };
    defer origin.server.socket.close(io);
    const tls_port = tls_l.socket.address.getPort();

    const t_plain = try std.Thread.spawn(.{}, PlainTarget.run, .{&target});
    defer t_plain.join();
    defer target.release(plain_port);
    const t_tls = try std.Thread.spawn(.{}, TlsOrigin.run, .{&origin});
    defer t_tls.join();

    var client = Client.init(io, gpa, .{
        .tls = .{ .verify = .insecure_no_verify },
        .connect_timeout_ms = 3000,
        .total_timeout_ms = 6000,
    });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "https://127.0.0.1:{d}/start", .{tls_port});

    if (allow) {
        var res = try client.request(.get, url, .{ .allow_https_to_http_redirect = true });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.head.status);
        try testing.expectEqual(@as(u32, 1), target.hit.load(.acquire));
    } else {
        try testing.expectError(error.RedirectRefused, client.request(.get, url, .{}));
        // The plain target was never dialed.
        target.release(plain_port);
        try testing.expectEqual(@as(u32, 0), target.hit.load(.acquire));
    }
}

test "request: an https origin that redirects to http:// is refused by default, and nothing dials the http target" {
    try redirectRig(false);
}

test "request: allow_https_to_http_redirect follows the same redirect (control for the refusal above)" {
    try redirectRig(true);
}

// ── HTTPS through a real TLS server ─────────────────────────────────────────
// Until `tlsserver` became a test dependency nothing here ever ran the client's
// TLS path against a peer: the flush of the ciphertext, the ALPN offer and the
// h2 start were only compiled.

fn tlsRig(origin_alpn: []const []const u8, client_h2: bool, expect_h2: bool, expect_chosen: ?[]const u8) !void {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const kv = comptime tlsserver.testKeyVector("p256-pkcs8");
    var pair: tlsserver.keys.CertKeyPair = undefined;
    try tlsserver.keys.CertKeyPair.fromPem(&pair, gpa, kv.cert_pem, kv.key_pem);
    defer pair.deinit(gpa);

    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const tls_l = addr.listen(io, .{ .reuse_address = true }) catch |err| return testkit.loopbackSkip("loopback listen failed ({t})", .{err});
    var origin: TlsOrigin = .{ .io = io, .server = tls_l, .ck = pair.certifiedKey(), .alpn = origin_alpn };
    defer origin.server.socket.close(io);
    const port = tls_l.socket.address.getPort();
    const t = try std.Thread.spawn(.{}, TlsOrigin.run, .{&origin});
    defer t.join();

    var client = Client.init(io, gpa, .{
        .tls = .{ .verify = .insecure_no_verify },
        .http2 = if (client_h2) .alpn() else null,
        .connect_timeout_ms = 3000,
        .total_timeout_ms = 6000,
    });
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "https://127.0.0.1:{d}/", .{port});

    var res = try client.request(.get, url, .{});
    defer res.deinit();
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqual(if (expect_h2) http.Client.Proto.http2 else http.Client.Proto.http1_1, res.proto());
    const body = try res.readAllAlloc(gpa, 1024);
    defer gpa.free(body);
    try testing.expectEqualStrings("hello tls", body);
    if (expect_chosen) |want| {
        try testing.expectEqualStrings(want, origin.chosenAlpn().?);
    } else try testing.expect(origin.chosenAlpn() == null);
}

test "https over TLS: a client without http2 offers no ALPN, and the response arrives (ciphertext flushed)" {
    try tlsRig(&.{ "h2", "http/1.1" }, false, false, null);
}

test "https over TLS: http2 client against an ALPN h2 origin speaks h2" {
    try tlsRig(&.{ "h2", "http/1.1" }, true, true, "h2");
}

test "https over TLS: http2 client against an http/1.1-only origin stays on HTTP/1.1" {
    try tlsRig(&.{"http/1.1"}, true, false, "http/1.1");
}
