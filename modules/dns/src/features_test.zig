// SPDX-License-Identifier: MIT
//! Resolver options that keep per-server memory: RFC 7873 cookies and server
//! failover, against scripted UDP servers on the loopback.
const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const netaddr = @import("netaddr");
const message = @import("message.zig");
const Resolver = @import("Resolver.zig");
const net = std.Io.net;

const question_end_fixed = 4;
const server_cookie = "SERVERCK";

const Stub = struct {
    io: std.Io,
    sock: net.Socket,
    mode: Mode,
    max: usize,
    served: usize = 0,
    /// Per query served: the length of its COOKIE option data (0: none) and the client cookie.
    /// Queries received (before any delay), the address answered with, a delay before answering.
    seen: usize = 0,
    ip: [4]u8 = .{ 192, 0, 2, 1 },
    delay_ms: i64 = 0,
    cookie_len: [4]usize = @splat(0),
    client: [4][8]u8 = @splat(@splat(0)),
    server_part: [4][8]u8 = @splat(@splat(0)),

    const Mode = enum { answer, servfail, silent, cookie_good, cookie_bad_client, badcookie };

    fn run(st: *Stub) void {
        while (st.served < st.max) st.serveOne() catch return;
    }

    fn serveOne(st: *Stub) !void {
        var rbuf: [message.max_query_len]u8 = undefined;
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake } };
        const incoming = try st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io));
        const q = incoming.data;
        st.seen += 1;
        if (st.mode == .silent) {
            st.served += 1;
            return;
        }
        if (st.delay_ms > 0) try st.io.sleep(.fromMilliseconds(st.delay_ms), .awake);
        var qend: usize = message.header_len;
        while (q[qend] != 0) qend += @as(usize, q[qend]) + 1;
        qend += 1 + question_end_fixed;
        const question = q[message.header_len..qend];
        // The COOKIE option of the query's OPT record, when it has one.
        var cookie: []const u8 = &.{};
        if (std.mem.readInt(u16, q[10..12], .big) == 1) {
            var opts = q[qend + 11 ..];
            while (opts.len >= 4) {
                const len = std.mem.readInt(u16, opts[2..4], .big);
                if (std.mem.readInt(u16, opts[0..2], .big) == 10) cookie = opts[4..][0..len];
                opts = opts[4 + len ..];
            }
        }
        const i = st.served;
        if (i < st.cookie_len.len) {
            st.cookie_len[i] = cookie.len;
            if (cookie.len >= 8) st.client[i] = cookie[0..8].*;
            if (cookie.len >= 16) st.server_part[i] = cookie[8..16].*;
        }

        var out: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        const answer = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ &st.ip;
        const bad = st.mode == .badcookie and cookie.len == 8;
        const with_cookie = (st.mode == .cookie_good or st.mode == .cookie_bad_client or st.mode == .badcookie) and cookie.len >= 8;
        const flags: u16 = if (st.mode == .servfail) 0x8182 else if (bad) 0x8187 else 0x8180;
        try w.writeAll(q[0..2]);
        try w.writeInt(u16, flags, .big);
        try w.writeInt(u16, 1, .big);
        try w.writeInt(u16, if (st.mode == .servfail or bad) 0 else 1, .big);
        try w.writeInt(u16, 0, .big);
        try w.writeInt(u16, @intFromBool(with_cookie), .big);
        try w.writeAll(question);
        if (st.mode != .servfail and !bad) try w.writeAll(answer);
        if (with_cookie) {
            var echo: [8]u8 = cookie[0..8].*;
            if (st.mode == .cookie_bad_client) echo[0] ^= 0xff;
            try w.writeAll("\x00\x00\x29\x04\xd0");
            try w.writeInt(u32, if (bad) 0x01000000 else 0, .big); // BADCOOKIE: extended rcode 1 + header 7
            try w.writeInt(u16, 4 + 16, .big);
            try w.writeAll("\x00\x0a\x00\x10");
            try w.writeAll(&echo);
            try w.writeAll(server_cookie);
        }
        st.served += 1;
        try st.sock.send(st.io, &incoming.from, w.buffered());
    }
};

fn bindStub(io: std.Io, ip4: [4]u8, port: u16, mode: Stub.Mode, max: usize) !Stub {
    const addr: net.IpAddress = .{ .ip4 = .{ .bytes = ip4, .port = port } };
    const sock = addr.bind(io, .{ .mode = .dgram }) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    return .{ .io = io, .sock = sock, .mode = mode, .max = max };
}

const lo1 = netaddr.Ip{ .v4 = .{ 127, 0, 0, 1 } };
const lo2 = netaddr.Ip{ .v4 = .{ 127, 0, 0, 2 } };
const one_server = [_]netaddr.Ip{lo1};
const two_servers = [_]netaddr.Ip{ lo1, lo2 };

fn resolver(io: std.Io, servers: []const netaddr.Ip, port: u16) Resolver {
    return Resolver.init(io, testing.allocator, .{
        .servers = servers,
        .port = port,
        .timeout_ms = 400,
        .attempts = 1,
        .use_hosts = false,
        .use_search = false,
    });
}

test "cookies: the client cookie is kept per server and the server cookie learned is sent back (RFC 7873)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .cookie_good, 3);
    defer stub.sock.close(io);
    var fut = try io.concurrent(Stub.run, .{&stub});
    defer fut.await(io);
    var r = resolver(io, &one_server, stub.sock.address.getPort());
    r.options.cookies = true;
    defer r.deinit();
    for (0..3) |_| {
        var m = try r.query("example.com", .a);
        defer m.deinit();
        try testing.expectEqual(@as(usize, 1), m.answers.len);
    }
    try testing.expectEqual(@as(usize, 8), stub.cookie_len[0]); // first contact: client cookie only
    try testing.expectEqual(@as(usize, 16), stub.cookie_len[1]);
    try testing.expectEqual(@as(usize, 16), stub.cookie_len[2]);
    try testing.expectEqualSlices(u8, &stub.client[0], &stub.client[1]);
    try testing.expectEqualSlices(u8, &stub.client[0], &stub.client[2]);
    try testing.expectEqualSlices(u8, server_cookie, &stub.server_part[1]);
    try testing.expect(!std.mem.allEqual(u8, &stub.client[0], 0));
}

test "cookies: off by default, no COOKIE option leaves the resolver" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .answer, 1);
    defer stub.sock.close(io);
    var fut = try io.concurrent(Stub.run, .{&stub});
    defer fut.await(io);
    var r = resolver(io, &one_server, stub.sock.address.getPort());
    defer r.deinit();
    var m = try r.query("example.com", .a);
    m.deinit();
    try testing.expectEqual(@as(usize, 0), stub.cookie_len[0]);
}

test "cookies: a server that does not speak them is accepted (RFC 7873 5.2.1)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .answer, 1);
    defer stub.sock.close(io);
    var fut = try io.concurrent(Stub.run, .{&stub});
    defer fut.await(io);
    var r = resolver(io, &one_server, stub.sock.address.getPort());
    r.options.cookies = true;
    defer r.deinit();
    var m = try r.query("example.com", .a);
    defer m.deinit();
    try testing.expectEqual(@as(usize, 1), m.answers.len);
    try testing.expectEqual(@as(usize, 8), stub.cookie_len[0]);
}

test "cookies: a reply with another client cookie is dropped like a spoofed one (RFC 7873 5.2.3)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .cookie_bad_client, 1);
    defer stub.sock.close(io);
    var fut = try io.concurrent(Stub.run, .{&stub});
    defer fut.await(io);
    var r = resolver(io, &one_server, stub.sock.address.getPort());
    r.options.cookies = true;
    defer r.deinit();
    try testing.expectError(error.Timeout, r.query("example.com", .a));
    try testing.expectEqual(@as(usize, 1), stub.served);
    // The same server is believed when cookies are not asked for.
    r.options.cookies = false;
    stub.max = 2;
    var fut2 = try io.concurrent(Stub.run, .{&stub});
    defer fut2.await(io);
    var m = try r.query("example.com", .a);
    m.deinit();
}

test "cookies: BADCOOKIE is asked once more with the server cookie it carried" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .badcookie, 2);
    defer stub.sock.close(io);
    var fut = try io.concurrent(Stub.run, .{&stub});
    defer fut.await(io);
    var r = resolver(io, &one_server, stub.sock.address.getPort());
    r.options.cookies = true;
    defer r.deinit();
    var m = try r.query("example.com", .a);
    defer m.deinit();
    try testing.expectEqual(message.Rcode.no_error, m.rcode());
    try testing.expectEqual(@as(usize, 1), m.answers.len);
    try testing.expectEqual(@as(usize, 2), stub.served);
    try testing.expectEqual(@as(usize, 8), stub.cookie_len[0]);
    try testing.expectEqual(@as(usize, 16), stub.cookie_len[1]);
    try testing.expectEqualSlices(u8, server_cookie, &stub.server_part[1]);
}

test "failover memory: a server that failed goes last until retried; none without the option" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]?Resolver.Failover{ null, .{ .retry_delay_ms = 3_600_000, .retry_percent = 0 }, .{ .retry_delay_ms = 0, .retry_percent = 100 } }, [_]usize{ 3, 1, 3 }) |fo, want_first| {
        var a = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .servfail, 3);
        defer a.sock.close(io);
        var b = try bindStub(io, .{ 127, 0, 0, 2 }, a.sock.address.getPort(), .answer, 3);
        defer b.sock.close(io);
        var fa = try io.concurrent(Stub.run, .{&a});
        var fb = try io.concurrent(Stub.run, .{&b});
        var r = resolver(io, &two_servers, a.sock.address.getPort());
        r.options.server_failover = fo;
        for (0..3) |_| {
            var m = try r.query("example.com", .a);
            try testing.expectEqual(@as(usize, 1), m.answers.len);
            m.deinit();
        }
        r.deinit();
        // Unblock a stub still waiting for datagrams the resolver will not send.
        a.max = a.served;
        b.max = b.served;
        fa.cancel(io);
        fb.cancel(io);
        // Without memory, or with every retry due, A is asked first every time;
        // with memory only the first query reaches it.
        try testing.expectEqual(want_first, a.served);
        try testing.expectEqual(@as(usize, 3), b.served);
    }
}

test "failover memory: every server down still returns the last failure, as before" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .servfail, 2);
    defer a.sock.close(io);
    var b = try bindStub(io, .{ 127, 0, 0, 2 }, a.sock.address.getPort(), .servfail, 2);
    defer b.sock.close(io);
    var fa = try io.concurrent(Stub.run, .{&a});
    var fb = try io.concurrent(Stub.run, .{&b});
    var r = resolver(io, &two_servers, a.sock.address.getPort());
    r.options.server_failover = .{ .retry_delay_ms = 3_600_000, .retry_percent = 0 };
    defer r.deinit();
    for (0..2) |_| {
        var m = try r.query("example.com", .a);
        try testing.expectEqual(message.Rcode.serv_fail, m.rcode());
        m.deinit();
    }
    fa.await(io);
    fb.await(io);
    try testing.expectEqual(@as(usize, 2), a.served);
    try testing.expectEqual(@as(usize, 2), b.served);
}

const lo3 = netaddr.Ip{ .v4 = .{ 127, 0, 0, 3 } };
const three_servers = [_]netaddr.Ip{ lo1, lo2, lo3 };

fn firstA(m: *const message.Message) [4]u8 {
    return m.answers[0].data.a;
}

test "routes: split DNS sends each name to its own servers; a route without servers is refused" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .answer, 2);
    defer a.sock.close(io);
    a.ip = .{ 192, 0, 2, 10 };
    var b = try bindStub(io, .{ 127, 0, 0, 2 }, a.sock.address.getPort(), .answer, 2);
    defer b.sock.close(io);
    b.ip = .{ 192, 0, 2, 20 };
    var fa = try io.concurrent(Stub.run, .{&a});
    var fb = try io.concurrent(Stub.run, .{&b});
    const to_b = [_]netaddr.Ip{lo2};
    const routes = [_]Resolver.Route{.{ .domain = "corp.example", .servers = &to_b }};
    var r = resolver(io, &one_server, a.sock.address.getPort());
    r.options.routes = &routes;
    defer r.deinit();
    for ([_][]const u8{ "www.corp.example", "www.public.example", "corp.example", "notcorp.example" }, [_][4]u8{ b.ip, a.ip, b.ip, a.ip }) |name, want| {
        var m = try r.query(name, .a);
        defer m.deinit();
        try testing.expectEqualSlices(u8, &want, &firstA(&m));
    }
    try testing.expectEqual(@as(usize, 2), a.served);
    try testing.expectEqual(@as(usize, 2), b.served);
    fa.await(io);
    fb.await(io);
    const empty = [_]Resolver.Route{.{ .domain = "x", .servers = &.{} }};
    r.options.routes = &empty;
    try testing.expectError(error.InvalidOptions, r.query("a.example", .a));
}

test "parallel servers: the first usable reply wins, a slow server does not hold the query" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .answer, 1);
    defer a.sock.close(io);
    a.ip = .{ 192, 0, 2, 10 };
    a.delay_ms = 700;
    var b = try bindStub(io, .{ 127, 0, 0, 2 }, a.sock.address.getPort(), .answer, 1);
    defer b.sock.close(io);
    b.ip = .{ 192, 0, 2, 20 };
    var fa = try io.concurrent(Stub.run, .{&a});
    var fb = try io.concurrent(Stub.run, .{&b});
    var r = resolver(io, &two_servers, a.sock.address.getPort());
    r.options.timeout_ms = 3000;
    r.options.parallel_servers = 2;
    defer r.deinit();
    var m = try r.query("example.com", .a);
    defer m.deinit();
    try testing.expectEqualSlices(u8, &b.ip, &firstA(&m)); // serial would have waited for A
    try testing.expectEqual(@as(usize, 1), a.seen); // and A was asked too
    fa.cancel(io);
    fb.await(io);
}

test "parallel servers: failure replies do not win, groups follow one another, serial stays serial" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]u8{ 2, 3, 1 }, [_]usize{ 1, 1, 1 }) |par, want_third| {
        var a = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .servfail, 1);
        defer a.sock.close(io);
        var b = try bindStub(io, .{ 127, 0, 0, 2 }, a.sock.address.getPort(), .servfail, 1);
        defer b.sock.close(io);
        var c = try bindStub(io, .{ 127, 0, 0, 3 }, a.sock.address.getPort(), .answer, 1);
        defer c.sock.close(io);
        c.ip = .{ 192, 0, 2, 30 };
        var fa = try io.concurrent(Stub.run, .{&a});
        var fb = try io.concurrent(Stub.run, .{&b});
        var fc = try io.concurrent(Stub.run, .{&c});
        var r = resolver(io, &three_servers, a.sock.address.getPort());
        r.options.parallel_servers = par;
        var m = try r.query("example.com", .a);
        try testing.expectEqualSlices(u8, &c.ip, &firstA(&m));
        m.deinit();
        r.deinit();
        fa.await(io);
        fb.await(io);
        fc.await(io);
        try testing.expectEqual(want_third, c.served);
        try testing.expectEqual(@as(usize, 1), a.served);
        try testing.expectEqual(@as(usize, 1), b.served);
    }
}

test "parallel servers: every server failing still returns the failure; zero is refused" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .servfail, 1);
    defer a.sock.close(io);
    var b = try bindStub(io, .{ 127, 0, 0, 2 }, a.sock.address.getPort(), .servfail, 1);
    defer b.sock.close(io);
    var fa = try io.concurrent(Stub.run, .{&a});
    var fb = try io.concurrent(Stub.run, .{&b});
    var r = resolver(io, &two_servers, a.sock.address.getPort());
    r.options.parallel_servers = 2;
    defer r.deinit();
    var m = try r.query("example.com", .a);
    try testing.expectEqual(message.Rcode.serv_fail, m.rcode());
    m.deinit();
    fa.await(io);
    fb.await(io);
    r.options.parallel_servers = 0;
    try testing.expectError(error.InvalidOptions, r.query("example.com", .a));
}

test "filter_addresses: a filtered answer is NODATA, a kept one stays; private_ranges cover the usual suspects" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .answer, 3);
    defer stub.sock.close(io);
    stub.ip = .{ 10, 1, 2, 3 };
    var fut = try io.concurrent(Stub.run, .{&stub});
    defer fut.cancel(io);
    var r = resolver(io, &one_server, stub.sock.address.getPort());
    r.options.family = .v4;
    defer r.deinit();
    var plain = try r.lookupIp("example.com");
    try testing.expectEqual(@as(usize, 1), plain.items.len);
    plain.deinit();
    r.options.filter_addresses = &Resolver.private_ranges;
    var gone = try r.lookupIp("example.com");
    try testing.expectEqual(@as(usize, 0), gone.items.len);
    try testing.expectEqual(Resolver.Status.nodata, gone.status);
    gone.deinit();
    const other = [_]netaddr.Prefix{netaddr.parsePrefix("192.0.2.0/24").?};
    r.options.filter_addresses = &other;
    var kept = try r.lookupIp("example.com");
    try testing.expectEqual(@as(usize, 1), kept.items.len);
    kept.deinit();
}

test "server metrics: per-server queries, replies, rcode failures, timeouts and round-trip time" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a = try bindStub(io, .{ 127, 0, 0, 1 }, 0, .silent, 2);
    defer a.sock.close(io);
    var b = try bindStub(io, .{ 127, 0, 0, 2 }, a.sock.address.getPort(), .servfail, 2);
    defer b.sock.close(io);
    var c = try bindStub(io, .{ 127, 0, 0, 3 }, a.sock.address.getPort(), .answer, 2);
    defer c.sock.close(io);
    var fa = try io.concurrent(Stub.run, .{&a});
    var fb = try io.concurrent(Stub.run, .{&b});
    var fc = try io.concurrent(Stub.run, .{&c});
    var r = resolver(io, &three_servers, a.sock.address.getPort());
    r.options.server_metrics = true;
    r.options.timeout_ms = 200;
    defer r.deinit();
    var none: [4]Resolver.ServerStats = undefined;
    for (0..2) |_| {
        var m = try r.query("example.com", .a);
        m.deinit();
    }
    fa.await(io);
    fb.await(io);
    fc.await(io);
    const n = r.serverStats(&none);
    try testing.expectEqual(@as(usize, 3), n);
    for (none[0..n]) |s| {
        if (s.server.eql(lo1)) {
            try testing.expectEqual(@as(u64, 2), s.queries);
            try testing.expectEqual(@as(u64, 2), s.timeouts);
            try testing.expectEqual(@as(u64, 0), s.replies);
            try testing.expectEqual(@as(?u64, null), s.rttMeanNs());
        } else if (s.server.eql(lo2)) {
            try testing.expectEqual(@as(u64, 2), s.queries);
            try testing.expectEqual(@as(u64, 2), s.replies);
            try testing.expectEqual(@as(u64, 2), s.failure_rcodes);
        } else {
            try testing.expect(s.server.eql(lo3));
            try testing.expectEqual(@as(u64, 2), s.queries);
            try testing.expectEqual(@as(u64, 2), s.replies);
            try testing.expectEqual(@as(u64, 0), s.failure_rcodes);
            try testing.expect(s.rttMeanNs() != null);
            try testing.expect(s.rtt_last_ns > 0);
        }
    }
    // Off by default: nothing is kept.
    var q = resolver(io, &one_server, 1);
    defer q.deinit();
    try testing.expectEqual(@as(usize, 0), q.serverStats(&none));
}
