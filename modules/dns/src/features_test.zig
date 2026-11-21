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
    cookie_len: [4]usize = @splat(0),
    client: [4][8]u8 = @splat(@splat(0)),
    server_part: [4][8]u8 = @splat(@splat(0)),

    const Mode = enum { answer, servfail, cookie_good, cookie_bad_client, badcookie };

    fn run(st: *Stub) void {
        while (st.served < st.max) st.serveOne() catch return;
    }

    fn serveOne(st: *Stub) !void {
        var rbuf: [message.max_query_len]u8 = undefined;
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake } };
        const incoming = try st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io));
        const q = incoming.data;
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
        const answer = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01";
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
