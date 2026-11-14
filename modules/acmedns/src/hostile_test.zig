// SPDX-License-Identifier: MIT

//! A publisher's HTTP endpoint is the other side of the wire: one that sends
//! its response head and then goes quiet must not park the solver (the
//! client's `total_timeout_ms` ends at the head, the body read needs its own
//! deadline).

const std = @import("std");
const testkit = @import("testkit");
const root = @import("root.zig");
const publishers = @import("publishers.zig");

const testing = std.testing;
const net = std.Io.net;

/// Reads the request head, answers `200` with `Content-Length: 5` and no body,
/// and closes after `hold_ms`. A client that waits for the body is released
/// by that close (so the test fails instead of hanging).
const HeadThenSilentPeer = struct {
    io: std.Io,
    listener: *net.Server,
    hold_ms: i64 = 3000,
    stop: std.atomic.Value(u32) = .init(0),
    accepted: std.atomic.Value(u32) = .init(0),

    fn run(p: *HeadThenSilentPeer) void {
        const s = p.listener.accept(p.io) catch return;
        p.accepted.store(1, .release);
        defer s.close(p.io);
        var rbuf: [4096]u8 = undefined;
        var wbuf: [256]u8 = undefined;
        var sr = s.reader(p.io, &rbuf);
        var sw = s.writer(p.io, &wbuf);
        // Everything up to the blank line; the (small) request body stays in
        // the socket buffer, unread.
        var seen: usize = 0;
        while (seen < 100) : (seen += 1) {
            const line = sr.interface.takeDelimiterInclusive('\n') catch break;
            if (std.mem.eql(u8, line, "\r\n")) break;
        }
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n") catch {};
        sw.interface.flush() catch {};
        var waited: i64 = 0;
        while (p.stop.load(.acquire) == 0 and waited < p.hold_ms) : (waited += 5)
            p.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }

    /// Release the thread before joining it; poke `accept` when the client
    /// never connected.
    fn release(p: *HeadThenSilentPeer, port: u16) void {
        p.stop.store(1, .release);
        if (p.accepted.load(.acquire) != 0) return;
        const addr = net.IpAddress.parse("127.0.0.1", port) catch return;
        const s = addr.connect(p.io, .{ .mode = .stream }) catch return;
        s.close(p.io);
    }
};

fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Clock.Timestamp.now(io, .awake);
    return @intCast(@divTrunc(ts.raw.nanoseconds, std.time.ns_per_ms));
}

const rec: root.Record = .{
    .domain = "a.test",
    .fqdn = "_acme-challenge.a.test",
    .zone = "a.test",
    .value = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
    .token = "tok",
    .key_authorization = "tok.thumb",
};

test "HttpReq.present: an endpoint that sends its head and stalls ends at the timeout (sweep AD-2)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| return testkit.loopbackSkip("listen failed ({t})", .{err});
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    var peer: HeadThenSilentPeer = .{ .io = io, .listener = &listener };
    const th = try std.Thread.spawn(.{}, HeadThenSilentPeer.run, .{&peer});
    defer th.join();
    defer peer.release(port);

    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/hook", .{port});
    var pub_ = publishers.HttpReq.init(io, testing.allocator, .{ .endpoint = url, .http = .{ .total_timeout_ms = 300 } });
    defer pub_.deinit();
    const t0 = nowMs(io);
    try testing.expectError(error.PublishFailed, pub_.publisher().present(pub_.publisher().ctx, &rec));
    // The peer would have held the connection for 3 s.
    try testing.expect(nowMs(io) - t0 < 1500);
}

test "AcmeDns.register: a server that sends its head and stalls ends at the timeout (sweep AD-2)" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| return testkit.loopbackSkip("listen failed ({t})", .{err});
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    var peer: HeadThenSilentPeer = .{ .io = io, .listener = &listener };
    const th = try std.Thread.spawn(.{}, HeadThenSilentPeer.run, .{&peer});
    defer th.join();
    defer peer.release(port);

    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}", .{port});
    const t0 = nowMs(io);
    if (publishers.AcmeDns.register(io, testing.allocator, url, .{ .total_timeout_ms = 300 }, &.{})) |*parsed| {
        parsed.deinit();
        return error.ExpectedAnError;
    } else |_| {}
    try testing.expect(nowMs(io) - t0 < 1500);
}
