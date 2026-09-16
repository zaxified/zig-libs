// SPDX-License-Identifier: MIT
//
// WHAT THIS ASKS. A caller pins headers on a request — `Host` (the vhost /
// SNI-less-routing idiom), `Authorization`, `Cookie`, `Proxy-Authorization`,
// `X-Api-Key` — and the first hop answers 302 to a DIFFERENT ORIGIN. Which of
// those headers does `Client` carry onto the second hop?
//
// The origins differ by PORT, not host: same 127.0.0.1, different listener. A
// probe that changed the host as well would prove nothing about which half of
// the origin triple (scheme, host, port) the check actually reads.
//
// WHY THIS IS A PROBE AND NOT A UNIT TEST. What is being observed is the bytes
// on hop TWO — so there have to be two real listeners, two threads, and a real
// redirect chain between them. `CONVENTIONS.md` §9 puts that in `tools/`.
//
// WHAT IT PRODUCES. Both hops' request heads verbatim, and for each hop whether
// each credential survived. Nothing is asserted: a credential surviving a
// SAME-origin hop is correct, and which headers a cross-origin hop may keep is
// a policy this module records in SPEC.md rather than a universal truth.
//
// MEASURED 2026-09-16 against this tree: hop 1 receives all five headers and
// the caller's `Host: vhost.internal`. Hop 2 — cross-origin — receives neither
// `Authorization` nor `Cookie` nor `Proxy-Authorization`, and the caller's
// `Host` is replaced by the real one; `X-Api-Key` DOES survive. That last one
// is the recorded default, not an oversight: the module strips the credentials
// it can name and does not guess at bearer-shaped custom headers. A consumer
// that ships its own credential header keeps it off a cross-origin hop with
// `RequestOptions.redirect_filter`, which is also the destination gate for
// loopback / link-local / RFC1918 targets.
//
// ⚠ Loopback only. No external host is contacted, and none should be added:
// this is an `interop`-class program in the sense of §9, not a `live` one.
const std = @import("std");
const http = @import("http");
const net = std.Io.net;

const Hop = struct {
    io: std.Io,
    listener: *net.Server,
    /// "" = answer 200 instead of redirecting.
    location: []const u8,
    seen: [2048]u8 = undefined,
    seen_len: usize = 0,
    label: []const u8,

    fn run(h: *Hop) void {
        const s = h.listener.accept(h.io) catch return;
        defer s.close(h.io);
        var rbuf: [4096]u8 = undefined;
        var wbuf: [1024]u8 = undefined;
        var sr = s.reader(h.io, &rbuf);
        var sw = s.writer(h.io, &wbuf);
        while (h.seen_len < h.seen.len) {
            const avail = sr.interface.peekGreedy(1) catch break;
            const take = @min(avail.len, h.seen.len - h.seen_len);
            @memcpy(h.seen[h.seen_len..][0..take], avail[0..take]);
            h.seen_len += take;
            sr.interface.toss(take);
            if (std.mem.indexOf(u8, h.seen[0..h.seen_len], "\r\n\r\n") != null) break;
        }
        if (h.location.len == 0) {
            sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok") catch {};
        } else {
            sw.interface.print("HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{h.location}) catch {};
        }
        sw.interface.flush() catch {};
    }

    fn hostLine(h: *const Hop) []const u8 {
        const b = h.seen[0..h.seen_len];
        const i = std.mem.indexOf(u8, b, "Host: ") orelse return "(none)";
        const j = std.mem.indexOfPos(u8, b, i, "\r\n") orelse b.len;
        return b[i..j];
    }
    fn firstLine(h: *const Hop) []const u8 {
        const b = h.seen[0..h.seen_len];
        const j = std.mem.indexOf(u8, b, "\r\n") orelse b.len;
        return b[0..j];
    }
};

/// Release a hop still parked in `accept()`; see `probe_injection.zig`'s `wake`
/// for why an instrument must be able to observe "nobody dialed".
fn wake(io: std.Io, addr: net.IpAddress) void {
    const s = addr.connect(io, .{ .mode = .stream }) catch return;
    s.close(io);
}

pub fn main() !void {
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbg.deinit();
    const gpa = dbg.allocator();
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    std.debug.print("optimize mode = {s}\n\n", .{@tagName(@import("builtin").mode)});

    const addr = try net.IpAddress.parse("127.0.0.1", 0);

    // Hop 2 first — hop 1's Location has to name its port.
    var l2 = try addr.listen(io, .{});
    defer l2.deinit(io);
    const a2 = l2.socket.address;
    var h2: Hop = .{ .io = io, .listener = &l2, .location = "", .label = "hop2 (cross-origin)" };

    var l1 = try addr.listen(io, .{});
    defer l1.deinit(io);
    const a1 = l1.socket.address;
    var loc_buf: [64]u8 = undefined;
    // Cross-origin by PORT: same host, different port -> a different origin.
    const loc = try std.fmt.bufPrint(&loc_buf, "http://127.0.0.1:{d}/second", .{a2.getPort()});
    var h1: Hop = .{ .io = io, .listener = &l1, .location = loc, .label = "hop1 (origin)" };

    const t1 = try std.Thread.spawn(.{}, Hop.run, .{&h1});
    const t2 = try std.Thread.spawn(.{}, Hop.run, .{&h2});

    var c = http.Client.init(io, gpa, .{ .pool = .{ .enabled = false }, .total_timeout_ms = 5000 });
    defer c.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/first", .{a1.getPort()});

    if (c.requestPlain(.get, url, .{ .headers = &.{
        .{ .name = "Host", .value = "vhost.internal" },
        .{ .name = "Authorization", .value = "Bearer SECRET" },
        .{ .name = "Cookie", .value = "sid=SECRET" },
        .{ .name = "Proxy-Authorization", .value = "Basic SECRET" },
        .{ .name = "X-Api-Key", .value = "SECRET" },
    } })) |*r| {
        var rr = r.*;
        std.debug.print("final status = {d}\n", .{rr.status});
        rr.deinit();
    } else |e| std.debug.print("client error: {s}\n", .{@errorName(e)});

    // If the chain stopped early, whichever hop was never dialed is still in
    // `accept()`; releasing both makes "it did not happen" a printable result.
    wake(io, a1);
    wake(io, a2);
    t1.join();
    t2.join();

    inline for (.{ &h1, &h2 }) |h| {
        std.debug.print("\n--- {s} ---\n{s}\n", .{ h.label, h.seen[0..h.seen_len] });
        std.debug.print(">>> request-line : {s}\n>>> Host header  : {s}\n", .{ h.firstLine(), h.hostLine() });
        const b = h.seen[0..h.seen_len];
        std.debug.print(">>> Authorization: {}   Cookie: {}   Proxy-Authorization: {}   X-Api-Key: {}\n", .{
            std.mem.indexOf(u8, b, "Authorization: Bearer SECRET") != null,
            std.mem.indexOf(u8, b, "Cookie: sid=SECRET") != null,
            std.mem.indexOf(u8, b, "Proxy-Authorization: Basic SECRET") != null,
            std.mem.indexOf(u8, b, "X-Api-Key: SECRET") != null,
        });
    }
    std.debug.print("\nhop1 was 127.0.0.1:{d}, hop2 was 127.0.0.1:{d}\n", .{ a1.getPort(), a2.getPort() });
}
