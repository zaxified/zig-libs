// SPDX-License-Identifier: MIT

//! OFFLINE replay of the kernel oracle (`tools/interop.zig` +
//! `tools/kernel_oracle.py`, frozen in `kernel_oracle_vectors.zig`). Real
//! routers in a client -> r1 -> r2 -> r3 -> server chain of network
//! namespaces answered every probe below: Time Exceeded from each router's
//! client-side address, Echo Reply / Port Unreachable from the server,
//! Administratively Prohibited from a filtering router, silence from a router
//! whose errors are dropped and from a server that drops everything. Each hop
//! is what the topology puts at that TTL, and traceroute(8) traced the same.
//! `traceWith` must send the very same probes, in the same order, and report
//! the very same trace. No namespaces at test time: the replay requires the
//! routers' own packets.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const vectors = @import("kernel_oracle_vectors.zig");

/// Plays a transcript back: every send must be the recorded one, every
/// receive returns the recorded packet or timeout, and the clock is the
/// recorder's -- +1 ms per reading, +the whole timeout on a timeout.
const Replay = struct {
    events: []const vectors.Event,
    next: usize = 0,
    clock: u64 = 1_000_000_000,
    diverged: bool = false,

    fn transport(self: *Replay, strip: bool) root.Transport {
        return .{ .ctx = self, .strip_ip_header = strip, .sendFn = sendFn, .sendUdpFn = sendUdpFn, .recvFn = recvFn, .nowFn = nowFn };
    }

    fn take(self: *Replay) ?vectors.Event {
        if (self.next >= self.events.len) return null;
        defer self.next += 1;
        return self.events[self.next];
    }

    fn sendFn(ctx: *anyopaque, ttl: u8, packet: []const u8) root.TransportError!void {
        const self: *Replay = @ptrCast(@alignCast(ctx));
        const e = self.take() orelse return self.fail();
        if (e != .send or e.send.ttl != ttl or !std.mem.eql(u8, e.send.bytes, packet)) return self.fail();
    }

    fn sendUdpFn(ctx: *anyopaque, ttl: u8, port: u16, payload: []const u8) root.TransportError!void {
        const self: *Replay = @ptrCast(@alignCast(ctx));
        const e = self.take() orelse return self.fail();
        if (e != .send_udp or e.send_udp.ttl != ttl or e.send_udp.port != port or !std.mem.eql(u8, e.send_udp.bytes, payload))
            return self.fail();
    }

    fn recvFn(ctx: *anyopaque, buf: []u8, timeout_ns: u64) root.TransportError!?root.Packet {
        const self: *Replay = @ptrCast(@alignCast(ctx));
        const e = self.take() orelse {
            self.diverged = true;
            return error.RecvFailed;
        };
        switch (e) {
            .recv => |r| {
                @memcpy(buf[0..r.bytes.len], r.bytes);
                return .{ .len = r.bytes.len, .from = r.from };
            },
            .timeout => {
                self.clock += timeout_ns;
                return null;
            },
            else => {
                self.diverged = true;
                return error.RecvFailed;
            },
        }
    }

    fn nowFn(ctx: *anyopaque) u64 {
        const self: *Replay = @ptrCast(@alignCast(ctx));
        self.clock += 1_000_000;
        return self.clock;
    }

    fn fail(self: *Replay) error{SendFailed} {
        self.diverged = true;
        return error.SendFailed;
    }
};

test "kernel oracle: traceWith replays every real transcript to the trace the topology dictates" {
    try testing.expectEqual(@as(usize, 16), vectors.scenarios.len);
    for (vectors.scenarios) |sc| {
        var rp: Replay = .{ .events = sc.events };
        const opts: root.Options = .{
            .method = sc.method,
            .ident = sc.ident,
            .max_hops = vectors.max_hops,
            .probes_per_hop = vectors.probes_per_hop,
            .timeout_ms = vectors.timeout_ms,
        };
        var tr = try root.traceWith(testing.allocator, rp.transport(sc.dest == .v4), sc.dest, opts);
        defer tr.deinit(testing.allocator);
        if (rp.diverged or rp.next != sc.events.len)
            std.debug.print("{s}: replay left the transcript at event {d} of {d}\n", .{ sc.name, rp.next, sc.events.len });
        try testing.expect(!rp.diverged);
        try testing.expectEqual(sc.events.len, rp.next);
        try testing.expectEqual(@as(?root.TransportError, null), tr.transport_err);
        try testing.expectEqual(sc.reached, tr.reached);
        try testing.expectEqual(sc.unreachable_code, tr.unreachable_code);
        try testing.expectEqual(sc.hops.len, tr.hops.len);
        for (sc.hops, tr.hops) |want, got| {
            try testing.expectEqual(want.len, got.probes.len);
            for (want, got.probes) |w, g| {
                try testing.expectEqual(w.kind, g.kind);
                try testing.expectEqual(w.code, g.code);
                try testing.expectEqual(w.rtt_ns, g.rtt_ns);
                if (w.address) |a| try testing.expect(a.eql(g.address.?)) else try testing.expect(g.address == null);
            }
        }
    }
}
