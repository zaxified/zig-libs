// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GX). Each test names the finding it kills.

const std = @import("std");
const testing = std.testing;
const netaddr = @import("netaddr");
const root = @import("root.zig");

test "Hop.stats with more probes than max_probes_per_hop (sweep TR1)" {
    var probes: [root.max_probes_per_hop * 3]root.Probe = undefined;
    for (&probes, 0..) |*p, i| {
        p.* = if (i % 2 == 0) .{ .kind = .reply, .rtt_ns = 1000 + i } else .{};
    }
    const hop: root.Hop = .{ .ttl = 1, .probes = &probes };
    const st = hop.stats();
    try testing.expectEqual(@as(u64, probes.len), st.sent);
    try testing.expectEqual(@as(u64, probes.len / 2), st.received);
    try testing.expectEqual(@as(u64, 1000), st.min_ns);
}

test "Hop.distinctAddresses with a buffer shorter than probes (sweep TR2)" {
    var probes: [6]root.Probe = undefined;
    for (&probes, 0..) |*p, i| {
        p.* = .{ .kind = .time_exceeded, .address = .{ .v4 = .{ 10, 0, 0, @intCast(i) } } };
    }
    const hop: root.Hop = .{ .ttl = 1, .probes = &probes };
    var small: [2]netaddr.Ip = undefined;
    const got = hop.distinctAddresses(&small);
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expect(got[0].eql(probes[0].address.?));
    try testing.expect(got[1].eql(probes[1].address.?));
    var none: [0]netaddr.Ip = undefined;
    try testing.expectEqual(@as(usize, 0), hop.distinctAddresses(&none).len);
    var full: [6]netaddr.Ip = undefined;
    try testing.expectEqual(@as(usize, 6), hop.distinctAddresses(&full).len);
}

const Scripted = struct {
    now: u64,
    step: u64,
    flood: bool,
    recv_calls: usize = 0,

    fn transport(s: *Scripted, strip: bool) root.Transport {
        return .{ .ctx = s, .strip_ip_header = strip, .sendFn = send, .recvFn = recv, .nowFn = nowFn };
    }
    fn send(_: *anyopaque, _: u8, _: []const u8) root.TransportError!void {}
    fn nowFn(ctx: *anyopaque) u64 {
        const s: *Scripted = @ptrCast(@alignCast(ctx));
        const n = s.now;
        s.now +|= s.step;
        return n;
    }
    fn recv(ctx: *anyopaque, buf: []u8, _: u64) root.TransportError!?root.Packet {
        const s: *Scripted = @ptrCast(@alignCast(ctx));
        s.recv_calls += 1;
        if (!s.flood) return null;
        // Hostile garbage: IPv4 header claiming IHL 0, then junk.
        @memset(buf[0..64], 0xff);
        buf[0] = 0x40;
        return .{ .len = 64, .from = .{ .v4 = .{ 6, 6, 6, 6 } } };
    }
};

test "clock near maxInt(u64) cannot overflow the probe deadline (sweep TR3)" {
    var s: Scripted = .{ .now = std.math.maxInt(u64) - 5, .step = 0, .flood = false };
    var tr = try root.traceWith(testing.allocator, s.transport(false), .{ .v4 = .{ 192, 0, 2, 1 } }, .{ .max_hops = 2, .probes_per_hop = 1 });
    defer tr.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), tr.hops.len);
    try testing.expectEqual(root.Probe.Kind.timeout, tr.probes[0].kind);
}

test "a flood of garbage replies cannot stretch a probe past its deadline (sweep TR4)" {
    // Every recv returns a hostile packet and the clock advances 10 ms per
    // reading; the 1 s probe window must end after ~100 readings, not loop on.
    var s: Scripted = .{ .now = 1_000, .step = 10 * std.time.ns_per_ms, .flood = true };
    var tr = try root.traceWith(testing.allocator, s.transport(true), .{ .v4 = .{ 192, 0, 2, 1 } }, .{ .max_hops = 3, .probes_per_hop = 2, .timeout_ms = 1000 });
    defer tr.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), tr.hops.len);
    for (tr.probes) |p| try testing.expectEqual(root.Probe.Kind.timeout, p.kind);
    // 6 probes x ~100 windows: bounded, and nowhere near unbounded.
    try testing.expect(s.recv_calls <= 6 * 101);
}
