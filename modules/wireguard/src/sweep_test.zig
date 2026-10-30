// SPDX-License-Identifier: MIT
//! No-panic sweep tests for the control plane (root.zig), wave GR (gr-a).
//! Every test name ends with the finding ID it kills (`WG-n`) or `WG-clean`
//! for a table of hostile inputs the sweep found already handled.

const std = @import("std");
const builtin = @import("builtin");
const netlink = @import("netlink");
const codec = netlink.codec;
const wg = @import("root.zig");
const testing = std.testing;
const native = builtin.cpu.arch.endian();

fn put(gpa: std.mem.Allocator, l: *std.ArrayList(u8), t: u16, data: []const u8) !void {
    try codec.appendAttr(gpa, l, t, data);
}

fn open(gpa: std.mem.Allocator, l: *std.ArrayList(u8), t: u16) !usize {
    return codec.nestBegin(gpa, l, t | codec.NLA_F_NESTED);
}

/// genlmsghdr + WGDEVICE_A_PEERS { one peer entry { `inner` } }.
fn wrap(gpa: std.mem.Allocator, inner: []const u8) ![]u8 {
    var l: std.ArrayList(u8) = .empty;
    errdefer l.deinit(gpa);
    try l.appendSlice(gpa, &.{ 0, 1, 0, 0 });
    const peers = try open(gpa, &l, wg.WGDEVICE_A.PEERS);
    const entry = try open(gpa, &l, 0);
    try l.appendSlice(gpa, inner);
    try codec.nestEnd(&l, entry);
    try codec.nestEnd(&l, peers);
    return l.toOwnedSlice(gpa);
}

fn keyBytes(b: u8) wg.Key {
    return @splat(b);
}

/// WGPEER_A_PUBLIC_KEY + WGPEER_A_ALLOWEDIPS { `n` well-formed v4 entries }.
fn peerWithIps(gpa: std.mem.Allocator, key: wg.Key, first: u32, n: u32) ![]u8 {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try put(gpa, &l, wg.WGPEER_A.PUBLIC_KEY, &key);
    const ips = try open(gpa, &l, wg.WGPEER_A.ALLOWEDIPS);
    for (0..n) |i| {
        const e = try open(gpa, &l, 0);
        var fam: [2]u8 = undefined;
        std.mem.writeInt(u16, &fam, wg.AF.INET, native);
        try put(gpa, &l, wg.WGALLOWEDIP_A.FAMILY, &fam);
        var a: [4]u8 = undefined;
        std.mem.writeInt(u32, &a, first +% @as(u32, @intCast(i)), .big);
        try put(gpa, &l, wg.WGALLOWEDIP_A.IPADDR, &a);
        try put(gpa, &l, wg.WGALLOWEDIP_A.CIDR_MASK, &.{32});
        try codec.nestEnd(&l, e);
    }
    try codec.nestEnd(&l, ips);
    return wrap(gpa, l.items);
}

/// Counts the bytes ever requested from `alloc` (resize/remap/free pass
/// through, they cost nothing a quadratic copy would hide in).
const Counting = struct {
    child: std.mem.Allocator,
    bytes: usize = 0,

    fn allocator(c: *Counting) std.mem.Allocator {
        return .{ .ptr = c, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.bytes += len;
        return c.child.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        return c.child.rawResize(m, a, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        return c.child.rawRemap(m, a, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.child.rawFree(m, a, ra);
    }
};

/// One peer whose allowed-ips arrive one per message (the continuation shape
/// a kernel dump produces when the datagram is full). Returns bytes allocated.
fn continuationBytes(n: u32) !usize {
    var c: Counting = .{ .child = testing.allocator };
    const gpa = c.allocator();
    var p: wg.DeviceParser = .init(gpa);
    defer p.deinit();
    for (0..n) |i| {
        const msg = try peerWithIps(testing.allocator, keyBytes(7), @intCast(i), 1);
        defer testing.allocator.free(msg);
        try p.feed(msg);
    }
    var dev = try p.finish();
    defer dev.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), dev.peers.len);
    try testing.expectEqual(@as(usize, n), dev.peers[0].allowed_ips.len);
    // Order preserved across the merge.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, dev.peers[0].allowed_ips[0].bytes());
    const last: u32 = n - 1;
    var want: [4]u8 = undefined;
    std.mem.writeInt(u32, &want, last, .big);
    try testing.expectEqualSlices(u8, &want, dev.peers[0].allowed_ips[n - 1].bytes());
    return c.bytes;
}

test "continuation merge is linear in the number of messages (sweep WG-1)" {
    const small = try continuationBytes(500);
    const big = try continuationBytes(2000);
    // 4x the messages: linear allocation is ~4x, the old exact-size
    // realloc-per-message merge is ~16x.
    try testing.expect(big < small * 9);
}

fn parseThreeMessages(gpa: std.mem.Allocator, msgs: []const []const u8) !void {
    var p: wg.DeviceParser = .init(gpa);
    defer p.deinit();
    for (msgs) |m| try p.feed(m);
    var dev = try p.finish();
    defer dev.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), dev.peers.len);
    try testing.expectEqual(@as(usize, 3), dev.peers[0].allowed_ips.len);
    try testing.expectEqual(@as(usize, 2), dev.peers[1].allowed_ips.len);
}

test "continuation merge: every allocation failure leaves nothing behind (sweep WG-1)" {
    const gpa = testing.allocator;
    const m1 = try peerWithIps(gpa, keyBytes(1), 0, 2);
    defer gpa.free(m1);
    const m2 = try peerWithIps(gpa, keyBytes(1), 10, 1); // continuation of peer 1
    defer gpa.free(m2);
    const m3 = try peerWithIps(gpa, keyBytes(2), 20, 2); // a new peer
    defer gpa.free(m3);
    try testing.checkAllAllocationFailures(gpa, parseThreeMessages, .{&[_][]const u8{ m1, m2, m3 }});
}

test "a different key in the first peer of a message does not merge (sweep WG-1)" {
    const gpa = testing.allocator;
    var p: wg.DeviceParser = .init(gpa);
    defer p.deinit();
    for ([_]u8{ 1, 2, 1 }) |k| {
        const m = try peerWithIps(gpa, keyBytes(k), k, 1);
        defer gpa.free(m);
        try p.feed(m);
    }
    var dev = try p.finish();
    defer dev.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), dev.peers.len);
    for (dev.peers) |peer| try testing.expectEqual(@as(usize, 1), peer.allowed_ips.len);
}

test "public value types are total on hand-built fields (sweep WG-2)" {
    const ip: wg.AllowedIp = .{ .family = wg.AF.INET, .addr_len = 200 };
    try testing.expectEqual(@as(usize, 16), ip.bytes().len);
    var d: wg.Device = .{};
    d.name_len = 255;
    try testing.expectEqual(@as(usize, wg.ifnamsiz), d.ifname().len);
    // ...and `buildSetRequests` still refuses such a value instead of sending it.
    try testing.expectError(error.InvalidConfig, wg.buildSetRequests(testing.allocator, 0x1c, 1, .{
        .ifname = "wg0",
        .peers = &.{.{ .public_key = keyBytes(1), .allowed_ips = &.{ip} }},
    }, 4096));
}

fn expectFeedError(inner: []const u8, want: anyerror) !void {
    const gpa = testing.allocator;
    const msg = try wrap(gpa, inner);
    defer gpa.free(msg);
    var p: wg.DeviceParser = .init(gpa);
    defer p.deinit();
    try testing.expectError(want, p.feed(msg));
}

test "hostile kernel replies are errors, never panics (sweep WG-clean)" {
    const gpa = testing.allocator;
    // Shorter than a genlmsghdr.
    {
        var p: wg.DeviceParser = .init(gpa);
        defer p.deinit();
        try testing.expectError(error.Truncated, p.feed(&.{ 0, 1 }));
    }
    const key = keyBytes(9);
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);

    // Peer without a public key.
    try expectFeedError("", error.BadLength);
    // Key attribute of 31 bytes.
    try put(gpa, &l, wg.WGPEER_A.PUBLIC_KEY, key[0..31]);
    try expectFeedError(l.items, error.BadLength);
    // Attribute whose length field is below the header size, and one that
    // overruns its parent.
    try expectFeedError(&.{ 3, 0, 1, 0 }, error.BadLength);
    try expectFeedError(&.{ 200, 0, 1, 0, 0, 0, 0, 0 }, error.Truncated);
    try expectFeedError(&.{ 4, 0 }, error.Truncated);

    // Endpoint of 15 bytes; timespec of 8; v6 endpoint with a v4 family.
    for ([_]struct { t: u16, n: usize }{
        .{ .t = wg.WGPEER_A.ENDPOINT, .n = 15 },
        .{ .t = wg.WGPEER_A.LAST_HANDSHAKE_TIME, .n = 8 },
        .{ .t = wg.WGPEER_A.ENDPOINT, .n = 28 }, // family bytes are zero
        .{ .t = wg.WGPEER_A.RX_BYTES, .n = 4 },
    }) |c| {
        l.clearRetainingCapacity();
        try put(gpa, &l, wg.WGPEER_A.PUBLIC_KEY, &key);
        const zeros: [32]u8 = @splat(0);
        try put(gpa, &l, c.t, zeros[0..c.n]);
        try expectFeedError(l.items, error.BadLength);
    }

    // Allowed-ip entries: cidr 33 on v4, family 7, address of 5 bytes, a
    // missing cidr, cidr 129 on v6.
    const Case = struct { fam: u16, addr_len: usize, cidr: ?u8 };
    for ([_]Case{
        .{ .fam = wg.AF.INET, .addr_len = 4, .cidr = 33 },
        .{ .fam = 7, .addr_len = 4, .cidr = 8 },
        .{ .fam = wg.AF.INET, .addr_len = 5, .cidr = 8 },
        .{ .fam = wg.AF.INET, .addr_len = 4, .cidr = null },
        .{ .fam = wg.AF.INET6, .addr_len = 16, .cidr = 129 },
        .{ .fam = wg.AF.INET6, .addr_len = 4, .cidr = 8 },
    }) |c| {
        l.clearRetainingCapacity();
        try put(gpa, &l, wg.WGPEER_A.PUBLIC_KEY, &key);
        const ips = try open(gpa, &l, wg.WGPEER_A.ALLOWEDIPS);
        const e = try open(gpa, &l, 0);
        var fam: [2]u8 = undefined;
        std.mem.writeInt(u16, &fam, c.fam, native);
        try put(gpa, &l, wg.WGALLOWEDIP_A.FAMILY, &fam);
        const addr: [16]u8 = @splat(1);
        try put(gpa, &l, wg.WGALLOWEDIP_A.IPADDR, addr[0..c.addr_len]);
        if (c.cidr) |cm| try put(gpa, &l, wg.WGALLOWEDIP_A.CIDR_MASK, &.{cm});
        try codec.nestEnd(&l, e);
        try codec.nestEnd(&l, ips);
        try expectFeedError(l.items, error.BadLength);
    }

    // Extreme timespec values are data, not arithmetic: accepted verbatim.
    {
        l.clearRetainingCapacity();
        try put(gpa, &l, wg.WGPEER_A.PUBLIC_KEY, &key);
        var ts: [16]u8 = undefined;
        std.mem.writeInt(i64, ts[0..8], std.math.minInt(i64), native);
        std.mem.writeInt(i64, ts[8..16], std.math.maxInt(i64), native);
        try put(gpa, &l, wg.WGPEER_A.LAST_HANDSHAKE_TIME, &ts);
        const msg = try wrap(gpa, l.items);
        defer gpa.free(msg);
        var p: wg.DeviceParser = .init(gpa);
        defer p.deinit();
        try p.feed(msg);
        var dev = try p.finish();
        defer dev.deinit(gpa);
        try testing.expectEqual(@as(i64, std.math.minInt(i64)), dev.peers[0].last_handshake_time.sec);
    }

    // Device-level: interface name of 16 bytes (no room for the NUL).
    {
        var d: std.ArrayList(u8) = .empty;
        defer d.deinit(gpa);
        try d.appendSlice(gpa, &.{ 0, 1, 0, 0 });
        try put(gpa, &d, wg.WGDEVICE_A.IFNAME, "0123456789abcdef");
        var p: wg.DeviceParser = .init(gpa);
        defer p.deinit();
        try testing.expectError(error.BadLength, p.feed(d.items));
    }
}

test "builder: tiny and huge max_msg_len terminate with a result or AttrTooLong (sweep WG-clean)" {
    const gpa = testing.allocator;
    var ips: [3000]wg.AllowedIp = undefined;
    for (&ips, 0..) |*ip, i| ip.* = wg.AllowedIp.v4(.{ 10, 0, @intCast(i >> 8), @intCast(i & 255) }, 32);
    const cfg: wg.Config = .{ .ifname = "wg0", .peers = &.{
        .{ .public_key = keyBytes(1), .allowed_ips = &ips },
        .{ .public_key = keyBytes(2), .allowed_ips = &ips },
    } };
    for ([_]usize{ 0, 1, 20, 4096 }) |max| {
        var r = try wg.buildSetRequests(gpa, 0x1c, 0xffff_ffff, cfg, max);
        defer r.deinit(gpa);
        try testing.expect(r.msg_count >= 1);
    }
    // One message cannot express > 64 KiB of nest.
    try testing.expectError(error.AttrTooLong, wg.buildSetRequests(gpa, 0x1c, 1, cfg, std.math.maxInt(usize)));
    // An ifname of IFNAMSIZ bytes, and neither name nor index.
    try testing.expectError(error.InvalidConfig, wg.buildSetRequests(gpa, 0x1c, 1, .{ .ifname = "0123456789abcdef" }, 4096));
    try testing.expectError(error.InvalidConfig, wg.buildSetRequests(gpa, 0x1c, 1, .{}, 4096));
}

test "keyFromBase64 and AllowedIp.parse on hostile text (sweep WG-clean)" {
    const bad = [_][]const u8{
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 43
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 45
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", // wrong padding
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00",
    };
    for (bad) |t| try testing.expectError(error.InvalidKey, wg.keyFromBase64(t));
    const badip = [_][]const u8{
        "fe80::1%eth0/64", "10.0.0.1/999", "10.0.0.1/0x8", "::/", "1.2.3.4/ 8", "\x00", "10.0.0.0/08",
    };
    for (badip) |t| try testing.expectError(error.InvalidAllowedIp, wg.AllowedIp.parse(t));
}

/// A scripted transport: every `recvDatagram` yields one 16-byte netlink
/// message, forever.
const Script = struct {
    seq: u32 = 100,
    portid: u32 = 7,
    sends: usize = 0,
    recvs: usize = 0,
    msg_type: u16,
    flags: u16 = 0,
    foreign_seq: bool = false,
    buf: [16]u8 = undefined,

    pub fn portId(s: *const Script) u32 {
        return s.portid;
    }
    pub fn nextSeq(s: *Script) u32 {
        s.seq += 1;
        return s.seq;
    }
    pub fn send(s: *Script, _: []const u8) error{SendFailed}!void {
        s.sends += 1;
    }
    pub fn recvDatagram(s: *Script) error{RecvFailed}![]const u8 {
        s.recvs += 1;
        std.mem.writeInt(u32, s.buf[0..4], 16, native);
        std.mem.writeInt(u16, s.buf[4..6], s.msg_type, native);
        std.mem.writeInt(u16, s.buf[6..8], s.flags, native);
        std.mem.writeInt(u32, s.buf[8..12], if (s.foreign_seq) s.seq +% 1000 else s.seq, native);
        std.mem.writeInt(u32, s.buf[12..16], s.portid, native);
        return &s.buf;
    }
};

test "getDevice: a flood of foreign datagrams ends in TooManyMessages (sweep REV-WG-1)" {
    var t: Script = .{ .msg_type = 0x1c, .foreign_seq = true };
    var dev: wg.Device = undefined;
    try testing.expectError(error.TooManyMessages, wg.test_seam.getDeviceOver(&t, testing.allocator, 0x1c, "wg0", &dev));
    try testing.expectEqual(@as(usize, wg.test_seam.max_reply_messages), t.recvs);
}

test "awaitAck: a flood of foreign datagrams ends in TooManyMessages (sweep REV-WG-1)" {
    var t: Script = .{ .msg_type = codec.NLMSG_ERROR, .foreign_seq = true };
    try testing.expectError(error.TooManyMessages, wg.test_seam.awaitAckOver(&t, 5));
    try testing.expectEqual(@as(usize, wg.test_seam.max_reply_messages), t.recvs);
}

test "getDevice: a dump interrupted forever is restarted 3 times, then errors (sweep REV-WG-2)" {
    var t: Script = .{ .msg_type = 0x1c, .flags = codec.NLM_F_DUMP_INTR };
    var dev: wg.Device = undefined;
    try testing.expectError(error.TooManyMessages, wg.test_seam.getDeviceOver(&t, testing.allocator, 0x1c, "wg0", &dev));
    try testing.expectEqual(@as(usize, 1 + wg.test_seam.max_dump_restarts), t.sends);
    try testing.expectEqual(@as(usize, 1 + wg.test_seam.max_dump_restarts), t.recvs);
}

test "getDevice: an empty dump ends at NLMSG_DONE, a stray ACK is skipped (sweep REV-WG-2)" {
    const gpa = testing.allocator;
    var t: Script = .{ .msg_type = codec.NLMSG_DONE };
    var dev: wg.Device = undefined;
    try wg.test_seam.getDeviceOver(&t, gpa, 0x1c, "wg0", &dev);
    dev.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), t.sends);
    // A bare ACK (NLMSG_ERROR code 0) is not the end of a dump: the 16-byte
    // script has no errno payload, so it is malformed, never "done".
    var u: Script = .{ .msg_type = codec.NLMSG_ERROR };
    try testing.expectError(error.MalformedReply, wg.test_seam.getDeviceOver(&u, gpa, 0x1c, "wg0", &dev));
}

test "finish after OOM leaves the parser feedable and finishable (sweep REV-WG-3)" {
    const gpa = testing.allocator;
    const m1 = try peerWithIps(gpa, keyBytes(1), 0, 1);
    defer gpa.free(m1);
    const m2 = try peerWithIps(gpa, keyBytes(1), 1, 1); // continuation
    defer gpa.free(m2);
    // k = 0: the peer-table allocation fails; k = 1: the flush fails.
    for (0..2) |k| {
        var fa: std.testing.FailingAllocator = .init(gpa, .{});
        const a = fa.allocator();
        var p: wg.DeviceParser = .init(a);
        defer p.deinit();
        try p.feed(m1);
        fa.fail_index = fa.alloc_index + k;
        try testing.expectError(error.OutOfMemory, p.finish());
        fa.fail_index = std.math.maxInt(usize);
        try p.feed(m2);
        var dev = try p.finish();
        defer dev.deinit(a);
        try testing.expectEqual(@as(usize, 1), dev.peers.len);
        try testing.expectEqual(@as(usize, 2), dev.peers[0].allowed_ips.len);
    }
}
