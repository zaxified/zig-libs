// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GV) for netlink's public API.
//! Findings NL-1 .. NL-4, see ~/CML/20261029-panic-sweep/netlink-sweep.report.md.
//! Tests that need the private engines (`collectDumpPass`, `recvDatagramLimit`)
//! sit at the end of root.zig.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const codec = @import("codec.zig");
const bridge = @import("bridge.zig");

/// Run `body` in a forked child with its stderr captured into `buf`; returns
/// the captured length and whether the child died from a signal.
const Child = struct { died: bool, len: usize };

fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

// Needles live in consts, never inline in the expectPanicMessage call (the child's stack trace prints
// the caller's source line, so an inline needle matches ANY panic).
const needle_len = "netlink: message exceeds 4 GiB";

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

fn lenOver4Gib() void {
    // A usize past u32 exists only on 64-bit targets (the test skips elsewhere).
    if (@bitSizeOf(usize) > 32) _ = codec.checkedMessageLen(@as(usize, std.math.maxInt(u32)) + 1);
}

test "message length: u32 range is exact, past it is a checked netlink panic (sweep NL-3)" {
    try testing.expectEqual(@as(u32, 16), codec.checkedMessageLen(16));
    try testing.expectEqual(std.math.maxInt(u32), codec.checkedMessageLen(std.math.maxInt(u32)));
    if (@bitSizeOf(usize) <= 32) return error.SkipZigTest; // no usize past u32 to pass
    try expectPanicMessage(lenOver4Gib, needle_len);
}

test "VlanEntry.count is total for a hand-built inverted entry (sweep NL-4)" {
    const e: bridge.VlanEntry = .{ .ifindex = 1, .vid = 100, .vid_end = 10, .flags = 0 };
    try testing.expectEqual(@as(u32, 0), e.count());
    const ok: bridge.VlanEntry = .{ .ifindex = 1, .vid = 10, .vid_end = 12, .flags = 0 };
    try testing.expectEqual(@as(u32, 3), ok.count());
}

// ── fix round (review GV-b) ─────────────────────────────────────────────────

fn doneMsg(payload: ?[]const u8) [24]u8 {
    var m: [24]u8 = @splat(0);
    const native = @import("builtin").cpu.arch.endian();
    const len: u32 = 16 + if (payload) |p| @as(u32, @intCast(p.len)) else 0;
    std.mem.writeInt(u32, m[0..4], len, native);
    std.mem.writeInt(u16, m[4..6], codec.NLMSG_DONE, native);
    std.mem.writeInt(u32, m[8..12], 5, native); // seq
    std.mem.writeInt(u32, m[12..16], 9, native); // pid
    if (payload) |p| @memcpy(m[16..][0..p.len], p);
    return m;
}

fn classifyDone(bytes: []const u8) codec.DumpStep {
    var it: codec.MessageIterator = .{ .buf = bytes };
    const m = (it.next() catch unreachable).?;
    return codec.classifyDumpMessage(m, 9, 5);
}

test "NLMSG_DONE carrying a negative errno is a failed dump, not a complete one (sweep REV-1)" {
    const native = @import("builtin").cpu.arch.endian();
    var neg: [4]u8 = undefined;
    std.mem.writeInt(i32, &neg, -12, native);
    const with_err = doneMsg(&neg);
    switch (classifyDone(with_err[0..20])) {
        .failed => |c| try testing.expectEqual(@as(i32, -12), c),
        else => return error.TestExpectedFailed,
    }
    // No payload (old kernels), a zero payload, a short payload: complete.
    const bare = doneMsg(null);
    try testing.expect(classifyDone(bare[0..16]) == .done);
    var zero: [4]u8 = @splat(0);
    const z = doneMsg(&zero);
    try testing.expect(classifyDone(z[0..20]) == .done);
    const short = doneMsg(&.{ 0xff, 0xff });
    try testing.expect(classifyDone(short[0..18]) == .done);
    // A positive payload is not an error either.
    std.mem.writeInt(i32, &neg, 7, native);
    const pos = doneMsg(&neg);
    try testing.expect(classifyDone(pos[0..20]) == .done);
}

// ── survey-parity wave (2026-11-02): the new pub inputs ─────────────────────
// Parsers: attribute-framed random payloads (random types from the families'
// real tables, lengths 0-20), so the typed branches run, not only the walker's
// first check. Builders: degenerate and oversized specs. Nothing may panic,
// leak (testing.allocator) or read out of bounds (the checked build).

const ext = @import("ext.zig");
const root = @import("root.zig");

fn genPayload(r: std.Random, out: []u8) usize {
    var n: usize = 0;
    const fixed = r.uintLessThan(usize, 5) * 4; // 0, 4, 8, 12, 16
    r.bytes(out[0..fixed]);
    n = fixed;
    const types = [_]u16{
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30, 31, 32, 33, 37, 39, 50, 51,
    };
    var attrs = r.intRangeAtMost(usize, 1, 8);
    while (attrs > 0 and n + 4 + 24 <= out.len) : (attrs -= 1) {
        const dlen = r.uintAtMost(usize, 20);
        const total: u16 = @intCast(4 + dlen);
        std.mem.writeInt(u16, out[n..][0..2], total, host_endian);
        std.mem.writeInt(u16, out[n + 2 ..][0..2], types[r.uintLessThan(usize, types.len)], host_endian);
        r.bytes(out[n + 4 ..][0..dlen]);
        n += codec.alignUp(total);
        if (n > out.len) return out.len;
    }
    return n;
}

const host_endian = builtin.cpu.arch.endian();

test "new parsers: attribute-framed random payloads never panic (parity sweep)" {
    var prng = std.Random.DefaultPrng.init(0x6e65_746c);
    const r = prng.random();
    var buf: [512]u8 = undefined;
    const kinds = [_][]const u8{ "vxlan", "macvlan", "macvtap", "ipvlan", "ipvtap", "vrf", "bond", "bridge", "gre", "gretap", "ipip", "sit", "geneve", "vlan", "veth", "" };
    var hops: [ext.max_route_hops]ext.RouteHop = undefined;
    for (0..20_000) |_| {
        const n = genPayload(r, &buf);
        const p = buf[0..n];
        for (kinds) |k| _ = ext.parseKindInfo(k, p) catch {};
        _ = ext.parseMultipath(p, &hops) catch {};
        _ = ext.parseNexthop(p) catch {};
        _ = ext.parseMetrics(p) catch {};
        _ = root.parseLink(p) catch {};
        _ = root.parseRoute(p) catch {};
        _ = root.parseRule(p) catch {};
        _ = root.parseAddress(p) catch {};
        _ = root.parseNeighbor(p) catch {};
        var it: ext.MultipathIterator = .{ .buf = p };
        while (it.next() catch null) |_| {}
    }
}

test "new builders: degenerate and oversized specs are errors or values, never a panic (parity sweep)" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const big = try gpa.alloc(u8, 70_000);
    defer gpa.free(big);
    @memset(big, 0xa5);
    const odd = [_][]const u8{ &.{}, &.{1}, &.{ 1, 2, 3, 4 }, &(@as([16]u8, @splat(9))), &(@as([17]u8, @splat(9))), big };
    for (odd) |a| {
        list.clearRetainingCapacity();
        _ = ext.encodeVxlan(gpa, &list, .{ .vni = 0xffffff, .group = a, .local = a, .port = 0xffff }, 0xffff_ffff) catch {};
        list.clearRetainingCapacity();
        _ = ext.encodeGre(gpa, &list, .{ .local = a, .remote = a, .ikey = 0xffff_ffff, .okey = 0 }, 0) catch {};
        list.clearRetainingCapacity();
        _ = ext.encodeIptun(gpa, &list, .{ .local = a, .remote = a }, null) catch {};
        list.clearRetainingCapacity();
        _ = ext.encodeGeneve(gpa, &list, .{ .vni = 0, .remote = a }) catch {};
        _ = ext.hopsFamily(&.{.{ .gateway = a, .oif = 0xffff_ffff, .weight = 256 }}) catch {};
        list.clearRetainingCapacity();
        _ = ext.appendMultipath(gpa, &list, &.{.{ .gateway = if (a.len == 4 or a.len == 16) a else null, .oif = 1 }}) catch {};
        _ = ext.nexthopFamily(.{ .id = 0xffff_ffff, .gateway = a }) catch {};
        if (ext.buildNexthopRequest(gpa, 1, ext.RTM_NEWNEXTHOP, 0, .{ .id = 1, .gateway = a, .oif = 1 })) |req| gpa.free(req) else |_| {}
    }
    // Maximum-size lists: refused cleanly, not half-built.
    const many_hops: [ext.max_spec_hops + 1]ext.HopSpec = @splat(.{ .oif = 1 });
    try testing.expectError(error.TooManyHops, ext.hopsFamily(&many_hops));
    const many_raw: [ext.max_raw_attrs + 1]ext.RawAttr = @splat(.{ .attr_type = 1, .data = "" });
    list.clearRetainingCapacity();
    try testing.expectError(error.TooManyAttrs, ext.encodeRaw(gpa, &list, &many_raw));
    // 64 raw attributes of 1 KiB overflow one nest (65535 bytes): refused, not truncated.
    const kib: [1024]u8 = @splat(7);
    const fat: [ext.max_raw_attrs]ext.RawAttr = @splat(.{ .attr_type = 1, .data = &kib });
    list.clearRetainingCapacity();
    try testing.expectError(error.AttrTooLong, ext.encodeRaw(gpa, &list, &fat));
    // The widest legal hop list fits one nest.
    const max_hops: [ext.max_spec_hops]ext.HopSpec = @splat(.{ .gateway = &(@as([16]u8, @splat(1))), .oif = 3, .weight = 256 });
    list.clearRetainingCapacity();
    try ext.appendMultipath(gpa, &list, &max_hops);
    var it: codec.AttrIterator = .{ .buf = list.items };
    _ = (try it.next()).?;
}

test "appendMultipath: the exact inputs that used to panic are errors (review item 1)" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // Weight 0 underflowed, weights above 256 and gateways of 65528..65531 bytes hit an @intCast.
    for ([_]u16{ 0, 257, 1000, 65535 }) |w| {
        list.clearRetainingCapacity();
        try testing.expectError(error.InvalidHop, ext.appendMultipath(gpa, &list, &.{.{ .oif = 1, .weight = w }}));
    }
    const buf = try gpa.alloc(u8, 65540);
    defer gpa.free(buf);
    @memset(buf, 1);
    for ([_]usize{ 0, 3, 5, 17, 65527, 65528, 65529, 65530, 65531, 65532, 65540 }) |n| {
        list.clearRetainingCapacity();
        try testing.expectError(error.InvalidAddressLength, ext.appendMultipath(gpa, &list, &.{.{ .gateway = buf[0..n], .oif = 1 }}));
    }
    // Nothing was half-built into the list by a refused call.
    try testing.expectEqual(@as(usize, 0), list.items.len);
}
