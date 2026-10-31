// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GX). Each test names the finding it kills.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const mac = @import("mac.zig");
const arp = @import("arp.zig");
const nd = @import("nd.zig");
const dhcp = @import("dhcp.zig");
const cdp = @import("cdp.zig");
const lldp = @import("lldp.zig");

/// Run `body` in a forked child with its stderr captured into `buf`; returns
/// the captured length and whether the child died from a signal (a panic
/// aborts). A child past five seconds counts as hung.
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

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

// Needles live in consts, never inline in the expectPanicMessage call: the
// child's stack trace prints the caller's source line (GS trap).
const needle_mac = "l2disco: Mac.format: buffer shorter than 17 bytes";
const needle_opt = "l2disco: dhcp.Builder.addOption: code 0 (Pad) and 255 (End) are not options";
const needle_rdnss = "l2disco: nd.Rdnss.at: index out of range";
const needle_ip4 = "l2disco: dhcp.Ip4List.at: index out of range";
const needle_addrs = "l2disco: dhcp.Builder: address list must be a non-empty multiple of 4 bytes";

fn childMacShort() void {
    var small: [16]u8 = undefined;
    _ = mac.Mac.broadcast.format(&small);
}

test "Mac.format with a short buffer is a checked panic (sweep L2-1)" {
    try expectPanicMessage(childMacShort, needle_mac);
    var ok: [17]u8 = undefined;
    try testing.expectEqualStrings("ff:ff:ff:ff:ff:ff", mac.Mac.broadcast.format(&ok));
}

test "arp.Packet.encode with inconsistent address lengths is an error, reachable from parsed data (sweep L2-2, REV-l2disco-2)" {
    var big: [300]u8 = @splat(0);
    const hw: arp.Packet = .{ .htype = 1, .ptype = 0x800, .oper = .request, .sha = &.{ 1, 2, 3, 4, 5, 6 }, .spa = &.{ 1, 2, 3, 4 }, .tha = &.{ 1, 2, 3 }, .tpa = &.{ 1, 2, 3, 4 } };
    const pr: arp.Packet = .{ .htype = 1, .ptype = 0x800, .oper = .request, .sha = &.{ 1, 2, 3, 4, 5, 6 }, .spa = &.{ 1, 2, 3, 4 }, .tha = &.{ 1, 2, 3, 4, 5, 6 }, .tpa = &.{ 1, 2, 3 } };
    const wide: arp.Packet = .{ .htype = 1, .ptype = 0x800, .oper = .request, .sha = &big, .spa = &.{ 1, 2, 3, 4 }, .tha = &big, .tpa = &.{ 1, 2, 3, 4 } };
    var buf: [1024]u8 = undefined;
    try testing.expectError(error.InvalidLength, hw.encode(&buf));
    try testing.expectError(error.InvalidLength, pr.encode(&buf));
    try testing.expectError(error.InvalidLength, wide.encode(&buf));
    // A parsed hlen=0 request with the responder's own 6-byte MAC swapped in.
    const hlen0 = [_]u8{ 0, 1, 8, 0, 0, 4, 0, 1, 10, 0, 0, 1, 10, 0, 0, 2 };
    var parsed = try arp.Packet.parse(&hlen0);
    parsed.sha = &.{ 1, 2, 3, 4, 5, 6 };
    try testing.expectError(error.InvalidLength, parsed.encode(&buf));
    // The documented-valid shape still encodes, with the exact-fit boundary.
    const p: arp.Packet = .{ .htype = 1, .ptype = 0x800, .oper = .reply, .sha = &.{ 1, 2, 3, 4, 5, 6 }, .spa = &.{ 1, 2, 3, 4 }, .tha = &.{ 6, 5, 4, 3, 2, 1 }, .tpa = &.{ 4, 3, 2, 1 } };
    var exact: [28]u8 = undefined;
    try testing.expectEqual(@as(usize, 28), (try p.encode(&exact)).len);
    var short: [27]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, p.encode(&short));
}

const zeros22: [22]u8 = @splat(0);

fn childRdnssAt() void {
    const o: nd.RawOption = .{ .type = nd.OptionType.rdnss, .data = &zeros22 };
    const r = nd.Rdnss.parse(o).?;
    _ = r.at(1);
}

test "nd.Rdnss.at past count is a checked panic (sweep L2-3)" {
    try expectPanicMessage(childRdnssAt, needle_rdnss);
    const o: nd.RawOption = .{ .type = nd.OptionType.rdnss, .data = &zeros22 };
    const r = nd.Rdnss.parse(o).?;
    try testing.expectEqual(@as(usize, 1), r.count());
    _ = r.at(0);
}

fn childIp4At() void {
    const l: dhcp.Ip4List = .{ .bytes = &.{ 1, 2, 3, 4 } };
    _ = l.at(std.math.maxInt(usize) / 4 + 1);
}

fn childIp4Empty() void {
    const l: dhcp.Ip4List = .{ .bytes = &.{} };
    _ = l.first();
}

test "dhcp.Ip4List.at out of range (incl. huge index) is a checked panic (sweep L2-4)" {
    try expectPanicMessage(childIp4At, needle_ip4);
    try expectPanicMessage(childIp4Empty, needle_ip4);
    const l: dhcp.Ip4List = .{ .bytes = &.{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    try testing.expectEqual([4]u8{ 5, 6, 7, 8 }, l.at(1));
}

fn childAddRoutersOdd() void {
    var buf: [400]u8 = undefined;
    var b = dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 1 }) catch return;
    b.addRouters(&.{ 1, 2, 3 }) catch {};
}

fn childAddDnsEmpty() void {
    var buf: [400]u8 = undefined;
    var b = dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 1 }) catch return;
    b.addDnsServers(&.{}) catch {};
}

fn childAddNtpOdd() void {
    var buf: [400]u8 = undefined;
    var b = dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 1 }) catch return;
    b.addNtpServers(&.{ 1, 2, 3, 4, 5 }) catch {};
}

test "dhcp.Builder address-list adders reject a bad list with a checked panic (sweep L2-5)" {
    try expectPanicMessage(childAddRoutersOdd, needle_addrs);
    try expectPanicMessage(childAddDnsEmpty, needle_addrs);
    try expectPanicMessage(childAddNtpOdd, needle_addrs);
}

test "dhcp.Builder.finish that fails on pad_to leaves the builder untouched (sweep L2-6)" {
    var buf: [250]u8 = undefined;
    var b = try dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 1 });
    try b.addMessageType(.discover);
    const pos = b.pos;
    try testing.expectError(error.BufferTooSmall, b.finish(.{ .pad_to = 300 }));
    try testing.expectEqual(pos, b.pos);
    // Exact boundary: pad_to == buf.len succeeds, one more fails.
    try testing.expectEqual(@as(usize, 250), (try b.finish(.{ .pad_to = 250 })).len);
    var b2 = try dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 1 });
    try testing.expectError(error.BufferTooSmall, b2.finish(.{ .pad_to = 251 }));
    try testing.expectEqual(@as(usize, 240), b2.pos);
}

test "cdp checksum over a frame longer than 128 KiB does not overflow (sweep L2-7)" {
    const gpa = testing.allocator;
    const frame = try gpa.alloc(u8, 200_001);
    defer gpa.free(frame);
    @memset(frame, 0xff);
    // All-ones words: the ones'-complement sum folds to 0xffff, whose
    // complement is 0; an odd tail byte is padded with zero.
    const c = cdp.compute(frame);
    _ = c;
    // Same value as a chunked reference (fold per 1000 words).
    var ref: u64 = 0;
    var i: usize = 0;
    while (i + 2 <= frame.len) : (i += 2) {
        ref += 0xffff;
        if (ref > 0xffff) ref = (ref & 0xffff) + (ref >> 16);
    }
    ref += @as(u64, 0xff) << 8;
    while (ref > 0xffff) ref = (ref & 0xffff) + (ref >> 16);
    try testing.expectEqual(@as(u16, @intCast(~ref & 0xffff)), cdp.compute(frame));
    // verify() must also run through; it need not be true.
    _ = cdp.verify(frame);
    // Frame.parse over it reports a typed error, never a trap.
    try testing.expectError(error.BadChecksum, cdp.Frame.parse(frame, .{}));
}

// ── hostile-input regressions: what the sweep found clean ───────────────────

test "nd option with length 0 is rejected, not looped on (sweep L2-clean)" {
    var msg = [_]u8{ 133, 0, 0, 0, 0, 0, 0, 0 } ++ [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.BadOption, nd.Message.parse(&msg));
}

test "lldp org TLV with a short OUI and an oversized TLV length (sweep L2-clean)" {
    // type 127, length 2: OrgSpecific.parse needs 4 bytes.
    const org = [_]u8{ 0xfe, 0x02, 0x00, 0x80 };
    var it = lldp.TlvIterator.init(&org);
    const t = (try it.next()).?;
    try testing.expectError(error.BadTlvLength, lldp.OrgSpecific.parse(t.value));
    // length field 511 over a 4-byte buffer
    const over = [_]u8{ 0x01, 0xff, 0, 0 };
    var it2 = lldp.TlvIterator.init(&over);
    try testing.expectError(error.TruncatedTlv, it2.next());
}

test "cdp address count that lies stops at the buffer (sweep L2-clean)" {
    const v = [_]u8{ 0xff, 0xff, 0xff, 0xff, 1, 1, 0xcc, 0, 4, 1, 2, 3, 4 };
    var it = try cdp.AddressIterator.init(&v);
    _ = (try it.next()).?;
    try testing.expectError(error.TruncatedAddress, it.next());
}

test "dhcp domain-search pointer cycles are bounded (sweep L2-clean)" {
    // label 'a' at 0, pointer back to 0 at 2: the name grows each lap and
    // hits max_name_len instead of looping forever.
    const data = [_]u8{ 1, 'a', 0xc0, 0x00 };
    var it: dhcp.DomainSearchIterator = .{ .data = &data };
    var out: [dhcp.DomainSearchIterator.max_name_len]u8 = undefined;
    try testing.expectError(error.BadOptionLength, it.next(&out));
}

fn childAddOption0() void {
    var buf: [400]u8 = undefined;
    var b = dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 1 }) catch return;
    b.addOption(0, &.{1}) catch {};
}

fn childAddOption255() void {
    var buf: [400]u8 = undefined;
    var b = dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 1 }) catch return;
    b.addOption(255, &.{}) catch {};
}

test "dhcp.Builder.addOption refuses Pad and End codes (sweep REV-l2disco-4)" {
    try expectPanicMessage(childAddOption0, needle_opt);
    try expectPanicMessage(childAddOption255, needle_opt);
    var buf: [400]u8 = undefined;
    var b = try dhcp.Builder.init(&buf, .{ .op = .boot_request, .xid = 1 });
    try b.addOption(254, &.{1});
    try b.addOption(1, &.{ 1, 2, 3, 4 });
}

// ── iterators are terminal after the first error (REV-l2disco-1) ────────────

test "dhcp iterators return null after an error (sweep REV-l2disco-1)" {
    const bad_opt = [_]u8{ 12, 200, 1 }; // length past the buffer
    var oi = dhcp.OptionIterator.init(&bad_opt);
    try testing.expectError(error.TruncatedOption, oi.next());
    try testing.expectEqual(@as(?dhcp.RawOption, null), try oi.next());

    const bad_sub = [_]u8{ 1, 9, 1 };
    var ri: dhcp.RelayAgentIterator = .{ .data = &bad_sub };
    try testing.expectError(error.BadOptionLength, ri.next());
    try testing.expectEqual(@as(?dhcp.RelayAgentSubOption, null), try ri.next());

    const bad_route = [_]u8{ 33, 0, 0 };
    var ci: dhcp.ClasslessRouteIterator = .{ .data = &bad_route };
    try testing.expectError(error.BadOptionLength, ci.next());
    try testing.expectEqual(@as(?dhcp.ClasslessRoute, null), try ci.next());

    const bad_dom = [_]u8{ 0x80, 1, 0, 0 }; // reserved label bits: error with pos still 0
    var di: dhcp.DomainSearchIterator = .{ .data = &bad_dom };
    var out: [dhcp.DomainSearchIterator.max_name_len]u8 = undefined;
    try testing.expectError(error.BadOptionLength, di.next(&out));
    try testing.expectEqual(@as(?[]const u8, null), try di.next(&out));
}

test "cdp iterators return null after an error, pos still at the failing TLV (sweep REV-l2disco-1)" {
    const bad = [_]u8{ 0, 1, 0, 2 }; // TLV total length 2 < 4
    var ti = cdp.TlvIterator.init(&bad);
    try testing.expectError(error.BadTlvLength, ti.next());
    try testing.expectEqual(@as(usize, 0), ti.pos); // Frame.parse's tolerant path relies on this
    try testing.expectEqual(@as(?cdp.RawTlv, null), try ti.next());

    const v = [_]u8{ 0, 0, 0, 2, 1, 1, 0xcc, 0, 4, 1 }; // 2 entries, first truncated
    var ai = try cdp.AddressIterator.init(&v);
    try testing.expectError(error.TruncatedAddress, ai.next());
    try testing.expectEqual(@as(?cdp.Address, null), try ai.next());
}

test "nd and lldp iterators return null after an error (sweep REV-l2disco-1)" {
    const bad = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 };
    var ni: nd.OptionIterator = .{ .buf = &bad };
    try testing.expectError(error.BadOption, ni.next());
    try testing.expectEqual(@as(?nd.RawOption, null), try ni.next());

    const trunc = [_]u8{ 0x01, 0xff, 0, 0 };
    var li = lldp.TlvIterator.init(&trunc);
    try testing.expectError(error.TruncatedTlv, li.next());
    try testing.expectEqual(@as(?lldp.RawTlv, null), try li.next());
}
