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

test "arp.Packet.encode: 255-byte address fields are the limit, 256 is refused (sweep audit GX-L2-A)" {
    const a255: [255]u8 = @splat(7);
    const a256: [256]u8 = @splat(7);
    const mac6 = [_]u8{ 1, 2, 3, 4, 5, 6 };
    const ip4 = [_]u8{ 1, 2, 3, 4 };
    var buf: [1028]u8 = undefined;
    // Both address kinds at exactly 255: encodes (8 + 2 * (255 + 255)) and parses back.
    const max: arp.Packet = .{ .htype = 1, .ptype = 0x800, .oper = .request, .sha = &a255, .spa = &a255, .tha = &a255, .tpa = &a255 };
    const out = try max.encode(&buf);
    try testing.expectEqual(@as(usize, 1028), out.len);
    const back = try arp.Packet.parse(out);
    try testing.expectEqual(@as(usize, 255), back.sha.len);
    try testing.expectEqual(@as(usize, 255), back.spa.len);
    // 256 in either kind is refused (the length byte is a u8).
    const wide_hw: arp.Packet = .{ .htype = 1, .ptype = 0x800, .oper = .request, .sha = &a256, .spa = &ip4, .tha = &a256, .tpa = &ip4 };
    const wide_pa: arp.Packet = .{ .htype = 1, .ptype = 0x800, .oper = .request, .sha = &mac6, .spa = &a256, .tha = &mac6, .tpa = &a256 };
    try testing.expectError(error.InvalidLength, wide_hw.encode(&buf));
    try testing.expectError(error.InvalidLength, wide_pa.encode(&buf));
}

// ── dhcp6 (2026-11-04): every public input, hostile ─────────────────────────

test "dhcp6: every truncation and every single-octet corruption of a rich Reply is an error or a walkable message (sweep D6-1)" {
    const dhcp6 = @import("dhcp6.zig");
    var out: [512]u8 = undefined;
    var b = try dhcp6.Builder.init(&out, .reply, 0x010203);
    try b.addClientId(&.{ 0, 3, 0, 1, 2, 0, 0, 0, 0, 1 });
    const na = try b.beginIa(.na, 1, 2, 3);
    try b.addIaAddr(@splat(9), 4, 5);
    try b.addStatusCode(.no_addrs_avail, "none");
    try b.end(na);
    const pd = try b.beginIa(.pd, 1, 2, 3);
    try b.addIaPrefix(@splat(9), 64, 4, 5);
    try b.end(pd);
    try b.addAddressList(23, &.{@as([16]u8, @splat(1))});
    try b.addDomainList(&.{ "a.example", "b.example" });
    try b.addOptionRequest(&.{ 23, 24 });
    const good = b.finish();
    var work: [512]u8 = undefined;
    var names: [dhcp6.DomainListIterator.max_name_len]u8 = undefined;
    var walked: usize = 0;
    // `walk` touches every accessor; none may panic whatever `bytes` holds.
    const walk = struct {
        fn go(bytes: []const u8, nb: *[dhcp6.DomainListIterator.max_name_len]u8) usize {
            const m = dhcp6.Message.parse(bytes) catch return 0;
            _ = m.clientId() catch {};
            _ = m.serverId() catch {};
            _ = m.statusCode() catch {};
            _ = m.optionRequest() catch {};
            _ = m.dnsServers() catch {};
            var n: usize = 1;
            inline for (.{ dhcp6.IaKind.na, dhcp6.IaKind.ta, dhcp6.IaKind.pd }) |k| {
                var it = m.identityAssociations(k);
                while (it.next() catch null) |ia| {
                    _ = ia.statusCode() catch {};
                    var a = ia.addresses();
                    while (a.next() catch null) |_| n += 1;
                    var p = ia.prefixes();
                    while (p.next() catch null) |_| n += 1;
                }
            }
            if (m.domainList()) |d0| {
                var d = d0;
                while (d.next(nb) catch null) |_| n += 1;
            }
            _ = m.unwrap(3) catch {};
            return n;
        }
    }.go;
    for (0..good.len + 1) |len| walked += walk(good[0..len], &names);
    for (0..good.len) |at| {
        for ([_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xff }) |v| {
            @memcpy(work[0..good.len], good);
            work[at] = v;
            walked += walk(work[0..good.len], &names);
        }
    }
    try testing.expect(walked > good.len); // the sweep reached past the framing walk
}

test "dhcp6: a deep relay chain is peeled iteratively and the depth limit holds (sweep D6-2)" {
    const dhcp6 = @import("dhcp6.zig");
    // 40 nested relay-forward layers around a Solicit, built inside out in two buffers.
    var a: [8192]u8 = undefined;
    var c: [8192]u8 = undefined;
    var inner = try dhcp6.Builder.init(&a, .solicit, 7);
    try inner.addElapsedTime(1);
    var cur: []const u8 = inner.finish();
    var flip = false;
    for (0..40) |_| {
        const buf: []u8 = if (flip) &a else &c;
        // the layer being built must not overwrite `cur`
        var r = try dhcp6.Builder.initRelay(buf, .relay_forw, 0, @splat(0), @splat(0));
        try r.addRelayMessage(cur);
        cur = r.finish();
        flip = !flip;
    }
    const m = try dhcp6.Message.parse(cur);
    try testing.expectError(error.TooDeep, m.unwrap(8));
    try testing.expectError(error.TooDeep, m.unwrap(39));
    const u = try m.unwrap(255);
    try testing.expectEqual(@as(u8, 40), u.depth);
    try testing.expectEqual(@as(u24, 7), u.inner.xid);
}

test "lldp MedLocation decoders: every format and length, hostile elements (sweep LOC-1)" {
    var data: [40]u8 = undefined;
    for (0..data.len) |i| data[i] = @truncate(i *% 37 +% 5);
    var decoded: usize = 0;
    var errors: usize = 0;
    for (0..256) |format| {
        for (0..data.len + 1) |len| {
            const l: lldp.MedLocation = .{ .format = @intCast(format), .data = data[0..len] };
            if (l.coordinate()) |m| {
                if (m) |c| {
                    std.mem.doNotOptimizeAway((c.latitudeDegrees() orelse 0) + (c.longitudeDegrees() orelse 0) + (c.altitudeUnits() orelse 0));
                    decoded += 1;
                }
            } else |_| errors += 1;
            if (l.elin()) |_| {} else |_| errors += 1;
            if (l.civic()) |m| {
                if (m) |cv| {
                    var it = cv.iterator();
                    while (it.next() catch null) |e| std.mem.doNotOptimizeAway(e.value.len);
                    decoded += 1;
                }
            } else |_| errors += 1;
        }
    }
    try testing.expect(decoded > 0 and errors > 0);
}

test "lldp coordinate LCI: each RFC rule is an error, unknown is null, not a precise number (sweep LOC-2)" {
    // lat_res (6) lat (34) | lon_res (6) lon (34) | AT (4) alt_res (6) alt (30) | datum (8)
    const mk = struct {
        fn go(lat_res: u128, lat: u128, lon_res: u128, lon: u128, at: u128, alt_res: u128, alt: u128, datum: u128) [16]u8 {
            const v = (lat_res << 122) | (lat << 88) | (lon_res << 82) | (lon << 48) | (at << 44) | (alt_res << 38) | (alt << 8) | datum;
            var out: [16]u8 = undefined;
            std.mem.writeInt(u128, &out, v, .big);
            return out;
        }
    }.go;
    const loc = struct {
        fn of(b: *const [16]u8) lldp.MedLocation {
            return .{ .format = 1, .data = b };
        }
    }.of;
    const deg90: u128 = 90 << 25;
    const deg180: u128 = 180 << 25;
    const ok = mk(18, 5 << 25, 18, 7 << 25, 1, 12, 256, 1);
    const c = (try loc(&ok).coordinate()).?;
    try testing.expectEqual(@as(f64, 5.0), c.latitudeDegrees().?);
    try testing.expectEqual(@as(f64, 1.0), c.altitudeUnits().?);
    try testing.expect(c.datumKnown());
    // Exactly at the limits: valid. One unit beyond: OutOfRange.
    _ = (try loc(&mk(34, deg90, 34, deg180, 1, 30, 0, 1)).coordinate()).?;
    const neg90: u128 = (@as(u128, 1) << 34) - deg90;
    _ = (try loc(&mk(34, neg90, 34, 0, 1, 30, 0, 1)).coordinate()).?;
    try testing.expectError(error.OutOfRange, loc(&mk(34, deg90 + 1, 34, 0, 1, 30, 0, 1)).coordinate());
    try testing.expectError(error.OutOfRange, loc(&mk(34, neg90 - 1, 34, 0, 1, 30, 0, 1)).coordinate());
    try testing.expectError(error.OutOfRange, loc(&mk(34, 0, 34, deg180 + 1, 1, 30, 0, 1)).coordinate());
    try testing.expectError(error.OutOfRange, loc(&mk(18, 0x1ffffffff, 0, 0, 1, 12, 0, 1)).coordinate());
    // Reserved resolutions and altitude type.
    try testing.expectError(error.Reserved, loc(&mk(35, 0, 34, 0, 1, 30, 0, 1)).coordinate());
    try testing.expectError(error.Reserved, loc(&mk(34, 0, 35, 0, 1, 30, 0, 1)).coordinate());
    try testing.expectError(error.Reserved, loc(&mk(34, 0, 34, 0, 1, 31, 0, 1)).coordinate());
    try testing.expectError(error.Reserved, loc(&mk(34, 0, 34, 0, 3, 30, 0, 1)).coordinate());
    // Resolution 0 / altitude type 0: decoded, the number is null, the raw field stays.
    const unk = (try loc(&mk(0, 123, 0, 456, 0, 0, 789, 9)).coordinate()).?;
    try testing.expect(unk.latitudeDegrees() == null and unk.longitudeDegrees() == null and unk.altitudeUnits() == null);
    try testing.expectEqual(@as(i34, 123), unk.lat);
    try testing.expect(!unk.datumKnown()); // not an error: RFC 6225 §2.5 reads it as WGS 84
    // Length and format.
    try testing.expectError(error.BadLength, (lldp.MedLocation{ .format = 1, .data = ok[0..15] }).coordinate());
    try testing.expect((try (lldp.MedLocation{ .format = 2, .data = &ok }).coordinate()) == null);
}

test "lldp civic LCI: RFC 4776 section 5 example decodes to the RFC's table; length mismatch is an error (sweep LOC-3)" {
    // The Munich city hall of RFC 4776 section 5, encoded by hand from that table:
    // what 2 (the client), country DE, then CAtype/CAlength/CAvalue (UTF-8; M=U+00FCnchen is 7 octets).
    const els = [_]struct { t: u8, v: []const u8 }{
        .{ .t = 0, .v = "de" },                   .{ .t = 128, .v = "Latn" },         .{ .t = 1, .v = "Bayern" },
        .{ .t = 2, .v = "Oberbayern" },           .{ .t = 3, .v = "M\xc3\xbcnchen" }, .{ .t = 6, .v = "Marienplatz" },
        .{ .t = 19, .v = "8" },                   .{ .t = 21, .v = "Rathaus" },       .{ .t = 24, .v = "80331" },
        .{ .t = 29, .v = "government-building" }, .{ .t = 31, .v = "Postfach 1000" }, .{ .t = 0, .v = "en" },
        .{ .t = 1, .v = "Bavaria" },              .{ .t = 3, .v = "Munich" },         .{ .t = 0, .v = "it" },
        .{ .t = 1, .v = "Baviera" },              .{ .t = 3, .v = "Monaco" },
    };
    var buf: [255]u8 = undefined;
    var n: usize = 2;
    buf[1] = 2;
    @memcpy(buf[2..4], "DE");
    n = 4;
    for (els) |e| {
        buf[n] = e.t;
        buf[n + 1] = @intCast(e.v.len);
        @memcpy(buf[n + 2 ..][0..e.v.len], e.v);
        n += 2 + e.v.len;
    }
    buf[0] = @intCast(n - 1);
    const l: lldp.MedLocation = .{ .format = 2, .data = buf[0..n] };
    const cv = (try l.civic()).?;
    try testing.expectEqual(@as(u8, 2), cv.what);
    try testing.expectEqualStrings("DE", &cv.country);
    var it = cv.iterator();
    for (els) |e| {
        const got = (try it.next()).?;
        try testing.expectEqual(e.t, got.ca_type);
        try testing.expectEqualStrings(e.v, got.value);
    }
    try testing.expect((try it.next()) == null);
    // The LCI length byte one off in either direction, and below 3.
    buf[0] += 1;
    try testing.expectError(error.BadLength, (lldp.MedLocation{ .format = 2, .data = buf[0..n] }).civic());
    buf[0] -= 2;
    try testing.expectError(error.BadLength, (lldp.MedLocation{ .format = 2, .data = buf[0..n] }).civic());
    try testing.expectError(error.BadLength, (lldp.MedLocation{ .format = 2, .data = &.{ 2, 2, 'D', 'E' } }).civic());
    try testing.expectError(error.BadLength, (lldp.MedLocation{ .format = 2, .data = &.{} }).civic());
    // An element that overruns the LCI: the iterator reports it once.
    const bad = [_]u8{ 6, 2, 'U', 'S', 1, 9, 'C' };
    var bit = (try (lldp.MedLocation{ .format = 2, .data = &bad }).civic()).?.iterator();
    try testing.expectError(error.Malformed, bit.next());
    try testing.expect((try bit.next()) == null);
    // ELIN: 10 to 25 octets.
    try testing.expectError(error.BadLength, (lldp.MedLocation{ .format = 3, .data = "123456789" }).elin());
    try testing.expectEqualStrings("5551234567", (try (lldp.MedLocation{ .format = 3, .data = "5551234567" }).elin()).?);
}

test "lldp 802.1 / 802.3 link aggregation, VID usage digest, management VID, protocol identity decode (sweep LOC-4)" {
    const agg = lldp.OrgSpecific{ .oui = .{ 0x00, 0x80, 0xc2 }, .subtype = 7, .info = &.{ 3, 0, 0, 0, 7 } };
    const la = agg.decode().?.link_aggregation;
    try testing.expect(la.capable and la.aggregated);
    try testing.expectEqual(@as(u32, 7), la.port_id);
    const dep = lldp.OrgSpecific{ .oui = .{ 0x00, 0x12, 0x0f }, .subtype = 3, .info = &.{ 1, 0, 0, 1, 0 } };
    const lb = dep.decode().?.link_aggregation;
    try testing.expect(lb.capable and !lb.aggregated);
    try testing.expectEqual(@as(u32, 256), lb.port_id);
    const short = lldp.OrgSpecific{ .oui = .{ 0x00, 0x80, 0xc2 }, .subtype = 7, .info = &.{ 3, 0, 0, 0 } };
    try testing.expect(short.decode() == null);
    const dig = lldp.OrgSpecific{ .oui = .{ 0x00, 0x80, 0xc2 }, .subtype = 5, .info = &.{ 0xde, 0xad, 0xbe, 0xef } };
    try testing.expectEqual(@as(u32, 0xdeadbeef), dig.decode().?.vid_usage_digest);
    const mv = lldp.OrgSpecific{ .oui = .{ 0x00, 0x80, 0xc2 }, .subtype = 6, .info = &.{ 0x01, 0x00 } };
    try testing.expectEqual(@as(u16, 256), mv.decode().?.management_vid);
    const pi = lldp.OrgSpecific{ .oui = .{ 0x00, 0x80, 0xc2 }, .subtype = 4, .info = &.{ 2, 0x88, 0x8e } };
    try testing.expectEqualSlices(u8, &.{ 0x88, 0x8e }, pi.decode().?.protocol_identity);
    const pi_bad = lldp.OrgSpecific{ .oui = .{ 0x00, 0x80, 0xc2 }, .subtype = 4, .info = &.{ 3, 0x88, 0x8e } };
    try testing.expect(pi_bad.decode() == null);
}

test "dhcp6: list accessors past the end are null, not a panic (sweep D6-3)" {
    const dhcp6 = @import("dhcp6.zig");
    const l: dhcp6.Ip6List = .{ .bytes = &@as([32]u8, @splat(1)) };
    try testing.expect(l.at(2) == null);
    try testing.expect(l.at(std.math.maxInt(usize)) == null);
    const c: dhcp6.CodeList = .{ .bytes = &.{ 0, 23, 0, 24, 9 } }; // a trailing odd octet is not counted
    try testing.expectEqual(@as(usize, 2), c.count());
    try testing.expect(c.at(2) == null);
    try testing.expect(c.at(std.math.maxInt(usize)) == null);
}

test "cdp typed accessors beyond the nine: MTU, power, system name, trust, CoS; wrong sizes are null (sweep CDP-1)" {
    var buf: [200]u8 = undefined;
    var b = try cdp.Builder.init(&buf, .{ .version = 2, .ttl_s = 180 });
    try b.addDeviceId("sw");
    try b.addTlv(0x11, &.{ 0, 0, 0x23, 0x28 });
    try b.addTlv(0x10, &.{ 0x3a, 0x98 });
    try b.addTlv(0x14, "core-1");
    try b.addTlv(0x12, &.{1});
    try b.addTlv(0x13, &.{ 1, 2 }); // two octets: not a CoS
    const f = try cdp.Frame.parse(b.finish(), .{});
    try testing.expectEqual(@as(?u32, 9000), f.mtu());
    try testing.expectEqual(@as(?u16, 15000), f.powerConsumptionMw());
    try testing.expectEqualStrings("core-1", f.systemName().?);
    try testing.expectEqual(@as(?u8, 1), f.extendedTrust());
    try testing.expect(f.untrustedCos() == null);
}
