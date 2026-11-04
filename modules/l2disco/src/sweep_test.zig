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
    try b.addOption(dhcp6.OptionCode.client_fqdn, &.{ 0, 3, 'a', 'b', 'c', 0 });
    try b.addOption(dhcp6.OptionCode.vendor_class, &.{ 0, 0, 0, 9, 0, 1, 'x' });
    try b.addOption(dhcp6.OptionCode.user_class, &.{ 0, 1, 'u' });
    try b.addOption(dhcp6.OptionCode.reconfigure_message, &.{5});
    try b.addOption(dhcp6.OptionCode.reconfigure_accept, &.{});
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
            var fq: [dhcp6.DomainListIterator.max_name_len]u8 = undefined;
            _ = m.clientFqdn(&fq) catch {};
            var vcs = m.vendorClasses();
            while (vcs.next() catch null) |vc| {
                var c = vc.classes;
                while (c.next() catch null) |_| {}
            }
            var ucs = m.userClasses();
            while (ucs.next() catch null) |uc0| {
                var c = uc0;
                while (c.next() catch null) |_| {}
            }
            _ = m.reconfigureMessage() catch {};
            _ = m.reconfigureAccept() catch {};
            var n: usize = 1;
            inline for (.{ dhcp6.IaKind.na, dhcp6.IaKind.ta, dhcp6.IaKind.pd }) |k| {
                var it = m.identityAssociations(k);
                while (it.next() catch null) |ia| {
                    _ = ia.statusCode() catch {};
                    var a = ia.addresses();
                    while (a.next() catch null) |_| n += 1;
                    var p = ia.prefixes();
                    while (p.next() catch null) |px| {
                        _ = px.prefixExclude() catch {};
                        n += 1;
                    }
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
    try testing.expect(errors > 0); // `decoded` stays unasserted: the dense pattern rarely forms a valid LCI now
    std.mem.doNotOptimizeAway(decoded);
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
    // Per field. A reserved latitude resolution makes THAT field unknown (not range-checked:
    // 0x1ffffffff is 255.99 degrees), the longitude beside it still decodes.
    const rl = (try loc(&mk(35, 0x1ffffffff, 34, 7 << 25, 1, 30, 0, 1)).coordinate()).?;
    try testing.expect(rl.latitudeDegrees() == null and rl.longitudeDegrees().? == 7.0);
    // Resolution 0 is unknown and not range-checked either; a known field beside it still is.
    _ = (try loc(&mk(0, 0x1ffffffff, 34, 0, 1, 30, 0, 1)).coordinate()).?;
    try testing.expectError(error.OutOfRange, loc(&mk(0, 0, 34, deg180 + 1, 1, 30, 0, 1)).coordinate());
    // A reserved altitude resolution or type drops the altitude only.
    const ra = (try loc(&mk(34, 3 << 25, 34, 4 << 25, 1, 31, 99, 1)).coordinate()).?;
    try testing.expect(ra.altitudeUnits() == null and ra.latitudeDegrees().? == 3.0 and ra.longitudeDegrees().? == 4.0);
    const rt = (try loc(&mk(34, 3 << 25, 34, 4 << 25, 3, 30, 99, 1)).coordinate()).?;
    try testing.expect(rt.altitudeUnits() == null and rt.latitudeDegrees().? == 3.0);
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
    // what 2 (the client), country DE, then CAtype/CAlength/CAvalue (UTF-8; "M" + U+00FC + "nchen" is 8 octets).
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
    // `what` above 2 and a country code that is not two capital letters (RFC 4776 §3.1).
    try testing.expectError(error.Reserved, (lldp.MedLocation{ .format = 2, .data = &.{ 3, 3, 'D', 'E' } }).civic());
    try testing.expectError(error.Reserved, (lldp.MedLocation{ .format = 2, .data = &.{ 3, 2, 'd', 'e' } }).civic());
    try testing.expectError(error.Reserved, (lldp.MedLocation{ .format = 2, .data = &.{ 3, 2, '1', 'E' } }).civic());
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
    try testing.expectEqual(@as(?u32, 9000), try f.mtu());
    try testing.expectEqual(@as(?u16, 15000), try f.powerConsumptionMw());
    try testing.expectEqualStrings("core-1", (try f.systemName()).?);
    try testing.expectEqual(@as(?u8, 1), try f.extendedTrust());
    try testing.expectError(error.BadTlvValue, f.untrustedCos());
}

// ── delta audit 2026-11-04: tests for the boundaries the mutant run found unpinned ──────────

test "dhcp6 delta audit: DUID minimum sizes, UUID is exactly 16, iterators are terminal at their first error" {
    const dhcp6 = @import("dhcp6.zig");
    // LLT needs hardware type, time and one address octet (7 after the type); EN an enterprise number and one octet (5).
    try testing.expectError(error.BadOptionLength, dhcp6.Duid.parse(&.{ 0, 1, 0, 1, 0, 0, 0, 0 }));
    _ = try dhcp6.Duid.parse(&.{ 0, 1, 0, 1, 0, 0, 0, 0, 7 });
    try testing.expectError(error.BadOptionLength, dhcp6.Duid.parse(&.{ 0, 2, 0, 0, 0, 9 }));
    _ = try dhcp6.Duid.parse(&.{ 0, 2, 0, 0, 0, 9, 1 });
    const uuid17 = [_]u8{ 0, 4 } ++ @as([17]u8, @splat(1));
    try testing.expectError(error.BadOptionLength, dhcp6.Duid.parse(&uuid17));
    const en = try dhcp6.Duid.parse(&.{ 0, 2, 0x01, 0x02, 0x03, 0x04, 0xaa });
    try testing.expectEqual(@as(?u32, 0x01020304), en.enterpriseNumber());
    // OptionIterator: terminal after a truncated option.
    var oi = dhcp6.OptionIterator.init(&.{ 0, 1, 0, 9, 1 });
    try testing.expectError(error.TruncatedOption, oi.next());
    try testing.expect((try oi.next()) == null);
    // OpaqueDataIterator: a lone trailing octet is a header error, once; then null.
    var od: dhcp6.OpaqueDataIterator = .{ .buf = &.{ 0, 1, 'a', 0 } };
    try testing.expectEqualStrings("a", (try od.next()).?);
    try testing.expectError(error.BadOptionLength, od.next());
    try testing.expect((try od.next()) == null);
}

test "dhcp6 delta audit: equal timers and lifetimes are valid; IA address and prefix minimum sizes" {
    const dhcp6 = @import("dhcp6.zig");
    const ia: dhcp6.Ia = .{ .iaid = 1, .t1 = 100, .t2 = 100, .options = &.{} };
    try testing.expect(ia.timersValid());
    const a: dhcp6.IaAddr = .{ .addr = @splat(0), .preferred = 5, .valid = 5, .options = &.{} };
    try testing.expect(a.isValid());
    const p: dhcp6.IaPrefix = .{ .preferred = 5, .valid = 5, .prefix_len = 64, .prefix = @splat(0), .options = &.{} };
    try testing.expect(p.isValid());
    // 23 octets after an IA Address header (24 needed), 24 after an IA Prefix header (25 needed).
    const short_addr: dhcp6.Ia = .{ .iaid = 0, .t1 = 0, .t2 = 0, .options = &([_]u8{ 0, 5, 0, 23 } ++ @as([23]u8, @splat(0))) };
    var ai = short_addr.addresses();
    try testing.expectError(error.BadOptionLength, ai.next());
    const short_pfx: dhcp6.Ia = .{ .iaid = 0, .t1 = 0, .t2 = 0, .options = &([_]u8{ 0, 26, 0, 24 } ++ @as([24]u8, @splat(0))) };
    var pi = short_pfx.prefixes();
    try testing.expectError(error.BadOptionLength, pi.next());
}

test "dhcp6 delta audit: Prefix Exclude length rules at their boundaries (RFC 6603)" {
    const dhcp6 = @import("dhcp6.zig");
    var px: dhcp6.IaPrefix = .{ .preferred = 0, .valid = 0, .prefix_len = 48, .prefix = @splat(0), .options = &.{} };
    // Excluded length 129 with the matching 12 octets: the 128 limit, not the size, must refuse it.
    var o129: [16]u8 = @splat(0);
    o129[1] = 0x43;
    o129[3] = 12;
    o129[4] = 129;
    px.options = &o129;
    try testing.expectError(error.BadOptionLength, px.prefixExclude());
    // Excluded length equal to the prefix length, in its only well-sized form (no subnet-id octets).
    px.options = &.{ 0, 0x43, 0, 1, 48 };
    try testing.expectError(error.BadOptionLength, px.prefixExclude());
    // 9 subnet-id bits need two octets, not one.
    px.options = &.{ 0, 0x43, 0, 2, 57, 0xab };
    try testing.expectError(error.BadOptionLength, px.prefixExclude());
    px.options = &.{ 0, 0x43, 0, 3, 57, 0xab, 0xcd };
    try testing.expectEqual(@as(u8, 57), (try px.prefixExclude()).?.len);
    // 128 is the largest excluded length: 80 bits = 10 octets.
    var o128: [15]u8 = @splat(0);
    o128[1] = 0x43;
    o128[3] = 11;
    o128[4] = 128;
    px.options = &o128;
    try testing.expectEqual(@as(u8, 128), (try px.prefixExclude()).?.len);
}

test "dhcp6 delta audit: name label limits (63) and the 253-character name in Client FQDN, domain list and Builder" {
    const dhcp6 = @import("dhcp6.zig");
    var nb: [dhcp6.DomainListIterator.max_name_len]u8 = undefined;
    // A 64-octet label is refused by the domain list iterator.
    var w64: [66]u8 = @splat('a');
    w64[0] = 64;
    w64[65] = 0;
    var dl: dhcp6.DomainListIterator = .{ .buf = &w64 };
    try testing.expectError(error.BadOptionLength, dl.next(&nb));
    // Client FQDN with labels of 63, 63, 63 and `label_len` octets.
    const mk = struct {
        fn go(out: []u8, label_len: u8) []const u8 {
            @memcpy(out[0..6], &[_]u8{ 7, 0, 0, 0, 0, 39 });
            var n: usize = 8;
            out[n] = 0; // flags
            n += 1;
            for ([_]u8{ 63, 63, 63, label_len }) |l| {
                out[n] = l;
                @memset(out[n + 1 ..][0..l], 'a');
                n += 1 + l;
            }
            out[n] = 0;
            n += 1;
            std.mem.writeInt(u16, out[6..8], @intCast(n - 8), .big);
            return out[0..n];
        }
    }.go;
    var buf: [400]u8 = undefined;
    // 63+63+63+61 characters and three dots = 253: accepted. One more character: refused.
    const m253 = try dhcp6.Message.parse(mk(&buf, 61));
    try testing.expectEqual(@as(usize, 253), (try m253.clientFqdn(&nb)).?.name.len);
    const m254 = try dhcp6.Message.parse(mk(&buf, 62));
    try testing.expectError(error.BadOptionLength, m254.clientFqdn(&nb));
    // A single 64-octet label (short enough overall that only the label limit can refuse it).
    @memcpy(buf[0..8], &[_]u8{ 7, 0, 0, 0, 0, 39, 0, 67 });
    buf[8] = 0; // flags
    buf[9] = 64;
    @memset(buf[10..74], 'a');
    buf[74] = 0;
    const m64 = try dhcp6.Message.parse(buf[0..75]);
    try testing.expectError(error.BadOptionLength, m64.clientFqdn(&nb));
    // Builder: a 64-octet label is a BadName, 63 is not.
    var b = try dhcp6.Builder.init(&buf, .reply, 1);
    const l64: [64]u8 = @splat('x');
    try testing.expectError(error.BadName, b.addDomainList(&.{&l64}));
    const l63: [63]u8 = @splat('x');
    try b.addDomainList(&.{&l63});
}

test "dhcp6 delta audit: Reconfigure Message accepts exactly 5, 6 and 11" {
    const dhcp6 = @import("dhcp6.zig");
    for (0..256) |v| {
        const m = try dhcp6.Message.parse(&[_]u8{ 10, 0, 0, 0, 0, 19, 0, 1, @intCast(v) });
        if (v == 5 or v == 6 or v == 11) {
            try testing.expectEqual(@as(u8, @intCast(v)), @backingInt((try m.reconfigureMessage()).?));
        } else {
            try testing.expectError(error.BadOptionLength, m.reconfigureMessage());
        }
    }
}

test "dhcp6 delta audit: Builder limits at their exact boundaries and a forged mark over zeroed bytes" {
    const dhcp6 = @import("dhcp6.zig");
    const gpa = testing.allocator;
    // A buffer that fits one option exactly.
    var tight: [9]u8 = undefined;
    var t = try dhcp6.Builder.init(&tight, .solicit, 0);
    try t.addOption(1, "x");
    try testing.expectEqual(@as(usize, 9), t.finish().len);
    // Forged mark three octets before the end, over zeroed bytes: a header of code 0 and length 0 would
    // be read one octet past the written part; it must be refused, not underflow.
    var zb: [64]u8 = @splat(0);
    var zbld = try dhcp6.Builder.init(&zb, .solicit, 0);
    try testing.expectError(error.BadMark, zbld.end(.{ .at = zbld.len - 3, .code = 0 }));
    // The 65535-octet limits.
    const big = try gpa.alloc(u8, 4 + 4 + 65535 + 8);
    defer gpa.free(big);
    const data = try gpa.alloc(u8, 65536);
    defer gpa.free(data);
    @memset(data, 0);
    {
        var b = try dhcp6.Builder.init(big, .solicit, 0);
        try b.addOption(1, data[0..65535]);
        const m = try dhcp6.Message.parse(b.finish());
        try testing.expectEqual(@as(usize, 65535), m.option(1).?.len);
        var c = try dhcp6.Builder.init(big, .solicit, 0);
        const mk = try c.begin(2, &.{});
        c.len += 65535;
        try c.end(mk);
        try testing.expectEqual(@as(u16, 65535), std.mem.readInt(u16, big[6..8], .big));
    }
    {
        var b = try dhcp6.Builder.init(big, .solicit, 0);
        const codes = try gpa.alloc(u16, 0x8000);
        defer gpa.free(codes);
        @memset(codes, 23);
        try b.addOptionRequest(codes[0..0x7fff]);
        try testing.expectError(error.OptionTooLong, b.addOptionRequest(codes));
    }
    {
        var b = try dhcp6.Builder.init(big, .reply, 0);
        try b.addStatusCode(.success, data[0 .. 0xffff - 2]);
        var c = try dhcp6.Builder.init(big, .reply, 0);
        try testing.expectError(error.OptionTooLong, c.addStatusCode(.success, data[0 .. 0xffff - 1]));
    }
    {
        var b = try dhcp6.Builder.init(big, .reply, 0);
        const addrs = try gpa.alloc([16]u8, 4096);
        defer gpa.free(addrs);
        @memset(addrs, @splat(1));
        try b.addAddressList(23, addrs[0 .. 0xffff / 16]);
        try testing.expectError(error.OptionTooLong, b.addAddressList(23, addrs));
    }
}

fn coordLci(lat_res: u128, lat: u128, lon_res: u128, lon: u128, at: u128, alt_res: u128, alt: u128, datum: u128) [16]u8 {
    const v = (lat_res << 122) | (lat << 88) | (lon_res << 82) | (lon << 48) | (at << 44) | (alt_res << 38) | (alt << 8) | datum;
    var out: [16]u8 = undefined;
    std.mem.writeInt(u128, &out, v, .big);
    return out;
}

test "lldp delta audit: coordinate raw fields at their widest, per-field knowns, exact limits (RFC 3825, 6225)" {
    const loc = struct {
        fn of(b: *const [16]u8) lldp.MedLocation {
            return .{ .format = 1, .data = b };
        }
    }.of;
    const deg180: u128 = 180 << 25;
    // Every raw field at a value that needs all its bits.
    const wide = coordLci(63, 0x155555555, 62, 0x2aaaaaaaa, 15, 61, 0x2aaaaaaa, 0xfe);
    const w = (try loc(&wide).coordinate()).?;
    try testing.expectEqual(@as(u6, 63), w.lat_resolution);
    try testing.expectEqual(@as(u6, 62), w.lon_resolution);
    try testing.expectEqual(@as(u4, 15), w.altitude_type);
    try testing.expectEqual(@as(u6, 61), w.alt_resolution);
    try testing.expectEqual(@as(u8, 0xfe), w.datum);
    try testing.expectEqual(@as(u34, 0x155555555), @as(u34, @bitCast(w.lat)));
    try testing.expectEqual(@as(u34, 0x2aaaaaaaa), @as(u34, @bitCast(w.lon)));
    try testing.expectEqual(@as(u30, 0x2aaaaaaa), @as(u30, @bitCast(w.alt)));
    // Seventeen octets are not a coordinate LCI.
    const sixteen = coordLci(34, 0, 34, 0, 1, 30, 0, 1);
    var seventeen: [17]u8 = undefined;
    @memcpy(seventeen[0..16], &sixteen);
    seventeen[16] = 0;
    try testing.expectError(error.BadLength, (lldp.MedLocation{ .format = 1, .data = &seventeen }).coordinate());
    // An unknown longitude (resolution 0) beside a known latitude is not range-checked; -180 exactly is valid.
    _ = (try loc(&coordLci(34, 0, 0, 0x1ffffffff, 1, 30, 0, 1)).coordinate()).?;
    _ = (try loc(&coordLci(34, 0, 34, (1 << 34) - deg180, 1, 30, 0, 1)).coordinate()).?;
    // Reserved longitude resolution 35 reads as unknown.
    const rl = (try loc(&coordLci(34, 0, 35, 7 << 25, 1, 30, 0, 1)).coordinate()).?;
    try testing.expect(rl.longitudeDegrees() == null);
    // Altitude: floors with a resolution is known; type 0 with a resolution, and type 1 with resolution 0, are not.
    const fl = (try loc(&coordLci(34, 0, 34, 0, 2, 12, 512, 1)).coordinate()).?;
    try testing.expectEqual(@as(?f64, 2.0), fl.altitudeUnits());
    const none = (try loc(&coordLci(34, 0, 34, 0, 0, 12, 512, 1)).coordinate()).?;
    try testing.expect(none.altitudeUnits() == null);
    const zero = (try loc(&coordLci(34, 0, 34, 0, 1, 0, 512, 1)).coordinate()).?;
    try testing.expect(zero.altitudeUnits() == null);
    // Datums 1..3 are registered; 0 and 4 are not.
    for ([_]struct { d: u128, known: bool }{ .{ .d = 0, .known = false }, .{ .d = 1, .known = true }, .{ .d = 3, .known = true }, .{ .d = 4, .known = false } }) |c| {
        const cc = (try loc(&coordLci(34, 0, 34, 0, 1, 30, 0, c.d)).coordinate()).?;
        try testing.expectEqual(c.known, cc.datumKnown());
    }
}

test "lldp delta audit: ELIN 10..25, civic element header, short 802.1 TLVs stay raw, DCBX bits and table bounds" {
    // ELIN: 25 octets valid, 26 refused.
    const e25: [25]u8 = @splat('5');
    const e26: [26]u8 = @splat('5');
    try testing.expectEqual(@as(usize, 25), (try (lldp.MedLocation{ .format = 3, .data = &e25 }).elin()).?.len);
    try testing.expectError(error.BadLength, (lldp.MedLocation{ .format = 3, .data = &e26 }).elin());
    // A civic LCI whose elements end in a single octet: a header cut, reported once.
    var cit = (try (lldp.MedLocation{ .format = 2, .data = &.{ 4, 2, 'U', 'S', 5 } }).civic()).?.iterator();
    try testing.expectError(error.Malformed, cit.next());
    try testing.expect((try cit.next()) == null);
    // TLVs one octet too short stay raw (decode returns null, no read past the value).
    const o8021 = [3]u8{ 0x00, 0x80, 0xc2 };
    for ([_]struct { sub: u8, info: []const u8 }{
        .{ .sub = 5, .info = &.{ 1, 2, 3 } },
        .{ .sub = 6, .info = &.{1} },
        .{ .sub = 11, .info = &.{1} },
        .{ .sub = 12, .info = &.{ 0, 1, 2, 3, 4 } }, // a table whose entries are not a multiple of three
        .{ .sub = 7, .info = &.{ 1, 0, 0, 0 } },
    }) |c| {
        const o = lldp.OrgSpecific{ .oui = o8021, .subtype = c.sub, .info = c.info };
        try testing.expect(o.decode() == null);
    }
    // PFC: the MACsec-bypass bit is 0x40, willing 0x80, capability the low nibble.
    const pfc = (lldp.OrgSpecific{ .oui = o8021, .subtype = 11, .info = &.{ 0x48, 0x08 } }).decode().?.pfc;
    try testing.expect(pfc.mbc and !pfc.willing);
    try testing.expectEqual(@as(u4, 8), pfc.capability);
    // Application priority: one entry; the table ends at its count.
    const app = (lldp.OrgSpecific{ .oui = o8021, .subtype = 12, .info = &.{ 0, 0x23, 0x00, 0x50 } }).decode().?.app_priority;
    try testing.expectEqual(@as(usize, 1), app.count());
    try testing.expect(app.at(0) != null and app.at(1) == null);
}

test "cdp delta audit: typed accessors: wrong size is an error, absent is null, a repeated TLV is the last one" {
    var buf: [200]u8 = undefined;
    var b = try cdp.Builder.init(&buf, .{ .version = 2, .ttl_s = 180 });
    try b.addDeviceId("sw");
    try b.addTlv(0x11, &.{ 0, 0, 0, 1, 2 }); // MTU of 5 octets
    try b.addTlv(0x10, &.{ 1, 2, 3 }); // power of 3
    try b.addTlv(0x0e, &.{ 1, 0, 100, 9 }); // VoIP VLAN reply of 4
    try b.addTlv(0x17, &.{}); // empty location
    try b.addTlv(0x14, "first");
    try b.addTlv(0x14, "last");
    const f = try cdp.Frame.parse(b.finish(), .{});
    try testing.expectError(error.BadTlvValue, f.mtu());
    try testing.expectError(error.BadTlvValue, f.powerConsumptionMw());
    try testing.expectError(error.BadTlvValue, f.voipVlanReply());
    try testing.expectError(error.BadTlvValue, f.location());
    try testing.expectEqualStrings("last", (try f.systemName()).?);
    try testing.expectEqual(@as(?u8, null), try f.extendedTrust());
    try testing.expectEqual(@as(?u8, null), try f.untrustedCos());
}
