// SPDX-License-Identifier: MIT
//! Killing tests of the 2026-11-27 whole-module mutation run (netlink). Every
//! test names the class of mutant it closes; expected values come from the
//! kernel UAPI / RFC 3549 (field offsets, widths, ranges), never from running
//! the code under test. Private items are covered by tests at the end of
//! root.zig.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const native_endian = builtin.cpu.arch.endian();
const testing = std.testing;

const codec = @import("codec.zig");
const root = @import("root.zig");
const bridge = @import("bridge.zig");
const ext = @import("ext.zig");

const Attr = struct { t: u16, d: []const u8 };

fn le16(v: u16) [2]u8 {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, native_endian);
    return b;
}

fn le32(v: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, native_endian);
    return b;
}

fn be16(v: u16) [2]u8 {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .big);
    return b;
}

fn be32(v: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    return b;
}

/// fixed header bytes, padded to 4, followed by the attributes.
fn mk(fixed: []const u8, attrs: []const Attr) ![]u8 {
    var l: std.ArrayList(u8) = .empty;
    errdefer l.deinit(testing.allocator);
    try codec.appendPadded(testing.allocator, &l, fixed);
    for (attrs) |a| try codec.appendAttr(testing.allocator, &l, a.t, a.d);
    return l.toOwnedSlice(testing.allocator);
}

/// The data of the first attribute of type `t` after `fixed_len` bytes.
fn findAttr(buf: []const u8, fixed_len: usize, t: u16) !?[]const u8 {
    var it: codec.AttrIterator = .{ .buf = buf[fixed_len..] };
    while (try it.next()) |a| if (a.type == t) return a.data;
    return null;
}

fn cat8(a: [4]u8, b: [4]u8) [8]u8 {
    return .{ a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3] };
}

fn expectErr(want: anyerror, got: anyerror) !void {
    try testing.expectEqual(want, got);
}

fn msgOf(msg_type: u16, payload: []const u8) codec.Message {
    return .{ .type = msg_type, .flags = 0, .seq = 0, .pid = 0, .payload = payload };
}

// ── codec ───────────────────────────────────────────────────────────────────

test "mutation 2026-11-27: Message.attrs takes a payload of exactly the fixed length" {
    const pl: [16]u8 = @splat(0);
    const m = msgOf(0x10, &pl);
    var it = try m.attrs(16);
    try testing.expect((try it.next()) == null);
    try testing.expectError(error.Truncated, m.attrs(17));
}

test "mutation 2026-11-27: errorAttrs bounds: echoed header of exactly 16 bytes, TLVs starting at the very end" {
    // struct nlmsgerr { i32 error; struct nlmsghdr msg; } = 20 bytes, the echoed
    // header says nlmsg_len = 16, no attributes follow.
    var pl: [20]u8 = @splat(0);
    std.mem.writeInt(u32, pl[4..8], 16, native_endian);
    var m = msgOf(codec.NLMSG_ERROR, &pl);
    m.flags = codec.NLM_F_ACK_TLVS;
    var it = (try m.errorAttrs()).?;
    try testing.expect((try it.next()) == null);
    m.flags = codec.NLM_F_ACK_TLVS | codec.NLM_F_CAPPED;
    var it2 = (try m.errorAttrs()).?;
    try testing.expect((try it2.next()) == null);
}

test "mutation 2026-11-27: errorMessage skips other extended-ACK attributes" {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(testing.allocator);
    var fixed: [20]u8 = @splat(0);
    std.mem.writeInt(u32, fixed[4..8], 16, native_endian);
    try l.appendSlice(testing.allocator, &fixed);
    try codec.appendAttrU32(testing.allocator, &l, codec.NLMSGERR_ATTR.OFFS, 9);
    try codec.appendAttrString(testing.allocator, &l, codec.NLMSGERR_ATTR.MSG, "bad thing");
    var m = msgOf(codec.NLMSG_ERROR, l.items);
    m.flags = codec.NLM_F_ACK_TLVS | codec.NLM_F_CAPPED;
    const s = (try m.errorMessage()).?;
    try testing.expectEqualStrings("bad thing", s);
}

test "mutation 2026-11-27: the message walker advances by the aligned length, and records where it stopped" {
    // Message 1: nlmsg_len 17 (one payload byte, 3 bytes of pad), message 2 at offset 20.
    var buf: [36]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], 17, native_endian);
    std.mem.writeInt(u16, buf[4..6], 0x10, native_endian);
    buf[16] = 0xaa;
    std.mem.writeInt(u32, buf[20..24], 16, native_endian);
    std.mem.writeInt(u16, buf[24..26], 0x11, native_endian);
    var it: codec.MessageIterator = .{ .buf = &buf };
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u16, 0x10), a.type);
    try testing.expectEqual(@as(usize, 1), a.payload.len);
    try testing.expectEqual(@as(usize, 20), it.offset);
    const b = (try it.next()).?;
    try testing.expectEqual(@as(u16, 0x11), b.type);
    try testing.expect((try it.next()) == null);
    // A final message without its pad: the walk stops exactly at the buffer end.
    var last: codec.MessageIterator = .{ .buf = buf[0..17] };
    _ = (try last.next()).?;
    try testing.expectEqual(@as(usize, 17), last.offset);
}

test "mutation 2026-11-27: the attribute walker records where it stopped after an unpadded final attribute" {
    const buf = [_]u8{ 5, 0, 1, 0, 0xaa };
    var it: codec.AttrIterator = .{ .buf = &buf };
    const a = (try it.next()).?;
    try testing.expectEqual(@as(usize, 1), a.data.len);
    try testing.expectEqual(@as(usize, 5), it.offset);
    // Two attributes, the first unpadded-length 5 (pad to 8): the second starts at 8.
    const two = [_]u8{ 5, 0, 1, 0, 0xaa, 0, 0, 0, 4, 0, 2, 0 };
    var it2: codec.AttrIterator = .{ .buf = &two };
    _ = (try it2.next()).?;
    try testing.expectEqual(@as(usize, 8), it2.offset);
    const second = (try it2.next()).?;
    try testing.expectEqual(@as(u16, 2), second.type);
}

test "mutation 2026-11-27: attribute accessors require the exact width, one more and one less" {
    const nine: [9]u8 = @splat(1);
    const widths = [_]struct { n: usize, which: u8 }{
        .{ .n = 1, .which = 'a' }, .{ .n = 2, .which = 'b' }, .{ .n = 4, .which = 'c' },
        .{ .n = 4, .which = 'd' }, .{ .n = 2, .which = 'e' }, .{ .n = 4, .which = 'f' },
        .{ .n = 8, .which = 'g' },
    };
    for (widths) |w| {
        for ([_]usize{ w.n - 1, w.n + 1 }) |len| {
            const a: codec.Attr = .{ .type = 1, .raw_type = 1, .data = nine[0..len] };
            const bad = error.BadLength;
            switch (w.which) {
                'a' => try testing.expectError(bad, a.asU8()),
                'b' => try testing.expectError(bad, a.asU16()),
                'c' => try testing.expectError(bad, a.asU32()),
                'd' => try testing.expectError(bad, a.asI32()),
                'e' => try testing.expectError(bad, a.asBe16()),
                'f' => try testing.expectError(bad, a.asBe32()),
                else => try testing.expectError(bad, a.asBe64()),
            }
        }
    }
}

test "mutation 2026-11-27: appendAttr and appendAttrString accept the largest u16 length and refuse one more" {
    const big = try testing.allocator.alloc(u8, 65532);
    defer testing.allocator.free(big);
    @memset(big, 'x');
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(testing.allocator);
    // 4 + 65531 = 65535 fits the u16 length; 4 + 65532 does not.
    try codec.appendAttr(testing.allocator, &l, 7, big[0..65531]);
    try testing.expectEqual(@as(u16, 65535), std.mem.readInt(u16, l.items[0..2], native_endian));
    try testing.expectError(error.AttrTooLong, codec.appendAttr(testing.allocator, &l, 7, big[0..65532]));
    var s: std.ArrayList(u8) = .empty;
    defer s.deinit(testing.allocator);
    // 4 + 65530 + 1 (NUL) = 65535.
    try codec.appendAttrString(testing.allocator, &s, 7, big[0..65530]);
    try testing.expectEqual(@as(u16, 65535), std.mem.readInt(u16, s.items[0..2], native_endian));
    try testing.expectError(error.AttrTooLong, codec.appendAttrString(testing.allocator, &s, 7, big[0..65531]));
}

test "mutation 2026-11-27: appendAttrU64 is 12 bytes, host order, the type it was given" {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(testing.allocator);
    try codec.appendAttrU64(testing.allocator, &l, 7, 0x0102030405060708);
    var want: [12]u8 = undefined;
    std.mem.writeInt(u16, want[0..2], 12, native_endian);
    std.mem.writeInt(u16, want[2..4], 7, native_endian);
    std.mem.writeInt(u64, want[4..12], 0x0102030405060708, native_endian);
    try testing.expectEqualSlices(u8, &want, l.items);
}

test "mutation 2026-11-27: the fixed-width appenders write the type they were given" {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(testing.allocator);
    try codec.appendAttrU8(testing.allocator, &l, 11, 1);
    try codec.appendAttrU16(testing.allocator, &l, 12, 2);
    try codec.appendAttrU32(testing.allocator, &l, 13, 3);
    try codec.appendAttrBe16(testing.allocator, &l, 14, 4);
    try codec.appendAttrBe32(testing.allocator, &l, 15, 5);
    try codec.appendAttrBe64(testing.allocator, &l, 16, 6);
    var it: codec.AttrIterator = .{ .buf = l.items };
    var want: u16 = 11;
    while (try it.next()) |a| : (want += 1) try testing.expectEqual(want, a.type);
    try testing.expectEqual(@as(u16, 17), want);
}

// ── errno mapping ───────────────────────────────────────────────────────────

fn neg(e: linux.E) i32 {
    return -@as(i32, @intCast(@backingInt(e)));
}

test "mutation 2026-11-27: errorFromCode maps every errno of its table, nothing else" {
    try expectErr(error.AccessDenied, root.errorFromCode(neg(.PERM)));
    try expectErr(error.AccessDenied, root.errorFromCode(neg(.ACCES)));
    try expectErr(error.InvalidRequest, root.errorFromCode(neg(.INVAL)));
    try expectErr(error.InvalidRequest, root.errorFromCode(neg(.OPNOTSUPP)));
    try expectErr(error.SystemResources, root.errorFromCode(neg(.NOBUFS)));
    try expectErr(error.SystemResources, root.errorFromCode(neg(.NOMEM)));
    try expectErr(error.Unexpected, root.errorFromCode(neg(.NOENT)));
    try expectErr(error.Unexpected, root.errorFromCode(std.math.minInt(i32)));
    try expectErr(error.Unexpected, root.errorFromCode(1));
}

test "mutation 2026-11-27: writeErrorFromCode maps every errno of its table, nothing else" {
    const E = linux.E;
    const table = [_]struct { e: E, want: root.RequestError }{
        .{ .e = .PERM, .want = error.AccessDenied },                .{ .e = .ACCES, .want = error.AccessDenied },
        .{ .e = .EXIST, .want = error.Exists },                     .{ .e = .NOENT, .want = error.NotFound },
        .{ .e = .SRCH, .want = error.NotFound },                    .{ .e = .NODEV, .want = error.NoSuchDevice },
        .{ .e = .ADDRNOTAVAIL, .want = error.AddressNotAvailable }, .{ .e = .NETUNREACH, .want = error.NetworkUnreachable },
        .{ .e = .HOSTUNREACH, .want = error.NetworkUnreachable },   .{ .e = .NETDOWN, .want = error.NetworkDown },
        .{ .e = .BUSY, .want = error.Busy },                        .{ .e = .INVAL, .want = error.InvalidRequest },
        .{ .e = .OPNOTSUPP, .want = error.NotSupported },           .{ .e = .AFNOSUPPORT, .want = error.NotSupported },
        .{ .e = .PROTONOSUPPORT, .want = error.NotSupported },      .{ .e = .NOBUFS, .want = error.SystemResources },
        .{ .e = .NOMEM, .want = error.SystemResources },
    };
    for (table) |t| try expectErr(t.want, root.writeErrorFromCode(neg(t.e)));
    try expectErr(error.Unexpected, root.writeErrorFromCode(neg(.IO)));
    try expectErr(error.Unexpected, root.writeErrorFromCode(std.math.minInt(i32)));
    try expectErr(error.Unexpected, root.writeErrorFromCode(5));
}

// ── parsers: fixed headers, boundaries, width strictness ────────────────────

test "mutation 2026-11-27: parseAddress reads every fixed field from its own byte" {
    const fixed = [_]u8{ 2, 24, 0x80, 253, 7, 0, 0, 0 };
    const p = try mk(&fixed, &.{.{ .t = 2, .d = &.{ 10, 0, 0, 1 } }});
    defer testing.allocator.free(p);
    const a = (try root.parseAddress(p)).?;
    try testing.expectEqual(@as(u8, 2), a.family);
    try testing.expectEqual(@as(u8, 24), a.prefixlen);
    try testing.expectEqual(@as(u8, 0x80), a.flags);
    try testing.expectEqual(@as(u8, 253), a.scope);
    try testing.expectEqual(@as(u32, 7), a.ifindex);
}

test "mutation 2026-11-27: parseAddress attribute edges: label of exactly 16 bytes, short cacheinfo, IFA_FLAGS" {
    const fixed = [_]u8{ 2, 24, 0, 0, 1, 0, 0, 0 };
    const label16 = "0123456789abcdef";
    const p = try mk(&fixed, &.{
        .{ .t = 2, .d = &.{ 10, 0, 0, 1 } },
        .{ .t = 3, .d = label16 },
        .{ .t = 6, .d = &cat8(le32(5), le32(6)) }, // 8-byte cacheinfo: ignored, never an error
        .{ .t = 8, .d = &le32(0x1ff) },
    });
    defer testing.allocator.free(p);
    const a = (try root.parseAddress(p)).?;
    try testing.expectEqualStrings(label16, a.label());
    try testing.expectEqual(root.infinite_lft, a.preferred_lft);
    try testing.expectEqual(root.infinite_lft, a.valid_lft);
    try testing.expectEqual(@as(u32, 0x1ff), a.flags32);
    // A 17-byte label is refused.
    const p2 = try mk(&fixed, &.{ .{ .t = 2, .d = &.{ 10, 0, 0, 1 } }, .{ .t = 3, .d = "0123456789abcdefg" } });
    defer testing.allocator.free(p2);
    try testing.expectError(error.BadLength, root.parseAddress(p2));
    // IFA_FLAGS of the wrong width is ignored, the record survives.
    const p3 = try mk(&fixed, &.{ .{ .t = 2, .d = &.{ 10, 0, 0, 1 } }, .{ .t = 8, .d = &.{ 1, 2, 3 } } });
    defer testing.allocator.free(p3);
    try testing.expectEqual(@as(u32, 0), (try root.parseAddress(p3)).?.flags32);
}

test "mutation 2026-11-27: parseRoute reads every fixed field from its own byte" {
    var fixed: [12]u8 = .{ 2, 24, 9, 0x10, 254, 4, 253, 1, 0, 0, 0, 0 };
    std.mem.writeInt(u32, fixed[8..12], 0x01020304, native_endian);
    const p = try mk(&fixed, &.{});
    defer testing.allocator.free(p);
    const r = (try root.parseRoute(p)).?;
    try testing.expectEqual(@as(u8, 2), r.family);
    try testing.expectEqual(@as(u8, 24), r.dst_prefixlen);
    try testing.expectEqual(@as(u8, 0x10), r.tos);
    try testing.expectEqual(@as(u32, 254), r.table);
    try testing.expectEqual(@as(u8, 4), r.protocol);
    try testing.expectEqual(@as(u8, 253), r.scope);
    try testing.expectEqual(@as(u8, 1), r.rtype);
    try testing.expectEqual(@as(u32, 0x01020304), r.flags);
}

test "mutation 2026-11-27: parseRoute width strictness: OIF/PRIORITY/TABLE are errors, NH_ID is tolerated" {
    const fixed: [12]u8 = @splat(0);
    for ([_]u16{ root.RTA.OIF, root.RTA.PRIORITY, root.RTA.TABLE }) |t| {
        const p = try mk(&fixed, &.{.{ .t = t, .d = &.{ 1, 2, 3 } }});
        defer testing.allocator.free(p);
        try testing.expectError(error.BadLength, root.parseRoute(p));
    }
    const p = try mk(&fixed, &.{.{ .t = root.RTA.NH_ID, .d = &.{ 1, 2, 3 } }});
    defer testing.allocator.free(p);
    try testing.expectEqual(@as(u32, 0), (try root.parseRoute(p)).?.nhid);
    // The same attributes at their right width are read.
    const ok = try mk(&fixed, &.{
        .{ .t = root.RTA.OIF, .d = &le32(9) },
        .{ .t = root.RTA.PRIORITY, .d = &le32(100) },
        .{ .t = root.RTA.TABLE, .d = &le32(1000) },
        .{ .t = root.RTA.NH_ID, .d = &le32(77) },
    });
    defer testing.allocator.free(ok);
    const r = (try root.parseRoute(ok)).?;
    try testing.expectEqual(@as(u32, 9), r.oif);
    try testing.expectEqual(@as(u32, 100), r.priority);
    try testing.expectEqual(@as(u32, 1000), r.table);
    try testing.expectEqual(@as(u32, 77), r.nhid);
}

test "mutation 2026-11-27: every parser accepts a payload of exactly its fixed length" {
    const z16: [16]u8 = @splat(0);
    try testing.expect((try root.parseLink(z16[0..16])) != null);
    try testing.expect((try root.parseRoute(z16[0..12])) != null);
    try testing.expect((try root.parseNeighbor(z16[0..12])) != null);
    try testing.expect((try root.parseRule(z16[0..12])) != null);
    try testing.expect((try root.parseAddress(z16[0..8])) == null); // no address: skipped, not an error
    try testing.expectError(error.Truncated, root.parseRoute(z16[0..11]));
    try testing.expectError(error.Truncated, root.parseNeighbor(z16[0..11]));
    try testing.expectError(error.Truncated, root.parseRule(z16[0..11]));
    var f: [12]u8 = @splat(0);
    f[0] = root.AF.BRIDGE;
    try testing.expect((try bridge.parseFdb(&f)) != null);
    var bp: [16]u8 = @splat(0);
    bp[0] = root.AF.BRIDGE;
    try testing.expect((try bridge.parseBrport(&bp)) == null);
    var out: std.ArrayList(bridge.VlanEntry) = .empty;
    defer out.deinit(testing.allocator);
    try bridge.parseVlans(testing.allocator, &out, &bp);
    try testing.expectEqual(@as(usize, 0), out.items.len);
}

test "mutation 2026-11-27: parseNeighbor reads flags and type from their own bytes; lladdr bounds" {
    var fixed: [12]u8 = .{ 2, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0x42, 5 };
    std.mem.writeInt(u16, fixed[8..10], 0x0082, native_endian);
    const lladdr32: [32]u8 = @splat(0xab);
    const p = try mk(&fixed, &.{
        .{ .t = root.NDA.DST, .d = &.{ 10, 0, 0, 9 } },
        .{ .t = root.NDA.LLADDR, .d = &lladdr32 },
    });
    defer testing.allocator.free(p);
    const n = (try root.parseNeighbor(p)).?;
    try testing.expectEqual(@as(u8, 2), n.family);
    try testing.expectEqual(@as(u32, 9), n.ifindex);
    try testing.expectEqual(@as(u16, 0x0082), n.state);
    try testing.expectEqual(@as(u8, 0x42), n.flags);
    try testing.expectEqual(@as(u8, 5), n.ntype);
    try testing.expectEqual(@as(usize, 32), n.lladdrBytes().len);
    // 33 bytes do not fit: ignored, not a crash.
    const lladdr33: [33]u8 = @splat(0xab);
    const p2 = try mk(&fixed, &.{.{ .t = root.NDA.LLADDR, .d = &lladdr33 }});
    defer testing.allocator.free(p2);
    try testing.expectEqual(@as(usize, 0), (try root.parseNeighbor(p2)).?.lladdrBytes().len);
}

test "mutation 2026-11-27: parseRule reads every fixed field from its own byte" {
    var fixed: [12]u8 = .{ 2, 24, 8, 4, 100, 0, 0, 7, 0, 0, 0, 0 };
    std.mem.writeInt(u32, fixed[8..12], root.FIB_RULE_INVERT, native_endian);
    const p = try mk(&fixed, &.{});
    defer testing.allocator.free(p);
    const r = (try root.parseRule(p)).?;
    try testing.expectEqual(@as(u8, 2), r.family);
    try testing.expectEqual(@as(u8, 24), r.dst_len);
    try testing.expectEqual(@as(u8, 8), r.src_len);
    try testing.expectEqual(@as(u8, 4), r.tos);
    try testing.expectEqual(@as(u32, 100), r.table);
    try testing.expectEqual(@as(u8, 7), r.action);
    try testing.expectEqual(root.FIB_RULE_INVERT, r.flags);
}

test "mutation 2026-11-27: parseRule attribute edges: names of exactly 16 bytes, widths, ranges" {
    const fixed: [12]u8 = @splat(0);
    const n16 = "0123456789abcdef";
    const p = try mk(&fixed, &.{
        .{ .t = root.FRA.IIFNAME, .d = n16 },
        .{ .t = root.FRA.OIFNAME, .d = n16 },
        .{ .t = root.FRA.FWMARK, .d = &le32(0x10) },
        .{ .t = root.FRA.FWMASK, .d = &le32(0xff) },
        .{ .t = root.FRA.TABLE, .d = &le32(4000) },
        .{ .t = root.FRA.GOTO, .d = &le32(5) },
        .{ .t = root.FRA.SUPPRESS_PREFIXLEN, .d = &le32(0) },
        .{ .t = root.FRA.SUPPRESS_IFGROUP, .d = &le32(3) },
        .{ .t = root.FRA.L3MDEV, .d = &.{1} },
        .{ .t = root.FRA.PROTOCOL, .d = &.{4} },
        .{ .t = root.FRA.IP_PROTO, .d = &.{6} },
    });
    defer testing.allocator.free(p);
    const r = (try root.parseRule(p)).?;
    try testing.expectEqualStrings(n16, r.iifname());
    try testing.expectEqualStrings(n16, r.oifname());
    try testing.expectEqual(@as(?u32, 0x10), r.fwmark);
    try testing.expectEqual(@as(?u32, 0xff), r.fwmask);
    try testing.expectEqual(@as(u32, 4000), r.table);
    try testing.expectEqual(@as(?u32, 5), r.goto);
    try testing.expectEqual(@as(?u32, 0), r.suppress_prefixlen);
    try testing.expectEqual(@as(?u32, 3), r.suppress_ifgroup);
    try testing.expect(r.l3mdev);
    try testing.expectEqual(@as(u8, 4), r.protocol);
    try testing.expectEqual(@as(u8, 6), r.ipproto);
    // Wrong widths: the strict ones are errors ...
    for ([_]u16{ root.FRA.FWMARK, root.FRA.FWMASK, root.FRA.TABLE, root.FRA.PRIORITY }) |t| {
        const bad = try mk(&fixed, &.{.{ .t = t, .d = &.{ 1, 2, 3 } }});
        defer testing.allocator.free(bad);
        try testing.expectError(error.BadLength, root.parseRule(bad));
    }
    // ... the tolerant ones leave the field at its default and keep the record.
    const tol = try mk(&fixed, &.{
        .{ .t = root.FRA.GOTO, .d = &.{ 1, 2, 3 } },
        .{ .t = root.FRA.SUPPRESS_PREFIXLEN, .d = &.{ 1, 2, 3 } },
        .{ .t = root.FRA.SUPPRESS_IFGROUP, .d = &.{ 1, 2, 3 } },
        .{ .t = root.FRA.L3MDEV, .d = &.{ 1, 2 } },
        .{ .t = root.FRA.PROTOCOL, .d = &.{ 1, 2 } },
        .{ .t = root.FRA.IP_PROTO, .d = &.{ 1, 2 } },
        .{ .t = root.FRA.SPORT_RANGE, .d = &.{ 1, 2, 3, 4, 5 } },
        .{ .t = root.FRA.DPORT_RANGE, .d = &.{ 1, 2, 3, 4, 5 } },
        .{ .t = root.FRA.UID_RANGE, .d = &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 } },
    });
    defer testing.allocator.free(tol);
    const t = (try root.parseRule(tol)).?;
    try testing.expectEqual(@as(?u32, null), t.goto);
    try testing.expectEqual(@as(?u32, null), t.suppress_prefixlen);
    try testing.expectEqual(@as(?u32, null), t.suppress_ifgroup);
    try testing.expect(!t.l3mdev);
    try testing.expectEqual(@as(u8, 0), t.protocol);
    try testing.expectEqual(@as(u8, 0), t.ipproto);
    try testing.expect(t.sport == null);
    try testing.expect(t.dport == null);
    try testing.expect(t.uid_range == null);
}

test "mutation 2026-11-27: parseLink width strictness of the link attributes" {
    const fixed: [16]u8 = @splat(0);
    for ([_]u16{ root.IFLA_LINK, root.IFLA_MASTER, root.IFLA_OPERSTATE }) |t| {
        const p = try mk(&fixed, &.{.{ .t = t, .d = &.{ 1, 2, 3 } }});
        defer testing.allocator.free(p);
        try testing.expectError(error.BadLength, root.parseLink(p));
    }
    // The optional counters and flags: a wrong width leaves the default, the record survives.
    const tolerated = [_]u16{
        root.IFLA_TXQLEN,       root.IFLA_GROUP,   root.IFLA_NUM_TX_QUEUES, root.IFLA_NUM_RX_QUEUES,
        root.IFLA_MIN_MTU,      root.IFLA_MAX_MTU, root.IFLA_PROMISCUITY,   root.IFLA_CARRIER,
        root.IFLA_LINK_NETNSID,
    };
    for (tolerated) |t| {
        const p = try mk(&fixed, &.{.{ .t = t, .d = &.{ 1, 2, 3 } }});
        defer testing.allocator.free(p);
        const l = (try root.parseLink(p)).?;
        try testing.expectEqual(@as(u32, 0), l.txqlen + l.group + l.num_tx_queues + l.num_rx_queues + l.min_mtu + l.max_mtu + l.promiscuity);
        try testing.expect(l.carrier == null);
        try testing.expect(l.link_netnsid == null);
    }
}

test "mutation 2026-11-27: parseLink: a 16-byte name, a 6-byte MAC only, vlan id width" {
    const fixed: [16]u8 = @splat(0);
    const p = try mk(&fixed, &.{
        .{ .t = root.IFLA_IFNAME, .d = "0123456789abcde\x00" }, // 15 chars + NUL = 16 on the wire
        .{ .t = root.IFLA_ADDRESS, .d = &.{ 1, 2, 3, 4, 5, 6, 7, 8 } }, // 8 bytes (not EUI-48): no MAC
    });
    defer testing.allocator.free(p);
    const l = (try root.parseLink(p)).?;
    try testing.expectEqualStrings("0123456789abcde", l.name());
    try testing.expect(l.mac == null);
    const p16 = try mk(&fixed, &.{.{ .t = root.IFLA_IFNAME, .d = "0123456789abcdef" }});
    defer testing.allocator.free(p16);
    try testing.expectEqual(@as(usize, 16), (try root.parseLink(p16)).?.name().len);
    // IFLA_VLAN_ID of the wrong width inside a "vlan" is an error.
    var li: std.ArrayList(u8) = .empty;
    defer li.deinit(testing.allocator);
    try codec.appendAttrString(testing.allocator, &li, root.IFLA_INFO.KIND, "vlan");
    const dat = try codec.nestBegin(testing.allocator, &li, root.IFLA_INFO.DATA);
    try codec.appendAttr(testing.allocator, &li, root.IFLA_VLAN.ID, &.{ 1, 2, 3 });
    try codec.nestEnd(&li, dat);
    const pv = try mk(&fixed, &.{.{ .t = root.IFLA_LINKINFO, .d = li.items }});
    defer testing.allocator.free(pv);
    try testing.expectError(error.BadLength, root.parseLink(pv));
}

test "mutation 2026-11-27: parseEvent keeps new and del apart for every object" {
    const z: [16]u8 = @splat(0);
    var addr: [12]u8 = @splat(0);
    addr[0] = 2;
    addr[1] = 8;
    const ap = try mk(addr[0..8], &.{.{ .t = 2, .d = &.{ 10, 0, 0, 1 } }});
    defer testing.allocator.free(ap);
    const Tag = std.meta.Tag(root.Event);
    const cases = [_]struct { t: u16, p: []const u8, want: Tag }{
        .{ .t = root.RTM_NEWLINK, .p = &z, .want = .link_new },
        .{ .t = root.RTM_DELLINK, .p = &z, .want = .link_del },
        .{ .t = root.RTM_NEWADDR, .p = ap, .want = .addr_new },
        .{ .t = root.RTM_DELADDR, .p = ap, .want = .addr_del },
        .{ .t = root.RTM_NEWROUTE, .p = z[0..12], .want = .route_new },
        .{ .t = root.RTM_DELROUTE, .p = z[0..12], .want = .route_del },
        .{ .t = root.RTM_NEWNEIGH, .p = z[0..12], .want = .neigh_new },
        .{ .t = root.RTM_DELNEIGH, .p = z[0..12], .want = .neigh_del },
        .{ .t = root.RTM_NEWRULE, .p = z[0..12], .want = .rule_new },
        .{ .t = root.RTM_DELRULE, .p = z[0..12], .want = .rule_del },
    };
    for (cases) |c| {
        const ev = (try root.parseEvent(msgOf(c.t, c.p))).?;
        try testing.expectEqual(c.want, std.meta.activeTag(ev));
    }
    try testing.expect((try root.parseEvent(msgOf(codec.NLMSG_DONE, &z))) == null);
}

// ── request builders (rtnetlink) ────────────────────────────────────────────

const gpa = testing.allocator;

test "mutation 2026-11-27: address request: flags, scope, peer, broadcast, label, lifetimes" {
    const req = try root.builders.address(gpa, 1, root.RTM_NEWADDR, (root.Create{}).flags(), .{
        .ifindex = 3,
        .local = &.{ 10, 0, 0, 1 },
        .prefixlen = 32,
        .peer = &.{ 10, 0, 0, 2 },
        .broadcast = &.{ 10, 0, 0, 255 },
        .label = "lo:1",
        .scope = root.RT_SCOPE.HOST,
        .flags = 0x80,
        .flags32 = 0x1ff,
        .family = root.AF.INET,
        .preferred_lft = 100,
    });
    defer gpa.free(req);
    const p = req[16..];
    try testing.expectEqual(@as(u8, 2), p[0]);
    try testing.expectEqual(@as(u8, 32), p[1]);
    try testing.expectEqual(@as(u8, 0x80), p[2]);
    try testing.expectEqual(@as(u8, 254), p[3]);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, (try findAttr(p, 8, 2)).?);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, (try findAttr(p, 8, 1)).?);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 255 }, (try findAttr(p, 8, 4)).?);
    try testing.expectEqualSlices(u8, "lo:1\x00", (try findAttr(p, 8, 3)).?);
    try testing.expectEqualSlices(u8, &le32(0x1ff), (try findAttr(p, 8, 8)).?);
    const ci = (try findAttr(p, 8, 6)).?;
    try testing.expectEqual(@as(usize, 16), ci.len);
    try testing.expectEqual(@as(u32, 100), std.mem.readInt(u32, ci[0..4], native_endian));
    try testing.expectEqual(@as(u32, 0xffffffff), std.mem.readInt(u32, ci[4..8], native_endian));
    // Only the valid lifetime set: the preferred one is infinite, not 0.
    const req2 = try root.builders.address(gpa, 1, root.RTM_NEWADDR, 0, .{
        .ifindex = 3,
        .local = &.{ 10, 0, 0, 1 },
        .prefixlen = 24,
        .valid_lft = 200,
    });
    defer gpa.free(req2);
    const ci2 = (try findAttr(req2[16..], 8, 6)).?;
    try testing.expectEqual(@as(u32, 0xffffffff), std.mem.readInt(u32, ci2[0..4], native_endian));
    try testing.expectEqual(@as(u32, 200), std.mem.readInt(u32, ci2[4..8], native_endian));
    // Neither set: no IFA_CACHEINFO at all.
    const req3 = try root.builders.address(gpa, 1, root.RTM_NEWADDR, 0, .{ .ifindex = 3, .local = &.{ 10, 0, 0, 1 }, .prefixlen = 24 });
    defer gpa.free(req3);
    try testing.expect((try findAttr(req3[16..], 8, 6)) == null);
}

test "mutation 2026-11-27: address request refusals and prefix bounds" {
    const v4: []const u8 = &.{ 10, 0, 0, 1 };
    const v6: [16]u8 = .{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expectError(error.MixedFamilies, root.builders.address(gpa, 1, root.RTM_NEWADDR, 0, .{ .ifindex = 1, .local = v4, .prefixlen = 24, .broadcast = &v6 }));
    try testing.expectError(error.MixedFamilies, root.builders.address(gpa, 1, root.RTM_NEWADDR, 0, .{ .ifindex = 1, .local = v4, .prefixlen = 24, .family = root.AF.INET6 }));
    const ok4 = try root.builders.address(gpa, 1, root.RTM_NEWADDR, 0, .{ .ifindex = 1, .local = v4, .prefixlen = 32 });
    gpa.free(ok4);
    try testing.expectError(error.InvalidAddressLength, root.builders.address(gpa, 1, root.RTM_NEWADDR, 0, .{ .ifindex = 1, .local = v4, .prefixlen = 33 }));
    const ok6 = try root.builders.address(gpa, 1, root.RTM_NEWADDR, 0, .{ .ifindex = 1, .local = &v6, .prefixlen = 128 });
    gpa.free(ok6);
    try testing.expectError(error.InvalidAddressLength, root.builders.address(gpa, 1, root.RTM_NEWADDR, 0, .{ .ifindex = 1, .local = &v6, .prefixlen = 129 }));
    // An equal-length broadcast and a matching explicit family are fine.
    const okb = try root.builders.address(gpa, 1, root.RTM_NEWADDR, 0, .{ .ifindex = 1, .local = v4, .prefixlen = 24, .broadcast = &.{ 10, 0, 0, 255 }, .family = root.AF.INET });
    gpa.free(okb);
}

test "mutation 2026-11-27: route request: mixed families, the table boundary, rtm_flags, host prefix" {
    const v4: []const u8 = &.{ 10, 0, 0, 0 };
    const v6src: [16]u8 = @splat(1);
    try testing.expectError(error.MixedFamilies, root.builders.route(gpa, 1, root.RTM_NEWROUTE, 0, .{ .dst = v4, .dst_prefixlen = 24, .prefsrc = &v6src }));
    // table 255 still fits rtm_table; 256 moves to RTA_TABLE and leaves rtm_table at 0.
    const r255 = try root.builders.route(gpa, 1, root.RTM_NEWROUTE, 0, .{ .dst = v4, .dst_prefixlen = 24, .table = 255, .rt_flags = 4 });
    defer gpa.free(r255);
    try testing.expectEqual(@as(u8, 255), r255[16 + 4]);
    try testing.expect((try findAttr(r255[16..], 12, root.RTA.TABLE)) == null);
    try testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, r255[16 + 8 ..][0..4], native_endian));
    const r256 = try root.builders.route(gpa, 1, root.RTM_NEWROUTE, 0, .{ .dst = v4, .dst_prefixlen = 24, .table = 256 });
    defer gpa.free(r256);
    try testing.expectEqual(@as(u8, 0), r256[16 + 4]);
    try testing.expectEqualSlices(u8, &le32(256), (try findAttr(r256[16..], 12, root.RTA.TABLE)).?);
    // /32 is a legal IPv4 prefix, /33 is not.
    const r32 = try root.builders.route(gpa, 1, root.RTM_NEWROUTE, 0, .{ .dst = v4, .dst_prefixlen = 32 });
    gpa.free(r32);
    try testing.expectError(error.InvalidAddressLength, root.builders.route(gpa, 1, root.RTM_NEWROUTE, 0, .{ .dst = v4, .dst_prefixlen = 33 }));
}

test "mutation 2026-11-27: link-set request: each attribute alone is a change; mask and value arithmetic" {
    const alone = [_]root.LinkChange{
        .{ .mac = &.{ 2, 0, 0, 0, 0, 1 } },
        .{ .txqlen = 1000 },
        .{ .netns_fd = 5 },
        .{ .netns_pid = 77 },
        .{ .group = 3 },
    };
    const types = [_]u16{ root.IFLA_ADDRESS, root.IFLA_TXQLEN, root.IFLA_NET_NS_FD, root.IFLA_NET_NS_PID, root.IFLA_GROUP };
    for (alone, types) |c, t| {
        const req = try root.builders.linkSet(gpa, 1, 2, c);
        defer gpa.free(req);
        try testing.expect((try findAttr(req[16..], 16, t)) != null);
    }
    try testing.expectError(error.InvalidLinkAddress, root.builders.linkSet(gpa, 1, 2, .{ .mac = "" }));
    try testing.expectError(error.InvalidLinkAddress, root.builders.linkSet(gpa, 1, 2, .{ .mac = &@as([33]u8, @splat(1)) }));
    // flags is gated by flags_mask: 0xf & 0x3 = 0x3, ifi_change = 0x3.
    const r = try root.builders.linkSet(gpa, 1, 2, .{ .flags = 0xf, .flags_mask = 0x3 });
    defer gpa.free(r);
    try testing.expectEqual(@as(u32, 0x3), std.mem.readInt(u32, r[16 + 8 ..][0..4], native_endian));
    try testing.expectEqual(@as(u32, 0x3), std.mem.readInt(u32, r[16 + 12 ..][0..4], native_endian));
    // up = false clears IFF_UP even when `flags` carries it.
    const d = try root.builders.linkSet(gpa, 1, 2, .{ .up = false, .flags = root.IFF.UP | root.IFF.PROMISC, .flags_mask = root.IFF.UP | root.IFF.PROMISC });
    defer gpa.free(d);
    try testing.expectEqual(root.IFF.PROMISC, std.mem.readInt(u32, d[16 + 8 ..][0..4], native_endian));
    try testing.expectEqual(root.IFF.UP | root.IFF.PROMISC, std.mem.readInt(u32, d[16 + 12 ..][0..4], native_endian));
}

test "mutation 2026-11-27: link-add request: mtu and mac travel, mac is validated, kind aliases are accepted" {
    const base: root.LinkAddSpec = .{ .name = "x0", .kind = "dummy", .mtu = 1400, .mac = &.{ 2, 0, 0, 0, 0, 9 } };
    const req = try root.builders.linkAdd(gpa, 1, 0, base);
    defer gpa.free(req);
    try testing.expectEqualSlices(u8, &le32(1400), (try findAttr(req[16..], 16, root.IFLA_MTU)).?);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0, 0, 9 }, (try findAttr(req[16..], 16, root.IFLA_ADDRESS)).?);
    try testing.expectError(error.InvalidLinkAddress, root.builders.linkAdd(gpa, 1, 0, .{ .name = "x0", .kind = "dummy", .mac = "" }));
    const ipvtap = try root.builders.linkAdd(gpa, 1, 0, .{ .name = "x1", .kind = "ipvtap", .parent = 2, .kind_data = .{ .ipvlan = .{} } });
    gpa.free(ipvtap);
    const gre = try root.builders.linkAdd(gpa, 1, 0, .{ .name = "x2", .kind = "gre", .kind_data = .{ .gre = .{} } });
    gpa.free(gre);
    const sit = try root.builders.linkAdd(gpa, 1, 0, .{ .name = "x3", .kind = "sit", .kind_data = .{ .iptun = .{} } });
    gpa.free(sit);
    // The lower device of an ipip/sit tunnel is inside its own data.
    const tun = try root.builders.linkAdd(gpa, 1, 0, .{ .name = "x4", .kind = "ipip", .parent = 5, .kind_data = .{ .iptun = .{ .ttl = 3 } } });
    defer gpa.free(tun);
    try testing.expect((try findAttr(tun[16..], 16, root.IFLA_LINK)) == null);
    const li = (try findAttr(tun[16..], 16, root.IFLA_LINKINFO)).?;
    const data = (try findAttr(li, 0, root.IFLA_INFO.DATA)).?;
    try testing.expectEqualSlices(u8, &le32(5), (try findAttr(data, 0, ext.IFLA_IPTUN.LINK)).?);
}

test "mutation 2026-11-27: route-get and neighbor requests carry tos, flags and type from their own bytes" {
    const g = try root.builders.routeGet(gpa, 1, .{ .dst = &.{ 10, 0, 0, 1 }, .tos = 0x10 });
    defer gpa.free(g);
    try testing.expectEqual(@as(u8, 0x10), g[16 + 3]);
    const n = try root.builders.neighbor(gpa, 1, root.RTM_NEWNEIGH, 0, .{
        .ifindex = 4,
        .dst = &.{ 10, 0, 0, 1 },
        .lladdr = &.{ 2, 0, 0, 0, 0, 1 },
        .state = root.NUD.REACHABLE,
        .flags = 0x42,
        .ntype = 5,
    });
    defer gpa.free(n);
    try testing.expectEqual(@as(u8, 0x42), n[16 + 10]);
    try testing.expectEqual(@as(u8, 5), n[16 + 11]);
    try testing.expectError(error.MixedFamilies, root.builders.neighbor(gpa, 1, root.RTM_NEWNEIGH, 0, .{ .ifindex = 1, .dst = &.{ 10, 0, 0, 1 }, .family = root.AF.INET6 }));
    try testing.expectError(error.InvalidLinkAddress, root.builders.neighbor(gpa, 1, root.RTM_NEWNEIGH, 0, .{ .ifindex = 1, .dst = &.{ 10, 0, 0, 1 }, .lladdr = "" }));
    try testing.expectError(error.InvalidLinkAddress, root.builders.neighbor(gpa, 1, root.RTM_NEWNEIGH, 0, .{ .ifindex = 1, .dst = &.{ 10, 0, 0, 1 }, .lladdr = &@as([33]u8, @splat(1)) }));
    const l32 = try root.builders.neighbor(gpa, 1, root.RTM_NEWNEIGH, 0, .{ .ifindex = 1, .dst = &.{ 10, 0, 0, 1 }, .lladdr = &@as([32]u8, @splat(1)) });
    gpa.free(l32);
}

test "mutation 2026-11-27: rule request: a lone dst defaults to a host prefix; boundaries of lengths and ranges" {
    const r = try root.builders.rule(gpa, 1, root.RTM_NEWRULE, 0, .{ .dst = &.{ 10, 0, 0, 0 }, .table = 100 });
    defer gpa.free(r);
    try testing.expectEqual(@as(u8, 32), r[16 + 1]); // dst_len
    try testing.expectEqual(@as(u8, 0), r[16 + 2]); // src_len: no src
    const r2 = try root.builders.rule(gpa, 1, root.RTM_NEWRULE, 0, .{ .dst = &.{ 10, 0, 0, 0 }, .dst_len = 32, .table = 100 });
    gpa.free(r2);
    const r3 = try root.builders.rule(gpa, 1, root.RTM_NEWRULE, 0, .{ .family = root.AF.INET, .sport = .{ .start = 80, .end = 80 }, .table = 100 });
    gpa.free(r3);
    try testing.expectError(error.InvalidPrefixLength, root.builders.rule(gpa, 1, root.RTM_NEWRULE, 0, .{ .dst = &.{ 10, 0, 0, 0 }, .dst_len = 33, .table = 100 }));
}

// ── bridge builders and parsers ─────────────────────────────────────────────

test "mutation 2026-11-27: bridge-add request: up bit, mtu, mac, option switches" {
    const up = try bridge.buildBridgeAddRequest(gpa, 1, 0, .{ .name = "br0", .up = true, .mtu = 1400, .mac = &.{ 2, 0, 0, 0, 0, 7 } });
    defer gpa.free(up);
    try testing.expectEqual(root.IFF.UP, std.mem.readInt(u32, up[16 + 8 ..][0..4], native_endian));
    try testing.expectEqual(root.IFF.UP, std.mem.readInt(u32, up[16 + 12 ..][0..4], native_endian));
    try testing.expectEqualSlices(u8, &le32(1400), (try findAttr(up[16..], 16, root.IFLA_MTU)).?);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0, 0, 7 }, (try findAttr(up[16..], 16, root.IFLA_ADDRESS)).?);
    const down = try bridge.buildBridgeAddRequest(gpa, 1, 0, .{ .name = "br0" });
    defer gpa.free(down);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, down[16 + 8 ..][0..4], native_endian));
    try testing.expectError(error.InvalidLinkAddress, bridge.buildBridgeAddRequest(gpa, 1, 0, .{ .name = "br0", .mac = "" }));
    try testing.expectError(error.InvalidLinkAddress, bridge.buildBridgeAddRequest(gpa, 1, 0, .{ .name = "br0", .mac = &@as([33]u8, @splat(1)) }));
    const m32 = try bridge.buildBridgeAddRequest(gpa, 1, 0, .{ .name = "br0", .mac = &@as([32]u8, @splat(1)) });
    gpa.free(m32);
    // Every option alone opens IFLA_INFO_DATA and writes its attribute (value 0/false included).
    const alone = [_]struct { spec: bridge.BridgeSpec, t: u16, want: []const u8 }{
        .{ .spec = .{ .name = "b", .forward_delay = 0 }, .t = 1, .want = &comptime le32(0) },
        .{ .spec = .{ .name = "b", .hello_time = 0 }, .t = 2, .want = &comptime le32(0) },
        .{ .spec = .{ .name = "b", .max_age = 0 }, .t = 3, .want = &comptime le32(0) },
        .{ .spec = .{ .name = "b", .ageing_time = 0 }, .t = 4, .want = &comptime le32(0) },
        .{ .spec = .{ .name = "b", .stp_state = 0 }, .t = 5, .want = &comptime le32(0) },
        .{ .spec = .{ .name = "b", .priority = 0 }, .t = 6, .want = &comptime le16(0) },
        .{ .spec = .{ .name = "b", .vlan_filtering = false }, .t = 7, .want = &.{0} },
        .{ .spec = .{ .name = "b", .vlan_protocol = 0x88a8 }, .t = 8, .want = &comptime be16(0x88a8) },
        .{ .spec = .{ .name = "b", .group_fwd_mask = 0 }, .t = 9, .want = &comptime le16(0) },
        .{ .spec = .{ .name = "b", .mcast_snooping = false }, .t = 23, .want = &.{0} },
        .{ .spec = .{ .name = "b", .mcast_querier = false }, .t = 25, .want = &.{0} },
        .{ .spec = .{ .name = "b", .vlan_default_pvid = 0 }, .t = 39, .want = &comptime le16(0) },
    };
    for (alone) |c| {
        const req = try bridge.buildBridgeAddRequest(gpa, 1, 0, c.spec);
        defer gpa.free(req);
        const li = (try findAttr(req[16..], 16, root.IFLA_LINKINFO)).?;
        const data = (try findAttr(li, 0, root.IFLA_INFO.DATA)).?;
        try testing.expectEqualSlices(u8, c.want, (try findAttr(data, 0, c.t)).?);
    }
}

test "mutation 2026-11-27: fdb request: type byte and address length bounds" {
    const req = try bridge.buildFdbRequest(gpa, 1, root.RTM_NEWNEIGH, 0, .{ .ifindex = 3, .lladdr = &.{ 2, 0, 0, 0, 0, 1 }, .ntype = 4 });
    defer gpa.free(req);
    try testing.expectEqual(@as(u8, 4), req[16 + 11]);
    const ok32 = try bridge.buildFdbRequest(gpa, 1, root.RTM_NEWNEIGH, 0, .{ .ifindex = 3, .lladdr = &@as([32]u8, @splat(1)) });
    gpa.free(ok32);
    try testing.expectError(error.InvalidLinkAddress, bridge.buildFdbRequest(gpa, 1, root.RTM_NEWNEIGH, 0, .{ .ifindex = 3, .lladdr = &@as([33]u8, @splat(1)) }));
}

test "mutation 2026-11-27: vlan request: vid 1 is the lowest, 4095 is refused as a range end" {
    const ok = try bridge.buildVlanRequest(gpa, 1, root.RTM_SETLINK, 3, .{ .vid = 1 });
    gpa.free(ok);
    try testing.expectError(error.InvalidVlanId, bridge.buildVlanRequest(gpa, 1, root.RTM_SETLINK, 3, .{ .vid = 0 }));
    try testing.expectError(error.InvalidVlanId, bridge.buildVlanRequest(gpa, 1, root.RTM_SETLINK, 3, .{ .vid = 10, .vid_end = 4095 }));
    try testing.expectError(error.InvalidVlanId, bridge.buildVlanRequest(gpa, 1, root.RTM_SETLINK, 3, .{ .vid = 10, .vid_end = 0 }));
}

test "mutation 2026-11-27: bridge-port request writes every option it was given" {
    const req = try bridge.buildBrportRequest(gpa, 1, 3, .{
        .guard = true,
        .fast_leave = true,
        .protect = true,
        .hairpin = true,
        .priority = 0x1234,
        .cost = 77,
        .unicast_flood = true,
        .mcast_flood = true,
        .bcast_flood = true,
        .learning = true,
        .state = 3,
        .neigh_suppress = true,
        .isolated = true,
    });
    defer gpa.free(req);
    const pi = (try findAttr(req[16..], 16, bridge.IFLA_PROTINFO)).?;
    const bools = [_]u16{
        bridge.IFLA_BRPORT.GUARD,       bridge.IFLA_BRPORT.FAST_LEAVE,    bridge.IFLA_BRPORT.PROTECT,
        bridge.IFLA_BRPORT.MODE,        bridge.IFLA_BRPORT.UNICAST_FLOOD, bridge.IFLA_BRPORT.MCAST_FLOOD,
        bridge.IFLA_BRPORT.BCAST_FLOOD, bridge.IFLA_BRPORT.LEARNING,      bridge.IFLA_BRPORT.NEIGH_SUPPRESS,
        bridge.IFLA_BRPORT.ISOLATED,
    };
    for (bools) |t| try testing.expectEqualSlices(u8, &.{1}, (try findAttr(pi, 0, t)).?);
    try testing.expectEqualSlices(u8, &le16(0x1234), (try findAttr(pi, 0, bridge.IFLA_BRPORT.PRIORITY)).?);
    try testing.expectEqualSlices(u8, &le32(77), (try findAttr(pi, 0, bridge.IFLA_BRPORT.COST)).?);
    try testing.expectEqualSlices(u8, &.{3}, (try findAttr(pi, 0, bridge.IFLA_BRPORT.STATE)).?);
}

test "mutation 2026-11-27: parseFdb reads type, lladdr and dst by their widths; attribute widths are strict" {
    var fixed: [12]u8 = .{ root.AF.BRIDGE, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0x42, 5 };
    std.mem.writeInt(u16, fixed[8..10], 0x82, native_endian);
    const p = try mk(&fixed, &.{
        .{ .t = root.NDA.LLADDR, .d = &.{ 1, 2, 3, 4, 5, 6 } },
        .{ .t = root.NDA.DST, .d = &.{ 10, 0, 0, 1 } },
        .{ .t = root.NDA.VLAN, .d = &le16(10) },
        .{ .t = root.NDA.MASTER, .d = &le32(2) },
        .{ .t = root.NDA.VNI, .d = &le32(5000) },
    });
    defer gpa.free(p);
    const e = (try bridge.parseFdb(p)).?;
    try testing.expectEqual(@as(u8, 0x42), e.flags);
    try testing.expectEqual(@as(u8, 5), e.ntype);
    try testing.expectEqual(@as(usize, 6), e.lladdrBytes().len);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, e.dstBytes());
    try testing.expectEqual(@as(?u16, 10), e.vlan);
    try testing.expectEqual(@as(?u32, 2), e.master);
    try testing.expectEqual(@as(?u32, 5000), e.vni);
    // A 16-byte dst, an 8-byte lladdr (ignored) and a 5-byte dst (ignored).
    const v6: [16]u8 = @splat(7);
    const p2 = try mk(&fixed, &.{ .{ .t = root.NDA.LLADDR, .d = &.{ 1, 2, 3, 4, 5, 6, 7, 8 } }, .{ .t = root.NDA.DST, .d = &v6 } });
    defer gpa.free(p2);
    const e2 = (try bridge.parseFdb(p2)).?;
    try testing.expectEqual(@as(usize, 0), e2.lladdrBytes().len);
    try testing.expectEqual(@as(usize, 16), e2.dstBytes().len);
    const p3 = try mk(&fixed, &.{.{ .t = root.NDA.DST, .d = &.{ 1, 2, 3, 4, 5 } }});
    defer gpa.free(p3);
    try testing.expectEqual(@as(usize, 0), (try bridge.parseFdb(p3)).?.dstBytes().len);
    for ([_]u16{ root.NDA.VLAN, root.NDA.MASTER, root.NDA.VNI }) |t| {
        const bad = try mk(&fixed, &.{.{ .t = t, .d = &.{ 1, 2, 3 } }});
        defer gpa.free(bad);
        try testing.expectError(error.BadLength, bridge.parseFdb(bad));
    }
}

fn vi(flags: u16, vid: u16) [4]u8 {
    const f = le16(flags);
    const v = le16(vid);
    return .{ f[0], f[1], v[0], v[1] };
}

test "mutation 2026-11-27: parseVlans: family gate, foreign attributes, ranges and the flag bookkeeping" {
    const P = bridge.BRIDGE_VLAN_INFO;
    var fixed: [16]u8 = @splat(0);
    fixed[0] = root.AF.BRIDGE;
    std.mem.writeInt(u32, fixed[4..8], 6, native_endian);
    var out: std.ArrayList(bridge.VlanEntry) = .empty;
    defer out.deinit(gpa);

    // 1. A non-AF_BRIDGE message yields nothing even when it carries IFLA_AF_SPEC.
    var other = fixed;
    other[0] = root.AF.INET;
    var nest: std.ArrayList(u8) = .empty;
    defer nest.deinit(gpa);
    try codec.appendAttr(gpa, &nest, bridge.IFLA_BRIDGE.VLAN_INFO, &vi(0, 5));
    const po = try mk(&other, &.{.{ .t = bridge.IFLA_AF_SPEC, .d = nest.items }});
    defer gpa.free(po);
    try bridge.parseVlans(gpa, &out, po);
    try testing.expectEqual(@as(usize, 0), out.items.len);

    // 2. A foreign sub-attribute of the wrong width is skipped, not parsed as a VlanInfo;
    //    a begin/end pair with equal vid is ONE entry; PVID survives, the range bits do not.
    var n2: std.ArrayList(u8) = .empty;
    defer n2.deinit(gpa);
    try codec.appendAttr(gpa, &n2, bridge.IFLA_BRIDGE.FLAGS, &.{ 1, 2, 3 });
    try codec.appendAttr(gpa, &n2, bridge.IFLA_BRIDGE.VLAN_INFO, &vi(P.RANGE_BEGIN | P.PVID, 10));
    try codec.appendAttr(gpa, &n2, bridge.IFLA_BRIDGE.VLAN_INFO, &vi(P.RANGE_END, 10));
    // 3. An unterminated begin is a lone entry, flags cleaned; a stray end likewise.
    try codec.appendAttr(gpa, &n2, bridge.IFLA_BRIDGE.VLAN_INFO, &vi(P.RANGE_BEGIN | P.UNTAGGED, 20));
    try codec.appendAttr(gpa, &n2, bridge.IFLA_BRIDGE.VLAN_INFO, &vi(P.UNTAGGED, 30));
    try codec.appendAttr(gpa, &n2, bridge.IFLA_BRIDGE.VLAN_INFO, &vi(P.RANGE_END | P.PVID, 40));
    const p2 = try mk(&fixed, &.{.{ .t = bridge.IFLA_AF_SPEC, .d = n2.items }});
    defer gpa.free(p2);
    try bridge.parseVlans(gpa, &out, p2);
    try testing.expectEqual(@as(usize, 4), out.items.len);
    try testing.expectEqual(@as(u32, 6), out.items[0].ifindex);
    try testing.expectEqual(@as(u16, 10), out.items[0].vid);
    try testing.expectEqual(@as(u16, 10), out.items[0].vid_end);
    try testing.expectEqual(P.PVID, out.items[0].flags);
    try testing.expectEqual(@as(u16, 20), out.items[1].vid);
    try testing.expectEqual(@as(u16, 20), out.items[1].vid_end);
    try testing.expectEqual(P.UNTAGGED, out.items[1].flags);
    try testing.expectEqual(P.UNTAGGED, out.items[2].flags);
    try testing.expectEqual(@as(u16, 40), out.items[3].vid);
    try testing.expectEqual(P.PVID, out.items[3].flags);
    // 4. A trailing begin with no further entry is emitted with its flags cleaned.
    out.clearRetainingCapacity();
    var n4: std.ArrayList(u8) = .empty;
    defer n4.deinit(gpa);
    try codec.appendAttr(gpa, &n4, bridge.IFLA_BRIDGE.VLAN_INFO, &vi(P.RANGE_BEGIN | P.PVID, 50));
    const p4 = try mk(&fixed, &.{.{ .t = bridge.IFLA_AF_SPEC, .d = n4.items }});
    defer gpa.free(p4);
    try bridge.parseVlans(gpa, &out, p4);
    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(P.PVID, out.items[0].flags);
    // 5. VlanInfo is exactly four bytes.
    try testing.expectError(error.BadLength, bridge.VlanInfo.parse(&.{ 1, 2, 3, 4, 5 }));
    try testing.expectError(error.BadLength, bridge.VlanInfo.parse(&.{ 1, 2, 3 }));
}

test "mutation 2026-11-27: parseBrport reads every option; widths are strict, booleans are != 0" {
    var fixed: [16]u8 = @splat(0);
    std.mem.writeInt(u32, fixed[4..8], 8, native_endian);
    var on: std.ArrayList(u8) = .empty;
    defer on.deinit(gpa);
    var off: std.ArrayList(u8) = .empty;
    defer off.deinit(gpa);
    const B = bridge.IFLA_BRPORT;
    const bools = [_]u16{ B.MODE, B.LEARNING, B.UNICAST_FLOOD, B.MCAST_FLOOD, B.BCAST_FLOOD, B.NEIGH_SUPPRESS, B.ISOLATED };
    for (bools) |t| {
        try codec.appendAttr(gpa, &on, t, &.{1});
        try codec.appendAttr(gpa, &off, t, &.{0});
    }
    inline for (.{ &on, &off }) |l| {
        try codec.appendAttr(gpa, l, B.STATE, &.{3});
        try codec.appendAttr(gpa, l, B.PRIORITY, &le16(0x1234));
        try codec.appendAttr(gpa, l, B.COST, &le32(99));
    }
    const pon = try mk(&fixed, &.{ .{ .t = bridge.IFLA_MASTER, .d = &le32(2) }, .{ .t = bridge.IFLA_PROTINFO, .d = on.items } });
    defer gpa.free(pon);
    const a = (try bridge.parseBrport(pon)).?;
    try testing.expectEqual(@as(u32, 8), a.ifindex);
    try testing.expectEqual(@as(?u32, 2), a.master);
    try testing.expectEqual(@as(?u8, 3), a.state);
    try testing.expectEqual(@as(?u16, 0x1234), a.priority);
    try testing.expectEqual(@as(?u32, 99), a.cost);
    try testing.expectEqual(@as(?bool, true), a.hairpin);
    try testing.expectEqual(@as(?bool, true), a.learning);
    try testing.expectEqual(@as(?bool, true), a.unicast_flood);
    try testing.expectEqual(@as(?bool, true), a.mcast_flood);
    try testing.expectEqual(@as(?bool, true), a.bcast_flood);
    try testing.expectEqual(@as(?bool, true), a.neigh_suppress);
    try testing.expectEqual(@as(?bool, true), a.isolated);
    const poff = try mk(&fixed, &.{.{ .t = bridge.IFLA_PROTINFO, .d = off.items }});
    defer gpa.free(poff);
    const b = (try bridge.parseBrport(poff)).?;
    try testing.expectEqual(@as(?bool, false), b.hairpin);
    try testing.expectEqual(@as(?bool, false), b.learning);
    try testing.expectEqual(@as(?bool, false), b.unicast_flood);
    try testing.expectEqual(@as(?bool, false), b.mcast_flood);
    try testing.expectEqual(@as(?bool, false), b.bcast_flood);
    try testing.expectEqual(@as(?bool, false), b.neigh_suppress);
    try testing.expectEqual(@as(?bool, false), b.isolated);
    // Wrong widths are errors.
    for ([_]u16{ B.STATE, B.PRIORITY, B.COST }) |t| {
        var bad: std.ArrayList(u8) = .empty;
        defer bad.deinit(gpa);
        try codec.appendAttr(gpa, &bad, t, &.{ 1, 2, 3 });
        const pb = try mk(&fixed, &.{.{ .t = bridge.IFLA_PROTINFO, .d = bad.items }});
        defer gpa.free(pb);
        try testing.expectError(error.BadLength, bridge.parseBrport(pb));
    }
    const pm = try mk(&fixed, &.{ .{ .t = bridge.IFLA_MASTER, .d = &.{ 1, 2, 3 } }, .{ .t = bridge.IFLA_PROTINFO, .d = &.{} } });
    defer gpa.free(pm);
    try testing.expectError(error.BadLength, bridge.parseBrport(pm));
}

// ── ext: multipath, metrics, nexthop objects, link kinds ────────────────────

fn hopBytes(l: *std.ArrayList(u8), flags: u8, hops: u8, oif: u32, attrs: []const Attr) !void {
    const start = l.items.len;
    var h: [8]u8 = @splat(0);
    h[2] = flags;
    h[3] = hops;
    std.mem.writeInt(u32, h[4..8], oif, native_endian);
    try l.appendSlice(gpa, &h);
    for (attrs) |a| try codec.appendAttr(gpa, l, a.t, a.d);
    std.mem.writeInt(u16, l.items[start..][0..2], @intCast(l.items.len - start), native_endian);
}

test "mutation 2026-11-27: the multipath walker confines each hop's attributes to that hop" {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    // Hop 2's header, read as an attribute, would be RTA_GATEWAY (len 8, type 5) with its oif as data.
    try hopBytes(&l, 0, 0, 2, &.{.{ .t = root.RTA.GATEWAY, .d = &.{ 10, 0, 0, 1 } }});
    try hopBytes(&l, 5, 0, 0x01020304, &.{});
    var out: [ext.max_route_hops]ext.RouteHop = @splat(.{});
    try testing.expectEqual(@as(u16, 2), try ext.parseMultipath(l.items, &out));
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, out[0].gatewayBytes());
    try testing.expectEqual(@as(u32, 2), out[0].oif);
    try testing.expectEqual(@as(u16, 1), out[0].weight);
    try testing.expectEqual(@as(u8, 5), out[1].flags);
    try testing.expectEqual(@as(u16, 1), out[1].weight);
    try testing.expectEqual(@as(u32, 0x01020304), out[1].oif);
    try testing.expectEqual(@as(usize, 0), out[1].gatewayBytes().len);
}

test "mutation 2026-11-27: the multipath walker steps over an unpadded hop by its aligned length" {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    // Hop A: rtnexthop (8) + one attribute of 5 bytes (header + 1) = 13, padded to 16 on the wire.
    const start = l.items.len;
    var h: [8]u8 = @splat(0);
    std.mem.writeInt(u32, h[4..8], 3, native_endian);
    try l.appendSlice(gpa, &h);
    try l.appendSlice(gpa, &.{ 5, 0, 99, 0, 0xee, 0, 0, 0 });
    std.mem.writeInt(u16, l.items[start..][0..2], 13, native_endian);
    try hopBytes(&l, 0, 0, 4, &.{});
    var out: [ext.max_route_hops]ext.RouteHop = @splat(.{});
    try testing.expectEqual(@as(u16, 2), try ext.parseMultipath(l.items, &out));
    try testing.expectEqual(@as(u32, 3), out[0].oif);
    try testing.expectEqual(@as(u32, 4), out[1].oif);
}

test "mutation 2026-11-27: a hop gateway is read at 4 and 16 bytes and ignored at any other width" {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    const v6: [16]u8 = @splat(0x20);
    try hopBytes(&l, 0, 0, 1, &.{.{ .t = root.RTA.GATEWAY, .d = &v6 }});
    try hopBytes(&l, 0, 0, 2, &.{.{ .t = root.RTA.GATEWAY, .d = &.{ 1, 2, 3, 4, 5, 6, 7, 8 } }});
    var out: [ext.max_route_hops]ext.RouteHop = @splat(.{});
    try testing.expectEqual(@as(u16, 2), try ext.parseMultipath(l.items, &out));
    try testing.expectEqual(@as(usize, 16), out[0].gatewayBytes().len);
    try testing.expectEqual(@as(usize, 0), out[1].gatewayBytes().len);
}

test "mutation 2026-11-27: parseMetrics reads three values and refuses a wrong width on each" {
    const types = [_]u16{ ext.RTAX.MTU, ext.RTAX.ADVMSS, ext.RTAX.HOPLIMIT };
    const buf = try mk(&.{}, &.{
        .{ .t = types[0], .d = &le32(1400) },
        .{ .t = types[1], .d = &le32(1360) },
        .{ .t = types[2], .d = &le32(64) },
    });
    defer gpa.free(buf);
    const m = try ext.parseMetrics(buf);
    try testing.expectEqual(@as(u32, 1400), m.mtu);
    try testing.expectEqual(@as(u32, 1360), m.advmss);
    try testing.expectEqual(@as(u32, 64), m.hoplimit);
    for (types) |t| {
        const bad = try mk(&.{}, &.{.{ .t = t, .d = &.{ 1, 2, 3 } }});
        defer gpa.free(bad);
        try testing.expectError(error.BadLength, ext.parseMetrics(bad));
    }
}

test "mutation 2026-11-27: parseNexthop reads its header, group type and weights; widths are strict" {
    var fixed: [8]u8 = .{ 2, 253, 4, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, fixed[4..8], 0x01020304, native_endian);
    var grp: [16]u8 = @splat(0);
    std.mem.writeInt(u32, grp[0..4], 5, native_endian);
    grp[4] = 0;
    grp[5] = 1; // weight_high: weight = (1 << 8 | 0) + 1 = 257
    std.mem.writeInt(u32, grp[8..12], 6, native_endian);
    grp[12] = 9; // weight_low only: 9 + 1 = 10
    const p = try mk(&fixed, &.{
        .{ .t = ext.NHA.ID, .d = &le32(7) },
        .{ .t = ext.NHA.GROUP, .d = &grp },
        .{ .t = ext.NHA.GROUP_TYPE, .d = &le16(1) },
    });
    defer gpa.free(p);
    const n = (try ext.parseNexthop(p)).?;
    try testing.expectEqual(@as(u8, 2), n.family);
    try testing.expectEqual(@as(u8, 253), n.scope);
    try testing.expectEqual(@as(u8, 4), n.protocol);
    try testing.expectEqual(@as(u32, 0x01020304), n.flags);
    try testing.expectEqual(@as(u32, 7), n.id);
    try testing.expectEqual(@as(u16, 1), n.group_type);
    try testing.expectEqual(@as(u16, 2), n.group_count);
    try testing.expectEqual(@as(u32, 5), n.group[0].id);
    try testing.expectEqual(@as(u16, 257), n.group[0].weight);
    try testing.expectEqual(@as(u32, 6), n.group[1].id);
    try testing.expectEqual(@as(u16, 10), n.group[1].weight);
    for ([_]u16{ ext.NHA.ID, ext.NHA.GROUP_TYPE }) |t| {
        const bad = try mk(&fixed, &.{ .{ .t = ext.NHA.ID, .d = &le32(7) }, .{ .t = t, .d = &.{ 1, 2, 3 } } });
        defer gpa.free(bad);
        try testing.expectError(error.BadLength, ext.parseNexthop(bad));
    }
}

test "mutation 2026-11-27: nexthop spec rules and request bytes" {
    try testing.expectEqual(root.AF.INET, try ext.nexthopFamily(.{ .id = 1 }));
    try testing.expectError(error.InvalidNexthop, ext.nexthopFamily(.{ .id = 1, .group = &.{.{ .id = 2 }}, .gateway = &.{ 10, 0, 0, 1 } }));
    const g128: [128]ext.GroupMember = @splat(.{ .id = 1 });
    try testing.expectEqual(root.AF.UNSPEC, try ext.nexthopFamily(.{ .id = 1, .group = &g128 }));
    const g129: [129]ext.GroupMember = @splat(.{ .id = 1 });
    try testing.expectError(error.TooManyHops, ext.nexthopFamily(.{ .id = 1, .group = &g129 }));
    const on = try ext.buildNexthopRequest(gpa, 1, ext.RTM_NEWNEXTHOP, 0, .{ .id = 5, .gateway = &.{ 10, 0, 0, 1 }, .onlink = true });
    defer gpa.free(on);
    try testing.expectEqual(@as(u32, ext.RTNH_F.ONLINK), std.mem.readInt(u32, on[16 + 4 ..][0..4], native_endian));
    const off = try ext.buildNexthopRequest(gpa, 1, ext.RTM_NEWNEXTHOP, 0, .{ .id = 5, .gateway = &.{ 10, 0, 0, 1 } });
    defer gpa.free(off);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, off[16 + 4 ..][0..4], native_endian));
    const grp = try ext.buildNexthopRequest(gpa, 1, ext.RTM_NEWNEXTHOP, 0, .{ .id = 9, .group = &.{ .{ .id = 1, .weight = 256 }, .{ .id = 2, .weight = 3 } } });
    defer gpa.free(grp);
    const gd = (try findAttr(grp[16..], 8, ext.NHA.GROUP)).?;
    try testing.expectEqual(@as(usize, 16), gd.len);
    // weight 256 is (256 - 1) = 0x00ff: low byte 255, high byte 0; weight 3 is 2.
    try testing.expectEqual(@as(u8, 255), gd[4]);
    try testing.expectEqual(@as(u8, 0), gd[5]);
    try testing.expectEqual(@as(u8, 2), gd[12]);
    try testing.expectEqual(@as(u8, 0), gd[13]);
}

fn dataOf(list: []const u8) ![]const u8 {
    return (try findAttr(list, 0, root.IFLA_INFO.DATA)).?;
}

test "mutation 2026-11-27: vxlan / geneve encoders: address family picks the attribute; flags and limits" {
    const v6a: [16]u8 = @splat(0x20);
    const v6b: [16]u8 = @splat(0x30);
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try ext.encodeVxlan(gpa, &l, .{ .vni = 0xffffff, .group = &v6a, .local = &v6b, .learning = false, .ttl = 3, .tos = 4 }, 9);
    var d = try dataOf(l.items);
    try testing.expectEqual(@as(usize, 16), (try findAttr(d, 0, ext.IFLA_VXLAN.GROUP6)).?.len);
    try testing.expectEqual(@as(usize, 16), (try findAttr(d, 0, ext.IFLA_VXLAN.LOCAL6)).?.len);
    try testing.expect((try findAttr(d, 0, ext.IFLA_VXLAN.GROUP)) == null);
    try testing.expectEqualSlices(u8, &.{0}, (try findAttr(d, 0, ext.IFLA_VXLAN.LEARNING)).?);
    l.clearRetainingCapacity();
    try ext.encodeVxlan(gpa, &l, .{ .vni = 1, .group = &.{ 239, 1, 1, 1 }, .local = &.{ 10, 0, 0, 1 } }, null);
    d = try dataOf(l.items);
    try testing.expectEqualSlices(u8, &.{ 239, 1, 1, 1 }, (try findAttr(d, 0, ext.IFLA_VXLAN.GROUP)).?);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, (try findAttr(d, 0, ext.IFLA_VXLAN.LOCAL)).?);
    l.clearRetainingCapacity();
    try testing.expectError(error.InvalidKindData, ext.encodeVxlan(gpa, &l, .{ .vni = 0x1000000 }, null));
    // geneve
    l.clearRetainingCapacity();
    try ext.encodeGeneve(gpa, &l, .{ .vni = 0xffffff, .remote = &v6a, .ttl = 5, .tos = 6 });
    d = try dataOf(l.items);
    try testing.expectEqual(@as(usize, 16), (try findAttr(d, 0, ext.IFLA_GENEVE.REMOTE6)).?.len);
    try testing.expectEqualSlices(u8, &.{5}, (try findAttr(d, 0, ext.IFLA_GENEVE.TTL)).?);
    try testing.expectEqualSlices(u8, &.{6}, (try findAttr(d, 0, ext.IFLA_GENEVE.TOS)).?);
    l.clearRetainingCapacity();
    try ext.encodeGeneve(gpa, &l, .{ .vni = 1, .remote = &.{ 10, 0, 0, 9 } });
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 9 }, (try findAttr(try dataOf(l.items), 0, ext.IFLA_GENEVE.REMOTE)).?);
    l.clearRetainingCapacity();
    try testing.expectError(error.InvalidKindData, ext.encodeGeneve(gpa, &l, .{ .vni = 0x1000000 }));
    try testing.expectError(error.InvalidAddressLength, ext.encodeGeneve(gpa, &l, .{ .vni = 1, .remote = &.{ 1, 2, 3 } }));
}

test "mutation 2026-11-27: ipvlan and bond encoders: any single option opens the data nest" {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try ext.encodeIpvlan(gpa, &l, .{});
    try testing.expectEqual(@as(usize, 0), l.items.len);
    try ext.encodeIpvlan(gpa, &l, .{ .mode = .l3 });
    try testing.expect(l.items.len > 0);
    l.clearRetainingCapacity();
    try ext.encodeIpvlan(gpa, &l, .{ .flags = 2 });
    try testing.expectEqualSlices(u8, &le16(2), (try findAttr(try dataOf(l.items), 0, ext.IFLA_IPVLAN.FLAGS)).?);
    const bonds = [_]ext.Bond{
        .{ .mode = .lacp },  .{ .miimon = 100 },         .{ .updelay = 200 }, .{ .downdelay = 300 },
        .{ .min_links = 2 }, .{ .xmit_hash_policy = 1 }, .{ .lacp_rate = 1 },
    };
    const btypes = [_]u16{
        ext.IFLA_BOND.MODE,      ext.IFLA_BOND.MIIMON,           ext.IFLA_BOND.UPDELAY,      ext.IFLA_BOND.DOWNDELAY,
        ext.IFLA_BOND.MIN_LINKS, ext.IFLA_BOND.XMIT_HASH_POLICY, ext.IFLA_BOND.AD_LACP_RATE,
    };
    for (bonds, btypes) |b, t| {
        l.clearRetainingCapacity();
        try ext.encodeBond(gpa, &l, b);
        try testing.expect((try findAttr(try dataOf(l.items), 0, t)) != null);
    }
    l.clearRetainingCapacity();
    try ext.encodeBond(gpa, &l, .{});
    try testing.expectEqual(@as(usize, 0), l.items.len);
}

test "mutation 2026-11-27: gre and ip-tunnel encoders: address checks, every attribute written" {
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    const v6: [16]u8 = @splat(1);
    try testing.expectError(error.InvalidAddressLength, ext.encodeGre(gpa, &l, .{ .remote = &v6 }, null));
    try testing.expectError(error.InvalidAddressLength, ext.encodeGre(gpa, &l, .{ .local = &v6 }, null));
    try testing.expectError(error.InvalidAddressLength, ext.encodeIptun(gpa, &l, .{ .local = &v6 }, null));
    try testing.expectError(error.InvalidAddressLength, ext.encodeIptun(gpa, &l, .{ .remote = &v6 }, null));
    try ext.encodeGre(gpa, &l, .{ .local = &.{ 10, 0, 0, 1 }, .remote = &.{ 10, 0, 0, 2 }, .tos = 4, .ttl = 5, .pmtudisc = true }, 7);
    var d = try dataOf(l.items);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, (try findAttr(d, 0, ext.IFLA_GRE.LOCAL)).?);
    try testing.expectEqualSlices(u8, &.{4}, (try findAttr(d, 0, ext.IFLA_GRE.TOS)).?);
    try testing.expectEqualSlices(u8, &le32(7), (try findAttr(d, 0, ext.IFLA_GRE.LINK)).?);
    l.clearRetainingCapacity();
    try ext.encodeIptun(gpa, &l, .{ .local = &.{ 10, 0, 0, 1 }, .remote = &.{ 10, 0, 0, 2 }, .ttl = 5, .tos = 6, .pmtudisc = false }, 8);
    d = try dataOf(l.items);
    try testing.expectEqualSlices(u8, &le32(8), (try findAttr(d, 0, ext.IFLA_IPTUN.LINK)).?);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, (try findAttr(d, 0, ext.IFLA_IPTUN.REMOTE)).?);
    try testing.expectEqualSlices(u8, &.{0}, (try findAttr(d, 0, ext.IFLA_IPTUN.PMTUDISC)).?);
}

test "mutation 2026-11-27: parseKindInfo reads every member of every kind" {
    const v6: [16]u8 = @splat(0x33);
    const vx = try mk(&.{}, &.{
        .{ .t = ext.IFLA_VXLAN.ID, .d = &le32(0x112233) },
        .{ .t = ext.IFLA_VXLAN.GROUP6, .d = &v6 },
        .{ .t = ext.IFLA_VXLAN.LOCAL, .d = &.{ 10, 0, 0, 1 } },
        .{ .t = ext.IFLA_VXLAN.LINK, .d = &le32(9) },
        .{ .t = ext.IFLA_VXLAN.TTL, .d = &.{7} },
        .{ .t = ext.IFLA_VXLAN.TOS, .d = &.{8} },
        .{ .t = ext.IFLA_VXLAN.LEARNING, .d = &.{1} },
        .{ .t = ext.IFLA_VXLAN.AGEING, .d = &le32(300) },
        .{ .t = ext.IFLA_VXLAN.PORT, .d = &be16(4789) },
        .{ .t = ext.IFLA_VXLAN.UDP_CSUM, .d = &.{1} },
    });
    defer gpa.free(vx);
    const v = (try ext.parseKindInfo("vxlan", vx)).vxlan;
    try testing.expectEqual(@as(u32, 0x112233), v.vni);
    try testing.expectEqual(@as(usize, 16), v.group.bytes().len);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, v.local.bytes());
    try testing.expectEqual(@as(u32, 9), v.link);
    try testing.expectEqual(@as(u8, 7), v.ttl);
    try testing.expectEqual(@as(u8, 8), v.tos);
    try testing.expect(v.learning);
    try testing.expectEqual(@as(u32, 300), v.ageing);
    try testing.expectEqual(@as(u16, 4789), v.port);
    try testing.expect(v.udp_csum);

    const mv = try mk(&.{}, &.{.{ .t = ext.IFLA_MACVLAN.MODE, .d = &le32(4) }});
    defer gpa.free(mv);
    try testing.expectEqual(@as(u32, 4), (try ext.parseKindInfo("macvtap", mv)).macvlan.mode);
    const ip = try mk(&.{}, &.{ .{ .t = ext.IFLA_IPVLAN.MODE, .d = &le16(2) }, .{ .t = ext.IFLA_IPVLAN.FLAGS, .d = &le16(1) } });
    defer gpa.free(ip);
    const ipi = (try ext.parseKindInfo("ipvtap", ip)).ipvlan;
    try testing.expectEqual(@as(u16, 2), ipi.mode);
    try testing.expectEqual(@as(u16, 1), ipi.flags);
    const vr = try mk(&.{}, &.{.{ .t = ext.IFLA_VRF.TABLE, .d = &le32(100) }});
    defer gpa.free(vr);
    try testing.expectEqual(@as(u32, 100), (try ext.parseKindInfo("vrf", vr)).vrf.table);
    const bd = try mk(&.{}, &.{
        .{ .t = ext.IFLA_BOND.MODE, .d = &.{4} },
        .{ .t = ext.IFLA_BOND.MIIMON, .d = &le32(100) },
        .{ .t = ext.IFLA_BOND.UPDELAY, .d = &le32(200) },
        .{ .t = ext.IFLA_BOND.DOWNDELAY, .d = &le32(300) },
        .{ .t = ext.IFLA_BOND.MIN_LINKS, .d = &le32(2) },
        .{ .t = ext.IFLA_BOND.XMIT_HASH_POLICY, .d = &.{1} },
        .{ .t = ext.IFLA_BOND.AD_LACP_RATE, .d = &.{1} },
    });
    defer gpa.free(bd);
    const b = (try ext.parseKindInfo("bond", bd)).bond;
    try testing.expectEqual(@as(u8, 4), b.mode);
    try testing.expectEqual(@as(u32, 100), b.miimon);
    try testing.expectEqual(@as(u32, 200), b.updelay);
    try testing.expectEqual(@as(u32, 300), b.downdelay);
    try testing.expectEqual(@as(u32, 2), b.min_links);
    try testing.expectEqual(@as(u8, 1), b.xmit_hash_policy);
    try testing.expectEqual(@as(u8, 1), b.lacp_rate);
    const br = try mk(&.{}, &.{
        .{ .t = ext.IFLA_BR.HELLO_TIME, .d = &le32(200) },
        .{ .t = ext.IFLA_BR.MAX_AGE, .d = &le32(2000) },
        .{ .t = root.IFLA_BR.FORWARD_DELAY, .d = &le32(1500) },
        .{ .t = root.IFLA_BR.AGEING_TIME, .d = &le32(30000) },
        .{ .t = root.IFLA_BR.STP_STATE, .d = &le32(1) },
        .{ .t = root.IFLA_BR.PRIORITY, .d = &le16(4096) },
        .{ .t = root.IFLA_BR.VLAN_FILTERING, .d = &.{1} },
        .{ .t = root.IFLA_BR.VLAN_PROTOCOL, .d = &be16(0x88a8) },
        .{ .t = ext.IFLA_BR.GROUP_FWD_MASK, .d = &le16(8) },
        .{ .t = ext.IFLA_BR.VLAN_DEFAULT_PVID, .d = &le16(5) },
        .{ .t = ext.IFLA_BR.MCAST_SNOOPING, .d = &.{1} },
        .{ .t = ext.IFLA_BR.MCAST_QUERIER, .d = &.{1} },
    });
    defer gpa.free(br);
    const bi = (try ext.parseKindInfo("bridge", br)).bridge;
    try testing.expectEqual(@as(u32, 200), bi.hello_time);
    try testing.expectEqual(@as(u32, 2000), bi.max_age);
    try testing.expectEqual(@as(u32, 1500), bi.forward_delay);
    try testing.expectEqual(@as(u32, 30000), bi.ageing_time);
    try testing.expectEqual(@as(u32, 1), bi.stp_state);
    try testing.expectEqual(@as(u16, 4096), bi.priority);
    try testing.expect(bi.vlan_filtering);
    try testing.expectEqual(@as(u16, 0x88a8), bi.vlan_protocol);
    try testing.expectEqual(@as(u16, 8), bi.group_fwd_mask);
    try testing.expectEqual(@as(u16, 5), bi.vlan_default_pvid);
    try testing.expect(bi.mcast_snooping);
    try testing.expect(bi.mcast_querier);
    const gr = try mk(&.{}, &.{
        .{ .t = ext.IFLA_GRE.LINK, .d = &le32(4) },
        .{ .t = ext.IFLA_GRE.IFLAGS, .d = &be16(0x2000) },
        .{ .t = ext.IFLA_GRE.OFLAGS, .d = &be16(0x2000) },
        .{ .t = ext.IFLA_GRE.IKEY, .d = &be32(11) },
        .{ .t = ext.IFLA_GRE.OKEY, .d = &be32(12) },
        .{ .t = ext.IFLA_GRE.LOCAL, .d = &.{ 10, 0, 0, 1 } },
        .{ .t = ext.IFLA_GRE.REMOTE, .d = &.{ 10, 0, 0, 2 } },
        .{ .t = ext.IFLA_GRE.TTL, .d = &.{5} },
        .{ .t = ext.IFLA_GRE.TOS, .d = &.{6} },
        .{ .t = ext.IFLA_GRE.PMTUDISC, .d = &.{1} },
    });
    defer gpa.free(gr);
    const g = (try ext.parseKindInfo("gretap", gr)).gre;
    try testing.expectEqual(@as(u32, 4), g.link);
    try testing.expectEqual(@as(u16, 0x2000), g.iflags);
    try testing.expectEqual(@as(u16, 0x2000), g.oflags);
    try testing.expectEqual(@as(u32, 11), g.ikey);
    try testing.expectEqual(@as(u32, 12), g.okey);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, g.local.bytes());
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, g.remote.bytes());
    try testing.expectEqual(@as(u8, 5), g.ttl);
    try testing.expectEqual(@as(u8, 6), g.tos);
    try testing.expect(g.pmtudisc);
    const it = try mk(&.{}, &.{
        .{ .t = ext.IFLA_IPTUN.LINK, .d = &le32(4) },
        .{ .t = ext.IFLA_IPTUN.LOCAL, .d = &.{ 10, 0, 0, 1 } },
        .{ .t = ext.IFLA_IPTUN.REMOTE, .d = &.{ 10, 0, 0, 2 } },
        .{ .t = ext.IFLA_IPTUN.TTL, .d = &.{5} },
        .{ .t = ext.IFLA_IPTUN.TOS, .d = &.{6} },
        .{ .t = ext.IFLA_IPTUN.PMTUDISC, .d = &.{1} },
    });
    defer gpa.free(it);
    const t = (try ext.parseKindInfo("sit", it)).iptun;
    try testing.expectEqual(@as(u32, 4), t.link);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, t.local.bytes());
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, t.remote.bytes());
    try testing.expectEqual(@as(u8, 5), t.ttl);
    try testing.expectEqual(@as(u8, 6), t.tos);
    try testing.expect(t.pmtudisc);
    const ge = try mk(&.{}, &.{
        .{ .t = ext.IFLA_GENEVE.ID, .d = &le32(77) },
        .{ .t = ext.IFLA_GENEVE.REMOTE6, .d = &v6 },
        .{ .t = ext.IFLA_GENEVE.TTL, .d = &.{5} },
        .{ .t = ext.IFLA_GENEVE.TOS, .d = &.{6} },
        .{ .t = ext.IFLA_GENEVE.PORT, .d = &be16(6081) },
        .{ .t = ext.IFLA_GENEVE.UDP_CSUM, .d = &.{1} },
    });
    defer gpa.free(ge);
    const gv = (try ext.parseKindInfo("geneve", ge)).geneve;
    try testing.expectEqual(@as(u32, 77), gv.vni);
    try testing.expectEqual(@as(usize, 16), gv.remote.bytes().len);
    try testing.expectEqual(@as(u8, 5), gv.ttl);
    try testing.expectEqual(@as(u8, 6), gv.tos);
    try testing.expectEqual(@as(u16, 6081), gv.port);
    try testing.expect(gv.udp_csum);
}

test "mutation 2026-11-27: parseKindInfo refuses a wrong width on every strict member" {
    const V = ext.IFLA_VXLAN;
    const B = ext.IFLA_BOND;
    const R = ext.IFLA_BR;
    const G = ext.IFLA_GRE;
    const T = ext.IFLA_IPTUN;
    const N = ext.IFLA_GENEVE;
    const table = [_]struct { kind: []const u8, types: []const u16 }{
        .{ .kind = "vxlan", .types = &.{ V.ID, V.LINK, V.TTL, V.TOS, V.LEARNING, V.AGEING, V.PORT, V.UDP_CSUM } },
        .{ .kind = "macvlan", .types = &.{ext.IFLA_MACVLAN.MODE} },
        .{ .kind = "ipvlan", .types = &.{ ext.IFLA_IPVLAN.MODE, ext.IFLA_IPVLAN.FLAGS } },
        .{ .kind = "vrf", .types = &.{ext.IFLA_VRF.TABLE} },
        .{ .kind = "bond", .types = &.{ B.MODE, B.MIIMON, B.UPDELAY, B.DOWNDELAY, B.MIN_LINKS, B.XMIT_HASH_POLICY, B.AD_LACP_RATE } },
        .{ .kind = "bridge", .types = &.{
            R.HELLO_TIME,           R.MAX_AGE,             root.IFLA_BR.FORWARD_DELAY,  root.IFLA_BR.AGEING_TIME,
            root.IFLA_BR.STP_STATE, root.IFLA_BR.PRIORITY, root.IFLA_BR.VLAN_FILTERING, root.IFLA_BR.VLAN_PROTOCOL,
            R.GROUP_FWD_MASK,       R.VLAN_DEFAULT_PVID,   R.MCAST_SNOOPING,            R.MCAST_QUERIER,
        } },
        .{ .kind = "gre", .types = &.{ G.LINK, G.IFLAGS, G.OFLAGS, G.IKEY, G.OKEY, G.TTL, G.TOS, G.PMTUDISC } },
        .{ .kind = "ipip", .types = &.{ T.LINK, T.TTL, T.TOS, T.PMTUDISC } },
        .{ .kind = "geneve", .types = &.{ N.ID, N.TTL, N.TOS, N.PORT, N.UDP_CSUM } },
    };
    for (table) |row| {
        for (row.types) |t| {
            const bad = try mk(&.{}, &.{.{ .t = t, .d = &.{ 1, 2, 3 } }});
            defer gpa.free(bad);
            try testing.expectError(error.BadLength, ext.parseKindInfo(row.kind, bad));
        }
    }
}
