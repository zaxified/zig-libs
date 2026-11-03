// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GX, gx1-a) for conntrack's public decoders.
//! The findings that needed code changes (CT-1, CT-2) live next to the private
//! dump engines in root.zig; these pin the entry points the sweep found CLEAN,
//! so a later change cannot silently open them.
//! See ~/CML/20261029-panic-sweep/conntrack-sweep.report.md.
const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const netlink = @import("netlink");
const codec = netlink.codec;
const wire = @import("wire.zig");
const goldens = @import("goldens.zig");

test "decodeFlow: every truncation of a real reply is an error or a flow, never a panic" {
    if (builtin.cpu.arch.endian() != .little) return error.SkipZigTest;
    var it: codec.MessageIterator = .{ .buf = &goldens.dump_reply_three_flows };
    const m = (try it.next()).?;
    var n_err: usize = 0;
    var n_ok: usize = 0;
    var cut: usize = 0;
    while (cut <= m.payload.len) : (cut += 1) {
        if (wire.decodeFlow(m.payload[0..cut])) |_| n_ok += 1 else |_| n_err += 1;
    }
    try testing.expect(n_err > 0);
    try testing.expect(n_ok > 0);
}

test "decodeFlow: unknown family byte and unknown TCP state are carried through, not trapped" {
    const gpa = testing.allocator;
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    const pi = try codec.nestBegin(gpa, &a, codec.NLA_F_NESTED | wire.CTA.PROTOINFO);
    const tcp = try codec.nestBegin(gpa, &a, codec.NLA_F_NESTED | wire.CTA_PROTOINFO.TCP);
    try codec.appendAttrU8(gpa, &a, wire.CTA_PROTOINFO_TCP.STATE, 255);
    try codec.nestEnd(&a, tcp);
    try codec.nestEnd(&a, pi);
    var p: std.ArrayList(u8) = .empty;
    defer p.deinit(gpa);
    try p.appendSlice(gpa, &.{ 0xee, 0, 0, 0 }); // nfgen_family 0xee
    try p.appendSlice(gpa, a.items);
    const f = try wire.decodeFlow(p.items);
    try testing.expectEqual(@as(u8, 255), @backingInt(f.tcp_state.?));
    try testing.expectEqual(@as(u8, 0xee), @backingInt(f.family));
}

test "decodeFlow: attributes nested 1000 deep cost one pass, no recursion" {
    // The decoder descends a fixed three levels (tuple -> ip/proto); a deeper
    // nest is skipped as an unknown attribute, so depth cannot drive the stack.
    const gpa = testing.allocator;
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(gpa);
    try codec.appendAttrU8(gpa, &inner, 1, 1);
    var depth: usize = 0;
    while (depth < 1000) : (depth += 1) {
        var outer: std.ArrayList(u8) = .empty;
        errdefer outer.deinit(gpa);
        const off = try codec.nestBegin(gpa, &outer, codec.NLA_F_NESTED | 99);
        try outer.appendSlice(gpa, inner.items);
        try codec.nestEnd(&outer, off);
        inner.deinit(gpa);
        inner = outer;
    }
    var p: std.ArrayList(u8) = .empty;
    defer p.deinit(gpa);
    try p.appendSlice(gpa, &.{ 2, 0, 0, 0 });
    try p.appendSlice(gpa, inner.items);
    _ = try wire.decodeFlow(p.items);
}

// ── 2026-11-03: the decoders and builders added with the grade-2 survey ────

const ext = @import("ext.zig");

/// A payload (`nfgenmsg` + attributes) made of `attrs`, each `{type, payload}`.
fn payloadOf(gpa: std.mem.Allocator, list: *std.ArrayList(u8), attrs: []const struct { u16, []const u8 }) !void {
    try wire.appendNfgenmsg(gpa, list, .ipv4, 0);
    for (attrs) |a| try codec.appendAttr(gpa, list, a[0], a[1]);
}

test "ext decoders: every prefix and every one-byte corruption is an error or a value" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try payloadOf(gpa, &list, &.{
        .{ 4, &.{ 0, 0, 0, 9 } },
        .{ 5, "ftp\x00" },
        .{ 3, &.{ 0, 0 } },
        .{ 2, "sip\x00" },
        .{ 12, &.{ 1, 2, 3, 4 } },
    });
    var cut: usize = 0;
    while (cut <= list.items.len) : (cut += 1) {
        _ = ext.decodeExpect(list.items[0..cut]) catch {};
        _ = ext.decodeCpuStats(list.items[0..cut]) catch {};
        _ = ext.decodeGlobalStats(list.items[0..cut]) catch {};
        _ = ext.decodeExpectStats(list.items[0..cut]) catch {};
    }
    var i: usize = 0;
    while (i < list.items.len) : (i += 1) {
        const keep = list.items[i];
        for ([_]u8{ 0, 1, 0x7f, 0x80, 0xff }) |v| {
            list.items[i] = v;
            _ = ext.decodeExpect(list.items) catch {};
            _ = ext.decodeCpuStats(list.items) catch {};
            _ = ext.decodeGlobalStats(list.items) catch {};
            _ = ext.decodeExpectStats(list.items) catch {};
            _ = wire.decodeFlow(list.items) catch {};
        }
        list.items[i] = keep;
    }
}

test "Name.fromAttr: every length 0..40, with and without a NUL, never overruns the buffer" {
    var raw: [40]u8 = @splat('x');
    var n: usize = 0;
    while (n <= raw.len) : (n += 1) {
        if (wire.Name.fromAttr(raw[0..n])) |name| {
            try testing.expect(n <= 15);
            try testing.expectEqual(n, name.slice().len);
        } else |e| {
            try testing.expectEqual(error.BadLength, e);
            try testing.expect(n > 15);
        }
    }
}

test "buildFlowDump: every filter combination fits the buffer and frames as one valid message" {
    const marks = [_]?ext.MarkFilter{ null, .{ .value = 1 }, .{ .value = 0xffff_ffff, .mask = 0 } };
    const stats = [_]?ext.StatusFilter{ null, .{ .value = 4 }, .{ .value = 0, .mask = 0xffff_ffff } };
    const zones = [_]?u16{ null, 0, 0xffff };
    for (std.enums.values(ext.DumpKind)) |k| for (marks) |m| for (stats) |s| for (zones) |z| {
        const r = ext.buildFlowDump(7, .{ .kind = k, .filter = .{ .mark = m, .status = s, .zone = z } });
        var it: codec.MessageIterator = .{ .buf = r.bytes() };
        const msg = (try it.next()).?;
        try testing.expect((try it.next()) == null);
        try testing.expectEqual(@as(u32, 7), msg.seq);
        const hdr = try wire.parseNfgenmsg(msg.payload);
        var ai = hdr.attrIterator();
        var n: usize = 0;
        while (try ai.next()) |_| n += 1;
        const want: usize = (if (m != null) @as(usize, 2) else 0) + (if (s) |x| @as(usize, if (x.mask != null) 2 else 1) else 0) + @intFromBool(z != null);
        try testing.expectEqual(want, n);
    };
}
