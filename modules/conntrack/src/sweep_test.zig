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
