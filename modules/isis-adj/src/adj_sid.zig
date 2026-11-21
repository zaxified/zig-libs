// SPDX-License-Identifier: MIT

//! Adjacency Segment Identifier sub-TLVs (RFC 8667 section 2.2): the Adj-SID
//! (sub-TLV 31) of a point-to-point adjacency and the LAN Adj-SID (sub-TLV 32,
//! which names the neighbour), as carried inside an Extended IS Reachability
//! (#22) or MT IS Reachability (#222) entry. Only the value and the sub-TLV
//! framing are modelled; the caller puts the result into the entry's
//! sub-TLV area. `fsm.Adjacency.adjSid` says when an adjacency owns one.
//!
//! Flags (octet 0): F address family (0 IPv4, 1 IPv6), B backup, V value (a
//! label rather than an index), L local, S set of adjacencies, P persistent.
//! Weight (octet 1). The SID follows: 3 octets (a 20-bit label) when V and L
//! are both set, 4 octets (an index) when both are clear; any other
//! combination is invalid (RFC 8667 section 2.2.1).

const std = @import("std");

pub const sub_tlv_adj_sid: u8 = 31;
pub const sub_tlv_lan_adj_sid: u8 = 32;

pub const DecodeError = error{ BadLength, BadSidForm };

pub const Sid = union(enum) {
    /// A local label (20 bits), V = L = 1.
    label: u20,
    /// An index into the SRGB, V = L = 0.
    index: u32,
};

pub const AdjSid = struct {
    ipv6: bool = false,
    backup: bool = false,
    set: bool = false,
    persistent: bool = false,
    weight: u8 = 0,
    sid: Sid,
    /// Present for the LAN form (sub-TLV 32): the neighbour the SID is for.
    neighbor_id: ?[6]u8 = null,

    pub const max_len = 2 + 2 + 6 + 4;

    /// Encode the sub-TLV with its type and length octets.
    pub fn encode(self: AdjSid, buf: *[max_len]u8) []const u8 {
        buf[0] = if (self.neighbor_id != null) sub_tlv_lan_adj_sid else sub_tlv_adj_sid;
        var f: u8 = 0;
        if (self.ipv6) f |= 0x80;
        if (self.backup) f |= 0x40;
        if (self.sid == .label) f |= 0x30;
        if (self.set) f |= 0x08;
        if (self.persistent) f |= 0x04;
        buf[2] = f;
        buf[3] = self.weight;
        var n: usize = 4;
        if (self.neighbor_id) |id| {
            @memcpy(buf[n..][0..6], &id);
            n += 6;
        }
        switch (self.sid) {
            .label => |l| {
                buf[n] = @intCast(l >> 16);
                buf[n + 1] = @intCast((l >> 8) & 0xff);
                buf[n + 2] = @intCast(l & 0xff);
                n += 3;
            },
            .index => |i| {
                std.mem.writeInt(u32, buf[n..][0..4], i, .big);
                n += 4;
            },
        }
        buf[1] = @intCast(n - 2);
        return buf[0..n];
    }

    /// Decode a sub-TLV VALUE of type `kind` (31 or 32).
    pub fn decode(kind: u8, value: []const u8) DecodeError!AdjSid {
        const lan = kind == sub_tlv_lan_adj_sid;
        const head: usize = if (lan) 8 else 2;
        if (value.len < head) return error.BadLength;
        const f = value[0];
        const v = f & 0x20 != 0;
        const l = f & 0x10 != 0;
        if (v != l) return error.BadSidForm;
        const rest = value[head..];
        var a: AdjSid = .{
            .ipv6 = f & 0x80 != 0,
            .backup = f & 0x40 != 0,
            .set = f & 0x08 != 0,
            .persistent = f & 0x04 != 0,
            .weight = value[1],
            .sid = undefined,
            .neighbor_id = if (lan) value[2..8].* else null,
        };
        if (v) {
            if (rest.len != 3) return error.BadLength;
            // The label is the 20 rightmost bits; the 4 leftmost are ignored.
            const label = (@as(u32, rest[0] & 0x0f) << 16) | (@as(u32, rest[1]) << 8) | rest[2];
            a.sid = .{ .label = @intCast(label) };
        } else {
            if (rest.len != 4) return error.BadLength;
            a.sid = .{ .index = std.mem.readInt(u32, rest[0..4], .big) };
        }
        return a;
    }
};

const testing = std.testing;

test "Adj-SID sub-TLVs round-trip in the label and index forms, P2P and LAN" {
    var buf: [AdjSid.max_len]u8 = undefined;
    const cases = [_]AdjSid{
        .{ .sid = .{ .label = 0x12345 }, .persistent = true, .weight = 5 },
        .{ .sid = .{ .index = 0xdead_beef }, .backup = true, .set = true },
        .{ .sid = .{ .label = 16 }, .neighbor_id = .{ 0, 0, 0, 0, 0, 0xB }, .ipv6 = true },
        .{ .sid = .{ .index = 7 }, .neighbor_id = .{ 9, 8, 7, 6, 5, 4 } },
    };
    for (cases) |c| {
        const e = c.encode(&buf);
        try testing.expectEqual(@as(usize, e[1]) + 2, e.len);
        try testing.expectEqual(c, try AdjSid.decode(e[0], e[2..]));
    }
    // Label 0x12345 persistent P2P, exact bytes: type 31, len 5, flags V|L|P = 0x34.
    const e = cases[0].encode(&buf);
    try testing.expectEqualSlices(u8, &.{ 31, 5, 0x34, 5, 0x01, 0x23, 0x45 }, e);
}

test "Adj-SID decode refuses V without L, wrong SID width and short values" {
    try testing.expectError(error.BadSidForm, AdjSid.decode(31, &.{ 0x20, 0, 0, 0, 1 }));
    try testing.expectError(error.BadSidForm, AdjSid.decode(31, &.{ 0x10, 0, 0, 0, 1 }));
    try testing.expectError(error.BadLength, AdjSid.decode(31, &.{ 0x30, 0, 0, 1 }));
    try testing.expectError(error.BadLength, AdjSid.decode(31, &.{ 0x00, 0, 0, 0, 1 }));
    try testing.expectError(error.BadLength, AdjSid.decode(32, &.{ 0x30, 0, 1, 2, 3 }));
    try testing.expectError(error.BadLength, AdjSid.decode(31, &.{0x30}));
    // The 4 leftmost bits of the 3 octets are not part of the label.
    try testing.expectEqual(Sid{ .label = 0xfffff }, (try AdjSid.decode(31, &.{ 0x30, 0, 0xff, 0xff, 0xff })).sid);
}
