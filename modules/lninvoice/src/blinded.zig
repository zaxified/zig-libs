// SPDX-License-Identifier: MIT
//! BOLT#12's blinded paths and payment info, typed: `blinded_path` (BOLT#4
//! "Route Blinding"), `sciddir_or_pubkey` (BOLT#1) and `blinded_payinfo`
//! (BOLT#12 "TLV Fields for `invoice`"). The TLV values `offer_paths` (16),
//! `invreq_paths` (90) and `invoice_paths` (160) are arrays of `blinded_path`;
//! `invoice_blindedpay` (162) is an array of `blinded_payinfo`, one per path.
//!
//! The iterators validate as they walk and borrow from the value they are
//! given (nothing is allocated); a path is only returned when every byte of it
//! decoded: `first_node_id` of kind 0..3, every `point` a valid compressed
//! curve point (prefix 02/03 and an x that lifts), `num_hops` non-zero (BOLT#12:
//! "MUST reject ... if `num_hops` is 0 in any `blinded_path`"), every hop
//! complete. The encrypted data of a hop is opaque here (BOLT#4's
//! `encrypted_recipient_data`, decrypted by the hop's node, not by the reader of
//! an offer).

const std = @import("std");
const Allocator = std.mem.Allocator;
const bip340 = @import("bip340");

pub const PathError = error{
    /// The value ends inside a path, a hop or a payinfo.
    Truncated,
    /// `first_node_id` starts with a byte other than 0, 1, 2 or 3.
    BadFirstNode,
    /// A `point` that is not a valid compressed secp256k1 point.
    InvalidPoint,
    /// A path with `num_hops` 0.
    ZeroHops,
};

/// BOLT#1 `sciddir_or_pubkey`: a channel side (9 bytes) or a node id (33 bytes).
pub const FirstNode = union(enum) {
    /// `direction` 0 is `node_id_1` of the channel's `channel_announcement`, 1 is `node_id_2`.
    scid: struct { direction: u1, short_channel_id: u64 },
    node_id: [33]u8,
};

pub const Hop = struct {
    /// The hop's blinded node id.
    blinded_node_id: [33]u8,
    /// Opaque `encrypted_recipient_data`; borrowed from the decoded value.
    encrypted_recipient_data: []const u8,
};

pub const HopIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    /// The next hop; null after the last. The bytes were validated when the path was returned.
    pub fn next(self: *HopIterator) ?Hop {
        if (self.pos >= self.bytes.len) return null;
        const b = self.bytes[self.pos..];
        const enclen = std.mem.readInt(u16, b[33..35], .big);
        const hop: Hop = .{ .blinded_node_id = b[0..33].*, .encrypted_recipient_data = b[35..][0..enclen] };
        self.pos += 35 + enclen;
        return hop;
    }
};

pub const Path = struct {
    first_node: FirstNode,
    first_path_key: [33]u8,
    num_hops: u8,
    /// The `num_hops` hops, still encoded; read them with `hops()`.
    hops_raw: []const u8,

    pub fn hops(self: Path) HopIterator {
        return .{ .bytes = self.hops_raw };
    }
};

/// A valid compressed point: prefix 02/03 and an x-coordinate that is on the curve.
fn validPoint(p: *const [33]u8) bool {
    if (p[0] != 2 and p[0] != 3) return false;
    _ = bip340.XOnlyPublicKey.fromBytes(p[1..33].*) catch return false;
    return true;
}

/// Walks a value that is an array of `blinded_path` (`offer_paths`, `invreq_paths`, `invoice_paths`).
pub const PathIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    /// The next path, null at the end of the value, an error for a malformed one (after
    /// which the iterator must not be used: the rest of the value cannot be framed).
    pub fn next(self: *PathIterator) PathError!?Path {
        if (self.pos >= self.bytes.len) return null;
        var b = self.bytes[self.pos..];
        var used: usize = 0;
        if (b.len < 1) return error.Truncated;
        const first: FirstNode = switch (b[0]) {
            0, 1 => blk: {
                if (b.len < 9) return error.Truncated;
                used = 9;
                break :blk .{ .scid = .{ .direction = @intCast(b[0]), .short_channel_id = std.mem.readInt(u64, b[1..9], .big) } };
            },
            2, 3 => blk: {
                if (b.len < 33) return error.Truncated;
                if (!validPoint(b[0..33])) return error.InvalidPoint;
                used = 33;
                break :blk .{ .node_id = b[0..33].* };
            },
            else => return error.BadFirstNode,
        };
        b = b[used..];
        if (b.len < 34) return error.Truncated;
        if (!validPoint(b[0..33])) return error.InvalidPoint;
        const path_key = b[0..33].*;
        const num_hops = b[33];
        if (num_hops == 0) return error.ZeroHops;
        b = b[34..];
        used += 34;
        var hop_bytes: usize = 0;
        var h: usize = 0;
        while (h < num_hops) : (h += 1) {
            if (b.len - hop_bytes < 35) return error.Truncated;
            if (!validPoint(b[hop_bytes..][0..33])) return error.InvalidPoint;
            const enclen = std.mem.readInt(u16, b[hop_bytes + 33 ..][0..2], .big);
            if (b.len - hop_bytes - 35 < enclen) return error.Truncated;
            hop_bytes += 35 + enclen;
        }
        const path: Path = .{ .first_node = first, .first_path_key = path_key, .num_hops = num_hops, .hops_raw = b[0..hop_bytes] };
        self.pos += used + hop_bytes;
        return path;
    }

    /// Validates every path of the value; returns how many there are.
    pub fn count(self: PathIterator) PathError!usize {
        var it = self;
        var n: usize = 0;
        while (try it.next()) |_| n += 1;
        return n;
    }
};

/// Appends one `blinded_path` to `out`. Refuses what BOLT#12 refuses on reading: no hops, more than 255
/// hops, a hop's data over 65535 bytes, a point that is not a valid compressed point.
// secret-api-ok: first_path_key is the path's first PUBLIC blinding point (33-byte compressed, checked by validPoint), not a secret
pub fn appendPath(allocator: Allocator, out: *std.ArrayList(u8), first_node: FirstNode, first_path_key: [33]u8, hops: []const Hop) (Allocator.Error || PathError || error{FieldTooLong})!void {
    if (hops.len == 0) return error.ZeroHops;
    if (hops.len > 255) return error.FieldTooLong;
    if (!validPoint(&first_path_key)) return error.InvalidPoint;
    for (hops) |hop| {
        if (!validPoint(&hop.blinded_node_id)) return error.InvalidPoint;
        if (hop.encrypted_recipient_data.len > std.math.maxInt(u16)) return error.FieldTooLong;
    }
    switch (first_node) {
        .scid => |s| {
            try out.append(allocator, s.direction);
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, s.short_channel_id, .big);
            try out.appendSlice(allocator, &b);
        },
        .node_id => |n| {
            if (!validPoint(&n)) return error.InvalidPoint;
            try out.appendSlice(allocator, &n);
        },
    }
    try out.appendSlice(allocator, &first_path_key);
    try out.append(allocator, @intCast(hops.len));
    for (hops) |hop| {
        try out.appendSlice(allocator, &hop.blinded_node_id);
        var l: [2]u8 = undefined;
        std.mem.writeInt(u16, &l, @intCast(hop.encrypted_recipient_data.len), .big);
        try out.appendSlice(allocator, &l);
        try out.appendSlice(allocator, hop.encrypted_recipient_data);
    }
}

/// BOLT#12 `blinded_payinfo`: the fees, CLTV delta, HTLC bounds and features of one blinded path.
pub const PayInfo = struct {
    fee_base_msat: u32,
    fee_proportional_millionths: u32,
    cltv_expiry_delta: u16,
    htlc_minimum_msat: u64,
    htlc_maximum_msat: u64,
    /// BOLT#9 feature bytes; borrowed from the decoded value.
    features: []const u8,

    pub const fixed_len = 4 + 4 + 2 + 8 + 8 + 2;
};

/// Walks `invoice_blindedpay` (an array of `blinded_payinfo`).
pub const PayInfoIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *PayInfoIterator) PathError!?PayInfo {
        if (self.pos >= self.bytes.len) return null;
        const b = self.bytes[self.pos..];
        if (b.len < PayInfo.fixed_len) return error.Truncated;
        const flen = std.mem.readInt(u16, b[26..28], .big);
        if (b.len - PayInfo.fixed_len < flen) return error.Truncated;
        const info: PayInfo = .{
            .fee_base_msat = std.mem.readInt(u32, b[0..4], .big),
            .fee_proportional_millionths = std.mem.readInt(u32, b[4..8], .big),
            .cltv_expiry_delta = std.mem.readInt(u16, b[8..10], .big),
            .htlc_minimum_msat = std.mem.readInt(u64, b[10..18], .big),
            .htlc_maximum_msat = std.mem.readInt(u64, b[18..26], .big),
            .features = b[28..][0..flen],
        };
        self.pos += PayInfo.fixed_len + flen;
        return info;
    }

    pub fn count(self: PayInfoIterator) PathError!usize {
        var it = self;
        var n: usize = 0;
        while (try it.next()) |_| n += 1;
        return n;
    }
};

/// Appends one `blinded_payinfo` to `out`.
pub fn appendPayInfo(allocator: Allocator, out: *std.ArrayList(u8), info: PayInfo) (Allocator.Error || error{FieldTooLong})!void {
    if (info.features.len > std.math.maxInt(u16)) return error.FieldTooLong;
    var b: [PayInfo.fixed_len]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], info.fee_base_msat, .big);
    std.mem.writeInt(u32, b[4..8], info.fee_proportional_millionths, .big);
    std.mem.writeInt(u16, b[8..10], info.cltv_expiry_delta, .big);
    std.mem.writeInt(u64, b[10..18], info.htlc_minimum_msat, .big);
    std.mem.writeInt(u64, b[18..26], info.htlc_maximum_msat, .big);
    std.mem.writeInt(u16, b[26..28], @intCast(info.features.len), .big);
    try out.appendSlice(allocator, &b);
    try out.appendSlice(allocator, info.features);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// 02 02 .. 02 is on the curve; 03 03 .. 03 is not (the offers-test.json "bad ..." rows use it).
const bad33: [33]u8 = @splat(3);

fn rep(comptime b: u8, comptime n: usize) [n]u8 {
    return @splat(b);
}

test "paths: a node-id first hop, an scid first hop, two paths in one value" {
    const a = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    const k = rep(2, 33);
    const hops1 = [_]Hop{.{ .blinded_node_id = k, .encrypted_recipient_data = &.{ 1, 2, 3 } }};
    try appendPath(a, &out, .{ .node_id = k }, k, &hops1);
    const hops2 = [_]Hop{
        .{ .blinded_node_id = k, .encrypted_recipient_data = &.{} },
        .{ .blinded_node_id = k, .encrypted_recipient_data = &@as([300]u8, @splat(9)) },
    };
    try appendPath(a, &out, .{ .scid = .{ .direction = 1, .short_channel_id = 0x0102030405060708 } }, k, &hops2);

    var it: PathIterator = .{ .bytes = out.items };
    try testing.expectEqual(@as(usize, 2), try it.count());
    const p1 = (try it.next()).?;
    try testing.expectEqualSlices(u8, &k, &p1.first_node.node_id);
    try testing.expectEqual(@as(u8, 1), p1.num_hops);
    var h1 = p1.hops();
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, h1.next().?.encrypted_recipient_data);
    try testing.expect(h1.next() == null);
    const p2 = (try it.next()).?;
    try testing.expectEqual(@as(u1, 1), p2.first_node.scid.direction);
    try testing.expectEqual(@as(u64, 0x0102030405060708), p2.first_node.scid.short_channel_id);
    var h2 = p2.hops();
    try testing.expectEqual(@as(usize, 0), h2.next().?.encrypted_recipient_data.len);
    try testing.expectEqual(@as(usize, 300), h2.next().?.encrypted_recipient_data.len);
    try testing.expect(h2.next() == null);
    try testing.expect((try it.next()) == null);
}

test "paths: every malformation is a typed error, truncation at every cut included" {
    const a = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    const k = rep(2, 33);
    try appendPath(a, &out, .{ .node_id = k }, k, &.{.{ .blinded_node_id = k, .encrypted_recipient_data = &.{ 7, 7 } }});
    var cut: usize = 1;
    while (cut < out.items.len) : (cut += 1) {
        var it: PathIterator = .{ .bytes = out.items[0..cut] };
        try testing.expectError(error.Truncated, it.next());
    }
    // zero hops
    var zero: [33 + 33 + 1]u8 = undefined;
    @memcpy(zero[0..33], &k);
    @memcpy(zero[33..66], &k);
    zero[66] = 0;
    var it0: PathIterator = .{ .bytes = &zero };
    try testing.expectError(error.ZeroHops, it0.next());
    // bad first node byte, bad points (prefix 04, prefix 02 with an x off the curve)
    var bytes = try a.dupe(u8, out.items);
    defer a.free(bytes);
    bytes[0] = 4;
    var it1: PathIterator = .{ .bytes = bytes };
    try testing.expectError(error.BadFirstNode, it1.next());
    bytes[0] = 3;
    @memcpy(bytes[1..33], bad33[1..33]);
    var it2: PathIterator = .{ .bytes = bytes };
    try testing.expectError(error.InvalidPoint, it2.next());
    @memcpy(bytes[0..33], &k);
    bytes[33] = 5;
    var it3: PathIterator = .{ .bytes = bytes };
    try testing.expectError(error.InvalidPoint, it3.next());
    bytes[33] = 2;
    @memcpy(bytes[67..100], &bad33);
    var it4: PathIterator = .{ .bytes = bytes };
    try testing.expectError(error.InvalidPoint, it4.next());
    // builders refuse the same things
    try testing.expectError(error.ZeroHops, appendPath(a, &out, .{ .node_id = k }, k, &.{}));
    try testing.expectError(error.InvalidPoint, appendPath(a, &out, .{ .node_id = bad33 }, k, &.{.{ .blinded_node_id = k, .encrypted_recipient_data = &.{} }}));
    try testing.expectError(error.InvalidPoint, appendPath(a, &out, .{ .node_id = k }, bad33, &.{.{ .blinded_node_id = k, .encrypted_recipient_data = &.{} }}));
}

test "payinfo: round trip, features, truncation" {
    const a = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    try appendPayInfo(a, &out, .{ .fee_base_msat = 1, .fee_proportional_millionths = 2, .cltv_expiry_delta = 3, .htlc_minimum_msat = 4, .htlc_maximum_msat = 5, .features = &.{} });
    try appendPayInfo(a, &out, .{ .fee_base_msat = 0xffffffff, .fee_proportional_millionths = 0, .cltv_expiry_delta = 0xffff, .htlc_minimum_msat = 0, .htlc_maximum_msat = std.math.maxInt(u64), .features = &.{ 0x01, 0x02 } });
    var it: PayInfoIterator = .{ .bytes = out.items };
    try testing.expectEqual(@as(usize, 2), try it.count());
    const p = (try it.next()).?;
    try testing.expectEqual(@as(u32, 1), p.fee_base_msat);
    try testing.expectEqual(@as(u16, 3), p.cltv_expiry_delta);
    try testing.expectEqual(@as(u64, 5), p.htlc_maximum_msat);
    const q = (try it.next()).?;
    try testing.expectEqual(@as(u32, 0xffffffff), q.fee_base_msat);
    try testing.expectEqual(std.math.maxInt(u64), q.htlc_maximum_msat);
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, q.features);
    try testing.expect((try it.next()) == null);
    for (1..out.items.len) |cut| {
        var t: PayInfoIterator = .{ .bytes = out.items[0..cut] };
        // A cut is clean only at a payinfo boundary (28 bytes for the first, 28 + 30 for the second).
        const boundary = cut == 28 or cut == 28 + 30;
        var failed = false;
        while (t.next() catch blk: {
            failed = true;
            break :blk null;
        }) |_| {}
        try testing.expect(failed != boundary);
    }
}
