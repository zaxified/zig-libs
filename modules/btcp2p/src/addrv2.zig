// SPDX-License-Identifier: MIT
//! `addrv2` (BIP155): the variable-length peer-address list that replaced
//! `addr` for peers that sent `sendaddrv2` (see `relay.zig`). One entry is
//! `time(4, LE) || services(CompactSize) || network_id(1) || addr(var_bytes)
//! || port(2, BE)`; the message is a CompactSize count (at most 1000) of them.
//!
//! BIP155's network ids and their address lengths: 1 IPv4 (4), 2 IPv6 (16),
//! 3 TorV2 (10, deprecated), 4 TorV3 (32), 5 I2P (32), 6 CJDNS (16, first
//! octet 0xFC); no address is longer than 512 octets. Decoding follows Bitcoin
//! Core's deserializer: a known id with the wrong length, an address over 512
//! octets, or a count over 1000 is an error (the message is dropped); an
//! unknown id is kept verbatim (a future network); an address that is
//! structurally fine but unusable (TorV2, an IPv4-mapped / 6to4 / Teredo /
//! OnionCat IPv6, a CJDNS address without the 0xFC prefix, an unknown id) is
//! returned with `usable() == false` so the caller skips it instead of
//! rejecting the message, as Core does.
//!
//! The address bytes of a decoded entry borrow the caller's input (see
//! `message.zig`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const net_addr = @import("net_addr.zig");

/// Command name, as `envelope.encodeMessage` takes it.
pub const command = "addrv2";

/// BIP155: "no more than 1000 addresses" per message (as `addr`).
pub const MAX_ADDRV2_ENTRIES: u64 = 1000;
/// BIP155: an address is at most 512 octets.
pub const MAX_ADDRV2_ADDR_LEN: u64 = 512;

pub const NetworkId = enum(u8) {
    ipv4 = 1,
    ipv6 = 2,
    /// Deprecated (BIP155: never to be sent; Core ignores it).
    torv2 = 3,
    torv3 = 4,
    i2p = 5,
    cjdns = 6,
    _,

    /// The address length BIP155 fixes for this id, null for an unknown one.
    pub fn addrLen(id: NetworkId) ?usize {
        return switch (id) {
            .ipv4 => 4,
            .ipv6 => 16,
            .torv2 => 10,
            .torv3 => 32,
            .i2p => 32,
            .cjdns => 16,
            _ => null,
        };
    }
};

pub const DecodeError = message.ReadError || message.CompactSizeError || error{
    TooManyItems,
    /// A known network id whose address has the wrong length.
    BadAddrLength,
    /// An address longer than 512 octets.
    AddrTooLong,
};

pub const EncodeError = Allocator.Error || error{ TooManyItems, BadAddrLength, AddrTooLong };

pub const Entry = struct {
    /// Seconds since the epoch this address was last seen.
    time: u32,
    services: u64,
    network: NetworkId,
    addr: []const u8,
    /// Host-order port (big-endian on the wire).
    port: u16,

    pub fn decode(r: *Reader) DecodeError!Entry {
        const time = try r.u32le();
        const services = try r.compactSize();
        const network: NetworkId = @fromBackingInt(@intCast(try r.byte()));
        const len = try r.compactSize();
        if (len > MAX_ADDRV2_ADDR_LEN) return error.AddrTooLong;
        if (network.addrLen()) |want| if (len != want) return error.BadAddrLength;
        const addr = try r.takeBytes(len);
        const port = try r.u16be();
        return .{ .time = time, .services = services, .network = network, .addr = addr, .port = port };
    }

    pub fn encode(self: Entry, w: *Writer, allocator: Allocator) EncodeError!void {
        if (self.addr.len > MAX_ADDRV2_ADDR_LEN) return error.AddrTooLong;
        if (self.network.addrLen()) |want| if (self.addr.len != want) return error.BadAddrLength;
        try w.putU32le(allocator, self.time);
        try w.putCompactSize(allocator, self.services);
        try w.putU8(allocator, @backingInt(self.network));
        try w.putVarBytes(allocator, self.addr);
        try w.putU16be(allocator, self.port);
    }

    /// Whether the address is one a node may use (BIP155 and Core's
    /// `IsRoutable`-independent validity): false for TorV2, an unknown
    /// network, a CJDNS address without the 0xFC prefix, and an IPv6 address
    /// in the IPv4-mapped, 6to4, Teredo, OnionCat or Core-internal ranges
    /// (those must travel under their own network id, or not at all).
    pub fn usable(self: Entry) bool {
        return switch (self.network) {
            .ipv4, .torv3, .i2p => true,
            .cjdns => self.addr[0] == 0xFC,
            .ipv6 => blk: {
                const a = self.addr;
                const mapped = std.mem.eql(u8, a[0..12], &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff });
                const sixtofour = a[0] == 0x20 and a[1] == 0x02;
                const teredo = a[0] == 0x20 and a[1] == 0x01 and a[2] == 0 and a[3] == 0;
                const onioncat = std.mem.eql(u8, a[0..6], &.{ 0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43 });
                const internal = std.mem.eql(u8, a[0..6], &.{ 0xfd, 0x6b, 0x88, 0xc0, 0x87, 0x24 });
                break :blk !(mapped or sixtofour or teredo or onioncat or internal);
            },
            .torv2 => false,
            _ => false,
        };
    }

    /// The legacy `addr` form of an IPv4 or IPv6 entry (an IPv4 one is
    /// mapped into the 16-byte slot); null for the other networks, which the
    /// old format cannot carry.
    pub fn toTimedNetAddr(self: Entry) ?net_addr.TimedNetAddr {
        const ip: [16]u8 = switch (self.network) {
            .ipv4 => net_addr.NetAddr.fromIpv4(self.addr[0..4].*),
            .ipv6 => self.addr[0..16].*,
            else => return null,
        };
        return .{ .time = self.time, .addr = .{ .services = self.services, .ip = ip, .port = self.port } };
    }

    /// The `addrv2` form of a legacy entry: an IPv4-mapped address becomes
    /// network 1, anything else network 2. `storage` holds the address bytes
    /// and must outlive the returned entry.
    pub fn fromTimedNetAddr(t: net_addr.TimedNetAddr, storage: *[16]u8) Entry {
        if (t.addr.ipv4()) |v4| {
            storage[0..4].* = v4;
            return .{ .time = t.time, .services = t.addr.services, .network = .ipv4, .addr = storage[0..4], .port = t.addr.port };
        }
        storage.* = t.addr.ip;
        return .{ .time = t.time, .services = t.addr.services, .network = .ipv6, .addr = storage[0..16], .port = t.addr.port };
    }
};

pub const AddrV2 = struct {
    entries: []Entry,

    pub fn deinit(self: *AddrV2, allocator: Allocator) void {
        allocator.free(self.entries);
        self.* = .{ .entries = &.{} };
    }
};

/// The smallest entry: time 4 + services 1 + id 1 + length 1 + port 2.
const min_entry_len = 9;

pub fn decodeAddrV2(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!AddrV2 {
    var r: Reader = .{ .bytes = bytes };
    const count = try r.compactSize();
    if (count > MAX_ADDRV2_ENTRIES) return error.TooManyItems;
    if (count > r.remaining() / min_entry_len) return error.TooManyItems;

    var entries: std.ArrayList(Entry) = .empty;
    errdefer entries.deinit(allocator);
    var i: u64 = 0;
    while (i < count) : (i += 1) try entries.append(allocator, try Entry.decode(&r));
    return .{ .entries = try entries.toOwnedSlice(allocator) };
}

pub fn serializeAddrV2(allocator: Allocator, a: AddrV2) EncodeError![]u8 {
    if (a.entries.len > MAX_ADDRV2_ENTRIES) return error.TooManyItems;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putCompactSize(allocator, a.entries.len);
    for (a.entries) |e| try e.encode(&w, allocator);
    return w.toOwned(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "addrv2: one entry per BIP155 network, byte layout and round trip" {
    const a = testing.allocator;
    const v4 = [_]u8{ 203, 0, 113, 7 };
    var v6: [16]u8 = @splat(0);
    v6[0] = 0x20;
    v6[1] = 0x01;
    v6[2] = 0x0d;
    v6[3] = 0xb8;
    v6[15] = 1;
    const tor3: [32]u8 = @splat(0x33);
    const i2p: [32]u8 = @splat(0x55);
    var cj: [16]u8 = @splat(0x11);
    cj[0] = 0xFC;
    var entries = [_]Entry{
        .{ .time = 0x01020304, .services = 1, .network = .ipv4, .addr = &v4, .port = 8333 },
        .{ .time = 5, .services = 0x409, .network = .ipv6, .addr = &v6, .port = 18333 },
        .{ .time = 6, .services = 0, .network = .torv3, .addr = &tor3, .port = 8333 },
        .{ .time = 7, .services = 1 << 40, .network = .i2p, .addr = &i2p, .port = 0 },
        .{ .time = 8, .services = 1, .network = .cjdns, .addr = &cj, .port = 8333 },
    };
    const bytes = try serializeAddrV2(a, .{ .entries = &entries });
    defer a.free(bytes);
    // count, then the first entry: time LE, services 1, id 1, length 4, address, port BE.
    try testing.expectEqualSlices(u8, &.{ 5, 0x04, 0x03, 0x02, 0x01, 0x01, 0x01, 0x04, 203, 0, 113, 7, 0x20, 0x8d }, bytes[0..14]);
    var d = try decodeAddrV2(a, bytes);
    defer d.deinit(a);
    try testing.expectEqual(@as(usize, 5), d.entries.len);
    for (entries, d.entries) |want, got| {
        try testing.expectEqual(want.time, got.time);
        try testing.expectEqual(want.services, got.services);
        try testing.expectEqual(want.network, got.network);
        try testing.expectEqualSlices(u8, want.addr, got.addr);
        try testing.expectEqual(want.port, got.port);
        try testing.expect(got.usable());
    }
}

test "addrv2: known ids with the wrong length, over-long addresses and big counts are errors" {
    const a = testing.allocator;
    // IPv4 with 5 octets.
    try testing.expectError(error.BadAddrLength, decodeAddrV2(a, &.{ 1, 0, 0, 0, 0, 1, 1, 5, 1, 2, 3, 4, 5, 0, 80 }));
    // TorV3 with 31 octets.
    var tor = [_]u8{ 1, 0, 0, 0, 0, 1, 4, 31 } ++ @as([31]u8, @splat(0)) ++ [_]u8{ 0, 80 };
    try testing.expectError(error.BadAddrLength, decodeAddrV2(a, &tor));
    // An unknown id with a 513-octet address: too long; with 512: kept.
    var big = [_]u8{ 1, 0, 0, 0, 0, 1, 9, 0xfd, 0x01, 0x02 } ++ @as([513]u8, @splat(7)) ++ [_]u8{ 0, 80 };
    try testing.expectError(error.AddrTooLong, decodeAddrV2(a, &big));
    var ok = [_]u8{ 1, 0, 0, 0, 0, 1, 9, 0xfd, 0x00, 0x02 } ++ @as([512]u8, @splat(7)) ++ [_]u8{ 0, 80 };
    var d = try decodeAddrV2(a, &ok);
    defer d.deinit(a);
    try testing.expectEqual(@as(usize, 512), d.entries[0].addr.len);
    try testing.expect(!d.entries[0].usable()); // unknown network: kept, not usable
    // 1001 entries (count only): over the cap before anything else is read.
    try testing.expectError(error.TooManyItems, decodeAddrV2(a, &.{ 0xfd, 0xe9, 0x03 }));
    // A count the bytes cannot hold.
    try testing.expectError(error.TooManyItems, decodeAddrV2(a, &.{ 3, 1, 2, 3 }));
    try testing.expectError(error.Truncated, decodeAddrV2(a, &.{ 1, 0, 0, 0, 0, 1, 1, 4, 1, 2, 3, 4, 0 }));
    // Encoding refuses what decoding refuses.
    var bad = [_]Entry{.{ .time = 0, .services = 0, .network = .ipv4, .addr = &.{ 1, 2, 3 }, .port = 1 }};
    try testing.expectError(error.BadAddrLength, serializeAddrV2(a, .{ .entries = &bad }));
}

test "addrv2: unusable addresses are kept and flagged, not message errors" {
    const a = testing.allocator;
    const mapped = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4 };
    const sixtofour = [_]u8{ 0x20, 0x02 } ++ @as([14]u8, @splat(0));
    const teredo = [_]u8{ 0x20, 0x01, 0, 0 } ++ @as([12]u8, @splat(0));
    const cj_bad: [16]u8 = @splat(0x11);
    const tor2: [10]u8 = @splat(0);
    const list = [_]Entry{
        .{ .time = 0, .services = 0, .network = .ipv6, .addr = &mapped, .port = 1 },
        .{ .time = 0, .services = 0, .network = .ipv6, .addr = &sixtofour, .port = 1 },
        .{ .time = 0, .services = 0, .network = .ipv6, .addr = &teredo, .port = 1 },
        .{ .time = 0, .services = 0, .network = .cjdns, .addr = &cj_bad, .port = 1 },
        .{ .time = 0, .services = 0, .network = .torv2, .addr = &tor2, .port = 1 },
    };
    const bytes = try serializeAddrV2(a, .{ .entries = @constCast(&list) });
    defer a.free(bytes);
    var d = try decodeAddrV2(a, bytes);
    defer d.deinit(a);
    for (d.entries) |e| try testing.expect(!e.usable());
}

test "addrv2: conversion to and from the legacy addr entry" {
    var st: [16]u8 = undefined;
    const t4: net_addr.TimedNetAddr = .{ .time = 9, .addr = .{ .services = 1, .ip = net_addr.NetAddr.fromIpv4(.{ 10, 0, 0, 1 }), .port = 8333 } };
    const e4 = Entry.fromTimedNetAddr(t4, &st);
    try testing.expectEqual(NetworkId.ipv4, e4.network);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, e4.addr);
    try testing.expectEqual(t4, e4.toTimedNetAddr().?);
    var ip6: [16]u8 = @splat(0);
    ip6[0] = 0x26;
    ip6[15] = 2;
    const t6: net_addr.TimedNetAddr = .{ .time = 9, .addr = .{ .services = 1, .ip = ip6, .port = 1 } };
    var st2: [16]u8 = undefined;
    const e6 = Entry.fromTimedNetAddr(t6, &st2);
    try testing.expectEqual(NetworkId.ipv6, e6.network);
    try testing.expectEqual(t6, e6.toTimedNetAddr().?);
    const tor: [32]u8 = @splat(1);
    try testing.expect((Entry{ .time = 0, .services = 0, .network = .torv3, .addr = &tor, .port = 0 }).toTimedNetAddr() == null);
}
