// SPDX-License-Identifier: MIT

//! **Common Packet Format** (CIP Volume 2, chapter 2-6): the item list every
//! CIP message rides in.
//!
//! The structure is trivial — an item count, then `{type, length, data}` — and
//! the *rules over it* are where implementations go wrong:
//!
//! * `SendRRData` and `SendUnitData` carry a four-octet interface handle and a
//!   two-octet timeout **before** the item count. `ListIdentity` and friends do
//!   not. Mixing those up shifts every item by six octets.
//! * The first item is an **address** item and the second a **data** item.
//!   That ordering is not advisory: a target that sees a data item first has no
//!   idea which connection the message belongs to.
//! * Unconnected messaging uses the *Null Address* item (type 0, length 0) —
//!   an address item that carries no address. Connected messaging uses the
//!   Connected Address item (0x00A1, four octets of connection id), and the
//!   data item then begins with a **two-octet sequence count** that is part of
//!   the item, not of the CIP message.
//! * Optional items (the two Sockaddr Info items, used by `Forward_Open` to
//!   name the O→T and T→O UDP endpoints) follow the data item. A decoder that
//!   assumes exactly two items drops them.
//!
//! Every accessor bounds itself against the buffer it was given rather than
//! against the declared item count, so a peer that lies about the count cannot
//! steer a walk out of bounds.

const std = @import("std");
const encap = @import("encap.zig");

pub const SocketAddress = encap.SocketAddress;

/// CPF item type ids (CIP Vol 2 Table 2-6.1).
pub const ItemType = enum(u16) {
    /// Unconnected messages: an address item with no address.
    null_address = 0x0000,
    /// A `ListIdentity` reply item.
    list_identity_response = 0x000C,
    /// Connected messages: four octets of connection id.
    connected_address = 0x00A1,
    /// Connected (Class 3 / Class 1) data, prefixed by a sequence count.
    connected_data = 0x00B1,
    /// Unconnected (UCMM) data — a bare Message Router message.
    unconnected_data = 0x00B2,
    /// A `ListServices` reply item.
    list_services_response = 0x0100,
    /// `sockaddr_in` for the originator→target direction.
    sockaddr_info_o_to_t = 0x8000,
    /// `sockaddr_in` for the target→originator direction.
    sockaddr_info_t_to_o = 0x8001,
    /// Class 0/1 I/O over UDP: connection id + sequence number.
    sequenced_address = 0x8002,
    _,

    /// True for the item types that may appear **first** (the address slot).
    pub fn isAddress(t: ItemType) bool {
        return switch (t) {
            .null_address, .connected_address, .sequenced_address => true,
            else => false,
        };
    }

    /// True for the item types that may appear **second** (the data slot).
    pub fn isData(t: ItemType) bool {
        return switch (t) {
            .connected_data, .unconnected_data => true,
            else => false,
        };
    }
};

pub const DecodeError = error{
    /// Not enough octets for the item count or an item header.
    Truncated,
    /// An item length runs past the end of the buffer.
    ItemOverruns,
    /// Trailing octets after the last announced item.
    TrailingData,
    /// A fixed-shape item (connected address, sequenced address, sockaddr)
    /// carries the wrong number of octets.
    BadItemLength,
    /// Fewer than the two items a data-carrying CPF must have, or an item in
    /// the wrong slot.
    BadItemOrder,
    /// A connected data item shorter than its two-octet sequence count.
    MissingSequenceCount,
};

pub const EncodeError = error{
    BufferTooSmall,
    /// More than 65535 octets in one item, or more than 65535 items.
    TooLong,
};

/// One raw item: its type and a slice of the caller's buffer.
pub const Item = struct {
    type_id: ItemType,
    data: []const u8,
};

/// A decoded item list. `items` slices the caller's storage array.
pub const ItemList = struct {
    items: []const Item,
    /// Octets the list occupied, so a caller can tell where it ended.
    encoded_len: usize,

    /// The address item (always the first), or null for an empty list.
    pub fn addressItem(self: ItemList) ?Item {
        return if (self.items.len == 0) null else self.items[0];
    }

    /// The data item (always the second), or null when there is none.
    pub fn dataItem(self: ItemList) ?Item {
        return if (self.items.len < 2) null else self.items[1];
    }

    /// The first item of the given type anywhere in the list — which is how
    /// the optional Sockaddr Info items are found.
    pub fn find(self: ItemList, t: ItemType) ?Item {
        for (self.items) |it| if (it.type_id == t) return it;
        return null;
    }
};

/// Decodes an item list into `storage`, which bounds how many items are
/// accepted. A list with more items than `storage` holds is an error rather
/// than a silent truncation.
pub fn decode(bytes: []const u8, storage: []Item) DecodeError!ItemList {
    if (bytes.len < 2) return error.Truncated;
    const count: usize = std.mem.readInt(u16, bytes[0..2], .little);
    if (count > storage.len) return error.ItemOverruns;
    var off: usize = 2;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (off + 4 > bytes.len) return error.Truncated;
        const type_id: ItemType = @enumFromInt(std.mem.readInt(u16, bytes[off..][0..2], .little));
        const len: usize = std.mem.readInt(u16, bytes[off + 2 ..][0..2], .little);
        off += 4;
        if (off + len > bytes.len) return error.ItemOverruns;
        storage[i] = .{ .type_id = type_id, .data = bytes[off..][0..len] };
        off += len;
    }
    if (off != bytes.len) return error.TrailingData;
    return .{ .items = storage[0..count], .encoded_len = off };
}

/// Encodes an item list. The per-item length fields are derived from the
/// slices given and never from a caller-supplied number.
pub fn encode(items: []const Item, out: []u8) EncodeError![]u8 {
    if (items.len > 0xFFFF) return error.TooLong;
    var need: usize = 2;
    for (items) |it| {
        if (it.data.len > 0xFFFF) return error.TooLong;
        need += 4 + it.data.len;
    }
    if (out.len < need) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[0..2], @intCast(items.len), .little);
    var off: usize = 2;
    for (items) |it| {
        std.mem.writeInt(u16, out[off..][0..2], @intFromEnum(it.type_id), .little);
        std.mem.writeInt(u16, out[off + 2 ..][0..2], @intCast(it.data.len), .little);
        off += 4;
        @memcpy(out[off..][0..it.data.len], it.data);
        off += it.data.len;
    }
    return out[0..off];
}

/// Checks the ordering rules a *data-carrying* CPF (the payload of
/// `SendRRData` / `SendUnitData`) must obey: at least two items, an address
/// item first, a data item second. `ListIdentity` replies do **not** obey this
/// and must not be checked with it.
pub fn validateDataOrder(list: ItemList) DecodeError!void {
    if (list.items.len < 2) return error.BadItemOrder;
    if (!list.items[0].type_id.isAddress()) return error.BadItemOrder;
    if (!list.items[1].type_id.isData()) return error.BadItemOrder;
    // A connected address item pairs with connected data, and a null address
    // item with unconnected data. Crossing them is a protocol error that a
    // target cannot route.
    const addr = list.items[0].type_id;
    const data = list.items[1].type_id;
    if (addr == .connected_address and data != .connected_data) return error.BadItemOrder;
    if (addr == .null_address and data != .unconnected_data) return error.BadItemOrder;
    if (addr == .connected_address and list.items[0].data.len != 4) return error.BadItemLength;
    if (addr == .sequenced_address and list.items[0].data.len != 8) return error.BadItemLength;
    return;
}

// ── the SendRRData / SendUnitData envelope ─────────────────────────────────

/// `SendRRData` and `SendUnitData` prefix their item list with an interface
/// handle and a timeout. Both are two more chances to be off by six octets.
pub const Envelope = struct {
    /// 0 selects CIP. No other value has ever been assigned.
    interface_handle: u32 = 0,
    /// Seconds the target may take. Meaningless (and set to 0) on
    /// `SendUnitData`, where the connection's own timeout governs.
    timeout: u16 = 0,
    list: ItemList,

    pub const prefix_len: usize = 6;
};

/// The interface handle that selects CIP. Nothing else is defined.
pub const cip_interface_handle: u32 = 0;

pub fn decodeEnvelope(bytes: []const u8, storage: []Item) DecodeError!Envelope {
    if (bytes.len < Envelope.prefix_len) return error.Truncated;
    const list = try decode(bytes[Envelope.prefix_len..], storage);
    return .{
        .interface_handle = std.mem.readInt(u32, bytes[0..4], .little),
        .timeout = std.mem.readInt(u16, bytes[4..6], .little),
        .list = list,
    };
}

pub fn encodeEnvelope(
    interface_handle: u32,
    timeout: u16,
    items: []const Item,
    out: []u8,
) EncodeError![]u8 {
    if (out.len < Envelope.prefix_len) return error.BufferTooSmall;
    std.mem.writeInt(u32, out[0..4], interface_handle, .little);
    std.mem.writeInt(u16, out[4..6], timeout, .little);
    const body = try encode(items, out[Envelope.prefix_len..]);
    return out[0 .. Envelope.prefix_len + body.len];
}

// ── typed views over the fixed-shape items ─────────────────────────────────

/// The four octets of a Connected Address item.
pub fn connectionId(item: Item) DecodeError!u32 {
    if (item.type_id != .connected_address) return error.BadItemOrder;
    if (item.data.len != 4) return error.BadItemLength;
    return std.mem.readInt(u32, item.data[0..4], .little);
}

/// A Sequenced Address item: the connection id plus the 32-bit sequence
/// number Class 0/1 I/O carries over UDP.
pub const SequencedAddress = struct {
    connection_id: u32,
    sequence_number: u32,

    pub const encoded_len: usize = 8;

    pub fn decode(item: Item) DecodeError!SequencedAddress {
        if (item.type_id != .sequenced_address) return error.BadItemOrder;
        if (item.data.len != encoded_len) return error.BadItemLength;
        return .{
            .connection_id = std.mem.readInt(u32, item.data[0..4], .little),
            .sequence_number = std.mem.readInt(u32, item.data[4..8], .little),
        };
    }

    pub fn encode(self: SequencedAddress, out: []u8) EncodeError![]u8 {
        if (out.len < encoded_len) return error.BufferTooSmall;
        std.mem.writeInt(u32, out[0..4], self.connection_id, .little);
        std.mem.writeInt(u32, out[4..8], self.sequence_number, .little);
        return out[0..encoded_len];
    }
};

/// A Connected Data item: a two-octet sequence count, then the CIP message.
///
/// The sequence count belongs to the *item*, not to CIP. Handing it on to a
/// CIP decoder shifts the service code by two octets and produces confident
/// nonsense.
pub const ConnectedData = struct {
    sequence_count: u16,
    payload: []const u8,

    pub fn decode(item: Item) DecodeError!ConnectedData {
        if (item.type_id != .connected_data) return error.BadItemOrder;
        if (item.data.len < 2) return error.MissingSequenceCount;
        return .{
            .sequence_count = std.mem.readInt(u16, item.data[0..2], .little),
            .payload = item.data[2..],
        };
    }

    /// Writes `{sequence count, payload}` into `out` and returns it, ready to
    /// be handed to `encode` as a connected data item's `data`.
    pub fn encode(sequence_count: u16, payload: []const u8, out: []u8) EncodeError![]u8 {
        if (out.len < 2 + payload.len) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], sequence_count, .little);
        @memcpy(out[2..][0..payload.len], payload);
        return out[0 .. 2 + payload.len];
    }
};

/// The 16 octets of a Sockaddr Info item.
pub fn socketAddress(item: Item) DecodeError!SocketAddress {
    switch (item.type_id) {
        .sockaddr_info_o_to_t, .sockaddr_info_t_to_o => {},
        else => return error.BadItemOrder,
    }
    if (item.data.len != SocketAddress.encoded_len) return error.BadItemLength;
    return SocketAddress.decode(item.data) catch error.BadItemLength;
}

// ── convenience builders ────────────────────────────────────────────────────

/// The item pair an unconnected (UCMM) request uses.
pub fn unconnectedItems(cip: []const u8) [2]Item {
    return .{
        .{ .type_id = .null_address, .data = &.{} },
        .{ .type_id = .unconnected_data, .data = cip },
    };
}

/// The item pair a connected (Class 3) request uses. `body` must already
/// carry the sequence count — build it with `ConnectedData.encode`.
pub fn connectedItems(connection_id_le: *const [4]u8, body: []const u8) [2]Item {
    return .{
        .{ .type_id = .connected_address, .data = connection_id_le },
        .{ .type_id = .connected_data, .data = body },
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "an unconnected item pair round trips" {
    const cip = [_]u8{ 0x4C, 0x02, 0x20, 0x06, 0x24, 0x01 };
    const items = unconnectedItems(&cip);
    var buf: [64]u8 = undefined;
    const wire = try encode(&items, &buf);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB2, 0x00, 0x06, 0x00 } ++ cip,
        wire,
    );
    var storage: [4]Item = undefined;
    const list = try decode(wire, &storage);
    try testing.expectEqual(@as(usize, 2), list.items.len);
    try validateDataOrder(list);
    try testing.expectEqual(ItemType.null_address, list.addressItem().?.type_id);
    try testing.expectEqualSlices(u8, &cip, list.dataItem().?.data);
}

test "envelope prefixes the item list with handle and timeout" {
    const cip = [_]u8{ 0x01, 0x02 };
    const items = unconnectedItems(&cip);
    var buf: [64]u8 = undefined;
    const wire = try encodeEnvelope(0, 10, &items, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 10, 0 }, wire[0..6]);
    var storage: [4]Item = undefined;
    const env = try decodeEnvelope(wire, &storage);
    try testing.expectEqual(@as(u16, 10), env.timeout);
    try testing.expectEqual(@as(u32, 0), env.interface_handle);
    try testing.expectEqualSlices(u8, &cip, env.list.dataItem().?.data);
}

test "an item length that overruns the buffer is refused" {
    // One item, type 0x00B2, length 0x0064, but only two octets present.
    const wire = [_]u8{ 0x01, 0x00, 0xB2, 0x00, 0x64, 0x00, 0xAA, 0xBB };
    var storage: [4]Item = undefined;
    try testing.expectError(error.ItemOverruns, decode(&wire, &storage));
}

test "an item count that overruns the storage is refused, not truncated" {
    const wire = [_]u8{ 0x08, 0x00 } ++ [_]u8{ 0x00, 0x00, 0x00, 0x00 } ** 8;
    var storage: [2]Item = undefined;
    try testing.expectError(error.ItemOverruns, decode(&wire, &storage));
    var big: [8]Item = undefined;
    const ok = try decode(&wire, &big);
    try testing.expectEqual(@as(usize, 8), ok.items.len);
}

test "trailing octets after the last item are an error" {
    const wire = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };
    var storage: [4]Item = undefined;
    try testing.expectError(error.TrailingData, decode(&wire, &storage));
}

test "a count of zero with no items is legal (ListInterfaces answers it)" {
    const wire = [_]u8{ 0x00, 0x00 };
    var storage: [4]Item = undefined;
    const list = try decode(&wire, &storage);
    try testing.expectEqual(@as(usize, 0), list.items.len);
    try testing.expectEqual(@as(?Item, null), list.addressItem());
    try testing.expectError(error.BadItemOrder, validateDataOrder(list));
}

test "item ordering rules reject the malformed combinations" {
    var storage: [4]Item = undefined;
    // Data item first.
    {
        const items = [_]Item{
            .{ .type_id = .unconnected_data, .data = &[_]u8{1} },
            .{ .type_id = .null_address, .data = &.{} },
        };
        var buf: [64]u8 = undefined;
        const list = try decode(try encode(&items, &buf), &storage);
        try testing.expectError(error.BadItemOrder, validateDataOrder(list));
    }
    // Connected address paired with unconnected data.
    {
        const items = [_]Item{
            .{ .type_id = .connected_address, .data = &[_]u8{ 1, 2, 3, 4 } },
            .{ .type_id = .unconnected_data, .data = &[_]u8{1} },
        };
        var buf: [64]u8 = undefined;
        const list = try decode(try encode(&items, &buf), &storage);
        try testing.expectError(error.BadItemOrder, validateDataOrder(list));
    }
    // Null address paired with connected data.
    {
        const items = [_]Item{
            .{ .type_id = .null_address, .data = &.{} },
            .{ .type_id = .connected_data, .data = &[_]u8{ 0, 0, 1 } },
        };
        var buf: [64]u8 = undefined;
        const list = try decode(try encode(&items, &buf), &storage);
        try testing.expectError(error.BadItemOrder, validateDataOrder(list));
    }
    // Connected address of the wrong width.
    {
        const items = [_]Item{
            .{ .type_id = .connected_address, .data = &[_]u8{ 1, 2, 3 } },
            .{ .type_id = .connected_data, .data = &[_]u8{ 0, 0 } },
        };
        var buf: [64]u8 = undefined;
        const list = try decode(try encode(&items, &buf), &storage);
        try testing.expectError(error.BadItemLength, validateDataOrder(list));
    }
    // A single item is never enough for a data-carrying CPF.
    {
        const items = [_]Item{.{ .type_id = .null_address, .data = &.{} }};
        var buf: [64]u8 = undefined;
        const list = try decode(try encode(&items, &buf), &storage);
        try testing.expectError(error.BadItemOrder, validateDataOrder(list));
    }
}

test "connected data carries a sequence count ahead of the CIP message" {
    var body: [16]u8 = undefined;
    const cip = [_]u8{ 0x4C, 0x02 };
    const b = try ConnectedData.encode(0x1234, &cip, &body);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x34, 0x12, 0x4C, 0x02 }, b);
    const cd = try ConnectedData.decode(.{ .type_id = .connected_data, .data = b });
    try testing.expectEqual(@as(u16, 0x1234), cd.sequence_count);
    try testing.expectEqualSlices(u8, &cip, cd.payload);
    // A connected data item too short to hold its own sequence count.
    try testing.expectError(
        error.MissingSequenceCount,
        ConnectedData.decode(.{ .type_id = .connected_data, .data = &[_]u8{0} }),
    );
}

test "sequenced address round trips and refuses the wrong width" {
    const sa = SequencedAddress{ .connection_id = 0xDEADBEEF, .sequence_number = 7 };
    var buf: [8]u8 = undefined;
    const wire = try sa.encode(&buf);
    const back = try SequencedAddress.decode(.{ .type_id = .sequenced_address, .data = wire });
    try testing.expectEqual(sa.connection_id, back.connection_id);
    try testing.expectEqual(sa.sequence_number, back.sequence_number);
    try testing.expectError(
        error.BadItemLength,
        SequencedAddress.decode(.{ .type_id = .sequenced_address, .data = wire[0..7] }),
    );
    try testing.expectError(
        error.BadItemOrder,
        SequencedAddress.decode(.{ .type_id = .null_address, .data = wire }),
    );
}

test "optional sockaddr items are found past the data item" {
    var sock: [16]u8 = undefined;
    _ = try SocketAddress.encode(.{ .port = 2222, .addr = .{ 10, 0, 0, 9 } }, &sock);
    const items = [_]Item{
        .{ .type_id = .null_address, .data = &.{} },
        .{ .type_id = .unconnected_data, .data = &[_]u8{ 0x54, 0x02 } },
        .{ .type_id = .sockaddr_info_t_to_o, .data = &sock },
    };
    var buf: [128]u8 = undefined;
    var storage: [4]Item = undefined;
    const list = try decode(try encode(&items, &buf), &storage);
    try validateDataOrder(list);
    const found = list.find(.sockaddr_info_t_to_o).?;
    const sa = try socketAddress(found);
    try testing.expectEqual(@as(u16, 2222), sa.port);
    try testing.expectEqual(@as(?Item, null), list.find(.sockaddr_info_o_to_t));
}

test "connection id reads only from a connected address item" {
    const item = Item{ .type_id = .connected_address, .data = &[_]u8{ 0x15, 0x21, 0x14, 0xFB } };
    try testing.expectEqual(@as(u32, 0xFB142115), try connectionId(item));
    try testing.expectError(
        error.BadItemOrder,
        connectionId(.{ .type_id = .null_address, .data = &.{} }),
    );
}

test "fuzz: cpf decode never panics and re-encodes exactly" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var storage: [16]Item = undefined;
    const list = decode(buf[0..len], &storage) catch return;
    try testing.expectEqual(len, list.encoded_len);
    var round: [512]u8 = undefined;
    const again = try encode(list.items, &round);
    try testing.expectEqualSlices(u8, buf[0..len], again);
    // Walking the typed views must never panic either.
    _ = validateDataOrder(list) catch {};
    for (list.items) |it| {
        _ = connectionId(it) catch {};
        _ = SequencedAddress.decode(it) catch {};
        _ = ConnectedData.decode(it) catch {};
        _ = socketAddress(it) catch {};
    }
}

test "fuzz: envelope decode never panics" {
    try std.testing.fuzz({}, fuzzEnvelope, .{});
}

fn fuzzEnvelope(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var storage: [16]Item = undefined;
    const env = decodeEnvelope(buf[0..len], &storage) catch return;
    var round: [512]u8 = undefined;
    const again = try encodeEnvelope(env.interface_handle, env.timeout, env.list.items, &round);
    try testing.expectEqualSlices(u8, buf[0..len], again);
}
