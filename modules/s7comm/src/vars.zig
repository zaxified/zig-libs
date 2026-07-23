// SPDX-License-Identifier: MIT

//! The Read Var / Write Var parameter block, which is the thin wrapper the
//! item structures of `items.zig` sit in.
//!
//! ```text
//! request:  <function> <item count> <item> <item> ...
//! reply:    <function> <item count>            (the values are in the data block)
//! ```
//!
//! The item count is a single octet, so 255 items is the protocol ceiling —
//! the real ceiling is much lower, because every item costs 12 octets of
//! request and at least 4 of reply and both must fit the negotiated PDU.
//!
//! A reply's item count is **not** to be trusted against the data block's
//! size: it is what tells the data-block iterator how many items to look for,
//! and a peer that lies about it is exactly the hostile case the iterator has
//! to survive. That is why `DataItemIterator` bounds every step against the
//! block it was given rather than against this count.

const std = @import("std");
const items = @import("items.zig");
const s7 = @import("s7.zig");

pub const Error = error{
    /// Fewer octets than a parameter block needs.
    ShortParameters,
    /// The function octet is not Read Var or Write Var.
    UnexpectedFunction,
    /// The item count does not match the octets present.
    ItemCountMismatch,
    /// More items than a single octet can express.
    TooManyItems,
    /// The caller's output buffer is too small.
    BufferTooSmall,
} || items.Error;

/// Ceiling imposed by the one-octet item count.
pub const max_items: usize = 255;

/// A decoded request parameter block.
pub const Request = struct {
    function: s7.Function,
    count: u8,
    /// The raw item octets; walk them with `iterator()`.
    item_bytes: []const u8,

    pub fn iterator(self: Request) ItemIterator {
        return .{ .bytes = self.item_bytes, .remaining = self.count };
    }
};

pub const ItemIterator = struct {
    bytes: []const u8,
    pos: usize = 0,
    remaining: u8,

    pub fn next(self: *ItemIterator) Error!?items.Item {
        if (self.remaining == 0) return null;
        if (self.pos + items.item_len > self.bytes.len) return error.ShortItem;
        const it = try items.Item.decode(self.bytes[self.pos..]);
        self.pos += items.item_len;
        self.remaining -= 1;
        return it;
    }
};

/// Decodes the parameter block of a Read Var or Write Var **request**.
/// Requires the item octets to account exactly for the announced count, since
/// a request that does not is malformed rather than merely odd.
pub fn decodeRequest(bytes: []const u8) Error!Request {
    if (bytes.len < 2) return error.ShortParameters;
    const function: s7.Function = @enumFromInt(bytes[0]);
    switch (function) {
        .read_var, .write_var => {},
        else => return error.UnexpectedFunction,
    }
    const count = bytes[1];
    const need = @as(usize, count) * items.item_len;
    if (bytes.len - 2 != need) return error.ItemCountMismatch;
    return .{ .function = function, .count = count, .item_bytes = bytes[2..] };
}

/// Decodes the parameter block of a Read Var or Write Var **reply**, which is
/// exactly the function octet and the item count.
pub fn decodeReply(bytes: []const u8) Error!struct { function: s7.Function, count: u8 } {
    if (bytes.len < 2) return error.ShortParameters;
    const function: s7.Function = @enumFromInt(bytes[0]);
    switch (function) {
        .read_var, .write_var => {},
        else => return error.UnexpectedFunction,
    }
    return .{ .function = function, .count = bytes[1] };
}

/// Writes `<function> <count> <items...>`.
pub fn encodeRequest(function: s7.Function, list: []const items.Item, out: []u8) Error![]u8 {
    if (list.len > max_items) return error.TooManyItems;
    const total = 2 + list.len * items.item_len;
    if (out.len < total) return error.BufferTooSmall;
    out[0] = @intFromEnum(function);
    out[1] = @intCast(list.len);
    for (list, 0..) |it, i| _ = try it.encode(out[2 + i * items.item_len ..]);
    return out[0..total];
}

/// Writes the two-octet reply parameter block.
pub fn encodeReply(function: s7.Function, count: u8, out: []u8) Error![]u8 {
    if (out.len < 2) return error.BufferTooSmall;
    out[0] = @intFromEnum(function);
    out[1] = count;
    return out[0..2];
}

// ── PDU budgeting ───────────────────────────────────────────────────────────
//
// Every one of these is derived from the frame layouts above, and the client
// enforces them so a request can never be built that the peer will refuse for
// being over the negotiated size.

/// Octets of payload a single-item Read Var **reply** can carry.
/// 12 (Ack-Data header) + 2 (parameters) + 4 (data-item header).
pub fn maxReadPayload(pdu_length: u16) usize {
    const overhead: usize = 12 + 2 + 4;
    return if (pdu_length > overhead) pdu_length - overhead else 0;
}

/// Octets of payload a single-item Write Var **request** can carry.
/// 10 (Job header) + 2 (parameters) + 12 (item) + 4 (data-item header).
pub fn maxWritePayload(pdu_length: u16) usize {
    const overhead: usize = 10 + 2 + items.item_len + 4;
    return if (pdu_length > overhead) pdu_length - overhead else 0;
}

/// How many items a Read Var **request** can carry (the request side is the
/// binding constraint; the reply side depends on the payload sizes).
pub fn maxRequestItems(pdu_length: u16) usize {
    const overhead: usize = 10 + 2;
    if (pdu_length <= overhead) return 0;
    return @min(max_items, (pdu_length - overhead) / items.item_len);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "read request round trip" {
    const list = [_]items.Item{
        try items.Item.at(.db, 1, 20, 0, .byte, 4),
        try items.Item.at(.flags, 0, 0, 0, .byte, 2),
    };
    var buf: [64]u8 = undefined;
    const enc = try encodeRequest(.read_var, &list, &buf);
    try testing.expectEqual(@as(usize, 2 + 24), enc.len);
    try testing.expectEqual(@as(u8, 0x04), enc[0]);
    try testing.expectEqual(@as(u8, 2), enc[1]);

    const req = try decodeRequest(enc);
    try testing.expectEqual(s7.Function.read_var, req.function);
    var it = req.iterator();
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u24, 160), a.address);
    const b = (try it.next()).?;
    try testing.expectEqual(items.Area.flags, b.area);
    try testing.expect((try it.next()) == null);
}

test "decodeRequest refuses a count that disagrees with the item octets" {
    // Count 2 with only one item present.
    var wire: [14]u8 = undefined;
    wire[0] = 0x04;
    wire[1] = 2;
    _ = try (try items.Item.at(.db, 1, 0, 0, .byte, 1)).encode(wire[2..]);
    try testing.expectError(error.ItemCountMismatch, decodeRequest(&wire));
    // Count 0 with an item present.
    wire[1] = 0;
    try testing.expectError(error.ItemCountMismatch, decodeRequest(&wire));
    // A foreign function code.
    wire[0] = 0xF0;
    wire[1] = 1;
    try testing.expectError(error.UnexpectedFunction, decodeRequest(&wire));
    try testing.expectError(error.ShortParameters, decodeRequest(&[_]u8{0x04}));
}

test "reply parameters" {
    var buf: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x02 }, try encodeReply(.write_var, 2, &buf));
    const r = try decodeReply(&[_]u8{ 0x04, 0x03, 0xFF });
    try testing.expectEqual(s7.Function.read_var, r.function);
    try testing.expectEqual(@as(u8, 3), r.count);
    try testing.expectError(error.ShortParameters, decodeReply(&[_]u8{0x04}));
}

test "PDU budgets match the reference stack's splitting" {
    // The reference stack split a 600-octet read of a 480-octet PDU into
    // 462 + 138 octets. 462 = 480 - 18.
    try testing.expectEqual(@as(usize, 462), maxReadPayload(480));
    try testing.expectEqual(@as(usize, 222), maxReadPayload(240));
    try testing.expectEqual(@as(usize, 452), maxWritePayload(480));
    try testing.expectEqual(@as(usize, 0), maxReadPayload(16));
    try testing.expectEqual(@as(usize, 0), maxWritePayload(16));
    // 480 - 12 = 468, / 12 = 39 items.
    try testing.expectEqual(@as(usize, 39), maxRequestItems(480));
    try testing.expectEqual(@as(usize, 19), maxRequestItems(240));
    try testing.expectEqual(@as(usize, 0), maxRequestItems(10));
}

test "encodeRequest refuses more items than the count octet holds" {
    var buf: [8]u8 = undefined;
    const list = [_]items.Item{try items.Item.at(.db, 1, 0, 0, .byte, 1)};
    try testing.expectError(error.BufferTooSmall, encodeRequest(.read_var, &list, &buf));
}

test "fuzz: request parameter decode never panics" {
    try std.testing.fuzz({}, fuzzRequest, .{});
}

fn fuzzRequest(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const req = decodeRequest(buf[0..len]) catch return;
    var it = req.iterator();
    var seen: usize = 0;
    while (true) {
        const got = it.next() catch return;
        if (got == null) break;
        seen += 1;
        try testing.expect(seen <= max_items);
    }
    try testing.expectEqual(@as(usize, req.count), seen);
}
