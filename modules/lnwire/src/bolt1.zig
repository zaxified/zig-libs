// SPDX-License-Identifier: MIT
//! BOLT#1 base-protocol messages: `init`, `error` (and `warning`, same
//! wire layout), `ping`, `pong`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const bolt7 = @import("bolt7.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const Extension = message.Extension;
const ChannelId = message.ChannelId;

pub const DecodeError = message.FrameError || message.tlv.StreamError;

/// A known TLV record of the wrong length (`InvalidTlvLength`); see `message.TlvLengthError`.
pub const TlvLengthError = message.TlvLengthError;

// ── init (type 16) ──────────────────────────────────────────────────────

pub const INIT_TYPE: u16 = 16;
/// `init_tlvs` TLV types (BOLT#1).
pub const TLV_NETWORKS: u64 = 1;
pub const TLV_REMOTE_ADDR: u64 = 3;
const init_known_tlv_types = [_]u64{ TLV_NETWORKS, TLV_REMOTE_ADDR };

/// Walks the `networks` TLV value: a concatenation of 32-octet chain hashes
/// (BOLT#1 `networks`: `...*chain_hash`). Borrowed from the decoded extension.
pub const NetworksIterator = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(self: *NetworksIterator) ?[32]u8 {
        if (self.bytes.len - self.pos < 32) return null;
        const h = self.bytes[self.pos..][0..32].*;
        self.pos += 32;
        return h;
    }

    /// How many chain hashes the value holds.
    pub fn count(self: NetworksIterator) usize {
        return self.bytes.len / 32;
    }
};

/// Checks the two known records' encodings: `networks` is a whole number of
/// 32-octet hashes; `remote_addr` is exactly one BOLT#7 address descriptor
/// (an unknown descriptor type cannot be framed, so it is let through and
/// `Init.remoteAddr` reports it as absent).
fn checkInitTlvs(ext: Extension) TlvLengthError!void {
    if (ext.find(TLV_NETWORKS)) |v| {
        if (v.len % 32 != 0) return error.InvalidTlvLength;
    }
    if (ext.find(TLV_REMOTE_ADDR)) |v| {
        var it = bolt7.addressIterator(v);
        const a = it.next() catch return error.InvalidTlvLength;
        if (a != null and it.unparsed().len != 0) return error.InvalidTlvLength;
    }
}

pub const Init = struct {
    /// Borrowed slices (see `message.zig`'s module doc comment).
    globalfeatures: []const u8,
    features: []const u8,
    extension: Extension = .{},

    pub fn deinit(self: *Init, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    /// `networks` (TLV 1), if present: the chain hashes the sender is
    /// interested in. Its length (a multiple of 32) was checked at decode.
    pub fn networks(self: Init) ?NetworksIterator {
        const v = self.extension.find(TLV_NETWORKS) orelse return null;
        if (v.len % 32 != 0) return null;
        return .{ .bytes = v };
    }

    /// `remote_addr` (TLV 3), if present: the address the sender sees this
    /// connection coming from. `null` when absent or of a descriptor type
    /// this module does not know. Borrowed from the decoded extension.
    pub fn remoteAddr(self: Init) ?bolt7.Address {
        const v = self.extension.find(TLV_REMOTE_ADDR) orelse return null;
        var it = bolt7.addressIterator(v);
        const a = it.next() catch return null;
        return a;
    }
};

pub fn decodeInit(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!Init {
    var r = try message.openFrame(bytes, INIT_TYPE);
    const globalfeatures = try r.bytesU16();
    const features = try r.bytesU16();
    var extension = try message.decodeExtension(allocator, r.rest(), &init_known_tlv_types);
    errdefer extension.deinit(allocator);
    try checkInitTlvs(extension);
    return .{ .globalfeatures = globalfeatures, .features = features, .extension = extension };
}

pub fn serializeInit(allocator: Allocator, msg: Init) (message.WriteError || TlvLengthError)![]u8 {
    try checkInitTlvs(msg.extension);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, INIT_TYPE);
    try w.putBytesU16(allocator, msg.globalfeatures);
    try w.putBytesU16(allocator, msg.features);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── error / warning (types 17 / 1) — identical layout ───────────────────
//
// BOLT#1 defines `error` (type 17) and `warning` (type 1) with the exact
// same 3-field layout (`channel_id` + `len` + `data`, no tlv_stream); one
// codec serves both, parameterized by `msg_type`.

pub const ERROR_TYPE: u16 = 17;
pub const WARNING_TYPE: u16 = 1;

pub const ErrorMsg = struct {
    channel_id: ChannelId,
    /// Borrowed slice (see module doc comment). BOLT#1: "if `data` is not
    /// composed solely of printable ASCII... SHOULD NOT print out `data`
    /// verbatim" -- left as opaque bytes here, no ASCII enforcement (a
    /// receiver display concern, not a wire-decode one).
    data: []const u8,

    pub fn deinit(_: *ErrorMsg, _: Allocator) void {}
};

pub fn decodeErrorLike(bytes: []const u8, msg_type: u16) message.FrameError!ErrorMsg {
    var r = try message.openFrame(bytes, msg_type);
    const channel_id = try r.takeArray(32);
    const data = try r.bytesU16();
    return .{ .channel_id = channel_id, .data = data };
}

pub fn serializeErrorLike(allocator: Allocator, msg: ErrorMsg, msg_type: u16) message.WriteError![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, msg_type);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytesU16(allocator, msg.data);
    return w.toOwned(allocator);
}

pub fn decodeError(bytes: []const u8) message.FrameError!ErrorMsg {
    return decodeErrorLike(bytes, ERROR_TYPE);
}
pub fn serializeError(allocator: Allocator, msg: ErrorMsg) message.WriteError![]u8 {
    return serializeErrorLike(allocator, msg, ERROR_TYPE);
}
pub fn decodeWarning(bytes: []const u8) message.FrameError!ErrorMsg {
    return decodeErrorLike(bytes, WARNING_TYPE);
}
pub fn serializeWarning(allocator: Allocator, msg: ErrorMsg) message.WriteError![]u8 {
    return serializeErrorLike(allocator, msg, WARNING_TYPE);
}

// ── ping / pong (types 18 / 19) ──────────────────────────────────────────

pub const PING_TYPE: u16 = 18;
pub const PONG_TYPE: u16 = 19;

pub const Ping = struct {
    num_pong_bytes: u16,
    /// Borrowed slice (see module doc comment).
    ignored: []const u8,

    pub fn deinit(_: *Ping, _: Allocator) void {}
};

pub fn decodePing(bytes: []const u8) message.FrameError!Ping {
    var r = try message.openFrame(bytes, PING_TYPE);
    const num_pong_bytes = try r.u16be();
    const ignored = try r.bytesU16();
    return .{ .num_pong_bytes = num_pong_bytes, .ignored = ignored };
}

pub fn serializePing(allocator: Allocator, msg: Ping) message.WriteError![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, PING_TYPE);
    try w.putU16be(allocator, msg.num_pong_bytes);
    try w.putBytesU16(allocator, msg.ignored);
    return w.toOwned(allocator);
}

pub const Pong = struct {
    /// Borrowed slice (see module doc comment).
    ignored: []const u8,

    pub fn deinit(_: *Pong, _: Allocator) void {}
};

pub fn decodePong(bytes: []const u8) message.FrameError!Pong {
    var r = try message.openFrame(bytes, PONG_TYPE);
    const ignored = try r.bytesU16();
    return .{ .ignored = ignored };
}

pub fn serializePong(allocator: Allocator, msg: Pong) message.WriteError![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, PONG_TYPE);
    try w.putBytesU16(allocator, msg.ignored);
    return w.toOwned(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "init: round-trip with empty feature vectors and no extension" {
    const allocator = testing.allocator;
    const msg: Init = .{ .globalfeatures = &.{}, .features = &.{} };
    const bytes = try serializeInit(allocator, msg);
    defer allocator.free(bytes);
    try testing.expectEqualSlices(u8, &.{ 0x00, INIT_TYPE, 0x00, 0x00, 0x00, 0x00 }, bytes);

    var decoded = try decodeInit(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), decoded.globalfeatures.len);
    try testing.expectEqual(@as(usize, 0), decoded.features.len);
}

test "init: round-trip with non-empty features and a networks TLV" {
    const allocator = testing.allocator;
    var chain_hash: [32]u8 = undefined;
    @memset(&chain_hash, 0xab);

    const msg: Init = .{
        .globalfeatures = &.{0x00},
        .features = &.{ 0x08, 0x00 },
        .extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{.{ .type = 1, .value = &chain_hash }}) },
    };
    const bytes = try serializeInit(allocator, msg);
    defer allocator.free(bytes);

    var decoded = try decodeInit(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqualSlices(u8, &.{0x00}, decoded.globalfeatures);
    try testing.expectEqualSlices(u8, &.{ 0x08, 0x00 }, decoded.features);
    try testing.expectEqualSlices(u8, &chain_hash, decoded.extension.find(1).?);
}

test "init: the remote_addr TLV (type 3) is kept, not discarded as unknown-odd" {
    // Mutation run 2026-10-05: dropping 3 from the known types passed every test.
    const allocator = testing.allocator;
    const addr = [_]u8{ 0x01, 192, 0, 2, 1, 0x26, 0x07 }; // IPv4 192.0.2.1:9735
    const msg: Init = .{
        .globalfeatures = &.{},
        .features = &.{},
        .extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{.{ .type = 3, .value = &addr }}) },
    };
    const bytes = try serializeInit(allocator, msg);
    defer allocator.free(bytes);
    var decoded = try decodeInit(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqualSlices(u8, &addr, decoded.extension.find(3).?);
}

test "hostile: init with a globalfeatures length prefix exceeding remaining bytes fails closed" {
    const bytes = [_]u8{ 0x00, INIT_TYPE, 0x00, 0x64 }; // gflen=100, nothing follows
    try testing.expectError(error.Truncated, decodeInit(testing.allocator, &bytes));
}

test "hostile: init with an unknown-even top-level TLV in the extension is rejected" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &.{ 0x00, INIT_TYPE, 0x00, 0x00, 0x00, 0x00 }); // empty gf/f
    try message.tlv.appendStream(&buf, allocator, &.{.{ .type = 2, .value = &.{} }}); // even, unknown
    try testing.expectError(error.UnknownEvenType, decodeInit(allocator, buf.items));
}

test "error: round-trip" {
    const allocator = testing.allocator;
    var cid: ChannelId = undefined;
    @memset(&cid, 0x11);
    const msg: ErrorMsg = .{ .channel_id = cid, .data = "boom" };
    const bytes = try serializeError(allocator, msg);
    defer allocator.free(bytes);
    try testing.expectEqual(@as(usize, 2 + 32 + 2 + 4), bytes.len);

    const decoded = try decodeError(bytes);
    try testing.expectEqualSlices(u8, &cid, &decoded.channel_id);
    try testing.expectEqualSlices(u8, "boom", decoded.data);
}

test "warning: shares error's wire layout, distinguished only by type" {
    const allocator = testing.allocator;
    var cid: ChannelId = undefined;
    @memset(&cid, 0);
    const msg: ErrorMsg = .{ .channel_id = cid, .data = "" };
    const bytes = try serializeWarning(allocator, msg);
    defer allocator.free(bytes);
    try testing.expectEqual(@as(u16, WARNING_TYPE), std.mem.readInt(u16, bytes[0..2], .big));
    try testing.expectError(error.WrongType, decodeError(bytes));
    _ = try decodeWarning(bytes);
}

test "hostile: error with a data length prefix exceeding remaining bytes fails closed" {
    var bytes: [2 + 32 + 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], ERROR_TYPE, .big);
    @memset(bytes[2..34], 0);
    std.mem.writeInt(u16, bytes[34..36], 0xffff, .big); // declared len way beyond buffer
    try testing.expectError(error.Truncated, decodeError(&bytes));
}

test "ping/pong: round-trip" {
    const allocator = testing.allocator;
    const ping_bytes = try serializePing(allocator, .{ .num_pong_bytes = 42, .ignored = &.{ 0, 0, 0 } });
    defer allocator.free(ping_bytes);
    const ping = try decodePing(ping_bytes);
    try testing.expectEqual(@as(u16, 42), ping.num_pong_bytes);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, ping.ignored);

    const pong_bytes = try serializePong(allocator, .{ .ignored = &.{ 1, 2 } });
    defer allocator.free(pong_bytes);
    const pong = try decodePong(pong_bytes);
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, pong.ignored);
}

test "hostile: ping with byteslen exceeding remaining bytes fails closed" {
    var bytes: [2 + 2 + 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], PING_TYPE, .big);
    std.mem.writeInt(u16, bytes[2..4], 0, .big); // num_pong_bytes
    std.mem.writeInt(u16, bytes[4..6], 0xffff, .big); // byteslen: nothing this large follows
    try testing.expectError(error.Truncated, decodePing(&bytes));
}
