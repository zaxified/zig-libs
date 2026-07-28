// SPDX-License-Identifier: MIT
//! BOLT#7 gossip messages: `channel_announcement`, `node_announcement`,
//! `channel_update`, `query_short_channel_ids`/
//! `reply_short_channel_ids_end`, `query_channel_range`/
//! `reply_channel_range` — plus the double-SHA256 message-digest helpers
//! the announcement/update signatures sign.
//!
//! **Signature verification is the caller's** (needs secp256k1 — out of
//! scope for a pure wire codec, see `../SPEC.md`). This module exposes
//! exactly what BOLT#7 defines as the signed pre-image: `channelAnnouncementDigest`/
//! `nodeAnnouncementDigest`/`channelUpdateDigest` compute the
//! double-SHA256 over "the message, beginning at offset N [256 or 64],
//! up to the end of the message" (BOLT#7's own words — the offset is
//! exactly the size of the signature field(s) each message leads with),
//! and each message's `.signature`/`.node_signature_1` etc. fields carry
//! the raw signature bytes for the caller to verify against that digest
//! with `node_id`/`bitcoin_key`.
//!
//! `channel_announcement`/`node_announcement`/`channel_update` define no
//! `tlv_stream` (BOLT#7 doesn't specify one for them, unlike the query
//! messages) — but each spec text notes the signature covers "any future
//! fields appended to the end", so any bytes after this module's known
//! fixed fields are preserved verbatim as `.extra` (borrowed, unparsed)
//! rather than dropped, keeping digest computation forward-compatible.
//!
//! Deferred (see `../SPEC.md`): `announcement_signatures`,
//! `gossip_timestamp_filter` — not in this module's required set.

const std = @import("std");
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const Extension = message.Extension;
const ChainHash = message.ChainHash;
const Signature = message.Signature;
const Point = message.Point;
const ShortChannelId = message.ShortChannelId;

pub const DecodeError = message.FrameError || message.tlv.StreamError;

fn readPoint(r: *Reader) message.ReadError!Point {
    return r.takeArray(33);
}
fn readSignature(r: *Reader) message.ReadError!Signature {
    return r.takeArray(64);
}
fn readScid(r: *Reader) message.ReadError!ShortChannelId {
    return r.u64be();
}
fn putScid(w: *Writer, allocator: Allocator, scid: ShortChannelId) Allocator.Error!void {
    try w.putU64be(allocator, scid);
}

/// `SHA256(SHA256(data))` -- the digest BOLT#7 announcement/update
/// signatures sign over.
fn sha256d(data: []const u8) [32]u8 {
    var first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &first, .{});
    var second: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&first, &second, .{});
    return second;
}

// ── channel_announcement (type 256) ──────────────────────────────────────

pub const CHANNEL_ANNOUNCEMENT_TYPE: u16 = 256;
/// The 4 leading `signature` fields (64 bytes each) BOLT#7 excludes from
/// the digest ("beginning at offset 256" -- exactly `4 * 64`).
pub const CHANNEL_ANNOUNCEMENT_SIG_BYTES: usize = 256;

pub const ChannelAnnouncement = struct {
    node_signature_1: Signature,
    node_signature_2: Signature,
    bitcoin_signature_1: Signature,
    bitcoin_signature_2: Signature,
    /// Borrowed slice (see `message.zig`'s module doc comment).
    features: []const u8,
    chain_hash: ChainHash,
    short_channel_id: ShortChannelId,
    node_id_1: Point,
    node_id_2: Point,
    bitcoin_key_1: Point,
    bitcoin_key_2: Point,
    /// Any bytes after `bitcoin_key_2` (module doc comment) -- borrowed,
    /// preserved verbatim, not TLV-interpreted.
    extra: []const u8 = &.{},

    pub fn deinit(_: *ChannelAnnouncement, _: Allocator) void {}
};

pub fn decodeChannelAnnouncement(bytes: []const u8) message.FrameError!ChannelAnnouncement {
    var r = try message.openFrame(bytes, CHANNEL_ANNOUNCEMENT_TYPE);
    var m: ChannelAnnouncement = undefined;
    m.node_signature_1 = try readSignature(&r);
    m.node_signature_2 = try readSignature(&r);
    m.bitcoin_signature_1 = try readSignature(&r);
    m.bitcoin_signature_2 = try readSignature(&r);
    m.features = try r.bytesU16();
    m.chain_hash = try r.takeArray(32);
    m.short_channel_id = try readScid(&r);
    m.node_id_1 = try readPoint(&r);
    m.node_id_2 = try readPoint(&r);
    m.bitcoin_key_1 = try readPoint(&r);
    m.bitcoin_key_2 = try readPoint(&r);
    m.extra = r.rest();
    return m;
}

pub fn serializeChannelAnnouncement(allocator: Allocator, msg: ChannelAnnouncement) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, CHANNEL_ANNOUNCEMENT_TYPE);
    try w.putBytes(allocator, &msg.node_signature_1);
    try w.putBytes(allocator, &msg.node_signature_2);
    try w.putBytes(allocator, &msg.bitcoin_signature_1);
    try w.putBytes(allocator, &msg.bitcoin_signature_2);
    try w.putBytesU16(allocator, msg.features);
    try w.putBytes(allocator, &msg.chain_hash);
    try putScid(&w, allocator, msg.short_channel_id);
    try w.putBytes(allocator, &msg.node_id_1);
    try w.putBytes(allocator, &msg.node_id_2);
    try w.putBytes(allocator, &msg.bitcoin_key_1);
    try w.putBytes(allocator, &msg.bitcoin_key_2);
    try w.putBytes(allocator, msg.extra);
    return w.toOwned(allocator);
}

/// BOLT#7: "compute the double-SHA256 hash `h` of the message, beginning
/// at offset 256, up to the end of the message" -- `payload` is the
/// message bytes AFTER the 2-byte type field (i.e. starting at
/// `node_signature_1`, as `decodeChannelAnnouncement` receives it).
pub fn channelAnnouncementDigest(payload: []const u8) message.ReadError![32]u8 {
    if (payload.len < CHANNEL_ANNOUNCEMENT_SIG_BYTES) return error.Truncated;
    return sha256d(payload[CHANNEL_ANNOUNCEMENT_SIG_BYTES..]);
}

// ── node_announcement (type 257) ─────────────────────────────────────────

pub const NODE_ANNOUNCEMENT_TYPE: u16 = 257;
pub const NODE_ANNOUNCEMENT_SIG_BYTES: usize = 64;

pub const NodeAnnouncement = struct {
    signature: Signature,
    /// Borrowed slice.
    features: []const u8,
    timestamp: u32,
    node_id: Point,
    rgb_color: [3]u8,
    alias: [32]u8,
    /// Borrowed slice: the raw `address descriptor` bytes (BOLT#7's
    /// `ipv4`/`ipv6`/`torv3`/`dns` encoding) -- opaque here, no per-type
    /// address parsing (a distinct, self-contained concern; see SPEC.md).
    addresses: []const u8,
    /// Any bytes after `addresses` (module doc comment).
    extra: []const u8 = &.{},

    pub fn deinit(_: *NodeAnnouncement, _: Allocator) void {}
};

pub fn decodeNodeAnnouncement(bytes: []const u8) message.FrameError!NodeAnnouncement {
    var r = try message.openFrame(bytes, NODE_ANNOUNCEMENT_TYPE);
    var m: NodeAnnouncement = undefined;
    m.signature = try readSignature(&r);
    m.features = try r.bytesU16();
    m.timestamp = try r.u32be();
    m.node_id = try readPoint(&r);
    m.rgb_color = try r.takeArray(3);
    m.alias = try r.takeArray(32);
    m.addresses = try r.bytesU16();
    m.extra = r.rest();
    return m;
}

pub fn serializeNodeAnnouncement(allocator: Allocator, msg: NodeAnnouncement) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, NODE_ANNOUNCEMENT_TYPE);
    try w.putBytes(allocator, &msg.signature);
    try w.putBytesU16(allocator, msg.features);
    try w.putU32be(allocator, msg.timestamp);
    try w.putBytes(allocator, &msg.node_id);
    try w.putBytes(allocator, &msg.rgb_color);
    try w.putBytes(allocator, &msg.alias);
    try w.putBytesU16(allocator, msg.addresses);
    try w.putBytes(allocator, msg.extra);
    return w.toOwned(allocator);
}

/// BOLT#7: "signature of the double-SHA256 of the entire remaining
/// packet after `signature`". `payload` = message bytes after the 2-byte
/// type field.
pub fn nodeAnnouncementDigest(payload: []const u8) message.ReadError![32]u8 {
    if (payload.len < NODE_ANNOUNCEMENT_SIG_BYTES) return error.Truncated;
    return sha256d(payload[NODE_ANNOUNCEMENT_SIG_BYTES..]);
}

// ── channel_update (type 258) ────────────────────────────────────────────

pub const CHANNEL_UPDATE_TYPE: u16 = 258;
pub const CHANNEL_UPDATE_SIG_BYTES: usize = 64;

pub const ChannelUpdate = struct {
    signature: Signature,
    chain_hash: ChainHash,
    short_channel_id: ShortChannelId,
    timestamp: u32,
    message_flags: u8,
    channel_flags: u8,
    cltv_expiry_delta: u16,
    htlc_minimum_msat: u64,
    fee_base_msat: u32,
    fee_proportional_millionths: u32,
    htlc_maximum_msat: u64,
    /// Any bytes after `htlc_maximum_msat` (module doc comment).
    extra: []const u8 = &.{},

    pub fn deinit(_: *ChannelUpdate, _: Allocator) void {}
};

pub fn decodeChannelUpdate(bytes: []const u8) message.FrameError!ChannelUpdate {
    var r = try message.openFrame(bytes, CHANNEL_UPDATE_TYPE);
    var m: ChannelUpdate = undefined;
    m.signature = try readSignature(&r);
    m.chain_hash = try r.takeArray(32);
    m.short_channel_id = try readScid(&r);
    m.timestamp = try r.u32be();
    m.message_flags = try r.byte();
    m.channel_flags = try r.byte();
    m.cltv_expiry_delta = try r.u16be();
    m.htlc_minimum_msat = try r.u64be();
    m.fee_base_msat = try r.u32be();
    m.fee_proportional_millionths = try r.u32be();
    m.htlc_maximum_msat = try r.u64be();
    m.extra = r.rest();
    return m;
}

pub fn serializeChannelUpdate(allocator: Allocator, msg: ChannelUpdate) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, CHANNEL_UPDATE_TYPE);
    try w.putBytes(allocator, &msg.signature);
    try w.putBytes(allocator, &msg.chain_hash);
    try putScid(&w, allocator, msg.short_channel_id);
    try w.putU32be(allocator, msg.timestamp);
    try w.putU8(allocator, msg.message_flags);
    try w.putU8(allocator, msg.channel_flags);
    try w.putU16be(allocator, msg.cltv_expiry_delta);
    try w.putU64be(allocator, msg.htlc_minimum_msat);
    try w.putU32be(allocator, msg.fee_base_msat);
    try w.putU32be(allocator, msg.fee_proportional_millionths);
    try w.putU64be(allocator, msg.htlc_maximum_msat);
    try w.putBytes(allocator, msg.extra);
    return w.toOwned(allocator);
}

pub fn channelUpdateDigest(payload: []const u8) message.ReadError![32]u8 {
    if (payload.len < CHANNEL_UPDATE_SIG_BYTES) return error.Truncated;
    return sha256d(payload[CHANNEL_UPDATE_SIG_BYTES..]);
}

// ── query_short_channel_ids / reply_short_channel_ids_end (261/262) ─────

pub const QUERY_SHORT_CHANNEL_IDS_TYPE: u16 = 261;
const query_short_channel_ids_known_tlv = [_]u64{1}; // query_flags

pub const QueryShortChannelIds = struct {
    chain_hash: ChainHash,
    /// Borrowed slice: `encoding_type` byte + the encoded ids.
    encoded_short_ids: []const u8,
    extension: Extension = .{},

    pub fn deinit(self: *QueryShortChannelIds, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeQueryShortChannelIds(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!QueryShortChannelIds {
    var r = try message.openFrame(bytes, QUERY_SHORT_CHANNEL_IDS_TYPE);
    const chain_hash = try r.takeArray(32);
    const encoded_short_ids = try r.bytesU16();
    const extension = try message.decodeExtension(allocator, r.rest(), &query_short_channel_ids_known_tlv);
    return .{ .chain_hash = chain_hash, .encoded_short_ids = encoded_short_ids, .extension = extension };
}

pub fn serializeQueryShortChannelIds(allocator: Allocator, msg: QueryShortChannelIds) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, QUERY_SHORT_CHANNEL_IDS_TYPE);
    try w.putBytes(allocator, &msg.chain_hash);
    try w.putBytesU16(allocator, msg.encoded_short_ids);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

pub const REPLY_SHORT_CHANNEL_IDS_END_TYPE: u16 = 262;

pub const ReplyShortChannelIdsEnd = struct {
    chain_hash: ChainHash,
    full_information: u8,

    pub fn deinit(_: *ReplyShortChannelIdsEnd, _: Allocator) void {}
};

pub fn decodeReplyShortChannelIdsEnd(bytes: []const u8) message.FrameError!ReplyShortChannelIdsEnd {
    var r = try message.openFrame(bytes, REPLY_SHORT_CHANNEL_IDS_END_TYPE);
    return .{ .chain_hash = try r.takeArray(32), .full_information = try r.byte() };
}

pub fn serializeReplyShortChannelIdsEnd(allocator: Allocator, msg: ReplyShortChannelIdsEnd) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, REPLY_SHORT_CHANNEL_IDS_END_TYPE);
    try w.putBytes(allocator, &msg.chain_hash);
    try w.putU8(allocator, msg.full_information);
    return w.toOwned(allocator);
}

// ── query_channel_range / reply_channel_range (263/264) ─────────────────

pub const QUERY_CHANNEL_RANGE_TYPE: u16 = 263;
const query_channel_range_known_tlv = [_]u64{1}; // query_option

pub const QueryChannelRange = struct {
    chain_hash: ChainHash,
    first_blocknum: u32,
    number_of_blocks: u32,
    extension: Extension = .{},

    pub fn deinit(self: *QueryChannelRange, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeQueryChannelRange(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!QueryChannelRange {
    var r = try message.openFrame(bytes, QUERY_CHANNEL_RANGE_TYPE);
    const chain_hash = try r.takeArray(32);
    const first_blocknum = try r.u32be();
    const number_of_blocks = try r.u32be();
    const extension = try message.decodeExtension(allocator, r.rest(), &query_channel_range_known_tlv);
    return .{ .chain_hash = chain_hash, .first_blocknum = first_blocknum, .number_of_blocks = number_of_blocks, .extension = extension };
}

pub fn serializeQueryChannelRange(allocator: Allocator, msg: QueryChannelRange) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, QUERY_CHANNEL_RANGE_TYPE);
    try w.putBytes(allocator, &msg.chain_hash);
    try w.putU32be(allocator, msg.first_blocknum);
    try w.putU32be(allocator, msg.number_of_blocks);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

pub const REPLY_CHANNEL_RANGE_TYPE: u16 = 264;
const reply_channel_range_known_tlv = [_]u64{ 1, 3 }; // timestamps_tlv, checksums_tlv

pub const ReplyChannelRange = struct {
    chain_hash: ChainHash,
    first_blocknum: u32,
    number_of_blocks: u32,
    sync_complete: u8,
    /// Borrowed slice: `encoding_type` byte + the encoded ids.
    encoded_short_ids: []const u8,
    extension: Extension = .{},

    pub fn deinit(self: *ReplyChannelRange, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeReplyChannelRange(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!ReplyChannelRange {
    var r = try message.openFrame(bytes, REPLY_CHANNEL_RANGE_TYPE);
    const chain_hash = try r.takeArray(32);
    const first_blocknum = try r.u32be();
    const number_of_blocks = try r.u32be();
    const sync_complete = try r.byte();
    const encoded_short_ids = try r.bytesU16();
    const extension = try message.decodeExtension(allocator, r.rest(), &reply_channel_range_known_tlv);
    return .{
        .chain_hash = chain_hash,
        .first_blocknum = first_blocknum,
        .number_of_blocks = number_of_blocks,
        .sync_complete = sync_complete,
        .encoded_short_ids = encoded_short_ids,
        .extension = extension,
    };
}

pub fn serializeReplyChannelRange(allocator: Allocator, msg: ReplyChannelRange) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, REPLY_CHANNEL_RANGE_TYPE);
    try w.putBytes(allocator, &msg.chain_hash);
    try w.putU32be(allocator, msg.first_blocknum);
    try w.putU32be(allocator, msg.number_of_blocks);
    try w.putU8(allocator, msg.sync_complete);
    try w.putBytesU16(allocator, msg.encoded_short_ids);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn fillPattern(comptime n: usize, seed: u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = seed +% @as(u8, @truncate(i));
    return out;
}

fn frameTypeBytes(t: u16) [2]u8 {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, t, .big);
    return b;
}

test "channel_announcement: round-trip + digest matches an independent sha256d over the tail" {
    const allocator = testing.allocator;
    const msg: ChannelAnnouncement = .{
        .node_signature_1 = fillPattern(64, 1),
        .node_signature_2 = fillPattern(64, 2),
        .bitcoin_signature_1 = fillPattern(64, 3),
        .bitcoin_signature_2 = fillPattern(64, 4),
        .features = &.{0x00},
        .chain_hash = fillPattern(32, 5),
        .short_channel_id = 0x1122_33_4455,
        .node_id_1 = fillPattern(33, 6),
        .node_id_2 = fillPattern(33, 7),
        .bitcoin_key_1 = fillPattern(33, 8),
        .bitcoin_key_2 = fillPattern(33, 9),
    };
    const bytes = try serializeChannelAnnouncement(allocator, msg);
    defer allocator.free(bytes);

    const decoded = try decodeChannelAnnouncement(bytes);
    try testing.expectEqual(msg.short_channel_id, decoded.short_channel_id);
    try testing.expectEqualSlices(u8, &msg.node_id_2, &decoded.node_id_2);

    const reser = try serializeChannelAnnouncement(allocator, decoded);
    defer allocator.free(reser);
    try testing.expectEqualSlices(u8, bytes, reser);

    // digest: payload = bytes[2..] (strip the 2-byte type); tail = bytes
    // after the 4 signatures (256 bytes into the payload).
    const payload = bytes[2..];
    const got = try channelAnnouncementDigest(payload);
    var want_first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload[256..], &want_first, .{});
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&want_first, &want, .{});
    try testing.expectEqualSlices(u8, &want, &got);

    // The digest must be invariant to the signature bytes themselves
    // (they're excluded from the pre-image) but must change if any byte
    // AFTER offset 256 changes.
    var msg2 = msg;
    msg2.node_signature_1 = fillPattern(64, 200); // different signature bytes
    const bytes2 = try serializeChannelAnnouncement(allocator, msg2);
    defer allocator.free(bytes2);
    const got2 = try channelAnnouncementDigest(bytes2[2..]);
    try testing.expectEqualSlices(u8, &got, &got2);

    var msg3 = msg;
    msg3.short_channel_id = msg.short_channel_id + 1; // a byte after offset 256
    const bytes3 = try serializeChannelAnnouncement(allocator, msg3);
    defer allocator.free(bytes3);
    const got3 = try channelAnnouncementDigest(bytes3[2..]);
    try testing.expect(!std.mem.eql(u8, &got, &got3));
}

test "hostile: channelAnnouncementDigest on a too-short payload fails closed" {
    try testing.expectError(error.Truncated, channelAnnouncementDigest(&([_]u8{0} ** 100)));
}

test "node_announcement: round-trip + digest offset-64 semantics" {
    const allocator = testing.allocator;
    const msg: NodeAnnouncement = .{
        .signature = fillPattern(64, 1),
        .features = &.{0x00},
        .timestamp = 1_700_000_000,
        .node_id = fillPattern(33, 2),
        .rgb_color = .{ 0x11, 0x22, 0x33 },
        .alias = fillPattern(32, 3),
        .addresses = &.{},
    };
    const bytes = try serializeNodeAnnouncement(allocator, msg);
    defer allocator.free(bytes);
    const decoded = try decodeNodeAnnouncement(bytes);
    try testing.expectEqual(msg.timestamp, decoded.timestamp);
    try testing.expectEqualSlices(u8, &msg.rgb_color, &decoded.rgb_color);

    const payload = bytes[2..];
    const got = try nodeAnnouncementDigest(payload);
    var want_first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload[64..], &want_first, .{});
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&want_first, &want, .{});
    try testing.expectEqualSlices(u8, &want, &got);
}

test "node_announcement: round-trip with a non-empty addresses field and trailing extra bytes" {
    const allocator = testing.allocator;
    // one ipv4 address descriptor: type(1) + 4-byte addr + 2-byte port
    const addr = [_]u8{ 1, 127, 0, 0, 1, 0x1f, 0x90 };
    const msg: NodeAnnouncement = .{
        .signature = fillPattern(64, 1),
        .features = &.{},
        .timestamp = 1,
        .node_id = fillPattern(33, 2),
        .rgb_color = .{ 0, 0, 0 },
        .alias = fillPattern(32, 3),
        .addresses = &addr,
        .extra = &.{ 0xde, 0xad },
    };
    const bytes = try serializeNodeAnnouncement(allocator, msg);
    defer allocator.free(bytes);
    const decoded = try decodeNodeAnnouncement(bytes);
    try testing.expectEqualSlices(u8, &addr, decoded.addresses);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, decoded.extra);
}

test "channel_update: round-trip + digest" {
    const allocator = testing.allocator;
    const msg: ChannelUpdate = .{
        .signature = fillPattern(64, 1),
        .chain_hash = fillPattern(32, 2),
        .short_channel_id = 0x0102_03_0405,
        .timestamp = 1_700_000_001,
        .message_flags = 1,
        .channel_flags = 0,
        .cltv_expiry_delta = 40,
        .htlc_minimum_msat = 1,
        .fee_base_msat = 1000,
        .fee_proportional_millionths = 100,
        .htlc_maximum_msat = 1_000_000_000,
    };
    const bytes = try serializeChannelUpdate(allocator, msg);
    defer allocator.free(bytes);
    const decoded = try decodeChannelUpdate(bytes);
    try testing.expectEqual(msg.fee_base_msat, decoded.fee_base_msat);
    try testing.expectEqual(msg.short_channel_id, decoded.short_channel_id);

    const payload = bytes[2..];
    const got = try channelUpdateDigest(payload);
    var want_first: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload[64..], &want_first, .{});
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&want_first, &want, .{});
    try testing.expectEqualSlices(u8, &want, &got);
}

test "hostile: channel_announcement/node_announcement/channel_update truncated fixed fields fail closed" {
    // channel_announcement cut off mid-way through the 4th signature.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, &frameTypeBytes(CHANNEL_ANNOUNCEMENT_TYPE));
    try buf.appendSlice(testing.allocator, &([_]u8{0xaa} ** 200)); // only 200 of 256 signature bytes
    try testing.expectError(error.Truncated, decodeChannelAnnouncement(buf.items));
}

test "query_short_channel_ids / reply_short_channel_ids_end: round-trip" {
    const allocator = testing.allocator;
    var msg: QueryShortChannelIds = .{
        .chain_hash = fillPattern(32, 1),
        .encoded_short_ids = &.{ 0x00, 0xaa, 0xbb },
        .extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{.{ .type = 1, .value = &.{ 0x00, 0x01 } }}) },
    };
    const bytes = try serializeQueryShortChannelIds(allocator, msg);
    defer allocator.free(bytes);
    _ = &msg;
    var decoded = try decodeQueryShortChannelIds(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xaa, 0xbb }, decoded.encoded_short_ids);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, decoded.extension.find(1).?);

    const end: ReplyShortChannelIdsEnd = .{ .chain_hash = fillPattern(32, 2), .full_information = 1 };
    const end_bytes = try serializeReplyShortChannelIdsEnd(allocator, end);
    defer allocator.free(end_bytes);
    const end_decoded = try decodeReplyShortChannelIdsEnd(end_bytes);
    try testing.expectEqual(@as(u8, 1), end_decoded.full_information);
}

test "query_channel_range / reply_channel_range: round-trip" {
    const allocator = testing.allocator;
    const q: QueryChannelRange = .{ .chain_hash = fillPattern(32, 1), .first_blocknum = 700_000, .number_of_blocks = 1000 };
    const q_bytes = try serializeQueryChannelRange(allocator, q);
    defer allocator.free(q_bytes);
    var q_decoded = try decodeQueryChannelRange(allocator, q_bytes);
    defer q_decoded.deinit(allocator);
    try testing.expectEqual(q.first_blocknum, q_decoded.first_blocknum);

    var ts_bytes: [9]u8 = undefined;
    ts_bytes[0] = 0; // encoding_type = uncompressed
    std.mem.writeInt(u32, ts_bytes[1..5], 111, .big);
    std.mem.writeInt(u32, ts_bytes[5..9], 222, .big);
    var r: ReplyChannelRange = .{
        .chain_hash = fillPattern(32, 2),
        .first_blocknum = 700_000,
        .number_of_blocks = 1000,
        .sync_complete = 1,
        .encoded_short_ids = &.{0x00},
        .extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{.{ .type = 1, .value = &ts_bytes }}) },
    };
    const r_bytes = try serializeReplyChannelRange(allocator, r);
    defer allocator.free(r_bytes);
    _ = &r;
    _ = &ts_bytes;
    var r_decoded = try decodeReplyChannelRange(allocator, r_bytes);
    defer r_decoded.deinit(allocator);
    try testing.expectEqual(@as(u8, 1), r_decoded.sync_complete);
    try testing.expectEqualSlices(u8, &ts_bytes, r_decoded.extension.find(1).?);
}

test "hostile: query_channel_range with an unknown-even extension TLV is rejected" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &frameTypeBytes(QUERY_CHANNEL_RANGE_TYPE));
    try buf.appendSlice(allocator, &fillPattern(32, 1));
    try buf.appendSlice(allocator, &([_]u8{0} ** 8)); // first_blocknum + number_of_blocks
    try message.tlv.appendStream(&buf, allocator, &.{.{ .type = 2, .value = &.{} }}); // even, unknown
    try testing.expectError(error.UnknownEvenType, decodeQueryChannelRange(allocator, buf.items));
}

test "hostile: reply_channel_range with an encoded_short_ids length prefix exceeding remaining bytes fails closed" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, &frameTypeBytes(REPLY_CHANNEL_RANGE_TYPE));
    try buf.appendSlice(testing.allocator, &fillPattern(32, 1));
    try buf.appendSlice(testing.allocator, &([_]u8{0} ** 8)); // first_blocknum, number_of_blocks
    try buf.appendSlice(testing.allocator, &.{1}); // sync_complete
    try buf.appendSlice(testing.allocator, &.{ 0xff, 0xff }); // len=65535, nothing follows
    try testing.expectError(error.Truncated, decodeReplyChannelRange(testing.allocator, buf.items));
}

// ── fuzz: decodeQueryShortChannelIds never panics on arbitrary bytes ──────
//
// The BOLT#7 gossip-query family's other recurring shape: a fixed prefix
// plus a `u16`-length-prefixed variable field (`encoded_short_ids`, whose
// own length prefix is exactly the "PSBT/TLV length-prefix" hazard class
// this pass is watching for) before the trailing tlv_stream. `chain_hash`
// (32) + `bytesU16` + `decodeExtension` is also `reply_channel_range`'s
// and `channel_announcement`'s `features` field's shape, so this one
// harness stands in for that whole sub-family.
test "fuzz: decodeQueryShortChannelIds never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeQueryShortChannelIds, .{});
}

fn fuzzDecodeQueryShortChannelIds(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    std.mem.writeInt(u16, buf[0..2], QUERY_SHORT_CHANNEL_IDS_TYPE, .big);
    // Bias the encoded_short_ids length prefix (bytes[34..36], right after
    // the 2-byte type + 32-byte chain_hash) toward both near-buffer-size
    // values (exercise the truncation path) and fully random ones.
    if (smith.value(bool)) {
        const near: u16 = @intCast(buf.len - 36 + smith.valueRangeAtMost(u8, 0, 4));
        std.mem.writeInt(u16, buf[34..36], near, .big);
    }
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var m = decodeQueryShortChannelIds(allocator, buf[0..len]) catch return;
    defer m.deinit(allocator);
}
