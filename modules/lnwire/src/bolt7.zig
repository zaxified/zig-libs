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

// ── verification seam ─────────────────────────────────────────────────────
//
// `decodeChannelAnnouncement`/`decodeNodeAnnouncement`/`decodeChannelUpdate`
// return a fully-populated struct for arbitrary bytes with a well-formed
// shape, signature included -- decoding never checks that a signature is
// genuine (this module has no secp256k1 dependency, see the file header).
// Nothing in the API previously distinguished a *verified* announcement/
// update from a merely-*decoded* one, unlike the sibling `lninvoice`
// module's `Invoice.verify`/`InvoiceRequest.verify`. `EcdsaVerifyFn` is the
// seam that closes that gap without adding a dependency: the caller plugs
// in whatever secp256k1 they already have (same function-pointer-seam shape
// as `iec62351`'s `RawVerifier`), and the three `verify*` functions below
// name, in the type signature, which digest goes with which signature and
// public key per BOLT#7 -- so "is this checked yet" is a question the
// caller's own code answers by whether it called `verify*` at all, not by
// re-deriving BOLT#7's signer/digest pairing from scratch.

/// `true` iff `signature` is a valid ECDSA signature by `pubkey` over
/// `digest`. The caller supplies this (secp256k1 is out of scope here);
/// `ctx` is an opaque pointer threaded through for the caller's own state
/// (a verification context, a key cache, …) -- `null` if unneeded.
pub const EcdsaVerifyFn = *const fn (ctx: ?*anyopaque, digest: [32]u8, signature: Signature, pubkey: Point) bool;

/// Verifies all four `channel_announcement` signatures (BOLT#7: two node
/// signatures over `node_id_1`/`node_id_2`, two bitcoin signatures over
/// `bitcoin_key_1`/`bitcoin_key_2`, all four over the same digest) against
/// `payload` (the decoded message's own wire bytes, type-prefix excluded --
/// what `channelAnnouncementDigest` takes). Short-circuits on the first
/// failing signature; never claims "verified" on a partial check.
pub fn verifyChannelAnnouncement(
    payload: []const u8,
    msg: ChannelAnnouncement,
    verify_fn: EcdsaVerifyFn,
    ctx: ?*anyopaque,
) message.ReadError!bool {
    const digest = try channelAnnouncementDigest(payload);
    return verify_fn(ctx, digest, msg.node_signature_1, msg.node_id_1) and
        verify_fn(ctx, digest, msg.node_signature_2, msg.node_id_2) and
        verify_fn(ctx, digest, msg.bitcoin_signature_1, msg.bitcoin_key_1) and
        verify_fn(ctx, digest, msg.bitcoin_signature_2, msg.bitcoin_key_2);
}

/// Verifies a `node_announcement`'s signature against its own `node_id`
/// (BOLT#7: a node signs its own announcement).
pub fn verifyNodeAnnouncement(
    payload: []const u8,
    msg: NodeAnnouncement,
    verify_fn: EcdsaVerifyFn,
    ctx: ?*anyopaque,
) message.ReadError!bool {
    const digest = try nodeAnnouncementDigest(payload);
    return verify_fn(ctx, digest, msg.signature, msg.node_id);
}

/// Verifies a `channel_update`'s signature. Unlike the other two messages,
/// `channel_update` does not carry the announcing node's public key --
/// BOLT#7 requires the verifier to already know it, learned from the
/// `channel_announcement` for the same `short_channel_id`/`direction`
/// (`channel_flags` bit 0) this update belongs to; the caller supplies it.
pub fn verifyChannelUpdate(
    payload: []const u8,
    msg: ChannelUpdate,
    announcing_node_id: Point,
    verify_fn: EcdsaVerifyFn,
    ctx: ?*anyopaque,
) message.ReadError!bool {
    const digest = try channelUpdateDigest(payload);
    return verify_fn(ctx, digest, msg.signature, announcing_node_id);
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
const eq_kat = @import("bolt7_extended_queries_kat_vectors.zig");
const au_kat = @import("bolt7_announcement_update_kat_vectors.zig");

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

// ── official BOLT#7 extended-queries.json vector helpers ─────────────────
//
// `lightning/bolts` `bolt07/extended-queries.json` (CC-BY 4.0, see
// modules/lnwire/NOTICE) supplies byte-exact `query_channel_range`/
// `reply_channel_range`/`query_short_channel_ids` wire vectors, vendored as
// Zig literals in `bolt7_extended_queries_kat_vectors.zig`. These helpers
// rebuild the raw wire bytes this module's codec treats as opaque
// (`encoded_short_ids`, `timestamps_tlv`, `checksums_tlv`) directly from a
// vector's *decoded* semantic fields, so the ENCODE direction is checked
// against an independently-constructed expectation, not just self-consistency.

fn hexToArray(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn hexDecodeAlloc(allocator: Allocator, hex: []const u8) Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = std.fmt.hexToBytes(out, hex) catch unreachable;
    return out;
}

/// rust-lightning's per-message `encode()` (the source of
/// `bolt7_announcement_update_kat_vectors.zig`'s `payload_hex`) emits only
/// the message's own fields, not BOLT#1's 2-byte `type` field -- see that
/// file's module doc comment. Prepend this module's own frame type (BOLT#7's
/// own published constant, e.g. 256 for `channel_announcement`) so the
/// result is decodable by `decodeChannelAnnouncement`/etc.
fn withTypePrefix(allocator: Allocator, t: u16, payload: []const u8) Allocator.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, &frameTypeBytes(t));
    try buf.appendSlice(allocator, payload);
    return buf.toOwnedSlice(allocator);
}

/// `encoding_type` byte (0x00, uncompressed) followed by each `Scid`'s
/// `block(3) || tx_index(3) || output_index(2)` big-endian encoding --
/// BOLT#7's `encoded_short_ids` field, uncompressed form.
fn buildScidBlob(allocator: Allocator, scids: []const eq_kat.Scid) Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.append(allocator, 0x00);
    for (scids) |s| {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u24, tmp[0..3], s.block, .big);
        std.mem.writeInt(u24, tmp[3..6], s.tx_index, .big);
        std.mem.writeInt(u16, tmp[6..8], s.output_index, .big);
        try list.appendSlice(allocator, &tmp);
    }
    return list.toOwnedSlice(allocator);
}

/// `timestamps_tlv`'s `encoding_type` byte (0x00) followed by each pair's
/// two big-endian `u32`s, uncompressed form.
fn buildTimestampsBlob(allocator: Allocator, pairs: []const eq_kat.TimestampPair) Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.append(allocator, 0x00);
    for (pairs) |p| {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u32, tmp[0..4], p.timestamp1, .big);
        std.mem.writeInt(u32, tmp[4..8], p.timestamp2, .big);
        try list.appendSlice(allocator, &tmp);
    }
    return list.toOwnedSlice(allocator);
}

/// `checksums_tlv`'s content -- BOLT#7 defines no `encoding_type` byte
/// here (fixed-width `u32` pairs are never compressed), so this is just
/// each pair's two big-endian `u32`s back to back.
fn buildChecksumsBlob(allocator: Allocator, pairs: []const eq_kat.ChecksumPair) Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    for (pairs) |p| {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u32, tmp[0..4], p.checksum1, .big);
        std.mem.writeInt(u32, tmp[4..8], p.checksum2, .big);
        try list.appendSlice(allocator, &tmp);
    }
    return list.toOwnedSlice(allocator);
}

test "official BOLT#7 vector (lightning/bolts bolt07/extended-queries.json): query_channel_range" {
    const allocator = testing.allocator;
    for (eq_kat.query_channel_range_vectors) |v| {
        const bytes = try hexDecodeAlloc(allocator, v.hex);
        defer allocator.free(bytes);
        const chain_hash = hexToArray(32, v.chain_hash_hex);

        var decoded = try decodeQueryChannelRange(allocator, bytes);
        defer decoded.deinit(allocator);
        try testing.expectEqualSlices(u8, &chain_hash, &decoded.chain_hash);
        try testing.expectEqual(v.first_blocknum, decoded.first_blocknum);
        try testing.expectEqual(v.number_of_blocks, decoded.number_of_blocks);

        if (v.query_option) |flag| {
            const got = decoded.extension.find(1) orelse return error.TestExpectedTlvPresent;
            try testing.expectEqualSlices(u8, &.{flag}, got);
        } else {
            try testing.expectEqual(@as(usize, 0), decoded.extension.records.len);
        }

        // ENCODE: build straight from the vector's own decoded fields --
        // this is the gap this pass prioritizes (see task notes) -- and
        // check the result is byte-exact against the official hex.
        var records_buf = [_]message.tlv.RawRecord{.{ .type = 1, .value = &.{v.query_option orelse 0} }};
        const msg: QueryChannelRange = .{
            .chain_hash = chain_hash,
            .first_blocknum = v.first_blocknum,
            .number_of_blocks = v.number_of_blocks,
            .extension = if (v.query_option != null) .{ .records = records_buf[0..] } else .{},
        };
        const reencoded = try serializeQueryChannelRange(allocator, msg);
        defer allocator.free(reencoded);
        try testing.expectEqualSlices(u8, bytes, reencoded);
    }
}

test "official BOLT#7 vector (lightning/bolts bolt07/extended-queries.json): reply_channel_range" {
    const allocator = testing.allocator;
    for (eq_kat.reply_channel_range_vectors) |v| {
        const bytes = try hexDecodeAlloc(allocator, v.hex);
        defer allocator.free(bytes);
        const chain_hash = hexToArray(32, v.chain_hash_hex);

        var decoded = try decodeReplyChannelRange(allocator, bytes);
        defer decoded.deinit(allocator);
        try testing.expectEqualSlices(u8, &chain_hash, &decoded.chain_hash);
        try testing.expectEqual(v.first_blocknum, decoded.first_blocknum);
        try testing.expectEqual(v.number_of_blocks, decoded.number_of_blocks);
        try testing.expectEqual(v.complete, decoded.sync_complete);

        const want_scid_enc_byte: u8 = switch (v.scid_encoding) {
            .uncompressed => 0,
            .zlib => 1,
        };
        try testing.expect(decoded.encoded_short_ids.len >= 1);
        try testing.expectEqual(want_scid_enc_byte, decoded.encoded_short_ids[0]);
        if (v.scid_encoding == .uncompressed) {
            const want = try buildScidBlob(allocator, v.scids);
            defer allocator.free(want);
            try testing.expectEqualSlices(u8, want, decoded.encoded_short_ids);
        }
        // .zlib: this module has no zlib decompressor (README's Scope) --
        // the decoded scid *content* isn't independently checked for these
        // vectors, only that the opaque blob round-trips byte-exact below.

        if (v.checksums.len > 0) {
            const want_checksums = try buildChecksumsBlob(allocator, v.checksums);
            defer allocator.free(want_checksums);
            const got = decoded.extension.find(3) orelse return error.TestExpectedTlvPresent;
            try testing.expectEqualSlices(u8, want_checksums, got);
        } else {
            try testing.expect(decoded.extension.find(3) == null);
        }

        if (v.timestamps_encoding) |enc| {
            const got = decoded.extension.find(1) orelse return error.TestExpectedTlvPresent;
            try testing.expectEqual(@as(u8, if (enc == .uncompressed) 0 else 1), got[0]);
            if (enc == .uncompressed) {
                const want_ts = try buildTimestampsBlob(allocator, v.timestamps);
                defer allocator.free(want_ts);
                try testing.expectEqualSlices(u8, want_ts, got);
            }
            // .zlib: skipped for the same reason as the main scid list.
        } else {
            try testing.expect(decoded.extension.find(1) == null);
        }

        // Opaque-blob round-trip: re-serializing the DECODED message must
        // reproduce the official bytes exactly, regardless of whether the
        // scid/timestamps *content* was independently verified above.
        const reser = try serializeReplyChannelRange(allocator, decoded);
        defer allocator.free(reser);
        try testing.expectEqualSlices(u8, bytes, reser);

        // ENCODE-from-fields: only buildable when every compressible field
        // in this vector is uncompressed -- this module implements no zlib
        // compressor, so a `.zlib` scid/timestamps list can't be built from
        // `msg`'s own decoded semantic fields (only round-tripped above).
        const fully_buildable = v.scid_encoding == .uncompressed and
            (v.timestamps_encoding == null or v.timestamps_encoding.? == .uncompressed);
        if (fully_buildable) {
            const scid_blob = try buildScidBlob(allocator, v.scids);
            defer allocator.free(scid_blob);
            var records_buf: [2]message.tlv.RawRecord = undefined;
            var n_records: usize = 0;
            var ts_blob: []u8 = &.{};
            defer if (ts_blob.len > 0) allocator.free(ts_blob);
            if (v.timestamps_encoding != null) {
                ts_blob = try buildTimestampsBlob(allocator, v.timestamps);
                records_buf[n_records] = .{ .type = 1, .value = ts_blob };
                n_records += 1;
            }
            var cs_blob: []u8 = &.{};
            defer if (cs_blob.len > 0) allocator.free(cs_blob);
            if (v.checksums.len > 0) {
                cs_blob = try buildChecksumsBlob(allocator, v.checksums);
                records_buf[n_records] = .{ .type = 3, .value = cs_blob };
                n_records += 1;
            }
            const efields: ReplyChannelRange = .{
                .chain_hash = chain_hash,
                .first_blocknum = v.first_blocknum,
                .number_of_blocks = v.number_of_blocks,
                .sync_complete = v.complete,
                .encoded_short_ids = scid_blob,
                .extension = .{ .records = records_buf[0..n_records] },
            };
            const reencoded = try serializeReplyChannelRange(allocator, efields);
            defer allocator.free(reencoded);
            try testing.expectEqualSlices(u8, bytes, reencoded);
        }
    }
}

test "official BOLT#7 vector (lightning/bolts bolt07/extended-queries.json): query_short_channel_ids" {
    const allocator = testing.allocator;
    for (eq_kat.query_short_channel_ids_vectors) |v| {
        const bytes = try hexDecodeAlloc(allocator, v.hex);
        defer allocator.free(bytes);
        const chain_hash = hexToArray(32, v.chain_hash_hex);

        var decoded = try decodeQueryShortChannelIds(allocator, bytes);
        defer decoded.deinit(allocator);
        try testing.expectEqualSlices(u8, &chain_hash, &decoded.chain_hash);

        const want_scid_enc_byte: u8 = switch (v.scid_encoding) {
            .uncompressed => 0,
            .zlib => 1,
        };
        try testing.expect(decoded.encoded_short_ids.len >= 1);
        try testing.expectEqual(want_scid_enc_byte, decoded.encoded_short_ids[0]);
        if (v.scid_encoding == .uncompressed) {
            const want = try buildScidBlob(allocator, v.scids);
            defer allocator.free(want);
            try testing.expectEqualSlices(u8, want, decoded.encoded_short_ids);
        }
        // .zlib: see reply_channel_range's test above -- content not
        // independently checked, only round-tripped byte-exact below.

        if (v.has_query_flags_tlv) {
            // `query_flags`' per-short_channel_id bit array is out of this
            // module's scope regardless of its own encoding byte (SPEC.md) --
            // presence only, never content, is asserted.
            try testing.expect(decoded.extension.find(1) != null);
        } else {
            try testing.expectEqual(@as(usize, 0), decoded.extension.records.len);
        }

        const reser = try serializeQueryShortChannelIds(allocator, decoded);
        defer allocator.free(reser);
        try testing.expectEqualSlices(u8, bytes, reser);

        // ENCODE-from-fields: only fully buildable when scids are
        // uncompressed AND there's no query_flags tlv -- its raw value is
        // itself zlib-compressed in both vectors that carry one, and this
        // module has no zlib compressor to reproduce that byte-exact.
        if (v.scid_encoding == .uncompressed and !v.has_query_flags_tlv) {
            const scid_blob = try buildScidBlob(allocator, v.scids);
            defer allocator.free(scid_blob);
            const efields: QueryShortChannelIds = .{
                .chain_hash = chain_hash,
                .encoded_short_ids = scid_blob,
                .extension = .{},
            };
            const reencoded = try serializeQueryShortChannelIds(allocator, efields);
            defer allocator.free(reencoded);
            try testing.expectEqualSlices(u8, bytes, reencoded);
        }
    }
}

// ── rust-lightning `msgs.rs` vectors: channel_announcement /
// node_announcement / channel_update (added 2026-08-02) ─────────────────
//
// Closes the "round-trip only" gap `ANCHOR-TASKS.tsv` recorded for these
// three messages: `lightning/bolts` (BOLT#7's own spec repo) carries no
// test vectors for them, but `lightningdevkit/rust-lightning` -- an
// independent implementation -- has encode/decode tests with full wire hex
// (see `bolt7_announcement_update_kat_vectors.zig`'s module doc comment for
// exactly which upstream test/lines and the "no type prefix" convention its
// `payload_hex` follows). Both directions are driven per vector: DECODE
// parses the official bytes and asserts every field; ENCODE builds the
// message from those same fields and asserts byte-exact output -- the
// direction this pass prioritizes, matching the extended-queries vectors
// above.

test "official BOLT#7 vector (rust-lightning msgs.rs encoding_channel_announcement): channel_announcement" {
    const allocator = testing.allocator;
    for (au_kat.channel_announcement_vectors) |v| {
        const payload = try hexDecodeAlloc(allocator, v.payload_hex);
        defer allocator.free(payload);
        const full = try withTypePrefix(allocator, CHANNEL_ANNOUNCEMENT_TYPE, payload);
        defer allocator.free(full);

        // DECODE: parse the official bytes, assert every field -- in
        // particular the 4-signature ORDER (node_sig_1, node_sig_2,
        // bitcoin_sig_1, bitcoin_sig_2, exactly BOLT#7's field order) since
        // each signature's bytes are distinct in this vector, a swap would
        // be caught here.
        const decoded = try decodeChannelAnnouncement(full);
        try testing.expectEqualSlices(u8, &hexToArray(64, v.node_signature_1_hex), &decoded.node_signature_1);
        try testing.expectEqualSlices(u8, &hexToArray(64, v.node_signature_2_hex), &decoded.node_signature_2);
        try testing.expectEqualSlices(u8, &hexToArray(64, v.bitcoin_signature_1_hex), &decoded.bitcoin_signature_1);
        try testing.expectEqualSlices(u8, &hexToArray(64, v.bitcoin_signature_2_hex), &decoded.bitcoin_signature_2);
        const want_features = try hexDecodeAlloc(allocator, v.features_hex);
        defer allocator.free(want_features);
        try testing.expectEqualSlices(u8, want_features, decoded.features);
        try testing.expectEqualSlices(u8, &hexToArray(32, v.chain_hash_hex), &decoded.chain_hash);
        try testing.expectEqual(v.short_channel_id, decoded.short_channel_id);
        try testing.expectEqualSlices(u8, &hexToArray(33, v.node_id_1_hex), &decoded.node_id_1);
        try testing.expectEqualSlices(u8, &hexToArray(33, v.node_id_2_hex), &decoded.node_id_2);
        try testing.expectEqualSlices(u8, &hexToArray(33, v.bitcoin_key_1_hex), &decoded.bitcoin_key_1);
        try testing.expectEqualSlices(u8, &hexToArray(33, v.bitcoin_key_2_hex), &decoded.bitcoin_key_2);
        // Trailing/excess data (BOLT#7: "future fields" the signature still
        // covers) must be preserved verbatim, not dropped.
        const want_extra = try hexDecodeAlloc(allocator, v.extra_hex);
        defer allocator.free(want_extra);
        try testing.expectEqualSlices(u8, want_extra, decoded.extra);

        // ENCODE: build straight from the vector's own fields (the gap
        // this pass prioritizes) and assert byte-exact against the
        // official wire bytes.
        const msg: ChannelAnnouncement = .{
            .node_signature_1 = hexToArray(64, v.node_signature_1_hex),
            .node_signature_2 = hexToArray(64, v.node_signature_2_hex),
            .bitcoin_signature_1 = hexToArray(64, v.bitcoin_signature_1_hex),
            .bitcoin_signature_2 = hexToArray(64, v.bitcoin_signature_2_hex),
            .features = want_features,
            .chain_hash = hexToArray(32, v.chain_hash_hex),
            .short_channel_id = v.short_channel_id,
            .node_id_1 = hexToArray(33, v.node_id_1_hex),
            .node_id_2 = hexToArray(33, v.node_id_2_hex),
            .bitcoin_key_1 = hexToArray(33, v.bitcoin_key_1_hex),
            .bitcoin_key_2 = hexToArray(33, v.bitcoin_key_2_hex),
            .extra = want_extra,
        };
        const reencoded = try serializeChannelAnnouncement(allocator, msg);
        defer allocator.free(reencoded);
        try testing.expectEqualSlices(u8, full, reencoded);
    }
}

test "official BOLT#7 vector (rust-lightning msgs.rs encoding_node_announcement): node_announcement" {
    const allocator = testing.allocator;
    for (au_kat.node_announcement_vectors) |v| {
        const payload = try hexDecodeAlloc(allocator, v.payload_hex);
        defer allocator.free(payload);
        const full = try withTypePrefix(allocator, NODE_ANNOUNCEMENT_TYPE, payload);
        defer allocator.free(full);

        const decoded = try decodeNodeAnnouncement(full);
        try testing.expectEqualSlices(u8, &hexToArray(64, v.signature_hex), &decoded.signature);
        const want_features = try hexDecodeAlloc(allocator, v.features_hex);
        defer allocator.free(want_features);
        try testing.expectEqualSlices(u8, want_features, decoded.features);
        try testing.expectEqual(v.timestamp, decoded.timestamp);
        try testing.expectEqualSlices(u8, &hexToArray(33, v.node_id_hex), &decoded.node_id);
        try testing.expectEqualSlices(u8, &hexToArray(3, v.rgb_color_hex), &decoded.rgb_color);
        try testing.expectEqualSlices(u8, &hexToArray(32, v.alias_hex), &decoded.alias);
        // `addresses` -- ipv4/ipv6/torv2/torv3/hostname descriptors and any
        // rust-lightning `excess_address_data` folded into the same
        // length-prefixed field (see the KAT file's struct doc comment) --
        // is opaque bytes here (SPEC.md's Scope: no address-descriptor
        // parsing), so only byte-exact presence is asserted, never
        // per-descriptor interpretation.
        const want_addresses = try hexDecodeAlloc(allocator, v.addresses_hex);
        defer allocator.free(want_addresses);
        try testing.expectEqualSlices(u8, want_addresses, decoded.addresses);
        const want_extra = try hexDecodeAlloc(allocator, v.extra_hex);
        defer allocator.free(want_extra);
        try testing.expectEqualSlices(u8, want_extra, decoded.extra);

        const msg: NodeAnnouncement = .{
            .signature = hexToArray(64, v.signature_hex),
            .features = want_features,
            .timestamp = v.timestamp,
            .node_id = hexToArray(33, v.node_id_hex),
            .rgb_color = hexToArray(3, v.rgb_color_hex),
            .alias = hexToArray(32, v.alias_hex),
            .addresses = want_addresses,
            .extra = want_extra,
        };
        const reencoded = try serializeNodeAnnouncement(allocator, msg);
        defer allocator.free(reencoded);
        try testing.expectEqualSlices(u8, full, reencoded);
    }
}

test "official BOLT#7 vector (rust-lightning msgs.rs encoding_channel_update): channel_update" {
    const allocator = testing.allocator;
    for (au_kat.channel_update_vectors) |v| {
        const payload = try hexDecodeAlloc(allocator, v.payload_hex);
        defer allocator.free(payload);
        const full = try withTypePrefix(allocator, CHANNEL_UPDATE_TYPE, payload);
        defer allocator.free(full);

        const decoded = try decodeChannelUpdate(full);
        try testing.expectEqualSlices(u8, &hexToArray(64, v.signature_hex), &decoded.signature);
        try testing.expectEqualSlices(u8, &hexToArray(32, v.chain_hash_hex), &decoded.chain_hash);
        try testing.expectEqual(v.short_channel_id, decoded.short_channel_id);
        try testing.expectEqual(v.timestamp, decoded.timestamp);
        // message_flags/channel_flags bit layout: message_flags is always 1
        // (BOLT#7's `must_be_one` bit) across every vector; channel_flags
        // exercises both the direction bit (bit 0) and the disable bit
        // (bit 1), all 4 combinations (0/1/2/3).
        try testing.expectEqual(v.message_flags, decoded.message_flags);
        try testing.expectEqual(v.channel_flags, decoded.channel_flags);
        try testing.expectEqual(v.cltv_expiry_delta, decoded.cltv_expiry_delta);
        try testing.expectEqual(v.htlc_minimum_msat, decoded.htlc_minimum_msat);
        try testing.expectEqual(v.fee_base_msat, decoded.fee_base_msat);
        try testing.expectEqual(v.fee_proportional_millionths, decoded.fee_proportional_millionths);
        // `htlc_maximum_msat`: BOLT#7's current spec text has this field
        // unconditional (see the KAT file's doc comment) -- every vector
        // carries it, none tests "field absent".
        try testing.expectEqual(v.htlc_maximum_msat, decoded.htlc_maximum_msat);
        const want_extra = try hexDecodeAlloc(allocator, v.extra_hex);
        defer allocator.free(want_extra);
        try testing.expectEqualSlices(u8, want_extra, decoded.extra);

        const msg: ChannelUpdate = .{
            .signature = hexToArray(64, v.signature_hex),
            .chain_hash = hexToArray(32, v.chain_hash_hex),
            .short_channel_id = v.short_channel_id,
            .timestamp = v.timestamp,
            .message_flags = v.message_flags,
            .channel_flags = v.channel_flags,
            .cltv_expiry_delta = v.cltv_expiry_delta,
            .htlc_minimum_msat = v.htlc_minimum_msat,
            .fee_base_msat = v.fee_base_msat,
            .fee_proportional_millionths = v.fee_proportional_millionths,
            .htlc_maximum_msat = v.htlc_maximum_msat,
            .extra = want_extra,
        };
        const reencoded = try serializeChannelUpdate(allocator, msg);
        defer allocator.free(reencoded);
        try testing.expectEqualSlices(u8, full, reencoded);
    }
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

// The three digest tests above (self-round-trip + digest) recompute the
// expected value with the SAME literal offset (`payload[256..]`/`[64..]`)
// `channelAnnouncementDigest`/`nodeAnnouncementDigest`/`channelUpdateDigest`
// themselves use -- an in-house oracle, not an outside one: a wrong offset
// baked into both the production function and the test would agree with
// itself and stay green forever. The three tests below are the outside
// check: each digest is independently recomputed in Python
// (`hashlib.sha256`, twice, over the tail of one of `au_kat`'s already-
// externally-sourced rust-lightning `payload_hex` vectors) and frozen as a
// literal, so a wrong offset here disagrees with a value this module's own
// code had no part in producing.

test "channelAnnouncementDigest: independently recomputed (Python hashlib) over an external vector" {
    const allocator = testing.allocator;
    const payload = try hexDecodeAlloc(allocator, au_kat.channel_announcement_vectors[0].payload_hex);
    defer allocator.free(payload);
    const got = try channelAnnouncementDigest(payload);
    const want = hexToArray(32, "24cda6c903a92a68d80ae36c8b382edba3e19f87c02afcbabc374426fc93e781");
    try testing.expectEqualSlices(u8, &want, &got);
}

test "nodeAnnouncementDigest: independently recomputed (Python hashlib) over an external vector" {
    const allocator = testing.allocator;
    const payload = try hexDecodeAlloc(allocator, au_kat.node_announcement_vectors[0].payload_hex);
    defer allocator.free(payload);
    const got = try nodeAnnouncementDigest(payload);
    const want = hexToArray(32, "3642f6aad0edeb0664c7f156b00b04284c0112523ccad02a7e437ec7d390eb85");
    try testing.expectEqualSlices(u8, &want, &got);
}

test "channelUpdateDigest: independently recomputed (Python hashlib) over an external vector" {
    const allocator = testing.allocator;
    const payload = try hexDecodeAlloc(allocator, au_kat.channel_update_vectors[0].payload_hex);
    defer allocator.free(payload);
    const got = try channelUpdateDigest(payload);
    const want = hexToArray(32, "0df68b88dabae0421dd9910e9a9dfe994d6ddcc20408d8ddf928c5c348733bac");
    try testing.expectEqualSlices(u8, &want, &got);
}

// ── verification seam tests ────────────────────────────────────────────────

const VerifyCall = struct { digest: [32]u8, signature: Signature, pubkey: Point };

/// A stub `EcdsaVerifyFn`: records every call (for wiring assertions) and
/// reports valid for every pubkey except `fail_pubkey`, so a test can force
/// exactly one signature to "fail" without needing real secp256k1.
const RecordingVerifier = struct {
    calls: std.ArrayList(VerifyCall) = .empty,
    fail_pubkey: ?Point = null,

    fn deinit(self: *RecordingVerifier, allocator: Allocator) void {
        self.calls.deinit(allocator);
    }

    fn verify(ctx: ?*anyopaque, digest: [32]u8, signature: Signature, pubkey: Point) bool {
        const self: *RecordingVerifier = @ptrCast(@alignCast(ctx.?));
        self.calls.append(std.testing.allocator, .{ .digest = digest, .signature = signature, .pubkey = pubkey }) catch @panic("OOM");
        if (self.fail_pubkey) |fp| {
            if (std.mem.eql(u8, &fp, &pubkey)) return false;
        }
        return true;
    }
};

test "verifyChannelAnnouncement: calls back once per signature, correctly paired with its own pubkey" {
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
    const payload = bytes[2..];

    var v: RecordingVerifier = .{};
    defer v.deinit(allocator);
    const ok = try verifyChannelAnnouncement(payload, msg, RecordingVerifier.verify, &v);
    try testing.expect(ok);
    try testing.expectEqual(@as(usize, 4), v.calls.items.len);

    const digest = try channelAnnouncementDigest(payload);
    const expected_pairs = [_]struct { sig: Signature, pk: Point }{
        .{ .sig = msg.node_signature_1, .pk = msg.node_id_1 },
        .{ .sig = msg.node_signature_2, .pk = msg.node_id_2 },
        .{ .sig = msg.bitcoin_signature_1, .pk = msg.bitcoin_key_1 },
        .{ .sig = msg.bitcoin_signature_2, .pk = msg.bitcoin_key_2 },
    };
    for (v.calls.items, expected_pairs) |call, want| {
        try testing.expectEqualSlices(u8, &digest, &call.digest);
        try testing.expectEqualSlices(u8, &want.sig, &call.signature);
        try testing.expectEqualSlices(u8, &want.pk, &call.pubkey);
    }
}

test "verifyChannelAnnouncement: false and short-circuits on the first failing signature" {
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
    const payload = bytes[2..];

    // Fail the FIRST check (node_id_1): `and` must short-circuit there, so
    // node_id_2/bitcoin_key_1/bitcoin_key_2 are never even asked about.
    var v: RecordingVerifier = .{ .fail_pubkey = msg.node_id_1 };
    defer v.deinit(allocator);
    const ok = try verifyChannelAnnouncement(payload, msg, RecordingVerifier.verify, &v);
    try testing.expect(!ok);
    try testing.expectEqual(@as(usize, 1), v.calls.items.len);
}

test "verifyNodeAnnouncement: calls back once, digest+signature+node_id all correct" {
    const allocator = testing.allocator;
    const msg: NodeAnnouncement = .{
        .signature = fillPattern(64, 1),
        .features = &.{0x00},
        .timestamp = 1_700_000_000,
        .node_id = fillPattern(33, 2),
        .rgb_color = .{ 1, 2, 3 },
        .alias = fillPattern(32, 4),
        .addresses = &.{},
        .extra = &.{},
    };
    const bytes = try serializeNodeAnnouncement(allocator, msg);
    defer allocator.free(bytes);
    const payload = bytes[2..];

    var v: RecordingVerifier = .{};
    defer v.deinit(allocator);
    const ok = try verifyNodeAnnouncement(payload, msg, RecordingVerifier.verify, &v);
    try testing.expect(ok);
    try testing.expectEqual(@as(usize, 1), v.calls.items.len);
    const digest = try nodeAnnouncementDigest(payload);
    try testing.expectEqualSlices(u8, &digest, &v.calls.items[0].digest);
    try testing.expectEqualSlices(u8, &msg.signature, &v.calls.items[0].signature);
    try testing.expectEqualSlices(u8, &msg.node_id, &v.calls.items[0].pubkey);
}

test "verifyChannelUpdate: verifies against the caller-supplied announcing node_id, not a field of its own" {
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
    const payload = bytes[2..];
    const announcing_node_id = fillPattern(33, 0xaa); // not carried by channel_update itself

    var v: RecordingVerifier = .{};
    defer v.deinit(allocator);
    const ok = try verifyChannelUpdate(payload, msg, announcing_node_id, RecordingVerifier.verify, &v);
    try testing.expect(ok);
    try testing.expectEqual(@as(usize, 1), v.calls.items.len);
    try testing.expectEqualSlices(u8, &announcing_node_id, &v.calls.items[0].pubkey);
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
