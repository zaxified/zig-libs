// SPDX-License-Identifier: MIT
//! BOLT#2 channel-management messages: the core Channel Establishment v1
//! + Normal Operation + Channel Close set — `open_channel`,
//! `accept_channel`, `funding_created`, `funding_signed`,
//! `channel_ready`, `update_add_htlc`, `update_fulfill_htlc`,
//! `update_fail_htlc`, `commitment_signed`, `revoke_and_ack`,
//! `update_fee`, `shutdown`, `closing_signed` — plus (2026-10-06)
//! `update_fail_malformed_htlc` (with BOLT#2's `BADONION` receiver rule)
//! and `channel_reestablish` (with its `next_funding` /
//! `my_current_funding_locked` TLVs, length-checked).
//!
//! Deferred (see `../SPEC.md`): Interactive Transaction Construction
//! (`tx_*`), Channel Establishment v2 (`open_channel2`/`accept_channel2`),
//! Channel Splicing, Quiescence (`stfu`), `start_batch`, modern Closing
//! Negotiation (`closing_complete`/`closing_sig`) — each a self-contained
//! follow-on, not a corner cut inside a message this file implements.
//!
//! Every message's trailing `tlv_stream` is decoded generically via
//! `message.Extension` (see `message.zig`'s doc comment) into its
//! defined top-level record types; per-field internal semantics (e.g.
//! `fee_range`'s two `u64`s) are the caller's to interpret from the raw
//! record bytes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const Extension = message.Extension;
const ChannelId = message.ChannelId;
const Sha256 = message.Sha256;
const Signature = message.Signature;
const Point = message.Point;

pub const DecodeError = message.FrameError || message.tlv.StreamError;

fn readPoint(r: *Reader) message.ReadError!Point {
    return r.takeArray(33);
}
fn readSignature(r: *Reader) message.ReadError!Signature {
    return r.takeArray(64);
}

// ── open_channel (type 32) ──────────────────────────────────────────────

pub const OPEN_CHANNEL_TYPE: u16 = 32;
const open_channel_known_tlv = [_]u64{ 0, 1 }; // upfront_shutdown_script, channel_type

pub const OpenChannel = struct {
    chain_hash: message.ChainHash,
    temporary_channel_id: ChannelId,
    funding_satoshis: u64,
    push_msat: u64,
    dust_limit_satoshis: u64,
    max_htlc_value_in_flight_msat: u64,
    channel_reserve_satoshis: u64,
    htlc_minimum_msat: u64,
    feerate_per_kw: u32,
    to_self_delay: u16,
    max_accepted_htlcs: u16,
    funding_pubkey: Point,
    revocation_basepoint: Point,
    payment_basepoint: Point,
    delayed_payment_basepoint: Point,
    htlc_basepoint: Point,
    first_per_commitment_point: Point,
    channel_flags: u8,
    extension: Extension = .{},

    pub fn deinit(self: *OpenChannel, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeOpenChannel(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!OpenChannel {
    var r = try message.openFrame(bytes, OPEN_CHANNEL_TYPE);
    var m: OpenChannel = undefined;
    m.chain_hash = try r.takeArray(32);
    m.temporary_channel_id = try r.takeArray(32);
    m.funding_satoshis = try r.u64be();
    m.push_msat = try r.u64be();
    m.dust_limit_satoshis = try r.u64be();
    m.max_htlc_value_in_flight_msat = try r.u64be();
    m.channel_reserve_satoshis = try r.u64be();
    m.htlc_minimum_msat = try r.u64be();
    m.feerate_per_kw = try r.u32be();
    m.to_self_delay = try r.u16be();
    m.max_accepted_htlcs = try r.u16be();
    m.funding_pubkey = try readPoint(&r);
    m.revocation_basepoint = try readPoint(&r);
    m.payment_basepoint = try readPoint(&r);
    m.delayed_payment_basepoint = try readPoint(&r);
    m.htlc_basepoint = try readPoint(&r);
    m.first_per_commitment_point = try readPoint(&r);
    m.channel_flags = try r.byte();
    m.extension = try message.decodeExtension(allocator, r.rest(), &open_channel_known_tlv);
    return m;
}

pub fn serializeOpenChannel(allocator: Allocator, msg: OpenChannel) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, OPEN_CHANNEL_TYPE);
    try w.putBytes(allocator, &msg.chain_hash);
    try w.putBytes(allocator, &msg.temporary_channel_id);
    try w.putU64be(allocator, msg.funding_satoshis);
    try w.putU64be(allocator, msg.push_msat);
    try w.putU64be(allocator, msg.dust_limit_satoshis);
    try w.putU64be(allocator, msg.max_htlc_value_in_flight_msat);
    try w.putU64be(allocator, msg.channel_reserve_satoshis);
    try w.putU64be(allocator, msg.htlc_minimum_msat);
    try w.putU32be(allocator, msg.feerate_per_kw);
    try w.putU16be(allocator, msg.to_self_delay);
    try w.putU16be(allocator, msg.max_accepted_htlcs);
    try w.putBytes(allocator, &msg.funding_pubkey);
    try w.putBytes(allocator, &msg.revocation_basepoint);
    try w.putBytes(allocator, &msg.payment_basepoint);
    try w.putBytes(allocator, &msg.delayed_payment_basepoint);
    try w.putBytes(allocator, &msg.htlc_basepoint);
    try w.putBytes(allocator, &msg.first_per_commitment_point);
    try w.putU8(allocator, msg.channel_flags);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── accept_channel (type 33) ─────────────────────────────────────────────

pub const ACCEPT_CHANNEL_TYPE: u16 = 33;
const accept_channel_known_tlv = [_]u64{ 0, 1 };

pub const AcceptChannel = struct {
    temporary_channel_id: ChannelId,
    dust_limit_satoshis: u64,
    max_htlc_value_in_flight_msat: u64,
    channel_reserve_satoshis: u64,
    htlc_minimum_msat: u64,
    minimum_depth: u32,
    to_self_delay: u16,
    max_accepted_htlcs: u16,
    funding_pubkey: Point,
    revocation_basepoint: Point,
    payment_basepoint: Point,
    delayed_payment_basepoint: Point,
    htlc_basepoint: Point,
    first_per_commitment_point: Point,
    extension: Extension = .{},

    pub fn deinit(self: *AcceptChannel, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeAcceptChannel(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!AcceptChannel {
    var r = try message.openFrame(bytes, ACCEPT_CHANNEL_TYPE);
    var m: AcceptChannel = undefined;
    m.temporary_channel_id = try r.takeArray(32);
    m.dust_limit_satoshis = try r.u64be();
    m.max_htlc_value_in_flight_msat = try r.u64be();
    m.channel_reserve_satoshis = try r.u64be();
    m.htlc_minimum_msat = try r.u64be();
    m.minimum_depth = try r.u32be();
    m.to_self_delay = try r.u16be();
    m.max_accepted_htlcs = try r.u16be();
    m.funding_pubkey = try readPoint(&r);
    m.revocation_basepoint = try readPoint(&r);
    m.payment_basepoint = try readPoint(&r);
    m.delayed_payment_basepoint = try readPoint(&r);
    m.htlc_basepoint = try readPoint(&r);
    m.first_per_commitment_point = try readPoint(&r);
    m.extension = try message.decodeExtension(allocator, r.rest(), &accept_channel_known_tlv);
    return m;
}

pub fn serializeAcceptChannel(allocator: Allocator, msg: AcceptChannel) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, ACCEPT_CHANNEL_TYPE);
    try w.putBytes(allocator, &msg.temporary_channel_id);
    try w.putU64be(allocator, msg.dust_limit_satoshis);
    try w.putU64be(allocator, msg.max_htlc_value_in_flight_msat);
    try w.putU64be(allocator, msg.channel_reserve_satoshis);
    try w.putU64be(allocator, msg.htlc_minimum_msat);
    try w.putU32be(allocator, msg.minimum_depth);
    try w.putU16be(allocator, msg.to_self_delay);
    try w.putU16be(allocator, msg.max_accepted_htlcs);
    try w.putBytes(allocator, &msg.funding_pubkey);
    try w.putBytes(allocator, &msg.revocation_basepoint);
    try w.putBytes(allocator, &msg.payment_basepoint);
    try w.putBytes(allocator, &msg.delayed_payment_basepoint);
    try w.putBytes(allocator, &msg.htlc_basepoint);
    try w.putBytes(allocator, &msg.first_per_commitment_point);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── funding_created (type 34) — no tlv_stream ────────────────────────────

pub const FUNDING_CREATED_TYPE: u16 = 34;

pub const FundingCreated = struct {
    temporary_channel_id: ChannelId,
    funding_txid: Sha256,
    funding_output_index: u16,
    signature: Signature,

    pub fn deinit(_: *FundingCreated, _: Allocator) void {}
};

pub fn decodeFundingCreated(bytes: []const u8) message.FrameError!FundingCreated {
    var r = try message.openFrame(bytes, FUNDING_CREATED_TYPE);
    return .{
        .temporary_channel_id = try r.takeArray(32),
        .funding_txid = try r.takeArray(32),
        .funding_output_index = try r.u16be(),
        .signature = try readSignature(&r),
    };
}

pub fn serializeFundingCreated(allocator: Allocator, msg: FundingCreated) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, FUNDING_CREATED_TYPE);
    try w.putBytes(allocator, &msg.temporary_channel_id);
    try w.putBytes(allocator, &msg.funding_txid);
    try w.putU16be(allocator, msg.funding_output_index);
    try w.putBytes(allocator, &msg.signature);
    return w.toOwned(allocator);
}

// ── funding_signed (type 35) — no tlv_stream ─────────────────────────────

pub const FUNDING_SIGNED_TYPE: u16 = 35;

pub const FundingSigned = struct {
    channel_id: ChannelId,
    signature: Signature,

    pub fn deinit(_: *FundingSigned, _: Allocator) void {}
};

pub fn decodeFundingSigned(bytes: []const u8) message.FrameError!FundingSigned {
    var r = try message.openFrame(bytes, FUNDING_SIGNED_TYPE);
    return .{ .channel_id = try r.takeArray(32), .signature = try readSignature(&r) };
}

pub fn serializeFundingSigned(allocator: Allocator, msg: FundingSigned) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, FUNDING_SIGNED_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytes(allocator, &msg.signature);
    return w.toOwned(allocator);
}

// ── channel_ready (type 36) ───────────────────────────────────────────────

pub const CHANNEL_READY_TYPE: u16 = 36;
const channel_ready_known_tlv = [_]u64{1}; // short_channel_id (alias)

pub const ChannelReady = struct {
    channel_id: ChannelId,
    second_per_commitment_point: Point,
    extension: Extension = .{},

    pub fn deinit(self: *ChannelReady, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeChannelReady(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!ChannelReady {
    var r = try message.openFrame(bytes, CHANNEL_READY_TYPE);
    const channel_id = try r.takeArray(32);
    const second_per_commitment_point = try readPoint(&r);
    const extension = try message.decodeExtension(allocator, r.rest(), &channel_ready_known_tlv);
    return .{ .channel_id = channel_id, .second_per_commitment_point = second_per_commitment_point, .extension = extension };
}

pub fn serializeChannelReady(allocator: Allocator, msg: ChannelReady) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, CHANNEL_READY_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytes(allocator, &msg.second_per_commitment_point);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── update_add_htlc (type 128) ────────────────────────────────────────────

pub const UPDATE_ADD_HTLC_TYPE: u16 = 128;
pub const ONION_ROUTING_PACKET_LEN: usize = 1366;
const update_add_htlc_known_tlv = [_]u64{0}; // blinded_path

pub const UpdateAddHtlc = struct {
    channel_id: ChannelId,
    id: u64,
    amount_msat: u64,
    payment_hash: Sha256,
    cltv_expiry: u32,
    onion_routing_packet: [ONION_ROUTING_PACKET_LEN]u8,
    extension: Extension = .{},

    pub fn deinit(self: *UpdateAddHtlc, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeUpdateAddHtlc(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!UpdateAddHtlc {
    var r = try message.openFrame(bytes, UPDATE_ADD_HTLC_TYPE);
    var m: UpdateAddHtlc = undefined;
    m.channel_id = try r.takeArray(32);
    m.id = try r.u64be();
    m.amount_msat = try r.u64be();
    m.payment_hash = try r.takeArray(32);
    m.cltv_expiry = try r.u32be();
    m.onion_routing_packet = try r.takeArray(ONION_ROUTING_PACKET_LEN);
    m.extension = try message.decodeExtension(allocator, r.rest(), &update_add_htlc_known_tlv);
    return m;
}

pub fn serializeUpdateAddHtlc(allocator: Allocator, msg: UpdateAddHtlc) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    // Fixed-size fields alone are 1452 bytes (dominated by the 1366-byte
    // onion routing packet). Pre-sizing for them avoids the ~8 geometric
    // reallocs an empty-`ArrayList` start would otherwise force before the
    // first `putBytes(&msg.onion_routing_packet)` call; the (usually empty)
    // TLV extension still grows on top as needed.
    try w.list.ensureTotalCapacity(allocator, 2 + 32 + 8 + 8 + 32 + 4 + msg.onion_routing_packet.len);
    try message.putFrameType(&w, allocator, UPDATE_ADD_HTLC_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, msg.id);
    try w.putU64be(allocator, msg.amount_msat);
    try w.putBytes(allocator, &msg.payment_hash);
    try w.putU32be(allocator, msg.cltv_expiry);
    try w.putBytes(allocator, &msg.onion_routing_packet);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── update_fulfill_htlc (type 130) ────────────────────────────────────────

pub const UPDATE_FULFILL_HTLC_TYPE: u16 = 130;
const update_fulfill_htlc_known_tlv = [_]u64{1}; // attribution_data

pub const UpdateFulfillHtlc = struct {
    channel_id: ChannelId,
    id: u64,
    /// SECRET — the preimage that redeems the HTLC; whoever holds it can claim
    /// the funds. **Caller-owned** (CONVENTIONS §2.1 Z2): this struct is decoded
    /// into storage the caller supplies and keeps, and `deinit` frees only the
    /// TLV extension, so the module has no point at which it may destroy this
    /// field. `std.crypto.secureZero` it once the HTLC is settled.
    payment_preimage: [32]u8,
    extension: Extension = .{},

    pub fn deinit(self: *UpdateFulfillHtlc, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeUpdateFulfillHtlc(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!UpdateFulfillHtlc {
    var r = try message.openFrame(bytes, UPDATE_FULFILL_HTLC_TYPE);
    const channel_id = try r.takeArray(32);
    const id = try r.u64be();
    const payment_preimage = try r.takeArray(32);
    const extension = try message.decodeExtension(allocator, r.rest(), &update_fulfill_htlc_known_tlv);
    return .{ .channel_id = channel_id, .id = id, .payment_preimage = payment_preimage, .extension = extension };
}

pub fn serializeUpdateFulfillHtlc(allocator: Allocator, msg: UpdateFulfillHtlc) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, UPDATE_FULFILL_HTLC_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, msg.id);
    try w.putBytes(allocator, &msg.payment_preimage);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── update_fail_htlc (type 131) ───────────────────────────────────────────

pub const UPDATE_FAIL_HTLC_TYPE: u16 = 131;
const update_fail_htlc_known_tlv = [_]u64{1}; // attribution_data

pub const UpdateFailHtlc = struct {
    channel_id: ChannelId,
    id: u64,
    /// Borrowed slice (see `message.zig`'s module doc comment).
    reason: []const u8,
    extension: Extension = .{},

    pub fn deinit(self: *UpdateFailHtlc, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeUpdateFailHtlc(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!UpdateFailHtlc {
    var r = try message.openFrame(bytes, UPDATE_FAIL_HTLC_TYPE);
    const channel_id = try r.takeArray(32);
    const id = try r.u64be();
    const reason = try r.bytesU16();
    const extension = try message.decodeExtension(allocator, r.rest(), &update_fail_htlc_known_tlv);
    return .{ .channel_id = channel_id, .id = id, .reason = reason, .extension = extension };
}

pub fn serializeUpdateFailHtlc(allocator: Allocator, msg: UpdateFailHtlc) message.WriteError![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, UPDATE_FAIL_HTLC_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, msg.id);
    try w.putBytesU16(allocator, msg.reason);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── commitment_signed (type 132) ─────────────────────────────────────────

pub const COMMITMENT_SIGNED_TYPE: u16 = 132;
const commitment_signed_known_tlv = [_]u64{1}; // funding_txid

pub const CommitmentSigned = struct {
    channel_id: ChannelId,
    signature: Signature,
    /// Borrowed, zero-copy view of `num_htlcs` reinterpreted as
    /// `Signature`s (see `message.zig`'s module doc comment); `[64]u8`
    /// has the same layout/alignment as `u8`, so this is a plain
    /// reinterpret, no copy.
    htlc_signatures: []align(1) const Signature,
    extension: Extension = .{},

    pub fn deinit(self: *CommitmentSigned, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeCommitmentSigned(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!CommitmentSigned {
    var r = try message.openFrame(bytes, COMMITMENT_SIGNED_TYPE);
    const channel_id = try r.takeArray(32);
    const signature = try readSignature(&r);
    const num_htlcs = try r.u16be();
    const sig_bytes = try r.takeBytes(@as(u64, num_htlcs) * 64);
    const htlc_signatures = std.mem.bytesAsSlice(Signature, sig_bytes);
    const extension = try message.decodeExtension(allocator, r.rest(), &commitment_signed_known_tlv);
    return .{ .channel_id = channel_id, .signature = signature, .htlc_signatures = htlc_signatures, .extension = extension };
}

pub fn serializeCommitmentSigned(allocator: Allocator, msg: CommitmentSigned) message.WriteError![]u8 {
    // Same shape as `putBytesU16`'s: a `std.debug.assert` is not a bound in
    // ReleaseFast, and the count here is the number of HTLCs on the channel —
    // not a constant this side picks.
    if (msg.htlc_signatures.len > std.math.maxInt(u16)) return error.FieldTooLong;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, COMMITMENT_SIGNED_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytes(allocator, &msg.signature);
    try w.putU16be(allocator, @intCast(msg.htlc_signatures.len));
    try w.putBytes(allocator, std.mem.sliceAsBytes(msg.htlc_signatures));
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── revoke_and_ack (type 133) — no tlv_stream ────────────────────────────

pub const REVOKE_AND_ACK_TYPE: u16 = 133;

pub const RevokeAndAck = struct {
    channel_id: ChannelId,
    /// SECRET — the revocation secret for the now-superseded commitment; it is
    /// what lets the peer punish a revoked broadcast. **Caller-owned**
    /// (CONVENTIONS §2.1 Z2), on the same terms as
    /// `UpdateFulfillHtlc.payment_preimage`: `deinit` is deliberately a no-op
    /// here, so the caller must `std.crypto.secureZero` this field itself once
    /// the secret has been folded into its revocation store.
    per_commitment_secret: [32]u8,
    next_per_commitment_point: Point,

    pub fn deinit(_: *RevokeAndAck, _: Allocator) void {}
};

pub fn decodeRevokeAndAck(bytes: []const u8) message.FrameError!RevokeAndAck {
    var r = try message.openFrame(bytes, REVOKE_AND_ACK_TYPE);
    return .{
        .channel_id = try r.takeArray(32),
        .per_commitment_secret = try r.takeArray(32),
        .next_per_commitment_point = try readPoint(&r),
    };
}

pub fn serializeRevokeAndAck(allocator: Allocator, msg: RevokeAndAck) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, REVOKE_AND_ACK_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytes(allocator, &msg.per_commitment_secret);
    try w.putBytes(allocator, &msg.next_per_commitment_point);
    return w.toOwned(allocator);
}

// ── update_fee (type 134) — no tlv_stream ────────────────────────────────

pub const UPDATE_FEE_TYPE: u16 = 134;

pub const UpdateFee = struct {
    channel_id: ChannelId,
    feerate_per_kw: u32,

    pub fn deinit(_: *UpdateFee, _: Allocator) void {}
};

pub fn decodeUpdateFee(bytes: []const u8) message.FrameError!UpdateFee {
    var r = try message.openFrame(bytes, UPDATE_FEE_TYPE);
    return .{ .channel_id = try r.takeArray(32), .feerate_per_kw = try r.u32be() };
}

pub fn serializeUpdateFee(allocator: Allocator, msg: UpdateFee) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, UPDATE_FEE_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU32be(allocator, msg.feerate_per_kw);
    return w.toOwned(allocator);
}

// ── shutdown (type 38) — no tlv_stream ───────────────────────────────────

pub const SHUTDOWN_TYPE: u16 = 38;

pub const Shutdown = struct {
    channel_id: ChannelId,
    /// Borrowed slice (see `message.zig`'s module doc comment). No
    /// script-form validation (BOLT#2's `OP_0`/`OP_1`-`OP_16`/
    /// `OP_RETURN` allow-list) — opaque bytes, same "no Script
    /// interpretation" cut the sibling `bitcointx` module documents.
    scriptpubkey: []const u8,

    pub fn deinit(_: *Shutdown, _: Allocator) void {}
};

pub fn decodeShutdown(bytes: []const u8) message.FrameError!Shutdown {
    var r = try message.openFrame(bytes, SHUTDOWN_TYPE);
    const channel_id = try r.takeArray(32);
    const scriptpubkey = try r.bytesU16();
    return .{ .channel_id = channel_id, .scriptpubkey = scriptpubkey };
}

pub fn serializeShutdown(allocator: Allocator, msg: Shutdown) message.WriteError![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, SHUTDOWN_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytesU16(allocator, msg.scriptpubkey);
    return w.toOwned(allocator);
}

// ── closing_signed (type 39) ─────────────────────────────────────────────

pub const CLOSING_SIGNED_TYPE: u16 = 39;
const closing_signed_known_tlv = [_]u64{1}; // fee_range

pub const ClosingSigned = struct {
    channel_id: ChannelId,
    fee_satoshis: u64,
    signature: Signature,
    extension: Extension = .{},

    pub fn deinit(self: *ClosingSigned, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeClosingSigned(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!ClosingSigned {
    var r = try message.openFrame(bytes, CLOSING_SIGNED_TYPE);
    const channel_id = try r.takeArray(32);
    const fee_satoshis = try r.u64be();
    const signature = try readSignature(&r);
    const extension = try message.decodeExtension(allocator, r.rest(), &closing_signed_known_tlv);
    return .{ .channel_id = channel_id, .fee_satoshis = fee_satoshis, .signature = signature, .extension = extension };
}

pub fn serializeClosingSigned(allocator: Allocator, msg: ClosingSigned) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, CLOSING_SIGNED_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, msg.fee_satoshis);
    try w.putBytes(allocator, &msg.signature);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── update_fail_malformed_htlc (type 135) — no tlv_stream ────────────────

pub const UPDATE_FAIL_MALFORMED_HTLC_TYPE: u16 = 135;
/// BOLT#4's `BADONION` failure-code flag: "unparsable onion encrypted by
/// sending peer". BOLT#2: a receiver of `update_fail_malformed_htlc` whose
/// `failure_code` lacks it "MUST send a `warning` and close the connection,
/// or send an `error` and fail the channel".
pub const BADONION: u16 = 0x8000;

pub const MalformedError = error{
    /// `failure_code` does not carry the `BADONION` bit (BOLT#2 MUST-fail).
    BadOnionBitNotSet,
};

pub const UpdateFailMalformedHtlc = struct {
    channel_id: ChannelId,
    id: u64,
    sha256_of_onion: Sha256,
    failure_code: u16,

    pub fn deinit(_: *UpdateFailMalformedHtlc, _: Allocator) void {}
};

/// Decodes `update_fail_malformed_htlc` and enforces BOLT#2's receiver rule
/// on `failure_code`: without the `BADONION` bit the message is refused with
/// `error.BadOnionBitNotSet` — fail-closed here rather than left to the
/// caller, because accepting it means relaying a non-onion failure code
/// upstream as if this hop had failed to parse the onion. Like every other
/// message without a `tlv_stream`, bytes after `failure_code` are ignored
/// (BOLT#1: a receiver "MAY ignore the `extension`").
pub fn decodeUpdateFailMalformedHtlc(bytes: []const u8) (message.FrameError || MalformedError)!UpdateFailMalformedHtlc {
    const m = try decodeUpdateFailMalformedHtlcLayout(bytes);
    if (m.failure_code & BADONION == 0) return error.BadOnionBitNotSet;
    return m;
}

/// The same `BADONION` rule on the sending side: a malformed-onion failure
/// code without the bit is a message the peer is required to fail the
/// channel over, so it is refused before it reaches the wire.
pub fn serializeUpdateFailMalformedHtlc(allocator: Allocator, msg: UpdateFailMalformedHtlc) (Allocator.Error || MalformedError)![]u8 {
    if (msg.failure_code & BADONION == 0) return error.BadOnionBitNotSet;
    return serializeUpdateFailMalformedHtlcLayout(allocator, msg);
}

/// Wire layout only, no `BADONION` rule. Private: it exists so the tests can
/// read rust-lightning's vector, whose `failure_code` is 255 (no `BADONION`
/// bit), field by field and byte-exact both ways.
fn decodeUpdateFailMalformedHtlcLayout(bytes: []const u8) message.FrameError!UpdateFailMalformedHtlc {
    var r = try message.openFrame(bytes, UPDATE_FAIL_MALFORMED_HTLC_TYPE);
    return .{
        .channel_id = try r.takeArray(32),
        .id = try r.u64be(),
        .sha256_of_onion = try r.takeArray(32),
        .failure_code = try r.u16be(),
    };
}

fn serializeUpdateFailMalformedHtlcLayout(allocator: Allocator, msg: UpdateFailMalformedHtlc) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, UPDATE_FAIL_MALFORMED_HTLC_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, msg.id);
    try w.putBytes(allocator, &msg.sha256_of_onion);
    try w.putU16be(allocator, msg.failure_code);
    return w.toOwned(allocator);
}

// ── channel_reestablish (type 136) ────────────────────────────────────────

pub const CHANNEL_REESTABLISH_TYPE: u16 = 136;
/// `channel_reestablish_tlvs` TLV types (BOLT#2, `lightning/bolts` master).
pub const REESTABLISH_TLV_NEXT_FUNDING: u64 = 1;
pub const REESTABLISH_TLV_MY_CURRENT_FUNDING_LOCKED: u64 = 5;
const channel_reestablish_known_tlv = [_]u64{ REESTABLISH_TLV_NEXT_FUNDING, REESTABLISH_TLV_MY_CURRENT_FUNDING_LOCKED };

/// The value both `channel_reestablish` TLVs carry: a funding txid
/// (`sha256`, wire byte order — not reversed for display) and a
/// `retransmit_flags` bitfield. Exactly 33 octets on the wire.
pub const FundingTxidFlags = struct {
    txid: Sha256,
    retransmit_flags: u8,

    pub const wire_len: usize = 33;

    /// The 33-octet TLV value, for building a `channel_reestablish`'s
    /// `extension.records` entry.
    pub fn toBytes(self: FundingTxidFlags) [wire_len]u8 {
        var out: [wire_len]u8 = undefined;
        @memcpy(out[0..32], &self.txid);
        out[32] = self.retransmit_flags;
        return out;
    }

    fn fromBytes(v: []const u8) FundingTxidFlags {
        return .{ .txid = v[0..32].*, .retransmit_flags = v[32] };
    }
};

pub const TlvLengthError = error{
    /// A KNOWN TLV record's length is not the one its encoding requires
    /// (BOLT#1: "if `length` is not exactly equal to that required for the
    /// known encoding for `type`: MUST fail to parse the `tlv_stream`").
    InvalidTlvLength,
};

pub const ChannelReestablish = struct {
    channel_id: ChannelId,
    /// BOLT#2's 48-bit counter, carried in a `u64` (no range check: the spec
    /// defines no receiver rule for the high 16 bits).
    next_commitment_number: u64,
    next_revocation_number: u64,
    /// SECRET — the last per-commitment secret received from the peer, echoed
    /// back so it can prove (or detect) data loss. **Caller-owned**
    /// (CONVENTIONS §2.1 Z2), on the same terms as
    /// `RevokeAndAck.per_commitment_secret`: `deinit` frees only the TLV
    /// extension, so `std.crypto.secureZero` this field once it is checked.
    your_last_per_commitment_secret: [32]u8,
    my_current_per_commitment_point: Point,
    extension: Extension = .{},

    pub fn deinit(self: *ChannelReestablish, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    /// `next_funding` (TLV 1), if present. Its length was checked at decode.
    pub fn nextFunding(self: ChannelReestablish) ?FundingTxidFlags {
        const v = self.extension.find(REESTABLISH_TLV_NEXT_FUNDING) orelse return null;
        if (v.len != FundingTxidFlags.wire_len) return null;
        return FundingTxidFlags.fromBytes(v);
    }

    /// `my_current_funding_locked` (TLV 5), if present.
    pub fn myCurrentFundingLocked(self: ChannelReestablish) ?FundingTxidFlags {
        const v = self.extension.find(REESTABLISH_TLV_MY_CURRENT_FUNDING_LOCKED) orelse return null;
        if (v.len != FundingTxidFlags.wire_len) return null;
        return FundingTxidFlags.fromBytes(v);
    }
};

fn checkReestablishTlvLengths(ext: Extension) TlvLengthError!void {
    for (ext.records) |rec| {
        if (rec.value.len != FundingTxidFlags.wire_len) return error.InvalidTlvLength;
    }
}

pub fn decodeChannelReestablish(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!ChannelReestablish {
    var r = try message.openFrame(bytes, CHANNEL_REESTABLISH_TYPE);
    var m: ChannelReestablish = undefined;
    m.channel_id = try r.takeArray(32);
    m.next_commitment_number = try r.u64be();
    m.next_revocation_number = try r.u64be();
    m.your_last_per_commitment_secret = try r.takeArray(32);
    m.my_current_per_commitment_point = try readPoint(&r);
    m.extension = try message.decodeExtension(allocator, r.rest(), &channel_reestablish_known_tlv);
    errdefer m.extension.deinit(allocator);
    // Both known records are `sha256 || byte`; any other length is a
    // stream BOLT#1 says MUST fail, not a record to hand back raw.
    try checkReestablishTlvLengths(m.extension);
    return m;
}

/// Refuses (`error.InvalidTlvLength`) to emit a known TLV record of the
/// wrong length — the peer would be required to fail the stream. Records
/// are written in the order given; build them in increasing type order.
pub fn serializeChannelReestablish(allocator: Allocator, msg: ChannelReestablish) (Allocator.Error || TlvLengthError)![]u8 {
    for (msg.extension.records) |rec| {
        const known = rec.type == REESTABLISH_TLV_NEXT_FUNDING or rec.type == REESTABLISH_TLV_MY_CURRENT_FUNDING_LOCKED;
        if (known and rec.value.len != FundingTxidFlags.wire_len) return error.InvalidTlvLength;
    }
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, CHANNEL_REESTABLISH_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, msg.next_commitment_number);
    try w.putU64be(allocator, msg.next_revocation_number);
    try w.putBytes(allocator, &msg.your_last_per_commitment_secret);
    try w.putBytes(allocator, &msg.my_current_per_commitment_point);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const testkit = @import("testkit");

fn fillPattern(comptime n: usize, seed: u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = seed +% @as(u8, @truncate(i));
    return out;
}

test "open_channel: round-trip with no extension" {
    const allocator = testing.allocator;
    const msg: OpenChannel = .{
        .chain_hash = fillPattern(32, 1),
        .temporary_channel_id = fillPattern(32, 2),
        .funding_satoshis = 100_000,
        .push_msat = 0,
        .dust_limit_satoshis = 354,
        .max_htlc_value_in_flight_msat = 1_000_000_000,
        .channel_reserve_satoshis = 1000,
        .htlc_minimum_msat = 1,
        .feerate_per_kw = 253,
        .to_self_delay = 144,
        .max_accepted_htlcs = 483,
        .funding_pubkey = fillPattern(33, 3),
        .revocation_basepoint = fillPattern(33, 4),
        .payment_basepoint = fillPattern(33, 5),
        .delayed_payment_basepoint = fillPattern(33, 6),
        .htlc_basepoint = fillPattern(33, 7),
        .first_per_commitment_point = fillPattern(33, 8),
        .channel_flags = 1,
    };
    const bytes = try serializeOpenChannel(allocator, msg);
    defer allocator.free(bytes);
    var decoded = try decodeOpenChannel(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqualSlices(u8, &msg.chain_hash, &decoded.chain_hash);
    try testing.expectEqual(msg.funding_satoshis, decoded.funding_satoshis);
    try testing.expectEqual(msg.channel_flags, decoded.channel_flags);
    try testing.expectEqualSlices(u8, &msg.first_per_commitment_point, &decoded.first_per_commitment_point);
    try testing.expectEqual(@as(usize, 0), decoded.extension.records.len);

    // re-serializing the decoded message reproduces the exact same bytes
    const reser = try serializeOpenChannel(allocator, decoded);
    defer allocator.free(reser);
    try testing.expectEqualSlices(u8, bytes, reser);
}

test "open_channel: round-trip with upfront_shutdown_script + channel_type TLVs" {
    const allocator = testing.allocator;
    var msg: OpenChannel = .{
        .chain_hash = fillPattern(32, 1),
        .temporary_channel_id = fillPattern(32, 2),
        .funding_satoshis = 1,
        .push_msat = 0,
        .dust_limit_satoshis = 354,
        .max_htlc_value_in_flight_msat = 1,
        .channel_reserve_satoshis = 1,
        .htlc_minimum_msat = 1,
        .feerate_per_kw = 1,
        .to_self_delay = 1,
        .max_accepted_htlcs = 1,
        .funding_pubkey = fillPattern(33, 3),
        .revocation_basepoint = fillPattern(33, 4),
        .payment_basepoint = fillPattern(33, 5),
        .delayed_payment_basepoint = fillPattern(33, 6),
        .htlc_basepoint = fillPattern(33, 7),
        .first_per_commitment_point = fillPattern(33, 8),
        .channel_flags = 0,
        .extension = .{
            .records = @constCast(&[_]message.tlv.RawRecord{
                .{ .type = 0, .value = &.{} }, // zero-length upfront_shutdown_script
                .{ .type = 1, .value = &.{0x08} }, // channel_type bitmap
            }),
        },
    };
    const bytes = try serializeOpenChannel(allocator, msg);
    defer allocator.free(bytes);
    _ = &msg;

    var decoded = try decodeOpenChannel(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), decoded.extension.records.len);
    try testing.expectEqualSlices(u8, &.{}, decoded.extension.find(0).?);
    try testing.expectEqualSlices(u8, &.{0x08}, decoded.extension.find(1).?);
}

test "hostile: open_channel truncated before the trailing point fields fails closed" {
    const allocator = testing.allocator;
    // A byte-exact, otherwise-well-formed prefix, cut off partway through
    // funding_pubkey (33 bytes -- only 10 supplied).
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &.{ 0x00, OPEN_CHANNEL_TYPE });
    try buf.appendSlice(allocator, &fillPattern(32, 1)); // chain_hash
    try buf.appendSlice(allocator, &fillPattern(32, 2)); // temporary_channel_id
    try buf.appendSlice(allocator, &(([_]u8{0} ** 8) ** 6)); // 6 * u64
    try buf.appendSlice(allocator, &([_]u8{0} ** 4)); // feerate_per_kw
    try buf.appendSlice(allocator, &([_]u8{0} ** 2)); // to_self_delay
    try buf.appendSlice(allocator, &([_]u8{0} ** 2)); // max_accepted_htlcs
    try buf.appendSlice(allocator, &([_]u8{0xaa} ** 10)); // truncated funding_pubkey
    try testing.expectError(error.Truncated, decodeOpenChannel(allocator, buf.items));
}

test "accept_channel: round-trip" {
    const allocator = testing.allocator;
    const msg: AcceptChannel = .{
        .temporary_channel_id = fillPattern(32, 1),
        .dust_limit_satoshis = 354,
        .max_htlc_value_in_flight_msat = 1,
        .channel_reserve_satoshis = 1,
        .htlc_minimum_msat = 1,
        .minimum_depth = 3,
        .to_self_delay = 144,
        .max_accepted_htlcs = 483,
        .funding_pubkey = fillPattern(33, 2),
        .revocation_basepoint = fillPattern(33, 3),
        .payment_basepoint = fillPattern(33, 4),
        .delayed_payment_basepoint = fillPattern(33, 5),
        .htlc_basepoint = fillPattern(33, 6),
        .first_per_commitment_point = fillPattern(33, 7),
    };
    const bytes = try serializeAcceptChannel(allocator, msg);
    defer allocator.free(bytes);
    var decoded = try decodeAcceptChannel(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(msg.minimum_depth, decoded.minimum_depth);
    try testing.expectEqualSlices(u8, &msg.temporary_channel_id, &decoded.temporary_channel_id);
}

test "funding_created / funding_signed: round-trip" {
    const allocator = testing.allocator;
    const fc: FundingCreated = .{
        .temporary_channel_id = fillPattern(32, 1),
        .funding_txid = fillPattern(32, 2),
        .funding_output_index = 7,
        .signature = fillPattern(64, 3),
    };
    const fc_bytes = try serializeFundingCreated(allocator, fc);
    defer allocator.free(fc_bytes);
    const fc_decoded = try decodeFundingCreated(fc_bytes);
    try testing.expectEqual(fc.funding_output_index, fc_decoded.funding_output_index);
    try testing.expectEqualSlices(u8, &fc.signature, &fc_decoded.signature);

    const fs: FundingSigned = .{ .channel_id = fillPattern(32, 4), .signature = fillPattern(64, 5) };
    const fs_bytes = try serializeFundingSigned(allocator, fs);
    defer allocator.free(fs_bytes);
    const fs_decoded = try decodeFundingSigned(fs_bytes);
    try testing.expectEqualSlices(u8, &fs.channel_id, &fs_decoded.channel_id);
}

test "hostile: funding_signed truncated mid-signature fails closed" {
    var bytes: [2 + 32 + 10]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], FUNDING_SIGNED_TYPE, .big);
    @memset(bytes[2..34], 0);
    @memset(bytes[34..44], 0xaa); // only 10 of 64 signature bytes
    try testing.expectError(error.Truncated, decodeFundingSigned(&bytes));
}

test "channel_ready: round-trip with short_channel_id alias TLV" {
    const allocator = testing.allocator;
    var scid_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &scid_bytes, 0x1122_33_4455, .big);
    var msg: ChannelReady = .{
        .channel_id = fillPattern(32, 1),
        .second_per_commitment_point = fillPattern(33, 2),
        .extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{.{ .type = 1, .value = &scid_bytes }}) },
    };
    const bytes = try serializeChannelReady(allocator, msg);
    defer allocator.free(bytes);
    _ = &msg;
    var decoded = try decodeChannelReady(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqualSlices(u8, &scid_bytes, decoded.extension.find(1).?);
}

test "update_add_htlc: round-trip with a full-size onion_routing_packet" {
    const allocator = testing.allocator;
    var msg: UpdateAddHtlc = .{
        .channel_id = fillPattern(32, 1),
        .id = 0,
        .amount_msat = 1000,
        .payment_hash = fillPattern(32, 2),
        .cltv_expiry = 500_000,
        .onion_routing_packet = undefined,
    };
    for (&msg.onion_routing_packet, 0..) |*b, i| b.* = @truncate(i);
    const bytes = try serializeUpdateAddHtlc(allocator, msg);
    defer allocator.free(bytes);
    var decoded = try decodeUpdateAddHtlc(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqualSlices(u8, &msg.onion_routing_packet, &decoded.onion_routing_packet);
    try testing.expectEqual(msg.cltv_expiry, decoded.cltv_expiry);
}

test "hostile: update_add_htlc with a truncated onion_routing_packet fails closed" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &.{ 0x00, UPDATE_ADD_HTLC_TYPE });
    try buf.appendSlice(allocator, &fillPattern(32, 1)); // channel_id
    try buf.appendSlice(allocator, &([_]u8{0} ** 8)); // id
    try buf.appendSlice(allocator, &([_]u8{0} ** 8)); // amount_msat
    try buf.appendSlice(allocator, &fillPattern(32, 2)); // payment_hash
    try buf.appendSlice(allocator, &([_]u8{0} ** 4)); // cltv_expiry
    try buf.appendSlice(allocator, &([_]u8{0xff} ** 100)); // only 100 of 1366 onion bytes
    try testing.expectError(error.Truncated, decodeUpdateAddHtlc(allocator, buf.items));
}

test "update_fulfill_htlc / update_fail_htlc: round-trip" {
    const allocator = testing.allocator;
    const fulfill: UpdateFulfillHtlc = .{
        .channel_id = fillPattern(32, 1),
        .id = 5,
        .payment_preimage = fillPattern(32, 2),
    };
    const fulfill_bytes = try serializeUpdateFulfillHtlc(allocator, fulfill);
    defer allocator.free(fulfill_bytes);
    var fulfill_decoded = try decodeUpdateFulfillHtlc(allocator, fulfill_bytes);
    defer fulfill_decoded.deinit(allocator);
    try testing.expectEqualSlices(u8, &fulfill.payment_preimage, &fulfill_decoded.payment_preimage);

    const fail: UpdateFailHtlc = .{ .channel_id = fillPattern(32, 3), .id = 6, .reason = "enc-reason" };
    const fail_bytes = try serializeUpdateFailHtlc(allocator, fail);
    defer allocator.free(fail_bytes);
    var fail_decoded = try decodeUpdateFailHtlc(allocator, fail_bytes);
    defer fail_decoded.deinit(allocator);
    try testing.expectEqualSlices(u8, "enc-reason", fail_decoded.reason);
}

test "hostile: update_fail_htlc with a reason length prefix exceeding remaining bytes fails closed" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &.{ 0x00, UPDATE_FAIL_HTLC_TYPE });
    try buf.appendSlice(allocator, &fillPattern(32, 1));
    try buf.appendSlice(allocator, &([_]u8{0} ** 8));
    try buf.appendSlice(allocator, &.{ 0xff, 0xff }); // reason len = 65535, nothing follows
    try testing.expectError(error.Truncated, decodeUpdateFailHtlc(allocator, buf.items));
}

test "commitment_signed: round-trip with multiple htlc_signatures + funding_txid TLV" {
    const allocator = testing.allocator;
    const sigs = [_]Signature{ fillPattern(64, 10), fillPattern(64, 20), fillPattern(64, 30) };
    var funding_txid = fillPattern(32, 99);
    var msg: CommitmentSigned = .{
        .channel_id = fillPattern(32, 1),
        .signature = fillPattern(64, 2),
        .htlc_signatures = &sigs,
        .extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{.{ .type = 1, .value = &funding_txid }}) },
    };
    const bytes = try serializeCommitmentSigned(allocator, msg);
    defer allocator.free(bytes);
    _ = &msg;
    _ = &funding_txid;

    var decoded = try decodeCommitmentSigned(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(@as(usize, 3), decoded.htlc_signatures.len);
    for (sigs, decoded.htlc_signatures) |want, got| try testing.expectEqualSlices(u8, &want, &got);
    try testing.expectEqualSlices(u8, &funding_txid, decoded.extension.find(1).?);
}

test "commitment_signed: 65536 htlc_signatures is FieldTooLong, not a truncated u16 count" {
    // Mutation run 2026-10-05: the guard's edge was unpinned.
    const allocator = testing.allocator;
    const sigs = try allocator.alloc(Signature, std.math.maxInt(u16) + 1);
    defer allocator.free(sigs);
    const msg: CommitmentSigned = .{ .channel_id = fillPattern(32, 1), .signature = fillPattern(64, 2), .htlc_signatures = sigs };
    try testing.expectError(error.FieldTooLong, serializeCommitmentSigned(allocator, msg));
}

test "commitment_signed: round-trip with zero htlc_signatures" {
    const allocator = testing.allocator;
    const msg: CommitmentSigned = .{
        .channel_id = fillPattern(32, 1),
        .signature = fillPattern(64, 2),
        .htlc_signatures = &.{},
    };
    const bytes = try serializeCommitmentSigned(allocator, msg);
    defer allocator.free(bytes);
    var decoded = try decodeCommitmentSigned(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), decoded.htlc_signatures.len);
}

test "hostile: commitment_signed with num_htlcs claiming far more signatures than remain fails closed (no OOM)" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &.{ 0x00, COMMITMENT_SIGNED_TYPE });
    try buf.appendSlice(allocator, &fillPattern(32, 1));
    try buf.appendSlice(allocator, &fillPattern(64, 2));
    try buf.appendSlice(allocator, &.{ 0xff, 0xff }); // num_htlcs = 65535 -> needs 4194240 bytes, none follow
    try testing.expectError(error.Truncated, decodeCommitmentSigned(allocator, buf.items));
}

test "revoke_and_ack / update_fee / shutdown / closing_signed: round-trip" {
    const allocator = testing.allocator;

    const rev: RevokeAndAck = .{
        .channel_id = fillPattern(32, 1),
        .per_commitment_secret = fillPattern(32, 2),
        .next_per_commitment_point = fillPattern(33, 3),
    };
    const rev_bytes = try serializeRevokeAndAck(allocator, rev);
    defer allocator.free(rev_bytes);
    const rev_decoded = try decodeRevokeAndAck(rev_bytes);
    try testing.expectEqualSlices(u8, &rev.per_commitment_secret, &rev_decoded.per_commitment_secret);

    const fee: UpdateFee = .{ .channel_id = fillPattern(32, 4), .feerate_per_kw = 2000 };
    const fee_bytes = try serializeUpdateFee(allocator, fee);
    defer allocator.free(fee_bytes);
    const fee_decoded = try decodeUpdateFee(fee_bytes);
    try testing.expectEqual(fee.feerate_per_kw, fee_decoded.feerate_per_kw);

    const sd: Shutdown = .{ .channel_id = fillPattern(32, 5), .scriptpubkey = &([_]u8{ 0x00, 0x14 } ++ [_]u8{0xaa} ** 20) };
    const sd_bytes = try serializeShutdown(allocator, sd);
    defer allocator.free(sd_bytes);
    const sd_decoded = try decodeShutdown(sd_bytes);
    try testing.expectEqualSlices(u8, sd.scriptpubkey, sd_decoded.scriptpubkey);

    var fee_range: [16]u8 = undefined;
    std.mem.writeInt(u64, fee_range[0..8], 100, .big);
    std.mem.writeInt(u64, fee_range[8..16], 500, .big);
    var cs: ClosingSigned = .{
        .channel_id = fillPattern(32, 6),
        .fee_satoshis = 300,
        .signature = fillPattern(64, 7),
        .extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{.{ .type = 1, .value = &fee_range }}) },
    };
    const cs_bytes = try serializeClosingSigned(allocator, cs);
    defer allocator.free(cs_bytes);
    _ = &cs;
    _ = &fee_range;
    var cs_decoded = try decodeClosingSigned(allocator, cs_bytes);
    defer cs_decoded.deinit(allocator);
    try testing.expectEqual(@as(u64, 300), cs_decoded.fee_satoshis);
    try testing.expectEqualSlices(u8, &fee_range, cs_decoded.extension.find(1).?);
}

test "hostile: shutdown with a scriptpubkey length prefix exceeding remaining bytes fails closed" {
    var bytes: [2 + 32 + 2]u8 = undefined;
    std.mem.writeInt(u16, bytes[0..2], SHUTDOWN_TYPE, .big);
    @memset(bytes[2..34], 0);
    std.mem.writeInt(u16, bytes[34..36], 1000, .big); // declared len, nothing follows
    try testing.expectError(error.Truncated, decodeShutdown(&bytes));
}

test "hostile: any message decoder rejects the wrong 2-byte type" {
    const bytes = [_]u8{ 0x00, ACCEPT_CHANNEL_TYPE };
    try testing.expectError(error.WrongType, decodeFundingSigned(&bytes));
}

// ── fuzz: decodeOpenChannel never panics on arbitrary attacker bytes ──────
//
// `open_channel` is the first message a channel-establishment peer sends
// off an untrusted transport -- and the richest BOLT#2 shape in this
// file: 17 fixed fields (six `u64`s, a `u32`, two `u16`s, six 33-byte
// points, a byte) followed by the generic TLV extension every other
// decoder in this file also ends with (already exercised standalone by
// `message.zig`/`tlv.zig`'s own fuzz harnesses). Representative of the
// whole "many fixed fields + trailing tlv_stream" BOLT#2 family this file
// implements (`accept_channel`/`channel_ready`/`update_add_htlc`/etc. all
// share the same `Reader`-then-`decodeExtension` shape).
/// `open_channel` messages, in the format `Smith.slice` reads (see
/// `testkit.fuzz`).
///
/// ⭐ Built at run time by this file's own `serializeOpenChannel`. A BOLT#2
/// `open_channel` is 321 octets of fixed fields — a 2-octet type, two 32-octet
/// hashes, six u64s, a u32 and two u16s, then SIX 33-octet curve points —
/// before the trailing `tlv_stream` even starts. Nothing shorter than that
/// reaches `channel_flags`, and no hand-written literal is reviewable at that
/// length, so the encoder writes them and the refusals are cut from a real one.
const OpenChannelCorpus = struct {
    store: [10 * (4 + 400)]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *OpenChannelCorpus, bytes: []const u8) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], bytes);
        self.entries[self.n] = head;
        self.used += head.len;
        self.n += 1;
    }

    fn base() OpenChannel {
        return .{
            .chain_hash = fillPattern(32, 1),
            .temporary_channel_id = fillPattern(32, 2),
            .funding_satoshis = 100_000,
            .push_msat = 0,
            .dust_limit_satoshis = 354,
            .max_htlc_value_in_flight_msat = 1_000_000_000,
            .channel_reserve_satoshis = 1000,
            .htlc_minimum_msat = 1,
            .feerate_per_kw = 253,
            .to_self_delay = 144,
            .max_accepted_htlcs = 483,
            .funding_pubkey = fillPattern(33, 3),
            .revocation_basepoint = fillPattern(33, 4),
            .payment_basepoint = fillPattern(33, 5),
            .delayed_payment_basepoint = fillPattern(33, 6),
            .htlc_basepoint = fillPattern(33, 7),
            .first_per_commitment_point = fillPattern(33, 8),
            .channel_flags = 1,
        };
    }

    fn build(self: *OpenChannelCorpus, allocator: Allocator) ![]const []const u8 {
        // No extension: the shortest message the decoder accepts.
        const plain = try serializeOpenChannel(allocator, base());
        defer allocator.free(plain);
        self.push(plain);

        // With the two TLVs a real peer sends: a zero-length
        // upfront_shutdown_script and a channel_type bitmap.
        var with_tlv = base();
        with_tlv.extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{
            .{ .type = 0, .value = &.{} },
            .{ .type = 1, .value = &.{0x08} },
        }) };
        const tlv_bytes = try serializeOpenChannel(allocator, with_tlv);
        defer allocator.free(tlv_bytes);
        self.push(tlv_bytes);

        // An UNKNOWN ODD TLV type, which BOLT#1's "it's ok to be odd" rule
        // says must be tolerated. ⚠ It is tolerated by being DISCARDED, so
        // this seed decodes and contributes no record — which is why the
        // guard below pins 2 records over three accepted messages rather than
        // the 3 a reader would guess.
        var odd = base();
        odd.extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{
            .{ .type = 255, .value = &.{ 0xAA, 0xBB, 0xCC } },
        }) };
        const odd_bytes = try serializeOpenChannel(allocator, odd);
        defer allocator.free(odd_bytes);
        self.push(odd_bytes);

        // The mirror: an unknown EVEN type, which the same rule says must be
        // refused (`UnknownEvenType`).
        var even = base();
        even.extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{
            .{ .type = 254, .value = &.{0x01} },
        }) };
        const even_bytes = try serializeOpenChannel(allocator, even);
        defer allocator.free(even_bytes);
        self.push(even_bytes);

        // ── refusals, each cut or bent from the message above ───────────────
        self.push(plain[0 .. plain.len - 1]); // Truncated: one octet short
        self.push(plain[0..200]); // Truncated: partway through the points
        self.push(plain[0..2]); // Truncated: the type frame and nothing else
        {
            // WrongType: the same 321 octets under another message's type.
            var wrong: [400]u8 = undefined;
            @memcpy(wrong[0..plain.len], plain);
            std.mem.writeInt(u16, wrong[0..2], OPEN_CHANNEL_TYPE + 1, .big);
            self.push(wrong[0..plain.len]);
        }
        {
            // A trailing tlv_stream whose record length runs past the end.
            var overrun: [400]u8 = undefined;
            @memcpy(overrun[0..plain.len], plain);
            overrun[plain.len] = 0x02; // type 2
            overrun[plain.len + 1] = 0x7f; // length 127, with nothing behind it
            self.push(overrun[0 .. plain.len + 2]);
        }
        return self.entries[0..self.n];
    }
};

test "fuzz: decodeOpenChannel never panics on arbitrary bytes" {
    var corpus: OpenChannelCorpus = .{};
    try testing.fuzz({}, fuzzDecodeOpenChannel, .{ .corpus = try corpus.build(testing.allocator) });
}

fn fuzzDecodeOpenChannel(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [400]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 for every seed and `decodeOpenChannel` was handed
    // `buf[0..0]`, which fails on the two-octet type frame. The "field reader
    // chain" the comment below claimed to reach was never entered.
    //
    // ⛔ And the line that forced `OPEN_CHANNEL_TYPE` into `buf[0..2]` was
    // stamping a type into a buffer the decoder never saw one octet of. It is
    // gone: a corpus of real messages carries its own type, and a seed that
    // does not is the `WrongType` case, which is worth having.
    // Measured 2026-09-07 over the corpus above: **0 of 9 seeds non-empty and
    // 0 decoded before, 9 of 9 non-empty and 3 decoded after.**
    const len: usize = smith.slice(&buf);

    var m = decodeOpenChannel(allocator, buf[0..len]) catch return;
    defer m.deinit(allocator);
}

test "corpus: every open_channel seed reaches the decoder, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the 400-octet buffer — `Smith.slice`
    // reads that back as the EMPTY seed, silently, and an `open_channel` is 321
    // octets before its extension, so that ceiling is close. `tlv_records` is
    // the second number: the trailing `tlv_stream` is the half of this message
    // that is variable-length and therefore attacker-shaped, and `decoded`
    // alone would count a corpus of extension-less messages as complete.
    var corpus: OpenChannelCorpus = .{};
    const allocator = testing.allocator;
    const entries = try corpus.build(allocator);
    var nonempty: usize = 0;
    var decoded: usize = 0;
    var tlv_records: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [400]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var m = decodeOpenChannel(allocator, buf[0..len]) catch continue;
        defer m.deinit(allocator);
        decoded += 1;
        tlv_records += m.extension.records.len;
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 3), decoded);
    try testing.expectEqual(@as(usize, 2), tlv_records);
}

// ── channel_reestablish / update_fail_malformed_htlc (added 2026-10-06) ──

const rm_kat = @import("bolt2_reestablish_malformed_kat_vectors.zig");

fn hexArray(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// `payload_hex` behind this module's own 2-octet frame type.
fn framedHex(allocator: Allocator, msg_type: u16, payload_hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, 2 + payload_hex.len / 2);
    errdefer allocator.free(out);
    std.mem.writeInt(u16, out[0..2], msg_type, .big);
    _ = try std.fmt.hexToBytes(out[2..], payload_hex);
    return out;
}

test "official vector (rust-lightning msgs.rs encoding_channel_reestablish*): channel_reestablish, both directions" {
    const allocator = testing.allocator;
    for (rm_kat.channel_reestablish_vectors) |v| {
        errdefer std.debug.print("channel_reestablish vector: {s}\n", .{v.description});
        const full = try framedHex(allocator, CHANNEL_REESTABLISH_TYPE, v.payload_hex);
        defer allocator.free(full);

        // DECODE: every field against the struct literal upstream encoded.
        var m = try decodeChannelReestablish(allocator, full);
        defer m.deinit(allocator);
        try testing.expectEqualSlices(u8, &hexArray(32, v.channel_id_hex), &m.channel_id);
        try testing.expectEqual(v.next_commitment_number, m.next_commitment_number);
        try testing.expectEqual(v.next_revocation_number, m.next_revocation_number);
        try testing.expectEqualSlices(u8, &hexArray(32, v.your_last_per_commitment_secret_hex), &m.your_last_per_commitment_secret);
        try testing.expectEqualSlices(u8, &hexArray(33, v.my_current_per_commitment_point_hex), &m.my_current_per_commitment_point);
        if (v.next_funding_txid_hex) |h| {
            const nf = m.nextFunding() orelse return error.ExpectedNextFunding;
            try testing.expectEqualSlices(u8, &hexArray(32, h), &nf.txid);
            try testing.expectEqual(v.next_funding_flags, nf.retransmit_flags);
        } else try testing.expect(m.nextFunding() == null);
        if (v.funding_locked_txid_hex) |h| {
            const fl = m.myCurrentFundingLocked() orelse return error.ExpectedFundingLocked;
            try testing.expectEqualSlices(u8, &hexArray(32, h), &fl.txid);
            try testing.expectEqual(v.funding_locked_flags, fl.retransmit_flags);
        } else try testing.expect(m.myCurrentFundingLocked() == null);

        // ENCODE: built from the vector's fields alone, byte-exact.
        var recs: [2]message.tlv.RawRecord = undefined;
        var n: usize = 0;
        var nf_bytes: [FundingTxidFlags.wire_len]u8 = undefined;
        var fl_bytes: [FundingTxidFlags.wire_len]u8 = undefined;
        if (v.next_funding_txid_hex) |h| {
            nf_bytes = (FundingTxidFlags{ .txid = hexArray(32, h), .retransmit_flags = v.next_funding_flags }).toBytes();
            recs[n] = .{ .type = REESTABLISH_TLV_NEXT_FUNDING, .value = &nf_bytes };
            n += 1;
        }
        if (v.funding_locked_txid_hex) |h| {
            fl_bytes = (FundingTxidFlags{ .txid = hexArray(32, h), .retransmit_flags = v.funding_locked_flags }).toBytes();
            recs[n] = .{ .type = REESTABLISH_TLV_MY_CURRENT_FUNDING_LOCKED, .value = &fl_bytes };
            n += 1;
        }
        const built: ChannelReestablish = .{
            .channel_id = hexArray(32, v.channel_id_hex),
            .next_commitment_number = v.next_commitment_number,
            .next_revocation_number = v.next_revocation_number,
            .your_last_per_commitment_secret = hexArray(32, v.your_last_per_commitment_secret_hex),
            .my_current_per_commitment_point = hexArray(33, v.my_current_per_commitment_point_hex),
            .extension = .{ .records = recs[0..n] },
        };
        const out = try serializeChannelReestablish(allocator, built);
        defer allocator.free(out);
        try testing.expectEqualSlices(u8, full, out);
    }
}

test "official vector (rust-lightning msgs.rs encoding_update_fail_malformed_htlc): layout both ways, and the BADONION refusal" {
    const allocator = testing.allocator;
    const v = rm_kat.update_fail_malformed_htlc_vector;
    const full = try framedHex(allocator, UPDATE_FAIL_MALFORMED_HTLC_TYPE, v.payload_hex);
    defer allocator.free(full);

    const m = try decodeUpdateFailMalformedHtlcLayout(full);
    try testing.expectEqualSlices(u8, &hexArray(32, v.channel_id_hex), &m.channel_id);
    try testing.expectEqual(v.id, m.id);
    try testing.expectEqualSlices(u8, &hexArray(32, v.sha256_of_onion_hex), &m.sha256_of_onion);
    try testing.expectEqual(v.failure_code, m.failure_code);

    const built: UpdateFailMalformedHtlc = .{
        .channel_id = hexArray(32, v.channel_id_hex),
        .id = v.id,
        .sha256_of_onion = hexArray(32, v.sha256_of_onion_hex),
        .failure_code = v.failure_code,
    };
    const out = try serializeUpdateFailMalformedHtlcLayout(allocator, built);
    defer allocator.free(out);
    try testing.expectEqualSlices(u8, full, out);

    // failure_code 255 has no BADONION bit: BOLT#2 says the receiver MUST
    // fail it, and the public codec does — in both directions.
    try testing.expectError(error.BadOnionBitNotSet, decodeUpdateFailMalformedHtlc(full));
    try testing.expectError(error.BadOnionBitNotSet, serializeUpdateFailMalformedHtlc(allocator, built));
}

test "update_fail_malformed_htlc: BADONION codes pass, the bit alone decides" {
    const allocator = testing.allocator;
    // BOLT#4's invalid_onion_version / _hmac / _key / _blinding are
    // BADONION|PERM|4,5,6,24 = 0xC004, 0xC005, 0xC006, 0xC018.
    for ([_]u16{ 0xC004, 0xC005, 0xC006, 0xC018, BADONION }) |code| {
        const msg: UpdateFailMalformedHtlc = .{ .channel_id = fillPattern(32, 1), .id = 9, .sha256_of_onion = fillPattern(32, 2), .failure_code = code };
        const bytes = try serializeUpdateFailMalformedHtlc(allocator, msg);
        defer allocator.free(bytes);
        try testing.expectEqual(@as(usize, 2 + 32 + 8 + 32 + 2), bytes.len);
        const back = try decodeUpdateFailMalformedHtlc(bytes);
        try testing.expectEqual(code, back.failure_code);
        try testing.expectEqual(msg.id, back.id);
    }
    // PERM|4 without BADONION (0x4004), the bit's neighbour 0x7FFF, and 0.
    for ([_]u16{ 0x4004, 0x7FFF, 0 }) |code| {
        const msg: UpdateFailMalformedHtlc = .{ .channel_id = fillPattern(32, 1), .id = 9, .sha256_of_onion = fillPattern(32, 2), .failure_code = code };
        try testing.expectError(error.BadOnionBitNotSet, serializeUpdateFailMalformedHtlc(allocator, msg));
    }
}

test "hostile: update_fail_malformed_htlc truncated inside failure_code fails closed" {
    var bytes: [2 + 32 + 8 + 32 + 1]u8 = @splat(0x80);
    std.mem.writeInt(u16, bytes[0..2], UPDATE_FAIL_MALFORMED_HTLC_TYPE, .big);
    try testing.expectError(error.Truncated, decodeUpdateFailMalformedHtlc(&bytes));
}

fn reestablishBase() ChannelReestablish {
    return .{
        .channel_id = fillPattern(32, 1),
        .next_commitment_number = 42,
        .next_revocation_number = 41,
        .your_last_per_commitment_secret = fillPattern(32, 2),
        .my_current_per_commitment_point = fillPattern(33, 3),
    };
}

test "channel_reestablish: both TLVs together, unknown odd discarded" {
    const allocator = testing.allocator;
    const nf = (FundingTxidFlags{ .txid = fillPattern(32, 7), .retransmit_flags = 1 }).toBytes();
    const fl = (FundingTxidFlags{ .txid = fillPattern(32, 8), .retransmit_flags = 0 }).toBytes();
    var msg = reestablishBase();
    msg.extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{
        .{ .type = 1, .value = &nf },
        .{ .type = 5, .value = &fl },
        .{ .type = 7, .value = &.{ 0xAA, 0xBB } },
    }) };
    const bytes = try serializeChannelReestablish(allocator, msg);
    defer allocator.free(bytes);
    var m = try decodeChannelReestablish(allocator, bytes);
    defer m.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), m.extension.records.len);
    try testing.expectEqualSlices(u8, &fillPattern(32, 7), &m.nextFunding().?.txid);
    try testing.expectEqual(@as(u8, 0), m.myCurrentFundingLocked().?.retransmit_flags);
    try testing.expectEqual(@as(u64, 42), m.next_commitment_number);
}

test "hostile: channel_reestablish refuses wrong-length known TLVs, unknown even TLVs, truncation" {
    const allocator = testing.allocator;
    const plain = try serializeChannelReestablish(allocator, reestablishBase());
    defer allocator.free(plain);
    try testing.expectEqual(@as(usize, 2 + 113), plain.len);

    var buf: [2 + 113 + 40]u8 = undefined;
    @memcpy(buf[0..plain.len], plain);
    // next_funding with 32 octets (the length before `retransmit_flags`).
    buf[plain.len] = 0x01;
    buf[plain.len + 1] = 32;
    @memset(buf[plain.len + 2 ..][0..32], 0x11);
    try testing.expectError(error.InvalidTlvLength, decodeChannelReestablish(allocator, buf[0 .. plain.len + 2 + 32]));
    // my_current_funding_locked with 34 octets.
    buf[plain.len] = 0x05;
    buf[plain.len + 1] = 34;
    @memset(buf[plain.len + 2 ..][0..34], 0x11);
    try testing.expectError(error.InvalidTlvLength, decodeChannelReestablish(allocator, buf[0 .. plain.len + 2 + 34]));
    // Unknown even type 2.
    buf[plain.len] = 0x02;
    buf[plain.len + 1] = 0;
    try testing.expectError(error.UnknownEvenType, decodeChannelReestablish(allocator, buf[0 .. plain.len + 2]));
    // One octet short of the point.
    try testing.expectError(error.Truncated, decodeChannelReestablish(allocator, plain[0 .. plain.len - 1]));

    // The encoder refuses the same wrong length.
    var bad = reestablishBase();
    const short_value = fillPattern(32, 1);
    bad.extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{.{ .type = 1, .value = &short_value }}) };
    try testing.expectError(error.InvalidTlvLength, serializeChannelReestablish(allocator, bad));
}

// ── fuzz: the two new BOLT#2 decoders over the same arbitrary bytes ───────
//
// Both decoders run on every input, so no drawn value selects the path
// (check-fuzz-reach R2(c)); a seed's own frame type decides which one gets
// past `openFrame`.
const ReestablishCorpus = struct {
    store: [12 * (4 + 256)]u8 = undefined,
    used: usize = 0,
    entries: [12][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *ReestablishCorpus, bytes: []const u8) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], bytes);
        self.entries[self.n] = head;
        self.used += head.len;
        self.n += 1;
    }

    fn build(self: *ReestablishCorpus, allocator: Allocator) ![]const []const u8 {
        const plain = try serializeChannelReestablish(allocator, reestablishBase());
        defer allocator.free(plain);
        self.push(plain);

        const nf = (FundingTxidFlags{ .txid = fillPattern(32, 7), .retransmit_flags = 1 }).toBytes();
        var both = reestablishBase();
        both.extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{
            .{ .type = 1, .value = &nf },
            .{ .type = 5, .value = &nf },
        }) };
        const both_bytes = try serializeChannelReestablish(allocator, both);
        defer allocator.free(both_bytes);
        self.push(both_bytes);

        var odd = reestablishBase();
        odd.extension = .{ .records = @constCast(&[_]message.tlv.RawRecord{.{ .type = 9, .value = &.{0x01} }}) };
        const odd_bytes = try serializeChannelReestablish(allocator, odd);
        defer allocator.free(odd_bytes);
        self.push(odd_bytes);

        // Refusals: wrong-length known TLV, unknown even, truncation, bare frame.
        {
            var b: [256]u8 = undefined;
            @memcpy(b[0..plain.len], plain);
            b[plain.len] = 0x01;
            b[plain.len + 1] = 0x01;
            b[plain.len + 2] = 0xEE;
            self.push(b[0 .. plain.len + 3]);
            b[plain.len] = 0x04;
            b[plain.len + 1] = 0x00;
            self.push(b[0 .. plain.len + 2]);
        }
        self.push(plain[0 .. plain.len - 1]);
        self.push(plain[0..2]);

        const good: UpdateFailMalformedHtlc = .{ .channel_id = fillPattern(32, 1), .id = 3, .sha256_of_onion = fillPattern(32, 2), .failure_code = 0xC005 };
        const mal = try serializeUpdateFailMalformedHtlc(allocator, good);
        defer allocator.free(mal);
        self.push(mal);
        {
            var b: [256]u8 = undefined;
            @memcpy(b[0..mal.len], mal);
            std.mem.writeInt(u16, b[mal.len - 2 ..][0..2], 0x4005, .big); // no BADONION
            self.push(b[0..mal.len]);
        }
        self.push(mal[0 .. mal.len - 1]);
        return self.entries[0..self.n];
    }
};

const ReestablishFuzzOutcome = struct { reestablish: bool = false, malformed: bool = false, records: usize = 0 };

fn runReestablishMalformed(allocator: Allocator, bytes: []const u8) ReestablishFuzzOutcome {
    var out: ReestablishFuzzOutcome = .{};
    if (decodeChannelReestablish(allocator, bytes)) |decoded| {
        var m = decoded;
        defer m.deinit(allocator);
        out.reestablish = true;
        out.records = m.extension.records.len;
        _ = m.nextFunding();
        _ = m.myCurrentFundingLocked();
    } else |_| {}
    if (decodeUpdateFailMalformedHtlc(bytes)) |_| {
        out.malformed = true;
    } else |_| {}
    return out;
}

test "fuzz: decodeChannelReestablish / decodeUpdateFailMalformedHtlc never panic on arbitrary bytes" {
    var corpus: ReestablishCorpus = .{};
    try testing.fuzz({}, fuzzReestablishMalformed, .{ .corpus = try corpus.build(testing.allocator) });
}

fn fuzzReestablishMalformed(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    // One faithful `smith.slice` draw (see `fuzzDecodeOpenChannel`).
    const len: usize = smith.slice(&buf);
    _ = runReestablishMalformed(testing.allocator, buf[0..len]);
}

test "corpus: every reestablish/malformed seed reaches a decoder, and the counts are pinned" {
    var corpus: ReestablishCorpus = .{};
    const allocator = testing.allocator;
    const entries = try corpus.build(allocator);
    var nonempty: usize = 0;
    var reestablish: usize = 0;
    var malformed: usize = 0;
    var records: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const o = runReestablishMalformed(allocator, buf[0..len]);
        if (o.reestablish) reestablish += 1;
        if (o.malformed) malformed += 1;
        records += o.records;
    }
    try testing.expectEqual(entries.len, nonempty);
    // plain, both TLVs, unknown-odd.
    try testing.expectEqual(@as(usize, 3), reestablish);
    // Only the BADONION one; its 0x4005 twin is refused.
    try testing.expectEqual(@as(usize, 1), malformed);
    // 2 from the both-TLV seed; the unknown-odd record is discarded.
    try testing.expectEqual(@as(usize, 2), records);
}
