// SPDX-License-Identifier: MIT
//! BOLT#2 channel-management messages: the core Channel Establishment v1
//! + Normal Operation + Channel Close set — `open_channel`,
//! `accept_channel`, `funding_created`, `funding_signed`,
//! `channel_ready`, `update_add_htlc`, `update_fulfill_htlc`,
//! `update_fail_htlc`, `commitment_signed`, `revoke_and_ack`,
//! `update_fee`, `shutdown`, `closing_signed`.
//!
//! Deferred (see `../SPEC.md`): Interactive Transaction Construction
//! (`tx_*`), Channel Establishment v2 (`open_channel2`/`accept_channel2`),
//! Channel Splicing, Quiescence (`stfu`), `update_fail_malformed_htlc`,
//! `start_batch`, modern Closing Negotiation (`closing_complete`/
//! `closing_sig`), `channel_reestablish` — none named in this module's
//! required set; each is a self-contained follow-on, not a corner cut
//! inside a message this file claims to implement.
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

pub fn serializeUpdateFailHtlc(allocator: Allocator, msg: UpdateFailHtlc) Allocator.Error![]u8 {
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

pub fn serializeCommitmentSigned(allocator: Allocator, msg: CommitmentSigned) Allocator.Error![]u8 {
    std.debug.assert(msg.htlc_signatures.len <= std.math.maxInt(u16));
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

pub fn serializeShutdown(allocator: Allocator, msg: Shutdown) Allocator.Error![]u8 {
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

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

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
test "fuzz: decodeOpenChannel never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeOpenChannel, .{});
}

fn fuzzDecodeOpenChannel(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [400]u8 = undefined;
    smith.bytes(&buf);
    // Force the 2-byte type frame so the fuzzer reaches the actual field
    // reader chain most of the time, rather than dying on `WrongType`.
    std.mem.writeInt(u16, buf[0..2], OPEN_CHANNEL_TYPE, .big);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var m = decodeOpenChannel(allocator, buf[0..len]) catch return;
    defer m.deinit(allocator);
}
