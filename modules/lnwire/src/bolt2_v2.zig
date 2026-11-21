// SPDX-License-Identifier: MIT
//! BOLT#2 messages of the current spec that `bolt2.zig` (Channel
//! Establishment v1 / Normal Operation / the first Closing Negotiation)
//! does not carry: Quiescence (`stfu`), Channel Establishment v2
//! (`open_channel2`, `accept_channel2`), Interactive Transaction Construction
//! (`tx_add_input`, `tx_add_output`, `tx_remove_input`, `tx_remove_output`,
//! `tx_complete`, `tx_signatures`, `tx_init_rbf`, `tx_ack_rbf`, `tx_abort`),
//! Splicing (`splice_init`, `splice_ack`, `splice_locked`), the modern Closing
//! Negotiation (`closing_complete`, `closing_sig`) and `start_batch`. Layouts
//! and TLV types are those of `lightning/bolts` `02-peer-protocol.md`
//! (checked against the file at its master revision of 2026-11).
//!
//! Same conventions as `bolt2.zig`: `decodeX` / `serializeX` per message, a
//! trailing `tlv_stream` decoded through `message.Extension` (unknown even
//! types and ordering errors rejected by the stream parser), the length of
//! each KNOWN record checked at decode and encode (`TlvLengthError`),
//! variable-length fields borrowed from the decoded bytes. The codecs carry
//! the wire format only; the protocol rules (serial-id parity, input/output
//! limits, "exactly one of" the closing signatures, ...) belong to the
//! caller's state machine.

const std = @import("std");
const Allocator = std.mem.Allocator;
const message = @import("message.zig");
const bolt2 = @import("bolt2.zig");
const Reader = message.Reader;
const Writer = message.Writer;
const Extension = message.Extension;
const ChannelId = message.ChannelId;
const Sha256 = message.Sha256;
const Signature = message.Signature;
const Point = message.Point;

pub const DecodeError = message.FrameError || message.tlv.StreamError;
pub const TlvLengthError = message.TlvLengthError;
pub const ChannelType = bolt2.ChannelType;

/// `require_confirmed_inputs` (TLV 2 in `opening_tlvs`, `accept_tlvs`, `tx_init_rbf_tlvs`,
/// `tx_ack_rbf_tlvs`, `splice_init_tlvs`, `splice_ack_tlvs`): an empty record.
pub const TLV_REQUIRE_CONFIRMED_INPUTS: u64 = 2;
pub const TLV_UPFRONT_SHUTDOWN_SCRIPT: u64 = 0;
pub const TLV_CHANNEL_TYPE: u64 = 1;
/// `funding_output_contribution` (TLV 0 of `tx_init_rbf_tlvs` / `tx_ack_rbf_tlvs`): an `s64`.
pub const TLV_FUNDING_OUTPUT_CONTRIBUTION: u64 = 0;
/// `shared_input_txid` (TLV 0 of `tx_add_input_tlvs`): a `sha256`.
pub const TLV_SHARED_INPUT_TXID: u64 = 0;
/// `shared_input_signature` (TLV 0 of `tx_signatures_tlvs`): a `signature`.
pub const TLV_SHARED_INPUT_SIGNATURE: u64 = 0;
/// `closing_tlvs`: each a `signature`.
pub const TLV_CLOSER_OUTPUT_ONLY: u64 = 1;
pub const TLV_CLOSEE_OUTPUT_ONLY: u64 = 2;
pub const TLV_CLOSER_AND_CLOSEE_OUTPUTS: u64 = 3;
/// `start_batch_tlvs`: `message_type`, a `u16`.
pub const TLV_BATCH_MESSAGE_TYPE: u64 = 1;

/// The exact length a known TLV record must have.
const Rule = struct { t: u64, len: usize };

fn checkLengths(ext: Extension, comptime rules: []const Rule) TlvLengthError!void {
    for (ext.records) |rec| {
        inline for (rules) |rule| {
            if (rec.type == rule.t and rec.value.len != rule.len) return error.InvalidTlvLength;
        }
    }
}

fn readPoint(r: *Reader) message.ReadError!Point {
    return r.takeArray(33);
}

// ── stfu (type 2) — no tlv_stream ───────────────────────────────────────

pub const STFU_TYPE: u16 = 2;

pub const Stfu = struct {
    channel_id: ChannelId,
    /// 1 if the sender is the quiescence initiator (BOLT#2: "MUST set `initiator`
    /// to 1 if it initiated, else 0"); other values are passed through.
    initiator: u8,

    pub fn deinit(_: *Stfu, _: Allocator) void {}
};

pub fn decodeStfu(bytes: []const u8) message.FrameError!Stfu {
    var r = try message.openFrame(bytes, STFU_TYPE);
    return .{ .channel_id = try r.takeArray(32), .initiator = try r.byte() };
}

pub fn serializeStfu(allocator: Allocator, msg: Stfu) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, STFU_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU8(allocator, msg.initiator);
    return w.toOwned(allocator);
}

// ── open_channel2 (type 64) / accept_channel2 (type 65) ─────────────────

pub const OPEN_CHANNEL2_TYPE: u16 = 64;
pub const ACCEPT_CHANNEL2_TYPE: u16 = 65;
const channel2_known_tlv = [_]u64{ TLV_UPFRONT_SHUTDOWN_SCRIPT, TLV_CHANNEL_TYPE, TLV_REQUIRE_CONFIRMED_INPUTS };
const channel2_rules = [_]Rule{.{ .t = TLV_REQUIRE_CONFIRMED_INPUTS, .len = 0 }};

pub const OpenChannel2 = struct {
    chain_hash: message.ChainHash,
    temporary_channel_id: ChannelId,
    funding_feerate_perkw: u32,
    commitment_feerate_perkw: u32,
    funding_satoshis: u64,
    dust_limit_satoshis: u64,
    max_htlc_value_in_flight_msat: u64,
    htlc_minimum_msat: u64,
    to_self_delay: u16,
    max_accepted_htlcs: u16,
    locktime: u32,
    funding_pubkey: Point,
    revocation_basepoint: Point,
    payment_basepoint: Point,
    delayed_payment_basepoint: Point,
    htlc_basepoint: Point,
    first_per_commitment_point: Point,
    second_per_commitment_point: Point,
    channel_flags: u8,
    extension: Extension = .{},

    pub fn deinit(self: *OpenChannel2, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    pub fn upfrontShutdownScript(self: OpenChannel2) ?[]const u8 {
        return self.extension.find(TLV_UPFRONT_SHUTDOWN_SCRIPT);
    }

    pub fn channelType(self: OpenChannel2) ?ChannelType {
        const v = self.extension.find(TLV_CHANNEL_TYPE) orelse return null;
        return .{ .bits = v };
    }

    pub fn requireConfirmedInputs(self: OpenChannel2) bool {
        return self.extension.find(TLV_REQUIRE_CONFIRMED_INPUTS) != null;
    }
};

pub fn decodeOpenChannel2(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!OpenChannel2 {
    var r = try message.openFrame(bytes, OPEN_CHANNEL2_TYPE);
    var m: OpenChannel2 = undefined;
    m.chain_hash = try r.takeArray(32);
    m.temporary_channel_id = try r.takeArray(32);
    m.funding_feerate_perkw = try r.u32be();
    m.commitment_feerate_perkw = try r.u32be();
    m.funding_satoshis = try r.u64be();
    m.dust_limit_satoshis = try r.u64be();
    m.max_htlc_value_in_flight_msat = try r.u64be();
    m.htlc_minimum_msat = try r.u64be();
    m.to_self_delay = try r.u16be();
    m.max_accepted_htlcs = try r.u16be();
    m.locktime = try r.u32be();
    m.funding_pubkey = try readPoint(&r);
    m.revocation_basepoint = try readPoint(&r);
    m.payment_basepoint = try readPoint(&r);
    m.delayed_payment_basepoint = try readPoint(&r);
    m.htlc_basepoint = try readPoint(&r);
    m.first_per_commitment_point = try readPoint(&r);
    m.second_per_commitment_point = try readPoint(&r);
    m.channel_flags = try r.byte();
    m.extension = try message.decodeExtension(allocator, r.rest(), &channel2_known_tlv);
    errdefer m.extension.deinit(allocator);
    try checkLengths(m.extension, &channel2_rules);
    return m;
}

pub fn serializeOpenChannel2(allocator: Allocator, msg: OpenChannel2) (Allocator.Error || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &channel2_rules);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, OPEN_CHANNEL2_TYPE);
    try w.putBytes(allocator, &msg.chain_hash);
    try w.putBytes(allocator, &msg.temporary_channel_id);
    try w.putU32be(allocator, msg.funding_feerate_perkw);
    try w.putU32be(allocator, msg.commitment_feerate_perkw);
    try w.putU64be(allocator, msg.funding_satoshis);
    try w.putU64be(allocator, msg.dust_limit_satoshis);
    try w.putU64be(allocator, msg.max_htlc_value_in_flight_msat);
    try w.putU64be(allocator, msg.htlc_minimum_msat);
    try w.putU16be(allocator, msg.to_self_delay);
    try w.putU16be(allocator, msg.max_accepted_htlcs);
    try w.putU32be(allocator, msg.locktime);
    try w.putBytes(allocator, &msg.funding_pubkey);
    try w.putBytes(allocator, &msg.revocation_basepoint);
    try w.putBytes(allocator, &msg.payment_basepoint);
    try w.putBytes(allocator, &msg.delayed_payment_basepoint);
    try w.putBytes(allocator, &msg.htlc_basepoint);
    try w.putBytes(allocator, &msg.first_per_commitment_point);
    try w.putBytes(allocator, &msg.second_per_commitment_point);
    try w.putU8(allocator, msg.channel_flags);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

pub const AcceptChannel2 = struct {
    temporary_channel_id: ChannelId,
    funding_satoshis: u64,
    dust_limit_satoshis: u64,
    max_htlc_value_in_flight_msat: u64,
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
    second_per_commitment_point: Point,
    extension: Extension = .{},

    pub fn deinit(self: *AcceptChannel2, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    pub fn upfrontShutdownScript(self: AcceptChannel2) ?[]const u8 {
        return self.extension.find(TLV_UPFRONT_SHUTDOWN_SCRIPT);
    }

    pub fn channelType(self: AcceptChannel2) ?ChannelType {
        const v = self.extension.find(TLV_CHANNEL_TYPE) orelse return null;
        return .{ .bits = v };
    }

    pub fn requireConfirmedInputs(self: AcceptChannel2) bool {
        return self.extension.find(TLV_REQUIRE_CONFIRMED_INPUTS) != null;
    }
};

pub fn decodeAcceptChannel2(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!AcceptChannel2 {
    var r = try message.openFrame(bytes, ACCEPT_CHANNEL2_TYPE);
    var m: AcceptChannel2 = undefined;
    m.temporary_channel_id = try r.takeArray(32);
    m.funding_satoshis = try r.u64be();
    m.dust_limit_satoshis = try r.u64be();
    m.max_htlc_value_in_flight_msat = try r.u64be();
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
    m.second_per_commitment_point = try readPoint(&r);
    m.extension = try message.decodeExtension(allocator, r.rest(), &channel2_known_tlv);
    errdefer m.extension.deinit(allocator);
    try checkLengths(m.extension, &channel2_rules);
    return m;
}

pub fn serializeAcceptChannel2(allocator: Allocator, msg: AcceptChannel2) (Allocator.Error || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &channel2_rules);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, ACCEPT_CHANNEL2_TYPE);
    try w.putBytes(allocator, &msg.temporary_channel_id);
    try w.putU64be(allocator, msg.funding_satoshis);
    try w.putU64be(allocator, msg.dust_limit_satoshis);
    try w.putU64be(allocator, msg.max_htlc_value_in_flight_msat);
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
    try w.putBytes(allocator, &msg.second_per_commitment_point);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── tx_add_input (66) ───────────────────────────────────────────────────

pub const TX_ADD_INPUT_TYPE: u16 = 66;
const tx_add_input_known_tlv = [_]u64{TLV_SHARED_INPUT_TXID};
const tx_add_input_rules = [_]Rule{.{ .t = TLV_SHARED_INPUT_TXID, .len = 32 }};

pub const TxAddInput = struct {
    channel_id: ChannelId,
    serial_id: u64,
    /// The whole previous transaction (borrowed; empty for a shared input).
    prevtx: []const u8,
    prevtx_vout: u32,
    sequence: u32,
    extension: Extension = .{},

    pub fn deinit(self: *TxAddInput, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    /// `shared_input_txid` (TLV 0): the funding txid of the shared (spliced) input.
    pub fn sharedInputTxid(self: TxAddInput) ?Sha256 {
        const v = self.extension.find(TLV_SHARED_INPUT_TXID) orelse return null;
        return v[0..32].*;
    }
};

pub fn decodeTxAddInput(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!TxAddInput {
    var r = try message.openFrame(bytes, TX_ADD_INPUT_TYPE);
    var m: TxAddInput = undefined;
    m.channel_id = try r.takeArray(32);
    m.serial_id = try r.u64be();
    m.prevtx = try r.bytesU16();
    m.prevtx_vout = try r.u32be();
    m.sequence = try r.u32be();
    m.extension = try message.decodeExtension(allocator, r.rest(), &tx_add_input_known_tlv);
    errdefer m.extension.deinit(allocator);
    try checkLengths(m.extension, &tx_add_input_rules);
    return m;
}

pub fn serializeTxAddInput(allocator: Allocator, msg: TxAddInput) (message.WriteError || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &tx_add_input_rules);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, TX_ADD_INPUT_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, msg.serial_id);
    try w.putBytesU16(allocator, msg.prevtx);
    try w.putU32be(allocator, msg.prevtx_vout);
    try w.putU32be(allocator, msg.sequence);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── tx_add_output (67) — no tlv_stream ─────────────────────────────────

pub const TX_ADD_OUTPUT_TYPE: u16 = 67;

pub const TxAddOutput = struct {
    channel_id: ChannelId,
    serial_id: u64,
    sats: u64,
    /// The output's scriptPubKey (borrowed; opaque).
    script: []const u8,

    pub fn deinit(_: *TxAddOutput, _: Allocator) void {}
};

pub fn decodeTxAddOutput(bytes: []const u8) message.FrameError!TxAddOutput {
    var r = try message.openFrame(bytes, TX_ADD_OUTPUT_TYPE);
    return .{ .channel_id = try r.takeArray(32), .serial_id = try r.u64be(), .sats = try r.u64be(), .script = try r.bytesU16() };
}

pub fn serializeTxAddOutput(allocator: Allocator, msg: TxAddOutput) message.WriteError![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, TX_ADD_OUTPUT_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, msg.serial_id);
    try w.putU64be(allocator, msg.sats);
    try w.putBytesU16(allocator, msg.script);
    return w.toOwned(allocator);
}

// ── tx_remove_input (68) / tx_remove_output (69) — no tlv_stream ───────

pub const TX_REMOVE_INPUT_TYPE: u16 = 68;
pub const TX_REMOVE_OUTPUT_TYPE: u16 = 69;

pub const TxRemove = struct {
    channel_id: ChannelId,
    serial_id: u64,

    pub fn deinit(_: *TxRemove, _: Allocator) void {}
};

pub fn decodeTxRemoveInput(bytes: []const u8) message.FrameError!TxRemove {
    var r = try message.openFrame(bytes, TX_REMOVE_INPUT_TYPE);
    return .{ .channel_id = try r.takeArray(32), .serial_id = try r.u64be() };
}

pub fn decodeTxRemoveOutput(bytes: []const u8) message.FrameError!TxRemove {
    var r = try message.openFrame(bytes, TX_REMOVE_OUTPUT_TYPE);
    return .{ .channel_id = try r.takeArray(32), .serial_id = try r.u64be() };
}

fn serializeTxRemove(allocator: Allocator, t: u16, msg: TxRemove) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, t);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, msg.serial_id);
    return w.toOwned(allocator);
}

pub fn serializeTxRemoveInput(allocator: Allocator, msg: TxRemove) Allocator.Error![]u8 {
    return serializeTxRemove(allocator, TX_REMOVE_INPUT_TYPE, msg);
}

pub fn serializeTxRemoveOutput(allocator: Allocator, msg: TxRemove) Allocator.Error![]u8 {
    return serializeTxRemove(allocator, TX_REMOVE_OUTPUT_TYPE, msg);
}

// ── tx_complete (70) — its tlv_stream has no types yet ─────────────────

pub const TX_COMPLETE_TYPE: u16 = 70;

pub const TxComplete = struct {
    channel_id: ChannelId,
    extension: Extension = .{},

    pub fn deinit(self: *TxComplete, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }
};

pub fn decodeTxComplete(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!TxComplete {
    var r = try message.openFrame(bytes, TX_COMPLETE_TYPE);
    const channel_id = try r.takeArray(32);
    return .{ .channel_id = channel_id, .extension = try message.decodeExtension(allocator, r.rest(), &.{}) };
}

pub fn serializeTxComplete(allocator: Allocator, msg: TxComplete) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, TX_COMPLETE_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── tx_signatures (71) ──────────────────────────────────────────────────

pub const TX_SIGNATURES_TYPE: u16 = 71;
const tx_signatures_known_tlv = [_]u64{TLV_SHARED_INPUT_SIGNATURE};
const tx_signatures_rules = [_]Rule{.{ .t = TLV_SHARED_INPUT_SIGNATURE, .len = 64 }};

pub const TxSignatures = struct {
    channel_id: ChannelId,
    txid: Sha256,
    /// One witness (borrowed bytes of the `witness` subtype: `u16 len` + data) per
    /// contributed input; the slice is owned (freed by `deinit`).
    witnesses: []const []const u8 = &.{},
    extension: Extension = .{},

    pub fn deinit(self: *TxSignatures, allocator: Allocator) void {
        allocator.free(self.witnesses);
        self.extension.deinit(allocator);
        self.* = undefined;
    }

    /// `shared_input_signature` (TLV 0), the 64-byte signature of the shared input.
    pub fn sharedInputSignature(self: TxSignatures) ?Signature {
        const v = self.extension.find(TLV_SHARED_INPUT_SIGNATURE) orelse return null;
        return v[0..64].*;
    }
};

pub fn decodeTxSignatures(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!TxSignatures {
    var r = try message.openFrame(bytes, TX_SIGNATURES_TYPE);
    const channel_id = try r.takeArray(32);
    const txid = try r.takeArray(32);
    const n = try r.u16be();
    // Each witness needs at least its 2-byte length: bound the allocation by the bytes present.
    if (@as(usize, n) * 2 > r.remaining()) return error.Truncated;
    const witnesses = try allocator.alloc([]const u8, n);
    errdefer allocator.free(witnesses);
    for (witnesses) |*wit| wit.* = try r.bytesU16();
    var extension = try message.decodeExtension(allocator, r.rest(), &tx_signatures_known_tlv);
    errdefer extension.deinit(allocator);
    try checkLengths(extension, &tx_signatures_rules);
    return .{ .channel_id = channel_id, .txid = txid, .witnesses = witnesses, .extension = extension };
}

pub fn serializeTxSignatures(allocator: Allocator, msg: TxSignatures) (message.WriteError || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &tx_signatures_rules);
    if (msg.witnesses.len > std.math.maxInt(u16)) return error.FieldTooLong;
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, TX_SIGNATURES_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytes(allocator, &msg.txid);
    try w.putU16be(allocator, @intCast(msg.witnesses.len));
    for (msg.witnesses) |wit| try w.putBytesU16(allocator, wit);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── tx_init_rbf (72) / tx_ack_rbf (73) ─────────────────────────────────

pub const TX_INIT_RBF_TYPE: u16 = 72;
pub const TX_ACK_RBF_TYPE: u16 = 73;
const rbf_known_tlv = [_]u64{ TLV_FUNDING_OUTPUT_CONTRIBUTION, TLV_REQUIRE_CONFIRMED_INPUTS };
const rbf_rules = [_]Rule{ .{ .t = TLV_FUNDING_OUTPUT_CONTRIBUTION, .len = 8 }, .{ .t = TLV_REQUIRE_CONFIRMED_INPUTS, .len = 0 } };

fn fundingContribution(ext: Extension) ?i64 {
    const v = ext.find(TLV_FUNDING_OUTPUT_CONTRIBUTION) orelse return null;
    return std.mem.readInt(i64, v[0..8], .big);
}

pub const TxInitRbf = struct {
    channel_id: ChannelId,
    locktime: u32,
    feerate: u32,
    extension: Extension = .{},

    pub fn deinit(self: *TxInitRbf, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    /// `funding_output_contribution` (TLV 0, an `s64`).
    pub fn fundingOutputContribution(self: TxInitRbf) ?i64 {
        return fundingContribution(self.extension);
    }

    pub fn requireConfirmedInputs(self: TxInitRbf) bool {
        return self.extension.find(TLV_REQUIRE_CONFIRMED_INPUTS) != null;
    }
};

pub fn decodeTxInitRbf(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!TxInitRbf {
    var r = try message.openFrame(bytes, TX_INIT_RBF_TYPE);
    const channel_id = try r.takeArray(32);
    const locktime = try r.u32be();
    const feerate = try r.u32be();
    var extension = try message.decodeExtension(allocator, r.rest(), &rbf_known_tlv);
    errdefer extension.deinit(allocator);
    try checkLengths(extension, &rbf_rules);
    return .{ .channel_id = channel_id, .locktime = locktime, .feerate = feerate, .extension = extension };
}

pub fn serializeTxInitRbf(allocator: Allocator, msg: TxInitRbf) (Allocator.Error || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &rbf_rules);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, TX_INIT_RBF_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU32be(allocator, msg.locktime);
    try w.putU32be(allocator, msg.feerate);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

pub const TxAckRbf = struct {
    channel_id: ChannelId,
    extension: Extension = .{},

    pub fn deinit(self: *TxAckRbf, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    pub fn fundingOutputContribution(self: TxAckRbf) ?i64 {
        return fundingContribution(self.extension);
    }

    pub fn requireConfirmedInputs(self: TxAckRbf) bool {
        return self.extension.find(TLV_REQUIRE_CONFIRMED_INPUTS) != null;
    }
};

pub fn decodeTxAckRbf(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!TxAckRbf {
    var r = try message.openFrame(bytes, TX_ACK_RBF_TYPE);
    const channel_id = try r.takeArray(32);
    var extension = try message.decodeExtension(allocator, r.rest(), &rbf_known_tlv);
    errdefer extension.deinit(allocator);
    try checkLengths(extension, &rbf_rules);
    return .{ .channel_id = channel_id, .extension = extension };
}

pub fn serializeTxAckRbf(allocator: Allocator, msg: TxAckRbf) (Allocator.Error || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &rbf_rules);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, TX_ACK_RBF_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── tx_abort (74) — no tlv_stream ───────────────────────────────────────

pub const TX_ABORT_TYPE: u16 = 74;

pub const TxAbort = struct {
    channel_id: ChannelId,
    /// Opaque (BOLT#2: SHOULD be printable ASCII when sent; borrowed).
    data: []const u8,

    pub fn deinit(_: *TxAbort, _: Allocator) void {}
};

pub fn decodeTxAbort(bytes: []const u8) message.FrameError!TxAbort {
    var r = try message.openFrame(bytes, TX_ABORT_TYPE);
    return .{ .channel_id = try r.takeArray(32), .data = try r.bytesU16() };
}

pub fn serializeTxAbort(allocator: Allocator, msg: TxAbort) message.WriteError![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, TX_ABORT_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytesU16(allocator, msg.data);
    return w.toOwned(allocator);
}

// ── splice_locked (77) — no tlv_stream ──────────────────────────────────

pub const SPLICE_LOCKED_TYPE: u16 = 77;

pub const SpliceLocked = struct {
    channel_id: ChannelId,
    splice_txid: Sha256,

    pub fn deinit(_: *SpliceLocked, _: Allocator) void {}
};

pub fn decodeSpliceLocked(bytes: []const u8) message.FrameError!SpliceLocked {
    var r = try message.openFrame(bytes, SPLICE_LOCKED_TYPE);
    return .{ .channel_id = try r.takeArray(32), .splice_txid = try r.takeArray(32) };
}

pub fn serializeSpliceLocked(allocator: Allocator, msg: SpliceLocked) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, SPLICE_LOCKED_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytes(allocator, &msg.splice_txid);
    return w.toOwned(allocator);
}

// ── splice_init (80) / splice_ack (81) ──────────────────────────────────

pub const SPLICE_INIT_TYPE: u16 = 80;
pub const SPLICE_ACK_TYPE: u16 = 81;
const splice_known_tlv = [_]u64{TLV_REQUIRE_CONFIRMED_INPUTS};
const splice_rules = [_]Rule{.{ .t = TLV_REQUIRE_CONFIRMED_INPUTS, .len = 0 }};

pub const SpliceInit = struct {
    channel_id: ChannelId,
    /// Satoshis the sender adds to (positive) or removes from (negative) the channel.
    funding_contribution_satoshis: i64,
    funding_feerate_perkw: u32,
    locktime: u32,
    funding_pubkey: Point,
    extension: Extension = .{},

    pub fn deinit(self: *SpliceInit, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    pub fn requireConfirmedInputs(self: SpliceInit) bool {
        return self.extension.find(TLV_REQUIRE_CONFIRMED_INPUTS) != null;
    }
};

pub fn decodeSpliceInit(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!SpliceInit {
    var r = try message.openFrame(bytes, SPLICE_INIT_TYPE);
    var m: SpliceInit = undefined;
    m.channel_id = try r.takeArray(32);
    m.funding_contribution_satoshis = @bitCast(try r.u64be());
    m.funding_feerate_perkw = try r.u32be();
    m.locktime = try r.u32be();
    m.funding_pubkey = try readPoint(&r);
    m.extension = try message.decodeExtension(allocator, r.rest(), &splice_known_tlv);
    errdefer m.extension.deinit(allocator);
    try checkLengths(m.extension, &splice_rules);
    return m;
}

pub fn serializeSpliceInit(allocator: Allocator, msg: SpliceInit) (Allocator.Error || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &splice_rules);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, SPLICE_INIT_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, @bitCast(msg.funding_contribution_satoshis));
    try w.putU32be(allocator, msg.funding_feerate_perkw);
    try w.putU32be(allocator, msg.locktime);
    try w.putBytes(allocator, &msg.funding_pubkey);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

pub const SpliceAck = struct {
    channel_id: ChannelId,
    funding_contribution_satoshis: i64,
    funding_pubkey: Point,
    extension: Extension = .{},

    pub fn deinit(self: *SpliceAck, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    pub fn requireConfirmedInputs(self: SpliceAck) bool {
        return self.extension.find(TLV_REQUIRE_CONFIRMED_INPUTS) != null;
    }
};

pub fn decodeSpliceAck(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!SpliceAck {
    var r = try message.openFrame(bytes, SPLICE_ACK_TYPE);
    var m: SpliceAck = undefined;
    m.channel_id = try r.takeArray(32);
    m.funding_contribution_satoshis = @bitCast(try r.u64be());
    m.funding_pubkey = try readPoint(&r);
    m.extension = try message.decodeExtension(allocator, r.rest(), &splice_known_tlv);
    errdefer m.extension.deinit(allocator);
    try checkLengths(m.extension, &splice_rules);
    return m;
}

pub fn serializeSpliceAck(allocator: Allocator, msg: SpliceAck) (Allocator.Error || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &splice_rules);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, SPLICE_ACK_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU64be(allocator, @bitCast(msg.funding_contribution_satoshis));
    try w.putBytes(allocator, &msg.funding_pubkey);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

// ── closing_complete (40) / closing_sig (41) ────────────────────────────

pub const CLOSING_COMPLETE_TYPE: u16 = 40;
pub const CLOSING_SIG_TYPE: u16 = 41;
const closing_known_tlv = [_]u64{ TLV_CLOSER_OUTPUT_ONLY, TLV_CLOSEE_OUTPUT_ONLY, TLV_CLOSER_AND_CLOSEE_OUTPUTS };
const closing_rules = [_]Rule{
    .{ .t = TLV_CLOSER_OUTPUT_ONLY, .len = 64 },
    .{ .t = TLV_CLOSEE_OUTPUT_ONLY, .len = 64 },
    .{ .t = TLV_CLOSER_AND_CLOSEE_OUTPUTS, .len = 64 },
};

/// The two messages share one layout (and one `closing_tlvs`): `closing_complete`
/// proposes a closing transaction with up to three signatures, `closing_sig`
/// answers with the one the closee chose. BOLT#2's "at least one signature" /
/// "exactly one" rules are the caller's.
pub const Closing = struct {
    channel_id: ChannelId,
    closer_scriptpubkey: []const u8,
    closee_scriptpubkey: []const u8,
    fee_satoshis: u64,
    locktime: u32,
    extension: Extension = .{},

    pub fn deinit(self: *Closing, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    fn sig(self: Closing, t: u64) ?Signature {
        const v = self.extension.find(t) orelse return null;
        return v[0..64].*;
    }

    /// `closer_output_only` (TLV 1): the signature over the transaction without the closee's output.
    pub fn closerOutputOnly(self: Closing) ?Signature {
        return self.sig(TLV_CLOSER_OUTPUT_ONLY);
    }

    /// `closee_output_only` (TLV 2).
    pub fn closeeOutputOnly(self: Closing) ?Signature {
        return self.sig(TLV_CLOSEE_OUTPUT_ONLY);
    }

    /// `closer_and_closee_outputs` (TLV 3).
    pub fn closerAndCloseeOutputs(self: Closing) ?Signature {
        return self.sig(TLV_CLOSER_AND_CLOSEE_OUTPUTS);
    }
};
pub const ClosingComplete = Closing;
pub const ClosingSig = Closing;

fn decodeClosing(allocator: Allocator, bytes: []const u8, t: u16) (DecodeError || TlvLengthError || Allocator.Error)!Closing {
    var r = try message.openFrame(bytes, t);
    var m: Closing = undefined;
    m.channel_id = try r.takeArray(32);
    m.closer_scriptpubkey = try r.bytesU16();
    m.closee_scriptpubkey = try r.bytesU16();
    m.fee_satoshis = try r.u64be();
    m.locktime = try r.u32be();
    m.extension = try message.decodeExtension(allocator, r.rest(), &closing_known_tlv);
    errdefer m.extension.deinit(allocator);
    try checkLengths(m.extension, &closing_rules);
    return m;
}

fn serializeClosing(allocator: Allocator, t: u16, msg: Closing) (message.WriteError || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &closing_rules);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, t);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putBytesU16(allocator, msg.closer_scriptpubkey);
    try w.putBytesU16(allocator, msg.closee_scriptpubkey);
    try w.putU64be(allocator, msg.fee_satoshis);
    try w.putU32be(allocator, msg.locktime);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}

pub fn decodeClosingComplete(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!ClosingComplete {
    return decodeClosing(allocator, bytes, CLOSING_COMPLETE_TYPE);
}

pub fn serializeClosingComplete(allocator: Allocator, msg: ClosingComplete) (message.WriteError || TlvLengthError)![]u8 {
    return serializeClosing(allocator, CLOSING_COMPLETE_TYPE, msg);
}

pub fn decodeClosingSig(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!ClosingSig {
    return decodeClosing(allocator, bytes, CLOSING_SIG_TYPE);
}

pub fn serializeClosingSig(allocator: Allocator, msg: ClosingSig) (message.WriteError || TlvLengthError)![]u8 {
    return serializeClosing(allocator, CLOSING_SIG_TYPE, msg);
}

// ── start_batch (127) ───────────────────────────────────────────────────

pub const START_BATCH_TYPE: u16 = 127;
const start_batch_known_tlv = [_]u64{TLV_BATCH_MESSAGE_TYPE};
const start_batch_rules = [_]Rule{.{ .t = TLV_BATCH_MESSAGE_TYPE, .len = 2 }};

pub const StartBatch = struct {
    channel_id: ChannelId,
    batch_size: u16,
    extension: Extension = .{},

    pub fn deinit(self: *StartBatch, allocator: Allocator) void {
        self.extension.deinit(allocator);
    }

    /// `message_type` (TLV 1): the type of the batched messages (132, `commitment_signed`).
    pub fn messageType(self: StartBatch) ?u16 {
        const v = self.extension.find(TLV_BATCH_MESSAGE_TYPE) orelse return null;
        return std.mem.readInt(u16, v[0..2], .big);
    }
};

pub fn decodeStartBatch(allocator: Allocator, bytes: []const u8) (DecodeError || TlvLengthError || Allocator.Error)!StartBatch {
    var r = try message.openFrame(bytes, START_BATCH_TYPE);
    const channel_id = try r.takeArray(32);
    const batch_size = try r.u16be();
    var extension = try message.decodeExtension(allocator, r.rest(), &start_batch_known_tlv);
    errdefer extension.deinit(allocator);
    try checkLengths(extension, &start_batch_rules);
    return .{ .channel_id = channel_id, .batch_size = batch_size, .extension = extension };
}

pub fn serializeStartBatch(allocator: Allocator, msg: StartBatch) (Allocator.Error || TlvLengthError)![]u8 {
    try checkLengths(msg.extension, &start_batch_rules);
    var w: Writer = .{};
    defer w.deinit(allocator);
    try message.putFrameType(&w, allocator, START_BATCH_TYPE);
    try w.putBytes(allocator, &msg.channel_id);
    try w.putU16be(allocator, msg.batch_size);
    try message.encodeExtension(&w, allocator, msg.extension);
    return w.toOwned(allocator);
}
