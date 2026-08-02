// SPDX-License-Identifier: MIT
//! lnwire — Lightning Network (BOLT#1/#2/#7) wire-message codec: the
//! BigSize varint + generic TLV stream (BOLT#1), the core channel
//! messages (BOLT#2), and the gossip messages + announcement-digest
//! helpers (BOLT#7). Parses untrusted wire bytes, fail-closed throughout
//! — see `SPEC.md` for the full scope/threat-model writeup.
//!
//! This module is the MESSAGE layer only. `bolt8` (sibling module) is
//! the transport layer underneath it (`Noise_XK` encryption + framing);
//! this module never touches a socket or a key.

const std = @import("std");

pub const tlv = @import("tlv.zig");
pub const message = @import("message.zig");
pub const bolt1 = @import("bolt1.zig");
pub const bolt2 = @import("bolt2.zig");
pub const bolt7 = @import("bolt7.zig");

pub const meta = .{
    .platform = .any, // pure transform over caller-owned byte slices, no I/O
    .role = .codec,
    .concurrency = .reentrant, // no shared/global state
    .model_after = "BOLT#1 (lightning/bolts, 'Base Protocol'), BOLT#2 ('Peer Protocol for Channel Management'), BOLT#7 ('P2P Node and Channel Discovery')",
    .deps = .{}, // std-only
};

// ── re-exports: BOLT#1 base wire ────────────────────────────────────────

pub const BigSizeError = tlv.BigSizeError;
pub const decodeBigSize = tlv.decodeBigSize;
pub const encodeBigSize = tlv.encodeBigSize;
pub const RawRecord = tlv.RawRecord;
pub const parseTlvStream = tlv.parseStream;
pub const Extension = message.Extension;

// ── re-exports: BOLT#1 setup/control messages ───────────────────────────

pub const Init = bolt1.Init;
pub const decodeInit = bolt1.decodeInit;
pub const serializeInit = bolt1.serializeInit;
pub const ErrorMsg = bolt1.ErrorMsg;
pub const decodeError = bolt1.decodeError;
pub const serializeError = bolt1.serializeError;
pub const decodeWarning = bolt1.decodeWarning;
pub const serializeWarning = bolt1.serializeWarning;
pub const Ping = bolt1.Ping;
pub const decodePing = bolt1.decodePing;
pub const serializePing = bolt1.serializePing;
pub const Pong = bolt1.Pong;
pub const decodePong = bolt1.decodePong;
pub const serializePong = bolt1.serializePong;

// ── re-exports: BOLT#2 channel messages ─────────────────────────────────

pub const OpenChannel = bolt2.OpenChannel;
pub const decodeOpenChannel = bolt2.decodeOpenChannel;
pub const serializeOpenChannel = bolt2.serializeOpenChannel;
pub const AcceptChannel = bolt2.AcceptChannel;
pub const decodeAcceptChannel = bolt2.decodeAcceptChannel;
pub const serializeAcceptChannel = bolt2.serializeAcceptChannel;
pub const FundingCreated = bolt2.FundingCreated;
pub const decodeFundingCreated = bolt2.decodeFundingCreated;
pub const serializeFundingCreated = bolt2.serializeFundingCreated;
pub const FundingSigned = bolt2.FundingSigned;
pub const decodeFundingSigned = bolt2.decodeFundingSigned;
pub const serializeFundingSigned = bolt2.serializeFundingSigned;
pub const ChannelReady = bolt2.ChannelReady;
pub const decodeChannelReady = bolt2.decodeChannelReady;
pub const serializeChannelReady = bolt2.serializeChannelReady;
pub const UpdateAddHtlc = bolt2.UpdateAddHtlc;
pub const decodeUpdateAddHtlc = bolt2.decodeUpdateAddHtlc;
pub const serializeUpdateAddHtlc = bolt2.serializeUpdateAddHtlc;
pub const UpdateFulfillHtlc = bolt2.UpdateFulfillHtlc;
pub const decodeUpdateFulfillHtlc = bolt2.decodeUpdateFulfillHtlc;
pub const serializeUpdateFulfillHtlc = bolt2.serializeUpdateFulfillHtlc;
pub const UpdateFailHtlc = bolt2.UpdateFailHtlc;
pub const decodeUpdateFailHtlc = bolt2.decodeUpdateFailHtlc;
pub const serializeUpdateFailHtlc = bolt2.serializeUpdateFailHtlc;
pub const CommitmentSigned = bolt2.CommitmentSigned;
pub const decodeCommitmentSigned = bolt2.decodeCommitmentSigned;
pub const serializeCommitmentSigned = bolt2.serializeCommitmentSigned;
pub const RevokeAndAck = bolt2.RevokeAndAck;
pub const decodeRevokeAndAck = bolt2.decodeRevokeAndAck;
pub const serializeRevokeAndAck = bolt2.serializeRevokeAndAck;
pub const UpdateFee = bolt2.UpdateFee;
pub const decodeUpdateFee = bolt2.decodeUpdateFee;
pub const serializeUpdateFee = bolt2.serializeUpdateFee;
pub const Shutdown = bolt2.Shutdown;
pub const decodeShutdown = bolt2.decodeShutdown;
pub const serializeShutdown = bolt2.serializeShutdown;
pub const ClosingSigned = bolt2.ClosingSigned;
pub const decodeClosingSigned = bolt2.decodeClosingSigned;
pub const serializeClosingSigned = bolt2.serializeClosingSigned;

// ── re-exports: BOLT#7 gossip messages ──────────────────────────────────

pub const ChannelAnnouncement = bolt7.ChannelAnnouncement;
pub const decodeChannelAnnouncement = bolt7.decodeChannelAnnouncement;
pub const serializeChannelAnnouncement = bolt7.serializeChannelAnnouncement;
pub const channelAnnouncementDigest = bolt7.channelAnnouncementDigest;
pub const NodeAnnouncement = bolt7.NodeAnnouncement;
pub const decodeNodeAnnouncement = bolt7.decodeNodeAnnouncement;
pub const serializeNodeAnnouncement = bolt7.serializeNodeAnnouncement;
pub const nodeAnnouncementDigest = bolt7.nodeAnnouncementDigest;
pub const ChannelUpdate = bolt7.ChannelUpdate;
pub const decodeChannelUpdate = bolt7.decodeChannelUpdate;
pub const serializeChannelUpdate = bolt7.serializeChannelUpdate;
pub const channelUpdateDigest = bolt7.channelUpdateDigest;
pub const QueryShortChannelIds = bolt7.QueryShortChannelIds;
pub const decodeQueryShortChannelIds = bolt7.decodeQueryShortChannelIds;
pub const serializeQueryShortChannelIds = bolt7.serializeQueryShortChannelIds;
pub const ReplyShortChannelIdsEnd = bolt7.ReplyShortChannelIdsEnd;
pub const decodeReplyShortChannelIdsEnd = bolt7.decodeReplyShortChannelIdsEnd;
pub const serializeReplyShortChannelIdsEnd = bolt7.serializeReplyShortChannelIdsEnd;
pub const QueryChannelRange = bolt7.QueryChannelRange;
pub const decodeQueryChannelRange = bolt7.decodeQueryChannelRange;
pub const serializeQueryChannelRange = bolt7.serializeQueryChannelRange;
pub const ReplyChannelRange = bolt7.ReplyChannelRange;
pub const decodeReplyChannelRange = bolt7.decodeReplyChannelRange;
pub const serializeReplyChannelRange = bolt7.serializeReplyChannelRange;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = tlv;
    _ = message;
    _ = bolt1;
    _ = bolt2;
    _ = bolt7;
    _ = @import("bolt2_kat_test.zig");
}
