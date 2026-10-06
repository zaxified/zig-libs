// SPDX-License-Identifier: MIT
// Vendored from `lightningdevkit/rust-lightning`'s `lightning/src/ln/msgs.rs`
// test module -- see modules/lnwire/NOTICE for the required MIT/Apache-2.0
// attribution. Do not hand-edit the vector bodies below; regenerate instead
// if the upstream file changes.
//!
//! `channel_reestablish` and `update_fail_malformed_htlc` byte-exact wire
//! vectors, from rust-lightning's `encoding_channel_reestablish`,
//! `encoding_channel_reestablish_with_next_funding_txid`,
//! `encoding_channel_reestablish_with_funding_locked_txid` and
//! `encoding_update_fail_malformed_htlc` tests (msgs.rs at `main` commit
//! `15c5d9b8459e852f2b33586e586e3e90307114ee`, fetched 2026-10-06). Every
//! upstream case is vendored; none synthesized.
//!
//! The three `channel_reestablish` tests assert `encode()` against a
//! DECIMAL `vec![...]` literal; each was converted to hex mechanically (a
//! regex over the literal, comments stripped, every value checked to be
//! 0..255) and its length checked against BOLT#2's fixed part (113 octets)
//! plus the TLV record (35). The per-field values below are the struct
//! literal's own (`next_local_commitment_number: 3`, `[9; 32]`, the
//! `Txid::from_raw_hash(..from_slice(&[..]))` bytes, `retransmit_flags: 1`),
//! not sliced out of the hex, so the field-by-field assertions are a second,
//! independent reading. `my_current_per_commitment_point` is the public key of
//! secret `0x01 * 32`, the same key `bolt7_announcement_update_kat_vectors.zig`
//! carries as `node_id`.
//!
//! IMPORTANT -- no message-type prefix (same convention as the sibling
//! vector files): `.encode()` emits only the message's own fields.
//!
//! ⚠ `update_fail_malformed_htlc`'s upstream `failure_code` is 255, which
//! has no `BADONION` bit: a message BOLT#2 requires a receiver to FAIL. The
//! vector therefore anchors the wire LAYOUT (through `bolt2.zig`'s private
//! layout codec) and is also the external case `decodeUpdateFailMalformedHtlc`
//! must refuse.

pub const ChannelReestablishVector = struct {
    description: []const u8,
    /// Full expected wire bytes, BOLT#1's 2-byte `type` field NOT included.
    payload_hex: []const u8,
    channel_id_hex: []const u8,
    /// rust-lightning `next_local_commitment_number` = BOLT#2 `next_commitment_number`.
    next_commitment_number: u64,
    /// rust-lightning `next_remote_commitment_number` = BOLT#2 `next_revocation_number`.
    next_revocation_number: u64,
    your_last_per_commitment_secret_hex: []const u8,
    my_current_per_commitment_point_hex: []const u8,
    /// `next_funding` (TLV 1): txid hex + retransmit_flags, or null.
    next_funding_txid_hex: ?[]const u8,
    next_funding_flags: u8,
    /// `my_current_funding_locked` (TLV 5): txid hex + retransmit_flags, or null.
    funding_locked_txid_hex: ?[]const u8,
    funding_locked_flags: u8,
};

const reestablish_channel_id = "0400000000000000050000000000000006000000000000000700000000000000";
const reestablish_secret = "0909090909090909090909090909090909090909090909090909090909090909";
const reestablish_point = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";

pub const channel_reestablish_vectors = [_]ChannelReestablishVector{
    .{
        .description = "encoding_channel_reestablish: no TLVs",
        .payload_hex = "0400000000000000050000000000000006000000000000000700000000000000000000000000000300000000000000040909090909090909090909090909090909090909090909090909090909090909031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        .channel_id_hex = reestablish_channel_id,
        .next_commitment_number = 3,
        .next_revocation_number = 4,
        .your_last_per_commitment_secret_hex = reestablish_secret,
        .my_current_per_commitment_point_hex = reestablish_point,
        .next_funding_txid_hex = null,
        .next_funding_flags = 0,
        .funding_locked_txid_hex = null,
        .funding_locked_flags = 0,
    },
    .{
        .description = "encoding_channel_reestablish_with_next_funding_txid: next_funding (TLV 1)",
        .payload_hex = "0400000000000000050000000000000006000000000000000700000000000000000000000000000300000000000000040909090909090909090909090909090909090909090909090909090909090909031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f012130a7fa45983067aca4633b13170b5c540f50040c62524b1fc90b5b176217357c01",
        .channel_id_hex = reestablish_channel_id,
        .next_commitment_number = 3,
        .next_revocation_number = 4,
        .your_last_per_commitment_secret_hex = reestablish_secret,
        .my_current_per_commitment_point_hex = reestablish_point,
        .next_funding_txid_hex = "30a7fa45983067aca4633b13170b5c540f50040c62524b1fc90b5b176217357c",
        .next_funding_flags = 1,
        .funding_locked_txid_hex = null,
        .funding_locked_flags = 0,
    },
    .{
        .description = "encoding_channel_reestablish_with_funding_locked_txid: my_current_funding_locked (TLV 5)",
        .payload_hex = "0400000000000000050000000000000006000000000000000700000000000000000000000000000300000000000000040909090909090909090909090909090909090909090909090909090909090909031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f052115a7fa45983067aca4633b13170b5c540f50040c62524b1fc90b5b176217357c01",
        .channel_id_hex = reestablish_channel_id,
        .next_commitment_number = 3,
        .next_revocation_number = 4,
        .your_last_per_commitment_secret_hex = reestablish_secret,
        .my_current_per_commitment_point_hex = reestablish_point,
        .next_funding_txid_hex = null,
        .next_funding_flags = 0,
        .funding_locked_txid_hex = "15a7fa45983067aca4633b13170b5c540f50040c62524b1fc90b5b176217357c",
        .funding_locked_flags = 1,
    },
};

pub const UpdateFailMalformedHtlcVector = struct {
    payload_hex: []const u8,
    channel_id_hex: []const u8,
    /// rust-lightning `htlc_id`.
    id: u64,
    sha256_of_onion_hex: []const u8,
    failure_code: u16,
};

/// `encoding_update_fail_malformed_htlc`: `channel_id: [2; 32]`,
/// `htlc_id: 2316138423780173`, `sha256_of_onion: [1; 32]`, `failure_code: 255`.
pub const update_fail_malformed_htlc_vector: UpdateFailMalformedHtlcVector = .{
    .payload_hex = "020202020202020202020202020202020202020202020202020202020202020200083a840000034d010101010101010101010101010101010101010101010101010101010101010100ff",
    .channel_id_hex = "0202020202020202020202020202020202020202020202020202020202020202",
    .id = 2316138423780173,
    .sha256_of_onion_hex = "0101010101010101010101010101010101010101010101010101010101010101",
    .failure_code = 255,
};
