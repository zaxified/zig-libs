// SPDX-License-Identifier: MIT
// Vendored from `lightningdevkit/rust-lightning`'s `lightning/src/ln/msgs.rs`
// test module -- see modules/lnwire/NOTICE for the required MIT/Apache-2.0
// attribution. Do not hand-edit the vector bodies below; regenerate instead
// if the upstream file changes.
//!
//! `announcement_signatures` and `gossip_timestamp_filter` byte-exact wire
//! vectors, from rust-lightning's `encoding_announcement_signatures` and
//! `encoding_gossip_timestamp_filter` tests (msgs.rs at `main` commit
//! `15c5d9b8459e852f2b33586e586e3e90307114ee`, fetched 2026-10-06). Both
//! upstream tests assert one hex literal, copied verbatim.
//!
//! Field values: `channel_id`, `short_channel_id: 2316138423780173`,
//! `chain_hash = ChainHash::using_genesis_block(Network::Regtest)`,
//! `first_timestamp: 1590000000`, `timestamp_range: 0xffff_ffff` are the
//! struct literals'. The two signatures are computed upstream at test time
//! (ECDSA by secret `0x01 * 32` over "0101…"/"0202…"), so their bytes here
//! are sliced out of the hex at BOLT#7's offsets — but `node_signature` is
//! the same signature (same key, same message) that
//! `bolt7_announcement_update_kat_vectors.zig` carries as
//! `node_announcement`'s `signature_hex`, which pins those offsets from a
//! second upstream test.
//!
//! IMPORTANT -- no message-type prefix (same convention as the sibling
//! vector files).

pub const AnnouncementSignaturesVector = struct {
    payload_hex: []const u8,
    channel_id_hex: []const u8,
    short_channel_id: u64,
    node_signature_hex: []const u8,
    bitcoin_signature_hex: []const u8,
};

pub const announcement_signatures_vector: AnnouncementSignaturesVector = .{
    .payload_hex = "040000000000000005000000000000000600000000000000070000000000000000083a840000034dd977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073acf9953cef4700860f5967838eba2bae89288ad188ebf8b20bf995c3ea53a26df1876d0a3a0e13172ba286a673140190c02ba9da60a2e43a745188c8a83c7f3ef",
    .channel_id_hex = "0400000000000000050000000000000006000000000000000700000000000000",
    .short_channel_id = 2316138423780173,
    .node_signature_hex = "d977cb9b53d93a6ff64bb5f1e158b4094b66e798fb12911168a3ccdf80a83096340a6a95da0ae8d9f776528eecdbb747eb6b545495a4319ed5378e35b21e073a",
    .bitcoin_signature_hex = "cf9953cef4700860f5967838eba2bae89288ad188ebf8b20bf995c3ea53a26df1876d0a3a0e13172ba286a673140190c02ba9da60a2e43a745188c8a83c7f3ef",
};

pub const GossipTimestampFilterVector = struct {
    payload_hex: []const u8,
    chain_hash_hex: []const u8,
    first_timestamp: u32,
    timestamp_range: u32,
};

pub const gossip_timestamp_filter_vector: GossipTimestampFilterVector = .{
    .payload_hex = "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f5ec57980ffffffff",
    // Bitcoin regtest genesis block hash, internal byte order.
    .chain_hash_hex = "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
    .first_timestamp = 1590000000,
    .timestamp_range = 0xffff_ffff,
};
