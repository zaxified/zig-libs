// SPDX-License-Identifier: MIT
//! Real-transaction anchors: round-trip + txid/wtxid byte-exact against the
//! externally-sourced fixtures in `tx_kat_vectors.zig`.

const std = @import("std");
const testing = std.testing;
const tx = @import("tx.zig");
const vectors = @import("tx_kat_vectors.zig");
const testutil = @import("testutil.zig");

test "known mainnet legacy tx (block 170): round-trip byte-exact, txid byte-exact" {
    const allocator = testing.allocator;
    const raw = try testutil.hexToBytesAlloc(allocator, vectors.legacy_raw_tx_hex);
    defer allocator.free(raw);
    const want_txid = testutil.hexToArray(32, vectors.legacy_txid_hex);

    var t = try tx.deserialize(allocator, raw);
    defer t.deinit(allocator);
    try testing.expectEqual(false, t.has_witness);
    try testing.expectEqual(@as(usize, 1), t.vin.len);
    try testing.expectEqual(@as(usize, 2), t.vout.len);

    const reser = try tx.serialize(allocator, t);
    defer allocator.free(reser);
    try testing.expectEqualSlices(u8, raw, reser);

    const got_txid = try t.txid(allocator);
    try testing.expectEqualSlices(u8, &want_txid, &got_txid);
}

test "known segwit tx (BIP143 Native-P2WPKH signed example): round-trip byte-exact, txid AND wtxid byte-exact" {
    const allocator = testing.allocator;
    const raw = try testutil.hexToBytesAlloc(allocator, vectors.segwit_raw_tx_hex);
    defer allocator.free(raw);
    const want_txid = testutil.hexToArray(32, vectors.segwit_txid_hex);
    const want_wtxid = testutil.hexToArray(32, vectors.segwit_wtxid_hex);

    var t = try tx.deserialize(allocator, raw);
    defer t.deinit(allocator);
    try testing.expectEqual(true, t.has_witness);
    try testing.expectEqual(@as(usize, 2), t.vin.len);
    try testing.expectEqual(@as(usize, 2), t.vout.len);
    try testing.expectEqual(@as(usize, 2), t.witness.len);
    // Input 0 (bare P2PK) carries no witness data; input 1 (P2WPKH) has a
    // 2-item stack (signature, pubkey).
    try testing.expectEqual(@as(usize, 0), t.witness[0].items.len);
    try testing.expectEqual(@as(usize, 2), t.witness[1].items.len);

    const reser = try tx.serialize(allocator, t);
    defer allocator.free(reser);
    try testing.expectEqualSlices(u8, raw, reser);

    const got_txid = try t.txid(allocator);
    const got_wtxid = try t.wtxid(allocator);
    try testing.expectEqualSlices(u8, &want_txid, &got_txid);
    try testing.expectEqualSlices(u8, &want_wtxid, &got_wtxid);
    try testing.expect(!std.mem.eql(u8, &got_txid, &got_wtxid));
}
