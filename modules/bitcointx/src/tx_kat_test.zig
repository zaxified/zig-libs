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

const mv = @import("merkle_kat_vectors.zig");

fn expectSizes(comptime name: []const u8, hex: []const u8, coinbase: bool, witness: bool) !void {
    const allocator = testing.allocator;
    const raw = try testutil.hexToBytesAlloc(allocator, hex);
    defer allocator.free(raw);
    var t = try tx.deserialize(allocator, raw);
    defer t.deinit(allocator);
    try testing.expectEqual(@field(mv, "tx_" ++ name ++ "_base_size"), t.baseSize());
    try testing.expectEqual(@field(mv, "tx_" ++ name ++ "_total_size"), try t.totalSize());
    try testing.expectEqual(@field(mv, "tx_" ++ name ++ "_weight"), try t.weight());
    try testing.expectEqual(@field(mv, "tx_" ++ name ++ "_vsize"), try t.vsize());
    try testing.expectEqual(coinbase, t.isCoinbase());
    try testing.expectEqual(witness, t.hasWitnessData());
    // The arithmetic sizes agree with the serializers.
    const legacy = try tx.serializeLegacy(allocator, t);
    defer allocator.free(legacy);
    try testing.expectEqual(legacy.len, t.baseSize());
    const full = try tx.serialize(allocator, t);
    defer allocator.free(full);
    try testing.expectEqual(full.len, try t.totalSize());
    try testing.expectEqual(raw.len, full.len);
}

// Weights and sizes: the blockstream.info explorer's reported `size`/`weight` for the
// mainnet transactions named in tools/gen_merkle_vectors.py (Core's GetTransactionWeight).
test "weight/vsize/baseSize/totalSize: real mainnet transactions (segwit odd weight, 3-in segwit, legacy)" {
    try expectSizes("segwit_1in1out", mv.tx_segwit_1in1out_hex, false, true);
    try expectSizes("segwit_3in3out", mv.tx_segwit_3in3out_hex, false, true);
    try expectSizes("legacy_5in", mv.tx_legacy_5in_hex, false, false);
    // 533 / 4 rounds UP to 134 (not 133).
    try testing.expectEqual(@as(usize, 533), mv.tx_segwit_1in1out_weight);
    try testing.expectEqual(@as(usize, 134), mv.tx_segwit_1in1out_vsize);
}

test "weight: BIP143 native P2WPKH example and block-170 legacy transaction" {
    const allocator = testing.allocator;
    const raw = try testutil.hexToBytesAlloc(allocator, vectors.segwit_raw_tx_hex);
    defer allocator.free(raw);
    var t = try tx.deserialize(allocator, raw);
    defer t.deinit(allocator);
    try testing.expectEqual(raw.len, try t.totalSize());
    const legacy = try tx.serializeLegacy(allocator, t);
    defer allocator.free(legacy);
    try testing.expectEqual(legacy.len * 3 + raw.len, try t.weight());
    try testing.expect(raw.len > legacy.len);

    const raw2 = try testutil.hexToBytesAlloc(allocator, vectors.legacy_raw_tx_hex);
    defer allocator.free(raw2);
    var t2 = try tx.deserialize(allocator, raw2);
    defer t2.deinit(allocator);
    // Legacy: weight is exactly 4x the size, vsize == size.
    try testing.expectEqual(raw2.len * 4, try t2.weight());
    try testing.expectEqual(raw2.len, try t2.vsize());
}

test "totalSize: has_witness with all-empty stacks is the legacy size; a mismatched hand-built value errors" {
    const ins = [_]tx.TxIn{.{ .prevout = .{ .txid = @splat(7), .vout = 1 }, .script_sig = "ab", .sequence = 5 }};
    const outs = [_]tx.TxOut{.{ .value = 1, .script_pubkey = "xyz" }};
    var stacks = [_]tx.Witness{.{ .items = &.{} }};
    var t: tx.Transaction = .{
        .version = 2,
        .vin = @constCast(&ins),
        .vout = @constCast(&outs),
        .witness = &stacks,
        .locktime = 9,
        .has_witness = true,
    };
    try testing.expectEqual(t.baseSize(), try t.totalSize());
    try testing.expectEqual(t.baseSize() * 4, try t.weight());
    var item = [_][]const u8{ "q", "" };
    stacks[0].items = &item;
    // marker+flag (2) + count (1) + item1 (1+1) + item2 (1+0)
    try testing.expectEqual(t.baseSize() + 2 + 1 + 2 + 1, try t.totalSize());
    t.witness = &.{};
    try testing.expectEqual(t.baseSize(), try t.totalSize()); // no witness data: legacy
    t.witness = &stacks;
    t.vin = &.{};
    try testing.expectError(error.WitnessCountMismatch, t.totalSize());
    try testing.expectError(error.WitnessCountMismatch, t.weight());
    try testing.expectError(error.WitnessCountMismatch, t.vsize());
}

test "isCoinbase: needs exactly one input with the null prevout" {
    const allocator = testing.allocator;
    // Genesis coinbase from the block fixture.
    const raw = try testutil.hexToBytesAlloc(allocator, mv.genesis_hex);
    defer allocator.free(raw);
    var t = try tx.deserialize(allocator, raw[81..]);
    defer t.deinit(allocator);
    try testing.expect(t.isCoinbase());
    const zero: [32]u8 = @splat(0);
    var buf: [2]tx.TxIn = undefined;
    const mk = struct {
        fn f(b: *[2]tx.TxIn, id: [32]u8, vout: u32, n: usize) tx.Transaction {
            const one: tx.TxIn = .{ .prevout = .{ .txid = id, .vout = vout }, .script_sig = "", .sequence = 0 };
            b.* = @splat(one);
            return .{ .version = 1, .vin = b[0..n], .vout = &.{}, .witness = &.{}, .locktime = 0, .has_witness = false };
        }
    }.f;
    try testing.expect(mk(&buf, zero, 0xffffffff, 1).isCoinbase());
    try testing.expect(!mk(&buf, zero, 0xffffffff, 2).isCoinbase()); // two inputs
    try testing.expect(!mk(&buf, zero, 0xffffffff, 0).isCoinbase()); // none
    try testing.expect(!mk(&buf, zero, 0, 1).isCoinbase()); // index not null
    try testing.expect(!mk(&buf, zero, 0xfffffffe, 1).isCoinbase());
    var id = zero;
    id[31] = 1;
    try testing.expect(!mk(&buf, id, 0xffffffff, 1).isCoinbase()); // hash not null (last octet)
    id = zero;
    id[0] = 1;
    try testing.expect(!mk(&buf, id, 0xffffffff, 1).isCoinbase()); // first octet
}

test "sizes agree with the serializers across every CompactSize width (253+ inputs, outputs, script and witness lengths)" {
    const allocator = testing.allocator;
    const big = try allocator.alloc(u8, 300);
    defer allocator.free(big);
    @memset(big, 0x5a);
    const n_in: usize = 253;
    const ins = try allocator.alloc(tx.TxIn, n_in);
    defer allocator.free(ins);
    for (ins, 0..) |*i, k| i.* = .{
        .prevout = .{ .txid = @splat(@truncate(k + 1)), .vout = @truncate(k) },
        .script_sig = big[0..if (k == 0) 300 else k % 3],
        .sequence = 1,
    };
    const outs = try allocator.alloc(tx.TxOut, 253);
    defer allocator.free(outs);
    for (outs, 0..) |*o, k| o.* = .{ .value = 1, .script_pubkey = big[0..if (k == 0) 253 else 0] };
    const stacks = try allocator.alloc(tx.Witness, n_in);
    defer allocator.free(stacks);
    const many = try allocator.alloc([]const u8, 253);
    defer allocator.free(many);
    for (many, 0..) |*m, k| m.* = big[0..if (k == 0) 300 else 0];
    for (stacks, 0..) |*w, k| w.* = .{ .items = if (k == 0) many else many[0..1] };
    var t: tx.Transaction = .{ .version = 1, .vin = ins, .vout = outs, .witness = stacks, .locktime = 0, .has_witness = true };
    const legacy = try tx.serializeLegacy(allocator, t);
    defer allocator.free(legacy);
    const full = try tx.serializeSegwit(allocator, t);
    defer allocator.free(full);
    try testing.expectEqual(legacy.len, t.baseSize());
    try testing.expectEqual(full.len, try t.totalSize());
    try testing.expectEqual(legacy.len * 3 + full.len, try t.weight());
    try testing.expectEqual((legacy.len * 3 + full.len + 3) / 4, try t.vsize());
    // 252 / 253 boundaries of the three counts individually.
    t.vin = ins[0..252];
    t.vout = outs[0..252];
    t.witness = stacks[0..252];
    const l2 = try tx.serializeLegacy(allocator, t);
    defer allocator.free(l2);
    const f2 = try tx.serializeSegwit(allocator, t);
    defer allocator.free(f2);
    try testing.expectEqual(l2.len, t.baseSize());
    try testing.expectEqual(f2.len, try t.totalSize());
}
