// SPDX-License-Identifier: MIT
//! BIP341 key-path sighash: byte-exact against the official
//! `bip-0341/wallet-test-vectors.json` `keyPathSpending` vectors
//! (`bip341_kat_vectors.zig`) -- both the SigMsg (with its leading epoch
//! byte, see `sighash_bip341.zig`) and the final TapSighash, across all 7
//! hashType combinations the fixture covers.

const std = @import("std");
const testing = std.testing;
const tx = @import("tx.zig");
const bip341 = @import("sighash_bip341.zig");
const vectors = @import("bip341_kat_vectors.zig");
const testutil = @import("testutil.zig");

test "BIP341 keyPathSpending: SigMsg and sighash byte-exact for every hashType combination" {
    const allocator = testing.allocator;
    const raw = try testutil.hexToBytesAlloc(allocator, vectors.raw_unsigned_tx_hex);
    defer allocator.free(raw);

    var t = try tx.deserialize(allocator, raw);
    defer t.deinit(allocator);
    try testing.expectEqual(false, t.has_witness);
    try testing.expectEqual(vectors.utxos_spent.len, t.vin.len);

    var spent = try allocator.alloc(tx.TxOut, vectors.utxos_spent.len);
    defer allocator.free(spent);
    var scripts = try allocator.alloc([]u8, vectors.utxos_spent.len);
    defer {
        for (scripts) |s| allocator.free(s);
        allocator.free(scripts);
    }
    for (vectors.utxos_spent, 0..) |u, i| {
        scripts[i] = try testutil.hexToBytesAlloc(allocator, u.script_pubkey_hex);
        spent[i] = .{ .value = u.amount_sats, .script_pubkey = scripts[i] };
    }

    for (vectors.input_cases) |c| {
        const got_msg = try bip341.sigMsg(allocator, t, c.input_index, c.hash_type, spent);
        defer allocator.free(got_msg);
        const want_msg = try testutil.hexToBytesAlloc(allocator, c.expected_sig_msg_hex);
        defer allocator.free(want_msg);
        testing.expectEqualSlices(u8, want_msg, got_msg) catch |err| {
            std.debug.print("FAILED sigMsg: input_index={d} hash_type=0x{x:0>2}\n", .{ c.input_index, c.hash_type });
            return err;
        };

        const got_sighash = try bip341.sighash(allocator, t, c.input_index, c.hash_type, spent);
        const want_sighash = testutil.hexToArray(32, c.expected_sighash_hex);
        testing.expectEqualSlices(u8, &want_sighash, &got_sighash) catch |err| {
            std.debug.print("FAILED sighash: input_index={d} hash_type=0x{x:0>2}\n", .{ c.input_index, c.hash_type });
            return err;
        };
    }
}
