// SPDX-License-Identifier: MIT
//! BIP143: byte-exact against BIP143's own published worked examples
//! (`bip143_kat_vectors.zig`) -- the intermediate hashPrevouts/hashSequence/
//! hashOutputs midstates, the full preimage, AND the final sighash.

const std = @import("std");
const testing = std.testing;
const tx = @import("tx.zig");
const bip143 = @import("sighash_bip143.zig");
const vectors = @import("bip143_kat_vectors.zig");
const testutil = @import("testutil.zig");

test "BIP143 worked examples: intermediates, preimage, and sighash all byte-exact" {
    const allocator = testing.allocator;
    for (vectors.examples) |ex| {
        const raw = try testutil.hexToBytesAlloc(allocator, ex.unsigned_raw_tx_hex);
        defer allocator.free(raw);
        const script_code = try testutil.hexToBytesAlloc(allocator, ex.script_code_hex);
        defer allocator.free(script_code);

        var t = try tx.deserialize(allocator, raw);
        defer t.deinit(allocator);
        // The published examples' unsigned tx has empty scriptSigs and no
        // witness marker -- decodes as plain legacy form.
        try testing.expectEqual(false, t.has_witness);

        const mid = try bip143.midstates(allocator, t, ex.input_index, ex.hash_type);
        const want_prevouts = testutil.hexToArray(32, ex.hash_prevouts_hex);
        const want_sequence = testutil.hexToArray(32, ex.hash_sequence_hex);
        const want_outputs = testutil.hexToArray(32, ex.hash_outputs_hex);
        testing.expectEqualSlices(u8, &want_prevouts, &mid.hash_prevouts) catch |err| {
            std.debug.print("FAILED hashPrevouts for {s}\n", .{ex.name});
            return err;
        };
        testing.expectEqualSlices(u8, &want_sequence, &mid.hash_sequence) catch |err| {
            std.debug.print("FAILED hashSequence for {s}\n", .{ex.name});
            return err;
        };
        testing.expectEqualSlices(u8, &want_outputs, &mid.hash_outputs) catch |err| {
            std.debug.print("FAILED hashOutputs for {s}\n", .{ex.name});
            return err;
        };

        const pre = try bip143.preimage(allocator, t, ex.input_index, script_code, ex.amount_sats, ex.hash_type);
        defer allocator.free(pre);
        const want_preimage = try testutil.hexToBytesAlloc(allocator, ex.preimage_hex);
        defer allocator.free(want_preimage);
        testing.expectEqualSlices(u8, want_preimage, pre) catch |err| {
            std.debug.print("FAILED preimage for {s}\n", .{ex.name});
            return err;
        };

        const got_sighash = try bip143.sighash(allocator, t, ex.input_index, script_code, ex.amount_sats, ex.hash_type);
        const want_sighash = testutil.hexToArray(32, ex.sighash_hex);
        testing.expectEqualSlices(u8, &want_sighash, &got_sighash) catch |err| {
            std.debug.print("FAILED sighash for {s}\n", .{ex.name});
            return err;
        };
    }
}
