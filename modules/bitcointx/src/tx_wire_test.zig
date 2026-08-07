// SPDX-License-Identifier: MIT
//! Runs every transaction in Bitcoin Core's `tx_valid.json` + `tx_invalid.json`
//! through this module's deserializer and serializer.
//!
//! The interesting assertion is NOT the round trip. A round trip only proves
//! our encoder and our decoder agree with each other. The oracle here is
//! Core's `prevouts` table: a hand-written `[txid, vout, scriptPubKey]` list
//! naming what each transaction spends, written from the transaction's meaning
//! rather than read off its bytes. Every outpoint our decoder reports has to be
//! in that table — a decoder that miscounts a `CompactSize`, reads `vout` at
//! the wrong offset, or gets txid byte order backwards round-trips perfectly
//! and fails this immediately.

const std = @import("std");
const testing = std.testing;
const tx = @import("tx.zig");
const testutil = @import("testutil.zig");
const vectors = @import("tx_wire_vectors.zig");

/// Core's JSON prints a prevout txid in RPC display order, byte-reversed
/// relative to the wire order `TxIn.prevout.txid` holds.
fn wireTxidFromDisplayHex(hex: []const u8) [32]u8 {
    const display = testutil.hexToArray(32, hex);
    var out: [32]u8 = undefined;
    for (display, 0..) |b, i| out[31 - i] = b;
    return out;
}

test "Core tx_valid/tx_invalid: all 213 transactions round-trip byte-exact" {
    const allocator = testing.allocator;
    var segwit: usize = 0;
    var legacy: usize = 0;
    var inputs: usize = 0;
    var outputs: usize = 0;
    for (vectors.vectors) |v| {
        const raw = try testutil.hexToBytesAlloc(allocator, v.tx_hex);
        defer allocator.free(raw);
        var t = tx.deserialize(allocator, raw) catch |err| {
            std.debug.print("\nTX WIRE: deserialize failed with error.{s} for: {s}\n", .{ @errorName(err), v.comment });
            return err;
        };
        defer t.deinit(allocator);
        const reser = try tx.serialize(allocator, t);
        defer allocator.free(reser);
        testing.expectEqualSlices(u8, raw, reser) catch |err| {
            std.debug.print("\nTX WIRE: round trip differs for: {s}\n", .{v.comment});
            return err;
        };
        if (t.has_witness) segwit += 1 else legacy += 1;
        inputs += t.vin.len;
        outputs += t.vout.len;
    }
    // Corpus-shape sanity, so a truncated vectors file cannot pass with no
    // coverage. Counted on upstream v29.0: 120 + 93 data rows, 41 of which
    // carry the BIP144 marker.
    try testing.expectEqual(@as(usize, 213), vectors.vectors.len);
    try testing.expectEqual(@as(usize, 41), segwit);
    try testing.expectEqual(@as(usize, 172), legacy);
    // Well past the two transactions this module's wire anchor used to be.
    try testing.expect(inputs > 250);
    try testing.expect(outputs > 200);
}

test "Core tx_valid/tx_invalid: every decoded outpoint matches Core's own prevout table" {
    const allocator = testing.allocator;
    var checked: usize = 0;
    for (vectors.vectors) |v| {
        const raw = try testutil.hexToBytesAlloc(allocator, v.tx_hex);
        defer allocator.free(raw);
        var t = try tx.deserialize(allocator, raw);
        defer t.deinit(allocator);
        for (t.vin) |in| {
            var found = false;
            for (v.prevouts) |p| {
                if (p.vout != in.prevout.vout) continue;
                if (!std.mem.eql(u8, &wireTxidFromDisplayHex(p.txid_hex), &in.prevout.txid)) continue;
                found = true;
                break;
            }
            if (!found) {
                std.debug.print(
                    "\nTX WIRE: decoded outpoint vout={d} is not in Core's prevout table for: {s}\n",
                    .{ in.prevout.vout, v.comment },
                );
                return error.OutpointNotInCoreTable;
            }
            checked += 1;
        }
    }
    // Every input of every row, not a sample.
    try testing.expect(checked > 250);
}

test "the wire corpus reaches the CompactSize and marker edges it claims to" {
    // A corpus of 213 one-input legacy transactions would be green while
    // proving nothing about the varint or BIP144 paths. Pin what is actually
    // in it, measured by decoding — not by reading the hex.
    const allocator = testing.allocator;
    var max_vin: usize = 0;
    var max_vout: usize = 0;
    var max_script: usize = 0;
    var empty_witness_stacks: usize = 0;
    var nonempty_witness_stacks: usize = 0;
    var nonzero_locktime: usize = 0;
    var nonfinal_sequence: usize = 0;
    for (vectors.vectors) |v| {
        const raw = try testutil.hexToBytesAlloc(allocator, v.tx_hex);
        defer allocator.free(raw);
        var t = try tx.deserialize(allocator, raw);
        defer t.deinit(allocator);
        max_vin = @max(max_vin, t.vin.len);
        max_vout = @max(max_vout, t.vout.len);
        for (t.vin) |in| {
            max_script = @max(max_script, in.script_sig.len);
            if (in.sequence != 0xffffffff) nonfinal_sequence += 1;
        }
        for (t.vout) |o| max_script = @max(max_script, o.script_pubkey.len);
        for (t.witness) |w| {
            if (w.items.len == 0) empty_witness_stacks += 1 else nonempty_witness_stacks += 1;
        }
        if (t.locktime != 0) nonzero_locktime += 1;
    }
    // A script longer than 252 bytes forces the 0xfd CompactSize form.
    try testing.expect(max_script > 252);
    // Multi-input and multi-output rows exercise the count varints.
    try testing.expect(max_vin >= 3);
    try testing.expect(max_vout >= 2);
    // BIP144: a segwit transaction serializes a stack for EVERY input,
    // including the ones with nothing in it.
    try testing.expect(empty_witness_stacks > 0);
    try testing.expect(nonempty_witness_stacks > 0);
    // Without these two, the whole BIP65/BIP112 side of the corpus would be
    // decoding into fields nothing ever reads.
    try testing.expect(nonzero_locktime > 20);
    try testing.expect(nonfinal_sequence > 20);
}
