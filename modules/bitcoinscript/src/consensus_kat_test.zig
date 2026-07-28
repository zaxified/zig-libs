// SPDX-License-Identifier: MIT
//! Runs `consensus_kat_vectors.zig`'s Bitcoin Core `script_assets_test.json`
//! entries through the SAME `verifyScript` entry point real spends use:
//! full transaction deserialization, every input's spent-output context
//! (BIP341 sighash commits to all of them), and the module's own witness
//! stack — not a simplified stand-in. Each vector's `success` witness MUST
//! verify and its `failure` witness (same tx/prevouts/flags) MUST fail;
//! this is what gives the KAT teeth (see `corrupt one byte` test below).

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const flags_mod = @import("flags.zig");
const vectors_mod = @import("consensus_kat_vectors.zig");

/// The exact `ScriptFlags` Bitcoin Core's `script_assets_test.json` lists
/// for every vector in `consensus_kat_vectors.zig` (flags string `P2SH,
/// DERSIG, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, NULLDUMMY,
/// TAPROOT` — verified against the raw JSON, not assumed).
const consensus_flags: flags_mod.ScriptFlags = .{
    .p2sh = true,
    .dersig = true,
    .checklocktimeverify = true,
    .checksequenceverify = true,
    .witness = true,
    .nulldummy = true,
    .taproot = true,
};

fn hexDecode(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len == 0) return &[_]u8{};
    const out = try a.alloc(u8, hex.len / 2);
    return try std.fmt.hexToBytes(out, hex);
}

/// Parses one raw serialized `TxOut` (8-byte LE value + CompactSize script
/// length + script bytes) — `script_assets_test.json`'s `prevouts` entries
/// are exactly this, not a whole transaction. `bitcointx.tx` doesn't
/// export a standalone `TxOut` decoder (a `TxOut` only ever otherwise
/// appears embedded in a full `Transaction`), so this is a thin
/// module-local re-implementation of the same 2-field layout.
fn decodePrevout(bytes: []const u8) !bitcointx.TxOut {
    if (bytes.len < 9) return error.Truncated;
    const value = std.mem.readInt(i64, bytes[0..8], .little);
    const len_r = try bitcointx.decodeCompactSize(bytes[8..]);
    const script_start = 8 + len_r.consumed;
    const script_len: usize = @intCast(len_r.value);
    if (bytes.len != script_start + script_len) return error.TrailingBytes;
    return .{ .value = value, .script_pubkey = bytes[script_start..] };
}

fn witnessSlice(a: std.mem.Allocator, hex_items: []const []const u8) ![][]const u8 {
    const out = try a.alloc([]const u8, hex_items.len);
    for (hex_items, 0..) |h, i| out[i] = try hexDecode(a, h);
    return out;
}

/// Runs `v` with `witness` (already-decoded bytes) substituted for the
/// input's witness stack (mirroring `script_assets_test.json` semantics:
/// the base `tx`'s own scriptSig/witness on the tested input are
/// placeholders, replaced by `success`/`failure` before verification).
/// Returns the `verifyScript` result so both the positive and negative
/// expectation can be asserted by the caller. Takes decoded bytes (not
/// hex) so the "teeth" test below can corrupt one raw byte directly,
/// without a lossy hex-encode round-trip.
fn runVectorBytes(a: std.mem.Allocator, v: vectors_mod.Vector, witness: []const []const u8) !void {
    const tx_bytes = try hexDecode(a, v.tx_hex);
    var tx = try bitcointx.deserialize(a, tx_bytes);
    defer tx.deinit(a);

    const spent_outputs = try a.alloc(bitcointx.TxOut, v.prevout_hexes.len);
    for (v.prevout_hexes, 0..) |ph, i| {
        const pb = try hexDecode(a, ph);
        spent_outputs[i] = try decodePrevout(pb);
    }
    try testing.expectEqual(tx.vin.len, spent_outputs.len);

    const ctx: txctx.TxContext = .{ .tx = tx, .input_index = v.index, .spent_outputs = spent_outputs };
    const script_pubkey = spent_outputs[v.index].script_pubkey;

    return verify.verifyScript(a, &.{}, script_pubkey, witness, consensus_flags, ctx);
}

fn runVector(a: std.mem.Allocator, v: vectors_mod.Vector, witness_hex: []const []const u8) !void {
    const witness = try witnessSlice(a, witness_hex);
    return runVectorBytes(a, v, witness);
}

test "BIP341/342 consensus vectors (bitcoin-core/qa-assets script_assets_test.json): success witness verifies" {
    for (vectors_mod.vectors) |v| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        runVector(arena.allocator(), v, v.success_witness) catch |err| {
            std.debug.print("\nCONSENSUS VECTOR MISMATCH (expected OK, got error.{s}): {s}\n", .{ @errorName(err), v.comment });
            return error.VectorMismatch;
        };
    }
}

test "BIP341/342 consensus vectors: failure witness (same tx/prevouts/flags) fails" {
    for (vectors_mod.vectors) |v| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        if (runVector(arena.allocator(), v, v.failure_witness)) |_| {
            std.debug.print("\nCONSENSUS VECTOR MISMATCH (expected failure, got OK): {s}\n", .{v.comment});
            return error.VectorMismatch;
        } else |_| {}
    }
}

test "teeth: corrupting one byte of a success witness makes it fail" {
    // Uses the smallest vector (single 65-byte Schnorr-sig witness item)
    // so a one-byte flip inside the signature can't accidentally still
    // parse as some OTHER valid witness -- proves this KAT can actually
    // detect a broken verifier, not just echo whatever bytes are given.
    const v = vectors_mod.vectors[0]; // siglen_empty_keypath

    // First, the un-corrupted control: the vector's real success witness
    // must still verify (guards against the corruption step below being
    // silently skipped).
    {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const good_witness = try witnessSlice(a, v.success_witness);
        try runVectorBytes(a, v, good_witness);
    }

    // Now flip one byte of the signature and confirm it fails closed.
    {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const witness = try witnessSlice(a, v.success_witness);
        const sig = @constCast(witness[0]);
        sig[0] ^= 0x01; // flip one bit of the signature's first byte
        const result = runVectorBytes(a, v, witness);
        try testing.expect(if (result) |_| false else |_| true);
    }
}
