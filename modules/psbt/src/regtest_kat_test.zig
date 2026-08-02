// SPDX-License-Identifier: MIT
//! Native P2WPKH finalize/extract, anchored on a real Bitcoin Core regtest
//! node. See `regtest_kat_vectors.zig` for the capture procedure, the
//! `walletprocesspsbt` finalize-defaults-true trap, and why this spend shape
//! needed vectors of its own.

const std = @import("std");
const testing = std.testing;
const psbt = @import("root.zig");
const bitcointx = @import("bitcointx");
const vectors = @import("regtest_kat_vectors.zig");

fn hexToBytesAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    return std.fmt.hexToBytes(out, hex);
}

/// True if `m` has ANY record of `keytype`, whatever its keydata. `Map.find`
/// only matches the no-keydata singleton shape, so it cannot show that a
/// *keyed* field type (PARTIAL_SIG, BIP32_DERIVATION) is completely absent.
fn hasAnyOfType(m: psbt.Map, keytype: u64) bool {
    for (m.records) |r| {
        if (r.keytype == keytype) return true;
    }
    return false;
}

test "regtest P2WPKH: finalize reproduces Core's bytes and clears exactly what BIP174 mandates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const raw = try hexToBytesAlloc(a, vectors.p2wpkh_signed_hex);
    const ps = try psbt.parse(a, raw);

    // The input really does carry the fields that must be cleared, so the
    // absence checks after finalizing cannot pass vacuously.
    try testing.expect(hasAnyOfType(ps.inputs[0], psbt.input_key.PARTIAL_SIG));
    try testing.expect(hasAnyOfType(ps.inputs[0], psbt.input_key.BIP32_DERIVATION));
    try testing.expect(ps.inputs[0].find(psbt.input_key.WITNESS_UTXO) != null);
    try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) == null);

    _ = try psbt.finalize(a, ps);

    const got = try psbt.serialize(a, ps);
    const want = try hexToBytesAlloc(a, vectors.p2wpkh_finalized_hex);
    try testing.expectEqualSlices(u8, want, got);

    // BIP174 "Input Finalizer": all other data except the UTXO and unknown
    // fields is cleared once the input is finalized.
    try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) != null);
    try testing.expect(!hasAnyOfType(ps.inputs[0], psbt.input_key.PARTIAL_SIG));
    try testing.expect(!hasAnyOfType(ps.inputs[0], psbt.input_key.BIP32_DERIVATION));
    try testing.expect(ps.inputs[0].find(psbt.input_key.WITNESS_UTXO) != null);

    // A native P2WPKH spend puts everything in the witness — there is no
    // scriptSig at all, unlike the P2SH shapes BIP174's own example covers.
    try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTSIG) == null);
}

test "regtest P2WPKH: extract from Core's own finalized PSBT is byte-exact" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Parsed from Core's finalized vector rather than our own finalize
    // output, so this exercises `extract` independently of whether
    // `finalize` works.
    const raw = try hexToBytesAlloc(a, vectors.p2wpkh_finalized_hex);
    const ps = try psbt.parse(a, raw);

    const extracted = try psbt.extract(a, ps);
    try testing.expect(extracted.has_witness);
    const got = try bitcointx.serialize(a, extracted);
    const want = try hexToBytesAlloc(a, vectors.p2wpkh_extracted_tx_hex);
    try testing.expectEqualSlices(u8, want, got);
}
