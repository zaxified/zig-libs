// SPDX-License-Identifier: MIT
//! Byte-exact checks against `kat_vectors.zig` -- see that file's doc
//! comment for provenance. Three groups, matching BIP174's own "Test
//! Vectors" section: invalid PSBTs (must all be rejected -- this is the
//! security core), valid PSBTs (parse -> serialize round-trip must be
//! byte-exact), and the worked Combiner example (`combine` output must be
//! byte-exact against the BIP's own expected result).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const psbt = @import("root.zig");
const vectors = @import("kat_vectors.zig");

fn hexToBytesAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// Asserts `psbt.parse` rejects `bytes` with *some* typed error (used when
/// the BIP's case name doesn't pin down a single unambiguous error tag --
/// still must never panic or leak on the reject path).
fn expectParseFails(allocator: Allocator, bytes: []const u8) !void {
    if (psbt.parse(allocator, bytes)) |result| {
        var r = result;
        r.deinit(allocator);
        return error.TestUnexpectedSuccess;
    } else |_| {}
}

test "BIP174 official invalid vectors: every one is rejected, none panics" {
    const allocator = testing.allocator;
    for (vectors.invalid) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        expectParseFails(allocator, raw) catch |err| {
            std.debug.print("FAIL (accepted an invalid PSBT): {s}\n", .{case.label});
            return err;
        };
    }
}

// Specific expected error per case, for the ones whose BIP174 case name
// pins down an unambiguous rejection reason (index matches `vectors.invalid`
// document order -- see that array's transcription for the case list).
test "BIP174 official invalid vectors: specific expected error per named case" {
    const allocator = testing.allocator;
    const Expect = struct { idx: usize, err: psbt.ParseError };
    const expected = [_]Expect{
        .{ .idx = 0, .err = error.BadMagic }, // Network transaction, not PSBT format
        .{ .idx = 1, .err = error.Truncated }, // PSBT missing outputs
        .{ .idx = 2, .err = error.UnsignedTxHasScriptSig }, // filled scriptSig in the unsigned tx
        .{ .idx = 3, .err = error.MissingUnsignedTx }, // without an unsigned tx
        .{ .idx = 4, .err = error.DuplicateKey }, // duplicate keys in an input
        .{ .idx = 5, .err = error.UnexpectedKeyData }, // invalid global transaction typed key
        .{ .idx = 6, .err = error.UnexpectedKeyData }, // invalid input witness utxo typed key
        .{ .idx = 7, .err = error.InvalidPubkeyLength }, // invalid pubkey length, partial sig
        .{ .idx = 8, .err = error.UnexpectedKeyData }, // invalid redeemscript typed key
        .{ .idx = 9, .err = error.UnexpectedKeyData }, // invalid witnessscript typed key
        .{ .idx = 10, .err = error.InvalidPubkeyLength }, // invalid pubkey, input BIP32 derivation
        .{ .idx = 11, .err = error.UnexpectedKeyData }, // invalid non-witness utxo typed key
        .{ .idx = 12, .err = error.UnexpectedKeyData }, // invalid final scriptsig typed key
        .{ .idx = 13, .err = error.UnexpectedKeyData }, // invalid final script witness typed key
        .{ .idx = 14, .err = error.InvalidPubkeyLength }, // invalid pubkey, output BIP32 derivation
        .{ .idx = 15, .err = error.UnexpectedKeyData }, // invalid input sighash type typed key
        .{ .idx = 16, .err = error.UnexpectedKeyData }, // invalid output redeemScript typed key
        .{ .idx = 17, .err = error.UnexpectedKeyData }, // invalid output witnessScript typed key
        .{ .idx = 18, .err = error.UnsignedTxNotLegacySerialization }, // witness-serialized unsigned tx
        // idx 19 ("invalid value data due to its size being not the stated
        // size") is exercised only by the "some error" test above -- it's
        // garbage bytes with no single well-defined rejection reason.
    };
    for (expected) |e| {
        const case = vectors.invalid[e.idx];
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        testing.expectError(e.err, psbt.parse(allocator, raw)) catch |err| {
            std.debug.print("FAIL (wrong/no error) case: {s}\n", .{case.label});
            return err;
        };
    }
}

test "F2: a garbage byte appended after a valid PSBT is rejected with TrailingBytes" {
    // `parse`'s `if (offset != bytes.len) return error.TrailingBytes;` had
    // no test teeth: deleting it left all 44 tests green (including every
    // BIP174 invalid vector, Core's invalid/invalid_with_msg vectors, and
    // the regtest KATs), because none of them is "a structurally valid PSBT
    // with one byte appended" -- they are all malformed from the start. A
    // PSBT accepted despite trailing garbage silently drops the tail on
    // re-serialize (PSBT malleability). Take a genuine BIP174 valid vector,
    // append one byte, and confirm it is now rejected -- and specifically
    // with TrailingBytes, not some other error.
    const allocator = testing.allocator;
    // Skip the last two vectors here too -- they hit bitcointx's documented
    // BIP144 marker/0-vin wire ambiguity on a plain `parse`, unrelated to
    // this test's own trailing-bytes concern (see the dedicated test below).
    for (vectors.valid[0 .. vectors.valid.len - 2]) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);

        // Sanity: the vector parses cleanly on its own first.
        var ok = try psbt.parse(allocator, raw);
        ok.deinit(allocator);

        var padded = try allocator.alloc(u8, raw.len + 1);
        defer allocator.free(padded);
        @memcpy(padded[0..raw.len], raw);
        padded[raw.len] = 0xAA; // one garbage byte appended

        try testing.expectError(error.TrailingBytes, psbt.parse(allocator, padded));
    }
}

test "BIP174 official valid vectors: parse -> serialize is byte-exact" {
    const allocator = testing.allocator;
    // The last two vectors (0-input legacy tx) hit bitcointx's documented
    // BIP144 marker/0-vin wire ambiguity -- see kat_vectors.zig doc comment
    // and the dedicated test below.
    for (vectors.valid[0 .. vectors.valid.len - 2]) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);

        var p = psbt.parse(allocator, raw) catch |err| {
            std.debug.print("FAIL (rejected a valid PSBT): {s}\n", .{case.label});
            return err;
        };
        defer p.deinit(allocator);

        const reser = try psbt.serialize(allocator, p);
        defer allocator.free(reser);
        testing.expectEqualSlices(u8, raw, reser) catch |err| {
            std.debug.print("FAIL (round-trip mismatch): {s}\n", .{case.label});
            return err;
        };
    }
}

test "BIP174 official valid vectors: the two 0-input cases hit bitcointx's documented marker/vin-count ambiguity" {
    const allocator = testing.allocator;
    for (vectors.valid[vectors.valid.len - 2 ..]) |case| {
        const raw = try hexToBytesAlloc(allocator, case.hex);
        defer allocator.free(raw);
        testing.expectError(error.InvalidWitnessFlag, psbt.parse(allocator, raw)) catch |err| {
            std.debug.print("FAIL (expected InvalidWitnessFlag): {s}\n", .{case.label});
            return err;
        };
    }
}

test "BIP174 official valid vector: PSBT_GLOBAL_XPUB round-trips and decodes via globalXpubDerivation" {
    const allocator = testing.allocator;
    // "PSBT with `PSBT_GLOBAL_XPUB`." -- index 7.
    const case = vectors.valid[7];
    const raw = try hexToBytesAlloc(allocator, case.hex);
    defer allocator.free(raw);

    var p = try psbt.parse(allocator, raw);
    defer p.deinit(allocator);

    var found_xpub = false;
    for (p.global.records) |r| {
        if (r.keytype == psbt.global_key.XPUB) {
            found_xpub = true;
            const deriv = psbt.globalXpubDerivation(p.global, r.keydata) orelse return error.TestUnexpectedNull;
            try testing.expect(deriv.len() >= 1);
        }
    }
    try testing.expect(found_xpub);
}

test "BIP174 official Combiner example: combine(a, b) is byte-exact against the BIP's own result" {
    const allocator = testing.allocator;
    const raw_a = try hexToBytesAlloc(allocator, vectors.combiner_a_hex);
    defer allocator.free(raw_a);
    const raw_b = try hexToBytesAlloc(allocator, vectors.combiner_b_hex);
    defer allocator.free(raw_b);
    const raw_want = try hexToBytesAlloc(allocator, vectors.combiner_result_hex);
    defer allocator.free(raw_want);

    var a = try psbt.parse(allocator, raw_a);
    defer a.deinit(allocator);
    var b = try psbt.parse(allocator, raw_b);
    defer b.deinit(allocator);

    var combined = try psbt.combine(allocator, a, b);
    defer combined.deinit(allocator);

    const got = try psbt.serialize(allocator, combined);
    defer allocator.free(got);

    try testing.expectEqualSlices(u8, raw_want, got);
}

test "BIP174 official Combiner example: each input PSBT round-trips standalone too" {
    const allocator = testing.allocator;
    for ([_][]const u8{ vectors.combiner_a_hex, vectors.combiner_b_hex, vectors.combiner_result_hex }) |hex| {
        const raw = try hexToBytesAlloc(allocator, hex);
        defer allocator.free(raw);
        var p = try psbt.parse(allocator, raw);
        defer p.deinit(allocator);
        const reser = try psbt.serialize(allocator, p);
        defer allocator.free(reser);
        try testing.expectEqualSlices(u8, raw, reser);
    }
}

test "combine rejects PSBTs for different transactions" {
    const allocator = testing.allocator;
    // Two structurally-valid-but-unrelated PSBTs: vectors.valid[0] (a
    // P2PKH-input tx) and combiner_a_hex (a different, unrelated tx).
    const raw_a = try hexToBytesAlloc(allocator, vectors.valid[0].hex);
    defer allocator.free(raw_a);
    const raw_b = try hexToBytesAlloc(allocator, vectors.combiner_a_hex);
    defer allocator.free(raw_b);

    var a = try psbt.parse(allocator, raw_a);
    defer a.deinit(allocator);
    var b = try psbt.parse(allocator, raw_b);
    defer b.deinit(allocator);

    try testing.expectError(error.DifferentTransactions, psbt.combine(allocator, a, b));
}

// W2-B/psbt-F6: `mergeMaps`'s dedup must key on the WHOLE record key
// (`keytype` + `keydata`), not `keytype` alone — two different signers'
// PARTIAL_SIG records for the same input share `keytype` (0x02) but have
// different `keydata` (their own pubkey), and BIP174's Combiner role
// requires "all of the key-value pairs from both" to survive. A dedup
// structure that only hashes/compares `keytype` would treat signer B's
// PARTIAL_SIG as "already present" once signer A's is in the accumulator
// and silently drop it — turning a 2-of-2 multisig into a 1-of-2 during
// combine, which is a signature-loss bug, not merely a slow one.
test "combine: two signers' PARTIAL_SIG records for the same input both survive (same keytype, different keydata)" {
    const allocator = testing.allocator;
    const tx_bytes = "dummy-tx-for-combine-key-collision-test";
    const pubkey_a = [_]u8{0xAA} ** 33;
    const pubkey_b = [_]u8{0xBB} ** 33;

    var a: psbt.Psbt = .{
        .global = .{ .records = try allocator.dupe(psbt.Record, &.{
            .{ .keytype = psbt.global_key.UNSIGNED_TX, .keydata = &.{}, .value = tx_bytes },
        }) },
        .inputs = try allocator.dupe(psbt.Map, &.{
            .{ .records = try allocator.dupe(psbt.Record, &.{
                .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey_a, .value = "sig-from-signer-A" },
            }) },
        }),
        .outputs = try allocator.dupe(psbt.Map, &.{}),
    };
    defer a.deinit(allocator);

    var b: psbt.Psbt = .{
        .global = .{ .records = try allocator.dupe(psbt.Record, &.{
            .{ .keytype = psbt.global_key.UNSIGNED_TX, .keydata = &.{}, .value = tx_bytes },
        }) },
        .inputs = try allocator.dupe(psbt.Map, &.{
            .{ .records = try allocator.dupe(psbt.Record, &.{
                .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey_b, .value = "sig-from-signer-B" },
            }) },
        }),
        .outputs = try allocator.dupe(psbt.Map, &.{}),
    };
    defer b.deinit(allocator);

    var combined = try psbt.combine(allocator, a, b);
    defer combined.deinit(allocator);

    try testing.expectEqual(@as(usize, 2), combined.inputs[0].records.len);
    const got_a = combined.inputs[0].findKeyed(psbt.input_key.PARTIAL_SIG, &pubkey_a) orelse return error.TestExpectedEqual;
    const got_b = combined.inputs[0].findKeyed(psbt.input_key.PARTIAL_SIG, &pubkey_b) orelse return error.TestExpectedEqual;
    try testing.expectEqualStrings("sig-from-signer-A", got_a.value);
    try testing.expectEqualStrings("sig-from-signer-B", got_b.value);
}
