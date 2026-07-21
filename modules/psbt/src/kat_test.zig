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
