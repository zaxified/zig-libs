// SPDX-License-Identifier: MIT
//! Creator/Updater, hash-preimage field and Base64 tests, anchored on the BIP174
//! "Test Vectors" Creator/Updater walkthrough (`bip_vectors.zig`).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const psbt = @import("root.zig");
const vec = @import("bip_vectors.zig");

fn unhex(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn txidBytes(display_hex: []const u8) ![32]u8 {
    var b: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, display_hex);
    std.mem.reverse(u8, &b);
    return b;
}

/// The Creator example's transaction (BIP174 Test Vectors): two inputs, two outputs.
fn creatorTx(a: Allocator) !bitcointx.Transaction {
    const vin = try a.alloc(bitcointx.TxIn, 2);
    vin[0] = .{ .prevout = .{ .txid = try txidBytes("75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858"), .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
    vin[1] = .{ .prevout = .{ .txid = try txidBytes("1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83"), .vout = 1 }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try a.alloc(bitcointx.TxOut, 2);
    vout[0] = .{ .value = 149990000, .script_pubkey = try unhex(a, "0014d85c2b71d0060b09c9886aeb815e50991dda124d") };
    vout[1] = .{ .value = 100000000, .script_pubkey = try unhex(a, "001400aea9a2e5f0f876a588df5546e8742d1d87008f") };
    return .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

fn expectHex(a: Allocator, hex: []const u8, got: []const u8) !void {
    const want = try unhex(a, hex);
    try testing.expectEqualSlices(u8, want, got);
}

const hardened: u32 = 0x80000000;
const fp = [4]u8{ 0xd9, 0x0c, 0x6a, 0x4f };
fn path(i: u32) [3]u32 {
    return .{ hardened, hardened, hardened + i };
}

test "BIP174 Creator example: fromUnsignedTx reproduces the official PSBT, hex and Base64" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ps = try psbt.fromUnsignedTx(a, try creatorTx(a));
    const bytes = try psbt.serialize(a, ps);
    try expectHex(a, vec.creator.hex, bytes);
    try testing.expectEqualStrings(vec.creator.b64, try psbt.toBase64(a, ps));
    // and it parses back
    var back = try psbt.parse(a, bytes);
    defer back.deinit(a);
    try testing.expectEqual(@as(usize, 2), back.inputs.len);
    try testing.expectEqual(@as(usize, 2), back.outputs.len);
}

test "BIP174 Updater example: UTXOs, scripts and BIP32 derivations give the official PSBT, then SIGHASH_ALL" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ps = try psbt.fromUnsignedTx(a, try creatorTx(a));

    const legacy = try unhex(a, vec.prev_tx_legacy_hex);
    const segwit = try unhex(a, vec.prev_tx_segwit_hex);
    const legacy_tx = try bitcointx.deserialize(a, legacy);
    const segwit_tx = try bitcointx.deserialize(a, segwit);

    // Updated in an order unlike the wire order: `Map.put` sorts.
    try psbt.setInputBip32Derivation(a, &ps, 1, &(try pk("03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc")), fp, &path(2));
    try psbt.setInputBip32Derivation(a, &ps, 1, &(try pk("023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73")), fp, &path(3));
    try psbt.setInputWitnessScript(a, &ps, 1, try unhex(a, "522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae"));
    try psbt.setInputRedeemScript(a, &ps, 1, try unhex(a, "00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903"));
    try psbt.setInputWitnessUtxo(a, &ps, 1, segwit_tx.vout[1]);
    try psbt.setInputBip32Derivation(a, &ps, 0, &(try pk("02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7")), fp, &path(1));
    try psbt.setInputBip32Derivation(a, &ps, 0, &(try pk("029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f")), fp, &path(0));
    try psbt.setInputRedeemScript(a, &ps, 0, try unhex(a, "5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae"));
    try psbt.setInputNonWitnessUtxo(a, &ps, 0, legacy_tx);
    try psbt.setOutputBip32Derivation(a, &ps, 0, &(try pk("03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771")), fp, &path(4));
    try psbt.setOutputBip32Derivation(a, &ps, 1, &(try pk("027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096")), fp, &path(5));

    try expectHex(a, vec.updater.hex, try psbt.serialize(a, ps));
    try testing.expectEqualStrings(vec.updater.b64, try psbt.toBase64(a, ps));

    try psbt.setInputSighashType(a, &ps, 0, 1);
    try psbt.setInputSighashType(a, &ps, 1, 1);
    try expectHex(a, vec.updater_sighash.hex, try psbt.serialize(a, ps));

    // The typed readers see what the setters wrote.
    try testing.expectEqual(@as(?u32, 1), psbt.inputSighashType(ps.inputs[0]));
    const d = psbt.inputBip32Derivation(ps.inputs[1], &(try pk("023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73"))).?;
    try testing.expectEqual(@as(usize, 3), d.len());
    try testing.expectEqual(hardened + 3, d.at(2));
}

fn pk(hex: []const u8) ![33]u8 {
    var b: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, hex);
    return b;
}

test "Creator refuses a transaction it could not hand back through parse" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tx = try creatorTx(a);
    var empty = tx;
    empty.vin = &.{};
    try testing.expectError(error.NoInputs, psbt.fromUnsignedTx(a, empty));
    tx.vin[1].script_sig = &.{0x51};
    try testing.expectError(error.UnsignedTxHasScriptSig, psbt.fromUnsignedTx(a, tx));
    tx.vin[1].script_sig = &.{};
    var w = tx;
    w.has_witness = true;
    try testing.expectError(error.UnsignedTxHasWitness, psbt.fromUnsignedTx(a, w));
}

test "Updater: bad indices, wrong previous transaction and malformed fields are refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ps = try psbt.fromUnsignedTx(a, try creatorTx(a));
    const segwit_tx = try bitcointx.deserialize(a, try unhex(a, vec.prev_tx_segwit_hex));
    const legacy_tx = try bitcointx.deserialize(a, try unhex(a, vec.prev_tx_legacy_hex));

    try testing.expectError(error.InputIndexOutOfRange, psbt.setInputSighashType(a, &ps, 2, 1));
    try testing.expectError(error.OutputIndexOutOfRange, psbt.setOutputRedeemScript(a, &ps, 2, &.{0x51}));
    // The legacy transaction is the funding of input 0, not of input 1.
    try testing.expectError(error.UtxoOutpointMismatch, psbt.setInputNonWitnessUtxo(a, &ps, 1, legacy_tx));
    try testing.expectError(error.UtxoOutpointMismatch, psbt.setInputNonWitnessUtxo(a, &ps, 0, segwit_tx));
    // Input 0 spends output 0 of a two-output transaction; a copy cut to zero outputs has no output 0.
    var cut = legacy_tx;
    cut.vout = &.{};
    try testing.expectError(error.UtxoOutpointMismatch, psbt.setInputNonWitnessUtxo(a, &ps, 0, cut)); // txid changed too
    // Field shapes are the parser's: a 32-byte key is no pubkey.
    try testing.expectError(error.InvalidPubkeyLength, psbt.setInputPartialSig(a, &ps, 0, &(@as([32]u8, @splat(2))), &.{0x30}));
    try testing.expectError(error.InvalidPubkeyLength, psbt.setInputBip32Derivation(a, &ps, 0, &(@as([20]u8, @splat(2))), fp, &.{}));
    try testing.expectEqual(@as(usize, 0), ps.inputs[0].records.len); // nothing half-written
}

test "Updater: setting a field twice replaces it; a built PSBT always parses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ps = try psbt.fromUnsignedTx(a, try creatorTx(a));
    try psbt.setInputSighashType(a, &ps, 0, 1);
    try psbt.setInputSighashType(a, &ps, 0, 0x83);
    try testing.expectEqual(@as(usize, 1), ps.inputs[0].records.len);
    try testing.expectEqual(@as(?u32, 0x83), psbt.inputSighashType(ps.inputs[0]));
    try psbt.setInputPartialSig(a, &ps, 0, &(try pk("029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f")), &.{ 0x30, 0x01 });
    try psbt.setGlobalXpub(a, &ps, &(@as([78]u8, @splat(7))), fp, &.{ hardened + 44, 0 });
    const bytes = try psbt.serialize(a, ps);
    var back = try psbt.parse(a, bytes);
    defer back.deinit(a);
    const x = psbt.globalXpubDerivation(back.global, &(@as([78]u8, @splat(7)))).?;
    try testing.expectEqual(@as(usize, 2), x.len());
    const again = try psbt.serialize(a, back);
    try testing.expectEqualSlices(u8, bytes, again);
}

test "Base64: every BIP174 valid vector's Base64 twin decodes to the hex bytes and round-trips" {
    const a = testing.allocator;
    for (vec.bip174_valid, 0..) |p, i| {
        const want = try unhex(a, p.hex);
        defer a.free(want);
        if (psbt.fromBase64(a, p.b64)) |owned| {
            var o = owned;
            defer o.deinit(a);
            try testing.expectEqualSlices(u8, want, o.bytes);
            const text = try psbt.toBase64(a, o.psbt);
            defer a.free(text);
            try testing.expectEqualStrings(p.b64, text);
        } else |err| {
            // The two 0-input vectors (see kat_test.zig): a parse error, not a Base64 one.
            try testing.expect(i >= 8);
            try testing.expectEqual(error.InvalidWitnessFlag, err);
        }
    }
}

test "Base64: surrounding whitespace is ignored; bad text is a typed error, never a panic" {
    const a = testing.allocator;
    const padded = try std.fmt.allocPrint(a, "  \n{s}\r\n", .{vec.creator.b64});
    defer a.free(padded);
    var o = try psbt.fromBase64(a, padded);
    o.deinit(a);
    try testing.expectError(error.InvalidCharacter, psbt.fromBase64(a, "cHNidP8B!AB="));
    try testing.expectError(error.InvalidPadding, psbt.fromBase64(a, "cHNidP8"));
    try testing.expectError(error.BadMagic, psbt.fromBase64(a, "AAAAAAAA"));
    try testing.expectError(error.BadMagic, psbt.fromBase64(a, ""));
    // valid Base64 of a truncated PSBT
    try testing.expectError(error.Truncated, psbt.fromBase64(a, vec.creator.b64[0..40]));
}

test "preimage fields: hashes of the standard vectors, set/get, iterate, parse validation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ps = try psbt.fromUnsignedTx(a, try creatorTx(a));
    const Case = struct { kind: psbt.PreimageKind, preimage: []const u8, hash: []const u8 };
    const cases = [_]Case{
        .{ .kind = .ripemd160, .preimage = "abc", .hash = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
        .{ .kind = .sha256, .preimage = "abc", .hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        .{ .kind = .hash160, .preimage = "", .hash = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb" },
        .{ .kind = .hash256, .preimage = "", .hash = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456" },
    };
    for (cases) |c| {
        const h = try unhex(a, c.hash);
        try testing.expect(psbt.preimageMatches(c.kind, h, c.preimage));
        try testing.expect(!psbt.preimageMatches(c.kind, h, "x"));
        try testing.expect(!psbt.preimageMatches(c.kind, h[1..], c.preimage));
        try psbt.setInputPreimage(a, &ps, 0, c.kind, c.preimage);
        try testing.expectEqualStrings(c.preimage, psbt.inputPreimage(ps.inputs[0], c.kind, h).?);
    }
    var n: usize = 0;
    var it = psbt.inputPreimages(ps.inputs[0]);
    while (it.next()) |p| {
        n += 1;
        try testing.expect(psbt.preimageMatches(p.kind, p.hash, p.preimage));
    }
    try testing.expectEqual(@as(usize, 4), n);

    const bytes = try psbt.serialize(a, ps);
    var back = try psbt.parse(a, bytes);
    defer back.deinit(a);
    try testing.expectEqualSlices(u8, bytes, try psbt.serialize(a, back));

    // A hash of the wrong size is refused by parse and by the generic put path.
    var bad = back;
    const recs = try a.dupe(psbt.Record, bad.inputs[0].records);
    recs[0].keydata = recs[0].keydata[1..];
    bad.inputs = try a.dupe(psbt.Map, back.inputs);
    bad.inputs[0] = .{ .records = recs };
    const badbytes = try psbt.serialize(a, bad);
    try testing.expectError(error.InvalidKeyDataLength, psbt.parse(a, badbytes));
}
