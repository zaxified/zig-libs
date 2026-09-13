// SPDX-License-Identifier: MIT
//! Teeth for `finalize`/`extract` (`finalize.zig`).
//!
//! Two anchors are grounded in official BIP174 vectors:
//!
//! 1. `kat_vectors.zig`'s `valid[1]` ("PSBT with one P2PKH input and one
//!    P2SH-P2WPKH input. First input is signed and finalized...") carries a
//!    REAL, byte-exact `FINAL_SCRIPTSIG` for its first input straight from
//!    the BIP itself. The anchor here works backwards from that one genuine
//!    finalized field: decompose it into the `PARTIAL_SIG` + pubkey it must
//!    have come from, re-finalize, and assert the byte-exact reproduction —
//!    plus a real negative control for free, since that vector's SECOND
//!    input is deliberately left unsigned (`extract` must refuse it).
//!
//! 2. `kat_vectors.zig`'s `finalize_combined_hex` / `finalize_finalized_hex`
//!    / `finalize_extracted_tx_hex` -- a correction of a claim this doc
//!    comment used to make ("no separate Finalizer test vectors section
//!    exists"): BIP174's own "Test Vectors" section DOES carry a genuine
//!    pre-finalize/post-finalize/post-extract triple, for its main
//!    multisig-workflow narrative (a bare P2SH 2-of-2 multisig input plus a
//!    P2SH-P2WSH 2-of-2 multisig input). Test group F below drives `finalize`
//!    and `extract` on that triple directly -- no decomposition needed, and
//!    it explicitly re-checks the BIP's "all fields except UTXO/unknown
//!    cleared" rule field-by-field rather than trusting the byte-compare
//!    alone to imply it.
//!
//! Everything else (P2WPKH, native P2WSH-multisig) is self-authored
//! end-to-end: real secp256k1 keys, real BIP143/legacy sighashes, real
//! `std.crypto.sign.ecdsa` signatures — verified not just by byte-exact
//! comparison against an independently hand-assembled expected value, but
//! by `finalize`'s own mandatory `bitcoinscript.verifyScript` pass (a wrong
//! assembly fails closed, doesn't just mismatch a byte string). This
//! mirrors `bitcoinscript/src/e2e_test.zig`'s own established pattern for
//! exactly this class of test. Bare P2SH multisig and P2SH-P2WSH multisig
//! (test groups C/D below) were self-authored when first written but are
//! NOW also covered by group F's official vectors above.
//!
//! P2TR key-path is exercised only via its two fail-closed paths (missing
//! `TAP_KEY_SIG`, missing another input's UTXO when BIP341 needs the full
//! set) -- a real positive-path Schnorr-signed spend needs `bip340`, which
//! is only a TRANSITIVE dependency here (through `bitcoinscript`), not a
//! direct one this module's `build.zig` wiring exposes; broadening that
//! wiring is out of scope for this change. `bitcoinscript/e2e_test.zig`
//! already covers a real signed P2TR spend through the exact same
//! `verifyScript` call `finalize`'s P2TR branch makes.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const bitcoinscript = @import("bitcoinscript");
const ripemd160 = @import("ripemd160");
const psbt = @import("root.zig");
const vectors = @import("kat_vectors.zig");

const EcdsaSecp256k1Sha256 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const SIGHASH_ALL: u32 = 1;

// ── shared helpers (mirrors bitcoinscript/e2e_test.zig's own) ──────────

/// secp256k1's group order `n` (SEC2 §2.4.1) -- hardcoded rather than
/// imported from `k256`, since that module is only a TRANSITIVE dependency
/// here (through `bitcoinscript`), not a direct one this module's
/// `build.zig` wiring exposes (module doc comment). A well-known public
/// curve parameter, not a secret.
const secp256k1_order: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

fn normalizeLowS(sig: EcdsaSecp256k1Sha256.Signature) EcdsaSecp256k1Sha256.Signature {
    const n: u256 = secp256k1_order;
    const half = n >> 1;
    const s_val = std.mem.readInt(u256, &sig.s, .big);
    if (s_val <= half) return sig;
    var new_s: [32]u8 = undefined;
    std.mem.writeInt(u256, &new_s, n - s_val, .big);
    return .{ .r = sig.r, .s = new_s };
}

fn derSigWithHashtype(allocator: Allocator, sig: EcdsaSecp256k1Sha256.Signature, hash_type: u8) ![]u8 {
    var der_buf: [EcdsaSecp256k1Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);
    const out = try allocator.alloc(u8, der.len + 1);
    @memcpy(out[0..der.len], der);
    out[der.len] = hash_type;
    return out;
}

fn dummyTxCtx() bitcoinscript.TxContext {
    return .{
        .tx = .{ .version = 1, .vin = @constCast(&[_]bitcointx.TxIn{.{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff }}), .vout = &.{}, .witness = &.{}, .locktime = 0, .has_witness = false },
        .input_index = 0,
        .spent_outputs = &[_]bitcointx.TxOut{.{ .value = 0, .script_pubkey = &.{} }},
    };
}

/// `hash160(data)` computed by actually running `OP_HASH160` through
/// `bitcoinscript.interpreter.eval` -- `ripemd160` (needed for a from-
/// scratch hash160) is only a transitive dependency of `psbt` (through
/// `bitcoinscript`), not a direct one, so this reuses the interpreter this
/// whole module is built on rather than reaching around it.
fn hash160Of(allocator: Allocator, data: []const u8) ![20]u8 {
    var script: std.ArrayList(u8) = .empty;
    try script.append(allocator, @intCast(data.len));
    try script.appendSlice(allocator, data);
    try script.append(allocator, 0xa9); // OP_HASH160
    var stack: std.ArrayList([]const u8) = .empty;
    try bitcoinscript.interpreter.eval(allocator, &stack, script.items, dummyTxCtx(), .base, bitcoinscript.ScriptFlags.none);
    var out: [20]u8 = undefined;
    @memcpy(&out, stack.items[0]);
    return out;
}

fn buildUnsignedTx(allocator: Allocator, out_value: i64) !bitcointx.Transaction {
    const vin = try allocator.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = [_]u8{0xee} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try allocator.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = out_value, .script_pubkey = &.{} };
    return .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

fn buildWitnessUtxoValue(allocator: Allocator, amount: i64, script_pubkey: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    var amt_bytes: [8]u8 = undefined;
    std.mem.writeInt(i64, &amt_bytes, amount, .little);
    try buf.appendSlice(allocator, &amt_bytes);
    var tmp: [9]u8 = undefined;
    const enc = bitcointx.encodeCompactSize(script_pubkey.len, &tmp) catch unreachable;
    try buf.appendSlice(allocator, enc);
    try buf.appendSlice(allocator, script_pubkey);
    return buf.toOwnedSlice(allocator);
}

/// Wraps `unsigned` (serialized once, legacy form -- BIP174 mandates this
/// for `PSBT_GLOBAL_UNSIGNED_TX`) plus caller-built `input_maps` into a
/// `Psbt` with matching empty output maps.
fn wrapPsbt(allocator: Allocator, unsigned: bitcointx.Transaction, input_maps: []psbt.Map) !psbt.Psbt {
    const unsigned_bytes = try bitcointx.serializeLegacy(allocator, unsigned);
    const global_records = try allocator.alloc(psbt.Record, 1);
    global_records[0] = .{ .keytype = psbt.global_key.UNSIGNED_TX, .keydata = &.{}, .value = unsigned_bytes };
    const output_maps = try allocator.alloc(psbt.Map, unsigned.vout.len);
    for (output_maps) |*om| om.* = .{ .records = &.{} };
    return .{ .global = .{ .records = global_records }, .inputs = input_maps, .outputs = output_maps };
}

fn buildMultisig2of2(allocator: Allocator, pub1: []const u8, pub2: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    try buf.append(allocator, 0x52); // OP_2
    try buf.append(allocator, @intCast(pub1.len));
    try buf.appendSlice(allocator, pub1);
    try buf.append(allocator, @intCast(pub2.len));
    try buf.appendSlice(allocator, pub2);
    try buf.append(allocator, 0x52); // OP_2
    try buf.append(allocator, 0xae); // OP_CHECKMULTISIG
    return buf.toOwnedSlice(allocator);
}

fn hexToBytesAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn expectInputError(results: []const ?psbt.InputFinalizeError, index: usize, expected: psbt.InputFinalizeError) !void {
    const got = results[index] orelse return error.TestUnexpectedResult; // expected an error, got success
    try testing.expectEqual(expected, got);
}

// ── A: BIP174 anchor (P2PKH), decomposed from the official finalized field ──

test "BIP174 anchor: re-finalizing valid[1]'s P2PKH input reproduces its official FINAL_SCRIPTSIG byte-exact; extract refuses the still-unsigned second input" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const raw = try hexToBytesAlloc(a, vectors.valid[1].hex);
    var original = try psbt.parse(a, raw);

    const expected_final_scriptsig = original.inputs[0].find(psbt.input_key.FINAL_SCRIPTSIG).?.value;

    // Decompose the official finalized scriptSig back into <sig><pubkey>.
    const instr1 = try bitcoinscript.interpreter.readInstruction(expected_final_scriptsig, 0);
    const sig_bytes = instr1.data.?;
    const instr2 = try bitcoinscript.interpreter.readInstruction(expected_final_scriptsig, instr1.next);
    const pubkey_bytes = instr2.data.?;
    try testing.expectEqual(expected_final_scriptsig.len, instr2.next); // exactly 2 pushes, nothing else

    const pkh = try hash160Of(a, pubkey_bytes);
    var script_pubkey: [25]u8 = undefined;
    script_pubkey[0] = 0x76;
    script_pubkey[1] = 0xa9;
    script_pubkey[2] = 0x14;
    @memcpy(script_pubkey[3..23], &pkh);
    script_pubkey[23] = 0x88;
    script_pubkey[24] = 0xac;

    const witness_utxo_value = try buildWitnessUtxoValue(a, 100_000, &script_pubkey);

    var my_input0_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = pubkey_bytes, .value = sig_bytes },
    };
    var my_inputs = [_]psbt.Map{
        .{ .records = &my_input0_records },
        original.inputs[1], // untouched: still unsigned (P2SH-P2WPKH, no PARTIAL_SIG)
    };
    const ps: psbt.Psbt = .{ .global = original.global, .inputs = &my_inputs, .outputs = original.outputs };

    const results = try psbt.finalize(a, ps, .{});
    try testing.expect(results[0] == null);
    try testing.expect(results[1] != null); // still unsigned -- expected, not part of the anchor claim

    const got_final = ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTSIG).?;
    try testing.expectEqualSlices(u8, expected_final_scriptsig, got_final.value);
    // Consumed fields cleared, UTXO kept (BIP174 §"Input Finalizer").
    try testing.expect(ps.inputs[0].find(psbt.input_key.PARTIAL_SIG) == null);
    try testing.expect(ps.inputs[0].find(psbt.input_key.WITNESS_UTXO) != null);

    try testing.expectError(error.InputNotFinalized, psbt.extract(a, ps));
}

// ── B: real P2WPKH (self-authored, real BIP143 sighash + ECDSA sign) ────

test "finalize+extract: real P2WPKH spend, byte-exact FINAL_SCRIPTWITNESS; a tampered PARTIAL_SIG fails closed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [32]u8 = [_]u8{0x55} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();
    const pkh = try hash160Of(a, &pubkey);

    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &pkh);

    var script_code: [25]u8 = undefined; // BIP143's implicit P2PKH-shaped scriptCode for P2WPKH
    script_code[0] = 0x76;
    script_code[1] = 0xa9;
    script_code[2] = 0x14;
    @memcpy(script_code[3..23], &pkh);
    script_code[23] = 0x88;
    script_code[24] = 0xac;

    const unsigned = try buildUnsignedTx(a, 900);
    const credit_value: i64 = 5000;
    const sighash = try bitcointx.bip143.sighash(a, unsigned, 0, &script_code, credit_value, SIGHASH_ALL);
    const sig = normalizeLowS(try kp.signPrehashed(sighash, null));
    const sig_ht = try derSigWithHashtype(a, sig, 0x01);

    const witness_utxo_value = try buildWitnessUtxoValue(a, credit_value, &script_pubkey);

    var input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig_ht },
    };
    var input_maps = [_]psbt.Map{.{ .records = &input_records }};
    const ps = try wrapPsbt(a, unsigned, &input_maps);

    const results = try psbt.finalize(a, ps, .{});
    try testing.expect(results[0] == null);

    const fw = ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS).?;
    const expected_enc = try psbt.encodeWitnessStack(a, &[_][]const u8{ sig_ht, &pubkey });
    try testing.expectEqualSlices(u8, expected_enc, fw.value);
    try testing.expect(ps.inputs[0].find(psbt.input_key.PARTIAL_SIG) == null); // cleared

    const extracted = try psbt.extract(a, ps);
    try testing.expect(extracted.has_witness);
    try testing.expectEqual(@as(usize, 1), extracted.witness.len);
    try testing.expectEqual(@as(usize, 2), extracted.witness[0].items.len);
    try testing.expectEqualSlices(u8, sig_ht, extracted.witness[0].items[0]);
    try testing.expectEqualSlices(u8, &pubkey, extracted.witness[0].items[1]);
    _ = try extracted.txid(a);
    _ = try extracted.wtxid(a);
    _ = try bitcointx.serialize(a, extracted);

    // Positive control: flip a byte inside the DER signature before finalizing.
    var tampered = try a.dupe(u8, sig_ht);
    tampered[5] ^= 0x01;
    var bad_input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = tampered },
    };
    var bad_input_maps = [_]psbt.Map{.{ .records = &bad_input_records }};
    const bad_ps = try wrapPsbt(a, unsigned, &bad_input_maps);
    const bad_results = try psbt.finalize(a, bad_ps, .{});
    try testing.expect(bad_results[0] != null); // verify-on-finalize must fail closed
}

test "finalize: SIGHASH_TYPE mismatch is rejected (BIP174's own sighash-type enforcement rule)" {
    // BIP174 SS"Input Finalizer": "finalizers must fail to finalize inputs
    // which have signatures that do not match the specified sighash
    // type." No existing test set PSBT_IN_SIGHASH_TYPE at all, so this
    // check (`sighashMatches` in finalize.zig) had zero coverage — every
    // other finalize test either omits SIGHASH_TYPE entirely (the check
    // is vacuously true) or uses a signature whose trailing byte already
    // happens to agree.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [32]u8 = [_]u8{0x55} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();
    const pkh = try hash160Of(a, &pubkey);

    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &pkh);

    var script_code: [25]u8 = undefined;
    script_code[0] = 0x76;
    script_code[1] = 0xa9;
    script_code[2] = 0x14;
    @memcpy(script_code[3..23], &pkh);
    script_code[23] = 0x88;
    script_code[24] = 0xac;

    const unsigned = try buildUnsignedTx(a, 900);
    const credit_value: i64 = 5000;
    const sighash = try bitcointx.bip143.sighash(a, unsigned, 0, &script_code, credit_value, SIGHASH_ALL);
    const sig = normalizeLowS(try kp.signPrehashed(sighash, null));
    // Signed with SIGHASH_ALL (0x01) trailing byte...
    const sig_ht = try derSigWithHashtype(a, sig, 0x01);

    const witness_utxo_value = try buildWitnessUtxoValue(a, credit_value, &script_pubkey);

    // ...but PSBT_IN_SIGHASH_TYPE declares SIGHASH_SINGLE (0x03): the
    // PARTIAL_SIG on hand does NOT match the input's own declared type.
    var sighash_type_value: [4]u8 = undefined;
    std.mem.writeInt(u32, &sighash_type_value, 0x03, .little);

    var input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig_ht },
        .{ .keytype = psbt.input_key.SIGHASH_TYPE, .keydata = &.{}, .value = &sighash_type_value },
    };
    var input_maps = [_]psbt.Map{.{ .records = &input_records }};
    const ps = try wrapPsbt(a, unsigned, &input_maps);

    const results = try psbt.finalize(a, ps, .{});
    try testing.expect(results[0] != null);
    try testing.expectEqual(psbt.InputFinalizeError.MissingSignature, results[0].?);
    // Nothing was finalized: no FINAL_SCRIPTWITNESS/SCRIPTSIG got written,
    // and the (mismatched) PARTIAL_SIG is left in place, not cleared.
    try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) == null);
    try testing.expect(ps.inputs[0].findKeyed(psbt.input_key.PARTIAL_SIG, &pubkey) != null);
}

test "finalize: a PARTIAL_SIG under some other key, ordered first, no longer shadows the right one (A1 F7)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x55} ** 32);
    const pubkey = kp.public_key.toCompressedSec1();
    const decoy_kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x56} ** 32);
    const decoy_pub = decoy_kp.public_key.toCompressedSec1();
    const pkh = try hash160Of(a, &pubkey);

    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &pkh);
    var script_code: [25]u8 = undefined;
    script_code[0] = 0x76;
    script_code[1] = 0xa9;
    script_code[2] = 0x14;
    @memcpy(script_code[3..23], &pkh);
    script_code[23] = 0x88;
    script_code[24] = 0xac;

    const unsigned = try buildUnsignedTx(a, 900);
    const credit_value: i64 = 5000;
    const sighash = try bitcointx.bip143.sighash(a, unsigned, 0, &script_code, credit_value, SIGHASH_ALL);
    const sig_ht = try derSigWithHashtype(a, normalizeLowS(try kp.signPrehashed(sighash, null)), 0x01);
    // A genuine signature over the same digest, under the wrong key.
    const decoy_ht = try derSigWithHashtype(a, normalizeLowS(try decoy_kp.signPrehashed(sighash, null)), 0x01);
    const witness_utxo_value = try buildWitnessUtxoValue(a, credit_value, &script_pubkey);

    var input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &decoy_pub, .value = decoy_ht }, // first
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig_ht },
    };
    var input_maps = [_]psbt.Map{.{ .records = &input_records }};
    const ps = try wrapPsbt(a, unsigned, &input_maps);

    const results = try psbt.finalize(a, ps, .{});
    try testing.expect(results[0] == null);
    const fw = ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS).?;
    const expected_enc = try psbt.encodeWitnessStack(a, &[_][]const u8{ sig_ht, &pubkey });
    try testing.expectEqualSlices(u8, expected_enc, fw.value);
}

test "finalize: an invalid signature for an earlier multisig key no longer blocks two valid later ones (A1 F7)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp1 = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x71} ** 32);
    const kp2 = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x72} ** 32);
    const kp3 = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x73} ** 32);
    const pub1 = kp1.public_key.toCompressedSec1();
    const pub2 = kp2.public_key.toCompressedSec1();
    const pub3 = kp3.public_key.toCompressedSec1();

    var redeem_buf: std.ArrayList(u8) = .empty;
    try redeem_buf.append(a, 0x52); // OP_2
    for ([_][]const u8{ &pub1, &pub2, &pub3 }) |p| {
        try redeem_buf.append(a, @intCast(p.len));
        try redeem_buf.appendSlice(a, p);
    }
    try redeem_buf.append(a, 0x53); // OP_3
    try redeem_buf.append(a, 0xae); // OP_CHECKMULTISIG
    const redeem = redeem_buf.items;

    // Not `hash160Of`: a 105-byte 2-of-3 script is past a one-byte direct
    // push (max 75), so that helper's `<len><data> OP_HASH160` would misread
    // the length byte as an opcode.
    var redeem_hash: [20]u8 = undefined;
    ripemd160.hash160(redeem, &redeem_hash);
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &redeem_hash);
    script_pubkey[22] = 0x87;

    const unsigned = try buildUnsignedTx(a, 900);
    const sighash = try bitcointx.legacy.sighash(a, unsigned, 0, redeem, SIGHASH_ALL);
    // Key 1's signature is well-formed but over some other digest.
    const bad1 = try derSigWithHashtype(a, normalizeLowS(try kp1.signPrehashed([_]u8{0x42} ** 32, null)), 0x01);
    const sig2 = try derSigWithHashtype(a, normalizeLowS(try kp2.signPrehashed(sighash, null)), 0x01);
    const sig3 = try derSigWithHashtype(a, normalizeLowS(try kp3.signPrehashed(sighash, null)), 0x01);
    const witness_utxo_value = try buildWitnessUtxoValue(a, 100_000, &script_pubkey);

    var input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pub1, .value = bad1 },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pub2, .value = sig2 },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pub3, .value = sig3 },
        .{ .keytype = psbt.input_key.REDEEM_SCRIPT, .keydata = &.{}, .value = redeem },
    };
    var input_maps = [_]psbt.Map{.{ .records = &input_records }};
    const ps = try wrapPsbt(a, unsigned, &input_maps);

    const results = try psbt.finalize(a, ps, .{});
    try testing.expect(results[0] == null);

    var expected: std.ArrayList(u8) = .empty;
    try expected.append(a, 0x00); // CHECKMULTISIG dummy
    for ([_][]const u8{ sig2, sig3 }) |push| {
        try expected.append(a, @intCast(push.len));
        try expected.appendSlice(a, push);
    }
    try expected.append(a, 0x4c); // OP_PUSHDATA1: the 105-byte script is past a direct push
    try expected.append(a, @intCast(redeem.len));
    try expected.appendSlice(a, redeem);
    try testing.expectEqualSlices(u8, expected.items, ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTSIG).?.value);
}

test "finalize: a legacy SIGHASH_SINGLE signature with no output at its index is refused by name unless allowed (A1 F4)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x81} ** 32);
    const pubkey = kp.public_key.toCompressedSec1();
    const pkh = try hash160Of(a, &pubkey);
    var script_pubkey: [25]u8 = undefined;
    script_pubkey[0] = 0x76;
    script_pubkey[1] = 0xa9;
    script_pubkey[2] = 0x14;
    @memcpy(script_pubkey[3..23], &pkh);
    script_pubkey[23] = 0x88;
    script_pubkey[24] = 0xac;

    // Two inputs, ONE output: input 1 has no output at its index.
    const vin = try a.alloc(bitcointx.TxIn, 2);
    vin[0] = .{ .prevout = .{ .txid = [_]u8{0xee} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
    vin[1] = .{ .prevout = .{ .txid = [_]u8{0xee} ** 32, .vout = 1 }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try a.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 900, .script_pubkey = &.{} };
    const unsigned: bitcointx.Transaction = .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };

    const SINGLE: u32 = 0x03;
    const digest0 = try bitcointx.legacy.sighash(a, unsigned, 0, &script_pubkey, SINGLE);
    const digest1 = try bitcointx.legacy.sighash(a, unsigned, 1, &script_pubkey, SINGLE);
    try testing.expectEqualSlices(u8, &bitcointx.legacy.sighash_single_bug, &digest1); // the bug, not a real digest
    const sig0 = try derSigWithHashtype(a, normalizeLowS(try kp.signPrehashed(digest0, null)), 0x03);
    const sig1 = try derSigWithHashtype(a, normalizeLowS(try kp.signPrehashed(digest1, null)), 0x03);
    const utxo = try buildWitnessUtxoValue(a, 100_000, &script_pubkey);

    // Default: input 0 (SINGLE with a matching output) finalizes, input 1 is refused.
    {
        var r0 = [_]psbt.Record{
            .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = utxo },
            .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig0 },
        };
        var r1 = [_]psbt.Record{
            .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = utxo },
            .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig1 },
        };
        var maps = [_]psbt.Map{ .{ .records = &r0 }, .{ .records = &r1 } };
        const ps = try wrapPsbt(a, unsigned, &maps);
        const results = try psbt.finalize(a, ps, .{});
        try testing.expect(results[0] == null);
        try expectInputError(results, 1, error.SighashSingleBug);
        try testing.expect(ps.inputs[1].find(psbt.input_key.FINAL_SCRIPTSIG) == null);
    }
    // Opt-in: exactly what consensus accepts.
    {
        var r1 = [_]psbt.Record{
            .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = utxo },
            .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig1 },
        };
        var r0 = [_]psbt.Record{
            .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = utxo },
        };
        var maps = [_]psbt.Map{ .{ .records = &r0 }, .{ .records = &r1 } };
        const ps = try wrapPsbt(a, unsigned, &maps);
        const results = try psbt.finalize(a, ps, .{ .allow_sighash_single_bug = true });
        try testing.expect(results[1] == null);
        try testing.expect(ps.inputs[1].find(psbt.input_key.FINAL_SCRIPTSIG) != null);
    }
}

// ── C: real P2SH 2-of-2 multisig (self-authored, real legacy sighash) ──

test "finalize+extract: real P2SH 2-of-2 multisig, byte-exact FINAL_SCRIPTSIG; insufficient signatures fails closed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp1 = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x61} ** 32);
    const kp2 = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x62} ** 32);
    const pub1 = kp1.public_key.toCompressedSec1();
    const pub2 = kp2.public_key.toCompressedSec1();

    const redeem = try buildMultisig2of2(a, &pub1, &pub2);
    const redeem_hash = try hash160Of(a, redeem);
    var script_pubkey: [23]u8 = undefined;
    script_pubkey[0] = 0xa9;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &redeem_hash);
    script_pubkey[22] = 0x87;

    const unsigned = try buildUnsignedTx(a, 900);
    const sighash = try bitcointx.legacy.sighash(a, unsigned, 0, redeem, SIGHASH_ALL);
    const sig1 = normalizeLowS(try kp1.signPrehashed(sighash, null));
    const sig2 = normalizeLowS(try kp2.signPrehashed(sighash, null));
    const sig1_ht = try derSigWithHashtype(a, sig1, 0x01);
    const sig2_ht = try derSigWithHashtype(a, sig2, 0x01);

    const witness_utxo_value = try buildWitnessUtxoValue(a, 100_000, &script_pubkey);

    var full_input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pub1, .value = sig1_ht },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pub2, .value = sig2_ht },
        .{ .keytype = psbt.input_key.REDEEM_SCRIPT, .keydata = &.{}, .value = redeem },
    };
    var full_input_maps = [_]psbt.Map{.{ .records = &full_input_records }};
    const ps = try wrapPsbt(a, unsigned, &full_input_maps);

    const results = try psbt.finalize(a, ps, .{});
    try testing.expect(results[0] == null);

    var expected: std.ArrayList(u8) = .empty;
    try expected.append(a, 0x00); // CHECKMULTISIG dummy
    try expected.append(a, @intCast(sig1_ht.len));
    try expected.appendSlice(a, sig1_ht);
    try expected.append(a, @intCast(sig2_ht.len));
    try expected.appendSlice(a, sig2_ht);
    try expected.append(a, @intCast(redeem.len));
    try expected.appendSlice(a, redeem);

    const got = ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTSIG).?;
    try testing.expectEqualSlices(u8, expected.items, got.value);
    try testing.expect(ps.inputs[0].find(psbt.input_key.REDEEM_SCRIPT) == null); // cleared

    const extracted = try psbt.extract(a, ps);
    try testing.expect(!extracted.has_witness);
    try testing.expectEqualSlices(u8, expected.items, extracted.vin[0].script_sig);

    // Independent re-check on the EXTRACTED transaction (not just finalize's
    // own internal verify): the spliced-in scriptSig must still satisfy the
    // original scriptPubKey through a fresh verifyScript call.
    const ctx: bitcoinscript.TxContext = .{ .tx = unsigned, .input_index = 0, .spent_outputs = &[_]bitcointx.TxOut{.{ .value = 100_000, .script_pubkey = &script_pubkey }} };
    try bitcoinscript.verifyScript(a, extracted.vin[0].script_sig, &script_pubkey, &.{}, bitcoinscript.ScriptFlags.standard, ctx);

    // Negative control: only ONE of the two required signatures present.
    var short_input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pub1, .value = sig1_ht },
        .{ .keytype = psbt.input_key.REDEEM_SCRIPT, .keydata = &.{}, .value = redeem },
    };
    var short_input_maps = [_]psbt.Map{.{ .records = &short_input_records }};
    const short_ps = try wrapPsbt(a, unsigned, &short_input_maps);
    const short_results = try psbt.finalize(a, short_ps, .{});
    try expectInputError(short_results, 0, error.InsufficientSignatures);
}

// ── D: real native P2WSH 2-of-2 multisig (self-authored, real BIP143) ──

test "finalize+extract: real native P2WSH 2-of-2 multisig, byte-exact FINAL_SCRIPTWITNESS" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp1 = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x71} ** 32);
    const kp2 = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic([_]u8{0x72} ** 32);
    const pub1 = kp1.public_key.toCompressedSec1();
    const pub2 = kp2.public_key.toCompressedSec1();
    const witness_script = try buildMultisig2of2(a, &pub1, &pub2);

    var program: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(witness_script, &program, .{});
    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x20;
    @memcpy(script_pubkey[2..34], &program);

    const unsigned = try buildUnsignedTx(a, 900);
    const credit_value: i64 = 7000;
    const sighash = try bitcointx.bip143.sighash(a, unsigned, 0, witness_script, credit_value, SIGHASH_ALL);
    const sig1_ht = try derSigWithHashtype(a, normalizeLowS(try kp1.signPrehashed(sighash, null)), 0x01);
    const sig2_ht = try derSigWithHashtype(a, normalizeLowS(try kp2.signPrehashed(sighash, null)), 0x01);

    const witness_utxo_value = try buildWitnessUtxoValue(a, credit_value, &script_pubkey);
    var input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pub1, .value = sig1_ht },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pub2, .value = sig2_ht },
        .{ .keytype = psbt.input_key.WITNESS_SCRIPT, .keydata = &.{}, .value = witness_script },
    };
    var input_maps = [_]psbt.Map{.{ .records = &input_records }};
    const ps = try wrapPsbt(a, unsigned, &input_maps);

    const results = try psbt.finalize(a, ps, .{});
    try testing.expect(results[0] == null);

    const expected_items = [_][]const u8{ &.{}, sig1_ht, sig2_ht, witness_script };
    const expected_enc = try psbt.encodeWitnessStack(a, &expected_items);
    const got = ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS).?;
    try testing.expectEqualSlices(u8, expected_enc, got.value);
    try testing.expect(ps.inputs[0].find(psbt.input_key.WITNESS_SCRIPT) == null); // cleared

    const extracted = try psbt.extract(a, ps);
    try testing.expect(extracted.has_witness);
    try testing.expectEqual(@as(usize, 4), extracted.witness[0].items.len);
}

// ── E: P2TR key-path -- fail-closed paths only (see file doc comment) ──

test "finalize: P2TR key-path with no TAP_KEY_SIG present fails closed with MissingTaprootSignature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const script_pubkey = [_]u8{ 0x51, 0x20 } ++ [_]u8{0xcc} ** 32;
    const unsigned = try buildUnsignedTx(a, 900);
    const witness_utxo_value = try buildWitnessUtxoValue(a, 7000, &script_pubkey);

    var input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
    };
    var input_maps = [_]psbt.Map{.{ .records = &input_records }};
    const ps = try wrapPsbt(a, unsigned, &input_maps);

    const results = try psbt.finalize(a, ps, .{});
    try expectInputError(results, 0, error.MissingTaprootSignature);
}

test "finalize: P2TR key-path fails closed with TaprootMissingAllUtxos when a SIBLING input's UTXO is unresolved" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const taproot_script_pubkey = [_]u8{ 0x51, 0x20 } ++ [_]u8{0xdd} ** 32;
    const dummy_sig = [_]u8{0xab} ** 64;

    const vin = try a.alloc(bitcointx.TxIn, 2);
    vin[0] = .{ .prevout = .{ .txid = [_]u8{0x01} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
    vin[1] = .{ .prevout = .{ .txid = [_]u8{0x02} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try a.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 900, .script_pubkey = &.{} };
    const unsigned: bitcointx.Transaction = .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };

    const witness_utxo_value = try buildWitnessUtxoValue(a, 7000, &taproot_script_pubkey);
    var input0_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.TAP_KEY_SIG, .keydata = &.{}, .value = &dummy_sig },
    };
    // Input 1: deliberately NO utxo information at all.
    var input1_records = [_]psbt.Record{};
    var input_maps = [_]psbt.Map{
        .{ .records = &input0_records },
        .{ .records = &input1_records },
    };
    const ps = try wrapPsbt(a, unsigned, &input_maps);

    const results = try psbt.finalize(a, ps, .{});
    try expectInputError(results, 0, error.TaprootMissingAllUtxos);
    try expectInputError(results, 1, error.MissingUtxo);
}

// ── F: BIP174 official Finalizer/Extractor worked example ───────────────
//
// `kat_vectors.zig`'s `finalize_combined_hex` -> `finalize_finalized_hex` ->
// `finalize_extracted_tx_hex` -- see that file's doc comment for exactly
// which BIP174 caption each came from. Two real spend shapes anchored
// byte-exact: bare P2SH 2-of-2 multisig (input 0, no witness) and
// P2SH-P2WSH 2-of-2 multisig (input 1, redeemScript push + witness).

/// True if `m` has ANY record of `keytype`, regardless of `keydata` --
/// unlike `Map.find` (which only matches the "no key data" singleton
/// shape), this is what's needed to assert a KEYED field type (e.g.
/// `BIP32_DERIVATION`, `PARTIAL_SIG`) is completely absent after clearing.
fn hasAnyOfType(m: psbt.Map, keytype: u64) bool {
    for (m.records) |r| {
        if (r.keytype == keytype) return true;
    }
    return false;
}

test "BIP174 official Finalizer/Extractor worked example: finalize is byte-exact; all BIP174-mandated fields cleared, UTXO kept" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const raw = try hexToBytesAlloc(a, vectors.finalize_combined_hex);
    const ps = try psbt.parse(a, raw);

    // Pre-finalize sanity: both inputs actually carry the fields BIP174
    // says must be cleared, so the post-finalize absence checks below are
    // testing something real, not vacuously true.
    try testing.expect(hasAnyOfType(ps.inputs[0], psbt.input_key.PARTIAL_SIG));
    try testing.expect(hasAnyOfType(ps.inputs[0], psbt.input_key.BIP32_DERIVATION));
    try testing.expect(ps.inputs[0].find(psbt.input_key.REDEEM_SCRIPT) != null);
    try testing.expect(hasAnyOfType(ps.inputs[1], psbt.input_key.PARTIAL_SIG));
    try testing.expect(hasAnyOfType(ps.inputs[1], psbt.input_key.BIP32_DERIVATION));
    try testing.expect(ps.inputs[1].find(psbt.input_key.WITNESS_SCRIPT) != null);

    const results = try psbt.finalize(a, ps, .{});
    try testing.expect(results[0] == null);
    try testing.expect(results[1] == null);

    const got = try psbt.serialize(a, ps);
    const want = try hexToBytesAlloc(a, vectors.finalize_finalized_hex);
    try testing.expectEqualSlices(u8, want, got);

    // BIP174 §"Input Finalizer": UTXO kept, everything else consumed
    // cleared -- checked explicitly per input, not just implied by the
    // byte-exact compare above.
    try testing.expect(ps.inputs[0].find(psbt.input_key.NON_WITNESS_UTXO) != null);
    try testing.expect(!hasAnyOfType(ps.inputs[0], psbt.input_key.PARTIAL_SIG));
    try testing.expect(ps.inputs[0].find(psbt.input_key.SIGHASH_TYPE) == null);
    try testing.expect(ps.inputs[0].find(psbt.input_key.REDEEM_SCRIPT) == null);
    try testing.expect(!hasAnyOfType(ps.inputs[0], psbt.input_key.BIP32_DERIVATION));
    try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTSIG) != null);
    try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) == null); // bare P2SH -- no witness

    try testing.expect(ps.inputs[1].find(psbt.input_key.WITNESS_UTXO) != null);
    try testing.expect(!hasAnyOfType(ps.inputs[1], psbt.input_key.PARTIAL_SIG));
    try testing.expect(ps.inputs[1].find(psbt.input_key.SIGHASH_TYPE) == null);
    try testing.expect(ps.inputs[1].find(psbt.input_key.REDEEM_SCRIPT) == null);
    try testing.expect(ps.inputs[1].find(psbt.input_key.WITNESS_SCRIPT) == null);
    try testing.expect(!hasAnyOfType(ps.inputs[1], psbt.input_key.BIP32_DERIVATION));
    try testing.expect(ps.inputs[1].find(psbt.input_key.FINAL_SCRIPTSIG) != null);
    try testing.expect(ps.inputs[1].find(psbt.input_key.FINAL_SCRIPTWITNESS) != null);
}

test "BIP174 official Finalizer/Extractor worked example: extract (from the BIP's OWN finalized PSBT, not our own output) is byte-exact" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Parsed directly from the BIP's own already-finalized vector -- this
    // exercises `extract` independent of whether `finalize` itself works,
    // so a bug in one doesn't mask a bug in (or hide a false pass of) the
    // other.
    const raw = try hexToBytesAlloc(a, vectors.finalize_finalized_hex);
    const ps = try psbt.parse(a, raw);

    const extracted = try psbt.extract(a, ps);
    try testing.expect(extracted.has_witness); // input 1's P2SH-P2WSH witness makes this a segwit-serialized tx
    const got = try bitcointx.serialize(a, extracted);
    const want = try hexToBytesAlloc(a, vectors.finalize_extracted_tx_hex);
    try testing.expectEqualSlices(u8, want, got);
}

// ── G: UTXO<->input binding (the spent output must belong to THIS input) ──
//
// A PSBT arrives from a co-signer who may be hostile, so its UTXO fields are
// CLAIMS. `finalize` runs `verifyScript` against the scriptPubKey and amount
// it resolves from them, so if the resolution is unbound, every signature is
// checked against whatever the sender chose to assert — the "verify-on-
// finalize" guarantee in `finalize.zig`'s doc comment reduces to "the sender's
// story is internally consistent". Both tests below therefore supply a
// well-formed, otherwise-verifying object that is bound to the WRONG thing;
// neither uses malformed input, which would prove nothing about this class.

/// A minimal, well-formed funding transaction paying `outs`.
fn buildPrevTx(a: Allocator, version: i32, outs: []const bitcointx.TxOut) !bitcointx.Transaction {
    const vin = try a.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = [_]u8{0xa1} ** 32, .vout = 7 }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try a.dupe(bitcointx.TxOut, outs);
    return .{ .version = version, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

fn buildUnsignedTxSpending(a: Allocator, prev_txid: [32]u8, vout_idx: u32, out_value: i64) !bitcointx.Transaction {
    const vin = try a.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = prev_txid, .vout = vout_idx }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try a.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = out_value, .script_pubkey = &.{} };
    return .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

test "finalize: a NON_WITNESS_UTXO whose txid is not the input's prevout is refused, even when its output is byte-identical to the real one" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [32]u8 = [_]u8{0x71} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();
    const pkh = try hash160Of(a, &pubkey);

    var script_pubkey: [22]u8 = undefined; // P2WPKH
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &pkh);

    var script_code: [25]u8 = undefined; // BIP143 implicit scriptCode
    script_code[0] = 0x76;
    script_code[1] = 0xa9;
    script_code[2] = 0x14;
    @memcpy(script_code[3..23], &pkh);
    script_code[23] = 0x88;
    script_code[24] = 0xac;

    const credit_value: i64 = 5000;
    const spent: bitcointx.TxOut = .{ .value = credit_value, .script_pubkey = &script_pubkey };

    // The genuine funding tx, and the input that actually spends its vout[0].
    const real_prev = try buildPrevTx(a, 2, &.{spent});
    const real_txid = try real_prev.txid(a);
    const unsigned = try buildUnsignedTxSpending(a, real_txid, 0, 900);

    const sighash = try bitcointx.bip143.sighash(a, unsigned, 0, &script_code, credit_value, SIGHASH_ALL);
    const sig_ht = try derSigWithHashtype(a, normalizeLowS(try kp.signPrehashed(sighash, null)), 0x01);

    // Control: the truthful NON_WITNESS_UTXO finalizes. This is what makes
    // the negative below meaningful -- it is the SAME PSBT with only the
    // funding transaction swapped.
    {
        const real_bytes = try bitcointx.serializeLegacy(a, real_prev);
        var recs = [_]psbt.Record{
            .{ .keytype = psbt.input_key.NON_WITNESS_UTXO, .keydata = &.{}, .value = real_bytes },
            .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig_ht },
        };
        var maps = [_]psbt.Map{.{ .records = &recs }};
        const ps = try wrapPsbt(a, unsigned, &maps);
        const results = try psbt.finalize(a, ps, .{});
        try testing.expect(results[0] == null);
    }

    // Attack: a DIFFERENT, perfectly well-formed transaction whose vout[0] is
    // byte-identical to the real one (same scriptPubKey, same amount) -- it
    // differs only in its version, so its txid differs. Because the output is
    // identical, `verifyScript` still passes and the signature still checks
    // out: nothing about this PSBT is internally inconsistent. The only thing
    // wrong with it is that it does not answer for THIS input, which is
    // exactly what an unbound resolution cannot see.
    const decoy = try buildPrevTx(a, 1, &.{spent});
    const decoy_txid = try decoy.txid(a);
    try testing.expect(!std.mem.eql(u8, &decoy_txid, &real_txid));

    const decoy_bytes = try bitcointx.serializeLegacy(a, decoy);
    var bad_recs = [_]psbt.Record{
        .{ .keytype = psbt.input_key.NON_WITNESS_UTXO, .keydata = &.{}, .value = decoy_bytes },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig_ht },
    };
    var bad_maps = [_]psbt.Map{.{ .records = &bad_recs }};
    const bad_ps = try wrapPsbt(a, unsigned, &bad_maps);
    const bad_results = try psbt.finalize(a, bad_ps, .{});
    try expectInputError(bad_results, 0, error.UtxoOutpointMismatch);
    try testing.expect(bad_ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) == null);
}

test "finalize: a WITNESS_UTXO contradicting the input's real NON_WITNESS_UTXO cannot override it (the lie must not win)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [32]u8 = [_]u8{0x72} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();
    const pkh = try hash160Of(a, &pubkey);

    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &pkh);

    var script_code: [25]u8 = undefined;
    script_code[0] = 0x76;
    script_code[1] = 0xa9;
    script_code[2] = 0x14;
    @memcpy(script_code[3..23], &pkh);
    script_code[23] = 0x88;
    script_code[24] = 0xac;

    const real_value: i64 = 5000;
    const claimed_value: i64 = 500_000; // the co-signer's lie
    const real_prev = try buildPrevTx(a, 2, &.{.{ .value = real_value, .script_pubkey = &script_pubkey }});
    const real_txid = try real_prev.txid(a);
    const unsigned = try buildUnsignedTxSpending(a, real_txid, 0, 900);

    // The signature commits to the LIE's amount (BIP143 covers the value), so
    // if the finalizer resolves the spent output from `WITNESS_UTXO` the whole
    // package verifies cleanly and the fabricated amount is what got checked.
    const sighash = try bitcointx.bip143.sighash(a, unsigned, 0, &script_code, claimed_value, SIGHASH_ALL);
    const sig_ht = try derSigWithHashtype(a, normalizeLowS(try kp.signPrehashed(sighash, null)), 0x01);

    const real_bytes = try bitcointx.serializeLegacy(a, real_prev);
    const lying_witness_utxo = try buildWitnessUtxoValue(a, claimed_value, &script_pubkey);

    var recs = [_]psbt.Record{
        .{ .keytype = psbt.input_key.NON_WITNESS_UTXO, .keydata = &.{}, .value = real_bytes },
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = lying_witness_utxo },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig_ht },
    };
    var maps = [_]psbt.Map{.{ .records = &recs }};
    const ps = try wrapPsbt(a, unsigned, &maps);
    const results = try psbt.finalize(a, ps, .{});
    try expectInputError(results, 0, error.UtxoFieldsDisagree);
    try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) == null);
}

// ── H: A1 audit F1 -- witness_utxo amount is a bare assertion ──────────────

test "finalize: spent-output amount outside 0..MAX_MONEY is rejected unconditionally; the boundary values are not (A1 F1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Recognized by no script-type parser in finalize.zig -- isolates the
    // amount check from script recognition entirely: if this test ever sees
    // `AmountOutOfRange` for a boundary value, or something OTHER than
    // `AmountOutOfRange` for an out-of-range one, the amount check itself is
    // what broke, not script dispatch.
    const dummy_script = [_]u8{0xff} ** 4;
    const unsigned = try buildUnsignedTxSpending(a, [_]u8{0xaa} ** 32, 0, 900);

    const out_of_range = [_]i64{ -1, psbt.MAX_MONEY + 1, std.math.minInt(i64), std.math.maxInt(i64) };
    for (out_of_range) |amount| {
        const wu = try buildWitnessUtxoValue(a, amount, &dummy_script);
        var recs = [_]psbt.Record{.{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = wu }};
        var maps = [_]psbt.Map{.{ .records = &recs }};
        const ps = try wrapPsbt(a, unsigned, &maps);
        const results = try psbt.finalize(a, ps, .{});
        try expectInputError(results, 0, error.AmountOutOfRange);
    }

    const boundary = [_]i64{ 0, psbt.MAX_MONEY };
    for (boundary) |amount| {
        const wu = try buildWitnessUtxoValue(a, amount, &dummy_script);
        var recs = [_]psbt.Record{.{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = wu }};
        var maps = [_]psbt.Map{.{ .records = &recs }};
        const ps = try wrapPsbt(a, unsigned, &maps);
        const results = try psbt.finalize(a, ps, .{});
        try expectInputError(results, 0, error.NonStandardScript);
    }
}

test "finalize: FinalizeOptions.require_non_witness_utxo rejects a witness-utxo-only input; default (off) still allows it (A1 F1 opt-in)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [32]u8 = [_]u8{0x94} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();
    const pkh = try hash160Of(a, &pubkey);

    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &pkh);

    var script_code: [25]u8 = undefined;
    script_code[0] = 0x76;
    script_code[1] = 0xa9;
    script_code[2] = 0x14;
    @memcpy(script_code[3..23], &pkh);
    script_code[23] = 0x88;
    script_code[24] = 0xac;

    const unsigned = try buildUnsignedTx(a, 900);
    const credit_value: i64 = 5000;
    const sighash = try bitcointx.bip143.sighash(a, unsigned, 0, &script_code, credit_value, SIGHASH_ALL);
    const sig_ht = try derSigWithHashtype(a, normalizeLowS(try kp.signPrehashed(sighash, null)), 0x01);
    const witness_utxo_value = try buildWitnessUtxoValue(a, credit_value, &script_pubkey);

    // Off by default: a legitimate P2WPKH-only signing flow that never sent
    // NON_WITNESS_UTXO still finalizes (DECISIONS.md SS2, psbt F1: requiring
    // it unconditionally "rozbije legitimni P2WPKH toky" -- breaks
    // legitimate P2WPKH flows).
    {
        var input_records = [_]psbt.Record{
            .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
            .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig_ht },
        };
        var input_maps = [_]psbt.Map{.{ .records = &input_records }};
        const ps = try wrapPsbt(a, unsigned, &input_maps);
        const results = try psbt.finalize(a, ps, .{});
        try testing.expect(results[0] == null);
    }

    // Same shape, opted in: now refused by name instead of silently trusted.
    {
        var input_records = [_]psbt.Record{
            .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
            .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig_ht },
        };
        var input_maps = [_]psbt.Map{.{ .records = &input_records }};
        const ps = try wrapPsbt(a, unsigned, &input_maps);
        const results = try psbt.finalize(a, ps, .{ .require_non_witness_utxo = true });
        try expectInputError(results, 0, error.MissingNonWitnessUtxo);
    }
}

// ── I: A1 audit F2 -- "already finalized" used to mean "trusted", not "verified" ──

test "finalize: attacker-supplied FINAL_SCRIPTSIG/FINAL_SCRIPTWITNESS is verified, not trusted for merely existing (A1 F2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [32]u8 = [_]u8{0x91} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();
    const pkh = try hash160Of(a, &pubkey);

    var script_pubkey: [22]u8 = undefined; // P2WPKH
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &pkh);

    const unsigned = try buildUnsignedTx(a, 900);
    const credit_value: i64 = 5000;
    const witness_utxo_value = try buildWitnessUtxoValue(a, credit_value, &script_pubkey);

    // (a) a bare FINAL_SCRIPTSIG the attacker made up directly: no
    // PARTIAL_SIG, no FINAL_SCRIPTWITNESS, no signature anywhere. Pre-fix,
    // `finalizeOneInput` saw a FINAL_SCRIPTSIG record and returned success
    // ("already finalized") without looking any further -- this is the
    // exact repro shape from the A1 audit record.
    {
        var recs = [_]psbt.Record{
            .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
            .{ .keytype = psbt.input_key.FINAL_SCRIPTSIG, .keydata = &.{}, .value = "\xde\xad\xbe\xef not a script at all" },
        };
        var maps = [_]psbt.Map{.{ .records = &recs }};
        const ps = try wrapPsbt(a, unsigned, &maps);
        const results = try psbt.finalize(a, ps, .{});
        try testing.expect(results[0] != null); // must NOT report success for junk
        try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTSIG) != null); // left as-is, not silently cleared
    }

    // (b) a bare FINAL_SCRIPTWITNESS the attacker made up: well-formed
    // CompactSize framing (so decodeWitnessStack itself has nothing to
    // reject), but not a real signature over anything.
    {
        const junk_witness = try psbt.encodeWitnessStack(a, &[_][]const u8{ "not a real sig", &pubkey });
        var recs = [_]psbt.Record{
            .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
            .{ .keytype = psbt.input_key.FINAL_SCRIPTWITNESS, .keydata = &.{}, .value = junk_witness },
        };
        var maps = [_]psbt.Map{.{ .records = &recs }};
        const ps = try wrapPsbt(a, unsigned, &maps);
        const results = try psbt.finalize(a, ps, .{});
        try testing.expect(results[0] != null); // must NOT report success for junk
    }
}

test "finalize: a genuinely-finalized input re-finalizes idempotently (positive control for A1 F2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [32]u8 = [_]u8{0x93} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();
    const pkh = try hash160Of(a, &pubkey);

    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &pkh);

    var script_code: [25]u8 = undefined;
    script_code[0] = 0x76;
    script_code[1] = 0xa9;
    script_code[2] = 0x14;
    @memcpy(script_code[3..23], &pkh);
    script_code[23] = 0x88;
    script_code[24] = 0xac;

    const unsigned = try buildUnsignedTx(a, 900);
    const credit_value: i64 = 5000;
    const sighash = try bitcointx.bip143.sighash(a, unsigned, 0, &script_code, credit_value, SIGHASH_ALL);
    const sig_ht = try derSigWithHashtype(a, normalizeLowS(try kp.signPrehashed(sighash, null)), 0x01);
    const witness_utxo_value = try buildWitnessUtxoValue(a, credit_value, &script_pubkey);

    var input_records = [_]psbt.Record{
        .{ .keytype = psbt.input_key.WITNESS_UTXO, .keydata = &.{}, .value = witness_utxo_value },
        .{ .keytype = psbt.input_key.PARTIAL_SIG, .keydata = &pubkey, .value = sig_ht },
    };
    var input_maps = [_]psbt.Map{.{ .records = &input_records }};
    const ps = try wrapPsbt(a, unsigned, &input_maps);

    const first = try psbt.finalize(a, ps, .{});
    try testing.expect(first[0] == null);
    try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) != null);

    // Second call sees an already-finalized input; it must still report
    // success -- the "already finalized" shortcut now means "STILL
    // verifies", not just "a FINAL_* record happens to be present".
    const second = try psbt.finalize(a, ps, .{});
    try testing.expect(second[0] == null);
}
