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

    const results = try psbt.finalize(a, ps);
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

    const results = try psbt.finalize(a, ps);
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
    const bad_results = try psbt.finalize(a, bad_ps);
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

    const results = try psbt.finalize(a, ps);
    try testing.expect(results[0] != null);
    try testing.expectEqual(psbt.InputFinalizeError.MissingSignature, results[0].?);
    // Nothing was finalized: no FINAL_SCRIPTWITNESS/SCRIPTSIG got written,
    // and the (mismatched) PARTIAL_SIG is left in place, not cleared.
    try testing.expect(ps.inputs[0].find(psbt.input_key.FINAL_SCRIPTWITNESS) == null);
    try testing.expect(ps.inputs[0].findKeyed(psbt.input_key.PARTIAL_SIG, &pubkey) != null);
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

    const results = try psbt.finalize(a, ps);
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
    const short_results = try psbt.finalize(a, short_ps);
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

    const results = try psbt.finalize(a, ps);
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

    const results = try psbt.finalize(a, ps);
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

    const results = try psbt.finalize(a, ps);
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

    const results = try psbt.finalize(a, ps);
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
