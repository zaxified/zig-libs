// SPDX-License-Identifier: MIT
//! End-to-end teeth: real P2PKH, P2WPKH, and P2TR (key-path) spends,
//! signed with `std.crypto.sign.ecdsa`/`bip340` and verified through this
//! module's `verifyScript` — i.e. through the SAME sighash
//! (`bitcointx.legacy`/`bitcointx.bip143`/`bitcointx.bip341`) and curve
//! verification (`sigcheck`/`bip340.verify`) code paths a real node would
//! use, not a simplified stand-in. Each spend has a positive control (a
//! one-byte-tampered signature must fail) proving these tests can actually
//! detect a broken verifier, not just a broken signer.
//!
//! P2TR here uses the internal key directly as the taproot output key
//! (no BIP341 tweak) — a legitimate (if unusual) key-path-only
//! construction; BIP341 does not require a script-tree tweak for
//! consensus validity, and applying one is a spender/wallet-side concern
//! orthogonal to what this test is checking (sighash + Schnorr
//! verification correctness).

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const bip340 = @import("bip340");
const k256 = @import("k256");
const ripemd160 = @import("ripemd160");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const flags_mod = @import("flags.zig");

const EcdsaSecp256k1Sha256 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const SIGHASH_ALL: u32 = 1;

/// Asserts `result` is ANY error (not a specific class) -- the exact error
/// class a one-byte signature tamper produces depends on incidental byte
/// patterns (whether the flipped byte happens to also break DER structural
/// validity vs. just the cryptographic check), which isn't the point of a
/// positive control; "must fail closed at all" is.
fn expectFailure(result: verify.VerifyError!void) !void {
    if (result) |_| {
        try testing.expect(false);
    } else |_| {}
}

/// `std.crypto.sign.ecdsa`'s `signPrehashed` does not itself enforce
/// BIP62/BIP146 low-S normalization (that's `sigcheck`'s job to CHECK, not
/// the signer's job to produce automatically) -- a raw signature is
/// low-S/high-S with roughly equal probability. Real wallets always
/// normalize before broadcasting; this test does the same (negate `s` to
/// `n - s`, which is an equally valid signature for the same message under
/// ECDSA's `(r, s)`/`(r, n-s)` symmetry) so it exercises
/// `ScriptFlags.standard` (which sets `low_s = true`) faithfully rather
/// than silently relying on getting lucky.
fn normalizeLowS(sig: EcdsaSecp256k1Sha256.Signature) EcdsaSecp256k1Sha256.Signature {
    const n: u256 = k256.scalar.field_order;
    const half = n >> 1;
    const s_val = std.mem.readInt(u256, &sig.s, .big);
    if (s_val <= half) return sig;
    var new_s: [32]u8 = undefined;
    std.mem.writeInt(u256, &new_s, n - s_val, .big);
    return .{ .r = sig.r, .s = new_s };
}

// NOTE: heap-allocated via `allocator` (an arena the caller tears down in
// bulk), not `@constCast(&[_]T{...})` stack literals -- these helpers take
// runtime parameters, so such a literal is a dangling pointer the instant
// the helper returns (see the identical note in script_tests_test.zig).
fn creditingTx(allocator: std.mem.Allocator, script_pubkey: []const u8, value: i64) !bitcointx.Transaction {
    const vin = try allocator.alloc(bitcointx.TxIn, 1);
    vin[0] = .{
        .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0xffffffff },
        .script_sig = &.{},
        .sequence = 0xffffffff,
    };
    const vout = try allocator.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = value, .script_pubkey = script_pubkey };
    return .{ .version = 1, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

fn spendingTx(allocator: std.mem.Allocator, script_sig: []const u8, credit_txid: [32]u8, has_witness: bool) !bitcointx.Transaction {
    const vin = try allocator.alloc(bitcointx.TxIn, 1);
    vin[0] = .{
        .prevout = .{ .txid = credit_txid, .vout = 0 },
        .script_sig = script_sig,
        .sequence = 0xffffffff,
    };
    const vout = try allocator.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 900, .script_pubkey = &.{} };
    return .{
        .version = 2,
        .vin = vin,
        .vout = vout,
        .witness = &.{},
        .locktime = 0,
        .has_witness = has_witness,
    };
}

// ── P2PKH ────────────────────────────────────────────────────────────────

test "e2e: real P2PKH spend verifies; a tampered signature byte fails closed" {
    const allocator = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [32]u8 = [_]u8{0x11} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();

    var pkh: [20]u8 = undefined;
    ripemd160.hash160(&pubkey, &pkh);

    var script_pubkey: [25]u8 = undefined;
    script_pubkey[0] = 0x76;
    script_pubkey[1] = 0xa9;
    script_pubkey[2] = 0x14;
    @memcpy(script_pubkey[3..23], &pkh);
    script_pubkey[23] = 0x88;
    script_pubkey[24] = 0xac;

    const credit_tx = try creditingTx(a, &script_pubkey, 1000);
    const credit_txid = try credit_tx.txid(a);

    // scriptSig depends on the spending tx, but the spending tx's shape
    // doesn't depend on scriptSig content length here -- build it once,
    // compute the sighash, then re-derive scriptSig bytes.
    var spend_tx = try spendingTx(a, &.{}, credit_txid, false);

    const sighash = try bitcointx.legacy.sighash(a, spend_tx, 0, &script_pubkey, SIGHASH_ALL);
    const sig = normalizeLowS(try kp.signPrehashed(sighash, null));
    var der_buf: [EcdsaSecp256k1Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    var sig_with_ht: [EcdsaSecp256k1Sha256.Signature.der_encoded_length_max + 1]u8 = undefined;
    @memcpy(sig_with_ht[0..der.len], der);
    sig_with_ht[der.len] = 0x01; // SIGHASH_ALL

    var script_sig: std.ArrayList(u8) = .empty;
    try script_sig.append(a, @intCast(der.len + 1));
    try script_sig.appendSlice(a, sig_with_ht[0 .. der.len + 1]);
    try script_sig.append(a, 33);
    try script_sig.appendSlice(a, &pubkey);

    spend_tx.vin[0].script_sig = script_sig.items;
    const spent = [_]bitcointx.TxOut{credit_tx.vout[0]};
    const ctx: txctx.TxContext = .{ .tx = spend_tx, .input_index = 0, .spent_outputs = &spent };

    try verify.verifyScript(a, script_sig.items, &script_pubkey, &.{}, flags_mod.ScriptFlags.standard, ctx);

    // Positive control: flip one byte inside the DER signature.
    var tampered = try a.dupe(u8, script_sig.items);
    tampered[5] ^= 0x01;
    try expectFailure(verify.verifyScript(a, tampered, &script_pubkey, &.{}, flags_mod.ScriptFlags.standard, ctx));
}

// ── P2WPKH ───────────────────────────────────────────────────────────────

test "e2e: real P2WPKH spend verifies via BIP143 sighash; tampered signature fails closed" {
    const allocator = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [32]u8 = [_]u8{0x22} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();

    var pkh: [20]u8 = undefined;
    ripemd160.hash160(&pubkey, &pkh);

    // P2WPKH output: 0x00 0x14 <20-byte-pubkeyhash>.
    var script_pubkey: [22]u8 = undefined;
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x14;
    @memcpy(script_pubkey[2..22], &pkh);

    // BIP143 scriptCode for P2WPKH is the implicit P2PKH-shaped script.
    var script_code: [25]u8 = undefined;
    script_code[0] = 0x76;
    script_code[1] = 0xa9;
    script_code[2] = 0x14;
    @memcpy(script_code[3..23], &pkh);
    script_code[23] = 0x88;
    script_code[24] = 0xac;

    const credit_value: i64 = 5000;
    const credit_tx = try creditingTx(a, &script_pubkey, credit_value);
    const credit_txid = try credit_tx.txid(a);
    const spend_tx = try spendingTx(a, &.{}, credit_txid, true);

    const sighash = try bitcointx.bip143.sighash(a, spend_tx, 0, &script_code, credit_value, SIGHASH_ALL);
    const sig = normalizeLowS(try kp.signPrehashed(sighash, null));
    var der_buf: [EcdsaSecp256k1Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    var sig_with_ht: [EcdsaSecp256k1Sha256.Signature.der_encoded_length_max + 1]u8 = undefined;
    @memcpy(sig_with_ht[0..der.len], der);
    sig_with_ht[der.len] = 0x01;

    const witness = [_][]const u8{ sig_with_ht[0 .. der.len + 1], &pubkey };
    const spent = [_]bitcointx.TxOut{credit_tx.vout[0]};
    const ctx: txctx.TxContext = .{ .tx = spend_tx, .input_index = 0, .spent_outputs = &spent };

    try verify.verifyScript(a, &.{}, &script_pubkey, &witness, flags_mod.ScriptFlags.standard, ctx);

    var tampered_sig = try a.dupe(u8, witness[0]);
    tampered_sig[5] ^= 0x01;
    const bad_witness = [_][]const u8{ tampered_sig, &pubkey };
    try expectFailure(verify.verifyScript(a, &.{}, &script_pubkey, &bad_witness, flags_mod.ScriptFlags.standard, ctx));
}

// ── P2TR key-path ───────────────────────────────────────────────────────

test "e2e: real P2TR key-path spend verifies via BIP341 sighash + BIP340 Schnorr; tampered signature fails closed" {
    const allocator = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sk = try bip340.SecretKey.fromBytes([_]u8{0x33} ** 32);
    const kp = try bip340.KeyPair.fromSecretKey(sk);
    const program = kp.public.x; // untweaked internal key used directly as the output key (module doc comment)

    var script_pubkey: [34]u8 = undefined;
    script_pubkey[0] = 0x51; // OP_1 (witness version 1)
    script_pubkey[1] = 0x20; // 32-byte push
    @memcpy(script_pubkey[2..34], &program);

    const credit_value: i64 = 7000;
    const credit_tx = try creditingTx(a, &script_pubkey, credit_value);
    const credit_txid = try credit_tx.txid(a);
    const spend_tx = try spendingTx(a, &.{}, credit_txid, true);

    const spent = [_]bitcointx.TxOut{credit_tx.vout[0]};
    const sighash = try bitcointx.bip341.sighash(a, spend_tx, 0, bitcointx.bip341.SIGHASH_DEFAULT, &spent);

    const io_undefined: std.Io = undefined;
    const sig64 = try bip340.sign(sk, &sighash, [_]u8{0x44} ** 32, io_undefined);

    const witness = [_][]const u8{&sig64};
    const ctx: txctx.TxContext = .{ .tx = spend_tx, .input_index = 0, .spent_outputs = &spent };

    try verify.verifyScript(a, &.{}, &script_pubkey, &witness, flags_mod.ScriptFlags.standard, ctx);

    var tampered = sig64;
    tampered[10] ^= 0x01;
    const bad_witness = [_][]const u8{&tampered};
    try expectFailure(verify.verifyScript(a, &.{}, &script_pubkey, &bad_witness, flags_mod.ScriptFlags.standard, ctx));
}
