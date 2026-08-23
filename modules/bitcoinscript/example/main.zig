// SPDX-License-Identifier: MIT

//! What a node validating a block does with `bitcoinscript`: given a
//! crediting output and the transaction that spends it, run the exact
//! consensus VM (`verifyScript`) a real node runs — legacy P2PKH here, the
//! simplest of the templates this module supports. The signature is
//! produced with `std.crypto.sign.ecdsa` and the sighash with the sibling
//! `bitcointx` module, so the whole chain (sighash -> ECDSA -> script
//! interpreter) is exercised, not a simplified stand-in. A second call with
//! an empty scriptSig shows script evaluation failing closed with a
//! nameable error rather than a panic on malformed input.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const bitcoinscript = @import("bitcoinscript");
const bitcointx = @import("bitcointx");
const ripemd160 = @import("ripemd160");

const EcdsaSecp256k1Sha256 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const SIGHASH_ALL: u32 = 1;

/// The coinbase-like transaction that creates the output being spent.
fn creditingTx(allocator: std.mem.Allocator, script_pubkey: []const u8, value: i64) !bitcointx.Transaction {
    const vin = try allocator.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0xffffffff }, .script_sig = &.{}, .sequence = 0xffffffff };
    const vout = try allocator.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = value, .script_pubkey = script_pubkey };
    return .{ .version = 1, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

/// The transaction under validation, spending `credit_txid`'s single output.
fn spendingTx(allocator: std.mem.Allocator, script_sig: []const u8, credit_txid: [32]u8) !bitcointx.Transaction {
    const vin = try allocator.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = credit_txid, .vout = 0 }, .script_sig = script_sig, .sequence = 0xffffffff };
    const vout = try allocator.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 900, .script_pubkey = &.{} };
    return .{ .version = 2, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // A deterministic key for a self-contained example — a real wallet
    // draws this from a proper CSPRNG/seed.
    const seed: [32]u8 = [_]u8{0x11} ** 32;
    const kp = try EcdsaSecp256k1Sha256.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toCompressedSec1();

    var pkh: [20]u8 = undefined;
    ripemd160.hash160(&pubkey, &pkh);

    // P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte pkh> OP_EQUALVERIFY OP_CHECKSIG.
    var script_pubkey: [25]u8 = undefined;
    script_pubkey[0] = 0x76;
    script_pubkey[1] = 0xa9;
    script_pubkey[2] = 0x14;
    @memcpy(script_pubkey[3..23], &pkh);
    script_pubkey[23] = 0x88;
    script_pubkey[24] = 0xac;

    const credit_tx = try creditingTx(a, &script_pubkey, 1000);
    const credit_txid = try credit_tx.txid(a);
    var spend_tx = try spendingTx(a, &.{}, credit_txid);

    const sighash = try bitcointx.legacy.sighash(a, spend_tx, 0, &script_pubkey, SIGHASH_ALL);
    var sig = try kp.signPrehashed(sighash, null);

    // BIP62 low-S: `ScriptFlags.standard` (used below) enforces that a
    // signature's S value is <= n/2 (`sigcheck.isLowS`) -- of the two
    // mathematically valid ECDSA signatures (r, s) and (r, n-s), only the
    // smaller S is standard. `std.crypto.sign.ecdsa` is a generic ECDSA
    // implementation with no Bitcoin awareness, so `signPrehashed` returns
    // whichever of the two the nonce happened to produce. bitcoinscript
    // itself only ever CHECKS this rule (it is a script verifier, not a
    // signer, and never produces a signature) -- canonicalizing to low-S is
    // the Bitcoin-aware caller's responsibility, exactly as a real wallet
    // does at signing time (e.g. Bitcoin Core's `CKey::Sign`).
    const neg_s = try std.crypto.ecc.Secp256k1.scalar.neg(sig.s, .big);
    if (std.mem.order(u8, &neg_s, &sig.s) == .lt) sig.s = neg_s;

    var der_buf: [EcdsaSecp256k1Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    var script_sig: std.ArrayList(u8) = .empty;
    try script_sig.append(a, @intCast(der.len + 1));
    try script_sig.appendSlice(a, der);
    try script_sig.append(a, 0x01); // SIGHASH_ALL byte
    try script_sig.append(a, 33);
    try script_sig.appendSlice(a, &pubkey);

    spend_tx.vin[0].script_sig = script_sig.items;
    const spent = [_]bitcointx.TxOut{credit_tx.vout[0]};
    const ctx: bitcoinscript.TxContext = .{ .tx = spend_tx, .input_index = 0, .spent_outputs = &spent };

    try bitcoinscript.verifyScript(a, script_sig.items, &script_pubkey, &.{}, bitcoinscript.ScriptFlags.standard, ctx);
    std.debug.print("P2PKH spend verified\n", .{});

    // An empty scriptSig leaves the stack empty when script_pubkey starts
    // executing, so P2PKH's very first opcode (OP_DUP) fails its own
    // precondition (it needs an existing top stack item to duplicate) —
    // `error.InvalidStackOperation`, not `error.EvalFalse` (which only
    // applies once evaluation reaches the end with a false top item).
    // Either way, `verifyScript` must reject this by a specific named
    // error, not a panic — exactly the untrusted-input contract the
    // module's docs describe.
    if (bitcoinscript.verifyScript(a, &.{}, &script_pubkey, &.{}, bitcoinscript.ScriptFlags.standard, ctx)) |_| {
        return error.EmptyScriptSigUnexpectedlyVerified;
    } else |err| switch (err) {
        error.InvalidStackOperation => std.debug.print("empty scriptSig correctly rejected: InvalidStackOperation\n", .{}),
        else => return err,
    }
}
