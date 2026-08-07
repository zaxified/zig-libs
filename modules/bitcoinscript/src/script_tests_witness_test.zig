// SPDX-License-Identifier: MIT
//! Runs every `script_tests_witness_vectors.zig` row — the witness-bearing
//! rows of Bitcoin Core's `script_tests.json` — through `verifyScript`.
//!
//! Same synthetic transaction pair as `script_tests_test.zig`, with the two
//! differences a witness row carries (`script_tests.cpp`):
//!
//!  - `BuildCreditingTransaction(scriptPubKey, nValue)` puts the row's amount
//!    on the credited output, and `BuildSpendingTransaction` copies it onto
//!    the spending output. The amount is not decoration: BIP143 commits to it,
//!    so a wrong value makes every signature-bearing witness row fail closed.
//!  - the witness stack is attached to the spending input, and is what
//!    `verifyScript` runs the witness program against.
//!
//! Core's JSON stores the amount in BTC as a JSON number; the generator has
//! already converted it to satoshis, so nothing here re-does float math.

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const asmparser = @import("asmparser.zig");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const vectors_mod = @import("script_tests_witness_vectors.zig");

// See the sibling file's note: `.vin`/`.vout` must be heap-allocated, because
// these helpers take runtime parameters and an `&[_]T{...}` literal here would
// dangle the moment the helper returns.
fn buildCreditingTx(allocator: std.mem.Allocator, script_pubkey: []const u8, amount: i64) !bitcointx.Transaction {
    const vin = try allocator.alloc(bitcointx.TxIn, 1);
    vin[0] = .{
        .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0xffffffff },
        .script_sig = &[_]u8{ 0x00, 0x00 }, // OP_0 OP_0
        .sequence = 0xffffffff,
    };
    const vout = try allocator.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = amount, .script_pubkey = script_pubkey };
    return .{ .version = 1, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

fn buildSpendingTx(
    allocator: std.mem.Allocator,
    script_sig: []const u8,
    credit_txid: [32]u8,
    amount: i64,
    witness: []const []const u8,
) !bitcointx.Transaction {
    const vin = try allocator.alloc(bitcointx.TxIn, 1);
    vin[0] = .{
        .prevout = .{ .txid = credit_txid, .vout = 0 },
        .script_sig = script_sig,
        .sequence = 0xffffffff,
    };
    const vout = try allocator.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = amount, .script_pubkey = &.{} };
    const wit = try allocator.alloc(bitcointx.Witness, 1);
    wit[0] = .{ .items = @constCast(witness) };
    return .{
        .version = 1,
        .vin = vin,
        .vout = vout,
        .witness = wit,
        .locktime = 0,
        .has_witness = witness.len != 0,
    };
}

fn hexItems(allocator: std.mem.Allocator, hexes: []const []const u8) ![]const []const u8 {
    const out = try allocator.alloc([]const u8, hexes.len);
    for (hexes, 0..) |h, i| {
        const buf = try allocator.alloc(u8, h.len / 2);
        out[i] = try std.fmt.hexToBytes(buf, h);
    }
    return out;
}

fn runVector(allocator: std.mem.Allocator, v: vectors_mod.Vector) !void {
    const script_sig = try asmparser.assemble(allocator, v.script_sig);
    const script_pubkey = try asmparser.assemble(allocator, v.script_pubkey);
    const witness = try hexItems(allocator, v.witness);

    const credit_tx = try buildCreditingTx(allocator, script_pubkey, v.amount);
    const credit_txid = try credit_tx.txid(allocator);
    const spend_tx = try buildSpendingTx(allocator, script_sig, credit_txid, v.amount, witness);

    const spent_outputs = [_]bitcointx.TxOut{credit_tx.vout[0]};
    const ctx: txctx.TxContext = .{ .tx = spend_tx, .input_index = 0, .spent_outputs = &spent_outputs };

    const result = verify.verifyScript(allocator, script_sig, script_pubkey, witness, v.flags, ctx);

    if (result) |_| {
        if (v.expect != null) {
            std.debug.print(
                "\nWITNESS VECTOR MISMATCH (expected error.{s} / SCRIPT_ERR_{s}, got OK): scriptSig={s} scriptPubKey={s} comment={s}\n",
                .{ v.expect.?, v.core_expect, v.script_sig, v.script_pubkey, v.comment },
            );
            return error.VectorMismatch;
        }
    } else |err| {
        const got_name = @errorName(err);
        const want = v.expect orelse {
            std.debug.print(
                "\nWITNESS VECTOR MISMATCH (expected OK, got error.{s}): scriptSig={s} scriptPubKey={s} comment={s}\n",
                .{ got_name, v.script_sig, v.script_pubkey, v.comment },
            );
            return error.VectorMismatch;
        };
        if (!std.mem.eql(u8, got_name, want)) {
            std.debug.print(
                "\nWITNESS VECTOR MISMATCH (expected error.{s} / SCRIPT_ERR_{s}, got error.{s}): scriptSig={s} scriptPubKey={s} comment={s}\n",
                .{ want, v.core_expect, got_name, v.script_sig, v.script_pubkey, v.comment },
            );
            return error.VectorMismatch;
        }
    }
}

test "script_tests.json witness rows: every result class matches Bitcoin Core's" {
    var ok_count: usize = 0;
    var err_count: usize = 0;
    for (vectors_mod.vectors) |v| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        try runVector(arena.allocator(), v);
        if (v.expect == null) ok_count += 1 else err_count += 1;
    }
    // Corpus-shape sanity, so a truncated or empty vectors file cannot "pass"
    // with zero coverage. Upstream v29.0 has 107 witness rows: 42 OK, 65 error.
    try testing.expectEqual(@as(usize, 107), vectors_mod.vectors.len);
    try testing.expectEqual(@as(usize, 42), ok_count);
    try testing.expectEqual(@as(usize, 65), err_count);
}

test "the witness corpus really does reach the segwit paths it claims to" {
    // A corpus that never enters the witness machinery would still be green
    // while proving nothing, so pin the distinct outcome classes it produces.
    var seen_p2wpkh = false;
    var seen_p2wsh = false;
    var seen_malleated = false;
    var seen_minimalif = false;
    var seen_cleanstack = false;
    var seen_pubkeytype = false;
    var signed_ok = false;
    for (vectors_mod.vectors) |v| {
        if (std.mem.eql(u8, v.core_expect, "WITNESS_MALLEATED")) seen_malleated = true;
        if (std.mem.eql(u8, v.core_expect, "MINIMALIF")) seen_minimalif = true;
        if (std.mem.eql(u8, v.core_expect, "CLEANSTACK")) seen_cleanstack = true;
        if (std.mem.eql(u8, v.core_expect, "WITNESS_PUBKEYTYPE")) seen_pubkeytype = true;
        // A 20-byte program is P2WPKH, a 32-byte one P2WSH (BIP141).
        if (std.mem.startsWith(u8, v.script_pubkey, "0 0x14")) seen_p2wpkh = true;
        if (std.mem.startsWith(u8, v.script_pubkey, "0 0x20")) seen_p2wsh = true;
        // An OK row with a real signature: BIP143 sighash actually ran.
        if (v.expect == null and v.witness.len >= 2 and v.witness[0].len > 100) signed_ok = true;
    }
    try testing.expect(seen_p2wpkh);
    try testing.expect(seen_p2wsh);
    try testing.expect(seen_malleated);
    try testing.expect(seen_minimalif);
    try testing.expect(seen_cleanstack);
    try testing.expect(seen_pubkeytype);
    try testing.expect(signed_ok);
}
