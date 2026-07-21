// SPDX-License-Identifier: MIT
//! Runs every `script_tests_vectors.zig` row through `verifyScript`,
//! reproducing Bitcoin Core's exact synthetic crediting/spending
//! transaction pair (`script_tests.cpp`):
//!
//! - crediting tx: 1 version, locktime 0, one null-prevout input with
//!   scriptSig `OP_0 OP_0` and max sequence, one output of value 0 holding
//!   the vector's `script_pubkey`.
//! - spending tx: 1 version, locktime 0, one input (prevout = the
//!   crediting tx's txid, vout 0) with scriptSig = the vector's
//!   `script_sig` and max sequence, one zero-value/empty-scriptPubKey
//!   output.
//!
//! Reproducing this exactly (not a simplified stand-in) is what makes the
//! CHECKSIG-bearing vectors meaningful: their signatures were computed
//! against precisely this pair, so a wrong harness would make every real
//! signature fail closed for the wrong reason.

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const asmparser = @import("asmparser.zig");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const vectors_mod = @import("script_tests_vectors.zig");

// NOTE: `.vin`/`.vout` are heap-allocated (via `allocator`, expected to be
// an arena the caller tears down in bulk) rather than
// `@constCast(&[_]T{...})` stack literals -- these helpers take runtime
// parameters (`script_pubkey`/`credit_txid`/etc.), so such a literal's
// backing storage is a function-local temporary that becomes a dangling
// pointer the instant the helper returns (Zig's `&<anon literal>` has
// ordinary local-variable lifetime, not "outlives the return"). A
// zero-parameter helper whose literal contents are fully comptime-known
// (e.g. `dummyCtx()` in the sibling test files) does not have this
// problem -- Zig promotes a fully comptime-known literal's address to
// static storage -- but nothing here is comptime-known.
fn buildCreditingTx(allocator: std.mem.Allocator, script_pubkey: []const u8) !bitcointx.Transaction {
    const vin = try allocator.alloc(bitcointx.TxIn, 1);
    vin[0] = .{
        .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0xffffffff },
        .script_sig = &[_]u8{ 0x00, 0x00 }, // OP_0 OP_0 (CScriptNum(0) CScriptNum(0))
        .sequence = 0xffffffff,
    };
    const vout = try allocator.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 0, .script_pubkey = script_pubkey };
    return .{ .version = 1, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

fn buildSpendingTx(allocator: std.mem.Allocator, script_sig: []const u8, credit_txid: [32]u8) !bitcointx.Transaction {
    const vin = try allocator.alloc(bitcointx.TxIn, 1);
    vin[0] = .{
        .prevout = .{ .txid = credit_txid, .vout = 0 },
        .script_sig = script_sig,
        .sequence = 0xffffffff,
    };
    const vout = try allocator.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = 0, .script_pubkey = &.{} };
    return .{ .version = 1, .vin = vin, .vout = vout, .witness = &.{}, .locktime = 0, .has_witness = false };
}

fn runVector(allocator: std.mem.Allocator, v: vectors_mod.Vector) !void {
    const script_sig = try asmparser.assemble(allocator, v.script_sig);
    const script_pubkey = try asmparser.assemble(allocator, v.script_pubkey);

    const credit_tx = try buildCreditingTx(allocator, script_pubkey);
    const credit_txid = try credit_tx.txid(allocator);
    const spend_tx = try buildSpendingTx(allocator, script_sig, credit_txid);

    const spent_outputs = [_]bitcointx.TxOut{credit_tx.vout[0]};
    const ctx: txctx.TxContext = .{ .tx = spend_tx, .input_index = 0, .spent_outputs = &spent_outputs };

    const result = verify.verifyScript(allocator, script_sig, script_pubkey, &.{}, v.flags, ctx);

    if (result) |_| {
        if (v.expect != null) {
            std.debug.print(
                "\nVECTOR MISMATCH (expected error {s}, got OK): scriptSig={s} scriptPubKey={s} comment={s}\n",
                .{ v.expect.?, v.script_sig, v.script_pubkey, v.comment },
            );
            return error.VectorMismatch;
        }
    } else |err| {
        const got_name = @errorName(err);
        const want = v.expect orelse {
            std.debug.print(
                "\nVECTOR MISMATCH (expected OK, got error.{s}): scriptSig={s} scriptPubKey={s} comment={s}\n",
                .{ got_name, v.script_sig, v.script_pubkey, v.comment },
            );
            return error.VectorMismatch;
        };
        if (!std.mem.eql(u8, got_name, want)) {
            std.debug.print(
                "\nVECTOR MISMATCH (expected error.{s}, got error.{s}): scriptSig={s} scriptPubKey={s} comment={s}\n",
                .{ want, got_name, v.script_sig, v.script_pubkey, v.comment },
            );
            return error.VectorMismatch;
        }
    }
}

test "script_tests.json pinned subset: every vector's result class matches Bitcoin Core's expectation" {
    var ok_count: usize = 0;
    var err_count: usize = 0;
    for (vectors_mod.vectors) |v| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        try runVector(arena.allocator(), v);
        if (v.expect == null) ok_count += 1 else err_count += 1;
    }
    // Sanity on the corpus shape itself (catches an accidental empty/truncated
    // vectors file from silently "passing" with zero coverage).
    try testing.expect(ok_count > 30);
    try testing.expect(err_count > 100);
    try testing.expectEqual(vectors_mod.vectors.len, ok_count + err_count);
}
