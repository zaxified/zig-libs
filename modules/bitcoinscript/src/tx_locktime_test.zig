// SPDX-License-Identifier: MIT
//! Runs `tx_locktime_vectors.zig` — the BIP65/BIP112 boundary rows of Bitcoin
//! Core's `tx_valid.json` + `tx_invalid.json` — through `verifyScript`, with
//! Core's per-file flag semantics (`transaction_tests.cpp`):
//!
//!   - `tx_valid`:   every input must verify under `~verify_flags`.
//!   - `tx_invalid`: at least one input must FAIL under exactly `verify_flags`.
//!
//! Why these rows and not more `script_tests.json`: `OP_CHECKLOCKTIMEVERIFY`
//! compares its operand against the spending transaction's `nLockTime` and is
//! disabled outright when the input's `nSequence` is `SEQUENCE_FINAL`;
//! `OP_CHECKSEQUENCEVERIFY` compares against `nSequence` itself. Core's
//! `script_tests.json` harness builds a synthetic spend with `nLockTime = 0`
//! and `nSequence = 0xffffffff` for EVERY row, so no row of that file can
//! distinguish `<=` from `>=` in either comparison. Real transactions are the
//! only external oracle for the boundary, and Core keeps them here.

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const asmparser = @import("asmparser.zig");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const flags_mod = @import("flags.zig");
const vectors_mod = @import("tx_locktime_vectors.zig");

const ScriptFlags = flags_mod.ScriptFlags;

fn hexDecode(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len == 0) return &[_]u8{};
    const out = try a.alloc(u8, hex.len / 2);
    return try std.fmt.hexToBytes(out, hex);
}

/// Core's JSON prints a prevout's txid in RPC display order (byte-reversed
/// relative to the wire order `TxIn.prevout.txid` holds).
fn txidFromDisplayHex(hex: []const u8) ![32]u8 {
    var buf: [32]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&buf, hex);
    if (decoded.len != 32) return error.BadTxid;
    var out: [32]u8 = undefined;
    for (buf, 0..) |b, i| out[31 - i] = b;
    return out;
}

fn flagsFor(v: vectors_mod.Vector) ScriptFlags {
    var f: ScriptFlags = if (v.valid) ScriptFlags.standard else ScriptFlags.none;
    for (v.json_flags) |name| {
        inline for (std.meta.fields(ScriptFlags)) |field| {
            if (field.type == bool and std.mem.eql(u8, field.name, @tagName(name))) {
                @field(f, field.name) = !v.valid;
            }
        }
    }
    return f;
}

const Row = struct {
    tx: bitcointx.Transaction,
    spent_outputs: []bitcointx.TxOut,
};

/// Aligns prevouts to `tx.vin` by OUTPOINT (Core keys
/// `mapprevOutScriptPubKeys` by `COutPoint`), so a mis-transcribed vector is a
/// hard error rather than a silently mismatched script.
fn buildRow(a: std.mem.Allocator, v: vectors_mod.Vector) !Row {
    const tx_bytes = try hexDecode(a, v.tx_hex);
    const tx = try bitcointx.deserialize(a, tx_bytes);

    const spent_outputs = try a.alloc(bitcointx.TxOut, tx.vin.len);
    for (tx.vin, 0..) |in, i| {
        var matched = false;
        for (v.prevouts) |p| {
            const txid = try txidFromDisplayHex(p.txid_hex);
            if (p.vout != in.prevout.vout) continue;
            if (!std.mem.eql(u8, &txid, &in.prevout.txid)) continue;
            spent_outputs[i] = .{
                .value = p.amount,
                .script_pubkey = try asmparser.assemble(a, p.script_asm),
            };
            matched = true;
            break;
        }
        if (!matched) return error.PrevoutNotFound;
    }
    return .{ .tx = tx, .spent_outputs = spent_outputs };
}

fn witnessFor(tx: bitcointx.Transaction, i: usize) []const []const u8 {
    if (!tx.has_witness) return &.{};
    return tx.witness[i].items;
}

fn verifyAllInputs(a: std.mem.Allocator, row: Row, flags: ScriptFlags) !void {
    for (row.tx.vin, 0..) |in, i| {
        const ctx: txctx.TxContext = .{ .tx = row.tx, .input_index = i, .spent_outputs = row.spent_outputs };
        try verify.verifyScript(a, in.script_sig, row.spent_outputs[i].script_pubkey, witnessFor(row.tx, i), flags, ctx);
    }
}

fn countValid() usize {
    var n: usize = 0;
    for (vectors_mod.vectors) |v| {
        if (v.valid) n += 1;
    }
    return n;
}

test "Bitcoin Core tx_valid.json BIP65/BIP112 rows: every input verifies" {
    var ran: usize = 0;
    for (vectors_mod.vectors) |v| {
        if (!v.valid) continue;
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const row = try buildRow(a, v);
        verifyAllInputs(a, row, flagsFor(v)) catch |err| {
            std.debug.print(
                "\nTX_VALID LOCKTIME MISMATCH (expected OK, got error.{s}): prevout={s} comment={s}\n",
                .{ @errorName(err), v.prevouts[0].script_asm, v.comment },
            );
            return error.VectorMismatch;
        };
        ran += 1;
    }
    try testing.expectEqual(countValid(), ran);
    try testing.expectEqual(@as(usize, 38), ran);
}

test "Bitcoin Core tx_invalid.json BIP65/BIP112 rows: at least one input fails" {
    var ran: usize = 0;
    for (vectors_mod.vectors) |v| {
        if (v.valid) continue;
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const row = try buildRow(a, v);
        if (verifyAllInputs(a, row, flagsFor(v))) |_| {
            std.debug.print(
                "\nTX_INVALID LOCKTIME MISMATCH (expected failure, got OK): prevout={s} comment={s}\n",
                .{ v.prevouts[0].script_asm, v.comment },
            );
            return error.VectorMismatch;
        } else |_| {}
        ran += 1;
    }
    try testing.expectEqual(vectors_mod.vectors.len - countValid(), ran);
    try testing.expectEqual(@as(usize, 30), ran);
}

test "the locktime corpus really does straddle the BIP65/BIP112 boundaries" {
    // A corpus that only carried, say, `0 CHECKLOCKTIMEVERIFY 1` rows would be
    // green while proving nothing about the comparison. Pin the presence of the
    // operands that sit exactly ON each threshold, in both directions.
    var below_lt_threshold = false; // 499999999 — last block-height value
    var at_lt_threshold = false; // 500000000 — first unix-time value
    var above_lt_threshold = false;
    var at_csv_type_flag = false; // 4194304 — BIP112 type flag bit
    var below_csv_type_flag = false; // 4194303
    var negative_operand = false;
    for (vectors_mod.vectors) |v| {
        for (v.prevouts) |p| {
            if (std.mem.indexOf(u8, p.script_asm, "499999999") != null) below_lt_threshold = true;
            if (std.mem.indexOf(u8, p.script_asm, "500000000 ") != null) at_lt_threshold = true;
            if (std.mem.indexOf(u8, p.script_asm, "500000001") != null) above_lt_threshold = true;
            if (std.mem.indexOf(u8, p.script_asm, "4194304") != null) at_csv_type_flag = true;
            if (std.mem.indexOf(u8, p.script_asm, "4194303") != null) below_csv_type_flag = true;
            if (std.mem.indexOf(u8, p.script_asm, "-1 CHECK") != null) negative_operand = true;
        }
    }
    try testing.expect(below_lt_threshold);
    try testing.expect(at_lt_threshold);
    try testing.expect(above_lt_threshold);
    try testing.expect(at_csv_type_flag);
    try testing.expect(below_csv_type_flag);
    try testing.expect(negative_operand);
}
