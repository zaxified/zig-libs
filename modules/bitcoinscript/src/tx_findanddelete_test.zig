// SPDX-License-Identifier: MIT
//! Runs `tx_findanddelete_vectors.zig` — the `FindAndDelete` /
//! `OP_CODESEPARATOR` / `CONST_SCRIPTCODE` rows of Bitcoin Core's
//! `tx_valid.json` + `tx_invalid.json` — through the same `verifyScript`
//! entry point real spends use: full transaction deserialization, every
//! input's prevout matched by outpoint (not by position), the input's own
//! witness stack, and Core's flag-field semantics preserved per file.
//!
//! Core's harness (`src/test/transaction_tests.cpp`):
//!   - `tx_valid`:   `CheckTxScripts(..., ~verify_flags, ..., expect_valid=true)`
//!     — EVERY input must verify with all flags except the listed ones.
//!   - `tx_invalid`: `CheckTxScripts(..., verify_flags, ..., expect_valid=false)`
//!     — at least one input must FAIL with exactly the listed flags.
//! Both directions are reproduced below.

const std = @import("std");
const testing = std.testing;
const bitcointx = @import("bitcointx");
const asmparser = @import("asmparser.zig");
const verify = @import("verify.zig");
const txctx = @import("txctx.zig");
const flags_mod = @import("flags.zig");
const vectors_mod = @import("tx_findanddelete_vectors.zig");

const ScriptFlags = flags_mod.ScriptFlags;

fn hexDecode(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len == 0) return &[_]u8{};
    const out = try a.alloc(u8, hex.len / 2);
    return try std.fmt.hexToBytes(out, hex);
}

/// Core's JSON prints a prevout's txid in RPC display order (byte-reversed
/// relative to the wire/serialized order `TxIn.prevout.txid` holds).
fn txidFromDisplayHex(hex: []const u8) ![32]u8 {
    var buf: [32]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&buf, hex);
    if (decoded.len != 32) return error.BadTxid;
    var out: [32]u8 = undefined;
    for (buf, 0..) |b, i| out[31 - i] = b;
    return out;
}

/// Builds the `ScriptFlags` Core would run this row with: the full set minus
/// the listed flags for a `tx_valid` row, exactly the listed flags for a
/// `tx_invalid` one.
fn flagsFor(v: vectors_mod.Vector, extra_const_scriptcode: bool) ScriptFlags {
    var f: ScriptFlags = if (v.valid) ScriptFlags.standard else ScriptFlags.none;
    for (v.json_flags) |name| {
        inline for (std.meta.fields(ScriptFlags)) |field| {
            if (field.type == bool and std.mem.eql(u8, field.name, @tagName(name))) {
                @field(f, field.name) = !v.valid;
            }
        }
    }
    if (extra_const_scriptcode) f.const_scriptcode = true;
    return f;
}

const Row = struct {
    tx: bitcointx.Transaction,
    spent_outputs: []bitcointx.TxOut,
};

/// Deserializes the row's transaction and aligns its prevouts to `tx.vin` by
/// OUTPOINT (Core keys `mapprevOutScriptPubKeys` by `COutPoint`), so a
/// mis-transcribed vector shows up as a hard error rather than as a silently
/// mismatched script.
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

/// Verifies every input of the row under `flags`; returns the first input's
/// error, or success if all inputs verified (Core's `CheckTxScripts`).
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

test "Bitcoin Core tx_valid.json FindAndDelete/CODESEPARATOR rows: every input verifies" {
    var ran: usize = 0;
    for (vectors_mod.vectors) |v| {
        if (!v.valid) continue;
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const row = try buildRow(a, v);
        verifyAllInputs(a, row, flagsFor(v, false)) catch |err| {
            std.debug.print("\nTX_VALID MISMATCH (expected OK, got error.{s}): {s}\n", .{ @errorName(err), v.comment });
            return error.VectorMismatch;
        };
        ran += 1;
    }
    try testing.expectEqual(countValid(), ran);
    try testing.expect(ran >= 18);
}

test "Bitcoin Core tx_invalid.json FindAndDelete/CONST_SCRIPTCODE rows: at least one input fails" {
    var ran: usize = 0;
    for (vectors_mod.vectors) |v| {
        if (v.valid) continue;
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const row = try buildRow(a, v);
        if (verifyAllInputs(a, row, flagsFor(v, false))) |_| {
            std.debug.print("\nTX_INVALID MISMATCH (expected failure, got OK): {s}\n", .{v.comment});
            return error.VectorMismatch;
        } else |_| {}
        ran += 1;
    }
    try testing.expectEqual(vectors_mod.vectors.len - countValid(), ran);
    try testing.expect(ran >= 20);
}

test "CONST_SCRIPTCODE is observable: adding the flag Core lists as excluded makes a valid row fail" {
    // `tx_valid.json`'s third field is the set of flags under which the row is
    // NOT valid (Core runs `~verify_flags`). Core's own harness only asserts
    // the positive direction plus flag REMOVAL, so the assertion below is a
    // consequence of the file's documented semantics rather than something
    // Core itself checks — but it is independently pinned by the 12
    // `tx_invalid.json` rows of the "SCRIPT_VERIFY_CONST_SCRIPTCODE tests"
    // section, which are the same transactions with the flag applied.
    var checked: usize = 0;
    for (vectors_mod.vectors) |v| {
        if (!v.valid) continue;
        var excluded = false;
        for (v.json_flags) |n| {
            if (n == .const_scriptcode) excluded = true;
        }
        if (!excluded) continue;
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const row = try buildRow(a, v);
        if (verifyAllInputs(a, row, flagsFor(v, true))) |_| {
            std.debug.print("\nCONST_SCRIPTCODE MISMATCH (expected failure with the flag on, got OK): {s}\n", .{v.comment});
            return error.VectorMismatch;
        } else |err| {
            switch (err) {
                error.SigFindanddelete, error.OpCodeseparator => {},
                else => {
                    std.debug.print("\nCONST_SCRIPTCODE MISMATCH (expected SigFindanddelete/OpCodeseparator, got error.{s}): {s}\n", .{ @errorName(err), v.comment });
                    return error.VectorMismatch;
                },
            }
        }
        checked += 1;
    }
    try testing.expect(checked >= 15);
}
