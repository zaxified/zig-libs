// SPDX-License-Identifier: MIT

//! What a validating node does with `bitcointx`: parse a raw transaction off
//! the wire, compute its txid, and produce the legacy (pre-segwit) sighash
//! for one input — the digest a signer or verifier actually needs.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const bitcointx = @import("bitcointx");

/// A minimal, well-formed legacy transaction: version 1, one input spending
/// an (arbitrary) previous output with an empty scriptSig, one output
/// paying 1 BTC to a trivial `OP_1` script, locktime 0.
const raw_tx = [_]u8{
    0x01, 0x00, 0x00, 0x00, // version = 1
    0x01, // vin count = 1
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // prevout txid (32 bytes)
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x00, 0x00, 0x00, 0x00, // prevout index = 0
    0x00, // scriptSig len = 0
    0xFF, 0xFF, 0xFF, 0xFF, // sequence
    0x01, // vout count = 1
    0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00, // value = 100_000_000 sats
    0x01, // scriptPubKey len = 1
    0x51, // scriptPubKey = OP_1
    0x00, 0x00, 0x00, 0x00, // locktime = 0
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var transaction = bitcointx.deserialize(gpa, &raw_tx) catch |err| switch (err) {
        error.Truncated, error.NonMinimal, error.TooManyItems, error.InvalidWitnessFlag, error.SuperfluousWitnessRecord, error.TrailingBytes => {
            std.debug.print("malformed transaction, rejecting\n", .{});
            return;
        },
        error.OutOfMemory => return err,
    };
    defer transaction.deinit(gpa);

    std.debug.print("parsed tx: version={d} vin={d} vout={d}\n", .{
        transaction.version,
        transaction.vin.len,
        transaction.vout.len,
    });

    const id = try transaction.txid(gpa);
    std.debug.print("txid[0..4]: {x:0>2}{x:0>2}{x:0>2}{x:0>2}\n", .{ id[0], id[1], id[2], id[3] });

    // Sign input 0 with SIGHASH_ALL, substituting the spent output's own
    // script as scriptCode — the digest a signer feeds into ECDSA.
    const digest = try bitcointx.legacy.sighash(gpa, transaction, 0, &[_]u8{0x51}, bitcointx.legacy.ALL);
    std.debug.print("legacy sighash[0..4]: {x:0>2}{x:0>2}{x:0>2}{x:0>2}\n", .{ digest[0], digest[1], digest[2], digest[3] });

    // An out-of-range input index must be a nameable error, not a panic —
    // a validator handling attacker-controlled indices relies on this.
    if (bitcointx.legacy.sighash(gpa, transaction, 5, &[_]u8{0x51}, bitcointx.legacy.ALL)) |_| {
        unreachable;
    } else |err| switch (err) {
        error.InputIndexOutOfRange => std.debug.print("out-of-range input index correctly rejected\n", .{}),
        error.OutOfMemory => return err,
    }
}
