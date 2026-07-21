// SPDX-License-Identifier: MIT
//! BIP143 segwit-v0 signature hashing — the sighash algorithm every
//! P2WPKH/P2WSH/P2SH-wrapped-segwit-v0 signature is computed over.
//!
//! Unlike the legacy algorithm (`sighash_legacy.zig`), BIP143 hashes three
//! reusable "midstates" once per transaction (not once per input) and
//! commits to the specific input's spent *amount* directly (closing the
//! "amount not signed" class of bug the legacy algorithm has always had —
//! BIP143's own Motivation section). It also drops the legacy algorithm's
//! `FindAndDelete(OP_CODESEPARATOR)` step entirely (BIP143 "No
//! FindAndDelete") — `script_code` here is used exactly as given, no
//! implicit Script-aware rewriting, so unlike `sighash_legacy.zig` this
//! algorithm has NO scope cut relative to the spec.
//!
//! Preimage (all fields fixed-width, little-endian unless noted):
//! `nVersion(4) . hashPrevouts(32) . hashSequence(32) . outpoint(36) .
//! scriptCode(varint-len-prefixed) . amount(8) . nSequence(4) .
//! hashOutputs(32) . nLockTime(4) . hash_type(4)`, then `sha256d`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const hash256 = @import("hash256.zig");
const hashtype = @import("hashtype.zig");
const tx = @import("tx.zig");

pub const ALL = hashtype.ALL;
pub const NONE = hashtype.NONE;
pub const SINGLE = hashtype.SINGLE;
pub const ANYONECANPAY = hashtype.ANYONECANPAY;

pub const Bip143Error = error{InputIndexOutOfRange} || Allocator.Error;

pub const Midstates = struct {
    hash_prevouts: [32]u8,
    hash_sequence: [32]u8,
    hash_outputs: [32]u8,
};

fn appendCompactSize(buf: *std.ArrayList(u8), allocator: Allocator, value: u64) Allocator.Error!void {
    var tmp: [9]u8 = undefined;
    const w = tx.encodeCompactSize(value, &tmp) catch unreachable;
    try buf.appendSlice(allocator, w);
}

fn appendU32LE(buf: *std.ArrayList(u8), allocator: Allocator, v: u32) Allocator.Error!void {
    var tmp: [4]u8 = undefined;
    std.mem.writeInt(u32, &tmp, v, .little);
    try buf.appendSlice(allocator, &tmp);
}

fn appendI32LE(buf: *std.ArrayList(u8), allocator: Allocator, v: i32) Allocator.Error!void {
    var tmp: [4]u8 = undefined;
    std.mem.writeInt(i32, &tmp, v, .little);
    try buf.appendSlice(allocator, &tmp);
}

fn appendI64LE(buf: *std.ArrayList(u8), allocator: Allocator, v: i64) Allocator.Error!void {
    var tmp: [8]u8 = undefined;
    std.mem.writeInt(i64, &tmp, v, .little);
    try buf.appendSlice(allocator, &tmp);
}

/// The three reusable per-transaction midstates (BIP143 "Specification").
/// Each is `sha256d` of zero or more fixed-width fields; a field set is
/// replaced by 32 zero bytes exactly when BIP143 says to omit it (see
/// inline comments) rather than hashing an empty input.
pub fn midstates(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u32,
) Bip143Error!Midstates {
    if (input_index >= transaction.vin.len) return error.InputIndexOutOfRange;
    const base = hashtype.baseType(hash_type);
    const anyone_can_pay = hashtype.isAnyoneCanPay(hash_type);

    var hash_prevouts: [32]u8 = [_]u8{0} ** 32;
    var hash_sequence: [32]u8 = [_]u8{0} ** 32;
    if (!anyone_can_pay) {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        for (transaction.vin) |vin| {
            try buf.appendSlice(allocator, &vin.prevout.txid);
            try appendU32LE(&buf, allocator, vin.prevout.vout);
        }
        hash_prevouts = hash256.sha256d(buf.items);

        // hashSequence is only meaningful for ALL-like (not NONE/SINGLE).
        if (base != NONE and base != SINGLE) {
            buf.clearRetainingCapacity();
            for (transaction.vin) |vin| try appendU32LE(&buf, allocator, vin.sequence);
            hash_sequence = hash256.sha256d(buf.items);
        }
    }

    var hash_outputs: [32]u8 = [_]u8{0} ** 32;
    if (base != NONE and base != SINGLE) {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        for (transaction.vout) |vout| {
            try appendI64LE(&buf, allocator, vout.value);
            try appendCompactSize(&buf, allocator, vout.script_pubkey.len);
            try buf.appendSlice(allocator, vout.script_pubkey);
        }
        hash_outputs = hash256.sha256d(buf.items);
    } else if (base == SINGLE and input_index < transaction.vout.len) {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        const vout = transaction.vout[input_index];
        try appendI64LE(&buf, allocator, vout.value);
        try appendCompactSize(&buf, allocator, vout.script_pubkey.len);
        try buf.appendSlice(allocator, vout.script_pubkey);
        hash_outputs = hash256.sha256d(buf.items);
    }
    // else (SINGLE with input_index >= vout.len): stays all-zero, per BIP143.

    return .{ .hash_prevouts = hash_prevouts, .hash_sequence = hash_sequence, .hash_outputs = hash_outputs };
}

/// The full BIP143 preimage (caller owns the returned slice). `amount_sats`
/// is the value of the output this input spends (the amount BIP143
/// commits to that legacy sighash never did).
pub fn preimage(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    script_code: []const u8,
    amount_sats: i64,
    hash_type: u32,
) Bip143Error![]u8 {
    const mid = try midstates(allocator, transaction, input_index, hash_type);
    const vin = transaction.vin[input_index];

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, transaction.version);
    try buf.appendSlice(allocator, &mid.hash_prevouts);
    try buf.appendSlice(allocator, &mid.hash_sequence);
    try buf.appendSlice(allocator, &vin.prevout.txid);
    try appendU32LE(&buf, allocator, vin.prevout.vout);
    try appendCompactSize(&buf, allocator, script_code.len);
    try buf.appendSlice(allocator, script_code);
    try appendI64LE(&buf, allocator, amount_sats);
    try appendU32LE(&buf, allocator, vin.sequence);
    try buf.appendSlice(allocator, &mid.hash_outputs);
    try appendU32LE(&buf, allocator, transaction.locktime);
    try appendU32LE(&buf, allocator, hash_type);
    return buf.toOwnedSlice(allocator);
}

pub fn sighash(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    script_code: []const u8,
    amount_sats: i64,
    hash_type: u32,
) Bip143Error![32]u8 {
    const pre = try preimage(allocator, transaction, input_index, script_code, amount_sats, hash_type);
    defer allocator.free(pre);
    return hash256.sha256d(pre);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "input_index out of range is a typed error (midstates and sighash)" {
    var t: tx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{.{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 }}),
        .vout = &.{},
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    try testing.expectError(error.InputIndexOutOfRange, midstates(testing.allocator, t, 3, ALL));
    try testing.expectError(error.InputIndexOutOfRange, sighash(testing.allocator, t, 3, &.{}, 0, ALL));
    _ = &t;
}
