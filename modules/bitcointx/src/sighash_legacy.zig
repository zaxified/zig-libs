// SPDX-License-Identifier: MIT
//! Legacy (pre-segwit) signature hashing — Bitcoin Core's `SignatureHash()`
//! from `script/interpreter.cpp`, the algorithm every P2PK/P2PKH/bare-
//! multisig/P2SH signature is computed over.
//!
//! ## Algorithm (per BIP: none — this predates the BIP process; described
//! here from Bitcoin Core's reference behavior, which `legacy_kat_vectors.zig`
//! is checked against)
//!
//! Build a modified copy of the transaction: every input's `scriptSig` is
//! cleared EXCEPT the input being signed, whose `scriptSig` becomes the
//! caller-supplied `script_code`. Then, keyed off `hash_type`'s low 5 bits
//! (`SIGHASH_NONE`/`SIGHASH_SINGLE`; every other value, including `ALL` and
//! any unrecognized value, is "ALL-like"):
//!
//! - `NONE`: drop all outputs; zero every OTHER input's `nSequence`.
//! - `SINGLE`: keep only outputs `0..=input_index` — nulling (`value = -1`,
//!   empty `scriptPubKey`) every one before `input_index`; zero every OTHER
//!   input's `nSequence`. If `input_index >= vout.len` there is no
//!   corresponding output to sign — Core returns the fixed constant
//!   `0x01` followed by 31 zero bytes without serializing anything (the
//!   historical "SIGHASH_SINGLE bug"; every implementation reproduces it
//!   for consensus/interop reasons even though it is not cryptographically
//!   sound as a signature target).
//! - `ALL`-like: keep everything as built above.
//!
//! Then, if `ANYONECANPAY` (`hash_type & 0x80`) is set, drop every input
//! except the one being signed. Serialize the result plus a trailing
//! 4-byte little-endian `hash_type`, and `sha256d` it.
//!
//! ## Scope: no `FindAndDelete(OP_CODESEPARATOR)`
//!
//! Bitcoin Core additionally strips every literal `OP_CODESEPARATOR`
//! (`0xab`) opcode from `script_code` before signing (`CScript::
//! FindAndDelete`), which requires walking `script_code` opcode-by-opcode
//! (respecting push-data lengths, so a `0xab` *byte* inside a push's data
//! payload must NOT be treated as an opcode) — i.e. a Script parser. This
//! module does not run a script interpreter (module doc comment, tx.zig)
//! and OP_CODESEPARATOR is essentially unused in deployed Bitcoin (no
//! standard script template ever emits it): callers whose `script_code`
//! could contain it must strip it themselves before calling `sighash`.
//! `legacy_kat_vectors.zig`'s vectors are filtered to exclude any case that
//! would need this step, so this simplification never masks a wrong
//! answer against the pinned KATs.

const std = @import("std");
const Allocator = std.mem.Allocator;
const hash256 = @import("hash256.zig");
const hashtype = @import("hashtype.zig");
const tx = @import("tx.zig");

pub const ALL = hashtype.ALL;
pub const NONE = hashtype.NONE;
pub const SINGLE = hashtype.SINGLE;
pub const ANYONECANPAY = hashtype.ANYONECANPAY;

pub const LegacyError = error{InputIndexOutOfRange} || Allocator.Error;

/// The historical "SIGHASH_SINGLE bug" constant (`uint256(1)`, internal
/// byte order: byte 0 = 0x01, the rest zero) that `sighash` returns,
/// without serializing anything, when `hash_type`'s base type is `SINGLE`
/// and `input_index` has no corresponding output.
pub const sighash_single_bug: [32]u8 = blk: {
    var b = [_]u8{0} ** 32;
    b[0] = 1;
    break :blk b;
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

/// Bitcoin Core's `SignatureHash()`. `input_index` selects which input is
/// being signed; `script_code` substitutes for that input's `scriptSig`
/// (see module doc comment for what "scriptCode" means here and what's
/// deliberately not handled).
pub fn sighash(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    script_code: []const u8,
    hash_type: u32,
) LegacyError![32]u8 {
    if (input_index >= transaction.vin.len) return error.InputIndexOutOfRange;
    const base = hashtype.baseType(hash_type);
    const anyone_can_pay = hashtype.isAnyoneCanPay(hash_type);

    // The SIGHASH_SINGLE bug: no corresponding output, no serialization.
    if (base == SINGLE and input_index >= transaction.vout.len) return sighash_single_bug;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try appendI32LE(&buf, allocator, transaction.version);

    if (anyone_can_pay) {
        try appendCompactSize(&buf, allocator, 1);
        const vin = transaction.vin[input_index];
        try buf.appendSlice(allocator, &vin.prevout.txid);
        try appendU32LE(&buf, allocator, vin.prevout.vout);
        try appendCompactSize(&buf, allocator, script_code.len);
        try buf.appendSlice(allocator, script_code);
        try appendU32LE(&buf, allocator, vin.sequence);
    } else {
        try appendCompactSize(&buf, allocator, transaction.vin.len);
        for (transaction.vin, 0..) |vin, i| {
            try buf.appendSlice(allocator, &vin.prevout.txid);
            try appendU32LE(&buf, allocator, vin.prevout.vout);
            if (i == input_index) {
                try appendCompactSize(&buf, allocator, script_code.len);
                try buf.appendSlice(allocator, script_code);
            } else {
                try appendCompactSize(&buf, allocator, 0);
            }
            // NONE/SINGLE zero every OTHER input's sequence; ALL-like and
            // the signed input itself always keep the original sequence.
            const seq = if (i != input_index and (base == NONE or base == SINGLE)) 0 else vin.sequence;
            try appendU32LE(&buf, allocator, seq);
        }
    }

    if (base == NONE) {
        try appendCompactSize(&buf, allocator, 0);
    } else if (base == SINGLE) {
        // input_index < vout.len, checked above.
        try appendCompactSize(&buf, allocator, input_index + 1);
        for (transaction.vout[0..input_index]) |_| {
            try appendI64LE(&buf, allocator, -1);
            try appendCompactSize(&buf, allocator, 0);
        }
        const vout = transaction.vout[input_index];
        try appendI64LE(&buf, allocator, vout.value);
        try appendCompactSize(&buf, allocator, vout.script_pubkey.len);
        try buf.appendSlice(allocator, vout.script_pubkey);
    } else {
        try appendCompactSize(&buf, allocator, transaction.vout.len);
        for (transaction.vout) |vout| {
            try appendI64LE(&buf, allocator, vout.value);
            try appendCompactSize(&buf, allocator, vout.script_pubkey.len);
            try buf.appendSlice(allocator, vout.script_pubkey);
        }
    }

    try appendU32LE(&buf, allocator, transaction.locktime);
    try appendU32LE(&buf, allocator, hash_type);

    return hash256.sha256d(buf.items);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn oneInOneOutTx(prevout_txid: [32]u8, out_value: i64) tx.Transaction {
    return .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{.{
            .prevout = .{ .txid = prevout_txid, .vout = 0 },
            .script_sig = &.{},
            .sequence = 0xffffffff,
        }}),
        .vout = @constCast(&[_]tx.TxOut{.{ .value = out_value, .script_pubkey = &.{} }}),
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
}

test "input_index out of range is a typed error" {
    var t = oneInOneOutTx([_]u8{0} ** 32, 1000);
    try testing.expectError(error.InputIndexOutOfRange, sighash(testing.allocator, t, 5, &.{}, ALL));
    _ = &t;
}

// This test is no longer the only thing standing behind the SIGHASH_SINGLE
// bug -- `single_bug_kat_test.zig` now anchors the boundary on an oracle from
// outside this repo. It stays because it checks something that oracle cannot:
// that the bug path returns *before* touching the allocator at all.
test "SIGHASH_SINGLE bug: input_index with no corresponding output returns the fixed constant, no allocation" {
    // 2 inputs, 1 output: input_index=1 is a valid vin index but has no
    // corresponding vout -- exactly the SIGHASH_SINGLE-bug trigger.
    var t: tx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{
            .{ .prevout = .{ .txid = [_]u8{0xaa} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff },
            .{ .prevout = .{ .txid = [_]u8{0xbb} ** 32, .vout = 1 }, .script_sig = &.{}, .sequence = 0xffffffff },
        }),
        .vout = @constCast(&[_]tx.TxOut{.{ .value = 1000, .script_pubkey = &.{} }}),
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    // fail_allocator: SIGHASH_SINGLE-bug path must return before touching
    // the allocator at all.
    var fail_alloc = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const got = try sighash(fail_alloc.allocator(), t, 1, &.{}, SINGLE);
    try testing.expectEqualSlices(u8, &sighash_single_bug, &got);
    _ = &t;
}
