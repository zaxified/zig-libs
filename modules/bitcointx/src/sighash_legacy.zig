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
//! ## `OP_CODESEPARATOR` removal is part of the serialization
//!
//! Core does NOT write `script_code` verbatim. `CTransactionSignatureSerializer
//! ::SerializeScriptCode` (`script/interpreter.cpp`) walks it opcode by opcode
//! and omits every literal `OP_CODESEPARATOR` (`0xab`) *opcode* — a `0xab`
//! byte inside a push's data payload is left alone, which is why the walk has
//! to be a real Script parse and not a `memchr`. `appendScriptCode` below
//! reproduces it, including the two details that make it not just "delete the
//! 0xab bytes":
//!
//!  - the CompactSize prefix Core writes is `scriptCode.size() -
//!    nCodeSeparators`, computed from the FIRST walk, not from the number of
//!    bytes the second walk actually emits;
//!  - both walks end at the first `GetOp` that fails, and the trailing write
//!    is bounded by where that failed `GetOp` left the cursor — so an
//!    undecodable tail is truncated, not copied whole.
//!
//! For a `script_code` that decodes cleanly and holds no `OP_CODESEPARATOR`
//! — every standard template — this is byte-for-byte the old verbatim write.
//!
//! This module still runs no interpreter: the walk below only needs push-length
//! rules, no opcode semantics, no stack.

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

/// Bitcoin Core's `GetScriptOp` (`script/script.cpp`), reduced to what
/// `SerializeScriptCode` uses: the opcode, and the cursor position afterwards.
/// Returns null when the decode fails — and, like Core's, leaves `pc` where the
/// failed attempt left it, having already consumed the opcode byte and any
/// length prefix it managed to read before the check that failed. That
/// end position is load-bearing: it bounds the trailing write below.
fn getOp(script: []const u8, pc: *usize) ?u8 {
    if (pc.* >= script.len) return null;
    const opcode = script[pc.*];
    pc.* += 1;
    if (opcode <= 0x4e) { // OP_PUSHDATA4
        var size: u64 = 0;
        if (opcode < 0x4c) {
            size = opcode;
        } else if (opcode == 0x4c) {
            if (script.len - pc.* < 1) return null;
            size = script[pc.*];
            pc.* += 1;
        } else if (opcode == 0x4d) {
            if (script.len - pc.* < 2) return null;
            size = std.mem.readInt(u16, script[pc.*..][0..2], .little);
            pc.* += 2;
        } else {
            if (script.len - pc.* < 4) return null;
            size = std.mem.readInt(u32, script[pc.*..][0..4], .little);
            pc.* += 4;
        }
        if (script.len - pc.* < size) return null;
        pc.* += @intCast(size);
    }
    return opcode;
}

const op_codeseparator: u8 = 0xab;

/// Core's `CTransactionSignatureSerializer::SerializeScriptCode`: the
/// CompactSize length, then `script_code` with every `OP_CODESEPARATOR`
/// *opcode* omitted.
///
/// The declared length is `script_code.len - n_separators`, taken from the
/// counting walk. When the emitting walk stops early on an undecodable tail
/// that number can exceed the bytes actually written — Core does exactly this,
/// so reproducing it is the point, not a bug to round off. It cannot change a
/// verdict on its own: the script that produced such a scriptCode fails to
/// decode in the interpreter too.
fn appendScriptCode(buf: *std.ArrayList(u8), allocator: Allocator, script_code: []const u8) Allocator.Error!void {
    var it: usize = 0;
    var n_separators: usize = 0;
    while (getOp(script_code, &it)) |op| {
        if (op == op_codeseparator) n_separators += 1;
    }
    try appendCompactSize(buf, allocator, script_code.len - n_separators);

    var begin: usize = 0;
    it = 0;
    while (getOp(script_code, &it)) |op| {
        if (op == op_codeseparator) {
            // `it` sits just past the 1-byte opcode, so `it - 1` is the 0xab.
            try buf.appendSlice(allocator, script_code[begin .. it - 1]);
            begin = it;
        }
    }
    if (begin != script_code.len) try buf.appendSlice(allocator, script_code[begin..it]);
}

/// Upper bound on `sighash`'s preimage size, for `ensureTotalCapacity` (B2).
/// Mirrors the append sequence below field for field; the one inexact term
/// (`script_code.len` standing in for `appendScriptCode`'s actual,
/// codeseparator-stripped output) can only overestimate.
fn estimatePreimageCapacity(
    transaction: tx.Transaction,
    script_code: []const u8,
    input_index: usize,
    base: u32,
    anyone_can_pay: bool,
) usize {
    var total: usize = 4; // version
    if (anyone_can_pay) {
        total += 1; // CompactSize(1)
        total += 36; // txid + vout
        total += tx.compactSizeLen(script_code.len) + script_code.len;
        total += 4; // sequence
    } else {
        total += tx.compactSizeLen(transaction.vin.len);
        for (transaction.vin, 0..) |_, i| {
            total += 36; // txid + vout
            total += if (i == input_index)
                tx.compactSizeLen(script_code.len) + script_code.len
            else
                1; // CompactSize(0): other inputs' scriptSig is cleared
            total += 4; // sequence
        }
    }
    if (base == NONE) {
        total += 1; // CompactSize(0)
    } else if (base == SINGLE) {
        total += tx.compactSizeLen(input_index + 1);
        total += input_index * 9; // each null output: value(8) + CompactSize(0)
        if (input_index < transaction.vout.len) {
            const vout = transaction.vout[input_index];
            total += 8 + tx.compactSizeLen(vout.script_pubkey.len) + vout.script_pubkey.len;
        }
    } else {
        total += tx.compactSizeLen(transaction.vout.len);
        for (transaction.vout) |vout| total += 8 + tx.compactSizeLen(vout.script_pubkey.len) + vout.script_pubkey.len;
    }
    total += 4 + 4; // locktime + hash_type
    return total;
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
    // B2: unlike the other two sighash algorithms, this preimage had NO
    // capacity reservation at all despite serializing the whole transaction.
    // `estimatePreimageCapacity` mirrors the append calls below; it may
    // overestimate slightly (it bounds `appendScriptCode`'s output by
    // `script_code.len`, which only shrinks when OP_CODESEPARATOR opcodes are
    // stripped) but never underestimates in a way that would be wrong --
    // `ensureTotalCapacity` is a hint, not a bound, so any gap just costs an
    // extra grow, same as today.
    try buf.ensureTotalCapacity(allocator, estimatePreimageCapacity(transaction, script_code, input_index, base, anyone_can_pay));

    try appendI32LE(&buf, allocator, transaction.version);

    if (anyone_can_pay) {
        try appendCompactSize(&buf, allocator, 1);
        const vin = transaction.vin[input_index];
        try buf.appendSlice(allocator, &vin.prevout.txid);
        try appendU32LE(&buf, allocator, vin.prevout.vout);
        try appendScriptCode(&buf, allocator, script_code);
        try appendU32LE(&buf, allocator, vin.sequence);
    } else {
        try appendCompactSize(&buf, allocator, transaction.vin.len);
        for (transaction.vin, 0..) |vin, i| {
            try buf.appendSlice(allocator, &vin.prevout.txid);
            try appendU32LE(&buf, allocator, vin.prevout.vout);
            if (i == input_index) {
                try appendScriptCode(&buf, allocator, script_code);
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

/// `SigningError`, in addition to `LegacyError`: the SIGHASH_SINGLE bug's
/// fixed constant (see `sighash_single_bug` and `sighash`'s SINGLE branch)
/// would be a real, verifiable digest, but as a signature TARGET it is not
/// cryptographically sound -- it is a fixed 32 bytes with no
/// transaction-specific input at all, so a signature over it is valid for
/// EVERY transaction that ever triggers the bug, not just this one.
pub const SigningError = error{SighashSingleBugNoCorrespondingOutput} || LegacyError;

/// Wave-2 audit finding `bitcointx` S1: `sighash` is correct for a
/// VERIFIER, which must reproduce Bitcoin Core's exact behavior byte for
/// byte -- returning `sighash_single_bug` on the SIGHASH_SINGLE bug is
/// consensus, not a choice, and `sighash` keeps doing exactly that; nothing
/// about it changes here. A SIGNER has no such obligation and every reason
/// not to proceed: this function is the same algorithm, with the one
/// difference that hitting the bug condition is a typed error instead of a
/// value that looks like an ordinary digest. Purely additive -- `sighash`
/// and every existing caller of it (a verifier, in this module's own
/// consumers) are untouched.
pub fn sighashForSigning(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    script_code: []const u8,
    hash_type: u32,
) SigningError![32]u8 {
    if (input_index < transaction.vin.len) {
        const base = hashtype.baseType(hash_type);
        if (base == SINGLE and input_index >= transaction.vout.len) {
            return error.SighashSingleBugNoCorrespondingOutput;
        }
    }
    // Anything else -- including `input_index >= transaction.vin.len`,
    // deliberately not re-checked above -- is identical to `sighash`, so
    // delegate rather than duplicate the serialization.
    return sighash(allocator, transaction, input_index, script_code, hash_type);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const testutil = @import("testutil.zig");

// DIAGNOSTIC FIXED 2026-09-10 (found chasing S1, not itself a wave-2 audit
// finding): the old `oneInOneOutTx` returned a `Transaction` whose
// `vin`/`vout` slices pointed at `&[_]T{...}` array literals -- temporaries
// scoped to THIS function's own stack frame, not to the caller's. The
// moment `oneInOneOutTx` returned, that frame was free to be reused by the
// next call, and any caller holding onto `t` held a dangling pointer. Every
// EXISTING caller happened to survive it: the sole prior use
// (`input_index out of range is a typed error`, below) hits
// `sighash`'s bounds check and returns `error.InputIndexOutOfRange` before
// ever touching `transaction.vin`/`vout`, so the dangling read never
// actually happened. The first test to run `sighash` to completion twice
// against the same `t` (added for S1, further down) reliably reused enough
// stack to corrupt it: `sighash`'s first call printed a correct-looking
// digest, its second call General-Protection-faulted inside
// `buf.appendSlice(..., vout.script_pubkey)` reading a `vout` that no
// longer pointed at anything live. Fixed by having the CALLER own the
// backing arrays (its stack frame persists for the whole test, unlike a
// helper's) and `oneInOneOutTx` fill them in rather than manufacture and
// return pointers into its own frame.
fn oneInOneOutTx(vin_buf: *[1]tx.TxIn, vout_buf: *[1]tx.TxOut, prevout_txid: [32]u8, out_value: i64) tx.Transaction {
    vin_buf.* = .{.{
        .prevout = .{ .txid = prevout_txid, .vout = 0 },
        .script_sig = &.{},
        .sequence = 0xffffffff,
    }};
    vout_buf.* = .{.{ .value = out_value, .script_pubkey = &.{} }};
    return .{
        .version = 1,
        .vin = vin_buf,
        .vout = vout_buf,
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
}

test "input_index out of range is a typed error" {
    var vin_buf: [1]tx.TxIn = undefined;
    var vout_buf: [1]tx.TxOut = undefined;
    var t = oneInOneOutTx(&vin_buf, &vout_buf, [_]u8{0} ** 32, 1000);
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

// ── S1: sighashForSigning refuses the SIGHASH_SINGLE bug constant ───────────

test "sighashForSigning: SIGHASH_SINGLE bug is a typed error, not the constant (S1)" {
    // Same 2-in/1-out shape as the SIGHASH_SINGLE bug test above.
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
    try testing.expectError(
        error.SighashSingleBugNoCorrespondingOutput,
        sighashForSigning(testing.allocator, t, 1, &.{}, SINGLE),
    );
    _ = &t;
}

test "sighashForSigning: matches sighash bit-for-bit whenever the bug does not trigger (positive control)" {
    var vin_buf: [1]tx.TxIn = undefined;
    var vout_buf: [1]tx.TxOut = undefined;
    var t = oneInOneOutTx(&vin_buf, &vout_buf, [_]u8{0x11} ** 32, 5000);
    // ALL-like, NONE and an in-range SINGLE all avoid the bug condition --
    // sighashForSigning must be byte-identical to sighash on every one.
    for ([_]u32{ ALL, NONE, SINGLE }) |ht| {
        const verifier = try sighash(testing.allocator, t, 0, &.{}, ht);
        const signer = try sighashForSigning(testing.allocator, t, 0, &.{}, ht);
        try testing.expectEqualSlices(u8, &verifier, &signer);
    }
    _ = &t;
}

test "sighashForSigning: out-of-range input_index still reports InputIndexOutOfRange (positive control)" {
    var vin_buf: [1]tx.TxIn = undefined;
    var vout_buf: [1]tx.TxOut = undefined;
    var t = oneInOneOutTx(&vin_buf, &vout_buf, [_]u8{0} ** 32, 1000);
    try testing.expectError(error.InputIndexOutOfRange, sighashForSigning(testing.allocator, t, 5, &.{}, ALL));
    _ = &t;
}

// ── SerializeScriptCode branches the vendored corpus cannot reach ────────────
//
// Measured over all 500 `sighash.json` data rows: 210 carry a real
// `OP_CODESEPARATOR` opcode, ZERO carry a `0xab` byte that is push *data*, and
// ZERO have a script whose `GetOp` walk fails. So the corpus anchors the
// ordinary removal path and nothing else. The three cases below are pinned
// against Bitcoin Core's source rather than against a vector file, and say so:
// they are read off `CTransactionSignatureSerializer::SerializeScriptCode` and
// `GetScriptOp` (`script/interpreter.cpp`, `script/script.cpp`, v29.0), not
// invented here.

fn serializedScriptCode(allocator: Allocator, script_code: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendScriptCode(&buf, allocator, script_code);
    return buf.toOwnedSlice(allocator);
}

test "SerializeScriptCode: a 0xab byte inside a push payload is DATA, not a separator" {
    // `<push 1 byte: 0xab> OP_1`. A `memchr`-style strip would eat the 0xab and
    // change the signed message; Core's walk keeps it, because `GetOp` consumed
    // it as the push's payload and never reported it as an opcode.
    const script = [_]u8{ 0x01, 0xab, 0x51 };
    const got = try serializedScriptCode(testing.allocator, &script);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x01, 0xab, 0x51 }, got);
}

test "SerializeScriptCode: a bare OP_CODESEPARATOR opcode is removed, length included" {
    // `OP_1 OP_CODESEPARATOR OP_2` -> `OP_1 OP_2`, and the CompactSize prefix
    // drops with it (`scriptCode.size() - nCodeSeparators` = 3 - 1).
    const script = [_]u8{ 0x51, 0xab, 0x52 };
    const got = try serializedScriptCode(testing.allocator, &script);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x51, 0x52 }, got);

    // Two separators, one of them trailing.
    const script2 = [_]u8{ 0xab, 0x51, 0xab };
    const got2 = try serializedScriptCode(testing.allocator, &script2);
    defer testing.allocator.free(got2);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x51 }, got2);
}

test "SerializeScriptCode: an undecodable tail truncates, and the length prefix over-declares" {
    // `OP_PUSHDATA2` with only one of its two length octets present. Core's
    // `GetScriptOp` has already done `*pc++` before the `end - pc < 2` check
    // that fails, so the cursor stops at 1 and `SerializeScriptCode`'s trailing
    // `s.write(Span{&itBegin[0], it - itBegin})` writes exactly that one byte —
    // while the prefix, computed as `scriptCode.size() - nCodeSeparators`,
    // still says 2. This mismatch is Core's, and is reproduced deliberately.
    const script = [_]u8{ 0x4d, 0x00 };
    const got = try serializedScriptCode(testing.allocator, &script);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x4d }, got);
    // Declared 2, wrote 1: the residual, stated as a fact rather than smoothed.
    try testing.expectEqual(@as(u8, 2), got[0]); // the declared length
    try testing.expectEqual(@as(usize, 1), got.len - 1); // the bytes actually written
}

test "SerializeScriptCode: an empty scriptCode is a bare zero length" {
    const got = try serializedScriptCode(testing.allocator, &.{});
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, got);
}

// ── `getOp` push-length boundaries (audit finding V1) ────────────────────────
//
// The four tests below pin `getOp`'s four length checks directly. None of the
// 500 vendored `sighash.json` rows contain a push that reaches exactly one of
// these boundaries (the corpus is real but blind to this axis — see
// `A1/bitcointx.md` V1), so a flipped `<` / `<=` on any of these four lines
// passes the whole suite today. Each expected value below is Core's
// `GetScriptOp`/`SerializeScriptCode` output for the given scriptCode,
// independently cross-checked with a Python transliteration of `getOp` run
// over the same 500-row corpus (0 divergences) — see
// `~/CML/20260901-zig-libs-audit/A1/repro/bitcointx/getop_probe.py`.

test "getOp boundary: OP_PUSHDATA4 (opcode == 0x4e) still takes the push branch" {
    // `<push4 len=1: 0xab> OP_1`. Mutating `opcode <= 0x4e` to `< 0x4e` drops
    // the 0x4e opcode out of the push branch entirely, so the parser
    // misreads the rest of the script and the 0xab payload byte gets
    // stripped as if it were OP_CODESEPARATOR.
    const script = [_]u8{ 0x4e, 0x01, 0x00, 0x00, 0x00, 0xab, 0x51 };
    const got = try serializedScriptCode(testing.allocator, &script);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x07, 0x4e, 0x01, 0x00, 0x00, 0x00, 0xab, 0x51 },
        got,
    );
}

test "getOp boundary: OP_PUSHDATA1 (opcode == 0x4c) reads its explicit length byte" {
    // `OP_PUSHDATA1 len=1: 0xab, OP_1`. Mutating `opcode < 0x4c` to
    // `opcode <= 0x4c` makes 0x4c fall into the direct-length branch
    // (`size = opcode = 0x4c = 76`) instead of reading the explicit length
    // byte that follows it — the walk then fails length-checking against
    // the 3 remaining bytes and truncates after the opcode alone.
    const script = [_]u8{ 0x4c, 0x01, 0xab, 0x51 };
    const got = try serializedScriptCode(testing.allocator, &script);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x04, 0x4c, 0x01, 0xab, 0x51 }, got);
}

test "getOp boundary: a push whose payload exactly fills the remaining script decodes" {
    // `<push 1 byte: 0xab>`, nothing after it. Mutating the payload bounds
    // check from `remaining < size` to `remaining <= size` rejects a push
    // that exactly fills the rest of the script (a legal, common shape),
    // truncating the walk one byte early.
    const script = [_]u8{ 0x01, 0xab };
    const got = try serializedScriptCode(testing.allocator, &script);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x01, 0xab }, got);
}

test "getOp boundary: OP_PUSHDATA2 (opcode == 0x4d) reads both of its length bytes" {
    // `OP_PUSHDATA2 len=0x0000` — the two length bytes exactly fill the
    // remaining script. Mutating `remaining < 2` to `remaining <= 2` rejects
    // this exact-fit case and truncates after the opcode alone.
    const script = [_]u8{ 0x4d, 0x00, 0x00 };
    const got = try serializedScriptCode(testing.allocator, &script);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x4d, 0x00, 0x00 }, got);
}

test "B2: sighash's preimage buffer doesn't reallocate growing many outputs" {
    // `A1/bitcointx.md` finding B2: unlike `bip143.sighash`/`bip341.sighash`,
    // this preimage builder had NO capacity reservation at all despite
    // serializing the whole transaction. Measured before
    // `estimatePreimageCapacity` existed and after, at 1024 outputs.
    const n = 1024;
    const spk = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x42} ** 20 ++ [_]u8{ 0x88, 0xac }; // 25-byte P2PKH

    var vin_buf: [1]tx.TxIn = .{.{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff }};
    var vout_buf: [n]tx.TxOut = undefined;
    for (0..n) |i| vout_buf[i] = .{ .value = 100, .script_pubkey = &spk };
    const t: tx.Transaction = .{
        .version = 1,
        .vin = vin_buf[0..],
        .vout = vout_buf[0..],
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };

    var counting: testutil.CountingAllocator = .{ .backing = testing.allocator };
    _ = try sighash(counting.allocator(), t, 0, &.{}, hashtype.ALL);
    const total_ops = counting.allocs + counting.resizes + counting.remaps;

    // Measured: 12 ops (9 allocs + 3 remaps) before the reservation, 1
    // (a single alloc) after, for 1024 outputs.
    try testing.expect(total_ops <= 3);
}
