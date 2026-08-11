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
const instrument = @import("instrument.zig");
const tx = @import("tx.zig");

pub const ALL = hashtype.ALL;
pub const NONE = hashtype.NONE;
pub const SINGLE = hashtype.SINGLE;
pub const ANYONECANPAY = hashtype.ANYONECANPAY;

pub const Bip143Error = error{
    InputIndexOutOfRange,
    /// F11 (2026-08-11 re-audit): `pre` was computed from a different
    /// `Transaction` than the one passed alongside it — see `Precomputed`'s
    /// doc comment. Refused rather than silently mixing another
    /// transaction's cached commitment hashes into this one's preimage.
    PrecomputedMismatch,
} || Allocator.Error;

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

// ── the three per-transaction commitment hashes ──────────────────────────────
//
// Each of these depends on the TRANSACTION only — never on `input_index`,
// never on `hash_type`. That is precisely why BIP143 defines them: the
// legacy algorithm's per-input reserialization made validation `O(n²)` in
// transaction size on attacker-chosen input, and hoisting these three out of
// the per-input loop is what makes segwit-v0 validation linear. Bitcoin Core
// hoists exactly these into `PrecomputedTransactionData`; `Precomputed`
// below is that seam. Computing them per input has the letter of BIP143 and
// none of its point.
//
// Each is the sole implementation of its byte layout — the cached and the
// uncached selection paths below both route through these, so there is no
// second copy of a consensus-critical serialization to drift.

fn hashPrevouts(allocator: Allocator, transaction: tx.Transaction) Allocator.Error![32]u8 {
    instrument.noteCommitmentHash();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.ensureTotalCapacity(allocator, transaction.vin.len * 36);
    for (transaction.vin) |vin| {
        try buf.appendSlice(allocator, &vin.prevout.txid);
        try appendU32LE(&buf, allocator, vin.prevout.vout);
    }
    return hash256.sha256d(buf.items);
}

fn hashSequence(allocator: Allocator, transaction: tx.Transaction) Allocator.Error![32]u8 {
    instrument.noteCommitmentHash();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.ensureTotalCapacity(allocator, transaction.vin.len * 4);
    for (transaction.vin) |vin| try appendU32LE(&buf, allocator, vin.sequence);
    return hash256.sha256d(buf.items);
}

fn hashOutputs(allocator: Allocator, transaction: tx.Transaction) Allocator.Error![32]u8 {
    instrument.noteCommitmentHash();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    for (transaction.vout) |vout| {
        try appendI64LE(&buf, allocator, vout.value);
        try appendCompactSize(&buf, allocator, vout.script_pubkey.len);
        try buf.appendSlice(allocator, vout.script_pubkey);
    }
    return hash256.sha256d(buf.items);
}

/// SIGHASH_SINGLE's `hashOutputs`: the ONE output matching this input.
/// Per-input by construction (Core computes it per input too), hence not
/// part of `Precomputed` and not counted by `instrument`.
fn hashSingleOutput(allocator: Allocator, vout: tx.TxOut) Allocator.Error![32]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendI64LE(&buf, allocator, vout.value);
    try appendCompactSize(&buf, allocator, vout.script_pubkey.len);
    try buf.appendSlice(allocator, vout.script_pubkey);
    return hash256.sha256d(buf.items);
}

/// The per-transaction half of Bitcoin Core's `PrecomputedTransactionData`
/// (`hashPrevouts`/`hashSequence`/`hashOutputs`): compute once per
/// transaction, reuse for every input and every `CHECKSIG`.
///
/// These are the UNCONDITIONAL hashes. Which of them a given signature
/// actually commits to depends on `hash_type` — that selection (including
/// BIP143's zero-substitutions) stays in `midstatesFrom`, so a cached
/// caller and an uncached one make the same choice from one piece of code.
pub const Precomputed = struct {
    hash_prevouts: [32]u8,
    hash_sequence: [32]u8,
    hash_outputs: [32]u8,
    /// F11 (2026-08-11 re-audit): a cheap **identity fingerprint** of the
    /// `Transaction` these hashes were computed from — `precompute`'s
    /// `transaction.vin`/`.vout` slice pointers and lengths, not a hash of
    /// their contents. `selectMidstates` compares it against the
    /// `transaction` argument passed in alongside `pre` (`midstatesFrom`/
    /// `preimageWith`/`sighashWith`) and refuses with
    /// `error.PrecomputedMismatch` on a mismatch, rather than silently
    /// mixing one transaction's cached commitment hashes into another's
    /// preimage. Deliberately O(1): re-hashing the transaction to check
    /// would reintroduce the exact per-call `O(n)` cost this cache exists to
    /// eliminate, so this catches "wrong `Transaction` value entirely" (a
    /// hoisted `pre` reused across transactions, e.g. from a pool) rather
    /// than "a different transaction that happens to occupy identical
    /// backing storage" — the class the fuzz harness could actually produce
    /// once it stopped only ever pairing `pre` with the tx it was built
    /// from. Bitcoin Core's own `PrecomputedTransactionData` carries no
    /// such check at all (correspondence is the caller's responsibility);
    /// this is deliberately stricter than parity, not a correctness
    /// requirement BIP143 itself imposes.
    ///
    /// ⚠ F12 (2026-08-11 re-audit) — the precondition this fingerprint does
    /// NOT relieve the caller of: **`pre` is invalidated by any mutation of
    /// the transaction or its spent outputs; the fingerprint detects
    /// substitution only.** Mutating `transaction.vout[0].value` in place
    /// leaves every pointer and length identical, so `matches` still says
    /// yes and `sighashWith` returns the digest of the transaction as it was
    /// at `precompute` time — no error. That is the same property Core's
    /// `PrecomputedTransactionData` has (parity, not divergence), and it is
    /// asserted rather than hidden by the F12 test in `precomputed.zig`.
    vin_ptr: [*]const tx.TxIn,
    vin_len: usize,
    vout_ptr: [*]const tx.TxOut,
    vout_len: usize,

    fn matches(self: Precomputed, transaction: tx.Transaction) bool {
        return self.vin_ptr == transaction.vin.ptr and self.vin_len == transaction.vin.len and
            self.vout_ptr == transaction.vout.ptr and self.vout_len == transaction.vout.len;
    }
};

/// Compute the per-transaction commitment hashes once. Cost is `O(n)` in
/// transaction size, paid once rather than once per input.
pub fn precompute(allocator: Allocator, transaction: tx.Transaction) Allocator.Error!Precomputed {
    return .{
        .hash_prevouts = try hashPrevouts(allocator, transaction),
        .hash_sequence = try hashSequence(allocator, transaction),
        .hash_outputs = try hashOutputs(allocator, transaction),
        .vin_ptr = transaction.vin.ptr,
        .vin_len = transaction.vin.len,
        .vout_ptr = transaction.vout.ptr,
        .vout_len = transaction.vout.len,
    };
}

/// BIP143's `hash_type`-dependent selection over the three commitment
/// hashes. `pre != null` takes them from the cache; `pre == null` computes
/// exactly the ones this `hash_type` needs, lazily. Both routes share this
/// one body, so the gates below exist once.
fn selectMidstates(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u32,
    pre: ?Precomputed,
) Bip143Error!Midstates {
    if (pre) |p| if (!p.matches(transaction)) return error.PrecomputedMismatch;
    if (input_index >= transaction.vin.len) return error.InputIndexOutOfRange;
    const base = hashtype.baseType(hash_type);
    const anyone_can_pay = hashtype.isAnyoneCanPay(hash_type);

    var hash_prevouts: [32]u8 = [_]u8{0} ** 32;
    var hash_sequence: [32]u8 = [_]u8{0} ** 32;
    if (!anyone_can_pay) {
        hash_prevouts = if (pre) |p| p.hash_prevouts else try hashPrevouts(allocator, transaction);

        // hashSequence is only meaningful for ALL-like (not NONE/SINGLE).
        if (base != NONE and base != SINGLE) {
            hash_sequence = if (pre) |p| p.hash_sequence else try hashSequence(allocator, transaction);
        }
    }

    var hash_outputs: [32]u8 = [_]u8{0} ** 32;
    if (base != NONE and base != SINGLE) {
        hash_outputs = if (pre) |p| p.hash_outputs else try hashOutputs(allocator, transaction);
    } else if (base == SINGLE and input_index < transaction.vout.len) {
        hash_outputs = try hashSingleOutput(allocator, transaction.vout[input_index]);
    }
    // else (SINGLE with input_index >= vout.len): stays all-zero, per BIP143.

    return .{ .hash_prevouts = hash_prevouts, .hash_sequence = hash_sequence, .hash_outputs = hash_outputs };
}

/// The three reusable per-transaction midstates (BIP143 "Specification").
/// Each is `sha256d` of zero or more fixed-width fields; a field set is
/// replaced by 32 zero bytes exactly when BIP143 says to omit it (see
/// inline comments) rather than hashing an empty input.
///
/// Recomputes the commitment hashes on every call. Validating a whole
/// transaction should use `precompute` + `midstatesFrom` instead — see
/// `Precomputed`.
pub fn midstates(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u32,
) Bip143Error!Midstates {
    return selectMidstates(allocator, transaction, input_index, hash_type, null);
}

/// `midstates` against an already-computed `Precomputed`. Byte-identical
/// output; the only difference is that the per-transaction hashes are not
/// recomputed.
pub fn midstatesFrom(
    allocator: Allocator,
    pre: Precomputed,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u32,
) Bip143Error!Midstates {
    return selectMidstates(allocator, transaction, input_index, hash_type, pre);
}

fn buildPreimage(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    script_code: []const u8,
    amount_sats: i64,
    hash_type: u32,
    pre: ?Precomputed,
) Bip143Error![]u8 {
    const mid = try selectMidstates(allocator, transaction, input_index, hash_type, pre);
    const vin = transaction.vin[input_index];

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    // The preimage's size is known exactly: 156 fixed bytes plus the
    // length-prefixed scriptCode. One allocation, no growth reallocs.
    try buf.ensureTotalCapacityPrecise(allocator, 156 + tx.compactSizeLen(script_code.len) + script_code.len);
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

/// The full BIP143 preimage (caller owns the returned slice). `amount_sats`
/// is the value of the output this input spends (the amount BIP143
/// commits to that legacy sighash never did).
///
/// Recomputes the per-transaction commitment hashes; see `preimageWith`.
pub fn preimage(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    script_code: []const u8,
    amount_sats: i64,
    hash_type: u32,
) Bip143Error![]u8 {
    return buildPreimage(allocator, transaction, input_index, script_code, amount_sats, hash_type, null);
}

/// `preimage` against an already-computed `Precomputed`. Byte-identical.
pub fn preimageWith(
    allocator: Allocator,
    pre: Precomputed,
    transaction: tx.Transaction,
    input_index: usize,
    script_code: []const u8,
    amount_sats: i64,
    hash_type: u32,
) Bip143Error![]u8 {
    return buildPreimage(allocator, transaction, input_index, script_code, amount_sats, hash_type, pre);
}

/// Recomputes the per-transaction commitment hashes on every call, so a
/// caller looping over inputs (or over the `CHECKSIG`s of one input) pays
/// `O(n)` per call and `O(n²)` overall. Use `sighashWith` for that; this
/// entry point remains for one-off signing of a single input.
pub fn sighash(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    script_code: []const u8,
    amount_sats: i64,
    hash_type: u32,
) Bip143Error![32]u8 {
    const img = try preimage(allocator, transaction, input_index, script_code, amount_sats, hash_type);
    defer allocator.free(img);
    return hash256.sha256d(img);
}

/// `sighash` against an already-computed `Precomputed` — byte-identical
/// output, `O(1)` commitment hashes per call. This is the entry point a
/// transaction validator wants: `precompute` once, then call this for every
/// input and every `CHECKSIG`.
pub fn sighashWith(
    allocator: Allocator,
    pre: Precomputed,
    transaction: tx.Transaction,
    input_index: usize,
    script_code: []const u8,
    amount_sats: i64,
    hash_type: u32,
) Bip143Error![32]u8 {
    const img = try preimageWith(allocator, pre, transaction, input_index, script_code, amount_sats, hash_type);
    defer allocator.free(img);
    return hash256.sha256d(img);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

// `bip143_kat_vectors.zig` covers SIGHASH_SINGLE/NONE/ANYONECANPAY
// byte-exactly (BIP143's "Native P2WSH" and "P2SH-P2WSH" examples), so the
// hash_type-dependent gates above are externally anchored. The tests below
// remain as the structural statement of the same rules on hand-built
// transactions. In particular, BIP143 deliberately PRESERVES the
// historical "SIGHASH_SINGLE bug" (a SINGLE hash_type with no corresponding
// output leaves `hashOutputs` all-zero rather than erroring, unlike
// BIP341's `MissingCorrespondingOutput`) — see this file's `midstates` doc
// comment / line comment. That branch had no test at all before the two
// below.

test "SIGHASH_SINGLE with a corresponding output hashes exactly that output (not all outputs)" {
    var t: tx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{
            .{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
            .{ .prevout = .{ .txid = [_]u8{1} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
        }),
        .vout = @constCast(&[_]tx.TxOut{
            .{ .value = 111, .script_pubkey = &[_]u8{0xAA} },
            .{ .value = 222, .script_pubkey = &[_]u8{0xBB} },
        }),
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const mid = try midstates(testing.allocator, t, 1, SINGLE);

    // Hand-built (not via this file's own append* helpers) preimage of
    // JUST vout[1]: value(8, LE) . compactsize(len) . script.
    var expected_preimage: [8 + 1 + 1]u8 = undefined;
    std.mem.writeInt(i64, expected_preimage[0..8], 222, .little);
    expected_preimage[8] = 1; // compactsize(1)
    expected_preimage[9] = 0xBB;
    const want = hash256.sha256d(&expected_preimage);
    try testing.expectEqualSlices(u8, &want, &mid.hash_outputs);

    // And it must NOT be the all-outputs hash (which would be the ALL-type
    // bug: hashing every vout instead of only the matching one).
    const all_outputs_hash = (try midstates(testing.allocator, t, 1, ALL)).hash_outputs;
    try testing.expect(!std.mem.eql(u8, &all_outputs_hash, &mid.hash_outputs));
    _ = &t;
}

test "SIGHASH_SINGLE with NO corresponding output preserves the historical bug: hashOutputs stays all-zero" {
    // 2 inputs, only 1 output: input_index=1 has no matching vout.
    var t: tx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{
            .{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
            .{ .prevout = .{ .txid = [_]u8{1} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
        }),
        .vout = @constCast(&[_]tx.TxOut{.{ .value = 100, .script_pubkey = &.{} }}),
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const mid = try midstates(testing.allocator, t, 1, SINGLE);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &mid.hash_outputs);
    _ = &t;
}

test "ANYONECANPAY leaves hashPrevouts/hashSequence all-zero (not derived from vin at all)" {
    var t: tx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{.{ .prevout = .{ .txid = [_]u8{7} ** 32, .vout = 3 }, .script_sig = &.{}, .sequence = 99 }}),
        .vout = @constCast(&[_]tx.TxOut{.{ .value = 5, .script_pubkey = &.{} }}),
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const mid = try midstates(testing.allocator, t, 0, ALL | ANYONECANPAY);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &mid.hash_prevouts);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &mid.hash_sequence);
    _ = &t;
}

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
