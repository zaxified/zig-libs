// SPDX-License-Identifier: MIT
//! BIP341 taproot **key-path** signature hashing — the `SigMsg`/sighash
//! computation behind every taproot key-path spend (BIP341 "Common
//! Signature Message" + "Default Sighash").
//!
//! Two structural differences from the legacy/BIP143 algorithms:
//!
//! - The commitment hashes (`sha_prevouts`/`sha_amounts`/
//!   `sha_scriptpubkeys`/`sha_sequences`/`sha_outputs`/`sha_single_output`)
//!   are a single SHA-256, NOT `sha256d` (`hash256.sha256`, not
//!   `hash256.sha256d`) — see `hash256.zig`'s doc comment for why.
//! - Because taproot has no separate "scriptCode", the sighash needs the
//!   `scriptPubKey` AND `value` of every input's spent output (not just
//!   the one being signed) to compute `sha_amounts`/`sha_scriptpubkeys` —
//!   the caller supplies these as `spent_outputs`, one per `vin` entry, in
//!   the same order (there is no UTXO set inside this module).
//!
//! The final sighash is `bip340.taggedHash("TapSighash", 0x00 || SigMsg)`
//! — the leading `0x00` is BIP341's fixed "sighash epoch" byte. `sigMsg`
//! below returns `0x00 || SigMsg` (epoch included), matching the official
//! `bip-0341/wallet-test-vectors.json` `sigMsg` field byte-for-byte — that
//! field's name is a bit of a false friend: despite being called `sigMsg`,
//! its own first byte IS the epoch (confirmed by decoding it field-by-field
//! against the vector's own `given`/`intermediary` values), i.e. it holds
//! what BIP341's prose calls "Message" (`0x00 || SigMsg`), not `SigMsg`
//! alone. This module follows the vector's actual content rather than the
//! prose's field-naming, so `sighash` below is simply
//! `bip340.taggedHash("TapSighash", sigMsg(...))` with no separate
//! epoch-prepending step.
//!
//! ## Scope: key-path only — annex and BIP342 tapscript deferred
//!
//! `ext_flag` (part of `spend_type`) is always `0` (key-path spending) and
//! an annex is never signaled (`spend_type` is always `0x00`). BIP341's
//! script-path fields (`ext_flag = 1`, the leaf hash / `key_version` /
//! `code_separator_position` a BIP342 tapscript signature additionally
//! commits to) and annex support (`sha_annex`, needing the witness stack's
//! last-item-starts-with-`0x50` detection rule) are real, self-contained
//! extensions with their own committed fields — not a partial/half-built
//! version of this function — and are out of scope for this pass: no
//! published, official key-path-spending test vector exercises an annex
//! (`bip341_kat_vectors.zig`'s source JSON has none), and tapscript
//! (BIP342) is a distinct signature-hashing mode this module does not
//! implement at all.

const std = @import("std");
const Allocator = std.mem.Allocator;
const hash256 = @import("hash256.zig");
const bip340 = @import("bip340");
const instrument = @import("instrument.zig");
const tx = @import("tx.zig");

pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

pub const Bip341Error = error{
    InputIndexOutOfRange,
    /// `hash_type`'s base type is SINGLE but `input_index` has no
    /// corresponding output. Unlike the legacy algorithm's historical
    /// "SIGHASH_SINGLE bug" fallback, BIP341 makes this combination
    /// outright invalid (BIP341 "Signature validation" step 2).
    MissingCorrespondingOutput,
    /// `spent_outputs.len` must equal `transaction.vin.len` (one prevout
    /// per input — see module doc comment).
    PrevoutsCountMismatch,
    /// Not one of the 7 values BIP341 defines
    /// (`{0x00,0x01,0x02,0x03,0x81,0x82,0x83}`).
    InvalidHashType,
} || Allocator.Error;

pub fn validateHashType(hash_type: u8) Bip341Error!void {
    switch (hash_type) {
        0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 => {},
        else => return error.InvalidHashType,
    }
}

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

/// `sha_single_output` — SIGHASH_SINGLE's commitment to the ONE output
/// matching this input. Per-input by construction (Core computes it per
/// input too), hence not part of `Precomputed` and not counted by
/// `instrument`.
fn shaOutput(allocator: Allocator, vout: tx.TxOut) Allocator.Error![32]u8 {
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(allocator);
    try appendI64LE(&tmp, allocator, vout.value);
    try appendCompactSize(&tmp, allocator, vout.script_pubkey.len);
    try tmp.appendSlice(allocator, vout.script_pubkey);
    return hash256.sha256(tmp.items);
}

// ── the five per-transaction commitment hashes ───────────────────────────────
//
// Each depends on the TRANSACTION (plus, for two of them, the spent-output
// set) only — never on `input_index`, never on `hash_type`. Bitcoin Core
// hoists all five into `PrecomputedTransactionData`
// (`m_prevouts_single_hash`, `m_spent_amounts_single_hash`,
// `m_spent_scripts_single_hash`, `m_sequences_single_hash`,
// `m_outputs_single_hash`); `Precomputed` below is that seam. Rebuilding
// them per input makes taproot validation `O(n²)` in transaction size on
// input an attacker chooses.
//
// Each is the sole implementation of its byte layout: the cached and the
// uncached routes through `buildCommonSigMsg` both call these.

fn shaPrevouts(allocator: Allocator, transaction: tx.Transaction) Allocator.Error![32]u8 {
    instrument.noteCommitmentHash();
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(allocator);
    try tmp.ensureTotalCapacity(allocator, transaction.vin.len * 36);
    for (transaction.vin) |vin| {
        try tmp.appendSlice(allocator, &vin.prevout.txid);
        try appendU32LE(&tmp, allocator, vin.prevout.vout);
    }
    return hash256.sha256(tmp.items);
}

fn shaAmounts(allocator: Allocator, spent_outputs: []const tx.TxOut) Allocator.Error![32]u8 {
    instrument.noteCommitmentHash();
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(allocator);
    try tmp.ensureTotalCapacity(allocator, spent_outputs.len * 8);
    for (spent_outputs) |o| try appendI64LE(&tmp, allocator, o.value);
    return hash256.sha256(tmp.items);
}

fn shaScriptPubkeys(allocator: Allocator, spent_outputs: []const tx.TxOut) Allocator.Error![32]u8 {
    instrument.noteCommitmentHash();
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(allocator);
    for (spent_outputs) |o| {
        try appendCompactSize(&tmp, allocator, o.script_pubkey.len);
        try tmp.appendSlice(allocator, o.script_pubkey);
    }
    return hash256.sha256(tmp.items);
}

fn shaSequences(allocator: Allocator, transaction: tx.Transaction) Allocator.Error![32]u8 {
    instrument.noteCommitmentHash();
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(allocator);
    try tmp.ensureTotalCapacity(allocator, transaction.vin.len * 4);
    for (transaction.vin) |vin| try appendU32LE(&tmp, allocator, vin.sequence);
    return hash256.sha256(tmp.items);
}

fn shaOutputs(allocator: Allocator, transaction: tx.Transaction) Allocator.Error![32]u8 {
    instrument.noteCommitmentHash();
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(allocator);
    for (transaction.vout) |vout| {
        try appendI64LE(&tmp, allocator, vout.value);
        try appendCompactSize(&tmp, allocator, vout.script_pubkey.len);
        try tmp.appendSlice(allocator, vout.script_pubkey);
    }
    return hash256.sha256(tmp.items);
}

/// The taproot half of Bitcoin Core's `PrecomputedTransactionData`: the five
/// per-transaction BIP341 commitment hashes, computed once and reused for
/// every input and every tapscript `CHECKSIG`.
///
/// All five are computed unconditionally (as Core does in
/// `PrecomputedTransactionData::Init`); which of them a given `hash_type`
/// actually commits to is decided in `buildCommonSigMsg`, so a cached
/// caller and an uncached one make the same choice from one piece of code.
pub const Precomputed = struct {
    sha_prevouts: [32]u8,
    sha_amounts: [32]u8,
    sha_scriptpubkeys: [32]u8,
    sha_sequences: [32]u8,
    sha_outputs: [32]u8,
};

/// Compute the five per-transaction commitment hashes once. `spent_outputs`
/// is the previous output every `vin[i]` spends, in `vin` order (BIP341
/// commits to all of them, not just the input being signed).
pub fn precompute(
    allocator: Allocator,
    transaction: tx.Transaction,
    spent_outputs: []const tx.TxOut,
) Bip341Error!Precomputed {
    if (spent_outputs.len != transaction.vin.len) return error.PrevoutsCountMismatch;
    return .{
        .sha_prevouts = try shaPrevouts(allocator, transaction),
        .sha_amounts = try shaAmounts(allocator, spent_outputs),
        .sha_scriptpubkeys = try shaScriptPubkeys(allocator, spent_outputs),
        .sha_sequences = try shaSequences(allocator, transaction),
        .sha_outputs = try shaOutputs(allocator, transaction),
    };
}

/// `0x00 || SigMsg(hash_type, ext_flag=0)` (key-path spending; the leading
/// byte is BIP341's fixed sighash epoch — see module doc comment for why
/// it's included here). Caller owns the returned slice.
/// What varies between a key-path and a script-path signature message.
///
/// BIP341's SigMsg is one layout with two tails: everything from the epoch
/// byte through the SINGLE output commitment is common, and only `spend_type`,
/// the optional annex commitment, and (for script paths) a BIP342 extension
/// differ. `commonSigMsg` below emits the common part so callers do not
/// reimplement it — a second copy of a consensus-critical byte layout is a
/// place for the two to drift apart silently.
pub const CommonOptions = struct {
    /// `2*ext_flag + annex_present`. 0 for a key-path spend, 2 for a tapscript
    /// spend without an annex, 3 with one.
    spend_type: u8 = 0,
    /// `SHA256(compact_size(annex) || annex)`, emitted right after this
    /// input's data when present. Must be set exactly when `spend_type` has
    /// bit 0, which the caller is responsible for.
    annex_hash: ?[32]u8 = null,
};

/// The BIP341 SigMsg through the SINGLE-output commitment — everything a
/// script-path message shares with a key-path one. A tapscript caller appends
/// its own `ext_flag = 1` fields (tapleaf_hash || key_version || codesep_pos)
/// to the result.
fn buildCommonSigMsg(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u8,
    spent_outputs: []const tx.TxOut,
    opts: CommonOptions,
    pre: ?Precomputed,
) Bip341Error![]u8 {
    try validateHashType(hash_type);
    if (input_index >= transaction.vin.len) return error.InputIndexOutOfRange;
    if (spent_outputs.len != transaction.vin.len) return error.PrevoutsCountMismatch;

    const anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    const base = hash_type & 0x03;

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.append(allocator, 0x00); // sighash epoch (BIP341)
    try buf.append(allocator, hash_type);
    try appendI32LE(&buf, allocator, transaction.version);
    try appendU32LE(&buf, allocator, transaction.locktime);

    if (!anyone_can_pay) {
        try buf.appendSlice(allocator, &(if (pre) |p| p.sha_prevouts else try shaPrevouts(allocator, transaction)));
        try buf.appendSlice(allocator, &(if (pre) |p| p.sha_amounts else try shaAmounts(allocator, spent_outputs)));
        try buf.appendSlice(allocator, &(if (pre) |p| p.sha_scriptpubkeys else try shaScriptPubkeys(allocator, spent_outputs)));
        try buf.appendSlice(allocator, &(if (pre) |p| p.sha_sequences else try shaSequences(allocator, transaction)));
    }

    if (base == SIGHASH_DEFAULT or base == SIGHASH_ALL) {
        try buf.appendSlice(allocator, &(if (pre) |p| p.sha_outputs else try shaOutputs(allocator, transaction)));
    }

    try buf.append(allocator, opts.spend_type);

    if (anyone_can_pay) {
        const o = spent_outputs[input_index];
        const vin = transaction.vin[input_index];
        try buf.appendSlice(allocator, &vin.prevout.txid);
        try appendU32LE(&buf, allocator, vin.prevout.vout);
        try appendI64LE(&buf, allocator, o.value);
        try appendCompactSize(&buf, allocator, o.script_pubkey.len);
        try buf.appendSlice(allocator, o.script_pubkey);
        try appendU32LE(&buf, allocator, vin.sequence);
    } else {
        try appendU32LE(&buf, allocator, @intCast(input_index));
    }

    // annex: deferred, never signaled/emitted (module doc comment).

    if (opts.annex_hash) |h| try buf.appendSlice(allocator, &h);

    if (base == SIGHASH_SINGLE) {
        if (input_index >= transaction.vout.len) return error.MissingCorrespondingOutput;
        try buf.appendSlice(allocator, &try shaOutput(allocator, transaction.vout[input_index]));
    }

    return buf.toOwnedSlice(allocator);
}

/// Rebuilds the five per-transaction commitment hashes on every call. A
/// caller validating a whole transaction should use `commonSigMsgWith`.
pub fn commonSigMsg(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u8,
    spent_outputs: []const tx.TxOut,
    opts: CommonOptions,
) Bip341Error![]u8 {
    return buildCommonSigMsg(allocator, transaction, input_index, hash_type, spent_outputs, opts, null);
}

/// `commonSigMsg` against an already-computed `Precomputed`. Byte-identical
/// output; `O(1)` commitment hashes per call instead of `O(n)`.
pub fn commonSigMsgWith(
    allocator: Allocator,
    pre: Precomputed,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u8,
    spent_outputs: []const tx.TxOut,
    opts: CommonOptions,
) Bip341Error![]u8 {
    return buildCommonSigMsg(allocator, transaction, input_index, hash_type, spent_outputs, opts, pre);
}

/// The key-path SigMsg: `commonSigMsg` with `spend_type = 0` and no annex.
pub fn sigMsg(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u8,
    spent_outputs: []const tx.TxOut,
) Bip341Error![]u8 {
    return commonSigMsg(allocator, transaction, input_index, hash_type, spent_outputs, .{});
}

/// `sigMsg` against an already-computed `Precomputed`. Byte-identical.
pub fn sigMsgWith(
    allocator: Allocator,
    pre: Precomputed,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u8,
    spent_outputs: []const tx.TxOut,
) Bip341Error![]u8 {
    return commonSigMsgWith(allocator, pre, transaction, input_index, hash_type, spent_outputs, .{});
}

/// `bip340.taggedHash("TapSighash", sigMsg(...))` — `sigMsg` already
/// includes the leading epoch byte (see its doc comment).
///
/// Rebuilds the per-transaction commitment hashes; see `sighashWith`.
pub fn sighash(
    allocator: Allocator,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u8,
    spent_outputs: []const tx.TxOut,
) Bip341Error![32]u8 {
    const msg = try sigMsg(allocator, transaction, input_index, hash_type, spent_outputs);
    defer allocator.free(msg);
    return bip340.taggedHash("TapSighash", msg);
}

/// `sighash` against an already-computed `Precomputed` — byte-identical
/// output, `O(1)` commitment hashes per call. The entry point a transaction
/// validator wants.
pub fn sighashWith(
    allocator: Allocator,
    pre: Precomputed,
    transaction: tx.Transaction,
    input_index: usize,
    hash_type: u8,
    spent_outputs: []const tx.TxOut,
) Bip341Error![32]u8 {
    const msg = try sigMsgWith(allocator, pre, transaction, input_index, hash_type, spent_outputs);
    defer allocator.free(msg);
    return bip340.taggedHash("TapSighash", msg);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "validateHashType accepts exactly the 7 BIP341 values, rejects everything else" {
    const valid = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 };
    for (valid) |h| try validateHashType(h);
    const invalid = [_]u8{ 0x04, 0x05, 0x80, 0x84, 0xff, 0x7f };
    for (invalid) |h| try testing.expectError(error.InvalidHashType, validateHashType(h));
}

test "input_index out of range and prevouts-count mismatch are typed errors" {
    var t: tx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{.{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 }}),
        .vout = @constCast(&[_]tx.TxOut{.{ .value = 100, .script_pubkey = &.{} }}),
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const prevouts = [_]tx.TxOut{.{ .value = 100, .script_pubkey = &.{} }};
    try testing.expectError(error.InputIndexOutOfRange, sigMsg(testing.allocator, t, 5, SIGHASH_DEFAULT, &prevouts));
    try testing.expectError(error.PrevoutsCountMismatch, sigMsg(testing.allocator, t, 0, SIGHASH_DEFAULT, &.{}));
    _ = &t;
}

test "SIGHASH_SINGLE with no corresponding output is rejected outright (no legacy-style bug fallback)" {
    var t: tx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{
            .{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
            .{ .prevout = .{ .txid = [_]u8{1} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 },
        }),
        .vout = @constCast(&[_]tx.TxOut{.{ .value = 100, .script_pubkey = &.{} }}), // only 1 output, 2 inputs
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const prevouts = [_]tx.TxOut{ .{ .value = 100, .script_pubkey = &.{} }, .{ .value = 200, .script_pubkey = &.{} } };
    try testing.expectError(error.MissingCorrespondingOutput, sigMsg(testing.allocator, t, 1, SIGHASH_SINGLE, &prevouts));
    _ = &t;
}
