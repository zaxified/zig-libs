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
//! ## Scope: the common SigMsg, including the annex — BIP342 tapscript itself deferred
//!
//! `commonSigMsg`/`commonSigMsgWith` build BIP341's SigMsg through the
//! SINGLE-output commitment for BOTH key-path (`spend_type` even, `ext_flag
//! = 0`) and script-path (`ext_flag = 1`) callers — including the annex
//! commitment (`sha_annex`, `CommonOptions.annex_hash`), which is emitted
//! whenever the caller sets it, regardless of path. `sigMsg`/`sighash` below
//! are the key-path convenience wrapper (`spend_type = 0`, no annex).
//! `bitcoinscript` calls `commonSigMsg{,With}` directly for BIP342 tapscript
//! spends, including ones that carry an annex, and appends its own
//! `ext_flag = 1` fields (tapleaf hash / `key_version` /
//! `code_separator_position`) on top.
//!
//! What this module does NOT implement: BIP342 tapscript's own
//! signature-hashing mode (the tapleaf-hash machinery and the fields above)
//! — that is a distinct, self-contained extension built one layer up, in
//! `bitcoinscript`, not a partial/half-built version of this function.
//!
//! ⚠ Coverage gap, not a scope cut: no published, official key-path test
//! vector exercises an annex (`bip341_kat_vectors.zig`'s source JSON has
//! none), and this module's own tests never set `annex_hash`, so the annex
//! wire layout below is reviewed rather than vector-anchored *here* —
//! `bitcoinscript`'s `sighash_annex` case anchors it one level up. What IS
//! checked in this module is `CommonOptions`'s internal consistency
//! (`spend_type`'s annex bit vs. `annex_hash != null`,
//! `error.SpendTypeAnnexMismatch`).

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
    /// F11 (2026-08-11 re-audit): `pre` was computed from a different
    /// `Transaction` than the one passed alongside it — see `Precomputed`'s
    /// doc comment. Refused rather than silently mixing another
    /// transaction's cached commitment hashes into this one's sig message.
    PrecomputedMismatch,
    /// `opts.spend_type` bit 0 (the annex-present bit) and
    /// `opts.annex_hash != null` disagree. `CommonOptions.annex_hash`'s doc
    /// comment says the caller is responsible for keeping the two in sync;
    /// this makes that a checked contract instead of a silent one — see
    /// finding X1, `A1/bitcointx.md`.
    SpendTypeAnnexMismatch,
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
    // B2: `script_pubkey` is variable-length, so (unlike `shaPrevouts`/
    // `shaAmounts`/`shaSequences` above) the total isn't a fixed per-item
    // constant -- sum it first so the append loop never reallocates.
    var total: usize = 0;
    for (spent_outputs) |o| total += tx.compactSizeLen(o.script_pubkey.len) + o.script_pubkey.len;
    try tmp.ensureTotalCapacityPrecise(allocator, total);
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
    // B2: same reasoning as `shaScriptPubkeys` above -- sum the variable
    // `script_pubkey` lengths first so the append loop never reallocates.
    var total: usize = 0;
    for (transaction.vout) |vout| total += 8 + tx.compactSizeLen(vout.script_pubkey.len) + vout.script_pubkey.len;
    try tmp.ensureTotalCapacityPrecise(allocator, total);
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
    /// F11 (2026-08-11 re-audit): a cheap **identity fingerprint** of the
    /// `Transaction` (and `spent_outputs`) these hashes were computed from —
    /// slice pointers and lengths, not a content hash. See
    /// `bip143.Precomputed`'s doc comment for why this is O(1) by design
    /// rather than a re-hash, and what class of mismatch it catches.
    ///
    /// ⚠ F12 (2026-08-11 re-audit): **`pre` is invalidated by any mutation
    /// of the transaction or its spent outputs; the fingerprint detects
    /// substitution only.** BIP341 commits to every input's spent amount and
    /// scriptPubKey, so mutating `spent_outputs[i].value` in place is as
    /// invalidating as mutating the transaction — and equally invisible
    /// here, since the slice pointer and length are unchanged. Rebuild after
    /// every change (parity with Core; see `precomputed.zig`).
    vin_ptr: [*]const tx.TxIn,
    vin_len: usize,
    vout_ptr: [*]const tx.TxOut,
    vout_len: usize,
    spent_outputs_ptr: [*]const tx.TxOut,
    spent_outputs_len: usize,

    fn matches(self: Precomputed, transaction: tx.Transaction, spent_outputs: []const tx.TxOut) bool {
        return self.vin_ptr == transaction.vin.ptr and self.vin_len == transaction.vin.len and
            self.vout_ptr == transaction.vout.ptr and self.vout_len == transaction.vout.len and
            self.spent_outputs_ptr == spent_outputs.ptr and self.spent_outputs_len == spent_outputs.len;
    }
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
        .vin_ptr = transaction.vin.ptr,
        .vin_len = transaction.vin.len,
        .vout_ptr = transaction.vout.ptr,
        .vout_len = transaction.vout.len,
        .spent_outputs_ptr = spent_outputs.ptr,
        .spent_outputs_len = spent_outputs.len,
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
    if (pre) |p| if (!p.matches(transaction, spent_outputs)) return error.PrecomputedMismatch;
    if (input_index >= transaction.vin.len) return error.InputIndexOutOfRange;
    if (spent_outputs.len != transaction.vin.len) return error.PrevoutsCountMismatch;
    // X1: `spend_type`'s annex-present bit (bit 0) and `annex_hash` must
    // agree — a caller that sets one without the other gets a SigMsg no
    // verifier computes, silently, instead of an error.
    if ((opts.spend_type & 1 != 0) != (opts.annex_hash != null)) return error.SpendTypeAnnexMismatch;

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
        // `input_index < transaction.vin.len` is already checked above, but
        // that bounds it only by the input array's length, not by `u32`'s
        // range — a `usize` past `maxInt(u32)` (i.e. a transaction with more
        // than 4 billion inputs) would make a bare `@intCast` UB in
        // ReleaseFast rather than a typed error. Not reachable through any
        // parser in this module today (nothing constructs a `Transaction`
        // with that many inputs), but this is public API over a caller-
        // supplied `input_index`, so the guard belongs here rather than
        // resting on every caller happening to stay in range.
        const idx_u32 = std.math.cast(u32, input_index) orelse return error.InputIndexOutOfRange;
        try appendU32LE(&buf, allocator, idx_u32);
    }

    // Annex commitment: IMPLEMENTED here — `opts.annex_hash`, when the caller
    // sets it, is emitted right here per BIP341. What is deferred (SPEC.md
    // §"Deferred") is a HIGHER-layer concern: no caller in this module ever
    // constructs an annex-carrying `CommonOptions` (every call site here
    // leaves `annex_hash = null`), there is no annex-parsing/witness-stack-
    // inspection helper to derive one from a real witness, and (per SPEC.md)
    // the official test-vector fixture this module's KATs are pinned against
    // contains no annex case to verify the presence path against. The
    // wire-layout primitive below is straightforward and reviewed, but is
    // NOT covered by a byte-exact test with `annex_hash != null` — do not
    // read its existence as meaning that path is anchored the way the rest
    // of this file is.

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
const testutil = @import("testutil.zig");

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

test "X1: CommonOptions.spend_type bit 0 and annex_hash presence must agree" {
    // Without this check, `spend_type = 2` (ext_flag=1, no annex signaled)
    // plus a non-null `annex_hash` silently emits a SigMsg with 32 extra
    // bytes no verifier computes — see finding X1, `A1/bitcointx.md`.
    var t: tx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{.{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 }}),
        .vout = @constCast(&[_]tx.TxOut{.{ .value = 100, .script_pubkey = &.{} }}),
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const prevouts = [_]tx.TxOut{.{ .value = 100, .script_pubkey = &.{} }};
    const annex: [32]u8 = [_]u8{0xcc} ** 32;

    // Positive controls that MUST keep succeeding: consistent combinations.
    {
        const got = try commonSigMsg(testing.allocator, t, 0, SIGHASH_DEFAULT, &prevouts, .{ .spend_type = 2, .annex_hash = null });
        testing.allocator.free(got);
    }
    {
        const got = try commonSigMsg(testing.allocator, t, 0, SIGHASH_DEFAULT, &prevouts, .{ .spend_type = 3, .annex_hash = annex });
        testing.allocator.free(got);
    }

    // The two inconsistent combinations must be rejected.
    try testing.expectError(
        error.SpendTypeAnnexMismatch,
        commonSigMsg(testing.allocator, t, 0, SIGHASH_DEFAULT, &prevouts, .{ .spend_type = 2, .annex_hash = annex }),
    );
    try testing.expectError(
        error.SpendTypeAnnexMismatch,
        commonSigMsg(testing.allocator, t, 0, SIGHASH_DEFAULT, &prevouts, .{ .spend_type = 3, .annex_hash = null }),
    );
    _ = &t;
}

test "V2: spend_type is committed byte-for-byte -- key-path and script-path SigMsgs diverge" {
    // Nothing in this module's OWN tests ever passed `spend_type != 0` before
    // finding V2 (`A1/bitcointx.md`): wiring `opts.spend_type` to a hardcoded
    // `0` left all 54 tests that existed at audit time green, and the
    // key-path SigMsg would then be byte-for-byte identical to the
    // tapscript-spend SigMsg for the same input -- exactly the domain
    // separation `spend_type` exists in BIP341 to prevent. This test locates
    // the one byte that must carry `spend_type` and pins it.
    var t: tx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]tx.TxIn{.{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0 }}),
        .vout = @constCast(&[_]tx.TxOut{.{ .value = 100, .script_pubkey = &.{} }}),
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const prevouts = [_]tx.TxOut{.{ .value = 100, .script_pubkey = &.{} }};

    // Same transaction, same input, same hash type -- only `spend_type`
    // differs: 0 (key-path) vs 2 (tapscript spend, no annex).
    const key_path = try commonSigMsg(testing.allocator, t, 0, SIGHASH_DEFAULT, &prevouts, .{ .spend_type = 0, .annex_hash = null });
    defer testing.allocator.free(key_path);
    const script_path = try commonSigMsg(testing.allocator, t, 0, SIGHASH_DEFAULT, &prevouts, .{ .spend_type = 2, .annex_hash = null });
    defer testing.allocator.free(script_path);

    // Neither carries an annex, so the two messages must be the same length
    // -- and must NOT be the same bytes.
    try testing.expectEqual(key_path.len, script_path.len);
    try testing.expect(!std.mem.eql(u8, key_path, script_path));

    // Exactly one byte differs, and it is `spend_type` itself, holding the
    // value each caller passed.
    var diffs: usize = 0;
    var diff_at: usize = 0;
    for (key_path, script_path, 0..) |a, b, i| {
        if (a != b) {
            diffs += 1;
            diff_at = i;
        }
    }
    try testing.expectEqual(@as(usize, 1), diffs);
    try testing.expectEqual(@as(u8, 0), key_path[diff_at]);
    try testing.expectEqual(@as(u8, 2), script_path[diff_at]);
    _ = &t;
}

test "B2: shaOutputs/shaScriptPubkeys/shaAmounts/shaPrevouts/shaSequences don't reallocate growing many outputs" {
    // `A1/bitcointx.md` finding B2: these five per-transaction commitment
    // builders grew their `ArrayList`s by repeated `appendSlice` with no
    // `ensureTotalCapacity` -- measured at 8 192 outputs, 24 allocations +
    // 35 remaps on ONE `bip341.sighash` call. Reserving exact capacity up
    // front (this file's `shaOutputs`/`shaScriptPubkeys`, and
    // `sighash_bip143.zig`'s `hashOutputs`) should cut each builder to
    // exactly one allocator round trip.
    const n = 1024;
    const spk = [_]u8{ 0x76, 0xa9, 0x14 } ++ [_]u8{0x42} ** 20 ++ [_]u8{ 0x88, 0xac }; // 25-byte P2PKH

    var vin_buf: [n]tx.TxIn = undefined;
    var vout_buf: [n]tx.TxOut = undefined;
    var spent_buf: [n]tx.TxOut = undefined;
    for (0..n) |i| {
        vin_buf[i] = .{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
        vout_buf[i] = .{ .value = 100, .script_pubkey = &spk };
        spent_buf[i] = .{ .value = 100, .script_pubkey = &spk };
    }
    const t: tx.Transaction = .{
        .version = 1,
        .vin = vin_buf[0..],
        .vout = vout_buf[0..],
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };

    var counting: testutil.CountingAllocator = .{ .backing = testing.allocator };
    _ = try sighash(counting.allocator(), t, 0, SIGHASH_DEFAULT, spent_buf[0..n]);
    const total_ops = counting.allocs + counting.resizes + counting.remaps;

    // 5 commitment builders + the outer SigMsg buffer: at most a handful of
    // allocator round trips total for 1024 outputs/prevouts, not one per
    // `appendSlice`-triggered growth step (O(log n) each without
    // reservation).
    // Measured: 30 ops (24 allocs + 6 remaps) before the reservation, 8
    // (8 allocs, 0 resizes, 0 remaps) after.
    try testing.expect(total_ops <= 10);
}
