// SPDX-License-Identifier: MIT
//! `finalize`/`extract` — BIP174's **Input Finalizer** and **Transaction
//! Extractor** roles, built on the sibling `bitcoinscript` module (a Script
//! interpreter) and `bitcointx` (transaction model/serialization).
//!
//! ## Scope: standard spend types only
//!
//! `finalize` assembles `PSBT_IN_FINAL_SCRIPTSIG`/`PSBT_IN_FINAL_SCRIPTWITNESS`
//! for: P2PKH, native P2WPKH, P2SH-P2WPKH, bare multisig, P2SH multisig,
//! native P2WSH multisig, P2SH-P2WSH multisig, and P2TR key-path (via
//! `PSBT_IN_TAP_KEY_SIG`, BIP371's field — not part of BIP174 v0 proper, but
//! added to `input_key` in `root.zig` so a taproot input can be finalized at
//! all). Multisig scripts are recognized only in the `OP_1..OP_16 <pubkey>*
//! OP_1..OP_16 OP_CHECKMULTISIG` shape (every real-world multisig script);
//! `M`/`N` encoded as a generic `CScriptNum` push (valid consensus, but
//! never used in practice since it only matters above 16 keys) is treated as
//! non-standard. Anything else — timelocked scripts, tapscript,
//! non-multisig bare P2SH redeem scripts — is `error.NonStandardScript`,
//! never silently mis-assembled.
//!
//! ## Verify-on-finalize
//!
//! After assembling a candidate `FINAL_SCRIPTSIG`/`FINAL_SCRIPTWITNESS`,
//! `finalize` runs it through `bitcoinscript.verifyScript` (against the
//! input's actual scriptPubKey, under `ScriptFlags.standard`) before
//! accepting it — a malformed, incomplete, or tampered assembly is rejected
//! there, not just at broadcast time. This is the whole reason this role
//! was deferred until `bitcoinscript` existed (see `root.zig`'s prior module
//! doc comment, still visible in history).
//!
//! ## BIP174 §"Input Finalizer": what gets cleared
//!
//! Per spec, all input fields except the UTXO and unknown/proprietary
//! fields are cleared once finalized: `PARTIAL_SIG`, `SIGHASH_TYPE`,
//! `REDEEM_SCRIPT`, `WITNESS_SCRIPT`, `BIP32_DERIVATION`, and (this module's
//! addition) `TAP_KEY_SIG` are dropped from the input map; everything else
//! (the UTXO, `PROPRIETARY`, any unrecognized key type) passes through
//! untouched. `finalize` is idempotent: an input that already carries a
//! `FINAL_SCRIPTSIG`/`FINAL_SCRIPTWITNESS` is left exactly as-is (treated as
//! already finalized, not re-verified).
//!
//! ## Allocator contract
//!
//! Like `bitcoinscript.interpreter.eval` (whose doc comment this mirrors),
//! `allocator` is assumed **arena-like**: `finalize` allocates new
//! `FINAL_SCRIPTSIG`/`FINAL_SCRIPTWITNESS` value buffers that are NOT
//! individually tracked by `Psbt.deinit` (which only frees each `Map`'s
//! `records` array, per `root.zig`'s ownership model — see its module doc
//! comment). A non-arena allocator will leak these buffers; callers that
//! need precise frees should finalize/extract inside an arena and free it
//! in bulk once done with the result.
//!
//! ## Sighash-type enforcement
//!
//! If `PSBT_IN_SIGHASH_TYPE` is present, a candidate `PARTIAL_SIG` whose
//! trailing hash-type byte doesn't match is skipped (BIP174: "finalizers
//! must fail to finalize inputs which have signatures that do not match the
//! specified sighash type") — for ECDSA-family spends. Taproot's sighash
//! byte lives inside `TAP_KEY_SIG` itself (BIP341's own encoding) and is
//! left to `verifyScript` to interpret; this module does not additionally
//! cross-check it against `PSBT_IN_SIGHASH_TYPE`.
//!
//! ## Taproot needs every input's UTXO
//!
//! BIP341's sighash commits to every input's spent output, not just the one
//! being signed (`bitcoinscript.txctx.TxContext`'s doc comment). `finalize`
//! resolves every input's UTXO once up front; finalizing a P2TR input when
//! ANY input's UTXO is unresolved fails closed with
//! `error.TaprootMissingAllUtxos`, even if the taproot input's own UTXO is
//! fine.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const bitcoinscript = @import("bitcoinscript");
const psbt = @import("root.zig");

// ── script template recognition ─────────────────────────────────────────

fn isP2pkh(script: []const u8) bool {
    return script.len == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac;
}

fn isP2sh(script: []const u8) bool {
    return script.len == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87;
}

const WitnessProgram = struct { version: u8, program: []const u8 };

/// `OP_0`/`OP_1..OP_16` followed by a single minimal 2..40-byte push,
/// nothing else, total length 4..42 (Bitcoin Core `CScript::IsWitnessProgram`
/// — mirrors `bitcoinscript.verify`'s private copy of the same check; not
/// exported from there, so this module keeps its own).
fn parseWitnessProgram(script: []const u8) ?WitnessProgram {
    if (script.len < 4 or script.len > 42) return null;
    const first = script[0];
    const version: u8 = if (first == 0x00) 0 else if (first >= 0x51 and first <= 0x60) first - 0x50 else return null;
    const push_len = script[1];
    if (push_len < 2 or push_len > 40) return null;
    if (script.len != @as(usize, 2) + push_len) return null;
    return .{ .version = version, .program = script[2..] };
}

fn smallInt(op: u8) ?u8 {
    if (op >= 0x51 and op <= 0x60) return op - 0x50;
    return null;
}

const max_multisig_keys = 16; // OP_1..OP_16 encoding ceiling (module doc comment: scope cut)

const MultisigShape = struct {
    m: u8,
    n: u8,
    pubkeys: [max_multisig_keys][]const u8,
};

/// Recognizes `OP_<m> <pubkey>{n} OP_<n> OP_CHECKMULTISIG`, `m`/`n` encoded
/// via `OP_1..OP_16` only (module doc comment). `null` for anything else,
/// including a structurally-broken script (`readInstruction` failing).
fn parseMultisig(script: []const u8) ?MultisigShape {
    if (script.len == 0) return null;
    const m = smallInt(script[0]) orelse return null;
    var i: usize = 1;
    var pubkeys: [max_multisig_keys][]const u8 = undefined;
    var count: u8 = 0;
    while (i < script.len) {
        const instr = bitcoinscript.interpreter.readInstruction(script, i) catch return null;
        const data = instr.data orelse break;
        if (data.len != 33 and data.len != 65) return null;
        if (count >= max_multisig_keys) return null;
        pubkeys[count] = data;
        count += 1;
        i = instr.next;
    }
    if (i >= script.len) return null;
    const n_instr = bitcoinscript.interpreter.readInstruction(script, i) catch return null;
    const n = smallInt(n_instr.opcode) orelse return null;
    if (n != count or m == 0 or m > n) return null;
    const cms_instr = bitcoinscript.interpreter.readInstruction(script, n_instr.next) catch return null;
    if (cms_instr.opcode != 0xae or cms_instr.next != script.len) return null; // OP_CHECKMULTISIG
    return .{ .m = m, .n = n, .pubkeys = pubkeys };
}

// ── script/witness assembly ─────────────────────────────────────────────

/// Bitcoin Core `CheckMinimalPush`-compliant data push (needed because
/// `ScriptFlags.standard` sets `minimaldata`). The only case that actually
/// arises for the data this module pushes (signatures, pubkeys, redeem/
/// witness scripts — all >1 byte) is the plain `<len><data>` form; the
/// 0/1..16/-1 special cases are handled anyway for the CHECKMULTISIG dummy
/// (an empty push, i.e. `OP_0`).
fn appendPush(buf: *std.ArrayList(u8), allocator: Allocator, data: []const u8) Allocator.Error!void {
    if (data.len == 0) {
        try buf.append(allocator, 0x00);
        return;
    }
    if (data.len == 1 and data[0] >= 1 and data[0] <= 16) {
        try buf.append(allocator, 0x50 + data[0]);
        return;
    }
    if (data.len == 1 and data[0] == 0x81) {
        try buf.append(allocator, 0x4f);
        return;
    }
    if (data.len < 0x4c) {
        try buf.append(allocator, @intCast(data.len));
    } else if (data.len <= 0xff) {
        try buf.append(allocator, 0x4c);
        try buf.append(allocator, @intCast(data.len));
    } else if (data.len <= 0xffff) {
        try buf.append(allocator, 0x4d);
        var lb: [2]u8 = undefined;
        std.mem.writeInt(u16, &lb, @intCast(data.len), .little);
        try buf.appendSlice(allocator, &lb);
    } else {
        try buf.append(allocator, 0x4e);
        var lb: [4]u8 = undefined;
        std.mem.writeInt(u32, &lb, @intCast(data.len), .little);
        try buf.appendSlice(allocator, &lb);
    }
    try buf.appendSlice(allocator, data);
}

fn buildSinglePush(allocator: Allocator, data: []const u8) Allocator.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendPush(&buf, allocator, data);
    return buf.toOwnedSlice(allocator);
}

fn buildP2pkhScriptSig(allocator: Allocator, sig: []const u8, pubkey: []const u8) Allocator.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendPush(&buf, allocator, sig);
    try appendPush(&buf, allocator, pubkey);
    return buf.toOwnedSlice(allocator);
}

/// `sig_value`'s trailing hash-type byte must equal `expected`'s low byte,
/// if `expected` is non-null (BIP174 §"Input Finalizer" sighash-type rule,
/// module doc comment).
fn sighashMatches(sig_value: []const u8, expected: ?u32) bool {
    const exp = expected orelse return true;
    if (sig_value.len == 0) return false;
    return sig_value[sig_value.len - 1] == @as(u8, @truncate(exp));
}

fn findMatchingPartialSig(m: psbt.Map, expected_sighash: ?u32) ?psbt.Record {
    for (m.records) |r| {
        if (r.keytype == psbt.input_key.PARTIAL_SIG and sighashMatches(r.value, expected_sighash)) return r;
    }
    return null;
}

/// Walks `ms.pubkeys[0..ms.n]` in order, taking the first `ms.m` that have a
/// matching (and sighash-eligible) `PARTIAL_SIG` — CHECKMULTISIG's own
/// pubkey-order matching algorithm accepts any such subsequence, and this is
/// the canonical "greedy, in order" choice real wallets make too. `null` if
/// fewer than `ms.m` are available.
fn collectMultisigSigs(m: psbt.Map, ms: MultisigShape, expected_sighash: ?u32, out: *[max_multisig_keys][]const u8) ?void {
    var found: u8 = 0;
    for (ms.pubkeys[0..ms.n]) |pk| {
        if (found == ms.m) break;
        const sig_rec = m.findKeyed(psbt.input_key.PARTIAL_SIG, pk) orelse continue;
        if (!sighashMatches(sig_rec.value, expected_sighash)) continue;
        out[found] = sig_rec.value;
        found += 1;
    }
    if (found < ms.m) return null;
    return {};
}

/// `redeem_push`, if given, is appended as a trailing push after the
/// signatures (P2SH resumption: the redeem script itself must be the last
/// scriptSig element).
fn buildMultisigScriptSig(
    allocator: Allocator,
    m: psbt.Map,
    ms_script: []const u8,
    expected_sighash: ?u32,
    redeem_push: ?[]const u8,
) InputFinalizeError![]u8 {
    const ms = parseMultisig(ms_script) orelse return error.NonStandardScript;
    var sigs: [max_multisig_keys][]const u8 = undefined;
    _ = collectMultisigSigs(m, ms, expected_sighash, &sigs) orelse return error.InsufficientSignatures;
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendPush(&buf, allocator, &.{}); // CHECKMULTISIG off-by-one dummy (BIP147: must be empty)
    for (sigs[0..ms.m]) |s| try appendPush(&buf, allocator, s);
    if (redeem_push) |rp| try appendPush(&buf, allocator, rp);
    return buf.toOwnedSlice(allocator);
}

fn buildMultisigWitness(
    allocator: Allocator,
    m: psbt.Map,
    witness_script: []const u8,
    expected_sighash: ?u32,
) InputFinalizeError![][]const u8 {
    const ms = parseMultisig(witness_script) orelse return error.NonStandardScript;
    var sigs: [max_multisig_keys][]const u8 = undefined;
    _ = collectMultisigSigs(m, ms, expected_sighash, &sigs) orelse return error.InsufficientSignatures;
    var items: std.ArrayList([]const u8) = .empty;
    errdefer items.deinit(allocator);
    try items.append(allocator, &.{}); // dummy: a raw empty witness item, no script push needed
    for (sigs[0..ms.m]) |s| try items.append(allocator, s);
    try items.append(allocator, witness_script);
    return items.toOwnedSlice(allocator);
}

fn finalizeWitnessProgram(
    allocator: Allocator,
    m: psbt.Map,
    wp: WitnessProgram,
    expected_sighash: ?u32,
    all_utxos_resolved: bool,
) InputFinalizeError![][]const u8 {
    if (wp.version == 0 and wp.program.len == 20) {
        // Native/P2SH-wrapped P2WPKH.
        const sig_rec = findMatchingPartialSig(m, expected_sighash) orelse return error.MissingSignature;
        return try allocator.dupe([]const u8, &[_][]const u8{ sig_rec.value, sig_rec.keydata });
    }
    if (wp.version == 0 and wp.program.len == 32) {
        // Native/P2SH-wrapped P2WSH multisig.
        const ws = m.find(psbt.input_key.WITNESS_SCRIPT) orelse return error.NonStandardScript;
        return try buildMultisigWitness(allocator, m, ws.value, expected_sighash);
    }
    if (wp.version == 1 and wp.program.len == 32) {
        // P2TR key-path.
        if (!all_utxos_resolved) return error.TaprootMissingAllUtxos;
        const sig = psbt.inputTapKeySig(m) orelse return error.MissingTaprootSignature;
        return try allocator.dupe([]const u8, &[_][]const u8{sig});
    }
    return error.NonStandardScript;
}

// ── UTXO resolution ──────────────────────────────────────────────────────

fn spentOutputFor(
    allocator: Allocator,
    m: psbt.Map,
    utx: bitcointx.Transaction,
    index: usize,
) (psbt.WitnessUtxoError || bitcointx.tx.DeserializeError)!?bitcointx.TxOut {
    if (try psbt.inputWitnessUtxo(m)) |wu| return wu;
    if (try psbt.inputNonWitnessUtxo(m, allocator)) |prevtx| {
        var pt = prevtx;
        defer pt.deinit(allocator); // frees only the vout ARRAY -- the TxOut copied out below still borrows its content bytes from `m`'s original buffer (module doc comment)
        if (index >= utx.vin.len) return null;
        const vout_idx = utx.vin[index].prevout.vout;
        if (vout_idx >= pt.vout.len) return null;
        return pt.vout[vout_idx];
    }
    return null;
}

// ── input-map rebuild (the BIP174 "clear consumed fields" step) ────────

fn isClearableOnFinalize(keytype: u64) bool {
    return switch (keytype) {
        psbt.input_key.PARTIAL_SIG,
        psbt.input_key.SIGHASH_TYPE,
        psbt.input_key.REDEEM_SCRIPT,
        psbt.input_key.WITNESS_SCRIPT,
        psbt.input_key.BIP32_DERIVATION,
        psbt.input_key.TAP_KEY_SIG,
        => true,
        else => false,
    };
}

fn appendCompactSizeLocal(buf: *std.ArrayList(u8), allocator: Allocator, value: u64) Allocator.Error!void {
    var tmp: [9]u8 = undefined;
    const w = bitcointx.encodeCompactSize(value, &tmp) catch unreachable; // tmp always big enough
    try buf.appendSlice(allocator, w);
}

/// `PSBT_IN_FINAL_SCRIPTWITNESS`'s value shape: a `CompactSize` count
/// followed by that many `CompactSize`-prefixed items -- identical to a
/// single input's witness-stack wire encoding (BIP144).
pub fn encodeWitnessStack(allocator: Allocator, items: []const []const u8) Allocator.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendCompactSizeLocal(&buf, allocator, items.len);
    for (items) |it| {
        try appendCompactSizeLocal(&buf, allocator, it.len);
        try buf.appendSlice(allocator, it);
    }
    return buf.toOwnedSlice(allocator);
}

pub const WitnessStackError = bitcointx.tx.CompactSizeError || error{TrailingBytes};

/// Inverse of `encodeWitnessStack`. `value` may be untrusted (a
/// `FINAL_SCRIPTWITNESS` a `Psbt` was NOT produced by this module's own
/// `finalize`, e.g. one `extract` is asked to process directly after
/// `parse`) -- fails closed on truncation/trailing bytes, never panics or
/// over-allocates on a hostile count (bounded the same way
/// `bitcointx.tx`'s own witness decoder is: each item needs >=1 byte, so a
/// count exceeding the bytes remaining is rejected before any per-item
/// allocation).
pub fn decodeWitnessStack(allocator: Allocator, value: []const u8) (WitnessStackError || Allocator.Error)![][]const u8 {
    var offset: usize = 0;
    const count_r = try bitcointx.decodeCompactSize(value[offset..]);
    offset += count_r.consumed;
    if (count_r.value > value.len - offset) return error.Truncated;
    var items: std.ArrayList([]const u8) = .empty;
    errdefer items.deinit(allocator);
    var i: u64 = 0;
    while (i < count_r.value) : (i += 1) {
        const len_r = try bitcointx.decodeCompactSize(value[offset..]);
        offset += len_r.consumed;
        if (len_r.value > value.len - offset) return error.Truncated;
        const l: usize = @intCast(len_r.value);
        try items.append(allocator, value[offset .. offset + l]);
        offset += l;
    }
    if (offset != value.len) return error.TrailingBytes;
    return items.toOwnedSlice(allocator);
}

fn rebuildInputMap(
    allocator: Allocator,
    old: psbt.Map,
    final_script_sig: ?[]const u8,
    final_witness: ?[][]const u8,
) Allocator.Error!psbt.Map {
    var list: std.ArrayList(psbt.Record) = .empty;
    errdefer list.deinit(allocator);
    for (old.records) |r| {
        if (isClearableOnFinalize(r.keytype)) continue;
        try list.append(allocator, r);
    }
    if (final_script_sig) |fs| {
        try list.append(allocator, .{ .keytype = psbt.input_key.FINAL_SCRIPTSIG, .keydata = &.{}, .value = fs });
    }
    if (final_witness) |fw| {
        const enc = try encodeWitnessStack(allocator, fw);
        try list.append(allocator, .{ .keytype = psbt.input_key.FINAL_SCRIPTWITNESS, .keydata = &.{}, .value = enc });
    }
    return .{ .records = try list.toOwnedSlice(allocator) };
}

// ── Input Finalizer ──────────────────────────────────────────────────────

pub const InputFinalizeError = error{
    /// Neither `WITNESS_UTXO` nor `NON_WITNESS_UTXO` (or a referenced
    /// non-witness UTXO whose `vout` index doesn't exist) resolves this
    /// input's spent output.
    MissingUtxo,
    /// This input is a P2TR key-path spend, but at least one OTHER input's
    /// UTXO could not be resolved -- BIP341 sighashing needs the full set
    /// (module doc comment).
    TaprootMissingAllUtxos,
    /// The (unwrapped) script is not one of the standard types this
    /// finalizer recognizes.
    NonStandardScript,
    /// No `PARTIAL_SIG`/`TAP_KEY_SIG` matching what's required (and, if
    /// `SIGHASH_TYPE` is set, its sighash type) is present.
    MissingSignature,
    MissingTaprootSignature,
    /// A multisig script needs more matching signatures than are present.
    InsufficientSignatures,
} || psbt.WitnessUtxoError || bitcointx.tx.DeserializeError || bitcoinscript.VerifyError || Allocator.Error;

fn finalizeOneInput(
    allocator: Allocator,
    ps: psbt.Psbt,
    utx: bitcointx.Transaction,
    spent: []const bitcointx.TxOut,
    resolved: []const bool,
    all_resolved: bool,
    index: usize,
) InputFinalizeError!void {
    const m = ps.inputs[index];
    if (m.find(psbt.input_key.FINAL_SCRIPTSIG) != null or m.find(psbt.input_key.FINAL_SCRIPTWITNESS) != null) {
        return; // already finalized -- idempotent success, BIP174 doc comment
    }
    if (!resolved[index]) return error.MissingUtxo;

    const script_pubkey = spent[index].script_pubkey;
    const expected_sighash = psbt.inputSighashType(m);

    var final_script_sig: ?[]const u8 = null;
    var final_witness: ?[][]const u8 = null;

    if (isP2pkh(script_pubkey)) {
        const sig_rec = findMatchingPartialSig(m, expected_sighash) orelse return error.MissingSignature;
        final_script_sig = try buildP2pkhScriptSig(allocator, sig_rec.value, sig_rec.keydata);
    } else if (parseWitnessProgram(script_pubkey)) |wp| {
        final_witness = try finalizeWitnessProgram(allocator, m, wp, expected_sighash, all_resolved);
    } else if (isP2sh(script_pubkey)) {
        const rs = m.find(psbt.input_key.REDEEM_SCRIPT) orelse return error.NonStandardScript;
        const redeem = rs.value;
        if (parseWitnessProgram(redeem)) |rwp| {
            final_witness = try finalizeWitnessProgram(allocator, m, rwp, expected_sighash, all_resolved);
            final_script_sig = try buildSinglePush(allocator, redeem);
        } else if (parseMultisig(redeem) != null) {
            final_script_sig = try buildMultisigScriptSig(allocator, m, redeem, expected_sighash, redeem);
        } else {
            return error.NonStandardScript;
        }
    } else if (parseMultisig(script_pubkey) != null) {
        final_script_sig = try buildMultisigScriptSig(allocator, m, script_pubkey, expected_sighash, null);
    } else {
        return error.NonStandardScript;
    }

    const ctx: bitcoinscript.TxContext = .{ .tx = utx, .input_index = index, .spent_outputs = spent };
    try bitcoinscript.verifyScript(
        allocator,
        final_script_sig orelse &.{},
        script_pubkey,
        final_witness orelse &.{},
        bitcoinscript.ScriptFlags.standard,
        ctx,
    );

    const new_map = try rebuildInputMap(allocator, m, final_script_sig, final_witness);
    var old = ps.inputs[index];
    ps.inputs[index] = new_map;
    old.deinit(allocator);
}

pub const FinalizeSetupError = Allocator.Error || bitcointx.tx.DeserializeError;

/// Finalizes every input of `ps` it can, mutating `ps.inputs` in place
/// (module doc comment: `Psbt.inputs` is a slice, so mutation through this
/// by-value `ps` parameter is visible to the caller's own `Psbt`). Returns
/// one `?InputFinalizeError` per input, in input order -- `null` for a
/// finalized (or already-finalized) input, the specific typed reason
/// otherwise. Never all-or-nothing: an unfinalizable non-standard input
/// doesn't block the rest.
pub fn finalize(allocator: Allocator, ps: psbt.Psbt) FinalizeSetupError![]?InputFinalizeError {
    var utx = try ps.unsignedTx(allocator);
    defer utx.deinit(allocator);

    const n = ps.inputs.len;
    const spent = try allocator.alloc(bitcointx.TxOut, n);
    defer allocator.free(spent);
    const resolved = try allocator.alloc(bool, n);
    defer allocator.free(resolved);

    for (ps.inputs, 0..) |m, i| {
        const so = spentOutputFor(allocator, m, utx, i) catch null;
        if (so) |v| {
            spent[i] = v;
            resolved[i] = true;
        } else {
            spent[i] = .{ .value = 0, .script_pubkey = &.{} };
            resolved[i] = false;
        }
    }
    var all_resolved = true;
    for (resolved) |r| {
        if (!r) {
            all_resolved = false;
            break;
        }
    }

    const results = try allocator.alloc(?InputFinalizeError, n);
    for (0..n) |i| {
        results[i] = if (finalizeOneInput(allocator, ps, utx, spent, resolved, all_resolved, i)) |_| null else |e| e;
    }
    return results;
}

// ── Transaction Extractor ────────────────────────────────────────────────

pub const ExtractError = error{
    /// Some input has neither `FINAL_SCRIPTSIG` nor `FINAL_SCRIPTWITNESS`
    /// (BIP174: the Extractor "must not modify the PSBT" if not every input
    /// is complete -- surfaced here as a typed refusal rather than a
    /// partial `Transaction`).
    InputNotFinalized,
} || Allocator.Error || bitcointx.tx.DeserializeError || WitnessStackError;

/// Splices every input's finalized scriptSig/scriptWitness into the
/// unsigned transaction, producing a network-ready `bitcointx.Transaction`
/// (caller owns it, `.deinit`). Requires every input finalized.
pub fn extract(allocator: Allocator, ps: psbt.Psbt) ExtractError!bitcointx.Transaction {
    var utx = try ps.unsignedTx(allocator);
    defer utx.deinit(allocator);

    const n = ps.inputs.len;
    const vin = try allocator.alloc(bitcointx.TxIn, n);
    errdefer allocator.free(vin);
    var any_witness = false;
    for (ps.inputs, 0..) |m, i| {
        const fs = m.find(psbt.input_key.FINAL_SCRIPTSIG);
        const fw = m.find(psbt.input_key.FINAL_SCRIPTWITNESS);
        if (fs == null and fw == null) return error.InputNotFinalized;
        if (fw != null) any_witness = true;
        vin[i] = .{
            .prevout = utx.vin[i].prevout,
            .script_sig = if (fs) |r| r.value else &.{},
            .sequence = utx.vin[i].sequence,
        };
    }

    const vout = try allocator.alloc(bitcointx.TxOut, utx.vout.len);
    errdefer allocator.free(vout);
    for (utx.vout, 0..) |v, i| vout[i] = v;

    var witness: []bitcointx.Witness = &.{};
    if (any_witness) {
        var list: std.ArrayList(bitcointx.Witness) = .empty;
        errdefer {
            for (list.items) |w| allocator.free(w.items);
            list.deinit(allocator);
        }
        for (ps.inputs) |m| {
            if (m.find(psbt.input_key.FINAL_SCRIPTWITNESS)) |r| {
                try list.append(allocator, .{ .items = try decodeWitnessStack(allocator, r.value) });
            } else {
                try list.append(allocator, .{ .items = &.{} });
            }
        }
        witness = try list.toOwnedSlice(allocator);
    }

    return .{
        .version = utx.version,
        .vin = vin,
        .vout = vout,
        .witness = witness,
        .locktime = utx.locktime,
        .has_witness = any_witness,
    };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseMultisig recognizes a 2-of-3 OP_CHECKMULTISIG script" {
    const pk1 = [_]u8{0x02} ++ [_]u8{0xaa} ** 32;
    const pk2 = [_]u8{0x03} ++ [_]u8{0xbb} ** 32;
    const pk3 = [_]u8{0x02} ++ [_]u8{0xcc} ** 32;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try script.append(testing.allocator, 0x52); // OP_2
    for ([_][]const u8{ &pk1, &pk2, &pk3 }) |pk| {
        try script.append(testing.allocator, 33);
        try script.appendSlice(testing.allocator, pk);
    }
    try script.append(testing.allocator, 0x53); // OP_3
    try script.append(testing.allocator, 0xae); // OP_CHECKMULTISIG

    const ms = parseMultisig(script.items) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, 2), ms.m);
    try testing.expectEqual(@as(u8, 3), ms.n);
    try testing.expectEqualSlices(u8, &pk1, ms.pubkeys[0]);
    try testing.expectEqualSlices(u8, &pk3, ms.pubkeys[2]);
}

test "parseMultisig rejects a non-multisig script" {
    try testing.expect(parseMultisig(&.{ 0x76, 0xa9, 0x88, 0xac }) == null);
    try testing.expect(parseMultisig(&.{}) == null);
}

test "parseWitnessProgram: P2WPKH and P2WSH shapes" {
    var p2wpkh = [_]u8{ 0x00, 0x14 } ++ [_]u8{0xaa} ** 20;
    const wp1 = parseWitnessProgram(&p2wpkh) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, 0), wp1.version);
    try testing.expectEqual(@as(usize, 20), wp1.program.len);

    var p2wsh = [_]u8{ 0x00, 0x20 } ++ [_]u8{0xbb} ** 32;
    const wp2 = parseWitnessProgram(&p2wsh) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, 0), wp2.version);
    try testing.expectEqual(@as(usize, 32), wp2.program.len);

    try testing.expect(parseWitnessProgram(&.{ 0x76, 0xa9 }) == null);
    _ = &p2wpkh;
    _ = &p2wsh;
}

test "appendPush: minimal-push encoding, including the empty (OP_0) dummy" {
    const allocator = testing.allocator;
    {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        try appendPush(&buf, allocator, &.{});
        try testing.expectEqualSlices(u8, &.{0x00}, buf.items);
    }
    {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        const data = [_]u8{0xab} ** 33;
        try appendPush(&buf, allocator, &data);
        try testing.expectEqual(@as(u8, 33), buf.items[0]);
        try testing.expectEqual(@as(usize, 34), buf.items.len);
    }
}

test "encodeWitnessStack / decodeWitnessStack round-trip" {
    const allocator = testing.allocator;
    const items = [_][]const u8{ "sig", "pubkey", &.{} };
    const enc = try encodeWitnessStack(allocator, &items);
    defer allocator.free(enc);
    const dec = try decodeWitnessStack(allocator, enc);
    defer allocator.free(dec);
    try testing.expectEqual(@as(usize, 3), dec.len);
    try testing.expectEqualSlices(u8, "sig", dec[0]);
    try testing.expectEqualSlices(u8, "pubkey", dec[1]);
    try testing.expectEqual(@as(usize, 0), dec[2].len);
}

test "hostile: decodeWitnessStack rejects a count exceeding remaining bytes, no over-allocation" {
    // CompactSize count = 0xff-class claiming ~2^64 items, nothing follows.
    const bytes = [_]u8{0xff} ++ [_]u8{0xff} ** 8;
    try testing.expectError(error.Truncated, decodeWitnessStack(testing.allocator, &bytes));
}

test "hostile: decodeWitnessStack rejects trailing bytes after a complete stack" {
    const allocator = testing.allocator;
    const items = [_][]const u8{"x"};
    const enc = try encodeWitnessStack(allocator, &items);
    defer allocator.free(enc);
    var padded = try allocator.alloc(u8, enc.len + 1);
    defer allocator.free(padded);
    @memcpy(padded[0..enc.len], enc);
    padded[enc.len] = 0xff;
    try testing.expectError(error.TrailingBytes, decodeWitnessStack(allocator, padded));
}
