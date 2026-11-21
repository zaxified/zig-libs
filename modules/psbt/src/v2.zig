// SPDX-License-Identifier: MIT
//! BIP370 (PSBT version 2): typed readers, the locktime rule, the unsigned
//! transaction built from the version 2 fields, the Creator / Constructor /
//! Updater functions, and the unique id.
//!
//! A version 2 PSBT has no `PSBT_GLOBAL_UNSIGNED_TX`: the transaction is spread
//! over the global map (version, fallback locktime, the input and output
//! counts), each input map (`PREVIOUS_TXID`, `OUTPUT_INDEX`, `SEQUENCE`, the
//! required locktimes) and each output map (`AMOUNT`, `SCRIPT`). `psbt.parse`
//! validates the shapes and the version 0 / version 2 inclusion rules, so on a
//! parsed PSBT the readers below cannot meet a malformed field; on a hand-built
//! `Map` they read a malformed one as absent. `Psbt.unsignedTx`, `finalize` and
//! `extract` work on version 2 unchanged because they go through
//! `Psbt.unsignedTx`, which builds the transaction from these fields.
//!
//! ## Locktime
//!
//! `lockTime` follows BIP370 §"Determining Lock Time": with no required
//! locktime on any input the global fallback (default 0) is used; otherwise the
//! locktime kind every constrained input supports is chosen (an input with
//! neither field, or with both, supports both kinds), the height kind when both
//! are possible, and the value is the maximum of that kind. Inputs that need
//! only a time and inputs that need only a height cannot be combined:
//! `error.ConflictingLocktimes`. `parse` accepts such a PSBT (BIP370's own
//! vectors list it as valid with an uncomputable locktime).
//!
//! ## Constructor
//!
//! `create` makes an empty PSBT (version 2, no inputs or outputs); `addInput`
//! and `addOutput` append one input or output after checking the
//! `PSBT_GLOBAL_TX_MODIFIABLE` flag, and keep the count fields in step. An
//! absent flag byte means nothing may be added (BIP370: "removing the field
//! entirely" declares the transaction final). `addInput` refuses an input whose
//! locktime fields cannot be combined with the existing ones, and one that would
//! change the locktime of a transaction that already carries signatures.
//! Appending never separates a SIGHASH_SINGLE input from its output, so the
//! "Has SIGHASH_SINGLE" flag needs no extra check here. The functions assume an
//! arena-like allocator exactly as the Updater in `update.zig` does.
//!
//! ## Not here
//!
//! The Signer's duty to update `PSBT_GLOBAL_TX_MODIFIABLE` after signing is the
//! caller's (`setTxModifiable`); this module never signs. Merging two
//! PSBTs' flag bytes is first-wins like every other conflicting value (`combine`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const psbt = @import("root.zig");
const update = @import("update.zig");

const Map = psbt.Map;
const Psbt = psbt.Psbt;
const Record = psbt.Record;
const global_key = psbt.global_key;
const input_key = psbt.input_key;
const output_key = psbt.output_key;

/// `PSBT_GLOBAL_TX_MODIFIABLE` bit 0: inputs may be added or removed.
pub const modifiable_inputs: u8 = 1;
/// `PSBT_GLOBAL_TX_MODIFIABLE` bit 1: outputs may be added or removed.
pub const modifiable_outputs: u8 = 2;
/// `PSBT_GLOBAL_TX_MODIFIABLE` bit 2: some signature uses SIGHASH_SINGLE.
pub const has_sighash_single: u8 = 4;

// ── version inclusion rules (used by `psbt.parse`) ──────────────────────

fn isV2InputKey(keytype: u64) bool {
    return keytype >= input_key.PREVIOUS_TXID and keytype <= input_key.REQUIRED_HEIGHT_LOCKTIME;
}

fn isV2OutputKey(keytype: u64) bool {
    return keytype == output_key.AMOUNT or keytype == output_key.SCRIPT;
}

/// BIP370 "Versions Requiring Inclusion / Exclusion" for an input map.
pub fn checkInputMap(m: Map, version: u32) psbt.ParseError!void {
    if (version == 0) {
        for (m.records) |r| if (isV2InputKey(r.keytype)) return error.FieldNotAllowedInVersion;
        return;
    }
    if (m.find(input_key.PREVIOUS_TXID) == null or m.find(input_key.OUTPUT_INDEX) == null) return error.MissingRequiredField;
}

/// BIP370 "Versions Requiring Inclusion / Exclusion" for an output map.
pub fn checkOutputMap(m: Map, version: u32) psbt.ParseError!void {
    if (version == 0) {
        for (m.records) |r| if (isV2OutputKey(r.keytype)) return error.FieldNotAllowedInVersion;
        return;
    }
    if (m.find(output_key.AMOUNT) == null or m.find(output_key.SCRIPT) == null) return error.MissingRequiredField;
}

// ── typed readers ───────────────────────────────────────────────────────

fn fixedValue(m: Map, keytype: u64, comptime n: usize) ?*const [n]u8 {
    const r = m.find(keytype) orelse return null;
    if (r.value.len != n) return null;
    return r.value[0..n];
}

fn u32Field(m: Map, keytype: u64) ?u32 {
    const v = fixedValue(m, keytype, 4) orelse return null;
    return std.mem.readInt(u32, v, .little);
}

/// `PSBT_GLOBAL_TX_VERSION`, or `null` when absent (version 0 PSBTs, or a malformed hand-built one).
pub fn txVersion(ps: Psbt) ?i32 {
    const v = fixedValue(ps.global, global_key.TX_VERSION, 4) orelse return null;
    return std.mem.readInt(i32, v, .little);
}

/// `PSBT_GLOBAL_FALLBACK_LOCKTIME`, or `null` when absent (the rule then assumes 0).
pub fn fallbackLocktime(ps: Psbt) ?u32 {
    return u32Field(ps.global, global_key.FALLBACK_LOCKTIME);
}

/// `PSBT_GLOBAL_TX_MODIFIABLE` flags (`modifiable_*`), or `null` when absent. Undefined bits are returned as stored.
pub fn txModifiable(ps: Psbt) ?u8 {
    const v = fixedValue(ps.global, global_key.TX_MODIFIABLE, 1) orelse return null;
    return v[0];
}

/// `PSBT_IN_PREVIOUS_TXID` (wire byte order), or `null` when absent.
pub fn inputPreviousTxid(m: Map) ?[32]u8 {
    const v = fixedValue(m, input_key.PREVIOUS_TXID, 32) orelse return null;
    return v.*;
}

/// `PSBT_IN_OUTPUT_INDEX`, or `null` when absent.
pub fn inputOutputIndex(m: Map) ?u32 {
    return u32Field(m, input_key.OUTPUT_INDEX);
}

/// `PSBT_IN_SEQUENCE`, or `null` when absent (the sequence is then 0xffffffff).
pub fn inputSequence(m: Map) ?u32 {
    return u32Field(m, input_key.SEQUENCE);
}

/// `PSBT_IN_REQUIRED_TIME_LOCKTIME`, or `null` when absent.
pub fn inputRequiredTimeLocktime(m: Map) ?u32 {
    return u32Field(m, input_key.REQUIRED_TIME_LOCKTIME);
}

/// `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME`, or `null` when absent.
pub fn inputRequiredHeightLocktime(m: Map) ?u32 {
    return u32Field(m, input_key.REQUIRED_HEIGHT_LOCKTIME);
}

/// `PSBT_OUT_AMOUNT` in satoshis, or `null` when absent.
pub fn outputAmount(m: Map) ?i64 {
    const v = fixedValue(m, output_key.AMOUNT, 8) orelse return null;
    return std.mem.readInt(i64, v, .little);
}

/// `PSBT_OUT_SCRIPT` (the scriptPubKey, borrowed), or `null` when absent.
pub fn outputScript(m: Map) ?[]const u8 {
    const r = m.find(output_key.SCRIPT) orelse return null;
    return r.value;
}

// ── lock time ───────────────────────────────────────────────────────────

/// BIP370 §"Determining Lock Time" over `inputs` and `fallback` (see the module doc comment).
fn computeLockTime(inputs: []const Map, fallback: ?u32) error{ConflictingLocktimes}!u32 {
    var possible_time = true;
    var possible_height = true;
    var max_time: ?u32 = null;
    var max_height: ?u32 = null;
    for (inputs) |m| {
        const t = inputRequiredTimeLocktime(m);
        const h = inputRequiredHeightLocktime(m);
        if (t != null and h == null) possible_height = false;
        if (h != null and t == null) possible_time = false;
        if (t) |v| max_time = @max(max_time orelse 0, v);
        if (h) |v| max_height = @max(max_height orelse 0, v);
    }
    if (!possible_time and !possible_height) return error.ConflictingLocktimes;
    if (max_time == null and max_height == null) return fallback orelse 0;
    if (possible_height) if (max_height) |h| return h;
    // `possible_time` here: the constrained inputs all allow a time lock, and any with only a
    // height field would have cleared it.
    return max_time orelse (fallback orelse 0);
}

/// The transaction's `nLockTime` as BIP370 determines it from the inputs and the fallback.
pub fn lockTime(ps: Psbt) error{ConflictingLocktimes}!u32 {
    return computeLockTime(ps.inputs, fallbackLocktime(ps));
}

// ── transaction ─────────────────────────────────────────────────────────

/// The unsigned transaction a version 2 PSBT describes (`Psbt.unsignedTx` calls this).
/// `zero_sequences` sets every input's sequence to 0 as BIP370 §"Unique Identification" does.
/// Caller owns the result (`.deinit`); scripts borrow from `ps`.
pub fn buildTx(allocator: Allocator, ps: Psbt, zero_sequences: bool) psbt.UnsignedTxError!bitcointx.Transaction {
    const version = txVersion(ps) orelse return error.MissingRequiredField;
    const locktime = try lockTime(ps);
    const vin = try allocator.alloc(bitcointx.TxIn, ps.inputs.len);
    errdefer allocator.free(vin);
    for (ps.inputs, vin) |m, *v| {
        v.* = .{
            .prevout = .{
                .txid = inputPreviousTxid(m) orelse return error.MissingRequiredField,
                .vout = inputOutputIndex(m) orelse return error.MissingRequiredField,
            },
            .script_sig = &.{},
            .sequence = if (zero_sequences) 0 else inputSequence(m) orelse 0xffffffff,
        };
    }
    const vout = try allocator.alloc(bitcointx.TxOut, ps.outputs.len);
    errdefer allocator.free(vout);
    for (ps.outputs, vout) |m, *o| {
        o.* = .{
            .value = outputAmount(m) orelse return error.MissingRequiredField,
            .script_pubkey = outputScript(m) orelse return error.MissingRequiredField,
        };
    }
    return .{ .version = version, .vin = vin, .vout = vout, .witness = &.{}, .locktime = locktime, .has_witness = false };
}

/// The PSBT's unique id (BIP370 §"Unique Identification"): the txid of the unsigned
/// transaction, with every sequence zeroed for version 2 (sequences can change under
/// Updaters and Combiners); for version 0 the txid of `PSBT_GLOBAL_UNSIGNED_TX`.
pub fn uniqueId(allocator: Allocator, ps: Psbt) psbt.UnsignedTxError![32]u8 {
    var tx = if (ps.global.find(global_key.UNSIGNED_TX) != null)
        try ps.unsignedTx(allocator)
    else
        try buildTx(allocator, ps, true);
    defer tx.deinit(allocator);
    return try tx.txid(allocator);
}

// ── Creator / Constructor / Updater ─────────────────────────────────────

pub const ConstructError = update.UpdateError || error{
    /// The PSBT is not version 2.
    NotPsbtV2,
    /// `PSBT_GLOBAL_TX_MODIFIABLE` is absent or lacks the inputs-modifiable bit.
    InputsNotModifiable,
    /// `PSBT_GLOBAL_TX_MODIFIABLE` is absent or lacks the outputs-modifiable bit.
    OutputsNotModifiable,
    /// The new input's required locktimes cannot be combined with the existing inputs'.
    ConflictingLocktimes,
    /// The new input would change the locktime of a transaction that already has signatures.
    ChangesLocktime,
};

fn putGlobal(allocator: Allocator, ps: *Psbt, keytype: u64, value: []const u8) ConstructError!void {
    const v = try allocator.dupe(u8, value);
    errdefer allocator.free(v);
    const rec: Record = .{ .keytype = keytype, .keydata = &.{}, .value = v };
    try psbt.validateGlobalRecord(rec);
    try ps.global.put(allocator, rec);
}

fn putCount(allocator: Allocator, ps: *Psbt, keytype: u64, n: usize) ConstructError!void {
    var buf: [9]u8 = undefined;
    const enc = bitcointx.encodeCompactSize(n, &buf) catch unreachable;
    try putGlobal(allocator, ps, keytype, enc);
}

/// A new version 2 PSBT with no inputs and no outputs (BIP370 §Creator). `modifiable`
/// is the `PSBT_GLOBAL_TX_MODIFIABLE` byte (`modifiable_*`; `null` omits the field, i.e.
/// nothing can be added afterwards); a PSBT that others will extend should use
/// `tx_version` >= 2 (BIP370). Owns nothing beyond what `allocator` hands out (arena-like).
pub fn create(allocator: Allocator, tx_version: i32, fallback: ?u32, modifiable: ?u8) ConstructError!Psbt {
    var ps: Psbt = .{ .global = .{ .records = &.{} }, .inputs = &.{}, .outputs = &.{} };
    var le4: [4]u8 = undefined;
    std.mem.writeInt(i32, &le4, tx_version, .little);
    try putGlobal(allocator, &ps, global_key.TX_VERSION, &le4);
    if (fallback) |f| {
        std.mem.writeInt(u32, &le4, f, .little);
        try putGlobal(allocator, &ps, global_key.FALLBACK_LOCKTIME, &le4);
    }
    try putCount(allocator, &ps, global_key.INPUT_COUNT, 0);
    try putCount(allocator, &ps, global_key.OUTPUT_COUNT, 0);
    if (modifiable) |f| try putGlobal(allocator, &ps, global_key.TX_MODIFIABLE, &.{f});
    std.mem.writeInt(u32, &le4, 2, .little);
    try putGlobal(allocator, &ps, global_key.VERSION, &le4);
    return ps;
}

/// `PSBT_GLOBAL_TX_MODIFIABLE`: the Signer's update after signing (BIP370 §Signer) or the Constructor's closing step.
pub fn setTxModifiable(allocator: Allocator, ps: *Psbt, flags: u8) ConstructError!void {
    if (ps.psbtVersion() != 2) return error.NotPsbtV2;
    try putGlobal(allocator, ps, global_key.TX_MODIFIABLE, &.{flags});
}

/// `PSBT_GLOBAL_FALLBACK_LOCKTIME`. Refused when it would change the locktime of a PSBT that carries signatures.
pub fn setFallbackLocktime(allocator: Allocator, ps: *Psbt, locktime: u32) ConstructError!void {
    if (ps.psbtVersion() != 2) return error.NotPsbtV2;
    const before = try lockTime(ps.*);
    var le: [4]u8 = undefined;
    std.mem.writeInt(u32, &le, locktime, .little);
    const old = ps.global.find(global_key.FALLBACK_LOCKTIME);
    try putGlobal(allocator, ps, global_key.FALLBACK_LOCKTIME, &le);
    if (hasSignatures(ps.*) and (try lockTime(ps.*)) != before) {
        if (old) |o| ps.global.put(allocator, o) catch {} else removeGlobal(ps, global_key.FALLBACK_LOCKTIME);
        return error.ChangesLocktime;
    }
}

fn removeGlobal(ps: *Psbt, keytype: u64) void {
    var w: usize = 0;
    for (ps.global.records) |r| {
        if (r.keytype == keytype and r.keydata.len == 0) continue;
        ps.global.records[w] = r;
        w += 1;
    }
    ps.global.records = ps.global.records[0..w];
}

/// `PSBT_IN_SEQUENCE` of input `index` (the Updater's one version 2 duty, BIP370 §Updater).
pub fn setInputSequence(allocator: Allocator, ps: *Psbt, index: usize, sequence: u32) ConstructError!void {
    if (ps.psbtVersion() != 2) return error.NotPsbtV2;
    var le: [4]u8 = undefined;
    std.mem.writeInt(u32, &le, sequence, .little);
    try update.putInput(allocator, ps, index, input_key.SEQUENCE, &.{}, &le);
}

/// An input for `addInput`.
pub const NewInput = struct {
    txid: [32]u8,
    vout: u32,
    /// `null`: no `PSBT_IN_SEQUENCE` (0xffffffff).
    sequence: ?u32 = null,
    /// At least 500000000.
    required_time_locktime: ?u32 = null,
    /// 1 to 499999999.
    required_height_locktime: ?u32 = null,
};

fn hasSignatures(ps: Psbt) bool {
    for (ps.inputs) |m| {
        for (m.records) |r| switch (r.keytype) {
            input_key.PARTIAL_SIG,
            input_key.FINAL_SCRIPTSIG,
            input_key.FINAL_SCRIPTWITNESS,
            input_key.TAP_KEY_SIG,
            input_key.TAP_SCRIPT_SIG,
            input_key.MUSIG2_PARTIAL_SIG,
            => return true,
            else => {},
        };
    }
    return false;
}

fn shrinkInputs(allocator: Allocator, ps: *Psbt, n: usize) void {
    ps.inputs = allocator.realloc(ps.inputs, n) catch ps.inputs[0..n];
}

fn shrinkOutputs(allocator: Allocator, ps: *Psbt, n: usize) void {
    ps.outputs = allocator.realloc(ps.outputs, n) catch ps.outputs[0..n];
}

/// Constructor: appends an input (BIP370 §Constructor). The PSBT's inputs-modifiable flag
/// must be set; the locktime fields must combine with the existing inputs' (otherwise
/// `error.ConflictingLocktimes`) and not change the locktime once any input is signed
/// (`error.ChangesLocktime`). On an error the PSBT is unchanged.
pub fn addInput(allocator: Allocator, ps: *Psbt, in: NewInput) ConstructError!void {
    if (ps.psbtVersion() != 2) return error.NotPsbtV2;
    if ((txModifiable(ps.*) orelse 0) & modifiable_inputs == 0) return error.InputsNotModifiable;
    const before = try lockTime(ps.*);
    const n = ps.inputs.len;
    ps.inputs = try allocator.realloc(ps.inputs, n + 1);
    ps.inputs[n] = .{ .records = &.{} };
    errdefer shrinkInputs(allocator, ps, n);
    try update.putInput(allocator, ps, n, input_key.PREVIOUS_TXID, &.{}, &in.txid);
    var le: [4]u8 = undefined;
    std.mem.writeInt(u32, &le, in.vout, .little);
    try update.putInput(allocator, ps, n, input_key.OUTPUT_INDEX, &.{}, &le);
    if (in.sequence) |s| try setInputSequence(allocator, ps, n, s);
    if (in.required_time_locktime) |t| {
        std.mem.writeInt(u32, &le, t, .little);
        try update.putInput(allocator, ps, n, input_key.REQUIRED_TIME_LOCKTIME, &.{}, &le);
    }
    if (in.required_height_locktime) |h| {
        std.mem.writeInt(u32, &le, h, .little);
        try update.putInput(allocator, ps, n, input_key.REQUIRED_HEIGHT_LOCKTIME, &.{}, &le);
    }
    const after = try lockTime(ps.*);
    if (after != before and hasSignatures(ps.*)) return error.ChangesLocktime;
    try putCount(allocator, ps, global_key.INPUT_COUNT, n + 1);
}

/// Constructor: appends an output. The PSBT's outputs-modifiable flag must be set. On an error the PSBT is unchanged.
pub fn addOutput(allocator: Allocator, ps: *Psbt, amount: i64, script: []const u8) ConstructError!void {
    if (ps.psbtVersion() != 2) return error.NotPsbtV2;
    if ((txModifiable(ps.*) orelse 0) & modifiable_outputs == 0) return error.OutputsNotModifiable;
    const n = ps.outputs.len;
    ps.outputs = try allocator.realloc(ps.outputs, n + 1);
    ps.outputs[n] = .{ .records = &.{} };
    errdefer shrinkOutputs(allocator, ps, n);
    var le: [8]u8 = undefined;
    std.mem.writeInt(i64, &le, amount, .little);
    try update.putOutput(allocator, ps, n, output_key.AMOUNT, &.{}, &le);
    try update.putOutput(allocator, ps, n, output_key.SCRIPT, &.{}, script);
    try putCount(allocator, ps, global_key.OUTPUT_COUNT, n + 1);
}
