// SPDX-License-Identifier: MIT
//! BIP174's **Creator** and **Updater** roles, the hash-preimage input fields
//! (`0x0a`-`0x0d`) and Base64 text I/O.
//!
//! ## Creator
//!
//! `fromUnsignedTx` wraps an unsigned `bitcointx.Transaction` (empty
//! scriptSigs, no witness) into a PSBT with one empty input map per input and
//! one empty output map per output -- BIP174 §Creator. A transaction with no
//! inputs is refused (`error.NoInputs`): its legacy serialization is
//! indistinguishable from the BIP144 marker (see SPEC), so the result could
//! not be parsed back.
//!
//! ## Updater
//!
//! The `set*` functions add one field to the global map or to input/output
//! `index`, replacing a field of the same key. Each builds the record, runs
//! it through the same structural check `parse` applies
//! (`psbt.validateInputRecord` & co.) and only then stores it, so a PSBT
//! assembled here always parses back; records are inserted in BIP174 key
//! order (see `Map.put`), which reproduces BIP174's own Updater example
//! byte for byte. Nothing here signs or interprets scripts.
//!
//! `fromUnsignedTx` and the setters allocate the unsigned-tx bytes, value
//! buffers and key-data copies from `allocator`. Like `finalize`, they assume
//! it is **arena-like**: `Psbt.deinit` frees only each map's `records` array,
//! so these buffers (and a replaced field's old value) are not tracked
//! individually and a general-purpose allocator will leak them. Create,
//! update, serialize inside one arena. Slices passed in are copied; the
//! caller keeps ownership of its own.
//!
//! ## Base64
//!
//! `fromBase64` returns an `OwnedPsbt`: the decoded bytes (which the parsed
//! `Psbt` borrows, see `root.zig`) travel with it. Leading and trailing ASCII
//! whitespace is ignored; standard alphabet with padding, nothing else.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const ripemd160 = @import("ripemd160");
const psbt = @import("root.zig");

const Record = psbt.Record;
const Map = psbt.Map;
const Psbt = psbt.Psbt;
const input_key = psbt.input_key;
const output_key = psbt.output_key;

// ── errors ──────────────────────────────────────────────────────────────

pub const CreateError = Allocator.Error || error{
    /// The transaction has no inputs (see the module doc comment).
    NoInputs,
    /// Some input has a non-empty scriptSig; the unsigned tx must have none.
    UnsignedTxHasScriptSig,
    /// The transaction carries witness data; the unsigned tx must not.
    UnsignedTxHasWitness,
};

pub const UpdateError = psbt.RecordError || bitcointx.tx.DeserializeError || Allocator.Error || error{
    InputIndexOutOfRange,
    OutputIndexOutOfRange,
    /// `setInputNonWitnessUtxo`: the transaction does not hash to the txid the
    /// input spends (Core refuses the same: "Non-witness UTXO does not match
    /// outpoint hash").
    UtxoOutpointMismatch,
    /// `setInputNonWitnessUtxo`: the transaction has no output at the index
    /// the input spends.
    PrevoutIndexOutOfRange,
};

// ── Creator ─────────────────────────────────────────────────────────────

/// BIP174 Creator: a PSBT for `tx`, with empty input and output maps. See the
/// module doc comment for the allocator contract.
pub fn fromUnsignedTx(allocator: Allocator, tx: bitcointx.Transaction) CreateError!Psbt {
    if (tx.vin.len == 0) return error.NoInputs;
    if (tx.has_witness or tx.witness.len != 0) return error.UnsignedTxHasWitness;
    for (tx.vin) |vin| {
        if (vin.script_sig.len != 0) return error.UnsignedTxHasScriptSig;
    }
    const utx = try bitcointx.serializeLegacy(allocator, tx);
    errdefer allocator.free(utx);

    const global_records = try allocator.alloc(Record, 1);
    errdefer allocator.free(global_records);
    global_records[0] = .{ .keytype = psbt.global_key.UNSIGNED_TX, .keydata = &.{}, .value = utx };

    const inputs = try allocator.alloc(Map, tx.vin.len);
    errdefer allocator.free(inputs);
    for (inputs) |*m| m.* = .{ .records = &.{} };
    const outputs = try allocator.alloc(Map, tx.vout.len);
    errdefer allocator.free(outputs);
    for (outputs) |*m| m.* = .{ .records = &.{} };

    return .{ .global = .{ .records = global_records }, .inputs = inputs, .outputs = outputs };
}

// ── record plumbing (also used by bip371.zig) ───────────────────────────

fn putOwned(
    allocator: Allocator,
    map: *Map,
    comptime validate: fn (Record) psbt.RecordError!void,
    keytype: u64,
    keydata: []const u8,
    value: []const u8,
) (psbt.RecordError || Allocator.Error)!void {
    const kd = try allocator.dupe(u8, keydata);
    errdefer allocator.free(kd);
    const rec: Record = .{ .keytype = keytype, .keydata = kd, .value = value };
    try validate(rec);
    try map.put(allocator, rec);
}

fn putCopy(
    allocator: Allocator,
    map: *Map,
    comptime validate: fn (Record) psbt.RecordError!void,
    keytype: u64,
    keydata: []const u8,
    value: []const u8,
) (psbt.RecordError || Allocator.Error)!void {
    const v = try allocator.dupe(u8, value);
    errdefer allocator.free(v);
    try putOwned(allocator, map, validate, keytype, keydata, v);
}

fn inputMap(ps: *Psbt, index: usize) error{InputIndexOutOfRange}!*Map {
    if (index >= ps.inputs.len) return error.InputIndexOutOfRange;
    return &ps.inputs[index];
}

fn outputMap(ps: *Psbt, index: usize) error{OutputIndexOutOfRange}!*Map {
    if (index >= ps.outputs.len) return error.OutputIndexOutOfRange;
    return &ps.outputs[index];
}

/// Stores a copy of (`keydata`, `value`) in input `index`.
pub fn putInput(allocator: Allocator, ps: *Psbt, index: usize, keytype: u64, keydata: []const u8, value: []const u8) UpdateError!void {
    try putCopy(allocator, try inputMap(ps, index), psbt.validateInputRecord, keytype, keydata, value);
}

/// As `putInput`, but takes ownership of `value` (allocated from `allocator`);
/// on error the caller still owns it.
pub fn putInputOwned(allocator: Allocator, ps: *Psbt, index: usize, keytype: u64, keydata: []const u8, value: []const u8) UpdateError!void {
    try putOwned(allocator, try inputMap(ps, index), psbt.validateInputRecord, keytype, keydata, value);
}

pub fn putOutput(allocator: Allocator, ps: *Psbt, index: usize, keytype: u64, keydata: []const u8, value: []const u8) UpdateError!void {
    try putCopy(allocator, try outputMap(ps, index), psbt.validateOutputRecord, keytype, keydata, value);
}

pub fn putOutputOwned(allocator: Allocator, ps: *Psbt, index: usize, keytype: u64, keydata: []const u8, value: []const u8) UpdateError!void {
    try putOwned(allocator, try outputMap(ps, index), psbt.validateOutputRecord, keytype, keydata, value);
}

fn bip32Value(allocator: Allocator, fingerprint: [4]u8, path: []const u32) Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, 4 + 4 * path.len);
    @memcpy(out[0..4], &fingerprint);
    for (path, 0..) |step, i| std.mem.writeInt(u32, out[4 + 4 * i ..][0..4], step, .little);
    return out;
}

// ── Updater: global ─────────────────────────────────────────────────────

/// Adds a `PSBT_GLOBAL_XPUB`: the 78-byte serialized extended public key, the
/// master key fingerprint and the derivation path (hardened steps carry bit 31).
pub fn setGlobalXpub(allocator: Allocator, ps: *Psbt, xpub: *const [78]u8, fingerprint: [4]u8, path: []const u32) UpdateError!void {
    const value = try bip32Value(allocator, fingerprint, path);
    errdefer allocator.free(value);
    try putOwned(allocator, &ps.global, psbt.validateGlobalRecord, psbt.global_key.XPUB, xpub, value);
}

// ── Updater: inputs ─────────────────────────────────────────────────────

/// `PSBT_IN_NON_WITNESS_UTXO`: the full previous transaction, serialized
/// without witness data as Core does. Checked against the input first: it must
/// hash to the txid the input spends and have an output at the spent index.
pub fn setInputNonWitnessUtxo(allocator: Allocator, ps: *Psbt, index: usize, prev_tx: bitcointx.Transaction) UpdateError!void {
    const map = try inputMap(ps, index);
    var utx = try ps.unsignedTx(allocator);
    defer utx.deinit(allocator);
    if (index >= utx.vin.len) return error.InputIndexOutOfRange;
    const prevout = utx.vin[index].prevout;
    const id = try prev_tx.txid(allocator);
    if (!std.mem.eql(u8, &id, &prevout.txid)) return error.UtxoOutpointMismatch;
    if (prevout.vout >= prev_tx.vout.len) return error.PrevoutIndexOutOfRange;
    const bytes = try bitcointx.serializeLegacy(allocator, prev_tx);
    errdefer allocator.free(bytes);
    try putOwned(allocator, map, psbt.validateInputRecord, input_key.NON_WITNESS_UTXO, &.{}, bytes);
}

/// `PSBT_IN_WITNESS_UTXO`: the spent output (`<i64 LE amount> <script>`).
/// Nothing ties it to the input -- see `finalize`'s UTXO binding notes.
pub fn setInputWitnessUtxo(allocator: Allocator, ps: *Psbt, index: usize, utxo: bitcointx.TxOut) UpdateError!void {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var amount: [8]u8 = undefined;
    std.mem.writeInt(i64, &amount, utxo.value, .little);
    try buf.appendSlice(allocator, &amount);
    try bitcointx.tx.appendCompactSize(&buf, allocator, utxo.script_pubkey.len);
    try buf.appendSlice(allocator, utxo.script_pubkey);
    const value = try buf.toOwnedSlice(allocator);
    errdefer allocator.free(value);
    try putInputOwned(allocator, ps, index, input_key.WITNESS_UTXO, &.{}, value);
}

/// `PSBT_IN_PARTIAL_SIG`: `sig` (DER plus sighash byte) by the 33/65-byte `pubkey`.
pub fn setInputPartialSig(allocator: Allocator, ps: *Psbt, index: usize, pubkey: []const u8, sig: []const u8) UpdateError!void {
    try putInput(allocator, ps, index, input_key.PARTIAL_SIG, pubkey, sig);
}

pub fn setInputSighashType(allocator: Allocator, ps: *Psbt, index: usize, sighash: u32) UpdateError!void {
    var le: [4]u8 = undefined;
    std.mem.writeInt(u32, &le, sighash, .little);
    try putInput(allocator, ps, index, input_key.SIGHASH_TYPE, &.{}, &le);
}

pub fn setInputRedeemScript(allocator: Allocator, ps: *Psbt, index: usize, script: []const u8) UpdateError!void {
    try putInput(allocator, ps, index, input_key.REDEEM_SCRIPT, &.{}, script);
}

pub fn setInputWitnessScript(allocator: Allocator, ps: *Psbt, index: usize, script: []const u8) UpdateError!void {
    try putInput(allocator, ps, index, input_key.WITNESS_SCRIPT, &.{}, script);
}

/// `PSBT_IN_BIP32_DERIVATION` for the 33/65-byte `pubkey`.
pub fn setInputBip32Derivation(allocator: Allocator, ps: *Psbt, index: usize, pubkey: []const u8, fingerprint: [4]u8, path: []const u32) UpdateError!void {
    const value = try bip32Value(allocator, fingerprint, path);
    errdefer allocator.free(value);
    try putInputOwned(allocator, ps, index, input_key.BIP32_DERIVATION, pubkey, value);
}

// ── Updater: outputs ────────────────────────────────────────────────────

pub fn setOutputRedeemScript(allocator: Allocator, ps: *Psbt, index: usize, script: []const u8) UpdateError!void {
    try putOutput(allocator, ps, index, output_key.REDEEM_SCRIPT, &.{}, script);
}

pub fn setOutputWitnessScript(allocator: Allocator, ps: *Psbt, index: usize, script: []const u8) UpdateError!void {
    try putOutput(allocator, ps, index, output_key.WITNESS_SCRIPT, &.{}, script);
}

/// `PSBT_OUT_BIP32_DERIVATION` for the 33/65-byte `pubkey`.
pub fn setOutputBip32Derivation(allocator: Allocator, ps: *Psbt, index: usize, pubkey: []const u8, fingerprint: [4]u8, path: []const u32) UpdateError!void {
    const value = try bip32Value(allocator, fingerprint, path);
    errdefer allocator.free(value);
    try putOutputOwned(allocator, ps, index, output_key.BIP32_DERIVATION, pubkey, value);
}

// ── hash preimages (PSBT_IN_RIPEMD160 / SHA256 / HASH160 / HASH256) ─────

/// The four BIP174 preimage fields. The keydata is the hash, the value its
/// preimage; the key type says which function the hash is.
pub const PreimageKind = enum(u64) {
    ripemd160 = input_key.RIPEMD160,
    sha256 = input_key.SHA256,
    hash160 = input_key.HASH160,
    hash256 = input_key.HASH256,

    pub fn keytype(self: PreimageKind) u64 {
        return @backingInt(self);
    }

    /// 20 for `ripemd160`/`hash160`, 32 for `sha256`/`hash256`.
    pub fn hashLen(self: PreimageKind) usize {
        return switch (self) {
            .ripemd160, .hash160 => 20,
            .sha256, .hash256 => 32,
        };
    }

    fn fromKeytype(kt: u64) ?PreimageKind {
        return std.enums.fromInt(PreimageKind, kt);
    }
};

/// `hash` as `kind` hashes `preimage`: `RIPEMD160(p)`, `SHA256(p)`,
/// `RIPEMD160(SHA256(p))` or `SHA256(SHA256(p))`. `hash` of the wrong length
/// is simply not a match.
pub fn preimageMatches(kind: PreimageKind, hash: []const u8, preimage: []const u8) bool {
    if (hash.len != kind.hashLen()) return false;
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var out: [32]u8 = undefined;
    switch (kind) {
        .ripemd160 => ripemd160.Ripemd160.hash(preimage, out[0..20], .{}),
        .sha256 => Sha256.hash(preimage, &out, .{}),
        .hash160 => ripemd160.hash160(preimage, out[0..20]),
        .hash256 => {
            Sha256.hash(preimage, &out, .{});
            Sha256.hash(&out, &out, .{});
        },
    }
    return std.mem.eql(u8, hash, out[0..kind.hashLen()]);
}

pub const Preimage = struct {
    kind: PreimageKind,
    hash: []const u8,
    preimage: []const u8,
};

/// Iterator over the preimage records of an input map, in map order.
/// Records whose hash has the wrong size (impossible after `parse`) are skipped.
pub const Preimages = struct {
    records: []const Record,
    index: usize = 0,

    pub fn next(self: *Preimages) ?Preimage {
        while (self.index < self.records.len) {
            const r = self.records[self.index];
            self.index += 1;
            const kind = PreimageKind.fromKeytype(r.keytype) orelse continue;
            if (r.keydata.len != kind.hashLen()) continue;
            return .{ .kind = kind, .hash = r.keydata, .preimage = r.value };
        }
        return null;
    }
};

pub fn inputPreimages(m: Map) Preimages {
    return .{ .records = m.records };
}

/// The preimage stored for `hash` under `kind`, or `null`. The stored value is
/// returned as is -- use `preimageMatches` to check it really hashes to `hash`.
pub fn inputPreimage(m: Map, kind: PreimageKind, hash: []const u8) ?[]const u8 {
    const r = m.findKeyed(kind.keytype(), hash) orelse return null;
    return r.value;
}

/// Adds the preimage field for `preimage` under `kind`; the hash (the key) is
/// computed here, so the pair always matches.
pub fn setInputPreimage(allocator: Allocator, ps: *Psbt, index: usize, kind: PreimageKind, preimage: []const u8) UpdateError!void {
    var hash: [32]u8 = undefined;
    const Sha256 = std.crypto.hash.sha2.Sha256;
    switch (kind) {
        .ripemd160 => ripemd160.Ripemd160.hash(preimage, hash[0..20], .{}),
        .sha256 => Sha256.hash(preimage, &hash, .{}),
        .hash160 => ripemd160.hash160(preimage, hash[0..20]),
        .hash256 => {
            Sha256.hash(preimage, &hash, .{});
            Sha256.hash(&hash, &hash, .{});
        },
    }
    try putInput(allocator, ps, index, kind.keytype(), hash[0..kind.hashLen()], preimage);
}

// ── Base64 ──────────────────────────────────────────────────────────────

/// A parsed PSBT together with the buffer it borrows from.
pub const OwnedPsbt = struct {
    psbt: Psbt,
    bytes: []u8,

    pub fn deinit(self: *OwnedPsbt, allocator: Allocator) void {
        self.psbt.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const Base64Error = psbt.ParseError || std.base64.Error;

/// Decodes a Base64 PSBT (the form wallets and `bitcoin-cli` exchange) and
/// parses it. The decoded buffer is at most 3/4 of `text.len`; nothing is
/// allocated before the text has been checked to be well-formed Base64.
pub fn fromBase64(allocator: Allocator, text: []const u8) Base64Error!OwnedPsbt {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    const decoder = std.base64.standard.Decoder;
    const n = try decoder.calcSizeForSlice(trimmed);
    const bytes = try allocator.alloc(u8, n);
    errdefer allocator.free(bytes);
    try decoder.decode(bytes, trimmed);
    const parsed = try psbt.parse(allocator, bytes);
    return .{ .psbt = parsed, .bytes = bytes };
}

/// `serialize`, then Base64 (standard alphabet, padded). Caller frees.
pub fn toBase64(allocator: Allocator, ps: Psbt) Allocator.Error![]u8 {
    const raw = try psbt.serialize(allocator, ps);
    defer allocator.free(raw);
    const encoder = std.base64.standard.Encoder;
    const out = try allocator.alloc(u8, encoder.calcSize(raw.len));
    _ = encoder.encode(out, raw);
    return out;
}
