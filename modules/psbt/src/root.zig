// SPDX-License-Identifier: MIT
//! `psbt` — BIP174 Partially Signed Bitcoin Transaction (PSBT) v0: binary
//! (de)serialization plus the Combiner role. Parses untrusted PSBT bytes
//! fail-closed; see SPEC.md for the full threat model and scope cuts.
//!
//! ## Format (BIP174)
//!
//! `<psbt> := <magic> <global-map> <input-map>* <output-map>*` where
//! `<magic> = 0x70 0x73 0x62 0x74 0xFF` and each `<map>` is a sequence of
//! `<keylen><keytype+keydata><valuelen><valuedata>` records terminated by a
//! `0x00` byte. `<keytype>` is itself a minimally-encoded CompactSize
//! prefix of the key bytes; `<keydata>` is whatever follows it within the
//! key. The number of input/output maps is exactly the unsigned
//! transaction's `vin`/`vout` count (BIP174 gives no explicit count field
//! for either — the unsigned tx is the sole source of truth).
//!
//! ## Ownership / zero-copy
//!
//! Mirrors `bitcointx.tx`'s model: every `Record.keydata`/`.value` is a
//! **borrowed** slice into the buffer `parse` was called with (never
//! copied) — `bytes` must outlive the returned `Psbt`. `Map.deinit` frees
//! only the `records` array itself. `Psbt.deinit` frees the per-input/
//! per-output `Map` arrays too. Typed accessors that decode a nested
//! Bitcoin transaction (`Psbt.unsignedTx`, `inputNonWitnessUtxo`) return an
//! **owned** `bitcointx.Transaction` the caller must `.deinit()` — its own
//! byte content still borrows from the same original PSBT buffer.
//!
//! ## Known vs. unknown key types
//!
//! Known key types (see `global_key`/`input_key`/`output_key`) get
//! structural validation at parse time (the BIP's "no key data" /
//! pubkey-length / fixed-value-length rules — this is the security core,
//! see SPEC.md) plus a typed decode helper. Every other key type —
//! including `PROPRIETARY = 0xFC` at every scope — is opaque passthrough:
//! it lands in `Map.records` untouched and is reserialized byte-for-byte,
//! per BIP174's "must pass those key-value pairs through" requirement.
//!
//! ## Roles implemented
//!
//! `parse`/`serialize` (Creator/Updater's wire format), `combine`
//! (Combiner: union of key-value pairs, BIP174-example lexicographic
//! ordering, first-PSBT-wins on conflicting values), and — now that a
//! Script interpreter exists (`bitcoinscript`) — `finalize` (Input
//! Finalizer) and `extract` (Transaction Extractor), both in
//! `finalize.zig`: `finalize` assembles `FINAL_SCRIPTSIG`/
//! `FINAL_SCRIPTWITNESS` for the standard spend types, verifying every
//! candidate through `bitcoinscript.verifyScript` before accepting it and
//! clearing the now-consumed fields per BIP174; `extract` splices finalized
//! inputs into a network-ready `bitcointx.Transaction`. The **Signer** role
//! is still NOT implemented — it needs private-key custody and signing
//! policy this module has no opinion about; `PARTIAL_SIG`/`TAP_KEY_SIG`
//! records are expected to already be present by the time `finalize` runs.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant, // no shared/global state; every call is over caller-owned values
    .model_after = "BIP174 (Partially Signed Bitcoin Transaction Format v0, bitcoin/bips)",
    .deps = .{ "bitcointx", "bitcoinscript" },
};

// ── magic ────────────────────────────────────────────────────────────────

pub const magic = [_]u8{ 0x70, 0x73, 0x62, 0x74, 0xff };

// ── key type registries ─────────────────────────────────────────────────

pub const global_key = struct {
    pub const UNSIGNED_TX: u64 = 0x00;
    pub const XPUB: u64 = 0x01;
    pub const VERSION: u64 = 0xfb;
    pub const PROPRIETARY: u64 = 0xfc;
};

pub const input_key = struct {
    pub const NON_WITNESS_UTXO: u64 = 0x00;
    pub const WITNESS_UTXO: u64 = 0x01;
    pub const PARTIAL_SIG: u64 = 0x02;
    pub const SIGHASH_TYPE: u64 = 0x03;
    pub const REDEEM_SCRIPT: u64 = 0x04;
    pub const WITNESS_SCRIPT: u64 = 0x05;
    pub const BIP32_DERIVATION: u64 = 0x06;
    pub const FINAL_SCRIPTSIG: u64 = 0x07;
    pub const FINAL_SCRIPTWITNESS: u64 = 0x08;
    pub const PROPRIETARY: u64 = 0xfc;
    /// BIP371's taproot key-path signature (not part of BIP174 v0 proper —
    /// added here so `finalize.zig` can assemble a P2TR key-path witness;
    /// see its module doc comment). Value is the 64-byte BIP340 Schnorr
    /// signature, or 65 bytes with an explicit trailing sighash-type byte.
    pub const TAP_KEY_SIG: u64 = 0x13;
};

pub const output_key = struct {
    pub const REDEEM_SCRIPT: u64 = 0x00;
    pub const WITNESS_SCRIPT: u64 = 0x01;
    pub const BIP32_DERIVATION: u64 = 0x02;
    pub const PROPRIETARY: u64 = 0xfc;
};

// ── record / map model ──────────────────────────────────────────────────

/// One key-value record. `keytype` is the decoded (minimally-encoded)
/// CompactSize prefix of the key; `keydata` is whatever key bytes follow
/// it. Both `keydata` and `value` are borrowed (see module doc comment).
pub const Record = struct {
    keytype: u64,
    keydata: []const u8,
    value: []const u8,
};

/// One global/input/output map: records in **original wire order**
/// (preserved, not canonicalized — this is what makes `serialize` produce
/// a byte-exact round-trip of whatever order a real-world encoder used;
/// `combine` is the one place that re-sorts, matching BIP174's own
/// worked Combiner example).
pub const Map = struct {
    records: []Record,

    pub fn deinit(self: *Map, allocator: Allocator) void {
        allocator.free(self.records);
        self.* = undefined;
    }

    /// The first record of `keytype` with empty `keydata` — for the
    /// "no key data" singleton fields (UNSIGNED_TX, VERSION, WITNESS_UTXO,
    /// SIGHASH_TYPE, REDEEM_SCRIPT, WITNESS_SCRIPT, FINAL_SCRIPTSIG,
    /// FINAL_SCRIPTWITNESS at whichever scope they apply).
    pub fn find(self: Map, keytype: u64) ?Record {
        for (self.records) |r| {
            if (r.keytype == keytype and r.keydata.len == 0) return r;
        }
        return null;
    }

    /// The record of `keytype` whose `keydata` equals `keydata` exactly —
    /// for fields keyed by a pubkey (PARTIAL_SIG, BIP32_DERIVATION) or an
    /// xpub (global XPUB).
    pub fn findKeyed(self: Map, keytype: u64, keydata: []const u8) ?Record {
        for (self.records) |r| {
            if (r.keytype == keytype and std.mem.eql(u8, r.keydata, keydata)) return r;
        }
        return null;
    }
};

pub const Psbt = struct {
    global: Map,
    inputs: []Map,
    outputs: []Map,

    pub fn deinit(self: *Psbt, allocator: Allocator) void {
        self.global.deinit(allocator);
        for (self.inputs) |*m| m.deinit(allocator);
        allocator.free(self.inputs);
        for (self.outputs) |*m| m.deinit(allocator);
        allocator.free(self.outputs);
        self.* = undefined;
    }

    /// Decodes the mandatory `PSBT_GLOBAL_UNSIGNED_TX` value. Caller owns
    /// the returned `Transaction` (`.deinit`); its byte content still
    /// borrows from the buffer `parse` was called with. Every `Psbt` this
    /// module hands back (from `parse` or `combine`) is guaranteed to have
    /// this record — constructing a `Psbt` any other way and calling this
    /// is a caller-construction contract, not untrusted-input territory
    /// (mirrors `bitcointx.serializeSegwit`'s witness-length assert).
    pub fn unsignedTx(self: Psbt, allocator: Allocator) bitcointx.tx.DeserializeError!bitcointx.Transaction {
        const r = self.global.find(global_key.UNSIGNED_TX) orelse unreachable;
        return bitcointx.deserialize(allocator, r.value);
    }

    /// `PSBT_GLOBAL_VERSION`, or `null` if omitted (BIP174: version 0).
    /// `parse` already rejects a nonzero value with `error.UnsupportedPsbtVersion`
    /// (BIP174 §"Version 0"), so this always returns `0` when non-null.
    pub fn version(self: Psbt) ?u32 {
        const r = self.global.find(global_key.VERSION) orelse return null;
        return std.mem.readInt(u32, r.value[0..4], .little);
    }
};

// ── BIP32 derivation value view (shared by XPUB / BIP32_DERIVATION) ────

/// `<4-byte fingerprint> <32-bit LE uint path element>*` — the value shape
/// shared by `PSBT_GLOBAL_XPUB`, `PSBT_IN_BIP32_DERIVATION`, and
/// `PSBT_OUT_BIP32_DERIVATION`. `parse` already validated `value.len >= 4`
/// and `(value.len - 4) % 4 == 0` for every record this view is built
/// from, so `at` never goes out of bounds.
pub const Bip32Path = struct {
    fingerprint: [4]u8,
    path_bytes: []const u8,

    pub fn len(self: Bip32Path) usize {
        return self.path_bytes.len / 4;
    }

    pub fn at(self: Bip32Path, i: usize) u32 {
        return std.mem.readInt(u32, self.path_bytes[i * 4 ..][0..4], .little);
    }
};

fn decodeBip32Value(value: []const u8) Bip32Path {
    var fp: [4]u8 = undefined;
    @memcpy(&fp, value[0..4]);
    return .{ .fingerprint = fp, .path_bytes = value[4..] };
}

/// Derivation info for `pubkey` under `PSBT_IN_BIP32_DERIVATION`.
pub fn inputBip32Derivation(m: Map, pubkey: []const u8) ?Bip32Path {
    const r = m.findKeyed(input_key.BIP32_DERIVATION, pubkey) orelse return null;
    return decodeBip32Value(r.value);
}

/// Derivation info for `pubkey` under `PSBT_OUT_BIP32_DERIVATION`.
pub fn outputBip32Derivation(m: Map, pubkey: []const u8) ?Bip32Path {
    const r = m.findKeyed(output_key.BIP32_DERIVATION, pubkey) orelse return null;
    return decodeBip32Value(r.value);
}

/// Derivation info for `xpub` (78-byte serialized extended public key)
/// under `PSBT_GLOBAL_XPUB`.
pub fn globalXpubDerivation(m: Map, xpub: []const u8) ?Bip32Path {
    const r = m.findKeyed(global_key.XPUB, xpub) orelse return null;
    return decodeBip32Value(r.value);
}

/// `PSBT_IN_SIGHASH_TYPE`, or `null` if omitted.
pub fn inputSighashType(m: Map) ?u32 {
    const r = m.find(input_key.SIGHASH_TYPE) orelse return null;
    return std.mem.readInt(u32, r.value[0..4], .little);
}

/// `PSBT_IN_TAP_KEY_SIG` (BIP371), or `null` if omitted. The raw 64/65-byte
/// value, unvalidated here -- `finalize.zig` is the only caller, and shape/
/// curve validity is `bitcoinscript.verifyScript`'s job to fail closed on,
/// not this accessor's.
pub fn inputTapKeySig(m: Map) ?[]const u8 {
    const r = m.find(input_key.TAP_KEY_SIG) orelse return null;
    return r.value;
}

/// `<64-bit LE int amount> <compact size scriptPubKeylen> <bytes scriptPubKey>`
/// decode for `PSBT_IN_WITNESS_UTXO`. Unlike the fields `parse` validates
/// structurally up front, this value's *shape* is only checked when this
/// accessor is actually called (see SPEC.md) — still always a typed
/// error, never a panic/OOB read, on malformed bytes.
pub const WitnessUtxoError = bitcointx.tx.CompactSizeError || error{TrailingBytes};

fn decodeWitnessUtxoValue(value: []const u8) WitnessUtxoError!bitcointx.TxOut {
    if (value.len < 8) return error.Truncated;
    const amount = std.mem.readInt(i64, value[0..8], .little);
    const r = try bitcointx.decodeCompactSize(value[8..]);
    const script_start = 8 + r.consumed;
    if (r.value > value.len - script_start) return error.Truncated;
    const script_len: usize = @intCast(r.value);
    if (script_start + script_len != value.len) return error.TrailingBytes;
    return .{ .value = amount, .script_pubkey = value[script_start .. script_start + script_len] };
}

/// `PSBT_IN_WITNESS_UTXO`, or `null` if omitted.
pub fn inputWitnessUtxo(m: Map) WitnessUtxoError!?bitcointx.TxOut {
    const r = m.find(input_key.WITNESS_UTXO) orelse return null;
    return try decodeWitnessUtxoValue(r.value);
}

/// `PSBT_IN_NON_WITNESS_UTXO`, or `null` if omitted. Caller owns the
/// returned `Transaction` (`.deinit`).
pub fn inputNonWitnessUtxo(m: Map, allocator: Allocator) bitcointx.tx.DeserializeError!?bitcointx.Transaction {
    const r = m.find(input_key.NON_WITNESS_UTXO) orelse return null;
    return try bitcointx.deserialize(allocator, r.value);
}

// ── low-level record/map codec ──────────────────────────────────────────

fn readBytes(bytes: []const u8, offset: *usize, n: u64) bitcointx.tx.CompactSizeError![]const u8 {
    const remaining: u64 = bytes.len - offset.*;
    if (n > remaining) return error.Truncated;
    const nu: usize = @intCast(n);
    const s = bytes[offset.* .. offset.* + nu];
    offset.* += nu;
    return s;
}

fn readCompactSizeAdvance(bytes: []const u8, offset: *usize) bitcointx.tx.CompactSizeError!u64 {
    const r = try bitcointx.decodeCompactSize(bytes[offset.*..]);
    offset.* += r.consumed;
    return r.value;
}

pub const ParseError = bitcointx.tx.DeserializeError || error{
    /// The first 5 bytes are not `0x70 0x73 0x62 0x74 0xff`.
    BadMagic,
    /// The same raw key (keytype + keydata) appears twice in one map.
    DuplicateKey,
    /// The global map has no `PSBT_GLOBAL_UNSIGNED_TX` record.
    MissingUnsignedTx,
    /// The unsigned tx is BIP144 witness-serialized; BIP174 requires the
    /// old (non-witness) serialization here.
    UnsignedTxNotLegacySerialization,
    /// The unsigned tx has a non-empty scriptSig on some input; BIP174
    /// requires every input's scriptSig to be empty.
    UnsignedTxHasScriptSig,
    /// A "no key data" field (see `Map.find`'s doc comment) has extra
    /// bytes in its key beyond the type byte.
    UnexpectedKeyData,
    /// A pubkey-keyed field's keydata is neither 33 (compressed) nor 65
    /// (uncompressed) bytes.
    InvalidPubkeyLength,
    /// A fixed-shape value (VERSION/SIGHASH_TYPE: exactly 4 bytes; XPUB/
    /// BIP32_DERIVATION: a 4-byte fingerprint plus a whole number of
    /// 4-byte path elements) doesn't match its required shape.
    InvalidFixedFieldLength,
    /// `PSBT_GLOBAL_VERSION` is present with a nonzero value. BIP174
    /// §"Version 0": "Version 0 PSBTs must either omit PSBT_GLOBAL_VERSION
    /// or include it and set it to 0." This module implements BIP174 v0
    /// only (BIP370/PSBTv2 is out of scope -- see SPEC.md), so a PSBT that
    /// declares a different version cannot be correctly interpreted and
    /// must be rejected rather than silently parsed as if it were v0.
    UnsupportedPsbtVersion,
};

fn parseMap(allocator: Allocator, bytes: []const u8, offset: *usize) ParseError!Map {
    var records: std.ArrayList(Record) = .empty;
    errdefer records.deinit(allocator);

    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);

    while (true) {
        const keylen = try readCompactSizeAdvance(bytes, offset);
        if (keylen == 0) break; // 0x00 map separator
        const key = try readBytes(bytes, offset, keylen);

        if (seen.contains(key)) return error.DuplicateKey;
        try seen.put(allocator, key, {});

        const vallen = try readCompactSizeAdvance(bytes, offset);
        const value = try readBytes(bytes, offset, vallen);

        const kt = try bitcointx.decodeCompactSize(key);
        try records.append(allocator, .{
            .keytype = kt.value,
            .keydata = key[kt.consumed..],
            .value = value,
        });
    }

    return .{ .records = try records.toOwnedSlice(allocator) };
}

fn requireNoKeyData(r: Record) ParseError!void {
    if (r.keydata.len != 0) return error.UnexpectedKeyData;
}

fn requirePubkeyLen(r: Record) ParseError!void {
    if (r.keydata.len != 33 and r.keydata.len != 65) return error.InvalidPubkeyLength;
}

fn requireFixedValueLen(r: Record, n: usize) ParseError!void {
    if (r.value.len != n) return error.InvalidFixedFieldLength;
}

fn requireBip32ValueShape(r: Record) ParseError!void {
    if (r.value.len < 4 or (r.value.len - 4) % 4 != 0) return error.InvalidFixedFieldLength;
}

fn validateGlobalMap(m: Map) ParseError!void {
    for (m.records) |r| {
        switch (r.keytype) {
            global_key.UNSIGNED_TX => try requireNoKeyData(r),
            global_key.VERSION => {
                try requireNoKeyData(r);
                try requireFixedValueLen(r, 4);
                // BIP174 §"Version 0": a present PSBT_GLOBAL_VERSION must be 0.
                if (std.mem.readInt(u32, r.value[0..4], .little) != 0) return error.UnsupportedPsbtVersion;
            },
            global_key.XPUB => try requireBip32ValueShape(r),
            else => {}, // unknown / PROPRIETARY -- opaque passthrough
        }
    }
}

fn validateInputMap(m: Map) ParseError!void {
    for (m.records) |r| {
        switch (r.keytype) {
            input_key.NON_WITNESS_UTXO,
            input_key.WITNESS_UTXO,
            input_key.REDEEM_SCRIPT,
            input_key.WITNESS_SCRIPT,
            input_key.FINAL_SCRIPTSIG,
            input_key.FINAL_SCRIPTWITNESS,
            => try requireNoKeyData(r),
            input_key.SIGHASH_TYPE => {
                try requireNoKeyData(r);
                try requireFixedValueLen(r, 4);
            },
            input_key.PARTIAL_SIG => try requirePubkeyLen(r),
            input_key.BIP32_DERIVATION => {
                try requirePubkeyLen(r);
                try requireBip32ValueShape(r);
            },
            else => {},
        }
    }
}

fn validateOutputMap(m: Map) ParseError!void {
    for (m.records) |r| {
        switch (r.keytype) {
            output_key.REDEEM_SCRIPT, output_key.WITNESS_SCRIPT => try requireNoKeyData(r),
            output_key.BIP32_DERIVATION => {
                try requirePubkeyLen(r);
                try requireBip32ValueShape(r);
            },
            else => {},
        }
    }
}

/// Parses a whole PSBT buffer. Rejects on any structural or per-field
/// violation (see `ParseError`) — never panics on malformed/truncated/
/// adversarial bytes (see SPEC.md "Threat model").
pub fn parse(allocator: Allocator, bytes: []const u8) ParseError!Psbt {
    if (bytes.len < magic.len or !std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    var offset: usize = magic.len;

    var global = try parseMap(allocator, bytes, &offset);
    errdefer global.deinit(allocator);
    try validateGlobalMap(global);

    const utx_rec = global.find(global_key.UNSIGNED_TX) orelse return error.MissingUnsignedTx;
    // `bitcointx.deserialize` now refuses a BIP144-marked tx whose witness
    // stacks are all empty (`error.SuperfluousWitnessRecord`, wave-2 audit
    // finding `bitcointx` F3). An UNSIGNED tx's inputs never carry witness
    // data by definition (nothing has signed yet), so a witness-serialized
    // unsigned tx is EXACTLY that shape -- every occurrence of
    // `SuperfluousWitnessRecord` on this specific field means "should have
    // been legacy-serialized", the PSBT-level, BIP174-specific, officially
    // vectored `error.UnsignedTxNotLegacySerialization` this function
    // already raises below for the has_witness-but-nonempty case.
    // Translate it rather than pre-empting it with the generic tx-level
    // error, and rather than re-deriving the marker/flag ambiguity by
    // peeking at the raw bytes here: BIP174's own "0 inputs" vector shows
    // why that would be unsafe (a legacy 0-vin tx can coincidentally start
    // with the same two bytes as a marker+flag -- see `core_kat_test.zig`'s
    // `valid[5]` note), so only `bitcointx`'s own parser -- which resolves
    // the ambiguity by committing to the segwit path and running out of
    // bytes -- gets to decide.
    var utx = bitcointx.deserialize(allocator, utx_rec.value) catch |err| switch (err) {
        error.SuperfluousWitnessRecord => return error.UnsignedTxNotLegacySerialization,
        else => return err,
    };
    defer utx.deinit(allocator);
    for (utx.vin) |vin| {
        if (vin.script_sig.len != 0) return error.UnsignedTxHasScriptSig;
    }
    const n_in = utx.vin.len;
    const n_out = utx.vout.len;

    var inputs: std.ArrayList(Map) = .empty;
    errdefer {
        for (inputs.items) |*m| m.deinit(allocator);
        inputs.deinit(allocator);
    }
    {
        var i: usize = 0;
        while (i < n_in) : (i += 1) {
            var m = try parseMap(allocator, bytes, &offset);
            errdefer m.deinit(allocator);
            try validateInputMap(m);
            try inputs.append(allocator, m);
        }
    }

    var outputs: std.ArrayList(Map) = .empty;
    errdefer {
        for (outputs.items) |*m| m.deinit(allocator);
        outputs.deinit(allocator);
    }
    {
        var i: usize = 0;
        while (i < n_out) : (i += 1) {
            var m = try parseMap(allocator, bytes, &offset);
            errdefer m.deinit(allocator);
            try validateOutputMap(m);
            try outputs.append(allocator, m);
        }
    }

    if (offset != bytes.len) return error.TrailingBytes;

    return .{
        .global = global,
        .inputs = try inputs.toOwnedSlice(allocator),
        .outputs = try outputs.toOwnedSlice(allocator),
    };
}

// ── serialize ────────────────────────────────────────────────────────────

fn appendCompactSize(buf: *std.ArrayList(u8), allocator: Allocator, value: u64) Allocator.Error!void {
    var tmp: [9]u8 = undefined;
    const w = bitcointx.encodeCompactSize(value, &tmp) catch unreachable; // tmp always big enough
    try buf.appendSlice(allocator, w);
}

fn appendMap(buf: *std.ArrayList(u8), allocator: Allocator, m: Map) Allocator.Error!void {
    for (m.records) |r| {
        var kt_buf: [9]u8 = undefined;
        const kt_enc = bitcointx.encodeCompactSize(r.keytype, &kt_buf) catch unreachable;
        try appendCompactSize(buf, allocator, kt_enc.len + r.keydata.len);
        try buf.appendSlice(allocator, kt_enc);
        try buf.appendSlice(allocator, r.keydata);
        try appendCompactSize(buf, allocator, r.value.len);
        try buf.appendSlice(allocator, r.value);
    }
    try buf.append(allocator, 0x00);
}

/// Serializes `p` back to wire bytes. Records are emitted in each map's
/// stored order (see `Map`'s doc comment) — round-tripping a `parse`d PSBT
/// through `serialize` reproduces the original bytes exactly.
pub fn serialize(allocator: Allocator, p: Psbt) Allocator.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, &magic);
    try appendMap(&buf, allocator, p.global);
    for (p.inputs) |m| try appendMap(&buf, allocator, m);
    for (p.outputs) |m| try appendMap(&buf, allocator, m);
    return buf.toOwnedSlice(allocator);
}

// ── combine (Combiner role) ─────────────────────────────────────────────

pub const CombineError = Allocator.Error || error{
    /// The two PSBTs' `PSBT_GLOBAL_UNSIGNED_TX` values differ (BIP174: "A
    /// Combiner must not combine two different PSBTs") -- includes the
    /// degenerate case of a differing input/output map count.
    DifferentTransactions,
};

fn keysEqual(a: Record, b: Record) bool {
    return a.keytype == b.keytype and std.mem.eql(u8, a.keydata, b.keydata);
}

/// Hashes/compares a `Record` by its key only (`keytype`+`keydata`, matching
/// `keysEqual`) — lets `mergeMaps` dedup with a real hash set instead of an
/// O(n) `containsKey` scan per record of `b` (parseMap's `seen` does the same
/// job with a `StringHashMapUnmanaged` because it already has the raw
/// concatenated key bytes on hand; here the key is split across two fields,
/// so a small `Context` is the natural equivalent instead of allocating a
/// synthetic concatenated key just to reuse `StringHashMapUnmanaged`).
const RecordKeyContext = struct {
    pub fn hash(_: RecordKeyContext, r: Record) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&r.keytype));
        h.update(r.keydata);
        return h.final();
    }
    pub fn eql(_: RecordKeyContext, a: Record, b: Record) bool {
        return keysEqual(a, b);
    }
};

/// Byte-lexicographic order of the raw key (encoded keytype ++ keydata) —
/// matches BIP174's own worked Combiner example ("A combiner which orders
/// keys lexicographically"). CompactSize's width-by-value-range encoding
/// is such that no valid encoding is ever a proper byte-prefix of another
/// (single-byte types are all `< 0xfd`; wider forms are fixed-width per
/// width class), so comparing the encoded-type bytes first and falling
/// back to `keydata` on a tie is equivalent to comparing the full
/// concatenated key bytes lexicographically.
fn lessThanKey(_: void, a: Record, b: Record) bool {
    var abuf: [9]u8 = undefined;
    var bbuf: [9]u8 = undefined;
    const aenc = bitcointx.encodeCompactSize(a.keytype, &abuf) catch unreachable;
    const benc = bitcointx.encodeCompactSize(b.keytype, &bbuf) catch unreachable;
    const ord = std.mem.order(u8, aenc, benc);
    if (ord != .eq) return ord == .lt;
    return std.mem.lessThan(u8, a.keydata, b.keydata);
}

fn mergeMaps(allocator: Allocator, a: Map, b: Map) Allocator.Error!Map {
    var list: std.ArrayList(Record) = .empty;
    errdefer list.deinit(allocator);

    var seen: std.HashMapUnmanaged(Record, void, RecordKeyContext, std.hash_map.default_max_load_percentage) = .empty;
    defer seen.deinit(allocator);

    for (a.records) |r| {
        try list.append(allocator, r);
        try seen.put(allocator, r, {});
    }
    for (b.records) |r| {
        if (!seen.contains(r)) {
            try list.append(allocator, r);
            try seen.put(allocator, r, {});
        }
    }
    std.mem.sort(Record, list.items, {}, lessThanKey);
    return .{ .records = try list.toOwnedSlice(allocator) };
}

/// The Combiner role: merges `a` and `b` into one PSBT. Every key-value
/// pair from both is present in the result (BIP174: "must contain all of
/// the key-value pairs"), deduplicated by raw key (BIP174: "must remove
/// any duplicate key-value pairs"); on a genuine conflict (same key,
/// different value) `a`'s value wins -- BIP174 explicitly allows a
/// Combiner to "arbitrarily choose" here. Fails if `a`/`b` are not PSBTs
/// for the same transaction.
pub fn combine(allocator: Allocator, a: Psbt, b: Psbt) CombineError!Psbt {
    const a_tx = a.global.find(global_key.UNSIGNED_TX) orelse unreachable;
    const b_tx = b.global.find(global_key.UNSIGNED_TX) orelse unreachable;
    if (!std.mem.eql(u8, a_tx.value, b_tx.value)) return error.DifferentTransactions;
    if (a.inputs.len != b.inputs.len or a.outputs.len != b.outputs.len) return error.DifferentTransactions;

    var global = try mergeMaps(allocator, a.global, b.global);
    errdefer global.deinit(allocator);

    var inputs: std.ArrayList(Map) = .empty;
    errdefer {
        for (inputs.items) |*m| m.deinit(allocator);
        inputs.deinit(allocator);
    }
    {
        var i: usize = 0;
        while (i < a.inputs.len) : (i += 1) {
            try inputs.append(allocator, try mergeMaps(allocator, a.inputs[i], b.inputs[i]));
        }
    }

    var outputs: std.ArrayList(Map) = .empty;
    errdefer {
        for (outputs.items) |*m| m.deinit(allocator);
        outputs.deinit(allocator);
    }
    {
        var i: usize = 0;
        while (i < a.outputs.len) : (i += 1) {
            try outputs.append(allocator, try mergeMaps(allocator, a.outputs[i], b.outputs[i]));
        }
    }

    return .{
        .global = global,
        .inputs = try inputs.toOwnedSlice(allocator),
        .outputs = try outputs.toOwnedSlice(allocator),
    };
}

// ── finalize / extract (Input Finalizer + Transaction Extractor) ───────
//
// Implementation lives in `finalize.zig` (its own module doc comment has
// the full scope/allocator-contract/threat-model story); re-exported here
// so callers only need `@import("psbt")`.

const finalize_mod = @import("finalize.zig");
pub const InputFinalizeError = finalize_mod.InputFinalizeError;
pub const UtxoBindingError = finalize_mod.UtxoBindingError;
pub const FinalizeSetupError = finalize_mod.FinalizeSetupError;
pub const ExtractError = finalize_mod.ExtractError;
pub const WitnessStackError = finalize_mod.WitnessStackError;
pub const finalize = finalize_mod.finalize;
pub const extract = finalize_mod.extract;
pub const encodeWitnessStack = finalize_mod.encodeWitnessStack;
pub const decodeWitnessStack = finalize_mod.decodeWitnessStack;

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

// dark-tests aggregator (CONVENTIONS.md §6 step 3) -- a bare @import of a
// sibling file does not pull its tests into the test binary on its own.
test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = finalize_mod;
    _ = @import("finalize_test.zig");
    _ = @import("core_kat_vectors.zig");
    _ = @import("core_kat_test.zig");
    _ = @import("regtest_kat_test.zig");
}

test "meta.deps names bitcointx and bitcoinscript" {
    try testing.expectEqual(@as(usize, 2), meta.deps.len);
    try testing.expect(std.mem.eql(u8, meta.deps[0], "bitcointx"));
    try testing.expect(std.mem.eql(u8, meta.deps[1], "bitcoinscript"));
}

test "rejects a buffer shorter than the magic" {
    try testing.expectError(error.BadMagic, parse(testing.allocator, &.{ 0x70, 0x73 }));
}

test "rejects the wrong magic" {
    try testing.expectError(error.BadMagic, parse(testing.allocator, &.{ 0x70, 0x73, 0x62, 0x74, 0xfe }));
}

test "hostile: empty global map (no unsigned tx) fails closed with MissingUnsignedTx" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, &magic);
    try buf.append(testing.allocator, 0x00); // empty global map
    try testing.expectError(error.MissingUnsignedTx, parse(testing.allocator, buf.items));
}

test "hostile: truncated map (keylen with no key bytes following) fails closed, no panic" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, &magic);
    try buf.append(testing.allocator, 0x05); // keylen=5, but nothing follows
    try testing.expectError(error.Truncated, parse(testing.allocator, buf.items));
}

test "hostile: vallen exceeding remaining bytes fails closed, no panic" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, &magic);
    try buf.append(testing.allocator, 0x01); // keylen=1
    try buf.append(testing.allocator, 0x00); // key = UNSIGNED_TX (type only)
    try buf.append(testing.allocator, 0xff); // vallen = 9-byte CompactSize form...
    try buf.appendSlice(testing.allocator, &([_]u8{0xff} ** 8)); // ...claiming ~2^64 bytes
    try testing.expectError(error.Truncated, parse(testing.allocator, buf.items));
}

test "hostile: keylen of 0xff-class CompactSize with declared length far beyond buffer fails closed" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, &magic);
    try buf.append(testing.allocator, 0xfe); // keylen = 4-byte CompactSize form
    try buf.appendSlice(testing.allocator, &[_]u8{ 0xff, 0xff, 0xff, 0x7f }); // huge keylen
    try testing.expectError(error.Truncated, parse(testing.allocator, buf.items));
}

// ── fuzz: parse never panics on an arbitrary attacker-supplied PSBT ──────
//
// A PSBT is a file two wallets exchange directly over an untrusted
// channel (BIP174's whole reason to exist). Plain random bytes after the
// 5-byte magic would almost always die on the very first CompactSize
// keylen -- so this harness builds a STRUCTURALLY valid skeleton (a real
// legacy, no-witness, no-scriptSig unsigned tx via `bitcointx.
// serializeLegacy`, so `n_in`/`n_out` come out non-degenerate and the
// input/output map loops actually run) and only randomizes the part that
// matters for THIS module: each map's key-value records, with the keytype
// biased toward the real registries (`global_key`/`input_key`/
// `output_key`) and the value bytes biased toward both the exact required
// shape and arbitrary lengths -- this is what drives `validateGlobalMap`/
// `validateInputMap`/`validateOutputMap`'s per-keytype shape checks
// (`requirePubkeyLen`/`requireFixedValueLen`/`requireBip32ValueShape`)
// instead of bouncing off the map-level CompactSize truncation checks
// every time.
test "fuzz: parse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParse, .{});
}

fn appendFuzzRecord(list: *std.ArrayList(u8), allocator: Allocator, keytype: u64, keydata: []const u8, value: []const u8) !void {
    var keytype_buf: [9]u8 = undefined;
    const kt_enc = bitcointx.encodeCompactSize(keytype, &keytype_buf) catch unreachable;
    try appendCompactSize(list, allocator, kt_enc.len + keydata.len);
    try list.appendSlice(allocator, kt_enc);
    try list.appendSlice(allocator, keydata);
    try appendCompactSize(list, allocator, value.len);
    try list.appendSlice(allocator, value);
}

/// Appends `n` Smith-driven pseudo-random records to `list`, biased toward
/// `known_keytypes` and toward the value shapes each keytype's validator
/// actually checks (a 33-byte pubkey keydata, a 4-or-4k-byte BIP32/fixed
/// value) -- with fully random keytype/keydata/value lengths some of the
/// time, so both the "valid shape" and "wrong shape" branches get hit.
fn appendFuzzedRecords(
    list: *std.ArrayList(u8),
    allocator: Allocator,
    smith: *std.testing.Smith,
    known_keytypes: []const u64,
) !void {
    try appendFuzzedRecordsOpen(list, allocator, smith, known_keytypes);
    try list.append(allocator, 0x00); // map terminator
}

/// The same, without the terminating `0x00`, so a caller can append further
/// records of its own to the same map before closing it.
fn appendFuzzedRecordsOpen(
    list: *std.ArrayList(u8),
    allocator: Allocator,
    smith: *std.testing.Smith,
    known_keytypes: []const u64,
) !void {
    const n = smith.valueRangeAtMost(u8, 0, 5);
    var i: u8 = 0;
    while (i < n) : (i += 1) {
        const keytype: u64 = if (smith.value(bool))
            known_keytypes[smith.valueRangeAtMost(u8, 0, @intCast(known_keytypes.len - 1))]
        else
            smith.value(u16);

        var keydata_buf: [65]u8 = undefined;
        const keydata_len: usize = if (smith.value(bool))
            (if (smith.value(bool)) @as(usize, 33) else 65) // pubkey-shaped
        else
            smith.valueRangeAtMost(u8, 0, keydata_buf.len);
        smith.bytes(keydata_buf[0..keydata_len]);

        var value_buf: [80]u8 = undefined;
        const value_len: usize = if (smith.value(bool))
            4 * (1 + smith.valueRangeAtMost(u8, 0, 4)) // BIP32/fixed-field-shaped: 4, 8, 12, ...
        else
            smith.valueRangeAtMost(u8, 0, value_buf.len);
        smith.bytes(value_buf[0..value_len]);

        try appendFuzzRecord(list, allocator, keytype, keydata_buf[0..keydata_len], value_buf[0..value_len]);
    }
}

/// Appends a `FINAL_SCRIPTSIG` and/or a `FINAL_SCRIPTWITNESS` to the input map
/// currently being written.
///
/// W2 A3 (F4) recorded that `decodeWitnessStack` is documented as taking
/// untrusted input ("one `extract` is asked to process directly after
/// `parse`") yet was not reachable from this harness at all, and that
/// `finalize`/`extract` -- the two roles that run a Script interpreter over
/// attacker-chosen bytes -- had zero fuzz coverage. The obstacle was in the
/// generator, not in the budget: the input keytypes it drew from were
/// `NON_WITNESS_UTXO`/`WITNESS_UTXO`/`PARTIAL_SIG`/`SIGHASH_TYPE`/
/// `BIP32_DERIVATION` and nothing else, so no input ever carried a final
/// field, `extract` returned `InputNotFinalized` at the first input every
/// time, and the witness decoder behind it could not be entered however long
/// the fuzzer ran.
fn appendFinalRecords(list: *std.ArrayList(u8), allocator: Allocator, smith: *std.testing.Smith) !void {
    var script_buf: [64]u8 = undefined;
    smith.bytes(&script_buf);
    const script = script_buf[0..smith.valueRangeAtMost(u8, 0, script_buf.len)];

    const with_sig = smith.value(bool);
    if (with_sig) {
        try appendFuzzRecord(list, allocator, input_key.FINAL_SCRIPTSIG, &.{}, script);
    }
    if (!with_sig or smith.value(bool)) {
        // Half the time a well-formed witness-stack encoding, half the time
        // arbitrary octets: `decodeWitnessStack` has to survive both, and only
        // the first form gets past it into `extract`.
        if (smith.value(bool)) {
            const items = [_][]const u8{ script, script[0..@min(script.len, 8)] };
            const enc = try encodeWitnessStack(allocator, items[0..smith.valueRangeAtMost(u8, 0, 2)]);
            defer allocator.free(enc);
            try appendFuzzRecord(list, allocator, input_key.FINAL_SCRIPTWITNESS, &.{}, enc);
        } else {
            try appendFuzzRecord(list, allocator, input_key.FINAL_SCRIPTWITNESS, &.{}, script);
        }
    }
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;

    const n_in: usize = smith.valueRangeAtMost(u8, 0, 3);
    const n_out: usize = smith.valueRangeAtMost(u8, 0, 3);

    var vin_buf: [3]bitcointx.TxIn = undefined;
    for (vin_buf[0..n_in]) |*vin| {
        vin.* = .{ .prevout = .{ .txid = @splat(0), .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff };
    }
    var vout_buf: [3]bitcointx.TxOut = undefined;
    for (vout_buf[0..n_out]) |*vout| {
        vout.* = .{ .value = 0, .script_pubkey = &.{} };
    }
    const utx: bitcointx.Transaction = .{
        .version = 2,
        .vin = vin_buf[0..n_in],
        .vout = vout_buf[0..n_out],
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const utx_bytes = bitcointx.serializeLegacy(allocator, utx) catch return;
    defer allocator.free(utx_bytes);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, &magic);

    // Global map: the mandatory UNSIGNED_TX record, then fuzzed extras.
    try appendFuzzRecord(&buf, allocator, global_key.UNSIGNED_TX, &.{}, utx_bytes);
    try appendFuzzedRecords(&buf, allocator, smith, &.{ global_key.XPUB, global_key.VERSION, global_key.PROPRIETARY });

    // See the note below `parse`: without a `FINAL_SCRIPTSIG`/
    // `FINAL_SCRIPTWITNESS` on *every* input, `extract` refuses at the first
    // one and everything behind it stays unreachable.
    const finalize_them = smith.value(bool);
    var i: usize = 0;
    while (i < n_in) : (i += 1) {
        try appendFuzzedRecordsOpen(&buf, allocator, smith, &.{
            input_key.NON_WITNESS_UTXO, input_key.WITNESS_UTXO,     input_key.PARTIAL_SIG,
            input_key.SIGHASH_TYPE,     input_key.BIP32_DERIVATION,
        });
        if (finalize_them) try appendFinalRecords(&buf, allocator, smith);
        try buf.append(allocator, 0x00); // map terminator
    }
    i = 0;
    while (i < n_out) : (i += 1) {
        try appendFuzzedRecords(&buf, allocator, smith, &.{ output_key.REDEEM_SCRIPT, output_key.BIP32_DERIVATION });
    }

    var psbt = parse(allocator, buf.items) catch return;
    defer psbt.deinit(allocator);

    // `decodeWitnessStack` driven directly as well: it is public, it is
    // documented as untrusted-input, and reaching it only through a PSBT that
    // parses would leave most of its own error paths behind a second gate.
    {
        var wbuf: [96]u8 = undefined;
        smith.bytes(&wbuf);
        const wlen = smith.valueRangeAtMost(u8, 0, wbuf.len);
        if (decodeWitnessStack(allocator, wbuf[0..wlen])) |stack| {
            defer allocator.free(stack);
            // Every item is a subslice of the value it was decoded from, and
            // the stack cannot claim more items than there were octets.
            if (stack.len > wlen) return error.MoreItemsThanOctets;
            for (stack) |item| {
                const off = @intFromPtr(item.ptr) - @intFromPtr(&wbuf);
                if (off > wlen or item.len > wlen - off) return error.ItemOutsideValue;
            }
        } else |_| {}
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var ps = parse(a, buf.items) catch return;
    defer ps.deinit(a);

    if (finalize(a, ps)) |results| {
        if (results.len != n_in) return error.FinalizeResultCountMismatch;
    } else |_| {}

    if (extract(a, ps)) |tx| {
        // The extractor splices signatures into the unsigned transaction; it
        // must not invent or drop inputs or outputs while doing it.
        if (tx.vin.len != n_in) return error.ExtractChangedInputCount;
        if (tx.vout.len != n_out) return error.ExtractChangedOutputCount;
        if (tx.has_witness and tx.witness.len != n_in) return error.WitnessCountMismatch;
    } else |_| {}
}
