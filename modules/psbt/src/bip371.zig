// SPDX-License-Identifier: MIT
//! BIP371 (Taproot fields for PSBT): structural validation, typed read
//! accessors and Updater setters for the taproot input and output fields.
//!
//! | scope  | key type                         | keydata                       | value                                    |
//! |--------|----------------------------------|-------------------------------|------------------------------------------|
//! | input  | `TAP_KEY_SIG` (0x13)             | none                          | 64/65-byte BIP340 signature              |
//! | input  | `TAP_SCRIPT_SIG` (0x14)          | x-only key ++ leaf hash (64)  | 64/65-byte signature                     |
//! | input  | `TAP_LEAF_SCRIPT` (0x15)         | control block (33 + 32m)      | script ++ leaf version                   |
//! | input  | `TAP_BIP32_DERIVATION` (0x16)    | x-only key (32)               | n, n leaf hashes, fingerprint, path      |
//! | input  | `TAP_INTERNAL_KEY` (0x17)        | none                          | 32-byte x-only key                       |
//! | input  | `TAP_MERKLE_ROOT` (0x18)         | none                          | 32-byte hash                             |
//! | output | `TAP_INTERNAL_KEY` (0x05)        | none                          | 32-byte x-only key                       |
//! | output | `TAP_TREE` (0x06)                | none                          | `{depth, leaf version, len, script}*`    |
//! | output | `TAP_BIP32_DERIVATION` (0x07)    | x-only key (32)               | as the input field                       |
//!
//! `parse` applies `validateInputRecord`/`validateOutputRecord` to every
//! record, so a parsed PSBT's taproot fields have the shapes above and the
//! accessors cannot meet a malformed one; on a hand-built `Map` they read a
//! malformed value as absent (`null`) rather than trusting it. The x-only keys
//! and signatures are not checked to be points / valid signatures here --
//! `finalize`'s `bitcoinscript.verifyScript` pass is the gate for that.
//!
//! Merkle-root computation from a tree, the output-key tweak and signing live
//! in the sibling modules `taproot` and `bip340`; this module only carries the
//! data. The Updater setters allocate value buffers from `allocator`, which
//! must be arena-like exactly as for `finalize` (see `update.zig`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const bitcoinscript = @import("bitcoinscript");
const psbt = @import("root.zig");
const update = @import("update.zig");

const Record = psbt.Record;
const Map = psbt.Map;
const RecordError = psbt.RecordError;
const input_key = psbt.input_key;
const output_key = psbt.output_key;

/// BIP341's maximum script-tree depth (and control-block path length).
pub const max_depth: u8 = 128;

// ── validation (used by `psbt.parse` and by the setters) ────────────────

fn requireSigValue(r: Record) RecordError!void {
    if (r.value.len != 64 and r.value.len != 65) return error.InvalidFixedFieldLength;
}

fn requireKeyDataLen(r: Record, n: usize) RecordError!void {
    if (r.keydata.len != n) return error.InvalidKeyDataLength;
}

fn derivationShapeOk(value: []const u8) bool {
    return decodeTapDerivation(value) != null;
}

/// Structural check of the BIP371 and hash-preimage input fields; any other
/// key type passes (opaque passthrough).
pub fn validateInputRecord(r: Record) RecordError!void {
    switch (r.keytype) {
        input_key.RIPEMD160, input_key.HASH160 => try requireKeyDataLen(r, 20),
        input_key.SHA256, input_key.HASH256 => try requireKeyDataLen(r, 32),
        input_key.TAP_KEY_SIG => {
            try psbt.requireNoKeyData(r);
            try requireSigValue(r);
        },
        input_key.TAP_SCRIPT_SIG => {
            try requireKeyDataLen(r, 64);
            try requireSigValue(r);
        },
        input_key.TAP_LEAF_SCRIPT => {
            if (!bitcoinscript.tapscript.controlBlockValid(r.keydata)) return error.InvalidKeyDataLength;
            if (r.value.len < 1) return error.InvalidFixedFieldLength; // at least the leaf version
        },
        input_key.TAP_BIP32_DERIVATION => {
            try requireKeyDataLen(r, 32);
            if (!derivationShapeOk(r.value)) return error.InvalidFixedFieldLength;
        },
        input_key.TAP_INTERNAL_KEY, input_key.TAP_MERKLE_ROOT => {
            try psbt.requireNoKeyData(r);
            try psbt.requireFixedValueLen(r, 32);
        },
        else => {},
    }
}

/// Structural check of the BIP371 output fields.
pub fn validateOutputRecord(r: Record) RecordError!void {
    switch (r.keytype) {
        output_key.TAP_INTERNAL_KEY => {
            try psbt.requireNoKeyData(r);
            try psbt.requireFixedValueLen(r, 32);
        },
        output_key.TAP_TREE => {
            try psbt.requireNoKeyData(r);
            if (!treeValueOk(r.value)) return error.InvalidTapTree;
        },
        output_key.TAP_BIP32_DERIVATION => {
            try requireKeyDataLen(r, 32);
            if (!derivationShapeOk(r.value)) return error.InvalidFixedFieldLength;
        },
        else => {},
    }
}

// ── TAP_BIP32_DERIVATION ────────────────────────────────────────────────

/// `<compact size n> <32-byte leaf hash>*n <4-byte fingerprint> <u32 LE>*`.
pub const TapBip32Derivation = struct {
    /// `32 * leafHashCount()` bytes: the leaves (by tapleaf hash) this key
    /// appears in; empty when the key is only the internal / output key.
    leaf_hashes: []const u8,
    path: psbt.Bip32Path,

    pub fn leafHashCount(self: TapBip32Derivation) usize {
        return self.leaf_hashes.len / 32;
    }

    pub fn leafHash(self: TapBip32Derivation, i: usize) [32]u8 {
        return self.leaf_hashes[i * 32 ..][0..32].*;
    }
};

fn decodeTapDerivation(value: []const u8) ?TapBip32Derivation {
    const c = bitcointx.decodeCompactSize(value) catch return null;
    const rest = value[c.consumed..];
    // Each leaf hash needs 32 bytes, so a hostile count cannot overflow the
    // multiplication below: it is compared against the bytes actually present.
    if (c.value > rest.len / 32) return null;
    const hashes_len: usize = @as(usize, @intCast(c.value)) * 32;
    const tail = rest[hashes_len..];
    if (tail.len < 4 or (tail.len - 4) % 4 != 0) return null;
    return .{
        .leaf_hashes = rest[0..hashes_len],
        .path = .{ .fingerprint = tail[0..4].*, .path_bytes = tail[4..] },
    };
}

/// `PSBT_IN_TAP_BIP32_DERIVATION` for the x-only key `xonly`.
pub fn inputTapBip32Derivation(m: Map, xonly: [32]u8) ?TapBip32Derivation {
    const r = m.findKeyed(input_key.TAP_BIP32_DERIVATION, &xonly) orelse return null;
    return decodeTapDerivation(r.value);
}

/// `PSBT_OUT_TAP_BIP32_DERIVATION` for the x-only key `xonly`.
pub fn outputTapBip32Derivation(m: Map, xonly: [32]u8) ?TapBip32Derivation {
    const r = m.findKeyed(output_key.TAP_BIP32_DERIVATION, &xonly) orelse return null;
    return decodeTapDerivation(r.value);
}

// ── fixed-size fields ───────────────────────────────────────────────────

fn find32(m: Map, keytype: u64) ?[32]u8 {
    const r = m.find(keytype) orelse return null;
    if (r.value.len != 32) return null;
    return r.value[0..32].*;
}

/// `PSBT_IN_TAP_INTERNAL_KEY`, or `null` if omitted.
pub fn inputTapInternalKey(m: Map) ?[32]u8 {
    return find32(m, input_key.TAP_INTERNAL_KEY);
}

/// `PSBT_IN_TAP_MERKLE_ROOT`, or `null` if omitted.
pub fn inputTapMerkleRoot(m: Map) ?[32]u8 {
    return find32(m, input_key.TAP_MERKLE_ROOT);
}

/// `PSBT_OUT_TAP_INTERNAL_KEY`, or `null` if omitted.
pub fn outputTapInternalKey(m: Map) ?[32]u8 {
    return find32(m, output_key.TAP_INTERNAL_KEY);
}

/// `PSBT_IN_TAP_SCRIPT_SIG` for the pair (`xonly`, `leaf_hash`): the 64/65-byte
/// signature, or `null`.
pub fn inputTapScriptSig(m: Map, xonly: [32]u8, leaf_hash: [32]u8) ?[]const u8 {
    const r = m.findKeyed(input_key.TAP_SCRIPT_SIG, &(xonly ++ leaf_hash)) orelse return null;
    return r.value;
}

// ── TAP_LEAF_SCRIPT ─────────────────────────────────────────────────────

pub const TapLeafScript = struct {
    /// The BIP341 control block: `(leaf version | parity) ++ internal key ++
    /// merkle path`, `33 + 32m` bytes.
    control_block: []const u8,
    script: []const u8,
    /// The leaf version stored in the record (the control block carries it too,
    /// in its first byte with the parity bit set or clear).
    leaf_version: u8,
};

/// Iterator over the `PSBT_IN_TAP_LEAF_SCRIPT` records of an input map, in
/// map order. Records of a hand-built map that are malformed are skipped.
pub const TapLeafScripts = struct {
    records: []const Record,
    index: usize = 0,

    pub fn next(self: *TapLeafScripts) ?TapLeafScript {
        while (self.index < self.records.len) {
            const r = self.records[self.index];
            self.index += 1;
            if (r.keytype != input_key.TAP_LEAF_SCRIPT) continue;
            if (!bitcoinscript.tapscript.controlBlockValid(r.keydata) or r.value.len < 1) continue;
            return .{
                .control_block = r.keydata,
                .script = r.value[0 .. r.value.len - 1],
                .leaf_version = r.value[r.value.len - 1],
            };
        }
        return null;
    }
};

pub fn inputTapLeafScripts(m: Map) TapLeafScripts {
    return .{ .records = m.records };
}

// ── TAP_TREE ────────────────────────────────────────────────────────────

pub const TapTreeLeaf = struct {
    depth: u8,
    leaf_version: u8,
    script: []const u8,
};

/// Iterator over the leaves of a `PSBT_OUT_TAP_TREE` value, depth-first.
pub const TapTree = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn next(self: *TapTree) ?TapTreeLeaf {
        const b = self.bytes;
        var o = self.offset;
        if (b.len - o < 3) return null;
        const depth = b[o];
        const version = b[o + 1];
        const c = bitcointx.decodeCompactSize(b[o + 2 ..]) catch return null;
        o += 2 + c.consumed;
        if (c.value > b.len - o) return null;
        const n: usize = @intCast(c.value);
        const script = b[o .. o + n];
        self.offset = o + n;
        return .{ .depth = depth, .leaf_version = version, .script = script };
    }
};

/// `PSBT_OUT_TAP_TREE`, or `null` if omitted (or malformed, which `parse`
/// already refuses).
pub fn outputTapTree(m: Map) ?TapTree {
    const r = m.find(output_key.TAP_TREE) orelse return null;
    if (!treeValueOk(r.value)) return null;
    return .{ .bytes = r.value };
}

/// BIP371: one or more `{depth, leaf version, script}` tuples that are the
/// depth-first listing of ONE complete binary tree. Mirrors Bitcoin Core's
/// `TaprootBuilder::IsComplete` check at deserialization, with the stack of
/// open subtree depths kept strictly increasing (a leaf shallower than the
/// open one can never complete it).
fn treeValueOk(value: []const u8) bool {
    var it: TapTree = .{ .bytes = value };
    var stack: [max_depth + 2]u8 = undefined;
    var n: usize = 0;
    var count: usize = 0;
    while (it.offset < value.len) {
        const leaf = it.next() orelse return false;
        count += 1;
        if (leaf.depth > max_depth or leaf.leaf_version & 1 != 0) return false;
        if (n > 0 and leaf.depth < stack[n - 1]) return false;
        stack[n] = leaf.depth;
        n += 1;
        while (n >= 2 and stack[n - 1] == stack[n - 2]) {
            if (stack[n - 1] == 0) return false; // two roots
            stack[n - 2] -= 1;
            n -= 1;
        }
    }
    return count > 0 and n == 1 and stack[0] == 0;
}

// ── Updater setters ─────────────────────────────────────────────────────

fn derivationValue(allocator: Allocator, leaf_hashes: []const [32]u8, fingerprint: [4]u8, path: []const u32) Allocator.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try bitcointx.tx.appendCompactSize(&buf, allocator, leaf_hashes.len);
    for (leaf_hashes) |h| try buf.appendSlice(allocator, &h);
    try buf.appendSlice(allocator, &fingerprint);
    for (path) |step| {
        var le: [4]u8 = undefined;
        std.mem.writeInt(u32, &le, step, .little);
        try buf.appendSlice(allocator, &le);
    }
    return buf.toOwnedSlice(allocator);
}

/// Sets `PSBT_IN_TAP_KEY_SIG` (64 bytes, or 65 with a trailing sighash type).
pub fn setInputTapKeySig(allocator: Allocator, ps: *psbt.Psbt, index: usize, sig: []const u8) update.UpdateError!void {
    try update.putInput(allocator, ps, index, input_key.TAP_KEY_SIG, &.{}, sig);
}

/// Sets `PSBT_IN_TAP_SCRIPT_SIG` for (`xonly`, `leaf_hash`).
pub fn setInputTapScriptSig(allocator: Allocator, ps: *psbt.Psbt, index: usize, xonly: [32]u8, leaf_hash: [32]u8, sig: []const u8) update.UpdateError!void {
    try update.putInput(allocator, ps, index, input_key.TAP_SCRIPT_SIG, &(xonly ++ leaf_hash), sig);
}

/// Adds (or replaces, by control block) a `PSBT_IN_TAP_LEAF_SCRIPT`.
pub fn addInputTapLeafScript(allocator: Allocator, ps: *psbt.Psbt, index: usize, control_block: []const u8, script: []const u8, leaf_version: u8) update.UpdateError!void {
    const value = try allocator.alloc(u8, script.len + 1);
    errdefer allocator.free(value);
    @memcpy(value[0..script.len], script);
    value[script.len] = leaf_version;
    try update.putInputOwned(allocator, ps, index, input_key.TAP_LEAF_SCRIPT, control_block, value);
}

/// Sets `PSBT_IN_TAP_BIP32_DERIVATION` for `xonly`.
pub fn setInputTapBip32Derivation(allocator: Allocator, ps: *psbt.Psbt, index: usize, xonly: [32]u8, leaf_hashes: []const [32]u8, fingerprint: [4]u8, path: []const u32) update.UpdateError!void {
    const value = try derivationValue(allocator, leaf_hashes, fingerprint, path);
    errdefer allocator.free(value);
    try update.putInputOwned(allocator, ps, index, input_key.TAP_BIP32_DERIVATION, &xonly, value);
}

pub fn setInputTapInternalKey(allocator: Allocator, ps: *psbt.Psbt, index: usize, xonly: [32]u8) update.UpdateError!void {
    try update.putInput(allocator, ps, index, input_key.TAP_INTERNAL_KEY, &.{}, &xonly);
}

pub fn setInputTapMerkleRoot(allocator: Allocator, ps: *psbt.Psbt, index: usize, root: [32]u8) update.UpdateError!void {
    try update.putInput(allocator, ps, index, input_key.TAP_MERKLE_ROOT, &.{}, &root);
}

pub fn setOutputTapInternalKey(allocator: Allocator, ps: *psbt.Psbt, index: usize, xonly: [32]u8) update.UpdateError!void {
    try update.putOutput(allocator, ps, index, output_key.TAP_INTERNAL_KEY, &.{}, &xonly);
}

/// Sets `PSBT_OUT_TAP_TREE` from the leaves in depth-first order; refuses a
/// list that is not one complete tree (`error.InvalidTapTree`).
pub fn setOutputTapTree(allocator: Allocator, ps: *psbt.Psbt, index: usize, leaves: []const TapTreeLeaf) update.UpdateError!void {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    for (leaves) |l| {
        try buf.append(allocator, l.depth);
        try buf.append(allocator, l.leaf_version);
        try bitcointx.tx.appendCompactSize(&buf, allocator, l.script.len);
        try buf.appendSlice(allocator, l.script);
    }
    const value = try buf.toOwnedSlice(allocator);
    errdefer allocator.free(value);
    try update.putOutputOwned(allocator, ps, index, output_key.TAP_TREE, &.{}, value);
}

/// Sets `PSBT_OUT_TAP_BIP32_DERIVATION` for `xonly`.
pub fn setOutputTapBip32Derivation(allocator: Allocator, ps: *psbt.Psbt, index: usize, xonly: [32]u8, leaf_hashes: []const [32]u8, fingerprint: [4]u8, path: []const u32) update.UpdateError!void {
    const value = try derivationValue(allocator, leaf_hashes, fingerprint, path);
    errdefer allocator.free(value);
    try update.putOutputOwned(allocator, ps, index, output_key.TAP_BIP32_DERIVATION, &xonly, value);
}
