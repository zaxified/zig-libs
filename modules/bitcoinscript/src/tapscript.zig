// SPDX-License-Identifier: MIT
//! BIP341/BIP342 taproot **script-path** primitives — everything the
//! tapscript leaf-execution path needs that is NOT plain stack-machine
//! opcode dispatch:
//!
//! - `controlBlockValid` / `verifyCommitment` — BIP341 "Script validation
//!   rules": parse the witness control block, recompute the tapleaf hash
//!   and Merkle root, tweak the internal key, and check the resulting
//!   output key against the witness program (x-coordinate + y-parity).
//! - `tapleafHash` — `hash_TapLeaf(leaf_version || compact_size(script) || script)`.
//! - `ExecData` — the per-leaf execution state a BIP342 signature commits
//!   to (tapleaf hash, last-executed-`OP_CODESEPARATOR` position, the
//!   validation-weight budget, and the optional annex).
//! - `sigMsg` / `sighash` — the BIP341 Common Signature Message with the
//!   BIP342 `ext_flag = 1` extension (tapleaf_hash || key_version ||
//!   codesep_pos) appended, plus annex commitment.
//! - `checkSchnorrSig` — BIP340 Schnorr verification of a tapscript
//!   signature (64/65-byte form, sighash-type extraction) against a 32-byte
//!   x-only public key.
//!
//! ## Why the SigMsg is (re)built here rather than reused from `bitcointx`
//!
//! `bitcointx.bip341.sigMsg` implements the **key-path** message only: it
//! hard-codes `spend_type = 0x00` (`ext_flag = 0`, no annex) and emits no
//! extension fields (that module's doc comment says so explicitly). A
//! script-path signature commits to `spend_type = 0x02` (or `0x03` with an
//! annex) and the three appended `ext_flag = 1` fields, so the key-path
//! function cannot be reused as-is. `sigMsg` below reproduces BIP341's
//! common layout byte-for-byte (cross-checked against `bitcointx`'s
//! KAT-backed key-path `sigMsg` by `tapscript_test.zig` for the shared
//! `ext_flag = 0` prefix) and adds the BIP342 tail. A future DRY refactor
//! could lift a shared `commonSigMsg` helper into `bitcointx`; it is called
//! out in the coordinator's interop-vector backlog.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const bip340 = @import("bip340");
const k256 = @import("k256");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Secp256k1 = k256.Secp256k1;

pub const SIGHASH_DEFAULT: u8 = 0x00;

/// The one assigned tapscript leaf version (BIP342). Any other value is an
/// unknown/future version (`verify.zig` treats it as anyone-can-spend
/// unless the discourage flag is set).
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// Initial per-input validation-weight budget offset (BIP342): the budget
/// starts at `50 + witness_serialized_size`.
pub const validation_weight_offset: i64 = 50;
/// Cost charged against the validation-weight budget for each executed
/// signature opcode with a non-empty signature (BIP342).
pub const validation_weight_per_sigop: i64 = 50;

/// Per-leaf tapscript execution data. A BIP342 signature commits to
/// `tapleaf_hash` and `codesep_pos`; `validation_weight` is the mutable
/// sigops budget; `annex` (if present, including its mandatory `0x50`
/// prefix) is committed via `sha_annex`.
pub const ExecData = struct {
    tapleaf_hash: [32]u8,
    /// Opcode position of the last executed `OP_CODESEPARATOR`, or
    /// `0xffffffff` if none has executed yet (BIP342 `codesep_pos`).
    codesep_pos: u32 = 0xffffffff,
    validation_weight: i64 = 0,
    annex: ?[]const u8 = null,
};

pub const SchnorrError = error{
    /// Tapscript signature is neither 64 nor 65 bytes (BIP342).
    SchnorrSigSize,
    /// A 65-byte tapscript signature's trailing hashtype byte is
    /// `SIGHASH_DEFAULT` (0x00) — forbidden (the 64-byte form must be used)
    /// — or is otherwise not one of the 6 defined non-default hashtypes.
    SchnorrSigHashtype,
    /// BIP340 Schnorr verification failed (a non-empty tapscript signature
    /// failing verification is a hard, immediate script failure).
    SchnorrSig,
} || bitcointx.bip341.Bip341Error;

// ── compact-size / little-endian append helpers (BIP341 SigMsg layout) ────

fn appendCompactSize(buf: *std.ArrayList(u8), allocator: Allocator, value: u64) Allocator.Error!void {
    var tmp: [9]u8 = undefined;
    const w = bitcointx.encodeCompactSize(value, &tmp) catch unreachable;
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

fn sha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

fn shaOutput(allocator: Allocator, vout: bitcointx.TxOut) Allocator.Error![32]u8 {
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(allocator);
    try appendI64LE(&tmp, allocator, vout.value);
    try appendCompactSize(&tmp, allocator, vout.script_pubkey.len);
    try tmp.appendSlice(allocator, vout.script_pubkey);
    return sha256(tmp.items);
}

// ── tapleaf hash ─────────────────────────────────────────────────────────

/// `hash_TapLeaf(leaf_version || compact_size(len(script)) || script)`
/// (BIP341). `leaf_version` is the control block's first byte with its low
/// (parity) bit cleared.
pub fn tapleafHash(leaf_version: u8, script: []const u8) [32]u8 {
    var h = bip340.hash.taggedHasher("TapLeaf");
    h.update(&[_]u8{leaf_version});
    var cs: [9]u8 = undefined;
    const w = bitcointx.encodeCompactSize(script.len, &cs) catch unreachable;
    h.update(w);
    h.update(script);
    return h.finalResult();
}

// ── BIP341 script-path control-block validation ──────────────────────────

/// Bitcoin Core `TAPROOT_CONTROL_BASE_SIZE`/`_NODE_SIZE`/`_MAX_NODE_COUNT`:
/// a control block is `33 + 32*m` bytes for `0 <= m <= 128`.
pub const control_base_size: usize = 33;
pub const control_node_size: usize = 32;
pub const control_max_node_count: usize = 128;

/// Structural validity of a control block's length only (`33 + 32m`,
/// `m <= 128`).
pub fn controlBlockValid(control_block: []const u8) bool {
    if (control_block.len < control_base_size) return false;
    if ((control_block.len - control_base_size) % control_node_size != 0) return false;
    const m = (control_block.len - control_base_size) / control_node_size;
    return m <= control_max_node_count;
}

/// BIP341 "Script validation rules": given the 32-byte witness program
/// `program_q` (the taproot output key's x-coordinate), a structurally
/// valid `control_block`, and the leaf `script`, verify the taproot
/// commitment. Returns `true` iff `q == x(Q)` and `c[0]&1 == y(Q) mod 2`
/// where `Q = lift_x(internal_key) + int(hash_TapTweak(internal_key ||
/// merkle_root))*G`. All inputs are public; this is variable-time.
///
/// Caller must have already checked `controlBlockValid` and
/// `program_q.len == 32`.
pub fn verifyCommitment(program_q: []const u8, control_block: []const u8, script: []const u8) bool {
    std.debug.assert(program_q.len == 32);
    std.debug.assert(controlBlockValid(control_block));

    const leaf_version = control_block[0] & 0xfe;
    const p: [32]u8 = control_block[1..33].*;

    // Merkle root: fold the leaf hash with each 32-byte path element,
    // lexicographically ordering the two 32-byte inputs before hashing
    // (BIP341 hash_TapBranch).
    var k = tapleafHash(leaf_version, script);
    var i: usize = control_base_size;
    while (i < control_block.len) : (i += control_node_size) {
        const e: [32]u8 = control_block[i..][0..32].*;
        var h = bip340.hash.taggedHasher("TapBranch");
        if (std.mem.lessThan(u8, &k, &e)) {
            h.update(&k);
            h.update(&e);
        } else {
            h.update(&e);
            h.update(&k);
        }
        k = h.finalResult();
    }

    // t = hash_TapTweak(p || merkle_root); fail if t >= curve order.
    var th = bip340.hash.taggedHasher("TapTweak");
    th.update(&p);
    th.update(&k);
    const t = th.finalResult();
    const t_int = std.mem.readInt(u256, &t, .big);
    if (t_int >= k256.scalar.field_order) return false;

    // Q = lift_x(p) + t*G.
    const xpk = bip340.XOnlyPublicKey.fromBytes(p) catch return false;
    const P = xpk.lift() catch return false;
    const tG = Secp256k1.basePoint.mulPublic(t, .big) catch return false; // t != 0 in practice (hash output)
    const Q = P.add(tG);
    const q_aff = Q.affineCoordinates();

    // Fail if q != x(Q) or c[0]&1 != y(Q) mod 2.
    const qx = q_aff.x.toBytes(.big);
    if (!std.mem.eql(u8, &qx, program_q)) return false;
    const y_parity: u8 = if (q_aff.y.isOdd()) 1 else 0;
    if ((control_block[0] & 1) != y_parity) return false;
    return true;
}

// ── BIP341/342 signature message + Schnorr check ─────────────────────────

/// `0x00 || SigMsg(hash_type, ext_flag=1)` for a tapscript spend of `ctx`'s
/// input: the BIP341 Common Signature Message, plus (from BIP342) the annex
/// commitment when `exec.annex != null`, and the appended extension
/// `tapleaf_hash || key_version(0x00) || codesep_pos`. Caller owns the
/// returned slice. Byte layout mirrors `bitcointx.bip341.sigMsg` (validated
/// against that KAT-backed implementation for the shared prefix).
pub fn sigMsg(
    allocator: Allocator,
    transaction: bitcointx.Transaction,
    input_index: usize,
    hash_type: u8,
    spent_outputs: []const bitcointx.TxOut,
    exec: *const ExecData,
) SchnorrError![]u8 {
    try bitcointx.bip341.validateHashType(hash_type);
    if (input_index >= transaction.vin.len) return error.InputIndexOutOfRange;
    if (spent_outputs.len != transaction.vin.len) return error.PrevoutsCountMismatch;

    const anyone_can_pay = (hash_type & 0x80) != 0;
    const base = hash_type & 0x03;
    const annex_present = exec.annex != null;
    // spend_type = 2*ext_flag + annex_present; ext_flag = 1 for tapscript.
    const spend_type: u8 = 2 + @as(u8, if (annex_present) 1 else 0);

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.append(allocator, 0x00); // sighash epoch (BIP341)
    try buf.append(allocator, hash_type);
    try appendI32LE(&buf, allocator, transaction.version);
    try appendU32LE(&buf, allocator, transaction.locktime);

    if (!anyone_can_pay) {
        {
            var tmp: std.ArrayList(u8) = .empty;
            defer tmp.deinit(allocator);
            for (transaction.vin) |vin| {
                try tmp.appendSlice(allocator, &vin.prevout.txid);
                try appendU32LE(&tmp, allocator, vin.prevout.vout);
            }
            try buf.appendSlice(allocator, &sha256(tmp.items));
        }
        {
            var tmp: std.ArrayList(u8) = .empty;
            defer tmp.deinit(allocator);
            for (spent_outputs) |o| try appendI64LE(&tmp, allocator, o.value);
            try buf.appendSlice(allocator, &sha256(tmp.items));
        }
        {
            var tmp: std.ArrayList(u8) = .empty;
            defer tmp.deinit(allocator);
            for (spent_outputs) |o| {
                try appendCompactSize(&tmp, allocator, o.script_pubkey.len);
                try tmp.appendSlice(allocator, o.script_pubkey);
            }
            try buf.appendSlice(allocator, &sha256(tmp.items));
        }
        {
            var tmp: std.ArrayList(u8) = .empty;
            defer tmp.deinit(allocator);
            for (transaction.vin) |vin| try appendU32LE(&tmp, allocator, vin.sequence);
            try buf.appendSlice(allocator, &sha256(tmp.items));
        }
    }

    if (base == SIGHASH_DEFAULT or base == 0x01) { // DEFAULT or ALL
        var tmp: std.ArrayList(u8) = .empty;
        defer tmp.deinit(allocator);
        for (transaction.vout) |vout| {
            try appendI64LE(&tmp, allocator, vout.value);
            try appendCompactSize(&tmp, allocator, vout.script_pubkey.len);
            try tmp.appendSlice(allocator, vout.script_pubkey);
        }
        try buf.appendSlice(allocator, &sha256(tmp.items));
    }

    try buf.append(allocator, spend_type);

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

    // sha_annex = SHA256(compact_size(len) || annex), annex incl. 0x50 prefix.
    if (exec.annex) |annex| {
        var tmp: std.ArrayList(u8) = .empty;
        defer tmp.deinit(allocator);
        try appendCompactSize(&tmp, allocator, annex.len);
        try tmp.appendSlice(allocator, annex);
        try buf.appendSlice(allocator, &sha256(tmp.items));
    }

    if (base == 0x03) { // SIGHASH_SINGLE
        if (input_index >= transaction.vout.len) return error.MissingCorrespondingOutput;
        try buf.appendSlice(allocator, &try shaOutput(allocator, transaction.vout[input_index]));
    }

    // BIP342 ext_flag=1 extension: tapleaf_hash || key_version || codesep_pos.
    try buf.appendSlice(allocator, &exec.tapleaf_hash);
    try buf.append(allocator, 0x00); // key_version
    try appendU32LE(&buf, allocator, exec.codesep_pos);

    return buf.toOwnedSlice(allocator);
}

/// `bip340.taggedHash("TapSighash", sigMsg(...))`.
pub fn sighash(
    allocator: Allocator,
    transaction: bitcointx.Transaction,
    input_index: usize,
    hash_type: u8,
    spent_outputs: []const bitcointx.TxOut,
    exec: *const ExecData,
) SchnorrError![32]u8 {
    const msg = try sigMsg(allocator, transaction, input_index, hash_type, spent_outputs, exec);
    defer allocator.free(msg);
    return bip340.taggedHash("TapSighash", msg);
}

/// Verifies a non-empty tapscript signature `sig` against the 32-byte x-only
/// `pubkey`, over the BIP341/342 sighash of `ctx`'s input. `sig` is 64 bytes
/// (implicit `SIGHASH_DEFAULT`) or 65 bytes (trailing sighash-type byte,
/// which must be a defined non-default type). Any failure — wrong size, bad
/// hashtype, or a failing curve check — is a hard error (BIP342: a non-empty
/// tapscript signature that fails validation terminates the script
/// immediately). Returns normally only on a successful verification.
///
/// Caller guarantees `sig.len != 0` and `pubkey.len == 32`.
pub fn checkSchnorrSig(
    allocator: Allocator,
    sig: []const u8,
    pubkey: []const u8,
    transaction: bitcointx.Transaction,
    input_index: usize,
    spent_outputs: []const bitcointx.TxOut,
    exec: *const ExecData,
) SchnorrError!void {
    std.debug.assert(pubkey.len == 32);
    std.debug.assert(sig.len != 0);

    if (sig.len != 64 and sig.len != 65) return error.SchnorrSigSize;
    var hash_type: u8 = SIGHASH_DEFAULT;
    if (sig.len == 65) {
        hash_type = sig[64];
        // A 65-byte sig must NOT carry SIGHASH_DEFAULT, and must be one of
        // the 6 defined non-default types.
        if (hash_type == SIGHASH_DEFAULT) return error.SchnorrSigHashtype;
        bitcointx.bip341.validateHashType(hash_type) catch return error.SchnorrSigHashtype;
    }

    const msg = try sighash(allocator, transaction, input_index, hash_type, spent_outputs, exec);

    const xpk = bip340.XOnlyPublicKey.fromBytes(pubkey[0..32].*) catch return error.SchnorrSig;
    const parsed = bip340.Signature.fromBytes(sig[0..64].*) catch return error.SchnorrSig;
    if (!bip340.verify(xpk, &msg, parsed)) return error.SchnorrSig;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "isOpSuccess set matches BIP342 exactly" {
    const opcodes = @import("opcodes.zig");
    // Spot-check the named boundaries from BIP342's list.
    const yes = [_]u8{ 80, 98, 126, 127, 128, 129, 131, 134, 137, 138, 141, 142, 149, 153, 187, 200, 254 };
    for (yes) |op| try testing.expect(opcodes.isOpSuccess(op));
    const no = [_]u8{ 0, 79, 81, 96, 97, 99, 100, 101, 102, 130, 135, 136, 139, 140, 143, 148, 154, 174, 175, 186, 255 };
    for (no) |op| try testing.expect(!opcodes.isOpSuccess(op));
}

// External KAT: BIP341 wallet-test-vectors.json `scriptPubKey` single-leaf
// cases (bitcoin/bips, bip-0341/wallet-test-vectors.json). Validates the
// full control-block commitment path (tapleaf hash + tweak + output-key
// x-coordinate + parity) against published vectors.
fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "BIP341 KAT: single-leaf tapleaf hash matches wallet-test-vectors" {
    // scriptPubKey[1]: leafVersion 192, script + expected leafHash.
    const script = hexToBytes("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac");
    const want = hexToBytes("5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21");
    const got = tapleafHash(0xc0, &script);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "BIP341 KAT: control-block commitment verifies for single-leaf script paths" {
    // Two independent single-leaf cases from wallet-test-vectors.json.
    {
        const script = hexToBytes("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac");
        const cb = hexToBytes("c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27");
        const q = hexToBytes("147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3");
        try testing.expect(controlBlockValid(&cb));
        try testing.expect(verifyCommitment(&q, &cb, &script));
        // Positive control: flip the parity bit -> must fail.
        var bad = cb;
        bad[0] ^= 0x01;
        try testing.expect(!verifyCommitment(&q, &bad, &script));
    }
    {
        const script = hexToBytes("20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac");
        const cb = hexToBytes("c093478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820");
        const q = hexToBytes("e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e");
        try testing.expect(verifyCommitment(&q, &cb, &script));
        // Positive control: corrupt the script -> different leaf -> fail.
        var bad_script = script;
        bad_script[1] ^= 0x01;
        try testing.expect(!verifyCommitment(&q, &cb, &bad_script));
    }
}

test "controlBlockValid: length must be 33 + 32m, m <= 128" {
    try testing.expect(controlBlockValid(&([_]u8{0} ** 33)));
    try testing.expect(controlBlockValid(&([_]u8{0} ** 65)));
    try testing.expect(!controlBlockValid(&([_]u8{0} ** 32)));
    try testing.expect(!controlBlockValid(&([_]u8{0} ** 34)));
    try testing.expect(!controlBlockValid(&([_]u8{0} ** 64)));
    // 33 + 32*129 = 4161 -> too many nodes.
    try testing.expect(!controlBlockValid(&([_]u8{0} ** (33 + 32 * 129))));
}

test "sigMsg ext_flag=0 prefix matches bitcointx key-path sigMsg byte-for-byte" {
    // Cross-check the shared BIP341 common part against bitcointx's
    // KAT-backed key-path sigMsg: with no annex and ext_flag stripped, our
    // message must equal bitcointx's followed only by our appended
    // ext_flag=1 extension. We assert the full common prefix is identical.
    const a = testing.allocator;
    var vin = [_]bitcointx.TxIn{
        .{ .prevout = .{ .txid = [_]u8{0xaa} ** 32, .vout = 1 }, .script_sig = &.{}, .sequence = 0xfffffffd },
        .{ .prevout = .{ .txid = [_]u8{0xbb} ** 32, .vout = 7 }, .script_sig = &.{}, .sequence = 0xffffffff },
    };
    var vout = [_]bitcointx.TxOut{
        .{ .value = 1234, .script_pubkey = &[_]u8{ 0x51, 0x20 } ++ [_]u8{0xcc} ** 32 },
        .{ .value = 5678, .script_pubkey = &[_]u8{0x6a} },
    };
    const t: bitcointx.Transaction = .{ .version = 2, .vin = &vin, .vout = &vout, .witness = &.{}, .locktime = 500000, .has_witness = true };
    const spent = [_]bitcointx.TxOut{
        .{ .value = 9000, .script_pubkey = &[_]u8{ 0x51, 0x20 } ++ [_]u8{0x11} ** 32 },
        .{ .value = 8000, .script_pubkey = &[_]u8{ 0x51, 0x20 } ++ [_]u8{0x22} ** 32 },
    };

    const exec: ExecData = .{ .tapleaf_hash = [_]u8{0x33} ** 32, .codesep_pos = 0xffffffff };
    const hash_types = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 };
    for (hash_types) |ht| {
        // SINGLE-family needs a corresponding output for input 1 (present).
        const ours = try sigMsg(a, t, 1, ht, &spent, &exec);
        defer a.free(ours);
        const keypath = try bitcointx.bip341.sigMsg(a, t, 1, ht, &spent);
        defer a.free(keypath);
        // keypath ends with spend_type=0x00; ours has spend_type=0x02 at the
        // same offset then the same tail, plus a 37-byte extension. Compare
        // everything up to (and excluding) the spend_type byte, then the
        // remainder after it.
        // Locate spend_type position: identical prefixes until then.
        // Simplest robust check: the two messages agree on every byte that
        // is not the spend_type byte and not in our appended extension.
        // We reconstruct: find first differing byte = spend_type index.
        var diff: usize = 0;
        while (diff < keypath.len and keypath[diff] == ours[diff]) : (diff += 1) {}
        try testing.expectEqual(@as(u8, 0x00), keypath[diff]); // key-path spend_type
        try testing.expectEqual(@as(u8, 0x02), ours[diff]); // script-path spend_type (no annex)
        // After the spend_type byte, the key-path tail must match ours up to
        // the key-path length; ours then has the 37-byte extension appended.
        try testing.expectEqualSlices(u8, keypath[diff + 1 ..], ours[diff + 1 .. diff + 1 + (keypath.len - diff - 1)]);
        try testing.expectEqual(keypath.len + 37, ours.len);
    }
}
