// SPDX-License-Identifier: MIT
//! ECDSA signature checking for `OP_CHECKSIG`/`OP_CHECKSIGVERIFY`/
//! `OP_CHECKMULTISIG`/`OP_CHECKMULTISIGVERIFY`: DER/pubkey encoding
//! validation (BIP62/BIP66/BIP146 flag-gated checks), sighash computation
//! (dispatched to `bitcointx`'s legacy/BIP143 algorithms by `SigVersion`),
//! and the actual curve verification.
//!
//! ## Why not `k256.sign.ecdsaVerify`
//!
//! `k256.sign.ecdsaVerify(pubkey, msg, sig)` hashes `msg` with SHA-256
//! internally (it verifies "ECDSA over SHA-256(msg)", matching
//! `std.crypto.sign.ecdsa`'s convention of taking an unhashed message).
//! Bitcoin's OP_CHECKSIG digest is different: `bitcointx.legacy.sighash`/
//! `bip143.sighash` already return the FINAL digest
//! (`sha256d(preimage)` = `SHA256(SHA256(preimage))`) that gets fed
//! directly into the ECDSA math — no further hashing. Calling
//! `k256.sign.ecdsaVerify(pk, &sighash, sig)` would hash that digest a
//! *third* time (`SHA256(SHA256(SHA256(preimage)))`), silently verifying
//! against the wrong value. `ecdsaVerifyDigest` below is
//! `k256.sign.ecdsaVerify`'s exact arithmetic with that extra hash
//! removed — verifying `sig` directly against a caller-supplied 32-byte
//! digest, which is what every consensus signature scheme (Bitcoin's
//! included) actually wants at this layer.
//!
//! Taproot key-path spending (Schnorr/BIP340 over the BIP341 sighash) does
//! NOT go through this file — it has no scriptCode/CHECKSIG opcode at all;
//! `verify.zig` calls `bip340`/`bitcointx.bip341` directly. This file is
//! ECDSA (legacy + segwit v0) only.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const k256 = @import("k256");
const flags_mod = @import("flags.zig");
const txctx = @import("txctx.zig");

pub const ScriptFlags = flags_mod.ScriptFlags;
pub const SigVersion = txctx.SigVersion;
pub const TxContext = txctx.TxContext;

pub const SigCheckError = error{
    /// BIP66: signature is not strict DER (checked when `dersig`, `low_s`,
    /// or `strictenc` is set).
    SigDer,
    /// BIP146: signature's `s` exceeds the curve half-order (checked when
    /// `low_s` is set).
    SigHighS,
    /// Sighash byte is not one of the defined types (checked when
    /// `strictenc` is set).
    SigHashtype,
    /// Public key is not a canonical compressed/uncompressed SEC1 encoding
    /// (checked when `strictenc` is set), or (segwit v0 + `witness_pubkeytype`)
    /// is not compressed.
    Pubkeytype,
} || Allocator.Error;

// ── DER / pubkey encoding checks (Bitcoin Core `interpreter.cpp`) ──────────

/// BIP66 `IsValidSignatureEncoding` — the exact structural check Bitcoin
/// Core applies, transcribed byte-for-byte (this is the canonical published
/// algorithm; see BIP66). `sig` is the FULL signature stack element,
/// INCLUDING the trailing sighash-type byte (Core's own `IsValidSignatureEncoding`
/// takes `vchSig` exactly as popped off the stack) — the length arithmetic
/// below (`sig.len - 3` / `len_r + len_s + 7`) is written against that one
/// extra trailing byte; passing DER-only bytes here undercounts by one and
/// rejects every otherwise-valid signature.
pub fn isValidSignatureEncoding(sig: []const u8) bool {
    if (sig.len < 9) return false;
    if (sig.len > 73) return false;
    if (sig[0] != 0x30) return false;
    if (sig[1] != sig.len - 3) return false;
    const len_r: usize = sig[3];
    if (5 + len_r >= sig.len) return false;
    const len_s: usize = sig[5 + len_r];
    if (len_r + len_s + 7 != sig.len) return false;
    if (sig[2] != 0x02) return false;
    if (len_r == 0) return false;
    if (sig[4] & 0x80 != 0) return false;
    if (len_r > 1 and sig[4] == 0x00 and (sig[5] & 0x80) == 0) return false;
    if (sig[len_r + 4] != 0x02) return false;
    if (len_s == 0) return false;
    if (sig[len_r + 6] & 0x80 != 0) return false;
    if (len_s > 1 and sig[len_r + 6] == 0x00 and (sig[len_r + 7] & 0x80) == 0) return false;
    return true;
}

/// A loosely-parsed `(r, s)` pair, each normalized to 32-byte big-endian
/// (leading zero bytes stripped, left-padded back to 32). Used for the
/// actual curve verification, independent of the strict BIP66 check above
/// (Bitcoin Core still *attempts* verification — via its DER parser — on
/// signatures that fail the strict check when no flag requires strictness;
/// it just fails closed on any structural problem it can't make sense of).
const RS = struct { r: [32]u8, s: [32]u8 };

fn normalizeToFieldBytes(bytes: []const u8) ?[32]u8 {
    var b = bytes;
    while (b.len > 0 and b[0] == 0) b = b[1..];
    if (b.len > 32) return null;
    var out = [_]u8{0} ** 32;
    @memcpy(out[32 - b.len ..], b);
    return out;
}

fn parseDerLoose(der: []const u8) ?RS {
    if (der.len < 8) return null;
    if (der[0] != 0x30) return null;
    var idx: usize = 1;
    if (idx >= der.len) return null;
    const seq_len = der[idx];
    idx += 1;
    if (seq_len & 0x80 != 0) return null; // long-form length: never valid for a sig-sized DER blob
    if (idx + seq_len > der.len) return null;
    if (idx >= der.len or der[idx] != 0x02) return null;
    idx += 1;
    if (idx >= der.len) return null;
    const rlen = der[idx];
    idx += 1;
    if (rlen & 0x80 != 0) return null;
    if (idx + rlen > der.len) return null;
    const rbytes = der[idx .. idx + rlen];
    idx += rlen;
    if (idx >= der.len or der[idx] != 0x02) return null;
    idx += 1;
    if (idx >= der.len) return null;
    const slen = der[idx];
    idx += 1;
    if (slen & 0x80 != 0) return null;
    if (idx + slen > der.len) return null;
    const sbytes = der[idx .. idx + slen];

    const r = normalizeToFieldBytes(rbytes) orelse return null;
    const s = normalizeToFieldBytes(sbytes) orelse return null;
    return .{ .r = r, .s = s };
}

/// secp256k1 group order `n`, halved (integer division) — BIP146's
/// `IsLowDERSignature` bound. `n` is odd so `n >> 1 == floor(n/2)`.
const half_order: u256 = k256.scalar.field_order >> 1;

/// BIP146 `IsLowDERSignature`: `s <= n/2`. Only meaningful to call on a sig
/// that already passed `isValidSignatureEncoding`.
pub fn isLowS(sig_der: []const u8) bool {
    const rs = parseDerLoose(sig_der) orelse return false;
    const s_val = std.mem.readInt(u256, &rs.s, .big);
    return s_val <= half_order;
}

/// The 7 defined sighash-type byte values (BIP62 rule 3 / Bitcoin Core
/// `IsDefinedHashtypeSignature`): `ALL`/`NONE`/`SINGLE`, each optionally
/// OR'd with `ANYONECANPAY` (`0x80`).
pub fn isDefinedHashtype(hash_type_byte: u8) bool {
    const base = hash_type_byte & ~@as(u8, 0x80);
    return base >= 1 and base <= 3;
}

/// `CPubKey::IsValid`-equivalent: compressed (33 bytes, `0x02`/`0x03`
/// prefix) or uncompressed (65 bytes, `0x04` prefix) SEC1 encoding. Hybrid
/// (`0x06`/`0x07`) and any other shape is not a canonical pubkey.
pub fn isCompressedOrUncompressedPubkey(pk: []const u8) bool {
    if (pk.len == 33 and (pk[0] == 0x02 or pk[0] == 0x03)) return true;
    if (pk.len == 65 and pk[0] == 0x04) return true;
    return false;
}

pub fn isCompressedPubkey(pk: []const u8) bool {
    return pk.len == 33 and (pk[0] == 0x02 or pk[0] == 0x03);
}

/// Runs every encoding check `flags` requires for one signature stack
/// element — `sig_with_hashtype` is the FULL element (DER bytes + trailing
/// sighash-type byte, exactly as popped); `sig_der` is that same slice
/// minus the last byte, for the checks that want pure DER content. Returns
/// normally if everything required passed (a script MAY still go on to
/// fail the actual crypto check; that is not this function's job).
pub fn checkSignatureEncoding(sig_with_hashtype: []const u8, sig_der: []const u8, hash_type_byte: u8, flags: ScriptFlags) SigCheckError!void {
    // Bitcoin Core `CheckSignatureEncoding`'s own first line: an empty
    // signature trivially passes every encoding check (it simply has
    // nothing to check) -- this is NOT the same as the signature failing
    // to verify, which is decided later, after `checkPubkeyEncoding` (a
    // SEPARATE, unconditional check) has also had its say. See
    // `checkEcdsaSig`'s doc comment for why this ordering matters: a
    // malformed pubkey next to an empty signature must still fail as
    // `Pubkeytype`, never silently pass through as "verify=false".
    if (sig_with_hashtype.len == 0) return;
    if (flags.dersig or flags.low_s or flags.strictenc) {
        if (!isValidSignatureEncoding(sig_with_hashtype)) return error.SigDer;
    }
    if (flags.low_s) {
        if (!isLowS(sig_der)) return error.SigHighS;
    }
    if (flags.strictenc) {
        if (!isDefinedHashtype(hash_type_byte)) return error.SigHashtype;
    }
}

pub fn checkPubkeyEncoding(pubkey: []const u8, sig_version: SigVersion, flags: ScriptFlags) SigCheckError!void {
    if (flags.strictenc and !isCompressedOrUncompressedPubkey(pubkey)) return error.Pubkeytype;
    if (flags.witness_pubkeytype and sig_version == .witness_v0 and !isCompressedPubkey(pubkey)) return error.Pubkeytype;
}

// ── the actual ECDSA check ───────────────────────────────────────────────

pub const CheckSigError = SigCheckError || bitcointx.legacy.LegacyError || bitcointx.bip143.Bip143Error;

/// `int(bytes32) mod n` — same reduction `k256.sign` uses internally.
fn reduceToScalar(bytes32: [32]u8) k256.Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return k256.Scalar.fromBytes48(wide, .big);
}

/// ECDSA/secp256k1 verification against an already-computed 32-byte digest
/// (module doc comment: "Why not `k256.sign.ecdsaVerify`"). Variable-time
/// (every input is public — the pubkey, the digest, and the signature all
/// come from the script/transaction being verified, never a secret).
fn ecdsaVerifyDigest(pubkey_sec1: []const u8, digest: [32]u8, sig_rs: [64]u8) bool {
    const Q = k256.Secp256k1.fromSec1(pubkey_sec1) catch return false;
    const r = k256.Scalar.fromBytes(sig_rs[0..32].*, .big) catch return false;
    const s = k256.Scalar.fromBytes(sig_rs[32..64].*, .big) catch return false;
    if (r.isZero() or s.isZero()) return false;

    const e = reduceToScalar(digest);
    const sinv = s.invert();
    const uu1 = e.mul(sinv);
    const uu2 = r.mul(sinv);

    const R = k256.Secp256k1.mulDoubleBasePublic(
        k256.Secp256k1.basePoint,
        uu1.toBytes(.big),
        Q,
        uu2.toBytes(.big),
        .big,
    ) catch return false;
    const v = reduceToScalar(R.affineCoordinates().x.toBytes(.big));
    return v.equivalent(r);
}

/// Verifies one ECDSA signature+pubkey pair over the sighash of `ctx`'s
/// input, using `script_code` (the already-CODESEPARATOR-trimmed subScript
/// — see `interpreter.zig`) and `sig_version` to select the legacy vs.
/// BIP143 sighash algorithm. `sig_with_hashtype` is the raw signature stack
/// element as popped (DER bytes + one trailing hashtype byte); an empty
/// slice is a well-formed "no signature" that simply verifies false.
///
/// Returns `true`/`false` for a completed cryptographic verification;
/// returns a `SigCheckError` only for a flag-gated ENCODING violation
/// (which Bitcoin Core treats as an unconditional script failure, not a
/// mere "this signature didn't verify"). Encoding is checked for BOTH the
/// signature AND the pubkey even when the signature is empty (Bitcoin
/// Core: `fSuccess = CheckSignatureEncoding(...) && CheckPubKeyEncoding(...)`
/// — two independent, unconditionally-run checks whose result is ANDed,
/// not a short-circuit on the signature alone) — a malformed pubkey next
/// to a deliberately-empty signature must still fail as `Pubkeytype`, not
/// silently as a plain "didn't verify".
pub fn checkEcdsaSig(
    allocator: Allocator,
    sig_with_hashtype: []const u8,
    pubkey: []const u8,
    script_code: []const u8,
    ctx: TxContext,
    sig_version: SigVersion,
    flags: ScriptFlags,
) CheckSigError!bool {
    const sig_der = if (sig_with_hashtype.len == 0) sig_with_hashtype else sig_with_hashtype[0 .. sig_with_hashtype.len - 1];
    const hash_type_byte: u8 = if (sig_with_hashtype.len == 0) 0 else sig_with_hashtype[sig_with_hashtype.len - 1];

    try checkSignatureEncoding(sig_with_hashtype, sig_der, hash_type_byte, flags);
    try checkPubkeyEncoding(pubkey, sig_version, flags);

    if (sig_with_hashtype.len == 0) return false;

    // A structurally-invalid-but-not-flag-rejected signature (encoding
    // checks above were skipped or passed leniently) simply fails to parse
    // here -- verify=false, not a script error, matching Bitcoin Core's
    // "DER-parse-then-verify" library call ffailing closed.
    const rs = parseDerLoose(sig_der) orelse return false;

    const hash_type: u32 = hash_type_byte;
    const sighash: [32]u8 = switch (sig_version) {
        .base => try bitcointx.legacy.sighash(allocator, ctx.tx, ctx.input_index, script_code, hash_type),
        .witness_v0 => try bitcointx.bip143.sighash(allocator, ctx.tx, ctx.input_index, script_code, ctx.amountSats(), hash_type),
        // Tapscript CHECKSIG uses BIP340 Schnorr over the BIP341/342 sighash
        // (`tapscript.zig`), never this ECDSA path — `interpreter.zig`
        // dispatches `.tapscript` away from `checkEcdsaSig` entirely.
        .tapscript => unreachable,
    };

    var sig_rs: [64]u8 = undefined;
    sig_rs[0..32].* = rs.r;
    sig_rs[32..64].* = rs.s;
    return ecdsaVerifyDigest(pubkey, sighash, sig_rs);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "isValidSignatureEncoding accepts a real DER sig + hashtype byte and rejects truncation/garbage" {
    // A syntactically valid minimal DER sig (30 44 02 20 <32 r-bytes> 02 20
    // <32 s-bytes>) PLUS a trailing sighash-type byte (71 bytes total) --
    // Core's IsValidSignatureEncoding takes the full popped stack element,
    // hashtype included (see this function's doc comment).
    var sig: [71]u8 = undefined;
    sig[0] = 0x30;
    sig[1] = 68;
    sig[2] = 0x02;
    sig[3] = 32;
    @memset(sig[4..36], 0x11);
    sig[36] = 0x02;
    sig[37] = 32;
    @memset(sig[38..70], 0x22);
    sig[70] = 0x01; // SIGHASH_ALL
    try testing.expect(isValidSignatureEncoding(&sig));

    try testing.expect(!isValidSignatureEncoding(sig[0..40])); // truncated
    try testing.expect(!isValidSignatureEncoding(&.{ 1, 2, 3 })); // way too short
    var bad = sig;
    bad[0] = 0x31; // wrong leading tag
    try testing.expect(!isValidSignatureEncoding(&bad));
}

test "isLowS: exactly half-order boundary" {
    // s = half_order -> low (<=). s = half_order+1 -> high.
    var sig_lo: [70]u8 = undefined;
    sig_lo[0] = 0x30;
    sig_lo[1] = 68;
    sig_lo[2] = 0x02;
    sig_lo[3] = 32;
    @memset(sig_lo[4..36], 0x01); // r doesn't matter for isLowS
    sig_lo[36] = 0x02;
    sig_lo[37] = 32;
    std.mem.writeInt(u256, sig_lo[38..70], half_order, .big);
    try testing.expect(isLowS(&sig_lo));

    var sig_hi = sig_lo;
    std.mem.writeInt(u256, sig_hi[38..70], half_order + 1, .big);
    try testing.expect(!isLowS(&sig_hi));
}

test "isDefinedHashtype accepts ALL/NONE/SINGLE with/without ANYONECANPAY, rejects 0 and 4+" {
    try testing.expect(isDefinedHashtype(0x01));
    try testing.expect(isDefinedHashtype(0x02));
    try testing.expect(isDefinedHashtype(0x03));
    try testing.expect(isDefinedHashtype(0x81));
    try testing.expect(isDefinedHashtype(0x83));
    try testing.expect(!isDefinedHashtype(0x00));
    try testing.expect(!isDefinedHashtype(0x04));
    try testing.expect(!isDefinedHashtype(0x80));
}

test "pubkey encoding: compressed/uncompressed accepted, hybrid/garbage rejected" {
    var comp: [33]u8 = undefined;
    comp[0] = 0x02;
    try testing.expect(isCompressedOrUncompressedPubkey(&comp));
    try testing.expect(isCompressedPubkey(&comp));

    var uncomp: [65]u8 = undefined;
    uncomp[0] = 0x04;
    try testing.expect(isCompressedOrUncompressedPubkey(&uncomp));
    try testing.expect(!isCompressedPubkey(&uncomp));

    var hybrid: [65]u8 = undefined;
    hybrid[0] = 0x06;
    try testing.expect(!isCompressedOrUncompressedPubkey(&hybrid));

    try testing.expect(!isCompressedOrUncompressedPubkey(&.{ 0x02, 0x01 })); // wrong length
}

test "checkEcdsaSig: empty signature verifies false with no allocation and no error" {
    var t: bitcointx.Transaction = .{
        .version = 1,
        .vin = @constCast(&[_]bitcointx.TxIn{.{ .prevout = .{ .txid = [_]u8{0} ** 32, .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff }}),
        .vout = &.{},
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const spent = [_]bitcointx.TxOut{.{ .value = 1000, .script_pubkey = &.{} }};
    const ctx: TxContext = .{ .tx = t, .input_index = 0, .spent_outputs = &spent };
    var fail_alloc = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const ok = try checkEcdsaSig(fail_alloc.allocator(), &.{}, &([_]u8{0x02} ** 33), &.{}, ctx, .base, ScriptFlags.none);
    try testing.expect(!ok);
    _ = &t;
}
