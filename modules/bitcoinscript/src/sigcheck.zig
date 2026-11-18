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
//! against the wrong value. **`k256.sign.ecdsaVerifyPrehashed`** (A1 `k256`
//! G4, perf pass, round-2 decision Q4) is `ecdsaVerify`'s exact arithmetic
//! with that extra hash removed — verifying `sig` directly against a
//! caller-supplied 32-byte digest, which is what every consensus signature
//! scheme (Bitcoin's included) actually wants at this layer. This file used
//! to carry its own copy of that arithmetic (`reduceToScalar` +
//! `ecdsaVerifyDigest`); it now calls the shared function instead, so a fix
//! to the verify core (e.g. a Wycheproof-anchored `r`/`s ≥ n` guard) only
//! has to be made once.
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
    var out = @as([32]u8, @splat(0));
    @memcpy(out[32 - b.len ..], b);
    return out;
}

/// Reads one lax DER INTEGER at `der[pos.*..]` (Bitcoin Core `pubkey.cpp`
/// `ecdsa_signature_parse_der_lax`, the `R` / `S` blocks): tag `0x02`, then a
/// length that is either short-form or long-form (`0x80 | n` followed by `n`
/// big-endian length bytes, of which leading zero bytes are skipped and at most
/// three significant ones may remain); the content must lie inside `der`.
/// Returns the content bytes (not yet trimmed) and advances `pos` past them.
fn readLaxInteger(der: []const u8, pos: *usize) ?[]const u8 {
    var p = pos.*;
    if (p == der.len or der[p] != 0x02) return null;
    p += 1;
    if (p == der.len) return null;
    var lenbyte: usize = der[p];
    p += 1;
    var len: usize = undefined;
    if (lenbyte & 0x80 != 0) {
        lenbyte -= 0x80;
        if (lenbyte > der.len - p) return null;
        while (lenbyte > 0 and der[p] == 0) {
            p += 1;
            lenbyte -= 1;
        }
        if (lenbyte >= 4) return null;
        len = 0;
        while (lenbyte > 0) {
            len = (len << 8) + der[p];
            p += 1;
            lenbyte -= 1;
        }
    } else {
        len = lenbyte;
    }
    if (len > der.len - p) return null;
    const out = der[p .. p + len];
    pos.* = p + len;
    return out;
}

/// Bitcoin Core's LAX DER parser (`ecdsa_signature_parse_der_lax`), which
/// `CPubKey::Verify` applies to every signature that no flag forced through
/// the strict BIP66 check — historic blocks hold signatures only this parser
/// accepts, so a consensus engine run WITHOUT `dersig` must accept the same
/// set. What it accepts beyond strict DER: long-form lengths anywhere, a
/// sequence length byte that is never checked against the data, integers with
/// any number of leading zero bytes and no sign padding (R and S are read as
/// unsigned), and trailing bytes after S. What it rejects: a wrong tag, a
/// length that overruns the input, a long-form length with 4 or more
/// significant bytes, and an R or S that is longer than 32 bytes once leading
/// zeros are trimmed (Core turns that into the all-zero, never-valid signature;
/// here it is `null`, which callers treat as "does not verify").
fn parseDerLoose(der: []const u8) ?RS {
    var pos: usize = 0;
    if (pos == der.len or der[pos] != 0x30) return null;
    pos += 1;
    if (pos == der.len) return null;
    var lenbyte: usize = der[pos];
    pos += 1;
    if (lenbyte & 0x80 != 0) {
        lenbyte -= 0x80;
        if (lenbyte > der.len - pos) return null;
        pos += lenbyte; // the sequence length is skipped, never checked
    }
    const rbytes = readLaxInteger(der, &pos) orelse return null;
    const sbytes = readLaxInteger(der, &pos) orelse return null;
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
        // The legacy algorithm has no per-transaction factor to hoist — its
        // digest depends on the input index and the scriptCode. That is the
        // defect BIP143 was written to retire, not an omission here.
        .base => try bitcointx.legacy.sighash(allocator, ctx.tx, ctx.input_index, script_code, hash_type),
        // BIP143: reuse the caller's per-transaction midstates when it has
        // them. Byte-identical to the uncached call (`bitcointx` routes both
        // through one selection body); the difference is O(1) commitment
        // hashes per CHECKSIG instead of O(vin.len + vout.len).
        .witness_v0 => if (ctx.segwitV0Precomputed()) |pre|
            try bitcointx.bip143.sighashWith(allocator, pre, ctx.tx, ctx.input_index, script_code, ctx.amountSats(), hash_type)
        else
            try bitcointx.bip143.sighash(allocator, ctx.tx, ctx.input_index, script_code, ctx.amountSats(), hash_type),
        // Tapscript CHECKSIG uses BIP340 Schnorr over the BIP341/342 sighash
        // (`tapscript.zig`), never this ECDSA path — `interpreter.zig`
        // dispatches `.tapscript` away from `checkEcdsaSig` entirely.
        .tapscript => unreachable,
    };

    var sig_rs: [64]u8 = undefined;
    sig_rs[0..32].* = rs.r;
    sig_rs[32..64].* = rs.s;
    return k256.sign.ecdsaVerifyPrehashed(pubkey, sighash, sig_rs);
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
        .vin = @constCast(&[_]bitcointx.TxIn{.{ .prevout = .{ .txid = @as([32]u8, @splat(0)), .vout = 0 }, .script_sig = &.{}, .sequence = 0xffffffff }}),
        .vout = &.{},
        .witness = &.{},
        .locktime = 0,
        .has_witness = false,
    };
    const spent = [_]bitcointx.TxOut{.{ .value = 1000, .script_pubkey = &.{} }};
    const ctx: TxContext = .{ .tx = t, .input_index = 0, .spent_outputs = &spent };
    var fail_alloc = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const ok = try checkEcdsaSig(fail_alloc.allocator(), &.{}, &(@as([33]u8, @splat(0x02))), &.{}, ctx, .base, ScriptFlags.none);
    try testing.expect(!ok);
    _ = &t;
}

// ── whole-module mutation audit 2026-11-17 ───────────────────────────────

fn rsOf(r: u8, s: u8) RS {
    var out: RS = .{ .r = @as([32]u8, @splat(0)), .s = @as([32]u8, @splat(0)) };
    out.r[31] = r;
    out.s[31] = s;
    return out;
}

test "isValidSignatureEncoding: BIP66 length rules at their edges" {
    // minimal valid shapes: R = 0 and S = 0 are structurally fine (one byte each)
    try testing.expect(isValidSignatureEncoding(&.{ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x01 }));
    try testing.expect(isValidSignatureEncoding(&.{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x01 }));
    // a 74-byte element (R 34 bytes, S 33 bytes, both validly padded) is one too long
    var long: [74]u8 = undefined;
    long[0] = 0x30;
    long[1] = 71;
    long[2] = 0x02;
    long[3] = 34;
    long[4] = 0x00;
    long[5] = 0x80;
    @memset(long[6..38], 0x11);
    long[38] = 0x02;
    long[39] = 33;
    long[40] = 0x00;
    long[41] = 0x80;
    @memset(long[42..73], 0x22);
    long[73] = 0x01;
    try testing.expect(!isValidSignatureEncoding(&long));
    // the DER total-length byte must match
    var sig: [71]u8 = undefined;
    sig[0] = 0x30;
    sig[1] = 68;
    sig[2] = 0x02;
    sig[3] = 32;
    @memset(sig[4..36], 0x11);
    sig[36] = 0x02;
    sig[37] = 32;
    @memset(sig[38..70], 0x22);
    sig[70] = 0x01;
    try testing.expect(isValidSignatureEncoding(&sig));
    sig[1] = 67;
    try testing.expect(!isValidSignatureEncoding(&sig));
    sig[1] = 68;
    // a declared R length that runs to / past the end of the element
    try testing.expect(!isValidSignatureEncoding(&.{ 0x30, 0x06, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01 }));
    try testing.expect(!isValidSignatureEncoding(&.{ 0x30, 0x07, 0x02, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }));
}

test "parseDerLoose: Bitcoin Core's lax DER parser, rule by rule" {
    const t = rsOf;
    // canonical shape
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07 }).?);
    // the sequence length byte is never checked: too long, too short, zero
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x7f, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07 }).?);
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x00, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07 }).?);
    // a long-form sequence length: its bytes are skipped whatever they hold
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x81, 0xee, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07 }).?);
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x82, 0x01, 0x02, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07 }).?);
    // ... but they must be present
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x84, 0x00, 0x00, 0x00 }));
    // long-form integer lengths, with and without leading zero length bytes
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x0a, 0x02, 0x81, 0x01, 0x05, 0x02, 0x81, 0x01, 0x07 }).?);
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x0a, 0x02, 0x83, 0x00, 0x00, 0x01, 0x05, 0x02, 0x82, 0x00, 0x01, 0x07 }).?);
    // a long-form length with 4 significant bytes is refused (Core: lenbyte >= 4), 3 are fine
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x0a, 0x02, 0x84, 0x01, 0x00, 0x00, 0x00, 0x05 }));
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x0a, 0x02, 0x01, 0x05, 0x02, 0x84, 0x01, 0x00, 0x00, 0x00, 0x07 }));
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x00, 0x02, 0x83, 0x00, 0x00, 0x01, 0x05, 0x02, 0x01, 0x07 }).?);
    // a long-form length byte count that runs past the input
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x00, 0x02, 0x82, 0x01 }));
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x00, 0x02, 0x01, 0x05, 0x02, 0x82, 0x01 }));
    // trailing bytes after S, leading zeros on either integer, no sign padding
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07, 0xde, 0xad }).?);
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x08, 0x02, 0x03, 0x00, 0x00, 0x05, 0x02, 0x02, 0x00, 0x07 }).?);
    const hi = parseDerLoose(&.{ 0x30, 0x06, 0x02, 0x01, 0xff, 0x02, 0x01, 0x80 }).?; // "negative" values read as unsigned
    try testing.expectEqual(@as(u8, 0xff), hi.r[31]);
    try testing.expectEqual(@as(u8, 0x80), hi.s[31]);
    // an empty R or S is the value zero
    try testing.expectEqual(t(0, 7), parseDerLoose(&.{ 0x30, 0x04, 0x02, 0x00, 0x02, 0x01, 0x07 }).?);
    // 32 significant bytes fit, 33 overflow
    var buf: [6 + 33 + 3]u8 = undefined;
    buf[0] = 0x30;
    buf[1] = 0x00;
    buf[2] = 0x02;
    buf[3] = 33;
    @memset(buf[4..37], 0x01);
    buf[37] = 0x02;
    buf[38] = 0x01;
    buf[39] = 0x07;
    try testing.expectEqual(@as(?RS, null), parseDerLoose(buf[0..40]));
    buf[3] = 32;
    @memset(buf[4..36], 0x01);
    buf[36] = 0x02;
    buf[37] = 0x01;
    buf[38] = 0x07;
    try testing.expect(parseDerLoose(buf[0..39]) != null);
    // wrong tags and every kind of truncation
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x31, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07 }));
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x06, 0x03, 0x01, 0x05, 0x02, 0x01, 0x07 }));
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x03, 0x01, 0x07 }));
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x06, 0x02, 0x09, 0x05, 0x02, 0x01, 0x07 })); // R overruns
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x09, 0x07 })); // S overruns
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x02, 0x07 })); // S one short
    try testing.expectEqual(t(5, 7), parseDerLoose(&.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07 }).?);
    const whole = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07 };
    var n: usize = 0;
    while (n < whole.len) : (n += 1) try testing.expectEqual(@as(?RS, null), parseDerLoose(whole[0..n]));
    // R exactly fills the input: no room for S
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x00, 0x02, 0x01, 0x05 }));
}

test "isLowS: lax parse, unparsable is not low, oversized integers are not low" {
    var sig: [70]u8 = undefined;
    sig[0] = 0x30;
    sig[1] = 68;
    sig[2] = 0x02;
    sig[3] = 32;
    @memset(sig[4..36], 0x01);
    sig[36] = 0x02;
    sig[37] = 32;
    std.mem.writeInt(u256, sig[38..70], 5, .big);
    try testing.expect(isLowS(&sig));
    try testing.expect(!isLowS("abc"));
    try testing.expect(!isLowS(&.{}));
    // S with 33 significant bytes
    var wide: [8 + 33]u8 = undefined;
    @memcpy(wide[0..8], &[_]u8{ 0x30, 0x00, 0x02, 0x01, 0x01, 0x02, 33, 0x01 });
    @memset(wide[7..], 0x01);
    try testing.expect(!isLowS(&wide));
}

test "pubkey shape predicates reject over-long keys" {
    var k66: [66]u8 = @splat(0x11);
    k66[0] = 0x04;
    try testing.expect(!isCompressedOrUncompressedPubkey(&k66));
    var k34: [34]u8 = @splat(0x11);
    k34[0] = 0x02;
    try testing.expect(!isCompressedPubkey(&k34));
    try testing.expect(!isCompressedOrUncompressedPubkey(&k34));
}

test "checkSignatureEncoding / checkPubkeyEncoding: each flag gates exactly its own rule" {
    const garbage = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    // DER shape is demanded by dersig, low_s and strictenc each on its own
    try testing.expectError(error.SigDer, checkSignatureEncoding(&garbage, garbage[0..11], 12, .{ .low_s = true }));
    try testing.expectError(error.SigDer, checkSignatureEncoding(&garbage, garbage[0..11], 12, .{ .dersig = true }));
    try testing.expectError(error.SigDer, checkSignatureEncoding(&garbage, garbage[0..11], 12, .{ .strictenc = true }));
    try checkSignatureEncoding(&garbage, garbage[0..11], 12, .{});
    // hashtype is only checked under strictenc
    const der = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00 };
    try checkSignatureEncoding(&der, der[0..8], 0x00, .{ .dersig = true });
    try checkSignatureEncoding(&der, der[0..8], 0x00, .{});
    try testing.expectError(error.SigHashtype, checkSignatureEncoding(&der, der[0..8], 0x00, .{ .strictenc = true }));
    // an uncompressed key is fine under strictenc, and under the witness rule only in witness v0
    var unc: [65]u8 = @splat(0x22);
    unc[0] = 0x04;
    try checkPubkeyEncoding(&unc, .base, .{ .strictenc = true });
    try checkPubkeyEncoding(&unc, .base, .{ .witness_pubkeytype = true });
    try testing.expectError(error.Pubkeytype, checkPubkeyEncoding(&unc, .witness_v0, .{ .witness_pubkeytype = true }));
    try checkPubkeyEncoding(&unc, .witness_v0, .{});
    var hybrid = unc;
    hybrid[0] = 0x06;
    try testing.expectError(error.Pubkeytype, checkPubkeyEncoding(&hybrid, .base, .{ .strictenc = true }));
}

test "parseDerLoose: long-form lengths at their exact fits and with 2- and 3-byte values" {
    // the S length bytes are the last bytes of the input: a zero-length S, accepted by Core
    try testing.expectEqual(rsOf(5, 0), parseDerLoose(&.{ 0x30, 0x00, 0x02, 0x01, 0x05, 0x02, 0x81, 0x00 }).?);
    // the zero skip stops at the declared number of length bytes, not at the next non-zero byte
    try testing.expectEqual(@as(?RS, null), parseDerLoose(&.{ 0x30, 0x00, 0x02, 0x81, 0x00, 0x00 }));
    // multi-byte lengths are big-endian (0x0102 = 258, 0x010000 = 65536)
    inline for (.{ .{ 258, &[_]u8{ 0x82, 0x01, 0x02 } }, .{ 65536, &[_]u8{ 0x83, 0x01, 0x00, 0x00 } } }) |c| {
        const buf = try testing.allocator.alloc(u8, 3 + c[1].len + c[0] + 3);
        defer testing.allocator.free(buf);
        @memset(buf, 0);
        @memcpy(buf[0..3], &[_]u8{ 0x30, 0x00, 0x02 });
        @memcpy(buf[3..][0..c[1].len], c[1]);
        @memcpy(buf[buf.len - 3 ..], &[_]u8{ 0x02, 0x01, 0x07 });
        try testing.expectEqual(rsOf(0, 7), parseDerLoose(buf).?);
    }
}
