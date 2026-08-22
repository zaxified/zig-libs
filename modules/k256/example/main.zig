// SPDX-License-Identifier: MIT

//! What a Lightning-style consumer does with `k256`: derive a public key,
//! produce a BIP340 Schnorr signature over a message (the Taproot-spend
//! shape) and verify it, then separately produce an RFC 6979 deterministic
//! ECDSA signature and recover the signer's public key from the compact
//! signature alone — the operation `sign.zig`'s BIP340 path does not cover.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const k256 = @import("k256");

pub fn main() !void {
    // A fixed, valid (0 < d < n) private key — deterministic example, not
    // real key material.
    const privkey = [_]u8{0x01} ** 31 ++ [_]u8{0x23};

    const pubkey_point = try k256.Secp256k1.combMulBase(privkey, .big);
    const pubkey_sec1 = k256.Secp256k1.toCompressedSec1(pubkey_point);
    const pubkey_xonly = pubkey_point.affineCoordinates().x.toBytes(.big);

    const msg = "spend txid=9f2c...:0 amount=42000sat";

    // ── BIP340 Schnorr: sign, verify, then show a tampered message fails ──
    const aux_rand = [_]u8{0xAB} ** 32;
    const schnorr_sig = try k256.sign.bip340Sign(privkey, msg, aux_rand);
    const schnorr_ok = k256.sign.bip340Verify(pubkey_xonly, msg, schnorr_sig);
    std.debug.print("bip340 verify (genuine msg): {}\n", .{schnorr_ok});
    if (!schnorr_ok) return error.VerifyFailed;

    const tampered_ok = k256.sign.bip340Verify(pubkey_xonly, "spend txid=9f2c...:0 amount=99999sat", schnorr_sig);
    std.debug.print("bip340 verify (tampered msg): {}\n", .{tampered_ok});
    if (tampered_ok) return error.ShouldHaveFailed;

    // `bip340Sign` names its precondition failure: an all-zero secret key.
    _ = k256.sign.bip340Sign([_]u8{0} ** 32, msg, aux_rand) catch |err| switch (err) {
        error.InvalidSecretKey => std.debug.print("zero secret key correctly rejected\n", .{}),
        error.InvalidNonce => return err,
    };

    // ── RFC 6979 ECDSA sign + public-key recovery ──────────────────────
    var hash32: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &hash32, .{});

    const compact_sig = try k256.ecdsa_recover.sign(privkey, hash32);
    std.debug.print("compact sig: recid={d} low-S={}\n", .{
        compact_sig.recid, k256.ecdsa_recover.isLowS(compact_sig.s),
    });

    const recovered = try k256.ecdsa_recover.recoverPubkey(hash32, compact_sig.r, compact_sig.s, compact_sig.recid);
    std.debug.print("recovered pubkey matches signer: {}\n", .{recovered.equivalent(pubkey_point)});
    if (!recovered.equivalent(pubkey_point)) return error.RecoveryMismatch;

    // The recovered signature also verifies directly against the SEC1
    // pubkey bytes, low-S enforced (BIP62-style canonical form).
    const sig_rs = compact_sig.r ++ compact_sig.s;
    const ecdsa_ok = k256.sign.ecdsaVerifyLowS(&pubkey_sec1, msg, sig_rs);
    std.debug.print("ecdsaVerifyLowS: {}\n", .{ecdsa_ok});
    if (!ecdsa_ok) return error.VerifyFailed;

    // `recoverPubkey` names a garbage-input failure by kind: an `r` of zero
    // is rejected as a malformed scalar rather than silently recovering a
    // bogus key.
    _ = k256.ecdsa_recover.recoverPubkey(hash32, [_]u8{0} ** 32, compact_sig.s, compact_sig.recid) catch |err| switch (err) {
        error.InvalidScalar => std.debug.print("zero r correctly rejected\n", .{}),
        error.NotSquare, error.InvalidPoint, error.IdentityElement => return err,
    };
}
