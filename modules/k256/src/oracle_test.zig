// SPDX-License-Identifier: MIT

//! oracle_test — the std-anchored differential harness.
//!
//! The field/group/scalar differentials live co-located in `field.zig`,
//! `group.zig`, and `scalar.zig` (each `k256.op == std.op` on thousands of
//! random inputs). This file adds the two things that need their own surface:
//!
//!   1. **ECDSA end-to-end vs std's SIGNER.** `sign.ecdsaVerify` must accept
//!      every signature produced by `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`
//!      and reject tampered ones — proving k256's verify path (double-base
//!      multiply + scalar inverse + x-mod-n) agrees with std end-to-end.
//!   2. **The GATED Fable-core differentials.** Both SKIP until their gate flips
//!      (a skip is NOT a green light); when a Fable agent implements a core they
//!      light up and pin it bit-for-bit to the proven portable path.

const std = @import("std");
const gate = @import("gate.zig");
const fast_core = @import("fast_core.zig");
const field = @import("field.zig");
const group = @import("group.zig");
const sign = @import("sign.zig");

const Secp256k1 = group.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

test "ECDSA: k256 verifies every std-produced signature, rejects tampering" {
    var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xEC_D5A_0011);
    const rand = prng.random();

    var i: usize = 0;
    while (i < 200) : (i += 1) {
        rand.bytes(&seed);
        const kp = Ecdsa.KeyPair.generateDeterministic(seed) catch continue;

        var msg: [40]u8 = undefined;
        rand.bytes(&msg);
        const sig = kp.sign(&msg, null) catch continue; // deterministic (RFC6979)
        const sig_rs = sig.toBytes();
        const pk_sec1 = kp.public_key.toUncompressedSec1();

        // k256 must accept the genuine signature (both SEC1 encodings).
        try std.testing.expect(sign.ecdsaVerify(&pk_sec1, &msg, sig_rs));
        const pk_compressed = kp.public_key.p.toCompressedSec1();
        try std.testing.expect(sign.ecdsaVerify(&pk_compressed, &msg, sig_rs));

        // Tamper with one message byte → must reject.
        var bad_msg = msg;
        bad_msg[0] ^= 0x01;
        try std.testing.expect(!sign.ecdsaVerify(&pk_sec1, &bad_msg, sig_rs));

        // Tamper with one signature byte → must reject.
        var bad_sig = sig_rs;
        bad_sig[10] ^= 0x01;
        try std.testing.expect(!sign.ecdsaVerify(&pk_sec1, &msg, bad_sig));
    }
}

// ── gated Fable-core differentials (SKIP ≠ pass) ─────────────────────────────

test "GATED differential: fast_core.fieldMul/fieldSq == portable Solinas" {
    if (!gate.field_asm_implemented) return error.SkipZigTest; // core not filled
    if (!fast_core.supported) return error.SkipZigTest; // non-amd64 target

    var prng = std.Random.DefaultPrng.init(0xA5_F1E1D_01);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 5000) : (i += 1) {
        var ab: [32]u8 = undefined;
        var bb: [32]u8 = undefined;
        rand.bytes(&ab);
        rand.bytes(&bb);
        const a = field.Fe.fromBytes(ab, .big) catch continue;
        const b = field.Fe.fromBytes(bb, .big) catch continue;

        const want_mul = field.mulPortable(a.limbs, b.limbs);
        var got_mul: [4]u64 = undefined;
        fast_core.fieldMul(&got_mul, &a.limbs, &b.limbs);
        try std.testing.expectEqualSlices(u64, &want_mul, &got_mul);

        const want_sq = field.sqPortable(a.limbs);
        var got_sq: [4]u64 = undefined;
        fast_core.fieldSq(&got_sq, &a.limbs);
        try std.testing.expectEqualSlices(u64, &want_sq, &got_sq);
    }
}

test "GATED differential: group.mulPublicGlv == plain scalar multiply" {
    if (!gate.glv_scalarmul_implemented) return error.SkipZigTest; // core not filled

    var prng = std.Random.DefaultPrng.init(0x61F_5CA1A2);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        var kb: [32]u8 = undefined;
        var sb: [32]u8 = undefined;
        rand.bytes(&kb);
        rand.bytes(&sb);
        const p = Secp256k1.basePoint.mul(kb, .big) catch continue;
        const want = p.mul(sb, .big) catch continue; // proven CT double-and-add
        const got = Secp256k1.mulPublicGlv(p, sb, .big) catch continue;
        try std.testing.expect(want.equivalent(got));
    }
}
