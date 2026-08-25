// SPDX-License-Identifier: MIT

//! oracle_test — the std-anchored differential harness.
//!
//! The field/group differentials live co-located in `field.zig` and `group.zig`
//! (each `p256.op == std.op` on thousands of random inputs). This file adds the
//! things that need their own surface:
//!
//!   1. **ECDSA end-to-end vs std's SIGNER + VERIFIER.** `sign.ecdsaVerify` must
//!      accept every signature produced by
//!      `std.crypto.sign.ecdsa.EcdsaP256Sha256` and reject tampered ones; and
//!      every signature `sign.ecdsaSign` produces (random key + nonce) must be
//!      accepted by BOTH p256 and std — proving sign+verify agree with std
//!      end-to-end (the double-base multiply + scalar inverse + x-mod-n path).
//!   2. **The GATED Fable-core differentials** — LIVE (both gates are now
//!      `true`). They pin the amd64 field core / the fast scalar multiplies
//!      bit-for-bit to the proven portable paths + std. On a non-amd64 host the
//!      field differential skips — a skip there means "core not present on this
//!      build", NOT a green light.

const std = @import("std");
const gate = @import("gate.zig");
const fast_core = @import("fast_core.zig");
const field = @import("field.zig");
const group = @import("group.zig");
const sign = @import("sign.zig");

const P256 = group.P256;
const StdEcdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const StdCurve = std.crypto.ecc.P256;

test "ECDSA: p256 verifies every std-produced signature, rejects tampering" {
    var seed: [StdEcdsa.KeyPair.seed_length]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xEC_D5A_9256);
    const rand = prng.random();

    var i: usize = 0;
    while (i < 200) : (i += 1) {
        rand.bytes(&seed);
        const kp = StdEcdsa.KeyPair.generateDeterministic(seed) catch continue;

        var msg: [40]u8 = undefined;
        rand.bytes(&msg);
        const sig = kp.sign(&msg, null) catch continue; // std deterministic nonce
        const sig_rs = sig.toBytes();
        const pk_sec1 = kp.public_key.toUncompressedSec1();

        // p256 must accept the genuine signature (both SEC1 encodings).
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

test "ECDSA: p256-produced signatures verify under BOTH p256 and std" {
    var prng = std.Random.DefaultPrng.init(0x516E_9256);
    const rand = prng.random();

    var produced: usize = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        var sk: [32]u8 = undefined;
        var k: [32]u8 = undefined;
        var msg: [24]u8 = undefined;
        rand.bytes(&sk);
        rand.bytes(&k);
        rand.bytes(&msg);

        const sig = sign.ecdsaSign(sk, &msg, k) catch continue; // skip degenerate k
        produced += 1;

        // p256's own verifier accepts it.
        const pk = (P256.combMulBase(sk, .big) catch continue).toUncompressedSec1();
        try std.testing.expect(sign.ecdsaVerify(&pk, &msg, sig));

        // std's independent verifier accepts the SAME signature + key.
        const std_pk = try StdEcdsa.PublicKey.fromSec1(&pk);
        try StdEcdsa.Signature.fromBytes(sig).verify(&msg, std_pk);
    }
    // Sanity: the random nonces almost never degenerate; make sure we actually
    // exercised the sign path rather than skipping everything.
    try std.testing.expect(produced > 150);
}

// ── gated Fable-core differentials (LIVE: both gates on; SKIP ≠ pass) ─────────

fn eqAffineStd(k: P256, s: StdCurve) !void {
    const ka = k.affineCoordinates();
    const sa = s.affineCoordinates();
    try std.testing.expectEqualSlices(u8, &sa.x.toBytes(.big), &ka.x.toBytes(.big));
    try std.testing.expectEqualSlices(u8, &sa.y.toBytes(.big), &ka.y.toBytes(.big));
}

test "GATED differential: fast_core.fieldMul/fieldSq == portable Solinas" {
    if (!gate.field_asm_implemented) return error.SkipZigTest; // core not filled (scaffold)
    if (!fast_core.supported) return error.SkipZigTest; // non-amd64 target

    var prng = std.Random.DefaultPrng.init(0xA5_F1E1D_92);
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

test "GATED differential: group.combMulBaseFast(k)·G == portable ladder + std" {
    if (!gate.fast_scalarmul_implemented) return error.SkipZigTest; // core not filled (scaffold)

    var prng = std.Random.DefaultPrng.init(0xC0FB_9256);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        if (P256.combMulBaseFast(kb, .big)) |kp| {
            const want = try P256.basePoint.mulDoubleAddCt(kb, .big);
            try std.testing.expect(want.equivalent(kp));
            const sp = try StdCurve.basePoint.mul(kb, .big);
            try eqAffineStd(kp, sp);
        } else |_| {
            try std.testing.expectError(error.IdentityElement, P256.basePoint.mulDoubleAddCt(kb, .big));
        }
    }
}

test "comb positive control: a corrupted table DISAGREES with std (harness has teeth)" {
    if (!gate.fast_scalarmul_implemented) return error.SkipZigTest; // core not filled

    // Drop a whole window (window 10 → all teeth = identity), i.e. digit 10
    // contributes nothing no matter its value. Any scalar with a nonzero
    // digit-10 (~15/16 of them) then yields the wrong point — so this must
    // diverge from std on the large majority of inputs. Proves the comb
    // differential would catch a dropped-digit / wrong-table comb.
    var bad = group.comb_table;
    for (&bad[10]) |*e| e.* = P256.identityElement;

    var prng = std.Random.DefaultPrng.init(0xBADC_0FFE_9256);
    const rand = prng.random();
    var disagreements: usize = 0;
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        const sp = StdCurve.basePoint.mul(kb, .big) catch continue;
        const kp = P256.combMulBaseFastWithTable(&bad, kb, .big) catch continue;
        const ka = kp.affineCoordinates();
        const sa = sp.affineCoordinates();
        if (!std.mem.eql(u8, &ka.x.toBytes(.big), &sa.x.toBytes(.big))) disagreements += 1;
    }
    try std.testing.expect(disagreements > 400);
}

test "GATED differential: group.mulCtWindowed == portable CT ladder" {
    if (!gate.fast_scalarmul_implemented) return error.SkipZigTest; // core not filled (scaffold)

    var prng = std.Random.DefaultPrng.init(0x61F_9256A2);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        var kb: [32]u8 = undefined;
        var sb: [32]u8 = undefined;
        rand.bytes(&kb);
        rand.bytes(&sb);
        const p = P256.combMulBase(kb, .big) catch continue;
        const want = p.mulDoubleAddCt(sb, .big) catch continue;
        const got = P256.mulCtWindowed(p, sb, .big) catch continue;
        try std.testing.expect(want.equivalent(got));
    }
}

test "basePoint.mul takes the comb redirect, and the redirect changes no answer" {
    // Two separate claims, and it is worth being precise about which is which
    // because the first attempt at this test checked only the second and
    // reported success while the redirect was deleted.
    //
    // The redirect exists because `std.crypto.sign.ecdsa.Ecdsa.sign` computes
    // its `R` as `Curve.basePoint.mul(k, .big)`. Before it, the fixed-base
    // comb -- this module's headline optimisation, ~4x the variable-base path
    // -- had NO call site on the signing path, so every signature took the
    // slow road.
    //
    // 1. The mechanism. Both branches of `mul` return identical points by
    //    construction, so no assertion on a result can distinguish them: what
    //    can break is the predicate that chooses, and that is what is asserted
    //    here. The `mul` body is three lines above it.
    try std.testing.expect(group.P256.isBasePointRepr(group.P256.basePoint));
    try std.testing.expect(!group.P256.isBasePointRepr(group.P256.basePoint.dbl()));
    try std.testing.expect(!group.P256.isBasePointRepr(group.P256.identityElement));
    // A point equal to G but in another projective representation is allowed
    // to miss the redirect -- it must not be *claimed*, because the comb table
    // belongs to this exact representation.
    const g_scaled = blk: {
        const two = try group.P256.Fe.fromInt(2);
        break :blk group.P256{
            .x = group.P256.basePoint.x.mul(two).mul(two),
            .y = group.P256.basePoint.y.mul(two).mul(two).mul(two),
            .z = group.P256.basePoint.z.mul(two),
        };
    };
    try std.testing.expect(!group.P256.isBasePointRepr(g_scaled));

    // 2. The consequence: taking the redirect must not change what comes back,
    //    against the comb (so the two agree) and against std (so both are
    //    right). A shared mistake between this module's two paths cannot pass
    //    the std leg.
    var prng = std.Random.DefaultPrng.init(0x9E37_79B9_7F4A_7C15);
    const rand = prng.random();

    var i: usize = 0;
    while (i < 256) : (i += 1) {
        var s: [32]u8 = undefined;
        rand.bytes(&s);
        s[0] &= 0x7f; // stay inside the group order for both implementations

        const via_mul = group.P256.basePoint.mul(s, .big) catch continue;
        const via_comb = try group.P256.combMulBase(s, .big);
        const via_std = try std.crypto.ecc.P256.basePoint.mul(s, .big);

        const a = via_mul.affineCoordinates();
        const b = via_comb.affineCoordinates();
        const c = via_std.affineCoordinates();

        try std.testing.expectEqualSlices(u8, &b.x.toBytes(.big), &a.x.toBytes(.big));
        try std.testing.expectEqualSlices(u8, &b.y.toBytes(.big), &a.y.toBytes(.big));
        try std.testing.expectEqualSlices(u8, &c.x.toBytes(.big), &a.x.toBytes(.big));
        try std.testing.expectEqualSlices(u8, &c.y.toBytes(.big), &a.y.toBytes(.big));
    }

    // And a point that is not G must still be multiplied the ordinary way:
    // the comb table is G's alone, so answering with it here would be wrong
    // rather than merely fast.
    const other = try group.P256.basePoint.dbl().mul([_]u8{3} ** 32, .big);
    const other_ref = try std.crypto.ecc.P256.basePoint.dbl().mul([_]u8{3} ** 32, .big);
    try std.testing.expectEqualSlices(
        u8,
        &other_ref.affineCoordinates().x.toBytes(.big),
        &other.affineCoordinates().x.toBytes(.big),
    );
}
