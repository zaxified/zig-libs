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
//!   2. **The GATED Fable-core differentials** — LIVE now that both gates are
//!      flipped: they pin the amd64 field core and the GLV scalarmuls
//!      bit-for-bit to the proven portable paths (random + edge inputs). They
//!      still SKIP on targets where a core cannot run (a skip is NOT a green
//!      light there — dispatch is on the portable oracle).

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

// ── fixed-base comb (CONSTANT-TIME k·G) differential + positive control ──────

const StdCurve = std.crypto.ecc.Secp256k1;

fn eqAffineStd(k: Secp256k1, s: StdCurve) !void {
    const ka = k.affineCoordinates();
    const sa = s.affineCoordinates();
    try std.testing.expectEqualSlices(u8, &sa.x.toBytes(.big), &ka.x.toBytes(.big));
    try std.testing.expectEqualSlices(u8, &sa.y.toBytes(.big), &ka.y.toBytes(.big));
}

test "comb: combMulBase(k)·G == std.basePoint.mul(k), random + edges" {
    var prng = std.Random.DefaultPrng.init(0xC0FB_0A5E_11);
    const rand = prng.random();

    // Thousands of random scalars: k256 comb must match std's base multiply
    // bit-exact (both compute the raw integer multiple k·G), including the
    // identity-reject agreement (k ≡ 0 mod n).
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        if (Secp256k1.combMulBase(kb, .big)) |kp| {
            const sp = try StdCurve.basePoint.mul(kb, .big);
            try eqAffineStd(kp, sp);
        } else |_| {
            try std.testing.expectError(error.IdentityElement, StdCurve.basePoint.mul(kb, .big));
        }
    }

    // Edge scalars: 0, 1, n−1, n (≡0), and values near 2^256 (raw-scalar range).
    const n = @import("scalar.zig").field_order;
    const edges = [_]u256{
        0, 1, 2, 3, 15, 16, 17,
        n - 1,                 n, // n ≡ 0 (mod n): identity reject, like k = 0
        (1 << 128),            (1 << 128) - 1,
        (1 << 255),            (1 << 255) + 1,
        std.math.maxInt(u256), std.math.maxInt(u256) - 1,
    };
    for (edges) |kv_| {
        var kb: [32]u8 = undefined;
        std.mem.writeInt(u256, &kb, kv_, .big);
        if (Secp256k1.combMulBase(kb, .big)) |kp| {
            const sp = try StdCurve.basePoint.mul(kb, .big);
            try eqAffineStd(kp, sp);
        } else |_| {
            try std.testing.expectError(error.IdentityElement, StdCurve.basePoint.mul(kb, .big));
        }
    }
}

test "comb positive control: a corrupted table DISAGREES with std (harness has teeth)" {
    // Drop a whole window (window 10 → all teeth = identity), i.e. digit 10
    // contributes nothing no matter its value. Any scalar with a nonzero
    // digit-10 (~15/16 of them) then yields the wrong point — so this must
    // diverge from std on the large majority of inputs. Proves the differential
    // above would catch a dropped-digit / wrong-table comb.
    var bad = group.comb_table;
    for (&bad[10]) |*e| e.* = Secp256k1.identityElement;

    var prng = std.Random.DefaultPrng.init(0xBADC_0FFE_10);
    const rand = prng.random();
    var disagreements: usize = 0;
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        const sp = StdCurve.basePoint.mul(kb, .big) catch continue;
        const kp = Secp256k1.combMulBaseWithTable(&bad, kb, .big) catch continue;
        const ka = kp.affineCoordinates();
        const sa = sp.affineCoordinates();
        if (!std.mem.eql(u8, &ka.x.toBytes(.big), &sa.x.toBytes(.big))) disagreements += 1;
    }
    try std.testing.expect(disagreements > 400);
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

test "GATED differential: fast_core edge cases (0, 1, p−1, fold-stressing patterns)" {
    if (!gate.field_asm_implemented) return error.SkipZigTest; // core not filled
    if (!fast_core.supported) return error.SkipZigTest; // non-amd64 target

    const p = field.field_order;
    const c: u256 = (1 << 32) + 977; // the Solinas fold constant
    // Canonical edge values (< p): boundaries, single bits, fold-constant
    // multiples, and max-limb patterns that stress the reduction carries.
    const edges = [_]u256{
        0,             1,           2,                                                                  c - 1,                                                              c,
        c + 1,         p - 1,       p - 2,                                                              p - c,                                                              p - c - 1,
        (1 << 64) - 1, 1 << 64,     (1 << 128) - 1,                                                     1 << 128,                                                           (1 << 192) - 1,
        1 << 192,      1 << 255,    (1 << 255) + 1,                                                     p >> 1,                                                             (p >> 1) + 1,
        p / c,         (p / c) * c, 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000, 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF,
    };
    for (edges) |av| {
        if (av >= p) continue;
        const a: [4]u64 = .{ @truncate(av), @truncate(av >> 64), @truncate(av >> 128), @truncate(av >> 192) };
        const want_sq = field.sqPortable(a);
        var got_sq: [4]u64 = undefined;
        fast_core.fieldSq(&got_sq, &a);
        try std.testing.expectEqualSlices(u64, &want_sq, &got_sq);
        for (edges) |bv| {
            if (bv >= p) continue;
            const b: [4]u64 = .{ @truncate(bv), @truncate(bv >> 64), @truncate(bv >> 128), @truncate(bv >> 192) };
            const want = field.mulPortable(a, b);
            var got: [4]u64 = undefined;
            fast_core.fieldMul(&got, &a, &b);
            try std.testing.expectEqualSlices(u64, &want, &got);
        }
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

fn beBytes(x: u256) [32]u8 {
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, x, .big);
    return b;
}

test "GATED GLV edge cases: s at 0/1/λ/n±1/2^256−1, base + random point, identity input" {
    if (!gate.glv_scalarmul_implemented) return error.SkipZigTest; // core not filled

    const scalarmod = @import("scalar.zig");
    const n = scalarmod.field_order;

    var prng = std.Random.DefaultPrng.init(0x61F_ED6E5);
    const rand = prng.random();
    var kb: [32]u8 = undefined;
    rand.bytes(&kb);
    const points = [_]Secp256k1{ Secp256k1.basePoint, try Secp256k1.basePoint.mul(kb, .big) };

    for (points) |p| {
        // s ≡ 0 (mod n): raw 0 and raw n both hit the identity reject.
        try std.testing.expectError(error.IdentityElement, Secp256k1.mulPublicGlv(p, beBytes(0), .big));
        try std.testing.expectError(error.IdentityElement, Secp256k1.mulPublicGlv(p, beBytes(n), .big));

        // Exact-value pins against the portable vartime oracle — no
        // catch-continue: every case MUST succeed on both paths and agree.
        const scalars = [_]u256{
            1, 2, 3, 15, 16, 17,
            scalarmod.lambda, // split degenerates to (0, 1)
            n - scalarmod.lambda, // negative-half exercise
            (1 << 128) - 1,
            1 << 128,
            n - 1, // ≡ −1: both halves negative-capable
            n + 1, // raw scalar above the order, reduces to 1
            std.math.maxInt(u256), // raw 2^256−1
        };
        for (scalars) |s| {
            const sb = beBytes(s);
            const want = try p.mulPublicDoubleAdd(sb, .big);
            const got = try Secp256k1.mulPublicGlv(p, sb, .big);
            try std.testing.expect(want.equivalent(got));
        }
    }

    // Identity input point must reject.
    try std.testing.expectError(error.IdentityElement, Secp256k1.mulPublicGlv(Secp256k1.identityElement, beBytes(1), .big));
}

test "GATED differential: mulDoubleBasePublic (GLV 4-way) == portable double-add" {
    if (!gate.glv_scalarmul_implemented) return error.SkipZigTest; // core not filled

    var prng = std.Random.DefaultPrng.init(0xD0B1_BA5E);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        var kb1: [32]u8 = undefined;
        var kb2: [32]u8 = undefined;
        var s1: [32]u8 = undefined;
        var s2: [32]u8 = undefined;
        rand.bytes(&kb1);
        rand.bytes(&kb2);
        rand.bytes(&s1);
        rand.bytes(&s2);
        const p1 = Secp256k1.basePoint.mul(kb1, .big) catch continue;
        const p2 = Secp256k1.basePoint.mul(kb2, .big) catch continue;

        // Errors must agree too (no silent skip of the GLV path).
        if (Secp256k1.mulDoubleBasePublicDoubleAdd(p1, s1, p2, s2, .big)) |want| {
            const got = try Secp256k1.mulDoubleBasePublic(p1, s1, p2, s2, .big);
            try std.testing.expect(want.equivalent(got));
        } else |e| {
            try std.testing.expectError(e, Secp256k1.mulDoubleBasePublic(p1, s1, p2, s2, .big));
        }
    }

    // Edge: zero scalars and an exact cancellation must reject as identity.
    const g = Secp256k1.basePoint;
    const g2 = try g.mul(beBytes(2), .big);
    try std.testing.expectError(error.IdentityElement, Secp256k1.mulDoubleBasePublic(g, beBytes(0), g2, beBytes(0), .big));
    // 2·G + 1·(−2G) = identity.
    try std.testing.expectError(error.IdentityElement, Secp256k1.mulDoubleBasePublic(g, beBytes(2), g2.neg(), beBytes(1), .big));
    // One zero scalar: s1·p1 alone.
    const want_single = try g.mulPublicDoubleAdd(beBytes(7), .big);
    const got_single = try Secp256k1.mulDoubleBasePublic(g, beBytes(7), g2, beBytes(0), .big);
    try std.testing.expect(want_single.equivalent(got_single));
}
