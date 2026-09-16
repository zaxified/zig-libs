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
const builtin = @import("builtin");
const gate = @import("gate.zig");
const fast_core = @import("fast_core.zig");
const field = @import("field.zig");
const group = @import("group.zig");
const sign = @import("sign.zig");

const Secp256k1 = group.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

// Debug is std's unoptimized signer/verifier (KeyPair.generateDeterministic +
// sign, each an uncached basePoint.mul) times four k256 verifies per round --
// full count adds materially to the full-gate Debug timeout budget (see
// group.zig's `random_scalars_iters`). Random draws cut in Debug; other modes
// keep the full count.
const ecdsa_oracle_iters: usize = if (builtin.mode == .Debug) 40 else 200;

test "ECDSA: k256 verifies every std-produced signature, rejects tampering" {
    var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xEC_D5A_0011);
    const rand = prng.random();

    var i: usize = 0;
    while (i < ecdsa_oracle_iters) : (i += 1) {
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

test "ECDSA malleability: std's own signatures come in both S forms; only low-S survives ecdsaVerifyLowS" {
    // Two things at once, and the first is what makes the second worth having:
    //
    //  1. Malleability is real here, not theoretical. For every signature std
    //     produces, the twin (r, n - s) is built and `ecdsaVerify` accepts it
    //     too — two distinct byte strings, same key, same message.
    //  2. `ecdsaVerifyLowS` accepts exactly one of the pair, whichever way
    //     round std happened to land, so a verified signature is unique for
    //     its (key, message).
    //
    // std's signer does NOT normalise to low-S, so both orientations actually
    // occur across the loop; the counters below fail the test if a change ever
    // made it emit only one of them, which would leave half of this untested.
    const n = @import("scalar.zig").field_order;
    var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x10_5A_9917);
    const rand = prng.random();

    // Debug is std's unoptimized signer (see `ecdsa_oracle_iters` above) --
    // cut in Debug, full count elsewhere. Both S-orientations still land
    // well before this shrinks to statistically flaky territory.
    const malleability_iters: usize = if (builtin.mode == .Debug) 20 else 100;

    var std_was_low: usize = 0;
    var std_was_high: usize = 0;
    var i: usize = 0;
    while (i < malleability_iters) : (i += 1) {
        rand.bytes(&seed);
        const kp = Ecdsa.KeyPair.generateDeterministic(seed) catch continue;
        var msg: [40]u8 = undefined;
        rand.bytes(&msg);
        const sig_rs = (kp.sign(&msg, null) catch continue).toBytes();
        const pk = kp.public_key.toUncompressedSec1();

        // The malleated twin: same r, s replaced by n - s.
        var twin = sig_rs;
        const s = std.mem.readInt(u256, sig_rs[32..64], .big);
        std.mem.writeInt(u256, twin[32..64], n - s, .big);

        // Both verify under plain ECDSA — that IS the malleability.
        try std.testing.expect(sign.ecdsaVerify(&pk, &msg, sig_rs));
        try std.testing.expect(sign.ecdsaVerify(&pk, &msg, twin));
        try std.testing.expect(!std.mem.eql(u8, &sig_rs, &twin));

        // Exactly one of the two is canonical, and it is the one that passes.
        const orig_low = sign.isLowS(sig_rs[32..64].*);
        try std.testing.expect(orig_low != sign.isLowS(twin[32..64].*));
        try std.testing.expectEqual(orig_low, sign.ecdsaVerifyLowS(&pk, &msg, sig_rs));
        try std.testing.expectEqual(!orig_low, sign.ecdsaVerifyLowS(&pk, &msg, twin));
        if (orig_low) std_was_low += 1 else std_was_high += 1;
    }
    // Neither orientation may be missing, or half the assertions above would
    // be vacuous.
    try std.testing.expect(std_was_low > 0);
    try std.testing.expect(std_was_high > 0);
}

test "ECDSA low-S boundary: n/2 is canonical, n/2 + 1 is not" {
    // The rule is `s <= n/2`, so the half-order itself must pass. Off-by-one
    // here would reject a signature Bitcoin considers canonical.
    const n = @import("scalar.zig").field_order;
    var s: [32]u8 = undefined;
    std.mem.writeInt(u256, &s, n >> 1, .big);
    try std.testing.expect(sign.isLowS(s));
    std.mem.writeInt(u256, &s, (n >> 1) + 1, .big);
    try std.testing.expect(!sign.isLowS(s));
}

// ── fixed-base comb (CONSTANT-TIME k·G) differential + positive control ──────

const StdCurve = std.crypto.ecc.Secp256k1;

fn eqAffineStd(k: Secp256k1, s: StdCurve) !void {
    const ka = k.affineCoordinates();
    const sa = s.affineCoordinates();
    try std.testing.expectEqualSlices(u8, &sa.x.toBytes(.big), &ka.x.toBytes(.big));
    try std.testing.expectEqualSlices(u8, &sa.y.toBytes(.big), &ka.y.toBytes(.big));
}

// Debug is unoptimized `std.basePoint.mul` (no comb table there, plain
// double-and-add) times 4000 draws: measured ~2m9s for this test ALONE under
// full-gate-level machine load (`nproc`=8, load average ~165 from other
// concurrent test lanes) -- close enough to a 3-minute per-test budget that
// the full gate timed it out (audit A1, 2026-09-15 attempt 4). ReleaseFast
// has no such problem (comb + std's own optimized path, both fast), so only
// Debug's random-draw count is cut; every named edge scalar below still runs
// in every mode -- this is a coverage TRIM, not a coverage DROP, and the
// mutant check at the end of this file (comb positive control) still runs
// the same 500 draws in both modes since it doesn't touch std's slow path.
// 300 (the previous cut, `14b2e983`) still ran ~9s isolated -- material
// against the module's own <40s-in-Debug budget (k256, audit A1 2026-09-15
// attempt 6, `group.test.differential` timed the full gate out separately;
// fixing that alone left this test as the next-largest contributor). Cut
// further; every named edge scalar below is unconditional in all modes.
const comb_random_iters: usize = if (builtin.mode == .Debug) 50 else 4000;

test "comb: combMulBase(k)·G == std.basePoint.mul(k), random + edges" {
    var prng = std.Random.DefaultPrng.init(0xC0FB_0A5E_11);
    const rand = prng.random();

    // Random scalars: k256 comb must match std's base multiply bit-exact
    // (both compute the raw integer multiple k·G), including the
    // identity-reject agreement (k ≡ 0 mod n). Count is mode-scaled, see
    // `comb_random_iters` above.
    var i: usize = 0;
    while (i < comb_random_iters) : (i += 1) {
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

    // Same std-mul cost as `comb_random_iters` above (~30ms/draw in Debug):
    // 500 draws ran ~15s isolated. Cut in Debug; the ~15/16 expected
    // disagreement rate needs only a modest sample to stay far from flaky.
    const rounds: usize = if (builtin.mode == .Debug) 50 else 500;
    const min_disagreements = rounds - rounds / 5; // > 80%, expected ~93.75%

    var prng = std.Random.DefaultPrng.init(0xBADC_0FFE_10);
    const rand = prng.random();
    var disagreements: usize = 0;
    var i: usize = 0;
    while (i < rounds) : (i += 1) {
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        const sp = StdCurve.basePoint.mul(kb, .big) catch continue;
        const kp = Secp256k1.combMulBaseWithTable(&bad, kb, .big) catch continue;
        const ka = kp.affineCoordinates();
        const sa = sp.affineCoordinates();
        if (!std.mem.eql(u8, &ka.x.toBytes(.big), &sa.x.toBytes(.big))) disagreements += 1;
    }
    try std.testing.expect(disagreements > min_disagreements);
}

// ── gated Fable-core differentials (SKIP ≠ pass) ─────────────────────────────

test "GATED differential: fast_core.fieldMul/fieldSq == portable Solinas" {
    if (!gate.field_asm_implemented) return error.SkipZigTest; // core not filled
    if (!fast_core.supported) return error.SkipZigTest; // non-amd64 target

    // amd64 fast_core is implemented, so this actually runs (not skipped) --
    // Debug margin for the module's <40s budget, full count elsewhere.
    const fast_core_iters: usize = if (builtin.mode == .Debug) 800 else 5000;

    var prng = std.Random.DefaultPrng.init(0xA5_F1E1D_01);
    const rand = prng.random();
    var i: usize = 0;
    while (i < fast_core_iters) : (i += 1) {
        var ab: [32]u8 = undefined;
        var bb: [32]u8 = undefined;
        rand.bytes(&ab);
        rand.bytes(&bb);
        const a = field.Fe.fromBytes(ab, .big) catch continue;
        const b = field.Fe.fromBytes(bb, .big) catch continue;

        const want_mul = field.mulPortable(a._limbs, b._limbs);
        var got_mul: [4]u64 = undefined;
        fast_core.fieldMul(&got_mul, &a._limbs, &b._limbs);
        try std.testing.expectEqualSlices(u64, &want_mul, &got_mul);

        const want_sq = field.sqPortable(a._limbs);
        var got_sq: [4]u64 = undefined;
        fast_core.fieldSq(&got_sq, &a._limbs);
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

// ── A1/k256.md fix-campaign guard tests ──────────────────────────────────
//
// F2/F3/F9: three validations the audit showed the suite could lose (source
// deleted, or the check simply never called) without a single test going
// red. Each test below is a genuine black-box regression test — mutating
// away the guard it names changes the OBSERVABLE return value of a public
// function, so these were verified RED (mutant) → GREEN (revert) by hand
// during the fix pass; see `A1/k256.md`'s 2026-09-10 disposition for the
// exact mutation and `scripts/modtest k256` output.

test "F2: fromAffineCoordinates / fromSec1 reject an off-curve point" {
    const Fe = field.Fe;

    // x = 1: x³+7 = 8, and y = 1 gives y² = 1 ≠ 8 — off the curve. (NOT
    // (0, 1): that pair IS this module's affine identity sentinel
    // (`AffineCoordinates.identityElement`, group.zig:653) and is correctly
    // accepted — verified the hard way, by first writing this test against
    // (0, 1) and watching it fail on UNMUTATED code.)
    try std.testing.expectError(
        error.InvalidEncoding,
        Secp256k1.fromAffineCoordinates(.{ .x = Fe.one, .y = Fe.one }),
    );

    var sec1: [65]u8 = undefined;
    sec1[0] = 4;
    @memset(sec1[1..33], 0);
    sec1[32] = 1; // x = 1
    @memset(sec1[33..64], 0);
    sec1[64] = 1; // y = 1
    try std.testing.expectError(error.InvalidEncoding, Secp256k1.fromSec1(&sec1));

    // A random SEC1-decoded on-curve point must still round-trip — the
    // guard rejects only what it should.
    const p = try Secp256k1.basePoint.mul(comptime blk: {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, 12345, .big);
        break :blk b;
    }, .big);
    const good_sec1 = p.toUncompressedSec1();
    _ = try Secp256k1.fromSec1(&good_sec1);
}

test "F3: Secp256k1.mul(P, s) rejects s ≡ 0 (mod n), same as combMulBase" {
    const g = Secp256k1.basePoint;
    const n = @import("scalar.zig").field_order;

    try std.testing.expectError(error.IdentityElement, g.mul(beBytes(0), .big));
    try std.testing.expectError(error.IdentityElement, g.mul(beBytes(n), .big));

    // Positive control: a nonzero scalar must still succeed and agree with
    // combMulBase — proves the guard above didn't just start rejecting
    // everything.
    const from_mul = try g.mul(beBytes(7), .big);
    const from_comb = try Secp256k1.combMulBase(beBytes(7), .big);
    try std.testing.expect(from_mul.equivalent(from_comb));
}

// ── A1/k256.md F5: the windowed constant-time `mul` (P5 evidence) ─────────
//
// `mul` stopped being the 256-bit ladder on 2026-09-16. The ladder stays as
// `mulLadder`, and these two tests are what licenses the swap: every result
// must equal the ladder's AND std's at the affine level, error for error, on
// random scalars and on the shapes random scalars never produce (all-negative
// digit strings, carries into the extra window, the raw range above `n`), over
// base, random, negated, un-normalised projective and identity points. The
// positive control shows that comparison can fail.

fn stdOf(p: Secp256k1) !StdCurve {
    const enc = p.toUncompressedSec1();
    return StdCurve.fromSec1(&enc);
}

fn mulAgrees(p: Secp256k1, kb: [32]u8) !void {
    const got = p.mul(kb, .big);
    const sp = try stdOf(p);
    if (p.mulLadder(kb, .big)) |want| {
        const g = try got;
        const ga = g.affineCoordinates();
        const wa = want.affineCoordinates();
        try std.testing.expectEqualSlices(u8, &wa.x.toBytes(.big), &ga.x.toBytes(.big));
        try std.testing.expectEqualSlices(u8, &wa.y.toBytes(.big), &ga.y.toBytes(.big));
        try eqAffineStd(g, try sp.mul(kb, .big));
    } else |e| {
        try std.testing.expectError(e, got);
        try std.testing.expectError(e, sp.mul(kb, .big));
    }
}

test "F5: windowed mul == mulLadder == std, random + edge scalars over base/random/projective/identity points" {
    const scalar = @import("scalar.zig");
    const n = scalar.field_order;
    const ones: u256 = std.math.maxInt(u256) / 15; // 0x1111…1
    const edges = [_]u256{
        0, 1, 2,  3,  7,
        8, 9, 15, 16, 17,
        ones * 8, // every window 8: every digit negative, carry through all 64
        ones * 7, // every window 7: largest non-negative digit everywhere
        ones * 15, // 2^256−1: every window carries
        (1 << 255),
        (1 << 255) + 1,
        (1 << 252),                (1 << 252) - 1, // top nibble boundary
        n - 1,                     n,
        n + 1,                     n + 2,
        (n - 1) / 2,               scalar.lambda,
        std.math.maxInt(u256) - 1, std.math.maxInt(u256) - 15,
    };

    var prng = std.Random.DefaultPrng.init(0xF5_0A1D_E120);
    const rand = prng.random();
    var rb: [32]u8 = undefined;
    rand.bytes(&rb);
    const r = try Secp256k1.combMulBase(rb, .big);
    const points = [_]Secp256k1{
        Secp256k1.basePoint,
        Secp256k1.identityElement,
        r, // projective, z ≠ 1
        r.neg(),
        r.add(Secp256k1.basePoint).dbl(), // un-normalised projective
        try Secp256k1.fromAffineCoordinates(r.affineCoordinates()), // same point, z = 1
    };
    for (points) |p| {
        for (edges) |e| try mulAgrees(p, beBytes(e));
    }

    // Random: a fresh random point and a raw 256-bit scalar each round.
    const rounds: usize = if (@import("builtin").mode == .Debug) 48 else 1000;
    var i: usize = 0;
    while (i < rounds) : (i += 1) {
        rand.bytes(&rb);
        const p = Secp256k1.combMulBase(rb, .big) catch continue;
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        try mulAgrees(p, kb);
    }
}

test "F5 positive control: a corrupted per-point table DISAGREES with std (the differential has teeth)" {
    var prng = std.Random.DefaultPrng.init(0xF5_BAD_7AB1E);
    const rand = prng.random();
    const rounds: usize = if (@import("builtin").mode == .Debug) 32 else 500;
    var disagreements: usize = 0;
    var i: usize = 0;
    while (i < rounds) : (i += 1) {
        var rb: [32]u8 = undefined;
        rand.bytes(&rb);
        const p = Secp256k1.combMulBase(rb, .big) catch continue;
        var tab = p.varBaseTable();
        tab[4] = Secp256k1.identityElement; // 5·P gone: any digit of magnitude 5 now adds nothing
        var kb: [32]u8 = undefined;
        rand.bytes(&kb);
        const sp = (try stdOf(p)).mul(kb, .big) catch continue;
        const kp = Secp256k1.mulWithTable(&tab, kb, .big) catch {
            disagreements += 1;
            continue;
        };
        if (!std.mem.eql(u8, &kp.affineCoordinates().x.toBytes(.big), &sp.affineCoordinates().x.toBytes(.big))) disagreements += 1;
    }
    // 65 digits, each of magnitude 5 with probability 1/8: a scalar avoids
    // them all with probability (7/8)^64 ≈ 2e-4.
    try std.testing.expect(disagreements * 10 > rounds * 9);
}

test "F9: Fe.rejectNonCanonical actually rejects >= p and accepts < p" {
    const Fe = field.Fe;
    const p = field.field_order;

    try std.testing.expectError(error.NonCanonical, Fe.rejectNonCanonical(beBytes(p), .big));
    try std.testing.expectError(error.NonCanonical, Fe.rejectNonCanonical(beBytes(p + 1), .big));
    try std.testing.expectError(error.NonCanonical, Fe.rejectNonCanonical(beBytes(std.math.maxInt(u256)), .big));
    try Fe.rejectNonCanonical(beBytes(p - 1), .big);
    try Fe.rejectNonCanonical(beBytes(0), .big);
}
