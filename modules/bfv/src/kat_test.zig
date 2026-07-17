// SPDX-License-Identifier: MIT

//! kat_test — the verification harness. Three jobs:
//!   1. BYTE-EXACT arithmetic KATs (`ntt`/`rns`) against the independent
//!      Python re-derivation in `kat_vectors.zig` — the deterministic anchor.
//!   2. DELIBERATELY-BROKEN positive controls that PASS today (proving the
//!      checkers have teeth BEFORE any scheme core exists): a
//!      cyclic-vs-negacyclic discriminator, and a wrong-scale "encryptor"
//!      whose structural scale-check is REJECTED.
//!   3. The homomorphic end-to-end anchors (add / mul+relin / depth) — the
//!      strong anchors — wired now but SKIP-gated until the scheme cores land.

const std = @import("std");
const testing = std.testing;

const ma = @import("modarith.zig");
const nttmod = @import("ntt.zig");
const rns = @import("rns.zig");
const ring = @import("ring.zig");
const encode = @import("encode.zig");
const params = @import("params.zig");
const bfv = @import("bfv.zig");
const gate = @import("gate.zig");
const kat = @import("kat_vectors.zig");

// ── 1. Byte-exact NTT KAT (the deterministic anti-self-consistency anchor) ────

fn checkNttVector(
    comptime q: u64,
    input_a: [8]u64,
    input_b: [8]u64,
    forward_a: [8]u64,
    negamul_ab: [8]u64,
    psi: u64,
) !void {
    const T = nttmod.Ntt(8);
    const engine = try T.init(q);

    // psi the transform chose must match the KAT's psi.
    try testing.expectEqual(psi, try ma.primitive2NthRoot(q, 8));

    // forward transform output (bit-reversed order) is byte-exact.
    var a = input_a;
    engine.forward(&a);
    try testing.expectEqualSlices(u64, &forward_a, &a);

    // round-trip identity.
    engine.inverse(&a);
    try testing.expectEqualSlices(u64, &input_a, &a);

    // canonical negacyclic product is byte-exact via BOTH paths.
    const viaNtt = engine.mulNegacyclic(input_a, input_b);
    try testing.expectEqualSlices(u64, &negamul_ab, &viaNtt);
    const viaSchool = T.mulSchoolbook(q, &input_a, &input_b);
    try testing.expectEqualSlices(u64, &negamul_ab, &viaSchool);
}

test "NTT byte-exact KAT vs independent Python re-derivation (q=17, q=97)" {
    try checkNttVector(17, kat.ntt_q17_input_a, kat.ntt_q17_input_b, kat.ntt_q17_forward_a, kat.ntt_q17_negamul_ab, kat.ntt_q17_psi);
    try checkNttVector(97, kat.ntt_q97_input_a, kat.ntt_q97_input_b, kat.ntt_q97_forward_a, kat.ntt_q97_negamul_ab, kat.ntt_q97_psi);
}

// ── 1b. Byte-exact RNS/CRT KAT ────────────────────────────────────────────────

test "RNS CRT byte-exact KAT vs Python re-derivation" {
    const basis = try rns.Basis.init(&kat.rns_primes);
    try testing.expectEqual(@as(u128, kat.rns_modulus), basis.modulus());
    for (kat.rns_values, kat.rns_res_p0, kat.rns_res_p1) |v, r0, r1| {
        var res: [2]u64 = undefined;
        basis.decompose(v, &res);
        try testing.expectEqual(r0, res[0]);
        try testing.expectEqual(r1, res[1]);
        try testing.expectEqual(@as(u128, v), basis.reconstruct(&res));
    }
}

// ── 2. Positive control A: cyclic-vs-negacyclic discriminator ─────────────────
// Independent proof the NTT cross-check has TEETH: had the NTT accidentally
// implemented a CYCLIC convolution (X^N = +1) instead of the negacyclic one
// (X^N = -1), the `mulNegacyclic == mulSchoolbook` test above would have caught
// it — because the two products differ. We build the WRONG (cyclic) product
// with no NTT code and confirm (a) it differs from the negacyclic answer, and
// (b) the real NTT matches the negacyclic one, NOT the cyclic one.

fn cyclicMulSchoolbook(comptime N: usize, q: u64, a: *const [N]u64, b: *const [N]u64) [N]u64 {
    var out = [_]u64{0} ** N;
    for (0..N) |i| for (0..N) |j| {
        const c = ma.mulMod(a[i], b[j], q);
        out[(i + j) % N] = ma.addMod(out[(i + j) % N], c, q); // X^N = +1 (WRONG for RLWE)
    };
    return out;
}

test "positive control: cyclic product differs from negacyclic (checker bites)" {
    const T = nttmod.Ntt(8);
    const q: u64 = 97;
    const engine = try T.init(q);
    const a = kat.ntt_q97_input_a;
    const b = kat.ntt_q97_input_b;

    const negacyclic = T.mulSchoolbook(q, &a, &b);
    const cyclic = cyclicMulSchoolbook(8, q, &a, &b);
    const viaNtt = engine.mulNegacyclic(a, b);

    // The two ring products are genuinely different (anchor is discriminating).
    try testing.expect(!std.mem.eql(u64, &negacyclic, &cyclic));
    // The real NTT computes the CORRECT (negacyclic) one, not the cyclic one.
    try testing.expectEqualSlices(u64, &negacyclic, &viaNtt);
    try testing.expect(!std.mem.eql(u64, &cyclic, &viaNtt));
}

// ── 2b. Positive control B: wrong-SCALE encryptor (noise/scaling teeth) ───────
// The BFV-specific hazard is scale/noise mismanagement. We build — with ONLY
// the real ring arithmetic, no gated core — a NOISELESS toy ciphertext whose
// structural invariant is `c0 + c1·s == Δ·m` (Δ = ⌊q/t⌋). A correct
// construction satisfies it; a wrong-scale construction (Δ'=1) does NOT. The
// `scaleCheck` checker REJECTS the wrong one and ACCEPTS the right one —
// proving the scaling anchor has teeth before `encrypt`/`decrypt` exist.

const P = params.test_tiny; // N=8, t=4, primes {17,97}, q=1649
const Ring8 = ring.RnsPoly(P.n, P.primes.len);
const primes8 = [_]u64{ 17, 97 };

fn deltaLimbs() [2]u64 {
    // Δ = ⌊q/t⌋ = ⌊1649/4⌋ = 412; per-limb residue.
    const q: u128 = 17 * 97;
    const delta: u128 = q / P.t;
    return .{ @intCast(delta % primes8[0]), @intCast(delta % primes8[1]) };
}

/// Δ·m as a ring element (scalar-times-plaintext, per-limb coefficient-wise).
fn scaledPlaintext(m: *const encode.Plaintext(P.n), scale: [2]u64) Ring8 {
    var out = Ring8.zero(.coeff);
    for (0..2) |i| {
        for (0..P.n) |j| out.limbs[i][j] = ma.mulMod(scale[i], m.coeffs[j] % primes8[i], primes8[i]);
    }
    return out;
}

/// The checker: does `c0 + c1·s` equal the expected `Δ·m` ring element?
fn scaleCheck(c0: *const Ring8, c1: *const Ring8, s: *const Ring8, expected: *const Ring8, engines: *const [2]Ring8.Engine) bool {
    var acc = c1.mul(s, engines, &primes8); // c1·s in R_q
    acc.addAssign(c0, &primes8); // + c0
    return acc.eql(expected);
}

test "positive control: wrong-scale encryptor is rejected, correct one accepted" {
    const engines = try ring.makeEngines(P.n, P.primes.len, &primes8);
    const Pt = encode.Plaintext(P.n);
    const m = Pt.fromCoeffs(P.t, .{ 1, 2, 3, 0, 1, 2, 3, 0 });

    // A fixed "secret" ring element s (small, coeff domain).
    const s = Ring8.fromCoeffs(&primes8, .{ [_]u64{ 1, 0, 16, 1, 0, 16, 1, 0 }, [_]u64{ 1, 0, 96, 1, 0, 96, 1, 0 } });
    // A fixed "mask" c1.
    const c1 = Ring8.fromCoeffs(&primes8, .{ [_]u64{ 3, 5, 7, 9, 11, 13, 15, 2 }, [_]u64{ 30, 50, 70, 90, 11, 33, 55, 77 } });

    const delta = deltaLimbs();
    const target_delta = scaledPlaintext(&m, delta); // Δ·m  (CORRECT)
    const target_one = scaledPlaintext(&m, .{ 1, 1 }); // 1·m  (WRONG scale)

    // CORRECT construction: c0 = Δ·m − c1·s. scaleCheck against Δ·m ACCEPTS.
    var c1s = c1.mul(&s, &engines, &primes8);
    var c0_correct = target_delta;
    c0_correct.subAssign(&c1s, &primes8);
    try testing.expect(scaleCheck(&c0_correct, &c1, &s, &target_delta, &engines));

    // WRONG-scale construction: c0 = 1·m − c1·s. scaleCheck against Δ·m REJECTS
    // (this is exactly the class of bug — dropped Δ scaling — the anchor must
    // catch). It only matches the (wrong) unit-scale target.
    _ = &c1s;
    var c0_wrong = target_one;
    c0_wrong.subAssign(&c1s, &primes8);
    try testing.expect(!scaleCheck(&c0_wrong, &c1, &s, &target_delta, &engines));
    try testing.expect(scaleCheck(&c0_wrong, &c1, &s, &target_one, &engines));
}

// ── 3. Homomorphic end-to-end anchors (SKIP-gated until scheme cores land) ────

test "homomorphic ADD end-to-end: Dec(Enc(a) ⊕ Enc(b)) == a+b (mod t)" {
    if (!gate.scheme_core_implemented) return error.SkipZigTest;
    const B = bfv.Bfv(P);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(1);
    const rnd = prng.random();
    const kp = inst.keyGen(rnd);
    const Pt = B.Plaintext;
    const ma_pt = Pt.fromCoeffs(P.t, .{ 1, 2, 3, 0, 1, 2, 3, 0 });
    const mb_pt = Pt.fromCoeffs(P.t, .{ 3, 3, 1, 2, 0, 0, 1, 1 });
    const ca = inst.encrypt(&kp.pk, &ma_pt, rnd);
    const cb = inst.encrypt(&kp.pk, &mb_pt, rnd);
    const cs = inst.add(&ca, &cb);
    const got = inst.decrypt(&kp.sk, &cs);
    const want = Pt.addRef(&ma_pt, &mb_pt);
    try testing.expectEqualSlices(u64, &want.coeffs, &got.coeffs);
}

test "homomorphic MUL+RELIN end-to-end: Dec(relin(Enc(a) ⊗ Enc(b))) == a·b (mod t)" {
    if (!gate.scheme_core_implemented or !gate.fable_core_implemented) return error.SkipZigTest;
    const B = bfv.Bfv(P);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(2);
    const rnd = prng.random();
    const kp = inst.keyGen(rnd);
    const rlk = inst.genRelinKey(&kp.sk, rnd);
    const Pt = B.Plaintext;
    const ma_pt = Pt.fromCoeffs(P.t, .{ 1, 1, 0, 0, 0, 0, 0, 0 });
    const mb_pt = Pt.fromCoeffs(P.t, .{ 0, 1, 1, 0, 0, 0, 0, 0 });
    const ca = inst.encrypt(&kp.pk, &ma_pt, rnd);
    const cb = inst.encrypt(&kp.pk, &mb_pt, rnd);
    const prod3 = inst.mul(&ca, &cb); // 3-component
    try testing.expectEqual(@as(usize, 3), prod3.numComponents());
    const prod2 = inst.relinearize(&prod3, &rlk); // back to 2
    try testing.expectEqual(@as(usize, 2), prod2.numComponents());
    const got = inst.decrypt(&kp.sk, &prod2);
    const want = Pt.mulRef(&ma_pt, &mb_pt);
    try testing.expectEqualSlices(u64, &want.coeffs, &got.coeffs);
}

test "multiply DEPTH: Dec(a·b·c) == a·b·c (mod t) exercises the noise budget" {
    if (!gate.scheme_core_implemented or !gate.fable_core_implemented) return error.SkipZigTest;
    const B = bfv.Bfv(P);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(3);
    const rnd = prng.random();
    const kp = inst.keyGen(rnd);
    const rlk = inst.genRelinKey(&kp.sk, rnd);
    const Pt = B.Plaintext;
    const a = Pt.fromCoeffs(P.t, .{ 1, 1, 0, 0, 0, 0, 0, 0 });
    const b = Pt.fromCoeffs(P.t, .{ 0, 1, 0, 0, 0, 0, 0, 0 });
    const c = Pt.fromCoeffs(P.t, .{ 1, 0, 1, 0, 0, 0, 0, 0 });
    const ea = inst.encrypt(&kp.pk, &a, rnd);
    const eb = inst.encrypt(&kp.pk, &b, rnd);
    const ec = inst.encrypt(&kp.pk, &c, rnd);
    const ab = inst.relinearize(&inst.mul(&ea, &eb), &rlk);
    // noise must still be positive after one multiply.
    try testing.expect(inst.noiseBudget(&kp.sk, &ab) > 0);
    const abc = inst.relinearize(&inst.mul(&ab, &ec), &rlk);
    const got = inst.decrypt(&kp.sk, &abc);
    const want = Pt.mulRef(&Pt.mulRef(&a, &b), &c);
    try testing.expectEqualSlices(u64, &want.coeffs, &got.coeffs);
}
