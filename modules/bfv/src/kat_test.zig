// SPDX-License-Identifier: MIT

//! kat_test — the verification harness. Three jobs:
//!   1. BYTE-EXACT arithmetic KATs (`ntt`/`rns`) against the independent
//!      Python re-derivation in `kat_vectors.zig` — the deterministic anchor.
//!   2. DELIBERATELY-BROKEN positive controls that PASS today (proving the
//!      checkers have teeth BEFORE any scheme core exists): a
//!      cyclic-vs-negacyclic discriminator, and a wrong-scale "encryptor"
//!      whose structural scale-check is REJECTED.
//!   3. The homomorphic end-to-end anchors (add / mul+relin / depth) — the
//!      strong anchors — LIVE since Parts 2–3 landed (the gate checks remain
//!      so a future param/gate change degrades to SKIP, never to a false
//!      green). Mul/depth run on `params.test_mul` (see the note there).

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
    var acc = c1.mul(s, engines); // c1·s in R_q
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
    var c1s = c1.mul(&s, &engines);
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

// ── 2c. Deterministic decrypt KAT: the Δ-rescale, independent of enc/keyGen ────
// The strongest anti-self-consistency anchor for `decrypt` that does NOT route
// through this module's own `encrypt`/`keyGen`. We hand-construct a NOISELESS
// ciphertext with the REAL (independently-KAT'd) ring arithmetic so that
// `c0 + c1·s == Δ·m` exactly, and require `decrypt((s),(c0,c1)) == m`. Then:
//   • add a within-margin noise (|E| < Δ/2 = 206) → still decrypts to m;
//   • add an over-margin noise (> Δ/2) at one coefficient → the rounding flips,
//     so decrypt DIFFERS there (proves the margin/rounding boundary bites).
// This pins the `⌊t/q·…⌉` rescale against an external re-derivation of `Δ·m`,
// not against round-trip self-consistency.

/// Integer `n` placed at coefficient 0 as a ring element (residues per limb).
fn noiseAtCoeff0(n: u64) Ring8 {
    var r = Ring8.zero(.coeff);
    r.limbs[0][0] = n % primes8[0];
    r.limbs[1][0] = n % primes8[1];
    return r;
}

test "decrypt KAT: noiseless Δ-rescale round-trips; margin boundary bites (deterministic)" {
    if (!gate.scheme_core_implemented) return error.SkipZigTest;
    const B = bfv.Bfv(P);
    const inst = try B.init();
    const engines = try ring.makeEngines(P.n, P.primes.len, &primes8);
    const Pt = encode.Plaintext(P.n);
    const m = Pt.fromCoeffs(P.t, .{ 1, 2, 3, 0, 1, 2, 3, 0 });

    // Fixed small secret s (ternary: 16≡−1 mod 17, 96≡−1 mod 97) and an
    // arbitrary mask c1 — NO keyGen/encrypt involved.
    const s = Ring8.fromCoeffs(&primes8, .{ [_]u64{ 1, 0, 16, 1, 0, 16, 1, 0 }, [_]u64{ 1, 0, 96, 1, 0, 96, 1, 0 } });
    const c1 = Ring8.fromCoeffs(&primes8, .{ [_]u64{ 3, 5, 7, 9, 11, 13, 15, 2 }, [_]u64{ 30, 50, 70, 90, 11, 33, 55, 77 } });

    // Noiseless: c0 = Δ·m − c1·s  ⇒  c0 + c1·s == Δ·m exactly.
    const target = scaledPlaintext(&m, deltaLimbs()); // Δ·m
    const c1s = c1.mul(&s, &engines);
    var c0 = target;
    c0.subAssign(&c1s, &primes8);

    const sk = B.SecretKey{ .s = s };
    const ct = B.Ciphertext{ .components = .{ c0, c1, Ring8.zero(.coeff) }, .len = 2 };
    const got = inst.decrypt(&sk, &ct);
    try testing.expectEqualSlices(u64, &m.coeffs, &got.coeffs); // exact Δ-rescale

    // Within-margin noise (+100 < Δ/2=206) at coeff 0 → still m.
    var c0_ok = c0;
    c0_ok.addAssign(&noiseAtCoeff0(100), &primes8);
    const ct_ok = B.Ciphertext{ .components = .{ c0_ok, c1, Ring8.zero(.coeff) }, .len = 2 };
    try testing.expectEqualSlices(u64, &m.coeffs, &inst.decrypt(&sk, &ct_ok).coeffs);

    // Over-margin noise (+300 > Δ/2) at coeff 0 → rounding flips that coeff.
    var c0_bad = c0;
    c0_bad.addAssign(&noiseAtCoeff0(300), &primes8);
    const ct_bad = B.Ciphertext{ .components = .{ c0_bad, c1, Ring8.zero(.coeff) }, .len = 2 };
    try testing.expect(inst.decrypt(&sk, &ct_bad).coeffs[0] != m.coeffs[0]);
}

// ── 2d. noiseBudget KAT: exercises the `vmax == 0` special case directly ──────
// Gap found by mutation testing: every existing noiseBudget call (the
// "multiply DEPTH" anchor below) only checks RELATIVE ordering
// (fresh > after-1-mul > after-2-mul, and > 0) on ciphertexts that always
// carry genuine ternary-sampled noise — vmax is never exactly 0 there, so the
// `if (vmax == 0) return log2(q/2)` branch (the exact-noiseless case) had NO
// discriminating test: mutating it to `return 0` left all 37 tests green.
// Reuse the same hand-built noiseless ciphertext as the decrypt KAT above
// (construction independent of keyGen/encrypt) to pin that branch, plus one
// call with known injected noise to confirm the budget strictly decreases
// away from the vmax==0 case.
test "noiseBudget KAT: noiseless ciphertext hits the exact vmax==0 case; added noise strictly lowers it" {
    if (!gate.scheme_core_implemented or !gate.fable_core_implemented) return error.SkipZigTest;
    const B = bfv.Bfv(P);
    const inst = try B.init();
    const engines = try ring.makeEngines(P.n, P.primes.len, &primes8);
    const Pt = encode.Plaintext(P.n);
    const m = Pt.fromCoeffs(P.t, .{ 1, 2, 3, 0, 1, 2, 3, 0 });

    const s = Ring8.fromCoeffs(&primes8, .{ [_]u64{ 1, 0, 16, 1, 0, 16, 1, 0 }, [_]u64{ 1, 0, 96, 1, 0, 96, 1, 0 } });
    const c1 = Ring8.fromCoeffs(&primes8, .{ [_]u64{ 3, 5, 7, 9, 11, 13, 15, 2 }, [_]u64{ 30, 50, 70, 90, 11, 33, 55, 77 } });
    const target = scaledPlaintext(&m, deltaLimbs());
    const c1s = c1.mul(&s, &engines);
    var c0 = target;
    c0.subAssign(&c1s, &primes8);

    const sk = B.SecretKey{ .s = s };
    const ct = B.Ciphertext{ .components = .{ c0, c1, Ring8.zero(.coeff) }, .len = 2 };
    // Exactly noiseless (v == Δ·m exactly, so the reconstructed `v` used
    // inside noiseBudget has zero deviation from Δ·m): the true max budget,
    // `log2(q/2)`, not the "exhausted" 0 a broken vmax==0 branch would give.
    const q: u128 = 17 * 97;
    const want_max: u32 = @intCast(std.math.log2_int(u128, q / 2));
    try testing.expectEqual(want_max, inst.noiseBudget(&sk, &ct));

    // Same ciphertext plus known noise at one coefficient: budget must drop
    // strictly below the noiseless maximum (and stay > 0, well under Δ/2=206).
    var c0_noisy = c0;
    c0_noisy.addAssign(&noiseAtCoeff0(100), &primes8);
    const ct_noisy = B.Ciphertext{ .components = .{ c0_noisy, c1, Ring8.zero(.coeff) }, .len = 2 };
    const budget_noisy = inst.noiseBudget(&sk, &ct_noisy);
    try testing.expect(budget_noisy < want_max);
    try testing.expect(budget_noisy > 0);
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

// The multiply/depth anchors run on `params.test_mul`, NOT `test_tiny`:
// test_tiny's q=1649 (Δ/2 = 206) cannot hold even ONE multiply's noise (the
// worst-case r–v cross term t·N·‖r‖·(B1+B2) ≈ 5.4e3 alone exceeds q), so a
// mul anchor there would at best pass probabilistically — exactly the hazard
// this harness must not have. test_mul is sized (worst-case ledger in
// params.zig) so depth-2 correctness is guaranteed for EVERY seed and EVERY
// plaintext, including the all-(t−1) boundary — which is why these tests can
// demand exact equality over random AND boundary inputs.
const PM = params.test_mul;
const BM = bfv.Bfv(PM);

test "homomorphic MUL+RELIN end-to-end: Dec(relin(Enc(a) ⊗ Enc(b))) == a·b (mod t), random + boundary" {
    if (!gate.scheme_core_implemented or !gate.fable_core_implemented) return error.SkipZigTest;
    const inst = try BM.init();
    var prng = std.Random.DefaultPrng.init(2);
    const rnd = prng.random();
    const kp = inst.keyGen(rnd);
    const rlk = inst.genRelinKey(&kp.sk, rnd);
    const Pt = BM.Plaintext;
    const t = PM.t;
    for (0..8) |it| {
        var ac: [BM.degree]u64 = undefined;
        var bc: [BM.degree]u64 = undefined;
        for (&ac, &bc) |*xx, *yy| {
            // Iteration 0: boundary — every coefficient t−1 (worst-case
            // message norm, catches range-dependent noise bugs); rest random.
            xx.* = if (it == 0) t - 1 else rnd.uintLessThan(u64, t);
            yy.* = if (it == 0) t - 1 else rnd.uintLessThan(u64, t);
        }
        const a = Pt.fromCoeffs(t, ac);
        const b = Pt.fromCoeffs(t, bc);
        const ca = inst.encrypt(&kp.pk, &a, rnd);
        const cb = inst.encrypt(&kp.pk, &b, rnd);
        const want = Pt.mulRef(&a, &b);
        const prod3 = inst.mul(&ca, &cb); // 3-component
        try testing.expectEqual(@as(usize, 3), prod3.numComponents());
        // The tensor+rescale must already be correct BEFORE relin (decrypt
        // handles the c2·s² term) — isolates `mul` from the key-switch.
        try testing.expectEqualSlices(u64, &want.coeffs, &inst.decrypt(&kp.sk, &prod3).coeffs);
        const prod2 = inst.relinearize(&prod3, &rlk); // back to 2
        try testing.expectEqual(@as(usize, 2), prod2.numComponents());
        try testing.expectEqualSlices(u64, &want.coeffs, &inst.decrypt(&kp.sk, &prod2).coeffs);
    }
}

test "positive control: corrupted relin key is caught by the mul anchor (key-switch is load-bearing)" {
    if (!gate.scheme_core_implemented or !gate.fable_core_implemented) return error.SkipZigTest;
    const inst = try BM.init();
    var prng = std.Random.DefaultPrng.init(4);
    const rnd = prng.random();
    const kp = inst.keyGen(rnd);
    var rlk = inst.genRelinKey(&kp.sk, rnd);
    // Corrupt the gadget rows' b-components: they no longer pseudo-encrypt
    // w^i·s², so the key-switched phase is wrong and the product must NOT
    // decrypt to a·b (deterministic seed ⇒ deterministic catch).
    for (&rlk.b) |*b_i| {
        for (0..BM.num_primes) |l| {
            for (&b_i.limbs[l]) |*x| x.* = rnd.uintLessThan(u64, PM.primes[l]);
        }
    }
    const Pt = BM.Plaintext;
    const a = Pt.fromCoeffs(PM.t, [_]u64{3} ** BM.degree);
    const b = Pt.fromCoeffs(PM.t, [_]u64{5} ** BM.degree);
    const ca = inst.encrypt(&kp.pk, &a, rnd);
    const cb = inst.encrypt(&kp.pk, &b, rnd);
    const prod2 = inst.relinearize(&inst.mul(&ca, &cb), &rlk);
    const got = inst.decrypt(&kp.sk, &prod2);
    const want = Pt.mulRef(&a, &b);
    try testing.expect(!std.mem.eql(u64, &want.coeffs, &got.coeffs));
}

test "enc/dec round-trip at realistic dimension (bfv_toy N=1024, comfortable margin)" {
    if (!gate.scheme_core_implemented) return error.SkipZigTest;
    const B = bfv.Bfv(params.bfv_toy);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0xB5F);
    const rnd = prng.random();
    const kp = inst.keyGen(rnd);
    const Pt = B.Plaintext;
    const t = params.bfv_toy.t;
    // A few random plaintexts + a homomorphic add, all decrypt back exactly:
    // fresh-noise |E| ≲ 2N+1 ≪ Δ/2 ≈ 2^49, so no seed can fail.
    for (0..8) |_| {
        var ca: [B.degree]u64 = undefined;
        var cb: [B.degree]u64 = undefined;
        for (&ca, &cb) |*x, *y| {
            x.* = rnd.uintLessThan(u64, t);
            y.* = rnd.uintLessThan(u64, t);
        }
        const a = Pt.fromCoeffs(t, ca);
        const b = Pt.fromCoeffs(t, cb);
        const ea = inst.encrypt(&kp.pk, &a, rnd);
        const eb = inst.encrypt(&kp.pk, &b, rnd);
        try testing.expectEqualSlices(u64, &a.coeffs, &inst.decrypt(&kp.sk, &ea).coeffs);
        const sum = inst.decrypt(&kp.sk, &inst.add(&ea, &eb));
        try testing.expectEqualSlices(u64, &Pt.addRef(&a, &b).coeffs, &sum.coeffs);
    }
}

// ── 4. Differential anchors for the RNS-NTT multiply rewrite ──────────────────
//
// `mul` no longer computes the tensor as an O(N²) exact-`i256` schoolbook; it
// runs it through an auxiliary RNS basis of NTT-friendly primes (7 transforms +
// 4N pointwise products per aux prime) and lifts the result back with a
// centered CRT. That is an EXACT algorithm, not an approximation, so the bar is
// bit-identical output — and the oracle is the OLD code, kept verbatim as
// `mulExactRef`, never a second fast path.
//
// The random corpus alone is not enough: real ciphertext coefficients are
// ~uniform in [0,q), so `|T|` concentrates far below the worst case that sizes
// `num_aux`. The extreme vectors below drive every centered coefficient to
// ±(q−1)/2 with aligned signs, which is exactly the input that saturates the
// `∏p_j > 2·tensor_bound` bound the exactness argument rests on.

/// Build a ring element whose j-th coefficient is the integer `vals[j] mod q`
/// (decomposed into its RNS residues) — lets a test pin exact big-integer
/// coefficients rather than only sampling residues.
fn ringFromIntegers(comptime B: type, primes_: []const u64, vals: []const u128) B.Ring {
    var out = B.Ring.zero(.coeff);
    for (0..B.num_primes) |i| {
        for (0..B.degree) |j| out.limbs[i][j] = @intCast(vals[j] % primes_[i]);
    }
    return out;
}

fn diffMul(comptime PP: params.Params, iters: usize, seed: u64) !void {
    const B = bfv.Bfv(PP);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    const q: u128 = B.q_product;
    const half: u128 = (q - 1) / 2;

    for (0..iters) |it| {
        var v: [4][B.degree]u128 = undefined;
        for (0..4) |c| {
            for (0..B.degree) |j| {
                v[c][j] = switch (it) {
                    // Saturating vectors: every centered coefficient at
                    // ±(q−1)/2, signs aligned so the convolution sums rather
                    // than cancels.
                    0 => half,
                    1 => q - half,
                    2 => if (j % 2 == 0) half else q - half,
                    // Mixed extremes + the 0 / 1 / q−1 boundary.
                    3 => ([_]u128{ 0, 1, q - 1, half, q - half })[j % 5],
                    else => rnd.int(u128) % q,
                };
            }
        }
        const x = B.Ciphertext{ .components = .{
            ringFromIntegers(B, PP.primes, &v[0]),
            ringFromIntegers(B, PP.primes, &v[1]),
            B.Ring.zero(.coeff),
        }, .len = 2 };
        const y = B.Ciphertext{ .components = .{
            ringFromIntegers(B, PP.primes, &v[2]),
            ringFromIntegers(B, PP.primes, &v[3]),
            B.Ring.zero(.coeff),
        }, .len = 2 };

        const fast = inst.mulRnsNtt(&x, &y); // direct, regardless of `mul`'s dispatch
        const ref = inst.mulExactRef(&x, &y);
        try testing.expectEqual(ref.len, fast.len);
        for (0..3) |c| {
            for (0..B.num_primes) |i| {
                try testing.expectEqualSlices(u64, &ref.components[c].limbs[i], &fast.components[c].limbs[i]);
            }
        }
    }
}

/// N=8, two ~60-bit primes: `q ≈ 2^120` drives `num_aux` to 4 (and the CRT
/// accumulator to `u320`), which none of the shipped parameter sets reaches.
/// Correctness-only, like every set in `params.zig`.
const wide_aux = params.Params{
    .n = 8,
    .t = 4,
    .primes = &.{ 1152921504606846577, 1152921504606846097 },
};

test "RNS-NTT tensor is bit-identical to the i256 schoolbook oracle (num_aux = 1, 2, 4)" {
    if (!gate.fable_core_implemented) return error.SkipZigTest;
    // num_aux == 1 (test_tiny, q = 1649)
    try testing.expectEqual(@as(usize, 1), bfv.Bfv(params.test_tiny).num_aux);
    try diffMul(params.test_tiny, 24, 0xD1);
    // num_aux == 2 (test_mul, q ≈ 2^35.6) — the set the mul anchors run on
    try testing.expectEqual(@as(usize, 2), bfv.Bfv(params.test_mul).num_aux);
    try diffMul(params.test_mul, 24, 0xD2);
    // num_aux == 4 (q ≈ 2^120) — exercises a multi-prime aux CRT and the
    // widened accumulator.
    try testing.expectEqual(@as(usize, 4), bfv.Bfv(wide_aux).num_aux);
    try diffMul(wide_aux, 24, 0xD3);
}

test "instance CRT reconstruct is bit-identical to rns.Basis.reconstruct" {
    inline for (.{ params.test_tiny, params.test_mul, wide_aux }) |PP| {
        const B = bfv.Bfv(PP);
        const inst = try B.init();
        const basis = try rns.Basis.init(PP.primes);
        var prng = std.Random.DefaultPrng.init(0xC27);
        const rnd = prng.random();
        var res: [PP.primes.len]u64 = undefined;
        // Boundary residue vectors first (all-zero, all-max), then random.
        for (0..2_000) |it| {
            for (0..PP.primes.len) |i| res[i] = switch (it) {
                0 => 0,
                1 => PP.primes[i] - 1,
                2 => 1,
                else => rnd.uintLessThan(u64, PP.primes[i]),
            };
            try testing.expectEqual(basis.reconstruct(&res), inst.reconstruct(&res));
        }
    }
}

// ── 5. Ternary sampler KAT (the constant-time rewrite needs teeth) ────────────
//
// Gap found by mutation testing DURING the F3 rewrite: swapping the `−1` and
// `+1` arms of the (new, branchless) trit select left ALL tests green — the
// ternary distribution is symmetric, so the scheme keeps working and every
// end-to-end anchor still passes. Nothing in the suite pinned what the sampler
// actually maps a draw to. That is precisely the hole a "constant-time" rewrite
// of a secret sampler must not be landed through, so this KAT drives `keyGen`
// with a SCRIPTED random source and pins the draw→trit map exactly, including
// both boundary words where `⌊3x/2^64⌋` steps.

/// A `std.Random` that emits a fixed cycle of 64-bit words (little-endian),
/// so a test can dictate exactly which trit the sampler must produce.
const ScriptedRandom = struct {
    words: []const u64,
    idx: usize = 0,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *ScriptedRandom = @ptrCast(@alignCast(ptr));
        var off: usize = 0;
        while (off < buf.len) {
            var tmp: [8]u8 = undefined;
            std.mem.writeInt(u64, &tmp, self.words[self.idx % self.words.len], .little);
            self.idx += 1;
            const n = @min(tmp.len, buf.len - off);
            @memcpy(buf[off..][0..n], tmp[0..n]);
            off += n;
        }
    }
    fn random(self: *ScriptedRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

test "ternary sampler KAT: scripted draws map to the exact trits (-1, 0, +1)" {
    if (!gate.scheme_core_implemented) return error.SkipZigTest;
    // `⌊3x/2^64⌋`: 0 for x ≤ 6148914691236517205, 1 up to 12297829382473034410,
    // 2 above. Both step points are included, from either side.
    var script = ScriptedRandom{
        .words = &.{
            0, // r=0 → −1
            6_148_914_691_236_517_205, // r=0 → −1  (last word below the first step)
            6_148_914_691_236_517_206, // r=1 →  0  (first word at/above it)
            12_297_829_382_473_034_410, // r=1 →  0  (last below the second step)
            12_297_829_382_473_034_411, // r=2 → +1  (first at/above it)
            std.math.maxInt(u64), // r=2 → +1
            1, // r=0 → −1
            1 << 63, // r=1 →  0
        },
    };
    const want_trit = [_]i8{ -1, -1, 0, 0, 1, 1, -1, 0 };

    const B = bfv.Bfv(P); // N=8, primes {17,97}
    const inst = try B.init();
    const kp = inst.keyGen(script.random()); // `s` is sampled first, from words[0..8]

    for (0..P.primes.len) |i| {
        const qi = primes8[i];
        for (0..P.n) |j| {
            const want: u64 = switch (want_trit[j]) {
                -1 => qi - 1,
                0 => 0,
                else => 1,
            };
            try testing.expectEqual(want, kp.sk.s.limbs[i][j]);
        }
    }
}

test "ternary sampler: every limb is a trit, consistently across limbs, all three occur" {
    if (!gate.scheme_core_implemented) return error.SkipZigTest;
    const B = bfv.Bfv(P);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0x7E12);
    const rnd = prng.random();
    var seen = [_]usize{ 0, 0, 0 };
    for (0..400) |_| {
        const kp = inst.keyGen(rnd);
        for (0..P.n) |j| {
            // Limb 0 decides the trit; every other limb must encode the SAME
            // small integer (this is the invariant that keeps the decrypt
            // noise a genuine small integer rather than a random residue).
            const v0 = kp.sk.s.limbs[0][j];
            const trit: usize = if (v0 == primes8[0] - 1) 0 else if (v0 == 0) 1 else if (v0 == 1) 2 else {
                return error.NotATrit;
            };
            seen[trit] += 1;
            for (0..P.primes.len) |i| {
                const want: u64 = switch (trit) {
                    0 => primes8[i] - 1,
                    1 => 0,
                    else => 1,
                };
                try testing.expectEqual(want, kp.sk.s.limbs[i][j]);
            }
        }
    }
    // 3200 draws: each trit's count is ~1067; a mapping that collapsed two
    // cases (or dropped one) shows up immediately.
    for (seen) |c| try testing.expect(c > 800 and c < 1400);
}

test "multiply DEPTH: Dec(a·b·c) == a·b·c (mod t) exercises the noise budget (random + boundary)" {
    if (!gate.scheme_core_implemented or !gate.fable_core_implemented) return error.SkipZigTest;
    const inst = try BM.init();
    var prng = std.Random.DefaultPrng.init(3);
    const rnd = prng.random();
    const kp = inst.keyGen(rnd);
    const rlk = inst.genRelinKey(&kp.sk, rnd);
    const Pt = BM.Plaintext;
    const t = PM.t;
    for (0..4) |it| {
        var ac: [BM.degree]u64 = undefined;
        var bc: [BM.degree]u64 = undefined;
        var cc: [BM.degree]u64 = undefined;
        for (&ac, &bc, &cc) |*xx, *yy, *zz| {
            // Iteration 0: all-(t−1) boundary triple (worst-case norms).
            xx.* = if (it == 0) t - 1 else rnd.uintLessThan(u64, t);
            yy.* = if (it == 0) t - 1 else rnd.uintLessThan(u64, t);
            zz.* = if (it == 0) t - 1 else rnd.uintLessThan(u64, t);
        }
        const a = Pt.fromCoeffs(t, ac);
        const b = Pt.fromCoeffs(t, bc);
        const c = Pt.fromCoeffs(t, cc);
        const ea = inst.encrypt(&kp.pk, &a, rnd);
        const eb = inst.encrypt(&kp.pk, &b, rnd);
        const ec = inst.encrypt(&kp.pk, &c, rnd);
        const ab = inst.relinearize(&inst.mul(&ea, &eb), &rlk);
        // Budget must still be positive after one multiply…
        const budget_fresh = inst.noiseBudget(&kp.sk, &ea);
        const budget_ab = inst.noiseBudget(&kp.sk, &ab);
        try testing.expect(budget_ab > 0);
        const abc = inst.relinearize(&inst.mul(&ab, &ec), &rlk);
        // …and each multiply must CONSUME budget (noiseBudget is honest).
        const budget_abc = inst.noiseBudget(&kp.sk, &abc);
        try testing.expect(budget_fresh > budget_ab);
        try testing.expect(budget_ab > budget_abc);
        const got = inst.decrypt(&kp.sk, &abc);
        const want = Pt.mulRef(&Pt.mulRef(&a, &b), &c);
        try testing.expectEqualSlices(u64, &want.coeffs, &got.coeffs);
    }
}
