// SPDX-License-Identifier: MIT

//! kat_test — the verification harness with teeth.
//!
//! Four families, per the scaffold plan:
//!   1. **KAT vs the external oracle.** The portable path's `mul` and `powMont`
//!      are byte-exact against `kat_vectors.zig` (independent CPython bignum,
//!      the `vdf`-audit anchoring) at 256/512/2048/4096 bits. This anchors the
//!      portable path as the correctness ORACLE.
//!   2. **asm-vs-portable differential.** The anti-self-consistency anchor: for
//!      many random `(a,b,odd-N)` the gated amd64 core MUST reproduce the
//!      oracle bit-for-bit. SKIPs until `gate.asm_core_implemented` — a skip is
//!      NOT a green light.
//!   3. **Positive control (BrokenMont).** A CIOS that drops the final
//!      conditional subtract disagrees with the oracle on random inputs, and
//!      only ever by exactly `m` — proving the reduction is load-bearing and
//!      the equality checks have teeth.
//!   4. **CT smoke.** Boundary behavior of the constant-time conditional
//!      subtract + a reasoning-anchored note on the no-secret-branch contract.

const std = @import("std");
const builtin = @import("builtin");
const montint = @import("montint.zig");
const limbs = @import("limbs.zig");
const gate = @import("gate.zig");
const asm_core = @import("asm_core.zig");
const kv = @import("kat_vectors.zig");
const Modint = montint.Modint;

// ── 1. KAT vs the external (CPython bignum) oracle ───────────────────────────

fn checkSize(comptime bits: comptime_int, comptime Size: type) !void {
    const M = Modint(bits);
    comptime std.debug.assert(M.L == Size.limbs_len);
    const m = try M.fromElem(Size.m);

    // modmul: (a·b) mod m
    const a: M.Elem = Size.a;
    const b: M.Elem = Size.b;
    const got_mul = m.mul(&a, &b);
    try std.testing.expectEqualSlices(u64, &@as(M.Elem, Size.mulmod), &got_mul);

    // modexp: a^e mod m (full-width exponent → constant-time windowed path)
    const e: M.Elem = Size.e;
    const got_exp = m.powMont(&a, &e);
    try std.testing.expectEqualSlices(u64, &@as(M.Elem, Size.powmod), &got_exp);
}

test "KAT: modmul + modexp byte-exact vs CPython oracle @ 256-bit" {
    try checkSize(256, kv.Size256);
}
test "KAT: modmul + modexp byte-exact vs CPython oracle @ 512-bit" {
    try checkSize(512, kv.Size512);
}
test "KAT: modmul + modexp byte-exact vs CPython oracle @ 2048-bit" {
    try checkSize(2048, kv.Size2048);
}
test "KAT: modmul + modexp byte-exact vs CPython oracle @ 4096-bit" {
    try checkSize(4096, kv.Size4096);
}

// A domain round-trip on real vectors: toMontgomery/fromMontgomery is identity,
// and Montgomery-resident multiply matches the normal-domain KAT.
test "domain conversion round-trips + Montgomery-resident mul matches KAT" {
    const M = Modint(2048);
    const m = try M.fromElem(kv.Size2048.m);
    const a: M.Elem = kv.Size2048.a;
    const back = m.fromMontgomery(&m.toMontgomery(&a));
    try std.testing.expectEqualSlices(u64, &a, &back);

    // mul via explicit Montgomery residency == the normal-domain KAT.
    const b: M.Elem = kv.Size2048.b;
    const am = m.toMontgomery(&a);
    const prod_mont = m.montMul(&am, &b); // (a·R)·b·R⁻¹ = a·b
    try std.testing.expectEqualSlices(u64, &@as(M.Elem, kv.Size2048.mulmod), &prod_mont);
}

// ── 2. asm-vs-portable differential (gated anti-self-consistency anchor) ─────

test "differential: amd64 asm core == portable oracle on random (a,b,odd-N)" {
    if (!gate.asm_core_implemented) return error.SkipZigTest; // SKIP ≠ pass
    if (!asm_core.supported) return error.SkipZigTest; // non-amd64 target

    const bits = 2048;
    const M = Modint(bits);
    var prng = std.Random.DefaultPrng.init(0x0C1057_A11_1);
    const rand = prng.random();

    var trials: usize = 0;
    while (trials < 5000) : (trials += 1) {
        // odd modulus with top bit set (⇒ any L-limb value < 2m).
        var mv: M.Elem = undefined;
        for (&mv) |*w| w.* = rand.int(u64);
        mv[0] |= 1;
        mv[M.L - 1] |= 1 << 63;
        const m = try M.fromElem(mv);

        const a = randBelow(M, rand, &mv);
        const b = randBelow(M, rand, &mv);

        // portable oracle
        const want = m.montMulCios(&a, &b);
        // asm core through the same public entry (dispatch is active here)
        var got: M.Elem = undefined;
        asm_core.montMul(&got, &a, &b, &m.m, m.n0inv);
        try std.testing.expectEqualSlices(u64, &want, &got);
    }
}

fn randBelow(comptime M: type, rand: std.Random, m: *const M.Elem) M.Elem {
    var v: M.Elem = undefined;
    for (&v) |*w| w.* = rand.int(u64);
    // v < 2m (top bit of m set), so a single conditional subtract reduces it.
    if (limbs.cmp(&v, m) != .lt) _ = limbs.subInto(&v, m);
    return v;
}

// ── 2b. squaring differential: montSqrCios == montMulCios(a,a) (the anchor) ──
//
// The dedicated portable square is anchored to the already-proven general
// multiply on the SAME operand: for thousands of random `a` across every limb
// count it must equal `montMulCios(a, a)` bit-for-bit, in Debug AND ReleaseFast.
// `montMulCios` is byte-exact vs the external CPython oracle (family 1), so this
// transitively pins the square to the external oracle without a second KAT set.

fn sqrDifferentialAtN(comptime bits: comptime_int, trials: usize, seed: u64) !void {
    const M = Modint(bits);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    var t: usize = 0;
    while (t < trials) : (t += 1) {
        // odd modulus, top bit set ⇒ any L-limb value is < 2m.
        var mv: M.Elem = undefined;
        for (&mv) |*w| w.* = rand.int(u64);
        mv[0] |= 1;
        mv[M.L - 1] |= 1 << 63;
        const m = try M.fromElem(mv);

        const a = randBelow(M, rand, &mv);
        const want = m.montMulCios(&a, &a); // proven-vs-oracle general multiply
        const got = m.montSqrCios(&a); // dedicated square under test
        try std.testing.expectEqualSlices(u64, &want, &got);

        // Also exercise the public `montSqr` dispatch: for L < asm_min_limbs it
        // routes to `montSqrCios`; for L ≥ it routes to asm `montMul(a,a)`.
        // Either way it must still equal the oracle square.
        const gotpub = m.montSqr(&a);
        try std.testing.expectEqualSlices(u64, &want, &gotpub);
    }
}

test "squaring differential: montSqrCios == montMulCios(a,a) across ALL limb counts" {
    // n ∈ {1,2,3,4,5,8,16,17,32,33,64} via bit widths; small n get more trials.
    try sqrDifferentialAtN(64, 4000, 0x5A11_0001); // L=1
    try sqrDifferentialAtN(128, 4000, 0x5A11_0002); // L=2
    try sqrDifferentialAtN(192, 4000, 0x5A11_0003); // L=3
    try sqrDifferentialAtN(256, 4000, 0x5A11_0004); // L=4
    try sqrDifferentialAtN(320, 3000, 0x5A11_0005); // L=5
    try sqrDifferentialAtN(512, 3000, 0x5A11_0008); // L=8
    try sqrDifferentialAtN(1024, 1500, 0x5A11_0010); // L=16 (rsa-2048 CRT half)
    try sqrDifferentialAtN(1088, 1500, 0x5A11_0011); // L=17 (odd, > karatsuba thr)
    try sqrDifferentialAtN(2048, 800, 0x5A11_0020); // L=32 (asm-dispatch boundary)
    try sqrDifferentialAtN(2112, 800, 0x5A11_0021); // L=33
    try sqrDifferentialAtN(4096, 300, 0x5A11_0040); // L=64
}

// ── 2c. ASM squaring differential: asm montSqr == montSqrCios == montMul(a,a) ─
//
// The dedicated amd64 asm square is anchored THREE ways per trial: against the
// portable dedicated square (`montSqrCios`, itself pinned to `montMulCios(a,a)`
// in 2b and transitively to the external CPython oracle), against the asm
// general multiply on the same operand (`asm_core.montMul(a,a)`, proven by the
// montMul differential), and through the public `montSqr` dispatch. Runs in
// Debug AND ReleaseFast. Limb counts cover every rem∈{0,1,2,3} class of the
// reduction row (32,33,34,35) plus 48 and 64; the cross-product rows sweep
// every length 1..n−1 within a single op, so all remainder paths of `mulRow`
// are exercised at every n.

fn asmSqrDifferentialAtN(comptime bits: comptime_int, trials: usize, seed: u64) !void {
    const M = Modint(bits);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    var t: usize = 0;
    while (t < trials) : (t += 1) {
        // odd modulus, top bit set ⇒ any L-limb value is < 2m.
        var mv: M.Elem = undefined;
        for (&mv) |*w| w.* = rand.int(u64);
        mv[0] |= 1;
        mv[M.L - 1] |= 1 << 63;
        const m = try M.fromElem(mv);
        const a = randBelow(M, rand, &mv);
        try asmSqrCheckOne(M, &m, &a);
    }
    // Deterministic carry-saturation edges: m = 2^(64L)−1 (odd, all-ones), with
    // a = m−1 (maximal limbs 0xFF…FE) and a small dense value; plus a = 0 and 1.
    const m1 = try M.fromElem(@as(M.Elem, @splat(std.math.maxInt(u64))));
    var edge: M.Elem = @splat(std.math.maxInt(u64));
    edge[0] = std.math.maxInt(u64) - 1; // a = m−1
    try asmSqrCheckOne(M, &m1, &edge);
    edge = std.mem.zeroes(M.Elem);
    try asmSqrCheckOne(M, &m1, &edge); // a = 0
    edge[0] = 1;
    try asmSqrCheckOne(M, &m1, &edge); // a = 1
}

fn asmSqrCheckOne(comptime M: type, m: *const M, a: *const M.Elem) !void {
    const want = m.montSqrCios(a); // portable dedicated square (2b-anchored)
    var got_sqr: M.Elem = undefined;
    var scratch: [2 * M.L]u64 = undefined;
    asm_core.montSqr(&got_sqr, a, &m.m, m.n0inv, &scratch);
    try std.testing.expectEqualSlices(u64, &want, &got_sqr);
    // asm general multiply on the same operand (independent asm path).
    var got_mul: M.Elem = undefined;
    asm_core.montMul(&got_mul, a, a, &m.m, m.n0inv);
    try std.testing.expectEqualSlices(u64, &want, &got_mul);
    // public dispatch (routes to the asm square at L ≥ asm_min_limbs).
    const got_pub = m.montSqr(a);
    try std.testing.expectEqualSlices(u64, &want, &got_pub);
}

test "ASM squaring differential: asm montSqr == montSqrCios == asm montMul(a,a)" {
    if (!gate.asm_core_implemented) return error.SkipZigTest; // SKIP ≠ pass
    if (!asm_core.supported) return error.SkipZigTest; // non-amd64 target

    // Small L first (the asm square must be correct at EVERY n, like montMul —
    // the L≥32 cutoff is a speed dispatch, not a correctness bound)…
    try asmSqrDifferentialAtN(64, 2000, 0xA5B_0001); // L=1
    try asmSqrDifferentialAtN(128, 2000, 0xA5B_0002); // L=2
    try asmSqrDifferentialAtN(192, 2000, 0xA5B_0003); // L=3
    try asmSqrDifferentialAtN(256, 2000, 0xA5B_0004); // L=4
    try asmSqrDifferentialAtN(320, 1500, 0xA5B_0005); // L=5
    try asmSqrDifferentialAtN(512, 1500, 0xA5B_0008); // L=8
    try asmSqrDifferentialAtN(1024, 800, 0xA5B_0010); // L=16
    try asmSqrDifferentialAtN(1088, 800, 0xA5B_0011); // L=17
    // …then the sizes the asm square actually serves (all rem classes of the
    // reduction row: 32≡0, 33≡1, 34≡2, 35≡3 mod 4) and the big RSA/Paillier Ls.
    try asmSqrDifferentialAtN(2048, 1000, 0xA5B_0020); // L=32 (dispatch boundary)
    try asmSqrDifferentialAtN(2112, 700, 0xA5B_0021); // L=33
    try asmSqrDifferentialAtN(2176, 500, 0xA5B_0022); // L=34
    try asmSqrDifferentialAtN(2240, 500, 0xA5B_0023); // L=35
    try asmSqrDifferentialAtN(3072, 400, 0xA5B_0030); // L=48 (rsa-3072)
    try asmSqrDifferentialAtN(4096, 300, 0xA5B_0040); // L=64
}

// Positive control for the ASM square: a deliberately-wrong asm-rows square —
// built from the SAME `asm_core.mulRow` primitive but with the doubling pass
// omitted (every off-diagonal product counted once instead of twice) — must
// DISAGREE with the oracle square, proving the asm differential has teeth.
fn brokenAsmSqrNoDouble(comptime M: type, self: *const M, a: *const M.Elem) M.Elem {
    const L = M.L;
    var A = [_]u64{0} ** (2 * L);
    // cross-product rows via the real asm primitive (correct)
    var i: usize = 0;
    while (i + 1 < L) : (i += 1) {
        const len = L - 1 - i;
        A[i + L] = asm_core.mulRow(@as([*]u64, &A) + (2 * i + 1), @as([*]const u64, a) + (i + 1), len & 3, len >> 2, a[i]);
    }
    // DOUBLING DELIBERATELY OMITTED (the bug).
    // diagonal (correct)
    var dcarry: u64 = 0;
    i = 0;
    while (i < L) : (i += 1) {
        const sq = @as(u128, a[i]) * @as(u128, a[i]);
        const p1 = @as(u128, A[2 * i]) + @as(u64, @truncate(sq)) + dcarry;
        A[2 * i] = @truncate(p1);
        const p2 = @as(u128, A[2 * i + 1]) + @as(u64, @truncate(sq >> 64)) + @as(u64, @truncate(p1 >> 64));
        A[2 * i + 1] = @truncate(p2);
        dcarry = @truncate(p2 >> 64);
    }
    // reduction rows via the real asm primitive (correct)
    var cc: u64 = 0;
    i = 0;
    while (i < L) : (i += 1) {
        const u = A[i] *% self.n0inv;
        const carry = asm_core.mulRow(@as([*]u64, &A) + i, &self.m, L & 3, L >> 2, u);
        const s = @as(u128, A[i + L]) + carry + cc;
        A[i + L] = @truncate(s);
        cc = @truncate(s >> 64);
    }
    var z: M.Elem = undefined;
    @memcpy(&z, A[L .. 2 * L]);
    var borrow: u1 = 0;
    var diff = z;
    for (&diff, &self.m) |*d, mi| {
        const s = @subWithOverflow(d.*, mi);
        const s2 = @subWithOverflow(s[0], borrow);
        d.* = s2[0];
        borrow = s[1] | s2[1];
    }
    const under = @subWithOverflow(cc, @as(u64, borrow))[1];
    if (under == 0) z = diff;
    return z;
}

test "positive control: an asm square missing the off-diagonal double is caught (teeth)" {
    if (!gate.asm_core_implemented) return error.SkipZigTest;
    if (!asm_core.supported) return error.SkipZigTest;
    const M = Modint(2048); // a size the asm square actually serves
    var prng = std.Random.DefaultPrng.init(0xA5B_DEAD);
    const rand = prng.random();
    var disagreements: usize = 0;
    var trials: usize = 0;
    while (trials < 100) : (trials += 1) {
        var mv: M.Elem = undefined;
        for (&mv) |*w| w.* = rand.int(u64);
        mv[0] |= 1;
        mv[M.L - 1] |= 1 << 63;
        const m = try M.fromElem(mv);
        const a = randBelow(M, rand, &mv);
        const good = m.montSqrCios(&a);
        const broken = brokenAsmSqrNoDouble(M, &m, &a);
        if (!std.mem.eql(u64, &good, &broken)) disagreements += 1;
    }
    // teeth: missing the ×2 MUST be observable.
    try std.testing.expect(disagreements > 0);
}

// Positive control for the SQUARE: a deliberately-wrong square (drops the
// diagonal `a[i]²` term) must DISAGREE with `montMulCios(a,a)`, proving the
// differential above has teeth — a silently-passing square is caught here.
fn brokenSqrNoDiagonal(comptime M: type, self: *const M, a: *const M.Elem) M.Elem {
    const L = M.L;
    const m = &self.m;
    var A = [_]u64{0} ** (2 * L);
    // cross products (correct)
    var i: usize = 0;
    while (i < L) : (i += 1) {
        var carry: u64 = 0;
        var j: usize = i + 1;
        while (j < L) : (j += 1) {
            const p = @as(u128, a[i]) * @as(u128, a[j]) + A[i + j] + carry;
            A[i + j] = @truncate(p);
            carry = @truncate(p >> 64);
        }
        A[i + L] = carry;
    }
    // double (correct)
    var top: u64 = 0;
    for (&A) |*w| {
        const nw = (w.* << 1) | top;
        top = w.* >> 63;
        w.* = nw;
    }
    // DIAGONAL DELIBERATELY OMITTED (the bug).
    // reduction (correct)
    var cc: u64 = 0;
    i = 0;
    while (i < L) : (i += 1) {
        const u = A[i] *% self.n0inv;
        var carry: u64 = 0;
        var j: usize = 0;
        while (j < L) : (j += 1) {
            const p = @as(u128, u) * @as(u128, m[j]) + A[i + j] + carry;
            A[i + j] = @truncate(p);
            carry = @truncate(p >> 64);
        }
        const s = @as(u128, A[i + L]) + carry + cc;
        A[i + L] = @truncate(s);
        cc = @truncate(s >> 64);
    }
    var z: M.Elem = undefined;
    @memcpy(&z, A[L .. 2 * L]);
    // reduce with the same masked helper the real path uses (via a full sub loop)
    var borrow: u1 = 0;
    var diff = z;
    for (&diff, m) |*d, mi| {
        const s = @subWithOverflow(d.*, mi);
        const s2 = @subWithOverflow(s[0], borrow);
        d.* = s2[0];
        borrow = s[1] | s2[1];
    }
    const under = @subWithOverflow(cc, @as(u64, borrow))[1];
    if (under == 0) z = diff;
    return z;
}

test "positive control: a square missing the diagonal term is caught (teeth)" {
    const M = Modint(512);
    var prng = std.Random.DefaultPrng.init(0x5A11_DEAD);
    const rand = prng.random();
    var disagreements: usize = 0;
    var trials: usize = 0;
    while (trials < 400) : (trials += 1) {
        var mv: M.Elem = undefined;
        for (&mv) |*w| w.* = rand.int(u64);
        mv[0] |= 1;
        mv[M.L - 1] |= 1 << 63;
        const m = try M.fromElem(mv);
        const a = randBelow(M, rand, &mv);
        const good = m.montSqrCios(&a);
        const broken = brokenSqrNoDiagonal(M, &m, &a);
        if (!std.mem.eql(u64, &good, &broken)) disagreements += 1;
    }
    // teeth: dropping the diagonal MUST be observable.
    try std.testing.expect(disagreements > 0);
}

// ── 3. positive control: BrokenMont (drops the final conditional subtract) ───

// A byte-for-byte copy of the portable CIOS with the reducing subtract removed.
// Its result is in [0, 2m) instead of [0, m).
fn brokenMontMulNoReduce(comptime M: type, self: *const M, a: *const M.Elem, b: *const M.Elem) M.Elem {
    const L = M.L;
    var t = [_]u64{0} ** (L + 2);
    var i: usize = 0;
    while (i < L) : (i += 1) {
        var carry: u64 = 0;
        var j: usize = 0;
        while (j < L) : (j += 1) {
            const p = @as(u128, a[j]) * @as(u128, b[i]) + t[j] + carry;
            t[j] = @truncate(p);
            carry = @truncate(p >> 64);
        }
        const s = @as(u128, t[L]) + carry;
        t[L] = @truncate(s);
        t[L + 1] = @truncate(s >> 64);
        const u = t[0] *% self.n0inv;
        const p0 = @as(u128, u) * @as(u128, self.m[0]) + t[0];
        var carry2: u64 = @truncate(p0 >> 64);
        j = 1;
        while (j < L) : (j += 1) {
            const p = @as(u128, u) * @as(u128, self.m[j]) + t[j] + carry2;
            t[j - 1] = @truncate(p);
            carry2 = @truncate(p >> 64);
        }
        const s2 = @as(u128, t[L]) + carry2;
        t[L - 1] = @truncate(s2);
        t[L] = t[L + 1] +% @as(u64, @truncate(s2 >> 64));
    }
    var z: M.Elem = undefined;
    @memcpy(&z, t[0..L]);
    // NOTE: the correct code does `condSubTop(&z, t[L], m)` HERE. Omitted.
    return z;
}

test "positive control: dropping the final conditional subtract is caught" {
    const M = Modint(512);
    const m = try M.fromElem(kv.Size512.m);
    var prng = std.Random.DefaultPrng.init(0xB0_07ED);
    const rand = prng.random();

    var disagreements: usize = 0;
    var trials: usize = 0;
    while (trials < 400) : (trials += 1) {
        var av: M.Elem = undefined;
        var bv: M.Elem = undefined;
        for (&av) |*w| w.* = rand.int(u64);
        for (&bv) |*w| w.* = rand.int(u64);
        if (limbs.cmp(&av, &m.m) != .lt) _ = limbs.subInto(&av, &m.m);
        if (limbs.cmp(&bv, &m.m) != .lt) _ = limbs.subInto(&bv, &m.m);

        const good = m.montMulCios(&av, &bv);
        const broken = brokenMontMulNoReduce(M, &m, &av, &bv);
        if (!std.mem.eql(u64, &good, &broken)) {
            disagreements += 1;
            // when it disagrees it is off by EXACTLY m (an unreduced residue).
            var fixed = broken;
            _ = limbs.subInto(&fixed, &m.m);
            try std.testing.expectEqualSlices(u64, &good, &fixed);
        }
    }
    // teeth: the missing subtract MUST be observable.
    try std.testing.expect(disagreements > 0);
}

// ── 4. CT smoke: boundary behavior of the constant-time reduction ────────────

test "CT smoke: modular add/sub reduce correctly at the m boundary" {
    // Use a small explicit odd modulus so boundaries are hand-checkable.
    const M = Modint(128);
    var mv = std.mem.zeroes(M.Elem);
    mv[0] = 1_000_003; // odd
    const m = try M.fromElem(mv);

    var mm1 = mv; // m - 1
    _ = limbs.subInto(&mm1, &blk: {
        var one = std.mem.zeroes(M.Elem);
        one[0] = 1;
        break :blk one;
    });
    var one = std.mem.zeroes(M.Elem);
    one[0] = 1;

    // (m-1) + 1 == 0  (exact wrap at the modulus)
    const wrap = m.add(&mm1, &one);
    try std.testing.expectEqualSlices(u64, &std.mem.zeroes(M.Elem), &wrap);
    // 0 - 1 == m-1
    const under = m.sub(&std.mem.zeroes(M.Elem), &one);
    try std.testing.expectEqualSlices(u64, &mm1, &under);
    // (m-1)*(m-1) mod m == 1
    const sq = m.mul(&mm1, &mm1);
    try std.testing.expectEqualSlices(u64, &one, &sq);
}

test "CT contract note" {
    // Reasoning anchor (no timing assertion is possible in a unit test): the
    // portable path has no secret-dependent branch, index, or early exit —
    //   • montMulCios: fixed L² inner iterations; the reduction is `condSubTop`
    //     (a masked select), never an `if`.
    //   • powMont: fixed 5-bit windows over ALL L·64 exponent bits; every
    //     window multiplies (digit 0 multiplies by `1`); the table gather is a
    //     branchless `limbs.select` over all 32 entries.
    //   • limbs.cmp inspects every limb regardless of where values differ.
    // The amd64 core inherits the same contract (see SPEC.md "Constant-time").
    try std.testing.expect(!(montint.asm_active and !asm_core.supported));
}
