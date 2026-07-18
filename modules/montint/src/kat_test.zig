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
