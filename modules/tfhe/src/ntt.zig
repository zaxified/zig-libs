// SPDX-License-Identifier: MIT

//! ntt — an **exact** `O(N log N)` negacyclic ring multiply for
//! `R = Z_{2^32}[X]/(X^N + 1)`, the GLWE/GGSW coefficient ring of TFHE.
//!
//! ## Why this is not the usual "TFHE FFT"
//!
//! Reference TFHE implementations (TFHE-rs, concrete, the original tfhe C++)
//! speed the ring multiply up with a **`f64` complex negacyclic FFT**. That is
//! fast but *inexact*: it needs a rounding-error budget, a proof that the
//! parameter set keeps the error below half an LSB, and it drags
//! floating-point reproducibility into a module that is otherwise pure integer
//! arithmetic. This module takes the other road:
//!
//!   * one 64-bit NTT-friendly prime `p = 2^64 − 2^32 + 1` (the "Goldilocks"
//!     prime — `2^32 | p−1`, so a primitive `2N`-th root of unity exists for
//!     every power-of-two `N ≤ 2^31`),
//!   * the two operands split into 16-bit halves so the *integer* convolution
//!     provably fits in `p`,
//!   * exact reconstruction of the result mod `2^32`.
//!
//! No floating point, no error bound to defend, no `platform` restriction:
//! the output is **bit-identical** to the `O(N²)` schoolbook convolution on
//! every input, and `poly.zig`'s differential test asserts exactly that.
//!
//! ## The split, and why it is exact
//!
//! Write `a = a_h·2^16 + a_l` and `b = b_h·2^16 + b_l` coefficient-wise, all
//! four parts in `[0, 2^16)`. Over the integers, negacyclically,
//!
//!     a·b = a_l·b_l + 2^16·(a_l·b_h + a_h·b_l) + 2^32·(a_h·b_h)
//!
//! and the last term vanishes mod `2^32`. So the value we need is
//!
//!     C = a_l·b_l + 2^16·(a_l·b_h + a_h·b_l)      (exact integers)
//!
//! whose coefficients are bounded by
//!
//!     |C_k| ≤ N·2^32 + 2^16·2N·2^32 < N·2^49.
//!
//! For every `N ≤ 2^13` that is `< p/2`, so the residue `C_k mod p` determines
//! `C_k` exactly (`C_k = r` if `r ≤ p/2`, else `r − p`), and `C_k mod 2^32` is
//! the answer. `max_degree` below pins the bound; `Engine` refuses to compile
//! above it.
//!
//! Cost: **four forward transforms and one inverse** — the `2^16` weighting
//! and the two cross terms are combined *inside* the transform domain (legal
//! because the bound above covers the combined value), so only one inverse
//! transform is needed.
//!
//! ## Transform convention
//!
//! Cooley–Tukey forward with `psi_rev[i] = psi^bitrev(i)` producing
//! bit-reversed output; Gentleman–Sande inverse with the inverse twiddles and
//! a final `N^{-1}` scaling, consuming bit-reversed input and producing
//! natural order (Longa–Naehrig). `psi` is a primitive `2N`-th root of unity,
//! which is what makes the transform negacyclic. Same convention as the
//! in-repo `bfv`/`falcon` NTTs, but with a compile-time prime and compile-time
//! twiddle tables (TFHE's ring modulus is fixed, so nothing is chosen at run
//! time).
//!
//! **All REAL / ungated** — no secrets, no randomness, no allocation.

const std = @import("std");

/// The Goldilocks prime `p = 2^64 − 2^32 + 1`.
pub const p: u64 = 0xFFFF_FFFF_0000_0001;
/// `2^64 − p = 2^32 − 1`. Subtracting `p` from a value that wrapped past
/// `2^64` is the same as adding this.
const eps: u64 = 0xFFFF_FFFF;
/// A generator of `(Z/p)^*`.
const generator: u64 = 7;

/// Largest ring degree the 16-bit split is proved exact for (`N·2^49 < p/2`
/// needs `N < 2^14`; we keep a full bit of margin).
pub const max_degree: usize = 1 << 13;

// ── modular arithmetic mod p (canonical, branch-light) ───────────────────────

/// All-ones iff `c` is set — the arithmetic-select mask these routines use in
/// place of a branch. (Chosen for *speed*, not for secrecy: nothing in this
/// file touches a secret. Branches here were measured at ~2× the cost.)
inline fn mask(c: u1) u64 {
    return 0 -% @as(u64, c);
}

/// `a + b mod p` for canonical `a, b < p`.
pub inline fn addMod(a: u64, b: u64) u64 {
    const s, const carry = @addWithOverflow(a, b);
    // Carry ⇒ the true sum is `s + 2^64 = s + p + eps`, so `s +% eps` is the
    // sum minus `p`, and it is already `< p` because `a + b < 2p`.
    var r = s +% (eps & mask(carry));
    r -%= p & mask(@intFromBool(r >= p));
    return r;
}

/// `a − b mod p` for canonical `a, b < p`.
pub inline fn subMod(a: u64, b: u64) u64 {
    const d, const borrow = @subWithOverflow(a, b);
    // Borrow ⇒ `d = a − b + 2^64`; we want `a − b + p = d − eps`.
    return d -% (eps & mask(borrow));
}

/// Reduce a 128-bit product to the canonical residue in `[0, p)`.
///
/// Uses `2^64 ≡ 2^32 − 1` and `2^96 ≡ −1 (mod p)`: writing
/// `x = lo + 2^64·(hh·2^32 + hl)` gives `x ≡ lo − hh + hl·(2^32−1)`.
/// Entirely branch-free: on this host the `if`-shaped version cost roughly
/// twice as much in the NTT butterflies.
pub inline fn reduce128(x: u128) u64 {
    const lo: u64 = @truncate(x);
    const hi: u64 = @truncate(x >> 64);
    const hh: u64 = hi >> 32; // < 2^32
    const hl: u64 = hi & 0xFFFF_FFFF; // < 2^32

    // `lo − hh (mod p)`, kept in `[0, 2^64)` rather than `[0, p)`. On borrow
    // the true value is `s0 − 2^64 ≡ s0 − eps (mod p)`, and `s0 > 2^64 − 2^32`
    // there, so the subtraction cannot underflow.
    const s0, const borrow = @subWithOverflow(lo, hh);
    const t0 = s0 -% (eps & mask(borrow));
    // `hl·eps ≤ (2^32−1)^2 = 2^64 − 2^33 + 1 < p`, so `t1` is already canonical.
    const t1 = hl *% eps;
    // `t0 + t1 < 2^64 + p < 2p·…`: one wraparound fix plus one conditional
    // subtract is enough to land back in `[0, p)`.
    const s1, const carry = @addWithOverflow(t0, t1);
    var r = s1 +% (eps & mask(carry));
    r -%= p & mask(@intFromBool(r >= p));
    return r;
}

/// `a · b mod p`.
pub inline fn mulMod(a: u64, b: u64) u64 {
    return reduce128(@as(u128, a) * @as(u128, b));
}

/// Map a canonical residue `r ∈ [0, p)` back to the `2^32` torus, under the
/// standing assumption that the value it represents is the **signed** integer
/// of least absolute value: `v = r` if `r ≤ p/2`, else `v = r − p`.
///
/// `p mod 2^32 == 1`, so `v mod 2^32` is `lo32(r)` minus one in the negative
/// branch. Branch-free (the comparison feeds an `@intFromBool`, not a jump).
///
/// ⚠ The `p/2` threshold is **not** pinned by the differential test against
/// `mulSchoolbook`: the convolution values are bounded by `N·2^49 ≤ 2^62/16`,
/// six binary orders below `p/2`, so every threshold in that whole gap gives
/// the same answer on real inputs and an off-by-one here is invisible to it.
/// The unit test below pins the threshold directly, at `p/2` and `p/2 + 1`.
pub inline fn recoverTorus(r: u64) u32 {
    const negative: u32 = @intFromBool(r > p / 2);
    return @as(u32, @truncate(r)) -% negative;
}

fn powMod(base: u64, exp: u64) u64 {
    var result: u64 = 1;
    var b = base % p;
    var e = exp;
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) result = mulMod(result, b);
        b = mulMod(b, b);
    }
    return result;
}

// ── the engine ───────────────────────────────────────────────────────────────

/// Negacyclic NTT engine for a comptime power-of-two degree `N`. All twiddle
/// tables are computed at comptime, so an `Engine(N)` is a pure namespace —
/// no state, no `init`, no allocation.
pub fn Engine(comptime N: usize) type {
    comptime std.debug.assert(N > 1 and (N & (N - 1)) == 0);
    comptime std.debug.assert(N <= max_degree);
    const log_n: u6 = std.math.log2_int(usize, N);

    return struct {
        const Self = @This();
        pub const degree = N;

        fn bitrev(x: usize) usize {
            var r: usize = 0;
            var v = x;
            var i: u6 = 0;
            while (i < log_n) : (i += 1) {
                r = (r << 1) | (v & 1);
                v >>= 1;
            }
            return r;
        }

        /// `psi` — a primitive `2N`-th root of unity mod `p`, and its inverse.
        pub const psi: u64 = blk: {
            @setEvalBranchQuota(2_000_000);
            const v = powMod(generator, (p - 1) / (2 * N));
            // Self-check: `psi^N = −1` is exactly what makes it negacyclic.
            std.debug.assert(powMod(v, N) == p - 1);
            break :blk v;
        };
        const psi_inv: u64 = blk: {
            @setEvalBranchQuota(2_000_000);
            break :blk powMod(psi, p - 2);
        };
        const n_inv: u64 = blk: {
            @setEvalBranchQuota(2_000_000);
            break :blk powMod(N % p, p - 2);
        };

        /// `psi_rev[i] = psi^bitrev(i)` (forward twiddles).
        const psi_rev: [N]u64 = tbl: {
            @setEvalBranchQuota(4_000_000);
            var pw: [N]u64 = undefined;
            pw[0] = 1;
            for (1..N) |i| pw[i] = mulMod(pw[i - 1], psi);
            var t: [N]u64 = undefined;
            for (0..N) |i| t[i] = pw[bitrev(i)];
            break :tbl t;
        };
        /// `psi_inv_rev[i] = psi^{-bitrev(i)}` (inverse twiddles).
        const psi_inv_rev: [N]u64 = tbl: {
            @setEvalBranchQuota(4_000_000);
            var pw: [N]u64 = undefined;
            pw[0] = 1;
            for (1..N) |i| pw[i] = mulMod(pw[i - 1], psi_inv);
            var t: [N]u64 = undefined;
            for (0..N) |i| t[i] = pw[bitrev(i)];
            break :tbl t;
        };

        /// Forward negacyclic NTT, in place. Natural order in, bit-reversed
        /// order out. Input coefficients must be canonical (`< p`).
        pub fn forward(x: *[N]u64) void {
            var t = N;
            var m: usize = 1;
            while (m < N) : (m *= 2) {
                t /= 2;
                for (0..m) |i| {
                    const j1 = 2 * i * t;
                    const s = psi_rev[m + i];
                    for (j1..j1 + t) |j| {
                        const u = x[j];
                        const v = mulMod(x[j + t], s);
                        x[j] = addMod(u, v);
                        x[j + t] = subMod(u, v);
                    }
                }
            }
        }

        /// Inverse negacyclic NTT, in place. Bit-reversed order in, natural
        /// order out, including the `N^{-1}` scaling.
        pub fn inverse(x: *[N]u64) void {
            var t: usize = 1;
            var m: usize = N;
            while (m > 1) : (m /= 2) {
                var j1: usize = 0;
                const h = m / 2;
                for (0..h) |i| {
                    const s = psi_inv_rev[h + i];
                    for (j1..j1 + t) |j| {
                        const u = x[j];
                        const v = x[j + t];
                        x[j] = addMod(u, v);
                        x[j + t] = mulMod(subMod(u, v), s);
                    }
                    j1 += 2 * t;
                }
                t *= 2;
            }
            for (x) |*c| c.* = mulMod(c.*, n_inv);
        }

        /// Exact negacyclic product `a·b mod (X^N+1)` over `Z_{2^32}` — the
        /// same function as the schoolbook convolution, computed in
        /// `O(N log N)`. See the file header for the exactness argument.
        pub fn mulTorus(a: *const [N]u32, b: *const [N]u32) [N]u32 {
            var al: [N]u64 = undefined;
            var ah: [N]u64 = undefined;
            var bl: [N]u64 = undefined;
            var bh: [N]u64 = undefined;
            for (0..N) |i| {
                al[i] = a[i] & 0xFFFF;
                ah[i] = a[i] >> 16;
                bl[i] = b[i] & 0xFFFF;
                bh[i] = b[i] >> 16;
            }
            forward(&al);
            forward(&ah);
            forward(&bl);
            forward(&bh);

            // C = a_l·b_l + 2^16·(a_l·b_h + a_h·b_l), formed in the transform
            // domain (one inverse transform instead of two).
            var acc: [N]u64 = undefined;
            for (0..N) |i| {
                const cross = addMod(mulMod(al[i], bh[i]), mulMod(ah[i], bl[i]));
                acc[i] = addMod(mulMod(al[i], bl[i]), mulMod(cross, 1 << 16));
            }
            inverse(&acc);

            var out: [N]u32 = undefined;
            for (0..N) |i| out[i] = recoverTorus(acc[i]);
            return out;
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "p is prime-shaped: 2^32 | p-1, p mod 2^32 == 1, 2^64 − p == eps" {
    try testing.expectEqual(@as(u64, 0), (p - 1) % (1 << 32));
    try testing.expectEqual(@as(u32, 1), @as(u32, @truncate(p)));
    try testing.expectEqual(@as(u128, eps), (@as(u128, 1) << 64) - p);
    // p really is prime (trial-division-free check: Fermat + the order of the
    // generator is exactly p−1 over the prime factors of p−1).
    // p − 1 = 2^32 · 3 · 5 · 17 · 257 · 65537
    const factors = [_]u64{ 2, 3, 5, 17, 257, 65537 };
    for (factors) |f| try testing.expect(powMod(generator, (p - 1) / f) != 1);
    try testing.expectEqual(@as(u64, 1), powMod(generator, p - 1));
}

test "reduce128 agrees with the 128-bit remainder on edge and random inputs" {
    const fixed = [_]u128{
        0,
        1,
        p - 1,
        p,
        p + 1,
        @as(u128, p) * p,
        std.math.maxInt(u128),
        @as(u128, 1) << 64,
        @as(u128, 1) << 96,
        @as(u128, 1) << 127,
        @as(u128, std.math.maxInt(u64)) * (p - 1),
    };
    for (fixed) |x| try testing.expectEqual(@as(u64, @intCast(x % p)), reduce128(x));

    var prng = std.Random.DefaultPrng.init(10);
    const rnd = prng.random();
    for (0..5000) |_| {
        const x: u128 = (@as(u128, rnd.int(u64)) << 64) | rnd.int(u64);
        try testing.expectEqual(@as(u64, @intCast(x % p)), reduce128(x));
    }
}

test "addMod/subMod/mulMod agree with wide arithmetic" {
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    for (0..2000) |_| {
        const a = rnd.int(u64) % p;
        const b = rnd.int(u64) % p;
        try testing.expectEqual(@as(u64, @intCast((@as(u128, a) + b) % p)), addMod(a, b));
        try testing.expectEqual(@as(u64, @intCast((@as(u128, a) + p - b) % p)), subMod(a, b));
        try testing.expectEqual(@as(u64, @intCast((@as(u128, a) * b) % p)), mulMod(a, b));
    }
}

test "psi is a primitive 2N-th root of unity for several N" {
    inline for (.{ 8, 16, 64, 256, 1024 }) |N| {
        const E = Engine(N);
        try testing.expectEqual(p - 1, powMod(E.psi, N)); // psi^N = −1
        try testing.expectEqual(@as(u64, 1), powMod(E.psi, 2 * N));
        try testing.expect(powMod(E.psi, N / 2) != 1);
    }
}

test "recoverTorus pins the p/2 sign threshold exactly" {
    const half = p / 2; // p is odd ⇒ half = (p−1)/2, the largest POSITIVE value
    // Positive branch: v = r, so the answer is the low 32 bits of r.
    try testing.expectEqual(@as(u32, 0), recoverTorus(0));
    try testing.expectEqual(@as(u32, 1), recoverTorus(1));
    try testing.expectEqual(@as(u32, 0xFFFF_FFFF), recoverTorus(0xFFFF_FFFF));
    try testing.expectEqual(@as(u32, @truncate(half)), recoverTorus(half));
    // Negative branch: v = r − p, i.e. lo32(r) − 1 (because p ≡ 1 mod 2^32).
    try testing.expectEqual(@as(u32, @truncate(half + 1)) -% 1, recoverTorus(half + 1));
    try testing.expectEqual(@as(u32, 0), recoverTorus(p - 1) +% 1); // p−1 ≡ −1
    try testing.expectEqual(@as(u32, 0xFFFF_FFFF), recoverTorus(p - 1));

    // Straddle the threshold with HARD LITERALS, not expressions rebuilt from
    // the same `p/2` the code uses — otherwise moving the threshold moves the
    // expectation with it and the test proves nothing. `p/2 = 0x7FFFFFFF_80000000`.
    try testing.expectEqual(@as(u64, 0x7FFF_FFFF_8000_0000), half);
    try testing.expectEqual(@as(u32, 0x7FFF_FFFF), recoverTorus(0x7FFF_FFFF_7FFF_FFFF)); // half−1, positive
    try testing.expectEqual(@as(u32, 0x8000_0000), recoverTorus(0x7FFF_FFFF_8000_0000)); // half,   positive
    try testing.expectEqual(@as(u32, 0x8000_0000), recoverTorus(0x7FFF_FFFF_8000_0001)); // half+1, negative
    try testing.expectEqual(@as(u32, 0x8000_0001), recoverTorus(0x7FFF_FFFF_8000_0002)); // half+2, negative
    // (`half` and `half+1` collide mod 2^32 because ±2^31 are the same
    // residue — that is why the *neighbours* are what pin the cut.)

    // Every residue is the two's-complement image of the signed value.
    inline for (.{ half, half + 1, p - 1, p / 2 - 1 }) |r| {
        const signed: i128 = if (r > p / 2) @as(i128, r) - p else @as(i128, r);
        try testing.expectEqual(@as(u32, @truncate(@as(u128, @bitCast(signed)))), recoverTorus(r));
    }
}

test "forward∘inverse is the identity" {
    const N = 64;
    const E = Engine(N);
    var prng = std.Random.DefaultPrng.init(12);
    const rnd = prng.random();
    var x: [N]u64 = undefined;
    for (&x) |*c| c.* = rnd.int(u64) % p;
    const orig = x;
    E.forward(&x);
    E.inverse(&x);
    try testing.expectEqualSlices(u64, &orig, &x);
}
