// SPDX-License-Identifier: MIT

//! poly — the negacyclic polynomial ring `R = Z_{2^32}[X]/(X^N + 1)`, `N` a
//! power of two. This is the GLWE/GGSW coefficient ring of TFHE.
//!
//! Because the modulus is `q = 2^32`, every operation is EXACT wrapping `u32`
//! arithmetic (each partial product and accumulation is taken mod `2^32` via
//! `*%`/`+%`/`-%`), and there is no floating-point rounding budget anywhere in
//! this module.
//!
//! ## Two multiply paths, one function
//!
//! `mul` dispatches on the comptime degree:
//!
//!   * `N < ntt_min_degree` → `mulSchoolbook`, the `O(N²)` negacyclic
//!     convolution. Also kept unconditionally as the **correctness oracle**.
//!   * `N ≥ ntt_min_degree` → `ntt.Engine(N).mulTorus`, an `O(N log N)`
//!     **exact** transform over the Goldilocks prime `2^64 − 2^32 + 1` with
//!     the operands split into 16-bit halves (see `ntt.zig` for the bound that
//!     makes it exact). This is *not* the `f64` complex FFT the reference TFHE
//!     libraries use: it is integer-only, so it carries no error bound, keeps
//!     `meta.platform = .any`, and is **bit-identical** to `mulSchoolbook` on
//!     every input — asserted by the differential test at the bottom of this
//!     file over the full range of supported degrees.
//!
//! **All REAL / ungated** — no secrets, no randomness, no allocation.

const std = @import("std");
const torus = @import("torus.zig");
const ntt = @import("ntt.zig");

/// Degrees at or above this use the exact NTT path in `mul`; below it `mul`
/// stays schoolbook.
///
/// **Measured, not guessed** (`bench.zig`, ReleaseFast, this host — schoolbook
/// ns/op ÷ NTT ns/op, min of three alternating passes):
///
///   | N    |   16 |   32 |   64 |  128 |  256 |  512 | 1024 | 2048 |
///   |------|------|------|------|------|------|------|------|------|
///   | ratio| 0.11 | 0.23 | 0.48 | 0.92 | 1.67 | 3.36 | 7.02 |12.08 |
///
/// The transform LOSES below 256: five length-`N` transforms plus the split
/// and the sign recovery cost more than `N²` wrapping `u32` mul-adds until the
/// quadratic term takes over. Run-to-run spread on this host is ≈ ±15 %, so
/// 128 reads as "no better", not "slightly worse". 256 is the first
/// unambiguous win, and it is also the degree the `toy` parameter set uses —
/// end to end that is a gate bootstrap of **54.4 ms → 33.3 ms**, measured by
/// building this constant both ways.
pub const ntt_min_degree: usize = 256;

const T = torus.Torus;

/// `Poly(N)` — `N` torus coefficients of `R = Z_{2^32}[X]/(X^N+1)`.
pub fn Poly(comptime N: usize) type {
    comptime std.debug.assert(N > 0 and (N & (N - 1)) == 0);
    return struct {
        const Self = @This();
        pub const degree = N;

        c: [N]T,

        pub fn zero() Self {
            return .{ .c = [_]T{0} ** N };
        }

        pub fn fromCoeffs(raw: [N]T) Self {
            return .{ .c = raw };
        }

        /// Constant polynomial `v` (only the degree-0 coefficient set).
        pub fn constant(v: T) Self {
            var out = Self.zero();
            out.c[0] = v;
            return out;
        }

        pub fn addAssign(self: *Self, other: *const Self) void {
            for (&self.c, other.c) |*x, y| x.* = x.* +% y;
        }

        pub fn subAssign(self: *Self, other: *const Self) void {
            for (&self.c, other.c) |*x, y| x.* = x.* -% y;
        }

        pub fn negate(self: *Self) void {
            for (&self.c) |*x| x.* = 0 -% x.*;
        }

        pub fn add(a: *const Self, b: *const Self) Self {
            var out = a.*;
            out.addAssign(b);
            return out;
        }

        pub fn sub(a: *const Self, b: *const Self) Self {
            var out = a.*;
            out.subAssign(b);
            return out;
        }

        /// Scalar-times-polynomial `s·a`, coefficient-wise `*%`.
        pub fn scalarMul(a: *const Self, s: T) Self {
            var out: Self = undefined;
            for (&out.c, a.c) |*o, x| o.* = x *% s;
            return out;
        }

        /// Exact negacyclic product `a·b mod (X^N+1)` over `Z_{2^32}`.
        /// Dispatches to `mulSchoolbook` for small `N` and to the exact NTT
        /// for `N ≥ ntt_min_degree`; both produce **the same bits**.
        pub fn mul(a: *const Self, b: *const Self) Self {
            if (comptime N >= ntt_min_degree and N <= ntt.max_degree) {
                return .{ .c = ntt.Engine(N).mulTorus(&a.c, &b.c) };
            }
            return mulSchoolbook(a, b);
        }

        /// Exact negacyclic product `a·b mod (X^N+1)` over `Z_{2^32}` — the
        /// `O(N²)` schoolbook convolution folding `X^N = −1`. Byte-exact
        /// (wrapping `u32`), the reference every faster transform must match.
        /// Retained as the differential oracle for `mul`'s NTT path (and used
        /// directly for degrees below `ntt_min_degree`).
        pub fn mulSchoolbook(a: *const Self, b: *const Self) Self {
            var acc = [_]T{0} ** N;
            for (0..N) |i| {
                for (0..N) |j| {
                    const p = a.c[i] *% b.c[j];
                    const k = i + j;
                    if (k < N) acc[k] = acc[k] +% p else acc[k - N] = acc[k - N] -% p; // X^N = −1
                }
            }
            return .{ .c = acc };
        }

        /// Multiply by the monomial `X^e`, `e ∈ [0, 2N)`: a negacyclic rotation
        /// (coefficients shift up by `e`, wrapping past `N` flips sign because
        /// `X^N = −1`). This is the accumulator rotation used by blind rotation
        /// and is REAL/mechanical (the *homomorphic* CMux around it is the
        /// gated core). `e` is taken mod `2N`.
        pub fn mulMonomial(a: *const Self, e: usize) Self {
            const two_n = 2 * N;
            const ee = e % two_n;
            var out = Self.zero();
            for (0..N) |i| {
                var d = i + ee;
                if (d >= two_n) d -= two_n;
                if (d < N) out.c[d] = out.c[d] +% a.c[i] else out.c[d - N] = out.c[d - N] -% a.c[i];
            }
            return out;
        }

        pub fn constTerm(self: *const Self) T {
            return self.c[0];
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return std.mem.eql(T, &a.c, &b.c);
        }
    };
}

const testing = std.testing;

test "negacyclic mul: constants and the X^N = −1 wrap" {
    const P = Poly(8);
    // 3 · 5 = 15 (constants)
    const a = P.constant(3);
    const b = P.constant(5);
    try testing.expectEqual(@as(T, 15), P.mul(&a, &b).constTerm());
    // X^7 · X^1 = X^8 = −1 ⇒ coeff 0 becomes −1 ≡ 2^32−1.
    var x7 = P.zero();
    x7.c[7] = 1;
    var x1 = P.zero();
    x1.c[1] = 1;
    const w = P.mul(&x7, &x1);
    try testing.expectEqual(@as(T, 0xFFFFFFFF), w.c[0]);
    for (w.c[1..]) |cc| try testing.expectEqual(@as(T, 0), cc);
}

test "mulMonomial equals mul-by-monomial-polynomial (exact, over random inputs)" {
    const N = 16;
    const P = Poly(N);
    var rng = std.Random.DefaultPrng.init(42);
    const rnd = rng.random();
    for (0..20) |_| {
        var raw: [N]T = undefined;
        for (&raw) |*x| x.* = rnd.int(T);
        const a = P.fromCoeffs(raw);
        const e = rnd.uintLessThan(usize, 2 * N);
        // Build X^e as an explicit polynomial (with the negacyclic sign) and
        // multiply the slow way; must match the fast rotation.
        var mono = P.zero();
        if (e < N) mono.c[e] = 1 else mono.c[e - N] = 0xFFFFFFFF; // X^{N+r} = −X^r
        const slow = P.mul(&a, &mono);
        const fast = P.mulMonomial(&a, e);
        try testing.expect(slow.eql(&fast));
    }
}

// ── the differential oracle for the NTT path ─────────────────────────────────
//
// `mulSchoolbook` is the ORACLE: it predates the transform, is unchanged, and
// is byte-exact by construction. The NTT path is only allowed to exist if it
// reproduces it bit for bit — not "closely", identically. These tests are the
// ones that go RED if a twiddle, a split, or the sign recovery is wrong.

test "mul == mulSchoolbook, bit-identical, over every supported degree" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rnd = prng.random();
    // 2..1024 spans both sides of `ntt_min_degree`, i.e. the smallest degree
    // `Poly` accepts and a degree well above the `N = 256` the params define.
    inline for (.{ 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024 }) |N| {
        const P = Poly(N);
        const reps = if (N >= 512) 3 else 12;
        for (0..reps) |_| {
            var ra: [N]T = undefined;
            var rb: [N]T = undefined;
            for (&ra) |*x| x.* = rnd.int(T);
            for (&rb) |*x| x.* = rnd.int(T);
            const a = P.fromCoeffs(ra);
            const b = P.fromCoeffs(rb);
            const slow = P.mulSchoolbook(&a, &b);
            // Call the transform DIRECTLY, not through `mul` — otherwise every
            // degree below `ntt_min_degree` would silently compare schoolbook
            // against schoolbook and the coverage would follow the threshold
            // around whenever it is retuned.
            const fast = ntt.Engine(N).mulTorus(&a.c, &b.c);
            try testing.expectEqualSlices(T, &slow.c, &fast);
            // …and `mul` itself must agree with whichever path it picked.
            try testing.expectEqualSlices(T, &slow.c, &P.mul(&a, &b).c);
        }
    }
}

test "mul == mulSchoolbook on saturating / sign-boundary coefficients" {
    // Random u32s almost never hit the values that stress the 16-bit split and
    // the `r > p/2` sign recovery: all-ones, the 2^31 sign bit, the 16-bit
    // half boundaries, and the single-monomial wrap.
    const interesting = [_]T{
        0,           1,           0xFFFF_FFFF, 0x8000_0000,
        0x7FFF_FFFF, 0x0000_FFFF, 0x0001_0000, 0xFFFF_0000,
    };
    inline for (.{ 64, 256 }) |N| {
        const P = Poly(N);
        for (interesting) |va| {
            for (interesting) |vb| {
                var a = P.zero();
                var b = P.zero();
                for (&a.c) |*x| x.* = va;
                for (&b.c) |*x| x.* = vb;
                try testing.expectEqualSlices(T, &P.mulSchoolbook(&a, &b).c, &ntt.Engine(N).mulTorus(&a.c, &b.c));
                // …and with the value in a single coefficient, which forces the
                // negacyclic `X^N = −1` fold to produce the negative branch.
                var a1 = P.zero();
                var b1 = P.zero();
                a1.c[N - 1] = va;
                b1.c[N - 3] = vb;
                try testing.expectEqualSlices(T, &P.mulSchoolbook(&a1, &b1).c, &ntt.Engine(N).mulTorus(&a1.c, &b1.c));
            }
        }
    }
}

test "mul is still the algebra it claims: X^{N-1}·X = −1, and it is commutative" {
    const N = 256;
    const P = Poly(N);
    var xnm1 = P.zero();
    xnm1.c[N - 1] = 1;
    var x1 = P.zero();
    x1.c[1] = 1;
    const w = P.mul(&xnm1, &x1);
    try testing.expectEqual(@as(T, 0xFFFF_FFFF), w.c[0]);
    for (w.c[1..]) |cc| try testing.expectEqual(@as(T, 0), cc);

    var prng = std.Random.DefaultPrng.init(77);
    const rnd = prng.random();
    var ra: [N]T = undefined;
    var rb: [N]T = undefined;
    for (&ra) |*x| x.* = rnd.int(T);
    for (&rb) |*x| x.* = rnd.int(T);
    const a = P.fromCoeffs(ra);
    const b = P.fromCoeffs(rb);
    try testing.expect(P.mul(&a, &b).eql(&P.mul(&b, &a)));
}

test "mulMonomial by X^{2N} is identity; X^N negates" {
    const N = 8;
    const P = Poly(N);
    var raw: [N]T = undefined;
    for (&raw, 0..) |*x, i| x.* = @intCast(i * 7 + 1);
    const a = P.fromCoeffs(raw);
    try testing.expect(a.eql(&P.mulMonomial(&a, 2 * N)));
    var neg = a;
    neg.negate();
    try testing.expect(neg.eql(&P.mulMonomial(&a, N)));
}
