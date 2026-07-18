// SPDX-License-Identifier: MIT

//! poly — the negacyclic polynomial ring `R = Z_{2^32}[X]/(X^N + 1)`, `N` a
//! power of two. This is the GLWE/GGSW coefficient ring of TFHE.
//!
//! Because the modulus is `q = 2^32`, every operation is EXACT wrapping `u32`
//! arithmetic — there is no NTT prime and no FFT here, so `mul` is a plain
//! `O(N²)` schoolbook negacyclic convolution that is byte-exact by
//! construction (each partial product `a[i]*b[j]` and the accumulation are
//! taken mod `2^32` via `*%`/`+%`/`-%`). A production TFHE would swap this for
//! a complex/`u64` NTT for speed; the exact schoolbook here is the correctness
//! oracle and is fine for the toy/test dimensions (`N ≤ 512`). **All REAL /
//! ungated** — no secrets, no randomness.

const std = @import("std");
const torus = @import("torus.zig");

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

        /// Exact negacyclic product `a·b mod (X^N+1)` over `Z_{2^32}` — the
        /// `O(N²)` schoolbook convolution folding `X^N = −1`. Byte-exact
        /// (wrapping `u32`), the reference every faster transform must match.
        pub fn mul(a: *const Self, b: *const Self) Self {
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
