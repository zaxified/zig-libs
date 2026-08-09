// SPDX-License-Identifier: MIT

//! ntt — negacyclic Number-Theoretic Transform over `Z_q[X]/(X^N + 1)` for a
//! single word-size NTT-friendly prime `q` (`q ≡ 1 mod 2N`, `q < 2^62`).
//!
//! The transform O(N log N)-diagonalises negacyclic convolution: for polys
//! `a`, `b`, `intt(fwd(a) ∘ fwd(b)) == a·b mod (X^N + 1)`. It is the
//! computational backbone of RLWE arithmetic.
//!
//! Convention (mirrors the in-repo `falcon` NTT and SEAL/Kyber): Cooley-Tukey
//! **forward** with `zetas[k] = psi^bitrev(k)`, producing a bit-reversed
//! output; Gentleman-Sande **inverse** with negated twiddles + the final
//! `N^-1` scaling, consuming bit-reversed input and producing natural order.
//! `psi` is a primitive `2N`-th root of unity (`psi^N == -1`), which is what
//! makes the transform negacyclic (the `X^N = -1` fold) rather than cyclic.
//!
//! This is REAL, ungated arithmetic — the anti-self-consistency anchor for
//! the whole module. `Ntt(N)` is parameterised by a comptime power-of-two
//! degree; the prime and its twiddle tables are built at `init` time (the
//! prime is an RNS-basis element chosen at runtime, not comptime).
//!
//! ## Butterfly arithmetic (perf)
//! Every twiddle is a *loop constant*: `zetas[k]` is fixed for the whole inner
//! `j` loop of a block, as is `n_inv` for the final scaling. That is exactly
//! the shape Shoup's precomputed-multiplier trick wants, so the butterflies use
//! `ma.Shoup` (one `mulhi` + one `mullo` + a masked conditional subtract)
//! instead of the 128-by-64 division `ma.mulMod` performs. `pointwiseMul` has
//! two varying factors and uses Barrett (`ma.Modulus`) instead.
//!
//! `forwardRef`/`inverseRef` retain the original division-based bodies verbatim
//! and are the differential oracle the fast transforms are tested against —
//! bit-identical on every input, not "close".

const std = @import("std");
const ma = @import("modarith.zig");

/// A negacyclic NTT engine over `Z_q[X]/(X^N+1)`. `N` is a comptime
/// power-of-two; `q` is supplied at `init`.
pub fn Ntt(comptime N: usize) type {
    std.debug.assert(N > 0 and (N & (N - 1)) == 0);
    const log_n: u6 = std.math.log2_int(usize, N);
    return struct {
        const Self = @This();
        pub const degree = N;
        pub const Poly = [N]u64;

        q: u64,
        /// Barrett constant for `q` — used where both factors vary.
        modulus: ma.Modulus,
        /// `zetas[k] = psi^bitrev(k)`, the forward twiddles.
        zetas: [N]u64,
        /// Shoup constants for `zetas` (forward butterfly) and for
        /// `−zetas` (Gentleman-Sande inverse butterfly).
        zetas_shoup: [N]ma.Shoup,
        neg_zetas_shoup: [N]ma.Shoup,
        n_inv: u64,
        n_inv_shoup: ma.Shoup,

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

        /// Build the engine for prime `q`. Requires `q` prime and `2N|(q-1)`.
        pub fn init(q: u64) !Self {
            if (q >= (@as(u64, 1) << ma.max_prime_bits)) return error.PrimeTooLarge;
            if (!ma.isPrime(q)) return error.NotPrime;
            const psi = try ma.primitive2NthRoot(q, N);
            var psi_pow: [N]u64 = undefined;
            psi_pow[0] = 1 % q;
            var i: usize = 1;
            while (i < N) : (i += 1) psi_pow[i] = ma.mulMod(psi_pow[i - 1], psi, q);
            var zetas: [N]u64 = undefined;
            var zetas_shoup: [N]ma.Shoup = undefined;
            var neg_zetas_shoup: [N]ma.Shoup = undefined;
            i = 0;
            while (i < N) : (i += 1) {
                zetas[i] = psi_pow[bitrev(i)];
                zetas_shoup[i] = ma.Shoup.init(zetas[i], q);
                neg_zetas_shoup[i] = ma.Shoup.init(ma.subMod(0, zetas[i], q), q);
            }
            const n_inv = try ma.invMod(@intCast(N), q);
            return .{
                .q = q,
                .modulus = try ma.Modulus.init(q),
                .zetas = zetas,
                .zetas_shoup = zetas_shoup,
                .neg_zetas_shoup = neg_zetas_shoup,
                .n_inv = n_inv,
                .n_inv_shoup = ma.Shoup.init(n_inv, q),
            };
        }

        /// In-place forward NTT (output in bit-reversed order). Shoup
        /// butterflies — bit-identical to `forwardRef`, division-free.
        pub fn forward(self: *const Self, a: *Poly) void {
            const q = self.q;
            var k: usize = 1;
            var len: usize = N / 2;
            while (len >= 1) : (len >>= 1) {
                var start: usize = 0;
                while (start < N) : (start += 2 * len) {
                    const zeta = self.zetas_shoup[k];
                    k += 1;
                    var j = start;
                    while (j < start + len) : (j += 1) {
                        const t = zeta.mul(a[j + len], q);
                        a[j + len] = ma.subMod(a[j], t, q);
                        a[j] = ma.addMod(a[j], t, q);
                    }
                }
            }
        }

        /// In-place inverse NTT (input bit-reversed, output natural order),
        /// including the `N^-1` scaling. Shoup butterflies — bit-identical to
        /// `inverseRef`, division-free.
        pub fn inverse(self: *const Self, a: *Poly) void {
            const q = self.q;
            var k: usize = N;
            var len: usize = 1;
            while (len < N) : (len <<= 1) {
                var start: usize = 0;
                while (start < N) : (start += 2 * len) {
                    k -= 1;
                    const neg_zeta = self.neg_zetas_shoup[k];
                    var j = start;
                    while (j < start + len) : (j += 1) {
                        const t = a[j];
                        a[j] = ma.addMod(t, a[j + len], q);
                        a[j + len] = neg_zeta.mul(ma.subMod(t, a[j + len], q), q);
                    }
                }
            }
            const ni = self.n_inv_shoup;
            for (a) |*x| x.* = ni.mul(x.*, q);
        }

        /// The ORIGINAL division-based forward transform, kept verbatim as the
        /// differential oracle for `forward` (see the module tests). Not used
        /// by any hot path.
        pub fn forwardRef(self: *const Self, a: *Poly) void {
            const q = self.q;
            var k: usize = 1;
            var len: usize = N / 2;
            while (len >= 1) : (len >>= 1) {
                var start: usize = 0;
                while (start < N) : (start += 2 * len) {
                    const zeta = self.zetas[k];
                    k += 1;
                    var j = start;
                    while (j < start + len) : (j += 1) {
                        const t = ma.mulMod(zeta, a[j + len], q);
                        a[j + len] = ma.subMod(a[j], t, q);
                        a[j] = ma.addMod(a[j], t, q);
                    }
                }
            }
        }

        /// The ORIGINAL division-based inverse transform, kept verbatim as the
        /// differential oracle for `inverse`.
        pub fn inverseRef(self: *const Self, a: *Poly) void {
            const q = self.q;
            var k: usize = N;
            var len: usize = 1;
            while (len < N) : (len <<= 1) {
                var start: usize = 0;
                while (start < N) : (start += 2 * len) {
                    k -= 1;
                    const neg_zeta = ma.subMod(0, self.zetas[k], q);
                    var j = start;
                    while (j < start + len) : (j += 1) {
                        const t = a[j];
                        a[j] = ma.addMod(t, a[j + len], q);
                        a[j + len] = ma.mulMod(neg_zeta, ma.subMod(t, a[j + len], q), q);
                    }
                }
            }
            for (a) |*x| x.* = ma.mulMod(x.*, self.n_inv, q);
        }

        /// Pointwise product in the NTT domain: `a[i] *= b[i]`. Both factors
        /// vary, so this is Barrett, not Shoup.
        pub fn pointwiseMul(self: *const Self, a: *Poly, b: *const Poly) void {
            const m = &self.modulus;
            for (a, b) |*x, y| x.* = m.mul(x.*, y);
        }

        /// Negacyclic convolution `a·b mod (X^N+1)` via NTT (natural order in
        /// and out). Both inputs are consumed by value (copied).
        pub fn mulNegacyclic(self: *const Self, a: Poly, b: Poly) Poly {
            var fa = a;
            var fb = b;
            self.forward(&fa);
            self.forward(&fb);
            self.pointwiseMul(&fa, &fb);
            self.inverse(&fa);
            return fa;
        }

        /// Independent O(N^2) schoolbook negacyclic convolution — the
        /// cross-check oracle for `mulNegacyclic`. Shares no code with the
        /// NTT path, so agreement is strong evidence of transform
        /// correctness (defeats a self-consistent-but-wrong NTT).
        pub fn mulSchoolbook(q: u64, a: *const Poly, b: *const Poly) Poly {
            var out = [_]u64{0} ** N;
            for (0..N) |i| {
                for (0..N) |j| {
                    const c = ma.mulMod(a[i], b[j], q);
                    const k = i + j;
                    if (k < N) {
                        out[k] = ma.addMod(out[k], c, q);
                    } else {
                        out[k - N] = ma.subMod(out[k - N], c, q); // X^N = -1
                    }
                }
            }
            return out;
        }
    };
}

// ── tests (all REAL, ungated) ────────────────────────────────────────────────

const testing = std.testing;

test "forward → inverse is the identity" {
    const T = Ntt(8);
    const engine = try T.init(97);
    var a = [_]u64{ 1, 4, 7, 10, 13, 16, 19, 22 };
    const orig = a;
    engine.forward(&a);
    engine.inverse(&a);
    try testing.expectEqualSlices(u64, &orig, &a);
}

test "NTT-mul == schoolbook (the independent cross-check)" {
    inline for (.{ 17, 97, 7681, 12289 }) |q| {
        const T = Ntt(8);
        const engine = try T.init(q);
        var prng = std.Random.DefaultPrng.init(@as(u64, 0xB5F) +% q);
        const rnd = prng.random();
        for (0..20) |_| {
            var a: T.Poly = undefined;
            var b: T.Poly = undefined;
            for (&a, &b) |*x, *y| {
                x.* = rnd.uintLessThan(u64, q);
                y.* = rnd.uintLessThan(u64, q);
            }
            const viaNtt = engine.mulNegacyclic(a, b);
            const viaSchool = T.mulSchoolbook(q, &a, &b);
            try testing.expectEqualSlices(u64, &viaSchool, &viaNtt);
        }
    }
}

// ── differential: Shoup/Barrett transforms vs the original division bodies ───
//
// The oracle is the OLD code (`forwardRef`/`inverseRef`/`ma.mulMod`), kept
// verbatim. Bit-identical is the bar: the fast path is an exact rewrite of the
// same arithmetic, not an approximation, so any difference at all is a bug.

fn diffTransforms(comptime N: usize, q: u64, iters: usize, seed: u64) !void {
    const T = Ntt(N);
    const engine = try T.init(q);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    for (0..iters) |it| {
        var a: T.Poly = undefined;
        var b: T.Poly = undefined;
        for (&a, &b, 0..) |*x, *y, i| {
            // Iteration 0 is the boundary vector (0 / 1 / q−1 cycling), the
            // rest random — a uniform-only corpus can miss the csub edge.
            x.* = if (it == 0) ([_]u64{ 0, 1, q - 1 })[i % 3] else rnd.uintLessThan(u64, q);
            y.* = if (it == 0) ([_]u64{ q - 1, 0, 1 })[i % 3] else rnd.uintLessThan(u64, q);
        }
        var fast = a;
        var ref = a;
        engine.forward(&fast);
        engine.forwardRef(&ref);
        try testing.expectEqualSlices(u64, &ref, &fast);

        // pointwise (Barrett) vs the mulMod division oracle
        var pw_fast = fast;
        engine.pointwiseMul(&pw_fast, &b);
        var pw_ref = ref;
        for (&pw_ref, b) |*x, y| x.* = ma.mulMod(x.*, y, q);
        try testing.expectEqualSlices(u64, &pw_ref, &pw_fast);

        engine.inverse(&pw_fast);
        engine.inverseRef(&pw_ref);
        try testing.expectEqualSlices(u64, &pw_ref, &pw_fast);
    }
}

test "forward/inverse/pointwise are bit-identical to the division reference" {
    try diffTransforms(8, 17, 40, 0xA1);
    try diffTransforms(8, 97, 40, 0xA2);
    try diffTransforms(16, 65537, 40, 0xA3);
    try diffTransforms(16, 786433, 40, 0xA4);
    try diffTransforms(1024, 1073750017, 8, 0xA5);
    // The tightest case for the Shoup/Barrett error bounds: the largest
    // NTT-friendly prime the `q < 2^62` guard admits (62-bit, 32 | q−1),
    // where the division oracle is slowest and `2q` is closest to `2^63`.
    try diffTransforms(16, 4611686018427387617, 20, 0xA6);
}

test "larger degree N=1024 round-trip + mul cross-check" {
    const T = Ntt(1024);
    const q: u64 = 1073750017; // ≡ 1 mod 2048, prime (~30-bit)
    try testing.expect(ma.isPrime(q));
    const engine = try T.init(q);
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    var a: T.Poly = undefined;
    var b: T.Poly = undefined;
    for (&a, &b) |*x, *y| {
        x.* = rnd.uintLessThan(u64, q);
        y.* = rnd.uintLessThan(u64, q);
    }
    const viaNtt = engine.mulNegacyclic(a, b);
    const viaSchool = T.mulSchoolbook(q, &a, &b);
    try testing.expectEqualSlices(u64, &viaSchool, &viaNtt);
}
