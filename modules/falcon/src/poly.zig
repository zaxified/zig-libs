// SPDX-License-Identifier: MIT
//! poly — arithmetic in Z_q[x]/(x^n + 1) for Falcon (q = 12289), generic
//! over the ring degree n = 2^logn so the same code serves Falcon-512
//! (logn = 9) and Falcon-1024 (logn = 10).
//!
//! `Ring(logn)` builds a negacyclic number-theoretic transform with
//! comptime-generated twiddle tables (psi = a primitive 2n-th root of
//! unity mod q, found from a comptime generator search), plus the
//! pointwise operations and the NTT-domain polynomial inversion used to
//! recompute the public key h = g * f^-1 mod q from a decoded secret key.
//! Plain `% q` arithmetic — no Montgomery form; q < 2^14 so all products
//! fit u32 comfortably.
//!
//! `Ring512`/`Ring1024` are the two Falcon parameter sets; the module's
//! flat top-level names (`n`, `q`, `Poly`, `ntt`, ...) are Ring512 aliases
//! kept for backward compatibility with existing Falcon-512 call sites.

const std = @import("std");

/// The Falcon modulus (shared by every parameter set).
pub const q: u32 = 12289;

fn addq(a: u32, b: u32) u32 {
    const s = a + b;
    return if (s >= q) s - q else s;
}

fn subq(a: u32, b: u32) u32 {
    return if (a >= b) a - b else a + q - b;
}

fn mulq(a: u32, b: u32) u32 {
    return (a * b) % q;
}

fn powq(base: u32, exp: u32) u32 {
    var result: u32 = 1;
    var b = base % q;
    var e = exp;
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) result = mulq(result, b);
        b = mulq(b, b);
    }
    return result;
}

/// Ring/NTT operations over Z_q[x]/(x^n + 1), n = 2^logn. Instantiated for
/// logn = 9 (Falcon-512) and logn = 10 (Falcon-1024) below.
pub fn Ring(comptime logn_: u5) type {
    return struct {
        const Self = @This();

        /// log2 of the ring degree.
        pub const logn: u5 = logn_;
        /// Ring degree n = 2^logn.
        pub const n: usize = @as(usize, 1) << logn_;

        /// A polynomial with coefficients in [0, q), plain or NTT domain.
        pub const Poly = [Self.n]u16;

        /// psi: a primitive 2n-th root of unity mod q, so psi^n = -1.
        /// Derived at comptime from the smallest generator of Z_q^*.
        const psi: u32 = blk: {
            @setEvalBranchQuota(100_000);
            // q - 1 = 12288 = 2^12 * 3; g generates Z_q^* iff g^((q-1)/2) != 1
            // and g^((q-1)/3) != 1.
            var g: u32 = 2;
            while (powq(g, (q - 1) / 2) == 1 or powq(g, (q - 1) / 3) == 1) g += 1;
            const p = powq(g, (q - 1) / (2 * Self.n));
            std.debug.assert(powq(p, Self.n) == q - 1); // psi^n == -1
            break :blk p;
        };

        /// n^-1 mod q, for the final inverse-NTT scaling.
        const n_inv: u32 = powq(@intCast(Self.n), q - 2);

        fn bitrev(x: u32) u32 {
            var r: u32 = 0;
            var v = x;
            for (0..logn_) |_| {
                r = (r << 1) | (v & 1);
                v >>= 1;
            }
            return r;
        }

        /// zetas[k] = psi^bitrev(k) — twiddles in the order consumed by the
        /// iterative Cooley-Tukey forward / Gentleman-Sande inverse passes.
        const zetas: [Self.n]u16 = blk: {
            @setEvalBranchQuota(4_000_000);
            var psi_pow: [Self.n]u32 = undefined;
            psi_pow[0] = 1;
            for (1..Self.n) |i| psi_pow[i] = mulq(psi_pow[i - 1], psi);
            var t: [Self.n]u16 = undefined;
            for (0..Self.n) |i| t[i] = @intCast(psi_pow[bitrev(i)]);
            break :blk t;
        };

        /// In-place forward negacyclic NTT (output in bit-reversed order).
        pub fn ntt(a: *Self.Poly) void {
            var k: usize = 1;
            var len: usize = Self.n / 2;
            while (len >= 1) : (len >>= 1) {
                var start: usize = 0;
                while (start < Self.n) : (start += 2 * len) {
                    const zeta: u32 = zetas[k];
                    k += 1;
                    var j = start;
                    while (j < start + len) : (j += 1) {
                        const t = mulq(zeta, a[j + len]);
                        a[j + len] = @intCast(subq(a[j], t));
                        a[j] = @intCast(addq(a[j], t));
                    }
                }
            }
        }

        /// In-place inverse negacyclic NTT (input in bit-reversed order),
        /// including the n^-1 scaling.
        pub fn intt(a: *Self.Poly) void {
            var k: usize = Self.n;
            var len: usize = 1;
            while (len < Self.n) : (len <<= 1) {
                var start: usize = 0;
                while (start < Self.n) : (start += 2 * len) {
                    k -= 1;
                    const neg_zeta: u32 = q - zetas[k];
                    var j = start;
                    while (j < start + len) : (j += 1) {
                        const t: u32 = a[j];
                        a[j] = @intCast(addq(t, a[j + len]));
                        a[j + len] = @intCast(mulq(neg_zeta, subq(t, a[j + len])));
                    }
                }
            }
            for (a) |*x| x.* = @intCast(mulq(x.*, n_inv));
        }

        /// Pointwise product in the NTT domain: a *= b.
        pub fn pointwiseMul(a: *Self.Poly, b: *const Self.Poly) void {
            for (a, b) |*x, y| x.* = @intCast(mulq(x.*, y));
        }

        /// Pointwise a = b * a^-1 in the NTT domain; error if any coefficient
        /// of a is zero (polynomial not invertible mod q).
        pub fn pointwiseDiv(a: *Self.Poly, b: *const Self.Poly) error{NotInvertible}!void {
            for (a, b) |*x, y| {
                if (x.* == 0) return error.NotInvertible;
                x.* = @intCast(mulq(y, powq(x.*, q - 2)));
            }
        }

        /// Lift a small (signed byte) polynomial into [0, q).
        pub fn fromSmall(src: *const [Self.n]i8) Self.Poly {
            var out: Self.Poly = undefined;
            for (&out, src) |*x, s| {
                const v: i32 = s;
                x.* = @intCast(if (v < 0) v + @as(i32, q) else v);
            }
            return out;
        }

        /// Recompute the public key h = g * f^-1 mod q (plain domain), as
        /// the reference `compute_public` does. Errors if f is not
        /// invertible.
        pub fn computePublic(f: *const [Self.n]i8, g: *const [Self.n]i8) error{NotInvertible}!Self.Poly {
            var hf = Self.fromSmall(f);
            var hg = Self.fromSmall(g);
            Self.ntt(&hf);
            Self.ntt(&hg);
            try Self.pointwiseDiv(&hf, &hg); // hf = hg * hf^-1
            Self.intt(&hf);
            return hf;
        }
    };
}

/// Falcon-512 ring (n = 512, logn = 9).
pub const Ring512 = Ring(9);
/// Falcon-1024 ring (n = 1024, logn = 10).
pub const Ring1024 = Ring(10);

// Flat aliases = Falcon-512, kept for backward compatibility.
pub const logn = Ring512.logn;
pub const n = Ring512.n;
pub const Poly = Ring512.Poly;
pub const ntt = Ring512.ntt;
pub const intt = Ring512.intt;
pub const pointwiseMul = Ring512.pointwiseMul;
pub const pointwiseDiv = Ring512.pointwiseDiv;
pub const fromSmall = Ring512.fromSmall;
pub const computePublic = Ring512.computePublic;

test "NTT round-trip is the identity" {
    var prng = std.Random.DefaultPrng.init(0x8a5f);
    const random = prng.random();
    var a: Poly = undefined;
    for (&a) |*x| x.* = random.uintLessThan(u16, @intCast(q));
    const orig = a;
    ntt(&a);
    intt(&a);
    try std.testing.expectEqualSlices(u16, &orig, &a);
}

test "negacyclic wrap: x * x^511 == -1 mod (x^512 + 1)" {
    var a = std.mem.zeroes(Poly);
    var b = std.mem.zeroes(Poly);
    a[1] = 1; // x
    b[n - 1] = 1; // x^511
    ntt(&a);
    ntt(&b);
    pointwiseMul(&a, &b);
    intt(&a);
    try std.testing.expectEqual(@as(u16, @intCast(q - 1)), a[0]); // -1
    for (a[1..]) |x| try std.testing.expectEqual(@as(u16, 0), x);
}

test "NTT product matches schoolbook negacyclic convolution" {
    var prng = std.Random.DefaultPrng.init(0x1d0c);
    const random = prng.random();
    var a: Poly = undefined;
    var b: Poly = undefined;
    for (&a) |*x| x.* = random.uintLessThan(u16, @intCast(q));
    for (&b) |*x| x.* = random.uintLessThan(u16, @intCast(q));

    // Schoolbook: c[k] = sum a[i]*b[j] with x^512 = -1 wraparound.
    var want = std.mem.zeroes([n]u32);
    for (0..n) |i| {
        for (0..n) |j| {
            const p = mulq(a[i], b[j]);
            const k = (i + j) % n;
            if (i + j < n) {
                want[k] = addq(want[k], p);
            } else {
                want[k] = subq(want[k], p);
            }
        }
    }

    ntt(&a);
    ntt(&b);
    pointwiseMul(&a, &b);
    intt(&a);
    for (0..n) |k| try std.testing.expectEqual(want[k], @as(u32, a[k]));
}

test "pointwiseDiv rejects non-invertible and inverts otherwise" {
    var a = std.mem.zeroes(Poly);
    var b = std.mem.zeroes(Poly);
    b[0] = 1;
    try std.testing.expectError(error.NotInvertible, pointwiseDiv(&a, &b));

    // a = constant 3 (NTT of a constant is the same constant everywhere).
    var c: Poly = undefined;
    for (&c) |*x| x.* = 3;
    var one: Poly = undefined;
    for (&one) |*x| x.* = 3;
    try pointwiseDiv(&c, &one); // c = 3 * 3^-1 = 1 pointwise
    for (c) |x| try std.testing.expectEqual(@as(u16, 1), x);
}

test "Falcon-1024 ring: NTT round-trip is the identity" {
    var prng = std.Random.DefaultPrng.init(0xf1024);
    const random = prng.random();
    var a: Ring1024.Poly = undefined;
    for (&a) |*x| x.* = random.uintLessThan(u16, @intCast(q));
    const orig = a;
    Ring1024.ntt(&a);
    Ring1024.intt(&a);
    try std.testing.expectEqualSlices(u16, &orig, &a);
}

test "Falcon-1024 ring: negacyclic wrap x * x^1023 == -1 mod (x^1024 + 1)" {
    var a = std.mem.zeroes(Ring1024.Poly);
    var b = std.mem.zeroes(Ring1024.Poly);
    a[1] = 1; // x
    b[Ring1024.n - 1] = 1; // x^1023
    Ring1024.ntt(&a);
    Ring1024.ntt(&b);
    Ring1024.pointwiseMul(&a, &b);
    Ring1024.intt(&a);
    try std.testing.expectEqual(@as(u16, @intCast(q - 1)), a[0]); // -1
    for (a[1..]) |x| try std.testing.expectEqual(@as(u16, 0), x);
}

test "Falcon-1024 ring: NTT product matches schoolbook negacyclic convolution" {
    var prng = std.Random.DefaultPrng.init(0x1d0c1024);
    const random = prng.random();
    var a: Ring1024.Poly = undefined;
    var b: Ring1024.Poly = undefined;
    for (&a) |*x| x.* = random.uintLessThan(u16, @intCast(q));
    for (&b) |*x| x.* = random.uintLessThan(u16, @intCast(q));

    var want = std.mem.zeroes([Ring1024.n]u32);
    for (0..Ring1024.n) |i| {
        for (0..Ring1024.n) |j| {
            const p = mulq(a[i], b[j]);
            const k = (i + j) % Ring1024.n;
            if (i + j < Ring1024.n) {
                want[k] = addq(want[k], p);
            } else {
                want[k] = subq(want[k], p);
            }
        }
    }

    Ring1024.ntt(&a);
    Ring1024.ntt(&b);
    Ring1024.pointwiseMul(&a, &b);
    Ring1024.intt(&a);
    for (0..Ring1024.n) |k| try std.testing.expectEqual(want[k], @as(u32, a[k]));
}

test "Falcon-1024 ring: pointwiseDiv rejects non-invertible and inverts otherwise" {
    var a = std.mem.zeroes(Ring1024.Poly);
    var b = std.mem.zeroes(Ring1024.Poly);
    b[0] = 1;
    try std.testing.expectError(error.NotInvertible, Ring1024.pointwiseDiv(&a, &b));

    var c: Ring1024.Poly = undefined;
    for (&c) |*x| x.* = 3;
    var one: Ring1024.Poly = undefined;
    for (&one) |*x| x.* = 3;
    try Ring1024.pointwiseDiv(&c, &one);
    for (c) |x| try std.testing.expectEqual(@as(u16, 1), x);
}
