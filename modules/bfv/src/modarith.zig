// SPDX-License-Identifier: MIT

//! modarith — word-size modular arithmetic over a single NTT-friendly prime
//! `q < 2^62`. All products go through `u128`, which is exact for any `q` whose
//! square fits in `u128` (`q < 2^64`); we require `q < 2^62` so intermediate
//! sums in the NTT butterflies (`a + t`, both `< q`) never overflow `u64`.
//!
//! ## Three multiply paths
//! `q` is a *runtime* value (an RNS-basis element chosen at `init`), so the
//! naive `(a*b) % q` is a genuine 128-by-64 **hardware/library division** — the
//! compiler cannot turn it into a magic-multiply. Measured on this host
//! (`bench.zig`, ReleaseFast) it costs **9.2 ns/op** at a 31-bit prime and
//! **28.5 ns/op** at a 61-bit prime. Two division-free replacements are
//! provided; `mulMod` itself is retained unchanged as the reference oracle both
//! are differentially tested against.
//!
//!   - `Modulus` — **Barrett** (SEAL's `multiply_uint_mod` shape): one
//!     precomputed `ratio = ⌊2^128/q⌋` per modulus, then two wide multiplies.
//!     Use when *both* factors vary (pointwise products, CRT recombination).
//!     Measured **2.8 ns/op** — 3.3x (31-bit) to 10.2x (61-bit) faster.
//!   - `Shoup` — one precomputed `w' = ⌊w·2^64/q⌋` per *fixed* multiplier `w`,
//!     then one `mulhi` + one `mullo` + a conditional subtract. Use when one
//!     factor is a constant of the loop (NTT twiddles, `N^-1`, `Δ mod q_i`,
//!     the relin gadget scalar). Measured **1.1 ns/op** — 8.2x (31-bit) to
//!     24x (61-bit) faster. This is what makes SEAL's butterfly a `mulhi` plus
//!     a correction rather than a division.
//!
//! ## Branch shape
//! `addMod`/`subMod`/`Modulus.mul`/`Shoup.mul` end in a *conditional subtract*
//! (`x < 2q ⇒ x mod q`). It is written as an arithmetic mask (`csub`), not an
//! `if`, because these are the leaf operations every secret-bearing product in
//! the scheme layer routes through. See `csub` for the exact caveat: this is
//! source-level constant time, not verified codegen.
//!
//! This is the ungated, fully-real backbone the `ntt`/`rns`/`ring` layers
//! build on. Every function here is deterministic and unit-tested; none is
//! part of the gated Fable core.

const std = @import("std");

/// Largest supported prime bit-length. `q < 2^62` keeps `a + b < 2^63` (no
/// `u64` overflow in additive butterflies), `q*q < 2^124` (exact `u128`
/// products), and `2q < 2^63` (so `csub` and `Shoup` are in range).
pub const max_prime_bits = 62;

/// Conditional subtract: for `x < 2q`, returns `x mod q`. Written as an
/// arithmetic mask rather than `if (x >= q) x - q else x` so no branch is
/// taken on the *value* — these leaves carry secret data (the ternary secret
/// key, the error polynomials, every product involving them).
///
/// Caveat, stated plainly: this is **source-level** constant time. LLVM is
/// free to rematerialise a branch from the mask (it usually emits `cmp`+`cmov`
/// or `sbb`, but that is not contractual), and nothing here constrains the
/// microarchitecture. It removes the *written* data-dependent control flow;
/// it is not a verified-codegen guarantee.
pub inline fn csub(x: u64, q: u64) u64 {
    const mask: u64 = 0 -% @as(u64, @intFromBool(x >= q));
    return x -% (q & mask);
}

pub fn addMod(a: u64, b: u64, q: u64) u64 {
    const s = a + b; // a,b < q < 2^62 ⇒ s < 2^63, no overflow
    return csub(s, q);
}

pub fn subMod(a: u64, b: u64, q: u64) u64 {
    const d = a -% b;
    const mask: u64 = 0 -% @as(u64, @intFromBool(a < b));
    return d +% (q & mask);
}

/// Reference modular multiply — a real 128-by-64 division. **Kept as the
/// oracle** `Modulus`/`Shoup` are differentially tested against (and used by
/// the cold setup paths `powMod`/`invMod`/`isPrime`/`primitive2NthRoot`, where
/// the precompute would cost more than it saves). Hot paths must use
/// `Modulus` or `Shoup`.
pub fn mulMod(a: u64, b: u64, q: u64) u64 {
    const p: u128 = @as(u128, a) * @as(u128, b);
    return @intCast(p % q);
}

/// A modulus with its Barrett constant precomputed: `ratio = ⌊2^128/q⌋`.
///
/// Correctness (why one conditional subtract is enough, for **any** `p < 2^128`
/// — not just `p < q²`): write `ratio = (2^128 − e)/q` with `0 ≤ e < q`. Then
/// `p·ratio/2^128 = p/q − p·e/(q·2^128)` and `p·e/(q·2^128) < p/2^128 < 1`, so
/// `qhat := ⌊p·ratio/2^128⌋` satisfies `⌊p/q⌋ − 1 ≤ qhat ≤ ⌊p/q⌋`. Hence the
/// remainder `p − qhat·q` lies in `[0, 2q)` and one `csub` canonicalises it.
/// `2q < 2^63` (from `max_prime_bits`), so the truncation to `u64` is exact
/// even though `qhat·q` is computed with wrapping `u128` arithmetic.
pub const Modulus = struct {
    q: u64,
    ratio: u128,

    pub fn init(q: u64) !Modulus {
        if (q < 2) return error.ModulusTooSmall;
        if (q >= (@as(u64, 1) << max_prime_bits)) return error.PrimeTooLarge;
        const num: u256 = @as(u256, 1) << 128;
        return .{ .q = q, .ratio = @intCast(num / q) };
    }

    /// `p mod q` for an arbitrary `u128` `p`.
    pub inline fn reduce(self: *const Modulus, p: u128) u64 {
        const qhat: u128 = @truncate((@as(u256, p) *% @as(u256, self.ratio)) >> 128);
        const r: u64 = @truncate(p -% qhat *% @as(u128, self.q));
        return csub(r, self.q);
    }

    /// `a·b mod q` for `a,b < 2^64` (in particular for canonical `a,b < q`).
    pub inline fn mul(self: *const Modulus, a: u64, b: u64) u64 {
        return self.reduce(@as(u128, a) * @as(u128, b));
    }

    /// `x mod q` for an unsigned `x` of ARBITRARY width (`u128`, `u256`,
    /// `u512`, …). Needed once the ciphertext modulus `q = ∏ q_i` stops
    /// fitting in a `u128`: reducing such a value with `%` is a genuine
    /// multi-limb library division, and unlike the `i256`-by-constant divisions
    /// elsewhere in this module the divisor here is a *runtime* prime, so LLVM
    /// cannot turn it into a magic-multiply.
    ///
    /// Instead: Horner over 64-bit limbs, most significant first, each step
    /// `acc·2^64 + limb (mod q)` done with the Barrett `reduce` above. Exact —
    /// `acc < q < 2^62`, so `(acc << 64) | limb < 2^126 + 2^64 < 2^128` and the
    /// `u128` intermediate never wraps. Costs `⌈bits/64⌉` Barrett reductions.
    pub fn reduceWide(self: *const Modulus, comptime T: type, x: T) u64 {
        const bits = @bitSizeOf(T);
        if (comptime bits <= 128) return self.reduce(@intCast(x));
        const limbs = comptime (bits + 63) / 64;
        var acc: u64 = 0;
        var i: usize = limbs;
        while (i > 0) {
            i -= 1;
            const limb: u64 = @truncate(x >> @intCast(64 * i));
            acc = self.reduce((@as(u128, acc) << 64) | limb);
        }
        return acc;
    }
};

/// A **fixed** multiplier `w` with its Shoup constant `w' = ⌊w·2^64/q⌋`
/// precomputed. `mul(x)` then costs one `mulhi`, one `mullo` and a `csub` —
/// no division and no wide (`u256`) intermediate.
///
/// Correctness: `w' = (w·2^64 − f)/q` with `0 ≤ f < q`. For `x < q`,
/// `hi := ⌊x·w'/2^64⌋` satisfies `⌊x·w/q⌋ − 1 ≤ hi ≤ ⌊x·w/q⌋`, so
/// `x·w − hi·q ∈ [0, 2q)`; computing it with wrapping `u64` arithmetic is
/// exact because the true value is `< 2q < 2^64`. Requires `q < 2^63`,
/// guaranteed by `max_prime_bits = 62`.
pub const Shoup = struct {
    w: u64,
    wp: u64,

    pub fn init(w: u64, q: u64) Shoup {
        std.debug.assert(w < q);
        return .{ .w = w, .wp = @truncate((@as(u128, w) << 64) / q) };
    }

    /// `x·w mod q` for canonical `x < q`.
    pub inline fn mul(self: Shoup, x: u64, q: u64) u64 {
        const hi: u64 = @truncate((@as(u128, x) * @as(u128, self.wp)) >> 64);
        return csub(x *% self.w -% hi *% q, q);
    }
};

/// `base^exp mod q` by square-and-multiply. Not constant-time (public
/// exponents only — twiddle/table setup, never a secret).
pub fn powMod(base: u64, exp: u64, q: u64) u64 {
    var result: u64 = 1 % q;
    var b = base % q;
    var e = exp;
    while (e != 0) : (e >>= 1) {
        if (e & 1 == 1) result = mulMod(result, b, q);
        b = mulMod(b, b, q);
    }
    return result;
}

/// Modular inverse via Fermat's little theorem (`q` must be prime).
/// Returns `error.NotInvertible` for `a == 0 (mod q)`.
pub fn invMod(a: u64, q: u64) !u64 {
    if (a % q == 0) return error.NotInvertible;
    return powMod(a, q - 2, q);
}

/// Deterministic Miller-Rabin primality for `n < 2^62`. The witness set
/// {2,3,5,7,11,13,17,19,23,29,31,37} is a proven deterministic test for all
/// `n < 3.3 * 10^24` (Sorenson-Webster), far above our `2^62` ceiling.
pub fn isPrime(n: u64) bool {
    if (n < 2) return false;
    for ([_]u64{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 }) |p| {
        if (n == p) return true;
        if (n % p == 0) return false;
    }
    // n-1 = d * 2^r with d odd
    var d = n - 1;
    var r: u6 = 0;
    while (d & 1 == 0) : (d >>= 1) r += 1;
    witness: for ([_]u64{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 }) |a| {
        var x = powMod(a, d, n);
        if (x == 1 or x == n - 1) continue :witness;
        var i: u6 = 1;
        while (i < r) : (i += 1) {
            x = mulMod(x, x, n);
            if (x == n - 1) continue :witness;
        }
        return false;
    }
    return true;
}

/// Find a primitive `2N`-th root of unity `psi` mod `q` (i.e. `psi^N == -1`),
/// the twiddle base for the negacyclic NTT. Requires `q` prime and
/// `2N | (q-1)`. Deterministic: scans `a = 2,3,...` and returns the first
/// `a^((q-1)/2N)` of exact order `2N`.
pub fn primitive2NthRoot(q: u64, n: usize) !u64 {
    const two_n: u64 = 2 * @as(u64, n);
    if ((q - 1) % two_n != 0) return error.NoRootExists;
    const e = (q - 1) / two_n;
    var a: u64 = 2;
    while (a < q) : (a += 1) {
        const psi = powMod(a, e, q);
        // order exactly 2N ⟺ psi^N == -1 (since psi^2N == 1 and 2N is 2^k)
        if (powMod(psi, @intCast(n), q) == q - 1) return psi;
    }
    return error.NoRootExists;
}

test "addMod/subMod wrap correctly" {
    const q: u64 = 97;
    try std.testing.expectEqual(@as(u64, 0), addMod(50, 47, q));
    try std.testing.expectEqual(@as(u64, 3), addMod(50, 50, q));
    try std.testing.expectEqual(@as(u64, 96), subMod(0, 1, q));
    try std.testing.expectEqual(@as(u64, 4), subMod(1, 94, q));
}

test "mulMod matches reference on a large prime" {
    const q: u64 = (1 << 61) - 1; // Mersenne prime, < 2^62
    try std.testing.expect(isPrime(q));
    const a: u64 = q - 3;
    const b: u64 = q - 5;
    // (q-3)(q-5) = q^2 -8q +15 ≡ 15 (mod q)
    try std.testing.expectEqual(@as(u64, 15), mulMod(a, b, q));
}

test "powMod / invMod round-trip" {
    const q: u64 = 1_000_000_007;
    try std.testing.expect(isPrime(q));
    var a: u64 = 2;
    while (a < 20) : (a += 1) {
        const inv = try invMod(a, q);
        try std.testing.expectEqual(@as(u64, 1), mulMod(a, inv, q));
    }
    try std.testing.expectError(error.NotInvertible, invMod(0, q));
}

test "isPrime deterministic on known cases" {
    try std.testing.expect(isPrime(2));
    try std.testing.expect(isPrime(17));
    try std.testing.expect(isPrime(97));
    try std.testing.expect(!isPrime(1));
    try std.testing.expect(!isPrime(561)); // Carmichael number
    try std.testing.expect(!isPrime(1024));
    try std.testing.expect(isPrime(1152921504606846883)); // < 2^61
}

// ── differential: the division-free paths vs the `mulMod` division oracle ────
//
// The oracle is the OLD code (`mulMod`, unchanged), never a second fast path.
// Coverage spans the prime sizes the module actually uses (17/97 KAT primes,
// the `test_mul` pair, the `bfv_toy` ~30-bit pair) plus the extreme the guard
// permits (the 61-bit Mersenne prime, where the division is slowest and the
// Barrett/Shoup error analysis is tightest).

const diff_primes = [_]u64{
    17, 97, 65537, 786433,
    1073750017, 1073754113, 4611686018427387847, // < 2^62, prime
    (1 << 61) - 1, // Mersenne, 61-bit
};

test "Modulus (Barrett) is bit-identical to the mulMod division oracle" {
    var prng = std.Random.DefaultPrng.init(0xBA88_0BEE);
    const rnd = prng.random();
    for (diff_primes) |q| {
        try std.testing.expect(isPrime(q));
        const m = try Modulus.init(q);
        // Boundary operands first: these are where an off-by-one in the
        // qhat bound would show up.
        for ([_]u64{ 0, 1, 2, q / 2, q - 2, q - 1 }) |a| {
            for ([_]u64{ 0, 1, 2, q / 2, q - 2, q - 1 }) |b| {
                try std.testing.expectEqual(mulMod(a, b, q), m.mul(a, b));
            }
        }
        for (0..20_000) |_| {
            const a = rnd.uintLessThan(u64, q);
            const b = rnd.uintLessThan(u64, q);
            try std.testing.expectEqual(mulMod(a, b, q), m.mul(a, b));
        }
        // `reduce` must also be exact for a full-width u128 (the CRT path
        // feeds it products that are NOT of the form a*b with a,b < q).
        for (0..20_000) |_| {
            const p: u128 = (@as(u128, rnd.int(u64)) << 64) | rnd.int(u64);
            try std.testing.expectEqual(@as(u64, @intCast(p % q)), m.reduce(p));
        }
        try std.testing.expectEqual(@as(u64, @intCast(@as(u128, std.math.maxInt(u128)) % q)), m.reduce(std.math.maxInt(u128)));
    }
}

test "Modulus.reduceWide is bit-identical to `%` at u128/u256/u320/u466/u512" {
    var prng = std.Random.DefaultPrng.init(0x1DE_2A17);
    const rnd = prng.random();
    for (diff_primes) |q| {
        const m = try Modulus.init(q);
        inline for (.{ u128, u256, u320, u466, u512 }) |T| {
            // Boundaries first: 0, 1, q−1, q, maxInt — an off-by-one in the
            // Horner chain or a dropped top limb shows up here.
            for ([_]T{ 0, 1, q - 1, q, q + 1, std.math.maxInt(T), std.math.maxInt(T) - 1 }) |x| {
                try std.testing.expectEqual(@as(u64, @intCast(x % q)), m.reduceWide(T, x));
            }
            for (0..3_000) |_| {
                var x: T = 0;
                var b: usize = 0;
                while (b < @bitSizeOf(T)) : (b += 64) x |= @as(T, rnd.int(u64)) << @intCast(b);
                try std.testing.expectEqual(@as(u64, @intCast(x % q)), m.reduceWide(T, x));
            }
        }
    }
}

test "Shoup (fixed multiplier) is bit-identical to the mulMod division oracle" {
    var prng = std.Random.DefaultPrng.init(0x5400_9E77);
    const rnd = prng.random();
    for (diff_primes) |q| {
        for ([_]u64{ 0, 1, 2, q / 2, q - 2, q - 1 }) |w| {
            const s = Shoup.init(w, q);
            for ([_]u64{ 0, 1, 2, q / 2, q - 2, q - 1 }) |x| {
                try std.testing.expectEqual(mulMod(w, x, q), s.mul(x, q));
            }
            for (0..2_000) |_| {
                const x = rnd.uintLessThan(u64, q);
                try std.testing.expectEqual(mulMod(w, x, q), s.mul(x, q));
            }
        }
        for (0..2_000) |_| {
            const w = rnd.uintLessThan(u64, q);
            const s = Shoup.init(w, q);
            const x = rnd.uintLessThan(u64, q);
            try std.testing.expectEqual(mulMod(w, x, q), s.mul(x, q));
        }
    }
}

test "csub / branchless addMod / subMod agree with the arithmetic definition" {
    for (diff_primes) |q| {
        for ([_]u64{ 0, 1, q - 1, q, q + 1, 2 * q - 1 }) |x| {
            try std.testing.expectEqual(@as(u64, @intCast(@as(u128, x) % q)), csub(x, q));
        }
        var prng = std.Random.DefaultPrng.init(q);
        const rnd = prng.random();
        for (0..20_000) |_| {
            const a = rnd.uintLessThan(u64, q);
            const b = rnd.uintLessThan(u64, q);
            try std.testing.expectEqual(@as(u64, @intCast((@as(u128, a) + b) % q)), addMod(a, b, q));
            try std.testing.expectEqual(@as(u64, @intCast((@as(u128, a) + q - b) % q)), subMod(a, b, q));
        }
    }
}

test "Modulus.init rejects out-of-range moduli" {
    try std.testing.expectError(error.ModulusTooSmall, Modulus.init(1));
    try std.testing.expectError(error.PrimeTooLarge, Modulus.init(1 << max_prime_bits));
}

test "primitive2NthRoot has exact order 2N" {
    const q: u64 = 17;
    const n: usize = 8;
    const psi = try primitive2NthRoot(q, n);
    try std.testing.expectEqual(@as(u64, 3), psi); // matches the KAT
    try std.testing.expectEqual(q - 1, powMod(psi, n, q)); // psi^N == -1
    try std.testing.expectEqual(@as(u64, 1), powMod(psi, 2 * n, q)); // psi^2N == 1
    try std.testing.expectError(error.NoRootExists, primitive2NthRoot(19, n)); // 16 ∤ 18
}
