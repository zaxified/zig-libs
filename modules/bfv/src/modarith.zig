// SPDX-License-Identifier: MIT

//! modarith — word-size modular arithmetic over a single NTT-friendly prime
//! `q < 2^62`. All products go through `u128` (schoolbook Barrett-free
//! reduction), which is exact for any `q` whose square fits in `u128`
//! (`q < 2^64`); we require `q < 2^62` so intermediate sums in the NTT
//! butterflies (`a + t`, both `< q`) never overflow `u64`.
//!
//! This is the ungated, fully-real backbone the `ntt`/`rns`/`ring` layers
//! build on. Every function here is deterministic and unit-tested; none is
//! part of the gated Fable core.

const std = @import("std");

/// Largest supported prime bit-length. `q < 2^62` keeps `a + b < 2^63` (no
/// `u64` overflow in additive butterflies) and `q*q < 2^124` (exact `u128`
/// products).
pub const max_prime_bits = 62;

pub fn addMod(a: u64, b: u64, q: u64) u64 {
    const s = a + b; // a,b < q < 2^62 ⇒ s < 2^63, no overflow
    return if (s >= q) s - q else s;
}

pub fn subMod(a: u64, b: u64, q: u64) u64 {
    return if (a >= b) a - b else a + q - b;
}

pub fn mulMod(a: u64, b: u64, q: u64) u64 {
    const p: u128 = @as(u128, a) * @as(u128, b);
    return @intCast(p % q);
}

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

test "primitive2NthRoot has exact order 2N" {
    const q: u64 = 17;
    const n: usize = 8;
    const psi = try primitive2NthRoot(q, n);
    try std.testing.expectEqual(@as(u64, 3), psi); // matches the KAT
    try std.testing.expectEqual(q - 1, powMod(psi, n, q)); // psi^N == -1
    try std.testing.expectEqual(@as(u64, 1), powMod(psi, 2 * n, q)); // psi^2N == 1
    try std.testing.expectError(error.NoRootExists, primitive2NthRoot(19, n)); // 16 ∤ 18
}
