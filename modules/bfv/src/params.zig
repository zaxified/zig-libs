// SPDX-License-Identifier: MIT

//! params — BFV parameter sets: ring degree `N` (power of two), plaintext
//! modulus `t`, and the RNS prime chain `q_0…q_{L-1}` for the ciphertext
//! modulus `q = ∏ q_i`. Every prime must be `≡ 1 (mod 2N)` (so a length-`N`
//! negacyclic NTT exists over it) and pairwise-distinct.
//!
//! The `test_tiny` set (`N=8`) is for exhaustive/byte-exact KAT and pins the
//! same primes the external Python re-derivation used. The `bfv_toy` set is a
//! small-but-realistic RLWE dimension for property tests once the scheme core
//! lands. Security-grade sets (`N≥4096`, ~128-bit) are a later increment —
//! Part 1 does not claim any security level (see SPEC.md "Security status").

const std = @import("std");
const ma = @import("modarith.zig");

pub const Params = struct {
    /// Ring degree, a power of two.
    n: usize,
    /// Plaintext modulus.
    t: u64,
    /// RNS prime chain for the ciphertext modulus `q = ∏ primes`.
    primes: []const u64,

    /// Structural validity: `N` a power of two, `t ≥ 2`, and every prime
    /// distinct, prime, and `≡ 1 (mod 2N)`. Does NOT assert any security
    /// level (that is a separate, deferred concern).
    pub fn validate(self: Params) !void {
        if (self.n == 0 or (self.n & (self.n - 1)) != 0) return error.DegreeNotPowerOfTwo;
        if (self.t < 2) return error.PlaintextModulusTooSmall;
        if (self.primes.len == 0) return error.EmptyPrimeChain;
        const two_n: u64 = 2 * @as(u64, self.n);
        for (self.primes, 0..) |p, i| {
            if (p >= (@as(u64, 1) << ma.max_prime_bits)) return error.PrimeTooLarge;
            if (!ma.isPrime(p)) return error.NotPrime;
            if ((p - 1) % two_n != 0) return error.PrimeNotNttFriendly;
            for (self.primes[0..i]) |q| if (p == q) return error.DuplicatePrime;
        }
    }

    pub fn numPrimes(self: Params) usize {
        return self.primes.len;
    }
};

/// Tiny KAT parameters — `N=8`, primes `{17, 97}` (both `≡ 1 mod 16`), the
/// exact primes the Python KAT re-derivation used. `q = 1649`.
pub const test_tiny = Params{
    .n = 8,
    .t = 4,
    .primes = &.{ 17, 97 },
};

/// Small property-test parameters — `N=1024`, two ~30-bit NTT primes
/// (`≡ 1 mod 2048`). NOT a security level, just a realistic RLWE dimension.
pub const bfv_toy = Params{
    .n = 1024,
    .t = 1024,
    .primes = &.{ 1073750017, 1073754113 },
};

/// Multiply/depth-test parameters — `N=16`, `t=16`, primes `{65537, 786433}`
/// (both `≡ 1 mod 32`), `q = 51,540,459,521 ≈ 2^35.6`, `Δ = ⌊q/t⌋ =
/// 3,221,278,720`, `r_t = q mod t = 1`. NOT a security level.
///
/// The Part-3 multiply anchors run here instead of `test_tiny` because
/// `test_tiny`'s `q = 1649` (`Δ/2 = 206`) cannot hold even ONE multiply: the
/// worst-case key-carry cross term alone (`t·N·‖r‖·(B1+B2) = 4·8·5·34 ≈
/// 5.4e3`) exceeds `q` itself. This set is sized so depth-2 correctness is a
/// WORST-CASE guarantee (every seed, every plaintext incl. boundary), not a
/// probabilistic pass. Ledger (ternary `s,u,e`; `ct(s) = Δm + v + q·r` over
/// the integers, `B := ‖v‖_∞`):
///   - fresh:   `B ≤ 2N+1 = 33`;  `‖r‖ ≤ (N+3)/2 < 10`;  `‖m‖ ≤ t−1 = 15`.
///   - one tensor+rescale adds `t·N·‖r‖·(B1+B2)` [r–v cross] +
///     `N·‖m‖·(B1+B2)` [m–v cross] + `r_t·(N·‖r‖·2‖m‖ + N‖m‖²/t)` +
///     `(1+N+N²)/2` [rounding] ≈ 1.82e5 for two fresh inputs; the relin
///     key-switch (`w = 2^8`, 5 digits, ternary `e_i`) adds
///     `≤ 5·N·(w−1) ≈ 2.1e4`  ⇒  depth-1 noise `B_ab ≤ 2.1e5`.
///   - depth 2 (`B1 = 2.1e5`, `B2 = 33`): `≤ (t·N·10 + N·15)·(B1+B2) + …`
///     `≈ 5.7e8 < Δ/2 ≈ 1.61e9` — ≈2.8× worst-case margin.
pub const test_mul = Params{
    .n = 16,
    .t = 16,
    .primes = &.{ 65537, 786433 },
};

const testing = std.testing;

test "test_tiny validates" {
    try test_tiny.validate();
    try testing.expectEqual(@as(usize, 2), test_tiny.numPrimes());
}

test "bfv_toy validates" {
    try bfv_toy.validate();
}

test "test_mul validates and has the documented shape" {
    try test_mul.validate();
    // The ledger above relies on r_t = q mod t == 1 (both primes ≡ 1 mod 16).
    var q: u128 = 1;
    for (test_mul.primes) |p| q *= p;
    try testing.expectEqual(@as(u128, 51_540_459_521), q);
    try testing.expectEqual(@as(u128, 1), q % test_mul.t);
}

test "validate rejects malformed sets" {
    try testing.expectError(error.DegreeNotPowerOfTwo, (Params{ .n = 6, .t = 4, .primes = &.{97} }).validate());
    try testing.expectError(error.PrimeNotNttFriendly, (Params{ .n = 8, .t = 4, .primes = &.{19} }).validate()); // 16 ∤ 18
    try testing.expectError(error.NotPrime, (Params{ .n = 8, .t = 4, .primes = &.{33} }).validate());
    try testing.expectError(error.PlaintextModulusTooSmall, (Params{ .n = 8, .t = 1, .primes = &.{17} }).validate());
    try testing.expectError(error.DuplicatePrime, (Params{ .n = 8, .t = 4, .primes = &.{ 17, 17 } }).validate());
}
