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
    /// Relinearisation gadget base, as `log2 w`. The key-switch decomposes
    /// `c2` into `⌈log2 q / log2 w⌉` base-`w` digits, so this trades key size
    /// and key-switch cost (one gadget row per digit) against key-switch noise
    /// (`digits·N·(w−1)`). `8` is the historical default and is what every toy
    /// set uses; a `log q ≈ 218` set would need 28 rows at that base — a
    /// 56-polynomial relin key — so security-grade sets raise it.
    relin_base_log2: u7 = 8,

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

/// **Security-grade set** — `N = 8192`, `t = 65537`, four NTT primes of
/// 55/55/54/54 bits, `log2 q = 218.000` exactly. This is the shape the
/// HomomorphicEncryption.org security tables give for ~128-bit classical
/// security with a ternary secret (`N = 8192 ⇒ log q ≤ 218`), and it is the
/// parameter set the module could NOT express before: the `u128` ciphertext
/// modulus capped `log q` at 127. `Bfv.QU` is now sized from `P` (here a
/// 219-bit accumulator) and the multiply runs `mulBehz`, whose `⌊t/q·…⌉`
/// rescale is pure residue arithmetic — no big-integer division at all.
///
/// `t = 65537 ≡ 1 (mod 2N)` (`65536 = 4·16384`), the standard batching prime,
/// so this set is also the one a future CRT-slot encoder would use.
/// `relin_base_log2 = 55` ⇒ 4 gadget rows; at the historical `w = 2^8` this
/// modulus would need 28 rows, i.e. a 56-polynomial relin key.
///
/// ## Worst-case noise ledger (same shape as `test_mul`)
/// Ternary `s,u,e,e0,e1`; `ct(s) = Δm + v + q·r` over the integers with
/// centered representatives; `B := ‖v‖_∞`; `Δ = ⌊q/t⌋` (202 bits);
/// `r_t = q mod t = 23199`.
///   - fresh:  `B ≤ 2N+1 = 16385 < 2^14`; `‖r‖ ≤ (N+3)/2 = 4098 < 2^12.1`;
///     `‖m‖ ≤ t−1 = 65536 = 2^16`.
///   - one tensor+rescale of inputs with noise `B1,B2` adds
///       `t·N·‖r‖·(B1+B2)`          = 2.20e12·(B1+B2) ≈ `2^41.0·(B1+B2)`
///     + `N·‖m‖·(B1+B2)`            = 5.37e8·(B1+B2)
///     + `r_t·(2N‖r‖‖m‖ + N‖m‖²/t)` ≈ 1.02e17 ≈ `2^56.5`
///     + `(1+N+N²)/2`               ≈ 3.36e7  ≈ `2^25`
///     ⇒ `B_out ≤ 2^41.1·(B1+B2) + 2^56.6`.
///   - the relin key-switch (`w = 2^55`, 4 digits, ternary `e_i`) adds
///     `≤ digits·N·(w−1) = 4·8192·(2^55−1) ≈ 2^70.0` — which DOMINATES the
///     tensor term at depth 1.
/// Chaining (each level: multiply, then relinearise):
///   `B_1 ≤ 2^57.4 + 2^70.0 ≈ 2^70.1`
///   `B_2 ≤ 2^41.1·2^70.1 ≈ 2^111.2`
///   `B_3 ≤ 2^41.1·2^111.2 ≈ 2^152.3`
///   `B_4 ≤ 2^41.1·2^152.3 ≈ 2^193.4`
/// Decryption stays exact while `t·B + r_t·‖m‖ < q/2 = 2^217`:
///   depth 4 ⇒ `2^16·2^193.4 = 2^209.4 < 2^217` — a `2^7.6 ≈ 190×` margin.
///   depth 5 ⇒ `2^250` — fails. So **multiplicative depth 4 is a worst-case
/// guarantee** for every seed and every plaintext including all-`(t−1)`; the
/// end-to-end test exercises depth 2 (the runtime at `N = 8192` is the only
/// reason it stops there, not the budget) — `kat_test.zig`'s
/// "security-grade N=8192 / log q=218: depth-2 evaluation decrypts exactly".
pub const sec_n8192_logq218 = Params{
    .n = 8192,
    .t = 65537,
    .primes = &.{ 36028797018652673, 36028797017571329, 18014398508400641, 18014398508138497 },
    .relin_base_log2 = 55,
};

const testing = std.testing;

test "sec_n8192_logq218 validates and has the documented shape" {
    try sec_n8192_logq218.validate();
    var q: u512 = 1;
    for (sec_n8192_logq218.primes) |p| q *= p;
    // ── the security claim is the (N, log q) PAIR, so BOTH ends are pinned ──
    // N is load-bearing and nothing else in this file constrains it. Measured
    // 2026-08-11: cutting N to 1024 while leaving log q = 218 left the ENTIRE
    // suite at exit 0. Every other assertion here is N-independent — `log2 q`,
    // `q mod t` and `bits(Δ)` do not mention N, `validate()` still passes
    // (1024 is a power of two and 2·1024 divides p−1 because 2·8192 does), and
    // the end-to-end correctness test gets EASIER because a smaller N grows
    // less noise, so its "budget > 60 bits" assertion still holds. The result
    // would be a set still named `sec_…` and still advertised as the ~128-bit
    // row of the HomomorphicEncryption.org tables while sitting at a
    // (N=1024, log q=218) shape those tables cap near log q ≈ 27 — i.e. no
    // meaningful security at all. Pin it.
    try testing.expectEqual(@as(usize, 8192), sec_n8192_logq218.n);
    // log2 q == 218 exactly: q ∈ [2^217, 2^218).
    try testing.expectEqual(@as(usize, 218), 512 - @clz(q));
    // The ledger's r_t and the batching condition t ≡ 1 mod 2N.
    try testing.expectEqual(@as(u512, 23199), q % sec_n8192_logq218.t);
    try testing.expectEqual(@as(u64, 1), sec_n8192_logq218.t % (2 * @as(u64, sec_n8192_logq218.n)));
    // Δ = ⌊q/t⌋ has 202 bits, so Δ/2 ≈ 2^201 — the ledger's decryption margin.
    try testing.expectEqual(@as(usize, 202), 512 - @clz(q / sec_n8192_logq218.t));
}

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
