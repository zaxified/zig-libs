// SPDX-License-Identifier: MIT

//! The Goldilocks field, `p = 2^64 - 2^32 + 1` — **deliberately a private
//! detail of this module, not a new general-purpose field module.**
//!
//! Rescue-Prime Optimized is specified over exactly this prime and nothing
//! else (`rescue_prime_optimized.sage` hard-codes it in five places), and the
//! repo's existing scalar fields (`bn254`, `bls12_381`) are 254/255-bit — they
//! cannot host it. Rather than grow a field module for one consumer, only what
//! RPO actually needs lives here: add, sub, mul, square, a square-and-multiply
//! ladder, and the two S-box exponentiations (scalar and layer-at-a-time).
//!
//! Everything is in **canonical** representation: a value is always the unique
//! integer in `[0, p)`. No Montgomery form — the modulus is a Solinas prime
//! (`2^64 ≡ 2^32 - 1 mod p`), so reduction of a 128-bit product is three
//! 64-bit operations and Montgomery would only cost extra.
//!
//! Every operation here is **branch-free and data-independent**: the
//! conditional subtractions are mask selects, not `if`s. See `SPEC.md`
//! ("Constant time") for why that matters and where it stops.

const std = @import("std");

/// `p = 2^64 - 2^32 + 1`.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// `2^64 mod p = 2^32 - 1`. The whole reason this prime is fast.
pub const EPSILON: u64 = 0xFFFF_FFFF;

/// A field element in canonical form; the integer is always `< P`.
pub const Fe = u64;

/// Reduce an arbitrary `u64` into the field. Public inputs only — this is the
/// "I have a number, make it an element" door.
pub inline fn fromU64(x: u64) Fe {
    return condSub(x);
}

/// Branch-free `x >= P ? x - P : x`. Correct only when `x < 2P`, which every
/// caller here guarantees (`2^64 - P = 2^32 - 1 < P`, so one subtraction
/// always suffices for any `u64`).
inline fn condSub(x: u64) Fe {
    // `x >= P` compiles to cmp+setae on x86-64: a flag, not a branch.
    const mask: u64 = 0 -% @as(u64, @intFromBool(x >= P));
    return x -% (P & mask);
}

pub inline fn add(a: Fe, b: Fe) Fe {
    const sum = a +% b;
    // A carry means the true sum is 2^64 + sum; fold 2^64 -> EPSILON.
    const carry: u64 = 0 -% @as(u64, @intFromBool(sum < a));
    return condSub(sum +% (carry & EPSILON));
}

pub inline fn sub(a: Fe, b: Fe) Fe {
    const diff = a -% b;
    // A borrow means the value is a - b + 2^64; unfold 2^64 -> P + EPSILON.
    const borrow: u64 = 0 -% @as(u64, @intFromBool(a < b));
    return diff -% (borrow & EPSILON);
}

pub inline fn neg(a: Fe) Fe {
    return sub(0, a);
}

/// Reduce a full 128-bit product. Writing `x = x_hi * 2^64 + x_lo` and
/// `x_hi = h1 * 2^32 + h0`, the two folds `2^64 ≡ 2^32 - 1` and
/// `2^96 ≡ -1 (mod p)` give `x ≡ x_lo - h1 + h0 * (2^32 - 1)`.
pub inline fn reduce128(x: u128) Fe {
    const lo: u64 = @truncate(x);
    const hi: u64 = @truncate(x >> 64);
    const h1 = hi >> 32; // contributes -h1  (2^96 ≡ -1)
    const h0 = hi & EPSILON; // contributes +h0 * EPSILON

    const d = lo -% h1;
    const borrow: u64 = 0 -% @as(u64, @intFromBool(lo < h1));
    const t0 = d -% (borrow & EPSILON);
    // h0 < 2^32 and EPSILON < 2^32, so this product never wraps; it is also
    // (h0 << 32) - h0, which is what the compiler emits.
    const t1 = h0 *% EPSILON;

    const sum = t0 +% t1;
    const carry: u64 = 0 -% @as(u64, @intFromBool(sum < t0));
    return condSub(sum +% (carry & EPSILON));
}

pub inline fn mul(a: Fe, b: Fe) Fe {
    return reduce128(@as(u128, a) * @as(u128, b));
}

pub inline fn square(a: Fe) Fe {
    return mul(a, a);
}

/// Constant-time square-and-multiply: a fixed 64 squarings + 64 masked
/// multiplies regardless of `e`. Used by the tests as the oracle for the
/// addition chains and by nothing on the hot path.
pub fn pow(a: Fe, e: u64) Fe {
    var result: Fe = 1;
    var base = a;
    var i: u6 = 0;
    while (true) : (i += 1) {
        const bit: u64 = (e >> i) & 1;
        const mask: u64 = 0 -% bit;
        const candidate = mul(result, base);
        result = (candidate & mask) | (result & ~mask);
        base = square(base);
        if (i == 63) break;
    }
    return result;
}

// ── the two S-box exponents ─────────────────────────────────────────────────

/// The forward S-box exponent. `alpha = 7` is the smallest exponent coprime to
/// `p - 1` for this prime: 3 and 5 both divide `2^32 - 1`, hence `p - 1`, so
/// `x^3` and `x^5` are not bijections here. Asserted in `constants_test.zig`
/// rather than asserted by prose.
pub const alpha: u64 = 7;

/// `alpha^-1 mod (p - 1)`, **computed** by the extended Euclidean algorithm at
/// comptime, never transcribed. The check `alpha * inv_alpha ≡ 1 (mod p-1)` is
/// a test, and a second test proves the addition chain in `sboxInv` really
/// raises to this exponent.
pub const inv_alpha: u64 = invModPMinus1(alpha);

/// Extended Euclid over `u128` (values stay well inside it), returning
/// `x^-1 mod (p - 1)`. `p - 1 = 2^32 * (2^32 - 1)` is composite, so this is a
/// ring inverse, not a Fermat exponentiation.
pub fn invModPMinus1(x: u64) u64 {
    const m: i128 = @as(i128, P) - 1;
    var old_r: i128 = x;
    var r: i128 = m;
    var old_s: i128 = 1;
    var s: i128 = 0;
    while (r != 0) {
        const q = @divTrunc(old_r, r);
        const nr = old_r - q * r;
        old_r = r;
        r = nr;
        const ns = old_s - q * s;
        old_s = s;
        s = ns;
    }
    std.debug.assert(old_r == 1); // gcd(x, p-1) == 1
    const inv = @mod(old_s, m);
    return @intCast(inv);
}

/// `x^7` — 3 squarings + 2 multiplies, the standard chain.
pub inline fn sbox(x: Fe) Fe {
    const x2 = square(x);
    const x3 = mul(x2, x);
    const x6 = square(x3);
    return mul(x6, x);
}

/// `x^(1/7) = x^inv_alpha`.
///
/// **This is the expensive half of Rescue and the reason the whole family
/// exists.** `inv_alpha` is a full 64-bit exponent, so a generic ladder costs
/// ~128 multiplications; the addition chain below — lifted from the RPO
/// reference implementations, which all share it — costs **72**, in a fixed
/// sequence with no data-dependent branch. `constants_test.zig` re-executes
/// this exact chain over *exponents* and asserts the result is `inv_alpha`.
///
/// The bit pattern being built:
/// `1001001001001001001001001001000110110110110110110110110110110111`.
pub inline fn sboxInv(x: Fe) Fe {
    const t1 = square(x); //  x^2
    const t2 = square(t1); //  x^4
    const t3 = expAcc(t2, t2, 3); //  x^36        = 0b100100
    const t4 = expAcc(t3, t3, 6); //  0b100100100100
    const t5 = expAcc(t4, t4, 12); //  0b100100...(24 bits)
    const t6 = expAcc(t5, t3, 6); //  0b100100...(30 bits)
    const t7 = expAcc(t6, t6, 31); //  0b1001001...(61 bits)

    const a = square(square(mul(square(t7), t6)));
    const b = mul(mul(t1, t2), x);
    return mul(a, b);
}

/// `base^(2^n) * tail` — the chain's only building block.
inline fn expAcc(base: Fe, tail: Fe, comptime n: u8) Fe {
    var r = base;
    for (0..n) |_| r = square(r);
    return mul(r, tail);
}

/// `sboxInv` applied to a whole S-box layer — **the shape matters, not just
/// the arithmetic.**
///
/// Written per-element, the 72-multiply chain is one 72-long dependency chain
/// and the compiler will not unroll a loop with that big a body, so the `m`
/// lanes run one after another and the layer costs `m * 72` *latencies*.
/// Advancing all `m` lanes one chain step at a time instead exposes `m`-way
/// instruction-level parallelism at the same instruction count. Measured on
/// this host at `m = 12`: a full RPO permutation goes 48.0 us -> 27.4 us
/// (and a further -> 18.15 us once the field's carry handling stopped going
/// through `@addWithOverflow` tuples, which LLVM was spilling to stack).
/// Every RPO implementation is written this way; that is why.
pub fn sboxInvLayer(comptime n: usize, state: *[n]Fe) void {
    var t1: [n]Fe = undefined;
    for (0..n) |i| t1[i] = square(state[i]);
    var t2: [n]Fe = undefined;
    for (0..n) |i| t2[i] = square(t1[i]);

    var t3 = t2;
    expAccLayer(n, &t3, &t2, 3);
    var t4 = t3;
    expAccLayer(n, &t4, &t3, 6);
    var t5 = t4;
    expAccLayer(n, &t5, &t4, 12);
    var t6 = t5;
    expAccLayer(n, &t6, &t3, 6);
    var t7 = t6;
    expAccLayer(n, &t7, &t6, 31);

    for (0..n) |i| {
        const a = square(square(mul(square(t7[i]), t6[i])));
        const b = mul(mul(t1[i], t2[i]), state[i]);
        state[i] = mul(a, b);
    }
}

fn expAccLayer(comptime n: usize, acc: *[n]Fe, tail: *const [n]Fe, times: usize) void {
    for (0..times) |_| {
        for (0..n) |i| acc[i] = square(acc[i]);
    }
    for (0..n) |i| acc[i] = mul(acc[i], tail[i]);
}

/// `sbox` applied to a whole layer, same reasoning at a much smaller scale.
pub fn sboxLayer(comptime n: usize, state: *[n]Fe) void {
    var x2: [n]Fe = undefined;
    for (0..n) |i| x2[i] = square(state[i]);
    var x3: [n]Fe = undefined;
    for (0..n) |i| x3[i] = mul(x2[i], state[i]);
    for (0..n) |i| x3[i] = square(x3[i]);
    for (0..n) |i| state[i] = mul(x3[i], state[i]);
}

// ── tests ───────────────────────────────────────────────────────────────────

/// The oracle: plain `u128` arithmetic with `%`. Slow, obviously correct, and
/// completely independent of the Solinas folds above — which is the point.
fn refMul(a: u64, b: u64) u64 {
    return @intCast((@as(u128, a) * @as(u128, b)) % P);
}

test "arithmetic agrees with a u128 modulo oracle on edge cases" {
    const edges = [_]u64{
        0,                         1,                         2,
        P - 1,                     P - 2,                     EPSILON,
        EPSILON + 1,               0xFFFF_FFFF_FFFF_FFFE % P, 1 << 32,
        (1 << 32) - 1,             (1 << 63),                 P / 2,
        0x1234_5678_9ABC_DEF0 % P,
    };
    for (edges) |a| {
        for (edges) |b| {
            try std.testing.expectEqual(refMul(a, b), mul(a, b));
            try std.testing.expectEqual(@as(u64, @intCast((@as(u128, a) + b) % P)), add(a, b));
            try std.testing.expectEqual(
                @as(u64, @intCast((@as(u128, a) + P - b) % P)),
                sub(a, b),
            );
        }
    }
}

test "arithmetic agrees with the oracle on random inputs" {
    var prng = std.Random.DefaultPrng.init(0x5265_7363_7565_5f47);
    const rnd = prng.random();
    for (0..20_000) |_| {
        const a = fromU64(rnd.int(u64));
        const b = fromU64(rnd.int(u64));
        try std.testing.expectEqual(refMul(a, b), mul(a, b));
        try std.testing.expectEqual(refMul(a, a), square(a));
        try std.testing.expectEqual(@as(u64, @intCast((@as(u128, a) + b) % P)), add(a, b));
        try std.testing.expectEqual(@as(u64, @intCast((@as(u128, a) + P - b) % P)), sub(a, b));
        try std.testing.expect(mul(a, b) < P);
        try std.testing.expect(add(a, b) < P);
    }
}

test "reduce128 agrees with the oracle on full-width products" {
    var prng = std.Random.DefaultPrng.init(0xDEAD_BEEF_1234_5678);
    const rnd = prng.random();
    for (0..20_000) |_| {
        const x: u128 = (@as(u128, rnd.int(u64)) << 64) | rnd.int(u64);
        try std.testing.expectEqual(@as(u64, @intCast(x % P)), reduce128(x));
    }
    // The extremes reduce128 must survive.
    try std.testing.expectEqual(@as(u64, 0), reduce128(0));
    try std.testing.expectEqual(
        @as(u64, @intCast((~@as(u128, 0)) % P)),
        reduce128(~@as(u128, 0)),
    );
}

test "pow ladder agrees with repeated multiplication" {
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    for (0..64) |_| {
        const a = fromU64(rnd.int(u64));
        const e: u64 = rnd.int(u8);
        var expected: u64 = 1;
        for (0..e) |_| expected = mul(expected, a);
        try std.testing.expectEqual(expected, pow(a, e));
    }
}

test "the two S-boxes are inverse to each other" {
    var prng = std.Random.DefaultPrng.init(99);
    const rnd = prng.random();
    for (0..2_000) |_| {
        const a = fromU64(rnd.int(u64));
        try std.testing.expectEqual(a, sboxInv(sbox(a)));
        try std.testing.expectEqual(a, sbox(sboxInv(a)));
    }
    // Fixed points that must survive both directions.
    for ([_]u64{ 0, 1, P - 1 }) |a| {
        try std.testing.expectEqual(a, sboxInv(sbox(a)));
        try std.testing.expectEqual(a, sbox(sboxInv(a)));
    }
}
