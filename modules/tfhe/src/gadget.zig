// SPDX-License-Identifier: MIT

//! gadget — the **signed (balanced) gadget decomposition** used by the GGSW
//! external product and by LWE-to-LWE key switching.
//!
//! A torus element `x ∈ Z_{2^32}` is approximated by `ℓ` signed base-`B` digits
//! (`B = 2^b_bits`), each in the balanced range `[−B/2, B/2)`:
//!
//!     x ≈ Σ_{i=0}^{ℓ−1} d_i · (q / B^{i+1}),   d_i ∈ [−B/2, B/2)
//!
//! keeping only the top `ℓ·b_bits` bits (round-to-nearest on the dropped tail).
//! The **balanced** digit range is what keeps the external-product noise small
//! (digits bounded by `B/2`, not `B`); a plain unsigned decomposition would
//! blow the noise budget — that is the deliberately-broken positive control in
//! the harness. All REAL/ungated: this is exact integer bit-fiddling, no
//! secrets. The gated core CONSUMES a decomposition; producing one is
//! mechanical.

const std = @import("std");
const torus = @import("torus.zig");

const T = torus.Torus;

/// Worst-case recomposition error `‖x − Σ d_i·q/B^{i+1}‖_∞` of the signed
/// decomposition: the dropped tail after rounding to `ℓ·b_bits` top bits,
/// bounded by `q / (2·B^ℓ) = 2^{31 − ℓ·b_bits}` (or `0` when the digits cover
/// all 32 bits). Comptime constant — the SPEC ledger cites it.
pub fn maxError(comptime b_bits: u6, comptime ell: usize) u64 {
    const rep_bits: u32 = @as(u32, b_bits) * @as(u32, @intCast(ell));
    if (rep_bits >= 32) return 0;
    return @as(u64, 1) << @intCast(31 - rep_bits);
}

/// Signed base-`2^b_bits` decomposition of `x` into `ell` balanced digits,
/// `digits[0]` the most significant (weight `q/B`). `b_bits·ell ≤ 32`.
pub fn decompose(comptime b_bits: u6, comptime ell: usize, x: T) [ell]i32 {
    comptime std.debug.assert(b_bits >= 1 and @as(u32, b_bits) * ell <= 32);
    const B: u32 = @as(u32, 1) << @intCast(b_bits);
    const half: u32 = B >> 1;
    const mask: u32 = B - 1;
    const rep_bits: u6 = @intCast(@as(u32, b_bits) * ell);
    const ignored: u6 = 32 - rep_bits;

    // Round `x` to the top `rep_bits` bits (nearest), giving a `rep_bits`-bit
    // integer `v` whose base-B digits are the raw (unsigned) digits.
    var v: u32 = if (ignored == 0)
        x
    else
        @truncate((@as(u64, x) + (@as(u64, 1) << @intCast(ignored - 1))) >> @intCast(ignored));

    var digits: [ell]i32 = undefined;
    var carry: u32 = 0;
    var i: usize = ell;
    while (i > 0) : (i -= 1) {
        const d: u32 = (v & mask) + carry;
        v >>= @intCast(b_bits);
        // Balance into [−B/2, B/2): if d ≥ B/2 borrow one from the next digit.
        if (d >= half) {
            digits[i - 1] = @as(i32, @intCast(d)) - @as(i32, @intCast(B));
            carry = 1;
        } else {
            digits[i - 1] = @intCast(d);
            carry = 0;
        }
    }
    return digits;
}

/// Exact inverse of `decompose` up to the dropped tail: `Σ d_i·q/B^{i+1}` as a
/// torus element (wrapping `u32`). `‖x − recompose(decompose(x))‖ ≤ maxError`.
pub fn recompose(comptime b_bits: u6, comptime ell: usize, digits: [ell]i32) T {
    var acc: T = 0;
    for (digits, 0..) |d, i| {
        const w = torus.gadgetWeight(b_bits, i);
        // signed digit → two's-complement u32; `*%` mod 2^32 is exact.
        const du: T = @bitCast(d);
        acc = acc +% (du *% w);
    }
    return acc;
}

const testing = std.testing;

test "signed decomposition round-trips within maxError, digits balanced" {
    const b_bits: u6 = 7;
    const ell: usize = 4; // covers top 28 bits ⇒ maxError = 2^3 = 8
    const B: i32 = 1 << b_bits;
    const half: i32 = B >> 1;
    var rng = std.Random.DefaultPrng.init(7);
    const rnd = rng.random();
    for (0..2000) |_| {
        const x = rnd.int(T);
        const d = decompose(b_bits, ell, x);
        for (d) |di| {
            try testing.expect(di >= -half and di < half); // balanced range
        }
        const back = recompose(b_bits, ell, d);
        const err = @min(x -% back, back -% x); // |x − back| as unsigned distance
        try testing.expect(err <= maxError(b_bits, ell));
    }
}

test "exact-cover decomposition (b·ell = 32) has zero error" {
    const b_bits: u6 = 4;
    const ell: usize = 8;
    try testing.expectEqual(@as(u64, 0), maxError(b_bits, ell));
    var rng = std.Random.DefaultPrng.init(11);
    const rnd = rng.random();
    for (0..2000) |_| {
        const x = rnd.int(T);
        try testing.expectEqual(x, recompose(b_bits, ell, decompose(b_bits, ell, x)));
    }
}
