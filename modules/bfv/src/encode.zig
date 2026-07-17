// SPDX-License-Identifier: MIT

//! encode — BFV plaintext encoding: a plaintext is an element of
//! `R_t = Z_t[X]/(X^N+1)`, i.e. `N` coefficients mod the plaintext modulus
//! `t`. Part 1 ships the two mechanical encodings that need no scheme state:
//!
//!   - **coefficient encoding** (`fromCoeffs`/`toCoeffs`): the caller supplies
//!     the `N` coefficients directly (reduced mod `t`); the natural encoding
//!     for polynomial/coefficient-wise homomorphic evaluation.
//!   - **integer (base-`t`) encoding** (`encodeUint`/`decodeUint`): a single
//!     unsigned integer packed into the low coefficients as base-`t` digits,
//!     decoded by Horner evaluation at `t` — a simple scalar encoding.
//!
//! CRT **batch/SIMD slot** encoding (an NTT mod `t`, giving `N` independent
//! integer slots) is a deferred increment (SPEC.md): it needs `t ≡ 1 mod 2N`
//! and is orthogonal to the Part-1 backbone. All of this is REAL/ungated.

const std = @import("std");

/// `Plaintext(N)` — `N` coefficients in `[0, t)`. `t` travels with the value
/// so decode can validate.
pub fn Plaintext(comptime N: usize) type {
    return struct {
        const Self = @This();
        pub const degree = N;
        coeffs: [N]u64,
        t: u64,

        pub fn zero(t: u64) Self {
            return .{ .coeffs = [_]u64{0} ** N, .t = t };
        }

        /// Coefficient encoding: reduce each supplied coefficient mod `t`.
        pub fn fromCoeffs(t: u64, raw: [N]u64) Self {
            var out = Self{ .coeffs = raw, .t = t };
            for (&out.coeffs) |*c| c.* %= t;
            return out;
        }

        pub fn toCoeffs(self: *const Self) [N]u64 {
            return self.coeffs;
        }

        /// Integer encoding: little-endian base-`t` digits of `x` in the low
        /// coefficients. `error.Overflow` if `x` needs more than `N` digits.
        pub fn encodeUint(t: u64, x: u128) !Self {
            var out = Self.zero(t);
            var v = x;
            var i: usize = 0;
            while (v != 0) : (i += 1) {
                if (i >= N) return error.Overflow;
                out.coeffs[i] = @intCast(v % t);
                v /= t;
            }
            return out;
        }

        /// Inverse of `encodeUint`: Horner evaluation at `t`. `error.Overflow`
        /// if the value exceeds `u128`.
        pub fn decodeUint(self: *const Self) !u128 {
            var acc: u128 = 0;
            var i: usize = N;
            while (i > 0) {
                i -= 1;
                acc = try std.math.mul(u128, acc, self.t);
                acc = try std.math.add(u128, acc, self.coeffs[i]);
            }
            return acc;
        }

        /// Coefficient-wise `(a + b) mod t` — the plaintext-space reference
        /// for what homomorphic add must compute after decrypt.
        pub fn addRef(a: *const Self, b: *const Self) Self {
            var out = Self{ .coeffs = undefined, .t = a.t };
            for (&out.coeffs, a.coeffs, b.coeffs) |*c, x, y| c.* = (x + y) % a.t;
            return out;
        }

        /// Coefficient-domain negacyclic `(a · b) mod (X^N+1) mod t` — the
        /// plaintext-space reference for what homomorphic multiply must
        /// compute after decrypt. O(N^2), exact, independent of any NTT.
        /// Signed `i128` accumulation folds `X^N = -1` before reducing mod `t`.
        pub fn mulRef(a: *const Self, b: *const Self) Self {
            var acc = [_]i128{0} ** N;
            for (0..N) |i| for (0..N) |j| {
                const prod: i128 = @as(i128, @intCast(a.coeffs[i])) * @as(i128, @intCast(b.coeffs[j]));
                const k = i + j;
                if (k < N) {
                    acc[k] += prod;
                } else {
                    acc[k - N] -= prod; // X^N = -1
                }
            };
            var out = Self{ .coeffs = undefined, .t = a.t };
            const tt: i128 = @intCast(a.t);
            for (&out.coeffs, acc) |*c, w| {
                const r = @mod(w, tt); // always in [0, t)
                c.* = @intCast(r);
            }
            return out;
        }
    };
}

const testing = std.testing;

test "coefficient encode reduces mod t" {
    const P = Plaintext(8);
    const p = P.fromCoeffs(4, .{ 0, 1, 2, 3, 4, 5, 6, 7 });
    try testing.expectEqualSlices(u64, &.{ 0, 1, 2, 3, 0, 1, 2, 3 }, &p.toCoeffs());
}

test "integer base-t encode/decode round-trip" {
    const P = Plaintext(8);
    const t: u64 = 4;
    for ([_]u128{ 0, 1, 3, 4, 255, 65535, 65536 - 1 }) |x| {
        const p = try P.encodeUint(t, x);
        try testing.expectEqual(x, try p.decodeUint());
    }
    try testing.expectError(error.Overflow, P.encodeUint(2, 1 << 40)); // needs > 8 base-2 digits
}

test "addRef is coefficient-wise mod t" {
    const P = Plaintext(8);
    const a = P.fromCoeffs(5, .{ 1, 2, 3, 4, 0, 0, 0, 0 });
    const b = P.fromCoeffs(5, .{ 4, 4, 4, 4, 0, 0, 0, 0 });
    const c = P.addRef(&a, &b);
    try testing.expectEqualSlices(u64, &.{ 0, 1, 2, 3, 0, 0, 0, 0 }, &c.coeffs);
}

test "mulRef folds X^N = -1 (constant polys and a wrap case)" {
    const P = Plaintext(8);
    const t: u64 = 17;
    // constants: 3 * 5 = 15
    const a = P.fromCoeffs(t, .{ 3, 0, 0, 0, 0, 0, 0, 0 });
    const b = P.fromCoeffs(t, .{ 5, 0, 0, 0, 0, 0, 0, 0 });
    try testing.expectEqual(@as(u64, 15), P.mulRef(&a, &b).coeffs[0]);
    // X^7 * X^1 = X^8 = -1  ⇒ coefficient 0 becomes -1 ≡ t-1
    const x7 = P.fromCoeffs(t, .{ 0, 0, 0, 0, 0, 0, 0, 1 });
    const x1 = P.fromCoeffs(t, .{ 0, 1, 0, 0, 0, 0, 0, 0 });
    const w = P.mulRef(&x7, &x1);
    try testing.expectEqual(@as(u64, t - 1), w.coeffs[0]);
    for (w.coeffs[1..]) |c| try testing.expectEqual(@as(u64, 0), c);
}
