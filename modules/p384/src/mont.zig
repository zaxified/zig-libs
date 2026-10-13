// SPDX-License-Identifier: MIT

//! Montgomery arithmetic over six 64-bit limbs for a 384-bit odd modulus m
//! (R = 2^384), shared by the base field (`field.zig`, m = p) and the scalar
//! field (`scalar.zig`, m = n). Values are little-endian limbs; every
//! operation here is branch-free and table-free in its inputs.
//!
//! `mul`/`sq` are a 6 × 6 schoolbook product (the square computes each
//! off-diagonal product once) into twelve limbs, then a six-round
//! word-by-word reduction and one masked final subtraction. Inputs and
//! outputs are canonical (< m).

const std = @import("std");

pub const Limbs = [6]u64;

pub fn limbsOf(x: anytype) Limbs {
    var r: Limbs = undefined;
    var v: u384 = @intCast(x);
    for (0..6) |i| {
        r[i] = @truncate(v);
        v >>= 64;
    }
    return r;
}

pub fn Mont(comptime m_int: u384) type {
    comptime std.debug.assert(m_int & 1 == 1 and m_int >> 383 == 1);
    return struct {
        pub const M: Limbs = limbsOf(m_int);

        /// −m⁻¹ mod 2^64 (Newton iteration on the low limb).
        pub const M0INV: u64 = blk: {
            var inv: u64 = 1;
            for (0..7) |_| inv = inv *% (2 -% M[0] *% inv);
            break :blk 0 -% inv;
        };

        /// R mod m and R² mod m.
        pub const R1: Limbs = limbsOf((@as(u768, 1) << 384) % m_int);
        pub const R2: Limbs = blk: {
            @setEvalBranchQuota(100_000);
            break :blk limbsOf((@as(u1152, 1) << 768) % m_int);
        };

        /// t (< 2m, seven limbs with t[6] ∈ {0, 1}) reduced into [0, m) by
        /// one masked subtraction.
        pub inline fn condSub(t: [7]u64) Limbs {
            var r: Limbs = undefined;
            var borrow: u1 = 0;
            inline for (0..6) |i| {
                const d1 = @subWithOverflow(t[i], M[i]);
                const d2 = @subWithOverflow(d1[0], borrow);
                r[i] = d2[0];
                borrow = d1[1] | d2[1];
            }
            // t < m iff the subtraction borrows past t[6]: keep t then.
            const under = @subWithOverflow(t[6], borrow)[1];
            const keep = 0 -% @as(u64, under);
            var out: Limbs = undefined;
            inline for (0..6) |i| out[i] = (t[i] & keep) | (r[i] & ~keep);
            return out;
        }

        /// The twelve-limb product a·b (a, b < 2^384).
        pub inline fn product(a: Limbs, b: Limbs) [12]u64 {
            var t: [12]u64 = @splat(0);
            inline for (0..6) |i| {
                var c: u64 = 0;
                inline for (0..6) |j| {
                    const x = @as(u128, a[j]) * b[i] + t[i + j] + c;
                    t[i + j] = @truncate(x);
                    c = @truncate(x >> 64);
                }
                t[i + 6] = c;
            }
            return t;
        }

        /// The twelve-limb square: each off-diagonal product once, doubled,
        /// plus the diagonal.
        pub inline fn square(a: Limbs) [12]u64 {
            var t: [12]u64 = @splat(0);
            inline for (0..5) |i| {
                var c: u64 = 0;
                inline for (i + 1..6) |j| {
                    const x = @as(u128, a[j]) * a[i] + t[i + j] + c;
                    t[i + j] = @truncate(x);
                    c = @truncate(x >> 64);
                }
                t[i + 6] = c;
            }
            // ×2: the off-diagonal sum is < 2^767, so no bit is shifted out.
            var hi: u64 = 0;
            inline for (0..12) |k| {
                const v = t[k];
                t[k] = (v << 1) | hi;
                hi = v >> 63;
            }
            // + the diagonal a_i² at 2^(128 i).
            var c: u1 = 0;
            inline for (0..6) |i| {
                const d = @as(u128, a[i]) * a[i];
                const lo = @addWithOverflow(t[2 * i], @as(u64, @truncate(d)));
                const lo2 = @addWithOverflow(lo[0], c);
                t[2 * i] = lo2[0];
                const hi1 = @addWithOverflow(t[2 * i + 1], @as(u64, @truncate(d >> 64)));
                const hi2 = @addWithOverflow(hi1[0], @as(u64, lo[1] | lo2[1]));
                t[2 * i + 1] = hi2[0];
                c = hi1[1] | hi2[1];
            }
            return t;
        }

        /// T·R⁻¹ mod m for T < m·R, canonical. Each round cancels one low
        /// limb with q·m, q = t_i·(−m⁻¹) mod 2^64; the round's carry out of
        /// position i + 6 enters the next round at i + 7.
        pub inline fn reduce(t_: [12]u64) Limbs {
            var t = t_;
            var top: u64 = 0;
            inline for (0..6) |i| {
                const q = t[i] *% M0INV;
                var c: u64 = 0;
                inline for (0..6) |j| {
                    const x = @as(u128, q) * M[j] + t[i + j] + c;
                    t[i + j] = @truncate(x);
                    c = @truncate(x >> 64);
                }
                const x = @as(u128, t[i + 6]) + c + top;
                t[i + 6] = @truncate(x);
                top = @truncate(x >> 64);
            }
            // (T + q·m)/R < (m·R + R·m)/R = 2m.
            return condSub(.{ t[6], t[7], t[8], t[9], t[10], t[11], top });
        }

        /// a·b·R⁻¹ mod m (a < 2^384, b < m).
        pub inline fn mul(a: Limbs, b: Limbs) Limbs {
            return reduce(product(a, b));
        }

        /// a²·R⁻¹ mod m (a < m).
        pub inline fn sq(a: Limbs) Limbs {
            return reduce(square(a));
        }

        /// a·R⁻¹ mod m: out of the domain (a < 2^384 — any 384-bit string,
        /// which also reduces it).
        pub inline fn fromMont(a: Limbs) Limbs {
            var t: [12]u64 = @splat(0);
            t[0..6].* = a;
            return reduce(t);
        }

        /// 1 iff a < m, no branch.
        pub fn lt(a: Limbs) u1 {
            var borrow: u1 = 0;
            inline for (0..6) |i| {
                const d1 = @subWithOverflow(a[i], M[i]);
                const d2 = @subWithOverflow(d1[0], borrow);
                borrow = d1[1] | d2[1];
            }
            return borrow;
        }

        pub inline fn add(a: Limbs, b: Limbs) Limbs {
            var t: [7]u64 = undefined;
            var c: u1 = 0;
            inline for (0..6) |i| {
                const s1 = @addWithOverflow(a[i], b[i]);
                const s2 = @addWithOverflow(s1[0], c);
                t[i] = s2[0];
                c = s1[1] | s2[1];
            }
            t[6] = c;
            return condSub(t);
        }

        pub inline fn sub(a: Limbs, b: Limbs) Limbs {
            var r: Limbs = undefined;
            var borrow: u1 = 0;
            inline for (0..6) |i| {
                const d1 = @subWithOverflow(a[i], b[i]);
                const d2 = @subWithOverflow(d1[0], borrow);
                r[i] = d2[0];
                borrow = d1[1] | d2[1];
            }
            // Went negative: add m back (masked).
            const msk = 0 -% @as(u64, borrow);
            var c: u1 = 0;
            inline for (0..6) |i| {
                const s1 = @addWithOverflow(r[i], M[i] & msk);
                const s2 = @addWithOverflow(s1[0], c);
                r[i] = s2[0];
                c = s1[1] | s2[1];
            }
            return r;
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "mont: square == product on extreme limb patterns, both moduli (audit 2026-10-13)" {
    // All-ones limbs drive every diagonal-carry path of `square`; m − 1 is
    // the largest canonical input.
    const P = Mont(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff);
    const N = Mont(0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973);
    const ones: Limbs = @splat(~@as(u64, 0));
    const alt: Limbs = .{ ~@as(u64, 0), 0, ~@as(u64, 0), 0, ~@as(u64, 0), 0 };
    inline for (.{ P, N }) |A| {
        var m1 = A.M;
        m1[0] -= 1;
        for ([_]Limbs{ ones, alt, m1, A.R1, A.R2 }) |x| {
            try testing.expectEqualSlices(u64, &A.product(x, x), &A.square(x));
        }
        try testing.expectEqualSlices(u64, &A.mul(m1, m1), &A.sq(m1));
    }
}
