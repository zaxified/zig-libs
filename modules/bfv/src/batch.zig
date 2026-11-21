// SPDX-License-Identifier: MIT

//! batch — CRT-slot ("SIMD") encoding of `N` integers mod `t` into one
//! plaintext of `R_t = Z_t[X]/(X^N+1)`, for a prime `t ≡ 1 (mod 2N)`.
//!
//! `X^N + 1` splits mod such a `t` into `N` linear factors `X − ζ^e`, `e` odd,
//! `ζ` a primitive `2N`-th root of unity mod `t`; by CRT a plaintext is the
//! vector of its values `m(ζ^e)`, and ring add/multiply act slot-wise. The
//! slots are laid out as SEAL's `BatchEncoder` lays them out: a `2 × N/2`
//! matrix, row 0 column `i` at `e = 3^i`, row 1 column `i` at `e = −3^i`
//! (`mod 2N`). The Galois automorphism `X ↦ X^{3^k}` then rotates both rows
//! left by `k` and `X ↦ X^{−1}` swaps the rows — `Bfv(P).galoisElement` /
//! `galois_row_swap` with `Bfv(P).applyGalois`.
//!
//! `encode`/`decode` are one inverse / forward negacyclic NTT mod `t`; which
//! NTT output position holds which slot is found once at `init` by probing
//! the engine with the polynomial `X` (whose transform is the list of roots),
//! so the layout does not depend on the engine's output order.

const std = @import("std");
const ma = @import("modarith.zig");
const nttmod = @import("ntt.zig");
const encode = @import("encode.zig");

pub fn BatchEncoder(comptime N: usize) type {
    if (N < 4) @compileError("BatchEncoder needs N >= 4 (two rows of N/2 >= 2 columns)");
    return struct {
        const Self = @This();
        pub const Plaintext = encode.Plaintext(N);
        pub const slot_count = N;
        pub const row_size = N / 2;

        engine: nttmod.Ntt(N),
        t: u64,
        /// `ntt_index[s]` = the NTT output position holding slot `s`
        /// (`s < N/2`: row 0 column `s`; else row 1 column `s − N/2`).
        ntt_index: [N]u32,

        /// `error.NotPrime` / `error.NoPrimitiveRoot`-style errors from the NTT
        /// engine when `t` is not a prime `≡ 1 (mod 2N)` (`< 2^62`).
        pub fn init(t: u64) !Self {
            const engine = try nttmod.Ntt(N).init(t);
            // The transform of `X` is the list of evaluation points.
            var roots: [N]u64 = @splat(0);
            roots[1] = 1;
            engine.forward(&roots);
            const Pair = struct { v: u64, k: u32 };
            var sorted: [N]Pair = undefined;
            for (roots, 0..) |v, k| sorted[k] = .{ .v = v, .k = @intCast(k) };
            std.mem.sort(Pair, &sorted, {}, struct {
                fn lt(_: void, a: Pair, b: Pair) bool {
                    return a.v < b.v;
                }
            }.lt);
            // ζ: any evaluation point is a primitive 2N-th root (an odd power
            // of the engine's ψ); take the one at position 0.
            const zeta = roots[0];
            var out: Self = .{ .engine = engine, .t = t, .ntt_index = undefined };
            var e: u64 = 1; // 3^i mod 2N
            for (0..row_size) |i| {
                out.ntt_index[i] = try find(&sorted, ma.powMod(zeta, e, t));
                out.ntt_index[row_size + i] = try find(&sorted, ma.powMod(zeta, 2 * N - e, t));
                e = (e * 3) % (2 * N);
            }
            return out;
        }

        fn find(sorted: anytype, v: u64) !u32 {
            var lo: usize = 0;
            var hi: usize = sorted.len;
            while (lo < hi) {
                const mid = (lo + hi) / 2;
                if (sorted[mid].v < v) lo = mid + 1 else hi = mid;
            }
            if (lo == sorted.len or sorted[lo].v != v) return error.NotASlotRoot;
            return sorted[lo].k;
        }

        /// Encode `N` slot values (each `< t`, else `error.ValueOutOfRange`,
        /// as SEAL refuses them) into one plaintext.
        pub fn encodeSlots(self: *const Self, values: *const [N]u64) error{ValueOutOfRange}!Plaintext {
            var v: [N]u64 = undefined;
            for (values, 0..) |x, s| {
                if (x >= self.t) return error.ValueOutOfRange;
                v[self.ntt_index[s]] = x;
            }
            self.engine.inverse(&v);
            return .{ .coeffs = v, .t = self.t };
        }

        /// The `N` slot values of `pt` (its coefficients taken mod `t`).
        pub fn decodeSlots(self: *const Self, pt: *const Plaintext) [N]u64 {
            var v: [N]u64 = undefined;
            for (pt.coeffs, 0..) |c, j| v[j] = c % self.t;
            self.engine.forward(&v);
            var out: [N]u64 = undefined;
            for (0..N) |s| out[s] = v[self.ntt_index[s]];
            return out;
        }

        /// Slot `s`'s evaluation exponent `e` (`m(ζ^e)`): `3^i` for row 0,
        /// `−3^i mod 2N` for row 1. Exposed for tests and for callers that
        /// reason about the layout.
        pub fn slotExponent(s: usize) u64 {
            var e: u64 = 1;
            for (0..s % row_size) |_| e = (e * 3) % (2 * N);
            return if (s < row_size) e else 2 * N - e;
        }
    };
}

const testing = std.testing;

test "batch: slot s holds m(zeta^e_s) — checked by direct evaluation" {
    const B = BatchEncoder(16);
    const t: u64 = 97; // prime, 97 = 3*32 + 1
    const enc = try B.init(t);
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    var vals: [16]u64 = undefined;
    for (&vals) |*x| x.* = rnd.uintLessThan(u64, t);
    const pt = try enc.encodeSlots(&vals);
    // Recover ζ from slot 0 of the polynomial X: decode(X)[0] = ζ^1.
    var x_poly = B.Plaintext.zero(t);
    x_poly.coeffs[1] = 1;
    const zeta = enc.decodeSlots(&x_poly)[0];
    // ζ is a primitive 32nd root: ζ^16 = −1.
    try testing.expectEqual(t - 1, ma.powMod(zeta, 16, t));
    for (0..16) |s| {
        const pt_at = ma.powMod(zeta, B.slotExponent(s), t);
        var acc: u64 = 0;
        var p: u64 = 1;
        for (pt.coeffs) |c| {
            acc = (acc + c * p) % t;
            p = p * pt_at % t;
        }
        try testing.expectEqual(vals[s], acc);
    }
    try testing.expectEqualSlices(u64, &vals, &enc.decodeSlots(&pt));
}

test "batch: slot-wise product and the refusals" {
    const B = BatchEncoder(8);
    const t: u64 = 17; // 17 = 16 + 1
    const enc = try B.init(t);
    const a = [8]u64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const b = [8]u64{ 16, 3, 0, 9, 1, 2, 5, 11 };
    const pa = try enc.encodeSlots(&a);
    const pb = try enc.encodeSlots(&b);
    const prod = B.Plaintext.mulRef(&pa, &pb);
    const got = enc.decodeSlots(&prod);
    for (0..8) |s| try testing.expectEqual(a[s] * b[s] % t, got[s]);
    var too_big = a;
    too_big[3] = t;
    try testing.expectError(error.ValueOutOfRange, enc.encodeSlots(&too_big));
    try testing.expectError(error.NoRootExists, B.init(23)); // prime, but 16 does not divide 22
    try testing.expectError(error.NotPrime, B.init(33));
}
