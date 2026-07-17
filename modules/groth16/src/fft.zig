// SPDX-License-Identifier: MIT
//! Radix-2 number-theoretic transform (NTT / "FFT over `Fr`") and FFT-based
//! polynomial multiplication. This is the mechanical transform layer that
//! turns coefficient form ↔ evaluation form over a `Domain` (`domain.zig`);
//! QAP interpolation is an inverse NTT and the quotient computation multiplies
//! polynomials through it. REAL and ungated — anchored by two properties its
//! own tests assert: ` intt(ntt(v)) == v` (round-trip identity) and
//! `mulViaFFT == poly.mulSchoolbook` (agreement with the reference product).
//!
//! Construction: the standard iterative in-place decimation-in-time
//! Cooley-Tukey butterfly, with the twiddle factors taken as powers of the
//! domain's primitive root of unity `ω` (forward) / `ω^{−1}` (inverse). No
//! novel algorithm — this is the same NTT every SNARK toolchain (arkworks,
//! gnark, snarkjs) runs.

const std = @import("std");
const field = @import("field.zig");
const domain = @import("domain.zig");
const poly = @import("poly.zig");
const Fr = field.Fr;

/// In-place radix-2 NTT of `vals` (length must be a power of two) using
/// `root` as the primitive `len`-th root of unity. Transforms coefficient
/// form into evaluation form at `root^0 … root^{len−1}`.
pub fn ntt(vals: []Fr, root: Fr) void {
    const nn = vals.len;
    std.debug.assert(nn != 0 and (nn & (nn - 1)) == 0);

    // Bit-reversal permutation.
    var j: usize = 0;
    var i: usize = 1;
    while (i < nn) : (i += 1) {
        var bit = nn >> 1;
        while (j & bit != 0) {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if (i < j) std.mem.swap(Fr, &vals[i], &vals[j]);
    }

    // Butterflies, doubling the transform length each pass.
    var len: usize = 2;
    while (len <= nn) : (len <<= 1) {
        // w_len is a primitive len-th root of unity = root^(nn/len).
        const w_len = field.frPowU64(root, @intCast(nn / len));
        var start: usize = 0;
        while (start < nn) : (start += len) {
            var w = Fr.one;
            var k: usize = 0;
            while (k < len / 2) : (k += 1) {
                const u = vals[start + k];
                const v = vals[start + k + len / 2].mul(w);
                vals[start + k] = u.add(v);
                vals[start + k + len / 2] = u.sub(v);
                w = w.mul(w_len);
            }
        }
    }
}

/// In-place inverse NTT: evaluation form → coefficient form. Uses `ω^{−1}`
/// and the `n^{−1}` normalisation from the `Domain`.
pub fn intt(comptime n: usize, vals: []Fr) void {
    std.debug.assert(vals.len == n);
    const D = domain.Domain(n);
    ntt(vals, D.rootInv());
    const n_inv = D.nInv();
    for (vals) |*x| x.* = x.mul(n_inv);
}

/// Forward NTT over `Domain(n)` — coefficient slice (length `n`) → its
/// evaluations at the domain points, in place.
pub fn nttOverDomain(comptime n: usize, vals: []Fr) void {
    std.debug.assert(vals.len == n);
    ntt(vals, domain.Domain(n).root());
}

/// Polynomial multiplication via the FFT path: `out = a · b`, computed by
/// evaluating both over a size-`m` domain (`m = n`, the caller-chosen power
/// of two `≥ a.len + b.len − 1`), pointwise-multiplying, and inverse-
/// transforming. `out.len` must be `a.len + b.len − 1`; the size-`n` scratch
/// buffers are stack-local. Cross-checked against `poly.mulSchoolbook`.
pub fn mulViaFFT(comptime n: usize, out: []Fr, a: []const Fr, b: []const Fr) void {
    std.debug.assert(a.len + b.len - 1 <= n);
    std.debug.assert(out.len == a.len + b.len - 1);

    var fa: [n]Fr = undefined;
    var fb: [n]Fr = undefined;
    @memset(&fa, Fr.zero);
    @memset(&fb, Fr.zero);
    @memcpy(fa[0..a.len], a);
    @memcpy(fb[0..b.len], b);

    nttOverDomain(n, &fa);
    nttOverDomain(n, &fb);
    for (&fa, fb) |*x, y| x.* = x.mul(y);
    intt(n, &fa);

    @memcpy(out, fa[0..out.len]);
}

// ── tests ────────────────────────────────────────────────────────────────

const frFromU64 = field.frFromU64;

test "NTT round-trip: intt(ntt(v)) == v" {
    inline for (.{ 2, 4, 8, 16, 64 }) |n| {
        var v: [n]Fr = undefined;
        for (&v, 0..) |*x, i| x.* = frFromU64(@as(u64, i) * 7 + 1);
        const orig = v;
        nttOverDomain(n, &v);
        intt(n, &v);
        try std.testing.expectEqualSlices(Fr, &orig, &v);
    }
}

test "NTT evaluates a polynomial at the domain points" {
    // Forward NTT of coefficient vector must equal poly.eval at ω^i.
    const n = 8;
    const D = domain.Domain(n);
    var coeffs: [n]Fr = undefined;
    for (&coeffs, 0..) |*c, i| c.* = frFromU64(@as(u64, i) + 1);
    var evals = coeffs;
    nttOverDomain(n, &evals);
    const pts = D.points();
    for (pts, evals) |x, got| {
        try std.testing.expect(poly.eval(&coeffs, x).eql(got));
    }
}

test "mulViaFFT agrees with schoolbook multiplication" {
    const a = [_]Fr{ frFromU64(1), frFromU64(2), frFromU64(3) };
    const b = [_]Fr{ frFromU64(4), frFromU64(5) };
    var expected: [4]Fr = undefined;
    poly.mulSchoolbook(&expected, &a, &b);
    var got: [4]Fr = undefined;
    mulViaFFT(8, &got, &a, &b); // 8 >= 3+2-1 = 4
    try std.testing.expectEqualSlices(Fr, &expected, &got);
}
