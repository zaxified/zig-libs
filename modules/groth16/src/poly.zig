// SPDX-License-Identifier: MIT
//! Dense univariate polynomials over `Fr`, represented as a coefficient
//! slice `[]const Fr` in ascending order (`c[0] + c[1]·x + …`). All
//! operations are slice-based and allocation-free — the caller supplies the
//! output buffer, sized per the documented degree bound. This is the
//! mechanical polynomial layer under the QAP construction; it is REAL and
//! ungated (round-trip / cross-checked against the FFT path in `fft.zig`).
//!
//! The one Groth16-specific operation here is `divByVanishing`: exact
//! division by the vanishing polynomial `Z(x) = x^n − 1` of the evaluation
//! domain, which is how the quotient `H(x) = (A·B − C)/Z` is formed. Because
//! `Z` has the special form `x^n − 1`, the division is a single linear pass
//! (`x^i ≡ x^{i−n}` modulo `Z`), not general long division.

const std = @import("std");
const field = @import("field.zig");
const Fr = field.Fr;

/// Evaluates `coeffs` at `x` via Horner's rule. `eval(&.{}, x) == 0`.
pub fn eval(coeffs: []const Fr, x: Fr) Fr {
    var acc = Fr.zero;
    var i: usize = coeffs.len;
    while (i > 0) {
        i -= 1;
        acc = acc.mul(x).add(coeffs[i]);
    }
    return acc;
}

/// `out = a + b` (coefficient-wise). `out.len` must be `max(a.len, b.len)`;
/// `out` is fully overwritten.
pub fn add(out: []Fr, a: []const Fr, b: []const Fr) void {
    std.debug.assert(out.len == @max(a.len, b.len));
    for (out, 0..) |*o, i| {
        const av = if (i < a.len) a[i] else Fr.zero;
        const bv = if (i < b.len) b[i] else Fr.zero;
        o.* = av.add(bv);
    }
}

/// `out = a − b` (coefficient-wise). `out.len` must be `max(a.len, b.len)`.
pub fn sub(out: []Fr, a: []const Fr, b: []const Fr) void {
    std.debug.assert(out.len == @max(a.len, b.len));
    for (out, 0..) |*o, i| {
        const av = if (i < a.len) a[i] else Fr.zero;
        const bv = if (i < b.len) b[i] else Fr.zero;
        o.* = av.sub(bv);
    }
}

/// Schoolbook (O(n·m)) polynomial multiplication `out = a · b`. `out.len`
/// must be `a.len + b.len − 1` (or the product is 0 for an empty operand,
/// in which case `out.len == 0`). `out` is zero-initialised internally.
/// This is the reference multiplication the FFT path (`fft.mulViaFFT`) is
/// cross-checked against.
pub fn mulSchoolbook(out: []Fr, a: []const Fr, b: []const Fr) void {
    if (a.len == 0 or b.len == 0) {
        std.debug.assert(out.len == 0);
        return;
    }
    std.debug.assert(out.len == a.len + b.len - 1);
    @memset(out, Fr.zero);
    for (a, 0..) |av, i| {
        for (b, 0..) |bv, j| {
            out[i + j] = out[i + j].add(av.mul(bv));
        }
    }
}

/// Exact division by the vanishing polynomial `Z(x) = x^n − 1`.
///
/// Writes the quotient into `quotient` (length `p.len − n`) and returns
/// `true` iff the division is exact (remainder is the zero polynomial). A
/// non-exact division still fills `quotient` with the polynomial part but
/// returns `false` — the caller (QAP divisibility oracle) uses the boolean
/// as the "witness satisfies the R1CS" test.
///
/// Algorithm: reduce `p` modulo `Z` from the top down. For `i ≥ n`,
/// `x^i = x^{i−n}·(x^n − 1) + x^{i−n}`, so coefficient `c` at degree `i`
/// contributes `c` to the quotient at degree `i−n` and folds `c` back into
/// degree `i−n` of the running remainder. What remains in degrees `< n` is
/// the true remainder.
pub fn divByVanishing(quotient: []Fr, p: []const Fr, comptime n: usize) bool {
    std.debug.assert(p.len >= n);
    std.debug.assert(quotient.len == p.len - n);

    // Working copy of the remainder lives in a caller-free scheme: we walk
    // `p` high→low, accumulating folds into a scratch we derive on the fly.
    // To stay allocation-free we reduce in place over a local copy bounded
    // by p.len; for scaffold-scale circuits this stack buffer is ample.
    var rem: [max_degree]Fr = undefined;
    std.debug.assert(p.len <= max_degree);
    @memcpy(rem[0..p.len], p);

    @memset(quotient, Fr.zero);
    var i: usize = p.len;
    while (i > n) {
        i -= 1;
        const c = rem[i];
        rem[i] = Fr.zero;
        quotient[i - n] = quotient[i - n].add(c);
        rem[i - n] = rem[i - n].add(c);
    }

    // Remainder is degrees 0..n-1 of `rem`; exact iff all zero.
    for (rem[0..n]) |coeff| {
        if (!coeff.isZero()) return false;
    }
    return true;
}

/// Upper bound on any polynomial length `divByVanishing` handles without
/// allocation. `A·B − C` has degree `< 2n` and the largest scaffold domain
/// in the test harness is well under this — bump if a larger circuit needs
/// it (or promote to an allocator-based path). 2·2^13 headroom.
pub const max_degree: usize = 1 << 14;

// ── tests ────────────────────────────────────────────────────────────────

const frFromU64 = field.frFromU64;

test "eval: Horner matches manual, empty poly is zero" {
    // p(x) = 3 + 2x + x^2 ; p(2) = 3 + 4 + 4 = 11
    const p = [_]Fr{ frFromU64(3), frFromU64(2), frFromU64(1) };
    try std.testing.expect(eval(&p, frFromU64(2)).eql(frFromU64(11)));
    try std.testing.expect(eval(&.{}, frFromU64(9)).isZero());
}

test "add / sub are inverse operations" {
    const a = [_]Fr{ frFromU64(1), frFromU64(2), frFromU64(3) };
    const b = [_]Fr{ frFromU64(10), frFromU64(20) };
    var s: [3]Fr = undefined;
    add(&s, &a, &b);
    var back: [3]Fr = undefined;
    sub(&back, &s, &b);
    try std.testing.expectEqualSlices(Fr, &a, &back);
}

test "mulSchoolbook: (1+x)(1+x) = 1 + 2x + x^2" {
    const a = [_]Fr{ frFromU64(1), frFromU64(1) };
    var out: [3]Fr = undefined;
    mulSchoolbook(&out, &a, &a);
    try std.testing.expect(out[0].eql(frFromU64(1)));
    try std.testing.expect(out[1].eql(frFromU64(2)));
    try std.testing.expect(out[2].eql(frFromU64(1)));
}

test "divByVanishing: (x^2-1) = (x-1)(x+1), exact for n=1 domain Z=x-1" {
    // Z(x) = x^1 - 1 = x - 1. Dividing p(x) = x^2 - 1 by (x - 1) gives
    // quotient (x + 1), remainder 0.
    // p = -1 + 0x + 1x^2
    const p = [_]Fr{ Fr.one.neg(), Fr.zero, Fr.one };
    var q: [2]Fr = undefined;
    const exact = divByVanishing(&q, &p, 1);
    try std.testing.expect(exact);
    // quotient should be (1 + x)
    try std.testing.expect(q[0].eql(Fr.one));
    try std.testing.expect(q[1].eql(Fr.one));
}

test "divByVanishing: non-multiple of Z reports inexact" {
    // p(x) = x^2 (not divisible by x^2 - 1 exactly: x^2 = 1·(x^2-1) + 1)
    const p = [_]Fr{ Fr.zero, Fr.zero, Fr.one };
    var q: [1]Fr = undefined;
    const exact = divByVanishing(&q, &p, 2);
    try std.testing.expect(!exact); // remainder is 1
    try std.testing.expect(q[0].eql(Fr.one)); // quotient is 1
}
