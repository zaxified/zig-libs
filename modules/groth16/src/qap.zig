// SPDX-License-Identifier: MIT
//! R1CS → QAP (quadratic arithmetic program) conversion and the divisibility
//! oracle that is THE self-contained teeth-test of this scaffold.
//!
//! Given an R1CS and a witness, the per-constraint dot products
//! `(aᵢ, bᵢ, cᵢ) = (Aᵢ·w, Bᵢ·w, Cᵢ·w)` are the evaluations, at the domain
//! points `ω^i`, of three polynomials `A(x), B(x), C(x)`. Interpolating them
//! (an inverse NTT) and forming `P(x) = A(x)·B(x) − C(x)` gives a polynomial
//! that vanishes on the ENTIRE domain — hence is divisible by the vanishing
//! polynomial `Z(x) = x^n − 1` — **iff every constraint is satisfied**
//! (`aᵢ·bᵢ = cᵢ` for all `i`). The Groth16 quotient is `H(x) = P(x)/Z(x)`.
//!
//! REAL and ungated. `checkDivisible` here MUST agree with
//! `r1cs.System.isSatisfied` on every input — the harness asserts exactly
//! that, which is what proves the FFT/interpolation/division stack correct
//! without needing the (gated) prover core.

const std = @import("std");
const field = @import("field.zig");
const poly = @import("poly.zig");
const fft = @import("fft.zig");
const r1cs = @import("r1cs.zig");
const Fr = field.Fr;

/// Interpolates the QAP polynomials for `sys`+`witness` over `Domain(n)`
/// (`n` a power of two `≥ sys.constraints.len`) and returns whether
/// `A·B − C` is divisible by `Z(x) = x^n − 1`. That boolean equals
/// "the witness satisfies the R1CS".
///
/// `n` must be a power of two ≥ the constraint count; slots beyond the
/// constraint count are the trivially-satisfied padding `0·0 = 0`.
/// All scratch is stack-local (sizes `n` and `2n`).
pub const DivisibilityError = error{DomainTooSmall} || poly.DivError;

pub fn checkDivisible(comptime n: usize, sys: r1cs.System, witness: []const Fr) DivisibilityError!bool {
    // ⛔ NOT an assert — see `prover.setup` for the measurement. A `false` here
    // would be the wrong answer as well as an unsafe one: the honest answer to
    // "does this witness satisfy a circuit that does not fit the domain" is
    // that the question cannot be asked, not that it does not.
    if (sys.constraints.len > n) return error.DomainTooSmall;

    // Evaluation vectors at the domain points.
    var a_evals: [n]Fr = undefined;
    var b_evals: [n]Fr = undefined;
    var c_evals: [n]Fr = undefined;
    for (0..n) |i| {
        if (i < sys.constraints.len) {
            const e = sys.evalConstraint(i, witness);
            a_evals[i] = e.a;
            b_evals[i] = e.b;
            c_evals[i] = e.c;
        } else {
            a_evals[i] = Fr.zero;
            b_evals[i] = Fr.zero;
            c_evals[i] = Fr.zero;
        }
    }

    // Interpolate to coefficient form (inverse NTT).
    fft.intt(n, &a_evals);
    fft.intt(n, &b_evals);
    fft.intt(n, &c_evals);

    // P = A·B − C.  A·B has degree ≤ 2n−2, so multiply over a size-2n domain.
    var ab: [2 * n - 1]Fr = undefined;
    fft.mulViaFFT(2 * n, &ab, &a_evals, &b_evals);

    var p: [2 * n - 1]Fr = undefined;
    poly.sub(&p, &ab, &c_evals);

    // Divide by Z(x) = x^n − 1; exact ⇔ every constraint satisfied.
    var quotient: [2 * n - 1 - n]Fr = undefined;
    return try poly.divByVanishing(&quotient, &p, n);
}

// ── tests ────────────────────────────────────────────────────────────────

test "QAP divisibility agrees with R1CS satisfaction (example circuit)" {
    const cons = r1cs.example.constraints();
    const sys = r1cs.example.system(&cons);
    const good = r1cs.example.goodWitness();
    const bad = r1cs.example.badWitness();

    // Domain n = 2 (1 constraint padded to the next power of two).
    try std.testing.expect(try checkDivisible(2, sys, &good));
    try std.testing.expect(sys.isSatisfied(&good));

    try std.testing.expect(!(try checkDivisible(2, sys, &bad)));
    try std.testing.expect(!sys.isSatisfied(&bad));
}

test "QAP divisibility: divisibility bool tracks satisfaction over many witnesses" {
    // Sweep several x values; out = x·x satisfies, out = x·x + k (k != 0)
    // does not. checkDivisible and isSatisfied must never disagree.
    const cons = r1cs.example.constraints();
    const sys = r1cs.example.system(&cons);
    var x: u64 = 2;
    while (x <= 6) : (x += 1) {
        const good = [_]Fr{ Fr.one, field.frFromU64(x), field.frFromU64(x * x) };
        const bad = [_]Fr{ Fr.one, field.frFromU64(x), field.frFromU64(x * x + 1) };
        try std.testing.expectEqual(sys.isSatisfied(&good), try checkDivisible(2, sys, &good));
        try std.testing.expectEqual(sys.isSatisfied(&bad), try checkDivisible(2, sys, &bad));
        try std.testing.expect(try checkDivisible(2, sys, &good));
        try std.testing.expect(!(try checkDivisible(2, sys, &bad)));
    }
}

test "TEETH: a circuit larger than the domain is REFUSED, not silently truncated" {
    // ⛔ The one failure mode a proof system exists not to have. Every walk over
    // the constraint system stops at the domain size — `columnEvalAtTau`
    // `break`s at `j >= n`, `prove` and this function fill
    // `for (0..n) |j| if (j < sys.constraints.len)` — so a circuit that does not
    // fit was silently CUT DOWN to one that does. The CRS is then built from the
    // truncated circuit, which means the dropped constraints are not merely
    // unproven: they are absent from the statement the verifier checks.
    //
    // The only thing in the way was `std.debug.assert`, compiled out in the very
    // mode README.md and SPEC.md tell you to run. Measured on the circuit below,
    // whose third constraint the witness violates: `isSatisfied` answers `false`,
    // Debug panicked, and ReleaseFast ran on into undefined behaviour — observed
    // as SIGSEGV inside this function on one host and, on another run of the same
    // code, as this oracle answering `true` with `bn254.groth16Verify` accepting
    // the proof. Undefined is undefined; both are the same missing check.
    const T = r1cs.Term;
    const sq = [_]T{.{ .index = 2, .coeff = Fr.one }};
    const out = [_]T{.{ .index = 1, .coeff = Fr.one }};
    const other = [_]T{.{ .index = 3, .coeff = Fr.one }};
    const cons = [_]r1cs.Constraint{
        .{ .a = &sq, .b = &sq, .c = &out }, // x·x = out
        .{ .a = &sq, .b = &sq, .c = &out }, // again
        .{ .a = &other, .b = &other, .c = &out }, // z·z = out — the one that gets DROPPED
    };
    const sys = r1cs.System{ .num_vars = 4, .constraints = &cons };
    // x = 5, out = 25, z = 7: the first two constraints hold, the third does not.
    const w = [_]Fr{ Fr.one, field.frFromU64(25), field.frFromU64(5), field.frFromU64(7) };

    // The honest oracle says what is true.
    try std.testing.expect(!sys.isSatisfied(&w));
    // And the QAP side now refuses to answer rather than answering wrongly —
    // "does this witness satisfy a circuit that does not fit the domain" has no
    // `false` answer, only a refusal.
    try std.testing.expectError(error.DomainTooSmall, checkDivisible(2, sys, &w));

    // Control: the SAME circuit at a domain big enough for it is answered, and
    // answered correctly. Without this, the refusal above could be any failure.
    try std.testing.expect(!try checkDivisible(4, sys, &w));
    const w_ok = [_]Fr{ Fr.one, field.frFromU64(25), field.frFromU64(5), field.frFromU64(5) };
    try std.testing.expect(sys.isSatisfied(&w_ok));
    try std.testing.expect(try checkDivisible(4, sys, &w_ok));
}
