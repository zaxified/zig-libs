// SPDX-License-Identifier: MIT
//! Rank-1 constraint system (R1CS) over `Fr` — the arithmetic circuit form
//! Groth16 proves satisfaction of. A system is `m` constraints over a
//! witness vector `w` (`w[0] = 1` by convention, then public inputs, then
//! private auxiliary values). Each constraint `i` carries three sparse
//! linear combinations `Aᵢ, Bᵢ, Cᵢ` of the witness and is satisfied iff
//! `(Aᵢ·w) · (Bᵢ·w) = (Cᵢ·w)`.
//!
//! REAL and ungated. This is both the prover's input and — crucially — the
//! oracle behind the QAP divisibility anchor (`qap.zig`): a witness satisfies
//! the R1CS **iff** `A(x)·B(x) − C(x)` (the QAP polynomials built from it) is
//! divisible by the domain's vanishing polynomial. `isSatisfied` here and the
//! divisibility test there must always agree.

const std = @import("std");
const field = @import("field.zig");
const Fr = field.Fr;

/// One nonzero entry of a constraint's linear combination: `coeff · w[index]`.
pub const Term = struct {
    index: usize,
    coeff: Fr,
};

/// A single rank-1 constraint `(a·w)·(b·w) = (c·w)`, each of `a`/`b`/`c`
/// given as a sparse list of `Term`s over the witness.
pub const Constraint = struct {
    a: []const Term,
    b: []const Term,
    c: []const Term,
};

/// A rank-1 constraint system. `num_vars` is the witness length (including
/// the leading constant `w[0] = 1`).
pub const System = struct {
    num_vars: usize,
    constraints: []const Constraint,

    /// Evaluates one sparse linear combination against the witness:
    /// `Σ term.coeff · w[term.index]`.
    fn dot(lc: []const Term, witness: []const Fr) Fr {
        var acc = Fr.zero;
        for (lc) |t| acc = acc.add(t.coeff.mul(witness[t.index]));
        return acc;
    }

    /// The three dot products `(Aᵢ·w, Bᵢ·w, Cᵢ·w)` for constraint `i` — the
    /// per-constraint evaluations QAP interpolation samples over the domain.
    pub fn evalConstraint(self: System, i: usize, witness: []const Fr) struct { a: Fr, b: Fr, c: Fr } {
        const con = self.constraints[i];
        return .{
            .a = dot(con.a, witness),
            .b = dot(con.b, witness),
            .c = dot(con.c, witness),
        };
    }

    /// Returns `true` iff `witness` satisfies EVERY constraint. `witness.len`
    /// must equal `num_vars`.
    pub fn isSatisfied(self: System, witness: []const Fr) bool {
        std.debug.assert(witness.len == self.num_vars);
        for (self.constraints, 0..) |_, i| {
            const e = self.evalConstraint(i, witness);
            if (!e.a.mul(e.b).eql(e.c)) return false;
        }
        return true;
    }
};

// ── a small reusable example circuit ───────────────────────────────────────

/// A tiny satisfiable circuit used across the test harness: prove knowledge
/// of `x` such that `x·x = 25` (i.e. `x = 5`), with `x` public. Witness
/// layout: `w = [1, x, x·x]`; constraints: `x · x = w[2]` and `w[2] · 1 = 25`
/// pinned via the constant. Concretely a single constraint `x·x = out` with
/// `out` a public input equal to 25 is enough — kept minimal on purpose.
pub const example = struct {
    // w = [ 1, x, out ]  (num_vars = 3)
    pub const num_vars: usize = 3;

    // Constraint 0:  x * x = out   →  a = {x}, b = {x}, c = {out} (coeff 1).
    pub fn constraints() [1]Constraint {
        const one = Fr.one;
        return .{.{
            .a = &[_]Term{.{ .index = 1, .coeff = one }},
            .b = &[_]Term{.{ .index = 1, .coeff = one }},
            .c = &[_]Term{.{ .index = 2, .coeff = one }},
        }};
    }

    pub fn system(cons: []const Constraint) System {
        return .{ .num_vars = num_vars, .constraints = cons };
    }

    /// Satisfying witness for `x = 5`: `[1, 5, 25]`.
    pub fn goodWitness() [3]Fr {
        return .{ Fr.one, field.frFromU64(5), field.frFromU64(25) };
    }

    /// A NON-satisfying witness (`out` tampered to 24): `[1, 5, 24]`.
    pub fn badWitness() [3]Fr {
        return .{ Fr.one, field.frFromU64(5), field.frFromU64(24) };
    }
};

// ── tests ────────────────────────────────────────────────────────────────

test "example circuit: good witness satisfies, bad witness does not" {
    const cons = example.constraints();
    const sys = example.system(&cons);
    const good = example.goodWitness();
    const bad = example.badWitness();
    try std.testing.expect(sys.isSatisfied(&good));
    try std.testing.expect(!sys.isSatisfied(&bad));
}

test "evalConstraint returns the three dot products" {
    const cons = example.constraints();
    const sys = example.system(&cons);
    const good = example.goodWitness();
    const e = sys.evalConstraint(0, &good);
    try std.testing.expect(e.a.eql(field.frFromU64(5)));
    try std.testing.expect(e.b.eql(field.frFromU64(5)));
    try std.testing.expect(e.c.eql(field.frFromU64(25)));
    try std.testing.expect(e.a.mul(e.b).eql(e.c));
}
