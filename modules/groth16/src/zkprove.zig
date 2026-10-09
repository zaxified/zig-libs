// SPDX-License-Identifier: MIT
//! The Groth16 prover over a snarkjs `.zkey` — what `snarkjs groth16 prove`
//! and rapidsnark do: a proving key from a real ceremony, a witness from
//! circom, a proof any snarkjs verifier (or `bn254.groth16Verify`) accepts.
//!
//! ## The quotient on a coset
//!
//! A zkey's H section is not the textbook `[τʲ·Z(τ)/δ]₁`. Measured on a real
//! file (δ = 1 before any contribution): `H_i == [L^{2n}_{2i+1}(τ)]₁`, the
//! Lagrange basis of the DOUBLED domain at its odd points — which are exactly
//! the coset `g·⟨ω⟩`, `g = ω_{2n}`. On that coset `Z(gωⁱ) = gⁿ − 1 = −2`, and
//! `L^{2n}_{2i+1}(x) = L^{coset}_i(x)·Z(x)/(−2)`. So for the degree-`n−2`
//! quotient `H = (A·B − C)/Z`,
//!
//! ```
//! H(τ)·Z(τ)/δ = Σᵢ H(gωⁱ)·L^{coset}_i(τ)·Z(τ)/δ
//!             = Σᵢ (A·B − C)(gωⁱ) · [L^{2n}_{2i+1}(τ)/δ]
//! ```
//!
//! — the prover evaluates `A·B − C` on the coset (inverse NTT, scale
//! coefficient `j` by `gʲ`, NTT) and does one MSM against the H points. No
//! polynomial division at all.
//!
//! `C` is never interpolated from a matrix: on the domain itself
//! `C(ωⁱ) = A(ωⁱ)·B(ωⁱ)` for a satisfying witness, which is why a zkey stores
//! only the A and B coefficients. A witness that does NOT satisfy the circuit
//! yields a proof that fails verification; nothing here detects that earlier
//! (`r1cs.System.isSatisfied` does, given the `.r1cs`).

const std = @import("std");
const bn254 = @import("bn254");
const burn = @import("burn.zig");
const fft = @import("fft.zig");
const domain = @import("domain.zig");
const msm = @import("msm.zig");
const zkey_mod = @import("zkey.zig");
const prover = @import("prover.zig");

const Fr = bn254.Fr;
const G1 = bn254.G1;
const G2 = bn254.G2;
const ZKey = zkey_mod.ZKey;
const Allocator = std.mem.Allocator;

pub const Proof = bn254.Groth16Proof;

pub const ProveError = error{
    /// `witness.len` is not the key's `n_vars`.
    WitnessMismatch,
    /// A `2^28` domain: the coset needs a `2^29`-th root of unity, which
    /// BN254's `Fr` does not have.
    DomainTooLarge,
} || Allocator.Error;

/// The multi-scalar multiplication the prover runs over the witness and the
/// quotient.
pub const Msm = enum {
    /// Pippenger's bucket method. ⚠ VARIABLE-TIME in the witness: which bucket
    /// a base lands in, and whether a bucket is still empty, depend on the
    /// witness digits, so a co-resident attacker who can time or cache-probe
    /// the prover learns about the witness (SPEC.md § 5b item 4). The trade
    /// snarkjs, rapidsnark, arkworks and gnark make; the default.
    pippenger,
    /// One constant-time `scalarMul` per term (`msm.msmG1`/`msmG2`), the
    /// group additions through `ctSelect`. For a prover sharing a machine
    /// with someone it does not trust. ~21× slower: 34 s against 1.6 s at
    /// 10 000 constraints, one core, ReleaseFast (2026-10-09).
    constant_time,
};

pub const Options = struct {
    msm: Msm = .pippenger,
};

/// Proves `witness` against `z` with the default options — Pippenger MSM,
/// VARIABLE-TIME in the witness (see `Msm`); `proveWith(…, .{ .msm =
/// .constant_time })` when the prover's timing is observable. `rand` are the
/// zero-knowledge randomizers: draw both uniformly at random for every proof
/// (`Fr.random(io)`); reusing them across two proofs of different witnesses
/// leaks the witness difference.
///
/// `rand` is taken by pointer and never copied; the caller wipes it (and the
/// witness). The body runs one frame down and the stack it dirtied is zeroed
/// after it; the heap scratch (evaluations, the Pippenger limbs and buckets) is
/// wiped before it goes back to `allocator`.
pub fn prove(allocator: Allocator, z: ZKey, witness: []const Fr, rand: *const prover.Randomizers) ProveError!Proof {
    return proveWith(allocator, z, witness, rand, .{});
}

/// `prove` with a choice of MSM. Both choices give the same proof for the same
/// inputs.
pub fn proveWith(allocator: Allocator, z: ZKey, witness: []const Fr, rand: *const prover.Randomizers, opts: Options) ProveError!Proof {
    return burn.run(burn.zkprove_burn, ProveError!Proof, proveBody, .{ allocator, z, witness, rand, opts.msm });
}

fn msmG1(allocator: Allocator, kind: Msm, bases: []const G1.Affine, scalars: []const Fr) Allocator.Error!G1.Jacobian {
    return switch (kind) {
        .pippenger => msm.pippengerG1(allocator, bases, scalars),
        .constant_time => msm.msmG1(bases, scalars),
    };
}

fn msmG2(allocator: Allocator, kind: Msm, bases: []const G2.Affine, scalars: []const Fr) Allocator.Error!G2.Jacobian {
    return switch (kind) {
        .pippenger => msm.pippengerG2(allocator, bases, scalars),
        .constant_time => msm.msmG2(bases, scalars),
    };
}

fn proveBody(allocator: Allocator, z: ZKey, witness: []const Fr, rand: *const prover.Randomizers, kind: Msm) ProveError!Proof {
    if (witness.len != z.n_vars) return error.WitnessMismatch;
    const log_n = z.power();
    if (log_n + 1 > domain.max_log_size) return error.DomainTooLarge;
    const n: usize = z.domain_size;

    const evals = try allocator.alloc(Fr, 3 * n);
    defer {
        // Witness-derived: A·w, B·w on the domain and the quotient.
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(evals));
        allocator.free(evals);
    }
    @memset(evals, Fr.zero);
    const a = evals[0..n];
    const b = evals[n .. 2 * n];
    const c = evals[2 * n ..];

    // A·w and B·w at every domain point, then C = A·B there.
    for (z.coefs) |co| {
        const target = if (co.matrix == .a) a else b;
        target[co.constraint] = target[co.constraint].add(co.value.mul(witness[co.signal]));
    }
    for (a, b, c) |av, bv, *cv| cv.* = av.mul(bv);

    // Move all three onto the coset g·⟨ω⟩.
    const w = domain.rootOfUnity(log_n);
    const w_inv = w.inv() catch unreachable;
    const n_inv = (Fr.fromBytes(nBytes(n)) catch unreachable).inv() catch unreachable;
    const g = domain.rootOfUnity(log_n + 1);
    for ([_][]Fr{ a, b, c }) |v| {
        fft.ntt(v, w_inv);
        var gj = n_inv; // fold the inverse-NTT normalisation into the shift
        for (v) |*x| {
            x.* = x.mul(gj);
            gj = gj.mul(g);
        }
        fft.ntt(v, w);
    }
    for (a, b, c) |*av, bv, cv| av.* = av.mul(bv).sub(cv);
    const h = a;

    const r = rand.r;
    const s = rand.s;
    const delta1 = G1.Jacobian.fromAffine(z.delta_g1);

    var pi_a = G1.Jacobian.fromAffine(z.alpha_g1);
    pi_a = pi_a.add(try msmG1(allocator, kind, z.a, witness));
    pi_a = pi_a.add(delta1.scalarMul(r));

    var pi_b = G2.Jacobian.fromAffine(z.beta_g2);
    pi_b = pi_b.add(try msmG2(allocator, kind, z.b_g2, witness));
    pi_b = pi_b.add(G2.Jacobian.fromAffine(z.delta_g2).scalarMul(s));

    var b_in_g1 = G1.Jacobian.fromAffine(z.beta_g1);
    b_in_g1 = b_in_g1.add(try msmG1(allocator, kind, z.b_g1, witness));
    b_in_g1 = b_in_g1.add(delta1.scalarMul(s));

    var pi_c = try msmG1(allocator, kind, z.c, witness[z.n_public + 1 ..]);
    pi_c = pi_c.add(try msmG1(allocator, kind, z.h, h));
    pi_c = pi_c.add(pi_a.scalarMul(s));
    pi_c = pi_c.add(b_in_g1.scalarMul(r));
    pi_c = pi_c.add(delta1.scalarMul(r.mul(s)).negate());

    return .{ .a = pi_a.toAffine(), .b = pi_b.toAffine(), .c = pi_c.toAffine() };
}

fn nBytes(n: usize) [32]u8 {
    var out: [32]u8 = @splat(0);
    std.mem.writeInt(u64, out[24..32], n, .big);
    return out;
}
