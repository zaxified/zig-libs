// SPDX-License-Identifier: MIT
//! The Groth16 PROVER — `setup` (a test-only toy CRS/trusted setup) and
//! `prove` (the 3-element proof assembly `πA ∈ G1, πB ∈ G2, πC ∈ G1`). This
//! is the one part of the module the Phase-1 SCAFFOLD does NOT implement: both
//! functions are gated behind `gate.prover_core_implemented` and `@panic`
//! until the core lands. See `gate.zig` for why this is an **Opus** flag (the
//! sibling `bn254` Groth16 verifier is a complete deterministic anchor), not a
//! Fable one.
//!
//! What IS real here: `brokenProof`, a deliberately-wrong "prover" output used
//! as the harness's positive control — `bn254.groth16Verify` REJECTS it,
//! proving the end-to-end anchor has teeth before `prove` exists.
//!
//! ## Proof/key types
//!
//! The output proof type is the sibling verifier's own `bn254.Groth16Proof`
//! (`{a: G1, b: G2, c: G1}`), so `prove`'s result feeds straight into
//! `bn254.groth16Verify` — the anchor. The `VerifyingKey` is likewise
//! `bn254.Groth16VerifyingKey`. `ProvingKey` (the CRS the prover consumes) is
//! defined here.

const std = @import("std");
const bn254 = @import("bn254");
const gate = @import("gate.zig");
const field = @import("field.zig");
const poly = @import("poly.zig");
const fft = @import("fft.zig");
const domain = @import("domain.zig");
const msm = @import("msm.zig");
const r1cs = @import("r1cs.zig");
const Fr = field.Fr;

const G1 = bn254.G1;
const G2 = bn254.G2;

/// The verifier's proof type, re-exported — `prove` produces exactly this so
/// it can be handed to `bn254.groth16Verify` (the anchor).
pub const Proof = bn254.Groth16Proof;

/// The verifier's key type, re-exported — `setup` produces exactly this.
pub const VerifyingKey = bn254.Groth16VerifyingKey;

/// The Groth16 proving key (CRS) the prover consumes. Standard Groth-2016 /
/// snarkjs `.zkey` layout: precomputed group-element "query" vectors indexed
/// by witness variable, plus the `H(x)` bases. Populated by `setup` (gated)
/// or ingested from a snarkjs `.zkey` (a deferred Phase-3 increment — see
/// `SPEC.md`). All slices are borrowed; the prover never mutates them.
pub const ProvingKey = struct {
    alpha_g1: G1.Affine,
    beta_g1: G1.Affine,
    delta_g1: G1.Affine,
    beta_g2: G2.Affine,
    delta_g2: G2.Affine,
    /// `A_i(τ)·G` bases, one per witness variable.
    a_query: []const G1.Affine,
    /// `B_i(τ)·G` bases in `G1`, one per witness variable.
    b_g1_query: []const G1.Affine,
    /// `B_i(τ)·G` bases in `G2`, one per witness variable.
    b_g2_query: []const G2.Affine,
    /// The private-witness `C` bases `((β·A_i + α·B_i + C_i)/δ)·G`.
    l_query: []const G1.Affine,
    /// `H(x)` bases `(τ^i·Z(τ)/δ)·G`, `n−1` of them for a size-`n` domain.
    h_query: []const G1.Affine,
    /// Domain size `n` this CRS was generated for.
    domain_size: usize,
};

/// Zero-knowledge randomizers `r, s ∈ Fr` for a single proof. Distinct random
/// draws per proof; fixing them (as a test may) makes `prove` deterministic —
/// the hook for a future byte-exact snarkjs cross-check.
pub const Randomizers = struct { r: Fr, s: Fr };

/// The five secret field elements of a Groth16 trusted setup — the "toxic
/// waste". `tau` is the evaluation point, `alpha`/`beta` blind the A/B halves
/// of the proof, and `gamma`/`delta` are the public/private query divisors.
///
/// **INSECURE — TEST ONLY.** A real deployment NEVER materialises these five
/// scalars in one place: that is exactly the knowledge that lets a holder
/// forge proofs. They are produced (and provably discarded) by a distributed
/// multi-party MPC ceremony (e.g. Powers-of-Tau + a per-circuit Phase-2), so
/// no single party ever learns them. This struct hands `setup` all five in the
/// clear purely so the end-to-end anchor is self-contained and deterministic.
/// Replacing this with `.zkey` ingestion of a real ceremony's CRS is the
/// deferred Phase-3 increment (see `SPEC.md`).
///
/// Constraints: `gamma` and `delta` MUST be nonzero (they are inverted), and
/// `tau` MUST NOT be one of the domain's roots of unity (else `Z(tau)=0` and
/// the H-query degenerates). `setup` returns `error.DegenerateToxicWaste` for
/// a zero `gamma`/`delta`; a domain-point `tau` is a caller error the toy
/// setup does not defensively check (any small integer is safe).
pub const ToxicWaste = struct {
    tau: Fr,
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    delta: Fr,

    /// Securely wipe the toxic waste. Every field is secret (see this
    /// struct's doc comment — a real ceremony never materialises any of
    /// them together), fixed-size, no heap, so zeroing the struct's bytes
    /// erases all five. Call once `setup` has consumed `tw` to build the
    /// CRS. Idempotent — safe to call more than once.
    pub fn deinit(self: *ToxicWaste) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

/// A matched `(ProvingKey, VerifyingKey)` pair — the output of `setup`. The
/// key slices are heap-allocated with the allocator passed to `setup`; release
/// them with `freeKeyPair`.
pub const KeyPair = struct { pk: ProvingKey, vk: VerifyingKey };

/// Errors `setup` can return: allocation failure, or a degenerate toxic-waste
/// (`gamma` or `delta` zero, hence non-invertible).
pub const SetupError = std.mem.Allocator.Error || error{DegenerateToxicWaste};

/// Frees the heap-allocated key slices in a `KeyPair` returned by `setup`.
pub fn freeKeyPair(allocator: std.mem.Allocator, kp: KeyPair) void {
    allocator.free(kp.pk.a_query);
    allocator.free(kp.pk.b_g1_query);
    allocator.free(kp.pk.b_g2_query);
    allocator.free(kp.pk.l_query);
    allocator.free(kp.pk.h_query);
    allocator.free(kp.vk.ic);
}

// ── setup/prove internals ──────────────────────────────────────────────────

/// `[s]·G1` as an affine point (identity/infinity for `s == 0`).
fn g1Mul(s: Fr) G1.Affine {
    return G1.Jacobian.fromAffine(G1.Affine.generator).scalarMul(s).toAffine();
}

/// `[s]·G2` as an affine point (identity/infinity for `s == 0`).
fn g2Mul(s: Fr) G2.Affine {
    return G2.Jacobian.fromAffine(G2.Affine.generator).scalarMul(s).toAffine();
}

/// Which of the three R1CS matrices a column is drawn from.
const Matrix = enum { a, b, c };

/// Evaluates the per-wire QAP polynomial at `tau`: `col_i(tau)`, where `col_i`
/// is the polynomial interpolating (over `Domain(n)`) the `i`-th column of the
/// selected R1CS matrix — i.e. the coefficient of wire `i` in each
/// constraint's linear combination, sampled at the domain points. Constraints
/// beyond `sys.constraints.len` are the trivially-zero padding. Interpolation
/// is the anchored inverse NTT (`fft.intt`); the result is `poly.eval` at
/// `tau`. Allocation-free (stack `[n]Fr`).
fn columnEvalAtTau(comptime n: usize, sys: r1cs.System, which: Matrix, wire: usize, tau: Fr) Fr {
    var evals = [_]Fr{Fr.zero} ** n;
    for (sys.constraints, 0..) |con, j| {
        if (j >= n) break;
        const lc = switch (which) {
            .a => con.a,
            .b => con.b,
            .c => con.c,
        };
        for (lc) |t| {
            if (t.index == wire) evals[j] = evals[j].add(t.coeff);
        }
    }
    fft.intt(n, &evals);
    return poly.eval(&evals, tau);
}

/// Toy, INSECURE trusted setup (Opus core). Builds a Groth16 CRS for `sys`
/// over `Domain(n)` from the explicit toxic-waste `tw`, producing a matched
/// `ProvingKey`/`VerifyingKey` such that a proof from `prove` verifies under
/// `bn254.groth16Verify`. `num_public` is the number of public inputs (the
/// non-constant public wires): witness wires `0..=num_public` are public
/// (wire 0 is the constant `1`), the rest are private. `tw` is the toxic
/// waste — see `ToxicWaste`'s doc comment for why materialising it is
/// test-only-insecure and what a real ceremony does instead.
///
/// The CRS elements (Groth 2016 §3), all as `[scalar]·G` with the scalar
/// computed from the toxic waste:
///   - `alpha_g1 = α·G1`, `beta_{g1,g2} = β·G`, `delta_{g1,g2} = δ·G`,
///     `gamma_g2 = γ·G2`.
///   - `a_query[i]  = uᵢ(τ)·G1`  (A-column poly at τ, per wire)
///   - `b_g1_query[i] = vᵢ(τ)·G1`, `b_g2_query[i] = vᵢ(τ)·G2`
///   - public wire `i≤num_public`: `ic[i] = (β·uᵢ(τ)+α·vᵢ(τ)+wᵢ(τ))/γ·G1`
///   - private wire `i>num_public`: `l_query = (β·uᵢ(τ)+α·vᵢ(τ)+wᵢ(τ))/δ·G1`
///   - `h_query[j] = (τʲ·Z(τ)/δ)·G1`, `j = 0..n−2` (the `H(x)` bases)
///
/// Key slices are heap-allocated with `allocator`; free with `freeKeyPair`.
pub fn setup(
    comptime n: usize,
    allocator: std.mem.Allocator,
    sys: r1cs.System,
    num_public: usize,
    tw: ToxicWaste,
) SetupError!KeyPair {
    comptime std.debug.assert(gate.prover_core_implemented);
    std.debug.assert(sys.constraints.len <= n);
    std.debug.assert(num_public + 1 <= sys.num_vars);

    // `tw` arrives by value (a local copy already, independent of the
    // caller's own copy) and is never returned — only the `[scalar]·G`
    // group elements derived from it are. Wipe this local copy on every
    // exit once it's been fully consumed, on top of the caller's own
    // responsibility to `deinit()` theirs.
    var tw_local = tw;
    defer tw_local.deinit();

    const gamma_inv = tw_local.gamma.inv() catch return error.DegenerateToxicWaste;
    const delta_inv = tw_local.delta.inv() catch return error.DegenerateToxicWaste;

    const m = sys.num_vars; // wire count, including the constant wire 0
    const num_priv = m - num_public - 1;

    var a_query = try allocator.alloc(G1.Affine, m);
    errdefer allocator.free(a_query);
    var b_g1_query = try allocator.alloc(G1.Affine, m);
    errdefer allocator.free(b_g1_query);
    var b_g2_query = try allocator.alloc(G2.Affine, m);
    errdefer allocator.free(b_g2_query);
    var l_query = try allocator.alloc(G1.Affine, num_priv);
    errdefer allocator.free(l_query);
    var h_query = try allocator.alloc(G1.Affine, n - 1);
    errdefer allocator.free(h_query);
    var ic = try allocator.alloc(G1.Affine, num_public + 1);
    errdefer allocator.free(ic);

    for (0..m) |i| {
        const ui = columnEvalAtTau(n, sys, .a, i, tw_local.tau);
        const vi = columnEvalAtTau(n, sys, .b, i, tw_local.tau);
        const wi = columnEvalAtTau(n, sys, .c, i, tw_local.tau);
        a_query[i] = g1Mul(ui);
        b_g1_query[i] = g1Mul(vi);
        b_g2_query[i] = g2Mul(vi);
        // β·uᵢ(τ) + α·vᵢ(τ) + wᵢ(τ) — the combined public/private base.
        const combined = tw_local.beta.mul(ui).add(tw_local.alpha.mul(vi)).add(wi);
        if (i <= num_public) {
            ic[i] = g1Mul(combined.mul(gamma_inv));
        } else {
            l_query[i - num_public - 1] = g1Mul(combined.mul(delta_inv));
        }
    }

    // H-query bases (τʲ·Z(τ)/δ)·G1 for j = 0..n−2, where Z(τ) = τⁿ − 1.
    const z_tau = domain.Domain(n).vanishingEval(tw_local.tau);
    {
        var tau_pow = Fr.one;
        for (0..n - 1) |j| {
            h_query[j] = g1Mul(tau_pow.mul(z_tau).mul(delta_inv));
            tau_pow = tau_pow.mul(tw_local.tau);
        }
    }

    return .{
        .pk = .{
            .alpha_g1 = g1Mul(tw_local.alpha),
            .beta_g1 = g1Mul(tw_local.beta),
            .delta_g1 = g1Mul(tw_local.delta),
            .beta_g2 = g2Mul(tw_local.beta),
            .delta_g2 = g2Mul(tw_local.delta),
            .a_query = a_query,
            .b_g1_query = b_g1_query,
            .b_g2_query = b_g2_query,
            .l_query = l_query,
            .h_query = h_query,
            .domain_size = n,
        },
        .vk = .{
            .alpha_g1 = g1Mul(tw_local.alpha),
            .beta_g2 = g2Mul(tw_local.beta),
            .gamma_g2 = g2Mul(tw_local.gamma),
            .delta_g2 = g2Mul(tw_local.delta),
            .ic = ic,
        },
    };
}

/// Produces a Groth16 proof for `witness` under `pk` (Opus core). The result
/// is a `bn254.Groth16Proof` that `bn254.groth16Verify` accepts for the
/// matching `VerifyingKey` and public inputs `witness[1..=num_public]` — the
/// end-to-end anchor. `witness` must satisfy `sys` (else the QAP quotient is
/// inexact and the proof will not verify). `num_public` must match the value
/// `setup` was called with. `rand` are the zero-knowledge randomizers `r,s`.
///
/// Proof elements (Groth 2016 §3; `L=Σ wᵢuᵢ(τ)`, `R=Σ wᵢvᵢ(τ)`, `H` the QAP
/// quotient `(A·B−C)/Z`):
///   - `πA = (α + L + r·δ)·G1`      = `alpha_g1 + Σ wᵢ·a_query[i] + r·delta_g1`
///   - `πB = (β + R + s·δ)·G2`      = `beta_g2  + Σ wᵢ·b_g2_query[i] + s·delta_g2`
///   - `πC = Σ_{priv} wᵢ·l_query[i] + Σⱼ Hⱼ·h_query[j] + s·πA + r·πB_g1 − r·s·δ·G1`
///     where `πB_g1 = (β + R + s·δ)·G1` is `B` computed in `G1`.
pub fn prove(
    comptime n: usize,
    pk: ProvingKey,
    sys: r1cs.System,
    num_public: usize,
    witness: []const Fr,
    rand: Randomizers,
) Proof {
    comptime std.debug.assert(gate.prover_core_implemented);
    std.debug.assert(witness.len == sys.num_vars);
    std.debug.assert(pk.domain_size == n);
    std.debug.assert(pk.a_query.len == witness.len);

    // ── QAP quotient H(x) = (A(x)·B(x) − C(x)) / Z(x) ──────────────────────
    // Sample the aggregate A/B/C evaluations at the domain points from the
    // witness, interpolate (inverse NTT), multiply A·B via FFT, subtract C,
    // and divide by the vanishing polynomial — the same anchored stack the
    // `qap` divisibility oracle uses, but keeping the quotient coefficients.
    //
    // These evaluations/quotient coefficients are witness-derived scratch,
    // fully owned by this call (never aliased into the returned `Proof`, which
    // is built purely from the `pi_a`/`pi_b`/`pi_c` group elements below) — so
    // every one of them is wiped on exit, success or otherwise.
    var a_ev = [_]Fr{Fr.zero} ** n;
    var b_ev = [_]Fr{Fr.zero} ** n;
    var c_ev = [_]Fr{Fr.zero} ** n;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&a_ev));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&b_ev));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&c_ev));
    for (0..n) |j| {
        if (j < sys.constraints.len) {
            const e = sys.evalConstraint(j, witness);
            a_ev[j] = e.a;
            b_ev[j] = e.b;
            c_ev[j] = e.c;
        }
    }
    fft.intt(n, &a_ev);
    fft.intt(n, &b_ev);
    fft.intt(n, &c_ev);

    var ab = [_]Fr{Fr.zero} ** (2 * n - 1);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ab));
    fft.mulViaFFT(2 * n, &ab, &a_ev, &b_ev);
    var p = [_]Fr{Fr.zero} ** (2 * n - 1);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&p));
    poly.sub(&p, &ab, &c_ev);
    var h = [_]Fr{Fr.zero} ** (n - 1);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
    // Exact for a satisfying witness (the boolean is the satisfaction oracle);
    // for a non-satisfying one the quotient is bogus and the proof won't verify.
    _ = poly.divByVanishing(&h, &p, n);

    // ── proof assembly (MSM over the proving key) ──────────────────────────
    // πA = α·G1 + Σ wᵢ·uᵢ(τ)·G1 + r·δ·G1
    var pi_a = G1.Jacobian.fromAffine(pk.alpha_g1);
    pi_a = pi_a.add(msm.msmG1(pk.a_query, witness));
    pi_a = pi_a.add(G1.Jacobian.fromAffine(pk.delta_g1).scalarMul(rand.r));

    // πB = β·G2 + Σ wᵢ·vᵢ(τ)·G2 + s·δ·G2   (the proof's B, in G2)
    var pi_b = G2.Jacobian.fromAffine(pk.beta_g2);
    pi_b = pi_b.add(msm.msmG2(pk.b_g2_query, witness));
    pi_b = pi_b.add(G2.Jacobian.fromAffine(pk.delta_g2).scalarMul(rand.s));

    // πB_g1 = β·G1 + Σ wᵢ·vᵢ(τ)·G1 + s·δ·G1   (same exponent as πB, in G1 —
    // needed for the r·B term of πC, which lives in G1)
    var pi_b_g1 = G1.Jacobian.fromAffine(pk.beta_g1);
    pi_b_g1 = pi_b_g1.add(msm.msmG1(pk.b_g1_query, witness));
    pi_b_g1 = pi_b_g1.add(G1.Jacobian.fromAffine(pk.delta_g1).scalarMul(rand.s));

    // πC = Σ_{priv} wᵢ·l_query + Σⱼ Hⱼ·h_query + s·πA + r·πB_g1 − r·s·δ·G1
    const priv_witness = witness[num_public + 1 ..];
    var pi_c = msm.msmG1(pk.l_query, priv_witness);
    pi_c = pi_c.add(msm.msmG1(pk.h_query, &h));
    pi_c = pi_c.add(pi_a.scalarMul(rand.s));
    pi_c = pi_c.add(pi_b_g1.scalarMul(rand.r));
    const rs = rand.r.mul(rand.s);
    pi_c = pi_c.add(G1.Jacobian.fromAffine(pk.delta_g1).scalarMul(rs).negate());

    return .{
        .a = pi_a.toAffine(),
        .b = pi_b.toAffine(),
        .c = pi_c.toAffine(),
    };
}

/// REAL positive control: a deliberately-WRONG "proof" (the group generators,
/// which do not satisfy any real circuit's pairing equation), used to prove
/// the anchor rejects garbage. NOT a real prover — see the harness test.
pub fn brokenProof() Proof {
    return .{
        .a = G1.Affine.generator,
        .b = G2.Affine.generator,
        .c = G1.Affine.generator,
    };
}

/// REAL: a well-formed-but-bogus verifying key (generator points) for the
/// positive control. Not from any real setup — only used to show
/// `bn254.groth16Verify` returns `false` for a non-proof.
pub fn bogusVerifyingKey(ic: []const G1.Affine) VerifyingKey {
    return .{
        .alpha_g1 = G1.Affine.generator,
        .beta_g2 = G2.Affine.generator,
        .gamma_g2 = G2.Affine.generator,
        .delta_g2 = G2.Affine.generator,
        .ic = ic,
    };
}

// ── tests ────────────────────────────────────────────────────────────────

test "positive control: bn254 verifier REJECTS the broken proof (anchor has teeth)" {
    // A bogus vk with 2 IC points (1 public input) and the broken proof.
    const ic = [_]G1.Affine{ G1.Affine.generator, G1.Affine.generator };
    const vk = bogusVerifyingKey(&ic);
    const proof = brokenProof();
    const public = [_]Fr{field.frFromU64(1)};
    const ok = try bn254.groth16Verify(vk, proof, &public);
    try std.testing.expect(!ok); // MUST reject — the equation cannot hold
}

test "setup+prove+verify smoke: knowledge of a square root (1 public input)" {
    if (!gate.prover_core_implemented) return error.SkipZigTest;
    // Circuit: prove knowledge of private `x` with `x·x = out`, `out` public.
    // Witness layout puts the public wire first: w = [1, out, x] (num_public
    // = 1), constraint w[2]·w[2] = w[1].
    const alloc = std.testing.allocator;
    const cons = [_]r1cs.Constraint{.{
        .a = &[_]r1cs.Term{.{ .index = 2, .coeff = Fr.one }},
        .b = &[_]r1cs.Term{.{ .index = 2, .coeff = Fr.one }},
        .c = &[_]r1cs.Term{.{ .index = 1, .coeff = Fr.one }},
    }};
    const sys = r1cs.System{ .num_vars = 3, .constraints = &cons };
    const witness = [_]Fr{ Fr.one, field.frFromU64(25), field.frFromU64(5) };
    try std.testing.expect(sys.isSatisfied(&witness));

    const tw = ToxicWaste{
        .tau = field.frFromU64(7),
        .alpha = field.frFromU64(11),
        .beta = field.frFromU64(13),
        .gamma = field.frFromU64(17),
        .delta = field.frFromU64(19),
    };
    const kp = try setup(2, alloc, sys, 1, tw);
    defer freeKeyPair(alloc, kp);

    const proof = prove(2, kp.pk, sys, 1, &witness, .{
        .r = field.frFromU64(3),
        .s = field.frFromU64(4),
    });
    try std.testing.expect(try bn254.groth16Verify(kp.vk, proof, witness[1..2]));
}

test "setup rejects degenerate toxic waste (gamma or delta zero)" {
    if (!gate.prover_core_implemented) return error.SkipZigTest;
    const cons = r1cs.example.constraints();
    const sys = r1cs.example.system(&cons);
    const base = ToxicWaste{
        .tau = field.frFromU64(7),
        .alpha = field.frFromU64(11),
        .beta = field.frFromU64(13),
        .gamma = field.frFromU64(17),
        .delta = field.frFromU64(19),
    };
    var zero_gamma = base;
    zero_gamma.gamma = Fr.zero;
    try std.testing.expectError(error.DegenerateToxicWaste, setup(2, std.testing.allocator, sys, 1, zero_gamma));
    var zero_delta = base;
    zero_delta.delta = Fr.zero;
    try std.testing.expectError(error.DegenerateToxicWaste, setup(2, std.testing.allocator, sys, 1, zero_delta));
}

test "ToxicWaste.deinit zeroes all five secret scalars" {
    var tw = ToxicWaste{
        .tau = field.frFromU64(7),
        .alpha = field.frFromU64(11),
        .beta = field.frFromU64(13),
        .gamma = field.frFromU64(17),
        .delta = field.frFromU64(19),
    };
    try std.testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&tw), 0));
    tw.deinit();
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&tw), 0));
}
