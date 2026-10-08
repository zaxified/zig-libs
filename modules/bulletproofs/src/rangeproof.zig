// SPDX-License-Identifier: MIT

//! rangeproof — Bulletproofs §4.1 ("the range proof"): a proof that a
//! Pedersen-committed value `v` satisfies `v ∈ [0, 2^n)` — without
//! revealing `v` or its blinding factor `gamma` — given only the public
//! commitment `V = v*G + gamma*H`. Reduces, via the polynomial
//! construction below, to exactly one call into `ipa.zig`'s Inner-Product
//! Argument: this file is the OTHER Fable-hard core (the range-specific
//! polynomial construction/reduction), not the IPA itself.
//!
//! **THE FABLE CORE — implemented.** `prove`/`verify` below carry the
//! range-specific hard content. Everything ELSE — the
//! `RangeProof` struct, its byte codec, `commit` (the Pedersen value
//! commitment), `deltaYZ` (the verifier's `delta(y,z)` public-input scalar
//! term), and `prove`'s `error.ValueOutOfRange` construction-time guard —
//! is REAL, not stubbed.
//!
//! **Single and aggregated proofs.** `prove`/`verify` cover one value;
//! `proveMultiple`/`verifyMultiple` cover `m` values (a power of two) in
//! one proof whose size grows with `log2(n*m)` (paper §4.3). The single
//! case IS the aggregated one with `m = 1` — one body, so the two cannot
//! drift. The steps below are written for `m = 1`; "Aggregation" after
//! them lists what changes for `m > 1`.
//!
//! ## Protocol (§4.1, single-value case)
//!
//! Public: `V` (the commitment), `n` (bit width, e.g. 64), `gens:
//! Generators` sized for `n` (`generators.zig`).
//! Prover's secret witness: `v` (`0 <= v < 2^n`), `gamma` (`V`'s blinding
//! factor, i.e. `V = commit(gens, v, gamma)`).
//!
//! 1. **Bit decomposition.** `a_L ∈ {0,1}^n`: the binary digits of `v`
//!    (pick ONE bit order — LSB-first or MSB-first — and use it
//!    consistently so `<a_L, 2^n> = v` holds, where `2^n` here means the
//!    vector `[2^0, 2^1, ..., 2^{n-1}]`, NOT the scalar `2^n`).
//!    `a_R = a_L - 1^n` (elementwise; each entry is `0` or `-1 mod L`).
//!    This encodes three facts the rest of the protocol turns into ONE
//!    random linear combination: `a_L` is 0/1-valued, `a_L . a_R = 0`
//!    (Hadamard product is the all-zero vector — provable since `a_L_i`
//!    is 0 or 1 forces `a_L_i * a_R_i = a_L_i*(a_L_i - 1) = 0`), and
//!    `<a_L, 2^n> = v` (by construction). See the paper §4.1 for the full
//!    derivation of why these three facts, folded via the `y`/`z`
//!    challenges below, prove `v` is a valid `n`-bit value.
//! 2. **Blind + commit `A`.** Sample secret `alpha` (random scalar).
//!    `A = alpha*gens.h + <a_L, gens.g_vec> + <a_R, gens.h_vec>`
//!    (`scalarvec.multiScalarMul` twice, summed with `alpha*gens.h`).
//! 3. **Blinding vectors + commit `S`.** Sample secret `s_L`, `s_R`
//!    (random length-`n` vectors) and secret `rho` (random scalar).
//!    `S = rho*gens.h + <s_L, gens.g_vec> + <s_R, gens.h_vec>`.
//! 4. **Transcript + challenges `y`, `z`.** `appendDomainSep(transcript,
//!    n)` (dalek's `rangeproof_domain_sep`: `"rangeproof v1"`, `n`, `m = 1`),
//!    then `transcript.appendPoint("V", V);` (binding the public commitment — do this once, before `A`/`S`,
//!    so `y`/`z` also depend on WHICH value is being proven, not just the
//!    proof shape); `transcript.appendPoint("A", A);
//!    transcript.appendPoint("S", S);` then `y =
//!    transcript.challengeScalar("y"); z = transcript.challengeScalar
//!    ("z");`.
//! 5. **Polynomials `l(x)`, `r(x)`** (paper eq. (63)-(64)): vector-valued
//!    degree-1 polynomials in a NEW formal variable `x` (bound via a
//!    THIRD challenge below, not `y`/`z`):
//!    ```text
//!    l(x) = a_L - z*1^n + s_L*x
//!    r(x) = y^n . (a_R + z*1^n + s_R*x) + z^2 * 2^n
//!    ```
//!    (`y^n = scalarvec.powers(y, n)`; `2^n = [1,2,4,...,2^{n-1}]`, e.g.
//!    also `scalarvec.powers(two, n)`; `.` = Hadamard product; all via
//!    `scalarvec` ops). `t(x) = <l(x), r(x)>` is then a degree-2 SCALAR
//!    polynomial `t0 + t1*x + t2*x^2`. `t0` is never needed directly
//!    (the verifier reconstructs it from `V`/`z`/`deltaYZ`, see below);
//!    `t1`/`t2` have closed forms in terms of the vectors above (paper
//!    eq. (61)) but MAY instead be obtained by evaluating `l(1)`/`r(1)`
//!    and `l(-1)`/`r(-1)` (or any two convenient sample points) and
//!    interpolating — simpler to get right, no less sound, at the cost of
//!    a couple of extra inner products.
//! 6. **Commit `T1`, `T2`.** Sample secret `tau1`, `tau2` (random
//!    scalars). `T1 = t1*gens.g + tau1*gens.h`, `T2 = t2*gens.g +
//!    tau2*gens.h` (`gens.g`/`gens.h` — the SAME base points `V` itself
//!    was committed under, NOT `g_vec`/`h_vec`).
//! 7. **Transcript + challenge `x`.** `transcript.appendPoint("T_1", T1);
//!    transcript.appendPoint("T_2", T2); const x =
//!    transcript.challengeScalar("x");`.
//! 8. **Evaluate + response scalars.**
//!    ```text
//!    l_vec = l(x); r_vec = r(x)          // concrete length-n vectors
//!    t_hat = <l_vec, r_vec>              // must equal t0 + t1*x + t2*x^2
//!                                        // by construction, not merely
//!                                        // "should" -- a correct prover
//!                                        // MAY self-check this in debug
//!                                        // builds (bip340.sign's
//!                                        // self-verify philosophy)
//!    tau_x = tau2*x^2 + tau1*x + z^2*gamma
//!    mu    = alpha + rho*x
//!    ```
//! 9. **The IPA reduction.** The verifier's final check needs a single
//!    point `P` with `P = <l_vec, gens.g_vec> + <r_vec, h_vec_prime> +
//!    t_hat*q` for a suitably chosen `q` and a per-index-RESCALED
//!    `h_vec_prime_i = gens.h_vec_i` raised to `y^{-i}` (paper §4.2's
//!    optimization, folding the `y^n` Hadamard factor out of `r(x)`'s
//!    definition into a generator rescaling instead — an implementer MAY
//!    instead fold `y^{-n}` into `r_vec` directly before calling the IPA
//!    with UNSCALED `h_vec`, which is mathematically equivalent and
//!    simpler to implement first). `q` is itself transcript-derived:
//!    `transcript.appendScalar("t_x", t_hat); transcript.appendScalar
//!    ("t_x_blinding", tau_x); transcript.appendScalar("e_blinding", mu);
//!    const w =
//!    transcript.challengeScalar("w"); const q = gens.g.mul(w)` (paper
//!    §4.2's trick for binding the IPA to THIS proof instance, so an IPA
//!    proof crafted for a different `t_hat` cannot be replayed here).
//!    Call `ipa.proveIpa(allocator, transcript, gens.g_vec, h_vec_prime,
//!    q, l_vec, r_vec)`.
//! 10. `RangeProof{ a = A, s = S, t1 = T1, t2 = T2, tau_x, mu, t_hat, ipa
//!     }`.
//!
//! ## Verifier (`verify`)
//!
//! Replays steps 4/7/9's transcript operations from the PROOF's own `A`/
//! `S`/`T1`/`T2`/`tau_x`/`mu`/`t_hat` fields (and the public `V`) to
//! recover the SAME `y`, `z`, `x`, `w` the prover derived — binding
//! `A`/`S`/`T1`/`T2` and the IPA's `L`/`R` with `validateAndAppendPoint`,
//! which refuses the identity as dalek's verifier does — then checks TWO
//! equations (dalek folds both into one random linear combination; the
//! verdict is the same):
//!
//! - **The `t_hat` relation** (paper eq. (72)):
//!   ```text
//!   t_hat*gens.g + tau_x*gens.h
//!     == V.mul(z^2) + deltaYZ(y,z,n)*gens.g + T1.mul(x) + T2.mul(x^2)
//!   ```
//!   (`deltaYZ` below is REAL — pure public-input scalar arithmetic, no
//!   witness involved.)
//! - **The IPA** (paper eq. (66)-(67)): reconstruct
//!   ```text
//!   P = A + S.mul(x) - <z*1^n, gens.g_vec> + <(z*y^n + z^2*2^n), h_vec_prime>
//!   ```
//!   (the point the IPA's `p` argument must equal — folding in `A`/`S`/`x`
//!   and the SAME `z`/`y^n`/`2^n` terms the prover's `l`/`r` polynomials
//!   encode; see paper eq. (67) for the exact derivation) and call
//!   `ipa.verifyIpa(transcript, gens.g_vec, h_vec_prime, q, p,
//!   proof.ipa)`.
//!
//! Accept iff BOTH checks pass; reject (return `false`) on either
//! failure, or on a structural mismatch (`proof`'s implied `n` — from
//! `proof.ipa.l_vec.len` — not matching `gens.n`'s `log2`) — a correct
//! FINAL implementation never panics on adversarial input.
//!
//! ## Aggregation (§4.3, `m` values)
//!
//! Vectors are `n*m` long; value `j` owns positions `j*n .. (j+1)*n` and
//! the generators of party `j` (`Generators.initParties`). Changes against
//! the steps above, in dalek's order and labels:
//!
//! - step 4 binds `m` in the domain separator and appends every `V_j`, in
//!   order, before `A`;
//! - `r(x)`'s constant term at position `j*n + i` uses `z^{2+j} * 2^i`
//!   instead of `z^2 * 2^i` (`y` powers run over all `n*m` positions);
//! - `tau_x = tau2*x^2 + tau1*x + sum_j z^{2+j} * gamma_j`;
//! - the verifier's `t_hat` relation has `sum_j z^{2+j} * V_j` in place of
//!   `z^2 * V`, `delta` sums `y` over `n*m` positions and subtracts
//!   `z^3 * (2^n - 1) * sum_j z^j`, and `P`'s `H_i` coefficient uses the
//!   same `z^{2+j} * 2^i`.
//!
//! One prover holds every witness (dalek's dealer and parties collapsed
//! into one call). Splitting the prover across parties that do not trust
//! each other is dalek's MPC API and is not offered here.
//!
//! Provenance: Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell,
//! "Bulletproofs: Short Proofs for Confidential Transactions and More",
//! IEEE S&P 2018 (eprint.iacr.org/2017/1066), §4.1/§4.2.
//!
//! ## Wire compatibility with dalek
//!
//! The transcript (Merlin, `transcript.zig`), its labels and order, the
//! generators (`generators.zig`) and the byte layout (`RangeProof.
//! toBytesAlloc`) are dalek-cryptography/bulletproofs 4.0's (MIT), read from
//! its `src/range_proof/mod.rs`, `src/inner_product_proof.rs`,
//! `src/transcript.rs` and `src/generators.rs`; the algebra was already the
//! paper's. A proof made here verifies under dalek's
//! `RangeProof::verify_single` and the reverse, given the same transcript
//! label and `n` in {8, 16, 32, 64} (dalek refuses other widths) —
//! `interop_test.zig` asserts both directions, for single proofs
//! (`verify_single`) and aggregated ones (`verify_multiple`). See NOTICE.

const std = @import("std");
const builtin = @import("builtin");
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;
const generators_mod = @import("generators.zig");
const Generators = generators_mod.Generators;
const transcript_mod = @import("transcript.zig");
const Transcript = transcript_mod.Transcript;
const scalarvec = @import("scalarvec.zig");
const ipa = @import("ipa.zig");
const InnerProductProof = ipa.InnerProductProof;

/// The label a caller starts a fresh `Transcript` with for `prove`/
/// `verify` (step 4's `transcript.appendPoint("V", ...)` onward reuses
/// this same transcript for the rest of the protocol, including the IPA
/// sub-step — see the module doc comment's step 9).
pub const transcript_domain = "bulletproofs/range-proof/v1";

/// dalek's `rangeproof_domain_sep(n, m)` with `m = 1` (a single-value
/// proof). Both `prove` and `verify` call it first, before `V`.
pub fn appendDomainSep(transcript: *Transcript, n: usize) void {
    appendDomainSepMultiple(transcript, n, 1);
}

/// dalek's `rangeproof_domain_sep(n, m)`: an aggregated proof over `m`
/// values binds `m` before the first `V_j`.
pub fn appendDomainSepMultiple(transcript: *Transcript, n: usize, m: usize) void {
    transcript.appendMessage("dom-sep", "rangeproof v1");
    transcript.appendU64("n", n);
    transcript.appendU64("m", m);
}

/// `v*gens.g + gamma*gens.h` — Bulletproofs' Pedersen VALUE commitment
/// (distinct from the vector Pedersen commitments `A`/`S`/`T1`/`T2` a
/// `RangeProof` itself carries). REAL — two scalar multiplications and a
/// point add, no ZK judgment. `v == 0` or `gamma == 0` correctly yields
/// (respectively) `gamma*gens.h`/`v*gens.g`/the identity. Both the
/// committed value and the blinding factor are SECRET, so both
/// multiplications go through the branch-free `scalarvec.mulCt` (which
/// returns the identity as a VALUE) rather than `Ristretto255.mul`, whose
/// `error.IdentityElement` would make the commitment's timing depend on
/// whether `v`/`gamma` was zero — audit finding F2.
pub fn commit(gens: Generators, v: [32]u8, gamma: [32]u8) Ristretto255 {
    const vg = scalarvec.mulCt(gens.g, v);
    const gh = scalarvec.mulCt(gens.h, gamma);
    return vg.add(gh);
}

/// `p*s` via the branch-free constant-time ladder `scalarvec.mulCt`, which
/// returns the identity element as a VALUE where `Ristretto255.mul` would
/// raise `error.IdentityElement` (i.e. when `s == 0 mod L`) — no `catch`,
/// hence no secret-dependent branch on the prove path (audit finding F2).
fn mulOrIdentity(p: Ristretto255, s: [32]u8) Ristretto255 {
    return scalarvec.mulCt(p, s);
}

/// `s^{-1} (mod L)`; `invert(0) == 0` (std's documented behavior), so a
/// (negligible-probability) zero `y` challenge cannot crash either side —
/// it merely yields a proof that does not verify.
fn invertScalar(s: [32]u8) [32]u8 {
    const inv = scalar.Scalar.fromBytes(s).invert();
    return inv.toBytes();
}

/// A uniformly random scalar in `[0, L)` for the prover's secret blinding
/// material (`alpha`, `rho`, `s_L`, `s_R`, `tau1`, `tau2`): 64 bytes of
/// `io.randomSecure`, wide-reduced — the same uniform reduction
/// `transcript.challengeScalar` uses (RFC 8032's scalar-reduction
/// convention). `randomSecure` asks the OS every time and has no fallback,
/// so a failure is an error, never a weaker source: a range proof made with
/// predictable blinding leaks the witness. (Until 2026-10-02 this was a
/// direct Linux `getrandom(2)` and a compile error on every other target.)
fn randomScalar(io: std.Io) error{ EntropyUnavailable, Canceled }![32]u8 {
    var wide: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &wide);
    try io.randomSecure(&wide);
    const out = scalar.reduce64(wide);
    if (builtin.is_test and test_random_count < test_randoms.len) {
        test_randoms[test_random_count] = out;
        test_random_count += 1;
    }
    return out;
}

/// Test builds only: every scalar `randomScalar` returned since the last
/// reset, so `stackprobe_test.zig` can look for the prover's random blinding
/// secrets on the dead stack too — they are drawn from the OS and no test
/// could know them otherwise. Zero-length and never written outside
/// `zig build test`.
pub var test_randoms: [if (builtin.is_test) 512 else 0][32]u8 = undefined;
pub var test_random_count: usize = 0;

/// `delta(y,z)` — Bulletproofs §4.1's verifier-side scalar correction
/// term (paper eq. (39), single-value case; `deltaYZMultiple` is the
/// aggregated one):
///
/// ```text
/// delta(y,z) = (z - z^2) * sum_{i=0}^{n-1} y^i  -  z^3 * (2^n - 1)
/// ```
///
/// Pure public-input scalar arithmetic — `y`, `z`, `n` are all public (no
/// witness touches this function). REAL, not a stub; independently
/// exercised in this file's test block against a hand-derived formula for
/// small `n` computed via a DIFFERENT method (direct repeated doubling /
/// multiplication rather than `scalarvec.powers`), to avoid the test
/// simply re-deriving the implementation.
pub fn deltaYZ(allocator: std.mem.Allocator, y: [32]u8, z: [32]u8, n: usize) std.mem.Allocator.Error![32]u8 {
    return deltaYZMultiple(allocator, y, z, n, 1);
}

/// `delta(y,z)` for an aggregated proof over `m` values (paper §4.3, dalek's
/// `delta(n, m, y, z)`):
///
/// ```text
/// delta(y,z) = (z - z^2) * sum_{i=0}^{n*m-1} y^i
///              - z^3 * (2^n - 1) * sum_{j=0}^{m-1} z^j
/// ```
///
/// `m = 1` is `deltaYZ`.
pub fn deltaYZMultiple(allocator: std.mem.Allocator, y: [32]u8, z: [32]u8, n: usize, m: usize) std.mem.Allocator.Error![32]u8 {
    const nm = std.math.mul(usize, n, m) catch return error.OutOfMemory;
    const y_pows = try scalarvec.powers(allocator, y, nm);
    defer allocator.free(y_pows);
    var sum_y = scalarvec.zero;
    for (y_pows) |yp| sum_y = scalar.add(sum_y, yp);

    var sum_z = scalarvec.zero;
    {
        var z_pow = scalarvec.one;
        for (0..m) |_| {
            sum_z = scalar.add(sum_z, z_pow);
            z_pow = scalar.mul(z_pow, z);
        }
    }

    // 2^n - 1 via repeated doubling — exact (no modular wraparound) for
    // any n a real range proof would use (n <= a few hundred keeps
    // 2^n well under the ~2^252 scalar field order).
    var two_pow_n = scalarvec.one;
    var i: usize = 0;
    while (i < n) : (i += 1) two_pow_n = scalar.add(two_pow_n, two_pow_n);
    const sum_2n = scalar.sub(two_pow_n, scalarvec.one);

    const z2 = scalar.mul(z, z);
    const z3 = scalar.mul(z2, z);
    const z_minus_z2 = scalar.sub(z, z2);

    const term1 = scalar.mul(z_minus_z2, sum_y);
    const term2 = scalar.mul(scalar.mul(z3, sum_2n), sum_z);
    return scalar.sub(term1, term2);
}

/// A completed single-value Bulletproofs range proof (§4.1).
pub const RangeProof = struct {
    a: Ristretto255,
    s: Ristretto255,
    t1: Ristretto255,
    t2: Ristretto255,
    tau_x: [32]u8,
    mu: [32]u8,
    t_hat: [32]u8,
    ipa: InnerProductProof,

    pub fn deinit(self: RangeProof, allocator: std.mem.Allocator) void {
        self.ipa.deinit(allocator);
    }

    /// `A(32) || S(32) || T1(32) || T2(32) || t_hat(32) || tau_x(32) ||
    /// mu(32) || <ipa.toBytesAlloc() bytes>` — dalek's
    /// `RangeProof::to_bytes` (there `t_x`, `t_x_blinding`, `e_blinding`).
    /// The IPA tail's round count is implied by the remaining length.
    pub fn toBytesAlloc(self: RangeProof, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const ipa_bytes = try self.ipa.toBytesAlloc(allocator);
        defer allocator.free(ipa_bytes);
        const fixed_len = 32 * 7;
        const out = try allocator.alloc(u8, fixed_len + ipa_bytes.len);
        var off: usize = 0;
        out[off..][0..32].* = self.a.toBytes();
        off += 32;
        out[off..][0..32].* = self.s.toBytes();
        off += 32;
        out[off..][0..32].* = self.t1.toBytes();
        off += 32;
        out[off..][0..32].* = self.t2.toBytes();
        off += 32;
        out[off..][0..32].* = self.t_hat;
        off += 32;
        out[off..][0..32].* = self.tau_x;
        off += 32;
        out[off..][0..32].* = self.mu;
        off += 32;
        @memcpy(out[off..], ipa_bytes);
        return out;
    }

    pub const FromBytesError = error{ InvalidEncoding, OutOfMemory };

    /// Inverse of `toBytesAlloc`.
    pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) FromBytesError!RangeProof {
        const fixed_len = 32 * 7;
        if (bytes.len < fixed_len) return error.InvalidEncoding;
        var off: usize = 0;
        const a = Ristretto255.fromBytes(bytes[off..][0..32].*) catch return error.InvalidEncoding;
        off += 32;
        const s = Ristretto255.fromBytes(bytes[off..][0..32].*) catch return error.InvalidEncoding;
        off += 32;
        const t1 = Ristretto255.fromBytes(bytes[off..][0..32].*) catch return error.InvalidEncoding;
        off += 32;
        const t2 = Ristretto255.fromBytes(bytes[off..][0..32].*) catch return error.InvalidEncoding;
        off += 32;
        // Audit finding B1's defense-in-depth half: these three scalars ARE
        // bound into the transcript (see `verify`'s replay below), so a
        // non-canonical re-encoding of one of them changes the derived
        // Fiat-Shamir challenges and a forged proof build atop it would not
        // verify -- unlike `ipa.zig`'s `a`/`b`, this path was not a live
        // malleability finding. Rejecting non-canonical bytes here anyway
        // keeps every raw scalar field in this module's two codecs held to
        // the same canonical-encoding standard as the point fields next to
        // them, rather than only the ones a live exploit was found for.
        const t_hat = bytes[off..][0..32].*;
        scalar.rejectNonCanonical(t_hat) catch return error.InvalidEncoding;
        off += 32;
        const tau_x = bytes[off..][0..32].*;
        scalar.rejectNonCanonical(tau_x) catch return error.InvalidEncoding;
        off += 32;
        const mu = bytes[off..][0..32].*;
        scalar.rejectNonCanonical(mu) catch return error.InvalidEncoding;
        off += 32;
        const ipa_proof = InnerProductProof.fromBytesAlloc(allocator, bytes[off..]) catch return error.InvalidEncoding;
        return .{ .a = a, .s = s, .t1 = t1, .t2 = t2, .tau_x = tau_x, .mu = mu, .t_hat = t_hat, .ipa = ipa_proof };
    }
};

pub const ProveError = error{
    /// `v >= 2^gens.n` — checked BEFORE any commitment is built (REAL,
    /// mechanical; never reaches the stub body below).
    ValueOutOfRange,
    OutOfMemory,
    /// `io.randomSecure` could not deliver: no proof is made rather than one
    /// with weak blinding. The transcript has been written to and must be
    /// discarded.
    EntropyUnavailable,
    /// The `Io` operation was canceled (same transcript caveat).
    Canceled,
};

/// **FABLE CORE — implemented.** See the module doc comment for the full
/// 10-step construction. `v`'s range guard is checked first — see
/// `ProveError.ValueOutOfRange`'s doc comment.
///
/// `v` is taken **by pointer** (audit finding B12): a `u64` witness passed
/// by value leaves an uncleared copy in the caller's argument-passing slot
/// that this function has no way to reach, even though every other secret
/// derived from it (`v_bytes`, the bit-decomposition vectors) is
/// `secureZero`'d before return. Taking `*const u64` means the only copy is
/// the caller's own storage, which the caller controls. (this scaffold does
/// not support `n > 64` — every realistic Bulletproofs range width,
/// 8/16/32/64, fits; a wider-`v` variant would need a bignum witness type
/// and is out of scope here, see SPEC.md).
///
/// Zeroes the stack its computation used before returning, on the error
/// path too (audit finding B12, see `burnStack`).
///
/// `io` supplies the blinding randomness (`io.randomSecure`, any target).
pub fn prove(
    allocator: std.mem.Allocator,
    io: std.Io,
    gens: Generators,
    transcript: *Transcript,
    v: *const u64,
    gamma: [32]u8,
) ProveError!RangeProof {
    const result = proveInner(allocator, io, gens, transcript, v[0..1], @as(*const [1][32]u8, &gamma));
    burnStack();
    return result catch |err| switch (err) {
        error.ValueOutOfRange => return error.ValueOutOfRange,
        error.OutOfMemory => return error.OutOfMemory,
        error.EntropyUnavailable => return error.EntropyUnavailable,
        error.Canceled => return error.Canceled,
        // One value, and every Generators set holds at least one party.
        error.InvalidAggregation => unreachable,
    };
}

pub const ProveMultipleError = ProveError || error{
    /// `values` is empty or not a power of two long, `gammas` is not as
    /// long as `values`, or `gens` was built for fewer parties
    /// (`Generators.initParties`) than there are values.
    InvalidAggregation,
};

/// An aggregated range proof (paper §4.3): every `values[j]` is in
/// `[0, 2^gens.n)`, against `V_j = commit(gens, values[j], gammas[j])`,
/// in one proof — dalek's `RangeProof::prove_multiple`. The verifier needs
/// the commitments in the same order (`verifyMultiple`). `values` is read
/// in place, never copied by value (see `prove`'s note on audit finding
/// B12); the stack is zeroed before returning, as in `prove`.
pub fn proveMultiple(
    allocator: std.mem.Allocator,
    io: std.Io,
    gens: Generators,
    transcript: *Transcript,
    values: []const u64,
    gammas: []const [32]u8,
) ProveMultipleError!RangeProof {
    const result = proveInner(allocator, io, gens, transcript, values, gammas);
    burnStack();
    return result;
}

/// How much stack below `prove`'s frame is zeroed after the proof is built.
///
/// Audit finding B12. `secureZero` on named locals (`v_val`, `v_bytes`, the
/// arena vectors) cannot reach the copies the optimizer and callees leave in
/// dead frames. Measured at ReleaseFast with `stackprobe_test.zig`'s method
/// after `prove(n=64)` returned: on the audited tree `v_bytes` ×1; on the
/// tree before this burn `v_bytes` ×1, `z²·γ` ×1 (with the public `z` that is
/// γ, and with `V` it is `v`) and 6 of the 132 random blinding scalars —
/// `alpha`/`rho`/`tau1`/`tau2` with the public `mu`/`tau_x` give γ too. So the
/// fix is on the region: the computation runs one frame down and this many
/// bytes at that depth are zeroed before `prove` returns.
///
/// Sized from the probe's dirty depth: the call tree reaches 46 856 B for
/// every `n` from 8 to 128 (a fixed-size frame, not one that grows with
/// `n`), and 128 KiB covers it about 2.7 times. The probe asserts zero
/// residue, so a call tree that outgrows the burn goes red there.
const prove_stack_burn = 128 * 1024;

/// Zero `prove_stack_burn` bytes at the depth `proveInner`'s frames
/// occupied. `noinline` here is load-bearing, measured: made `inline`, this
/// buffer lands in the caller's frame, above the region the proof used, and
/// the probe finds blinding scalars again. Volatile stores keep the dead store.
noinline fn burnStack() void {
    // Volatile 32-byte vector stores: `secureZero` is a volatile byte memset
    // (~3 B/ns without libc, 2.5 µs per 8 KiB); this is ~100 B/ns (2026-10-08).
    const V = @Vector(4, u64);
    var buf: [prove_stack_burn / @sizeOf(V)]V = undefined;
    const p: [*]volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

/// Steps 1-10 of `prove`, for `m = values.len` values ("Aggregation" in the
/// module doc comment; `m = 1` is the single-value proof). `noinline` is a
/// guard, not a measured necessity: dropping it left the probe green (the
/// compiler does not inline a function this large today).
noinline fn proveInner(
    allocator: std.mem.Allocator,
    io: std.Io,
    gens: Generators,
    transcript: *Transcript,
    values: []const u64,
    gammas: []const [32]u8,
) ProveMultipleError!RangeProof {
    const m = values.len;
    if (m == 0 or !std.math.isPowerOfTwo(m) or gammas.len != m or m > gens.parties)
        return error.InvalidAggregation;
    if (gens.n < 64) {
        // One branch for the whole batch, not one per value: an early
        // return would time WHICH value was out of range.
        const limit = @as(u64, 1) << @intCast(gens.n);
        var out_of_range: u1 = 0;
        for (values) |v| out_of_range |= @intFromBool(v >= limit);
        if (out_of_range != 0) return error.ValueOutOfRange;
    }

    // Each secret witness is read through the slice exactly once, into
    // this local, which is cleaned up. Repeatedly dereferencing the caller's
    // value across the bit-decomposition loop gave the optimizer room to
    // spill it to its own uncontrolled stack slot (measured:
    // `stackprobe_test.zig`'s B12 probe found 1 copy with `v` taken by
    // pointer but dereferenced in the loop).
    var v_val: u64 = 0;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&v_val));

    const n = gens.n;
    // The IPA reduction needs a nonzero power-of-two length. A Generators
    // set is caller-constructed (non-adversarial) input, so this is a
    // contract assertion, not an error variant (mirrors proveIpa's own
    // unreachable below). `m` is a power of two (checked above), so `n*m`
    // is one too.
    std.debug.assert(n != 0 and std.math.isPowerOfTwo(n));
    const nm = n * m;
    std.debug.assert(gens.g_vec.len >= nm and gens.h_vec.len >= nm);
    const g_vec = gens.g_vec[0..nm];
    const h_vec = gens.h_vec[0..nm];

    // Every internal vector lives in one arena (freed on all paths); the
    // witness-bearing ones get a best-effort secureZero before the arena
    // releases them. The IPA sub-proof is allocated from `allocator`
    // directly since it outlives this call (freed by RangeProof.deinit).
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const scratch = arena_state.allocator();

    // 1. Bit decomposition, LSB-first per value: <a_L[j*n..], [2^0,...,
    //    2^{n-1}]> == values[j]. a_R = a_L - 1^{nm} elementwise. Branchless
    //    bit extract (the values are secret); bit positions >= 64 are
    //    structurally zero (u64 witness).
    const a_l = try scratch.alloc([32]u8, nm);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(a_l));
    const a_r = try scratch.alloc([32]u8, nm);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(a_r));
    for (0..m) |j| {
        v_val = values[j];
        for (a_l[j * n ..][0..n], a_r[j * n ..][0..n], 0..) |*al, *ar, i| {
            const bit: u8 = if (i < 64) @truncate((v_val >> @intCast(i)) & 1) else 0;
            al.* = scalarvec.zero;
            al.*[0] = bit;
            ar.* = scalar.sub(al.*, scalarvec.one);
        }
    }

    // 2. A = alpha*H + <a_L, G_vec> + <a_R, H_vec>. All lengths are nm by
    //    construction — LengthMismatch is unreachable throughout.
    const alpha = try randomScalar(io);
    const a_commit = mulOrIdentity(gens.h, alpha)
        .add(scalarvec.multiScalarMul(a_l, g_vec) catch unreachable)
        .add(scalarvec.multiScalarMul(a_r, h_vec) catch unreachable);

    // 3. S = rho*H + <s_L, G_vec> + <s_R, H_vec>, s_L/s_R fresh random.
    const s_l = try scratch.alloc([32]u8, nm);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(s_l));
    const s_r = try scratch.alloc([32]u8, nm);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(s_r));
    for (s_l, s_r) |*sl, *sr| {
        sl.* = try randomScalar(io);
        sr.* = try randomScalar(io);
    }
    const rho = try randomScalar(io);
    const s_commit = mulOrIdentity(gens.h, rho)
        .add(scalarvec.multiScalarMul(s_l, g_vec) catch unreachable)
        .add(scalarvec.multiScalarMul(s_r, h_vec) catch unreachable);

    // 4. Bind n and m (audit finding B10: the bit-width was documented as an
    //    `appendU64` use case but never actually bound -- `transcript.zig`'s
    //    doc comment named it as an example and nothing called it; adding
    //    this wires the doc comment's own claim into the real protocol as
    //    defense-in-depth. No exploit was found without it (the round count
    //    is already checked structurally in `verify`, and the generator set
    //    is a deterministic function of `n`), but the module has no
    //    consumer in this repo, so no proof anywhere depends on the exact
    //    challenge derivation this changes. Then bind every V_j (recomputed
    //    from the witness — the points the verifier is handed), then A/S;
    //    draw y, z.
    appendDomainSepMultiple(transcript, n, m);
    var v_bytes = scalarvec.zero;
    defer std.crypto.secureZero(u8, &v_bytes);
    for (0..m) |j| {
        v_val = values[j];
        std.mem.writeInt(u64, v_bytes[0..8], v_val, .little);
        transcript.appendPoint("V", commit(gens, v_bytes, gammas[j]));
    }
    transcript.appendPoint("A", a_commit);
    transcript.appendPoint("S", s_commit);
    const y = transcript.challengeScalar("y");
    const z = transcript.challengeScalar("z");

    // 5. l(X) = l0 + l1*X, r(X) = r0 + r1*X (paper eq. (63)-(64); §4.3 for
    //    the per-value z power), at position k = j*n + i:
    //      l0 = a_L - z*1                                 l1 = s_L
    //      r0 = y^k * (a_R + z) + z^{2+j} * 2^i           r1 = y^k * s_R
    const y_pows = try scalarvec.powers(scratch, y, nm);
    const two_pows = try scalarvec.powers(scratch, scalarvec.two, n);
    const z2 = scalar.mul(z, z);
    // zz[j] = z^{2+j}, the weight of value j's statement.
    const zz = try scratch.alloc([32]u8, m);
    {
        var acc = z2;
        for (zz) |*o| {
            o.* = acc;
            acc = scalar.mul(acc, z);
        }
    }

    const l0 = try scratch.alloc([32]u8, nm);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(l0));
    for (l0, a_l) |*o, al| o.* = scalar.sub(al, z);
    const l1 = s_l;
    const r0 = try scratch.alloc([32]u8, nm);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(r0));
    for (r0, a_r, y_pows, 0..) |*o, ar, yp, k|
        o.* = scalar.mulAdd(zz[k / n], two_pows[k % n], scalar.mul(yp, scalar.add(ar, z)));
    const r1 = try scratch.alloc([32]u8, nm);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(r1));
    scalarvec.hadamard(r1, y_pows, s_r) catch unreachable;

    //    t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2 — closed forms (paper
    //    eq. (61)); t0 itself is never sent (the verifier reconstructs it
    //    from the V_j/z/deltaYZMultiple).
    const t1_scalar = scalar.add(
        scalarvec.innerProduct(l0, r1) catch unreachable,
        scalarvec.innerProduct(l1, r0) catch unreachable,
    );
    const t2_scalar = scalarvec.innerProduct(l1, r1) catch unreachable;

    // 6.-7. T1/T2 under the SAME g/h base points the V_j were committed
    //    under; bind them; draw x.
    const tau1 = try randomScalar(io);
    const tau2 = try randomScalar(io);
    const t1_commit = mulOrIdentity(gens.g, t1_scalar).add(mulOrIdentity(gens.h, tau1));
    const t2_commit = mulOrIdentity(gens.g, t2_scalar).add(mulOrIdentity(gens.h, tau2));
    transcript.appendPoint("T_1", t1_commit);
    transcript.appendPoint("T_2", t2_commit);
    const x = transcript.challengeScalar("x");
    const x2 = scalar.mul(x, x);

    // 8. Evaluate l(x)/r(x) + the response scalars.
    const l_x = try scratch.alloc([32]u8, nm);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(l_x));
    for (l_x, l0, l1) |*o, c0, c1| o.* = scalar.mulAdd(c1, x, c0);
    const r_x = try scratch.alloc([32]u8, nm);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(r_x));
    for (r_x, r0, r1) |*o, c0, c1| o.* = scalar.mulAdd(c1, x, c0);
    const t_hat = scalarvec.innerProduct(l_x, r_x) catch unreachable;

    // Debug self-check (bip340.sign's self-verify philosophy): the direct
    // evaluation must equal the polynomial identity t0 + t1*x + t2*x^2.
    if (std.debug.runtime_safety) {
        const t0 = scalarvec.innerProduct(l0, r0) catch unreachable;
        const want = scalar.add(t0, scalar.mulAdd(t2_scalar, x2, scalar.mul(t1_scalar, x)));
        std.debug.assert(std.mem.eql(u8, &t_hat, &want));
    }

    // sum_j z^{2+j} * gamma_j — for m = 1 exactly the single proof's
    // z^2 * gamma.
    var zg = scalar.mul(zz[0], gammas[0]);
    defer std.crypto.secureZero(u8, &zg);
    for (zz[1..], gammas[1..]) |w_j, g_j| zg = scalar.mulAdd(w_j, g_j, zg);
    const tau_x = scalar.add(scalar.mulAdd(tau2, x2, scalar.mul(tau1, x)), zg);
    const mu = scalar.mulAdd(rho, x, alpha);

    // 9. Bind the response scalars, derive w -> Q = w*G (binding the IPA
    //    to THIS proof instance), rescale H'_k = y^{-k}*H_k, run the IPA
    //    on (l(x), r(x)) over the SAME continuing transcript.
    transcript.appendScalar("t_x", t_hat);
    transcript.appendScalar("t_x_blinding", tau_x);
    transcript.appendScalar("e_blinding", mu);
    const w = transcript.challengeScalar("w");
    const q = mulOrIdentity(gens.g, w);

    const y_inv = invertScalar(y);
    const h_prime = try scratch.alloc(Ristretto255, nm);
    {
        var y_inv_pow = scalarvec.one;
        for (h_prime, h_vec) |*o, hp| {
            o.* = mulOrIdentity(hp, y_inv_pow);
            y_inv_pow = scalar.mul(y_inv_pow, y_inv);
        }
    }

    const ipa_proof = ipa.proveIpa(allocator, transcript, g_vec, h_prime, q, l_x, r_x) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // All vector lengths are nm by construction, and nm's nonzero
        // power-of-two-ness was asserted at the top.
        error.LengthMismatch, error.NotPowerOfTwo => unreachable,
    };

    // 10. Assemble.
    return .{
        .a = a_commit,
        .s = s_commit,
        .t1 = t1_commit,
        .t2 = t2_commit,
        .tau_x = tau_x,
        .mu = mu,
        .t_hat = t_hat,
        .ipa = ipa_proof,
    };
}

/// **FABLE CORE — implemented.** See the module doc comment for the two
/// checks (`t_hat` relation + IPA). Never panics on adversarial input —
/// every structural mismatch, failed equation, or internal-scratch
/// failure returns `false` (fail-closed).
pub fn verify(
    gens: Generators,
    transcript: *Transcript,
    v: Ristretto255,
    proof: RangeProof,
) bool {
    return verifyTraced(gens, transcript, v, proof, null);
}

/// Verifies an aggregated proof (`proveMultiple`) for `commitments`, in the
/// order the prover bound them — dalek's `RangeProof::verify_multiple`.
/// `commitments.len` is the proof's `m`: a power of two, at most
/// `gens.parties`. Fail-closed like `verify`. The identity is accepted as a
/// commitment (value 0, blinding 0), as dalek does.
pub fn verifyMultiple(
    gens: Generators,
    transcript: *Transcript,
    commitments: []const Ristretto255,
    proof: RangeProof,
) bool {
    return verifyMultipleTraced(gens, transcript, commitments, proof, null);
}

/// What `verify` computed on its way to a verdict, recorded only when a
/// caller asks for it. It exists for `verify_b8_diff_test.zig`, which holds
/// the pre-B8 verifier as a reference and requires the points below to be
/// BYTE-IDENTICAL between the two on every input, forged ones included — a
/// stronger seam than comparing the boolean, which two broken verifiers can
/// agree on.
pub const VerifyTrace = struct {
    /// Check 1 (the `t_hat` relation) passed and the IPA check ran.
    reached_ipa: bool = false,
    /// Canonical encoding of the IPA statement point `P`.
    p: [32]u8 = scalarvec.zero,
    /// Canonical encodings of the IPA's final equation sides.
    ipa_lhs: [32]u8 = scalarvec.zero,
    ipa_rhs: [32]u8 = scalarvec.zero,
};

/// The body of `verify`. `trace` is written to, never read, so the verdict
/// cannot depend on it.
pub fn verifyTraced(
    gens: Generators,
    transcript: *Transcript,
    v: Ristretto255,
    proof: RangeProof,
    trace: ?*VerifyTrace,
) bool {
    return verifyMultipleTraced(gens, transcript, &[_]Ristretto255{v}, proof, trace);
}

/// The body of `verify` and `verifyMultiple`; `m = commitments.len`.
pub fn verifyMultipleTraced(
    gens: Generators,
    transcript: *Transcript,
    commitments: []const Ristretto255,
    proof: RangeProof,
    trace: ?*VerifyTrace,
) bool {
    const n = gens.n;
    const m = commitments.len;
    if (n == 0 or !std.math.isPowerOfTwo(n)) return false;
    if (m == 0 or !std.math.isPowerOfTwo(m) or m > gens.parties) return false;
    const gens_len = std.math.mul(usize, n, gens.parties) catch return false;
    if (gens.g_vec.len != gens_len or gens.h_vec.len != gens_len) return false;
    // n and m are powers of two and n*m <= n*parties fits, so nm is a
    // power of two too.
    const nm = n * m;
    const g_vec = gens.g_vec[0..nm];
    const h_vec = gens.h_vec[0..nm];
    const rounds: usize = std.math.log2_int(usize, nm);
    // Structural check: the proof's implied n*m (from its IPA round count)
    // must match this generator set and commitment count — rejects, among
    // other things, an n=8 proof replayed against an n=16 Generators set,
    // and an m=2 proof checked against one commitment.
    //
    // ⭐ Audit finding B14: `ipa.verifyIpa` (called below, at the end of
    // this function) performs THIS EXACT check again on its own `rounds`
    // parameter (derived from `g_vec.len`, which here is always `nm`)
    // against `proof.l_vec.len`/`proof.r_vec.len`. That duplication is
    // deliberate defense-in-depth, not dead code left over from a refactor —
    // `verifyIpa` is also called standalone (see `root.zig`'s re-export and
    // `kat_test.zig`'s "IPA standalone" test), so it cannot drop its own
    // copy without leaving THAT caller unchecked. A mutation that deletes
    // the check here survives (`verifyIpa`'s copy still catches it) — that
    // is expected, not evidence this line is redundant. Do not remove either
    // copy on the strength of a surviving mutation on just one of them.
    if (proof.ipa.l_vec.len != rounds or proof.ipa.r_vec.len != rounds) return false;

    // The verifier is allocator-less by signature; scratch comes from the
    // page allocator and EVERY failure — including OOM — rejects
    // (fail-closed), never panics. All inputs here are public, so no
    // constant-time concern applies.
    const scratch = std.heap.page_allocator; // global-alloc-ok: verifier is allocator-less by signature; scratch only, fail-closed on OOM (see doc comment above)

    // Replay step 4's transcript ops from the proof's own fields (and the
    // public V_j) to recover the prover's y, z, x. `n` and `m` first (audit
    // finding B10) — must mirror `prove`'s call exactly, same argument, same
    // position, or completeness breaks immediately (see the regression test
    // in this file's test block).
    appendDomainSepMultiple(transcript, n, m);
    for (commitments) |v| transcript.appendPoint("V", v);
    // dalek's verifier refuses an identity A/S/T_1/T_2 before binding it.
    transcript.validateAndAppendPoint("A", proof.a) catch return false;
    transcript.validateAndAppendPoint("S", proof.s) catch return false;
    const y = transcript.challengeScalar("y");
    const z = transcript.challengeScalar("z");
    transcript.validateAndAppendPoint("T_1", proof.t1) catch return false;
    transcript.validateAndAppendPoint("T_2", proof.t2) catch return false;
    const x = transcript.challengeScalar("x");
    const z2 = scalar.mul(z, z);
    const x2 = scalar.mul(x, x);

    // zz[j] = z^{2+j}, the weight of value j's statement.
    const zz = scratch.alloc([32]u8, m) catch return false;
    defer scratch.free(zz);
    {
        var acc = z2;
        for (zz) |*o| {
            o.* = acc;
            acc = scalar.mul(acc, z);
        }
    }

    // Check 1 — the t_hat relation (paper eq. (72), §4.3 for m > 1):
    //   t_hat*G + tau_x*H == sum_j z^{2+j}*V_j + delta(y,z)*G + x*T1 + x^2*T2.
    const delta = deltaYZMultiple(scratch, y, z, n, m) catch return false;
    const lhs = mulOrIdentity(gens.g, proof.t_hat).add(mulOrIdentity(gens.h, proof.tau_x));
    var v_sum = scalarvec.identity_point;
    for (commitments, zz) |v, w_j| v_sum = v_sum.add(mulOrIdentity(v, w_j));
    const rhs = v_sum
        .add(mulOrIdentity(gens.g, delta))
        .add(mulOrIdentity(proof.t1, x))
        .add(mulOrIdentity(proof.t2, x2));
    if (!lhs.equivalent(rhs)) return false;

    // Replay step 9: bind the response scalars, derive w -> Q = w*G.
    transcript.appendScalar("t_x", proof.t_hat);
    transcript.appendScalar("t_x_blinding", proof.tau_x);
    transcript.appendScalar("e_blinding", proof.mu);
    const w = transcript.challengeScalar("w");
    const q = mulOrIdentity(gens.g, w);

    // Check 2 — the IPA, over the rescaled generators h'_k = y^{-k}*H_k and
    // the IPA statement point (paper eq. (66)-(67), completed with the -mu*H
    // blinding removal and the +t_hat*Q inner-product binding so it
    // matches proveIpa's `P = <l,G> + <r,H'> + <l,r>*Q` form exactly), with
    // k = j*n + i:
    //   P = A + x*S - z*<1,G> - mu*H
    //       + sum_k (z*y^k + z^{2+j}*2^i)*h'_k + t_hat*Q
    //
    // ⭐ Audit finding B8: h' is NEVER materialised. Building it cost n
    // constant-time ladders — 63 % of verify at n=64 — over data with no
    // secret in it. Both places h' enters are MSMs, so y^{-k} moves into the
    // coefficient instead: ((z*y^k + z^{2+j}*2^i) * y^{-k}) * H_k here, and
    // `ipa.equationSides`'s `h_scale` there. That is the identity
    // (c*s)*H == c*(s*H), exact in a prime-order group for every scalar —
    // including y == 0 (`invert(0) == 0`), which is why the coefficient is
    // the old one times y^{-k} rather than the "simplified"
    // z + z^{2+j}*2^i*y^{-k}: that form is NOT equal to it when y == 0.
    // `verify_b8_diff_test.zig` pins P and both IPA equation sides
    // byte-for-byte against the pre-B8 verifier kept there (m = 1).
    const y_inv = invertScalar(y);
    // y_inv_pows[k] = y^{-k}: the implicit scale of h'_k, handed to the IPA.
    const y_inv_pows = scratch.alloc([32]u8, nm) catch return false;
    defer scratch.free(y_inv_pows);
    // Per-index coefficients of H_k in the h_term MSM below.
    const h_scalars = scratch.alloc([32]u8, nm) catch return false;
    defer scratch.free(h_scalars);

    var sum_g = scalarvec.identity_point;
    {
        var y_inv_pow = scalarvec.one;
        var y_pow = scalarvec.one;
        var two_pow = scalarvec.one;
        for (y_inv_pows, h_scalars, g_vec, 0..) |*s_out, *c_out, gp, k| {
            // 2^i restarts at every value's block.
            if (k % n == 0) two_pow = scalarvec.one;
            s_out.* = y_inv_pow;
            const c = scalar.mulAdd(zz[k / n], two_pow, scalar.mul(z, y_pow));
            c_out.* = scalar.mul(c, y_inv_pow);
            // sum_g accumulates the all-ones combination of the g generators
            // (a plain point sum, not a weighted MSM), so it stays a fold.
            sum_g = sum_g.add(gp);
            y_inv_pow = scalar.mul(y_inv_pow, y_inv);
            y_pow = scalar.mul(y_pow, y);
            two_pow = scalar.add(two_pow, two_pow);
        }
    }
    // h_term = sum_k ((z*y^k + z^{2+j}*2^i) * y^{-k}) * H_k — over PUBLIC
    // verifier data (challenges + public generators), so the vartime
    // Pippenger MSM applies.
    const h_term = scalarvec.multiScalarMulVartime(h_scalars, h_vec) catch return false;

    const p = proof.a
        .add(mulOrIdentity(proof.s, x))
        .sub(mulOrIdentity(sum_g, z))
        .sub(mulOrIdentity(gens.h, proof.mu))
        .add(h_term)
        .add(mulOrIdentity(q, proof.t_hat));

    const sides = ipa.equationSides(transcript, g_vec, h_vec, y_inv_pows, q, p, proof.ipa) orelse return false;
    if (trace) |t| {
        t.reached_ipa = true;
        t.p = p.toBytes();
        t.ipa_lhs = sides.lhs.toBytes();
        t.ipa_rhs = sides.rhs.toBytes();
    }
    return sides.lhs.equivalent(sides.rhs);
}

/// One proof in a `verifyBatch` call: its own transcript (positioned exactly
/// as `verifyMultiple` would receive it), its commitments in the prover's
/// order (`commitments.len` is the proof's `m`), and the proof.
pub const BatchEntry = struct {
    transcript: *Transcript,
    commitments: []const Ristretto255,
    proof: RangeProof,
};

pub const VerifyBatchError = error{ EntropyUnavailable, Canceled };

/// Verifies several independent range proofs (single or aggregated, mixed
/// `m`) with ONE vartime multi-scalar multiplication — dalek's batch
/// verification. Each proof's two checks are rewritten as one equation equal
/// to the identity (the IPA check expanded through `P`, so the shared
/// generators `G_k`, `H_k`, `g`, `h` appear once with summed coefficients),
/// weighted by two fresh random scalars per proof, and summed:
///
/// ```text
///   α·[ Σ_k (a·s_k + z)·G_k + Σ_k (b·s'_k·y^{-k} − c_k)·H_k
///       + w·(a·b − t̂)·g + μ·h − A − x·S − Σ_j (u_j²·L_j + u_j^{-2}·R_j) ]
/// + β·[ (t̂ − δ)·g + τ_x·h − Σ_j z^{2+j}·V_j − x·T_1 − x²·T_2 ]  =  O
/// ```
///
/// (`c_k = (z·y^k + z^{2+j}·2^i)·y^{-k}`, `s'_k = s_{nm−1−k}`, as in
/// `verifyMultiple`.) A forged proof survives only if its weighted sum
/// cancels the others', probability about `2^-252` per proof for weights the
/// prover cannot predict — which is why they come from `io.randomSecure`
/// and an entropy failure is an error, never a verdict. `true` iff every
/// proof verifies; an empty batch is `true`. Per-proof structural checks
/// and transcript replay are `verifyMultiple`'s, so a proof that
/// `verifyMultiple` rejects for shape or an identity point fails the batch.
/// All data is public (variable-time by design); scratch comes from the page
/// allocator and OOM rejects, like `verify`.
pub fn verifyBatch(gens: Generators, io: std.Io, entries: []const BatchEntry) VerifyBatchError!bool {
    const n = gens.n;
    if (n == 0 or !std.math.isPowerOfTwo(n)) return false;
    const gens_len = std.math.mul(usize, n, gens.parties) catch return false;
    if (gens.g_vec.len != gens_len or gens.h_vec.len != gens_len) return false;
    if (entries.len == 0) return true;

    const scratch = std.heap.page_allocator; // global-alloc-ok: verifier is allocator-less by signature; scratch only, fail-closed on OOM (see verify's doc comment)

    // Shape pass: sizes for the MSM, and verifyMultiple's structural checks.
    var max_nm: usize = 0;
    var per_proof_terms: usize = 0;
    for (entries) |e| {
        const m = e.commitments.len;
        if (m == 0 or !std.math.isPowerOfTwo(m) or m > gens.parties) return false;
        const nm = n * m;
        const rounds: usize = std.math.log2_int(usize, nm);
        if (e.proof.ipa.l_vec.len != rounds or e.proof.ipa.r_vec.len != rounds) return false;
        max_nm = @max(max_nm, nm);
        per_proof_terms += 4 + 2 * rounds + m; // A, S, T1, T2, L/R, V
    }
    const shared = 2 * max_nm + 2; // G_k, H_k, g, h
    const total = shared + per_proof_terms;
    const scalars = scratch.alloc([32]u8, total) catch return false;
    defer scratch.free(scalars);
    const points = scratch.alloc(Ristretto255, total) catch return false;
    defer scratch.free(points);
    @memset(scalars[0..shared], scalarvec.zero);
    @memcpy(points[0..max_nm], gens.g_vec[0..max_nm]);
    @memcpy(points[max_nm .. 2 * max_nm], gens.h_vec[0..max_nm]);
    points[2 * max_nm] = gens.g;
    points[2 * max_nm + 1] = gens.h;
    const g_coef = &scalars[2 * max_nm];
    const h_coef = &scalars[2 * max_nm + 1];

    var at: usize = shared;
    for (entries) |e| {
        const m = e.commitments.len;
        const nm = n * m;
        const rounds: usize = std.math.log2_int(usize, nm);
        const proof = e.proof;
        const t = e.transcript;

        // verifyMultiple's transcript replay, step for step.
        appendDomainSepMultiple(t, n, m);
        for (e.commitments) |v| t.appendPoint("V", v);
        t.validateAndAppendPoint("A", proof.a) catch return false;
        t.validateAndAppendPoint("S", proof.s) catch return false;
        const y = t.challengeScalar("y");
        const z = t.challengeScalar("z");
        t.validateAndAppendPoint("T_1", proof.t1) catch return false;
        t.validateAndAppendPoint("T_2", proof.t2) catch return false;
        const x = t.challengeScalar("x");
        t.appendScalar("t_x", proof.t_hat);
        t.appendScalar("t_x_blinding", proof.tau_x);
        t.appendScalar("e_blinding", proof.mu);
        const w = t.challengeScalar("w");
        var u: [64][32]u8 = undefined;
        var u_inv: [64][32]u8 = undefined;
        if (!ipa.replayChallenges(t, nm, proof.ipa, &u, &u_inv)) return false;
        const s = ipa.challengeProducts(scratch, u[0..rounds], u_inv[0..rounds], nm) orelse return false;
        defer scratch.free(s);
        const delta = deltaYZMultiple(scratch, y, z, n, m) catch return false;

        const alpha = try randomScalar(io);
        const beta = try randomScalar(io);
        const neg_alpha = scalar.neg(alpha);
        const neg_beta = scalar.neg(beta);
        const x2 = scalar.mul(x, x);

        // Shared generators. zz = z^{2+j} for value j's block.
        const y_inv = invertScalar(y);
        var y_pow = scalarvec.one;
        var y_inv_pow = scalarvec.one;
        var two_pow = scalarvec.one;
        var zz = scalar.mul(z, z);
        const a_alpha = scalar.mul(proof.ipa.a, alpha);
        const b_alpha = scalar.mul(proof.ipa.b, alpha);
        const z_alpha = scalar.mul(z, alpha);
        for (0..nm) |k| {
            if (k != 0 and k % n == 0) {
                two_pow = scalarvec.one;
                zz = scalar.mul(zz, z);
            }
            // G_k: α·(a·s_k + z)
            scalars[k] = scalar.add(scalars[k], scalar.mulAdd(a_alpha, s[k], z_alpha));
            // H_k: α·(b·s'_k − (z·y^k + zz·2^i))·y^{-k}
            const c = scalar.mulAdd(zz, two_pow, scalar.mul(z, y_pow));
            const hk = scalar.mul(scalar.sub(scalar.mul(b_alpha, s[nm - 1 - k]), scalar.mul(alpha, c)), y_inv_pow);
            scalars[max_nm + k] = scalar.add(scalars[max_nm + k], hk);
            y_pow = scalar.mul(y_pow, y);
            y_inv_pow = scalar.mul(y_inv_pow, y_inv);
            two_pow = scalar.add(two_pow, two_pow);
        }
        // g: α·w·(a·b − t̂) + β·(t̂ − δ);  h: α·μ + β·τ_x
        const ab = scalar.mul(proof.ipa.a, proof.ipa.b);
        const g_this = scalar.add(
            scalar.mul(scalar.mul(alpha, w), scalar.sub(ab, proof.t_hat)),
            scalar.mul(beta, scalar.sub(proof.t_hat, delta)),
        );
        g_coef.* = scalar.add(g_coef.*, g_this);
        h_coef.* = scalar.add(h_coef.*, scalar.add(scalar.mul(alpha, proof.mu), scalar.mul(beta, proof.tau_x)));

        // Per-proof points.
        scalars[at] = neg_alpha;
        points[at] = proof.a;
        scalars[at + 1] = scalar.mul(neg_alpha, x);
        points[at + 1] = proof.s;
        scalars[at + 2] = scalar.mul(neg_beta, x);
        points[at + 2] = proof.t1;
        scalars[at + 3] = scalar.mul(neg_beta, x2);
        points[at + 3] = proof.t2;
        at += 4;
        for (0..rounds) |j| {
            scalars[at] = scalar.mul(neg_alpha, scalar.mul(u[j], u[j]));
            points[at] = proof.ipa.l_vec[j];
            scalars[at + 1] = scalar.mul(neg_alpha, scalar.mul(u_inv[j], u_inv[j]));
            points[at + 1] = proof.ipa.r_vec[j];
            at += 2;
        }
        var zj = scalar.mul(z, z);
        for (e.commitments) |v| {
            scalars[at] = scalar.mul(neg_beta, zj);
            points[at] = v;
            at += 1;
            zj = scalar.mul(zj, z);
        }
    }
    std.debug.assert(at == total);
    const sum = scalarvec.multiScalarMulVartime(scalars, points) catch return false;
    return sum.equivalent(scalarvec.identity_point);
}

// ── tests (commit + deltaYZ + codec + construction-time guard — REAL, ungated) ──

test "commit: matches direct scalar-mult + add" {
    const gens = try Generators.init(std.testing.allocator, 8);
    defer gens.deinit(std.testing.allocator);
    const v = [_]u8{5} ++ [_]u8{0} ** 31;
    const gamma = [_]u8{9} ++ [_]u8{0} ** 31;
    const got = commit(gens, v, gamma);
    const want = (try gens.g.mul(v)).add(try gens.h.mul(gamma));
    try std.testing.expect(got.equivalent(want));
}

test "commit: v=0 reduces to gamma*H; gamma=0 reduces to v*G; both zero is identity" {
    const gens = try Generators.init(std.testing.allocator, 8);
    defer gens.deinit(std.testing.allocator);
    const gamma = [_]u8{9} ++ [_]u8{0} ** 31;
    const v = [_]u8{5} ++ [_]u8{0} ** 31;

    const c1 = commit(gens, scalarvec.zero, gamma);
    try std.testing.expect(c1.equivalent(try gens.h.mul(gamma)));

    const c2 = commit(gens, v, scalarvec.zero);
    try std.testing.expect(c2.equivalent(try gens.g.mul(v)));

    const c3 = commit(gens, scalarvec.zero, scalarvec.zero);
    try std.testing.expect(c3.equivalent(scalarvec.identity_point));
}

test "commit: distinct (v, gamma) pairs give distinct commitments" {
    const gens = try Generators.init(std.testing.allocator, 8);
    defer gens.deinit(std.testing.allocator);
    const c1 = commit(gens, [_]u8{1} ++ [_]u8{0} ** 31, [_]u8{2} ++ [_]u8{0} ** 31);
    const c2 = commit(gens, [_]u8{1} ++ [_]u8{0} ** 31, [_]u8{3} ++ [_]u8{0} ** 31);
    try std.testing.expect(!c1.equivalent(c2));
}

test "deltaYZ: n=1 matches hand-derived formula for arbitrary y,z" {
    // n=1: sum y^i for i in [0,1) is just y^0 = 1, independent of y.
    // delta = (z - z^2)*1 - z^3*(2^1 - 1) = (z - z^2) - z^3.
    const y = [_]u8{42} ++ [_]u8{0} ** 31;
    const z = [_]u8{7} ++ [_]u8{0} ** 31;
    const got = try deltaYZ(std.testing.allocator, y, z, 1);

    const z2 = scalar.mul(z, z);
    const z3 = scalar.mul(z2, z);
    const want = scalar.sub(scalar.sub(z, z2), z3);
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "deltaYZ: n=4, y=3, z=5 matches an independently-computed value" {
    // sum_{i=0}^{3} 3^i = 1+3+9+27 = 40. 2^4 - 1 = 15.
    // delta = (5-25)*40 - 125*15 = (-20)*40 - 1875 = -800 - 1875 = -2675.
    const y = [_]u8{3} ++ [_]u8{0} ** 31;
    const z = [_]u8{5} ++ [_]u8{0} ** 31;
    const got = try deltaYZ(std.testing.allocator, y, z, 4);

    // Independently constructed as field_order - 2675 via scalar.neg on
    // the positive magnitude 2675 (0x0A73), little-endian.
    const magnitude = [_]u8{ 0x73, 0x0A } ++ [_]u8{0} ** 30;
    const want = scalar.neg(magnitude);
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "deltaYZ: n=0 gives -z^3 (empty sum_y term)" {
    const y = [_]u8{9} ++ [_]u8{0} ** 31;
    const z = [_]u8{4} ++ [_]u8{0} ** 31;
    const got = try deltaYZ(std.testing.allocator, y, z, 0);
    // sum_y = 0 (empty), 2^0 - 1 = 0, so delta = 0 - 0 = 0.
    try std.testing.expectEqualSlices(u8, &scalarvec.zero, &got);
}

fn fakeIpaProof(allocator: std.mem.Allocator, rounds: usize) !InnerProductProof {
    const l_vec = try allocator.alloc(Ristretto255, rounds);
    errdefer allocator.free(l_vec);
    const r_vec = try allocator.alloc(Ristretto255, rounds);
    errdefer allocator.free(r_vec);
    var g = Ristretto255.basePoint;
    for (l_vec, r_vec) |*l, *r| {
        l.* = g;
        g = g.dbl();
        r.* = g;
        g = g.dbl();
    }
    return .{ .l_vec = l_vec, .r_vec = r_vec, .a = [_]u8{3} ++ [_]u8{0} ** 31, .b = [_]u8{4} ++ [_]u8{0} ** 31 };
}

test "RangeProof: byte round-trip" {
    const gens = try Generators.init(std.testing.allocator, 8);
    defer gens.deinit(std.testing.allocator);
    const ipa_proof = try fakeIpaProof(std.testing.allocator, 3);

    const proof = RangeProof{
        .a = gens.g,
        .s = gens.h,
        .t1 = gens.g_vec[0],
        .t2 = gens.h_vec[0],
        .tau_x = [_]u8{1} ++ [_]u8{0} ** 31,
        .mu = [_]u8{2} ++ [_]u8{0} ** 31,
        .t_hat = [_]u8{3} ++ [_]u8{0} ** 31,
        .ipa = ipa_proof,
    };
    defer proof.deinit(std.testing.allocator);

    const bytes = try proof.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(bytes);

    const back = try RangeProof.fromBytesAlloc(std.testing.allocator, bytes);
    defer back.deinit(std.testing.allocator);

    try std.testing.expect(proof.a.equivalent(back.a));
    try std.testing.expect(proof.s.equivalent(back.s));
    try std.testing.expect(proof.t1.equivalent(back.t1));
    try std.testing.expect(proof.t2.equivalent(back.t2));
    try std.testing.expectEqualSlices(u8, &proof.tau_x, &back.tau_x);
    try std.testing.expectEqualSlices(u8, &proof.mu, &back.mu);
    try std.testing.expectEqualSlices(u8, &proof.t_hat, &back.t_hat);
    try std.testing.expectEqual(proof.ipa.l_vec.len, back.ipa.l_vec.len);
    for (proof.ipa.l_vec, back.ipa.l_vec) |a, b| try std.testing.expect(a.equivalent(b));
}

test "RangeProof.fromBytesAlloc: rejects truncated input" {
    const gens = try Generators.init(std.testing.allocator, 4);
    defer gens.deinit(std.testing.allocator);
    const ipa_proof = try fakeIpaProof(std.testing.allocator, 2);
    const proof = RangeProof{
        .a = gens.g,
        .s = gens.h,
        .t1 = gens.g,
        .t2 = gens.h,
        .tau_x = scalarvec.one,
        .mu = scalarvec.one,
        .t_hat = scalarvec.one,
        .ipa = ipa_proof,
    };
    defer proof.deinit(std.testing.allocator);
    const bytes = try proof.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(bytes);

    try std.testing.expectError(error.InvalidEncoding, RangeProof.fromBytesAlloc(std.testing.allocator, bytes[0..10]));
    try std.testing.expectError(error.InvalidEncoding, RangeProof.fromBytesAlloc(std.testing.allocator, bytes[0 .. bytes.len - 1]));
}

test "RangeProof.fromBytesAlloc: rejects non-canonical tau_x/mu/t_hat scalars (defense-in-depth, audit B1)" {
    const gens = try Generators.init(std.testing.allocator, 4);
    defer gens.deinit(std.testing.allocator);
    const ipa_proof = try fakeIpaProof(std.testing.allocator, 2);
    const proof = RangeProof{
        .a = gens.g,
        .s = gens.h,
        .t1 = gens.g,
        .t2 = gens.h,
        .tau_x = scalarvec.one,
        .mu = scalarvec.one,
        .t_hat = scalarvec.one,
        .ipa = ipa_proof,
    };
    defer proof.deinit(std.testing.allocator);
    const bytes = try proof.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(bytes);

    // Same `L` little-endian bytes as ipa.zig's B1 test.
    const l_bytes = [_]u8{
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0,    0,    0,    0,    0,    0,    0,    0,
        0,    0,    0,    0,    0,    0,    0,    0x10,
    };
    const offsets = [_]usize{ 128, 160, 192 }; // tau_x, mu, t_hat (after 4 points)
    for (offsets) |base| {
        var mutated = try std.testing.allocator.dupe(u8, bytes);
        defer std.testing.allocator.free(mutated);
        var carry: u16 = 0;
        for (mutated[base .. base + 32], l_bytes) |*o, ad| {
            const sum = @as(u16, o.*) + @as(u16, ad) + carry;
            o.* = @truncate(sum);
            carry = sum >> 8;
        }
        try std.testing.expectError(error.InvalidEncoding, RangeProof.fromBytesAlloc(std.testing.allocator, mutated));
    }

    // Positive control: the untampered encoding must still decode.
    const back = try RangeProof.fromBytesAlloc(std.testing.allocator, bytes);
    back.deinit(std.testing.allocator);
}

test "prove: rejects v >= 2^n at construction, without touching the stub" {
    const gens = try Generators.init(std.testing.allocator, 4); // n = 4, values must be < 16
    defer gens.deinit(std.testing.allocator);
    var t = Transcript.init("bulletproofs/range-proof/v1");
    try std.testing.expectError(error.ValueOutOfRange, prove(std.testing.allocator, std.testing.io, gens, &t, &@as(u64, 16), scalarvec.zero));
    try std.testing.expectError(error.ValueOutOfRange, prove(std.testing.allocator, std.testing.io, gens, &t, &@as(u64, 255), scalarvec.zero));
}

test "prove: n=64 construction-time guard is skipped, and the boundary values it would have to handle actually verify (audit B6)" {
    // The test this replaces asserted `n >= 64` -- a fact about `usize`
    // literals, true unconditionally, that would pass even if `prove`/
    // `verify` were deleted outright. Its own justification ("cannot call
    // prove() itself here, n=64 would fall through to the @panic stub") is
    // stale: there is no `@panic` stub left (`gate.core_implemented` is
    // `true`, see `gate.zig`), so the real call it claimed was impossible
    // has been possible since the Fable core pass. Audit finding B6: this
    // module's flagship width, n=64 (README/SPEC/root.zig all name it as
    // the typical case), was not exercised by ANY test -- the full suite
    // ran entirely on n=8 (`kat_test.zig`) and n=4/n=8 (this file).
    // (This file's own tests call `prove`/`verify` directly, ungated --
    // gating on `gate.core_implemented` is `kat_test.zig`'s convention, for
    // the cross-cutting end-to-end scenarios; see this file's other
    // `prove`-calling tests above.)
    const gens = try Generators.init(std.testing.allocator, 64);
    defer gens.deinit(std.testing.allocator);
    const gamma = [_]u8{7} ++ [_]u8{0} ** 31;

    // The guard's own boundary values: 0, 1, and the maximum representable
    // u64 (2^64 - 1) -- exactly the shift-amount edge case the removed
    // test's comment worried about, now checked by actually running the
    // guard AND the full proof it guards, rather than re-deriving one
    // comparison in isolation.
    for ([_]u64{ 0, 1, std.math.maxInt(u64) }) |v| {
        var v_bytes = scalarvec.zero;
        std.mem.writeInt(u64, v_bytes[0..8], v, .little);
        const commitment = commit(gens, v_bytes, gamma);

        var prove_t = Transcript.init(transcript_domain);
        const proof = try prove(std.testing.allocator, std.testing.io, gens, &prove_t, &v, gamma);
        defer proof.deinit(std.testing.allocator);

        var verify_t = Transcript.init(transcript_domain);
        try std.testing.expect(verify(gens, &verify_t, commitment, proof));
    }
}

// ── fuzz: untrusted-input decoder never panics ──────────────────────────────

const fuzzseed = @import("testkit").fuzz;

/// `32*7` fixed octets and then a whole `InnerProductProof` behind them, so
/// the buffer has to hold both. 1024 leaves room for a 10-round IPA tail.
const rp_fuzz_buf_len = 1024;

/// The Ristretto255 identity - accepted by `fromBytes`, so a hand-written
/// seed can be a decodable proof without a real transcript behind it.
const rp_identity_hex = "00" ** 32;
const rp_bad_point_hex = "ff" ** 32;
/// `a, s, t1, t2` (four points) then `t_hat, tau_x, mu` (three raw scalars).
const rp_fixed_hex = rp_identity_hex ** 4 ++ "01" ** 32 ++ "02" ** 32 ++ "03" ** 32;

// Rewritten 2026-09-30 for dalek's layout: the nested IPA has no rounds
// field any more, its round count is implied by the remaining length.
const rp_seeds = [_][]const u8{
    fuzzseed.seedHex(""), // the empty slice: exactly what the collapsed draw ran, for ever
    fuzzseed.seedHex("00" ** 223), // one octet short of the 224-octet fixed part
    fuzzseed.seedHex("00" ** 224), // the fixed part alone: the IPA tail is empty, so the nested decode refuses
    fuzzseed.seedHex(rp_fixed_hex ++ "00" ** 64), // a complete, ACCEPTED proof with a rounds = 0 IPA
    fuzzseed.seedHex(rp_fixed_hex ++ rp_identity_hex ** 2 ++ "00" ** 64), // accepted, one IPA round
    fuzzseed.seedHex(rp_fixed_hex ++ rp_identity_hex ** 12 ++ "44" ** 64), // six rounds - the IPA width an n = 64 range proof produces
    fuzzseed.seedHex(rp_bad_point_hex ++ rp_identity_hex ** 3 ++ "00" ** 96 ++ "00" ** 64), // `a` is not a valid point: refused on the FIRST of the four
    fuzzseed.seedHex(rp_identity_hex ** 3 ++ rp_bad_point_hex ++ "00" ** 96 ++ "00" ** 64), // `t2` is not a valid point: refused on the LAST of the four
    fuzzseed.seedHex(rp_fixed_hex ++ rp_bad_point_hex ++ rp_identity_hex ++ "00" ** 64), // the fixed part decodes and the nested IPA then fails
    fuzzseed.seedHex(rp_fixed_hex ++ "00" ** 63), // the IPA tail one octet short
    fuzzseed.seedHex(rp_fixed_hex ++ rp_identity_hex ** 3 ++ "00" ** 64), // an odd element count behind a valid fixed part: an L without its R
    fuzzseed.seedHex("ff" ** 224), // every one of the four points invalid
};

fn fuzzFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    var buf: [rp_fuzz_buf_len]u8 = undefined;
    // One `smith.slice`, never `bytes` then a ranged draw - see the twin in
    // `ipa.zig`. `len` was 0 for every input this lane can carry, so the
    // decoder refused at `bytes.len < 32*7` and neither `Ristretto255.fromBytes`
    // nor the nested `InnerProductProof.fromBytesAlloc` had ever run from this
    // target. Measured 2026-09-07: 0 of 12 seeds arrived non-empty and 0
    // proofs were decoded before; 11 and 3 after.
    const len: usize = smith.slice(&buf);
    const proof = RangeProof.fromBytesAlloc(std.testing.allocator, buf[0..len]) catch return;
    proof.deinit(std.testing.allocator);
}
test "fuzz RangeProof.fromBytesAlloc never panics" {
    try std.testing.fuzz({}, fuzzFromBytesAlloc, .{ .corpus = &rp_seeds });
}

test "corpus: every range-proof seed reaches the decoder, and the nested IPA rounds are pinned" {
    // The second number is the nested IPA's rounds, because that is the
    // only part of this encoding whose size the attacker declares - and the
    // part an empty input cannot reach at all, since the four point decodes
    // come first.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var ipa_rounds: usize = 0;
    for (rp_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [rp_fuzz_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const proof = RangeProof.fromBytesAlloc(std.testing.allocator, buf[0..len]) catch continue;
        defer proof.deinit(std.testing.allocator);
        accepted += 1;
        ipa_rounds += proof.ipa.l_vec.len;
    }
    // One seed is deliberately the empty slice.
    try std.testing.expectEqual(rp_seeds.len - 1, nonempty);
    // Measured 2026-09-07. Before the draw was restructured both were 0.
    // ⭐ Re-measured 2026-09-10 after audit finding B1's fix (non-canonical
    // scalars now rejected, including the nested IPA's `a`/`b` via
    // `ipa.zig`'s own fix): the "six nested IPA rounds" seed's `a`/`b`
    // bytes are `0x44` repeated 32 times, non-canonical for the same
    // reason as `ipa.zig`'s corpus test, so it flips from accepted to
    // rejected: accepted 3 -> 2, ipa_rounds 7 -> 1 (loses that seed's 6
    // rounds).
    try std.testing.expectEqual(@as(usize, 2), accepted);
    try std.testing.expectEqual(@as(usize, 1), ipa_rounds);
}
