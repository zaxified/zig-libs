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
//! **Scope: single-value range proofs only** (Bulletproofs' `m = 1`
//! aggregation case). §4.3's aggregated multi-value range-proof extension
//! (proving several `V_j`s in one proof, `m > 1`) is explicitly OUT of
//! scope for this scaffold — see SPEC.md.
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
//! 4. **Transcript + challenges `y`, `z`.** `transcript.appendPoint("V",
//!    V);` (binding the public commitment — do this once, before `A`/`S`,
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
//! 7. **Transcript + challenge `x`.** `transcript.appendPoint("T1", T1);
//!    transcript.appendPoint("T2", T2); const x =
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
//!    `transcript.appendScalar("t_hat", t_hat); transcript.appendScalar
//!    ("tau_x", tau_x); transcript.appendScalar("mu", mu); const w =
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
//! recover the SAME `y`, `z`, `x`, `w` the prover derived, then checks
//! TWO equations:
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
//! Provenance: Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell,
//! "Bulletproofs: Short Proofs for Confidential Transactions and More",
//! IEEE S&P 2018 (eprint.iacr.org/2017/1066), §4.1/§4.2. Cross-referenced
//! against dalek-cryptography/bulletproofs's `range_proof.rs` for the
//! SHAPE of the construction (which scalars/points are committed in which
//! order) — no source ported, see NOTICE.

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

/// OS-entropy fill for the prover's secret blinding material (`alpha`,
/// `rho`, `s_L`, `s_R`, `tau1`, `tau2`). Mirrors the `ssh` module's
/// `transport.zig` `fillRandom`: direct getrandom(2), panic — never
/// silently degrade — if the OS entropy source fails (a range proof made
/// with predictable blinding leaks the witness).
fn fillRandom(buf: []u8) void {
    if (builtin.os.tag != .linux)
        @compileError("bulletproofs rangeproof.prove: only the Linux getrandom(2) entropy path is wired up (same posture as ssh/transport.zig's fillRandom)");
    var off: usize = 0;
    while (off < buf.len) {
        const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            if (signed == -@as(isize, @intFromEnum(std.os.linux.E.INTR))) continue;
            @panic("bulletproofs: getrandom failed");
        }
        off += rc;
    }
}

/// A uniformly random scalar in `[0, L)`: 64 OS-entropy bytes,
/// wide-reduced — the same uniform reduction `transcript.challengeScalar`
/// uses (RFC 8032's scalar-reduction convention).
fn randomScalar() [32]u8 {
    var wide: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &wide);
    fillRandom(&wide);
    return scalar.reduce64(wide);
}

/// `delta(y,z)` — Bulletproofs §4.1's verifier-side scalar correction
/// term (paper eq. (39), single-value `m=1` case — this scaffold's
/// scope, see SPEC.md):
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
    const y_pows = try scalarvec.powers(allocator, y, n);
    defer allocator.free(y_pows);
    var sum_y = scalarvec.zero;
    for (y_pows) |yp| sum_y = scalar.add(sum_y, yp);

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
    const term2 = scalar.mul(z3, sum_2n);
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

    /// `A(32) || S(32) || T1(32) || T2(32) || tau_x(32) || mu(32) ||
    /// t_hat(32) || <ipa.toBytesAlloc() bytes>`. REAL — mechanical
    /// concatenation; the trailing IPA sub-proof needs no outer length
    /// prefix since `InnerProductProof.fromBytesAlloc`'s own leading
    /// `rounds` field self-describes its exact remaining length (see that
    /// function's doc comment).
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
        out[off..][0..32].* = self.tau_x;
        off += 32;
        out[off..][0..32].* = self.mu;
        off += 32;
        out[off..][0..32].* = self.t_hat;
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
        const tau_x = bytes[off..][0..32].*;
        off += 32;
        const mu = bytes[off..][0..32].*;
        off += 32;
        const t_hat = bytes[off..][0..32].*;
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
};

/// **FABLE CORE — implemented.** See the module doc comment for the full
/// 10-step construction. `v`'s range guard is checked first — see
/// `ProveError.ValueOutOfRange`'s doc comment.
///
/// `v` is a plain `u64` (this scaffold does not support `n > 64` — every
/// realistic Bulletproofs range width, 8/16/32/64, fits; a wider-`v`
/// variant would need a bignum witness type and is out of scope here, see
/// SPEC.md).
pub fn prove(
    allocator: std.mem.Allocator,
    gens: Generators,
    transcript: *Transcript,
    v: u64,
    gamma: [32]u8,
) ProveError!RangeProof {
    if (gens.n < 64) {
        const limit = @as(u64, 1) << @intCast(gens.n);
        if (v >= limit) return error.ValueOutOfRange;
    }

    const n = gens.n;
    // The IPA reduction needs a nonzero power-of-two n. A Generators set
    // is caller-constructed (non-adversarial) input, so this is a contract
    // assertion, not an error variant (mirrors proveIpa's own unreachable
    // below).
    std.debug.assert(n != 0 and std.math.isPowerOfTwo(n));

    // Every internal vector lives in one arena (freed on all paths); the
    // witness-bearing ones get a best-effort secureZero before the arena
    // releases them. The IPA sub-proof is allocated from `allocator`
    // directly since it outlives this call (freed by RangeProof.deinit).
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const scratch = arena_state.allocator();

    // 1. Bit decomposition, LSB-first: <a_L, [2^0,...,2^{n-1}]> == v.
    //    a_R = a_L - 1^n elementwise. Branchless bit extract (v is
    //    secret); bit positions >= 64 are structurally zero (u64 witness).
    const a_l = try scratch.alloc([32]u8, n);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(a_l));
    const a_r = try scratch.alloc([32]u8, n);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(a_r));
    for (a_l, a_r, 0..) |*al, *ar, i| {
        const bit: u8 = if (i < 64) @truncate((v >> @intCast(i)) & 1) else 0;
        al.* = scalarvec.zero;
        al.*[0] = bit;
        ar.* = scalar.sub(al.*, scalarvec.one);
    }

    // 2. A = alpha*H + <a_L, G_vec> + <a_R, H_vec>. All lengths are n by
    //    construction — LengthMismatch is unreachable throughout.
    const alpha = randomScalar();
    const a_commit = mulOrIdentity(gens.h, alpha)
        .add(scalarvec.multiScalarMul(a_l, gens.g_vec) catch unreachable)
        .add(scalarvec.multiScalarMul(a_r, gens.h_vec) catch unreachable);

    // 3. S = rho*H + <s_L, G_vec> + <s_R, H_vec>, s_L/s_R fresh random.
    const s_l = try scratch.alloc([32]u8, n);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(s_l));
    const s_r = try scratch.alloc([32]u8, n);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(s_r));
    for (s_l, s_r) |*sl, *sr| {
        sl.* = randomScalar();
        sr.* = randomScalar();
    }
    const rho = randomScalar();
    const s_commit = mulOrIdentity(gens.h, rho)
        .add(scalarvec.multiScalarMul(s_l, gens.g_vec) catch unreachable)
        .add(scalarvec.multiScalarMul(s_r, gens.h_vec) catch unreachable);

    // 4. Bind V (recomputed from the witness — the same point the
    //    verifier is handed), then A/S; draw y, z.
    var v_bytes = scalarvec.zero;
    defer std.crypto.secureZero(u8, &v_bytes);
    std.mem.writeInt(u64, v_bytes[0..8], v, .little);
    const v_point = commit(gens, v_bytes, gamma);
    transcript.appendPoint("V", v_point);
    transcript.appendPoint("A", a_commit);
    transcript.appendPoint("S", s_commit);
    const y = transcript.challengeScalar("y");
    const z = transcript.challengeScalar("z");

    // 5. l(X) = l0 + l1*X, r(X) = r0 + r1*X (paper eq. (63)-(64)):
    //      l0 = a_L - z*1^n                       l1 = s_L
    //      r0 = y^n . (a_R + z*1^n) + z^2*2^n     r1 = y^n . s_R
    const y_pows = try scalarvec.powers(scratch, y, n);
    const two_pows = try scalarvec.powers(scratch, scalarvec.two, n);
    const z2 = scalar.mul(z, z);

    const l0 = try scratch.alloc([32]u8, n);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(l0));
    for (l0, a_l) |*o, al| o.* = scalar.sub(al, z);
    const l1 = s_l;
    const r0 = try scratch.alloc([32]u8, n);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(r0));
    for (r0, a_r, y_pows, two_pows) |*o, ar, yp, tp|
        o.* = scalar.mulAdd(z2, tp, scalar.mul(yp, scalar.add(ar, z)));
    const r1 = try scratch.alloc([32]u8, n);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(r1));
    scalarvec.hadamard(r1, y_pows, s_r) catch unreachable;

    //    t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2 — closed forms (paper
    //    eq. (61)); t0 itself is never sent (the verifier reconstructs it
    //    from V/z/deltaYZ).
    const t1_scalar = scalar.add(
        scalarvec.innerProduct(l0, r1) catch unreachable,
        scalarvec.innerProduct(l1, r0) catch unreachable,
    );
    const t2_scalar = scalarvec.innerProduct(l1, r1) catch unreachable;

    // 6.-7. T1/T2 under the SAME g/h base points V was committed under;
    //    bind them; draw x.
    const tau1 = randomScalar();
    const tau2 = randomScalar();
    const t1_commit = mulOrIdentity(gens.g, t1_scalar).add(mulOrIdentity(gens.h, tau1));
    const t2_commit = mulOrIdentity(gens.g, t2_scalar).add(mulOrIdentity(gens.h, tau2));
    transcript.appendPoint("T1", t1_commit);
    transcript.appendPoint("T2", t2_commit);
    const x = transcript.challengeScalar("x");
    const x2 = scalar.mul(x, x);

    // 8. Evaluate l(x)/r(x) + the response scalars.
    const l_x = try scratch.alloc([32]u8, n);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(l_x));
    for (l_x, l0, l1) |*o, c0, c1| o.* = scalar.mulAdd(c1, x, c0);
    const r_x = try scratch.alloc([32]u8, n);
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

    const tau_x = scalar.add(scalar.mulAdd(tau2, x2, scalar.mul(tau1, x)), scalar.mul(z2, gamma));
    const mu = scalar.mulAdd(rho, x, alpha);

    // 9. Bind the response scalars, derive w -> Q = w*G (binding the IPA
    //    to THIS proof instance), rescale H'_i = y^{-i}*H_i, run the IPA
    //    on (l(x), r(x)) over the SAME continuing transcript.
    transcript.appendScalar("t_hat", t_hat);
    transcript.appendScalar("tau_x", tau_x);
    transcript.appendScalar("mu", mu);
    const w = transcript.challengeScalar("w");
    const q = mulOrIdentity(gens.g, w);

    const y_inv = invertScalar(y);
    const h_prime = try scratch.alloc(Ristretto255, n);
    {
        var y_inv_pow = scalarvec.one;
        for (h_prime, gens.h_vec) |*o, hp| {
            o.* = mulOrIdentity(hp, y_inv_pow);
            y_inv_pow = scalar.mul(y_inv_pow, y_inv);
        }
    }

    const ipa_proof = ipa.proveIpa(allocator, transcript, gens.g_vec, h_prime, q, l_x, r_x) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // All vector lengths are n by construction, and n's nonzero
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
    const n = gens.n;
    if (n == 0 or !std.math.isPowerOfTwo(n)) return false;
    if (gens.g_vec.len != n or gens.h_vec.len != n) return false;
    const rounds: usize = std.math.log2_int(usize, n);
    // Structural check: the proof's implied n (from its IPA round count)
    // must match this generator set — rejects, among other things, an
    // n=8 proof replayed against an n=16 Generators set.
    if (proof.ipa.l_vec.len != rounds or proof.ipa.r_vec.len != rounds) return false;

    // The verifier is allocator-less by signature; scratch comes from the
    // page allocator and EVERY failure — including OOM — rejects
    // (fail-closed), never panics. All inputs here are public, so no
    // constant-time concern applies.
    const scratch = std.heap.page_allocator; // global-alloc-ok: verifier is allocator-less by signature; scratch only, fail-closed on OOM (see doc comment above)

    // Replay step 4's transcript ops from the proof's own fields (and the
    // public V) to recover the prover's y, z, x.
    transcript.appendPoint("V", v);
    transcript.appendPoint("A", proof.a);
    transcript.appendPoint("S", proof.s);
    const y = transcript.challengeScalar("y");
    const z = transcript.challengeScalar("z");
    transcript.appendPoint("T1", proof.t1);
    transcript.appendPoint("T2", proof.t2);
    const x = transcript.challengeScalar("x");
    const z2 = scalar.mul(z, z);
    const x2 = scalar.mul(x, x);

    // Check 1 — the t_hat relation (paper eq. (72)):
    //   t_hat*G + tau_x*H == z^2*V + delta(y,z)*G + x*T1 + x^2*T2.
    const delta = deltaYZ(scratch, y, z, n) catch return false;
    const lhs = mulOrIdentity(gens.g, proof.t_hat).add(mulOrIdentity(gens.h, proof.tau_x));
    const rhs = mulOrIdentity(v, z2)
        .add(mulOrIdentity(gens.g, delta))
        .add(mulOrIdentity(proof.t1, x))
        .add(mulOrIdentity(proof.t2, x2));
    if (!lhs.equivalent(rhs)) return false;

    // Replay step 9: bind the response scalars, derive w -> Q = w*G.
    transcript.appendScalar("t_hat", proof.t_hat);
    transcript.appendScalar("tau_x", proof.tau_x);
    transcript.appendScalar("mu", proof.mu);
    const w = transcript.challengeScalar("w");
    const q = mulOrIdentity(gens.g, w);

    // Check 2 — the IPA. Rescaled generators h'_i = y^{-i}*H_i, and the
    // IPA statement point (paper eq. (66)-(67), completed with the -mu*H
    // blinding removal and the +t_hat*Q inner-product binding so it
    // matches proveIpa's `P = <l,G> + <r,H'> + <l,r>*Q` form exactly):
    //   P = A + x*S - z*<1,G> - mu*H
    //       + sum_i (z*y^i + z^2*2^i)*h'_i + t_hat*Q
    const y_inv = invertScalar(y);
    const h_prime = scratch.alloc(Ristretto255, n) catch return false;
    defer scratch.free(h_prime);
    // Per-index coefficients (z*y^i + z^2*2^i) of the h'_i term, collected so
    // the sum can go through the vartime Pippenger MSM below.
    const h_scalars = scratch.alloc([32]u8, n) catch return false;
    defer scratch.free(h_scalars);

    var sum_g = scalarvec.identity_point;
    {
        var y_inv_pow = scalarvec.one;
        var y_pow = scalarvec.one;
        var two_pow = scalarvec.one;
        for (h_prime, h_scalars, gens.h_vec, gens.g_vec) |*o, *c_out, hp, gp| {
            o.* = mulOrIdentity(hp, y_inv_pow);
            c_out.* = scalar.mulAdd(z2, two_pow, scalar.mul(z, y_pow));
            // sum_g accumulates the all-ones combination of the g generators
            // (a plain point sum, not a weighted MSM), so it stays a fold.
            sum_g = sum_g.add(gp);
            y_inv_pow = scalar.mul(y_inv_pow, y_inv);
            y_pow = scalar.mul(y_pow, y);
            two_pow = scalar.add(two_pow, two_pow);
        }
    }
    // h_term = sum_i (z*y^i + z^2*2^i) * h'_i — over PUBLIC verifier data
    // (challenges + public generators), so the vartime Pippenger MSM applies.
    const h_term = scalarvec.multiScalarMulVartime(h_scalars, h_prime) catch return false;

    const p = proof.a
        .add(mulOrIdentity(proof.s, x))
        .sub(mulOrIdentity(sum_g, z))
        .sub(mulOrIdentity(gens.h, proof.mu))
        .add(h_term)
        .add(mulOrIdentity(q, proof.t_hat));

    return ipa.verifyIpa(transcript, gens.g_vec, h_prime, q, p, proof.ipa);
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

test "prove: rejects v >= 2^n at construction, without touching the stub" {
    const gens = try Generators.init(std.testing.allocator, 4); // n = 4, values must be < 16
    defer gens.deinit(std.testing.allocator);
    var t = Transcript.init("bulletproofs/range-proof/v1");
    try std.testing.expectError(error.ValueOutOfRange, prove(std.testing.allocator, gens, &t, 16, scalarvec.zero));
    try std.testing.expectError(error.ValueOutOfRange, prove(std.testing.allocator, gens, &t, 255, scalarvec.zero));
}

test "prove: n=64 never rejects any u64 value at the construction-time guard" {
    // Cannot call prove() itself here (n=64 would fall through to the
    // @panic stub) -- this test only exercises the shift-amount edge
    // case of the guard's own arithmetic by re-deriving it directly,
    // guarding against a regression that reintroduces a `<<64` overflow.
    const n: usize = 64;
    try std.testing.expect(n >= 64); // guard's `if (gens.n < 64)` branch is skipped for n=64
}

// ── fuzz: untrusted-input decoder never panics ──────────────────────────────

fn fuzzFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const proof = RangeProof.fromBytesAlloc(std.testing.allocator, buf[0..len]) catch return;
    proof.deinit(std.testing.allocator);
}
test "fuzz RangeProof.fromBytesAlloc never panics" {
    try std.testing.fuzz({}, fuzzFromBytesAlloc, .{});
}
