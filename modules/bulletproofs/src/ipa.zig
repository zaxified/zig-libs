// SPDX-License-Identifier: MIT

//! ipa — the Inner-Product Argument (Bulletproofs §3, Bünz, Bootle, Boneh,
//! Poelstra, Wuille, Maxwell, "Bulletproofs: Short Proofs for Confidential
//! Transactions and More", IEEE S&P 2018): a logarithmic-size
//! zero-knowledge argument that a prover knows vectors `a`, `b` (length
//! `n`, a power of two) satisfying
//!
//! ```text
//! P = <a, G_vec> + <b, H_vec> + <a, b>*Q
//! ```
//!
//! for public generator vectors `G_vec`/`H_vec` (length `n`), a public
//! point `Q`, and a public point `P` — without revealing `a`/`b` beyond
//! their (already public, via `P`) inner product `<a,b>`.
//! `rangeproof.zig`'s range proof reduces its final check to exactly this
//! statement (see its own module doc comment) — this file's
//! `proveIpa`/`verifyIpa` is the shared "vector relation" argument BOTH
//! the range proof, and any future Bulletproofs-family protocol added to
//! this module, would call into.
//!
//! **THE FABLE CORE — implemented.** `proveIpa`/`verifyIpa` below carry
//! the genuinely hard
//! cryptographic content of the whole `bulletproofs` module: a
//! recursive, `log2(n)`-round vector-folding argument whose soundness
//! rests on the discrete-log assumption over Ristretto255 and whose
//! zero-knowledge property rests on each round's Fiat-Shamir challenge
//! being drawn AFTER that round's commitments are fixed (enforced by
//! `transcript.zig`'s append-then-challenge ordering). Every OTHER piece
//! here — the `InnerProductProof` struct, its byte codec, and the
//! round-count/length preconditions checked at the top of each stub — is
//! REAL, not stubbed.
//!
//! ## Protocol (§3.1, "Improving the Efficiency" — the recursive
//! logarithmic-round version; NOT §3's naive un-folded 2n-round opening)
//!
//! Setup: `n` a power of two, `g_vec`/`h_vec` length-`n` generator
//! vectors, `q` a generator such that no party knows any `log_q(g_i)`/
//! `log_q(h_i)` (the range-proof caller derives `q` from ITS OWN
//! transcript challenge — see `rangeproof.zig`), `p` the public
//! commitment, `a`/`b` the prover's secret length-`n` witness vectors
//! with `p = <a,g_vec> + <b,h_vec> + <a,b>*q`.
//!
//! One ROUND, repeated `log2(n)` times (`n'` = the current half-length,
//! starting at `n/2` and halving each round):
//!
//! 1. Split `a = a_lo || a_hi`, `b = b_lo || b_hi`, `g_vec = g_lo || g_hi`,
//!    `h_vec = h_lo || h_hi` — each half length `n'`.
//! 2. Prover computes (via `scalarvec.innerProduct`/`multiScalarMul`):
//!    ```text
//!    c_L = <a_lo, b_hi>
//!    c_R = <a_hi, b_lo>
//!    L = <a_lo, g_hi> + <b_hi, h_lo> + c_L*q
//!    R = <a_hi, g_lo> + <b_lo, h_hi> + c_R*q
//!    ```
//!    and appends `L`/`R` to the proof's `l_vec`/`r_vec`.
//! 3. Both sides: `transcript.appendPoint("L", L); transcript
//!    .appendPoint("R", R);` then `u = transcript.challengeScalar("u")`
//!    — MUST be nonzero (negligible probability of `u == 0`, but a
//!    correct implementation must not divide by zero if it ever is —
//!    same defensive posture as `bip340.sign`'s `k0 == 0` check).
//! 4. Prover folds the witness (using the scalar field's
//!    multiplicative-inverse, `u^{-1}`, via
//!    `Ristretto255.scalar.Scalar.fromBytes(u).invert().toBytes()`):
//!    ```text
//!    a' = a_lo*u + a_hi*u^{-1}
//!    b' = b_lo*u^{-1} + b_hi*u
//!    ```
//!    Both sides fold the generators identically (the verifier needs
//!    this to recompute the final check without ever seeing `a`/`b`):
//!    ```text
//!    g'_i = g_lo_i*u^{-1} + g_hi_i*u   (per-index EC point combination)
//!    h'_i = h_lo_i*u       + h_hi_i*u^{-1}
//!    ```
//! 5. Recurse with `(a', b', g', h', n')` until `n' == 1`: the FINAL
//!    round sends the two remaining scalars directly as
//!    `InnerProductProof.a`/`.b` instead of another `L`/`R` pair.
//!
//! Verifier (`verifyIpa`): does not have `a`/`b`, but reproduces every
//! `u_i` by replaying the SAME transcript operations against the proof's
//! own `l_vec`/`r_vec` (L/R MUST be appended before deriving `u` —
//! Fiat-Shamir), folds `g_vec`/`h_vec` down to two single points exactly
//! as the prover did, and checks the single final equation
//!
//! ```text
//! P + sum_i (u_i^2 * L_i + u_i^{-2} * R_i) == a*g_final + b*h_final + (a*b)*q
//! ```
//!
//! (the "single multi-exponentiation" form — §3.1's own optimization:
//! rather than recursively reconstructing a shrinking `P'` round by
//! round, the verifier can equivalently fold the ORIGINAL `P` by the
//! accumulated `u_i^{2}`/`u_i^{-2}` factors and fold the ORIGINAL
//! `g_vec`/`h_vec` by explicit per-index products of `u_j^{±1}`, checking
//! everything in one multi-scalar multiplication. A real implementation
//! SHOULD use this form for performance; the round-by-round fold above is
//! mathematically identical and simpler to state/implement first — either
//! is an acceptable `verifyIpa` implementation). Accept iff the equation
//! holds (`Ristretto255.equivalent`); reject (return `false`) otherwise —
//! NEVER panic on a malformed/adversarial `proof` in the FINAL
//! implementation (only length/struct-shape is checked by the codec;
//! anything else is simply "does not satisfy the equation").
//!
//! Soundness/zero-knowledge: §3 Theorem 1 (soundness, via a
//! `log(n)`-special-soundness/rewinding argument over the discrete-log
//! relation problem) and §3's honest-verifier zero-knowledge argument
//! (Fiat-Shamir removes interactivity at the cost of the random-oracle
//! model). No independent re-derivation of the security proof is
//! attempted here — this module matches the paper's algorithm exactly,
//! per CONVENTIONS.md's "model after a proven implementation" directive,
//! and leans on the paper's own proof.
//!
//! Provenance: see NOTICE. Cross-referenced against
//! dalek-cryptography/bulletproofs's `inner_product_proof.rs` for the
//! SHAPE of the recursive fold (which of `u`/`u^{-1}` multiplies which
//! half) — no source ported.

const std = @import("std");
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;
const transcript_mod = @import("transcript.zig");
const Transcript = transcript_mod.Transcript;
const scalarvec = @import("scalarvec.zig");

/// `p*s`, mapping std's "result is the identity element" error (raised
/// exactly when `s == 0 mod L`, per `Ristretto255.mul`'s doc) to the
/// identity element itself — the same exact-not-approximate convention
/// `scalarvec.multiScalarMul` documents for its own `catch continue`.
fn mulOrIdentity(p: Ristretto255, s: [32]u8) Ristretto255 {
    return p.mul(s) catch scalarvec.identity_point;
}

/// `s^{-1} (mod L)` via std's expanded-scalar exponentiation chain.
/// `invert(0) == 0` (std's documented behavior) — there is no literal
/// division anywhere, so a (negligible-probability) zero challenge cannot
/// crash prover or verifier; it merely yields a proof that does not
/// verify (the defensive posture the module doc comment's step 3 asks
/// for).
fn invertScalar(s: [32]u8) [32]u8 {
    const inv = scalar.Scalar.fromBytes(s).invert();
    return inv.toBytes();
}

/// The label a caller SHOULD start a fresh `Transcript` with when using
/// the IPA standalone (not as a range-proof sub-step, where
/// `rangeproof.transcript_domain`'s already-started transcript is reused
/// directly instead — see `rangeproof.zig`'s step 9).
pub const transcript_domain = "bulletproofs/ipa/v1";

/// A completed Inner-Product Argument proof: one `(L, R)` pair per fold
/// round (`log2(n)` rounds total) plus the final folded scalar pair
/// `(a, b)`.
pub const InnerProductProof = struct {
    /// One `L` per fold round.
    l_vec: []Ristretto255,
    /// One `R` per fold round, `r_vec.len == l_vec.len`.
    r_vec: []Ristretto255,
    /// The final, length-1 folded `a`.
    a: [32]u8,
    /// The final, length-1 folded `b`.
    b: [32]u8,

    pub fn deinit(self: InnerProductProof, allocator: std.mem.Allocator) void {
        allocator.free(self.l_vec);
        allocator.free(self.r_vec);
    }

    /// `rounds(u32 BE) || (L_i(32) || R_i(32)) * rounds || a(32) || b(32)`.
    /// REAL — mechanical length-prefixed point/scalar concatenation, the
    /// same shape `rangeproof.RangeProof.toBytesAlloc` uses for its own
    /// fixed fields.
    pub fn toBytesAlloc(self: InnerProductProof, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        std.debug.assert(self.l_vec.len == self.r_vec.len);
        const rounds = self.l_vec.len;
        const out = try allocator.alloc(u8, 4 + rounds * 64 + 64);
        var off: usize = 0;
        std.mem.writeInt(u32, out[0..4], @intCast(rounds), .big);
        off += 4;
        for (self.l_vec, self.r_vec) |l, r| {
            out[off..][0..32].* = l.toBytes();
            off += 32;
            out[off..][0..32].* = r.toBytes();
            off += 32;
        }
        out[off..][0..32].* = self.a;
        off += 32;
        out[off..][0..32].* = self.b;
        off += 32;
        return out;
    }

    pub const FromBytesError = error{ InvalidEncoding, OutOfMemory };

    /// Inverse of `toBytesAlloc`. `bytes.len` MUST equal exactly the
    /// length implied by its own leading `rounds` field — this exact-length
    /// check is what lets `rangeproof.RangeProof.fromBytesAlloc` hand this
    /// function a trailing sub-slice with no extra outer length prefix
    /// (see that file's codec).
    pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) FromBytesError!InnerProductProof {
        if (bytes.len < 4) return error.InvalidEncoding;
        const rounds = std.mem.readInt(u32, bytes[0..4], .big);
        const expected_len = 4 + @as(usize, rounds) * 64 + 64;
        if (bytes.len != expected_len) return error.InvalidEncoding;

        const l_vec = try allocator.alloc(Ristretto255, rounds);
        errdefer allocator.free(l_vec);
        const r_vec = try allocator.alloc(Ristretto255, rounds);
        errdefer allocator.free(r_vec);

        var off: usize = 4;
        for (l_vec, r_vec) |*l, *r| {
            l.* = Ristretto255.fromBytes(bytes[off..][0..32].*) catch return error.InvalidEncoding;
            off += 32;
            r.* = Ristretto255.fromBytes(bytes[off..][0..32].*) catch return error.InvalidEncoding;
            off += 32;
        }
        const a = bytes[off..][0..32].*;
        off += 32;
        const b = bytes[off..][0..32].*;
        off += 32;

        return .{ .l_vec = l_vec, .r_vec = r_vec, .a = a, .b = b };
    }
};

pub const IpaError = error{
    LengthMismatch,
    NotPowerOfTwo,
    OutOfMemory,
};

/// **FABLE CORE — implemented.** See the module doc comment for the exact
/// per-round construction and recursion base case (Bulletproofs §3.1's
/// recursive logarithmic fold, implemented iteratively in place).
pub fn proveIpa(
    allocator: std.mem.Allocator,
    transcript: *Transcript,
    g_vec: []const Ristretto255,
    h_vec: []const Ristretto255,
    q: Ristretto255,
    a_in: []const [32]u8,
    b_in: []const [32]u8,
) IpaError!InnerProductProof {
    if (a_in.len != b_in.len or a_in.len != g_vec.len or g_vec.len != h_vec.len) return error.LengthMismatch;
    if (a_in.len == 0 or !std.math.isPowerOfTwo(a_in.len)) return error.NotPowerOfTwo;

    const rounds: usize = std.math.log2_int(usize, a_in.len);

    // Working copies — each round folds in place, halving the live prefix.
    // `a`/`b` are the secret witness: best-effort zeroed before free (the
    // fold arithmetic itself runs on std's constant-time scalar limbs; see
    // the constant-time note in this function's report/commit trail).
    const a = try allocator.dupe([32]u8, a_in);
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(a));
        allocator.free(a);
    }
    const b = try allocator.dupe([32]u8, b_in);
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(b));
        allocator.free(b);
    }
    const g = try allocator.dupe(Ristretto255, g_vec);
    defer allocator.free(g);
    const h = try allocator.dupe(Ristretto255, h_vec);
    defer allocator.free(h);

    const l_out = try allocator.alloc(Ristretto255, rounds);
    errdefer allocator.free(l_out);
    const r_out = try allocator.alloc(Ristretto255, rounds);
    errdefer allocator.free(r_out);

    var n = a_in.len;
    var round: usize = 0;
    while (n > 1) : (round += 1) {
        const half = n / 2;
        const a_lo = a[0..half];
        const a_hi = a[half..n];
        const b_lo = b[0..half];
        const b_hi = b[half..n];
        const g_lo = g[0..half];
        const g_hi = g[half..n];
        const h_lo = h[0..half];
        const h_hi = h[half..n];

        // Step 2: cross inner products + the round's L/R commitments.
        // Halves are equal-length by construction — LengthMismatch is
        // unreachable.
        const c_l = scalarvec.innerProduct(a_lo, b_hi) catch unreachable;
        const c_r = scalarvec.innerProduct(a_hi, b_lo) catch unreachable;
        const l_pt = (scalarvec.multiScalarMul(a_lo, g_hi) catch unreachable)
            .add(scalarvec.multiScalarMul(b_hi, h_lo) catch unreachable)
            .add(mulOrIdentity(q, c_l));
        const r_pt = (scalarvec.multiScalarMul(a_hi, g_lo) catch unreachable)
            .add(scalarvec.multiScalarMul(b_lo, h_hi) catch unreachable)
            .add(mulOrIdentity(q, c_r));

        l_out[round] = l_pt;
        r_out[round] = r_pt;

        // Step 3: Fiat-Shamir — L/R are bound BEFORE u is drawn.
        transcript.appendPoint("L", l_pt);
        transcript.appendPoint("R", r_pt);
        const u = transcript.challengeScalar("u");
        const u_inv = invertScalar(u);

        // Step 4: fold. Every write lands in the lo half at index i and
        // every read of index i happens before that write, so folding in
        // place is safe:
        //   a' = a_lo*u      + a_hi*u^{-1}
        //   b' = b_lo*u^{-1} + b_hi*u
        //   g' = g_lo*u^{-1} + g_hi*u
        //   h' = h_lo*u      + h_hi*u^{-1}
        for (0..half) |i| {
            a[i] = scalar.add(scalar.mul(a_lo[i], u), scalar.mul(a_hi[i], u_inv));
            b[i] = scalar.add(scalar.mul(b_lo[i], u_inv), scalar.mul(b_hi[i], u));
            g[i] = mulOrIdentity(g_lo[i], u_inv).add(mulOrIdentity(g_hi[i], u));
            h[i] = mulOrIdentity(h_lo[i], u).add(mulOrIdentity(h_hi[i], u_inv));
        }
        n = half;
    }

    // Step 5 base case: the two remaining scalars ARE the proof tail.
    return .{ .l_vec = l_out, .r_vec = r_out, .a = a[0], .b = b[0] };
}

/// **FABLE CORE — implemented.** See the module doc comment for the
/// fold-and-check equation (the single-multi-exponentiation form). Never
/// panics on a malformed/adversarial `proof` — every structural mismatch
/// or failed equation simply returns `false`.
pub fn verifyIpa(
    transcript: *Transcript,
    g_vec: []const Ristretto255,
    h_vec: []const Ristretto255,
    q: Ristretto255,
    p: Ristretto255,
    proof: InnerProductProof,
) bool {
    const n = g_vec.len;
    if (h_vec.len != n or n == 0 or !std.math.isPowerOfTwo(n)) return false;
    const rounds: usize = std.math.log2_int(usize, n);
    if (proof.l_vec.len != rounds or proof.r_vec.len != rounds) return false;

    // `rounds <= 63` always (n fits in a usize), so a fixed stack array
    // keeps this verifier allocation-free (its signature has no
    // allocator).
    var u: [64][32]u8 = undefined;
    var u_inv: [64][32]u8 = undefined;
    for (0..rounds) |j| {
        // Replay the prover's exact transcript ops: L/R bound before u.
        transcript.appendPoint("L", proof.l_vec[j]);
        transcript.appendPoint("R", proof.r_vec[j]);
        u[j] = transcript.challengeScalar("u");
        u_inv[j] = invertScalar(u[j]);
    }

    // §3.1's single-multi-exponentiation form: rather than folding a
    // shrinking P' round by round, fold the ORIGINAL generators by the
    // accumulated per-index challenge products
    //   s_i     = prod_j u_j^{+1 if bit (rounds-1-j) of i is 1, else -1}
    //   s_i^{-1} = the same product with the exponents negated
    // (round j consumes index bit rounds-1-j: round 0 splits on the TOP
    // bit) and check
    //   <a*s, G> + <b*s^{-1}, H> + (a*b)*Q
    //     == P + sum_j (u_j^2 * L_j + u_j^{-2} * R_j).
    // The per-index products s_i are computed the O(n) incremental way
    // (dalek's trick) instead of an O(n·log n) per-index inner loop:
    //   s_0 = prod_j u_j^{-1};  setting the highest bit of an index i
    //   multiplies s by the corresponding u_j^2.
    // The inverse product s_i^{-1} needs no per-index inversion: bit-
    // complementing the index inverts every factor, so s_i^{-1} = s_{n-1-i}.
    //
    // This whole multi-exponentiation is over PUBLIC data (the proof, the
    // public generators/Q/P, and the challenges replayed from the proof), so
    // it uses the VARTIME Pippenger MSM (`multiScalarMulVartime`) — the
    // standard verifier speed-up. (The prover's MSMs are over secret
    // witness scalars and stay constant-time; see `proveIpa`.)
    //
    // The verifier has no allocator by signature, so this scratch comes from
    // the page allocator and every failure — including OOM — returns false
    // (fail-closed), never panics; all of it is public, so no constant-time
    // concern applies (matching `rangeproof.verify`).
    const alloc = std.heap.page_allocator;

    var allinv = scalarvec.one;
    for (0..rounds) |j| allinv = scalar.mul(allinv, u_inv[j]);

    const s = alloc.alloc([32]u8, n) catch return false;
    defer alloc.free(s);
    s[0] = allinv;
    for (1..n) |i| {
        const lg = std.math.log2_int(usize, i); // floor(log2 i), i >= 1
        const k = @as(usize, 1) << @intCast(lg);
        const jj = rounds - 1 - lg;
        const u_sq = scalar.mul(u[jj], u[jj]);
        s[i] = scalar.mul(s[i - k], u_sq);
    }

    // lhs = <a*s, G> + <b*s^{-1}, H> + (a*b)*Q as one (2n+1)-term MSM.
    const terms = 2 * n + 1;
    const msm_scalars = alloc.alloc([32]u8, terms) catch return false;
    defer alloc.free(msm_scalars);
    const msm_points = alloc.alloc(Ristretto255, terms) catch return false;
    defer alloc.free(msm_points);
    for (0..n) |i| {
        msm_scalars[i] = scalar.mul(proof.a, s[i]);
        msm_points[i] = g_vec[i];
        msm_scalars[n + i] = scalar.mul(proof.b, s[n - 1 - i]);
        msm_points[n + i] = h_vec[i];
    }
    msm_scalars[2 * n] = scalar.mul(proof.a, proof.b);
    msm_points[2 * n] = q;
    const lhs = scalarvec.multiScalarMulVartime(msm_scalars, msm_points) catch return false;

    // rhs = P + sum_j (u_j^2 * L_j + u_j^{-2} * R_j) — only 2*rounds terms
    // (logarithmic in n), so a plain accumulation is already cheap.
    var rhs = p;
    for (0..rounds) |j| {
        rhs = rhs.add(mulOrIdentity(proof.l_vec[j], scalar.mul(u[j], u[j])));
        rhs = rhs.add(mulOrIdentity(proof.r_vec[j], scalar.mul(u_inv[j], u_inv[j])));
    }

    return lhs.equivalent(rhs);
}

// ── tests (codec + mechanical preconditions — REAL, ungated) ───────────────

fn fakeProof(allocator: std.mem.Allocator, rounds: usize) !InnerProductProof {
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
    return .{
        .l_vec = l_vec,
        .r_vec = r_vec,
        .a = [_]u8{7} ++ [_]u8{0} ** 31,
        .b = [_]u8{9} ++ [_]u8{0} ** 31,
    };
}

test "InnerProductProof: byte round-trip, rounds=3" {
    const proof = try fakeProof(std.testing.allocator, 3);
    defer proof.deinit(std.testing.allocator);

    const bytes = try proof.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 4 + 3 * 64 + 64), bytes.len);

    const back = try InnerProductProof.fromBytesAlloc(std.testing.allocator, bytes);
    defer back.deinit(std.testing.allocator);

    try std.testing.expectEqual(proof.l_vec.len, back.l_vec.len);
    for (proof.l_vec, back.l_vec) |a, b| try std.testing.expect(a.equivalent(b));
    for (proof.r_vec, back.r_vec) |a, b| try std.testing.expect(a.equivalent(b));
    try std.testing.expectEqualSlices(u8, &proof.a, &back.a);
    try std.testing.expectEqualSlices(u8, &proof.b, &back.b);
}

test "InnerProductProof: byte round-trip, rounds=0 (n=1 base case)" {
    const proof = try fakeProof(std.testing.allocator, 0);
    defer proof.deinit(std.testing.allocator);
    const bytes = try proof.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 4 + 64), bytes.len);
    const back = try InnerProductProof.fromBytesAlloc(std.testing.allocator, bytes);
    defer back.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &proof.a, &back.a);
    try std.testing.expectEqualSlices(u8, &proof.b, &back.b);
}

test "InnerProductProof.fromBytesAlloc: rejects truncated / wrong-length input" {
    const proof = try fakeProof(std.testing.allocator, 2);
    defer proof.deinit(std.testing.allocator);
    const bytes = try proof.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(bytes);

    try std.testing.expectError(error.InvalidEncoding, InnerProductProof.fromBytesAlloc(std.testing.allocator, bytes[0 .. bytes.len - 1]));
    try std.testing.expectError(error.InvalidEncoding, InnerProductProof.fromBytesAlloc(std.testing.allocator, bytes[0..2]));

    var too_long = try std.testing.allocator.alloc(u8, bytes.len + 1);
    defer std.testing.allocator.free(too_long);
    @memcpy(too_long[0..bytes.len], bytes);
    too_long[bytes.len] = 0;
    try std.testing.expectError(error.InvalidEncoding, InnerProductProof.fromBytesAlloc(std.testing.allocator, too_long));
}

test "InnerProductProof.fromBytesAlloc: rejects a non-canonical point encoding" {
    const proof = try fakeProof(std.testing.allocator, 1);
    defer proof.deinit(std.testing.allocator);
    const bytes = try proof.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(bytes);

    var corrupt = try std.testing.allocator.dupe(u8, bytes);
    defer std.testing.allocator.free(corrupt);
    // All-0xff is not a valid canonical Ristretto255 encoding.
    @memset(corrupt[4..36], 0xff);
    try std.testing.expectError(error.InvalidEncoding, InnerProductProof.fromBytesAlloc(std.testing.allocator, corrupt));
}

test "proveIpa: length mismatch rejected before reaching the stub" {
    var t = Transcript.init("bulletproofs/ipa/v1");
    const g_vec = [_]Ristretto255{ Ristretto255.basePoint, Ristretto255.basePoint.dbl() };
    const h_vec = [_]Ristretto255{ Ristretto255.basePoint, Ristretto255.basePoint.dbl() };
    const a = [_][32]u8{[_]u8{1} ++ [_]u8{0} ** 31};
    const b = [_][32]u8{ [_]u8{1} ++ [_]u8{0} ** 31, [_]u8{1} ++ [_]u8{0} ** 31 };
    try std.testing.expectError(
        error.LengthMismatch,
        proveIpa(std.testing.allocator, &t, &g_vec, &h_vec, Ristretto255.basePoint, &a, &b),
    );
}

test "proveIpa: non-power-of-two length rejected before reaching the stub" {
    var t = Transcript.init("bulletproofs/ipa/v1");
    const g_vec = [_]Ristretto255{ Ristretto255.basePoint, Ristretto255.basePoint.dbl(), Ristretto255.basePoint.mul([_]u8{3} ++ [_]u8{0} ** 31) catch unreachable };
    const h_vec = g_vec;
    const a = [_][32]u8{ [_]u8{1} ++ [_]u8{0} ** 31, [_]u8{1} ++ [_]u8{0} ** 31, [_]u8{1} ++ [_]u8{0} ** 31 };
    const b = a;
    try std.testing.expectError(
        error.NotPowerOfTwo,
        proveIpa(std.testing.allocator, &t, &g_vec, &h_vec, Ristretto255.basePoint, &a, &b),
    );
}

test "proveIpa: zero length rejected before reaching the stub" {
    var t = Transcript.init("bulletproofs/ipa/v1");
    try std.testing.expectError(
        error.NotPowerOfTwo,
        proveIpa(std.testing.allocator, &t, &.{}, &.{}, Ristretto255.basePoint, &.{}, &.{}),
    );
}

// ── fuzz: untrusted-input decoder never panics ──────────────────────────────

fn fuzzFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const proof = InnerProductProof.fromBytesAlloc(std.testing.allocator, buf[0..len]) catch return;
    proof.deinit(std.testing.allocator);
}
test "fuzz InnerProductProof.fromBytesAlloc never panics" {
    try std.testing.fuzz({}, fuzzFromBytesAlloc, .{});
}
