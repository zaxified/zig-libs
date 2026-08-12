// SPDX-License-Identifier: MIT

//! credential — Coconut's Pointcheval-Sanders (PS) re-randomizable
//! credential: partial issuance, threshold aggregation, and the
//! selective-disclosure show/verify NIZK (Sonnino-Bano-Al-Bassam-Danezis,
//! NDSS 2019, §4.2 `Sign`/`AggCred`/`ProveCred`/`VerifyCred`). A credential
//! is a PS signature `σ = (h, s)` on the attribute vector, where
//! `s = h^{x + Σ mᵢ yᵢ}` under the group secret key `(x, y_i)` and `h` is
//! the common base every authority derives from the public attribute
//! commitment (`params.commonBase`).
//!
//! ## What is REAL here (harness teeth, no gate)
//!
//! - `psSignWithSecret` — a single-signer PS signature from KNOWN scalars
//!   `(x, y_i)`: `s = [x + Σ mᵢ yᵢ] h`. Pure `Fr`/`G1` arithmetic. This is
//!   the mechanical oracle that stands in for a correctly threshold-
//!   aggregated credential (by construction the two must be byte-equal —
//!   Lagrange interpolation reconstructs the SAME `x + Σ mᵢ yᵢ` exponent).
//! - `psVerifyPlain` — the PS pairing-verify equation `e(h, α · Π βᵢ^{mᵢ})
//!   == e(s, g2)` with the mandatory `h ≠ 1` guard. This is the
//!   verification math with teeth: it accepts a valid `psSignWithSecret`
//!   output and rejects any tampered `s` or wrong attribute — proven in the
//!   harness + the `BrokenCoconut` positive control BEFORE any gated core
//!   exists.
//! - the wire codecs for `Credential`/`PartialCredential`/`ShowProof`.
//!
//! ## The FABLE CORE (`gate.fable_core_implemented` — now `true`)
//!
//! - `signPartial` — an authority's partial PS signature under its Shamir
//!   SHARE of `(x, y_i)`.
//! - `aggregateCredential` — Lagrange-in-EXPONENT recombination of `t`
//!   partial signatures (sharing a common `h`) into one PS credential.
//! - `proveCredential` / `verifyCredential` — the genuinely Fable-hard
//!   part: re-randomise `σ → σ'`, build the ZK commitment `κ`/`ν`, and run
//!   the Fiat-Shamir selective-disclosure NIZK proving knowledge of the
//!   HIDDEN attributes + the blinding, checked against the recomputed
//!   challenge and the `e(σ₁', κ) == e(σ₂'·ν, g2)` pairing equation. The
//!   classic real-world break — omitting a commitment (e.g. `ν` or a
//!   disclosed index) from the challenge hash — must be caught by the
//!   soundness controls, and a self-consistent proof can PASS while being
//!   unsound, so there is no external byte-exact anchor for it (see SPEC's
//!   tier finding).

const std = @import("std");
const bls = @import("bls12_381");
const gate = @import("gate.zig");
const lagrange = @import("lagrange.zig");
const keys = @import("keys.zig");
const params_mod = @import("params.zig");

const g1 = bls.g1;
const g2 = bls.g2;
const Fr = bls.Fr;

const Parameters = params_mod.Parameters;
const SecretKey = keys.SecretKey;
const SecretKeyShare = keys.SecretKeyShare;
const VerificationKey = keys.VerificationKey;

pub const CoconutError = error{
    /// Attribute-count mismatch between two operands.
    MismatchedAttributes,
    /// Fewer than `t` partial signatures supplied to aggregation.
    NotEnoughPartials,
    /// Partial signatures do not all share the same base point `h` — they
    /// cannot be Lagrange-combined (each authority must sign under the
    /// SAME `commonBase`).
    InconsistentBase,
    /// A serialized artifact was malformed / not a valid curve point or
    /// scalar.
    InvalidEncoding,
    /// The disclosure mask length or disclosed-value count is inconsistent.
    InvalidDisclosure,
} || keys.KeysError;

// ── credential types ────────────────────────────────────────────────────────

/// A PS credential `σ = (h, s)` — the aggregated, unblinded credential.
pub const Credential = struct {
    h: g1.Affine,
    s: g1.Affine,

    pub const encoded_bytes = 2 * g1.compressed_bytes; // 96

    pub fn toBytes(self: Credential) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        out[0..g1.compressed_bytes].* = g1.toBytesCompressed(self.h);
        out[g1.compressed_bytes..].* = g1.toBytesCompressed(self.s);
        return out;
    }

    pub fn fromBytes(bytes: [encoded_bytes]u8) CoconutError!Credential {
        const h = g1.fromBytesCompressed(bytes[0..g1.compressed_bytes].*) catch return error.InvalidEncoding;
        const s = g1.fromBytesCompressed(bytes[g1.compressed_bytes..].*) catch return error.InvalidEncoding;
        return .{ .h = h, .s = s };
    }
};

/// One authority's partial credential `σⱼ = (h, sⱼ)` at index `j`.
pub const PartialCredential = struct {
    index: u64,
    h: g1.Affine,
    s: g1.Affine,

    pub const encoded_bytes = 8 + 2 * g1.compressed_bytes; // 104

    pub fn toBytes(self: PartialCredential) [encoded_bytes]u8 {
        var out: [encoded_bytes]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], self.index, .big);
        out[8..][0..g1.compressed_bytes].* = g1.toBytesCompressed(self.h);
        out[8 + g1.compressed_bytes ..].* = g1.toBytesCompressed(self.s);
        return out;
    }

    pub fn fromBytes(bytes: [encoded_bytes]u8) CoconutError!PartialCredential {
        const index = std.mem.readInt(u64, bytes[0..8], .big);
        const h = g1.fromBytesCompressed(bytes[8..][0..g1.compressed_bytes].*) catch return error.InvalidEncoding;
        const s = g1.fromBytesCompressed(bytes[8 + g1.compressed_bytes ..].*) catch return error.InvalidEncoding;
        return .{ .index = index, .h = h, .s = s };
    }
};

/// A selective-disclosure show proof (§4.2 `ProveCred` output): the
/// re-randomised credential `(σ₁', σ₂')`, the ZK commitments `κ`/`ν`, the
/// Fiat-Shamir `challenge`, and the responses (`response_r` for the
/// blinding, one `responses_m` entry per HIDDEN attribute in ascending
/// attribute-index order). `disclosed` (length `q`) records which
/// attribute indices are revealed. Heap-owned slices; call `deinit`.
pub const ShowProof = struct {
    sigma1: g1.Affine,
    sigma2: g1.Affine,
    kappa: g2.Affine,
    nu: g1.Affine,
    challenge: Fr,
    response_r: Fr,
    responses_m: []Fr,
    disclosed: []bool,

    pub fn deinit(self: ShowProof, allocator: std.mem.Allocator) void {
        allocator.free(self.responses_m);
        allocator.free(self.disclosed);
    }

    /// Self-describing wire form: `q:u16 ‖ disclosed[q] ‖ σ₁(48) ‖ σ₂(48)
    /// ‖ κ(96) ‖ ν(48) ‖ challenge(32) ‖ response_r(32) ‖ responses_m[k]
    /// (32 each)`, where `k` = number of hidden attributes = zeros in
    /// `disclosed`. Caller frees the returned slice.
    pub fn toBytes(self: ShowProof, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const q = self.disclosed.len;
        const k = self.responses_m.len;
        const len = 2 + q + 2 * g1.compressed_bytes + g2.compressed_bytes + g1.compressed_bytes + 2 * 32 + k * 32;
        var out = try allocator.alloc(u8, len);
        errdefer allocator.free(out);
        var off: usize = 0;
        std.mem.writeInt(u16, out[0..2], @intCast(q), .big);
        off = 2;
        for (self.disclosed) |d| {
            out[off] = if (d) 1 else 0;
            off += 1;
        }
        out[off..][0..g1.compressed_bytes].* = g1.toBytesCompressed(self.sigma1);
        off += g1.compressed_bytes;
        out[off..][0..g1.compressed_bytes].* = g1.toBytesCompressed(self.sigma2);
        off += g1.compressed_bytes;
        out[off..][0..g2.compressed_bytes].* = g2.toBytesCompressed(self.kappa);
        off += g2.compressed_bytes;
        out[off..][0..g1.compressed_bytes].* = g1.toBytesCompressed(self.nu);
        off += g1.compressed_bytes;
        out[off..][0..32].* = self.challenge.toBytes();
        off += 32;
        out[off..][0..32].* = self.response_r.toBytes();
        off += 32;
        for (self.responses_m) |m| {
            out[off..][0..32].* = m.toBytes();
            off += 32;
        }
        return out;
    }

    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) CoconutError!ShowProof {
        if (bytes.len < 2) return error.InvalidEncoding;
        const q = std.mem.readInt(u16, bytes[0..2], .big);
        const floor = 2 + @as(usize, q) + 2 * g1.compressed_bytes + g2.compressed_bytes + g1.compressed_bytes + 2 * 32;
        if (bytes.len < floor or (bytes.len - floor) % 32 != 0) return error.InvalidEncoding;
        const k = (bytes.len - floor) / 32;

        const disclosed = try allocator.alloc(bool, q);
        errdefer allocator.free(disclosed);
        var off: usize = 2;
        var revealed: usize = 0;
        for (disclosed) |*d| {
            if (bytes[off] > 1) return error.InvalidEncoding;
            d.* = bytes[off] == 1;
            if (d.*) revealed += 1;
            off += 1;
        }
        // k hidden responses must match q - revealed.
        if (k + revealed != q) return error.InvalidDisclosure;

        const sigma1 = g1.fromBytesCompressed(bytes[off..][0..g1.compressed_bytes].*) catch return error.InvalidEncoding;
        off += g1.compressed_bytes;
        const sigma2 = g1.fromBytesCompressed(bytes[off..][0..g1.compressed_bytes].*) catch return error.InvalidEncoding;
        off += g1.compressed_bytes;
        const kappa = g2.fromBytesCompressed(bytes[off..][0..g2.compressed_bytes].*) catch return error.InvalidEncoding;
        off += g2.compressed_bytes;
        const nu = g1.fromBytesCompressed(bytes[off..][0..g1.compressed_bytes].*) catch return error.InvalidEncoding;
        off += g1.compressed_bytes;
        const challenge = Fr.fromBytes(bytes[off..][0..32].*) catch return error.InvalidEncoding;
        off += 32;
        const response_r = Fr.fromBytes(bytes[off..][0..32].*) catch return error.InvalidEncoding;
        off += 32;
        const responses_m = try allocator.alloc(Fr, k);
        errdefer allocator.free(responses_m);
        for (responses_m) |*m| {
            m.* = Fr.fromBytes(bytes[off..][0..32].*) catch return error.InvalidEncoding;
            off += 32;
        }
        return .{
            .sigma1 = sigma1,
            .sigma2 = sigma2,
            .kappa = kappa,
            .nu = nu,
            .challenge = challenge,
            .response_r = response_r,
            .responses_m = responses_m,
            .disclosed = disclosed,
        };
    }
};

// ── REAL mechanical oracles (harness teeth) ─────────────────────────────────

/// The signing exponent `x + Σ mᵢ yᵢ` for a KNOWN secret key — the scalar
/// half of a PS signature. REAL.
pub fn signingExponent(sk: SecretKey, attributes: []const Fr) Fr {
    std.debug.assert(sk.ys.len == attributes.len);
    var e = sk.x;
    for (sk.ys, attributes) |y, m| e = e.add(y.mul(m));
    return e;
}

/// A single-signer PS credential `σ = (h, [x + Σ mᵢ yᵢ] h)` from a KNOWN
/// secret key. REAL, mechanical — the oracle a correct threshold
/// aggregation must reproduce byte-for-byte.
pub fn psSignWithSecret(sk: SecretKey, h: g1.Affine, attributes: []const Fr) Credential {
    const e = signingExponent(sk, attributes);
    const s = g1.Jacobian.fromAffine(h).scalarMul(e).toAffine();
    return .{ .h = h, .s = s };
}

/// The commitment `κ = α · Π βᵢ^{mᵢ} ∈ G2` for a fully-disclosed
/// attribute vector (no ZK blinding). REAL.
pub fn kappaPlain(vk: VerificationKey, attributes: []const Fr) g2.Affine {
    std.debug.assert(vk.betas.len == attributes.len);
    var acc = g2.Jacobian.fromAffine(vk.alpha);
    for (vk.betas, attributes) |b, m| acc = acc.add(g2.Jacobian.fromAffine(b).scalarMul(m));
    return acc.toAffine();
}

/// The PS pairing-verify equation `e(h, α · Π βᵢ^{mᵢ}) == e(s, g2)` with
/// the mandatory `h ≠ 1` guard, for a fully-disclosed credential. REAL —
/// the verification math with teeth (accepts a valid `psSignWithSecret`
/// output, rejects any tampered `s`).
pub fn psVerifyPlain(vk: VerificationKey, cred: Credential, attributes: []const Fr) bool {
    if (g1.Jacobian.fromAffine(cred.h).isIdentity()) return false;
    const kappa = kappaPlain(vk, attributes);
    const neg_s = g1.Jacobian.fromAffine(cred.s).negate().toAffine();
    // e(h, κ) · e(−s, g2) == 1  ⇔  e(h, κ) == e(s, g2).
    return bls.pairing.pairingCheck(&.{
        .{ .p = cred.h, .q = kappa },
        .{ .p = neg_s, .q = g2.Affine.generator },
    });
}

// ── GATED Fable cores ───────────────────────────────────────────────────────

/// Domain-separation tag for the show-proof Fiat-Shamir challenge. Names
/// the scheme, the curve, and the transcript version — bumping the wire
/// or transcript layout MUST bump the version.
const show_challenge_dst = "COCONUT-BLS12381_XMD:SHA-512_SHOW-V01_CHALLENGE_";

/// The Fiat-Shamir challenge for the selective-disclosure show proof —
/// SHA-512 over the FULL transcript, reduced into `Fr` (`Fr.reduceWide`,
/// the RFC 9380 hash-to-field reduction shape). Shared verbatim by
/// `proveCredential` (with the prover's fresh witnesses `Aw`/`Bw`) and
/// `verifyCredential` (with the recomputed `Aw'`/`Bw'`), so any
/// divergence in ANY hashed element makes the recomputed challenge
/// mismatch and the proof reject.
///
/// Transcript, in order (every field fixed-width given `q`, so the
/// encoding is injective — no length-extension/concatenation ambiguity):
///
///  1. `show_challenge_dst`             — domain separation (scheme/curve/version);
///  2. `q` (u64 BE)                     — attribute count, frames all vectors;
///  3. `hs[0..q]` (48 B each)           — the attribute generators: binds the
///                                        parameter set the commitment/base
///                                        derivation lives in;
///  4. `vk.alpha` (96 B), `vk.betas[0..q]` (96 B each) — the verifier key the
///                                        statement is relative to: a proof
///                                        must not transplant to another
///                                        authority set's key;
///  5. `σ₁'`, `σ₂'` (48 B each)         — the re-randomised credential being
///                                        shown (σ₁' is a NIZK base; σ₂' ties
///                                        the proof to the exact credential
///                                        half checked by the pairing);
///  6. `κ` (96 B), `ν` (48 B)           — the statement group elements;
///  7. `Aw` (96 B), `Bw` (48 B)         — the sigma-protocol commitments (the
///                                        strictly load-bearing FS binding:
///                                        omit either and the challenge is
///                                        forgeable straight-line);
///  8. `disclosed` mask (q bytes 0/1)   — WHICH attribute indices are claimed
///                                        revealed;
///  9. `n_disclosed` (u64 BE), then per disclosed index ascending:
///     `index` (u64 BE) ‖ `value` (32 B) — the claimed revealed values
///                                        themselves.
fn showChallenge(
    parameters: Parameters,
    vk: VerificationKey,
    sigma1: g1.Affine,
    sigma2: g1.Affine,
    kappa: g2.Affine,
    nu: g1.Affine,
    aw: g2.Affine,
    bw: g1.Affine,
    disclosed: []const bool,
    disclosed_values: []const Fr,
) Fr {
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    hasher.update(show_challenge_dst);
    var u64buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &u64buf, @as(u64, parameters.q), .big);
    hasher.update(&u64buf);
    for (parameters.hs) |h| hasher.update(&g1.toBytesCompressed(h));
    hasher.update(&g2.toBytesCompressed(vk.alpha));
    for (vk.betas) |b| hasher.update(&g2.toBytesCompressed(b));
    hasher.update(&g1.toBytesCompressed(sigma1));
    hasher.update(&g1.toBytesCompressed(sigma2));
    hasher.update(&g2.toBytesCompressed(kappa));
    hasher.update(&g1.toBytesCompressed(nu));
    hasher.update(&g2.toBytesCompressed(aw));
    hasher.update(&g1.toBytesCompressed(bw));
    for (disclosed) |d| hasher.update(&[1]u8{if (d) 1 else 0});
    std.mem.writeInt(u64, &u64buf, @as(u64, disclosed_values.len), .big);
    hasher.update(&u64buf);
    var k: usize = 0;
    for (disclosed, 0..) |d, i| {
        if (!d) continue;
        std.mem.writeInt(u64, &u64buf, @as(u64, i), .big);
        hasher.update(&u64buf);
        hasher.update(&disclosed_values[k].toBytes());
        k += 1;
    }
    var digest: [64]u8 = undefined;
    hasher.final(&digest);
    return Fr.reduceWide(&digest);
}

/// §4.2 `Sign` (threshold, per-authority): the authority holding Shamir
/// share `(x(j), y_i(j))` produces `σⱼ = (h, [x(j) + Σ mᵢ yᵢ(j)] h)` over
/// the caller-supplied common base `h` (`params.commonBase` — every
/// authority MUST use the same `h` or the partials cannot be Lagrange-
/// combined). GATED core.
pub fn signPartial(share: SecretKeyShare, h: g1.Affine, attributes: []const Fr) CoconutError!PartialCredential {
    if (share.ys.len != attributes.len) return error.MismatchedAttributes;
    // The share is a point-evaluation of the master key vector, so the
    // partial signing exponent is the SAME `x + Σ mᵢ yᵢ` form over the
    // share's scalars — Lagrange over these exponents reconstructs the
    // group exponent by linearity.
    const as_sk = SecretKey{ .x = share.x, .ys = share.ys };
    const e = signingExponent(as_sk, attributes);
    const s = g1.Jacobian.fromAffine(h).scalarMul(e).toAffine();
    return .{ .index = share.index, .h = h, .s = s };
}

/// §4.4 `AggCred`: Lagrange-in-EXPONENT recombination of `t` (or more)
/// partial signatures — all sharing the SAME base `h` — into a single PS
/// credential `σ = (h, Π sⱼ^{lⱼ})`, where `lⱼ` is the Lagrange coefficient
/// (`lagrange.coefficientAtZero`) for authority `j`'s index. The result
/// must be byte-equal to `psSignWithSecret` under the reconstructed group
/// key. GATED core. `partials` must have distinct nonzero indices; at
/// least `t` are required. Caller supplies `t` for the count check.
pub fn aggregateCredential(
    allocator: std.mem.Allocator,
    partials: []const PartialCredential,
    t: u64,
) CoconutError!Credential {
    if (t == 0 or partials.len < t) return error.NotEnoughPartials;
    const h = partials[0].h;
    for (partials[1..]) |p| {
        if (!(p.h.x.eql(h.x) and p.h.y.eql(h.y) and p.h.infinity == h.infinity))
            return error.InconsistentBase;
    }
    // Public authority indices for the Lagrange coefficients at x = 0.
    // Duplicate / zero indices are rejected inside `coefficientAtZero`.
    const indices = try allocator.alloc(u64, partials.len);
    defer allocator.free(indices);
    for (indices, partials) |*ix, p| ix.* = p.index;

    // Lagrange-in-EXPONENT: s = Σ [lⱼ] sⱼ = [Σ lⱼ (x(j) + Σ mᵢ yᵢ(j))] h
    // = [x + Σ mᵢ yᵢ] h — byte-equal to the single-signer oracle.
    var acc = g1.Jacobian.identity;
    for (partials) |p| {
        const l = try lagrange.coefficientAtZero(indices, p.index);
        acc = acc.add(g1.Jacobian.fromAffine(p.s).scalarMul(l));
    }
    return .{ .h = h, .s = acc.toAffine() };
}

/// §4.2 `ProveCred`: re-randomise `σ → σ' = (σ₁', σ₂') = ([r'] h, [r'] s)`,
/// build the ZK commitment `κ = α · Π βᵢ^{mᵢ} · [r] g2` and `ν = [r] σ₁'`,
/// and run the Fiat-Shamir selective-disclosure NIZK proving knowledge of
/// the HIDDEN attributes `{mᵢ : ¬disclosed[i]}` and the blinding `r`.
/// `disclosed` (length `q`) selects revealed indices; `attributes` is the
/// full length-`q` vector. GATED core — the genuinely Fable-hard construction
/// (the challenge MUST commit to `κ`, `ν`, `σ'`, and every disclosed
/// index/value or the proof is unsound). Caller frees the returned proof.
///
/// **Entropy.** `io` supplies the re-randomisation scalars `r'`/`r` and the
/// Sigma-protocol witness nonces `r̃`/`m̃ⱼ`. `std.Io.random` is a CSPRNG by
/// contract, and that is load-bearing here: a stream that REPEATS across two
/// shows (a re-seeded `DefaultPrng`, PRNG state inherited across a `fork`)
/// produces two transcripts with identical witnesses but different challenges
/// `c` — different `κ`/`ν`/disclosure set means a different Fiat-Shamir hash.
/// Subtracting the two responses recovers `r̃`, hence the blinding `r` and
/// every HIDDEN attribute, by the standard two-transcript extraction. A
/// verifier who simply watches two shows learns exactly what selective
/// disclosure exists to withhold. Tests use `proveCredentialSeededForTest`.
pub fn proveCredential(
    allocator: std.mem.Allocator,
    io: std.Io,
    parameters: Parameters,
    vk: VerificationKey,
    cred: Credential,
    attributes: []const Fr,
    disclosed: []const bool,
) CoconutError!ShowProof {
    return proveCredentialFrom(allocator, .{ .io = io }, parameters, vk, cred, attributes, disclosed);
}

/// **TEST ONLY** — `proveCredential` over a caller-seeded `std.Random`, so a
/// suite can reproduce a show. Two shows from the same seed leak the hidden
/// attributes to anyone who sees both (see `proveCredential`'s entropy note).
/// Production callers want `proveCredential`.
pub fn proveCredentialSeededForTest(
    allocator: std.mem.Allocator,
    random: std.Random,
    parameters: Parameters,
    vk: VerificationKey,
    cred: Credential,
    attributes: []const Fr,
    disclosed: []const bool,
) CoconutError!ShowProof {
    return proveCredentialFrom(allocator, .{ .seeded_for_test = random }, parameters, vk, cred, attributes, disclosed);
}

fn proveCredentialFrom(
    allocator: std.mem.Allocator,
    entropy: keys.Entropy,
    parameters: Parameters,
    vk: VerificationKey,
    cred: Credential,
    attributes: []const Fr,
    disclosed: []const bool,
) CoconutError!ShowProof {
    const q = parameters.q;
    if (attributes.len != q or vk.betas.len != q) return error.MismatchedAttributes;
    if (disclosed.len != q) return error.InvalidDisclosure;
    var revealed: usize = 0;
    for (disclosed) |d| revealed += @intFromBool(d);
    const hidden = q - revealed;

    // Re-randomise σ → σ' = ([r'] h, [r'] s). r' MUST be nonzero or σ₁'
    // degenerates to the identity (which VerifyCred rejects — e(1, κ)
    // is trivially satisfiable).
    var r_prime = blk: {
        while (true) {
            const c = entropy.scalar();
            if (!c.isZero()) break :blk c;
        }
    };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&r_prime));
    var r = entropy.scalar();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&r));
    const sigma1_jac = g1.Jacobian.fromAffine(cred.h).scalarMul(r_prime);
    const sigma1 = sigma1_jac.toAffine();
    const sigma2 = g1.Jacobian.fromAffine(cred.s).scalarMul(r_prime).toAffine();

    // Statement: κ = α · Π βᵢ^{mᵢ} (ALL attributes) · [r] g2, ν = [r] σ₁'.
    const g2gen = g2.Jacobian.fromAffine(g2.Affine.generator);
    const kappa = g2.Jacobian.fromAffine(kappaPlain(vk, attributes)).add(g2gen.scalarMul(r)).toAffine();
    const nu = sigma1_jac.scalarMul(r).toAffine();

    // Sigma-protocol commitments over fresh witnesses: one nonce for the
    // blinding r, one per HIDDEN attribute:
    //   Aw = [r̃] g2 + Σ_{hidden j} [m̃ⱼ] βⱼ   (the κ-side witness)
    //   Bw = [r̃] σ₁'                          (the ν-side witness)
    var r_tilde = entropy.scalar();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&r_tilde));
    const m_tilde = try allocator.alloc(Fr, hidden);
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(m_tilde));
        allocator.free(m_tilde);
    }
    for (m_tilde) |*m| m.* = entropy.scalar();

    var aw_acc = g2gen.scalarMul(r_tilde);
    {
        var k: usize = 0;
        for (disclosed, vk.betas) |d, beta| {
            if (d) continue;
            aw_acc = aw_acc.add(g2.Jacobian.fromAffine(beta).scalarMul(m_tilde[k]));
            k += 1;
        }
    }
    const aw = aw_acc.toAffine();
    const bw = sigma1_jac.scalarMul(r_tilde).toAffine();

    // Fiat-Shamir challenge over the FULL transcript (see showChallenge).
    const disclosed_values = try allocator.alloc(Fr, revealed);
    defer allocator.free(disclosed_values);
    {
        var k: usize = 0;
        for (disclosed, attributes) |d, m| {
            if (!d) continue;
            disclosed_values[k] = m;
            k += 1;
        }
    }
    const challenge = showChallenge(parameters, vk, sigma1, sigma2, kappa, nu, aw, bw, disclosed, disclosed_values);

    // Responses: z = witness + c · secret (ascending attribute-index
    // order for the hidden responses, matching the verifier's walk).
    const response_r = r_tilde.add(challenge.mul(r));
    const responses_m = try allocator.alloc(Fr, hidden);
    errdefer allocator.free(responses_m);
    {
        var k: usize = 0;
        for (disclosed, attributes) |d, m| {
            if (d) continue;
            responses_m[k] = m_tilde[k].add(challenge.mul(m));
            k += 1;
        }
    }
    const disclosed_copy = try allocator.dupe(bool, disclosed);
    return .{
        .sigma1 = sigma1,
        .sigma2 = sigma2,
        .kappa = kappa,
        .nu = nu,
        .challenge = challenge,
        .response_r = response_r,
        .responses_m = responses_m,
        .disclosed = disclosed_copy,
    };
}

/// §4.2 `VerifyCred`: recompute the Fiat-Shamir challenge from the proof's
/// transcript (`κ ‖ ν ‖ σ' ‖ disclosed indices/values ‖ vk`), check every
/// NIZK response equation, enforce `σ₁' ≠ 1`, and finally verify the PS
/// pairing equation `e(σ₁', κ) == e(σ₂' · ν, g2)`. `disclosed_values`
/// holds the revealed attribute scalars in ascending index order (matching
/// `proof.disclosed`). Returns `true` iff every check passes. GATED core.
pub fn verifyCredential(
    allocator: std.mem.Allocator,
    parameters: Parameters,
    vk: VerificationKey,
    proof: ShowProof,
    disclosed_values: []const Fr,
) CoconutError!bool {
    _ = allocator; // recompute-commitment verification is allocation-free
    const q = parameters.q;
    if (vk.betas.len != q) return error.MismatchedAttributes;
    if (proof.disclosed.len != q) return error.InvalidDisclosure;
    var revealed: usize = 0;
    for (proof.disclosed) |d| revealed += @intFromBool(d);
    if (disclosed_values.len != revealed) return error.InvalidDisclosure;
    if (proof.responses_m.len != q - revealed) return error.InvalidDisclosure;

    // σ₁' ≠ 1 — mandatory: with σ₁' = 1 the pairing equation is trivially
    // satisfiable by σ₂'·ν = 1 without any credential.
    const sigma1_jac = g1.Jacobian.fromAffine(proof.sigma1);
    if (sigma1_jac.isIdentity()) return false;

    // Public offset A = α · Π_{disclosed i} βᵢ^{vᵢ} from the CLAIMED
    // disclosed values — a wrong claim shifts A, hence Aw', hence the
    // recomputed challenge.
    var a_acc = g2.Jacobian.fromAffine(vk.alpha);
    {
        var k: usize = 0;
        for (proof.disclosed, vk.betas) |d, beta| {
            if (!d) continue;
            a_acc = a_acc.add(g2.Jacobian.fromAffine(beta).scalarMul(disclosed_values[k]));
            k += 1;
        }
    }

    // Recompute the sigma commitments from the responses:
    //   Aw' = [z_r] g2 + Σ_{hidden j} [zⱼ] βⱼ − [c](κ − A)
    //   Bw' = [z_r] σ₁' − [c] ν
    // For an honest proof both collapse to the prover's Aw/Bw; any
    // tampering with κ, ν, σ₁', the responses, the challenge, or the
    // claimed disclosure diverges here and fails the challenge equality.
    const g2gen = g2.Jacobian.fromAffine(g2.Affine.generator);
    var aw_acc = g2gen.scalarMul(proof.response_r);
    {
        var k: usize = 0;
        for (proof.disclosed, vk.betas) |d, beta| {
            if (d) continue;
            aw_acc = aw_acc.add(g2.Jacobian.fromAffine(beta).scalarMul(proof.responses_m[k]));
            k += 1;
        }
    }
    const a_minus_kappa = a_acc.add(g2.Jacobian.fromAffine(proof.kappa).negate());
    aw_acc = aw_acc.add(a_minus_kappa.scalarMul(proof.challenge));
    const bw = sigma1_jac.scalarMul(proof.response_r)
        .add(g1.Jacobian.fromAffine(proof.nu).scalarMul(proof.challenge).negate());

    const expected = showChallenge(
        parameters,
        vk,
        proof.sigma1,
        proof.sigma2,
        proof.kappa,
        proof.nu,
        aw_acc.toAffine(),
        bw.toAffine(),
        proof.disclosed,
        disclosed_values,
    );
    if (!expected.eql(proof.challenge)) return false;

    // PS pairing equation over the re-randomised credential:
    //   e(σ₁', κ) == e(σ₂' · ν, g2)
    // via the product form e(σ₁', κ) · e(−(σ₂'·ν), g2) == 1.
    const s2nu = g1.Jacobian.fromAffine(proof.sigma2).add(g1.Jacobian.fromAffine(proof.nu));
    return bls.pairing.pairingCheck(&.{
        .{ .p = proof.sigma1, .q = proof.kappa },
        .{ .p = s2nu.negate().toAffine(), .q = g2.Affine.generator },
    });
}

// ── tests (real, ungated) ───────────────────────────────────────────────────

test "psSignWithSecret / psVerifyPlain: valid credential accepted, tamper rejected" {
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 3);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(0x5151);
    var kk = try keys.keygenSeededForTest(allocator, prng.random(), 3, 2, 3);
    defer kk.deinit(allocator);

    const attrs = [_]Fr{ frOf(10), frOf(20), frOf(30) };
    const h = p.commonBase(&attrs);
    const cred = psSignWithSecret(kk.master_sk, h, &attrs);

    try std.testing.expect(psVerifyPlain(kk.master_vk, cred, &attrs));

    // tampered s → reject
    var bad = cred;
    bad.s = g1.Jacobian.fromAffine(cred.s).add(g1.Jacobian.fromAffine(h)).toAffine();
    try std.testing.expect(!psVerifyPlain(kk.master_vk, bad, &attrs));

    // wrong attribute → reject
    const wrong = [_]Fr{ frOf(10), frOf(99), frOf(30) };
    try std.testing.expect(!psVerifyPlain(kk.master_vk, cred, &wrong));

    // h == identity, s == a REAL (nonzero) signature value → reject. NOTE:
    // this specific combination is already rejected by the pairing math
    // alone (e(1, kappa) = 1, but e(s, g2) != 1 for a nonzero s), so on its
    // own it does NOT prove the `h != 1` guard in `psVerifyPlain` is
    // load-bearing — see the DEGENERATE FORGERY case right below, which is
    // the actual attack the guard exists to stop.
    const id_cred = Credential{ .h = g1.Affine.identity, .s = cred.s };
    try std.testing.expect(!psVerifyPlain(kk.master_vk, id_cred, &attrs));

    // DEGENERATE FORGERY: h == identity AND s == identity. Both sides of
    // the pairing equation collapse to e(1, x) == 1 for ANY vk/attributes —
    // e(h, kappa) = e(1, kappa) = 1 and e(-s, g2) = e(-1, g2) = 1, so
    // 1 * 1 == 1 regardless of the verification key or claimed attributes.
    // This is the universal forgery the explicit `h != 1` guard exists to
    // block; without it, `(identity, identity)` verifies against EVERY key.
    const forged = Credential{ .h = g1.Affine.identity, .s = g1.Affine.identity };
    try std.testing.expect(!psVerifyPlain(kk.master_vk, forged, &attrs));
}

test "Credential / PartialCredential codec round-trips" {
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 2);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(7);
    var kk = try keys.keygenSeededForTest(allocator, prng.random(), 2, 2, 3);
    defer kk.deinit(allocator);
    const attrs = [_]Fr{ frOf(3), frOf(4) };
    const h = p.commonBase(&attrs);
    const cred = psSignWithSecret(kk.master_sk, h, &attrs);

    const back = try Credential.fromBytes(cred.toBytes());
    try std.testing.expect(g1Eql(back.h, cred.h) and g1Eql(back.s, cred.s));

    const part = PartialCredential{ .index = 2, .h = cred.h, .s = cred.s };
    const pback = try PartialCredential.fromBytes(part.toBytes());
    try std.testing.expect(pback.index == 2 and g1Eql(pback.h, cred.h));
}

test "ShowProof codec round-trip (hand-constructed artifact, no gated core)" {
    const allocator = std.testing.allocator;
    const responses = try allocator.dupe(Fr, &[_]Fr{ frOf(101), frOf(202) });
    const disclosed = try allocator.dupe(bool, &[_]bool{ true, false, false });
    const proof = ShowProof{
        .sigma1 = g1.Affine.generator,
        .sigma2 = g1.Affine.generator,
        .kappa = g2.Affine.generator,
        .nu = g1.Affine.generator,
        .challenge = frOf(9),
        .response_r = frOf(8),
        .responses_m = responses,
        .disclosed = disclosed,
    };
    defer proof.deinit(allocator);

    const bytes = try proof.toBytes(allocator);
    defer allocator.free(bytes);
    const back = try ShowProof.fromBytes(allocator, bytes);
    defer back.deinit(allocator);

    try std.testing.expect(back.challenge.eql(proof.challenge));
    try std.testing.expect(back.response_r.eql(proof.response_r));
    try std.testing.expectEqual(@as(usize, 2), back.responses_m.len);
    try std.testing.expect(back.responses_m[0].eql(frOf(101)));
    try std.testing.expectEqualSlices(bool, disclosed, back.disclosed);
}

test "gate is flipped: the gated end-to-end tests EXECUTE (no silent skip)" {
    // Inversion of the scaffold-era assertion (which pinned the gate to
    // false while the cores were @panic stubs): the cores are implemented,
    // so the gate MUST be on — otherwise the harness's end-to-end anchor
    // and soundness rejections would silently SKIP instead of asserting.
    try std.testing.expect(gate.fable_core_implemented);
}

fn frOf(v: u64) Fr {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, buf[24..32], v, .big);
    return Fr.fromBytes(buf) catch unreachable;
}

fn g1Eql(a: g1.Affine, b: g1.Affine) bool {
    return a.x.eql(b.x) and a.y.eql(b.y) and a.infinity == b.infinity;
}

// ── fuzz: untrusted-wire decoders never panic/OOB on arbitrary bytes ──────

fn fuzzCredentialDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [Credential.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    const cred = Credential.fromBytes(buf) catch return;
    _ = cred.toBytes();
}
test "fuzz Credential.fromBytes never panics" {
    try std.testing.fuzz({}, fuzzCredentialDecode, .{});
}

fn fuzzPartialCredentialDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [PartialCredential.encoded_bytes]u8 = undefined;
    smith.bytes(&buf);
    const part = PartialCredential.fromBytes(buf) catch return;
    _ = part.toBytes();
}
test "fuzz PartialCredential.fromBytes never panics" {
    try std.testing.fuzz({}, fuzzPartialCredentialDecode, .{});
}

fn fuzzShowProofDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    // Self-describing (length-prefixed `q`, then a `disclosed` mask, then a
    // count of remaining 32-byte scalars derived from the REST of the
    // buffer) — the classic "attacker-controlled count vs. actual buffer
    // length" surface. Must never panic/OOB, only return a typed error.
    const proof = ShowProof.fromBytes(std.testing.allocator, buf[0..len]) catch return;
    defer proof.deinit(std.testing.allocator);
}
test "fuzz ShowProof.fromBytes never panics" {
    try std.testing.fuzz({}, fuzzShowProofDecode, .{});
}

// ── RNG-seam pin (B6, 2026-08-12) ───────────────────────────────────────────

test "proveCredential's entropy parameter is std.Io — a repeated witness nonce is not one call away" {
    const gen_params = @typeInfo(@TypeOf(proveCredential)).@"fn".params;
    // Two shows under a nonce stream that repeats (a re-seeded PRNG, a forked
    // process inheriting PRNG state) give two transcripts with the same
    // witnesses `r̃`/`m̃` but a different challenge `c` — the standard
    // Sigma-protocol two-transcript extraction, which recovers the HIDDEN
    // attributes and the blinding `r`. That is the module's entire purpose,
    // gone. `std.Io.random` is contractually a CSPRNG and a `DefaultPrng`
    // cannot be spelled at this type.
    try std.testing.expectEqual(std.Io, gen_params[1].type.?);
    const test_params = @typeInfo(@TypeOf(proveCredentialSeededForTest)).@"fn".params;
    try std.testing.expectEqual(std.Random, test_params[1].type.?);
}
