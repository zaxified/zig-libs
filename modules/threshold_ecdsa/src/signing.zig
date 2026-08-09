// SPDX-License-Identifier: MIT
//! signing — the GG20 online **threshold-ECDSA signing** protocol, I2
//! **Phase 2d**: the arc's finale, tying keygen (2a, `root.zig`) + the
//! semi-honest MtA core (2b, `mta.zig`) + the GG18 Appendix A malicious-
//! secure range proofs / MtAwc (2c, `zkproofs.zig`, IMPLEMENTED — not a
//! scaffold) into a `t`-of-`n` signature that is a STANDARD secp256k1 ECDSA
//! signature, verifiable under `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`
//! against `KeyShare.group_public_key` — no threshold-aware verifier is
//! needed on the other end. See R. Gennaro, S. Goldfeder, "One Round
//! Threshold ECDSA with Identifiable Abort" (GG20, IACR ePrint 2020/540)
//! for the protocol this implements, and GG18 (ePrint 2019/114) §4 for the
//! base MtA-driven signing shape GG20 refines into one round.
//!
//! ## Status: round orchestration, MtA/MtAwc wiring, and the signature
//! arithmetic are REAL (built entirely on already-implemented Phase-2b/2c
//! primitives); ONE security layer is a documented, deliberate scope cut —
//! see "Identifiable abort scope" below. `signWithShares` (this file's
//! main entry point) produces a signature that genuinely verifies under
//! `std`'s own ECDSA — it does not `@panic`.
//!
//! ## The protocol, phase by phase
//!
//! For a signing subset `S` of `t` parties (each holding a `KeyShare`) and
//! a message:
//!
//! 1. **Local secrets.** Each party `i` in `S` samples `k_i, γ_i ← Zq`
//!    (`randomScalar`) and computes its LAGRANGE-WEIGHTED secret share
//!    `w_i = λ_i · x_i` (`lagrangeCoefficient`, the same Lagrange-at-zero
//!    weights `root.reconstructSecret` uses internally, exposed here as a
//!    standalone function) — chosen so `Σ_{i∈S} w_i = x` (the group secret)
//!    without ever reconstructing `x` itself.
//! 2. **Γ commit-reveal.** Each party computes `Γ_i = γ_i·G`, commits to it
//!    (`commitGamma`, a plain SHA-256 hash of the point), and proves
//!    knowledge of `γ_i` via a standard Fiat-Shamir Schnorr NIZK
//!    (`provePoK`/`verifyPoK`) — this is what stops a rushing adversary
//!    from choosing its `Γ_i` AFTER seeing everyone else's (a classic
//!    "last-mover" attack on the aggregated `R`). Every party then checks
//!    every other party's `(commitment, Γ_i, proof)` triple.
//! 3. **MtA phase.** For every ORDERED pair `(i,j)`, `i≠j`, in `S`:
//!      - `i` (Alice, input `k_i`) and `j` (Bob, input `γ_j`) run the
//!        Phase-2c CHECKED MtA (`runCheckedMtA` — `mta
//!        .mtaAliceInitChecked`/`mtaBobResponseChecked`/
//!        `mtaAliceFinalizeChecked` plus `zkproofs.proveAliceRange`/
//!        `verifyAliceRange`/`proveBobMta`, all REAL, GG18 Appendix A) →
//!        additive shares of `k_i·γ_j`.
//!      - `i` (Alice, `k_i`) and `j` (Bob, input `w_j`) run the CHECKED
//!        **MtAwc** (`runCheckedMtAwc` — `zkproofs.proveBobMtaWc`/
//!        `verifyBobMtaWc`, REAL) against the PUBLIC point `W_j = λ_j·X_j`
//!        (`j`'s Lagrange-weighted verifying share) → additive shares of
//!        `k_i·w_j`, with Bob's `w_j` provably tied to his already-public
//!        key share.
//!    Summing every party's shares (own diagonal term `k_i·γ_i`/`k_i·w_i`
//!    plus every pairwise `α`/`β`) yields `δ_i`/`σ_i` with `Σδ_i = k·γ` and
//!    `Σσ_i = k·x` (see `signWithShares`'s body for the exact sum, which is
//!    the standard telescoping-sum identity GG20 Figure 3 / GG18 §4 use).
//! 4. **δ reveal → R.** `δ = Σδ_i` (plaintext scalars, no MtA needed to
//!    reveal a sum) → `δ⁻¹` → `R = (Σ Γ_i)^{δ⁻¹} = k⁻¹·G` → `r = R.x mod q`.
//! 5. **s shares → s.** Each party computes `s_i = m·k_i + r·σ_i` (`m` =
//!    the message hash reduced into `Zq` via the SAME wide-reduction
//!    `std.crypto.sign.ecdsa`'s own `Signer.finalizePrehashed` uses —
//!    `scalarFromHash32`, so the resulting `m` matches std's own) and
//!    reveals it; `s = Σs_i`, normalized to the smaller of `{s, q-s}`
//!    (canonical/low-S form, BIP-62 convention — std's own verifier does
//!    not require this, but a well-behaved signer produces it).
//! 6. **Fail-closed self-check.** Before returning, `signWithShares`
//!    verifies its OWN output against `group_public_key` via
//!    `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.Signature.verify` — if
//!    that fails for any reason (see "Identifiable abort scope"),
//!    `error.SigningAborted` is returned instead of a bad signature. This
//!    is a hard invariant: this function NEVER returns a signature that
//!    does not verify.
//!
//! ## Identifiable-abort scope — DELIBERATE, DOCUMENTED CUT (read this
//! before extending)
//!
//! GG20's headline contribution over GG18 is **identifiable abort**: when
//! signing fails, the protocol doesn't just abort — it produces evidence
//! naming EXACTLY which party misbehaved, without a trusted dealer. This
//! file implements the WEAKER **"abort-only v1"**: every per-round check
//! this file DOES perform (MtA/MtAwc range-proof verification, Γ
//! commitment/knowledge-proof verification, and the final std-ECDSA
//! self-check) is fail-closed — a cheating party can never cause a bad
//! signature to be returned, only an `error.SigningAborted` (or one of the
//! more specific `Invalid*` errors, if the culprit's misbehavior was
//! caught mid-protocol at a specific pairwise check) — but the SPECIFIC
//! residual gap it does NOT close is: **a malicious party could use an
//! INCONSISTENT `k_i`/`γ_i`/`w_i` value across different pairwise MtA
//! sessions** (e.g. a different `k_i` in the `(i,j)` session than in the
//! `(i,l)` session). Each pairwise range/MtA proof only attests to THAT
//! session's witness in isolation — nothing here proves the SAME `k_i` was
//! used in every session `i` participates in. If that happens, the final
//! self-check in step 6 will (with overwhelming probability) catch the
//! resulting bad `(r,s)` and abort — so this gap is NOT an integrity hole
//! against the "never return a bad signature" invariant — but it IS an
//! availability/attribution hole: the honest parties learn only that
//! SOMETHING was inconsistent, not WHO. Closing this — proving cross-
//! session `k_i`/`γ_i`/`w_i` consistency and, on failure, opening enough
//! transcript material to name a culprit — is GG20's actual identifiable-
//! abort apparatus (paper §4's "Identifiable Abort" rounds) and is left as
//! `identifyAbortCulprit` (below), `@panic`-stubbed: it is paper-exact
//! machinery this scaffold pass deliberately did not guess at.
//!
//! ## Zig std GAP: none new — `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`
//! (the FINAL verification target), `std.crypto.ecc.Secp256k1`, and
//! `std.crypto.hash.sha2.Sha256` are the only primitives this file needs
//! beyond the sibling `root`/`mta`/`zkproofs` modules.

const std = @import("std");
const builtin = @import("builtin");
const paillier = @import("paillier");
const root = @import("root.zig");
const mta = @import("mta.zig");
const zkproofs = @import("zkproofs.zig");

pub const Scalar = root.Scalar;
pub const Secp256k1 = root.Secp256k1;
pub const Element = root.Element;
const Ns = root.Ns;
const Ne = root.Ne;

const Sha256 = std.crypto.hash.sha2.Sha256;

/// The standard-library ECDSA scheme every `signWithShares` output MUST
/// verify under — the whole point of this module.
pub const ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
/// Re-exported for callers that only import `signing` directly.
pub const Signature = ecdsa.Signature;

// ── small shared helpers (mechanical; mirror root.zig/zkproofs.zig's own
// identically-shaped PRIVATE helpers — this repo's established "small
// mechanical helper, copied per file" convention) ───────────────────────

/// Sample a uniform `Zq` scalar from CSPRNG bytes (48-byte draw, constant-
/// time wide reduction) — same idiom as `mta.zig`'s private `randomScalar`.
fn randomScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

/// `int(bytes32) mod q` via the SAME wide-reduction idiom
/// `std.crypto.sign.ecdsa`'s own `Signer.finalizePrehashed`/`Verifier.init`
/// use internally for both the message-hash scalar `z` and the `r = R.x
/// mod q` reduction (`reduceToScalar(32, ...)`, itself `fromBytes48` over a
/// 16-zero-byte-padded 48-byte buffer) — using the IDENTICAL scheme here is
/// what makes this module's `s_i = m·k_i + r·σ_i` land on the exact `m`/`r`
/// std's own verifier will recompute.
fn scalarFromHash32(bytes32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

/// Lagrange coefficient `λ_i = Prod_{j∈indices, j≠i} x_j / (x_j - x_i)` at
/// evaluation point 0, over the PUBLIC participant `index` set — the same
/// arithmetic `root.reconstructSecret` performs internally, exposed here
/// standalone since signing needs each party's `w_i = λ_i · x_i` WITHOUT
/// ever reconstructing the secret itself. `scalarFromIndex` duplicates
/// `root.zig`'s private identically-named helper (same "small integer
/// index, always canonical" convention).
fn scalarFromIndex(index: u32) Scalar {
    var buf = [_]u8{0} ** Ns;
    std.mem.writeInt(u32, buf[Ns - 4 .. Ns], index, .big);
    return Scalar.fromBytes(buf, .big) catch unreachable; // u32 << q: always canonical
}

pub fn lagrangeCoefficient(indices: []const u32, index: u32) Scalar {
    const xi = scalarFromIndex(index);
    var numerator = Scalar.one;
    var denominator = Scalar.one;
    for (indices) |j| {
        if (j == index) continue;
        const xj = scalarFromIndex(j);
        numerator = numerator.mul(xj);
        denominator = denominator.mul(xj.sub(xi));
    }
    return numerator.mul(denominator.invert());
}

// ── Γ commit-reveal + Schnorr proof-of-knowledge (REAL — standard
// Fiat-Shamir Sigma protocol, NOT verified byte-for-byte against GG20's own
// Πzk instantiation; see the module doc comment) ────────────────────────

pub const gamma_commit_domain = "threshold_ecdsa/signing/gamma-commit/v1";
pub const gamma_pok_domain = "threshold_ecdsa/signing/gamma-pok/v1";

/// Round-1 broadcast: `H(domain || index || Γ_i)`. Binding (a party can't
/// change its mind about `Γ_i` after committing) is all this needs to buy —
/// `Γ_i` alone never reveals `γ_i` (discrete-log hardness), so a plain hash
/// commitment (no separate blinding nonce) is sufficient; this is NOT a
/// general-purpose hiding commitment scheme.
pub const GammaCommitment = struct {
    index: u32,
    commitment: [32]u8,

    pub const encoded_length = 4 + 32;

    pub fn toBytes(self: GammaCommitment) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.index, .big);
        out[4..encoded_length].* = self.commitment;
        return out;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) GammaCommitment {
        return .{
            .index = std.mem.readInt(u32, bytes[0..4], .big),
            .commitment = bytes[4..encoded_length].*,
        };
    }
};

fn commitGamma(index: u32, big_gamma: Element) [32]u8 {
    var h = Sha256.init(.{});
    h.update(gamma_commit_domain);
    var idx_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &idx_buf, index, .big);
    h.update(&idx_buf);
    h.update(&big_gamma.toBytes());
    return h.finalResult();
}

/// A standard non-interactive (Fiat-Shamir) Schnorr proof of knowledge of
/// the discrete log behind a public point — here, `Γ_i = γ_i·G`. Textbook
/// construction (`R = k·G`, `e = H(...||Γ||R)`, `s = k + e·γ`, verify
/// `s·G == R + e·Γ`); this is the well-known folklore Sigma protocol any
/// implementation of this shape uses, NOT GG20's own paper-specific `Πzk`
/// instantiation (which this scaffold pass did not have open) — see the
/// module doc comment.
pub const SchnorrProof = struct {
    r_point: Element,
    s: Scalar,

    pub const encoded_length = Ne + Ns;

    pub fn toBytes(self: SchnorrProof) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        out[0..Ne].* = self.r_point.toBytes();
        out[Ne..encoded_length].* = self.s.toBytes(.big);
        return out;
    }

    pub const DecodeError = root.ElementError || error{InvalidEncoding};

    pub fn fromBytes(bytes: [encoded_length]u8) DecodeError!SchnorrProof {
        const r_point = try Element.fromBytes(bytes[0..Ne].*);
        const s = Scalar.fromBytes(bytes[Ne..encoded_length].*, .big) catch return error.InvalidEncoding;
        return .{ .r_point = r_point, .s = s };
    }
};

fn pokChallenge(index: u32, big_gamma: Element, r_point: Element) Scalar {
    var h = Sha256.init(.{});
    h.update(gamma_pok_domain);
    var idx_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &idx_buf, index, .big);
    h.update(&idx_buf);
    h.update(&big_gamma.toBytes());
    h.update(&r_point.toBytes());
    return scalarFromHash32(h.finalResult());
}

fn provePoK(index: u32, gamma: Scalar, big_gamma: Element, random: std.Random) SignError!SchnorrProof {
    while (true) {
        const nonce = randomScalar(random);
        const r_full = Secp256k1.basePoint.mul(nonce.toBytes(.big), .big) catch continue;
        const r_point = Element.fromPoint(r_full) catch continue;
        const e = pokChallenge(index, big_gamma, r_point);
        const s = nonce.add(e.mul(gamma));
        return .{ .r_point = r_point, .s = s };
    }
}

fn verifyPoK(index: u32, big_gamma: Element, proof: SchnorrProof) bool {
    const e = pokChallenge(index, big_gamma, proof.r_point);
    const lhs = Secp256k1.basePoint.mul(proof.s.toBytes(.big), .big) catch return false;
    const gamma_pt = big_gamma.point() catch return false;
    const e_gamma = gamma_pt.mul(e.toBytes(.big), .big) catch return false;
    const r_pt = proof.r_point.point() catch return false;
    return lhs.equivalent(e_gamma.add(r_pt));
}

/// Round-2 reveal: `Γ_i` plus its knowledge-of-exponent proof. Every OTHER
/// party checks this against the Round-1 `GammaCommitment` before trusting
/// `Γ_i`.
pub const GammaReveal = struct {
    index: u32,
    big_gamma: Element,
    proof: SchnorrProof,

    pub const encoded_length = 4 + Ne + SchnorrProof.encoded_length;

    pub fn toBytes(self: GammaReveal) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.index, .big);
        out[4 .. 4 + Ne].* = self.big_gamma.toBytes();
        out[4 + Ne .. encoded_length].* = self.proof.toBytes();
        return out;
    }

    pub const DecodeError = root.ElementError || SchnorrProof.DecodeError;

    pub fn fromBytes(bytes: [encoded_length]u8) DecodeError!GammaReveal {
        const index = std.mem.readInt(u32, bytes[0..4], .big);
        const big_gamma = try Element.fromBytes(bytes[4 .. 4 + Ne].*);
        const proof = try SchnorrProof.fromBytes(bytes[4 + Ne .. encoded_length].*);
        return .{ .index = index, .big_gamma = big_gamma, .proof = proof };
    }
};

/// Round-4 reveal: one party's additive share of `k·γ` — plaintext scalars
/// summed publicly (no MtA needed to open a value every party already
/// helped compute additively).
pub const DeltaShare = struct {
    index: u32,
    delta: Scalar,

    pub const encoded_length = 4 + Ns;

    pub fn toBytes(self: DeltaShare) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.index, .big);
        out[4..encoded_length].* = self.delta.toBytes(.big);
        return out;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) error{InvalidEncoding}!DeltaShare {
        const index = std.mem.readInt(u32, bytes[0..4], .big);
        const delta = Scalar.fromBytes(bytes[4..encoded_length].*, .big) catch return error.InvalidEncoding;
        return .{ .index = index, .delta = delta };
    }
};

/// Round-5 reveal: one party's signature share `s_i`.
pub const SigShare = struct {
    index: u32,
    s: Scalar,

    pub const encoded_length = 4 + Ns;

    pub fn toBytes(self: SigShare) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.index, .big);
        out[4..encoded_length].* = self.s.toBytes(.big);
        return out;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) error{InvalidEncoding}!SigShare {
        const index = std.mem.readInt(u32, bytes[0..4], .big);
        const s = Scalar.fromBytes(bytes[4..encoded_length].*, .big) catch return error.InvalidEncoding;
        return .{ .index = index, .s = s };
    }
};

// ── Phase-2b/2c-composed MtA/MtAwc rounds (REAL — pure composition over
// already-implemented mta.zig/zkproofs.zig entry points) ────────────────

pub const SignError = std.mem.Allocator.Error || mta.MtaError || error{
    InvalidParameters,
    InvalidRangeProof,
    InvalidMtaProof,
    InvalidCommitment,
    InvalidKnowledgeProof,
    IdentityPoint,
    SigningAborted,
    // Audit F1/F2: a RECEIVED aux tuple / Paillier key failed the fail-closed
    // `zkproofs` prove-side validation (`root.AuxParams.validate` /
    // `root.paillierNMeetsFloor`) — surfaced from `runCheckedMtA(wc)`.
    InvalidAuxParams,
};

/// One instance of the Phase-2c CHECKED MtA (`mta.zig`'s
/// `*Checked`/`zkproofs`'s range+MtA proofs — GG18 Appendix A.1/A.3, all
/// REAL) between `alice_secret` (owned by the party whose `alice_pk`/
/// `alice_sk`/`alice_aux` are passed) and `bob_secret` (owned by the
/// counterparty, whose `bob_aux` is passed — see `zkproofs.zig`'s
/// "verifier-vs-prover aux-param ownership" note: `bob_aux` is what BOB
/// uses to VERIFY Alice's range proof, `alice_aux` is what ALICE uses to
/// verify Bob's MtA proof). Returns Alice's `alpha` and Bob's `beta` with
/// `alpha + beta ≡ alice_secret · bob_secret (mod q)`.
fn runCheckedMtA(
    allocator: std.mem.Allocator,
    alice_secret: Scalar,
    bob_secret: Scalar,
    alice_pk: paillier.PublicKey,
    alice_sk: paillier.SecretKey,
    alice_aux: root.AuxParams,
    bob_aux: root.AuxParams,
    random: std.Random,
) SignError!struct { alpha: Scalar, beta: Scalar } {
    const alice_init = try mta.mtaAliceInitChecked(alice_secret, alice_pk, random);
    const range_proof = try zkproofs.proveAliceRange(allocator, alice_secret, alice_init.r_a, alice_pk, bob_aux, random);
    defer range_proof.deinit(allocator);
    if (!zkproofs.verifyAliceRange(range_proof, alice_init.c_a, alice_pk, bob_aux)) return error.InvalidRangeProof;

    const bob_resp = try mta.mtaBobResponseChecked(bob_secret, alice_init.c_a, alice_pk, random);
    const beta_prime = bob_resp.beta.neg();
    const mta_proof = try zkproofs.proveBobMta(allocator, bob_secret, beta_prime, bob_resp.r_b, alice_init.c_a, bob_resp.c_b, alice_pk, alice_aux, random);
    defer mta_proof.deinit(allocator);

    const alpha = try mta.mtaAliceFinalizeChecked(alice_init.c_a, bob_resp.c_b, mta_proof, alice_sk, alice_pk, alice_aux);
    return .{ .alpha = alpha, .beta = bob_resp.beta };
}

/// The MtAwc variant: like `runCheckedMtA`, but Bob additionally proves his
/// `bob_secret` matches the PUBLIC point `b_point` (`zkproofs
/// .proveBobMtaWc`/`verifyBobMtaWc`, GG18 Appendix A.2, REAL) — this is
/// what GG20's `k·x` share conversion needs (`b_point` = the counterparty's
/// Lagrange-weighted verifying share `W_j = λ_j·X_j`). `mta.zig` has no
/// `*Wc`-specific finalize wrapper, so this calls the plain (semi-honest)
/// `mta.mtaAliceFinalize` for decryption AFTER this function's own
/// `verifyBobMtaWc` gate — equivalent fail-closed posture to
/// `mtaAliceFinalizeChecked`, just assembled locally.
fn runCheckedMtAwc(
    allocator: std.mem.Allocator,
    alice_secret: Scalar,
    bob_secret: Scalar,
    alice_pk: paillier.PublicKey,
    alice_sk: paillier.SecretKey,
    alice_aux: root.AuxParams,
    bob_aux: root.AuxParams,
    b_point: Element,
    random: std.Random,
) SignError!struct { alpha: Scalar, beta: Scalar } {
    const alice_init = try mta.mtaAliceInitChecked(alice_secret, alice_pk, random);
    const range_proof = try zkproofs.proveAliceRange(allocator, alice_secret, alice_init.r_a, alice_pk, bob_aux, random);
    defer range_proof.deinit(allocator);
    if (!zkproofs.verifyAliceRange(range_proof, alice_init.c_a, alice_pk, bob_aux)) return error.InvalidRangeProof;

    const bob_resp = try mta.mtaBobResponseChecked(bob_secret, alice_init.c_a, alice_pk, random);
    const beta_prime = bob_resp.beta.neg();
    const wc_proof = try zkproofs.proveBobMtaWc(allocator, bob_secret, beta_prime, bob_resp.r_b, alice_init.c_a, bob_resp.c_b, alice_pk, alice_aux, b_point, random);
    defer wc_proof.deinit(allocator);
    if (!zkproofs.verifyBobMtaWc(wc_proof, alice_init.c_a, bob_resp.c_b, alice_pk, alice_aux, b_point)) return error.InvalidMtaProof;

    const alpha = try mta.mtaAliceFinalize(bob_resp.c_b, alice_sk);
    return .{ .alpha = alpha, .beta = bob_resp.beta };
}

// ── the driver: signWithShares (REAL end to end) ─────────────────────────

/// Per-party ephemeral state the driver threads through its rounds.
const Ephemeral = struct {
    k: Scalar,
    gamma: Scalar,
    w: Scalar,
    big_gamma: Element,
    delta: Scalar,
    sigma: Scalar,
};

/// **The decisive entry point.** Runs the FULL GG20 online signing
/// protocol, in-process, over `shares` (the signing subset `S` — any `t`
/// of the group's `n` `KeyShare`s; `t`/`n`/`group_public_key` must agree
/// across all of them), producing a standard secp256k1 ECDSA signature
/// over `message` that VERIFIES under `shares[0].group_public_key` via
/// `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256` — see the module doc
/// comment for the phase-by-phase construction and the "identifiable
/// abort scope" section for exactly what security property this does
/// and does not provide. Never returns an invalid signature (step 6's
/// fail-closed self-check): callers get either a genuinely-verifying
/// `Signature` or `error.SigningAborted`/one of the more specific
/// `Invalid*` errors.
///
/// `random` MUST be cryptographically secure for real use. This function
/// allocates and frees all its own working memory; nothing is retained.
pub fn signWithShares(
    allocator: std.mem.Allocator,
    shares: []const root.KeyShare,
    message: []const u8,
    random: std.Random,
) SignError!Signature {
    const t = shares.len;
    if (t < 2) return error.InvalidParameters;

    const indices = try allocator.alloc(u32, t);
    defer allocator.free(indices);
    for (shares, 0..) |s, idx| indices[idx] = s.index;
    for (indices, 0..) |a, ia| {
        for (indices[ia + 1 ..]) |b| {
            if (a == b) return error.InvalidParameters;
        }
    }

    const group_pk = shares[0].group_public_key;
    for (shares[1..]) |s| {
        if (!std.mem.eql(u8, &s.group_public_key.toBytes(), &group_pk.toBytes())) return error.InvalidParameters;
    }

    // ── Phase 1/2: local secrets + Γ commit-reveal + knowledge proofs ───
    const eph = try allocator.alloc(Ephemeral, t);
    // `k`/`gamma`/`w`/`delta`/`sigma` are all secret per-party scalars
    // (the ephemeral nonce, blinding, weighted key share, and their MtA
    // accumulators); `big_gamma` is the public Γ commitment. Zero the
    // whole scratch array before freeing — nothing here is retained past
    // this function, and it's simplest/safest to wipe it all.
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(eph));
        allocator.free(eph);
    }

    for (shares, 0..) |s, idx| {
        const k_i = randomScalar(random);
        const gamma_i = randomScalar(random);
        const lambda_i = lagrangeCoefficient(indices, s.index);
        const w_i = lambda_i.mul(s.secret_share);
        const big_gamma_pt = Secp256k1.basePoint.mul(gamma_i.toBytes(.big), .big) catch return error.IdentityPoint;
        const big_gamma = Element.fromPoint(big_gamma_pt) catch return error.IdentityPoint;
        eph[idx] = .{ .k = k_i, .gamma = gamma_i, .w = w_i, .big_gamma = big_gamma, .delta = Scalar.zero, .sigma = Scalar.zero };
    }

    // Commit (Round 1), then reveal + verify (Round 2) — collapsed into one
    // pass since this driver holds every party's state in-process, but the
    // commit/verify STEPS are the real ones a networked implementation
    // would run over `GammaCommitment`/`GammaReveal` messages.
    for (shares, 0..) |s, idx| {
        const commitment = commitGamma(s.index, eph[idx].big_gamma);
        const proof = try provePoK(s.index, eph[idx].gamma, eph[idx].big_gamma, random);
        // "Receive" + verify (self-consistency here; a networked party
        // verifies every OTHER party's triple against what it broadcast).
        if (!std.mem.eql(u8, &commitGamma(s.index, eph[idx].big_gamma), &commitment)) return error.InvalidCommitment;
        if (!verifyPoK(s.index, eph[idx].big_gamma, proof)) return error.InvalidKnowledgeProof;
    }

    var gamma_sum = Secp256k1.identityElement;
    for (eph) |e| {
        const pt = e.big_gamma.point() catch return error.IdentityPoint;
        gamma_sum = gamma_sum.add(pt);
    }

    // ── Phase 3: MtA (k·γ) + MtAwc (k·x) over every ordered pair ─────────
    for (shares, 0..) |ai_share, ii| {
        const alice_pk = ai_share.public_keys.get(ai_share.index).?.paillier_pk;
        const alice_sk = ai_share.paillier_secret;
        const alice_aux = ai_share.public_keys.get(ai_share.index).?.aux;

        for (shares, 0..) |aj_share, jj| {
            if (ii == jj) continue;
            const bob_aux = aj_share.public_keys.get(aj_share.index).?.aux;

            const gamma_res = try runCheckedMtA(allocator, eph[ii].k, eph[jj].gamma, alice_pk, alice_sk, alice_aux, bob_aux, random);
            eph[ii].delta = eph[ii].delta.add(gamma_res.alpha);
            eph[jj].delta = eph[jj].delta.add(gamma_res.beta);

            const xj_pt = aj_share.verifying_share.point() catch return error.IdentityPoint;
            const lambda_j = lagrangeCoefficient(indices, aj_share.index);
            const wj_pt = xj_pt.mul(lambda_j.toBytes(.big), .big) catch return error.IdentityPoint;
            const w_point = Element.fromPoint(wj_pt) catch return error.IdentityPoint;

            const x_res = try runCheckedMtAwc(allocator, eph[ii].k, eph[jj].w, alice_pk, alice_sk, alice_aux, bob_aux, w_point, random);
            eph[ii].sigma = eph[ii].sigma.add(x_res.alpha);
            eph[jj].sigma = eph[jj].sigma.add(x_res.beta);
        }
    }
    for (eph) |*e| {
        e.delta = e.delta.add(e.k.mul(e.gamma));
        e.sigma = e.sigma.add(e.k.mul(e.w));
    }

    // ── Phase 4: δ reveal → R → r ─────────────────────────────────────
    var delta_sum = Scalar.zero;
    for (eph) |e| delta_sum = delta_sum.add(e.delta);
    if (delta_sum.isZero()) return error.SigningAborted;
    const delta_inv = delta_sum.invert();

    const r_full = gamma_sum.mul(delta_inv.toBytes(.big), .big) catch return error.SigningAborted;
    r_full.rejectIdentity() catch return error.SigningAborted;
    const r = scalarFromHash32(r_full.affineCoordinates().x.toBytes(.big));
    if (r.isZero()) return error.SigningAborted;

    // ── Phase 5: s shares → s ────────────────────────────────────────
    var digest: [32]u8 = undefined;
    Sha256.hash(message, &digest, .{});
    const m = scalarFromHash32(digest);

    var s_sum = Scalar.zero;
    for (eph) |e| {
        const s_i = m.mul(e.k).add(r.mul(e.sigma));
        s_sum = s_sum.add(s_i);
    }
    if (s_sum.isZero()) return error.SigningAborted;

    // Canonical/low-S form: the smaller of {s, q-s} (BIP-62 convention;
    // std's verifier does not require this, but a well-behaved signer
    // avoids the malleability of the other form).
    const neg_s = s_sum.neg();
    const s_final = if (std.mem.order(u8, &s_sum.toBytes(.big), &neg_s.toBytes(.big)) == .gt) neg_s else s_sum;

    const sig: Signature = .{ .r = r.toBytes(.big), .s = s_final.toBytes(.big) };

    // ── Phase 6: fail-closed self-check (see "Identifiable abort scope")
    const pk = ecdsa.PublicKey.fromSec1(&group_pk.toBytes()) catch return error.SigningAborted;
    sig.verify(message, pk) catch return error.SigningAborted;

    return sig;
}

/// **STUB (TODO(core)).** GG20's actual identifiable-abort apparatus (paper
/// §4's "Identifiable Abort" rounds): when `signWithShares` returns
/// `error.SigningAborted`, name EXACTLY which party's `k_i`/`γ_i`/`w_i` was
/// used inconsistently across two different pairwise MtA sessions (the
/// residual gap `signWithShares`'s "abort-only v1" posture does not close
/// — see the module doc comment's "Identifiable abort scope" section for
/// the precise threat this closes and why it does NOT threaten the "never
/// return a bad signature" invariant, only attribution). A real
/// implementation needs:
///
///   1. Every party to RETAIN its pairwise MtA transcripts (the `c_a`/
///      `c_b`/proof values `runCheckedMtA`/`runCheckedMtAwc` currently
///      discard once each pairwise round finishes) tagged by session.
///   2. On final-signature failure, an opening/decommitment sub-protocol
///      (GG20's Rounds 6/7) that lets an auditor cross-check a party's
///      committed `k_i`/`γ_i` against what it actually fed into EVERY
///      pairwise session, and produce a publicly-checkable fault
///      attributable to one party index.
///
/// See GG20 (R. Gennaro, S. Goldfeder, IACR ePrint 2020/540) §4 for the
/// exact construction — deliberately NOT transcribed here (this scaffold
/// pass did not have the paper's identifiable-abort sections open; guessing
/// paper-exact machinery would be worse than an honest stub).
pub fn identifyAbortCulprit(shares: []const root.KeyShare, transcripts: anytype) noreturn {
    _ = shares;
    _ = transcripts;
    @panic("TODO(core): GG20 identifiable-abort culprit identification (IACR ePrint 2020/540 §4). " ++
        "signWithShares implements the weaker 'abort-only v1' posture (see this module's doc comment): " ++
        "it never returns an invalid signature, but cannot name a culprit when it aborts. A full " ++
        "implementation needs signWithShares to start RETAINING each pairwise MtA transcript (currently " ++
        "discarded after each round) plus the paper's opening/decommitment sub-protocol.");
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Fast test-only ring-Pedersen aux params: derives a genuine (if not
/// safe-prime, hence not production-strength) two-prime-product modulus
/// from an ordinary `paillier.generate` RSA-strength keygen (skipping the
/// slow safe-prime search `root.generateAuxParams` performs) and sets
/// `h2 = h1^2` for a KNOWN small lambda — mirrors `mta.zig`'s own
/// established end-to-end-test recipe (see its "Phase 2c end-to-end" test)
/// for exactly the same reason: the prove/verify EQUATIONS are valid
/// regardless of `N_tilde`'s provenance, only the SECURITY (statistical
/// hiding / soundness margin) depends on it being a genuine safe-prime
/// product — irrelevant for a correctness-focused unit test.
fn sampleFeBelow(m: root.AuxModulus, random: std.Random) root.AuxFe {
    const n_bits = m.bits();
    const n_len = (n_bits + 7) / 8;
    var buf: [root.aux_modulus_bytes]u8 = undefined;
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const r = root.AuxFe.fromBytes(m, buf[0..n_len], .big) catch continue;
        if (!r.isZero()) return r;
    }
}

fn testAuxParams(random: std.Random) !root.AuxParams {
    // 2048-bit Ñ (was 512): the audit-F2 floor now requires every checked-path
    // aux Ñ to exceed q⁷ ≈ 2^1792. h2 = h1² (lambda = 2) keeps a known DL for
    // the completeness-only fixture — a square, hence Jacobi +1 like validate wants.
    const nt_kp = try paillier.generate(random, 2048);
    var nt_buf: [paillier.modulus_bytes]u8 = undefined;
    const nt_len = nt_kp.public.nByteLen();
    try nt_kp.public.nToBytes(nt_buf[0..nt_len]);
    var strip: usize = 0;
    while (strip < nt_len and nt_buf[strip] == 0) : (strip += 1) {}
    const n_tilde = try root.AuxModulus.fromBytes(nt_buf[strip..nt_len], .big);
    const x = sampleFeBelow(n_tilde, random);
    const h1 = n_tilde.sq(x);
    const h2 = n_tilde.sq(h1); // h2 = h1^2 = h1^lambda, lambda = 2
    return .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 };
}

const TestKeygen = struct {
    key_shares: []root.KeyShare,

    fn deinit(self: TestKeygen, allocator: std.mem.Allocator) void {
        allocator.free(self.key_shares[0].public_keys.entries);
        allocator.free(self.key_shares);
    }
};

/// Small-but-real 1024-bit Paillier keys (the same "test-only fast size"
/// this module's own `mta.zig`/`zkproofs.zig` tests already establish —
/// see e.g. `zkproofs.zig`'s "Phase 2c end-to-end" test) + fast
/// `testAuxParams` tuples, wired through the REAL `root.keygenTrustedDealer`.
fn testKeygen(allocator: std.mem.Allocator, random: std.Random, t: u32, n: u32) !TestKeygen {
    const paillier_keys = try allocator.alloc(paillier.KeyPair, n);
    defer allocator.free(paillier_keys);
    const aux_params = try allocator.alloc(root.AuxParams, n);
    defer allocator.free(aux_params);
    for (0..n) |i| {
        // 2048-bit (was 1024): audit-F2 floor requires checked-path Paillier N > q⁷.
        paillier_keys[i] = try paillier.generate(random, 2048);
        aux_params[i] = try testAuxParams(random);
    }

    const secret = randomScalar(random);
    const coefficients = try allocator.alloc(Scalar, t - 1);
    defer allocator.free(coefficients);
    for (coefficients) |*c| c.* = randomScalar(random);

    const key_shares = try root.keygenTrustedDealer(allocator, t, n, secret, coefficients, paillier_keys, aux_params);
    return .{ .key_shares = key_shares };
}

fn expectVerifies(shares: []const root.KeyShare, message: []const u8, sig: Signature) !void {
    const pk = try ecdsa.PublicKey.fromSec1(&shares[0].group_public_key.toBytes());
    try sig.verify(message, pk);
}

test "signWithShares: decisive test — keygen(2,3) -> sign over 2 shares -> verifies under std EcdsaSecp256k1Sha256" {
    // Heavy: 2048-bit keygen. `threshold_ecdsa` is `heavy` in build.zig,
    // so the DEFAULT lane builds it at ReleaseSafe and DOES run this test;
    // it skips ONLY under `-Dstrict-debug` (audit N2 claimed the opposite).
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x736967_6e696e67); // "signing"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    const subset = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1] };
    const message = "GG20 threshold-ECDSA Phase 2d decisive test";

    const sig = try signWithShares(allocator, &subset, message, random);
    try expectVerifies(kg.key_shares, message, sig);
}

test "signWithShares: different t-subsets of n all produce signatures that verify under X" {
    // Heavy: 2048-bit keygen. `threshold_ecdsa` is `heavy` in build.zig,
    // so the DEFAULT lane builds it at ReleaseSafe and DOES run this test;
    // it skips ONLY under `-Dstrict-debug` (audit N2 claimed the opposite).
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7375627365747300); // "subsets"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    const message = "same group key, different signing subsets";
    const pairs = [_][2]usize{ .{ 0, 1 }, .{ 0, 2 }, .{ 1, 2 } };
    for (pairs) |pair| {
        const subset = [_]root.KeyShare{ kg.key_shares[pair[0]], kg.key_shares[pair[1]] };
        const sig = try signWithShares(allocator, &subset, message, random);
        try expectVerifies(kg.key_shares, message, sig);
    }
}

test "signWithShares: tampered signature share does not verify" {
    // Heavy: 2048-bit keygen. `threshold_ecdsa` is `heavy` in build.zig,
    // so the DEFAULT lane builds it at ReleaseSafe and DOES run this test;
    // it skips ONLY under `-Dstrict-debug` (audit N2 claimed the opposite).
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x74616d706572); // "tamper"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    const subset = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1] };
    const message = "tamper me";
    var sig = try signWithShares(allocator, &subset, message, random);
    try expectVerifies(kg.key_shares, message, sig);

    // Flip one bit of s: must no longer verify.
    sig.s[31] ^= 0x01;
    const pk = try ecdsa.PublicKey.fromSec1(&kg.key_shares[0].group_public_key.toBytes());
    try testing.expectError(error.SignatureVerificationFailed, sig.verify(message, pk));
}

test "signWithShares: signature over one message does not verify against a different message" {
    // Heavy: 2048-bit keygen. `threshold_ecdsa` is `heavy` in build.zig,
    // so the DEFAULT lane builds it at ReleaseSafe and DOES run this test;
    // it skips ONLY under `-Dstrict-debug` (audit N2 claimed the opposite).
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6d69736d61746368); // "mismatch"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    const subset = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1] };
    const sig = try signWithShares(allocator, &subset, "message A", random);

    const pk = try ecdsa.PublicKey.fromSec1(&kg.key_shares[0].group_public_key.toBytes());
    try testing.expectError(error.SignatureVerificationFailed, sig.verify("message B", pk));
}

test "signWithShares: rejects a subset with fewer than 2 shares or mismatched group_public_key" {
    // Heavy: 2048-bit keygen. `threshold_ecdsa` is `heavy` in build.zig,
    // so the DEFAULT lane builds it at ReleaseSafe and DOES run this test;
    // it skips ONLY under `-Dstrict-debug` (audit N2 claimed the opposite).
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x76616c6964617465); // "validate"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    const one = [_]root.KeyShare{kg.key_shares[0]};
    try testing.expectError(error.InvalidParameters, signWithShares(allocator, &one, "m", random));

    const kg2 = try testKeygen(allocator, random, 2, 2);
    defer kg2.deinit(allocator);
    const mixed = [_]root.KeyShare{ kg.key_shares[0], kg2.key_shares[1] };
    try testing.expectError(error.InvalidParameters, signWithShares(allocator, &mixed, "m", random));
}

/// A `std.Random` that hands back `scripted[i]` (exactly `48` bytes each) for
/// its first `scripted.len` calls to `.bytes()`, then falls through to
/// `fallback` for everything after. `signWithShares`'s Phase 1 loop is the
/// FIRST thing that draws randomness (`randomScalar` = one 48-byte
/// `.bytes()` call each for `k_i` then `gamma_i`, per party, before
/// anything else touches `random`) — so scripting exactly `2*t` chunks lets
/// a test dictate every party's `k_i`/`gamma_i` and leave every later draw
/// (commit-reveal PoK nonces, MtA/zkproof randomness) genuinely random.
const RiggedRandom = struct {
    scripted: []const [48]u8,
    calls: usize = 0,
    fallback: std.Random,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *RiggedRandom = @ptrCast(@alignCast(ptr));
        if (self.calls < self.scripted.len and buf.len == 48) {
            @memcpy(buf, &self.scripted[self.calls]);
            self.calls += 1;
        } else {
            self.fallback.bytes(buf);
        }
    }

    fn random(self: *RiggedRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

/// `Scalar` `s`'s wide-reduction encoding: `randomScalar` reduces a 48-byte
/// big-endian buffer mod q, so 16 zero bytes followed by `s`'s own 32-byte
/// encoding reduces right back to `s` (no-op reduction, since `s < q`
/// already by construction).
fn wide48(s: Scalar) [48]u8 {
    var buf = [_]u8{0} ** 48;
    @memcpy(buf[16..48], &s.toBytes(.big));
    return buf;
}

test "signWithShares: gamma_i values that sum to ZERO abort with SigningAborted, not a bad/degenerate signature" {
    // The exact class this audit's mandate calls out: "the zero scalar ...
    // on every public entry point." `delta_sum.isZero()` (Phase 4) is
    // reachable in honest operation only if Sigma gamma_i == 0 — astronomically
    // unlikely with real random draws, hence untested by every other test in
    // this file (none of them ever calls `expectError(error.SigningAborted,
    // ...)`). Rigging `gamma_1 = 1`, `gamma_2 = -1` forces the ALGEBRAIC
    // IDENTITY `delta = k * gamma = k * 0 = 0` exactly — not approximately —
    // so this is a reliable trigger, not a probabilistic one.
    // Heavy: 2048-bit keygen. `threshold_ecdsa` is `heavy` in build.zig,
    // so the DEFAULT lane builds it at ReleaseSafe and DOES run this test;
    // it skips ONLY under `-Dstrict-debug` (audit N2 claimed the opposite).
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x646567656e657261); // "degenera"
    const setup_random = prng.random();

    const kg = try testKeygen(allocator, setup_random, 2, 2);
    defer kg.deinit(allocator);
    const subset = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1] };

    const k1 = Scalar.one.add(Scalar.one); // 2, arbitrary nonzero
    const k2 = Scalar.one.add(Scalar.one).add(Scalar.one); // 3, arbitrary nonzero
    const gamma1 = Scalar.one;
    const gamma2 = Scalar.zero.sub(Scalar.one); // -1 mod q, so gamma1+gamma2 == 0

    const scripted = [_][48]u8{ wide48(k1), wide48(gamma1), wide48(k2), wide48(gamma2) };
    var rigged = RiggedRandom{ .scripted = &scripted, .fallback = setup_random };

    try testing.expectError(error.SigningAborted, signWithShares(allocator, &subset, "message", rigged.random()));
}

test "round-message codecs round-trip" {
    var prng = std.Random.DefaultPrng.init(0x636f6465635f7274); // "codec_rt"
    const random = prng.random();

    const gamma = randomScalar(random);
    const big_gamma_pt = try Secp256k1.basePoint.mul(gamma.toBytes(.big), .big);
    const big_gamma = try Element.fromPoint(big_gamma_pt);

    const commitment: GammaCommitment = .{ .index = 7, .commitment = commitGamma(7, big_gamma) };
    const c_back = GammaCommitment.fromBytes(commitment.toBytes());
    try testing.expectEqual(commitment.index, c_back.index);
    try testing.expectEqualSlices(u8, &commitment.commitment, &c_back.commitment);

    const proof = try provePoK(7, gamma, big_gamma, random);
    try testing.expect(verifyPoK(7, big_gamma, proof));
    const p_back = try SchnorrProof.fromBytes(proof.toBytes());
    try testing.expectEqualSlices(u8, &proof.r_point.toBytes(), &p_back.r_point.toBytes());
    try testing.expectEqualSlices(u8, &proof.s.toBytes(.big), &p_back.s.toBytes(.big));

    const reveal: GammaReveal = .{ .index = 7, .big_gamma = big_gamma, .proof = proof };
    const r_back = try GammaReveal.fromBytes(reveal.toBytes());
    try testing.expectEqual(reveal.index, r_back.index);
    try testing.expectEqualSlices(u8, &reveal.big_gamma.toBytes(), &r_back.big_gamma.toBytes());

    const delta_share: DeltaShare = .{ .index = 3, .delta = randomScalar(random) };
    const d_back = try DeltaShare.fromBytes(delta_share.toBytes());
    try testing.expectEqual(delta_share.index, d_back.index);
    try testing.expectEqualSlices(u8, &delta_share.delta.toBytes(.big), &d_back.delta.toBytes(.big));

    const sig_share: SigShare = .{ .index = 3, .s = randomScalar(random) };
    const s_back = try SigShare.fromBytes(sig_share.toBytes());
    try testing.expectEqual(sig_share.index, s_back.index);
    try testing.expectEqualSlices(u8, &sig_share.s.toBytes(.big), &s_back.s.toBytes(.big));
}

test "lagrangeCoefficient: Σ λ_i · x_i over a subset reconstructs the group secret (self-consistency)" {
    // Heavy: 2048-bit keygen. `threshold_ecdsa` is `heavy` in build.zig,
    // so the DEFAULT lane builds it at ReleaseSafe and DOES run this test;
    // it skips ONLY under `-Dstrict-debug` (audit N2 claimed the opposite).
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6c6167_72616e6765); // "lagrange"
    const random = prng.random();

    const kg = try testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);

    const indices = [_]u32{ kg.key_shares[0].index, kg.key_shares[1].index };
    var acc = Scalar.zero;
    for (indices) |idx| {
        const share = for (kg.key_shares) |s| {
            if (s.index == idx) break s;
        } else unreachable;
        acc = acc.add(lagrangeCoefficient(&indices, idx).mul(share.secret_share));
    }
    const expected_x = try Secp256k1.basePoint.mul(acc.toBytes(.big), .big);
    const actual_x = try kg.key_shares[0].group_public_key.point();
    try testing.expect(expected_x.equivalent(actual_x));
}

test "Ephemeral scratch: secureZero wipes the secret per-party k/gamma/w/delta/sigma scalars" {
    // Regression test for signWithShares' `defer secureZero(...); allocator.free(eph)`
    // (this file's Ephemeral[] scratch). Builds a small Ephemeral array with
    // recognizably-nonzero secret fields, applies the SAME secureZero the
    // driver's defer uses, and checks every byte went to zero — cheap
    // (no keygen), so it runs in Debug too, unlike the heavy end-to-end tests.
    const allocator = testing.allocator;
    const nonzero = Scalar.fromBytes([_]u8{0} ** 31 ++ [_]u8{0x42}, .big) catch unreachable;
    const g = Element.fromPoint(Secp256k1.basePoint) catch unreachable;

    const eph = try allocator.alloc(Ephemeral, 2);
    defer allocator.free(eph);
    for (eph) |*e| e.* = .{ .k = nonzero, .gamma = nonzero, .w = nonzero, .big_gamma = g, .delta = nonzero, .sigma = nonzero };

    std.crypto.secureZero(u8, std.mem.sliceAsBytes(eph));

    const zero_scalar_bytes = [_]u8{0} ** Ns;
    for (eph) |e| {
        try testing.expectEqualSlices(u8, &zero_scalar_bytes, &e.k.toBytes(.big));
        try testing.expectEqualSlices(u8, &zero_scalar_bytes, &e.gamma.toBytes(.big));
        try testing.expectEqualSlices(u8, &zero_scalar_bytes, &e.w.toBytes(.big));
        try testing.expectEqualSlices(u8, &zero_scalar_bytes, &e.delta.toBytes(.big));
        try testing.expectEqualSlices(u8, &zero_scalar_bytes, &e.sigma.toBytes(.big));
    }
}
