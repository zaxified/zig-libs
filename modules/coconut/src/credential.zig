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
//! ## What is GATED (`gate.fable_core_implemented`, the Fable core)
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

/// §4.2 `Sign` (threshold, per-authority): the authority holding Shamir
/// share `(x(j), y_i(j))` produces `σⱼ = (h, [x(j) + Σ mᵢ yᵢ(j)] h)` over
/// the caller-supplied common base `h` (`params.commonBase` — every
/// authority MUST use the same `h` or the partials cannot be Lagrange-
/// combined). GATED core.
pub fn signPartial(share: SecretKeyShare, h: g1.Affine, attributes: []const Fr) CoconutError!PartialCredential {
    _ = share;
    _ = h;
    _ = attributes;
    if (!gate.fable_core_implemented)
        @panic("TODO(fable/core): partial PS signature s_j = [x(j) + Σ m_i y_i(j)] h under this authority's Shamir share");
    @panic("unreachable: gate.fable_core_implemented is true but signPartial has no body");
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
    _ = allocator;
    _ = partials;
    _ = t;
    if (!gate.fable_core_implemented)
        @panic("TODO(fable/core): Lagrange-in-exponent aggregation σ = (h, Π s_j^{l_j}) over t partials sharing base h; reject mismatched h / <t partials / duplicate indices");
    @panic("unreachable: gate.fable_core_implemented is true but aggregateCredential has no body");
}

/// §4.2 `ProveCred`: re-randomise `σ → σ' = (σ₁', σ₂') = ([r'] h, [r'] s)`,
/// build the ZK commitment `κ = α · Π βᵢ^{mᵢ} · [r] g2` and `ν = [r] σ₁'`,
/// and run the Fiat-Shamir selective-disclosure NIZK proving knowledge of
/// the HIDDEN attributes `{mᵢ : ¬disclosed[i]}` and the blinding `r`.
/// `disclosed` (length `q`) selects revealed indices; `attributes` is the
/// full length-`q` vector. `random` supplies the blinding + witness
/// nonces. GATED core — the genuinely Fable-hard construction (the
/// challenge MUST commit to `κ`, `ν`, `σ'`, and every disclosed index/value
/// or the proof is unsound). Caller frees the returned proof.
pub fn proveCredential(
    allocator: std.mem.Allocator,
    random: std.Random,
    parameters: Parameters,
    vk: VerificationKey,
    cred: Credential,
    attributes: []const Fr,
    disclosed: []const bool,
) CoconutError!ShowProof {
    _ = allocator;
    _ = random;
    _ = parameters;
    _ = vk;
    _ = cred;
    _ = attributes;
    _ = disclosed;
    if (!gate.fable_core_implemented)
        @panic("TODO(fable/core): re-randomise σ, build κ/ν, and produce the Fiat-Shamir selective-disclosure NIZK over hidden attributes + blinding r");
    @panic("unreachable: gate.fable_core_implemented is true but proveCredential has no body");
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
    _ = allocator;
    _ = parameters;
    _ = vk;
    _ = proof;
    _ = disclosed_values;
    if (!gate.fable_core_implemented)
        @panic("TODO(fable/core): recompute the FS challenge over the full transcript, verify NIZK responses, σ₁'≠1, and the e(σ₁',κ)==e(σ₂'·ν,g2) pairing check");
    @panic("unreachable: gate.fable_core_implemented is true but verifyCredential has no body");
}

// ── tests (real, ungated) ───────────────────────────────────────────────────

test "psSignWithSecret / psVerifyPlain: valid credential accepted, tamper rejected" {
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 3);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(0x5151);
    const kk = try keys.keygen(allocator, prng.random(), 3, 2, 3);
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

    // h == identity → reject (guard)
    const id_cred = Credential{ .h = g1.Affine.identity, .s = cred.s };
    try std.testing.expect(!psVerifyPlain(kk.master_vk, id_cred, &attrs));
}

test "Credential / PartialCredential codec round-trips" {
    const allocator = std.testing.allocator;
    const p = try Parameters.generate(allocator, 2);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(7);
    const kk = try keys.keygen(allocator, prng.random(), 2, 2, 3);
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

test "gated cores panic while gate is false (contract frozen, body absent)" {
    // The four cores are @panic stubs today; assert the gate is off so the
    // harness's gated end-to-end tests SKIP rather than silently pass.
    try std.testing.expect(!gate.fable_core_implemented);
}

fn frOf(v: u64) Fr {
    var buf: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, buf[24..32], v, .big);
    return Fr.fromBytes(buf) catch unreachable;
}

fn g1Eql(a: g1.Affine, b: g1.Affine) bool {
    return a.x.eql(b.x) and a.y.eql(b.y) and a.infinity == b.infinity;
}
