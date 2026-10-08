// SPDX-License-Identifier: MIT
//! ecproofs — the curve-only Sigma proofs GG20's signing rounds need
//! (R. Gennaro, S. Goldfeder, "One Round Threshold ECDSA with Identifiable
//! Abort", IACR ePrint 2020/540, §3.3), made non-interactive with
//! Fiat-Shamir over SHA-256:
//!
//!   - `PedersenProof` (Phase 3): knowledge of `(σ, ℓ)` with
//!     `T = σ·G + ℓ·H`. The paper: prover sends `α = a·G + b·H`, answers
//!     `t = a + cσ`, `u = b + cℓ`; verifier checks `t·G + u·H == α + c·T`.
//!   - `StProof` (Phase 6): the same `σ` behind `S = σ·R` and
//!     `T = σ·G + ℓ·H`. Prover sends `α = a·R`, `β = a·G + b·H`; verifier
//!     checks `t·R == α + c·S` and `t·G + u·H == β + c·T`.
//!   - `SchnorrProof` (Phase 4): knowledge of `γ` with `Γ = γ·G`, the
//!     textbook Schnorr proof.
//!   - `DleqProof` (§4.3 type-7 opening): the same `σ` behind `S = σ·R` and
//!     `Σ = σ·G` (Chaum–Pedersen). Prover sends `α = a·R`, `β = a·G`,
//!     answers `t = a + cσ`; verifier checks `t·R == α + c·S` and
//!     `t·G == β + c·Σ`.
//!
//! `H` (`pedersenH`) is a nothing-up-my-sleeve second generator: the first
//! x-coordinate of the form `SHA-256(pedersen_h_domain || u32 ctr)` that is
//! on the curve, with even y. Nobody knows `log_G(H)` — which is what makes
//! `T` binding to `σ` (a prover who knew it could open `T` to any `σ`).
//!
//! Every challenge absorbs a caller `context` first. The signing state
//! machine passes `session id || prover index`, so a proof cannot be
//! replayed into another session or claimed by another party. Every field is
//! length-prefixed, so no two different inputs hash alike.
//!
//! Secrets (`σ`, `ℓ`, `γ`, the nonces `a`, `b`) only meet constant-time
//! operations (`Scalar` arithmetic, `Secp256k1.mul`); verification uses the
//! variable-time `mulPublic`, over public values only.

const std = @import("std");
const root = @import("root.zig");
const burn = @import("burn.zig");

// Dead-stack burns of the secret entry points (`burn.zig`), each a little
// above the depth its body reached in `stackprobe_test.zig` (ReleaseFast,
// x86_64, 2026-10-08; `verbose = true` prints the depths). The probe asserts
// that no secret survives, which a body outgrowing its burn would break.
const pedersen_commit_stack_burn = 24 * 1024;
const prove_pedersen_stack_burn = 24 * 1024;
const prove_st_stack_burn = 24 * 1024;
const prove_schnorr_stack_burn = 24 * 1024;
const prove_dleq_stack_burn = 24 * 1024;

const Sha256 = std.crypto.hash.sha2.Sha256;
const Scalar = root.Scalar;
const Secp256k1 = root.Secp256k1;
const Element = root.Element;
const Ns = root.Ns;
const Ne = root.Ne;

pub const pedersen_h_domain = "threshold_ecdsa/ecproofs/pedersen-h/v1";
pub const pedersen_proof_domain = "threshold_ecdsa/ecproofs/pedersen-pok/v1";
pub const st_proof_domain = "threshold_ecdsa/ecproofs/st-proof/v1";
pub const schnorr_proof_domain = "threshold_ecdsa/ecproofs/schnorr-pok/v1";
pub const dleq_proof_domain = "threshold_ecdsa/ecproofs/dleq/v1";

/// The second Pedersen generator `H` (see the module doc comment). Cheap to
/// recompute (a hash and a square root), so it is not cached.
pub fn pedersenH() Element {
    var ctr: u32 = 0;
    while (true) : (ctr += 1) {
        var h = Sha256.init(.{});
        h.update(pedersen_h_domain);
        var ctr_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &ctr_buf, ctr, .big);
        h.update(&ctr_buf);
        var enc: [Ne]u8 = undefined;
        enc[0] = 0x02;
        enc[1..].* = h.finalResult();
        return Element.fromBytes(enc) catch continue;
    }
}

/// `σ·G + ℓ·H` — the Phase-3 commitment `T`. Constant-time in `σ`, `ℓ`.
/// `error.InvalidElement` only for the identity (probability ~2⁻²⁵⁶).
pub fn pedersenCommit(sigma: *const Scalar, ell: *const Scalar) root.ElementError!Element {
    const result = pedersenCommitUnburned(sigma, ell);
    burn.stack(pedersen_commit_stack_burn);
    return result;
}

noinline fn pedersenCommitUnburned(sigma: *const Scalar, ell: *const Scalar) root.ElementError!Element {
    return pedersenCommitByValue(sigma.*, ell.*);
}

fn pedersenCommitByValue(sigma: Scalar, ell: Scalar) root.ElementError!Element {
    const h = pedersenH().point() catch unreachable;
    const sg = Secp256k1.basePoint.mul(sigma.toBytes(.big), .big) catch return error.InvalidElement;
    const lh = h.mul(ell.toBytes(.big), .big) catch return error.InvalidElement;
    return Element.fromPoint(sg.add(lh));
}

const Challenge = struct {
    hasher: Sha256,

    fn init(comptime domain: []const u8, context: []const u8) Challenge {
        var c: Challenge = .{ .hasher = Sha256.init(.{}) };
        c.hasher.update(domain);
        c.append(context);
        return c;
    }

    fn append(self: *Challenge, bytes: []const u8) void {
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(bytes.len), .big);
        self.hasher.update(&len_buf);
        self.hasher.update(bytes);
    }

    fn element(self: *Challenge, e: Element) void {
        self.append(&e.toBytes());
    }

    /// SHA-256 digest reduced mod q through a 48-byte buffer (bias 2⁻¹²⁸).
    fn finish(self: *Challenge) Scalar {
        var wide = [_]u8{0} ** 48;
        wide[16..48].* = self.hasher.finalResult();
        return Scalar.fromBytes48(wide, .big);
    }
};

fn randomScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

fn decodeScalar(bytes: [Ns]u8) error{InvalidEncoding}!Scalar {
    return Scalar.fromBytes(bytes, .big) catch error.InvalidEncoding;
}

/// `a·P + b·Q` over public values, or null on an identity intermediate.
fn mulAdd(p: Secp256k1, a: Scalar, q: Secp256k1, b: Scalar) ?Secp256k1 {
    const ap = p.mulPublic(a.toBytes(.big), .big) catch return null;
    const bq = q.mulPublic(b.toBytes(.big), .big) catch return null;
    return ap.add(bq);
}

// ── Phase 3: knowledge of (σ, ℓ) behind T ───────────────────────────────

pub const PedersenProof = struct {
    alpha: Element,
    t: Scalar,
    u: Scalar,

    pub const encoded_length = Ne + 2 * Ns;

    pub fn toBytes(self: PedersenProof) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        out[0..Ne].* = self.alpha.toBytes();
        out[Ne..][0..Ns].* = self.t.toBytes(.big);
        out[Ne + Ns ..][0..Ns].* = self.u.toBytes(.big);
        return out;
    }

    pub const DecodeError = root.ElementError || error{InvalidEncoding};

    pub fn fromBytes(bytes: [encoded_length]u8) DecodeError!PedersenProof {
        return .{
            .alpha = try Element.fromBytes(bytes[0..Ne].*),
            .t = try decodeScalar(bytes[Ne..][0..Ns].*),
            .u = try decodeScalar(bytes[Ne + Ns ..][0..Ns].*),
        };
    }
};

fn pedersenChallenge(context: []const u8, t_point: Element, alpha: Element) Scalar {
    var c = Challenge.init(pedersen_proof_domain, context);
    c.element(pedersenH());
    c.element(t_point);
    c.element(alpha);
    return c.finish();
}

pub fn provePedersen(sigma: *const Scalar, ell: *const Scalar, t_point: Element, context: []const u8, random: std.Random) PedersenProof {
    const result = provePedersenUnburned(sigma, ell, t_point, context, random);
    burn.stack(prove_pedersen_stack_burn);
    return result;
}

noinline fn provePedersenUnburned(sigma: *const Scalar, ell: *const Scalar, t_point: Element, context: []const u8, random: std.Random) PedersenProof {
    return provePedersenByValue(sigma.*, ell.*, t_point, context, random);
}

fn provePedersenByValue(sigma: Scalar, ell: Scalar, t_point: Element, context: []const u8, random: std.Random) PedersenProof {
    while (true) {
        var a = randomScalar(random);
        var b = randomScalar(random);
        defer {
            std.crypto.secureZero(u8, std.mem.asBytes(&a));
            std.crypto.secureZero(u8, std.mem.asBytes(&b));
        }
        const alpha = pedersenCommit(&a, &b) catch continue;
        const c = pedersenChallenge(context, t_point, alpha);
        return .{ .alpha = alpha, .t = a.add(c.mul(sigma)), .u = b.add(c.mul(ell)) };
    }
}

/// `t·G + u·H == α + c·T`.
pub fn verifyPedersen(proof: PedersenProof, t_point: Element, context: []const u8) bool {
    const c = pedersenChallenge(context, t_point, proof.alpha);
    const h = pedersenH().point() catch return false;
    const lhs = mulAdd(Secp256k1.basePoint, proof.t, h, proof.u) orelse return false;
    const t_pt = t_point.point() catch return false;
    const ct = t_pt.mulPublic(c.toBytes(.big), .big) catch return false;
    const alpha = proof.alpha.point() catch return false;
    return lhs.equivalent(alpha.add(ct));
}

// ── Phase 6: the same σ behind S = σ·R and T = σ·G + ℓ·H ─────────────────

pub const StProof = struct {
    alpha: Element,
    beta: Element,
    t: Scalar,
    u: Scalar,

    pub const encoded_length = 2 * Ne + 2 * Ns;

    pub fn toBytes(self: StProof) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        out[0..Ne].* = self.alpha.toBytes();
        out[Ne..][0..Ne].* = self.beta.toBytes();
        out[2 * Ne ..][0..Ns].* = self.t.toBytes(.big);
        out[2 * Ne + Ns ..][0..Ns].* = self.u.toBytes(.big);
        return out;
    }

    pub const DecodeError = root.ElementError || error{InvalidEncoding};

    pub fn fromBytes(bytes: [encoded_length]u8) DecodeError!StProof {
        return .{
            .alpha = try Element.fromBytes(bytes[0..Ne].*),
            .beta = try Element.fromBytes(bytes[Ne..][0..Ne].*),
            .t = try decodeScalar(bytes[2 * Ne ..][0..Ns].*),
            .u = try decodeScalar(bytes[2 * Ne + Ns ..][0..Ns].*),
        };
    }
};

fn stChallenge(context: []const u8, r_point: Element, s_point: Element, t_point: Element, alpha: Element, beta: Element) Scalar {
    var c = Challenge.init(st_proof_domain, context);
    c.element(pedersenH());
    c.element(r_point);
    c.element(s_point);
    c.element(t_point);
    c.element(alpha);
    c.element(beta);
    return c.finish();
}

/// `error.InvalidElement` only for an `r_point` that does not decode (the
/// caller's `R` is always a valid non-identity point).
pub fn proveSt(
    sigma: *const Scalar,
    ell: *const Scalar,
    r_point: Element,
    s_point: Element,
    t_point: Element,
    context: []const u8,
    random: std.Random,
) root.ElementError!StProof {
    const result = proveStUnburned(sigma, ell, r_point, s_point, t_point, context, random);
    burn.stack(prove_st_stack_burn);
    return result;
}

noinline fn proveStUnburned(
    sigma: *const Scalar,
    ell: *const Scalar,
    r_point: Element,
    s_point: Element,
    t_point: Element,
    context: []const u8,
    random: std.Random,
) root.ElementError!StProof {
    return proveStByValue(sigma.*, ell.*, r_point, s_point, t_point, context, random);
}

fn proveStByValue(
    sigma: Scalar,
    ell: Scalar,
    r_point: Element,
    s_point: Element,
    t_point: Element,
    context: []const u8,
    random: std.Random,
) root.ElementError!StProof {
    const r_pt = try r_point.point();
    while (true) {
        var a = randomScalar(random);
        var b = randomScalar(random);
        defer {
            std.crypto.secureZero(u8, std.mem.asBytes(&a));
            std.crypto.secureZero(u8, std.mem.asBytes(&b));
        }
        const alpha_pt = r_pt.mul(a.toBytes(.big), .big) catch continue;
        const alpha = Element.fromPoint(alpha_pt) catch continue;
        const beta = pedersenCommit(&a, &b) catch continue;
        const c = stChallenge(context, r_point, s_point, t_point, alpha, beta);
        return .{ .alpha = alpha, .beta = beta, .t = a.add(c.mul(sigma)), .u = b.add(c.mul(ell)) };
    }
}

/// `t·R == α + c·S` and `t·G + u·H == β + c·T`.
pub fn verifySt(proof: StProof, r_point: Element, s_point: Element, t_point: Element, context: []const u8) bool {
    const c = stChallenge(context, r_point, s_point, t_point, proof.alpha, proof.beta);
    const c_bytes = c.toBytes(.big);

    const r_pt = r_point.point() catch return false;
    const tr = r_pt.mulPublic(proof.t.toBytes(.big), .big) catch return false;
    const s_pt = s_point.point() catch return false;
    const cs = s_pt.mulPublic(c_bytes, .big) catch return false;
    const alpha = proof.alpha.point() catch return false;
    if (!tr.equivalent(alpha.add(cs))) return false;

    const h = pedersenH().point() catch return false;
    const lhs = mulAdd(Secp256k1.basePoint, proof.t, h, proof.u) orelse return false;
    const t_pt = t_point.point() catch return false;
    const ct = t_pt.mulPublic(c_bytes, .big) catch return false;
    const beta = proof.beta.point() catch return false;
    return lhs.equivalent(beta.add(ct));
}

// ── Phase 4: knowledge of γ behind Γ = γ·G ──────────────────────────────

pub const SchnorrProof = struct {
    r_point: Element,
    s: Scalar,

    pub const encoded_length = Ne + Ns;

    pub fn toBytes(self: SchnorrProof) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        out[0..Ne].* = self.r_point.toBytes();
        out[Ne..][0..Ns].* = self.s.toBytes(.big);
        return out;
    }

    pub const DecodeError = root.ElementError || error{InvalidEncoding};

    pub fn fromBytes(bytes: [encoded_length]u8) DecodeError!SchnorrProof {
        return .{
            .r_point = try Element.fromBytes(bytes[0..Ne].*),
            .s = try decodeScalar(bytes[Ne..][0..Ns].*),
        };
    }
};

fn schnorrChallenge(context: []const u8, x_point: Element, r_point: Element) Scalar {
    var c = Challenge.init(schnorr_proof_domain, context);
    c.element(x_point);
    c.element(r_point);
    return c.finish();
}

pub fn proveSchnorr(x: *const Scalar, x_point: Element, context: []const u8, random: std.Random) SchnorrProof {
    const result = proveSchnorrUnburned(x, x_point, context, random);
    burn.stack(prove_schnorr_stack_burn);
    return result;
}

noinline fn proveSchnorrUnburned(x: *const Scalar, x_point: Element, context: []const u8, random: std.Random) SchnorrProof {
    return proveSchnorrByValue(x.*, x_point, context, random);
}

fn proveSchnorrByValue(x: Scalar, x_point: Element, context: []const u8, random: std.Random) SchnorrProof {
    while (true) {
        var k = randomScalar(random);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
        const r_full = Secp256k1.basePoint.mul(k.toBytes(.big), .big) catch continue;
        const r_point = Element.fromPoint(r_full) catch continue;
        const c = schnorrChallenge(context, x_point, r_point);
        return .{ .r_point = r_point, .s = k.add(c.mul(x)) };
    }
}

/// `s·G == R + c·X`.
pub fn verifySchnorr(proof: SchnorrProof, x_point: Element, context: []const u8) bool {
    const c = schnorrChallenge(context, x_point, proof.r_point);
    const lhs = Secp256k1.basePoint.mulPublic(proof.s.toBytes(.big), .big) catch return false;
    const x_pt = x_point.point() catch return false;
    const cx = x_pt.mulPublic(c.toBytes(.big), .big) catch return false;
    const r_pt = proof.r_point.point() catch return false;
    return lhs.equivalent(r_pt.add(cx));
}

// ── §4.3 type-7 opening: the same σ behind S = σ·R and Σ = σ·G ──────────

pub const DleqProof = struct {
    alpha: Element,
    beta: Element,
    t: Scalar,

    pub const encoded_length = 2 * Ne + Ns;

    pub fn toBytes(self: DleqProof) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        out[0..Ne].* = self.alpha.toBytes();
        out[Ne..][0..Ne].* = self.beta.toBytes();
        out[2 * Ne ..][0..Ns].* = self.t.toBytes(.big);
        return out;
    }

    pub const DecodeError = root.ElementError || error{InvalidEncoding};

    pub fn fromBytes(bytes: [encoded_length]u8) DecodeError!DleqProof {
        return .{
            .alpha = try Element.fromBytes(bytes[0..Ne].*),
            .beta = try Element.fromBytes(bytes[Ne..][0..Ne].*),
            .t = try decodeScalar(bytes[2 * Ne ..][0..Ns].*),
        };
    }
};

fn dleqChallenge(context: []const u8, r_point: Element, s_point: Element, sigma_point: Element, alpha: Element, beta: Element) Scalar {
    var c = Challenge.init(dleq_proof_domain, context);
    c.element(r_point);
    c.element(s_point);
    c.element(sigma_point);
    c.element(alpha);
    c.element(beta);
    return c.finish();
}

/// Proves `log_R(S) = log_G(Σ) = σ`. `error.InvalidElement` only for an
/// `r_point` that does not decode.
pub fn proveDleq(sigma: *const Scalar, r_point: Element, s_point: Element, sigma_point: Element, context: []const u8, random: std.Random) root.ElementError!DleqProof {
    const result = proveDleqUnburned(sigma, r_point, s_point, sigma_point, context, random);
    burn.stack(prove_dleq_stack_burn);
    return result;
}

noinline fn proveDleqUnburned(sigma: *const Scalar, r_point: Element, s_point: Element, sigma_point: Element, context: []const u8, random: std.Random) root.ElementError!DleqProof {
    return proveDleqByValue(sigma.*, r_point, s_point, sigma_point, context, random);
}

fn proveDleqByValue(sigma: Scalar, r_point: Element, s_point: Element, sigma_point: Element, context: []const u8, random: std.Random) root.ElementError!DleqProof {
    const r_pt = try r_point.point();
    while (true) {
        var a = randomScalar(random);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&a));
        const alpha = Element.fromPoint(r_pt.mul(a.toBytes(.big), .big) catch continue) catch continue;
        const beta = Element.fromPoint(Secp256k1.basePoint.mul(a.toBytes(.big), .big) catch continue) catch continue;
        const c = dleqChallenge(context, r_point, s_point, sigma_point, alpha, beta);
        return .{ .alpha = alpha, .beta = beta, .t = a.add(c.mul(sigma)) };
    }
}

/// `t·R == α + c·S` and `t·G == β + c·Σ`.
pub fn verifyDleq(proof: DleqProof, r_point: Element, s_point: Element, sigma_point: Element, context: []const u8) bool {
    const c = dleqChallenge(context, r_point, s_point, sigma_point, proof.alpha, proof.beta);
    const c_bytes = c.toBytes(.big);
    const t_bytes = proof.t.toBytes(.big);
    const r_pt = r_point.point() catch return false;
    const tr = r_pt.mulPublic(t_bytes, .big) catch return false;
    const cs = (s_point.point() catch return false).mulPublic(c_bytes, .big) catch return false;
    if (!tr.equivalent((proof.alpha.point() catch return false).add(cs))) return false;
    const tg = Secp256k1.basePoint.mulPublic(t_bytes, .big) catch return false;
    const csig = (sigma_point.point() catch return false).mulPublic(c_bytes, .big) catch return false;
    return tg.equivalent((proof.beta.point() catch return false).add(csig));
}
// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn pointOf(s: Scalar) Element {
    return Element.fromPoint(Secp256k1.basePoint.mul(s.toBytes(.big), .big) catch unreachable) catch unreachable;
}

test "pedersenH: deterministic, on the curve, not G" {
    const h1 = pedersenH();
    const h2 = pedersenH();
    try testing.expectEqualSlices(u8, &h1.toBytes(), &h2.toBytes());
    _ = try h1.point();
    try testing.expect(!std.mem.eql(u8, &h1.toBytes(), &(try Element.fromPoint(Secp256k1.basePoint)).toBytes()));
}

test "PedersenProof: honest accepts; wrong T, wrong context, every mangled field reject" {
    var prng = std.Random.DefaultPrng.init(0x7065_6465_7273_656e);
    const random = prng.random();
    const sigma = randomScalar(random);
    const ell = randomScalar(random);
    const t_point = try pedersenCommit(&sigma, &ell);
    const proof = provePedersen(&sigma, &ell, t_point, "ctx", random);
    try testing.expect(verifyPedersen(proof, t_point, "ctx"));
    try testing.expect(!verifyPedersen(proof, t_point, "ctx2"));
    const ell1 = ell.add(Scalar.one);
    try testing.expect(!verifyPedersen(proof, try pedersenCommit(&sigma, &ell1), "ctx"));

    var bad = proof;
    bad.t = bad.t.add(Scalar.one);
    try testing.expect(!verifyPedersen(bad, t_point, "ctx"));
    bad = proof;
    bad.u = bad.u.add(Scalar.one);
    try testing.expect(!verifyPedersen(bad, t_point, "ctx"));
    bad = proof;
    bad.alpha = pointOf(Scalar.one);
    try testing.expect(!verifyPedersen(bad, t_point, "ctx"));

    // A prover who does not know (σ, ℓ) for T: a proof for another T.
    const other = provePedersen(&sigma, &ell1, try pedersenCommit(&sigma, &ell1), "ctx", random);
    try testing.expect(!verifyPedersen(other, t_point, "ctx"));

    const back = try PedersenProof.fromBytes(proof.toBytes());
    try testing.expect(verifyPedersen(back, t_point, "ctx"));

    // Transcript completeness: if the challenge did not bind T, a prover
    // could fix α, take the challenge, pick any t, u and only THEN solve
    // T = c⁻¹·(t·G + u·H − α) — a "proof" for a T it cannot open.
    const alpha = pointOf(randomScalar(random));
    const c = blk: {
        var ch = Challenge.init(pedersen_proof_domain, "ctx");
        ch.element(pedersenH());
        ch.element(alpha);
        break :blk ch.finish();
    };
    const ft = randomScalar(random);
    const fu = randomScalar(random);
    const h = try pedersenH().point();
    const sum = (try Secp256k1.basePoint.mul(ft.toBytes(.big), .big)).add(try h.mul(fu.toBytes(.big), .big)).sub(try alpha.point());
    const forged_t = try Element.fromPoint(try sum.mul(c.invert().toBytes(.big), .big));
    try testing.expect(!verifyPedersen(.{ .alpha = alpha, .t = ft, .u = fu }, forged_t, "ctx"));
}

test "StProof: honest accepts; S from another σ, T from another σ, wrong R, mangled fields reject" {
    var prng = std.Random.DefaultPrng.init(0x7374_7072_6f6f66);
    const random = prng.random();
    const sigma = randomScalar(random);
    const ell = randomScalar(random);
    const r_point = pointOf(randomScalar(random));
    const r_pt = try r_point.point();
    const s_point = try Element.fromPoint(try r_pt.mul(sigma.toBytes(.big), .big));
    const t_point = try pedersenCommit(&sigma, &ell);

    const proof = try proveSt(&sigma, &ell, r_point, s_point, t_point, "ctx", random);
    try testing.expect(verifySt(proof, r_point, s_point, t_point, "ctx"));
    try testing.expect(!verifySt(proof, r_point, s_point, t_point, "other"));

    // The cheat this proof exists for: S built from σ' ≠ σ (T still honest).
    const sigma2 = sigma.add(Scalar.one);
    const s_bad = try Element.fromPoint(try r_pt.mul(sigma2.toBytes(.big), .big));
    const cheat = try proveSt(&sigma2, &ell, r_point, s_bad, t_point, "ctx", random);
    try testing.expect(!verifySt(cheat, r_point, s_bad, t_point, "ctx"));
    try testing.expect(!verifySt(proof, r_point, s_bad, t_point, "ctx"));
    try testing.expect(!verifySt(proof, pointOf(Scalar.one), s_point, t_point, "ctx"));
    try testing.expect(!verifySt(proof, r_point, s_point, try pedersenCommit(&sigma2, &ell), "ctx"));

    var bad = proof;
    bad.t = bad.t.add(Scalar.one);
    try testing.expect(!verifySt(bad, r_point, s_point, t_point, "ctx"));
    bad = proof;
    bad.u = bad.u.add(Scalar.one);
    try testing.expect(!verifySt(bad, r_point, s_point, t_point, "ctx"));
    bad = proof;
    bad.alpha = pointOf(Scalar.one);
    try testing.expect(!verifySt(bad, r_point, s_point, t_point, "ctx"));
    bad = proof;
    bad.beta = pointOf(Scalar.one);
    try testing.expect(!verifySt(bad, r_point, s_point, t_point, "ctx"));

    const back = try StProof.fromBytes(proof.toBytes());
    try testing.expect(verifySt(back, r_point, s_point, t_point, "ctx"));

    // Each equation alone: a transcript whose β side is honest but whose α
    // was made with another nonce fails only `t·R == α + c·S`, and one whose
    // α side is honest but whose β hides another b fails only the second.
    const a = randomScalar(random);
    const b = randomScalar(random);
    for ([_]bool{ true, false }) |break_alpha| {
        const alpha_nonce = if (break_alpha) a.add(Scalar.one) else a;
        const alpha = try Element.fromPoint(try r_pt.mul(alpha_nonce.toBytes(.big), .big));
        const b_used = if (break_alpha) b else b.add(Scalar.one);
        const beta = try pedersenCommit(&a, &b_used);
        const c = stChallenge("ctx", r_point, s_point, t_point, alpha, beta);
        const half: StProof = .{ .alpha = alpha, .beta = beta, .t = a.add(c.mul(sigma)), .u = b.add(c.mul(ell)) };
        try testing.expect(!verifySt(half, r_point, s_point, t_point, "ctx"));
    }
}

test "SchnorrProof: honest accepts; foreign point, wrong context, mangled fields reject" {
    var prng = std.Random.DefaultPrng.init(0x7363_686e_6f72_72);
    const random = prng.random();
    const x = randomScalar(random);
    const x_point = pointOf(x);
    const proof = proveSchnorr(&x, x_point, "ctx", random);
    try testing.expect(verifySchnorr(proof, x_point, "ctx"));
    try testing.expect(!verifySchnorr(proof, x_point, "ctx2"));
    try testing.expect(!verifySchnorr(proof, pointOf(x.add(Scalar.one)), "ctx"));
    var bad = proof;
    bad.s = bad.s.add(Scalar.one);
    try testing.expect(!verifySchnorr(bad, x_point, "ctx"));
    bad = proof;
    bad.r_point = pointOf(Scalar.one);
    try testing.expect(!verifySchnorr(bad, x_point, "ctx"));
    const back = try SchnorrProof.fromBytes(proof.toBytes());
    try testing.expect(verifySchnorr(back, x_point, "ctx"));
}

test "DleqProof: honest accepts; S or Σ from another σ, wrong R, wrong context, mangled fields reject" {
    var prng = std.Random.DefaultPrng.init(0x646c_6571);
    const random = prng.random();
    const sigma = randomScalar(random);
    const r_point = pointOf(randomScalar(random));
    const s_point = try Element.fromPoint(try (try r_point.point()).mul(sigma.toBytes(.big), .big));
    const sigma_point = pointOf(sigma);
    const proof = try proveDleq(&sigma, r_point, s_point, sigma_point, "ctx", random);
    try testing.expect(verifyDleq(proof, r_point, s_point, sigma_point, "ctx"));
    try testing.expect(!verifyDleq(proof, r_point, s_point, sigma_point, "ctx2"));
    try testing.expect(!verifyDleq(proof, r_point, s_point, pointOf(sigma.add(Scalar.one)), "ctx"));
    const s_other = try Element.fromPoint(try (try r_point.point()).mul(sigma.add(Scalar.one).toBytes(.big), .big));
    try testing.expect(!verifyDleq(proof, r_point, s_other, sigma_point, "ctx"));
    try testing.expect(!verifyDleq(proof, pointOf(Scalar.one), s_point, sigma_point, "ctx"));
    // A prover whose σ is not the one behind Σ cannot make a proof that verifies.
    const sigma_lie = sigma.add(Scalar.one);
    const lying = try proveDleq(&sigma_lie, r_point, s_point, sigma_point, "ctx", random);
    try testing.expect(!verifyDleq(lying, r_point, s_point, sigma_point, "ctx"));
    var bad = proof;
    bad.t = bad.t.add(Scalar.one);
    try testing.expect(!verifyDleq(bad, r_point, s_point, sigma_point, "ctx"));
    bad = proof;
    bad.alpha = pointOf(Scalar.one);
    try testing.expect(!verifyDleq(bad, r_point, s_point, sigma_point, "ctx"));
    bad = proof;
    bad.beta = pointOf(Scalar.one);
    try testing.expect(!verifyDleq(bad, r_point, s_point, sigma_point, "ctx"));
    const back = try DleqProof.fromBytes(proof.toBytes());
    try testing.expect(verifyDleq(back, r_point, s_point, sigma_point, "ctx"));
}

test "fuzz: PedersenProof/StProof/SchnorrProof.fromBytes never panic" {
    try testing.fuzz({}, fuzzDecoders, .{});
}
fn fuzzDecoders(_: void, smith: *std.testing.Smith) !void {
    var a: [PedersenProof.encoded_length]u8 = undefined;
    smith.bytes(&a);
    _ = PedersenProof.fromBytes(a) catch {};
    var b: [StProof.encoded_length]u8 = undefined;
    smith.bytes(&b);
    _ = StProof.fromBytes(b) catch {};
    var c: [SchnorrProof.encoded_length]u8 = undefined;
    smith.bytes(&c);
    _ = SchnorrProof.fromBytes(c) catch {};
    var d: [DleqProof.encoded_length]u8 = undefined;
    smith.bytes(&d);
    _ = DleqProof.fromBytes(d) catch {};
}

test "DleqProof: each equation is load-bearing, and the challenge binds Σ" {
    var prng = std.Random.DefaultPrng.init(0x646c_6571_32);
    const random = prng.random();
    const sigma = randomScalar(random);
    const other = sigma.add(Scalar.one);
    const r_point = pointOf(randomScalar(random));
    const s_true = try Element.fromPoint(try (try r_point.point()).mul(sigma.toBytes(.big), .big));
    const s_other = try Element.fromPoint(try (try r_point.point()).mul(other.toBytes(.big), .big));
    // The witness matches Σ = σ'·G but S = σ·R: only S R-equation can refuse.
    const split_s = try proveDleq(&other, r_point, s_true, pointOf(other), "ctx", random);
    try testing.expect(!verifyDleq(split_s, r_point, s_true, pointOf(other), "ctx"));
    // The witness matches S = σ'·R but Σ = σ·G: only the G-equation can refuse.
    const split_g = try proveDleq(&other, r_point, s_other, pointOf(sigma), "ctx", random);
    try testing.expect(!verifyDleq(split_g, r_point, s_other, pointOf(sigma), "ctx"));
    // Control: a consistent statement verifies.
    const ok = try proveDleq(&other, r_point, s_other, pointOf(other), "ctx", random);
    try testing.expect(verifyDleq(ok, r_point, s_other, pointOf(other), "ctx"));
    // The challenge depends on Σ.
    const a = pointOf(Scalar.one);
    try testing.expect(!dleqChallenge("ctx", r_point, s_true, pointOf(sigma), a, a).equivalent(dleqChallenge("ctx", r_point, s_true, pointOf(other), a, a)));
}
