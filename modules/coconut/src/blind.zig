// SPDX-License-Identifier: MIT

//! blind — Coconut's blind issuance (Sonnino et al., NDSS 2019, §4.3
//! `PrepareBlindSign` / `BlindSign` / `Unblind`, as the authors' reference
//! `asonnino/coconut` implements it): the authorities sign attributes they
//! never see.
//!
//! The user holds an ElGamal key `(d, γ = [d] g1)`. For private attributes
//! `m_1..m_p` and public ones `m_{p+1}..m_q` it commits
//! `cm = [o] g1 + Σ [m_i] h_i`, derives the base `h = H(cm)`, encrypts each
//! private attribute "in the exponent" of `h`, `(a_i, b_i) = ([k_i] g1,
//! [k_i] γ + [m_i] h)`, and proves in zero knowledge (`π_s`, Fiat-Shamir)
//! that the ciphertexts and `cm` are well formed and open to the same `m_i`.
//! An authority checks `π_s` and returns
//! `c̃ = (Σ [y_i] a_i, [x] h + Σ_{i≤p} [y_i] b_i + Σ_{i>p} [y_i m_i] h)`,
//! an ElGamal encryption of its PS signature `[x + Σ y_i m_i] h`; the user
//! decrypts it (`b − [d] a`) into an ordinary `PartialCredential`, and the
//! partials aggregate (`credential.aggregateCredential`) and show
//! (`credential.proveCredential`) like publicly issued ones.
//!
//! Secrets: `d`, the attribute blinding `o`, the ElGamal randomness `k_i`, the
//! private attributes and the proof witnesses on the user side; the key share
//! on the authority side. Every entry point that touches them takes them by
//! pointer, writes key material through an out-parameter, and runs its body
//! under a dead-stack burn (`burn.zig`).

const std = @import("std");
const bls = @import("bls12_381");
const keys = @import("keys.zig");
const burn = @import("burn.zig");
const params_mod = @import("params.zig");
const credential = @import("credential.zig");

const g1 = bls.g1;
const Fr = bls.Fr;
const Parameters = params_mod.Parameters;
const SecretKeyShare = keys.SecretKeyShare;
const PartialCredential = credential.PartialCredential;

/// The blind-issuance errors: `CoconutError`, plus a request whose `π_s`
/// does not verify.
pub const BlindError = credential.CoconutError || error{InvalidProof};

const blind_challenge_dst = "COCONUT-BLS12381_XMD:SHA-512_BLINDSIGN-V01_CHALLENGE_";

fn inG1(p: g1.Affine) bool {
    return g1.Jacobian.fromAffine(p).subgroupCheck();
}

fn jac(p: g1.Affine) g1.Jacobian {
    return g1.Jacobian.fromAffine(p);
}

/// The user's ElGamal key pair: secret `d`, public `γ = [d] g1`.
pub const ElGamalKeyPair = struct {
    d: Fr,
    gamma: g1.Affine,

    /// Zero the secret `d`.
    pub fn deinit(self: *ElGamalKeyPair) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.d));
    }
};

/// A fresh ElGamal key pair from `io`'s CSPRNG, written through `out`.
pub fn elgamalKeyGen(io: std.Io, out: *ElGamalKeyPair) void {
    return burn.run(burn.sign_burn, void, elgamalKeyGenBody, .{ keys.Entropy{ .io = io }, out });
}

/// **TEST ONLY** — `elgamalKeyGen` over a caller-seeded generator.
pub fn elgamalKeyGenSeededForTest(random: std.Random, out: *ElGamalKeyPair) void {
    return burn.run(burn.sign_burn, void, elgamalKeyGenBody, .{ keys.Entropy{ .seeded_for_test = random }, out });
}

fn elgamalKeyGenBody(entropy: keys.Entropy, out: *ElGamalKeyPair) void {
    while (true) {
        entropy.scalar(&out.d);
        if (!out.d.isZero()) break;
    }
    out.gamma = jac(g1.Affine.generator).scalarMul(out.d).toAffine();
}

pub const ElGamalCiphertext = struct { a: g1.Affine, b: g1.Affine };

/// `π_s`: the challenge and the responses for `o` (`rr`), each `k_i` (`rk`,
/// one per private attribute) and each attribute (`rm`, all `q`).
pub const BlindSignProof = struct {
    challenge: Fr,
    rr: Fr,
    rk: []Fr,
    rm: []Fr,
};

/// What the user sends every authority (`Λ` in the paper).
pub const BlindSignRequest = struct {
    cm: g1.Affine,
    ciphertexts: []ElGamalCiphertext,
    proof: BlindSignProof,

    pub fn deinit(self: *BlindSignRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.ciphertexts);
        allocator.free(self.proof.rk);
        allocator.free(self.proof.rm);
        self.* = undefined;
    }

    /// The common base every authority signs under: `H(cm)`.
    pub fn base(self: *const BlindSignRequest) g1.Affine {
        return bls.hash_to_curve.hashToCurveG1(&g1.toBytesCompressed(self.cm), params_mod.base_dst);
    }
};

/// An authority's blinded partial signature: `c̃ = (a, b)`, an ElGamal
/// encryption under `γ` of `[x(j) + Σ y_i(j) m_i] h`.
pub const BlindSignature = struct {
    index: u64,
    h: g1.Affine,
    a: g1.Affine,
    b: g1.Affine,
};

fn blindChallenge(
    parameters: Parameters,
    gamma: g1.Affine,
    cm: g1.Affine,
    h: g1.Affine,
    ciphertexts: []const ElGamalCiphertext,
    public_attributes: []const Fr,
    cw: g1.Affine,
    aw: []const g1.Affine,
    bw: []const g1.Affine,
) Fr {
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    hasher.update(blind_challenge_dst);
    var u64buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &u64buf, @as(u64, parameters.q), .big);
    hasher.update(&u64buf);
    std.mem.writeInt(u64, &u64buf, @as(u64, ciphertexts.len), .big);
    hasher.update(&u64buf);
    hasher.update(&g1.toBytesCompressed(g1.Affine.generator));
    hasher.update(&bls.g2.toBytesCompressed(bls.g2.Affine.generator));
    for (parameters.hs) |hi| hasher.update(&g1.toBytesCompressed(hi));
    hasher.update(&g1.toBytesCompressed(gamma));
    hasher.update(&g1.toBytesCompressed(cm));
    hasher.update(&g1.toBytesCompressed(h));
    for (ciphertexts) |c| {
        hasher.update(&g1.toBytesCompressed(c.a));
        hasher.update(&g1.toBytesCompressed(c.b));
    }
    for (public_attributes) |m| hasher.update(&m.toBytes());
    hasher.update(&g1.toBytesCompressed(cw));
    for (aw) |p| hasher.update(&g1.toBytesCompressed(p));
    for (bw) |p| hasher.update(&g1.toBytesCompressed(p));
    var digest: [64]u8 = undefined;
    hasher.final(&digest);
    return Fr.reduceWide(&digest);
}

/// §4.3 `PrepareBlindSign`: the request for `private_attributes` (encrypted,
/// proven) and `public_attributes` (in the clear), attribute order
/// `private ++ public` (`q` in all). `gamma` is the user's ElGamal public key.
/// `io` draws `o`, every `k_i` and the proof witnesses. Caller `deinit`s.
pub fn prepareBlindSign(
    allocator: std.mem.Allocator,
    io: std.Io,
    parameters: Parameters,
    gamma: g1.Affine,
    private_attributes: []const Fr,
    public_attributes: []const Fr,
) BlindError!BlindSignRequest {
    return prepareFrom(allocator, .{ .io = io }, parameters, gamma, private_attributes, public_attributes);
}

/// **TEST ONLY** — `prepareBlindSign` over a caller-seeded generator. Two
/// requests from one seed share their witnesses and leak the private
/// attributes by two-transcript extraction.
pub fn prepareBlindSignSeededForTest(
    allocator: std.mem.Allocator,
    random: std.Random,
    parameters: Parameters,
    gamma: g1.Affine,
    private_attributes: []const Fr,
    public_attributes: []const Fr,
) BlindError!BlindSignRequest {
    return prepareFrom(allocator, .{ .seeded_for_test = random }, parameters, gamma, private_attributes, public_attributes);
}

fn prepareFrom(
    allocator: std.mem.Allocator,
    entropy: keys.Entropy,
    parameters: Parameters,
    gamma: g1.Affine,
    private_attributes: []const Fr,
    public_attributes: []const Fr,
) BlindError!BlindSignRequest {
    if (private_attributes.len + public_attributes.len != parameters.q) return error.MismatchedAttributes;
    if (jac(gamma).isIdentity() or !inG1(gamma)) return error.InvalidEncoding;
    return burn.run(burn.prove_burn, BlindError!BlindSignRequest, prepareBody, .{ allocator, entropy, parameters, gamma, private_attributes, public_attributes });
}

fn prepareBody(
    allocator: std.mem.Allocator,
    entropy: keys.Entropy,
    parameters: Parameters,
    gamma: g1.Affine,
    private_attributes: []const Fr,
    public_attributes: []const Fr,
) BlindError!BlindSignRequest {
    const p = private_attributes.len;
    const q = parameters.q;
    const g1gen = jac(g1.Affine.generator);
    const gj = jac(gamma);

    // Secrets: o, k_i, and the witnesses; zeroed on every path.
    const scratch = try allocator.alloc(Fr, 2 + 2 * p + q);
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(scratch));
        allocator.free(scratch);
    }
    const o = &scratch[0];
    const wr = &scratch[1];
    const k = scratch[2..][0..p];
    const wk = scratch[2 + p ..][0..p];
    const wm = scratch[2 + 2 * p ..][0..q];
    entropy.scalar(o);
    entropy.scalar(wr);
    for (k) |*x| entropy.scalar(x);
    for (wk) |*x| entropy.scalar(x);
    for (wm) |*x| entropy.scalar(x);

    // cm = [o] g1 + Σ [m_i] h_i, attributes in private ++ public order.
    var cm_acc = g1gen.scalarMul(o.*);
    var cw_acc = g1gen.scalarMul(wr.*);
    for (parameters.hs, 0..) |hi, i| {
        const m = if (i < p) private_attributes[i] else public_attributes[i - p];
        cm_acc = cm_acc.add(jac(hi).scalarMul(m));
        cw_acc = cw_acc.add(jac(hi).scalarMul(wm[i]));
    }
    const cm = cm_acc.toAffine();
    const h = bls.hash_to_curve.hashToCurveG1(&g1.toBytesCompressed(cm), params_mod.base_dst);
    const hj = jac(h);

    const ciphertexts = try allocator.alloc(ElGamalCiphertext, p);
    errdefer allocator.free(ciphertexts);
    const aw = try allocator.alloc(g1.Affine, p);
    defer allocator.free(aw);
    const bw = try allocator.alloc(g1.Affine, p);
    defer allocator.free(bw);
    for (0..p) |i| {
        ciphertexts[i] = .{
            .a = g1gen.scalarMul(k[i]).toAffine(),
            .b = gj.scalarMul(k[i]).add(hj.scalarMul(private_attributes[i])).toAffine(),
        };
        aw[i] = g1gen.scalarMul(wk[i]).toAffine();
        bw[i] = gj.scalarMul(wk[i]).add(hj.scalarMul(wm[i])).toAffine();
    }
    const c = blindChallenge(parameters, gamma, cm, h, ciphertexts, public_attributes, cw_acc.toAffine(), aw, bw);

    // Responses z = w − c·secret (the reference's sign convention).
    const rk = try allocator.alloc(Fr, p);
    errdefer allocator.free(rk);
    const rm = try allocator.alloc(Fr, q);
    errdefer allocator.free(rm);
    for (rk, wk, k) |*r, w, s| r.* = w.sub(c.mul(s));
    for (rm, wm, 0..) |*r, w, i| {
        const m = if (i < p) private_attributes[i] else public_attributes[i - p];
        r.* = w.sub(c.mul(m));
    }
    return .{
        .cm = cm,
        .ciphertexts = ciphertexts,
        .proof = .{ .challenge = c, .rr = wr.sub(c.mul(o.*)), .rk = rk, .rm = rm },
    };
}

/// Check `π_s` of `request` against `gamma` and `public_attributes` (what an
/// authority does first in `blindSign`). Also refuses any point outside the
/// order-`r` subgroup: an authority multiplies the ciphertexts by its key
/// share, and `[y] T` for a small-order `T` reveals `y` modulo that order.
pub fn verifyBlindSignRequest(
    allocator: std.mem.Allocator,
    parameters: Parameters,
    gamma: g1.Affine,
    request: *const BlindSignRequest,
    public_attributes: []const Fr,
) BlindError!bool {
    const p = request.ciphertexts.len;
    if (p + public_attributes.len != parameters.q) return error.MismatchedAttributes;
    if (request.proof.rk.len != p or request.proof.rm.len != parameters.q) return error.MismatchedAttributes;
    if (jac(gamma).isIdentity() or !inG1(gamma) or !inG1(request.cm)) return false;
    for (request.ciphertexts) |c| if (!inG1(c.a) or !inG1(c.b)) return false;

    const pr = request.proof;
    const g1gen = jac(g1.Affine.generator);
    const h = request.base();
    const hj = jac(h);
    const aw = try allocator.alloc(g1.Affine, p);
    defer allocator.free(aw);
    const bw = try allocator.alloc(g1.Affine, p);
    defer allocator.free(bw);
    for (request.ciphertexts, 0..) |c, i| {
        // Aw_i = [c] a_i + [rk_i] g1;  Bw_i = [c] b_i + [rk_i] γ + [rm_i] h.
        aw[i] = jac(c.a).scalarMul(pr.challenge).add(g1gen.scalarMul(pr.rk[i])).toAffine();
        bw[i] = jac(c.b).scalarMul(pr.challenge).add(jac(gamma).scalarMul(pr.rk[i])).add(hj.scalarMul(pr.rm[i])).toAffine();
    }
    // Cw = [c] cm + [rr] g1 + Σ [rm_i] h_i.
    var cw = jac(request.cm).scalarMul(pr.challenge).add(g1gen.scalarMul(pr.rr));
    for (parameters.hs, pr.rm) |hi, r| cw = cw.add(jac(hi).scalarMul(r));
    // The claimed public attributes are hashed into the challenge, so a
    // request proven for one public vector does not verify for another.
    const c = blindChallenge(parameters, gamma, request.cm, h, request.ciphertexts, public_attributes, cw.toAffine(), aw, bw);
    return c.eql(pr.challenge);
}

/// §4.3 `BlindSign`, by the authority holding `share`: verify the request
/// (`error.InvalidProof` if `π_s` fails), then return the encrypted partial
/// signature. The share comes in by pointer and the body is burned.
pub fn blindSign(
    allocator: std.mem.Allocator,
    share: *const SecretKeyShare,
    parameters: Parameters,
    gamma: g1.Affine,
    request: *const BlindSignRequest,
    public_attributes: []const Fr,
) BlindError!BlindSignature {
    if (share.ys.len != parameters.q) return error.MismatchedAttributes;
    if (!try verifyBlindSignRequest(allocator, parameters, gamma, request, public_attributes)) return error.InvalidProof;
    return burn.run(burn.sign_burn, BlindSignature, blindSignBody, .{ share, request, public_attributes });
}

fn blindSignBody(share: *const SecretKeyShare, request: *const BlindSignRequest, public_attributes: []const Fr) BlindSignature {
    const p = request.ciphertexts.len;
    const h = request.base();
    // a = Σ_{i≤p} [y_i] a_i;  b = [x + Σ_{i>p} y_i m_i] h + Σ_{i≤p} [y_i] b_i.
    var a = g1.Jacobian.identity;
    var b = g1.Jacobian.identity;
    for (request.ciphertexts, share.ys[0..p]) |c, y| {
        a = a.add(jac(c.a).scalarMul(y));
        b = b.add(jac(c.b).scalarMul(y));
    }
    var e: Fr = share.x;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&e));
    for (share.ys[p..], public_attributes) |y, m| e = e.add(y.mul(m));
    b = b.add(jac(h).scalarMul(e));
    return .{ .index = share.index, .h = h, .a = a.toAffine(), .b = b.toAffine() };
}

/// §4.3 `Unblind`: decrypt an authority's `c̃` with the user's ElGamal secret
/// into the partial credential `(h, b − [d] a)`, ready for
/// `aggregateCredential`. The key comes in by pointer; the body is burned.
pub fn unblind(kp: *const ElGamalKeyPair, sig: *const BlindSignature) PartialCredential {
    return burn.run(burn.sign_burn, PartialCredential, unblindBody, .{ kp, sig });
}

fn unblindBody(kp: *const ElGamalKeyPair, sig: *const BlindSignature) PartialCredential {
    var nd = kp.d.neg();
    defer std.crypto.secureZero(u8, std.mem.asBytes(&nd));
    const s = jac(sig.b).add(jac(sig.a).scalarMul(nd)).toAffine();
    return .{ .index = sig.index, .h = sig.h, .s = s };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn frOf(v: u64) Fr {
    var b: [32]u8 = @splat(0);
    std.mem.writeInt(u64, b[24..32], v, .big);
    return Fr.fromBytes(b) catch unreachable;
}

const Setup = struct {
    p: Parameters,
    kk: keys.ThresholdKeys,
    eg: ElGamalKeyPair,

    fn init(allocator: std.mem.Allocator, seed: u64) !Setup {
        const p = try Parameters.generate(allocator, 4);
        errdefer p.deinit(allocator);
        var prng = std.Random.DefaultPrng.init(seed);
        var kk: keys.ThresholdKeys = undefined;
        try keys.keygenSeededForTest(&kk, allocator, prng.random(), 4, 2, 3);
        var eg: ElGamalKeyPair = undefined;
        elgamalKeyGenSeededForTest(prng.random(), &eg);
        return .{ .p = p, .kk = kk, .eg = eg };
    }

    fn deinit(self: *Setup, allocator: std.mem.Allocator) void {
        self.eg.deinit();
        self.kk.deinit(allocator);
        self.p.deinit(allocator);
    }
};

test "blind issuance end to end: 2-of-3 authorities sign hidden attributes; the credential verifies and shows" {
    const allocator = testing.allocator;
    var s = try Setup.init(allocator, 0xB11D);
    defer s.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(7);
    const private = [_]Fr{ frOf(111), frOf(222) };
    const public = [_]Fr{ frOf(3), frOf(4) };
    var req = try prepareBlindSignSeededForTest(allocator, prng.random(), s.p, s.eg.gamma, &private, &public);
    defer req.deinit(allocator);
    try testing.expect(try verifyBlindSignRequest(allocator, s.p, s.eg.gamma, &req, &public));

    var partials: [2]PartialCredential = undefined;
    for (&partials, [_]usize{ 0, 2 }) |*pc, j| {
        const bs = try blindSign(allocator, &s.kk.sk_shares[j], s.p, s.eg.gamma, &req, &public);
        pc.* = unblind(&s.eg, &bs);
    }
    const cred = try credential.aggregateCredential(allocator, &partials, 2);
    const attrs = private ++ public;
    try testing.expect(credential.psVerifyPlain(s.kk.master_vk, cred, &attrs));
    // It is the PS signature under the master key on the blinded base.
    const direct = credential.psSignWithSecret(&s.kk.master_sk, req.base(), &attrs);
    try testing.expect(direct.s.x.eql(cred.s.x) and direct.s.y.eql(cred.s.y));
    // And it shows like a publicly issued credential, hiding the private two.
    const mask = [_]bool{ false, false, true, true };
    const proof = try credential.proveCredentialSeededForTest(allocator, prng.random(), s.p, s.kk.master_vk, cred, &attrs, &mask, "ctx");
    defer proof.deinit(allocator);
    try testing.expect(try credential.verifyCredential(allocator, s.p, s.kk.master_vk, proof, &mask, &public, "ctx"));
    // Wrong private attribute: the PS check fails.
    const wrong = [_]Fr{ frOf(111), frOf(223), frOf(3), frOf(4) };
    try testing.expect(!credential.psVerifyPlain(s.kk.master_vk, cred, &wrong));
}

test "blind issuance: a tampered request, a different public vector or gamma, and small-order points are refused" {
    const allocator = testing.allocator;
    var s = try Setup.init(allocator, 0xB12D);
    defer s.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(9);
    const private = [_]Fr{frOf(5)};
    const public = [_]Fr{ frOf(6), frOf(7), frOf(8) };
    var req = try prepareBlindSignSeededForTest(allocator, prng.random(), s.p, s.eg.gamma, &private, &public);
    defer req.deinit(allocator);
    const share = &s.kk.sk_shares[0];

    // Another public vector than the one proven.
    const other_public = [_]Fr{ frOf(6), frOf(7), frOf(9) };
    try testing.expectError(error.InvalidProof, blindSign(allocator, share, s.p, s.eg.gamma, &req, &other_public));
    // Another gamma (the ciphertexts would not decrypt under it).
    var eg2: ElGamalKeyPair = undefined;
    elgamalKeyGenSeededForTest(prng.random(), &eg2);
    defer eg2.deinit();
    try testing.expectError(error.InvalidProof, blindSign(allocator, share, s.p, eg2.gamma, &req, &public));
    // Each field of the request, tampered.
    {
        const saved = req.ciphertexts[0];
        req.ciphertexts[0].b = jac(saved.b).add(jac(g1.Affine.generator)).toAffine();
        try testing.expectError(error.InvalidProof, blindSign(allocator, share, s.p, s.eg.gamma, &req, &public));
        req.ciphertexts[0] = saved;
    }
    {
        const saved = req.cm;
        req.cm = jac(saved).add(jac(g1.Affine.generator)).toAffine();
        try testing.expectError(error.InvalidProof, blindSign(allocator, share, s.p, s.eg.gamma, &req, &public));
        req.cm = saved;
    }
    inline for (.{ "rr", "challenge" }) |f| {
        const saved = @field(req.proof, f);
        @field(req.proof, f) = saved.add(frOf(1));
        try testing.expectError(error.InvalidProof, blindSign(allocator, share, s.p, s.eg.gamma, &req, &public));
        @field(req.proof, f) = saved;
    }
    for ([_][]Fr{ req.proof.rk, req.proof.rm }) |v| {
        const saved = v[0];
        v[0] = saved.add(frOf(1));
        try testing.expectError(error.InvalidProof, blindSign(allocator, share, s.p, s.eg.gamma, &req, &public));
        v[0] = saved;
    }
    // Still good after restoring every field.
    _ = try blindSign(allocator, share, s.p, s.eg.gamma, &req, &public);
    // Length mismatches.
    try testing.expectError(error.MismatchedAttributes, blindSign(allocator, share, s.p, s.eg.gamma, &req, public[0..2]));
    try testing.expectError(error.MismatchedAttributes, prepareBlindSignSeededForTest(allocator, prng.random(), s.p, s.eg.gamma, &private, public[0..2]));
    // An identity gamma is refused up front.
    try testing.expectError(error.InvalidEncoding, prepareBlindSignSeededForTest(allocator, prng.random(), s.p, g1.Affine.identity, &private, &public));
    try testing.expect(!try verifyBlindSignRequest(allocator, s.p, g1.Affine.identity, &req, &public));
}

test "blind issuance with no private attribute reduces to public issuance" {
    const allocator = testing.allocator;
    var s = try Setup.init(allocator, 0xB13D);
    defer s.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(11);
    const public = [_]Fr{ frOf(1), frOf(2), frOf(3), frOf(4) };
    var req = try prepareBlindSignSeededForTest(allocator, prng.random(), s.p, s.eg.gamma, &.{}, &public);
    defer req.deinit(allocator);
    var partials: [2]PartialCredential = undefined;
    for (&partials, [_]usize{ 1, 2 }) |*pc, j| {
        const bs = try blindSign(allocator, &s.kk.sk_shares[j], s.p, s.eg.gamma, &req, &public);
        pc.* = unblind(&s.eg, &bs);
    }
    const cred = try credential.aggregateCredential(allocator, &partials, 2);
    try testing.expect(credential.psVerifyPlain(s.kk.master_vk, cred, &public));
}
