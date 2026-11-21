// SPDX-License-Identifier: MIT

//! dkg — dealer-free key generation for Coconut over BLS12-381: the
//! two-round Pedersen DKG of the FROST paper (Komlo–Goldberg 2020, Figure 1)
//! in frost-core's `part1` / `part2` / `part3` shape (the sibling
//! `frost.dkg` follows the same reference over secp256k1), run once per key
//! component. A Coconut key is the vector `(x, y_1..y_q)`, so every
//! participant deals `q + 1` polynomials of degree `t − 1` instead of one.
//!
//! ```text
//! part1(i, n, t, q):                       round 1
//!   for each component c in 0..q:  a_ic0..a_ic(t-1) random,  k_ic random
//!     φ_ick = [a_ick] g2                    (Feldman commitment, broadcast)
//!     R_ic = [k_ic] g2;  c_ic = H(i ‖ c ‖ φ_ic0 ‖ R_ic);  μ_ic = k_ic + a_ic0·c_ic
//!   broadcast (φ_i, (R_ic, μ_ic)_c);  keep a_i, φ_i
//! part2(secret_1, {(ℓ, φ_ℓ, σ_ℓ)}):         round 2
//!   check every φ_ℓck in G2 and not the identity at k = 0, and
//!   R_ℓc == [μ_ℓc] g2 − [c_ℓc] φ_ℓc0 for every ℓ ≠ i and c
//!   send (f_ℓ'c(ℓ))_c privately to each ℓ;  keep (f_ic(i))_c, φ_i
//! part3(secret_2, {(ℓ, φ_ℓ)}, {(ℓ, (f_ℓc(i))_c)}):
//!   check [f_ℓc(i)] g2 == Σ_k [i^k] φ_ℓck   for every ℓ ≠ i and c
//!   share:  x(i) = Σ_ℓ f_ℓ0(i),  y_c(i) = Σ_ℓ f_ℓc(i)
//!   group vk: α = Σ_ℓ φ_ℓ00,  β_c = Σ_ℓ φ_ℓc0
//!   every vk share j: (Σ_k [j^k] Σ_ℓ φ_ℓck)_c
//! ```
//!
//! The commitments live in G2 because that is where Coconut's verification
//! key lives: the summed commitment's constant terms ARE the group key
//! `(α, β_1..β_q)`, and its evaluation at `j` IS authority `j`'s
//! `VerificationKeyShare`, so the output plugs into `signPartial`,
//! `aggregateVerificationKeys`, `aggregateCredential` and `blindSign`
//! unchanged.
//!
//! Participants are numbered `1..n` (Coconut's Shamir indices). Packages are
//! plain values; the caller carries them (round-1 packages over an
//! authenticated broadcast channel, round-2 shares over confidential,
//! authenticated point-to-point channels — the DKG's own requirement). Each
//! `*Received.sender` is the identity the channel vouches for. A failed
//! check names the first failing sender in `culprit`.
//!
//! Randomness is drawn inside `part1` (`keys.Entropy`, fail-closed
//! `std.Io.randomSecure`), as everywhere in this module. Every entry point
//! that touches a secret runs its body one frame down under a dead-stack
//! burn (`burn.zig`); secret heap scratch is wiped before it is freed.

const std = @import("std");
const bls = @import("bls12_381");
const keys = @import("keys.zig");
const burn = @import("burn.zig");
const lagrange = @import("lagrange.zig");

const Allocator = std.mem.Allocator;
const g2 = bls.g2;
const Fr = bls.Fr;
const SecretKeyShare = keys.SecretKeyShare;
const VerificationKey = keys.VerificationKey;
const VerificationKeyShare = keys.VerificationKeyShare;

const pok_dst = "COCONUT-BLS12381G2_XMD:SHA-512_DKG-V01_POK_";

// ── packages ────────────────────────────────────────────────────────────────

/// What participant `i` broadcasts after `part1`: the Feldman commitments
/// `φ_ick` (component-major: `commitment[c * t + k]`) and, per component, the
/// proof of knowledge of its constant term `(R_ic, μ_ic)`. Public.
pub const Round1Package = struct {
    /// `(q + 1) · t` points, `commitment[c * t + k] = [a_ick] g2`.
    commitment: []g2.Affine,
    /// `q + 1` proof commitments `R_ic`.
    pok_r: []g2.Affine,
    /// `q + 1` proof responses `μ_ic`.
    pok_mu: []Fr,

    pub fn deinit(self: *Round1Package, allocator: Allocator) void {
        allocator.free(self.commitment);
        allocator.free(self.pok_r);
        allocator.free(self.pok_mu);
        self.* = undefined;
    }
};

/// A round-1 package as received from `sender`.
pub const Round1Received = struct {
    sender: u64,
    package: Round1Package,
};

/// What `part1` keeps for `part2`: the polynomial coefficients (secret,
/// wiped by `deinit`) and the participant's own commitment.
pub const Round1SecretPackage = struct {
    index: u64,
    n: u64,
    t: u64,
    q: usize,
    /// `(q + 1) · t` coefficients, component-major like the commitment.
    coefficients: []Fr,
    commitment: []g2.Affine,

    pub fn deinit(self: *Round1SecretPackage, allocator: Allocator) void {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.coefficients));
        allocator.free(self.coefficients);
        allocator.free(self.commitment);
        self.* = undefined;
    }
};

/// The secret share participant `i` sends to `recipient`:
/// `values[c] = f_ic(recipient)` for every component. Secret; confidential
/// channel.
pub const Round2Package = struct {
    recipient: u64,
    values: []Fr,
};

/// Wipe and free the shares `part2` returned.
pub fn freeRound2Packages(allocator: Allocator, packages: []Round2Package) void {
    for (packages) |p| {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(p.values));
        allocator.free(p.values);
    }
    allocator.free(packages);
}

/// A round-2 share as received from `sender`.
pub const Round2Received = struct {
    sender: u64,
    values: []const Fr,
};

/// What `part2` keeps for `part3`: the participant's own evaluation
/// `f_ic(i)` per component (secret, wiped by `deinit`) and its commitment.
pub const Round2SecretPackage = struct {
    index: u64,
    n: u64,
    t: u64,
    q: usize,
    own_values: []Fr,
    commitment: []g2.Affine,

    pub fn deinit(self: *Round2SecretPackage, allocator: Allocator) void {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.own_values));
        allocator.free(self.own_values);
        allocator.free(self.commitment);
        self.* = undefined;
    }
};

/// The public output of `part3`, identical at every participant: the group
/// verification key and every authority's verification-key share (indices
/// `1..n`, ascending).
pub const PublicKeyPackage = struct {
    t: u64,
    vk: VerificationKey,
    vk_shares: []VerificationKeyShare,

    pub fn deinit(self: *PublicKeyPackage, allocator: Allocator) void {
        for (self.vk_shares) |s| s.deinit(allocator);
        allocator.free(self.vk_shares);
        self.vk.deinit(allocator);
        self.* = undefined;
    }
};

// ── errors (frost-core's names) ─────────────────────────────────────────────

pub const Part1Error = error{
    OutOfMemory,
    /// `t < 2`, `n < t`, `q == 0`, or `index` outside `1..n`.
    InvalidParameters,
};

pub const Part2Error = error{
    OutOfMemory,
    /// Not exactly `n − 1` round-1 packages.
    IncorrectNumberOfPackages,
    /// A sender outside `1..n` or equal to the participant's own index.
    UnknownIdentifier,
    /// Two packages from the same sender.
    DuplicatedIdentifier,
    /// A sender's commitment does not have `(q + 1) · t` points, or its
    /// proof does not have `q + 1` commitments and responses.
    IncorrectNumberOfCommitments,
    /// A sender's proof of knowledge does not verify, or a point of its
    /// commitment is outside G2 (or the identity at a constant term); the
    /// sender is written to `culprit`.
    InvalidProofOfKnowledge,
};

pub const Part3Error = error{
    OutOfMemory,
    /// Not exactly `n − 1` round-1 packages, or not as many round-2 shares.
    IncorrectNumberOfPackages,
    /// A sender outside `1..n` or equal to the participant's own index.
    UnknownIdentifier,
    /// Two packages (round 1 or round 2) from the same sender.
    DuplicatedIdentifier,
    /// A round-1 sender with no round-2 share.
    IncorrectPackage,
    /// A sender's commitment does not have `(q + 1) · t` points, or its
    /// share does not have `q + 1` values.
    IncorrectNumberOfCommitments,
    /// A sender's share is not on its committed polynomials; the sender is
    /// written to `culprit`.
    InvalidSecretShare,
    /// A summed constant term is the identity (the participants'
    /// polynomials cancel). Not reachable with honestly drawn coefficients.
    InvalidCommitment,
};

// ── part1 ───────────────────────────────────────────────────────────────────

/// Round 1 for participant `index` of `n` (threshold `t`, `q` attributes):
/// draws the `q + 1` polynomials and the proof nonces from `io`, writes the
/// secret package to `out` (owned; `Round1SecretPackage.deinit`) and returns
/// the package to broadcast (owned; `Round1Package.deinit`).
pub fn part1(
    allocator: Allocator,
    io: std.Io,
    out: *Round1SecretPackage,
    index: u64,
    n: u64,
    t: u64,
    q: usize,
) Part1Error!Round1Package {
    return part1From(allocator, .{ .io = io }, out, index, n, t, q);
}

/// **TEST ONLY** — `part1` over a caller-seeded generator. The polynomials
/// are a function of the seed: whoever recovers it holds this participant's
/// contribution to the group key.
pub fn part1SeededForTest(
    allocator: Allocator,
    random: std.Random,
    out: *Round1SecretPackage,
    index: u64,
    n: u64,
    t: u64,
    q: usize,
) Part1Error!Round1Package {
    return part1From(allocator, .{ .seeded_for_test = random }, out, index, n, t, q);
}

fn part1From(
    allocator: Allocator,
    entropy: keys.Entropy,
    out: *Round1SecretPackage,
    index: u64,
    n: u64,
    t: u64,
    q: usize,
) Part1Error!Round1Package {
    if (t < 2 or n < t or q == 0 or index == 0 or index > n) return error.InvalidParameters;
    return burn.run(burn.key_burn, Part1Error!Round1Package, part1Body, .{ allocator, entropy, out, index, n, t, q });
}

fn part1Body(
    allocator: Allocator,
    entropy: keys.Entropy,
    out: *Round1SecretPackage,
    index: u64,
    n: u64,
    t: u64,
    q: usize,
) Part1Error!Round1Package {
    const tc: usize = @intCast(t);
    const comps = q + 1;
    const g2base = g2.Jacobian.fromAffine(g2.Affine.generator);

    const coefficients = try allocator.alloc(Fr, comps * tc);
    errdefer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(coefficients));
        allocator.free(coefficients);
    }
    const nonces = try allocator.alloc(Fr, comps);
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(nonces));
        allocator.free(nonces);
    }
    // A zero coefficient or nonce commits to the identity; redraw (frost-core
    // refuses one, but here the draw is ours, so the redraw is the fix).
    for (coefficients) |*a| drawNonZero(entropy, a);
    for (nonces) |*k| drawNonZero(entropy, k);

    const commitment = try allocator.alloc(g2.Affine, comps * tc);
    errdefer allocator.free(commitment);
    for (commitment, coefficients) |*phi, *a| phi.* = g2base.scalarMul(a.*).toAffine();

    const pok_r = try allocator.alloc(g2.Affine, comps);
    errdefer allocator.free(pok_r);
    const pok_mu = try allocator.alloc(Fr, comps);
    errdefer allocator.free(pok_mu);
    for (0..comps) |c| {
        pok_r[c] = g2base.scalarMul(nonces[c]).toAffine();
        const ch = challenge(index, c, commitment[c * tc], pok_r[c]);
        pok_mu[c] = nonces[c].add(coefficients[c * tc].mul(ch));
    }

    const kept = try allocator.dupe(g2.Affine, commitment);
    out.* = .{ .index = index, .n = n, .t = t, .q = q, .coefficients = coefficients, .commitment = kept };
    return .{ .commitment = commitment, .pok_r = pok_r, .pok_mu = pok_mu };
}

fn drawNonZero(entropy: keys.Entropy, out: *Fr) void {
    while (true) {
        entropy.scalar(out);
        if (!out.isZero()) break;
    }
}

/// `c = Fr.reduceWide(SHA-512(dst ‖ index ‖ component ‖ φ_0 ‖ R))`, `index`
/// and `component` as u64 big-endian, points compressed. frost-core hashes
/// `i ‖ φ_0 ‖ R`; the component number separates the `q + 1` proofs of one
/// participant.
fn challenge(index: u64, component: usize, phi0: g2.Affine, r: g2.Affine) Fr {
    var h = std.crypto.hash.sha2.Sha512.init(.{});
    h.update(pok_dst);
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, index, .big);
    h.update(&buf);
    std.mem.writeInt(u64, &buf, @intCast(component), .big);
    h.update(&buf);
    h.update(&g2.toBytesCompressed(phi0));
    h.update(&g2.toBytesCompressed(r));
    var digest: [64]u8 = undefined;
    h.final(&digest);
    return Fr.reduceWide(&digest);
}

fn inG2(p: g2.Affine) bool {
    return g2.Jacobian.fromAffine(p).subgroupCheck();
}

fn sameG2(a: g2.Jacobian, b: g2.Jacobian) bool {
    return a.add(b.negate()).isIdentity();
}

/// Checks `sender`'s round-1 package for `q` attributes and threshold `t`:
/// every commitment point in G2, every constant term and proof commitment
/// not the identity, and `R_c == [μ_c] g2 − [c_c] φ_c0` for every
/// component. Public data only. Shapes must already match (`part2` checks
/// them first).
pub fn verifyProofOfKnowledge(sender: u64, package: Round1Package, t: u64, q: usize) bool {
    const tc: usize = @intCast(t);
    const comps = q + 1;
    if (package.commitment.len != comps * tc or package.pok_r.len != comps or package.pok_mu.len != comps) return false;
    for (package.commitment) |phi| if (!inG2(phi)) return false;
    const g2base = g2.Jacobian.fromAffine(g2.Affine.generator);
    for (0..comps) |c| {
        const phi0 = package.commitment[c * tc];
        const r = package.pok_r[c];
        if (g2.Jacobian.fromAffine(phi0).isIdentity()) return false;
        if (!inG2(r) or g2.Jacobian.fromAffine(r).isIdentity()) return false;
        const ch = challenge(sender, c, phi0, r);
        const rhs = g2base.scalarMul(package.pok_mu[c]).add(g2.Jacobian.fromAffine(phi0).scalarMul(ch).negate());
        if (!sameG2(g2.Jacobian.fromAffine(r), rhs)) return false;
    }
    return true;
}

// ── part2 ───────────────────────────────────────────────────────────────────

/// Round 2: checks every other participant's round-1 package (count,
/// senders, shapes — all before any proof — then each proof of knowledge in
/// order) and evaluates this participant's polynomials at every sender.
/// Returns the shares to send (owned, in the order of `round1_packages`;
/// `freeRound2Packages`) and writes the secret package for `part3` to `out`
/// (owned; `Round2SecretPackage.deinit`). On `error.InvalidProofOfKnowledge`
/// the first failing sender is written to `culprit` (when not null).
pub fn part2(
    allocator: Allocator,
    out: *Round2SecretPackage,
    secret: *const Round1SecretPackage,
    round1_packages: []const Round1Received,
    culprit: ?*u64,
) Part2Error![]Round2Package {
    if (round1_packages.len != secret.n - 1) return error.IncorrectNumberOfPackages;
    try checkSenders(Round1Received, round1_packages, secret.index, secret.n);
    const tc: usize = @intCast(secret.t);
    const comps = secret.q + 1;
    for (round1_packages) |p| {
        const pk = p.package;
        if (pk.commitment.len != comps * tc or pk.pok_r.len != comps or pk.pok_mu.len != comps)
            return error.IncorrectNumberOfCommitments;
    }
    for (round1_packages) |p| {
        if (!verifyProofOfKnowledge(p.sender, p.package, secret.t, secret.q)) {
            if (culprit) |c| c.* = p.sender;
            return error.InvalidProofOfKnowledge;
        }
    }
    return burn.run(burn.key_burn, Part2Error![]Round2Package, part2Body, .{ allocator, out, secret, round1_packages });
}

fn part2Body(
    allocator: Allocator,
    out: *Round2SecretPackage,
    secret: *const Round1SecretPackage,
    round1_packages: []const Round1Received,
) Part2Error![]Round2Package {
    const tc: usize = @intCast(secret.t);
    const comps = secret.q + 1;
    const packages = try allocator.alloc(Round2Package, round1_packages.len);
    for (packages, round1_packages) |*dst, p| dst.* = .{ .recipient = p.sender, .values = &.{} };
    errdefer freeRound2Packages(allocator, packages);
    for (packages) |*dst| {
        dst.values = try allocator.alloc(Fr, comps);
        const x = lagrange.indexScalar(dst.recipient);
        for (dst.values, 0..) |*v, c| evalBody(v, secret.coefficients[c * tc ..][0..tc], x);
    }
    const own = try allocator.alloc(Fr, comps);
    errdefer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(own));
        allocator.free(own);
    }
    const xi = lagrange.indexScalar(secret.index);
    for (own, 0..) |*v, c| evalBody(v, secret.coefficients[c * tc ..][0..tc], xi);
    const commitment = try allocator.dupe(g2.Affine, secret.commitment);
    out.* = .{ .index = secret.index, .n = secret.n, .t = secret.t, .q = secret.q, .own_values = own, .commitment = commitment };
    return packages;
}

/// Horner over `Fr` (constant time in the coefficients; the loop bound is
/// public). Runs inside a burned body.
fn evalBody(out: *Fr, poly: []const Fr, x: Fr) void {
    out.* = Fr.zero;
    var i: usize = poly.len;
    while (i > 0) {
        i -= 1;
        out.* = out.mul(x).add(poly[i]);
    }
}

/// Every sender in `1..n`, none equal to `own`, none twice.
fn checkSenders(comptime T: type, list: []const T, own: u64, n: u64) error{ UnknownIdentifier, DuplicatedIdentifier }!void {
    for (list, 0..) |a, i| {
        if (a.sender == own or a.sender == 0 or a.sender > n) return error.UnknownIdentifier;
        for (list[i + 1 ..]) |b| if (a.sender == b.sender) return error.DuplicatedIdentifier;
    }
}

// ── part3 ───────────────────────────────────────────────────────────────────

/// Round 3 (local): checks each received share against its sender's
/// commitment, sums them into this participant's `SecretKeyShare` (written
/// to `out`; `SecretKeyShare.deinit`), and derives the group verification
/// key and every authority's verification-key share from the summed
/// commitments. `round1_packages` must be the ones `part2` was given (they
/// were checked there). Returns the `PublicKeyPackage` (owned; `deinit`),
/// identical at every participant. On `error.InvalidSecretShare` the first
/// failing sender is written to `culprit` (when not null).
pub fn part3(
    allocator: Allocator,
    out: *SecretKeyShare,
    secret: *const Round2SecretPackage,
    round1_packages: []const Round1Received,
    round2_packages: []const Round2Received,
    culprit: ?*u64,
) Part3Error!PublicKeyPackage {
    if (round1_packages.len != secret.n - 1) return error.IncorrectNumberOfPackages;
    try checkSenders(Round1Received, round1_packages, secret.index, secret.n);
    try checkSenders(Round2Received, round2_packages, secret.index, secret.n);
    if (round1_packages.len != round2_packages.len) return error.IncorrectNumberOfPackages;
    const tc: usize = @intCast(secret.t);
    const comps = secret.q + 1;
    for (round1_packages) |p| {
        const r2 = findRound2(round2_packages, p.sender) orelse return error.IncorrectPackage;
        if (p.package.commitment.len != comps * tc or r2.values.len != comps) return error.IncorrectNumberOfCommitments;
    }
    // Feldman check of every received share, public commitments against the
    // (secret) received values: [f] g2 == Σ_k [i^k] φ_k.
    const xi = lagrange.indexScalar(secret.index);
    for (round2_packages) |share| {
        const commitment = findRound1(round1_packages, share.sender).?.package.commitment;
        const ok = burn.run(burn.key_burn, bool, shareOnCommitment, .{ share.values, commitment, tc, xi });
        if (!ok) {
            if (culprit) |c| c.* = share.sender;
            return error.InvalidSecretShare;
        }
    }

    // Σ_ℓ φ_ℓck, coefficient by coefficient (public data).
    const group = try allocator.alloc(g2.Jacobian, comps * tc);
    defer allocator.free(group);
    for (group, secret.commitment) |*g, phi| g.* = g2.Jacobian.fromAffine(phi);
    for (round1_packages) |p| {
        for (group, p.package.commitment) |*g, phi| g.* = g.add(g2.Jacobian.fromAffine(phi));
    }
    for (0..comps) |c| if (group[c * tc].isIdentity()) return error.InvalidCommitment;

    const betas = try allocator.alloc(g2.Affine, secret.q);
    errdefer allocator.free(betas);
    for (betas, 1..) |*b, c| b.* = group[c * tc].toAffine();
    const vk: VerificationKey = .{ .alpha = group[0].toAffine(), .betas = betas };

    const n: usize = @intCast(secret.n);
    const vk_shares = try allocator.alloc(VerificationKeyShare, n);
    var vk_done: usize = 0;
    errdefer {
        for (vk_shares[0..vk_done]) |s| s.deinit(allocator);
        allocator.free(vk_shares);
    }
    for (vk_shares, 1..) |*dst, j| {
        const x = lagrange.indexScalar(@intCast(j));
        const sb = try allocator.alloc(g2.Affine, secret.q);
        dst.* = .{ .index = @intCast(j), .alpha = hornerG2(group[0..tc], x).toAffine(), .betas = sb };
        for (sb, 1..) |*b, c| b.* = hornerG2(group[c * tc ..][0..tc], x).toAffine();
        vk_done += 1;
    }

    const ys = try allocator.alloc(Fr, secret.q);
    burn.run(burn.eval_burn, void, sumShares, .{ out, ys, secret, round2_packages });
    return .{ .t = secret.t, .vk = vk, .vk_shares = vk_shares };
}

fn sumShares(out: *SecretKeyShare, ys: []Fr, secret: *const Round2SecretPackage, round2_packages: []const Round2Received) void {
    var x = secret.own_values[0];
    for (ys, secret.own_values[1..]) |*y, v| y.* = v;
    for (round2_packages) |share| {
        x = x.add(share.values[0]);
        for (ys, share.values[1..]) |*y, v| y.* = y.add(v);
    }
    out.* = .{ .index = secret.index, .x = x, .ys = ys };
    std.crypto.secureZero(u8, std.mem.asBytes(&x));
}

/// `Σ_k [x^k] coeffs[k]` by Horner over G2 (public points, public `x`).
fn hornerG2(coeffs: []const g2.Jacobian, x: Fr) g2.Jacobian {
    var acc = coeffs[coeffs.len - 1];
    var k = coeffs.len - 1;
    while (k > 0) {
        k -= 1;
        acc = acc.scalarMul(x).add(coeffs[k]);
    }
    return acc;
}

fn shareOnCommitment(values: []const Fr, commitment: []const g2.Affine, tc: usize, xi: Fr) bool {
    const g2base = g2.Jacobian.fromAffine(g2.Affine.generator);
    var ok = true;
    for (values, 0..) |v, c| {
        var acc = g2.Jacobian.fromAffine(commitment[c * tc + tc - 1]);
        var k = tc - 1;
        while (k > 0) {
            k -= 1;
            acc = acc.scalarMul(xi).add(g2.Jacobian.fromAffine(commitment[c * tc + k]));
        }
        ok = ok and sameG2(g2base.scalarMul(v), acc);
    }
    return ok;
}

fn findRound1(list: []const Round1Received, sender: u64) ?*const Round1Received {
    for (list) |*p| if (p.sender == sender) return p;
    return null;
}

fn findRound2(list: []const Round2Received, sender: u64) ?*const Round2Received {
    for (list) |*p| if (p.sender == sender) return p;
    return null;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const credential = @import("credential.zig");
const params_mod = @import("params.zig");
const blind = @import("blind.zig");
const g1 = bls.g1;

fn frOf(v: u64) Fr {
    var b: [32]u8 = @splat(0);
    std.mem.writeInt(u64, b[24..32], v, .big);
    return Fr.fromBytes(b) catch unreachable;
}

/// A whole DKG run held in memory: every participant's round packages and
/// outputs. Tests tamper with `r1` / `r2` between the rounds.
const Run = struct {
    n: u64,
    t: u64,
    q: usize,
    s1: []Round1SecretPackage,
    r1: []Round1Package,
    s2: []Round2SecretPackage,
    /// `r2[i]` = what participant `i + 1` sends, in the order of its received list.
    r2: [][]Round2Package,
    shares: []SecretKeyShare,
    pubs: []PublicKeyPackage,
    s2_done: usize = 0,
    out_done: usize = 0,

    fn round1(allocator: Allocator, seed: u64, n: u64, t: u64, q: usize) !Run {
        const nn: usize = @intCast(n);
        var self: Run = .{
            .n = n,
            .t = t,
            .q = q,
            .s1 = try allocator.alloc(Round1SecretPackage, nn),
            .r1 = try allocator.alloc(Round1Package, nn),
            .s2 = try allocator.alloc(Round2SecretPackage, nn),
            .r2 = try allocator.alloc([]Round2Package, nn),
            .shares = try allocator.alloc(SecretKeyShare, nn),
            .pubs = try allocator.alloc(PublicKeyPackage, nn),
        };
        var prng = std.Random.DefaultPrng.init(seed);
        for (0..nn) |i| self.r1[i] = try part1SeededForTest(allocator, prng.random(), &self.s1[i], @intCast(i + 1), n, t, q);
        return self;
    }

    /// Round-1 packages participant `me` (1-based) receives: everyone else's.
    fn received1(self: *const Run, allocator: Allocator, me: u64) ![]Round1Received {
        const list = try allocator.alloc(Round1Received, @intCast(self.n - 1));
        var k: usize = 0;
        for (self.r1, 1..) |pk, j| {
            if (j == me) continue;
            list[k] = .{ .sender = @intCast(j), .package = pk };
            k += 1;
        }
        return list;
    }

    /// Round-2 shares addressed to `me`.
    fn received2(self: *const Run, allocator: Allocator, me: u64) ![]Round2Received {
        const list = try allocator.alloc(Round2Received, @intCast(self.n - 1));
        var k: usize = 0;
        for (self.r2, 1..) |sent, j| {
            if (j == me) continue;
            for (sent) |pk| if (pk.recipient == me) {
                list[k] = .{ .sender = @intCast(j), .values = pk.values };
                k += 1;
            };
        }
        try testing.expectEqual(list.len, k);
        return list;
    }

    fn round2(self: *Run, allocator: Allocator) !void {
        for (0..self.s1.len) |i| {
            const rec = try self.received1(allocator, @intCast(i + 1));
            defer allocator.free(rec);
            self.r2[i] = try part2(allocator, &self.s2[i], &self.s1[i], rec, null);
            self.s2_done += 1;
        }
    }

    fn round3(self: *Run, allocator: Allocator) !void {
        for (0..self.s1.len) |i| {
            const me: u64 = @intCast(i + 1);
            const rec1 = try self.received1(allocator, me);
            defer allocator.free(rec1);
            const rec2 = try self.received2(allocator, me);
            defer allocator.free(rec2);
            self.pubs[i] = try part3(allocator, &self.shares[i], &self.s2[i], rec1, rec2, null);
            self.out_done += 1;
        }
    }

    fn deinit(self: *Run, allocator: Allocator) void {
        for (self.s1) |*s| s.deinit(allocator);
        for (self.r1) |*r| r.deinit(allocator);
        for (self.s2[0..self.s2_done], self.r2[0..self.s2_done]) |*s, r| {
            s.deinit(allocator);
            freeRound2Packages(allocator, r);
        }
        for (self.shares[0..self.out_done], self.pubs[0..self.out_done]) |*s, *p| {
            s.deinit(allocator);
            p.deinit(allocator);
        }
        allocator.free(self.s1);
        allocator.free(self.r1);
        allocator.free(self.s2);
        allocator.free(self.r2);
        allocator.free(self.shares);
        allocator.free(self.pubs);
    }
};

fn expectSameG2(a: g2.Affine, b: g2.Affine) !void {
    try testing.expectEqualSlices(u8, &g2.toBytesCompressed(a), &g2.toBytesCompressed(b));
}

test "dkg: t-of-n issue and verify with the DKG output (property, several shapes)" {
    const allocator = testing.allocator;
    const Shape = struct { n: u64, t: u64, q: usize, seed: u64 };
    const shapes = [_]Shape{
        .{ .n = 3, .t = 2, .q = 1, .seed = 0xD1 },
        .{ .n = 4, .t = 3, .q = 2, .seed = 0xD2 },
        .{ .n = 5, .t = 3, .q = 2, .seed = 0xD3 },
    };
    for (shapes) |sh| {
        var run = try Run.round1(allocator, sh.seed, sh.n, sh.t, sh.q);
        defer run.deinit(allocator);
        try run.round2(allocator);
        try run.round3(allocator);

        // Every participant derived the same public package, and its own
        // share's vk share is the one the package lists.
        const ref = run.pubs[0];
        try testing.expectEqual(@as(usize, @intCast(sh.n)), ref.vk_shares.len);
        for (run.pubs, run.shares) |pk, *share| {
            try expectSameG2(ref.vk.alpha, pk.vk.alpha);
            for (ref.vk.betas, pk.vk.betas) |a, b| try expectSameG2(a, b);
            for (ref.vk_shares, pk.vk_shares, 1..) |a, b, j| {
                try testing.expectEqual(@as(u64, @intCast(j)), b.index);
                try expectSameG2(a.alpha, b.alpha);
                for (a.betas, b.betas) |x, y| try expectSameG2(x, y);
            }
            const own = try VerificationKeyShare.fromShare(allocator, share);
            defer own.deinit(allocator);
            const listed = ref.vk_shares[@intCast(share.index - 1)];
            try expectSameG2(listed.alpha, own.alpha);
            for (listed.betas, own.betas) |x, y| try expectSameG2(x, y);
        }

        // The group key is the Lagrange aggregate of any t vk shares.
        const agg = try keys.aggregateVerificationKeys(allocator, ref.vk_shares[@intCast(sh.n - sh.t)..]);
        defer agg.deinit(allocator);
        try expectSameG2(ref.vk.alpha, agg.alpha);
        for (ref.vk.betas, agg.betas) |a, b| try expectSameG2(a, b);

        // Issue under two different t-subsets; both verify under the group
        // key and are the same credential; t - 1 partials do not verify.
        const p = try params_mod.Parameters.generate(allocator, sh.q);
        defer p.deinit(allocator);
        const attrs = try allocator.alloc(Fr, sh.q);
        defer allocator.free(attrs);
        for (attrs, 0..) |*m, i| m.* = frOf(1000 + i);
        const h = p.commonBase(attrs);
        const partials = try allocator.alloc(credential.PartialCredential, run.shares.len);
        defer allocator.free(partials);
        for (partials, run.shares) |*pc, *share| pc.* = try credential.signPartial(share, h, attrs);
        const tt: usize = @intCast(sh.t);
        const first = try credential.aggregateCredential(allocator, partials[0..tt], sh.t);
        const last = try credential.aggregateCredential(allocator, partials[partials.len - tt ..], sh.t);
        try testing.expect(credential.psVerifyPlain(ref.vk, first, attrs));
        try testing.expectEqualSlices(u8, &g1.toBytesCompressed(first.s), &g1.toBytesCompressed(last.s));
        const short = try credential.aggregateCredential(allocator, partials[0 .. tt - 1], sh.t - 1);
        try testing.expect(!credential.psVerifyPlain(ref.vk, short, attrs));

        // A show over the DKG-issued credential verifies under the group key.
        var prng = std.Random.DefaultPrng.init(sh.seed ^ 0x5A);
        const disclosed = try allocator.alloc(bool, sh.q);
        defer allocator.free(disclosed);
        for (disclosed, 0..) |*d, i| d.* = i == 0;
        const proof = try credential.proveCredentialSeededForTest(allocator, prng.random(), p, ref.vk, first, attrs, disclosed, "dkg");
        defer proof.deinit(allocator);
        try testing.expect(try credential.verifyCredential(allocator, p, ref.vk, proof, disclosed, attrs[0..1], "dkg"));
    }
}

test "dkg: blind issuance under DKG shares" {
    const allocator = testing.allocator;
    var run = try Run.round1(allocator, 0xD4, 3, 2, 2);
    defer run.deinit(allocator);
    try run.round2(allocator);
    try run.round3(allocator);
    const vk = run.pubs[0].vk;

    const p = try params_mod.Parameters.generate(allocator, 2);
    defer p.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(0xD5);
    var kp: blind.ElGamalKeyPair = undefined;
    blind.elgamalKeyGenSeededForTest(prng.random(), &kp);
    defer kp.deinit();
    const priv = [_]Fr{frOf(7)};
    const publ = [_]Fr{frOf(8)};
    var req = try blind.prepareBlindSignSeededForTest(allocator, prng.random(), p, kp.gamma, &priv, &publ);
    defer req.deinit(allocator);
    var partials: [2]credential.PartialCredential = undefined;
    for (&partials, run.shares[1..3]) |*pc, *share| {
        const sig = try blind.blindSign(allocator, share, p, kp.gamma, &req, &publ);
        pc.* = blind.unblind(&kp, &sig);
    }
    const cred = try credential.aggregateCredential(allocator, &partials, 2);
    try testing.expect(credential.psVerifyPlain(vk, cred, &.{ frOf(7), frOf(8) }));
}

test "dkg: a bad proof of knowledge is refused and the sender named" {
    const allocator = testing.allocator;
    var run = try Run.round1(allocator, 0xD6, 4, 3, 1);
    defer run.deinit(allocator);

    // Participant 3's response for component 1 is off by one.
    run.r1[2].pok_mu[1] = run.r1[2].pok_mu[1].add(Fr.one);
    const rec = try run.received1(allocator, 1);
    defer allocator.free(rec);
    var culprit: u64 = 0;
    var s2: Round2SecretPackage = undefined;
    try testing.expectError(error.InvalidProofOfKnowledge, part2(allocator, &s2, &run.s1[0], rec, &culprit));
    try testing.expectEqual(@as(u64, 3), culprit);
    run.r1[2].pok_mu[1] = run.r1[2].pok_mu[1].sub(Fr.one);

    // Participant 2's constant-term commitment swapped for another valid
    // point: its proof no longer opens it.
    const saved = run.r1[1].commitment[0];
    run.r1[1].commitment[0] = run.r1[3].commitment[0];
    culprit = 0;
    try testing.expectError(error.InvalidProofOfKnowledge, part2(allocator, &s2, &run.s1[0], rec, &culprit));
    try testing.expectEqual(@as(u64, 2), culprit);
    run.r1[1].commitment[0] = saved;

    // A higher-degree commitment point of participant 4 outside G2.
    const saved_hi = run.r1[3].commitment[1];
    run.r1[3].commitment[1] = notInG2();
    culprit = 0;
    try testing.expectError(error.InvalidProofOfKnowledge, part2(allocator, &s2, &run.s1[0], rec, &culprit));
    try testing.expectEqual(@as(u64, 4), culprit);
    run.r1[3].commitment[1] = saved_hi;

    // Restored: part2 succeeds.
    const out = try part2(allocator, &s2, &run.s1[0], rec, null);
    freeRound2Packages(allocator, out);
    s2.deinit(allocator);

    // Shape and sender errors come before any proof.
    rec[0].sender = 1;
    try testing.expectError(error.UnknownIdentifier, part2(allocator, &s2, &run.s1[0], rec, null));
    rec[0].sender = 3;
    try testing.expectError(error.DuplicatedIdentifier, part2(allocator, &s2, &run.s1[0], rec, null));
    rec[0].sender = 5;
    try testing.expectError(error.UnknownIdentifier, part2(allocator, &s2, &run.s1[0], rec, null));
    rec[0].sender = 2;
    try testing.expectError(error.IncorrectNumberOfPackages, part2(allocator, &s2, &run.s1[0], rec[0..2], null));
    const full = rec[0].package.commitment;
    rec[0].package.commitment = full[0 .. full.len - 1];
    try testing.expectError(error.IncorrectNumberOfCommitments, part2(allocator, &s2, &run.s1[0], rec, null));
    rec[0].package.commitment = full;
}

/// An on-curve G2 point outside the order-r subgroup: `hashToCurveG2`
/// without the cofactor clearing is not exposed, so take the
/// `fromBytesCompressedUnchecked` decode of small x until one lands off the
/// subgroup.
fn notInG2() g2.Affine {
    var bytes: [g2.compressed_bytes]u8 = @splat(0);
    bytes[0] = 0x80;
    var x: u8 = 1;
    while (true) : (x += 1) {
        bytes[g2.compressed_bytes - 1] = x;
        const p = g2.fromBytesCompressedUnchecked(bytes) catch continue;
        if (!inG2(p)) return p;
    }
}

test "dkg: a bad share is refused and the sender named" {
    const allocator = testing.allocator;
    var run = try Run.round1(allocator, 0xD7, 3, 2, 2);
    defer run.deinit(allocator);
    try run.round2(allocator);

    // Participant 3's share for participant 1, component 2, is off by one.
    const to1 = for (run.r2[2]) |pk| {
        if (pk.recipient == 1) break pk;
    } else unreachable;
    to1.values[2] = to1.values[2].add(Fr.one);
    const rec1 = try run.received1(allocator, 1);
    defer allocator.free(rec1);
    const rec2 = try run.received2(allocator, 1);
    defer allocator.free(rec2);
    var culprit: u64 = 0;
    var share: SecretKeyShare = undefined;
    try testing.expectError(error.InvalidSecretShare, part3(allocator, &share, &run.s2[0], rec1, rec2, &culprit));
    try testing.expectEqual(@as(u64, 3), culprit);
    to1.values[2] = to1.values[2].sub(Fr.one);

    // A share with the wrong number of components, a missing sender.
    const full = rec2[0].values;
    rec2[0].values = full[0..2];
    try testing.expectError(error.IncorrectNumberOfCommitments, part3(allocator, &share, &run.s2[0], rec1, rec2, null));
    rec2[0].values = full;
    rec2[0].sender = 1;
    try testing.expectError(error.UnknownIdentifier, part3(allocator, &share, &run.s2[0], rec1, rec2, null));
    rec2[0].sender = rec2[1].sender;
    try testing.expectError(error.DuplicatedIdentifier, part3(allocator, &share, &run.s2[0], rec1, rec2, null));
    try testing.expectError(error.IncorrectNumberOfPackages, part3(allocator, &share, &run.s2[0], rec1, rec2[0..1], null));
}

test "dkg: part1 parameter checks" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xD8);
    var s1: Round1SecretPackage = undefined;
    try testing.expectError(error.InvalidParameters, part1SeededForTest(allocator, prng.random(), &s1, 1, 3, 1, 1));
    try testing.expectError(error.InvalidParameters, part1SeededForTest(allocator, prng.random(), &s1, 1, 2, 3, 1));
    try testing.expectError(error.InvalidParameters, part1SeededForTest(allocator, prng.random(), &s1, 1, 3, 2, 0));
    try testing.expectError(error.InvalidParameters, part1SeededForTest(allocator, prng.random(), &s1, 0, 3, 2, 1));
    try testing.expectError(error.InvalidParameters, part1SeededForTest(allocator, prng.random(), &s1, 4, 3, 2, 1));
}

test "dkg: the group key is the sum of the participants' constant terms" {
    const allocator = testing.allocator;
    var run = try Run.round1(allocator, 0xD9, 3, 2, 1);
    defer run.deinit(allocator);
    try run.round2(allocator);
    try run.round3(allocator);
    // x = Σ_i a_i00, so α = [x] g2; reconstruct x from the coefficients.
    var x = Fr.zero;
    for (run.s1) |s| x = x.add(s.coefficients[0]);
    const alpha = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(x).toAffine();
    try expectSameG2(alpha, run.pubs[0].vk.alpha);
    // And any t shares' x(i) Lagrange-reconstruct it.
    const idx = [_]u64{ 1, 3 };
    var rx = Fr.zero;
    for (idx) |i| rx = rx.add((try lagrange.coefficientAtZero(&idx, i)).mul(run.shares[@intCast(i - 1)].x));
    try testing.expect(rx.eql(x));
}
