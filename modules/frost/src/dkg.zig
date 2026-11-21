// SPDX-License-Identifier: MIT
//! Distributed key generation for FROST(secp256k1, SHA-256): frost-core's
//! `dkg` module (`part1` / `part2` / `part3`), the two-round Pedersen DKG of
//! the FROST paper (Komlo–Goldberg 2020, Figure 1) — every participant deals
//! a Feldman-committed polynomial of its own and proves knowledge of its
//! constant term with a Schnorr signature, so no one ever holds the group
//! secret. RFC 9591 leaves key generation out (its Appendix C is the trusted
//! dealer, `trustedDealerKeygen`); frost-core is the reference this file
//! follows, including its challenge hash (`HDKG`, DST
//! `"FROST-secp256k1-SHA256-v1dkg"`), its checks and their order, and its
//! error names.
//!
//! ```text
//! part1(i, n, t, a_i0..a_i(t-1), k):            round 1, steps 1-4
//!   φ_ij = a_ij·G                                  (Feldman commitment, broadcast)
//!   R_i = k·G;  c_i = HDKG(i || φ_i0 || R_i);  μ_i = k + a_i0·c_i
//!   broadcast (φ_i, σ_i = (R_i, μ_i));  keep a_i, φ_i
//! part2(secret_1, {(ℓ, φ_ℓ, σ_ℓ)}):             round 1 step 5, round 2 step 1
//!   check R_ℓ == μ_ℓ·G − c_ℓ·φ_ℓ0 for every ℓ ≠ i
//!   send f_i(ℓ) privately to each ℓ;  keep f_i(i), φ_i
//! part3(secret_2, {(ℓ, φ_ℓ)}, {(ℓ, f_ℓ(i))}):   round 2 steps 2-4
//!   check f_ℓ(i)·G == Σ_k φ_ℓk · i^k  (vssVerify) for every ℓ ≠ i
//!   s_i = Σ_ℓ f_ℓ(i);  Y_i = s_i·G;  Y = Σ_ℓ φ_ℓ0
//!   verifying share of each j = Σ_k (Σ_ℓ φ_ℓk) · j^k
//! ```
//!
//! The randomness is the caller's (`coefficients`, `nonce`), as everywhere
//! in this module: draw them from a CSPRNG (`Scalar.random`). Packages are
//! plain values; the caller carries them between participants (round-1
//! packages over an authenticated broadcast channel, round-2 shares over
//! confidential, authenticated point-to-point channels — the DKG's own
//! requirement). Each `Round*Received.sender` is the identity the channel
//! vouches for, frost-core's map key.
//!
//! Every entry point that touches a secret runs its body one `noinline`
//! frame down and burns the stack after it (`burn.zig`).

const std = @import("std");
const frost = @import("root.zig");
const burnStack = @import("burn.zig").burnStack;

const Allocator = std.mem.Allocator;
const Secp256k1 = frost.Secp256k1;
const Scalar = frost.Scalar;
const Identifier = frost.Identifier;
const Element = frost.Element;
const Signature = frost.Signature;
const SigningShare = frost.SigningShare;
const VerifyingShare = frost.VerifyingShare;
const GroupPublicKey = frost.GroupPublicKey;

// ── packages ────────────────────────────────────────────────────────────────

/// What participant `i` broadcasts after `part1` (frost-core
/// `round1::Package`): its Feldman commitment `φ_i0..φ_i(t-1)` and the
/// proof of knowledge of `a_i0`. Public.
pub const Round1Package = struct {
    /// `min_signers` elements; `commitment[0] = a_i0·G`.
    commitment: []const Element,
    /// `(R_i, μ_i)` in the signature encoding (33 + 32 bytes).
    proof_of_knowledge: Signature,

    /// Frees `commitment` (a package returned by `part1`).
    pub fn deinit(self: *Round1Package, allocator: Allocator) void {
        allocator.free(self.commitment);
        self.* = undefined;
    }
};

/// A round-1 package as received, with the sender the broadcast channel
/// vouches for. Borrowed by `part2`/`part3`.
pub const Round1Received = struct {
    sender: Identifier,
    package: Round1Package,
};

/// What participant `i` keeps between `part1` and `part2` (frost-core
/// `round1::SecretPackage`). SECRET: `deinit` wipes it.
pub const Round1SecretPackage = struct {
    identifier: Identifier,
    /// `a_i0..a_i(t-1)`, owned.
    coefficients: []Scalar,
    /// `φ_i0..φ_i(t-1)`, owned.
    commitment: []Element,
    min_signers: u16,
    max_signers: u16,

    /// Zeroes the coefficients and frees both slices. Call it once `part2`
    /// has run (frost-core consumes the package there).
    pub fn deinit(self: *Round1SecretPackage, allocator: Allocator) void {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.coefficients));
        allocator.free(self.coefficients);
        allocator.free(self.commitment);
        self.* = undefined;
    }
};

/// One secret share `f_i(ℓ)` that participant `i` sends privately to
/// `recipient` after `part2` (frost-core `round2::Package`). SECRET.
pub const Round2Package = struct {
    recipient: Identifier,
    signing_share: SigningShare,
};

/// Zeroes and frees the shares `part2` returned (once they are sent).
pub fn freeRound2Packages(allocator: Allocator, packages: []Round2Package) void {
    std.crypto.secureZero(u8, std.mem.sliceAsBytes(packages));
    allocator.free(packages);
}

/// A round-2 share as received: `f_sender(i)`, with the sender the private
/// channel vouches for. SECRET.
pub const Round2Received = struct {
    sender: Identifier,
    signing_share: SigningShare,
};

/// What participant `i` keeps between `part2` and `part3` (frost-core
/// `round2::SecretPackage`). SECRET: `deinit` wipes it.
pub const Round2SecretPackage = struct {
    identifier: Identifier,
    /// `φ_i0..φ_i(t-1)`, owned.
    commitment: []Element,
    /// `f_i(i)`.
    secret_share: SigningShare,
    min_signers: u16,
    max_signers: u16,

    pub fn deinit(self: *Round2SecretPackage, allocator: Allocator) void {
        self.secret_share.deinit();
        allocator.free(self.commitment);
        self.* = undefined;
    }
};

/// Participant `i`'s long-lived key material (frost-core `KeyPackage`):
/// what `generateNonces` / `round2Sign` take. SECRET (`signing_share`).
pub const KeyPackage = struct {
    identifier: Identifier,
    /// `s_i = Σ_ℓ f_ℓ(i)`.
    signing_share: SigningShare,
    /// `Y_i = s_i·G`.
    verifying_share: VerifyingShare,
    /// `Y = Σ_ℓ φ_ℓ0`, the group public key.
    verifying_key: GroupPublicKey,
    min_signers: u16,

    pub fn deinit(self: *KeyPackage) void {
        self.signing_share.deinit();
    }
};

/// One participant's verifying share in a `PublicKeyPackage`.
pub const ParticipantVerifyingShare = struct {
    identifier: Identifier,
    verifying_share: VerifyingShare,
};

/// The public outcome every participant computes identically (frost-core
/// `PublicKeyPackage`): every participant's verifying share, ascending by
/// identifier, and the group public key.
pub const PublicKeyPackage = struct {
    verifying_shares: []ParticipantVerifyingShare,
    verifying_key: GroupPublicKey,
    min_signers: u16,

    pub fn deinit(self: *PublicKeyPackage, allocator: Allocator) void {
        allocator.free(self.verifying_shares);
        self.* = undefined;
    }

    /// The verifying share of `identifier`, or null.
    pub fn verifyingShare(self: PublicKeyPackage, identifier: Identifier) ?VerifyingShare {
        for (self.verifying_shares) |e| {
            if (std.mem.eql(u8, &e.identifier.bytes, &identifier.bytes)) return e.verifying_share;
        }
        return null;
    }
};

// ── errors (frost-core's names) ─────────────────────────────────────────────

pub const Part1Error = error{
    OutOfMemory,
    /// `min_signers < 2`, `max_signers < min_signers`,
    /// `coefficients.len != min_signers`, or a zero coefficient or nonce
    /// (its commitment would be the identity). frost-core:
    /// `InvalidMinSigners` / `InvalidMaxSigners` / `InvalidCoefficients`.
    InvalidParameters,
};

pub const Part2Error = error{
    OutOfMemory,
    /// Not exactly `max_signers - 1` round-1 packages.
    IncorrectNumberOfPackages,
    /// The participant's own identifier among the senders.
    UnknownIdentifier,
    /// Two packages from the same sender.
    DuplicatedIdentifier,
    /// A sender's commitment does not have `min_signers` elements.
    IncorrectNumberOfCommitments,
    /// A sender's proof of knowledge does not verify; the sender is
    /// written to `culprit`.
    InvalidProofOfKnowledge,
};

pub const Part3Error = error{
    OutOfMemory,
    /// Not exactly `max_signers - 1` round-1 packages, or not as many
    /// round-2 shares as round-1 packages.
    IncorrectNumberOfPackages,
    /// The participant's own identifier among the senders.
    UnknownIdentifier,
    /// Two packages (round 1 or round 2) from the same sender.
    DuplicatedIdentifier,
    /// A round-1 sender with no round-2 share.
    IncorrectPackage,
    /// A sender's commitment does not have `min_signers` elements.
    IncorrectNumberOfCommitments,
    /// A sender's share is not on its committed polynomial (or its
    /// commitment holds an invalid element); the sender is written to
    /// `culprit`.
    InvalidSecretShare,
    /// The summed commitment has an identity coefficient or an identity
    /// verifying share: the participants' polynomials cancel. Not reachable
    /// with honestly drawn coefficients.
    InvalidCommitment,
};

// ── part1 ───────────────────────────────────────────────────────────────────

/// frost-core `dkg::part1`: commits to `coefficients` (`a_i0..a_i(t-1)`,
/// `t = min_signers`, all secret and freshly drawn) and proves knowledge of
/// `a_i0` with `nonce` (`k`, secret, fresh). Writes the secret package to
/// `out` (owned; `Round1SecretPackage.deinit`) and returns the package to
/// broadcast (owned; `Round1Package.deinit`).
pub fn part1(
    allocator: Allocator,
    out: *Round1SecretPackage,
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
    coefficients: []const Scalar,
    nonce: *const Scalar,
) Part1Error!Round1Package {
    const r = part1Burned(allocator, out, identifier, max_signers, min_signers, coefficients, nonce);
    burnStack();
    return r;
}

noinline fn part1Burned(
    allocator: Allocator,
    out: *Round1SecretPackage,
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
    coefficients: []const Scalar,
    nonce: *const Scalar,
) Part1Error!Round1Package {
    if (min_signers < 2 or max_signers < min_signers) return error.InvalidParameters;
    if (coefficients.len != min_signers) return error.InvalidParameters;

    const commitment = try allocator.alloc(Element, min_signers);
    errdefer allocator.free(commitment);
    for (commitment, coefficients) |*c, a| {
        const pt = Secp256k1.combMulBase(a.toBytes(.big), .big) catch return error.InvalidParameters;
        c.* = Element.fromPoint(pt) catch return error.InvalidParameters;
    }

    const r_pt = Secp256k1.combMulBase(nonce.toBytes(.big), .big) catch return error.InvalidParameters;
    const r = Element.fromPoint(r_pt) catch return error.InvalidParameters;
    const c = challenge(identifier, commitment[0], r);
    const mu = nonce.add(coefficients[0].mul(c));

    const broadcast = try allocator.dupe(Element, commitment);
    errdefer allocator.free(broadcast);
    const kept = try allocator.dupe(Scalar, coefficients);
    out.* = .{
        .identifier = identifier,
        .coefficients = kept,
        .commitment = commitment,
        .min_signers = min_signers,
        .max_signers = max_signers,
    };
    return .{ .commitment = broadcast, .proof_of_knowledge = .{ .r = r, .z = mu.toBytes(.big) } };
}

/// The proof-of-knowledge challenge `c = HDKG(SerializeScalar(i) ||
/// SerializeElement(φ_i0) || SerializeElement(R_i))` (frost-core
/// `dkg::challenge`).
fn challenge(identifier: Identifier, verifying_key: Element, r: Element) Scalar {
    var preimage: [frost.Ns + 2 * frost.Ne]u8 = undefined;
    preimage[0..frost.Ns].* = identifier.toBytes();
    preimage[frost.Ns..][0..frost.Ne].* = verifying_key.toBytes();
    preimage[frost.Ns + frost.Ne ..][0..frost.Ne].* = r.toBytes();
    return frost.hdkg(&preimage);
}

/// frost-core `verify_proof_of_knowledge`: `R == μ·G − c·φ_0`. Public data
/// only. `false` on any malformed element or scalar.
pub fn verifyProofOfKnowledge(sender: Identifier, package: Round1Package) bool {
    if (package.commitment.len == 0) return false;
    const phi0 = package.commitment[0].point() catch return false;
    const r = package.proof_of_knowledge.r.point() catch return false;
    const mu = Scalar.fromBytes(package.proof_of_knowledge.z, .big) catch return false;
    const c = challenge(sender, package.commitment[0], package.proof_of_knowledge.r);
    const mu_g = Secp256k1.basePoint.mulPublic(mu.toBytes(.big), .big) catch return false;
    const c_phi = phi0.mulPublic(c.toBytes(.big), .big) catch return false;
    return r.equivalent(mu_g.sub(c_phi));
}

// ── part2 ───────────────────────────────────────────────────────────────────

/// frost-core `dkg::part2`: checks every other participant's round-1
/// package (count, no own or repeated sender, commitment length — all before
/// any proof — then each proof of knowledge in order) and evaluates this
/// participant's polynomial at every sender. Returns the shares to send
/// (owned, in the order of `round1_packages`; `freeRound2Packages`) and
/// writes the secret package for `part3` to `out` (owned;
/// `Round2SecretPackage.deinit`). On `error.InvalidProofOfKnowledge` the
/// first failing sender is written to `culprit` (when not null).
pub fn part2(
    allocator: Allocator,
    out: *Round2SecretPackage,
    secret: *const Round1SecretPackage,
    round1_packages: []const Round1Received,
    culprit: ?*Identifier,
) Part2Error![]Round2Package {
    const r = part2Burned(allocator, out, secret, round1_packages, culprit);
    burnStack();
    return r;
}

noinline fn part2Burned(
    allocator: Allocator,
    out: *Round2SecretPackage,
    secret: *const Round1SecretPackage,
    round1_packages: []const Round1Received,
    culprit: ?*Identifier,
) Part2Error![]Round2Package {
    if (round1_packages.len != @as(usize, secret.max_signers) - 1) return error.IncorrectNumberOfPackages;
    try checkSenders(Round1Received, round1_packages, secret.identifier);
    for (round1_packages) |p| {
        if (p.package.commitment.len != secret.min_signers) return error.IncorrectNumberOfCommitments;
    }
    for (round1_packages) |p| {
        if (!verifyProofOfKnowledge(p.sender, p.package)) {
            if (culprit) |c| c.* = p.sender;
            return error.InvalidProofOfKnowledge;
        }
    }

    const packages = try allocator.alloc(Round2Package, round1_packages.len);
    errdefer freeRound2Packages(allocator, packages);
    for (packages, round1_packages) |*dst, p| {
        dst.* = .{
            .recipient = p.sender,
            .signing_share = SigningShare.fromScalar(evalPolynomial(secret.coefficients, p.sender.scalar())),
        };
    }
    const commitment = try allocator.dupe(Element, secret.commitment);
    out.* = .{
        .identifier = secret.identifier,
        .commitment = commitment,
        .secret_share = SigningShare.fromScalar(evalPolynomial(secret.coefficients, secret.identifier.scalar())),
        .min_signers = secret.min_signers,
        .max_signers = secret.max_signers,
    };
    return packages;
}

/// `f(x) = Σ_j a_j·x^j` by Horner's rule (constant time in the
/// coefficients; the loop bound is public).
fn evalPolynomial(coefficients: []const Scalar, x: Scalar) Scalar {
    var acc = Scalar.zero;
    var j = coefficients.len;
    while (j > 0) : (j -= 1) acc = acc.mul(x).add(coefficients[j - 1]);
    return acc;
}

/// No sender equals `own`, no sender twice (frost-core's map keys).
fn checkSenders(comptime T: type, list: []const T, own: Identifier) error{ UnknownIdentifier, DuplicatedIdentifier }!void {
    for (list, 0..) |a, i| {
        if (std.mem.eql(u8, &a.sender.bytes, &own.bytes)) return error.UnknownIdentifier;
        for (list[i + 1 ..]) |b| {
            if (std.mem.eql(u8, &a.sender.bytes, &b.sender.bytes)) return error.DuplicatedIdentifier;
        }
    }
}

// ── part3 ───────────────────────────────────────────────────────────────────

/// frost-core `dkg::part3`: checks each received share against its
/// sender's commitment (`vssVerify`), sums them into the signing share,
/// and derives the group public key and every participant's verifying
/// share from the summed commitments. `round1_packages` must be the ones
/// `part2` was given. Writes this participant's `KeyPackage` to `out` and
/// returns the `PublicKeyPackage` (owned; `deinit`), identical at every
/// participant. On `error.InvalidSecretShare` the first failing sender is
/// written to `culprit` (when not null).
pub fn part3(
    allocator: Allocator,
    out: *KeyPackage,
    secret: *const Round2SecretPackage,
    round1_packages: []const Round1Received,
    round2_packages: []const Round2Received,
    culprit: ?*Identifier,
) Part3Error!PublicKeyPackage {
    const r = part3Burned(allocator, out, secret, round1_packages, round2_packages, culprit);
    burnStack();
    return r;
}

noinline fn part3Burned(
    allocator: Allocator,
    out: *KeyPackage,
    secret: *const Round2SecretPackage,
    round1_packages: []const Round1Received,
    round2_packages: []const Round2Received,
    culprit: ?*Identifier,
) Part3Error!PublicKeyPackage {
    if (round1_packages.len != @as(usize, secret.max_signers) - 1) return error.IncorrectNumberOfPackages;
    try checkSenders(Round1Received, round1_packages, secret.identifier);
    try checkSenders(Round2Received, round2_packages, secret.identifier);
    if (round1_packages.len != round2_packages.len) return error.IncorrectNumberOfPackages;
    for (round1_packages) |p| {
        if (findRound2(round2_packages, p.sender) == null) return error.IncorrectPackage;
        if (p.package.commitment.len != secret.min_signers) return error.IncorrectNumberOfCommitments;
    }

    var s = secret.secret_share.scalar();
    for (round2_packages) |share| {
        // Same sets (checked above), so every round-2 sender has a package.
        const commitment = findRound1(round1_packages, share.sender).?.package.commitment;
        const as_share: frost.ParticipantShare = .{ .identifier = secret.identifier, .signing_share = share.signing_share };
        const ok = frost.vssVerify(&as_share, commitment) catch false;
        if (!ok) {
            if (culprit) |c| c.* = share.sender;
            return error.InvalidSecretShare;
        }
        s = s.add(share.signing_share.scalar());
    }

    // Σ_ℓ φ_ℓk, coefficient by coefficient (public data).
    const t = secret.min_signers;
    const group = try allocator.alloc(Secp256k1, t);
    defer allocator.free(group);
    for (group, 0..) |*g, k| {
        g.* = secret.commitment[k].point() catch return error.InvalidCommitment;
        for (round1_packages) |p| {
            // Checked by vssVerify above: every element decodes.
            g.* = g.add(p.package.commitment[k].point() catch return error.InvalidCommitment);
        }
    }
    const verifying_key = Element.fromPoint(group[0]) catch return error.InvalidCommitment;

    const n = round1_packages.len + 1;
    const shares = try allocator.alloc(ParticipantVerifyingShare, n);
    errdefer allocator.free(shares);
    shares[0] = .{ .identifier = secret.identifier, .verifying_share = undefined };
    for (shares[1..], round1_packages) |*dst, p| dst.* = .{ .identifier = p.sender, .verifying_share = undefined };
    std.sort.block(ParticipantVerifyingShare, shares, {}, struct {
        fn lessThan(_: void, a: ParticipantVerifyingShare, b: ParticipantVerifyingShare) bool {
            return std.mem.order(u8, &a.identifier.bytes, &b.identifier.bytes) == .lt;
        }
    }.lessThan);
    for (shares) |*e| {
        const x = e.identifier.scalar().toBytes(.big);
        var acc = group[t - 1];
        var k: usize = t - 1;
        while (k > 0) : (k -= 1) {
            const scaled = acc.mulPublic(x, .big) catch return error.InvalidCommitment;
            acc = scaled.add(group[k - 1]);
        }
        e.verifying_share = Element.fromPoint(acc) catch return error.InvalidCommitment;
    }

    const signing_share = SigningShare.fromScalar(s);
    const own_pt = Secp256k1.combMulBase(signing_share.toBytes(), .big) catch return error.InvalidCommitment;
    out.* = .{
        .identifier = secret.identifier,
        .signing_share = signing_share,
        .verifying_share = Element.fromPoint(own_pt) catch return error.InvalidCommitment,
        .verifying_key = verifying_key,
        .min_signers = t,
    };
    return .{ .verifying_shares = shares, .verifying_key = verifying_key, .min_signers = t };
}

fn findRound1(list: []const Round1Received, sender: Identifier) ?*const Round1Received {
    for (list) |*p| if (std.mem.eql(u8, &p.sender.bytes, &sender.bytes)) return p;
    return null;
}

fn findRound2(list: []const Round2Received, sender: Identifier) ?*const Round2Received {
    for (list) |*p| if (std.mem.eql(u8, &p.sender.bytes, &sender.bytes)) return p;
    return null;
}
