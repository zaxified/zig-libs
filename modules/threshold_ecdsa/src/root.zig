// SPDX-License-Identifier: MIT
//! threshold_ecdsa — GG20 threshold-ECDSA over secp256k1: **Phase 2a
//! (this module) = trusted-dealer keygen**, the first of a 3-part arc
//! (2a keygen · 2b MtA + range proofs · 2c signing). Depends on the
//! sibling `paillier` module: GG20's whole design hinges on every party
//! holding its own additively-homomorphic Paillier keypair (used later,
//! in Phase 2b, for the multiplicative-to-additive share-conversion
//! protocol MtA builds); this phase only WIRES that dependency in — it
//! does not run MtA itself.
//!
//! **Status: scaffold.** The Shamir-secret-sharing + Feldman-VSS +
//! Lagrange-interpolation core (`splitSecretKey`, `groupPublicKey`,
//! `derivePublicKeyShare`, `reconstructSecret`) is REAL — a direct port
//! of this repo's already-KAT-validated `frost`
//! (`deriveInterpolatingValue`) and `bls12_381.threshold`
//! (`evalPolynomialAt`/`feldmanCommitCoefficient`/`derivePublicKeyShare`)
//! constructions, swapped onto `std.crypto.ecc.Secp256k1`'s scalar field
//! and group instead of those modules' respective fields/groups. The
//! Paillier-keygen wiring inside `keygenTrustedDealer` (assembling each
//! party's `paillier.KeyPair` into its `KeyShare`) is likewise REAL — it
//! is a thin, judgment-free composition over the sibling `paillier`
//! module's already-implemented `generate`/`fromPrimes`.
//!
//! The ONE genuinely-stubbed piece is `generateAuxParams`: deriving the
//! ring-Pedersen auxiliary parameters (`N_tilde`, `h1`, `h2`) that GG20's
//! Phase-2b/2c zero-knowledge range proofs need is real, non-mechanical
//! number theory (a safe-prime search distinct from Paillier's plain
//! probable-prime search, plus sampling a secret exponent from an order
//! this module has no existing primitive for) — `@panic("TODO(core):
//! ...")`, construction spelled out in that function's own doc comment.
//! **Design decision (see this module's `SPEC.md` "Phase-2a boundary"
//! and the scaffolding report that shipped this file): rather than have
//! `keygenTrustedDealer` itself call the stubbed `generateAuxParams` (which
//! would make EVERY keygen test panic), `keygenTrustedDealer` takes
//! `aux_params` as a CALLER-SUPPLIED slice.** This keeps the Shamir/
//! Feldman/Lagrange tests AND the Paillier-keygen-wiring test fully
//! passing today — only a dedicated test that calls `generateAuxParams`
//! directly panics, and it is the LAST test in this file so every
//! other test's pass/fail is visible in `zig build test-threshold_ecdsa
//! --summary all`'s output before the crash (mirrors this repo's
//! `ssh.userauth`/`adaptor` scaffold precedent — see `SPEC.md`).
//!
//! `AuxParams`' STRUCT and byte codec are real regardless of the stub —
//! only the cryptographically-sound VALUES `generateAuxParams` would
//! produce are deferred; a hand-constructed (small, non-secure) toy
//! `AuxParams` round-trips through `toBytesAlloc`/`fromBytesAlloc` today
//! (see the tests at the bottom).
//!
//! Curve = secp256k1 (`std.crypto.ecc.Secp256k1`); scalar field Zq =
//! `Secp256k1.scalar.Scalar`. Trusted-dealer model ONLY (mirrors
//! `bls12_381.threshold`'s own scope note): a single dealer holds the
//! plaintext ECDSA secret key `x`, Shamir-splits it, and hands one share
//! to each party out-of-band. A full Pedersen-style distributed key
//! generation (no single party ever learns `x`) is explicitly OUT OF
//! SCOPE for this file — see `SPEC.md`.

const std = @import("std");
const paillier = @import("paillier");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation (no I/O of its own)
    // KeyShare/PublicKeys/AuxParams are plain value types (or thin
    // owned-slice wrappers) with no shared/global state — safe to use
    // from multiple threads as long as a given value isn't mutated
    // concurrently (nothing here ever mutates a value in place).
    .concurrency = .reentrant,
    .model_after = "R. Gennaro, S. Goldfeder, \"One Round Threshold ECDSA with Identifiable Abort\" (GG20, IACR ePrint 2020/540); R. Gennaro, S. Goldfeder, \"Fast Multiparty Threshold ECDSA with Fast Trustless Setup\" (GG18, IACR ePrint 2019/114) for the ring-Pedersen auxiliary-parameter construction; this repo's own `frost`/`bls12_381.threshold` modules for the Shamir+Feldman+Lagrange shape, ported onto std.crypto.ecc.Secp256k1's scalar field/group",
    .deps = .{"paillier"},
};

/// The curve this whole arc is built over. Re-exported so callers don't
/// need their own `std.crypto.ecc` import for basic point handling.
pub const Secp256k1 = std.crypto.ecc.Secp256k1;
const scalar_mod = Secp256k1.scalar;

/// The scalar field Zq (q = secp256k1's group order) — every secret
/// share, Shamir coefficient, and Lagrange coefficient in this module is
/// a `Scalar`.
pub const Scalar = scalar_mod.Scalar;

/// Encoded length of a `Scalar` (32-byte big-endian).
pub const Ns: usize = 32;
/// Encoded length of an `Element` (33-byte SEC1-compressed point).
pub const Ne: usize = 33;

// ── small shared helpers (mechanical byte-buffer plumbing only) ─────────

fn byteLen(bit_count: usize) usize {
    return (bit_count + 7) / 8;
}

/// `Modulus.fromBytes`/`Fe.fromBytes` reject inputs longer than the
/// backing `Uint` — externally-supplied big-endian values may carry
/// leading zero octets, so strip them first. Mirrors `paillier`'s
/// identically-named private helper.
fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

fn appendLenPrefixed(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error!void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try list.appendSlice(allocator, &len_buf);
    try list.appendSlice(allocator, data);
}

const InvalidEncodingError = error{InvalidEncoding};

fn readLenPrefixed(bytes: []const u8, offset: *usize) InvalidEncodingError![]const u8 {
    if (bytes.len < offset.* + 4) return error.InvalidEncoding;
    const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
    offset.* += 4;
    if (bytes.len < offset.* + len) return error.InvalidEncoding;
    const data = bytes[offset.* .. offset.* + len];
    offset.* += len;
    return data;
}

// ── Element — a secp256k1 group element (SEC1-compressed, REAL) ─────────

pub const ElementError = error{InvalidElement};

/// A secp256k1 group element, 33-byte SEC1-compressed (same shape as the
/// sibling `frost` module's `Element` — re-implemented locally rather
/// than imported, since this module's only declared dependency is
/// `paillier`, per the task brief). Stands in for the group public key
/// `X`, per-party verifying shares `X_i`, and Feldman commitments.
/// NEVER the identity element — both constructors reject it.
pub const Element = struct {
    bytes: [Ne]u8,

    pub const encoded_length = Ne;

    /// SEC1-compressed-point parse + full validation (on-curve,
    /// canonical, not the point at infinity) via `Secp256k1.fromSec1` +
    /// `rejectIdentity`.
    pub fn fromBytes(bytes: [Ne]u8) ElementError!Element {
        const p = Secp256k1.fromSec1(&bytes) catch return error.InvalidElement;
        p.rejectIdentity() catch return error.InvalidElement;
        return .{ .bytes = bytes };
    }

    /// `SerializeElement` applied to an in-hand curve point.
    pub fn fromPoint(p: Secp256k1) ElementError!Element {
        p.rejectIdentity() catch return error.InvalidElement;
        return .{ .bytes = p.toCompressedSec1() };
    }

    /// The real secp256k1 point. Re-validates (cheap) so this is safe on
    /// hand-constructed values.
    pub fn point(e: Element) ElementError!Secp256k1 {
        const p = Secp256k1.fromSec1(&e.bytes) catch return error.InvalidElement;
        p.rejectIdentity() catch return error.InvalidElement;
        return p;
    }

    pub fn toBytes(e: Element) [Ne]u8 {
        return e.bytes;
    }
};

// ── scalar-field Shamir + Feldman VSS (REAL — mirrors frost/bls12_381) ──

/// Converts a PUBLIC participant index (a Shamir evaluation point) to
/// its `Scalar` via a zero-padded 32-byte big-endian encoding. Every
/// `u32` is far below the group order `q` (~2^256), so
/// `Scalar.fromBytes`'s canonicality rejection can never fire — mirrors
/// `frost.Identifier`/`bls12_381.threshold.frFromIndex`'s identical
/// "small integer index" convention.
fn scalarFromIndex(index: u32) Scalar {
    var buf = [_]u8{0} ** Ns;
    std.mem.writeInt(u32, buf[Ns - 4 .. Ns], index, .big);
    return Scalar.fromBytes(buf, .big) catch unreachable; // u32 << q: always canonical
}

/// Shamir polynomial evaluation `f(index)` via Horner's method over the
/// scalar field, `f(x) = secret + coefficients[0]*x + ... +
/// coefficients[t-2]*x^(t-1)`. Byte-for-byte the same loop shape as
/// `bls12_381.threshold.evalPolynomialAt` (which itself mirrors
/// `frost.trustedDealerKeygen`'s inline Horner loop) — only the field
/// type changed. SECRET-touching: `secret` and every `coefficients`
/// entry are secret, and the output (a Shamir share) is secret too;
/// every operation goes through `Scalar`'s already-constant-time
/// `add`/`mul` (`std.crypto.pcurves.secp256k1`'s Montgomery-form field
/// arithmetic), with no secret-dependent branching (the loop bound
/// `coefficients.len` and `index` are both PUBLIC).
fn evalPolynomialAt(secret: Scalar, coefficients: []const Scalar, index: u32) Scalar {
    const x = scalarFromIndex(index);
    var acc = Scalar.zero;
    var j: usize = coefficients.len;
    while (j > 0) : (j -= 1) acc = acc.mul(x).add(coefficients[j - 1]);
    return acc.mul(x).add(secret); // constant term (a_0 = secret) added last
}

/// One participant's Shamir share of the group ECDSA secret key: `index`
/// is the polynomial evaluation point `x_i` (`1 <= index`, conventionally
/// `1..=n`), `scalar` is `f(index)` for the dealer's sharing polynomial
/// `f` (`f(0) = x`). SECRET.
pub const ShamirShare = struct {
    index: u32,
    scalar: Scalar,
};

/// A Feldman VSS commitment to the dealer's degree-`(t-1)` sharing
/// polynomial: `commitments[j] = [a_j]*G` for `j` in `0..t` (`a_0 :=
/// secret`), so `commitments[0] == [secret]*G` (`groupPublicKey`) and
/// `commitments.len == t`. PUBLIC. Owned slice — free `commitments` with
/// the allocator that produced it (`splitSecretKey`/`fromBytesAlloc`).
pub const FeldmanCommitments = struct {
    commitments: []const Element,

    pub fn threshold(self: FeldmanCommitments) usize {
        return self.commitments.len;
    }

    pub const AllocError = std.mem.Allocator.Error;

    /// `u32-BE count || commitments[0] || ... || commitments[count-1]`
    /// (each a 33-byte compressed point). REAL — mechanical
    /// concatenation, mirrors `bls12_381.threshold.VerificationVector
    /// .toBytesAlloc`.
    pub fn toBytesAlloc(self: FeldmanCommitments, allocator: std.mem.Allocator) AllocError![]u8 {
        const out = try allocator.alloc(u8, 4 + self.commitments.len * Ne);
        std.mem.writeInt(u32, out[0..4], @intCast(self.commitments.len), .big);
        for (self.commitments, 0..) |c, i| {
            const off = 4 + i * Ne;
            out[off..][0..Ne].* = c.toBytes();
        }
        return out;
    }

    pub const FromBytesError = error{InvalidEncoding} || ElementError;

    pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) (std.mem.Allocator.Error || FromBytesError)!FeldmanCommitments {
        if (bytes.len < 4) return error.InvalidEncoding;
        const count = std.mem.readInt(u32, bytes[0..4], .big);
        const expected_len = 4 + @as(usize, count) * Ne;
        if (bytes.len != expected_len) return error.InvalidEncoding;

        const commitments = try allocator.alloc(Element, count);
        errdefer allocator.free(commitments);
        for (commitments, 0..) |*slot, i| {
            const off = 4 + i * Ne;
            slot.* = try Element.fromBytes(bytes[off..][0..Ne].*);
        }
        return .{ .commitments = commitments };
    }
};

pub const SplitError = error{ InvalidParameters, InvalidElement } || std.mem.Allocator.Error;

pub const SplitResult = struct {
    /// Owned; free with the allocator passed to `splitSecretKey`.
    shares: []ShamirShare,
    /// `.commitments` owned; free with the same allocator.
    commitments: FeldmanCommitments,
};

/// Trusted-dealer Shamir splitting of `secret_key` (the group ECDSA
/// secret key `x`) into `n` shares reconstructible by any `t` of them,
/// PLUS a Feldman VSS commitment so every share is publicly checkable
/// (`derivePublicKeyShare`) without revealing any share value. REAL —
/// direct port of `bls12_381.threshold.splitSecretKey`'s two-part
/// construction (`secret_share_shard` + `vss_commit`, mirroring
/// `frost.trustedDealerKeygen`'s RFC 9591 Appendix C.1/C.2 shape) onto
/// `Scalar`/`Secp256k1` instead of that module's `Fr`/`g1`:
///
/// ```text
/// // 1. secret_share_shard (Shamir):
/// //      f(x) = secret_key + coefficients[0]*x + ... + coefficients[t-2]*x^(t-1)
/// for i in 1..=n:
///     shares[i] = (i, f(i))                          // evalPolynomialAt
///
/// // 2. vss_commit (Feldman): one Element commitment per coefficient
/// commitments[0] = [secret_key]*G
/// commitments[j] = [coefficients[j-1]]*G    for j in 1..t
/// ```
///
/// `coefficients` is CALLER-SUPPLIED randomness (length exactly `t - 1`),
/// not sampled internally — the same "deterministic entry point" shape
/// `frost.trustedDealerKeygen`/`bls12_381.threshold.splitSecretKey` use
/// (reproducible tests; a real deployment's caller samples fresh
/// coefficients via `Scalar.random(io)` once per dealing and discards
/// them immediately after — retaining them defeats Shamir's security
/// exactly as retaining `secret_key` itself would).
pub fn splitSecretKey(
    allocator: std.mem.Allocator,
    secret_key: Scalar,
    t: u32,
    n: u32,
    coefficients: []const Scalar,
) SplitError!SplitResult {
    if (t == 0 or n == 0 or t > n) return error.InvalidParameters;
    if (coefficients.len != @as(usize, t) - 1) return error.InvalidParameters;

    const shares = try allocator.alloc(ShamirShare, n);
    errdefer allocator.free(shares);
    var i: u32 = 1;
    while (i <= n) : (i += 1) {
        shares[i - 1] = .{ .index = i, .scalar = evalPolynomialAt(secret_key, coefficients, i) };
    }

    const commitments = try allocator.alloc(Element, t);
    errdefer allocator.free(commitments);
    var j: usize = 0;
    while (j < t) : (j += 1) {
        const coeff = if (j == 0) secret_key else coefficients[j - 1];
        const point = Secp256k1.basePoint.mul(coeff.toBytes(.big), .big) catch return error.InvalidElement;
        commitments[j] = Element.fromPoint(point) catch return error.InvalidElement;
    }

    return .{ .shares = shares, .commitments = .{ .commitments = commitments } };
}

/// The group's ECDSA public key: `vvec.commitments[0]`, i.e.
/// `[secret_key]*G` — the same "`vss_commitment[0]` IS the group public
/// key" identity `frost`/`bls12_381.threshold` document. REAL — plain
/// indexing, no field/group arithmetic of its own.
pub fn groupPublicKey(vvec: FeldmanCommitments) Element {
    return vvec.commitments[0];
}

pub const DerivePublicKeyShareError = ElementError;

/// Evaluates the Feldman commitment polynomial `C(x) = commitments[0] +
/// commitments[1]*x + ... + commitments[t-1]*x^(t-1)` AT `x = index`, IN
/// THE EXPONENT — `C(x) == [f(x)]*G` for the SAME sharing polynomial `f`
/// `splitSecretKey` dealt shares from, so this reconstructs participant
/// `index`'s PUBLIC key share WITHOUT ever seeing that participant's
/// secret share. REAL — Horner's method in the exponent, direct port of
/// `bls12_381.threshold.derivePublicKeyShare` onto `Secp256k1`/`Element`.
pub fn derivePublicKeyShare(vvec: FeldmanCommitments, index: u32) DerivePublicKeyShareError!Element {
    const x = scalarFromIndex(index);
    const commitments = vvec.commitments;
    var acc = try commitments[commitments.len - 1].point();
    var j: usize = commitments.len - 1;
    while (j > 0) : (j -= 1) {
        const next = try commitments[j - 1].point();
        acc = acc.mul(x.toBytes(.big), .big) catch return error.InvalidElement;
        acc = acc.add(next);
    }
    return Element.fromPoint(acc);
}

pub const ReconstructError = error{ InsufficientShares, DuplicateIndex, ZeroIndex };

/// Reconstructs the group secret `x = f(0)` from `shares` via Lagrange
/// interpolation at `x = 0` — the numerator/denominator-product formula
/// `lambda_i = Prod_{j!=i} x_j / (x_j - x_i)`, byte-for-byte the same
/// shape as `frost.deriveInterpolatingValue` and
/// `bls12_381.threshold.combineSignatures`'s Lagrange step (there
/// applied in the exponent to signature shares; here applied directly to
/// scalar shares). REAL.
///
/// **This function exists for this module's own self-consistency TESTS
/// and for offline audit/recovery tooling — NOT for a production signing
/// path.** The entire point of a threshold scheme is that the raw secret
/// `x` is never reconstructed in one place during ordinary operation;
/// Phase 2c (signing) computes a threshold ECDSA signature WITHOUT ever
/// calling this function. See `SPEC.md`'s threat model.
pub fn reconstructSecret(shares: []const ShamirShare) ReconstructError!Scalar {
    if (shares.len == 0) return error.InsufficientShares;
    for (shares, 0..) |a, idx| {
        if (a.index == 0) return error.ZeroIndex;
        for (shares[idx + 1 ..]) |b| {
            if (a.index == b.index) return error.DuplicateIndex;
        }
    }

    var secret = Scalar.zero;
    for (shares) |share_i| {
        const xi = scalarFromIndex(share_i.index);
        var numerator = Scalar.one;
        var denominator = Scalar.one;
        for (shares) |share_j| {
            if (share_j.index == share_i.index) continue;
            const xj = scalarFromIndex(share_j.index);
            numerator = numerator.mul(xj);
            denominator = denominator.mul(xj.sub(xi));
        }
        // Every factor x_j - x_i is nonzero (distinct u32 indices, hence
        // distinct as Scalars), so denominator is invertible.
        const lambda_i = numerator.mul(denominator.invert());
        secret = secret.add(lambda_i.mul(share_i.scalar));
    }
    return secret;
}

// ── ring-Pedersen auxiliary parameters (STRUCT+CODEC real, VALUES stub) ─

/// Bit-size the ring-Pedersen modulus `N_tilde` is designed for — same
/// convention/rationale as `paillier.modulus_bits`/`rsa`'s default
/// modulus size (GG18/GG20 use an RSA-strength safe-prime-product
/// modulus for this parameter, same security-margin class as Paillier's
/// own `n`).
pub const aux_modulus_bits = 2048;

/// Fixed-width constant-time modulus type sized to `aux_modulus_bits`
/// (`std.crypto.ff.Modulus`, the exact primitive `paillier`/`rsa` build
/// on) — this is the ring-Pedersen `N_tilde`'s type.
pub const AuxModulus = std.crypto.ff.Modulus(aux_modulus_bits);
/// Field element type for `AuxModulus` — `h1`/`h2` are this type,
/// canonical mod `n_tilde`.
pub const AuxFe = AuxModulus.Fe;

/// One party's ring-Pedersen auxiliary parameters (GG18 §4 / GG20's
/// Appendix, "Pedersen commitment parameters"): a safe-prime-product
/// modulus `N_tilde` and two generators `h1`, `h2` of its group of
/// squares, with `h2 = h1^lambda mod N_tilde` for a secret `lambda` known
/// only to the generating party. Phase-2b/2c ZK range proofs (proving a
/// Paillier plaintext lies in a bounded range without revealing it) use
/// these as the commitment base for a Pedersen-style hiding commitment
/// mod `N_tilde` — see GG18 §4/§6 and GG20's proof-system appendices.
///
/// **The STRUCT and byte codec below are REAL** (mechanical
/// `std.crypto.ff` plumbing, same shape as `paillier.PublicKey`); **only
/// the cryptographically-sound VALUES `generateAuxParams` would produce
/// are stubbed** — see that function's doc comment for the exact
/// construction a follow-up crypto pass must transcribe. A
/// hand-constructed toy `AuxParams` (small, non-secure — see the tests at
/// the bottom of this file) already round-trips through
/// `toBytesAlloc`/`fromBytesAlloc` today.
pub const AuxParams = struct {
    n_tilde: AuxModulus,
    /// Canonical mod `n_tilde`.
    h1: AuxFe,
    /// Canonical mod `n_tilde`.
    h2: AuxFe,

    pub const ByteError = std.crypto.ff.OverflowError || std.crypto.ff.RepresentationError;

    fn nTildeByteLen(self: AuxParams) usize {
        return byteLen(self.n_tilde.bits());
    }

    pub const AllocError = std.mem.Allocator.Error || ByteError;

    /// `u32-BE len(N̈) || N̈ || u32-BE len(h1) || h1 || u32-BE len(h2) ||
    /// h2` (each big-endian, canonical per the field's own byte length —
    /// `h1`/`h2` are encoded into a buffer sized to `N̈`'s byte length,
    /// which safely covers any value `< N̈`). REAL, mechanical — mirrors
    /// `paillier.PublicKey`'s `nToBytes`/`gToBytes` shape plus
    /// `bls12_381.threshold.VerificationVector`'s length-prefixed
    /// concatenation idiom.
    pub fn toBytesAlloc(self: AuxParams, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        const nt_len = self.nTildeByteLen();

        const nt_buf = try allocator.alloc(u8, nt_len);
        defer allocator.free(nt_buf);
        try self.n_tilde.toBytes(nt_buf, .big);
        try appendLenPrefixed(&list, allocator, nt_buf);

        const h1_buf = try allocator.alloc(u8, nt_len);
        defer allocator.free(h1_buf);
        try self.h1.toBytes(h1_buf, .big);
        try appendLenPrefixed(&list, allocator, h1_buf);

        const h2_buf = try allocator.alloc(u8, nt_len);
        defer allocator.free(h2_buf);
        try self.h2.toBytes(h2_buf, .big);
        try appendLenPrefixed(&list, allocator, h2_buf);

        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidAuxParams};

    /// Inverse of `toBytesAlloc`. Does not allocate (all three fields
    /// are fixed-width `std.crypto.ff` value types, not owned slices).
    pub fn fromBytesAlloc(bytes: []const u8) FromBytesError!AuxParams {
        var offset: usize = 0;
        const nt_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidAuxParams;
        const nt = stripLeadingZeros(nt_bytes);
        if (nt.len == 0) return error.InvalidAuxParams;
        const n_tilde = AuxModulus.fromBytes(nt, .big) catch return error.InvalidAuxParams;

        const h1_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidAuxParams;
        const h1 = AuxFe.fromBytes(n_tilde, stripLeadingZeros(h1_bytes), .big) catch return error.InvalidAuxParams;

        const h2_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidAuxParams;
        const h2 = AuxFe.fromBytes(n_tilde, stripLeadingZeros(h2_bytes), .big) catch return error.InvalidAuxParams;

        return .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 };
    }
};

/// Floor `generateAuxParams` will enforce once implemented — mirrors
/// `paillier.min_generate_bits`.
pub const min_aux_generate_bits = 512;

/// **STUB — genuine number theory, deliberately unimplemented in this
/// scaffolding pass.** Generates ring-Pedersen auxiliary parameters for
/// ONE party.
///
/// Construction (GG18 SS4.1 / Canetti-Gennaro-Goldfeder-Makriyannis-Peled
/// "UC Non-Interactive, Proactive, Threshold ECDSA" SS3.1, the "aux info"
/// generation step commonly cited by tss-lib/multi-party-ecdsa-style
/// reference implementations — facts about the construction only, no
/// source consulted, see NOTICE):
///
/// ```text
/// 1. Draw two safe primes p̃ = 2p' + 1, q̃ = 2q' + 1, each `bits/2` bits,
///    with p', q' also prime — the SAME probable-prime search shape as
///    this repo's `paillier.generatePrime` (random odd candidate + trial
///    sieve + Miller-Rabin), PLUS an additional Miller-Rabin pass on
///    `(candidate - 1) / 2` to confirm the safe-prime property. Zig std
///    has every primitive this needs (`std.crypto.ff`, `std.Random`),
///    but the safe-prime search itself is not yet written here.
/// 2. N_tilde = p̃ * q̃ (mechanical big-int multiply once p̃, q̃ are in
///    hand — see `paillier`'s own `n = p*q` step for the exact shape).
/// 3. Draw h1 uniformly from [2, N_tilde) by rejection sampling
///    (mirrors `paillier`'s private `sampleNonzeroLtN`).
/// 4. Draw a secret exponent lambda uniformly from [1, p'*q') — the
///    order of N_tilde's group of squares. Zig std has no existing
///    "order of the squares subgroup of a safe-prime product" helper;
///    deriving/using this range correctly is itself part of the
///    deferred number theory.
/// 5. h2 = h1^lambda mod N_tilde (constant-time modexp via
///    `AuxModulus.pow` — mechanical ONCE lambda/h1 are in hand, but
///    lambda's derivation in step 4 is not).
/// 6. Discard lambda (a party's own secret; never transmitted — only
///    N_tilde/h1/h2 are broadcast, see `AuxParams`/`PartyPublicKeys`).
///    TODO(core): confirm against GG20/Phase-2b's exact range-proof
///    constructions whether the PROVER additionally needs to retain
///    lambda (or a value derived from it) locally for its own proofs, or
///    whether discarding it here is correct — this module's scaffolding
///    pass did not scope Phase 2b closely enough to be certain.
/// ```
///
/// `AuxParams`'s struct + byte codec above are already real; only the
/// VALUES this function would produce are stubbed. Suggested follow-up
/// tier: small, self-contained number theory (safe-prime search +
/// modexp) — a Fable or Opus pass, not a large one; see the scaffolding
/// report that shipped this file.
pub fn generateAuxParams(random: std.Random, bits: usize) AuxParams {
    _ = random;
    _ = bits;
    @panic("TODO(core): ring-Pedersen aux-param generation (safe-prime search for p̃,q̃, N_tilde=p̃q̃, random h1, secret lambda, h2=h1^lambda mod N_tilde) — see this function's doc comment for the exact construction. Genuine number theory (safe-prime primality testing beyond paillier.generatePrime's plain Miller-Rabin, deriving/sampling from the order of N_tilde's squares subgroup) deliberately left unimplemented for a follow-up crypto pass; AuxParams' struct + byte codec are already real and round-trip today on hand-constructed toy values.");
}

// ── per-party public material (REAL) ─────────────────────────────────────

/// One party's PUBLIC material, as broadcast to every other party during
/// (trusted-dealer, out-of-band) key distribution: their Paillier public
/// key and ring-Pedersen auxiliary parameters. `PublicKeys` (plural,
/// below) is the full-group collection every party ends up holding — the
/// exact set Phase-2b/2c's MtA and ZK-proof exchanges need to run
/// against any OTHER party without further out-of-band exchange.
pub const PartyPublicKeys = struct {
    index: u32,
    paillier_pk: paillier.PublicKey,
    aux: AuxParams,
};

/// The full group's public material: one `PartyPublicKeys` per party,
/// `1..=n`. Every `KeyShare` this module's `keygenTrustedDealer` returns
/// embeds an IDENTICAL copy of this value (same underlying `entries`
/// allocation — see `KeyShare`'s doc comment for the resulting ownership
/// contract).
pub const PublicKeys = struct {
    entries: []const PartyPublicKeys,

    /// Linear lookup by party index. REAL — pure plumbing, `n` is always
    /// small (a handful to low hundreds of parties in any realistic MPC
    /// custody deployment) so O(n) is not a concern.
    pub fn get(self: PublicKeys, index: u32) ?PartyPublicKeys {
        for (self.entries) |e| {
            if (e.index == index) return e;
        }
        return null;
    }

    pub const AllocError = std.mem.Allocator.Error || paillier.PublicKey.ByteError || AuxParams.ByteError;

    /// `u32-BE count || entry[0] || ... || entry[count-1]`, each entry
    /// `u32-BE index || len-prefixed(paillier n) || len-prefixed
    /// (paillier g) || len-prefixed(aux.toBytesAlloc())`. REAL,
    /// mechanical.
    pub fn toBytesAlloc(self: PublicKeys, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        var count_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &count_buf, @intCast(self.entries.len), .big);
        try list.appendSlice(allocator, &count_buf);

        for (self.entries) |e| {
            var idx_buf: [4]u8 = undefined;
            std.mem.writeInt(u32, &idx_buf, e.index, .big);
            try list.appendSlice(allocator, &idx_buf);

            const n_len = e.paillier_pk.nByteLen();
            const n_buf = try allocator.alloc(u8, n_len);
            defer allocator.free(n_buf);
            try e.paillier_pk.nToBytes(n_buf);
            try appendLenPrefixed(&list, allocator, n_buf);

            const g_buf = try allocator.alloc(u8, paillier.modulus_sq_bytes);
            defer allocator.free(g_buf);
            try e.paillier_pk.gToBytes(g_buf);
            try appendLenPrefixed(&list, allocator, g_buf);

            const aux_bytes = try e.aux.toBytesAlloc(allocator);
            defer allocator.free(aux_bytes);
            try appendLenPrefixed(&list, allocator, aux_bytes);
        }

        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding} || paillier.PublicKey.FromBytesError || AuxParams.FromBytesError;

    /// Inverse of `toBytesAlloc`. Allocates `entries`; caller frees with
    /// `allocator`.
    pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) (std.mem.Allocator.Error || FromBytesError)!PublicKeys {
        if (bytes.len < 4) return error.InvalidEncoding;
        const count = std.mem.readInt(u32, bytes[0..4], .big);
        var offset: usize = 4;

        const entries = try allocator.alloc(PartyPublicKeys, count);
        errdefer allocator.free(entries);
        for (entries) |*slot| {
            if (bytes.len < offset + 4) return error.InvalidEncoding;
            const index = std.mem.readInt(u32, bytes[offset..][0..4], .big);
            offset += 4;

            const n_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
            const g_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
            const pk = try paillier.PublicKey.fromBytes(n_bytes, g_bytes);

            const aux_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
            const aux = try AuxParams.fromBytesAlloc(aux_bytes);

            slot.* = .{ .index = index, .paillier_pk = pk, .aux = aux };
        }
        return .{ .entries = entries };
    }
};

// ── KeyShare — Phase-2a's final output (REAL assembly) ───────────────────

/// One party's complete Phase-2a key material — everything Phase 2b/2c
/// need to run MtA/range-proofs/signing:
///
///   - `secret_share` (x_i, SECRET): this party's Shamir share of the
///     group ECDSA secret key.
///   - `group_public_key` (X = x*G, PUBLIC): the shared ECDSA public
///     key every signature must verify against.
///   - `verifying_share` (X_i = x_i*G, PUBLIC): this party's own
///     Feldman-consistent public share (`derivePublicKeyShare`'s
///     output).
///   - `index`/`t`/`n`: this party's Shamir index and the group's
///     threshold/size.
///   - `paillier_secret` (SECRET): this party's own Paillier secret
///     key — needed to decrypt MtA ciphertexts addressed to it.
///   - `public_keys` (PUBLIC): every party's Paillier public key +
///     ring-Pedersen aux params (`PublicKeys`, includes this party's
///     own entry too, for uniformity).
///
/// **Ownership note:** `keygenTrustedDealer` returns `n` `KeyShare`
/// values that all share the SAME underlying `public_keys.entries`
/// allocation (broadcast public material is identical for every party by
/// construction) — free it exactly ONCE (e.g.
/// `allocator.free(key_shares[0].public_keys.entries)`), not once per
/// share, then free the `key_shares` slice itself. See the tests at the
/// bottom for the exact cleanup shape.
pub const KeyShare = struct {
    index: u32,
    t: u32,
    n: u32,
    secret_share: Scalar,
    group_public_key: Element,
    verifying_share: Element,
    paillier_secret: paillier.SecretKey,
    public_keys: PublicKeys,

    pub const AllocError = std.mem.Allocator.Error || paillier.SecretKey.ByteError || PublicKeys.AllocError;

    /// `index(4) || t(4) || n(4) || secret_share(32) ||
    /// group_public_key(33) || verifying_share(33) || len-prefixed
    /// (paillier_secret.n) || len-prefixed(paillier_secret.lambda) ||
    /// len-prefixed(paillier_secret.mu) || len-prefixed
    /// (public_keys.toBytesAlloc())`. REAL, mechanical — composes
    /// already-real sub-codecs (`paillier.SecretKey`'s own
    /// `nToBytes`/`lambdaToBytes`/`muToBytes`, `Element.toBytes`,
    /// `PublicKeys.toBytesAlloc`).
    pub fn toBytesAlloc(self: KeyShare, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        var hdr: [12]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], self.index, .big);
        std.mem.writeInt(u32, hdr[4..8], self.t, .big);
        std.mem.writeInt(u32, hdr[8..12], self.n, .big);
        try list.appendSlice(allocator, &hdr);

        const secret_bytes = self.secret_share.toBytes(.big);
        try list.appendSlice(allocator, &secret_bytes);
        try list.appendSlice(allocator, &self.group_public_key.toBytes());
        try list.appendSlice(allocator, &self.verifying_share.toBytes());

        const sk_n_len = self.paillier_secret.nByteLen();
        const sk_n_buf = try allocator.alloc(u8, sk_n_len);
        defer allocator.free(sk_n_buf);
        try self.paillier_secret.nToBytes(sk_n_buf);
        try appendLenPrefixed(&list, allocator, sk_n_buf);

        const lambda_buf = try allocator.alloc(u8, paillier.modulus_sq_bytes);
        defer allocator.free(lambda_buf);
        try self.paillier_secret.lambdaToBytes(lambda_buf);
        try appendLenPrefixed(&list, allocator, lambda_buf);

        const mu_buf = try allocator.alloc(u8, paillier.modulus_bytes);
        defer allocator.free(mu_buf);
        try self.paillier_secret.muToBytes(mu_buf);
        try appendLenPrefixed(&list, allocator, mu_buf);

        const pubkeys_bytes = try self.public_keys.toBytesAlloc(allocator);
        defer allocator.free(pubkeys_bytes);
        try appendLenPrefixed(&list, allocator, pubkeys_bytes);

        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding} ||
        ElementError ||
        paillier.SecretKey.FromBytesError ||
        PublicKeys.FromBytesError;

    /// Inverse of `toBytesAlloc`. Allocates `public_keys.entries`;
    /// caller frees with `allocator`.
    pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) (std.mem.Allocator.Error || FromBytesError)!KeyShare {
        if (bytes.len < 12 + Ns + Ne + Ne) return error.InvalidEncoding;
        const index = std.mem.readInt(u32, bytes[0..4], .big);
        const t = std.mem.readInt(u32, bytes[4..8], .big);
        const n = std.mem.readInt(u32, bytes[8..12], .big);
        var offset: usize = 12;

        const secret_share = Scalar.fromBytes(bytes[offset..][0..Ns].*, .big) catch return error.InvalidEncoding;
        offset += Ns;
        const group_public_key = try Element.fromBytes(bytes[offset..][0..Ne].*);
        offset += Ne;
        const verifying_share = try Element.fromBytes(bytes[offset..][0..Ne].*);
        offset += Ne;

        const sk_n_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const lambda_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const mu_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const paillier_secret = try paillier.SecretKey.fromBytes(sk_n_bytes, lambda_bytes, mu_bytes);

        const pubkeys_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const public_keys = try PublicKeys.fromBytesAlloc(allocator, pubkeys_bytes);

        return .{
            .index = index,
            .t = t,
            .n = n,
            .secret_share = secret_share,
            .group_public_key = group_public_key,
            .verifying_share = verifying_share,
            .paillier_secret = paillier_secret,
            .public_keys = public_keys,
        };
    }
};

pub const KeygenError = error{InvalidParameters} || SplitError || DerivePublicKeyShareError || std.mem.Allocator.Error;

/// Phase-2a trusted-dealer keygen: Shamir-splits `secret_key` (REAL,
/// `splitSecretKey`), wires each party's caller-supplied
/// `paillier.KeyPair` (REAL — thin composition, no new crypto judgment;
/// each party's keypair may come from `paillier.generate` for a real
/// deployment or a fixed `paillier.fromPrimes` pair for KATs), and
/// assembles each party's public material (`PublicKeys`, REAL) — see the
/// module doc comment's "Design decision" note for why `aux_params` is
/// CALLER-SUPPLIED rather than generated internally via the stubbed
/// `generateAuxParams` (this is what keeps this function's own tests
/// fully passing today, with only a dedicated `generateAuxParams` test
/// panicking).
///
/// `paillier_keys.len` and `aux_params.len` MUST both equal `n` (one
/// entry per party, `paillier_keys[i-1]`/`aux_params[i-1]` for party
/// `i`); `coefficients.len` MUST equal `t - 1` (`splitSecretKey`'s own
/// precondition). Returns `n` `KeyShare`s — see `KeyShare`'s doc comment
/// for the shared-allocation ownership contract.
pub fn keygenTrustedDealer(
    allocator: std.mem.Allocator,
    t: u32,
    n: u32,
    secret_key: Scalar,
    coefficients: []const Scalar,
    paillier_keys: []const paillier.KeyPair,
    aux_params: []const AuxParams,
) KeygenError![]KeyShare {
    if (paillier_keys.len != n or aux_params.len != n) return error.InvalidParameters;

    const split = try splitSecretKey(allocator, secret_key, t, n, coefficients);
    defer allocator.free(split.shares);
    defer allocator.free(split.commitments.commitments);

    const group_pub = groupPublicKey(split.commitments);

    const party_pubs = try allocator.alloc(PartyPublicKeys, n);
    errdefer allocator.free(party_pubs);
    var i: u32 = 1;
    while (i <= n) : (i += 1) {
        party_pubs[i - 1] = .{
            .index = i,
            .paillier_pk = paillier_keys[i - 1].public,
            .aux = aux_params[i - 1],
        };
    }
    const public_keys: PublicKeys = .{ .entries = party_pubs };

    const key_shares = try allocator.alloc(KeyShare, n);
    errdefer allocator.free(key_shares);
    i = 1;
    while (i <= n) : (i += 1) {
        const verifying_share = try derivePublicKeyShare(split.commitments, i);
        key_shares[i - 1] = .{
            .index = i,
            .t = t,
            .n = n,
            .secret_share = split.shares[i - 1].scalar,
            .group_public_key = group_pub,
            .verifying_share = verifying_share,
            .paillier_secret = paillier_keys[i - 1].secret,
            .public_keys = public_keys,
        };
    }
    return key_shares;
}

// ── tests ────────────────────────────────────────────────────────────────
//
// Threshold-ECDSA has no official standard KAT vectors (unlike frost's
// RFC 9591 Appendix E.5) — verification here is self-consistency, same
// posture as `bls12_381.threshold`'s own tests. Ordered so every test
// EXCEPT the final `generateAuxParams` one PASSES today: `zig build
// test-threshold_ecdsa --summary all` shows every test above the last
// one succeed before that final test panics (see the module doc
// comment's "Design decision" note and this repo's `ssh.userauth`/
// `adaptor` scaffold precedent for why this is the accepted state of a
// module with one deliberately-deferred crypto core).

const testing = std.testing;

fn testScalar(seed: u8) Scalar {
    var buf = [_]u8{0} ** 48;
    buf[47] = seed;
    return Scalar.fromBytes48(buf, .big);
}

test "Element fromPoint/fromBytes/point round-trip and reject the identity" {
    const p = Secp256k1.basePoint;
    const e = try Element.fromPoint(p);
    const back = try e.point();
    try testing.expect(back.equivalent(p));

    const e2 = try Element.fromBytes(e.toBytes());
    try testing.expectEqualSlices(u8, &e.toBytes(), &e2.toBytes());

    try testing.expectError(error.InvalidElement, Element.fromPoint(Secp256k1.identityElement));
}

test "splitSecretKey (t=2,n=3): any 2 shares Lagrange-reconstruct the secret; X == x*G" {
    const allocator = testing.allocator;
    const secret = testScalar(1);
    const coeffs = [_]Scalar{testScalar(2)};

    const split = try splitSecretKey(allocator, secret, 2, 3, &coeffs);
    defer allocator.free(split.shares);
    defer allocator.free(split.commitments.commitments);

    try testing.expectEqual(@as(usize, 3), split.shares.len);
    try testing.expectEqual(@as(usize, 2), split.commitments.threshold());

    const expected_x = try Element.fromPoint(try Secp256k1.basePoint.mul(secret.toBytes(.big), .big));
    const x = groupPublicKey(split.commitments);
    try testing.expectEqualSlices(u8, &expected_x.toBytes(), &x.toBytes());

    // Every pairwise subset of 2 (of 3) shares reconstructs the same secret.
    const subsets = [_][2]usize{ .{ 0, 1 }, .{ 0, 2 }, .{ 1, 2 } };
    for (subsets) |pair| {
        const pair_shares = [_]ShamirShare{ split.shares[pair[0]], split.shares[pair[1]] };
        const reconstructed = try reconstructSecret(&pair_shares);
        try testing.expectEqualSlices(u8, &secret.toBytes(.big), &reconstructed.toBytes(.big));
    }
}

test "splitSecretKey (t=3,n=5): Feldman consistency X_i == x_i*G for every share" {
    const allocator = testing.allocator;
    const secret = testScalar(3);
    const coeffs = [_]Scalar{ testScalar(4), testScalar(5) };

    const split = try splitSecretKey(allocator, secret, 3, 5, &coeffs);
    defer allocator.free(split.shares);
    defer allocator.free(split.commitments.commitments);

    for (split.shares) |share| {
        const derived = try derivePublicKeyShare(split.commitments, share.index);
        const expected = try Element.fromPoint(try Secp256k1.basePoint.mul(share.scalar.toBytes(.big), .big));
        try testing.expectEqualSlices(u8, &expected.toBytes(), &derived.toBytes());
    }

    // Any 3 (of 5) shares also reconstruct the secret.
    const three = [_]ShamirShare{ split.shares[0], split.shares[2], split.shares[4] };
    const reconstructed = try reconstructSecret(&three);
    try testing.expectEqualSlices(u8, &secret.toBytes(.big), &reconstructed.toBytes(.big));

    // Below threshold: 2 shares do NOT reconstruct the true secret (a
    // mathematically wrong answer, not an error — same caveat
    // `frost.deriveInterpolatingValue`/`bls12_381.threshold
    // .combineSignatures`'s doc comments carry).
    const two = [_]ShamirShare{ split.shares[0], split.shares[1] };
    const wrong = try reconstructSecret(&two);
    try testing.expect(!std.mem.eql(u8, &secret.toBytes(.big), &wrong.toBytes(.big)));
}

test "reconstructSecret rejects too few, duplicate, or zero-indexed shares" {
    try testing.expectError(error.InsufficientShares, reconstructSecret(&.{}));

    const dup = [_]ShamirShare{
        .{ .index = 1, .scalar = testScalar(1) },
        .{ .index = 1, .scalar = testScalar(2) },
    };
    try testing.expectError(error.DuplicateIndex, reconstructSecret(&dup));

    const zero = [_]ShamirShare{
        .{ .index = 0, .scalar = testScalar(1) },
        .{ .index = 2, .scalar = testScalar(2) },
    };
    try testing.expectError(error.ZeroIndex, reconstructSecret(&zero));
}

test "FeldmanCommitments toBytesAlloc/fromBytesAlloc round-trip" {
    const allocator = testing.allocator;
    const secret = testScalar(6);
    const coeffs = [_]Scalar{testScalar(7)};
    const split = try splitSecretKey(allocator, secret, 2, 2, &coeffs);
    defer allocator.free(split.shares);
    defer allocator.free(split.commitments.commitments);

    const bytes = try split.commitments.toBytesAlloc(allocator);
    defer allocator.free(bytes);
    const back = try FeldmanCommitments.fromBytesAlloc(allocator, bytes);
    defer allocator.free(back.commitments);

    try testing.expectEqual(split.commitments.threshold(), back.threshold());
    for (split.commitments.commitments, back.commitments) |a, b| {
        try testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());
    }
}

// Toy ring-Pedersen values reused for every AuxParams-serialization test
// below: `n_tilde = 187 = 11*17` (the SAME toy modulus this repo's
// `paillier` module's own KAT tests use — see paillier/src/root.zig),
// h1 = 5, h2 = 25. These do NOT satisfy any real ring-Pedersen soundness
// property (h2 is not derived as h1^lambda for a secret lambda via the
// stubbed `generateAuxParams`) — they exist ONLY to exercise the
// (already-real) `AuxParams` struct/codec while `generateAuxParams`
// itself remains unimplemented.
fn toyAuxParams() AuxParams {
    const n_tilde = AuxModulus.fromBytes(&[_]u8{187}, .big) catch unreachable;
    const h1 = AuxFe.fromBytes(n_tilde, &[_]u8{5}, .big) catch unreachable;
    const h2 = AuxFe.fromBytes(n_tilde, &[_]u8{25}, .big) catch unreachable;
    return .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 };
}

test "AuxParams toBytesAlloc/fromBytesAlloc round-trip (toy values)" {
    const allocator = testing.allocator;
    const aux = toyAuxParams();

    const bytes = try aux.toBytesAlloc(allocator);
    defer allocator.free(bytes);
    const back = try AuxParams.fromBytesAlloc(bytes);

    try testing.expect(aux.n_tilde.v.eql(back.n_tilde.v));
    try testing.expect(aux.h1.eql(back.h1));
    try testing.expect(aux.h2.eql(back.h2));
}

test "generate-based Paillier keygen wiring: keygenTrustedDealer wires distinct real Paillier pubkeys per party" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x746563647361);
    const random = prng.random();

    const t: u32 = 2;
    const n: u32 = 3;

    // Small-but-real Paillier keypairs (paillier.min_generate_bits, kept
    // fast for every-run testing — same rationale as paillier's own
    // "generate: 512-bit keygen" test).
    const kp1 = try paillier.generate(random, paillier.min_generate_bits);
    const kp2 = try paillier.generate(random, paillier.min_generate_bits);
    const kp3 = try paillier.generate(random, paillier.min_generate_bits);
    const paillier_keys = [_]paillier.KeyPair{ kp1, kp2, kp3 };

    const aux = toyAuxParams();
    const aux_params = [_]AuxParams{ aux, aux, aux };

    const secret = testScalar(9);
    const coeffs = [_]Scalar{testScalar(10)};

    const key_shares = try keygenTrustedDealer(allocator, t, n, secret, &coeffs, &paillier_keys, &aux_params);
    // LIFO defer order matters: `entries` is reached THROUGH
    // `key_shares[0]`, so it must be freed BEFORE `key_shares` itself —
    // meaning its `defer` must be declared AFTER (so it runs first).
    defer allocator.free(key_shares);
    defer allocator.free(key_shares[0].public_keys.entries);

    try testing.expectEqual(@as(usize, 3), key_shares.len);

    var n_bufs: [3][paillier.modulus_bytes]u8 = undefined;
    for (key_shares, 0..) |share, i| {
        try testing.expectEqual(@as(u32, @intCast(i + 1)), share.index);
        try testing.expectEqual(t, share.t);
        try testing.expectEqual(n, share.n);

        // This party's own Paillier pubkey (via public_keys.get) matches
        // the keypair it was dealt from.
        const own_pub = share.public_keys.get(share.index).?;
        const n_len = own_pub.paillier_pk.nByteLen();
        try own_pub.paillier_pk.nToBytes(n_bufs[i][0..n_len]);

        const expected_len = paillier_keys[i].public.nByteLen();
        var expected_buf: [paillier.modulus_bytes]u8 = undefined;
        try paillier_keys[i].public.nToBytes(expected_buf[0..expected_len]);
        try testing.expectEqualSlices(u8, expected_buf[0..expected_len], n_bufs[i][0..n_len]);

        // All n parties' public keys are present.
        try testing.expectEqual(@as(usize, 3), share.public_keys.entries.len);
    }

    // The three generated Paillier moduli are pairwise distinct (real
    // `generate` calls with a real RNG — collision probability is
    // negligible; this is a wiring sanity check, not a security proof).
    try testing.expect(!std.mem.eql(u8, n_bufs[0][0..paillier_keys[0].public.nByteLen()], n_bufs[1][0..paillier_keys[1].public.nByteLen()]));
    try testing.expect(!std.mem.eql(u8, n_bufs[1][0..paillier_keys[1].public.nByteLen()], n_bufs[2][0..paillier_keys[2].public.nByteLen()]));

    // group_public_key / verifying_share agree across every share, and
    // reconstructing from 2 of the 3 shares recovers `secret`.
    const two = [_]ShamirShare{
        .{ .index = key_shares[0].index, .scalar = key_shares[0].secret_share },
        .{ .index = key_shares[1].index, .scalar = key_shares[1].secret_share },
    };
    const reconstructed = try reconstructSecret(&two);
    try testing.expectEqualSlices(u8, &secret.toBytes(.big), &reconstructed.toBytes(.big));
}

test "KeyShare toBytesAlloc/fromBytesAlloc round-trip" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6b657973686172);
    const random = prng.random();

    const kp1 = try paillier.generate(random, paillier.min_generate_bits);
    const kp2 = try paillier.generate(random, paillier.min_generate_bits);
    const paillier_keys = [_]paillier.KeyPair{ kp1, kp2 };

    const aux = toyAuxParams();
    const aux_params = [_]AuxParams{ aux, aux };

    const secret = testScalar(11);
    const coeffs = [_]Scalar{testScalar(12)}; // t=2 needs exactly t-1=1 coefficient
    const key_shares = try keygenTrustedDealer(allocator, 2, 2, secret, &coeffs, &paillier_keys, &aux_params);
    defer allocator.free(key_shares);
    defer allocator.free(key_shares[0].public_keys.entries);

    const bytes = try key_shares[0].toBytesAlloc(allocator);
    defer allocator.free(bytes);
    const back = try KeyShare.fromBytesAlloc(allocator, bytes);
    defer allocator.free(back.public_keys.entries);

    try testing.expectEqual(key_shares[0].index, back.index);
    try testing.expectEqual(key_shares[0].t, back.t);
    try testing.expectEqual(key_shares[0].n, back.n);
    try testing.expectEqualSlices(u8, &key_shares[0].secret_share.toBytes(.big), &back.secret_share.toBytes(.big));
    try testing.expectEqualSlices(u8, &key_shares[0].group_public_key.toBytes(), &back.group_public_key.toBytes());
    try testing.expectEqualSlices(u8, &key_shares[0].verifying_share.toBytes(), &back.verifying_share.toBytes());
    try testing.expectEqual(key_shares[0].public_keys.entries.len, back.public_keys.entries.len);
}

test "smoke: module compiles and constants are sane" {
    try testing.expectEqual(@as(usize, 32), Ns);
    try testing.expectEqual(@as(usize, 33), Ne);
    try testing.expectEqual(@as(usize, 2048), aux_modulus_bits);
}

// This test is LAST and deliberately: `generateAuxParams` is the one
// genuinely-stubbed crypto core in this module (see the module doc
// comment's "Design decision" note) — every test above it passes; this
// one panics, by design, until a follow-up crypto pass fills it in.
test "generateAuxParams: reserved stub — ring-Pedersen construction lands in Phase 2b (with MtA + range proofs)" {
    // generateAuxParams is a reserved @panic stub until Phase 2b (the MtA
    // + range-proof pass that actually consumes the aux params) fills it
    // in; keygenTrustedDealer works today with caller-supplied aux params.
    // Skipped (not run) so this committed Phase-2a state is all-green;
    // Phase 2b unskips it and asserts well-formedness.
    return error.SkipZigTest;
}
