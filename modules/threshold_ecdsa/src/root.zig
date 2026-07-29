// SPDX-License-Identifier: MIT
//! threshold_ecdsa — GG20 threshold-ECDSA over secp256k1: **Phase 2a
//! (trusted-dealer keygen) + Phase 2b (ring-Pedersen aux params + the
//! semi-honest MtA core) + Phase 2c (GG18 Appendix A zero-knowledge MtA
//! range proofs + MtAwc, `zkproofs.zig`) + Phase 2d (GG20 online signing,
//! `signing.zig`)** — the full arc (2a keygen · 2b aux-params/MtA · 2c
//! range proofs + MtAwc · 2d signing) is implemented end to end. Depends
//! on the sibling `paillier` module: GG20's whole design hinges on every
//! party holding its own additively-homomorphic Paillier keypair — MtA
//! (`mta.zig`) is literally `paillier`'s homomorphic ops composed into a
//! multiplicative→additive share conversion.
//!
//! **Status: keygen + aux-params + MtA + range proofs + online signing are
//! all implemented (`signWithShares` genuinely produces a standard
//! secp256k1 ECDSA signature verifying under `std.crypto.sign.ecdsa
//! .EcdsaSecp256k1Sha256`).** One security layer remains a documented,
//! deliberate scope cut: GG20's identifiable-abort culprit-naming apparatus
//! (`signing.identifyAbortCulprit`) is `@panic`-stubbed — "abort-only v1"
//! never returns a bad signature but cannot name a culprit on abort; see
//! `signing.zig`'s module doc comment for the exact boundary. The
//! Shamir-secret-sharing + Feldman-VSS + Lagrange-interpolation core
//! (`splitSecretKey`, `groupPublicKey`, `derivePublicKeyShare`,
//! `reconstructSecret`) is a direct port of this repo's already-KAT-
//! validated `frost` (`deriveInterpolatingValue`) and `bls12_381.threshold`
//! (`evalPolynomialAt`/`feldmanCommitCoefficient`/`derivePublicKeyShare`)
//! constructions, swapped onto `std.crypto.ecc.Secp256k1`'s scalar field
//! and group. The Paillier-keygen wiring inside `keygenTrustedDealer`
//! (assembling each party's `paillier.KeyPair` into its `KeyShare`) is a
//! thin composition over `paillier.generate`/`fromPrimes`.
//!
//! `generateAuxParams` is now REAL: it derives the ring-Pedersen auxiliary
//! parameters (`N_tilde`, `h1`, `h2`) via a genuine safe-prime search
//! (p̃ = 2p'+1 with p' also prime — distinct from Paillier's plain
//! probable-prime search) and samples the secret exponent `lambda` from the
//! squares-subgroup order `p'·q'`; see its own doc comment for the
//! construction and the `lambda`-retention decision. `keygenTrustedDealer`
//! still takes `aux_params` as a CALLER-SUPPLIED slice (a caller generates
//! each party's tuple with `generateAuxParams` and passes them in), so the
//! keygen path stays independent of the — comparatively slow — safe-prime
//! search.
//!
//! MtA (`mta.zig`, re-exported as `mta`) is the semi-honest correctness core
//! of the share conversion: `α + β ≡ a·b (mod q)` with neither party
//! learning the other's input. Its malicious-security layer — the GG18
//! Appendix A zero-knowledge range proofs (which consume `AuxParams` as
//! their Pedersen commitment base) and the MtAwc check — is Phase 2c
//! (`zkproofs.zig`), IMPLEMENTED (verified against the paper) and wired
//! into `mta.zig`'s fail-closed `*Checked` entry points; the online signing
//! rounds are Phase 2d (`signing.zig`), also IMPLEMENTED — see that file's
//! module doc comment for the identifiable-abort scope cut.
//!
//! `AuxParams`' STRUCT and byte codec round-trip on hand-constructed toy
//! values too (see the tests at the bottom).
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

/// The MtA (multiplicative-to-additive) share-conversion protocol — I2
/// Phase 2b's semi-honest core. Converts a product `a·b` of two parties'
/// secret `Zq` inputs into an additive sharing `α + β ≡ a·b (mod q)`, built
/// on `paillier`'s homomorphic ops. See `mta.zig`'s doc comment for the
/// construction, the β sign convention, the Z_N→Zq reduction, and the
/// (Phase-2c) malicious-security boundary.
pub const mta = @import("mta.zig");

/// **Phase 2c** — the GG18 Appendix A zero-knowledge MtA range proofs
/// (`RangeProof`/`MtaProof`/`MtaProofWc` structs, the Fiat-Shamir
/// `Transcript`, and the `proveAliceRange`/`verifyAliceRange`/
/// `proveBobMta`/`verifyBobMta`/`proveBobMtaWc`/`verifyBobMtaWc` API) that
/// upgrade `mta`'s semi-honest core to malicious security. Structs,
/// codecs, the transcript, AND the prove/verify number theory are all REAL
/// (GG18 Appendix A.1/A.2/A.3, verified against the paper) — see
/// `zkproofs.zig`'s module doc comment for the full construction + the
/// verification-level caveat, and `mta.zig`'s `mtaAliceInitChecked`/
/// `mtaBobResponseChecked`/`mtaAliceFinalizeChecked` for how this wires
/// into the fail-closed checked-MtA flow.
pub const zkproofs = @import("zkproofs.zig");

/// **Phase 2d** — the GG20 online threshold-ECDSA SIGNING protocol: ties
/// keygen (this file) + MtA (`mta`) + the range proofs/MtAwc (`zkproofs`)
/// into a `t`-of-`n` signature that is a STANDARD secp256k1 ECDSA
/// signature, verifiable under `std.crypto.sign.ecdsa
/// .EcdsaSecp256k1Sha256` against `KeyShare.group_public_key`. Round
/// orchestration, the MtA/MtAwc wiring, and the signature arithmetic are
/// all REAL (`signWithShares` genuinely produces a verifying signature,
/// end to end); the GG20 identifiable-abort culprit-naming apparatus is a
/// documented, deliberate scope cut ("abort-only v1" — never returns a bad
/// signature, but cannot name a culprit on abort) — see `signing.zig`'s
/// module doc comment.
pub const signing = @import("signing.zig");

/// **Audit-F1 closure (IMPLEMENTED)** — the Πprm/Πmod zero-knowledge
/// proofs-of-correct-generation for `AuxParams` (CGGMP21 ePrint 2021/060
/// Fig.16/17): proves a ring-Pedersen tuple `(N_tilde, h1, h2)` is a
/// genuine Blum-integer setup (not just the structural floor
/// `AuxParams.validate` can check without the factorization). Struct/codec/
/// Fiat-Shamir-transcript wiring AND the two proof cores
/// (`Piprm.prove`/`.verify`, `Pimod.prove`/`.verify`) are all REAL;
/// `gate.aux_proofs_core_implemented` is flipped `true`, so the F1-soundness
/// KATs (a 3-prime `n_tilde` and an `h2 ∉ ⟨h1⟩` pair both REJECT while
/// `validate` still accepts them), completeness, and tamper tests all run —
/// see `aux_proofs.zig`'s module doc comment.
pub const aux_proofs = @import("aux_proofs.zig");

/// Module-local feature gate — see `gate.zig`'s own doc comment.
pub const gate = @import("gate.zig");

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation (no I/O of its own)
    // KeyShare/PublicKeys/AuxParams are plain value types (or thin
    // owned-slice wrappers) with no shared/global state — safe to use
    // from multiple threads as long as a given value isn't mutated
    // concurrently (nothing here ever mutates a value in place).
    .concurrency = .reentrant,
    .model_after = "R. Gennaro, S. Goldfeder, \"One Round Threshold ECDSA with Identifiable Abort\" (GG20, IACR ePrint 2020/540); R. Gennaro, S. Goldfeder, \"Fast Multiparty Threshold ECDSA with Fast Trustless Setup\" (GG18, IACR ePrint 2019/114) for the ring-Pedersen auxiliary-parameter construction; this repo's own `frost`/`bls12_381.threshold` modules for the Shamir+Feldman+Lagrange shape, ported onto std.crypto.ecc.Secp256k1's scalar field/group",
    // `paillier`: per-party additively-homomorphic keypairs.
    // `montint`: zkproofs.zig's constant-time Montgomery modexp over the
    // ring-Pedersen (Ñ, h1, h2) commitments -- wider than Paillier's own N².
    .deps = .{ "paillier", "montint" },
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

/// Byte length of a canonical `aux_modulus_bits`-wide value — the buffer
/// size the safe-prime search / modexp helpers below work in.
pub const aux_modulus_bytes = aux_modulus_bits / 8;

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

    pub const ValidateError = error{InvalidAuxParams};

    /// **Audit F1 + F2 — validate a RECEIVED counterparty aux tuple
    /// `(Ñ, h1, h2)` before using it as a range proof's Pedersen commitment
    /// base.** `fromBytesAlloc` only PARSES the tuple; nothing there checks
    /// it. Outside the trusted-dealer scope (i.e. the general checked-MtA
    /// API), a MALICIOUS verifier can broadcast a crafted `Ñ`/`h1`/`h2` whose
    /// group structure leaks the PROVER's secret witness through the Pedersen
    /// commitment `z = h1^m · h2^ρ mod Ñ` — the TSSHOCK / Alpha-Rays class.
    /// The checked-MtA / zkproofs PROVE entry points (`zkproofs
    /// .proveAliceRange`/`proveBobMta`/`proveBobMtaWc`) call this on the
    /// `verifier_aux` they are about to commit under, fail-closed.
    ///
    /// Checks enforced (`random` MUST be a real CSPRNG; the MR witnesses it
    /// draws are public):
    ///
    ///   - **F1 — Ñ composite.** A PRIME `Ñ` is rejected (its cyclic
    ///     known-order group would defeat the commitment's hiding). Reuses
    ///     this module's own Miller-Rabin (`isProbablePrime`); no new
    ///     primality impl. `Ñ` is ODD by construction (`std.crypto.ff
    ///     .Modulus` rejects even moduli). An honest two-prime `Ñ` fails MR on
    ///     the first witness — only a malicious prime pays the full round
    ///     count.
    ///   - **F1 — 1 < h1 < Ñ, 1 < h2 < Ñ.** The upper bound is guaranteed by
    ///     `AuxFe` canonicality; the degenerate `0`/`1` are rejected.
    ///   - **F1 — h1, h2 in the subgroup of squares mod Ñ.** The strongest
    ///     check cheaply available WITHOUT `Ñ`'s factorization is the Jacobi
    ///     symbol `(h/Ñ) == +1`. **Exact guarantee:** `+1` is a NECESSARY
    ///     condition for a quadratic residue and simultaneously proves
    ///     `gcd(h, Ñ) == 1` (the symbol is `0` iff `h` shares a factor with
    ///     `Ñ`, so the gcd check is subsumed). It is NOT sufficient — a value
    ///     that is a non-residue mod BOTH prime factors of `Ñ` also has
    ///     symbol `+1`. Closing that gap needs the party to PROVE correct
    ///     generation.
    ///   - **F2 — key-size floor, Ñ > q⁷.** Below this the GG18 `t1 <= q⁷`
    ///     range bound is vacuous (audit F2); see `nTildeMeetsFloor`.
    ///
    /// **TODO(Πprm/Πmod):** the full fix is a GG20/CMP zero-knowledge
    /// proof-of-correct-generation broadcast alongside the tuple (that `Ñ` is
    /// a product of two safe primes and `h2 = h1^λ` for a known `λ`) — the
    /// larger, deliberately-deferred item (`generateAuxParamsInternal`
    /// already returns the `λ` such a prover would need). This structural
    /// validation is the cheap, always-enforced floor beneath it, not a
    /// replacement.
    pub fn validate(self: AuxParams, random: std.Random) ValidateError!void {
        const nt = self.n_tilde;
        const one = nt.one();

        // F1: Ñ composite (reject a PRIME Ñ).
        if (isProbablePrime(nt, random)) return error.InvalidAuxParams;

        // F1: 1 < h1 < Ñ and 1 < h2 < Ñ.
        if (self.h1.isZero() or self.h1.eql(one)) return error.InvalidAuxParams;
        if (self.h2.isZero() or self.h2.eql(one)) return error.InvalidAuxParams;

        // F1: h1, h2 in the subgroup of squares mod Ñ (Jacobi == +1, which
        // also proves coprimality — see the doc comment's exact guarantee).
        var scratch: [aux_scratch_bytes]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&scratch);
        const gpa = fba.allocator();
        if (!auxFeJacobiIsOne(gpa, nt, self.h1)) return error.InvalidAuxParams;
        if (!auxFeJacobiIsOne(gpa, nt, self.h2)) return error.InvalidAuxParams;

        // F2: key-size floor Ñ > q⁷ (checked last — cheap structural checks
        // above catch most malformed tuples first).
        if (!nTildeMeetsFloor(nt)) return error.InvalidAuxParams;
    }
};

/// Recommended production floor for `generateAuxParams`'s `bits` — mirrors
/// `paillier.min_generate_bits` / `rsa`'s default modulus strength. A real
/// deployment uses `aux_modulus_bits` (2048). `generateAuxParams` itself
/// enforces only a much smaller *hard* minimum (so tests can exercise the
/// real number theory at a fast size); values below this constant are
/// cryptographically weak and only appropriate for testing.
pub const min_aux_generate_bits = 512;

/// Hard minimum `generateAuxParams` asserts — just large enough that the
/// safe-prime search / squares-subgroup arithmetic below is well-defined
/// (each prime is `bits/2` bits; `bits/2 >= 16` keeps the trial-division
/// sieve sound, i.e. a zero remainder always means a proper factor).
const min_aux_hard_bits = 32;

// ── ring-Pedersen number theory (safe-prime search + squares subgroup) ─────
//
// Distinct from `paillier.generatePrime`'s *plain* probable-prime search:
// here each prime p̃ must be a SAFE prime (p̃ = 2p' + 1 with p' also prime),
// so N_tilde = p̃·q̃ has a large-order group of squares whose order p'·q' we
// can sample the secret exponent `lambda` from. This is the genuine number
// theory the Phase-2a scaffold deferred; `AuxParams`' struct + codec were
// already real. Reuses the same Miller-Rabin / trial-sieve shape
// `paillier`/`rsa` establish (re-implemented locally — those are private to
// their modules), typed onto `AuxModulus`.

const BigInt = std.math.big.int.Managed;

/// Limb capacity covering an `aux_modulus_bits`-wide product plus headroom.
const aux_big_capacity = (2 * aux_modulus_bits) / @bitSizeOf(std.math.big.Limb) + 4;

/// Scratch arena for the one-time N_tilde = p̃·q̃ / ord = p'·q' big-int
/// derivations (not on any hot path). Matches `paillier`'s scratch sizing.
const aux_scratch_bytes = 128 * 1024;

fn newBig(gpa: std.mem.Allocator) !BigInt {
    return BigInt.initCapacity(gpa, aux_big_capacity);
}

fn bigFromBytes(gpa: std.mem.Allocator, bytes: []const u8) !BigInt {
    var x = try newBig(gpa);
    if (bytes.len == 0) {
        try x.set(0);
        return x;
    }
    try x.ensureCapacity(bytes.len / @sizeOf(std.math.big.Limb) + 2);
    var m = x.toMutable();
    m.readTwosComplement(bytes, bytes.len * 8, .big, .unsigned);
    x.setMetadata(m.positive, m.len);
    return x;
}

/// Odd primes below 1024 for the trial-division pre-sieve (comptime sieve of
/// Eratosthenes) — same construction as `paillier.sieve_primes`.
const sieve_primes = blk: {
    @setEvalBranchQuota(20_000);
    const limit = 1024;
    var composite = [_]bool{false} ** limit;
    var count: usize = 0;
    var i: usize = 3;
    while (i < limit) : (i += 2) {
        if (composite[i]) continue;
        count += 1;
        var j = i * i;
        while (j < limit) : (j += 2 * i) composite[j] = true;
    }
    var list: [count]u16 = undefined;
    var idx: usize = 0;
    i = 3;
    while (i < limit) : (i += 2) {
        if (composite[i]) continue;
        list[idx] = i;
        idx += 1;
    }
    break :blk list;
};

/// Miller-Rabin rounds per candidate — matches `paillier.mr_rounds`
/// (4^-64 = 2^-128 worst-case error per accepted candidate).
const aux_mr_rounds = 64;

/// Big-endian unsigned `bytes` mod `divisor` (u128 intermediate) —
/// pre-sieve only, mirrors `paillier.bytesMod`.
fn bytesMod(bytes: []const u8, divisor: u64) u64 {
    std.debug.assert(divisor != 0);
    var r: u64 = 0;
    for (bytes) |b| {
        r = @intCast(((@as(u128, r) << 8) | b) % divisor);
    }
    return r;
}

/// In-place big-endian right shift by `s` bits — mirrors `paillier.shrBytesBe`.
fn shrBytesBe(buf: []u8, s: usize) void {
    const byte_sh = s / 8;
    const bit_sh: u4 = @intCast(s % 8);
    var i: usize = buf.len;
    while (i > 0) {
        i -= 1;
        const lo: u16 = if (i >= byte_sh) buf[i - byte_sh] else 0;
        const hi: u16 = if (i >= byte_sh + 1) buf[i - byte_sh - 1] else 0;
        buf[i] = @truncate(((hi << 8) | lo) >> bit_sh);
    }
}

/// Set bit `bit` (LSB = 0) of a big-endian byte string.
fn setBitBe(buf: []u8, bit: usize) void {
    buf[buf.len - 1 - bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
}

/// Uniform Miller-Rabin witness in [2, m-2] by rejection sampling — mirrors
/// `paillier.randomWitness`, typed onto `AuxModulus`.
fn randomWitness(m: AuxModulus, random: std.Random) AuxFe {
    const n_bits = m.bits();
    const n_len = byteLen(n_bits);
    const n_minus_1 = m.sub(m.zero, m.one());
    var buf: [aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, buf[0..n_len]);
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const a = AuxFe.fromBytes(m, buf[0..n_len], .big) catch continue;
        if (a.isZero() or a.eql(m.one()) or a.eql(n_minus_1)) continue;
        return a;
    }
}

/// Miller-Rabin probable-prime test — mirrors `paillier.isProbablePrime`,
/// typed onto `AuxModulus`. `m` must be odd (every `AuxModulus` is).
fn isProbablePrime(m: AuxModulus, random: std.Random) bool {
    const n_len = byteLen(m.bits());

    var d_buf: [aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, d_buf[0..n_len]);
    m.toBytes(d_buf[0..n_len], .big) catch unreachable;
    d_buf[n_len - 1] &= 0xfe; // m - 1 (m odd)
    var s: usize = 0;
    var i: usize = n_len;
    while (i > 0) {
        i -= 1;
        if (d_buf[i] == 0) {
            s += 8;
        } else {
            s += @ctz(d_buf[i]);
            break;
        }
    }
    shrBytesBe(d_buf[0..n_len], s);
    const d_bytes = stripLeadingZeros(d_buf[0..n_len]);

    const one = m.one();
    const n_minus_1 = m.sub(m.zero, one);

    var round: usize = 0;
    rounds: while (round < aux_mr_rounds) : (round += 1) {
        const a = randomWitness(m, random);
        var x = m.powWithEncodedExponent(a, d_bytes, .big) catch unreachable; // d odd, never 0
        if (x.eql(one) or x.eql(n_minus_1)) continue :rounds;
        var j: usize = 1;
        while (j < s) : (j += 1) {
            x = m.sq(x);
            if (x.eql(n_minus_1)) continue :rounds;
            if (x.eql(one)) return false;
        }
        return false;
    }
    return true;
}

/// Search for a SAFE prime p̃ = 2p' + 1 (p' also prime) of exactly
/// `prime_bits` bits, top two bits set (so N_tilde = p̃·q̃ of two such
/// primes reaches `2·prime_bits` bits) and p̃ ≡ 3 (mod 4) (which forces
/// p' = (p̃-1)/2 odd, hence a valid `AuxModulus` to primality-test).
/// `out.len == byteLen(prime_bits)`. Variable-time (every prime search is);
/// candidate buffers are the caller's to zero.
fn generateSafePrime(random: std.Random, prime_bits: usize, out: []u8) void {
    std.debug.assert(out.len == byteLen(prime_bits));
    std.debug.assert(prime_bits >= 16);
    const top_mask = @as(u8, 0xff) >> @intCast(8 * out.len - prime_bits);
    var pprime_buf: [aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, pprime_buf[0..out.len]);
    candidates: while (true) {
        random.bytes(out);
        out[0] &= top_mask;
        setBitBe(out, prime_bits - 1); // exact bit length…
        setBitBe(out, prime_bits - 2); // …and p̃·q̃ >= 2^(2·prime_bits - 1)
        out[out.len - 1] |= 0x03; // p̃ ≡ 3 (mod 4): odd AND p' = (p̃-1)/2 odd

        // p' = (p̃ - 1) / 2, computed for the sieve + its own primality test.
        @memcpy(pprime_buf[0..out.len], out);
        pprime_buf[out.len - 1] &= 0xfe; // p̃ - 1
        shrBytesBe(pprime_buf[0..out.len], 1); // (p̃ - 1) / 2

        // Trial-division pre-sieve on BOTH p̃ and p' (a zero remainder is a
        // proper factor for either — both are >= 2^(prime_bits-2) ≫ 1024).
        for (sieve_primes) |sp| {
            if (bytesMod(out, sp) == 0) continue :candidates;
            if (bytesMod(pprime_buf[0..out.len], sp) == 0) continue :candidates;
        }

        const m_p = AuxModulus.fromBytes(out, .big) catch continue :candidates;
        if (!isProbablePrime(m_p, random)) continue :candidates;
        const m_pprime = AuxModulus.fromBytes(stripLeadingZeros(pprime_buf[0..out.len]), .big) catch continue :candidates;
        if (!isProbablePrime(m_pprime, random)) continue :candidates;
        return; // out holds a safe prime p̃
    }
}

/// Uniform nonzero `AuxFe` in [1, m) by rejection sampling (the base for
/// deriving a quadratic residue h1 = r²). Not secret (h1/N_tilde are public).
fn sampleNonzeroLtModulus(m: AuxModulus, random: std.Random) AuxFe {
    const n_bits = m.bits();
    const n_len = byteLen(n_bits);
    var buf: [aux_modulus_bytes]u8 = undefined;
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const r = AuxFe.fromBytes(m, buf[0..n_len], .big) catch continue;
        if (r.isZero()) continue;
        return r;
    }
}

/// The full ring-Pedersen generation, returning the secret discrete log
/// `lambda` (= log_{h1} h2) ALONGSIDE the public `AuxParams`.
/// `generateAuxParams` calls this and discards `lambda` (see its doc
/// comment's retention decision); this module's own test uses the returned
/// `lambda` to verify `h2 == h1^lambda`.
const AuxGen = struct {
    params: AuxParams,
    /// log_{h1} h2 ∈ [1, p'·q') — SECRET. Canonical mod `n_tilde`.
    lambda: AuxFe,
    /// Non-null only when `generateAuxParamsInternal` was called with a
    /// non-null `retain_allocator`: `p̃`/`q̃` (big-endian, owned by that
    /// allocator) — the two safe-prime factors of `n_tilde`. SECRET. See
    /// `generateAuxParamsWithTrapdoor`.
    p: ?[]const u8 = null,
    q: ?[]const u8 = null,
};

/// `retain_allocator`: when non-null, `p̃`/`q̃` are duplicated into
/// allocator-owned slices and returned via `AuxGen.p`/`.q` INSTEAD of being
/// discarded — the trapdoor `aux_proofs.zig`'s Πprm/Πmod provers need. When
/// null (the ordinary `generateAuxParams` path), behavior is unchanged: `p̃`/
/// `q̃` live only in stack buffers that get `secureZero`'d before return.
fn generateAuxParamsInternal(random: std.Random, bits: usize, retain_allocator: ?std.mem.Allocator) std.mem.Allocator.Error!AuxGen {
    std.debug.assert(bits % 2 == 0);
    std.debug.assert(bits >= min_aux_hard_bits);

    const prime_bits = bits / 2;
    const prime_len = byteLen(prime_bits);
    const n_len = byteLen(bits);

    // 1. Two distinct safe primes p̃ = 2p'+1, q̃ = 2q'+1.
    var p_buf: [aux_modulus_bytes]u8 = undefined;
    var q_buf: [aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, p_buf[0..prime_len]); // p̃ is secret-adjacent (reveals a factor)
    defer std.crypto.secureZero(u8, q_buf[0..prime_len]);
    generateSafePrime(random, prime_bits, p_buf[0..prime_len]);
    while (true) {
        generateSafePrime(random, prime_bits, q_buf[0..prime_len]);
        if (!std.mem.eql(u8, p_buf[0..prime_len], q_buf[0..prime_len])) break;
    }

    // Retain p̃/q̃ for the caller BEFORE any further processing — the trapdoor
    // a Πprm/Πmod prover needs (see `generateAuxParamsWithTrapdoor`). The
    // stack copies above are still `secureZero`'d on return regardless.
    var ret_p: ?[]const u8 = null;
    errdefer if (ret_p) |rp| retain_allocator.?.free(rp);
    var ret_q: ?[]const u8 = null;
    if (retain_allocator) |gpa2| {
        ret_p = try gpa2.dupe(u8, p_buf[0..prime_len]);
        ret_q = try gpa2.dupe(u8, q_buf[0..prime_len]);
    }

    // p' = (p̃-1)/2, q' = (q̃-1)/2 — the squares-subgroup order is p'·q'.
    var pp_buf: [aux_modulus_bytes]u8 = undefined;
    var qp_buf: [aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, pp_buf[0..prime_len]);
    defer std.crypto.secureZero(u8, qp_buf[0..prime_len]);
    @memcpy(pp_buf[0..prime_len], p_buf[0..prime_len]);
    @memcpy(qp_buf[0..prime_len], q_buf[0..prime_len]);
    pp_buf[prime_len - 1] &= 0xfe;
    qp_buf[prime_len - 1] &= 0xfe;
    shrBytesBe(pp_buf[0..prime_len], 1);
    shrBytesBe(qp_buf[0..prime_len], 1);

    // 2. N_tilde = p̃·q̃ and 4. ord = p'·q' (big-int; a one-time derivation).
    var scratch: [aux_scratch_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();

    var bp = bigFromBytes(gpa, p_buf[0..prime_len]) catch unreachable;
    var bq = bigFromBytes(gpa, q_buf[0..prime_len]) catch unreachable;
    var bn = newBig(gpa) catch unreachable;
    bn.mul(&bp, &bq) catch unreachable;
    var n_buf: [aux_modulus_bytes]u8 = undefined;
    bn.toConst().writeTwosComplement(n_buf[0..n_len], .big);
    const n_tilde = AuxModulus.fromBytes(stripLeadingZeros(n_buf[0..n_len]), .big) catch unreachable;

    var bpp = bigFromBytes(gpa, stripLeadingZeros(pp_buf[0..prime_len])) catch unreachable;
    var bqp = bigFromBytes(gpa, stripLeadingZeros(qp_buf[0..prime_len])) catch unreachable;
    var b_ord = newBig(gpa) catch unreachable;
    b_ord.mul(&bpp, &bqp) catch unreachable; // ord = p'·q'
    const ord_bits = b_ord.bitCountAbs();
    const ord_len = byteLen(ord_bits);

    // 3. h1 = r² mod N_tilde — a random element of the group of squares.
    const one = n_tilde.one();
    var h1: AuxFe = undefined;
    while (true) {
        const r = sampleNonzeroLtModulus(n_tilde, random);
        const cand = n_tilde.sq(r);
        if (!cand.isZero() and !cand.eql(one)) {
            h1 = cand;
            break;
        }
    }

    // 4. lambda ← [1, ord) uniformly (SECRET). Rejection-sample against ord.
    var lam_buf: [aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, lam_buf[0..ord_len]);
    const lam_top_mask = @as(u8, 0xff) >> @intCast(8 * ord_len - ord_bits);
    const lambda_fe: AuxFe = blk: {
        while (true) {
            random.bytes(lam_buf[0..ord_len]);
            lam_buf[0] &= lam_top_mask;
            var cand = bigFromBytes(gpa, lam_buf[0..ord_len]) catch unreachable;
            if (cand.eqlZero()) continue; // lambda != 0
            if (cand.order(b_ord) != .lt) continue; // lambda < ord
            // lambda < ord < N_tilde ⇒ canonical mod n_tilde.
            break :blk AuxFe.fromBytes(n_tilde, stripLeadingZeros(lam_buf[0..ord_len]), .big) catch unreachable;
        }
    };

    // 5. h2 = h1^lambda mod N_tilde (constant-time modexp; lambda is secret).
    const h2 = n_tilde.pow(h1, lambda_fe) catch unreachable; // lambda != 0

    return .{ .params = .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 }, .lambda = lambda_fe, .p = ret_p, .q = ret_q };
}

/// The trapdoor behind a ring-Pedersen `AuxParams` tuple: the two safe-prime
/// factors `p̃`, `q̃` of `n_tilde` and the secret exponent `lambda = log_{h1}
/// h2`. SECRET — as sensitive as any other private-key material. Needed by
/// `aux_proofs.Piprm.prove`/`aux_proofs.Pimod.prove` (the Πprm/Πmod
/// proofs-of-correct-generation that close audit F1 for real, on top of the
/// structural floor `AuxParams.validate` already enforces) to PROVE this
/// tuple is well-formed — see `generateAuxParamsWithTrapdoor`.
pub const AuxTrapdoor = struct {
    /// `p̃` (big-endian, owned — free via `deinit`). SECRET.
    p: []const u8,
    /// `q̃` (big-endian, owned — free via `deinit`). SECRET.
    q: []const u8,
    /// `log_{h1} h2 mod p'·q'`, canonical mod `n_tilde`. SECRET.
    lambda: AuxFe,

    pub fn deinit(self: AuxTrapdoor, allocator: std.mem.Allocator) void {
        allocator.free(self.p);
        allocator.free(self.q);
    }
};

pub const AuxParamsWithTrapdoor = struct {
    params: AuxParams,
    trapdoor: AuxTrapdoor,
};

/// Like `generateAuxParams`, but ALSO retains the trapdoor
/// (`p̃`/`q̃`/`lambda`) a Πprm/Πmod prover needs — see `AuxTrapdoor`'s doc
/// comment. `generateAuxParams` itself is UNCHANGED (still discards the
/// trapdoor; most callers only ever act as a proof VERIFIER under their own
/// tuple, per its own doc comment's "λ-retention decision"). A caller that
/// intends to broadcast a proof-of-correct-generation alongside its
/// `AuxParams` calls this variant instead.
///
/// Caller owns the returned `AuxTrapdoor` — free with
/// `result.trapdoor.deinit(allocator)`, and handle it with the same care as
/// any other private-key material (SECRET, zero/free promptly after use).
/// `random` MUST be cryptographically secure for real parameters; `bits`
/// constraints are identical to `generateAuxParams`.
pub fn generateAuxParamsWithTrapdoor(allocator: std.mem.Allocator, random: std.Random, bits: usize) std.mem.Allocator.Error!AuxParamsWithTrapdoor {
    const gen = try generateAuxParamsInternal(random, bits, allocator);
    return .{
        .params = gen.params,
        .trapdoor = .{ .p = gen.p.?, .q = gen.q.?, .lambda = gen.lambda },
    };
}

/// Generate ring-Pedersen auxiliary parameters `(N_tilde, h1, h2)` for ONE
/// party (GG18 §4.1's "aux info" generation, which GG20 reuses for its range
/// proofs — facts about the widely-used construction only, no source
/// consulted, see NOTICE).
///
/// Construction:
///
/// ```text
/// 1. Draw two distinct SAFE primes p̃ = 2p'+1, q̃ = 2q'+1, each bits/2
///    bits, with p', q' also prime (generateSafePrime: the paillier/rsa
///    probable-prime search shape + an extra Miller-Rabin pass on
///    (candidate-1)/2, and a p̃ ≡ 3 (mod 4) filter so p' is odd).
/// 2. N_tilde = p̃ · q̃.
/// 3. h1 = r² mod N_tilde for a random r — a uniform element of N_tilde's
///    group of quadratic residues (order p'·q').
/// 4. lambda ← [1, p'·q') uniformly, the secret exponent.
/// 5. h2 = h1^lambda mod N_tilde (constant-time modexp).
/// ```
///
/// **λ-retention decision: `lambda` is DISCARDED here** — `AuxParams` holds
/// only the public `(N_tilde, h1, h2)`, and only those are broadcast. In
/// GG18/GG20 the tuple belongs to this party acting as the *verifier* of
/// range proofs about OTHER parties' Paillier plaintexts; soundness (binding
/// of the Pedersen commitment) requires the *prover* — i.e. every other
/// party — not to know `lambda = log_{h1} h2`, and this party never acts as
/// a prover under its own tuple, so retaining `lambda` buys nothing and only
/// widens the secret's exposure. It is therefore zeroed with the rest of the
/// safe-prime material before return. **TODO(2c):** if a later phase adds
/// the ZK proof of *correct aux-param generation* (a "Πprm"/"Πmod"-style
/// proof that `h2 = h1^lambda` for a known `lambda`, which some GG20/CMP
/// variants broadcast alongside the tuple), that proof's PROVER step needs
/// `lambda` retained during setup — expose it then via
/// `generateAuxParamsInternal` (which already returns it) rather than
/// discarding. This Phase-2b pass produces no such proof.
///
/// `random` MUST be cryptographically secure for real parameters. `bits`
/// must be even and >= `min_aux_hard_bits`; a real deployment uses
/// `aux_modulus_bits` (`min_aux_generate_bits`+ is the recommended-strength
/// floor). Expect a slow safe-prime search as `bits` grows (safe primes are
/// rarer than ordinary primes).
///
/// **Const-time:** the safe-prime *search* is inherently variable-time (how
/// long it took reveals nothing about the primes kept); the secret exponent
/// `lambda`'s use in `h2 = h1^lambda mod N_tilde` is the constant-time
/// `AuxModulus.pow`, mirroring `paillier.fromPrimes`'s `g^lambda mod n²`
/// step. All secret buffers are `secureZero`'d.
pub fn generateAuxParams(random: std.Random, bits: usize) AuxParams {
    const gen = generateAuxParamsInternal(random, bits, null) catch unreachable; // retain_allocator == null never allocates
    // lambda (gen.lambda) is a stack AuxFe, discarded with this frame; its
    // byte-level source buffer is already secureZero'd inside the internal
    // routine. See the λ-retention decision above.
    return gen.params;
}

// ── received-aux-param validation (audit F1) + key-size floor (audit F2) ──
//
// The number theory `AuxParams.validate` (above) leans on: the audit-F2
// key-size floor `q⁷` and a factorization-free Jacobi-symbol quadratic-
// residue test. `q_int`/`comptimeIntBytes` mirror `zkproofs.zig`'s own
// comptime `q`-power constants; the Jacobi routine reuses this file's
// `std.math.big.int` scratch helpers (`newBig`/`bigFromBytes`).

const q_int = Secp256k1.scalar.field_order;

/// Big-endian fixed-width encoding of a comptime integer (mirrors
/// `zkproofs.zig`'s identically-named private helper).
fn comptimeIntBytes(comptime len: usize, comptime value: comptime_int) [len]u8 {
    var out: [len]u8 = undefined;
    var v = value;
    var i: usize = len;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(v & 0xff);
        v >>= 8;
    }
    if (v != 0) @compileError("comptimeIntBytes: value does not fit in len bytes");
    return out;
}

/// `q⁷` (224 big-endian bytes) — the audit-F2 key-size floor. Every RECEIVED
/// Paillier `N` and ring-Pedersen `Ñ` on the checked-MtA / zkproofs path must
/// STRICTLY EXCEED this, or the GG18 `t1 <= q⁷` range bound is vacuous (a
/// modulus `<= q⁷` can never make that check bite, so the range proof stops
/// constraining Bob's additive blind `β'` at all). `q⁷ ≈ 2^1792`, so a
/// modulus clears the floor iff it is (a hair over) 1792 bits — any real
/// ≥2048-bit key clears it with room to spare, a 1024-bit key never does.
pub const key_size_floor_bytes = comptimeIntBytes(224, q_int * q_int * q_int * q_int * q_int * q_int * q_int);

/// Unsigned big-endian comparison (leading zeros ignored).
fn intCompareBytes(a_in: []const u8, b_in: []const u8) std.math.Order {
    const a = stripLeadingZeros(a_in);
    const b = stripLeadingZeros(b_in);
    if (a.len != b.len) return if (a.len < b.len) .lt else .gt;
    return std.mem.order(u8, a, b);
}

/// Audit-F2 floor test for a ring-Pedersen `Ñ`: `Ñ > q⁷`.
pub fn nTildeMeetsFloor(nt: AuxModulus) bool {
    var buf: [aux_modulus_bytes]u8 = undefined;
    nt.toBytes(&buf, .big) catch return false;
    return intCompareBytes(&buf, &key_size_floor_bytes) == .gt;
}

/// Audit-F2 floor test for a RECEIVED Paillier modulus `N`: `N > q⁷`. Used by
/// the checked-MtA / zkproofs prove+verify entry points so the `s1 <= q³` /
/// `t1 <= q⁷` range bounds are never vacuous.
pub fn paillierNMeetsFloor(pk: paillier.PublicKey) bool {
    var buf: [paillier.modulus_bytes]u8 = undefined;
    const n_len = pk.nByteLen();
    pk.nToBytes(buf[0..n_len]) catch return false;
    return intCompareBytes(buf[0..n_len], &key_size_floor_bytes) == .gt;
}

/// **Audit F3 — the RECEIVED Paillier generator must be the standard
/// `Γ = N+1`.** GG18 Appendix A's range/MtA proofs are statements about a
/// ciphertext `c = Γ^m · r^N mod N²`, and every one of their soundness
/// arguments assumes `Γ` generates a subgroup of order exactly `N` (that is
/// what makes `m` well-defined mod `N` at all). A counterparty-supplied
/// `Γ` of SMALLER order — `Γ = 1` being the extreme case — collapses the
/// plaintext space the proof is about: verification equation 2
/// (`u · c^e == Γ^{s1} · s^N`) stops tying `s1` to anything, so the `s1 <= q³`
/// range bound in equation 1 is left constraining a value that no longer
/// relates to the ciphertext's plaintext. Binding `Γ` into the Fiat-Shamir
/// transcript (see `zkproofs.Transcript.appendPaillierPublicKey`) removes the
/// prover's freedom to CHANGE `Γ` after seeing the challenge; this predicate
/// removes the freedom to choose a degenerate `Γ` in the first place. Both
/// are needed — the transcript binding is the general Fiat-Shamir-completeness
/// fix, this is the structural precondition underneath it.
///
/// Every key this repo's `paillier.generate`/`fromPrimes` produces has
/// `g = n+1` (`standardGenerator`), so this rejects only keys deliberately
/// hand-built with an explicit non-standard `g` — which on the checked path
/// is exactly the adversarial case. Not imposed on the generic
/// `PublicKeys`/`KeyShare` byte codecs (they parse arbitrary wire values, the
/// same posture the F2 floor takes).
pub fn paillierGeneratorIsStandard(pk: paillier.PublicKey) bool {
    var n_buf: [paillier.modulus_bytes]u8 = undefined;
    const n_len = pk.nByteLen();
    pk.nToBytes(n_buf[0..n_len]) catch return false;
    const n_fe = paillier.Fe.fromBytes(pk.n_sq, n_buf[0..n_len], .big) catch return false;
    const g_std = pk.n_sq.add(n_fe, pk.n_sq.one());
    // Byte-exact comparison (sidesteps ff's internal Montgomery-form flag,
    // same rationale as `zkproofs.zig`'s `pailFeEql`).
    var got: [paillier.modulus_sq_bytes]u8 = undefined;
    pk.g.toBytes(&got, .big) catch return false;
    var want: [paillier.modulus_sq_bytes]u8 = undefined;
    g_std.toBytes(&want, .big) catch return false;
    return std.mem.eql(u8, &got, &want);
}

/// Jacobi symbol `(a / n)` for odd `n > 0` (standard reciprocity algorithm
/// over `std.math.big.int`). Returns `-1`, `0`, or `+1`; `0` exactly when
/// `gcd(a, n) > 1`. Variable-time — applied only to PUBLIC received aux
/// params during `AuxParams.validate`.
fn jacobiSymbol(gpa: std.mem.Allocator, a_in: *const BigInt, n_in: *const BigInt) !i8 {
    var a = try newBig(gpa);
    var n = try newBig(gpa);
    var quot = try newBig(gpa);
    var rem = try newBig(gpa);
    var tmp = try newBig(gpa);
    try a.copy(a_in.toConst());
    try n.copy(n_in.toConst());

    // a := a mod n
    try quot.divFloor(&rem, &a, &n);
    a.swap(&rem);

    var result: i8 = 1;
    while (!a.eqlZero()) {
        // Strip factors of two, flipping per (2/n) = (-1)^((n²-1)/8) — i.e.
        // flip whenever n ≡ 3 or 5 (mod 8). `a` is nonzero here (outer
        // guard), so its odd part is ≥ 1 and limbs[0] is always in range.
        while ((a.toConst().limbs[0] & 1) == 0) {
            try tmp.shiftRight(&a, 1);
            a.swap(&tmp);
            const n8 = n.toConst().limbs[0] & 7;
            if (n8 == 3 or n8 == 5) result = -result;
        }
        // Quadratic reciprocity: swap, flipping when a ≡ n ≡ 3 (mod 4).
        a.swap(&n);
        if ((a.toConst().limbs[0] & 3) == 3 and (n.toConst().limbs[0] & 3) == 3) result = -result;
        try quot.divFloor(&rem, &a, &n);
        a.swap(&rem);
    }
    if (n.toConst().orderAgainstScalar(1) == .eq) return result;
    return 0; // gcd(a, n) > 1
}

/// True iff `(h / Ñ) == +1`: the cheapest sound check (no factorization of
/// `Ñ`) that `h` lies in the subgroup of squares mod `Ñ`. Fail-closed on any
/// encoding/allocation error (returns false). See `AuxParams.validate` for
/// the exact guarantee.
fn auxFeJacobiIsOne(gpa: std.mem.Allocator, nt: AuxModulus, h: AuxFe) bool {
    var h_buf: [aux_modulus_bytes]u8 = undefined;
    h.toBytes(&h_buf, .big) catch return false;
    var nt_buf: [aux_modulus_bytes]u8 = undefined;
    nt.toBytes(&nt_buf, .big) catch return false;
    var ha = bigFromBytes(gpa, stripLeadingZeros(&h_buf)) catch return false;
    var na = bigFromBytes(gpa, stripLeadingZeros(&nt_buf)) catch return false;
    const j = jacobiSymbol(gpa, &ha, &na) catch return false;
    return j == 1;
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
        // BUG FIX (unbounded allocation): `count` is attacker-controlled and
        // was previously handed straight to `allocator.alloc` with no check
        // that `bytes` could possibly back that many entries -- a 4-byte
        // message with count = 0xFFFFFFFF forced a ~29 TB allocation
        // attempt (sizeOf(PartyPublicKeys) is ~6.8 KB; verified at a safe
        // scale that count=200_000 alone already peaks ~1.3 GB RSS for a
        // 4-byte input). Every entry needs at least 16 bytes on the wire
        // (index(4) + 3 length-prefixes(4 each), even before any of the
        // length-prefixed payloads), so reject a `count` the remaining
        // bytes could not possibly satisfy BEFORE allocating -- the same
        // bound `FeldmanCommitments.fromBytesAlloc` above already enforces
        // for its own (fixed-size-element) count.
        const min_entry_bytes = 16;
        if ((bytes.len - 4) / min_entry_bytes < count) return error.InvalidEncoding;
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

// Pull the `mta` submodule's tests into this module's test binary — a bare
// `pub const mta = @import(...)` re-export does NOT (the dark-tests rule,
// CONVENTIONS.md §6).
test {
    _ = mta;
}

// generateAuxParams is now IMPLEMENTED (Phase 2b) — this test asserts the
// ring-Pedersen tuple is well-formed at a small, fast bit size, and (via the
// internal generator that also returns the secret exponent) that
// h2 = h1^lambda actually holds.
test "generateAuxParams: ring-Pedersen tuple is well-formed (N_tilde composite/odd/right-size, h1/h2 in range, h2 = h1^lambda)" {
    var prng = std.Random.DefaultPrng.init(0x617578706172616d); // "auxparam"
    const random = prng.random();

    // Small test size for speed: 128-bit N_tilde = two 64-bit safe primes.
    // (min_aux_generate_bits=2048-class is the production strength; the real
    // safe-prime number theory is exercised here at a fast size.)
    const bits: usize = 128;
    const gen = generateAuxParamsInternal(random, bits, null) catch unreachable;
    const aux = gen.params;

    // N_tilde: right bit length (product of two `bits/2`-bit primes with top
    // two bits set lands on `bits` or `bits-1` bits) and ODD (every Modulus).
    const nb = aux.n_tilde.bits();
    try testing.expect(nb == bits or nb == bits - 1);
    try testing.expect((try aux.n_tilde.v.toPrimitive(u128)) & 1 == 1);

    // N_tilde is COMPOSITE (it is p̃·q̃): Miller-Rabin must reject it.
    try testing.expect(!isProbablePrime(aux.n_tilde, random));

    // h1, h2 in range [2, N_tilde): nonzero, not one, canonical (fromBytes
    // already guarantees < N_tilde).
    const one = aux.n_tilde.one();
    try testing.expect(!aux.h1.isZero() and !aux.h1.eql(one));
    try testing.expect(!aux.h2.isZero() and !aux.h2.eql(one));

    // The load-bearing relation: h2 == h1^lambda mod N_tilde.
    const h2_check = try aux.n_tilde.pow(aux.h1, gen.lambda);
    try testing.expect(h2_check.eql(aux.h2));

    // The public wrapper produces an equally well-formed (independent) tuple
    // and it round-trips through the byte codec.
    const pub_aux = generateAuxParams(random, bits);
    try testing.expect(!isProbablePrime(pub_aux.n_tilde, random));
    const bytes = try pub_aux.toBytesAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    const back = try AuxParams.fromBytesAlloc(bytes);
    try testing.expect(pub_aux.n_tilde.v.eql(back.n_tilde.v));
    try testing.expect(pub_aux.h1.eql(back.h1));
    try testing.expect(pub_aux.h2.eql(back.h2));
}

test "jacobiSymbol matches known small values" {
    var scratch: [aux_scratch_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();

    const Case = struct { a: u64, n: u64, want: i8 };
    const cases = [_]Case{
        .{ .a = 1, .n = 3, .want = 1 },
        .{ .a = 2, .n = 7, .want = 1 }, // 2 is a QR mod 7
        .{ .a = 3, .n = 7, .want = -1 }, // 3 is a non-residue mod 7
        .{ .a = 2, .n = 15, .want = 1 }, // 15 ≡ -1 (mod 8)
        .{ .a = 7, .n = 15, .want = -1 },
        .{ .a = 3, .n = 15, .want = 0 }, // gcd(3,15) = 3
        .{ .a = 4, .n = 187, .want = 1 }, // a perfect square: coprime + QR
        .{ .a = 5, .n = 187, .want = -1 },
        .{ .a = 16, .n = 187, .want = 1 },
    };
    for (cases) |c| {
        var a = try newBig(gpa);
        try a.set(c.a);
        var n = try newBig(gpa);
        try n.set(c.n);
        try testing.expectEqual(c.want, try jacobiSymbol(gpa, &a, &n));
    }
}

test "AuxParams.validate accepts a well-formed tuple and rejects malformed / sub-floor ones (audit F1/F2)" {
    var prng = std.Random.DefaultPrng.init(0x76616c6964617465); // "validate"
    const random = prng.random();

    // A genuine ~2000-bit ODD COMPOSITE (product of two odd ~1000-bit values,
    // computed at comptime) with h1 = 4 = 2², h2 = 16 = 4² — both perfect
    // squares (hence Jacobi +1 and coprime to the odd Ñ). This tuple PASSES:
    // composite, in-range square-subgroup generators, Ñ > q⁷.
    const big_composite = comptime comptimeIntBytes(256, ((1 << 1000) + 9) * ((1 << 1000) + 15));
    const nt_ok = AuxModulus.fromBytes(stripLeadingZeros(&big_composite), .big) catch unreachable;
    const good: AuxParams = .{
        .n_tilde = nt_ok,
        .h1 = AuxFe.fromBytes(nt_ok, &[_]u8{4}, .big) catch unreachable,
        .h2 = AuxFe.fromBytes(nt_ok, &[_]u8{16}, .big) catch unreachable,
    };
    try good.validate(random); // accepts

    // F1 — Ñ PRIME (251): the Miller-Rabin composite check rejects.
    {
        const nt = AuxModulus.fromBytes(&[_]u8{251}, .big) catch unreachable;
        const bad: AuxParams = .{
            .n_tilde = nt,
            .h1 = AuxFe.fromBytes(nt, &[_]u8{2}, .big) catch unreachable,
            .h2 = AuxFe.fromBytes(nt, &[_]u8{4}, .big) catch unreachable,
        };
        try testing.expectError(error.InvalidAuxParams, bad.validate(random));
    }
    // F1 — h1 out of range (h1 = 1) on the otherwise-valid large Ñ.
    {
        const bad: AuxParams = .{ .n_tilde = nt_ok, .h1 = nt_ok.one(), .h2 = good.h2 };
        try testing.expectError(error.InvalidAuxParams, bad.validate(random));
    }
    // F1 — h2 out of range (h2 = 0).
    {
        const bad: AuxParams = .{ .n_tilde = nt_ok, .h1 = good.h1, .h2 = nt_ok.zero };
        try testing.expectError(error.InvalidAuxParams, bad.validate(random));
    }
    // F1 — h1 not in the square subgroup: (5/187) = -1 (also would catch a
    // shared small factor, which yields Jacobi 0).
    {
        const nt = AuxModulus.fromBytes(&[_]u8{187}, .big) catch unreachable;
        const bad: AuxParams = .{
            .n_tilde = nt,
            .h1 = AuxFe.fromBytes(nt, &[_]u8{5}, .big) catch unreachable,
            .h2 = AuxFe.fromBytes(nt, &[_]u8{4}, .big) catch unreachable,
        };
        try testing.expectError(error.InvalidAuxParams, bad.validate(random));
    }
    // F2 — sub-floor Ñ (187 ≪ q⁷) with structurally-valid QR generators
    // (h1 = 4, h2 = 16): the key-size floor is the check that fires.
    {
        const nt = AuxModulus.fromBytes(&[_]u8{187}, .big) catch unreachable;
        const bad: AuxParams = .{
            .n_tilde = nt,
            .h1 = AuxFe.fromBytes(nt, &[_]u8{4}, .big) catch unreachable,
            .h2 = AuxFe.fromBytes(nt, &[_]u8{16}, .big) catch unreachable,
        };
        try testing.expectError(error.InvalidAuxParams, bad.validate(random));
    }

    // The F2 floor predicates in isolation.
    try testing.expect(nTildeMeetsFloor(nt_ok));
    try testing.expect(!nTildeMeetsFloor(AuxModulus.fromBytes(&[_]u8{187}, .big) catch unreachable));
}

// Pull the `zkproofs` submodule's tests into this module's test binary —
// same dark-tests rule as `test { _ = mta; }` above. As of the Phase-2c
// implementation pass the six prove/verify functions are REAL (GG18
// Appendix A.1/A.2/A.3, verified against the paper), so all of
// `zkproofs.zig`'s tests pass — nothing here panics any more.
test {
    _ = zkproofs;
}

// Pull the `signing` submodule's tests into this module's test binary —
// same dark-tests rule. Phase 2d's `signWithShares` is REAL end to end
// (its decisive std-ECDSA-verify test PASSES, does not panic); only
// `identifyAbortCulprit` (not exercised by any test — it always panics by
// design) represents deferred work. See `signing.zig`'s module doc comment.
test {
    _ = signing;
}

// Pull the `aux_proofs` submodule's tests into this module's test binary —
// same dark-tests rule. `gate.aux_proofs_core_implemented` is now `true`, so
// every test runs for real: the struct/codec/Fiat-Shamir-transcript tests
// plus the proof-core-dependent tests (both F1-soundness rejections,
// completeness, and the tamper suite). See `aux_proofs.zig`'s module doc
// comment.
test {
    _ = aux_proofs;
}

test "generateAuxParamsWithTrapdoor: retains p̃/q̃/lambda; p̃*q̃ == n_tilde and h2 == h1^lambda" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x747261706400); // "trapd\0"
    const random = prng.random();

    const bits: usize = 128;
    const gen = try generateAuxParamsWithTrapdoor(allocator, random, bits);
    defer gen.trapdoor.deinit(allocator);

    // p̃, q̃ nonzero and distinct.
    try testing.expect(gen.trapdoor.p.len > 0 and gen.trapdoor.q.len > 0);
    try testing.expect(!std.mem.eql(u8, gen.trapdoor.p, gen.trapdoor.q));

    // p̃ * q̃ == n_tilde (big-int check, same scratch-arena idiom the rest of
    // this file uses).
    var scratch: [aux_scratch_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();
    var bp = bigFromBytes(gpa, gen.trapdoor.p) catch unreachable;
    var bq = bigFromBytes(gpa, gen.trapdoor.q) catch unreachable;
    var bn = newBig(gpa) catch unreachable;
    bn.mul(&bp, &bq) catch unreachable;
    var n_buf: [aux_modulus_bytes]u8 = undefined;
    gen.params.n_tilde.toBytes(&n_buf, .big) catch unreachable;
    const expected_n = bigFromBytes(gpa, stripLeadingZeros(&n_buf)) catch unreachable;
    try testing.expect(bn.order(expected_n) == .eq);

    // h2 == h1^lambda mod n_tilde — same load-bearing relation the ungated
    // `generateAuxParams` test checks via the internal `lambda`.
    const h2_check = try gen.params.n_tilde.pow(gen.params.h1, gen.trapdoor.lambda);
    try testing.expect(h2_check.eql(gen.params.h2));
}

// ── fuzz: the length-prefixed / counted wire codecs never panic or ───────
// over-allocate on arbitrary attacker-supplied bytes ─────────────────────
//
// `FeldmanCommitments`/`PublicKeys`/`AuxParams` are exactly the shape this
// pass is watching hardest for: a `u32`-BE count or length read straight
// from the wire and used to size an allocation or a loop BEFORE the rest
// of the buffer is known to actually hold that much data (`PSBT`-map /
// `TLV`-stream territory, per the module's own doc comments citing
// `bls12_381.threshold.VerificationVector`'s length-prefixed idiom).
//
// **A real bug of exactly this shape was found and fixed while writing
// this harness**: `PublicKeys.fromBytesAlloc` read its `u32`-BE `count`
// and called `allocator.alloc(PartyPublicKeys, count)` *before* checking
// that `bytes` could possibly back that many entries — a 4-byte message
// with `count = 0xFFFFFFFF` forced a ~29 TB allocation attempt
// (`sizeOf(PartyPublicKeys)` is ~6.8 KB; verified at a safe scale that
// `count = 200_000` alone already peaks ~1.3 GB RSS for a 4-byte input).
// Fixed by rejecting a `count` the remaining bytes could not possibly
// satisfy before allocating (mirroring `FeldmanCommitments.fromBytesAlloc`,
// which already had the analogous `expected_len` check). This harness
// guards against a regression of that exact class, alongside
// `FeldmanCommitments`/`AuxParams`'s own counted/length-prefixed fields.
test "fuzz: FeldmanCommitments.fromBytesAlloc never panics or over-allocates" {
    try testing.fuzz({}, fuzzFeldmanCommitmentsFromBytesAlloc, .{});
}

fn fuzzFeldmanCommitmentsFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    // Bias the count toward both small-real values and the
    // maximum-u32/near-buffer-size boundary -- the two ends of the
    // "could this possibly be backed by real data" check.
    const count: u32 = switch (smith.valueRangeAtMost(u8, 0, 2)) {
        0 => smith.valueRangeAtMost(u8, 0, 5),
        1 => std.math.maxInt(u32),
        else => smith.value(u32),
    };
    var count_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &count_buf, count, .big);
    buf.appendSlice(allocator, &count_buf) catch return;

    var tail: [128]u8 = undefined;
    smith.bytes(&tail);
    const tail_len: usize = smith.valueRangeAtMost(u8, 0, tail.len);
    buf.appendSlice(allocator, tail[0..tail_len]) catch return;

    const result = FeldmanCommitments.fromBytesAlloc(allocator, buf.items) catch return;
    defer allocator.free(result.commitments);
}

test "fuzz: PublicKeys.fromBytesAlloc never panics or over-allocates" {
    try testing.fuzz({}, fuzzPublicKeysFromBytesAlloc, .{});
}

fn fuzzPublicKeysFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    // Same three-way count bias as the FeldmanCommitments harness above --
    // this is the exact field the fixed bug lived in.
    const count: u32 = switch (smith.valueRangeAtMost(u8, 0, 2)) {
        0 => smith.valueRangeAtMost(u8, 0, 3),
        1 => std.math.maxInt(u32),
        else => smith.value(u32),
    };
    var count_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &count_buf, count, .big);
    buf.appendSlice(allocator, &count_buf) catch return;

    var tail: [256]u8 = undefined;
    smith.bytes(&tail);
    const tail_len: usize = smith.valueRangeAtMost(u16, 0, tail.len);
    buf.appendSlice(allocator, tail[0..tail_len]) catch return;

    const result = PublicKeys.fromBytesAlloc(allocator, buf.items) catch return;
    defer allocator.free(result.entries);
}

test "fuzz: AuxParams.fromBytesAlloc never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzAuxParamsFromBytesAlloc, .{});
}

fn fuzzAuxParamsFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);

    // Three independent len-prefixed fields (n_tilde/h1/h2) -- bias each
    // length toward small-real and near-buffer-boundary values so
    // `readLenPrefixed`'s own bound check gets real traffic both ways.
    var i: u8 = 0;
    while (i < 3) : (i += 1) {
        var field_buf: [64]u8 = undefined;
        smith.bytes(&field_buf);
        const field_len: usize = smith.valueRangeAtMost(u8, 0, field_buf.len);
        var len_buf: [4]u8 = undefined;
        const declared_len: u32 = if (smith.value(bool))
            @intCast(field_len) // honest length
        else
            smith.value(u32); // lying length
        std.mem.writeInt(u32, &len_buf, declared_len, .big);
        buf.appendSlice(testing.allocator, &len_buf) catch return;
        buf.appendSlice(testing.allocator, field_buf[0..field_len]) catch return;
    }

    _ = AuxParams.fromBytesAlloc(buf.items) catch return;
}
