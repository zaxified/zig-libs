// SPDX-License-Identifier: MIT
//! threshold_ecdsa — GG20 threshold-ECDSA over secp256k1: trusted-dealer
//! keygen (this file), ring-Pedersen aux params, MtA (`mta.zig`), the GG18
//! Appendix A range proofs + MtAwc (`zkproofs.zig`), and GG20 signing as a
//! per-signer state machine (`presign.zig`: Phases 1–6 → a `Presignature`,
//! then one online round) with identifiable abort, driven in-process by
//! `signing.signWithShares`. Depends on the sibling `paillier` module: GG20's
//! whole design hinges on every party holding its own additively-homomorphic
//! Paillier keypair — MtA is `paillier`'s homomorphic ops composed into a
//! multiplicative→additive share conversion.
//!
//! **Status:** every signer can run in its own process (`presign.Party`,
//! message in → message out); every check of GG20 §3.2 is made, and every
//! abort names its culprit except the paper's types 5 and 7, which need its
//! §4.3 opening protocol (not implemented). The output is a standard
//! secp256k1 ECDSA signature verifying under `std.crypto.sign.ecdsa
//! .EcdsaSecp256k1Sha256`. The
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
const montint = @import("montint");
const burn = @import("burn.zig");

// Dead-stack burns of the secret entry points (`burn.zig`), each a little
// above the depth its body reached in `stackprobe_test.zig` (ReleaseFast,
// x86_64, 2026-10-08; `verbose = true` prints the depths). The probe asserts
// that no secret survives, which a body outgrowing its burn would break.
const keygen_trusted_dealer_stack_burn = 64 * 1024;

// Dead-stack burns of the secret entry points (`burn.zig`), each a little
// above the depth its body reached in `stackprobe_test.zig` (ReleaseFast,
// x86_64, 2026-10-08; `verbose = true` prints the depths). The probe asserts
// that no secret survives, which a body outgrowing its burn would break.
const split_secret_key_stack_burn = 16 * 1024;
const reconstruct_secret_stack_burn = 4 * 1024;
const paillier_blum_from_primes_stack_burn = 256 * 1024;
const generate_paillier_blum_stack_burn = 256 * 1024;
const aux_log_inverse_stack_burn = 40 * 1024;
const aux_params_with_trapdoor_from_safe_primes_stack_burn = 128 * 1024;
const generate_aux_params_with_trapdoor_stack_burn = 128 * 1024;
const generate_aux_params_stack_burn = 128 * 1024;
const message_public_key_stack_burn = 8 * 1024;
const key_share_to_bytes_stack_burn = 32 * 1024;
const key_share_from_bytes_stack_burn = 256 * 1024;

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

/// The in-process driver `signWithShares` (one `presign.Party` per share,
/// messages routed by a loop) and `lagrangeCoefficient`. See `signing.zig`.
pub const signing = @import("signing.zig");

/// GG20 signing as one state machine per signer: `Party` (Phases 1–6,
/// message in → message out), `Presignature` (one online round, used once),
/// `PresignaturePublic.combine` (checks every share, names a bad one). See
/// `presign.zig`'s module doc comment for the rounds and the caller's duties.
pub const presign = @import("presign.zig");

/// The curve-only Sigma proofs of GG20 §3.3 (`T_i`, `S_i`/`T_i`, `Γ_i`) and
/// the NUMS Pedersen generator `H`.
pub const ecproofs = @import("ecproofs.zig");

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

/// Πfac (CGGMP21 Fig.28): a party's Paillier `N` has no small factor —
/// proven per verifier under the verifier's ring-Pedersen tuple. With
/// `aux_proofs.Pimod.provePaillier` it is what dealer-free keygen needs
/// before anyone runs MtA against a key it did not generate.
pub const fac_proof = @import("fac_proof.zig");

/// Dealer-free keygen, Paillier/ring-Pedersen half: per-party generation,
/// the broadcast with its proofs, Πfac per peer, and `KeyShare` assembly
/// from a DKG's output (the sibling `dkg` module runs the whole protocol).
pub const aux_info = @import("aux_info.zig");

/// Module-local feature gate — see `gate.zig`'s own doc comment.
pub const gate = @import("gate.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "GG20 threshold ECDSA over secp256k1 (t-of-n) — dealer keygen, per-signer presigning state machine with identifiable abort, one-round online signing; standard verifiable ECDSA sigs. **Audit warranted before production use.**",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
    // Subtractions, not `offset + len`: a u32 length added to a usize offset
    // wraps on 32-bit targets and would pass the bound.
    if (bytes.len - offset.* < 4) return error.InvalidEncoding;
    const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
    offset.* += 4;
    if (bytes.len - offset.* < len) return error.InvalidEncoding;
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
    secret_key: *const Scalar,
    t: u32,
    n: u32,
    coefficients: []const Scalar,
) SplitError!SplitResult {
    const result = splitSecretKeyUnburned(allocator, secret_key, t, n, coefficients);
    burn.stack(split_secret_key_stack_burn);
    return result;
}

noinline fn splitSecretKeyUnburned(
    allocator: std.mem.Allocator,
    secret_key: *const Scalar,
    t: u32,
    n: u32,
    coefficients: []const Scalar,
) SplitError!SplitResult {
    return splitSecretKeyByValue(allocator, secret_key.*, t, n, coefficients);
}

fn splitSecretKeyByValue(
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
pub fn reconstructSecret(shares: []const ShamirShare, out: *Scalar) ReconstructError!void {
    const result = reconstructSecretUnburned(shares, out);
    burn.stack(reconstruct_secret_stack_burn);
    return result;
}

noinline fn reconstructSecretUnburned(shares: []const ShamirShare, out: *Scalar) ReconstructError!void {
    out.* = try reconstructSecretByValue(shares);
}

fn reconstructSecretByValue(shares: []const ShamirShare) ReconstructError!Scalar {
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
/// squares, with `h1 = h2^lambda mod N_tilde` for a secret `lambda` known
/// only to the generating party (so `h1 ∈ ⟨h2⟩`: the commitment
/// `h1^x·h2^ρ` hides `x` because its randomness base generates the message
/// base). Phase-2b/2c ZK range proofs (proving a
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
    /// a product of two safe primes and `h1 = h2^λ` for a known `λ`) — the
    /// larger, deliberately-deferred item (`generateAuxParamsInternal`
    /// already returns the `λ` such a prover would need). This structural
    /// validation is the cheap, always-enforced floor beneath it, not a
    /// replacement.
    pub fn validate(self: AuxParams, random: std.Random) ValidateError!void {
        const nt = self.n_tilde;
        const one = nt.one();

        // F1: Ñ composite (reject a PRIME Ñ).
        if (isProbablePrime(nt, nt.bits(), random)) return error.InvalidAuxParams;

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

        // Audit F1 (2026-09-10 fix, user decision: cheap floor now, Πprm/
        // Πmod deferred as a separate task): reject a generator of ORDER 2.
        // `h2 = Ñ-1` slips past every check above whenever Ñ ≡ 1 (mod 4)
        // (e.g. both prime factors ≡ 3 mod 4, which `generateSafePrime`
        // always produces) -- Jacobi(-1/Ñ) = (-1)^((Ñ-1)/2) = +1 there, and
        // -1 is trivially never 0 or 1. An order-2 h2 collapses the Pedersen
        // commitment's hiding: z = h1^m * h2^rho mod Ñ gives
        // z^2 = h1^(2m) * h2^(2rho) = h1^(2m) (the blinding `rho` cancels
        // out via h2^2 == 1), so z^2 becomes a DETERMINISTIC function of the
        // witness `m` alone -- confirmed by mutation: `z^2` came back
        // byte-identical across three independent `rho` draws for the same
        // witness, byte-DIFFERENT for a different witness (see
        // `AuxParams.validate` order-2 tests below). Symmetric check on h1
        // too: an order-2 h1 analogously collapses z^2 down to a function of
        // `rho` alone. This is the "cheap, always-enforced floor" the doc
        // comment above already promised, not the full Πprm/Πmod
        // proof-of-correct-generation (SPEC.md A6, TODO) -- it closes the
        // MAXIMUM of the residual gap that floor can reach without one.
        if (nt.sq(self.h1).eql(one) or nt.sq(self.h2).eql(one)) return error.InvalidAuxParams;

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

/// `⌊2^32 / p⌋` for every sieve prime — the reciprocals `bytesModCt`
/// multiplies by instead of dividing.
const sieve_recips = blk: {
    var out: [sieve_primes.len]u64 = undefined;
    for (sieve_primes, &out) |sp, *m| m.* = (@as(u64, 1) << 32) / sp;
    break :blk out;
};

/// Big-endian unsigned `bytes` mod `d` (`d < 2^10`, `m = ⌊2^32/d⌋`) without
/// a division: per byte `x = 256·r + b < 2^18`, `q = ⌊x·m / 2^32⌋` is the
/// true quotient or one less (the error is `< x / 2^32 < 1`), and one masked
/// subtraction fixes the remainder. Constant time in the bytes: a hardware
/// or compiler-rt division takes value-dependent time, and the sieve runs
/// on the secret candidate that ends up being the prime (2026-10-03; was
/// `u128 % u64`).
fn bytesModCt(bytes: []const u8, d: u64, m: u64) u64 {
    var r: u64 = 0;
    for (bytes) |b| {
        const x = (r << 8) | b;
        const q = (x * m) >> 32;
        const rr = x - q * d; // in [0, 2d)
        const ge = 1 -% ((rr -% d) >> 63); // 1 iff rr >= d
        r = rr - (d & (0 -% ge));
    }
    return r;
}

/// True when some sieve prime divides the big-endian `candidate`. Every
/// remainder is computed (`bytesModCt`) and the zero flags are OR-ed, so the
/// one branch is the verdict — a candidate that survives (the secret prime)
/// takes the same path as every other survivor. `pub` for the ctgrind
/// harness (target `prime`).
pub fn sieveRejects(candidate: []const u8) bool {
    var hit: u64 = 0;
    for (sieve_primes, sieve_recips) |sp, m| {
        const r = bytesModCt(candidate, sp, m);
        hit |= (r -% 1) >> 63; // 1 iff r == 0 (r < 2^10)
    }
    return montint.nt.blackBox(hit) != 0;
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

/// Miller-Rabin probable-prime test. `m` must be odd (every `AuxModulus` is)
/// and exactly `n_bits` bits long — the length the caller already knows (a
/// prime search's target size), so the test never scans the secret value
/// for it; any other `m` is reported composite. `pub` for the ctgrind
/// harness (target `prime`).
///
/// Constant-time in `m`'s value along the path a PRIME takes: this runs on
/// the secret candidates of `generateSafePrime`/`generateBlumPrime`. Since
/// 2026-10-03 it is `montint.DynModint.isProbablePrime` (the recipe this
/// function introduced on 2026-10-02, moved into montint so `rsa` and
/// `paillier` share it): montint ladder modulo the secret `m`, witnesses
/// below `2^(bits−1)` (no compare against `m`), `m − 1 = d·2^s` by masked
/// shifts, a round's verdicts OR-ed before the one branch. Variable-time
/// still: the squaring count `s` (`= 1` for every candidate here, all
/// `≡ 3 mod 4`). The callers' sieve is `sieveRejects` (constant-time since
/// 2026-10-03) and they test bytes directly (`isProbablePrimeBE`).
pub fn isProbablePrime(m: AuxModulus, n_bits: usize, random: std.Random) bool {
    const D = montint.DynModint(aux_modulus_bits);
    var mv = D.elemFromFf(&m.v);
    defer std.crypto.secureZero(u64, &mv);
    return isProbablePrimeLimbs(&mv, n_bits, random);
}

/// `isProbablePrime` straight from big-endian bytes — the prime searches'
/// path: no detour through `AuxModulus.fromBytes` (ff), which is not
/// constant-time in the value it parses.
pub fn isProbablePrimeBE(m: []const u8, n_bits: usize, random: std.Random) bool {
    const D = montint.DynModint(aux_modulus_bits);
    var mv = D.loadBE(m) catch return false;
    defer std.crypto.secureZero(u64, &mv);
    return isProbablePrimeLimbs(&mv, n_bits, random);
}

fn isProbablePrimeLimbs(mv: *const montint.DynModint(aux_modulus_bits).Elem, n_bits: usize, random: std.Random) bool {
    const D = montint.DynModint(aux_modulus_bits);
    var mc = D.fromLimbsBits(mv, n_bits) catch return false;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mc));
    return mc.isProbablePrime(random, aux_mr_rounds);
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
        if (sieveRejects(out) or sieveRejects(pprime_buf[0..out.len])) continue :candidates;

        if (!isProbablePrimeBE(out, prime_bits, random)) continue :candidates;
        if (!isProbablePrimeBE(pprime_buf[0..out.len], prime_bits - 1, random)) continue :candidates;
        return; // out holds a safe prime p̃
    }
}

/// Search for a Blum prime `p ≡ 3 (mod 4)` of exactly `prime_bits` bits, top
/// two bits set — the Paillier half of dealer-free keygen. Πmod needs both
/// factors ≡ 3 (mod 4); a SAFE prime is not required there (CGGMP21 asks for
/// a Paillier-Blum modulus), and a Blum prime is found as fast as any prime.
/// Variable-time like every prime search; `out` is the caller's to zero.
fn generateBlumPrime(random: std.Random, prime_bits: usize, out: []u8) void {
    std.debug.assert(out.len == byteLen(prime_bits));
    std.debug.assert(prime_bits >= 16);
    const top_mask = @as(u8, 0xff) >> @intCast(8 * out.len - prime_bits);
    candidates: while (true) {
        random.bytes(out);
        out[0] &= top_mask;
        setBitBe(out, prime_bits - 1);
        setBitBe(out, prime_bits - 2);
        out[out.len - 1] |= 0x03; // ≡ 3 (mod 4)
        if (sieveRejects(out)) continue :candidates;
        if (isProbablePrimeBE(out, prime_bits, random)) return;
    }
}

/// Largest Paillier prime `generatePaillierBlum` produces (half of
/// `aux_modulus_bits`, the widest modulus Πmod/Πfac take).
pub const paillier_blum_prime_bytes = aux_modulus_bytes / 2;

/// A party's own Paillier key for dealer-free keygen, WITH its factors: the
/// prover of `aux_proofs.Pimod.provePaillier` and `fac_proof.prove` needs
/// them, and nothing else does. `p`/`q` are SECRET — `wipe` when done.
pub const PaillierBlumKey = struct {
    key: paillier.KeyPair,
    p_buf: [paillier_blum_prime_bytes]u8,
    q_buf: [paillier_blum_prime_bytes]u8,
    prime_len: usize,

    pub fn p(self: *const PaillierBlumKey) []const u8 {
        return self.p_buf[0..self.prime_len];
    }

    pub fn q(self: *const PaillierBlumKey) []const u8 {
        return self.q_buf[0..self.prime_len];
    }

    /// `N` as the `AuxModulus` the proofs run over.
    pub fn modulus(self: *const PaillierBlumKey) AuxModulus {
        return paillierModulusAsAux(self.key.public) orelse unreachable; // bits <= aux_modulus_bits by construction
    }

    /// Zeroes the factors AND the Paillier secret key (λ, μ and the CRT
    /// block are factorization-equivalent). The public key stays readable.
    pub fn wipe(self: *PaillierBlumKey) void {
        std.crypto.secureZero(u8, &self.p_buf);
        std.crypto.secureZero(u8, &self.q_buf);
        self.key.secret.deinit();
    }
};

pub const GeneratePaillierBlumError = paillier.FromPrimesError || error{InvalidBits};

/// Generate a Paillier key `N = p·q` of exactly `bits` bits with
/// `p ≡ q ≡ 3 (mod 4)` (a Paillier-Blum modulus), keeping `p`, `q`. `bits`
/// must be a multiple of 16 (whole-byte primes, so the closeness guard sees
/// the real top 100 bits), at least `paillier.min_modulus_bits`, at most
/// `aux_modulus_bits`; a real key is `paillier.modulus_bits` (2048). The two
/// primes are refused when their top 100 bits coincide (Fermat closeness, as
/// `paillier.generate` does). `random` MUST be a CSPRNG for real keys.
pub fn generatePaillierBlum(random: std.Random, bits: usize, out: *PaillierBlumKey) GeneratePaillierBlumError!void {
    const result = generatePaillierBlumUnburned(random, bits, out);
    burn.stack(generate_paillier_blum_stack_burn);
    return result;
}

noinline fn generatePaillierBlumUnburned(random: std.Random, bits: usize, out: *PaillierBlumKey) GeneratePaillierBlumError!void {
    out.* = try generatePaillierBlumByValue(random, bits);
}

fn generatePaillierBlumByValue(random: std.Random, bits: usize) GeneratePaillierBlumError!PaillierBlumKey {
    if (bits % 16 != 0 or bits < paillier.min_modulus_bits or bits > aux_modulus_bits) return error.InvalidBits;
    const half = bits / 2;
    var out: PaillierBlumKey = undefined;
    out.prime_len = byteLen(half);
    errdefer {
        std.crypto.secureZero(u8, &out.p_buf);
        std.crypto.secureZero(u8, &out.q_buf);
    }
    const p_bytes = out.p_buf[0..out.prime_len];
    const q_bytes = out.q_buf[0..out.prime_len];
    while (true) {
        generateBlumPrime(random, half, p_bytes);
        while (true) {
            generateBlumPrime(random, half, q_bytes);
            if (!topHundredBitsMatch(p_bytes, q_bytes)) break;
        }
        paillier.fromPrimes(p_bytes, q_bytes, &out.key) catch |err| switch (err) {
            error.InvalidPrimes => continue, // a Miller-Rabin false positive: search again
            else => return err,
        };
        return out;
    }
}

pub const PaillierBlumFromPrimesError = paillier.FromPrimesError || error{NotBlum};

/// A `PaillierBlumKey` from factors the caller already has (precomputed
/// primes, as tss-lib's "pre-params" are; or test vectors). Both must be
/// ≡ 3 (mod 4) and at most `paillier_blum_prime_bytes` long;
/// `paillier.fromPrimes` checks primality and closeness.
pub fn paillierBlumFromPrimes(p_in: []const u8, q_in: []const u8, out: *PaillierBlumKey) PaillierBlumFromPrimesError!void {
    const result = paillierBlumFromPrimesUnburned(p_in, q_in, out);
    burn.stack(paillier_blum_from_primes_stack_burn);
    return result;
}

noinline fn paillierBlumFromPrimesUnburned(p_in: []const u8, q_in: []const u8, out: *PaillierBlumKey) PaillierBlumFromPrimesError!void {
    out.* = try paillierBlumFromPrimesByValue(p_in, q_in);
}

fn paillierBlumFromPrimesByValue(p_in: []const u8, q_in: []const u8) PaillierBlumFromPrimesError!PaillierBlumKey {
    const p_bytes = stripLeadingZeros(p_in);
    const q_bytes = stripLeadingZeros(q_in);
    const len = @max(p_bytes.len, q_bytes.len);
    if (p_bytes.len == 0 or q_bytes.len == 0 or len > paillier_blum_prime_bytes) return error.InvalidPrimes;
    if (p_bytes[p_bytes.len - 1] & 3 != 3 or q_bytes[q_bytes.len - 1] & 3 != 3) return error.NotBlum;
    var out: PaillierBlumKey = undefined;
    out.prime_len = len;
    errdefer {
        std.crypto.secureZero(u8, &out.p_buf);
        std.crypto.secureZero(u8, &out.q_buf);
    }
    @memset(&out.p_buf, 0);
    @memset(&out.q_buf, 0);
    @memcpy(out.p_buf[len - p_bytes.len .. len], p_bytes);
    @memcpy(out.q_buf[len - q_bytes.len .. len], q_bytes);
    try paillier.fromPrimes(p_bytes, q_bytes, &out.key);
    if (paillierModulusAsAux(out.key.public) == null) return error.InvalidPrimes;
    return out;
}

/// FIPS 186-5 §A.1.3 closeness guard over the top 100 bits (same rule as
/// `paillier.generate`; its helper is private there).
fn topHundredBitsMatch(a: []const u8, b: []const u8) bool {
    std.debug.assert(a.len == b.len and a.len >= 13);
    if (!std.mem.eql(u8, a[0..12], b[0..12])) return false;
    return (a[12] ^ b[12]) & 0xf0 == 0;
}

/// A Paillier `N` as an `AuxModulus` — the type Πmod/Πfac are written over.
/// `null` when `N` is wider than `aux_modulus_bits` (no such key can be
/// proven here) or not a valid modulus.
pub fn paillierModulusAsAux(pk: paillier.PublicKey) ?AuxModulus {
    var buf: [paillier.modulus_bytes]u8 = undefined;
    const len = pk.nByteLen();
    if (len > aux_modulus_bytes) return null;
    pk.nToBytes(buf[0..len]) catch return null;
    return AuxModulus.fromBytes(buf[0..len], .big) catch null;
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
/// `lambda` (= log_{h2} h1) ALONGSIDE the public `AuxParams`.
/// `generateAuxParams` calls this and discards `lambda` (see its doc
/// comment's retention decision); this module's own test uses the returned
/// `lambda` to verify `h1 == h2^lambda`.
const AuxGen = struct {
    params: AuxParams,
    /// log_{h2} h1 ∈ [1, p'·q') — SECRET. Canonical mod `n_tilde`.
    lambda: AuxFe,
    /// Non-null only when `generateAuxParamsInternal` was called with a
    /// non-null `retain_allocator`: `p̃`/`q̃` (big-endian, owned by that
    /// allocator) — the two safe-prime factors of `n_tilde`. SECRET. See
    /// `generateAuxParamsWithTrapdoor`.
    p: ?[]const u8 = null,
    q: ?[]const u8 = null,
};

/// Little-endian limbs → big-endian bytes, `out.len` bytes (the low ones).
fn limbsToBE(l: []const u64, out: []u8) void {
    for (out, 0..) |*b, i| {
        const pos = out.len - 1 - i;
        b.* = if (pos / 8 < l.len) @truncate(l[pos / 8] >> @intCast(8 * (pos % 8))) else 0;
    }
}

/// `x >>= 1` over little-endian limbs (no branch on the values).
fn shrLimbs1(x: []u64) void {
    for (x, 0..) |*w, i| {
        const hi: u64 = if (i + 1 < x.len) x[i + 1] << 63 else 0;
        w.* = (w.* >> 1) | hi;
    }
}

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

    const d = deriveAuxFromSafePrimes(p_buf[0..prime_len], q_buf[0..prime_len], bits, random);
    return .{ .params = d.params, .lambda = d.lambda, .p = ret_p, .q = ret_q };
}

/// Steps 2–5 of `generateAuxParams` over the caller's safe primes
/// `p̃`, `q̃` (big-endian, `bits / 2` bits each): `N_tilde`, `h2`, `λ`,
/// `h1`. Constant-time in `p̃`, `q̃` and `λ` up to the λ draw's accept
/// verdict (ctgrind target `auxgen`).
fn deriveAuxFromSafePrimes(p_be: []const u8, q_be: []const u8, bits: usize, random: std.Random) struct { params: AuxParams, lambda: AuxFe } {
    const n_len = byteLen(bits);
    // 2. N_tilde = p̃·q̃ and ord = p'·q' (p' = (p̃−1)/2, q' = (q̃−1)/2, the
    //    squares-subgroup order) on montint limbs: the primes are SECRET and
    //    nothing below branches on them (until 2026-10-03 this was
    //    std.math.big.int, and the λ rejection loop compared against ord
    //    with a big-int `order`).
    const D = montint.DynModint(aux_modulus_bits);
    var p_l = D.loadBE(p_be) catch unreachable; // ≤ aux_modulus_bytes
    defer std.crypto.secureZero(u64, &p_l);
    var q_l = D.loadBE(q_be) catch unreachable;
    defer std.crypto.secureZero(u64, &q_l);
    var prod: [2 * D.max_limbs]u64 = undefined;
    defer std.crypto.secureZero(u64, &prod);
    montint.limbs.mulSchoolbook(&prod, &p_l, &q_l);
    var n_buf: [aux_modulus_bytes]u8 = undefined;
    limbsToBE(prod[0..D.max_limbs], n_buf[0..n_len]);
    const n_tilde = AuxModulus.fromBytes(stripLeadingZeros(n_buf[0..n_len]), .big) catch unreachable;

    // p̃, q̃ are odd: (p̃−1)/2 = p̃ >> 1.
    shrLimbs1(&p_l);
    shrLimbs1(&q_l);
    montint.limbs.mulSchoolbook(&prod, &p_l, &q_l);
    var ord: D.Elem = prod[0..D.max_limbs].*;
    defer std.crypto.secureZero(u64, &ord);

    // 3. h2 = r² mod N_tilde — a random element of the group of squares.
    //    h2 is the base the commitment's RANDOMNESS rides on (`h1^x·h2^ρ`),
    //    so it is the one drawn uniformly and h1 is derived from it in step
    //    5: Πprm then proves h1 ∈ ⟨h2⟩, the direction hiding needs.
    const one = n_tilde.one();
    var h2: AuxFe = undefined;
    while (true) {
        const r = sampleNonzeroLtModulus(n_tilde, random);
        const cand = n_tilde.sq(r);
        if (!cand.isZero() and !cand.eql(one)) {
            h2 = cand;
            break;
        }
    }

    // 4. lambda ← [1, ord) uniformly (SECRET). Draws below the PUBLIC bound
    //    2^(bits−2) (ord has bits−2 or bits−3 bits, so a draw is kept with
    //    probability ≥ 1/4), kept when the borrow of λ − ord says λ < ord and
    //    λ ≠ 0 — the accept verdict is the only branch.
    const draw_bits = bits - 2;
    const draw_len = byteLen(draw_bits);
    var lam_buf: [aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, lam_buf[0..draw_len]);
    const lam_top_mask = @as(u8, 0xff) >> @intCast(8 * draw_len - draw_bits);
    var lam_l: D.Elem = undefined;
    defer std.crypto.secureZero(u64, &lam_l);
    while (true) {
        random.bytes(lam_buf[0..draw_len]);
        lam_buf[0] &= lam_top_mask;
        lam_l = D.loadBE(lam_buf[0..draw_len]) catch unreachable;
        var t = lam_l;
        defer std.crypto.secureZero(u64, &t);
        const below = montint.limbs.subInto(&t, &ord);
        var nz: u64 = 0;
        for (lam_l) |w| nz |= w;
        const nonzero: u1 = @intFromBool(nz != 0);
        if (below & nonzero == 1) break;
    }
    // lambda < ord < N_tilde ⇒ canonical mod n_tilde.
    const lambda_fe = D.elemToFf(AuxFe, n_tilde, &lam_l);

    // 5. h1 = h2^lambda mod N_tilde (constant-time modexp; lambda is secret —
    // montint via `zkproofs.powSecret`, not ff's pow, which branches on the
    // exponent's windows once LLVM has optimised it).
    var lam_bytes: [aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &lam_bytes);
    lambda_fe.toBytes(&lam_bytes, .big) catch unreachable;
    const h1 = zkproofs.powSecret(n_tilde, h2, &lam_bytes);

    return .{ .params = .{ .n_tilde = n_tilde, .h1 = h1, .h2 = h2 }, .lambda = lambda_fe };
}

/// The trapdoor behind a ring-Pedersen `AuxParams` tuple: the two safe-prime
/// factors `p̃`, `q̃` of `n_tilde` and the secret exponent `lambda = log_{h2}
/// h1` (CGGMP21's `s = t^λ` with `s := h1`, `t := h2`). SECRET — as sensitive as any other private-key material. Needed by
/// `aux_proofs.Piprm.prove`/`aux_proofs.Pimod.prove` (the Πprm/Πmod
/// proofs-of-correct-generation that close audit F1 for real, on top of the
/// structural floor `AuxParams.validate` already enforces) to PROVE this
/// tuple is well-formed — see `generateAuxParamsWithTrapdoor`.
pub const AuxTrapdoor = struct {
    /// `p̃` (big-endian, owned — free via `deinit`). SECRET.
    p: []const u8,
    /// `q̃` (big-endian, owned — free via `deinit`). SECRET.
    q: []const u8,
    /// `log_{h2} h1 mod p'·q'`, canonical mod `n_tilde`. SECRET. Until
    /// 2026-10-03 this was `log_{h1} h2` and Πprm proved the wrong
    /// direction (see `aux_proofs.Piprm`).
    lambda: AuxFe,

    pub fn deinit(self: AuxTrapdoor, allocator: std.mem.Allocator) void {
        allocator.free(self.p);
        allocator.free(self.q);
    }
};

/// `x⁻¹ mod p'·q'` for the safe primes `p̃ = 2p'+1`, `q̃ = 2q'+1` of
/// `n_tilde` (big-endian) — the trapdoor converted between this module's
/// `log_{h2} h1` and tss-lib's `LocalPreParams.Alpha = log_{h1} h2`, either
/// way (the two are inverse mod the squares' order `p'·q'`). For interop
/// tooling and fixtures; constant-time like `montint.DynModint.inverse`.
pub fn auxLogInverse(n_tilde: AuxModulus, p_safe: []const u8, q_safe: []const u8, x: *const AuxFe, out: *AuxFe) error{ NotInvertible, InvalidTrapdoor }!void {
    const result = auxLogInverseUnburned(n_tilde, p_safe, q_safe, x, out);
    burn.stack(aux_log_inverse_stack_burn);
    return result;
}

noinline fn auxLogInverseUnburned(n_tilde: AuxModulus, p_safe: []const u8, q_safe: []const u8, x: *const AuxFe, out: *AuxFe) error{ NotInvertible, InvalidTrapdoor }!void {
    out.* = try auxLogInverseByValue(n_tilde, p_safe, q_safe, x.*);
}

fn auxLogInverseByValue(n_tilde: AuxModulus, p_safe: []const u8, q_safe: []const u8, x: AuxFe) error{ NotInvertible, InvalidTrapdoor }!AuxFe {
    const D = montint.DynModint(aux_modulus_bits);
    var pp = D.loadBE(p_safe) catch return error.InvalidTrapdoor;
    defer std.crypto.secureZero(u64, &pp);
    var qp = D.loadBE(q_safe) catch return error.InvalidTrapdoor;
    defer std.crypto.secureZero(u64, &qp);
    for ([_]*D.Elem{ &pp, &qp }) |v| { // p' = (p̃ − 1)/2 = p̃ >> 1, p̃ odd
        for (v, 0..) |*limb, i| limb.* = (limb.* >> 1) | if (i + 1 < v.len) v[i + 1] << 63 else 0;
    }
    var prod: [2 * D.max_limbs]u64 = undefined;
    defer std.crypto.secureZero(u64, &prod);
    montint.limbs.mulSchoolbook(&prod, &pp, &qp);
    for (prod[D.max_limbs..]) |hi| if (hi != 0) return error.InvalidTrapdoor;
    const ord = D.fromLimbs(prod[0..D.max_limbs]) catch return error.InvalidTrapdoor;
    var x_buf: [aux_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &x_buf);
    x.toBytes(&x_buf, .big) catch unreachable; // canonical mod n_tilde, which fits
    var xr = ord.reduceBytesBE(&x_buf); // tss-lib's Alpha may exceed p'·q'
    defer std.crypto.secureZero(u64, &xr);
    var inv: D.Elem = undefined;
    defer std.crypto.secureZero(u64, &inv);
    if (!ord.inverse(&xr, &inv)) return error.NotInvertible;
    ord.toBytesBE(&inv, &x_buf);
    return AuxFe.fromBytes(n_tilde, &x_buf, .big) catch error.InvalidTrapdoor; // < p'·q' < n_tilde
}

pub const AuxParamsWithTrapdoor = struct {
    params: AuxParams,
    trapdoor: AuxTrapdoor,
};

/// `generateAuxParamsWithTrapdoor` over the caller's own safe primes
/// `p̃ = 2p'+1`, `q̃ = 2q'+1` (big-endian, equal length, top bit of the
/// first byte set — `Ñ` is taken to be `16·p.len` bits — both ≡ 3 mod 4,
/// distinct) — for importing a ring-Pedersen key generated
/// elsewhere (tss-lib's `LocalPreParams`) or for measuring the derivation
/// alone. The primes are NOT checked: wrong ones give a tuple whose Πprm/Πmod
/// a correct verifier refuses. The trapdoor's `p`/`q` are copies owned by
/// `allocator` (free with `trapdoor.deinit`).
pub fn auxParamsWithTrapdoorFromSafePrimes(allocator: std.mem.Allocator, p: []const u8, q: []const u8, random: std.Random, out: *AuxParamsWithTrapdoor) std.mem.Allocator.Error!void {
    const result = auxParamsWithTrapdoorFromSafePrimesUnburned(allocator, p, q, random, out);
    burn.stack(aux_params_with_trapdoor_from_safe_primes_stack_burn);
    return result;
}

noinline fn auxParamsWithTrapdoorFromSafePrimesUnburned(allocator: std.mem.Allocator, p: []const u8, q: []const u8, random: std.Random, out: *AuxParamsWithTrapdoor) std.mem.Allocator.Error!void {
    out.* = try auxParamsWithTrapdoorFromSafePrimesByValue(allocator, p, q, random);
}

fn auxParamsWithTrapdoorFromSafePrimesByValue(allocator: std.mem.Allocator, p: []const u8, q: []const u8, random: std.Random) std.mem.Allocator.Error!AuxParamsWithTrapdoor {
    // The bit length comes from the public byte length, not from the secret
    // top byte (`@clz(p[0])` made every loop bound below depend on p̃).
    std.debug.assert(p.len == q.len and p.len > 0);
    const d = deriveAuxFromSafePrimes(p, q, 16 * p.len, random);
    const p_copy = try allocator.dupe(u8, p);
    errdefer allocator.free(p_copy);
    const q_copy = try allocator.dupe(u8, q);
    return .{ .params = d.params, .trapdoor = .{ .p = p_copy, .q = q_copy, .lambda = d.lambda } };
}

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
pub fn generateAuxParamsWithTrapdoor(allocator: std.mem.Allocator, random: std.Random, bits: usize, out: *AuxParamsWithTrapdoor) std.mem.Allocator.Error!void {
    const result = generateAuxParamsWithTrapdoorUnburned(allocator, random, bits, out);
    burn.stack(generate_aux_params_with_trapdoor_stack_burn);
    return result;
}

noinline fn generateAuxParamsWithTrapdoorUnburned(allocator: std.mem.Allocator, random: std.Random, bits: usize, out: *AuxParamsWithTrapdoor) std.mem.Allocator.Error!void {
    out.* = try generateAuxParamsWithTrapdoorByValue(allocator, random, bits);
}

fn generateAuxParamsWithTrapdoorByValue(allocator: std.mem.Allocator, random: std.Random, bits: usize) std.mem.Allocator.Error!AuxParamsWithTrapdoor {
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
/// 3. h2 = r² mod N_tilde for a random r — a uniform element of N_tilde's
///    group of quadratic residues (order p'·q').
/// 4. lambda ← [1, p'·q') uniformly, the secret exponent.
/// 5. h1 = h2^lambda mod N_tilde (constant-time modexp) — h1 ∈ ⟨h2⟩, the
///    relation Πprm proves (the commitment `h1^x·h2^ρ` hides x only if it
///    holds; see `aux_proofs.Piprm`).
/// ```
///
/// **λ-retention decision: `lambda` is DISCARDED here** — `AuxParams` holds
/// only the public `(N_tilde, h1, h2)`, and only those are broadcast. In
/// GG18/GG20 the tuple belongs to this party acting as the *verifier* of
/// range proofs about OTHER parties' Paillier plaintexts; soundness (binding
/// of the Pedersen commitment) requires the *prover* — i.e. every other
/// party — not to know `lambda = log_{h2} h1`, and this party never acts as
/// a prover under its own tuple, so retaining `lambda` buys nothing and only
/// widens the secret's exposure. It is therefore zeroed with the rest of the
/// safe-prime material before return. **TODO(2c):** if a later phase adds
/// the ZK proof of *correct aux-param generation* (a "Πprm"/"Πmod"-style
/// proof that `h1 = h2^lambda` for a known `lambda`, which some GG20/CMP
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
/// `lambda`'s use in `h1 = h2^lambda mod N_tilde` is the constant-time
/// `AuxModulus.pow`, mirroring `paillier.fromPrimes`'s `g^lambda mod n²`
/// step. All secret buffers are `secureZero`'d.
pub fn generateAuxParams(random: std.Random, bits: usize) AuxParams {
    const result = generateAuxParamsUnburned(random, bits);
    burn.stack(generate_aux_params_stack_burn);
    return result;
}

noinline fn generateAuxParamsUnburned(random: std.Random, bits: usize) AuxParams {
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
    /// `X_j = x_j·G`, this party's Feldman-consistent public share. Every
    /// signer needs every other signer's `X_j`: GG20's MtAwc binds the
    /// counterparty's input to `W_j = λ_j·X_j` (`presign.zig`).
    verifying_share: Element,
    /// Ed25519 public key this party signs its presigning messages with
    /// (`presign.zig`): a signed broadcast shown two ways is proof of who
    /// equivocated, and a signed p2p message cannot be disowned when the
    /// identifiable-abort openings are checked. Encoded, validated by the
    /// codec and by `presign.Party.init`.
    message_key: [32]u8,
};

/// Decodes a message key: canonical, and not of small order. `presign`
/// verifies message signatures with `verifyStrict`, but a small-order key
/// is still refused at the door: under cofactored verification anyone could
/// sign for it, and no honest key is one (review 2026-10-03 F10).
pub fn decodeMessageKey(bytes: [32]u8) error{InvalidEncoding}!std.crypto.sign.Ed25519.PublicKey {
    const key = std.crypto.sign.Ed25519.PublicKey.fromBytes(bytes) catch return error.InvalidEncoding;
    const p = std.crypto.ecc.Edwards25519.fromBytes(bytes) catch return error.InvalidEncoding;
    p.rejectLowOrder() catch return error.InvalidEncoding;
    return key;
}

test "decodeMessageKey refuses small-order keys (review F10) and takes a real one" {
    var order8: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&order8, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
    const order4: [32]u8 = @splat(0); // y = 0: the order-4 point (sqrt(-1), 0)
    var identity: [32]u8 = @splat(0);
    identity[0] = 1;
    for ([_][32]u8{ order8, order4, identity }) |k| try std.testing.expectError(error.InvalidEncoding, decodeMessageKey(k));
    const real = try messagePublicKey(&@as([32]u8, @splat(7)));
    _ = try decodeMessageKey(real);
}

/// The Ed25519 public key of a message-signing seed (`KeyShare.message_seed`).
pub fn messagePublicKey(seed: *const [32]u8) error{InvalidParameters}![32]u8 {
    const result = messagePublicKeyUnburned(seed);
    burn.stack(message_public_key_stack_burn);
    return result;
}

noinline fn messagePublicKeyUnburned(seed: *const [32]u8) error{InvalidParameters}![32]u8 {
    const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed.*) catch return error.InvalidParameters;
    return kp.public_key.toBytes();
}

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
    /// (paillier g) || len-prefixed(aux.toBytesAlloc()) ||
    /// verifying_share (33 bytes) || message_key (32 bytes)`. REAL,
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

            try list.appendSlice(allocator, &e.verifying_share.toBytes());
            try list.appendSlice(allocator, &e.message_key);
        }

        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding} || paillier.PublicKey.FromBytesError || AuxParams.FromBytesError || ElementError;

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
        // for its own (fixed-size-element) count. (+33: the verifying share,
        // +32: the message key.)
        const min_entry_bytes = 16 + Ne + 32;
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

            if (bytes.len < offset + Ne) return error.InvalidEncoding;
            const verifying_share = try Element.fromBytes(bytes[offset..][0..Ne].*);
            offset += Ne;

            if (bytes.len < offset + 32) return error.InvalidEncoding;
            const message_key = bytes[offset..][0..32].*;
            offset += 32;
            _ = try decodeMessageKey(message_key);

            slot.* = .{ .index = index, .paillier_pk = pk, .aux = aux, .verifying_share = verifying_share, .message_key = message_key };
        }
        if (offset != bytes.len) return error.InvalidEncoding;
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
    /// SECRET: the Ed25519 seed this party signs its presigning messages
    /// with; its public key is `public_keys.get(index).message_key`.
    message_seed: [32]u8,

    pub const AllocError = std.mem.Allocator.Error || paillier.SecretKey.ByteError || PublicKeys.AllocError;

    /// `index(4) || t(4) || n(4) || secret_share(32) ||
    /// group_public_key(33) || verifying_share(33) || message_seed(32) || len-prefixed
    /// (paillier_secret.n) || len-prefixed(paillier_secret.lambda) ||
    /// len-prefixed(paillier_secret.mu) || len-prefixed
    /// (public_keys.toBytesAlloc())`. REAL, mechanical — composes
    /// already-real sub-codecs (`paillier.SecretKey`'s own
    /// `nToBytes`/`lambdaToBytes`/`muToBytes`, `Element.toBytes`,
    /// `PublicKeys.toBytesAlloc`).
    pub fn toBytesAlloc(self: *const KeyShare, allocator: std.mem.Allocator) AllocError![]u8 {
        const result = toBytesAllocUnburned(self, allocator);
        burn.stack(key_share_to_bytes_stack_burn);
        return result;
    }

    noinline fn toBytesAllocUnburned(self: *const KeyShare, allocator: std.mem.Allocator) AllocError![]u8 {
        return toBytesAllocByValue(self.*, allocator);
    }

    fn toBytesAllocByValue(self: KeyShare, allocator: std.mem.Allocator) AllocError![]u8 {
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
        try list.appendSlice(allocator, &self.message_seed);

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
    pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8, out: *KeyShare) (std.mem.Allocator.Error || FromBytesError)!void {
        const result = fromBytesAllocUnburned(allocator, bytes, out);
        burn.stack(key_share_from_bytes_stack_burn);
        return result;
    }

    noinline fn fromBytesAllocUnburned(allocator: std.mem.Allocator, bytes: []const u8, out: *KeyShare) (std.mem.Allocator.Error || FromBytesError)!void {
        out.* = try fromBytesAllocByValue(allocator, bytes);
    }

    fn fromBytesAllocByValue(allocator: std.mem.Allocator, bytes: []const u8) (std.mem.Allocator.Error || FromBytesError)!KeyShare {
        if (bytes.len < 12 + Ns + Ne + Ne + 32) return error.InvalidEncoding;
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
        const message_seed = bytes[offset..][0..32].*;
        offset += 32;

        const sk_n_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const lambda_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        const mu_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        var paillier_secret: paillier.SecretKey = undefined;
        try paillier.SecretKey.fromBytes(sk_n_bytes, lambda_bytes, mu_bytes, &paillier_secret);

        const pubkeys_bytes = readLenPrefixed(bytes, &offset) catch return error.InvalidEncoding;
        if (offset != bytes.len) return error.InvalidEncoding;
        const public_keys = try PublicKeys.fromBytesAlloc(allocator, pubkeys_bytes);
        errdefer allocator.free(public_keys.entries);

        // Audit F2 (HIGH, 2026-09-10 fix): reject a tuple whose own `index`
        // is missing from `public_keys` -- `signing.signWithShares` looks
        // itself up via `public_keys.get(index)`, and a `KeyShare` that
        // decodes cleanly here but lacks its own entry used to make that
        // lookup return `null` and panic/UB downstream. Defense in depth on
        // top of `signWithShares`'s own fail-closed fix: a `KeyShare` built
        // by any OTHER path (not through this codec) still gets caught
        // there.
        const own = public_keys.get(index) orelse return error.InvalidEncoding;
        // The broadcast copy of this party's own `X_i` must be the one it holds.
        if (!std.mem.eql(u8, &own.verifying_share.toBytes(), &verifying_share.toBytes())) return error.InvalidEncoding;
        // …and so must its message key.
        const own_mk = messagePublicKey(&message_seed) catch return error.InvalidEncoding;
        if (!std.mem.eql(u8, &own_mk, &own.message_key)) return error.InvalidEncoding;

        return .{
            .index = index,
            .t = t,
            .n = n,
            .secret_share = secret_share,
            .group_public_key = group_public_key,
            .verifying_share = verifying_share,
            .paillier_secret = paillier_secret,
            .public_keys = public_keys,
            .message_seed = message_seed,
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
/// `paillier_keys.len`, `aux_params.len` and `message_seeds.len` MUST all
/// equal `n` (one entry per party, `paillier_keys[i-1]`/`aux_params[i-1]`/
/// `message_seeds[i-1]` for party `i`; a seed is 32 random bytes, the
/// party's Ed25519 message-signing key); `coefficients.len` MUST equal `t - 1` (`splitSecretKey`'s own
/// precondition). Returns `n` `KeyShare`s — see `KeyShare`'s doc comment
/// for the shared-allocation ownership contract.
pub fn keygenTrustedDealer(
    allocator: std.mem.Allocator,
    t: u32,
    n: u32,
    secret_key: *const Scalar,
    coefficients: []const Scalar,
    paillier_keys: []const paillier.KeyPair,
    aux_params: []const AuxParams,
    message_seeds: []const [32]u8,
) KeygenError![]KeyShare {
    const result = keygenTrustedDealerUnburned(allocator, t, n, secret_key, coefficients, paillier_keys, aux_params, message_seeds);
    burn.stack(keygen_trusted_dealer_stack_burn);
    return result;
}

noinline fn keygenTrustedDealerUnburned(
    allocator: std.mem.Allocator,
    t: u32,
    n: u32,
    secret_key: *const Scalar,
    coefficients: []const Scalar,
    paillier_keys: []const paillier.KeyPair,
    aux_params: []const AuxParams,
    message_seeds: []const [32]u8,
) KeygenError![]KeyShare {
    return keygenTrustedDealerByValue(allocator, t, n, secret_key.*, coefficients, paillier_keys, aux_params, message_seeds);
}

fn keygenTrustedDealerByValue(
    allocator: std.mem.Allocator,
    t: u32,
    n: u32,
    secret_key: Scalar,
    coefficients: []const Scalar,
    paillier_keys: []const paillier.KeyPair,
    aux_params: []const AuxParams,
    message_seeds: []const [32]u8,
) KeygenError![]KeyShare {
    if (paillier_keys.len != n or aux_params.len != n or message_seeds.len != n) return error.InvalidParameters;

    const split = try splitSecretKey(allocator, &secret_key, t, n, coefficients);
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
            .verifying_share = try derivePublicKeyShare(split.commitments, i),
            .message_key = try messagePublicKey(&message_seeds[i - 1]),
        };
    }
    const public_keys: PublicKeys = .{ .entries = party_pubs };

    const key_shares = try allocator.alloc(KeyShare, n);
    errdefer allocator.free(key_shares);
    i = 1;
    while (i <= n) : (i += 1) {
        const verifying_share = party_pubs[i - 1].verifying_share;
        key_shares[i - 1] = .{
            .index = i,
            .t = t,
            .n = n,
            .secret_share = split.shares[i - 1].scalar,
            .group_public_key = group_pub,
            .verifying_share = verifying_share,
            .paillier_secret = paillier_keys[i - 1].secret,
            .public_keys = public_keys,
            .message_seed = message_seeds[i - 1],
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

/// Distinct message-signing seeds for test key shares (party i gets seed i+1).
const test_message_seeds = blk: {
    var out: [8][32]u8 = undefined;
    for (&out, 1..) |*x, i| x.* = @splat(@intCast(i));
    break :blk out;
};

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

test "splitSecretKey: a ZERO secret key is rejected (group public key would be the identity)" {
    // The zero scalar across a public entry point — this audit's mandate,
    // item 1. `splitSecretKey` never checks `secret_key` itself; a
    // zero-secret's `commitments[0]` would be `[0]*G = O`, the identity —
    // exactly what a legitimate dealing must never produce (an all-zero
    // group secret). NOTHING previously called `splitSecretKey` itself with
    // a zero secret key, so this path had no regression coverage at this
    // entry point. Mutation testing during this audit found the rejection
    // is defense-in-depth two layers deep: std's own `Secp256k1.basePoint
    // .mul` already refuses a zero scalar (confirmed by bypassing
    // `Element.fromPoint`'s `rejectIdentity` and observing this test still
    // pass) — `Element.fromPoint`'s own identity check is a second,
    // currently-redundant backstop for this specific input, not the sole
    // guard the surrounding doc comments suggest.
    const allocator = testing.allocator;
    const coeffs = [_]Scalar{testScalar(2)};
    try testing.expectError(error.InvalidElement, splitSecretKey(allocator, &Scalar.zero, 2, 3, &coeffs));
}

test "splitSecretKey (t=2,n=3): any 2 shares Lagrange-reconstruct the secret; X == x*G" {
    const allocator = testing.allocator;
    const secret = testScalar(1);
    const coeffs = [_]Scalar{testScalar(2)};

    const split = try splitSecretKey(allocator, &secret, 2, 3, &coeffs);
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
        var reconstructed: Scalar = undefined;
        try reconstructSecret(&pair_shares, &reconstructed);
        try testing.expectEqualSlices(u8, &secret.toBytes(.big), &reconstructed.toBytes(.big));
    }
}

test "splitSecretKey (t=3,n=5): Feldman consistency X_i == x_i*G for every share" {
    const allocator = testing.allocator;
    const secret = testScalar(3);
    const coeffs = [_]Scalar{ testScalar(4), testScalar(5) };

    const split = try splitSecretKey(allocator, &secret, 3, 5, &coeffs);
    defer allocator.free(split.shares);
    defer allocator.free(split.commitments.commitments);

    for (split.shares) |share| {
        const derived = try derivePublicKeyShare(split.commitments, share.index);
        const expected = try Element.fromPoint(try Secp256k1.basePoint.mul(share.scalar.toBytes(.big), .big));
        try testing.expectEqualSlices(u8, &expected.toBytes(), &derived.toBytes());
    }

    // Any 3 (of 5) shares also reconstruct the secret.
    const three = [_]ShamirShare{ split.shares[0], split.shares[2], split.shares[4] };
    var reconstructed: Scalar = undefined;
    try reconstructSecret(&three, &reconstructed);
    try testing.expectEqualSlices(u8, &secret.toBytes(.big), &reconstructed.toBytes(.big));

    // Below threshold: 2 shares do NOT reconstruct the true secret (a
    // mathematically wrong answer, not an error — same caveat
    // `frost.deriveInterpolatingValue`/`bls12_381.threshold
    // .combineSignatures`'s doc comments carry).
    const two = [_]ShamirShare{ split.shares[0], split.shares[1] };
    var wrong: Scalar = undefined;
    try reconstructSecret(&two, &wrong);
    try testing.expect(!std.mem.eql(u8, &secret.toBytes(.big), &wrong.toBytes(.big)));
}

test "reconstructSecret rejects too few, duplicate, or zero-indexed shares" {
    var scratch: Scalar = undefined;
    try testing.expectError(error.InsufficientShares, reconstructSecret(&.{}, &scratch));

    const dup = [_]ShamirShare{
        .{ .index = 1, .scalar = testScalar(1) },
        .{ .index = 1, .scalar = testScalar(2) },
    };
    try testing.expectError(error.DuplicateIndex, reconstructSecret(&dup, &scratch));

    const zero = [_]ShamirShare{
        .{ .index = 0, .scalar = testScalar(1) },
        .{ .index = 2, .scalar = testScalar(2) },
    };
    try testing.expectError(error.ZeroIndex, reconstructSecret(&zero, &scratch));
}

test "FeldmanCommitments toBytesAlloc/fromBytesAlloc round-trip" {
    const allocator = testing.allocator;
    const secret = testScalar(6);
    const coeffs = [_]Scalar{testScalar(7)};
    const split = try splitSecretKey(allocator, &secret, 2, 2, &coeffs);
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
    var kp1: paillier.KeyPair = undefined;
    try paillier.generate(random, paillier.min_generate_bits, &kp1);
    var kp2: paillier.KeyPair = undefined;
    try paillier.generate(random, paillier.min_generate_bits, &kp2);
    var kp3: paillier.KeyPair = undefined;
    try paillier.generate(random, paillier.min_generate_bits, &kp3);
    const paillier_keys = [_]paillier.KeyPair{ kp1, kp2, kp3 };

    const aux = toyAuxParams();
    const aux_params = [_]AuxParams{ aux, aux, aux };

    const secret = testScalar(9);
    const coeffs = [_]Scalar{testScalar(10)};

    const key_shares = try keygenTrustedDealer(allocator, t, n, &secret, &coeffs, &paillier_keys, &aux_params, test_message_seeds[0..n]);
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
    var reconstructed: Scalar = undefined;
    try reconstructSecret(&two, &reconstructed);
    try testing.expectEqualSlices(u8, &secret.toBytes(.big), &reconstructed.toBytes(.big));
}

test "KeyShare toBytesAlloc/fromBytesAlloc round-trip" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6b657973686172);
    const random = prng.random();

    var kp1: paillier.KeyPair = undefined;
    try paillier.generate(random, paillier.min_generate_bits, &kp1);
    var kp2: paillier.KeyPair = undefined;
    try paillier.generate(random, paillier.min_generate_bits, &kp2);
    const paillier_keys = [_]paillier.KeyPair{ kp1, kp2 };

    const aux = toyAuxParams();
    const aux_params = [_]AuxParams{ aux, aux };

    const secret = testScalar(11);
    const coeffs = [_]Scalar{testScalar(12)}; // t=2 needs exactly t-1=1 coefficient
    const key_shares = try keygenTrustedDealer(allocator, 2, 2, &secret, &coeffs, &paillier_keys, &aux_params, test_message_seeds[0..2]);
    defer allocator.free(key_shares);
    defer allocator.free(key_shares[0].public_keys.entries);

    const bytes = try key_shares[0].toBytesAlloc(allocator);
    defer allocator.free(bytes);
    var back: KeyShare = undefined;
    try KeyShare.fromBytesAlloc(allocator, bytes, &back);
    defer allocator.free(back.public_keys.entries);

    try testing.expectEqual(key_shares[0].index, back.index);
    try testing.expectEqual(key_shares[0].t, back.t);
    try testing.expectEqual(key_shares[0].n, back.n);
    try testing.expectEqualSlices(u8, &key_shares[0].secret_share.toBytes(.big), &back.secret_share.toBytes(.big));
    try testing.expectEqualSlices(u8, &key_shares[0].group_public_key.toBytes(), &back.group_public_key.toBytes());
    try testing.expectEqualSlices(u8, &key_shares[0].verifying_share.toBytes(), &back.verifying_share.toBytes());
    try testing.expectEqual(key_shares[0].public_keys.entries.len, back.public_keys.entries.len);
}

test "KeyShare.fromBytesAlloc rejects a tuple whose own index is missing from public_keys (audit F2 HIGH, 2026-09-10 fix)" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x66325f6869676832); // "f2_high2"
    const random = prng.random();

    var kp1: paillier.KeyPair = undefined;
    try paillier.generate(random, paillier.min_generate_bits, &kp1);
    var kp2: paillier.KeyPair = undefined;
    try paillier.generate(random, paillier.min_generate_bits, &kp2);
    const paillier_keys = [_]paillier.KeyPair{ kp1, kp2 };

    const aux = toyAuxParams();
    const aux_params = [_]AuxParams{ aux, aux };

    const secret = testScalar(41);
    const coeffs = [_]Scalar{testScalar(42)}; // t=2 needs exactly t-1=1 coefficient
    const key_shares = try keygenTrustedDealer(allocator, 2, 2, &secret, &coeffs, &paillier_keys, &aux_params, test_message_seeds[0..2]);
    defer allocator.free(key_shares);
    defer allocator.free(key_shares[0].public_keys.entries);

    // Strip party 1's own entry from the `public_keys` list it carries --
    // reproduces the audit's `probe_keyshare_panic.zig` shape via the
    // codec's public entry point (`toBytesAlloc` -> `fromBytesAlloc`), not
    // a hand-built struct. This is the wire-format equivalent of a peer
    // sending back a `KeyShare` a different, buggy dealer assembled.
    var stripped_entries: std.ArrayList(PartyPublicKeys) = .empty;
    defer stripped_entries.deinit(allocator);
    for (key_shares[0].public_keys.entries) |e| {
        if (e.index != key_shares[0].index) try stripped_entries.append(allocator, e);
    }
    try testing.expectEqual(key_shares[0].public_keys.entries.len - 1, stripped_entries.items.len);

    var stripped = key_shares[0];
    stripped.public_keys = .{ .entries = stripped_entries.items };

    const bytes = try stripped.toBytesAlloc(allocator);
    defer allocator.free(bytes);

    var scratch_ks: KeyShare = undefined;
    try testing.expectError(error.InvalidEncoding, KeyShare.fromBytesAlloc(allocator, bytes, &scratch_ks));
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
// h1 = h2^lambda actually holds.
test "generateAuxParams: ring-Pedersen tuple is well-formed (N_tilde composite/odd/right-size, h1/h2 in range, h1 = h2^lambda)" {
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
    try testing.expect(!isProbablePrime(aux.n_tilde, aux.n_tilde.bits(), random));

    // h1, h2 in range [2, N_tilde): nonzero, not one, canonical (fromBytes
    // already guarantees < N_tilde).
    const one = aux.n_tilde.one();
    try testing.expect(!aux.h1.isZero() and !aux.h1.eql(one));
    try testing.expect(!aux.h2.isZero() and !aux.h2.eql(one));

    // The load-bearing relation: h1 == h2^lambda mod N_tilde (h1 ∈ ⟨h2⟩).
    const h1_check = try aux.n_tilde.pow(aux.h2, gen.lambda);
    try testing.expect(h1_check.eql(aux.h1));

    // The public wrapper produces an equally well-formed (independent) tuple
    // and it round-trips through the byte codec.
    const pub_aux = generateAuxParams(random, bits);
    try testing.expect(!isProbablePrime(pub_aux.n_tilde, pub_aux.n_tilde.bits(), random));
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

test "AuxParams.validate rejects an order-2 generator (audit F1 HIGH, 2026-09-10 fix)" {
    var prng = std.Random.DefaultPrng.init(0x6f726465722d32); // "order-2"
    const random = prng.random();

    // A genuine ~2000-bit odd composite ≡ 1 (mod 4) -- the module's other
    // `big_composite` fixture (`(2^1000+9)*(2^1000+15)`, used by the
    // validate() test above) is ≡ 3 (mod 4), for which Jacobi(-1|Ñ) = -1
    // and the PRE-EXISTING Jacobi check already rejects h2 = Ñ-1, so it
    // cannot reproduce this bug. `(2^1000+9)*(2^1000+13)` is ≡ 1 (mod 4)
    // (9*13 mod 4 = 1), giving Jacobi(-1|Ñ) = (-1)^((Ñ-1)/2) = +1 -- exactly
    // the case `generateSafePrime`'s real safe primes (both ≡ 3 mod 4) land
    // on, per the audit.
    const big_composite = comptime comptimeIntBytes(256, ((1 << 1000) + 9) * ((1 << 1000) + 13));
    const nt = AuxModulus.fromBytes(stripLeadingZeros(&big_composite), .big) catch unreachable;
    const one = nt.one();
    const h1_ok = AuxFe.fromBytes(nt, &[_]u8{4}, .big) catch unreachable; // 2², order != 2
    const minus_one = nt.sub(nt.zero, one); // Ñ-1, order 2 for ANY odd Ñ

    // Precondition: this Ñ actually reproduces the audit's exact scenario
    // (h2 = Ñ-1 passes Jacobi, and has order 2) -- if either flips, the
    // rejection below would come from the OLDER checks, not the new one.
    var scratch: [aux_scratch_bytes]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    try testing.expect(auxFeJacobiIsOne(fba.allocator(), nt, minus_one));
    try testing.expect(nt.sq(minus_one).eql(one));
    try testing.expect(!nt.sq(h1_ok).eql(one));

    // h2 = Ñ-1: order 2, Jacobi +1, in range (1, Ñ) -- every OLDER check
    // (composite, range, Jacobi, size floor) passes; only the new order-2
    // guard can catch it.
    {
        const evil: AuxParams = .{ .n_tilde = nt, .h1 = h1_ok, .h2 = minus_one };
        try testing.expectError(error.InvalidAuxParams, evil.validate(random));
    }
    // Symmetric: h1 = Ñ-1 instead of h2.
    {
        const evil: AuxParams = .{ .n_tilde = nt, .h1 = minus_one, .h2 = h1_ok };
        try testing.expectError(error.InvalidAuxParams, evil.validate(random));
    }
    // Positive control: swapping in a non-degenerate h2 (the SAME Ñ/h1,
    // structurally identical otherwise) must still be ACCEPTED -- proves
    // the new check isn't rejecting everything on this Ñ.
    {
        const h2_ok = AuxFe.fromBytes(nt, &[_]u8{16}, .big) catch unreachable; // 4², order != 2
        try testing.expect(!nt.sq(h2_ok).eql(one));
        const good: AuxParams = .{ .n_tilde = nt, .h1 = h1_ok, .h2 = h2_ok };
        try good.validate(random);
    }

    // NOTE: this fix also closes the entry-point-level collapse the audit
    // measured (`zkproofs.proveAliceRange`/`proveBobMta`/`proveBobMtaWc`
    // all call `validateReceivedParams` -> `AuxParams.validate` on the
    // RECEIVED tuple before using it, fail-closed) -- an end-to-end test
    // through one of those entry points with `evil` above would now just
    // observe `error.InvalidAuxParams` from the SAME guard tested directly
    // here, not exercise any additional code path, so it is not repeated.
}

// Pull the `zkproofs` submodule's tests into this module's test binary —
// same dark-tests rule as `test { _ = mta; }` above. As of the Phase-2c
// implementation pass the six prove/verify functions are REAL (GG18
// Appendix A.1/A.2/A.3, verified against the paper), so all of
// `zkproofs.zig`'s tests pass — nothing here panics any more.
test {
    _ = zkproofs;
}

// Pull the `signing`, `presign` and `ecproofs` submodules' tests into this
// module's test binary — same dark-tests rule.
test {
    _ = signing;
    _ = presign;
    _ = ecproofs;
    _ = @import("tsslib_interop.zig");
    _ = @import("stackprobe_test.zig");
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

test {
    _ = fac_proof;
}

test {
    _ = aux_info;
}

test "generateAuxParamsWithTrapdoor: retains p̃/q̃/lambda; p̃*q̃ == n_tilde and h1 == h2^lambda" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x747261706400); // "trapd\0"
    const random = prng.random();

    const bits: usize = 128;
    var gen: AuxParamsWithTrapdoor = undefined;
    try generateAuxParamsWithTrapdoor(allocator, random, bits, &gen);
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

    // h1 == h2^lambda mod n_tilde — same load-bearing relation the ungated
    // `generateAuxParams` test checks via the internal `lambda`.
    const h1_check = try gen.params.n_tilde.pow(gen.params.h2, gen.trapdoor.lambda);
    try testing.expect(h1_check.eql(gen.params.h1));
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
//
// ⛔⛔ Except that it did not, and could not. All three harnesses ASSEMBLED a
// frame out of ranged draws, and a ranged draw reads eight input octets as a
// little-endian u64 and returns the range MINIMUM when fewer remain. With no
// corpus the lane runs one round on `in = ""`, so every draw took its minimum
// and each target ran exactly one input, for ever:
//
//   FeldmanCommitments : `00 00 00 00`     -- count = 0, ACCEPTED, 0 elements
//   PublicKeys         : `00 00 00 00`     -- count = 0, ACCEPTED, 0 entries
//   AuxParams          : twelve zero bytes -- three empty fields, refused
//
// So the `count = 0xFFFFFFFF` arm — the exact input of the ~29 TB
// over-allocation bug this harness was WRITTEN to guard against — had never
// been produced once. The switch that selects it is `valueRangeAtMost(u8, 0,
// 2)`, whose minimum is the small-count arm.
//
// ⛔ The buffers were too small for the module's own frames as well: a real
// two-party `PublicKeys` encoding is ~1150 octets (every entry carries a
// `paillier.modulus_sq_bytes`-wide `g` field) against a 4 + 256 assembly
// buffer, and a real `AuxParams` at this module's `aux_modulus_bits` is 780
// against 3 x 64.
//
// All three now draw the message itself with one `smith.slice` and carry a
// corpus: frames from this module's own encoders, and the hostile counts and
// lying length prefixes written out as bytes, which is reproducible where a
// draw is not.

/// The corpus for the three counted/length-prefixed decoders.
///
/// ⭐ Each harness and its guard build it from HERE, so the guard measures the
/// seeds the harness actually gets.
const Corpus = struct {
    const feld_buf_bytes = 512;
    const pk_buf_bytes = 4096;
    const aux_buf_bytes = 1024;
    const ks_buf_bytes = 8192;

    feld_store: [8][4 + feld_buf_bytes]u8 = undefined,
    feld_entries: [8][]const u8 = undefined,
    pk_store: [7][4 + pk_buf_bytes]u8 = undefined,
    pk_entries: [7][]const u8 = undefined,
    aux_store: [8][4 + aux_buf_bytes]u8 = undefined,
    aux_entries: [8][]const u8 = undefined,
    ks_store: [6][4 + ks_buf_bytes]u8 = undefined,
    ks_entries: [6][]const u8 = undefined,

    /// `bytes` with a u32-BE value written at `at`. The counted-field
    /// mutations are all of this shape: a real frame whose ONE length or count
    /// word lies.
    fn withU32(scratch: []u8, bytes: []const u8, at: usize, v: u32) []const u8 {
        @memcpy(scratch[0..bytes.len], bytes);
        std.mem.writeInt(u32, scratch[at..][0..4], v, .big);
        return scratch[0..bytes.len];
    }

    fn build(self: *Corpus, allocator: std.mem.Allocator) !void {
        var scratch: [pk_buf_bytes]u8 = undefined;

        // ── FeldmanCommitments: real Feldman VSS commitments from this
        //    module's own `splitSecretKey`, at two thresholds.
        const sk6 = testScalar(6);
        const c2 = try splitSecretKey(allocator, &sk6, 2, 2, &[_]Scalar{testScalar(7)});
        defer allocator.free(c2.shares);
        defer allocator.free(c2.commitments.commitments);
        const f2 = try c2.commitments.toBytesAlloc(allocator);
        defer allocator.free(f2);

        const sk9 = testScalar(9);
        const c3 = try splitSecretKey(allocator, &sk9, 3, 3, &[_]Scalar{ testScalar(4), testScalar(5) });
        defer allocator.free(c3.shares);
        defer allocator.free(c3.commitments.commitments);
        const f3 = try c3.commitments.toBytesAlloc(allocator);
        defer allocator.free(f3);
        std.debug.assert(f3.len <= feld_buf_bytes);

        var i: usize = 0;
        self.feld_entries[i] = fuzzSeedIntoLocal(&self.feld_store[i], f2);
        i += 1; // 2 real commitments
        self.feld_entries[i] = fuzzSeedIntoLocal(&self.feld_store[i], f3);
        i += 1; // 3 real commitments
        // ⭐ The input of the fixed over-allocation bug, which the harness that
        //    exists to guard it had never once produced.
        self.feld_entries[i] = fuzzSeedIntoLocal(&self.feld_store[i], &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });
        i += 1;
        // The same shape at a scale that once peaked ~1.3 GB RSS on its own.
        self.feld_entries[i] = fuzzSeedIntoLocal(&self.feld_store[i], &[_]u8{ 0x00, 0x03, 0x0d, 0x40 });
        i += 1;
        // count = 0: legal, ACCEPTED with zero elements. The one input this
        // target ran for ever, kept so the guard's second number can show what
        // it was worth.
        self.feld_entries[i] = fuzzSeedIntoLocal(&self.feld_store[i], &[_]u8{ 0, 0, 0, 0 });
        i += 1;
        // A real frame whose first commitment is no longer a SEC1 point.
        self.feld_entries[i] = fuzzSeedIntoLocal(
            &self.feld_store[i],
            withU32(&scratch, f2, 4, 0x0400_0000),
        );
        i += 1;
        self.feld_entries[i] = fuzzSeedIntoLocal(&self.feld_store[i], f2[0 .. f2.len - 1]);
        i += 1; // truncated: length no longer matches the count
        self.feld_entries[i] = fuzzSeedIntoLocal(&self.feld_store[i], "");
        i += 1;
        std.debug.assert(i == self.feld_entries.len);

        // ── PublicKeys: a real two-party keygen. Nothing drawn produces one —
        //    each entry carries a Paillier modulus, its generator and a full
        //    `AuxParams` block.
        var prng = std.Random.DefaultPrng.init(0x74686665656c64);
        const random = prng.random();
        var kp1: paillier.KeyPair = undefined;
        try paillier.generate(random, paillier.min_generate_bits, &kp1);
        var kp2: paillier.KeyPair = undefined;
        try paillier.generate(random, paillier.min_generate_bits, &kp2);
        const aux = toyAuxParams();
        const sk11 = testScalar(11);
        const key_shares = try keygenTrustedDealer(
            allocator,
            2,
            2,
            &sk11,
            &[_]Scalar{testScalar(12)},
            &[_]paillier.KeyPair{ kp1, kp2 },
            &[_]AuxParams{ aux, aux },
            test_message_seeds[0..2],
        );
        defer allocator.free(key_shares);
        defer allocator.free(key_shares[0].public_keys.entries);
        const pk_bytes = try key_shares[0].public_keys.toBytesAlloc(allocator);
        defer allocator.free(pk_bytes);
        // ⚠ The check the old harness never made: the buffer has to hold the
        // module's own frame, or the seed reads back EMPTY without a word.
        std.debug.assert(pk_bytes.len <= pk_buf_bytes);

        var p: usize = 0;
        self.pk_entries[p] = fuzzSeedIntoLocal(&self.pk_store[p], pk_bytes);
        p += 1; // 2 real parties
        self.pk_entries[p] = fuzzSeedIntoLocal(&self.pk_store[p], &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });
        p += 1; // ⭐ the ~29 TB allocation attempt, verbatim
        self.pk_entries[p] = fuzzSeedIntoLocal(
            &self.pk_store[p],
            withU32(&scratch, pk_bytes, 0, 0xFFFF_FFFF),
        );
        p += 1; // the same lie behind a real body
        self.pk_entries[p] = fuzzSeedIntoLocal(&self.pk_store[p], &[_]u8{ 0, 0, 0, 0 });
        p += 1; // count = 0: legal, and all this target ever ran
        self.pk_entries[p] = fuzzSeedIntoLocal(
            &self.pk_store[p],
            withU32(&scratch, pk_bytes, 8, 0xFFFF_FFF0),
        );
        p += 1; // the first inner length prefix lies
        self.pk_entries[p] = fuzzSeedIntoLocal(&self.pk_store[p], pk_bytes[0 .. pk_bytes.len / 2]);
        p += 1; // truncated mid-entry
        self.pk_entries[p] = fuzzSeedIntoLocal(&self.pk_store[p], "");
        p += 1;
        std.debug.assert(p == self.pk_entries.len);

        // ── KeyShare: reuses the SAME real `key_shares[0]` built for the
        //    PublicKeys section above, plus the audit F2 (HIGH) shape --
        //    the "own index missing from public_keys" tuple that used to
        //    panic/UB in `signWithShares` (2026-09-10 fix) -- as a fuzz
        //    corpus seed, not just the standalone regression test at
        //    "KeyShare.fromBytesAlloc rejects a tuple whose own index is
        //    missing...". Audit F8: this decoder was one of 12 public
        //    `fromBytes*` entry points with zero fuzz coverage, the same
        //    dozen that includes every wire message a counterparty sends
        //    during signing -- this closes the single highest-severity one
        //    (F2 was HIGH, the others 11 are unfuzzed too but lower risk).
        const ks_bytes = try key_shares[0].toBytesAlloc(allocator);
        defer allocator.free(ks_bytes);
        std.debug.assert(ks_bytes.len <= ks_buf_bytes);

        var stripped_entries: std.ArrayList(PartyPublicKeys) = .empty;
        defer stripped_entries.deinit(allocator);
        for (key_shares[0].public_keys.entries) |e| {
            if (e.index != key_shares[0].index) try stripped_entries.append(allocator, e);
        }
        var stripped = key_shares[0];
        stripped.public_keys = .{ .entries = stripped_entries.items };
        const ks_stripped_bytes = try stripped.toBytesAlloc(allocator);
        defer allocator.free(ks_stripped_bytes);

        var ks_scratch: [ks_buf_bytes]u8 = undefined;

        var k: usize = 0;
        self.ks_entries[k] = fuzzSeedIntoLocal(&self.ks_store[k], ks_bytes);
        k += 1; // a real, accepted KeyShare
        self.ks_entries[k] = fuzzSeedIntoLocal(&self.ks_store[k], ks_stripped_bytes);
        k += 1; // audit F2 (HIGH): own index missing from public_keys -- must be rejected, not panic/UB
        self.ks_entries[k] = fuzzSeedIntoLocal(
            &self.ks_store[k],
            withU32(&ks_scratch, ks_bytes, 0, 0xFFFF_FFFF),
        );
        k += 1; // index tampered to a value no public_keys entry carries either
        self.ks_entries[k] = fuzzSeedIntoLocal(&self.ks_store[k], ks_bytes[0 .. ks_bytes.len - 1]);
        k += 1; // truncated: the last length-prefixed field runs off the end
        self.ks_entries[k] = fuzzSeedIntoLocal(&self.ks_store[k], ks_bytes[0..12]);
        k += 1; // header only -- exercises the `bytes.len < 12 + Ns + Ne + Ne` floor
        self.ks_entries[k] = fuzzSeedIntoLocal(&self.ks_store[k], "");
        k += 1;
        std.debug.assert(k == self.ks_entries.len);

        // ── AuxParams: a REAL ring-Pedersen triple, `h1 = h2^lambda mod Ñ`,
        //    from this module's own generator; plus the toy triple.
        var gen: AuxParamsWithTrapdoor = undefined;
        try generateAuxParamsWithTrapdoor(allocator, random, 128, &gen);
        defer gen.trapdoor.deinit(allocator);
        const real_aux = try gen.params.toBytesAlloc(allocator);
        defer allocator.free(real_aux);
        std.debug.assert(real_aux.len <= aux_buf_bytes);
        const toy = try aux.toBytesAlloc(allocator);
        defer allocator.free(toy);

        var a: usize = 0;
        self.aux_entries[a] = fuzzSeedIntoLocal(&self.aux_store[a], real_aux);
        a += 1; // a real 128-bit Ñ with a genuine h1/h2 relation
        self.aux_entries[a] = fuzzSeedIntoLocal(&self.aux_store[a], toy);
        a += 1; // the toy triple (Ñ = 187)
        self.aux_entries[a] = fuzzSeedIntoLocal(
            &self.aux_store[a],
            withU32(&scratch, real_aux, 0, 0xFFFF_FFFF),
        );
        a += 1; // Ñ's declared length lies -- `readLenPrefixed`'s bound check
        self.aux_entries[a] = fuzzSeedIntoLocal(
            &self.aux_store[a],
            withU32(&scratch, real_aux, 0, 0),
        );
        a += 1; // Ñ declared empty: strips to nothing, refused
        // h1's declared length lies about a field that IS there.
        self.aux_entries[a] = fuzzSeedIntoLocal(
            &self.aux_store[a],
            withU32(&scratch, real_aux, 4 + (real_aux.len - 12) / 3, 0xFFFF_FFFF),
        );
        a += 1;
        self.aux_entries[a] = fuzzSeedIntoLocal(&self.aux_store[a], real_aux[0 .. real_aux.len - 1]);
        a += 1; // truncated: h2 runs off the end
        self.aux_entries[a] = fuzzSeedIntoLocal(&self.aux_store[a], &[_]u8{0} ** 12);
        a += 1; // three empty fields -- the one input this target ran
        self.aux_entries[a] = fuzzSeedIntoLocal(&self.aux_store[a], "");
        a += 1;
        std.debug.assert(a == self.aux_entries.len);
    }
};

test "fuzz: FeldmanCommitments.fromBytesAlloc never panics or over-allocates" {
    var corpus: Corpus = .{};
    try corpus.build(testing.allocator);
    try testing.fuzz({}, fuzzFeldmanCommitmentsFromBytesAlloc, .{ .corpus = &corpus.feld_entries });
}

fn fuzzFeldmanCommitmentsFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    // ⚠ One `smith.slice`: the message IS the input, so the hostile counts are
    // seeds rather than draws the replay lane cannot make.
    var buf: [Corpus.feld_buf_bytes]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const result = FeldmanCommitments.fromBytesAlloc(allocator, buf[0..len]) catch return;
    defer allocator.free(result.commitments);
}

test "corpus: the FeldmanCommitments seeds reach the decoder, counts pinned" {
    // ⛔ `accepted` is worthless on its own here: `00 00 00 00` is a LEGAL
    // frame carrying zero commitments, and it is the only input this target
    // ever ran. `elements` — commitments actually decoded — is the number the
    // collapse cannot hold up.
    var corpus: Corpus = .{};
    try corpus.build(testing.allocator);
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var elements: usize = 0;
    for (corpus.feld_entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [Corpus.feld_buf_bytes]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const result = FeldmanCommitments.fromBytesAlloc(testing.allocator, buf[0..len]) catch continue;
        defer testing.allocator.free(result.commitments);
        accepted += 1;
        elements += result.commitments.len;
    }
    try testing.expectEqual(corpus.feld_entries.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(@as(usize, 5), elements);
}

test "fuzz: PublicKeys.fromBytesAlloc never panics or over-allocates" {
    var corpus: Corpus = .{};
    try corpus.build(testing.allocator);
    try testing.fuzz({}, fuzzPublicKeysFromBytesAlloc, .{ .corpus = &corpus.pk_entries });
}

fn fuzzPublicKeysFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    // 4096 against a ~1150-octet real two-party frame; the old assembly buffer
    // was 260, so no real frame could have gone through even had the draw
    // worked.
    var buf: [Corpus.pk_buf_bytes]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const result = PublicKeys.fromBytesAlloc(allocator, buf[0..len]) catch return;
    defer allocator.free(result.entries);
}

test "corpus: the PublicKeys seeds reach the decoder, counts pinned" {
    // Same trap as above: `00 00 00 00` is a legal zero-party frame.
    // `parties` is what only a real body produces.
    var corpus: Corpus = .{};
    try corpus.build(testing.allocator);
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var parties: usize = 0;
    for (corpus.pk_entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [Corpus.pk_buf_bytes]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const result = PublicKeys.fromBytesAlloc(testing.allocator, buf[0..len]) catch continue;
        defer testing.allocator.free(result.entries);
        accepted += 1;
        parties += result.entries.len;
    }
    try testing.expectEqual(corpus.pk_entries.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 2), accepted);
    try testing.expectEqual(@as(usize, 2), parties);
}

test "fuzz: AuxParams.fromBytesAlloc never panics on arbitrary bytes" {
    var corpus: Corpus = .{};
    try corpus.build(testing.allocator);
    try testing.fuzz({}, fuzzAuxParamsFromBytesAlloc, .{ .corpus = &corpus.aux_entries });
}

fn fuzzAuxParamsFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    // 1024 against the 780 octets a full `aux_modulus_bits` triple encodes to;
    // the old assembly buffer was three fields of 64.
    var buf: [Corpus.aux_buf_bytes]u8 = undefined;
    const len: usize = smith.slice(&buf);
    _ = AuxParams.fromBytesAlloc(buf[0..len]) catch return;
}

test "corpus: the AuxParams seeds reach the decoder, counts pinned" {
    // The second number is the count of distinct Ñ bit-widths recovered: it
    // moves only when a seed's own octets reach `AuxModulus.fromBytes`, which
    // the twelve zero bytes this target ran for ever never did.
    var corpus: Corpus = .{};
    try corpus.build(testing.allocator);
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var widths: [8]usize = undefined;
    var n_widths: usize = 0;
    for (corpus.aux_entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [Corpus.aux_buf_bytes]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const params = AuxParams.fromBytesAlloc(buf[0..len]) catch continue;
        accepted += 1;
        const bits = params.n_tilde.bits();
        for (widths[0..n_widths]) |w| {
            if (w == bits) break;
        } else {
            widths[n_widths] = bits;
            n_widths += 1;
        }
    }
    try testing.expectEqual(corpus.aux_entries.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 2), accepted);
    try testing.expectEqual(@as(usize, 2), n_widths);
}

test "fuzz: KeyShare.fromBytesAlloc never panics on arbitrary bytes (audit F8)" {
    var corpus: Corpus = .{};
    try corpus.build(testing.allocator);
    try testing.fuzz({}, fuzzKeyShareFromBytesAlloc, .{ .corpus = &corpus.ks_entries });
}

fn fuzzKeyShareFromBytesAlloc(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [Corpus.ks_buf_bytes]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var result: KeyShare = undefined;
    KeyShare.fromBytesAlloc(allocator, buf[0..len], &result) catch return;
    defer allocator.free(result.public_keys.entries);
}

test "corpus: the KeyShare seeds reach the decoder, only the well-formed one is accepted" {
    // Pins that the audit-F2 "own index missing" seed, the tampered-index
    // seed, the truncation and the header-only seed are all REJECTED (not
    // silently mis-parsed) -- only the first, real seed decodes.
    var corpus: Corpus = .{};
    try corpus.build(testing.allocator);
    var nonempty: usize = 0;
    var accepted: usize = 0;
    for (corpus.ks_entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [Corpus.ks_buf_bytes]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var result: KeyShare = undefined;
        KeyShare.fromBytesAlloc(testing.allocator, buf[0..len], &result) catch continue;
        defer testing.allocator.free(result.public_keys.entries);
        accepted += 1;
    }
    try testing.expectEqual(corpus.ks_entries.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 1), accepted);
}

// ── audit F8: `Element.fromBytes` was the 12th unfuzzed decoder this
// finding counted -- present in the audit's own list ("root.KeyShare.
// fromBytesAlloc, root.Element.fromBytes, zkproofs...") but overlooked by
// every earlier pass at this finding (each one enumerated "the remaining
// N" from the previous pass's own count rather than re-checking against
// the audit's original twelve). FIXED-SIZE `fromBytes([Ne]u8)`, same shape
// as `signing.zig`'s five wire-message codecs -- `smith.bytes` into the
// exact-width buffer is the whole harness, no corpus needed. This closes
// the audit's twelfth and last decoder.
test "fuzz: Element.fromBytes never panics (audit F8)" {
    try testing.fuzz({}, fuzzElementFromBytes, .{});
}
fn fuzzElementFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [Element.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    _ = Element.fromBytes(buf) catch return;
}

/// ⛔ A LOCAL COPY of `testkit.fuzz.seedInto`, and it has to be one — see the
/// note on `check-testonly` below. Enrolling this module in `test_deps` puts it
/// into that gate, whose probe imports the PUBLISHED module and references every
/// declaration three levels deep, and this module deliberately guards a
/// test-only function with a `@compileError` that fires outside a test build.
/// The two gates contradict each other.
///
/// The anchor test underneath stops this copy drifting from
/// `modules/testkit/src/fuzz.zig`.
fn fuzzSeedIntoLocal(out: []u8, frame: []const u8) []const u8 {
    std.debug.assert(out.len >= 4 + frame.len);
    std.mem.writeInt(u32, out[0..4], @intCast(frame.len), .little);
    @memcpy(out[4..][0..frame.len], frame);
    return out[0 .. 4 + frame.len];
}

test "the local seedInto helper produces what Smith.slice reads back" {
    var storage: [32]u8 = undefined;
    const s = fuzzSeedIntoLocal(&storage, "abcdef");
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [32]u8 = undefined;
    const n = smith.slice(&buf);
    try std.testing.expectEqualStrings("abcdef", buf[0..n]);
}

test "bytesModCt equals % for every sieve prime, and sieveRejects finds a small factor" {
    var prng = std.Random.DefaultPrng.init(0x7369_6576_65); // "sieve"
    const random = prng.random();
    var buf: [128]u8 = undefined;
    for (0..64) |_| {
        random.bytes(&buf);
        for (sieve_primes, sieve_recips) |sp, m| {
            var r: u64 = 0;
            for (buf) |b| r = @intCast(((@as(u128, r) << 8) | b) % sp);
            try testing.expectEqual(r, bytesModCt(&buf, sp, m));
        }
    }
    // 1021 (the largest sieve prime) times a large number: rejected. The top
    // two bytes of the multiplicand are zero so the product fits.
    @memset(&buf, 0xff);
    buf[0] = 0;
    buf[1] = 0;
    var x: [128]u8 = undefined;
    var carry: u32 = 0;
    var i: usize = buf.len;
    while (i > 0) {
        i -= 1;
        const v = @as(u32, buf[i]) * 1021 + carry;
        x[i] = @truncate(v);
        carry = v >> 8;
    }
    try testing.expectEqual(@as(u32, 0), carry);
    try testing.expect(sieveRejects(&x));
    // A prime above the sieve (2^127 − 1, a Mersenne prime): kept.
    var mp: [16]u8 = undefined;
    @memset(&mp, 0xff);
    mp[0] = 0x7f;
    try testing.expect(!sieveRejects(&mp));
}

test "KeyShare.fromBytesAlloc rejects a message seed that is not the one behind its own announced message key" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6d73_6773_6565_64);
    const random = prng.random();
    var kp1: paillier.KeyPair = undefined;
    try paillier.generate(random, paillier.min_generate_bits, &kp1);
    var kp2: paillier.KeyPair = undefined;
    try paillier.generate(random, paillier.min_generate_bits, &kp2);
    const paillier_keys = [_]paillier.KeyPair{ kp1, kp2 };
    const aux = toyAuxParams();
    const aux_params = [_]AuxParams{ aux, aux };
    const coeffs = [_]Scalar{testScalar(12)};
    const sk11 = testScalar(11);
    const key_shares = try keygenTrustedDealer(allocator, 2, 2, &sk11, &coeffs, &paillier_keys, &aux_params, test_message_seeds[0..2]);
    defer allocator.free(key_shares);
    defer allocator.free(key_shares[0].public_keys.entries);

    const bytes = try key_shares[0].toBytesAlloc(allocator);
    defer allocator.free(bytes);
    var back: KeyShare = undefined;
    try KeyShare.fromBytesAlloc(allocator, bytes, &back);
    allocator.free(back.public_keys.entries);
    // The seed of party 1 is 32 x 0x01 (`test_message_seeds`); the announced
    // keys are derived from it. Change the seed in the encoding only.
    const at = std.mem.indexOf(u8, bytes, &test_message_seeds[0]) orelse return error.TestFixtureSeedNotFound;
    const bad = try allocator.dupe(u8, bytes);
    defer allocator.free(bad);
    bad[at] ^= 0x01;
    var scratch_ks: KeyShare = undefined;
    try testing.expectError(error.InvalidEncoding, KeyShare.fromBytesAlloc(allocator, bad, &scratch_ks));
}
