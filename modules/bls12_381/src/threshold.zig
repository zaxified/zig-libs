// SPDX-License-Identifier: MIT
//! threshold — Part 6 of the `bls12_381` arc: **trusted-dealer**
//! threshold BLS over any Basic or ProofOfPossession ciphersuite of
//! `scheme.zig` (`Threshold(variant, scheme)`, generalised 2026-11-17 the
//! way `scheme.zig` generalised the signatures). The file-level names are
//! the min-pk POP instance `MinPk` (public keys/shares in `G1`,
//! signatures/partial signatures in `G2` — Part 4's `bls_sig.zig`
//! convention, whose `SecretKey`/`PublicKey`/`Signature` wire types they
//! reuse); `MinSig` swaps the groups (keys in `G2`, signatures in `G1`)
//! and signs/verifies as `bls_sig.MinSigPop`. A `t`-of-`n` Shamir secret
//! sharing of a BLS secret key `sk`, with a Feldman verifiable-secret-
//! sharing (VSS) commitment so every share is publicly checkable
//! against the dealer's claimed sharing polynomial, and a Lagrange-
//! interpolation-in-the-exponent combiner that turns any `t` (or more)
//! partial signatures into a signature **indistinguishable from**
//! (byte-for-byte equal to) `bls_sig.sign(&sk, msg)`.
//!
//! This is what makes threshold BLS uniquely simple among threshold
//! signature schemes: unlike threshold Schnorr (the sibling `frost`
//! module, RFC 9591), there is no interactive nonce-commitment round at
//! all. `bls_sig.sign`'s equation `R = SK * Q` is LINEAR in `SK`, so
//! (a) any Shamir-shared piece of `SK` produces a correspondingly-
//! shared piece of `R` with NO coordination between signers (each
//! signer just calls `bls_sig.sign` with their own share, once, ever —
//! `partialSign`), and (b) Lagrange interpolation IN THE EXPONENT
//! recombines those pieces exactly as it would recombine the secret key
//! itself (`combineSignatures`). `frost`'s two-round `commit`/`sign`/
//! `aggregate` protocol (`SigningNonces`, binding factors, a sorted
//! `commitment_list`) has no counterpart here — there is nothing to
//! bind or coordinate. Types and naming mirror `frost` wherever the
//! shape genuinely matches (a trusted-dealer split step returning
//! shares + a VSS commitment, a Lagrange-combine step, the "index/
//! identifier as evaluation point" convention), adjusted for BLS's
//! simpler non-interactive structure — see each function's doc comment
//! for the specific `frost` counterpart it mirrors.
//!
//! **Trusted-dealer model ONLY** (mirrors `frost.trustedDealerKeygen`'s
//! own scope note, RFC 9591 Appendix C): a single party (the "dealer")
//! holds the plaintext `sk`, splits it into `n` Shamir shares via
//! `splitSecretKey`, and hands one to each participant out-of-band — the
//! dealer sees, and could retain, the whole secret. A full
//! Pedersen-style **distributed key generation (DKG)**, where no single
//! party ever learns `sk`, is explicitly **OUT OF SCOPE** for this file
//! (see `SPEC.md`'s "Part 6 design" / threat model) — a DKG needs an
//! interactive complaint/justification sub-protocol (Pedersen's or
//! Gennaro–Jarecki–Krawczyk–Rabin's construction) between ALL
//! participants, not merely a different `splitSecretKey` signature, and
//! would be a distinct follow-up module/part.
//!
//! **Status: COMPLETE (crypto-core pass 2026-07-14).** Every function
//! is real: the Shamir polynomial evaluation (`evalPolynomialAt`),
//! Feldman commitment computation (`feldmanCommitCoefficient`), Feldman
//! evaluation-in-the-exponent (`derivePublicKeyShare`), and Lagrange
//! interpolation-in-the-exponent (`combineSignatures`) cores were
//! filled in per the constructions each doc comment quotes, mirroring
//! the sibling `frost` module's already-KAT-validated Horner/Lagrange
//! loops (RFC 9591 Appendix C) with the field/group types swapped. The
//! keystone self-consistency chain — `splitSecretKey` → `partialSign`
//! (`t` distinct shares) → `combineSignatures` byte-for-byte equal to
//! `bls_sig.sign(&sk, msg)` — transitively pins this file to Part 4's
//! ethereum/bls12-381-tests vectors (see the tests at the bottom).
//! `partialSign`, `verifyPartialSignature`, and `groupPublicKey` are
//! thin, judgment-free wrappers over Part 4's `bls_sig.sign`/
//! `bls_sig.verify` (see their own doc comments for why no new crypto
//! judgment is needed).
//!
//! **Const-time discipline**: `SecretKeyShare.scalar` is exactly as
//! sensitive as Part 4's `SecretKey.scalar` — `partialSign` reuses Part
//! 4's already-constant-time `bls_sig.sign` for precisely this reason.
//! The polynomial-evaluation (`evalPolynomialAt`) and
//! Feldman-commitment (`feldmanCommitCoefficient`) paths touch secret
//! coefficients/shares directly and follow the same discipline as
//! `bls_sig.skToPk`/`sign` (`scalar.zig`'s constant-time `Fr` ops;
//! `g1.zig`'s constant-time `scalarMul`) — see `SPEC.md`'s threat
//! model. `combineSignatures`'s Lagrange coefficients
//! are computed from PUBLIC participant indices only (same reasoning as
//! `frost.deriveInterpolatingValue`'s own doc comment: the indices
//! themselves carry no secret, only the values they multiply do), so
//! that arithmetic may use `Fr.inv`'s existing constant-time
//! implementation without further judgment; the per-partial `g2`
//! scalar multiplication by a Lagrange coefficient does NOT need to be
//! constant-time with respect to the (public) coefficient, but the
//! ACCUMULATION touches signature material that is not itself secret
//! post-hoc (a valid signature is meant to be published) — no special
//! discipline beyond "use `g2.zig`'s existing operations" is required
//! there.

const std = @import("std");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const scalarmod = @import("scalar.zig");
const bls_sig = @import("bls_sig.zig");
const schememod = @import("scheme.zig");
const burn = @import("burn.zig");

pub const Fr = scalarmod.Fr;

pub const ThresholdError = error{
    /// `splitSecretKey`'s own "invalid parameters" cases: `t == 0`,
    /// `n == 0`, `t > n`, or `coefficients.len != t - 1` — mirrors
    /// `frost.TrustedDealerKeygenError.InvalidParameters` (RFC 9591
    /// Appendix C's identical precondition on `secret_share_shard`).
    InvalidParameters,
    /// A participant index was `0` (wire-decoded by any `fromBytes`, or
    /// carried by an in-memory-constructed partial handed to
    /// `combineSignatures`). Shamir/Feldman indices are evaluation
    /// points `x_i`; `x = 0` is reserved for the SECRET itself
    /// (`f(0) = sk`) and is never a valid participant index — mirrors
    /// RFC 9591's own `NonZeroScalar` `Identifier` convention
    /// (`frost.Identifier.fromU16`/`fromBytes`, both of which reject 0).
    ZeroIndex,
    /// A serialized value's length or count field did not match the
    /// expected wire shape (`VerificationVector.fromBytesAlloc`).
    InvalidEncoding,
    /// `combineSignatures` was given fewer than `t` partial signatures
    /// (or `t == 0`) — Lagrange interpolation cannot determine a unique
    /// degree-`(t-1)` polynomial from fewer than `t` points.
    InsufficientShares,
    /// `combineSignatures` was given two or more partials carrying the
    /// SAME index — Lagrange interpolation is undefined on a repeated
    /// node, and this is almost always a caller bug (the same partial
    /// submitted twice, or two distinct signers accidentally dealt the
    /// same share index).
    DuplicateIndex,
} || std.mem.Allocator.Error || g1.G1Error || g2.G2Error || scalarmod.FrError;

// ── wire types ───────────────────────────────────────────────────────

/// One participant's Shamir share of a BLS secret key: `index` is the
/// polynomial evaluation point `x_i` (`1 <= index`, conventionally
/// `1..=n` for an `n`-participant dealing — see `splitSecretKey`),
/// `scalar` is `f(index)` for the dealer's sharing polynomial `f`
/// (`f(0) = sk`). SECRET: `scalar` must be handled with the same care
/// as a `bls_sig.SecretKey.scalar` (never logged, zeroed after use by a
/// careful caller, etc — this module does not itself add any
/// additional handling beyond what `Fr` already provides). The same type
/// for every ciphersuite: a share is a scalar, like `SecretKey`.
pub const SecretKeyShare = struct {
    index: u32,
    scalar: Fr,

    pub const encoded_bytes = 4 + Fr.encoded_bytes; // 36

    /// REAL: `index` big-endian (4 bytes) `||` `Fr.toBytes()` (32
    /// bytes) — mechanical concatenation over already-real codecs. Into
    /// `out`: the encoding is a secret, never returned through the stack.
    pub fn toBytes(self: *const SecretKeyShare, out: *[encoded_bytes]u8) void {
        burn.run(burn.codec_burn, void, toBytesBody, .{ self, out });
    }

    fn toBytesBody(self: *const SecretKeyShare, out: *[encoded_bytes]u8) void {
        std.mem.writeInt(u32, out[0..4], self.index, .big);
        out[4..encoded_bytes].* = self.scalar.toBytes();
    }

    /// REAL. Rejects `index == 0` (see `ThresholdError.ZeroIndex`) and
    /// a non-canonical scalar (`Fr.fromBytes`'s own `>= r` rejection).
    /// The share is written to `out`; on error its scalar is zeroed.
    pub fn fromBytes(out: *SecretKeyShare, bytes: *const [encoded_bytes]u8) ThresholdError!void {
        burn.run(burn.codec_burn, ThresholdError!void, fromBytesBody, .{ out, bytes }) catch |e| {
            out.deinit();
            return e;
        };
    }

    fn fromBytesBody(out: *SecretKeyShare, bytes: *const [encoded_bytes]u8) ThresholdError!void {
        const index = std.mem.readInt(u32, bytes[0..4], .big);
        if (index == 0) return error.ZeroIndex;
        out.scalar = try Fr.fromBytes(bytes[4..encoded_bytes].*);
        out.index = index;
    }

    /// Zeroize the secret `scalar` field in place; `index` is a public
    /// share identifier (not secret) and is left untouched. Idempotent.
    /// Hygiene only — no effect on any public share/signature already
    /// derived from it.
    pub fn deinit(self: *SecretKeyShare) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.scalar));
    }
};

/// Shamir polynomial evaluation `f(index)` via Horner's method, over
/// `Fr`:
///
/// ```text
/// acc = 0
/// // coefficients holds a_1..a_{t-1}; visit HIGHEST degree first
/// for a_j in reverse(coefficients):
///     acc = acc * Fr(index) + a_j
/// return acc * Fr(index) + secret          // constant term (a_0 = secret) added LAST
/// ```
///
/// (`frost.trustedDealerKeygen`'s inline `while (j > 0)` Horner loop is
/// the byte-for-byte-identical shape over `Secp256k1.scalar.Scalar`
/// instead of this module's `Fr` — that loop, ported directly with the
/// field type and the `x` encoding swapped: `index` here is a plain
/// `u32`, not a `frost.Identifier`, converted to an `Fr` via
/// `frFromIndex`.) SECRET-touching: `secret` and every entry of
/// `coefficients` are secret, and the polynomial's OUTPUT (a Shamir
/// share) is secret too — every operation here goes through `Fr`'s
/// already-constant-time `add`/`mul` (`scalar.zig`, `std.crypto.ff`
/// Montgomery arithmetic), with no secret-dependent branching (the loop
/// bound `coefficients.len` and `index` are both PUBLIC, so looping/
/// indexing on them is fine). Variant-independent: a share is a scalar.
fn evalPolynomialAt(secret: Fr, coefficients: []const Fr, index: u32) Fr {
    const x = frFromIndex(index);
    var acc = Fr.zero;
    var j: usize = coefficients.len;
    while (j > 0) : (j -= 1) acc = acc.mul(x).add(coefficients[j - 1]);
    return acc.mul(x).add(secret); // constant term (a_0 = secret) last
}

/// Converts a PUBLIC participant index (a Shamir evaluation point) to
/// its `Fr` element via a zero-padded 32-byte big-endian encoding.
/// Every `u32` is far below the group order `r` (~2^255), so
/// `Fr.fromBytes`'s canonicality rejection can never fire.
fn frFromIndex(index: u32) Fr {
    var buf = @as([Fr.encoded_bytes]u8, @splat(0));
    std.mem.writeInt(u32, buf[Fr.encoded_bytes - 4 ..][0..4], index, .big);
    return Fr.fromBytes(buf) catch unreachable; // u32 << r: always canonical
}

// ── the threshold layer of one ciphersuite ──────────────────────────

/// Trusted-dealer threshold BLS over the ciphersuite `scheme.Bls(variant,
/// scheme)` — the same generalisation `scheme.zig` made of the signature
/// suites: `PkGroup` carries the Feldman commitments, the public key
/// shares and the group key (`G1` for min-pk, `G2` for min-sig), and
/// `SigGroup` the partial and combined signatures (`G2` for min-pk, `G1`
/// for min-sig). `partialSign`/`verifyPartialSignature` are the suite's
/// own `sign`/`verify` under a share, so the combined signature is
/// byte-for-byte that suite's `sign(&sk, msg)`.
///
/// Basic and ProofOfPossession only. MessageAugmentation signs
/// `SkToPk(SK) || msg` (draft §3.2.1): under a share that prefix is the
/// share's own public key, a different message per signer, so the
/// partials do not interpolate to `sign(&sk, msg)` — rejected at compile
/// time rather than produce a signature nothing verifies. Threshold
/// deployments use Basic (drand: min-pk chained and min-sig quicknet)
/// or POP.
pub fn Threshold(comptime variant: schememod.Variant, comptime scheme: schememod.Scheme) type {
    if (scheme == .message_augmentation)
        @compileError("threshold BLS: MessageAugmentation signs SkToPk(share) || msg, which does not interpolate; use .basic or .proof_of_possession");
    return struct {
        const Layer = @This();
        /// The ciphersuite this threshold layer signs and verifies under.
        pub const Suite = schememod.Bls(variant, scheme);
        /// The group of the commitments, key shares and group key.
        pub const PkGroup = Suite.PkGroup;
        /// The group of the partial and combined signatures.
        pub const SigGroup = Suite.SigGroup;

        /// Participant `index`'s PUBLIC verifying share `[share_i]P` (a
        /// `PkGroup` point, the suite's `PublicKey` shape). Obtained
        /// either by evaluating a dealer's `VerificationVector` at `index`
        /// (`derivePublicKeyShare`, without ever seeing `share_i` itself —
        /// the VSS-consistency property) or, degenerately, by a participant
        /// computing `Suite.skToPk` on their own `SecretKeyShare` directly.
        pub const PublicKeyShare = struct {
            index: u32,
            point: PkGroup.Affine,

            /// 52 bytes for min-pk, 100 for min-sig.
            pub const encoded_bytes = 4 + PkGroup.compressed_bytes;

            /// REAL: `index` big-endian `||` the compressed point.
            pub fn toBytes(self: Layer.PublicKeyShare) [encoded_bytes]u8 {
                var out: [encoded_bytes]u8 = undefined;
                std.mem.writeInt(u32, out[0..4], self.index, .big);
                out[4..encoded_bytes].* = PkGroup.toBytesCompressed(self.point);
                return out;
            }

            /// REAL. Rejects `index == 0`; `point` is checked on-curve and
            /// in the subgroup by `fromBytesCompressed` (the identity still
            /// decodes; `verifyPartialSignature` refuses it through the
            /// suite's `verify` and its `keyValidate`).
            pub fn fromBytes(bytes: [encoded_bytes]u8) ThresholdError!Layer.PublicKeyShare {
                const index = std.mem.readInt(u32, bytes[0..4], .big);
                if (index == 0) return error.ZeroIndex;
                const point = try PkGroup.fromBytesCompressed(bytes[4..encoded_bytes].*);
                return .{ .index = index, .point = point };
            }
        };

        /// Participant `index`'s partial signature: `[share_i]H(msg)` (a
        /// `SigGroup` point, the suite's `Signature` shape). Produced by
        /// `partialSign`, consumed by `verifyPartialSignature` and
        /// `combineSignatures`.
        pub const PartialSignature = struct {
            index: u32,
            point: SigGroup.Affine,

            /// 100 bytes for min-pk, 52 for min-sig.
            pub const encoded_bytes = 4 + SigGroup.compressed_bytes;

            /// REAL: `index` big-endian `||` the compressed point.
            pub fn toBytes(self: Layer.PartialSignature) [encoded_bytes]u8 {
                var out: [encoded_bytes]u8 = undefined;
                std.mem.writeInt(u32, out[0..4], self.index, .big);
                out[4..encoded_bytes].* = SigGroup.toBytesCompressed(self.point);
                return out;
            }

            /// REAL. Rejects `index == 0`; `point` is checked on-curve and
            /// in the subgroup by `fromBytesCompressed`, so
            /// `combineSignatures` never sees a torsion component from a
            /// decoded partial.
            pub fn fromBytes(bytes: [encoded_bytes]u8) ThresholdError!Layer.PartialSignature {
                const index = std.mem.readInt(u32, bytes[0..4], .big);
                if (index == 0) return error.ZeroIndex;
                const point = try SigGroup.fromBytesCompressed(bytes[4..encoded_bytes].*);
                return .{ .index = index, .point = point };
            }
        };

        /// A Feldman VSS commitment to the dealer's degree-`(t-1)` sharing
        /// polynomial `f(x) = sk + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}`:
        /// `commitments[j] = [a_j]P` (`P` the `PkGroup` generator) for `j`
        /// in `0..t` (`a_0 := sk`), so `commitments[0] == [sk]P`
        /// (`groupPublicKey`) and `commitments.len == t` (`threshold()`).
        /// PUBLIC — this is the information the dealer broadcasts alongside
        /// the (secret, out-of-band) per-participant shares, letting every
        /// participant verify their own share (and derive anyone else's
        /// PUBLIC key share) without trusting the dealer any further. Owned
        /// slice: free `commitments` with the same allocator that produced
        /// it (`splitSecretKey`/`fromBytesAlloc`).
        pub const VerificationVector = struct {
            commitments: []const PkGroup.Affine,

            /// `t`, the reconstruction threshold this vector commits to.
            /// REAL: plain length read.
            pub fn threshold(self: Layer.VerificationVector) usize {
                return self.commitments.len;
            }

            /// Length-prefixed encoding: `u32-BE count || commitments[0] ||
            /// ... || commitments[count-1]` (each a compressed `PkGroup`
            /// point: 48 bytes for min-pk, 96 for min-sig). REAL —
            /// mechanical concatenation, the same "allocate the exact owned
            /// slice, encode in order" shape as `frost.
            /// encodeGroupCommitmentList`. Caller frees the returned slice
            /// with `allocator`.
            pub fn toBytesAlloc(self: Layer.VerificationVector, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
                const out = try allocator.alloc(u8, 4 + self.commitments.len * PkGroup.compressed_bytes);
                std.mem.writeInt(u32, out[0..4], @intCast(self.commitments.len), .big);
                for (self.commitments, 0..) |c, i| {
                    const off = 4 + i * PkGroup.compressed_bytes;
                    out[off..][0..PkGroup.compressed_bytes].* = PkGroup.toBytesCompressed(c);
                }
                return out;
            }

            /// Inverse of `toBytesAlloc`. REAL: validates the length-prefix
            /// against the actual byte length, then decodes each compressed
            /// point (on-curve and subgroup checked by
            /// `fromBytesCompressed`, so `groupPublicKey`/
            /// `derivePublicKeyShare` never fold a torsion component from a
            /// dealer's broadcast into a key). Caller frees the returned
            /// `commitments` slice with `allocator`.
            pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) ThresholdError!Layer.VerificationVector {
                if (bytes.len < 4) return error.InvalidEncoding;
                const count = std.mem.readInt(u32, bytes[0..4], .big);
                const expected_len = 4 + @as(usize, count) * PkGroup.compressed_bytes;
                if (bytes.len != expected_len) return error.InvalidEncoding;

                const commitments = try allocator.alloc(PkGroup.Affine, count);
                errdefer allocator.free(commitments);
                for (commitments, 0..) |*slot, i| {
                    const off = 4 + i * PkGroup.compressed_bytes;
                    slot.* = try PkGroup.fromBytesCompressed(bytes[off..][0..PkGroup.compressed_bytes].*);
                }
                return .{ .commitments = commitments };
            }
        };

        // ── trusted-dealer split (Shamir + Feldman) ─────────────────

        /// `splitSecretKey`'s return value: `n` shares plus the `t`-length
        /// Feldman commitment to the sharing polynomial. `shares` and
        /// `vvec.commitments` are TWO SEPARATE owned allocations (both made
        /// with the same `allocator` passed to `splitSecretKey`) — free
        /// each individually.
        pub const SplitResult = struct {
            shares: []SecretKeyShare,
            vvec: Layer.VerificationVector,
        };

        /// Trusted-dealer Shamir splitting of `sk` into `n` shares
        /// reconstructible by any `t` of them, PLUS a Feldman VSS
        /// commitment so every share is publicly checkable
        /// (`derivePublicKeyShare`) without revealing any share value.
        /// Mirrors `frost.trustedDealerKeygen` (`secret_share_shard` +
        /// `vss_commit`, RFC 9591 Appendix C.1/C.2) over THIS module's
        /// `Fr`/`PkGroup` instead of secp256k1 — the identical two-part
        /// construction:
        ///
        /// ```text
        /// // 1. secret_share_shard (Shamir): the degree-(t-1) polynomial
        /// //      f(x) = sk + coefficients[0]*x + ... + coefficients[t-2]*x^(t-1)
        /// //    (coefficients is the caller-supplied RANDOM a_1..a_{t-1}; f(0) = sk)
        /// for i in 1..=n:
        ///     shares[i] = (i, f(i))                 // Horner's method — evalPolynomialAt
        ///
        /// // 2. vss_commit (Feldman): one PkGroup commitment per coefficient
        /// commitments[0] = [sk]P
        /// commitments[j] = [coefficients[j-1]]P      for j in 1..t            // feldmanCommitCoefficient
        /// ```
        ///
        /// `coefficients` is CALLER-SUPPLIED randomness (length exactly
        /// `t - 1`), not sampled internally — the same "deterministic entry
        /// point" shape `frost.trustedDealerKeygen` uses for its own
        /// `coefficients` parameter (reproducible tests; a real
        /// deployment's caller samples fresh coefficients via
        /// `Fr.random`/`std.Io`, once per dealing, and discards them
        /// immediately after — retaining them defeats Shamir's security
        /// exactly as retaining `sk` itself would). The shares are the same
        /// for every ciphersuite; only the commitments' group differs.
        pub fn splitSecretKey(
            allocator: std.mem.Allocator,
            sk: *const bls_sig.SecretKey,
            t: u32,
            n: u32,
            coefficients: []const Fr,
        ) ThresholdError!Layer.SplitResult {
            return burn.run(burn.sign_burn, ThresholdError!Layer.SplitResult, splitSecretKeyBody, .{ allocator, sk, t, n, coefficients });
        }

        fn splitSecretKeyBody(
            allocator: std.mem.Allocator,
            sk: *const bls_sig.SecretKey,
            t: u32,
            n: u32,
            coefficients: []const Fr,
        ) ThresholdError!Layer.SplitResult {
            if (t == 0 or n == 0 or t > n) return error.InvalidParameters;
            if (coefficients.len != @as(usize, t) - 1) return error.InvalidParameters;

            const shares = try allocator.alloc(SecretKeyShare, n);
            errdefer {
                // The shares are secrets: wipe them before the heap hands them on.
                std.crypto.secureZero(u8, std.mem.sliceAsBytes(shares));
                allocator.free(shares);
            }
            var i: u32 = 1;
            while (i <= n) : (i += 1) {
                shares[i - 1] = .{ .index = i, .scalar = evalPolynomialAt(sk.scalar, coefficients, i) };
            }

            const commitments = try allocator.alloc(PkGroup.Affine, t);
            errdefer allocator.free(commitments);
            for (commitments, 0..) |*slot, j| {
                const coeff = if (j == 0) sk.scalar else coefficients[j - 1];
                slot.* = feldmanCommitCoefficient(coeff);
            }

            return .{ .shares = shares, .vvec = .{ .commitments = commitments } };
        }

        /// One Feldman VSS commitment: `[coeff]P` — PUBLIC output, but
        /// `coeff` itself is a secret polynomial coefficient (or `sk`
        /// itself, for `j == 0`), so the multiplication MUST use the
        /// group's constant-time `scalarMul` — this is EXACTLY the suite's
        /// `skToPk` construction, one call site removed (`g1.zig`'s and
        /// `g2.zig`'s `Jacobian.scalarMul` are both constant-time
        /// double-and-add-always).
        fn feldmanCommitCoefficient(coeff: Fr) PkGroup.Affine {
            return PkGroup.Jacobian.fromAffine(PkGroup.Affine.generator).scalarMul(coeff).toAffine();
        }

        // ── public-key-share derivation ─────────────────────────────

        /// The group's BLS public key: `vvec.commitments[0]`, i.e.
        /// `[sk]P` — the same "`vss_commitment[0]` IS the group public key"
        /// identity RFC 9591 Appendix C documents (`frost.
        /// TrustedDealerKeygenResult.group_public_key`). REAL: plain
        /// indexing, no field/group arithmetic of its own.
        pub fn groupPublicKey(vvec: Layer.VerificationVector) Suite.PublicKey {
            return .{ .point = vvec.commitments[0] };
        }

        /// Evaluates the Feldman commitment polynomial
        /// `C(x) = commitments[0] + commitments[1]*x + ... + commitments[t-1]*x^(t-1)`
        /// AT `x = index`, IN THE EXPONENT — no discrete log needed, since
        /// `C(x) == [f(x)]P` for the SAME sharing polynomial `f`
        /// `splitSecretKey` dealt shares from (linearity of `[.]P` in the
        /// coefficients). This reconstructs participant `index`'s PUBLIC
        /// key share WITHOUT ever seeing that participant's secret share
        /// `f(index)` — the defining VSS-consistency property:
        /// `derivePublicKeyShare(vvec, i)` MUST equal `[share_i]P` for every
        /// share `splitSecretKey` dealt, which is exactly what this file's
        /// Feldman-consistency test checks.
        ///
        /// Construction — Horner's method IN THE EXPONENT (mirrors
        /// `evalPolynomialAt`'s scalar-field Horner loop one tower level
        /// up; `index` is PUBLIC here, unlike `evalPolynomialAt`'s secret
        /// coefficients, so a variable-time ladder would be an acceptable
        /// follow-up optimization):
        ///
        /// ```text
        /// x = Fr(index)
        /// acc = commitments[t-1]
        /// for j in (t-2)..=0:
        ///     acc = [x]acc + commitments[j]
        /// return PublicKeyShare{ .index = index, .point = acc }   // == Σ_j x^j * commitments[j]
        /// ```
        pub fn derivePublicKeyShare(vvec: Layer.VerificationVector, index: u32) Layer.PublicKeyShare {
            const x = frFromIndex(index);
            const commitments = vvec.commitments;
            var acc = PkGroup.Jacobian.fromAffine(commitments[commitments.len - 1]);
            var j: usize = commitments.len - 1;
            while (j > 0) : (j -= 1) {
                acc = acc.scalarMul(x).add(PkGroup.Jacobian.fromAffine(commitments[j - 1]));
            }
            return .{ .index = index, .point = acc.toAffine() };
        }

        // ── partial signing / verification (thin over the suite) ────

        /// A participant's non-interactive partial signature:
        /// `[share.scalar]H(msg)` — EXACTLY the suite's `sign`, called with
        /// the SHARE's scalar instead of the whole secret key. This is the
        /// entire reason threshold BLS needs no interactive signing round:
        /// `sign`'s equation `R = SK * H(msg)` is LINEAR in `SK`, so any
        /// Shamir-shared piece of `SK` produces a correspondingly-shared
        /// piece of `R`, and Lagrange interpolation in the exponent
        /// (`combineSignatures`) recombines the pieces exactly as it would
        /// recombine the secret key itself. A thin wrapper over the
        /// suite's already-constant-time `sign`.
        pub fn partialSign(share: *const SecretKeyShare, msg: []const u8) Layer.PartialSignature {
            return burn.run(burn.sign_burn, Layer.PartialSignature, partialSignBody, .{ share, msg });
        }

        fn partialSignBody(share: *const SecretKeyShare, msg: []const u8) Layer.PartialSignature {
            const partial_sk: bls_sig.SecretKey = .{ .scalar = share.scalar };
            const sig = Suite.sign(&partial_sk, msg);
            return .{ .index = share.index, .point = sig.point };
        }

        /// Checks partial signature `partial` against participant
        /// `partial.index`'s public key share `pk_share` (obtained via
        /// `derivePublicKeyShare`, or a participant's own `Suite.skToPk` on
        /// their `SecretKeyShare`) — lets a Coordinator identify a
        /// misbehaving signer BEFORE combining, the same "Identifiable
        /// Abort" motivation as `frost.verifySignatureShare`. Once
        /// unwrapped, `pk_share.point` and `partial.point` are literally a
        /// `Suite.PublicKey`/`Suite.Signature` pair, checked by the suite's
        /// own `verify`, including ALL of that function's mandatory
        /// fail-closed subgroup/`keyValidate` checks. Returns `false`
        /// (never panics) on an index mismatch between `pk_share`/`partial`
        /// — a caller bug this function catches before any pairing work.
        pub fn verifyPartialSignature(pk_share: Layer.PublicKeyShare, msg: []const u8, partial: Layer.PartialSignature) bool {
            if (pk_share.index != partial.index) return false;
            const pk: Suite.PublicKey = .{ .point = pk_share.point };
            const sig: Suite.Signature = .{ .point = partial.point };
            return Suite.verify(pk, msg, sig);
        }

        // ── combining (SECURITY-CRITICAL) ───────────────────────────

        /// Combines `t` (or more) valid, distinctly-indexed partial
        /// signatures into ONE ordinary `Suite.Signature` — byte-for-byte
        /// the SAME signature `Suite.sign(&sk, msg)` would have produced
        /// directly, because Lagrange interpolation in the exponent
        /// reconstructs `[sk]H(msg)` from the partials' `[share_i]H(msg)`
        /// pieces exactly as `frost.secretShareCombine` reconstructs `sk`
        /// itself from `share_i` values — only every scalar multiplication
        /// happens in `SigGroup` instead of on the scalar field directly:
        ///
        /// ```text
        /// x_coords = [i for (i, _) in partials]
        /// combined = Identity
        /// for (i, partial_i) in partials:
        ///     lambda_i = Π_{j in x_coords, j != i} (0 - x_j) / (x_i - x_j)   // Fr; division via Fr.inv
        ///     combined = combined + [lambda_i] * partial_i
        /// return Signature{ .point = combined.toAffine() }
        /// ```
        ///
        /// — evaluating the unique degree-`(t-1)` polynomial the dealt
        /// shares lie on AT `x = 0` (`splitSecretKey`'s own `f(0) = sk`).
        /// Requires `>= t` DISTINCT indices among `partials` (validated
        /// first); MORE than `t` distinct, mutually-consistent partials
        /// reconstruct the SAME unique low-degree polynomial (the reasoning
        /// `frost.secretShareCombine`'s own doc comment gives). The explicit
        /// `t` lets a too-small set be refused up front.
        ///
        /// The distinct-index / minimum-count / nonzero-index checks run
        /// first (mechanical, no field/group arithmetic — the same `O(n^2)`
        /// public-index comparison `frost.deriveInterpolatingValue`/
        /// `secretShareCombine` use; index `0` is additionally rejected
        /// here because an in-memory-constructed partial bypasses
        /// `PartialSignature.fromBytes`'s own `ZeroIndex` check, and `x = 0`
        /// as a Lagrange node would silently return that partial VERBATIM
        /// instead of interpolating). All index arithmetic is over PUBLIC
        /// values (see the module doc comment's const-time note); `Fr.inv`
        /// is constant-time regardless.
        pub fn combineSignatures(partials: []const Layer.PartialSignature, t: u32) ThresholdError!Suite.Signature {
            if (t == 0 or partials.len < t) return error.InsufficientShares;
            for (partials, 0..) |a, i| {
                if (a.index == 0) return error.ZeroIndex;
                for (partials[i + 1 ..]) |b| {
                    if (a.index == b.index) return error.DuplicateIndex;
                }
            }

            var combined = SigGroup.Jacobian.identity;
            for (partials) |partial_i| {
                // lambda_i = Π_{j != i} x_j * (x_j - x_i)^-1 — frost.
                // deriveInterpolatingValue's exact numerator/denominator-
                // product form (equivalently Π (0 - x_j)/(x_i - x_j): both
                // signs flip, so the quotient is identical).
                const xi = frFromIndex(partial_i.index);
                var numerator = Fr.one;
                var denominator = Fr.one;
                for (partials) |partial_j| {
                    if (partial_j.index == partial_i.index) continue;
                    const xj = frFromIndex(partial_j.index);
                    numerator = numerator.mul(xj);
                    denominator = denominator.mul(xj.sub(xi));
                }
                // Every factor x_j - x_i is nonzero (indices are distinct
                // u32s < r, so distinct as Fr elements), and a product of
                // nonzero elements of the prime field Fr is nonzero —
                // invertible.
                const lambda_i = numerator.mul(denominator.inv() catch unreachable);
                combined = combined.add(SigGroup.Jacobian.fromAffine(partial_i.point).scalarMul(lambda_i));
            }
            return .{ .point = combined.toAffine() };
        }
    };
}

/// The min-pk ProofOfPossession threshold layer — Ethereum's suite and
/// `bls_sig`'s file-level one. The file-level names below are this
/// instance, kept as they were before min-sig existed.
pub const MinPk = Threshold(.min_pk, .proof_of_possession);
/// The min-sig ProofOfPossession threshold layer (`G2` keys and commitments,
/// `G1` partial and combined signatures; signs and verifies as
/// `bls_sig.MinSigPop`). `Threshold(.min_sig, .basic)` is drand quicknet's.
pub const MinSig = Threshold(.min_sig, .proof_of_possession);

pub const PublicKeyShare = MinPk.PublicKeyShare;
pub const PartialSignature = MinPk.PartialSignature;
pub const VerificationVector = MinPk.VerificationVector;
pub const SplitResult = MinPk.SplitResult;
pub const splitSecretKey = MinPk.splitSecretKey;
pub const groupPublicKey = MinPk.groupPublicKey;
pub const derivePublicKeyShare = MinPk.derivePublicKeyShare;
pub const partialSign = MinPk.partialSign;
pub const verifyPartialSignature = MinPk.verifyPartialSignature;
pub const combineSignatures = MinPk.combineSignatures;

// ── tests: wire/plumbing ─────────────────────────────────────────────

test "SecretKeyShare/PublicKeyShare/PartialSignature byte codecs round-trip" {
    const sk_share: SecretKeyShare = .{ .index = 3, .scalar = try Fr.fromBytes(@as([31]u8, @splat(0)) ++ [_]u8{7}) };
    var sk_bytes: [SecretKeyShare.encoded_bytes]u8 = undefined;
    sk_share.toBytes(&sk_bytes);
    try std.testing.expectEqual(@as(usize, 36), sk_bytes.len);
    var sk_back: SecretKeyShare = undefined;
    try SecretKeyShare.fromBytes(&sk_back, &sk_bytes);
    try std.testing.expectEqual(sk_share.index, sk_back.index);
    try std.testing.expect(sk_share.scalar.eql(sk_back.scalar));

    const pk_share: PublicKeyShare = .{ .index = 5, .point = g1.Affine.generator };
    const pk_bytes = pk_share.toBytes();
    try std.testing.expectEqual(@as(usize, 52), pk_bytes.len);
    const pk_back = try PublicKeyShare.fromBytes(pk_bytes);
    try std.testing.expectEqual(pk_share.index, pk_back.index);
    try std.testing.expect(pk_share.point.x.eql(pk_back.point.x));

    const partial: PartialSignature = .{ .index = 2, .point = g2.Affine.generator };
    const partial_bytes = partial.toBytes();
    try std.testing.expectEqual(@as(usize, 100), partial_bytes.len);
    const partial_back = try PartialSignature.fromBytes(partial_bytes);
    try std.testing.expectEqual(partial.index, partial_back.index);
    try std.testing.expect(partial.point.x.c0.eql(partial_back.point.x.c0));
}

test "SecretKeyShare.deinit zeroizes scalar but leaves index untouched (regression: fails if secureZero is removed)" {
    var sk_share: SecretKeyShare = .{ .index = 3, .scalar = try Fr.fromBytes(@as([31]u8, @splat(0)) ++ [_]u8{7}) };
    // `Fr`'s in-memory (Montgomery) size may exceed its 32-byte canonical
    // encoding, so assert over the raw struct bytes, not a fixed-width buffer.
    var any_nonzero = false;
    for (std.mem.asBytes(&sk_share.scalar)) |b| {
        if (b != 0) any_nonzero = true;
    }
    try std.testing.expect(any_nonzero);
    sk_share.deinit();
    for (std.mem.asBytes(&sk_share.scalar)) |b| try std.testing.expectEqual(@as(u8, 0), b);
    try std.testing.expectEqual(@as(u32, 3), sk_share.index);
}

test "SecretKeyShare/PublicKeyShare/PartialSignature fromBytes rejects a zero index" {
    var sk_bytes = @as([SecretKeyShare.encoded_bytes]u8, @splat(0));
    sk_bytes[SecretKeyShare.encoded_bytes - 1] = 1; // scalar = 1, index = 0
    var bad_share: SecretKeyShare = undefined;
    try std.testing.expectError(error.ZeroIndex, SecretKeyShare.fromBytes(&bad_share, &sk_bytes));

    var pk_bytes = @as([PublicKeyShare.encoded_bytes]u8, @splat(0));
    pk_bytes[4..PublicKeyShare.encoded_bytes].* = g1.toBytesCompressed(g1.Affine.generator);
    try std.testing.expectError(error.ZeroIndex, PublicKeyShare.fromBytes(pk_bytes));

    var sig_bytes = @as([PartialSignature.encoded_bytes]u8, @splat(0));
    sig_bytes[4..PartialSignature.encoded_bytes].* = g2.toBytesCompressed(g2.Affine.generator);
    try std.testing.expectError(error.ZeroIndex, PartialSignature.fromBytes(sig_bytes));
}

test "VerificationVector toBytesAlloc/fromBytesAlloc round-trip" {
    const allocator = std.testing.allocator;
    const commitments = [_]g1.Affine{
        g1.Affine.generator,
        g1.Jacobian.fromAffine(g1.Affine.generator).double().toAffine(),
    };
    const vvec: VerificationVector = .{ .commitments = &commitments };
    try std.testing.expectEqual(@as(usize, 2), vvec.threshold());

    const bytes = try vvec.toBytesAlloc(allocator);
    defer allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 4 + 2 * g1.compressed_bytes), bytes.len);

    const back = try VerificationVector.fromBytesAlloc(allocator, bytes);
    defer allocator.free(back.commitments);
    try std.testing.expectEqual(@as(usize, 2), back.threshold());
    try std.testing.expect(back.commitments[0].x.eql(commitments[0].x));
    try std.testing.expect(back.commitments[1].x.eql(commitments[1].x));
}

test "VerificationVector.fromBytesAlloc rejects a length/count mismatch" {
    const allocator = std.testing.allocator;
    var bytes = @as([4]u8, @splat(0));
    std.mem.writeInt(u32, bytes[0..4], 3, .big); // claims 3 commitments, has 0
    try std.testing.expectError(error.InvalidEncoding, VerificationVector.fromBytesAlloc(allocator, &bytes));

    // Trailing bytes past the declared count are refused too (mutation
    // run 2026-10-05: `!=` weakened to `<` survived).
    var long = @as([4 + g1.compressed_bytes + 1]u8, @splat(0));
    std.mem.writeInt(u32, long[0..4], 1, .big);
    long[4..][0..g1.compressed_bytes].* = g1.toBytesCompressed(g1.Affine.generator);
    const exact = try VerificationVector.fromBytesAlloc(allocator, long[0 .. long.len - 1]);
    allocator.free(exact.commitments);
    try std.testing.expectError(error.InvalidEncoding, VerificationVector.fromBytesAlloc(allocator, &long));
}

test "groupPublicKey extracts commitments[0]" {
    const commitments = [_]g1.Affine{
        g1.Affine.generator,
        g1.Jacobian.fromAffine(g1.Affine.generator).double().toAffine(),
    };
    const vvec: VerificationVector = .{ .commitments = &commitments };
    const pk = groupPublicKey(vvec);
    try std.testing.expect(pk.point.x.eql(g1.Affine.generator.x));
}

test "splitSecretKey rejects invalid (t, n, coefficients) combinations before any crypto work" {
    const allocator = std.testing.allocator;
    var sk: bls_sig.SecretKey = undefined;
    try bls_sig.keyGen(&sk, &(@as([32]u8, @splat(0x9a))), "");
    try std.testing.expectError(error.InvalidParameters, splitSecretKey(allocator, &sk, 0, 5, &.{}));
    try std.testing.expectError(error.InvalidParameters, splitSecretKey(allocator, &sk, 3, 0, &.{}));
    try std.testing.expectError(error.InvalidParameters, splitSecretKey(allocator, &sk, 4, 3, &.{ Fr.one, Fr.one, Fr.one }));
    // t=3 needs exactly 2 coefficients; supplying 1 must be rejected
    // before any polynomial evaluation is attempted.
    try std.testing.expectError(error.InvalidParameters, splitSecretKey(allocator, &sk, 3, 5, &.{Fr.one}));
}

test "combineSignatures rejects too few, duplicate-indexed, or zero-indexed partials before any crypto work" {
    const partials = [_]PartialSignature{
        .{ .index = 1, .point = g2.Affine.generator },
        .{ .index = 2, .point = g2.Affine.generator },
    };
    try std.testing.expectError(error.InsufficientShares, combineSignatures(&partials, 3));
    try std.testing.expectError(error.InsufficientShares, combineSignatures(&partials, 0));

    const dup_partials = [_]PartialSignature{
        .{ .index = 1, .point = g2.Affine.generator },
        .{ .index = 1, .point = g2.Affine.generator },
    };
    try std.testing.expectError(error.DuplicateIndex, combineSignatures(&dup_partials, 2));

    // An in-memory-constructed partial can carry index 0 (fromBytes
    // would have rejected it); combineSignatures must too — x = 0 is
    // the SECRET's own evaluation point, never a participant's.
    const zero_partials = [_]PartialSignature{
        .{ .index = 0, .point = g2.Affine.generator },
        .{ .index = 2, .point = g2.Affine.generator },
    };
    try std.testing.expectError(error.ZeroIndex, combineSignatures(&zero_partials, 2));
}

test "partialSign/verifyPartialSignature round-trip in isolation (a share IS just a bls_sig.SecretKey)" {
    // A hand-rolled "share" (not dealt via splitSecretKey — this test
    // exercises partialSign/verifyPartialSignature in isolation, both
    // of which are REAL today) — any nonzero Fr scalar behaves exactly
    // like an ordinary bls_sig.SecretKey for these two functions' own
    // contracts, since partialSign IS bls_sig.sign under the hood.
    var sk: bls_sig.SecretKey = undefined;
    try bls_sig.keyGen(&sk, &(@as([32]u8, @splat(0x5c))), "");
    const share: SecretKeyShare = .{ .index = 7, .scalar = sk.scalar };
    const pk_share: PublicKeyShare = .{ .index = 7, .point = bls_sig.skToPk(&sk).point };

    const msg = "threshold BLS partial signing, no dealer involved";
    const partial = partialSign(&share, msg);
    try std.testing.expectEqual(@as(u32, 7), partial.index);
    try std.testing.expect(verifyPartialSignature(pk_share, msg, partial));

    // The plain bls_sig equation agrees: a partial signed with a
    // share's raw scalar IS an ordinary bls_sig.sign output under the
    // corresponding bls_sig public key.
    const ordinary_sig = bls_sig.sign(&sk, msg);
    try std.testing.expectEqualSlices(u8, &ordinary_sig.toBytes(), &(bls_sig.Signature{ .point = partial.point }).toBytes());

    // Wrong message, wrong key, and an index mismatch must all reject.
    try std.testing.expect(!verifyPartialSignature(pk_share, "wrong message", partial));
    var other_sk: bls_sig.SecretKey = undefined;
    try bls_sig.keyGen(&other_sk, &(@as([32]u8, @splat(0x5d))), "");
    const other_pk_share: PublicKeyShare = .{ .index = 7, .point = bls_sig.skToPk(&other_sk).point };
    try std.testing.expect(!verifyPartialSignature(other_pk_share, msg, partial));
    const mismatched_partial: PartialSignature = .{ .index = 8, .point = partial.point };
    try std.testing.expect(!verifyPartialSignature(pk_share, msg, mismatched_partial));
}

// ── tests: the keystone self-consistency chain ──────────────────────

/// Builds a fresh `(sk, t, n)` dealing with fixed, reproducible
/// "randomness" (test-only — a real deployment MUST use genuinely
/// random coefficients, see `splitSecretKey`'s doc comment) and returns
/// the split result. Shared by every keystone test below so they all
/// dial the same knobs consistently.
fn testSplit(allocator: std.mem.Allocator, ikm_byte: u8, t: u32, n: u32) !struct { sk: bls_sig.SecretKey, split: SplitResult } {
    var sk: bls_sig.SecretKey = undefined;
    try bls_sig.keyGen(&sk, &(@as([32]u8, @splat(ikm_byte))), "");
    var coeffs: [8]Fr = undefined;
    var j: usize = 0;
    while (j < t - 1) : (j += 1) {
        var seed = @as([32]u8, @splat(0));
        seed[31] = @intCast(j + 1);
        seed[30] = ikm_byte;
        coeffs[j] = Fr.reduceWide(&seed);
    }
    const split = try splitSecretKey(allocator, &sk, t, n, coeffs[0 .. t - 1]);
    return .{ .sk = sk, .split = split };
}

test "keystone round trip: splitSecretKey -> partialSign (t of n) -> combineSignatures == bls_sig.sign, and verifies under groupPublicKey" {
    const allocator = std.testing.allocator;
    const t: u32 = 3;
    const n: u32 = 5;
    const built = try testSplit(allocator, 0x01, t, n);
    defer allocator.free(built.split.shares);
    defer allocator.free(built.split.vvec.commitments);

    const msg = "threshold BLS keystone round trip";
    const partials = [_]PartialSignature{
        partialSign(&built.split.shares[0], msg),
        partialSign(&built.split.shares[2], msg),
        partialSign(&built.split.shares[4], msg),
    };
    const combined = try combineSignatures(&partials, t);

    // This is the chain that ties the threshold path to Part 4's
    // eth-vector-pinned signatures: the combined signature must be
    // byte-for-byte the SAME as an ordinary bls_sig.sign, and must
    // verify under the group public key via the ordinary bls_sig.verify
    // equation.
    const expected = bls_sig.sign(&built.sk, msg);
    try std.testing.expectEqualSlices(u8, &expected.toBytes(), &combined.toBytes());
    try std.testing.expect(bls_sig.verify(groupPublicKey(built.split.vvec), msg, combined));
}

test "any t-of-n subset combines to the SAME signature (two different 3-of-5 subsets)" {
    const allocator = std.testing.allocator;
    const t: u32 = 3;
    const n: u32 = 5;
    const built = try testSplit(allocator, 0x02, t, n);
    defer allocator.free(built.split.shares);
    defer allocator.free(built.split.vvec.commitments);

    const msg = "any t-of-n subset agrees";
    const shares = built.split.shares;

    const subset_a = [_]PartialSignature{
        partialSign(&shares[0], msg),
        partialSign(&shares[1], msg),
        partialSign(&shares[2], msg),
    };
    const subset_b = [_]PartialSignature{
        partialSign(&shares[1], msg),
        partialSign(&shares[3], msg),
        partialSign(&shares[4], msg),
    };

    const combined_a = try combineSignatures(&subset_a, t);
    const combined_b = try combineSignatures(&subset_b, t);
    try std.testing.expectEqualSlices(u8, &combined_a.toBytes(), &combined_b.toBytes());

    const expected = bls_sig.sign(&built.sk, msg);
    try std.testing.expectEqualSlices(u8, &expected.toBytes(), &combined_a.toBytes());
}

test "Feldman VSS consistency: derivePublicKeyShare(vvec, i) equals [share_i]G1 for every dealt share" {
    const allocator = std.testing.allocator;
    const t: u32 = 2;
    const n: u32 = 3;
    const built = try testSplit(allocator, 0x03, t, n);
    defer allocator.free(built.split.shares);
    defer allocator.free(built.split.vvec.commitments);

    for (built.split.shares) |share| {
        const derived = derivePublicKeyShare(built.split.vvec, share.index);
        const expected = bls_sig.skToPk(&.{ .scalar = share.scalar });
        try std.testing.expectEqual(share.index, derived.index);
        try std.testing.expect(derived.point.x.eql(expected.point.x));
    }
}

test "(t=2, n=3) end-to-end keystone chain" {
    const allocator = std.testing.allocator;
    const t: u32 = 2;
    const n: u32 = 3;
    const built = try testSplit(allocator, 0x04, t, n);
    defer allocator.free(built.split.shares);
    defer allocator.free(built.split.vvec.commitments);

    const msg = "t=2,n=3 case";
    const partials = [_]PartialSignature{
        partialSign(&built.split.shares[0], msg),
        partialSign(&built.split.shares[1], msg),
    };
    const combined = try combineSignatures(&partials, t);
    const expected = bls_sig.sign(&built.sk, msg);
    try std.testing.expectEqualSlices(u8, &expected.toBytes(), &combined.toBytes());
    try std.testing.expect(bls_sig.verify(groupPublicKey(built.split.vvec), msg, combined));
}

test "fewer than t partials do NOT reconstruct the group signature (t is really the threshold)" {
    // A t=3 dealing, but only 2 partials combined (with a LYING t'=2 so
    // the count check passes): Lagrange through 2 points of a genuinely
    // degree-2 polynomial interpolates the WRONG constant term — the
    // result must neither equal bls_sig.sign nor verify under the group
    // key. (This is the caller-side precondition frost.
    // secretShareCombine's doc comment describes: too few shares give a
    // mathematically wrong answer, not an error — combineSignatures's
    // explicit `t` parameter exists precisely so an honest caller CAN
    // get the error instead, as the plumbing test above checks.)
    const allocator = std.testing.allocator;
    const built = try testSplit(allocator, 0x06, 3, 5);
    defer allocator.free(built.split.shares);
    defer allocator.free(built.split.vvec.commitments);

    const msg = "below-threshold subsets must fail";
    const partials = [_]PartialSignature{
        partialSign(&built.split.shares[0], msg),
        partialSign(&built.split.shares[1], msg),
    };
    const under = try combineSignatures(&partials, 2);
    const expected = bls_sig.sign(&built.sk, msg);
    try std.testing.expect(!std.mem.eql(u8, &expected.toBytes(), &under.toBytes()));
    try std.testing.expect(!bls_sig.verify(groupPublicKey(built.split.vvec), msg, under));
}

test "more than t distinct partials combine to the same signature (over-determined interpolation)" {
    const allocator = std.testing.allocator;
    const t: u32 = 3;
    const built = try testSplit(allocator, 0x07, t, 5);
    defer allocator.free(built.split.shares);
    defer allocator.free(built.split.vvec.commitments);

    const msg = "over-determined but consistent";
    const partials = [_]PartialSignature{
        partialSign(&built.split.shares[0], msg),
        partialSign(&built.split.shares[1], msg),
        partialSign(&built.split.shares[2], msg),
        partialSign(&built.split.shares[3], msg),
    };
    const combined = try combineSignatures(&partials, t);
    const expected = bls_sig.sign(&built.sk, msg);
    try std.testing.expectEqualSlices(u8, &expected.toBytes(), &combined.toBytes());
}

test "verifyPartialSignature over a real dealing: accepts each valid partial, rejects wrong-share and wrong-index partials" {
    const allocator = std.testing.allocator;
    const built = try testSplit(allocator, 0x08, 3, 5);
    defer allocator.free(built.split.shares);
    defer allocator.free(built.split.vvec.commitments);

    const msg = "identifiable abort: check partials before combining";
    const shares = built.split.shares;

    // Every honestly-produced partial verifies against the VSS-derived
    // public key share for its own index.
    for (shares) |share| {
        const pk_share = derivePublicKeyShare(built.split.vvec, share.index);
        try std.testing.expect(verifyPartialSignature(pk_share, msg, partialSign(&share, msg)));
    }

    // A partial made with share 2's scalar but claiming index 1 must be
    // rejected against index 1's derived public key share (wrong share
    // under the claimed identity — the misbehaving-signer case).
    const pk_share_1 = derivePublicKeyShare(built.split.vvec, 1);
    const forged: PartialSignature = .{ .index = 1, .point = partialSign(&shares[1], msg).point };
    try std.testing.expect(shares[1].index == 2); // shares[1] IS index 2
    try std.testing.expect(!verifyPartialSignature(pk_share_1, msg, forged));

    // An index mismatch between the pk share and the partial is caught
    // before any pairing work.
    const honest_1 = partialSign(&shares[0], msg);
    const relabeled: PartialSignature = .{ .index = 3, .point = honest_1.point };
    try std.testing.expect(!verifyPartialSignature(pk_share_1, msg, relabeled));
}

test "(t=n=4) end-to-end keystone chain (every share required)" {
    const allocator = std.testing.allocator;
    const t: u32 = 4;
    const n: u32 = 4;
    const built = try testSplit(allocator, 0x05, t, n);
    defer allocator.free(built.split.shares);
    defer allocator.free(built.split.vvec.commitments);

    const msg = "t=n=4 case: no slack, every share needed";
    const partials = [_]PartialSignature{
        partialSign(&built.split.shares[0], msg),
        partialSign(&built.split.shares[1], msg),
        partialSign(&built.split.shares[2], msg),
        partialSign(&built.split.shares[3], msg),
    };
    const combined = try combineSignatures(&partials, t);
    const expected = bls_sig.sign(&built.sk, msg);
    try std.testing.expectEqualSlices(u8, &expected.toBytes(), &combined.toBytes());
    try std.testing.expect(bls_sig.verify(groupPublicKey(built.split.vvec), msg, combined));
}

// ── tests: the min-sig instances (mirrors of the min-pk tests above) ─

/// The min-sig threshold layers under test: POP (`MinSig`) and Basic
/// (drand quicknet's suite).
const min_sig_layers = .{ MinSig, Threshold(.min_sig, .basic) };

/// `testSplit` for any threshold layer `T`, same deterministic knobs.
fn testSplitT(comptime T: type, allocator: std.mem.Allocator, ikm_byte: u8, t: u32, n: u32) !struct { sk: bls_sig.SecretKey, split: T.SplitResult } {
    var sk: bls_sig.SecretKey = undefined;
    try bls_sig.keyGen(&sk, &(@as([32]u8, @splat(ikm_byte))), "");
    var coeffs: [8]Fr = undefined;
    var j: usize = 0;
    while (j < t - 1) : (j += 1) {
        var seed = @as([32]u8, @splat(0));
        seed[31] = @intCast(j + 1);
        seed[30] = ikm_byte;
        coeffs[j] = Fr.reduceWide(&seed);
    }
    const split = try T.splitSecretKey(allocator, &sk, t, n, coeffs[0 .. t - 1]);
    return .{ .sk = sk, .split = split };
}

/// Reconstructs `f(0)` from shares by Lagrange interpolation over `Fr` —
/// the test-side oracle for "the reconstructed key": independent of any
/// group, so a combined signature can be compared with `sign` under it.
fn reconstructSecret(shares: []const SecretKeyShare) bls_sig.SecretKey {
    var acc = Fr.zero;
    for (shares) |si| {
        const xi = frFromIndex(si.index);
        var num = Fr.one;
        var den = Fr.one;
        for (shares) |sj| {
            if (sj.index == si.index) continue;
            const xj = frFromIndex(sj.index);
            num = num.mul(xj);
            den = den.mul(xj.sub(xi));
        }
        acc = acc.add(si.scalar.mul(num.mul(den.inv() catch unreachable)));
    }
    return .{ .scalar = acc };
}

test "min-sig: the layer's groups and wire sizes are the min-pk ones swapped" {
    inline for (min_sig_layers) |T| {
        try std.testing.expect(T.PkGroup == g2);
        try std.testing.expect(T.SigGroup == g1);
        try std.testing.expectEqual(@as(usize, 100), T.PublicKeyShare.encoded_bytes);
        try std.testing.expectEqual(@as(usize, 52), T.PartialSignature.encoded_bytes);
    }
    try std.testing.expect(MinPk.PkGroup == g1);
    try std.testing.expect(MinPk.SigGroup == g2);
    try std.testing.expect(MinSig.Suite == bls_sig.MinSigPop);
    try std.testing.expect(MinPk.Suite == bls_sig.MinPkPop);
}

test "min-sig: PublicKeyShare/PartialSignature codecs round-trip and refuse a zero index" {
    inline for (min_sig_layers) |T| {
        const pk_share: T.PublicKeyShare = .{ .index = 5, .point = g2.Affine.generator };
        const pk_back = try T.PublicKeyShare.fromBytes(pk_share.toBytes());
        try std.testing.expectEqual(pk_share.index, pk_back.index);
        try std.testing.expectEqualSlices(u8, &pk_share.toBytes(), &pk_back.toBytes());

        const partial: T.PartialSignature = .{ .index = 2, .point = g1.Affine.generator };
        const partial_back = try T.PartialSignature.fromBytes(partial.toBytes());
        try std.testing.expectEqual(partial.index, partial_back.index);
        try std.testing.expectEqualSlices(u8, &partial.toBytes(), &partial_back.toBytes());

        var pk_bytes = pk_share.toBytes();
        @memset(pk_bytes[0..4], 0);
        try std.testing.expectError(error.ZeroIndex, T.PublicKeyShare.fromBytes(pk_bytes));
        var sig_bytes = partial.toBytes();
        @memset(sig_bytes[0..4], 0);
        try std.testing.expectError(error.ZeroIndex, T.PartialSignature.fromBytes(sig_bytes));
    }
}

test "min-sig: VerificationVector codec round-trips G2 commitments and refuses a length/count mismatch" {
    const allocator = std.testing.allocator;
    inline for (min_sig_layers) |T| {
        const commitments = [_]g2.Affine{
            g2.Affine.generator,
            g2.Jacobian.fromAffine(g2.Affine.generator).double().toAffine(),
        };
        const vvec: T.VerificationVector = .{ .commitments = &commitments };
        const bytes = try vvec.toBytesAlloc(allocator);
        defer allocator.free(bytes);
        try std.testing.expectEqual(@as(usize, 4 + 2 * g2.compressed_bytes), bytes.len);
        const back = try T.VerificationVector.fromBytesAlloc(allocator, bytes);
        defer allocator.free(back.commitments);
        try std.testing.expectEqual(@as(usize, 2), back.threshold());
        try std.testing.expectEqualSlices(u8, &g2.toBytesCompressed(commitments[1]), &g2.toBytesCompressed(back.commitments[1]));
        // One byte short and one byte over: both refused.
        try std.testing.expectError(error.InvalidEncoding, T.VerificationVector.fromBytesAlloc(allocator, bytes[0 .. bytes.len - 1]));
        var long: [4 + 2 * g2.compressed_bytes + 1]u8 = undefined;
        @memcpy(long[0..bytes.len], bytes);
        long[bytes.len] = 0;
        try std.testing.expectError(error.InvalidEncoding, T.VerificationVector.fromBytesAlloc(allocator, &long));
        try std.testing.expectError(error.InvalidEncoding, T.VerificationVector.fromBytesAlloc(allocator, bytes[0..3]));
    }
}

test "min-sig: splitSecretKey and combineSignatures refuse bad parameters before any crypto work" {
    const allocator = std.testing.allocator;
    var sk: bls_sig.SecretKey = undefined;
    try bls_sig.keyGen(&sk, &(@as([32]u8, @splat(0x9a))), "");
    inline for (min_sig_layers) |T| {
        try std.testing.expectError(error.InvalidParameters, T.splitSecretKey(allocator, &sk, 0, 5, &.{}));
        try std.testing.expectError(error.InvalidParameters, T.splitSecretKey(allocator, &sk, 3, 0, &.{}));
        try std.testing.expectError(error.InvalidParameters, T.splitSecretKey(allocator, &sk, 4, 3, &.{ Fr.one, Fr.one, Fr.one }));
        try std.testing.expectError(error.InvalidParameters, T.splitSecretKey(allocator, &sk, 3, 5, &.{Fr.one}));

        const two = [_]T.PartialSignature{
            .{ .index = 1, .point = g1.Affine.generator },
            .{ .index = 2, .point = g1.Affine.generator },
        };
        try std.testing.expectError(error.InsufficientShares, T.combineSignatures(&two, 3));
        try std.testing.expectError(error.InsufficientShares, T.combineSignatures(&two, 0));
        const dup = [_]T.PartialSignature{
            .{ .index = 1, .point = g1.Affine.generator },
            .{ .index = 1, .point = g1.Affine.generator },
        };
        try std.testing.expectError(error.DuplicateIndex, T.combineSignatures(&dup, 2));
        const zero = [_]T.PartialSignature{
            .{ .index = 0, .point = g1.Affine.generator },
            .{ .index = 2, .point = g1.Affine.generator },
        };
        try std.testing.expectError(error.ZeroIndex, T.combineSignatures(&zero, 2));
    }
}

test "min-sig keystone: t-of-n combine == the suite's sign under the reconstructed key, and verifies under the min-sig suite" {
    const allocator = std.testing.allocator;
    inline for (min_sig_layers, .{ 0x11, 0x12 }) |T, ikm| {
        const t: u32 = 3;
        const built = try testSplitT(T, allocator, ikm, t, 5);
        defer allocator.free(built.split.shares);
        defer allocator.free(built.split.vvec.commitments);
        const shares = built.split.shares;

        const msg = "min-sig threshold keystone";
        const subset_a = [_]T.PartialSignature{ T.partialSign(&shares[0], msg), T.partialSign(&shares[2], msg), T.partialSign(&shares[4], msg) };
        const subset_b = [_]T.PartialSignature{ T.partialSign(&shares[1], msg), T.partialSign(&shares[3], msg), T.partialSign(&shares[4], msg) };
        const combined = try T.combineSignatures(&subset_a, t);

        // The reconstructed key (Lagrange over Fr, no group involved) is the
        // dealt key, and the combined signature is its ordinary signature.
        const rec = reconstructSecret(&.{ shares[0], shares[2], shares[4] });
        try std.testing.expect(rec.scalar.eql(built.sk.scalar));
        const direct = T.Suite.sign(&rec, msg);
        try std.testing.expectEqualSlices(u8, &direct.toBytes(), &combined.toBytes());
        try std.testing.expectEqual(@as(usize, 48), combined.toBytes().len); // a G1 signature

        // It verifies under the min-sig suite with the group key, which is
        // the suite's own skToPk of the dealt key.
        const gpk = T.groupPublicKey(built.split.vvec);
        try std.testing.expectEqualSlices(u8, &T.Suite.skToPk(&built.sk).toBytes(), &gpk.toBytes());
        try std.testing.expect(T.Suite.verify(gpk, msg, combined));
        try std.testing.expect(!T.Suite.verify(gpk, "another message", combined));

        // Any other t-subset agrees.
        try std.testing.expectEqualSlices(u8, &combined.toBytes(), &(try T.combineSignatures(&subset_b, t)).toBytes());
    }
}

test "min-sig: the combined signature belongs to its suite only (POP and Basic do not cross, min-pk differs)" {
    const allocator = std.testing.allocator;
    const built = try testSplitT(MinSig, allocator, 0x13, 2, 3);
    defer allocator.free(built.split.shares);
    defer allocator.free(built.split.vvec.commitments);
    const msg = "suite separation";
    const parts = [_]MinSig.PartialSignature{ MinSig.partialSign(&built.split.shares[0], msg), MinSig.partialSign(&built.split.shares[1], msg) };
    const combined = try MinSig.combineSignatures(&parts, 2);
    const gpk = MinSig.groupPublicKey(built.split.vvec);
    try std.testing.expect(bls_sig.MinSigPop.verify(gpk, msg, combined));
    // Same groups, different DST: Basic refuses it.
    try std.testing.expect(!bls_sig.MinSigBasic.verify(.{ .point = gpk.point }, msg, .{ .point = combined.point }));
    // The same dealing through the min-pk layer gives the min-pk signature,
    // not this one (different group, different hash).
    const built_pk = try testSplit(allocator, 0x13, 2, 3);
    defer allocator.free(built_pk.split.shares);
    defer allocator.free(built_pk.split.vvec.commitments);
    const pk_parts = [_]PartialSignature{ partialSign(&built_pk.split.shares[0], msg), partialSign(&built_pk.split.shares[1], msg) };
    const pk_combined = try combineSignatures(&pk_parts, 2);
    try std.testing.expectEqualSlices(u8, &bls_sig.sign(&built.sk, msg).toBytes(), &pk_combined.toBytes());
    // Shares are scalars, the same for both layers.
    for (built.split.shares, built_pk.split.shares) |a, b| try std.testing.expect(a.scalar.eql(b.scalar));
}

test "min-sig Feldman VSS consistency: derivePublicKeyShare(vvec, i) equals skToPk(share_i) in G2" {
    const allocator = std.testing.allocator;
    inline for (min_sig_layers) |T| {
        const built = try testSplitT(T, allocator, 0x14, 3, 4);
        defer allocator.free(built.split.shares);
        defer allocator.free(built.split.vvec.commitments);
        for (built.split.shares) |share| {
            const derived = T.derivePublicKeyShare(built.split.vvec, share.index);
            const expected = T.Suite.skToPk(&.{ .scalar = share.scalar });
            try std.testing.expectEqual(share.index, derived.index);
            try std.testing.expectEqualSlices(u8, &expected.toBytes(), &g2.toBytesCompressed(derived.point));
        }
    }
}

test "min-sig: fewer than t partials do NOT reconstruct; more than t still do" {
    const allocator = std.testing.allocator;
    inline for (min_sig_layers) |T| {
        const built = try testSplitT(T, allocator, 0x15, 3, 5);
        defer allocator.free(built.split.shares);
        defer allocator.free(built.split.vvec.commitments);
        const shares = built.split.shares;
        const msg = "below and above threshold";
        const expected = T.Suite.sign(&built.sk, msg);

        const under_parts = [_]T.PartialSignature{ T.partialSign(&shares[0], msg), T.partialSign(&shares[1], msg) };
        const under = try T.combineSignatures(&under_parts, 2); // a lying t
        try std.testing.expect(!std.mem.eql(u8, &expected.toBytes(), &under.toBytes()));
        try std.testing.expect(!T.Suite.verify(T.groupPublicKey(built.split.vvec), msg, under));

        const over_parts = [_]T.PartialSignature{
            T.partialSign(&shares[0], msg), T.partialSign(&shares[1], msg),
            T.partialSign(&shares[2], msg), T.partialSign(&shares[3], msg),
        };
        try std.testing.expectEqualSlices(u8, &expected.toBytes(), &(try T.combineSignatures(&over_parts, 3)).toBytes());
    }
}

test "min-sig verifyPartialSignature: accepts each valid partial, rejects wrong-share and wrong-index partials" {
    const allocator = std.testing.allocator;
    inline for (min_sig_layers) |T| {
        const built = try testSplitT(T, allocator, 0x16, 3, 5);
        defer allocator.free(built.split.shares);
        defer allocator.free(built.split.vvec.commitments);
        const shares = built.split.shares;
        const msg = "identifiable abort, min-sig";
        for (shares) |share| {
            const pk_share = T.derivePublicKeyShare(built.split.vvec, share.index);
            try std.testing.expect(T.verifyPartialSignature(pk_share, msg, T.partialSign(&share, msg)));
            try std.testing.expect(!T.verifyPartialSignature(pk_share, "wrong message", T.partialSign(&share, msg)));
        }
        const pk_share_1 = T.derivePublicKeyShare(built.split.vvec, 1);
        const forged: T.PartialSignature = .{ .index = 1, .point = T.partialSign(&shares[1], msg).point };
        try std.testing.expect(!T.verifyPartialSignature(pk_share_1, msg, forged));
        const relabeled: T.PartialSignature = .{ .index = 3, .point = T.partialSign(&shares[0], msg).point };
        try std.testing.expect(!T.verifyPartialSignature(pk_share_1, msg, relabeled));
        // The identity key share is refused (keyValidate inside verify).
        const id_share: T.PublicKeyShare = .{ .index = 1, .point = g2.Affine.identity };
        try std.testing.expect(!T.verifyPartialSignature(id_share, msg, T.partialSign(&shares[0], msg)));
    }
}

test "min-sig (t=n=4) and (t=2, n=3) end-to-end chains" {
    const allocator = std.testing.allocator;
    inline for (.{ .{ 4, 4 }, .{ 2, 3 } }) |tn| {
        const t: u32 = tn[0];
        const built = try testSplitT(MinSig, allocator, 0x17, t, tn[1]);
        defer allocator.free(built.split.shares);
        defer allocator.free(built.split.vvec.commitments);
        const msg = "min-sig no slack";
        var parts: [4]MinSig.PartialSignature = undefined;
        for (parts[0..t], built.split.shares[0..t]) |*p, *s| p.* = MinSig.partialSign(s, msg);
        const combined = try MinSig.combineSignatures(parts[0..t], t);
        try std.testing.expectEqualSlices(u8, &bls_sig.MinSigPop.sign(&built.sk, msg).toBytes(), &combined.toBytes());
        try std.testing.expect(bls_sig.MinSigPop.verify(MinSig.groupPublicKey(built.split.vvec), msg, combined));
    }
}
