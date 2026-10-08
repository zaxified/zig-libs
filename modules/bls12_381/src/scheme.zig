// SPDX-License-Identifier: MIT
//! scheme — the six BLS ciphersuites of draft-irtf-cfrg-bls-signature-05
//! §4.2 as one comptime-generic type, `Bls(variant, scheme)`: min-pk or
//! min-sig, times the Basic, MessageAugmentation and ProofOfPossession
//! schemes. `bls_sig.zig` keeps the shared parts (`SecretKey`, `keyGen`,
//! the error set) and re-exports everything here; its file-level names
//! (`sign`, `verify`, …) are the min-pk ProofOfPossession suite.

const std = @import("std");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const pairingmod = @import("pairing.zig");
const hash_to_curve = @import("hash_to_curve.zig");
const entropy = @import("entropy");
const bls_sig = @import("bls_sig.zig");
const burn = @import("burn.zig");

const SecretKey = bls_sig.SecretKey;
const BlsError = bls_sig.BlsError;

// ── the six ciphersuites: variant × scheme ─────────────────────────────

/// Which group carries the public key and which the signature (draft §2.1).
pub const Variant = enum {
    /// Public keys in `G1` (48 bytes), signatures and message hashes in
    /// `G2` (96 bytes). Ethereum's consensus layer and most deployments.
    min_pk,
    /// Public keys in `G2` (96 bytes), signatures and message hashes in
    /// `G1` (48 bytes). drand's quicknet, chains that store many
    /// signatures per key.
    min_sig,
};

/// How the scheme defeats rogue-key attacks on aggregate verification
/// (draft §3).
pub const Scheme = enum {
    /// §3.1 `NUL`: `AggregateVerify` refuses any two equal messages.
    basic,
    /// §3.2 `AUG`: every message is signed and verified as `PK || message`,
    /// so equal messages under different keys hash apart.
    message_augmentation,
    /// §3.3 `POP`: every key carries a proof of possession checked once at
    /// registration; adds `FastAggregateVerify` (one message, many keys).
    proof_of_possession,
};

/// One BLS ciphersuite of draft-irtf-cfrg-bls-signature-05 §4.2:
/// `BLS_SIG_BLS12381G{1,2}_XMD:SHA-256_SSWU_RO_{NUL,AUG,POP}_`, where the
/// group digit names the group messages hash into (the signature group).
/// `SecretKey`, `keyGen` and the error set are shared by all six; the
/// key and signature types are per variant, so a min-pk key cannot be
/// passed to a min-sig verifier.
///
/// Every verify-family function is TOTAL on attacker-controlled input:
/// the signature subgroup check and `KeyValidate` of every key run first,
/// fail closed (`false`), and never panic. Signing uses the constant-time
/// `scalarMul`; verification works on public data and is variable-time.
pub fn Bls(comptime variant: Variant, comptime scheme: Scheme) type {
    return struct {
        /// The group public keys live in (`g1` for min-pk, `g2` for min-sig).
        pub const PkGroup = if (variant == .min_pk) g1 else g2;
        /// The group signatures and message hashes live in.
        pub const SigGroup = if (variant == .min_pk) g2 else g1;

        const group_digit = if (variant == .min_pk) "2" else "1";
        const scheme_tag = switch (scheme) {
            .basic => "NUL",
            .message_augmentation => "AUG",
            .proof_of_possession => "POP",
        };

        /// The ciphersuite ID, also the `hash_to_point` DST (draft §4.2).
        pub const dst_sig = "BLS_SIG_BLS12381G" ++ group_digit ++ "_XMD:SHA-256_SSWU_RO_" ++ scheme_tag ++ "_";

        /// The proof-of-possession DST (draft §4.2.3), POP suites only.
        /// Separate from `dst_sig` so a proof can never double as an
        /// ordinary signature over the key's bytes.
        pub const dst_pop: if (scheme == .proof_of_possession) []const u8 else void =
            if (scheme == .proof_of_possession) "BLS_POP_BLS12381G" ++ group_digit ++ "_XMD:SHA-256_SSWU_RO_POP_" else {};

        /// A public key: a point of `PkGroup`.
        pub const PublicKey = struct {
            point: PkGroup.Affine,

            pub const encoded_bytes = PkGroup.compressed_bytes;

            pub fn toBytes(self: PublicKey) [encoded_bytes]u8 {
                return PkGroup.toBytesCompressed(self.point);
            }

            /// Checks on-curve and subgroup membership (`error.NotInSubgroup`).
            /// Accepts the identity, which `KeyValidate` refuses: every
            /// verifier runs `keyValidate` itself, so a key built without
            /// this decoder gets the check too.
            pub fn fromBytes(bytes: [encoded_bytes]u8) BlsError!PublicKey {
                return .{ .point = try PkGroup.fromBytesCompressed(bytes) };
            }
        };

        /// A signature: a point of `SigGroup`.
        pub const Signature = struct {
            point: SigGroup.Affine,

            pub const encoded_bytes = SigGroup.compressed_bytes;

            pub fn toBytes(self: Signature) [encoded_bytes]u8 {
                return SigGroup.toBytesCompressed(self.point);
            }

            /// Checks subgroup membership. Verifiers still run
            /// `signature_subgroup_check`, because a `Signature` can be
            /// built without this decoder.
            pub fn fromBytes(bytes: [encoded_bytes]u8) BlsError!Signature {
                return .{ .point = try SigGroup.fromBytesCompressed(bytes) };
            }
        };

        /// `hash_to_point` over `parts[0] || parts[1] || ...` into `SigGroup`.
        fn hashToPoint(parts: []const []const u8, dst: []const u8) SigGroup.Affine {
            return if (variant == .min_pk)
                hash_to_curve.hashToCurveG2Parts(parts, dst)
            else
                hash_to_curve.hashToCurveG1Parts(parts, dst);
        }

        /// The pairing pair `e(PK, H)` with each point in its own slot of
        /// `pairing(G1, G2)`.
        fn keyPair(pk: PkGroup.Affine, h: SigGroup.Affine) pairingmod.PairingPair {
            return if (variant == .min_pk) .{ .p = pk, .q = h } else .{ .p = h, .q = pk };
        }

        /// The pairing pair `e(generator, sig)^-1`, so that `e(PK, H) ==
        /// e(generator, sig)` becomes the product check `keyPair * sigPair
        /// == 1`. The negation goes on whichever side is cheaper to negate
        /// and is public: the fixed `G1` generator (min-pk), or the `G1`
        /// signature (min-sig).
        fn sigPair(sig: SigGroup.Affine) pairingmod.PairingPair {
            return if (variant == .min_pk)
                .{ .p = negatedG1Generator(), .q = sig }
            else
                .{ .p = g1.Jacobian.fromAffine(sig).negate().toAffine(), .q = g2.Affine.generator };
        }

        fn signatureSubgroupCheck(sig: Signature) bool {
            return SigGroup.Jacobian.fromAffine(sig.point).subgroupCheck();
        }

        /// draft §2.4 `SkToPk(SK) = SK * P`, `P` the `PkGroup` generator.
        /// Constant-time `scalarMul` — `SK` is secret, so it is passed by
        /// pointer and the multiply runs one frame down, burned after.
        pub fn skToPk(sk: *const SecretKey) PublicKey {
            return burn.run(burn.sign_burn, PublicKey, skToPkBody, .{sk});
        }

        fn skToPkBody(sk: *const SecretKey) PublicKey {
            const p = PkGroup.Jacobian.fromAffine(PkGroup.Affine.generator).scalarMul(sk.scalar);
            return .{ .point = p.toAffine() };
        }

        /// draft §2.5 `KeyValidate(PK)`: a non-identity point of the
        /// order-`r` subgroup. Every verifier runs it on every key.
        pub fn keyValidate(pk: PublicKey) bool {
            if (pk.point.infinity) return false;
            return PkGroup.Jacobian.fromAffine(pk.point).subgroupCheck();
        }

        /// draft §2.6 `CoreSign` over `parts`, under `dst`. The hash lands
        /// in the subgroup by construction (RFC 9380 `clear_cofactor`).
        fn coreSign(sk: *const SecretKey, parts: []const []const u8, dst: []const u8) Signature {
            const q = hashToPoint(parts, dst);
            // Constant-time: `sk` is secret; `q` is public.
            const r = SigGroup.Jacobian.fromAffine(q).scalarMul(sk.scalar);
            return .{ .point = r.toAffine() };
        }

        /// draft §2.7 `CoreVerify` over `parts`, under `dst`: the two
        /// mandatory checks first, then `e(PK, H) == e(P, sig)` as one
        /// shared Miller loop and one final exponentiation.
        fn coreVerify(pk: PublicKey, parts: []const []const u8, dst: []const u8, sig: Signature) bool {
            if (!signatureSubgroupCheck(sig)) return false;
            if (!keyValidate(pk)) return false;
            const q = hashToPoint(parts, dst);
            return pairingmod.pairingCheck(&.{ keyPair(pk.point, q), sigPair(sig.point) });
        }

        /// `Sign(SK, message)`: `CoreSign` under `dst_sig`; for
        /// MessageAugmentation over `SkToPk(SK) || message` (draft §3.2.1).
        /// The body runs one frame down and is burned after.
        pub fn sign(sk: *const SecretKey, msg: []const u8) Signature {
            return burn.run(burn.sign_burn, Signature, signBody, .{ sk, msg });
        }

        fn signBody(sk: *const SecretKey, msg: []const u8) Signature {
            if (scheme == .message_augmentation) {
                const pk_bytes = skToPkBody(sk).toBytes();
                return coreSign(sk, &.{ &pk_bytes, msg }, dst_sig);
            }
            return coreSign(sk, &.{msg}, dst_sig);
        }

        /// `Verify(PK, message, signature)`: `CoreVerify` under `dst_sig`;
        /// for MessageAugmentation over `PK || message` (draft §3.2.2).
        pub fn verify(pk: PublicKey, msg: []const u8, sig: Signature) bool {
            if (scheme == .message_augmentation) {
                const pk_bytes = pk.toBytes();
                return coreVerify(pk, &.{ &pk_bytes, msg }, dst_sig, sig);
            }
            return coreVerify(pk, &.{msg}, dst_sig, sig);
        }

        /// draft §2.8 `Aggregate`: the sum of the signature points. Does
        /// not subgroup-check its inputs — the aggregate verifiers check
        /// the result. `error.EmptySet` on no input (INVALID, not
        /// vacuously true).
        pub fn aggregate(sigs: []const Signature) BlsError!Signature {
            if (sigs.len == 0) return error.EmptySet;
            var acc = SigGroup.Jacobian.fromAffine(sigs[0].point);
            for (sigs[1..]) |s| acc = acc.add(SigGroup.Jacobian.fromAffine(s.point));
            return .{ .point = acc.toAffine() };
        }

        /// The sum of public keys (`FastAggregateVerify`'s first step,
        /// and Ethereum's `eth_aggregate_pubkeys`).
        pub fn aggregatePublicKeys(pks: []const PublicKey) BlsError!PublicKey {
            if (pks.len == 0) return error.EmptySet;
            var acc = PkGroup.Jacobian.fromAffine(pks[0].point);
            for (pks[1..]) |pk| acc = acc.add(PkGroup.Jacobian.fromAffine(pk.point));
            return .{ .point = acc.toAffine() };
        }

        /// The shared core of the aggregate verifiers (draft §2.9
        /// `CoreAggregateVerify`): signature subgroup check, `KeyValidate`
        /// of every key, then `prod_i e(PK_i, H(m_i)) == e(P, sig)` with the
        /// Miller values accumulated over fixed stack chunks and ONE final
        /// exponentiation — the same value one big `pairingCheck` would
        /// give (Miller values multiply; the final exponentiation is a
        /// homomorphism), with no allocator. `augment` prefixes each
        /// message with its key's bytes.
        fn aggregateCheck(pks: []const PublicKey, msgs: []const []const u8, sig: Signature, dst: []const u8, augment: bool) BlsError!bool {
            if (pks.len == 0) return error.EmptySet;
            if (pks.len != msgs.len) return error.LengthMismatch;
            if (!signatureSubgroupCheck(sig)) return false;

            var f = pairingmod.Fp12.one;
            var pairs_buf: [8]pairingmod.PairingPair = undefined; // 8 == pairing.zig's miller_batch_max
            var pending: usize = 0;
            for (pks, msgs) |pk, msg| {
                if (!keyValidate(pk)) return false;
                const pk_bytes = pk.toBytes();
                const q = if (augment) hashToPoint(&.{ &pk_bytes, msg }, dst) else hashToPoint(&.{msg}, dst);
                pairs_buf[pending] = keyPair(pk.point, q);
                pending += 1;
                if (pending == pairs_buf.len) {
                    f = f.mul(pairingmod.multiMillerLoop(pairs_buf[0..pending]));
                    pending = 0;
                }
            }
            pairs_buf[pending] = sigPair(sig.point);
            pending += 1;
            f = f.mul(pairingmod.multiMillerLoop(pairs_buf[0..pending]));
            return pairingmod.finalExponentiation(f).eql(pairingmod.Fp12.one);
        }

        /// draft §2.9 `CoreAggregateVerify` under an explicit `dst`, with
        /// no scheme rule applied (no distinct-message check, no
        /// augmentation). The building block; callers normally want
        /// `aggregateVerify`.
        pub fn coreAggregateVerify(pks: []const PublicKey, msgs: []const []const u8, sig: Signature, dst: []const u8) BlsError!bool {
            return aggregateCheck(pks, msgs, sig, dst, false);
        }

        /// `AggregateVerify((PK_1..PK_n), (m_1..m_n), signature)` with the
        /// scheme's rogue-key rule:
        ///  • Basic (§3.1.1): INVALID if any two messages are equal — the
        ///    check is pairwise (`O(n^2)` comparisons, no allocator);
        ///  • MessageAugmentation (§3.2.3): each `m_i` is verified as
        ///    `PK_i || m_i`;
        ///  • ProofOfPossession (§3.3.3): plain, the keys' proofs having
        ///    been checked at registration.
        pub fn aggregateVerify(pks: []const PublicKey, msgs: []const []const u8, sig: Signature) BlsError!bool {
            if (scheme == .basic) {
                if (pks.len == 0) return error.EmptySet;
                if (pks.len != msgs.len) return error.LengthMismatch;
                for (msgs, 0..) |a, i| {
                    for (msgs[i + 1 ..]) |b| if (std.mem.eql(u8, a, b)) return false;
                }
            }
            return aggregateCheck(pks, msgs, sig, dst_sig, scheme == .message_augmentation);
        }

        /// draft §3.3.4 `FastAggregateVerify(PKs, message, signature)`,
        /// ProofOfPossession only (`void` in the other schemes, like
        /// `popProve`/`popVerify` and `dst_pop`, so it cannot be called): aggregate the keys, then `Verify`.
        ///
        /// **The caller MUST hold a valid proof of possession for every
        /// `PK_i`** (`popVerify`, checked once at registration). That is
        /// what makes adding keys safe; without it a rogue key cancels the
        /// others and forges.
        pub const fastAggregateVerify = if (scheme == .proof_of_possession) fastAggregateVerifyImpl else {};

        fn fastAggregateVerifyImpl(pks: []const PublicKey, msg: []const u8, sig: Signature) BlsError!bool {
            if (pks.len == 0) return error.EmptySet;
            const agg_pk = try aggregatePublicKeys(pks);
            return verify(agg_pk, msg, sig);
        }

        /// draft §3.3.2 `PopProve(SK)`: a signature over the key's own
        /// bytes under `dst_pop`.
        pub const popProve = if (scheme == .proof_of_possession) popProveImpl else {};

        fn popProveImpl(sk: *const SecretKey) Signature {
            return burn.run(burn.sign_burn, Signature, popProveBody, .{sk});
        }

        fn popProveBody(sk: *const SecretKey) Signature {
            const pk_bytes = skToPkBody(sk).toBytes();
            return coreSign(sk, &.{&pk_bytes}, dst_pop);
        }

        /// draft §3.3.3 `PopVerify(PK, proof)`.
        pub const popVerify = if (scheme == .proof_of_possession) popVerifyImpl else {};

        fn popVerifyImpl(pk: PublicKey, proof: Signature) bool {
            const pk_bytes = pk.toBytes();
            return coreVerify(pk, &.{&pk_bytes}, dst_pop, proof);
        }

        /// Verify `n` independent signatures `(pks[i], msgs[i], sigs[i])`
        /// at once — the same verdict as `verify` on each, at the cost of
        /// one shared multi-Miller loop and ONE final exponentiation
        /// instead of `n`. Random-linear-combination batching: with fresh
        /// random 128-bit `r_i`, check
        /// `prod_i e(r_i * PK_i, H_i) == e(P, sum_i r_i * sig_i)`. Without
        /// the `r_i`, two invalid signatures whose errors cancel would pass
        /// (`sig_1 + D`, `sig_2 - D`); with them a batch containing any
        /// invalid signature passes with probability at most `2^-128`
        /// over the draw. Every signature is subgroup-checked and every
        /// key validated first, exactly as `verify` does — a batch is
        /// never more permissive than its members.
        ///
        /// `false` says some member is invalid, not which: on `false`,
        /// verify the members one by one. The `r_i` come from `entropy`
        /// (fail-closed: a degraded draw aborts rather than verify with
        /// guessable coefficients). Messages need not be distinct, in any
        /// scheme: each signature is checked on its own key. No allocator.
        pub fn verifyBatch(io: std.Io, pks: []const PublicKey, msgs: []const []const u8, sigs: []const Signature) BlsError!bool {
            if (pks.len == 0) return error.EmptySet;
            if (pks.len != msgs.len or pks.len != sigs.len) return error.LengthMismatch;

            var f = pairingmod.Fp12.one;
            var pairs_buf: [8]pairingmod.PairingPair = undefined;
            var pending: usize = 0;
            var sig_acc = SigGroup.Jacobian.identity;
            for (pks, msgs, sigs) |pk, msg, sig| {
                if (!signatureSubgroupCheck(sig)) return false;
                if (!keyValidate(pk)) return false;
                var r: [16]u8 = undefined;
                entropy.fill(io, &r);
                r[0] |= 0x80; // r_i != 0, and every r_i the same bit length
                const pk_bytes = pk.toBytes();
                const q = if (scheme == .message_augmentation)
                    hashToPoint(&.{ &pk_bytes, msg }, dst_sig)
                else
                    hashToPoint(&.{msg}, dst_sig);
                const rpk = PkGroup.Jacobian.fromAffine(pk.point).scalarMulBytes(&r).toAffine();
                sig_acc = sig_acc.add(SigGroup.Jacobian.fromAffine(sig.point).scalarMulBytes(&r));
                pairs_buf[pending] = keyPair(rpk, q);
                pending += 1;
                if (pending == pairs_buf.len) {
                    f = f.mul(pairingmod.multiMillerLoop(pairs_buf[0..pending]));
                    pending = 0;
                }
            }
            pairs_buf[pending] = sigPair(sig_acc.toAffine());
            pending += 1;
            f = f.mul(pairingmod.multiMillerLoop(pairs_buf[0..pending]));
            return pairingmod.finalExponentiation(f).eql(pairingmod.Fp12.one);
        }
    };
}

/// The minimal-pubkey-size ProofOfPossession suite,
/// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` — Ethereum's. The
/// file-level names below (`PublicKey`, `sign`, `verify`, …) are this
/// suite, kept as they were before the other five suites existed.
pub const MinPkPop = Bls(.min_pk, .proof_of_possession);
pub const MinPkBasic = Bls(.min_pk, .basic);
pub const MinPkAug = Bls(.min_pk, .message_augmentation);
/// `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` — drand quicknet's.
pub const MinSigBasic = Bls(.min_sig, .basic);
pub const MinSigAug = Bls(.min_sig, .message_augmentation);
pub const MinSigPop = Bls(.min_sig, .proof_of_possession);

/// The negated `G1` generator `-P`, the fixed operand of the min-pk verify
/// equation `e(PK, H) * e(-P, sig) == 1`.
pub fn negatedG1Generator() g1.Affine {
    return g1.Jacobian.fromAffine(g1.Affine.generator).negate().toAffine();
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const all_suites = .{ MinPkBasic, MinPkAug, MinPkPop, MinSigBasic, MinSigAug, MinSigPop };

test "ciphersuite IDs are the draft's six strings (§4.2.1-§4.2.3)" {
    try testing.expectEqualStrings("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_", MinPkBasic.dst_sig);
    try testing.expectEqualStrings("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_", MinPkAug.dst_sig);
    try testing.expectEqualStrings("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", MinPkPop.dst_sig);
    try testing.expectEqualStrings("BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", MinPkPop.dst_pop);
    try testing.expectEqualStrings("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_", MinSigBasic.dst_sig);
    try testing.expectEqualStrings("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_", MinSigAug.dst_sig);
    try testing.expectEqualStrings("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_", MinSigPop.dst_sig);
    try testing.expectEqualStrings("BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_", MinSigPop.dst_pop);
    try testing.expectEqual(@as(usize, 48), MinPkBasic.PublicKey.encoded_bytes);
    try testing.expectEqual(@as(usize, 96), MinPkBasic.Signature.encoded_bytes);
    try testing.expectEqual(@as(usize, 96), MinSigBasic.PublicKey.encoded_bytes);
    try testing.expectEqual(@as(usize, 48), MinSigBasic.Signature.encoded_bytes);
}

test "min-pk Basic KAT: drand mainnet `default` chain, round 1000000 (pedersen-bls-chained)" {
    // Live drand data, pinned in modules/drand (chaininfo.zig, verify.zig):
    // the chain signs SHA-256(previous_signature || u64be(round)) with
    // BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_, key in G1.
    const pk = try MinPkBasic.PublicKey.fromBytes(hexBytes(48, "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"));
    const sig = try MinPkBasic.Signature.fromBytes(hexBytes(96, "87e355169c4410a8ad6d3e7f5094b2122932c1062f603e6628aba2e4cb54f46c3bf1083c3537cd3b99e8296784f46fb40e090961cf9634f02c7dc2a96b69fc3c03735bc419962780a71245b72f81882cf6bb9c961bcf32da5624993bb747c9e5"));
    const prev = hexBytes(96, "86bbc40c9d9347568967add4ddf6e351aff604352a7e1eec9b20dea4ca531ed6c7d38de9956ffc3bb5a7fabe28b3a36b069c8113bd9824135c3bff9b03359476f6b03beec179d4aeff456f4d34bbf702b9af78c3bb44e1892ace8e581bf4afa9");
    var h = Sha256.init(.{});
    h.update(&prev);
    var round_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &round_be, 1_000_000, .big);
    h.update(&round_be);
    var msg: [32]u8 = undefined;
    h.final(&msg);
    try testing.expect(MinPkBasic.verify(pk, &msg, sig));
    // Negative controls: the next round's message, and the same signature
    // under the POP suite (same groups, different DST).
    std.mem.writeInt(u64, &round_be, 1_000_001, .big);
    var h2 = Sha256.init(.{});
    h2.update(&prev);
    h2.update(&round_be);
    var msg2: [32]u8 = undefined;
    h2.final(&msg2);
    try testing.expect(!MinPkBasic.verify(pk, &msg2, sig));
    try testing.expect(!MinPkPop.verify(.{ .point = pk.point }, &msg, .{ .point = sig.point }));
}

test "min-sig Basic KAT: drand mainnet quicknet, round 1000 (bls-unchained-g1-rfc9380)" {
    // Live drand data, pinned in modules/drand: quicknet signs
    // SHA-256(u64be(round)) with BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_,
    // signature in G1, key in G2.
    const pk = try MinSigBasic.PublicKey.fromBytes(hexBytes(96, "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"));
    const sig = try MinSigBasic.Signature.fromBytes(hexBytes(48, "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"));
    var round_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &round_be, 1000, .big);
    var msg: [32]u8 = undefined;
    Sha256.hash(&round_be, &msg, .{});
    try testing.expect(MinSigBasic.verify(pk, &msg, sig));
    std.mem.writeInt(u64, &round_be, 1001, .big);
    Sha256.hash(&round_be, &msg, .{});
    try testing.expect(!MinSigBasic.verify(pk, &msg, sig));
}

fn testKeys(comptime n: usize) [n]SecretKey {
    var sks: [n]SecretKey = undefined;
    for (&sks, 0..) |*sk, i| {
        var ikm: [32]u8 = @splat(@intCast(0x40 + i));
        ikm[31] = 0x5c;
        bls_sig.keyGen(sk, &ikm, "scheme test") catch unreachable;
    }
    return sks;
}

test "every suite: sign → verify; a wrong message, key or suite is rejected" {
    const sks = testKeys(2);
    inline for (all_suites) |S| {
        const pk = S.skToPk(&sks[0]);
        const other = S.skToPk(&sks[1]);
        try testing.expect(S.keyValidate(pk));
        const sig = S.sign(&sks[0], "attestation");
        try testing.expect(S.verify(pk, "attestation", sig));
        try testing.expect(!S.verify(pk, "attestatioN", sig));
        try testing.expect(!S.verify(other, "attestation", sig));
        // Codec round trip.
        const pk2 = try S.PublicKey.fromBytes(pk.toBytes());
        const sig2 = try S.Signature.fromBytes(sig.toBytes());
        try testing.expect(S.verify(pk2, "attestation", sig2));
    }
    // Same groups, different scheme: the DST (and for AUG the message)
    // differs, so a signature never crosses suites.
    const sig_basic = MinPkBasic.sign(&sks[0], "m");
    const pk_basic = MinPkBasic.skToPk(&sks[0]);
    try testing.expect(!MinPkAug.verify(.{ .point = pk_basic.point }, "m", .{ .point = sig_basic.point }));
    try testing.expect(!MinPkPop.verify(.{ .point = pk_basic.point }, "m", .{ .point = sig_basic.point }));
    const sig_sb = MinSigBasic.sign(&sks[0], "m");
    const pk_sb = MinSigBasic.skToPk(&sks[0]);
    try testing.expect(!MinSigAug.verify(.{ .point = pk_sb.point }, "m", .{ .point = sig_sb.point }));
    try testing.expect(!MinSigPop.verify(.{ .point = pk_sb.point }, "m", .{ .point = sig_sb.point }));
}

test "MessageAugmentation signs PK || message: it equals CoreSign over the concatenation" {
    const sks = testKeys(1);
    inline for (.{ MinPkAug, MinSigAug }) |S| {
        const pk = S.skToPk(&sks[0]);
        var buf: [S.PublicKey.encoded_bytes + 5]u8 = undefined;
        @memcpy(buf[0..S.PublicKey.encoded_bytes], &pk.toBytes());
        @memcpy(buf[S.PublicKey.encoded_bytes..], "hello");
        const want = S.coreSign(&sks[0], &.{&buf}, S.dst_sig);
        try testing.expectEqual(want.toBytes(), S.sign(&sks[0], "hello").toBytes());
        // A plain CoreVerify of the bare message must fail.
        try testing.expect(!S.coreVerify(pk, &.{"hello"}, S.dst_sig, S.sign(&sks[0], "hello")));
    }
}

test "aggregateVerify per scheme: Basic refuses equal messages, AUG and POP accept them" {
    const sks = testKeys(3);
    inline for (all_suites) |S| {
        var pks: [3]S.PublicKey = undefined;
        var sigs: [3]S.Signature = undefined;
        const distinct = [_][]const u8{ "m0", "m1", "m2" };
        for (&pks, &sigs, sks, distinct) |*pk, *sig, sk, m| {
            pk.* = S.skToPk(&sk);
            sig.* = S.sign(&sk, m);
        }
        const agg = try S.aggregate(&sigs);
        try testing.expect(try S.aggregateVerify(&pks, &distinct, agg));
        // A swapped message pair fails.
        try testing.expect(!try S.aggregateVerify(&pks, &.{ "m1", "m0", "m2" }, agg));

        const same = [_][]const u8{ "same", "same", "other" };
        for (&sigs, sks, same) |*sig, sk, m| sig.* = S.sign(&sk, m);
        const agg_same = try S.aggregate(&sigs);
        const ok = try S.aggregateVerify(&pks, &same, agg_same);
        try testing.expectEqual(S != MinPkBasic and S != MinSigBasic, ok);

        try testing.expectError(error.EmptySet, S.aggregateVerify(&.{}, &.{}, agg));
        try testing.expectError(error.LengthMismatch, S.aggregateVerify(&pks, distinct[0..2], agg));
    }
}

test "min-sig ProofOfPossession: popProve/popVerify and fastAggregateVerify" {
    const sks = testKeys(3);
    const S = MinSigPop;
    var pks: [3]S.PublicKey = undefined;
    var sigs: [3]S.Signature = undefined;
    for (&pks, &sigs, sks) |*pk, *sig, sk| {
        pk.* = S.skToPk(&sk);
        try testing.expect(S.popVerify(pk.*, S.popProve(&sk)));
        sig.* = S.sign(&sk, "block 42");
    }
    // A proof is not a signature over the key bytes (separate DST), and a
    // proof for one key does not verify for another.
    try testing.expect(!S.verify(pks[0], &pks[0].toBytes(), S.popProve(&sks[0])));
    try testing.expect(!S.popVerify(pks[1], S.popProve(&sks[0])));
    const agg = try S.aggregate(&sigs);
    try testing.expect(try S.fastAggregateVerify(&pks, "block 42", agg));
    try testing.expect(!try S.fastAggregateVerify(pks[0..2], "block 42", agg));
}

test "min-sig verifiers reject the identity key and a non-subgroup G1 signature" {
    const sks = testKeys(1);
    const S = MinSigBasic;
    const sig = S.sign(&sks[0], "m");
    try testing.expect(!S.verify(.{ .point = g2.Affine.identity }, "m", .{ .point = g1.Affine.identity }));
    try testing.expect(!S.keyValidate(.{ .point = g2.Affine.identity }));
    // A point on E1 outside the order-r subgroup: the map-to-curve output
    // before cofactor clearing (cofactor h1 > 1, so it is outside for any
    // hash but with negligible probability).
    const u = hash_to_curve.hashToFieldFp(1, "off-subgroup", "TEST-DST")[0];
    const raw = hash_to_curve.mapToCurveG1(u);
    try testing.expect(!g1.Jacobian.fromAffine(raw).subgroupCheck());
    try testing.expect(!S.verify(S.skToPk(&sks[0]), "m", .{ .point = raw }));
    try testing.expect(S.verify(S.skToPk(&sks[0]), "m", sig));
}

test "verifyBatch: valid batches pass in every suite, across Miller chunks" {
    const sks = testKeys(10); // 10 > the 8-pair chunk
    inline for (all_suites) |S| {
        var pks: [10]S.PublicKey = undefined;
        var sigs: [10]S.Signature = undefined;
        var msgs: [10][]const u8 = undefined;
        for (&pks, &sigs, &msgs, sks, 0..) |*pk, *sig, *m, sk, i| {
            pk.* = S.skToPk(&sk);
            // Repeated messages are fine in a batch, in every scheme.
            m.* = if (i % 3 == 0) "dup" else "msg";
            sig.* = S.sign(&sk, m.*);
        }
        try testing.expect(try S.verifyBatch(testing.io, &pks, &msgs, &sigs));
        // One signature for the wrong message spoils the batch.
        const saved = sigs[7];
        sigs[7] = S.sign(&sks[7], "forged");
        try testing.expect(!try S.verifyBatch(testing.io, &pks, &msgs, &sigs));
        sigs[7] = saved;
        // Errors before any work.
        try testing.expectError(error.EmptySet, S.verifyBatch(testing.io, &.{}, &.{}, &.{}));
        try testing.expectError(error.LengthMismatch, S.verifyBatch(testing.io, &pks, msgs[0..9], &sigs));
    }
}

test "verifyBatch: two invalid signatures whose errors cancel are caught (the reason for the random coefficients)" {
    const sks = testKeys(2);
    inline for (.{ MinPkBasic, MinSigBasic }) |S| {
        const pks = [_]S.PublicKey{ S.skToPk(&sks[0]), S.skToPk(&sks[1]) };
        const msgs = [_][]const u8{ "pay alice", "pay bob" };
        const good = [_]S.Signature{ S.sign(&sks[0], msgs[0]), S.sign(&sks[1], msgs[1]) };
        // D: any non-identity point of the signature group.
        const d = S.SigGroup.Jacobian.fromAffine(S.SigGroup.Affine.generator);
        const bad = [_]S.Signature{
            .{ .point = S.SigGroup.Jacobian.fromAffine(good[0].point).add(d).toAffine() },
            .{ .point = S.SigGroup.Jacobian.fromAffine(good[1].point).add(d.negate()).toAffine() },
        };
        try testing.expect(!S.verify(pks[0], msgs[0], bad[0]));
        try testing.expect(!S.verify(pks[1], msgs[1], bad[1]));
        // The unweighted sum cannot tell: their aggregate is the genuine
        // aggregate, and aggregateVerify accepts it.
        try testing.expect(try S.aggregateVerify(&pks, &msgs, try S.aggregate(&bad)));
        // The weighted batch can.
        try testing.expect(!try S.verifyBatch(testing.io, &pks, &msgs, &bad));
        try testing.expect(try S.verifyBatch(testing.io, &pks, &msgs, &good));
    }
}

test "verifyBatch never accepts what verify refuses: identity key, non-subgroup signature" {
    const sks = testKeys(2);
    const S = MinPkPop;
    var pks = [_]S.PublicKey{ S.skToPk(&sks[0]), S.skToPk(&sks[1]) };
    const msgs = [_][]const u8{ "a", "b" };
    var sigs = [_]S.Signature{ S.sign(&sks[0], "a"), S.sign(&sks[1], "b") };
    pks[1] = .{ .point = g1.Affine.identity };
    sigs[1] = .{ .point = g2.Affine.identity };
    try testing.expect(!try S.verifyBatch(testing.io, &pks, &msgs, &sigs));
    pks[1] = S.skToPk(&sks[1]);
    const u = hash_to_curve.hashToFieldFp2(1, "off-subgroup", "TEST-DST")[0];
    sigs[1] = .{ .point = hash_to_curve.mapToCurveG2(u) };
    try testing.expect(!g2.Jacobian.fromAffine(sigs[1].point).subgroupCheck());
    try testing.expect(!try S.verifyBatch(testing.io, &pks, &msgs, &sigs));
}
