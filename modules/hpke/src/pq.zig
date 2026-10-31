// SPDX-License-Identifier: MIT
//! Post-quantum and hybrid KEMs for HPKE (draft-ietf-hpke-pq): ML-KEM-512/768/1024
//! (FIPS 203, kem_id 0x0040/0x0041/0x0042) and the three ML-KEM + ECDH hybrids
//! MLKEM768-P256 (0x0050), MLKEM1024-P384 (0x0051) and MLKEM768-X25519 (0x647a,
//! X-Wing). Same shape as the DHKEMs in `dhkem.zig` (`KeyPair`, `PublicKey`,
//! `EncappedKey`, `Encapped`, `generateKeyPair`, `deriveKeyPair`, `encap`,
//! `encapDeterministic`, `decap`), so every `setup*`/`seal*`/`open*` entry point
//! in base and psk mode takes them; there is no `AuthEncap` for a KEM that is
//! not a DH (the auth modes are a compile error).
//!
//! The deterministic seam differs from a DHKEM's: an ephemeral is not a key pair
//! but the encapsulation randomness (`Ephemeral`): ML-KEM's 32-byte `m`, and for
//! a hybrid `m` followed by the curve's ephemeral-scalar candidates.
//!
//! Construction ported from Go 1.26 `crypto/hpke/pq.go` (BSD-3-Clause, see
//! NOTICE), checked byte for byte against the draft's vectors in Go's
//! `testdata/hpke-pq.json` (`kat_hpke_pq.zig`):
//! - private key = seed; ML-KEM: the 64-byte FIPS 203 seed `d || z`; hybrid: 32
//!   bytes, expanded by SHAKE256 into the ML-KEM seed and then curve-scalar
//!   candidates (rejection-sampled for P-256/P-384, X25519 takes the first);
//! - `DeriveKeyPair(ikm)` = SHAKE256 `LabeledDerive` under "KEM" || kem_id,
//!   label "DeriveKeyPair", empty context, 64 (ML-KEM) or 32 (hybrid) bytes;
//! - hybrid shared secret = SHA3-256(ss_PQ || ss_T || ct_T || ek_T || label);
//!   `enc` = ct_PQ || ct_T, public key = ek_PQ || ek_T; the ECDH secret of a NIST
//!   curve is the shared point's X coordinate.
//!
//! The ML-KEM arithmetic is std's (`std.crypto.kem.ml_kem`; its constant-time
//! behaviour is std's: decapsulation compares and selects with `ctneq`/`cmov`).
//! Curves as in `dhkem.zig`: X25519 from std, P-256 from the `p256` module,
//! P-384 from std.

const std = @import("std");
const suite = @import("suite.zig");
const kdf = @import("kdf.zig");
const burn = @import("burn.zig");
const dhkem = @import("dhkem.zig");
const entropy = @import("entropy");
const ml_kem = std.crypto.kem.ml_kem;
const sha3 = std.crypto.hash.sha3;
const X25519 = std.crypto.dh.X25519;
const P256 = @import("p256").P256;
const P384 = @import("p384").P384;

pub const EncapError = dhkem.EncapError;
pub const DecapError = dhkem.DecapError;

/// `SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", out.len)` under the KEM
/// suite id — draft-ietf-hpke-pq's `DeriveKeyPair` for every KEM here.
fn deriveSeed(comptime kem_id: u16, out: []u8, ikm: []const u8) void {
    const kem_suite_id = comptime suite.kemSuiteId(kem_id);
    // out.len is 32 or 64 and the label is a literal: LabelTooLong cannot fire.
    kdf.Shake256.labeledDerive(out, &kem_suite_id, &.{ikm}, "DeriveKeyPair", &.{}) catch |e| switch (e) {
        error.LabelTooLong => @panic("hpke: DeriveKeyPair output length"),
    };
}

/// Pure ML-KEM as an HPKE KEM.
fn MlKemKem(comptime K: type, comptime id: suite.KemId, comptime burn_bytes: usize) type {
    return struct {
        pub const kem_id: u16 = @backingInt(id);
        pub const Nsecret: usize = K.shared_length; // 32
        pub const Npk: usize = K.PublicKey.encoded_length;
        pub const Nsk: usize = K.seed_length; // 64, FIPS 203 d || z
        pub const Nenc: usize = K.ciphertext_length;

        pub const PublicKey = [Npk]u8;
        pub const EncappedKey = [Nenc]u8;
        /// The encapsulation randomness `m` (FIPS 203 ML-KEM.Encaps_internal).
        pub const Ephemeral = [K.encaps_seed_length]u8;

        /// The seed (the serialized private key) and the expanded key, so
        /// `decap` does not redo key generation.
        pub const KeyPair = struct {
            seed: [Nsk]u8,
            public_key: PublicKey,
            expanded: K.KeyPair,
        };

        pub const Encapped = struct {
            shared_secret: [Nsecret]u8,
            enc: EncappedKey,
        };

        pub fn generateKeyPair(out: *KeyPair, io: std.Io) void {
            var seed: [Nsk]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            entropy.fill(io, &seed);
            fromSeed(out, &seed);
        }

        /// The key pair of a serialized private key (the 64-byte seed).
        pub fn fromSeed(out: *KeyPair, seed: *const [Nsk]u8) void {
            burn.run(burn_bytes, void, fromSeedBody, .{ out, seed });
        }

        fn fromSeedBody(out: *KeyPair, seed: *const [Nsk]u8) void {
            out.seed = seed.*;
            out.expanded = K.KeyPair.generateDeterministic(seed.*) catch |e| switch (e) {};
            out.public_key = out.expanded.public_key.toBytes();
        }

        pub fn deriveKeyPair(out: *KeyPair, ikm: []const u8) void {
            var seed: [Nsk]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            deriveSeed(kem_id, &seed, ikm);
            fromSeed(out, &seed);
        }

        pub fn generateEphemeral(out: *Ephemeral, io: std.Io) void {
            entropy.fill(io, out);
        }

        pub fn encap(out: *Encapped, pkR: PublicKey, io: std.Io) EncapError!void {
            var eph: Ephemeral = undefined;
            defer std.crypto.secureZero(u8, &eph);
            generateEphemeral(&eph, io);
            return encapDeterministic(out, pkR, &eph);
        }

        /// A non-canonical encapsulation key (a coefficient >= q, FIPS 203
        /// §7.2's modulus check) is `DeserializeError`.
        pub fn encapDeterministic(out: *Encapped, pkR: PublicKey, eph: *const Ephemeral) EncapError!void {
            return burn.run(burn_bytes, EncapError!void, encapBody, .{ out, &pkR, eph });
        }

        fn encapBody(out: *Encapped, pkR: *const PublicKey, eph: *const Ephemeral) EncapError!void {
            errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
            const pk = K.PublicKey.fromBytes(pkR) catch return error.DeserializeError;
            var es = pk.encapsDeterministic(eph);
            defer std.crypto.secureZero(u8, &es.shared_secret);
            out.shared_secret = es.shared_secret;
            out.enc = es.ciphertext;
        }

        /// Never fails: a forged ciphertext decapsulates to FIPS 203's implicit
        /// rejection secret, and the AEAD open fails later.
        pub fn decap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair) DecapError!void {
            return burn.run(burn_bytes, DecapError!void, decapBody, .{ out, &enc, skR });
        }

        fn decapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair) DecapError!void {
            out.* = skR.expanded.secret_key.decaps(enc) catch |e| switch (e) {};
        }
    };
}

// ── curve halves of the hybrids ─────────────────────────────────────────

const X25519Group = struct {
    pub const Nscalar = 32;
    pub const Npoint = 32;
    /// Every 32-byte string is a scalar (clamped at use).
    pub const candidates_in_ephemeral = 1;

    fn validScalar(_: *const [Nscalar]u8) bool {
        return true;
    }
    fn publicKey(sk: *const [Nscalar]u8) [Npoint]u8 {
        return X25519.recoverPublicKey(sk.*);
    }
    fn dh(sk: *const [Nscalar]u8, point: *const [Npoint]u8, out: *[Nscalar]u8) error{ DhFailed, DeserializeError }!void {
        out.* = X25519.scalarmult(sk.*, point.*) catch return error.DhFailed;
    }
};

fn NistGroup(comptime Curve: type, comptime n_candidates: usize) type {
    return struct {
        pub const Nscalar = Curve.scalar.encoded_length;
        pub const Npoint = 2 * Nscalar + 1;
        pub const candidates_in_ephemeral = n_candidates;

        fn validScalar(c: *const [Nscalar]u8) bool {
            Curve.scalar.rejectNonCanonical(c.*, .big) catch return false;
            return !std.mem.allEqual(u8, c, 0);
        }
        fn publicKey(sk: *const [Nscalar]u8) [Npoint]u8 {
            // Only called on a validScalar: non-zero and < n.
            if (@hasDecl(Curve, "mulBaseCtUnburned")) {
                // p384's fixed-base comb; we run under the KEM's burn.
                var le = sk.*;
                defer std.crypto.secureZero(u8, &le);
                std.mem.reverse(u8, &le);
                return Curve.mulBaseCtUnburned(&le).toUncompressedSec1();
            }
            const p = Curve.basePoint.mul(sk.*, .big) catch |e| switch (e) {
                error.IdentityElement => @panic("hpke: base multiplication by a valid scalar"),
            };
            return p.toUncompressedSec1();
        }
        fn dh(sk: *const [Nscalar]u8, point: *const [Npoint]u8, out: *[Nscalar]u8) error{ DhFailed, DeserializeError }!void {
            const q = Curve.fromSec1(point) catch return error.DeserializeError;
            const s = q.mul(sk.*, .big) catch return error.DhFailed;
            out.* = s.affineCoordinates().x.toBytes(.big);
        }
    };
}

/// ML-KEM + ECDH hybrid (draft-ietf-hpke-pq / draft-irtf-cfrg-concrete-hybrid-kems).
fn HybridKem(
    comptime K: type,
    comptime G: type,
    comptime id: suite.KemId,
    comptime label: []const u8,
    comptime burn_bytes: usize,
) type {
    return struct {
        pub const kem_id: u16 = @backingInt(id);
        pub const Nsecret: usize = 32;
        pub const Npk: usize = K.PublicKey.encoded_length + G.Npoint;
        pub const Nsk: usize = 32;
        pub const Nenc: usize = K.ciphertext_length + G.Npoint;

        pub const PublicKey = [Npk]u8;
        pub const EncappedKey = [Nenc]u8;
        /// ML-KEM's `m`, then the curve's ephemeral-scalar candidates in order
        /// (X25519 1, P-256 3, P-384 1: the draft vectors' `ikmE` lengths).
        pub const Ephemeral = [K.encaps_seed_length + G.Nscalar * G.candidates_in_ephemeral]u8;

        pub const KeyPair = struct {
            seed: [Nsk]u8,
            public_key: PublicKey,
            pq: K.KeyPair,
            t_secret: [G.Nscalar]u8,
        };

        pub const Encapped = struct {
            shared_secret: [Nsecret]u8,
            enc: EncappedKey,
        };

        pub fn generateKeyPair(out: *KeyPair, io: std.Io) void {
            var seed: [Nsk]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            entropy.fill(io, &seed);
            fromSeed(out, &seed);
        }

        /// The key pair of a serialized private key (the 32-byte seed):
        /// SHAKE256(seed) → the 64-byte ML-KEM seed, then curve-scalar
        /// candidates until one is valid (Go `hybridKEM.NewPrivateKey`).
        pub fn fromSeed(out: *KeyPair, seed: *const [Nsk]u8) void {
            burn.run(burn_bytes, void, fromSeedBody, .{ out, seed });
        }

        fn fromSeedBody(out: *KeyPair, seed: *const [Nsk]u8) void {
            var x = sha3.Shake256.init(.{});
            defer std.crypto.secureZero(u8, std.mem.asBytes(&x));
            x.update(seed);
            var pq_seed: [K.seed_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &pq_seed);
            x.squeeze(&pq_seed);
            out.seed = seed.*;
            out.pq = K.KeyPair.generateDeterministic(pq_seed) catch |e| switch (e) {};
            // A P-256 candidate fails with probability ~2^-32, a P-384 one
            // ~2^-190, X25519 never: 256 failures in a row is unreachable.
            var tries: usize = 0;
            while (tries < 256) : (tries += 1) {
                x.squeeze(&out.t_secret);
                if (G.validScalar(&out.t_secret)) break;
            } else @panic("hpke: hybrid key derivation exhausted 256 scalar candidates");
            out.public_key[0..K.PublicKey.encoded_length].* = out.pq.public_key.toBytes();
            out.public_key[K.PublicKey.encoded_length..].* = G.publicKey(&out.t_secret);
        }

        pub fn deriveKeyPair(out: *KeyPair, ikm: []const u8) void {
            var seed: [Nsk]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            deriveSeed(kem_id, &seed, ikm);
            fromSeed(out, &seed);
        }

        /// Draws encapsulation randomness with at least one valid curve
        /// candidate. All candidates invalid has probability ~2^-96 (P-256)
        /// or ~2^-190 (P-384), X25519 never; the bound only caps the work.
        pub fn generateEphemeral(out: *Ephemeral, io: std.Io) void {
            var tries: usize = 0;
            while (tries < 8) : (tries += 1) {
                entropy.fill(io, out);
                if (firstValidCandidate(out) != null) return;
            }
            @panic("hpke: 8 ephemeral draws without a valid curve scalar");
        }

        fn firstValidCandidate(eph: *const Ephemeral) ?*const [G.Nscalar]u8 {
            for (0..G.candidates_in_ephemeral) |i| {
                const c = eph[K.encaps_seed_length + i * G.Nscalar ..][0..G.Nscalar];
                if (G.validScalar(c)) return c;
            }
            return null;
        }

        pub fn encap(out: *Encapped, pkR: PublicKey, io: std.Io) EncapError!void {
            var eph: Ephemeral = undefined;
            defer std.crypto.secureZero(u8, &eph);
            generateEphemeral(&eph, io);
            return encapDeterministic(out, pkR, &eph);
        }

        /// `DeserializeError`: a non-canonical ML-KEM key or a curve point off
        /// the curve; `DhFailed`: a low-order X25519 point, the identity, or an
        /// `eph` none of whose curve candidates is a valid scalar
        /// (`generateEphemeral` never produces one).
        pub fn encapDeterministic(out: *Encapped, pkR: PublicKey, eph: *const Ephemeral) EncapError!void {
            return burn.run(burn_bytes, EncapError!void, encapBody, .{ out, &pkR, eph });
        }

        fn encapBody(out: *Encapped, pkR: *const PublicKey, eph: *const Ephemeral) EncapError!void {
            errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
            const ek_pq_len = K.PublicKey.encoded_length;
            const ek_t = pkR[ek_pq_len..][0..G.Npoint];
            const pk_pq = K.PublicKey.fromBytes(pkR[0..ek_pq_len]) catch return error.DeserializeError;

            const sk_e = firstValidCandidate(eph) orelse return error.DhFailed;
            const ct_t = G.publicKey(sk_e);
            var ss_t: [G.Nscalar]u8 = undefined;
            defer std.crypto.secureZero(u8, &ss_t);
            try G.dh(sk_e, ek_t, &ss_t);

            var es = pk_pq.encapsDeterministic(eph[0..K.encaps_seed_length]);
            defer std.crypto.secureZero(u8, &es.shared_secret);

            combine(&out.shared_secret, &es.shared_secret, &ss_t, &ct_t, ek_t);
            out.enc[0..K.ciphertext_length].* = es.ciphertext;
            out.enc[K.ciphertext_length..].* = ct_t;
        }

        pub fn decap(out: *[Nsecret]u8, enc: EncappedKey, skR: *const KeyPair) DecapError!void {
            return burn.run(burn_bytes, DecapError!void, decapBody, .{ out, &enc, skR });
        }

        fn decapBody(out: *[Nsecret]u8, enc: *const EncappedKey, skR: *const KeyPair) DecapError!void {
            errdefer std.crypto.secureZero(u8, out);
            const ct_t = enc[K.ciphertext_length..][0..G.Npoint];
            var ss_pq = skR.pq.secret_key.decaps(enc[0..K.ciphertext_length]) catch |e| switch (e) {};
            defer std.crypto.secureZero(u8, &ss_pq);
            var ss_t: [G.Nscalar]u8 = undefined;
            defer std.crypto.secureZero(u8, &ss_t);
            try G.dh(&skR.t_secret, ct_t, &ss_t);
            combine(out, &ss_pq, &ss_t, ct_t, skR.public_key[K.PublicKey.encoded_length..][0..G.Npoint]);
        }

        /// The C2PRI combiner: SHA3-256(ss_PQ || ss_T || ct_T || ek_T || label).
        fn combine(out: *[Nsecret]u8, ss_pq: *const [32]u8, ss_t: *const [G.Nscalar]u8, ct_t: *const [G.Npoint]u8, ek_t: *const [G.Npoint]u8) void {
            var h = sha3.Sha3_256.init(.{});
            defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
            h.update(ss_pq);
            h.update(ss_t);
            h.update(ct_t);
            h.update(ek_t);
            h.update(label);
            h.final(out);
        }
    };
}

// Burns: deepest ReleaseFast depth ×~1.5, measured by `stackprobe_test.zig`.
pub const MlKem512Kem = MlKemKem(ml_kem.MLKem512, .ml_kem_512, burn.pq_burn_768);
pub const MlKem768Kem = MlKemKem(ml_kem.MLKem768, .ml_kem_768, burn.pq_burn_768);
pub const MlKem1024Kem = MlKemKem(ml_kem.MLKem1024, .ml_kem_1024, burn.pq_burn_1024);
pub const MlKem768P256Kem = HybridKem(ml_kem.MLKem768, NistGroup(P256, 3), .mlkem768_p256, "MLKEM768-P256", burn.pq_burn_768);
pub const MlKem1024P384Kem = HybridKem(ml_kem.MLKem1024, NistGroup(P384, 1), .mlkem1024_p384, "MLKEM1024-P384", burn.pq_burn_1024);
/// X-Wing. The label is the six bytes `\./` `/^\`.
pub const MlKem768X25519Kem = HybridKem(ml_kem.MLKem768, X25519Group, .mlkem768_x25519, "\\.//^\\", burn.pq_burn_768);

const testing = std.testing;

test "pq KEM sizes match draft-ietf-hpke-pq" {
    try testing.expectEqual(@as(usize, 1184), MlKem768Kem.Npk);
    try testing.expectEqual(@as(usize, 1088), MlKem768Kem.Nenc);
    try testing.expectEqual(@as(usize, 1568), MlKem1024Kem.Nenc);
    try testing.expectEqual(@as(usize, 1216), MlKem768X25519Kem.Npk);
    try testing.expectEqual(@as(usize, 1120), MlKem768X25519Kem.Nenc);
    try testing.expectEqual(@as(usize, 1249), MlKem768P256Kem.Npk);
    try testing.expectEqual(@as(usize, 1153), MlKem768P256Kem.Nenc);
    try testing.expectEqual(@as(usize, 1665), MlKem1024P384Kem.Nenc);
    try testing.expectEqual(@as(usize, 32 + 96), @sizeOf(MlKem768P256Kem.Ephemeral));
    try testing.expectEqual(@as(usize, 32 + 48), @sizeOf(MlKem1024P384Kem.Ephemeral));
}

test "hybrid encapDeterministic: an ephemeral with no valid curve candidate is DhFailed, out zeroed" {
    const K = MlKem768P256Kem;
    var kp: K.KeyPair = undefined;
    K.fromSeed(&kp, &@as([32]u8, @splat(7)));
    // Every P-256 candidate 0xff..ff is >= n.
    var eph: K.Ephemeral = @splat(0xff);
    @memset(eph[0..32], 1);
    var out: K.Encapped = undefined;
    @memset(std.mem.asBytes(&out), 0xaa);
    try testing.expectError(error.DhFailed, K.encapDeterministic(&out, kp.public_key, &eph));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&out), 0));
    // One valid candidate among invalid ones is used.
    eph[32 + 64 ..][0..32].* = @splat(0x11);
    try K.encapDeterministic(&out, kp.public_key, &eph);
    var ss: [32]u8 = undefined;
    try K.decap(&ss, out.enc, &kp);
    try testing.expectEqualSlices(u8, &out.shared_secret, &ss);
}
