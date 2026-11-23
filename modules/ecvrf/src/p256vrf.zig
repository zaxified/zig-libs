// SPDX-License-Identifier: MIT
//! ECVRF-P256-SHA256-TAI (`suite_string = 0x01`) and ECVRF-P256-SHA256-SSWU
//! (`0x02`), RFC 9381 §5.5: the ciphersuite-generic §5.1-§5.4 algorithms
//! over NIST P-256 with SHA-256, SEC1 compressed points (`ptLen = 33`),
//! big-endian `int_to_string`, the RFC 6979 nonce (§5.4.2.1) and either
//! try-and-increment (`interpret_hash_value_as_a_point(s) =
//! string_to_point(0x02 || s)`) or RFC 9380 `P256_XMD:SHA-256_SSWU_NU_`.
//!
//! Reuse: the curve, its constant-time `mulInto` and the RFC 6979 DRBG are
//! the sibling `p256` module's; the SSWU map and `hash_to_field` are
//! `voprf`'s (`groups.P256Sha256.hash_to_curve`), which owns the NIST maps.
//! Anchors: RFC 9381 Appendix B.1 (Examples 10-12) and B.2 (13-15), every
//! published intermediate (`kat_test.zig`).
//!
//! `x = SK` (§5.5: "the secret scalar x is equal to the secret key SK"),
//! so a key outside `[1, q-1]` is refused at `KeyPair.init`
//! (`error.InvalidSecretKey`); `prove` then cannot fail.

const std = @import("std");
const p256 = @import("p256");
const voprf = @import("voprf");
const burn = @import("burn.zig");

const P256 = p256.P256;
const Scalar = p256.Scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;
const H2c = voprf.groups.P256Sha256.hash_to_curve;

/// RFC 9381 §5.5 `cLen`.
pub const c_len: usize = 16;
/// `qLen` (= `fLen`).
pub const q_len: usize = 32;
/// `ptLen`: SEC1 compressed (`fLen + 1`).
pub const pt_len: usize = 33;
/// `hLen`: SHA-256.
pub const h_len: usize = 32;
/// `pi_string` length, `ptLen + cLen + qLen`.
pub const proof_len: usize = pt_len + c_len + q_len;

pub const SecretKey = [q_len]u8;
pub const PublicKey = [pt_len]u8;
pub const Proof = [proof_len]u8;
pub const Output = [h_len]u8;

/// As the edwards25519 suites' `Error`, plus `InvalidSecretKey` for a
/// `SK` outside `[1, q-1]` (only `KeyPair.init`).
pub const Error = error{ InvalidProof, InvalidPublicKey };
pub const KeyError = error{InvalidSecretKey};

pub const Kind = enum { tai, sswu };

/// One of the two P-256 ciphersuites.
pub fn Suite(comptime kind: Kind) type {
    return struct {
        pub const suite_string: u8 = switch (kind) {
            .tai => 0x01,
            .sswu => 0x02,
        };
        /// `h2c_suite_ID_string` of the SSWU suite.
        pub const h2c_suite_id = "P256_XMD:SHA-256_SSWU_NU_";
        /// `DST = "ECVRF_" || h2c_suite_ID_string || suite_string` (§5.4.1.2).
        pub const dst = "ECVRF_" ++ h2c_suite_id ++ [_]u8{suite_string};

        /// The SSWU `hash_to_field` / map (tests pin the RFC's published `u`).
        pub const hash_to_curve = H2c;

        /// A validated secret key and its public key.
        pub const KeyPair = struct {
            sk: SecretKey,
            pk: PublicKey,

            /// `SK` as a big-endian integer in `[1, q-1]` (SEC1 §3.2.1),
            /// `Y = x*B`, written to `out`. `error.InvalidSecretKey`
            /// otherwise (`out` untouched). The key pair goes out through a
            /// pointer, not by value: a returned `KeyError!KeyPair` left a
            /// copy of `SK` in this frame, above the burn
            /// (`stackprobe3_test.zig`).
            pub fn init(out: *KeyPair, sk: *const SecretKey) KeyError!void {
                const r = initUnburned(out, sk);
                burn.stack(burn.key_burn);
                return r;
            }

            noinline fn initUnburned(out: *KeyPair, sk: *const SecretKey) KeyError!void {
                var x = Scalar.fromBytes(sk.*, .big) catch return error.InvalidSecretKey;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&x));
                if (x.isZero()) return error.InvalidSecretKey;
                var y: P256 = undefined;
                P256.basePoint.mulInto(&y, sk, .big) catch unreachable; // x in [1, q-1]
                out.pk = y.toCompressedSec1();
                out.sk = sk.*;
            }

            /// `ECVRF_prove(SK, alpha_string)` (§5.1). The key pair holds
            /// `SK`: wipe it when done.
            pub fn prove(kp: *const KeyPair, alpha_string: []const u8) Proof {
                const r = proveUnburned(kp, alpha_string);
                burn.stack(burn.prove_burn);
                return r;
            }
        };

        /// `ECVRF_encode_to_curve(PK_string, alpha_string)`, returned as
        /// `point_to_string(H)`. TAI runs a data-dependent loop over
        /// `alpha_string` (§5.4.1.1: avoid it for a secret `alpha`); SSWU
        /// does not.
        pub fn encodeToCurve(pk_string: *const PublicKey, alpha_string: []const u8) PublicKey {
            return encodePoint(pk_string, alpha_string).toCompressedSec1();
        }

        fn encodePoint(pk_string: *const PublicKey, alpha_string: []const u8) P256 {
            switch (kind) {
                .tai => {
                    var ctr: u8 = 0;
                    while (true) : (ctr +%= 1) {
                        var st = Sha256.init(.{});
                        st.update(&[_]u8{ suite_string, 0x01 });
                        st.update(pk_string);
                        st.update(alpha_string);
                        st.update(&[_]u8{ ctr, 0x00 });
                        var s: [pt_len]u8 = undefined;
                        s[0] = 0x02;
                        st.final(s[1..]);
                        // cofactor 1; a 0x02 encoding is never the identity.
                        if (P256.fromSec1(&s)) |h| return h else |_| {}
                    }
                },
                .sswu => {
                    const u = H2c.hashToField(1, &.{ pk_string, alpha_string }, dst);
                    const q = H2c.mapToCurve(u[0]);
                    return .{ .x = q.x, .y = q.y, .z = P256.Fe.one };
                },
            }
        }

        /// `ECVRF_challenge_generation(P1..P5)` (§5.4.3) over encoded points.
        fn challenge(points: [5]*const PublicKey) [c_len]u8 {
            var st = Sha256.init(.{});
            st.update(&[_]u8{ suite_string, 0x02 });
            for (points) |p| st.update(p);
            st.update(&[_]u8{0x00});
            var c: [h_len]u8 = undefined;
            st.final(&c);
            return c[0..c_len].*;
        }

        fn cScalar(c: *const [c_len]u8) Scalar {
            var wide: [32]u8 = @splat(0);
            wide[32 - c_len ..].* = c.*;
            return Scalar.fromBytes(wide, .big) catch unreachable; // < 2^128
        }

        noinline fn proveUnburned(kp: *const KeyPair, alpha_string: []const u8) Proof {
            const h = encodePoint(&kp.pk, alpha_string);
            const h_string = h.toCompressedSec1();
            var gamma: P256 = undefined;
            h.mulInto(&gamma, &kp.sk, .big) catch unreachable; // H has prime order, x != 0
            // §5.4.2.1: RFC 6979 §3.2 with m = h_string, H = SHA-256.
            var hm: [32]u8 = undefined;
            Sha256.hash(&h_string, &hm, .{});
            var k = p256.sign.rfc6979Nonce(kp.sk, hm);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
            var k_bytes = k.toBytes(.big);
            defer std.crypto.secureZero(u8, &k_bytes);
            var kb: P256 = undefined;
            var kh: P256 = undefined;
            P256.basePoint.mulInto(&kb, &k_bytes, .big) catch unreachable; // k in [1, q-1]
            h.mulInto(&kh, &k_bytes, .big) catch unreachable;
            const gamma_string = gamma.toCompressedSec1();
            const u_string = kb.toCompressedSec1();
            const v_string = kh.toCompressedSec1();
            const c = challenge(.{ &kp.pk, &h_string, &gamma_string, &u_string, &v_string });
            var x = Scalar.fromBytes(kp.sk, .big) catch unreachable; // validated by init
            defer std.crypto.secureZero(u8, std.mem.asBytes(&x));
            const s = k.add(cScalar(&c).mul(x));
            var pi: Proof = undefined;
            pi[0..pt_len].* = gamma_string;
            pi[pt_len..][0..c_len].* = c;
            pi[pt_len + c_len ..].* = s.toBytes(.big);
            return pi;
        }

        const Decoded = struct { gamma: P256, c: [c_len]u8, s: Scalar };

        /// `ECVRF_decode_proof` (§5.4.4): `Gamma` must decode (SEC1 §2.3.4),
        /// `s < q`.
        fn decodeProof(pi: *const Proof) Error!Decoded {
            const gamma = P256.fromSec1(pi[0..pt_len]) catch return error.InvalidProof;
            // The identity (a 1-byte encoding) cannot be a 33-byte string.
            const s = Scalar.fromBytes(pi[pt_len + c_len ..].*, .big) catch return error.InvalidProof;
            return .{ .gamma = gamma, .c = pi[pt_len..][0..c_len].*, .s = s };
        }

        fn betaFromGamma(gamma: P256) Output {
            var st = Sha256.init(.{});
            st.update(&[_]u8{ suite_string, 0x03 });
            st.update(&gamma.toCompressedSec1()); // cofactor 1
            st.update(&[_]u8{0x00});
            var beta: Output = undefined;
            st.final(&beta);
            return beta;
        }

        /// `ECVRF_proof_to_hash(pi_string)` (§5.2). As RFC 9381 warns, only
        /// on a proof `verify` accepted or `prove` made.
        pub fn proofToHash(pi: *const Proof) Error!Output {
            const d = try decodeProof(pi);
            return betaFromGamma(d.gamma);
        }

        /// `ECVRF_verify(PK_string, alpha_string, pi_string)` (§5.3) with
        /// `validate_key` TRUE: `PK_string` must be a SEC1 compressed point
        /// on P-256 (§5.4.5: cofactor 1, so only the identity is refused,
        /// and it has no 33-byte encoding).
        pub fn verify(pk_string: *const PublicKey, alpha_string: []const u8, pi: *const Proof) Error!Output {
            const y = P256.fromSec1(pk_string) catch return error.InvalidPublicKey;
            const pk_canon = y.toCompressedSec1();
            const d = try decodeProof(pi);
            const h = encodePoint(&pk_canon, alpha_string);
            const neg_c = cScalar(&d.c).neg().toBytes(.big);
            const s_bytes = d.s.toBytes(.big);
            // U = s*B - c*Y, V = s*H - c*Gamma (public inputs).
            const u = P256.mulDoubleBasePublic(P256.basePoint, s_bytes, y, neg_c, .big) catch return error.InvalidProof;
            const v = P256.mulDoubleBasePublic(h, s_bytes, d.gamma, neg_c, .big) catch return error.InvalidProof;
            const h_string = h.toCompressedSec1();
            const gamma_string = d.gamma.toCompressedSec1();
            const c2 = challenge(.{ &pk_canon, &h_string, &gamma_string, &u.toCompressedSec1(), &v.toCompressedSec1() });
            if (!std.mem.eql(u8, &c2, &d.c)) return error.InvalidProof;
            return betaFromGamma(d.gamma);
        }
    };
}

/// ECVRF-P256-SHA256-TAI (`suite_string = 0x01`).
pub const tai = Suite(.tai);
/// ECVRF-P256-SHA256-SSWU (`suite_string = 0x02`).
pub const sswu = Suite(.sswu);
