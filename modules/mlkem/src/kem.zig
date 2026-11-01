// SPDX-License-Identifier: MIT
//! ML-KEM.KeyGen / Encaps / Decaps (FIPS 203 §6, Algorithms 16–18) over
//! K-PKE (§5, Algorithms 13–15). The public shape follows
//! `std.crypto.kem.ml_kem.nist.MLKem*` so a consumer can swap the type in.

const std = @import("std");
const poly = @import("poly.zig");
const sample = @import("sample.zig");

const Poly = poly.Poly;
const sha3 = std.crypto.hash.sha3;

pub const Params = struct {
    name: []const u8,
    k: u8,
    eta1: u2,
    du: u4,
    dv: u4,
};

pub const ml_kem_512: Params = .{ .name = "ML-KEM-512", .k = 2, .eta1 = 3, .du = 10, .dv = 4 };
pub const ml_kem_768: Params = .{ .name = "ML-KEM-768", .k = 3, .eta1 = 2, .du = 10, .dv = 4 };
pub const ml_kem_1024: Params = .{ .name = "ML-KEM-1024", .k = 4, .eta1 = 2, .du = 11, .dv = 5 };

const eta2: u2 = 2;

/// Errors of key import.
pub const KeyError = error{
    /// The encapsulation key fails the modulus check (FIPS 203 §7.2): a
    /// coefficient of t̂ is not in [0, q).
    NonCanonical,
    /// The decapsulation key fails the hash check (FIPS 203 §7.3): its
    /// embedded H(ek) is not the hash of its embedded ek.
    InconsistentKey,
};

pub fn Kem(comptime p: Params) type {
    const k: usize = p.k;
    return struct {
        pub const name = p.name;
        pub const shared_length: usize = 32;
        pub const encaps_seed_length: usize = 32;
        /// d ‖ z of FIPS 203 Algorithm 16.
        pub const seed_length: usize = 64;
        pub const ciphertext_length: usize = 32 * (@as(usize, p.du) * k + p.dv);

        const poly_bytes = 384;
        const du_bytes = 32 * @as(usize, p.du);
        const dv_bytes = 32 * @as(usize, p.dv);

        pub const EncapsulatedSecret = struct {
            shared_secret: [shared_length]u8,
            ciphertext: [ciphertext_length]u8,
        };

        /// K-PKE encryption key with the expanded matrix cached.
        const InnerPk = struct {
            /// t̂ in the NTT layout, canonical [0, q).
            th: [k]Poly,
            rho: [32]u8,
            /// Âᵀ: at[i][j] = Â[j][i] = SampleNTT(ρ ‖ i ‖ j).
            at: [k][k]Poly,

            const encoded_length = poly_bytes * k + 32;

            fn toBytes(pk: *const InnerPk, out: *[encoded_length]u8) void {
                inline for (0..k) |i| pk.th[i].toNttBytes(out[poly_bytes * i ..][0..poly_bytes]);
                out[poly_bytes * k ..][0..32].* = pk.rho;
            }

            fn fromBytes(pk: *InnerPk, in: *const [encoded_length]u8) KeyError!void {
                var ok = true;
                inline for (0..k) |i| ok = pk.th[i].fromNttBytes(in[poly_bytes * i ..][0..poly_bytes]) and ok;
                if (!ok) return error.NonCanonical;
                pk.rho = in[poly_bytes * k ..][0..32].*;
                sample.matrix(k, &pk.at, &pk.rho, true);
            }

            /// K-PKE.Encrypt (Algorithm 14).
            fn encrypt(pk: *const InnerPk, m: *const [32]u8, r: *const [32]u8, out: *[ciphertext_length]u8) void {
                var rh: [k]Poly = undefined;
                var e1: [k]Poly = undefined;
                var e2: Poly = undefined;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&rh));
                defer std.crypto.secureZero(u8, std.mem.asBytes(&e1));
                defer std.crypto.secureZero(u8, std.mem.asBytes(&e2));
                sample.noiseEncrypt(k, p.eta1, &rh, &e1, &e2, r);
                inline for (0..k) |i| rh[i].ntt();

                inline for (0..k) |i| {
                    var u: Poly = .zero;
                    inline for (0..k) |j| u.baseMulAcc(&pk.at[i][j], &rh[j]);
                    u.reduce();
                    u.invNtt();
                    u = u.add(e1[i]);
                    u.normalize();
                    u.compress(p.du, out[du_bytes * i ..][0..du_bytes]);
                }

                var v: Poly = .zero;
                inline for (0..k) |j| v.baseMulAcc(&pk.th[j], &rh[j]);
                v.reduce();
                v.invNtt();
                var mu: Poly = undefined;
                mu.fromMsg(m);
                v = v.add(e2).add(mu);
                v.normalize();
                v.compress(p.dv, out[du_bytes * k ..][0..dv_bytes]);
                std.crypto.secureZero(u8, std.mem.asBytes(&mu));
                std.crypto.secureZero(u8, std.mem.asBytes(&v));
            }
        };

        /// K-PKE decryption key.
        const InnerSk = struct {
            /// ŝ in the NTT layout, canonical [0, q).
            sh: [k]Poly,

            const encoded_length = poly_bytes * k;

            fn toBytes(sk: *const InnerSk, out: *[encoded_length]u8) void {
                inline for (0..k) |i| sk.sh[i].toNttBytes(out[poly_bytes * i ..][0..poly_bytes]);
            }

            /// FIPS 203 does not require a modulus check on dk_PKE; values
            /// ≥ q are reduced (as every other implementation does).
            fn fromBytes(sk: *InnerSk, in: *const [encoded_length]u8) void {
                inline for (0..k) |i| {
                    _ = sk.sh[i].fromNttBytes(in[poly_bytes * i ..][0..poly_bytes]);
                    sk.sh[i].normalize();
                }
            }

            /// K-PKE.Decrypt (Algorithm 15).
            fn decrypt(sk: *const InnerSk, c: *const [ciphertext_length]u8, m: *[32]u8) void {
                var w: Poly = .zero;
                inline for (0..k) |i| {
                    var u: Poly = undefined;
                    u.decompress(p.du, c[du_bytes * i ..][0..du_bytes]);
                    u.ntt();
                    w.baseMulAcc(&sk.sh[i], &u);
                }
                w.reduce();
                w.invNtt();
                var v: Poly = undefined;
                v.decompress(p.dv, c[du_bytes * k ..][0..dv_bytes]);
                w = v.sub(w);
                w.normalize();
                w.toMsg(m);
                std.crypto.secureZero(u8, std.mem.asBytes(&w));
            }
        };

        pub const PublicKey = struct {
            pk: InnerPk,
            /// H(ek), cached.
            hpk: [32]u8,

            pub const encoded_length: usize = InnerPk.encoded_length;

            /// Encapsulate a fresh shared secret (std's infallible shape).
            /// m determines the shared secret, so it is drawn fail-closed
            /// (CONVENTIONS.md §2.2): without entropy the process aborts.
            /// `tryEncaps` returns the failure instead.
            pub fn encaps(pk: *const PublicKey, io: std.Io) EncapsulatedSecret {
                var m: [32]u8 = undefined;
                defer std.crypto.secureZero(u8, &m);
                entropy.fill(io, &m);
                return pk.encapsDeterministic(&m);
            }

            /// `encaps` with the entropy failure as an error.
            pub fn tryEncaps(pk: *const PublicKey, io: std.Io) error{EntropyUnavailable}!EncapsulatedSecret {
                var m: [32]u8 = undefined;
                defer std.crypto.secureZero(u8, &m);
                try entropy.tryFill(io, &m);
                return pk.encapsDeterministic(&m);
            }

            /// ML-KEM.Encaps_internal (Algorithm 17) with m supplied. For
            /// known-answer tests and protocols that derive m themselves;
            /// m must be uniformly random and secret, or the shared secret
            /// is not.
            pub fn encapsDeterministic(pk: *const PublicKey, m: *const [encaps_seed_length]u8) EncapsulatedSecret {
                var kr: [64]u8 = undefined;
                defer std.crypto.secureZero(u8, &kr);
                var g = sha3.Sha3_512.init(.{});
                defer std.crypto.secureZero(u8, std.mem.asBytes(&g));
                g.update(m);
                g.update(&pk.hpk);
                g.final(&kr);
                var out: EncapsulatedSecret = undefined;
                pk.pk.encrypt(m, kr[32..64], &out.ciphertext);
                out.shared_secret = kr[0..32].*;
                return out;
            }

            pub fn toBytes(pk: *const PublicKey) [encoded_length]u8 {
                var out: [encoded_length]u8 = undefined;
                pk.pk.toBytes(&out);
                return out;
            }

            /// Import an encapsulation key, with the FIPS 203 §7.2 modulus
            /// check; expands the matrix.
            pub fn fromBytes(buf: *const [encoded_length]u8) KeyError!PublicKey {
                var ret: PublicKey = undefined;
                try ret.pk.fromBytes(buf);
                sha3.Sha3_256.hash(buf, &ret.hpk, .{});
                return ret;
            }
        };

        pub const SecretKey = struct {
            sk: InnerSk,
            pk: InnerPk,
            hpk: [32]u8,
            z: [32]u8,
            /// d ‖ z when the key was generated here (the 64-byte seed form
            /// Go, BoringSSL, RustCrypto and OpenSSL keep as the private key);
            /// absent for a key imported with `fromBytes`.
            seed: [seed_length]u8,
            has_seed: bool,

            pub const encoded_length: usize = InnerSk.encoded_length + InnerPk.encoded_length + 32 + 32;

            /// ML-KEM.Decaps_internal (Algorithm 18). Never fails: an
            /// invalid ciphertext yields the implicit-rejection key J(z ‖ c).
            pub fn decaps(sk: *const SecretKey, c: *const [ciphertext_length]u8) [shared_length]u8 {
                var m: [32]u8 = undefined;
                var kr: [64]u8 = undefined;
                var c2: [ciphertext_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &m);
                defer std.crypto.secureZero(u8, &kr);
                defer std.crypto.secureZero(u8, &c2);
                sk.sk.decrypt(c, &m);
                var g = sha3.Sha3_512.init(.{});
                defer std.crypto.secureZero(u8, std.mem.asBytes(&g));
                g.update(&m);
                g.update(&sk.hpk);
                g.final(&kr);
                sk.pk.encrypt(&m, kr[32..64], &c2);

                var k_bar: [32]u8 = undefined;
                defer std.crypto.secureZero(u8, &k_bar);
                var j = sha3.Shake256.init(.{});
                defer std.crypto.secureZero(u8, std.mem.asBytes(&j));
                j.update(&sk.z);
                j.update(c);
                j.squeeze(&k_bar);

                // Constant-time select: K' when c' = c, else K̄.
                var diff: u8 = 0;
                for (c, &c2) |a, b| diff |= a ^ b;
                var keep = @as(u8, @truncate((@as(u16, diff) -% 1) >> 8)); // 0xff iff diff == 0
                // Hide that `keep` is 0x00/0xff so LLVM cannot turn the
                // masked select below back into a branch.
                asm volatile (""
                    : [keep] "+r" (keep),
                );
                var out: [32]u8 = undefined;
                for (&out, kr[0..32], &k_bar) |*o, a, b| o.* = (a & keep) | (b & ~keep);
                return out;
            }

            pub fn toBytes(sk: *const SecretKey) [encoded_length]u8 {
                var out: [encoded_length]u8 = undefined;
                sk.sk.toBytes(out[0..InnerSk.encoded_length]);
                sk.pk.toBytes(out[InnerSk.encoded_length..][0..InnerPk.encoded_length]);
                out[InnerSk.encoded_length + InnerPk.encoded_length ..][0..32].* = sk.hpk;
                out[InnerSk.encoded_length + InnerPk.encoded_length + 32 ..][0..32].* = sk.z;
                return out;
            }

            /// Import a decapsulation key with the FIPS 203 §7.3 checks: the
            /// embedded ek passes the modulus check and H(ek) matches.
            pub fn fromBytes(buf: *const [encoded_length]u8) KeyError!SecretKey {
                var ret: SecretKey = undefined;
                errdefer std.crypto.secureZero(u8, std.mem.asBytes(&ret));
                ret.has_seed = false;
                ret.seed = @splat(0);
                const s0 = InnerSk.encoded_length;
                const s1 = s0 + InnerPk.encoded_length;
                ret.sk.fromBytes(buf[0..s0]);
                try ret.pk.fromBytes(buf[s0..s1]);
                var h: [32]u8 = undefined;
                sha3.Sha3_256.hash(buf[s0..s1], &h, .{});
                ret.hpk = buf[s1..][0..32].*;
                ret.z = buf[s1 + 32 ..][0..32].*;
                // The hash is over public data; a plain compare is fine.
                if (!std.mem.eql(u8, &h, &ret.hpk)) return error.InconsistentKey;
                return ret;
            }

            /// The 64-byte seed d ‖ z this key was generated from, or null
            /// for a key imported in expanded form (`fromBytes`).
            pub fn seedBytes(sk: *const SecretKey) ?[seed_length]u8 {
                return if (sk.has_seed) sk.seed else null;
            }
        };

        pub const KeyPair = struct {
            secret_key: SecretKey,
            public_key: PublicKey,

            /// ML-KEM.KeyGen_internal (Algorithm 16) from the seed d ‖ z —
            /// the seed-form private key's import (Go's
            /// `NewDecapsulationKey768`, BoringSSL's `private_key_from_seed`),
            /// and the KAT entry point. A seed must be uniformly random and
            /// secret.
            pub fn generateDeterministic(seed: [seed_length]u8) KeyPair {
                var kp: KeyPair = undefined;
                generateDeterministicInto(&kp, &seed);
                return kp;
            }

            pub fn generateDeterministicInto(kp: *KeyPair, seed: *const [seed_length]u8) void {
                // (ρ, σ) = G(d ‖ k)
                var rs: [64]u8 = undefined;
                defer std.crypto.secureZero(u8, &rs);
                var g = sha3.Sha3_512.init(.{});
                defer std.crypto.secureZero(u8, std.mem.asBytes(&g));
                g.update(seed[0..32]);
                g.update(&[1]u8{p.k});
                g.final(&rs);
                const pk = &kp.secret_key.pk;
                pk.rho = rs[0..32].*;
                // ρ is published in ek; under ctgrind it would inherit d's
                // taint and flag SampleNTT's (public-data) rejection loop.
                // A no-op without `-fvalgrind`.
                std.valgrind.memcheck.makeMemDefined(&pk.rho);

                // Â[i][j] = SampleNTT(ρ ‖ j ‖ i), kept in `at` and transposed below.
                sample.matrix(k, &pk.at, &pk.rho, false);

                var e: [k]Poly = undefined;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&e));
                const sh = &kp.secret_key.sk.sh;
                sample.noiseKeygen(k, p.eta1, sh, &e, rs[32..64]);
                inline for (0..k) |i| {
                    sh[i].ntt();
                    sh[i].normalize();
                    e[i].ntt();
                }
                inline for (0..k) |i| {
                    var t: Poly = .zero;
                    inline for (0..k) |j| t.baseMulAcc(&pk.at[i][j], &sh[j]);
                    t.reduce();
                    t.toMont();
                    pk.th[i] = t.add(e[i]);
                    pk.th[i].normalize();
                }
                inline for (0..k) |i| {
                    inline for (i + 1..k) |j| std.mem.swap(Poly, &pk.at[i][j], &pk.at[j][i]);
                }

                var ek: [InnerPk.encoded_length]u8 = undefined;
                pk.toBytes(&ek);
                sha3.Sha3_256.hash(&ek, &kp.secret_key.hpk, .{});
                kp.secret_key.z = seed[32..64].*;
                kp.secret_key.seed = seed.*;
                kp.secret_key.has_seed = true;
                kp.public_key = .{ .pk = pk.*, .hpk = kp.secret_key.hpk };
            }

            /// Generate a fresh key pair (std's infallible shape); the seed
            /// is drawn fail-closed — without entropy the process aborts.
            /// `tryGenerate` returns the failure instead, and can run the
            /// FIPS 140-3 pairwise consistency test.
            pub fn generate(io: std.Io) KeyPair {
                var kp: KeyPair = undefined;
                generateInto(&kp, io);
                return kp;
            }

            pub fn generateInto(kp: *KeyPair, io: std.Io) void {
                var seed: [seed_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &seed);
                entropy.fill(io, &seed);
                generateDeterministicInto(kp, &seed);
            }

            pub const GenerateOptions = struct {
                /// Run `pairwiseConsistencyCheck` on the new pair (FIPS 140-3
                /// IG 10.3.A; AWS-LC's FIPS module always does, mlkem-native
                /// and OpenSSL make it optional). Costs one encaps + decaps.
                pairwise_check: bool = false,
            };

            pub const GenerateError = error{ EntropyUnavailable, PairwiseConsistency };

            /// `generate` with the entropy failure (and, if enabled, a failed
            /// pairwise consistency test) as an error.
            pub fn tryGenerate(io: std.Io, options: GenerateOptions) GenerateError!KeyPair {
                var kp: KeyPair = undefined;
                try tryGenerateInto(&kp, io, options);
                return kp;
            }

            pub fn tryGenerateInto(kp: *KeyPair, io: std.Io, options: GenerateOptions) GenerateError!void {
                var seed: [seed_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &seed);
                try entropy.tryFill(io, &seed);
                generateDeterministicInto(kp, &seed);
                errdefer std.crypto.secureZero(u8, std.mem.asBytes(kp));
                if (options.pairwise_check) try kp.pairwiseConsistencyCheck();
            }

            /// Encapsulate to the public key and decapsulate with the secret
            /// key; error when the shared secrets differ (a corrupted or
            /// mismatched pair). m is fixed: the check is about the keys,
            /// and its shared secret is never used.
            pub fn pairwiseConsistencyCheck(kp: *const KeyPair) error{PairwiseConsistency}!void {
                const m: [32]u8 = @splat(0x5a);
                var e = kp.public_key.encapsDeterministic(&m);
                defer std.crypto.secureZero(u8, std.mem.asBytes(&e));
                var ss = kp.secret_key.decaps(&e.ciphertext);
                defer std.crypto.secureZero(u8, &ss);
                if (!std.crypto.timing_safe.eql([32]u8, ss, e.shared_secret)) return error.PairwiseConsistency;
            }
        };
    };
}

const entropy = @import("entropy");
