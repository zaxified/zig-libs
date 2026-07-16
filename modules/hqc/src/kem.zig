// SPDX-License-Identifier: MIT
//! kem — the HQC-KEM Fujisaki-Okamoto (implicit-rejection) transform over
//! `pke.zig`'s PKE (spec §4.2; reference `src/common/kem.c`'s
//! `crypto_kem_keypair`/`crypto_kem_enc`/`crypto_kem_dec`).
//!
//! **Pure composition, same posture as `pke.zig`**: no new algorithm, only
//! the FO wiring (hash the ek, derive (K, theta) via G, re-encrypt and
//! compare in decaps, constant-time-select the real key or the implicit-
//! rejection value). Every step is a direct byte-layout-faithful port of
//! `kem.c` — see each function's doc comment for the correspondence.
//!
//! **API shape**: this module takes `seed_kem`/`coins` as explicit byte
//! arrays rather than owning a stateful PRNG — the caller supplies
//! randomness (from `std.crypto.random`, a test's deterministic vector,
//! or anything else). This mirrors the spec's own presentation (keygen
//! and encaps are literally functions of a random seed) and keeps this
//! module free of hidden global state (`prng.zig`'s reference-derived
//! `Prng` is still there for whoever wants to drive it, e.g. the KAT test
//! reproducing the NIST harness's continuing DRBG stream — see
//! `kem_kat_test.zig`).
//!
//! **FO details matched against the reference** (see `symmetric.c`/
//! `kem.c`, both consulted directly, not re-derived from a generic FO
//! paper):
//! - `(K, theta) = G(H(ek), m, salt)` — a single SHA3-512 call, first
//!   half is `K`, second half is `theta` (`hash_g`'s `output` layout).
//! - The implicit-rejection value is `K_bar = J(H(ek), sigma, ct)`
//!   where `ct` is the ALREADY-SERIALIZED ciphertext bytes the decaps
//!   caller was actually given (`c_kem_t`, i.e. `u || v || salt`) — not
//!   the re-encrypted `ct'`. `sigma` is stored in the decapsulation key,
//!   sampled once at keygen time and never touched again.
//! - The match/mismatch selection is `result -= 1` then
//!   `(K'[i] & result) ^ (K_bar[i] & ~result)` (reference's
//!   `vect_compare`-based mask trick) — reproduced here bit-for-bit via
//!   `ctCompare`, not a source-level `if`/`select`, so there is no
//!   secret-dependent branch in the selection itself (though whether the
//!   *compiler* keeps it branchless is, as with every constant-time claim
//!   elsewhere in this arc, unverified by tooling — see prng.zig's
//!   posture note).

const std = @import("std");
const params = @import("params.zig");
const gf2x = @import("gf2x.zig");
const prng = @import("prng.zig");
const pke = @import("pke.zig");

/// The HQC-KEM scheme for one parameter set.
pub fn Kem(comptime p: params.Params, comptime generator: [2 * p.delta + 1]u8) type {
    return struct {
        pub const Pke = pke.Pke(p, generator);
        pub const Ring = Pke.Ring;
        pub const Message = Pke.Message;

        pub const ek_bytes = p.ekBytes();
        pub const dk_bytes = p.dkBytes();
        pub const ct_bytes = p.ctBytes();
        pub const ss_bytes = params.shared_secret_bytes;
        /// `p.securityBytes()` cached as a named comptime const — used
        /// (rather than calling `p.securityBytes()` inline) everywhere it
        /// appears as a slice bound below: an inline function call isn't
        /// automatically treated as comptime by Zig's array-pointer-
        /// slicing rule even when its value provably is, so slicing with
        /// it inline degrades to a runtime `[]const u8` slice instead of
        /// a sized `*[N]u8` pointer. A named top-level const doesn't have
        /// that problem (container-level consts are always comptime).
        pub const security_bytes = p.securityBytes();
        /// |m| + |salt| — the exact number of bytes `encaps` needs as
        /// external randomness (what the reference draws via two
        /// consecutive `prng_get_bytes` calls: `m` then `salt`).
        pub const coins_bytes = security_bytes + params.salt_bytes;

        pub const EncapsKey = [ek_bytes]u8;
        pub const DecapsKey = [dk_bytes]u8;
        pub const Ciphertext = [ct_bytes]u8;
        pub const SharedSecret = [ss_bytes]u8;

        pub const KeyPair = struct { ek: EncapsKey, dk: DecapsKey };

        comptime {
            std.debug.assert(dk_bytes == ek_bytes + params.seed_bytes + security_bytes + params.seed_bytes);
            std.debug.assert(ct_bytes == Ring.n_bytes + Pke.Code.codeword_len + params.salt_bytes);
        }

        /// crypto_kem_keypair: `seed_kem` (32 B) -> (ek_kem, dk_kem).
        ///
        ///   (seed_pke, sigma) = Xof(seed_kem).getBytes(32), then
        ///                       .getBytes(securityBytes) [CHAINED, same
        ///                       Xof context — reference's `xof_get_bytes`
        ///                       calls on the same `ctx_kem`]
        ///   (ek_pke, dk_pke) = Pke.keygen(seed_pke)
        ///   ek_kem = ek_pke
        ///   dk_kem = ek_kem || dk_pke || sigma || seed_kem
        pub fn keypair(seed_kem: *const [params.seed_bytes]u8) KeyPair {
            var xof = prng.Xof.init(seed_kem);
            var seed_pke: [params.seed_bytes]u8 = undefined;
            xof.getBytes(&seed_pke);
            var sigma: [security_bytes]u8 = undefined;
            xof.getBytes(&sigma);

            const pke_kp = Pke.keygen(&seed_pke);

            var dk: DecapsKey = undefined;
            var off: usize = 0;
            @memcpy(dk[off..][0..ek_bytes], &pke_kp.ek);
            off += ek_bytes;
            @memcpy(dk[off..][0..params.seed_bytes], &pke_kp.dk);
            off += params.seed_bytes;
            @memcpy(dk[off..][0..security_bytes], &sigma);
            off += security_bytes;
            @memcpy(dk[off..][0..params.seed_bytes], seed_kem);

            return .{ .ek = pke_kp.ek, .dk = dk };
        }

        fn serializeCt(u: Ring.Elem, v: Pke.Code.Codeword, salt: [params.salt_bytes]u8) Ciphertext {
            var out: Ciphertext = undefined;
            Ring.toBytes(u, out[0..Ring.n_bytes]);
            @memcpy(out[Ring.n_bytes..][0..Pke.Code.codeword_len], &v);
            @memcpy(out[Ring.n_bytes + Pke.Code.codeword_len ..], &salt);
            return out;
        }

        const ParsedCt = struct { u: Ring.Elem, v: Pke.Code.Codeword, salt: [params.salt_bytes]u8 };

        fn deserializeCt(ct: Ciphertext) ParsedCt {
            const u = Ring.fromBytes(ct[0..Ring.n_bytes]);
            const v: Pke.Code.Codeword = ct[Ring.n_bytes..][0..Pke.Code.codeword_len].*;
            const salt: [params.salt_bytes]u8 = ct[Ring.n_bytes + Pke.Code.codeword_len ..][0..params.salt_bytes].*;
            return .{ .u = u, .v = v, .salt = salt };
        }

        /// Constant-time byte-string compare mirroring the reference's
        /// `vect_compare` exactly: 0 if equal, 1 if different — NOT a
        /// generic bool, because `decaps`'s masking arithmetic below
        /// depends on this exact 0/1 range (see that function).
        fn vectCompare(a: []const u8, b: []const u8) u8 {
            std.debug.assert(a.len == b.len);
            var r: u16 = 0x0100;
            for (a, b) |x, y| r |= x ^ y;
            return @intCast((r -% 1) >> 8);
        }

        /// crypto_kem_enc: `coins` = m(securityBytes) || salt(16).
        ///
        ///   H_ek = H(ek)
        ///   (K, theta) = G(H_ek, m, salt)
        ///   c = Pke.encrypt(ek, m, theta)
        ///   ct = u || v || salt
        ///   ss = K
        pub fn encaps(ek: EncapsKey, coins: *const [coins_bytes]u8) struct { ct: Ciphertext, ss: SharedSecret } {
            const m: Message = coins[0..security_bytes].*;
            const salt: [params.salt_bytes]u8 = coins[security_bytes..coins_bytes].*;

            var h_ek: [params.seed_bytes]u8 = undefined;
            prng.hashH(&h_ek, &ek);

            var k_theta: [64]u8 = undefined;
            prng.hashG(&k_theta, &h_ek, &m, &salt);
            const theta = k_theta[32..64];

            const c = Pke.encrypt(ek, m, theta);
            const ct = serializeCt(c.u, c.v, salt);

            var ss: SharedSecret = undefined;
            @memcpy(&ss, k_theta[0..32]);

            return .{ .ct = ct, .ss = ss };
        }

        /// crypto_kem_dec: parse dk_kem = ek || dk_pke || sigma ||
        /// seed_kem (seed_kem itself unused here, exactly as the
        /// reference never reads it in `crypto_kem_dec`).
        ///
        ///   m' = Pke.decrypt(dk_pke, c)
        ///   H_ek = H(ek)
        ///   (K', theta') = G(H_ek, m', salt)
        ///   c' = Pke.encrypt(ek, m', theta'); ct' = u' || v' || salt
        ///   K_bar = J(H_ek, sigma, ct)              [the ORIGINAL ct]
        ///   ss = (ct' == ct) ? K' : K_bar            [constant-time]
        pub fn decaps(dk: DecapsKey, ct: Ciphertext) SharedSecret {
            var off: usize = 0;
            const ek: EncapsKey = dk[off..][0..ek_bytes].*;
            off += ek_bytes;
            const dk_pke: Pke.DecKey = dk[off..][0..params.seed_bytes].*;
            off += params.seed_bytes;
            const sigma: [security_bytes]u8 = dk[off..][0..security_bytes].*;

            const parsed = deserializeCt(ct);
            const m_prime = Pke.decrypt(dk_pke, .{ .u = parsed.u, .v = parsed.v });

            var h_ek: [params.seed_bytes]u8 = undefined;
            prng.hashH(&h_ek, &ek);

            var k_theta_prime: [64]u8 = undefined;
            prng.hashG(&k_theta_prime, &h_ek, &m_prime, &parsed.salt);
            const theta_prime = k_theta_prime[32..64];

            const c_prime = Pke.encrypt(ek, m_prime, theta_prime);
            const ct_prime = serializeCt(c_prime.u, c_prime.v, parsed.salt);

            var k_bar: SharedSecret = undefined;
            prng.hashJ(&k_bar, &h_ek, &sigma, &ct);

            // result: 0 if ct'==ct (match), 1 otherwise — then wrapped
            // -1 so match -> 0xFF (select K'), mismatch -> 0x00 (select
            // K_bar), matching the reference's mask arithmetic exactly.
            const result: u8 = vectCompare(&ct_prime, &ct) -% 1;

            var ss: SharedSecret = undefined;
            for (&ss, k_theta_prime[0..32], k_bar) |*o, kp, kb| {
                o.* = (kp & result) ^ (kb & ~result);
            }
            return ss;
        }
    };
}
