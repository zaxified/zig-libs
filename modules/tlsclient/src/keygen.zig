// SPDX-License-Identifier: MIT

//! zig-libs tlsclient: the ClientHello's ECDHE key shares without std's
//! `basePoint.mul`, which was ~2/3 of a handshake's client CPU (P-384 ~1.07 ms,
//! P-256 ~0.29 ms on the author's host, 2026-10-11).
//!
//! * P-384: the `p384` module's key pair (`fromSecretKey`: its fixed-base
//!   comb, constant time, burned). Until 2026-10-13 this file carried its own
//!   comb over std's `P384` and a generated table; the `p384` module replaced
//!   both.
//! * P-256: the `p256` module's comb (`P256.combMulBase`).
//!
//! The key pairs are std's `generateDeterministic`, byte for byte, so the
//! default ClientHello stays std's: the secret scalar comes from std's
//! derivation (`deterministicSecret`, copied from Zig 0.16
//! `std/crypto/ecdsa.zig`, MIT), only the public point is computed elsewhere.
//! `p384`'s own `generateDeterministic` puts the seed last in the HMAC-DRBG
//! input instead of before `x`, so it derives a different secret from the
//! same seed — it is not used here.

const std = @import("std");
const crypto = std.crypto;
const Ecdsa = @import("p384").EcdsaP384Sha384;
const StdEcdsaP384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const EcdsaP256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const p256 = @import("p256");
const IdentityElementError = crypto.errors.IdentityElementError;

/// std's `EcdsaP384Sha384.KeyPair.generateDeterministic(seed)`, byte for
/// byte, as a `p384` key pair (public key from p384's comb).
pub fn keyPairP384(seed: [Ecdsa.KeyPair.seed_length]u8) IdentityElementError!Ecdsa.KeyPair {
    var sk: Ecdsa.SecretKey = .{ .bytes = deterministicSecret(StdEcdsaP384, crypto.ecc.P384, crypto.hash.sha2.Sha384, seed) };
    defer crypto.secureZero(u8, &sk.bytes);
    var kp: Ecdsa.KeyPair = undefined;
    // The derivation returns a scalar in [1, n − 1], so p384's range check
    // (`NonCanonical`) cannot fire; the identity cannot either.
    Ecdsa.KeyPair.fromSecretKeyInto(&kp, &sk) catch return error.IdentityElement;
    return kp;
}

/// std's `EcdsaP256Sha256.KeyPair.generateDeterministic(seed)`, byte for
/// byte, with the public key from `p256.P256.combMulBase` (converted to std's
/// point through its SEC1 encoding, a public value).
pub fn keyPairP256(seed: [EcdsaP256.KeyPair.seed_length]u8) IdentityElementError!EcdsaP256.KeyPair {
    const sk = deterministicSecret(EcdsaP256, crypto.ecc.P256, crypto.hash.sha2.Sha256, seed);
    const q = try p256.P256.combMulBase(sk, .big);
    // The public key goes out in the ClientHello: declassified for ctgrind
    // before std's parser branches on it (a no-op without `-fvalgrind`).
    const sec1 = q.toUncompressedSec1();
    std.valgrind.memcheck.makeMemDefined(&sec1);
    const p = crypto.ecc.P256.fromSec1(&sec1) catch unreachable; // a valid point by construction
    return .{ .secret_key = .{ .bytes = sk }, .public_key = .{ .p = p } };
}

/// The secret scalar of std's `Ecdsa(Curve, Hash).KeyPair.generateDeterministic`:
/// its private `deterministicScalar(h = 0^digest, x = 0x01^scalar, noise = seed)`
/// — copied from Zig 0.16 `std/crypto/ecdsa.zig` (MIT); the differential
/// tests pin the two together.
fn deterministicSecret(comptime E: type, comptime Curve: type, comptime Hash: type, seed: [E.KeyPair.seed_length]u8) [Curve.scalar.encoded_length]u8 {
    const Prf = crypto.auth.hmac.Hmac(Hash);
    const sl = Curve.scalar.encoded_length;
    const nl = E.noise_length;
    const h = [_]u8{0x00} ** Hash.digest_length;
    const x = [_]u8{0x01} ** sl;

    var k = [_]u8{0x00} ** h.len;
    var m = [_]u8{0x00} ** (h.len + 1 + nl + x.len + h.len);
    var t = [_]u8{0x00} ** sl;
    defer crypto.secureZero(u8, &k);
    defer crypto.secureZero(u8, &m);
    defer crypto.secureZero(u8, &t);
    const m_v = m[0..h.len];
    const m_i = &m[m_v.len];
    const m_z = m[m_v.len + 1 ..][0..nl];
    const m_x = m[m_v.len + 1 + nl ..][0..x.len];
    const m_h = m[m.len - h.len ..];
    @memset(m_v, 0x01);
    m_i.* = 0x00;
    @memcpy(m_z, &seed);
    @memcpy(m_x, &x);
    @memcpy(m_h, &h);
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    m_i.* = 0x01;
    Prf.create(&k, &m, &k);
    Prf.create(m_v, m_v, &k);
    while (true) {
        var t_off: usize = 0;
        while (t_off < t.len) : (t_off += m_v.len) {
            const t_end = @min(t_off + m_v.len, t.len);
            Prf.create(m_v, m_v, &k);
            @memcpy(t[t_off..t_end], m_v[0 .. t_end - t_off]);
        }
        if (Curve.scalar.Scalar.fromBytes(t, .big)) |sc| return sc.toBytes(.big) else |_| {}
        m_i.* = 0x00;
        Prf.create(&k, m[0 .. m_v.len + 1], &k);
        Prf.create(m_v, m_v, &k);
    }
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "keygen: keyPairP384 / keyPairP256 == std generateDeterministic, byte for byte" {
    var prng = std.Random.DefaultPrng.init(0x5EED_384);
    for (0..64) |_| {
        var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
        prng.random().bytes(&seed);
        const want = try StdEcdsaP384.KeyPair.generateDeterministic(seed);
        const got = try keyPairP384(seed);
        try testing.expectEqualSlices(u8, &want.secret_key.bytes, &got.secret_key.bytes);
        try testing.expectEqualSlices(u8, &want.public_key.toUncompressedSec1(), &got.public_key.toUncompressedSec1());

        var seed2: [EcdsaP256.KeyPair.seed_length]u8 = undefined;
        prng.random().bytes(&seed2);
        const want2 = try EcdsaP256.KeyPair.generateDeterministic(seed2);
        const got2 = try keyPairP256(seed2);
        try testing.expectEqualSlices(u8, &want2.secret_key.bytes, &got2.secret_key.bytes);
        try testing.expectEqualSlices(u8, &want2.public_key.toUncompressedSec1(), &got2.public_key.toUncompressedSec1());
    }
}
