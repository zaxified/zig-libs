// SPDX-License-Identifier: MIT

//! tls13.kex -- the (EC)DHE key exchange of a TLS/DTLS 1.3 handshake (RFC 8446
//! §4.2.7/§4.2.8, §7.4) for the groups x25519, secp256r1 and the
//! X25519MLKEM768 hybrid (draft-ietf-tls-ecdhe-mlkem): the ephemeral share a
//! side offers, the shared secret the side holding a private key computes, and
//! the server's one-step answer (needed because the hybrid server
//! ENCAPSULATES to the client's key instead of generating a key pair). Moved
//! from `dtls/src/Connection.zig` on 2026-10-20 (earlier history there);
//! `dtls` calls it through thin wrappers under its old names.
//!
//! Group policy -- which groups to advertise, in what order, which share to
//! offer first -- stays with the engine. This file only computes.
//!
//! Every entry point takes its randomness as a `std.Random` and writes its
//! secrets through an out-pointer; each runs under a dead-stack burn sized
//! for its group (`burn.zig`). On an error the out-pointer's secret bytes are
//! zeroed.

const std = @import("std");
const burn = @import("burn.zig");

const X25519 = std.crypto.dh.X25519;
const P256 = std.crypto.ecc.P256;

/// The ML-KEM-768 half of the `x25519_ml_kem768` hybrid. The construction is
/// draft-ietf-tls-ecdhe-mlkem's, transcribed here rather than taken from
/// `std.crypto.kem.hybrid.MlKem768X25519` — std's type has the SAME share
/// sizes but is X-Wing (a SHA3-256 combiner over secrets ‖ ciphertext ‖ key
/// ‖ label), while TLS feeds the bare `ss_MLKEM ‖ ss_X25519` concatenation
/// to its key schedule. Reusing std's combiner would interoperate with
/// nothing — the same trap `ssh`'s `SHA256(ss_M ‖ ss_X)` documents.
const MlKem768 = std.crypto.kem.ml_kem.MLKem768;

/// RFC 8446 §4.2.7 `NamedGroup` code points of the groups this file computes.
pub const x25519_group: u16 = 0x001d;
pub const secp256r1_group: u16 = 0x0017;
/// draft-ietf-tls-ecdhe-mlkem §6 (IANA TLS Supported Groups registry).
pub const x25519_mlkem768_group: u16 = 0x11ec;

/// draft-ietf-tls-ecdhe-mlkem §3.1.1/§3.1.2 fixed sizes for X25519MLKEM768,
/// pinned as comptime facts so a std resize (there has been one Kyber →
/// ML-KEM transition already) breaks the build here, not on the wire:
/// client share = encapsulation key ‖ X25519 public (ML-KEM FIRST, despite
/// the group's name), server share = ciphertext ‖ X25519 public.
pub const hybrid_client_share_len = MlKem768.PublicKey.encoded_length + 32;
pub const hybrid_server_share_len = MlKem768.ciphertext_length + 32;
comptime {
    std.debug.assert(hybrid_client_share_len == 1216);
    std.debug.assert(hybrid_server_share_len == 1120);
    std.debug.assert(MlKem768.shared_length == 32);
}

/// The longest `KeyShareEntry.key_exchange` any group here produces: the
/// hybrid's client share (ML-KEM-768 encapsulation key ‖ X25519 public).
pub const max_share_len = hybrid_client_share_len;

/// Private-key bytes a `KeyPair` holds: a 32-byte scalar for the two curves;
/// for the hybrid, the 64-byte ML-KEM-768 keygen seed (`d ‖ z` — re-expanded
/// at decapsulation time, FIPS 203's compact seed form, 25× smaller than the
/// expanded decapsulation key) followed by the 32-byte X25519 scalar.
pub const secret_len = MlKem768.seed_length + 32;
comptime {
    std.debug.assert(secret_len == 96);
}

pub const Error = error{
    /// The exchange produced no usable secret: an X25519 low-order/identity
    /// result (in the hybrid's X25519 half too), a P-256 point off the curve
    /// or an identity product, a non-canonical ML-KEM encapsulation key, a
    /// private key shorter than the group needs, or a P-256 keygen that drew
    /// 64 out-of-range scalars in a row (a broken RNG).
    KeyExchangeFailed,
    /// A group this file does not compute, or a peer share whose length is
    /// not the exact one the group fixes.
    MissingKeyShare,
};

/// The exact CLIENT-form `KeyShareEntry.key_exchange` length RFC 8446
/// §4.2.8.1/§4.2.8.2 (and draft-ietf-tls-ecdhe-mlkem for the hybrid) fixes
/// for each group. Exact, not a maximum: a P-256 share that is not 65
/// bytes is not a P-256 share, and accepting a short one would hand
/// peer-controlled bytes to `fromSec1` on the strength of the group id alone.
/// Returns 0 for groups this file does not compute, which never matches a
/// real share length and so reads as "unusable".
///
/// CLIENT-form, because the two curves are symmetric but the hybrid is not:
/// a hybrid CLIENT offers the 1216-byte encapsulation-key form (what this
/// function returns — it sizes what a server accepts and what `generate`
/// produces), while a hybrid SERVER answers with the 1120-byte ciphertext
/// form (checked where the client consumes it, `sharedSecret`).
pub fn expectedShareLen(group: u16) usize {
    return switch (group) {
        x25519_group => 32,
        secp256r1_group => 65,
        x25519_mlkem768_group => hybrid_client_share_len,
        else => 0,
    };
}

/// An ephemeral key pair for one handshake; the public part is the wire
/// CLIENT-form `key_share` value. Only the group's own prefix of `secret` is
/// meaningful (see `secret_len`); zeroization always covers the whole array.
pub const KeyPair = struct {
    group: u16,
    secret: [secret_len]u8,
    public: [max_share_len]u8,
    public_len: usize,
};

/// The key-exchange output fed to `keyschedule.*.deriveHandshakeSecret`: 32
/// bytes for the two curves, 64 (`ss_MLKEM ‖ ss_X25519`) for the hybrid.
/// A struct rather than a slice so the secret bytes live in (and are wiped
/// from) exactly one place per side.
pub const SharedSecret = struct {
    bytes: [64]u8,
    len: usize,

    pub fn slice(self: *const SharedSecret) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// The server's answer: its wire share (the CLIENT-form length for the two
/// curves, the 1120-byte ciphertext form for the hybrid) and the shared
/// secret. Nothing private outlives the call — a server never needs its
/// ephemeral secret again.
pub const ServerExchange = struct {
    group: u16,
    public: [max_share_len]u8,
    public_len: usize,
    shared: SharedSecret,
};

/// Generates this side's ephemeral share in `group` into `out`.
///
/// `random` MUST be a cryptographically secure source. This is the
/// highest-consequence use of randomness in a handshake: the bytes drawn
/// here ARE the ephemeral PRIVATE KEY (the x25519 / secp256r1 scalar, and
/// for the hybrid also the ML-KEM-768 keygen seed). Under a predictable
/// generator a passive eavesdropper who learns the seed derives the same
/// private key, recomputes the (EC)DHE shared secret, and decrypts every
/// session recorded from that peer, retroactively.
///
///   * x25519 (RFC 7748 / RFC 8446 §4.2.8.1): 32 random bytes as the secret
///     scalar — `generateDeterministic` clamps — and the 32-byte public key
///     as the share.
///   * secp256r1 (RFC 8446 §4.2.8.2): a scalar in `[1, n-1]` by rejection
///     sampling (`P256.scalar.rejectNonCanonical` refuses `>= n`; zero is
///     refused separately), and `0x04 || X || Y` as the share. Rejection
///     probability is ~2^-32 per draw, so the bounded loop cannot
///     realistically exhaust; it fails closed with a typed error rather than
///     looping forever on a broken RNG.
///   * x25519_ml_kem768 (draft-ietf-tls-ecdhe-mlkem): a 64-byte ML-KEM-768
///     keygen seed plus an x25519 scalar as above; the share is the 1216-byte
///     `encapsulation key ‖ X25519 public` — the ML-KEM half FIRST, despite
///     the group's name (the draft's one famous inconsistency).
pub fn generate(group: u16, random: std.Random, out: *KeyPair) Error!void {
    return switch (group) {
        x25519_group => burn.run(burn.kex_x25519_burn, Error!void, generateBody, .{ group, random, out }),
        secp256r1_group => burn.run(burn.kex_p256_burn, Error!void, generateBody, .{ group, random, out }),
        x25519_mlkem768_group => burn.run(burn.kex_hybrid_burn, Error!void, generateBody, .{ group, random, out }),
        else => {
            std.crypto.secureZero(u8, &out.secret);
            return error.MissingKeyShare;
        },
    };
}

fn generateBody(group: u16, random: std.Random, out: *KeyPair) Error!void {
    errdefer std.crypto.secureZero(u8, &out.secret);
    out.group = group;
    out.public_len = 0;
    switch (group) {
        x25519_group => {
            var seed: [32]u8 = undefined;
            random.bytes(&seed);
            const x = X25519.KeyPair.generateDeterministic(seed);
            std.crypto.secureZero(u8, &seed);
            out.secret[0..32].* = x.secret_key;
            out.public[0..32].* = x.public_key;
            out.public_len = 32;
        },
        secp256r1_group => {
            var tries: usize = 0;
            while (tries < 64) : (tries += 1) {
                var candidate: [32]u8 = undefined;
                random.bytes(&candidate);
                P256.scalar.rejectNonCanonical(candidate, .big) catch continue; // >= n
                if (std.mem.allEqual(u8, &candidate, 0)) continue; // == 0
                // basePoint * a nonzero canonical scalar is never the identity.
                const point = P256.basePoint.mul(candidate, .big) catch continue;
                out.secret[0..32].* = candidate;
                out.public[0..65].* = point.toUncompressedSec1();
                out.public_len = 65;
                return;
            }
            return error.KeyExchangeFailed;
        },
        x25519_mlkem768_group => {
            var kem_seed: [MlKem768.seed_length]u8 = undefined;
            random.bytes(&kem_seed);
            const kem_kp = MlKem768.KeyPair.generateDeterministic(kem_seed) catch {
                std.crypto.secureZero(u8, &kem_seed);
                return error.KeyExchangeFailed;
            };
            var x_seed: [32]u8 = undefined;
            random.bytes(&x_seed);
            const x = X25519.KeyPair.generateDeterministic(x_seed);
            out.secret[0..MlKem768.seed_length].* = kem_seed;
            out.secret[MlKem768.seed_length..][0..32].* = x.secret_key;
            std.crypto.secureZero(u8, &kem_seed);
            std.crypto.secureZero(u8, &x_seed);
            out.public[0..MlKem768.PublicKey.encoded_length].* = kem_kp.public_key.toBytes();
            out.public[MlKem768.PublicKey.encoded_length..][0..32].* = x.public_key;
            out.public_len = hybrid_client_share_len;
        },
        else => return error.MissingKeyShare,
    }
}

/// The key-exchange shared secret, into `out` — the side that HOLDS a
/// private key (a client always; a server only for the two curve groups, and
/// it uses `serverExchange` for those too).
///
/// The groups differ in more than size, and conflating them is a real
/// interop bug rather than a cosmetic one: X25519's `scalarmult` output IS
/// the shared secret, whereas for the NIST curves RFC 8446 §7.4.2 takes only
/// the X COORDINATE of the shared point ("the shared secret is the x
/// coordinate ... converted to a byte string"), not the 65-byte point. The
/// hybrid is the 64-byte `ss_MLKEM ‖ ss_X25519` concatenation, fed to the
/// key schedule AS-IS (draft-ietf-tls-ecdhe-mlkem) — no hash combiner (see
/// the `MlKem768` note for the two same-sized constructions that DO hash).
/// For the hybrid, `peer_share` is the SERVER form (ciphertext ‖ X25519
/// public, 1120 bytes) — only the client holds a decapsulation key.
///
/// `secret` is the group's own prefix of `KeyPair.secret` (32 bytes for the
/// curves, `secret_len` for the hybrid); a shorter one is a typed error, so a
/// caller cannot silently decapsulate with a truncated key.
///
/// Every path rejects a degenerate result rather than using it: X25519's
/// low-order/identity outputs are rejected by std (in the hybrid too — a
/// poisoned X25519 half must not yield a secret whose classical component
/// the peer controls), and P-256's identity output by `mul`. `peer_share`
/// is peer-controlled, so a wrong length or an off-curve point is a typed
/// error here, never a panic. ML-KEM decapsulation of a valid-length
/// ciphertext cannot fail by design (FIPS 203 implicit rejection: a forged
/// ciphertext yields a garbage secret and the handshake dies at Finished),
/// so there is deliberately no "bad ciphertext" arm to test for.
pub fn sharedSecret(group: u16, secret: []const u8, peer_share: []const u8, out: *SharedSecret) Error!void {
    return switch (group) {
        x25519_group => burn.run(burn.kex_x25519_burn, Error!void, sharedSecretBody, .{ group, secret, peer_share, out }),
        secp256r1_group => burn.run(burn.kex_p256_burn, Error!void, sharedSecretBody, .{ group, secret, peer_share, out }),
        x25519_mlkem768_group => burn.run(burn.kex_hybrid_burn, Error!void, sharedSecretBody, .{ group, secret, peer_share, out }),
        else => {
            std.crypto.secureZero(u8, &out.bytes);
            return error.MissingKeyShare;
        },
    };
}

fn sharedSecretBody(group: u16, secret: []const u8, peer_share: []const u8, out: *SharedSecret) Error!void {
    errdefer std.crypto.secureZero(u8, &out.bytes);
    switch (group) {
        x25519_group => {
            if (secret.len < 32) return error.KeyExchangeFailed;
            if (peer_share.len != 32) return error.MissingKeyShare;
            out.bytes[0..32].* = X25519.scalarmult(secret[0..32].*, peer_share[0..32].*) catch return error.KeyExchangeFailed;
            out.len = 32;
        },
        secp256r1_group => {
            if (secret.len < 32) return error.KeyExchangeFailed;
            if (peer_share.len != 65) return error.MissingKeyShare;
            const point = P256.fromSec1(peer_share) catch return error.KeyExchangeFailed;
            const shared = point.mul(secret[0..32].*, .big) catch return error.KeyExchangeFailed;
            out.bytes[0..32].* = shared.affineCoordinates().x.toBytes(.big);
            out.len = 32;
        },
        x25519_mlkem768_group => {
            if (secret.len < secret_len) return error.KeyExchangeFailed;
            if (peer_share.len != hybrid_server_share_len) return error.MissingKeyShare;
            // Re-expand the decapsulation key from its FIPS 203 seed (the
            // stored private form — see `secret_len`); one keygen, tens of
            // microseconds, once per handshake.
            // Audit A1 (dtls) F5/LOW5: every SEED here is wiped on every
            // exit, but the values derived from a seed are equally
            // sufficient to recompute the session keys from a recorded
            // handshake: `kem_kp` re-expands the FULL ML-KEM decapsulation
            // key (~2.4 KB), and the two `ss_*` are the raw shared secrets.
            // None is read again after this returns, so all three are wiped.
            var kem_kp = MlKem768.KeyPair.generateDeterministic(secret[0..MlKem768.seed_length].*) catch return error.KeyExchangeFailed;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&kem_kp));
            var ss_pq = kem_kp.secret_key.decaps(peer_share[0..MlKem768.ciphertext_length]) catch return error.KeyExchangeFailed;
            defer std.crypto.secureZero(u8, &ss_pq);
            var ss_x = X25519.scalarmult(
                secret[MlKem768.seed_length..][0..32].*,
                peer_share[MlKem768.ciphertext_length..][0..32].*,
            ) catch return error.KeyExchangeFailed;
            defer std.crypto.secureZero(u8, &ss_x);
            out.bytes[0..32].* = ss_pq;
            out.bytes[32..64].* = ss_x;
            out.len = 64;
        },
        else => return error.MissingKeyShare,
    }
}

/// The SERVER half of the key exchange, in one step: consume the client's
/// offered share (CLIENT form), produce this server's answering share and the
/// shared secret into `out`. One function rather than `generate` +
/// `sharedSecret`, because the hybrid cannot be decomposed that way —
/// encapsulation needs the peer's key at "generate" time, and the server's
/// wire share IS the ciphertext, not a public key. For the two curve groups
/// it is exactly that pair, with the ephemeral secret wiped before return.
///
/// `random` MUST be a cryptographically secure source (see `generate`): it
/// draws the server's ephemeral scalar, and for the hybrid the ML-KEM
/// encapsulation seed.
pub fn serverExchange(group: u16, peer_share: []const u8, random: std.Random, out: *ServerExchange) Error!void {
    return switch (group) {
        x25519_group => burn.run(burn.kex_x25519_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        secp256r1_group => burn.run(burn.kex_p256_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        x25519_mlkem768_group => burn.run(burn.kex_hybrid_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        else => {
            std.crypto.secureZero(u8, &out.shared.bytes);
            return error.MissingKeyShare;
        },
    };
}

fn serverExchangeBody(group: u16, peer_share: []const u8, random: std.Random, out: *ServerExchange) Error!void {
    errdefer std.crypto.secureZero(u8, &out.shared.bytes);
    out.group = group;
    switch (group) {
        x25519_group, secp256r1_group => {
            var kp: KeyPair = undefined;
            defer std.crypto.secureZero(u8, &kp.secret);
            try generateBody(group, random, &kp);
            try sharedSecretBody(group, kp.secret[0..32], peer_share, &out.shared);
            out.public = kp.public;
            out.public_len = kp.public_len;
        },
        x25519_mlkem768_group => {
            if (peer_share.len != hybrid_client_share_len) return error.MissingKeyShare;
            // FIPS 203 §7.2 encapsulation-key check: `fromBytes` rejects a
            // non-canonical (out-of-modulus) key — peer-controlled bytes,
            // typed error, never a panic.
            const ek = MlKem768.PublicKey.fromBytes(peer_share[0..MlKem768.PublicKey.encoded_length]) catch return error.KeyExchangeFailed;
            var encaps_seed: [MlKem768.encaps_seed_length]u8 = undefined;
            random.bytes(&encaps_seed);
            var enc = ek.encapsDeterministic(&encaps_seed);
            std.crypto.secureZero(u8, &encaps_seed);
            // Audit A1 (dtls) F5/LOW5: `enc.shared_secret`, `x.secret_key`
            // and `ss_x` are the DERIVED values, equally sufficient to
            // recompute the session keys from a recorded handshake, so they
            // are wiped too. `enc.ciphertext` goes on the wire.
            defer std.crypto.secureZero(u8, &enc.shared_secret);
            var x_seed: [32]u8 = undefined;
            random.bytes(&x_seed);
            var x = X25519.KeyPair.generateDeterministic(x_seed);
            std.crypto.secureZero(u8, &x_seed);
            defer std.crypto.secureZero(u8, &x.secret_key);
            // Same low-order/identity rejection as the classical arm — the
            // X25519 half of a hybrid must not be poisonable either.
            var ss_x = X25519.scalarmult(x.secret_key, peer_share[MlKem768.PublicKey.encoded_length..][0..32].*) catch return error.KeyExchangeFailed;
            defer std.crypto.secureZero(u8, &ss_x);
            out.public[0..MlKem768.ciphertext_length].* = enc.ciphertext;
            out.public[MlKem768.ciphertext_length..][0..32].* = x.public_key;
            out.public_len = hybrid_server_share_len;
            out.shared.bytes[0..32].* = enc.shared_secret;
            out.shared.bytes[32..64].* = ss_x;
            out.shared.len = 64;
        },
        else => return error.MissingKeyShare,
    }
}

// ── tests (moved from dtls/src/Connection.zig with the code) ─────────────

const testing = std.testing;
const hx = @import("testkit").hex.bytes;

test "every group computes and has an exact share length; others are refused" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x91)));
    for ([_]u16{ x25519_mlkem768_group, x25519_group, secp256r1_group }) |g| {
        var kp: KeyPair = undefined;
        try generate(g, csprng.random(), &kp);
        try testing.expectEqual(g, kp.group);
        try testing.expectEqual(expectedShareLen(g), kp.public_len);
        try testing.expect(expectedShareLen(g) != 0);
    }
    // x448 (0x001e) is a real code point this file does not compute.
    var kp: KeyPair = undefined;
    try testing.expectEqual(@as(usize, 0), expectedShareLen(0x001e));
    try testing.expectError(error.MissingKeyShare, generate(0x001e, csprng.random(), &kp));
    var ex: ServerExchange = undefined;
    try testing.expectError(error.MissingKeyShare, serverExchange(0x001e, &(@as([32]u8, @splat(9))), csprng.random(), &ex));
}

test "x25519 and secp256r1: server exchange and client shared secret agree" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x92)));
    for ([_]u16{ x25519_group, secp256r1_group }) |g| {
        var kp: KeyPair = undefined;
        try generate(g, csprng.random(), &kp);
        var ex: ServerExchange = undefined;
        try serverExchange(g, kp.public[0..kp.public_len], csprng.random(), &ex);
        try testing.expectEqual(expectedShareLen(g), ex.public_len);
        var ss: SharedSecret = undefined;
        try sharedSecret(g, &kp.secret, ex.public[0..ex.public_len], &ss);
        try testing.expectEqual(@as(usize, 32), ss.len);
        try testing.expectEqualSlices(u8, ex.shared.slice(), ss.slice());
    }
}

test "x25519 KAT: RFC 8448 §3 ephemeral keys give the RFC's shared secret" {
    const client_priv = hx(32, "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
    const server_pub = hx(32, "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f");
    const shared = hx(32, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    var ss: SharedSecret = undefined;
    try sharedSecret(x25519_group, &client_priv, &server_pub, &ss);
    try testing.expectEqualSlices(u8, &shared, ss.slice());
}

test "sharedSecret secp256r1 KAT: byte-exact against Python `cryptography` (OpenSSL) ECDH" {
    // An INDEPENDENT oracle for the P-256 half of the key exchange, in the
    // same spirit as the RFC 8448 X25519 vector above. Generated with
    // `cryptography` 46.0.5 (OpenSSL 3.5.5): two fixed private scalars,
    // their SEC1 uncompressed public points, and the ECDH output — which for
    // the NIST curves is the shared point's X COORDINATE ONLY (RFC 8446
    // §7.4.2 / SEC1 ECDH), not the 65-byte point. Returning the point, or
    // X||Y, would still make both sides of a self-interop test agree and
    // would still "work" — against nothing but itself.
    const a_scalar = hx(32, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const a_point = hx(65, "04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354");
    const b_scalar = hx(32, "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
    const b_point = hx(65, "0477186fee3e281f9d033a64994f823f7e384151e7383090c3c2954340f295153601a0e901c22a7a492a04cce5c24768a613f77c71b3380043912955379ec12723");
    const shared = hx(32, "ead387cf12ed00b1fd75e195c967ff086d52da18622a70a9b6c05603cbdd913c");

    // (1) the public shares `generate` would put on the wire, recovered
    //     from the same scalars OpenSSL used.
    try testing.expectEqualSlices(u8, &a_point, &(try P256.basePoint.mul(a_scalar, .big)).toUncompressedSec1());
    try testing.expectEqualSlices(u8, &b_point, &(try P256.basePoint.mul(b_scalar, .big)).toUncompressedSec1());

    // (2) the shared secret, from BOTH sides.
    var ss: SharedSecret = undefined;
    try sharedSecret(secp256r1_group, &a_scalar, &b_point, &ss);
    try testing.expectEqualSlices(u8, &shared, ss.slice());
    try sharedSecret(secp256r1_group, &b_scalar, &a_point, &ss);
    try testing.expectEqualSlices(u8, &shared, ss.slice());
}

test "sharedSecret: peer-supplied garbage is a typed error, never a panic, and leaves no secret" {
    const a_scalar = hx(32, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    var ss: SharedSecret = .{ .bytes = @splat(0xAB), .len = 0 };
    // Wrong length for the group (an x25519-sized share labelled P-256).
    try testing.expectError(error.MissingKeyShare, sharedSecret(secp256r1_group, &a_scalar, &(@as([32]u8, @splat(0xAA))), &ss));
    try testing.expect(std.mem.allEqual(u8, &ss.bytes, 0));
    // Right length, not a point on the curve.
    var off_curve = @as([65]u8, @splat(0));
    off_curve[0] = 0x04;
    off_curve[1] = 0x01;
    try testing.expectError(error.KeyExchangeFailed, sharedSecret(secp256r1_group, &a_scalar, &off_curve, &ss));
    // A group this file does not compute.
    try testing.expectError(error.MissingKeyShare, sharedSecret(0x001e, &a_scalar, &(@as([32]u8, @splat(0xAA))), &ss));
    // x25519's own low-order/identity rejection still stands.
    try testing.expectError(error.KeyExchangeFailed, sharedSecret(x25519_group, &a_scalar, &(@as([32]u8, @splat(0))), &ss));
    // A private key shorter than the group needs is a typed error too — the
    // hybrid arm must not decapsulate with a truncated seed.
    try testing.expectError(error.KeyExchangeFailed, sharedSecret(x25519_mlkem768_group, &a_scalar, &(@as([hybrid_server_share_len]u8, @splat(0xAA))), &ss));
}

test "hybrid X25519MLKEM768: both sides agree, and each half is the RIGHT half in the RIGHT place" {
    // No byte-exact external vector exists for the concatenation itself
    // (draft-ietf-tls-ecdhe-mlkem publishes none — the composition is two
    // already-anchored primitives glued end to end), and a plain self-interop
    // round trip would stay green with the halves SWAPPED on both sides. So
    // each half is pinned independently against the primitive it must equal:
    // bytes 0..32 must be the ML-KEM shared secret (recomputed by direct
    // decapsulation of the server's ciphertext), bytes 32..64 the X25519
    // scalarmult output — the draft's order, ML-KEM first despite the name.
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x77)));
    const rnd = csprng.random();

    var kp: KeyPair = undefined;
    try generate(x25519_mlkem768_group, rnd, &kp);
    try testing.expectEqual(@as(usize, hybrid_client_share_len), kp.public_len);

    var ex: ServerExchange = undefined;
    try serverExchange(x25519_mlkem768_group, kp.public[0..kp.public_len], rnd, &ex);
    try testing.expectEqual(@as(usize, hybrid_server_share_len), ex.public_len);
    try testing.expectEqual(@as(usize, 64), ex.shared.len);

    var client_shared: SharedSecret = undefined;
    try sharedSecret(x25519_mlkem768_group, &kp.secret, ex.public[0..ex.public_len], &client_shared);
    try testing.expectEqual(@as(usize, 64), client_shared.len);
    try testing.expectEqualSlices(u8, ex.shared.slice(), client_shared.slice());

    // The ML-KEM half, via direct decapsulation with the re-expanded seed.
    const kem_kp = try MlKem768.KeyPair.generateDeterministic(kp.secret[0..MlKem768.seed_length].*);
    const ss_pq = try kem_kp.secret_key.decaps(ex.public[0..MlKem768.ciphertext_length]);
    try testing.expectEqualSlices(u8, &ss_pq, client_shared.bytes[0..32]);
    // The X25519 half, via direct scalarmult of the two ephemerals.
    const ss_x = try X25519.scalarmult(
        kp.secret[MlKem768.seed_length..][0..32].*,
        ex.public[MlKem768.ciphertext_length..][0..32].*,
    );
    try testing.expectEqualSlices(u8, &ss_x, client_shared.bytes[32..64]);
    // ...which also proves the wire layout: the ciphertext occupies the
    // server share's FIRST 1088 bytes, the X25519 public its last 32.
}

test "hybrid X25519MLKEM768: peer-supplied garbage is a typed error, never a panic" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x78)));
    const rnd = csprng.random();
    var ex: ServerExchange = undefined;

    // Server side: wrong client-share length (the SERVER form's 1120 —
    // right length for the other direction, so a copy-paste of the two
    // constants would pass a naive length check).
    try testing.expectError(error.MissingKeyShare, serverExchange(x25519_mlkem768_group, &(@as([hybrid_server_share_len]u8, @splat(0xAA))), rnd, &ex));
    // Server side: right length, non-canonical encapsulation key (0xFF
    // coefficients are ≥ q, FIPS 203 §7.2's modulus check must refuse).
    try testing.expectError(error.KeyExchangeFailed, serverExchange(x25519_mlkem768_group, &(@as([hybrid_client_share_len]u8, @splat(0xFF))), rnd, &ex));
    // Server side: canonical ML-KEM key, but the X25519 half is the
    // identity — the classical poisoning the hybrid must still refuse.
    var kp: KeyPair = undefined;
    try generate(x25519_mlkem768_group, rnd, &kp);
    var poisoned = kp.public;
    @memset(poisoned[MlKem768.PublicKey.encoded_length..][0..32], 0);
    try testing.expectError(error.KeyExchangeFailed, serverExchange(x25519_mlkem768_group, poisoned[0..hybrid_client_share_len], rnd, &ex));

    // Client side: wrong server-share length (the CLIENT form's 1216).
    var ss: SharedSecret = undefined;
    try testing.expectError(error.MissingKeyShare, sharedSecret(x25519_mlkem768_group, &kp.secret, &(@as([hybrid_client_share_len]u8, @splat(0xAA))), &ss));
    // Client side: identity X25519 half in an otherwise well-formed answer.
    try serverExchange(x25519_mlkem768_group, kp.public[0..kp.public_len], rnd, &ex);
    @memset(ex.public[MlKem768.ciphertext_length..][0..32], 0);
    try testing.expectError(error.KeyExchangeFailed, sharedSecret(x25519_mlkem768_group, &kp.secret, ex.public[0..ex.public_len], &ss));
    // (No "bad ciphertext" arm: FIPS 203 implicit rejection makes a forged
    // ciphertext decapsulate SUCCESSFULLY to garbage, by design — the
    // handshake then dies at Finished.)
}
