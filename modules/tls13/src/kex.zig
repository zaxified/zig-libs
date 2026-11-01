// SPDX-License-Identifier: MIT

//! tls13.kex -- the (EC)DHE key exchange of a TLS/DTLS 1.3 handshake (RFC 8446
//! §4.2.7/§4.2.8, §7.4) for the groups x25519, secp256r1, secp384r1, secp521r1, the
//! X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 hybrids
//! (draft-ietf-tls-ecdhe-mlkem) and standalone
//! ML-KEM-512/768/1024 (draft-ietf-tls-mlkem) and the finite-field groups
//! ffdhe2048..ffdhe8192 (RFC 7919, `ffdhe.zig`): the ephemeral share a
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
//!
//! The curve arithmetic is the collection's, not std's (2026-10-21, M3 of
//! `tlsserver`): `ct25519.X25519` (comb key generation, MULX/ADX ladder),
//! `p256`, `p384` and `p521` (comb `k·G`, asm field). Each is byte-exact with std's
//! (their own differential tests), so the shares and secrets are the same
//! octets std computed; std's curves still check the scalar range.

const std = @import("std");
const burn = @import("burn.zig");
const ct25519 = @import("ct25519");
const p256 = @import("p256");
const p384 = @import("p384");
const p521 = @import("p521");
const mlkem = @import("mlkem");
const ffdhe = @import("ffdhe.zig");

const X25519 = ct25519.X25519;
const p256_mod = p256;
const p384_mod = p384;
const P256 = std.crypto.ecc.P256;
const P384 = std.crypto.ecc.P384;

/// The ML-KEM-768 half of the `x25519_ml_kem768` hybrid (the collection's
/// `mlkem` module, byte-identical with std's). The construction is
/// draft-ietf-tls-ecdhe-mlkem's, transcribed here rather than taken from
/// `std.crypto.kem.hybrid.MlKem768X25519` — std's type has the SAME share
/// sizes but is X-Wing (a SHA3-256 combiner over secrets ‖ ciphertext ‖ key
/// ‖ label), while TLS feeds the bare `ss_MLKEM ‖ ss_X25519` concatenation
/// to its key schedule. Reusing std's combiner would interoperate with
/// nothing — the same trap `ssh`'s `SHA256(ss_M ‖ ss_X)` documents.
const MlKem768 = mlkem.MLKem768;
/// Standalone ML-KEM-1024 (draft-ietf-tls-mlkem): the client share is the
/// encapsulation key, the server's the ciphertext, the secret ML-KEM's own
/// 32 bytes. `mlkem` is plain FIPS 203 (no combiner), so it is used as is.
const MlKem1024 = mlkem.MLKem1024;
/// Standalone ML-KEM-512 and ML-KEM-768 (draft-ietf-tls-mlkem), same shape.
const MlKem512 = mlkem.MLKem512;

/// RFC 8446 §4.2.7 `NamedGroup` code points of the groups this file computes.
pub const x25519_group: u16 = 0x001d;
pub const secp256r1_group: u16 = 0x0017;
pub const secp384r1_group: u16 = 0x0018;
pub const secp521r1_group: u16 = 0x0019;
/// draft-ietf-tls-ecdhe-mlkem §6 (IANA TLS Supported Groups registry).
pub const x25519_mlkem768_group: u16 = 0x11ec;
/// draft-ietf-tls-mlkem §6 (IANA TLS Supported Groups registry: MLKEM1024).
pub const mlkem1024_group: u16 = 0x0202;
/// draft-ietf-tls-mlkem §6: MLKEM512 and MLKEM768.
pub const mlkem512_group: u16 = 0x0200;
pub const mlkem768_group: u16 = 0x0201;
/// draft-ietf-tls-ecdhe-mlkem §6: the two NIST-curve hybrids. UNLIKE
/// X25519MLKEM768 the ECDH element comes FIRST in the client share, the server
/// share and the shared secret (Go 1.26 `key_schedule.go`: "For SecP256r1MLKEM768
/// and SecP384r1MLKEM1024, the ECDH share comes first").
pub const secp256r1_mlkem768_group: u16 = 0x11eb;
pub const secp384r1_mlkem1024_group: u16 = 0x11ed;
/// RFC 7919 named finite-field groups (RFC 8446 §4.2.7 code points). Not in any
/// default group list: `tlsserver` enables them through its `groups` config.
pub const ffdhe2048_group: u16 = 0x0100;
pub const ffdhe3072_group: u16 = 0x0101;
pub const ffdhe4096_group: u16 = 0x0102;
pub const ffdhe6144_group: u16 = 0x0103;
pub const ffdhe8192_group: u16 = 0x0104;

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

/// draft-ietf-tls-mlkem §4 fixed sizes for MLKEM1024: client share = the
/// encapsulation key, server share = the ciphertext (the same length, by
/// coincidence of the parameter set).
pub const mlkem1024_client_share_len = MlKem1024.PublicKey.encoded_length;
pub const mlkem1024_server_share_len = MlKem1024.ciphertext_length;
comptime {
    std.debug.assert(mlkem1024_client_share_len == 1568);
    std.debug.assert(mlkem1024_server_share_len == 1568);
    std.debug.assert(MlKem1024.shared_length == 32);
    std.debug.assert(MlKem1024.seed_length == MlKem768.seed_length);
}

/// MLKEM512 / MLKEM768 (draft-ietf-tls-mlkem §4): the same shape, client share
/// = encapsulation key, server share = ciphertext.
pub const mlkem512_client_share_len = MlKem512.PublicKey.encoded_length;
pub const mlkem512_server_share_len = MlKem512.ciphertext_length;
pub const mlkem768_client_share_len = MlKem768.PublicKey.encoded_length;
pub const mlkem768_server_share_len = MlKem768.ciphertext_length;
/// secp521r1 (RFC 8446 §4.2.8.2): the SEC1 uncompressed point, both directions.
pub const p521_share_len = 133;
comptime {
    std.debug.assert(mlkem512_client_share_len == 800);
    std.debug.assert(mlkem512_server_share_len == 768);
    std.debug.assert(mlkem768_client_share_len == 1184);
    std.debug.assert(mlkem768_server_share_len == 1088);
    std.debug.assert(MlKem512.shared_length == 32);
    std.debug.assert(MlKem768.shared_length == 32);
    std.debug.assert(MlKem512.seed_length == MlKem768.seed_length);
    std.debug.assert(2 * p521.scalar.encoded_length + 1 == p521_share_len);
}

/// SecP256r1MLKEM768: client share = SEC1 point (65) ‖ ML-KEM-768
/// encapsulation key; server share = SEC1 point ‖ ciphertext.
pub const p256_hybrid_client_share_len = 65 + MlKem768.PublicKey.encoded_length;
pub const p256_hybrid_server_share_len = 65 + MlKem768.ciphertext_length;
/// SecP384r1MLKEM1024: SEC1 point (97) ‖ ML-KEM-1024 key / ciphertext.
pub const p384_hybrid_client_share_len = 97 + MlKem1024.PublicKey.encoded_length;
pub const p384_hybrid_server_share_len = 97 + MlKem1024.ciphertext_length;
comptime {
    std.debug.assert(p256_hybrid_client_share_len == 1249);
    std.debug.assert(p256_hybrid_server_share_len == 1153);
    std.debug.assert(p384_hybrid_client_share_len == 1665);
    std.debug.assert(p384_hybrid_server_share_len == 1665);
}

comptime {
    // The FFDHE share (len(p)) fits `KeyPair.public` and `ServerExchange.public`
    // whatever else `max_share_len` is made of.
    std.debug.assert(ffdhe.max_plen == ffdhe.infos[ffdhe.infos.len - 1].plen());
}

/// The longest `KeyShareEntry.key_exchange` any group here produces, in
/// either direction: SecP384r1MLKEM1024's.
pub const max_share_len = @max(p521_share_len, mlkem768_client_share_len, hybrid_client_share_len, mlkem1024_client_share_len, mlkem1024_server_share_len, p256_hybrid_client_share_len, p384_hybrid_client_share_len, p384_hybrid_server_share_len, ffdhe.max_plen);
/// The longest SERVER-form share (`ServerExchange.public`). Sizes a ServerHello.
pub const max_server_share_len = @max(hybrid_server_share_len, mlkem1024_server_share_len, p521_share_len, p256_hybrid_server_share_len, p384_hybrid_server_share_len, ffdhe.max_plen);

/// Private-key bytes a `KeyPair` holds: a 32-byte scalar for x25519 and
/// secp256r1, a 48-byte one for secp384r1, a 66-byte one for secp521r1 (`scalarLen`);
/// for the hybrids, the 64-byte ML-KEM keygen seed (`d ‖ z` — re-expanded
/// at decapsulation time, FIPS 203's compact seed form, 25× smaller than the
/// expanded decapsulation key) followed by the 32-byte X25519 scalar; for
/// the standalone ML-KEM groups their 64-byte keygen seed alone.
/// SecP384r1MLKEM1024 is the longest: seed ‖ 48-byte P-384 scalar (the P-256
/// hybrid stores seed ‖ 32-byte scalar, X25519MLKEM768 seed ‖ 32-byte scalar).
pub const secret_len = MlKem768.seed_length + 48;
comptime {
    std.debug.assert(secret_len == 112);
}
/// Private-key bytes X25519MLKEM768 and SecP256r1MLKEM768 use.
const secret_len_32 = MlKem768.seed_length + 32;

pub const Error = error{
    /// The exchange produced no usable secret: an X25519 low-order/identity
    /// result (in the hybrid's X25519 half too), a P-256/P-384 point off the
    /// curve or an identity product, a non-canonical ML-KEM encapsulation key, a
    /// private key shorter than the group needs, or a NIST-curve keygen that drew
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
/// CLIENT-form, because the curves are symmetric but the hybrid is not:
/// a hybrid CLIENT offers the 1216-byte encapsulation-key form (what this
/// function returns — it sizes what a server accepts and what `generate`
/// produces), while a hybrid SERVER answers with the 1120-byte ciphertext
/// form (checked where the client consumes it, `sharedSecret`).
pub fn expectedShareLen(group: u16) usize {
    return switch (group) {
        x25519_group => 32,
        secp256r1_group => 65,
        secp384r1_group => 97,
        secp521r1_group => p521_share_len,
        x25519_mlkem768_group => hybrid_client_share_len,
        mlkem1024_group => mlkem1024_client_share_len,
        mlkem512_group => mlkem512_client_share_len,
        mlkem768_group => mlkem768_client_share_len,
        secp256r1_mlkem768_group => p256_hybrid_client_share_len,
        secp384r1_mlkem1024_group => p384_hybrid_client_share_len,
        else => if (ffdhe.find(group)) |f| f.plen() else 0,
    };
}

/// The prefix of `KeyPair.secret` the group uses: its scalar for the three
/// curves, 96 bytes (seed ‖ X25519 scalar) for X25519MLKEM768, `secret_len`
/// for the P-384 hybrid, the 64-byte seed for
/// ML-KEM-1024; 0 for groups this file does not compute. The least
/// `sharedSecret` accepts as `secret`.
pub fn scalarLen(group: u16) usize {
    return switch (group) {
        x25519_group, secp256r1_group => 32,
        secp384r1_group => 48,
        secp521r1_group => 66,
        x25519_mlkem768_group, secp256r1_mlkem768_group => secret_len_32,
        secp384r1_mlkem1024_group => secret_len,
        mlkem1024_group, mlkem512_group, mlkem768_group => MlKem1024.seed_length,
        // The FFDHE exponent: 29 / 35 / 41 / 47 / 50 bytes (225 .. 400 bits).
        else => if (ffdhe.find(group)) |f| f.xlen() else 0,
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

/// Capacity of `SharedSecret.bytes`: ffdhe8192's 1024 bytes (the others need at most 80).
pub const shared_secret_cap = ffdhe.max_plen;

/// The key-exchange output fed to `keyschedule.*.deriveHandshakeSecret`: 32
/// bytes for x25519, secp256r1 and the standalone ML-KEM groups, 48 for secp384r1, 66 for secp521r1,
/// len(p) = 256 .. 1024 for ffdhe2048 .. ffdhe8192 (leading zeros kept), 64
/// (`ss_MLKEM ‖ ss_X25519`) for the X25519 hybrid, 64 (`ss_ECDH ‖ ss_MLKEM`,
/// ECDH FIRST) for SecP256r1MLKEM768, 80 for SecP384r1MLKEM1024.
/// A struct rather than a slice so the secret bytes live in (and are wiped
/// from) exactly one place per side.
pub const SharedSecret = struct {
    bytes: [shared_secret_cap]u8,
    len: usize,

    pub fn slice(self: *const SharedSecret) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// The server's answer: its wire share (the CLIENT-form length for the
/// curves, the ciphertext for the hybrid and ML-KEM-1024) and the shared
/// secret. Nothing private outlives the call — a server never needs its
/// ephemeral secret again.
pub const ServerExchange = struct {
    group: u16,
    public: [max_server_share_len]u8,
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
///   * secp256r1 / secp384r1 (RFC 8446 §4.2.8.2): a scalar in `[1, n-1]` by
///     rejection sampling (`scalar.rejectNonCanonical` refuses `>= n`; zero is
///     refused separately), and `0x04 || X || Y` as the share. Rejection
///     probability is ~2^-32 per draw, so the bounded loop cannot
///     realistically exhaust; it fails closed with a typed error rather than
///     looping forever on a broken RNG.
///   * x25519_ml_kem768 (draft-ietf-tls-ecdhe-mlkem): a 64-byte ML-KEM-768
///     keygen seed plus an x25519 scalar as above; the share is the 1216-byte
///     `encapsulation key ‖ X25519 public` — the ML-KEM half FIRST, despite
///     the group's name (the draft's one famous inconsistency).
///   * mlkem1024 (draft-ietf-tls-mlkem): a 64-byte ML-KEM-1024 keygen seed;
///     the share is the 1568-byte encapsulation key.
pub fn generate(group: u16, random: std.Random, out: *KeyPair) Error!void {
    return generateWith(group, random, out, null);
}

/// `generate`, and also the expanded ML-KEM decapsulation key (`Expanded`)
/// the same keygen computed anyway -- one expansion instead of the second one
/// `sharedSecret` would do. For groups without an ML-KEM half `exp` is `.none`.
/// Hand `exp` back to `sharedSecretExpanded`; wipe it with `Expanded.wipe`.
pub fn generateExpanded(group: u16, random: std.Random, out: *KeyPair, exp: *Expanded) Error!void {
    return generateWith(group, random, out, exp);
}

fn generateWith(group: u16, random: std.Random, out: *KeyPair, exp: ?*Expanded) Error!void {
    if (exp) |e| e.* = .none;
    return switch (group) {
        x25519_group => burn.run(burn.kex_x25519_burn, Error!void, generateBody, .{ group, random, out, exp }),
        secp256r1_group => burn.run(burn.kex_p256_burn, Error!void, generateBody, .{ group, random, out, exp }),
        secp384r1_group => burn.run(burn.kex_p384_burn, Error!void, generateBody, .{ group, random, out, exp }),
        secp521r1_group => burn.run(burn.kex_p521_burn, Error!void, generateBody, .{ group, random, out, exp }),
        mlkem512_group => burn.run(burn.kex_mlkem512_burn, Error!void, generateBody, .{ group, random, out, exp }),
        mlkem768_group => burn.run(burn.kex_mlkem768_burn, Error!void, generateBody, .{ group, random, out, exp }),
        x25519_mlkem768_group => burn.run(burn.kex_hybrid_burn, Error!void, generateBody, .{ group, random, out, exp }),
        mlkem1024_group => burn.run(burn.kex_mlkem1024_burn, Error!void, generateBody, .{ group, random, out, exp }),
        secp256r1_mlkem768_group => burn.run(burn.kex_p256_hybrid_burn, Error!void, generateBody, .{ group, random, out, exp }),
        secp384r1_mlkem1024_group => burn.run(burn.kex_p384_hybrid_burn, Error!void, generateBody, .{ group, random, out, exp }),
        ffdhe2048_group, ffdhe3072_group, ffdhe4096_group, ffdhe6144_group, ffdhe8192_group => burn.run(burn.kex_ffdhe_burn, Error!void, generateBody, .{ group, random, out, exp }),
        else => {
            std.crypto.secureZero(u8, &out.secret);
            out.group = group;
            out.public_len = 0;
            return error.MissingKeyShare;
        },
    };
}

fn generateBody(group: u16, random: std.Random, out: *KeyPair, exp: ?*Expanded) Error!void {
    errdefer {
        std.crypto.secureZero(u8, &out.secret);
        out.public_len = 0;
        if (exp) |e| e.wipe();
    }
    out.group = group;
    out.public_len = 0;
    switch (group) {
        x25519_group => {
            random.bytes(out.secret[0..32]);
            // Never fails: a clamped scalar times the base point is not the identity.
            X25519.recoverPublicKeyInto(out.public[0..32], out.secret[0..32]) catch return error.KeyExchangeFailed;
            out.public_len = 32;
        },
        secp256r1_group => try generateNist(p256.EcdsaP256Sha256, P256, random, out),
        secp384r1_group => try generateNist(p384.EcdsaP384Sha384, P384, random, out),
        secp521r1_group => try generateNist(p521.EcdsaP521Sha512, p521, random, out),
        x25519_mlkem768_group => try hybridGenerate(random, out, exp),
        mlkem1024_group => try mlkemGenerate(MlKem1024, random, out, exp),
        mlkem512_group => try mlkemGenerate(MlKem512, random, out, exp),
        mlkem768_group => try mlkemGenerate(MlKem768, random, out, exp),
        secp256r1_mlkem768_group => try nistHybridGenerate(NistHybrid.p256, random, out, exp),
        secp384r1_mlkem1024_group => try nistHybridGenerate(NistHybrid.p384, random, out, exp),
        ffdhe2048_group, ffdhe3072_group, ffdhe4096_group, ffdhe6144_group, ffdhe8192_group => try ffdheGenerate(group, random, out),
        else => return error.MissingKeyShare,
    }
}

/// The secp256r1 / secp384r1 arm of `generate`: `E` is the collection's
/// `p256.EcdsaP256Sha256` / `p384.EcdsaP384Sha384` / `p521.EcdsaP521Sha512` (its
/// key pair is `d·G` on the fixed-base comb), `C` std's `P256` / `P384` or the
/// `p521` module (it has `scalar` too) for the range check.
noinline fn generateNist(comptime E: type, comptime C: type, random: std.Random, out: *KeyPair) Error!void {
    return generateNistAt(E, C, random, out, 0);
}

/// `generateNist` with the scalar stored at `out.secret[sec_off..]` (the
/// hybrids keep the ML-KEM seed in front of it); the SEC1 point goes to
/// `out.public[0..]`.
fn generateNistAt(comptime E: type, comptime C: type, random: std.Random, out: *KeyPair, sec_off: usize) Error!void {
    const n = C.scalar.encoded_length;
    var tries: usize = 0;
    while (tries < 64) : (tries += 1) {
        const candidate = out.secret[sec_off..][0..n];
        random.bytes(candidate);
        // P-521's order has 521 bits in 66 bytes: mask the top byte to the one
        // bit it can carry (RFC 9180 §7.1.3's bitmask), or 127 of 128 draws
        // would be rejected. The masked draw is still uniform over [0, 2^521).
        if (comptime n == 66) candidate[0] &= 0x01;
        C.scalar.rejectNonCanonical(candidate.*, .big) catch continue; // >= n
        if (std.mem.allEqual(u8, candidate, 0)) continue; // == 0
        var kp: E.KeyPair = undefined;
        defer std.crypto.secureZero(u8, &kp.secret_key.bytes);
        // basePoint * a nonzero canonical scalar is never the identity.
        E.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = candidate.* }) catch continue;
        out.public[0 .. 2 * n + 1].* = kp.public_key.toUncompressedSec1();
        out.public_len = 2 * n + 1;
        return;
    }
    return error.KeyExchangeFailed;
}

/// The key-exchange shared secret, into `out` — the side that HOLDS a
/// private key (a client always; a server only for the curve groups, and
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
/// `secret` is the group's own prefix of `KeyPair.secret` (`scalarLen`: the
/// curve's scalar, the ML-KEM seed plus the curve scalar for a hybrid); a shorter one is a typed error, so a
/// caller cannot silently decapsulate with a truncated key.
///
/// Every path rejects a degenerate result rather than using it: X25519's
/// low-order/identity outputs are rejected by std (in the hybrid too — a
/// poisoned X25519 half must not yield a secret whose classical component
/// the peer controls), and P-256/P-384 identity output by `mul`. `peer_share`
/// is peer-controlled, so a wrong length or an off-curve point is a typed
/// error here, never a panic. ML-KEM decapsulation of a valid-length
/// ciphertext cannot fail by design (FIPS 203 implicit rejection: a forged
/// ciphertext yields a garbage secret and the handshake dies at Finished),
/// so there is deliberately no "bad ciphertext" arm to test for.
pub fn sharedSecret(group: u16, secret: []const u8, peer_share: []const u8, out: *SharedSecret) Error!void {
    return sharedSecretWith(group, secret, null, peer_share, out);
}

/// `sharedSecret` with the expanded decapsulation key `generateExpanded` (or
/// `expand`) produced for the SAME `secret`: skips the seed re-expansion (a
/// full ML-KEM keygen, ~40% of the client's decapsulation). `exp` must come
/// from this key pair -- a mismatched one yields a garbage secret (the
/// handshake dies at Finished, FIPS 203 implicit rejection), not a typed
/// error; one for another KEM size is `KeyExchangeFailed`. For a group without
/// an ML-KEM half `exp` is ignored.
pub fn sharedSecretExpanded(group: u16, secret: []const u8, exp: *const Expanded, peer_share: []const u8, out: *SharedSecret) Error!void {
    return sharedSecretWith(group, secret, exp, peer_share, out);
}

fn sharedSecretWith(group: u16, secret: []const u8, exp: ?*const Expanded, peer_share: []const u8, out: *SharedSecret) Error!void {
    return switch (group) {
        x25519_group => burn.run(burn.kex_x25519_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        secp256r1_group => burn.run(burn.kex_p256_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        secp384r1_group => burn.run(burn.kex_p384_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        secp521r1_group => burn.run(burn.kex_p521_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        mlkem512_group => burn.run(burn.kex_mlkem512_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        mlkem768_group => burn.run(burn.kex_mlkem768_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        x25519_mlkem768_group => burn.run(burn.kex_hybrid_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        mlkem1024_group => burn.run(burn.kex_mlkem1024_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        secp256r1_mlkem768_group => burn.run(burn.kex_p256_hybrid_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        secp384r1_mlkem1024_group => burn.run(burn.kex_p384_hybrid_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        ffdhe2048_group, ffdhe3072_group, ffdhe4096_group, ffdhe6144_group, ffdhe8192_group => burn.run(burn.kex_ffdhe_burn, Error!void, sharedSecretBody, .{ group, secret, exp, peer_share, out }),
        else => {
            std.crypto.secureZero(u8, &out.bytes);
            out.len = 0;
            return error.MissingKeyShare;
        },
    };
}

fn sharedSecretBody(group: u16, secret: []const u8, exp: ?*const Expanded, peer_share: []const u8, out: *SharedSecret) Error!void {
    // An error leaves an empty secret: `slice()` stays in bounds.
    errdefer {
        std.crypto.secureZero(u8, &out.bytes);
        out.len = 0;
    }
    switch (group) {
        x25519_group => {
            if (secret.len < 32) return error.KeyExchangeFailed;
            if (peer_share.len != 32) return error.MissingKeyShare;
            X25519.scalarmultInto(out.bytes[0..32], secret[0..32], peer_share[0..32].*) catch return error.KeyExchangeFailed;
            out.len = 32;
        },
        secp256r1_group => {
            if (secret.len < 32) return error.KeyExchangeFailed;
            if (peer_share.len != 65) return error.MissingKeyShare;
            p256.ecdhInto(out.bytes[0..32], secret[0..32], peer_share) catch return error.KeyExchangeFailed;
            out.len = 32;
        },
        secp384r1_group => {
            if (secret.len < 48) return error.KeyExchangeFailed;
            if (peer_share.len != 97) return error.MissingKeyShare;
            p384.ecdhInto(out.bytes[0..48], secret[0..48], peer_share) catch return error.KeyExchangeFailed;
            out.len = 48;
        },
        secp521r1_group => {
            if (secret.len < 66) return error.KeyExchangeFailed;
            if (peer_share.len != p521_share_len) return error.MissingKeyShare;
            p521.ecdhInto(out.bytes[0..66], secret[0..66], peer_share) catch return error.KeyExchangeFailed;
            out.len = 66;
        },
        x25519_mlkem768_group => try hybridDecaps(secret, exp, peer_share, out),
        mlkem1024_group => try mlkemDecaps1(MlKem1024, secret, exp, peer_share, out),
        mlkem512_group => try mlkemDecaps1(MlKem512, secret, exp, peer_share, out),
        mlkem768_group => try mlkemDecaps1(MlKem768, secret, exp, peer_share, out),
        secp256r1_mlkem768_group => try nistHybridDecaps(NistHybrid.p256, secret, exp, peer_share, out),
        secp384r1_mlkem1024_group => try nistHybridDecaps(NistHybrid.p384, secret, exp, peer_share, out),
        ffdhe2048_group, ffdhe3072_group, ffdhe4096_group, ffdhe6144_group, ffdhe8192_group => try ffdheShared(group, secret, peer_share, out),
        else => return error.MissingKeyShare,
    }
}

/// The SERVER half of the key exchange, in one step: consume the client's
/// offered share (CLIENT form), produce this server's answering share and the
/// shared secret into `out`. One function rather than `generate` +
/// `sharedSecret`, because the hybrid cannot be decomposed that way —
/// encapsulation needs the peer's key at "generate" time, and the server's
/// wire share IS the ciphertext, not a public key. For the curve groups
/// it is exactly that pair, with the ephemeral secret wiped before return.
///
/// `random` MUST be a cryptographically secure source (see `generate`): it
/// draws the server's ephemeral scalar, and for the hybrid the ML-KEM
/// encapsulation seed.
pub fn serverExchange(group: u16, peer_share: []const u8, random: std.Random, out: *ServerExchange) Error!void {
    return switch (group) {
        x25519_group => burn.run(burn.kex_x25519_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        secp256r1_group => burn.run(burn.kex_p256_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        secp384r1_group => burn.run(burn.kex_p384_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        secp521r1_group => burn.run(burn.kex_p521_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        mlkem512_group => burn.run(burn.kex_mlkem512_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        mlkem768_group => burn.run(burn.kex_mlkem768_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        x25519_mlkem768_group => burn.run(burn.kex_hybrid_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        mlkem1024_group => burn.run(burn.kex_mlkem1024_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        secp256r1_mlkem768_group => burn.run(burn.kex_p256_hybrid_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        secp384r1_mlkem1024_group => burn.run(burn.kex_p384_hybrid_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        ffdhe2048_group, ffdhe3072_group, ffdhe4096_group, ffdhe6144_group, ffdhe8192_group => burn.run(burn.kex_ffdhe_burn, Error!void, serverExchangeBody, .{ group, peer_share, random, out }),
        else => {
            std.crypto.secureZero(u8, &out.shared.bytes);
            out.group = group;
            out.public_len = 0;
            out.shared.len = 0;
            return error.MissingKeyShare;
        },
    };
}

fn serverExchangeBody(group: u16, peer_share: []const u8, random: std.Random, out: *ServerExchange) Error!void {
    errdefer {
        std.crypto.secureZero(u8, &out.shared.bytes);
        out.public_len = 0;
        out.shared.len = 0;
    }
    out.group = group;
    switch (group) {
        x25519_group, secp256r1_group, secp384r1_group, secp521r1_group, ffdhe2048_group, ffdhe3072_group, ffdhe4096_group, ffdhe6144_group, ffdhe8192_group => {
            var kp: KeyPair = undefined;
            defer std.crypto.secureZero(u8, &kp.secret);
            try generateBody(group, random, &kp, null);
            try sharedSecretBody(group, kp.secret[0..scalarLen(group)], null, peer_share, &out.shared);
            out.public = kp.public;
            out.public_len = kp.public_len;
        },
        x25519_mlkem768_group => try hybridEncaps(peer_share, random, out),
        mlkem1024_group => try mlkemEncaps1(MlKem1024, peer_share, random, out),
        mlkem512_group => try mlkemEncaps1(MlKem512, peer_share, random, out),
        mlkem768_group => try mlkemEncaps1(MlKem768, peer_share, random, out),
        secp256r1_mlkem768_group => try nistHybridEncaps(NistHybrid.p256, peer_share, random, out),
        secp384r1_mlkem1024_group => try nistHybridEncaps(NistHybrid.p384, peer_share, random, out),
        else => return error.MissingKeyShare,
    }
}

// The ML-KEM arms (X25519MLKEM768's and ML-KEM-1024's), out of line:
// inlined into the bodies above, their key structures deepen the shared
// frame for every group (the stack probe measured x25519's
// `serverExchange` at 161 KiB instead of 58 with ML-KEM-1024 inline; with
// the hybrid inline its curve work began 44 KiB down, 2026-10-21).

/// The expanded ML-KEM decapsulation key a client can keep from key
/// generation to the ServerHello instead of re-deriving it from the seed in
/// `KeyPair.secret` (a full keygen, ~40% of a client's decapsulation:
/// `generateExpanded`, `expand`, `sharedSecretExpanded`). **Secret material**
/// (~7.8 KB / ~12.4 KB: `mlkem`'s key carries the expanded matrix Âᵀ):
/// wipe it with `wipe` wherever the matching
/// `KeyPair.secret` is wiped. Plain bytes, so it can be copied and moved like
/// `KeyPair`.
pub const Expanded = union(enum) {
    none,
    mlkem512: MlKem512.SecretKey,
    mlkem768: MlKem768.SecretKey,
    mlkem1024: MlKem1024.SecretKey,

    fn of(comptime K: type, sk: K.SecretKey) Expanded {
        return if (K == MlKem512) .{ .mlkem512 = sk } else if (K == MlKem768) .{ .mlkem768 = sk } else .{ .mlkem1024 = sk };
    }

    /// Zeroes the whole union (the unused variant's bytes included) and sets `.none`.
    pub fn wipe(e: *Expanded) void {
        std.crypto.secureZero(u8, std.mem.asBytes(e));
        e.* = .none;
    }
};

/// Expands `secret` (the group's `KeyPair.secret` prefix) into `exp` for a
/// later `sharedSecretExpanded`: one ML-KEM keygen from the seed. Groups
/// without an ML-KEM half yield `.none`.
pub fn expand(group: u16, secret: []const u8, exp: *Expanded) Error!void {
    exp.* = .none;
    return switch (group) {
        x25519_mlkem768_group => burn.run(burn.kex_hybrid_burn, Error!void, expandWith, .{ MlKem768, secret, exp }),
        secp256r1_mlkem768_group => burn.run(burn.kex_p256_hybrid_burn, Error!void, expandWith, .{ MlKem768, secret, exp }),
        mlkem1024_group => burn.run(burn.kex_mlkem1024_burn, Error!void, expandWith, .{ MlKem1024, secret, exp }),
        mlkem512_group => burn.run(burn.kex_mlkem512_burn, Error!void, expandWith, .{ MlKem512, secret, exp }),
        mlkem768_group => burn.run(burn.kex_mlkem768_burn, Error!void, expandWith, .{ MlKem768, secret, exp }),
        secp384r1_mlkem1024_group => burn.run(burn.kex_p384_hybrid_burn, Error!void, expandWith, .{ MlKem1024, secret, exp }),
        x25519_group, secp256r1_group, secp384r1_group, secp521r1_group, ffdhe2048_group, ffdhe3072_group, ffdhe4096_group, ffdhe6144_group, ffdhe8192_group => {},
        else => error.MissingKeyShare,
    };
}

noinline fn expandWith(comptime K: type, secret: []const u8, exp: *Expanded) Error!void {
    if (secret.len < K.seed_length) return error.KeyExchangeFailed;
    var kem_kp = K.KeyPair.generateDeterministic(secret[0..K.seed_length].*);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kem_kp));
    exp.* = Expanded.of(K, kem_kp.secret_key);
}

/// ML-KEM decapsulation with the caller's `Expanded` when it is of this KEM,
/// else from the seed (the expanded key is wiped here, the caller's is not).
/// A caller's `Expanded` of another KEM size is a typed error.
fn mlkemDecaps(comptime K: type, seed: *const [K.seed_length]u8, exp: ?*const Expanded, ct: *const [K.ciphertext_length]u8) Error![K.shared_length]u8 {
    if (exp) |e| {
        const have: ?K.SecretKey = switch (e.*) {
            .none => null,
            .mlkem512 => |sk| if (K == MlKem512) sk else return error.KeyExchangeFailed,
            .mlkem768 => |sk| if (K == MlKem768) sk else return error.KeyExchangeFailed,
            .mlkem1024 => |sk| if (K == MlKem1024) sk else return error.KeyExchangeFailed,
        };
        if (have) |sk0| {
            var sk = sk0;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&sk));
            return sk.decaps(ct);
        }
    }
    var kem_kp = K.KeyPair.generateDeterministic(seed.*);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kem_kp));
    return kem_kp.secret_key.decaps(ct);
}

noinline fn hybridGenerate(random: std.Random, out: *KeyPair, exp: ?*Expanded) Error!void {
    var kem_seed: [MlKem768.seed_length]u8 = undefined;
    random.bytes(&kem_seed);
    var kem_kp = MlKem768.KeyPair.generateDeterministic(kem_seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kem_kp.secret_key));
    out.secret[0..MlKem768.seed_length].* = kem_seed;
    std.crypto.secureZero(u8, &kem_seed);
    const x_secret = out.secret[MlKem768.seed_length..][0..32];
    random.bytes(x_secret);
    X25519.recoverPublicKeyInto(out.public[MlKem768.PublicKey.encoded_length..][0..32], x_secret) catch return error.KeyExchangeFailed;
    out.public[0..MlKem768.PublicKey.encoded_length].* = kem_kp.public_key.toBytes();
    out.public_len = hybrid_client_share_len;
    if (exp) |e| e.* = .{ .mlkem768 = kem_kp.secret_key };
}

noinline fn hybridDecaps(secret: []const u8, exp: ?*const Expanded, peer_share: []const u8, out: *SharedSecret) Error!void {
    if (secret.len < secret_len_32) return error.KeyExchangeFailed;
    if (peer_share.len != hybrid_server_share_len) return error.MissingKeyShare;
    // Re-expand the decapsulation key from its FIPS 203 seed (the stored
    // private form -- see `secret_len`) unless the caller kept the expanded
    // one (`generateExpanded`): one keygen, tens of microseconds, once per
    // handshake.
    // Audit A1 (dtls) F5/LOW5: every SEED here is wiped on every
    // exit, but the values derived from a seed are equally
    // sufficient to recompute the session keys from a recorded
    // handshake: `sk` is the FULL ML-KEM decapsulation key (~7.8 KB in memory),
    // and the two `ss_*` are the raw shared secrets. None is read again
    // after this returns, so all of them are wiped (the caller owns and
    // wipes a passed-in `Expanded`).
    var ss_pq = try mlkemDecaps(MlKem768, secret[0..MlKem768.seed_length], exp, peer_share[0..MlKem768.ciphertext_length]);
    defer std.crypto.secureZero(u8, &ss_pq);
    X25519.scalarmultInto(
        out.bytes[32..64],
        secret[MlKem768.seed_length..][0..32],
        peer_share[MlKem768.ciphertext_length..][0..32].*,
    ) catch return error.KeyExchangeFailed;
    out.bytes[0..32].* = ss_pq;
    out.len = 64;
}

noinline fn hybridEncaps(peer_share: []const u8, random: std.Random, out: *ServerExchange) Error!void {
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
    var x_secret: [32]u8 = undefined;
    random.bytes(&x_secret);
    defer std.crypto.secureZero(u8, &x_secret);
    X25519.recoverPublicKeyInto(out.public[MlKem768.ciphertext_length..][0..32], &x_secret) catch return error.KeyExchangeFailed;
    // Same low-order/identity rejection as the classical arm — the
    // X25519 half of a hybrid must not be poisonable either.
    X25519.scalarmultInto(out.shared.bytes[32..64], &x_secret, peer_share[MlKem768.PublicKey.encoded_length..][0..32].*) catch return error.KeyExchangeFailed;
    out.public[0..MlKem768.ciphertext_length].* = enc.ciphertext;
    out.public_len = hybrid_server_share_len;
    out.shared.bytes[0..32].* = enc.shared_secret;
    out.shared.len = 64;
}

/// The two NIST-curve hybrids (draft-ietf-tls-ecdhe-mlkem §4): the ECDH
/// element FIRST everywhere -- client share `point ‖ ek`, server share
/// `point ‖ ciphertext`, shared secret `x(ECDH) ‖ ss_MLKEM` -- the reverse of
/// X25519MLKEM768. `KeyPair.secret` is `seed(64) ‖ scalar`.
const NistHybrid = struct {
    group: u16,
    /// SEC1 uncompressed point length and ECDH scalar / X length.
    point_len: usize,
    scalar_len: usize,
    kem: type,
    curve: type,
    ecdsa: type,

    const p256: NistHybrid = .{ .group = secp256r1_mlkem768_group, .point_len = 65, .scalar_len = 32, .kem = MlKem768, .curve = P256, .ecdsa = p256_mod.EcdsaP256Sha256 };
    const p384: NistHybrid = .{ .group = secp384r1_mlkem1024_group, .point_len = 97, .scalar_len = 48, .kem = MlKem1024, .curve = P384, .ecdsa = p384_mod.EcdsaP384Sha384 };

    fn ecdhInto(comptime h: NistHybrid, out: []u8, scalar: []const u8, point: []const u8) !void {
        if (comptime h.scalar_len == 32) {
            return p256_mod.ecdhInto(out[0..32], scalar[0..32], point);
        } else {
            return p384_mod.ecdhInto(out[0..48], scalar[0..48], point);
        }
    }
};

noinline fn nistHybridGenerate(comptime h: NistHybrid, random: std.Random, out: *KeyPair, exp: ?*Expanded) Error!void {
    const seed_len = h.kem.seed_length;
    var kem_seed: [seed_len]u8 = undefined;
    random.bytes(&kem_seed);
    var kem_kp = h.kem.KeyPair.generateDeterministic(kem_seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kem_kp.secret_key));
    out.secret[0..seed_len].* = kem_seed;
    std.crypto.secureZero(u8, &kem_seed);
    try generateNistAt(h.ecdsa, h.curve, random, out, seed_len);
    out.public[h.point_len..][0..h.kem.PublicKey.encoded_length].* = kem_kp.public_key.toBytes();
    out.public_len = h.point_len + h.kem.PublicKey.encoded_length;
    if (exp) |e| e.* = Expanded.of(h.kem, kem_kp.secret_key);
}

noinline fn nistHybridDecaps(comptime h: NistHybrid, secret: []const u8, exp: ?*const Expanded, peer_share: []const u8, out: *SharedSecret) Error!void {
    const seed_len = h.kem.seed_length;
    if (secret.len < seed_len + h.scalar_len) return error.KeyExchangeFailed;
    if (peer_share.len != h.point_len + h.kem.ciphertext_length) return error.MissingKeyShare;
    var ss_pq = try mlkemDecaps(h.kem, secret[0..seed_len], exp, peer_share[h.point_len..][0..h.kem.ciphertext_length]);
    defer std.crypto.secureZero(u8, &ss_pq);
    h.ecdhInto(out.bytes[0..h.scalar_len], secret[seed_len..][0..h.scalar_len], peer_share[0..h.point_len]) catch return error.KeyExchangeFailed;
    out.bytes[h.scalar_len..][0..32].* = ss_pq;
    out.len = h.scalar_len + 32;
}

noinline fn nistHybridEncaps(comptime h: NistHybrid, peer_share: []const u8, random: std.Random, out: *ServerExchange) Error!void {
    if (peer_share.len != h.point_len + h.kem.PublicKey.encoded_length) return error.MissingKeyShare;
    const ek = h.kem.PublicKey.fromBytes(peer_share[h.point_len..][0..h.kem.PublicKey.encoded_length]) catch return error.KeyExchangeFailed;
    // The ECDH half first: it validates the peer point before any secret is made.
    var kp: KeyPair = undefined;
    defer std.crypto.secureZero(u8, &kp.secret);
    try generateNistAt(h.ecdsa, h.curve, random, &kp, 0);
    h.ecdhInto(out.shared.bytes[0..h.scalar_len], kp.secret[0..h.scalar_len], peer_share[0..h.point_len]) catch return error.KeyExchangeFailed;
    var encaps_seed: [h.kem.encaps_seed_length]u8 = undefined;
    random.bytes(&encaps_seed);
    var enc = ek.encapsDeterministic(&encaps_seed);
    std.crypto.secureZero(u8, &encaps_seed);
    defer std.crypto.secureZero(u8, &enc.shared_secret);
    out.public[0..h.point_len].* = kp.public[0..h.point_len].*;
    out.public[h.point_len..][0..h.kem.ciphertext_length].* = enc.ciphertext;
    out.public_len = h.point_len + h.kem.ciphertext_length;
    out.shared.bytes[h.scalar_len..][0..32].* = enc.shared_secret;
    out.shared.len = h.scalar_len + 32;
}

/// ffdhe2048..8192 (RFC 7919, `ffdhe.zig`): `KeyPair.secret` holds the
/// exponent (`scalarLen` bytes), `KeyPair.public` the len(p)-byte value.
noinline fn ffdheGenerate(group: u16, random: std.Random, out: *KeyPair) Error!void {
    const f = ffdhe.find(group) orelse return error.MissingKeyShare;
    try ffdhe.generate(f, random, out.secret[0..f.xlen()], out.public[0..f.plen()]);
    out.public_len = f.plen();
}

noinline fn ffdheShared(group: u16, secret: []const u8, peer_share: []const u8, out: *SharedSecret) Error!void {
    const f = ffdhe.find(group) orelse return error.MissingKeyShare;
    try ffdhe.shared(f, secret, peer_share, out.bytes[0..f.plen()]);
    out.len = f.plen();
}

/// Standalone ML-KEM groups (MLKEM512/768/1024), one instance per KEM size.
noinline fn mlkemGenerate(comptime K: type, random: std.Random, out: *KeyPair, exp: ?*Expanded) Error!void {
    random.bytes(out.secret[0..K.seed_length]);
    var kem_kp = K.KeyPair.generateDeterministic(out.secret[0..K.seed_length].*);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kem_kp.secret_key));
    out.public[0..K.PublicKey.encoded_length].* = kem_kp.public_key.toBytes();
    out.public_len = K.PublicKey.encoded_length;
    if (exp) |e| e.* = Expanded.of(K, kem_kp.secret_key);
}

noinline fn mlkemDecaps1(comptime K: type, secret: []const u8, exp: ?*const Expanded, peer_share: []const u8, out: *SharedSecret) Error!void {
    if (secret.len < K.seed_length) return error.KeyExchangeFailed;
    if (peer_share.len != K.ciphertext_length) return error.MissingKeyShare;
    // The same seed re-expansion (or the caller's `Expanded`) and wipes as the hybrid's ML-KEM half.
    out.bytes[0..32].* = try mlkemDecaps(K, secret[0..K.seed_length], exp, peer_share[0..K.ciphertext_length]);
    out.len = 32;
}

noinline fn mlkemEncaps1(comptime K: type, peer_share: []const u8, random: std.Random, out: *ServerExchange) Error!void {
    if (peer_share.len != K.PublicKey.encoded_length) return error.MissingKeyShare;
    // FIPS 203 §7.2 modulus check, as for the hybrid.
    const ek = K.PublicKey.fromBytes(peer_share[0..K.PublicKey.encoded_length]) catch return error.KeyExchangeFailed;
    var encaps_seed: [K.encaps_seed_length]u8 = undefined;
    random.bytes(&encaps_seed);
    var enc = ek.encapsDeterministic(&encaps_seed);
    std.crypto.secureZero(u8, &encaps_seed);
    defer std.crypto.secureZero(u8, &enc.shared_secret);
    out.public[0..K.ciphertext_length].* = enc.ciphertext;
    out.public_len = K.ciphertext_length;
    out.shared.bytes[0..32].* = enc.shared_secret;
    out.shared.len = 32;
}

// ── tests (moved from dtls/src/Connection.zig with the code) ─────────────

const testing = std.testing;
const hx = @import("testkit").hex.bytes;

test "every group computes and has an exact share length; others are refused" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x91)));
    for ([_]u16{ x25519_mlkem768_group, mlkem1024_group, mlkem512_group, mlkem768_group, x25519_group, secp256r1_group, secp384r1_group, secp521r1_group, secp256r1_mlkem768_group, secp384r1_mlkem1024_group }) |g| {
        var kp: KeyPair = undefined;
        try generate(g, csprng.random(), &kp);
        try testing.expectEqual(g, kp.group);
        try testing.expectEqual(expectedShareLen(g), kp.public_len);
        try testing.expect(expectedShareLen(g) != 0);
        try testing.expect(scalarLen(g) != 0);
    }
    // x448 (0x001e) is a real code point this file does not compute.
    var kp: KeyPair = undefined;
    try testing.expectEqual(@as(usize, 0), expectedShareLen(0x001e));
    try testing.expectEqual(@as(usize, 0), scalarLen(0x001e));
    try testing.expectError(error.MissingKeyShare, generate(0x001e, csprng.random(), &kp));
    var ex: ServerExchange = undefined;
    try testing.expectError(error.MissingKeyShare, serverExchange(0x001e, &(@as([32]u8, @splat(9))), csprng.random(), &ex));
}

test "x25519, secp256r1, secp384r1 and secp521r1: server exchange and client shared secret agree" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x92)));
    for ([_]u16{ x25519_group, secp256r1_group, secp384r1_group, secp521r1_group }) |g| {
        var kp: KeyPair = undefined;
        try generate(g, csprng.random(), &kp);
        var ex: ServerExchange = undefined;
        try serverExchange(g, kp.public[0..kp.public_len], csprng.random(), &ex);
        try testing.expectEqual(expectedShareLen(g), ex.public_len);
        var ss: SharedSecret = undefined;
        try sharedSecret(g, &kp.secret, ex.public[0..ex.public_len], &ss);
        try testing.expectEqual(scalarLen(g), ss.len);
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

test "sharedSecret secp384r1 KAT: byte-exact against Python `cryptography` (OpenSSL) ECDH" {
    // Same oracle and shape as the secp256r1 KAT above (`cryptography`
    // 46.0.5, OpenSSL 3.5.5): fixed scalars, their SEC1 points, and the
    // 48-byte X coordinate of the shared point.
    const a_scalar = hx(48, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30");
    const a_point = hx(97, "04c76f2283dda95cd49b0ed9e733d2904474e37216f124e13d2c9ab4cf01021c49ad9cabb3d0b97499aef2f0ab313fa02826bc1f83451b5c8962a75caff73588d4400a6296436154fb343c393e91048a6c7bcbadc83cd8a5f26feae883156f92a1");
    const b_scalar = hx(48, "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
    const b_point = hx(97, "04525a259a4c8c7b6cd2ff3d47a0427ca13535609207768b4c31f80e45bd1a2b863afd325fc17c5bc13a1c056c34a43b409867575f744543cc443a44c5c8d03d8c3be4818087beb3474a846d88118fb676b3d2f150c432b3d6716cb568df43cf63");
    const shared = hx(48, "ceed5c73a8c3155389ca588d4b6a3e9f82522352d52039a25fcf35334813ce32c7007e16747f527f2a0a99f39e3e8f95");

    try testing.expectEqualSlices(u8, &a_point, &(try P384.basePoint.mul(a_scalar, .big)).toUncompressedSec1());
    try testing.expectEqualSlices(u8, &b_point, &(try P384.basePoint.mul(b_scalar, .big)).toUncompressedSec1());

    var ss: SharedSecret = undefined;
    try sharedSecret(secp384r1_group, &a_scalar, &b_point, &ss);
    try testing.expectEqualSlices(u8, &shared, ss.slice());
    try sharedSecret(secp384r1_group, &b_scalar, &a_point, &ss);
    try testing.expectEqualSlices(u8, &shared, ss.slice());
    // A 32-byte scalar is too short for P-384: typed error, not a truncated key.
    try testing.expectError(error.KeyExchangeFailed, sharedSecret(secp384r1_group, a_scalar[0..32], &b_point, &ss));
    // A P-256 share labelled P-384 (and vice versa) is the wrong length.
    var p256_point = @as([65]u8, @splat(0));
    p256_point[0] = 0x04;
    try testing.expectError(error.MissingKeyShare, sharedSecret(secp384r1_group, &a_scalar, &p256_point, &ss));
    try testing.expectError(error.MissingKeyShare, sharedSecret(secp256r1_group, &a_scalar, &b_point, &ss));
    // Right length, off the curve.
    var off_curve = @as([97]u8, @splat(0));
    off_curve[0] = 0x04;
    off_curve[1] = 0x01;
    try testing.expectError(error.KeyExchangeFailed, sharedSecret(secp384r1_group, &a_scalar, &off_curve, &ss));
    try testing.expect(std.mem.allEqual(u8, &ss.bytes, 0));
}

test "sharedSecret secp521r1 KAT: byte-exact against Python `cryptography` (OpenSSL) ECDH" {
    // Same oracle and shape as the P-256 / P-384 KATs above (`cryptography`
    // 46.0.5, OpenSSL 3.5.5): fixed scalars, their SEC1 points, and the
    // 66-byte X coordinate of the shared point.
    const a_scalar = hx(66, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142");
    const a_point = hx(133, "04000366c8c3b22dfb87d0922163cd4b53cd43a24a29f79292fa4ef1288d69ed139a7fc0552120ea1bdb4f88ca0da4eb91de9b077018d5885dbff0e91a66639a9b72a500bd5e44e3a526e1051a4371c9bae5c7611ed489582ecdcc1ea277fe2379286a3a1c0c7224c7b1ebb0a8b6e5fbda5cead23f47c300917d4f98f2d2d4dc79d0109826");
    const b_scalar = hx(66, "01a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a6168");
    const b_point = hx(133, "04016f3e729d423ea084221e494508a4f40c546af61750c8ec4205c61e1c29248372e1a79508c3c3821312917dd36776d9b807ea0ce8f23829ae7575237d58c1f78812016a068102ba3be1ccfe77ba8d7f1e7cfb792152f32978d41f2e61461bf0787cc612a17bd0d7cb51ca690e1539e35f22cbb47ed389fea20b813ba385ff69fdd2417d");
    const shared = hx(66, "002af529ef123d6691f54a346cc094761f0171ebaf327c0c383220956c8159c2f43e41f08870acda312bb194e443d8a8de1446eeacee2a314b9d5d04e0d0a65ad459");

    // The public shares `generate` puts on the wire, recovered from the same scalars.
    var le = a_scalar;
    std.mem.reverse(u8, &le);
    try testing.expectEqualSlices(u8, &a_point, &p521.P521.mulBaseCtUnburned(&le).toUncompressedSec1());
    le = b_scalar;
    std.mem.reverse(u8, &le);
    try testing.expectEqualSlices(u8, &b_point, &p521.P521.mulBaseCtUnburned(&le).toUncompressedSec1());

    var ss: SharedSecret = undefined;
    try sharedSecret(secp521r1_group, &a_scalar, &b_point, &ss);
    try testing.expectEqualSlices(u8, &shared, ss.slice());
    try sharedSecret(secp521r1_group, &b_scalar, &a_point, &ss);
    try testing.expectEqualSlices(u8, &shared, ss.slice());
    // A 48-byte scalar is too short for P-521: typed error, not a truncated key.
    try testing.expectError(error.KeyExchangeFailed, sharedSecret(secp521r1_group, a_scalar[0..48], &b_point, &ss));
    // A P-384 share labelled P-521 (and vice versa) is the wrong length.
    try testing.expectError(error.MissingKeyShare, sharedSecret(secp521r1_group, &a_scalar, b_point[0..97], &ss));
    try testing.expectError(error.MissingKeyShare, sharedSecret(secp384r1_group, a_scalar[0..48], &b_point, &ss));
    // Right length, off the curve.
    var off_curve = @as([133]u8, @splat(0));
    off_curve[0] = 0x04;
    off_curve[1] = 0x01;
    try testing.expectError(error.KeyExchangeFailed, sharedSecret(secp521r1_group, &a_scalar, &off_curve, &ss));
    try testing.expect(std.mem.allEqual(u8, &ss.bytes, 0));
    // Wrong SEC1 form octet, and a server refusing a damaged client share.
    var bad = a_point;
    bad[0] = 0x05;
    var ex: ServerExchange = undefined;
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x41)));
    try testing.expectError(error.KeyExchangeFailed, serverExchange(secp521r1_group, &bad, csprng.random(), &ex));
    try testing.expect(std.mem.allEqual(u8, &ex.shared.bytes, 0));
    try testing.expectError(error.MissingKeyShare, serverExchange(secp521r1_group, a_point[0..132], csprng.random(), &ex));
}

test "secp521r1 generate: the scalar is in [1, n-1] (top byte masked) and the share is its public point" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x42)));
    for (0..8) |_| {
        var kp: KeyPair = undefined;
        try generate(secp521r1_group, csprng.random(), &kp);
        try testing.expect(kp.secret[0] <= 1);
        try testing.expectEqual(@as(usize, 133), kp.public_len);
        try testing.expectEqual(@as(u8, 0x04), kp.public[0]);
        var le: [66]u8 = kp.secret[0..66].*;
        std.mem.reverse(u8, &le);
        try testing.expectEqualSlices(u8, &p521.P521.mulBaseCtUnburned(&le).toUncompressedSec1(), kp.public[0..133]);
    }
}

test "mlkem512 / mlkem768: both sides agree, the secret is ML-KEM's own, garbage is a typed error" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x43)));
    const rnd = csprng.random();
    inline for (.{
        .{ mlkem512_group, MlKem512, mlkem512_client_share_len, mlkem512_server_share_len, 800, 768 },
        .{ mlkem768_group, MlKem768, mlkem768_client_share_len, mlkem768_server_share_len, 1184, 1088 },
    }) |c| {
        const g = c[0];
        const K = c[1];
        try testing.expectEqual(@as(usize, c[4]), c[2]);
        try testing.expectEqual(@as(usize, c[5]), c[3]);
        try testing.expectEqual(@as(usize, c[2]), expectedShareLen(g));
        try testing.expectEqual(@as(usize, 64), scalarLen(g));
        var kp: KeyPair = undefined;
        try generate(g, rnd, &kp);
        try testing.expectEqual(@as(usize, c[2]), kp.public_len);
        var ex: ServerExchange = undefined;
        try serverExchange(g, kp.public[0..kp.public_len], rnd, &ex);
        try testing.expectEqual(@as(usize, c[3]), ex.public_len);
        try testing.expectEqual(@as(usize, 32), ex.shared.len);
        var ss: SharedSecret = undefined;
        try sharedSecret(g, &kp.secret, ex.public[0..ex.public_len], &ss);
        try testing.expectEqualSlices(u8, ex.shared.slice(), ss.slice());
        const kem_kp = K.KeyPair.generateDeterministic(kp.secret[0..K.seed_length].*);
        try testing.expectEqualSlices(u8, &kem_kp.public_key.toBytes(), kp.public[0..kp.public_len]);
        try testing.expectEqualSlices(u8, &(kem_kp.secret_key.decaps(ex.public[0..K.ciphertext_length])), ss.slice());

        // Non-canonical key, truncated and padded shares, and the other
        // standalone sizes' shares (the ML-KEM-512 / -768 / -1024 lengths all differ).
        ex.shared.bytes = @splat(0xAB);
        try testing.expectError(error.KeyExchangeFailed, serverExchange(g, &(@as([c[2]]u8, @splat(0xFF))), rnd, &ex));
        try testing.expect(std.mem.allEqual(u8, &ex.shared.bytes, 0));
        try testing.expectError(error.MissingKeyShare, serverExchange(g, kp.public[0 .. kp.public_len - 1], rnd, &ex));
        var padded: [c[2] + 1]u8 = undefined;
        @memcpy(padded[0..kp.public_len], kp.public[0..kp.public_len]);
        padded[kp.public_len] = 0;
        try testing.expectError(error.MissingKeyShare, serverExchange(g, &padded, rnd, &ex));
        try serverExchange(g, kp.public[0..kp.public_len], rnd, &ex);
        try testing.expectError(error.MissingKeyShare, sharedSecret(g, &kp.secret, ex.public[0 .. ex.public_len - 1], &ss));
        try testing.expectError(error.MissingKeyShare, sharedSecret(g, &kp.secret, &(@as([mlkem1024_server_share_len]u8, @splat(0xAA))), &ss));
        try testing.expectError(error.KeyExchangeFailed, sharedSecret(g, kp.secret[0..32], ex.public[0..ex.public_len], &ss));
        try testing.expectEqual(@as(usize, 0), ss.len);
    }
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
    const kem_kp = MlKem768.KeyPair.generateDeterministic(kp.secret[0..MlKem768.seed_length].*);
    const ss_pq = kem_kp.secret_key.decaps(ex.public[0..MlKem768.ciphertext_length]);
    try testing.expectEqualSlices(u8, &ss_pq, client_shared.bytes[0..32]);
    // The X25519 half, via direct scalarmult of the two ephemerals.
    const ss_x = try std.crypto.dh.X25519.scalarmult(
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

test "mlkem1024: both sides agree, the secret is ML-KEM's own, garbage is a typed error" {
    // The group is plain FIPS 203 on the wire (no combiner, no second half),
    // so the shared secret must equal a direct decapsulation of the server's
    // ciphertext with the re-expanded seed — and std's ML-KEM-1024 is
    // anchored on its own KATs.
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x79)));
    const rnd = csprng.random();
    var kp: KeyPair = undefined;
    try generate(mlkem1024_group, rnd, &kp);
    try testing.expectEqual(@as(usize, mlkem1024_client_share_len), kp.public_len);
    var ex: ServerExchange = undefined;
    try serverExchange(mlkem1024_group, kp.public[0..kp.public_len], rnd, &ex);
    try testing.expectEqual(@as(usize, mlkem1024_server_share_len), ex.public_len);
    try testing.expectEqual(@as(usize, 32), ex.shared.len);
    var ss: SharedSecret = undefined;
    try sharedSecret(mlkem1024_group, &kp.secret, ex.public[0..ex.public_len], &ss);
    try testing.expectEqualSlices(u8, ex.shared.slice(), ss.slice());
    const kem_kp = MlKem1024.KeyPair.generateDeterministic(kp.secret[0..MlKem1024.seed_length].*);
    try testing.expectEqualSlices(u8, &kem_kp.public_key.toBytes(), kp.public[0..kp.public_len]);
    try testing.expectEqualSlices(u8, &(kem_kp.secret_key.decaps(ex.public[0..MlKem1024.ciphertext_length])), ss.slice());

    // Non-canonical encapsulation key (BoGo MLKEMEncapKeyNotReduced), a
    // truncated and a padded one (TruncateKeyShare / PadKeyShare).
    ex.shared.bytes = @splat(0xAB);
    try testing.expectError(error.KeyExchangeFailed, serverExchange(mlkem1024_group, &(@as([mlkem1024_client_share_len]u8, @splat(0xFF))), rnd, &ex));
    try testing.expect(std.mem.allEqual(u8, &ex.shared.bytes, 0));
    try testing.expectError(error.MissingKeyShare, serverExchange(mlkem1024_group, kp.public[0 .. kp.public_len - 1], rnd, &ex));
    var padded: [mlkem1024_client_share_len + 1]u8 = undefined;
    @memcpy(padded[0..kp.public_len], kp.public[0..kp.public_len]);
    padded[kp.public_len] = 0;
    try testing.expectError(error.MissingKeyShare, serverExchange(mlkem1024_group, &padded, rnd, &ex));
    // The hybrid's share lengths are not ML-KEM-1024's (both directions).
    try testing.expectError(error.MissingKeyShare, sharedSecret(mlkem1024_group, &kp.secret, &(@as([hybrid_server_share_len]u8, @splat(0xAA))), &ss));
    try testing.expectError(error.KeyExchangeFailed, sharedSecret(mlkem1024_group, kp.secret[0..32], ex.public[0..ex.public_len], &ss));
}

test "sharedSecret: a share one octet long for its curve is MissingKeyShare, and an error leaves an empty secret" {
    // 66 bytes: longer than any curve here needs, so the share length is what each curve checks first.
    const a_scalar = hx(66, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142");
    var ss: SharedSecret = .{ .bytes = @splat(0xAB), .len = 64 };
    inline for (.{ .{ x25519_group, 32 }, .{ secp256r1_group, 65 }, .{ secp384r1_group, 97 }, .{ secp521r1_group, 133 } }) |c| {
        var long_share: [c[1] + 1]u8 = @splat(0);
        long_share[0] = 0x04;
        ss.len = 64;
        try testing.expectError(error.MissingKeyShare, sharedSecret(c[0], &a_scalar, &long_share, &ss));
        try testing.expectEqual(@as(usize, 0), ss.slice().len);
    }
    ss.len = 64;
    try testing.expectError(error.MissingKeyShare, sharedSecret(0x001e, &a_scalar, &a_scalar, &ss));
    try testing.expectEqual(@as(usize, 0), ss.slice().len);
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x33)));
    var ex: ServerExchange = undefined;
    ex.public_len = 99;
    ex.shared.len = 64;
    try testing.expectError(error.MissingKeyShare, serverExchange(secp384r1_group, &(@as([98]u8, @splat(4))), csprng.random(), &ex));
    try testing.expectEqual(@as(usize, 0), ex.public_len);
    try testing.expectEqual(@as(usize, 0), ex.shared.slice().len);
}

test "NIST hybrids: halves in the right place (ECDH first), sizes exact, garbage is a typed error" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x7a)));
    const rnd = csprng.random();
    inline for (.{
        .{ secp256r1_mlkem768_group, 65, 32, MlKem768, p256_hybrid_client_share_len, p256_hybrid_server_share_len, secp256r1_group },
        .{ secp384r1_mlkem1024_group, 97, 48, MlKem1024, p384_hybrid_client_share_len, p384_hybrid_server_share_len, secp384r1_group },
    }) |c| {
        const g = c[0];
        var kp: KeyPair = undefined;
        try generate(g, rnd, &kp);
        try testing.expectEqual(@as(usize, c[4]), kp.public_len);
        try testing.expectEqual(@as(usize, c[4]), expectedShareLen(g));
        try testing.expectEqual(@as(u8, 0x04), kp.public[0]);
        var ex: ServerExchange = undefined;
        try serverExchange(g, kp.public[0..kp.public_len], rnd, &ex);
        try testing.expectEqual(@as(usize, c[5]), ex.public_len);
        try testing.expectEqual(@as(usize, c[2] + 32), ex.shared.len);
        var ss: SharedSecret = undefined;
        try sharedSecret(g, &kp.secret, ex.public[0..ex.public_len], &ss);
        try testing.expectEqualSlices(u8, ex.shared.slice(), ss.slice());
        // ECDH half = the plain curve's secret, FIRST; ML-KEM half after it.
        var plain: SharedSecret = undefined;
        try sharedSecret(c[6], kp.secret[64..][0..c[2]], ex.public[0..c[1]], &plain);
        try testing.expectEqualSlices(u8, plain.slice(), ss.slice()[0..c[2]]);
        const kem_kp = c[3].KeyPair.generateDeterministic(kp.secret[0..64].*);
        try testing.expectEqualSlices(u8, &kem_kp.public_key.toBytes(), kp.public[c[1]..kp.public_len]);
        try testing.expectEqualSlices(u8, &(kem_kp.secret_key.decaps(ex.public[c[1]..][0..c[3].ciphertext_length])), ss.slice()[c[2]..]);

        // Peer garbage.
        try testing.expectError(error.MissingKeyShare, serverExchange(g, kp.public[0 .. kp.public_len - 1], rnd, &ex));
        try testing.expectError(error.MissingKeyShare, sharedSecret(g, &kp.secret, kp.public[0 .. c[5] - 1], &ss));
        var bad = kp.public;
        bad[0] = 0x05; // not an uncompressed SEC1 point
        try testing.expectError(error.KeyExchangeFailed, serverExchange(g, bad[0..kp.public_len], rnd, &ex));
        try testing.expect(allZeroBytes(&ex.shared.bytes));
        bad = kp.public;
        @memset(bad[c[1]..kp.public_len], 0xFF); // non-canonical encapsulation key
        try testing.expectError(error.KeyExchangeFailed, serverExchange(g, bad[0..kp.public_len], rnd, &ex));
        try testing.expectError(error.KeyExchangeFailed, sharedSecret(g, kp.secret[0..32], ex.public[0..c[5]], &ss));
    }
}

fn allZeroBytes(b: []const u8) bool {
    return std.mem.allEqual(u8, b, 0);
}

test "sharedSecret accepts a secret of exactly scalarLen(group) bytes, for every group" {
    var csprng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5b)));
    const rnd = csprng.random();
    for ([_]u16{ x25519_group, secp256r1_group, secp384r1_group, secp521r1_group, x25519_mlkem768_group, mlkem1024_group, mlkem512_group, mlkem768_group, secp256r1_mlkem768_group, secp384r1_mlkem1024_group }) |g| {
        var kp: KeyPair = undefined;
        try generate(g, rnd, &kp);
        var ex: ServerExchange = undefined;
        try serverExchange(g, kp.public[0..kp.public_len], rnd, &ex);
        var ss: SharedSecret = undefined;
        try sharedSecret(g, kp.secret[0..scalarLen(g)], ex.public[0..ex.public_len], &ss);
        try testing.expectEqualSlices(u8, ex.shared.slice(), ss.slice());
        try testing.expectError(error.KeyExchangeFailed, sharedSecret(g, kp.secret[0 .. scalarLen(g) - 1], ex.public[0..ex.public_len], &ss));
    }
}

/// The active variant's key bytes (the rest of the union is unspecified).
fn activeBytes(e: *const Expanded) []const u8 {
    return switch (e.*) {
        .none => &.{},
        .mlkem512 => |*sk| std.mem.asBytes(sk),
        .mlkem768 => |*sk| std.mem.asBytes(sk),
        .mlkem1024 => |*sk| std.mem.asBytes(sk),
    };
}

test "Expanded: generateExpanded/expand/sharedSecretExpanded agree with the seed path for every ML-KEM group" {
    const groups = [_]u16{ x25519_mlkem768_group, secp256r1_mlkem768_group, mlkem1024_group, mlkem512_group, mlkem768_group, secp384r1_mlkem1024_group };
    var prng = std.Random.DefaultPrng.init(0x3203);
    for (groups) |g| {
        var kp: KeyPair = undefined;
        var exp: Expanded = .none;
        defer exp.wipe();
        try generateExpanded(g, prng.random(), &kp, &exp);
        try testing.expect(exp != .none);
        // `expand` from the stored seed reproduces the keygen's expanded key.
        var exp2: Expanded = .none;
        defer exp2.wipe();
        try expand(g, kp.secret[0..scalarLen(g)], &exp2);
        try testing.expectEqualSlices(u8, activeBytes(&exp), activeBytes(&exp2));
        var ex: ServerExchange = undefined;
        try serverExchange(g, kp.public[0..kp.public_len], prng.random(), &ex);
        var a: SharedSecret = undefined;
        var b: SharedSecret = undefined;
        try sharedSecret(g, kp.secret[0..scalarLen(g)], ex.public[0..ex.public_len], &a);
        try sharedSecretExpanded(g, kp.secret[0..scalarLen(g)], &exp, ex.public[0..ex.public_len], &b);
        try testing.expectEqualSlices(u8, a.slice(), b.slice());
        try testing.expectEqualSlices(u8, ex.shared.slice(), b.slice());
        // A forged ciphertext decapsulates to the same implicit-rejection secret either way.
        ex.public[ex.public_len - 40] ^= 0x40; // inside the ciphertext for every layout
        try sharedSecret(g, kp.secret[0..scalarLen(g)], ex.public[0..ex.public_len], &a);
        try sharedSecretExpanded(g, kp.secret[0..scalarLen(g)], &exp, ex.public[0..ex.public_len], &b);
        try testing.expectEqualSlices(u8, a.slice(), b.slice());
    }
}

test "Expanded: wrong KEM size is a typed error, classical groups yield .none and ignore it, wipe clears all bytes" {
    var prng = std.Random.DefaultPrng.init(0x3204);
    var kp: KeyPair = undefined;
    var exp: Expanded = .none;
    try generateExpanded(mlkem1024_group, prng.random(), &kp, &exp);
    var kp768: KeyPair = undefined;
    var ex: ServerExchange = undefined;
    try generate(x25519_mlkem768_group, prng.random(), &kp768);
    try serverExchange(x25519_mlkem768_group, kp768.public[0..kp768.public_len], prng.random(), &ex);
    var ss: SharedSecret = undefined;
    try testing.expectError(error.KeyExchangeFailed, sharedSecretExpanded(x25519_mlkem768_group, kp768.secret[0..scalarLen(x25519_mlkem768_group)], &exp, ex.public[0..ex.public_len], &ss));
    exp.wipe();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&exp), 0));

    var cexp: Expanded = .none;
    var ckp: KeyPair = undefined;
    try generateExpanded(x25519_group, prng.random(), &ckp, &cexp);
    try testing.expect(cexp == .none);
    try expand(secp256r1_group, ckp.secret[0..32], &cexp);
    try testing.expect(cexp == .none);
    try testing.expectError(error.MissingKeyShare, expand(0x001e, ckp.secret[0..32], &cexp));
    try testing.expectError(error.KeyExchangeFailed, expand(mlkem1024_group, ckp.secret[0..10], &cexp));
}
