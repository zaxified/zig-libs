// SPDX-License-Identifier: MIT

//! JOSE building blocks for ACME: base64url (no padding), ES256 / ES384 /
//! ES512 / RS256 JWS in the flattened JSON serialization (RFC 7515 §7.2.2),
//! EC and RSA JWK rendering, the RFC 7638 JWK thumbprint and the RFC 8555
//! §8.1 key authorization.
//!
//! Everything here is pure and offline-testable: signing is deterministic
//! (std's RFC 6979-style nonce derivation — `KeyPair.sign` with null noise;
//! RSASSA-PKCS1-v1_5 is deterministic by construction), so the same key +
//! header + payload always produce the same JWS.
//! `verifyFlattened` is the server-side half — used by the mock-ACME
//! integration test to check every JWS the client sends.

const std = @import("std");
const entropy = @import("entropy");
const burn = @import("burn.zig");
/// The `rsa` module, for `rsa.KeyPair` (RS256 keys are held by pointer).
pub const rsa = @import("rsa");

/// The one JWS algorithm ACME accounts use here: ECDSA P-256 + SHA-256, over
/// p256's burned wrapper rather than std's signer (which leaves the private
/// key and the nonce on the dead stack after every signature — measured
/// 2026-10-08, `stackprobe_test.zig`).
pub const Es256 = @import("p256").EcdsaP256Sha256;
pub const KeyPair = Es256.KeyPair;

/// ECDSA P-384 + SHA-384 (ES384), over the `p384` module's burned signer
/// (std's leaves the key on the dead stack, same as std's P-256).
pub const Es384 = @import("p384").EcdsaP384Sha384;

/// ECDSA P-521 + SHA-512 (ES512, RFC 7518 §3.4), over the `p521` module's
/// burned signer.
pub const Es512 = @import("p521").EcdsaP521Sha512;

/// The JWS algorithms an ACME account or certificate key can use here:
/// ECDSA on P-256, P-384 and P-521, and RSASSA-PKCS1-v1_5 with SHA-256
/// (RS256, RFC 7518 §3.3) over the `rsa` module.
pub const Alg = enum {
    es256,
    es384,
    es512,
    rs256,

    /// The JOSE `alg` name (RFC 7518 §3.1).
    pub fn name(a: Alg) []const u8 {
        return switch (a) {
            .es256 => "ES256",
            .es384 => "ES384",
            .es512 => "ES512",
            .rs256 => "RS256",
        };
    }

    /// True for the ECDSA algorithms — the ones `crv`, `coordLen` and
    /// `sigLen` are defined for.
    pub fn isEc(a: Alg) bool {
        return a != .rs256;
    }

    /// The JWK `crv` (RFC 7518 §6.2.1.1). EC algorithms only (`isEc`): an RSA
    /// key has no curve, so asking is a caller bug (`unreachable`).
    pub fn crv(a: Alg) []const u8 {
        return switch (a) {
            .es256 => "P-256",
            .es384 => "P-384",
            .es512 => "P-521",
            .rs256 => unreachable, // callers branch on `isEc` first
        };
    }

    /// Octets of one affine coordinate, and of one scalar. EC algorithms only
    /// (`isEc`).
    pub fn coordLen(a: Alg) usize {
        return switch (a) {
            .es256 => 32,
            .es384 => 48,
            .es512 => 66,
            .rs256 => unreachable, // callers branch on `isEc` first
        };
    }

    /// Octets of an ECDSA JWS signature, `R ‖ S` (RFC 7518 §3.4). EC
    /// algorithms only (`isEc`): an RS256 signature is as long as the key's
    /// modulus (RFC 7518 §3.3), so it depends on the key, not on the `Alg`.
    pub fn sigLen(a: Alg) usize {
        return 2 * a.coordLen();
    }

    pub fn fromName(s: []const u8) ?Alg {
        if (std.mem.eql(u8, s, "ES256")) return .es256;
        if (std.mem.eql(u8, s, "ES384")) return .es384;
        if (std.mem.eql(u8, s, "ES512")) return .es512;
        if (std.mem.eql(u8, s, "RS256")) return .rs256;
        return null;
    }
};

/// Which algorithm a key-pair or public-key type belongs to.
pub fn algOf(comptime T: type) Alg {
    return switch (T) {
        Es256.KeyPair, Es256.PublicKey => .es256,
        Es384.KeyPair, Es384.PublicKey => .es384,
        Es512.KeyPair, Es512.PublicKey => .es512,
        rsa.KeyPair, rsa.PublicKey, rsa.VerifyKey => .rs256,
        else => @compileError("not an acme key type: " ++ @typeName(T)),
    };
}

/// The RSA key sizes an ACME account or certificate key may have here: the
/// range public CAs accept (Let's Encrypt: 2048..4096). Enforced where a key
/// enters — `generateRsaKeyPair`, `x509.rsaPrivateKeyFromPem`, a JWK or CSR
/// that `verifyFlattenedAny` / `x509.parseCsrAny` parse — not by the signers,
/// whose buffers are sized for the `rsa` module's own ceiling
/// (`rsa.max_modulus_bits`) and so cannot overflow.
pub const rsa_min_bits = 2048;
pub const rsa_max_bits = 4096;

/// Big-endian modulus and exponent of an RSA verify key, leading zeros
/// stripped (RFC 7518 §6.3.1: the JWK form), into caller buffers.
const RsaParts = struct {
    n: []const u8,
    e: []const u8,

    fn of(vk: *const rsa.VerifyKey, n_buf: *[rsa.max_modulus_len]u8, e_buf: *[4]u8) RsaParts {
        const len = vk.mp.byteLen(); // <= max_modulus_len: every VerifyKey constructor checks
        vk.mp.toBytesBE(&vk.mp.m, n_buf[0..len]);
        std.mem.writeInt(u32, e_buf, vk.e, .big);
        return .{
            .n = std.mem.trimStart(u8, n_buf[0..len], "\x00"),
            .e = std.mem.trimStart(u8, e_buf, "\x00"),
        };
    }
};

/// A public key of any supported algorithm.
pub const AnyPublicKey = union(Alg) {
    es256: Es256.PublicKey,
    es384: Es384.PublicKey,
    es512: Es512.PublicKey,
    /// By value: a `rsa.VerifyKey` is the modulus and exponent only (a few KiB
    /// at most), without the key-generation constants of `rsa.PublicKey`.
    rs256: rsa.VerifyKey,

    pub fn alg(k: AnyPublicKey) Alg {
        return std.meta.activeTag(k);
    }

    /// Longest uncompressed SEC1 point (P-521: `04 ‖ X(66) ‖ Y(66)`).
    pub const max_sec1_len = 133;

    /// `04 ‖ X ‖ Y` into `buf`; the returned slice is its prefix. EC keys only
    /// (`alg().isEc()`): an RSA key has no point (`unreachable`).
    pub fn uncompressedSec1(k: AnyPublicKey, buf: *[max_sec1_len]u8) []const u8 {
        switch (k) {
            .rs256 => unreachable, // callers branch on `isEc` first
            inline .es256, .es384, .es512 => |pk| {
                const s = pk.toUncompressedSec1();
                @memcpy(buf[0..s.len], &s);
                return buf[0..s.len];
            },
        }
    }

    /// Same algorithm and same key (public data, so a plain comparison).
    pub fn eql(a: AnyPublicKey, b: AnyPublicKey) bool {
        if (a.alg() != b.alg()) return false;
        if (a.alg() == .rs256) {
            var an: [rsa.max_modulus_len]u8 = undefined;
            var ae: [4]u8 = undefined;
            var bn: [rsa.max_modulus_len]u8 = undefined;
            var be: [4]u8 = undefined;
            const pa = RsaParts.of(&a.rs256, &an, &ae);
            const pb = RsaParts.of(&b.rs256, &bn, &be);
            return std.mem.eql(u8, pa.n, pb.n) and std.mem.eql(u8, pa.e, pb.e);
        }
        var ab: [max_sec1_len]u8 = undefined;
        var bb: [max_sec1_len]u8 = undefined;
        return std.mem.eql(u8, a.uncompressedSec1(&ab), b.uncompressedSec1(&bb));
    }
};

/// A key pair of any supported algorithm — what `Client` holds. An EC pair is
/// held by value and holds a private key: wipe it with
/// `std.crypto.secureZero(u8, std.mem.asBytes(&k))`. An RSA pair is tens of KiB
/// (`rsa.SecretKey`), so `rs256` BORROWS it: the caller keeps the
/// `rsa.KeyPair` alive for as long as this value is used, and wipes that pair
/// (`std.crypto.secureZero(u8, std.mem.asBytes(pair))`) — wiping the
/// `AnyKeyPair` only clears the pointer.
pub const AnyKeyPair = union(Alg) {
    es256: Es256.KeyPair,
    es384: Es384.KeyPair,
    es512: Es512.KeyPair,
    rs256: *const rsa.KeyPair,

    pub fn alg(k: *const AnyKeyPair) Alg {
        return std.meta.activeTag(k.*);
    }

    // secret-api-ok: reads the public half only (for RS256 a public VerifyKey built from the pair's public key); no secret enters the frame.
    pub fn publicKey(k: *const AnyKeyPair) AnyPublicKey {
        return switch (k.*) {
            .es256 => |*kp| .{ .es256 = kp.public_key },
            .es384 => |*kp| .{ .es384 = kp.public_key },
            .es512 => |*kp| .{ .es512 = kp.public_key },
            .rs256 => |kp| .{ .rs256 = kp.public_key.verifyKey() },
        };
    }
};

/// View any supported public key as an `AnyPublicKey`.
pub fn anyPublic(pk: anytype) AnyPublicKey {
    return switch (@TypeOf(pk)) {
        AnyPublicKey => pk,
        Es256.PublicKey => .{ .es256 = pk },
        Es384.PublicKey => .{ .es384 = pk },
        Es512.PublicKey => .{ .es512 = pk },
        rsa.VerifyKey => .{ .rs256 = pk },
        rsa.PublicKey => .{ .rs256 = pk.verifyKey() },
        else => @compileError("not an acme public key: " ++ @typeName(@TypeOf(pk))),
    };
}

/// The public half of a pointer to any supported key pair.
pub fn publicOfPair(key_pair: anytype) AnyPublicKey {
    return switch (@TypeOf(key_pair.*)) {
        AnyKeyPair => key_pair.publicKey(),
        Es256.KeyPair => .{ .es256 = key_pair.public_key },
        Es384.KeyPair => .{ .es384 = key_pair.public_key },
        Es512.KeyPair => .{ .es512 = key_pair.public_key },
        rsa.KeyPair => .{ .rs256 = key_pair.public_key.verifyKey() },
        else => @compileError("not an acme key pair: " ++ @typeName(@TypeOf(key_pair.*))),
    };
}

/// Copy the pair behind `key_pair` (a pointer to an EC pair, to an
/// `rsa.KeyPair` or to an `AnyKeyPair`) into `out`. An EC copy is a second
/// resident private key: the caller wipes it. An RSA pair is NOT copied: `out`
/// stores the pointer, so the `rsa.KeyPair` must outlive `out`.
pub fn copyPairInto(out: *AnyKeyPair, key_pair: anytype) void {
    switch (@TypeOf(key_pair.*)) {
        AnyKeyPair => out.* = key_pair.*,
        Es256.KeyPair => out.* = .{ .es256 = key_pair.* },
        Es384.KeyPair => out.* = .{ .es384 = key_pair.* },
        Es512.KeyPair => out.* = .{ .es512 = key_pair.* },
        rsa.KeyPair => out.* = .{ .rs256 = key_pair },
        else => @compileError("not an acme key pair: " ++ @typeName(@TypeOf(key_pair.*))),
    }
}

/// Mint an account or certificate key. **Use this, not
/// `KeyPair.generate(io)`** — they differ only in where the seed comes
/// from, and std's takes it from `io.random`, whose contract permits a
/// silent degrade to a pid-and-clock seed (CONVENTIONS.md §2.2).
///
/// Everything an ACME deployment is worth hangs off these two keys: the
/// account key authenticates every request to the CA for the lifetime of
/// the account, and a certificate key is what a publicly-trusted
/// certificate ends up attesting to. Neither is recoverable after the
/// fact — a weak account key is a CA that will happily take orders from
/// whoever else derives it.
///
/// Otherwise the same as std's ECDSA `KeyPair.generate`; the retry loop is std's, absorbing the seed whose
/// derived scalar lands on the identity element.
///
/// The pair goes into `out` (zeroed on error), not through a return value: a
/// returned pair would sit in the caller's frame temporary, where nothing
/// wipes it. The seed's frames are burned (`burn.zig`).
pub fn generateKeyPair(out: *KeyPair, io: std.Io) void {
    generateKeyPairUnburned(KeyPair, out, io);
    burn.stack(burn.key_burn);
}

/// `generateKeyPair` for a chosen curve, into an `AnyKeyPair` (ES384 / ES512
/// account and certificate keys). Same entropy path and burn. EC algorithms
/// only: `alg` must satisfy `isEc()` — an RSA key is too large to live in the
/// union, so it is minted by `generateRsaKeyPair` into a pair the caller owns.
pub fn generateAnyKeyPair(out: *AnyKeyPair, alg: Alg, io: std.Io) void {
    switch (alg) {
        .es256 => {
            out.* = .{ .es256 = undefined };
            generateKeyPairUnburned(Es256.KeyPair, &out.es256, io);
        },
        .es384 => {
            out.* = .{ .es384 = undefined };
            generateKeyPairUnburned(Es384.KeyPair, &out.es384, io);
        },
        .es512 => {
            out.* = .{ .es512 = undefined };
            generateKeyPairUnburned(Es512.KeyPair, &out.es512, io);
        },
        .rs256 => unreachable, // documented precondition: `alg.isEc()`; see `generateRsaKeyPair`
    }
    burn.stack(burn.key_burn);
}

/// Mint an RSA account or certificate key (`bits` 2048, 3072 or 4096; anything
/// else is `InvalidBits` and `out` is zeroed). Same entropy discipline as
/// `generateKeyPair` — the 32-byte seed comes from the fail-closed
/// `entropy.fill`, never from `io.random` — expanded by a ChaCha20 CSPRNG
/// (`std.Random.DefaultCsprng`) into the `rsa.generate` prime search. The
/// CSPRNG state and the seed are wiped and the frames burned. The pair goes
/// into `out` (zeroed on error); the caller owns and wipes it. Key generation
/// is slow (seconds at 4096 bits; much slower in Debug builds).
pub fn generateRsaKeyPair(out: *rsa.KeyPair, bits: u16, io: std.Io) error{InvalidBits}!void {
    if (bits != 2048 and bits != 3072 and bits != 4096) {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return error.InvalidBits;
    }
    generateRsaKeyPairUnburned(out, bits, io);
    burn.stack(burn.key_burn);
}

noinline fn generateRsaKeyPairUnburned(out: *rsa.KeyPair, bits: u16, io: std.Io) void {
    var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    entropy.fill(io, &seed);
    var csprng = std.Random.DefaultCsprng.init(seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&csprng));
    // `bits` is one of the three checked above and 65537 is a valid exponent,
    // so `rsa.generate` has no error left to report.
    rsa.generate(out, csprng.random(), bits, 65537) catch unreachable;
}

noinline fn generateKeyPairUnburned(comptime KP: type, out: *KP, io: std.Io) void {
    var seed: [KP.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    while (true) {
        entropy.fill(io, &seed);
        KP.generateDeterministicInto(out, &seed) catch {
            @branchHint(.unlikely);
            continue;
        };
        return;
    }
}

const b64 = std.base64.url_safe_no_pad;
const Sha256 = std.crypto.hash.sha2.Sha256;

// ── base64url (RFC 4648 §5, no padding) ─────────────────────────────────────

/// Exact encoded length for `n` input bytes.
pub fn base64UrlLen(n: usize) usize {
    return b64.Encoder.calcSize(n);
}

/// Encode into `dest` (must be at least `base64UrlLen(source.len)`).
pub fn base64UrlEncode(dest: []u8, source: []const u8) []const u8 {
    return b64.Encoder.encode(dest, source);
}

/// Allocate + encode.
pub fn base64UrlEncodeAlloc(gpa: std.mem.Allocator, source: []const u8) std.mem.Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, base64UrlLen(source.len));
    _ = b64.Encoder.encode(out, source);
    return out;
}

/// Decode a base64url-no-pad string (caller owns the result).
pub fn base64UrlDecodeAlloc(gpa: std.mem.Allocator, source: []const u8) error{ OutOfMemory, InvalidBase64 }![]u8 {
    const n = b64.Decoder.calcSizeForSlice(source) catch return error.InvalidBase64;
    const out = try gpa.alloc(u8, n);
    errdefer gpa.free(out);
    b64.Decoder.decode(out, source) catch return error.InvalidBase64;
    return out;
}

// ── JWK + RFC 7638 thumbprint ───────────────────────────────────────────────

/// Length of the canonical P-256 JWK JSON (all fields fixed-width).
pub const canonical_jwk_len = canonicalJwkLen();

fn canonicalJwkLen() usize {
    // {"crv":"P-256","kty":"EC","x":"<43>","y":"<43>"}
    return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\",\"y\":\"\"}".len + 2 * 43;
}

/// Length of the longest canonical JWK: an RSA key of the `rsa` module's
/// ceiling (`rsa.max_modulus_bits`, 8192 bits: a 1366-character `n`), which
/// also covers 4096-bit keys (683 characters) and P-521 (88-character
/// coordinates).
pub const max_canonical_jwk_len = "{\"e\":\"\",\"kty\":\"RSA\",\"n\":\"\"}".len +
    base64UrlLen(4) + base64UrlLen(rsa.max_modulus_len);

comptime {
    const ec_max = "{\"crv\":\"P-521\",\"kty\":\"EC\",\"x\":\"\",\"y\":\"\"}".len + 2 * 88;
    std.debug.assert(max_canonical_jwk_len >= ec_max);
}

/// The canonical JWK of a public key (`Es256.PublicKey`, `Es384.PublicKey`,
/// `Es512.PublicKey`, `rsa.VerifyKey`, `rsa.PublicKey` or `AnyPublicKey`):
/// required members only, in lexicographic order, no whitespace — the exact
/// byte sequence RFC 7638 hashes. EC: `{"crv","kty":"EC","x","y"}`; RSA (RFC
/// 7518 §6.3.1): `{"e","kty":"RSA","n"}` with `e` and `n` the unsigned
/// big-endian bytes without leading zeros. `buf` must hold
/// `max_canonical_jwk_len` bytes (`canonical_jwk_len` suffices for P-256).
pub fn canonicalJwk(buf: []u8, public_key: anytype) []const u8 {
    const pk = anyPublic(public_key);
    if (pk.alg() == .rs256) {
        var n_buf: [rsa.max_modulus_len]u8 = undefined;
        var e_buf: [4]u8 = undefined;
        const parts = RsaParts.of(&pk.rs256, &n_buf, &e_buf);
        var nb: [base64UrlLen(rsa.max_modulus_len)]u8 = undefined;
        var eb: [base64UrlLen(4)]u8 = undefined;
        return std.fmt.bufPrint(
            buf,
            "{{\"e\":\"{s}\",\"kty\":\"RSA\",\"n\":\"{s}\"}}",
            .{ b64.Encoder.encode(&eb, parts.e), b64.Encoder.encode(&nb, parts.n) },
        ) catch unreachable; // sized by max_canonical_jwk_len for the largest key rsa accepts
    }
    var sec1_buf: [AnyPublicKey.max_sec1_len]u8 = undefined;
    const sec1 = pk.uncompressedSec1(&sec1_buf); // 0x04 ‖ X ‖ Y
    const n = pk.alg().coordLen();
    var xb: [88]u8 = undefined;
    var yb: [88]u8 = undefined;
    const x = b64.Encoder.encode(&xb, sec1[1 .. 1 + n]);
    const y = b64.Encoder.encode(&yb, sec1[1 + n .. 1 + 2 * n]);
    return std.fmt.bufPrint(
        buf,
        "{{\"crv\":\"{s}\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}",
        .{ pk.alg().crv(), x, y },
    ) catch unreachable; // fixed-width fields, buf is sized by the caller
}

/// RFC 7638 thumbprint of an already-canonical JWK byte sequence (any key
/// type) — SHA-256 over the exact bytes. Exposed so the RSA example vector
/// from RFC 7638 §3.1 can be checked; EC callers use `thumbprint`.
pub fn thumbprintOfCanonical(canonical_json: []const u8) [Sha256.digest_length]u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(canonical_json, &out, .{});
    return out;
}

/// RFC 7638 JWK thumbprint of a public key of either curve (raw 32 bytes,
/// SHA-256 whatever the curve: the thumbprint hash is independent of `alg`).
pub fn thumbprint(public_key: anytype) [Sha256.digest_length]u8 {
    var buf: [max_canonical_jwk_len]u8 = undefined;
    return thumbprintOfCanonical(canonicalJwk(&buf, public_key));
}

/// Encoded length of a base64url thumbprint.
pub const thumbprint_b64_len = base64UrlLen(Sha256.digest_length); // 43

/// base64url(thumbprint) — the form ACME uses everywhere.
pub fn thumbprintBase64(public_key: anytype) [thumbprint_b64_len]u8 {
    const raw = thumbprint(public_key);
    var out: [thumbprint_b64_len]u8 = undefined;
    _ = b64.Encoder.encode(&out, &raw);
    return out;
}

// ── RFC 8555 §8.1 key authorization ─────────────────────────────────────────

/// Upper bound we accept for a challenge token (RFC 8555 tokens are ~43
/// chars; anything much longer is not a token).
pub const max_token_len = 256;

/// Buffer size that always fits a key authorization.
pub const max_key_authorization_len = max_token_len + 1 + thumbprint_b64_len;

pub const KeyAuthorizationError = error{InvalidToken};

/// True for the token charset RFC 8555 §8.1 prescribes (base64url — the
/// token is embedded in a URL path and served back verbatim, so anything
/// else is rejected rather than echoed).
pub fn isValidToken(token: []const u8) bool {
    if (token.len == 0 or token.len > max_token_len) return false;
    for (token) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_' => {},
        else => return false,
    };
    return true;
}

/// `token ++ "." ++ base64url(JWK thumbprint)` (RFC 8555 §8.1). `buf` must
/// hold `max_key_authorization_len` bytes.
pub fn keyAuthorization(
    buf: []u8,
    token: []const u8,
    public_key: anytype,
) KeyAuthorizationError![]const u8 {
    if (!isValidToken(token)) return error.InvalidToken;
    const tp = thumbprintBase64(public_key);
    return std.fmt.bufPrint(buf, "{s}.{s}", .{ token, tp }) catch unreachable; // bounded by max_token_len
}

// ── RFC 8737 §3 TLS-ALPN-01 acmeIdentifier ──────────────────────────────────

/// SHA-256 of an already-computed key authorization string (RFC 8737 §3) —
/// the raw 32 bytes that go inside the certificate's `id-pe-acmeIdentifier`
/// extension. Same key authorization the HTTP-01 challenge serves; TLS-ALPN-01
/// instead hashes it and presents it over TLS.
// secret-api-ok: the key authorization is public by design (RFC 8555 §8.1: the CA fetches it, and its SHA-256 is published in the validation certificate).
pub fn acmeIdentifierFromKeyAuthorization(key_auth: []const u8) [Sha256.digest_length]u8 {
    var out: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(key_auth, &out, .{});
    return out;
}

/// The RFC 8737 §3 acmeIdentifier for `token` under `public_key`: computes the
/// RFC 8555 §8.1 key authorization, then returns `SHA-256(keyAuthorization)`
/// (32 bytes). This is the value embedded in the TLS-ALPN-01 validation
/// certificate's critical `id-pe-acmeIdentifier` extension.
pub fn acmeIdentifier(
    token: []const u8,
    public_key: anytype,
) KeyAuthorizationError![Sha256.digest_length]u8 {
    var buf: [max_key_authorization_len]u8 = undefined;
    const ka = try keyAuthorization(&buf, token, public_key);
    return acmeIdentifierFromKeyAuthorization(ka);
}

// ── RFC 8555 §8.4 DNS-01 TXT record value ───────────────────────────────────

/// Length of a DNS-01 TXT record value: base64url of a SHA-256 digest.
pub const dns01_txt_len = base64UrlLen(Sha256.digest_length); // 43

/// The DNS-01 TXT record value for `token` under `public_key` (RFC 8555 §8.4):
/// `base64url(SHA-256(keyAuthorization))`, unpadded. The digest is the one
/// TLS-ALPN-01 embeds raw in its certificate; DNS-01 publishes it as text.
pub fn dns01TxtValue(
    token: []const u8,
    public_key: anytype,
) KeyAuthorizationError![dns01_txt_len]u8 {
    const digest = try acmeIdentifier(token, public_key);
    var out: [dns01_txt_len]u8 = undefined;
    _ = b64.Encoder.encode(&out, &digest);
    return out;
}

// ── flattened-JSON JWS signing ──────────────────────────────────────────────

/// The ACME protected header (RFC 8555 §6.2): `alg` follows the signing key
/// (ES256, ES384 or ES512); `kid` null embeds the signer's `jwk` instead
/// (newAccount / revoke-by-key / the inner JWS of a key rollover), any other
/// POST carries the account URL as `kid`. `nonce` null omits the member (the
/// inner JWS of a key rollover MUST NOT carry one, RFC 8555 §7.3.5).
pub const Header = struct {
    nonce: ?[]const u8,
    url: []const u8,
    kid: ?[]const u8 = null,
};

pub const SignError = error{ OutOfMemory, SigningFailed };

/// Sign `payload` (raw bytes; "" for POST-as-GET) into a flattened JSON JWS
/// (`{"protected","payload","signature"}`). `key_pair` is a pointer to an
/// `Es256.KeyPair`, an `Es384.KeyPair`, an `Es512.KeyPair`, an `rsa.KeyPair`
/// (RS256: RSASSA-PKCS1-v1_5 + SHA-256, deterministic, `rsa.signPkcs1v15` —
/// whose private operation runs with base blinding off) or an `AnyKeyPair`.
/// Caller owns the returned JSON.
pub fn sign(
    gpa: std.mem.Allocator,
    key_pair: anytype,
    payload: []const u8,
    header: Header,
) SignError![]u8 {
    if (comptime @TypeOf(key_pair.*) == AnyKeyPair) {
        return switch (key_pair.*) {
            inline .es256, .es384, .es512 => |*kp| signTyped(gpa, kp, payload, header),
            .rs256 => |kp| signTyped(gpa, kp, payload, header),
        };
    } else {
        return signTyped(gpa, key_pair, payload, header);
    }
}

fn signTyped(
    gpa: std.mem.Allocator,
    key_pair: anytype,
    payload: []const u8,
    header: Header,
) SignError![]u8 {
    const KP = @TypeOf(key_pair.*);
    return burn.run(burn.sign_burn, SignError![]u8, SignBody(KP).run, .{ gpa, key_pair, payload, header });
}

fn SignBody(comptime KP: type) type {
    return struct {
        fn run(
            gpa: std.mem.Allocator,
            key_pair: *const KP,
            payload: []const u8,
            header: Header,
        ) SignError![]u8 {
            // Protected header JSON. Field order mirrors x/crypto/acme (alg,
            // jwk|kid, nonce, url) — servers must not care, but goldens do.
            var hw: std.Io.Writer.Allocating = .init(gpa);
            defer hw.deinit();
            var js: std.json.Stringify = .{ .writer = &hw.writer, .options = .{} };
            writeProtected(&js, publicOfPair(key_pair), header) catch return error.OutOfMemory;
            const protected = hw.written();

            var out: std.Io.Writer.Allocating = .init(gpa);
            defer out.deinit();
            const w = &out.writer;
            appendJws(KP, gpa, w, key_pair, protected, payload) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.WriteFailed => return error.OutOfMemory, // Allocating writer only fails on OOM
                error.SigningFailed => return error.SigningFailed,
            };
            return out.toOwnedSlice();
        }
    };
}

fn writeProtected(js: *std.json.Stringify, public_key: AnyPublicKey, header: Header) !void {
    try js.beginObject();
    try js.objectField("alg");
    try js.write(public_key.alg().name());
    if (header.kid) |kid| {
        try js.objectField("kid");
        try js.write(kid);
    } else {
        var jwk_buf: [max_canonical_jwk_len]u8 = undefined;
        try js.objectField("jwk");
        try js.beginWriteRaw();
        try js.writer.writeAll(canonicalJwk(&jwk_buf, public_key));
        js.endWriteRaw();
    }
    if (header.nonce) |nonce| {
        try js.objectField("nonce");
        try js.write(nonce);
    }
    try js.objectField("url");
    try js.write(header.url);
    try js.endObject();
}

/// Longest JWS signature: an RSA modulus at the `rsa` module's ceiling (the
/// EC signatures are at most 132 bytes).
const max_sig_len = rsa.max_modulus_len;

/// The JWS signature over `input` (BASE64URL(protected) ‖ "." ‖ BASE64URL(payload)),
/// into `out`: `r ‖ s` for ECDSA (64 / 96 / 132 bytes), the PKCS#1 v1.5 value
/// for RS256 (one modulus length).
fn signInput(comptime KP: type, key_pair: *const KP, input: []const u8, out: *[max_sig_len]u8) SignError![]const u8 {
    if (comptime KP == rsa.KeyPair) {
        return rsa.signPkcs1v15(&key_pair.secret_key, Sha256, input, out) catch return error.SigningFailed;
    } else {
        const sig = key_pair.sign(input, null) catch return error.SigningFailed;
        const bytes = sig.toBytes(); // r ‖ s: 64 bytes (ES256), 96 (ES384) or 132 (ES512)
        @memcpy(out[0..bytes.len], &bytes);
        return out[0..bytes.len];
    }
}

fn appendJws(
    comptime KP: type,
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    key_pair: *const KP,
    protected: []const u8,
    payload: []const u8,
) (SignError || std.Io.Writer.Error)!void {
    const protected_b64 = try base64UrlEncodeAlloc(gpa, protected);
    defer gpa.free(protected_b64);
    const payload_b64 = try base64UrlEncodeAlloc(gpa, payload);
    defer gpa.free(payload_b64);

    // Signing input = BASE64URL(protected) ‖ "." ‖ BASE64URL(payload).
    const input = try std.mem.concat(gpa, u8, &.{ protected_b64, ".", payload_b64 });
    defer gpa.free(input);
    var sig_buf: [max_sig_len]u8 = undefined;
    const sig_bytes = try signInput(KP, key_pair, input, &sig_buf);
    var sig_b64_buf: [base64UrlLen(max_sig_len)]u8 = undefined;
    const sig_b64 = b64.Encoder.encode(&sig_b64_buf, sig_bytes);

    try w.print(
        "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"{s}\"}}",
        .{ protected_b64, payload_b64, sig_b64 },
    );
}

// ── RFC 8555 §7.3.4 external account binding (HS256 inner JWS) ──────────────

/// The EAB inner JWS (RFC 8555 §7.3.4): a flattened JWS whose payload is the
/// account's public JWK, protected header `{alg:"HS256", kid, url}` (no
/// nonce), MAC'd with the CA-issued key. `hmac_key` is the raw MAC key (the
/// CAs hand it out base64url-encoded: decode with `base64UrlDecodeAlloc`
/// first). Caller owns the returned JSON.
pub fn signEab(
    gpa: std.mem.Allocator,
    account_public_key: anytype,
    eab_kid: []const u8,
    hmac_key: []const u8,
    new_account_url: []const u8,
) error{OutOfMemory}![]u8 {
    var jwk_buf: [max_canonical_jwk_len]u8 = undefined;
    const jwk = canonicalJwk(&jwk_buf, account_public_key);

    var hw: std.Io.Writer.Allocating = .init(gpa);
    defer hw.deinit();
    var js: std.json.Stringify = .{ .writer = &hw.writer, .options = .{} };
    js.beginObject() catch return error.OutOfMemory;
    js.objectField("alg") catch return error.OutOfMemory;
    js.write("HS256") catch return error.OutOfMemory;
    js.objectField("kid") catch return error.OutOfMemory;
    js.write(eab_kid) catch return error.OutOfMemory;
    js.objectField("url") catch return error.OutOfMemory;
    js.write(new_account_url) catch return error.OutOfMemory;
    js.endObject() catch return error.OutOfMemory;

    const protected_b64 = try base64UrlEncodeAlloc(gpa, hw.written());
    defer gpa.free(protected_b64);
    const payload_b64 = try base64UrlEncodeAlloc(gpa, jwk);
    defer gpa.free(payload_b64);
    const input = try std.mem.concat(gpa, u8, &.{ protected_b64, ".", payload_b64 });
    defer gpa.free(input);

    var mac = hs256(hmac_key, input);
    var mac_b64: [base64UrlLen(mac.len)]u8 = undefined;
    _ = b64.Encoder.encode(&mac_b64, &mac);
    std.crypto.secureZero(u8, &mac);
    burn.stack(burn.key_burn);

    return std.fmt.allocPrint(
        gpa,
        "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"{s}\"}}",
        .{ protected_b64, payload_b64, mac_b64 },
    );
}

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// HMAC-SHA256 with the MAC context wiped (it holds the key-derived pads).
noinline fn hs256(key: []const u8, msg: []const u8) [HmacSha256.mac_length]u8 {
    var ctx = HmacSha256.init(key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ctx));
    ctx.update(msg);
    var out: [HmacSha256.mac_length]u8 = undefined;
    ctx.final(&out);
    return out;
}

/// A verified EAB inner JWS (the mock-CA half of `signEab`). Arena-owned.
pub const VerifiedEab = struct {
    arena: std.heap.ArenaAllocator,
    payload: []const u8,
    kid: []const u8,
    url: []const u8,
    /// True when the protected header carried a `nonce` (forbidden).
    has_nonce: bool,

    pub fn deinit(v: *VerifiedEab) void {
        v.arena.deinit();
        v.* = undefined;
    }
};

/// Parse a flattened HS256 JWS and check its MAC against `hmac_key`.
pub fn verifyEab(
    gpa: std.mem.Allocator,
    jws_json: []const u8,
    hmac_key: []const u8,
) VerifyError!VerifiedEab {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const flat = std.json.parseFromSliceLeaky(FlattenedJson, a, jws_json, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedJws,
    };
    if (flat.protected.len == 0 or flat.signature.len == 0) return error.MalformedJws;
    const protected = base64UrlDecodeAlloc(a, flat.protected) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidBase64 => return error.MalformedJws,
    };
    const payload = base64UrlDecodeAlloc(a, flat.payload) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidBase64 => return error.MalformedJws,
    };
    const mac = base64UrlDecodeAlloc(a, flat.signature) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidBase64 => return error.MalformedJws,
    };
    const Head = struct { alg: []const u8 = "", kid: []const u8 = "", url: []const u8 = "", nonce: ?[]const u8 = null };
    const head = std.json.parseFromSliceLeaky(Head, a, protected, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedJws,
    };
    if (!std.mem.eql(u8, head.alg, "HS256")) return error.UnsupportedJws;
    const input = std.mem.concat(a, u8, &.{ flat.protected, ".", flat.payload }) catch
        return error.OutOfMemory;
    var want = hs256(hmac_key, input);
    defer {
        std.crypto.secureZero(u8, &want);
        burn.stack(burn.key_burn);
    }
    if (mac.len != want.len or !std.crypto.timing_safe.eql([want.len]u8, mac[0..want.len].*, want))
        return error.BadSignature;
    return .{
        .arena = arena,
        .payload = payload,
        .kid = head.kid,
        .url = head.url,
        .has_nonce = head.nonce != null,
    };
}

// ── flattened-JSON JWS verification (the server side) ───────────────────────

pub const VerifyError = error{
    OutOfMemory,
    /// Not a flattened JWS / protected header not JSON / bad base64.
    MalformedJws,
    /// alg is not a supported one, or jwk/kid are missing/both present.
    UnsupportedJws,
    /// Signature does not verify.
    BadSignature,
};

/// A parsed + cryptographically verified flattened JWS. All slices are
/// arena-owned by this struct — free with `deinit`.
pub const Verified = struct {
    arena: std.heap.ArenaAllocator,
    /// Decoded payload bytes ("" for POST-as-GET).
    payload: []const u8,
    nonce: []const u8,
    url: []const u8,
    /// Account URL, when the header used `kid`.
    kid: ?[]const u8,
    /// The embedded key, when the header used `jwk`.
    jwk_key: ?Es256.PublicKey,

    pub fn deinit(v: *Verified) void {
        v.arena.deinit();
        v.* = undefined;
    }
};

const FlattenedJson = struct {
    protected: []const u8 = "",
    payload: []const u8 = "",
    signature: []const u8 = "",
};

const ProtectedJson = struct {
    alg: []const u8 = "",
    nonce: []const u8 = "",
    url: []const u8 = "",
    kid: ?[]const u8 = null,
    jwk: ?JwkJson = null,

    const JwkJson = struct {
        kty: []const u8 = "",
        crv: []const u8 = "",
        x: []const u8 = "",
        y: []const u8 = "",
        n: []const u8 = "",
        e: []const u8 = "",
    };
};

/// `Verified` for either curve — what `verifyFlattenedAny` returns.
pub const VerifiedAny = struct {
    arena: std.heap.ArenaAllocator,
    alg: Alg,
    payload: []const u8,
    /// "" when the header carried no nonce.
    nonce: []const u8,
    url: []const u8,
    kid: ?[]const u8,
    jwk_key: ?AnyPublicKey,

    pub fn deinit(v: *VerifiedAny) void {
        v.arena.deinit();
        v.* = undefined;
    }
};

/// Parse a flattened JWS and verify its ES256 signature. `expected_key`
/// null means "use the embedded jwk" (newAccount); otherwise the signature
/// must verify against `expected_key` (the account key a real CA has on
/// file). This is the mock-CA / test half of the module. ES256 only: an
/// ES384 or ES512 JWS answers `UnsupportedJws` (see `verifyFlattenedAny`).
pub fn verifyFlattened(
    gpa: std.mem.Allocator,
    jws_json: []const u8,
    expected_key: ?Es256.PublicKey,
) VerifyError!Verified {
    var v = try verifyFlattenedAny(gpa, jws_json, if (expected_key) |k| .{ .es256 = k } else null);
    errdefer v.deinit();
    if (v.alg != .es256) return error.UnsupportedJws;
    return .{
        .arena = v.arena,
        .payload = v.payload,
        .nonce = v.nonce,
        .url = v.url,
        .kid = v.kid,
        .jwk_key = if (v.jwk_key) |k| k.es256 else null,
    };
}

/// `verifyFlattened` for ES256, ES384, ES512 and RS256: the header's `alg`
/// picks the curve (or RSA), the embedded jwk must be of that kind, and an
/// `expected_key` must be too. An RS256 key must have `rsa_min_bits` ..
/// `rsa_max_bits` bits, its JWK `n` and `e` must carry no leading zero octet
/// (RFC 7518 §6.3.1.1), and its signature must be exactly one modulus long
/// (RFC 7518 §3.3).
pub fn verifyFlattenedAny(
    gpa: std.mem.Allocator,
    jws_json: []const u8,
    expected_key: ?AnyPublicKey,
) VerifyError!VerifiedAny {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const flat = std.json.parseFromSliceLeaky(FlattenedJson, a, jws_json, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedJws,
    };
    if (flat.protected.len == 0 or flat.signature.len == 0) return error.MalformedJws;

    const protected = base64UrlDecodeAlloc(a, flat.protected) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidBase64 => return error.MalformedJws,
    };
    const payload = base64UrlDecodeAlloc(a, flat.payload) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidBase64 => return error.MalformedJws,
    };
    const sig_bytes = base64UrlDecodeAlloc(a, flat.signature) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidBase64 => return error.MalformedJws,
    };
    // An ECDSA signature has one of three fixed lengths; an RS256 one is as
    // long as the key's modulus, known only once the key is. So a length that
    // fits no ECDSA curve is refused here unless the header turns out to name
    // RS256 (decided below, at the same point in the error order as before).
    const ec_sig_len = sig_bytes.len == Alg.es256.sigLen() or sig_bytes.len == Alg.es384.sigLen() or
        sig_bytes.len == Alg.es512.sigLen();

    const head = std.json.parseFromSliceLeaky(ProtectedJson, a, protected, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedJws,
    };
    const alg = Alg.fromName(head.alg) orelse return if (ec_sig_len) error.UnsupportedJws else error.MalformedJws;
    if (alg != .rs256 and !ec_sig_len) return error.MalformedJws;
    if ((head.kid == null) == (head.jwk == null)) return error.UnsupportedJws; // exactly one

    var jwk_key: ?AnyPublicKey = null;
    if (head.jwk) |jwk| {
        if (alg == .rs256) {
            if (!std.mem.eql(u8, jwk.kty, "RSA")) return error.UnsupportedJws;
            jwk_key = rsaPublicKeyFromJwk(a, jwk.n, jwk.e) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.MalformedJws,
            };
        } else {
            if (!std.mem.eql(u8, jwk.kty, "EC") or !std.mem.eql(u8, jwk.crv, alg.crv()))
                return error.UnsupportedJws;
            jwk_key = publicKeyFromCoords(a, alg, jwk.x, jwk.y) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.MalformedJws,
            };
        }
    }
    const key = expected_key orelse (jwk_key orelse return error.UnsupportedJws);
    if (key.alg() != alg) return error.UnsupportedJws; // a key of another curve cannot verify it
    switch (key) {
        .rs256 => |*k| if (sig_bytes.len != k.mp.byteLen()) return error.MalformedJws, // RFC 7518 §3.3: one modulus
        else => if (sig_bytes.len != alg.sigLen()) return error.MalformedJws, // RFC 7518 §3.4: exactly R ‖ S
    }

    // Verify over the exact base64url text from the wire.
    const input = std.mem.concat(a, u8, &.{ flat.protected, ".", flat.payload }) catch
        return error.OutOfMemory;
    switch (key) {
        .es256 => |k| Es256.Signature.fromBytes(sig_bytes[0..64].*).verify(input, k) catch return error.BadSignature,
        .es384 => |k| Es384.Signature.fromBytes(sig_bytes[0..96].*).verify(input, k) catch return error.BadSignature,
        .es512 => |k| Es512.Signature.fromBytes(sig_bytes[0..132].*).verify(input, k) catch return error.BadSignature,
        .rs256 => |*k| k.verifyPkcs1v15(Sha256, input, sig_bytes) catch return error.BadSignature,
    }

    return .{
        .arena = arena,
        .alg = alg,
        .payload = payload,
        .nonce = head.nonce,
        .url = head.url,
        .kid = head.kid,
        .jwk_key = jwk_key,
    };
}

/// The RS256 public key of a JWK's `n` and `e` (RFC 7518 §6.3.1): base64url of
/// the unsigned big-endian octets, minimal (no leading zero), a modulus of
/// `rsa_min_bits` .. `rsa_max_bits`.
fn rsaPublicKeyFromJwk(
    scratch: std.mem.Allocator,
    n_b64: []const u8,
    e_b64: []const u8,
) error{ OutOfMemory, InvalidBase64, InvalidKey }!AnyPublicKey {
    const n = try base64UrlDecodeAlloc(scratch, n_b64);
    const e = try base64UrlDecodeAlloc(scratch, e_b64);
    if (n.len == 0 or e.len == 0 or n[0] == 0 or e[0] == 0) return error.InvalidKey;
    const vk = rsa.VerifyKey.fromBytes(n, e) catch return error.InvalidKey;
    if (vk.bits() < rsa_min_bits or vk.bits() > rsa_max_bits) return error.InvalidKey;
    return .{ .rs256 = vk };
}

fn publicKeyFromCoords(
    scratch: std.mem.Allocator,
    alg: Alg,
    x_b64: []const u8,
    y_b64: []const u8,
) error{ OutOfMemory, InvalidBase64, InvalidKey }!AnyPublicKey {
    const x = try base64UrlDecodeAlloc(scratch, x_b64);
    const y = try base64UrlDecodeAlloc(scratch, y_b64);
    const n = alg.coordLen();
    if (x.len != n or y.len != n) return error.InvalidKey;
    var sec1: [AnyPublicKey.max_sec1_len]u8 = undefined;
    sec1[0] = 0x04;
    @memcpy(sec1[1 .. 1 + n], x);
    @memcpy(sec1[1 + n .. 1 + 2 * n], y);
    return switch (alg) {
        .es256 => .{ .es256 = Es256.PublicKey.fromSec1(sec1[0 .. 1 + 2 * n]) catch return error.InvalidKey },
        .es384 => .{ .es384 = Es384.PublicKey.fromSec1(sec1[0 .. 1 + 2 * n]) catch return error.InvalidKey },
        .es512 => .{ .es512 = Es512.PublicKey.fromSec1(sec1[0 .. 1 + 2 * n]) catch return error.InvalidKey },
        .rs256 => unreachable, // callers use `rsaPublicKeyFromJwk` for RSA
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// RFC 7515 Appendix A.3 — the ES256 example key and vectors.
const rfc7515_x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const rfc7515_y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
const rfc7515_d = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";
const rfc7515_signing_input = "eyJhbGciOiJFUzI1NiJ9" ++ "." ++
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" ++
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
const rfc7515_signature = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" ++
    "pmWQxfKTUJqPP3-Kg6NU1Q";

/// The RFC 7515 A.3 key pair (a published test key, not a secret), in static
/// storage so tests pass it by pointer like production code.
fn rfc7515KeyPair() !*const KeyPair {
    const S = struct {
        var kp: KeyPair = undefined;
        var ready = false;
    };
    if (!S.ready) {
        var sk: Es256.SecretKey = undefined;
        try b64.Decoder.decode(&sk.bytes, rfc7515_d);
        try KeyPair.fromSecretKeyInto(&S.kp, &sk);
        S.ready = true;
    }
    return &S.kp;
}

/// A fixed non-secret test pair per seed byte, static storage.
fn seedKeyPair(comptime seed_byte: u8) *const KeyPair {
    const S = struct {
        var kp: KeyPair = undefined;
        var ready = false;
    };
    if (!S.ready) {
        const seed: [KeyPair.seed_length]u8 = @splat(seed_byte);
        KeyPair.generateDeterministicInto(&S.kp, &seed) catch unreachable;
        S.ready = true;
    }
    return &S.kp;
}

test "base64url: RFC 4648 behavior, no padding, url-safe alphabet" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("", base64UrlEncode(&buf, ""));
    try testing.expectEqualStrings("Zg", base64UrlEncode(&buf, "f"));
    try testing.expectEqualStrings("Zm8", base64UrlEncode(&buf, "fo"));
    try testing.expectEqualStrings("Zm9v", base64UrlEncode(&buf, "foo"));
    try testing.expectEqualStrings("Zm9vYg", base64UrlEncode(&buf, "foob"));
    try testing.expectEqualStrings("Zm9vYmE", base64UrlEncode(&buf, "fooba"));
    try testing.expectEqualStrings("Zm9vYmFy", base64UrlEncode(&buf, "foobar"));
    // The url-safe alphabet: 0xfb 0xff → "-_" territory, and never '+' '/'.
    try testing.expectEqualStrings("-_8", base64UrlEncode(&buf, &.{ 0xfb, 0xff }));

    // Round-trip through the alloc variants.
    const enc = try base64UrlEncodeAlloc(testing.allocator, "any carnal pleasure");
    defer testing.allocator.free(enc);
    try testing.expect(std.mem.indexOfScalar(u8, enc, '=') == null);
    const dec = try base64UrlDecodeAlloc(testing.allocator, enc);
    defer testing.allocator.free(dec);
    try testing.expectEqualStrings("any carnal pleasure", dec);

    try testing.expectError(error.InvalidBase64, base64UrlDecodeAlloc(testing.allocator, "a+b/"));
}

test "canonical JWK: exact RFC 7638 member order for the RFC 7515 A.3 key" {
    const kp = try rfc7515KeyPair();
    // Deriving the public key from d must reproduce the RFC's x and y.
    var buf: [canonical_jwk_len]u8 = undefined;
    const jwk = canonicalJwk(&buf, kp.public_key);
    try testing.expectEqualStrings(
        "{\"crv\":\"P-256\",\"kty\":\"EC\"," ++
            "\"x\":\"" ++ rfc7515_x ++ "\",\"y\":\"" ++ rfc7515_y ++ "\"}",
        jwk,
    );
}

test "thumbprint: RFC 7638 §3.1 example vector (RSA canonical bytes)" {
    // The RFC's example key is RSA; its canonical form and expected
    // thumbprint are given verbatim — hash the exact bytes.
    const canonical = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"" ++
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSo" ++
        "c_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YG" ++
        "jQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt" ++
        "-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" ++
        "\"}";
    const tp = thumbprintOfCanonical(canonical);
    var tp_b64: [thumbprint_b64_len]u8 = undefined;
    _ = b64.Encoder.encode(&tp_b64, &tp);
    try testing.expectEqualStrings("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", &tp_b64);
}

test "thumbprint: P-256 (RFC 7515 A.3 key, independently computed oracle)" {
    const kp = try rfc7515KeyPair();
    const tp = thumbprintBase64(kp.public_key);
    // Oracle: python hashlib/base64 over the canonical JWK above.
    try testing.expectEqualStrings("oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U", &tp);
}

test "key authorization: token.thumbprint, bad tokens rejected" {
    const kp = try rfc7515KeyPair();
    var buf: [max_key_authorization_len]u8 = undefined;
    const ka = try keyAuthorization(&buf, "DGyRejmCefe7v4NfDGDKfA", kp.public_key);
    try testing.expectEqualStrings(
        "DGyRejmCefe7v4NfDGDKfA.oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U",
        ka,
    );

    try testing.expectError(error.InvalidToken, keyAuthorization(&buf, "", kp.public_key));
    try testing.expectError(error.InvalidToken, keyAuthorization(&buf, "a/b", kp.public_key));
    try testing.expectError(error.InvalidToken, keyAuthorization(&buf, "a.b", kp.public_key));
    try testing.expectError(error.InvalidToken, keyAuthorization(&buf, "tok en", kp.public_key));
    try testing.expectError(error.InvalidToken, keyAuthorization(&buf, "x" ** 257, kp.public_key));
}

test "acmeIdentifier (RFC 8737 §3): SHA-256 of the key authorization" {
    const kp = try rfc7515KeyPair();
    // The key authorization for this (token, key) pair is checked byte-exact
    // in the test above; here we hash it. Oracle: `printf '%s' '<key-auth>'
    // | sha256sum` over that exact string.
    const id = try acmeIdentifier("DGyRejmCefe7v4NfDGDKfA", kp.public_key);
    const expected = [_]u8{
        0x54, 0x88, 0x65, 0x39, 0xb5, 0x35, 0xe1, 0x2b, 0x33, 0xb8, 0x68, 0x89, 0x8d, 0x81, 0x24, 0x48,
        0x25, 0xb3, 0x6b, 0xdf, 0x97, 0xf9, 0x41, 0x54, 0xbb, 0x31, 0xa1, 0xd5, 0x0b, 0x22, 0x61, 0xc5,
    };
    try testing.expectEqualSlices(u8, &expected, &id);

    // The convenience path equals hashing the key-authorization string directly.
    var ka_buf: [max_key_authorization_len]u8 = undefined;
    const ka = try keyAuthorization(&ka_buf, "DGyRejmCefe7v4NfDGDKfA", kp.public_key);
    try testing.expectEqualSlices(u8, &id, &acmeIdentifierFromKeyAuthorization(ka));

    // A non-token is rejected the same way keyAuthorization rejects it.
    try testing.expectError(error.InvalidToken, acmeIdentifier("a/b", kp.public_key));
}

test "dns01TxtValue (RFC 8555 §8.4): base64url of SHA-256 of the key authorization" {
    const kp = try rfc7515KeyPair();
    // Oracle, two independent tools over the key authorization pinned above
    // ("DGyRejmCefe7v4NfDGDKfA.oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"):
    //   printf '%s' '<key-auth>' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='
    //   python3: base64.urlsafe_b64encode(<the acmeIdentifier bytes above>).rstrip(b'=')
    // Both give the value below (2026-09-30).
    const txt = try dns01TxtValue("DGyRejmCefe7v4NfDGDKfA", kp.public_key);
    try testing.expectEqualStrings("VIhlObU14SszuGiJjYEkSCWza9-X-UFUuzGh1QsiYcU", &txt);
    try testing.expectError(error.InvalidToken, dns01TxtValue("a/b", kp.public_key));
}

test "ES256 known-answer: the RFC 7515 A.3 signature verifies (and tampering fails)" {
    const kp = try rfc7515KeyPair();
    var sig_bytes: [64]u8 = undefined;
    try b64.Decoder.decode(&sig_bytes, rfc7515_signature);
    const sig = Es256.Signature.fromBytes(sig_bytes);
    try sig.verify(rfc7515_signing_input, kp.public_key);

    // Any bit flip in the input must fail.
    var tampered: [rfc7515_signing_input.len]u8 = rfc7515_signing_input.*;
    tampered[0] ^= 1;
    try testing.expectError(error.SignatureVerificationFailed, sig.verify(&tampered, kp.public_key));
}

test "sign → verifyFlattened round-trip (jwk mode, deterministic)" {
    const kp = try rfc7515KeyPair();
    const jws1 = try sign(testing.allocator, kp, "{\"termsOfServiceAgreed\":true}", .{
        .nonce = "nonce-1",
        .url = "https://ca.example/new-acct",
    });
    defer testing.allocator.free(jws1);
    const jws2 = try sign(testing.allocator, kp, "{\"termsOfServiceAgreed\":true}", .{
        .nonce = "nonce-1",
        .url = "https://ca.example/new-acct",
    });
    defer testing.allocator.free(jws2);
    // Deterministic signing: identical inputs → identical JWS.
    try testing.expectEqualStrings(jws1, jws2);

    // Self-authenticating (jwk embedded): verify with no expected key.
    var v = try verifyFlattened(testing.allocator, jws1, null);
    defer v.deinit();
    try testing.expectEqualStrings("{\"termsOfServiceAgreed\":true}", v.payload);
    try testing.expectEqualStrings("nonce-1", v.nonce);
    try testing.expectEqualStrings("https://ca.example/new-acct", v.url);
    try testing.expect(v.kid == null);
    // The embedded jwk is the signer's key.
    const embedded = v.jwk_key.?;
    try testing.expectEqualSlices(
        u8,
        &kp.public_key.toUncompressedSec1(),
        &embedded.toUncompressedSec1(),
    );
}

test "sign → verifyFlattened (kid mode + POST-as-GET empty payload)" {
    const kp = try rfc7515KeyPair();
    const jws_json = try sign(testing.allocator, kp, "", .{
        .nonce = "n2",
        .url = "https://ca.example/order/1",
        .kid = "https://ca.example/acct/17",
    });
    defer testing.allocator.free(jws_json);

    var v = try verifyFlattened(testing.allocator, jws_json, kp.public_key);
    defer v.deinit();
    try testing.expectEqualStrings("", v.payload);
    try testing.expectEqualStrings("https://ca.example/acct/17", v.kid.?);
    try testing.expect(v.jwk_key == null);

    // The wrong key must not verify.
    const other = seedKeyPair(7);
    try testing.expectError(
        error.BadSignature,
        verifyFlattened(testing.allocator, jws_json, other.public_key),
    );
}

// ── the RNG seam (entropy re-audit 2026-08-13) ──────────────────────────────

test "RNG seam: generateKeyPair really draws entropy, and round-trips end to end" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A signature pin alone would pass over a body that ignores `io`. Two
    // account keys drawn from the same `io` must differ.
    //
    // This catches a constant seed and a seed that is drawn but never read
    // (both leave `generateKeyPair` minting the same key every call). It
    // does NOT catch a weak-but-varying PRNG substituted for `entropy.fill`
    // — two draws from a seeded `DefaultPrng` also differ from each other,
    // so distinctness alone cannot tell "real entropy" from "some other
    // stream of varying bytes". `entropy`'s own `CountingIo` pins which
    // `std.Io` vtable slot a draw goes through, but that probe lives in
    // `modules/entropy/src/root.zig` as a private test helper (not a public
    // export) and this module has one call site behind `entropy.fill`
    // itself, already covered there — duplicating the probe here would
    // re-test `entropy.fill`, not `jws.generateKeyPair`.
    //
    // A third gap, sharper than the second: this also does not catch a
    // PARTIAL draw — `entropy.fill` writing real entropy into only part of
    // the 32-byte seed and leaving the rest constant. The surviving bytes
    // alone are enough to make `generateDeterministic` mint two different
    // keys, so `!std.mem.eql` below cannot tell "fully drawn" from "mostly
    // constant". Measured directly in `megolm`'s 128-byte ratchet seed
    // (`session.zig`): zeroing 96 of the 128 drawn bytes right after
    // `entropy.fill` left `zig build test-megolm` green. Not re-measured
    // here, but the seed above is one buffer filled the same way, so the
    // same failure mode applies.
    var kp1: KeyPair = undefined;
    var kp2: KeyPair = undefined;
    generateKeyPair(&kp1, io);
    generateKeyPair(&kp2, io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp1));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp2));
    try testing.expect(!std.mem.eql(u8, &kp1.secret_key.bytes, &kp2.secret_key.bytes));

    // And the production path is a working path, not just a typed one:
    // sign with the freshly drawn key, verify with its own embedded jwk.
    const jws_json = try sign(testing.allocator, &kp1, "{}", .{
        .nonce = "n",
        .url = "https://ca.example/x",
    });
    defer testing.allocator.free(jws_json);
    var v = try verifyFlattened(testing.allocator, jws_json, null);
    defer v.deinit();
    try testing.expectEqualStrings("{}", v.payload);
}

test "verifyFlattened: malformed and tampered inputs never verify" {
    const kp = try rfc7515KeyPair();
    const jws_json = try sign(testing.allocator, kp, "{\"a\":1}", .{
        .nonce = "n",
        .url = "https://ca.example/x",
        .kid = "https://ca.example/acct/1",
    });
    defer testing.allocator.free(jws_json);

    // Tamper with the payload field (swap a base64 char).
    const tampered = try testing.allocator.dupe(u8, jws_json);
    defer testing.allocator.free(tampered);
    const pay_at = std.mem.indexOf(u8, tampered, "\"payload\":\"").? + "\"payload\":\"".len;
    tampered[pay_at] = if (tampered[pay_at] == 'A') 'B' else 'A';
    try testing.expectError(error.BadSignature, verifyFlattened(testing.allocator, tampered, kp.public_key));

    try testing.expectError(error.MalformedJws, verifyFlattened(testing.allocator, "not json", null));
    try testing.expectError(error.MalformedJws, verifyFlattened(testing.allocator, "{}", null));
    // kid and jwk are mutually exclusive; neither is also an error.
    const no_key = "{\"protected\":\"" ++ "eyJhbGciOiJFUzI1NiJ9" ++ "\",\"payload\":\"\",\"signature\":\"" ++ ("A" ** 86) ++ "\"}";
    try testing.expectError(error.UnsupportedJws, verifyFlattened(testing.allocator, no_key, null));
}

// ── audit 2026-10-04: tests asked for by mutation survivors ──────────────────

/// A flattened JWS with a hand-written protected header, genuinely ES256-
/// signed by `kp` over `b64(protected) "." b64(payload)` — so the only
/// thing wrong with it is whatever the header says.
fn craftJws(a: std.mem.Allocator, kp: *const KeyPair, protected: []const u8, sig_extra: []const u8) ![]u8 {
    const p64 = try base64UrlEncodeAlloc(a, protected);
    const input = try std.mem.concat(a, u8, &.{ p64, "." });
    const sig = try kp.sign(input, null);
    const raw = try std.mem.concat(a, u8, &.{ &sig.toBytes(), sig_extra });
    const s64 = try base64UrlEncodeAlloc(a, raw);
    return std.fmt.allocPrint(a, "{{\"protected\":\"{s}\",\"payload\":\"\",\"signature\":\"{s}\"}}", .{ p64, s64 });
}

test "verifyFlattened refuses a validly signed JWS whose header breaks RFC 8555 §6.2 / RFC 7518" {
    // §6.2: alg MUST be an asymmetric algorithm the server supports (ES256
    // here); "jwk" and "kid" are mutually exclusive, exactly one present;
    // the JWK must be an EC P-256 key (RFC 7518 §6.2.1) with 32-byte
    // coordinates. And an account-key verification (`expected_key`) must
    // use THAT key — an embedded jwk cannot substitute its own. Every JWS
    // below carries a genuine signature by the key it names.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const kp = try rfc7515KeyPair();
    var jwk_buf: [256]u8 = undefined;
    const jwk = canonicalJwk(&jwk_buf, kp.public_key);

    const ok = try craftJws(a, kp, try std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"jwk\":{s},\"nonce\":\"n\",\"url\":\"u\"}}", .{jwk}), "");
    var v = try verifyFlattened(testing.allocator, ok, null); // control
    v.deinit();

    const bad_alg = try craftJws(a, kp, try std.fmt.allocPrint(a, "{{\"alg\":\"ES384\",\"jwk\":{s},\"nonce\":\"n\",\"url\":\"u\"}}", .{jwk}), "");
    try testing.expectError(error.UnsupportedJws, verifyFlattened(testing.allocator, bad_alg, null));
    const both = try craftJws(a, kp, try std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"jwk\":{s},\"kid\":\"acct\",\"nonce\":\"n\",\"url\":\"u\"}}", .{jwk}), "");
    try testing.expectError(error.UnsupportedJws, verifyFlattened(testing.allocator, both, null));
    const rsa_kty = try std.mem.replaceOwned(u8, a, jwk, "\"kty\":\"EC\"", "\"kty\":\"RSA\"");
    const wrong_kty = try craftJws(a, kp, try std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"jwk\":{s},\"nonce\":\"n\",\"url\":\"u\"}}", .{rsa_kty}), "");
    try testing.expectError(error.UnsupportedJws, verifyFlattened(testing.allocator, wrong_kty, null));
    const short_x = "{\"alg\":\"ES256\",\"jwk\":{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"AAAA\",\"y\":\"" ++ rfc7515_y ++ "\"},\"nonce\":\"n\",\"url\":\"u\"}";
    try testing.expectError(error.MalformedJws, verifyFlattened(testing.allocator, try craftJws(a, kp, short_x, ""), null));
    // A 65-byte "signature": the real 64 bytes plus one — not an ES256
    // signature (RFC 7518 §3.4: exactly R ‖ S, 64 octets).
    const long_sig = try craftJws(a, kp, try std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"jwk\":{s},\"nonce\":\"n\",\"url\":\"u\"}}", .{jwk}), "\x00");
    try testing.expectError(error.MalformedJws, verifyFlattened(testing.allocator, long_sig, null));

    // An attacker's own key, embedded as jwk, against the account key.
    const attacker = seedKeyPair(9);
    var ajwk_buf: [256]u8 = undefined;
    const ajwk = canonicalJwk(&ajwk_buf, attacker.public_key);
    const forged = try craftJws(a, attacker, try std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"jwk\":{s},\"nonce\":\"n\",\"url\":\"u\"}}", .{ajwk}), "");
    try testing.expectError(error.BadSignature, verifyFlattened(testing.allocator, forged, kp.public_key));
}

// ── ES384 (2026-10-13) ──────────────────────────────────────────────────────

// A throwaway P-384 key from `openssl genpkey -algorithm EC -pkeyopt
// ec_paramgen_curve:P-384` (the same key as x509.zig's PKCS#8 fixture).
const p384_d_hex = "84d10a65cc763b042d4869fc59e090632b1380b66262baaafb1db64dc25e6047ba1147d12bda24532edb3bdfd8250313";
// Oracle: python3 over `openssl pkey -pubout -outform DER` of that key —
// canonical JWK, then base64url(SHA-256) of it.
const p384_canonical_jwk = "{\"crv\":\"P-384\",\"kty\":\"EC\"," ++
    "\"x\":\"i2evqQWuRMKFLy97rKoVK0zwFObkJKOfLLqPmmESj4cNoHCdy4oEh9yAzNzMat-k\"," ++
    "\"y\":\"92gl3bxR8kPRgt3pdeHFAnrLlS1u8mGondQVoAh6gn-KS-x4yoALPwyskHRl342T\"}";
const p384_thumbprint = "2VCJSNUJIQy7ZROopAJ0jVV6boMAShF-cexxKMd4IN0";

fn p384KeyPair() !*const Es384.KeyPair {
    const S = struct {
        var kp: Es384.KeyPair = undefined;
        var ready = false;
    };
    if (!S.ready) {
        var sk: Es384.SecretKey = undefined;
        _ = try std.fmt.hexToBytes(&sk.bytes, p384_d_hex);
        try Es384.KeyPair.fromSecretKeyInto(&S.kp, &sk);
        S.ready = true;
    }
    return &S.kp;
}

test "ES384: JWK, RFC 7638 thumbprint and key authorization against openssl + python" {
    const kp = try p384KeyPair();
    var buf: [max_canonical_jwk_len]u8 = undefined;
    try testing.expectEqualStrings(p384_canonical_jwk, canonicalJwk(&buf, kp.public_key));
    try testing.expectEqualStrings(p384_thumbprint, &thumbprintBase64(kp.public_key));
    // The same through the union.
    try testing.expectEqualStrings(p384_thumbprint, &thumbprintBase64(AnyPublicKey{ .es384 = kp.public_key }));
    var ka: [max_key_authorization_len]u8 = undefined;
    try testing.expectEqualStrings(
        "DGyRejmCefe7v4NfDGDKfA." ++ p384_thumbprint,
        try keyAuthorization(&ka, "DGyRejmCefe7v4NfDGDKfA", kp.public_key),
    );
    // P-256 stays what it was, through the same generic entry points.
    const k256 = try rfc7515KeyPair();
    try testing.expectEqualStrings("oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U", &thumbprintBase64(AnyPublicKey{ .es256 = k256.public_key }));
}

test "ES384: sign -> verifyFlattenedAny (jwk and kid), 96-byte signature, alg ES384, no nonce member when null" {
    const kp = try p384KeyPair();
    const jws_json = try sign(testing.allocator, kp, "{\"a\":1}", .{ .nonce = "n-384", .url = "https://ca.example/new-acct" });
    defer testing.allocator.free(jws_json);
    var v = try verifyFlattenedAny(testing.allocator, jws_json, null);
    defer v.deinit();
    try testing.expectEqual(Alg.es384, v.alg);
    try testing.expectEqualStrings("{\"a\":1}", v.payload);
    try testing.expectEqualStrings("n-384", v.nonce);
    try testing.expect(v.jwk_key.?.eql(.{ .es384 = kp.public_key }));
    // The header is exactly alg, the canonical jwk, nonce, url.
    const Flat = struct { protected: []const u8, signature: []const u8 };
    const flat = try std.json.parseFromSlice(Flat, testing.allocator, jws_json, .{ .ignore_unknown_fields = true });
    defer flat.deinit();
    const protected = try base64UrlDecodeAlloc(testing.allocator, flat.value.protected);
    defer testing.allocator.free(protected);
    try testing.expectEqualStrings(
        "{\"alg\":\"ES384\",\"jwk\":" ++ p384_canonical_jwk ++ ",\"nonce\":\"n-384\",\"url\":\"https://ca.example/new-acct\"}",
        protected,
    );
    const sig = try base64UrlDecodeAlloc(testing.allocator, flat.value.signature);
    defer testing.allocator.free(sig);
    try testing.expectEqual(@as(usize, 96), sig.len);

    // The ES256-only verifier refuses it by name; a P-256 key cannot stand in for the P-384 one.
    try testing.expectError(error.UnsupportedJws, verifyFlattened(testing.allocator, jws_json, null));
    const k256 = try rfc7515KeyPair();
    try testing.expectError(error.UnsupportedJws, verifyFlattenedAny(testing.allocator, jws_json, .{ .es256 = k256.public_key }));

    // kid mode through an AnyKeyPair, deterministic, and no nonce member when null.
    const any: AnyKeyPair = .{ .es384 = kp.* };
    const kid1 = try sign(testing.allocator, &any, "", .{ .nonce = null, .url = "https://ca.example/x", .kid = "https://ca.example/acct/1" });
    defer testing.allocator.free(kid1);
    const kid2 = try sign(testing.allocator, kp, "", .{ .nonce = null, .url = "https://ca.example/x", .kid = "https://ca.example/acct/1" });
    defer testing.allocator.free(kid2);
    try testing.expectEqualStrings(kid1, kid2);
    var v2 = try verifyFlattenedAny(testing.allocator, kid1, .{ .es384 = kp.public_key });
    defer v2.deinit();
    try testing.expectEqualStrings("", v2.nonce);
    try testing.expectEqualStrings("https://ca.example/acct/1", v2.kid.?);
    // Another P-384 key does not verify it.
    const other = try Es384.KeyPair.generateDeterministic(@splat(9));
    try testing.expectError(error.BadSignature, verifyFlattenedAny(testing.allocator, kid1, .{ .es384 = other.public_key }));
    // A 64-byte signature under alg ES384 is malformed (RFC 7518 §3.4).
    const short = try craftJwsAlg(testing.allocator, "ES384", kp.public_key, 64);
    defer testing.allocator.free(short);
    try testing.expectError(error.MalformedJws, verifyFlattenedAny(testing.allocator, short, null));
}

/// A flattened JWS under `alg` whose "signature" is `sig_len` zero bytes —
/// only its length matters for the check above.
fn craftJwsAlg(gpa: std.mem.Allocator, alg: []const u8, public_key: Es384.PublicKey, sig_len: usize) ![]u8 {
    var jwk_buf: [max_canonical_jwk_len]u8 = undefined;
    const jwk = canonicalJwk(&jwk_buf, public_key);
    const protected = try std.fmt.allocPrint(gpa, "{{\"alg\":\"{s}\",\"jwk\":{s},\"nonce\":\"n\",\"url\":\"u\"}}", .{ alg, jwk });
    defer gpa.free(protected);
    const p64 = try base64UrlEncodeAlloc(gpa, protected);
    defer gpa.free(p64);
    const zeros = try gpa.alloc(u8, sig_len);
    defer gpa.free(zeros);
    @memset(zeros, 0);
    const s64 = try base64UrlEncodeAlloc(gpa, zeros);
    defer gpa.free(s64);
    return std.fmt.allocPrint(gpa, "{{\"protected\":\"{s}\",\"payload\":\"\",\"signature\":\"{s}\"}}", .{ p64, s64 });
}

test "generateAnyKeyPair: both curves draw entropy and sign" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ Alg.es256, Alg.es384, Alg.es512 }) |alg| {
        var a: AnyKeyPair = undefined;
        var b: AnyKeyPair = undefined;
        generateAnyKeyPair(&a, alg, io);
        generateAnyKeyPair(&b, alg, io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&a));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&b));
        try testing.expectEqual(alg, a.alg());
        try testing.expect(!a.publicKey().eql(b.publicKey()));
        const out = try sign(testing.allocator, &a, "{}", .{ .nonce = "n", .url = "https://ca.example/x" });
        defer testing.allocator.free(out);
        var v = try verifyFlattenedAny(testing.allocator, out, null);
        v.deinit();
    }
}

test "Alg and AnyPublicKey bookkeeping" {
    try testing.expectEqualStrings("ES384", Alg.es384.name());
    try testing.expectEqualStrings("P-384", Alg.es384.crv());
    try testing.expectEqual(@as(usize, 96), Alg.es384.sigLen());
    try testing.expectEqual(@as(usize, 64), Alg.es256.sigLen());
    try testing.expectEqual(@as(?Alg, .es256), Alg.fromName("ES256"));
    try testing.expectEqual(@as(?Alg, null), Alg.fromName("ES256K"));
    try testing.expectEqual(@as(?Alg, null), Alg.fromName("es256"));
    try testing.expect(!(AnyPublicKey{ .es256 = (try rfc7515KeyPair()).public_key }).eql(.{ .es384 = (try p384KeyPair()).public_key }));
    try testing.expectEqualStrings("ES512", Alg.es512.name());
    try testing.expectEqualStrings("P-521", Alg.es512.crv());
    try testing.expectEqual(@as(usize, 66), Alg.es512.coordLen());
    try testing.expectEqual(@as(usize, 132), Alg.es512.sigLen());
    try testing.expectEqual(@as(?Alg, .es512), Alg.fromName("ES512"));
    try testing.expectEqual(@as(?Alg, null), Alg.fromName("es512"));
    try testing.expect(!(AnyPublicKey{ .es384 = (try p384KeyPair()).public_key }).eql(.{ .es512 = (try p521KeyPair()).public_key }));
    try testing.expectEqual(Alg.es512, algOf(Es512.KeyPair));
    try testing.expectEqual(@as(usize, 133), (try p521KeyPair()).public_key.toUncompressedSec1().len);
}

// ── ES512 (2026-10-16) ──────────────────────────────────────────────────────

// A throwaway P-521 key (the same key as x509.zig's PKCS#8 fixture), made with
//   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out k.pkcs8.pem
// and its scalar read back with
//   openssl ec -in k.pkcs8.pem -text -noout   (the `priv:` block, 66 bytes).
const p521_d_hex = "0083913efb00f857a280618efa0ccf12f1239aa873ecd2bcd8ba0f2c1151150c556dbb9f9a5818b13dcca7aa9906d98f685d2c2162fa7780fec27ef6214395212279";
// Oracle: python3 -I (hashlib, base64) over the last 133 bytes of
//   openssl pkey -in k.pkcs8.pem -pubout -outform DER
// (04 || X(66) || Y(66)): canonical JWK per RFC 7638, then
// base64url(SHA-256) of its bytes.
const p521_canonical_jwk = "{\"crv\":\"P-521\",\"kty\":\"EC\"," ++
    "\"x\":\"AOnWQyNjrh6pOja0XoTQ58LC0rigU_Sbx0ylxJpPRPpn-n9xpfpBZQzmO2lZ9rOx8P55quCuziKsIQ-1rl1Mwmhy\"," ++
    "\"y\":\"AB8t7jfRkWDJWqynLNIZ4IiK6Yp_S3TRBtff3gHQIaILzH2DnGqccTcAx9gTVQttwRtmY3fXdtNLWsvm84CsnNy9\"}";
const p521_thumbprint = "nRl-ZR2ZBULOBkcF9B_bG2TMCNglNTXj0MVWjG-GD-o";

fn p521KeyPair() !*const Es512.KeyPair {
    const S = struct {
        var kp: Es512.KeyPair = undefined;
        var ready = false;
    };
    if (!S.ready) {
        var sk: Es512.SecretKey = undefined;
        _ = try std.fmt.hexToBytes(&sk.bytes, p521_d_hex);
        try Es512.KeyPair.fromSecretKeyInto(&S.kp, &sk);
        S.ready = true;
    }
    return &S.kp;
}

test "ES512: JWK, RFC 7638 thumbprint and key authorization against openssl + python" {
    const kp = try p521KeyPair();
    var buf: [max_canonical_jwk_len]u8 = undefined;
    try testing.expectEqualStrings(p521_canonical_jwk, canonicalJwk(&buf, kp.public_key));
    try testing.expect(max_canonical_jwk_len >= p521_canonical_jwk.len);
    try testing.expectEqualStrings(p521_thumbprint, &thumbprintBase64(kp.public_key));
    try testing.expectEqualStrings(p521_thumbprint, &thumbprintBase64(AnyPublicKey{ .es512 = kp.public_key }));
    var ka: [max_key_authorization_len]u8 = undefined;
    try testing.expectEqualStrings(
        "DGyRejmCefe7v4NfDGDKfA." ++ p521_thumbprint,
        try keyAuthorization(&ka, "DGyRejmCefe7v4NfDGDKfA", kp.public_key),
    );
}

test "ES512: sign -> verifyFlattenedAny (jwk and kid), 132-byte signature, alg ES512, no nonce member when null" {
    const kp = try p521KeyPair();
    const jws_json = try sign(testing.allocator, kp, "{\"a\":1}", .{ .nonce = "n-521", .url = "https://ca.example/new-acct" });
    defer testing.allocator.free(jws_json);
    var v = try verifyFlattenedAny(testing.allocator, jws_json, null);
    defer v.deinit();
    try testing.expectEqual(Alg.es512, v.alg);
    try testing.expectEqualStrings("{\"a\":1}", v.payload);
    try testing.expectEqualStrings("n-521", v.nonce);
    try testing.expect(v.jwk_key.?.eql(.{ .es512 = kp.public_key }));
    const Flat = struct { protected: []const u8, signature: []const u8 };
    const flat = try std.json.parseFromSlice(Flat, testing.allocator, jws_json, .{ .ignore_unknown_fields = true });
    defer flat.deinit();
    const protected = try base64UrlDecodeAlloc(testing.allocator, flat.value.protected);
    defer testing.allocator.free(protected);
    try testing.expectEqualStrings(
        "{\"alg\":\"ES512\",\"jwk\":" ++ p521_canonical_jwk ++ ",\"nonce\":\"n-521\",\"url\":\"https://ca.example/new-acct\"}",
        protected,
    );
    const sig = try base64UrlDecodeAlloc(testing.allocator, flat.value.signature);
    defer testing.allocator.free(sig);
    try testing.expectEqual(@as(usize, 132), sig.len);

    // The ES256-only verifier refuses it by name; keys of the other curves cannot stand in.
    try testing.expectError(error.UnsupportedJws, verifyFlattened(testing.allocator, jws_json, null));
    const k256 = try rfc7515KeyPair();
    try testing.expectError(error.UnsupportedJws, verifyFlattenedAny(testing.allocator, jws_json, .{ .es256 = k256.public_key }));
    const k384 = try p384KeyPair();
    try testing.expectError(error.UnsupportedJws, verifyFlattenedAny(testing.allocator, jws_json, .{ .es384 = k384.public_key }));

    // kid mode through an AnyKeyPair, deterministic, and no nonce member when null.
    const any: AnyKeyPair = .{ .es512 = kp.* };
    const kid1 = try sign(testing.allocator, &any, "", .{ .nonce = null, .url = "https://ca.example/x", .kid = "https://ca.example/acct/1" });
    defer testing.allocator.free(kid1);
    const kid2 = try sign(testing.allocator, kp, "", .{ .nonce = null, .url = "https://ca.example/x", .kid = "https://ca.example/acct/1" });
    defer testing.allocator.free(kid2);
    try testing.expectEqualStrings(kid1, kid2);
    var v2 = try verifyFlattenedAny(testing.allocator, kid1, .{ .es512 = kp.public_key });
    defer v2.deinit();
    try testing.expectEqualStrings("", v2.nonce);
    try testing.expectEqualStrings("https://ca.example/acct/1", v2.kid.?);
    // Another P-521 key does not verify it.
    const other = try Es512.KeyPair.generateDeterministic(@splat(9));
    try testing.expectError(error.BadSignature, verifyFlattenedAny(testing.allocator, kid1, .{ .es512 = other.public_key }));
    // A 96-byte signature under alg ES512 is malformed (RFC 7518 §3.4).
    const short = try craftJwsAlgAny(testing.allocator, "ES512", .{ .es512 = kp.public_key }, 96);
    defer testing.allocator.free(short);
    try testing.expectError(error.MalformedJws, verifyFlattenedAny(testing.allocator, short, null));
    // A tampered payload fails the signature.
    const tampered = try testing.allocator.dupe(u8, jws_json);
    defer testing.allocator.free(tampered);
    const pay_at = std.mem.indexOf(u8, tampered, "\"payload\":\"").? + "\"payload\":\"".len;
    tampered[pay_at] = if (tampered[pay_at] == 'A') 'B' else 'A';
    try testing.expectError(error.BadSignature, verifyFlattenedAny(testing.allocator, tampered, null));
}

fn craftJwsAlgAny(gpa: std.mem.Allocator, alg: []const u8, public_key: AnyPublicKey, sig_len: usize) ![]u8 {
    var jwk_buf: [max_canonical_jwk_len]u8 = undefined;
    const jwk = canonicalJwk(&jwk_buf, public_key);
    const protected = try std.fmt.allocPrint(gpa, "{{\"alg\":\"{s}\",\"jwk\":{s},\"nonce\":\"n\",\"url\":\"u\"}}", .{ alg, jwk });
    defer gpa.free(protected);
    const p64 = try base64UrlEncodeAlloc(gpa, protected);
    defer gpa.free(p64);
    const zeros = try gpa.alloc(u8, sig_len);
    defer gpa.free(zeros);
    @memset(zeros, 0);
    const s64 = try base64UrlEncodeAlloc(gpa, zeros);
    defer gpa.free(s64);
    return std.fmt.allocPrint(gpa, "{{\"protected\":\"{s}\",\"payload\":\"\",\"signature\":\"{s}\"}}", .{ p64, s64 });
}

// ── RS256 (2026-10-16) ──────────────────────────────────────────────────────

// A throwaway RSA-2048 key (not a secret), made with
//   openssl genrsa -out k.pkcs8.pem 2048        (OpenSSL 3.5.5: PKCS#8 "PRIVATE KEY")
const rsa2048_pkcs8_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCFclHEPYa49gNd
    \\vBIPrMUfKEKaeE3xmM469V6sBhj5FHYgQcd0JgA5ZfpGMLWd8caTT8Pq/KjIS3cF
    \\ThcTD3o0sEmGUVdIH8NiZBkZcps4VuRLjB1oi619M8TG8qqOLaTDlmt3SOaj5oRS
    \\cRUzb2vFYAQwK6iylBY4Lg+vIL0pHb5NqzPiW4K9996mCKXP7HOD+bECsTmcDKeh
    \\/iDxibaumlA5ojkF245wyf+yhJkB5iFIVdV97+nyTVHDvtTHGkgv463kTZ1nNrMS
    \\YXoqO2mLK11BxT2K/JgHMsRbpQnvHKx/qZxx4Rz0edQglZkHAr6USor7Rkj/Wrlu
    \\znvKVeqjAgMBAAECggEALP62Xj5Gmj/tM6JRzrI5Bv/qsS3mThNxWgTY5pTpv7Zr
    \\/AVh7KJRigj+AcOzwS1AAPSwwR9vA5YabBIACr+5u2FDcUQk818uYJMSuXdgqfb2
    \\ZBi648DQ/vnBHDm/U1BFkWM7Gg3dIp97t1aEyQKFKphs4RcfexMeiNPTGwAld+Kg
    \\W/BdFgbQrzEKkxSzSVbZ+8hTGfd1Okfancr/tfaV4xdHFeVUVk/yWfjeKEHMmBGQ
    \\YbXmSB2cYypcQ1LMYWoyw8uWTzEihe3rrNZt8TcAMAG6osRYrjV+cXlnqUnv87oQ
    \\0Ei6WgAdpmKIIEtCUwfIZ0C6me4aq4sMOY7emc0igQKBgQC7amDC5++Pj92r/oFI
    \\i/mn+0vyIkzoEVPkYo+TeImJk38owRbPZ58shX+pEL+iM40XbGa9+MrqExTmApSv
    \\s2ugZGtxGRim7CnihMB1SzWma85lD2lshK7vJ0vGgpCQGtCShJi6+fSZE1uyQZGT
    \\5niFOxSdmmJZA13cbHEik1zDgQKBgQC2R/k/VnFRL8kMKWk6OGQI7tZu/RfTf/hK
    \\U9H1Ng8a8END6Pvmgj+8BcVtgU2JLDgqpbf1dztvEUywkr+fvg5zLPuGBPtmcAQX
    \\BZ0j/h+HRjJ2YXyaS90UmSp6gxs9HzM0blqSTLBgJTZcvJYbE86HspNy87GBtenJ
    \\FO8ww38wIwKBgQCzYH+4TNFnMKVUJ0WKMB8FfmoUGGxPebY303XkCexp9vgwA49X
    \\d7BLpoKnSFaCYqDaGHDFxsg//X91Hmc9O5b5buO+3exQZ503JyQln5R78pca9wNK
    \\UDw2vf+yweinZGLYuXyNCQvpLzQGiudRDbewnPmAVvFmjOhbPpeSJkUVAQKBgBHj
    \\CCtV8TK1TLY7zg6ff/l8bmBfx5nCgfvRM9YrItpS31bnouhguZ5atp/jQ1eFllFh
    \\B6c3twZUHUFqdRFY1hQpQtlI3d6UeWJE88GXa0Kb+dGyCUce0Kf3y7pP6TlbOWwY
    \\tByNF/WnUSlSfCxWCjs4o81w6mc/EZzgyAPx+yYfAoGAOuKqYZUlQf6qESwycemd
    \\vWdplgQS86KELyJe4+i1vDSc7nEV4vLfw19Fq1RnPFbQyU/VBTi0yHnZm0VIm12F
    \\SfARyPbKN2wXy61GVGk8KjO7iKAa8ChCp9ZrtD3qErzG4ixRU/dxc5/zJgPY4HBO
    \\nKhgr4xUe9OqdoSafb5oCtM=
    \\-----END PRIVATE KEY-----
    \\
;
// Oracle: python3 -I over `openssl pkey -in k.pkcs8.pem -pubout -outform DER`
// (SPKI -> BIT STRING -> RSAPublicKey -> n, e parsed by hand): the RFC 7518
// §6.3.1 canonical JWK (base64url of the unsigned big-endian n, e without
// leading zeros), then base64url(SHA-256) of its bytes (RFC 7638).
const rsa2048_canonical_jwk = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"" ++
    "hXJRxD2GuPYDXbwSD6zFHyhCmnhN8ZjOOvVerAYY-RR2IEHHdCYAOWX6RjC1nfHG" ++
    "k0_D6vyoyEt3BU4XEw96NLBJhlFXSB_DYmQZGXKbOFbkS4wdaIutfTPExvKqji2k" ++
    "w5Zrd0jmo-aEUnEVM29rxWAEMCuospQWOC4PryC9KR2-Tasz4luCvffepgilz-xz" ++
    "g_mxArE5nAynof4g8Ym2rppQOaI5BduOcMn_soSZAeYhSFXVfe_p8k1Rw77UxxpI" ++
    "L-Ot5E2dZzazEmF6KjtpiytdQcU9ivyYBzLEW6UJ7xysf6mcceEc9HnUIJWZBwK-" ++
    "lEqK-0ZI_1q5bs57ylXqow" ++
    "\"}";
const rsa2048_thumbprint = "vQHIXQi7n2ktWvrJlhbhcbN48NXARhKToNoXv9CAXwk";
// `openssl dgst -sha256 -sign k.pkcs8.pem input.txt` where input.txt holds the
// JWS signing input of the "RS256: sign" test below (no trailing newline):
//   BASE64URL({"alg":"RS256","jwk":<canonical JWK>,"nonce":"n-rsa","url":"https://ca.example/new-acct"})
//   ++ "." ++ BASE64URL({"a":1})
// PKCS#1 v1.5 is deterministic, so the signature must be byte-identical.
const rsa2048_openssl_signature = "Rsm_tEGijDzpkQhd_DWe5LsuESwJy3xnzJDL59Xtfa14Wc262KXYLF0yf6AzJbAz" ++
    "dQEsS62m5Iyp6ccfmuAPuQasNutXbWQfi134WtW55XJ7WnEtxI9uByWm_VZLMTL7" ++
    "9M_NDWDzb00cyMApprf_UMTkwIjkXnPR8ot4LThYLKlsdcbxYw2sltq7XYWxJPnj" ++
    "YrLpiilr-Xq5q2Un0TLHbURl8AgxEQY6wDbMT9HUScwF8Vy6mnDReU1tQXHKEgHq" ++
    "hcev2Zzha7eGbu1EFDqvArKrDUgGKc41aAlYNr3RsXXOu5dK3sz_pl8uO8ZzDC9b" ++
    "LsSsOdYS55gh2PrOBJBUNA";

fn rsa2048KeyPair() !*const rsa.KeyPair {
    const S = struct {
        var kp: rsa.KeyPair = undefined;
        var ready = false;
    };
    if (!S.ready) {
        try rsa.SecretKey.fromPem(&S.kp.secret_key, rsa2048_pkcs8_pem);
        S.kp.public_key = S.kp.secret_key.publicKey();
        S.ready = true;
    }
    return &S.kp;
}

test "RS256: JWK, RFC 7638 thumbprint and key authorization against openssl + python" {
    const kp = try rsa2048KeyPair();
    const vk = kp.public_key.verifyKey();
    var buf: [max_canonical_jwk_len]u8 = undefined;
    try testing.expectEqualStrings(rsa2048_canonical_jwk, canonicalJwk(&buf, vk));
    try testing.expectEqualStrings(rsa2048_canonical_jwk, canonicalJwk(&buf, kp.public_key));
    try testing.expectEqualStrings(rsa2048_canonical_jwk, canonicalJwk(&buf, AnyPublicKey{ .rs256 = vk }));
    try testing.expectEqualStrings(rsa2048_canonical_jwk, canonicalJwk(&buf, publicOfPair(kp)));
    try testing.expectEqualStrings(rsa2048_thumbprint, &thumbprintBase64(vk));
    try testing.expectEqualStrings(rsa2048_thumbprint, &thumbprintBase64(kp.public_key));
    var ka: [max_key_authorization_len]u8 = undefined;
    try testing.expectEqualStrings(
        "DGyRejmCefe7v4NfDGDKfA." ++ rsa2048_thumbprint,
        try keyAuthorization(&ka, "DGyRejmCefe7v4NfDGDKfA", vk),
    );
    // The buffer bound covers the largest key `rsa` accepts (1024-octet modulus), 4096 bits included.
    try testing.expect(max_canonical_jwk_len >= "{\"e\":\"\",\"kty\":\"RSA\",\"n\":\"\"}".len + 6 + base64UrlLen(512));
    try testing.expect(max_canonical_jwk_len >= p521_canonical_jwk.len);
}

test "RS256: sign -> verifyFlattenedAny (jwk and kid); signature byte-identical to openssl" {
    const kp = try rsa2048KeyPair();
    const jws_json = try sign(testing.allocator, kp, "{\"a\":1}", .{ .nonce = "n-rsa", .url = "https://ca.example/new-acct" });
    defer testing.allocator.free(jws_json);
    var v = try verifyFlattenedAny(testing.allocator, jws_json, null);
    defer v.deinit();
    try testing.expectEqual(Alg.rs256, v.alg);
    try testing.expectEqualStrings("{\"a\":1}", v.payload);
    try testing.expectEqualStrings("n-rsa", v.nonce);
    try testing.expect(v.jwk_key.?.eql(publicOfPair(kp)));
    const Flat = struct { protected: []const u8, signature: []const u8 };
    const flat = try std.json.parseFromSlice(Flat, testing.allocator, jws_json, .{ .ignore_unknown_fields = true });
    defer flat.deinit();
    const protected = try base64UrlDecodeAlloc(testing.allocator, flat.value.protected);
    defer testing.allocator.free(protected);
    try testing.expectEqualStrings(
        "{\"alg\":\"RS256\",\"jwk\":" ++ rsa2048_canonical_jwk ++ ",\"nonce\":\"n-rsa\",\"url\":\"https://ca.example/new-acct\"}",
        protected,
    );
    // PKCS#1 v1.5 is deterministic: openssl's signature over the same input.
    try testing.expectEqualStrings(rsa2048_openssl_signature, flat.value.signature);
    const sig = try base64UrlDecodeAlloc(testing.allocator, flat.value.signature);
    defer testing.allocator.free(sig);
    try testing.expectEqual(@as(usize, 256), sig.len);

    // The ES256-only verifier refuses it by name; an EC key cannot stand in.
    try testing.expectError(error.UnsupportedJws, verifyFlattened(testing.allocator, jws_json, null));
    const k256 = try rfc7515KeyPair();
    try testing.expectError(error.UnsupportedJws, verifyFlattenedAny(testing.allocator, jws_json, .{ .es256 = k256.public_key }));

    // kid mode through an AnyKeyPair (a borrowed pointer), deterministic, no nonce member when null.
    const any: AnyKeyPair = .{ .rs256 = kp };
    const kid1 = try sign(testing.allocator, &any, "", .{ .nonce = null, .url = "https://ca.example/x", .kid = "https://ca.example/acct/1" });
    defer testing.allocator.free(kid1);
    const kid2 = try sign(testing.allocator, kp, "", .{ .nonce = null, .url = "https://ca.example/x", .kid = "https://ca.example/acct/1" });
    defer testing.allocator.free(kid2);
    try testing.expectEqualStrings(kid1, kid2);
    var v2 = try verifyFlattenedAny(testing.allocator, kid1, publicOfPair(kp));
    defer v2.deinit();
    try testing.expectEqualStrings("", v2.nonce);
    try testing.expectEqualStrings("https://ca.example/acct/1", v2.kid.?);
    try testing.expect(v2.jwk_key == null);

    // Another modulus (one middle byte flipped: still a well-formed odd 2048-bit n) does not verify it.
    var n_buf: [rsa.max_modulus_len]u8 = undefined;
    var e_buf: [4]u8 = undefined;
    const parts = RsaParts.of(&kp.public_key.verifyKey(), &n_buf, &e_buf);
    var other_n: [256]u8 = undefined;
    @memcpy(&other_n, parts.n);
    other_n[100] ^= 0x40;
    const other = try rsa.VerifyKey.fromBytes(&other_n, parts.e);
    try testing.expectError(error.BadSignature, verifyFlattenedAny(testing.allocator, kid1, .{ .rs256 = other }));

    // A tampered payload fails the signature.
    const tampered = try testing.allocator.dupe(u8, jws_json);
    defer testing.allocator.free(tampered);
    const pay_at = std.mem.indexOf(u8, tampered, "\"payload\":\"").? + "\"payload\":\"".len;
    tampered[pay_at] = if (tampered[pay_at] == 'A') 'B' else 'A';
    try testing.expectError(error.BadSignature, verifyFlattenedAny(testing.allocator, tampered, null));
}

test "RS256: malformed signatures and JWKs are refused at the right layer" {
    const kp = try rsa2048KeyPair();
    const pk = publicOfPair(kp);
    // A signature that is not one modulus long (RFC 7518 §3.3), however plausible otherwise.
    const short = try craftJwsAlgAny(testing.allocator, "RS256", pk, 255);
    defer testing.allocator.free(short);
    try testing.expectError(error.MalformedJws, verifyFlattenedAny(testing.allocator, short, null));
    const ec_len = try craftJwsAlgAny(testing.allocator, "RS256", pk, 64); // an ECDSA length is no RS256 length
    defer testing.allocator.free(ec_len);
    try testing.expectError(error.MalformedJws, verifyFlattenedAny(testing.allocator, ec_len, null));
    // Right length, wrong bytes: reaches the verifier.
    const zeros = try craftJwsAlgAny(testing.allocator, "RS256", pk, 256);
    defer testing.allocator.free(zeros);
    try testing.expectError(error.BadSignature, verifyFlattenedAny(testing.allocator, zeros, null));
    // A non-ECDSA length under an unknown alg stays MalformedJws (the order the ES paths always had).
    const unknown_alg = try craftJwsAlgAny(testing.allocator, "RS512", pk, 256);
    defer testing.allocator.free(unknown_alg);
    try testing.expectError(error.MalformedJws, verifyFlattenedAny(testing.allocator, unknown_alg, null));
    const unknown_alg_ec = try craftJwsAlgAny(testing.allocator, "RS512", pk, 64);
    defer testing.allocator.free(unknown_alg_ec);
    try testing.expectError(error.UnsupportedJws, verifyFlattenedAny(testing.allocator, unknown_alg_ec, null));

    // kty must match the alg's family.
    var jwk_buf: [max_canonical_jwk_len]u8 = undefined;
    const rsa_jwk = canonicalJwk(&jwk_buf, pk);
    const wrong_kty = try craftJwsRaw(testing.allocator, "RS256", "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"AA\",\"y\":\"AA\"}", 256);
    defer testing.allocator.free(wrong_kty);
    try testing.expectError(error.UnsupportedJws, verifyFlattenedAny(testing.allocator, wrong_kty, null));
    const ec_alg_rsa_jwk = try craftJwsRaw(testing.allocator, "ES256", rsa_jwk, 64);
    defer testing.allocator.free(ec_alg_rsa_jwk);
    try testing.expectError(error.UnsupportedJws, verifyFlattenedAny(testing.allocator, ec_alg_rsa_jwk, null));

    // JWK integers must be minimal (RFC 7518 §6.3.1.1): a leading zero octet in n or e.
    var n_buf: [rsa.max_modulus_len]u8 = undefined;
    var e_buf: [4]u8 = undefined;
    const parts = RsaParts.of(&pk.rs256, &n_buf, &e_buf);
    var padded: [257]u8 = undefined;
    padded[0] = 0;
    @memcpy(padded[1..], parts.n);
    const padded_b64 = try base64UrlEncodeAlloc(testing.allocator, &padded);
    defer testing.allocator.free(padded_b64);
    const lead_n = try std.fmt.allocPrint(testing.allocator, "{{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"{s}\"}}", .{padded_b64});
    defer testing.allocator.free(lead_n);
    const j1 = try craftJwsRaw(testing.allocator, "RS256", lead_n, 256);
    defer testing.allocator.free(j1);
    try testing.expectError(error.MalformedJws, verifyFlattenedAny(testing.allocator, j1, null));
    const n_b64 = try base64UrlEncodeAlloc(testing.allocator, parts.n);
    defer testing.allocator.free(n_b64);
    const lead_e = try std.fmt.allocPrint(testing.allocator, "{{\"e\":\"AAEAAQ\",\"kty\":\"RSA\",\"n\":\"{s}\"}}", .{n_b64});
    defer testing.allocator.free(lead_e);
    const j2 = try craftJwsRaw(testing.allocator, "RS256", lead_e, 256);
    defer testing.allocator.free(j2);
    try testing.expectError(error.MalformedJws, verifyFlattenedAny(testing.allocator, j2, null));

    // Key sizes outside 2048..4096 are refused: 1024 bits (odd n, top bit set) ...
    var small: [128]u8 = @splat(0xc3);
    small[127] = 0x01;
    const small_b64 = try base64UrlEncodeAlloc(testing.allocator, &small);
    defer testing.allocator.free(small_b64);
    const small_jwk = try std.fmt.allocPrint(testing.allocator, "{{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"{s}\"}}", .{small_b64});
    defer testing.allocator.free(small_jwk);
    const j3 = try craftJwsRaw(testing.allocator, "RS256", small_jwk, 128);
    defer testing.allocator.free(j3);
    try testing.expectError(error.MalformedJws, verifyFlattenedAny(testing.allocator, j3, null));
    // ... and 8192 bits, which `rsa` accepts but no ACME CA does.
    var big: [1024]u8 = @splat(0xc3);
    big[1023] = 0x01;
    const big_b64 = try base64UrlEncodeAlloc(testing.allocator, &big);
    defer testing.allocator.free(big_b64);
    const big_jwk = try std.fmt.allocPrint(testing.allocator, "{{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"{s}\"}}", .{big_b64});
    defer testing.allocator.free(big_jwk);
    const j4 = try craftJwsRaw(testing.allocator, "RS256", big_jwk, 1024);
    defer testing.allocator.free(j4);
    try testing.expectError(error.MalformedJws, verifyFlattenedAny(testing.allocator, j4, null));
}

/// A JWS with a caller-written JWK member and an all-zero signature.
fn craftJwsRaw(gpa: std.mem.Allocator, alg: []const u8, jwk_json: []const u8, sig_len: usize) ![]u8 {
    const protected = try std.fmt.allocPrint(gpa, "{{\"alg\":\"{s}\",\"jwk\":{s},\"nonce\":\"n\",\"url\":\"u\"}}", .{ alg, jwk_json });
    defer gpa.free(protected);
    const p64 = try base64UrlEncodeAlloc(gpa, protected);
    defer gpa.free(p64);
    const zeros = try gpa.alloc(u8, sig_len);
    defer gpa.free(zeros);
    @memset(zeros, 0);
    const s64 = try base64UrlEncodeAlloc(gpa, zeros);
    defer gpa.free(s64);
    return std.fmt.allocPrint(gpa, "{{\"protected\":\"{s}\",\"payload\":\"\",\"signature\":\"{s}\"}}", .{ p64, s64 });
}

test "RS256: Alg and AnyPublicKey/AnyKeyPair bookkeeping" {
    try testing.expectEqualStrings("RS256", Alg.rs256.name());
    try testing.expectEqual(@as(?Alg, .rs256), Alg.fromName("RS256"));
    try testing.expectEqual(@as(?Alg, null), Alg.fromName("rs256"));
    try testing.expectEqual(@as(?Alg, null), Alg.fromName("RS384"));
    try testing.expectEqual(@as(?Alg, null), Alg.fromName("PS256"));
    try testing.expect(!Alg.rs256.isEc());
    try testing.expect(Alg.es512.isEc());
    try testing.expectEqual(Alg.rs256, algOf(rsa.KeyPair));
    try testing.expectEqual(Alg.rs256, algOf(rsa.PublicKey));
    try testing.expectEqual(Alg.rs256, algOf(rsa.VerifyKey));

    const kp = try rsa2048KeyPair();
    const any: AnyKeyPair = .{ .rs256 = kp };
    try testing.expectEqual(Alg.rs256, any.alg());
    try testing.expect(any.publicKey().eql(publicOfPair(kp)));
    try testing.expect(any.publicKey().eql(anyPublic(kp.public_key)));
    try testing.expect(any.publicKey().eql(anyPublic(kp.public_key.verifyKey())));
    try testing.expect(!any.publicKey().eql(.{ .es256 = (try rfc7515KeyPair()).public_key }));

    // copyPairInto stores the POINTER (the pair is not copied); from an AnyKeyPair likewise.
    var out: AnyKeyPair = undefined;
    copyPairInto(&out, kp);
    try testing.expectEqual(@intFromPtr(kp), @intFromPtr(out.rs256));
    var out2: AnyKeyPair = undefined;
    copyPairInto(&out2, &out);
    try testing.expectEqual(@intFromPtr(kp), @intFromPtr(out2.rs256));
    // The union stays small: the RSA arm is a pointer.
    try testing.expect(@sizeOf(AnyKeyPair) < 1024);
}

test "generateRsaKeyPair: refuses sizes other than 2048/3072/4096; one real 2048 key signs and verifies" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var kp: rsa.KeyPair = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
    for ([_]u16{ 0, 512, 1024, 2047, 2049, 2560, 8192 }) |bad| {
        @memset(std.mem.asBytes(&kp), 0xaa);
        try testing.expectError(error.InvalidBits, generateRsaKeyPair(&kp, bad, io));
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&kp), 0)); // zeroed on error
    }

    try generateRsaKeyPair(&kp, 2048, io);
    try testing.expectEqual(@as(usize, 2048), kp.public_key.bits());
    try testing.expectEqual(@as(usize, 2048), kp.secret_key.publicKey().bits());
    const out = try sign(testing.allocator, &kp, "{}", .{ .nonce = "n", .url = "https://ca.example/x" });
    defer testing.allocator.free(out);
    var v = try verifyFlattenedAny(testing.allocator, out, null);
    defer v.deinit();
    try testing.expectEqual(Alg.rs256, v.alg);
    try testing.expect(v.jwk_key.?.eql(publicOfPair(&kp)));
    // It is not the fixture key.
    try testing.expect(!v.jwk_key.?.eql(publicOfPair(try rsa2048KeyPair())));
}
