// SPDX-License-Identifier: MIT

//! JOSE building blocks for ACME: base64url (no padding), ES256 JWS in the
//! flattened JSON serialization (RFC 7515 §7.2.2), P-256 JWK rendering, the
//! RFC 7638 JWK thumbprint and the RFC 8555 §8.1 key authorization.
//!
//! Everything here is pure and offline-testable: signing is deterministic
//! (std's RFC 6979-style nonce derivation — `KeyPair.sign` with null noise),
//! so the same key + header + payload always produce the same JWS.
//! `verifyFlattened` is the server-side half — used by the mock-ACME
//! integration test to check every JWS the client sends.

const std = @import("std");
const entropy = @import("entropy");
const burn = @import("burn.zig");

/// The one JWS algorithm ACME accounts use here: ECDSA P-256 + SHA-256, over
/// p256's burned wrapper rather than std's signer (which leaves the private
/// key and the nonce on the dead stack after every signature — measured
/// 2026-10-08, `stackprobe_test.zig`).
pub const Es256 = @import("p256").EcdsaP256Sha256;
pub const KeyPair = Es256.KeyPair;

/// ECDSA P-384 + SHA-384 (ES384), over the `p384` module's burned signer
/// (std's leaves the key on the dead stack, same as std's P-256).
pub const Es384 = @import("p384").EcdsaP384Sha384;

/// The JWS algorithms an ACME account or certificate key can use here.
/// RSA is not supported (see SPEC "Backlog").
pub const Alg = enum {
    es256,
    es384,

    /// The JOSE `alg` name (RFC 7518 §3.1).
    pub fn name(a: Alg) []const u8 {
        return switch (a) {
            .es256 => "ES256",
            .es384 => "ES384",
        };
    }

    /// The JWK `crv` (RFC 7518 §6.2.1.1).
    pub fn crv(a: Alg) []const u8 {
        return switch (a) {
            .es256 => "P-256",
            .es384 => "P-384",
        };
    }

    /// Octets of one affine coordinate, and of one scalar.
    pub fn coordLen(a: Alg) usize {
        return switch (a) {
            .es256 => 32,
            .es384 => 48,
        };
    }

    /// Octets of a JWS signature, `R ‖ S` (RFC 7518 §3.4).
    pub fn sigLen(a: Alg) usize {
        return 2 * a.coordLen();
    }

    pub fn fromName(s: []const u8) ?Alg {
        if (std.mem.eql(u8, s, "ES256")) return .es256;
        if (std.mem.eql(u8, s, "ES384")) return .es384;
        return null;
    }
};

/// Which algorithm a key-pair or public-key type belongs to.
pub fn algOf(comptime T: type) Alg {
    return switch (T) {
        Es256.KeyPair, Es256.PublicKey => .es256,
        Es384.KeyPair, Es384.PublicKey => .es384,
        else => @compileError("not an acme key type: " ++ @typeName(T)),
    };
}

/// A public key of either supported curve.
pub const AnyPublicKey = union(Alg) {
    es256: Es256.PublicKey,
    es384: Es384.PublicKey,

    pub fn alg(k: AnyPublicKey) Alg {
        return std.meta.activeTag(k);
    }

    /// Longest uncompressed SEC1 point (P-384: `04 ‖ X(48) ‖ Y(48)`).
    pub const max_sec1_len = 97;

    /// `04 ‖ X ‖ Y` into `buf`; the returned slice is its prefix.
    pub fn uncompressedSec1(k: AnyPublicKey, buf: *[max_sec1_len]u8) []const u8 {
        switch (k) {
            inline else => |pk| {
                const s = pk.toUncompressedSec1();
                @memcpy(buf[0..s.len], &s);
                return buf[0..s.len];
            },
        }
    }

    /// Same curve and same point (public data, so a plain comparison).
    pub fn eql(a: AnyPublicKey, b: AnyPublicKey) bool {
        if (a.alg() != b.alg()) return false;
        var ab: [max_sec1_len]u8 = undefined;
        var bb: [max_sec1_len]u8 = undefined;
        return std.mem.eql(u8, a.uncompressedSec1(&ab), b.uncompressedSec1(&bb));
    }
};

/// A key pair of either supported curve — what `Client` holds. Holds a
/// private key: wipe it with `std.crypto.secureZero(u8, std.mem.asBytes(&k))`.
pub const AnyKeyPair = union(Alg) {
    es256: Es256.KeyPair,
    es384: Es384.KeyPair,

    pub fn alg(k: *const AnyKeyPair) Alg {
        return std.meta.activeTag(k.*);
    }

    pub fn publicKey(k: *const AnyKeyPair) AnyPublicKey {
        return switch (k.*) {
            .es256 => |*kp| .{ .es256 = kp.public_key },
            .es384 => |*kp| .{ .es384 = kp.public_key },
        };
    }
};

/// View any supported public key as an `AnyPublicKey`.
pub fn anyPublic(pk: anytype) AnyPublicKey {
    return switch (@TypeOf(pk)) {
        AnyPublicKey => pk,
        Es256.PublicKey => .{ .es256 = pk },
        Es384.PublicKey => .{ .es384 = pk },
        else => @compileError("not an acme public key: " ++ @typeName(@TypeOf(pk))),
    };
}

/// The public half of a pointer to any supported key pair.
pub fn publicOfPair(key_pair: anytype) AnyPublicKey {
    return switch (@TypeOf(key_pair.*)) {
        AnyKeyPair => key_pair.publicKey(),
        Es256.KeyPair => .{ .es256 = key_pair.public_key },
        Es384.KeyPair => .{ .es384 = key_pair.public_key },
        else => @compileError("not an acme key pair: " ++ @typeName(@TypeOf(key_pair.*))),
    };
}

/// Copy the pair behind `key_pair` (a pointer to either curve's pair or to an
/// `AnyKeyPair`) into `out`. The copy is a second resident private key: the
/// caller wipes it.
pub fn copyPairInto(out: *AnyKeyPair, key_pair: anytype) void {
    switch (@TypeOf(key_pair.*)) {
        AnyKeyPair => out.* = key_pair.*,
        Es256.KeyPair => out.* = .{ .es256 = key_pair.* },
        Es384.KeyPair => out.* = .{ .es384 = key_pair.* },
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

/// `generateKeyPair` for a chosen curve, into an `AnyKeyPair` (ES384 account
/// and certificate keys). Same entropy path and burn.
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
    }
    burn.stack(burn.key_burn);
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

/// Length of the longest canonical JWK (P-384: 64-character coordinates).
pub const max_canonical_jwk_len = "{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"\",\"y\":\"\"}".len + 2 * 64;

/// The canonical JWK of a public key (`Es256.PublicKey`, `Es384.PublicKey` or
/// `AnyPublicKey`): required members only, in lexicographic order, no
/// whitespace — the exact byte sequence RFC 7638 hashes. `buf` must hold
/// `max_canonical_jwk_len` bytes (`canonical_jwk_len` suffices for P-256).
pub fn canonicalJwk(buf: []u8, public_key: anytype) []const u8 {
    const pk = anyPublic(public_key);
    var sec1_buf: [AnyPublicKey.max_sec1_len]u8 = undefined;
    const sec1 = pk.uncompressedSec1(&sec1_buf); // 0x04 ‖ X ‖ Y
    const n = pk.alg().coordLen();
    var xb: [64]u8 = undefined;
    var yb: [64]u8 = undefined;
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
/// (ES256 or ES384); `kid` null embeds the signer's `jwk` instead
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
/// `Es256.KeyPair`, an `Es384.KeyPair` or an `AnyKeyPair`. Caller owns the
/// returned JSON.
pub fn sign(
    gpa: std.mem.Allocator,
    key_pair: anytype,
    payload: []const u8,
    header: Header,
) SignError![]u8 {
    if (comptime @TypeOf(key_pair.*) == AnyKeyPair) {
        return switch (key_pair.*) {
            inline else => |*kp| signTyped(gpa, kp, payload, header),
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
            writeProtected(&js, anyPublic(key_pair.public_key), header) catch return error.OutOfMemory;
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
    const sig = key_pair.sign(input, null) catch return error.SigningFailed;
    const sig_bytes = sig.toBytes(); // r ‖ s: 64 bytes (ES256) or 96 (ES384)
    var sig_b64_buf: [base64UrlLen(96)]u8 = undefined;
    const sig_b64 = b64.Encoder.encode(&sig_b64_buf, &sig_bytes);

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
    /// alg is not ES256, or jwk/kid are missing/both present.
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
/// ES384 JWS answers `UnsupportedJws` (see `verifyFlattenedAny`).
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

/// `verifyFlattened` for ES256 and ES384: the header's `alg` picks the curve,
/// the embedded jwk must be on it, and an `expected_key` must be too.
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
    if (sig_bytes.len != Alg.es256.sigLen() and sig_bytes.len != Alg.es384.sigLen())
        return error.MalformedJws;

    const head = std.json.parseFromSliceLeaky(ProtectedJson, a, protected, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedJws,
    };
    const alg = Alg.fromName(head.alg) orelse return error.UnsupportedJws;
    if ((head.kid == null) == (head.jwk == null)) return error.UnsupportedJws; // exactly one

    var jwk_key: ?AnyPublicKey = null;
    if (head.jwk) |jwk| {
        if (!std.mem.eql(u8, jwk.kty, "EC") or !std.mem.eql(u8, jwk.crv, alg.crv()))
            return error.UnsupportedJws;
        jwk_key = publicKeyFromCoords(a, alg, jwk.x, jwk.y) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MalformedJws,
        };
    }
    const key = expected_key orelse (jwk_key orelse return error.UnsupportedJws);
    if (key.alg() != alg) return error.UnsupportedJws; // a key of another curve cannot verify it
    if (sig_bytes.len != alg.sigLen()) return error.MalformedJws; // RFC 7518 §3.4: exactly R ‖ S

    // Verify over the exact base64url text from the wire.
    const input = std.mem.concat(a, u8, &.{ flat.protected, ".", flat.payload }) catch
        return error.OutOfMemory;
    switch (key) {
        .es256 => |k| Es256.Signature.fromBytes(sig_bytes[0..64].*).verify(input, k) catch return error.BadSignature,
        .es384 => |k| Es384.Signature.fromBytes(sig_bytes[0..96].*).verify(input, k) catch return error.BadSignature,
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
    inline for (.{ Alg.es256, Alg.es384 }) |alg| {
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
    try testing.expectEqual(@as(?Alg, null), Alg.fromName("ES512"));
    try testing.expectEqual(@as(?Alg, null), Alg.fromName("es256"));
    try testing.expect(!(AnyPublicKey{ .es256 = (try rfc7515KeyPair()).public_key }).eql(.{ .es384 = (try p384KeyPair()).public_key }));
}
