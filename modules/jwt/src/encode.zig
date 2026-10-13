// SPDX-License-Identifier: MIT
//! Token issuance: `encode` / `encodeJson` build a compact JWS
//! (`header.payload.signature`, RFC 7515 §7.1) for the algorithms `verify`
//! checks.
//!
//! RFC 8725 §2.1 / §3.1: the `alg` in the header is taken from the key's
//! variant, never from the caller alone, and there is no way to produce
//! `alg: "none"`. An HMAC secret shorter than the hash output is refused
//! (RFC 7518 §3.2: "A key of the same size as the hash output ... or larger
//! MUST be used"). Signatures are deterministic except PS*: ECDSA per RFC
//! 6979 as std implements it, Ed25519 by construction, ML-DSA in its
//! deterministic mode, RS* (PKCS#1 v1.5) by construction — so the same input
//! yields the same token, which is what a test wants and costs a production
//! issuer nothing it relies on. PS* (RSASSA-PSS) draws a fresh salt per
//! signature (RFC 7518 §3.5: salt length = hash length), so its key carries
//! the caller's CSPRNG (`RsaPss`).
//!
//! RS* and PS* sign through the `rsa` module (CRT with base blinding and the
//! Bellcore fault check, which surfaces as `SigningFailed`); ES512 through
//! the `p521` module.

const std = @import("std");
const root = @import("root.zig");
const burn = @import("burn.zig");
const ct25519 = @import("ct25519");

const hmac_sha2 = std.crypto.auth.hmac.sha2;
const b64 = std.base64.url_safe_no_pad.Encoder;

/// A signing key. The variant IS the algorithm: `encode` writes the `alg`
/// that belongs to it, so a caller cannot label an HMAC token ES256 or the
/// reverse.
///
/// Every variant is BORROWED for the call: the secret stays in the caller's
/// own storage and is never copied into a frame of this module's (a key pair
/// by value would leave one copy per call on the dead stack — ML-DSA-87's is
/// ~100 KiB in memory). Signing runs one frame down and zeroes the stack it
/// dirtied (`burn.zig`).
pub const SigningKey = union(enum) {
    /// Shared secrets. At least 32/48/64 bytes.
    hs256: []const u8,
    hs384: []const u8,
    hs512: []const u8,
    es256: *const root.EcdsaP256Sha256.KeyPair,
    es384: *const root.EcdsaP384Sha384.KeyPair,
    es512: *const root.EcdsaP521Sha512.KeyPair,
    /// EdDSA (RFC 8037) over Ed25519.
    ed25519: *const root.Ed25519.KeyPair,
    /// RFC 9964, empty context string (as the RFC requires).
    ml_dsa_44: *const root.MlDsa44.KeyPair,
    ml_dsa_65: *const root.MlDsa65.KeyPair,
    ml_dsa_87: *const root.MlDsa87.KeyPair,
    /// RSASSA-PKCS1-v1_5 with SHA-256/384/512 (RFC 7518 §3.3). The modulus
    /// must be 2048 bits or more (`InvalidKey` otherwise), as for verifying.
    rs256: *const root.rsa.KeyPair,
    rs384: *const root.rsa.KeyPair,
    rs512: *const root.rsa.KeyPair,
    /// RSASSA-PSS with SHA-256/384/512, MGF1 over the same hash, salt as long
    /// as the hash (RFC 7518 §3.5).
    ps256: RsaPss,
    ps384: RsaPss,
    ps512: RsaPss,

    /// A PS* signing key: the borrowed RSA key pair and the CSPRNG that
    /// draws the PSS salt and the RSA blinding factor. `random` MUST be
    /// cryptographically secure (`std.Random.DefaultCsprng` seeded from OS
    /// entropy, or `std.Io`'s secure source).
    pub const RsaPss = struct {
        key: *const root.rsa.KeyPair,
        random: std.Random,
    };

    /// The longest signature any variant produces (ML-DSA-87's), for a
    /// caller-side buffer to `sign` into.
    pub const max_signature_len = maxSignatureLen();

    /// Sign an already assembled JWS signing input (`b64(header) '.'
    /// b64(payload)`, RFC 7515 §5.1 step 5) — golang-jwt's
    /// `SigningMethod.Sign`. For a JWS whose payload is not a JSON object or
    /// whose header carries members `EncodeOptions` does not; `encode` and
    /// `encodeJson` are the JWT path and call this. Returns the raw signature
    /// in `out` (base64url-encode it for the compact form). The header's `alg`
    /// is the caller's to get right here: it must be `k.alg()`.
    // secret-api-ok: SigningKey is a union of BORROWED slices / pointers (see its doc comment); a by-value copy copies a pointer, never key bytes
    pub fn sign(k: SigningKey, signing_input: []const u8, out: *[max_signature_len]u8) EncodeError![]const u8 {
        try checkKey(k);
        return signInput(k, signing_input, out);
    }

    // secret-api-ok: SigningKey is a union of BORROWED slices / pointers (see its doc comment); a by-value copy copies a pointer, never key bytes
    pub fn alg(k: SigningKey) root.Alg {
        return switch (k) {
            .hs256 => .HS256,
            .hs384 => .HS384,
            .hs512 => .HS512,
            .es256 => .ES256,
            .es384 => .ES384,
            .es512 => .ES512,
            .ed25519 => .EdDSA,
            .ml_dsa_44 => .@"ML-DSA-44",
            .ml_dsa_65 => .@"ML-DSA-65",
            .ml_dsa_87 => .@"ML-DSA-87",
            .rs256 => .RS256,
            .rs384 => .RS384,
            .rs512 => .RS512,
            .ps256 => .PS256,
            .ps384 => .PS384,
            .ps512 => .PS512,
        };
    }

    /// The matching verification key, for a caller that issues and verifies
    /// (or tests a round trip). A borrowed HMAC secret stays borrowed. An RSA
    /// key below 2048 bits, which `encode` refuses too, has none: `.hmac = ""`
    /// stands in, which every `verify` rejects.
    // secret-api-ok: SigningKey is a union of BORROWED slices / pointers (see its doc comment); a by-value copy copies a pointer, never key bytes
    pub fn verificationKey(k: SigningKey) root.Key {
        return switch (k) {
            .hs256, .hs384, .hs512 => |s| .{ .hmac = s },
            .es256 => |kp| .{ .ecdsa_p256 = kp.public_key },
            .es384 => |kp| .{ .ecdsa_p384 = kp.public_key },
            .es512 => |kp| .{ .ecdsa_p521 = kp.public_key },
            .ed25519 => |kp| .{ .ed25519 = kp.public_key },
            .ml_dsa_44 => |kp| .{ .ml_dsa_44 = kp.public_key },
            .ml_dsa_65 => |kp| .{ .ml_dsa_65 = kp.public_key },
            .ml_dsa_87 => |kp| .{ .ml_dsa_87 = kp.public_key },
            .rs256, .rs384, .rs512 => |kp| root.Key.rsaFromPublicKey(&kp.public_key) catch .{ .hmac = "" },
            .ps256, .ps384, .ps512 => |p| root.Key.rsaFromPublicKey(&p.key.public_key) catch .{ .hmac = "" },
        };
    }
};

/// Header parameters besides `alg`, which comes from the key.
pub const EncodeOptions = struct {
    /// `typ` (RFC 7519 §5.1). null omits it. An access token for `Guard`
    /// wants "at+jwt" (RFC 9068).
    typ: ?[]const u8 = "JWT",
    /// `kid`, so a verifier holding a JWK Set picks the key.
    kid: ?[]const u8 = null,
};

pub const EncodeError = error{
    /// An HMAC secret shorter than its hash output, or empty; an RSA modulus
    /// below 2048 bits.
    InvalidKey,
    /// `encodeJson`: the claims are not one JSON object.
    InvalidClaims,
    /// The signature primitive refused (a key pair whose halves disagree, an
    /// RSA fault caught by the CRT check).
    SigningFailed,
    OutOfMemory,
};

/// A signed compact token whose payload is `claims` serialized by
/// `std.json` — a struct (optional fields left null are omitted), a
/// `std.json.Value`, anything `std.json.Stringify` takes that is a JSON
/// object. The caller owns the result.
// secret-api-ok: SigningKey is a union of BORROWED slices / pointers (a by-value copy copies a pointer); the signature primitive runs in `sign` under its burn
pub fn encode(gpa: std.mem.Allocator, claims: anytype, key: SigningKey, opts: EncodeOptions) EncodeError![]u8 {
    const json = std.json.Stringify.valueAlloc(gpa, claims, .{ .emit_null_optional_fields = false }) catch
        return error.OutOfMemory;
    defer gpa.free(json);
    return encodeJson(gpa, json, key, opts);
}

/// A signed compact token whose payload is `claims_json` verbatim. It must
/// be exactly one JSON object (RFC 7519 §7.1 step 2); anything else is
/// `error.InvalidClaims`. The caller owns the result.
// secret-api-ok: SigningKey is a union of BORROWED slices / pointers (a by-value copy copies a pointer); the signature primitive runs in `sign` under its burn
pub fn encodeJson(gpa: std.mem.Allocator, claims_json: []const u8, key: SigningKey, opts: EncodeOptions) EncodeError![]u8 {
    if (!isOneObject(gpa, claims_json)) return error.InvalidClaims;
    try checkKey(key);

    const Header = struct { alg: []const u8, typ: ?[]const u8, kid: ?[]const u8 };
    const header = std.json.Stringify.valueAlloc(gpa, Header{
        .alg = @tagName(key.alg()),
        .typ = opts.typ,
        .kid = opts.kid,
    }, .{ .emit_null_optional_fields = false }) catch return error.OutOfMemory;
    defer gpa.free(header);

    // signing input = b64(header) '.' b64(payload); the signature follows.
    const input_len = b64.calcSize(header.len) + 1 + b64.calcSize(claims_json.len);
    const sig_max = comptime maxSignatureLen();
    const out = gpa.alloc(u8, input_len + 1 + b64.calcSize(sig_max)) catch return error.OutOfMemory;
    errdefer gpa.free(out);
    var n = b64.encode(out, header).len;
    out[n] = '.';
    n += 1;
    n += b64.encode(out[n..], claims_json).len;
    const signing_input = out[0..n];

    var sig_buf: [sig_max]u8 = undefined;
    const sig = try signInput(key, signing_input, &sig_buf);
    out[n] = '.';
    n += 1;
    n += b64.encode(out[n..], sig).len;
    return gpa.realloc(out, n) catch out[0..n];
}

fn maxSignatureLen() usize {
    return @max(
        root.MlDsa87.Signature.encoded_length,
        @max(root.MlDsa65.Signature.encoded_length, root.MlDsa44.Signature.encoded_length),
    );
}

fn checkKey(key: SigningKey) EncodeError!void {
    const rsa_kp: ?*const root.rsa.KeyPair = switch (key) {
        .rs256, .rs384, .rs512 => |kp| kp,
        .ps256, .ps384, .ps512 => |p| p.key,
        else => null,
    };
    if (rsa_kp) |kp| {
        // RFC 7518 §3.3/§3.5; the same floor `Key.rsaFromModExp` applies.
        if (kp.secret_key.n.bits() < 2048) return error.InvalidKey;
        return;
    }
    const min: usize = switch (key) {
        .hs256 => hmac_sha2.HmacSha256.mac_length,
        .hs384 => hmac_sha2.HmacSha384.mac_length,
        .hs512 => hmac_sha2.HmacSha512.mac_length,
        else => return,
    };
    const secret = switch (key) {
        .hs256, .hs384, .hs512 => |s| s,
        else => unreachable,
    };
    if (secret.len < min) return error.InvalidKey;
}

/// The signing step. Each algorithm family has a body of its own, run one
/// frame down and followed by a burn of the stack that frame dirtied (sizes
/// and measurements in `burn.zig`). The bodies are separate so that one
/// frame does not grow to the largest algorithm's (ML-DSA's locals are
/// hundreds of KiB): a burn only reaches as deep as its body is wide.
fn signInput(key: SigningKey, input: []const u8, buf: []u8) EncodeError![]const u8 {
    const R = EncodeError![]const u8;
    switch (key) {
        .hs256 => |s| return burn.run(burn.hmac_burn, R, mac, .{ hmac_sha2.HmacSha256, s, input, buf }),
        .hs384 => |s| return burn.run(burn.hmac_burn, R, mac, .{ hmac_sha2.HmacSha384, s, input, buf }),
        .hs512 => |s| return burn.run(burn.hmac_burn, R, mac, .{ hmac_sha2.HmacSha512, s, input, buf }),
        .es256 => |kp| return burn.run(burn.ec_burn, R, signEc, .{ kp, input, buf }),
        .es384 => |kp| return burn.run(burn.ec_burn, R, signEc, .{ kp, input, buf }),
        // p521's `sign` burns its own body (24 KiB); this burn covers the
        // frame above it.
        .es512 => |kp| return burn.run(burn.ec_burn, R, signEc, .{ kp, input, buf }),
        .ed25519 => |kp| return burn.run(burn.ec_burn, R, signEd25519, .{ kp, input, buf }),
        .ml_dsa_44 => |kp| return burn.run(burn.mldsa44_burn, R, signMlDsa, .{ kp, input, buf }),
        .ml_dsa_65 => |kp| return burn.run(burn.mldsa65_burn, R, signMlDsa, .{ kp, input, buf }),
        .ml_dsa_87 => |kp| return burn.run(burn.mldsa87_burn, R, signMlDsa, .{ kp, input, buf }),
        // The `rsa` module burns its private operation's own stack; this
        // burn covers the EMSA encoding frame above it.
        .rs256 => |kp| return burn.run(burn.ec_burn, R, signRsaPkcs1, .{ std.crypto.hash.sha2.Sha256, kp, input, buf }),
        .rs384 => |kp| return burn.run(burn.ec_burn, R, signRsaPkcs1, .{ std.crypto.hash.sha2.Sha384, kp, input, buf }),
        .rs512 => |kp| return burn.run(burn.ec_burn, R, signRsaPkcs1, .{ std.crypto.hash.sha2.Sha512, kp, input, buf }),
        .ps256 => |p| return burn.run(burn.ec_burn, R, signRsaPss, .{ std.crypto.hash.sha2.Sha256, p, input, buf }),
        .ps384 => |p| return burn.run(burn.ec_burn, R, signRsaPss, .{ std.crypto.hash.sha2.Sha384, p, input, buf }),
        .ps512 => |p| return burn.run(burn.ec_burn, R, signRsaPss, .{ std.crypto.hash.sha2.Sha512, p, input, buf }),
    }
}

fn signRsaPkcs1(comptime H: type, kp: *const root.rsa.KeyPair, input: []const u8, buf: []u8) EncodeError![]const u8 {
    return root.rsa.signPkcs1v15(&kp.secret_key, H, input, buf) catch error.SigningFailed;
}

fn signRsaPss(comptime H: type, p: SigningKey.RsaPss, input: []const u8, buf: []u8) EncodeError![]const u8 {
    return root.rsa.signPss(&p.key.secret_key, H, p.random, input, H.digest_length, buf) catch error.SigningFailed;
}

/// ES256 / ES384 / ES512 / Ed25519. JWS ECDSA signatures are the raw fixed-width R‖S
/// (RFC 7518 §3.4), which is what `Signature.toBytes` yields — not DER.
fn signEc(kp: anytype, input: []const u8, buf: []u8) EncodeError![]const u8 {
    return put(buf, &((kp.sign(input, null) catch return error.SigningFailed).toBytes()));
}

/// Ed25519 (RFC 8032 §5.1.6), std's algorithm step for step — so the
/// signature is byte-identical to `std.crypto.sign.Ed25519.KeyPair.sign(msg,
/// null)` — with one substitution: `R = r·B` runs on `ct25519.mulBase`, a
/// constant-time fixed-base comb (~3× std's window ladder, ct25519 SPEC "C3"),
/// instead of `Edwards25519.basePoint.mul`. That multiplication was most of
/// EdDSA signing (bench-jwt 2026-10-10: `eddsa_sign` 1.6× golang-jwt). The
/// scalar, prefix and nonce are wiped here; the frame is burned by the caller.
fn signEd25519(kp: *const root.Ed25519.KeyPair, input: []const u8, buf: []u8) EncodeError![]const u8 {
    const Curve = std.crypto.ecc.Edwards25519;
    const Sha512 = std.crypto.hash.sha2.Sha512;
    // std's KeyPair.sign refuses a pair whose halves disagree; so does this.
    const pk = kp.public_key.toBytes();
    if (!std.mem.eql(u8, &kp.secret_key.publicKeyBytes(), &pk)) return error.SigningFailed;

    // (a, prefix) = SHA-512(seed), a clamped.
    var az: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &az);
    var seed = kp.secret_key.seed();
    defer std.crypto.secureZero(u8, &seed);
    Sha512.hash(&seed, &az, .{});
    var a = az[0..32].*;
    defer std.crypto.secureZero(u8, &a);
    Curve.scalar.clamp(&a);

    // r = SHA-512(prefix || M) mod L; R = r·B.
    var r64: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &r64);
    var h = Sha512.init(.{});
    h.update(az[32..64]);
    h.update(input);
    h.final(&r64);
    var r = Curve.scalar.reduce64(r64);
    defer std.crypto.secureZero(u8, &r);
    const big_r = ct25519.mulBase(r);
    // std's `basePoint.mul` fails on the identity (r ≡ 0 mod L, probability
    // 2^-252); keep the same refusal.
    big_r.rejectIdentity() catch return error.SigningFailed;
    const r_bytes = big_r.toBytes();

    // S = r + SHA-512(R || A || M)·a mod L.
    var k64: [64]u8 = undefined;
    h = Sha512.init(.{});
    h.update(&r_bytes);
    h.update(&pk);
    h.update(input);
    h.final(&k64);
    const s = Curve.scalar.mulAdd(Curve.scalar.reduce64(k64), a, r);
    return put(buf, &(r_bytes ++ s));
}

/// ML-DSA through the streaming signer, which reads the secret key in place:
/// `KeyPair.sign` takes the pair by value (~100 KiB for ML-DSA-87) and std
/// copies it again inside.
fn signMlDsa(kp: anytype, input: []const u8, buf: []u8) EncodeError![]const u8 {
    var st = kp.signer(null) catch return error.SigningFailed;
    st.update(input);
    return put(buf, &st.finalize().toBytes());
}

fn mac(comptime H: type, secret: []const u8, input: []const u8, buf: []u8) []const u8 {
    H.create(buf[0..H.mac_length], input, secret);
    return buf[0..H.mac_length];
}

fn put(buf: []u8, bytes: []const u8) []const u8 {
    @memcpy(buf[0..bytes.len], bytes);
    return buf[0..bytes.len];
}

fn isOneObject(gpa: std.mem.Allocator, json: []const u8) bool {
    const trimmed = std.mem.trim(u8, json, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '{') return false;
    return std.json.validate(gpa, json) catch false;
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

const TestClaims = struct {
    iss: []const u8 = "https://issuer.test",
    sub: []const u8 = "user-1",
    exp: i64 = 4_102_444_800, // 2100-01-01
    scope: ?[]const u8 = null,
};

const test_opts: root.Options = .{ .now_s = 1_790_000_000, .issuer = .{ .required = "https://issuer.test" }, .audience = .any };

fn roundTrip(key: SigningKey, opts: EncodeOptions) !void {
    const token = try encode(testing.allocator, TestClaims{}, key, opts);
    defer testing.allocator.free(token);
    var parsed = try root.parseAndVerify(testing.allocator, token, key.verificationKey(), test_opts);
    defer parsed.deinit();
    try testing.expectEqual(key.alg(), parsed.alg);
    try testing.expectEqualStrings("user-1", parsed.claims.claimStr("sub").?);
    try testing.expectEqual(@as(?std.json.Value, null), parsed.claims.claim("scope")); // null field omitted
    if (opts.kid) |k| try testing.expectEqualStrings(k, parsed.header.kid.?);
}

test "encode: every algorithm round-trips through parseAndVerify, alg from the key" {
    const secret64 = [_]u8{0x5a} ** 64;
    try roundTrip(.{ .hs256 = secret64[0..32] }, .{});
    try roundTrip(.{ .hs384 = secret64[0..48] }, .{ .kid = "k\"1" }); // kid is JSON-escaped
    try roundTrip(.{ .hs512 = &secret64 }, .{ .typ = null });
    const seed32 = [_]u8{7} ** 32;
    const es256 = try root.EcdsaP256Sha256.KeyPair.generateDeterministic(seed32);
    try roundTrip(.{ .es256 = &es256 }, .{ .kid = "ec" });
    const es384 = try root.EcdsaP384Sha384.KeyPair.generateDeterministic([_]u8{7} ** root.EcdsaP384Sha384.KeyPair.seed_length);
    try roundTrip(.{ .es384 = &es384 }, .{});
    var es512: root.EcdsaP521Sha512.KeyPair = undefined;
    try root.EcdsaP521Sha512.KeyPair.generateDeterministicInto(&es512, &([_]u8{7} ** root.EcdsaP521Sha512.KeyPair.seed_length));
    try roundTrip(.{ .es512 = &es512 }, .{ .kid = "p521" });
    const ed = try root.Ed25519.KeyPair.generateDeterministic(seed32);
    try roundTrip(.{ .ed25519 = &ed }, .{});
    const ml44 = try root.MlDsa44.KeyPair.generateDeterministic(seed32);
    try roundTrip(.{ .ml_dsa_44 = &ml44 }, .{});
    const ml65 = try root.MlDsa65.KeyPair.generateDeterministic(seed32);
    try roundTrip(.{ .ml_dsa_65 = &ml65 }, .{});
    const ml87 = try root.MlDsa87.KeyPair.generateDeterministic(seed32);
    try roundTrip(.{ .ml_dsa_87 = &ml87 }, .{});
}

test "encode: ES384 (p384 module) interoperates with std's EcdsaP384Sha384 both ways" {
    // ES384 moved off std on 2026-10-13. p384's nonces are RFC 6979 exactly,
    // so the signature bytes differ from std's; what must not change is that
    // either side accepts the other's tokens for the same key.
    const Std = std.crypto.sign.ecdsa.EcdsaP384Sha384;
    const d = [_]u8{0x11} ** 48;
    const ours = try root.EcdsaP384Sha384.KeyPair.fromSecretKey(try root.EcdsaP384Sha384.SecretKey.fromBytes(d));
    const theirs = try Std.KeyPair.fromSecretKey(try Std.SecretKey.fromBytes(d));
    try testing.expectEqualSlices(u8, &theirs.public_key.toUncompressedSec1(), &ours.public_key.toUncompressedSec1());

    // Ours → std. Deterministic: the same claims sign to the same token.
    const token = try encode(testing.allocator, TestClaims{}, .{ .es384 = &ours }, .{});
    defer testing.allocator.free(token);
    const again = try encode(testing.allocator, TestClaims{}, .{ .es384 = &ours }, .{});
    defer testing.allocator.free(again);
    try testing.expectEqualStrings(token, again);
    var parsed = try root.parse(testing.allocator, token);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 96), parsed.signature.len);
    try Std.Signature.fromBytes(parsed.signature[0..96].*).verify(parsed.signing_input, theirs.public_key);

    // Std → ours: std's signature over the same signing input, as a token.
    const std_sig = (try theirs.sign(parsed.signing_input, null)).toBytes();
    try testing.expect(!std.mem.eql(u8, &std_sig, parsed.signature[0..96]));
    var sig_b64: [b64.calcSize(96)]u8 = undefined;
    const std_token = try std.mem.concat(testing.allocator, u8, &.{ parsed.signing_input, ".", b64.encode(&sig_b64, &std_sig) });
    defer testing.allocator.free(std_token);
    var p_std = try root.parseAndVerify(testing.allocator, std_token, .{ .ecdsa_p384 = ours.public_key }, test_opts);
    p_std.deinit();
}

test "encode: a token signed with one key does not verify with another" {
    const a = [_]u8{1} ** 32;
    const b = [_]u8{2} ** 32;
    const token = try encode(testing.allocator, TestClaims{}, .{ .hs256 = &a }, .{});
    defer testing.allocator.free(token);
    try testing.expectError(error.BadSignature, root.parseAndVerify(testing.allocator, token, .{ .hmac = &b }, test_opts));
    // And not as another algorithm family either (RFC 8725 §2.1).
    const kp = try root.Ed25519.KeyPair.generateDeterministic(a);
    try testing.expectError(error.AlgKeyMismatch, root.parseAndVerify(testing.allocator, token, .{ .ed25519 = kp.public_key }, test_opts));
}

test "encode: a short HMAC secret and non-object claims are refused" {
    const short = [_]u8{1} ** 31;
    try testing.expectError(error.InvalidKey, encode(testing.allocator, TestClaims{}, .{ .hs256 = &short }, .{}));
    try testing.expectError(error.InvalidKey, encode(testing.allocator, TestClaims{}, .{ .hs512 = &([_]u8{1} ** 63) }, .{}));
    try testing.expectError(error.InvalidKey, encode(testing.allocator, TestClaims{}, .{ .hs256 = "" }, .{}));
    const k = [_]u8{1} ** 32;
    for ([_][]const u8{ "[1,2]", "\"x\"", "", "{\"a\":1", "{\"a\":1}{}", "  " }) |bad| {
        try testing.expectError(error.InvalidClaims, encodeJson(testing.allocator, bad, .{ .hs256 = &k }, .{}));
    }
}

test "encodeJson: verbatim payload, deterministic output, known HS256 bytes" {
    // RFC 7515 Appendix A.1's header and payload are not byte-reproducible
    // here (its header has a line break); pin our own form instead: same
    // input, same token, and the header is exactly what we wrote.
    const k = [_]u8{0x42} ** 32;
    const claims = "{\"sub\":\"x\"}";
    const t1 = try encodeJson(testing.allocator, claims, .{ .hs256 = &k }, .{});
    defer testing.allocator.free(t1);
    const t2 = try encodeJson(testing.allocator, claims, .{ .hs256 = &k }, .{});
    defer testing.allocator.free(t2);
    try testing.expectEqualStrings(t1, t2);
    try testing.expect(std.mem.startsWith(u8, t1, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.")); // {"alg":"HS256","typ":"JWT"}.{"sub":"x"}
    var opts = test_opts;
    opts.require_exp = false;
    opts.issuer = .any;
    var parsed = try root.parseAndVerify(testing.allocator, t1, .{ .hmac = &k }, opts);
    defer parsed.deinit();
}

test "Ed25519: the comb signer is byte-identical to std's KeyPair.sign" {
    var seed: [32]u8 = undefined;
    var msg: [300]u8 = undefined;
    for (0..64) |i| {
        for (&seed, 0..) |*b, j| b.* = @truncate(i *% 31 +% j *% 7 +% 1);
        for (&msg, 0..) |*b, j| b.* = @truncate(j *% 13 +% i);
        const kp = try root.Ed25519.KeyPair.generateDeterministic(seed);
        const m = msg[0 .. i * 4];
        var out: [SigningKey.max_signature_len]u8 = undefined;
        const ours = try (SigningKey{ .ed25519 = &kp }).sign(m, &out);
        const want = (try kp.sign(m, null)).toBytes();
        try testing.expectEqualSlices(u8, &want, ours);
    }
}
