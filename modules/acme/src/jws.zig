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

/// The one JWS algorithm ACME accounts use here: ECDSA P-256 + SHA-256.
pub const Es256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const KeyPair = Es256.KeyPair;

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

/// The canonical JWK of a P-256 public key: required members only, in
/// lexicographic order, no whitespace — the exact byte sequence RFC 7638
/// hashes. `buf` must hold `canonical_jwk_len` bytes.
pub fn canonicalJwk(buf: []u8, public_key: Es256.PublicKey) []const u8 {
    const sec1 = public_key.toUncompressedSec1(); // 0x04 ‖ X(32) ‖ Y(32)
    var xb: [43]u8 = undefined;
    var yb: [43]u8 = undefined;
    const x = b64.Encoder.encode(&xb, sec1[1..33]);
    const y = b64.Encoder.encode(&yb, sec1[33..65]);
    return std.fmt.bufPrint(
        buf,
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}",
        .{ x, y },
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

/// RFC 7638 JWK thumbprint of a P-256 public key (raw 32 bytes).
pub fn thumbprint(public_key: Es256.PublicKey) [Sha256.digest_length]u8 {
    var buf: [canonical_jwk_len]u8 = undefined;
    return thumbprintOfCanonical(canonicalJwk(&buf, public_key));
}

/// Encoded length of a base64url thumbprint.
pub const thumbprint_b64_len = base64UrlLen(Sha256.digest_length); // 43

/// base64url(thumbprint) — the form ACME uses everywhere.
pub fn thumbprintBase64(public_key: Es256.PublicKey) [thumbprint_b64_len]u8 {
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
    public_key: Es256.PublicKey,
) KeyAuthorizationError![]const u8 {
    if (!isValidToken(token)) return error.InvalidToken;
    const tp = thumbprintBase64(public_key);
    return std.fmt.bufPrint(buf, "{s}.{s}", .{ token, tp }) catch unreachable; // bounded by max_token_len
}

// ── flattened-JSON JWS signing ──────────────────────────────────────────────

/// The ACME protected header (RFC 8555 §6.2): `alg` is always ES256; `kid`
/// null embeds the account `jwk` instead (newAccount / revoke-by-key), any
/// other POST carries the account URL as `kid`.
pub const Header = struct {
    nonce: []const u8,
    url: []const u8,
    kid: ?[]const u8 = null,
};

pub const SignError = error{ OutOfMemory, SigningFailed };

/// Sign `payload` (raw bytes; "" for POST-as-GET) into a flattened JSON JWS
/// (`{"protected","payload","signature"}`). Caller owns the returned JSON.
pub fn sign(
    gpa: std.mem.Allocator,
    key_pair: KeyPair,
    payload: []const u8,
    header: Header,
) SignError![]u8 {
    // Protected header JSON. Field order mirrors x/crypto/acme (alg,
    // jwk|kid, nonce, url) — servers must not care, but goldens do.
    var hw: std.Io.Writer.Allocating = .init(gpa);
    defer hw.deinit();
    var js: std.json.Stringify = .{ .writer = &hw.writer, .options = .{} };
    writeProtected(&js, key_pair.public_key, header) catch return error.OutOfMemory;
    const protected = hw.written();

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const w = &out.writer;
    appendJws(gpa, w, key_pair, protected, payload) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.WriteFailed => return error.OutOfMemory, // Allocating writer only fails on OOM
        error.SigningFailed => return error.SigningFailed,
    };
    return out.toOwnedSlice();
}

fn writeProtected(js: *std.json.Stringify, public_key: Es256.PublicKey, header: Header) !void {
    try js.beginObject();
    try js.objectField("alg");
    try js.write("ES256");
    if (header.kid) |kid| {
        try js.objectField("kid");
        try js.write(kid);
    } else {
        const sec1 = public_key.toUncompressedSec1();
        var xb: [43]u8 = undefined;
        var yb: [43]u8 = undefined;
        try js.objectField("jwk");
        try js.beginObject();
        try js.objectField("crv");
        try js.write("P-256");
        try js.objectField("kty");
        try js.write("EC");
        try js.objectField("x");
        try js.write(b64.Encoder.encode(&xb, sec1[1..33]));
        try js.objectField("y");
        try js.write(b64.Encoder.encode(&yb, sec1[33..65]));
        try js.endObject();
    }
    try js.objectField("nonce");
    try js.write(header.nonce);
    try js.objectField("url");
    try js.write(header.url);
    try js.endObject();
}

fn appendJws(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    key_pair: KeyPair,
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
    const sig_bytes = sig.toBytes(); // r ‖ s, 64 bytes
    var sig_b64: [base64UrlLen(64)]u8 = undefined;
    _ = b64.Encoder.encode(&sig_b64, &sig_bytes);

    try w.print(
        "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"{s}\"}}",
        .{ protected_b64, payload_b64, sig_b64 },
    );
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

/// Parse a flattened JWS and verify its ES256 signature. `expected_key`
/// null means "use the embedded jwk" (newAccount); otherwise the signature
/// must verify against `expected_key` (the account key a real CA has on
/// file). This is the mock-CA / test half of the module.
pub fn verifyFlattened(
    gpa: std.mem.Allocator,
    jws_json: []const u8,
    expected_key: ?Es256.PublicKey,
) VerifyError!Verified {
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
    if (sig_bytes.len != 64) return error.MalformedJws;

    const head = std.json.parseFromSliceLeaky(ProtectedJson, a, protected, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedJws,
    };
    if (!std.mem.eql(u8, head.alg, "ES256")) return error.UnsupportedJws;
    if ((head.kid == null) == (head.jwk == null)) return error.UnsupportedJws; // exactly one

    var jwk_key: ?Es256.PublicKey = null;
    if (head.jwk) |jwk| {
        if (!std.mem.eql(u8, jwk.kty, "EC") or !std.mem.eql(u8, jwk.crv, "P-256"))
            return error.UnsupportedJws;
        jwk_key = publicKeyFromCoords(a, jwk.x, jwk.y) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MalformedJws,
        };
    }
    const key = expected_key orelse (jwk_key orelse return error.UnsupportedJws);

    // Verify over the exact base64url text from the wire.
    const input = std.mem.concat(a, u8, &.{ flat.protected, ".", flat.payload }) catch
        return error.OutOfMemory;
    const sig = Es256.Signature.fromBytes(sig_bytes[0..64].*);
    sig.verify(input, key) catch return error.BadSignature;

    return .{
        .arena = arena,
        .payload = payload,
        .nonce = head.nonce,
        .url = head.url,
        .kid = head.kid,
        .jwk_key = jwk_key,
    };
}

fn publicKeyFromCoords(
    scratch: std.mem.Allocator,
    x_b64: []const u8,
    y_b64: []const u8,
) error{ OutOfMemory, InvalidBase64, InvalidKey }!Es256.PublicKey {
    const x = try base64UrlDecodeAlloc(scratch, x_b64);
    const y = try base64UrlDecodeAlloc(scratch, y_b64);
    if (x.len != 32 or y.len != 32) return error.InvalidKey;
    var sec1: [65]u8 = undefined;
    sec1[0] = 0x04;
    @memcpy(sec1[1..33], x);
    @memcpy(sec1[33..65], y);
    return Es256.PublicKey.fromSec1(&sec1) catch error.InvalidKey;
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

fn rfc7515KeyPair() !KeyPair {
    var d: [32]u8 = undefined;
    try b64.Decoder.decode(&d, rfc7515_d);
    return KeyPair.fromSecretKey(try Es256.SecretKey.fromBytes(d));
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
    const other = try Es256.KeyPair.generateDeterministic(@splat(7));
    try testing.expectError(
        error.BadSignature,
        verifyFlattened(testing.allocator, jws_json, other.public_key),
    );
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
